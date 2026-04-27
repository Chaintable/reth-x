//! Pipeline gap fallback for historical state reads.
//!
//! During pipeline sync, the [`ExecutionStage`](reth_stages_types::StageId::Execution) commits
//! `PlainAccountState` / `PlainStorageState` along with [`tables::AccountChangeSets`] and
//! [`tables::StorageChangeSets`] in its own MDBX transaction, **before** the
//! [`IndexAccountHistoryStage`](reth_stages_types::StageId::IndexAccountHistory) /
//! [`IndexStorageHistoryStage`](reth_stages_types::StageId::IndexStorageHistory) stages commit the
//! corresponding history index shards. This creates a window where
//! [`HistoricalStateProvider`](super::historical::HistoricalStateProvider) would incorrectly fall
//! back to `PlainState` and return data from a future block for any account/slot modified in the
//! uncommitted range.
//!
//! [`PipelineGapIndex`] indexes that uncommitted range so that `InPlainState` reads can be served
//! correctly even while the indexing stages catch up.
//!
//! # Per-dimension tips
//!
//! Account and storage history index stages can advance independently. The account dimension's
//! gap is `(account_history_tip, execution_tip]` and the storage dimension's gap is
//! `(storage_history_tip, execution_tip]`. Mixing them via `min` would over-report the gap for
//! whichever stage is ahead and produce incorrect "earliest gap modification" answers when
//! callers use the wrong dimension's tip. We therefore walk and key each dimension separately.
//!
//! # Static-file aware
//!
//! When `account_changesets_in_static_files` is enabled, account changesets live in static files
//! rather than the MDBX [`tables::AccountChangeSets`] table. Build and probe routes through
//! [`ChangeSetReader::account_block_changeset`] / [`ChangeSetReader::get_account_before_block`]
//! so both layouts work transparently. Storage changesets currently have no static-file variant
//! and continue to use the MDBX cursor path directly.

use crate::ChangeSetReader;
use alloy_primitives::{Address, BlockNumber, B256};
use dashmap::DashMap;
use parking_lot::RwLock;
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    models::BlockNumberAddress,
    tables,
    transaction::DbTx,
};
use reth_primitives_traits::{Account, StorageEntry};
use reth_storage_api::{DBProvider, StorageSettingsCache};
use reth_storage_errors::provider::ProviderResult;
use std::sync::Arc;
use tracing::warn;

/// Per-key index of the earliest modification block in each per-dimension gap window.
#[derive(Debug)]
pub struct PipelineGapIndex {
    /// Block number up to which `PlainState` reflects state (Execution stage checkpoint).
    pub execution_tip: BlockNumber,
    /// Block number up to which the account history index has been built. Account gap is
    /// `(account_history_tip, execution_tip]`.
    pub account_history_tip: BlockNumber,
    /// Block number up to which the storage history index has been built. Storage gap is
    /// `(storage_history_tip, execution_tip]`.
    pub storage_history_tip: BlockNumber,
    /// For each address modified in the **account** gap, the earliest block where it was
    /// modified.
    pub account_first_block: DashMap<Address, BlockNumber>,
    /// For each `(address, slot)` modified in the **storage** gap, the earliest block where it
    /// was modified.
    pub storage_first_block: DashMap<(Address, B256), BlockNumber>,
}

impl PipelineGapIndex {
    /// Build the gap index by walking changesets in the per-dimension gap windows.
    ///
    /// Caller must guarantee at least one of the dimensions has a gap (i.e.
    /// `account_history_tip < execution_tip || storage_history_tip < execution_tip`). The
    /// account walk is skipped if `account_history_tip >= execution_tip`; same for storage. This
    /// avoids any work when only one dimension is lagging.
    pub fn build<P>(
        provider: &P,
        account_history_tip: BlockNumber,
        storage_history_tip: BlockNumber,
        execution_tip: BlockNumber,
    ) -> ProviderResult<Self>
    where
        P: DBProvider + ChangeSetReader + StorageSettingsCache,
    {
        debug_assert!(
            account_history_tip < execution_tip || storage_history_tip < execution_tip,
            "PipelineGapIndex::build called with no gap"
        );

        let account_first_block: DashMap<Address, BlockNumber> = DashMap::new();
        let storage_first_block: DashMap<(Address, B256), BlockNumber> = DashMap::new();

        // Account dimension. Use the static-file aware ChangeSetReader API when account
        // changesets live in static files; otherwise walk the MDBX table directly for speed.
        if account_history_tip < execution_tip {
            let acc_start = account_history_tip + 1;
            if provider.cached_storage_settings().account_changesets_in_static_files {
                // Static-file path: per-block iteration through the routed reader.
                for block in acc_start..=execution_tip {
                    for entry in provider.account_block_changeset(block)? {
                        account_first_block.entry(entry.address).or_insert(block);
                    }
                }
            } else {
                let mut cursor = provider.tx_ref().cursor_read::<tables::AccountChangeSets>()?;
                for entry in cursor.walk_range(acc_start..=execution_tip)? {
                    let (block, before) = entry?;
                    // or_insert keeps the first (smallest) block. Walk order is ascending by
                    // primary key, so the first insert is the earliest gap block.
                    account_first_block.entry(before.address).or_insert(block);
                }
            }
        }

        // Storage dimension. No static-file variant exists yet, so always cursor-walk MDBX.
        if storage_history_tip < execution_tip {
            let sto_start = storage_history_tip + 1;
            let mut cursor = provider.tx_ref().cursor_dup_read::<tables::StorageChangeSets>()?;
            let range = BlockNumberAddress::range(sto_start..=execution_tip);
            for entry in cursor.walk_range(range)? {
                let (key, StorageEntry { key: slot, .. }) = entry?;
                let block = key.block_number();
                let address = key.address();
                storage_first_block.entry((address, slot)).or_insert(block);
            }
        }

        Ok(Self {
            execution_tip,
            account_history_tip,
            storage_history_tip,
            account_first_block,
            storage_first_block,
        })
    }

    /// Probe the gap for an account modification.
    ///
    /// Returns the earliest block in the account gap where this address was modified, or `None`
    /// if it was not touched in the gap.
    pub fn account_first_gap_block(&self, address: &Address) -> Option<BlockNumber> {
        self.account_first_block.get(address).map(|v| *v)
    }

    /// Probe the gap for a storage slot modification.
    ///
    /// Returns the earliest block in the storage gap where this `(address, slot)` was modified,
    /// or `None` if it was not touched in the gap.
    pub fn storage_first_gap_block(&self, address: &Address, slot: &B256) -> Option<BlockNumber> {
        self.storage_first_block.get(&(*address, *slot)).map(|v| *v)
    }

    /// Look up the historical account value at the start of the earliest gap block. Routes
    /// through [`ChangeSetReader::get_account_before_block`] so static-file storage is honored.
    ///
    /// Returns `Ok(Some(info))` when the account was modified in the gap (info is the value at
    /// the end of the previous block, equal to the value at end of `account_history_tip`).
    /// Returns `Ok(None)` when the account was not modified in the gap; callers should fall back
    /// to `PlainState`.
    pub fn find_account_before<P>(
        &self,
        provider: &P,
        address: Address,
    ) -> ProviderResult<Option<Option<Account>>>
    where
        P: ChangeSetReader,
    {
        let Some(block) = self.account_first_gap_block(&address) else { return Ok(None) };
        Ok(provider.get_account_before_block(block, address)?.map(|acc| acc.info))
    }

    /// Look up the historical storage value at the start of the earliest gap block for
    /// `(address, slot)`. Storage changesets have no static-file variant yet, so this reads
    /// MDBX [`tables::StorageChangeSets`] directly via the provider's tx.
    ///
    /// Returns `None` when the slot is not in the gap, or the stored before-value otherwise.
    pub fn find_storage_before<TX: DbTx>(
        &self,
        tx: &TX,
        address: Address,
        slot: B256,
    ) -> ProviderResult<Option<StorageEntry>> {
        let Some(block) = self.storage_first_gap_block(&address, &slot) else { return Ok(None) };
        let entry = tx
            .cursor_dup_read::<tables::StorageChangeSets>()?
            .seek_by_key_subkey(BlockNumberAddress::from((block, address)), slot)?
            .filter(|e| e.key == slot);
        Ok(entry)
    }
}

/// Composite key identifying a built gap index — `(execution_tip, account_history_tip,
/// storage_history_tip)`. The cache is invalidated whenever any of the three changes.
type GapTips = (BlockNumber, BlockNumber, BlockNumber);

/// Lock-protected, lazily built cache of [`PipelineGapIndex`] keyed by the current pipeline tips.
#[derive(Debug, Default)]
pub struct PipelineGapCache {
    inner: RwLock<CachedSlot>,
}

#[derive(Debug, Default)]
struct CachedSlot {
    /// Tips the cached index was built for. None until first build.
    tips: Option<GapTips>,
    /// The cached index. Cleared when there is no gap in either dimension.
    index: Option<Arc<PipelineGapIndex>>,
}

impl PipelineGapCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Synchronously rebuild the gap index for the given tips, replacing any cached state.
    ///
    /// When neither dimension has a gap (`account_history_tip >= execution_tip &&
    /// storage_history_tip >= execution_tip`), the cache is cleared.
    ///
    /// The eager counterpart to [`Self::get_or_build`]: callers that already know the tips have
    /// changed (e.g. the pipeline driver after a stage commit) call this so RPC queries don't
    /// pay the rebuild cost.
    pub fn rebuild_sync<P>(
        &self,
        provider: &P,
        execution_tip: BlockNumber,
        account_history_tip: BlockNumber,
        storage_history_tip: BlockNumber,
    ) -> ProviderResult<()>
    where
        P: DBProvider + ChangeSetReader + StorageSettingsCache,
    {
        if account_history_tip >= execution_tip && storage_history_tip >= execution_tip {
            let mut guard = self.inner.write();
            guard.tips = None;
            guard.index = None;
            return Ok(());
        }
        let idx = Arc::new(PipelineGapIndex::build(
            provider,
            account_history_tip,
            storage_history_tip,
            execution_tip,
        )?);
        let mut guard = self.inner.write();
        guard.tips = Some((execution_tip, account_history_tip, storage_history_tip));
        guard.index = Some(idx);
        Ok(())
    }

    /// Returns the current cached tips, or `None` if nothing is cached.
    pub fn cached_tips(&self) -> Option<GapTips> {
        self.inner.read().tips
    }

    /// Get or build the gap index for the given tips. Lazy fallback used when active rebuild
    /// hooks miss an event; logs a warn so the gap can be diagnosed.
    pub fn get_or_build<P>(
        &self,
        provider: &P,
        execution_tip: BlockNumber,
        account_history_tip: BlockNumber,
        storage_history_tip: BlockNumber,
    ) -> ProviderResult<Option<Arc<PipelineGapIndex>>>
    where
        P: DBProvider + ChangeSetReader + StorageSettingsCache,
    {
        if account_history_tip >= execution_tip && storage_history_tip >= execution_tip {
            // No gap. Drop any stale cached index so we don't hold memory.
            let mut guard = self.inner.write();
            if guard.index.is_some() || guard.tips.is_some() {
                guard.tips = None;
                guard.index = None;
            }
            return Ok(None);
        }

        let key = (execution_tip, account_history_tip, storage_history_tip);

        // Fast path: cached tips match.
        {
            let guard = self.inner.read();
            if guard.tips == Some(key) &&
                let Some(idx) = guard.index.clone()
            {
                return Ok(Some(idx));
            }
        }

        // Slow path: rebuild under write lock with double-check.
        //
        // Reaching here means the cache is stale despite the active rebuild hooks
        // (`refresh_pipeline_gap_index` invoked on startup, after every relevant stage commit,
        // and after every relevant unwind). The lazy fallback keeps us correct, but the warn
        // surfaces a missed active-rebuild event so it can be tracked down — in steady state
        // this log line should be silent.
        let mut guard = self.inner.write();
        if guard.tips == Some(key) &&
            let Some(idx) = guard.index.clone()
        {
            return Ok(Some(idx));
        }

        warn!(
            target: "provider::pipeline_gap",
            cached_tips = ?guard.tips,
            current_tips = ?key,
            "gap cache stale, falling back to inline rebuild — active refresh hook may have missed this transition"
        );

        let idx = Arc::new(PipelineGapIndex::build(
            provider,
            account_history_tip,
            storage_history_tip,
            execution_tip,
        )?);
        guard.tips = Some(key);
        guard.index = Some(idx.clone());
        Ok(Some(idx))
    }
}
