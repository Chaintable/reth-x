use crate::{
    providers::state::pipeline_gap::PipelineGapIndex, AccountReader, BlockHashReader,
    ChangeSetReader, EitherReader, HashedPostStateProvider, ProviderError, RocksDBProviderFactory,
    StateProvider, StateRootProvider,
};
use alloy_eips::merge::EPOCH_SLOTS;
use alloy_primitives::{Address, BlockNumber, Bytes, StorageKey, StorageValue, B256};
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    table::Table,
    tables,
    transaction::DbTx,
    BlockNumberList,
};
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{
    BlockNumReader, BytecodeReader, DBProvider, NodePrimitivesProvider, StateProofProvider,
    StorageRootProvider, StorageSettingsCache,
};
use reth_storage_errors::provider::ProviderResult;
use reth_trie::{
    proof::{Proof, StorageProof},
    updates::TrieUpdates,
    witness::TrieWitness,
    AccountProof, HashedPostState, HashedPostStateSorted, HashedStorage, KeccakKeyHasher,
    MultiProof, MultiProofTargets, StateRoot, StorageMultiProof, StorageRoot, TrieInput,
    TrieInputSorted,
};
use reth_trie_db::{
    DatabaseHashedPostState, DatabaseHashedStorage, DatabaseProof, DatabaseStateRoot,
    DatabaseStorageProof, DatabaseStorageRoot, DatabaseTrieWitness,
};

use std::{fmt::Debug, sync::Arc};

/// Result of a history lookup for an account or storage slot.
///
/// Indicates where to find the historical value for a given key at a specific block.
#[derive(Debug, Eq, PartialEq)]
pub enum HistoryInfo {
    /// The key is written to, but only after our block (not yet written at the target block). Or
    /// it has never been written.
    NotYetWritten,
    /// The chunk contains an entry for a write after our block at the given block number.
    /// The value should be looked up in the changeset at this block.
    InChangeset(u64),
    /// The chunk does not contain an entry for a write after our block. This can only
    /// happen if this is the last chunk, so we need to look in the plain state.
    InPlainState,
    /// The key may have been written, but due to pruning we may not have changesets and
    /// history, so we need to make a plain state lookup.
    MaybeInPlainState,
}

impl HistoryInfo {
    /// Determines where to find the historical value based on computed shard lookup results.
    ///
    /// This is a pure function shared by both MDBX and `RocksDB` backends.
    ///
    /// # Arguments
    /// * `found_block` - The block number from the shard lookup
    /// * `is_before_first_write` - True if the target block is before the first write to this key.
    ///   This should be computed as: `rank == 0 && found_block != Some(block_number) &&
    ///   !has_previous_shard` where `has_previous_shard` comes from a lazy `cursor.prev()` check.
    /// * `lowest_available` - Lowest block where history is available (pruning boundary)
    pub const fn from_lookup(
        found_block: Option<u64>,
        is_before_first_write: bool,
        lowest_available: Option<BlockNumber>,
    ) -> Self {
        if is_before_first_write {
            if let (Some(_), Some(block_number)) = (lowest_available, found_block) {
                // The key may have been written, but due to pruning we may not have changesets
                // and history, so we need to make a changeset lookup.
                return Self::InChangeset(block_number)
            }
            // The key is written to, but only after our block.
            return Self::NotYetWritten
        }

        if let Some(block_number) = found_block {
            // The chunk contains an entry for a write after our block, return it.
            Self::InChangeset(block_number)
        } else {
            // The chunk does not contain an entry for a write after our block. This can only
            // happen if this is the last chunk and so we need to look in the plain state.
            Self::InPlainState
        }
    }
}

/// State provider for a given block number which takes a tx reference.
///
/// Historical state provider accesses the state at the start of the provided block number.
/// It means that all changes made in the provided block number are not included.
///
/// Historical state provider reads the following tables:
/// - [`tables::AccountsHistory`]
/// - [`tables::Bytecodes`]
/// - [`tables::StoragesHistory`]
/// - [`tables::AccountChangeSets`]
/// - [`tables::StorageChangeSets`]
#[derive(Debug)]
pub struct HistoricalStateProviderRef<'b, Provider> {
    /// Database provider
    provider: &'b Provider,
    /// Block number is main index for the history state of accounts and storages.
    block_number: BlockNumber,
    /// Lowest blocks at which different parts of the state are available.
    lowest_available_blocks: LowestAvailableBlocks,
    /// Cached pipeline consistency info. When the Execution stage checkpoint is ahead of the
    /// history index checkpoint, `PlainState` has been advanced beyond history coverage and the
    /// `InPlainState` fallback would return data from a future block.
    pipeline_consistency: PipelineConsistency,
    /// Gap index covering `(history_tip, execution_tip]`. Built lazily by the provider factory
    /// and shared across providers. When present, `InPlainState` reads can be served by reading
    /// the changeset entry for the earliest gap modification of the requested key.
    pipeline_gap_index: Option<Arc<PipelineGapIndex>>,
}

impl<'b, Provider: DBProvider + ChangeSetReader + BlockNumReader>
    HistoricalStateProviderRef<'b, Provider>
{
    /// Create new `StateProvider` for historical block number
    pub fn new(provider: &'b Provider, block_number: BlockNumber) -> Self {
        Self {
            provider,
            block_number,
            lowest_available_blocks: Default::default(),
            pipeline_consistency: Default::default(),
            pipeline_gap_index: None,
        }
    }

    /// Create new `StateProvider` for historical block number and lowest block numbers at which
    /// account & storage histories are available.
    pub const fn new_with_lowest_available_blocks(
        provider: &'b Provider,
        block_number: BlockNumber,
        lowest_available_blocks: LowestAvailableBlocks,
    ) -> Self {
        Self {
            provider,
            block_number,
            lowest_available_blocks,
            pipeline_consistency: PipelineConsistency {
                execution_tip: None,
                account_history_tip: None,
                storage_history_tip: None,
            },
            pipeline_gap_index: None,
        }
    }

    /// Set the pipeline consistency info for detecting stale `InPlainState` reads during
    /// pipeline sync.
    pub const fn with_pipeline_consistency(
        mut self,
        pipeline_consistency: PipelineConsistency,
    ) -> Self {
        self.pipeline_consistency = pipeline_consistency;
        self
    }

    /// Attach a [`PipelineGapIndex`] so `InPlainState` reads can be served correctly while the
    /// history index stages catch up to Execution.
    pub fn with_pipeline_gap_index(mut self, gap_index: Option<Arc<PipelineGapIndex>>) -> Self {
        self.pipeline_gap_index = gap_index;
        self
    }

    /// Lookup an account in the `AccountsHistory` table using `EitherReader`.
    pub fn account_history_lookup(&self, address: Address) -> ProviderResult<HistoryInfo>
    where
        Provider: StorageSettingsCache + RocksDBProviderFactory + NodePrimitivesProvider,
    {
        if !self.lowest_available_blocks.is_account_history_available(self.block_number) {
            return Err(ProviderError::StateAtBlockPruned(self.block_number))
        }

        self.provider.with_rocksdb_tx(|rocks_tx_ref| {
            let mut reader = EitherReader::new_accounts_history(self.provider, rocks_tx_ref)?;
            reader.account_history_info(
                address,
                self.block_number,
                self.lowest_available_blocks.account_history_block_number,
            )
        })
    }

    /// Lookup a storage key in the `StoragesHistory` table using `EitherReader`.
    pub fn storage_history_lookup(
        &self,
        address: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<HistoryInfo>
    where
        Provider: StorageSettingsCache + RocksDBProviderFactory + NodePrimitivesProvider,
    {
        if !self.lowest_available_blocks.is_storage_history_available(self.block_number) {
            return Err(ProviderError::StateAtBlockPruned(self.block_number))
        }

        self.provider.with_rocksdb_tx(|rocks_tx_ref| {
            let mut reader = EitherReader::new_storages_history(self.provider, rocks_tx_ref)?;
            reader.storage_history_info(
                address,
                storage_key,
                self.block_number,
                self.lowest_available_blocks.storage_history_block_number,
            )
        })
    }

    /// Checks and returns `true` if distance to historical block exceeds the provided limit.
    fn check_distance_against_limit(&self, limit: u64) -> ProviderResult<bool> {
        let tip = self.provider.last_block_number()?;

        Ok(tip.saturating_sub(self.block_number) > limit)
    }

    /// Retrieve revert hashed state for this history provider.
    fn revert_state(&self) -> ProviderResult<HashedPostStateSorted> {
        if !self.lowest_available_blocks.is_account_history_available(self.block_number) ||
            !self.lowest_available_blocks.is_storage_history_available(self.block_number)
        {
            return Err(ProviderError::StateAtBlockPruned(self.block_number))
        }

        if self.check_distance_against_limit(EPOCH_SLOTS)? {
            tracing::warn!(
                target: "provider::historical_sp",
                target = self.block_number,
                "Attempt to calculate state root for an old block might result in OOM"
            );
        }

        HashedPostStateSorted::from_reverts::<KeccakKeyHasher>(self.provider, self.block_number..)
    }

    /// Retrieve revert hashed storage for this history provider and target address.
    fn revert_storage(&self, address: Address) -> ProviderResult<HashedStorage> {
        if !self.lowest_available_blocks.is_storage_history_available(self.block_number) {
            return Err(ProviderError::StateAtBlockPruned(self.block_number))
        }

        if self.check_distance_against_limit(EPOCH_SLOTS * 10)? {
            tracing::warn!(
                target: "provider::historical_sp",
                target = self.block_number,
                "Attempt to calculate storage root for an old block might result in OOM"
            );
        }

        Ok(HashedStorage::from_reverts(self.tx(), address, self.block_number)?)
    }

    /// Set the lowest block number at which the account history is available.
    pub const fn with_lowest_available_account_history_block_number(
        mut self,
        block_number: BlockNumber,
    ) -> Self {
        self.lowest_available_blocks.account_history_block_number = Some(block_number);
        self
    }

    /// Set the lowest block number at which the storage history is available.
    pub const fn with_lowest_available_storage_history_block_number(
        mut self,
        block_number: BlockNumber,
    ) -> Self {
        self.lowest_available_blocks.storage_history_block_number = Some(block_number);
        self
    }
}

impl<Provider: DBProvider + BlockNumReader> HistoricalStateProviderRef<'_, Provider> {
    fn tx(&self) -> &Provider::Tx {
        self.provider.tx_ref()
    }
}

impl<
        Provider: DBProvider
            + BlockNumReader
            + ChangeSetReader
            + StorageSettingsCache
            + RocksDBProviderFactory
            + NodePrimitivesProvider,
    > AccountReader for HistoricalStateProviderRef<'_, Provider>
{
    /// Get basic account information.
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        match self.account_history_lookup(*address)? {
            HistoryInfo::NotYetWritten => Ok(None),
            HistoryInfo::InChangeset(changeset_block_number) => {
                // Use ChangeSetReader trait method to get the account from changesets
                self.provider
                    .get_account_before_block(changeset_block_number, *address)?
                    .ok_or(ProviderError::AccountChangesetNotFound {
                        block_number: changeset_block_number,
                        address: *address,
                    })
                    .map(|account_before| account_before.info)
            }
            HistoryInfo::InPlainState | HistoryInfo::MaybeInPlainState => {
                if let Some((exec_tip, hist_tip)) =
                    self.pipeline_consistency.account_inconsistency()
                {
                    // Queries strictly inside the gap window cannot be answered: we'd need state
                    // at an arbitrary mid-gap block (block_number > history_tip + 1 means the
                    // requested state is at the end of some block > history_tip, which the gap
                    // index — only tracking the FIRST gap modification — cannot reconstruct).
                    //
                    // The boundary case `block_number == history_tip + 1` (state at end of
                    // history_tip) IS answerable because all modifications up to history_tip are
                    // in the history index and any modification in the gap window has its
                    // before-value cached.
                    if self.block_number > hist_tip + 1 {
                        return Err(ProviderError::HistoryStateInconsistent {
                            block: self.block_number,
                            execution_tip: exec_tip,
                            history_tip: hist_tip,
                        })
                    }
                    if let Some(gap) = &self.pipeline_gap_index {
                        if let Some(info) = gap.find_account_before(self.provider, *address)? {
                            // Earliest gap modification's before-value equals the value at end of
                            // history_tip. Combined with `query_block <= history_tip` and the
                            // history-index lookup returning InPlainState (i.e. no modification in
                            // (query_block, history_tip]), this is the value at start of
                            // query_block.
                            return Ok(info)
                        }
                        // Fall through: address not modified in gap → PlainState is correct.
                    } else {
                        // Gap exists but no index built (factory didn't supply one). Be safe.
                        return Err(ProviderError::HistoryStateInconsistent {
                            block: self.block_number,
                            execution_tip: exec_tip,
                            history_tip: hist_tip,
                        })
                    }
                }
                Ok(self.tx().get_by_encoded_key::<tables::PlainAccountState>(address)?)
            }
        }
    }
}

impl<Provider: DBProvider + BlockNumReader + BlockHashReader> BlockHashReader
    for HistoricalStateProviderRef<'_, Provider>
{
    /// Get block hash by number.
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.provider.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        self.provider.canonical_hashes_range(start, end)
    }
}

impl<Provider: DBProvider + ChangeSetReader + BlockNumReader> StateRootProvider
    for HistoricalStateProviderRef<'_, Provider>
{
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        let mut revert_state = self.revert_state()?;
        let hashed_state_sorted = hashed_state.into_sorted();
        revert_state.extend_ref_and_sort(&hashed_state_sorted);
        Ok(StateRoot::overlay_root(self.tx(), &revert_state)?)
    }

    fn state_root_from_nodes(&self, mut input: TrieInput) -> ProviderResult<B256> {
        input.prepend(self.revert_state()?.into());
        Ok(StateRoot::overlay_root_from_nodes(self.tx(), TrieInputSorted::from_unsorted(input))?)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        let mut revert_state = self.revert_state()?;
        let hashed_state_sorted = hashed_state.into_sorted();
        revert_state.extend_ref_and_sort(&hashed_state_sorted);
        Ok(StateRoot::overlay_root_with_updates(self.tx(), &revert_state)?)
    }

    fn state_root_from_nodes_with_updates(
        &self,
        mut input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        input.prepend(self.revert_state()?.into());
        Ok(StateRoot::overlay_root_from_nodes_with_updates(
            self.tx(),
            TrieInputSorted::from_unsorted(input),
        )?)
    }
}

impl<Provider: DBProvider + ChangeSetReader + BlockNumReader> StorageRootProvider
    for HistoricalStateProviderRef<'_, Provider>
{
    fn storage_root(
        &self,
        address: Address,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        let mut revert_storage = self.revert_storage(address)?;
        revert_storage.extend(&hashed_storage);
        StorageRoot::overlay_root(self.tx(), address, revert_storage)
            .map_err(|err| ProviderError::Database(err.into()))
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        hashed_storage: HashedStorage,
    ) -> ProviderResult<reth_trie::StorageProof> {
        let mut revert_storage = self.revert_storage(address)?;
        revert_storage.extend(&hashed_storage);
        StorageProof::overlay_storage_proof(self.tx(), address, slot, revert_storage)
            .map_err(ProviderError::from)
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        let mut revert_storage = self.revert_storage(address)?;
        revert_storage.extend(&hashed_storage);
        StorageProof::overlay_storage_multiproof(self.tx(), address, slots, revert_storage)
            .map_err(ProviderError::from)
    }
}

impl<Provider: DBProvider + ChangeSetReader + BlockNumReader> StateProofProvider
    for HistoricalStateProviderRef<'_, Provider>
{
    /// Get account and storage proofs.
    fn proof(
        &self,
        mut input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        input.prepend(self.revert_state()?.into());
        let proof = <Proof<_, _> as DatabaseProof>::from_tx(self.tx());
        proof.overlay_account_proof(input, address, slots).map_err(ProviderError::from)
    }

    fn multiproof(
        &self,
        mut input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        input.prepend(self.revert_state()?.into());
        let proof = <Proof<_, _> as DatabaseProof>::from_tx(self.tx());
        proof.overlay_multiproof(input, targets).map_err(ProviderError::from)
    }

    fn witness(&self, mut input: TrieInput, target: HashedPostState) -> ProviderResult<Vec<Bytes>> {
        input.prepend(self.revert_state()?.into());
        TrieWitness::overlay_witness(self.tx(), input, target)
            .map_err(ProviderError::from)
            .map(|hm| hm.into_values().collect())
    }
}

impl<Provider> HashedPostStateProvider for HistoricalStateProviderRef<'_, Provider> {
    fn hashed_post_state(&self, bundle_state: &revm_database::BundleState) -> HashedPostState {
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state())
    }
}

impl<
        Provider: DBProvider
            + BlockNumReader
            + BlockHashReader
            + ChangeSetReader
            + StorageSettingsCache
            + RocksDBProviderFactory
            + NodePrimitivesProvider,
    > StateProvider for HistoricalStateProviderRef<'_, Provider>
{
    /// Get storage.
    fn storage(
        &self,
        address: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        match self.storage_history_lookup(address, storage_key)? {
            HistoryInfo::NotYetWritten => Ok(None),
            HistoryInfo::InChangeset(changeset_block_number) => Ok(Some(
                self.tx()
                    .cursor_dup_read::<tables::StorageChangeSets>()?
                    .seek_by_key_subkey((changeset_block_number, address).into(), storage_key)?
                    .filter(|entry| entry.key == storage_key)
                    .ok_or_else(|| ProviderError::StorageChangesetNotFound {
                        block_number: changeset_block_number,
                        address,
                        storage_key: Box::new(storage_key),
                    })?
                    .value,
            )),
            HistoryInfo::InPlainState | HistoryInfo::MaybeInPlainState => {
                if let Some((exec_tip, hist_tip)) =
                    self.pipeline_consistency.storage_inconsistency()
                {
                    // See `basic_account` for the boundary reasoning. block_number == hist_tip+1
                    // is still answerable; block_number > hist_tip+1 is mid-gap and not.
                    if self.block_number > hist_tip + 1 {
                        return Err(ProviderError::HistoryStateInconsistent {
                            block: self.block_number,
                            execution_tip: exec_tip,
                            history_tip: hist_tip,
                        })
                    }
                    if let Some(gap) = &self.pipeline_gap_index {
                        if let Some(entry) =
                            gap.find_storage_before(self.tx(), address, storage_key)?
                        {
                            // Slot was modified in the gap — return the before-value at the
                            // earliest gap block.
                            return Ok(Some(entry.value))
                        }
                        // Fall through: slot not modified in gap → PlainState is correct.
                    } else {
                        return Err(ProviderError::HistoryStateInconsistent {
                            block: self.block_number,
                            execution_tip: exec_tip,
                            history_tip: hist_tip,
                        })
                    }
                }
                Ok(self
                    .tx()
                    .cursor_dup_read::<tables::PlainStorageState>()?
                    .seek_by_key_subkey(address, storage_key)?
                    .filter(|entry| entry.key == storage_key)
                    .map(|entry| entry.value)
                    .or(Some(StorageValue::ZERO)))
            }
        }
    }
}

impl<Provider: DBProvider + BlockNumReader> BytecodeReader
    for HistoricalStateProviderRef<'_, Provider>
{
    /// Get account code by its hash
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.tx().get_by_encoded_key::<tables::Bytecodes>(code_hash).map_err(Into::into)
    }
}

/// State provider for a given block number.
/// For more detailed description, see [`HistoricalStateProviderRef`].
#[derive(Debug)]
pub struct HistoricalStateProvider<Provider> {
    /// Database provider.
    provider: Provider,
    /// State at the block number is the main indexer of the state.
    block_number: BlockNumber,
    /// Lowest blocks at which different parts of the state are available.
    lowest_available_blocks: LowestAvailableBlocks,
    /// Cached pipeline consistency info.
    pipeline_consistency: PipelineConsistency,
    /// Optional gap index (see [`HistoricalStateProviderRef::pipeline_gap_index`]).
    pipeline_gap_index: Option<Arc<PipelineGapIndex>>,
}

impl<Provider: DBProvider + ChangeSetReader + BlockNumReader> HistoricalStateProvider<Provider> {
    /// Create new `StateProvider` for historical block number
    pub fn new(provider: Provider, block_number: BlockNumber) -> Self {
        Self {
            provider,
            block_number,
            lowest_available_blocks: Default::default(),
            pipeline_consistency: Default::default(),
            pipeline_gap_index: None,
        }
    }

    /// Set the lowest block number at which the account history is available.
    pub const fn with_lowest_available_account_history_block_number(
        mut self,
        block_number: BlockNumber,
    ) -> Self {
        self.lowest_available_blocks.account_history_block_number = Some(block_number);
        self
    }

    /// Set the lowest block number at which the storage history is available.
    pub const fn with_lowest_available_storage_history_block_number(
        mut self,
        block_number: BlockNumber,
    ) -> Self {
        self.lowest_available_blocks.storage_history_block_number = Some(block_number);
        self
    }

    /// Set the pipeline consistency info for detecting stale `InPlainState` reads during
    /// pipeline sync.
    pub const fn with_pipeline_consistency(
        mut self,
        pipeline_consistency: PipelineConsistency,
    ) -> Self {
        self.pipeline_consistency = pipeline_consistency;
        self
    }

    /// Attach a [`PipelineGapIndex`] so `InPlainState` reads can be served correctly while the
    /// history index stages catch up to Execution.
    pub fn with_pipeline_gap_index(mut self, gap_index: Option<Arc<PipelineGapIndex>>) -> Self {
        self.pipeline_gap_index = gap_index;
        self
    }

    /// Returns a new provider that takes the `TX` as reference
    #[inline(always)]
    fn as_ref(&self) -> HistoricalStateProviderRef<'_, Provider> {
        HistoricalStateProviderRef::new_with_lowest_available_blocks(
            &self.provider,
            self.block_number,
            self.lowest_available_blocks,
        )
        .with_pipeline_consistency(self.pipeline_consistency)
        .with_pipeline_gap_index(self.pipeline_gap_index.clone())
    }
}

// Delegates all provider impls to [HistoricalStateProviderRef]
reth_storage_api::macros::delegate_provider_impls!(HistoricalStateProvider<Provider> where [Provider: DBProvider + BlockNumReader + BlockHashReader + ChangeSetReader + StorageSettingsCache + RocksDBProviderFactory + NodePrimitivesProvider]);

/// Cached pipeline stage checkpoint info used to detect inconsistent `InPlainState` reads.
///
/// During pipeline sync, the `ExecutionStage` commits `PlainAccountState` / `PlainStorageState`
/// in its own MDBX write transaction **before** the `IndexAccountHistoryStage` and
/// `IndexStorageHistoryStage` commit the corresponding history indices. This creates a window
/// where `HistoricalStateProvider` would incorrectly fall back to `InPlainState` and return
/// data from a future block.
///
/// When the Execution checkpoint is ahead of the history index checkpoint, we know `PlainState`
/// has been silently advanced and the `InPlainState` path must not be used.
#[derive(Clone, Copy, Debug, Default)]
pub struct PipelineConsistency {
    /// Block number up to which the Execution stage has committed `PlainState`.
    pub execution_tip: Option<BlockNumber>,
    /// Block number up to which the account history index has been built.
    pub account_history_tip: Option<BlockNumber>,
    /// Block number up to which the storage history index has been built.
    pub storage_history_tip: Option<BlockNumber>,
}

impl PipelineConsistency {
    /// Returns `Some((exec_tip, hist_tip))` if account history is inconsistent with `PlainState`,
    /// meaning the `InPlainState` fallback would return wrong data.
    ///
    /// A `None` history tip means the index stage has never run, which is equivalent to block 0.
    pub const fn account_inconsistency(&self) -> Option<(BlockNumber, BlockNumber)> {
        match (self.execution_tip, self.account_history_tip) {
            (Some(exec), Some(hist)) if exec > hist => Some((exec, hist)),
            (Some(exec), None) => Some((exec, 0)),
            _ => None,
        }
    }

    /// Returns `Some((exec_tip, hist_tip))` if storage history is inconsistent with `PlainState`.
    ///
    /// A `None` history tip means the index stage has never run, which is equivalent to block 0.
    pub const fn storage_inconsistency(&self) -> Option<(BlockNumber, BlockNumber)> {
        match (self.execution_tip, self.storage_history_tip) {
            (Some(exec), Some(hist)) if exec > hist => Some((exec, hist)),
            (Some(exec), None) => Some((exec, 0)),
            _ => None,
        }
    }
}

/// Lowest blocks at which different parts of the state are available.
/// They may be [Some] if pruning is enabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct LowestAvailableBlocks {
    /// Lowest block number at which the account history is available. It may not be available if
    /// [`reth_prune_types::PruneSegment::AccountHistory`] was pruned.
    /// [`Option::None`] means all history is available.
    pub account_history_block_number: Option<BlockNumber>,
    /// Lowest block number at which the storage history is available. It may not be available if
    /// [`reth_prune_types::PruneSegment::StorageHistory`] was pruned.
    /// [`Option::None`] means all history is available.
    pub storage_history_block_number: Option<BlockNumber>,
}

impl LowestAvailableBlocks {
    /// Check if account history is available at the provided block number, i.e. lowest available
    /// block number for account history is less than or equal to the provided block number.
    pub fn is_account_history_available(&self, at: BlockNumber) -> bool {
        self.account_history_block_number.map(|block_number| block_number <= at).unwrap_or(true)
    }

    /// Check if storage history is available at the provided block number, i.e. lowest available
    /// block number for storage history is less than or equal to the provided block number.
    pub fn is_storage_history_available(&self, at: BlockNumber) -> bool {
        self.storage_history_block_number.map(|block_number| block_number <= at).unwrap_or(true)
    }
}

/// Computes the rank and finds the next modification block in a history shard.
///
/// Given a `block_number`, this function returns:
/// - `rank`: The number of entries strictly before `block_number` in the shard
/// - `found_block`: The block number at position `rank` (i.e., the first block >= `block_number`
///   where a modification occurred), or `None` if `rank` is out of bounds
///
/// The rank is adjusted when `block_number` exactly matches an entry in the shard,
/// so that `found_block` always returns the modification at or after the target.
///
/// This logic is shared between MDBX cursor-based lookups and `RocksDB` iterator lookups.
#[inline]
pub fn compute_history_rank(
    chunk: &reth_db_api::BlockNumberList,
    block_number: BlockNumber,
) -> (u64, Option<u64>) {
    let mut rank = chunk.rank(block_number);
    // `rank(block_number)` returns count of entries <= block_number.
    // We want the first entry >= block_number, so if block_number is in the shard,
    // we need to step back one position to point at it (not past it).
    if rank.checked_sub(1).and_then(|r| chunk.select(r)) == Some(block_number) {
        rank -= 1;
    }
    (rank, chunk.select(rank))
}

/// Checks if a previous shard lookup is needed to determine if we're before the first write.
///
/// Returns `true` when `rank == 0` (first entry in shard) and the found block doesn't match
/// the target block number. In this case, we need to check if there's a previous shard.
#[inline]
pub fn needs_prev_shard_check(
    rank: u64,
    found_block: Option<u64>,
    block_number: BlockNumber,
) -> bool {
    rank == 0 && found_block != Some(block_number)
}

/// Generic history lookup for sharded history tables.
///
/// Seeks to the shard containing `block_number`, verifies the key via `key_filter`,
/// and checks previous shard to detect if we're before the first write.
pub fn history_info<T, K, C>(
    cursor: &mut C,
    key: K,
    block_number: BlockNumber,
    key_filter: impl Fn(&K) -> bool,
    lowest_available_block_number: Option<BlockNumber>,
) -> ProviderResult<HistoryInfo>
where
    T: Table<Key = K, Value = BlockNumberList>,
    C: DbCursorRO<T>,
{
    // Lookup the history chunk in the history index. If the key does not appear in the
    // index, the first chunk for the next key will be returned so we filter out chunks that
    // have a different key.
    if let Some(chunk) = cursor.seek(key)?.filter(|(k, _)| key_filter(k)).map(|x| x.1) {
        let (rank, found_block) = compute_history_rank(&chunk, block_number);

        // If our block is before the first entry in the index chunk and this first entry
        // doesn't equal to our block, it might be before the first write ever. To check, we
        // look at the previous entry and check if the key is the same.
        // This check is worth it, the `cursor.prev()` check is rarely triggered (the if will
        // short-circuit) and when it passes we save a full seek into the changeset/plain state
        // table.
        let is_before_first_write = needs_prev_shard_check(rank, found_block, block_number) &&
            !cursor.prev()?.is_some_and(|(k, _)| key_filter(&k));

        Ok(HistoryInfo::from_lookup(
            found_block,
            is_before_first_write,
            lowest_available_block_number,
        ))
    } else if lowest_available_block_number.is_some() {
        // The key may have been written, but due to pruning we may not have changesets and
        // history, so we need to make a plain state lookup.
        Ok(HistoryInfo::MaybeInPlainState)
    } else {
        // The key has not been written to at all.
        Ok(HistoryInfo::NotYetWritten)
    }
}

#[cfg(test)]
mod tests {
    use super::needs_prev_shard_check;
    use crate::{
        providers::state::historical::{HistoryInfo, LowestAvailableBlocks, PipelineConsistency},
        test_utils::create_test_provider_factory,
        AccountReader, HistoricalStateProvider, HistoricalStateProviderRef, RocksDBProviderFactory,
        StateProvider,
    };
    use alloy_primitives::{address, b256, Address, B256, U256};
    use reth_db_api::{
        models::{storage_sharded_key::StorageShardedKey, AccountBeforeTx, ShardedKey},
        tables,
        transaction::{DbTx, DbTxMut},
        BlockNumberList,
    };
    use reth_primitives_traits::{Account, StorageEntry};
    use reth_storage_api::{
        BlockHashReader, BlockNumReader, ChangeSetReader, DBProvider, DatabaseProviderFactory,
        NodePrimitivesProvider, StorageSettingsCache,
    };
    use reth_storage_errors::provider::ProviderError;

    const ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");
    const HIGHER_ADDRESS: Address = address!("0x0000000000000000000000000000000000000005");
    const STORAGE: B256 =
        b256!("0x0000000000000000000000000000000000000000000000000000000000000001");

    const fn assert_state_provider<T: StateProvider>() {}
    #[expect(dead_code)]
    const fn assert_historical_state_provider<
        T: DBProvider
            + BlockNumReader
            + BlockHashReader
            + ChangeSetReader
            + StorageSettingsCache
            + RocksDBProviderFactory
            + NodePrimitivesProvider,
    >() {
        assert_state_provider::<HistoricalStateProvider<T>>();
    }

    #[test]
    fn history_provider_get_account() {
        let factory = create_test_provider_factory();
        let tx = factory.provider_rw().unwrap().into_tx();

        tx.put::<tables::AccountsHistory>(
            ShardedKey { key: ADDRESS, highest_block_number: 7 },
            BlockNumberList::new([1, 3, 7]).unwrap(),
        )
        .unwrap();
        tx.put::<tables::AccountsHistory>(
            ShardedKey { key: ADDRESS, highest_block_number: u64::MAX },
            BlockNumberList::new([10, 15]).unwrap(),
        )
        .unwrap();
        tx.put::<tables::AccountsHistory>(
            ShardedKey { key: HIGHER_ADDRESS, highest_block_number: u64::MAX },
            BlockNumberList::new([4]).unwrap(),
        )
        .unwrap();

        let acc_plain = Account { nonce: 100, balance: U256::ZERO, bytecode_hash: None };
        let acc_at15 = Account { nonce: 15, balance: U256::ZERO, bytecode_hash: None };
        let acc_at10 = Account { nonce: 10, balance: U256::ZERO, bytecode_hash: None };
        let acc_at7 = Account { nonce: 7, balance: U256::ZERO, bytecode_hash: None };
        let acc_at3 = Account { nonce: 3, balance: U256::ZERO, bytecode_hash: None };

        let higher_acc_plain = Account { nonce: 4, balance: U256::ZERO, bytecode_hash: None };

        // setup
        tx.put::<tables::AccountChangeSets>(1, AccountBeforeTx { address: ADDRESS, info: None })
            .unwrap();
        tx.put::<tables::AccountChangeSets>(
            3,
            AccountBeforeTx { address: ADDRESS, info: Some(acc_at3) },
        )
        .unwrap();
        tx.put::<tables::AccountChangeSets>(
            4,
            AccountBeforeTx { address: HIGHER_ADDRESS, info: None },
        )
        .unwrap();
        tx.put::<tables::AccountChangeSets>(
            7,
            AccountBeforeTx { address: ADDRESS, info: Some(acc_at7) },
        )
        .unwrap();
        tx.put::<tables::AccountChangeSets>(
            10,
            AccountBeforeTx { address: ADDRESS, info: Some(acc_at10) },
        )
        .unwrap();
        tx.put::<tables::AccountChangeSets>(
            15,
            AccountBeforeTx { address: ADDRESS, info: Some(acc_at15) },
        )
        .unwrap();

        // setup plain state
        tx.put::<tables::PlainAccountState>(ADDRESS, acc_plain).unwrap();
        tx.put::<tables::PlainAccountState>(HIGHER_ADDRESS, higher_acc_plain).unwrap();
        tx.commit().unwrap();

        let db = factory.provider().unwrap();

        // run
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 1).basic_account(&ADDRESS),
            Ok(None)
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 2).basic_account(&ADDRESS),
            Ok(Some(acc)) if acc == acc_at3
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 3).basic_account(&ADDRESS),
            Ok(Some(acc)) if acc == acc_at3
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 4).basic_account(&ADDRESS),
            Ok(Some(acc)) if acc == acc_at7
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 7).basic_account(&ADDRESS),
            Ok(Some(acc)) if acc == acc_at7
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 9).basic_account(&ADDRESS),
            Ok(Some(acc)) if acc == acc_at10
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 10).basic_account(&ADDRESS),
            Ok(Some(acc)) if acc == acc_at10
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 11).basic_account(&ADDRESS),
            Ok(Some(acc)) if acc == acc_at15
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 16).basic_account(&ADDRESS),
            Ok(Some(acc)) if acc == acc_plain
        ));

        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 1).basic_account(&HIGHER_ADDRESS),
            Ok(None)
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 1000).basic_account(&HIGHER_ADDRESS),
            Ok(Some(acc)) if acc == higher_acc_plain
        ));
    }

    #[test]
    fn history_provider_get_storage() {
        let factory = create_test_provider_factory();
        let tx = factory.provider_rw().unwrap().into_tx();

        tx.put::<tables::StoragesHistory>(
            StorageShardedKey {
                address: ADDRESS,
                sharded_key: ShardedKey { key: STORAGE, highest_block_number: 7 },
            },
            BlockNumberList::new([3, 7]).unwrap(),
        )
        .unwrap();
        tx.put::<tables::StoragesHistory>(
            StorageShardedKey {
                address: ADDRESS,
                sharded_key: ShardedKey { key: STORAGE, highest_block_number: u64::MAX },
            },
            BlockNumberList::new([10, 15]).unwrap(),
        )
        .unwrap();
        tx.put::<tables::StoragesHistory>(
            StorageShardedKey {
                address: HIGHER_ADDRESS,
                sharded_key: ShardedKey { key: STORAGE, highest_block_number: u64::MAX },
            },
            BlockNumberList::new([4]).unwrap(),
        )
        .unwrap();

        let higher_entry_plain = StorageEntry { key: STORAGE, value: U256::from(1000) };
        let higher_entry_at4 = StorageEntry { key: STORAGE, value: U256::from(0) };
        let entry_plain = StorageEntry { key: STORAGE, value: U256::from(100) };
        let entry_at15 = StorageEntry { key: STORAGE, value: U256::from(15) };
        let entry_at10 = StorageEntry { key: STORAGE, value: U256::from(10) };
        let entry_at7 = StorageEntry { key: STORAGE, value: U256::from(7) };
        let entry_at3 = StorageEntry { key: STORAGE, value: U256::from(0) };

        // setup
        tx.put::<tables::StorageChangeSets>((3, ADDRESS).into(), entry_at3).unwrap();
        tx.put::<tables::StorageChangeSets>((4, HIGHER_ADDRESS).into(), higher_entry_at4).unwrap();
        tx.put::<tables::StorageChangeSets>((7, ADDRESS).into(), entry_at7).unwrap();
        tx.put::<tables::StorageChangeSets>((10, ADDRESS).into(), entry_at10).unwrap();
        tx.put::<tables::StorageChangeSets>((15, ADDRESS).into(), entry_at15).unwrap();

        // setup plain state
        tx.put::<tables::PlainStorageState>(ADDRESS, entry_plain).unwrap();
        tx.put::<tables::PlainStorageState>(HIGHER_ADDRESS, higher_entry_plain).unwrap();
        tx.commit().unwrap();

        let db = factory.provider().unwrap();

        // run
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 0).storage(ADDRESS, STORAGE),
            Ok(None)
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 3).storage(ADDRESS, STORAGE),
            Ok(Some(U256::ZERO))
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 4).storage(ADDRESS, STORAGE),
            Ok(Some(expected_value)) if expected_value == entry_at7.value
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 7).storage(ADDRESS, STORAGE),
            Ok(Some(expected_value)) if expected_value == entry_at7.value
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 9).storage(ADDRESS, STORAGE),
            Ok(Some(expected_value)) if expected_value == entry_at10.value
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 10).storage(ADDRESS, STORAGE),
            Ok(Some(expected_value)) if expected_value == entry_at10.value
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 11).storage(ADDRESS, STORAGE),
            Ok(Some(expected_value)) if expected_value == entry_at15.value
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 16).storage(ADDRESS, STORAGE),
            Ok(Some(expected_value)) if expected_value == entry_plain.value
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 1).storage(HIGHER_ADDRESS, STORAGE),
            Ok(None)
        ));
        assert!(matches!(
            HistoricalStateProviderRef::new(&db, 1000).storage(HIGHER_ADDRESS, STORAGE),
            Ok(Some(expected_value)) if expected_value == higher_entry_plain.value
        ));
    }

    #[test]
    fn history_provider_unavailable() {
        let factory = create_test_provider_factory();
        let db = factory.database_provider_rw().unwrap();

        // provider block_number < lowest available block number,
        // i.e. state at provider block is pruned
        let provider = HistoricalStateProviderRef::new_with_lowest_available_blocks(
            &db,
            2,
            LowestAvailableBlocks {
                account_history_block_number: Some(3),
                storage_history_block_number: Some(3),
            },
        );
        assert!(matches!(
            provider.account_history_lookup(ADDRESS),
            Err(ProviderError::StateAtBlockPruned(number)) if number == provider.block_number
        ));
        assert!(matches!(
            provider.storage_history_lookup(ADDRESS, STORAGE),
            Err(ProviderError::StateAtBlockPruned(number)) if number == provider.block_number
        ));

        // provider block_number == lowest available block number,
        // i.e. state at provider block is available
        let provider = HistoricalStateProviderRef::new_with_lowest_available_blocks(
            &db,
            2,
            LowestAvailableBlocks {
                account_history_block_number: Some(2),
                storage_history_block_number: Some(2),
            },
        );
        assert!(matches!(
            provider.account_history_lookup(ADDRESS),
            Ok(HistoryInfo::MaybeInPlainState)
        ));
        assert!(matches!(
            provider.storage_history_lookup(ADDRESS, STORAGE),
            Ok(HistoryInfo::MaybeInPlainState)
        ));

        // provider block_number == lowest available block number,
        // i.e. state at provider block is available
        let provider = HistoricalStateProviderRef::new_with_lowest_available_blocks(
            &db,
            2,
            LowestAvailableBlocks {
                account_history_block_number: Some(1),
                storage_history_block_number: Some(1),
            },
        );
        assert!(matches!(
            provider.account_history_lookup(ADDRESS),
            Ok(HistoryInfo::MaybeInPlainState)
        ));
        assert!(matches!(
            provider.storage_history_lookup(ADDRESS, STORAGE),
            Ok(HistoryInfo::MaybeInPlainState)
        ));
    }

    #[test]
    fn test_history_info_from_lookup() {
        // Before first write, no pruning → not yet written
        assert_eq!(HistoryInfo::from_lookup(Some(10), true, None), HistoryInfo::NotYetWritten);
        assert_eq!(HistoryInfo::from_lookup(None, true, None), HistoryInfo::NotYetWritten);

        // Before first write WITH pruning → check changeset (pruning may have removed history)
        assert_eq!(HistoryInfo::from_lookup(Some(10), true, Some(5)), HistoryInfo::InChangeset(10));
        assert_eq!(HistoryInfo::from_lookup(None, true, Some(5)), HistoryInfo::NotYetWritten);

        // Not before first write → check changeset or plain state
        assert_eq!(HistoryInfo::from_lookup(Some(10), false, None), HistoryInfo::InChangeset(10));
        assert_eq!(HistoryInfo::from_lookup(None, false, None), HistoryInfo::InPlainState);
    }

    #[test]
    fn test_needs_prev_shard_check() {
        // Only needs check when rank == 0 and found_block != block_number
        assert!(needs_prev_shard_check(0, Some(10), 5));
        assert!(needs_prev_shard_check(0, None, 5));
        assert!(!needs_prev_shard_check(0, Some(5), 5)); // found_block == block_number
        assert!(!needs_prev_shard_check(1, Some(10), 5)); // rank > 0
    }

    #[test]
    fn pipeline_consistency_unit_logic() {
        // Consistent: execution == history
        let pc = PipelineConsistency {
            execution_tip: Some(100),
            account_history_tip: Some(100),
            storage_history_tip: Some(100),
        };
        assert!(pc.account_inconsistency().is_none());
        assert!(pc.storage_inconsistency().is_none());

        // Inconsistent: execution ahead of history
        let pc = PipelineConsistency {
            execution_tip: Some(200),
            account_history_tip: Some(100),
            storage_history_tip: Some(150),
        };
        assert_eq!(pc.account_inconsistency(), Some((200, 100)));
        assert_eq!(pc.storage_inconsistency(), Some((200, 150)));

        // History never ran (None) → treated as block 0
        let pc = PipelineConsistency {
            execution_tip: Some(50),
            account_history_tip: None,
            storage_history_tip: None,
        };
        assert_eq!(pc.account_inconsistency(), Some((50, 0)));
        assert_eq!(pc.storage_inconsistency(), Some((50, 0)));

        // Execution not run yet → consistent
        let pc = PipelineConsistency {
            execution_tip: None,
            account_history_tip: None,
            storage_history_tip: None,
        };
        assert!(pc.account_inconsistency().is_none());
        assert!(pc.storage_inconsistency().is_none());
    }

    /// Verifies selective rejection during pipeline inconsistency:
    /// - Accounts resolving via changeset path → return correct data (not blocked)
    /// - Accounts resolving via `InPlainState` path → return `HistoryStateInconsistent` error
    #[test]
    fn pipeline_consistency_selective_rejection() {
        let factory = create_test_provider_factory();
        let tx = factory.provider_rw().unwrap().into_tx();

        let no_history_addr = address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

        // History index for ADDRESS: modified at blocks 3, 7, 10, 15
        tx.put::<tables::AccountsHistory>(
            ShardedKey { key: ADDRESS, highest_block_number: 7 },
            BlockNumberList::new([3, 7]).unwrap(),
        )
        .unwrap();
        tx.put::<tables::AccountsHistory>(
            ShardedKey { key: ADDRESS, highest_block_number: u64::MAX },
            BlockNumberList::new([10, 15]).unwrap(),
        )
        .unwrap();

        // Changesets for ADDRESS
        let acc_at7 = Account { nonce: 7, balance: U256::ZERO, bytecode_hash: None };
        let acc_at10 = Account { nonce: 10, balance: U256::ZERO, bytecode_hash: None };
        tx.put::<tables::AccountChangeSets>(
            7,
            AccountBeforeTx { address: ADDRESS, info: Some(acc_at7) },
        )
        .unwrap();
        tx.put::<tables::AccountChangeSets>(
            10,
            AccountBeforeTx { address: ADDRESS, info: Some(acc_at10) },
        )
        .unwrap();

        // PlainState
        let acc_plain = Account { nonce: 100, balance: U256::ZERO, bytecode_hash: None };
        let no_hist_plain = Account { nonce: 999, balance: U256::from(999), bytecode_hash: None };
        tx.put::<tables::PlainAccountState>(ADDRESS, acc_plain).unwrap();
        tx.put::<tables::PlainAccountState>(no_history_addr, no_hist_plain).unwrap();
        tx.commit().unwrap();

        let db = factory.provider().unwrap();

        // Simulate inconsistency: Execution=200, HistoryIndex=15
        let inconsistent = PipelineConsistency {
            execution_tip: Some(200),
            account_history_tip: Some(15),
            storage_history_tip: Some(15),
        };

        // Test 1: ADDRESS at block 5 → history index finds block 7 → InChangeset → correct
        let provider =
            HistoricalStateProviderRef::new(&db, 5).with_pipeline_consistency(inconsistent);
        let result = provider.basic_account(&ADDRESS);
        assert!(result.is_ok(), "Changeset path should work during inconsistency: {result:?}");
        assert_eq!(result.unwrap().unwrap().nonce, 7);

        // Test 2: ADDRESS at block 16 → no entry after 16 → InPlainState → BLOCKED
        let provider =
            HistoricalStateProviderRef::new(&db, 16).with_pipeline_consistency(inconsistent);
        let result = provider.basic_account(&ADDRESS);
        assert!(
            matches!(result, Err(ProviderError::HistoryStateInconsistent { .. })),
            "InPlainState should be blocked: {result:?}"
        );

        // Test 3: no_history_addr at block 5 → never written to history → NotYetWritten → Ok(None)
        // This is correct: accounts that never existed in history return None regardless of
        // pipeline consistency, because they were never modified by any block.
        let provider =
            HistoricalStateProviderRef::new(&db, 5).with_pipeline_consistency(inconsistent);
        let result = provider.basic_account(&no_history_addr);
        assert!(matches!(result, Ok(None)), "Never-written account should return None: {result:?}");

        // Test 4: Same queries with consistent pipeline → all succeed
        let consistent = PipelineConsistency {
            execution_tip: Some(200),
            account_history_tip: Some(200),
            storage_history_tip: Some(200),
        };

        let provider =
            HistoricalStateProviderRef::new(&db, 16).with_pipeline_consistency(consistent);
        let result = provider.basic_account(&ADDRESS);
        assert!(result.is_ok(), "Should succeed when consistent: {result:?}");
        assert_eq!(result.unwrap().unwrap().nonce, acc_plain.nonce);

        let provider =
            HistoricalStateProviderRef::new(&db, 5).with_pipeline_consistency(consistent);
        let result = provider.basic_account(&no_history_addr);
        assert!(result.is_ok(), "Should succeed when consistent: {result:?}");
    }

    /// Verifies the gap fallback for `InPlainState` reads:
    /// - Account modified in the gap window: `find_account_before` returns the before-value at the
    ///   earliest gap block, so historical query at `query_block <= history_tip` returns the
    ///   correct historical state instead of erroring.
    /// - Account NOT modified in the gap: gap probe misses, and the historical query falls back to
    ///   `PlainState` (which correctly reflects the historical value because the account never
    ///   changed since `query_block`).
    /// - Storage same shape as account.
    /// - Query at block strictly inside the gap (`> history_tip`) still errors.
    #[test]
    fn pipeline_gap_fallback_returns_historical_state() {
        use super::PipelineGapIndex;
        use std::sync::Arc;

        let factory = create_test_provider_factory();
        let tx = factory.provider_rw().unwrap().into_tx();

        let dirty_addr = ADDRESS;
        let clean_addr = HIGHER_ADDRESS;
        let dirty_slot = STORAGE;

        // History index covers up to block 15 for both addresses. dirty_addr is modified
        // multiple times within and outside the indexed range; clean_addr is only modified at
        // block 5 (well within the indexed range and before the gap).
        tx.put::<tables::AccountsHistory>(
            ShardedKey { key: dirty_addr, highest_block_number: 7 },
            BlockNumberList::new([3, 7]).unwrap(),
        )
        .unwrap();
        tx.put::<tables::AccountsHistory>(
            ShardedKey { key: dirty_addr, highest_block_number: u64::MAX },
            BlockNumberList::new([10, 15]).unwrap(),
        )
        .unwrap();
        tx.put::<tables::AccountsHistory>(
            ShardedKey { key: clean_addr, highest_block_number: u64::MAX },
            BlockNumberList::new([5]).unwrap(),
        )
        .unwrap();
        // Match the changeset entry for clean_addr at block 5 (otherwise would-be-InChangeset
        // queries fail). For our test we only query at block 16 → InPlainState path, so the
        // changeset itself isn't read; but keep the table consistent.
        let acc_clean_at5 = Account { nonce: 0, balance: U256::ZERO, bytecode_hash: None };
        tx.put::<tables::AccountChangeSets>(
            5,
            AccountBeforeTx { address: clean_addr, info: Some(acc_clean_at5) },
        )
        .unwrap();
        // Storage history index — same shape.
        tx.put::<tables::StoragesHistory>(
            StorageShardedKey {
                address: dirty_addr,
                sharded_key: ShardedKey { key: dirty_slot, highest_block_number: u64::MAX },
            },
            BlockNumberList::new([10, 15]).unwrap(),
        )
        .unwrap();

        // Existing changesets up to block 15 (covered by history index).
        let acc_at7 = Account { nonce: 7, balance: U256::ZERO, bytecode_hash: None };
        let acc_at10 = Account { nonce: 10, balance: U256::ZERO, bytecode_hash: None };
        tx.put::<tables::AccountChangeSets>(
            7,
            AccountBeforeTx { address: dirty_addr, info: Some(acc_at7) },
        )
        .unwrap();
        tx.put::<tables::AccountChangeSets>(
            10,
            AccountBeforeTx { address: dirty_addr, info: Some(acc_at10) },
        )
        .unwrap();

        // Gap window changeset entries (history_tip=15, execution_tip=200, gap=[16, 200]):
        // - account dirty_addr modified at block 50 (was acc_gap_before).
        // - storage (dirty_addr, dirty_slot) modified at block 50 (was U256::from(42)).
        let acc_gap_before = Account { nonce: 42, balance: U256::from(42), bytecode_hash: None };
        tx.put::<tables::AccountChangeSets>(
            50,
            AccountBeforeTx { address: dirty_addr, info: Some(acc_gap_before) },
        )
        .unwrap();
        let storage_before_value = U256::from(42);
        tx.put::<tables::StorageChangeSets>(
            (50u64, dirty_addr).into(),
            StorageEntry { key: dirty_slot, value: storage_before_value },
        )
        .unwrap();

        // PlainState is "future" relative to query_block — different from historical values.
        let acc_plain = Account { nonce: 100, balance: U256::ZERO, bytecode_hash: None };
        let clean_plain = Account { nonce: 7, balance: U256::ZERO, bytecode_hash: None };
        tx.put::<tables::PlainAccountState>(dirty_addr, acc_plain).unwrap();
        tx.put::<tables::PlainAccountState>(clean_addr, clean_plain).unwrap();
        tx.put::<tables::PlainStorageState>(
            dirty_addr,
            StorageEntry { key: dirty_slot, value: U256::from(100) },
        )
        .unwrap();
        tx.commit().unwrap();

        let db = factory.provider().unwrap();
        let inconsistent = PipelineConsistency {
            execution_tip: Some(200),
            account_history_tip: Some(15),
            storage_history_tip: Some(15),
        };
        let gap = Arc::new(PipelineGapIndex::build(&db, 15, 15, 200).unwrap());

        // Sanity: the gap index should pick up the dirty entries and skip clean ones.
        assert_eq!(gap.account_first_gap_block(&dirty_addr), Some(50));
        assert!(gap.account_first_gap_block(&clean_addr).is_none());
        assert_eq!(gap.storage_first_gap_block(&dirty_addr, &dirty_slot), Some(50));

        // 1. Dirty account at block 16 → InPlainState path → gap probe hits → returns historical
        //    value (acc_gap_before), NOT PlainState.
        let provider = HistoricalStateProviderRef::new(&db, 16)
            .with_pipeline_consistency(inconsistent)
            .with_pipeline_gap_index(Some(gap.clone()));
        let result = provider.basic_account(&dirty_addr).unwrap();
        assert_eq!(result, Some(acc_gap_before), "Gap fallback must return before-value");

        // 2. Clean account at block 16 → InPlainState path → gap miss → PlainState is correct.
        let provider = HistoricalStateProviderRef::new(&db, 16)
            .with_pipeline_consistency(inconsistent)
            .with_pipeline_gap_index(Some(gap.clone()));
        let result = provider.basic_account(&clean_addr).unwrap();
        assert_eq!(result, Some(clean_plain), "Bloom miss → PlainState passthrough");

        // 3. Dirty storage slot at block 16 → InPlainState → gap hits → returns 42, not 100.
        let provider = HistoricalStateProviderRef::new(&db, 16)
            .with_pipeline_consistency(inconsistent)
            .with_pipeline_gap_index(Some(gap.clone()));
        let result = provider.storage(dirty_addr, dirty_slot).unwrap();
        assert_eq!(result, Some(storage_before_value), "Storage gap fallback");

        // 4. Query strictly inside the gap (block 100 > history_tip 15) still errors, since the gap
        //    index only tells us the FIRST gap block, not state at arbitrary mid-gap blocks.
        let provider = HistoricalStateProviderRef::new(&db, 100)
            .with_pipeline_consistency(inconsistent)
            .with_pipeline_gap_index(Some(gap));
        let result = provider.basic_account(&dirty_addr);
        assert!(
            matches!(result, Err(ProviderError::HistoryStateInconsistent { .. })),
            "Query inside gap window must still error: {result:?}"
        );

        // 5. Without a gap index attached, behavior reverts to the strict guard (rejects).
        let provider =
            HistoricalStateProviderRef::new(&db, 16).with_pipeline_consistency(inconsistent);
        let result = provider.basic_account(&dirty_addr);
        assert!(
            matches!(result, Err(ProviderError::HistoryStateInconsistent { .. })),
            "Missing gap index → strict rejection: {result:?}"
        );
    }

    /// Verifies the eager rebuild path on `ProviderFactory`:
    /// - `refresh_pipeline_gap_index` populates the cache from current stage checkpoints.
    /// - After refresh, `cached_tips` reflects the new `(execution_tip, history_tip)`.
    /// - When checkpoints flip to a no-gap state, refresh clears the cache.
    #[test]
    fn pipeline_gap_active_rebuild_via_factory() {
        use reth_db_api::transaction::DbTxMut;
        use reth_stages_types::{StageCheckpoint, StageId};
        use reth_storage_api::{StageCheckpointReader, StageCheckpointWriter};

        let factory = create_test_provider_factory();
        // Seed checkpoints + a single account/storage gap entry.
        {
            let provider_rw = factory.provider_rw().unwrap();
            provider_rw
                .save_stage_checkpoint(StageId::Execution, StageCheckpoint::new(200))
                .unwrap();
            provider_rw
                .save_stage_checkpoint(StageId::IndexAccountHistory, StageCheckpoint::new(15))
                .unwrap();
            provider_rw
                .save_stage_checkpoint(StageId::IndexStorageHistory, StageCheckpoint::new(15))
                .unwrap();
            // One account modification in the gap window so the rebuilt index is non-empty.
            let acc = Account { nonce: 1, balance: U256::ZERO, bytecode_hash: None };
            provider_rw
                .tx_ref()
                .put::<tables::AccountChangeSets>(
                    50,
                    AccountBeforeTx { address: ADDRESS, info: Some(acc) },
                )
                .unwrap();
            provider_rw.commit().unwrap();
        }

        let cache = factory.provider().unwrap().pipeline_gap_cache().clone();
        assert_eq!(cache.cached_tips(), None, "Cache starts empty");

        // Eagerly rebuild — the trait method on the factory.
        use reth_storage_api::DatabaseProviderFactory;
        factory.refresh_pipeline_gap_index().unwrap();

        let tips = cache.cached_tips().expect("Refresh should populate cache when gap exists");
        assert_eq!(tips, (200, 15, 15));

        // Flip to no-gap by advancing history checkpoints to match execution.
        {
            let provider_rw = factory.provider_rw().unwrap();
            provider_rw
                .save_stage_checkpoint(StageId::IndexAccountHistory, StageCheckpoint::new(200))
                .unwrap();
            provider_rw
                .save_stage_checkpoint(StageId::IndexStorageHistory, StageCheckpoint::new(200))
                .unwrap();
            provider_rw.commit().unwrap();
        }

        // Sanity: checkpoints actually flipped before we refresh.
        let provider_after = factory.provider().unwrap();
        assert_eq!(
            provider_after
                .get_stage_checkpoint(StageId::IndexAccountHistory)
                .unwrap()
                .map(|c| c.block_number),
            Some(200)
        );
        drop(provider_after);

        factory.refresh_pipeline_gap_index().unwrap();
        assert_eq!(cache.cached_tips(), None, "No-gap state should clear the cache");
    }

    /// Verifies the P1 fix: when account and storage history tips are different, each
    /// dimension's gap window is keyed by ITS OWN history tip — not by `min(...)`.
    ///
    /// Concretely: account A is modified at block 5 (covered by `account_history_tip = 30`) and
    /// at block 50 (in the account gap). With the old `min(account_history_tip,
    /// storage_history_tip)` logic, the index would see block 5 as "first gap modification" and
    /// `find_account_before` would return the pre-5 value — wrong, because state at end of
    /// block 30 = post-5 value (A unchanged in [6, 30]).
    ///
    /// With per-dimension tips, the account gap correctly starts at block 31, so `first_block =
    /// 50` and `find_account_before` returns pre-50 = correct state at end of block 30.
    #[test]
    fn pipeline_gap_uses_per_dimension_tips() {
        use super::PipelineGapIndex;
        use std::sync::Arc;

        let factory = create_test_provider_factory();
        let tx = factory.provider_rw().unwrap().into_tx();

        let addr = ADDRESS;
        // Account history covers up to block 30: shard contains only the block-5 modification.
        tx.put::<tables::AccountsHistory>(
            ShardedKey { key: addr, highest_block_number: u64::MAX },
            BlockNumberList::new([5]).unwrap(),
        )
        .unwrap();

        let pre_5 = Account { nonce: 0, balance: U256::ZERO, bytecode_hash: None };
        let pre_50 = Account { nonce: 5, balance: U256::ZERO, bytecode_hash: None };
        // Block 5 changeset: pre-5 value.
        tx.put::<tables::AccountChangeSets>(
            5,
            AccountBeforeTx { address: addr, info: Some(pre_5) },
        )
        .unwrap();
        // Block 50 changeset: pre-50 value (this is what the gap fallback should return for a
        // query at block 31).
        tx.put::<tables::AccountChangeSets>(
            50,
            AccountBeforeTx { address: addr, info: Some(pre_50) },
        )
        .unwrap();

        let plain = Account { nonce: 100, balance: U256::ZERO, bytecode_hash: None };
        tx.put::<tables::PlainAccountState>(addr, plain).unwrap();
        tx.commit().unwrap();

        let db = factory.provider().unwrap();
        let inconsistent = PipelineConsistency {
            execution_tip: Some(200),
            // Asymmetric: account history covers more than storage. Old min-based code would
            // collapse both gaps to (0, 200], pulling block 5 into the gap index incorrectly.
            account_history_tip: Some(30),
            storage_history_tip: Some(0),
        };

        // Build with the new per-dimension API.
        let gap = Arc::new(PipelineGapIndex::build(&db, 30, 0, 200).unwrap());
        // Account gap is (30, 200] — block 5 is OUTSIDE; block 50 is the first inside.
        assert_eq!(
            gap.account_first_gap_block(&addr),
            Some(50),
            "Account gap must use account_history_tip, not min"
        );

        // Query account A at block 31 (= account_history_tip + 1) → InPlainState path → gap
        // probe → pre-50 value.
        let provider = HistoricalStateProviderRef::new(&db, 31)
            .with_pipeline_consistency(inconsistent)
            .with_pipeline_gap_index(Some(gap));
        let result = provider.basic_account(&addr).unwrap();
        assert_eq!(result, Some(pre_50), "Per-dimension gap returns correct historical value");
    }
}
