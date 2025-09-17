use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_consensus::BlockHeader;
use alloy_genesis::Genesis;
use alloy_network::ReceiptResponse;
use alloy_primitives::{
    hex, keccak256, Address, BlockHash, BlockNumber, Bytes, B256 as H256, U256,
};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use alloy_rpc_types_eth::Header;
use reth_primitives_traits::{Block, RecoveredBlock, Transaction};
use reth_revm::db::{AccountState, Cache, CacheDB};
use revm::DatabaseRef;
use revm_bytecode::opcode::OpCode;
use revm_inspectors::tracing::types::{CallKind, CallLog, CallTraceNode, TraceMemberOrder};
use revm_inspectors::tracing::CallTraceArena;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::str::FromStr;
use tracing::info;

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable, Default)]
pub struct BlockStorageDiff {
    /// Block root hash.
    pub hash: H256,
    /// Parent block root hash.
    pub parent_hash: H256,
    /// New accounts
    pub new_accounts: Vec<NewAccount>,
    /// Deleted accounts
    pub deleted_accounts: Vec<H256>,
    /// Account storage diff
    pub storage_diffs: Vec<AccountStorageDiff>,
    /// New codes
    pub new_codes: Vec<NewCode>,
}

pub fn get_storage_contracts_from_genesis(genesis: &Genesis) -> Vec<Address> {
    let mut addresses = Vec::new();
    for (address, account) in genesis.alloc.iter() {
        if account.storage.is_some() {
            addresses.push(*address);
        }
    }
    addresses
}

pub fn get_storage_contracts_from_cache(cache: &Cache) -> Vec<Address> {
    let mut addresses = Vec::new();
    for (address, account) in cache.accounts.iter() {
        if account.storage.len() > 0 {
            addresses.push(*address);
        }
    }
    addresses
}

pub fn get_storage_diffs_from_cache<DB: DatabaseRef>(cache: Cache, pre_db: DB) -> BlockStorageDiff {
    let mut new_accounts = Vec::new();
    let mut deleted_accounts = Vec::new();
    let mut storage_diffs = Vec::new();
    let mut new_codes = Vec::new();

    // Process accounts
    for (address, db_account) in cache.accounts {
        // Check if account is deleted (non-existing)
        if db_account.account_state == AccountState::NotExisting {
            deleted_accounts.push(keccak256(address.0));
            continue;
        }

        new_accounts.push(NewAccount {
            address: keccak256(address.0),
            balance: db_account.info.balance,
            nonce: db_account.info.nonce,
            code_hash: db_account.info.code_hash,
        });

        // Collect storage changes
        if !db_account.storage.is_empty() {
            let diffs: Vec<IndexValuePair> = db_account
                .storage
                .into_iter()
                .map(|(key, value)| IndexValuePair {
                    index: keccak256::<[u8; 32]>(key.to_be_bytes()),
                    value,
                })
                .collect();

            if !diffs.is_empty() {
                storage_diffs.push(AccountStorageDiff { address: keccak256(address.0), diffs });
            }
        }

        if let Some(code) = db_account.info.code {
            let code_hash = db_account.info.code_hash;
            if let Ok(Some(account)) = pre_db.basic_ref(address) {
                if account.code_hash == code_hash {
                    continue; // Code already exists in the previous state
                }
            }
            new_codes.push(NewCode { code_hash, code: code.bytes() });
        }
    }

    BlockStorageDiff {
        hash: H256::ZERO,        // These will need to be set by the caller
        parent_hash: H256::ZERO, // These will need to be set by the caller
        new_accounts,
        deleted_accounts,
        storage_diffs,
        new_codes,
    }
}

impl From<&Genesis> for BlockStorageDiff {
    fn from(genesis: &Genesis) -> Self {
        let mut new_accounts = Vec::new();
        let mut new_codes = Vec::new();
        let mut storage_diffs = Vec::new();

        for (address, account) in genesis.alloc.iter() {
            let code_hash = if account.code.is_none() {
                KECCAK_EMPTY
            } else {
                let code_hash = keccak256(account.code.as_ref().unwrap());
                new_codes.push(NewCode { code_hash, code: account.code.clone().unwrap().into() });
                code_hash
            };

            new_accounts.push(NewAccount {
                address: keccak256(address.0),
                balance: account.balance,
                nonce: account.nonce.unwrap_or_default(),
                code_hash,
            });

            if let Some(storage) = &account.storage {
                let mut diffs: Vec<IndexValuePair> = vec![];
                for (key, value) in storage.iter() {
                    diffs.push(IndexValuePair {
                        index: keccak256::<[u8; 32]>(key.0),
                        value: U256::from_be_bytes(value.0),
                    });
                }
                if !diffs.is_empty() {
                    storage_diffs.push(AccountStorageDiff { address: keccak256(address.0), diffs });
                }
            }
        }

        BlockStorageDiff {
            hash: H256::ZERO, // These will need to be set by the caller
            parent_hash: KECCAK_EMPTY,
            new_accounts,
            deleted_accounts: vec![],
            storage_diffs,
            new_codes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct NewCode {
    pub code_hash: H256,
    pub code: Bytes,
}

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct NewAccount {
    /// Account address
    pub address: H256,
    /// Account balance
    pub balance: U256,
    /// Account nonce
    pub nonce: u64,
    /// code hash
    pub code_hash: H256,
}

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct AccountStorageDiff {
    pub address: H256,
    pub diffs: Vec<IndexValuePair>,
}

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct IndexValuePair {
    pub index: H256,
    pub value: U256,
}

pub fn calc_validation_hash(ids: &[String]) -> i64 {
    let mut sha1_sum = U256::from(0);
    for each in ids {
        let mut hasher = Sha1::new();
        hasher.update(each.as_bytes());
        let hash_int = U256::from_str_radix(&hex::encode(hasher.finalize()), 16)
            .unwrap_or_else(|_| panic!("Failed to convert id {} to U256", each));
        sha1_sum += hash_int;
    }
    let sha1_sum_str = sha1_sum.to_string();
    let last_6_digits = if sha1_sum_str.len() >= 6 {
        &sha1_sum_str[sha1_sum_str.len().saturating_sub(6)..]
    } else {
        &sha1_sum_str
    };

    i64::from_str(last_6_digits).unwrap_or(0)
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(default)]
pub struct DebankBlock {
    pub id: BlockHash,
    pub height: BlockNumber,
    pub parent_id: BlockHash,
    pub base_fee_per_gas: Option<u64>,
    pub miner: Address,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub process_start_timestamp: u64,
}

impl<B: Block> From<&RecoveredBlock<B>> for DebankBlock {
    fn from(block: &RecoveredBlock<B>) -> Self {
        Self {
            id: block.hash(),
            height: block.header().number(),
            parent_id: block.header().parent_hash(),
            base_fee_per_gas: block.header().base_fee_per_gas(),
            miner: block.header().beneficiary(),
            gas_limit: block.header().gas_limit(),
            gas_used: block.header().gas_used(),
            timestamp: block.header().timestamp(),
            process_start_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(default)]
pub struct DebankTransaction {
    pub id: BlockHash,
    #[serde(rename = "from_addr")]
    pub from: Address,
    #[serde(rename = "to_addr")]
    pub to: Address,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub gas_used: u64,
    pub status: bool,
    #[serde(rename = "max_fee_per_gas")]
    pub gas_fee_cap: u128,
    #[serde(rename = "max_priority_fee_per_gas")]
    pub gas_tip_cap: u128,
    pub input: Bytes,
    pub nonce: u64,
    #[serde(rename = "idx")]
    pub transaction_index: u64,
    pub value: U256,
}

impl<R, T> From<(&R, &T)> for DebankTransaction
where
    R: ReceiptResponse,
    T: Transaction,
{
    fn from((receipt, tx): (&R, &T)) -> Self {
        Self {
            id: receipt.transaction_hash(),
            from: receipt.from(),
            to: receipt.to().unwrap_or_default(),
            gas_limit: tx.gas_limit(),
            gas_price: receipt.effective_gas_price(),
            gas_used: receipt.gas_used(),
            status: receipt.status(),
            gas_fee_cap: tx.max_fee_per_gas(),
            gas_tip_cap: tx.max_priority_fee_per_gas().unwrap_or_default(),
            input: tx.input().clone(),
            nonce: tx.nonce(),
            transaction_index: receipt.transaction_index().unwrap_or(0),
            value: tx.value(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DebankEvent {
    pub id: String,
    pub contract_id: Address,
    pub selector: String,
    pub topics: Vec<String>,
    pub data: Bytes,
    pub tx_id: H256,
    pub parent_trace_id: String,
    pub pos_in_parent_trace: usize,
    pub idx: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DebankTrace {
    pub id: String,
    pub from_addr: Address,
    pub gas_limit: u64,
    pub input: Bytes,
    pub to_addr: Address,
    pub value: U256,
    pub gas_used: u64,
    pub output: Bytes,
    #[serde(rename = "type")]
    pub call_create_type: String,
    pub call_type: String,
    pub tx_id: H256,
    pub parent_trace_id: String,
    pub pos_in_parent_trace: usize,
    pub self_storage_change: bool,
    pub storage_change: bool,
    pub subtraces: usize,
    pub trace_address: Vec<usize>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BlockValidation {
    pub validation_hash: i64,
    pub is_fork: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(default)]
pub struct BlockFile {
    pub block: DebankBlock,
    #[serde(rename = "txs")]
    pub transactions: Vec<DebankTransaction>,
    pub events: Vec<DebankEvent>,
    pub traces: Vec<DebankTrace>,
    pub error_events: Vec<DebankEvent>,
    pub error_traces: Vec<DebankTrace>,
    pub storage_contracts: Vec<Address>,
}

impl BlockFile {
    pub fn validation(&self) -> BlockValidation {
        let mut ids = Vec::new();
        ids.push(self.block.id.to_string());
        for transaction in self.transactions.iter() {
            ids.push(transaction.id.to_string());
        }
        for event in self.events.iter() {
            ids.push(event.id.clone())
        }
        for trace in self.traces.iter() {
            ids.push(trace.id.clone())
        }
        BlockValidation { validation_hash: calc_validation_hash(&ids), is_fork: false }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DebankOutPut {
    pub block_file: BlockFile,
    pub header: Header,
    pub state_diff: Bytes,
    pub validation_hash: i64,
}

pub trait DebankID {
    fn debank_id(&self) -> String;

    fn calculate_id(args: Vec<&str>) -> String {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        for arg in args {
            hasher.update(arg.as_bytes());
        }
        let result = hasher.finalize();
        format!("{:x}", result)
    }
}

impl DebankID for DebankEvent {
    fn debank_id(&self) -> String {
        Self::calculate_id(vec![&self.parent_trace_id, &self.pos_in_parent_trace.to_string()])
    }
}

impl DebankID for DebankTrace {
    fn debank_id(&self) -> String {
        Self::calculate_id(vec![
            &self.tx_id.to_string(),
            &self.parent_trace_id,
            &self.pos_in_parent_trace.to_string(),
        ])
    }
}

impl From<&CallTraceNode> for DebankTrace {
    fn from(call_trace: &CallTraceNode) -> Self {
        let trace = &call_trace.trace;
        let mut call_create_type = match trace.kind {
            CallKind::Call
            | CallKind::StaticCall
            | CallKind::CallCode
            | CallKind::DelegateCall
            | CallKind::AuthCall => "call".to_string(),
            CallKind::Create => "create".to_string(),
            CallKind::Create2 => "create2".to_string(),
        };
        if call_trace.is_selfdestruct() {
            call_create_type = "suicide".to_string();
        }
        let mut call_type = "".to_string();
        if call_create_type == "call" {
            call_type = trace.kind.to_string().to_lowercase();
        }
        let mut debank_trace = DebankTrace {
            id: "".to_string(),
            from_addr: trace.caller,
            gas_limit: trace.gas_limit,
            input: trace.data.clone(),
            to_addr: trace.address,
            value: trace.value,
            gas_used: trace.gas_used,
            output: trace.output.clone(),
            call_create_type,
            call_type,
            subtraces: call_trace.children.len(),
            ..Default::default()
        };
        if call_trace.is_selfdestruct() {
            debank_trace.call_create_type = "suicide".to_string();
        }
        for op in trace.steps.iter() {
            if op.op == OpCode::SSTORE {
                debank_trace.self_storage_change = true;
                debank_trace.storage_change = true;
            }
        }
        debank_trace
    }
}

impl From<&CallLog> for DebankEvent {
    fn from(log: &CallLog) -> Self {
        let selector = log.raw_log.topics().first().map(|h| h.to_string()).unwrap_or_default();
        let topics = if log.raw_log.topics().len() > 1 {
            log.raw_log.topics()[1..].iter().map(|h| h.to_string()).collect()
        } else {
            vec![]
        };

        DebankEvent { selector, topics, data: log.raw_log.data.clone(), ..Default::default() }
    }
}

enum DebankTraceOrLog {
    Trace(DebankTraceNode),
    Log(DebankEvent),
}

struct DebankTraceNode {
    trace: DebankTrace,
    children: Vec<DebankTraceOrLog>,
    success: bool,
}

fn build_trace_node(
    tx_id: H256,
    parent_trace_id: String,
    pos_in_parent_trace: usize,
    node: &CallTraceNode,
    nodes: &Vec<CallTraceNode>,
    parent_success: bool,
    trace_address: Vec<usize>,
) -> DebankTraceNode {
    let mut debank_node = DebankTraceNode {
        trace: node.into(),
        children: Vec::new(),
        success: node.trace.success && parent_success,
    };
    debank_node.trace.trace_address = trace_address.clone();
    debank_node.trace.parent_trace_id = parent_trace_id;
    debank_node.trace.pos_in_parent_trace = pos_in_parent_trace;
    debank_node.trace.tx_id = tx_id;
    debank_node.trace.id = debank_node.trace.debank_id();

    let id = debank_node.trace.id.clone();
    let contract_id = node.execution_address();

    for pos in node.ordering.iter() {
        match &pos {
            TraceMemberOrder::Call(i) => {
                let child_node = &nodes[node.children[*i]];
                if !child_node.trace.success {
                    continue;
                }
                let mut trace_address = trace_address.clone();
                trace_address.push(*i);
                let child_trace = build_trace_node(
                    tx_id,
                    id.clone(),
                    debank_node.children.len(),
                    child_node,
                    nodes,
                    debank_node.success,
                    trace_address,
                );
                if child_trace.trace.storage_change {
                    debank_node.trace.storage_change = true;
                }
                debank_node.children.push(DebankTraceOrLog::Trace(child_trace));
            }
            TraceMemberOrder::Log(i) => {
                let mut child_event: DebankEvent = (&node.logs[*i]).into();
                child_event.pos_in_parent_trace = debank_node.children.len();
                child_event.contract_id = contract_id;
                child_event.tx_id = tx_id;
                child_event.parent_trace_id = id.clone();
                child_event.id = child_event.debank_id();
                debank_node.children.push(DebankTraceOrLog::Log(child_event));
            }
            _ => {}
        }
    }
    debank_node
}

fn finish_build_traces(
    node: &mut DebankTraceNode,
    traces: &mut Vec<DebankTrace>,
    error_traces: &mut Vec<DebankTrace>,
    events: &mut Vec<DebankEvent>,
    error_events: &mut Vec<DebankEvent>,
) {
    if node.success {
        traces.push(node.trace.clone());
    } else {
        error_traces.push(node.trace.clone());
    }

    for child in node.children.iter_mut() {
        match child {
            DebankTraceOrLog::Trace(trace) => {
                trace.trace.parent_trace_id = node.trace.id.clone();
                finish_build_traces(trace, traces, error_traces, events, error_events);
            }
            DebankTraceOrLog::Log(log) => {
                if node.success {
                    events.push(log.clone());
                } else {
                    error_events.push(log.clone());
                }
            }
        }
    }
}

pub fn build_debank_traces(
    tx_id: H256,
    traces: CallTraceArena,
) -> (Vec<DebankTrace>, Vec<DebankTrace>, Vec<DebankEvent>, Vec<DebankEvent>) {
    let nodes = traces.into_nodes();
    if nodes.is_empty() {
        return (vec![], vec![], vec![], vec![]);
    }
    let mut top = build_trace_node(tx_id, "".to_string(), 0, &nodes[0], &nodes, true, vec![]);
    let mut traces = vec![];
    let mut error_traces = vec![];
    let mut events = vec![];
    let mut error_events = vec![];
    finish_build_traces(&mut top, &mut traces, &mut error_traces, &mut events, &mut error_events);
    (traces, error_traces, events, error_events)
}
