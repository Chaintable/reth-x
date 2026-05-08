use alloy_consensus::{constants::KECCAK_EMPTY, BlockHeader};
use alloy_genesis::Genesis;
use alloy_network::ReceiptResponse;
use alloy_primitives::{
    hex, keccak256, Address, BlockHash, BlockNumber, Bytes, B256 as H256, U256,
};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use alloy_rpc_types_eth::Header;
use reth_primitives_traits::{Block, RecoveredBlock, Transaction};
use reth_trie::EMPTY_ROOT_HASH;
use revm::{database::BundleState, interpreter::InstructionResult, DatabaseRef};
use revm_bytecode::opcode::OpCode;
use revm_inspectors::tracing::{
    types::{CallKind, CallLog, CallTraceNode, TraceMemberOrder},
    CallTraceArena,
};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::str::FromStr;

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

pub fn get_storage_contracts_from_bundle(bundle: &BundleState) -> Vec<Address> {
    bundle
        .state
        .iter()
        .filter_map(|(address, account)| (!account.storage.is_empty()).then_some(*address))
        .collect()
}

pub fn get_storage_diffs_from_bundle<DB: DatabaseRef>(
    bundle: BundleState,
    pre_db: DB,
) -> BlockStorageDiff {
    let mut new_accounts = Vec::new();
    let mut deleted_accounts = Vec::new();
    let mut storage_diffs = Vec::new();
    let mut new_codes = Vec::new();

    for (address, account) in bundle.state {
        let Some(info) = account.info else {
            deleted_accounts.push(keccak256(address.0));
            continue;
        };

        new_accounts.push(NewAccount {
            address: keccak256(address.0),
            balance: info.balance,
            nonce: info.nonce,
            code_hash: info.code_hash,
        });

        if !account.storage.is_empty() {
            let diffs: Vec<IndexValuePair> = account
                .storage
                .into_iter()
                .map(|(key, slot)| IndexValuePair {
                    index: keccak256::<[u8; 32]>(key.to_be_bytes()),
                    value: slot.present_value,
                })
                .collect();

            if !diffs.is_empty() {
                storage_diffs.push(AccountStorageDiff { address: keccak256(address.0), diffs });
            }
        }

        if let Some(code) = info.code {
            let code_hash = info.code_hash;
            if let Ok(Some(prev)) = pre_db.basic_ref(address) {
                if prev.code_hash == code_hash {
                    continue;
                }
            }
            new_codes.push(NewCode { code_hash, code: code.original_bytes() });
        }
    }

    BlockStorageDiff {
        hash: H256::ZERO,
        parent_hash: H256::ZERO,
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
            parent_hash: EMPTY_ROOT_HASH,
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
    pub process_start_timestamp: u128,
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
                .as_millis(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(default)]
pub struct DebankTransaction {
    pub id: String,
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
            id: receipt.transaction_hash().to_string(),
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
    pub tx_id: String,
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
            &self.tx_id,
            &self.parent_trace_id,
            &self.pos_in_parent_trace.to_string(),
        ])
    }
}

pub(crate) fn fmt_error_msg(res: InstructionResult) -> Option<String> {
    if res.is_ok() {
        return None;
    }
    let msg = match res {
        InstructionResult::Revert => "Reverted".to_string(),
        InstructionResult::OutOfGas |
        InstructionResult::PrecompileOOG |
        InstructionResult::MemoryOOG |
        InstructionResult::MemoryLimitOOG |
        InstructionResult::InvalidOperandOOG |
        InstructionResult::ReentrancySentryOOG => "Out of gas".to_string(),
        InstructionResult::OutOfFunds => "Insufficient balance for transfer".to_string(),
        InstructionResult::OpcodeNotFound | InstructionResult::InvalidFEOpcode => {
            "Bad instruction".to_string()
        }
        InstructionResult::StackOverflow => "Out of stack".to_string(),
        InstructionResult::InvalidJump => "Bad jump destination".to_string(),
        InstructionResult::PrecompileError => "Built-in failed".to_string(),
        status => format!("{status:?}"),
    };
    Some(msg)
}

impl From<&CallTraceNode> for DebankTrace {
    fn from(call_trace: &CallTraceNode) -> Self {
        let trace = &call_trace.trace;
        let call_create_type = match trace.kind {
            CallKind::Call |
            CallKind::StaticCall |
            CallKind::CallCode |
            CallKind::DelegateCall |
            CallKind::AuthCall => "call".to_string(),
            CallKind::Create => "create".to_string(),
            CallKind::Create2 => "create2".to_string(),
        };
        let mut call_type = "".to_string();
        if call_create_type == "call" {
            call_type = trace.kind.to_string().to_lowercase();
        }
        let error = trace.status.and_then(fmt_error_msg);
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
            error: error.unwrap_or_default(),
            ..Default::default()
        };
        for op in trace.steps.iter() {
            if op.op == OpCode::SSTORE {
                debank_trace.self_storage_change = true;
                debank_trace.storage_change = true;
                break;
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
    tx_id: String,
    parent_trace_id: String,
    pos_in_parent_trace: usize,
    node: &CallTraceNode,
    nodes: &Vec<CallTraceNode>,
    parent_success: bool,
    trace_address: Vec<usize>,
    log_index: &mut usize,
) -> DebankTraceNode {
    let mut debank_node = DebankTraceNode {
        trace: node.into(),
        children: Vec::new(),
        success: node.trace.success && parent_success,
    };
    debank_node.trace.trace_address = trace_address.clone();
    debank_node.trace.parent_trace_id = parent_trace_id;
    debank_node.trace.pos_in_parent_trace = pos_in_parent_trace;
    debank_node.trace.tx_id = tx_id.clone();
    debank_node.trace.id = debank_node.trace.debank_id();

    let id = debank_node.trace.id.clone();
    let contract_id = node.execution_address();

    let mut child_trace_address = Vec::new();
    for pos in node.ordering.iter() {
        match &pos {
            TraceMemberOrder::Call(i) => {
                let child_node = &nodes[node.children[*i]];
                let mut trace_address = trace_address.clone();
                trace_address.push(*i);
                child_trace_address = trace_address.clone();
                let child_trace = build_trace_node(
                    tx_id.clone(),
                    id.clone(),
                    debank_node.children.len(),
                    child_node,
                    nodes,
                    parent_success && debank_node.success,
                    trace_address,
                    log_index,
                );
                if child_trace.trace.storage_change && child_node.trace.success {
                    debank_node.trace.storage_change = true;
                }
                debank_node.children.push(DebankTraceOrLog::Trace(child_trace));
            }
            TraceMemberOrder::Log(i) => {
                let mut child_event: DebankEvent = (&node.logs[*i]).into();
                child_event.pos_in_parent_trace = debank_node.children.len();
                child_event.contract_id = contract_id;
                child_event.parent_trace_id = id.clone();
                child_event.id = child_event.debank_id();
                child_event.idx = *log_index;
                if debank_node.success {
                    *log_index += 1;
                }
                debank_node.children.push(DebankTraceOrLog::Log(child_event));
            }
            _ => {}
        }
    }
    // selfdestructs are not recorded as individual call traces but are derived from
    // the call trace and are added as additional `TransactionTrace` objects in the
    // trace array
    if node.is_selfdestruct() {
        child_trace_address.last_mut().map(|last| *last += 1);
        debank_node.trace.subtraces += 1;
        let mut selfdestruct_trace = DebankTrace {
            from_addr: node.trace.selfdestruct_address.unwrap_or_default(),
            to_addr: node.trace.selfdestruct_refund_target.unwrap_or_default(),
            value: node.trace.selfdestruct_transferred_value.unwrap_or_default(),
            trace_address: child_trace_address,
            parent_trace_id: id.clone(),
            pos_in_parent_trace: debank_node.children.len(),
            tx_id: tx_id.clone(),
            call_create_type: "suicide".to_string(),
            ..Default::default()
        };
        selfdestruct_trace.id = selfdestruct_trace.debank_id();
        debank_node.children.push(DebankTraceOrLog::Trace(DebankTraceNode {
            trace: selfdestruct_trace,
            children: vec![],
            success: parent_success && debank_node.success,
        }));
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
    log_index: &std::cell::RefCell<usize>,
) -> (Vec<DebankTrace>, Vec<DebankTrace>, Vec<DebankEvent>, Vec<DebankEvent>) {
    let nodes = traces.into_nodes();
    if nodes.is_empty() {
        return (vec![], vec![], vec![], vec![]);
    }
    let mut top = build_trace_node(
        tx_id.to_string(),
        "".to_string(),
        0,
        &nodes[0],
        &nodes,
        true,
        vec![],
        &mut log_index.borrow_mut(),
    );
    let mut traces = vec![];
    let mut error_traces = vec![];
    let mut events = vec![];
    let mut error_events = vec![];
    finish_build_traces(&mut top, &mut traces, &mut error_traces, &mut events, &mut error_events);
    (traces, error_traces, events, error_events)
}

/// Build genesis transactions and traces from genesis alloc
/// This corresponds to the Go implementation in pipeline_tracer.go line 344-500
pub fn build_genesis_txs_and_traces(
    genesis: &Genesis,
) -> (Vec<DebankTransaction>, Vec<DebankTrace>) {
    let zero_addr = Address::ZERO;
    let mut tx_idx: u64 = 0;
    let mut txs = Vec::new();
    let mut traces = Vec::new();

    // Sort addresses to ensure deterministic traversal order
    let mut sorted_addrs: Vec<&Address> = genesis.alloc.keys().collect();
    sorted_addrs.sort_by(|a, b| a.to_string().to_lowercase().cmp(&b.to_string().to_lowercase()));

    for addr in sorted_addrs {
        let account = &genesis.alloc[addr];
        let addr_lower = format!("{:?}", addr).to_lowercase();

        // Process accounts with balance - construct transfer tx and call trace
        if account.balance > U256::ZERO {
            // tx id: 0xgenesis01 + 13 zeros + address(42 chars) = 67 chars
            let tx_id = format!("0xgenesis01{:013}{}", 0, addr_lower);

            let tx = DebankTransaction {
                id: tx_id.clone(),
                from: zero_addr,
                to: *addr,
                gas_limit: 0,
                gas_price: 0,
                gas_used: 0,
                status: true,
                gas_fee_cap: 0,
                gas_tip_cap: 0,
                input: Bytes::default(),
                nonce: 0,
                transaction_index: tx_idx,
                value: account.balance,
            };
            txs.push(tx);

            // trace id = hash(tx_id, parent_trace_id, pos_in_parent_trace)
            let trace_id = DebankTrace::calculate_id(vec![&tx_id, "", "0"]);
            let trace = DebankTrace {
                id: trace_id,
                from_addr: zero_addr,
                gas_limit: 0,
                input: Bytes::default(),
                to_addr: *addr,
                value: account.balance,
                gas_used: 0,
                output: Bytes::default(),
                call_create_type: "call".to_string(),
                call_type: "call".to_string(),
                tx_id,
                parent_trace_id: "".to_string(),
                pos_in_parent_trace: 0,
                self_storage_change: false,
                storage_change: false,
                subtraces: 0,
                trace_address: vec![],
                error: "".to_string(),
            };
            traces.push(trace);
            tx_idx += 1;
        }

        // Process accounts with code - construct create tx and create trace
        if let Some(ref code) = account.code {
            if !code.is_empty() {
                // tx id: 0xgenesis02 + 13 zeros + address(42 chars) = 67 chars
                let tx_id = format!("0xgenesis02{:013}{}", 0, addr_lower);

                let tx = DebankTransaction {
                    id: tx_id.clone(),
                    from: zero_addr,
                    to: *addr,
                    gas_limit: 0,
                    gas_price: 0,
                    gas_used: 0,
                    status: true,
                    gas_fee_cap: 0,
                    gas_tip_cap: 0,
                    input: code.clone(),
                    nonce: 0,
                    transaction_index: tx_idx,
                    value: U256::ZERO,
                };
                txs.push(tx);

                // trace id = hash(tx_id, parent_trace_id, pos_in_parent_trace)
                let trace_id = DebankTrace::calculate_id(vec![&tx_id, "", "0"]);
                let trace = DebankTrace {
                    id: trace_id,
                    from_addr: zero_addr,
                    gas_limit: 0,
                    input: code.clone(),
                    to_addr: *addr,
                    value: U256::ZERO,
                    gas_used: 0,
                    output: code.clone(), // output directly uses input (code)
                    call_create_type: "create".to_string(),
                    call_type: "".to_string(),
                    tx_id,
                    parent_trace_id: "".to_string(),
                    pos_in_parent_trace: 0,
                    self_storage_change: false,
                    storage_change: false,
                    subtraces: 0,
                    trace_address: vec![],
                    error: "".to_string(),
                };
                traces.push(trace);
                tx_idx += 1;
            }
        }
    }

    // Add native token contract creation tx and trace (E address: 0xeeee...eeee)
    let native_token_addr =
        Address::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
    let native_token_addr_lower = format!("{:?}", native_token_addr).to_lowercase();
    let native_token_tx_id = format!("0xgenesis03{:013}{}", 0, native_token_addr_lower);

    let native_token_tx = DebankTransaction {
        id: native_token_tx_id.clone(),
        from: zero_addr,
        to: native_token_addr,
        gas_limit: 0,
        gas_price: 0,
        gas_used: 0,
        status: true,
        gas_fee_cap: 0,
        gas_tip_cap: 0,
        input: Bytes::default(),
        nonce: 0,
        transaction_index: tx_idx,
        value: U256::ZERO,
    };
    txs.push(native_token_tx);

    let native_token_trace_id = DebankTrace::calculate_id(vec![&native_token_tx_id, "", "0"]);
    let native_token_trace = DebankTrace {
        id: native_token_trace_id,
        from_addr: zero_addr,
        gas_limit: 0,
        input: Bytes::default(),
        to_addr: native_token_addr,
        value: U256::ZERO,
        gas_used: 0,
        output: Bytes::default(),
        call_create_type: "create".to_string(),
        call_type: "".to_string(),
        tx_id: native_token_tx_id,
        parent_trace_id: "".to_string(),
        pos_in_parent_trace: 0,
        self_storage_change: false,
        storage_change: false,
        subtraces: 0,
        trace_address: vec![],
        error: "".to_string(),
    };
    traces.push(native_token_trace);

    (txs, traces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::map::AddressMap;
    use reth_revm::db::{AccountState, Cache, DbAccount};
    use revm::{
        database::{
            states::{plain_account::StorageSlot, AccountStatus, BundleAccount},
            EmptyDB,
        },
        state::{AccountInfo, Bytecode},
    };
    use std::collections::BTreeMap;

    pub fn get_storage_contracts_from_cache(cache: &Cache) -> Vec<Address> {
        let mut addresses = Vec::new();
        for (address, account) in cache.accounts.iter() {
            if account.storage.len() > 0 {
                addresses.push(*address);
            }
        }
        addresses
    }

    pub fn get_storage_diffs_from_cache<DB: DatabaseRef>(
        cache: Cache,
        pre_db: DB,
    ) -> BlockStorageDiff {
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
                new_codes.push(NewCode { code_hash, code: code.original_bytes() });
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

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn slot(value: u64) -> U256 {
        U256::from(value)
    }

    fn info(balance: u64, nonce: u64, code: Option<Bytecode>) -> AccountInfo {
        let code_hash = code.as_ref().map(|c| c.hash_slow()).unwrap_or(KECCAK_EMPTY);
        AccountInfo { balance: U256::from(balance), nonce, code_hash, code, account_id: None }
    }

    #[derive(Default)]
    struct Fixture {
        cache: Cache,
        bundle_state: AddressMap<BundleAccount>,
    }

    impl Fixture {
        fn add_account(
            &mut self,
            address: Address,
            account_state: AccountState,
            account_info: AccountInfo,
            storage: BTreeMap<U256, U256>,
            status: AccountStatus,
        ) {
            let storage_map: alloy_primitives::map::HashMap<_, _, _> =
                storage.iter().map(|(k, v)| (*k, *v)).collect();
            self.cache.accounts.insert(
                address,
                DbAccount { info: account_info.clone(), account_state, storage: storage_map },
            );

            let bundle_storage: alloy_primitives::map::HashMap<_, _, _> = storage
                .into_iter()
                .map(|(k, v)| (k, StorageSlot::new_changed(U256::ZERO, v)))
                .collect();
            self.bundle_state.insert(
                address,
                BundleAccount::new(None, Some(account_info), bundle_storage, status),
            );
        }

        fn add_deleted(&mut self, address: Address, original: AccountInfo) {
            self.cache.accounts.insert(address, DbAccount::new_not_existing());
            self.bundle_state.insert(
                address,
                BundleAccount::new(
                    Some(original),
                    None,
                    Default::default(),
                    AccountStatus::Destroyed,
                ),
            );
        }

        fn build(self) -> (Cache, BundleState) {
            let mut bundle = BundleState::default();
            bundle.state = self.bundle_state;
            (self.cache, bundle)
        }
    }

    fn sort_diff(d: &mut BlockStorageDiff) {
        d.new_accounts.sort_by_key(|a| a.address);
        d.deleted_accounts.sort();
        for s in &mut d.storage_diffs {
            s.diffs.sort_by_key(|p| p.index);
        }
        d.storage_diffs.sort_by_key(|s| s.address);
        d.new_codes.sort_by_key(|c| c.code_hash);
    }

    fn assert_equivalent(cache: Cache, bundle: BundleState) {
        let pre_db = EmptyDB::default();
        let mut from_cache = get_storage_diffs_from_cache(cache, &pre_db);
        let mut from_bundle = get_storage_diffs_from_bundle(bundle, &pre_db);
        sort_diff(&mut from_cache);
        sort_diff(&mut from_bundle);
        assert_eq!(from_cache, from_bundle);
    }

    #[test]
    fn equivalence_new_account_with_balance() {
        let mut f = Fixture::default();
        f.add_account(
            addr(1),
            AccountState::Touched,
            info(1_000, 0, None),
            BTreeMap::new(),
            AccountStatus::InMemoryChange,
        );
        let (cache, bundle) = f.build();
        assert_equivalent(cache, bundle);
    }

    #[test]
    fn equivalence_deleted_account() {
        let mut f = Fixture::default();
        f.add_deleted(addr(2), info(500, 1, None));
        let (cache, bundle) = f.build();
        assert_equivalent(cache, bundle);
    }

    #[test]
    fn equivalence_storage_modification() {
        let mut f = Fixture::default();
        let mut storage = BTreeMap::new();
        storage.insert(slot(0), U256::from(42));
        storage.insert(slot(1), U256::from(99));
        f.add_account(
            addr(3),
            AccountState::Touched,
            info(0, 5, None),
            storage,
            AccountStatus::Changed,
        );
        let (cache, bundle) = f.build();
        assert_equivalent(cache, bundle);
    }

    #[test]
    fn equivalence_new_contract_deployment() {
        let mut f = Fixture::default();
        let code = Bytecode::new_raw(vec![0x60, 0x00, 0x60, 0x00].into());
        let mut storage = BTreeMap::new();
        storage.insert(slot(0), U256::from(1));
        f.add_account(
            addr(4),
            AccountState::Touched,
            info(0, 1, Some(code)),
            storage,
            AccountStatus::InMemoryChange,
        );
        let (cache, bundle) = f.build();
        assert_equivalent(cache, bundle);
    }

    #[test]
    fn equivalence_existing_contract_storage_change() {
        let mut f = Fixture::default();
        let mut storage = BTreeMap::new();
        storage.insert(slot(7), U256::from(123));
        f.add_account(
            addr(5),
            AccountState::Touched,
            info(100, 10, None),
            storage,
            AccountStatus::Changed,
        );
        let (cache, bundle) = f.build();
        assert_equivalent(cache, bundle);
    }

    #[test]
    fn equivalence_system_call_storage_only_write() {
        let mut f = Fixture::default();
        let mut storage = BTreeMap::new();
        storage.insert(slot(0), U256::from(0xdeadbeefu64));
        f.add_account(
            addr(6),
            AccountState::Touched,
            info(0, 0, None),
            storage,
            AccountStatus::InMemoryChange,
        );
        let (cache, bundle) = f.build();
        assert_equivalent(cache, bundle);
    }

    #[test]
    fn equivalence_combined_scenario() {
        let mut f = Fixture::default();
        f.add_account(
            addr(1),
            AccountState::Touched,
            info(1_000, 0, None),
            BTreeMap::new(),
            AccountStatus::InMemoryChange,
        );
        f.add_deleted(addr(2), info(500, 1, None));
        let mut storage3 = BTreeMap::new();
        storage3.insert(slot(0), U256::from(42));
        f.add_account(
            addr(3),
            AccountState::Touched,
            info(0, 5, None),
            storage3,
            AccountStatus::Changed,
        );
        let code = Bytecode::new_raw(vec![0x60, 0x00].into());
        let mut storage4 = BTreeMap::new();
        storage4.insert(slot(0), U256::from(1));
        f.add_account(
            addr(4),
            AccountState::Touched,
            info(0, 1, Some(code)),
            storage4,
            AccountStatus::InMemoryChange,
        );
        let (cache, bundle) = f.build();
        assert_equivalent(cache, bundle);
    }
}
