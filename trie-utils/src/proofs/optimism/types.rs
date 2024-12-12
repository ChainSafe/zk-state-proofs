use op_alloy::rpc_types::Transaction as OPTransaction;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockResponse {
    pub jsonrpc: String,
    pub result: BlockResult,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockResult {
    pub difficulty: String,
    pub hash: String,
    pub miner: String,
    pub nonce: String,
    pub number: String,
    pub size: String,
    pub timestamp: String,
    pub withdrawals_root: Option<String>,
    pub uncles: Vec<String>,
    pub transactions: Vec<OPTransaction>,
    pub withdrawals: Vec<Withdrawal>,
    #[serde(rename = "transactionsRoot")]
    pub transactions_root: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Withdrawal {
    // Not yet supported
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessListItem {
    // Not yet supported
}
