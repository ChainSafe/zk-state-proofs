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
    pub uncles: Vec<String>,
    // tx proofs not supported
    // pub transactions: Vec<OPTransaction>,
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    // tx proofs not supported
    // #[serde(rename = "transactionsRoot")]
    // pub transactions_root: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Withdrawal {
    // Not yet supported
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessListItem {
    // Not yet supported
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountProofResponse {
    pub jsonrpc: String,
    pub result: AccountProof,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountProof {
    #[serde(rename = "accountProof")]
    pub account_proof: Vec<String>,
    pub address: String,
    pub balance: String,
    #[serde(rename = "codeHash")]
    pub code_hash: String,
    pub nonce: String,
    #[serde(rename = "storageHash")]
    pub storage_hash: String,
    #[serde(rename = "storageProof")]
    pub storage_proof: Option<Vec<StorageProof>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageProof {
    pub key: String,
    pub proof: Vec<String>,
    pub value: String,
}
