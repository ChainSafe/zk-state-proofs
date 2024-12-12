use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MerkleProofInput {
    pub proof: Vec<Vec<u8>>,
    pub root_hash: Vec<u8>,
    pub key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MerkleProofListInput {
    pub account_proof: Vec<Vec<u8>>,
    pub storage_proofs: Vec<Vec<Vec<u8>>>,
    pub root_hash: Vec<u8>,
    pub account_key: Vec<u8>,
    pub storage_keys: Vec<Vec<u8>>,
}
