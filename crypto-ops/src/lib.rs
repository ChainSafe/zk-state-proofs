use std::sync::Arc;

use alloy_primitives::B256;
use eth_trie::{EthTrie, MemoryDB, Trie, DB};
use keccak::digest_keccak;
use serde::{Deserialize, Serialize};
pub mod keccak;

// verify single transaction proof
// utilizes keccak precompile for SP1
pub fn verify_merkle_proof(root_hash: B256, proof: Vec<Vec<u8>>, key: &[u8]) -> Vec<u8> {
    let proof_db = Arc::new(MemoryDB::new(true));
    for node_encoded in proof.clone().into_iter() {
        let hash: B256 = digest_keccak(&node_encoded).into();
        proof_db.insert(hash.as_slice(), node_encoded).unwrap();
    }
    let mut trie = EthTrie::from(proof_db, root_hash).expect("Invalid merkle proof");
    // verify the root hash is indeed that of the freshly constructed trie
    // this might be somewhat inefficient but seems to be the way to go with eth_trie lib
    // this step might be obsolete, to be completely honest I'm not yet sure about that :D
    // better to be safe than sorry!
    assert_eq!(root_hash, trie.root_hash().unwrap());
    trie.verify_proof(root_hash, key, proof)
        .expect("Failed to verify Merkle Proof")
        .expect("Key does not exist!")
}

#[derive(Serialize, Deserialize)]
pub struct MerkleProofInput {
    pub proof: Vec<Vec<u8>>,
    pub root_hash: Vec<u8>,
    pub key: Vec<u8>,
}
