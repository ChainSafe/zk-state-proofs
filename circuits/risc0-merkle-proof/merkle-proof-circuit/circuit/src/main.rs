use crypto_ops::{types::MerkleProofInput, verify_merkle_proof};
use risc0_zkvm::guest::env;
use std::io::Read;

fn main() {
    let mut buffer: Vec<u8> = vec![];
    let _ = env::stdin().read_to_end(&mut buffer);
    let merkle_proof: MerkleProofInput = borsh::from_slice(&mut buffer).unwrap();
    let output = verify_merkle_proof(
        merkle_proof.root_hash.as_slice().try_into().unwrap(),
        merkle_proof.proof.clone(),
        &merkle_proof.key,
    );
    env::commit_slice(&output);
}
