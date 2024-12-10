use crypto_ops::{types::MerkleProofInput, verify_merkle_proof};
use risc0_zkvm::guest::env;

fn main() {
    let merkle_proof: MerkleProofInput = env::read();

    let output = verify_merkle_proof(
        merkle_proof.root_hash.as_slice().try_into().unwrap(),
        merkle_proof.proof.clone(),
        &merkle_proof.key,
    );
    env::commit_slice(&output);
}
