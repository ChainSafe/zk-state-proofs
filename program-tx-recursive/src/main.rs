#![no_main]
sp1_zkvm::entrypoint!(main);
use merkle_lib::{verify_merkle_proof, MerkleProofInput};
pub fn main() {
    todo!("Implement this circuit!");

    //sp1_zkvm::io::commit_slice(&output.unwrap());
}
