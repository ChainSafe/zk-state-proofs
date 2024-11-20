#![no_main]
sp1_zkvm::entrypoint!(main);
use merkle_lib::{verify_merkle_proof, MerkleProofInput};
pub fn main() {
    let merkle_proof: MerkleProofInput =
        serde_json::from_slice(&sp1_zkvm::io::read::<Vec<u8>>()).unwrap();
    verify_merkle_proof(
        merkle_proof.root_hash.as_slice().try_into().unwrap(),
        merkle_proof.proof,
    );
    /*let output = digest_keccak(&bytes);
    sp1_zkvm::io::commit_slice(&output);*/
}
