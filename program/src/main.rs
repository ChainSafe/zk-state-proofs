#![no_main]
sp1_zkvm::entrypoint!(main);
use merkle_lib::keccak::digest_keccak;
pub fn main() {
    let bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let output = digest_keccak(&bytes);
    sp1_zkvm::io::commit_slice(&output);
}
