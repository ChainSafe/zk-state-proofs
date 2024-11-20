use tiny_keccak::{Hasher, Keccak};

pub fn digest_keccak(bytes: &[u8]) -> [u8; 32] {
    let mut sha3 = Keccak::v256();
    let mut output = [0u8; 32];

    sha3.update(bytes);
    sha3.finalize(&mut output);

    output
}
