use alloy_consensus::Account;
use crypto_ops::{keccak::digest_keccak, types::StorageProofInput, verify_merkle_proof};
use risc0_zkvm::guest::env;
use std::io::Read;

fn main() {
    let mut buffer: Vec<u8> = vec![];
    let _ = env::stdin().read_to_end(&mut buffer);
    let merkle_proof: StorageProofInput = borsh::from_slice(&mut buffer).unwrap();
    let account_proof: Vec<u8> = verify_merkle_proof(
        merkle_proof.root_hash.as_slice().try_into().unwrap(),
        merkle_proof.account_proof,
        &merkle_proof.address_keccak,
    );
    let decoded_account: Account = alloy_rlp::decode_exact(&account_proof).unwrap();

    let mut stored_values: Vec<Vec<u8>> = vec![];
    for (proof, key) in merkle_proof
        .storage_proofs
        .iter()
        .zip(merkle_proof.storage_keys.iter())
    {
        let stored_value: Vec<u8> = verify_merkle_proof(
            decoded_account.storage_root,
            proof.to_vec(),
            &digest_keccak(&key),
        );
        stored_values.push(stored_value);
    }
    env::commit(&stored_values);
}
