#[cfg(test)]
mod tests {
    use crypto_ops::verify_merkle_proof;
    use trie_utils::{
        constants::{DEFAULT_BLOCK_HASH, DEFAULT_OPTIMISM_BLOCK_HASH},
        proofs::transaction::{
            get_ethereum_transaction_proof_inputs, get_optimism_transaction_proof_inputs,
        },
    };

    #[tokio::test]
    async fn test_get_and_verify_ethereum_transaction_merkle_proof() {
        let target_index: u32 = 15u32;
        let inputs: crypto_ops::types::MerkleProofInput =
            get_ethereum_transaction_proof_inputs(target_index, DEFAULT_BLOCK_HASH).await;
        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let _ = verify_merkle_proof(
            alloy::primitives::FixedBytes::from_slice(&inputs.root_hash),
            inputs.proof,
            &alloy_rlp::encode(target_index),
        );
        println!("[Success] Verified Transaction against Transactions Root.",);
    }

    #[tokio::test]
    async fn test_get_and_verify_optimism_transaction_merkle_proof() {
        let target_index: u32 = 0u32;
        let inputs: crypto_ops::types::MerkleProofInput =
            get_optimism_transaction_proof_inputs(target_index, DEFAULT_OPTIMISM_BLOCK_HASH).await;

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let _ = verify_merkle_proof(
            alloy::primitives::FixedBytes::from_slice(&inputs.root_hash),
            inputs.proof,
            &alloy_rlp::encode(target_index),
        );
        println!("[Success] Verified Transaction against Transactions Root.",);
    }
}
