#[cfg(test)]
mod tests {
    use alloy::{
        primitives::B256,
        providers::{Provider, ProviderBuilder},
    };
    use crypto_ops::verify_merkle_proof;
    use std::str::FromStr;
    use trie_utils::{
        constants::{
            DEFAULT_BLOCK_HASH, DEFAULT_OPTIMISM_BLOCK_HASH, NODE_RPC_URL, OPTIMISM_RPC_URL,
        },
        get_ethereum_transaction_proof_inputs, load_infura_key_from_env,
    };
    use url::Url;

    #[tokio::test]
    async fn test_get_and_verify_ethereum_transaction_merkle_proof() {
        let key = load_infura_key_from_env();
        let rpc_url: String = NODE_RPC_URL.to_string() + &key;
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let target_index: u32 = 15u32;
        let inputs: crypto_ops::types::MerkleProofInput =
            get_ethereum_transaction_proof_inputs(target_index, DEFAULT_BLOCK_HASH).await;
        let block = provider
            .get_block_by_hash(
                B256::from_str(DEFAULT_BLOCK_HASH).unwrap(),
                alloy::rpc::types::BlockTransactionsKind::Full,
            )
            .await
            .expect("Failed to get Ethereum Block!")
            .expect("Block not found!");
        let _ = verify_merkle_proof(
            block.header.transactions_root,
            inputs.proof,
            &alloy_rlp::encode(target_index),
        );
        println!("[Success] Verified Transaction against Transactions Root.",);
    }

    #[tokio::test]
    async fn test_get_and_verify_optimism_transaction_merkle_proof() {
        let rpc_url = OPTIMISM_RPC_URL.to_string();
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let target_index: u32 = 15u32;
        let inputs: crypto_ops::types::MerkleProofInput =
            get_ethereum_transaction_proof_inputs(target_index, DEFAULT_BLOCK_HASH).await;
        let block = provider
            .get_block_by_hash(
                B256::from_str(DEFAULT_OPTIMISM_BLOCK_HASH).unwrap(),
                alloy::rpc::types::BlockTransactionsKind::Full,
            )
            .await
            .expect("Failed to get Ethereum Block!")
            .expect("Block not found!");
        let _ = verify_merkle_proof(
            block.header.transactions_root,
            inputs.proof,
            &alloy_rlp::encode(target_index),
        );
        println!("[Success] Verified Transaction against Transactions Root.",);
    }
}
