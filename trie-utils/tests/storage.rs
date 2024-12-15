#[cfg(test)]
mod tests {
    #[allow(deprecated)]
    use alloy::{
        consensus::Account,
        hex::{self, FromHex, ToHex},
        primitives::{Address, FixedBytes},
        providers::{Provider, ProviderBuilder},
    };
    use crypto_ops::{keccak::digest_keccak, verify_merkle_proof};
    use reqwest::Client;
    use std::str::FromStr;
    use trie_utils::{
        constants::{
            DEFAULT_STORAGE_KEY_ETH, DEFAULT_STORAGE_KEY_OPTIMISM, NODE_RPC_URL, OPTIMISM_RPC_URL,
            USDT_CONTRACT_ADDRESS, USDT_CONTRACT_ADDRESS_OPTIMISM,
        },
        load_infura_key_from_env,
        proofs::{optimism::client::OPClient, storage::get_storage_proof_inputs},
        types::NetworkEvm,
    };
    use url::Url;

    /// This test could fail in case a new block is produced during execution.
    /// The risk of this happening is accepted and it's recommended to re-run the test
    /// in the very rare case where it fails for said reason.
    /// The same is true for the test in account.rs
    #[tokio::test]
    async fn test_verify_ethereum_account_and_storage_proof() {
        let key = load_infura_key_from_env();
        let rpc_url = NODE_RPC_URL.to_string() + &key;
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let block = provider
            .get_block(
                alloy::eips::BlockId::Number(provider.get_block_number().await.unwrap().into()),
                alloy::rpc::types::BlockTransactionsKind::Full,
            )
            .await
            .unwrap()
            .unwrap();
        let proof = provider
            .get_proof(
                Address::from_hex(USDT_CONTRACT_ADDRESS).unwrap(),
                vec![FixedBytes::from_hex(DEFAULT_STORAGE_KEY_ETH).unwrap()],
            )
            .await
            .expect("Failed to get proof");
        let account_proof: Vec<u8> = verify_merkle_proof(
            block.header.state_root,
            proof
                .account_proof
                .clone()
                .into_iter()
                .map(|b| b.to_vec())
                .collect(),
            &digest_keccak(&hex::decode(USDT_CONTRACT_ADDRESS).unwrap()),
        );
        let decoded_account: Account = alloy_rlp::decode_exact(&account_proof).unwrap();
        assert_eq!(
            decoded_account.storage_root.encode_hex::<String>(),
            hex::encode(&proof.storage_hash)
        );
        let storage_proof = get_storage_proof_inputs(
            Address::from_hex(USDT_CONTRACT_ADDRESS).unwrap(),
            vec![FixedBytes::from_hex(DEFAULT_STORAGE_KEY_ETH).unwrap()],
            NetworkEvm::Ethereum,
            block.header.state_root.to_vec(),
        )
        .await;
        let _ = verify_merkle_proof(
            proof.storage_hash,
            storage_proof.storage_proofs.first().unwrap().to_owned(),
            &digest_keccak(&storage_proof.storage_keys.first().unwrap()),
        );
        println!("[Success] Verified Account Proof against Block Root and Storage Proof against Account Root.")
    }

    #[tokio::test]
    async fn test_verify_optimism_account_and_storage_proof() {
        let key = load_infura_key_from_env();
        let rpc_url = OPTIMISM_RPC_URL.to_string() + &key;
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let reqwest_client = Client::new();
        let op_client: OPClient = OPClient::new(rpc_url.to_string(), reqwest_client);
        let block = op_client.get_block_by_number("latest").await;
        let proof = provider
            .get_proof(
                Address::from_hex(USDT_CONTRACT_ADDRESS_OPTIMISM).unwrap(),
                vec![FixedBytes::from_hex(DEFAULT_STORAGE_KEY_OPTIMISM).unwrap()],
            )
            .await
            .expect("Failed to get proof");
        let account_proof: Vec<u8> = verify_merkle_proof(
            FixedBytes::from_slice(&hex::decode(&block.state_root).unwrap()),
            proof
                .account_proof
                .clone()
                .into_iter()
                .map(|b| b.to_vec())
                .collect(),
            &digest_keccak(&hex::decode(USDT_CONTRACT_ADDRESS_OPTIMISM).unwrap()),
        );
        let decoded_account: Account = alloy_rlp::decode_exact(&account_proof).unwrap();
        assert_eq!(
            decoded_account.storage_root.encode_hex::<String>(),
            hex::encode(&proof.storage_hash)
        );
        let storage_proof = get_storage_proof_inputs(
            Address::from_hex(USDT_CONTRACT_ADDRESS_OPTIMISM).unwrap(),
            vec![FixedBytes::from_hex(DEFAULT_STORAGE_KEY_OPTIMISM).unwrap()],
            NetworkEvm::Optimism,
            hex::decode(&block.state_root).unwrap(),
        )
        .await;
        let _ = verify_merkle_proof(
            proof.storage_hash,
            storage_proof.storage_proofs.first().unwrap().to_owned(),
            &digest_keccak(&storage_proof.storage_keys.first().unwrap()),
        );
        println!("[Success] Verified Account Proof against Block Root and Storage Proof against Account Root.")
    }
}
