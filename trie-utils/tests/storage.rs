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
            ARBITRUM_ONE_RPC_URL, DEFAULT_STORAGE_KEY_ETHEREUM, DEFAULT_STORAGE_KEY_OPTIMISM,
            NODE_RPC_URL, OPTIMISM_RPC_URL, USDT_CONTRACT_ADDRESS, USDT_CONTRACT_ADDRESS_ARBITRUM,
            USDT_CONTRACT_ADDRESS_OPTIMISM,
        },
        load_infura_key_from_env,
        proofs::{
            arbitrum::client::ArbitrumClient,
            optimism::client::OPClient,
            storage::{get_storage_proof_inputs, get_storage_proof_inputs_arbitrum},
        },
        types::NetworkEvm,
    };
    use url::Url;

    /// This test could fail in case a new block is produced during execution.
    /// The risk of this happening is accepted and it's recommended to re-run the test
    /// handle this case by verifying the merkle proof before generating a zkp!
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
                vec![FixedBytes::from_hex(DEFAULT_STORAGE_KEY_ETHEREUM).unwrap()],
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
            vec![FixedBytes::from_hex(DEFAULT_STORAGE_KEY_ETHEREUM).unwrap()],
            NetworkEvm::Ethereum,
            block.header.state_root.to_vec(),
        )
        .await;
        let _ = verify_merkle_proof(
            proof.storage_hash,
            storage_proof.storage_proofs.first().unwrap().to_owned(),
            &digest_keccak(&storage_proof.storage_keys.first().unwrap()),
        );
        println!("[Success] Verified Ethereum Storage Proof!")
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
        println!("[Success] Verified Optimism Storage Proof!")
    }

    #[tokio::test]
    async fn test_verify_arbitrum_storage_proof() {
        let reqwest_client = Client::new();
        let arb_client: ArbitrumClient =
            ArbitrumClient::new(ARBITRUM_ONE_RPC_URL.to_string(), reqwest_client);
        let block = arb_client.get_block_by_number("latest").await;
        let proof = arb_client
            .get_proof(
                USDT_CONTRACT_ADDRESS_ARBITRUM,
                vec![DEFAULT_STORAGE_KEY_ETHEREUM.to_string()],
            )
            .await;
        let account_proof: Vec<u8> = verify_merkle_proof(
            FixedBytes::from_slice(&hex::decode(&block.state_root).unwrap()),
            proof
                .result
                .account_proof
                .clone()
                .into_iter()
                .map(|b| hex::decode(b).unwrap())
                .collect(),
            &digest_keccak(&hex::decode(USDT_CONTRACT_ADDRESS_ARBITRUM).unwrap()),
        );
        let decoded_account: Account = alloy_rlp::decode_exact(&account_proof).unwrap();
        assert_eq!(
            decoded_account.storage_root.encode_hex::<String>(),
            // strip 0x suffix from response
            proof.result.storage_hash[2..]
        );
        let storage_proof = get_storage_proof_inputs_arbitrum(
            USDT_CONTRACT_ADDRESS_ARBITRUM.to_string(),
            vec![DEFAULT_STORAGE_KEY_ETHEREUM.to_string()],
            hex::decode(block.state_root).unwrap(),
        )
        .await;
        let _ = verify_merkle_proof(
            FixedBytes::from_slice(&hex::decode(&proof.result.storage_hash).unwrap()),
            storage_proof.storage_proofs.first().unwrap().to_owned(),
            &digest_keccak(&storage_proof.storage_keys.first().unwrap()),
        );
        println!("[Success] Verified Arbitrum Storage Proof!")
    }
}
