#[cfg(test)]
mod test {
    use std::str::FromStr;

    use alloy::{
        consensus::Account,
        hex::{self, FromHex, ToHex},
        primitives::{Address, FixedBytes},
        providers::{Provider, ProviderBuilder},
    };
    use crypto_ops::{keccak::digest_keccak, types::MerkleProofInput, verify_merkle_proof};
    use reqwest::Client;
    use trie_utils::{
        constants::{
            DEFAULT_STORAGE_KEY_ETH_ARB, DEFAULT_STORAGE_KEY_OPTIMISM, NODE_RPC_URL,
            OPTIMISM_RPC_URL, USDT_CONTRACT_ADDRESS, USDT_CONTRACT_ADDRESS_OPTIMISM,
        },
        load_infura_key_from_env,
        proofs::{account::get_account_proof_inputs, optimism::client::OPClient},
        types::NetworkEvm,
    };
    use url::Url;

    /// This test could fail in case a new block is produced during execution.
    /// The risk of this happening is accepted and it's recommended to re-run the test
    /// in the very rare case where it fails for said reason.
    /// The same is true for the test in storage.rs
    #[tokio::test]
    async fn test_verify_ethereum_account_proof() {
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
                vec![FixedBytes::from_hex(DEFAULT_STORAGE_KEY_ETH_ARB).unwrap()],
            )
            .await
            .expect("Failed to get proof");

        let inputs: MerkleProofInput = get_account_proof_inputs(
            Address::from_hex(USDT_CONTRACT_ADDRESS).unwrap(),
            NetworkEvm::Ethereum,
        )
        .await;
        let account_rlp: Vec<u8> = verify_merkle_proof(
            block.header.state_root,
            inputs.proof,
            &digest_keccak(&hex::decode(USDT_CONTRACT_ADDRESS).unwrap()),
        );
        let decoded_account: Account = alloy_rlp::decode_exact(&account_rlp).unwrap();
        assert_eq!(
            decoded_account.storage_root.encode_hex::<String>(),
            hex::encode(&proof.storage_hash)
        );
    }

    #[tokio::test]
    async fn test_verify_optimism_account_proof() {
        let provider = ProviderBuilder::new().on_http(Url::from_str(OPTIMISM_RPC_URL).unwrap());
        let reqwest_client = Client::new();
        let op_client: OPClient = OPClient::new(OPTIMISM_RPC_URL.to_string(), reqwest_client);
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
    }
}
