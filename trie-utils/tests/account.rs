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
    use trie_utils::{
        constants::{DEFAULT_STORAGE_KEY, NODE_RPC_URL, USDT_CONTRACT_ADDRESS},
        load_infura_key_from_env,
        proofs::account::get_account_proof_inputs,
        types::NetworkEvm,
    };
    use url::Url;

    /// This test could fail in case a new block is produced during execution.
    /// The risk of this happening is accepted and it's recommended to re-run the test
    /// in the very rare case where it fails for said reason.
    /// The same is true for the test in storage.rs
    #[tokio::test]
    async fn test_verify_account_and_storage_proof() {
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
                vec![FixedBytes::from_hex(DEFAULT_STORAGE_KEY).unwrap()],
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
        let _ = verify_merkle_proof(
            proof.storage_hash,
            proof
                .storage_proof
                .first()
                .unwrap()
                .proof
                .clone()
                .into_iter()
                .map(|b| b.to_vec())
                .collect(),
            &digest_keccak(&hex::decode(DEFAULT_STORAGE_KEY).unwrap()),
        );
        println!("[Success] Verified Account Proof against Block Root")
    }
}
