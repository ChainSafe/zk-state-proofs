use crate::{constants::NODE_RPC_URL, load_infura_key_from_env};
use alloy::{
    primitives::{Address, FixedBytes},
    providers::{Provider, ProviderBuilder},
};
use crypto_ops::{keccak::digest_keccak, types::MerkleProofListInput};
use std::{io::Read, str::FromStr};
use url::Url;

pub async fn get_ethereum_storage_proof_inputs(
    address: Address,
    keys: Vec<FixedBytes<32>>,
) -> MerkleProofListInput {
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
        .get_proof(address, keys)
        .await
        .expect("Failed to get proof!");

    MerkleProofListInput {
        account_proof: proof
            .account_proof
            .into_iter()
            .map(|b| b.to_vec())
            .collect(),
        storage_proofs: proof
            .storage_proof
            .iter()
            .cloned()
            .map(|p| p.proof.into_iter().map(|b| b.to_vec()).collect())
            .collect(),
        root_hash: block.header.state_root.to_vec(),
        account_key: digest_keccak(&address.bytes().collect::<Result<Vec<u8>, _>>().unwrap())
            .to_vec(),
        storage_keys: proof
            .storage_proof
            .iter()
            .cloned()
            .map(|p| {
                p.key
                    .as_b256()
                    .bytes()
                    .collect::<Result<Vec<u8>, _>>()
                    .unwrap()
            })
            .collect(),
    }
}
