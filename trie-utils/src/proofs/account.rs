/* Use case

    Prove that an account exists in global state.
    Prerequisite to verifying storage proofs against that account's storage root.
*/

use crate::{
    constants::{ARBITRUM_ONE_RPC_URL, NODE_RPC_URL, OPTIMISM_RPC_URL},
    load_infura_key_from_env,
    types::NetworkEvm,
};
use alloy::{
    hex,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use crypto_ops::{keccak::digest_keccak, types::MerkleProofInput};
use reqwest::Client;
use std::{io::Read, str::FromStr};
use url::Url;

use super::arbitrum::client::ArbitrumClient;

pub async fn get_account_proof_inputs(address: Address, network: NetworkEvm) -> MerkleProofInput {
    let rpc_url: String = match network {
        NetworkEvm::Ethereum => {
            let key = load_infura_key_from_env();
            NODE_RPC_URL.to_string() + &key
        }
        NetworkEvm::Optimism => OPTIMISM_RPC_URL.to_string(),
        NetworkEvm::Arbitrum => panic!("Use get_account_proof_inputs_arbitrum instead!"),
    };
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
        .get_proof(address, vec![])
        .await
        .expect("Failed to get proof!");

    MerkleProofInput {
        proof: proof
            .account_proof
            .into_iter()
            .map(|b| b.to_vec())
            .collect(),
        root_hash: block.header.state_root.to_vec(),
        key: digest_keccak(&address.bytes().collect::<Result<Vec<u8>, _>>().unwrap()).to_vec(),
    }
}

pub async fn get_account_proof_inputs_arbitrum(address_hex: &str) -> MerkleProofInput {
    let reqwest_client: Client = Client::new();
    let arb_client: ArbitrumClient =
        ArbitrumClient::new(ARBITRUM_ONE_RPC_URL.to_string(), reqwest_client);
    let block = arb_client.get_block_by_number("latest").await;
    let proof = arb_client.get_proof(address_hex, vec![]).await;
    MerkleProofInput {
        proof: proof
            .result
            .account_proof
            .into_iter()
            .map(|b| hex::decode(b).unwrap())
            .collect(),
        root_hash: hex::decode(block.state_root).unwrap(),
        key: digest_keccak(&hex::decode(&address_hex).unwrap()).to_vec(),
    }
}
