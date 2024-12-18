/* Use case

    The storage trie is used to verify that a certain value exists in ethereum state.
    This can be used to prove balances or any other values stored under contracts / accounts.
*/

use crate::{
    constants::{ARBITRUM_ONE_RPC_URL, NODE_RPC_URL, OPTIMISM_RPC_URL},
    load_infura_key_from_env,
    types::NetworkEvm,
};
use alloy::{
    hex::{self, FromHex, ToHex},
    primitives::{Address, FixedBytes},
    providers::{Provider, ProviderBuilder},
};
use crypto_ops::{keccak::digest_keccak, types::StorageProofInput};
use reqwest::Client;
use std::{io::Read, str::FromStr};
use url::Url;

use super::arbitrum::client::ArbitrumClient;

pub async fn get_storage_proof_inputs(
    address_hex: String,
    keys: Vec<FixedBytes<32>>,
    network: NetworkEvm,
    root_hash: Vec<u8>,
) -> StorageProofInput {
    let address_object = Address::from_hex(&address_hex).unwrap();
    let rpc_url: String = match network {
        NetworkEvm::Ethereum => {
            let key = load_infura_key_from_env();
            NODE_RPC_URL.to_string() + &key
        }
        NetworkEvm::Optimism => OPTIMISM_RPC_URL.to_string(),
        NetworkEvm::Arbitrum => panic!("Use get_storage_proof_inputs_arbitrum instead!"),
    };
    let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
    let proof = provider
        .get_proof(address_object, keys)
        .await
        .expect("Failed to get proof!");

    StorageProofInput {
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
        root_hash,
        account_key: digest_keccak(
            &address_object
                .bytes()
                .collect::<Result<Vec<u8>, _>>()
                .unwrap(),
        )
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
        address_keccak: digest_keccak(&hex::decode(&address_hex).unwrap()),
    }
}

pub async fn get_storage_proof_inputs_arbitrum(
    address_hex: String,
    keys: Vec<String>,
    root_hash: Vec<u8>,
) -> StorageProofInput {
    let reqwest_client: Client = Client::new();
    let arb_client: ArbitrumClient =
        ArbitrumClient::new(ARBITRUM_ONE_RPC_URL.to_string(), reqwest_client);
    let proof = arb_client.get_proof(&address_hex, keys).await;
    let proof_result = proof.result;
    StorageProofInput {
        account_proof: proof_result
            .account_proof
            .into_iter()
            .map(|b| hex::decode(b).unwrap())
            .collect(),
        storage_proofs: proof_result
            .storage_proof
            .clone()
            .unwrap()
            .iter()
            .cloned()
            .map(|p| {
                p.proof
                    .into_iter()
                    .map(|b| hex::decode(b).unwrap())
                    .collect()
            })
            .collect(),
        root_hash,
        account_key: digest_keccak(&hex::decode(&address_hex).unwrap()).to_vec(),
        storage_keys: proof_result
            .storage_proof
            .unwrap()
            .iter()
            .cloned()
            .map(|p| hex::decode(p.key).unwrap())
            .collect(),
        address_keccak: digest_keccak(&hex::decode(address_hex).unwrap()),
    }
}
