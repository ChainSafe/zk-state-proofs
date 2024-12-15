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
    primitives::{Address, FixedBytes},
    providers::{Provider, ProviderBuilder},
};
use crypto_ops::{keccak::digest_keccak, types::MerkleProofListInput};
use std::{io::Read, str::FromStr};
use url::Url;

pub async fn get_storage_proof_inputs(
    address: Address,
    keys: Vec<FixedBytes<32>>,
    network: NetworkEvm,
    root_hash: Vec<u8>,
) -> MerkleProofListInput {
    let rpc_url: String = match network {
        NetworkEvm::Ethereum => {
            let key = load_infura_key_from_env();
            NODE_RPC_URL.to_string() + &key
        }
        NetworkEvm::Optimism => OPTIMISM_RPC_URL.to_string(),
        NetworkEvm::Arbitrum => ARBITRUM_ONE_RPC_URL.to_string(),
    };
    let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
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
        root_hash,
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
