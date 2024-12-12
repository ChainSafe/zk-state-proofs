/* Use case

    Prove that an account exists in global state.
    Prerequisite to verifying storage proofs against that account's storage root.
*/

use crate::{constants::NODE_RPC_URL, load_infura_key_from_env};
use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use crypto_ops::{keccak::digest_keccak, types::MerkleProofInput};
use std::{io::Read, str::FromStr};
use url::Url;

pub async fn get_ethereum_account_proof_inputs(address: Address) -> MerkleProofInput {
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
