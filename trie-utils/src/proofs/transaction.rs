use crate::load_infura_key_from_env;
use alloy::{
    consensus::TxEnvelope,
    primitives::B256,
    providers::{Provider, ProviderBuilder},
};
use crypto_ops::types::MerkleProofInput;
use eth_trie::{EthTrie, MemoryDB, Trie};
use std::{str::FromStr, sync::Arc};
use url::Url;

pub async fn get_ethereum_transaction_proof_inputs(
    target_index: u32,
    block_hash: &str,
) -> MerkleProofInput {
    let key = load_infura_key_from_env();
    println!("Key: {}", key);
    let rpc_url = "https://mainnet.infura.io/v3/".to_string() + &key;
    let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
    let block = provider
        .get_block_by_hash(
            B256::from_str(block_hash).unwrap(),
            alloy::rpc::types::BlockTransactionsKind::Full,
        )
        .await
        .expect("Failed to get Block!")
        .expect("Block not found!");
    let memdb = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(memdb.clone());

    for (index, tx) in block.transactions.txns().enumerate() {
        let path = alloy_rlp::encode(index);
        let mut encoded_tx = vec![];
        match &tx.inner {
            TxEnvelope::Legacy(tx) => tx.eip2718_encode(&mut encoded_tx),
            TxEnvelope::Eip2930(tx) => {
                tx.eip2718_encode(&mut encoded_tx);
            }
            TxEnvelope::Eip1559(tx) => {
                tx.eip2718_encode(&mut encoded_tx);
            }
            TxEnvelope::Eip4844(tx) => {
                tx.eip2718_encode(&mut encoded_tx);
            }
            TxEnvelope::Eip7702(tx) => {
                tx.eip2718_encode(&mut encoded_tx);
            }
            _ => panic!("Unsupported transaction type"),
        }
        trie.insert(&path, &encoded_tx).expect("Failed to insert");
    }

    trie.root_hash().unwrap();
    let tx_key: Vec<u8> = alloy_rlp::encode(target_index);
    let proof: Vec<Vec<u8>> = trie.get_proof(&tx_key).unwrap();
    MerkleProofInput {
        proof,
        root_hash: block.header.transactions_root.to_vec(),
        key: tx_key,
    }
}
