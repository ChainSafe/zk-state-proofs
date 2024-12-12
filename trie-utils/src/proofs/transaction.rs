/* Use case

    The transaction trie stores NATIVE transactions ONLY.
    For proving individual (NFT, FT) transactions look into the receipts trie!
*/

use crate::{
    constants::{NODE_RPC_URL, OPTIMISM_RPC_URL},
    load_infura_key_from_env,
};
use alloy::{
    consensus::TxEnvelope,
    hex,
    primitives::B256,
    providers::{Provider, ProviderBuilder},
};
use alloy_rlp::BufMut;
use crypto_ops::types::MerkleProofInput;
use eth_trie::{EthTrie, MemoryDB, Trie};
use reqwest::Client;
use std::{str::FromStr, sync::Arc};
use url::Url;

use super::optimism::client::OPClient;

pub async fn get_ethereum_transaction_proof_inputs(
    target_index: u32,
    block_hash: &str,
) -> MerkleProofInput {
    let key = load_infura_key_from_env();
    let rpc_url = NODE_RPC_URL.to_string() + &key;
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
            _ => panic!("Unsupported transaction type!"),
        }
        trie.insert(&path, &encoded_tx).expect("Failed to insert!");
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

pub async fn get_optimism_transaction_proof_inputs(
    target_index: u32,
    block_hash: &str,
) -> MerkleProofInput {
    let reqwest_client = Client::new();
    let op_client = OPClient::new(OPTIMISM_RPC_URL.to_string(), reqwest_client);
    let block_result = op_client.get_block_by_hash(block_hash).await;
    let mem_db = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(mem_db);

    for transaction in block_result.transactions.into_iter() {
        let mut encoded_tx = vec![];
        match transaction.inner.inner.tx_type() {
            op_alloy::consensus::OpTxType::Legacy => {
                let x = transaction.inner.inner.as_legacy().unwrap();
                x.eip2718_encode(&mut encoded_tx);
            }
            op_alloy::consensus::OpTxType::Deposit => {
                let x = transaction.inner.inner.as_deposit().unwrap();
                encoded_tx.put_u8(transaction.inner.inner.tx_type().into());
                x.rlp_encode(&mut encoded_tx);
            }
            op_alloy::consensus::OpTxType::Eip1559 => {
                let x = transaction.inner.inner.as_eip1559().unwrap();
                x.eip2718_encode(&mut encoded_tx);
            }
            op_alloy::consensus::OpTxType::Eip2930 => {
                let x = transaction.inner.inner.as_eip2930().unwrap();
                x.eip2718_encode(&mut encoded_tx);
            }
            op_alloy::consensus::OpTxType::Eip7702 => {
                panic!("Not yet supported Transaction Type!");
            }
        }
        trie.insert(
            &alloy_rlp::encode(transaction.transaction_index.unwrap()),
            &encoded_tx,
        )
        .expect("Failed to insert!");
    }

    trie.root_hash().unwrap();
    let tx_key: Vec<u8> = alloy_rlp::encode(target_index);
    let proof: Vec<Vec<u8>> = trie.get_proof(&tx_key).unwrap();
    MerkleProofInput {
        proof,
        root_hash: hex::decode(block_result.transactions_root).unwrap(),
        key: tx_key,
    }
}
