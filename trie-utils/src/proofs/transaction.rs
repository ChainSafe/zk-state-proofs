use crate::{constants::NODE_RPC_URL, load_infura_key_from_env};
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

#[cfg(test)]
mod tests {
    use super::BlockResponse;
    use alloy::hex::ToHex;
    use alloy_rlp::BufMut;
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use reqwest::Client;
    use serde_json::json;
    use std::sync::Arc;
    #[tokio::test]
    async fn test_get_optimism_transaction_proof_inputs() {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByHash",
            "params": [
                "0xda01e7fa47eb8261260369794b4eb1afe06470f2f7b047eadaf031737a3038e8",
                true
            ],
            "id": 1
        });
        let client = Client::new();
        let response = client
            .post("https://mainnet.optimism.io/")
            .json(&payload)
            .send()
            .await
            .unwrap();

        if response.status().is_success() {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie = EthTrie::new(memdb.clone());
            let text = response.text().await.unwrap();
            let block: BlockResponse = serde_json::from_str(&text).unwrap();
            for (_, transaction) in block.result.transactions.into_iter().enumerate() {
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
            assert_eq!(
                &trie.root_hash().unwrap().to_string(),
                &block.result.transactions_root
            );
        } else {
            panic!("Failed to get Block!");
        }
    }
}

// a temporary type since I wasn't able to find one?
use op_alloy::rpc_types::Transaction as OPTransaction;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug)]
pub struct BlockResponse {
    pub jsonrpc: String,
    pub result: BlockResult,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockResult {
    pub difficulty: String,
    pub hash: String,
    pub miner: String,
    pub nonce: String,
    pub number: String,
    pub size: String,
    pub timestamp: String,
    pub withdrawals_root: Option<String>,
    pub uncles: Vec<String>,
    pub transactions: Vec<OPTransaction>,
    pub withdrawals: Vec<Withdrawal>,
    #[serde(rename = "transactionsRoot")]
    pub transactions_root: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Withdrawal {
    // Not yet supported
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessListItem {
    // Not yet supported
}
