/* Use case

    The receipt trie stores all events (including those emitted from ERC20 contracts).
    We can use the receipt proofs to verify that an ERC20 or NFT transfer happened e.g. that the
    transaction hash was included in a block.

    Once the transaction hash is trusted we can either re-hash the raw tx and compare those hashs
    or generate and verify a zkp that the transaction hash matches that of the claim.

    To verify balances or stored values use the state trie, not the receipt trie!
    The receipt trie is only useful when proving individual (NFT, FT) transactions occurred.
    Use the Transactions trie to prove native transactions occurred.
*/

use crate::{constants::NODE_RPC_URL, load_infura_key_from_env, receipt::insert_receipt};
use alloy::{
    consensus::ReceiptEnvelope,
    primitives::B256,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionReceipt,
};
use alloy_rlp::BufMut;
use crypto_ops::types::MerkleProofInput;
use eth_trie::{EthTrie, MemoryDB, Trie};
use std::{str::FromStr, sync::Arc};
use url::Url;

pub async fn get_ethereum_receipt_proof_inputs(
    target_index: u32,
    block_hash: &str,
) -> MerkleProofInput {
    let key = load_infura_key_from_env();
    let rpc_url = NODE_RPC_URL.to_string() + &key;
    let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
    let block_hash_b256 = B256::from_str(block_hash).unwrap();
    let block = provider
        .get_block_by_hash(
            B256::from_str(block_hash).unwrap(),
            alloy::rpc::types::BlockTransactionsKind::Full,
        )
        .await
        .expect("Failed to get Block!")
        .expect("Block not found!");
    let receipts: Vec<TransactionReceipt> = provider
        .get_block_receipts(alloy::eips::BlockId::Hash(block_hash_b256.into()))
        .await
        .unwrap()
        .unwrap();
    let memdb = Arc::new(MemoryDB::new(true));
    let mut trie = EthTrie::new(memdb.clone());

    for (index, receipt) in receipts.into_iter().enumerate() {
        let inner: ReceiptEnvelope<alloy::rpc::types::Log> = receipt.inner;
        let mut out: Vec<u8> = Vec::new();
        let index_encoded = alloy_rlp::encode(index);
        match inner {
            ReceiptEnvelope::Eip2930(r) => {
                let prefix: u8 = 0x01;
                insert_receipt(r, &mut trie, index_encoded, Some(prefix));
            }
            ReceiptEnvelope::Eip1559(r) => {
                let prefix: u8 = 0x02;
                insert_receipt(r, &mut trie, index_encoded, Some(prefix));
            }
            ReceiptEnvelope::Eip4844(r) => {
                let prefix: u8 = 0x03;
                out.put_u8(0x03);
                insert_receipt(r, &mut trie, index_encoded, Some(prefix));
            }
            ReceiptEnvelope::Eip7702(r) => {
                let prefix: u8 = 0x04;
                out.put_u8(0x04);
                insert_receipt(r, &mut trie, index_encoded, Some(prefix));
            }
            ReceiptEnvelope::Legacy(r) => {
                insert_receipt(r, &mut trie, index_encoded, None);
            }
            _ => {
                eprintln!("Unknown Receipt Type!")
            }
        }
    }

    trie.root_hash().unwrap();
    let receipt_key: Vec<u8> = alloy_rlp::encode(target_index);
    let proof = trie.get_proof(&receipt_key).unwrap();

    MerkleProofInput {
        proof,
        root_hash: block.header.receipts_root.to_vec(),
        key: receipt_key,
    }
}
