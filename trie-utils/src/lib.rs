use alloy::{
    consensus::{ReceiptEnvelope, ReceiptWithBloom, TxEnvelope, TxReceipt},
    primitives::B256,
    providers::{Provider, ProviderBuilder},
    rpc::types::{BlockTransactionsKind, TransactionReceipt},
};
// get transaction merkle proof from Ethereum
pub use alloy::eips::eip2718::{Eip2718Envelope, Encodable2718};
use alloy_rlp::{BufMut, Encodable};
use dotenv::dotenv;
use eth_trie::{EthTrie, MemoryDB, Trie};
use merkle_lib::MerkleProofInput;
use std::{env, str::FromStr, sync::Arc};
use url::Url;
mod macros;
pub fn load_infura_key_from_env() -> String {
    dotenv().ok();
    env::var("INFURA").expect("Missing Infura API key!")
}
pub mod types;
use alloy::rpc::types::Log as AlloyLog;
use types::{Log, H256};

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
            BlockTransactionsKind::Full,
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
            // Legacy transactions have no difference between network and 2718
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

pub async fn get_ethereum_receipt_proof_inputs(
    target_index: u32,
    block_hash: &str,
) -> MerkleProofInput {
    let key = load_infura_key_from_env();
    println!("Key: {}", key);
    let rpc_url = "https://mainnet.infura.io/v3/".to_string() + &key;
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
                eprintln!("Critical: Unknown Receipt Type")
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

fn insert_receipt(
    r: ReceiptWithBloom<AlloyLog>,
    trie: &mut EthTrie<MemoryDB>,
    index_encoded: Vec<u8>,
    prefix: Option<u8>,
) {
    let status = r.status();
    let cumulative_gas_used = r.cumulative_gas_used();
    let bloom = r.logs_bloom;
    let mut logs: Vec<Log> = Vec::new();
    for l in r.logs() {
        let mut topics: Vec<H256> = Vec::new();
        for t in l.topics() {
            topics.push(H256::from_slice(t.as_ref()));
        }
        logs.push(Log {
            address: l.address(),
            topics,
            data: l.data().data.to_vec(),
        });
    }
    let list_encode: [&dyn Encodable; 4] = [&status, &cumulative_gas_used, &bloom, &logs];
    let mut payload: Vec<u8> = Vec::new();
    alloy_rlp::encode_list::<_, dyn Encodable>(&list_encode, &mut payload);
    let mut out: Vec<u8> = Vec::new();
    if let Some(prefix) = prefix {
        out.put_u8(prefix);
    };
    out.put_slice(&payload);
    trie.insert(&index_encoded, &out).expect("Failed to insert");
}

#[cfg(test)]
mod test {

    use super::load_infura_key_from_env;
    use crate::{
        get_ethereum_receipt_proof_inputs, get_ethereum_transaction_proof_inputs, insert_receipt,
        types::{Log, H256},
    };
    use alloy::{
        consensus::ReceiptEnvelope,
        hex::{self, FromHex},
        primitives::{Address, Bloom, B256},
        providers::{Provider, ProviderBuilder},
        rpc::types::TransactionReceipt,
    };
    use alloy_rlp::{BufMut, Encodable};
    use eth_trie::{EthTrie, MemoryDB, Trie, DB};
    use keccak_hash::keccak;
    use merkle_lib::keccak::digest_keccak;
    use std::{str::FromStr, sync::Arc};
    use url::Url;

    #[test]
    fn test_infura_key() {
        let key = load_infura_key_from_env();
        println!("Key: {}", key);
    }

    #[tokio::test]
    async fn test_get_and_verify_ethereum_transaction_merkle_proof() {
        let key = load_infura_key_from_env();
        println!("Key: {}", key);
        let rpc_url: String = "https://mainnet.infura.io/v3/".to_string() + &key;
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let block_hash = "0x8230bd00f36e52e68dd4a46bfcddeceacbb689d808327f4c76dbdf8d33d58ca8";
        let target_index: u32 = 15u32;
        let inputs: merkle_lib::MerkleProofInput =
            get_ethereum_transaction_proof_inputs(target_index, block_hash).await;

        let block = provider
            .get_block_by_hash(
                B256::from_str(block_hash).unwrap(),
                alloy::rpc::types::BlockTransactionsKind::Full,
            )
            .await
            .expect("Failed to get Block!")
            .expect("Block not found!");

        let transaction = verify_merkle_proof(
            block.header.transactions_root,
            inputs.proof,
            &alloy_rlp::encode(target_index),
        );

        println!(
            "Verified {:?} against {:?}",
            &transaction, &block.header.transactions_root
        );
    }

    #[tokio::test]
    async fn test_get_and_verify_ethereum_receipt_merkle_proof() {
        let key = load_infura_key_from_env();
        println!("Key: {}", key);
        let rpc_url: String = "https://mainnet.infura.io/v3/".to_string() + &key;
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let block_hash = "0x8230bd00f36e52e68dd4a46bfcddeceacbb689d808327f4c76dbdf8d33d58ca8";
        let target_index: u32 = 0u32;
        let inputs: merkle_lib::MerkleProofInput =
            get_ethereum_receipt_proof_inputs(target_index, block_hash).await;

        let block = provider
            .get_block_by_hash(
                B256::from_str(block_hash).unwrap(),
                alloy::rpc::types::BlockTransactionsKind::Full,
            )
            .await
            .expect("Failed to get Block!")
            .expect("Block not found!");

        let transaction = verify_merkle_proof(
            block.header.receipts_root,
            inputs.proof,
            &alloy_rlp::encode(target_index),
        );

        println!(
            "Verified {:?} against {:?}",
            &transaction, &block.header.receipts_root
        );
    }

    #[test]
    fn compare_hash_fn() {
        let input: Vec<u8> = vec![0, 0, 0];
        let keccak_hash = keccak(input.clone());
        println!("keccak hash: {:?}", &keccak_hash.as_bytes());
        let sha3_hash = digest_keccak(&input);
        println!("sha3 hash: {:?}", &sha3_hash);
    }

    fn verify_merkle_proof(root_hash: B256, proof: Vec<Vec<u8>>, key: &[u8]) -> Vec<u8> {
        let proof_db = Arc::new(MemoryDB::new(true));
        for node_encoded in proof.clone().into_iter() {
            let hash: B256 = keccak(&node_encoded).as_fixed_bytes().into();
            proof_db.insert(hash.as_slice(), node_encoded).unwrap();
        }
        let mut trie = EthTrie::from(proof_db, root_hash).expect("Invalid root");
        println!("Root from Merkle Proof: {:?}", trie.root_hash().unwrap());
        trie.verify_proof(root_hash, key, proof)
            .expect("Failed to verify Merkle Proof")
            .expect("Key does not exist!")
    }

    #[tokio::test]
    async fn test_verify_receipt_merkle_proof() {
        let key = load_infura_key_from_env();
        println!("Key: {}", key);
        let rpc_url = "https://mainnet.infura.io/v3/".to_string() + &key;
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let block_hash = "0xe1dd1d7e0fa5263787bf0dca315a065bbd466ce6b827ef0b619502359feadac3";
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
                    eprintln!("Critical: Unknown Receipt Type")
                }
            }
        }
        assert_eq!(&block.header.receipts_root, &trie.root_hash().unwrap())
    }

    #[test]
    fn test_encode_receipt() {
        let expected = hex::decode("f901668001b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f85ff85d940000000000000000000000000000000000000011f842a0000000000000000000000000000000000000000000000000000000000000deada0000000000000000000000000000000000000000000000000000000000000beef830100ff").unwrap();
        let status = false;
        let cumulative_gas = 0x1u64;
        let bloom = Bloom::new([0; 256]);
        let logs: Vec<Log> = vec![Log {
            address: Address::from_hex("0000000000000000000000000000000000000011").unwrap(),
            topics: vec![
                H256::from_slice(
                    &hex::decode(
                        "000000000000000000000000000000000000000000000000000000000000dead",
                    )
                    .unwrap(),
                ),
                H256::from_slice(
                    &hex::decode(
                        "000000000000000000000000000000000000000000000000000000000000beef",
                    )
                    .unwrap(),
                ),
            ],
            data: hex::decode("0100ff").unwrap().to_vec(),
        }];

        let list_encode: [&dyn Encodable; 4] = [&status, &cumulative_gas, &bloom, &logs];
        let mut out: Vec<u8> = Vec::new();
        alloy_rlp::encode_list::<_, dyn Encodable>(&list_encode, &mut out);

        let mut o: Vec<u8> = Vec::new();
        logs.encode(&mut o);
        println!("Outputs: {:?}", &o);
        println!("Result: {:?}", &out);
        println!("Expectation: {:?}", &expected);
        assert_eq!(out, expected);
    }
}
