use alloy::{
    consensus::{ReceiptWithBloom, TxEnvelope, TxReceipt},
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    rpc::types::BlockTransactionsKind,
};
// get transaction merkle proof from Ethereum
pub use alloy::eips::eip2718::{Eip2718Envelope, Encodable2718};
use alloy_rlp::{Encodable, RlpEncodableWrapper};
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

pub async fn get_proof_for_transaction() -> MerkleProofInput {
    let key = load_infura_key_from_env();
    println!("Key: {}", key);
    let rpc_url = "https://mainnet.infura.io/v3/".to_string() + &key;
    let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
    let block_hash = "0x8230bd00f36e52e68dd4a46bfcddeceacbb689d808327f4c76dbdf8d33d58ca8";
    // another block
    // 0xfa2459292cc258e554940516cd4dc12beb058a5640d0c4f865aa106db0354dfa

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
    let trie_root = trie.root_hash().unwrap();
    let expected_root = block.header.transactions_root;
    println!("Expected Root: {:?}", &expected_root);
    println!("Actual Root: {:?}", &trie_root);

    let tx_index = 0u64;
    let tx_key = alloy_rlp::encode(tx_index);

    // todo: check merkle proof
    let proof: Vec<Vec<u8>> = trie.get_proof(&tx_key).unwrap();
    /*trie.verify_proof(expected_root, &tx_key, proof.clone())
    .expect("Invalid merkle proof");*/

    //verify_merkle_proof(expected_root, proof);
    MerkleProofInput {
        proof,
        root_hash: expected_root.to_vec(),
        key: tx_key,
    }
}

#[cfg(test)]
mod test {

    use crate::{Log, H256};
    use alloy::{consensus::TxReceipt, rpc::types::Log as AlloyLog};

    use super::load_infura_key_from_env;
    use alloy::{
        consensus::{ReceiptEnvelope, ReceiptWithBloom, TxEnvelope},
        hex::{self, FromHex},
        primitives::{Address, Bloom, B256},
        providers::{Provider, ProviderBuilder},
        rpc::types::TransactionReceipt,
    };
    use alloy_rlp::{BufMut, Encodable};
    use eth_trie::{EthTrie, MemoryDB, Trie, DB};
    // ethers was deprecated
    // todo: use alloy everywhere
    //use eth_trie_proofs::tx_trie::TxsMptHandler;
    use keccak_hash::keccak;
    use merkle_lib::keccak::digest_keccak;
    use std::{io::Read, str::FromStr, sync::Arc};
    use url::Url;

    #[test]
    fn test_infura_key() {
        let key = load_infura_key_from_env();
        println!("Key: {}", key);
    }

    #[tokio::test]
    async fn test_get_merkle_proof() {
        let key = load_infura_key_from_env();
        println!("Key: {}", key);
        let rpc_url = "https://mainnet.infura.io/v3/".to_string() + &key;
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let block_hash = "0x8230bd00f36e52e68dd4a46bfcddeceacbb689d808327f4c76dbdf8d33d58ca8";
        // another block
        // 0xfa2459292cc258e554940516cd4dc12beb058a5640d0c4f865aa106db0354dfa

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
        let trie_root = trie.root_hash().unwrap();
        let expected_root = block.header.transactions_root;

        let tx_index = 15u64;
        let tx_key = alloy_rlp::encode(tx_index);

        // todo: check merkle proof
        let proof: Vec<Vec<u8>> = trie.get_proof(&tx_key).unwrap();

        trie.verify_proof(expected_root, &tx_key, proof.clone())
            .expect("Invalid merkle proof");

        assert_eq!(expected_root, trie_root);

        let transaction = verify_merkle_proof(expected_root, proof, &tx_key);
        println!(
            "Verified Transaction: {:?} against Root: {:?}",
            &transaction, &trie_root
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
        // another block
        // 0xfa2459292cc258e554940516cd4dc12beb058a5640d0c4f865aa106db0354dfa
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
        let mut out: Vec<u8> = Vec::new();
        if let Some(prefix) = prefix {
            out.put_u8(prefix);
        };

        alloy_rlp::encode_list::<_, dyn Encodable>(&list_encode, &mut out);
        trie.insert(&index_encoded, &alloy_rlp::encode(&out))
            .expect("Failed to insert");
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

pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}

impl Log {
    fn rlp_header(&self) -> alloy_rlp::Header {
        let payload_length =
            self.address.length() + self.topics.length() + self.data.as_slice().length();
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
    }
}

impl Encodable for Log {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let header = self.rlp_header();
        encode!(out, header, self.address, self.topics, self.data.as_slice());
    }
    fn length(&self) -> usize {
        let rlp_head = self.rlp_header();
        alloy_rlp::length_of_length(rlp_head.payload_length) + rlp_head.payload_length
    }
}

#[derive(Debug, RlpEncodableWrapper, PartialEq, Clone)]
pub struct H256(pub [u8; 32]);

impl H256 {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..slice.len()].copy_from_slice(slice);
        Self(bytes)
    }
}
