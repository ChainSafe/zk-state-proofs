pub use alloy::eips::eip2718::{Eip2718Envelope, Encodable2718};
use alloy::{
    consensus::{ReceiptEnvelope, ReceiptWithBloom, TxEnvelope, TxReceipt},
    primitives::B256,
    providers::{Provider, ProviderBuilder},
    rpc::types::{BlockTransactionsKind, TransactionReceipt},
};
use alloy_rlp::{BufMut, Encodable};
use crypto_ops::MerkleProofInput;
use dotenv::dotenv;
use eth_trie::{EthTrie, MemoryDB, Trie};
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
        consensus::{Account, ReceiptEnvelope},
        hex::{self, FromHex, ToHex},
        primitives::{Address, Bloom, FixedBytes, B256},
        providers::{Provider, ProviderBuilder},
        rpc::types::TransactionReceipt,
    };
    use alloy_rlp::{BufMut, Encodable};
    use crypto_ops::keccak::digest_keccak;
    use eth_trie::{EthTrie, MemoryDB, Trie, DB};
    use keccak_hash::keccak;
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
        let inputs: crypto_ops::MerkleProofInput =
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
        let inputs: crypto_ops::MerkleProofInput =
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

    #[tokio::test]
    async fn dump_test_block() {
        use std::fs::File;
        use std::io::Write;
        let key = load_infura_key_from_env();
        println!("Key: {}", key);
        let rpc_url: String = "https://mainnet.infura.io/v3/".to_string() + &key;
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let block_hash = "0x2683344180300c9eb6a2b7ef4f9ab6136ac230de731e742d482394b162d6a43b";

        let block = provider
            .get_block_by_hash(
                B256::from_str(block_hash).unwrap(),
                alloy::rpc::types::BlockTransactionsKind::Full,
            )
            .await
            .expect("Failed to get Block!")
            .expect("Block not found!");

        let mut block_file = File::create("./data/block.dat").unwrap();
        block_file
            .write_all(&serde_json::to_vec(&block).unwrap())
            .expect("Failed to write to block file");
    }

    #[tokio::test]
    async fn test_verify_account_and_storage_proof() {
        use std::fs::File;
        use std::io::Read;
        let mut block_file = File::open("./data/block.dat").unwrap();
        let mut block_buffer: Vec<u8> = vec![];
        block_file
            .read_to_end(&mut block_buffer)
            .expect("Failed to read block file");
        let key = load_infura_key_from_env();
        let rpc_url = "https://mainnet.infura.io/v3/".to_string() + &key;
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
            .get_proof(
                Address::from_hex("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap(),
                vec![FixedBytes::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap()],
            )
            .await
            .expect("Failed to get proof");
        println!("Proof: {:?}", &proof);
        let account_proof: Vec<u8> = verify_merkle_proof(
            block.header.state_root,
            proof
                .account_proof
                .clone()
                .into_iter()
                .map(|b| b.to_vec())
                .collect(),
            // key: keccak hash of the account hash
            &digest_keccak(&hex::decode("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap()),
        );

        let decoded_account: Account = alloy_rlp::decode_exact(&account_proof).unwrap();
        assert_eq!(
            decoded_account.storage_root.encode_hex::<String>(),
            hex::encode(&proof.storage_hash)
        );
        let _ = verify_merkle_proof(
            proof.storage_hash,
            proof
                .storage_proof
                .first()
                .unwrap()
                .proof
                .clone()
                .into_iter()
                .map(|b| b.to_vec())
                .collect(),
            &digest_keccak(
                &hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
            ),
        );
        println!("Verified Account Proof against Block Root & Storage Proof against Account Root")
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

/*
Storage Proof: [EIP1186StorageProof { key: Hash(0x0000000000000000000000000000000000000000000000000000000000000000), value: 1134972014892877928712953364190483482895670224936, proof: [0xf90211a0159e7ca4556d4e19a25a2536fb7de76e9bf3acbdaa5026f76e451518e98ccb77a0dfbb9dab1e5c517935c2432f6e9ab417481252413cdf0d49e233d49c1a74f4c3a0f536cf070243c692d2a86b48b5f94d17e38321b9f5126c787bb51ae3a2fc00ada0e52e8951b6f11787e28f00e2dc4d572bdcd3de56c25b35319aa3733945eb4cf6a0b5127f9ae185fb7817875c812f50e0b0e19be7e35dc84b5fee3e8d4e7d61f11ba033d5dd3cbac129dcc6384a065f7784331afc146b041b2c878d475d970c135e9ca0e32b15b66e0313810235f65df5df2627e13355560f428db951a88bfdd4a09c7fa055ffe102b7653a34622e6bdcf86896c377dc370eda7918d1619fcfc3e5624e78a022abb25ea28248075f5a09911589dee42c2695300d3fc9db53f52c5bd8544b6ea0c5844fe6de29b18798ed5d0782f6c3d184ab4c66fd646fd3c39480f59f3d1f39a0bb9ac6bbe29c665e711e2d2f785b4398991ef8a9cdb240468f40216c18911407a09d282fe0b3a84f410c5160b0ec51398c132f5c8f63c9a7a3b10356321b5c9fa6a020440b9bbafc0d0ed9e35997d8c36a1dcbe4bd89ba7712f206e44a6935cf3c10a0a58663cefcdd3a9a8e4ba49e584e0706150148527df146f02206cd21fe350893a0cb3e2f8e701792fd4790ba6468a47b93f21e60eeadad6c3777c479d4892f368ca05994fc7ace3f6b64d520b637413c2368236ce8136891833c34a471514b3eddf480, 0xf90211a0fec5ce2777fa890d7433a61aa81f7cbc75ff57a5badaae3e15f90118f8a0881ba0f129f1b128d0ee6a4785aae36f0cb108f06fe74393932cba832d4000ded56689a03e824ebff2a5b5a887e3355e41ee3409d9bf2a67af9c421c48b4793c598cd692a0ee1ef9cd1e3cc662a34464d205b1e4251c22410d3b78d234f5983bc8e9a234d7a06f320b898a36c572be9557f04a53607c87dc58359611d63a4d27a544e718fef1a0f5368d63204dc97038744ca87b222fae12d7ba0b54b91897a454342e51ee7936a06db150da0e48174ee9636cdbfa82c58b0bb7641b46a57939cf4c1bca675c0a7ea03715bfb63affee5d89dcc0a003774f0eff9fbd7bef926247d2bc1341610535a2a0736698252e432febd9a39bdeb5761bacb4505acf22e7d324312a159b90f9604da021ab3a390132fe16eaa12772aba1ff369372fff09a8a2f3d35347d911d4b9b20a001eb734670b80ed28a9a66a30e3a83073569796652bfcc91ee3e277325dfafa9a017905b08a03622b6bd0c678559324404fba9adc01bdc006909472433b47c5bd0a005095d30b8e76ccf6218e16b525bbc703454a6c0035835c04bdb851b2428cee3a0d81faaf03e08da11c3b33519ebf32f74c057c8c7eaa367d0433175b157bd4f0da04c42b452ee94b594599a4fc6ca02b3cb31038dd64537b3e0145fc912a86dea18a036af617e16c883eec2e6fa60b4b427728017846b4ca708ca1d05d91272bcbc9080, 0xf90211a0df4d774b4dc5e4bf6c6915c6d889dbe9e36b364ac6a99a93832b6b1710c6b90fa0e40776dd795a6f0fc1a7013a20e33fd7b86f7035764307af288e1f62328392dea0453ef21b7d313751bc4ec76e1a9fd7858f517cdfbd43ecae9741d6574e792f93a0aa782feb3bd5f6acb914fc85b47f21e4fb35c0825f5a2f9f2fe62097bb891736a0f9dd6351ca148f010ffe1f7587fde5fe63026185ba17a58c273166a0f83e7533a0eff4a301c5d6ca7f5fd24fd4cc256a9c2c60c05c96f5e69883526f551dc058a4a0d019d39da940b50fc02b10fcd421b87416fe07fc2ea9d97fc7ed77b2cfd0c3dfa0fd7da8856a12acf7fd0874066bd09b74f59da7dc0e3a0868e19c36eb58be84bfa011e621f30f50fdc79344194c7c128ea0c84676c600f573219df2eb88d7501d63a0e5e38fa6ac7e50a04d72df1b35d7fb834b65ceb40c9bc8b91b7298d5c64169faa093f50f828283b0ad89c8d47064ea0002bc1a26e80b51101157db8b9bc10719c7a05f0353bf77e91ba5fb341022c68a3ccdfe363ab4a534089e90150f467a644463a0d0c2c43722348b996c78fbc646dc9afb2528b79e7e3c4d1b118df8e408314643a04db525a945a0410d078b43ab287c8e2a8f2e55bb3df307bfd893dfcad4db3914a0e9f35ac3cad2239a4910bd0e93cb8dd4646ce7d09d1f6f3a6a334dc60c0782c7a0837047f1c5ff5b298d9a9a25cfbf255572f0d04696683c05ff59270339a3e86480, 0xf90211a0e2ca64ae529075620877150c41c06ee33397aa9aead27bf8074dffd505c975f5a0db1cd7d1abe822345a954498d749e5406c0e0b90a19b8655d9c3751a543cb77da0fb398296cc34be049babfc067d5cd28a7b50968fe5f05ccb378b4f9d7dbbda1ea0dacb81f3e0130eaa66a04e00bfd15f0cf70a342b7ac541d3f066bad2a7299778a0a191ebb38fb7614b96d79427270c0755aeaf2beb9d59631d98d16f4bc7f6dc65a008091207166a4253f96e1ee895819038ab70cd2f4b27fa6eb52ec142d4e58a0aa09a113c36f6e23dae3314ecd7358a9d0160cc3fcf26d28d7ec5f4403cf5e15c84a0df59486f9769ebe4974621e0ae830476d0ffd5a89c0d31ce4c192183f3ad009aa00cadac6dd57d9ee9b430c1cfe40016daee7f666e13fe4a174afa6eef13706252a01b4ff7c4b70485834450077a4093117d1f4e4b4c5c4276671e5a7a52789b2e9fa04abbe591e1f327f726c0bbe168bff20475172d4fd63acd9933227c1495a9b94fa0652f123d856a806ea9d57fd399eed98d51a44588e4bf6d09f784e659fb7044a2a0ed16548443f417533261d35bca2a1918f8ea235ff9f5ae6ff595a00cdc787a73a09b7c8f9712660c4061d7ea0a617255d1c64431a7f3ff8327d18dff713ac33028a092ba4b394f51cb7f2fd861dfccfded38e81f9c19f2e9a8e53ab091d9b456264ca03003f470a5df696027da8d2254497655bafac957248bf56c33cb5101eb70ee5380, 0xf90211a0f3f18d6137f5867680e9fa619a64a0d1219f226a3efaf6a2984bdba51e0643ada0f7bbbd7316355473103ddd064be4426aaaff58e3323f829ce4bb1cdcc8f28b4fa0e9d293c729f85f94ae3ab82bd218760111d8475b436de2a920d371f1c54052faa04fe703989a2141ba8e0d7281fbecd20b1df144490fd38aceaf13fd5b20008914a0b69e02b499a875eb7b788f98d5c97ad589d4b4066709424518a784d44d2b5e8fa0926d19c899776b49e45795c0cffaa8ff70ebb708bcc38a0beec2072e802dc14da0313ac10759fd92b6eb3b5f184173a2fc08d4523b45264fe12c98f9489b3c3277a0ba20155cc8761a6d4c1d8d38656adb254334a67bf50f7bbcef8804805cdacc40a0e4503b8905fe1fd79e6ed8c2864c98af51fa521399071c9ecc71a25ca73d84a8a0e74239bea0a082ec243a70a581befc4cc8057243788531f60544d2fdb7e58602a07f6d5530fab1ffabf0210affa9b84ccfc168a936db7187fefab6f30d9efa1012a05d78b052b59a09204f24c93ada6a17a6452df4ca6101df6042340610696a403fa07721cd100d940caa315627f1864d84ca3574c144464def50e09b112d004697c7a0a004bf8978e314f8d453bd1084c86b94ef87e390288a10df9447f42f229e145ba0112e5abe86fa4deedb100916c0d14a33b889bd34e31419cb53a5872b8e27aa91a05afa364d9e0e60570b92975507f8224c1029e1abb51ab3e91e3da194dd1d244880, 0xf90111a022b9d68ec893e46a41c316bde1406b19b1b15e51f5c35f3dfbbaeff3e302661e80a00ad2d2e385dff997534ad374657268101fda36e31285552d4ac0f06209ff6df6808080a07a52523bb1990b64c50fd6648a657e92e196788ba02f98ad0c1fd3d25b0b0d53a0294bde53062110328103e301062faad0e1175bc1e3649eadc5b281a298f4df1680a06634703c405b8015855bb7bea0084457878c1b806f1db3997ed8889a82f85c948080a032f769f61f78abf648e9985feb6e0712a65ed03fdd534069a16594c895712f11a0de64a3a75f4323d8f7c9db0c643ef1c2bf521e28ad8540271be9d4e7b9da198a80a06f23ca1f167b52e366a7cb9628d5d7d5ca2af5377e951e6907721d6a2227210380, 0xf8718080a03269a56e4a8c5a0db5480a777c04f55435708b2aa668221eca0a51597f917eed8080808080808080a0188adbc95db819328813c282bfe9d78819dff2c5c83041ba936431635424da8a80a0f4873cb7178849abe99b3515f3195aebc99d9534da6ec2e0810451fa4b9991d8808080, 0xf49d39548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594c6cde7c39eb2f0f0095f41570af89efc2c1ea828] }]


*/
