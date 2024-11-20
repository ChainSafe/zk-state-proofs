use alloy::{
    consensus::TxEnvelope,
    providers::{Provider, ProviderBuilder},
};
use alloy_primitives::B256;
// get transaction merkle proof from Ethereum
use dotenv::dotenv;
use eth_trie::{EthTrie, MemoryDB, Trie};
use merkle_lib::MerkleProofInput;
use std::{env, str::FromStr, sync::Arc};
use url::Url;
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
    println!("Expected Root: {:?}", &expected_root);
    println!("Actual Root: {:?}", &trie_root);

    let tx_index = 0u64;
    let tx_key = tx_index.to_be_bytes();

    // todo: check merkle proof
    let proof: Vec<Vec<u8>> = trie.get_proof(&tx_key).unwrap();
    /*trie.verify_proof(expected_root, &tx_key, proof.clone())
    .expect("Invalid merkle proof");*/

    //verify_merkle_proof(expected_root, proof);
    MerkleProofInput {
        proof,
        root_hash: expected_root.to_vec(),
    }
}

#[cfg(test)]
mod test {
    use super::load_infura_key_from_env;
    use alloy_primitives::{hex, B256};
    use eth_trie::{EthTrie, MemoryDB, Trie, DB};
    // ethers was deprecated
    // todo: use alloy everywhere
    use alloy::{
        consensus::TxEnvelope,
        providers::{Provider, ProviderBuilder},
    };
    use eth_trie_proofs::tx_trie::TxsMptHandler;
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
            println!(
                "index {:?}: {:?}",
                hex::encode(path),
                hex::encode(encoded_tx)
            );
        }
        let trie_root = trie.root_hash().unwrap();
        let expected_root = block.header.transactions_root;
        println!("Expected Root: {:?}", &expected_root);
        println!("Actual Root: {:?}", &trie_root);

        let tx_index = 0u64;
        let tx_key = tx_index.to_be_bytes();

        // todo: check merkle proof
        let proof: Vec<Vec<u8>> = trie.get_proof(&tx_key).unwrap();
        trie.verify_proof(expected_root, &tx_key, proof.clone())
            .expect("Invalid merkle proof");

        verify_merkle_proof(expected_root, proof);
    }

    #[tokio::test]
    async fn test_get_merkle_proof_eth_trie_proofs_lib() {
        let key = load_infura_key_from_env();
        println!("Key: {}", key);
        let rpc_url = "https://mainnet.infura.io/v3/".to_string() + &key;

        let mut txs_mpt_handler = TxsMptHandler::new(Url::parse(&rpc_url).unwrap()).unwrap();
        txs_mpt_handler
            .build_tx_tree_from_block(21229780)
            .await
            .unwrap();

        // take the hash of the first transaction
        let target_tx_hash = B256::from(hex!(
            "9b313a8091203cf49e5ebb519b57952331cc9471bf4043044518dfcfd79f834e"
        ));
        println!("Target TX: {}", &target_tx_hash);
        let tx_index = txs_mpt_handler.tx_hash_to_tx_index(target_tx_hash).unwrap();
        let proof = txs_mpt_handler.get_proof(tx_index).unwrap();
        txs_mpt_handler
            .verify_proof(tx_index, proof.clone())
            .unwrap();
    }

    /*
    #[tokio::test]
    async fn test_get_merkle_proof_alloy() {
        let key = load_infura_key_from_env();
        println!("Key: {}", key);
        let rpc_url = "https://mainnet.infura.io/v3/".to_string() + &key;
        let provider = Provider::try_from(rpc_url).expect("Failed to construct provider!");
        let block_hash = "0x8230bd00f36e52e68dd4a46bfcddeceacbb689d808327f4c76dbdf8d33d58ca8";
        //let untrusted_hash = "0xacb81623523bbabccb1638a907686bc2f3229c70e3ab51777bef0a635f3ac03f";

        let block = provider
            .get_block_with_txs(H256::from_str(block_hash).unwrap())
            .await
            .expect("Failed to get Block!")
            .expect("Block not found!");

        let mut builder = alloy_trie::HashBuilder::default();
        println!("Empty Root: {:?}", &builder.root());
        for (index, tx) in block.transactions.iter().enumerate() {
            let bytes = alloy_rlp::encode(index);
            println!("bytes: {:?}", &bytes);
            let nibbles = alloy_trie::Nibbles::unpack(index.to_be_bytes());
            println!("Nibbles: {:?}", &nibbles);
            builder.add_leaf(nibbles, &tx.rlp())
        }
        let root = builder.root();
        println!("Root: {:?}", &root);
        println!("Expected Root: {:?}", &block.transactions_root);
    }
    */

    /* Reference implementation

        fn verify_proof(
            &self,
            root_hash: B256,
            key: &[u8],
            proof: Vec<Vec<u8>>,
        ) -> TrieResult<Option<Vec<u8>>> {
            let proof_db = Arc::new(MemoryDB::new(true));
            for node_encoded in proof.into_iter() {
                let hash: B256 = keccak(&node_encoded).as_fixed_bytes().into();

                if root_hash.eq(&hash) || node_encoded.len() >= HASHED_LENGTH {
                    proof_db.insert(hash.as_slice(), node_encoded).unwrap();
                }
            }
            let trie = EthTrie::from(proof_db, root_hash).or(Err(TrieError::InvalidProof))?;
            trie.get(key).or(Err(TrieError::InvalidProof))
        }

    */
    fn verify_merkle_proof(root_hash: B256, proof: Vec<Vec<u8>>) {
        let proof_db = Arc::new(MemoryDB::new(true));
        for node_encoded in proof.into_iter() {
            let hash: B256 = keccak(&node_encoded).as_fixed_bytes().into();
            proof_db.insert(hash.as_slice(), node_encoded).unwrap();
        }
        let mut trie = EthTrie::from(proof_db, root_hash).expect("Invalid merkle proof");
        println!("Root from Merkle Proof: {:?}", trie.root_hash().unwrap());
    }

    #[test]
    fn compare_hash_fn() {
        let input: Vec<u8> = vec![0, 0, 0];
        let keccak_hash = keccak(input.clone());
        println!("keccak hash: {:?}", &keccak_hash.as_bytes());
        let sha3_hash = digest_keccak(&input);
        println!("sha3 hash: {:?}", &sha3_hash);
    }
}
