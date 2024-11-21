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
        }
        let trie_root = trie.root_hash().unwrap();
        let expected_root = block.header.transactions_root;

        let tx_index = 0u64;
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

        /*for node_rlp in proof.into_iter().rev() {
            let node = decode_node(&mut node_rlp.as_slice()).expect("Failed to decode node");
            let recomputed_hash: B256 = digest_keccak(&node_rlp).into();
            match node {
                Node::Extension(_) => {}
                Node::Branch(_) => {}
                Node::Leaf(_) => {}
                _ => {}
            }
        }*/
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
