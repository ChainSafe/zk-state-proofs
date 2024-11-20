// get transaction merkle proof from Ethereum
use dotenv::dotenv;
use std::env;

pub fn load_infura_key_from_env() -> String {
    dotenv().ok();
    env::var("INFURA").expect("Missing Infura API key!")
}

#[cfg(test)]
mod test {
    use super::load_infura_key_from_env;
    use alloy_primitives::{hex, B256};
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use eth_trie_proofs::tx_trie::TxsMptHandler;
    use ethers::{
        providers::{Middleware, Provider},
        types::H256,
        utils::rlp::Encodable,
    };
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
        let provider = Provider::try_from(rpc_url).expect("Failed to construct provider!");
        // works with
        let block_hash = "0x8230bd00f36e52e68dd4a46bfcddeceacbb689d808327f4c76dbdf8d33d58ca8";
        // does not work with
        // 0xfa2459292cc258e554940516cd4dc12beb058a5640d0c4f865aa106db0354dfa

        let block = provider
            .get_block_with_txs(H256::from_str(block_hash).unwrap())
            .await
            .expect("Failed to get Block!")
            .expect("Block not found!");

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());

        for (index, tx) in block.transactions.iter().enumerate() {
            trie.insert(&index.rlp_bytes(), &tx.rlp())
                .expect("Failed to insert");
            println!("index {}: {:?}", index, index.rlp_bytes());
        }

        println!("transaction count: {}", block.transactions.len());

        let transaction_root = block.transactions_root;
        println!(
            "Expected Transaction Root: {:?}",
            &transaction_root.as_bytes()
        );
        let trie_root = trie.root_hash().unwrap();

        println!("Transaction Root raw: {}", &block.transactions_root);
        println!("Transaction Root raw: {}", &trie_root);
        assert_eq!(trie_root.to_vec(), transaction_root.as_bytes());

        /*let tx_index = block
        .transactions
        .iter()
        .position(|tx| tx.hash == H256::from_str(untrusted_hash).unwrap())
        .ok_or("Transaction not found in block")
        .unwrap();*/

        let tx_index = 0u64;
        let tx_key = tx_index.to_be_bytes();
        let proof = trie.get_proof(&tx_key).unwrap();

        println!(
            "Root from Proof: {:?}",
            &digest_keccak(proof.first().unwrap()).bytes()
        )
        // Trie potentially flawed, see https://github.com/ethereum/eth-trie.rs/issues/4
    }

    #[tokio::test]
    async fn test_get_merkle_proof_ggx() {
        use merkle_generator::IterativeTrie;
        let mut trie = merkle_generator::PatriciaTrie::new();

        let key = load_infura_key_from_env();
        println!("Key: {}", key);
        let rpc_url = "https://mainnet.infura.io/v3/".to_string() + &key;
        let provider = Provider::try_from(rpc_url).expect("Failed to construct provider!");
        let block_hash = "0xfa2459292cc258e554940516cd4dc12beb058a5640d0c4f865aa106db0354dfa";
        //let untrusted_hash = "0xacb81623523bbabccb1638a907686bc2f3229c70e3ab51777bef0a635f3ac03f";

        let block = provider
            .get_block_with_txs(H256::from_str(block_hash).unwrap())
            .await
            .expect("Failed to get Block!")
            .expect("Block not found!");

        for (index, tx) in block.transactions.iter().enumerate() {
            trie.insert(index.rlp_bytes().to_vec(), tx.rlp().to_vec());
            println!("index {}: {:?}", index, index.rlp_bytes());
        }

        let key = 0u64.rlp_bytes().to_vec();
        //let merkle_proof = trie.merkle_proof(key.clone());
    }

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

    #[test]
    fn compare_hash_fn() {
        use keccak_hash::keccak;
        let input: Vec<u8> = vec![0, 0, 0];
        let keccak_hash = keccak(input.clone());
        println!("keccak hash: {:?}", &keccak_hash.as_bytes());
        let sha3_hash = digest_keccak(&input);
        println!("sha3 hash: {:?}", &sha3_hash);
    }
}
