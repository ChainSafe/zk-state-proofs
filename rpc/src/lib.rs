// get transaction merkle proof from Ethereum
use dotenv::dotenv;
use std::env;

pub fn load_infura_key_from_env() -> String {
    dotenv().ok();
    env::var("INFURA").expect("Missing Infura API key!")
}

#[cfg(test)]
mod test {
    use std::{hash::Hash, io::Read, str::FromStr, sync::Arc};

    use super::load_infura_key_from_env;
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethers::{
        providers::{Middleware, Provider},
        types::H256,
        utils::rlp::{self, RlpStream},
    };
    use keccak_hash::keccak;
    use merkle_lib::keccak::digest_keccak;

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
        let block_hash = "0xc32470c2459fd607246412e23b4b4d19781c1fa24a603d47a5bc066be3b5c0af";
        let untrusted_hash = "0xacb81623523bbabccb1638a907686bc2f3229c70e3ab51777bef0a635f3ac03f";

        let block = provider
            .get_block_with_txs(H256::from_str(block_hash).unwrap())
            .await
            .expect("Failed to get Block!")
            .expect("Block not found!");

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        for (index, tx) in block.transactions.iter().enumerate() {
            let serialized_tx = tx.rlp();
            trie.insert(&alloy_rlp::encode(index), &serialized_tx)
                .expect("Failed to insert");
        }

        let tx_index = block
            .transactions
            .iter()
            .position(|tx| tx.hash == H256::from_str(untrusted_hash).unwrap())
            .ok_or("Transaction not found in block")
            .unwrap();
        let tx_key = tx_index.to_be_bytes();
        let proof = trie.get_proof(&tx_key).unwrap();
        let transaction_root = block.transactions_root;
        println!(
            "Expected Transaction Root: {:?}",
            &transaction_root.as_bytes()
        );
        let trie_root = trie.root_hash().unwrap();
        println!("Trie root: {:?}", &trie_root.bytes());

        println!(
            "Root from Proof: {:?}",
            &digest_keccak(proof.first().unwrap()).bytes()
        )
    }
    #[test]
    fn compare_hash_fn() {
        use keccak_hash::{keccak, H256};
        let input: Vec<u8> = vec![0, 0, 0];
        let keccak_hash = keccak(input.clone());
        println!("keccak hash: {:?}", &keccak_hash.as_bytes());
        let sha3_hash = digest_keccak(&input);
        println!("sha3 hash: {:?}", &sha3_hash);
    }
}
