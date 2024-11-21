# Prove merkle paths for EVM transactions in SP1

> [!WARNING]
> Not production ready, under heavy development

## Test Data
```rust
    let blockHashThatITrust = '0xc32470c2459fd607246412e23b4b4d19781c1fa24a603d47a5bc066be3b5c0af'
    let untrustedTxHash = '0xacb81623523bbabccb1638a907686bc2f3229c70e3ab51777bef0a635f3ac03f'
```

## Prove a real Ethereum mainnet Transaction in ZK

`cd script && cargo test zk_verify_real_eth_transaction --release`:

```rust
#[tokio::test]
async fn zk_verify_real_eth_transaction() {
    sp1_sdk::utils::setup_logger();
    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();

    let proof_input = serde_json::to_vec(&get_proof_for_transaction().await).unwrap();

    stdin.write(&proof_input);
    let (pk, vk) = client.setup(MERKLE_ELF);
    let proof = client
        .prove(&pk, stdin)
        .run()
        .expect("failed to generate proof");
    println!("Successfully generated proof!");
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Successfully verified proof!");
}
```

## Deep dive 1: Circuit
The circuit calls the simple merkle proof verification function that depends on the `keccak` precompile:

```rust
pub fn verify_merkle_proof(root_hash: B256, proof: Vec<Vec<u8>>, key: &[u8]) -> Vec<u8> {
    let proof_db = Arc::new(MemoryDB::new(true));
    for node_encoded in proof.clone().into_iter() {
        let hash: B256 = digest_keccak(&node_encoded).into();
        proof_db.insert(hash.as_slice(), node_encoded).unwrap();
    }
    let trie = EthTrie::from(proof_db, root_hash).expect("Invalid merkle proof");
    trie.verify_proof(root_hash, key, proof)
        .expect("Failed to verify Merkle Proof")
        .expect("Key does not exist!")
}
```

If the merkle proof is invalid for the given root hash the circuit will revert and there will be no valid
proof.

## Deep dive 2: Ethereum Merkle Trie
This implementation depends on the [eth_trie](https://crates.io/crates/eth_trie) crate.
`eth_trie` is a reference implementation of the merkle patricia trie.
In the `rpc` crate full integration tests for constructing the trie can be found.
Click [here](https://github.com/jonas089/sp1-eth-tx/blob/master/rpc/src/lib.rs) to review the code.




