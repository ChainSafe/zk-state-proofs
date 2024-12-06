# Prove merkle paths for EVM transactions in SP1

> [!WARNING]
> Not production ready, under heavy development

## Prove a real Ethereum mainnet Transaction in SP1
`cargo test --bin prover test_sp1_merkle_proof_circuit --release`:

```rust
#[tokio::test]
async fn test_sp1_merkle_proof_circuit() {
    sp1_sdk::utils::setup_logger();
    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();
    let proof_input = serde_json::to_vec(
        &get_ethereum_transaction_proof_inputs(
            0u32,
            "0x8230bd00f36e52e68dd4a46bfcddeceacbb689d808327f4c76dbdf8d33d58ca8",
        )
        .await,
    )
    .unwrap();
    stdin.write(&proof_input);
    let (pk, vk) = client.setup(MERKLE_ELF);
    let proof = client
        .prove(&pk, stdin)
        .run()
        .expect("failed to generate proof");
    let transaction_hash = proof.public_values.to_vec();
    println!(
        "Successfully generated proof for Transaction: {:?}",
        transaction_hash
    );
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!(
        "Successfully verified proof for Transaction: {:?}",
        transaction_hash
    );
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




## Benchmarks on M3 Macbook Pro

### Eth-trie (not perfectly optimized) using Keccak precompile

| 10 Transactions  | 20 Transactions | 30 Transactions |
| ------------- | ------------- | ------------- |
| - | - | - |