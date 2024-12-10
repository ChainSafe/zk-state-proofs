# 🔐 Complete Library to prove EVM state in ZK, to cryptographically verify storage, transactions, receipts and accounts!
This library exposes functions and ZK circuits (SP1, Risc0) to obtain, verify and prove query infromation from `Ethereum` clients.

# Overview of provided functions

| account | storage | receipt | transaction |
| --- | --- | --- | --- |
| Verify that an account exists in the Ethereum Trie | Verify a value stored under an account or smart contract | Verify a receipt or the entire receipt trie of a block | Verify native Ethereum transactions |

- `accounts`: any Ethereum address with a Balance > 0
- `receipts`: data related to events (for example ERC20 transfer information)

# Obtain a Merkle Proof for a value in Ethereum State
For each of these values in storage a function is provided that helps obtain a `merkle proof` from the Ethereum client using `alloy rpc`:

`trie-utils/src/proofs/*`
- account.rs
- receipt.rs
- storage.rs
- transaction.rs

For example `transaction.rs` returns a `merkle proof` for an individual native Ethereum transaction:

```rust
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
```

# Verify a Merkle Proof against a trusted State Root
The `merkle proof` is then be verified using the `verify_merkle_proof` function found in `crypto-ops/lib.rs`:

```rust
pub fn verify_merkle_proof(root_hash: B256, proof: Vec<Vec<u8>>, key: &[u8]) -> Vec<u8> {
    let proof_db = Arc::new(MemoryDB::new(true));
    for node_encoded in proof.clone().into_iter() {
        let hash: B256 = digest_keccak(&node_encoded).into();
        proof_db.insert(hash.as_slice(), node_encoded).unwrap();
    }
    let mut trie = EthTrie::from(proof_db, root_hash).expect("Invalid merkle proof");
    assert_eq!(root_hash, trie.root_hash().unwrap());
    trie.verify_proof(root_hash, key, proof)
        .expect("Failed to verify Merkle Proof")
        .expect("Key does not exist!")
}
```

This function checks that the trie root matches the `trusted root` obtained from the [Light Client](https://github.com/jonas089/spectre-rad).
And that the data we claim exists in the Trie is actually present at the specified path (=`key`). 

# Generate a ZK proof for the validity of a Merkle Proof
In order to prove our Merkle verification in ZK, we can use the circuit located in `circuits/merkle-proof/src/main.rs`:

```rust
#![no_main]
sp1_zkvm::entrypoint!(main);
use crypto_ops::{types::MerkleProofInput, verify_merkle_proof};
pub fn main() {
    let merkle_proof: MerkleProofInput =
        serde_json::from_slice(&sp1_zkvm::io::read::<Vec<u8>>()).unwrap();

    let output = verify_merkle_proof(
        merkle_proof.root_hash.as_slice().try_into().unwrap(),
        merkle_proof.proof.clone(),
        &merkle_proof.key,
    );
    sp1_zkvm::io::commit_slice(&output);
}
```

To try this against a real Ethereum Transaction for testing purposes, run:

`cargo test --bin prover test_generate_transaction_zk_proof_sp1 -F sp1`

> [!NOTE]
> The feature flag `sp1` tells the compiler to leverage the `keccak` precompile for hash acceleration in the ZK circuit.