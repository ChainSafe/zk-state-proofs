# Prove merkle paths for EVM transactions in SP1

## Test Data
```rust
    let blockHashThatITrust = '0xc32470c2459fd607246412e23b4b4d19781c1fa24a603d47a5bc066be3b5c0af'
    let untrustedTxHash = '0xacb81623523bbabccb1638a907686bc2f3229c70e3ab51777bef0a635f3ac03f'
```

## Prove a real Ethereum mainnet Transaction in ZK

`cargo test zk_verify_real_eth_transaction`:

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


