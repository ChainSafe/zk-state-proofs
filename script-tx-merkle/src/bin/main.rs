use trie_utils::get_proof_for_transaction;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const MERKLE_ELF: &[u8] = include_elf!("program-tx-merkle");

fn main() {
    todo!("implement as client or lib")
}

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
