use sp1_sdk::include_elf;
pub const MERKLE_ELF: &[u8] = include_elf!("merkle-proof");
fn main() {
    todo!("implement as client or lib")
}

#[cfg(test)]
mod tests {
    use crate::MERKLE_ELF;
    use sp1_sdk::{ProverClient, SP1Stdin};
    use trie_utils::{constants::DEFAULT_BLOCK_HASH, get_ethereum_transaction_proof_inputs};
    #[tokio::test]
    async fn test_generate_transaction_zk_proof() {
        sp1_sdk::utils::setup_logger();
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();
        let proof_input = serde_json::to_vec(
            &get_ethereum_transaction_proof_inputs(0u32, DEFAULT_BLOCK_HASH).await,
        )
        .unwrap();
        stdin.write(&proof_input);
        let (pk, vk) = client.setup(MERKLE_ELF);
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("Failed to generate proof!");
        let transaction_hash = proof.public_values.to_vec();
        println!(
            "[Success] Generated proof for Transaction: {:?}.",
            transaction_hash
        );
        client.verify(&proof, &vk).expect("Failed to verify proof!");
        println!(
            "[Success] Verified proof for Transaction: {:?}.",
            transaction_hash
        );
    }
}
