use sp1_sdk::include_elf;
/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const MERKLE_ELF: &[u8] = include_elf!("program-tx-merkle");

fn main() {
    todo!("implement as client or lib")
}

#[cfg(test)]
mod tests {
    use crate::MERKLE_ELF;
    use sp1_sdk::{ProverClient, SP1Stdin};
    use trie_utils::get_ethereum_transaction_proof_inputs;
    #[tokio::test]
    async fn zk_verify_real_eth_transaction() {
        sp1_sdk::utils::setup_logger();
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();
        // alternative block hash
        // 0xfa2459292cc258e554940516cd4dc12beb058a5640d0c4f865aa106db0354dfa
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
}
