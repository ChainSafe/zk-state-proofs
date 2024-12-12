use sp1_sdk::include_elf;
pub const MERKLE_ELF: &[u8] = include_elf!("sp1-merkle-proof");
fn main() {
    todo!("implement as client or lib")
}

#[cfg(test)]
mod tests {
    use crate::MERKLE_ELF;
    use alloy_primitives::Address;
    use hex::FromHex;
    use risc0_merkle_proof_circuit::{RISC0_MERKLE_PROOF_ELF, RISC0_MERKLE_PROOF_ID};
    use risc0_zkvm::{default_prover, ExecutorEnv};
    use sp1_sdk::{ProverClient, SP1Stdin};
    use std::time::Instant;
    use trie_utils::{
        constants::{DEFAULT_BLOCK_HASH, DEFAULT_OPTIMISM_BLOCK_HASH, USDT_CONTRACT_ADDRESS},
        proofs::{
            account::get_ethereum_account_proof_inputs,
            transaction::{
                get_ethereum_transaction_proof_inputs, get_optimism_transaction_proof_inputs,
            },
        },
    };

    #[tokio::test]
    async fn test_generate_ethereum_transaction_zk_proof_risc0() {
        let start_time = Instant::now();
        let proof_input = get_ethereum_transaction_proof_inputs(0u32, DEFAULT_BLOCK_HASH).await;

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let env = ExecutorEnv::builder()
            .write(&proof_input)
            .unwrap()
            .build()
            .unwrap();
        let prover = default_prover();
        let prove_info = prover.prove(env, RISC0_MERKLE_PROOF_ELF).unwrap();
        let receipt = prove_info.receipt;
        receipt.verify(RISC0_MERKLE_PROOF_ID).unwrap();
        let duration = start_time.elapsed();
        println!("Elapsed time: {:?}", duration);
    }

    #[tokio::test]
    async fn test_generate_ethereum_transaction_zk_proof_sp1() {
        let start_time = Instant::now();
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
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
        let duration = start_time.elapsed();
        println!("Elapsed time: {:?}", duration);
    }

    #[tokio::test]
    async fn test_generate_optimism_transaction_zk_proof_risc0() {
        let start_time = Instant::now();

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let proof_input =
            get_optimism_transaction_proof_inputs(0u32, DEFAULT_OPTIMISM_BLOCK_HASH).await;
        let env = ExecutorEnv::builder()
            .write(&proof_input)
            .unwrap()
            .build()
            .unwrap();
        let prover = default_prover();
        let prove_info = prover.prove(env, RISC0_MERKLE_PROOF_ELF).unwrap();
        let receipt = prove_info.receipt;
        receipt.verify(RISC0_MERKLE_PROOF_ID).unwrap();
        let duration = start_time.elapsed();
        println!("Elapsed time: {:?}", duration);
    }

    #[tokio::test]
    async fn test_generate_optimism_transaction_zk_proof_sp1() {
        let start_time = Instant::now();
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let proof_input = serde_json::to_vec(
            &get_optimism_transaction_proof_inputs(0u32, DEFAULT_OPTIMISM_BLOCK_HASH).await,
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
        let duration = start_time.elapsed();
        println!("Elapsed time: {:?}", duration);
    }

    #[tokio::test]
    async fn test_generate_ethereum_account_zk_proof_sp1() {
        let start_time = Instant::now();
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let proof_input = serde_json::to_vec(
            &get_ethereum_account_proof_inputs(Address::from_hex(USDT_CONTRACT_ADDRESS).unwrap())
                .await,
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
        let duration = start_time.elapsed();
        println!("Elapsed time: {:?}", duration);
    }

    #[tokio::test]
    async fn test_generate_ethereum_account_zk_proof_risc0() {
        let start_time = Instant::now();

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let proof_input =
            get_ethereum_account_proof_inputs(Address::from_hex(USDT_CONTRACT_ADDRESS).unwrap())
                .await;
        let env = ExecutorEnv::builder()
            .write(&proof_input)
            .unwrap()
            .build()
            .unwrap();
        let prover = default_prover();
        let prove_info = prover.prove(env, RISC0_MERKLE_PROOF_ELF).unwrap();
        let receipt = prove_info.receipt;
        receipt.verify(RISC0_MERKLE_PROOF_ID).unwrap();
        let duration = start_time.elapsed();
        println!("Elapsed time: {:?}", duration);
    }
}
