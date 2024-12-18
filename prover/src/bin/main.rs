use sp1_sdk::include_elf;
pub const MERKLE_ELF: &[u8] = include_elf!("sp1-merkle-proof");
fn main() {
    todo!("implement as client or lib")
}

#[cfg(test)]
mod tests {
    use crate::MERKLE_ELF;
    use alloy::{
        providers::{Provider, ProviderBuilder},
        transports::http::reqwest::Url,
    };
    use alloy_primitives::{Address, FixedBytes};
    use hex::FromHex;
    use risc0_merkle_proof_circuit::{RISC0_MERKLE_PROOF_ELF, RISC0_MERKLE_PROOF_ID};
    use risc0_storage_proof_circuit::{RISC0_STORAGE_PROOF_ELF, RISC0_STORAGE_PROOF_ID};
    use risc0_zkvm::{default_prover, ExecutorEnv};
    use sp1_sdk::{ProverClient, SP1Stdin};
    use std::{str::FromStr, time::Instant};
    use trie_utils::{
        constants::{
            DEFAULT_BLOCK_HASH, DEFAULT_OPTIMISM_BLOCK_HASH, DEFAULT_STORAGE_KEY_ETHEREUM,
            NODE_RPC_URL, USDT_CONTRACT_ADDRESS,
        },
        load_infura_key_from_env,
        proofs::{
            account::get_account_proof_inputs,
            storage::get_storage_proof_inputs,
            transaction::{
                get_ethereum_transaction_proof_inputs, get_optimism_transaction_proof_inputs,
            },
        },
        types::NetworkEvm,
    };

    #[tokio::test]
    async fn test_generate_ethereum_transaction_zk_proof_risc0() {
        let start_time = Instant::now();
        let proof_input =
            borsh::to_vec(&get_ethereum_transaction_proof_inputs(0u32, DEFAULT_BLOCK_HASH).await)
                .unwrap();

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let env = ExecutorEnv::builder()
            .write_slice(&proof_input)
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
        let proof_input =
            borsh::to_vec(&get_ethereum_transaction_proof_inputs(0u32, DEFAULT_BLOCK_HASH).await)
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
        let proof_input = borsh::to_vec(
            &get_optimism_transaction_proof_inputs(0u32, DEFAULT_OPTIMISM_BLOCK_HASH).await,
        )
        .unwrap();

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let env = ExecutorEnv::builder()
            .write_slice(&proof_input)
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
        let proof_input = borsh::to_vec(
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
    async fn test_generate_ethereum_account_zk_proof_risc0() {
        let start_time = Instant::now();

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let proof_input = borsh::to_vec(
            &get_account_proof_inputs(
                Address::from_hex(USDT_CONTRACT_ADDRESS).unwrap(),
                NetworkEvm::Ethereum,
            )
            .await,
        )
        .unwrap();
        let env = ExecutorEnv::builder()
            .write_slice(&proof_input)
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
    async fn test_generate_ethereum_account_zk_proof_sp1() {
        let start_time = Instant::now();
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        // note that when verifying the merkle proof a trusted root should be used
        // instead of the root hash from input
        let proof_input = borsh::to_vec(
            &get_account_proof_inputs(
                Address::from_hex(USDT_CONTRACT_ADDRESS).unwrap(),
                NetworkEvm::Ethereum,
            )
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
    async fn test_generate_ethereum_storage_zk_proof_risc0() {
        let start_time = Instant::now();
        let key = load_infura_key_from_env();
        let rpc_url = NODE_RPC_URL.to_string() + &key;
        let provider = ProviderBuilder::new().on_http(Url::from_str(&rpc_url).unwrap());
        let block = provider
            .get_block(
                alloy::eips::BlockId::Number(provider.get_block_number().await.unwrap().into()),
                alloy::rpc::types::BlockTransactionsKind::Full,
            )
            .await
            .unwrap()
            .unwrap();

        let proof_input = borsh::to_vec(
            &get_storage_proof_inputs(
                USDT_CONTRACT_ADDRESS.to_string(),
                vec![FixedBytes::from_hex(DEFAULT_STORAGE_KEY_ETHEREUM).unwrap()],
                NetworkEvm::Ethereum,
                block.header.state_root.to_vec(),
            )
            .await,
        )
        .unwrap();
        let env = ExecutorEnv::builder()
            .write_slice(&proof_input)
            .build()
            .unwrap();
        let prover = default_prover();
        let prove_info = prover.prove(env, RISC0_STORAGE_PROOF_ELF).unwrap();
        let receipt = prove_info.receipt;
        receipt.verify(RISC0_STORAGE_PROOF_ID).unwrap();
        let duration = start_time.elapsed();
        println!("Elapsed time: {:?}", duration);
    }
}
