use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const MERKLE_ELF: &[u8] = include_elf!("merkle-prover");

fn main() {
    sp1_sdk::utils::setup_logger();
    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();
    stdin.write(&vec![0, 0, 0]);
    let (pk, vk) = client.setup(MERKLE_ELF);
    let proof = client
        .prove(&pk, stdin)
        .run()
        .expect("failed to generate proof");
    println!("Successfully generated proof!");
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Successfully verified proof!");
}
