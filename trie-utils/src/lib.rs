pub use alloy::eips::eip2718::{Eip2718Envelope, Encodable2718};
use dotenv::dotenv;
use std::env;
mod macros;
pub fn load_infura_key_from_env() -> String {
    dotenv().ok();
    env::var("INFURA").expect("Missing Infura API key!")
}
mod proofs;
pub mod receipt;
pub mod types;
pub use proofs::{
    account::get_ethereum_account_proof_inputs, receipt::get_ethereum_receipt_proof_inputs,
    storage::get_ethereum_storage_proof_inputs, transaction::get_ethereum_transaction_proof_inputs,
};
pub mod constants;
