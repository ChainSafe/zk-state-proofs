pub use alloy::eips::eip2718::{Eip2718Envelope, Encodable2718};
use dotenv::dotenv;
use std::env;
mod macros;
pub fn load_infura_key_from_env() -> String {
    dotenv().ok();
    env::var("INFURA").expect("Missing Infura API key!")
}
pub mod constants;
pub mod proofs;
pub mod receipt;
pub mod types;
