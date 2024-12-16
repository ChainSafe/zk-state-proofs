use reqwest::Client;
use serde_json::json;

use super::types::{AccountProofResponse, BlockResponse, BlockResult};

pub struct ArbitrumClient {
    rpc_url: String,
    client: Client,
}

impl ArbitrumClient {
    pub fn new(rpc_url: String, client: Client) -> Self {
        Self { rpc_url, client }
    }
    pub async fn get_block_by_hash(&self, block_hash: &str) -> BlockResult {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByHash",
            "params": [
                block_hash,
                true
            ],
            "id": 1
        });
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await
            .unwrap();
        if response.status().is_success() {
            let response_text = response.text().await.unwrap();
            let block_response: BlockResponse = serde_json::from_str(&response_text).unwrap();
            block_response.result
        } else {
            panic!("Failed to get Arb Block!");
        }
    }
    pub async fn get_block_by_number(&self, block_number: &str) -> BlockResult {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [
                block_number,
                true
            ],
            "id": 1
        });
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await
            .unwrap();
        if response.status().is_success() {
            let response_text = response.text().await.unwrap();
            let block_response: BlockResponse = serde_json::from_str(&response_text).unwrap();
            block_response.result
        } else {
            panic!("Failed to get Arb Block!");
        }
    }
    pub async fn get_proof(&self, account: &str, keys: Vec<String>) -> AccountProofResponse {
        let payload = json!({
          "id": 1,
          "jsonrpc": "2.0",
          "method": "eth_getProof",
          "params": [
            account,
            keys,
            "latest"
          ]
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await
            .unwrap();

        if response.status().is_success() {
            let response_text = response.text().await.unwrap();
            println!("Response: {:?}", &response_text);
            let account_proof_response: AccountProofResponse =
                serde_json::from_str(&response_text).unwrap();
            account_proof_response
        } else {
            panic!("Failed to get Arb Block!");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ArbitrumClient;
    use crate::constants::{
        ARBITRUM_ONE_RPC_URL, DEFAULT_ARBITRUM_ONE_BLOCK_HASH, DEFAULT_STORAGE_KEY_ETHEREUM,
        USDT_CONTRACT_ADDRESS_ARBITRUM,
    };
    use reqwest::Client;

    #[tokio::test]
    async fn test_get_block() {
        let reqwest_client = Client::new();
        let arb_client = ArbitrumClient::new(ARBITRUM_ONE_RPC_URL.to_string(), reqwest_client);
        let block = arb_client
            .get_block_by_hash(DEFAULT_ARBITRUM_ONE_BLOCK_HASH)
            .await;
        println!("Block: {:?}", &block);
    }

    #[tokio::test]
    async fn test_get_latest_block() {
        let reqwest_client = Client::new();
        let arb_client = ArbitrumClient::new(ARBITRUM_ONE_RPC_URL.to_string(), reqwest_client);
        let block = arb_client.get_block_by_number("latest").await;
        println!("Block: {:?}", &block);
    }

    #[tokio::test]
    async fn test_get_account_proof() {
        let reqwest_client: Client = Client::new();
        let arb_client = ArbitrumClient::new(ARBITRUM_ONE_RPC_URL.to_string(), reqwest_client);
        let _ = arb_client
            .get_proof(USDT_CONTRACT_ADDRESS_ARBITRUM, vec![])
            .await;
    }

    #[tokio::test]
    async fn test_get_storage_proof() {
        let reqwest_client: Client = Client::new();
        let arb_client = ArbitrumClient::new(ARBITRUM_ONE_RPC_URL.to_string(), reqwest_client);
        let proof = arb_client
            .get_proof(
                USDT_CONTRACT_ADDRESS_ARBITRUM,
                vec![DEFAULT_STORAGE_KEY_ETHEREUM.to_string()],
            )
            .await;
        assert!(proof.result.storage_proof.is_some());
    }
}
