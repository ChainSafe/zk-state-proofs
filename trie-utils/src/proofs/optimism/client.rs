use super::types::{BlockResponse, BlockResult};
use reqwest::Client;
use serde_json::json;

pub struct OPClient {
    rpc_url: String,
    client: Client,
}

impl OPClient {
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
            let block_response: BlockResponse =
                serde_json::from_str(&response.text().await.unwrap()).unwrap();
            block_response.result
        } else {
            panic!("Failed to get OP Block!");
        }
    }
}
