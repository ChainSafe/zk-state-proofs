pub const NODE_RPC_URL: &'static str = "https://mainnet.infura.io/v3/";
pub const ARBITRUM_ONE_RPC_URL: &'static str = "https://arb1.arbitrum.io/rpc";
pub const OPTIMISM_RPC_URL: &'static str = "https://mainnet.optimism.io/";
// used for testing
pub const DEFAULT_BLOCK_HASH: &'static str =
    "0x8230bd00f36e52e68dd4a46bfcddeceacbb689d808327f4c76dbdf8d33d58ca8";
// used for testing
pub const DEFAULT_ARBITRUM_ONE_BLOCK_HASH: &'static str =
    "0x4f1ab3cfc6ce0b2cf989b4e7a1811e38647b0e0fd6695b923fe8870eab1aaf24";
// used for testing
pub const DEFAULT_OPTIMISM_BLOCK_HASH: &'static str =
    "0xda01e7fa47eb8261260369794b4eb1afe06470f2f7b047eadaf031737a3038e8";
// used for testing
pub const USDT_CONTRACT_ADDRESS: &'static str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
// used for testing
pub const DEFAULT_STORAGE_KEY: &'static str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/* Get Block

curl -X POST -H "Content-Type: application/json" --data '{
    "jsonrpc": "2.0",
    "method": "eth_getBlockByHash",
    "params": [
        "0xda01e7fa47eb8261260369794b4eb1afe06470f2f7b047eadaf031737a3038e8",
        true
    ],
    "id": 1
}' https://mainnet.optimism.io/

     */
