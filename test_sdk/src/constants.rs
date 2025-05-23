//! This module contains constants for testing purposes

/// Default node address for testing
pub const NODE1_ADDRESS: &str = "http://localhost:9002/";

/// The file path where the caller stores information (test-specific)
pub const CALLER_FILE_PATH: &str = ".caller.json";
pub const PROGRAM_FILE_PATH: &str = ".program.json";
pub const PROGRAM_AUTHORITY_FILE_PATH: &str = ".program_authority.json";

/// Arbitrary example names for HelloWorld program (test-specific)
pub const NAME1: &str = "Amine";
pub const NAME2: &str = "Marouane";

/// Test Bitcoin node configuration
pub const BITCOIN_NODE_ENDPOINT: &str = "http://127.0.0.1:18443/wallet/testwallet";
pub const BITCOIN_NODE_USERNAME: &str = "bitcoin";
pub const BITCOIN_NODE_PASSWORD: &str = "bitcoinpass";
pub const MINING_ADDRESS: &str = "bcrt1q9s6pf9hswah20jjnzmyvk9s2xwp7srz6m2r5tw";

pub const BITCOIN_NODE1_ADDRESS: &str = "http://127.0.0.1:18443/wallet/testwallet";
pub const BITCOIN_NODE2_ADDRESS: &str = "http://127.0.0.1:18453/wallet/testwallet";

pub const BITCOIN_NODE1_P2P_ADDRESS: &str = "127.0.0.1:18444";
pub const BITCOIN_NODE2_P2P_ADDRESS: &str = "127.0.0.1:18454";

pub const BITCOIN_NETWORK: bitcoin::Network = bitcoin::Network::Regtest;

/// Explorer URL constants
pub const EXPLORER_URL_MAINNET: &str = "https://mempool.space";
pub const EXPLORER_URL_TESTNET: &str = "https://mempool.space/testnet4";
pub const EXPLORER_URL_DEV: &str = "https://mempool.dev.aws.archnetwork.xyz";

pub const API_URL_MAINNET: &str = "https://mempool.space/api/v1";
pub const API_URL_TESTNET: &str = "https://mempool.space/testnet4/api/v1";
pub const API_URL_DEV: &str = "https://mempool.dev.aws.archnetwork.xyz/api/v1";

/// Get the explorer URL based on the Bitcoin network
pub fn get_explorer_url(network: bitcoin::Network) -> String {
    match network {
        bitcoin::Network::Bitcoin => EXPLORER_URL_MAINNET.to_string(),
        bitcoin::Network::Testnet => EXPLORER_URL_TESTNET.to_string(),
        _ => EXPLORER_URL_DEV.to_string(),
    }
}

/// Get the transaction URL for the explorer
pub fn get_explorer_tx_url(network: bitcoin::Network, tx_id: &str) -> String {
    format!("{}/tx/{}", get_explorer_url(network), tx_id)
}

/// Get the address URL for the explorer
pub fn get_explorer_address_url(network: bitcoin::Network, address: &str) -> String {
    format!("{}/address/{}", get_explorer_url(network), address)
}

/// Get the API URL based on the Bitcoin network
pub fn get_api_url(network: bitcoin::Network) -> String {
    match network {
        bitcoin::Network::Bitcoin => API_URL_MAINNET.to_string(),
        bitcoin::Network::Testnet => API_URL_TESTNET.to_string(),
        _ => API_URL_DEV.to_string(),
    }
}

/// Get the API endpoint URL
pub fn get_api_endpoint_url(network: bitcoin::Network, endpoint: &str) -> String {
    format!("{}/{}", get_api_url(network), endpoint)
}
