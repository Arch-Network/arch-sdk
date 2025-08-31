use bitcoin::Network;

#[derive(Clone)]
pub struct Config {
    pub node_endpoint: String,
    pub node_username: String,
    pub node_password: String,
    pub network: Network,
    pub arch_node_url: String,
}

impl Config {
    pub fn localnet() -> Self {
        Self {
            node_endpoint: "http://127.0.0.1:18443/wallet/testwallet".to_string(),
            node_username: "bitcoin".to_string(),
            node_password: "bitcoinpass".to_string(),
            network: Network::Regtest,
            arch_node_url: "http://localhost:9002/".to_string(),
        }
    }

    pub fn devnet() -> Self {
        Self {
            node_endpoint: "".to_string(),
            node_username: "bitcoin".to_string(),
            node_password: "bitcoinpass".to_string(),
            network: Network::Testnet4,
            arch_node_url: "".to_string(),
        }
    }

    pub fn testnet() -> Self {
        Self {
            node_endpoint: "".to_string(),
            node_username: "bitcoin".to_string(),
            node_password: "bitcoinpass".to_string(),
            network: Network::Testnet4,
            arch_node_url: "".to_string(),
        }
    }

    pub fn mainnet() -> Self {
        Self {
            node_endpoint: "".to_string(),
            node_username: "bitcoin".to_string(),
            node_password: "bitcoinpass".to_string(),
            network: Network::Bitcoin,
            arch_node_url: "".to_string(),
        }
    }
    // TODO: Add devnet, testnet and mainnet configs
}
