use crate::arch_program::pubkey::Pubkey;
use crate::client::ArchRpcClient;
use crate::Config;
use bitcoin::{address::Address, Amount, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::str::FromStr;
use std::sync::Arc;
use titan_client::{TitanApiBlocking, TitanBlockingClient};

/// Helper struct for Bitcoin operations
#[derive(Clone)]
pub struct BitcoinHelper {
    /// Bitcoin network (Mainnet, Testnet, Regtest)
    network: Network,
    /// Bitcoin RPC client
    rpc_client: Arc<Client>,
    /// Arch RPC client
    arch_client: ArchRpcClient,
    /// Titan Client
    titan_client: TitanBlockingClient,
}

impl BitcoinHelper {
    /// Create a new BitcoinHelper
    pub fn new(config: &Config) -> Self {
        let userpass = Auth::UserPass(config.node_username.clone(), config.node_password.clone());
        let rpc_client = Arc::new(
            Client::new(&config.node_endpoint, userpass)
                .expect("Failed to initialize Bitcoin RPC client"),
        );
        let arch_client = ArchRpcClient::new(config);
        Self {
            network: config.network,
            rpc_client,
            arch_client,
            titan_client: titan_client::TitanBlockingClient::new(config.titan_url.as_str()),
        }
    }

    /// Get the account address for the given pubkey
    fn get_account_address(&self, pubkey: Pubkey) -> String {
        self.arch_client
            .get_account_address(&pubkey)
            .expect("Failed to get account address")
    }

    /// Used to send a utxo to the taptweaked account address corresponding to the
    /// network's joint pubkey
    pub fn send_utxo(&self, pubkey: Pubkey) -> Result<(String, u32), String> {
        let address = self.get_account_address(pubkey);

        let account_address = match Address::from_str(&address) {
            Ok(addr) => match addr.require_network(self.network) {
                Ok(addr) => addr,
                Err(e) => return Err(format!("Network mismatch for address: {}", e)),
            },
            Err(e) => return Err(format!("Failed to parse address: {}", e)),
        };

        let txid = match self.rpc_client.send_to_address(
            &account_address,
            Amount::from_sat(3000),
            None,
            None,
            None,
            None,
            None,
            None,
        ) {
            Ok(txid) => txid,
            Err(e) => return Err(format!("Failed to send to address: {}", e)),
        };

        let sent_tx = match self.rpc_client.get_raw_transaction(&txid, None) {
            Ok(tx) => tx,
            Err(e) => return Err(format!("Failed to get raw transaction: {}", e)),
        };

        let mut vout = 0;
        for (index, output) in sent_tx.output.iter().enumerate() {
            if output.script_pubkey == account_address.script_pubkey() {
                vout = index as u32;
            }
        }

        self.wait_until_titan_indexes_transaction(&txid)?;

        Ok((txid.to_string(), vout))
    }

    pub fn wait_until_titan_indexes_transaction(&self, txid: &bitcoin::Txid) -> Result<(), String> {
        let mut wait_time = 0;
        while self.titan_client.get_transaction(txid).is_err() && wait_time < 60 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            wait_time += 1;
        }

        if wait_time >= 60 {
            return Err("Failed to wait for transaction to be indexed".to_string());
        }

        Ok(())
    }
}
