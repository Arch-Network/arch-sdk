use bitcoin::{address::Address, Amount, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use crate::arch_program::pubkey::Pubkey;
use crate::client::ArchRpcClient;

/// Helper struct for Bitcoin operations
pub struct BitcoinHelper {
    /// Bitcoin network (Mainnet, Testnet, Regtest)
    network: Network,
    /// Bitcoin RPC client
    rpc_client: Client,
    /// Arch RPC client
    arch_client: ArchRpcClient,
}

impl BitcoinHelper {
    /// Create a new BitcoinHelper
    pub fn new(
        node_endpoint: String,
        node_username: String,
        node_password: String,
        network: Network,
        arch_node_url: String,
    ) -> Self {
        let userpass = Auth::UserPass(node_username.clone(), node_password.clone());
        let rpc_client =
            Client::new(&node_endpoint, userpass).expect("Failed to initialize Bitcoin RPC client");

        let arch_client = ArchRpcClient::new(&arch_node_url);

        Self {
            network,
            rpc_client,
            arch_client,
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

        sleep(Duration::from_millis(200));

        Ok((txid.to_string(), vout))
    }
}
