use crate::client::ArchRpcClient;
use crate::ArchError;
use crate::Config;
use crate::{arch_program::pubkey::Pubkey, with_secret_key_file};
use bitcoin::{address::Address, Amount, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::str::FromStr;
use std::sync::Arc;
use titan_client::{TitanApi, TitanClient};

#[derive(Clone)]
pub struct BitcoinHelper {
    network: Network,
    rpc_client: Arc<Client>,
    arch_client: ArchRpcClient,
    titan_client: TitanClient,
}

impl BitcoinHelper {
    pub fn new(config: &Config) -> Result<Self, ArchError> {
        let userpass = Auth::UserPass(config.node_username.clone(), config.node_password.clone());
        let rpc_client = Arc::new(
            Client::new(&config.node_endpoint, userpass)
                .map_err(|e| ArchError::BitcoinRpcError(e.to_string()))?,
        );
        let arch_client = ArchRpcClient::new(config);
        Ok(Self {
            network: config.network,
            rpc_client,
            arch_client,
            titan_client: TitanClient::new(config.titan_url.as_str()),
        })
    }

    async fn get_account_address(&self, pubkey: Pubkey) -> Result<String, ArchError> {
        self.arch_client.get_account_address(&pubkey).await
    }

    pub async fn send_utxo(&self, pubkey: Pubkey) -> Result<(String, u32), String> {
        let address = self
            .get_account_address(pubkey)
            .await
            .map_err(|e| e.to_string())?;

        let account_address = match Address::from_str(&address) {
            Ok(addr) => match addr.require_network(self.network) {
                Ok(addr) => addr,
                Err(e) => return Err(format!("Network mismatch for address: {}", e)),
            },
            Err(e) => return Err(format!("Failed to parse address: {}", e)),
        };

        let rpc = self.rpc_client.clone();
        let addr_clone = account_address.clone();
        let (txid, sent_tx) = tokio::task::spawn_blocking(move || {
            let txid = rpc
                .send_to_address(
                    &addr_clone,
                    Amount::from_sat(3000),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .map_err(|e| format!("Failed to send to address: {}", e))?;

            let sent_tx = rpc
                .get_raw_transaction(&txid, None)
                .map_err(|e| format!("Failed to get raw transaction: {}", e))?;

            Ok::<_, String>((txid, sent_tx))
        })
        .await
        .map_err(|e| format!("spawn_blocking join error: {}", e))??;

        let mut vout = 0;
        for (index, output) in sent_tx.output.iter().enumerate() {
            if output.script_pubkey == account_address.script_pubkey() {
                vout = index as u32;
            }
        }

        self.wait_until_titan_indexes_transaction(&txid).await?;

        Ok((txid.to_string(), vout))
    }

    pub async fn wait_until_titan_indexes_transaction(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<(), String> {
        for _ in 0..60 {
            if self.titan_client.get_transaction(txid).await.is_ok() {
                return Ok(());
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }

        Err("Failed to wait for transaction to be indexed".to_string())
    }
}

pub async fn prepare_fees() -> Result<String, ArchError> {
    use bitcoin::{
        absolute::LockTime,
        address::Address,
        key::{TapTweak, TweakedKeypair, XOnlyPublicKey},
        secp256k1::{self, Secp256k1},
        sighash::{Prevouts, SighashCache},
        transaction::Version,
        Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, Witness,
    };
    use bitcoincore_rpc::{Auth, Client, RawTx, RpcApi};

    let test_config = crate::Config::localnet();

    let userpass = Auth::UserPass(
        test_config.node_username.to_string(),
        test_config.node_password.to_string(),
    );
    let rpc = Arc::new(
        Client::new(&test_config.node_endpoint, userpass)
            .map_err(|e| ArchError::BitcoinRpcError(e.to_string()))?,
    );

    let (key_pair, _) = with_secret_key_file(".program")?;

    let (public_key, _) = XOnlyPublicKey::from_keypair(&key_pair);
    let secp = Secp256k1::new();
    let address = Address::p2tr(&secp, public_key, None, test_config.network);

    let rpc_clone = rpc.clone();
    let addr_clone = address.clone();
    let txid = tokio::task::spawn_blocking(move || {
        rpc_clone
            .send_to_address(
                &addr_clone,
                Amount::from_sat(100000),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .map_err(|e| ArchError::BitcoinRpcError(e.to_string()))
    })
    .await
    .map_err(|e| ArchError::BitcoinRpcError(e.to_string()))??;

    let rpc_clone = rpc.clone();
    let txid_clone = txid;
    let sent_tx = tokio::task::spawn_blocking(move || {
        rpc_clone
            .get_raw_transaction(&txid_clone, None)
            .map_err(|e| ArchError::BitcoinRpcError(e.to_string()))
    })
    .await
    .map_err(|e| ArchError::BitcoinRpcError(e.to_string()))??;

    let mut vout: u32 = 0;
    for (index, output) in sent_tx.output.iter().enumerate() {
        if output.script_pubkey == address.script_pubkey() {
            vout = index as u32;
        }
    }

    let mut tx = Transaction {
        version: Version::TWO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![],
        lock_time: LockTime::ZERO,
    };

    let sighash_type = TapSighashType::NonePlusAnyoneCanPay;
    let prevouts = vec![sent_tx.output[vout as usize].clone()];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .map_err(|e| ArchError::BitcoinRpcError(e.to_string()))?;

    let secp = Secp256k1::new();
    let tweaked: TweakedKeypair = key_pair.tap_tweak(&secp, None);
    let msg = secp256k1::Message::from(sighash);
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    tx.input[0].witness.push(signature.to_vec());

    Ok(tx.raw_hex())
}
