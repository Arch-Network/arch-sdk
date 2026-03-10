use crate::arch_program::pubkey::Pubkey;
use crate::client::error::{ArchError, Result};
use crate::client::transport::http::HttpClient;
use crate::client::transport::{RpcTransport, TcpClient};
use crate::{
    sign_message_bip322, AccountInfoWithPubkey, BlockTransactionFilter, Config, FullBlock,
    MAX_TX_BATCH_SIZE,
};
use arch_program::hash::Hash;
use bitcoin::key::Keypair;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{from_str, json, Value};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

// Import the appropriate result types
use crate::types::{
    AccountFilter, AccountInfo, Block, ProcessedTransaction, ProgramAccount, RuntimeTransaction,
    Status,
};

pub const ACCOUNT_FUNDING_AMOUNT: u64 = 1_000_000;

// RPC method constants
pub const READ_ACCOUNT_INFO: &str = "read_account_info";
pub const GET_MULTIPLE_ACCOUNTS: &str = "get_multiple_accounts";
pub const SEND_TRANSACTION: &str = "send_transaction";
pub const SEND_TRANSACTIONS: &str = "send_transactions";
pub const GET_BLOCK: &str = "get_block";
pub const GET_FULL_BLOCK_WITH_TXIDS: &str = "get_full_block_with_txids";
pub const GET_BLOCK_BY_HEIGHT: &str = "get_block_by_height";
pub const GET_BLOCK_COUNT: &str = "get_block_count";
pub const GET_BLOCK_HASH: &str = "get_block_hash";
pub const GET_BEST_BLOCK_HASH: &str = "get_best_block_hash";
pub const GET_BEST_FINALIZED_BLOCK_HASH: &str = "get_best_finalized_block_hash";
pub const GET_PROCESSED_TRANSACTION: &str = "get_processed_transaction";
pub const GET_ACCOUNT_ADDRESS: &str = "get_account_address";
pub const GET_PROGRAM_ACCOUNTS: &str = "get_program_accounts";
pub const CHECK_PRE_ANCHOR_CONFLICT: &str = "check_pre_anchor_conflict";

/// Error code returned by the RPC server for "not found" responses
const RPC_NOT_FOUND_CODE: i64 = 404;

/// ArchRpcClient provides a simple interface for making RPC calls to the Arch blockchain
#[derive(Clone)]
pub struct ArchRpcClient {
    pub config: Config,
    transport: Arc<dyn RpcTransport>,
}

impl ArchRpcClient {
    /// Create a new ArchRpcClient with the specified URL
    pub fn new(config: &Config) -> Self {
        let http = HttpClient::new(config.arch_node_url.clone());
        Self {
            config: config.clone(),
            transport: Arc::new(http),
        }
    }

    /// Create a new ArchRpcClient with the specified TCP server address.
    pub fn new_tcp(config: &Config, addr: String) -> Result<Self> {
        let tcp = TcpClient::new(addr)?;
        Ok(Self {
            config: config.clone(),
            transport: Arc::new(tcp),
        })
    }

    /// Make a raw RPC call with no parameters and parse the result
    /// Returns None if the item was not found (404)
    pub async fn call_method<R: DeserializeOwned>(&self, method: &str) -> Result<Option<R>> {
        match self.process_result(self.post(method).await?)? {
            Some(value) => {
                let result = serde_json::from_value(value).map_err(|e| {
                    ArchError::ParseError(format!("Failed to deserialize response: {}", e))
                })?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Make a raw RPC call with parameters and parse the result
    /// Returns None if the item was not found (404)
    pub async fn call_method_with_params<T: Serialize + std::fmt::Debug, R: DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<Option<R>> {
        match self.process_result(self.post_data(method, params).await?)? {
            Some(value) => {
                let result = serde_json::from_value(value).map_err(|e| {
                    ArchError::ParseError(format!("Failed to deserialize response: {}", e))
                })?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Get raw value from a method call
    /// Returns None if the item was not found (404)
    pub async fn call_method_raw(&self, method: &str) -> Result<Option<Value>> {
        self.process_result(self.post(method).await?)
    }

    /// Get raw value from a method call with parameters
    /// Returns None if the item was not found (404)
    pub async fn call_method_with_params_raw<T: Serialize + std::fmt::Debug>(
        &self,
        method: &str,
        params: T,
    ) -> Result<Option<Value>> {
        self.process_result(self.post_data(method, params).await?)
    }

    /// Read account information for the specified public key
    pub async fn read_account_info(&self, pubkey: Pubkey) -> Result<AccountInfo> {
        match self
            .call_method_with_params(READ_ACCOUNT_INFO, pubkey)
            .await?
        {
            Some(info) => Ok(info),
            None => Err(ArchError::NotFound(format!(
                "Account not found for pubkey: {}",
                pubkey
            ))),
        }
    }

    /// Read account information for multiple public keys
    pub async fn get_multiple_accounts(
        &self,
        pubkeys: Vec<Pubkey>,
    ) -> Result<Vec<Option<AccountInfoWithPubkey>>> {
        match self
            .call_method_with_params(GET_MULTIPLE_ACCOUNTS, pubkeys.clone())
            .await?
        {
            Some(info) => Ok(info),
            None => Err(ArchError::NotFound(format!(
                "Accounts not found for pubkeys: {:?}",
                pubkeys
            ))),
        }
    }

    /// Request an airdrop for a given public key
    pub async fn request_airdrop(&self, pubkey: Pubkey) -> Result<ProcessedTransaction> {
        let result = self
            .process_result(self.post_data("request_airdrop", pubkey).await?)?
            .ok_or(ArchError::RpcRequestFailed(
                "request_airdrop failed".to_string(),
            ))?;

        // Handle the result parsing with proper error handling
        let txid_str = result.as_str().ok_or_else(|| {
            ArchError::ParseError("Failed to get transaction ID as string".to_string())
        })?;

        let txid = Hash::from_str(txid_str)?;
        let processed_tx = self.wait_for_processed_transaction(&txid).await?;
        Ok(processed_tx)
    }

    /// Create an account with lamports
    pub async fn create_and_fund_account_with_faucet(&self, keypair: &Keypair) -> Result<()> {
        let pubkey = Pubkey::from_slice(&keypair.x_only_public_key().0.serialize());

        if self.read_account_info(pubkey).await.is_ok() {
            let _processed_tx = self.request_airdrop(pubkey).await?;
        } else {
            let result = self
                .process_result(self.post_data("create_account_with_faucet", pubkey).await?)?
                .ok_or(ArchError::RpcRequestFailed(
                    "create_account_with_faucet failed".to_string(),
                ))?;
            let mut runtime_tx: RuntimeTransaction = serde_json::from_value(result)?;

            let message_hash = runtime_tx.message.hash();
            let signature = crate::Signature::from(sign_message_bip322(
                keypair,
                &message_hash,
                self.config.network,
            )?);

            runtime_tx.signatures.push(signature);

            let result = self.send_transaction(runtime_tx).await?;

            let _processed_tx = self.wait_for_processed_transaction(&result).await?;
        }
        let account_info = self.read_account_info(pubkey).await?;

        // assert_eq!(account_info.owner, Pubkey::system_program());
        assert!(account_info.lamports >= ACCOUNT_FUNDING_AMOUNT);

        Ok(())
    }

    /// Get a processed transaction by ID
    pub async fn get_processed_transaction(
        &self,
        tx_id: &Hash,
    ) -> Result<Option<ProcessedTransaction>> {
        self.call_method_with_params(GET_PROCESSED_TRANSACTION, tx_id.to_string())
            .await
    }

    /// Get a block with its transactions by ID
    pub async fn get_full_block_with_txids(
        &self,
        block_id: &Hash,
    ) -> Result<(Block, Vec<ProcessedTransaction>)> {
        match self
            .call_method_with_params(GET_FULL_BLOCK_WITH_TXIDS, block_id.to_string())
            .await?
        {
            Some(info) => Ok(info),
            None => Err(ArchError::NotFound(format!(
                "Block with txids not found for block id: {}",
                block_id
            ))),
        }
    }

    /// Waits for a transaction to be processed, polling until it reaches "Processed" or "Failed" status.
    /// Will timeout after 60 seconds of wall-clock time.
    pub async fn wait_for_processed_transaction(
        &self,
        tx_id: &Hash,
    ) -> Result<ProcessedTransaction> {
        let timeout = Duration::from_secs(60);
        let start = Instant::now();
        let poll_interval = Duration::from_secs(1);

        // First try to get the transaction, retry if null
        let mut tx = match self.get_processed_transaction(tx_id).await {
            Ok(Some(tx)) => tx,
            Ok(None) => {
                // Transaction not found, start polling
                loop {
                    tokio::time::sleep(poll_interval).await;
                    if start.elapsed() >= timeout {
                        return Err(ArchError::TimeoutError(format!(
                            "Failed to retrieve processed transaction {} after 60 seconds",
                            tx_id
                        )));
                    }
                    match self.get_processed_transaction(tx_id).await? {
                        Some(tx) => break tx,
                        None => continue,
                    }
                }
            }
            Err(e) => return Err(e),
        };

        // Now wait for the transaction to finish processing
        while !is_transaction_finalized(&tx) {
            tokio::time::sleep(poll_interval).await;
            if start.elapsed() >= timeout {
                return Err(ArchError::TimeoutError(format!(
                    "Transaction {} did not reach final status after 60 seconds",
                    tx_id
                )));
            }
            match self.get_processed_transaction(tx_id).await? {
                Some(updated_tx) => {
                    tx = updated_tx;
                }
                None => {
                    return Err(ArchError::TransactionError(format!(
                        "Transaction {} disappeared after being found",
                        tx_id
                    )));
                }
            }
        }

        Ok(tx)
    }

    /// Waits for multiple transactions to be processed, showing progress with a progress bar
    /// Returns a vector of processed transactions in the same order as the input transaction IDs
    pub async fn wait_for_processed_transactions(
        &self,
        tx_ids: Vec<Hash>,
    ) -> Result<Vec<ProcessedTransaction>> {
        let mut processed_transactions: Vec<ProcessedTransaction> =
            Vec::with_capacity(tx_ids.len());

        for tx_id in tx_ids {
            match self.wait_for_processed_transaction(&tx_id).await {
                Ok(tx) => processed_transactions.push(tx),
                Err(e) => {
                    return Err(ArchError::TransactionError(format!(
                        "Failed to process transaction {}: {}",
                        tx_id, e
                    )))
                }
            }
        }

        Ok(processed_transactions)
    }

    /// Get the best block hash
    pub async fn get_best_block_hash(&self) -> Result<Hash> {
        self.fetch_hash(GET_BEST_BLOCK_HASH, "best block hash")
            .await
    }

    /// Get the best finalized block hash
    pub async fn get_best_finalized_block_hash(&self) -> Result<Hash> {
        self.fetch_hash(GET_BEST_FINALIZED_BLOCK_HASH, "best finalized block hash")
            .await
    }

    /// Shared helper: call a no-params RPC method and parse the result as a Hash
    async fn fetch_hash(&self, method: &str, description: &str) -> Result<Hash> {
        match self.call_method_raw(method).await? {
            Some(value) => {
                let hash_str = value.as_str().ok_or_else(|| {
                    ArchError::ParseError(format!("Failed to get {}", description))
                })?;
                Ok(Hash::from_str(hash_str)?)
            }
            None => Err(ArchError::NotFound(format!("{} not found", description))),
        }
    }

    /// Get the block hash for a given height
    pub async fn get_block_hash(&self, block_height: u64) -> Result<String> {
        match self
            .call_method_with_params_raw(GET_BLOCK_HASH, block_height)
            .await?
        {
            Some(value) => value.as_str().map(|s| s.to_string()).ok_or_else(|| {
                ArchError::ParseError("Failed to get block hash as string".to_string())
            }),
            None => Err(ArchError::NotFound(format!(
                "Block hash not found for height: {}",
                block_height
            ))),
        }
    }

    /// Get the current block count
    pub async fn get_block_count(&self) -> Result<u64> {
        match self.call_method(GET_BLOCK_COUNT).await? {
            Some(count) => Ok(count),
            None => Err(ArchError::NotFound("Block count not found".to_string())),
        }
    }

    /// Get block by hash with signatures only
    pub async fn get_block_by_hash(&self, block_hash: &str) -> Result<Option<Block>> {
        // For signatures only, we can just pass the block hash directly
        self.call_method_with_params(GET_BLOCK, block_hash).await
    }

    /// Get full block by hash with complete transaction details
    pub async fn get_full_block_by_hash(&self, block_hash: &str) -> Result<Option<FullBlock>> {
        self.fetch_full_block(GET_BLOCK, block_hash).await
    }

    /// Get block by height with signatures only
    pub async fn get_block_by_height(&self, block_height: u64) -> Result<Option<Block>> {
        self.call_method_with_params(GET_BLOCK_BY_HEIGHT, block_height)
            .await
    }

    /// Get full block by height with complete transaction details
    pub async fn get_full_block_by_height(&self, block_height: u64) -> Result<Option<FullBlock>> {
        self.fetch_full_block(GET_BLOCK_BY_HEIGHT, block_height)
            .await
    }

    /// Shared helper: fetch a full block with a given key (hash or height)
    async fn fetch_full_block<T: Serialize>(
        &self,
        method: &str,
        key: T,
    ) -> Result<Option<FullBlock>> {
        let params = vec![
            serde_json::to_value(key)?,
            serde_json::to_value(BlockTransactionFilter::Full)?,
        ];
        match self.process_result(self.post_data(method, params).await?)? {
            Some(value) => {
                let result = serde_json::from_value(value).map_err(|e| {
                    ArchError::ParseError(format!("Failed to deserialize FullBlock: {}", e))
                })?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Get account address for a public key
    pub async fn get_account_address(&self, pubkey: &Pubkey) -> Result<String> {
        match self.process_result(
            self.post_data(GET_ACCOUNT_ADDRESS, pubkey.serialize())
                .await?,
        )? {
            Some(value) => value.as_str().map(|s| s.to_string()).ok_or_else(|| {
                ArchError::ParseError("Failed to get account address as string".to_string())
            }),
            None => Err(ArchError::NotFound(format!(
                "Account address not found for pubkey: {}",
                pubkey
            ))),
        }
    }

    /// Get program accounts for a given program ID
    pub async fn get_program_accounts(
        &self,
        program_id: &Pubkey,
        filters: Option<Vec<AccountFilter>>,
    ) -> Result<Vec<ProgramAccount>> {
        // Format params as [program_id, filters]
        let params = json!([program_id.serialize(), filters]);
        match self
            .call_method_with_params(GET_PROGRAM_ACCOUNTS, params)
            .await?
        {
            Some(accounts) => Ok(accounts),
            None => Err(ArchError::NotFound(format!(
                "Program accounts not found for program ID: {}",
                program_id
            ))),
        }
    }

    pub async fn check_pre_anchor_conflict(&self, accounts: Vec<Pubkey>) -> Result<bool> {
        let params = accounts;
        match self
            .call_method_with_params(CHECK_PRE_ANCHOR_CONFLICT, params)
            .await?
        {
            Some(result) => Ok(result),
            None => Err(ArchError::RpcRequestFailed(
                "check_pre_anchor_conflict returned no result".to_string(),
            )),
        }
    }

    /// Get the network pubkey from the network
    pub async fn get_network_pubkey(&self) -> Result<String> {
        match self.call_method::<String>("get_network_pubkey").await? {
            Some(key) => Ok(key),
            None => Err(ArchError::NotFound("Network pubkey not found".to_string())),
        }
    }

    /// Send a single transaction
    pub async fn send_transaction(&self, transaction: RuntimeTransaction) -> Result<Hash> {
        match self.process_result(self.post_data(SEND_TRANSACTION, transaction).await?)? {
            Some(value) => {
                let tx_id_str = value.as_str().ok_or_else(|| {
                    ArchError::ParseError("Failed to get transaction ID as string".to_string())
                })?;
                Ok(Hash::from_str(tx_id_str)?)
            }
            None => Err(ArchError::TransactionError(
                "Failed to send transaction".to_string(),
            )),
        }
    }

    /// Send multiple transactions
    pub async fn send_transactions(
        &self,
        transactions: Vec<RuntimeTransaction>,
    ) -> Result<Vec<Hash>> {
        if transactions.len() > MAX_TX_BATCH_SIZE {
            return Err(ArchError::TransactionError(
                "Batch size exceeds maximum".to_string(),
            ));
        }

        match self
            .call_method_with_params::<Vec<RuntimeTransaction>, Vec<String>>(
                SEND_TRANSACTIONS,
                transactions,
            )
            .await?
        {
            Some(tx_ids) => {
                let mut parsed_tx_ids = Vec::new();
                for id in tx_ids {
                    let hash = Hash::from_str(&id)?;
                    parsed_tx_ids.push(hash);
                }
                Ok(parsed_tx_ids)
            }
            None => Err(ArchError::TransactionError(
                "Failed to send transactions".to_string(),
            )),
        }
    }

    /// Helper methods for RPC communication
    pub fn process_result(&self, response: String) -> Result<Option<Value>> {
        let result = from_str::<Value>(&response)
            .map_err(|e| ArchError::ParseError(format!("Failed to parse JSON: {}", e)))?;

        let result = match result {
            Value::Object(object) => object,
            _ => {
                return Err(ArchError::ParseError(
                    "Unexpected JSON structure".to_string(),
                ))
            }
        };

        if let Some(err) = result.get("error") {
            if let Value::Object(err_obj) = err {
                if let (Some(Value::Number(code)), Some(Value::String(message))) =
                    (err_obj.get("code"), err_obj.get("message"))
                {
                    if code.as_i64() == Some(RPC_NOT_FOUND_CODE) {
                        return Ok(None);
                    }
                    return Err(ArchError::RpcRequestFailed(format!(
                        "Code: {}, Message: {}",
                        code, message
                    )));
                }
            }
            return Err(ArchError::RpcRequestFailed(format!("{:?}", err)));
        }

        Ok(Some(result["result"].clone()))
    }

    async fn post(&self, method: &str) -> Result<String> {
        let json = json!({
            "jsonrpc": "2.0",
            "id": "curlycurl",
            "method": method,
        });
        self.transport.call(&json).await
    }

    pub async fn post_data<T: Serialize + std::fmt::Debug>(
        &self,
        method: &str,
        params: T,
    ) -> Result<String> {
        let json = json!({
            "jsonrpc": "2.0",
            "id": "curlycurl",
            "method": method,
            "params": params,
        });
        self.transport.call(&json).await
    }
}

/// Helper function to check if a transaction has reached a final status
pub(crate) fn is_transaction_finalized(tx: &ProcessedTransaction) -> bool {
    matches!(&tx.status, Status::Processed | Status::Failed(_))
}
