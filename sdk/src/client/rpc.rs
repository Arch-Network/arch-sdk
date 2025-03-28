use crate::arch_program::pubkey::Pubkey;
use crate::client::error::{ArchError, Result};
use crate::{AccountInfoWithPubkey, BlockTransactionFilter, FullBlock};
use jsonrpsee::types::error::ErrorCode;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{from_str, json, Value};
use std::time::Duration;

// Import the appropriate result types
use crate::types::{
    AccountFilter, AccountInfo, Block, ProcessedTransaction, ProgramAccount, RuntimeTransaction,
    Status,
};

// RPC method constants
const ASSIGN_AUTHORITY: &str = "assign_authority";
const READ_ACCOUNT_INFO: &str = "read_account_info";
const GET_MULTIPLE_ACCOUNTS: &str = "get_multiple_accounts";
const DEPLOY_PROGRAM: &str = "deploy_program";
const SEND_TRANSACTION: &str = "send_transaction";
const SEND_TRANSACTIONS: &str = "send_transactions";
const GET_PROGRAM: &str = "get_program";
const GET_BLOCK: &str = "get_block";
const GET_BLOCK_BY_HEIGHT: &str = "get_block_by_height";
const GET_BLOCK_COUNT: &str = "get_block_count";
const GET_BLOCK_HASH: &str = "get_block_hash";
const GET_BEST_BLOCK_HASH: &str = "get_best_block_hash";
const GET_PROCESSED_TRANSACTION: &str = "get_processed_transaction";
const GET_ACCOUNT_ADDRESS: &str = "get_account_address";
const GET_PROGRAM_ACCOUNTS: &str = "get_program_accounts";
const START_DKG: &str = "start_dkg";

pub const NOT_FOUND_CODE: i64 = 404;

/// ArchRpcClient provides a simple interface for making RPC calls to the Arch blockchain
#[derive(Clone)]
pub struct ArchRpcClient {
    url: String,
}

impl ArchRpcClient {
    /// Create a new ArchRpcClient with the specified URL
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    /// Make a raw RPC call with no parameters and parse the result
    /// Returns None if the item was not found (404)
    pub fn call_method<R: DeserializeOwned>(&self, method: &str) -> Result<Option<R>> {
        match self.process_result(self.post(method)?)? {
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
    pub fn call_method_with_params<T: Serialize + std::fmt::Debug, R: DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<Option<R>> {
        match self.process_result(self.post_data(method, params)?)? {
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
    pub fn call_method_raw(&self, method: &str) -> Result<Option<Value>> {
        self.process_result(self.post(method)?)
    }

    /// Get raw value from a method call with parameters
    /// Returns None if the item was not found (404)
    pub fn call_method_with_params_raw<T: Serialize + std::fmt::Debug>(
        &self,
        method: &str,
        params: T,
    ) -> Result<Option<Value>> {
        self.process_result(self.post_data(method, params)?)
    }

    /// Read account information for the specified public key
    pub fn read_account_info(&self, pubkey: Pubkey) -> Result<AccountInfo> {
        match self.call_method_with_params(READ_ACCOUNT_INFO, pubkey)? {
            Some(info) => Ok(info),
            None => Err(ArchError::NotFound(format!(
                "Account not found for pubkey: {}",
                pubkey
            ))),
        }
    }

    /// Read account information for multiple public keys
    pub fn get_multiple_accounts(
        &self,
        pubkeys: Vec<Pubkey>,
    ) -> Result<Vec<Option<AccountInfoWithPubkey>>> {
        match self.call_method_with_params(GET_MULTIPLE_ACCOUNTS, pubkeys.clone())? {
            Some(info) => Ok(info),
            None => Err(ArchError::NotFound(format!(
                "Accounts not found for pubkeys: {:?}",
                pubkeys
            ))),
        }
    }

    /// Get a processed transaction by ID
    pub fn get_processed_transaction(&self, tx_id: &str) -> Result<Option<ProcessedTransaction>> {
        self.call_method_with_params(GET_PROCESSED_TRANSACTION, tx_id)
    }

    /// Waits for a transaction to be processed, polling until it reaches "Processed" or "Failed" status
    /// Will timeout after 60 seconds
    pub fn wait_for_processed_transaction(&self, tx_id: &str) -> Result<ProcessedTransaction> {
        let mut wait_time = 1;

        // First try to get the transaction, retry if null
        let mut tx = match self.get_processed_transaction(tx_id) {
            Ok(Some(tx)) => tx,
            Ok(None) => {
                // Transaction not found, start polling
                loop {
                    std::thread::sleep(Duration::from_secs(wait_time));
                    match self.get_processed_transaction(tx_id)? {
                        Some(tx) => break tx,
                        None => {
                            wait_time += 1;
                            if wait_time >= 60 {
                                return Err(ArchError::TimeoutError(
                                    "Failed to retrieve processed transaction after 60 seconds"
                                        .to_string(),
                                ));
                            }
                            continue;
                        }
                    }
                }
            }
            Err(e) => return Err(e),
        };

        // Now wait for the transaction to finish processing
        while !is_transaction_finalized(&tx) {
            std::thread::sleep(Duration::from_secs(wait_time));
            match self.get_processed_transaction(tx_id)? {
                Some(updated_tx) => {
                    tx = updated_tx;
                    if is_transaction_finalized(&tx) {
                        break;
                    }
                }
                None => {
                    return Err(ArchError::TransactionError(
                        "Transaction disappeared after being found".to_string(),
                    ));
                }
            }

            wait_time += 1;
            if wait_time >= 60 {
                return Err(ArchError::TimeoutError(
                    "Transaction did not reach final status after 60 seconds".to_string(),
                ));
            }
        }

        Ok(tx)
    }

    /// Waits for multiple transactions to be processed, showing progress with a progress bar
    /// Returns a vector of processed transactions in the same order as the input transaction IDs
    pub fn wait_for_processed_transactions(
        &self,
        tx_ids: Vec<String>,
    ) -> Result<Vec<ProcessedTransaction>> {
        let mut processed_transactions: Vec<ProcessedTransaction> =
            Vec::with_capacity(tx_ids.len());

        for tx_id in tx_ids {
            match self.wait_for_processed_transaction(&tx_id) {
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
    pub fn get_best_block_hash(&self) -> Result<String> {
        match self.call_method_raw(GET_BEST_BLOCK_HASH)? {
            Some(value) => value.as_str().map(|s| s.to_string()).ok_or_else(|| {
                ArchError::ParseError("Failed to get best block hash as string".to_string())
            }),
            None => Err(ArchError::NotFound("Best block hash not found".to_string())),
        }
    }

    /// Get the block hash for a given height
    pub fn get_block_hash(&self, block_height: u64) -> Result<String> {
        match self.call_method_with_params_raw(GET_BLOCK_HASH, block_height)? {
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
    pub fn get_block_count(&self) -> Result<u64> {
        match self.call_method(GET_BLOCK_COUNT)? {
            Some(count) => Ok(count),
            None => Err(ArchError::NotFound("Block count not found".to_string())),
        }
    }

    /// Get block by hash with signatures only
    pub fn get_block_by_hash(&self, block_hash: &str) -> Result<Option<Block>> {
        // For signatures only, we can just pass the block hash directly
        self.call_method_with_params(GET_BLOCK, block_hash)
    }

    /// Get full block by hash with complete transaction details
    pub fn get_full_block_by_hash(&self, block_hash: &str) -> Result<Option<FullBlock>> {
        // Create parameters array with block_hash and full filter
        let params = vec![
            serde_json::to_value(block_hash)?,
            serde_json::to_value(BlockTransactionFilter::Full)?,
        ];

        // Process the response - first get the raw value
        match self.process_result(self.post_data(GET_BLOCK, params)?)? {
            Some(value) => {
                // Deserialize into a FullBlock
                let result = serde_json::from_value(value).map_err(|e| {
                    ArchError::ParseError(format!("Failed to deserialize FullBlock: {}", e))
                })?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Get block by height with signatures only
    pub fn get_block_by_height(&self, block_height: u64) -> Result<Option<Block>> {
        // For signatures only, we can just pass the block hash directly
        self.call_method_with_params(GET_BLOCK_BY_HEIGHT, block_height)
    }

    /// Get full block by hash with complete transaction details
    pub fn get_full_block_by_height(&self, block_height: u64) -> Result<Option<FullBlock>> {
        // Create parameters array with block_hash and full filter
        let params = vec![
            serde_json::to_value(block_height)?,
            serde_json::to_value(BlockTransactionFilter::Full)?,
        ];

        // Process the response - first get the raw value
        match self.process_result(self.post_data(GET_BLOCK_BY_HEIGHT, params)?)? {
            Some(value) => {
                // Deserialize into a FullBlock
                let result = serde_json::from_value(value).map_err(|e| {
                    ArchError::ParseError(format!("Failed to deserialize FullBlock: {}", e))
                })?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Get account address for a public key
    pub fn get_account_address(&self, pubkey: &Pubkey) -> Result<String> {
        match self.process_result(self.post_data(GET_ACCOUNT_ADDRESS, pubkey.serialize())?)? {
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
    pub fn get_program_accounts(
        &self,
        program_id: &Pubkey,
        filters: Option<Vec<AccountFilter>>,
    ) -> Result<Vec<ProgramAccount>> {
        // Format params as [program_id, filters]
        let params = json!([program_id.serialize(), filters]);
        match self.call_method_with_params(GET_PROGRAM_ACCOUNTS, params)? {
            Some(accounts) => Ok(accounts),
            None => Err(ArchError::NotFound(format!(
                "Program accounts not found for program ID: {}",
                program_id
            ))),
        }
    }

    /// Start distributed key generation
    pub fn start_dkg(&self) -> Result<()> {
        self.call_method_raw(START_DKG)?;
        Ok(())
    }

    /// Send a single transaction
    pub fn send_transaction(&self, transaction: RuntimeTransaction) -> Result<String> {
        match self.process_result(self.post_data(SEND_TRANSACTION, transaction)?)? {
            Some(value) => value.as_str().map(|s| s.to_string()).ok_or_else(|| {
                ArchError::ParseError("Failed to get transaction ID as string".to_string())
            }),
            None => Err(ArchError::TransactionError(
                "Failed to send transaction".to_string(),
            )),
        }
    }

    /// Send multiple transactions
    pub fn send_transactions(&self, transactions: Vec<RuntimeTransaction>) -> Result<Vec<String>> {
        match self.call_method_with_params(SEND_TRANSACTIONS, transactions)? {
            Some(tx_ids) => Ok(tx_ids),
            None => Err(ArchError::TransactionError(
                "Failed to send transactions".to_string(),
            )),
        }
    }

    /// Helper methods for RPC communication
    fn process_result(&self, response: String) -> Result<Option<Value>> {
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
                    if code.as_i64() == Some(NOT_FOUND_CODE) {
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

    fn post(&self, method: &str) -> Result<String> {
        let client = reqwest::blocking::Client::new();
        match client
            .post(&self.url)
            .header("content-type", "application/json")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": "curlycurl",
                "method": method,
            }))
            .send()
        {
            Ok(res) => match res.text() {
                Ok(text) => Ok(text),
                Err(e) => {
                    return Err(ArchError::NetworkError(format!(
                        "Failed to read response text: {}",
                        e
                    ))
                    .into())
                }
            },
            Err(e) => return Err(ArchError::NetworkError(format!("Request failed: {}", e)).into()),
        }
    }

    fn post_data<T: Serialize + std::fmt::Debug>(&self, method: &str, params: T) -> Result<String> {
        let client = reqwest::blocking::Client::new();
        match client
            .post(&self.url)
            .header("content-type", "application/json")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": "curlycurl",
                "method": method,
                "params": params,
            }))
            .send()
        {
            Ok(res) => match res.text() {
                Ok(text) => Ok(text),
                Err(e) => {
                    return Err(ArchError::NetworkError(format!(
                        "Failed to get response text: {}",
                        e
                    ))
                    .into())
                }
            },
            Err(e) => return Err(ArchError::NetworkError(format!("Request failed: {}", e)).into()),
        }
    }
}

/// Helper function to check if a transaction has reached a final status
fn is_transaction_finalized(tx: &ProcessedTransaction) -> bool {
    match &tx.status {
        Status::Processed | Status::Failed(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch_program::pubkey::Pubkey;
    use crate::arch_program::{account::AccountMeta, instruction::Instruction, message::Message};
    use crate::types::Signature;
    use jsonrpsee::types::{error::ErrorCode, ErrorObject};
    use mockall::mock;
    use mockall::predicate;
    use mockito::Server;

    mock! {
        RpcServer {
            fn get_transaction_status(&self, txid: String) -> Result<Option<TransactionStatus>>;
            fn send_transactions(&self, txs: Vec<RuntimeTransaction>) -> Result<Vec<String>>;
        }
    }

    #[derive(Debug, Clone)]
    pub enum TransactionStatus {
        Queued,
        Processed,
        Failed,
    }

    pub struct RpcClient {
        url: String,
    }

    impl RpcClient {
        pub fn new(url: String) -> Self {
            Self { url }
        }

        pub async fn is_transaction_finalized(&self, txid: &str) -> Result<bool> {
            Ok(true) // Simplified for tests
        }

        pub async fn send_transactions(&self, txs: Vec<RuntimeTransaction>) -> Result<Vec<String>> {
            Ok(vec![]) // Simplified for tests
        }
    }

    // Helper to create a test client with the mockito server
    fn get_test_client(server: &Server) -> ArchRpcClient {
        ArchRpcClient::new(&server.url())
    }

    // Helper to create a mock RPC response
    fn mock_rpc_response(server: &mut Server, method: &str, result: Value) -> mockito::Mock {
        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "curlycurl",
                    "result": result
                })
                .to_string(),
            )
            .match_body(mockito::Matcher::Json(json!({
                "jsonrpc": "2.0",
                "id": "curlycurl",
                "method": method
            })))
            .create()
    }

    // Helper to create a mock RPC response with params
    fn mock_rpc_response_with_params<T: Serialize>(
        server: &mut Server,
        method: &str,
        params: T,
        result: Value,
    ) -> mockito::Mock {
        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "curlycurl",
                    "result": result
                })
                .to_string(),
            )
            .match_body(mockito::Matcher::Json(json!({
                "jsonrpc": "2.0",
                "id": "curlycurl",
                "method": method,
                "params": params
            })))
            .create()
    }

    // Helper to create a mock RPC error response
    fn mock_rpc_error(
        server: &mut Server,
        method: &str,
        error_code: i64,
        error_message: &str,
    ) -> mockito::Mock {
        server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": "curlycurl",
                    "error": {
                        "code": error_code,
                        "message": error_message
                    }
                })
                .to_string(),
            )
            .match_body(mockito::Matcher::Json(json!({
                "jsonrpc": "2.0",
                "id": "curlycurl",
                "method": method
            })))
            .create()
    }

    #[test]
    fn test_get_best_block_hash() {
        let mut server = Server::new();
        let mock = mock_rpc_response(&mut server, GET_BEST_BLOCK_HASH, json!("0123456789abcdef"));

        let client = get_test_client(&server);
        let result = client.get_best_block_hash().unwrap();

        assert_eq!(result, "0123456789abcdef");
        mock.assert();
    }

    #[test]
    fn test_get_block_count() {
        let mut server = Server::new();
        let mock = mock_rpc_response(&mut server, GET_BLOCK_COUNT, json!(123456));

        let client = get_test_client(&server);
        let result = client.get_block_count().unwrap();

        assert_eq!(result, 123456);
        mock.assert();
    }

    #[test]
    fn test_read_account_info() {
        let mut server = Server::new();
        let pubkey = Pubkey::new_unique();

        // Create account info according to the actual struct definition
        let account_info = AccountInfo {
            owner: Pubkey::new_unique(),
            data: vec![1, 2, 3, 4],
            utxo: "utxo123".to_string(),
            is_executable: false,
        };

        let mock = mock_rpc_response_with_params(
            &mut server,
            READ_ACCOUNT_INFO,
            pubkey,
            serde_json::to_value(account_info.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result = client.read_account_info(pubkey).unwrap();

        assert_eq!(result.owner, account_info.owner);
        assert_eq!(result.data, account_info.data);
        assert_eq!(result.utxo, account_info.utxo);
        assert_eq!(result.is_executable, account_info.is_executable);
        mock.assert();
    }

    #[test]
    fn test_not_found_error() {
        let mut server = Server::new();
        let mock = mock_rpc_error(
            &mut server,
            GET_BEST_BLOCK_HASH,
            NOT_FOUND_CODE,
            "Not found",
        );

        let client = get_test_client(&server);
        let result = client.call_method_raw(GET_BEST_BLOCK_HASH).unwrap();

        assert!(result.is_none());
        mock.assert();
    }

    #[tokio::test]
    async fn test_is_transaction_finalized_function() {
        let mut mock_server = MockRpcServer::new();
        let client = RpcClient::new("http://localhost:8899".to_string());

        // Create a valid signer
        let signer = Pubkey::new_unique();

        // Create a valid instruction with proper data
        let instruction = Instruction {
            program_id: Pubkey::system_program(),
            accounts: vec![AccountMeta {
                pubkey: signer,
                is_signer: true,
                is_writable: true,
            }],
            data: vec![1; 32], // 32 bytes of data
        };

        // Create a message with the signer and instruction
        let message = Message {
            signers: vec![signer],
            instructions: vec![instruction],
        };

        // Create a RuntimeTransaction
        let transaction = RuntimeTransaction {
            version: 1,
            block_hash: "block_hash".to_string(),
            message,
        };

        let transaction_id = transaction.txid();

        // Test error case
        mock_server
            .expect_get_transaction_status()
            .with(predicate::eq(transaction_id.clone()))
            .times(1)
            .returning(|_| Err(ArchError::RpcRequestFailed("Invalid request".to_string())));

        let result = client.is_transaction_finalized(&transaction_id).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ArchError::RpcRequestFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_send_transactions() {
        let mut mock_server = MockRpcServer::new();
        let client = RpcClient::new("http://localhost:8899".to_string());

        // Create two unique public keys for signers
        let signer1 = Pubkey::new_unique();
        let signer2 = Pubkey::new_unique();

        // Create valid signatures (64 bytes each)
        let signature1 = Signature(vec![1; 64]);
        let signature2 = Signature(vec![2; 64]);

        // Create two instructions, each with a signer and some data
        let instruction1 = Instruction {
            program_id: Pubkey::system_program(),
            accounts: vec![AccountMeta {
                pubkey: signer1,
                is_signer: true,
                is_writable: true,
            }],
            data: vec![1; 32], // 32 bytes of data
        };

        let instruction2 = Instruction {
            program_id: Pubkey::system_program(),
            accounts: vec![AccountMeta {
                pubkey: signer2,
                is_signer: true,
                is_writable: true,
            }],
            data: vec![2; 32], // 32 bytes of data
        };

        // Create two messages, each with a signer and instruction
        let message1 = Message {
            signers: vec![signer1],
            instructions: vec![instruction1],
        };

        let message2 = Message {
            signers: vec![signer2],
            instructions: vec![instruction2],
        };

        // Create two transactions
        let transaction1 = RuntimeTransaction {
            version: 1,
            block_hash: "block_hash1".to_string(),
            message: message1,
        };

        let transaction2 = RuntimeTransaction {
            version: 1,
            block_hash: "block_hash2".to_string(),
            message: message2,
        };

        let transactions = vec![transaction1, transaction2];
        let expected_transaction_ids = vec![transactions[0].txid(), transactions[1].txid()];
        let expected_ids = expected_transaction_ids.clone();

        // Test successful case
        mock_server
            .expect_send_transactions()
            .with(predicate::eq(transactions.clone()))
            .times(1)
            .returning(move |_| Ok(expected_ids.clone()));

        let result = client.send_transactions(transactions.clone()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_transaction_ids);

        // Test error case
        mock_server
            .expect_send_transactions()
            .with(predicate::eq(transactions.clone()))
            .times(1)
            .returning(|_| Err(ArchError::RpcRequestFailed("Invalid request".to_string())));

        let result = client.send_transactions(transactions).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ArchError::RpcRequestFailed(_)
        ));
    }

    #[test]
    fn test_start_dkg() {
        let mut server = Server::new();
        let mock = mock_rpc_response(&mut server, START_DKG, json!(null));

        let client = get_test_client(&server);
        let result = client.start_dkg();

        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_call_method_basic() {
        let mut server = Server::new();

        // Test a basic string return type
        let mock = mock_rpc_response(&mut server, "test_method", json!("test_result"));

        let client = get_test_client(&server);
        let result: Option<String> = client.call_method("test_method").unwrap();

        assert_eq!(result, Some("test_result".to_string()));
        mock.assert();
    }

    #[test]
    fn test_call_method_complex_type() {
        let mut server = Server::new();

        // Test a more complex return type (using AccountInfo as an example)
        let account_info = AccountInfo {
            owner: Pubkey::new_unique(),
            data: vec![1, 2, 3, 4],
            utxo: "utxo123".to_string(),
            is_executable: false,
        };

        let mock = mock_rpc_response(
            &mut server,
            "get_account_info",
            serde_json::to_value(account_info.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result: Option<AccountInfo> = client.call_method("get_account_info").unwrap();

        assert!(result.is_some());
        let returned_info = result.unwrap();
        assert_eq!(returned_info.owner, account_info.owner);
        assert_eq!(returned_info.data, account_info.data);
        mock.assert();
    }

    #[test]
    fn test_rpc_error_handling() {
        let mut server = Server::new();

        // Test handling of a non-404 error code
        let error_code = 500;
        let error_message = "Internal server error";

        let mock = mock_rpc_error(&mut server, "test_method", error_code, error_message);

        let client = get_test_client(&server);
        let result = client.call_method_raw("test_method");

        assert!(result.is_err());
        if let Err(ArchError::RpcRequestFailed(message)) = result {
            assert!(message.contains(&error_code.to_string()));
            assert!(message.contains(error_message));
        } else {
            panic!("Expected RpcRequestFailed error");
        }

        mock.assert();
    }

    #[test]
    fn test_get_multiple_accounts() {
        let mut server = Server::new();

        // Create test pubkeys
        let pubkey1 = Pubkey::new_unique();
        let pubkey2 = Pubkey::new_unique();
        let pubkeys = vec![pubkey1, pubkey2];

        // Create account info for responses
        let account_info1 = AccountInfo {
            owner: Pubkey::new_unique(),
            data: vec![1, 2, 3, 4],
            utxo: "utxo123".to_string(),
            is_executable: false,
        };

        let account_info2 = AccountInfo {
            owner: Pubkey::new_unique(),
            data: vec![5, 6, 7, 8],
            utxo: "utxo456".to_string(),
            is_executable: true,
        };

        // Updated to match actual struct definition
        let account_with_pubkey1 = AccountInfoWithPubkey {
            key: pubkey1,
            owner: account_info1.owner,
            data: account_info1.data.clone(),
            utxo: account_info1.utxo.clone(),
            is_executable: account_info1.is_executable,
        };

        // Updated to match actual struct definition
        let account_with_pubkey2 = AccountInfoWithPubkey {
            key: pubkey2,
            owner: account_info2.owner,
            data: account_info2.data.clone(),
            utxo: account_info2.utxo.clone(),
            is_executable: account_info2.is_executable,
        };

        let expected_accounts = vec![
            Some(account_with_pubkey1.clone()),
            Some(account_with_pubkey2.clone()),
        ];

        let mock = mock_rpc_response_with_params(
            &mut server,
            GET_MULTIPLE_ACCOUNTS,
            pubkeys.clone(),
            serde_json::to_value(expected_accounts.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result = client.get_multiple_accounts(pubkeys).unwrap();

        assert_eq!(result.len(), 2);
        // Updated assertions to use the correct field names
        assert_eq!(result[0].as_ref().unwrap().key, pubkey1);
        assert_eq!(result[0].as_ref().unwrap().data, account_info1.data);
        assert_eq!(result[1].as_ref().unwrap().key, pubkey2);
        assert_eq!(
            result[1].as_ref().unwrap().is_executable,
            account_info2.is_executable
        );

        mock.assert();
    }

    #[test]
    fn test_get_full_block() {
        let mut server = Server::new();
        let block_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

        // Create a sample full block for the response
        let full_block = FullBlock {
            transactions: vec![], // Simplified for test purposes
            previous_block_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            timestamp: 1630000000,
            bitcoin_block_height: 100,
            transaction_count: 0,
            merkle_root: "merkle_root_hash".to_string(),
        };

        // Mock response with the correct parameters (block_hash and BlockTransactionFilter::Full)
        let params = vec![
            serde_json::to_value(block_hash).unwrap(),
            serde_json::to_value(BlockTransactionFilter::Full).unwrap(),
        ];

        let mock = mock_rpc_response_with_params(
            &mut server,
            GET_BLOCK,
            params,
            serde_json::to_value(full_block.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result = client.get_full_block_by_hash(block_hash).unwrap();

        assert!(result.is_some());
        let returned_block = result.unwrap();
        assert_eq!(returned_block.timestamp, full_block.timestamp);
        assert_eq!(
            returned_block.previous_block_hash,
            full_block.previous_block_hash
        );
        assert_eq!(
            returned_block.bitcoin_block_height,
            full_block.bitcoin_block_height
        );
        assert_eq!(returned_block.merkle_root, full_block.merkle_root);

        mock.assert();
    }

    #[test]
    fn test_get_block_by_height() {
        let mut server = Server::new();
        let block_height = 12345u64;

        // Create a sample block for the response
        let block = Block {
            transactions: vec!["tx1".to_string(), "tx2".to_string()],
            previous_block_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            timestamp: 1630000000,
            bitcoin_block_height: 100,
            transaction_count: 2,
            merkle_root: "merkle_root_hash".to_string(),
        };

        let mock = mock_rpc_response_with_params(
            &mut server,
            GET_BLOCK_BY_HEIGHT,
            block_height,
            serde_json::to_value(block.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result = client.get_block_by_height(block_height).unwrap();

        assert!(result.is_some());
        let returned_block = result.unwrap();
        assert_eq!(returned_block.transactions, block.transactions);
        assert_eq!(returned_block.transaction_count, block.transaction_count);
        assert_eq!(
            returned_block.bitcoin_block_height,
            block.bitcoin_block_height
        );
        mock.assert();
    }

    #[test]
    fn test_get_full_block_by_height() {
        let mut server = Server::new();
        let block_height = 12345u64;

        // Create a sample full block for the response
        let full_block = FullBlock {
            transactions: vec![], // Simplified for test purposes
            previous_block_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            timestamp: 1630000000,
            bitcoin_block_height: 100,
            transaction_count: 0,
            merkle_root: "merkle_root_hash".to_string(),
        };

        // Mock response with the correct parameters (block_height and BlockTransactionFilter::Full)
        let params = vec![
            serde_json::to_value(block_height).unwrap(),
            serde_json::to_value(BlockTransactionFilter::Full).unwrap(),
        ];

        let mock = mock_rpc_response_with_params(
            &mut server,
            GET_BLOCK_BY_HEIGHT,
            params,
            serde_json::to_value(full_block.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result = client.get_full_block_by_height(block_height).unwrap();

        assert!(result.is_some());
        let returned_block = result.unwrap();
        assert_eq!(returned_block.timestamp, full_block.timestamp);
        assert_eq!(
            returned_block.previous_block_hash,
            full_block.previous_block_hash
        );
        assert_eq!(
            returned_block.bitcoin_block_height,
            full_block.bitcoin_block_height
        );
        assert_eq!(returned_block.merkle_root, full_block.merkle_root);

        mock.assert();
    }
}
