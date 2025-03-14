use crate::arch_program::pubkey::Pubkey;
use crate::client::error::{ArchError, Result};
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
const DEPLOY_PROGRAM: &str = "deploy_program";
const SEND_TRANSACTION: &str = "send_transaction";
const SEND_TRANSACTIONS: &str = "send_transactions";
const GET_PROGRAM: &str = "get_program";
const GET_BLOCK: &str = "get_block";
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

    /// Get block by hash
    pub fn get_block(&self, block_hash: &str) -> Result<Option<Block>> {
        self.call_method_with_params(GET_BLOCK, block_hash)
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
    use mockito::Server;

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

    #[test]
    fn test_is_transaction_finalized_function() {
        use crate::types::{RollbackStatus, Signature};
        use arch_program::message::Message;

        // Create a RuntimeTransaction for testing
        let rt_tx = RuntimeTransaction {
            version: 0,
            signatures: Vec::new(),
            message: Message {
                signers: Vec::new(),
                instructions: Vec::new(),
            },
        };

        // Test all status variants
        let processed_tx = ProcessedTransaction {
            runtime_transaction: rt_tx.clone(),
            status: Status::Processed,
            bitcoin_txid: None,
            logs: Vec::new(),
            rollback_status: RollbackStatus::NotRolledback,
        };
        assert!(is_transaction_finalized(&processed_tx));

        let failed_tx = ProcessedTransaction {
            runtime_transaction: rt_tx.clone(),
            status: Status::Failed("error".to_string()),
            bitcoin_txid: None,
            logs: Vec::new(),
            rollback_status: RollbackStatus::NotRolledback,
        };
        assert!(is_transaction_finalized(&failed_tx));

        let queued_tx = ProcessedTransaction {
            runtime_transaction: rt_tx.clone(),
            status: Status::Queued,
            bitcoin_txid: None,
            logs: Vec::new(),
            rollback_status: RollbackStatus::NotRolledback,
        };
        assert!(!is_transaction_finalized(&queued_tx));
    }

    #[test]
    fn test_send_transaction() {
        let mut server = Server::new();
        use arch_program::message::Message;

        // Create a minimal valid RuntimeTransaction for the test
        let tx = RuntimeTransaction {
            version: 0,
            signatures: Vec::new(),
            message: Message {
                signers: Vec::new(),
                instructions: Vec::new(),
            },
        };

        let mock = mock_rpc_response_with_params(
            &mut server,
            SEND_TRANSACTION,
            tx.clone(),
            json!("tx_id_12345"),
        );

        let client = get_test_client(&server);
        let result = client.send_transaction(tx).unwrap();

        assert_eq!(result, "tx_id_12345");
        mock.assert();
    }

    // Additional test for get_program_accounts
    #[test]
    fn test_get_program_accounts() {
        let mut server = Server::new();
        let program_id = Pubkey::new_unique();
        let filters = None;

        // Create some program accounts for the response
        let account_info = AccountInfo {
            owner: program_id,
            data: vec![1, 2, 3, 4],
            utxo: "utxo123".to_string(),
            is_executable: false,
        };

        let program_account = ProgramAccount {
            pubkey: Pubkey::new_unique(),
            account: account_info,
        };

        let mock = mock_rpc_response_with_params(
            &mut server,
            GET_PROGRAM_ACCOUNTS,
            json!([program_id.serialize(), filters]),
            json!([program_account]),
        );

        let client = get_test_client(&server);
        let result = client.get_program_accounts(&program_id, filters).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pubkey, program_account.pubkey);
        assert_eq!(result[0].account.data, program_account.account.data);
        mock.assert();
    }

    #[test]
    fn test_get_block_hash() {
        let mut server = Server::new();
        let block_height = 12345u64;
        let expected_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

        let mock = mock_rpc_response_with_params(
            &mut server,
            GET_BLOCK_HASH,
            block_height,
            json!(expected_hash),
        );

        let client = get_test_client(&server);
        let result = client.get_block_hash(block_height).unwrap();

        assert_eq!(result, expected_hash);
        mock.assert();
    }

    #[test]
    fn test_get_block() {
        let mut server = Server::new();
        let block_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

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
            GET_BLOCK,
            block_hash,
            serde_json::to_value(block.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result = client.get_block(block_hash).unwrap();

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
    fn test_get_processed_transaction() {
        let mut server = Server::new();
        let tx_id = "tx_test_12345";

        use crate::types::{RollbackStatus, Signature};
        use arch_program::message::Message;

        // Create a sample processed transaction
        let rt_tx = RuntimeTransaction {
            version: 0,
            signatures: Vec::new(),
            message: Message {
                signers: Vec::new(),
                instructions: Vec::new(),
            },
        };

        let processed_tx = ProcessedTransaction {
            runtime_transaction: rt_tx.clone(),
            status: Status::Processed,
            bitcoin_txid: None,
            logs: vec!["Log entry 1".to_string(), "Log entry 2".to_string()],
            rollback_status: RollbackStatus::NotRolledback,
        };

        let mock = mock_rpc_response_with_params(
            &mut server,
            GET_PROCESSED_TRANSACTION,
            tx_id,
            serde_json::to_value(processed_tx.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result = client.get_processed_transaction(tx_id).unwrap();

        assert!(result.is_some());
        let returned_tx = result.unwrap();
        assert_eq!(returned_tx.status, processed_tx.status);
        assert_eq!(returned_tx.logs, processed_tx.logs);
        mock.assert();
    }

    #[test]
    fn test_send_transactions() {
        let mut server = Server::new();
        use arch_program::message::Message;

        // Create multiple transactions
        let tx1 = RuntimeTransaction {
            version: 0,
            signatures: Vec::new(),
            message: Message {
                signers: Vec::new(),
                instructions: Vec::new(),
            },
        };

        let tx2 = RuntimeTransaction {
            version: 1,
            signatures: Vec::new(),
            message: Message {
                signers: Vec::new(),
                instructions: Vec::new(),
            },
        };

        let transactions = vec![tx1, tx2];
        let expected_tx_ids = vec!["tx_id_1".to_string(), "tx_id_2".to_string()];

        let mock = mock_rpc_response_with_params(
            &mut server,
            SEND_TRANSACTIONS,
            transactions.clone(),
            json!(expected_tx_ids),
        );

        let client = get_test_client(&server);
        let result = client.send_transactions(transactions).unwrap();

        assert_eq!(result, expected_tx_ids);
        mock.assert();
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
}
