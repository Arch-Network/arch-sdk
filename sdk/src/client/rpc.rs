use crate::arch_program::pubkey::Pubkey;
use crate::client::error::Result;
use crate::runtime::block_on;
use crate::{AccountInfoWithPubkey, ArchRpcClient, Config, FullBlock};
use arch_program::hash::Hash;
use bitcoin::key::Keypair;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

#[cfg(test)]
use crate::client::async_rpc::{
    GET_BEST_BLOCK_HASH, GET_BLOCK, GET_BLOCK_BY_HEIGHT, GET_BLOCK_COUNT, GET_BLOCK_HASH,
    GET_MULTIPLE_ACCOUNTS, GET_PROCESSED_TRANSACTION, GET_PROGRAM_ACCOUNTS, READ_ACCOUNT_INFO,
    SEND_TRANSACTION, SEND_TRANSACTIONS,
};
use crate::types::{
    AccountFilter, AccountInfo, Block, ProcessedTransaction, ProgramAccount, RuntimeTransaction,
};

/// ArchRpcClient provides a simple interface for making RPC calls to the Arch blockchain.
///
/// When used from an async context (e.g. inside a tokio runtime), the client delegates to the
/// existing runtime. When used from a sync context, a shared fallback runtime is used.
#[derive(Clone)]
pub struct BlockingArchRpcClient {
    pub config: Config,
    client: ArchRpcClient,
}

impl BlockingArchRpcClient {
    /// Create a new ArchRpcClient with the specified URL
    pub fn new(config: &Config) -> Self {
        let client = ArchRpcClient::new(config);
        Self {
            config: config.clone(),
            client,
        }
    }

    /// Create a new ArchRpcClient with the specified TCP server address.
    pub fn new_tcp(config: &Config, addr: String) -> Result<Self> {
        let client = ArchRpcClient::new_tcp(config, addr)?;
        Ok(Self {
            config: config.clone(),
            client,
        })
    }

    /// Make a raw RPC call with no parameters and parse the result
    /// Returns None if the item was not found (404)
    pub fn call_method<R: DeserializeOwned + Send>(&self, method: &str) -> Result<Option<R>> {
        block_on(async { self.client.call_method(method).await })
    }

    /// Make a raw RPC call with parameters and parse the result
    /// Returns None if the item was not found (404)
    pub fn call_method_with_params<
        T: Serialize + std::fmt::Debug + Send,
        R: DeserializeOwned + Send,
    >(
        &self,
        method: &str,
        params: T,
    ) -> Result<Option<R>> {
        block_on(async { self.client.call_method_with_params(method, params).await })
    }

    /// Get raw value from a method call
    /// Returns None if the item was not found (404)
    pub fn call_method_raw(&self, method: &str) -> Result<Option<Value>> {
        block_on(async { self.client.call_method_raw(method).await })
    }

    /// Get raw value from a method call with parameters
    /// Returns None if the item was not found (404)
    pub fn call_method_with_params_raw<T: Serialize + std::fmt::Debug + Send>(
        &self,
        method: &str,
        params: T,
    ) -> Result<Option<Value>> {
        block_on(async {
            self.client
                .call_method_with_params_raw(method, params)
                .await
        })
    }

    /// Read account information for the specified public key
    pub fn read_account_info(&self, pubkey: Pubkey) -> Result<AccountInfo> {
        block_on(async { self.client.read_account_info(pubkey).await })
    }

    /// Read account information for multiple public keys
    pub fn get_multiple_accounts(
        &self,
        pubkeys: Vec<Pubkey>,
    ) -> Result<Vec<Option<AccountInfoWithPubkey>>> {
        block_on(async { self.client.get_multiple_accounts(pubkeys).await })
    }

    /// Request an airdrop for a given public key
    pub fn request_airdrop(&self, pubkey: Pubkey) -> Result<ProcessedTransaction> {
        block_on(async { self.client.request_airdrop(pubkey).await })
    }

    /// Create an account with lamports
    pub fn create_and_fund_account_with_faucet(&self, keypair: &Keypair) -> Result<()> {
        block_on(async {
            self.client
                .create_and_fund_account_with_faucet(keypair)
                .await
        })
    }

    /// Get a processed transaction by ID
    pub fn get_processed_transaction(&self, tx_id: &Hash) -> Result<Option<ProcessedTransaction>> {
        block_on(async { self.client.get_processed_transaction(tx_id).await })
    }

    /// Get a block with its transactions by ID
    pub fn get_full_block_with_txids(
        &self,
        block_id: &Hash,
    ) -> Result<(Block, Vec<ProcessedTransaction>)> {
        block_on(async { self.client.get_full_block_with_txids(block_id).await })
    }

    /// Waits for a transaction to be processed, polling until it reaches "Processed" or "Failed" status
    /// Will timeout after 60 seconds
    pub fn wait_for_processed_transaction(&self, tx_id: &Hash) -> Result<ProcessedTransaction> {
        block_on(async { self.client.wait_for_processed_transaction(tx_id).await })
    }

    /// Waits for multiple transactions to be processed, showing progress with a progress bar
    /// Returns a vector of processed transactions in the same order as the input transaction IDs
    pub fn wait_for_processed_transactions(
        &self,
        tx_ids: Vec<Hash>,
    ) -> Result<Vec<ProcessedTransaction>> {
        block_on(async { self.client.wait_for_processed_transactions(tx_ids).await })
    }

    /// Get the best block hash
    pub fn get_best_block_hash(&self) -> Result<Hash> {
        block_on(async { self.client.get_best_block_hash().await })
    }

    /// Get the best block hash
    pub fn get_best_finalized_block_hash(&self) -> Result<Hash> {
        block_on(async { self.client.get_best_finalized_block_hash().await })
    }

    /// Get the block hash for a given height
    pub fn get_block_hash(&self, block_height: u64) -> Result<String> {
        block_on(async { self.client.get_block_hash(block_height).await })
    }

    /// Get the current block count
    pub fn get_block_count(&self) -> Result<u64> {
        block_on(async { self.client.get_block_count().await })
    }

    /// Get block by hash with signatures only
    pub fn get_block_by_hash(&self, block_hash: &str) -> Result<Option<Block>> {
        block_on(async { self.client.get_block_by_hash(block_hash).await })
    }

    /// Get full block by hash with complete transaction details
    pub fn get_full_block_by_hash(&self, block_hash: &str) -> Result<Option<FullBlock>> {
        block_on(async { self.client.get_full_block_by_hash(block_hash).await })
    }

    /// Get block by height with signatures only
    pub fn get_block_by_height(&self, block_height: u64) -> Result<Option<Block>> {
        block_on(async { self.client.get_block_by_height(block_height).await })
    }

    /// Get full block by hash with complete transaction details
    pub fn get_full_block_by_height(&self, block_height: u64) -> Result<Option<FullBlock>> {
        block_on(async { self.client.get_full_block_by_height(block_height).await })
    }

    /// Get account address for a public key
    pub fn get_account_address(&self, pubkey: &Pubkey) -> Result<String> {
        block_on(async { self.client.get_account_address(pubkey).await })
    }

    /// Get program accounts for a given program ID
    pub fn get_program_accounts(
        &self,
        program_id: &Pubkey,
        filters: Option<Vec<AccountFilter>>,
    ) -> Result<Vec<ProgramAccount>> {
        block_on(async { self.client.get_program_accounts(program_id, filters).await })
    }

    pub fn check_pre_anchor_conflict(&self, accounts: Vec<Pubkey>) -> Result<bool> {
        block_on(async { self.client.check_pre_anchor_conflict(accounts).await })
    }

    /// Get the network pubkey from the network
    pub fn get_network_pubkey(&self) -> Result<String> {
        block_on(async { self.client.get_network_pubkey().await })
    }

    /// Send a single transaction
    pub fn send_transaction(&self, transaction: RuntimeTransaction) -> Result<Hash> {
        block_on(async { self.client.send_transaction(transaction).await })
    }

    /// Send multiple transactions
    pub fn send_transactions(&self, transactions: Vec<RuntimeTransaction>) -> Result<Vec<Hash>> {
        block_on(async { self.client.send_transactions(transactions).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch_program::pubkey::Pubkey;
    use crate::{is_transaction_finalized, ArchError, BlockTransactionFilter, Status};
    use arch_program::hash::Hash;
    use arch_program::rent::minimum_rent;
    use arch_program::sanitized::ArchMessage;
    use mockito::Server;
    use serde_json::json;
    use std::str::FromStr;

    // Helper to create a test client with the mockito server
    fn get_test_client(server: &Server) -> BlockingArchRpcClient {
        let mut config = Config::localnet();
        config.arch_node_url = server.url().to_string();
        BlockingArchRpcClient::new(&config)
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
                    "id": "1",
                    "result": result
                })
                .to_string(),
            )
            .match_body(mockito::Matcher::PartialJson(json!({
                "jsonrpc": "2.0",
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
                    "id": "1",
                    "result": result
                })
                .to_string(),
            )
            .match_body(mockito::Matcher::PartialJson(json!({
                "jsonrpc": "2.0",
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
                    "id": "1",
                    "error": {
                        "code": error_code,
                        "message": error_message
                    }
                })
                .to_string(),
            )
            .match_body(mockito::Matcher::PartialJson(json!({
                "jsonrpc": "2.0",
                "method": method
            })))
            .create()
    }

    #[test]
    fn test_get_best_block_hash() {
        let mut server = Server::new();

        let expected_hash = Hash::from([1; 32]);
        let mock = mock_rpc_response(
            &mut server,
            GET_BEST_BLOCK_HASH,
            json!(expected_hash.to_string()),
        );

        let client = get_test_client(&server);
        let result = client.get_best_block_hash().unwrap();

        assert_eq!(result, expected_hash);
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
            lamports: minimum_rent(4),
            owner: Pubkey::new_unique(),
            data: vec![1u8, 2, 3, 4],
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
        let mock = mock_rpc_error(&mut server, GET_BEST_BLOCK_HASH, 404, "Not found");

        let client = get_test_client(&server);
        let result = client.call_method_raw(GET_BEST_BLOCK_HASH).unwrap();

        assert!(result.is_none());
        mock.assert();
    }

    #[test]
    fn test_is_transaction_finalized_function() {
        use crate::types::RollbackStatus;

        // Create a RuntimeTransaction for testing
        let rt_tx = RuntimeTransaction {
            version: 0,
            signatures: Vec::new(),
            message: ArchMessage::new(&[], None, Hash::from([0; 32])),
        };

        // Test all status variants
        let processed_tx = ProcessedTransaction {
            runtime_transaction: rt_tx.clone(),
            status: Status::Processed,
            bitcoin_txid: None,
            logs: Vec::new(),
            rollback_status: RollbackStatus::NotRolledback,
            inner_instructions_list: vec![],
        };
        assert!(is_transaction_finalized(&processed_tx));

        let failed_tx = ProcessedTransaction {
            runtime_transaction: rt_tx.clone(),
            status: Status::Failed("error".to_string()),
            bitcoin_txid: None,
            logs: Vec::new(),
            rollback_status: RollbackStatus::NotRolledback,
            inner_instructions_list: vec![],
        };
        assert!(is_transaction_finalized(&failed_tx));

        let queued_tx = ProcessedTransaction {
            runtime_transaction: rt_tx.clone(),
            status: Status::Queued,
            bitcoin_txid: None,
            logs: Vec::new(),
            rollback_status: RollbackStatus::NotRolledback,
            inner_instructions_list: vec![],
        };
        assert!(!is_transaction_finalized(&queued_tx));
    }

    #[test]
    fn test_send_transaction() {
        let mut server = Server::new();

        // Create a minimal valid RuntimeTransaction for the test
        let tx = RuntimeTransaction {
            version: 0,
            signatures: Vec::new(),
            message: ArchMessage::new(&[], None, Hash::from([0; 32])),
        };

        let expected_tx_id = Hash::from([0; 32]);

        let mock = mock_rpc_response_with_params(
            &mut server,
            SEND_TRANSACTION,
            tx.clone(),
            json!(expected_tx_id.to_string()),
        );

        let client = get_test_client(&server);
        let result = client.send_transaction(tx).unwrap();

        assert_eq!(result, expected_tx_id);
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
            lamports: minimum_rent(4),
            owner: program_id,
            data: vec![1u8, 2, 3, 4],
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
            transactions: vec![
                Hash::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap(),
                Hash::from_str("0000000000000000000000000000000000000000000000000000000000000002")
                    .unwrap(),
            ],
            previous_block_hash: Hash::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            timestamp: 1630000000,
            block_height: 100,
            bitcoin_block_height: 100,
        };

        let mock = mock_rpc_response_with_params(
            &mut server,
            GET_BLOCK,
            block_hash,
            serde_json::to_value(block.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result = client.get_block_by_hash(block_hash).unwrap();

        assert!(result.is_some());
        let returned_block = result.unwrap();
        assert_eq!(returned_block.transactions, block.transactions);
        assert_eq!(
            returned_block.bitcoin_block_height,
            block.bitcoin_block_height
        );
        mock.assert();
    }

    #[test]
    fn test_get_processed_transaction() {
        let mut server = Server::new();
        let tx_id = Hash::from([0; 32]);

        use crate::types::RollbackStatus;

        // Create a sample processed transaction
        let rt_tx = RuntimeTransaction {
            version: 0,
            signatures: Vec::new(),
            message: ArchMessage::new(&[], None, Hash::from([0; 32])),
        };

        let processed_tx = ProcessedTransaction {
            runtime_transaction: rt_tx.clone(),
            status: Status::Processed,
            bitcoin_txid: None,
            logs: vec!["Log entry 1".to_string(), "Log entry 2".to_string()],
            rollback_status: RollbackStatus::NotRolledback,
            inner_instructions_list: vec![],
        };

        let mock = mock_rpc_response_with_params(
            &mut server,
            GET_PROCESSED_TRANSACTION,
            tx_id.to_string(),
            serde_json::to_value(processed_tx.clone()).unwrap(),
        );

        let client = get_test_client(&server);
        let result = client.get_processed_transaction(&tx_id).unwrap();

        assert!(result.is_some());
        let returned_tx = result.unwrap();
        assert_eq!(returned_tx.status, processed_tx.status);
        assert_eq!(returned_tx.logs, processed_tx.logs);
        mock.assert();
    }

    #[test]
    fn test_send_transactions() {
        let mut server = Server::new();

        // Create multiple transactions
        let tx1 = RuntimeTransaction {
            version: 0,
            signatures: Vec::new(),
            message: ArchMessage::new(&[], None, Hash::from([0; 32])),
        };

        let tx2 = RuntimeTransaction {
            version: 1,
            signatures: Vec::new(),
            message: ArchMessage::new(&[], None, Hash::from([0; 32])),
        };

        let transactions = vec![tx1, tx2];
        let expected_tx_ids = vec![
            Hash::from([
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ]),
            Hash::from([
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2,
            ]),
        ];

        let mock = mock_rpc_response_with_params(
            &mut server,
            SEND_TRANSACTIONS,
            transactions.clone(),
            json!(expected_tx_ids
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<String>>()),
        );

        let client = get_test_client(&server);
        let result = client.send_transactions(transactions).unwrap();

        assert_eq!(result, expected_tx_ids);
        mock.assert();
    }

    #[test]
    fn test_get_network_pubkey() {
        let mut server = Server::new();
        let expected_key = "0000000000000000000000000000000000000000000000000000000000000000";
        let mock = mock_rpc_response(&mut server, "get_network_pubkey", json!(expected_key));

        let client = get_test_client(&server);
        let result = client.get_network_pubkey().unwrap();

        assert_eq!(result, expected_key);
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

    #[tokio::test(flavor = "current_thread")]
    async fn test_call_method_basic_inside_current_thread_runtime() {
        let mut server = Server::new_async().await;

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
            lamports: minimum_rent(4),
            owner: Pubkey::new_unique(),
            data: vec![1u8, 2, 3, 4],
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
            lamports: minimum_rent(4),
            owner: Pubkey::new_unique(),
            data: vec![1u8, 2, 3, 4],
            utxo: "utxo123".to_string(),
            is_executable: false,
        };

        let account_info2 = AccountInfo {
            lamports: minimum_rent(4),
            owner: Pubkey::new_unique(),
            data: vec![5, 6, 7, 8],
            utxo: "utxo456".to_string(),
            is_executable: true,
        };

        // Updated to match actual struct definition
        let account_with_pubkey1 = AccountInfoWithPubkey {
            key: pubkey1,
            lamports: minimum_rent(account_info1.data.len()),
            owner: account_info1.owner,
            data: account_info1.data.clone(),
            utxo: account_info1.utxo.clone(),
            is_executable: account_info1.is_executable,
        };

        // Updated to match actual struct definition
        let account_with_pubkey2 = AccountInfoWithPubkey {
            key: pubkey2,
            lamports: minimum_rent(account_info2.data.len()),
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
            previous_block_hash: Hash::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            timestamp: 1630000000,
            block_height: 100,
            bitcoin_block_height: 100,
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

        mock.assert();
    }

    #[test]
    fn test_get_block_by_height() {
        let mut server = Server::new();
        let block_height = 12345u64;

        // Create a sample block for the response
        let block = Block {
            transactions: vec![
                Hash::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                    .unwrap(),
                Hash::from_str("0000000000000000000000000000000000000000000000000000000000000002")
                    .unwrap(),
            ],
            previous_block_hash: Hash::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            timestamp: 1630000000,
            block_height: 100,
            bitcoin_block_height: 100,
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
            previous_block_hash: Hash::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            timestamp: 1630000000,
            block_height,
            bitcoin_block_height: 100,
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

        mock.assert();
    }
}
