//! Public API stability tests for the `arch_sdk` crate.
//!
//! These tests guarantee that every public type, constant, function, trait, and
//! method that downstream crates may depend on continues to exist and has a
//! compatible signature.  If any public API item is removed, renamed, or has
//! its signature changed in an incompatible way, these tests will fail at
//! **compile time**.
//!
//! Runtime assertions pin the *values* of public constants so that
//! accidentally changing them is also caught.

// ---------------------------------------------------------------------------
// 0. Crate-level re-exports
// ---------------------------------------------------------------------------

#[allow(unused_imports)]
use arch_sdk::arch_program;

// ---------------------------------------------------------------------------
// 1. types – structs, enums, type aliases, constants
// ---------------------------------------------------------------------------

#[allow(unused_imports)]
use arch_sdk::{
    // types/account_filter.rs
    AccountFilter,
    // types/account_info.rs
    AccountInfo,
    AccountInfoWithPubkey,
    // types/event.rs
    AccountUpdateEvent,
    // types/block.rs
    Block,
    BlockEvent,
    BlockParseError,
    // types/block_filter.rs
    BlockTransactionFilter,
    DKGEvent,
    Event,
    EventFilter,
    EventTopic,
    FullBlock,
    // types/inner_instruction.rs
    InnerInstruction,
    InnerInstructions,
    InnerInstructionsList,
    // types/processed_transaction.rs
    ParseProcessedTransactionError,
    ProcessedTransaction,
    // types/program_account.rs
    ProgramAccount,
    ReappliedTransactionsEvent,
    RollbackStatus,
    RolledbackTransactionsEvent,
    // types/runtime_transaction.rs
    RuntimeTransaction,
    RuntimeTransactionError,
    // types/signature.rs
    Signature,
    Status,
    // types/subscription.rs
    SubscriptionErrorResponse,
    SubscriptionRequest,
    SubscriptionResponse,
    SubscriptionStatus,
    TransactionEvent,
    // types/transaction_to_sign.rs
    TransactionToSign,
    UnsubscribeRequest,
    UnsubscribeResponse,
    WebSocketRequest,
    ALLOWED_VERSIONS,
    MAX_LOG_MESSAGES_COUNT,
    MAX_LOG_MESSAGES_LEN,
    MAX_STATUS_FAILED_MESSAGE_SIZE,
    MAX_TRANSACTIONS_PER_BLOCK,
    // types/mod.rs
    MAX_TX_BATCH_SIZE,
    ROLLBACK_MESSAGE_BUFFER_SIZE,
    RUNTIME_TX_SIZE_LIMIT,
};

// ---------------------------------------------------------------------------
// 2. client – RPC, config, error, websocket, transport
// ---------------------------------------------------------------------------

#[allow(unused_imports)]
use arch_sdk::{
    // client/error.rs
    ArchError,
    // client/async_rpc.rs
    ArchRpcClient,
    BIP322SigningErrorKind,
    // client/websocket.rs
    BackoffStrategy,
    // client/config.rs
    Config,
    WebSocketClient,
    WebSocketError,
    WebSocketMessage,
    ACCOUNT_FUNDING_AMOUNT,
    CHECK_PRE_ANCHOR_CONFLICT,
    GET_ACCOUNT_ADDRESS,
    GET_BEST_BLOCK_HASH,
    GET_BEST_FINALIZED_BLOCK_HASH,
    GET_BLOCK,
    GET_BLOCK_BY_HEIGHT,
    GET_BLOCK_COUNT,
    GET_BLOCK_HASH,
    GET_FULL_BLOCK_WITH_TXIDS,
    GET_MULTIPLE_ACCOUNTS,
    GET_PROCESSED_TRANSACTION,
    GET_PROGRAM_ACCOUNTS,
    READ_ACCOUNT_INFO,
    SEND_TRANSACTION,
    SEND_TRANSACTIONS,
};

// ---------------------------------------------------------------------------
// 3. helper – keys, BIP322, program deployment, transaction building
// ---------------------------------------------------------------------------

#[allow(unused_imports)]
use arch_sdk::{
    // helper/transaction_building.rs
    build_and_sign_transaction,
    // helper/keys.rs
    generate_new_keypair,
    get_state,
    is_parity_even,
    prepare_fees,
    // helper/bip322.rs
    sign_message_bip322,
    verify_message_bip322,
    with_secret_key_file,
    // helper/async_utxo.rs
    BitcoinHelper,
    // helper/async_program_deployment.rs
    ProgramDeployer,
    // helper/program_deployment.rs
    ProgramDeployerError,
};

// ---------------------------------------------------------------------------
// 4. blocking module
// ---------------------------------------------------------------------------

use arch_sdk::blocking;

// ==========================================================================
//  COMPILE-TIME CHECKS (existence + type compatibility)
// ==========================================================================

// ---------------------------------------------------------------------------
// AccountInfo / AccountInfoWithPubkey
// ---------------------------------------------------------------------------

#[test]
fn account_info_fields() {
    let ai = AccountInfo {
        lamports: 100,
        owner: arch_program::pubkey::Pubkey::system_program(),
        data: vec![0u8; 4],
        utxo: String::new(),
        is_executable: false,
    };
    let _: u64 = ai.lamports;
    let _: arch_program::pubkey::Pubkey = ai.owner;
    let _: Vec<u8> = ai.data;
    let _: String = ai.utxo;
    let _: bool = ai.is_executable;

    let aip = AccountInfoWithPubkey {
        key: arch_program::pubkey::Pubkey::system_program(),
        lamports: 0,
        owner: arch_program::pubkey::Pubkey::system_program(),
        data: vec![],
        utxo: String::new(),
        is_executable: false,
    };
    let _: arch_program::pubkey::Pubkey = aip.key;

    // Conversions
    let _: AccountInfoWithPubkey =
        AccountInfoWithPubkey::from((arch_program::pubkey::Pubkey::system_program(), ai.clone()));
    let _: AccountInfo = AccountInfo::from(aip);
}

// ---------------------------------------------------------------------------
// AccountFilter
// ---------------------------------------------------------------------------

#[test]
fn account_filter_variants_and_methods() {
    let _ = AccountFilter::DataSize(32);
    let _ = AccountFilter::DataContent {
        offset: 0,
        bytes: vec![0],
    };

    let ai = AccountInfo {
        lamports: 0,
        owner: arch_program::pubkey::Pubkey::system_program(),
        data: vec![0u8; 32],
        utxo: String::new(),
        is_executable: false,
    };
    let _: bool = AccountFilter::DataSize(32).matches(&ai);
}

// ---------------------------------------------------------------------------
// Block / FullBlock
// ---------------------------------------------------------------------------

#[test]
fn block_types_and_methods() {
    let b = Block {
        transactions: vec![],
        previous_block_hash: arch_program::hash::Hash::from([0u8; 32]),
        timestamp: 0u128,
        block_height: 0u64,
        bitcoin_block_height: 0u64,
    };
    let _: arch_program::hash::Hash = b.hash();
    let _: Vec<u8> = b.to_vec();
    let _: usize = Block::max_serialized_size();
    let _: Result<Block, BlockParseError> = Block::from_vec(&b.to_vec());

    // BlockParseError variants
    let _ = BlockParseError::InvalidBytes;
    let _ = BlockParseError::InvalidString;
    let _ = BlockParseError::InvalidU64;
    let _ = BlockParseError::InvalidU128;
    let _ = BlockParseError::InvalidTransactionsLength;
    let _ = BlockParseError::TryFromSliceError;

    assert_eq!(MAX_TRANSACTIONS_PER_BLOCK, 1024);
}

// ---------------------------------------------------------------------------
// BlockTransactionFilter
// ---------------------------------------------------------------------------

#[test]
fn block_transaction_filter_variants() {
    let _ = BlockTransactionFilter::Full;
    let _ = BlockTransactionFilter::Signatures;
    let _ = format!("{}", BlockTransactionFilter::Full);
    let _: Result<BlockTransactionFilter, _> = "full".parse();
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

#[test]
fn event_topic_variants() {
    let _ = EventTopic::Block;
    let _ = EventTopic::Transaction;
    let _ = EventTopic::AccountUpdate;
    let _ = EventTopic::RolledbackTransactions;
    let _ = EventTopic::ReappliedTransactions;
    let _ = EventTopic::DKG;
    let _ = format!("{}", EventTopic::Block);
}

#[test]
fn event_variants() {
    let be = BlockEvent {
        hash: String::new(),
        timestamp: 0,
    };
    let _: String = be.hash;
    let _: u128 = be.timestamp;

    let te = TransactionEvent {
        hash: String::new(),
        status: Status::Processed,
        program_ids: vec![],
        block_height: 0,
    };
    let _: String = te.hash;
    let _: Status = te.status;
    let _: Vec<String> = te.program_ids;
    let _: u64 = te.block_height;

    let aue = AccountUpdateEvent {
        account: String::new(),
        transaction_hash: String::new(),
        block_height: 0,
    };
    let _: String = aue.account;
    let _: String = aue.transaction_hash;
    let _: u64 = aue.block_height;

    let rte = RolledbackTransactionsEvent {
        block_height: 0,
        transaction_hashes: vec![],
    };
    let _: u64 = rte.block_height;
    let _: Vec<String> = rte.transaction_hashes;

    let rate = ReappliedTransactionsEvent {
        block_height: 0,
        transaction_hashes: vec![],
    };
    let _: u64 = rate.block_height;
    let _: Vec<String> = rate.transaction_hashes;

    let de = DKGEvent {
        status: String::new(),
    };
    let _: String = de.status;

    // Event enum variants
    let _ = Event::Block(be);
    let _ = Event::Transaction(te);
    let _ = Event::AccountUpdate(aue);
    let _ = Event::RolledbackTransactions(rte);
    let _ = Event::ReappliedTransactions(rate);
    let _ = Event::DKG(de);
}

#[test]
fn event_filter_api() {
    let ef = EventFilter::new();
    let _: EventFilter = EventFilter::default();
    let _: bool = ef.matches(&serde_json::Value::Null);
    let _: EventFilter = EventFilter::from_value(serde_json::Value::Null);
}

// ---------------------------------------------------------------------------
// InnerInstruction
// ---------------------------------------------------------------------------

#[test]
fn inner_instruction_types() {
    use arch_program::sanitized::SanitizedInstruction;

    let ii = InnerInstruction {
        instruction: SanitizedInstruction {
            program_id_index: 0,
            accounts: vec![],
            data: vec![],
        },
        stack_height: 1,
    };
    let _: SanitizedInstruction = ii.instruction;
    let _: u8 = ii.stack_height;

    // Type aliases
    let _: InnerInstructions = vec![ii];
    let _: InnerInstructionsList = vec![];
}

// ---------------------------------------------------------------------------
// ProcessedTransaction / Status / RollbackStatus
// ---------------------------------------------------------------------------

#[test]
fn processed_transaction_fields_and_methods() {
    let _ = Status::Queued;
    let _ = Status::Processed;
    let _ = Status::Failed(String::new());

    let _ = RollbackStatus::NotRolledback;
    let _ = RollbackStatus::Rolledback(String::new());

    assert_eq!(ROLLBACK_MESSAGE_BUFFER_SIZE, 1033);
    assert_eq!(MAX_LOG_MESSAGES_COUNT, 400);
    assert_eq!(MAX_LOG_MESSAGES_LEN, 10_020);
    assert_eq!(MAX_STATUS_FAILED_MESSAGE_SIZE, 1000);

    // ParseProcessedTransactionError variants
    let _ = ParseProcessedTransactionError::TryFromSliceError;
    let _ = ParseProcessedTransactionError::BufferTooShort;
    let _ = ParseProcessedTransactionError::RollbackMessageTooLong;
    let _ = ParseProcessedTransactionError::LogMessageTooLong;
    let _ = ParseProcessedTransactionError::TooManyLogMessages;
    let _ = ParseProcessedTransactionError::StatusFailedMessageTooLong;
    let _ = ParseProcessedTransactionError::TooManyInstructions;
    let _ = ParseProcessedTransactionError::TooManyInnerInstructions;
}

// ---------------------------------------------------------------------------
// ProgramAccount
// ---------------------------------------------------------------------------

#[test]
fn program_account_fields() {
    let pa = ProgramAccount {
        pubkey: arch_program::pubkey::Pubkey::system_program(),
        account: AccountInfo {
            lamports: 0,
            owner: arch_program::pubkey::Pubkey::system_program(),
            data: vec![],
            utxo: String::new(),
            is_executable: false,
        },
    };
    let _: arch_program::pubkey::Pubkey = pa.pubkey;
    let _: AccountInfo = pa.account;
}

// ---------------------------------------------------------------------------
// RuntimeTransaction
// ---------------------------------------------------------------------------

#[test]
fn runtime_transaction_fields_and_methods() {
    use arch_program::sanitized::{ArchMessage, MessageHeader};

    assert_eq!(RUNTIME_TX_SIZE_LIMIT, 10240);
    assert_eq!(ALLOWED_VERSIONS, [0]);

    let rt = RuntimeTransaction {
        version: 0,
        signatures: vec![],
        message: ArchMessage {
            header: MessageHeader {
                num_required_signatures: 0,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 0,
            },
            account_keys: vec![],
            recent_blockhash: arch_program::hash::Hash::from([0u8; 32]),
            instructions: vec![],
        },
    };
    let _: u32 = rt.version;
    let _: Vec<Signature> = rt.signatures;
    let _: ArchMessage = rt.message;

    // Methods
    let _: arch_program::hash::Hash = rt.txid();
    let _: Vec<u8> = rt.serialize();
    let _: arch_program::hash::Hash = rt.hash();
    let _ = rt.check_tx_size_limit();
    let _ = format!("{}", rt); // Display

    let serialized = rt.serialize();
    let _: Result<RuntimeTransaction, RuntimeTransactionError> =
        RuntimeTransaction::from_slice(&serialized);

    // RuntimeTransactionError variants
    let _ = RuntimeTransactionError::RuntimeTransactionSizeExceedsLimit(0, 0);
    let _ = RuntimeTransactionError::InsufficientBytesForMessage;
    let _ = RuntimeTransactionError::InvalidRecentBlockhash;
    let _ = RuntimeTransactionError::TooManySignatures(0, 0);
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

#[test]
fn signature_api() {
    let sig = Signature::from([0u8; 64]);
    let _: [u8; 64] = sig.to_array();
    let _: [u8; 64] = <[u8; 64]>::from(sig.clone());

    // Inner field accessible
    let _: [u8; 64] = sig.0;
}

// ---------------------------------------------------------------------------
// TransactionToSign (SDK version)
// ---------------------------------------------------------------------------

#[test]
fn sdk_transaction_to_sign_fields_and_methods() {
    let tts = TransactionToSign {
        tx_bytes: vec![0u8; 4],
        inputs_to_sign: vec![],
    };
    let _: Vec<u8> = tts.tx_bytes;
    let _: Vec<arch_program::input_to_sign::InputToSign> = tts.inputs_to_sign;

    let serialized = tts.serialise();
    let _: Result<TransactionToSign, std::io::Error> = TransactionToSign::from_slice(&serialized);
}

// ---------------------------------------------------------------------------
// Subscription types
// ---------------------------------------------------------------------------

#[test]
fn subscription_types() {
    let _ = SubscriptionStatus::Subscribed;
    let _ = SubscriptionStatus::Unsubscribed;
    let _ = SubscriptionStatus::Error;

    let _ = WebSocketRequest::Subscribe(SubscriptionRequest {
        topic: EventTopic::Block,
        filter: EventFilter::new(),
        request_id: None,
    });
    let _ = WebSocketRequest::Unsubscribe(UnsubscribeRequest {
        topic: EventTopic::Block,
        subscription_id: String::new(),
    });
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn config_fields_and_presets() {
    let c = Config::localnet();
    let _: String = c.node_endpoint;
    let _: String = c.node_username;
    let _: String = c.node_password;
    let _: bitcoin::Network = c.network;
    let _: String = c.arch_node_url;
    let _: String = c.titan_url;

    let _ = Config::devnet();
    let _ = Config::testnet();
    let _ = Config::mainnet();
}

// ---------------------------------------------------------------------------
// ArchError
// ---------------------------------------------------------------------------

#[test]
fn arch_error_variants() {
    let _ = ArchError::RpcRequestFailed(String::new());
    let _ = ArchError::ParseError(String::new());
    let _ = ArchError::TimeoutError(String::new());
    let _ = ArchError::TransactionError(String::new());
    let _ = ArchError::NetworkError(String::new());
    let _ = ArchError::NotFound(String::new());
    let _ = ArchError::UnknownError(String::new());
    let _ = ArchError::FromHexError(String::new());
    let _ = ArchError::RequiredSignerNotFound(arch_program::pubkey::Pubkey::system_program());
    let _ = ArchError::TcpClientError(String::new());
    let _ = ArchError::ProgramError(String::new());
    let _ = ArchError::XOnlyPublicKeyFromSliceError(String::new());
    let _ = ArchError::BIP322VerificationFailed(String::new());
    let _ = ArchError::BIP322SigningError(BIP322SigningErrorKind::UnsupportedAddress);
    let _ = ArchError::BitcoinRpcError(String::new());

    // Result type alias
    let _: arch_sdk::Result<()> = Ok(());
}

#[test]
fn bip322_signing_error_kind_variants() {
    let _ = BIP322SigningErrorKind::UnsupportedAddress;
    let _ = BIP322SigningErrorKind::NotKeySpendPath;
    let _ = BIP322SigningErrorKind::ToSpendCreationFailed;
    let _ = BIP322SigningErrorKind::ToSignCreationFailed;
    let _ = BIP322SigningErrorKind::TransactionExtractFailed;
    let _ = BIP322SigningErrorKind::SignatureExtractFailed;
    let _ = BIP322SigningErrorKind::SighashComputationFailed;
}

// ---------------------------------------------------------------------------
// WebSocket types
// ---------------------------------------------------------------------------

#[test]
fn websocket_error_variants() {
    let _ = WebSocketError::ConnectionFailed(String::new());
    let _ = WebSocketError::SendFailed(String::new());
    let _ = WebSocketError::ParseError(String::new());
    let _ = WebSocketError::SubscriptionFailed(String::new());
    let _ = WebSocketError::UnsubscriptionFailed(String::new());
    let _ = WebSocketError::ReadFailed(String::new());
    let _ = WebSocketError::Other(String::new());
}

#[test]
fn backoff_strategy_variants() {
    use std::time::Duration;

    let _ = BackoffStrategy::Constant(Duration::from_secs(1));
    let _ = BackoffStrategy::Linear {
        initial: Duration::from_secs(1),
        step: Duration::from_secs(1),
    };
    let _ = BackoffStrategy::Exponential {
        initial: Duration::from_secs(1),
        factor: 2.0,
        max_delay: Duration::from_secs(60),
        jitter: 0.1,
    };

    let bs = BackoffStrategy::default_exponential();
    let _: std::time::Duration = bs.next_delay(0);
}

// ---------------------------------------------------------------------------
// ArchRpcClient method signatures (compile-time check)
// ---------------------------------------------------------------------------

#[test]
fn async_rpc_client_construction() {
    // Constants
    assert_eq!(ACCOUNT_FUNDING_AMOUNT, 1_000_000);
    let _: &str = READ_ACCOUNT_INFO;
    let _: &str = GET_MULTIPLE_ACCOUNTS;
    let _: &str = SEND_TRANSACTION;
    let _: &str = SEND_TRANSACTIONS;
    let _: &str = GET_BLOCK;
    let _: &str = GET_FULL_BLOCK_WITH_TXIDS;
    let _: &str = GET_BLOCK_BY_HEIGHT;
    let _: &str = GET_BLOCK_COUNT;
    let _: &str = GET_BLOCK_HASH;
    let _: &str = GET_BEST_BLOCK_HASH;
    let _: &str = GET_BEST_FINALIZED_BLOCK_HASH;
    let _: &str = GET_PROCESSED_TRANSACTION;
    let _: &str = GET_ACCOUNT_ADDRESS;
    let _: &str = GET_PROGRAM_ACCOUNTS;
    let _: &str = CHECK_PRE_ANCHOR_CONFLICT;

    // Construction
    let config = Config::localnet();
    let client = ArchRpcClient::new(&config);
    let _: &Config = &client.config;
}

/// This test verifies that every public async method on ArchRpcClient exists
/// with the expected signature by taking function pointers. The methods
/// themselves are not called (they require a running node).
#[test]
fn async_rpc_client_method_signatures() {
    use arch_program::hash::Hash;
    use arch_program::pubkey::Pubkey;

    // We verify method existence by ensuring the struct has these methods.
    // For async methods, we check that calling them returns the correct
    // future output type by examining trait bounds. We do this at compile
    // time by referencing each method.
    let config = Config::localnet();
    let client = ArchRpcClient::new(&config);

    // The existence of these methods is proven by the fact that taking
    // a reference to them compiles:
    let _ = &ArchRpcClient::new;
    let _ = &ArchRpcClient::new_tcp;
    let _ = &ArchRpcClient::process_result;

    // Async methods - verified via a non-executed async block that
    // checks return types compile:
    let _verify_signatures = async {
        let pk = Pubkey::system_program();
        let h = Hash::from([0u8; 32]);

        let _: arch_sdk::Result<AccountInfo> = client.read_account_info(pk).await;
        let _: arch_sdk::Result<Vec<Option<AccountInfoWithPubkey>>> =
            client.get_multiple_accounts(vec![pk]).await;
        let _: arch_sdk::Result<ProcessedTransaction> = client.request_airdrop(pk).await;
        let _: arch_sdk::Result<()> = client
            .create_and_fund_account_with_faucet(&bitcoin::key::UntweakedKeypair::new(
                &bitcoin::secp256k1::Secp256k1::new(),
                &mut bitcoin::key::rand::thread_rng(),
            ))
            .await;
        let _: arch_sdk::Result<Option<ProcessedTransaction>> =
            client.get_processed_transaction(&h).await;
        let _: arch_sdk::Result<(Block, Vec<ProcessedTransaction>)> =
            client.get_full_block_with_txids(&h).await;
        let _: arch_sdk::Result<ProcessedTransaction> =
            client.wait_for_processed_transaction(&h).await;
        let _: arch_sdk::Result<Vec<ProcessedTransaction>> =
            client.wait_for_processed_transactions(vec![h]).await;
        let _: arch_sdk::Result<Hash> = client.get_best_block_hash().await;
        let _: arch_sdk::Result<Hash> = client.get_best_finalized_block_hash().await;
        let _: arch_sdk::Result<String> = client.get_block_hash(0).await;
        let _: arch_sdk::Result<u64> = client.get_block_count().await;
        let _: arch_sdk::Result<Option<Block>> = client.get_block_by_hash("").await;
        let _: arch_sdk::Result<Option<FullBlock>> = client.get_full_block_by_hash("").await;
        let _: arch_sdk::Result<Option<Block>> = client.get_block_by_height(0).await;
        let _: arch_sdk::Result<Option<FullBlock>> = client.get_full_block_by_height(0).await;
        let _: arch_sdk::Result<String> = client.get_account_address(&pk).await;
        let _: arch_sdk::Result<Vec<ProgramAccount>> = client.get_program_accounts(&pk, None).await;
        let _: arch_sdk::Result<bool> = client.check_pre_anchor_conflict(vec![pk]).await;
        let _: arch_sdk::Result<String> = client.get_network_pubkey().await;
        let rt = RuntimeTransaction {
            version: 0,
            signatures: vec![],
            message: Default::default(),
        };
        let _: arch_sdk::Result<Hash> = client.send_transaction(rt.clone()).await;
        let _: arch_sdk::Result<Vec<Hash>> = client.send_transactions(vec![rt]).await;
    };
}

// ---------------------------------------------------------------------------
// BlockingArchRpcClient via blocking module
// ---------------------------------------------------------------------------

#[test]
fn blocking_module_exports() {
    // These type aliases must exist
    let _: fn(&Config) -> blocking::ArchRpcClient = blocking::ArchRpcClient::new;

    // prepare_fees function
    let _: fn() -> Result<String, ArchError> = blocking::prepare_fees;
}

// ---------------------------------------------------------------------------
// ProgramDeployer
// ---------------------------------------------------------------------------

#[test]
fn program_deployer_construction() {
    let config = Config::localnet();
    let _ = ProgramDeployer::new(&config);
}

#[test]
fn program_deployer_error_variants() {
    use arch_program::hash::Hash;
    use arch_program::pubkey::Pubkey;

    let _ = ProgramDeployerError::ElfMismatch {
        program: Pubkey::system_program(),
    };
    let _ = ProgramDeployerError::NotExecutable {
        program: Pubkey::system_program(),
    };
    let _ = ProgramDeployerError::AccountCreationFailed {
        txid: Hash::from([0u8; 32]),
        reason: String::new(),
    };
    let _ = ProgramDeployerError::MakeExecutableFailed {
        txid: Hash::from([0u8; 32]),
        reason: String::new(),
    };
    let _ = ProgramDeployerError::ElfWriteFailed {
        txid: Hash::from([0u8; 32]),
        offset: 0,
        reason: String::new(),
    };

    // From conversions
    let _: ProgramDeployerError =
        ProgramDeployerError::from(ArchError::UnknownError(String::new()));
}

// ---------------------------------------------------------------------------
// get_state helper
// ---------------------------------------------------------------------------

#[test]
fn get_state_function_signature() {
    use arch_program::bpf_loader::LoaderState;
    use arch_program::instruction::InstructionError;

    let _: fn(&[u8]) -> Result<&LoaderState, InstructionError> = get_state;
}

// ---------------------------------------------------------------------------
// BitcoinHelper
// ---------------------------------------------------------------------------

#[test]
fn bitcoin_helper_construction() {
    // Just verify the constructor signature compiles
    let _: fn(&Config) -> Result<BitcoinHelper, ArchError> = BitcoinHelper::new;
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

#[test]
fn key_helper_signatures() {
    // generate_new_keypair
    let (kp, pk, addr) = generate_new_keypair(bitcoin::Network::Regtest);
    let _: bitcoin::key::UntweakedKeypair = kp;
    let _: arch_program::pubkey::Pubkey = pk;
    let _: bitcoin::Address = addr;

    // is_parity_even
    let _: bool = is_parity_even(&kp);
}

// ---------------------------------------------------------------------------
// BIP322 helpers
// ---------------------------------------------------------------------------

#[test]
fn bip322_function_signatures() {
    let _: fn(
        &bitcoin::key::UntweakedKeypair,
        &[u8],
        bitcoin::Network,
    ) -> Result<[u8; 64], ArchError> = sign_message_bip322;
    let _: fn(&[u8], [u8; 32], [u8; 64], bool, bitcoin::Network) -> Result<(), ArchError> =
        verify_message_bip322;
}

// ---------------------------------------------------------------------------
// Transaction building
// ---------------------------------------------------------------------------

#[test]
fn build_and_sign_transaction_signature() {
    use arch_program::sanitized::ArchMessage;

    let _: fn(
        ArchMessage,
        Vec<bitcoin::key::UntweakedKeypair>,
        bitcoin::Network,
    ) -> Result<RuntimeTransaction, ArchError> = build_and_sign_transaction;
}

// ---------------------------------------------------------------------------
// Constants value assertions
// ---------------------------------------------------------------------------

#[test]
fn constant_values() {
    assert_eq!(MAX_TX_BATCH_SIZE, 100);
    assert_eq!(RUNTIME_TX_SIZE_LIMIT, 10240);
    assert_eq!(ALLOWED_VERSIONS, [0]);
    assert_eq!(ACCOUNT_FUNDING_AMOUNT, 1_000_000);
    assert_eq!(MAX_TRANSACTIONS_PER_BLOCK, 1024);
    assert_eq!(ROLLBACK_MESSAGE_BUFFER_SIZE, 1033);
    assert_eq!(MAX_LOG_MESSAGES_COUNT, 400);
    assert_eq!(MAX_LOG_MESSAGES_LEN, 10_020);
    assert_eq!(MAX_STATUS_FAILED_MESSAGE_SIZE, 1000);
}

// ---------------------------------------------------------------------------
// WebSocketClient construction
// ---------------------------------------------------------------------------

#[test]
fn websocket_client_construction() {
    let _ = WebSocketClient::new("ws://localhost:9001");
}
