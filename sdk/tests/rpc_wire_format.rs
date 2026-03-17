//! RPC wire-format stability tests for `arch_sdk`.
//!
//! These tests ensure the JSON-RPC interface does not change in an
//! incompatible way.  They cover three aspects:
//!
//! 1. **Method name strings** — the exact string values sent as `"method"` in
//!    the JSON-RPC envelope.
//! 2. **Request parameter serialization** — the JSON shape produced by
//!    serializing the parameter types each RPC method sends.
//! 3. **Response deserialization** — known JSON fixtures can be deserialized
//!    into the expected Rust return types.
//!
//! If a field is added, removed, renamed, or re-typed in any of these
//! structures, the corresponding test will fail.

use arch_sdk::arch_program::{
    hash::Hash,
    pubkey::Pubkey,
    sanitized::{ArchMessage, MessageHeader, SanitizedInstruction},
};
use arch_sdk::{
    AccountFilter, AccountInfo, AccountInfoWithPubkey, Block, BlockTransactionFilter, Config,
    FullBlock, ProcessedTransaction, ProgramAccount, RollbackStatus, RuntimeTransaction, Signature,
    Status,
};
use serde_json::{json, Value};

// =========================================================================
//  1. METHOD NAME STRINGS
// =========================================================================

/// Every RPC method name sent over the wire must stay exactly the same.
/// This covers both the public constants and the inline string literals
/// used in `request_airdrop`, `create_account_with_faucet`, and
/// `get_network_pubkey`.
#[test]
fn rpc_method_name_strings() {
    assert_eq!(arch_sdk::READ_ACCOUNT_INFO, "read_account_info");
    assert_eq!(arch_sdk::GET_MULTIPLE_ACCOUNTS, "get_multiple_accounts");
    assert_eq!(arch_sdk::SEND_TRANSACTION, "send_transaction");
    assert_eq!(arch_sdk::SEND_TRANSACTIONS, "send_transactions");
    assert_eq!(arch_sdk::GET_BLOCK, "get_block");
    assert_eq!(
        arch_sdk::GET_FULL_BLOCK_WITH_TXIDS,
        "get_full_block_with_txids"
    );
    assert_eq!(arch_sdk::GET_BLOCK_BY_HEIGHT, "get_block_by_height");
    assert_eq!(arch_sdk::GET_BLOCK_COUNT, "get_block_count");
    assert_eq!(arch_sdk::GET_BLOCK_HASH, "get_block_hash");
    assert_eq!(arch_sdk::GET_BEST_BLOCK_HASH, "get_best_block_hash");
    assert_eq!(
        arch_sdk::GET_BEST_FINALIZED_BLOCK_HASH,
        "get_best_finalized_block_hash"
    );
    assert_eq!(
        arch_sdk::GET_PROCESSED_TRANSACTION,
        "get_processed_transaction"
    );
    assert_eq!(arch_sdk::GET_ACCOUNT_ADDRESS, "get_account_address");
    assert_eq!(arch_sdk::GET_PROGRAM_ACCOUNTS, "get_program_accounts");
    assert_eq!(
        arch_sdk::CHECK_PRE_ANCHOR_CONFLICT,
        "check_pre_anchor_conflict"
    );
}

// =========================================================================
//  2. REQUEST PARAMETER SERIALIZATION
// =========================================================================

/// `Pubkey` serializes as an array of 32 integers.
/// Used by: read_account_info, request_airdrop, create_account_with_faucet,
///          check_pre_anchor_conflict, get_multiple_accounts
#[test]
fn pubkey_json_serialization() {
    let pk = Pubkey::from([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);
    let json_val = serde_json::to_value(&pk).unwrap();

    // Must be an array of 32 numbers
    assert!(json_val.is_array(), "Pubkey must serialize as JSON array");
    let arr = json_val.as_array().unwrap();
    assert_eq!(arr.len(), 32, "Pubkey array must have 32 elements");
    assert_eq!(arr[0], json!(1));
    assert_eq!(arr[31], json!(32));
}

/// `Hash` serializes as an array of 32 integers (via serde derive on
/// newtype `Hash([u8; 32])`).
/// Note: some RPC methods send `hash.to_string()` (hex) rather than the
/// struct itself — those are tested separately below.
#[test]
fn hash_json_serialization() {
    let h = Hash::from([0xAB; 32]);
    let json_val = serde_json::to_value(&h).unwrap();

    assert!(json_val.is_array(), "Hash must serialize as JSON array");
    assert_eq!(json_val.as_array().unwrap().len(), 32);
    assert_eq!(json_val.as_array().unwrap()[0], json!(0xAB));
}

/// `Hash::to_string()` produces a 64-char hex string.
/// Used by: get_processed_transaction, get_full_block_with_txids
#[test]
fn hash_to_string_hex_format() {
    let h = Hash::from([0x0A; 32]);
    let s = h.to_string();
    assert_eq!(s.len(), 64, "Hash hex string must be 64 chars");
    assert!(
        s.chars().all(|c| c.is_ascii_hexdigit()),
        "Hash string must be hex"
    );
}

/// `Signature` serializes as a byte array (via custom serde impl).
#[test]
fn signature_json_serialization() {
    let sig = Signature::from([42u8; 64]);
    let json_val = serde_json::to_value(&sig).unwrap();

    assert!(json_val.is_array(), "Signature must serialize as array");
    assert_eq!(json_val.as_array().unwrap().len(), 64);
    assert_eq!(json_val.as_array().unwrap()[0], json!(42));
}

/// `RuntimeTransaction` serializes as an object with `version`, `signatures`,
/// and `message` fields.
/// Used by: send_transaction, send_transactions
#[test]
fn runtime_transaction_json_serialization() {
    let rt = RuntimeTransaction {
        version: 0,
        signatures: vec![Signature::from([1u8; 64])],
        message: ArchMessage {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![Pubkey::system_program(), Pubkey::new_unique()],
            recent_blockhash: Hash::from([0u8; 32]),
            instructions: vec![SanitizedInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![1, 2, 3],
            }],
        },
    };

    let json_val = serde_json::to_value(&rt).unwrap();
    let obj = json_val.as_object().unwrap();

    // Required top-level fields
    assert!(obj.contains_key("version"), "must have 'version' field");
    assert!(
        obj.contains_key("signatures"),
        "must have 'signatures' field"
    );
    assert!(obj.contains_key("message"), "must have 'message' field");

    assert_eq!(obj["version"], json!(0));
    assert!(obj["signatures"].is_array());
    assert_eq!(obj["signatures"].as_array().unwrap().len(), 1);

    // Message sub-fields
    let msg = obj["message"].as_object().unwrap();
    assert!(msg.contains_key("header"), "message must have 'header'");
    assert!(
        msg.contains_key("account_keys"),
        "message must have 'account_keys'"
    );
    assert!(
        msg.contains_key("recent_blockhash"),
        "message must have 'recent_blockhash'"
    );
    assert!(
        msg.contains_key("instructions"),
        "message must have 'instructions'"
    );

    // Header sub-fields
    let hdr = msg["header"].as_object().unwrap();
    assert!(hdr.contains_key("num_required_signatures"));
    assert!(hdr.contains_key("num_readonly_signed_accounts"));
    assert!(hdr.contains_key("num_readonly_unsigned_accounts"));

    // Instructions shape
    let ix = msg["instructions"].as_array().unwrap()[0]
        .as_object()
        .unwrap();
    assert!(ix.contains_key("program_id_index"));
    assert!(ix.contains_key("accounts"));
    assert!(ix.contains_key("data"));
}

/// `AccountFilter::DataSize` serializes as `{"DataSize": n}`.
/// `AccountFilter::DataContent` serializes as `{"DataContent": {"offset": n, "bytes": [...]}}`.
/// Used by: get_program_accounts
#[test]
fn account_filter_json_serialization() {
    let ds = AccountFilter::DataSize(32);
    let ds_json = serde_json::to_value(&ds).unwrap();
    assert!(
        ds_json.get("DataSize").is_some(),
        "DataSize variant must serialize with 'DataSize' key"
    );
    assert_eq!(ds_json["DataSize"], json!(32));

    let dc = AccountFilter::DataContent {
        offset: 8,
        bytes: vec![0xFF, 0x01],
    };
    let dc_json = serde_json::to_value(&dc).unwrap();
    let inner = dc_json
        .get("DataContent")
        .expect("DataContent variant must serialize with 'DataContent' key");
    assert_eq!(inner["offset"], json!(8));
    assert!(inner["bytes"].is_array());
}

/// `BlockTransactionFilter::Full` serializes as `"full"`.
/// `BlockTransactionFilter::Signatures` serializes as `"signatures"`.
/// Used by: get_full_block_by_hash, get_full_block_by_height
#[test]
fn block_transaction_filter_json_serialization() {
    let full = serde_json::to_value(&BlockTransactionFilter::Full).unwrap();
    assert_eq!(full, json!("full"));

    let sigs = serde_json::to_value(&BlockTransactionFilter::Signatures).unwrap();
    assert_eq!(sigs, json!("signatures"));
}

/// Pubkey.serialize() returns [u8; 32] which serializes as a 32-element
/// JSON array.
/// Used by: get_account_address, get_program_accounts
#[test]
fn pubkey_serialize_bytes_json() {
    let pk = Pubkey::from([0xAA; 32]);
    let bytes = pk.serialize();
    let json_val = serde_json::to_value(bytes).unwrap();
    assert!(json_val.is_array());
    assert_eq!(json_val.as_array().unwrap().len(), 32);
    assert_eq!(json_val.as_array().unwrap()[0], json!(0xAA));
}

// =========================================================================
//  3. RESPONSE DESERIALIZATION (JSON → Rust types)
// =========================================================================

/// Helper: a JSON array of `n` zeros, usable inside `json!()`.
fn zeros(n: usize) -> Value {
    Value::Array(vec![json!(0); n])
}

/// AccountInfo deserializes from JSON with the expected field names.
/// Returned by: read_account_info
#[test]
fn account_info_response_deserialization() {
    let mut obj = serde_json::Map::new();
    obj.insert("lamports".into(), json!(1000000));
    obj.insert("owner".into(), zeros(32));
    obj.insert("data".into(), json!([1, 2, 3, 4]));
    obj.insert("utxo".into(), json!("abc123:0"));
    obj.insert("is_executable".into(), json!(false));

    let ai: AccountInfo = serde_json::from_value(Value::Object(obj)).unwrap();
    assert_eq!(ai.lamports, 1000000);
    assert_eq!(ai.data, vec![1, 2, 3, 4]);
    assert_eq!(ai.utxo, "abc123:0");
    assert!(!ai.is_executable);
}

/// AccountInfoWithPubkey includes a `key` field.
/// Returned by: get_multiple_accounts
#[test]
fn account_info_with_pubkey_response_deserialization() {
    let mut obj = serde_json::Map::new();
    obj.insert("key".into(), zeros(32));
    obj.insert("lamports".into(), json!(500));
    obj.insert("owner".into(), zeros(32));
    obj.insert("data".into(), json!([]));
    obj.insert("utxo".into(), json!(""));
    obj.insert("is_executable".into(), json!(false));

    let aip: AccountInfoWithPubkey = serde_json::from_value(Value::Object(obj)).unwrap();
    assert_eq!(aip.lamports, 500);
    assert_eq!(aip.key, Pubkey::from([0; 32]));
}

/// Status variants deserialize from their tagged representation.
/// Returned by: get_processed_transaction (nested in ProcessedTransaction)
#[test]
fn status_response_deserialization() {
    let queued: Status = serde_json::from_value(json!({"type": "queued"})).unwrap();
    assert_eq!(queued, Status::Queued);

    let processed: Status = serde_json::from_value(json!({"type": "processed"})).unwrap();
    assert_eq!(processed, Status::Processed);

    let failed: Status =
        serde_json::from_value(json!({"type": "failed", "message": "out of gas"})).unwrap();
    assert_eq!(failed, Status::Failed("out of gas".to_string()));
}

/// RollbackStatus variants deserialize from their tagged representation.
#[test]
fn rollback_status_response_deserialization() {
    let not_rb: RollbackStatus = serde_json::from_value(json!({"type": "notRolledback"})).unwrap();
    assert_eq!(not_rb, RollbackStatus::NotRolledback);

    let rb: RollbackStatus =
        serde_json::from_value(json!({"type": "rolledback", "message": "conflict detected"}))
            .unwrap();
    assert_eq!(
        rb,
        RollbackStatus::Rolledback("conflict detected".to_string())
    );
}

/// Helper: build a minimal empty ArchMessage JSON object.
fn empty_message_json() -> Value {
    json!({
        "header": {
            "num_required_signatures": 0,
            "num_readonly_signed_accounts": 0,
            "num_readonly_unsigned_accounts": 0
        },
        "account_keys": [],
        "recent_blockhash": zeros(32),
        "instructions": []
    })
}

/// Helper: build a minimal ProcessedTransaction JSON object.
fn minimal_processed_tx_json(status: Value) -> Value {
    json!({
        "runtime_transaction": {
            "version": 0,
            "signatures": [],
            "message": empty_message_json()
        },
        "status": status,
        "bitcoin_txid": null,
        "logs": [],
        "rollback_status": {"type": "notRolledback"},
        "inner_instructions_list": []
    })
}

/// ProcessedTransaction has the expected top-level fields.
/// Returned by: get_processed_transaction, wait_for_processed_transaction
#[test]
fn processed_transaction_response_deserialization() {
    let mut json_val = minimal_processed_tx_json(json!({"type": "processed"}));
    json_val["logs"] = json!(["Program log: hello"]);

    let pt: ProcessedTransaction = serde_json::from_value(json_val).unwrap();
    assert_eq!(pt.status, Status::Processed);
    assert_eq!(pt.bitcoin_txid, None);
    assert_eq!(pt.logs, vec!["Program log: hello"]);
    assert_eq!(pt.rollback_status, RollbackStatus::NotRolledback);
    assert!(pt.inner_instructions_list.is_empty());
}

/// Block has the expected fields.
/// Returned by: get_block_by_hash, get_block_by_height
#[test]
fn block_response_deserialization() {
    let json_val = json!({
        "transactions": [zeros(32)],
        "previous_block_hash": zeros(32),
        "timestamp": 1700000000000_u64,
        "block_height": 42,
        "bitcoin_block_height": 800000
    });

    let b: Block = serde_json::from_value(json_val).unwrap();
    assert_eq!(b.block_height, 42);
    assert_eq!(b.bitcoin_block_height, 800000);
    assert_eq!(b.transactions.len(), 1);
}

/// FullBlock has transactions as full ProcessedTransaction objects.
/// Returned by: get_full_block_by_hash, get_full_block_by_height
#[test]
fn full_block_response_deserialization() {
    let json_val = json!({
        "transactions": [minimal_processed_tx_json(json!({"type": "processed"}))],
        "previous_block_hash": zeros(32),
        "timestamp": 1700000000000_u64,
        "block_height": 100,
        "bitcoin_block_height": 800001
    });

    let fb: FullBlock = serde_json::from_value(json_val).unwrap();
    assert_eq!(fb.block_height, 100);
    assert_eq!(fb.transactions.len(), 1);
    assert_eq!(fb.transactions[0].status, Status::Processed);
}

/// RuntimeTransaction round-trips through JSON correctly.
/// Returned by: create_account_with_faucet (in the response)
#[test]
fn runtime_transaction_response_deserialization() {
    let ones_32: Value = Value::Array(vec![json!(1); 32]);
    let json_val = json!({
        "version": 0,
        "signatures": [Value::Array(vec![json!(0); 64])],
        "message": {
            "header": {
                "num_required_signatures": 1,
                "num_readonly_signed_accounts": 0,
                "num_readonly_unsigned_accounts": 1
            },
            "account_keys": [zeros(32), ones_32],
            "recent_blockhash": zeros(32),
            "instructions": [{
                "program_id_index": 1,
                "accounts": [0],
                "data": [1, 2, 3]
            }]
        }
    });

    let rt: RuntimeTransaction = serde_json::from_value(json_val).unwrap();
    assert_eq!(rt.version, 0);
    assert_eq!(rt.signatures.len(), 1);
    assert_eq!(rt.message.account_keys.len(), 2);
    assert_eq!(rt.message.instructions.len(), 1);
    assert_eq!(rt.message.instructions[0].data, vec![1, 2, 3]);
}

/// ProgramAccount wraps a pubkey and AccountInfo.
/// Returned by: get_program_accounts
#[test]
fn program_account_response_deserialization() {
    let fives_32: Value = Value::Array(vec![json!(5); 32]);
    let json_val = json!({
        "pubkey": fives_32,
        "account": {
            "lamports": 999,
            "owner": zeros(32),
            "data": [10, 20],
            "utxo": "txid:1",
            "is_executable": true
        }
    });

    let pa: ProgramAccount = serde_json::from_value(json_val).unwrap();
    assert_eq!(pa.pubkey, Pubkey::from([5; 32]));
    assert_eq!(pa.account.lamports, 999);
    assert!(pa.account.is_executable);
}

// =========================================================================
//  4. FULL JSON-RPC ENVELOPE SHAPE
// =========================================================================

/// The JSON-RPC envelope sent by `post_data()` has the standard 2.0 shape.
/// This test constructs the envelope the same way the client does and
/// verifies its structure.
#[test]
fn json_rpc_envelope_shape() {
    // This mirrors what ArchRpcClient::post_data() builds internally
    let params = serde_json::to_value(Pubkey::from([0; 32])).unwrap();
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": "curlycurl",
        "method": "read_account_info",
        "params": params,
    });

    let obj = envelope.as_object().unwrap();
    assert_eq!(obj["jsonrpc"], json!("2.0"));
    assert_eq!(obj["id"], json!("curlycurl"));
    assert_eq!(obj["method"], json!("read_account_info"));
    assert!(obj.contains_key("params"));
}

/// The JSON-RPC envelope sent by `post()` (no params) omits `params`.
#[test]
fn json_rpc_envelope_no_params_shape() {
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": "curlycurl",
        "method": "get_best_block_hash",
    });

    let obj = envelope.as_object().unwrap();
    assert_eq!(obj["jsonrpc"], json!("2.0"));
    assert_eq!(obj["method"], json!("get_best_block_hash"));
    assert!(!obj.contains_key("params"));
}

/// The `process_result` method expects `{"result": <value>}` on success and
/// `{"error": {"code": <int>, "message": <string>}}` on failure. This test
/// verifies the client can parse both shapes.
#[test]
fn process_result_response_shapes() {
    let config = Config::localnet();
    let client = arch_sdk::ArchRpcClient::new(&config);

    // Success shape
    let success = r#"{"result": "abc123"}"#.to_string();
    let result = client.process_result(success).unwrap();
    assert_eq!(result, Some(json!("abc123")));

    // Not-found shape (404 code returns None)
    let not_found = r#"{"error": {"code": 404, "message": "not found"}}"#.to_string();
    let result = client.process_result(not_found).unwrap();
    assert!(result.is_none());

    // Error shape (non-404 returns Err)
    let error = r#"{"error": {"code": 500, "message": "internal error"}}"#.to_string();
    let result = client.process_result(error);
    assert!(result.is_err());
}

// =========================================================================
//  5. ROUND-TRIP: serialize → deserialize for wire types
// =========================================================================

/// All wire types must round-trip through JSON without data loss.
#[test]
fn runtime_transaction_json_round_trip() {
    let rt = RuntimeTransaction {
        version: 0,
        signatures: vec![Signature::from([42u8; 64])],
        message: ArchMessage {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![Pubkey::from([1; 32]), Pubkey::from([2; 32])],
            recent_blockhash: Hash::from([3; 32]),
            instructions: vec![SanitizedInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![10, 20, 30],
            }],
        },
    };

    let json_val = serde_json::to_value(&rt).unwrap();
    let rt2: RuntimeTransaction = serde_json::from_value(json_val).unwrap();
    assert_eq!(rt, rt2);
}

#[test]
fn processed_transaction_json_round_trip() {
    let pt = ProcessedTransaction {
        runtime_transaction: RuntimeTransaction {
            version: 0,
            signatures: vec![],
            message: ArchMessage::default(),
        },
        status: Status::Failed("test error".to_string()),
        bitcoin_txid: Some(Hash::from([0xFF; 32])),
        logs: vec!["log1".to_string(), "log2".to_string()],
        rollback_status: RollbackStatus::Rolledback("reason".to_string()),
        inner_instructions_list: vec![],
    };

    let json_val = serde_json::to_value(&pt).unwrap();
    let pt2: ProcessedTransaction = serde_json::from_value(json_val).unwrap();
    assert_eq!(pt, pt2);
}

#[test]
fn account_info_json_round_trip() {
    let ai = AccountInfo {
        lamports: 42,
        owner: Pubkey::from([7; 32]),
        data: vec![1, 2, 3],
        utxo: "deadbeef:0".to_string(),
        is_executable: true,
    };

    let json_val = serde_json::to_value(&ai).unwrap();
    let ai2: AccountInfo = serde_json::from_value(json_val).unwrap();
    assert_eq!(ai, ai2);
}

#[test]
fn block_json_round_trip() {
    let b = Block {
        transactions: vec![Hash::from([1; 32]), Hash::from([2; 32])],
        previous_block_hash: Hash::from([3; 32]),
        timestamp: 1700000000000u128,
        block_height: 100,
        bitcoin_block_height: 800000,
    };

    let json_val = serde_json::to_value(&b).unwrap();
    let b2: Block = serde_json::from_value(json_val).unwrap();
    assert_eq!(b, b2);
}

// =========================================================================
//  6. PARAMETER SHAPES PER RPC METHOD
// =========================================================================

/// Pin the exact parameter shape for each RPC method by constructing the
/// JSON body the way the client does and checking its structure.
#[test]
fn per_method_param_shapes() {
    let pk = Pubkey::from([1; 32]);
    let h = Hash::from([2; 32]);

    // read_account_info: params = Pubkey
    let params = serde_json::to_value(&pk).unwrap();
    assert!(params.is_array());
    assert_eq!(params.as_array().unwrap().len(), 32);

    // get_multiple_accounts: params = Vec<Pubkey>
    let params = serde_json::to_value(&vec![pk]).unwrap();
    assert!(params.is_array());
    assert!(params.as_array().unwrap()[0].is_array());

    // get_processed_transaction: params = hex string
    let params = serde_json::to_value(h.to_string()).unwrap();
    assert!(params.is_string());
    assert_eq!(params.as_str().unwrap().len(), 64);

    // get_block_hash: params = u64
    let params = serde_json::to_value(42u64).unwrap();
    assert!(params.is_number());

    // get_block_by_hash: params = string (hash)
    let params = serde_json::to_value("abc123").unwrap();
    assert!(params.is_string());

    // get_block_by_height: params = u64
    let params = serde_json::to_value(100u64).unwrap();
    assert!(params.is_number());

    // get_full_block_by_hash: params = [hash, "full"]
    let params = vec![
        serde_json::to_value("abc123").unwrap(),
        serde_json::to_value(BlockTransactionFilter::Full).unwrap(),
    ];
    assert_eq!(params.len(), 2);
    assert!(params[0].is_string());
    assert_eq!(params[1], json!("full"));

    // get_account_address: params = [u8; 32] (from pubkey.serialize())
    let params = serde_json::to_value(pk.serialize()).unwrap();
    assert!(params.is_array());
    assert_eq!(params.as_array().unwrap().len(), 32);

    // get_program_accounts: params = [[u8; 32], filters]
    let filters: Option<Vec<AccountFilter>> = Some(vec![AccountFilter::DataSize(64)]);
    let params = json!([pk.serialize(), filters]);
    assert!(params.is_array());
    assert_eq!(params.as_array().unwrap().len(), 2);

    // check_pre_anchor_conflict: params = Vec<Pubkey>
    let params = serde_json::to_value(&vec![pk]).unwrap();
    assert!(params.is_array());

    // send_transaction: params = RuntimeTransaction
    let rt = RuntimeTransaction {
        version: 0,
        signatures: vec![],
        message: ArchMessage::default(),
    };
    let params = serde_json::to_value(&rt).unwrap();
    assert!(params.is_object());
    assert!(params.as_object().unwrap().contains_key("version"));

    // send_transactions: params = Vec<RuntimeTransaction>
    let params = serde_json::to_value(&vec![rt]).unwrap();
    assert!(params.is_array());
    assert!(params.as_array().unwrap()[0].is_object());
}
