//! This module contains helper methods for interacting with programs

use anyhow::{anyhow, Result};
use bip322::{create_to_sign, create_to_spend, verify_simple};
use bitcoin::{
    absolute::LockTime,
    address::Address,
    key::{Keypair, TapTweak, TweakedKeypair},
    secp256k1::{self, Secp256k1},
    sighash::{self, Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, PrivateKey, Psbt, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use bitcoincore_rpc::{Auth, Client, RawTx, RpcApi};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use serde::Serialize;
use serde_json::{from_str, json, Value};
use std::fs;
use std::str::FromStr;

use crate::processed_transaction::ProcessedTransaction;

use crate::arch_program::instruction::Instruction;
use crate::arch_program::message::Message;
use crate::arch_program::pubkey::Pubkey;
use crate::arch_program::system_instruction::SystemInstruction;
use crate::constants::{
    BITCOIN_NETWORK, BITCOIN_NODE_ENDPOINT, BITCOIN_NODE_PASSWORD, BITCOIN_NODE_USERNAME,
    CALLER_FILE_PATH, GET_ACCOUNT_ADDRESS, GET_BEST_BLOCK_HASH, GET_BLOCK,
    GET_PROCESSED_TRANSACTION, GET_PROGRAM, NODE1_ADDRESS, READ_ACCOUNT_INFO,
    TRANSACTION_NOT_FOUND_CODE,
};
use crate::error::SDKError;
use crate::models::CallerInfo;
use crate::runtime_transaction::RuntimeTransaction;
use crate::runtime_transaction::RUNTIME_TX_SIZE_LIMIT;
use crate::signature::Signature;

pub fn process_result(response: String) -> Result<Value> {
    let result = from_str::<Value>(&response).expect("result should be Value parseable");

    let result = match result {
        Value::Object(object) => object,
        _ => panic!("unexpected output"),
    };

    if let Some(err) = result.get("error") {
        return Err(anyhow!("{:?}", err));
    }

    Ok(result["result"].clone())
}

pub fn process_get_transaction_result(response: String) -> Result<Value> {
    let result = from_str::<Value>(&response).expect("result should be string parseable");

    let result = match result {
        Value::Object(object) => object,
        _ => panic!("unexpected output"),
    };

    if let Some(err) = result.get("error") {
        if let Value::Number(code) = result["error"]["code"].clone() {
            if code.as_i64() == Some(TRANSACTION_NOT_FOUND_CODE) {
                return Ok(Value::Null);
            }
        }
        return Err(anyhow!("{:?}", err));
    }

    Ok(result["result"].clone())
}

pub fn post(url: &str, method: &str) -> String {
    let client = reqwest::blocking::Client::new();
    let res = client
        .post(url)
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "curlycurl",
            "method": method,
        }))
        .send()
        .expect("post method should not fail");

    res.text().expect("result should be text decodable")
}

pub fn post_data<T: Serialize + std::fmt::Debug>(url: &str, method: &str, params: T) -> String {
    let client = reqwest::blocking::Client::new();
    let res = client
        .post(url)
        .header("content-type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "curlycurl",
            "method": method,
            "params": params,
        }))
        .send();

    res.expect("post method should not fail")
        .text()
        .expect("result should be text decodable")
}

/// Returns a caller information using the secret key file specified
fn _get_trader(trader_id: u64) -> Result<CallerInfo> {
    let file_path = &format!("../../.arch/trader{}.json", trader_id);
    CallerInfo::with_secret_key_file(file_path)
}

use crate::helper::secp256k1::SecretKey;
use bitcoin::key::UntweakedKeypair;
use bitcoin::XOnlyPublicKey;
use rand_core::OsRng;

pub fn with_secret_key_file(file_path: &str) -> Result<(UntweakedKeypair, Pubkey)> {
    let secp = Secp256k1::new();
    let secret_key = match fs::read_to_string(file_path) {
        Ok(key) => SecretKey::from_str(&key).unwrap(),
        Err(_) => {
            let (key, _) = secp.generate_keypair(&mut OsRng);
            fs::write(file_path, key.display_secret().to_string())
                .map_err(|_| anyhow!("Unable to write file"))?;
            key
        }
    };
    let keypair = UntweakedKeypair::from_secret_key(&secp, &secret_key);
    let pubkey = Pubkey::from_slice(&XOnlyPublicKey::from_keypair(&keypair).0.serialize());
    Ok((keypair, pubkey))
}

fn extend_bytes_max_len() -> usize {
    let message = Message {
        signers: vec![Pubkey::system_program()],
        instructions: vec![SystemInstruction::new_write_bytes_instruction(
            0,
            0,
            vec![0_u8; 8],
            Pubkey::system_program(),
        )],
    };

    RUNTIME_TX_SIZE_LIMIT
        - RuntimeTransaction {
            version: 0,
            signatures: vec![Signature([0_u8; 64].to_vec())],
            message,
        }
        .serialize()
        .len()
}

/// Creates an instruction, signs it as a message
/// and sends the signed message as a transaction
pub fn sign_and_send_instruction(
    instruction: Instruction,
    signers: Vec<Keypair>,
) -> Result<(String, String)> {
    // Get public keys from signers
    let pubkeys = signers
        .iter()
        .map(|signer| Pubkey::from_slice(&XOnlyPublicKey::from_keypair(signer).0.serialize()))
        .collect::<Vec<Pubkey>>();

    // Step 2: Create a message with the instruction and signers
    let message = Message {
        signers: pubkeys.clone(), // Clone for logging purposes
        instructions: vec![instruction.clone()],
    };

    // Step 3: Hash the message and decode
    let digest_slice = message.hash();

    // Step 5: Sign the message with each signer's key
    let signatures = signers
        .iter()
        .map(|signer| {
            let signature = sign_message_bip322(signer, &digest_slice, BITCOIN_NETWORK).to_vec();
            Signature(signature)
        })
        .collect::<Vec<Signature>>();

    //println!("Message signed by {} signers",signatures.len());

    // Step 6: Create transaction parameters
    let params = RuntimeTransaction {
        version: 0,
        signatures: signatures.clone(), // Clone for logging purposes
        message: message.clone(),       // Clone for logging purposes
    };

    //println!("Runtime Transaction constructed : {:?} ",params);
    // Step 7: Send transaction to node for processeing
    let result = process_result(post_data(NODE1_ADDRESS, "send_transaction", params))
        .expect("send_transaction should not fail")
        .as_str()
        .expect("cannot convert result to string")
        .to_string();

    //println!("Arch transaction ID: {:?}", result);

    // Step 8: Hash the instruction
    let hashed_instruction = instruction.hash();

    Ok((result, hashed_instruction))
}

pub fn sign_and_send_transaction(
    instructions: Vec<Instruction>,
    signers: Vec<UntweakedKeypair>,
) -> Result<String> {
    let pubkeys = signers
        .iter()
        .map(|signer| Pubkey::from_slice(&XOnlyPublicKey::from_keypair(signer).0.serialize()))
        .collect::<Vec<Pubkey>>();

    let message = Message {
        signers: pubkeys,
        instructions,
    };
    let digest_slice = message.hash();
    let signatures = signers
        .iter()
        .map(|signer| {
            Signature(sign_message_bip322(signer, &digest_slice, BITCOIN_NETWORK).to_vec())
        })
        .collect::<Vec<Signature>>();

    let params = RuntimeTransaction {
        version: 0,
        signatures,
        message,
    };
    let result = process_result(post_data(NODE1_ADDRESS, "send_transaction", params))
        .expect("send_transaction should not fail")
        .as_str()
        .expect("cannot convert result to string")
        .to_string();

    Ok(result)
}

/// Deploys the HelloWorld program using the compiled ELF
pub fn deploy_program_txs(
    program_keypair: UntweakedKeypair,
    elf_path: &str,
) -> Result<(), SDKError> {
    let program_pubkey =
        Pubkey::from_slice(&XOnlyPublicKey::from_keypair(&program_keypair).0.serialize());

    let account_info = read_account_info(NODE1_ADDRESS, program_pubkey)?;

    if account_info.is_executable {
        let (txid, _) = sign_and_send_instruction(
            SystemInstruction::new_retract_instruction(program_pubkey),
            vec![program_keypair],
        )
        .map_err(|_| SDKError::SignAndSendFailed)?;

        let processed_tx = get_processed_transaction(NODE1_ADDRESS, txid.clone())
            .map_err(|_| SDKError::GetProcessedTransactionFailed)?;

        println!("processed_tx {:?}", processed_tx);
    }

    let elf = fs::read(elf_path).map_err(|_| SDKError::ElfPathNotFound)?;

    if account_info.data.len() > elf.len() {
        let (txid, _) = sign_and_send_instruction(
            SystemInstruction::new_truncate_instruction(program_pubkey, elf.len() as u32),
            vec![program_keypair],
        )
        .map_err(|_| SDKError::SignAndSendFailed)?;

        let processed_tx = get_processed_transaction(NODE1_ADDRESS, txid.clone())
            .map_err(|_| SDKError::GetProcessedTransactionFailed)?;

        println!("processed_tx {:?}", processed_tx);
    }

    let txs = elf
        .chunks(extend_bytes_max_len())
        .enumerate()
        .map(|(i, chunk)| {
            let offset: u32 = (i * extend_bytes_max_len()) as u32;
            let len: u32 = chunk.len() as u32;

            let message = Message {
                signers: vec![program_pubkey],
                instructions: vec![SystemInstruction::new_write_bytes_instruction(
                    offset,
                    len,
                    chunk.to_vec(),
                    program_pubkey,
                )],
            };

            let digest_slice = message.hash();

            RuntimeTransaction {
                version: 0,
                signatures: vec![Signature(
                    sign_message_bip322(&program_keypair, &digest_slice, BITCOIN_NETWORK).to_vec(),
                )],
                message,
            }
        })
        .collect::<Vec<RuntimeTransaction>>();

    let post_result = post_data(NODE1_ADDRESS, "send_transactions", txs);
    let processed_data =
        process_result(post_result).map_err(|_| SDKError::SendTransactionFailed)?;
    let array_data = processed_data
        .as_array()
        .ok_or(SDKError::InvalidResponseType)?;
    let txids = array_data
        .iter()
        .map(|r| {
            r.as_str()
                .ok_or(SDKError::InvalidResponseType)
                .map(String::from)
        })
        .collect::<Result<Vec<String>, SDKError>>()?;

    let pb = ProgressBar::new(txids.len() as u64);

    pb.set_style(ProgressStyle::default_bar()
        .progress_chars("#>-")
        .template("{spinner:.green}[{elapsed_precise:.blue}] {msg:.blue} [{bar:100.green/blue}] {pos}/{len} ({eta})").unwrap());

    pb.set_message("Successfully Processed Deployment Transactions :");

    for txid in txids {
        let _processed_tx = get_processed_transaction(NODE1_ADDRESS, txid.clone())
            .map_err(|_| SDKError::GetProcessedTransactionFailed)?;
        pb.inc(1);
        pb.set_message("Successfully Processed Deployment Transactions :");
    }

    pb.finish();
    Ok(())
}

/// Starts Key Exchange by calling the RPC method
pub fn start_key_exchange() {
    match process_result(post(NODE1_ADDRESS, "start_key_exchange")) {
        Err(err) => println!("Error starting Key Exchange: {:?}", err),
        Ok(val) => assert!(val.as_bool().unwrap()),
    };
}

/// Starts a Distributed Key Generation round by calling the RPC method
pub fn start_dkg() {
    if let Err(err) = process_result(post(NODE1_ADDRESS, "start_dkg")) {
        println!("Error starting DKG: {:?}", err);
    };
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountInfoResult {
    pub owner: Pubkey,
    pub data: Vec<u8>,
    pub utxo: String,
    pub is_executable: bool,
    pub tag: String,
}

/// Read Utxo given the utxo ID
pub fn read_account_info(url: &str, pubkey: Pubkey) -> Result<AccountInfoResult> {
    let result = process_result(post_data(url, READ_ACCOUNT_INFO, pubkey))?;
    serde_json::from_value(result).map_err(|_| anyhow!("Unable to decode read_account_info result"))
}
/*
pub async fn get_program_accounts(
    context: Arc<ValidatorContext>,
    program_id: Pubkey,
    filters: Option<Vec<AccountFilter>>,
) -> Result<Vec<ProgramAccount>, ErrorObject<'static>> {
    match context
        .rocks_db()
        .await
        .get_program_accounts(&program_id, filters)
    {
        Ok(accounts) => Ok(accounts),
        Err(err) => {
            error!("Error fetching program accounts: {:?}", err);
            Err(ErrorObject::borrowed(
                ErrorCode::InternalError.code(),
                "Error fetching program accounts",
                None,
            ))
        }
    }
}
*/

/// Returns a program given the program ID
pub fn get_program(url: &str, program_id: String) -> String {
    process_result(post_data(url, GET_PROGRAM, program_id))
        .expect("get_program should not fail")
        .as_str()
        .expect("cannot convert result to string")
        .to_string()
}

/// Returns the best block
fn _get_best_block() -> String {
    let best_block_hash = process_result(post(NODE1_ADDRESS, GET_BEST_BLOCK_HASH))
        .expect("best_block_hash should not fail")
        .as_str()
        .expect("cannot convert result to string")
        .to_string();
    process_result(post_data(NODE1_ADDRESS, GET_BLOCK, best_block_hash))
        .expect("get_block should not fail")
        .as_str()
        .expect("cannot convert result to string")
        .to_string()
}

/// Returns a processed transaction given the txid
/// Keeps trying for a maximum of 60 seconds if the processed transaction is not available
pub fn get_processed_transaction(url: &str, tx_id: String) -> Result<ProcessedTransaction> {
    let mut processed_tx =
        process_get_transaction_result(post_data(url, GET_PROCESSED_TRANSACTION, tx_id.clone()));
    if let Err(e) = processed_tx {
        return Err(anyhow!("{}", e));
    }

    let mut wait_time = 1;
    while let Ok(Value::Null) = processed_tx {
        std::thread::sleep(std::time::Duration::from_secs(wait_time));
        processed_tx = process_get_transaction_result(post_data(
            url,
            GET_PROCESSED_TRANSACTION,
            tx_id.clone(),
        ));
        wait_time += 1;
        if wait_time >= 60 {
            println!("get_processed_transaction has run for more than 60 seconds");
            return Err(anyhow!("Failed to retrieve processed transaction"));
        }
    }

    if let Ok(ref tx) = processed_tx {
        let mut p = tx.clone();

        let get_status = |p: Value| -> String {
            if p["status"].as_str().is_some() {
                p["status"].as_str().unwrap().to_string()
            } else if let Some(val) = p["status"].as_object() {
                if val.contains_key("Failed") {
                    "Failed".to_string()
                } else {
                    unreachable!("WTFFF");
                }
            } else {
                unreachable!("WTFFF2");
            }
        };

        while get_status(p.clone()) != *"Processed" && get_status(p.clone()) != *"Failed" {
            println!("Processed transaction is not yet finalized. Retrying...");
            std::thread::sleep(std::time::Duration::from_secs(wait_time));
            p = process_get_transaction_result(post_data(
                url,
                GET_PROCESSED_TRANSACTION,
                tx_id.clone(),
            ))
            .unwrap();
            wait_time += 10;
            if wait_time >= 60 {
                println!("get_processed_transaction has run for more than 60 seconds");
                return Err(anyhow!("Failed to retrieve processed transaction"));
            }
        }
        processed_tx = Ok(p);
    }

    Ok(serde_json::from_value(processed_tx?).unwrap())
}

pub fn prepare_fees() -> String {
    let userpass = Auth::UserPass(
        BITCOIN_NODE_USERNAME.to_string(),
        BITCOIN_NODE_PASSWORD.to_string(),
    );
    let rpc =
        Client::new(BITCOIN_NODE_ENDPOINT, userpass).expect("rpc shouldn not fail to be initiated");

    let caller = CallerInfo::with_secret_key_file(CALLER_FILE_PATH)
        .expect("getting caller info should not fail");

    let txid = rpc
        .send_to_address(
            &caller.address,
            Amount::from_sat(100000),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("SATs should be sent to address");

    let sent_tx = rpc
        .get_raw_transaction(&txid, None)
        .expect("should get raw transaction");
    let mut vout: u32 = 0;

    for (index, output) in sent_tx.output.iter().enumerate() {
        if output.script_pubkey == caller.address.script_pubkey() {
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
    let raw_tx = rpc
        .get_raw_transaction(&txid, None)
        .expect("raw transaction should not fail");
    let prevouts = vec![raw_tx.output[vout as usize].clone()];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .expect("should not fail to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    let secp = Secp256k1::new();
    let tweaked: TweakedKeypair = caller.key_pair.tap_tweak(&secp, None);
    let msg = secp256k1::Message::from(sighash);
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack.
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    tx.input[0].witness.push(signature.to_vec());

    tx.raw_hex()
}

pub fn prepare_fees_with_extra_utxo(rune_txid: String, rune_vout: u32) -> String {
    let rune_txid = Txid::from_str(&rune_txid).unwrap();

    let userpass = Auth::UserPass(
        BITCOIN_NODE_USERNAME.to_string(),
        BITCOIN_NODE_PASSWORD.to_string(),
    );
    let rpc =
        Client::new(BITCOIN_NODE_ENDPOINT, userpass).expect("rpc shouldn not fail to be initiated");

    let caller = CallerInfo::with_secret_key_file(CALLER_FILE_PATH)
        .expect("getting caller info should not fail");

    let txid = rpc
        .send_to_address(
            &caller.address,
            Amount::from_sat(3000),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("SATs should be sent to address");

    let sent_tx = rpc
        .get_raw_transaction(&txid, None)
        .expect("should get raw transaction");
    let mut vout: u32 = 0;

    for (index, output) in sent_tx.output.iter().enumerate() {
        if output.script_pubkey == caller.address.script_pubkey() {
            vout = index as u32;
        }
    }

    let rune_sent_tx = rpc
        .get_raw_transaction(&rune_txid, None)
        .expect("should get raw transaction");

    let mut tx = Transaction {
        version: Version::TWO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: rune_txid,
                    vout: rune_vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: rune_sent_tx.output[rune_vout as usize].value,
            script_pubkey: ScriptBuf::from_bytes(vec![]),
        }],
        lock_time: LockTime::ZERO,
    };

    // PREPARE Prevouts

    let rune_raw_tx = rpc
        .get_raw_transaction(&rune_txid, None)
        .expect("raw transaction should not fail");

    let raw_tx = rpc
        .get_raw_transaction(&txid, None)
        .expect("raw transaction should not fail");

    let prevouts = vec![
        rune_raw_tx.output[rune_vout as usize].clone(),
        raw_tx.output[vout as usize].clone(),
    ];
    let prevouts = Prevouts::All(&prevouts);

    // Sign rune input
    let rune_sighash_type = TapSighashType::SinglePlusAnyoneCanPay;

    let mut rune_sighasher = SighashCache::new(&mut tx);

    let rune_sighash = rune_sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, rune_sighash_type)
        .expect("should not fail to construct sighash");

    let secp = Secp256k1::new();
    let tweaked: TweakedKeypair = caller.key_pair.tap_tweak(&secp, None);
    let msg = secp256k1::Message::from(rune_sighash);
    let rune_signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    let rune_signature = bitcoin::taproot::Signature {
        signature: rune_signature,
        sighash_type: rune_sighash_type,
    };

    tx.input[0].witness.push(rune_signature.to_vec());

    // Sign the anchoring utxo
    let sighash_type = TapSighashType::NonePlusAnyoneCanPay;

    let mut sighasher = SighashCache::new(&mut tx);

    let sighash = sighasher
        .taproot_key_spend_signature_hash(1, &prevouts, sighash_type)
        .expect("should not fail to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    let secp = Secp256k1::new();
    let tweaked: TweakedKeypair = caller.key_pair.tap_tweak(&secp, None);
    let msg = secp256k1::Message::from(sighash);
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack.
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    tx.input[1].witness.push(signature.to_vec());

    tx.raw_hex()
}

pub fn send_utxo(pubkey: Pubkey) -> (String, u32) {
    let userpass = Auth::UserPass(
        BITCOIN_NODE_USERNAME.to_string(),
        BITCOIN_NODE_PASSWORD.to_string(),
    );
    let rpc =
        Client::new(BITCOIN_NODE_ENDPOINT, userpass).expect("rpc shouldn not fail to be initiated");

    let _caller = CallerInfo::with_secret_key_file(CALLER_FILE_PATH)
        .expect("getting caller info should not fail");

    let address = get_account_address(pubkey);

    let account_address = Address::from_str(&address)
        .unwrap()
        .require_network(BITCOIN_NETWORK)
        .unwrap();

    let txid = rpc
        .send_to_address(
            &account_address,
            Amount::from_sat(3000),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("SATs should be sent to address");

    let sent_tx = rpc
        .get_raw_transaction(&txid, None)
        .expect("should get raw transaction");
    let mut vout = 0;

    for (index, output) in sent_tx.output.iter().enumerate() {
        if output.script_pubkey == account_address.script_pubkey() {
            vout = index as u32;
        }
    }

    // let tx_info = rpc.get_raw_transaction_info(&txid, None).unwrap();

    (txid.to_string(), vout)
}

pub fn send_utxo_2(pubkey: Pubkey) -> (Txid, u32) {
    let userpass = Auth::UserPass(
        BITCOIN_NODE_USERNAME.to_string(),
        BITCOIN_NODE_PASSWORD.to_string(),
    );
    let rpc =
        Client::new(BITCOIN_NODE_ENDPOINT, userpass).expect("rpc shouldn not fail to be initiated");

    let _caller = CallerInfo::with_secret_key_file(CALLER_FILE_PATH)
        .expect("getting caller info should not fail");

    let address = get_account_address(pubkey);
    println!("address {:?}", address);
    let account_address = Address::from_str(&address)
        .unwrap()
        .require_network(BITCOIN_NETWORK)
        .unwrap();

    let txid = rpc
        .send_to_address(
            &account_address,
            Amount::from_sat(3000),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("SATs should be sent to address");

    let sent_tx = rpc
        .get_raw_transaction(&txid, None)
        .expect("should get raw transaction");
    let mut vout = 0;

    for (index, output) in sent_tx.output.iter().enumerate() {
        if output.script_pubkey == account_address.script_pubkey() {
            vout = index as u32;
            println!("FOUUUND MATCHING UTXO")
        }
    }

    (txid, vout)
}

fn get_account_address(pubkey: Pubkey) -> String {
    process_result(post_data(
        NODE1_ADDRESS,
        GET_ACCOUNT_ADDRESS,
        pubkey.serialize(),
    ))
    .expect("get_account_address should not fail")
    .as_str()
    .expect("cannot convert result to string")
    .to_string()
}

fn _get_address_utxos(rpc: &Client, address: String) -> Vec<Value> {
    let client = reqwest::blocking::Client::new();

    let res = client
        .get(format!(
            "https://mempool.dev.aws.archnetwork.xyz/api/address/{}/utxo",
            address
        ))
        .header("Accept", "application/json")
        .send()
        .unwrap();

    let utxos = from_str::<Value>(&res.text().unwrap()).unwrap();

    utxos
        .as_array()
        .unwrap()
        .iter()
        .filter(|utxo| {
            utxo["status"]["block_height"].as_u64().unwrap() <= rpc.get_block_count().unwrap() - 100
        })
        .cloned()
        .collect()
}

// bip322 utils
pub fn sign_message_bip322(
    keypair: &UntweakedKeypair,
    msg: &[u8],
    network: bitcoin::Network,
) -> [u8; 64] {
    let secp = Secp256k1::new();
    let xpubk = XOnlyPublicKey::from_keypair(keypair).0;
    let private_key = PrivateKey::new(SecretKey::from_keypair(keypair), network);

    let address = Address::p2tr(&secp, xpubk, None, network);

    let to_spend = create_to_spend(&address, msg).unwrap();
    let mut to_sign = create_to_sign(&to_spend, None).unwrap();

    let witness = match address.witness_program() {
        Some(witness_program) => {
            let version = witness_program.version().to_num();
            let program_len = witness_program.program().len();

            match version {
                1 => {
                    if program_len != 32 {
                        panic!("not key spend path");
                    }
                    create_message_signature_taproot(&to_spend, &to_sign, private_key)
                }
                _ => {
                    panic!("unsuported address");
                }
            }
        }
        None => {
            panic!("unsuported address");
        }
    };

    to_sign.inputs[0].final_script_witness = Some(witness);

    let signature = to_sign.extract_tx().unwrap().input[0].witness.clone();

    signature.to_vec()[0][..64].try_into().unwrap()
}

fn create_message_signature_taproot(
    to_spend_tx: &Transaction,
    to_sign: &Psbt,
    private_key: PrivateKey,
) -> Witness {
    let mut to_sign = to_sign.clone();

    let secp = Secp256k1::new();
    let key_pair = Keypair::from_secret_key(&secp, &private_key.inner);

    let (x_only_public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
    to_sign.inputs[0].tap_internal_key = Some(x_only_public_key);

    let sighash_type = TapSighashType::All;

    let mut sighash_cache = SighashCache::new(to_sign.unsigned_tx.clone());

    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            0,
            &sighash::Prevouts::All(&[TxOut {
                value: Amount::from_sat(0),
                script_pubkey: to_spend_tx.output[0].clone().script_pubkey,
            }]),
            sighash_type,
        )
        .expect("signature hash should compute");

    let key_pair = key_pair
        .tap_tweak(&secp, to_sign.inputs[0].tap_merkle_root)
        .to_inner();

    let sig = secp.sign_schnorr(
        &bitcoin::secp256k1::Message::from_digest_slice(sighash.as_ref())
            .expect("should be cryptographically secure hash"),
        &key_pair,
    );

    let witness = sighash_cache
        .witness_mut(0)
        .expect("getting mutable witness reference should work");

    witness.push(
        bitcoin::taproot::Signature {
            signature: sig,
            sighash_type,
        }
        .to_vec(),
    );

    witness.to_owned()
}

pub fn verify_message_bip322(
    msg: &[u8],
    pubkey: [u8; 32],
    signature: [u8; 64],
    uses_sighash_all: bool,
    network: bitcoin::Network,
) -> Result<()> {
    let mut signature = signature.to_vec();
    if uses_sighash_all {
        signature.push(1);
    }
    let mut witness = Witness::new();
    witness.push(&signature);

    let secp = Secp256k1::new();
    let xpubk = XOnlyPublicKey::from_slice(&pubkey).unwrap();
    let address = Address::p2tr(&secp, xpubk, None, network);

    verify_simple(&address, msg, witness).map_err(|e| anyhow!("BIP-322 verification failed: {}", e))
}
