use std::{fs, str::FromStr};

use arch_program::{
    account::MIN_ACCOUNT_LAMPORTS, hash::Hash, pubkey::Pubkey, sanitized::ArchMessage,
    system_instruction, system_program::SYSTEM_PROGRAM_ID,
};
use arch_sdk::{
    build_and_sign_transaction, generate_new_keypair, AccountInfo, ArchRpcClient,
    ProcessedTransaction, ProgramDeployer, RuntimeTransaction, Status, {BitcoinHelper, Config},
};
use bitcoin::{
    absolute::LockTime,
    key::{Keypair, Secp256k1, TapTweak, TweakedKeypair},
    secp256k1::{self},
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Address, Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use bitcoincore_rpc::{Auth, Client, RawTx, RpcApi};

use crate::{
    constants::{
        BITCOIN_NETWORK, BITCOIN_NODE_ENDPOINT, BITCOIN_NODE_PASSWORD, BITCOIN_NODE_USERNAME,
        CALLER_FILE_PATH, NODE1_ADDRESS,
    },
    models::CallerInfo,
};

/* -------------------------------------------------------------------------- */
/*                             PREPARES A FEE PSBT                            */
/* -------------------------------------------------------------------------- */
/// This function sends the caller BTC, then prepares a fee PSBT and returns
/// the said PSBT in HEX encoding
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

/* -------------------------------------------------------------------------- */
/*               PREPARES A FEE PSBT WITH EXTRA UTXO (RBF TESTS)              */
/* -------------------------------------------------------------------------- */
/// This function sends the caller BTC, then prepares a fee PSBT and returns
/// the said PSBT in HEX encoding
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

/* -------------------------------------------------------------------------- */
/*                     SENDS A UTXO TO THE ACCOUNT ADDRESS                    */
/* -------------------------------------------------------------------------- */
/// Used to send a utxo the taptweaked account address corresponding to the
/// network's joint pubkey
pub fn send_utxo(pubkey: Pubkey) -> (String, u32) {
    let bitcoin_config = Config {
        node_endpoint: BITCOIN_NODE_ENDPOINT.to_string(),
        node_username: BITCOIN_NODE_USERNAME.to_string(),
        node_password: BITCOIN_NODE_PASSWORD.to_string(),
        network: BITCOIN_NETWORK,
        arch_node_url: NODE1_ADDRESS.to_string(),
    };

    let bitcoin_helper = BitcoinHelper::new(&bitcoin_config);

    let (txid, vout) = bitcoin_helper.send_utxo(pubkey).unwrap();

    (txid, vout)
}

pub fn deploy_program(
    program_name: String,
    elf_path: String,
    program_keypair: Keypair,
    authority_keypair: Keypair,
) -> Pubkey {
    let deployer = ProgramDeployer::new(NODE1_ADDRESS, BITCOIN_NETWORK);

    deployer
        .try_deploy_program(program_name, program_keypair, authority_keypair, &elf_path)
        .unwrap()
}

pub fn deploy_program_elf(elf_path: String, program_keypair: Keypair, authority_keypair: Keypair) {
    let deployer = ProgramDeployer::new(NODE1_ADDRESS, BITCOIN_NETWORK);

    let elf = fs::read(elf_path).expect("elf path should be available");

    deployer
        .deploy_program_elf(program_keypair, authority_keypair, &elf)
        .unwrap();
}

pub fn create_account_with_anchor(
    from_pubkey: Pubkey,
    from_keypair: Keypair,
) -> (Keypair, Pubkey, Address) {
    let (account_key_pair, account_pubkey, address) = generate_new_keypair(BITCOIN_NETWORK);

    let (txid, vout) = send_utxo(account_pubkey);

    let arch_rpc_client = ArchRpcClient::new(&NODE1_ADDRESS.to_string());

    let recent_blockhash = arch_rpc_client.get_best_block_hash().unwrap();
    let transaction = build_and_sign_transaction(
        ArchMessage::new(
            &[system_instruction::create_account_with_anchor(
                &from_pubkey,
                &account_pubkey,
                MIN_ACCOUNT_LAMPORTS,
                0,
                &SYSTEM_PROGRAM_ID,
                hex::decode(txid).unwrap().try_into().unwrap(),
                vout,
            )],
            Some(from_pubkey),
            recent_blockhash,
        ),
        vec![account_key_pair, from_keypair],
        BITCOIN_NETWORK,
    )
    .expect("Failed to build and sign transaction");

    let txid = arch_rpc_client
        .send_transaction(transaction)
        .expect("signing and sending a transaction should not fail");

    let processed_tx = arch_rpc_client
        .wait_for_processed_transaction(&txid)
        .expect("get processed transaction should not fail");

    assert!(matches!(processed_tx.status, Status::Processed));

    (account_key_pair, account_pubkey, address)
}

pub fn read_account_info(pubkey: Pubkey) -> AccountInfo {
    let arch_rpc_client = ArchRpcClient::new(&NODE1_ADDRESS.to_string());

    let account_info = arch_rpc_client
        .read_account_info(pubkey)
        .expect("read account info should not fail");
    account_info
}

pub fn try_read_account_info(pubkey: Pubkey) -> Option<AccountInfo> {
    let arch_rpc_client = ArchRpcClient::new(&NODE1_ADDRESS.to_string());

    arch_rpc_client.read_account_info(pubkey).ok()
}

pub fn send_transactions_and_wait(
    transactions: Vec<RuntimeTransaction>,
) -> Vec<ProcessedTransaction> {
    let arch_rpc_client = ArchRpcClient::new(&NODE1_ADDRESS.to_string());
    let txids = arch_rpc_client.send_transactions(transactions).unwrap();

    let processed_txs = arch_rpc_client
        .wait_for_processed_transactions(txids)
        .expect("get processed transactions should not fail");

    processed_txs
}

/* -------------------------------------------------------------------------- */
/*                  ASSIGN AN ACCOUNT OWNERSHIP TO A PROGRAM                  */
/* -------------------------------------------------------------------------- */
/// Used to assign an account's ownership to another pubkey, requires current
/// owner's key pair.
pub fn assign_ownership_to_program(
    program_pubkey: Pubkey,
    account_to_transfer_pubkey: Pubkey,
    current_owner_keypair: Keypair,
) -> Hash {
    let arch_rpc_client = ArchRpcClient::new(&NODE1_ADDRESS.to_string());

    let assign_instruction =
        system_instruction::assign(&account_to_transfer_pubkey, &program_pubkey);

    let current_owner_pubkey = Pubkey(current_owner_keypair.x_only_public_key().0.serialize());

    let recent_blockhash = arch_rpc_client.get_best_block_hash().unwrap();
    let transaction = build_and_sign_transaction(
        ArchMessage::new(
            &[assign_instruction],
            Some(current_owner_pubkey),
            recent_blockhash,
        ),
        vec![current_owner_keypair],
        BITCOIN_NETWORK,
    )
    .expect("Failed to build and sign transaction");

    let txid = arch_rpc_client
        .send_transaction(transaction)
        .expect("signing and sending a transaction should not fail");

    arch_rpc_client
        .wait_for_processed_transaction(&txid)
        .expect("get processed transaction should not fail");

    txid
}

pub fn create_and_fund_account_with_faucet(keypair: &Keypair, bitcoin_network: bitcoin::Network) {
    let arch_rpc_client = ArchRpcClient::new(&NODE1_ADDRESS.to_string());

    arch_rpc_client
        .create_and_fund_account_with_faucet(keypair, bitcoin_network)
        .expect("create and fund account with faucet should not fail");
}
