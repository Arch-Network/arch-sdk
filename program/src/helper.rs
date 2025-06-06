/// Helper functions for Arch transaction creation and manipulation.
use std::str::FromStr;

use bitcoin::{
    absolute::LockTime, transaction::Version, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};

use crate::{
    account::AccountInfo,
    msg,
    program::{get_account_script_pubkey, get_bitcoin_tx},
};

/// Creates an Arch transaction representing a state transition from the provided accounts.
///
/// This function builds a transaction with:
/// - Inputs from all writable accounts' UTXOs
/// - Outputs that maintain the same value with script pubkeys derived from account keys
///
/// # Parameters
/// * `accounts` - A slice of `AccountInfo` objects representing the accounts involved in the state transition
///
/// # Returns
/// A `Transaction` object representing the Arch state transition
pub fn get_state_transition_tx(accounts: &[AccountInfo]) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: accounts
            .iter()
            .filter(|account| account.is_writable)
            .map(|account| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(&hex::encode(account.utxo.txid())).unwrap(),
                    vout: account.utxo.vout(),
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect::<Vec<TxIn>>(),
        output: accounts
            .iter()
            .filter(|account| account.is_writable)
            .map(|account| {
                let tx = get_bitcoin_tx(account.utxo.txid().try_into().unwrap()).unwrap();

                let output = tx.output[account.utxo.vout() as usize].clone();

                TxOut {
                    value: output.value,
                    script_pubkey: ScriptBuf::from_bytes(
                        get_account_script_pubkey(account.key).to_vec(),
                    ),
                }
            })
            .collect::<Vec<TxOut>>(),
    }
}

/// Adds a new state transition input-output pair to an existing transaction.
///
/// This function appends a new input derived from the account's UTXO and a corresponding
/// output with a script pubkey derived from the account's key.
///
/// # Parameters
/// * `transaction` - A mutable reference to the transaction being modified
/// * `account` - A reference to the `AccountInfo` to add to the transaction
///
/// # Panics
/// This function will panic if the provided account is not writable.
pub fn add_state_transition(transaction: &mut Transaction, account: &AccountInfo) {
    assert!(account.is_writable);
    transaction.input.push(TxIn {
        previous_output: OutPoint {
            txid: Txid::from_str(&hex::encode(account.utxo.txid())).unwrap(),
            vout: account.utxo.vout(),
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    });

    msg!("account utxo : {:?}", hex::encode(account.utxo.txid()));

    let tx = get_bitcoin_tx(account.utxo.txid().try_into().unwrap()).unwrap();

    let output = tx.output[account.utxo.vout() as usize].clone();

    transaction.output.push(TxOut {
        value: output.value,
        script_pubkey: ScriptBuf::from_bytes(get_account_script_pubkey(account.key).to_vec()),
    });
}
