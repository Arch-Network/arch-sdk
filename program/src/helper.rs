/// Helper functions for Arch transaction creation and manipulation.
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};

use crate::{
    account::AccountInfo,
    program::{get_account_script_pubkey, get_bitcoin_tx_output_value},
    program_error::ProgramError,
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
/// A `Result<Transaction, ProgramError>` representing the Arch state transition
pub fn get_state_transition_tx(accounts: &[AccountInfo]) -> Result<Transaction, ProgramError> {
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: Vec::<TxIn>::new(),
        output: Vec::<TxOut>::new(),
    };

    for account in accounts.iter().filter(|account| account.is_writable) {
        // Reuse the helper that already does proper error handling
        let _ = add_state_transition(&mut transaction, account)?;
    }

    Ok(transaction)
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
pub fn add_state_transition(
    transaction: &mut Transaction,
    account: &AccountInfo,
) -> Result<u64, ProgramError> {
    assert!(account.is_writable);

    transaction.input.push(TxIn {
        previous_output: OutPoint {
            txid: account.utxo.to_txid(),
            vout: account.utxo.vout(),
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    });

    let utxo_value =
        get_bitcoin_tx_output_value(account.utxo.txid_big_endian(), account.utxo.vout()).ok_or(
            ProgramError::InvalidStateTransition(format!(
                "Couldn't get utxo value for account {}",
                account.key
            )),
        )?;

    transaction.output.push(TxOut {
        value: Amount::from_sat(utxo_value),
        script_pubkey: ScriptBuf::from_bytes(get_account_script_pubkey(account.key).to_vec()),
    });

    Ok(utxo_value)
}
