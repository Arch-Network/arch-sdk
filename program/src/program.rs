use bitcoin::Transaction;

use crate::instruction::Instruction;
use crate::program_error::ProgramError;
#[cfg(target_os = "solana")]
use crate::stable_layout::stable_ins::StableInstruction;
use crate::MAX_BTC_TX_SIZE;

use crate::clock::Clock;
use crate::transaction_to_sign::TransactionToSign;
use crate::utxo::UtxoMeta;
use crate::{account::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

/// Invokes a program instruction through cross-program invocation.
///
/// This function processes the provided instruction by dispatching control to another program
/// using the account information provided.
///
/// # Arguments
/// * `instruction` - The instruction to process
/// * `account_infos` - The accounts required to process the instruction
///
/// # Returns
/// * `ProgramResult` - Ok(()) if successful, or an error if the operation fails
pub fn invoke(instruction: &Instruction, account_infos: &[AccountInfo]) -> ProgramResult {
    invoke_signed(instruction, account_infos, &[])
}

/// Invokes a program instruction without checking account permissions.
///
/// Similar to `invoke`, but skips the account permission checking step.
/// This is generally less safe than `invoke` and should be used carefully.
///
/// # Arguments
/// * `instruction` - The instruction to process
/// * `account_infos` - The accounts required to process the instruction
///
/// # Returns
/// * `ProgramResult` - Ok(()) if successful, or an error if the operation fails
pub fn invoke_unchecked(instruction: &Instruction, account_infos: &[AccountInfo]) -> ProgramResult {
    invoke_signed_unchecked(instruction, account_infos, &[])
}

/// Invokes a program instruction with additional signing authority.
///
/// This function processes the provided instruction by dispatching control to another program,
/// while also providing program-derived address signing authority.
/// It performs permission checks on the accounts before invoking.
///
/// # Arguments
/// * `instruction` - The instruction to process
/// * `account_infos` - The accounts required to process the instruction
/// * `signers_seeds` - Seeds used to sign the transaction as a program-derived address
///
/// # Returns
/// * `ProgramResult` - Ok(()) if successful, or an error if the operation fails
///
/// # Errors
/// Returns an error if any required account cannot be borrowed according to its stated permissions
pub fn invoke_signed(
    instruction: &Instruction,
    account_infos: &[AccountInfo],
    signers_seeds: &[&[&[u8]]],
) -> ProgramResult {
    // Check that the account RefCells are consistent with the request
    for account_meta in instruction.accounts.iter() {
        for account_info in account_infos.iter() {
            if account_meta.pubkey == *account_info.key {
                if account_meta.is_writable {
                    let _ = account_info.try_borrow_mut_data()?;
                } else {
                    let _ = account_info.try_borrow_data()?;
                }
                break;
            }
        }
    }

    invoke_signed_unchecked(instruction, account_infos, signers_seeds)
}

/// Invokes a program instruction with additional signing authority without checking account permissions.
///
/// Similar to `invoke_signed`, but skips the account permission checking step.
/// This is generally less safe than `invoke_signed` and should be used carefully.
///
/// # Arguments
/// * `instruction` - The instruction to process
/// * `account_infos` - The accounts required to process the instruction
/// * `signers_seeds` - Seeds used to sign the transaction as a program-derived address
///
/// # Returns
/// * `ProgramResult` - Ok(()) if successful, or an error if the operation fails
pub fn invoke_signed_unchecked(
    instruction: &Instruction,
    account_infos: &[AccountInfo],
    signers_seeds: &[&[&[u8]]],
) -> ProgramResult {
    #[cfg(target_os = "solana")]
    {
        let instruction = StableInstruction::from(instruction.clone());
        let result = unsafe {
            crate::syscalls::sol_invoke_signed_rust(
                &instruction as *const _ as *const u8,
                account_infos as *const _ as *const u8,
                account_infos.len() as u64,
                signers_seeds as *const _ as *const u8,
                signers_seeds.len() as u64,
            )
        };
        match result {
            crate::entrypoint::SUCCESS => Ok(()),
            _ => Err(result.into()),
        }
    }

    #[cfg(not(target_os = "solana"))]
    crate::program_stubs::sol_invoke_signed(instruction, account_infos, signers_seeds)
}

/// Gets the next account from an account iterator.
///
/// A utility function that advances the iterator and returns the next `AccountInfo`,
/// or returns a `NotEnoughAccountKeys` error if there are no more accounts.
///
/// # Arguments
/// * `iter` - Mutable reference to an iterator yielding references to `AccountInfo`
///
/// # Returns
/// * `Result<&AccountInfo, ProgramError>` - The next account info or an error if depleted
///
/// # Errors
/// Returns `ProgramError::NotEnoughAccountKeys` if the iterator has no more items
pub fn next_account_info<'a, 'b, I: Iterator<Item = &'a AccountInfo<'b>>>(
    iter: &mut I,
) -> Result<I::Item, ProgramError> {
    iter.next().ok_or(ProgramError::NotEnoughAccountKeys)
}

pub const MAX_TRANSACTION_TO_SIGN: usize = 4 * 1024;

/// Sets an Arch transaction to be signed by the program.
///
/// This function takes a transaction and its associated signing metadata and prepares it
/// for signing through the runtime. It also updates the UTXO metadata for relevant accounts.
///
/// # Arguments
/// * `accounts` - Slice of account information required for the transaction
/// * `transaction_to_sign` - The transaction and metadata needed for signing
///
/// # Returns
/// * `ProgramResult` - Ok(()) if successful, or an error if the operation fails
pub fn set_transaction_to_sign(
    accounts: &[AccountInfo],
    transaction_to_sign: TransactionToSign,
) -> ProgramResult {
    let serialized_transaction_to_sign = &transaction_to_sign.serialise();
    #[cfg(target_os = "solana")]
    let result = unsafe {
        crate::syscalls::arch_set_transaction_to_sign(
            serialized_transaction_to_sign.as_ptr(),
            serialized_transaction_to_sign.len() as u64,
        )
    };
    #[cfg(not(target_os = "solana"))]
    let result = crate::program_stubs::arch_set_transaction_to_sign(
        serialized_transaction_to_sign.as_ptr(),
        serialized_transaction_to_sign.len(),
    );

    match result {
        crate::entrypoint::SUCCESS => {
            let tx: Transaction = bitcoin::consensus::deserialize(transaction_to_sign.tx_bytes)
                .expect("failed to deserialize tx_bytes");
            for input in transaction_to_sign.inputs_to_sign {
                if let Some(account) = accounts.iter().find(|account| *account.key == input.signer)
                {
                    account.set_utxo(&UtxoMeta::from(
                        hex::decode(tx.compute_txid().to_string())
                            .expect("failed to decode_hex")
                            .try_into()
                            .expect("failed to try_into"),
                        input.index,
                    ));
                }
            }
            Ok(())
        }
        _ => Err(result.into()),
    }
}

/// Maximum size that can be set using [`set_return_data`].
pub const MAX_RETURN_DATA: usize = 1024;

/// Set the running program's return data.
///
/// Return data is a dedicated per-transaction buffer for data passed
/// from cross-program invoked programs back to their caller.
///
/// The maximum size of return data is [`MAX_RETURN_DATA`]. Return data is
/// retrieved by the caller with [`get_return_data`].
pub fn set_return_data(data: &[u8]) {
    unsafe { crate::syscalls::sol_set_return_data(data.as_ptr(), data.len() as u64) };
}

/// Get the return data from an invoked program.
///
/// For every transaction there is a single buffer with maximum length
/// [`MAX_RETURN_DATA`], paired with a [`Pubkey`] representing the program ID of
/// the program that most recently set the return data. Thus the return data is
/// a global resource and care must be taken to ensure that it represents what
/// is expected: called programs are free to set or not set the return data; and
/// the return data may represent values set by programs multiple calls down the
/// call stack, depending on the circumstances of transaction execution.
///
/// Return data is set by the callee with [`set_return_data`].
///
/// Return data is cleared before every CPI invocation &mdash; a program that
/// has invoked no other programs can expect the return data to be `None`; if no
/// return data was set by the previous CPI invocation, then this function
/// returns `None`.
///
/// Return data is not cleared after returning from CPI invocations &mdash; a
/// program that has called another program may retrieve return data that was
/// not set by the called program, but instead set by a program further down the
/// call stack; or, if a program calls itself recursively, it is possible that
/// the return data was not set by the immediate call to that program, but by a
/// subsequent recursive call to that program. Likewise, an external RPC caller
/// may see return data that was not set by the program it is directly calling,
/// but by a program that program called.
///
/// For more about return data see the [documentation for the return data proposal][rdp].
///
/// [rdp]: https://docs.solanalabs.com/proposals/return-data
pub fn get_return_data() -> Option<(Pubkey, Vec<u8>)> {
    use std::cmp::min;

    let mut buf = [0u8; MAX_RETURN_DATA];
    let mut program_id = Pubkey::default();

    let size = unsafe {
        crate::syscalls::sol_get_return_data(buf.as_mut_ptr(), buf.len() as u64, &mut program_id)
    };

    if size == 0 {
        None
    } else {
        let size = min(size as usize, MAX_RETURN_DATA);
        Some((program_id, buf[..size as usize].to_vec()))
    }
}

/// Retrieves a Bitcoin transaction by its transaction ID.
///
/// # Arguments
/// * `txid` - 32-byte array containing the Bitcoin transaction ID
///
/// # Returns
/// * `Option<Vec<u8>>` - The raw transaction bytes if found, None if not found
pub fn get_bitcoin_tx(txid: [u8; 32]) -> Option<Vec<u8>> {
    use std::cmp::min;
    if txid == [0u8; 32] {
        return None;
    }

    let mut buf = [0u8; MAX_BTC_TX_SIZE];

    #[cfg(target_os = "solana")]
    let size =
        unsafe { crate::syscalls::arch_get_bitcoin_tx(buf.as_mut_ptr(), buf.len() as u64, &txid) };

    #[cfg(not(target_os = "solana"))]
    let size = crate::program_stubs::arch_get_bitcoin_tx(buf.as_mut_ptr(), buf.len(), &txid);

    if size == 0 {
        None
    } else {
        let size = min(size as usize, MAX_BTC_TX_SIZE);
        Some(buf[..size as usize].to_vec())
    }
}

pub fn get_runes_from_output(txid: [u8; 32], output_index: u32) -> Option<Vec<u8>> {
    use std::cmp::min;
    if txid == [0u8; 32] {
        return None;
    }

    let mut buf = [0u8; MAX_BTC_TX_SIZE];

    #[cfg(target_os = "solana")]
    let size = unsafe {
        crate::syscalls::arch_get_runes_from_output(
            buf.as_mut_ptr(),
            buf.len() as u64,
            &txid,
            output_index,
        )
    };

    #[cfg(not(target_os = "solana"))]
    let size = crate::program_stubs::arch_get_runes_from_output(
        buf.as_mut_ptr(),
        buf.len(),
        &txid,
        output_index,
    );

    if size == 0 {
        None
    } else {
        let size = min(size as usize, MAX_BTC_TX_SIZE);
        Some(buf[..size as usize].to_vec())
    }
}

/// Retrieves the network's X-only public key.
///
/// This function fetches the X-only public key associated with the current network configuration.
///
/// # Returns
/// * `[u8; 32]` - The 32-byte X-only public key
pub fn get_network_xonly_pubkey() -> [u8; 32] {
    let mut buf = [0u8; 32];
    let _ = unsafe { crate::syscalls::arch_get_network_xonly_pubkey(buf.as_mut_ptr()) };
    buf
}

/// Validates if a UTXO is owned by the specified public key.
///
/// # Arguments
/// * `utxo` - The UTXO metadata to validate
/// * `owner` - The public key to check ownership against
///
/// # Returns
/// * `bool` - true if the UTXO is owned by the specified public key, false otherwise
pub fn validate_utxo_ownership(utxo: &UtxoMeta, owner: &Pubkey) -> bool {
    #[cfg(target_os = "solana")]
    unsafe {
        crate::syscalls::arch_validate_utxo_ownership(utxo, owner) != 0
    }

    #[cfg(not(target_os = "solana"))]
    {
        crate::program_stubs::arch_validate_utxo_ownership(utxo, owner) != 0
    }
}

/// Gets the script public key for a given account.
///
/// # Arguments
/// * `pubkey` - The public key of the account
///
/// # Returns
/// * `[u8; 34]` - The 34-byte script public key
pub fn get_account_script_pubkey(pubkey: &Pubkey) -> [u8; 34] {
    let mut buf = [0u8; 34];

    #[cfg(target_os = "solana")]
    let _ = unsafe { crate::syscalls::arch_get_account_script_pubkey(buf.as_mut_ptr(), pubkey) };

    #[cfg(not(target_os = "solana"))]
    crate::program_stubs::arch_get_account_script_pubkey(&mut buf, pubkey);
    buf
}

/// Retrieves the current Bitcoin block height from the runtime.
///
/// # Returns
/// * `u64` - The current Bitcoin block height
pub fn get_bitcoin_block_height() -> u64 {
    unsafe { crate::syscalls::arch_get_bitcoin_block_height() }
}

/// Gets the current clock information from the runtime.
///
/// # Returns
/// * `Clock` - The current clock state containing timing information
pub fn get_clock() -> Clock {
    let mut clock = Clock::default();
    unsafe { crate::syscalls::arch_get_clock(&mut clock) };
    clock
}
