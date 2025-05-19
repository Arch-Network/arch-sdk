//! Core account abstractions and management functionality for blockchain accounts, including account information and metadata structures.
use crate::{msg, pubkey::Pubkey, utxo::UtxoMeta};

use bitcode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Account information that is passed to programs during instruction execution.
/// The account's data contains the actual account state managed by programs.
#[derive(Clone)]
#[repr(C)]
pub struct AccountInfo<'a> {
    pub key: &'a Pubkey,
    pub utxo: &'a UtxoMeta, // utxo has this account key in script_pubkey
    pub data: Rc<RefCell<&'a mut [u8]>>,
    pub owner: &'a Pubkey, // owner of an account is always a program
    pub is_signer: bool,
    pub is_writable: bool,
    pub is_executable: bool,
}

/// Meta information about an account used to define its role in an instruction.
/// This includes whether the account is a signer and if it's writable.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Encode,
    Decode,
)]
#[repr(C)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    /// Creates a new `AccountMeta` with the given public key as a writable account.
    ///
    /// # Arguments
    /// * `pubkey` - The account's public key
    /// * `is_signer` - Whether this account is a transaction signer
    pub fn new(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }

    /// Creates a new read-only `AccountMeta` with the given public key.
    ///
    /// # Arguments
    /// * `pubkey` - The account's public key
    /// * `is_signer` - Whether this account is a transaction signer
    pub fn new_readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }

    /// Serializes the AccountMeta into a fixed-size byte array.
    ///
    /// # Returns
    /// A 34-byte array containing the serialized account metadata
    pub fn serialize(&self) -> [u8; 34] {
        let mut serilized = [0; size_of::<Pubkey>() + 2];

        serilized[..size_of::<Pubkey>()].copy_from_slice(&self.pubkey.serialize());
        serilized[size_of::<Pubkey>()] = self.is_signer as u8;
        serilized[size_of::<Pubkey>() + 1] = self.is_writable as u8;

        serilized
    }

    /// Deserializes an AccountMeta from a byte slice.
    ///
    /// # Arguments
    /// * `data` - Byte slice containing serialized account metadata
    ///
    /// # Returns
    /// A new AccountMeta instance
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            pubkey: Pubkey::from_slice(&data[..size_of::<Pubkey>()]),
            is_signer: data[size_of::<Pubkey>()] != 0,
            is_writable: data[size_of::<Pubkey>() + 1] != 0,
        }
    }
}

/// Gets the next AccountInfo from an iterator, or returns a NotEnoughAccountKeys error.
///
/// # Arguments
/// * `iter` - Iterator over AccountInfo references
///
/// # Returns
/// * `Ok(AccountInfo)` - The next account info
/// * `Err(ProgramError)` - If there are no more accounts in the iterator
pub fn next_account_info<'a, 'b, I: Iterator<Item = &'a AccountInfo<'b>>>(
    iter: &mut I,
) -> Result<I::Item, ProgramError> {
    iter.next().ok_or(ProgramError::NotEnoughAccountKeys)
}

use core::fmt;
use std::{
    cell::{Ref, RefCell, RefMut},
    mem::size_of,
    rc::Rc,
    slice::from_raw_parts_mut,
};

use crate::entrypoint::MAX_PERMITTED_DATA_INCREASE;

use crate::debug_account_data::debug_account_data;
use crate::program_error::ProgramError;

impl<'a> fmt::Debug for AccountInfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("AccountInfo");

        f.field("txid", &self.utxo.txid())
            .field("vout", &self.utxo.vout())
            .field("owner", &self.owner)
            .field("data.len", &self.data_len())
            .field("key", &self.key)
            .field("is_signer", &self.is_signer)
            .field("is_writable", &self.is_writable)
            .field("is_executable", &self.is_executable);
        debug_account_data(&self.data.borrow(), &mut f);

        f.finish_non_exhaustive()
    }
}

impl<'a> AccountInfo<'a> {
    /// Creates a new AccountInfo instance.
    ///
    /// # Arguments
    /// * `key` - The account's public key
    /// * `data` - The account's mutable data
    /// * `owner` - The program that owns this account
    /// * `utxo` - The UTXO metadata associated with this account
    /// * `is_signer` - Whether this account is a signer
    /// * `is_writable` - Whether this account is writable
    /// * `is_executable` - Whether this account contains executable code
    pub fn new(
        key: &'a Pubkey,
        data: &'a mut [u8],
        owner: &'a Pubkey,
        utxo: &'a UtxoMeta,
        is_signer: bool,
        is_writable: bool,
        is_executable: bool,
    ) -> Self {
        Self {
            key,
            data: Rc::new(RefCell::new(data)),
            owner,
            utxo,
            is_signer,
            is_writable,
            is_executable,
        }
    }

    /// Returns the length of the account's data.
    ///
    /// # Returns
    /// The length of the account's data in bytes
    pub fn data_len(&self) -> usize {
        self.data.borrow().len()
    }

    /// Immutably borrows the account's data.
    ///
    /// # Returns
    /// * `Ok(Ref<&mut [u8]>)` - A reference to the account's data
    /// * `Err(ProgramError)` - If the data is already mutably borrowed
    pub fn try_borrow_data(&self) -> Result<Ref<&mut [u8]>, ProgramError> {
        self.data
            .try_borrow()
            .map_err(|_| ProgramError::AccountBorrowFailed)
    }

    /// Checks if the account's data is empty.
    ///
    /// # Returns
    /// `true` if the account contains no data, `false` otherwise
    pub fn data_is_empty(&self) -> bool {
        self.data.borrow().is_empty()
    }

    /// Mutably borrows the account's data.
    ///
    /// # Returns
    /// * `Ok(RefMut<&mut [u8]>)` - A mutable reference to the account's data
    /// * `Err(ProgramError)` - If the data is already borrowed
    pub fn try_borrow_mut_data(&self) -> Result<RefMut<&'a mut [u8]>, ProgramError> {
        self.data
            .try_borrow_mut()
            .map_err(|_| ProgramError::AccountBorrowFailed)
    }

    /// Return the utxo's original data length when it was serialized for the
    /// current program invocation.
    ///
    /// # Safety
    ///
    /// This method assumes that the original data length was serialized as a u64
    /// integer in the 1 bytes immediately succeeding is_executable.
    pub unsafe fn original_data_len(&self) -> usize {
        let key_ptr = self.key as *const _ as *const u8;
        let original_data_len_ptr = key_ptr.offset(32) as *const u64;
        *original_data_len_ptr as usize
    }

    /// Realloc the account's data and optionally zero-initialize the new
    /// memory.
    ///
    /// Note:  Account data can be increased within a single call by up to
    /// `solana_program::entrypoint::MAX_PERMITTED_DATA_INCREASE` bytes.
    ///
    /// Note: Memory used to grow is already zero-initialized upon program
    /// entrypoint and re-zeroing it wastes compute units.  If within the same
    /// call a program reallocs from larger to smaller and back to larger again
    /// the new space could contain stale data.  Pass `true` for `zero_init` in
    /// this case, otherwise compute units will be wasted re-zero-initializing.
    ///
    /// # Safety
    ///
    /// This method makes assumptions about the layout and location of memory
    /// referenced by `AccountInfo` fields. It should only be called for
    /// instances of `AccountInfo` that were created by the runtime and received
    /// in the `process_instruction` entrypoint of a program.
    pub fn realloc(&self, new_len: usize, zero_init: bool) -> Result<(), ProgramError> {
        let mut data = self.try_borrow_mut_data()?;
        let old_len = data.len();

        // Return early if length hasn't changed
        if new_len == old_len {
            return Ok(());
        }

        // Return early if the length increase from the original serialized data
        // length is too large and would result in an out of bounds allocation.
        let original_data_len = unsafe { self.original_data_len() };
        msg!(
            "account realloc {} {} {}",
            new_len,
            original_data_len,
            MAX_PERMITTED_DATA_INCREASE
        );
        if new_len.saturating_sub(original_data_len) > MAX_PERMITTED_DATA_INCREASE {
            return Err(ProgramError::InvalidRealloc);
        }

        // realloc
        unsafe {
            let data_ptr = data.as_mut_ptr();

            // First set new length in the serialized data
            *(data_ptr.offset(-8) as *mut u64) = new_len as u64;

            // Then recreate the local slice with the new length
            *data = from_raw_parts_mut(data_ptr, new_len)
        }

        if zero_init {
            let len_increase = new_len.saturating_sub(old_len);
            if len_increase > 0 {
                let data = &mut data[old_len..];
                data.fill(0);
            }
        }

        Ok(())
    }

    /// Sets a new owner for the account.
    ///
    /// # Arguments
    /// * `owner` - The public key of the new owner program
    ///
    /// # Safety
    /// This method uses unsafe operations to modify a non-mutable reference.
    /// It should only be used in contexts where this operation is valid.
    #[rustversion::attr(since(1.72), allow(invalid_reference_casting))]
    pub fn set_owner(&self, owner: &Pubkey) {
        // Set the non-mut owner field
        unsafe {
            std::ptr::write_volatile(
                self.owner as *const Pubkey as *mut [u8; 32],
                owner.serialize(),
            );
        }
    }

    /// Sets a new UTXO for the account.
    ///
    /// # Arguments
    /// * `utxo` - The new UTXO metadata to associate with this account
    ///
    /// # Safety
    /// This method uses unsafe operations to modify a non-mutable reference.
    /// It should only be used in contexts where this operation is valid.
    #[rustversion::attr(since(1.72), allow(invalid_reference_casting))]
    pub fn set_utxo(&self, utxo: &UtxoMeta) {
        // Set the non-mut owner field
        unsafe {
            std::ptr::write_volatile(
                self.utxo as *const UtxoMeta as *mut [u8; 36],
                utxo.serialize(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{account::AccountMeta, pubkey::Pubkey};

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_serialize_deserialize_account_meta(
            pubkey_bytes in any::<[u8; 32]>(),
            is_signer in any::<bool>(),
            is_writable in any::<bool>()
        ) {
            let pubkey = Pubkey::from(pubkey_bytes);
            let account_meta = AccountMeta {
                pubkey,
                is_signer,
                is_writable,
            };

            let serialized = account_meta.serialize();
            let deserialized = AccountMeta::from_slice(&serialized);

            assert_eq!(account_meta, deserialized);
        }
    }
}
