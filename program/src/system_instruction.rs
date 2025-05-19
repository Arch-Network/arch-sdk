use crate::account::AccountMeta;
use crate::instruction::Instruction;
use crate::pubkey::Pubkey;
use crate::utxo::UtxoMeta;

/// Creates a new account instruction linked to a specific UTXO.
///
/// This instruction will create a new account in the system identified by the given
/// transaction ID and output index (txid, vout).
///
/// # Parameters
/// * `txid` - The transaction ID as a 32-byte array
/// * `vout` - The output index
/// * `pubkey` - The public key that will own the new account
///
/// # Returns
/// * `Instruction` - The system instruction to create the account
pub fn create_account(txid: [u8; 32], vout: u32, pubkey: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::system_program(),
        accounts: vec![AccountMeta {
            pubkey,
            is_signer: true,
            is_writable: true,
        }],
        data: [&[0][..], &UtxoMeta::from(txid, vout).serialize()].concat(),
    }
}

/// Writes data to an account at the specified offset.
///
/// This instruction allows writing a byte array to an existing account's data,
/// starting at the given offset.
///
/// # Parameters
/// * `offset` - The starting offset in the account's data (in bytes)
/// * `len` - The length of data to write
/// * `data` - The byte array to write to the account
/// * `pubkey` - The public key of the account to modify
///
/// # Returns
/// * `Instruction` - The system instruction to write data to the account
pub fn write_bytes(offset: u32, len: u32, data: Vec<u8>, pubkey: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::system_program(),
        accounts: vec![AccountMeta {
            pubkey,
            is_signer: true,
            is_writable: true,
        }],
        data: [
            &[1][..],
            offset.to_le_bytes().as_slice(),
            len.to_le_bytes().as_slice(),
            data.as_slice(),
        ]
        .concat(),
    }
}

/// Deploys an executable program from the account's data.
///
/// This instruction marks an existing account as executable, making its data
/// available to be executed as a program.
///
/// # Parameters
/// * `pubkey` - The public key of the account to deploy
///
/// # Returns
/// * `Instruction` - The system instruction to deploy the program
pub fn deploy(pubkey: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::system_program(),
        accounts: vec![AccountMeta {
            pubkey,
            is_signer: true,
            is_writable: true,
        }],
        data: vec![2],
    }
}

/// Assigns a new owner to an account.
///
/// This instruction changes the owner of an account, which determines
/// which program has authority to modify the account.
///
/// # Parameters
/// * `pubkey` - The public key of the account to be reassigned
/// * `owner` - The public key of the new owner (program)
///
/// # Returns
/// * `Instruction` - The system instruction to assign a new owner
pub fn assign(pubkey: Pubkey, owner: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::system_program(),
        accounts: vec![AccountMeta {
            pubkey,
            is_signer: true,
            is_writable: true,
        }],
        data: [&[3][..], owner.serialize().as_slice()].concat(),
    }
}

/// Retracts an account's executable status.
///
/// This instruction marks a previously executable account as non-executable,
/// preventing its data from being executed as a program.
///
/// # Parameters
/// * `pubkey` - The public key of the account to retract
///
/// # Returns
/// * `Instruction` - The system instruction to retract the account
pub fn retract(pubkey: Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::system_program(),
        accounts: vec![AccountMeta {
            pubkey,
            is_signer: true,
            is_writable: true,
        }],
        data: vec![4],
    }
}

/// Resizes an account to a new byte size.
///
/// This instruction changes the size of an account's data storage,
/// either increasing or decreasing it to the specified size.
///
/// # Parameters
/// * `pubkey` - The public key of the account to resize
/// * `new_size` - The new size of the account in bytes
///
/// # Returns
/// * `Instruction` - The system instruction to truncate the account
pub fn truncate(pubkey: Pubkey, new_size: u32) -> Instruction {
    Instruction {
        program_id: Pubkey::system_program(),
        accounts: vec![AccountMeta {
            pubkey,
            is_signer: true,
            is_writable: true,
        }],
        data: [&[5][..], new_size.to_le_bytes().as_slice()].concat(),
    }
}
