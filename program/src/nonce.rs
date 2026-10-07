//! Durable transaction nonces.
//!
//! A nonce account is a system-program-owned account holding a [`State`]. A
//! transaction whose first instruction is
//! [`SystemInstruction::AdvanceNonceAccount`](crate::system_instruction::SystemInstruction::AdvanceNonceAccount)
//! on a writable nonce account is a *durable-nonce transaction*
//! (see [`durable_nonce_account_index`]):
//! its `recent_blockhash` must equal the nonce stored in that account instead
//! of a recent block hash, so it stays valid until the nonce is advanced.
//! Executing it advances the nonce, which makes the transaction unreplayable;
//! the advance is committed even when a later instruction fails.

use crate::hash::Hash;
use crate::hashing_functions::sha256;
use crate::pubkey::Pubkey;
use crate::sanitized::ArchMessage;
use crate::system_program;
use thiserror::Error;

/// Account data length of a nonce account: the wincode encoding of
/// [`State::Initialized`].
pub const NONCE_ACCOUNT_LENGTH: usize = 68;

const DURABLE_NONCE_HASH_PREFIX: &[u8] = b"DURABLE_NONCE";

/// Wincode encoding of `SystemInstruction::AdvanceNonceAccount`: its `u32`
/// variant tag. The system program decodes instruction data with
/// `wincode::deserialize`, which ignores trailing bytes, so any data starting
/// with these bytes executes as an advance.
const ADVANCE_NONCE_ACCOUNT_DATA: [u8; 4] = 9u32.to_le_bytes();

/// The nonce value an advance stores while `blockhash` is the latest block
/// hash. Domain-separated so a nonce value never equals a block hash.
pub fn durable_nonce_from_blockhash(blockhash: &Hash) -> Hash {
    let mut preimage = [0u8; DURABLE_NONCE_HASH_PREFIX.len() + 32];
    preimage[..DURABLE_NONCE_HASH_PREFIX.len()].copy_from_slice(DURABLE_NONCE_HASH_PREFIX);
    preimage[DURABLE_NONCE_HASH_PREFIX.len()..].copy_from_slice(blockhash.as_ref());
    Hash::from(sha256(&preimage).to_bytes())
}

/// Contents of an initialized nonce account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, wincode::SchemaWrite, wincode::SchemaRead)]
pub struct Data {
    /// Signer required to advance, withdraw from, or re-authorize the account.
    pub authority: Pubkey,
    /// Value a durable-nonce transaction must use as its `recent_blockhash`.
    pub durable_nonce: Hash,
}

/// Nonce account state, wincode-encoded into the account data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, wincode::SchemaWrite, wincode::SchemaRead)]
pub enum State {
    Uninitialized,
    Initialized(Data),
}

/// Why a durable-nonce transaction cannot execute against its nonce account.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum NonceError {
    #[error("nonce account is not an initialized system-owned nonce account")]
    InvalidNonceAccount,
    #[error("nonce authority must sign the AdvanceNonceAccount instruction")]
    AuthorityNotSigner,
    #[error("recent blockhash does not match the stored nonce")]
    NonceMismatch,
    #[error("nonce was already advanced in this block")]
    NonceAlreadyAdvanced,
}

/// Returns the message account index of the nonce account when `message` is
/// a durable-nonce transaction: its first instruction is a system-program
/// `AdvanceNonceAccount` whose first account is a writable message account.
///
/// Any other transaction, including one whose first `AdvanceNonceAccount`
/// names no writable account, is a regular recent-blockhash transaction: the
/// system program fails that instruction after the fee is paid.
pub fn durable_nonce_account_index(message: &ArchMessage) -> Option<usize> {
    let instruction = message.instructions.first()?;
    let is_advance = message
        .account_keys
        .get(usize::from(instruction.program_id_index))
        .is_some_and(system_program::check_id)
        && instruction.data.starts_with(&ADVANCE_NONCE_ACCOUNT_DATA);
    if !is_advance {
        return None;
    }
    instruction
        .accounts
        .first()
        .map(|&index| usize::from(index))
        .filter(|&index| index < message.account_keys.len() && message.is_writable_index(index))
}

/// Checks that a nonce account (`owner`, `data`) authorizes `message`, a
/// durable-nonce transaction: it is an initialized system-owned nonce account
/// of [`NONCE_ACCOUNT_LENGTH`] bytes storing `message.recent_blockhash`, and
/// its authority is a signer account of the first (`AdvanceNonceAccount`)
/// instruction. These are the conditions under which the system program can
/// advance it.
pub fn verify_nonce_account(
    message: &ArchMessage,
    owner: &Pubkey,
    data: &[u8],
) -> Result<Data, NonceError> {
    if !system_program::check_id(owner) || data.len() != NONCE_ACCOUNT_LENGTH {
        return Err(NonceError::InvalidNonceAccount);
    }
    let Ok(State::Initialized(nonce)) = wincode::deserialize(data) else {
        return Err(NonceError::InvalidNonceAccount);
    };
    if nonce.durable_nonce != message.recent_blockhash {
        return Err(NonceError::NonceMismatch);
    }
    // The system program only counts the instruction's own signer accounts.
    let authority_signed = message.instructions.first().is_some_and(|instruction| {
        instruction.accounts.iter().any(|&index| {
            let index = usize::from(index);
            message.account_keys.get(index) == Some(&nonce.authority) && message.is_signer(index)
        })
    });
    if !authority_signed {
        return Err(NonceError::AuthorityNotSigner);
    }
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitized::{MessageHeader, SanitizedInstruction};
    use crate::system_instruction::SystemInstruction;

    #[test]
    fn initialized_state_fills_nonce_account_length() {
        let state = State::Initialized(Data {
            authority: Pubkey::new_unique(),
            durable_nonce: Hash::from([7; 32]),
        });
        assert_eq!(
            wincode::serialized_size(&state).unwrap() as usize,
            NONCE_ACCOUNT_LENGTH
        );
        // A freshly allocated (zeroed) nonce account reads as uninitialized.
        assert_eq!(
            wincode::deserialize::<State>(&[0; NONCE_ACCOUNT_LENGTH]).unwrap(),
            State::Uninitialized
        );
    }

    #[test]
    fn durable_nonce_never_equals_its_blockhash() {
        let blockhash = Hash::from([3; 32]);
        let nonce = durable_nonce_from_blockhash(&blockhash);
        assert_ne!(nonce, blockhash);
        assert_eq!(nonce, durable_nonce_from_blockhash(&blockhash));
        assert_ne!(nonce, durable_nonce_from_blockhash(&Hash::from([4; 32])));
    }

    /// Keys: 0 payer (signer, writable), 1 authority (signer, read-only),
    /// 2 nonce account (writable), 3 system program (read-only).
    fn message(first_instruction: SanitizedInstruction, recent_blockhash: Hash) -> ArchMessage {
        ArchMessage {
            header: MessageHeader {
                num_required_signatures: 2,
                num_readonly_signed_accounts: 1,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys: vec![
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                Pubkey::new_unique(),
                system_program::ID,
            ],
            recent_blockhash,
            instructions: vec![first_instruction],
        }
    }

    fn advance(accounts: Vec<u8>) -> SanitizedInstruction {
        SanitizedInstruction {
            program_id_index: 3,
            accounts,
            data: wincode::serialize(&SystemInstruction::AdvanceNonceAccount).unwrap(),
        }
    }

    #[test]
    fn classifies_first_instruction() {
        assert_eq!(
            durable_nonce_account_index(&message(advance(vec![2, 1]), Hash::default())),
            Some(2)
        );
        // The system program ignores trailing bytes, so this is an advance too.
        let mut padded = advance(vec![2, 1]);
        padded.data.push(0);
        assert_eq!(
            durable_nonce_account_index(&message(padded, Hash::default())),
            Some(2)
        );

        // Any other first instruction is a regular recent-blockhash transaction.
        let transfer = SanitizedInstruction {
            program_id_index: 3,
            accounts: vec![0, 2],
            data: wincode::serialize(&SystemInstruction::Transfer { lamports: 1 }).unwrap(),
        };
        assert_eq!(
            durable_nonce_account_index(&message(transfer, Hash::default())),
            None
        );

        // The same data sent to another program is not an advance.
        let mut other_program = advance(vec![2, 1]);
        other_program.program_id_index = 2;
        assert_eq!(
            durable_nonce_account_index(&message(other_program, Hash::default())),
            None
        );

        // An advance on a read-only or missing account can never advance a
        // nonce: the transaction is a regular one whose advance fails.
        for accounts in [vec![1, 1], vec![3, 1], vec![]] {
            assert_eq!(
                durable_nonce_account_index(&message(advance(accounts), Hash::default())),
                None
            );
        }
    }

    #[test]
    fn verifies_stored_nonce_and_authority() {
        let nonce_value = Hash::from([9; 32]);
        let message = message(advance(vec![2, 1]), nonce_value);
        let authority = message.account_keys[1];
        let data = |authority, durable_nonce| {
            wincode::serialize(&State::Initialized(Data {
                authority,
                durable_nonce,
            }))
            .unwrap()
        };

        assert_eq!(
            verify_nonce_account(&message, &system_program::ID, &data(authority, nonce_value)),
            Ok(Data {
                authority,
                durable_nonce: nonce_value
            })
        );
        assert_eq!(
            verify_nonce_account(
                &message,
                &system_program::ID,
                &data(authority, Hash::from([8; 32]))
            ),
            Err(NonceError::NonceMismatch)
        );
        // The nonce account (index 2) is in the message but did not sign.
        assert_eq!(
            verify_nonce_account(
                &message,
                &system_program::ID,
                &data(message.account_keys[2], nonce_value)
            ),
            Err(NonceError::AuthorityNotSigner)
        );
        // The authority signed the transaction but is not an account of the
        // advance instruction, so the system program cannot see its signature.
        let mut omitted = message.clone();
        omitted.instructions[0].accounts = vec![2];
        assert_eq!(
            verify_nonce_account(
                &omitted,
                &system_program::ID,
                &data(omitted.account_keys[1], nonce_value)
            ),
            Err(NonceError::AuthorityNotSigner)
        );
        assert_eq!(
            verify_nonce_account(
                &message,
                &Pubkey::new_unique(),
                &data(authority, nonce_value)
            ),
            Err(NonceError::InvalidNonceAccount)
        );
        assert_eq!(
            verify_nonce_account(&message, &system_program::ID, &[0; NONCE_ACCOUNT_LENGTH]),
            Err(NonceError::InvalidNonceAccount)
        );
        // The system program only advances accounts of exactly this length.
        let mut oversized = data(authority, nonce_value);
        oversized.push(0);
        assert_eq!(
            verify_nonce_account(&message, &system_program::ID, &oversized),
            Err(NonceError::InvalidNonceAccount)
        );
    }
}
