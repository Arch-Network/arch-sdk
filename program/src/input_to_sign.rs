//! Input requiring signature.
//!
//! `InputToSign` represents a transaction input
//! that needs a signature from a specific key.
#[cfg(feature = "fuzzing")]
use libfuzzer_sys::arbitrary;

use crate::{program_error::ProgramError, pubkey::Pubkey};

/// Represents a transaction input that needs to be signed.
///
/// An `InputToSign` contains the index of the input within a transaction
/// and the public key of the signer that should sign this input.
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]

pub enum InputToSign<'a> {
    Sign {
        index: u32,
        signer: Pubkey,
    },
    SignWithSeeds {
        index: u32,
        program_id: Pubkey,
        signers_seeds: &'a [&'a [u8]],
    },
}

impl InputToSign<'_> {
    pub fn get_signer(&self) -> Result<Pubkey, ProgramError> {
        let signer = match self {
            InputToSign::Sign { signer, .. } => *signer,
            InputToSign::SignWithSeeds {
                signers_seeds,
                program_id,
                ..
            } => Pubkey::create_program_address(signers_seeds, program_id)?,
        };

        Ok(signer)
    }

    pub fn get_index(&self) -> u32 {
        match self {
            InputToSign::Sign { index, .. } => *index,
            InputToSign::SignWithSeeds { index, .. } => *index,
        }
    }
}
