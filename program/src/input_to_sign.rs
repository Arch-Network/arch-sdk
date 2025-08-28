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

pub struct InputToSign {
    pub index: u32,
    pub signer: Pubkey,
}

impl InputToSign {
    pub fn from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        fn get_const_slice<const N: usize>(
            data: &[u8],
            offset: usize,
        ) -> Result<[u8; N], ProgramError> {
            let end = offset + N;
            let slice = data
                .get(offset..end)
                .ok_or(ProgramError::InsufficientDataLength)?;
            let array_ref = slice
                .try_into()
                .map_err(|_| ProgramError::IncorrectLength)?;
            Ok(array_ref)
        }

        let mut offset = 0;

        let index = u32::from_le_bytes(get_const_slice(data, offset)?);
        offset += 4;

        let signer = Pubkey(get_const_slice(data, offset)?);

        Ok(InputToSign { index, signer })
    }

    pub fn serialise(&self) -> Vec<u8> {
        let mut serialized = vec![];
        serialized.extend_from_slice(&self.index.to_le_bytes());
        serialized.extend_from_slice(&self.signer.serialize());

        serialized
    }
}
