use std::{
    array::TryFromSliceError,
    fmt::{Display, Formatter},
};

use arch_program::sanitize::{Sanitize, SanitizeError};
use arch_program::sanitized::ArchMessage;
use bitcode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "fuzzing")]
use libfuzzer_sys::arbitrary;
use serde::{Deserialize, Serialize};
use sha256::digest;

use super::Signature;

pub const RUNTIME_TX_SIZE_LIMIT: usize = 10240;

/// Allowed versions for RuntimeTransaction
pub const ALLOWED_VERSIONS: [u32; 1] = [0];

#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum RuntimeTransactionError {
    #[error("runtime transaction size exceeds limit: {0} > {1}")]
    RuntimeTransactionSizeExceedsLimit(usize, usize),

    #[error("failed to deserialize runtime transaction : {0}")]
    TryFromSliceError(String),

    #[error("sanitize error: {0}")]
    SanitizeError(#[from] SanitizeError),

    #[error("invalid recent blockhash")]
    InvalidRecentBlockhash,
}

impl From<TryFromSliceError> for RuntimeTransactionError {
    fn from(e: TryFromSliceError) -> Self {
        RuntimeTransactionError::TryFromSliceError(e.to_string())
    }
}

// type Result<T> = std::result::Result<T, RuntimeTransactionError>;

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Encode,
    Decode,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]

pub struct RuntimeTransaction {
    pub version: u32,
    pub signatures: Vec<Signature>,
    pub message: ArchMessage,
}

impl Sanitize for RuntimeTransaction {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        // Check if version is allowed
        if !ALLOWED_VERSIONS.contains(&self.version) {
            return Err(SanitizeError::InvalidVersion);
        }

        // Check if number of signatures matches required signers
        if self.signatures.len() != self.message.header().num_required_signatures as usize {
            return Err(SanitizeError::SignatureCountMismatch {
                expected: self.message.header().num_required_signatures as usize,
                actual: self.signatures.len(),
            });
        }
        // Continue with message sanitization
        self.message.sanitize()
    }
}

impl Display for RuntimeTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RuntimeTransaction {{ version: {}, signatures: {}, message: {:?} }}",
            self.version,
            self.signatures.len(),
            self.message
        )
    }
}

impl RuntimeTransaction {
    pub fn txid(&self) -> String {
        digest(digest(self.serialize()))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut serilized = vec![];

        serilized.extend(self.version.to_le_bytes());
        serilized.push(self.signatures.len() as u8);
        for signature in self.signatures.iter() {
            serilized.extend(&signature.serialize());
        }
        serilized.extend(self.message.serialize());

        serilized
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, RuntimeTransactionError> {
        let mut cursor: usize = 0;
        let version_size = size_of::<u32>();
        if data.len() < version_size {
            return Err(RuntimeTransactionError::TryFromSliceError(
                "Insufficient bytes for version".to_string(),
            ));
        }
        let version = u32::from_le_bytes(data[..version_size].try_into()?);
        cursor += version_size;

        if data.len() < cursor + size_of::<u8>() {
            return Err(RuntimeTransactionError::TryFromSliceError(
                "Insufficient bytes for signatures length".to_string(),
            ));
        }

        let signatures_len = data[cursor] as usize;
        cursor += size_of::<u8>();

        let signature_size = 64;

        let mut signatures = Vec::with_capacity(signatures_len);

        for _ in 0..signatures_len {
            if data.len() < cursor + signature_size {
                return Err(RuntimeTransactionError::TryFromSliceError(
                    "Insufficient bytes for signatures".to_string(),
                ));
            }
            signatures.push(Signature::from_slice(
                &data[cursor..(cursor + signature_size)],
            ));
            cursor += signature_size;
        }

        let message = ArchMessage::deserialize(&data[cursor..])
            .map_err(|e| RuntimeTransactionError::TryFromSliceError(e.to_string()))?;

        Ok(Self {
            version,
            signatures,
            message,
        })
    }

    pub fn hash(&self) -> String {
        digest(digest(self.serialize()))
    }

    pub fn check_tx_size_limit(&self) -> Result<(), RuntimeTransactionError> {
        let serialized_tx = self.serialize();
        if serialized_tx.len() > RUNTIME_TX_SIZE_LIMIT {
            Err(RuntimeTransactionError::RuntimeTransactionSizeExceedsLimit(
                serialized_tx.len(),
                RUNTIME_TX_SIZE_LIMIT,
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeTransaction, Signature, ALLOWED_VERSIONS};
    use arch_program::{
        pubkey::Pubkey,
        sanitize::{Sanitize as _, SanitizeError},
        sanitized::{ArchMessage, MessageHeader, SanitizedInstruction},
    };

    fn create_test_transaction(
        version: u32,
        num_signatures: usize,
        num_accounts: usize,
    ) -> RuntimeTransaction {
        RuntimeTransaction {
            version,
            signatures: vec![Signature::from_slice(&[1; 64]); num_signatures],
            message: ArchMessage {
                header: MessageHeader {
                    num_required_signatures: 2,
                    num_readonly_signed_accounts: 1,
                    num_readonly_unsigned_accounts: 1,
                },
                account_keys: (0..num_accounts).map(|_| Pubkey::new_unique()).collect(),
                recent_blockhash: hex::encode([0; 32]),
                instructions: vec![SanitizedInstruction {
                    program_id_index: 2,
                    accounts: vec![0, 1, 3],
                    data: vec![1, 2, 3],
                }],
            },
        }
    }

    #[test]
    fn test_all_allowed_versions_are_valid() {
        for &version in ALLOWED_VERSIONS.iter() {
            let transaction = create_test_transaction(version, 2, 4);
            assert!(
                transaction.sanitize().is_ok(),
                "Version {} should be valid",
                version
            );
        }
    }

    #[test]
    fn test_version_not_in_allowed_versions() {
        // Find a version that's not in ALLOWED_VERSIONS
        let invalid_version = (0..u32::MAX)
            .find(|&v| !ALLOWED_VERSIONS.contains(&v))
            .expect("Should find at least one invalid version");

        let transaction = create_test_transaction(invalid_version, 2, 2);
        assert_eq!(
            transaction.sanitize().unwrap_err(),
            SanitizeError::InvalidVersion,
            "Version {} should be invalid",
            invalid_version
        );
    }
}
