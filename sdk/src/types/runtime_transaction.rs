use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use super::Signature;
use arch_program::sanitized::ArchMessage;
use arch_program::{
    hash::Hash,
    serde_error::{get_const_slice, get_slice, SerialisationErrors},
};
use arch_program::{
    sanitize::{Sanitize, SanitizeError},
    MAX_SIGNERS,
};
use bitcode::{Decode, Encode};
use bitcoin::Network;
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "fuzzing")]
use libfuzzer_sys::arbitrary;
use serde::{Deserialize, Serialize};
use sha256::digest;

use crate::verify_message_bip322;

/// Maximum serialized transaction size, matching Solana's packet payload limit.
pub const RUNTIME_TX_SIZE_LIMIT: usize = 1_232;

/// Allowed versions for RuntimeTransaction
pub const ALLOWED_VERSIONS: [u32; 1] = [0];

pub const MAX_SIGNERS_IN_TRANSACTION: usize = 11;

#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum RuntimeTransactionError {
    #[error("runtime transaction size exceeds limit: {0} > {1}")]
    RuntimeTransactionSizeExceedsLimit(usize, usize),

    #[error("insufficient bytes for message")]
    InsufficientBytesForMessage,

    #[error("sanitize error: {0}")]
    SanitizeError(#[from] SanitizeError),

    #[error("invalid recent blockhash")]
    InvalidRecentBlockhash,

    #[error("too many signatures: allowed {0}, found {1}")]
    TooManySignatures(usize, usize),

    #[error("SerialisationError: {0}")]
    SerialisationError(#[from] SerialisationErrors),

    #[error("MAX Signature Limit crossed; allowed {allowed} found {found}")]
    MaxSignatureLimitCrossed { allowed: usize, found: usize },

    #[error("BIP322 signature verification failed: {0}")]
    BIP322SignatureVerificationFailed(String),

    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

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
    Hash,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct RuntimeTransaction {
    pub version: u32,
    pub signatures: Vec<Signature>,
    pub message: ArchMessage,
}
/// A runtime transaction whose structural invariants have been checked.
///
/// The inner transaction is only exposed immutably so sanitization remains
/// valid for the lifetime of this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SanitizedRuntimeTransaction(RuntimeTransaction);

impl SanitizedRuntimeTransaction {
    pub fn into_inner(self) -> RuntimeTransaction {
        self.0
    }

    pub fn inner(&self) -> &RuntimeTransaction {
        &self.0
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, RuntimeTransactionError> {
        self.inner().serialize_with_size_limit()
    }

    /// Restores a transaction with structural checks only.
    ///
    /// Authenticate with [`RuntimeTransaction::verify_sigs`] before execution.
    pub fn from_vec(data: &[u8]) -> Result<Self, RuntimeTransactionError> {
        let transaction = RuntimeTransaction::from_slice(data)?;
        transaction.sanitize()?;
        Ok(Self(transaction))
    }
}

impl TryFrom<(RuntimeTransaction, Network)> for SanitizedRuntimeTransaction {
    type Error = RuntimeTransactionError;

    fn try_from(
        (transaction, network): (RuntimeTransaction, Network),
    ) -> Result<Self, Self::Error> {
        transaction.verify_sigs(network)?;
        Ok(Self(transaction))
    }
}

impl Sanitize for RuntimeTransaction {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        // Size check
        self.check_tx_size_limit().map_err(|err| match err {
            RuntimeTransactionError::RuntimeTransactionSizeExceedsLimit(serialized_len, limit) => {
                SanitizeError::InvalidSize {
                    serialized_len,
                    limit,
                }
            }
            _ => SanitizeError::InvalidValue,
        })?;

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
    pub fn txid(&self) -> Hash {
        self.hash()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let capacity = 4 + 1 + (self.signatures.len() * 64) + 256;
        let mut serilized = Vec::with_capacity(capacity);

        serilized.extend(self.version.to_le_bytes());
        serilized.push(self.signatures.len() as u8);
        for signature in self.signatures.iter() {
            serilized.extend(&signature.0);
        }
        serilized.extend(self.message.serialize());

        serilized
    }

    pub fn serialize_with_size_limit(&self) -> Result<Vec<u8>, RuntimeTransactionError> {
        let serialized = self.serialize();
        if serialized.len() > RUNTIME_TX_SIZE_LIMIT {
            Err(RuntimeTransactionError::RuntimeTransactionSizeExceedsLimit(
                serialized.len(),
                RUNTIME_TX_SIZE_LIMIT,
            ))
        } else {
            Ok(serialized)
        }
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, RuntimeTransactionError> {
        let mut cursor: usize = 0;

        // Read version
        const VERSION_SIZE: usize = 4;
        let version_bytes = get_const_slice::<VERSION_SIZE>(data, cursor)?;
        let version = u32::from_le_bytes(version_bytes);
        cursor += VERSION_SIZE;

        // Read signatures length
        const SIG_LEN_SIZE: usize = 1;
        let signatures_len_byte = get_const_slice::<SIG_LEN_SIZE>(data, cursor)?;
        let signatures_len = signatures_len_byte[0] as usize;
        cursor += SIG_LEN_SIZE;

        if signatures_len > MAX_SIGNERS {
            return Err(RuntimeTransactionError::TooManySignatures(
                MAX_SIGNERS,
                signatures_len,
            ));
        }

        // Read signatures
        const SIGNATURE_SIZE: usize = 64;
        let signatures_data_len = signatures_len
            .checked_mul(SIGNATURE_SIZE)
            .ok_or(SanitizeError::InvalidValue)?;
        let signatures_slice = get_slice(data, cursor, signatures_data_len)?;

        let mut signatures = Vec::with_capacity(signatures_len);
        for sig_bytes in signatures_slice.chunks_exact(SIGNATURE_SIZE) {
            let sig_array = get_const_slice::<SIGNATURE_SIZE>(sig_bytes, 0)?;
            signatures.push(Signature::from(sig_array));
            cursor += SIGNATURE_SIZE;
        }

        // Deserialize the rest of the message from the corrected cursor position
        let message_slice = data
            .get(cursor..)
            .ok_or(RuntimeTransactionError::InsufficientBytesForMessage)?;
        let message = ArchMessage::deserialize(message_slice)?;

        Ok(Self {
            version,
            signatures,
            message,
        })
    }

    pub fn hash(&self) -> Hash {
        let hash_string = digest(digest(self.serialize()));
        Hash::from_str(&hash_string).expect("SHA256 always produces valid hex")
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

    /// Validates the transaction and authenticates the canonical signer prefix.
    ///
    /// The signed message header and ordered account keys also determine runtime
    /// signer privileges. Reject noncanonical messages before verifying signatures.
    pub fn verify_sigs(&self, network: Network) -> Result<(), RuntimeTransactionError> {
        self.sanitize()?;
        let required_sigs = self.message.header.num_required_signatures as usize;

        if self.signatures.len() > MAX_SIGNERS_IN_TRANSACTION {
            return Err(RuntimeTransactionError::MaxSignatureLimitCrossed {
                allowed: MAX_SIGNERS_IN_TRANSACTION,
                found: self.signatures.len(),
            });
        }

        // `sanitize` bounds `required_sigs` by the account keys and matches it to
        // the signature count, so the prefix and the zip below are exact.
        let signers = &self.message.account_keys[..required_sigs];
        let digest_slice = self.message.hash();

        for (pubkey, signature) in signers.iter().zip(&self.signatures) {
            verify_message_bip322(
                &digest_slice,
                pubkey.serialize(),
                signature.0,
                false,
                network,
            )
            .or_else(|_| {
                verify_message_bip322(
                    &digest_slice,
                    pubkey.serialize(),
                    signature.0,
                    true,
                    network,
                )
            })
            .map_err(|err| {
                RuntimeTransactionError::BIP322SignatureVerificationFailed(err.to_string())
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeTransaction, RuntimeTransactionError, SanitizedRuntimeTransaction, Signature,
        ALLOWED_VERSIONS, RUNTIME_TX_SIZE_LIMIT,
    };
    use arch_program::hash::Hash;
    use arch_program::system_instruction;
    use arch_program::{
        pubkey::Pubkey,
        sanitize::{Sanitize as _, SanitizeError},
        sanitized::{ArchMessage, MessageHeader, SanitizedInstruction},
    };
    use bitcoin::{
        key::Keypair,
        secp256k1::{Secp256k1, SecretKey},
        Network,
    };

    use crate::{build_and_sign_transaction, sign_message_bip322};

    fn authorization_keypair(seed: u8) -> Keypair {
        Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[seed; 32]).unwrap(),
        )
    }

    fn authorization_transfer() -> (RuntimeTransaction, Keypair, Keypair) {
        let payer = authorization_keypair(1);
        let owner = authorization_keypair(2);
        let payer_key = Pubkey(payer.x_only_public_key().0.serialize());
        let owner_key = Pubkey(owner.x_only_public_key().0.serialize());
        let instruction = system_instruction::transfer(&owner_key, &payer_key, 1);
        let message = ArchMessage::new(&[instruction], Some(payer_key), Hash::from([9; 32]));
        let transaction =
            build_and_sign_transaction(message, vec![owner, payer], Network::Regtest).unwrap();
        (transaction, payer, owner)
    }

    #[test]
    fn transaction_authorization_rejects_duplicate_signer_keys() {
        let (mut transaction, payer, _) = authorization_transfer();
        transaction.message.account_keys[1] = transaction.message.account_keys[0];
        let signature =
            sign_message_bip322(&payer, &transaction.message.hash(), Network::Regtest).unwrap();
        transaction.signatures = vec![Signature(signature); 2];

        assert_eq!(
            transaction.verify_sigs(Network::Regtest),
            Err(RuntimeTransactionError::SanitizeError(
                SanitizeError::DuplicateAccount
            ))
        );
    }

    #[test]
    fn transaction_authorization_rejects_unsigned_fee_payer() {
        let (mut transaction, _, _) = authorization_transfer();
        transaction.message.header.num_required_signatures = 0;
        transaction.signatures.clear();

        assert_eq!(
            transaction.verify_sigs(Network::Regtest),
            Err(RuntimeTransactionError::SanitizeError(
                SanitizeError::IndexOutOfBounds
            ))
        );
    }

    #[test]
    fn transaction_authorization_rejects_malformed_signer_header() {
        let (mut transaction, payer, owner) = authorization_transfer();
        transaction.message.header.num_readonly_signed_accounts = 3;
        transaction =
            build_and_sign_transaction(transaction.message, vec![payer, owner], Network::Regtest)
                .unwrap();

        assert_eq!(
            transaction.verify_sigs(Network::Regtest),
            Err(RuntimeTransactionError::SanitizeError(
                SanitizeError::IndexOutOfBounds
            ))
        );
    }

    #[test]
    fn transaction_authorization_requires_the_transfer_owners_signature() {
        let (mut transaction, payer, _) = authorization_transfer();
        SanitizedRuntimeTransaction::try_from((transaction.clone(), Network::Regtest)).unwrap();

        // Preserve the correct count while substituting the attacker's valid signature
        // for the victim's signature. Signing the instruction is not owner consent.
        let signature =
            sign_message_bip322(&payer, &transaction.message.hash(), Network::Regtest).unwrap();
        transaction.signatures = vec![Signature(signature); 2];

        assert!(matches!(
            transaction.verify_sigs(Network::Regtest),
            Err(RuntimeTransactionError::BIP322SignatureVerificationFailed(
                _
            ))
        ));
        assert!(matches!(
            SanitizedRuntimeTransaction::try_from((transaction, Network::Regtest)),
            Err(RuntimeTransactionError::BIP322SignatureVerificationFailed(
                _
            ))
        ));
    }

    #[test]
    fn transaction_authorization_rejects_missing_extra_and_reordered_signatures() {
        let (transaction, _, _) = authorization_transfer();
        for count in [0, 1, 3] {
            let mut malformed = transaction.clone();
            malformed
                .signatures
                .resize(count, transaction.signatures[0].clone());
            assert!(malformed.verify_sigs(Network::Regtest).is_err());
            assert!(SanitizedRuntimeTransaction::try_from((malformed, Network::Regtest)).is_err());
        }

        let mut reordered = transaction.clone();
        reordered.signatures.swap(0, 1);
        assert!(matches!(
            reordered.verify_sigs(Network::Regtest),
            Err(RuntimeTransactionError::BIP322SignatureVerificationFailed(
                _
            ))
        ));

        let mut missing_key = transaction;
        missing_key.message.account_keys.truncate(1);
        assert!(missing_key.verify_sigs(Network::Regtest).is_err());
    }

    fn create_test_transaction(
        version: u32,
        num_signatures: usize,
        num_accounts: usize,
    ) -> RuntimeTransaction {
        RuntimeTransaction {
            version,
            signatures: vec![Signature::from([1; 64]); num_signatures],
            message: ArchMessage {
                header: MessageHeader {
                    num_required_signatures: 2,
                    num_readonly_signed_accounts: 1,
                    num_readonly_unsigned_accounts: 1,
                },
                account_keys: (0..num_accounts).map(|_| Pubkey::new_unique()).collect(),
                recent_blockhash: Hash::from([0; 32]),
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

    #[test]
    fn test_serde_roundtrip() {
        let original_transaction = create_test_transaction(0, 2, 4);

        // Serialize the transaction.
        let serialized_data = original_transaction.serialize();

        // Deserialize the data back into a transaction.
        let deserialized_transaction =
            RuntimeTransaction::from_slice(&serialized_data).expect("Deserialization failed");

        // The deserialized transaction must be identical to the original.
        assert_eq!(original_transaction, deserialized_transaction);
    }

    #[test]
    fn test_transaction_size_limit_boundary() {
        let mut transaction = create_test_transaction(0, 2, 4);
        let instruction_data_len = transaction.message.instructions[0].data.len();
        let fixed_serialized_len = transaction.serialize().len() - instruction_data_len;
        transaction.message.instructions[0].data =
            vec![0; RUNTIME_TX_SIZE_LIMIT - fixed_serialized_len];

        assert_eq!(transaction.serialize().len(), RUNTIME_TX_SIZE_LIMIT);
        assert!(transaction.serialize_with_size_limit().is_ok());

        transaction.message.instructions[0].data.push(0);
        assert_eq!(
            transaction.check_tx_size_limit(),
            Err(RuntimeTransactionError::RuntimeTransactionSizeExceedsLimit(
                RUNTIME_TX_SIZE_LIMIT + 1,
                RUNTIME_TX_SIZE_LIMIT,
            ))
        );
    }

    #[test]
    fn test_from_slice_insufficient_data() {
        let original_transaction = create_test_transaction(0, 2, 4);
        let serialized_data = original_transaction.serialize();

        // Test with data that is too short.
        for i in 0..serialized_data.len() {
            let truncated_data = &serialized_data[..i];
            assert!(
                RuntimeTransaction::from_slice(truncated_data).is_err(),
                "Deserialization should fail for truncated data of length {}",
                i
            );
        }
    }
}
