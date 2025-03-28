use std::{
    array::TryFromSliceError,
    fmt::{Display, Formatter},
    string::FromUtf8Error,
};

use arch_program::message::Message;
use bitcode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha256::digest;
use thiserror::Error;

use super::Signature;

pub const RUNTIME_TX_SIZE_LIMIT: usize = 10240;

#[derive(Debug, Error, Clone, PartialEq)]
pub enum RuntimeTransactionError {
    #[error("runtime transaction size exceeds limit: {0} > {1}")]
    RuntimeTransactionSizeExceedsLimit(usize, usize),

    #[error("try from slice error")]
    TryFromSliceError,

    #[error("from utf8 error: {0}")]
    FromUtf8Error(#[from] FromUtf8Error),
}

impl From<TryFromSliceError> for RuntimeTransactionError {
    fn from(_e: TryFromSliceError) -> Self {
        RuntimeTransactionError::TryFromSliceError
    }
}

pub type Result<T> = std::result::Result<T, RuntimeTransactionError>;

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
pub struct RuntimeTransaction {
    pub message: Message,
    pub block_hash: String,
    pub version: u32,
}

impl Default for RuntimeTransaction {
    fn default() -> Self {
        Self {
            message: Message::from_slice(&[]),
            block_hash: String::new(),
            version: 0,
        }
    }
}

impl Display for RuntimeTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RuntimeTransaction {{ version: {}, block_hash: {}, message: {:?} }}",
            self.version, self.block_hash, self.message
        )
    }
}

impl RuntimeTransaction {
    pub fn txid(&self) -> String {
        digest(digest(self.serialize()))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut serilized = vec![];

        serilized.push(self.version as u8);
        serilized.push(self.block_hash.len() as u8);
        serilized.extend(self.block_hash.as_bytes());
        serilized.extend(self.message.serialize());

        serilized
    }

    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let mut size = 1;
        let block_hash_len = data[size] as usize;
        size += 1;
        let block_hash = String::from_utf8(data[size..(size + block_hash_len)].to_vec())?;
        size += block_hash_len;
        let message = Message::from_slice(&data[size..]);

        Ok(Self {
            version: data[0] as u32,
            block_hash,
            message,
        })
    }

    pub fn hash(&self) -> String {
        digest(digest(self.serialize()))
    }

    pub fn check_tx_size_limit(&self) -> Result<()> {
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
    use super::RuntimeTransaction;
    use super::Signature;
    use arch_program::instruction::Instruction;
    use arch_program::message::Message;
    use arch_program::pubkey::Pubkey;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_serialize_deserialize_runtime_transaction(
            version in any::<u8>(),
            signatures in prop::collection::vec(prop::collection::vec(any::<u8>(), 64), 0..10),
            signers in prop::collection::vec(any::<[u8; 32]>(), 0..10),
            instructions in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..100), 0..10)
        ) {
            let signatures: Vec<Signature> = signatures.into_iter()
                .map(|sig_bytes| Signature::from_slice(&sig_bytes))
                .collect();

            let signers: Vec<Pubkey> = signers.into_iter()
                .map(Pubkey::from)
                .collect();

            let instructions: Vec<Instruction> = instructions.into_iter()
                .map(|data| Instruction {
                    program_id: Pubkey::system_program(),
                    accounts: vec![],
                    data,
                })
                .collect();

            let message = Message {
                signers,
                instructions,
            };

            let transaction = RuntimeTransaction {
                version: version.into(),
                block_hash: String::new(),
                message,
            };

            let serialized = transaction.serialize();
            let deserialized = RuntimeTransaction::from_slice(&serialized).unwrap();
            assert_eq!(transaction, deserialized);
        }
    }
}
