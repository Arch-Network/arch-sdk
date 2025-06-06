use std::{array::TryFromSliceError, string::FromUtf8Error};

use anyhow::Result;
use bitcode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{RuntimeTransaction, RuntimeTransactionError};

#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum ParseProcessedTransactionError {
    #[error("from hex error: {0}")]
    FromHexError(#[from] hex::FromHexError),

    #[error("from utf8 error: {0}")]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error("try from slice error")]
    TryFromSliceError,

    #[error("runtime transaction error: {0}")]
    RuntimeTransactionError(#[from] RuntimeTransactionError),

    #[error("rollback message too long")]
    RollbackMessageTooLong,
}

impl From<TryFromSliceError> for ParseProcessedTransactionError {
    fn from(_e: TryFromSliceError) -> Self {
        ParseProcessedTransactionError::TryFromSliceError
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Encode,
    Decode,
    Eq,
)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", content = "message")]
pub enum Status {
    Queued,
    Processed,
    Failed(String),
}

impl Status {
    pub fn from_value(value: &Value) -> Option<Self> {
        if let Some(status_str) = value.as_str() {
            match status_str {
                "Queued" => return Some(Status::Queued),
                _ => return Some(Status::Processed),
            }
        } else if let Some(obj) = value.as_object() {
            if let Some(failed_message) = obj.get("Failed").and_then(|v| v.as_str()) {
                return Some(Status::Failed(failed_message.to_string()));
            } else {
                return None;
            }
        }
        None
    }
}

#[derive(
    Clone,
    PartialEq,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Encode,
    Decode,
    Eq,
)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", content = "message")]
pub enum RollbackStatus {
    Rolledback(String),
    NotRolledback,
}

impl RollbackStatus {
    pub fn to_fixed_array(
        &self,
    ) -> Result<[u8; ROLLBACK_MESSAGE_BUFFER_SIZE], ParseProcessedTransactionError> {
        let mut buffer = [0; ROLLBACK_MESSAGE_BUFFER_SIZE];

        if let RollbackStatus::Rolledback(msg) = self {
            buffer[0] = 1;
            let message_bytes = msg.as_bytes();
            buffer[1..9].copy_from_slice(&(msg.len() as u64).to_le_bytes());

            if message_bytes.len() > ROLLBACK_MESSAGE_BUFFER_SIZE - 9 {
                return Err(ParseProcessedTransactionError::RollbackMessageTooLong);
            }
            buffer[9..(9 + message_bytes.len())].copy_from_slice(message_bytes);
        }

        Ok(buffer)
    }

    pub fn from_fixed_array(
        data: &[u8; ROLLBACK_MESSAGE_BUFFER_SIZE],
    ) -> Result<Self, ParseProcessedTransactionError> {
        if data[0] == 1 {
            let msg_len = u64::from_le_bytes(data[1..9].try_into()?) as usize;
            let msg = String::from_utf8(data[9..(9 + msg_len)].to_vec())?;
            Ok(RollbackStatus::Rolledback(msg))
        } else {
            Ok(RollbackStatus::NotRolledback)
        }
    }
}

#[derive(
    Clone,
    PartialEq,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Encode,
    Decode,
    Eq,
)]
pub struct ProcessedTransaction {
    pub runtime_transaction: RuntimeTransaction,
    pub status: Status,
    pub bitcoin_txid: Option<String>,
    pub logs: Vec<String>,
    pub rollback_status: RollbackStatus,
}

const ROLLBACK_MESSAGE_BUFFER_SIZE: usize = 1033;

impl ProcessedTransaction {
    pub fn txid(&self) -> String {
        self.runtime_transaction.txid()
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, ParseProcessedTransactionError> {
        let mut serialized = vec![];

        serialized.extend(self.rollback_status.to_fixed_array()?);

        serialized.extend((self.runtime_transaction.serialize().len() as u64).to_le_bytes());
        serialized.extend(self.runtime_transaction.serialize());

        serialized.extend(match &self.bitcoin_txid {
            Some(txid) => {
                let mut res = vec![1];
                res.extend(hex::decode(txid)?);
                res
            }
            None => vec![0],
        });

        serialized.extend((self.logs.len() as u64).to_le_bytes());
        for log in &self.logs {
            serialized.extend((log.len() as u64).to_le_bytes());
            serialized.extend(log.as_bytes());
        }

        serialized.extend(match &self.status {
            Status::Queued => vec![0_u8],
            Status::Processed => vec![1_u8],
            Status::Failed(err) => {
                let mut result = vec![2_u8];
                result.extend((err.len() as u64).to_le_bytes());
                result.extend(err.as_bytes());
                result
            }
        });
        Ok(serialized)
    }

    pub fn from_vec(data: &[u8]) -> Result<Self, ParseProcessedTransactionError> {
        let mut size = 0;

        let rollback_buffer: [u8; ROLLBACK_MESSAGE_BUFFER_SIZE] = data
            [size..(size + ROLLBACK_MESSAGE_BUFFER_SIZE)]
            .try_into()
            .map_err(|_| ParseProcessedTransactionError::TryFromSliceError)?;
        let rollback_status = RollbackStatus::from_fixed_array(&rollback_buffer)?;

        size += ROLLBACK_MESSAGE_BUFFER_SIZE;
        let data_bytes = data[size..(size + 8)].try_into()?;
        let runtime_transaction_len = u64::from_le_bytes(data_bytes) as usize;
        size += 8;
        let runtime_transaction =
            RuntimeTransaction::from_slice(&data[size..(size + runtime_transaction_len)])?;
        size += runtime_transaction_len;

        let bitcoin_txid = if data[size] == 1 {
            size += 1;
            let res = Some(hex::encode(&data[(size)..(size + 32)]));
            size += 32;
            res
        } else {
            size += 1;
            None
        };

        let data_bytes = data[size..(size + 8)].try_into()?;
        let logs_len = u64::from_le_bytes(data_bytes) as usize;
        size += 8;
        let mut logs = vec![];
        for _ in 0..logs_len {
            let log_len = u64::from_le_bytes(data[size..(size + 8)].try_into().unwrap()) as usize;
            size += 8;
            logs.push(String::from_utf8(data[size..(size + log_len)].to_vec()).unwrap());
            size += log_len;
        }

        let status = match data[size] {
            0 => Status::Queued,
            1 => Status::Processed,
            2 => {
                let data_bytes = data[(size + 1)..(size + 9)].try_into()?;
                let error_len = u64::from_le_bytes(data_bytes) as usize;
                size += 9;
                let error = String::from_utf8(data[size..(size + error_len)].to_vec())?;
                Status::Failed(error)
            }
            _ => unreachable!("status doesn't exist"),
        };

        Ok(ProcessedTransaction {
            runtime_transaction,
            status,
            bitcoin_txid,
            logs,
            rollback_status,
        })
    }

    pub fn compute_units_consumed(&self) -> Option<&str> {
        self.logs[self.logs.len() - 2].get(82..86)
    }
}

#[cfg(test)]
mod tests {
    // use crate::processed_transaction::ProcessedTransaction;
    // use crate::processed_transaction::RollbackStatus;
    // use crate::processed_transaction::Status;
    // use crate::runtime_transaction::RuntimeTransaction;
    // use crate::signature::Signature;
    // use arch_program::instruction::Instruction;
    // use arch_program::message::Message;
    // use arch_program::pubkey::Pubkey;
    // use arch_program::sanitized::ArchMessage;
    // use arch_program::sanitized::MessageHeader;
    // use proptest::prelude::*;

    // use proptest::strategy::Just;
    //TODO: fix this to work with new ArchMessage

    //     proptest! {
    //         #[test]
    //         fn fuzz_serialize_deserialize_processed_transaction(
    //             version in any::<u32>(),
    //             signatures in prop::collection::vec(prop::collection::vec(any::<u8>(), 64), 0..10),
    //             signers in prop::collection::vec(any::<[u8; 32]>(), 0..10),
    //             instructions in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..100), 0..10),
    //             bitcoin_txid in "[0-9a-f]{64}",
    //             accounts_tags in prop::collection::vec("[0-9a-f]{64}", 0..10)
    //         ) {
    //             // Generate a random RuntimeTransaction
    //             let signatures: Vec<Signature> = signatures.into_iter()
    //                 .map(|sig_bytes| Signature::from_slice(&sig_bytes))
    //                 .collect();

    //             let signers: Vec<Pubkey> = signers.into_iter()
    //                 .map(Pubkey::from)
    //                 .collect();

    //             let instructions: Vec<Instruction> = instructions.into_iter()
    //                 .map(|data| Instruction {
    //                     program_id: Pubkey::system_program(),
    //                     accounts: vec![],
    //                     data,
    //                 })
    //                 .collect();

    //             // Create ArchMessage instead of Message
    //             let message = ArchMessage

    //             let runtime_transaction = RuntimeTransaction {
    //                 version,
    //                 signatures,
    //                 message,
    //             };

    //             let processed_transaction = ProcessedTransaction {
    //                 runtime_transaction,
    //                 status: Status::Queued,
    //                 bitcoin_txid: Some(bitcoin_txid.to_string()),
    //                 accounts_tags: accounts_tags.iter().map(|s| s.to_string()).collect(),
    //                 logs: vec![],
    //                 rollback_status: false,
    //             };

    //             let serialized = processed_transaction.to_vec().unwrap();
    //             let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();

    //             let reserialized = deserialized.to_vec().unwrap();
    //             assert_eq!(serialized, reserialized);
    //         }
    //     }

    use arch_program::sanitized::{ArchMessage, MessageHeader};

    use crate::{
        types::processed_transaction::ROLLBACK_MESSAGE_BUFFER_SIZE, RollbackStatus, Status,
    };

    use super::ProcessedTransaction;

    #[test]
    fn test_rollback_with_message() {
        let rollback_message = "a".repeat(ROLLBACK_MESSAGE_BUFFER_SIZE - 10);
        let processed_transaction = ProcessedTransaction {
            runtime_transaction: crate::RuntimeTransaction {
                version: 1,
                signatures: vec![],
                message: ArchMessage {
                    header: MessageHeader {
                        num_readonly_signed_accounts: 0,
                        num_readonly_unsigned_accounts: 0,
                        num_required_signatures: 0,
                    },
                    account_keys: vec![],
                    instructions: vec![],
                    recent_blockhash:
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                },
            },
            status: Status::Processed,
            bitcoin_txid: None,
            logs: vec![],
            rollback_status: RollbackStatus::Rolledback(rollback_message),
        };

        let serialized = processed_transaction.to_vec().unwrap();
        let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();
        assert_eq!(processed_transaction, deserialized);
    }

    #[test]
    fn test_rollback_with_message_too_long() {
        let rollback_message = "a".repeat(ROLLBACK_MESSAGE_BUFFER_SIZE);
        let processed_transaction = ProcessedTransaction {
            runtime_transaction: crate::RuntimeTransaction {
                version: 1,
                signatures: vec![],
                message: ArchMessage {
                    header: MessageHeader {
                        num_readonly_signed_accounts: 0,
                        num_readonly_unsigned_accounts: 0,
                        num_required_signatures: 0,
                    },
                    account_keys: vec![],
                    instructions: vec![],
                    recent_blockhash:
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                },
            },
            status: Status::Processed,
            bitcoin_txid: None,
            logs: vec![],
            rollback_status: RollbackStatus::Rolledback(rollback_message),
        };

        let serialized = processed_transaction.to_vec();
        assert_eq!(serialized.is_err(), true);
    }

    #[test]
    fn test_serialization_not_rolledback() {
        let processed_transaction = ProcessedTransaction {
            runtime_transaction: crate::RuntimeTransaction {
                version: 1,
                signatures: vec![],
                message: ArchMessage {
                    header: MessageHeader {
                        num_readonly_signed_accounts: 0,
                        num_readonly_unsigned_accounts: 0,
                        num_required_signatures: 0,
                    },
                    account_keys: vec![],
                    instructions: vec![],
                    recent_blockhash:
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                },
            },
            status: Status::Processed,
            bitcoin_txid: None,
            logs: vec![],
            rollback_status: RollbackStatus::NotRolledback,
        };

        let serialized = processed_transaction.to_vec().unwrap();
        let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();
        assert_eq!(processed_transaction, deserialized);
    }

    #[test]
    fn rollback_default_message_size() {
        let message = "Transaction rolled back in Bitcoin";
        println!("Message size as bytes : {}", message.as_bytes().len());
    }
}
