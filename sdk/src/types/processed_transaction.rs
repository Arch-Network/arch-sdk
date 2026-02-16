use std::{array::TryFromSliceError, string::FromUtf8Error};

use arch_program::hash::Hash;
use arch_program::sanitized::{SanitizedInstruction, MAX_INSTRUCTION_COUNT_PER_TRANSACTION};
use bitcode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "fuzzing")]
use libfuzzer_sys::arbitrary;

use crate::{
    types::inner_instruction::{InnerInstruction, InnerInstructionsList},
    RUNTIME_TX_SIZE_LIMIT,
};

use super::{RuntimeTransaction, RuntimeTransactionError};

#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum ParseProcessedTransactionError {
    #[error("from hex error: {0}")]
    FromHexError(#[from] hex::FromHexError),

    #[error("from utf8 error: {0}")]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error("try from slice error")]
    TryFromSliceError,

    #[error("buffer too short for deserialization")]
    BufferTooShort,

    #[error("runtime transaction error: {0}")]
    RuntimeTransactionError(#[from] RuntimeTransactionError),

    #[error("rollback message too long")]
    RollbackMessageTooLong,

    #[error("runtime transaction size exceeds limit: {0} > {1}")]
    RuntimeTransactionSizeExceedsLimit(usize, usize),

    #[error("log message too long")]
    LogMessageTooLong,

    #[error("log messages too long")]
    TooManyLogMessages,

    #[error("status failed message too long")]
    StatusFailedMessageTooLong,

    #[error("too many instructions")]
    TooManyInstructions,

    #[error("too many inner instructions")]
    TooManyInnerInstructions,
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
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
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
            let msg_len = u64::from_le_bytes(
                data[1..9]
                    .try_into()
                    .map_err(|_| ParseProcessedTransactionError::TryFromSliceError)?,
            ) as usize;
            // Check that msg_len doesn't exceed the available space in the fixed buffer
            if 9 + msg_len > ROLLBACK_MESSAGE_BUFFER_SIZE {
                return Err(ParseProcessedTransactionError::BufferTooShort);
            }
            let msg = String::from_utf8(data[9..(9 + msg_len)].to_vec())
                .map_err(ParseProcessedTransactionError::FromUtf8Error)?;
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
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct ProcessedTransaction {
    pub runtime_transaction: RuntimeTransaction,
    pub status: Status,
    pub bitcoin_txid: Option<Hash>,
    pub logs: Vec<String>,
    pub rollback_status: RollbackStatus,
    pub inner_instructions_list: InnerInstructionsList,
}

pub const ROLLBACK_MESSAGE_BUFFER_SIZE: usize = 1033;
const LOG_MESSAGES_BYTES_LIMIT: usize = 255;
pub const MAX_LOG_MESSAGES_COUNT: usize = 400;
pub const MAX_LOG_MESSAGES_LEN: usize = 10_000 + 20; // adding extra 20 to the logs length field
pub const MAX_STATUS_FAILED_MESSAGE_SIZE: usize = 1000;

// Conservative upper bounds for inner-instruction serialization sizing
const MAX_INNER_INSTRUCTIONS_TOTAL: usize = u8::MAX as usize;
const MAX_ACCOUNTS_PER_INSTRUCTION: usize = u8::MAX as usize; // bounded by pubkey indices
const MAX_CPI_INSTRUCTION_SIZE: usize = 1280; // matches default in compute budget
const MAX_CPI_INSTRUCTION_SERIALIZED_SIZE: usize = 1 /*program_id_index*/ + 4 /*accounts len*/ + MAX_ACCOUNTS_PER_INSTRUCTION + 4 /*data len*/ + MAX_CPI_INSTRUCTION_SIZE;

impl ProcessedTransaction {
    pub fn max_serialized_size() -> usize {
        ROLLBACK_MESSAGE_BUFFER_SIZE  // rollback status (fixed size buffer)
            + 8  // runtime_transaction length field
            + RUNTIME_TX_SIZE_LIMIT  // max runtime transaction size
            + 1  // bitcoin_txid variant flag (None/Some)
            + 32  // bitcoin_txid hash (when Some)
            + 8  // logs count field
            + MAX_LOG_MESSAGES_COUNT * 8 // max overhead for individual log lengths
            + MAX_LOG_MESSAGES_LEN // max logs data
            + 1  // status variant flag (Queued/Processed/Failed)
            + 8  // error message length field (for Failed status)
            + MAX_STATUS_FAILED_MESSAGE_SIZE // reasonable max error message size
            // inner instructions list serialization upper bound (conservative)
            + 8 // outer instructions count field
            + (MAX_INSTRUCTION_COUNT_PER_TRANSACTION * 8 )// per-outer inner count fields
            + (MAX_INNER_INSTRUCTIONS_TOTAL
                * (1 /*stack height*/ + MAX_CPI_INSTRUCTION_SERIALIZED_SIZE))
    }

    pub fn txid(&self) -> Hash {
        self.runtime_transaction.txid()
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, ParseProcessedTransactionError> {
        let mut serialized = vec![];

        serialized.extend(self.rollback_status.to_fixed_array()?);

        let serialized_runtime_transaction = self.runtime_transaction.serialize();
        if serialized_runtime_transaction.len() > RUNTIME_TX_SIZE_LIMIT {
            return Err(
                ParseProcessedTransactionError::RuntimeTransactionSizeExceedsLimit(
                    serialized_runtime_transaction.len(),
                    RUNTIME_TX_SIZE_LIMIT,
                ),
            );
        }
        serialized.extend((serialized_runtime_transaction.len() as u64).to_le_bytes());
        serialized.extend(serialized_runtime_transaction);

        serialized.extend(match &self.bitcoin_txid {
            Some(txid) => {
                let mut res = vec![1];
                res.extend(txid.to_array());
                res
            }
            None => vec![0],
        });

        if self.logs.len() > MAX_LOG_MESSAGES_COUNT {
            return Err(ParseProcessedTransactionError::TooManyLogMessages);
        }
        if self.logs.iter().map(|s| s.len()).sum::<usize>() > MAX_LOG_MESSAGES_LEN {
            return Err(ParseProcessedTransactionError::TooManyLogMessages);
        }

        serialized.extend((self.logs.len() as u64).to_le_bytes());
        for log in &self.logs {
            let log_len = std::cmp::min(log.len(), LOG_MESSAGES_BYTES_LIMIT);
            serialized.extend((log_len as u64).to_le_bytes());
            serialized.extend(log.as_bytes()[..log_len].to_vec());
        }

        serialized.extend(match &self.status {
            Status::Queued => vec![0_u8],
            Status::Processed => vec![1_u8],
            Status::Failed(err) => {
                let mut result = vec![2_u8];
                if err.len() > MAX_STATUS_FAILED_MESSAGE_SIZE {
                    return Err(ParseProcessedTransactionError::StatusFailedMessageTooLong);
                }
                result.extend((err.len() as u64).to_le_bytes());
                result.extend(err.as_bytes());
                result
            }
        });

        // Serialize inner instructions list
        if self.inner_instructions_list.len() > MAX_INSTRUCTION_COUNT_PER_TRANSACTION {
            return Err(ParseProcessedTransactionError::TooManyInstructions);
        }
        serialized.extend((self.inner_instructions_list.len() as u64).to_le_bytes());
        let mut total_inners = 0usize;
        for inner_instructions in &self.inner_instructions_list {
            total_inners = total_inners
                .checked_add(inner_instructions.len())
                .ok_or(ParseProcessedTransactionError::TooManyInnerInstructions)?;
            if inner_instructions.len() > MAX_INNER_INSTRUCTIONS_TOTAL
                || total_inners > MAX_INNER_INSTRUCTIONS_TOTAL
            {
                return Err(ParseProcessedTransactionError::TooManyInnerInstructions);
            }
            serialized.extend((inner_instructions.len() as u64).to_le_bytes());
            for inner in inner_instructions {
                // stack_height
                serialized.push(inner.stack_height);
                // instruction
                let instr_bytes = inner.instruction.serialize();
                if instr_bytes.len() > MAX_CPI_INSTRUCTION_SERIALIZED_SIZE {
                    return Err(ParseProcessedTransactionError::TooManyInnerInstructions);
                }
                serialized.extend(instr_bytes);
            }
        }
        Ok(serialized)
    }

    pub fn from_vec(data: &[u8]) -> Result<Self, ParseProcessedTransactionError> {
        fn get_const_slice<const N: usize>(
            data: &[u8],
            offset: usize,
        ) -> Result<[u8; N], ParseProcessedTransactionError> {
            let end = offset + N;
            let slice = data
                .get(offset..end)
                .ok_or(ParseProcessedTransactionError::TryFromSliceError)?;
            let array_ref = slice
                .try_into()
                .map_err(|_| ParseProcessedTransactionError::TryFromSliceError)?;
            Ok(array_ref)
        }

        fn get_slice(
            data: &[u8],
            start: usize,
            len: usize,
        ) -> Result<&[u8], ParseProcessedTransactionError> {
            data.get(start..start + len)
                .ok_or(ParseProcessedTransactionError::TryFromSliceError)
        }

        fn get_byte(data: &[u8], offset: usize) -> Result<u8, ParseProcessedTransactionError> {
            data.get(offset)
                .copied()
                .ok_or(ParseProcessedTransactionError::TryFromSliceError)
        }

        let mut size = 0;

        // Rollback buffer - use get_const_slice
        let rollback_buffer = get_const_slice(data, size)?;
        let rollback_status = RollbackStatus::from_fixed_array(&rollback_buffer)?;

        size += ROLLBACK_MESSAGE_BUFFER_SIZE;

        // Runtime transaction length - use get_const_slice
        let data_bytes = get_const_slice(data, size)?;
        let runtime_transaction_len = u64::from_le_bytes(data_bytes) as usize;
        if runtime_transaction_len > RUNTIME_TX_SIZE_LIMIT {
            return Err(
                ParseProcessedTransactionError::RuntimeTransactionSizeExceedsLimit(
                    runtime_transaction_len,
                    RUNTIME_TX_SIZE_LIMIT,
                ),
            );
        }
        size += 8;

        // Runtime transaction data - use get_slice
        let runtime_transaction =
            RuntimeTransaction::from_slice(get_slice(data, size, runtime_transaction_len)?)?;
        size += runtime_transaction_len;

        // Bitcoin transaction ID - use get_byte and get_const_slice
        let bitcoin_txid = if get_byte(data, size)? == 1 {
            size += 1;
            let bytes = get_const_slice(data, size)?;
            let res = Some(Hash::from(bytes));
            size += 32;
            res
        } else {
            size += 1;
            None
        };

        // Logs length - use get_const_slice
        let data_bytes = get_const_slice(data, size)?;
        let logs_len = u64::from_le_bytes(data_bytes) as usize;

        if logs_len > MAX_LOG_MESSAGES_COUNT {
            return Err(ParseProcessedTransactionError::TooManyLogMessages);
        }
        size += 8;
        let mut logs = vec![];

        let mut total_logs_size = 0;
        // Process each log - use get_const_slice and get_slice
        for _ in 0..logs_len {
            let log_len_bytes = get_const_slice(data, size)?;
            let log_len = u64::from_le_bytes(log_len_bytes) as usize;
            size += 8;
            if log_len > LOG_MESSAGES_BYTES_LIMIT {
                return Err(ParseProcessedTransactionError::LogMessageTooLong);
            }
            total_logs_size += log_len;
            if total_logs_size > MAX_LOG_MESSAGES_LEN {
                return Err(ParseProcessedTransactionError::TooManyLogMessages);
            }
            let log_data = get_slice(data, size, log_len)?;
            logs.push(String::from_utf8(log_data.to_vec())?);
            size += log_len;
        }

        // Status processing - use get_byte, get_const_slice and get_slice
        let status_flag = get_byte(data, size)?;
        size += 1; // advance for status byte
        let status = match status_flag {
            0 => Status::Queued,
            1 => Status::Processed,
            2 => {
                let error_len_bytes = get_const_slice(data, size)?;
                let error_len = u64::from_le_bytes(error_len_bytes) as usize;
                if error_len > MAX_STATUS_FAILED_MESSAGE_SIZE {
                    return Err(ParseProcessedTransactionError::StatusFailedMessageTooLong);
                }
                size += 8;
                let error_data = get_slice(data, size, error_len)?;
                let error = String::from_utf8(error_data.to_vec())?;
                size += error_len;
                Status::Failed(error)
            }
            _ => return Err(ParseProcessedTransactionError::TryFromSliceError),
        };

        // Deserialize inner instructions list
        let outer_len_bytes = get_const_slice::<8>(data, size)?;
        let outer_len = u64::from_le_bytes(outer_len_bytes) as usize;
        if outer_len > MAX_INSTRUCTION_COUNT_PER_TRANSACTION {
            return Err(ParseProcessedTransactionError::TooManyInstructions);
        }
        size += 8;
        let mut inner_instructions_list: InnerInstructionsList = Vec::with_capacity(outer_len);
        let mut total_inners = 0usize;

        for _ in 0..outer_len {
            let inner_len_bytes = get_const_slice::<8>(data, size)?;
            let inner_len = u64::from_le_bytes(inner_len_bytes) as usize;
            total_inners = total_inners
                .checked_add(inner_len)
                .ok_or(ParseProcessedTransactionError::TooManyInnerInstructions)?;
            if inner_len > MAX_INNER_INSTRUCTIONS_TOTAL
                || total_inners > MAX_INNER_INSTRUCTIONS_TOTAL
            {
                return Err(ParseProcessedTransactionError::TooManyInnerInstructions);
            }
            size += 8;

            let mut inners: Vec<InnerInstruction> = Vec::with_capacity(inner_len);
            for _ in 0..inner_len {
                // stack height
                let stack_height = get_byte(data, size)?;
                size += 1;

                // instruction deserialization uses remaining slice
                let remaining = data
                    .get(size..)
                    .ok_or(ParseProcessedTransactionError::TryFromSliceError)?;
                let (instruction, consumed) = SanitizedInstruction::deserialize(remaining)
                    .map_err(|_| ParseProcessedTransactionError::TryFromSliceError)?;
                if consumed > MAX_CPI_INSTRUCTION_SERIALIZED_SIZE {
                    return Err(ParseProcessedTransactionError::TooManyInnerInstructions);
                }
                size += consumed;

                inners.push(InnerInstruction {
                    instruction,
                    stack_height,
                });
            }
            inner_instructions_list.push(inners);
        }

        Ok(ProcessedTransaction {
            runtime_transaction,
            status,
            bitcoin_txid,
            logs,
            rollback_status,
            inner_instructions_list,
        })
    }

    pub fn compute_units_consumed(&self) -> Option<&str> {
        if self.logs.len() < 2 {
            return None;
        }
        self.logs.get(self.logs.len() - 2)?.get(82..86)
    }
}

#[cfg(test)]
mod tests {
    use super::ParseProcessedTransactionError;
    use super::ProcessedTransaction;
    use crate::types::inner_instruction::InnerInstruction;
    use crate::Signature;
    use crate::{
        types::processed_transaction::ROLLBACK_MESSAGE_BUFFER_SIZE, RollbackStatus, Status,
    };
    use arch_program::hash::Hash;
    use arch_program::pubkey::Pubkey;
    use arch_program::sanitized::SanitizedInstruction;
    use arch_program::sanitized::{ArchMessage, MessageHeader};
    use std::str::FromStr;

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
                    recent_blockhash: Hash::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                },
            },
            status: Status::Processed,
            bitcoin_txid: None,
            logs: vec![],
            rollback_status: RollbackStatus::Rolledback(rollback_message),
            inner_instructions_list: vec![],
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
                    recent_blockhash: Hash::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                },
            },
            status: Status::Processed,
            bitcoin_txid: None,
            logs: vec![],
            rollback_status: RollbackStatus::Rolledback(rollback_message),
            inner_instructions_list: vec![],
        };

        let serialized = processed_transaction.to_vec();
        assert!(serialized.is_err());
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
                    recent_blockhash: Hash::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                },
            },
            status: Status::Processed,
            bitcoin_txid: None,
            logs: vec![],
            rollback_status: RollbackStatus::NotRolledback,
            inner_instructions_list: vec![],
        };

        let serialized = processed_transaction.to_vec().unwrap();
        let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();
        assert_eq!(processed_transaction, deserialized);
    }

    #[test]
    fn rollback_default_message_size() {
        let message = "Transaction rolled back in Bitcoin";
        println!("Message size as bytes : {}", message.len());
    }

    // Tests for log validation checks
    fn create_minimal_processed_transaction() -> ProcessedTransaction {
        ProcessedTransaction {
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
                    recent_blockhash: Hash::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                },
            },
            status: Status::Processed,
            bitcoin_txid: None,
            logs: vec![],
            rollback_status: RollbackStatus::NotRolledback,
            inner_instructions_list: vec![],
        }
    }

    #[test]
    fn test_serialization_too_many_log_messages() {
        let mut processed_transaction = create_minimal_processed_transaction();

        // Create logs that exceed MAX_LOG_MESSAGES_LEN in total size
        processed_transaction.logs = vec!["a".to_string(); super::MAX_LOG_MESSAGES_COUNT + 1];

        let result = processed_transaction.to_vec();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            super::ParseProcessedTransactionError::TooManyLogMessages
        );
    }

    #[test]
    fn test_serialization_exactly_max_log_messages() {
        let mut processed_transaction = create_minimal_processed_transaction();

        // Create logs that have a total size of exactly MAX_LOG_MESSAGES_LEN
        processed_transaction.logs = vec!["a".to_string(); super::MAX_LOG_MESSAGES_COUNT];

        let result = processed_transaction.to_vec();
        assert!(result.is_ok());

        // Verify round-trip
        let serialized = result.unwrap();
        let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();
        assert_eq!(processed_transaction, deserialized);
    }

    #[test]
    fn test_deserialization_too_many_log_messages() {
        // Create a valid processed transaction first
        let mut processed_transaction = create_minimal_processed_transaction();
        processed_transaction.logs = vec!["Valid log".to_string()];

        let mut serialized = processed_transaction.to_vec().unwrap();

        // Manually corrupt the serialized data to have too many log messages
        // Find the position where logs length is stored
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let runtime_tx_len_pos = rollback_size;
        let runtime_tx_len = u64::from_le_bytes(
            serialized[runtime_tx_len_pos..runtime_tx_len_pos + 8]
                .try_into()
                .unwrap(),
        ) as usize;
        let bitcoin_txid_pos = runtime_tx_len_pos + 8 + runtime_tx_len;
        let logs_len_pos = bitcoin_txid_pos + 1; // +1 for the bitcoin_txid flag (0 in this case)

        // Set logs_len to MAX_LOG_MESSAGES_COUNT + 1
        let corrupted_logs_len = (super::MAX_LOG_MESSAGES_COUNT + 1) as u64;
        serialized[logs_len_pos..logs_len_pos + 8]
            .copy_from_slice(&corrupted_logs_len.to_le_bytes());

        let result = ProcessedTransaction::from_vec(&serialized);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            super::ParseProcessedTransactionError::TooManyLogMessages
        );
    }

    #[test]
    fn test_serialization_log_message_gets_truncated() {
        let mut processed_transaction = create_minimal_processed_transaction();

        // Create a log message longer than LOG_MESSAGES_BYTES_LIMIT
        let long_message = "a".repeat(super::LOG_MESSAGES_BYTES_LIMIT + 10);
        processed_transaction.logs = vec![long_message.clone()];

        let result = processed_transaction.to_vec();
        assert!(result.is_ok());

        // Verify that the message was truncated during serialization
        let serialized = result.unwrap();
        let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();

        assert_eq!(deserialized.logs.len(), 1);
        assert_eq!(deserialized.logs[0].len(), super::LOG_MESSAGES_BYTES_LIMIT);
        assert_eq!(
            deserialized.logs[0],
            "a".repeat(super::LOG_MESSAGES_BYTES_LIMIT)
        );
    }

    #[test]
    fn test_deserialization_log_message_too_long() {
        // Create a valid processed transaction first
        let mut processed_transaction = create_minimal_processed_transaction();
        processed_transaction.logs = vec!["Valid log".to_string()];

        let mut serialized = processed_transaction.to_vec().unwrap();

        // Find the position where the first log message length is stored
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let runtime_tx_len_pos = rollback_size;
        let runtime_tx_len = u64::from_le_bytes(
            serialized[runtime_tx_len_pos..runtime_tx_len_pos + 8]
                .try_into()
                .unwrap(),
        ) as usize;
        let bitcoin_txid_pos = runtime_tx_len_pos + 8 + runtime_tx_len;
        let logs_len_pos = bitcoin_txid_pos + 1; // +1 for the bitcoin_txid flag
        let first_log_len_pos = logs_len_pos + 8; // +8 for logs_len

        // Set the first log message length to exceed LOG_MESSAGES_BYTES_LIMIT
        let corrupted_log_len = (super::LOG_MESSAGES_BYTES_LIMIT + 1) as u64;
        serialized[first_log_len_pos..first_log_len_pos + 8]
            .copy_from_slice(&corrupted_log_len.to_le_bytes());

        let result = ProcessedTransaction::from_vec(&serialized);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            super::ParseProcessedTransactionError::LogMessageTooLong
        );
    }

    #[test]
    fn test_log_message_exactly_at_limit() {
        let mut processed_transaction = create_minimal_processed_transaction();

        // Create a log message exactly at the LOG_MESSAGES_BYTES_LIMIT
        let max_message = "a".repeat(super::LOG_MESSAGES_BYTES_LIMIT);
        processed_transaction.logs = vec![max_message.clone()];

        let result = processed_transaction.to_vec();
        assert!(result.is_ok());

        // Verify round-trip
        let serialized = result.unwrap();
        let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();
        assert_eq!(processed_transaction, deserialized);
        assert_eq!(deserialized.logs[0], max_message);
    }

    #[test]
    fn test_multiple_log_messages_within_limits() {
        let mut processed_transaction = create_minimal_processed_transaction();

        // Create multiple log messages within both limits
        processed_transaction.logs = (0..10)
            .map(|i| format!("Log message number {} with some content", i))
            .collect();

        let result = processed_transaction.to_vec();
        assert!(result.is_ok());

        // Verify round-trip
        let serialized = result.unwrap();
        let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();
        assert_eq!(processed_transaction, deserialized);
    }

    #[test]
    fn test_inner_instructions_empty_list_roundtrip() {
        let mut tx = create_minimal_processed_transaction();
        tx.inner_instructions_list = vec![];

        let bytes = tx.to_vec().unwrap();
        let de = ProcessedTransaction::from_vec(&bytes).unwrap();
        assert_eq!(tx, de);
    }

    #[test]
    fn test_inner_instructions_single_outer_empty_roundtrip() {
        let mut tx = create_minimal_processed_transaction();
        tx.inner_instructions_list = vec![vec![]];

        let bytes = tx.to_vec().unwrap();
        let de = ProcessedTransaction::from_vec(&bytes).unwrap();
        assert_eq!(tx, de);
    }

    #[test]
    fn test_inner_instructions_non_empty_roundtrip() {
        let mut tx = create_minimal_processed_transaction();

        let ii1 = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 1,
                accounts: vec![0, 2],
                data: vec![0xAA, 0xBB],
            },
            stack_height: 2,
        };
        let ii2 = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 3,
                accounts: vec![],
                data: vec![0x01],
            },
            stack_height: 3,
        };

        tx.inner_instructions_list = vec![vec![ii1.clone(), ii2.clone()], vec![ii2]];

        let bytes = tx.to_vec().unwrap();
        let de = ProcessedTransaction::from_vec(&bytes).unwrap();
        assert_eq!(tx, de);
    }

    #[test]
    fn test_failed_status_with_inner_instructions_alignment() {
        let mut tx = create_minimal_processed_transaction();
        tx.status = Status::Failed("some error".to_string());

        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![0x10, 0x20, 0x30],
            },
            stack_height: 2,
        };
        tx.inner_instructions_list = vec![vec![ii]];

        let bytes = tx.to_vec().unwrap();
        let de = ProcessedTransaction::from_vec(&bytes).unwrap();
        assert_eq!(tx, de);
    }

    #[test]
    fn test_malformed_status_flag_returns_error() {
        let mut tx = create_minimal_processed_transaction();
        tx.logs = vec!["a".to_string()];
        let mut bytes = tx.to_vec().unwrap();

        // Compute offset to status flag
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let mut cursor = rollback_size;
        let rt_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8 + rt_len;

        // bitcoin_txid flag
        cursor += 1 + 0 * 32; // None => 0

        // logs len and each entry
        let logs_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        for _ in 0..logs_len {
            let l = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8 + l;
        }

        // Set invalid status flag
        bytes[cursor] = 9;

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn test_truncated_inner_instruction_returns_error() {
        let mut tx = create_minimal_processed_transaction();
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![0x01, 0x02],
            },
            stack_height: 2,
        };
        tx.inner_instructions_list = vec![vec![ii]];

        let mut bytes = tx.to_vec().unwrap();
        // Truncate last byte from inner instructions encoding
        bytes.pop();
        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn test_inner_instructions_length_mismatch_returns_error() {
        let mut tx = create_minimal_processed_transaction();
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 2,
                accounts: vec![0, 1],
                data: vec![0xFF],
            },
            stack_height: 2,
        };
        tx.inner_instructions_list = vec![vec![ii]];
        let mut bytes = tx.to_vec().unwrap();

        // Walk to the first inner_len field to tamper it
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let mut cursor = rollback_size;
        let rt_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8 + rt_len;

        // btc flag
        cursor += 1;

        // logs len
        let logs_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        for _ in 0..logs_len {
            let l = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8 + l;
        }

        // status flag
        cursor += 1;

        // outer_len
        let _outer_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;

        // inner_len of first outer: set to 2 while only 1 present
        bytes[cursor..cursor + 8].copy_from_slice(&(2u64).to_le_bytes());

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn test_inner_instruction_zero_accounts_zero_data_roundtrip() {
        let mut tx = create_minimal_processed_transaction();
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 0,
                accounts: vec![],
                data: vec![],
            },
            stack_height: 1,
        };
        tx.inner_instructions_list = vec![vec![ii]];

        let bytes = tx.to_vec().unwrap();
        let de = ProcessedTransaction::from_vec(&bytes).unwrap();
        assert_eq!(tx, de);
    }

    #[test]
    fn test_inner_instruction_max_accounts_and_max_data_roundtrip() {
        let mut tx = create_minimal_processed_transaction();
        let accounts: Vec<u8> = (0..=254).collect(); // 255 accounts
        let data: Vec<u8> = vec![0xAB; super::MAX_CPI_INSTRUCTION_SIZE];
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: u8::MAX,
                accounts,
                data,
            },
            stack_height: u8::MAX,
        };
        tx.inner_instructions_list = vec![vec![ii]];

        let bytes = tx.to_vec().unwrap();
        let de = ProcessedTransaction::from_vec(&bytes).unwrap();
        assert_eq!(tx, de);
    }

    #[test]
    fn test_multiple_outers_mixed_empty_and_nonempty_roundtrip() {
        let mut tx = create_minimal_processed_transaction();
        let ii1 = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 5,
                accounts: vec![1, 2, 3],
                data: vec![0x01, 0x02],
            },
            stack_height: 2,
        };
        let ii2 = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 7,
                accounts: vec![],
                data: vec![0xFF],
            },
            stack_height: 3,
        };
        tx.inner_instructions_list =
            vec![vec![], vec![ii1], vec![ii2.clone(), ii2.clone()], vec![]];

        let bytes = tx.to_vec().unwrap();
        let de = ProcessedTransaction::from_vec(&bytes).unwrap();
        assert_eq!(tx, de);
    }

    #[test]
    fn test_outer_len_mismatch_returns_error() {
        let mut tx = create_minimal_processed_transaction();
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 1,
                accounts: vec![0],
                data: vec![0x11],
            },
            stack_height: 2,
        };
        tx.inner_instructions_list = vec![vec![ii]];

        let mut bytes = tx.to_vec().unwrap();

        // Walk to outer_len
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let mut cursor = rollback_size;
        let rt_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8 + rt_len;
        // btc flag
        cursor += 1;
        // logs
        let logs_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        for _ in 0..logs_len {
            let l = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8 + l;
        }
        // status
        if bytes[cursor] == 2 {
            // failed: skip len + data as well
            cursor += 1;
            let e_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8 + e_len;
        } else {
            cursor += 1;
        }

        // Now at outer_len
        bytes[cursor..cursor + 8].copy_from_slice(&(2u64).to_le_bytes());

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn test_too_many_outer_instructions_returns_error() {
        let tx = create_minimal_processed_transaction();
        let mut bytes = tx.to_vec().unwrap();

        // Walk to outer_len
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let mut cursor = rollback_size;
        let rt_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8 + rt_len;
        // btc flag
        cursor += 1;
        // logs
        let logs_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        for _ in 0..logs_len {
            let l = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8 + l;
        }
        // status (Queued => 0)
        cursor += 1;

        // Set outer_len to MAX_INSTRUCTION_COUNT_PER_TRANSACTION + 1
        let excessive = (arch_program::sanitized::MAX_INSTRUCTION_COUNT_PER_TRANSACTION as u64) + 1;
        bytes[cursor..cursor + 8].copy_from_slice(&excessive.to_le_bytes());

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::TooManyInstructions)
        ));
    }

    #[test]
    fn test_outer_len_at_max_roundtrip_ok() {
        let mut tx = create_minimal_processed_transaction();
        let max_outer = arch_program::sanitized::MAX_INSTRUCTION_COUNT_PER_TRANSACTION;
        tx.inner_instructions_list = vec![vec![]; max_outer];

        let bytes = tx.to_vec().unwrap();
        let de = ProcessedTransaction::from_vec(&bytes).unwrap();
        assert_eq!(tx, de);
    }

    #[test]
    fn test_total_inners_at_max_roundtrip_ok() {
        let mut tx = create_minimal_processed_transaction();

        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 1,
                accounts: vec![],
                data: vec![],
            },
            stack_height: 1,
        };

        // Single outer containing exactly MAX_INNER_INSTRUCTIONS_TOTAL inners
        tx.inner_instructions_list = vec![vec![ii; super::MAX_INNER_INSTRUCTIONS_TOTAL]];

        let bytes = tx.to_vec().unwrap();
        let de = ProcessedTransaction::from_vec(&bytes).unwrap();
        assert_eq!(tx, de);
    }

    #[test]
    fn test_total_inners_cumulative_exceeds_returns_error() {
        // Build a transaction with two outers: first has 1 inner, second has 0
        // Then mutate second inner_len to MAX so total becomes MAX + 1 -> error
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 1,
                accounts: vec![],
                data: vec![],
            },
            stack_height: 1,
        };

        let mut tx = create_minimal_processed_transaction();
        tx.inner_instructions_list = vec![vec![ii.clone()], vec![]];
        let mut bytes = tx.to_vec().unwrap();

        // Walk to outer_len
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let mut cursor = rollback_size;
        let rt_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8 + rt_len;
        // btc flag
        cursor += 1;
        // logs
        let logs_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        for _ in 0..logs_len {
            let l = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8 + l;
        }
        // status (Queued => 0)
        // If Failed, we'd need to skip message; our minimal tx uses Processed by default
        cursor += 1;

        // outer_len
        let outer_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        assert_eq!(outer_len, 2);
        cursor += 8;

        // inner_len[0]
        let first_inner_len_pos = cursor;
        let first_inner_len = u64::from_le_bytes(
            bytes[first_inner_len_pos..first_inner_len_pos + 8]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(first_inner_len, 1);
        cursor += 8;

        // Skip body of first outer: 1 byte stack + serialized instruction
        let body_len = 1 + ii.instruction.serialize().len();
        cursor += body_len;

        // Now at second inner_len field; set it to MAX to cause cumulative overflow
        let excessive = super::MAX_INNER_INSTRUCTIONS_TOTAL as u64;
        bytes[cursor..cursor + 8].copy_from_slice(&excessive.to_le_bytes());

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::TooManyInnerInstructions)
        ));
    }

    #[test]
    fn test_too_many_inner_instructions_single_outer_returns_error() {
        let mut tx = create_minimal_processed_transaction();
        tx.inner_instructions_list = vec![vec![]];
        let mut bytes = tx.to_vec().unwrap();

        // Walk to outer_len
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let mut cursor = rollback_size;
        let rt_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8 + rt_len;
        // btc flag
        cursor += 1;
        // logs
        let logs_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        for _ in 0..logs_len {
            let l = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8 + l;
        }
        // status
        cursor += 1;

        // outer_len = 1
        bytes[cursor..cursor + 8].copy_from_slice(&(1u64).to_le_bytes());
        cursor += 8;

        // inner_len[0] = MAX_INNER_INSTRUCTIONS_TOTAL + 1
        let excessive_inners = (super::MAX_INNER_INSTRUCTIONS_TOTAL as u64) + 1;
        bytes[cursor..cursor + 8].copy_from_slice(&excessive_inners.to_le_bytes());

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::TooManyInnerInstructions)
        ));
    }

    #[test]
    fn test_too_many_inner_instructions_cumulative_returns_error() {
        let mut tx = create_minimal_processed_transaction();
        tx.inner_instructions_list = vec![vec![], vec![]];
        let mut bytes = tx.to_vec().unwrap();

        // Walk to outer_len
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let mut cursor = rollback_size;
        let rt_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8 + rt_len;
        // btc flag
        cursor += 1;
        // logs
        let logs_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        for _ in 0..logs_len {
            let l = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8 + l;
        }
        // status
        cursor += 1;

        // outer_len = 2
        bytes[cursor..cursor + 8].copy_from_slice(&(2u64).to_le_bytes());
        cursor += 8;

        // inner_len[0] = MAX_INNER_INSTRUCTIONS_TOTAL + 1 -> triggers error early
        let excessive = (super::MAX_INNER_INSTRUCTIONS_TOTAL as u64) + 1;
        bytes[cursor..cursor + 8].copy_from_slice(&excessive.to_le_bytes());

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::TooManyInnerInstructions)
        ));
    }

    #[test]
    fn test_compute_units_consumed_edge_cases() {
        let mut tx = create_minimal_processed_transaction();
        // No logs
        tx.logs = vec![];
        assert_eq!(tx.compute_units_consumed(), None);

        // Only one log
        tx.logs = vec!["only one".to_string()];
        assert_eq!(tx.compute_units_consumed(), None);

        // Second last too short
        tx.logs = vec!["a".to_string(), "short".to_string()];
        assert_eq!(tx.compute_units_consumed(), None);

        // Properly formatted second last log: take slice 82..86
        let mut mid = "x".repeat(82);
        mid.push_str("1234");
        mid.push_str("rest");
        tx.logs = vec!["first".to_string(), mid.clone(), "last".to_string()];
        assert_eq!(tx.compute_units_consumed(), Some("1234"));
    }

    #[test]
    fn test_corrupt_accounts_length_in_instruction_returns_error() {
        let mut tx = create_minimal_processed_transaction();
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 42,
                accounts: vec![1, 2, 3, 4],
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            },
            stack_height: 9,
        };
        tx.inner_instructions_list = vec![vec![ii.clone()]];

        let mut bytes = tx.to_vec().unwrap();

        // Find the serialized instruction bytes inside the buffer
        let needle = ii.instruction.serialize();
        if let Some(pos) = bytes
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
        {
            // accounts length is at offset 1 of the instruction encoding, corrupt it to an impossible large value
            let accounts_len_offset = pos + 1;
            bytes[accounts_len_offset..accounts_len_offset + 4]
                .copy_from_slice(&(u32::MAX).to_le_bytes());
        } else {
            panic!("could not locate instruction bytes inside serialized transaction");
        }

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(res.is_err());
    }

    #[test]
    fn test_empty_log_messages() {
        let mut processed_transaction = create_minimal_processed_transaction();

        // Test with some empty log messages
        processed_transaction.logs = vec!["".to_string(), "Valid log".to_string(), "".to_string()];

        let result = processed_transaction.to_vec();
        assert!(result.is_ok());

        // Verify round-trip
        let serialized = result.unwrap();
        let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();
        assert_eq!(processed_transaction, deserialized);
    }

    #[test]
    fn test_no_log_messages() {
        let processed_transaction = create_minimal_processed_transaction();
        // logs is already empty in the minimal transaction

        let result = processed_transaction.to_vec();
        assert!(result.is_ok());

        // Verify round-trip
        let serialized = result.unwrap();
        let deserialized = ProcessedTransaction::from_vec(&serialized).unwrap();
        assert_eq!(processed_transaction, deserialized);
    }

    #[test]
    fn test_biggest_processed_transaction_within_max_size() {
        // Now let's create a truly maximum transaction with all fields maximized
        let runtime_transaction = crate::RuntimeTransaction {
            version: 0,
            signatures: vec![Signature::from([0xFF; 64]); 10], // Some signatures
            message: ArchMessage {
                header: MessageHeader {
                    num_required_signatures: 10,
                    num_readonly_signed_accounts: 5,
                    num_readonly_unsigned_accounts: 5,
                },
                account_keys: (0..50)
                    .map(|i| {
                        let mut bytes = [0u8; 32];
                        bytes[0] = i as u8;
                        Pubkey::from(bytes)
                    })
                    .collect(),
                instructions: vec![SanitizedInstruction {
                    program_id_index: 0,
                    accounts: (0..20).collect(),
                    data: vec![0xAA; 7923],
                }],
                recent_blockhash: Hash::from([0xFF; 32]),
            },
        };

        println!(
            "runtime_transaction.serialize().len(): {}",
            runtime_transaction.serialize().len()
        );

        // Ensure the runtime transaction is within its limit
        assert!(runtime_transaction.check_tx_size_limit().is_ok());

        let n = super::MAX_LOG_MESSAGES_COUNT;
        let base = super::MAX_LOG_MESSAGES_LEN / n; // floor
        let rem = super::MAX_LOG_MESSAGES_LEN % n; // remainder
        assert!(base <= super::LOG_MESSAGES_BYTES_LIMIT);
        let mut logs: Vec<String> = Vec::with_capacity(n);
        for i in 0..n {
            let len = base + if i < rem { 1 } else { 0 };
            logs.push("X".repeat(len));
        }

        // Build maximum-sized inner instructions list
        let max_accounts: Vec<u8> = (0..=254).collect(); // 255 accounts
        let max_data: Vec<u8> = vec![0xAB; super::MAX_CPI_INSTRUCTION_SIZE];
        let max_inner = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: u8::MAX,
                accounts: max_accounts,
                data: max_data,
            },
            stack_height: u8::MAX,
        };

        // Outer length = MAX_INSTRUCTION_COUNT_PER_TRANSACTION
        // Total inners = MAX_INNER_INSTRUCTIONS_TOTAL (1 per outer across 255 outers)
        let inner_instructions_list: Vec<Vec<InnerInstruction>> = (0
            ..arch_program::sanitized::MAX_INSTRUCTION_COUNT_PER_TRANSACTION)
            .map(|_| vec![max_inner.clone()])
            .collect();

        let processed_transaction = ProcessedTransaction {
            runtime_transaction: runtime_transaction.clone(),
            status: Status::Failed("X".repeat(super::MAX_STATUS_FAILED_MESSAGE_SIZE)), // Large error message
            bitcoin_txid: Some(Hash::from([0xFF; 32])),
            logs,
            rollback_status: RollbackStatus::Rolledback(
                "X".repeat(ROLLBACK_MESSAGE_BUFFER_SIZE - 9),
            ),
            inner_instructions_list,
        };

        let processed_transaction_serialized_len = processed_transaction.to_vec().unwrap();

        println!(
            "processed_transaction_serialized_len: {}",
            processed_transaction_serialized_len.len()
        );
        println!(
            "max_serialized_size: {}",
            ProcessedTransaction::max_serialized_size()
        );

        assert!(
            processed_transaction_serialized_len.len()
                == ProcessedTransaction::max_serialized_size()
        );
    }

    #[test]
    fn test_from_fixed_array_invalid_utf8() {
        let mut data = [0u8; ROLLBACK_MESSAGE_BUFFER_SIZE];
        data[0] = 1;
        data[1..9].copy_from_slice(&(3u64.to_le_bytes()));
        data[9..12].copy_from_slice(&[0xff, 0xff, 0xff]); // Invalid UTF-8
        let result = RollbackStatus::from_fixed_array(&data);
        assert!(matches!(
            result,
            Err(ParseProcessedTransactionError::FromUtf8Error(_))
        ));
    }

    #[test]
    fn test_from_fixed_array_msg_len_exceeds_buffer() {
        let mut data = [0u8; ROLLBACK_MESSAGE_BUFFER_SIZE];
        data[0] = 1;
        // Set msg_len to exceed available space (buffer size - 9 bytes for header)
        let invalid_msg_len = ROLLBACK_MESSAGE_BUFFER_SIZE - 8; // This will exceed when we add 9
        data[1..9].copy_from_slice(&(invalid_msg_len as u64).to_le_bytes());
        let result = RollbackStatus::from_fixed_array(&data);
        assert!(matches!(
            result,
            Err(ParseProcessedTransactionError::BufferTooShort)
        ));
    }

    #[test]
    fn test_serialization_failed_message_too_long() {
        let mut tx = create_minimal_processed_transaction();
        tx.status = super::Status::Failed("X".repeat(super::MAX_STATUS_FAILED_MESSAGE_SIZE + 1));

        let res = tx.to_vec();
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::StatusFailedMessageTooLong)
        ));
    }

    #[test]
    fn test_deserialization_failed_message_too_long() {
        // Start from a valid transaction with Failed status and short message
        let mut tx = create_minimal_processed_transaction();
        tx.status = super::Status::Failed("short".to_string());
        let mut bytes = tx.to_vec().unwrap();

        // Walk to status flag, then bump error_len beyond MAX_STATUS_FAILED_MESSAGE_SIZE
        let rollback_size = super::ROLLBACK_MESSAGE_BUFFER_SIZE;
        let mut cursor = rollback_size;
        let rt_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8 + rt_len;
        // bitcoin_txid flag
        cursor += 1;
        // logs
        let logs_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        for _ in 0..logs_len {
            let l = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
            cursor += 8 + l;
        }
        // status flag (should be 2 for Failed)
        assert_eq!(bytes[cursor], 2);
        cursor += 1;

        // Overwrite error_len to exceed limit
        let excessive: u64 = (super::MAX_STATUS_FAILED_MESSAGE_SIZE as u64) + 1;
        bytes[cursor..cursor + 8].copy_from_slice(&excessive.to_le_bytes());

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::StatusFailedMessageTooLong)
        ));
    }
    #[test]
    fn test_to_vec_too_many_outer_instructions_direct_error() {
        let mut tx = create_minimal_processed_transaction();
        let max_outer = arch_program::sanitized::MAX_INSTRUCTION_COUNT_PER_TRANSACTION;
        tx.inner_instructions_list = vec![vec![]; max_outer + 1];

        let res = tx.to_vec();
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::TooManyInstructions)
        ));
    }

    #[test]
    fn test_to_vec_too_many_inners_single_outer_direct_error() {
        let mut tx = create_minimal_processed_transaction();
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 0,
                accounts: vec![],
                data: vec![],
            },
            stack_height: 0,
        };
        tx.inner_instructions_list = vec![vec![ii; super::MAX_INNER_INSTRUCTIONS_TOTAL + 1]];

        let res = tx.to_vec();
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::TooManyInnerInstructions)
        ));
    }

    #[test]
    fn test_to_vec_total_inners_exceeds_direct_error() {
        let mut tx = create_minimal_processed_transaction();
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 0,
                accounts: vec![],
                data: vec![],
            },
            stack_height: 0,
        };

        // First outer at MAX, second with 1 -> cumulative exceeds
        tx.inner_instructions_list = vec![
            vec![ii.clone(); super::MAX_INNER_INSTRUCTIONS_TOTAL],
            vec![ii],
        ];

        let res = tx.to_vec();
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::TooManyInnerInstructions)
        ));
    }

    #[test]
    fn test_to_vec_inner_instruction_serialized_size_exceeds_direct_error() {
        let mut tx = create_minimal_processed_transaction();
        // Exceed serialized-size bound by using more than MAX_ACCOUNTS_PER_INSTRUCTION accounts
        let accounts = vec![0u8; super::MAX_ACCOUNTS_PER_INSTRUCTION + 1];
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 0,
                accounts,
                data: vec![0xAB; super::MAX_CPI_INSTRUCTION_SIZE],
            },
            stack_height: 1,
        };
        tx.inner_instructions_list = vec![vec![ii]];

        let res = tx.to_vec();
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::TooManyInnerInstructions)
        ));
    }

    #[test]
    fn test_from_vec_inner_instruction_consumed_len_exceeds_error() {
        // Start with a valid transaction with a single inner instruction
        let mut tx = create_minimal_processed_transaction();
        let ii = InnerInstruction {
            instruction: SanitizedInstruction {
                program_id_index: 0,
                accounts: vec![],
                data: vec![0x01, 0x02, 0x03],
            },
            stack_height: 1,
        };
        tx.inner_instructions_list = vec![vec![ii.clone()]];

        let mut bytes = tx.to_vec().unwrap();

        // Locate the serialized instruction in the buffer
        let needle = ii.instruction.serialize();
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .expect("instruction bytes not found");

        // Compute offset to data length: 1 (program_id_index) + 4 (accounts len) + accounts.len()
        let data_len_offset = pos + 1 + 4 + ii.instruction.accounts.len();

        // Overwrite data length to push consumed length beyond limit
        let new_len: u32 = super::MAX_CPI_INSTRUCTION_SERIALIZED_SIZE as u32;
        let old_len = u32::from_le_bytes(
            bytes[data_len_offset..data_len_offset + 4]
                .try_into()
                .unwrap(),
        );
        bytes[data_len_offset..data_len_offset + 4].copy_from_slice(&new_len.to_le_bytes());

        // Ensure the buffer has enough bytes for the larger data by appending padding
        let diff = (new_len - old_len) as usize;
        if diff > 0 {
            bytes.extend(std::iter::repeat(0u8).take(diff));
        }

        let res = ProcessedTransaction::from_vec(&bytes);
        assert!(matches!(
            res,
            Err(ParseProcessedTransactionError::TooManyInnerInstructions)
        ));
    }
}
