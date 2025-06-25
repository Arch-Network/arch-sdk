use bitcode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "fuzzing")]
use libfuzzer_sys::arbitrary;
use serde::{Deserialize, Serialize};

use super::ProcessedTransaction;
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 1024;

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum BlockParseError {
    #[error("Invalid bytes")]
    InvalidBytes,
    #[error("Invalid string")]
    InvalidString,
    #[error("Invalid u64")]
    InvalidU64,
    #[error("Invalid u128")]
    InvalidU128,
    #[error("Invalid transactions length")]
    InvalidTransactionsLength,
}

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Encode,
    Decode,
    Eq,
)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]

pub struct Block {
    pub transactions: Vec<String>,
    pub previous_block_hash: String,
    pub timestamp: u128,
    pub block_height: u64,
    pub bitcoin_block_height: u64,
    pub transaction_count: u64,
}

impl Block {
    pub fn hash(&self) -> String {
        let serialized_block = self.to_vec();
        sha256::digest(sha256::digest(serialized_block))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut serialized = Vec::new();

        // Serialize previous_block_hash
        serialized.extend_from_slice(self.previous_block_hash.as_bytes());
        serialized.push(0); // Null terminator

        // Serialize timestamp
        serialized.extend_from_slice(&self.timestamp.to_le_bytes());

        // Serialize block height
        serialized.extend_from_slice(&self.block_height.to_le_bytes());

        // Serialize bitcoin block height
        serialized.extend_from_slice(&self.bitcoin_block_height.to_le_bytes());

        // Serialize transaction_count
        serialized.extend_from_slice(&self.transaction_count.to_le_bytes());

        // Serialize transactions
        serialized.extend_from_slice(&(self.transactions.len() as u64).to_le_bytes());
        for transaction in &self.transactions {
            serialized.extend_from_slice(transaction.as_bytes());
            serialized.push(0); // Null terminator
        }

        serialized
    }

    pub fn from_vec(data: &[u8]) -> Result<Self, BlockParseError> {
        let mut cursor = 0;

        // Deserialize previous_block_hash
        let previous_block_hash = read_string(data, &mut cursor)?;

        // Deserialize timestamp
        let timestamp = read_u128(data, &mut cursor)?;

        // Deserialize block height
        let block_height = read_u64(data, &mut cursor)?;

        // Deserialize bitcoin_block_height
        let bitcoin_block_height = read_u64(data, &mut cursor)?;

        // Deserialize transaction_count
        let transaction_count = read_u64(data, &mut cursor)?;

        // Deserialize transactions
        let transactions_len = read_u64(data, &mut cursor)?;

        if transactions_len > MAX_TRANSACTIONS_PER_BLOCK as u64 {
            return Err(BlockParseError::InvalidTransactionsLength);
        }
        let mut transactions = Vec::with_capacity(transactions_len as usize);
        for _ in 0..transactions_len {
            transactions.push(read_string(data, &mut cursor)?);
        }

        Ok(Block {
            transactions,
            previous_block_hash,
            timestamp,
            block_height,
            bitcoin_block_height,
            transaction_count,
        })
    }
}

fn read_string(data: &[u8], cursor: &mut usize) -> Result<String, BlockParseError> {
    let start = *cursor;
    while *cursor < data.len() && data[*cursor] != 0 {
        *cursor += 1;
    }
    if *cursor == data.len() {
        return Err(BlockParseError::InvalidBytes);
    }
    let result = String::from_utf8(data[start..*cursor].to_vec())
        .map_err(|_| BlockParseError::InvalidBytes)?;
    *cursor += 1; // Skip null terminator
    Ok(result)
}

fn read_u64(data: &[u8], cursor: &mut usize) -> Result<u64, BlockParseError> {
    if *cursor + 8 > data.len() {
        return Err(BlockParseError::InvalidBytes);
    }
    let result = u64::from_le_bytes(data[*cursor..*cursor + 8].try_into().unwrap());
    *cursor += 8;
    Ok(result)
}

fn read_u128(data: &[u8], cursor: &mut usize) -> Result<u128, BlockParseError> {
    if *cursor + 16 > data.len() {
        return Err(BlockParseError::InvalidBytes);
    }
    let result = u128::from_le_bytes(data[*cursor..*cursor + 16].try_into().unwrap());
    *cursor += 16;
    Ok(result)
}

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Encode,
    Decode,
)]
pub struct FullBlock {
    pub transactions: Vec<ProcessedTransaction>,
    pub previous_block_hash: String,
    pub timestamp: u128,
    pub block_height: u64,
    pub bitcoin_block_height: u64,
    pub transaction_count: u64,
}

impl From<(Block, Vec<ProcessedTransaction>)> for FullBlock {
    fn from(value: (Block, Vec<ProcessedTransaction>)) -> Self {
        FullBlock {
            transactions: value.1,
            previous_block_hash: value.0.previous_block_hash,
            timestamp: value.0.timestamp,
            block_height: value.0.block_height,
            bitcoin_block_height: value.0.bitcoin_block_height,
            transaction_count: value.0.transaction_count,
        }
    }
}

impl FullBlock {
    pub fn hash(&self) -> String {
        // Create Block without cloning the entire FullBlock
        let block = Block {
            transactions: self.transactions.iter().map(|t| t.txid()).collect(),
            previous_block_hash: self.previous_block_hash.clone(),
            timestamp: self.timestamp,
            bitcoin_block_height: self.bitcoin_block_height,
            transaction_count: self.transaction_count,
            block_height: self.block_height,
        };
        block.hash()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        // Create Block without cloning the entire FullBlock
        let block = Block {
            transactions: self.transactions.iter().map(|t| t.txid()).collect(),
            previous_block_hash: self.previous_block_hash.clone(),
            timestamp: self.timestamp,
            bitcoin_block_height: self.bitcoin_block_height,
            transaction_count: self.transaction_count,
            block_height: self.block_height,
        };
        block.to_vec()
    }
}

impl From<FullBlock> for Block {
    fn from(value: FullBlock) -> Self {
        Block {
            transactions: value.transactions.into_iter().map(|t| t.txid()).collect(),
            previous_block_hash: value.previous_block_hash,
            timestamp: value.timestamp,
            bitcoin_block_height: value.bitcoin_block_height,
            transaction_count: value.transaction_count,
            block_height: value.block_height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GENESIS_BLOCK_PREVIOUS_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_block_serialization_deserialization() {
        let original_block = Block {
            transactions: vec!["tx1".to_string(), "tx2".to_string()],
            previous_block_hash: GENESIS_BLOCK_PREVIOUS_HASH.to_string(),
            timestamp: 1630000000,
            block_height: 100,
            bitcoin_block_height: 100,
            transaction_count: 2,
        };

        let serialized_data = original_block.to_vec();
        let deserialized_block = Block::from_vec(&serialized_data).expect("Deserialization failed");

        assert_eq!(
            original_block.previous_block_hash,
            deserialized_block.previous_block_hash
        );
        assert_eq!(original_block.transactions, deserialized_block.transactions);
        assert_eq!(original_block.timestamp, deserialized_block.timestamp);
        assert_eq!(
            original_block.transaction_count,
            deserialized_block.transaction_count
        );
    }

    #[test]
    fn test_block_hash() {
        let block = Block {
            transactions: vec!["tx1".to_string(), "tx2".to_string()],
            previous_block_hash: GENESIS_BLOCK_PREVIOUS_HASH.to_string(),
            timestamp: 1630000000,
            block_height: 100,
            bitcoin_block_height: 100,
            transaction_count: 2,
        };

        let hash = block.hash();
        assert!(!hash.is_empty(), "Block hash should not be empty");
        assert_eq!(hash.len(), 64, "Block hash should be 64 characters long");
    }
}
