use bitcode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

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
pub struct Block {
    pub transactions: Vec<String>,
    pub previous_block_hash: String,
    pub timestamp: u128,
    pub bitcoin_block_height: u64,
    pub transaction_count: u64,
    pub merkle_root: String,
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

        // Serialize bitcoin block height
        serialized.extend_from_slice(&self.bitcoin_block_height.to_le_bytes());

        // Serialize transaction_count
        serialized.extend_from_slice(&self.transaction_count.to_le_bytes());

        // Serialize merkle_root
        serialized.extend_from_slice(self.merkle_root.as_bytes());
        serialized.push(0); // Null terminator

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

        // Deserialize bitcoin_block_height
        let bitcoin_block_height = read_u64(data, &mut cursor)?;

        // Deserialize transaction_count
        let transaction_count = read_u64(data, &mut cursor)?;

        // Deserialize merkle_root
        let merkle_root = read_string(data, &mut cursor)?;

        // Deserialize transactions
        let transactions_len = read_u64(data, &mut cursor)?;
        let mut transactions = Vec::with_capacity(transactions_len as usize);
        for _ in 0..transactions_len {
            transactions.push(read_string(data, &mut cursor)?);
        }

        Ok(Block {
            transactions,
            previous_block_hash,
            timestamp,
            bitcoin_block_height,
            transaction_count,
            merkle_root,
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

#[cfg(test)]
mod tests {
    use super::*;
    const GENESIS_BLOCK_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_block_serialization_deserialization() {
        let original_block = Block {
            transactions: vec!["tx1".to_string(), "tx2".to_string()],
            previous_block_hash: GENESIS_BLOCK_HASH.to_string(),
            timestamp: 1630000000,
            bitcoin_block_height: 100,
            transaction_count: 2,
            merkle_root: "merkle_root_hash".to_string(),
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
        assert_eq!(original_block.merkle_root, deserialized_block.merkle_root);
    }

    #[test]
    fn test_block_hash() {
        let block = Block {
            transactions: vec!["tx1".to_string(), "tx2".to_string()],
            previous_block_hash: GENESIS_BLOCK_HASH.to_string(),
            timestamp: 1630000000,
            bitcoin_block_height: 100,
            transaction_count: 2,
            merkle_root: "merkle_root_hash".to_string(),
        };

        let hash = block.hash();
        assert!(!hash.is_empty(), "Block hash should not be empty");
        assert_eq!(hash.len(), 64, "Block hash should be 64 characters long");
    }
}
