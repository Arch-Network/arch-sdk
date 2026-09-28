//! Resharing data types.

use borsh::{BorshDeserialize, BorshSerialize};
use std::io::{Read, Write};
use thiserror::Error;

use crate::pubkey::Pubkey;

const RESHARING_STATE_PREFIX: u64 = u64::MAX;

/// Instruction for writing and aggregating resharing transcript shards.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone)]
pub enum ResharingShardInstruction {
    /// Info about a chunk in a shard.
    Chunk(ShardChunk),

    /// Instruction to aggregate the chunks.
    Aggregate(ShardAggregate),
}

/// Info about a chunk in a shard.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone)]
pub struct ShardChunk {
    /// If this is the first chunk in the shard.
    pub first_chunk: bool,

    /// Byte offset of the chunk in the shard.
    pub start_offset: u64,

    /// Chunk data.
    pub chunk: Vec<u8>,
}

/// Info for aggregating data from the shards.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone)]
pub struct ShardAggregate {
    /// Total size of the serialized transcript.
    pub total_size: u64,

    /// Shards to aggregate from.
    /// (shard account key, data size in the shard).
    pub shards: Vec<(Pubkey, u64)>,
}

/// Resharing state version.
#[derive(Debug, Clone, PartialEq)]
pub enum ResharingStateVersion {
    V1,
}

impl ResharingStateVersion {
    pub fn to_u64(&self) -> u64 {
        match self {
            Self::V1 => 1,
        }
    }
}

impl TryFrom<u64> for ResharingStateVersion {
    type Error = ResharingStateError;

    fn try_from(val: u64) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(Self::V1),
            _ => Err(ResharingStateError::UnsupportedVersion(val)),
        }
    }
}

/// State kept in the RESHARING_DATA_ACCOUNT_ID account.
#[derive(Debug, Clone)]
pub struct ResharingStateV1 {
    /// Serialized public key package from the previous epoch.
    pub prev_pubkey_package: Vec<u8>,

    /// Transctipt for the cuurrent epoch.
    pub transcript: Vec<u8>,
}

pub type ResharingState = ResharingStateV1;

#[derive(Debug, Error)]
pub enum ResharingStateError {
    #[error("Invalid resharing state prefix: {0:#x}")]
    InvalidPrefix(u64),

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u64),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl ResharingStateV1 {
    pub fn new(prev_pubkey_package: Vec<u8>, transcript: Vec<u8>) -> Self {
        Self {
            transcript,
            prev_pubkey_package,
        }
    }

    /// Serialize the state.
    pub fn to_vec(&self) -> Result<Vec<u8>, ResharingStateError> {
        let mut writer = Vec::new();
        writer.write_all(&RESHARING_STATE_PREFIX.to_le_bytes())?;
        writer.write_all(&ResharingStateVersion::V1.to_u64().to_le_bytes())?;

        writer.write_all(&(self.transcript.len() as u64).to_le_bytes())?;
        writer.write_all(&self.transcript)?;

        writer.write_all(&(self.prev_pubkey_package.len() as u64).to_le_bytes())?;
        writer.write_all(&self.prev_pubkey_package)?;
        Ok(writer)
    }

    /// Deserialize the state from the bytes.
    pub fn from_vec(data: &[u8]) -> Result<Self, ResharingStateError> {
        let mut reader = std::io::Cursor::new(data);

        let read_u64 = |reader: &mut std::io::Cursor<&[u8]>| -> std::io::Result<u64> {
            let mut bytes = [0_u8; 8];
            reader.read_exact(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        };

        let prefix = read_u64(&mut reader)?;
        if prefix != RESHARING_STATE_PREFIX {
            return Err(ResharingStateError::InvalidPrefix(prefix));
        }

        let version = read_u64(&mut reader)?;
        ResharingStateVersion::try_from(version)?;

        let read_bytes = |reader: &mut std::io::Cursor<&[u8]>| -> std::io::Result<Vec<u8>> {
            let len = read_u64(reader)?;
            let len = usize::try_from(len).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Resharing state field length does not fit usize",
                )
            })?;
            let position = usize::try_from(reader.position()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Resharing state cursor position does not fit usize",
                )
            })?;
            let remaining = data.len().checked_sub(position).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid resharing state cursor position",
                )
            })?;
            if len > remaining {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Resharing state field exceeds remaining data",
                ));
            }

            let mut bytes = vec![0_u8; len];
            reader.read_exact(&mut bytes)?;
            Ok(bytes)
        };

        let transcript = read_bytes(&mut reader)?;
        let prev_pubkey_package = read_bytes(&mut reader)?;
        if reader.position() != data.len() as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Trailing bytes in resharing state",
            )
            .into());
        }

        Ok(Self {
            transcript,
            prev_pubkey_package,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resharing_state_version() {
        let version = ResharingStateVersion::V1;
        assert_eq!(version.to_u64(), 1);

        assert!(matches!(
            ResharingStateVersion::try_from(0_u64),
            Err(ResharingStateError::UnsupportedVersion(0))
        ));

        assert!(matches!(
            ResharingStateVersion::try_from(100_u64),
            Err(ResharingStateError::UnsupportedVersion(100))
        ));
    }

    #[test]
    fn resharing_state_v1_roundtrip() {
        let state = ResharingStateV1::new(vec![1, 2, 3], vec![4, 5, 6, 7]);
        let serialized = state.to_vec().unwrap();
        let restored = ResharingStateV1::from_vec(&serialized).unwrap();

        assert_eq!(&serialized[..8], &[0xFF; 8]);
        assert_eq!(restored.transcript, state.transcript);
        assert_eq!(restored.prev_pubkey_package, state.prev_pubkey_package);
    }

    #[test]
    fn resharing_state_v1_rejects_invalid_encoding() {
        let state = ResharingStateV1::new(vec![1, 2, 3], vec![4, 5]);
        let serialized = state.to_vec().unwrap();

        let mut invalid_prefix = serialized.clone();
        invalid_prefix[..8].copy_from_slice(&0_u64.to_le_bytes());
        assert!(matches!(
            ResharingStateV1::from_vec(&invalid_prefix),
            Err(ResharingStateError::InvalidPrefix(0))
        ));

        let mut unsupported = serialized.clone();
        unsupported[8..16].copy_from_slice(&2_u64.to_le_bytes());
        assert!(matches!(
            ResharingStateV1::from_vec(&unsupported),
            Err(ResharingStateError::UnsupportedVersion(2))
        ));

        for len in 0..serialized.len() {
            assert!(
                ResharingStateV1::from_vec(&serialized[..len]).is_err(),
                "accepted truncated encoding of length {len}"
            );
        }

        let mut oversized = serialized.clone();
        oversized[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(ResharingStateV1::from_vec(&oversized).is_err());

        let mut trailing = serialized;
        trailing.push(0);
        assert!(ResharingStateV1::from_vec(&trailing).is_err());
    }
}
