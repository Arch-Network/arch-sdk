//! Resharing account details.

use crate::pubkey::Pubkey;
use borsh::{BorshDeserialize, BorshSerialize};

crate::declare_id!("Resharing1111111111111111111111111111111111");

/// Backwards-compatible alias for the resharing program ID.
pub const RESHARING_PROGRAM_ID: Pubkey = ID;

pub mod data_account {
    crate::declare_id!("ResharingData111111111111111111111111111111");
}

pub mod staging_account {
    crate::declare_id!("ResharingStaging111111111111111111111111111");
}

/// Backwards-compatible alias for the resharing data account ID.
pub const RESHARING_DATA_ACCOUNT_ID: Pubkey = data_account::ID;
/// Backwards-compatible alias for the resharing staging account ID.
pub const RESHARING_STAGING_ACCOUNT_ID: Pubkey = staging_account::ID;

pub const CHUNK_SIZE: u64 = 8192;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone)]
pub struct ResharingInstruction {
    /// If this is the first chunk.
    pub first_chunk: bool,

    /// If this is the last chunk.
    pub last_chunk: bool,

    /// Start offset of the chunk.
    pub start_offset: u64,

    /// Chunk data.
    pub chunk: Vec<u8>,
}
