//! Resharing account details.

use crate::account::{AccountMeta, SHARED_VALIDATOR_DATA_ACCOUNT_ID};
use crate::instruction::{Instruction, InstructionError};
use crate::pubkey::Pubkey;
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::HashSet;

crate::declare_id!("Resharing1111111111111111111111111111111111");

/// Backwards-compatible alias for the resharing program ID.
pub const RESHARING_PROGRAM_ID: Pubkey = ID;

pub mod data_account {
    crate::declare_id!("ResharingData111111111111111111111111111111");
}

/// 10 way sharding of the staging data account.
pub mod staging_account {
    crate::declare_id!("ResharingStaging111111111111111111111111111");
}

pub mod shard_account_1 {
    crate::declare_id!("ResharingShard11111111111111111111111111111");
}

pub mod shard_account_2 {
    crate::declare_id!("ResharingShard22222222222222222222222222222");
}

pub mod shard_account_3 {
    crate::declare_id!("ResharingShard33333333333333333333333333333");
}

pub mod shard_account_4 {
    crate::declare_id!("ResharingShard44444444444444444444444444444");
}

pub mod shard_account_5 {
    crate::declare_id!("ResharingShard55555555555555555555555555555");
}

pub mod shard_account_6 {
    crate::declare_id!("ResharingShard66666666666666666666666666666");
}

pub mod shard_account_7 {
    crate::declare_id!("ResharingShard77777777777777777777777777777");
}

pub mod shard_account_8 {
    crate::declare_id!("ResharingShard88888888888888888888888888888");
}

pub mod shard_account_9 {
    crate::declare_id!("ResharingShard99999999999999999999999999999");
}

pub mod shard_account_10 {
    crate::declare_id!("ResharingShardaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

/// Backwards-compatible alias for the resharing data account ID.
pub const RESHARING_DATA_ACCOUNT_ID: Pubkey = data_account::ID;

/// Backwards-compatible alias for the resharing shard account IDs.
pub const RESHARING_STAGING_SHARD_1_ACCOUNT_ID: Pubkey = shard_account_1::ID;
pub const RESHARING_STAGING_SHARD_2_ACCOUNT_ID: Pubkey = shard_account_2::ID;
pub const RESHARING_STAGING_SHARD_3_ACCOUNT_ID: Pubkey = shard_account_3::ID;
pub const RESHARING_STAGING_SHARD_4_ACCOUNT_ID: Pubkey = shard_account_4::ID;
pub const RESHARING_STAGING_SHARD_5_ACCOUNT_ID: Pubkey = shard_account_5::ID;
pub const RESHARING_STAGING_SHARD_6_ACCOUNT_ID: Pubkey = shard_account_6::ID;
pub const RESHARING_STAGING_SHARD_7_ACCOUNT_ID: Pubkey = shard_account_7::ID;
pub const RESHARING_STAGING_SHARD_8_ACCOUNT_ID: Pubkey = shard_account_8::ID;
pub const RESHARING_STAGING_SHARD_9_ACCOUNT_ID: Pubkey = shard_account_9::ID;
pub const RESHARING_STAGING_SHARD_10_ACCOUNT_ID: Pubkey = shard_account_10::ID;

pub const CHUNK_SIZE: u64 = 8192;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone)]
pub enum ResharingShardInstruction {
    /// Info about the chunk in a shard.
    Chunk(ShardChunk),

    /// Instruction to aggregate the chunks.
    Aggregate(ShardAggregate),
}

/// Info about the chunk in a shard.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone)]
pub struct ShardChunk {
    /// If this is the first chunk in the shard.
    pub first_chunk: bool,

    /// Byte offset of the chunk in the shard.
    pub start_offset: u64,

    /// Chunk data.
    pub chunk: Vec<u8>,
}

/// Info for agggeating from the shards.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone)]
pub struct ShardAggregate {
    /// Total size of the data.
    pub total_size: u64,

    /// Shards to aggregate from.
    /// (shard account key, data size in the shard).
    pub shards: Vec<(Pubkey, u64)>,
}

impl ResharingShardInstruction {
    /// Helper to build the chunk instruction.
    pub fn shard_chunk(
        first_chunk: bool,
        start_offset: u64,
        chunk: Vec<u8>,
        authority_pubkey: Pubkey,
        shard_account: Pubkey,
    ) -> Result<Instruction, InstructionError> {
        let instruction = Self::Chunk(ShardChunk {
            first_chunk,
            start_offset,
            chunk,
        });
        let mut data = Vec::new();
        BorshSerialize::serialize(&instruction, &mut data)
            .map_err(|err| InstructionError::BorshIoError(err.to_string()))?;
        Ok(Instruction {
            program_id: RESHARING_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(authority_pubkey, true),
                AccountMeta::new_readonly(Pubkey::from(SHARED_VALIDATOR_DATA_ACCOUNT_ID), false),
                AccountMeta::new(shard_account, false),
            ],
            data,
        })
    }

    /// Helper to build the aggregate instruction.
    pub fn shard_aggregate(
        total_size: u64,
        shards: Vec<(Pubkey, u64)>,
        authority_pubkey: Pubkey,
        data_account: Pubkey,
    ) -> Result<Instruction, InstructionError> {
        let shard_accounts: Vec<_> = shards
            .iter()
            .map(|(shard_account, _)| AccountMeta::new_readonly(*shard_account, false))
            .collect();

        let instruction = Self::Aggregate(ShardAggregate { total_size, shards });
        let mut data = Vec::new();
        BorshSerialize::serialize(&instruction, &mut data)
            .map_err(|err| InstructionError::BorshIoError(err.to_string()))?;

        let mut accounts = vec![
            AccountMeta::new_readonly(authority_pubkey, true),
            AccountMeta::new_readonly(Pubkey::from(SHARED_VALIDATOR_DATA_ACCOUNT_ID), false),
            AccountMeta::new(data_account, false),
        ];
        accounts.extend(shard_accounts);

        Ok(Instruction {
            program_id: RESHARING_PROGRAM_ID,
            accounts,
            data,
        })
    }
}

pub fn staging_shard_accounts() -> HashSet<Pubkey> {
    HashSet::from_iter([
        RESHARING_STAGING_SHARD_1_ACCOUNT_ID,
        RESHARING_STAGING_SHARD_2_ACCOUNT_ID,
        RESHARING_STAGING_SHARD_3_ACCOUNT_ID,
        RESHARING_STAGING_SHARD_4_ACCOUNT_ID,
        RESHARING_STAGING_SHARD_5_ACCOUNT_ID,
        RESHARING_STAGING_SHARD_6_ACCOUNT_ID,
        RESHARING_STAGING_SHARD_7_ACCOUNT_ID,
        RESHARING_STAGING_SHARD_8_ACCOUNT_ID,
        RESHARING_STAGING_SHARD_9_ACCOUNT_ID,
        RESHARING_STAGING_SHARD_10_ACCOUNT_ID,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staging_shard_accounts() {
        let accounts = staging_shard_accounts();
        assert_eq!(accounts.len(), 10);
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_1_ACCOUNT_ID));
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_2_ACCOUNT_ID));
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_3_ACCOUNT_ID));
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_4_ACCOUNT_ID));
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_5_ACCOUNT_ID));
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_6_ACCOUNT_ID));
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_7_ACCOUNT_ID));
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_8_ACCOUNT_ID));
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_9_ACCOUNT_ID));
        assert!(accounts.contains(&RESHARING_STAGING_SHARD_10_ACCOUNT_ID));
    }
}
