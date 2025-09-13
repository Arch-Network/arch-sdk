#![allow(clippy::arithmetic_side_effects)]
// Remove the following `allow` when `StakeState` is removed, required to avoid
// warnings from uses of deprecated types during trait derivations.
#![allow(deprecated)]

use {
    super::history::StakeHistoryEntry,
    crate::{instruction::InstructionError, pubkey::Pubkey, stake::instruction::StakeError},
    borsh::{BorshDeserialize, BorshSerialize},
    std::collections::HashSet,
};

pub type StakeActivationStatus = StakeHistoryEntry;

// means that no more than RATE of current effective stake may be added or subtracted per
// epoch
pub const DEFAULT_SLASH_PENALTY: u8 = ((5 * u8::MAX as usize) / 100) as u8;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone, Copy)]
#[allow(clippy::large_enum_variant)]
pub enum StakeState {
    #[default]
    Uninitialized,
    Initialized(Authorized),
    Stake(Authorized, Delegation),
}

impl StakeState {
    /// The fixed number of bytes used to serialize each stake account
    pub const fn size_of() -> usize {
        128
    }

    pub fn delegation(&self) -> Option<Delegation> {
        match self {
            StakeState::Stake(_meta, delegation) => Some(*delegation),
            _ => None,
        }
    }

    pub fn authorized(&self) -> Option<Authorized> {
        match self {
            StakeState::Stake(meta, _delegation) => Some(*meta),
            StakeState::Initialized(meta) => Some(*meta),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum StakeAuthorize {
    Staker,
    Withdrawer,
}

#[derive(
    Default,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Clone,
    Copy,
    BorshDeserialize,
    BorshSerialize,
)]
#[borsh(crate = "borsh")]
pub struct Authorized {
    pub staker: Pubkey,
    pub withdrawer: Pubkey,
}

impl Authorized {
    pub fn auto(authorized: &Pubkey) -> Self {
        Self {
            staker: *authorized,
            withdrawer: *authorized,
        }
    }
    pub fn check(
        &self,
        signers: &HashSet<Pubkey>,
        stake_authorize: StakeAuthorize,
    ) -> Result<(), InstructionError> {
        match stake_authorize {
            StakeAuthorize::Staker if signers.contains(&self.staker) => Ok(()),
            StakeAuthorize::Withdrawer if signers.contains(&self.withdrawer) => Ok(()),
            _ => Err(InstructionError::MissingRequiredSignature),
        }
    }

    pub fn authorize(
        &mut self,
        signers: &HashSet<Pubkey>,
        new_authorized: &Pubkey,
        stake_authorize: StakeAuthorize,
    ) -> Result<(), InstructionError> {
        match stake_authorize {
            StakeAuthorize::Staker => {
                // Allow either the staker or the withdrawer to change the staker key
                if !signers.contains(&self.staker) && !signers.contains(&self.withdrawer) {
                    return Err(InstructionError::MissingRequiredSignature);
                }
                self.staker = *new_authorized
            }
            StakeAuthorize::Withdrawer => {
                self.check(signers, stake_authorize)?;
                self.withdrawer = *new_authorized
            }
        }
        Ok(())
    }
}

#[derive(
    Debug, Serialize, Deserialize, PartialEq, Clone, Copy, BorshDeserialize, BorshSerialize,
)]
#[borsh(crate = "borsh")]
pub struct Delegation {
    /// to whom the stake is delegated
    pub voter_pubkey: Pubkey,
    /// activated stake amount, set at delegate() time
    pub stake: u64,
    /// epoch at which this stake was activated, std::Epoch::MAX if is a bootstrap stake
    pub activation_epoch: u64,
    /// epoch the stake was deactivated, std::Epoch::MAX if not deactivated
    pub deactivation_epoch: u64,
}

impl Default for Delegation {
    fn default() -> Self {
        #[allow(deprecated)]
        Self {
            voter_pubkey: Pubkey::default(),
            stake: 0,
            activation_epoch: 0,
            deactivation_epoch: u64::MAX,
        }
    }
}

impl Delegation {
    pub fn new(voter_pubkey: &Pubkey, stake: u64, activation_epoch: u64) -> Self {
        Self {
            voter_pubkey: *voter_pubkey,
            stake,
            activation_epoch,
            ..Delegation::default()
        }
    }

    pub fn deactivate(&mut self, epoch: u64) -> Result<(), StakeError> {
        if self.deactivation_epoch != u64::MAX {
            Err(StakeError::AlreadyDeactivated)
        } else {
            self.deactivation_epoch = epoch;
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::stake::state::StakeState;

    #[test]
    fn test_size_of() {
        assert_eq!(StakeState::size_of(), std::mem::size_of::<StakeState>());
    }
}
