//! State transition types

use {
    crate::instruction::MAX_SIGNERS,
    arch_program::{
        program_error::ProgramError,
        program_option::COption,
        program_pack::{IsInitialized, Pack, Sealed},
        pubkey::{Pubkey, PUBKEY_BYTES},
    },
    arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs},
    num_enum::TryFromPrimitive,
};

/// Mint data.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Mint {
    /// Optional authority used to mint new tokens. The mint authority may only
    /// be provided during mint creation. If no mint authority is present
    /// then the mint has a fixed supply and no further tokens may be
    /// minted.
    pub mint_authority: COption<Pubkey>,
    /// Total supply of tokens.
    pub supply: u64,
    /// Number of base 10 digits to the right of the decimal place.
    pub decimals: u8,
    /// Is `true` if this structure has been initialized
    pub is_initialized: bool,
    /// Optional authority to freeze token accounts.
    pub freeze_authority: COption<Pubkey>,
}
impl Sealed for Mint {}
impl IsInitialized for Mint {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}
impl Pack for Mint {
    const LEN: usize = 82;
    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, 82];
        let (mint_authority, supply, decimals, is_initialized, freeze_authority) =
            array_refs![src, 36, 8, 1, 1, 36];
        let mint_authority = unpack_coption_key(mint_authority)?;
        let supply = u64::from_le_bytes(*supply);
        let decimals = decimals[0];
        let is_initialized = match is_initialized {
            [0] => false,
            [1] => true,
            _ => return Err(ProgramError::InvalidAccountData),
        };
        let freeze_authority = unpack_coption_key(freeze_authority)?;
        Ok(Mint {
            mint_authority,
            supply,
            decimals,
            is_initialized,
            freeze_authority,
        })
    }
    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, 82];
        let (
            mint_authority_dst,
            supply_dst,
            decimals_dst,
            is_initialized_dst,
            freeze_authority_dst,
        ) = mut_array_refs![dst, 36, 8, 1, 1, 36];
        let &Mint {
            ref mint_authority,
            supply,
            decimals,
            is_initialized,
            ref freeze_authority,
        } = self;
        pack_coption_key(mint_authority, mint_authority_dst);
        *supply_dst = supply.to_le_bytes();
        decimals_dst[0] = decimals;
        is_initialized_dst[0] = is_initialized as u8;
        pack_coption_key(freeze_authority, freeze_authority_dst);
    }
}

/// Account data.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Account {
    /// The mint associated with this account
    pub mint: Pubkey,
    /// The owner of this account.
    pub owner: Pubkey,
    /// The amount of tokens this account holds.
    pub amount: u64,
    /// If `delegate` is `Some` then `delegated_amount` represents
    /// the amount authorized by the delegate
    pub delegate: COption<Pubkey>,
    /// The account's state
    pub state: AccountState,
    /// The amount delegated
    pub delegated_amount: u64,
    /// Optional authority to close the account.
    pub close_authority: COption<Pubkey>,
}
impl Account {
    /// Checks if account is frozen
    pub fn is_frozen(&self) -> bool {
        self.state == AccountState::Frozen
    }
    /// Checks if a token Account's owner is the `system_program` or the
    /// incinerator
    pub fn is_owned_by_system_program_or_incinerator_(&self) -> bool {
        // solana_program::system_program::check_id(&self.owner)
        //     || solana_program::incinerator::check_id(&self.owner)
        true
    }
}
impl Sealed for Account {}
impl IsInitialized for Account {
    fn is_initialized(&self) -> bool {
        self.state != AccountState::Uninitialized
    }
}
impl Pack for Account {
    const LEN: usize = 164;
    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, 164];
        let (mint, owner, amount, delegate, state, delegated_amount, close_authority) =
            array_refs![src, 32, 32, 8, 36, 12, 8, 36];
        Ok(Account {
            mint: Pubkey::from_slice(mint),
            owner: Pubkey::from_slice(owner),
            amount: u64::from_le_bytes(*amount),
            delegate: unpack_coption_key(delegate)?,
            state: AccountState::try_from_primitive(state[0])
                .or(Err(ProgramError::InvalidAccountData))?,
            delegated_amount: u64::from_le_bytes(*delegated_amount),
            close_authority: unpack_coption_key(close_authority)?,
        })
    }
    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, 164];
        let (
            mint_dst,
            owner_dst,
            amount_dst,
            delegate_dst,
            state_dst,
            delegated_amount_dst,
            close_authority_dst,
        ) = mut_array_refs![dst, 32, 32, 8, 36, 12, 8, 36];
        let &Account {
            ref mint,
            ref owner,
            amount,
            ref delegate,
            state,
            delegated_amount,
            ref close_authority,
        } = self;
        mint_dst.copy_from_slice(mint.as_ref());
        owner_dst.copy_from_slice(owner.as_ref());
        *amount_dst = amount.to_le_bytes();
        pack_coption_key(delegate, delegate_dst);
        state_dst[0] = state as u8;
        *delegated_amount_dst = delegated_amount.to_le_bytes();
        pack_coption_key(close_authority, close_authority_dst);
    }
}

/// Account state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, TryFromPrimitive)]
pub enum AccountState {
    /// Account is not yet initialized
    #[default]
    Uninitialized,
    /// Account is initialized; the account owner and/or delegate may perform
    /// permitted operations on this account
    Initialized,
    /// Account has been frozen by the mint freeze authority. Neither the
    /// account owner nor the delegate are able to perform operations on
    /// this account.
    Frozen,
}

/// Multisignature data.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Multisig {
    /// Number of signers required
    pub m: u8,
    /// Number of valid signers
    pub n: u8,
    /// Is `true` if this structure has been initialized
    pub is_initialized: bool,
    /// Signer public keys
    pub signers: [Pubkey; MAX_SIGNERS],
}
impl Sealed for Multisig {}
impl IsInitialized for Multisig {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}
impl Pack for Multisig {
    const LEN: usize = 355;
    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, 355];
        #[allow(clippy::ptr_offset_with_cast)]
        let (m, n, is_initialized, signers_flat) = array_refs![src, 1, 1, 1, 32 * MAX_SIGNERS];
        let mut result = Multisig {
            m: m[0],
            n: n[0],
            is_initialized: match is_initialized {
                [0] => false,
                [1] => true,
                _ => return Err(ProgramError::InvalidAccountData),
            },
            signers: [Pubkey::from_slice(&[0u8; 32]); MAX_SIGNERS],
        };
        for (src, dst) in signers_flat.chunks(32).zip(result.signers.iter_mut()) {
            *dst = Pubkey::from_slice(src);
        }
        Ok(result)
    }
    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, 355];
        #[allow(clippy::ptr_offset_with_cast)]
        let (m, n, is_initialized, signers_flat) = mut_array_refs![dst, 1, 1, 1, 32 * MAX_SIGNERS];
        *m = [self.m];
        *n = [self.n];
        *is_initialized = [self.is_initialized as u8];
        for (i, src) in self.signers.iter().enumerate() {
            let dst_array = array_mut_ref![signers_flat, 32 * i, 32];
            dst_array.copy_from_slice(src.as_ref());
        }
    }
}

// Helpers
fn pack_coption_key(src: &COption<Pubkey>, dst: &mut [u8; 36]) {
    let (tag, body) = mut_array_refs![dst, 4, 32];
    match src {
        COption::Some(key) => {
            *tag = [1, 0, 0, 0];
            body.copy_from_slice(key.as_ref());
        }
        COption::None => {
            *tag = [0; 4];
        }
    }
}
fn unpack_coption_key(src: &[u8; 36]) -> Result<COption<Pubkey>, ProgramError> {
    let (tag, body) = array_refs![src, 4, 32];
    match *tag {
        [0, 0, 0, 0] => Ok(COption::None),
        [1, 0, 0, 0] => Ok(COption::Some(Pubkey::from_slice(body))),
        _ => Err(ProgramError::InvalidAccountData),
    }
}
#[allow(dead_code)]
fn pack_coption_u64(src: &COption<u64>, dst: &mut [u8; 12]) {
    let (tag, body) = mut_array_refs![dst, 4, 8];
    match src {
        COption::Some(amount) => {
            *tag = [1, 0, 0, 0];
            *body = amount.to_le_bytes();
        }
        COption::None => {
            *tag = [0; 4];
        }
    }
}
#[allow(dead_code)]
fn unpack_coption_u64(src: &[u8; 12]) -> Result<COption<u64>, ProgramError> {
    let (tag, body) = array_refs![src, 4, 8];
    match *tag {
        [0, 0, 0, 0] => Ok(COption::None),
        [1, 0, 0, 0] => Ok(COption::Some(u64::from_le_bytes(*body))),
        _ => Err(ProgramError::InvalidAccountData),
    }
}

const SPL_TOKEN_ACCOUNT_MINT_OFFSET: usize = 0;
const SPL_TOKEN_ACCOUNT_OWNER_OFFSET: usize = 32;

/// A trait for token Account structs to enable efficiently unpacking various
/// fields without unpacking the complete state.
pub trait GenericTokenAccount {
    /// Check if the account data is a valid token account
    fn valid_account_data(account_data: &[u8]) -> bool;

    /// Call after account length has already been verified to unpack the
    /// account owner
    fn unpack_account_owner_unchecked(account_data: &[u8]) -> &Pubkey {
        Self::unpack_pubkey_unchecked(account_data, SPL_TOKEN_ACCOUNT_OWNER_OFFSET)
    }

    /// Call after account length has already been verified to unpack the
    /// account mint
    fn unpack_account_mint_unchecked(account_data: &[u8]) -> &Pubkey {
        Self::unpack_pubkey_unchecked(account_data, SPL_TOKEN_ACCOUNT_MINT_OFFSET)
    }

    /// Call after account length has already been verified to unpack a Pubkey
    /// at the specified offset. Panics if `account_data.len()` is less than
    /// `PUBKEY_BYTES`
    fn unpack_pubkey_unchecked(account_data: &[u8], offset: usize) -> &Pubkey {
        bytemuck::from_bytes(&account_data[offset..offset + PUBKEY_BYTES])
    }

    /// Unpacks an account's owner from opaque account data.
    fn unpack_account_owner(account_data: &[u8]) -> Option<&Pubkey> {
        if Self::valid_account_data(account_data) {
            Some(Self::unpack_account_owner_unchecked(account_data))
        } else {
            None
        }
    }

    /// Unpacks an account's mint from opaque account data.
    fn unpack_account_mint(account_data: &[u8]) -> Option<&Pubkey> {
        if Self::valid_account_data(account_data) {
            Some(Self::unpack_account_mint_unchecked(account_data))
        } else {
            None
        }
    }
}

/// The offset of state field in Account's C representation
pub const ACCOUNT_INITIALIZED_INDEX: usize = 108;

/// Check if the account data buffer represents an initialized account.
/// This is checking the `state` (`AccountState`) field of an Account object.
pub fn is_initialized_account(account_data: &[u8]) -> bool {
    *account_data
        .get(ACCOUNT_INITIALIZED_INDEX)
        .unwrap_or(&(AccountState::Uninitialized as u8))
        != AccountState::Uninitialized as u8
}

impl GenericTokenAccount for Account {
    fn valid_account_data(account_data: &[u8]) -> bool {
        account_data.len() == Account::LEN && is_initialized_account(account_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_unpack_from_slice() {
        let src: [u8; 82] = [0; 82];
        let mint = Mint::unpack_from_slice(&src).unwrap();
        assert!(!mint.is_initialized);

        let mut src: [u8; 82] = [0; 82];
        src[45] = 2;
        let mint = Mint::unpack_from_slice(&src).unwrap_err();
        assert_eq!(mint, ProgramError::InvalidAccountData);
    }

    #[test]
    fn test_account_state() {
        let account_state = AccountState::default();
        assert_eq!(account_state, AccountState::Uninitialized);
    }

    #[test]
    fn test_multisig_unpack_from_slice() {
        let src: [u8; 355] = [0; 355];
        let multisig = Multisig::unpack_from_slice(&src).unwrap();
        assert_eq!(multisig.m, 0);
        assert_eq!(multisig.n, 0);
        assert!(!multisig.is_initialized);

        let mut src: [u8; 355] = [0; 355];
        src[0] = 1;
        src[1] = 1;
        src[2] = 1;
        let multisig = Multisig::unpack_from_slice(&src).unwrap();
        assert_eq!(multisig.m, 1);
        assert_eq!(multisig.n, 1);
        assert!(multisig.is_initialized);

        let mut src: [u8; 355] = [0; 355];
        src[2] = 2;
        let multisig = Multisig::unpack_from_slice(&src).unwrap_err();
        assert_eq!(multisig, ProgramError::InvalidAccountData);
    }

    #[test]
    fn test_unpack_coption_key() {
        let src: [u8; 36] = [0; 36];
        let result = unpack_coption_key(&src).unwrap();
        assert_eq!(result, COption::None);

        let mut src: [u8; 36] = [0; 36];
        src[1] = 1;
        let result = unpack_coption_key(&src).unwrap_err();
        assert_eq!(result, ProgramError::InvalidAccountData);
    }

    #[test]
    fn test_unpack_coption_u64() {
        let src: [u8; 12] = [0; 12];
        let result = unpack_coption_u64(&src).unwrap();
        assert_eq!(result, COption::None);

        let mut src: [u8; 12] = [0; 12];
        src[0] = 1;
        let result = unpack_coption_u64(&src).unwrap();
        assert_eq!(result, COption::Some(0));

        let mut src: [u8; 12] = [0; 12];
        src[1] = 1;
        let result = unpack_coption_u64(&src).unwrap_err();
        assert_eq!(result, ProgramError::InvalidAccountData);
    }

    #[test]
    fn test_unpack_token_owner() {
        // Account data length < Account::LEN, unpack will not return a key
        let src: [u8; 12] = [0; 12];
        let result = Account::unpack_account_owner(&src);
        assert_eq!(result, Option::None);

        // The right account data size and initialized, unpack will return some key
        let mut src: [u8; Account::LEN] = [0; Account::LEN];
        src[ACCOUNT_INITIALIZED_INDEX] = AccountState::Initialized as u8;
        let result = Account::unpack_account_owner(&src);
        assert!(result.is_some());

        // The right account data size and frozen, unpack will return some key
        src[ACCOUNT_INITIALIZED_INDEX] = AccountState::Frozen as u8;
        let result = Account::unpack_account_owner(&src);
        assert!(result.is_some());

        // The right account data size and uninitialized, unpack will return None
        src[ACCOUNT_INITIALIZED_INDEX] = AccountState::Uninitialized as u8;
        let result = Account::unpack_account_mint(&src);
        assert_eq!(result, Option::None);

        // Account data length > account data size, unpack will not return a key
        let src: [u8; Account::LEN + 5] = [0; Account::LEN + 5];
        let result = Account::unpack_account_owner(&src);
        assert_eq!(result, Option::None);
    }

    #[test]
    fn test_unpack_token_mint() {
        // Account data length < Account::LEN, unpack will not return a key
        let src: [u8; 12] = [0; 12];
        let result = Account::unpack_account_mint(&src);
        assert_eq!(result, Option::None);

        // The right account data size and initialized, unpack will return some key
        let mut src: [u8; Account::LEN] = [0; Account::LEN];
        src[ACCOUNT_INITIALIZED_INDEX] = AccountState::Initialized as u8;
        let result = Account::unpack_account_mint(&src);
        assert!(result.is_some());

        // The right account data size and frozen, unpack will return some key
        src[ACCOUNT_INITIALIZED_INDEX] = AccountState::Frozen as u8;
        let result = Account::unpack_account_mint(&src);
        assert!(result.is_some());

        // The right account data size and uninitialized, unpack will return None
        src[ACCOUNT_INITIALIZED_INDEX] = AccountState::Uninitialized as u8;
        let result = Account::unpack_account_mint(&src);
        assert_eq!(result, Option::None);

        // Account data length > account data size, unpack will not return a key
        let src: [u8; Account::LEN + 5] = [0; Account::LEN + 5];
        let result = Account::unpack_account_mint(&src);
        assert_eq!(result, Option::None);
    }
}
