use num_derive::{FromPrimitive, ToPrimitive};
use thiserror::Error;

use crate::account::AccountMeta;
use crate::decode_error::DecodeError;
use crate::instruction::Instruction;
use crate::nonce::NONCE_ACCOUNT_LENGTH;
use crate::pubkey::Pubkey;
use crate::system_program::SYSTEM_PROGRAM_ID;

#[derive(Error, Debug, Serialize, Clone, PartialEq, Eq, FromPrimitive, ToPrimitive)]
pub enum SystemError {
    #[error("an account with the same address already exists")]
    AccountAlreadyInUse,
    #[error("account does not have enough ARCH to perform the operation")]
    ResultWithNegativeLamports,
    #[error("cannot assign account to this program id")]
    InvalidProgramId,
    #[error("cannot allocate account data of this length")]
    InvalidAccountDataLength,
    #[error("length of requested seed is too long")]
    MaxSeedLengthExceeded,
    #[error("provided address does not match addressed derived from seed")]
    AddressWithSeedMismatch,
    #[error("nonce was already advanced in this block")]
    NonceAlreadyAdvanced,
}

impl<T> DecodeError<T> for SystemError {
    fn type_of() -> &'static str {
        "SystemError"
    }
}

#[derive(
    Serialize, Deserialize, Debug, Clone, PartialEq, Eq, wincode::SchemaWrite, wincode::SchemaRead,
)]
pub enum SystemInstruction {
    /// Create a new account
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE, SIGNER]` New account
    CreateAccount {
        /// Number of lamports to transfer to the new account
        lamports: u64,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Address of program that will own the new account
        owner: Pubkey,
    },

    /// Assign account to a program
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Assigned account public key
    Assign {
        /// Owner program account
        owner: Pubkey,
    },

    SignInput {
        index: u32,
    },

    /// Transfer lamports
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE]` Recipient account
    Transfer {
        lamports: u64,
    },

    /// Allocate space in a (possibly new) account without funding
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` New account
    Allocate {
        /// Number of bytes of memory to allocate
        space: u64,
    },

    /// Create a new account at an address derived from a base pubkey and a seed
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE]` Created account
    ///   2. `[SIGNER]` (optional) Base account; the account matching the base Pubkey below must be
    ///      provided as a signer, but may be the same as the funding account
    ///      and provided as account 0
    CreateAccountWithSeed {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `Pubkey::MAX_SEED_LEN`
        seed: String,

        /// Number of lamports to transfer to the new account
        lamports: u64,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Owner program account address
        owner: Pubkey,
    },

    /// Allocate space for and assign an account at an address
    /// derived from a base public key and a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Allocated account
    ///   1. `[SIGNER]` Base account
    AllocateWithSeed {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: String,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Owner program account
        owner: Pubkey,
    },

    /// Assign account to a program based on a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Assigned account
    ///   1. `[SIGNER]` Base account
    AssignWithSeed {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: String,

        /// Owner program account
        owner: Pubkey,
    },

    /// Transfer lamports from a derived address
    ///
    /// # Account references
    ///   0. `[WRITE]` Funding account
    ///   1. `[SIGNER]` Base for funding account
    ///   2. `[WRITE]` Recipient account
    TransferWithSeed {
        /// Amount to transfer
        lamports: u64,

        /// Seed to use to derive the funding account address
        from_seed: String,

        /// Owner to use to derive the funding account address
        from_owner: Pubkey,
    },

    /// Consume a stored nonce, replacing it with the value for the current
    /// block. At most one advance per nonce account per block.
    ///
    /// As the first instruction of a transaction, this makes it a
    /// durable-nonce transaction: its `recent_blockhash` must be the stored
    /// nonce, and the advance is committed even if a later instruction fails.
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[SIGNER]` Nonce authority
    AdvanceNonceAccount,

    /// Withdraw funds from a nonce account
    ///
    /// The `u64` parameter is the lamports to withdraw, which must leave the
    /// account balance at or above the rent-exempt minimum, or at zero. A
    /// withdrawal to zero closes the account (clears its data); an initialized
    /// nonce account cannot be closed in the block that last advanced it.
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[WRITE]` Recipient account
    ///   2. `[SIGNER]` Nonce authority (the nonce account itself while
    ///      uninitialized)
    WithdrawNonceAccount(u64),

    /// Drive state of Uninitialized nonce account to Initialized, setting the nonce value
    ///
    /// The account must be system-owned, `nonce::NONCE_ACCOUNT_LENGTH` bytes
    /// long, and rent-exempt.
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///
    /// The `Pubkey` parameter specifies the entity authorized to execute nonce
    /// instruction on the account
    ///
    /// No signatures are required to execute this instruction, enabling derived
    /// nonce account addresses
    InitializeNonceAccount(Pubkey),

    /// Change the entity authorized to execute nonce instructions on the account
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[SIGNER]` Nonce authority
    ///
    /// The `Pubkey` parameter identifies the entity to authorize
    AuthorizeNonceAccount(Pubkey),
}

/// Creates a new account funded by `from_pubkey` and owned by `owner`.
///
/// # Parameters
/// * `from_pubkey` - The funding account
/// * `to_pubkey` - The account to create
/// * `lamports` - Number of lamports to transfer to the new account
/// * `space` - Number of bytes of memory to allocate
/// * `owner` - The program that will own the new account
///
/// # Returns
/// * `Instruction` - The system instruction to create the account
pub fn create_account(
    from_pubkey: &Pubkey,
    to_pubkey: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*from_pubkey, true),
        AccountMeta::new(*to_pubkey, true),
    ];
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        &SystemInstruction::CreateAccount {
            lamports,
            space,
            owner: *owner,
        },
        account_metas,
    )
}

/// Assigns a new owner to an account.
///
/// This instruction changes the owner of an account, which determines
/// which program has authority to modify the account.
///
/// # Parameters
/// * `pubkey` - The public key of the account to be reassigned
/// * `owner` - The public key of the new owner (program)
///
/// # Returns
/// * `Instruction` - The system instruction to assign a new owner
pub fn assign(pubkey: &Pubkey, owner: &Pubkey) -> Instruction {
    let account_metas = vec![AccountMeta::new(*pubkey, true)];
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        &SystemInstruction::Assign { owner: *owner },
        account_metas,
    )
}

pub fn transfer(from_pubkey: &Pubkey, to_pubkey: &Pubkey, lamports: u64) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*from_pubkey, true),
        AccountMeta::new(*to_pubkey, false),
    ];
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        &SystemInstruction::Transfer { lamports },
        account_metas,
    )
}

pub fn allocate(pubkey: &Pubkey, space: u64) -> Instruction {
    let account_metas = vec![AccountMeta::new(*pubkey, true)];
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        &SystemInstruction::Allocate { space },
        account_metas,
    )
}

pub fn sign_input(index: u32, signer: &Pubkey) -> Instruction {
    let account_metas = vec![AccountMeta::new(*signer, true)];
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        &SystemInstruction::SignInput { index },
        account_metas,
    )
}

pub fn create_account_with_seed(
    from_pubkey: &Pubkey,
    to_pubkey: &Pubkey, // must match create_with_seed(base, seed, owner)
    base: &Pubkey,
    seed: &str,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut account_metas = vec![
        AccountMeta::new(*from_pubkey, true),
        AccountMeta::new(*to_pubkey, false),
    ];
    if base != from_pubkey {
        account_metas.push(AccountMeta::new_readonly(*base, true));
    }

    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        &SystemInstruction::CreateAccountWithSeed {
            base: *base,
            seed: seed.to_string(),
            lamports,
            space,
            owner: *owner,
        },
        account_metas,
    )
}

pub fn assign_with_seed(
    address: &Pubkey, // must match create_with_seed(base, seed, owner)
    base: &Pubkey,
    seed: &str,
    owner: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*address, false),
        AccountMeta::new_readonly(*base, true),
    ];
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        &SystemInstruction::AssignWithSeed {
            base: *base,
            seed: seed.to_string(),
            owner: *owner,
        },
        account_metas,
    )
}

pub fn transfer_with_seed(
    from_pubkey: &Pubkey, // must match create_with_seed(base, seed, owner)
    from_base: &Pubkey,
    from_seed: String,
    from_owner: &Pubkey,
    to_pubkey: &Pubkey,
    lamports: u64,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*from_pubkey, false),
        AccountMeta::new_readonly(*from_base, true),
        AccountMeta::new(*to_pubkey, false),
    ];
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        &SystemInstruction::TransferWithSeed {
            lamports,
            from_seed,
            from_owner: *from_owner,
        },
        account_metas,
    )
}

pub fn allocate_with_seed(
    address: &Pubkey, // must match create_with_seed(base, seed, owner)
    base: &Pubkey,
    seed: &str,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*address, false),
        AccountMeta::new_readonly(*base, true),
    ];
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        &SystemInstruction::AllocateWithSeed {
            base: *base,
            seed: seed.to_string(),
            space,
            owner: *owner,
        },
        account_metas,
    )
}

/// Creates and initializes a nonce account funded by `from_pubkey`.
/// `nonce_pubkey` must sign; `lamports` must cover the rent-exempt minimum of
/// `nonce::NONCE_ACCOUNT_LENGTH` bytes.
pub fn create_nonce_account(
    from_pubkey: &Pubkey,
    nonce_pubkey: &Pubkey,
    authority: &Pubkey,
    lamports: u64,
) -> Vec<Instruction> {
    vec![
        create_account(
            from_pubkey,
            nonce_pubkey,
            lamports,
            NONCE_ACCOUNT_LENGTH as u64,
            &SYSTEM_PROGRAM_ID,
        ),
        Instruction::new_with_wincode(
            SYSTEM_PROGRAM_ID,
            SystemInstruction::InitializeNonceAccount(*authority),
            vec![AccountMeta::new(*nonce_pubkey, false)],
        ),
    ]
}

/// Advances a nonce account. Put it first in a transaction whose
/// `recent_blockhash` is the stored nonce to make a durable-nonce transaction.
pub fn advance_nonce_account(nonce_pubkey: &Pubkey, authorized_pubkey: &Pubkey) -> Instruction {
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        SystemInstruction::AdvanceNonceAccount,
        vec![
            AccountMeta::new(*nonce_pubkey, false),
            AccountMeta::new_readonly(*authorized_pubkey, true),
        ],
    )
}

pub fn withdraw_nonce_account(
    nonce_pubkey: &Pubkey,
    authorized_pubkey: &Pubkey,
    to_pubkey: &Pubkey,
    lamports: u64,
) -> Instruction {
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        SystemInstruction::WithdrawNonceAccount(lamports),
        vec![
            AccountMeta::new(*nonce_pubkey, false),
            AccountMeta::new(*to_pubkey, false),
            AccountMeta::new_readonly(*authorized_pubkey, true),
        ],
    )
}

pub fn authorize_nonce_account(
    nonce_pubkey: &Pubkey,
    authorized_pubkey: &Pubkey,
    new_authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_wincode(
        SYSTEM_PROGRAM_ID,
        SystemInstruction::AuthorizeNonceAccount(*new_authority),
        vec![
            AccountMeta::new(*nonce_pubkey, false),
            AccountMeta::new_readonly(*authorized_pubkey, true),
        ],
    )
}
