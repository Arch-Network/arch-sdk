//! Public API stability tests for the `arch_program` crate.
//!
//! These tests guarantee that every public type, constant, function, trait, and
//! method that downstream crates may depend on continues to exist and has a
//! compatible signature.  If any public API item is removed, renamed, or has
//! its signature changed in an incompatible way, these tests will fail at
//! **compile time**.
//!
//! Runtime assertions pin the *values* of public constants so that
//! accidentally changing them is also caught.

// ---------------------------------------------------------------------------
// 1. Module existence – every `pub mod` in lib.rs must be importable.
// ---------------------------------------------------------------------------

#[allow(unused_imports)]
use arch_program::account;
#[allow(unused_imports)]
use arch_program::atomic_u64;
#[allow(unused_imports)]
use arch_program::bpf_loader;
#[allow(unused_imports)]
use arch_program::clock;
#[allow(unused_imports)]
use arch_program::compiled_keys;
#[allow(unused_imports)]
use arch_program::compute_budget;
#[allow(unused_imports)]
use arch_program::debug_account_data;
#[allow(unused_imports)]
use arch_program::decode_error;
#[allow(unused_imports)]
use arch_program::entrypoint;
#[allow(unused_imports)]
use arch_program::hash;
#[allow(unused_imports)]
use arch_program::hashing_functions;
#[allow(unused_imports)]
use arch_program::helper;
#[allow(unused_imports)]
use arch_program::input_to_sign;
#[allow(unused_imports)]
use arch_program::instruction;
#[allow(unused_imports)]
use arch_program::loader_instruction;
#[allow(unused_imports)]
use arch_program::log;
#[allow(unused_imports)]
use arch_program::native_loader;
#[allow(unused_imports)]
use arch_program::program;
#[allow(unused_imports)]
use arch_program::program_error;
#[allow(unused_imports)]
use arch_program::program_memory;
#[allow(unused_imports)]
use arch_program::program_option;
#[allow(unused_imports)]
use arch_program::program_pack;
#[allow(unused_imports)]
use arch_program::program_stubs;
#[allow(unused_imports)]
use arch_program::program_utils;
#[allow(unused_imports)]
use arch_program::pubkey;
#[allow(unused_imports)]
use arch_program::rent;
#[allow(unused_imports)]
use arch_program::resharing;
#[allow(unused_imports)]
use arch_program::rune;
#[allow(unused_imports)]
use arch_program::sanitize;
#[allow(unused_imports)]
use arch_program::sanitized;
#[allow(unused_imports)]
use arch_program::serde_error;
#[allow(unused_imports)]
use arch_program::sol_secp256k1_recover;
#[allow(unused_imports)]
use arch_program::stable_layout;
#[allow(unused_imports)]
use arch_program::stake;
#[allow(unused_imports)]
use arch_program::syscalls;
#[allow(unused_imports)]
use arch_program::system_instruction;
#[allow(unused_imports)]
use arch_program::system_program;
#[allow(unused_imports)]
use arch_program::transaction_to_sign;
#[allow(unused_imports)]
use arch_program::utxo;
#[allow(unused_imports)]
use arch_program::vote;

// Re-exported `bitcoin` crate
#[allow(unused_imports)]
use arch_program::bitcoin;

// Re-exported top-level functions
#[allow(unused_imports)]
use arch_program::{
    get_bitcoin_block_height, get_clock, get_remaining_compute_units, get_stack_height,
};

// ---------------------------------------------------------------------------
// 2. Top-level constants
// ---------------------------------------------------------------------------

#[test]
fn top_level_constants() {
    let _: usize = arch_program::MAX_BTC_TX_SIZE;
    let _: usize = arch_program::MAX_BTC_RUNE_OUTPUT_SIZE;
    let _: usize = arch_program::MAX_SIGNERS;
    let _: usize = arch_program::MAX_SEEDS;
    let _: usize = arch_program::MAX_SEED_LEN;
    let _: usize = arch_program::MAX_BTC_TXN_INPUTS;

    assert_eq!(arch_program::MAX_BTC_TX_SIZE, 3976);
    assert_eq!(arch_program::MAX_BTC_RUNE_OUTPUT_SIZE, 2048);
    assert_eq!(arch_program::MAX_SIGNERS, 16);
    assert_eq!(arch_program::MAX_SEEDS, 16);
    assert_eq!(arch_program::MAX_SEED_LEN, 32);
    assert_eq!(arch_program::MAX_BTC_TXN_INPUTS, 25);
}

// ---------------------------------------------------------------------------
// 3. builtin module
// ---------------------------------------------------------------------------

#[test]
fn builtin_module() {
    let _: &[pubkey::Pubkey] = arch_program::builtin::BUILTIN_PROGRAMS_ID;
}

// ---------------------------------------------------------------------------
// 4. account module
// ---------------------------------------------------------------------------

#[test]
fn account_types_and_methods() {
    // AccountMeta struct fields
    let meta = account::AccountMeta {
        pubkey: pubkey::Pubkey::system_program(),
        is_signer: true,
        is_writable: true,
    };

    // AccountMeta methods
    let _ = account::AccountMeta::new(pubkey::Pubkey::system_program(), true);
    let _ = account::AccountMeta::new_readonly(pubkey::Pubkey::system_program(), true);
    let serialized = meta.serialize();
    let _: [u8; 34] = serialized;
    let _roundtrip = account::AccountMeta::from_slice(&serialized).unwrap();

    // SHARED_VALIDATOR_DATA_ACCOUNT_ID constant
    let _: [u8; 32] = account::SHARED_VALIDATOR_DATA_ACCOUNT_ID;

    // next_account_info function exists (verified by calling it)
    let empty: Vec<account::AccountInfo<'_>> = vec![];
    let mut iter = empty.iter();
    let _ = account::next_account_info(&mut iter); // should return Err
}

/// Verify AccountInfo fields and methods exist with correct types by
/// constructing one from raw parts.
#[test]
fn account_info_construction_and_methods() {
    let key = pubkey::Pubkey::system_program();
    let owner = pubkey::Pubkey::system_program();
    let mut lamports: u64 = 100;
    let mut data = vec![0u8; 32];
    let utxo_meta = utxo::UtxoMeta::from([0u8; 32], 0);

    let info = account::AccountInfo::new(
        &key,
        &mut lamports,
        &mut data,
        &owner,
        &utxo_meta,
        true,  // is_signer
        true,  // is_writable
        false, // is_executable
    );

    // Field accessors
    let _: &pubkey::Pubkey = info.key;
    let _: bool = info.is_signer;
    let _: bool = info.is_writable;
    let _: bool = info.is_executable;

    // Methods
    let _: usize = info.data_len();
    let _: Result<usize, _> = info.try_data_len();
    let _: bool = info.data_is_empty();
    let _: Result<bool, _> = info.try_data_is_empty();
    let _: Option<&pubkey::Pubkey> = info.signer_key();
    let _: &pubkey::Pubkey = info.unsigned_key();
    let _: u64 = info.lamports();
    let _: Result<u64, _> = info.try_lamports();
    let _ = info.try_borrow_lamports().unwrap();
    let _ = info.try_borrow_mut_lamports().unwrap();
    let _ = info.try_borrow_data().unwrap();
    let _ = info.try_borrow_mut_data().unwrap();
    let _: &utxo::UtxoMeta = info.get_utxo();
}

// ---------------------------------------------------------------------------
// 5. pubkey module
// ---------------------------------------------------------------------------

#[test]
fn pubkey_types_and_methods() {
    let _: usize = pubkey::PUBKEY_BYTES;
    assert_eq!(pubkey::PUBKEY_BYTES, 32);

    // Construction
    let pk = pubkey::Pubkey::new_from_array([0u8; 32]);
    let _: pubkey::Pubkey = pubkey::Pubkey::from_str_const("11111111111111111111111111111111");
    let _: pubkey::Pubkey = pubkey::Pubkey::from_slice(&[0u8; 32]);
    let _: pubkey::Pubkey = pubkey::Pubkey::system_program();
    let _: pubkey::Pubkey = pubkey::Pubkey::new_unique();

    // Methods
    let _: [u8; 32] = pk.serialize();
    let _: bool = pk.is_system_program();

    // PDA derivation
    let (_, _bump): (pubkey::Pubkey, u8) = pubkey::Pubkey::find_program_address(&[b"seed"], &pk);
    let _: Option<(pubkey::Pubkey, u8)> = pubkey::Pubkey::try_find_program_address(&[b"seed"], &pk);
    let _: Result<pubkey::Pubkey, _> =
        pubkey::Pubkey::create_program_address(&[b"seed", &[255u8]], &pk);
    let _: Result<pubkey::Pubkey, _> = pubkey::Pubkey::create_with_seed(&pk, "seed", &pk);

    // Trait impls
    let _: &[u8] = pk.as_ref();
    let _: pubkey::Pubkey = pubkey::Pubkey::from([0u8; 32]);
    let _: Result<pubkey::Pubkey, _> = "11111111111111111111111111111111".parse::<pubkey::Pubkey>();
    let _ = format!("{}", pk); // Display
    let _ = format!("{:?}", pk); // Debug
    let _ = format!("{:x}", pk); // LowerHex
}

// ---------------------------------------------------------------------------
// 6. instruction module
// ---------------------------------------------------------------------------

#[test]
fn instruction_types_and_methods() {
    // Instruction struct fields
    let ix = instruction::Instruction {
        program_id: pubkey::Pubkey::system_program(),
        accounts: vec![],
        data: vec![1, 2, 3],
    };

    // Constructors
    let _ = instruction::Instruction::new(pubkey::Pubkey::system_program(), vec![1], vec![]);
    let _ =
        instruction::Instruction::new_with_borsh(pubkey::Pubkey::system_program(), &0u8, vec![]);
    let _ =
        instruction::Instruction::new_with_bincode(pubkey::Pubkey::system_program(), 0u8, vec![]);

    // Methods
    let serialized = ix.serialize();
    let _: instruction::Instruction = instruction::Instruction::from_slice(&serialized);
    let _: String = ix.hash();
}

#[test]
fn instruction_error_variants() {
    use instruction::InstructionError;

    // Verify all variants exist
    let _ = InstructionError::GenericError;
    let _ = InstructionError::InvalidArgument;
    let _ = InstructionError::InvalidInstructionData;
    let _ = InstructionError::InvalidAccountData;
    let _ = InstructionError::AccountDataTooSmall;
    let _ = InstructionError::InsufficientFunds;
    let _ = InstructionError::IncorrectProgramId;
    let _ = InstructionError::MissingRequiredSignature;
    let _ = InstructionError::AccountAlreadyInitialized;
    let _ = InstructionError::UninitializedAccount;
    let _ = InstructionError::UnbalancedInstruction;
    let _ = InstructionError::ModifiedProgramId;
    let _ = InstructionError::ExternalAccountLamportSpend;
    let _ = InstructionError::ExternalAccountDataModified(String::new());
    let _ = InstructionError::ReadonlyDataModified(String::new());
    let _ = InstructionError::DuplicateAccountIndex;
    let _ = InstructionError::ExecutableModified;
    let _ = InstructionError::NotEnoughAccountKeys;
    let _ = InstructionError::AccountDataSizeChanged;
    let _ = InstructionError::AccountNotExecutable;
    let _ = InstructionError::AccountBorrowFailed;
    let _ = InstructionError::AccountBorrowOutstanding;
    let _ = InstructionError::DuplicateAccountOutOfSync;
    let _ = InstructionError::Custom(0);
    let _ = InstructionError::ProgramError(program_error::ProgramError::InvalidArgument);
    let _ = InstructionError::InvalidError;
    let _ = InstructionError::ExecutableDataModified;
    let _ = InstructionError::UnsupportedProgramId;
    let _ = InstructionError::CallDepth;
    let _ = InstructionError::MissingAccount;
    let _ = InstructionError::ReentrancyNotAllowed;
    let _ = InstructionError::MaxSeedLengthExceeded;
    let _ = InstructionError::InvalidSeeds;
    let _ = InstructionError::InvalidRealloc;
    let _ = InstructionError::ComputationalBudgetExceeded;
    let _ = InstructionError::PrivilegeEscalation;
    let _ = InstructionError::ProgramEnvironmentSetupFailure;
    let _ = InstructionError::ProgramFailedToComplete;
    let _ = InstructionError::ProgramFailedToCompile;
    let _ = InstructionError::ElfFailedToParse;
    let _ = InstructionError::Immutable;
    let _ = InstructionError::IncorrectAuthority;
    let _ = InstructionError::BorshIoError(String::new());
    let _ = InstructionError::InvalidAccountOwner;
    let _ = InstructionError::ArithmeticOverflow;
    let _ = InstructionError::UnsupportedSysvar;
    let _ = InstructionError::IllegalOwner;
    let _ = InstructionError::MaxAccountsDataAllocationsExceeded;
    let _ = InstructionError::MaxAccountsExceeded;
    let _ = InstructionError::MaxInstructionTraceLengthExceeded;
    let _ = InstructionError::RPCError;
    let _ = InstructionError::BuiltinProgramsMustConsumeComputeUnits;
    let _ = InstructionError::EbpfError(String::new());
    let _ = InstructionError::InvalidTxToSign;
    let _ = InstructionError::InvalidInputToSign;
    let _ = InstructionError::NegativeAccountLamports;
    let _ = InstructionError::ReadonlyLamportChange;
    let _ = InstructionError::ExecutableLamportChange;
    let _ = InstructionError::BitcoinEncodingError;
    let _ = InstructionError::TitanError;
    let _ = InstructionError::InvalidUtxoOwner;
    let _ = InstructionError::AccountNotAnchored;
    let _ = InstructionError::NotEnoughComputeUnits;
    let _ = InstructionError::TranscriptVerificationFailed;
    let _ = InstructionError::InvalidChunk(String::new());
    let _ = InstructionError::TransactionToSignEmpty;
    let _ = InstructionError::InvalidUtxoId;
    let _ = InstructionError::InvalidUtxoSigner;
    let _ = InstructionError::InvalidUtxo;
    let _ = InstructionError::UnableToFetchUtxoTx;
    let _ = InstructionError::BuildAccountAddressError;

    // Conversions
    let _: InstructionError = InstructionError::from(0u64);
    let _: InstructionError =
        InstructionError::from(system_instruction::SystemError::AccountAlreadyInUse);
}

// ---------------------------------------------------------------------------
// 7. program_error module
// ---------------------------------------------------------------------------

#[test]
fn program_error_variants() {
    use program_error::ProgramError;

    let _ = ProgramError::Custom(0);
    let _ = ProgramError::InvalidArgument;
    let _ = ProgramError::InvalidInstructionData;
    let _ = ProgramError::InvalidAccountData;
    let _ = ProgramError::AccountDataTooSmall;
    let _ = ProgramError::InsufficientFunds;
    let _ = ProgramError::IncorrectProgramId;
    let _ = ProgramError::MissingRequiredSignature;
    let _ = ProgramError::AccountAlreadyInitialized;
    let _ = ProgramError::UninitializedAccount;
    let _ = ProgramError::NotEnoughAccountKeys;
    let _ = ProgramError::AccountBorrowFailed;
    let _ = ProgramError::MaxSeedLengthExceeded;
    let _ = ProgramError::MaxSeedsExceeded;
    let _ = ProgramError::InvalidSeeds;
    let _ = ProgramError::BorshIoError(String::new());
    let _ = ProgramError::IllegalOwner;
    let _ = ProgramError::MaxAccountsDataAllocationsExceeded;
    let _ = ProgramError::InvalidRealloc;
    let _ = ProgramError::MaxInstructionTraceLengthExceeded;
    let _ = ProgramError::BuiltinProgramsMustConsumeComputeUnits;
    let _ = ProgramError::InvalidAccountOwner;
    let _ = ProgramError::ArithmeticOverflow;
    let _ = ProgramError::Immutable;
    let _ = ProgramError::IncorrectAuthority;
    let _ = ProgramError::FromHexError;
    let _ = ProgramError::NegativeAccountLamports;
    let _ = ProgramError::ReadonlyLamportChange;
    let _ = ProgramError::ExecutableLamportChange;
    let _ = ProgramError::AccountNotAnchored;
    let _ = ProgramError::NotEnoughComputeUnits;
    let _ = ProgramError::InsufficientDataLength;
    let _ = ProgramError::IncorrectLength;
    let _ = ProgramError::TranscriptVerificationFailed;
    let _ = ProgramError::InvalidChunk(String::new());
    let _ = ProgramError::TransactionToSignEmpty;
    let _ = ProgramError::InvalidUtxoId;
    let _ = ProgramError::InvalidUtxoSigner;
    let _ = ProgramError::InvalidStateTransition(String::new());

    // Conversions
    let _: u64 = u64::from(ProgramError::InvalidArgument);
    let _: ProgramError = ProgramError::from(0u64);
    let _: ProgramError =
        ProgramError::from(std::io::Error::new(std::io::ErrorKind::Other, "test"));
}

#[test]
fn program_error_constants() {
    use program_error::*;

    let _: usize = BUILTIN_BIT_SHIFT;
    assert_eq!(BUILTIN_BIT_SHIFT, 32);

    let _: u64 = CUSTOM_ZERO;
    let _: u64 = INVALID_ARGUMENT;
    let _: u64 = INVALID_INSTRUCTION_DATA;
    let _: u64 = INVALID_ACCOUNT_DATA;
    let _: u64 = ACCOUNT_DATA_TOO_SMALL;
    let _: u64 = INSUFFICIENT_FUNDS;
    let _: u64 = INCORRECT_PROGRAM_ID;
    let _: u64 = MISSING_REQUIRED_SIGNATURES;
    let _: u64 = ACCOUNT_ALREADY_INITIALIZED;
    let _: u64 = UNINITIALIZED_ACCOUNT;
    let _: u64 = NOT_ENOUGH_ACCOUNT_KEYS;
    let _: u64 = ACCOUNT_BORROW_FAILED;
    let _: u64 = MAX_SEED_LENGTH_EXCEEDED;
    let _: u64 = MAX_SEEDS_EXCEEDED;
    let _: u64 = INVALID_SEEDS;
    let _: u64 = BORSH_IO_ERROR;
    let _: u64 = ACCOUNT_NOT_RENT_EXEMPT;
    let _: u64 = UNSUPPORTED_SYSVAR;
    let _: u64 = ILLEGAL_OWNER;
    let _: u64 = MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED;
    let _: u64 = INVALID_ACCOUNT_DATA_REALLOC;
    let _: u64 = MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED;
    let _: u64 = BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS;
    let _: u64 = INVALID_ACCOUNT_OWNER;
    let _: u64 = ARITHMETIC_OVERFLOW;
    let _: u64 = IMMUTABLE;
    let _: u64 = INCORRECT_AUTHORITY;
    let _: u64 = FROM_HEX_ERROR;
    let _: u64 = NEGATIVE_ACCOUNT_LAMPORTS;
    let _: u64 = READONLY_LAMPORT_CHANGE;
    let _: u64 = EXECUTABLE_LAMPORT_CHANGE;
    let _: u64 = ACCOUNT_NOT_ANCHORED;
    let _: u64 = NOT_ENOUGH_COMPUTE_UNITS;
    let _: u64 = INSUFFICIENT_DATA_LENGTH;
    let _: u64 = INCORRECT_LENGTH;
    let _: u64 = TRANSCRIPT_VERIFICATION_FAILED;
    let _: u64 = INVALID_CHUNK;
    let _: u64 = TRANSACTION_TO_SIGN_EMPTY;
    let _: u64 = INVALID_UTXO_ID;
    let _: u64 = INVALID_UTXO_SIGNER;
    let _: u64 = INVALID_STATE_TRANSITION;
}

// ---------------------------------------------------------------------------
// 8. entrypoint module
// ---------------------------------------------------------------------------

#[test]
fn entrypoint_types_and_constants() {
    let _: u64 = entrypoint::HEAP_START_ADDRESS;
    let _: usize = entrypoint::HEAP_LENGTH;
    let _: usize = entrypoint::MAX_PERMITTED_DATA_LENGTH;
    let _: usize = entrypoint::MAX_PERMITTED_DATA_INCREASE;
    let _: usize = entrypoint::BPF_ALIGN_OF_U128;
    let _: u8 = entrypoint::NON_DUP_MARKER;
    let _: u64 = entrypoint::SUCCESS;
    assert_eq!(entrypoint::SUCCESS, 0);

    // ProgramResult type alias
    let _: entrypoint::ProgramResult = Ok(());

    // ProcessInstruction type alias
    fn _dummy(
        _: &pubkey::Pubkey,
        _: &[account::AccountInfo],
        _: &[u8],
    ) -> entrypoint::ProgramResult {
        Ok(())
    }
    let _: entrypoint::ProcessInstruction = _dummy;
}

// ---------------------------------------------------------------------------
// 9. utxo module
// ---------------------------------------------------------------------------

#[test]
fn utxo_types_and_methods() {
    // Construction
    let meta = utxo::UtxoMeta::from([0u8; 32], 0);
    let _ = utxo::UtxoMeta::from_slice(&[0u8; 36]);
    let _ = utxo::UtxoMeta::default();

    // Accessors
    let _: &[u8] = meta.txid();
    let _: [u8; 32] = meta.txid_big_endian();
    let _: [u8; 32] = meta.txid_little_endian();
    let _: bitcoin::Txid = meta.to_txid();
    let _: bitcoin::blockdata::transaction::OutPoint = meta.to_outpoint();
    let _: u32 = meta.vout();
    let _: [u8; 36] = meta.serialize();
    let _: bool = meta.is_defined();

    // From OutPoint
    let outpoint = bitcoin::blockdata::transaction::OutPoint::null();
    let _ = utxo::UtxoMeta::from_outpoint(outpoint.txid, outpoint.vout);

    // Trait impls
    let _: &[u8] = meta.as_ref();
    let _: utxo::UtxoMeta = <utxo::UtxoMeta as From<[u8; 36]>>::from([0u8; 36]);
    let _ = format!("{}", meta); // Display
}

// ---------------------------------------------------------------------------
// 10. hash module
// ---------------------------------------------------------------------------

#[test]
fn hash_types_and_methods() {
    let h = hash::Hash::from([0u8; 32]);

    // Methods
    let _: [u8; 32] = h.to_array();
    let mut out = [0u8; 32];
    h.copy_bytes(&mut out);
    let _: String = h.to_string_short();

    // HashError
    let _ = hash::HashError::InvalidLength(0);
    let _ = hash::HashError::InvalidHex(String::new());

    // Conversions
    let _: String = String::from(h);
    let _: bitcoin::Txid = bitcoin::Txid::from(h);
    let _: bitcoin::Txid = bitcoin::Txid::from(&h);
    let _: Result<hash::Hash, _> = hash::Hash::try_from("aa".repeat(32).as_str());
    let _: Result<hash::Hash, _> = hash::Hash::try_from("aa".repeat(32));
    let _: Result<hash::Hash, _> = hash::Hash::try_from([0u8; 32].as_slice());
    let _: Result<hash::Hash, _> = "aa".repeat(32).parse::<hash::Hash>();

    // Trait impls
    let _: &[u8; 32] = h.as_ref();
    let _ = format!("{}", h);
    let _ = format!("{:?}", h);
}

// ---------------------------------------------------------------------------
// 11. clock module
// ---------------------------------------------------------------------------

#[test]
fn clock_type() {
    let c = clock::Clock {
        slot: 0,
        epoch: 0,
        unix_timestamp: 0,
    };
    let _: u64 = c.slot;
    let _: u64 = c.epoch;
    let _: i64 = c.unix_timestamp;
}

// ---------------------------------------------------------------------------
// 12. system_instruction module
// ---------------------------------------------------------------------------

#[test]
fn system_instruction_enum_variants() {
    use system_instruction::SystemInstruction;

    let _ = SystemInstruction::CreateAccount {
        lamports: 0,
        space: 0,
        owner: pubkey::Pubkey::system_program(),
    };
    let _ = SystemInstruction::CreateAccountWithAnchor {
        lamports: 0,
        space: 0,
        owner: pubkey::Pubkey::system_program(),
        txid: [0; 32],
        vout: 0,
    };
    let _ = SystemInstruction::Assign {
        owner: pubkey::Pubkey::system_program(),
    };
    let _ = SystemInstruction::Anchor {
        txid: [0; 32],
        vout: 0,
    };
    let _ = SystemInstruction::SignInput { index: 0 };
    let _ = SystemInstruction::Transfer { lamports: 0 };
    let _ = SystemInstruction::Allocate { space: 0 };
    let _ = SystemInstruction::CreateAccountWithSeed {
        base: pubkey::Pubkey::system_program(),
        seed: String::new(),
        lamports: 0,
        space: 0,
        owner: pubkey::Pubkey::system_program(),
    };
    let _ = SystemInstruction::AllocateWithSeed {
        base: pubkey::Pubkey::system_program(),
        seed: String::new(),
        space: 0,
        owner: pubkey::Pubkey::system_program(),
    };
    let _ = SystemInstruction::AssignWithSeed {
        base: pubkey::Pubkey::system_program(),
        seed: String::new(),
        owner: pubkey::Pubkey::system_program(),
    };
    let _ = SystemInstruction::TransferWithSeed {
        lamports: 0,
        from_seed: String::new(),
        from_owner: pubkey::Pubkey::system_program(),
    };
}

#[test]
fn system_instruction_functions() {
    let pk = pubkey::Pubkey::system_program();

    let _: instruction::Instruction = system_instruction::create_account(&pk, &pk, 0, 0, &pk);
    let _: instruction::Instruction =
        system_instruction::create_account_with_anchor(&pk, &pk, 0, 0, &pk, [0; 32], 0);
    let _: instruction::Instruction = system_instruction::assign(&pk, &pk);
    let _: instruction::Instruction = system_instruction::transfer(&pk, &pk, 0);
    let _: instruction::Instruction = system_instruction::allocate(&pk, 0);
    let _: instruction::Instruction = system_instruction::anchor(&pk, [0; 32], 0);
    let _: instruction::Instruction = system_instruction::sign_input(0, &pk);
    let _: instruction::Instruction =
        system_instruction::create_account_with_seed(&pk, &pk, &pk, "seed", 0, 0, &pk);
    let _: instruction::Instruction = system_instruction::assign_with_seed(&pk, &pk, "seed", &pk);
    let _: instruction::Instruction =
        system_instruction::transfer_with_seed(&pk, &pk, String::new(), &pk, &pk, 0);
    let _: instruction::Instruction =
        system_instruction::allocate_with_seed(&pk, &pk, "seed", 0, &pk);
}

#[test]
fn system_error_variants() {
    use system_instruction::SystemError;

    let _ = SystemError::AccountAlreadyInUse;
    let _ = SystemError::ResultWithNegativeLamports;
    let _ = SystemError::InvalidProgramId;
    let _ = SystemError::InvalidAccountDataLength;
    let _ = SystemError::MaxSeedLengthExceeded;
    let _ = SystemError::AddressWithSeedMismatch;
    let _ = SystemError::NonceNoRecentBlockhashes;
    let _ = SystemError::NonceBlockhashNotExpired;
    let _ = SystemError::NonceUnexpectedBlockhashValue;
}

// ---------------------------------------------------------------------------
// 13. system_program module
// ---------------------------------------------------------------------------

#[test]
fn system_program_id() {
    let _: pubkey::Pubkey = system_program::SYSTEM_PROGRAM_ID;
}

// ---------------------------------------------------------------------------
// 14. compute_budget module
// ---------------------------------------------------------------------------

#[test]
fn compute_budget_types() {
    use compute_budget::ComputeBudgetInstruction;

    let _: pubkey::Pubkey = compute_budget::COMPUTE_BUDGET_PROGRAM_ID;

    let _ = ComputeBudgetInstruction::RequestHeapFrame(1024);
    let _ = ComputeBudgetInstruction::SetComputeUnitLimit(1000);
    let _: instruction::Instruction = ComputeBudgetInstruction::request_heap_frame(1024);
    let _: instruction::Instruction = ComputeBudgetInstruction::set_compute_unit_limit(1000);
}

// ---------------------------------------------------------------------------
// 15. input_to_sign module
// ---------------------------------------------------------------------------

#[test]
fn input_to_sign_type() {
    let its = input_to_sign::InputToSign {
        index: 0,
        signer: pubkey::Pubkey::system_program(),
    };
    let _: u32 = its.index;
    let _: pubkey::Pubkey = its.signer;
    let serialized = its.serialise();
    let _ = input_to_sign::InputToSign::from_slice(&serialized).unwrap();
}

// ---------------------------------------------------------------------------
// 16. transaction_to_sign module
// ---------------------------------------------------------------------------

#[test]
fn transaction_to_sign_methods() {
    use transaction_to_sign::TransactionToSign;

    // Static method
    let inputs = vec![input_to_sign::InputToSign {
        index: 0,
        signer: pubkey::Pubkey::system_program(),
    }];
    let _: Vec<u8> = TransactionToSign::serialise_inputs_to_sign(&inputs);
}

// ---------------------------------------------------------------------------
// 17. helper module
// ---------------------------------------------------------------------------

#[test]
fn helper_functions_exist() {
    // We can only check function signatures, not call them without valid accounts
    let _: fn(
        &[account::AccountInfo],
    ) -> Result<bitcoin::Transaction, program_error::ProgramError> =
        helper::get_state_transition_tx;
}

// ---------------------------------------------------------------------------
// 18. rent module
// ---------------------------------------------------------------------------

#[test]
fn rent_constants_and_functions() {
    let _: u64 = rent::DEFAULT_LAMPORTS_PER_BYTE_YEAR;
    let _: f64 = rent::DEFAULT_EXEMPTION_THRESHOLD;
    let _: u64 = rent::ACCOUNT_STORAGE_OVERHEAD;

    let _: u64 = rent::minimum_rent(100);
    let _: bool = rent::is_exempt(1000, 100);
}

// ---------------------------------------------------------------------------
// 19. bpf_loader module
// ---------------------------------------------------------------------------

#[test]
fn bpf_loader_types() {
    let _: pubkey::Pubkey = bpf_loader::BPF_LOADER_ID;

    let _ = bpf_loader::LoaderStatus::Retracted;
    let _ = bpf_loader::LoaderStatus::Deployed;
    let _ = bpf_loader::LoaderStatus::Finalized;

    let state = bpf_loader::LoaderState {
        authority_address_or_next_version: pubkey::Pubkey::system_program(),
        status: bpf_loader::LoaderStatus::Deployed,
    };
    let _: pubkey::Pubkey = state.authority_address_or_next_version;
    let _: bpf_loader::LoaderStatus = state.status;
    let _: usize = bpf_loader::LoaderState::program_data_offset();
}

// ---------------------------------------------------------------------------
// 20. native_loader module
// ---------------------------------------------------------------------------

#[test]
fn native_loader_id() {
    let _: pubkey::Pubkey = native_loader::NATIVE_LOADER_ID;
}

// ---------------------------------------------------------------------------
// 21. loader_instruction module
// ---------------------------------------------------------------------------

#[test]
fn loader_instruction_types_and_functions() {
    use loader_instruction::LoaderInstruction;

    let _ = LoaderInstruction::Write {
        offset: 0,
        bytes: vec![],
    };
    let _ = LoaderInstruction::Truncate { new_size: 0 };
    let _ = LoaderInstruction::Deploy;
    let _ = LoaderInstruction::Retract;
    let _ = LoaderInstruction::TransferAuthority;
    let _ = LoaderInstruction::Finalize;

    let pk = pubkey::Pubkey::system_program();
    let _: instruction::Instruction = loader_instruction::write(pk, pk, 0, vec![]);
    let _: instruction::Instruction = loader_instruction::truncate(pk, pk, 0);
    let _: instruction::Instruction = loader_instruction::deploy(pk, pk);
    let _: instruction::Instruction = loader_instruction::retract(pk, pk);
    let _: instruction::Instruction = loader_instruction::transfer_authority(pk, pk, pk);
    let _: instruction::Instruction = loader_instruction::finalize(pk, pk, pk);

    let _: bool = loader_instruction::is_write_instruction(&[0]);
    let _: bool = loader_instruction::is_truncate_instruction(&[1]);
    let _: bool = loader_instruction::is_deploy_instruction(&[2]);
    let _: bool = loader_instruction::is_retract_instruction(&[3]);
    let _: bool = loader_instruction::is_transfer_authority_instruction(&[4]);
    let _: bool = loader_instruction::is_finalize_instruction(&[5]);
}

// ---------------------------------------------------------------------------
// 22. sol_secp256k1_recover module
// ---------------------------------------------------------------------------

#[test]
fn secp256k1_types_and_constants() {
    let _: usize = sol_secp256k1_recover::SECP256K1_SIGNATURE_LENGTH;
    let _: usize = sol_secp256k1_recover::SECP256K1_PUBLIC_KEY_LENGTH;
    let _: usize = sol_secp256k1_recover::HASH_BYTES;
    let _: u64 = sol_secp256k1_recover::SUCCESS;

    assert_eq!(sol_secp256k1_recover::SECP256K1_SIGNATURE_LENGTH, 64);
    assert_eq!(sol_secp256k1_recover::SECP256K1_PUBLIC_KEY_LENGTH, 64);
    assert_eq!(sol_secp256k1_recover::HASH_BYTES, 32);
    assert_eq!(sol_secp256k1_recover::SUCCESS, 0);

    let pk = sol_secp256k1_recover::Secp256k1Pubkey::new(&[0u8; 64]);
    let _: [u8; 64] = pk.to_bytes();

    let _ = sol_secp256k1_recover::Secp256k1RecoverError::InvalidHash;
    let _ = sol_secp256k1_recover::Secp256k1RecoverError::InvalidRecoveryId;
    let _ = sol_secp256k1_recover::Secp256k1RecoverError::InvalidSignature;
}

// ---------------------------------------------------------------------------
// 23. hashing_functions module
// ---------------------------------------------------------------------------

#[test]
fn hashing_functions_api() {
    let _: usize = hashing_functions::HASH_BYTES;
    assert_eq!(hashing_functions::HASH_BYTES, 32);

    let h = hashing_functions::Hash([0u8; 32]);
    let _: [u8; 32] = h.to_bytes();

    let mut hasher = hashing_functions::Hasher::default();
    hasher.hash(b"test");
    hasher.hashv(&[b"a", b"b"]);
    let _: hashing_functions::Hash = hasher.result();

    let _: hashing_functions::Hash = hashing_functions::keccak256(b"test");
    let _: hashing_functions::Hash = hashing_functions::sha256(b"test");
    let _: hashing_functions::Hash = hashing_functions::extend_and_hash(&h, b"test");
}

// ---------------------------------------------------------------------------
// 24. sanitize module
// ---------------------------------------------------------------------------

#[test]
fn sanitize_types() {
    let _ = sanitize::SanitizeError::IndexOutOfBounds;
    let _ = sanitize::SanitizeError::ValueOutOfBounds;
    let _ = sanitize::SanitizeError::InvalidValue;
    let _ = sanitize::SanitizeError::InvalidVersion;
    let _ = sanitize::SanitizeError::SignatureCountMismatch {
        expected: 0,
        actual: 0,
    };
    let _ = sanitize::SanitizeError::InvalidRecentBlockhash;
    let _ = sanitize::SanitizeError::DuplicateAccount;
    let _ = sanitize::SanitizeError::InvalidSize {
        serialized_len: 0,
        limit: 0,
    };

    // Trait exists
    fn _assert_sanitize<T: sanitize::Sanitize>() {}
}

// ---------------------------------------------------------------------------
// 25. sanitized module
// ---------------------------------------------------------------------------

#[test]
fn sanitized_types() {
    let _: usize = sanitized::MAX_INSTRUCTION_COUNT_PER_TRANSACTION;
    let _: u32 = sanitized::MAX_PUBKEYS_ALLOWED;

    // ArchMessage fields
    let msg = sanitized::ArchMessage {
        header: sanitized::MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 0,
        },
        account_keys: vec![
            pubkey::Pubkey::system_program(),
            pubkey::Pubkey::new_unique(),
        ],
        recent_blockhash: hash::Hash::from([0u8; 32]),
        instructions: vec![],
    };

    // ArchMessage methods
    let _: bool = msg.is_writable_index(0);
    let _: &sanitized::MessageHeader = msg.header();
    let _: bool = msg.is_signer(0);
    let _: Option<&pubkey::Pubkey> = msg.get_account_key(0);

    // SanitizedMessage
    let sm = sanitized::SanitizedMessage::new(msg);
    let _: bool = sm.is_signer(0);
    let _: bool = sm.is_writable(0);
    let _: &Vec<sanitized::SanitizedInstruction> = sm.instructions();
}

// ---------------------------------------------------------------------------
// 26. serde_error module
// ---------------------------------------------------------------------------

#[test]
fn serde_error_types() {
    let _ = serde_error::SerialisationErrors::OverFlow;
    let _ = serde_error::SerialisationErrors::SizeTooSmall;
    let _ = serde_error::SerialisationErrors::CorruptedData;
    let _ = serde_error::SerialisationErrors::MoreThanMaxInstructionsAllowed;
    let _ = serde_error::SerialisationErrors::MoreThanMaxAccountsAllowed;
    let _ = serde_error::SerialisationErrors::MoreThanMaxSigners;
    let _ = serde_error::SerialisationErrors::MoreThanMaxAllowedKeys;

    let _: Result<[u8; 4], _> = serde_error::get_const_slice::<4>(&[0u8; 8], 0);
    let _: Result<&[u8], _> = serde_error::get_slice(&[0u8; 8], 0, 4);
}

// ---------------------------------------------------------------------------
// 27. resharing module
// ---------------------------------------------------------------------------

#[test]
fn resharing_types_and_constants() {
    let _: pubkey::Pubkey = resharing::RESHARING_PROGRAM_ID;
    let _: pubkey::Pubkey = resharing::RESHARING_DATA_ACCOUNT_ID;
    let _: pubkey::Pubkey = resharing::RESHARING_STAGING_ACCOUNT_ID;
    let _: u64 = resharing::CHUNK_SIZE;

    let ri = resharing::ResharingInstruction {
        first_chunk: true,
        last_chunk: false,
        start_offset: 0,
        chunk: vec![],
    };
    let _: bool = ri.first_chunk;
    let _: bool = ri.last_chunk;
    let _: u64 = ri.start_offset;
    let _: Vec<u8> = ri.chunk;
}

// ---------------------------------------------------------------------------
// 28. rune module
// ---------------------------------------------------------------------------

#[test]
fn rune_types() {
    // Re-exports from titan_types_core
    let _: rune::RuneAmount;
    let _: rune::RuneId;

    let _ = rune::RuneInfo {
        max_supply: 0u128,
        premine: 0u128,
        divisibility: 0u8,
        name: Default::default(),
    };
}

// ---------------------------------------------------------------------------
// 29. program module functions (signature check)
// ---------------------------------------------------------------------------

#[test]
fn program_module_constants_and_type_aliases() {
    use program::*;

    let _: usize = MAX_TRANSACTION_TO_SIGN;
    let _: usize = MAX_RETURN_DATA;
    assert_eq!(MAX_TRANSACTION_TO_SIGN, 4 * 1024);
    assert_eq!(MAX_RETURN_DATA, 1024);

    // Type aliases exist
    let _: BitcoinTransaction;
    let _: BitcoinRuneOutput;
    let _: ReturnedData;
    let _: RuneInfoBuf;
}

#[test]
fn fixed_size_buffer_api() {
    let mut buf = program::FixedSizeBuffer::<64>::new([0u8; 64], 10);
    let _: usize = buf.size();
    let _: &[u8] = buf.as_slice();
    let _: *mut u8 = buf.as_mut_ptr();
    let _: usize = buf.capacity();
    buf.set_size(20);
}

// ---------------------------------------------------------------------------
// 30. program_memory module
// ---------------------------------------------------------------------------

#[test]
fn program_memory_functions() {
    let mut dst = [0u8; 4];
    let src = [1u8; 4];
    program_memory::sol_memcpy(&mut dst, &src, 4);
    let _: i32 = program_memory::sol_memcmp(&dst, &src, 4);
    program_memory::sol_memset(&mut dst, 0, 4);
}

// ---------------------------------------------------------------------------
// 31. program_pack module
// ---------------------------------------------------------------------------

#[test]
fn program_pack_traits() {
    fn _assert_is_initialized<T: program_pack::IsInitialized>() {}
    fn _assert_sealed<T: program_pack::Sealed>() {}
    fn _assert_pack<T: program_pack::Pack>() {}
}

// ---------------------------------------------------------------------------
// 32. program_option module
// ---------------------------------------------------------------------------

#[test]
fn program_option_type() {
    let _ = program_option::COption::<u32>::Some(42);
    let _ = program_option::COption::<u32>::None;
}

// ---------------------------------------------------------------------------
// 33. log module functions
// ---------------------------------------------------------------------------

#[test]
fn log_functions_exist() {
    // Just verify the function signatures compile; don't call them as they
    // invoke syscalls.
    let _: fn(&str) = log::sol_log;
    let _: fn(u64, u64, u64, u64, u64) = log::sol_log_64;
    let _: fn(&[&[u8]]) = log::sol_log_data;
    let _: fn(&[u8]) = log::sol_log_slice;
    let _: fn() = log::sol_log_compute_units;
}

// ---------------------------------------------------------------------------
// 34. stake module
// ---------------------------------------------------------------------------

#[test]
fn stake_program_id() {
    let _: pubkey::Pubkey = stake::program::STAKE_PROGRAM_ID;
}

// ---------------------------------------------------------------------------
// 35. vote module
// ---------------------------------------------------------------------------

#[test]
fn vote_program_id() {
    let _: pubkey::Pubkey = vote::program::VOTE_PROGRAM_ID;
}

// ---------------------------------------------------------------------------
// 36. syscalls constants
// ---------------------------------------------------------------------------

#[test]
fn syscalls_constants() {
    let _: u64 = syscalls::MAX_CPI_INSTRUCTION_DATA_LEN;
    let _: u8 = syscalls::MAX_CPI_INSTRUCTION_ACCOUNTS;
    let _: usize = syscalls::MAX_CPI_ACCOUNT_INFOS;
}

// ---------------------------------------------------------------------------
// 37. decode_error trait
// ---------------------------------------------------------------------------

#[test]
fn decode_error_trait() {
    fn _assert_decode_error<T: decode_error::DecodeError<T>>() {}
}

// ---------------------------------------------------------------------------
// 38. compiled_keys module
// ---------------------------------------------------------------------------

#[test]
fn compile_error_variants() {
    let _ = compiled_keys::CompileError::AccountIndexOverflow;
    let _ = compiled_keys::CompileError::AddressTableLookupIndexOverflow;
    let _ = compiled_keys::CompileError::UnknownInstructionKey(pubkey::Pubkey::system_program());
}

// ---------------------------------------------------------------------------
// 40. program_utils module
// ---------------------------------------------------------------------------

#[test]
fn program_utils_function() {
    // Just verify signature compiles
    let _: fn(&[u8]) -> Result<u8, instruction::InstructionError> =
        program_utils::deserialize_syscall_instruction::<u8>;
}
