#![allow(unexpected_cfgs)]
/*!
# Arch Program
A Rust library for building programs that run inside the Arch Virtual Machine. This crate
provides core functionality for creating instructions, managing accounts, handling program
errors, and interacting with the Arch runtime environment.
## Features
- Bitcoin transaction and UTXO management
- Account data manipulation and ownership verification
- System instruction creation and processing
- Program error handling
- Logging utilities
- Cryptographic operations including secp256k1 signature recovery
- Memory management for on-chain programs
## Usage
Add this crate to your `Cargo.toml`:
```toml
[dependencies]
arch_program = "0.4.0"
```
Then import the modules you need in your code:
```rust
use arch_program::account::AccountInfo;
use arch_program::pubkey::Pubkey;
use arch_program::instruction::Instruction;
// ... other imports as needed
```
*/

pub use bitcoin;

// Re-export commonly used functions
pub use program::{
    get_bitcoin_block_height, get_clock, get_remaining_compute_units, get_stack_height,
};

/// Account management and ownership verification
pub mod account;
/// Atomic operations for u64 values
pub mod atomic_u64;
pub mod bpf_loader;
/// Time-related functionality for on-chain programs
pub mod clock;
pub mod compiled_keys;
/// Compute budget instruction definitions and processing
pub mod compute_budget;
/// Utilities for debugging account data
pub mod debug_account_data;
/// Error handling for decoding operations
pub mod decode_error;
/// Program entrypoint definitions and processing
pub mod entrypoint;
/// Hash type for 32-byte cryptographic hashes
pub mod hash;
pub mod hashing_functions;
/// Helper functions for common operations
pub mod helper;
/// Bitcoin transaction input signing utilities
pub mod input_to_sign;
/// Instruction definitions and processing
pub mod instruction;
pub mod loader_instruction;
/// Logging functionality for on-chain programs
pub mod log;

pub mod native_loader;
/// Program runtime interfaces and state management
pub mod program;
/// Error types for program operations
pub mod program_error;
/// Memory management for program execution
pub mod program_memory;
/// Optional value representation for programs
pub mod program_option;
/// Data serialization and deserialization for on-chain storage
pub mod program_pack;
/// Stub implementations for program interfaces
#[cfg(not(target_os = "solana"))]
pub mod program_stubs;
pub mod program_utils;
/// Public key definitions and operations
pub mod pubkey;

/// Convenience macro to declare a static program ID and helper functions.
///
/// Input: a single literal base58 string representation of a program's ID.
///
/// This generates:
/// - A `const ID: Pubkey` — the program ID, decoded at compile time.
/// - A `fn check_id(id: &Pubkey) -> bool` — returns `true` if the given pubkey matches.
/// - A `const fn id() -> Pubkey` — returns the program ID.
///
/// # Example
///
/// ```ignore
/// use arch_program::declare_id;
///
/// declare_id!("MyProgram111111111111111111111111111111111");
///
/// assert_eq!(id(), ID);
/// assert!(check_id(&id()));
/// ```
#[macro_export]
macro_rules! declare_id {
    ($address:expr) => {
        /// The const program ID.
        pub const ID: $crate::pubkey::Pubkey = $crate::pubkey::Pubkey::from_str_const($address);

        /// Returns `true` if given pubkey is the program ID.
        pub fn check_id(id: &$crate::pubkey::Pubkey) -> bool {
            id == &ID
        }

        /// Returns the program ID.
        pub const fn id() -> $crate::pubkey::Pubkey {
            ID
        }

        #[cfg(test)]
        #[test]
        fn test_id() {
            assert!(check_id(&id()));
        }
    };
}
pub mod rent;
/// Resharing defines.
pub mod resharing;
/// Sanitization trait and error types for validating over-the-wire messages
pub mod sanitize;
/// Sanitized transaction processing
pub mod sanitized;
/// Secp256k1 signature recovery utilities
pub mod sol_secp256k1_recover;
/// Stable memory layout implementations
pub mod stable_layout;
pub mod stake;
/// System call interfaces for interacting with the runtime
pub mod syscalls;
/// System instruction definitions and creation
pub mod system_instruction;
pub mod system_program;
/// Bitcoin transaction signing utilities
pub mod transaction_to_sign;
/// Bitcoin UTXO (Unspent Transaction Output) management
pub mod utxo;
pub mod vote;

pub mod serde_error;

#[macro_use]
extern crate serde_derive;

/// Rune management
pub mod rune;

/// Maximum size of a Bitcoin transaction in bytes
pub const MAX_BTC_TX_SIZE: usize = 3976;

/// Maximum size of a Bitcoin rune output in bytes
pub const MAX_BTC_RUNE_OUTPUT_SIZE: usize = 2048;

pub const MAX_SIGNERS: usize = 16;
pub const MAX_SEEDS: usize = 16;
pub const MAX_SEED_LEN: usize = 32;
/// Max Taproot inputs to keep tx size ≤ 4096 bytes.
/// Each input ≈ 161 bytes (base + witness).
/// 4096 / 161 ≈ 25
pub const MAX_BTC_TXN_INPUTS: usize = 25;

pub mod builtin {
    use super::*;
    use crate::pubkey::Pubkey;

    pub const BUILTIN_PROGRAMS_ID: &[Pubkey] =
        &[native_loader::ID, system_program::ID, bpf_loader::ID];
}
