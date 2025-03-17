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
arch_program = "0.3.2"
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

/// Account management and ownership verification
pub mod account;
/// Atomic operations for u64 values
pub mod atomic_u64;
/// Time-related functionality for on-chain programs
pub mod clock;
/// Utilities for debugging account data
pub mod debug_account_data;
/// Error handling for decoding operations
pub mod decode_error;
/// Program entrypoint definitions and processing
pub mod entrypoint;
/// Helper functions for common operations
pub mod helper;
/// Bitcoin transaction input signing utilities
pub mod input_to_sign;
/// Instruction definitions and processing
pub mod instruction;
/// Logging functionality for on-chain programs
pub mod log;
/// Message format and processing utilities
pub mod message;
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
pub mod program_stubs;
/// Public key definitions and operations
pub mod pubkey;
/// Sanitized transaction processing
pub mod sanitized;
/// Secp256k1 signature recovery utilities
pub mod sol_secp256k1_recover;
/// Stable memory layout implementations
pub mod stable_layout;
/// System call interfaces for interacting with the runtime
pub mod syscalls;
/// System instruction definitions and creation
pub mod system_instruction;
/// Bitcoin transaction signing utilities
pub mod transaction_to_sign;
/// Bitcoin UTXO (Unspent Transaction Output) management
pub mod utxo;

/// Maximum size of a Bitcoin transaction in bytes
pub const MAX_BTC_TX_SIZE: usize = 3976;
