//! Syscall-backed curve25519 (edwards25519 / ristretto255) group operations.
//!
//! These wrappers mirror Solana's `solana-curve25519` crate. On-chain
//! (`target_os = "solana"`) they call the native `sol_curve_*` syscalls, which
//! are orders of magnitude cheaper than running `curve25519-dalek` in software
//! inside the BPF VM. Off-chain they fall back to `curve25519-dalek` directly so
//! the same code can be used for client-side and on-host verification.
//!
//! Points are 32-byte compressed encodings and scalars are 32-byte
//! little-endian values. A `Some`/return code of `0` indicates success; invalid
//! or off-curve inputs yield `None`/a nonzero return code.

pub mod curve_syscall_traits;
pub mod edwards;
pub mod errors;
pub mod ristretto;
pub mod scalar;
