//! Blocking (synchronous) API wrappers.
//!
//! This module mirrors the async top-level API but provides blocking
//! versions of each type, following the same pattern as `reqwest::blocking`.
//!
//! # Example
//! ```ignore
//! use arch_sdk::blocking::{ArchRpcClient, ProgramDeployer, BitcoinHelper};
//!
//! let client = ArchRpcClient::new(&config);
//! let deployer = ProgramDeployer::new(&config);
//! let helper = BitcoinHelper::new(&config);
//! ```

pub use crate::client::rpc::BlockingArchRpcClient as ArchRpcClient;
pub use crate::helper::program_deployment::BlockingProgramDeployer as ProgramDeployer;
pub use crate::helper::utxo::BlockingBitcoinHelper as BitcoinHelper;

/// Blocking version of [`crate::prepare_fees`].
pub fn prepare_fees() -> Result<String, crate::ArchError> {
    crate::helper::utxo::blocking_prepare_fees()
}
