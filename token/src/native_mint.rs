//! The Mint that represents the native token

/// There are `10^9` lamports in one SOL
pub const DECIMALS: u8 = 9;

use crate::Pubkey;

/// The Mint that represents the native token
pub fn id() -> Pubkey {
    Pubkey::from_slice(b"AplNative11111111111111111111111")
}

/// The Mint that represents the native token
pub const ID: Pubkey = Pubkey::new_from_array(*b"AplNative11111111111111111111111");
