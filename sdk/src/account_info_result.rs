use arch_program::pubkey::Pubkey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfoResult {
    pub owner: Pubkey,
    pub data: Vec<u8>,
    pub utxo: String,
    pub is_executable: bool,
}
