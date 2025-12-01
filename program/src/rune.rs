use borsh::{BorshDeserialize, BorshSerialize};
pub use titan_types_core::{RuneAmount, RuneId, SpacedRune};

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RuneInfo {
    pub max_supply: u128,
    pub premine: u128,
    pub divisibility: u8,
    pub name: SpacedRune,
}
