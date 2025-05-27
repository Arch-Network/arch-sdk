use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct RuneId {
    pub block: u64,
    pub tx: u32,
}

impl RuneId {
    pub const BTC: Self = RuneId { block: 0, tx: 0 };

    pub fn to_string(&self) -> String {
        format!("{}:{}", self.block, self.tx)
    }

    /// Returns token bytes as a fixed-size array without heap allocation
    pub fn to_bytes_array(&self) -> [u8; 12] {
        let mut result = [0u8; 12];
        result[0..8].copy_from_slice(&self.block.to_le_bytes());
        result[8..12].copy_from_slice(&self.tx.to_le_bytes());
        result
    }
}

impl BorshSerialize for RuneId {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.block, writer)?;
        borsh::BorshSerialize::serialize(&self.tx, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for RuneId {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let block = <u64 as borsh::BorshDeserialize>::deserialize(buf)?;
        let tx = <u32 as borsh::BorshDeserialize>::deserialize(buf)?;
        Ok(RuneId { block, tx })
    }

    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let block = u64::deserialize_reader(reader)?;
        let tx = u32::deserialize_reader(reader)?;
        Ok(RuneId { block, tx })
    }
}

impl FromStr for RuneId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split(':').collect::<Vec<&str>>();

        if parts.len() != 2 {
            return Err("Invalid format: expected 'block:tx'".to_string());
        }

        let block = parts[0]
            .parse::<u64>()
            .map_err(|_| "Invalid block number")?;
        let tx = parts[1]
            .parse::<u32>()
            .map_err(|_| "Invalid transaction number")?;
        Ok(RuneId { block, tx })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RuneAmount {
    pub id: RuneId,
    pub amount: u128,
}

impl RuneAmount {
    pub fn zero() -> Self {
        Self {
            id: RuneId::default(),
            amount: 0,
        }
    }
}

impl Default for RuneAmount {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialOrd for RuneAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let same_id = self.id == other.id;
        let amt_ord = self.amount.cmp(&other.amount);

        match (same_id, amt_ord) {
            (false, _) => None,
            (true, ord) => Some(ord),
        }
    }
}
