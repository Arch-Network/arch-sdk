use std::{
    io::{Error, ErrorKind},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockTransactionFilter {
    #[serde(rename = "full")]
    Full,
    #[serde(rename = "signatures")]
    Signatures,
}

impl BlockTransactionFilter {
    pub fn to_string(&self) -> String {
        match self {
            BlockTransactionFilter::Full => "full".to_string(),
            BlockTransactionFilter::Signatures => "signatures".to_string(),
        }
    }
}

impl FromStr for BlockTransactionFilter {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "full" => Ok(BlockTransactionFilter::Full),
            "signatures" => Ok(BlockTransactionFilter::Signatures),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "Invalid block transaction filter",
            )),
        }
    }
}
