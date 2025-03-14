use serde::{Deserialize, Serialize};

use super::AccountInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountFilter {
    DataSize(usize),
    DataContent { offset: usize, bytes: Vec<u8> },
}

impl AccountFilter {
    pub fn matches(&self, account_info: &AccountInfo) -> bool {
        match self {
            AccountFilter::DataSize(size) => account_info.data.len() == *size,
            AccountFilter::DataContent { offset, bytes } => {
                account_info.data.len() >= offset + bytes.len()
                    && account_info.data[*offset..offset + bytes.len()] == *bytes
            }
        }
    }
}
