#[cfg(feature = "fuzzing")]
use libfuzzer_sys::arbitrary;
use serde::{Deserialize, Serialize};

use super::AccountInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub enum AccountFilter {
    DataSize(usize),
    DataContent { offset: usize, bytes: Vec<u8> },
}

impl AccountFilter {
    pub fn matches(&self, account_info: &AccountInfo) -> bool {
        match self {
            AccountFilter::DataSize(size) => account_info.data.len() == *size,
            AccountFilter::DataContent { offset, bytes } => offset
                .checked_add(bytes.len())
                .and_then(|end| account_info.data.get(*offset..end))
                .is_some_and(|window| window == bytes.as_slice()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arch_program::pubkey::Pubkey;

    fn account(data: &[u8]) -> AccountInfo {
        AccountInfo {
            lamports: 0,
            owner: Pubkey::system_program(),
            data: data.to_vec(),
            is_executable: false,
        }
    }

    fn content(offset: usize, bytes: &[u8]) -> AccountFilter {
        AccountFilter::DataContent {
            offset,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn data_content_rejects_offset_that_overflows_instead_of_panicking() {
        let account = account(&[1, 2, 3]);

        assert!(!content(usize::MAX, &[0]).matches(&account));
        assert!(!content(usize::MAX - 1, &[0, 0]).matches(&account));
    }

    #[test]
    fn data_content_matches_only_within_account_bounds() {
        let account = account(&[1, 2, 3]);

        assert!(content(1, &[2, 3]).matches(&account));
        assert!(content(3, &[]).matches(&account));
        assert!(!content(2, &[3, 4]).matches(&account));
        assert!(!content(4, &[]).matches(&account));
        assert!(!content(0, &[1, 3]).matches(&account));
    }
}
