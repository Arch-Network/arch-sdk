//! Hashing with the [keccak] (SHA-3) hash function.
//!
//! [keccak]: https://keccak.team/keccak.html

use serde::{Deserialize, Serialize};

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use {
    sha3::{Digest, Keccak256},
    solana_sanitize::Sanitize,
    std::{convert::TryFrom, fmt, mem, str::FromStr},
    thiserror::Error,
};

pub const HASH_BYTES: usize = 32;
/// Maximum string length of a base58 encoded hash
const MAX_BASE58_LEN: usize = 44;
#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[cfg_attr(
    feature = "borsh",
    derive(BorshSerialize, BorshDeserialize, BorshSchema),
    borsh(crate = "borsh")
)]
#[derive(Serialize, Deserialize, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Hash(pub [u8; HASH_BYTES]);

#[derive(Clone, Default)]
pub struct Hasher {
    hasher: Keccak256,
}

impl Hasher {
    pub fn hash(&mut self, val: &[u8]) {
        self.hasher.update(val);
    }
    pub fn hashv(&mut self, vals: &[&[u8]]) {
        for val in vals {
            self.hash(val);
        }
    }
    pub fn result(self) -> Hash {
        Hash(self.hasher.finalize().into())
    }
}

impl Sanitize for Hash {}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseHashError {
    #[error("string decoded to wrong size for hash")]
    WrongSize,
    #[error("failed to decoded string to hash")]
    Invalid,
}

impl FromStr for Hash {
    type Err = ParseHashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_BASE58_LEN {
            return Err(ParseHashError::WrongSize);
        }
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| ParseHashError::Invalid)?;
        if bytes.len() != mem::size_of::<Hash>() {
            Err(ParseHashError::WrongSize)
        } else {
            Ok(Hash::new(&bytes))
        }
    }
}

impl Hash {
    pub fn new(hash_slice: &[u8]) -> Self {
        Hash(<[u8; HASH_BYTES]>::try_from(hash_slice).unwrap())
    }

    pub const fn new_from_array(hash_array: [u8; HASH_BYTES]) -> Self {
        Self(hash_array)
    }

    /// unique Hash for tests and benchmarks.
    pub fn new_unique() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static I: AtomicU64 = AtomicU64::new(1);

        let mut b = [0u8; HASH_BYTES];
        let i = I.fetch_add(1, Ordering::Relaxed);
        b[0..8].copy_from_slice(&i.to_le_bytes());
        Self::new(&b)
    }

    pub fn to_bytes(self) -> [u8; HASH_BYTES] {
        self.0
    }
}

/// Return a Keccak256 hash for the given data.
fn keccak256_internal(vals: &[&[u8]]) -> Hash {
    // Perform the calculation inline, calling this from within a program is
    // not supported
    #[cfg(not(target_os = "solana"))]
    {
        let mut hasher = Hasher::default();
        hasher.hashv(vals);
        hasher.result()
    }
    // Call via a system call to perform the calculation
    #[cfg(target_os = "solana")]
    {
        let mut hash_result = [0; HASH_BYTES];
        unsafe {
            crate::syscalls::sol_keccak256(
                vals as *const _ as *const u8,
                vals.len() as u64,
                &mut hash_result as *mut _ as *mut u8,
            );
        }
        Hash::new_from_array(hash_result)
    }
}

/// Return a Keccak256 hash for the given data.
pub fn keccak256(val: &[u8]) -> Hash {
    keccak256_internal(&[val])
}

/// Return a SHA-256 hash for the given data.
fn sha256_internal(vals: &[&[u8]]) -> Hash {
    // Host-side implementation (tests, tooling, etc.)
    #[cfg(not(target_os = "solana"))]
    {
        use bitcoin::hashes::{sha256, Hash as _};

        let total_len: usize = vals.iter().map(|v| v.len()).sum();
        let mut buf = Vec::with_capacity(total_len);
        for v in vals {
            buf.extend_from_slice(v);
        }

        let digest = sha256::Hash::hash(&buf);
        Hash::new_from_array(digest.to_byte_array())
    }

    // BPF/syscall implementation
    #[cfg(target_os = "solana")]
    {
        let mut hash_result = [0; HASH_BYTES];
        unsafe {
            // NOTE: the sha256 syscall expects a pointer to an array of (ptr,len) pairs,
            // i.e. the in-memory representation of `&[&[u8]]`, and `length` is the
            // number of slices (not the total number of bytes).
            crate::syscalls::sol_sha256(
                vals as *const _ as *const u8,
                vals.len() as u64,
                &mut hash_result as *mut _ as *mut u8,
            );
        }
        Hash::new_from_array(hash_result)
    }
}

#[allow(unused_variables)]
pub fn sha256(val: &[u8]) -> Hash {
    sha256_internal(&[val])
}

/// Return the hash of the given hash extended with the given value.
pub fn extend_and_hash(id: &Hash, val: &[u8]) -> Hash {
    let mut hash_data = id.as_ref().to_vec();
    hash_data.extend_from_slice(val);
    keccak256_internal(&[&hash_data])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector_for_8_bytes() {
        let input = b"12345678";
        let out = sha256(input);
        // sha256("12345678") =
        // ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f
        let expected = [
            0xef, 0x79, 0x7c, 0x81, 0x18, 0xf0, 0x2d, 0xfb, 0x64, 0x96, 0x07, 0xdd, 0x5d, 0x3f,
            0x8c, 0x76, 0x23, 0x04, 0x8c, 0x9c, 0x06, 0x3d, 0x53, 0x2c, 0xc9, 0x5c, 0x5e, 0xd7,
            0xa8, 0x98, 0xa6, 0x4f,
        ];
        assert_eq!(out.to_bytes(), expected);
    }
}
