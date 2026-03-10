use std::fmt;

use arch_program::pubkey::Pubkey;
use hex::FromHexError;
use serde::{Deserialize, Serialize};

use crate::client::transport::tcp::TcpClientError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BIP322SigningErrorKind {
    UnsupportedAddress,
    NotKeySpendPath,
    ToSpendCreationFailed,
    ToSignCreationFailed,
    TransactionExtractFailed,
    SignatureExtractFailed,
    SighashComputationFailed,
}

impl fmt::Display for BIP322SigningErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAddress => write!(f, "unsupported address type"),
            Self::NotKeySpendPath => write!(f, "not a key spend path"),
            Self::ToSpendCreationFailed => write!(f, "failed to create to_spend transaction"),
            Self::ToSignCreationFailed => write!(f, "failed to create to_sign transaction"),
            Self::TransactionExtractFailed => write!(f, "failed to extract transaction from PSBT"),
            Self::SignatureExtractFailed => write!(f, "failed to extract signature bytes"),
            Self::SighashComputationFailed => write!(f, "failed to compute sighash"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, thiserror::Error)]
pub enum ArchError {
    #[error("RPC request failed: {0}")]
    RpcRequestFailed(String),

    #[error("Failed to parse response: {0}")]
    ParseError(String),

    #[error("Operation timed out: {0}")]
    TimeoutError(String),

    #[error("Transaction error: {0}")]
    TransactionError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Hash error: {0}")]
    HashError(#[from] arch_program::hash::HashError),

    #[error("Unknown error: {0}")]
    UnknownError(String),

    #[error("FromHexError: {0}")]
    FromHexError(String),

    #[error("Required signer not found for key: {0}")]
    RequiredSignerNotFound(Pubkey),

    #[error("TCP client error: {0}")]
    TcpClientError(String),

    #[error("Program error: {0}")]
    ProgramError(String),

    #[error("XOnlyPublicKey from slice error: {0}")]
    XOnlyPublicKeyFromSliceError(String),

    #[error("BIP322 verification failed: {0}")]
    BIP322VerificationFailed(String),

    #[error("BIP322 signing error: {0}")]
    BIP322SigningError(BIP322SigningErrorKind),

    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpcError(String),
}

impl From<serde_json::Error> for ArchError {
    fn from(err: serde_json::Error) -> Self {
        ArchError::ParseError(err.to_string())
    }
}

impl From<std::io::Error> for ArchError {
    fn from(err: std::io::Error) -> Self {
        ArchError::NetworkError(err.to_string())
    }
}

impl From<reqwest::Error> for ArchError {
    fn from(err: reqwest::Error) -> Self {
        ArchError::NetworkError(err.to_string())
    }
}

impl From<String> for ArchError {
    fn from(err: String) -> Self {
        ArchError::UnknownError(err)
    }
}

impl From<&str> for ArchError {
    fn from(err: &str) -> Self {
        ArchError::UnknownError(err.to_string())
    }
}

impl From<FromHexError> for ArchError {
    fn from(err: FromHexError) -> Self {
        ArchError::FromHexError(err.to_string())
    }
}

impl From<TcpClientError> for ArchError {
    fn from(err: TcpClientError) -> Self {
        ArchError::TcpClientError(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ArchError>;
