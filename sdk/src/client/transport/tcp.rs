use borsh::{BorshDeserialize, BorshSerialize};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::Mutex;

use crate::client::error::Result;
use crate::client::transport::RpcTransport;

pub struct TcpClient {
    stream: Mutex<TcpStream>,
}

impl TcpClient {
    pub fn new(addr: String) -> Result<Self> {
        let addr = SocketAddr::from_str(&addr).map_err(TcpClientError::InvalidAddress)?;
        let stream = TcpStream::connect(addr).map_err(TcpClientError::ConnectFailed)?;
        Ok(Self {
            stream: Mutex::new(stream),
        })
    }

    /// Writes the message to the socket.
    fn write<T: BorshSerialize>(stream: &mut TcpStream, val: &T) -> Result<()> {
        let mut serialized = Vec::new();
        BorshSerialize::serialize(val, &mut serialized).map_err(TcpClientError::BorshSerialize)?;

        // Write the payload length prefix.
        let len = serialized.len() as u64;
        let prefix = len.to_be_bytes();
        stream
            .write_all(&prefix)
            .map_err(TcpClientError::SocketWrite)?;

        // Write the payload.
        stream
            .write_all(&serialized)
            .map_err(TcpClientError::SocketWrite)?;

        Ok(())
    }

    /// Reads the next message from the socket.
    fn read<T: BorshDeserialize>(stream: &mut TcpStream) -> Result<T> {
        let mut prefix = [0_u8; 8];
        stream
            .read_exact(&mut prefix)
            .map_err(TcpClientError::SocketRead)?;
        let payload_len = u64::from_be_bytes(prefix);

        let mut payload = vec![0_u8; payload_len as usize];
        stream
            .read_exact(&mut payload)
            .map_err(TcpClientError::SocketRead)?;

        let mut cursor = &payload[..];
        let ret = T::deserialize_reader(&mut cursor).map_err(TcpClientError::BorshDeserialize)?;

        Ok(ret)
    }
}

impl RpcTransport for TcpClient {
    fn call(&self, json: &Value) -> Result<String> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|err| TcpClientError::PoisonedLock(err.to_string()))?;
        Self::write(&mut stream, &json.to_string())?;
        let ret: String = Self::read(&mut stream)?;
        Ok(ret)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TcpClientError {
    #[error("Failed to parse server address: {0}")]
    InvalidAddress(#[from] std::net::AddrParseError),

    #[error("Failed to connect: {0}")]
    ConnectFailed(std::io::Error),

    #[error("Failed to read from socket: {0}")]
    SocketRead(std::io::Error),

    #[error("Failed to write to socket: {0}")]
    SocketWrite(std::io::Error),

    #[error("Failed to serialize: {0}")]
    BorshSerialize(std::io::Error),

    #[error("Failed to deserialize: {0}")]
    BorshDeserialize(std::io::Error),

    #[error("Failed to lock: {0}")]
    PoisonedLock(String),
}
