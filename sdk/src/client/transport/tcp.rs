use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::client::error::Result;
use crate::client::transport::RpcTransport;

pub struct TcpClient {
    stream: Mutex<TcpStream>,
}

impl TcpClient {
    pub fn new(addr: String) -> Result<Self> {
        let addr = SocketAddr::from_str(&addr).map_err(TcpClientError::InvalidAddress)?;
        let std_stream =
            std::net::TcpStream::connect(addr).map_err(TcpClientError::ConnectFailed)?;
        std_stream
            .set_nonblocking(true)
            .map_err(TcpClientError::ConnectFailed)?;
        let stream = TcpStream::from_std(std_stream).map_err(TcpClientError::ConnectFailed)?;
        Ok(Self {
            stream: Mutex::new(stream),
        })
    }

    async fn write_all(stream: &mut TcpStream, val: &str) -> Result<()> {
        let mut serialized = Vec::new();
        BorshSerialize::serialize(val, &mut serialized).map_err(TcpClientError::BorshSerialize)?;

        let len = serialized.len() as u64;
        let prefix = len.to_be_bytes();
        stream
            .write_all(&prefix)
            .await
            .map_err(TcpClientError::SocketWrite)?;
        stream
            .write_all(&serialized)
            .await
            .map_err(TcpClientError::SocketWrite)?;

        Ok(())
    }

    /// Reads the next message from the socket.
    async fn read_response<T: BorshDeserialize>(stream: &mut TcpStream) -> Result<T> {
        let mut prefix = [0_u8; 8];
        stream
            .read_exact(&mut prefix)
            .await
            .map_err(TcpClientError::SocketRead)?;
        let payload_len = u64::from_be_bytes(prefix);

        let mut payload = vec![0_u8; payload_len as usize];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(TcpClientError::SocketRead)?;

        let mut cursor = &payload[..];
        let ret = T::deserialize_reader(&mut cursor).map_err(TcpClientError::BorshDeserialize)?;

        Ok(ret)
    }
}

#[async_trait]
impl RpcTransport for TcpClient {
    async fn call(&self, json: &Value) -> Result<String> {
        let mut stream = self.stream.lock().await;
        Self::write_all(&mut stream, &json.to_string()).await?;
        let ret = Self::read_response(&mut stream).await?;
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
}
