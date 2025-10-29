use crate::client::error::Result;
use serde_json::Value;

pub mod http;
pub mod tcp;

pub use http::HttpClient;
pub use tcp::TcpClient;

pub trait RpcTransport: Send + Sync {
    /// Calls the RPC method on the server and returns the
    /// resulting JSON in serialized format.
    fn call(&self, json: &Value) -> Result<String>;
}
