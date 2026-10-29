use crate::client::error::Result;
use async_trait::async_trait;
use serde_json::Value;

pub mod http;
pub mod tcp;

pub use tcp::TcpClient;
// async-trait < 0.1.92 trips this lint in its generated code. Bumping it is
// consensus-visible: it reaches the APL programs (arch_program → sha256), so
// their ELFs, and so genesis, change.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait RpcTransport: Send + Sync {
    /// Calls the RPC method on the server and returns the
    /// resulting JSON in serialized format.
    async fn call(&self, json: &Value) -> Result<String>;
}
