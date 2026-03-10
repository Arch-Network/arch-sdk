use async_trait::async_trait;
use serde_json::Value;

use crate::client::error::{ArchError, Result};
use crate::client::transport::RpcTransport;

pub struct HttpClient {
    arch_node_url: String,
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new(arch_node_url: String) -> Self {
        Self {
            arch_node_url,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl RpcTransport for HttpClient {
    async fn call(&self, json: &Value) -> Result<String> {
        match self
            .client
            .post(&self.arch_node_url)
            .header("content-type", "application/json")
            .json(json)
            .send()
            .await
        {
            Ok(res) => match res.text().await {
                Ok(text) => Ok(text),
                Err(e) => Err(ArchError::NetworkError(format!(
                    "Failed to read response text: {}",
                    e
                ))),
            },
            Err(e) => Err(ArchError::NetworkError(format!("Request failed: {}", e))),
        }
    }
}
