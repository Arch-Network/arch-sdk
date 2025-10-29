use serde_json::Value;

use crate::client::error::{ArchError, Result};
use crate::client::transport::RpcTransport;

pub struct HttpClient {
    arch_node_url: String,
}

impl HttpClient {
    pub fn new(arch_node_url: String) -> Self {
        Self { arch_node_url }
    }
}

impl RpcTransport for HttpClient {
    fn call(&self, json: &Value) -> Result<String> {
        let client = reqwest::blocking::Client::new();
        match client
            .post(&self.arch_node_url)
            .header("content-type", "application/json")
            .json(json)
            .send()
        {
            Ok(res) => match res.text() {
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
