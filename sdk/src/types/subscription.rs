//! WebSocket subscription wire-format types.
//!
//! The server and SDK communicate using a method-tagged JSON envelope:
//! - subscribe: `{"method":"subscribe","params":{...}}`
//! - unsubscribe: `{"method":"unsubscribe","params":{...}}`
//!
//! Requests operate on a single topic plus an event filter. Successful
//! subscribe/unsubscribe responses carry a server-issued `subscription_id`
//! used for later unsubscription.

use serde::{Deserialize, Serialize};

use super::{EventFilter, EventTopic};

/// Outbound WebSocket request sent to the validator subscription server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum WebSocketRequest {
    #[serde(rename = "subscribe")]
    Subscribe(SubscriptionRequest),
    #[serde(rename = "unsubscribe")]
    Unsubscribe(UnsubscribeRequest),
}

/// Request payload for a single topic subscription.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubscriptionRequest {
    /// Topic to subscribe to.
    pub topic: EventTopic,

    /// Additional server-side filtering for the topic.
    pub filter: EventFilter,

    /// Optional client-generated correlation ID echoed back by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Request payload used to unsubscribe an existing subscription.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    /// Topic the subscription belongs to.
    pub topic: EventTopic,

    /// Server-issued subscription identifier returned by `SubscriptionResponse`.
    pub subscription_id: String,
}

/// Status returned by subscribe/unsubscribe operations.
#[derive(Debug, Serialize, Deserialize)]
pub enum SubscriptionStatus {
    Subscribed,
    Unsubscribed,
    Error,
}

/// Response to a subscription request.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubscriptionResponse {
    /// The result status
    pub status: SubscriptionStatus,
    /// The subscription ID (to use for unsubscribing)
    pub subscription_id: String,
    /// The topic that was subscribed to
    pub topic: EventTopic,
    /// The request ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Response to an unsubscribe request.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsubscribeResponse {
    /// Result status of the unsubscribe request.
    pub status: SubscriptionStatus,

    /// Server-issued subscription identifier that was removed.
    pub subscription_id: String,

    /// Human-readable server message.
    pub message: String,
}

/// Error response returned by the subscription server.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubscriptionErrorResponse {
    /// Error status for the failed operation.
    pub status: SubscriptionStatus,

    /// Human-readable error message.
    pub error: String,
}
