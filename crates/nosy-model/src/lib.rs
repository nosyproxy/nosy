//! Shared data model for Nosy. Every type that crosses the API boundary
//! derives [`TS`] so the TypeScript bindings in `web/src/api/generated` stay in sync
//! (regenerate with `cargo test -p nosy-model`).

pub mod capture;
pub mod headers;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub type FlowId = i64;

/// Unix time in milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

/// One row of the proxy history table. Kept small: bodies live elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize, TS, PartialEq)]
#[ts(export)]
pub struct FlowSummary {
    #[ts(type = "number")]
    pub id: FlowId,
    #[ts(type = "number")]
    pub ts_start: i64,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    /// Path + query.
    pub path: String,
    pub http_version: String,
    pub status: Option<u16>,
    #[ts(type = "number")]
    pub req_size: i64,
    #[ts(type = "number | null")]
    pub resp_size: Option<i64>,
    pub content_type: Option<String>,
    #[ts(type = "number | null")]
    pub duration_us: Option<i64>,
    pub error: Option<String>,
    pub truncated: bool,
    pub highlight: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Full flow metadata including headers (bodies are fetched separately as bytes).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FlowDetail {
    pub summary: FlowSummary,
    pub request_headers: Vec<Header>,
    pub response_headers: Option<Vec<Header>>,
    pub response_version: Option<String>,
    #[ts(type = "number")]
    pub req_body_len: i64,
    #[ts(type = "number")]
    pub resp_body_len: i64,
}

/// Filter for the history list. All fields optional; combined with AND.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FlowFilter {
    /// Keyset pagination: only flows with `id < before_id`.
    #[ts(type = "number | null")]
    pub before_id: Option<FlowId>,
    /// Only flows with `id > after_id` (used for resync).
    #[ts(type = "number | null")]
    pub after_id: Option<FlowId>,
    pub limit: Option<u32>,
    /// Substring match on host + path.
    pub q: Option<String>,
    pub host: Option<String>,
    /// Comma-separated list of methods.
    pub methods: Option<String>,
    /// Comma-separated status classes: `1,2,3,4,5` and `0` for "no response".
    pub status: Option<String>,
    pub hide_static: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS, Default)]
#[ts(export)]
pub struct FlowPatch {
    /// `Some("")` clears.
    pub highlight: Option<String>,
    pub note: Option<String>,
}

/// Pushed over the WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum WsEvent {
    /// New or updated flows (upserted by id on the client).
    Flows { flows: Vec<FlowSummary> },
    /// Flows were deleted.
    Deleted {
        #[ts(type = "number[]")]
        ids: Vec<FlowId>,
    },
    /// History cleared.
    Cleared,
    /// The client lagged behind and must reload.
    Resync,
}

// ---------------------------------------------------------------- repeater

#[derive(Debug, Clone, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub http2: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RepeaterTab {
    #[ts(type = "number")]
    pub id: i64,
    pub name: String,
    #[ts(type = "number")]
    pub position: i64,
    pub target: Target,
    pub raw_request: String,
    #[ts(type = "number")]
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS, Default)]
#[ts(export)]
pub struct RepeaterTabPatch {
    pub name: Option<String>,
    #[ts(type = "number | null")]
    pub position: Option<i64>,
    pub target: Option<Target>,
    pub raw_request: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NewRepeaterTab {
    pub name: Option<String>,
    pub target: Target,
    pub raw_request: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SendRequest {
    pub target: Target,
    pub raw_request: String,
    #[serde(default = "default_true")]
    pub update_content_length: bool,
    #[ts(type = "number | null")]
    pub timeout_ms: Option<u64>,
}

fn default_true() -> bool {
    true
}

/// One request/response exchange made from a repeater tab.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RepeaterEntry {
    #[ts(type = "number")]
    pub id: i64,
    #[ts(type = "number")]
    pub tab_id: i64,
    #[ts(type = "number")]
    pub ts: i64,
    pub target: Target,
    pub status: Option<u16>,
    pub http_version: Option<String>,
    #[ts(type = "number | null")]
    pub ttfb_us: Option<i64>,
    #[ts(type = "number | null")]
    pub duration_us: Option<i64>,
    #[ts(type = "number")]
    pub resp_size: i64,
    pub error: Option<String>,
}

// ---------------------------------------------------------------- settings

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AppInfo {
    pub version: String,
    pub proxy_addr: String,
    pub ui_addr: String,
    pub project_path: String,
    pub ca_path: String,
    pub verify_upstream: bool,
    #[ts(type = "number")]
    pub max_capture_bytes: u64,
}

// ---------------------------------------------------------------- search / automation

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct HostCount {
    pub host: String,
    #[ts(type = "number")]
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SearchHit {
    pub flow: FlowSummary,
    /// `request.head`, `request.body`, `response.head` or `response.body`.
    pub location: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    /// Flows examined.
    pub scanned: u32,
    /// Pass as `before_id` to continue searching older flows.
    #[ts(type = "number | null")]
    pub next_before_id: Option<FlowId>,
}

/// A captured request prepared for re-sending (same shape as a new repeater tab).
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ReplayTemplate {
    pub target: Target,
    pub raw_request: String,
}
