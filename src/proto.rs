//! Messages of the `agentbox.v1.Daemon` service (Connect protocol, JSON codec).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

fn default_sandbox() -> String {
    "default".into()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub workdir: String,
    #[serde(default = "default_sandbox")]
    pub sandbox: String,
}

/// What would change relative to the last approved state.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Diff {
    /// Reason given by the agent, if this is an agent request.
    pub reason: Option<String>,
    /// RFC 6902 JSON Patch of the evaluated policy.
    pub policy_patch: serde_json::Value,
    /// Unified diff of nix files and flake.lock.
    pub text_diff: String,
    pub drv_changed: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateRunReq {
    pub target: Target,
    pub argv: Vec<String>,
    /// Accept unapproved edits left in the workdir.
    pub confirm: bool,
    /// Terminal-related variables forwarded from the CLI (TERM etc.).
    pub env: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct CreateRunRes {
    pub run_id: Option<String>,
    /// Socket the CLI passes its stdio fds to (SCM_RIGHTS) and keeps open.
    pub fd_socket: Option<String>,
    pub needs_confirm: Option<Diff>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RunRef {
    pub run_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WaitRunRes {
    pub exit_code: i32,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignalReq {
    pub run_id: String,
    pub signal: i32,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ReloadReq {
    pub target: Target,
    pub confirm: bool,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ReloadRes {
    pub needs_confirm: Option<Diff>,
    pub result: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct PendingRes {
    pub pending: Option<Diff>,
    /// Status lines, e.g. "approved, waiting for the agent's turn to end".
    pub notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DecideReq {
    pub target: Target,
    pub accept: bool,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PolicyReq {
    pub target: Target,
    pub effective: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExplainReq {
    pub target: Target,
    pub what: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TextRes {
    pub text: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Denial {
    pub run_id: String,
    /// Unix seconds.
    pub time: u64,
    pub kind: String,
    pub target: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct DenialsRes {
    pub denials: Vec<Denial>,
}
