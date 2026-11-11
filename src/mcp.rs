//! MCP server for the agent, served on the per-run socket with the official SDK (`rmcp`).
//!
//! Approval operations are deliberately absent: an agent can only ask.

use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ProgressNotificationParam, RequestMetaObject};
use rmcp::schemars::{self, JsonSchema};
use rmcp::{ErrorData, Peer, RoleServer, ServiceExt, tool, tool_router};
use serde::Deserialize;
use serde_json::json;
use tokio::net::UnixStream;

use crate::daemon::{Daemon, Outcome};

const PROGRESS_INTERVAL: Duration = Duration::from_secs(15);

/// The tools of one sandbox run.
struct AgentTools {
    daemon: Arc<Daemon>,
    run_id: String,
}

#[derive(Deserialize, JsonSchema)]
struct ReloadEnvArgs {
    /// Why the environment needs to change; shown to the human reviewer.
    reason: Option<String>,
}

fn text(text: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text)])
}

fn error(text: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text)])
}

fn pretty<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

impl AgentTools {
    /// Waits for the human's decision on a pending request.
    ///
    /// Humans are slow, so progress notifications keep the client's tool timeout from
    /// firing, and after `approval_timeout_secs` the agent is told to call again.
    async fn wait_for_decision(
        &self,
        mut decision: crate::daemon::Decision,
        meta: &RequestMetaObject,
        client: &Peer<RoleServer>,
    ) -> Outcome {
        let progress_token = meta.get_progress_token();
        let timeout = Duration::from_secs(self.daemon.cfg.approval_timeout_secs);
        let timeout = tokio::time::sleep(timeout);
        tokio::pin!(timeout);
        let mut tick = tokio::time::interval(PROGRESS_INTERVAL);
        let mut progress = 0.0;

        loop {
            if let Some(outcome) = decision.borrow().clone() {
                return outcome;
            }

            tokio::select! {
                changed = decision.changed() => {
                    if changed.is_err() {
                        return Outcome::new("rejected", "the request was dropped (daemon restarted?)");
                    }
                }

                _ = &mut timeout => {
                    return Outcome::new(
                        "still_pending",
                        "Still waiting for human approval. Call reload_env again without \
                         changing the files to keep waiting.",
                    );
                }

                _ = tick.tick() => {
                    let Some(token) = progress_token.clone() else {
                        continue;
                    };

                    progress += 1.0;
                    let notification = ProgressNotificationParam::new(token, progress)
                        .with_message("waiting for human approval");
                    let _ = client.notify_progress(notification).await;
                }
            }
        }
    }
}

#[tool_router(server_handler)]
impl AgentTools {
    /// Re-evaluate the sandbox environment from the nix files currently in the working
    /// directory. Edit flake.nix (or the files it imports) first, then call this with the
    /// reason for the change. If the result differs from the applied environment a human
    /// must approve it; this call blocks until they decide. Results: unchanged,
    /// eval_error, applied, restart_scheduled, build_error, rejected, still_pending (call
    /// again with the same files to keep waiting).
    #[tool]
    async fn reload_env(
        &self,
        Parameters(args): Parameters<ReloadEnvArgs>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let reason = args.reason.unwrap_or_default();

        let outcome = match self.daemon.agent_reload(&self.run_id, reason).await {
            Ok(decision) => self.wait_for_decision(decision, &meta, &client).await,
            Err(immediate) => immediate,
        };

        let is_error = matches!(outcome.kind.as_str(), "eval_error" | "build_error");
        let body = json!({ "result": outcome.kind, "message": outcome.message }).to_string();

        Ok(if is_error { error(body) } else { text(body) })
    }

    /// List accesses this sandbox run was denied (e.g. network destinations not in
    /// network.allow). Use it to decide what to request with reload_env.
    #[tool]
    async fn list_denials(&self) -> Result<CallToolResult, ErrorData> {
        Ok(text(pretty(&self.daemon.run_denials(&self.run_id))))
    }

    /// Return the effective sandbox policy (repository policy intersected with the
    /// host's limits).
    #[tool]
    async fn current_policy(&self) -> Result<CallToolResult, ErrorData> {
        Ok(match self.daemon.run_policy(&self.run_id) {
            Some(policy) => text(pretty(&policy)),
            None => error("no policy applied".into()),
        })
    }
}

/// Serves one MCP session until the client disconnects.
pub async fn serve_conn(daemon: Arc<Daemon>, run_id: String, stream: UnixStream) {
    let tools = AgentTools { daemon, run_id };

    if let Ok(session) = tools.serve(stream).await {
        let _ = session.waiting().await;
    }
}
