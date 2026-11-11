//! MCP server for the agent, spoken as newline-delimited JSON-RPC on the per-run socket.
//!
//! Approval operations are deliberately absent: an agent can only ask.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::mpsc;

use crate::daemon::{Daemon, Outcome};

/// Lines queued for the client.
type Outbox = mpsc::UnboundedSender<String>;

const PROGRESS_INTERVAL: Duration = Duration::from_secs(15);

const RELOAD_ENV_DESCRIPTION: &str = "Re-evaluate the sandbox environment from the nix files \
    currently in the working directory. Edit flake.nix (or the files it imports) first, then \
    call this with the reason for the change. If the result differs from the applied \
    environment a human must approve it; this call blocks until they decide. Results: \
    unchanged, eval_error, applied, restart_scheduled, build_error, rejected, still_pending \
    (call again with the same files to keep waiting).";

const LIST_DENIALS_DESCRIPTION: &str = "List accesses this sandbox run was denied (e.g. network \
    destinations not in network.allow). Use it to decide what to request with reload_env.";

const CURRENT_POLICY_DESCRIPTION: &str = "Return the effective sandbox policy (repository \
    policy intersected with the host's limits).";

const REASON_DESCRIPTION: &str =
    "Why the environment needs to change; shown to the human reviewer.";

fn tools() -> Value {
    let no_arguments = json!({ "type": "object", "properties": {} });

    json!([
        {
            "name": "reload_env",
            "description": RELOAD_ENV_DESCRIPTION,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reason": { "type": "string", "description": REASON_DESCRIPTION },
                },
            },
        },
        {
            "name": "list_denials",
            "description": LIST_DENIALS_DESCRIPTION,
            "inputSchema": no_arguments,
        },
        {
            "name": "current_policy",
            "description": CURRENT_POLICY_DESCRIPTION,
            "inputSchema": no_arguments,
        },
    ])
}

fn response(id: &Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error_response(id: &Value, code: i64, message: String) -> String {
    let error = json!({ "code": code, "message": message });

    json!({ "jsonrpc": "2.0", "id": id, "error": error }).to_string()
}

fn text_result(text: String, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error,
    })
}

fn pretty<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

fn progress_notification(token: &Value, progress: u64) -> String {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": token,
            "progress": progress,
            "message": "waiting for human approval",
        },
    })
    .to_string()
}

/// `reload_env`: returns at once when no human is needed, otherwise waits for the decision.
///
/// Humans are slow, so progress notifications keep the client's tool timeout from firing,
/// and after `approval_timeout_secs` the agent is told to call again.
async fn reload_env(
    daemon: &Arc<Daemon>,
    run_id: &str,
    params: &Value,
    outbox: &Outbox,
) -> Outcome {
    let reason = params["arguments"]["reason"].as_str().unwrap_or("");

    let mut decision = match daemon.agent_reload(run_id, reason.to_owned()).await {
        Ok(decision) => decision,
        Err(immediate) => return immediate,
    };

    let progress_token = &params["_meta"]["progressToken"];
    let timeout = tokio::time::sleep(Duration::from_secs(daemon.cfg.approval_timeout_secs));
    tokio::pin!(timeout);
    let mut tick = tokio::time::interval(PROGRESS_INTERVAL);
    let mut progress = 0;

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
                    "Still waiting for human approval. Call reload_env again without changing \
                     the files to keep waiting.",
                );
            }

            _ = tick.tick() => {
                if !progress_token.is_null() {
                    progress += 1;
                    let _ = outbox.send(progress_notification(progress_token, progress));
                }
            }
        }
    }
}

async fn call_tool(
    daemon: &Arc<Daemon>,
    run_id: &str,
    params: &Value,
    outbox: &Outbox,
) -> Result<Value, String> {
    match params["name"].as_str().unwrap_or("") {
        "reload_env" => {
            let outcome = reload_env(daemon, run_id, params, outbox).await;
            let is_error = matches!(outcome.kind.as_str(), "eval_error" | "build_error");
            let text = json!({ "result": outcome.kind, "message": outcome.message });

            Ok(text_result(text.to_string(), is_error))
        }

        "list_denials" => Ok(text_result(pretty(&daemon.run_denials(run_id)), false)),

        "current_policy" => Ok(match daemon.run_policy(run_id) {
            Some(policy) => text_result(pretty(&policy), false),
            None => text_result("no policy applied".into(), true),
        }),

        other => Err(format!("unknown tool {other:?}")),
    }
}

/// Writes queued lines to the client until it goes away.
async fn write_lines(mut socket: OwnedWriteHalf, mut lines: mpsc::UnboundedReceiver<String>) {
    while let Some(line) = lines.recv().await {
        let line = format!("{line}\n");

        if socket.write_all(line.as_bytes()).await.is_err() {
            break;
        }
    }
}

pub async fn serve_conn(daemon: Arc<Daemon>, run_id: String, stream: UnixStream) {
    let (read, write) = stream.into_split();
    let (outbox, lines) = mpsc::unbounded_channel();
    tokio::spawn(write_lines(write, lines));

    let mut registered = false;
    let mut incoming = BufReader::new(read).lines();

    while let Ok(Some(line)) = incoming.next_line().await {
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let method = message["method"].as_str().unwrap_or("");
        let id = message["id"].clone();
        let params = message["params"].clone();

        // Sent by `agentbox hook`, not by MCP clients.
        if method == "agentbox/hook" {
            daemon.set_busy(&run_id, params["state"] == "busy");
            continue;
        }

        // Notifications, and responses to our own notifications, need no reply.
        if id.is_null() {
            continue;
        }

        match method {
            "initialize" => {
                // Only real MCP sessions receive daemon-initiated notifications.
                if !registered {
                    daemon.register_mcp_session(&run_id, outbox.clone());
                    registered = true;
                }

                let version = params["protocolVersion"].as_str().unwrap_or("2025-06-18");
                let result = json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {}, "logging": {} },
                    "serverInfo": { "name": "agentbox", "version": env!("CARGO_PKG_VERSION") },
                });
                let _ = outbox.send(response(&id, result));
            }

            "ping" | "logging/setLevel" => {
                let _ = outbox.send(response(&id, json!({})));
            }

            "tools/list" => {
                let _ = outbox.send(response(&id, json!({ "tools": tools() })));
            }

            "tools/call" => {
                // Can take minutes: run it beside the read loop so pings still get answered.
                let (daemon, run_id, outbox) = (daemon.clone(), run_id.clone(), outbox.clone());

                tokio::spawn(async move {
                    let line = match call_tool(&daemon, &run_id, &params, &outbox).await {
                        Ok(result) => response(&id, result),
                        Err(message) => error_response(&id, -32602, message),
                    };
                    let _ = outbox.send(line);
                });
            }

            _ => {
                let message = format!("method not found: {method}");
                let _ = outbox.send(error_response(&id, -32601, message));
            }
        }
    }
}
