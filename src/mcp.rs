//! MCP server for the agent, spoken as newline-delimited JSON-RPC on the per-run socket.
//! Approval operations are deliberately absent.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::daemon::Daemon;

fn tools() -> Value {
    json!([
        {
            "name": "reload_env",
            "description": "Re-evaluate the sandbox environment from the nix files currently in the working directory. Edit flake.nix (or the files it imports) first, then call this with the reason for the change. If the result differs from the applied environment a human must approve it; this call blocks until they decide. Results: unchanged, eval_error, applied, restart_scheduled, build_error, rejected, still_pending (call again with the same files to keep waiting).",
            "inputSchema": {
                "type": "object",
                "properties": { "reason": { "type": "string", "description": "Why the environment needs to change; shown to the human reviewer." } },
            },
        },
        {
            "name": "list_denials",
            "description": "List accesses this sandbox run was denied (e.g. network destinations not in network.allow). Use it to decide what to request with reload_env.",
            "inputSchema": { "type": "object", "properties": {} },
        },
        {
            "name": "current_policy",
            "description": "Return the effective sandbox policy (repository policy intersected with the host's limits).",
            "inputSchema": { "type": "object", "properties": {} },
        },
    ])
}

fn text_result(text: String, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

async fn call_tool(d: &Arc<Daemon>, run_id: &str, params: &Value, out: &mpsc::UnboundedSender<String>) -> Result<Value, String> {
    let args = &params["arguments"];
    match params["name"].as_str().unwrap_or("") {
        "reload_env" => {
            let reason = args["reason"].as_str().unwrap_or("").to_owned();
            let (kind, message) = match d.agent_reload(run_id, reason).await {
                Err(immediate) => immediate,
                Ok(mut rx) => {
                    // Humans are slow: keep the client's tool timeout from firing.
                    let token = params["_meta"]["progressToken"].clone();
                    let deadline = tokio::time::sleep(Duration::from_secs(d.cfg.approval_timeout_secs));
                    let mut tick = tokio::time::interval(Duration::from_secs(15));
                    tokio::pin!(deadline);
                    let mut n = 0;
                    loop {
                        if let Some(outcome) = rx.borrow().clone() {
                            break outcome;
                        }
                        tokio::select! {
                            changed = rx.changed() => if changed.is_err() {
                                break ("rejected".into(), "the request was dropped (daemon restarted?)".into());
                            },
                            _ = &mut deadline => break (
                                "still_pending".into(),
                                "Still waiting for human approval. Call reload_env again without changing the files to keep waiting.".into(),
                            ),
                            _ = tick.tick() => if !token.is_null() {
                                n += 1;
                                let _ = out.send(json!({ "jsonrpc": "2.0", "method": "notifications/progress",
                                    "params": { "progressToken": token, "progress": n, "message": "waiting for human approval" } }).to_string());
                            },
                        }
                    }
                }
            };
            let is_error = matches!(kind.as_str(), "eval_error" | "build_error");
            Ok(text_result(json!({ "result": kind, "message": message }).to_string(), is_error))
        }
        "list_denials" => Ok(text_result(serde_json::to_string_pretty(&d.run_denials(run_id)).unwrap(), false)),
        "current_policy" => match d.run_policy(run_id) {
            Some(p) => Ok(text_result(serde_json::to_string_pretty(&p).unwrap(), false)),
            None => Ok(text_result("no policy applied".into(), true)),
        },
        other => Err(format!("unknown tool {other:?}")),
    }
}

fn reply(id: &Value, result: Result<Value, (i64, String)>) -> String {
    match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    }
    .to_string()
}

pub async fn serve_conn(d: Arc<Daemon>, run_id: String, stream: UnixStream) {
    let (read, mut write) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if write.write_all(format!("{line}\n").as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let mut lines = BufReader::new(read).lines();
    let mut registered = false;
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
        let method = msg["method"].as_str().unwrap_or("").to_owned();
        let id = msg["id"].clone();
        let params = msg["params"].clone();
        if method == "agentbox/hook" {
            d.set_busy(&run_id, params["state"] == "busy");
            continue;
        }
        if id.is_null() {
            continue; // notification or a response to us
        }
        let respond = |result: Result<Value, (i64, String)>| reply(&id, result);
        match method.as_str() {
            "initialize" => {
                if !registered {
                    // Only real MCP sessions receive daemon-initiated notifications.
                    d.register_mcp(&run_id, tx.clone());
                    registered = true;
                }
                let version = params["protocolVersion"].as_str().unwrap_or("2025-06-18");
                let _ = tx.send(respond(Ok(json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {}, "logging": {} },
                    "serverInfo": { "name": "agentbox", "version": env!("CARGO_PKG_VERSION") },
                }))));
            }
            "ping" | "logging/setLevel" => {
                let _ = tx.send(respond(Ok(json!({}))));
            }
            "tools/list" => {
                let _ = tx.send(respond(Ok(json!({ "tools": tools() }))));
            }
            "tools/call" => {
                // Long-running: must not block pings on the same connection.
                let (d, run_id, tx, id) = (d.clone(), run_id.clone(), tx.clone(), id.clone());
                tokio::spawn(async move {
                    let line = reply(&id, call_tool(&d, &run_id, &params, &tx).await.map_err(|m| (-32602, m)));
                    let _ = tx.send(line);
                });
            }
            _ => {
                let _ = tx.send(respond(Err((-32601, format!("method not found: {method}")))));
            }
        }
    }
}
