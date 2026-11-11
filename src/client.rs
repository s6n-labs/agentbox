//! Host-side CLI commands. The CLI is a thin client: all state lives in the daemon.

use std::collections::BTreeMap;
use std::io::{IoSlice, IsTerminal, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use anyhow::{Context, bail};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use crate::proto::*;
use crate::{config, rpc};

/// Terminal-related variables forwarded into the sandbox.
const FORWARDED_VARS: &[&str] = &["TERM", "COLORTERM", "LANG", "LC_ALL"];

/// Blocking handle to the daemon, targeting the current directory.
pub struct Client {
    runtime: tokio::runtime::Runtime,
    pub target: Target,
}

impl Client {
    pub fn new(sandbox: String) -> anyhow::Result<Self> {
        let workdir = std::env::current_dir()?.to_string_lossy().into_owned();

        Ok(Self {
            runtime: tokio::runtime::Runtime::new()?,
            target: Target { workdir, sandbox },
        })
    }

    pub fn call<Q: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        req: &Q,
    ) -> anyhow::Result<R> {
        let socket = config::socket_path();
        self.runtime.block_on(rpc::call(&socket, method, req))
    }
}

/// Renders a JSON Patch as one line per operation: `add /network/allow/2 "github.com:443"`.
fn format_patch(patch: &Value) -> Vec<String> {
    let operations = patch.as_array().map(Vec::as_slice).unwrap_or_default();

    operations
        .iter()
        .map(|operation| {
            let name = operation["op"].as_str().unwrap_or("?");
            let path = operation["path"].as_str().unwrap_or("");

            match operation.get("value") {
                Some(value) => format!("{name} {path} {value}"),
                None => format!("{name} {path}"),
            }
        })
        .collect()
}

/// Lines shown for a diff, both by `review` and by confirmation prompts.
pub fn format_diff(diff: &Diff) -> Vec<String> {
    let mut lines = Vec::new();

    if let Some(reason) = &diff.reason {
        lines.push(format!("# reason: {reason}"));
    }

    lines.push("# policy".into());
    let patch = format_patch(&diff.policy_patch);
    if patch.is_empty() {
        lines.push("(unchanged)".into());
    }
    lines.extend(patch);

    let derivation = if diff.drv_changed {
        "changed"
    } else {
        "unchanged"
    };
    lines.push(format!("# environment (derivation {derivation})"));
    lines.extend(diff.text_diff.lines().map(str::to_owned));

    lines
}

/// Shows edits nobody approved and asks whether to apply them.
fn confirm(diff: &Diff) -> anyhow::Result<()> {
    eprintln!(
        "agentbox: the nix files changed since the last approval, and an agent has run here \
         since:\n"
    );
    for line in format_diff(diff) {
        eprintln!("{line}");
    }

    if !std::io::stdin().is_terminal() {
        bail!("refusing to apply unapproved changes non-interactively; pass --yes to accept them");
    }

    eprint!("\nApply these changes? [y/N] ");
    std::io::stderr().flush()?;

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        bail!("aborted");
    }
    Ok(())
}

/// Hands our terminal to the daemon (no PTY relay).
///
/// The returned connection must stay open: the daemon stops the run when it closes.
fn attach_terminal(fd_socket: &str) -> anyhow::Result<UnixStream> {
    let socket = UnixStream::connect(fd_socket).context("attaching to the run")?;

    let stdio = [0, 1, 2];
    sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(b"x")],
        &[ControlMessage::ScmRights(&stdio)],
        MsgFlags::empty(),
        None,
    )?;

    Ok(socket)
}

/// Waits for the run to exit, forwarding signals to it meanwhile.
async fn wait_forwarding_signals(run_id: String) -> anyhow::Result<i32> {
    let socket = config::socket_path();

    let (signals, mut received) = mpsc::unbounded_channel();
    let kinds = [
        SignalKind::interrupt(),
        SignalKind::terminate(),
        SignalKind::hangup(),
        SignalKind::quit(),
        SignalKind::window_change(),
    ];
    for kind in kinds {
        let mut stream = signal(kind)?;
        let signals = signals.clone();

        tokio::spawn(async move {
            while stream.recv().await.is_some() {
                let _ = signals.send(kind.as_raw_value());
            }
        });
    }

    let run_ref = RunRef {
        run_id: run_id.clone(),
    };
    let exited = rpc::call::<_, WaitRunRes>(&socket, "WaitRun", &run_ref);
    tokio::pin!(exited);

    loop {
        tokio::select! {
            response = &mut exited => return Ok(response?.exit_code),

            Some(signal) = received.recv() => {
                let req = SignalReq { run_id: run_id.clone(), signal };
                let _ = rpc::call::<_, Value>(&socket, "SignalRun", &req).await;
            }
        }
    }
}

/// `agentbox run`: returns the command's exit code.
pub fn run(client: &Client, yes: bool, argv: Vec<String>) -> anyhow::Result<i32> {
    let env: BTreeMap<String, String> = FORWARDED_VARS
        .iter()
        .filter_map(|name| Some((name.to_string(), std::env::var(name).ok()?)))
        .collect();

    let mut req = CreateRunReq {
        target: client.target.clone(),
        argv,
        confirm: yes,
        env,
    };

    let (run_id, fd_socket) = loop {
        let res: CreateRunRes = client.call("CreateRun", &req)?;

        if let Some(diff) = res.needs_confirm {
            confirm(&diff)?;
            req.confirm = true;
            continue;
        }

        match (res.run_id, res.fd_socket) {
            (Some(run_id), Some(fd_socket)) => break (run_id, fd_socket),
            _ => bail!("unexpected response from the daemon"),
        }
    };

    let _terminal = attach_terminal(&fd_socket)?;
    client.runtime.block_on(wait_forwarding_signals(run_id))
}

/// `agentbox reload`
pub fn reload(client: &Client, yes: bool) -> anyhow::Result<()> {
    let mut req = ReloadReq {
        target: client.target.clone(),
        confirm: yes,
    };

    loop {
        let res: ReloadRes = client.call("Reload", &req)?;

        let Some(diff) = res.needs_confirm else {
            println!("{}", res.result.unwrap_or_default());
            return Ok(());
        };

        confirm(&diff)?;
        req.confirm = true;
    }
}

/// `agentbox accept` and `agentbox reject`
pub fn decide(client: &Client, accept: bool, reason: String) -> anyhow::Result<()> {
    let req = DecideReq {
        target: client.target.clone(),
        accept,
        reason,
    };
    let res: TextRes = client.call("Decide", &req)?;

    println!("{}", res.text);
    Ok(())
}

/// `agentbox policy`
pub fn policy(client: &Client, effective: bool) -> anyhow::Result<()> {
    let req = PolicyReq {
        target: client.target.clone(),
        effective,
    };
    let policy: Value = client.call("GetPolicy", &req)?;

    println!("{}", serde_json::to_string_pretty(&policy)?);
    Ok(())
}

/// `agentbox denials`
pub fn denials(client: &Client) -> anyhow::Result<()> {
    let res: DenialsRes = client.call("ListDenials", &client.target)?;

    for denial in res.denials {
        println!(
            "{}\t{}\t{}\t{}",
            denial.time, denial.run_id, denial.kind, denial.target
        );
    }
    Ok(())
}

/// `agentbox explain`
pub fn explain(client: &Client, what: String) -> anyhow::Result<()> {
    let req = ExplainReq {
        target: client.target.clone(),
        what,
    };
    let res: TextRes = client.call("Explain", &req)?;

    println!("{}", res.text);
    Ok(())
}
