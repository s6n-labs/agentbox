mod config;
mod daemon;
mod inner;
mod mcp;
mod nixcmd;
mod policy;
mod proto;
mod proxy;
mod review;
mod rpc;
mod sandbox;

use std::io::{IoSlice, IsTerminal, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::signal::unix::{SignalKind, signal};

use proto::*;

#[derive(Parser)]
#[command(name = "agentbox", version, about = "Nix-based sandbox for LLM agents")]
struct Cli {
    /// Sandbox name under `agentSandboxes.<system>`.
    #[arg(short, long, global = true, default_value = "default")]
    sandbox: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the host daemon (normally started by systemd/launchd).
    Daemon,
    /// Run a command in a new sandbox for the current directory; it lives as long as the command.
    Run {
        /// Accept nix file edits an agent may have left unapproved.
        #[arg(short, long)]
        yes: bool,
        #[arg(required = true, last = true)]
        argv: Vec<String>,
    },
    /// Re-evaluate the current files and apply them to every run of this directory (no approval).
    Reload {
        #[arg(short, long)]
        yes: bool,
    },
    /// Review the agent's pending environment request.
    Review {
        #[arg(long)]
        json: bool,
    },
    /// Approve the pending request without the TUI.
    Accept,
    /// Reject the pending request; the reason is returned to the agent.
    Reject {
        #[arg(short, long)]
        message: String,
    },
    /// Print the policy of the current files.
    Policy {
        /// Repository layer ∩ host layer.
        #[arg(long)]
        effective: bool,
    },
    /// List denied accesses.
    Denials,
    /// Show which rule allows or denies a path or domain.
    Explain { what: String },
    /// (inside the sandbox) MCP server on stdio.
    Mcp,
    #[command(hide = true)]
    Inner {
        #[arg(last = true)]
        argv: Vec<String>,
    },
    #[command(hide = true)]
    Hook { state: String },
}

/// Blocking handle to the daemon for the current directory.
pub struct Client {
    rt: tokio::runtime::Runtime,
    pub target: Target,
}

impl Client {
    fn new(sandbox: String) -> anyhow::Result<Self> {
        let workdir = std::env::current_dir()?.to_string_lossy().into_owned();
        Ok(Self { rt: tokio::runtime::Runtime::new()?, target: Target { workdir, sandbox } })
    }

    pub fn call<Q: Serialize, R: DeserializeOwned>(&self, method: &str, req: &Q) -> anyhow::Result<R> {
        self.rt.block_on(rpc::call(&config::socket_path(), method, req))
    }
}

pub fn format_patch(patch: &serde_json::Value) -> Vec<String> {
    let ops = patch.as_array().map(Vec::as_slice).unwrap_or_default();
    ops.iter()
        .map(|op| {
            let (name, path) = (op["op"].as_str().unwrap_or("?"), op["path"].as_str().unwrap_or(""));
            match op.get("value") {
                Some(v) => format!("{name} {path} {v}"),
                None => format!("{name} {path}"),
            }
        })
        .collect()
}

pub fn format_diff(diff: &Diff) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(reason) = &diff.reason {
        lines.push(format!("# reason: {reason}"));
    }
    lines.push("# policy".into());
    let patch = format_patch(&diff.policy_patch);
    lines.extend(if patch.is_empty() { vec!["(unchanged)".into()] } else { patch });
    lines.push(format!("# environment (derivation {})", if diff.drv_changed { "changed" } else { "unchanged" }));
    lines.extend(diff.text_diff.lines().map(str::to_owned));
    lines
}

/// Shows unapproved edits and asks whether to apply them.
fn confirm(diff: &Diff) -> anyhow::Result<()> {
    eprintln!("agentbox: the nix files changed since the last approval, and an agent has run here since:\n");
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

fn run(client: &Client, mut yes: bool, argv: Vec<String>) -> anyhow::Result<i32> {
    let env = ["TERM", "COLORTERM", "LANG", "LC_ALL"].iter().filter_map(|k| Some((k.to_string(), std::env::var(k).ok()?))).collect();
    let mut req = CreateRunReq { target: client.target.clone(), argv, confirm: yes, env };
    let (run_id, fd_socket) = loop {
        req.confirm = yes;
        let res: CreateRunRes = client.call("CreateRun", &req)?;
        match (res.needs_confirm, res.run_id, res.fd_socket) {
            (Some(diff), ..) => {
                confirm(&diff)?;
                yes = true;
            }
            (None, Some(id), Some(sock)) => break (id, sock),
            _ => bail!("unexpected response from the daemon"),
        }
    };

    // Hand our terminal to the daemon: no PTY relay. The socket stays open so the
    // daemon notices if we die.
    let ctl = UnixStream::connect(&fd_socket).context("attaching to the run")?;
    let fds = [0, 1, 2];
    sendmsg::<()>(ctl.as_raw_fd(), &[IoSlice::new(b"x")], &[ControlMessage::ScmRights(&fds)], MsgFlags::empty(), None)?;

    client.rt.block_on(async {
        let socket = config::socket_path();
        let run_ref = RunRef { run_id: run_id.clone() };
        let wait = rpc::call::<_, WaitRunRes>(&socket, "WaitRun", &run_ref);
        tokio::pin!(wait);
        let kinds = [SignalKind::interrupt(), SignalKind::terminate(), SignalKind::hangup(), SignalKind::quit(), SignalKind::window_change()];
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        for kind in kinds {
            let (tx, mut stream) = (tx.clone(), signal(kind)?);
            tokio::spawn(async move {
                while stream.recv().await.is_some() {
                    let _ = tx.send(kind.as_raw_value());
                }
            });
        }
        loop {
            tokio::select! {
                res = &mut wait => break Ok(res?.exit_code),
                Some(sig) = rx.recv() => {
                    let req = SignalReq { run_id: run_id.clone(), signal: sig };
                    let _ = rpc::call::<_, serde_json::Value>(&socket, "SignalRun", &req).await;
                }
            }
        }
    })
}

fn main() {
    let cli = Cli::parse();
    let result = (|| -> anyhow::Result<i32> {
        // These run inside the sandbox and must not start a runtime (the bootstrap forks).
        match &cli.cmd {
            Cmd::Inner { argv } => return inner::inner(argv).map(|_| 0),
            Cmd::Mcp => return inner::mcp().map(|_| 0),
            Cmd::Hook { state } => return inner::hook(state).map(|_| 0),
            Cmd::Daemon => return tokio::runtime::Runtime::new()?.block_on(daemon::main()).map(|_| 0),
            _ => {}
        }
        let client = Client::new(cli.sandbox)?;
        let target = client.target.clone();
        match cli.cmd {
            Cmd::Run { yes, argv } => return run(&client, yes, argv),
            Cmd::Reload { mut yes } => loop {
                let res: ReloadRes = client.call("Reload", &ReloadReq { target: target.clone(), confirm: yes })?;
                match (res.needs_confirm, res.result) {
                    (Some(diff), _) => {
                        confirm(&diff)?;
                        yes = true;
                    }
                    (None, result) => {
                        println!("{}", result.unwrap_or_default());
                        break;
                    }
                }
            },
            Cmd::Review { json } => review::run(&client, json)?,
            Cmd::Accept | Cmd::Reject { .. } => {
                let (accept, reason) = match cli.cmd {
                    Cmd::Reject { message } => (false, message),
                    _ => (true, String::new()),
                };
                let res: TextRes = client.call("Decide", &DecideReq { target, accept, reason })?;
                println!("{}", res.text);
            }
            Cmd::Policy { effective } => {
                let v: serde_json::Value = client.call("GetPolicy", &PolicyReq { target, effective })?;
                println!("{}", serde_json::to_string_pretty(&v)?);
            }
            Cmd::Denials => {
                let res: DenialsRes = client.call("ListDenials", &target)?;
                for d in res.denials {
                    println!("{}\t{}\t{}\t{}", d.time, d.run_id, d.kind, d.target);
                }
            }
            Cmd::Explain { what } => {
                let res: TextRes = client.call("Explain", &ExplainReq { target, what })?;
                println!("{}", res.text);
            }
            Cmd::Daemon | Cmd::Mcp | Cmd::Inner { .. } | Cmd::Hook { .. } => unreachable!(),
        }
        Ok(0)
    })();
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("agentbox: {e:#}");
            std::process::exit(1);
        }
    }
}
