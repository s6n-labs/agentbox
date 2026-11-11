//! Host-side CLI commands. The CLI is a thin client: all state lives in the daemon.

use std::io::{IoSlice, IsTerminal, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use anyhow::{Context, anyhow, bail};
use buffa::{Inline, MessageField};
use connectrpc::{ConnectError, ErrorCode};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use serde_json::Value;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

use agentbox::config;
use agentbox::proto::*;
use agentbox::rpc::{self, DaemonClient};

/// Terminal-related variables forwarded into the sandbox.
const FORWARDED_VARS: &[&str] = &["TERM", "COLORTERM", "LANG", "LC_ALL"];

/// Blocking handle to the daemon, targeting the current directory.
pub struct Client {
    runtime: tokio::runtime::Runtime,
    pub daemon: DaemonClient,
    target: Target,
}

impl Client {
    pub fn new(sandbox: String) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Runtime::new()?;
        let workdir = std::env::current_dir()?.to_string_lossy().into_owned();

        // The connection is established lazily, from within the runtime.
        let daemon = {
            let _guard = runtime.enter();
            rpc::client(&config::socket_path())
        };

        Ok(Self {
            runtime,
            daemon,
            target: Target {
                workdir,
                sandbox,
                ..Default::default()
            },
        })
    }

    /// The `target` field of a request.
    pub fn target(&self) -> MessageField<Target, Inline<Target>> {
        MessageField::some(self.target.clone())
    }

    /// Runs one RPC to completion.
    pub fn block_on<T>(
        &self,
        call: impl Future<Output = Result<T, ConnectError>>,
    ) -> anyhow::Result<T> {
        self.runtime.block_on(call).map_err(describe_error)
    }
}

/// Turns an RPC error into what the user should read.
fn describe_error(error: ConnectError) -> anyhow::Error {
    let message = error
        .message
        .unwrap_or_else(|| error.code.as_str().to_owned());

    if error.code == ErrorCode::Unavailable {
        let socket = config::socket_path();
        return anyhow!(
            "cannot reach the agentbox daemon at {} (is `agentbox daemon` running?): {message}",
            socket.display()
        );
    }

    anyhow!(message)
}

/// Renders a JSON Patch as one line per operation: `add /network/allow/2 "github.com:443"`.
fn format_patch(patch: &[PatchOperation]) -> Vec<String> {
    patch
        .iter()
        .map(|operation| match &operation.value {
            Some(value) => format!("{} {} {value}", operation.op, operation.path),
            None => format!("{} {}", operation.op, operation.path),
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

    let derivation = if diff.derivation_changed {
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
async fn wait_forwarding_signals(
    daemon: DaemonClient,
    run_id: String,
) -> Result<i32, ConnectError> {
    let (signals, mut received) = mpsc::unbounded_channel();
    let kinds = [
        SignalKind::interrupt(),
        SignalKind::terminate(),
        SignalKind::hangup(),
        SignalKind::quit(),
        SignalKind::window_change(),
    ];
    for kind in kinds {
        let mut stream = signal(kind).map_err(|e| ConnectError::internal(e.to_string()))?;
        let signals = signals.clone();

        tokio::spawn(async move {
            while stream.recv().await.is_some() {
                let _ = signals.send(kind.as_raw_value());
            }
        });
    }

    let exited = daemon.wait_run(WaitRunRequest {
        run_id: run_id.clone(),
        ..Default::default()
    });
    tokio::pin!(exited);

    loop {
        tokio::select! {
            response = &mut exited => return Ok(response?.into_owned().exit_code),

            Some(signal) = received.recv() => {
                let request = SignalRunRequest {
                    run_id: run_id.clone(),
                    signal,
                    ..Default::default()
                };
                let _ = daemon.signal_run(request).await;
            }
        }
    }
}

/// `agentbox run`: returns the command's exit code.
pub fn run(client: &Client, yes: bool, argv: Vec<String>) -> anyhow::Result<i32> {
    let env = FORWARDED_VARS
        .iter()
        .filter_map(|name| Some((name.to_string(), std::env::var(name).ok()?)))
        .collect();

    let mut request = CreateRunRequest {
        target: client.target(),
        argv,
        confirm: yes,
        env,
        ..Default::default()
    };

    let response = loop {
        let response = client
            .block_on(client.daemon.create_run(request.clone()))?
            .into_owned();

        let Some(diff) = response.needs_confirm.as_option() else {
            break response;
        };

        confirm(diff)?;
        request.confirm = true;
    };

    let _terminal = attach_terminal(&response.fd_socket)?;

    client.block_on(wait_forwarding_signals(
        client.daemon.clone(),
        response.run_id,
    ))
}

/// `agentbox reload`
pub fn reload(client: &Client, yes: bool) -> anyhow::Result<()> {
    let mut request = ReloadRequest {
        target: client.target(),
        confirm: yes,
        ..Default::default()
    };

    loop {
        let response = client
            .block_on(client.daemon.reload(request.clone()))?
            .into_owned();

        let Some(diff) = response.needs_confirm.as_option() else {
            println!("{}", response.result);
            return Ok(());
        };

        confirm(diff)?;
        request.confirm = true;
    }
}

/// `agentbox accept` and `agentbox reject`
pub fn decide(client: &Client, accept: bool, reason: String) -> anyhow::Result<()> {
    let request = DecideRequest {
        target: client.target(),
        accept,
        reason,
        ..Default::default()
    };
    let response = client.block_on(client.daemon.decide(request))?.into_owned();

    println!("{}", response.result);
    Ok(())
}

/// `agentbox policy`
pub fn policy(client: &Client, effective: bool) -> anyhow::Result<()> {
    let request = GetPolicyRequest {
        target: client.target(),
        effective,
        ..Default::default()
    };
    let response = client
        .block_on(client.daemon.get_policy(request))?
        .into_owned();

    let policy: Value = serde_json::from_str(&response.policy_json)?;
    println!("{}", serde_json::to_string_pretty(&policy)?);
    Ok(())
}

/// `agentbox denials`
pub fn denials(client: &Client) -> anyhow::Result<()> {
    let request = ListDenialsRequest {
        target: client.target(),
        ..Default::default()
    };
    let response = client
        .block_on(client.daemon.list_denials(request))?
        .into_owned();

    for denial in response.denials {
        println!(
            "{}\t{}\t{}\t{}",
            denial.time, denial.run_id, denial.kind, denial.target
        );
    }
    Ok(())
}

/// `agentbox explain`
pub fn explain(client: &Client, what: String) -> anyhow::Result<()> {
    let request = ExplainRequest {
        target: client.target(),
        what,
        ..Default::default()
    };
    let response = client
        .block_on(client.daemon.explain(request))?
        .into_owned();

    println!("{}", response.text);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(op: &str, path: &str, value: Option<&str>) -> PatchOperation {
        PatchOperation {
            op: op.into(),
            path: path.into(),
            value: value.map(str::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn patch_operations_read_like_commands() {
        let patch = [
            operation("add", "/network/allow/2", Some("\"github.com:443\"")),
            operation("remove", "/env/OLD", None),
            operation("replace", "/fs/workdirWritable", Some("false")),
        ];

        assert_eq!(
            format_patch(&patch),
            [
                "add /network/allow/2 \"github.com:443\"",
                "remove /env/OLD",
                "replace /fs/workdirWritable false",
            ]
        );
    }

    #[test]
    fn a_diff_lists_reason_policy_and_environment() {
        let diff = Diff {
            reason: Some("need github".into()),
            policy_patch: vec![operation("add", "/network/allow/1", Some("\"github.com\""))],
            text_diff: "--- a/flake.nix\n+++ b/flake.nix\n-old\n+new\n".into(),
            derivation_changed: true,
            ..Default::default()
        };

        assert_eq!(
            format_diff(&diff),
            [
                "# reason: need github",
                "# policy",
                "add /network/allow/1 \"github.com\"",
                "# environment (derivation changed)",
                "--- a/flake.nix",
                "+++ b/flake.nix",
                "-old",
                "+new",
            ]
        );
    }

    #[test]
    fn an_empty_diff_says_so() {
        let lines = format_diff(&Diff::default());

        assert_eq!(
            lines,
            [
                "# policy",
                "(unchanged)",
                "# environment (derivation unchanged)"
            ]
        );
    }

    #[test]
    fn an_unreachable_daemon_is_explained() {
        let error = describe_error(ConnectError::unavailable("connection refused"));

        let message = error.to_string();
        assert!(
            message.contains("is `agentbox daemon` running?"),
            "{message}"
        );
        assert!(message.contains("connection refused"), "{message}");
    }

    #[test]
    fn daemon_errors_are_shown_without_the_error_code() {
        let error = describe_error(ConnectError::failed_precondition(
            "error: undefined variable",
        ));

        assert_eq!(error.to_string(), "error: undefined variable");
    }
}
