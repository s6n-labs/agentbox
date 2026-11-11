//! Run lifecycle: one `agentbox run` is one sandbox, living as long as its command.

use std::collections::BTreeMap;
use std::os::unix::fs::chown;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use buffa::MessageField;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::{self, is_root};
use crate::nixcmd::Owner;
use crate::policy::Policy;
use crate::proto::*;
use crate::sandbox::{BRIDGE_PORT, DevEnv};
use crate::{mcp, proxy};
use connectrpc::ConnectError;

use super::environment::trigger_restart;
use super::fsutil::{recv_stdio, set_mode, write_atomic};
use super::state::{Key, Run};
use super::{Daemon, internal, not_found, precondition};

const MAX_DENIALS: usize = 500;

/// Variables the CLI may forward from the human's terminal.
const TERMINAL_VARS: &[&str] = &["TERM", "COLORTERM", "LANG", "LC_ALL"];

/// Where a run keeps its files.
struct RunPaths {
    /// env.sh, shell rc files and the agent-facing sockets. Read-only in the sandbox.
    dir: PathBuf,
    dir_inside: PathBuf,
    /// Directory holding the Nix profile (GC root) of the run.
    gcroot: PathBuf,
    /// Socket the CLI attaches its terminal to. Not visible in the sandbox.
    ctl: PathBuf,
}

/// The proxy listens on a Unix socket on Linux (the sandbox has no network at all)
/// and on a local TCP port on macOS (no network namespaces there).
enum ProxyListener {
    Unix(UnixListener),
    Tcp(TcpListener),
}

struct RunSockets {
    agent: UnixListener,
    ctl: UnixListener,
    proxy: ProxyListener,
}

fn exit_response(exit_code: i32) -> WaitRunResponse {
    WaitRunResponse {
        exit_code,
        ..Default::default()
    }
}

fn now() -> u64 {
    let since_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since_epoch.map_or(0, |d| d.as_secs())
}

impl Daemon {
    fn run_paths(&self, id: &str) -> RunPaths {
        let dir = self.state_dir.join("runs").join(id);
        let dir_inside = if cfg!(target_os = "macos") {
            dir.clone()
        } else {
            PathBuf::from("/run/agentbox")
        };

        RunPaths {
            dir,
            dir_inside,
            gcroot: config::gcroots_dir().join(id),
            ctl: self.state_dir.join("ctl").join(format!("{id}.sock")),
        }
    }

    /// Creates the run directory with its static files and sockets.
    fn prepare_run(
        &self,
        paths: &RunPaths,
        key: &Key,
        owner: &Owner,
    ) -> anyhow::Result<RunSockets> {
        let (uid, gid) = self.sandbox_ids(owner);
        let inside = paths.dir_inside.display();

        std::fs::create_dir_all(paths.dir.join("zdotdir"))?;
        std::fs::create_dir_all(&paths.gcroot)?;

        // Shells source env.sh before every command; that is how hot reload reaches them.
        write_atomic(
            &paths.dir.join("zdotdir/.zshenv"),
            &format!(". {inside}/env.sh\n"),
        )?;

        // One line only: Claude Code has been reported to expand this file's content
        // into arguments.
        write_atomic(
            &paths.dir.join("claude-env"),
            &format!("source {inside}/env.sh\n"),
        )?;

        let home = key.workdir.join(".agentbox/home");
        write_atomic(
            &paths.dir.join("passwd"),
            &format!("agent:x:{uid}:{gid}::{}:/bin/sh\n", home.display()),
        )?;

        let agent = UnixListener::bind(paths.dir.join("agent.sock"))?;
        let ctl = UnixListener::bind(&paths.ctl)?;
        let proxy = if cfg!(target_os = "macos") {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            ProxyListener::Tcp(TcpListener::from_std(listener)?)
        } else {
            ProxyListener::Unix(UnixListener::bind(paths.dir.join("proxy.sock"))?)
        };

        if is_root() {
            // The sandbox user may read the run directory and connect to its sockets,
            // but never write there.
            set_mode(&paths.dir, 0o750)?;
            for name in ["", "zdotdir", "agent.sock", "proxy.sock"] {
                let path = paths.dir.join(name);
                if path.exists() {
                    chown(&path, Some(0), Some(gid))?;
                }
            }
            for socket in ["agent.sock", "proxy.sock"] {
                let _ = set_mode(&paths.dir.join(socket), 0o660);
            }

            chown(&paths.ctl, Some(owner.uid), None)?;
            chown(&paths.gcroot, Some(owner.uid), Some(owner.gid))?;
        }

        Ok(RunSockets { agent, ctl, proxy })
    }

    pub(super) async fn create_run(
        self: &Arc<Self>,
        uid: u32,
        req: CreateRunRequest,
    ) -> Result<CreateRunResponse, ConnectError> {
        if req.argv.is_empty() {
            return Err(ConnectError::invalid_argument("no command given"));
        }

        let (key, owner) = self.target(uid, &req.target)?;
        let eval = self.evaluate(&key, &owner).await.map_err(precondition)?;

        if let Some(diff) = self.unapproved_changes(&key, &eval, req.confirm) {
            return Ok(CreateRunResponse {
                needs_confirm: MessageField::some(diff),
                ..Default::default()
            });
        }

        let id = {
            let mut state = self.lock();
            state.next_run += 1;
            format!("r{}", state.next_run)
        };
        let paths = self.run_paths(&id);
        let sockets = self.prepare_run(&paths, &key, &owner).map_err(internal)?;

        let proxy_port = match &sockets.proxy {
            ProxyListener::Tcp(listener) => listener.local_addr().map_err(internal)?.port(),
            ProxyListener::Unix(_) => BRIDGE_PORT,
        };
        let term_env: BTreeMap<String, String> = req
            .env
            .into_iter()
            .filter(|(name, _)| TERMINAL_VARS.contains(&name.as_str()))
            .collect();

        let run = Run {
            key: key.clone(),
            owner,
            argv: req.argv,
            term_env,
            dir: paths.dir.clone(),
            dir_inside: paths.dir_inside.clone(),
            profile: paths.gcroot.join("env"),
            proxy_port,
            stdio: None,
            pgid: None,
            exe_path: None,
            dev: DevEnv::default(),
            busy: false,
            restart: None,
            restart_when_idle: None,
            exit: watch::channel(None).0,
            mcp_sessions: Vec::new(),
            tasks: Vec::new(),
        };
        self.lock().runs.insert(id.clone(), run);

        // A run is also a reload: it brings the whole workdir to the current files.
        if let Err(e) = self.apply(&key, &eval).await {
            self.remove_run(&id);
            return Err(precondition(e));
        }

        let tasks = self.start_run_tasks(&id, uid, sockets);
        match self.lock().runs.get_mut(&id) {
            Some(run) => run.tasks = tasks,
            None => tasks.iter().for_each(JoinHandle::abort),
        }

        Ok(CreateRunResponse {
            run_id: id,
            fd_socket: paths.ctl.to_string_lossy().into_owned(),
            ..Default::default()
        })
    }

    /// Serves the run's sockets until the run is removed.
    fn start_run_tasks(
        self: &Arc<Self>,
        id: &str,
        uid: u32,
        sockets: RunSockets,
    ) -> Vec<JoinHandle<()>> {
        let RunSockets { agent, ctl, proxy } = sockets;

        let (daemon, run_id) = (self.clone(), id.to_owned());
        let mcp_task = tokio::spawn(async move {
            while let Ok((stream, _)) = agent.accept().await {
                tokio::spawn(mcp::serve_conn(daemon.clone(), run_id.clone(), stream));
            }
        });

        let (daemon, run_id) = (self.clone(), id.to_owned());
        let proxy_task = tokio::spawn(async move { daemon.serve_proxy(&run_id, proxy).await });

        let (daemon, run_id) = (self.clone(), id.to_owned());
        let attach_task = tokio::spawn(async move {
            let Err(error) = daemon.attach(&run_id, ctl, uid).await else {
                return;
            };

            // Tell the human at the terminal, if we got one.
            let message = format!("agentbox: {error:#}\n");
            if let Some(stdio) = daemon
                .lock()
                .runs
                .get(&run_id)
                .and_then(|r| r.stdio.as_ref())
            {
                let _ = nix::unistd::write(&stdio[2], message.as_bytes());
            }
            daemon.finish(&run_id, 127);
        });

        vec![mcp_task, proxy_task, attach_task]
    }

    async fn serve_proxy(self: Arc<Self>, run_id: &str, listener: ProxyListener) {
        loop {
            let (daemon, id) = (self.clone(), run_id.to_owned());
            let allowed = move |host: &str, port: u16| daemon.check_network(&id, host, port);

            match &listener {
                ProxyListener::Unix(listener) => {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(async move { proxy::handle(stream, allowed).await });
                }
                ProxyListener::Tcp(listener) => {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(async move { proxy::handle(stream, allowed).await });
                }
            }
        }
    }

    /// Receives the CLI's terminal, starts the sandbox, and ties its life to the CLI.
    async fn attach(self: &Arc<Self>, id: &str, ctl: UnixListener, uid: u32) -> anyhow::Result<()> {
        let accepted = tokio::time::timeout(Duration::from_secs(30), ctl.accept()).await;
        let (stream, _) = accepted.context("the CLI never attached")??;
        anyhow::ensure!(stream.peer_cred()?.uid() == uid, "peer mismatch");

        // SCM_RIGHTS needs a blocking recvmsg.
        let stream = stream.into_std()?;
        stream.set_nonblocking(false)?;
        let (stream, stdio) =
            tokio::task::spawn_blocking(move || recv_stdio(&stream).map(|fds| (stream, fds)))
                .await??;

        if let Some(run) = self.lock().runs.get_mut(id) {
            run.stdio = Some(stdio);
        }
        self.spawn_sandbox(id, None).map_err(anyhow::Error::msg)?;

        // The CLI keeps this connection open for as long as it lives.
        stream.set_nonblocking(true)?;
        let mut stream = UnixStream::from_std(stream)?;
        let mut buf = [0u8; 16];
        while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}

        self.hang_up(id).await;
        Ok(())
    }

    /// The CLI is gone, so nothing owns the terminal anymore: stop the sandbox.
    async fn hang_up(&self, id: &str) {
        for signal in [Signal::SIGHUP, Signal::SIGKILL] {
            let pgid = self.lock().runs.get_mut(id).and_then(|run| {
                run.restart = None;
                run.restart_when_idle = None;
                run.pgid
            });
            let Some(pgid) = pgid else {
                return;
            };

            let _ = killpg(Pid::from_raw(pgid), signal);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    /// Reports the exit code to the CLI and forgets the run.
    pub(super) fn finish(&self, id: &str, code: i32) {
        {
            let mut state = self.lock();
            if let Some(run) = state.runs.get(id) {
                let _ = run.exit.send(Some(code));
                state.exited.insert(id.to_owned(), code);
            }
        }

        self.remove_run(id);
    }

    /// Drops the run, its directory and its GC roots. The store is left to Nix's GC.
    fn remove_run(&self, id: &str) {
        let Some(run) = self.lock().runs.remove(id) else {
            return;
        };
        run.tasks.iter().for_each(JoinHandle::abort);

        let paths = self.run_paths(id);
        let _ = std::fs::remove_dir_all(&paths.dir);
        let _ = std::fs::remove_dir_all(&paths.gcroot);
        let _ = std::fs::remove_file(&paths.ctl);
    }

    /// Proxy hook: is this run allowed to reach `host:port`? Denials are recorded.
    fn check_network(&self, run_id: &str, host: &str, port: u16) -> bool {
        let mut state = self.lock();
        let Some(key) = state.runs.get(run_id).map(|run| run.key.clone()) else {
            return false;
        };

        let policy = state.approved(&key).and_then(|a| self.effective(a).ok());
        let allowed = policy.is_some_and(|p| p.net_allowed(host, port));
        if allowed {
            return true;
        }

        let denials = &mut state.dirs.entry(key).or_default().denials;
        if denials.len() >= MAX_DENIALS {
            denials.pop_front();
        }
        denials.push_back(Denial {
            run_id: run_id.to_owned(),
            time: now(),
            kind: "network".into(),
            target: format!("{host}:{port}"),
            ..Default::default()
        });
        false
    }

    // ---- RPCs ----

    /// Runs `f` on a run after checking that the peer owns it.
    fn with_run<T>(
        &self,
        uid: u32,
        id: &str,
        f: impl FnOnce(&Run) -> T,
    ) -> Result<T, ConnectError> {
        let state = self.lock();
        let run = state.runs.get(id).ok_or_else(|| not_found("no such run"))?;

        if uid != 0 && run.owner.uid != uid {
            return Err(ConnectError::permission_denied("not your run"));
        }
        Ok(f(run))
    }

    pub(super) async fn wait_run(
        &self,
        uid: u32,
        req: WaitRunRequest,
    ) -> Result<WaitRunResponse, ConnectError> {
        // The command may have exited before the CLI got here.
        if let Some(exit_code) = self.lock().exited.remove(&req.run_id) {
            return Ok(exit_response(exit_code));
        }

        let mut exit = self.with_run(uid, &req.run_id, |run| run.exit.subscribe())?;
        loop {
            if let Some(exit_code) = *exit.borrow() {
                self.lock().exited.remove(&req.run_id);
                return Ok(exit_response(exit_code));
            }

            exit.changed().await.map_err(|_| internal("run vanished"))?;
        }
    }

    pub(super) fn signal_run(
        &self,
        uid: u32,
        req: SignalRunRequest,
    ) -> Result<SignalRunResponse, ConnectError> {
        let pgid = self.with_run(uid, &req.run_id, |run| run.pgid)?;
        let signal = Signal::try_from(req.signal)
            .map_err(|e| ConnectError::invalid_argument(e.to_string()))?;

        if let Some(pgid) = pgid {
            let _ = killpg(Pid::from_raw(pgid), signal);
        }
        Ok(SignalRunResponse::default())
    }

    pub(super) fn denials(
        &self,
        uid: u32,
        target: &Target,
    ) -> Result<ListDenialsResponse, ConnectError> {
        let (key, _) = self.target(uid, target)?;
        let state = self.lock();

        let denials = match state.dirs.get(&key) {
            Some(dir) => dir.denials.iter().cloned().collect(),
            None => Vec::new(),
        };
        Ok(ListDenialsResponse {
            denials,
            ..Default::default()
        })
    }

    // ---- agent side (per-run socket, see mcp.rs) ----

    pub fn register_mcp_session(&self, run_id: &str, session: mpsc::UnboundedSender<String>) {
        if let Some(run) = self.lock().runs.get_mut(run_id) {
            run.mcp_sessions.push(session);
        }
    }

    /// Called by the agent's turn hooks. A restart waiting for the turn to end happens now.
    pub fn set_busy(&self, run_id: &str, busy: bool) {
        let mut state = self.lock();
        let Some(run) = state.runs.get_mut(run_id) else {
            return;
        };

        run.busy = busy;
        if busy {
            return;
        }

        if let Some(message) = run.restart_when_idle.take() {
            trigger_restart(run, message);
        }
    }

    pub fn run_denials(&self, run_id: &str) -> Vec<Denial> {
        let state = self.lock();
        let Some(dir) = state
            .runs
            .get(run_id)
            .and_then(|run| state.dirs.get(&run.key))
        else {
            return Vec::new();
        };

        dir.denials
            .iter()
            .filter(|denial| denial.run_id == run_id)
            .cloned()
            .collect()
    }

    pub fn run_policy(&self, run_id: &str) -> Option<Policy> {
        let state = self.lock();
        let run = state.runs.get(run_id)?;
        let approved = state.approved(&run.key)?;

        self.effective(approved).ok()
    }
}
