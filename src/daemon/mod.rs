//! The host daemon: owns evaluation, builds, approval state, runs and the outbound proxy.
//!
//! Its socket is never visible inside a sandbox, so a request on it is a human's decision.
//! Agents talk to a separate per-run socket (see `mcp.rs`) that offers no approval operations.

mod approval;
mod diff;
mod environment;
mod fsutil;
mod run;
mod spawn;
mod state;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Context;
use nix::unistd::{Uid, User};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

use crate::config::{self, Config, is_root};
use crate::nixcmd::{Eval, Owner};
use crate::policy::Policy;
use crate::proto::Target;
use crate::rpc::{self, RpcError};

use fsutil::{set_mode, write_atomic};
use state::{Key, State};

pub use state::Outcome;

const OS: &str = std::env::consts::OS;

pub struct Daemon {
    pub cfg: Config,
    state_dir: PathBuf,

    /// Nix system string, e.g. `x86_64-linux`.
    system: String,

    /// This binary on the host, and where sandboxes see it.
    exe: PathBuf,
    exe_inside: PathBuf,

    /// uid and gid of `agent_user`, when running as root.
    agent_ids: Option<(u32, u32)>,

    state: Mutex<State>,
}

fn precondition(e: impl ToString) -> RpcError {
    RpcError::new("failed_precondition", e)
}

fn internal(e: impl ToString) -> RpcError {
    RpcError::new("internal", e)
}

fn not_found(e: impl ToString) -> RpcError {
    RpcError::new("not_found", e)
}

fn is_valid_sandbox_name(name: &str) -> bool {
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    !name.is_empty() && name.chars().all(allowed)
}

impl Daemon {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Persists approval state so it survives a daemon restart.
    fn save(&self, state: &State) {
        let json = serde_json::to_string(&state.to_saved()).unwrap_or_default();

        if let Err(e) = write_atomic(&self.state_dir.join("state.json"), &json) {
            eprintln!("agentbox: cannot persist state: {e}");
        }
    }

    /// Who the sandbox runs as: the dedicated agent user if configured, else the human.
    fn sandbox_ids(&self, owner: &Owner) -> (u32, u32) {
        self.agent_ids.unwrap_or((owner.uid, owner.gid))
    }

    /// Repository policy of `eval`, capped by the host layer.
    fn effective(&self, eval: &Eval) -> Result<Policy, String> {
        let repo = Policy::parse(&eval.policy)?;
        Ok(repo.effective(&self.cfg, OS))
    }

    /// Resolves the workdir a request is about and checks that the peer owns it.
    fn target(&self, uid: u32, target: &Target) -> Result<(Key, Owner), RpcError> {
        let workdir = std::fs::canonicalize(&target.workdir)
            .map_err(|e| not_found(format!("{}: {e}", target.workdir)))?;

        let meta = std::fs::metadata(&workdir).map_err(internal)?;
        let owned = uid == 0 || std::os::unix::fs::MetadataExt::uid(&meta) == uid;
        if !meta.is_dir() || !owned {
            let message = format!("{} is not a directory you own", workdir.display());
            return Err(RpcError::new("permission_denied", message));
        }

        if !is_valid_sandbox_name(&target.sandbox) {
            return Err(RpcError::new("invalid_argument", "invalid sandbox name"));
        }

        let user = User::from_uid(Uid::from_raw(uid))
            .ok()
            .flatten()
            .ok_or_else(|| internal("unknown peer user"))?;

        let owner = Owner {
            uid,
            gid: user.gid.as_raw(),
            name: user.name,
            home: user.dir,
        };
        let key = Key {
            workdir,
            sandbox: target.sandbox.clone(),
        };
        Ok((key, owner))
    }

    /// Dispatches one RPC of the `agentbox.v1.Daemon` service.
    async fn handle(self: Arc<Self>, uid: u32, method: &str, body: &[u8]) -> RpcResult {
        match method {
            "CreateRun" => reply(self.create_run(uid, parse(body)?).await?),
            "WaitRun" => reply(self.wait_run(uid, parse(body)?).await?),
            "SignalRun" => reply(self.signal_run(uid, parse(body)?)?),
            "Reload" => reply(self.reload(uid, parse(body)?).await?),
            "GetPending" => reply(self.pending(uid, &parse(body)?)?),
            "Decide" => reply(self.decide(uid, parse(body)?).await?),
            "ClosureDiff" => reply(self.closure_diff(uid, &parse(body)?).await?),
            "GetPolicy" => reply(self.policy(uid, parse(body)?).await?),
            "Explain" => reply(self.explain(uid, parse(body)?).await?),
            "ListDenials" => reply(self.denials(uid, &parse(body)?)?),
            _ => Err(RpcError::new(
                "unimplemented",
                format!("unknown method {method:?}"),
            )),
        }
    }
}

type RpcResult = Result<Vec<u8>, RpcError>;

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, RpcError> {
    serde_json::from_slice(body).map_err(|e| RpcError::new("invalid_argument", e))
}

fn reply<T: Serialize>(response: T) -> RpcResult {
    serde_json::to_vec(&response).map_err(internal)
}

/// Every run died with the previous daemon: start from empty run directories and GC roots.
fn reset_run_dirs(state_dir: &Path) -> anyhow::Result<()> {
    let gcroots = config::gcroots_dir();
    let dirs = [state_dir.join("runs"), state_dir.join("ctl"), gcroots];

    for dir in &dirs {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    if !is_root() {
        return Ok(set_mode(state_dir, 0o700)?);
    }

    // As root, other users may pass through these directories but not list them.
    set_mode(state_dir, 0o711)?;
    for dir in &dirs {
        set_mode(dir, 0o711)?;
    }
    Ok(())
}

/// Looks up the dedicated agent user. Only a root daemon can switch users.
fn agent_ids(cfg: &Config) -> anyhow::Result<Option<(u32, u32)>> {
    let Some(name) = &cfg.agent_user else {
        return Ok(None);
    };

    if !is_root() {
        eprintln!("agentbox: agent_user is ignored: the daemon is not running as root");
        return Ok(None);
    }

    let user =
        User::from_name(name)?.with_context(|| format!("agent_user {name:?} does not exist"))?;
    Ok(Some((user.uid.as_raw(), user.gid.as_raw())))
}

fn load_state(state_dir: &Path) -> State {
    let saved = std::fs::read_to_string(state_dir.join("state.json"))
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    State::from_saved(saved)
}

fn bind_socket() -> anyhow::Result<(UnixListener, PathBuf)> {
    let path = config::socket_path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&path);

    let listener =
        UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;

    // A root daemon serves every user and authorizes each request by peer credentials.
    set_mode(&path, if is_root() { 0o666 } else { 0o600 })?;

    Ok((listener, path))
}

pub async fn main() -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let state_dir = config::state_dir();
    reset_run_dirs(&state_dir)?;

    let on_macos = cfg!(target_os = "macos");
    let exe = std::env::current_exe()?;
    let exe_inside = if on_macos {
        exe.clone()
    } else {
        PathBuf::from("/run/agentbox-bin/agentbox")
    };
    let arch = std::env::consts::ARCH;
    let system = format!("{arch}-{}", if on_macos { "darwin" } else { "linux" });

    let daemon = Arc::new(Daemon {
        agent_ids: agent_ids(&cfg)?,
        state: Mutex::new(load_state(&state_dir)),
        cfg,
        state_dir,
        system,
        exe,
        exe_inside,
    });

    let (listener, socket) = bind_socket()?;
    eprintln!("agentbox: listening on {}", socket.display());

    let serve = rpc::serve(listener, move |uid, method, body| {
        let daemon = daemon.clone();
        async move { daemon.handle(uid, &method, &body).await }
    });

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = serve => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }

    // Sandboxes die with us (bwrap --die-with-parent).
    let _ = std::fs::remove_file(&socket);
    Ok(())
}
