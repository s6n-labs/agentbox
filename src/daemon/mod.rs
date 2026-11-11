//! The host daemon: owns evaluation, builds, approval state, runs and the outbound proxy.
//!
//! Its socket is never visible inside a sandbox, so a request on it is a human's decision.
//! Agents talk to a separate per-run socket (see `mcp.rs`) that offers no approval operations.

mod approval;
mod diff;
mod environment;
mod fsutil;
mod run;
mod service;
mod spawn;
mod state;
#[cfg(test)]
mod testing;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Context;
use connectrpc::ConnectError;
use nix::unistd::{Uid, User};
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

use crate::config::{self, Config, is_root};
use crate::nixcmd::{Eval, Nix, Owner};
use crate::policy::Policy;
use crate::proto::Target;
use crate::rpc;

use fsutil::{set_mode, write_atomic};
use state::{Key, State};

pub use approval::Decision;
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

    /// The platform's sandbox launcher: `bwrap` or `sandbox-exec`.
    launcher: PathBuf,

    /// uid and gid of `agent_user`, when running as root.
    agent_ids: Option<(u32, u32)>,

    state: Mutex<State>,
}

fn precondition(e: impl ToString) -> ConnectError {
    ConnectError::failed_precondition(e.to_string())
}

fn internal(e: impl ToString) -> ConnectError {
    ConnectError::internal(e.to_string())
}

fn not_found(e: impl ToString) -> ConnectError {
    ConnectError::not_found(e.to_string())
}

fn is_valid_sandbox_name(name: &str) -> bool {
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    !name.is_empty() && name.chars().all(allowed)
}

impl Daemon {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Persists approval state so it survives a daemon restart.
    fn save(&self, state: &State) {
        let json = serde_json::to_string(&state.to_saved()).unwrap_or_default();

        if let Err(e) = write_atomic(&self.state_dir.join("state.json"), &json) {
            eprintln!("agentbox: cannot persist state: {e}");
        }
    }

    /// Nix, run on behalf of `owner`.
    fn nix<'a>(&'a self, owner: &'a Owner) -> Nix<'a> {
        Nix {
            cfg: &self.cfg,
            owner,
            system: &self.system,
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
    fn target(uid: u32, target: &Target) -> Result<(Key, Owner), ConnectError> {
        let workdir = std::fs::canonicalize(&target.workdir)
            .map_err(|e| not_found(format!("{}: {e}", target.workdir)))?;

        let meta = std::fs::metadata(&workdir).map_err(internal)?;
        let owned = uid == 0 || std::os::unix::fs::MetadataExt::uid(&meta) == uid;
        if !meta.is_dir() || !owned {
            let message = format!("{} is not a directory you own", workdir.display());
            return Err(ConnectError::permission_denied(message));
        }

        let sandbox = match target.sandbox.as_str() {
            "" => "default",
            name => name,
        };
        if !is_valid_sandbox_name(sandbox) {
            return Err(ConnectError::invalid_argument("invalid sandbox name"));
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
            sandbox: sandbox.to_owned(),
        };
        Ok((key, owner))
    }
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

/// Finds the sandbox launcher once, with the daemon's own PATH.
///
/// Sandboxes are started with their own environment, so a bare `bwrap` would be looked
/// up in the sandbox's PATH instead.
fn launcher() -> anyhow::Result<PathBuf> {
    if cfg!(target_os = "macos") {
        return Ok("/usr/bin/sandbox-exec".into());
    }

    which::which("bwrap").context("bubblewrap (bwrap) is not on PATH")
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
        launcher: launcher()?,
    });

    let (listener, socket) = bind_socket()?;
    eprintln!("agentbox: listening on {}", socket.display());

    let serve = rpc::serve(listener, service::router(daemon));

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        () = serve => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }

    // Sandboxes die with us (bwrap --die-with-parent).
    let _ = std::fs::remove_file(&socket);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::testing::Fixture;
    use super::*;

    #[test]
    fn sandbox_names_are_plain_identifiers() {
        for good in ["default", "ci", "my-sandbox", "a_b", "v2"] {
            assert!(is_valid_sandbox_name(good), "{good}");
        }

        // The name is interpolated into a flake attribute path.
        for bad in ["", "a.b", "a\"b", "a b", "a#b", "../x", "a;b"] {
            assert!(!is_valid_sandbox_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_target_resolves_to_the_canonical_workdir() {
        let fixture = Fixture::new();
        let mut target = fixture.target();
        target.workdir.push_str("/./");

        let (key, owner) = Daemon::target(fixture.uid(), &target).unwrap();

        assert_eq!(key, fixture.key);
        assert_eq!(owner.uid, fixture.uid());
    }

    #[test]
    fn an_empty_sandbox_name_means_default() {
        let fixture = Fixture::new();
        let mut target = fixture.target();
        target.sandbox.clear();

        let (key, _) = Daemon::target(fixture.uid(), &target).unwrap();

        assert_eq!(key.sandbox, "default");
    }

    #[test]
    fn targets_are_checked() {
        let fixture = Fixture::new();
        let code = |target: &Target, uid| Daemon::target(uid, target).unwrap_err().code;

        let mut missing = fixture.target();
        missing.workdir.push_str("/does-not-exist");
        assert_eq!(
            code(&missing, fixture.uid()),
            connectrpc::ErrorCode::NotFound
        );

        let mut bad_name = fixture.target();
        bad_name.sandbox = "a.b".into();
        assert_eq!(
            code(&bad_name, fixture.uid()),
            connectrpc::ErrorCode::InvalidArgument
        );

        // Someone else's directory: the peer's uid comes from the socket, not the request.
        let stranger = fixture.uid() + 1;
        assert_eq!(
            code(&fixture.target(), stranger),
            connectrpc::ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn a_file_is_not_a_workdir() {
        let fixture = Fixture::new();
        let file = fixture.key.workdir.join("file");
        std::fs::write(&file, "").unwrap();
        let mut target = fixture.target();
        target.workdir = file.to_string_lossy().into_owned();

        let error = Daemon::target(fixture.uid(), &target).unwrap_err();

        assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn approvals_are_persisted_and_reloaded() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", testing::policy(&[]));
        fixture.approve_current().await;

        let restored = load_state(&fixture.daemon.state_dir);

        assert_eq!(restored.approved(&fixture.key).unwrap().drv, "env1.drv");
    }

    #[test]
    fn a_missing_or_corrupt_state_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_state(dir.path()).dirs.is_empty());

        std::fs::write(dir.path().join("state.json"), "{ not json").unwrap();
        assert!(load_state(dir.path()).dirs.is_empty());
    }
}
