//! A daemon wired to a fake `nix`, for testing the approval flow without Nix or sandboxes.
//!
//! The fake (`tests/fixtures/nix-from-workdir`) treats the workdir itself as the pinned
//! source and reads the "evaluation" from `eval.json` in it. `eval-error` and
//! `build-error` files make it fail.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::watch;

use crate::config::Config;
use crate::nixcmd::Owner;
use crate::proto::Target;
use crate::sandbox::DevEnv;

use super::Daemon;
use super::state::{Key, Run, State};

/// Checked in rather than written by each test: executing a file another thread has
/// just written races with that thread's forks ("Text file busy").
const FAKE_NIX: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/nix-from-workdir"
);

/// A daemon, the workdir it serves, and the directories keeping both alive.
pub struct Fixture {
    pub daemon: Arc<Daemon>,
    pub key: Key,
    pub owner: Owner,
    _dirs: TempDir,
}

/// A valid policy document with the given network destinations.
pub fn policy(allow: &[&str]) -> Value {
    json!({
        "version": 1,
        "network": { "allow": allow },
        "fs": { "writable": [], "workdirWritable": true },
        "capabilities": [],
        "env": {},
    })
}

impl Fixture {
    pub fn new() -> Self {
        let dirs = tempfile::tempdir().unwrap();
        let root = dirs.path().canonicalize().unwrap();

        let workdir = root.join("work");
        let state_dir = root.join("state");
        std::fs::create_dir_all(&workdir).unwrap();
        std::fs::create_dir_all(state_dir.join("runs")).unwrap();

        let cfg = Config {
            nix_bin: FAKE_NIX.into(),
            approval_timeout_secs: 1,
            ..Config::default()
        };

        let daemon = Arc::new(Daemon {
            cfg,
            state_dir,
            system: "x86_64-linux".into(),
            exe: "/host/agentbox".into(),
            exe_inside: "/run/agentbox-bin/agentbox".into(),
            launcher: "/nonexistent/bwrap".into(),
            agent_ids: None,
            state: Mutex::new(State::default()),
        });

        let owner = Owner {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
            name: "tester".into(),
            home: root.clone(),
        };
        let key = Key {
            workdir,
            sandbox: "default".into(),
        };

        Self {
            daemon,
            key,
            owner,
            _dirs: dirs,
        }
    }

    fn workdir(&self) -> &Path {
        &self.key.workdir
    }

    /// What the next evaluation of the workdir yields.
    pub fn set_eval(&self, drv: &str, policy: Value) {
        let eval = json!({ "drv": drv, "policy": policy });
        std::fs::write(self.workdir().join("eval.json"), eval.to_string()).unwrap();
    }

    pub fn fail_eval(&self, message: &str) {
        std::fs::write(self.workdir().join("eval-error"), message).unwrap();
    }

    pub fn fail_build(&self, message: &str) {
        std::fs::write(self.workdir().join("build-error"), message).unwrap();
    }

    pub fn uid(&self) -> u32 {
        self.owner.uid
    }

    /// The `target` of an RPC about this workdir.
    pub fn target(&self) -> Target {
        Target {
            workdir: self.workdir().to_string_lossy().into_owned(),
            sandbox: "default".into(),
            ..Default::default()
        }
    }

    /// Registers a run that was never started (no sandbox, no terminal).
    pub fn add_run(&self, id: &str, argv: &[&str]) {
        let dir = self.daemon.state_dir.join("runs").join(id);
        std::fs::create_dir_all(&dir).unwrap();

        let run = Run {
            key: self.key.clone(),
            owner: self.owner.clone(),
            argv: argv.iter().map(ToString::to_string).collect(),
            term_env: BTreeMap::new(),
            dir_inside: "/run/agentbox".into(),
            profile: dir.join("profile"),
            dir,
            proxy_port: 3128,
            stdio: None,
            pgid: None,
            exe_path: None,
            dev: DevEnv::default(),
            busy: false,
            restart: None,
            restart_when_idle: None,
            exit: watch::channel(None).0,
            tasks: Vec::new(),
        };

        self.daemon.lock().runs.insert(id.to_owned(), run);
    }

    /// Evaluates the current files and applies them, like a human's `agentbox reload`.
    pub async fn approve_current(&self) {
        let eval = self.daemon.evaluate(&self.key, &self.owner).await.unwrap();
        self.daemon.apply(&self.key, &eval).await.unwrap();
    }

    /// Pretends the run's sandbox is up, without starting anything.
    ///
    /// The process group does not exist, so signalling it is harmless.
    pub fn mark_running(&self, id: &str) {
        let mut state = self.daemon.lock();
        let run = state.runs.get_mut(id).unwrap();

        run.pgid = Some(i32::MAX);
        run.exe_path = crate::sandbox::resolve_in_path("/bin", &run.argv[0], &run.key.workdir);
    }

    pub fn with_run<T>(&self, id: &str, read: impl FnOnce(&Run) -> T) -> T {
        read(&self.daemon.lock().runs[id])
    }

    pub fn approved_drv(&self) -> Option<String> {
        let state = self.daemon.lock();

        state.approved(&self.key).map(|eval| eval.drv.clone())
    }
}
