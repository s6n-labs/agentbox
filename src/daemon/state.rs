//! What the daemon remembers: approval state per workdir and the live runs.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::nixcmd::{Eval, Owner};
use crate::proto::Denial;
use crate::sandbox::DevEnv;

/// Approval state is tracked per workdir and sandbox name.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    pub workdir: PathBuf,
    pub sandbox: String,
}

/// Result of an agent's `reload_env` request.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// One of the result names in the MCP tool description, e.g. `applied`.
    pub kind: String,
    pub message: String,
}

impl Outcome {
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_owned(),
            message: message.into(),
        }
    }
}

/// An agent's request waiting for a human.
pub struct Pending {
    pub eval: Eval,
    pub reason: String,
    pub outcome: watch::Sender<Option<Outcome>>,
}

#[derive(Default)]
pub struct Dir {
    /// Last evaluation a human approved (explicitly, or by requesting it themselves).
    /// This is what is applied to the runs of the workdir.
    pub approved: Option<Eval>,

    /// Something ran in this workdir since the approval, so its nix files may hold
    /// edits nobody approved.
    pub agent_ran: bool,

    /// At most one request per workdir; a newer one replaces it.
    pub pending: Option<Pending>,

    pub denials: VecDeque<Denial>,
}

pub struct Run {
    pub key: Key,
    pub owner: Owner,
    pub argv: Vec<String>,

    /// TERM and friends, forwarded from the CLI.
    pub term_env: BTreeMap<String, String>,

    /// Per-run directory on the host, and the path the sandbox sees it at.
    pub dir: PathBuf,
    pub dir_inside: PathBuf,

    /// Nix profile path that keeps this run's environment alive (GC root).
    pub profile: PathBuf,

    pub proxy_port: u16,

    /// stdin, stdout and stderr of the CLI's terminal.
    pub stdio: Option<Vec<OwnedFd>>,

    /// Process group of the running sandbox; `None` while it is not running.
    pub pgid: Option<i32>,

    /// What argv[0] resolved to. A change means the agent itself was updated.
    pub exe_path: Option<PathBuf>,

    pub dev: DevEnv,

    /// The agent is in the middle of a turn (reported by its hooks).
    pub busy: bool,

    /// Set right before the sandbox is killed: respawn it with this resume message.
    pub restart: Option<String>,

    /// Restart requested while the agent was busy; done when its turn ends.
    pub restart_when_idle: Option<String>,

    pub exit: watch::Sender<Option<i32>>,

    pub tasks: Vec<JoinHandle<()>>,
}

impl Run {
    pub fn is_running(&self) -> bool {
        self.pgid.is_some()
    }
}

#[derive(Default)]
pub struct State {
    pub dirs: HashMap<Key, Dir>,
    pub runs: HashMap<String, Run>,

    /// Exit codes not collected by WaitRun yet.
    pub exited: HashMap<String, i32>,

    pub next_run: u64,
}

/// The part of [`Dir`] that survives a daemon restart.
#[derive(Serialize, Deserialize)]
pub struct SavedDir {
    pub workdir: PathBuf,
    pub sandbox: String,
    pub approved: Option<Eval>,
    pub agent_ran: bool,
}

impl State {
    pub fn to_saved(&self) -> Vec<SavedDir> {
        self.dirs
            .iter()
            .map(|(key, dir)| SavedDir {
                workdir: key.workdir.clone(),
                sandbox: key.sandbox.clone(),
                approved: dir.approved.clone(),
                agent_ran: dir.agent_ran,
            })
            .collect()
    }

    pub fn from_saved(saved: Vec<SavedDir>) -> Self {
        let mut state = State::default();

        for entry in saved {
            let key = Key {
                workdir: entry.workdir,
                sandbox: entry.sandbox,
            };
            let dir = Dir {
                approved: entry.approved,
                agent_ran: entry.agent_ran,
                ..Default::default()
            };
            state.dirs.insert(key, dir);
        }

        state
    }

    pub fn approved(&self, key: &Key) -> Option<&Eval> {
        self.dirs.get(key)?.approved.as_ref()
    }
}
