//! Isolation backends, environment indirection and agent adapters.
//!
//! Everything here is a pure function of its inputs, so both backends can be tested
//! on any platform. Starting processes is the daemon's job.

mod adapter;
mod bwrap;
mod env;
mod seatbelt;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::policy::Policy;

pub use adapter::{adapt_argv, is_agent};
pub use bwrap::bwrap_args;
pub use env::{DevEnv, env_sh, env_vars, resolve_in_path};
pub use seatbelt::seatbelt_profile;

/// Port of the in-sandbox TCP→Unix bridge to the proxy (Linux, private network namespace).
pub const BRIDGE_PORT: u16 = 3128;

/// Everything a backend needs to know about one run.
pub struct Ctx<'a> {
    pub workdir: &'a Path,

    /// Per-run directory on the host (env.sh, sockets, shell rc files), and where the
    /// sandbox sees it.
    pub rundir: &'a Path,
    pub rundir_inside: &'a Path,

    /// The agentbox binary on the host, and where the sandbox sees it.
    pub exe: &'a Path,
    pub exe_inside: &'a Path,

    /// Effective policy (repository layer ∩ host layer).
    pub policy: &'a Policy,
    pub cfg: &'a Config,

    pub proxy_port: u16,

    /// Writable directories already opened without following symlinks: path → fd that
    /// bwrap inherits. The agent controls these paths, so they are bound by fd.
    pub pinned: &'a BTreeMap<PathBuf, i32>,
}

impl Ctx<'_> {
    /// Sandbox-private directory inside the workdir; HOME and TMPDIR are recreated here.
    pub fn private_dir(&self) -> PathBuf {
        self.workdir.join(".agentbox")
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use serde_json::json;

    use super::*;

    pub fn policy(workdir_writable: bool) -> Policy {
        let json = json!({
            "version": 1,
            "network": { "allow": [] },
            "fs": { "writable": ["target"], "workdirWritable": workdir_writable },
            "capabilities": ["xcode"],
            "env": {
                "CARGO_HOME": "$WORKDIR/.cache/cargo",
                "HOME": "/evil",
                "PATH": "/evil",
            },
        });

        Policy::parse(&json).unwrap()
    }

    /// Runs `f` with a context for workdir `/w/it's` (quoting matters).
    pub fn with_ctx<T>(policy: &Policy, cfg: &Config, f: impl FnOnce(&Ctx) -> T) -> T {
        let pinned = BTreeMap::from([(PathBuf::from("/w/it's/.agentbox"), 7)]);

        f(&Ctx {
            workdir: Path::new("/w/it's"),
            rundir: Path::new("/state/runs/r1"),
            rundir_inside: Path::new("/run/agentbox"),
            exe: Path::new("/host/agentbox"),
            exe_inside: Path::new("/run/agentbox-bin/agentbox"),
            policy,
            cfg,
            proxy_port: 3128,
            pinned: &pinned,
        })
    }
}
