//! Host layer: per-user configuration the agent can never touch, plus well-known paths.

use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub nix_bin: String,
    /// Dedicated OS user the sandbox runs as (root daemon only).
    /// The operator must grant this user access to the workdirs (e.g. ACLs).
    pub agent_user: Option<String>,
    /// How long `reload_env` waits for a human before returning `still_pending`.
    pub approval_timeout_secs: u64,
    pub network: AllowList,
    pub capabilities: AllowList,
    pub fs: HostFs,
    pub seatbelt: Seatbelt,
}

/// Upper bound for what a repository may request. `*` permits everything.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct AllowList {
    pub allow: Vec<String>,
}

/// Absolute host paths shown to every sandbox. Only the host layer can do this.
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct HostFs {
    pub readonly: Vec<PathBuf>,
    pub writable: Vec<PathBuf>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Seatbelt {
    /// Raw SBPL appended to the generated profile.
    pub extra: String,
}

impl Default for AllowList {
    fn default() -> Self {
        Self { allow: vec!["*".into()] }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nix_bin: "nix".into(),
            agent_user: None,
            approval_timeout_secs: 600,
            network: AllowList::default(),
            capabilities: AllowList::default(),
            fs: HostFs::default(),
            seatbelt: Seatbelt::default(),
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path();
        match std::fs::read_to_string(&path) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
}

pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn home() -> PathBuf {
    env_path("HOME").unwrap_or_else(|| "/".into())
}

pub fn config_path() -> PathBuf {
    env_path("AGENTBOX_CONFIG").unwrap_or_else(|| {
        if is_root() {
            "/etc/agentbox/config.toml".into()
        } else {
            env_path("XDG_CONFIG_HOME").unwrap_or_else(|| home().join(".config")).join("agentbox/config.toml")
        }
    })
}

pub fn socket_path() -> PathBuf {
    env_path("AGENTBOX_SOCKET").unwrap_or_else(|| {
        if is_root() {
            return "/run/agentbox/daemon.sock".into();
        }
        // A root daemon serves every user; prefer it when present.
        let system = PathBuf::from("/run/agentbox/daemon.sock");
        if system.exists() {
            return system;
        }
        env_path("XDG_RUNTIME_DIR")
            .unwrap_or_else(|| format!("/tmp/agentbox-{}", nix::unistd::geteuid()).into())
            .join("agentbox/daemon.sock")
    })
}

pub fn state_dir() -> PathBuf {
    env_path("AGENTBOX_STATE_DIR").unwrap_or_else(|| {
        if is_root() {
            "/var/lib/agentbox".into()
        } else {
            env_path("XDG_STATE_HOME").unwrap_or_else(|| home().join(".local/state")).join("agentbox")
        }
    })
}

/// One GC root directory per run. A root daemon registers direct roots; otherwise
/// `nix --profile` registers indirect roots pointing here.
pub fn gcroots_dir() -> PathBuf {
    if is_root() && std::path::Path::new("/nix/var/nix/gcroots").is_dir() {
        "/nix/var/nix/gcroots/agentbox".into()
    } else {
        state_dir().join("gcroots")
    }
}
