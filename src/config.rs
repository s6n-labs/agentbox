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
        Self {
            allow: vec!["*".into()],
        }
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

/// Socket of a root daemon, which serves every user of the machine.
const SYSTEM_SOCKET: &str = "/run/agentbox/daemon.sock";

/// An explicit location from the environment, mainly for tests.
fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Per-user state directory: `$XDG_STATE_HOME` where that exists (Linux), otherwise
/// the platform's local data directory (macOS).
fn user_state_dir() -> PathBuf {
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| "/var/tmp".into())
        .join("agentbox")
}

pub fn config_path() -> PathBuf {
    if let Some(path) = env_path("AGENTBOX_CONFIG") {
        return path;
    }

    if is_root() {
        return "/etc/agentbox/config.toml".into();
    }

    dirs::config_dir()
        .unwrap_or_else(|| "/etc".into())
        .join("agentbox/config.toml")
}

pub fn socket_path() -> PathBuf {
    if let Some(path) = env_path("AGENTBOX_SOCKET") {
        return path;
    }

    // Prefer a root daemon when there is one.
    let system = PathBuf::from(SYSTEM_SOCKET);
    if is_root() || system.exists() {
        return system;
    }

    // macOS has no runtime directory; the state directory is just as private.
    dirs::runtime_dir()
        .map(|dir| dir.join("agentbox"))
        .unwrap_or_else(user_state_dir)
        .join("daemon.sock")
}

pub fn state_dir() -> PathBuf {
    if let Some(path) = env_path("AGENTBOX_STATE_DIR") {
        return path;
    }

    if is_root() {
        return "/var/lib/agentbox".into();
    }

    user_state_dir()
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
