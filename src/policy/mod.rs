//! Platform-independent sandbox policy.
//!
//! Two layers: the repository says what it wants, the host layer (see `config.rs`) sets
//! the upper bound. What is enforced is their intersection, the *effective* policy.

mod explain;
mod network;

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Config;

pub use explain::explain;
use network::Pattern;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub network: Network,
    pub fs: Fs,
    pub capabilities: Vec<String>,
    pub env: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Outbound destinations: `host`, `*.host`, optionally with `:port`.
    pub allow: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Fs {
    /// Workdir-relative paths that are created and stay writable.
    pub writable: Vec<String>,

    /// If false, only `writable` is writable inside the workdir.
    pub workdir_writable: bool,
}

/// A named platform-specific permission. Repositories only name it; the expansion into
/// paths and services lives in the backend.
struct Capability {
    name: &'static str,
    /// The OS it applies to, as in `std::env::consts::OS`.
    os: &'static str,
}

const CAPABILITIES: &[Capability] = &[Capability {
    name: "xcode",
    os: "macos",
}];

fn capability(name: &str) -> Option<&'static Capability> {
    CAPABILITIES.iter().find(|known| known.name == name)
}

/// Is `path` relative, without `..` components?
fn stays_in_workdir(path: &str) -> bool {
    let harmless = |component| matches!(component, Component::Normal(_) | Component::CurDir);

    !path.is_empty() && Path::new(path).components().all(harmless)
}

fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    let starts_well = chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_');

    starts_well && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Policy {
    /// Parses and validates an evaluated repository policy.
    ///
    /// The flake is untrusted and can bypass the Nix module that normally checks this,
    /// so everything is validated again here.
    pub fn parse(json: &Value) -> Result<Self, String> {
        let policy: Policy =
            serde_json::from_value(json.clone()).map_err(|e| format!("invalid policy: {e}"))?;

        if policy.version != 1 {
            return Err(format!("unsupported policy version {}", policy.version));
        }

        for path in &policy.fs.writable {
            if !stays_in_workdir(path) {
                return Err(format!(
                    "fs.writable: {path:?} must be a path relative to the workdir without `..`"
                ));
            }
        }

        for name in &policy.capabilities {
            if capability(name).is_none() {
                return Err(format!("unknown capability {name:?}"));
            }
        }

        for name in policy.env.keys() {
            if !is_variable_name(name) {
                return Err(format!("env: invalid variable name {name:?}"));
            }
        }

        Ok(policy)
    }

    /// The effective policy on `os`: this repository policy capped by the host layer.
    pub fn effective(&self, host: &Config, os: &str) -> Policy {
        let mut effective = self.clone();

        effective
            .network
            .allow
            .retain(|entry| network::permitted_by(&host.network.allow, entry).is_some());

        effective.capabilities.retain(|name| {
            let permitted = host
                .capabilities
                .allow
                .iter()
                .any(|allowed| allowed == "*" || allowed == name);
            let applies = capability(name).is_some_and(|known| known.os == os);

            permitted && applies
        });

        effective
    }

    pub fn net_allowed(&self, host: &str, port: u16) -> bool {
        self.network
            .allow
            .iter()
            .any(|entry| Pattern::parse(entry).matches(host, port))
    }
}

/// Does going from `old` to `new` require recreating the sandbox?
///
/// Filesystem rules and capabilities are enforced by the kernel-side profile, which
/// cannot be loosened once applied. Network rules and the environment can change live.
pub fn needs_restart(old: &Policy, new: &Policy) -> bool {
    old.fs != new.fs || old.capabilities != new.capabilities
}

#[cfg(test)]
pub(crate) mod testing {
    use serde_json::json;

    use super::Policy;

    /// A policy that allows the given destinations and only `target/` for writing.
    pub fn policy(allow: &[&str]) -> Policy {
        let json = json!({
            "version": 1,
            "network": { "allow": allow },
            "fs": { "writable": ["target"], "workdirWritable": false },
            "capabilities": ["xcode"],
            "env": {},
        });

        Policy::parse(&json).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::testing::policy;
    use super::*;

    #[test]
    fn destinations_are_matched() {
        let policy = policy(&["crates.io", "github.com:443", "*.example.com"]);

        assert!(policy.net_allowed("crates.io", 80));
        assert!(policy.net_allowed("github.com", 443));
        assert!(policy.net_allowed("a.example.com", 443));

        assert!(!policy.net_allowed("github.com", 22));
        assert!(!policy.net_allowed("example.com", 443));
        assert!(!policy.net_allowed("evilcrates.io", 443));
    }

    #[test]
    fn host_layer_caps_the_repository() {
        let policy = policy(&["crates.io", "github.com:443", "a.corp.example"]);
        let mut host = Config::default();

        // The default host layer permits everything; capabilities still follow the OS.
        assert_eq!(policy.effective(&host, "macos"), policy);
        assert!(policy.effective(&host, "linux").capabilities.is_empty());

        host.network.allow = vec![
            "*.io".into(),
            "github.com:443".into(),
            "github.com:22".into(),
        ];
        host.capabilities.allow = vec![];
        let effective = policy.effective(&host, "macos");

        assert_eq!(effective.network.allow, ["crates.io", "github.com:443"]);
        assert!(effective.capabilities.is_empty());

        // A port-restricted host pattern does not cover an any-port repository entry.
        host.network.allow = vec!["crates.io:443".into()];
        assert!(policy.effective(&host, "linux").network.allow.is_empty());
    }

    fn with_writable(path: &str) -> Value {
        json!({
            "version": 1,
            "network": { "allow": [] },
            "fs": { "writable": [path], "workdirWritable": true },
            "capabilities": [],
            "env": {},
        })
    }

    #[test]
    fn paths_cannot_escape_the_workdir() {
        for bad in ["/etc", "../x", "a/../../b", ""] {
            assert!(Policy::parse(&with_writable(bad)).is_err(), "{bad}");
        }

        assert!(Policy::parse(&with_writable("target/debug")).is_ok());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let mut json = with_writable("target");
        json["sbpl"] = json!("(allow default)");

        assert!(Policy::parse(&json).is_err());
    }
}
