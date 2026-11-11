//! Platform-independent sandbox policy: repo layer, host-layer intersection, explain.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Config;

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
    pub allow: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Fs {
    pub writable: Vec<String>,
    pub workdir_writable: bool,
}

/// Capabilities the host knows how to expand, and where they apply.
const CAPABILITIES: &[(&str, &str)] = &[("xcode", "macos")];

impl Policy {
    /// Parses and validates the evaluated repo policy. The flake is untrusted and can
    /// bypass the Nix module, so everything is checked again here.
    pub fn parse(v: &Value) -> Result<Self, String> {
        let p: Policy =
            serde_json::from_value(v.clone()).map_err(|e| format!("invalid policy: {e}"))?;
        if p.version != 1 {
            return Err(format!("unsupported policy version {}", p.version));
        }
        for w in &p.fs.writable {
            let ok = !w.is_empty()
                && Path::new(w)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
            if !ok {
                return Err(format!(
                    "fs.writable: {w:?} must be a path relative to the workdir without `..`"
                ));
            }
        }
        for c in &p.capabilities {
            if !CAPABILITIES.iter().any(|(name, _)| name == c) {
                return Err(format!("unknown capability {c:?}"));
            }
        }
        for k in p.env.keys() {
            let ok = !k.is_empty()
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !k.starts_with(|c: char| c.is_ascii_digit());
            if !ok {
                return Err(format!("env: invalid variable name {k:?}"));
            }
        }
        Ok(p)
    }

    /// Effective policy = repo layer ∩ host layer, for the given OS.
    pub fn effective(&self, host: &Config, os: &str) -> Policy {
        let mut p = self.clone();
        p.network
            .allow
            .retain(|e| host.network.allow.iter().any(|h| covers(h, e)));
        p.capabilities.retain(|c| {
            host.capabilities.allow.iter().any(|h| h == "*" || h == c)
                && CAPABILITIES.iter().any(|(name, on)| name == c && *on == os)
        });
        p
    }

    pub fn net_allowed(&self, host: &str, port: u16) -> bool {
        self.network
            .allow
            .iter()
            .any(|e| entry_matches(e, host, port))
    }
}

/// Changes enforced by the kernel-side profile cannot be applied to a live sandbox.
pub fn needs_restart(old: &Policy, new: &Policy) -> bool {
    old.fs != new.fs || old.capabilities != new.capabilities
}

/// Splits `host[:port]`.
fn split_entry(e: &str) -> (&str, Option<u16>) {
    match e.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p.parse().ok()),
        _ => (e, None),
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match pattern.strip_prefix('*') {
        Some("") => true,
        Some(suffix) if suffix.starts_with('.') => host.ends_with(suffix),
        _ => pattern == host,
    }
}

/// An entry without a port allows every port.
fn entry_matches(entry: &str, host: &str, port: u16) -> bool {
    let (pat, p) = split_entry(entry);
    host_matches(pat, host) && p.is_none_or(|p| p == port)
}

/// Does the host-layer pattern permit the whole repo entry?
fn covers(host_pat: &str, entry: &str) -> bool {
    let (hp, hport) = split_entry(host_pat);
    let (ep, eport) = split_entry(entry);
    // `*.a.b` is covered by `*.b`: compare the entry's suffix like a hostname.
    host_matches(hp, ep.trim_start_matches('*')) && hport.is_none_or(|p| Some(p) == eport)
}

/// Says which layer and rule allows or denies a path or `host[:port]`.
pub fn explain(repo: &Policy, host: &Config, os: &str, workdir: &Path, what: &str) -> String {
    let eff = repo.effective(host, os);
    if what.starts_with('/') || what.starts_with('.') {
        let path = if Path::new(what).is_absolute() {
            Path::new(what).to_path_buf()
        } else {
            workdir.join(what)
        };
        return explain_path(&eff, host, workdir, &path);
    }
    let (h, port) = split_entry(what);
    let port = port.unwrap_or(443);
    for (i, e) in repo.network.allow.iter().enumerate() {
        if entry_matches(e, h, port) {
            return match host.network.allow.iter().find(|hp| covers(hp, e)) {
                Some(hp) => format!(
                    "{h}:{port}: allowed by repo network.allow[{i}] = {e:?} (within host network.allow {hp:?})"
                ),
                None => format!(
                    "{h}:{port}: denied by host layer: repo network.allow[{i}] = {e:?} is not covered by host network.allow"
                ),
            };
        }
    }
    format!("{h}:{port}: denied: no entry in repo network.allow matches")
}

fn explain_path(eff: &Policy, host: &Config, workdir: &Path, path: &Path) -> String {
    let p = path.display();
    if path.starts_with(workdir.join(".agentbox")) {
        return format!("{p}: read-write: sandbox-managed HOME/TMPDIR");
    }
    if let Ok(rel) = path.strip_prefix(workdir) {
        for (i, w) in eff.fs.writable.iter().enumerate() {
            if rel.starts_with(Path::new(w).strip_prefix(".").unwrap_or(Path::new(w))) {
                return format!("{p}: read-write by repo fs.writable[{i}] = {w:?}");
            }
        }
        return if eff.fs.workdir_writable {
            format!("{p}: read-write: workdir (repo fs.workdirWritable = true)")
        } else {
            format!(
                "{p}: read-only: workdir (repo fs.workdirWritable = false, no fs.writable entry matches)"
            )
        };
    }
    if path.starts_with("/nix/store") {
        return format!(
            "{p}: read-only: shared nix store (directory listing of /nix/store itself is denied on macOS)"
        );
    }
    if path.starts_with("/nix/var/nix") {
        return format!("{p}: denied: nix database, gcroots and daemon socket are never visible");
    }
    for (i, w) in host.fs.writable.iter().enumerate() {
        if path.starts_with(w) {
            return format!(
                "{p}: read-write by host fs.writable[{i}] = {:?}",
                w.display()
            );
        }
    }
    for (i, r) in host.fs.readonly.iter().enumerate() {
        if path.starts_with(r) {
            return format!(
                "{p}: read-only by host fs.readonly[{i}] = {:?}",
                r.display()
            );
        }
    }
    format!("{p}: denied: not visible by default (only the host layer can expose absolute paths)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(allow: &[&str]) -> Policy {
        Policy::parse(&json!({
            "version": 1,
            "network": { "allow": allow },
            "fs": { "writable": ["target"], "workdirWritable": false },
            "capabilities": ["xcode"],
            "env": {},
        }))
        .unwrap()
    }

    #[test]
    fn matching() {
        let p = policy(&["crates.io", "github.com:443", "*.example.com"]);
        assert!(p.net_allowed("crates.io", 80));
        assert!(p.net_allowed("github.com", 443));
        assert!(!p.net_allowed("github.com", 22));
        assert!(p.net_allowed("a.example.com", 443));
        assert!(!p.net_allowed("example.com", 443));
        assert!(!p.net_allowed("evilcrates.io", 443));
    }

    #[test]
    fn intersection() {
        let mut host = Config::default();
        let p = policy(&["crates.io", "github.com:443", "a.corp.example"]);
        assert_eq!(p.effective(&host, "macos"), p);
        assert!(p.effective(&host, "linux").capabilities.is_empty());
        host.network.allow = vec![
            "*.io".into(),
            "github.com:443".into(),
            "github.com:22".into(),
        ];
        host.capabilities.allow = vec![];
        let eff = p.effective(&host, "macos");
        assert_eq!(eff.network.allow, ["crates.io", "github.com:443"]);
        assert!(eff.capabilities.is_empty());
        // A port-restricted host pattern does not cover an any-port repo entry.
        host.network.allow = vec!["crates.io:443".into()];
        assert!(p.effective(&host, "linux").network.allow.is_empty());
    }

    #[test]
    fn rejects_escapes() {
        for bad in ["/etc", "../x", "a/../../b", ""] {
            let v = json!({"version": 1, "network": {"allow": []}, "fs": {"writable": [bad], "workdirWritable": true}, "capabilities": [], "env": {}});
            assert!(Policy::parse(&v).is_err(), "{bad}");
        }
        let v = json!({"version": 1, "network": {"allow": []}, "fs": {"writable": [], "workdirWritable": true}, "capabilities": [], "env": {}, "sbpl": "(allow default)"});
        assert!(Policy::parse(&v).is_err());
    }

    #[test]
    fn explains() {
        let p = policy(&["crates.io"]);
        let host = Config::default();
        let w = Path::new("/w");
        assert!(
            explain(&p, &host, "linux", w, "crates.io")
                .contains("allowed by repo network.allow[0]")
        );
        assert!(explain(&p, &host, "linux", w, "evil.com").contains("denied"));
        assert!(explain(&p, &host, "linux", w, "./target/debug").contains("fs.writable[0]"));
        assert!(explain(&p, &host, "linux", w, "./src").contains("read-only"));
        assert!(explain(&p, &host, "linux", w, "/home/me").contains("denied"));
    }
}
