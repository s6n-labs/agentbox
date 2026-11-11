//! `agentbox explain`: which layer and which rule allows or denies an access.

use std::path::{Path, PathBuf};

use crate::config::Config;

use super::Policy;
use super::network::{self, Pattern};

/// HTTPS, unless the question names a port.
const DEFAULT_PORT: u16 = 443;

/// Explains access to a path (anything starting with `/` or `.`) or to `host[:port]`.
pub fn explain(repo: &Policy, host: &Config, os: &str, workdir: &Path, what: &str) -> String {
    if what.starts_with('/') || what.starts_with('.') {
        let effective = repo.effective(host, os);

        return explain_path(&effective, host, workdir, &workdir.join(what));
    }

    explain_destination(repo, host, what)
}

fn explain_destination(repo: &Policy, host: &Config, what: &str) -> String {
    let (name, port) = match what.rsplit_once(':') {
        Some((name, port)) if port.parse::<u16>().is_ok() => (name, port.parse().unwrap()),
        _ => (what, DEFAULT_PORT),
    };
    let subject = format!("{name}:{port}");

    let matching = repo
        .network
        .allow
        .iter()
        .enumerate()
        .find(|(_, entry)| Pattern::parse(entry).matches(name, port));
    let Some((index, entry)) = matching else {
        return format!("{subject}: denied: no entry in repo network.allow matches");
    };

    let rule = format!("repo network.allow[{index}] = {entry:?}");
    match network::permitted_by(&host.network.allow, entry) {
        Some(pattern) => {
            format!("{subject}: allowed by {rule} (within host network.allow {pattern:?})")
        }
        None => {
            format!("{subject}: denied by host layer: {rule} is not covered by host network.allow")
        }
    }
}

/// The first host-layer path containing `path`, with its index.
fn containing<'a>(paths: &'a [PathBuf], path: &Path) -> Option<(usize, &'a PathBuf)> {
    paths
        .iter()
        .enumerate()
        .find(|(_, shown)| path.starts_with(shown))
}

fn explain_path(effective: &Policy, host: &Config, workdir: &Path, path: &Path) -> String {
    let subject = path.display();

    if path.starts_with(workdir.join(".agentbox")) {
        return format!("{subject}: read-write: sandbox-managed HOME/TMPDIR");
    }

    if let Ok(relative) = path.strip_prefix(workdir) {
        return explain_workdir_path(effective, &subject.to_string(), relative);
    }

    if path.starts_with("/nix/store") {
        return format!(
            "{subject}: read-only: shared nix store (listing /nix/store itself is denied on macOS)"
        );
    }
    if path.starts_with("/nix/var/nix") {
        return format!(
            "{subject}: denied: the nix database, gcroots and daemon socket are never visible"
        );
    }

    if let Some((index, shown)) = containing(&host.fs.writable, path) {
        return format!("{subject}: read-write by host fs.writable[{index}] = {shown:?}");
    }
    if let Some((index, shown)) = containing(&host.fs.readonly, path) {
        return format!("{subject}: read-only by host fs.readonly[{index}] = {shown:?}");
    }

    format!(
        "{subject}: denied: not visible by default (only the host layer can show absolute paths)"
    )
}

fn explain_workdir_path(effective: &Policy, subject: &str, relative: &Path) -> String {
    let writable = effective.fs.writable.iter().enumerate().find(|(_, entry)| {
        // `./target` and `target` mean the same.
        let entry = Path::new(entry);
        relative.starts_with(entry.strip_prefix(".").unwrap_or(entry))
    });

    if let Some((index, entry)) = writable {
        return format!("{subject}: read-write by repo fs.writable[{index}] = {entry:?}");
    }

    if effective.fs.workdir_writable {
        return format!("{subject}: read-write: workdir (repo fs.workdirWritable = true)");
    }

    format!(
        "{subject}: read-only: workdir (repo fs.workdirWritable = false and no fs.writable \
         entry matches)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::testing::policy;

    #[test]
    fn names_the_rule() {
        let policy = policy(&["crates.io"]);
        let host = Config::default();
        let explain = |what| explain(&policy, &host, "linux", Path::new("/w"), what);

        assert!(explain("crates.io").contains("allowed by repo network.allow[0]"));
        assert!(explain("evil.com").contains("denied"));

        assert!(explain("./target/debug").contains("fs.writable[0]"));
        assert!(explain("./src").contains("read-only"));
        assert!(explain("/home/me").contains("denied"));
    }

    #[test]
    fn says_when_the_host_layer_is_the_reason() {
        let policy = policy(&["crates.io"]);
        let mut host = Config::default();
        host.network.allow = vec!["*.com".into()];

        let answer = explain(&policy, &host, "linux", Path::new("/w"), "crates.io");

        assert!(answer.contains("denied by host layer"), "{answer}");
        assert!(answer.contains("network.allow[0]"), "{answer}");
    }

    #[test]
    fn ports_default_to_https() {
        let policy = policy(&["github.com:22"]);
        let host = Config::default();
        let explain = |what| explain(&policy, &host, "linux", Path::new("/w"), what);

        assert!(explain("github.com").starts_with("github.com:443: denied"));
        assert!(explain("github.com:22").starts_with("github.com:22: allowed"));
    }

    #[test]
    fn explains_paths_outside_the_workdir() {
        let policy = policy(&[]);
        let mut host = Config::default();
        host.fs.readonly = vec!["/usr".into()];
        host.fs.writable = vec!["/var/cache/shared".into()];
        let explain = |what| explain(&policy, &host, "linux", Path::new("/w"), what);

        assert!(explain("/usr/bin/env").contains("read-only by host fs.readonly[0]"));
        assert!(explain("/var/cache/shared/x").contains("read-write by host fs.writable[0]"));
        assert!(explain("/nix/store/abc-hello").contains("read-only: shared nix store"));
        assert!(explain("/nix/var/nix/db").contains("denied"));
        assert!(explain("/etc/passwd").contains("denied: not visible"));
    }

    #[test]
    fn explains_paths_inside_the_workdir() {
        let host = Config::default();

        let read_only = policy(&[]);
        let explain_ro = |what| explain(&read_only, &host, "linux", Path::new("/w"), what);
        assert!(explain_ro("/w/.agentbox/home/.cache").contains("sandbox-managed"));
        assert!(explain_ro("/w/target").contains("fs.writable[0]"));
        assert!(explain_ro("/w/targets").contains("read-only"));

        let mut writable = policy(&[]);
        writable.fs.workdir_writable = true;
        let answer = explain(&writable, &host, "linux", Path::new("/w"), "./src/main.rs");
        assert!(answer.contains("read-write: workdir"), "{answer}");
    }
}
