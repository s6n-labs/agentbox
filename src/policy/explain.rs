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
}
