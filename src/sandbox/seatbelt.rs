//! macOS backend: a Seatbelt (SBPL) profile for `sandbox-exec`.
//!
//! In SBPL the last matching rule wins, so the static rules come first and the
//! per-run rules after them.
// ponytail: base.sb and xcode.sb are a starting point modelled on Nix's
// sandbox-defaults.sb. Which system paths and Mach services are really needed still
// has to be found out on a real Mac.

use std::path::Path;

use super::Ctx;

const BASE: &str = include_str!("base.sb");

/// Expansion of the `xcode` capability. Repositories only ever name it.
const XCODE: &str = include_str!("xcode.sb");

const READ_AND_EXEC: &str = "file-read* file-map-executable process-exec";

/// An SBPL string literal.
fn string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");

    format!("\"{escaped}\"")
}

fn subpath(path: &Path) -> String {
    format!("(subpath {})", string(&path.to_string_lossy()))
}

fn literal(path: &Path) -> String {
    format!("(literal {})", string(&path.to_string_lossy()))
}

pub fn seatbelt_profile(ctx: &Ctx) -> String {
    let mut rules = vec![BASE.to_owned()];
    let mut allow = |operations: &str, filter: String| {
        rules.push(format!("(allow {operations} {filter})"));
    };

    // Workdir, sandbox-managed HOME/TMPDIR, the run directory and our own binary.
    allow(READ_AND_EXEC, subpath(ctx.workdir));
    allow("file-write*", subpath(&ctx.private_dir()));
    allow("file-read*", subpath(ctx.rundir_inside));
    allow(READ_AND_EXEC, literal(ctx.exe_inside));

    if ctx.policy.fs.workdir_writable {
        allow("file-write*", subpath(ctx.workdir));
    }
    for rel in &ctx.policy.fs.writable {
        allow("file-write*", subpath(&ctx.workdir.join(rel)));
    }

    // Network: only the local proxy and the agent's sockets. Not even DNS
    // (mDNSResponder); names are resolved by the proxy.
    let proxy = format!("(remote tcp \"localhost:{}\")", ctx.proxy_port);
    allow("network-outbound", proxy);
    allow(
        "network-outbound",
        literal(&ctx.rundir_inside.join("agent.sock")),
    );
    allow(
        "network-outbound",
        literal(&ctx.rundir_inside.join("hook.sock")),
    );

    // Host layer: the only way to show absolute host paths.
    for path in &ctx.cfg.fs.readonly {
        allow(READ_AND_EXEC, subpath(path));
    }
    for path in &ctx.cfg.fs.writable {
        allow(&format!("file-write* {READ_AND_EXEC}"), subpath(path));
    }

    for capability in &ctx.policy.capabilities {
        if capability == "xcode" {
            rules.push(XCODE.to_owned());
        }
    }

    // Raw SBPL is accepted from the host layer only.
    if !ctx.cfg.seatbelt.extra.is_empty() {
        rules.push(format!("; host layer\n{}", ctx.cfg.seatbelt.extra));
    }

    rules.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::sandbox::testing::{policy, with_ctx};

    #[test]
    fn respects_policy() {
        let policy = policy(false);
        let mut cfg = Config::default();
        cfg.seatbelt.extra = "(allow mach-lookup (global-name \"x\"))".into();

        let profile = with_ctx(&policy, &cfg, seatbelt_profile);

        assert!(profile.starts_with("(version 1)\n(deny default)"));
        assert!(profile.contains("(deny file-read-data (literal \"/nix/store\"))"));
        assert!(profile.contains("(remote tcp \"localhost:3128\")"));
        assert!(profile.contains("(allow file-write* (subpath \"/w/it's/target\"))"));
        assert!(!profile.contains("(allow file-write* (subpath \"/w/it's\"))"));
        assert!(profile.contains("/Applications/Xcode.app"));
        assert!(profile.ends_with("(allow mach-lookup (global-name \"x\"))\n"));
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(string("/plain"), "\"/plain\"");
        assert_eq!(string("/a\"b"), r#""/a\"b""#);
        assert_eq!(string(r"/a\b"), r#""/a\\b""#);
    }

    #[test]
    fn a_path_cannot_break_out_of_its_rule() {
        let hostile = Path::new("/w\") (allow default) (\"");

        let rule = subpath(hostile);

        assert_eq!(rule, r#"(subpath "/w\") (allow default) (\"")"#);
    }

    #[test]
    fn a_writable_workdir_gets_a_write_rule() {
        let profile = with_ctx(&policy(true), &Config::default(), seatbelt_profile);

        assert!(profile.contains("(allow file-write* (subpath \"/w/it's\"))"));
    }

    #[test]
    fn the_run_directory_is_never_writable() {
        let profile = with_ctx(&policy(true), &Config::default(), seatbelt_profile);

        assert!(profile.contains("(allow file-read* (subpath \"/run/agentbox\"))"));
        assert!(!profile.contains("(allow file-write* (subpath \"/run/agentbox\"))"));
    }

    #[test]
    fn only_the_agent_sockets_and_the_proxy_are_reachable() {
        let profile = with_ctx(&policy(true), &Config::default(), seatbelt_profile);
        let network: Vec<&str> = profile
            .lines()
            .filter(|line| line.contains("network-outbound"))
            .collect();

        assert_eq!(
            network,
            [
                "(allow network-outbound (remote tcp \"localhost:3128\"))",
                "(allow network-outbound (literal \"/run/agentbox/agent.sock\"))",
                "(allow network-outbound (literal \"/run/agentbox/hook.sock\"))",
            ]
        );
    }

    #[test]
    fn capabilities_and_host_paths_are_expanded() {
        let mut cfg = Config::default();
        cfg.fs.readonly = vec!["/opt/tools".into()];

        let mut without = policy(true);
        without.capabilities.clear();

        let profile = with_ctx(&without, &cfg, seatbelt_profile);

        assert!(profile.contains("(subpath \"/opt/tools\")"));
        assert!(!profile.contains("Xcode.app"));
    }

    #[test]
    fn user_rules_come_after_the_base_denials() {
        // In SBPL the last matching rule wins, so the workdir rule must follow the
        // blanket denial of /Users.
        let profile = with_ctx(&policy(true), &Config::default(), seatbelt_profile);

        let deny_users = profile.find("(subpath \"/Users\")").unwrap();
        let allow_workdir = profile.find("(subpath \"/w/it's\")").unwrap();
        assert!(deny_users < allow_workdir);
    }
}
