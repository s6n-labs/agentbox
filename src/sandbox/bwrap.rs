//! Linux backend: bubblewrap.

use std::path::Path;

use super::{Ctx, resolve_in_path};

/// Namespaces and the minimal root filesystem every sandbox starts from.
const BASE: &[&str] = &[
    "--die-with-parent",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
];

/// Scripts expect these two to exist, even on NixOS.
const WELL_KNOWN_TOOLS: &[(&str, &str)] = &[("sh", "/bin"), ("env", "/usr/bin")];

/// Collects bubblewrap arguments.
#[derive(Default)]
struct Args(Vec<String>);

impl Args {
    fn push(&mut self, args: &[&str]) {
        self.0.extend(args.iter().map(ToString::to_string));
    }

    /// `--bind`, `--ro-bind` or `--ro-bind-try` of `source` at `target`.
    fn bind(&mut self, kind: &str, source: &Path, target: &Path) {
        self.push(&[kind, &source.to_string_lossy(), &target.to_string_lossy()]);
    }

    /// Binds a host path at the same place inside.
    fn bind_same(&mut self, kind: &str, path: &Path) {
        self.bind(kind, path, path);
    }
}

/// bubblewrap arguments up to and including `--`; the command follows.
///
/// `path_var` is the sandbox's PATH, used to find `sh` and `env`.
pub fn bwrap_args(ctx: &Ctx, path_var: &str) -> Vec<String> {
    let host = &ctx.cfg.fs;
    let host_paths = || host.readonly.iter().chain(&host.writable);
    let shown_by_host = |path: &str| host_paths().any(|shown| Path::new(path).starts_with(shown));

    let mut args = Args::default();
    args.push(BASE);

    // ponytail: the whole store is listable on Linux. Hiding other paths needs
    // per-closure binds (strict mode), which would turn every env change into a restart.
    args.bind_same("--ro-bind-try", Path::new("/nix/store"));

    // Host layer: the only way to show absolute host paths.
    for path in &host.readonly {
        args.bind_same("--ro-bind", path);
    }
    for path in &host.writable {
        args.bind_same("--bind", path);
    }

    // Workdir, then what stays writable inside it.
    let workdir_kind = if ctx.policy.fs.workdir_writable {
        "--bind"
    } else {
        "--ro-bind"
    };
    args.bind_same(workdir_kind, ctx.workdir);

    let writable = ctx.policy.fs.writable.iter();
    let writable = writable.map(|rel| ctx.workdir.join(rel));
    for path in writable.chain([ctx.private_dir()]) {
        let target = path.to_string_lossy();

        match ctx.pinned.get(&path) {
            Some(fd) => args.push(&["--bind-fd", &fd.to_string(), &target]),
            None => args.bind_same("--bind", &path),
        }
    }

    // Run directory (env.sh, sockets) and the agentbox binary, both read-only.
    args.bind("--ro-bind", ctx.rundir, ctx.rundir_inside);
    args.bind("--ro-bind", ctx.exe, ctx.exe_inside);

    if !shown_by_host("/etc") {
        args.bind(
            "--ro-bind",
            &ctx.rundir.join("passwd"),
            Path::new("/etc/passwd"),
        );
    }

    for (tool, dir) in WELL_KNOWN_TOOLS {
        if shown_by_host(dir) {
            continue;
        }

        if let Some(target) = resolve_in_path(path_var, tool, ctx.workdir) {
            args.push(&[
                "--symlink",
                &target.to_string_lossy(),
                &format!("{dir}/{tool}"),
            ]);
        }
    }

    args.push(&["--chdir", &ctx.workdir.to_string_lossy(), "--"]);
    args.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::sandbox::testing::{policy, with_ctx};

    #[test]
    fn respects_policy() {
        let policy = policy(false);
        let cfg = Config::default();

        let args = with_ctx(&policy, &cfg, |ctx| bwrap_args(ctx, "")).join(" ");

        assert!(args.contains("--unshare-net"));
        assert!(args.contains("--ro-bind /w/it's /w/it's --bind /w/it's/target /w/it's/target"));
        assert!(args.contains("--ro-bind /state/runs/r1 /run/agentbox"));
        assert!(args.contains("--bind-fd 7 /w/it's/.agentbox"));
        assert!(!args.contains("/home"));
    }

    fn args(policy: &crate::policy::Policy, cfg: &Config, path_var: &str) -> String {
        with_ctx(policy, cfg, |ctx| bwrap_args(ctx, path_var)).join(" ")
    }

    #[test]
    fn a_writable_workdir_is_bound_read_write() {
        let args = args(&policy(true), &Config::default(), "");

        assert!(args.contains(" --bind /w/it's /w/it's "));
        assert!(!args.contains("--ro-bind /w/it's /w/it's"));
    }

    #[test]
    fn everything_is_unshared_and_the_command_comes_last() {
        let args = with_ctx(&policy(true), &Config::default(), |ctx| bwrap_args(ctx, ""));

        for flag in [
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--die-with-parent",
        ] {
            assert!(args.contains(&flag.to_string()), "{flag}");
        }
        assert_eq!(&args[args.len() - 3..], ["--chdir", "/w/it's", "--"]);
    }

    #[test]
    fn only_the_host_layer_shows_absolute_paths() {
        let mut cfg = Config::default();
        cfg.fs.readonly = vec!["/usr".into()];
        cfg.fs.writable = vec!["/var/cache/shared".into()];

        let args = args(&policy(true), &cfg, "");

        assert!(args.contains("--ro-bind /usr /usr"));
        assert!(args.contains("--bind /var/cache/shared /var/cache/shared"));
    }

    #[test]
    fn passwd_is_synthesised_unless_the_host_shows_etc() {
        let synthesised = "--ro-bind /state/runs/r1/passwd /etc/passwd";
        assert!(args(&policy(true), &Config::default(), "").contains(synthesised));

        let mut cfg = Config::default();
        cfg.fs.readonly = vec!["/etc".into()];
        assert!(!args(&policy(true), &cfg, "").contains(synthesised));
    }

    #[test]
    fn sh_and_env_are_linked_from_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        for tool in ["sh", "env"] {
            let path = dir.path().join(tool);
            std::fs::write(&path, "").unwrap();
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
        }
        let path_var = dir.path().to_string_lossy().into_owned();

        let linked = args(&policy(true), &Config::default(), &path_var);
        assert!(linked.contains(&format!("--symlink {path_var}/sh /bin/sh")));
        assert!(linked.contains(&format!("--symlink {path_var}/env /usr/bin/env")));

        // Not when the host already shows those directories.
        let mut cfg = Config::default();
        cfg.fs.readonly = vec!["/bin".into(), "/usr".into()];
        assert!(!args(&policy(true), &cfg, &path_var).contains("--symlink"));
    }

    #[test]
    fn unpinned_writable_paths_fall_back_to_path_binds() {
        // The test context pins only `.agentbox`; `target` is not pinned.
        let args = args(&policy(false), &Config::default(), "");

        assert!(args.contains("--bind /w/it's/target /w/it's/target"));
        assert!(!args.contains("--bind /w/it's/.agentbox /w/it's/.agentbox"));
    }
}
