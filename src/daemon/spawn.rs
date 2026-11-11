//! Starting (and restarting) the sandboxed process of a run.

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use tokio::process::{Child, Command};

use crate::config::is_root;
use crate::policy::Policy;
use crate::sandbox::{self, BRIDGE_PORT, Ctx};

use super::Daemon;
use super::fsutil::{pin_dir, write_atomic, write_in_dir};
use super::state::Run;

/// Sandbox-private state inside the workdir: HOME and TMPDIR live here.
const PRIVATE_DIR: &str = ".agentbox";

/// Writable directories opened without following symlinks.
struct PinnedDirs {
    /// Keeps the fds open until the sandbox has started.
    _fds: Vec<OwnedFd>,
    /// Bind-mount sources for bwrap: path → fd it inherits.
    by_path: BTreeMap<PathBuf, i32>,
}

fn exit_code(status: std::io::Result<ExitStatus>) -> i32 {
    let Ok(status) = status else {
        return 1;
    };

    match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(signal)) => 128 + signal,
        (None, None) => 1,
    }
}

impl Daemon {
    /// Creates and pins every directory the policy makes writable inside the workdir.
    fn pin_writable_dirs(&self, run: &Run, policy: &Policy) -> Result<PinnedDirs, String> {
        let workdir = &run.key.workdir;
        let owner = is_root().then(|| self.sandbox_ids(&run.owner));

        let mut fds = Vec::new();
        let mut by_path = BTreeMap::new();

        let private = pin_dir(workdir, Path::new(PRIVATE_DIR), owner)?;
        // Keep sandbox state out of git, and therefore out of the pinned flake source.
        write_in_dir(&private, ".gitignore", b"*\n");
        by_path.insert(workdir.join(PRIVATE_DIR), private.as_raw_fd());
        fds.push(private);

        for name in ["home", "tmp"] {
            pin_dir(workdir, &Path::new(PRIVATE_DIR).join(name), owner)?;
        }

        for rel in &policy.fs.writable {
            let dir = pin_dir(workdir, Path::new(rel), owner)?;
            by_path.insert(workdir.join(rel), dir.as_raw_fd());
            fds.push(dir);
        }

        Ok(PinnedDirs { _fds: fds, by_path })
    }

    /// The platform's sandbox launcher, up to the point where the command follows.
    fn launcher(
        &self,
        run: &Run,
        ctx: &Ctx,
        vars: &mut BTreeMap<String, String>,
    ) -> Result<Command, String> {
        if cfg!(target_os = "macos") {
            let profile = run.dir.join("profile.sb");
            write_atomic(&profile, &sandbox::seatbelt_profile(ctx)).map_err(|e| e.to_string())?;

            let mut command = Command::new(&self.launcher);
            command.arg("-f").arg(profile);
            return Ok(command);
        }

        // The sandbox has no network: `agentbox inner` bridges a local port to the proxy.
        let proxy_socket = run.dir_inside.join("proxy.sock");
        vars.insert(
            "AGENTBOX_BRIDGE".into(),
            format!("{BRIDGE_PORT}:{}", proxy_socket.display()),
        );

        let mut command = Command::new(&self.launcher);
        command.args(sandbox::bwrap_args(ctx, &vars["PATH"]));
        Ok(command)
    }

    /// Starts the run's command in a fresh sandbox built from the applied policy.
    ///
    /// `resume` is set when restarting an agent: it is told to continue its session.
    pub(super) fn spawn_sandbox(
        self: &Arc<Self>,
        id: &str,
        resume: Option<String>,
    ) -> Result<(), String> {
        let mut guard = self.lock();
        let state = &mut *guard;

        let run = state.runs.get_mut(id).ok_or("run is gone")?;
        let approved = state
            .dirs
            .get(&run.key)
            .and_then(|dir| dir.approved.as_ref())
            .ok_or("no applied environment")?;
        let policy = self.effective(approved)?;

        let pinned = self.pin_writable_dirs(run, &policy)?;
        let ctx = self.ctx(run, &policy, &pinned.by_path);
        let mut vars = sandbox::env_vars(&run.dev, &ctx);
        let exe_path = sandbox::resolve_in_path(&vars["PATH"], &run.argv[0], &run.key.workdir);
        let argv = sandbox::adapt_argv(&run.argv, &self.exe_inside, resume.as_deref());

        let mut command = self.launcher(run, &ctx, &mut vars)?;
        command
            .arg(&self.exe_inside)
            .args(["inner", "--"])
            .args(&argv)
            .env_clear()
            .envs(&vars)
            .envs(&run.term_env)
            .current_dir(&run.key.workdir)
            .process_group(0);

        let stdio = run.stdio.as_ref().ok_or("no terminal attached")?;
        let dup = |fd: &OwnedFd| fd.try_clone().map(Stdio::from).map_err(|e| e.to_string());
        command
            .stdin(dup(&stdio[0])?)
            .stdout(dup(&stdio[1])?)
            .stderr(dup(&stdio[2])?);

        if is_root() {
            let (uid, gid) = self.sandbox_ids(&run.owner);
            command.uid(uid).gid(gid);
        }

        // bwrap receives the pinned directories as inherited fds (--bind-fd).
        let inherited: Vec<i32> = pinned.by_path.values().copied().collect();
        unsafe {
            command.pre_exec(move || {
                for fd in &inherited {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }

        let child = command
            .spawn()
            .map_err(|e| format!("starting the sandbox: {e}"))?;

        run.pgid = child.id().map(|pid| pid as i32);
        run.exe_path = exe_path;
        run.busy = false;

        // From here on the nix files may be edited by whatever runs inside.
        let key = run.key.clone();
        state.dirs.entry(key).or_default().agent_ran = true;
        self.save(state);

        self.watch(id, child);
        Ok(())
    }

    /// Waits for the sandbox to exit, then either restarts it or ends the run.
    fn watch(self: &Arc<Self>, id: &str, mut child: Child) {
        let (daemon, id) = (self.clone(), id.to_owned());

        tokio::spawn(async move {
            let status = child.wait().await;

            let resume = daemon.lock().runs.get_mut(&id).and_then(|run| {
                run.pgid = None;
                run.restart.take()
            });
            let Some(message) = resume else {
                daemon.finish(&id, exit_code(status));
                return;
            };

            if let Err(e) = daemon.spawn_sandbox(&id, Some(message)) {
                eprintln!("agentbox: run {id}: restart failed: {e}");
                daemon.finish(&id, 1);
            }
        });
    }
}
