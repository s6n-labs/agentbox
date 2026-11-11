//! The host daemon: owns evaluation, builds, approval state, runs and the outbound proxy.
//! Its socket is never visible inside a sandbox, so any request on it comes from a human.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::IoSliceMut;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::Context;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl, openat};
use nix::sys::signal::{Signal, killpg};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{Gid, Pid, Uid, User, fchown};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::{self, Config, is_root};
use crate::nixcmd::{self, Eval, Owner, tail};
use crate::policy::{self, Policy};
use crate::proto::*;
use crate::rpc::{self, RpcError};
use crate::sandbox::{self, BRIDGE_PORT, Ctx, DevEnv};
use crate::{mcp, proxy};

const OS: &str = std::env::consts::OS;
const MAX_DENIALS: usize = 500;
const RESTART_NOTE: &str = "agentbox: the sandbox was recreated with the updated environment and this session was resumed.";
const HOT_NOTE: &str = "agentbox: the environment was updated. New commands already use it; restart long-running processes (LSP, MCP servers, watchers) started earlier.";

/// (workdir, sandbox name)
type Key = (String, String);
/// (result kind, message) of an agent's reload request.
pub type Outcome = (String, String);

struct Pending {
    ev: Eval,
    reason: String,
    tx: watch::Sender<Option<Outcome>>,
}

#[derive(Default)]
struct Dir {
    /// Last evaluation a human approved (explicitly or by requesting it); what is applied.
    approved: Option<Eval>,
    /// Something ran in this workdir since then, so its nix files may hold unapproved edits.
    agent_ran: bool,
    pending: Option<Pending>,
    denials: VecDeque<Denial>,
}

struct Run {
    key: Key,
    owner: Owner,
    argv: Vec<String>,
    term_env: BTreeMap<String, String>,
    dir: PathBuf,
    dir_inside: PathBuf,
    profile: PathBuf,
    proxy_port: u16,
    fds: Option<Vec<OwnedFd>>,
    /// Process group of the running sandbox.
    pgid: Option<i32>,
    /// What argv[0] resolved to; a change means the agent itself was updated.
    exe_path: Option<PathBuf>,
    dev: DevEnv,
    busy: bool,
    /// Set right before killing the sandbox: respawn with this resume message.
    restart: Option<String>,
    restart_when_idle: Option<String>,
    exit: watch::Sender<Option<i32>>,
    mcp: Vec<mpsc::UnboundedSender<String>>,
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Default)]
struct State {
    dirs: HashMap<Key, Dir>,
    runs: HashMap<String, Run>,
    /// Exit codes not collected by WaitRun yet.
    exited: HashMap<String, i32>,
    seq: u64,
}

pub struct Daemon {
    pub cfg: Config,
    state_dir: PathBuf,
    system: String,
    exe: PathBuf,
    exe_inside: PathBuf,
    /// uid/gid of `agent_user`, when running as root.
    agent_ids: Option<(u32, u32)>,
    st: Mutex<State>,
}

fn fp(e: impl ToString) -> RpcError {
    RpcError::new("failed_precondition", e)
}

fn internal(e: impl ToString) -> RpcError {
    RpcError::new("internal", e)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(tmp, path)
}

/// Creates `rel` under `base` and returns it opened, never following symlinks: the
/// agent controls the workdir and must not be able to redirect a bind mount.
fn pin_dir(base: &Path, rel: &Path, owner: Option<(u32, u32)>) -> Result<OwnedFd, String> {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let err = |e| format!("{}: {e} (symlinks are not allowed here)", base.join(rel).display());
    let mut fd = nix::fcntl::open(base, flags, Mode::empty()).map_err(err)?;
    for comp in rel.components() {
        let std::path::Component::Normal(name) = comp else { continue };
        let created = mkdirat(&fd, name, Mode::from_bits_truncate(0o755)).is_ok();
        let next = openat(&fd, name, flags, Mode::empty()).map_err(err)?;
        if let (true, Some((uid, gid))) = (created, owner) {
            let _ = fchown(&next, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)));
        }
        fd = next;
    }
    Ok(fd)
}

fn recv_fds(sock: &std::os::unix::net::UnixStream) -> anyhow::Result<Vec<OwnedFd>> {
    let mut byte = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut space = nix::cmsg_space!([RawFd; 3]);
    let msg = recvmsg::<()>(sock.as_raw_fd(), &mut iov, Some(&mut space), MsgFlags::empty())?;
    let mut fds = Vec::new();
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(raw) = c {
            for fd in raw {
                let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
                fds.push(fd);
            }
        }
    }
    anyhow::ensure!(fds.len() == 3, "expected 3 file descriptors, got {}", fds.len());
    Ok(fds)
}

/// nix files and the lock file of a pinned source tree, keyed by relative path.
fn nix_files(root: &Path, rel: &Path, out: &mut BTreeMap<String, String>) {
    let Ok(entries) = std::fs::read_dir(root.join(rel)) else { return };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let path = rel.join(&*name);
        let Ok(ty) = e.file_type() else { continue };
        if ty.is_dir() {
            if !name.starts_with('.') && name != "target" && name != "node_modules" {
                nix_files(root, &path, out);
            }
        } else if (name.ends_with(".nix") || name == "flake.lock")
            && let Ok(s) = std::fs::read_to_string(e.path())
        {
            out.insert(path.to_string_lossy().into_owned(), s);
        }
    }
}

fn text_diff(old: Option<&str>, new: &str) -> String {
    let (mut a, mut b) = (BTreeMap::new(), BTreeMap::new());
    if let Some(old) = old {
        nix_files(Path::new(old), Path::new(""), &mut a);
    }
    nix_files(Path::new(new), Path::new(""), &mut b);
    let names: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    let mut out = String::new();
    for name in names {
        let (x, y) = (a.get(name).map_or("", |s| s.as_str()), b.get(name).map_or("", |s| s.as_str()));
        if x != y {
            let diff = similar::TextDiff::from_lines(x, y);
            out += &diff.unified_diff().header(&format!("a/{name}"), &format!("b/{name}")).to_string();
        }
    }
    out
}

fn make_diff(old: Option<&Eval>, new: &Eval, reason: Option<String>) -> Diff {
    let old_policy = old.map_or(Value::Null, |o| o.policy.clone());
    Diff {
        reason,
        policy_patch: serde_json::to_value(json_patch::diff(&old_policy, &new.policy)).unwrap_or_default(),
        text_diff: text_diff(old.map(|o| o.pinned.as_str()), &new.pinned),
        drv_changed: old.is_none_or(|o| o.drv != new.drv),
    }
}

fn trigger_restart(run: &mut Run, message: String) {
    run.restart = Some(message);
    if let Some(pgid) = run.pgid {
        let _ = killpg(Pid::from_raw(pgid), Signal::SIGTERM);
    }
}

type Persisted = Vec<(String, String, Option<Eval>, bool)>;

impl Daemon {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn persist(&self, st: &State) {
        let data: Persisted =
            st.dirs.iter().map(|(k, d)| (k.0.clone(), k.1.clone(), d.approved.clone(), d.agent_ran)).collect();
        if let Err(e) = write_atomic(&self.state_dir.join("state.json"), &serde_json::to_string(&data).unwrap()) {
            eprintln!("agentbox: cannot persist state: {e}");
        }
    }

    /// Who the sandbox runs as: the dedicated agent user if configured, else the human.
    fn sandbox_ids(&self, owner: &Owner) -> (u32, u32) {
        self.agent_ids.unwrap_or((owner.uid, owner.gid))
    }

    fn effective(&self, ev: &Eval) -> Result<Policy, String> {
        Ok(Policy::parse(&ev.policy)?.effective(&self.cfg, OS))
    }

    /// Resolves and authorizes the target workdir for the peer.
    fn key(&self, uid: u32, t: &Target) -> Result<(Key, Owner), RpcError> {
        let workdir = std::fs::canonicalize(&t.workdir).map_err(|e| RpcError::new("not_found", format!("{}: {e}", t.workdir)))?;
        let meta = std::fs::metadata(&workdir).map_err(internal)?;
        if !meta.is_dir() || (uid != 0 && meta.uid() != uid) {
            return Err(RpcError::new("permission_denied", format!("{} is not a directory you own", workdir.display())));
        }
        if t.sandbox.is_empty() || !t.sandbox.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(RpcError::new("invalid_argument", "invalid sandbox name"));
        }
        let user = User::from_uid(Uid::from_raw(uid)).ok().flatten().ok_or_else(|| internal("unknown peer user"))?;
        let owner = Owner { uid, gid: user.gid.as_raw(), name: user.name, home: user.dir };
        Ok(((workdir.to_string_lossy().into_owned(), t.sandbox.clone()), owner))
    }

    /// Pins the current files and evaluates them. Nothing is built.
    async fn evaluate(&self, key: &Key, owner: &Owner) -> Result<Eval, String> {
        let pinned = nixcmd::pin(&self.cfg, owner, Path::new(&key.0)).await?;
        let ev = nixcmd::eval(&self.cfg, owner, &pinned, &self.system, &key.1).await?;
        Policy::parse(&ev.policy)?;
        Ok(ev)
    }

    /// A human-requested evaluation is applied as is, unless it would silently pick up
    /// edits an agent may have left behind.
    fn confirm_diff(&self, key: &Key, ev: &Eval, confirm: bool) -> Option<Diff> {
        let st = self.lock();
        let dir = st.dirs.get(key)?;
        let approved = dir.approved.as_ref()?;
        (!confirm && dir.agent_ran && !approved.same(ev)).then(|| make_diff(Some(approved), ev, None))
    }

    fn ctx<'a>(&'a self, run: &'a Run, policy: &'a Policy, pinned: &'a BTreeMap<PathBuf, i32>) -> Ctx<'a> {
        Ctx {
            workdir: Path::new(&run.key.0),
            rundir: &run.dir,
            rundir_inside: &run.dir_inside,
            exe: &self.exe,
            exe_inside: &self.exe_inside,
            policy,
            cfg: &self.cfg,
            proxy_port: run.proxy_port,
            pinned,
        }
    }

    /// Builds `ev` and makes it the applied state of every run in the workdir:
    /// hot reload where possible, restart where the kernel-enforced profile changed.
    async fn apply(self: &Arc<Self>, key: &Key, ev: &Eval) -> Result<&'static str, String> {
        let new_policy = self.effective(ev)?;
        let targets: Vec<(String, Owner, PathBuf)> = {
            let st = self.lock();
            st.runs.iter().filter(|(_, r)| r.key == *key).map(|(id, r)| (id.clone(), r.owner.clone(), r.profile.clone())).collect()
        };
        // Build everything first; state only changes once all builds succeeded.
        let mut built = Vec::new();
        for (id, owner, profile) in &targets {
            let v = nixcmd::build_env(&self.cfg, owner, ev, &self.system, &key.1, profile).await?;
            built.push((id.clone(), DevEnv::parse(&v)));
        }

        let mut guard = self.lock();
        let st = &mut *guard;
        let old_policy = st.dirs.get(key).and_then(|d| d.approved.as_ref()).and_then(|a| self.effective(a).ok());
        let policy_restart = old_policy.as_ref().is_some_and(|old| policy::needs_restart(old, &new_policy));
        let mut restarting = false;
        let no_pins = BTreeMap::new();
        for (id, dev) in built {
            let Some(run) = st.runs.get_mut(&id) else { continue };
            run.dev = dev;
            let vars = sandbox::env_vars(&run.dev, &self.ctx(run, &new_policy, &no_pins));
            write_atomic(&run.dir.join("env.sh"), &sandbox::env_sh(&vars, run.dev.shell_hook.as_deref())).map_err(|e| e.to_string())?;
            if run.pgid.is_none() {
                continue; // not started yet
            }
            let exe_changed = run.exe_path != sandbox::resolve_in_path(&vars["PATH"], &run.argv[0]);
            if policy_restart || exe_changed {
                restarting = true;
                if !sandbox::is_agent(&run.argv) {
                    // A human's shell is not restarted behind their back.
                    if let Some(fds) = &run.fds {
                        let _ = nix::unistd::write(&fds[2], b"\r\nagentbox: the sandbox policy changed; exit and run again to pick it up.\r\n");
                    }
                } else if run.busy {
                    run.restart_when_idle = Some(RESTART_NOTE.into());
                } else {
                    trigger_restart(run, RESTART_NOTE.into());
                }
            } else {
                let note = serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/message",
                    "params": { "level": "notice", "logger": "agentbox", "data": HOT_NOTE } });
                run.mcp.retain(|tx| tx.send(note.to_string()).is_ok());
            }
        }
        let live = st.runs.values().any(|r| r.key == *key && r.pgid.is_some());
        let dir = st.dirs.entry(key.clone()).or_default();
        dir.approved = Some(ev.clone());
        dir.agent_ran = live;
        let (kind, message) = if restarting {
            ("restart_scheduled", "Approved and built. The sandbox will be recreated when this turn ends and the session resumed; finish your turn now.")
        } else {
            ("applied", HOT_NOTE)
        };
        // Also settles a pending agent request the human satisfied with `agentbox reload`.
        if let Some(p) = dir.pending.take_if(|p| p.ev.same(ev)) {
            let _ = p.tx.send(Some((kind.into(), message.into())));
        }
        self.persist(st);
        Ok(kind)
    }

    async fn create_run(self: &Arc<Self>, uid: u32, r: CreateRunReq) -> Result<CreateRunRes, RpcError> {
        if r.argv.is_empty() {
            return Err(RpcError::new("invalid_argument", "no command given"));
        }
        let (key, owner) = self.key(uid, &r.target)?;
        let ev = self.evaluate(&key, &owner).await.map_err(fp)?;
        if let Some(diff) = self.confirm_diff(&key, &ev, r.confirm) {
            return Ok(CreateRunRes { needs_confirm: Some(diff), ..Default::default() });
        }

        let id = {
            let mut st = self.lock();
            st.seq += 1;
            format!("r{}", st.seq)
        };
        let sandbox_ids = self.sandbox_ids(&owner);
        let dir = self.state_dir.join("runs").join(&id);
        let ctl_path = self.state_dir.join("ctl").join(format!("{id}.sock"));
        let profile_dir = config::gcroots_dir().join(&id);
        let setup = || -> anyhow::Result<_> {
            std::fs::create_dir_all(dir.join("zdotdir"))?;
            std::fs::create_dir_all(&profile_dir)?;
            let dir_inside = if cfg!(target_os = "macos") { dir.clone() } else { PathBuf::from("/run/agentbox") };
            let rc = format!(". {}/env.sh\n", dir_inside.display());
            write_atomic(&dir.join("zdotdir/.zshenv"), &rc)?;
            // One line only: Claude Code has been reported to expand the file's content into arguments.
            write_atomic(&dir.join("claude-env"), &format!("source {}/env.sh\n", dir_inside.display()))?;
            let home = Path::new(&key.0).join(".agentbox/home");
            write_atomic(&dir.join("passwd"), &format!("agent:x:{}:{}::{}:/bin/sh\n", sandbox_ids.0, sandbox_ids.1, home.display()))?;
            let agent = UnixListener::bind(dir.join("agent.sock"))?;
            let ctl = UnixListener::bind(&ctl_path)?;
            let unix_proxy = if cfg!(target_os = "macos") { None } else { Some(UnixListener::bind(dir.join("proxy.sock"))?) };
            for sock in ["agent.sock", "proxy.sock"] {
                let _ = std::fs::set_permissions(dir.join(sock), std::fs::Permissions::from_mode(0o660));
            }
            if is_root() {
                // The sandbox user may read the run directory but never write it.
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750))?;
                for p in [dir.clone(), dir.join("zdotdir"), dir.join("agent.sock"), dir.join("proxy.sock")] {
                    let _ = chown(&p, Some(0), Some(sandbox_ids.1));
                }
                chown(&ctl_path, Some(owner.uid), None)?;
                chown(&profile_dir, Some(owner.uid), Some(owner.gid))?;
            }
            Ok((dir_inside, agent, ctl, unix_proxy))
        };
        let (dir_inside, agent, ctl, unix_proxy) = setup().map_err(internal)?;
        // ponytail: one TCP port per run on macOS (no network namespaces there).
        let tcp_proxy = if unix_proxy.is_none() { Some(TcpListener::bind("127.0.0.1:0").await.map_err(internal)?) } else { None };
        let proxy_port = tcp_proxy.as_ref().and_then(|l| l.local_addr().ok()).map_or(BRIDGE_PORT, |a| a.port());

        let term_env = r.env.into_iter().filter(|(k, _)| matches!(k.as_str(), "TERM" | "COLORTERM" | "LANG" | "LC_ALL")).collect();
        let run = Run {
            key: key.clone(),
            owner,
            argv: r.argv,
            term_env,
            dir,
            dir_inside,
            profile: profile_dir.join("env"),
            proxy_port,
            fds: None,
            pgid: None,
            exe_path: None,
            dev: DevEnv::default(),
            busy: false,
            restart: None,
            restart_when_idle: None,
            exit: watch::channel(None).0,
            mcp: Vec::new(),
            tasks: Vec::new(),
        };
        self.lock().runs.insert(id.clone(), run);
        // A run is also a reload: it brings the workdir to the current files.
        if let Err(e) = self.apply(&key, &ev).await {
            self.cleanup(&id);
            return Err(fp(e));
        }

        let mut tasks = Vec::new();
        let (d, rid) = (self.clone(), id.clone());
        tasks.push(tokio::spawn(async move {
            while let Ok((stream, _)) = agent.accept().await {
                tokio::spawn(mcp::serve_conn(d.clone(), rid.clone(), stream));
            }
        }));
        let (d, rid) = (self.clone(), id.clone());
        tasks.push(tokio::spawn(async move {
            loop {
                let (d, rid) = (d.clone(), rid.clone());
                let allowed = move |host: &str, port: u16| d.net_check(&rid, host, port);
                match (&unix_proxy, &tcp_proxy) {
                    (Some(l), _) => match l.accept().await {
                        Ok((s, _)) => drop(tokio::spawn(async move { proxy::handle(s, allowed).await })),
                        Err(_) => return,
                    },
                    (_, Some(l)) => match l.accept().await {
                        Ok((s, _)) => drop(tokio::spawn(async move { proxy::handle(s, allowed).await })),
                        Err(_) => return,
                    },
                    _ => return,
                }
            }
        }));
        let (d, rid) = (self.clone(), id.clone());
        tasks.push(tokio::spawn(async move {
            if let Err(e) = d.attach(&rid, ctl, uid).await {
                eprintln!("agentbox: run {rid}: {e:#}");
                d.finish(&rid, 127);
            }
        }));
        match self.lock().runs.get_mut(&id) {
            Some(run) => run.tasks = tasks,
            None => tasks.iter().for_each(|t| t.abort()),
        }
        Ok(CreateRunRes { run_id: Some(id), fd_socket: Some(ctl_path.to_string_lossy().into_owned()), needs_confirm: None })
    }

    /// Receives the CLI's terminal fds, starts the sandbox, and ties its life to the CLI.
    async fn attach(self: &Arc<Self>, id: &str, ctl: UnixListener, uid: u32) -> anyhow::Result<()> {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(30), ctl.accept()).await.context("the CLI never attached")??;
        anyhow::ensure!(stream.peer_cred()?.uid() == uid, "peer mismatch");
        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;
        let (std_stream, fds) = tokio::task::spawn_blocking(move || recv_fds(&std_stream).map(|fds| (std_stream, fds))).await??;
        if let Some(run) = self.lock().runs.get_mut(id) {
            run.fds = Some(fds);
        }
        self.spawn_child(id, None).map_err(anyhow::Error::msg)?;

        std_stream.set_nonblocking(true)?;
        let mut stream = UnixStream::from_std(std_stream)?;
        let mut buf = [0u8; 16];
        while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
        // The CLI is gone: nothing owns the terminal anymore.
        for sig in [Signal::SIGHUP, Signal::SIGKILL] {
            let pgid = self.lock().runs.get_mut(id).and_then(|r| {
                r.restart = None;
                r.restart_when_idle = None;
                r.pgid
            });
            let Some(pgid) = pgid else { break };
            let _ = killpg(Pid::from_raw(pgid), sig);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        Ok(())
    }

    fn spawn_child(self: &Arc<Self>, id: &str, resume: Option<String>) -> Result<(), String> {
        let mut guard = self.lock();
        let st = &mut *guard;
        let run = st.runs.get_mut(id).ok_or("run is gone")?;
        let approved = st.dirs.get(&run.key).and_then(|d| d.approved.as_ref()).ok_or("no applied environment")?;
        let policy = self.effective(approved)?;
        let workdir = PathBuf::from(&run.key.0);
        let ids = self.sandbox_ids(&run.owner);
        let chown_to = is_root().then_some(ids);

        // Open every policy-controlled writable directory without following symlinks.
        let mut keep = Vec::new();
        let mut pinned = BTreeMap::new();
        let private = [".agentbox", ".agentbox/home", ".agentbox/tmp"].map(PathBuf::from);
        for rel in private.iter().cloned().chain(policy.fs.writable.iter().map(PathBuf::from)) {
            let fd = pin_dir(&workdir, &rel, chown_to)?;
            if rel == private[0] {
                // Keep sandbox state out of git (and therefore out of the pinned flake source).
                let flags = OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
                if let Ok(f) = openat(&fd, ".gitignore", flags, Mode::from_bits_truncate(0o644)) {
                    let _ = nix::unistd::write(&f, b"*\n");
                }
            }
            if rel != private[1] && rel != private[2] {
                pinned.insert(workdir.join(&rel), fd.as_raw_fd());
            }
            keep.push(fd);
        }

        let ctx = self.ctx(run, &policy, &pinned);
        let mut vars = sandbox::env_vars(&run.dev, &ctx);
        let path_var = vars["PATH"].clone();
        let argv = sandbox::adapt_argv(&run.argv, &self.exe_inside, resume.as_deref());
        let mut cmd;
        if cfg!(target_os = "macos") {
            let profile = run.dir.join("profile.sb");
            write_atomic(&profile, &sandbox::seatbelt_profile(&ctx)).map_err(|e| e.to_string())?;
            cmd = Command::new("/usr/bin/sandbox-exec");
            cmd.arg("-f").arg(profile);
        } else {
            cmd = Command::new("bwrap");
            cmd.args(sandbox::bwrap_args(&ctx, &path_var));
            vars.insert("AGENTBOX_BRIDGE".into(), format!("{BRIDGE_PORT}:{}/proxy.sock", run.dir_inside.display()));
        }
        let fds = run.fds.as_ref().ok_or("no terminal attached")?;
        let stdio = |i: usize| fds[i].try_clone().map(Stdio::from).map_err(|e| e.to_string());
        cmd.arg(&self.exe_inside)
            .args(["inner", "--"])
            .args(&argv)
            .env_clear()
            .envs(&vars)
            .envs(&run.term_env)
            .current_dir(&workdir)
            .stdin(stdio(0)?)
            .stdout(stdio(1)?)
            .stderr(stdio(2)?)
            .process_group(0);
        if is_root() {
            cmd.uid(ids.0).gid(ids.1);
        }
        let inherit: Vec<i32> = pinned.values().copied().collect();
        unsafe {
            // bwrap receives the pinned directories as inherited fds (--bind-fd).
            cmd.pre_exec(move || {
                for fd in &inherit {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|e| format!("starting the sandbox: {e}"))?;
        drop(keep);
        run.pgid = child.id().map(|p| p as i32);
        run.exe_path = sandbox::resolve_in_path(&path_var, &run.argv[0]);
        run.busy = false;
        let key = run.key.clone();
        st.dirs.entry(key).or_default().agent_ran = true;
        self.persist(st);

        let (d, id) = (self.clone(), id.to_owned());
        tokio::spawn(async move {
            let status = child.wait().await;
            let resume = d.lock().runs.get_mut(&id).and_then(|r| {
                r.pgid = None;
                r.restart.take()
            });
            match resume {
                Some(message) => {
                    if let Err(e) = d.spawn_child(&id, Some(message)) {
                        eprintln!("agentbox: run {id}: restart failed: {e}");
                        d.finish(&id, 1);
                    }
                }
                None => {
                    use std::os::unix::process::ExitStatusExt;
                    let code = status.ok().and_then(|s| s.code().or(s.signal().map(|sig| 128 + sig))).unwrap_or(1);
                    d.finish(&id, code);
                }
            }
        });
        Ok(())
    }

    fn finish(&self, id: &str, code: i32) {
        let mut st = self.lock();
        if let Some(run) = st.runs.get(id) {
            let _ = run.exit.send(Some(code));
            st.exited.insert(id.to_owned(), code);
        }
        drop(st);
        self.cleanup(id);
    }

    /// Drops the run, its directory and its GC roots. The store itself is left to Nix GC.
    fn cleanup(&self, id: &str) {
        let Some(run) = self.lock().runs.remove(id) else { return };
        run.tasks.iter().for_each(|t| t.abort());
        let _ = std::fs::remove_dir_all(&run.dir);
        let _ = std::fs::remove_file(self.state_dir.join("ctl").join(format!("{id}.sock")));
        if let Some(roots) = run.profile.parent() {
            let _ = std::fs::remove_dir_all(roots);
        }
    }

    fn net_check(&self, run_id: &str, host: &str, port: u16) -> bool {
        let mut st = self.lock();
        let Some(key) = st.runs.get(run_id).map(|r| r.key.clone()) else { return false };
        let dir = st.dirs.entry(key).or_default();
        let allowed = dir.approved.as_ref().and_then(|a| self.effective(a).ok()).is_some_and(|p| p.net_allowed(host, port));
        if !allowed {
            if dir.denials.len() >= MAX_DENIALS {
                dir.denials.pop_front();
            }
            dir.denials.push_back(Denial { run_id: run_id.to_owned(), time: now(), kind: "network".into(), target: format!("{host}:{port}") });
        }
        allowed
    }

    // ---- agent side (per-run socket) ----

    pub fn register_mcp(&self, run_id: &str, tx: mpsc::UnboundedSender<String>) {
        if let Some(run) = self.lock().runs.get_mut(run_id) {
            run.mcp.push(tx);
        }
    }

    pub fn set_busy(&self, run_id: &str, busy: bool) {
        if let Some(run) = self.lock().runs.get_mut(run_id) {
            run.busy = busy;
            if !busy && let Some(message) = run.restart_when_idle.take() {
                trigger_restart(run, message);
            }
        }
    }

    pub fn run_denials(&self, run_id: &str) -> Vec<Denial> {
        let st = self.lock();
        let Some(run) = st.runs.get(run_id) else { return Vec::new() };
        st.dirs.get(&run.key).map(|d| d.denials.iter().filter(|x| x.run_id == run_id).cloned().collect()).unwrap_or_default()
    }

    pub fn run_policy(&self, run_id: &str) -> Option<Policy> {
        let st = self.lock();
        let run = st.runs.get(run_id)?;
        self.effective(st.dirs.get(&run.key)?.approved.as_ref()?).ok()
    }

    /// An agent asks for re-evaluation. Returns immediately (`Err`) when no human is
    /// needed, otherwise a channel that yields the human's decision.
    pub async fn agent_reload(self: &Arc<Self>, run_id: &str, reason: String) -> Result<watch::Receiver<Option<Outcome>>, Outcome> {
        let found = self.lock().runs.get(run_id).map(|r| (r.key.clone(), r.owner.clone()));
        let (key, owner) = found.ok_or_else(|| ("eval_error".to_owned(), "this run no longer exists".to_owned()))?;
        // Evaluation errors go straight back; a human is never bothered with them.
        let ev = self.evaluate(&key, &owner).await.map_err(|e| ("eval_error".to_owned(), e))?;
        let mut st = self.lock();
        let dir = st.dirs.entry(key).or_default();
        if dir.approved.as_ref().is_some_and(|a| a.same(&ev)) {
            return Err(("unchanged".into(), "The evaluated environment is identical to the applied one; nothing to approve.".into()));
        }
        if let Some(p) = &dir.pending
            && p.ev.same(&ev)
        {
            return Ok(p.tx.subscribe()); // idempotent retry
        }
        // At most one pending request per workdir: the newest wins.
        if let Some(old) = dir.pending.take() {
            let _ = old.tx.send(Some(("rejected".into(), "Superseded by a newer reload_env request.".into())));
        }
        let (tx, rx) = watch::channel(None);
        dir.pending = Some(Pending { ev, reason, tx });
        Ok(rx)
    }

    // ---- human side (daemon socket) ----

    async fn reload(self: &Arc<Self>, uid: u32, r: ReloadReq) -> Result<ReloadRes, RpcError> {
        let (key, owner) = self.key(uid, &r.target)?;
        let ev = self.evaluate(&key, &owner).await.map_err(fp)?;
        if let Some(diff) = self.confirm_diff(&key, &ev, r.confirm) {
            return Ok(ReloadRes { needs_confirm: Some(diff), result: None });
        }
        let unchanged = self.lock().dirs.get(&key).and_then(|d| d.approved.as_ref()).is_some_and(|a| a.same(&ev));
        let result = if unchanged { "unchanged" } else { self.apply(&key, &ev).await.map_err(fp)? };
        Ok(ReloadRes { needs_confirm: None, result: Some(result.into()) })
    }

    fn pending(&self, uid: u32, t: &Target) -> Result<PendingRes, RpcError> {
        let (key, _) = self.key(uid, t)?;
        let st = self.lock();
        let dir = st.dirs.get(&key);
        let pending = dir.and_then(|d| d.pending.as_ref().map(|p| make_diff(d.approved.as_ref(), &p.ev, Some(p.reason.clone()))));
        let notes = st
            .runs
            .iter()
            .filter(|(_, r)| r.key == key && r.restart_when_idle.is_some())
            .map(|(id, _)| format!("approved, waiting to apply: run {id} restarts when the agent's turn ends"))
            .collect();
        Ok(PendingRes { pending, notes })
    }

    async fn decide(self: &Arc<Self>, uid: u32, r: DecideReq) -> Result<TextRes, RpcError> {
        let (key, _) = self.key(uid, &r.target)?;
        let no_pending = || RpcError::new("not_found", "no pending request for this workdir");
        if !r.accept {
            let p = self.lock().dirs.get_mut(&key).and_then(|d| d.pending.take()).ok_or_else(no_pending)?;
            // The files stay edited after a rejection, so tell the agent to deal with them.
            let message = format!("Rejected by the human: {}\nThe nix files still contain your edits: revert them or fix them and call reload_env again.", r.reason);
            let _ = p.tx.send(Some(("rejected".into(), message)));
            return Ok(TextRes { text: "rejected".into() });
        }
        // Applied from the copy pinned at request time, so it is exactly what was reviewed.
        let ev = self.lock().dirs.get(&key).and_then(|d| d.pending.as_ref().map(|p| p.ev.clone())).ok_or_else(no_pending)?;
        match self.apply(&key, &ev).await {
            Ok(kind) => Ok(TextRes { text: kind.into() }),
            Err(e) => {
                if let Some(p) = self.lock().dirs.get_mut(&key).and_then(|d| d.pending.take_if(|p| p.ev.same(&ev))) {
                    let _ = p.tx.send(Some(("build_error".into(), tail(&e, 40))));
                }
                Err(fp(format!("build failed (reported to the agent):\n{e}")))
            }
        }
    }

    async fn closure_diff(&self, uid: u32, t: &Target) -> Result<TextRes, RpcError> {
        let (key, owner) = self.key(uid, t)?;
        let drvs = {
            let st = self.lock();
            st.dirs.get(&key).and_then(|d| Some((d.approved.as_ref()?.drv.clone(), d.pending.as_ref()?.ev.drv.clone())))
        };
        let (old, new) = drvs.ok_or_else(|| RpcError::new("not_found", "nothing to compare"))?;
        let text = nixcmd::closure_diff(&self.cfg, &owner, &old, &new).await.map_err(fp)?;
        Ok(TextRes { text })
    }

    async fn policy(&self, uid: u32, r: PolicyReq) -> Result<Value, RpcError> {
        let (key, owner) = self.key(uid, &r.target)?;
        let ev = self.evaluate(&key, &owner).await.map_err(fp)?;
        if !r.effective {
            return Ok(ev.policy);
        }
        let mut v = serde_json::to_value(self.effective(&ev).map_err(fp)?).map_err(internal)?;
        v["host"] = serde_json::json!({ "fs": { "readonly": self.cfg.fs.readonly, "writable": self.cfg.fs.writable } });
        Ok(v)
    }

    async fn explain(&self, uid: u32, r: ExplainReq) -> Result<TextRes, RpcError> {
        let (key, owner) = self.key(uid, &r.target)?;
        let approved = self.lock().dirs.get(&key).and_then(|d| d.approved.clone());
        let ev = match approved {
            Some(ev) => ev,
            None => self.evaluate(&key, &owner).await.map_err(fp)?,
        };
        let repo = Policy::parse(&ev.policy).map_err(fp)?;
        Ok(TextRes { text: policy::explain(&repo, &self.cfg, OS, Path::new(&key.0), &r.what) })
    }

    fn denials(&self, uid: u32, t: &Target) -> Result<DenialsRes, RpcError> {
        let (key, _) = self.key(uid, t)?;
        let denials = self.lock().dirs.get(&key).map(|d| d.denials.iter().cloned().collect()).unwrap_or_default();
        Ok(DenialsRes { denials })
    }

    fn owned_run<T>(&self, uid: u32, id: &str, f: impl FnOnce(&Run) -> T) -> Result<T, RpcError> {
        let st = self.lock();
        let run = st.runs.get(id).ok_or_else(|| RpcError::new("not_found", "no such run"))?;
        if uid != 0 && run.owner.uid != uid {
            return Err(RpcError::new("permission_denied", "not your run"));
        }
        Ok(f(run))
    }

    async fn wait_run(&self, uid: u32, r: RunRef) -> Result<WaitRunRes, RpcError> {
        if let Some(code) = self.lock().exited.remove(&r.run_id) {
            return Ok(WaitRunRes { exit_code: code });
        }
        let mut rx = self.owned_run(uid, &r.run_id, |run| run.exit.subscribe())?;
        loop {
            if let Some(code) = *rx.borrow() {
                self.lock().exited.remove(&r.run_id);
                return Ok(WaitRunRes { exit_code: code });
            }
            rx.changed().await.map_err(|_| internal("run vanished"))?;
        }
    }

    fn signal_run(&self, uid: u32, r: SignalReq) -> Result<Value, RpcError> {
        let pgid = self.owned_run(uid, &r.run_id, |run| run.pgid)?;
        let sig = Signal::try_from(r.signal).map_err(|e| RpcError::new("invalid_argument", e))?;
        if let Some(pgid) = pgid {
            let _ = killpg(Pid::from_raw(pgid), sig);
        }
        Ok(Value::Object(Default::default()))
    }

    async fn handle(self: Arc<Self>, uid: u32, method: &str, body: &[u8]) -> Result<Vec<u8>, RpcError> {
        fn req<T: DeserializeOwned>(body: &[u8]) -> Result<T, RpcError> {
            serde_json::from_slice(body).map_err(|e| RpcError::new("invalid_argument", e))
        }
        fn res<T: Serialize>(v: T) -> Result<Vec<u8>, RpcError> {
            serde_json::to_vec(&v).map_err(internal)
        }
        match method {
            "CreateRun" => res(self.create_run(uid, req(body)?).await?),
            "WaitRun" => res(self.wait_run(uid, req(body)?).await?),
            "SignalRun" => res(self.signal_run(uid, req(body)?)?),
            "Reload" => res(self.reload(uid, req(body)?).await?),
            "GetPending" => res(self.pending(uid, &req(body)?)?),
            "Decide" => res(self.decide(uid, req(body)?).await?),
            "ClosureDiff" => res(self.closure_diff(uid, &req(body)?).await?),
            "GetPolicy" => res(self.policy(uid, req(body)?).await?),
            "Explain" => res(self.explain(uid, req(body)?).await?),
            "ListDenials" => res(self.denials(uid, &req(body)?)?),
            _ => Err(RpcError::new("unimplemented", format!("unknown method {method:?}"))),
        }
    }
}

pub async fn main() -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let state_dir = config::state_dir();
    // Every run died with the previous daemon: drop their directories and GC roots.
    for stale in [state_dir.join("runs"), state_dir.join("ctl"), config::gcroots_dir()] {
        let _ = std::fs::remove_dir_all(&stale);
        std::fs::create_dir_all(&stale).with_context(|| format!("creating {}", stale.display()))?;
    }
    if is_root() {
        // Traversable, not listable.
        for dir in [&state_dir, &state_dir.join("runs"), &state_dir.join("ctl")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711))?;
        }
        std::fs::set_permissions(config::gcroots_dir(), std::fs::Permissions::from_mode(0o711))?;
    } else {
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let agent_ids = match (&cfg.agent_user, is_root()) {
        (Some(name), true) => {
            let user = User::from_name(name)?.with_context(|| format!("agent_user {name:?} does not exist"))?;
            Some((user.uid.as_raw(), user.gid.as_raw()))
        }
        (Some(_), false) => {
            eprintln!("agentbox: agent_user is ignored: the daemon is not running as root");
            None
        }
        _ => None,
    };

    let mut st = State::default();
    if let Ok(s) = std::fs::read_to_string(state_dir.join("state.json")) {
        for (workdir, sandbox, approved, agent_ran) in serde_json::from_str::<Persisted>(&s).unwrap_or_default() {
            st.dirs.insert((workdir, sandbox), Dir { approved, agent_ran, ..Default::default() });
        }
    }

    let exe = std::env::current_exe()?;
    let arch = std::env::consts::ARCH;
    let daemon = Arc::new(Daemon {
        system: format!("{arch}-{}", if cfg!(target_os = "macos") { "darwin" } else { "linux" }),
        exe_inside: if cfg!(target_os = "macos") { exe.clone() } else { "/run/agentbox-bin/agentbox".into() },
        exe,
        cfg,
        state_dir,
        agent_ids,
        st: Mutex::new(st),
    });

    let socket = config::socket_path();
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).with_context(|| format!("binding {}", socket.display()))?;
    // A root daemon serves every user and authorizes by peer credentials.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(if is_root() { 0o666 } else { 0o600 }))?;
    eprintln!("agentbox: listening on {}", socket.display());

    let serve = rpc::serve(listener, move |uid, method, body| {
        let d = daemon.clone();
        async move { d.handle(uid, &method, &body).await }
    });
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = serve => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    let _ = std::fs::remove_file(&socket);
    Ok(())
}
