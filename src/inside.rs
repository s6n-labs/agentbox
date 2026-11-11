//! Code that runs inside the sandbox: the bootstrap, the MCP stdio shim and turn hooks.
//! No async runtime here: the bootstrap forks.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, bail};
use nix::sys::signal::{SigHandler, Signal, signal};
use nix::unistd::{ForkResult, fork, setsid};

/// Signals the bridge must survive: it lives until the sandbox itself goes away.
const IGNORED_SIGNALS: [Signal; 5] = [
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGPIPE,
];

/// `agentbox inner -- cmd...`: prepares the sandbox from the inside, then becomes the command.
pub fn bootstrap(argv: &[String]) -> anyhow::Result<()> {
    // Set on Linux only, as `port:socket`. The sandbox has its own network namespace,
    // so the proxy is reached through a Unix socket; HTTP(S)_PROXY needs a TCP port.
    if let Ok(bridge) = std::env::var("AGENTBOX_BRIDGE") {
        // SAFETY: no other thread exists yet.
        unsafe { std::env::remove_var("AGENTBOX_BRIDGE") };

        let (port, socket) = bridge.split_once(':').context("AGENTBOX_BRIDGE")?;
        start_bridge(port.parse()?, socket)?;
    }

    let (program, args) = argv.split_first().context("no command")?;
    let error = Command::new(program).args(args).exec();

    Err(error).with_context(|| format!("exec {program}"))
}

/// Forwards `127.0.0.1:port` to the Unix socket, from a detached background process.
fn start_bridge(port: u16, socket: &str) -> anyhow::Result<()> {
    // Bound before forking, so the port accepts connections as soon as we return.
    let listener = TcpListener::bind(("127.0.0.1", port)).context("binding the proxy bridge")?;

    // Fork twice: the bridge must not be a child of the command we are about to exec.
    // SAFETY: the process is single-threaded here.
    if let ForkResult::Child = unsafe { fork() }? {
        if let Ok(ForkResult::Child) = unsafe { fork() } {
            run_bridge(listener, socket);
        }

        // SAFETY: plain exit of the intermediate process, without running destructors.
        unsafe { libc::_exit(0) };
    }

    // Reap the intermediate process.
    let _ = nix::sys::wait::wait();
    Ok(())
}

/// Detaches the bridge from the terminal and from signals meant for the command.
fn detach() {
    let _ = setsid();

    for signal_kind in IGNORED_SIGNALS {
        // SAFETY: ignoring a signal installs no handler code.
        let _ = unsafe { signal(signal_kind, SigHandler::SigIgn) };
    }

    if let Ok(null) = OpenOptions::new().read(true).write(true).open("/dev/null") {
        for stdio in 0..3 {
            // SAFETY: both are valid, open file descriptors.
            unsafe { libc::dup2(null.as_raw_fd(), stdio) };
        }
    }
}

/// Copies bytes from one stream to the other until EOF, then passes the EOF on.
fn pipe(mut from: impl Read, mut to: impl Write, shutdown: impl FnOnce()) {
    let _ = io::copy(&mut from, &mut to);
    shutdown();
}

fn run_bridge(listener: TcpListener, socket: &str) -> ! {
    detach();

    for tcp in listener.incoming().flatten() {
        let Ok(unix) = UnixStream::connect(socket) else {
            continue;
        };
        let (Ok(tcp_reader), Ok(unix_reader)) = (tcp.try_clone(), unix.try_clone()) else {
            continue;
        };

        std::thread::spawn(move || {
            pipe(tcp_reader, &unix, || {
                let _ = unix.shutdown(Shutdown::Write);
            })
        });
        std::thread::spawn(move || {
            pipe(unix_reader, &tcp, || {
                let _ = tcp.shutdown(Shutdown::Write);
            })
        });
    }

    std::process::exit(0)
}

/// Connects to one of the run's sockets, named by an environment variable.
fn connect(var: &str) -> anyhow::Result<UnixStream> {
    let path = std::env::var(var)
        .with_context(|| format!("{var} is not set: this only works inside an agentbox sandbox"))?;

    UnixStream::connect(&path).with_context(|| format!("connecting to {path}"))
}

/// `agentbox mcp`: stdio MCP server. The daemon implements it; this just pipes bytes.
pub fn mcp() -> anyhow::Result<()> {
    let mut socket = connect("AGENTBOX_SOCK")?;
    let mut upstream = socket.try_clone()?;

    std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut upstream);
        let _ = upstream.shutdown(Shutdown::Write);
    });

    let mut stdout = io::stdout().lock();
    let mut buf = [0u8; 8192];
    loop {
        let n = socket.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }

        stdout.write_all(&buf[..n])?;
        stdout.flush()?;
    }
}

/// `agentbox hook busy|idle`: tells the daemon whether the agent is mid-turn.
pub fn hook(state: &str) -> anyhow::Result<()> {
    if !matches!(state, "busy" | "idle") {
        bail!("state must be busy or idle");
    }

    let mut socket = connect("AGENTBOX_HOOK_SOCK")?;
    writeln!(socket, "{state}")?;

    Ok(())
}
