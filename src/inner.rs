//! Code that runs inside the sandbox: the bootstrap, the MCP stdio shim and turn hooks.
//! No async runtime here: the bootstrap forks.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, bail};
use nix::sys::signal::{SigHandler, Signal, signal};
use nix::unistd::{ForkResult, fork, setsid};

/// `agentbox inner -- cmd...`: starts the proxy bridge if requested, then becomes the command.
pub fn inner(argv: &[String]) -> anyhow::Result<()> {
    // Linux only: the sandbox has its own network namespace, so the proxy is reached
    // through a Unix socket. Expose it as a local TCP port for HTTP(S)_PROXY.
    if let Ok(spec) = std::env::var("AGENTBOX_BRIDGE") {
        unsafe { std::env::remove_var("AGENTBOX_BRIDGE") };
        let (port, sock) = spec.split_once(':').context("AGENTBOX_BRIDGE")?;
        let listener = TcpListener::bind(("127.0.0.1", port.parse::<u16>()?))
            .context("binding the proxy bridge")?;
        // Double fork so the bridge is not a child of the command we are about to exec.
        if let ForkResult::Child = unsafe { fork() }? {
            if let Ok(ForkResult::Child) = unsafe { fork() } {
                bridge(listener, sock.to_owned());
            }
            unsafe { libc::_exit(0) };
        }
        let _ = nix::sys::wait::wait();
    }
    let (cmd, args) = argv.split_first().context("no command")?;
    Err(Command::new(cmd).args(args).exec()).with_context(|| format!("exec {cmd}"))
}

fn bridge(listener: TcpListener, sock: String) -> ! {
    // Lives until the sandbox's PID namespace goes away; detached from the terminal.
    let _ = setsid();
    for sig in [
        Signal::SIGINT,
        Signal::SIGTERM,
        Signal::SIGHUP,
        Signal::SIGQUIT,
        Signal::SIGPIPE,
    ] {
        let _ = unsafe { signal(sig, SigHandler::SigIgn) };
    }
    if let Ok(null) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        for fd in 0..3 {
            unsafe { libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&null), fd) };
        }
    }
    for tcp in listener.incoming().flatten() {
        let Ok(unix) = UnixStream::connect(&sock) else {
            continue;
        };
        let (Ok(mut tcp2), Ok(mut unix2)) = (tcp.try_clone(), unix.try_clone()) else {
            continue;
        };
        let (mut tcp, mut unix) = (tcp, unix);
        std::thread::spawn(move || {
            let _ = io::copy(&mut tcp2, &mut unix2);
            let _ = unix2.shutdown(Shutdown::Write);
        });
        std::thread::spawn(move || {
            let _ = io::copy(&mut unix, &mut tcp);
            let _ = tcp.shutdown(Shutdown::Write);
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
