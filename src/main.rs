mod client;
mod config;
mod daemon;
mod inner;
mod mcp;
mod nixcmd;
mod policy;
mod proto;
mod proxy;
mod review;
mod rpc;
mod sandbox;

use clap::{Parser, Subcommand};

use client::Client;

#[derive(Parser)]
#[command(name = "agentbox", version, about = "Nix-based sandbox for LLM agents")]
struct Cli {
    /// Sandbox name under `agentSandboxes.<system>`.
    #[arg(short, long, global = true, default_value = "default")]
    sandbox: String,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the host daemon (normally started by systemd/launchd).
    Daemon,

    /// Run a command in a new sandbox for the current directory; it lives as long as the command.
    Run {
        /// Accept nix file edits an agent may have left unapproved.
        #[arg(short, long)]
        yes: bool,

        #[arg(required = true, last = true)]
        argv: Vec<String>,
    },

    /// Re-evaluate the current files and apply them to every run of this directory (no approval).
    Reload {
        /// Accept nix file edits an agent may have left unapproved.
        #[arg(short, long)]
        yes: bool,
    },

    /// Review the agent's pending environment request.
    Review {
        /// Print the request as JSON instead of opening the TUI.
        #[arg(long)]
        json: bool,
    },

    /// Approve the pending request without the TUI.
    Accept,

    /// Reject the pending request; the reason is returned to the agent.
    Reject {
        #[arg(short, long)]
        message: String,
    },

    /// Print the policy of the current files.
    Policy {
        /// Repository layer ∩ host layer.
        #[arg(long)]
        effective: bool,
    },

    /// List denied accesses.
    Denials,

    /// Show which rule allows or denies a path or domain.
    Explain { what: String },

    /// (inside the sandbox) MCP server on stdio.
    Mcp,

    /// (inside the sandbox) Bootstrap, then exec the command.
    #[command(hide = true)]
    Inner {
        #[arg(last = true)]
        argv: Vec<String>,
    },

    /// (inside the sandbox) Report whether the agent is mid-turn.
    #[command(hide = true)]
    Hook { state: String },
}

/// Runs the command and returns the process exit code.
fn dispatch(cli: Cli) -> anyhow::Result<i32> {
    // These run inside the sandbox. They must not start an async runtime: the bootstrap forks.
    match &cli.command {
        Cmd::Inner { argv } => return inner::inner(argv).map(|_| 0),
        Cmd::Mcp => return inner::mcp().map(|_| 0),
        Cmd::Hook { state } => return inner::hook(state).map(|_| 0),
        _ => {}
    }

    if let Cmd::Daemon = cli.command {
        let runtime = tokio::runtime::Runtime::new()?;

        return runtime.block_on(daemon::main()).map(|_| 0);
    }

    let client = Client::new(cli.sandbox)?;
    match cli.command {
        Cmd::Run { yes, argv } => return client::run(&client, yes, argv),
        Cmd::Reload { yes } => client::reload(&client, yes)?,
        Cmd::Review { json } => review::run(&client, json)?,
        Cmd::Accept => client::decide(&client, true, String::new())?,
        Cmd::Reject { message } => client::decide(&client, false, message)?,
        Cmd::Policy { effective } => client::policy(&client, effective)?,
        Cmd::Denials => client::denials(&client)?,
        Cmd::Explain { what } => client::explain(&client, what)?,
        Cmd::Daemon | Cmd::Mcp | Cmd::Inner { .. } | Cmd::Hook { .. } => unreachable!(),
    }

    Ok(0)
}

fn main() {
    let code = match dispatch(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("agentbox: {e:#}");
            1
        }
    };

    std::process::exit(code);
}
