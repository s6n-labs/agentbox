//! agentbox core: the host daemon, sandbox backends and policy handling.
//!
//! The command-line interface lives in the binary (`src/cli`) and only uses what is
//! public here.

pub mod config;
pub mod daemon;
pub mod inside;
pub mod proto;
pub mod rpc;

mod mcp;
mod nixcmd;
mod policy;
mod proxy;
mod sandbox;
