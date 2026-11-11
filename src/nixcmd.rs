//! All Nix invocations. Evaluation and builds only ever happen here, on the host.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::Value;
use tokio::process::Command;

use crate::config::{Config, is_root};

/// The human on whose behalf Nix runs.
#[derive(Clone, Debug)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
}

/// Result of evaluating one sandbox from a pinned flake source.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Eval {
    /// Store path of the flake source copied at request time.
    pub pinned: String,
    pub drv: String,
    pub policy: Value,
}

impl Eval {
    /// Same outcome, regardless of which source copy produced it.
    pub fn same(&self, other: &Eval) -> bool {
        self.drv == other.drv && self.policy == other.policy
    }
}

async fn nix(cfg: &Config, owner: &Owner, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(&cfg.nix_bin);
    cmd.args(["--extra-experimental-features", "nix-command flakes"])
        // Never let the flake inject substituters or trusted keys.
        .args(["--option", "accept-flake-config", "false"])
        .args(args)
        .stdin(Stdio::null())
        .env("HOME", &owner.home)
        .env("USER", &owner.name);
    if is_root() {
        // Evaluate as the requesting user, not as root.
        cmd.uid(owner.uid).gid(owner.gid);
    }
    let out = cmd.output().await.map_err(|e| format!("running {}: {e}", cfg.nix_bin))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(tail(&String::from_utf8_lossy(&out.stderr), 40))
    }
}

pub fn tail(s: &str, lines: usize) -> String {
    let all: Vec<&str> = s.trim_end().lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

/// Copies the current flake source to the store, so that what is reviewed is what gets applied.
pub async fn pin(cfg: &Config, owner: &Owner, workdir: &Path) -> Result<String, String> {
    let out = nix(cfg, owner, &["flake", "metadata", "--json", "--no-write-lock-file", &workdir.to_string_lossy()]).await?;
    let v: Value = serde_json::from_str(&out).map_err(|e| format!("nix flake metadata: {e}"))?;
    v["path"].as_str().map(str::to_owned).ok_or_else(|| "nix flake metadata: no store path".into())
}

fn installable(pinned: &str, system: &str, sandbox: &str) -> String {
    format!("path:{pinned}#agentSandboxes.{system}.\"{sandbox}\"")
}

/// Pure evaluation with IFD disabled: nothing is built or run before approval.
pub async fn eval(cfg: &Config, owner: &Owner, pinned: &str, system: &str, sandbox: &str) -> Result<Eval, String> {
    let out = nix(
        cfg,
        owner,
        &[
            "eval",
            "--json",
            "--no-write-lock-file",
            "--option",
            "allow-import-from-derivation",
            "false",
            &installable(pinned, system, sandbox),
            "--apply",
            "s: { policy = s.policy; drv = s.env.drvPath; }",
        ],
    )
    .await?;
    let v: Value = serde_json::from_str(&out).map_err(|e| format!("nix eval: {e}"))?;
    let drv = v["drv"].as_str().ok_or("nix eval: no drvPath")?.to_owned();
    Ok(Eval { pinned: pinned.to_owned(), drv, policy: v["policy"].clone() })
}

/// Builds the environment and registers `profile` as its GC root.
/// Returns the JSON of `nix print-dev-env`.
pub async fn build_env(cfg: &Config, owner: &Owner, ev: &Eval, system: &str, sandbox: &str, profile: &Path) -> Result<Value, String> {
    let out = nix(
        cfg,
        owner,
        &[
            "print-dev-env",
            "--json",
            "--no-write-lock-file",
            "--profile",
            &profile.to_string_lossy(),
            &format!("{}.env", installable(&ev.pinned, system, sandbox)),
        ],
    )
    .await?;
    serde_json::from_str(&out).map_err(|e| format!("nix print-dev-env: {e}"))
}

/// Package-level diff of the two derivation closures; works before anything is built.
pub async fn closure_diff(cfg: &Config, owner: &Owner, old_drv: &str, new_drv: &str) -> Result<String, String> {
    nix(cfg, owner, &["store", "diff-closures", old_drv, new_drv]).await
}
