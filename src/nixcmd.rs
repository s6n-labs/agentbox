//! All Nix invocations. Evaluation and builds only ever happen here, on the host.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::process::Command;

use crate::config::{Config, is_root};

/// Lines of Nix's stderr kept when a command fails.
const ERROR_LINES: usize = 40;

/// Pulls out what the daemon needs from a sandbox definition in one evaluation.
const EVAL_EXPRESSION: &str = "s: { policy = s.policy; drv = s.env.drvPath; }";

/// The human on whose behalf Nix runs.
#[derive(Clone, Debug)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
}

/// Result of evaluating one sandbox from a pinned flake source.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Eval {
    /// Store path of the flake source, copied when the evaluation was requested.
    pub pinned: String,

    /// Derivation of the environment (the dev shell).
    pub drv: String,

    /// The repository policy, as evaluated.
    pub policy: Value,
}

impl Eval {
    /// Same outcome, regardless of which source copy produced it.
    pub fn same(&self, other: &Eval) -> bool {
        self.drv == other.drv && self.policy == other.policy
    }
}

/// The last `lines` lines of a command's output.
pub fn tail(output: &str, lines: usize) -> String {
    let all: Vec<&str> = output.trim_end().lines().collect();
    let start = all.len().saturating_sub(lines);

    all[start..].join("\n")
}

fn parse_json(command: &str, output: &str) -> Result<Value, String> {
    serde_json::from_str(output).map_err(|e| format!("nix {command}: {e}"))
}

/// Runs Nix for one user and one system.
pub struct Nix<'a> {
    pub cfg: &'a Config,
    pub owner: &'a Owner,

    /// e.g. `x86_64-linux`
    pub system: &'a str,
}

impl Nix<'_> {
    /// Runs `nix` and returns its stdout, or the end of its stderr on failure.
    async fn run(&self, args: &[&str]) -> Result<String, String> {
        let mut command = Command::new(&self.cfg.nix_bin);
        command
            .args(["--extra-experimental-features", "nix-command flakes"])
            // Never let the flake inject substituters or trusted keys.
            .args(["--option", "accept-flake-config", "false"])
            .args(args)
            .stdin(Stdio::null())
            .env("HOME", &self.owner.home)
            .env("USER", &self.owner.name);

        // A root daemon evaluates as the requesting user, not as root.
        if is_root() {
            command.uid(self.owner.uid).gid(self.owner.gid);
        }

        let output = command
            .output()
            .await
            .map_err(|e| format!("running {}: {e}", self.cfg.nix_bin))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(tail(&stderr, ERROR_LINES));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// The flake output of one sandbox in a pinned source.
    fn installable(&self, pinned: &str, sandbox: &str) -> String {
        format!("path:{pinned}#agentSandboxes.{}.\"{sandbox}\"", self.system)
    }

    /// Copies the current flake source to the store and returns its store path.
    ///
    /// Everything afterwards works on this copy, so that what a human reviews is
    /// exactly what gets applied, whatever happens to the files in the meantime.
    pub async fn pin(&self, workdir: &Path) -> Result<String, String> {
        let workdir = workdir.to_string_lossy();
        let args = [
            "flake",
            "metadata",
            "--json",
            "--no-write-lock-file",
            &workdir,
        ];

        let output = self.run(&args).await?;
        let metadata = parse_json("flake metadata", &output)?;

        match metadata["path"].as_str() {
            Some(path) => Ok(path.to_owned()),
            None => Err("nix flake metadata: no store path".into()),
        }
    }

    /// Evaluates a sandbox. Pure and with import-from-derivation disabled, so nothing
    /// is built or run: it is safe to do before a human approved anything.
    pub async fn eval(&self, pinned: &str, sandbox: &str) -> Result<Eval, String> {
        let installable = self.installable(pinned, sandbox);
        let args = [
            "eval",
            "--json",
            "--no-write-lock-file",
            "--option",
            "allow-import-from-derivation",
            "false",
            &installable,
            "--apply",
            EVAL_EXPRESSION,
        ];

        let output = self.run(&args).await?;
        let result = parse_json("eval", &output)?;
        let drv = result["drv"].as_str().ok_or("nix eval: no drvPath")?;

        Ok(Eval {
            pinned: pinned.to_owned(),
            drv: drv.to_owned(),
            policy: result["policy"].clone(),
        })
    }

    /// Builds the environment and registers `profile` as its GC root.
    /// Returns the JSON of `nix print-dev-env`.
    pub async fn build_env(
        &self,
        eval: &Eval,
        sandbox: &str,
        profile: &Path,
    ) -> Result<Value, String> {
        let installable = format!("{}.env", self.installable(&eval.pinned, sandbox));
        let profile = profile.to_string_lossy();
        let args = [
            "print-dev-env",
            "--json",
            "--no-write-lock-file",
            "--profile",
            &profile,
            &installable,
        ];

        let output = self.run(&args).await?;

        parse_json("print-dev-env", &output)
    }

    /// Package-level diff of two derivation closures. Works before anything is built.
    pub async fn closure_diff(&self, old_drv: &str, new_drv: &str) -> Result<String, String> {
        self.run(&["store", "diff-closures", old_drv, new_drv])
            .await
    }
}
