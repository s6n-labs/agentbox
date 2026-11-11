//! Evaluating the nix files and applying the result to the runs of a workdir.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use buffa::MessageField;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde_json::{Value, json};

use crate::nixcmd::{Eval, Owner};
use crate::policy::{self, Policy};
use crate::proto::*;
use crate::sandbox::{self, Ctx, DevEnv};
use connectrpc::ConnectError;

use super::diff::make_diff;
use super::fsutil::write_atomic;
use super::state::{Key, Outcome, Run, State};
use super::{Daemon, OS, internal, precondition};

const RESTART_NOTE: &str = "agentbox: the sandbox was recreated with the updated environment \
    and this session was resumed.";

const POLICY_CHANGED_NOTE: &[u8] =
    b"\r\nagentbox: the sandbox policy changed; exit and run again to pick it up.\r\n";

/// How an approved environment reached the runs.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Applied {
    /// New commands see it immediately.
    Hot,
    /// The kernel-enforced profile (or the agent itself) changed: sandboxes are recreated.
    Restart,
}

impl Applied {
    pub fn kind(self) -> &'static str {
        match self {
            Applied::Hot => "applied",
            Applied::Restart => "restart_scheduled",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Applied::Hot => {
                "agentbox: the environment was updated. New commands already use it; restart \
                 long-running processes (LSP, MCP servers, watchers) started earlier."
            }
            Applied::Restart => {
                "Approved and built. The sandbox will be recreated when this turn ends and \
                 the session resumed; finish your turn now."
            }
        }
    }

    pub fn outcome(self) -> Outcome {
        Outcome::new(self.kind(), self.message())
    }
}

/// Kills the sandbox; the task watching it respawns it with `message` as resume prompt.
pub fn trigger_restart(run: &mut Run, message: String) {
    run.restart = Some(message);

    if let Some(pgid) = run.pgid {
        let _ = killpg(Pid::from_raw(pgid), Signal::SIGTERM);
    }
}

fn policy_response(policy: &Value) -> GetPolicyResponse {
    GetPolicyResponse {
        policy_json: policy.to_string(),
        ..Default::default()
    }
}

impl Daemon {
    /// Pins the current files and evaluates them. Nothing is built.
    pub(super) async fn evaluate(&self, key: &Key, owner: &Owner) -> Result<Eval, String> {
        let nix = self.nix(owner);
        let pinned = nix.pin(&key.workdir).await?;
        let eval = nix.eval(&pinned, &key.sandbox).await?;

        // Reject invalid policies here, so they surface as evaluation errors.
        Policy::parse(&eval.policy)?;

        Ok(eval)
    }

    /// A human-requested evaluation is applied as is, unless it would silently pick up
    /// edits an agent may have left behind. In that case, returns what would change.
    pub(super) fn unapproved_changes(&self, key: &Key, eval: &Eval, confirm: bool) -> Option<Diff> {
        let state = self.lock();
        let dir = state.dirs.get(key)?;
        let approved = dir.approved.as_ref()?;

        let needs_confirmation = !confirm && dir.agent_ran && !approved.same(eval);
        needs_confirmation.then(|| make_diff(Some(approved), eval, None))
    }

    pub(super) fn ctx<'a>(
        &'a self,
        run: &'a Run,
        policy: &'a Policy,
        pinned: &'a BTreeMap<PathBuf, i32>,
    ) -> Ctx<'a> {
        Ctx {
            workdir: &run.key.workdir,
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

    /// Builds `eval` and makes it the applied state of every run of the workdir.
    ///
    /// All builds happen before any state changes, so a build failure changes nothing.
    pub(super) async fn apply(self: &Arc<Self>, key: &Key, eval: &Eval) -> Result<Applied, String> {
        let new_policy = self.effective(eval)?;
        let built = self.build_for_runs(key, eval).await?;

        let mut guard = self.lock();
        let state = &mut *guard;

        let old_policy = state.approved(key).and_then(|a| self.effective(a).ok());
        let policy_restart = old_policy
            .as_ref()
            .is_some_and(|old| policy::needs_restart(old, &new_policy));

        let mut applied = Applied::Hot;
        for (run_id, dev) in built {
            let Some(run) = state.runs.get_mut(&run_id) else {
                continue;
            };

            if self.update_run(run, dev, &new_policy, policy_restart)? == Applied::Restart {
                applied = Applied::Restart;
            }
        }

        self.record_approval(state, key, eval, applied);
        Ok(applied)
    }

    /// Builds the environment once per run, registering each run's GC root.
    async fn build_for_runs(
        &self,
        key: &Key,
        eval: &Eval,
    ) -> Result<Vec<(String, DevEnv)>, String> {
        let runs: Vec<(String, Owner, PathBuf)> = self
            .lock()
            .runs
            .iter()
            .filter(|(_, run)| run.key == *key)
            .map(|(id, run)| (id.clone(), run.owner.clone(), run.profile.clone()))
            .collect();

        let mut built = Vec::new();
        for (run_id, owner, profile) in runs {
            let nix = self.nix(&owner);
            let json = nix.build_env(eval, &key.sandbox, &profile).await?;
            built.push((run_id, DevEnv::parse(&json)));
        }

        Ok(built)
    }

    /// Gives one run its new environment: swaps env.sh, then restarts or notifies.
    fn update_run(
        &self,
        run: &mut Run,
        dev: DevEnv,
        policy: &Policy,
        policy_restart: bool,
    ) -> Result<Applied, String> {
        run.dev = dev;

        let no_pins = BTreeMap::new();
        let vars = sandbox::env_vars(&run.dev, &self.ctx(run, policy, &no_pins));
        let env_sh = sandbox::env_sh(&vars, run.dev.shell_hook.as_deref());
        write_atomic(&run.dir.join("env.sh"), &env_sh).map_err(|e| e.to_string())?;

        if !run.is_running() {
            return Ok(Applied::Hot);
        }

        let agent_changed =
            run.exe_path != sandbox::resolve_in_path(&vars["PATH"], &run.argv[0], &run.key.workdir);
        if policy_restart || agent_changed {
            schedule_restart(run);
            return Ok(Applied::Restart);
        }

        // ponytail: an agent that did not ask for this reload is not told to restart its
        // long-running processes. MCP has no server-to-client message for that anymore
        // (logging is deprecated by SEP-2577); the requester reads it in the tool result.
        Ok(Applied::Hot)
    }

    /// Remembers `eval` as approved and settles a pending request it satisfies
    /// (the human may have run `agentbox reload` instead of accepting it).
    fn record_approval(&self, state: &mut State, key: &Key, eval: &Eval, applied: Applied) {
        let still_running = state
            .runs
            .values()
            .any(|run| run.key == *key && run.is_running());

        let dir = state.dirs.entry(key.clone()).or_default();
        dir.approved = Some(eval.clone());
        dir.agent_ran = still_running;

        if let Some(pending) = dir.pending.take_if(|p| p.eval.same(eval)) {
            let _ = pending.outcome.send(Some(applied.outcome()));
        }

        self.save(state);
    }

    // ---- RPCs ----

    pub(super) async fn reload(
        self: &Arc<Self>,
        uid: u32,
        req: ReloadRequest,
    ) -> Result<ReloadResponse, ConnectError> {
        let (key, owner) = self.target(uid, &req.target)?;
        let eval = self.evaluate(&key, &owner).await.map_err(precondition)?;

        if let Some(diff) = self.unapproved_changes(&key, &eval, req.confirm) {
            return Ok(ReloadResponse {
                needs_confirm: MessageField::some(diff),
                ..Default::default()
            });
        }

        let unchanged = self.lock().approved(&key).is_some_and(|a| a.same(&eval));
        let result = if unchanged {
            "unchanged"
        } else {
            self.apply(&key, &eval).await.map_err(precondition)?.kind()
        };

        Ok(ReloadResponse {
            result: result.into(),
            ..Default::default()
        })
    }

    /// Policy of the files as they are now (not necessarily what is applied).
    pub(super) async fn policy(
        &self,
        uid: u32,
        req: GetPolicyRequest,
    ) -> Result<GetPolicyResponse, ConnectError> {
        let (key, owner) = self.target(uid, &req.target)?;
        let eval = self.evaluate(&key, &owner).await.map_err(precondition)?;

        if !req.effective {
            return Ok(policy_response(&eval.policy));
        }

        let effective = self.effective(&eval).map_err(precondition)?;
        let mut json = serde_json::to_value(effective).map_err(internal)?;
        json["host"] = json!({
            "fs": {
                "readonly": self.cfg.fs.readonly,
                "writable": self.cfg.fs.writable,
            },
        });

        Ok(policy_response(&json))
    }

    pub(super) async fn explain(
        &self,
        uid: u32,
        req: ExplainRequest,
    ) -> Result<ExplainResponse, ConnectError> {
        let (key, owner) = self.target(uid, &req.target)?;

        let approved = self.lock().approved(&key).cloned();
        let eval = match approved {
            Some(eval) => eval,
            None => self.evaluate(&key, &owner).await.map_err(precondition)?,
        };

        let repo = Policy::parse(&eval.policy).map_err(precondition)?;
        let text = policy::explain(&repo, &self.cfg, OS, &key.workdir, &req.what);
        Ok(ExplainResponse {
            text,
            ..Default::default()
        })
    }
}

/// Agents are restarted once their turn ends. A human's shell is never restarted behind
/// their back; they are told to re-enter instead.
fn schedule_restart(run: &mut Run) {
    if !sandbox::is_agent(&run.argv) {
        if let Some(stdio) = &run.stdio {
            let _ = nix::unistd::write(&stdio[2], POLICY_CHANGED_NOTE);
        }
        return;
    }

    if run.busy {
        run.restart_when_idle = Some(RESTART_NOTE.into());
    } else {
        trigger_restart(run, RESTART_NOTE.into());
    }
}
