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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::testing::{Fixture, policy};

    fn reload_request(fixture: &Fixture, confirm: bool) -> ReloadRequest {
        ReloadRequest {
            target: MessageField::some(fixture.target()),
            confirm,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn the_first_reload_applies_without_questions() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));

        let request = reload_request(&fixture, false);
        let response = fixture.daemon.reload(fixture.uid(), request).await.unwrap();

        assert_eq!(response.result, "applied");
        assert!(response.needs_confirm.is_unset());
        assert_eq!(fixture.approved_drv().as_deref(), Some("env1.drv"));
    }

    #[tokio::test]
    async fn reloading_unchanged_files_does_nothing() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.approve_current().await;

        let request = reload_request(&fixture, false);
        let response = fixture.daemon.reload(fixture.uid(), request).await.unwrap();

        assert_eq!(response.result, "unchanged");
    }

    #[tokio::test]
    async fn a_human_edit_is_applied_without_confirmation() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.approve_current().await;

        // Nothing ran since the approval, so the edit can only be the human's.
        fixture.set_eval("env2.drv", policy(&[]));
        let request = reload_request(&fixture, false);
        let response = fixture.daemon.reload(fixture.uid(), request).await.unwrap();

        assert_eq!(response.result, "applied");
    }

    #[tokio::test]
    async fn edits_after_an_agent_ran_need_confirmation() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.approve_current().await;
        fixture
            .daemon
            .lock()
            .dirs
            .get_mut(&fixture.key)
            .unwrap()
            .agent_ran = true;
        fixture.set_eval("env2.drv", policy(&["example.com"]));

        let request = reload_request(&fixture, false);
        let asked = fixture.daemon.reload(fixture.uid(), request).await.unwrap();

        let diff = asked.needs_confirm.as_option().expect("a diff to confirm");
        assert_eq!(diff.policy_patch[0].path, "/network/allow/0");
        assert_eq!(asked.result, "");
        assert_eq!(fixture.approved_drv().as_deref(), Some("env1.drv"));

        // With --yes it goes through, and the question is not asked again.
        let request = reload_request(&fixture, true);
        let confirmed = fixture.daemon.reload(fixture.uid(), request).await.unwrap();
        assert_eq!(confirmed.result, "applied");

        let request = reload_request(&fixture, false);
        let after = fixture.daemon.reload(fixture.uid(), request).await.unwrap();
        assert_eq!(after.result, "unchanged");
    }

    #[tokio::test]
    async fn an_evaluation_error_fails_the_reload() {
        let fixture = Fixture::new();
        fixture.fail_eval("error: syntax error");

        let request = reload_request(&fixture, false);
        let error = fixture
            .daemon
            .reload(fixture.uid(), request)
            .await
            .unwrap_err();

        assert_eq!(error.code, connectrpc::ErrorCode::FailedPrecondition);
        assert!(error.message.unwrap().contains("syntax error"));
    }

    #[tokio::test]
    async fn applying_writes_env_sh_for_every_run() {
        let fixture = Fixture::new();
        let mut with_env = policy(&[]);
        with_env["env"] = serde_json::json!({ "GREETING": "hello" });
        fixture.set_eval("env1.drv", with_env);
        fixture.add_run("r1", &["zsh"]);
        fixture.add_run("r2", &["claude"]);

        fixture.approve_current().await;

        for id in ["r1", "r2"] {
            let env_sh = fixture.with_run(id, |run| run.dir.join("env.sh"));
            let script = std::fs::read_to_string(env_sh).unwrap();

            assert!(script.contains("export GREETING=hello"), "{script}");
            assert!(
                script.contains("export PATH=/bin:/run/agentbox-bin"),
                "{script}"
            );
        }
    }

    #[tokio::test]
    async fn a_failed_build_leaves_env_sh_and_the_approval_alone() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.add_run("r1", &["zsh"]);
        fixture.approve_current().await;
        let env_sh = fixture.with_run("r1", |run| run.dir.join("env.sh"));
        let before = std::fs::read_to_string(&env_sh).unwrap();

        fixture.set_eval("env2.drv", policy(&[]));
        fixture.fail_build("error: boom");
        let eval = fixture
            .daemon
            .evaluate(&fixture.key, &fixture.owner)
            .await
            .unwrap();
        let error = fixture.daemon.apply(&fixture.key, &eval).await.unwrap_err();

        assert!(error.contains("boom"));
        assert_eq!(std::fs::read_to_string(&env_sh).unwrap(), before);
        assert_eq!(fixture.approved_drv().as_deref(), Some("env1.drv"));
    }

    #[tokio::test]
    async fn environment_and_network_changes_are_hot() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.add_run("r1", &["sh"]);
        fixture.approve_current().await;
        fixture.mark_running("r1");

        fixture.set_eval("env2.drv", policy(&["example.com"]));
        let eval = fixture
            .daemon
            .evaluate(&fixture.key, &fixture.owner)
            .await
            .unwrap();
        let applied = fixture.daemon.apply(&fixture.key, &eval).await.unwrap();

        assert_eq!(applied, Applied::Hot);
        assert!(fixture.with_run("r1", |run| run.restart.is_none()));
    }

    /// A policy change the kernel-side profile enforces.
    fn make_out_writable(fixture: &Fixture) {
        let mut writable = policy(&[]);
        writable["fs"]["writable"] = serde_json::json!(["out"]);
        fixture.set_eval("env1.drv", writable);
    }

    #[tokio::test]
    async fn a_busy_agent_is_restarted_only_when_its_turn_ends() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.add_run("r1", &["claude"]);
        fixture.approve_current().await;
        fixture.mark_running("r1");
        fixture.daemon.set_busy("r1", true);

        make_out_writable(&fixture);
        let eval = fixture
            .daemon
            .evaluate(&fixture.key, &fixture.owner)
            .await
            .unwrap();
        let applied = fixture.daemon.apply(&fixture.key, &eval).await.unwrap();

        assert_eq!(applied, Applied::Restart);
        assert!(fixture.with_run("r1", |run| run.restart.is_none()));
        assert!(fixture.with_run("r1", |run| run.restart_when_idle.is_some()));

        // The Stop hook fires.
        fixture.daemon.set_busy("r1", false);

        assert!(fixture.with_run("r1", |run| run.restart.is_some()));
        assert!(fixture.with_run("r1", |run| run.restart_when_idle.is_none()));
    }

    #[tokio::test]
    async fn an_idle_agent_is_restarted_at_once() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.add_run("r1", &["claude"]);
        fixture.approve_current().await;
        fixture.mark_running("r1");

        make_out_writable(&fixture);
        let eval = fixture
            .daemon
            .evaluate(&fixture.key, &fixture.owner)
            .await
            .unwrap();
        let applied = fixture.daemon.apply(&fixture.key, &eval).await.unwrap();

        assert_eq!(applied, Applied::Restart);
        assert!(fixture.with_run("r1", |run| run.restart.is_some()));
    }

    #[tokio::test]
    async fn a_humans_shell_is_never_restarted() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.add_run("r1", &["sh"]);
        fixture.approve_current().await;
        fixture.mark_running("r1");

        make_out_writable(&fixture);
        let eval = fixture
            .daemon
            .evaluate(&fixture.key, &fixture.owner)
            .await
            .unwrap();
        let applied = fixture.daemon.apply(&fixture.key, &eval).await.unwrap();

        // The change needs a new sandbox, but the human decides when to re-enter.
        assert_eq!(applied, Applied::Restart);
        assert!(fixture.with_run("r1", |run| run.restart.is_none()));
        assert!(fixture.with_run("r1", |run| run.restart_when_idle.is_none()));
    }

    #[tokio::test]
    async fn runs_that_have_not_started_are_never_restarted() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.add_run("r1", &["claude"]);
        fixture.approve_current().await;

        make_out_writable(&fixture);
        let eval = fixture
            .daemon
            .evaluate(&fixture.key, &fixture.owner)
            .await
            .unwrap();
        let applied = fixture.daemon.apply(&fixture.key, &eval).await.unwrap();

        assert_eq!(applied, Applied::Hot);
    }

    #[tokio::test]
    async fn approval_remembers_whether_something_is_still_running() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&[]));
        fixture.add_run("r1", &["sh"]);

        fixture.approve_current().await;
        assert!(!fixture.daemon.lock().dirs[&fixture.key].agent_ran);

        // With a live sandbox, later edits may still come from the agent.
        fixture.mark_running("r1");
        fixture.set_eval("env2.drv", policy(&[]));
        fixture.approve_current().await;
        assert!(fixture.daemon.lock().dirs[&fixture.key].agent_ran);
    }

    #[tokio::test]
    async fn the_effective_policy_is_capped_and_shows_the_host_layer() {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&["example.com"]));
        let request = |effective| GetPolicyRequest {
            target: MessageField::some(fixture.target()),
            effective,
            ..Default::default()
        };

        let repo = fixture
            .daemon
            .policy(fixture.uid(), request(false))
            .await
            .unwrap();
        let repo: Value = serde_json::from_str(&repo.policy_json).unwrap();
        assert_eq!(repo, policy(&["example.com"]));

        let effective = fixture
            .daemon
            .policy(fixture.uid(), request(true))
            .await
            .unwrap();
        let effective: Value = serde_json::from_str(&effective.policy_json).unwrap();
        assert_eq!(effective["network"]["allow"], json!(["example.com"]));
        assert_eq!(effective["host"]["fs"]["readonly"], json!([]));
    }

    #[test]
    fn outcomes_use_the_documented_result_names() {
        assert_eq!(Applied::Hot.kind(), "applied");
        assert_eq!(Applied::Restart.kind(), "restart_scheduled");
        assert_eq!(Applied::Restart.outcome().kind, "restart_scheduled");
    }
}
