//! The approval flow: agents request, humans review and decide.

use std::sync::Arc;

use buffa::MessageField;
use tokio::sync::watch;

use crate::nixcmd::tail;
use crate::proto::*;
use connectrpc::ConnectError;

use super::diff::make_diff;
use super::state::{Outcome, Pending};
use super::{Daemon, not_found, precondition};

/// Waiting side of an agent's request.
pub type Decision = watch::Receiver<Option<Outcome>>;

fn decided(result: String) -> DecideResponse {
    DecideResponse {
        result,
        ..Default::default()
    }
}

fn no_pending() -> ConnectError {
    not_found("no pending request for this workdir")
}

impl Daemon {
    /// An agent asks for re-evaluation of the current files.
    ///
    /// Returns `Err` with the final outcome when no human is needed, otherwise a
    /// channel that yields the human's decision.
    pub async fn agent_reload(
        self: &Arc<Self>,
        run_id: &str,
        reason: String,
    ) -> Result<Decision, Outcome> {
        let run = self
            .lock()
            .runs
            .get(run_id)
            .map(|run| (run.key.clone(), run.owner.clone()));
        let Some((key, owner)) = run else {
            return Err(Outcome::new("eval_error", "this run no longer exists"));
        };

        // Evaluation errors go straight back; a human is never bothered with them.
        let eval = self
            .evaluate(&key, &owner)
            .await
            .map_err(|e| Outcome::new("eval_error", e))?;

        let mut state = self.lock();
        let dir = state.dirs.entry(key).or_default();

        if dir.approved.as_ref().is_some_and(|a| a.same(&eval)) {
            let message =
                "The evaluated environment is identical to the applied one; nothing to approve.";
            return Err(Outcome::new("unchanged", message));
        }

        // Calling again with the same files re-attaches to the same request.
        if let Some(pending) = &dir.pending
            && pending.eval.same(&eval)
        {
            return Ok(pending.outcome.subscribe());
        }

        // At most one pending request per workdir: the newest wins.
        if let Some(old) = dir.pending.take() {
            let superseded = Outcome::new("rejected", "Superseded by a newer reload_env request.");
            let _ = old.outcome.send(Some(superseded));
        }

        let (outcome, decision) = watch::channel(None);
        dir.pending = Some(Pending {
            eval,
            reason,
            outcome,
        });
        Ok(decision)
    }

    /// What `agentbox review` shows.
    pub(super) fn pending(
        &self,
        uid: u32,
        target: &Target,
    ) -> Result<GetPendingResponse, ConnectError> {
        let (key, _) = self.target(uid, target)?;
        let state = self.lock();

        let pending = state.dirs.get(&key).and_then(|dir| {
            let pending = dir.pending.as_ref()?;
            let reason = Some(pending.reason.clone());
            Some(make_diff(dir.approved.as_ref(), &pending.eval, reason))
        });

        let notes = state
            .runs
            .iter()
            .filter(|(_, run)| run.key == key && run.restart_when_idle.is_some())
            .map(|(id, _)| {
                format!("approved, not applied yet: run {id} restarts when the agent's turn ends")
            })
            .collect();

        Ok(GetPendingResponse {
            pending: pending.map(MessageField::some).unwrap_or_default(),
            notes,
            ..Default::default()
        })
    }

    pub(super) async fn decide(
        self: &Arc<Self>,
        uid: u32,
        req: DecideRequest,
    ) -> Result<DecideResponse, ConnectError> {
        let (key, _) = self.target(uid, &req.target)?;

        if !req.accept {
            let pending = self
                .lock()
                .dirs
                .get_mut(&key)
                .and_then(|dir| dir.pending.take())
                .ok_or_else(no_pending)?;

            // The files stay edited after a rejection, so tell the agent to deal with them.
            let message = format!(
                "Rejected by the human: {}\nThe nix files still contain your edits: revert \
                 them, or fix them and call reload_env again.",
                req.reason
            );
            let _ = pending
                .outcome
                .send(Some(Outcome::new("rejected", message)));

            return Ok(decided("rejected".into()));
        }

        // Applied from the copy pinned at request time, so it is exactly what was reviewed.
        let eval = self
            .lock()
            .dirs
            .get(&key)
            .and_then(|dir| dir.pending.as_ref())
            .map(|pending| pending.eval.clone())
            .ok_or_else(no_pending)?;

        match self.apply(&key, &eval).await {
            // `apply` settled the pending request.
            Ok(applied) => Ok(decided(applied.kind().into())),
            Err(error) => {
                let pending = self
                    .lock()
                    .dirs
                    .get_mut(&key)
                    .and_then(|dir| dir.pending.take_if(|p| p.eval.same(&eval)));

                if let Some(pending) = pending {
                    let outcome = Outcome::new("build_error", tail(&error, 40));
                    let _ = pending.outcome.send(Some(outcome));
                }

                Err(precondition(format!(
                    "build failed (reported to the agent):\n{error}"
                )))
            }
        }
    }

    /// Package-level diff between the applied and the requested environment.
    pub(super) async fn closure_diff(
        &self,
        uid: u32,
        target: &Target,
    ) -> Result<ClosureDiffResponse, ConnectError> {
        let (key, owner) = self.target(uid, target)?;

        let drvs = self.lock().dirs.get(&key).and_then(|dir| {
            let old = dir.approved.as_ref()?.drv.clone();
            let new = dir.pending.as_ref()?.eval.drv.clone();
            Some((old, new))
        });
        let (old, new) = drvs.ok_or_else(|| not_found("nothing to compare"))?;

        let text = self
            .nix(&owner)
            .closure_diff(&old, &new)
            .await
            .map_err(precondition)?;
        Ok(ClosureDiffResponse {
            text,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::testing::{Fixture, policy};

    /// A fixture where env1 is applied and one (unstarted) agent run exists.
    async fn applied() -> Fixture {
        let fixture = Fixture::new();
        fixture.set_eval("env1.drv", policy(&["example.com"]));
        fixture.add_run("r1", &["claude"]);
        fixture.approve_current().await;

        fixture
    }

    fn decide_request(fixture: &Fixture, accept: bool, reason: &str) -> DecideRequest {
        DecideRequest {
            target: MessageField::some(fixture.target()),
            accept,
            reason: reason.into(),
            ..Default::default()
        }
    }

    /// The outcome an agent waiting on `decision` has received so far.
    fn outcome(decision: &Decision) -> Option<(String, String)> {
        let outcome = decision.borrow().clone()?;

        Some((outcome.kind, outcome.message))
    }

    #[tokio::test]
    async fn the_same_environment_needs_no_approval() {
        let fixture = applied().await;

        let immediate = fixture
            .daemon
            .agent_reload("r1", "why".into())
            .await
            .unwrap_err();

        assert_eq!(immediate.kind, "unchanged");
    }

    #[tokio::test]
    async fn evaluation_errors_return_without_a_pending_request() {
        let fixture = applied().await;
        fixture.fail_eval("error: undefined variable 'pkgs'");

        let immediate = fixture
            .daemon
            .agent_reload("r1", "why".into())
            .await
            .unwrap_err();

        assert_eq!(immediate.kind, "eval_error");
        assert!(immediate.message.contains("undefined variable"));

        let pending = fixture
            .daemon
            .pending(fixture.uid(), &fixture.target())
            .unwrap();
        assert!(pending.pending.is_unset());
    }

    #[tokio::test]
    async fn an_invalid_policy_is_an_evaluation_error() {
        let fixture = applied().await;
        let mut escaping = policy(&[]);
        escaping["fs"]["writable"] = serde_json::json!(["../outside"]);
        fixture.set_eval("env2.drv", escaping);

        let immediate = fixture
            .daemon
            .agent_reload("r1", "why".into())
            .await
            .unwrap_err();

        assert_eq!(immediate.kind, "eval_error");
        assert!(immediate.message.contains("fs.writable"));
    }

    #[tokio::test]
    async fn an_unknown_run_cannot_request_anything() {
        let fixture = applied().await;

        let immediate = fixture
            .daemon
            .agent_reload("nope", "why".into())
            .await
            .unwrap_err();

        assert_eq!(immediate.kind, "eval_error");
    }

    #[tokio::test]
    async fn a_change_waits_for_a_human_and_is_shown_for_review() {
        let fixture = applied().await;
        fixture.set_eval("env2.drv", policy(&["example.com", "github.com:443"]));

        let decision = fixture
            .daemon
            .agent_reload("r1", "need github".into())
            .await
            .unwrap();
        assert_eq!(outcome(&decision), None);

        let review = fixture
            .daemon
            .pending(fixture.uid(), &fixture.target())
            .unwrap();
        let diff = review.pending.as_option().unwrap();
        assert_eq!(diff.reason.as_deref(), Some("need github"));
        assert_eq!(diff.policy_patch[0].path, "/network/allow/1");
        assert!(diff.derivation_changed);

        // Nothing is applied before the decision.
        assert_eq!(fixture.approved_drv().as_deref(), Some("env1.drv"));
    }

    #[tokio::test]
    async fn calling_again_with_the_same_files_joins_the_same_request() {
        let fixture = applied().await;
        fixture.set_eval("env2.drv", policy(&["example.com"]));

        let first = fixture
            .daemon
            .agent_reload("r1", "first".into())
            .await
            .unwrap();
        let again = fixture
            .daemon
            .agent_reload("r1", "again".into())
            .await
            .unwrap();

        let request = decide_request(&fixture, false, "no");
        fixture.daemon.decide(fixture.uid(), request).await.unwrap();

        // Both callers get the one decision; the original reason was kept.
        assert_eq!(outcome(&first).unwrap().0, "rejected");
        assert_eq!(outcome(&again).unwrap().0, "rejected");
    }

    #[tokio::test]
    async fn a_newer_request_replaces_the_pending_one() {
        let fixture = applied().await;

        fixture.set_eval("env2.drv", policy(&["example.com"]));
        let old = fixture
            .daemon
            .agent_reload("r1", "old".into())
            .await
            .unwrap();

        fixture.set_eval("env3.drv", policy(&["example.com"]));
        let new = fixture
            .daemon
            .agent_reload("r1", "new".into())
            .await
            .unwrap();

        let (kind, message) = outcome(&old).unwrap();
        assert_eq!(kind, "rejected");
        assert!(message.contains("Superseded"));
        assert_eq!(outcome(&new), None);

        let review = fixture
            .daemon
            .pending(fixture.uid(), &fixture.target())
            .unwrap();
        assert_eq!(
            review.pending.as_option().unwrap().reason.as_deref(),
            Some("new")
        );
    }

    #[tokio::test]
    async fn rejecting_returns_the_reason_and_applies_nothing() {
        let fixture = applied().await;
        fixture.set_eval("env2.drv", policy(&["example.com"]));
        let decision = fixture
            .daemon
            .agent_reload("r1", "why".into())
            .await
            .unwrap();

        let request = decide_request(&fixture, false, "not needed");
        let response = fixture.daemon.decide(fixture.uid(), request).await.unwrap();

        assert_eq!(response.result, "rejected");
        let (kind, message) = outcome(&decision).unwrap();
        assert_eq!(kind, "rejected");
        assert!(message.contains("not needed"));
        assert!(
            message.contains("revert"),
            "the agent must be told its edits remain"
        );

        assert_eq!(fixture.approved_drv().as_deref(), Some("env1.drv"));
        let review = fixture
            .daemon
            .pending(fixture.uid(), &fixture.target())
            .unwrap();
        assert!(review.pending.is_unset());
    }

    #[tokio::test]
    async fn accepting_applies_and_tells_the_agent() {
        let fixture = applied().await;
        fixture.set_eval("env2.drv", policy(&["example.com"]));
        let decision = fixture
            .daemon
            .agent_reload("r1", "why".into())
            .await
            .unwrap();

        let request = decide_request(&fixture, true, "");
        let response = fixture.daemon.decide(fixture.uid(), request).await.unwrap();

        assert_eq!(response.result, "applied");
        assert_eq!(outcome(&decision).unwrap().0, "applied");
        assert_eq!(fixture.approved_drv().as_deref(), Some("env2.drv"));
    }

    #[tokio::test]
    async fn a_failed_build_is_reported_and_changes_nothing() {
        let fixture = applied().await;
        fixture.set_eval("env2.drv", policy(&["example.com"]));
        let decision = fixture
            .daemon
            .agent_reload("r1", "why".into())
            .await
            .unwrap();
        fixture.fail_build("error: builder for 'env2.drv' failed");

        let request = decide_request(&fixture, true, "");
        let error = fixture
            .daemon
            .decide(fixture.uid(), request)
            .await
            .unwrap_err();

        assert!(error.message.unwrap().contains("builder for"));
        let (kind, message) = outcome(&decision).unwrap();
        assert_eq!(kind, "build_error");
        assert!(message.contains("builder for"));

        assert_eq!(fixture.approved_drv().as_deref(), Some("env1.drv"));
        let review = fixture
            .daemon
            .pending(fixture.uid(), &fixture.target())
            .unwrap();
        assert!(review.pending.is_unset());
    }

    #[tokio::test]
    async fn deciding_without_a_request_is_an_error() {
        let fixture = applied().await;

        for accept in [true, false] {
            let request = decide_request(&fixture, accept, "");
            let error = fixture
                .daemon
                .decide(fixture.uid(), request)
                .await
                .unwrap_err();

            assert_eq!(error.code, connectrpc::ErrorCode::NotFound);
        }
    }

    #[tokio::test]
    async fn a_human_reload_settles_the_request_it_satisfies() {
        let fixture = applied().await;
        fixture.set_eval("env2.drv", policy(&["example.com"]));
        let decision = fixture
            .daemon
            .agent_reload("r1", "why".into())
            .await
            .unwrap();

        // The human runs `agentbox reload` instead of accepting.
        fixture.approve_current().await;

        assert_eq!(outcome(&decision).unwrap().0, "applied");
        let review = fixture
            .daemon
            .pending(fixture.uid(), &fixture.target())
            .unwrap();
        assert!(review.pending.is_unset());
    }

    #[tokio::test]
    async fn other_users_cannot_review_or_decide() {
        let fixture = applied().await;
        fixture.set_eval("env2.drv", policy(&["example.com"]));
        let _decision = fixture
            .daemon
            .agent_reload("r1", "why".into())
            .await
            .unwrap();
        let stranger = fixture.uid() + 1;

        let review = fixture.daemon.pending(stranger, &fixture.target());
        assert_eq!(
            review.unwrap_err().code,
            connectrpc::ErrorCode::PermissionDenied
        );

        let request = decide_request(&fixture, true, "");
        let decided = fixture.daemon.decide(stranger, request).await;
        assert_eq!(
            decided.unwrap_err().code,
            connectrpc::ErrorCode::PermissionDenied
        );

        assert_eq!(fixture.approved_drv().as_deref(), Some("env1.drv"));
    }
}
