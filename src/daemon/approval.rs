//! The approval flow: agents request, humans review and decide.

use std::sync::Arc;

use tokio::sync::watch;

use crate::nixcmd::{self, tail};
use crate::proto::*;
use crate::rpc::RpcError;

use super::diff::make_diff;
use super::state::{Outcome, Pending};
use super::{Daemon, not_found, precondition};

/// Waiting side of an agent's request.
pub type Decision = watch::Receiver<Option<Outcome>>;

fn no_pending() -> RpcError {
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
    pub(super) fn pending(&self, uid: u32, target: &Target) -> Result<PendingRes, RpcError> {
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

        Ok(PendingRes { pending, notes })
    }

    pub(super) async fn decide(
        self: &Arc<Self>,
        uid: u32,
        req: DecideReq,
    ) -> Result<TextRes, RpcError> {
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

            return Ok(TextRes {
                text: "rejected".into(),
            });
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
            Ok(applied) => Ok(TextRes {
                text: applied.kind().into(),
            }),
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
    ) -> Result<TextRes, RpcError> {
        let (key, owner) = self.target(uid, target)?;

        let drvs = self.lock().dirs.get(&key).and_then(|dir| {
            let old = dir.approved.as_ref()?.drv.clone();
            let new = dir.pending.as_ref()?.eval.drv.clone();
            Some((old, new))
        });
        let (old, new) = drvs.ok_or_else(|| not_found("nothing to compare"))?;

        let text = nixcmd::closure_diff(&self.cfg, &owner, &old, &new)
            .await
            .map_err(precondition)?;
        Ok(TextRes { text })
    }
}
