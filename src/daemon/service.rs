//! `agentbox.v1.DaemonService`: the generated trait, implemented by delegating to [`Daemon`].
//!
//! Every method first identifies the peer from the socket credentials; the daemon
//! methods then check that the peer owns what the request is about.

use std::sync::Arc;

use connectrpc::{ConnectError, RequestContext, Response, Router, ServiceRequest, ServiceResult};

use crate::proto::*;
use crate::rpc::PeerUid;

use super::Daemon;

struct Service {
    daemon: Arc<Daemon>,
}

/// Builds the Connect router serving the daemon's API.
pub fn router(daemon: Arc<Daemon>) -> Router {
    Arc::new(Service { daemon }).register(Router::new())
}

fn peer(ctx: &RequestContext) -> Result<u32, ConnectError> {
    PeerUid::of(ctx).ok_or_else(|| ConnectError::unauthenticated("no peer credentials"))
}

// Naming the concrete response types (as the SDK's own examples do) refines the
// generated `impl Encodable<_>` signatures.
#[allow(refining_impl_trait)]
impl DaemonService for Service {
    async fn create_run(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateRunRequest>,
    ) -> ServiceResult<CreateRunResponse> {
        let uid = peer(&ctx)?;
        let response = self
            .daemon
            .create_run(uid, request.to_owned_message())
            .await?;

        Response::ok(response)
    }

    async fn wait_run(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, WaitRunRequest>,
    ) -> ServiceResult<WaitRunResponse> {
        let uid = peer(&ctx)?;
        let response = self
            .daemon
            .wait_run(uid, request.to_owned_message())
            .await?;

        Response::ok(response)
    }

    async fn signal_run(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SignalRunRequest>,
    ) -> ServiceResult<SignalRunResponse> {
        let uid = peer(&ctx)?;
        let response = self.daemon.signal_run(uid, request.to_owned_message())?;

        Response::ok(response)
    }

    async fn reload(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReloadRequest>,
    ) -> ServiceResult<ReloadResponse> {
        let uid = peer(&ctx)?;
        let response = self.daemon.reload(uid, request.to_owned_message()).await?;

        Response::ok(response)
    }

    async fn get_pending(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetPendingRequest>,
    ) -> ServiceResult<GetPendingResponse> {
        let uid = peer(&ctx)?;
        let request = request.to_owned_message();
        let response = self.daemon.pending(uid, &request.target)?;

        Response::ok(response)
    }

    async fn decide(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DecideRequest>,
    ) -> ServiceResult<DecideResponse> {
        let uid = peer(&ctx)?;
        let response = self.daemon.decide(uid, request.to_owned_message()).await?;

        Response::ok(response)
    }

    async fn closure_diff(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ClosureDiffRequest>,
    ) -> ServiceResult<ClosureDiffResponse> {
        let uid = peer(&ctx)?;
        let request = request.to_owned_message();
        let response = self.daemon.closure_diff(uid, &request.target).await?;

        Response::ok(response)
    }

    async fn get_policy(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetPolicyRequest>,
    ) -> ServiceResult<GetPolicyResponse> {
        let uid = peer(&ctx)?;
        let response = self.daemon.policy(uid, request.to_owned_message()).await?;

        Response::ok(response)
    }

    async fn explain(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ExplainRequest>,
    ) -> ServiceResult<ExplainResponse> {
        let uid = peer(&ctx)?;
        let response = self.daemon.explain(uid, request.to_owned_message()).await?;

        Response::ok(response)
    }

    async fn list_denials(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListDenialsRequest>,
    ) -> ServiceResult<ListDenialsResponse> {
        let uid = peer(&ctx)?;
        let request = request.to_owned_message();
        let response = self.daemon.denials(uid, &request.target)?;

        Response::ok(response)
    }
}
