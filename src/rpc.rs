//! Connect RPC transport: the generated service and client, carried over a Unix socket.

use std::path::Path;

use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};
use connectrpc::{ConnectRpcService, RequestContext, Router};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use tokio::net::UnixListener;
use tower::ServiceExt;

use crate::proto::DaemonServiceClient;

/// The authority is never resolved; the socket path decides where requests go.
const AUTHORITY: &str = "http://localhost";

/// Requests queued while the connection is busy.
const CLIENT_BUFFER: usize = 16;

pub type DaemonClient = DaemonServiceClient<SharedHttp2Connection>;

/// uid of the process on the other end of the socket, taken from its credentials.
///
/// The server puts it into every request's extensions; it is how requests are authorized.
#[derive(Clone, Copy, Debug)]
pub struct PeerUid(pub u32);

impl PeerUid {
    pub fn of(ctx: &RequestContext) -> Option<u32> {
        ctx.extensions().get::<PeerUid>().map(|peer| peer.0)
    }
}

/// Serves the router on a Unix socket until the listener fails.
pub async fn serve(listener: UnixListener, router: Router) {
    let service = ConnectRpcService::new(router);

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(credentials) = stream.peer_cred() else {
            continue;
        };
        let peer = PeerUid(credentials.uid());

        let service = service
            .clone()
            .map_request(move |mut request: http::Request<Incoming>| {
                request.extensions_mut().insert(peer);
                request
            });

        tokio::spawn(async move {
            let server = auto::Builder::new(TokioExecutor::new());
            let service = TowerToHyperService::new(service);

            // The peer hanging up mid-request is not worth reporting.
            let _ = server.serve_connection(TokioIo::new(stream), service).await;
        });
    }
}

/// A client for the daemon listening on `socket`. Connects on first use.
///
/// Must be called from within a Tokio runtime.
pub fn client(socket: &Path) -> DaemonClient {
    let authority: http::Uri = AUTHORITY.parse().expect("static URI");
    let connection = Http2Connection::lazy_unix(socket, authority.clone()).shared(CLIENT_BUFFER);

    DaemonServiceClient::new(connection, ClientConfig::new(authority))
}
