//! Connect protocol (unary, JSON codec) over a Unix socket.
// ponytail: hand-rolled unary Connect-JSON; switch to .proto + connectrpc codegen
// when a second client or streaming is needed. The wire format stays compatible.

use std::convert::Infallible;
use std::future::Future;
use std::path::Path;

use anyhow::{Context, bail};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use tokio::net::{UnixListener, UnixStream};

const PREFIX: &str = "/agentbox.v1.Daemon/";

#[derive(Debug)]
pub struct RpcError {
    /// Connect error code, e.g. `not_found`.
    pub code: &'static str,
    pub message: String,
}

impl RpcError {
    pub fn new(code: &'static str, message: impl ToString) -> Self {
        Self { code, message: message.to_string() }
    }

    fn http_status(&self) -> u16 {
        match self.code {
            "invalid_argument" | "failed_precondition" => 400,
            "permission_denied" => 403,
            "not_found" | "unimplemented" => 404,
            _ => 500,
        }
    }
}

/// Serves until the listener fails. The handler gets the peer uid, method name and JSON body.
pub async fn serve<H, F>(listener: UnixListener, handler: H)
where
    H: Fn(u32, String, Bytes) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<Vec<u8>, RpcError>> + Send + 'static,
{
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let Ok(uid) = stream.peer_cred().map(|c| c.uid()) else { continue };
        let handler = handler.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let handler = handler.clone();
                async move {
                    let method = req.uri().path().strip_prefix(PREFIX).unwrap_or("").to_string();
                    let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                    let (status, bytes) = match handler(uid, method, body).await {
                        Ok(b) => (200, b),
                        Err(e) => (e.http_status(), json!({"code": e.code, "message": e.message}).to_string().into_bytes()),
                    };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(bytes)))
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}

pub async fn call<Q: Serialize, R: DeserializeOwned>(socket: &Path, method: &str, req: &Q) -> anyhow::Result<R> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to the agentbox daemon at {} (is `agentbox daemon` running?)", socket.display()))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(conn);
    let req = Request::post(format!("{PREFIX}{method}"))
        .header("host", "agentbox")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(req)?)))?;
    let res = sender.send_request(req).await?;
    let ok = res.status().is_success();
    let body = res.into_body().collect().await?.to_bytes();
    if !ok {
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        bail!("{}", v["message"].as_str().unwrap_or("daemon returned an error"));
    }
    Ok(serde_json::from_slice(&body)?)
}
