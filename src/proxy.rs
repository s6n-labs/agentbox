//! Outbound HTTP(S) proxy, built on hyper.
//!
//! The allow-list is enforced here rather than in the sandbox profile, so it can change
//! without restarting the sandbox. Every request is checked, also on reused connections.

use std::convert::Infallible;

use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::TcpStream;

type Body = BoxBody<Bytes, hyper::Error>;

/// The destination of a proxied request: `(host, port)`.
///
/// `CONNECT host:port` for HTTPS tunnels, or an absolute `http://host[:port]/…` URI.
fn destination<B>(request: &Request<B>) -> Option<(String, u16)> {
    let authority = request.uri().authority()?;
    let default_port = if request.method() == Method::CONNECT {
        443
    } else {
        80
    };

    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = authority.port_u16().unwrap_or(default_port);

    Some((host.to_owned(), port))
}

fn reply(status: StatusCode, message: String) -> Response<Body> {
    let body = Full::new(Bytes::from(message)).map_err(|never| match never {});

    let mut response = Response::new(body.boxed());
    *response.status_mut() = status;
    response
}

/// Opens an HTTPS tunnel: after the `200`, bytes flow both ways untouched.
async fn tunnel(request: Request<Incoming>, mut upstream: TcpStream) -> Response<Body> {
    tokio::spawn(async move {
        if let Ok(upgraded) = hyper::upgrade::on(request).await {
            let _ = copy_bidirectional(&mut TokioIo::new(upgraded), &mut upstream).await;
        }
    });

    reply(StatusCode::OK, String::new())
}

/// Forwards one plain HTTP request to its origin server.
async fn forward(mut request: Request<Incoming>, upstream: TcpStream) -> Response<Body> {
    // Origin servers expect `GET /path`, not the absolute URI proxies receive.
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    let Ok(origin_form) = path.parse() else {
        return reply(StatusCode::BAD_REQUEST, "invalid request path\n".into());
    };
    *request.uri_mut() = origin_form;

    let handshake = hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await;
    let Ok((mut sender, connection)) = handshake else {
        return reply(
            StatusCode::BAD_GATEWAY,
            "upstream handshake failed\n".into(),
        );
    };
    tokio::spawn(connection);

    match sender.send_request(request).await {
        Ok(response) => response.map(|body| body.boxed()),
        Err(error) => reply(StatusCode::BAD_GATEWAY, format!("{error}\n")),
    }
}

async fn proxy(request: Request<Incoming>, allowed: impl Fn(&str, u16) -> bool) -> Response<Body> {
    let Some((host, port)) = destination(&request) else {
        let message = "agentbox: this is a proxy; expected CONNECT or an absolute URI\n";
        return reply(StatusCode::BAD_REQUEST, message.into());
    };

    if !allowed(&host, port) {
        let message = format!("agentbox: {host}:{port} is not in network.allow\n");
        return reply(StatusCode::FORBIDDEN, message);
    }

    let Ok(upstream) = TcpStream::connect((host.as_str(), port)).await else {
        let message = format!("agentbox: cannot connect to {host}:{port}\n");
        return reply(StatusCode::BAD_GATEWAY, message);
    };

    if request.method() == Method::CONNECT {
        tunnel(request, upstream).await
    } else {
        forward(request, upstream).await
    }
}

/// Serves one client connection. `allowed` decides per request (and records denials).
pub async fn handle<S, F>(client: S, allowed: F)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(&str, u16) -> bool + Clone + Send + Sync + 'static,
{
    let service = service_fn(move |request| {
        let allowed = allowed.clone();
        async move { Ok::<_, Infallible>(proxy(request, allowed).await) }
    });

    let connection = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(TokioIo::new(client), service)
        .with_upgrades();

    // Clients hanging up is routine.
    let _ = connection.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, uri: &str) -> Request<()> {
        Request::builder().method(method).uri(uri).body(()).unwrap()
    }

    #[test]
    fn destinations() {
        let host_port = |method, uri| destination(&request(method, uri));

        assert_eq!(
            host_port("CONNECT", "github.com:443"),
            Some(("github.com".into(), 443))
        );
        assert_eq!(
            host_port("GET", "http://example.com/a?b"),
            Some(("example.com".into(), 80))
        );
        assert_eq!(
            host_port("GET", "http://example.com:8080/"),
            Some(("example.com".into(), 8080))
        );
        assert_eq!(host_port("CONNECT", "[::1]:443"), Some(("::1".into(), 443)));
        assert_eq!(host_port("GET", "/relative"), None);
    }
}
