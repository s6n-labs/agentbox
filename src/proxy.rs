//! Outbound HTTP(S) proxy, built on hyper.
//!
//! The allow-list is enforced here rather than in the sandbox profile, so it can change
//! without restarting the sandbox. Every request is checked, also on reused connections.

use std::convert::Infallible;

use http::header::{CONNECTION, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::TcpStream;

type Body = BoxBody<Bytes, hyper::Error>;

/// Headers that describe one connection and must not be passed through a proxy.
const HOP_BY_HOP: &[&str] = &["connection", "keep-alive", "proxy-connection"];

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

    // Connection handling is per hop: each request gets its own upstream connection,
    // while the client may keep its connection to us open.
    for header in HOP_BY_HOP {
        request.headers_mut().remove(*header);
    }
    request
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));

    match sender.send_request(request).await {
        Ok(mut response) => {
            for header in HOP_BY_HOP {
                response.headers_mut().remove(*header);
            }

            response.map(|body| body.boxed())
        }
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

    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::TcpListener;

    /// Destinations the proxy was asked about, in order.
    type Asked = Arc<Mutex<Vec<String>>>;

    /// Starts a proxy that allows only the given port, and returns the client's end.
    fn proxy_allowing(port: u16) -> (DuplexStream, Asked) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let asked = Asked::default();

        let record = asked.clone();
        let allowed = move |host: &str, requested: u16| {
            record.lock().unwrap().push(format!("{host}:{requested}"));
            requested == port
        };
        tokio::spawn(handle(server, allowed));

        (client, asked)
    }

    /// An origin server answering one request with `body`; yields the request it saw.
    async fn origin(body: &'static str) -> (u16, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let seen = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();

            String::from_utf8(request).unwrap()
        });

        (port, seen)
    }

    /// Sends one request and reads the whole response.
    async fn exchange(mut client: DuplexStream, request: String) -> String {
        client.write_all(request.as_bytes()).await.unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn plain_http_is_forwarded_in_origin_form() {
        let (port, seen) = origin("hello").await;
        let (client, asked) = proxy_allowing(port);

        let request = format!(
            "GET http://127.0.0.1:{port}/path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Connection: keep-alive\r\nConnection: close\r\n\r\n"
        );
        let response = exchange(client, request).await;

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.ends_with("hello"), "{response}");

        // The origin gets a normal request line, not the proxy form.
        let seen = seen.await.unwrap();
        assert!(seen.starts_with("GET /path?q=1 HTTP/1.1\r\n"), "{seen}");
        assert!(!seen.to_lowercase().contains("proxy-connection"), "{seen}");
        assert_eq!(*asked.lock().unwrap(), [format!("127.0.0.1:{port}")]);
    }

    #[tokio::test]
    async fn denied_destinations_get_403_and_are_never_contacted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (client, asked) = proxy_allowing(0);

        let request = format!(
            "GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        );
        let response = exchange(client, request).await;

        assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
        assert!(response.contains("is not in network.allow"), "{response}");
        assert_eq!(asked.lock().unwrap().len(), 1);

        // Nothing connected to the origin.
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept());
        assert!(accepted.await.is_err());
    }

    #[tokio::test]
    async fn connect_opens_a_transparent_tunnel() {
        // An echo server stands in for a TLS endpoint: the proxy must not look inside.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        let (mut client, _asked) = proxy_allowing(port);

        let request =
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();

        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(client.read_u8().await.unwrap());
        }
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&head)
        );

        client.write_all(b"\x16\x03\x01 not http").await.unwrap();
        let mut echoed = [0u8; 12];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"\x16\x03\x01 not http");
    }

    #[tokio::test]
    async fn connect_to_a_denied_destination_is_refused() {
        let (client, asked) = proxy_allowing(0);

        let request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n";
        let response = exchange(client, request.to_owned()).await;

        assert!(response.starts_with("HTTP/1.1 403 Forbidden"), "{response}");
        assert_eq!(*asked.lock().unwrap(), ["example.com:443"]);
    }

    #[tokio::test]
    async fn every_request_on_a_connection_is_checked() {
        let (port, _seen) = origin("first").await;
        let (mut client, asked) = proxy_allowing(port);

        // Allowed request, then a second one to another destination on the same connection.
        let allowed = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: a\r\n\r\n");
        client.write_all(allowed.as_bytes()).await.unwrap();
        let denied = "GET http://example.org/ HTTP/1.1\r\nHost: b\r\nConnection: close\r\n\r\n";
        client.write_all(denied.as_bytes()).await.unwrap();

        let mut responses = String::new();
        client.read_to_string(&mut responses).await.unwrap();

        assert!(responses.starts_with("HTTP/1.1 200 OK"), "{responses}");
        assert!(responses.contains("HTTP/1.1 403 Forbidden"), "{responses}");
        assert_eq!(
            *asked.lock().unwrap(),
            [format!("127.0.0.1:{port}"), "example.org:80".to_string()]
        );
    }

    #[tokio::test]
    async fn requests_that_are_not_proxy_requests_are_rejected() {
        let (client, asked) = proxy_allowing(80);

        let request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let response = exchange(client, request.to_owned()).await;

        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "{response}"
        );
        assert!(asked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_origin_is_a_bad_gateway() {
        // Bind and drop to get a port nothing listens on.
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let (client, _asked) = proxy_allowing(port);

        let request = format!(
            "GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        );
        let response = exchange(client, request).await;

        assert!(
            response.starts_with("HTTP/1.1 502 Bad Gateway"),
            "{response}"
        );
    }
}
