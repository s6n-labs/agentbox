//! Outbound HTTP(S) proxy. The allow-list is enforced here, so it can change without a restart.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;

const MAX_HEADER: usize = 64 * 1024;

/// Parses the request head into (host, port, is_connect).
fn parse_target(head: &str) -> Option<(String, u16, bool)> {
    let mut parts = head.lines().next()?.split_whitespace();
    let (method, target) = (parts.next()?, parts.next()?);
    let (authority, default_port, connect) = if method.eq_ignore_ascii_case("CONNECT") {
        (target, 443, true)
    } else {
        let rest = target.strip_prefix("http://")?;
        (rest.split(['/', '?']).next()?, 80, false)
    };
    let authority = authority.rsplit('@').next()?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => (h, p.parse().ok()?),
        _ => (authority, default_port),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| (host.to_owned(), port, connect))
}

/// Handles one client connection. `allowed` decides (and records denials).
pub async fn handle<S>(mut client: S, allowed: impl Fn(&str, u16) -> bool) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let mut chunk = [0u8; 4096];
        let n = client.read(&mut chunk).await?;
        if n == 0 || buf.len() + n > MAX_HEADER {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let Some((host, port, connect)) = parse_target(&String::from_utf8_lossy(&buf[..head_end])) else {
        return client.write_all(b"HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n").await;
    };
    if !allowed(&host, port) {
        let body = format!("agentbox: {host}:{port} is not in network.allow\n");
        let res = format!("HTTP/1.1 403 Forbidden\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        return client.write_all(res.as_bytes()).await;
    }
    let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)).await else {
        return client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n").await;
    };
    if connect {
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
        upstream.write_all(&buf[head_end..]).await?;
    } else {
        // Plain HTTP: the connection stays pinned to this upstream.
        upstream.write_all(&buf).await?;
    }
    copy_bidirectional(&mut client, &mut upstream).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::parse_target;

    #[test]
    fn targets() {
        assert_eq!(parse_target("CONNECT github.com:443 HTTP/1.1\r\n"), Some(("github.com".into(), 443, true)));
        assert_eq!(parse_target("GET http://example.com/a?b HTTP/1.1\r\n"), Some(("example.com".into(), 80, false)));
        assert_eq!(parse_target("GET http://u:p@example.com:8080/ HTTP/1.1\r\n"), Some(("example.com".into(), 8080, false)));
        assert_eq!(parse_target("CONNECT [::1]:443 HTTP/1.1\r\n"), Some(("::1".into(), 443, true)));
        assert_eq!(parse_target("GET /relative HTTP/1.1\r\n"), None);
    }
}
