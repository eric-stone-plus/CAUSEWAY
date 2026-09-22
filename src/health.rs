//! Health check: a generate_204-style plaintext HTTP GET through the whole
//! path, or a CONNECT-tunnel reachability probe for services whose own HTTP
//! semantics say nothing about reachability.
//!
//! Deliberately a hand-rolled minimal HTTP/1.1 request instead of pulling in
//! reqwest/hyper: the request is three lines, only the status line is read —
//! the smaller the dependency surface, the steadier the daemon.
//! A GET target must be plaintext http:// and a CONNECT target
//! `connect://host[:port]` (default 443); both are enforced at the config
//! layer. No TLS is handled here.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Extract the Host header value and the request target (absolute form) from
/// `http://host[:port]/path`.
fn split_url(url: &str) -> anyhow::Result<(String, &str)> {
    let rest = url
        .strip_prefix("http://")
        .context("health check URL must be plaintext http://")?;
    let split = rest.find(['/', '?']);
    let (authority, path) = match split {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], &rest[i..]),
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty()
        || authority.contains('@')
        || url.contains('#')
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("invalid health check URL");
    }
    Ok((authority.to_string(), path))
}

/// Normalize `connect://host[:port]` into a CONNECT authority, defaulting
/// the port to 443. An authority only — no path, query, fragment, or
/// userinfo.
fn split_connect_target(url: &str) -> anyhow::Result<String> {
    let rest = url
        .strip_prefix("connect://")
        .context("connect target must start with connect://")?;
    if rest.is_empty()
        || rest.contains(['/', '?', '#', '@'])
        || rest.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("invalid connect target");
    }
    if let Some((host, port)) = rest.rsplit_once(':') {
        let port: u16 = port
            .parse()
            .context("connect target port must be numeric")?;
        anyhow::ensure!(port != 0, "connect target port must be nonzero");
        anyhow::ensure!(
            !host.is_empty(),
            "connect target must name a host, not just a port"
        );
        anyhow::ensure!(
            !host.contains(':'),
            "connect target must be host:port (or a bare host); extra colons are rejected"
        );
    }
    Ok(if rest.contains(':') {
        rest.to_string()
    } else {
        format!("{rest}:443")
    })
}

/// Read one CRLF-terminated status line from the stream (8 KiB cap in case
/// the peer misbehaves) and return the HTTP status code.
async fn read_status_line(stream: &mut tokio::net::TcpStream) -> anyhow::Result<u16> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .context("read health check response")?;
        if n == 0 {
            bail!("peer closed the connection before the status line");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            buf.truncate(pos);
            break;
        }
        if buf.len() > 8192 {
            bail!("status line too long (>8KiB), treating as abnormal");
        }
    }

    let line = String::from_utf8_lossy(&buf);
    let mut parts = line.split_whitespace();
    let _version = parts
        .next()
        .context("status line missing protocol version")?;
    let code: u16 = parts
        .next()
        .context("status line missing status code")?
        .parse()
        .context("status code is not a number")?;
    Ok(code)
}

/// Issue an absolute-form GET via the proxy entry point `proxy_addr` and
/// return the HTTP status code plus the time to the status line (the
/// end-to-end RTT as observed on this path).
///
/// `proxy_addr` may be either CAUSEWAY's own listen port (full-path check) or
/// a data-plane http local port (pre-switch candidate path pre-check).
pub async fn http_get_status_timed(
    proxy_addr: SocketAddr,
    url: &str,
    timeout: Duration,
) -> anyhow::Result<(u16, Duration)> {
    let (host, _path) = split_url(url)?;
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: causeway-health/0.1\r\nConnection: close\r\n\r\n"
    );

    let t0 = std::time::Instant::now();
    let fut = async {
        let mut stream = tokio::net::TcpStream::connect(proxy_addr)
            .await
            .with_context(|| format!("connect health check entry {proxy_addr}"))?;
        stream
            .write_all(request.as_bytes())
            .await
            .context("send health check request")?;
        read_status_line(&mut stream).await
    };
    let code = match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => bail!("health check timed out ({timeout:?})"),
    }?;
    Ok((code, t0.elapsed()))
}



/// Open an HTTP CONNECT tunnel to `connect://host[:port]` through the proxy
/// entry point and return the tunnel reply's status code (2xx = the
/// egress accepted the tunnel). For services whose API edge redirects
/// plaintext HTTP (so a GET would never read 2xx), an accepted CONNECT is
/// the reachability fact we want — with the documented caveat that it
/// proves the egress's acceptance, not the origin's answer.
pub async fn connect_status_timed(
    proxy_addr: SocketAddr,
    url: &str,
    timeout: Duration,
) -> anyhow::Result<(u16, Duration)> {
    let authority = split_connect_target(url)?;
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: causeway-health/0.1\r\n\r\n"
    );

    let t0 = std::time::Instant::now();
    let fut = async {
        let mut stream = tokio::net::TcpStream::connect(proxy_addr)
            .await
            .with_context(|| format!("connect health check entry {proxy_addr}"))?;
        stream
            .write_all(request.as_bytes())
            .await
            .context("send CONNECT health check request")?;
        read_status_line(&mut stream).await
    };
    let code = match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => bail!("health check timed out ({timeout:?})"),
    }?;
    Ok((code, t0.elapsed()))
}

/// The effective health check for a configured target: GET for `http://`
/// URLs, CONNECT reachability for `connect://` authorities. Returns the
/// status code; 2xx counts as healthy in both forms.
pub async fn check_status_timed(
    proxy_addr: SocketAddr,
    url: &str,
    timeout: Duration,
) -> anyhow::Result<(u16, Duration)> {
    if url.starts_with("connect://") {
        connect_status_timed(proxy_addr, url, timeout).await
    } else {
        http_get_status_timed(proxy_addr, url, timeout).await
    }
}

/// Status-code-only variant of [`check_status_timed`].
pub async fn check_status(
    proxy_addr: SocketAddr,
    url: &str,
    timeout: Duration,
) -> anyhow::Result<u16> {
    Ok(check_status_timed(proxy_addr, url, timeout).await?.0)
}

/// Validate a health target of either form; used by the config layer so a
/// bad target refuses startup instead of failing every check at runtime.
pub fn valid_target(url: &str) -> bool {
    if url.starts_with("connect://") {
        split_connect_target(url).is_ok()
    } else {
        split_url(url).is_ok()
    }
}

/// 2xx counts as healthy.
pub async fn is_healthy(proxy_addr: SocketAddr, url: &str, timeout: Duration) -> bool {
    match check_status(proxy_addr, url, timeout).await {
        Ok(code) => (200..300).contains(&code),
        Err(e) => {
            // `proxy_addr` is an ephemeral implementation detail, and a
            // nested adapter error may contain a provider endpoint. Keep the
            // routine health log deliberately opaque; lifecycle logs and the
            // node-scoped event stream carry the actionable attribution.
            tracing::debug!(error = %e, "health check failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_targets_normalize_and_reject_garbage() {
        assert_eq!(
            split_connect_target("connect://api.example:443").unwrap(),
            "api.example:443"
        );
        assert_eq!(
            split_connect_target("connect://api.example").unwrap(),
            "api.example:443",
            "port defaults to 443"
        );
        for bad in [
            "connect://",
            "connect:///path",
            "connect://host:0x10",
            "connect://host:99999",
            "connect://host:0",
            "connect://:443",
            "connect://user@host",
            "connect://ho st",
            "connect://host:443:443",
        ] {
            assert!(split_connect_target(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn valid_target_accepts_both_forms_and_rejects_others() {
        assert!(valid_target("http://www.gstatic.com/generate_204"));
        assert!(valid_target("connect://api.example:443"));
        assert!(!valid_target("https://www.gstatic.com/generate_204"));
        assert!(!valid_target("ftp://example/"));
        assert!(!valid_target("connect://api.example/path"));
    }

    /// A loopback fake proxy proves the CONNECT probe's wire shape: 2xx
    /// establishes the tunnel, anything else (or a closed socket) is
    /// failure. Network-touching tests may only use 127.0.0.1.
    #[tokio::test]
    async fn connect_probe_reads_the_tunnel_reply_status() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn spawn_reply(status: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 512];
                let n = sock.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                assert!(
                    request.starts_with("CONNECT api.example:443 HTTP/1.1\r\n"),
                    "wire shape: {request}"
                );
                assert!(request.contains("Host: api.example:443\r\n"));
                sock.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
            });
            (addr, handle)
        }

        let (ok_addr, ok_task) = spawn_reply("200 Connection established").await;
        let (code, _) = connect_status_timed(
            ok_addr,
            "connect://api.example:443",
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(code, 200);
        ok_task.await.unwrap();

        let (deny_addr, deny_task) = spawn_reply("403 Forbidden").await;
        let (code, _) = connect_status_timed(
            deny_addr,
            "connect://api.example",
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(code, 403, "the port default reaches the same target");
        deny_task.await.unwrap();

        // check_status dispatches by scheme: the connect:// form routes to
        // the CONNECT probe.
        let (addr, task) = spawn_reply("204 No Content").await;
        let code = check_status(addr, "connect://api.example:443", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(code, 204);
        task.await.unwrap();
    }
}
