//! Health check: a generate_204-style plaintext HTTP GET through the whole
//! path.
//!
//! Deliberately a hand-rolled minimal HTTP/1.1 request instead of pulling in
//! reqwest/hyper: the request is three lines, only the status line is read —
//! the smaller the dependency surface, the steadier the daemon.
//! The health-check URL must be plaintext http:// (enforced at the config
//! layer); no TLS is handled here.

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

        // Read only up to the status line (8 KiB cap in case the peer misbehaves)
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
    };

    let code = match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => bail!("health check timed out ({timeout:?})"),
    }?;
    Ok((code, t0.elapsed()))
}

/// Status-code-only variant (pre-check callers that do not need the timing).
pub async fn http_get_status(
    proxy_addr: SocketAddr,
    url: &str,
    timeout: Duration,
) -> anyhow::Result<u16> {
    Ok(http_get_status_timed(proxy_addr, url, timeout).await?.0)
}

/// 204/2xx counts as healthy.
pub async fn is_healthy(proxy_addr: SocketAddr, url: &str, timeout: Duration) -> bool {
    match http_get_status(proxy_addr, url, timeout).await {
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
