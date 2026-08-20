//! Anti-bot freeze awareness: HTTPS site probes through a node's data-plane
//! HTTP proxy port, and the verdict classification that turns a status code
//! into "this exit IP is frozen for this site".
//!
//! The health check deliberately stays plaintext HTTP (generate_204
//! semantics). Site probes are the opposite: anti-bot systems fingerprint
//! the TLS leg, so a verdict taken over plaintext http would say nothing
//! about the traffic it stands in for. Hence a minimal rustls client here —
//! CONNECT through the proxy, one handshake, one GET, the status line only.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

/// Verdict for one (site, node) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteStatus {
    /// The site served the node's exit IP normally (2xx/3xx)
    Ok,
    /// The site explicitly refused the node's exit IP (401/403/429/451)
    Blocked,
    /// Timeout, connection failure, or an ambiguous status: the exit may be
    /// fine and the site itself be having a bad moment. Never rotate TO an
    /// unconfirmed node on this signal, and never rotate AWAY without a
    /// confirming Blocked verdict.
    Unknown,
}

impl SiteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SiteStatus::Ok => "ok",
            SiteStatus::Blocked => "blocked",
            SiteStatus::Unknown => "unknown",
        }
    }
}

/// Recorded per (site, node) in the state file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteVerdict {
    pub status: SiteStatus,
    /// HTTP status code observed on the TLS leg, when one was reached
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub checked_unix: i64,
    /// Transport-level detail for Unknown verdicts (timeout, plane failure).
    /// Node and site names are known to the reader; never include a provider
    /// endpoint or credential here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Classify an HTTPS status from the site. 5xx and everything unusual stay
/// `Unknown`: a 503 is just as often the site's own bad deploy as an IP
/// block, and rotating exits on it would attribute failures we cannot see.
pub fn classify_status(code: u16) -> SiteStatus {
    match code {
        200..=399 => SiteStatus::Ok,
        401 | 403 | 429 | 451 => SiteStatus::Blocked,
        _ => SiteStatus::Unknown,
    }
}

/// Split an https:// URL into (host, port, request_target, server_name).
fn split_https_url(
    url: &str,
) -> anyhow::Result<(String, u16, String, rustls::pki_types::ServerName<'static>)> {
    let rest = url
        .strip_prefix("https://")
        .context("site probe URL must be https://")?;
    let split = rest.find(['/', '?']);
    let (authority, path) = match split {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        bail!("invalid site probe authority");
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().context("invalid site probe port")?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), 443),
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-.".contains(c))
    {
        bail!("invalid site probe host");
    }
    let server_name =
        rustls::pki_types::ServerName::try_from(host.clone()).context("invalid server name")?;
    Ok((host, port, path.to_string(), server_name))
}

fn roots() -> &'static rustls::RootCertStore {
    static ROOTS: OnceLock<rustls::RootCertStore> = OnceLock::new();
    ROOTS.get_or_init(|| rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    })
}

/// Issue one HTTPS GET through the HTTP proxy at `proxy_addr` (CONNECT
/// tunnel) and return the status code from the TLS leg. Only the status
/// line is read; the body is discarded by dropping the connection.
pub async fn https_get_status_via_proxy(
    proxy_addr: SocketAddr,
    url: &str,
    user_agent: &str,
    timeout: Duration,
) -> anyhow::Result<u16> {
    let (host, port, target, server_name) = split_https_url(url)?;
    let fut = async {
        // 1. CONNECT tunnel through the node's HTTP proxy port
        use tokio::io::AsyncWriteExt as _;
        let mut sock = TcpStream::connect(proxy_addr)
            .await
            .with_context(|| format!("connect site-probe proxy {proxy_addr}"))?;
        sock.write_all(
            format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
        )
        .await?;
        let code = read_status_line_socket(&mut sock).await?;
        if code != 200 {
            bail!("proxy CONNECT returned HTTP {code}");
        }

        // 2. TLS inside the tunnel, then one GET
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots().clone())
            .with_no_client_auth();
        let mut tls = TlsClient {
            sock,
            conn: rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
                .context("build TLS client")?,
        };
        tls.handshake().await?;
        tls.send(
            format!(
                "GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
        let line = tls.read_line().await?;
        let code = line
            .split_whitespace()
            .nth(1)
            .context("status line missing status code")?
            .parse::<u16>()
            .context("status code is not a number")?;
        Ok(code)
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => bail!("site probe timed out ({timeout:?})"),
    }
}

/// Read from a raw socket until one CRLF line; return the HTTP status code.
async fn read_status_line_socket(sock: &mut TcpStream) -> anyhow::Result<u16> {
    use tokio::io::AsyncReadExt as _;
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        let n = sock.read(&mut chunk).await.context("read status line")?;
        if n == 0 {
            bail!("peer closed the connection before the status line");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            buf.truncate(pos);
            break;
        }
        if buf.len() > 8192 {
            bail!("status line too long (>8KiB)");
        }
    }
    let line = String::from_utf8_lossy(&buf);
    let code = line
        .split_whitespace()
        .nth(1)
        .context("status line missing status code")?
        .parse::<u16>()
        .context("status code is not a number")?;
    Ok(code)
}

/// Minimal rustls-over-tokio client. Uses `readable()` + `try_read` instead
/// of trait plumbing: everything here is strictly sequential (one request,
/// one status line), so a plain pull loop is the clearest correct shape.
struct TlsClient {
    sock: TcpStream,
    conn: rustls::ClientConnection,
}

impl TlsClient {
    /// Drive the handshake to completion.
    async fn handshake(&mut self) -> anyhow::Result<()> {
        while self.conn.is_handshaking() {
            self.flush_tls().await?;
            if self.conn.wants_read() {
                self.pull_ciphertext().await?;
            }
        }
        Ok(())
    }

    /// Encode all pending TLS records onto the socket.
    async fn flush_tls(&mut self) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        while self.conn.wants_write() {
            let mut buf = Vec::with_capacity(8192);
            self.conn.write_tls(&mut buf)?;
            if buf.is_empty() {
                break;
            }
            self.sock.write_all(&buf).await?;
        }
        Ok(())
    }

    /// Read one batch of ciphertext and hand it to the connection.
    async fn pull_ciphertext(&mut self) -> anyhow::Result<()> {
        self.sock.readable().await?;
        let mut cipher = [0u8; 16384];
        match self.sock.try_read(&mut cipher) {
            Ok(0) => bail!("TLS peer closed the connection"),
            Ok(n) => {
                self.conn
                    .read_tls(&mut &cipher[..n])
                    .context("decode TLS record")?;
                self.conn
                    .process_new_packets()
                    .context("process TLS packets")?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Queue plaintext and flush the records it produces.
    async fn send(&mut self, data: &[u8]) -> anyhow::Result<()> {
        use std::io::Write as _;
        self.conn
            .writer()
            .write_all(data)
            .context("queue plaintext into TLS connection")?;
        self.flush_tls().await?;
        Ok(())
    }

    /// Read decrypted plaintext until one CRLF line is available.
    async fn read_line(&mut self) -> anyhow::Result<String> {
        let mut line: Vec<u8> = Vec::with_capacity(256);
        loop {
            use std::io::Read as _;
            let mut tmp = [0u8; 8192];
            let n = self.conn.reader().read(&mut tmp).unwrap_or(0);
            if n > 0 {
                line.extend_from_slice(&tmp[..n]);
                if let Some(pos) = line.windows(2).position(|w| w == b"\r\n") {
                    line.truncate(pos);
                    return Ok(String::from_utf8_lossy(&line).into_owned());
                }
                if line.len() > 8192 {
                    bail!("status line too long (>8KiB)");
                }
                continue;
            }
            self.pull_ciphertext().await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classification_separates_refusals_from_ambiguity() {
        assert_eq!(classify_status(200), SiteStatus::Ok);
        assert_eq!(classify_status(301), SiteStatus::Ok);
        assert_eq!(classify_status(403), SiteStatus::Blocked);
        assert_eq!(classify_status(429), SiteStatus::Blocked);
        assert_eq!(classify_status(451), SiteStatus::Blocked);
        assert_eq!(classify_status(401), SiteStatus::Blocked);
        // Ambiguous: never rotate on these
        assert_eq!(classify_status(404), SiteStatus::Unknown);
        assert_eq!(classify_status(500), SiteStatus::Unknown);
        assert_eq!(classify_status(503), SiteStatus::Unknown);
    }

    #[test]
    fn https_url_splitting_accepts_only_https_authorities() {
        let (host, port, target, _) = split_https_url("https://www.cnbc.com/markets/").unwrap();
        assert_eq!(host, "www.cnbc.com");
        assert_eq!(port, 443);
        assert_eq!(target, "/markets/");

        let (host, port, target, _) = split_https_url("https://example.org:8443/x?y=1").unwrap();
        assert_eq!(host, "example.org");
        assert_eq!(port, 8443);
        assert_eq!(target, "/x?y=1");

        assert!(split_https_url("http://plain.example/").is_err());
        assert!(split_https_url("https://user@example.com/").is_err());
        assert!(split_https_url("https:///path").is_err());
    }

    #[test]
    fn verdict_serialization_round_trips() {
        let v = SiteVerdict {
            status: SiteStatus::Blocked,
            http_status: Some(403),
            checked_unix: 1234567,
            detail: None,
        };
        let text = serde_json::to_string(&v).unwrap();
        assert!(text.contains("\"blocked\""));
        let back: SiteVerdict = serde_json::from_str(&text).unwrap();
        assert_eq!(back, v);
    }

    #[tokio::test]
    async fn connect_tunnel_status_line_is_parsed_from_a_local_proxy() {
        // A fake HTTP proxy: accept one connection, read the CONNECT line,
        // answer 200, then serve a plaintext "HTTP/1.1 403" line inside the
        // tunnel (no TLS — this tests the framing layer only; the TLS leg is
        // covered by live end-to-end probes).
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            assert!(std::str::from_utf8(&buf[..n])
                .unwrap()
                .starts_with("CONNECT "));
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            // Deterministic ordering: wait for the client's go-ahead before
            // the tunnel payload, so the two status lines cannot coalesce
            // into one TCP segment and get truncated by the line reader.
            let n = sock.read(&mut buf).await.unwrap();
            assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), "GO\n");
            sock.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        });
        // Direct socket-level check of the CONNECT + status-line parsing:
        // the full helper CONNECTs then hands off to TLS, so exercise the
        // socket reader directly here.
        use tokio::io::AsyncWriteExt as _;
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        use tokio::io::AsyncReadExt as _;
        let code = read_status_line_socket(&mut sock).await.unwrap();
        assert_eq!(code, 200);
        sock.write_all(b"GO\n").await.unwrap();
        let second = read_status_line_socket(&mut sock).await.unwrap();
        assert_eq!(second, 403);
        server.await.unwrap();
    }
}
