//! Health check: a generate_204-style plaintext HTTP GET through the whole
//! path, or a CONNECT write-through probe for services whose own HTTP
//! semantics say nothing about reachability.
//!
//! Deliberately a hand-rolled minimal HTTP/1.1 request instead of pulling in
//! reqwest/hyper: the request is three lines, only the status line is read —
//! the smaller the dependency surface, the steadier the daemon.
//! A GET target must be plaintext http:// and a CONNECT target
//! `connect://host[:port]` (default 443); both are enforced at the config
//! layer. No TLS is handled here: the write-through probe requires response
//! bytes to come back through the tunnel — strictly stronger than reading
//! the CONNECT status line, but not end-to-end authentication; an adapter
//! fabricating local answers would remain indistinguishable (none observed
//! in the field). Proving a TLS handshake succeeds is a different lane:
//! anti-bot sites that fingerprint the TLS leg belong to the site probe,
//! `src/siteprobe.rs`.
//!
//! Multi-sampling: destination-level degradation in the field is bursty and
//! intermittent (measured 2026-09-25: pool nodes failing 3-23% of probes
//! over a 30-sample window while single-shot matrices read all-green
//! mid-incident), so a tick can demand K samples under an any-fail rule —
//! see [`is_healthy_sampled`].

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



/// Probe payload written into an established CONNECT tunnel: a minimal
/// HTTP/1.0 GET. TLS-speaking edges answer it with a 4xx (measured: nginx on
/// :443 replies "400 Bad Request" in ~0.5s); the content is never
/// interpreted — any response byte is the reachability proof.
const CONNECT_PROBE_PAYLOAD: &[u8] = b"GET / HTTP/1.0\r\n\r\n";

/// Open an HTTP CONNECT tunnel to `connect://host[:port]` through the proxy
/// entry point, then require the tunnel to answer: after a 2xx tunnel reply,
/// write [`CONNECT_PROBE_PAYLOAD`] and demand at least one response byte
/// back through the tunnel. Returns the tunnel reply's status code.
///
/// Why write-through (measured 2026-09-25): adapters answer CONNECT
/// optimistically — the 2xx status line is generated locally before the
/// remote dial completes, so blackhole authorities reply "200" in 0.000s and
/// a status-line-only check is tautological. The write-through read
/// discriminates all three field-measured shapes: response bytes (a healthy
/// TLS edge's 400) = reachable; EOF before any byte (remote reset — the
/// exit-IP-blacklist signature) = unreachable; silence until timeout
/// (blackhole) = unreachable.
///
/// Requires the target to answer a plaintext probe with *something*; a
/// service that waits silently for a TLS ClientHello would read unhealthy.
/// Verify a target's probe behavior before relying on it.
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
        let code = read_status_line(&mut stream).await?;
        if (200..300).contains(&code) {
            stream
                .write_all(CONNECT_PROBE_PAYLOAD)
                .await
                .context("send write-through probe")?;
            let mut probe = [0u8; 512];
            let n = stream
                .read(&mut probe)
                .await
                .context("read write-through probe response")?;
            anyhow::ensure!(
                n > 0,
                "tunnel closed before the write-through probe answered \
                 (remote reset or failed dial)"
            );
        }
        Ok(code)
    };
    let code = match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => bail!("health check timed out ({timeout:?})"),
    }?;
    Ok((code, t0.elapsed()))
}

/// The effective health check for a configured target: GET for `http://`
/// URLs, the CONNECT probe for `connect://` authorities (see
/// [`connect_status_timed`] for how much a 2xx there actually proves).
/// Returns the status code; 2xx counts as healthy in both forms.
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
async fn is_healthy(proxy_addr: SocketAddr, url: &str, timeout: Duration) -> bool {
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

/// Gap between samples inside one multi-sample health tick.
const SAMPLE_SPACING: Duration = Duration::from_secs(1);

/// Outcome of a multi-sample health tick. `Cancelled` is distinct from
/// `Unhealthy` on purpose: a daemon shutting down mid-tick must not book a
/// health failure it never finished measuring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampledVerdict {
    Healthy,
    Unhealthy,
    Cancelled,
}

/// Multi-sample health verdict: every one of `samples` probes must pass
/// (any-fail rule). `cancelled` is checked before every sample — including
/// the first, so a shutdown that fired while the caller waited for its
/// reconfiguration gate aborts the tick without measuring.
///
/// Why (measured 2026-09-25): destination-level degradation in the field is
/// bursty — pool nodes failed 3-23% of probes to their class's pinned HTTPS
/// target over a 30-sample window while single-shot matrices read all-green
/// mid-incident, and a write-through CONNECT probe and TLS end-to-end
/// traffic agreed on the same failing windows (22.5% vs 23.3%). One sample
/// per tick cannot see that; K samples under any-fail turn a per-connection
/// failure rate p into a per-tick rate 1-(1-p)^K, and the existing
/// consecutive-failure threshold provides the rest of the discrimination.
/// Worst-case tick cost is samples × (timeout + [`SAMPLE_SPACING`]); the
/// config layer bounds it against the tick interval and an absolute budget.
pub async fn is_healthy_sampled<F: Fn() -> bool>(
    proxy_addr: SocketAddr,
    url: &str,
    timeout: Duration,
    samples: u32,
    cancelled: F,
) -> SampledVerdict {
    let samples = samples.max(1);
    for i in 0..samples {
        if i > 0 {
            tokio::time::sleep(SAMPLE_SPACING).await;
        }
        if cancelled() {
            return SampledVerdict::Cancelled;
        }
        if !is_healthy(proxy_addr, url, timeout).await {
            return SampledVerdict::Unhealthy;
        }
    }
    SampledVerdict::Healthy
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

    /// What the fake tunnel does after the checker writes its probe payload.
    #[derive(Clone, Copy)]
    enum ProbeMode {
        /// Answer with these bytes (a healthy TLS edge's nginx-400 shape).
        Respond(&'static [u8]),
        /// Never answer; hold the socket until the checker times out
        /// (blackhole shape), then end within a bounded window.
        Hang,
        /// Drop the socket right after the status line (EOF/reset shape).
        CloseAfterStatus,
    }

    const NGINX_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
    const T2: Duration = Duration::from_secs(2);

    type Observed = std::sync::Arc<std::sync::Mutex<Vec<(String, Option<Vec<u8>>)>>>;

    /// Loopback fake proxy serving `conns` sequential connections, each
    /// replying `HTTP/1.1 {status}` and then following its [`ProbeMode`].
    /// Records every CONNECT request and probe payload seen, for wire-shape
    /// assertions on the test side. Network-touching tests may only use
    /// 127.0.0.1.
    async fn spawn_connect_fake(
        conns: Vec<(&'static str, ProbeMode)>,
    ) -> (
        SocketAddr,
        Observed,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let observed: Observed = Default::default();
        let seen = observed.clone();
        let handle = tokio::spawn(async move {
            for (status, mode) in conns {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 512];
                let n = sock.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                sock.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                    .await
                    .unwrap();
                let mut probe = None;
                // Always perform the bounded read, whatever the status or
                // mode: "the checker wrote no probe" must be a recorded
                // fact, not a fake-side assumption — otherwise the non-2xx
                // pin below is true by construction and unfalsifiable.
                if let Ok(Ok(m)) =
                    tokio::time::timeout(Duration::from_millis(500), sock.read(&mut buf)).await
                {
                    if m > 0 {
                        probe = Some(buf[..m].to_vec());
                    }
                }
                seen.lock().unwrap().push((request, probe));
                match mode {
                    ProbeMode::Respond(bytes) => {
                        let _ = sock.write_all(bytes).await;
                    }
                    ProbeMode::Hang => {
                        tokio::time::sleep(Duration::from_millis(700)).await;
                    }
                    ProbeMode::CloseAfterStatus => {}
                }
            }
        });
        (addr, observed, handle)
    }

    #[tokio::test]
    async fn connect_probe_reads_the_tunnel_reply_status() {
        let (addr, seen, task) = spawn_connect_fake(vec![
            ("200 Connection established", ProbeMode::Respond(NGINX_400)),
            ("403 Forbidden", ProbeMode::CloseAfterStatus),
            ("204 No Content", ProbeMode::Respond(NGINX_400)),
        ])
        .await;

        let (code, _) = connect_status_timed(addr, "connect://api.example:443", T2)
            .await
            .unwrap();
        assert_eq!(code, 200);

        let (code, _) = connect_status_timed(addr, "connect://api.example", T2)
            .await
            .unwrap();
        assert_eq!(code, 403, "the port default reaches the same target");

        // check_status dispatches by scheme: the connect:// form routes to
        // the CONNECT probe.
        let code = check_status(addr, "connect://api.example:443", T2)
            .await
            .unwrap();
        assert_eq!(code, 204);

        task.await.unwrap();
        assert_eq!(
            CONNECT_PROBE_PAYLOAD, b"GET / HTTP/1.0\r\n\r\n",
            "the payload literal is pinned so the observed-vs-const asserts below cannot both drift"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        for (req, _) in seen.iter() {
            assert!(
                req.starts_with("CONNECT api.example:443 HTTP/1.1\r\n"),
                "wire shape: {req}"
            );
            assert!(req.contains("Host: api.example:443\r\n"));
        }
        assert_eq!(
            seen[0].1.as_deref(),
            Some(CONNECT_PROBE_PAYLOAD),
            "a 2xx tunnel reply must trigger the write-through probe"
        );
        assert_eq!(seen[1].1, None, "non-2xx never writes the probe payload");
        assert_eq!(seen[2].1.as_deref(), Some(CONNECT_PROBE_PAYLOAD));
    }

    /// Regression pin (the 2026-09-25 tautology incident): an adapter that
    /// answers CONNECT optimistically — 2xx generated locally before the
    /// remote dial, blackhole authorities included — must NOT read healthy.
    /// Only response bytes to the write-through probe count.
    #[tokio::test]
    async fn optimistic_reply_without_probe_response_is_not_healthy() {
        let (addr, _seen, task) = spawn_connect_fake(vec![
            ("200 Connection established", ProbeMode::Hang),
            ("200 Connection established", ProbeMode::Hang),
        ])
        .await;
        let t = Duration::from_millis(300);
        let err = connect_status_timed(addr, "connect://api.example:443", t)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(!is_healthy(addr, "connect://api.example:443", t).await);
        task.await.unwrap();
    }

    /// The remote-reset shape (2026-09-22 exit-IP blacklist signature): the
    /// tunnel closes before any probe response byte. Unhealthy, whether the
    /// failure surfaces on the write or the read.
    #[tokio::test]
    async fn tunnel_eof_before_probe_response_is_not_healthy() {
        let (addr, _seen, task) = spawn_connect_fake(vec![
            ("200 Connection established", ProbeMode::CloseAfterStatus),
            ("200 Connection established", ProbeMode::CloseAfterStatus),
        ])
        .await;
        let err = connect_status_timed(addr, "connect://api.example:443", T2)
            .await
            .unwrap_err();
        let e = err.to_string();
        assert!(
            e.contains("tunnel closed") || e.contains("probe"),
            "EOF must surface as tunnel-closed or a probe I/O error: {e}"
        );
        assert!(!is_healthy(addr, "connect://api.example:443", T2).await);
        task.await.unwrap();
    }

    /// Any response byte proves the round trip; its content is never
    /// interpreted — a TLS edge's plaintext-probe 400 is the healthy shape
    /// in the field (measured on a pool node's nginx-fronted :443 target).
    #[tokio::test]
    async fn probe_response_bytes_mean_reachable_whatever_they_say() {
        let (addr, _seen, task) = spawn_connect_fake(vec![
            ("200 Connection established", ProbeMode::Respond(NGINX_400)),
            ("200 Connection established", ProbeMode::Respond(NGINX_400)),
        ])
        .await;
        let (code, _) = connect_status_timed(addr, "connect://api.example:443", T2)
            .await
            .unwrap();
        assert_eq!(code, 200, "the verdict rides the CONNECT status");
        assert!(is_healthy(addr, "connect://api.example:443", T2).await);
        task.await.unwrap();
    }

    /// Any-fail rule: one dead sample inside a tick sinks the whole tick,
    /// even when the others pass — this is what turns a bursty per-connection
    /// failure rate into a visible per-tick rate. The wire log pins WHERE the
    /// tick died: all three samples must have reached the probe-write stage,
    /// so the failure can only be the third tunnel's missing answer.
    #[tokio::test]
    async fn sampled_verdict_fails_when_any_sample_fails() {
        let (addr, seen, task) = spawn_connect_fake(vec![
            ("200 Connection established", ProbeMode::Respond(NGINX_400)),
            ("200 Connection established", ProbeMode::Respond(NGINX_400)),
            ("200 Connection established", ProbeMode::Hang),
        ])
        .await;
        assert_eq!(
            is_healthy_sampled(
                addr,
                "connect://api.example:443",
                Duration::from_millis(300),
                3,
                || false
            )
            .await,
            SampledVerdict::Unhealthy
        );
        task.await.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.iter().map(|(_, p)| p.as_deref()).collect::<Vec<_>>(),
            vec![Some(CONNECT_PROBE_PAYLOAD); 3],
            "samples 1-2 were answered; sample 3 was probe-written and never answered"
        );
    }

    #[tokio::test]
    async fn sampled_verdict_passes_when_all_samples_pass() {
        let (addr, _seen, task) =
            spawn_connect_fake(vec![("200 Connection established", ProbeMode::Respond(NGINX_400)); 3])
                .await;
        assert_eq!(
            is_healthy_sampled(addr, "connect://api.example:443", T2, 3, || false).await,
            SampledVerdict::Healthy
        );
        task.await.unwrap();

        // samples = 0 clamps to a single sample.
        let (addr, _seen, task) = spawn_connect_fake(vec![(
            "200 Connection established",
            ProbeMode::Respond(NGINX_400),
        )])
        .await;
        assert_eq!(
            is_healthy_sampled(addr, "connect://api.example:443", T2, 0, || false).await,
            SampledVerdict::Healthy
        );
        task.await.unwrap();
    }

    /// Cancellation is a distinct verdict, not a health fact: a tick aborted
    /// by shutdown stops before the next sample and books nothing. The
    /// predicate is checked before the first sample too — a shutdown that
    /// fired while the caller waited for its gate must not measure at all.
    #[tokio::test]
    async fn cancelled_tick_stops_before_the_next_sample() {
        let (addr, seen, task) = spawn_connect_fake(vec![(
            "200 Connection established",
            ProbeMode::Respond(NGINX_400),
        )])
        .await;
        let calls = std::cell::Cell::new(0u32);
        let verdict =
            is_healthy_sampled(addr, "connect://api.example:443", T2, 3, || {
                let n = calls.get();
                calls.set(n + 1);
                n >= 1
            })
            .await;
        assert_eq!(verdict, SampledVerdict::Cancelled);
        task.await.unwrap();
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "only the first sample reached the wire"
        );

        // Cancelled before the first sample: nothing is measured at all.
        let (addr, seen, task) = spawn_connect_fake(vec![]).await;
        assert_eq!(
            is_healthy_sampled(addr, "connect://api.example:443", T2, 3, || true).await,
            SampledVerdict::Cancelled
        );
        task.await.unwrap();
        assert!(seen.lock().unwrap().is_empty());
    }

    /// Pin the 2xx-only verdict for `http://` targets: an origin that answers
    /// redirects (3xx) is NOT healthy. Pointing a class health target at such
    /// an origin without changing the verdict would make every check fail and
    /// burn the class's recovery loop — the trap the connect:// caveat warns
    /// about, nailed from the other side.
    #[tokio::test]
    async fn redirecting_origin_is_not_healthy_under_the_2xx_verdict() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let n = sock.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(
                request.starts_with("GET http://api.example/ HTTP/1.1\r\n"),
                "wire shape: {request}"
            );
            sock.write_all(b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://api.example/\r\n\r\n")
                .await
                .unwrap();
        });

        let healthy = is_healthy(addr, "http://api.example/", Duration::from_secs(2)).await;
        assert!(!healthy, "3xx must not count as healthy");
        task.await.unwrap();
    }
}
