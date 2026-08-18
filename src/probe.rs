//! Periodic probing: TCP connect RTT, semaphore-bounded concurrency (default
//! 32, no hammering).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::debug;

use crate::subscription::Node;

#[derive(Debug)]
pub struct ProbeOutcome {
    pub node: Node,
    /// Some(rtt) = success; None = timeout or connection failure
    pub rtt: Option<Duration>,
}

/// Probe a single node: TCP connect to server:port, measure RTT.
pub async fn probe_one(server: &str, port: u16, timeout: Duration) -> Option<Duration> {
    let t0 = Instant::now();
    let result =
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect((server, port))).await;
    match result {
        Ok(Ok(_stream)) => Some(t0.elapsed()),
        Ok(Err(e)) => {
            // A provider endpoint is operationally sensitive even without
            // its credential. Keep it out of debug logs and report only the
            // failure class; the caller already retains node attribution.
            debug!(error_kind = ?e.kind(), "probe connect failed");
            None
        }
        Err(_) => {
            debug!("probe timed out");
            None
        }
    }
}

/// Probe all nodes concurrently, in arbitrary completion order; logs progress
/// every 50 completions.
pub async fn probe_all(
    nodes: Vec<Node>,
    timeout: Duration,
    concurrency: usize,
) -> Vec<ProbeOutcome> {
    let total = nodes.len();
    let done = Arc::new(AtomicUsize::new(0));
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set: JoinSet<ProbeOutcome> = JoinSet::new();

    for node in nodes {
        let sem = Arc::clone(&sem);
        let done = Arc::clone(&done);
        set.spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore is never closed");
            let rtt = probe_one(node.server(), node.port(), timeout).await;
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 50 == 0 || n == total {
                tracing::info!(done = n, total, "probe progress");
            }
            ProbeOutcome { node, rtt }
        });
    }

    let mut out = Vec::with_capacity(total);
    while let Some(res) = set.join_next().await {
        match res {
            Ok(outcome) => out.push(outcome),
            Err(e) => tracing::warn!(error = %e, "probe task ended abnormally"),
        }
    }
    out
}
