//! Mixed-protocol listener: serves HTTP and SOCKS5 clients on the same port.
//!
//! How it works: peek at the first byte to classify the protocol → pick the
//! current route (an sslocal local port) for that protocol → TCP connect
//! upstream → byte-for-byte bidirectional passthrough. The listener itself
//! **never** parses proxy protocols and **never** connects to targets
//! directly — it is a pipe that can swap its upstream.
//!
//! The route table uses std::sync::RwLock: the critical section is a few field
//! copies, no await while holding the lock, and a switch is a single
//! write-lock assignment (an atomic flip invisible to clients).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::control::NodeTraffic;
use crate::peek::{classify, InboundProto, PeekError};

/// The current route of a class. None = path not yet established (early
/// startup / all candidates failed).
#[derive(Debug, Clone, Default)]
pub struct ClassRoute {
    pub socks_upstream: Option<SocketAddr>,
    pub http_upstream: Option<SocketAddr>,
    pub node_name: String,
    pub generation: u64,
    /// Connections that captured this exact installed path. The counter is
    /// swapped under the same route write lock as the upstream addresses, so
    /// retirement cannot miss a connection racing with publication.
    pub path_connections: Option<Arc<AtomicU64>>,
    /// Subscription namespace captured with the route. A connection that
    /// finishes after a profile change must not repopulate the new profile's
    /// traffic view with bytes from the retired one.
    pub traffic_subscription: String,
}

pub type SharedRoute = Arc<RwLock<ClassRoute>>;

/// Cumulative per-node byte counts, session-only. Attribution happens at
/// connection accept time: the bytes a connection carries belong to the node
/// it was routed to, even if the class switches while it is in flight.
#[derive(Default)]
pub struct TrafficCounters {
    inner: Mutex<TrafficState>,
}

#[derive(Default)]
struct TrafficState {
    subscription: Option<String>,
    nodes: BTreeMap<String, NodeTraffic>,
}

impl TrafficCounters {
    pub fn add(&self, subscription: &str, node: &str, up: u64, down: u64) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if state.subscription.as_deref() != Some(subscription) {
            return;
        }
        let entry = state.nodes.entry(node.to_string()).or_default();
        entry.up = entry.up.saturating_add(up);
        entry.down = entry.down.saturating_add(down);
    }

    pub fn snapshot(&self) -> BTreeMap<String, NodeTraffic> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .nodes
            .clone()
    }

    /// Session traffic is meaningful only inside one subscription namespace:
    /// different profiles may reuse the same display name for different
    /// endpoints. Clear counters exactly at a profile publication boundary.
    pub fn select_subscription(&self, subscription: &str) {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if state.subscription.as_deref() != Some(subscription) {
            state.nodes.clear();
            state.subscription = Some(subscription.to_string());
        }
    }
}

/// RAII guard: +1 on accept, −1 on drop (normal end, error, or abort).
struct ConnGuard(Arc<AtomicU64>);

impl ConnGuard {
    fn new(counter: Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

/// A route-scoped lease acquired while the route read lock is held. Unlike
/// the global accepted-connection count, this begins only after protocol
/// classification has selected a concrete installed path.
struct PathConnGuard(Arc<AtomicU64>);

impl PathConnGuard {
    fn new(counter: Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self(counter)
    }
}

impl Drop for PathConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// First-byte wait timeout: guards against "connected but says nothing"
/// connections leaking tasks.
const PEEK_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout for connecting to the upstream (local sslocal) — on loopback, 10s
/// is already generous.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Existing proxy sessions get a short bounded chance to finish after the
/// listening socket closes. The daemon must never hang indefinitely behind a
/// client that keeps a tunnel open.
const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve(
    class_name: String,
    listener: TcpListener,
    route: SharedRoute,
    traffic: Arc<TrafficCounters>,
    conns: Arc<AtomicU64>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    serve_with_drain_timeout(
        class_name,
        listener,
        route,
        traffic,
        conns,
        shutdown,
        CONNECTION_DRAIN_TIMEOUT,
    )
    .await
}

async fn serve_with_drain_timeout(
    class_name: String,
    listener: TcpListener,
    route: SharedRoute,
    traffic: Arc<TrafficCounters>,
    conns: Arc<AtomicU64>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    drain_timeout: Duration,
) -> anyhow::Result<()> {
    let local_addr = listener.local_addr()?;
    info!(class = %class_name, %local_addr, "listener started");
    let mut connections = JoinSet::new();
    loop {
        // Bias a simultaneous accept/shutdown race toward closing admission.
        // The explicit pre-check also handles a receiver created after the
        // shutdown value was already published.
        if *shutdown.borrow() {
            info!(class = %class_name, "listener found shutdown already requested");
            break;
        }
        tokio::select! { biased;
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if !*shutdown.borrow() => continue,
                    Ok(()) => info!(class = %class_name, "listener received shutdown signal"),
                    Err(_) => info!(class = %class_name, "listener shutdown sender was dropped"),
                }
                break;
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    warn!(class = %class_name, %error, "connection task ended abnormally");
                }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        let route = Arc::clone(&route);
                        let class = class_name.clone();
                        let traffic = Arc::clone(&traffic);
                        let conns = Arc::clone(&conns);
                        connections.spawn(async move {
                            let _guard = ConnGuard::new(conns);
                            if let Err(e) = handle_conn(stream, route, &class, &traffic).await {
                                debug!(%peer, class = %class, error = %format!("{e:#}"), "connection ended (abnormal)");
                            }
                        });
                    }
                    Err(e) => warn!(class = %class_name, error = %e, "accept failed"),
                }
            }
        }
    }

    // Dropping the listener closes admission before draining owned sessions.
    drop(listener);
    let drain = async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                warn!(class = %class_name, %error, "connection task ended abnormally while draining");
            }
        }
    };
    if tokio::time::timeout(drain_timeout, drain).await.is_err() {
        let remaining = connections.len();
        warn!(class = %class_name, remaining, "connection drain timed out; aborting owned sessions");
        connections.abort_all();
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                if !error.is_cancelled() {
                    warn!(class = %class_name, %error, "connection task failed during abort");
                }
            }
        }
    }
    info!(class = %class_name, "listener stopped; all owned sessions finished");
    Ok(())
}

async fn handle_conn(
    mut inbound: TcpStream,
    route: SharedRoute,
    class: &str,
    traffic: &TrafficCounters,
) -> anyhow::Result<()> {
    inbound.set_nodelay(true).ok();

    // peek does not consume bytes: after classification the byte flows on to
    // sslocal unchanged, so byte-for-byte passthrough holds
    let mut first = [0u8; 1];
    let n = match tokio::time::timeout(PEEK_TIMEOUT, inbound.peek(&mut first)).await {
        Ok(res) => res?,
        Err(_) => return Err(PeekError::Timeout.into()),
    };
    if n == 0 {
        return Err(PeekError::Eof.into());
    }
    let proto = classify(first[0])?;

    // Upstream and node attribution are captured together in one route read:
    // the bytes this connection carries belong to the node it was routed to,
    // even if the class switches mid-connection.
    let (upstream, node_name, traffic_subscription, _path_connection) = {
        let route = route.read().expect("route lock should not be poisoned");
        let upstream = match proto {
            InboundProto::Socks5 => route.socks_upstream,
            InboundProto::Http => route.http_upstream,
        };
        let path_connection = upstream.and_then(|_| {
            route
                .path_connections
                .as_ref()
                .map(|counter| PathConnGuard::new(Arc::clone(counter)))
        });
        (
            upstream,
            route.node_name.clone(),
            route.traffic_subscription.clone(),
            path_connection,
        )
    };

    let Some(upstream) = upstream else {
        // Path not yet established: HTTP gets a readable 502 to ease
        // troubleshooting; SOCKS5 is simply closed (there is no legal error
        // frame to hand-write)
        if proto == InboundProto::Http {
            let body = "CAUSEWAY: no active upstream node yet (failover in progress)\n";
            let resp = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            tokio::io::AsyncWriteExt::write_all(&mut inbound, resp.as_bytes())
                .await
                .ok();
        }
        debug!(class, "no active path, connection dropped");
        return Ok(());
    };

    let mut outbound =
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(upstream)).await {
            Ok(s) => s?,
            Err(_) => anyhow::bail!("connect to upstream {upstream} timed out"),
        };
    outbound.set_nodelay(true).ok();

    let (up, down) = copy_bidirectional(&mut inbound, &mut outbound).await?;
    if !node_name.is_empty() {
        traffic.add(&traffic_subscription, &node_name, up, down);
    }
    debug!(class, proto = ?proto, node = %node_name, bytes_up = up, bytes_down = down, "connection closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn traffic_is_reset_when_subscription_namespace_changes() {
        let counters = TrafficCounters::default();
        counters.select_subscription("alpha");
        counters.add("alpha", "shared-name", 10, 20);
        counters.select_subscription("alpha");
        assert_eq!(counters.snapshot()["shared-name"].up, 10);

        counters.select_subscription("beta");
        assert!(counters.snapshot().is_empty());
        counters.add("alpha", "shared-name", 10, 20);
        assert!(counters.snapshot().is_empty());
        counters.add("beta", "shared-name", 1, 2);
        assert_eq!(counters.snapshot()["shared-name"].down, 2);
    }

    #[tokio::test]
    async fn shutdown_closes_admission_and_joins_silent_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let route = Arc::new(RwLock::new(ClassRoute::default()));
        let traffic = Arc::new(TrafficCounters::default());
        let conns = Arc::new(AtomicU64::new(0));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_conns = Arc::clone(&conns);
        let server = tokio::spawn(serve(
            "test".to_string(),
            listener,
            route,
            traffic,
            server_conns,
            shutdown_rx,
        ));

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while conns.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("route-less connection finishes and listener joins promptly")
            .expect("listener task does not panic")
            .expect("listener stops cleanly");
        assert_eq!(conns.load(Ordering::Relaxed), 0);
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn shutdown_aborts_owned_connection_after_bounded_drain() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (_stream, _) = upstream_listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let path_connections = Arc::new(AtomicU64::new(0));
        let route = Arc::new(RwLock::new(ClassRoute {
            socks_upstream: Some(upstream_addr),
            http_upstream: Some(upstream_addr),
            node_name: "fixture".to_string(),
            generation: 1,
            path_connections: Some(Arc::clone(&path_connections)),
            traffic_subscription: "fixture".to_string(),
        }));
        let traffic = Arc::new(TrafficCounters::default());
        let conns = Arc::new(AtomicU64::new(0));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_conns = Arc::clone(&conns);
        let server = tokio::spawn(serve_with_drain_timeout(
            "test".to_string(),
            listener,
            route,
            traffic,
            server_conns,
            shutdown_rx,
            Duration::from_millis(20),
        ));

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[5]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while conns.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while path_connections.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the installed path must account for its captured pipe");
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("listener must enforce its drain deadline")
            .expect("listener task does not panic")
            .expect("listener stops cleanly");
        assert_eq!(conns.load(Ordering::Relaxed), 0);
        assert_eq!(path_connections.load(Ordering::Acquire), 0);
        upstream.abort();
        let _ = upstream.await;
    }

    #[tokio::test]
    async fn pre_requested_shutdown_never_opens_admission() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let route = Arc::new(RwLock::new(ClassRoute::default()));
        let traffic = Arc::new(TrafficCounters::default());
        let conns = Arc::new(AtomicU64::new(0));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx.send(true).unwrap();

        serve(
            "test".to_string(),
            listener,
            route,
            traffic,
            Arc::clone(&conns),
            shutdown_rx,
        )
        .await
        .unwrap();
        assert_eq!(conns.load(Ordering::Relaxed), 0);
        assert!(TcpStream::connect(address).await.is_err());
    }
}
