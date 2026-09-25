//! Inline unit tests for the supervisor, extracted from supervisor.rs
//! (2026-09-18): the 4,101-line file was 40% test code by line count.
//! Same-module child, so private items stay reachable — no API change.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::config::{SubscriptionProfileConfig, LEGACY_SUBSCRIPTION_NAME};
use crate::score::NodeStats;
use crate::state::ClassState;
use crate::subscription::SsNode;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct ReleaseCommitOnDrop(Arc<AtomicBool>);

impl Drop for ReleaseCommitOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[derive(Default)]
struct FakeTrace {
    starts: Mutex<Vec<String>>,
    stops: Mutex<Vec<String>>,
    drops: Mutex<Vec<String>>,
    /// First request line seen by each fake data plane, in start order —
    /// pins the health check's wire shape (GET vs CONNECT) per class.
    requests: Mutex<Vec<String>>,
    next_handle: AtomicU64,
}

impl FakeTrace {
    fn starts(&self) -> Vec<String> {
        self.starts.lock().unwrap().clone()
    }

    fn stops(&self) -> Vec<String> {
        self.stops.lock().unwrap().clone()
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

/// Each successful fake start owns a real loopback HTTP listener. This
/// exercises the same pre-publication health request as production while
/// keeping every test entirely local and deterministic.
struct FakePlane {
    responses: Mutex<VecDeque<(String, u16)>>,
    /// Per-node responder delay in ms, empty by default. Lets ordering
    /// tests invert completion order deterministically (a node's delay
    /// decides when it finishes, so completion order can be made to
    /// differ from pool order on purpose) instead of hoping for
    /// scheduler jitter.
    delays: HashMap<String, u64>,
    trace: Arc<FakeTrace>,
}

impl FakePlane {
    fn new_with_delays(
        responses: impl IntoIterator<Item = (&'static str, u16)>,
        delays: HashMap<String, u64>,
    ) -> (Self, Arc<FakeTrace>) {
        let trace = Arc::new(FakeTrace::default());
        let responses = responses
            .into_iter()
            .map(|(name, status)| (name.to_string(), status))
            .collect();
        (
            Self {
                responses: Mutex::new(responses),
                delays,
                trace: Arc::clone(&trace),
            },
            trace,
        )
    }
}

struct FakeHandle {
    id: String,
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
    server: Option<tokio::task::JoinHandle<()>>,
    stopped: bool,
    trace: Arc<FakeTrace>,
}

impl FakeHandle {
    fn incumbent(id: &str, trace: Arc<FakeTrace>) -> Self {
        Self {
            id: id.to_string(),
            socks_addr: "127.0.0.1:41001".parse().unwrap(),
            http_addr: "127.0.0.1:41002".parse().unwrap(),
            server: None,
            stopped: false,
            trace,
        }
    }
}

impl Drop for FakeHandle {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
        }
        self.trace.drops.lock().unwrap().push(self.id.clone());
    }
}

#[async_trait]
impl DataPlaneHandle for FakeHandle {
    fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    fn describe(&self) -> String {
        self.id.clone()
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if !self.stopped {
            self.stopped = true;
            self.trace.stops.lock().unwrap().push(self.id.clone());
        }
        if let Some(server) = self.server.take() {
            server.abort();
        }
        Ok(())
    }
}

#[async_trait]
impl DataPlane for FakePlane {
    async fn start(&self, spec: StartSpec) -> anyhow::Result<Box<dyn DataPlaneHandle>> {
        let (expected, status) = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected data-plane start");
        anyhow::ensure!(
            expected == spec.node.name(),
            "expected start for {expected}, got {}",
            spec.node.name()
        );
        let node_name = spec.node.name().to_string();
        self.trace.starts.lock().unwrap().push(node_name.clone());
        let delay_ms = self.delays.get(&node_name).copied().unwrap_or(0);

        let socks_addr = spec.socks_addr();
        let http_addr = spec.http_addr();
        // The real adapters release their reservation immediately before
        // spawning. The fake mirrors that boundary before binding its
        // loopback-only health responder.
        drop(spec);
        // Loopback port release→rebind has a small TOCTOU window (the
        // reservation is dropped just above, mirroring the real adapter
        // boundary); retry transient EADDRINUSE instead of failing the test.
        let listener = {
            let mut last_err = None;
            let mut bound = None;
            for _ in 0..10 {
                match tokio::net::TcpListener::bind(http_addr).await {
                    Ok(l) => {
                        bound = Some(l);
                        break;
                    }
                    Err(e) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        last_err = Some(e);
                    }
                }
            }
            bound.ok_or_else(|| anyhow::anyhow!("bind fake plane {http_addr}: {:?}", last_err))?
        };
        let trace = Arc::clone(&self.trace);
        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Record the request line so tests can assert which health
                // target shape (GET vs CONNECT) actually reached the plane.
                let mut buf = [0u8; 512];
                if let Ok(n) = stream.read(&mut buf).await {
                    if let Some(pos) = buf[..n].iter().position(|b| *b == b'\n') {
                        let line = String::from_utf8_lossy(&buf[..pos])
                            .trim_end_matches('\r')
                            .to_string();
                        trace.requests.lock().unwrap().push(line);
                    }
                }
                if delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n");
                let _ = stream.write_all(response.as_bytes()).await;
                // connect:// write-through: after a 2xx tunnel reply the
                // checker writes a plaintext probe into the tunnel and
                // requires response bytes. Mirror the field shape — a TLS
                // edge answers a plaintext probe with a 400 — so class
                // CONNECT targets read reachable.
                if (200..300).contains(&status) {
                    if let Ok(n) = stream.read(&mut buf).await {
                        if n > 0 {
                            let _ = stream
                                .write_all(
                                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                )
                                .await;
                        }
                    }
                }
            }
        });
        let sequence = self.trace.next_handle.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(FakeHandle {
            id: format!("candidate-{sequence}-{node_name}"),
            socks_addr,
            http_addr,
            server: Some(server),
            stopped: false,
            trace: Arc::clone(&self.trace),
        }))
    }
}

/// Install a per-class health override on a fixture config (the config is
/// behind an Arc, so this only works before the runtime spawns).
fn install_class_health_override(ctx: &mut Arc<Ctx>, class: &str, url: &str) {
    Arc::get_mut(ctx)
        .unwrap()
        .cfg
        .classes
        .get_mut(class)
        .unwrap()
        .health = Some(crate::config::ClassHealth {
        url: Some(url.to_string()),
        samples: None,
    });
}

fn node(name: &str) -> Node {
    Node::Ss(SsNode {
        name: name.to_string(),
        server: "192.0.2.1".to_string(),
        port: 443,
        cipher: "aes-128-gcm".to_string(),
        password: "test-only".to_string(),
        plugin: None,
    })
}

fn stats(success: f64, rtt_ms: Option<f64>) -> NodeStats {
    NodeStats {
        success_ema: success,
        rtt_ema_ms: rtt_ms,
        recent_rtts_ms: rtt_ms.into_iter().collect(),
        consecutive_health_failures: 0,
        probe_count: 1,
        last_probe_unix: Some(1),
    }
}

fn assert_stats_unchanged(actual: &NodeStats, expected: &NodeStats, context: &str) {
    assert_eq!(actual.success_ema, expected.success_ema, "{context}");
    assert_eq!(actual.rtt_ema_ms, expected.rtt_ema_ms, "{context}");
    assert_eq!(actual.recent_rtts_ms, expected.recent_rtts_ms, "{context}");
    assert_eq!(
        actual.consecutive_health_failures, expected.consecutive_health_failures,
        "{context}"
    );
    assert_eq!(actual.probe_count, expected.probe_count, "{context}");
    assert_eq!(
        actual.last_probe_unix, expected.last_probe_unix,
        "{context}"
    );
}

fn test_dir(label: &str) -> PathBuf {
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "causeway-supervisor-{label}-{}-{sequence}",
        std::process::id()
    ))
}

fn test_config(state_file: PathBuf, drain_grace_secs: u64) -> Config {
    let mut cfg: Config = toml::from_str(
        r#"
[subscriptions]
files = ["/test/unused.yaml"]

[classes.dev]
listen = "127.0.0.1:17878"
"#,
    )
    .unwrap();
    cfg.state_file = state_file;
    cfg.health.url = "http://health.test/generate_204".to_string();
    cfg.health.timeout_ms = 1_000;
    cfg.health.drain_grace_secs = drain_grace_secs;
    cfg
}

fn one_node_manifest(name: &str) -> String {
    format!(
        "proxies:\n  - name: {name}\n    type: ss\n    server: 192.0.2.20\n    port: 443\n    cipher: aes-128-gcm\n    password: test-only\n"
    )
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, contents: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Fake curl that drains the curl-config the fetcher receives on stdin
/// BEFORE printing `body` and exiting: a child that exits first races the
/// parent's write_all into EPIPE, failing prepare with "subscription
/// preparation failed" (measured: 36% red under 12-way test contention, 0
/// after this drain — same shape as subscription.rs's own fake fetcher).
fn fake_fetcher_script(body: &str) -> String {
    format!(
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{}'\n",
        body.replace('\\', "\\\\").replace('\'', "'\\''")
    )
}

fn recovery_fixture(
    nodes: Vec<Node>,
    responses: impl IntoIterator<Item = (&'static str, u16)>,
    generation: u64,
    drain_grace_secs: u64,
    label: &str,
) -> (
    Arc<Ctx>,
    Arc<tokio::sync::Mutex<ClassRuntime>>,
    Arc<FakeTrace>,
    PathBuf,
) {
    recovery_fixture_with_delays(
        nodes,
        responses,
        generation,
        drain_grace_secs,
        label,
        HashMap::new(),
    )
}

/// Variant with per-node responder delays (see [`FakePlane::delays`]) for
/// tests that must control completion order.
fn recovery_fixture_with_delays(
    nodes: Vec<Node>,
    responses: impl IntoIterator<Item = (&'static str, u16)>,
    generation: u64,
    drain_grace_secs: u64,
    label: &str,
    delays: HashMap<String, u64>,
) -> (
    Arc<Ctx>,
    Arc<tokio::sync::Mutex<ClassRuntime>>,
    Arc<FakeTrace>,
    PathBuf,
) {
    let dir = test_dir(label);
    let cfg = test_config(dir.join("state.json"), drain_grace_secs);
    let catalog = cfg.subscriptions.clone();
    let (plane, trace) = FakePlane::new_with_delays(responses, delays);
    let current = nodes
        .iter()
        .find(|candidate| candidate.name() == "current")
        .expect("fixture current node")
        .clone();
    let mut state = StateFile::default();
    state.activate_subscription(LEGACY_SUBSCRIPTION_NAME);
    for candidate in &nodes {
        let quality = if candidate.name() == "current" {
            0.5
        } else {
            0.9
        };
        state
            .nodes
            .insert(candidate.name().to_string(), stats(quality, Some(100.0)));
    }
    state.classes.insert(
        "dev".to_string(),
        ClassState {
            active_node: Some("current".to_string()),
            socks_port: Some(41001),
            http_port: Some(41002),
            generation,
        },
    );

    let incumbent_connections = Arc::new(AtomicU64::new(0));
    let route = Arc::new(RwLock::new(ClassRoute {
        socks_upstream: Some("127.0.0.1:41001".parse().unwrap()),
        http_upstream: Some("127.0.0.1:41002".parse().unwrap()),
        node_name: "current".to_string(),
        generation,
        path_connections: Some(Arc::clone(&incumbent_connections)),
        traffic_subscription: LEGACY_SUBSCRIPTION_NAME.to_string(),
    }));
    let class = Arc::new(tokio::sync::Mutex::new(ClassRuntime {
        name: "dev".to_string(),
        listen_addr: "127.0.0.1:17878".parse().unwrap(),
        route,
        active: Some(ActiveNode {
            node: current,
            handle: Box::new(FakeHandle::incumbent("incumbent-old", Arc::clone(&trace))),
            path_connections: incumbent_connections,
        }),
        auto_recovery: AutoRecoveryBackoff::default(),
        health_failures: 0,
    }));
    let (drain_shutdown, _) = watch::channel(false);
    let ctx = Arc::new(Ctx {
        config_path: dir.join("config.toml"),
        subscriptions: Arc::new(RwLock::new(SubscriptionRuntime {
            active: LEGACY_SUBSCRIPTION_NAME.to_string(),
            nodes,
            catalog,
            generation: 0,
        })),
        subscription_txn: Arc::new(tokio::sync::Mutex::new(())),
        subscription_txns_in_progress: Arc::new(AtomicU64::new(0)),
        reconfiguration: Arc::new(tokio::sync::RwLock::new(())),
        state: Arc::new(Mutex::new(state)),
        plane: Arc::new(plane),
        events: Arc::new(EventLog::new(32)),
        traffic: Arc::new(listener::TrafficCounters::default()),
        conns: Arc::new(AtomicU64::new(0)),
        draining: Arc::new(tokio::sync::Mutex::new(JoinSet::new())),
        drain_shutdown,
        cfg,
    });
    (ctx, class, trace, dir)
}

async fn wait_for_stop(trace: &FakeTrace, handle: &str) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !trace.stops().iter().any(|stopped| stopped == handle) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retired data plane should stop promptly");
}

#[tokio::test]
async fn retired_path_waits_for_captured_connections_then_stops() {
    let (ctx, class, trace, dir) =
        recovery_fixture(vec![node("current")], [], 1, 0, "drain-connections");
    let (active, connections) = {
        let mut runtime = class.lock().await;
        let active = runtime.active.take().unwrap();
        let connections = Arc::clone(&active.path_connections);
        (active, connections)
    };
    connections.store(1, Ordering::Release);

    schedule_drain_with(
        &ctx,
        active,
        Duration::from_secs(1),
        Duration::from_millis(5),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        trace.stops().is_empty(),
        "minimum grace expiry must not stop a path with a captured connection"
    );

    connections.store(0, Ordering::Release);
    wait_for_stop(&trace, "incumbent-old").await;
    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn retired_path_hard_cap_bounds_stuck_connection() {
    let (ctx, class, trace, dir) =
        recovery_fixture(vec![node("current")], [], 1, 0, "drain-hard-cap");
    let active = {
        let mut runtime = class.lock().await;
        let active = runtime.active.take().unwrap();
        active.path_connections.store(1, Ordering::Release);
        active
    };

    schedule_drain_with(
        &ctx,
        active,
        Duration::from_millis(30),
        Duration::from_millis(5),
    )
    .await;
    wait_for_stop(&trace, "incumbent-old").await;
    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn shutdown_bypasses_retired_path_wait_and_reaps_handle() {
    let (ctx, class, trace, dir) =
        recovery_fixture(vec![node("current")], [], 1, 3_600, "drain-shutdown");
    let active = {
        let mut runtime = class.lock().await;
        let active = runtime.active.take().unwrap();
        active.path_connections.store(1, Ordering::Release);
        active
    };

    schedule_drain_with(
        &ctx,
        active,
        Duration::from_secs(1),
        Duration::from_millis(5),
    )
    .await;
    stop_draining(&ctx).await;
    assert_eq!(trace.stops(), ["incumbent-old"]);
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn status_marks_subscription_transaction_until_guard_drops() {
    let current = node("current");
    let (ctx, _class, _trace, dir) =
        recovery_fixture(vec![current], [], 3, 0, "subscription-txn-status");

    let idle = class_snapshot(&ctx, "dev").unwrap();
    assert_eq!(idle.subscription_generation, Some(0));
    assert_eq!(idle.subscription_txn_in_progress, Some(false));

    let transaction = SubscriptionTxnStatusGuard::begin(&ctx.subscription_txns_in_progress);
    let staging = class_snapshot(&ctx, "dev").unwrap();
    assert_eq!(
        staging.active_subscription.as_deref(),
        Some(LEGACY_SUBSCRIPTION_NAME)
    );
    assert_eq!(staging.subscription_generation, Some(0));
    assert_eq!(staging.subscription_txn_in_progress, Some(true));

    drop(transaction);
    assert_eq!(
        class_snapshot(&ctx, "dev")
            .unwrap()
            .subscription_txn_in_progress,
        Some(false)
    );
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn recovery_tries_alternates_then_freshly_rebuilds_incumbent() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("alternate", 503), ("current", 204)],
        7,
        3_600,
        "rebuild-success",
    );

    switch_node_inner(&ctx, &class, "health-failures").await;

    assert_eq!(trace.starts(), ["alternate", "current"]);
    assert_eq!(
        trace.stops(),
        ["candidate-0-alternate"],
        "failed alternate is stopped immediately"
    );
    let rt = class.lock().await;
    let active = rt.active.as_ref().unwrap();
    assert_eq!(active.node.name(), "current");
    assert_eq!(active.handle.describe(), "candidate-1-current");
    let route = rt.route.read().unwrap().clone();
    assert_eq!(route.node_name, "current");
    assert_eq!(route.generation, 8);
    assert_ne!(route.http_upstream.unwrap().port(), 41002);
    drop(rt);
    assert_eq!(ctx.draining.lock().await.len(), 1);
    {
        let state = lock_state(&ctx.state);
        assert_eq!(state.classes["dev"].active_node.as_deref(), Some("current"));
        assert_eq!(state.classes["dev"].generation, 8);
    }

    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn failed_rebuild_keeps_old_route_handle_and_generation() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("alternate", 503), ("current", 503)],
        11,
        3_600,
        "rebuild-failure",
    );

    switch_node_inner(&ctx, &class, "health-failures").await;

    assert_eq!(trace.starts(), ["alternate", "current"]);
    // The two failed candidates stop from concurrent tasks, so their stop
    // ORDER is scheduler-dependent (flaked ~1-in-3 suite runs under
    // parallel load). The contract is "both stopped", not their sequence.
    let mut stops = trace.stops().to_vec();
    stops.sort_unstable();
    assert_eq!(stops, ["candidate-0-alternate", "candidate-1-current"]);
    let rt = class.lock().await;
    assert_eq!(
        rt.active.as_ref().unwrap().handle.describe(),
        "incumbent-old"
    );
    let route = rt.route.read().unwrap().clone();
    assert_eq!(route.node_name, "current");
    assert_eq!(route.generation, 11);
    assert_eq!(route.socks_upstream.unwrap().port(), 41001);
    assert_eq!(route.http_upstream.unwrap().port(), 41002);
    drop(rt);
    assert!(ctx.draining.lock().await.is_empty());
    let state = lock_state(&ctx.state);
    assert_eq!(state.classes["dev"].active_node.as_deref(), Some("current"));
    assert_eq!(state.classes["dev"].generation, 11);
    drop(state);
    assert!(!ctx
        .events
        .snapshot()
        .iter()
        .any(|event| { matches!(event, control::Event::Switched { .. }) }));

    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn egress_rebuild_keeps_same_node_and_drains_old_path() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("current", 204)],
        4,
        3_600,
        "egress-rebuild-success",
    );
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    rebuild_current_after_egress_change_with(&ctx, &class, &mut shutdown_rx, || async { true })
        .await;

    assert_eq!(trace.starts(), ["current"]);
    assert!(trace.stops().is_empty(), "the incumbent must drain first");
    let rt = class.lock().await;
    assert_eq!(rt.active.as_ref().unwrap().node.name(), "current");
    assert_eq!(
        rt.active.as_ref().unwrap().handle.describe(),
        "candidate-0-current"
    );
    assert_eq!(rt.route.read().unwrap().generation, 5);
    drop(rt);
    assert_eq!(ctx.draining.lock().await.len(), 1);
    assert!(ctx.events.snapshot().iter().any(|event| matches!(
        event,
        control::Event::Switched { reason, node, .. }
            if reason == "egress-change" && node == "current"
    )));

    drop(shutdown_tx);
    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn failed_or_superseded_egress_rebuild_preserves_incumbent() {
    let (failed_ctx, failed_class, failed_trace, failed_dir) = recovery_fixture(
        vec![node("current")],
        [("current", 503)],
        8,
        0,
        "egress-rebuild-failure",
    );
    let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let failed_stats_before = lock_state(&failed_ctx.state).nodes["current"].clone();
    rebuild_current_after_egress_change_with(
        &failed_ctx,
        &failed_class,
        &mut shutdown_rx,
        || async { true },
    )
    .await;
    assert_eq!(failed_trace.starts(), ["current"]);
    assert_eq!(failed_trace.stops(), ["candidate-0-current"]);
    assert_eq!(
        failed_class
            .lock()
            .await
            .active
            .as_ref()
            .unwrap()
            .handle
            .describe(),
        "incumbent-old"
    );
    assert_eq!(
        failed_class.lock().await.route.read().unwrap().generation,
        8
    );
    assert!(failed_ctx.draining.lock().await.is_empty());
    assert_stats_unchanged(
        &lock_state(&failed_ctx.state).nodes["current"],
        &failed_stats_before,
        "an egress-triggered failure must not poison node quality",
    );

    let (stale_ctx, stale_class, stale_trace, stale_dir) = recovery_fixture(
        vec![node("current")],
        [("current", 204)],
        9,
        0,
        "egress-rebuild-stale",
    );
    let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let stale_stats_before = lock_state(&stale_ctx.state).nodes["current"].clone();
    rebuild_current_after_egress_change_with(
        &stale_ctx,
        &stale_class,
        &mut shutdown_rx,
        || async { false },
    )
    .await;
    assert_eq!(stale_trace.starts(), ["current"]);
    assert_eq!(stale_trace.stops(), ["candidate-0-current"]);
    assert_eq!(
        stale_class
            .lock()
            .await
            .active
            .as_ref()
            .unwrap()
            .handle
            .describe(),
        "incumbent-old"
    );
    assert_eq!(stale_class.lock().await.route.read().unwrap().generation, 9);
    assert!(stale_ctx.draining.lock().await.is_empty());
    assert_stats_unchanged(
        &lock_state(&stale_ctx.state).nodes["current"],
        &stale_stats_before,
        "discarding a superseded rebuild must not alter node quality",
    );

    let (shutdown_ctx, shutdown_class, shutdown_trace, shutdown_dir) = recovery_fixture(
        vec![node("current")],
        [("current", 204)],
        10,
        0,
        "egress-rebuild-shutdown-after-stage",
    );
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    rebuild_current_after_egress_change_with(
        &shutdown_ctx,
        &shutdown_class,
        &mut shutdown_rx,
        || async move {
            shutdown_tx.send(true).unwrap();
            true
        },
    )
    .await;
    assert_eq!(shutdown_trace.starts(), ["current"]);
    assert_eq!(shutdown_trace.stops(), ["candidate-0-current"]);
    assert_eq!(
        shutdown_class
            .lock()
            .await
            .active
            .as_ref()
            .unwrap()
            .handle
            .describe(),
        "incumbent-old"
    );
    assert_eq!(
        shutdown_class.lock().await.route.read().unwrap().generation,
        10
    );

    std::fs::remove_dir_all(failed_dir).ok();
    std::fs::remove_dir_all(stale_dir).ok();
    std::fs::remove_dir_all(shutdown_dir).ok();
}

#[tokio::test]
async fn egress_rebuild_yields_to_subscription_or_class_mutation_and_shutdown() {
    let (ctx, class, trace, dir) =
        recovery_fixture(vec![node("current")], [], 3, 0, "egress-rebuild-priority");
    let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let transaction = SubscriptionTxnStatusGuard::begin(&ctx.subscription_txns_in_progress);
    rebuild_current_after_egress_change_with(&ctx, &class, &mut shutdown_rx, || async { true })
        .await;
    drop(transaction);

    let class_guard = class.lock().await;
    rebuild_current_after_egress_change_with(&ctx, &class, &mut shutdown_rx, || async { true })
        .await;
    drop(class_guard);

    let probe_or_manual_guard = ctx.reconfiguration.read().await;
    rebuild_current_after_egress_change_with(&ctx, &class, &mut shutdown_rx, || async { true })
        .await;
    drop(probe_or_manual_guard);

    let (shutdown_tx, mut stopped_rx) = watch::channel(false);
    shutdown_tx.send(true).unwrap();
    rebuild_current_after_egress_change_with(&ctx, &class, &mut stopped_rx, || async { true })
        .await;

    assert!(trace.starts().is_empty());
    assert_eq!(class.lock().await.route.read().unwrap().generation, 3);
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn automatic_recovery_backoff_grows_caps_and_resets() {
    let start = std::time::Instant::now();
    let mut backoff = AutoRecoveryBackoff::default();
    assert!(backoff.is_ready_at(start));

    let mut delays = Vec::new();
    let mut now = start;
    for _ in 0..8 {
        let delay = backoff.record_failure_at(now);
        delays.push(delay);
        assert!(!backoff.is_ready_at(now));
        now += delay;
        assert!(backoff.is_ready_at(now));
    }
    assert_eq!(
        delays,
        [
            Duration::from_secs(60),
            Duration::from_secs(120),
            Duration::from_secs(240),
            Duration::from_secs(480),
            Duration::from_secs(900),
            Duration::from_secs(900),
            Duration::from_secs(900),
            Duration::from_secs(900),
        ]
    );

    backoff.reset();
    assert_eq!(backoff.consecutive_failures, 0);
    assert!(backoff.retry_not_before.is_none());
    assert!(backoff.is_ready_at(now));
    assert_eq!(
        backoff.record_failure_at(now),
        AUTO_RECOVERY_INITIAL_BACKOFF,
        "a successful publication must restart the sequence"
    );
}

#[tokio::test]
async fn health_recovery_cooldown_skips_churn_but_manual_path_is_unblocked() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("alternate", 503), ("current", 503), ("alternate", 204)],
        2,
        0,
        "health-backoff",
    );

    recover_after_health_failure(&ctx, &class).await;
    assert_eq!(trace.starts(), ["alternate", "current"]);
    assert_eq!(class.lock().await.auto_recovery.consecutive_failures, 1);

    recover_after_health_failure(&ctx, &class).await;
    assert_eq!(
        trace.starts(),
        ["alternate", "current"],
        "a health tick inside cooldown must not start more adapters"
    );

    // The actual control-socket manual path deliberately bypasses the
    // health cooldown, and a successful publication resets it immediately.
    let outcome = switch_to(&ctx, &class, "alternate").await.unwrap();
    assert_eq!(outcome.installed, "alternate");
    assert_eq!(trace.starts(), ["alternate", "current", "alternate"]);
    {
        let rt = class.lock().await;
        assert_eq!(rt.active.as_ref().unwrap().node.name(), "alternate");
        assert_eq!(rt.auto_recovery.consecutive_failures, 0);
        assert!(rt.auto_recovery.retry_not_before.is_none());
    }

    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn missing_active_path_also_obeys_health_recovery_cooldown() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("alternate", 503), ("current", 503)],
        0,
        0,
        "no-active-backoff",
    );
    {
        let mut rt = class.lock().await;
        rt.active.take();
        *rt.route.write().unwrap() = ClassRoute::default();
    }

    recover_after_health_failure(&ctx, &class).await;
    assert_eq!(trace.starts(), ["alternate", "current"]);
    assert_eq!(class.lock().await.auto_recovery.consecutive_failures, 1);

    recover_after_health_failure(&ctx, &class).await;
    assert_eq!(
        trace.starts(),
        ["alternate", "current"],
        "a listener with no active path must not respawn candidates every health tick"
    );
    {
        let rt = class.lock().await;
        assert!(rt.active.is_none());
        assert_eq!(rt.route.read().unwrap().generation, 0);
    }

    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn only_successful_publication_schedules_and_stops_old_handle() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("bad"), node("good")],
        [("bad", 503), ("good", 204)],
        3,
        0,
        "publication-drain",
    );

    {
        let mut rt = class.lock().await;
        assert_eq!(
            try_candidates(&ctx, &mut rt, &[node("bad")], "test").await,
            None
        );
        assert_eq!(
            rt.active.as_ref().unwrap().handle.describe(),
            "incumbent-old"
        );
        assert_eq!(rt.route.read().unwrap().generation, 3);
    }
    assert!(ctx.draining.lock().await.is_empty());
    assert_eq!(trace.stops(), ["candidate-0-bad"]);

    {
        let mut rt = class.lock().await;
        assert_eq!(
            try_candidates(&ctx, &mut rt, &[node("good")], "test").await,
            Some("good".to_string())
        );
        assert_eq!(rt.active.as_ref().unwrap().node.name(), "good");
        assert_eq!(rt.route.read().unwrap().generation, 4);
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if trace.stops().iter().any(|id| id == "incumbent-old") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("published incumbent should finish its zero-grace drain");
    stop_draining(&ctx).await;
    assert_eq!(
        ctx.events
            .snapshot()
            .iter()
            .filter(|event| matches!(event, control::Event::Switched { .. }))
            .count(),
        1
    );

    std::fs::remove_dir_all(dir).ok();
}

#[cfg(unix)]
#[tokio::test]
async fn state_commit_failure_keeps_live_and_confirmed_cache_generation() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current")],
        [("candidate", 204)],
        5,
        3_600,
        "subscription-state-failure",
    );
    std::fs::create_dir_all(&dir).unwrap();

    let old_manifest = dir.join("old.yaml");
    write_private(&old_manifest, &one_node_manifest("current"), 0o600);
    let url_file = dir.join("new.url");
    write_private(&url_file, "https://subscription.invalid/test-only", 0o600);
    let cache_file = dir.join("new-cache.yaml");
    let slot_a =
        subscription::cache_slot_path(&cache_file, subscription::CACHE_SLOT_A).unwrap();
    let slot_b =
        subscription::cache_slot_path(&cache_file, subscription::CACHE_SLOT_B).unwrap();
    write_private(&slot_a, &one_node_manifest("generation-a"), 0o600);

    let fetcher = dir.join("fake-curl");
    let body = one_node_manifest("candidate");
    let script = fake_fetcher_script(&body);
    write_private(&fetcher, &script, 0o700);
    let _fetcher_override = subscription::TestCurlOverride::install(url_file.clone(), fetcher);

    let old_profile = SubscriptionProfileConfig {
        files: vec![old_manifest],
        url_file: None,
        cache_file: None,
    };
    let new_profile = SubscriptionProfileConfig {
        files: Vec::new(),
        url_file: Some(url_file),
        cache_file: Some(cache_file.clone()),
    };
    let catalog = SubscriptionsConfig {
        files: Vec::new(),
        default: Some("old".to_string()),
        profiles: BTreeMap::from([
            ("new".to_string(), new_profile.clone()),
            ("old".to_string(), old_profile),
        ]),
    };

    {
        let mut runtime = ctx
            .subscriptions
            .write()
            .unwrap_or_else(|error| error.into_inner());
        runtime.active = "old".to_string();
        runtime.catalog = catalog.clone();
    }
    {
        let mut state = lock_state(&ctx.state);
        state.active_subscription = Some("old".to_string());
        state
            .subscription_cache_slots
            .insert("new".to_string(), subscription::CACHE_SLOT_A.to_string());
    }
    state::save_atomic(&ctx.cfg.state_file, &lock_state(&ctx.state)).unwrap();
    // Force the post-cache, pre-publication state replacement to fail at
    // its temporary-file open. The existing durable state remains intact.
    std::fs::create_dir(ctx.cfg.state_file.with_extension("json.tmp")).unwrap();

    let classes = HashMap::from([("dev".to_string(), Arc::clone(&class))]);
    let reply =
        switch_subscription_locked(&ctx, &classes, "new", catalog.clone(), false, false).await;

    assert!(!reply.ok);
    assert_eq!(
        reply.error.as_deref(),
        Some("subscription state commit failed")
    );
    assert!(
        slot_b.exists(),
        "fresh generation B must reach its inactive slot"
    );
    assert_eq!(
        subscription::load_profile_snapshot_from_slot(
            &new_profile,
            Some(subscription::CACHE_SLOT_A)
        )[0]
        .name(),
        "generation-a",
        "restart must ignore the unconfirmed B slot"
    );
    assert_eq!(
        subscription::load_profile_snapshot_from_slot(
            &new_profile,
            Some(subscription::CACHE_SLOT_B)
        )[0]
        .name(),
        "candidate"
    );

    {
        let runtime = ctx
            .subscriptions
            .read()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(runtime.active, "old");
        assert_eq!(
            runtime.nodes.iter().map(Node::name).collect::<Vec<_>>(),
            ["current"]
        );
        assert_eq!(runtime.catalog, catalog);
        assert_eq!(runtime.generation, 0);
    }

    {
        let memory_state = lock_state(&ctx.state);
        assert_eq!(memory_state.active_subscription.as_deref(), Some("old"));
        assert_eq!(
            memory_state
                .subscription_cache_slots
                .get("new")
                .map(String::as_str),
            Some(subscription::CACHE_SLOT_A)
        );
        assert_eq!(memory_state.classes["dev"].generation, 5);
    }
    let disk_state = state::load(&ctx.cfg.state_file).unwrap().unwrap();
    assert_eq!(disk_state.active_subscription.as_deref(), Some("old"));
    assert_eq!(
        disk_state
            .subscription_cache_slots
            .get("new")
            .map(String::as_str),
        Some(subscription::CACHE_SLOT_A)
    );
    assert_eq!(disk_state.classes["dev"].generation, 5);

    let rt = class.lock().await;
    assert_eq!(rt.active.as_ref().unwrap().node.name(), "current");
    assert_eq!(
        rt.active.as_ref().unwrap().handle.describe(),
        "incumbent-old"
    );
    let route = rt.route.read().unwrap().clone();
    assert_eq!(route.node_name, "current");
    assert_eq!(route.generation, 5);
    assert_eq!(route.socks_upstream.unwrap().port(), 41001);
    assert_eq!(route.http_upstream.unwrap().port(), 41002);
    drop(rt);
    assert_eq!(trace.starts(), ["candidate"]);
    assert_eq!(trace.stops(), ["candidate-0-candidate"]);
    assert!(ctx.draining.lock().await.is_empty());
    assert!(!ctx.events.snapshot().iter().any(|event| {
        matches!(
            event,
            control::Event::Switched { .. } | control::Event::SubscriptionChanged { .. }
        )
    }));

    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn reload_source_change_blocks_inactive_old_cache_and_stats() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current")],
        [("current", 204)],
        2,
        0,
        "reload-source-isolation",
    );
    std::fs::create_dir_all(&dir).unwrap();
    let active_manifest = dir.join("active.yaml");
    write_private(&active_manifest, &one_node_manifest("current"), 0o600);
    let old_url = dir.join("old.url");
    let new_url = dir.join("new.url");
    let cache_file = dir.join("inactive-cache.yaml");
    let old_slot =
        subscription::cache_slot_path(&cache_file, subscription::CACHE_SLOT_A).unwrap();
    write_private(&old_slot, &one_node_manifest("old-cached-node"), 0o600);

    let active_profile = SubscriptionProfileConfig {
        files: vec![active_manifest],
        url_file: None,
        cache_file: None,
    };
    let old_inactive = SubscriptionProfileConfig {
        files: Vec::new(),
        url_file: Some(old_url),
        cache_file: Some(cache_file.clone()),
    };
    let new_inactive = SubscriptionProfileConfig {
        files: Vec::new(),
        url_file: Some(new_url),
        cache_file: Some(cache_file),
    };
    let old_catalog = SubscriptionsConfig {
        files: Vec::new(),
        default: Some("active".into()),
        profiles: BTreeMap::from([
            ("active".into(), active_profile.clone()),
            ("inactive".into(), old_inactive.clone()),
        ]),
    };
    let new_catalog = SubscriptionsConfig {
        files: Vec::new(),
        default: Some("active".into()),
        profiles: BTreeMap::from([
            ("active".into(), active_profile),
            ("inactive".into(), new_inactive.clone()),
        ]),
    };
    {
        let mut runtime = ctx
            .subscriptions
            .write()
            .unwrap_or_else(|error| error.into_inner());
        runtime.active = "active".into();
        runtime.catalog = old_catalog.clone();
    }
    {
        let mut state = lock_state(&ctx.state);
        state.activate_subscription("active");
        state.activate_subscription("inactive");
        state
            .nodes
            .insert("old-cached-node".into(), stats(0.99, Some(1.0)));
        state.activate_subscription("active");
        state
            .subscription_cache_slots
            .insert("inactive".into(), subscription::CACHE_SLOT_A.to_string());
        state
            .subscription_source_identities
            .insert("inactive".into(), old_inactive.source_identity().unwrap());
    }

    let classes = HashMap::from([("dev".to_string(), Arc::clone(&class))]);
    let refreshed =
        switch_subscription_locked(&ctx, &classes, "active", new_catalog.clone(), false, true)
            .await;
    assert!(refreshed.ok);
    {
        let state = lock_state(&ctx.state);
        assert!(state.nodes_for_subscription("inactive").is_none());
        assert!(!state.subscription_cache_slots.contains_key("inactive"));
        assert!(!state.source_is_trusted("inactive", &new_inactive.source_identity().unwrap()));
    }
    assert!(
        old_slot.exists(),
        "invalidation need not delete an old file"
    );

    let rejected =
        switch_subscription_locked(&ctx, &classes, "inactive", new_catalog, true, false).await;
    assert!(!rejected.ok);
    assert_eq!(
        rejected.error.as_deref(),
        Some("subscription preparation failed")
    );
    assert_eq!(trace.starts(), ["current"]);

    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[cfg(unix)]
#[test]
fn startup_snapshot_quarantines_legacy_cache_after_source_change() {
    let dir = test_dir("startup-legacy-quarantine");
    std::fs::create_dir_all(&dir).unwrap();
    let cache_file = dir.join("cache.yaml");
    write_private(&cache_file, &one_node_manifest("legacy-node"), 0o600);
    let profile = SubscriptionProfileConfig {
        files: Vec::new(),
        url_file: Some(dir.join("url")),
        cache_file: Some(cache_file.clone()),
    };

    // Upgrade story: a legacy daemon left a bare cache, the new daemon
    // never wrote a slot, and the persisted identity still matches — the
    // compatibility fallback must keep working.
    let mut st = StateFile::default();
    let identities =
        BTreeMap::from([("remote".to_string(), profile.source_identity().unwrap())]);
    st.reconcile_startup_sources(&identities);
    let (nodes, quarantined) = startup_snapshot(&st, &identities, "remote", &profile);
    assert_eq!(nodes.len(), 1, "trusted source keeps the legacy fallback");
    assert!(!quarantined);

    // Same-name source change: reconcile_startup_sources quarantines the
    // profile; startup must not serve the previous source's bare cache
    // through the None-slot fallback.
    let new_profile = SubscriptionProfileConfig {
        files: Vec::new(),
        url_file: Some(dir.join("moved.url")),
        cache_file: Some(cache_file),
    };
    let changed =
        BTreeMap::from([("remote".to_string(), new_profile.source_identity().unwrap())]);
    st.reconcile_startup_sources(&changed);
    let (nodes, quarantined) = startup_snapshot(&st, &changed, "remote", &new_profile);
    assert!(nodes.is_empty(), "quarantined cache must not be served");
    assert!(quarantined);

    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn on_demand_probe_skips_nodes_from_a_replaced_pool() {
    let (ctx, _class, _trace, dir) =
        recovery_fixture(vec![node("current")], [("current", 204)], 1, 0, "probe-era");
    // Live era: the per-node test runs end to end and records statistics.
    let era = ctx
        .subscriptions
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .generation;
    let result = probe_now_node(&ctx, node("current"), era, &ctx.cfg.health.url, true).await;
    assert!(result.ok);
    assert!(lock_state(&ctx.state).nodes["current"].probe_count >= 1);

    // Publication bumped the pool generation: a probe task still holding
    // an old pool snapshot must skip instead of writing old-pool
    // statistics into the new profile.
    ctx.subscriptions
        .write()
        .unwrap_or_else(|error| error.into_inner())
        .generation += 1;
    let before = lock_state(&ctx.state).nodes["current"].clone();
    let result = probe_now_node(&ctx, node("current"), era, &ctx.cfg.health.url, true).await;
    assert!(!result.ok);
    assert_eq!(
        result.error.as_deref(),
        Some("skipped: subscription changed")
    );
    let after = lock_state(&ctx.state).nodes["current"].clone();
    assert_stats_unchanged(&after, &before, "skipped probe must not record stats");
    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[cfg(unix)]
#[tokio::test]
async fn cache_commit_keeps_owned_guards_after_subscription_task_abort() {
    let target = "commit-barrier";
    let (ctx, class, _trace, dir) = recovery_fixture(
        vec![node("current")],
        [("candidate", 204)],
        5,
        0,
        "subscription-commit-barrier",
    );
    std::fs::create_dir_all(&dir).unwrap();

    let old_manifest = dir.join("old.yaml");
    write_private(&old_manifest, &one_node_manifest("current"), 0o600);
    let url_file = dir.join("new.url");
    write_private(&url_file, "https://subscription.invalid/test-only", 0o600);
    let cache_file = dir.join("new-cache.yaml");
    let committed_slot =
        subscription::cache_slot_path(&cache_file, subscription::CACHE_SLOT_A).unwrap();

    let fetcher = dir.join("fake-curl");
    let body = one_node_manifest("candidate");
    let script = fake_fetcher_script(&body);
    write_private(&fetcher, &script, 0o700);
    let _fetcher_override = subscription::TestCurlOverride::install(url_file.clone(), fetcher);

    let catalog = SubscriptionsConfig {
        files: Vec::new(),
        default: Some("old".to_string()),
        profiles: BTreeMap::from([
            (
                target.to_string(),
                SubscriptionProfileConfig {
                    files: Vec::new(),
                    url_file: Some(url_file),
                    cache_file: Some(cache_file),
                },
            ),
            (
                "old".to_string(),
                SubscriptionProfileConfig {
                    files: vec![old_manifest],
                    url_file: None,
                    cache_file: None,
                },
            ),
        ]),
    };
    {
        let mut runtime = ctx
            .subscriptions
            .write()
            .unwrap_or_else(|error| error.into_inner());
        runtime.active = "old".to_string();
        runtime.catalog = catalog;
    }
    {
        let mut state = lock_state(&ctx.state);
        state.active_subscription = Some("old".to_string());
    }
    state::save_atomic(&ctx.cfg.state_file, &lock_state(&ctx.state)).unwrap();

    let commit_started = Arc::new(AtomicBool::new(false));
    let release_commit = Arc::new(AtomicBool::new(false));
    let commit_finished = Arc::new(AtomicBool::new(false));
    let _release_commit_on_drop = ReleaseCommitOnDrop(Arc::clone(&release_commit));
    let _hook = CacheCommitTestHookGuard::install(
        target,
        CacheCommitTestHook {
            before: {
                let commit_started = Arc::clone(&commit_started);
                let release_commit = Arc::clone(&release_commit);
                Arc::new(move || {
                    commit_started.store(true, Ordering::Release);
                    while !release_commit.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                })
            },
            after: {
                let commit_finished = Arc::clone(&commit_finished);
                Arc::new(move || commit_finished.store(true, Ordering::Release))
            },
            precommit_timeout: Duration::from_secs(1),
        },
    );

    let classes = Arc::new(HashMap::from([("dev".to_string(), Arc::clone(&class))]));
    let task = {
        let ctx = Arc::clone(&ctx);
        let classes = Arc::clone(&classes);
        tokio::spawn(async move { switch_subscription(&ctx, &classes, target).await })
    };
    // The spin exits the moment the worker sets the flag. On expiry, name the
    // transaction's own recorded error: a bare Elapsed(()) hid the real failure
    // mode (fetcher stdin race, see fake_fetcher_script) for a whole review
    // round. The ceiling must exceed the fixture's own precommit deadline
    // (precommit_timeout, 1 s above): prepare, gating and activation all run
    // inside it, and once it lapses the transaction aborts before the commit
    // hook can set the flag, so no larger ceiling helps. Measured time-to-flag
    // p99 49 ms under load avg 33 (2026-09-26). Re-derive both numbers if this
    // fixture ever grows responder delays or a longer precommit_timeout.
    if tokio::time::timeout(Duration::from_secs(2), async {
        while !commit_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_err()
    {
        let recent: Vec<_> = ctx.events.snapshot().into_iter().rev().take(3).collect();
        panic!("cache commit worker should start; recent events: {recent:?}");
    }

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(
        !task.is_finished(),
        "deadline must not detach the cache writer"
    );
    assert!(!commit_finished.load(Ordering::Acquire));
    assert!(!committed_slot.exists());
    assert!(
        ctx.subscription_txn.try_lock().is_err(),
        "transaction guard must remain held across the commit barrier"
    );
    assert!(
        ctx.reconfiguration.try_write().is_err(),
        "reconfiguration guard must remain held across the commit barrier"
    );
    assert!(
        class.try_lock().is_err(),
        "class guard must remain held across the commit barrier"
    );

    task.abort();
    assert!(
        task.await
            .expect_err("subscription task should be aborted")
            .is_cancelled(),
        "test must cancel the outer transaction while commit is blocked"
    );
    assert!(
        ctx.subscription_txn.try_lock().is_ok(),
        "the cancelled outer task should release its transaction mutex"
    );
    assert!(
        ctx.reconfiguration.try_write().is_err(),
        "the cache worker must retain the owned write gate after outer cancellation"
    );
    assert!(
        class.try_lock().is_err(),
        "the cache worker must retain owned class guards after outer cancellation"
    );

    // Model the next subscription transaction. It can queue on the now
    // free transaction mutex, but it must not cross the reconfiguration
    // gate or class lock until the previous cache writer has completed.
    let follow_on = {
        let ctx = Arc::clone(&ctx);
        let class = Arc::clone(&class);
        let commit_finished = Arc::clone(&commit_finished);
        tokio::spawn(async move {
            let _transaction = ctx.subscription_txn.lock().await;
            let _reconfiguration = Arc::clone(&ctx.reconfiguration).write_owned().await;
            let _class = class.lock_owned().await;
            commit_finished.load(Ordering::Acquire)
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !follow_on.is_finished(),
        "a later transaction must not overlap the detached cache writer"
    );

    release_commit.store(true, Ordering::Release);
    let previous_commit_finished = tokio::time::timeout(Duration::from_secs(2), follow_on)
        .await
        .expect("later transaction should proceed after cache commit")
        .expect("later transaction should not panic");
    assert!(
        previous_commit_finished,
        "the next transaction crossed the write gate before the previous writer finished"
    );
    assert!(commit_finished.load(Ordering::Acquire));
    assert!(committed_slot.exists());
    assert!(ctx.subscription_txn.try_lock().is_ok());
    assert!(ctx.reconfiguration.try_write().is_ok());
    assert!(class.try_lock().is_ok());

    // Once the guards open, the cancelled transaction has no late writer
    // left that can mutate the slot behind its successor.
    let bytes_after_commit = std::fs::read(&committed_slot).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(std::fs::read(&committed_slot).unwrap(), bytes_after_commit);

    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn profile_candidates_prefer_incumbent_then_quality_then_unknown_name() {
    let nodes = vec![
        node("unknown-z"),
        node("slow"),
        node("preferred"),
        node("fast"),
        node("best"),
        node("unknown-a"),
        node("unknown-m"),
    ];
    let stats = BTreeMap::from([
        ("preferred".to_string(), stats(0.10, Some(900.0))),
        ("best".to_string(), stats(0.99, Some(500.0))),
        ("fast".to_string(), stats(0.80, Some(50.0))),
        ("slow".to_string(), stats(0.80, Some(500.0))),
    ]);

    let ordered = profile_candidates(&nodes, Some(&stats), Some("preferred"), &[]);
    let names: Vec<_> = ordered.iter().map(Node::name).collect();
    assert_eq!(
        names,
        [
            "preferred",
            "best",
            "fast",
            "slow",
            "unknown-a",
            "unknown-m",
            "unknown-z"
        ]
    );

    let attempted: Vec<_> = ordered
        .into_iter()
        .take(MAX_SWITCH_CANDIDATES)
        .map(|candidate| candidate.name().to_string())
        .collect();
    assert_eq!(attempted.len(), MAX_SWITCH_CANDIDATES);
    assert_eq!(
        attempted,
        ["preferred", "best", "fast", "slow", "unknown-a"]
    );
}

#[test]
fn reload_shape_accepts_only_subscription_changes() {
    let running = test_config(test_dir("reload-shape").join("state.json"), 10);
    let mut subscriptions_only = running.clone();
    subscriptions_only.subscriptions.files = vec![PathBuf::from("/test/new.yaml")];
    assert!(!non_subscription_config_changed(
        &running,
        &subscriptions_only
    ));

    let mut changed = Vec::new();
    let mut candidate = running.clone();
    candidate.log_dir.push("different");
    changed.push(candidate);
    let mut candidate = running.clone();
    candidate.state_file.set_file_name("different-state.json");
    changed.push(candidate);
    let mut candidate = running.clone();
    candidate.sslocal_bin.push("different");
    changed.push(candidate);
    let mut candidate = running.clone();
    candidate.obfs_plugin_bin.push("different");
    changed.push(candidate);
    let mut candidate = running.clone();
    candidate.singbox_bin.push("different");
    changed.push(candidate);
    let mut candidate = running.clone();
    candidate.classes.get_mut("dev").unwrap().listen = "127.0.0.1:17879".parse().unwrap();
    changed.push(candidate);
    let mut candidate = running.clone();
    candidate.probe.interval_secs += 1;
    changed.push(candidate);
    let mut candidate = running.clone();
    candidate.health.timeout_ms += 1;
    changed.push(candidate);
    let mut candidate = running.clone();
    candidate.selection.ema_alpha = 0.5;
    changed.push(candidate);
    let mut candidate = running.clone();
    candidate.routing.direct_hosts = vec!["api.example.test".to_string()];
    changed.push(candidate);

    for candidate in changed {
        assert!(non_subscription_config_changed(&running, &candidate));
    }
}
#[test]
fn profile_candidates_region_filter_covers_preferred_probed_and_unknown() {
    let nodes = vec![
        node("🇭🇰 Hong Kong丨01"),
        node("🇯🇵 Japan丨01"),
        node("🇯🇵 Japan丨02"),
    ];
    let stats = BTreeMap::from([
        ("🇭🇰 Hong Kong丨01".to_string(), stats(0.5, Some(500.0))),
        ("🇯🇵 Japan丨01".to_string(), stats(0.99, Some(50.0))),
        // Japan丨02 stays unprobed.
    ]);

    // The preferred incumbent, the higher-scoring probed node, and the
    // unprobed tail must all stay inside the allowlist.
    let ordered = profile_candidates(
        &nodes,
        Some(&stats),
        Some("🇯🇵 Japan丨01"),
        &["🇭🇰".to_string()],
    );
    let names: Vec<_> = ordered.iter().map(Node::name).collect();
    assert_eq!(names, ["🇭🇰 Hong Kong丨01"]);

    let unfiltered = profile_candidates(&nodes, Some(&stats), Some("🇯🇵 Japan丨01"), &[]);
    assert_eq!(unfiltered.len(), 3, "empty allowlist keeps the whole pool");
}

#[tokio::test]
async fn initial_activation_respects_region_allowlist() {
    // state.json records the incumbent (fixture node "current", standing
    // in for a Japan node) as the preferred node, but the region
    // allowlist only admits Hong Kong: initial activation must skip the
    // out-of-allowlist incumbent instead of reinstalling it.
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("🇭🇰 Hong Kong丨01")],
        [("🇭🇰 Hong Kong丨01", 204)],
        1,
        0,
        "initial-regions",
    );
    let mut ctx = ctx;
    Arc::get_mut(&mut ctx).unwrap().cfg.selection.regions = vec!["🇭🇰".to_string()];
    {
        let mut rt = class.lock().await;
        rt.active = None;
    }
    activate_initial(&ctx, &class).await;
    assert_eq!(
        trace.starts(),
        vec!["🇭🇰 Hong Kong丨01".to_string()],
        "initial activation must not try the out-of-allowlist incumbent"
    );
    let installed = class
        .lock()
        .await
        .active
        .as_ref()
        .map(|a| a.node.name().to_string());
    assert_eq!(installed.as_deref(), Some("🇭🇰 Hong Kong丨01"));
    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn initial_activation_respects_per_class_region_override() {
    // Global [selection].regions stays EMPTY (would admit any node), but the
    // class carries [classes.<name>.selection] with a Hong Kong-only
    // allowlist: the class-scoped override must skip the out-of-allowlist
    // incumbent even though global policy would have admitted it.
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("🇭🇰 Hong Kong丨01")],
        [("🇭🇰 Hong Kong丨01", 204)],
        1,
        0,
        "initial-class-regions",
    );
    let mut ctx = ctx;
    Arc::get_mut(&mut ctx).unwrap()
        .cfg
        .classes
        .get_mut("dev")
        .unwrap()
        .selection = Some(crate::config::ClassSelection {
        regions: Some(vec!["🇭🇰".to_string()]),
        auto_switch: None,
    });
    {
        let mut rt = class.lock().await;
        rt.active = None;
    }
    activate_initial(&ctx, &class).await;
    assert_eq!(
        trace.starts(),
        vec!["🇭🇰 Hong Kong丨01".to_string()],
        "initial activation must not try the node outside the class allowlist"
    );
    let installed = class
        .lock()
        .await
        .active
        .as_ref()
        .map(|a| a.node.name().to_string());
    assert_eq!(installed.as_deref(), Some("🇭🇰 Hong Kong丨01"));
    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn ranked_candidates_region_filter_restricts_automatic_pool() {
    let dir = test_dir("regions");
    let cfg = test_config(dir.join("state.json"), 10);
    let _catalog = cfg.subscriptions.clone();
    let nodes = vec![
        node("🇭🇰 Hong Kong丨01"),
        node("🇭🇰 Hong Kong丨02"),
        node("🇯🇵 Japan丨01"),
    ];
    let mut state = StateFile::default();
    state.activate_subscription(LEGACY_SUBSCRIPTION_NAME);
    for n in &nodes {
        state
            .nodes
            .insert(n.name().to_string(), stats(1.0, Some(100.0)));
    }
    let all = ranked_candidates(&nodes, &state, &[]);
    assert_eq!(all.len(), 3, "no filter keeps the whole pool");
    let hk_only = ranked_candidates(&nodes, &state, &["🇭🇰".to_string()]);
    assert_eq!(hk_only.len(), 2);
    assert!(hk_only.iter().all(|n| n.name().contains("🇭🇰")));
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn pinned_mode_health_failure_stays_on_active_node() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("alternate", 204), ("current", 503)],
        2,
        0,
        "health-pinned",
    );
    let mut ctx = ctx;
    Arc::get_mut(&mut ctx).unwrap().cfg.selection.auto_switch = false;
    recover_after_health_failure(&ctx, &class).await;
    assert_eq!(
        trace.starts(),
        Vec::<String>::new(),
        "pinned mode must not switch away from the active node on health failure"
    );
    // Manual switching stays available and unrestricted.
    let outcome = switch_to(&ctx, &class, "alternate").await.unwrap();
    assert_eq!(outcome.installed, "alternate");
    assert_eq!(trace.starts(), vec!["alternate"]);
    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn pinned_mode_without_active_node_still_activates() {
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("alternate", 204), ("current", 204)],
        2,
        0,
        "health-pinned-activate",
    );
    let mut ctx = ctx;
    Arc::get_mut(&mut ctx).unwrap().cfg.selection.auto_switch = false;
    {
        let mut rt = class.lock().await;
        rt.active = None;
    }
    recover_after_health_failure(&ctx, &class).await;
    assert!(
        !trace.starts().is_empty(),
        "establishing a path with no active node is activation, not switching"
    );
    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn health_streak_is_class_local_when_classes_share_a_node() {
    // Two classes share the active node (the default topology: every class
    // ranks the same pool). With per-class health targets their verdicts
    // diverge; the dev class's failure streak must survive the browser
    // class's ok on the same node, or the recovery threshold is
    // unreachable — the exact suppression shape of the 2026-09-22
    // incident.
    let (ctx, _class, _trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [],
        1,
        0,
        "class-local-streak",
    );
    let mut dev = tokio::sync::Mutex::new(ClassRuntime {
        name: "dev".into(),
        listen_addr: "127.0.0.1:17878".parse().unwrap(),
        route: Arc::new(RwLock::new(ClassRoute::default())),
        active: None,
        auto_recovery: AutoRecoveryBackoff::default(),
        health_failures: 0,
    });
    let shared = node("current");
    let incumbent = ActiveNode {
        node: shared.clone(),
        handle: Box::new(FakeHandle::incumbent("incumbent-dev", Arc::new(FakeTrace::default()))),
        path_connections: Arc::new(AtomicU64::new(0)),
    };
    dev.get_mut().active = Some(incumbent);
    let mut browser = tokio::sync::Mutex::new(ClassRuntime {
        name: "browser".into(),
        listen_addr: "127.0.0.1:17880".parse().unwrap(),
        route: Arc::new(RwLock::new(ClassRoute::default())),
        active: Some(ActiveNode {
            node: shared,
            handle: Box::new(FakeHandle::incumbent("incumbent-browser", Arc::new(FakeTrace::default()))),
            path_connections: Arc::new(AtomicU64::new(0)),
        }),
        auto_recovery: AutoRecoveryBackoff::default(),
        health_failures: 0,
    });

    let (streak, has_active) = record_health_outcome(&ctx, dev.get_mut(), false);
    assert!((streak, has_active) == (1, true));
    // The other class's ok resets only the shared DISPLAY counter.
    let (ok_streak, _) = record_health_outcome(&ctx, browser.get_mut(), true);
    assert_eq!(ok_streak, 0);
    let display = lock_state(&ctx.state)
        .nodes
        .get("current")
        .unwrap()
        .consecutive_health_failures;
    assert_eq!(display, 0, "shared display counter follows the last verdict");
    // dev's streak survives the reset and keeps climbing.
    let (streak, _) = record_health_outcome(&ctx, dev.get_mut(), false);
    assert_eq!(streak, 2, "the class-local streak is not reset by another class");
    // A class ok clears its own streak.
    let (streak, _) = record_health_outcome(&ctx, dev.get_mut(), true);
    assert_eq!(streak, 0);
    // No active path: the caller establishes one immediately.
    dev.get_mut().active = None;
    let (streak, has_active) = record_health_outcome(&ctx, dev.get_mut(), false);
    assert!(!has_active);
    assert_eq!(streak, ctx.cfg.health.fail_threshold);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn class_target_precheck_failures_never_touch_the_shared_scores() {
    // The try_candidates gate mirrors the probe-path rule: a candidate that
    // fails a pre-check judged against a class-specific target must not
    // write a probe failure into the shared scores.
    let (ctx, class, _trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("alternate", 503)],
        1,
        0,
        "trycand-override-gate",
    );
    let mut ctx = ctx;
    install_class_health_override(&mut ctx, "dev", "connect://api.example:443");
    let before = lock_state(&ctx.state)
        .nodes
        .get("alternate")
        .unwrap()
        .probe_count;

    let mut rt = class.lock().await;
    let installed =
        try_candidates(&ctx, &mut rt, &[node("alternate")], "test").await;
    assert_eq!(installed, None, "the 503 pre-check fails the candidate");
    drop(rt);
    let after = lock_state(&ctx.state)
        .nodes
        .get("alternate")
        .unwrap()
        .probe_count;
    assert_eq!(
        after, before,
        "an override class's pre-check failure must not write shared scores"
    );
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn class_target_probe_verdicts_never_touch_the_shared_scores() {
    // The on-demand probe still REPORTS per-node verdicts against the class
    // target, but with an override active those verdicts must not write the
    // shared per-node EMAs — one destination's opinion must not steer every
    // class's automatic ranking.
    let (ctx, _class, _trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("current", 503), ("alternate", 204)],
        1,
        0,
        "class-target-no-ema",
    );
    let mut ctx = ctx;
    install_class_health_override(&mut ctx, "dev", "connect://api.example:443");
    let before: Vec<(f64, u64)> = {
        let st = lock_state(&ctx.state);
        ["current", "alternate"]
            .iter()
            .map(|n| {
                let s = st.nodes.get(*n).unwrap();
                (s.success_ema, s.probe_count)
            })
            .collect()
    };

    let results = probe_now(&ctx, "dev").await;
    assert_eq!(
        results.iter().map(|r| r.node.as_str()).collect::<Vec<_>>(),
        vec!["current", "alternate"],
        "the listing carries every pool node, in pool order (ordering pin: probe_now_results_follow_pool_order_not_completion_order)"
    );
    assert_eq!(
        results.iter().map(|r| r.ok).collect::<Vec<_>>(),
        vec![false, true],
        "verdicts are still reported per node"
    );
    let after: Vec<(f64, u64)> = {
        let st = lock_state(&ctx.state);
        ["current", "alternate"]
            .iter()
            .map(|n| {
                let s = st.nodes.get(*n).unwrap();
                (s.success_ema, s.probe_count)
            })
            .collect()
    };
    assert_eq!(before, after, "an override class never writes shared EMAs");

    // Without an override the same flow records (legacy behavior).
    let (ctx2, _c2, _t2, dir2) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("current", 503), ("alternate", 204)],
        1,
        0,
        "global-target-records",
    );
    let before2 = lock_state(&ctx2.state).nodes.get("current").unwrap().probe_count;
    probe_now(&ctx2, "dev").await;
    let after2 = lock_state(&ctx2.state).nodes.get("current").unwrap().probe_count;
    assert!(after2 > before2, "the global target keeps recording");

    std::fs::remove_dir_all(dir).ok();
    std::fs::remove_dir_all(dir2).ok();
}

#[tokio::test]
async fn per_class_health_target_reaches_the_wire() {
    // The class carries [classes.dev.health] url = connect://…: the
    // candidate pre-check and the on-demand probe must issue a CONNECT to
    // that authority — not the global generate_204 GET that can stay green
    // while the class's real destination is blackholed.
    // Three plane starts: both nodes probed, then "alternate" started again
    // for the manual switch's pre-check.
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("current", 204), ("alternate", 204), ("alternate", 204)],
        1,
        0,
        "class-health-target",
    );
    let mut ctx = ctx;
    install_class_health_override(&mut ctx, "dev", "connect://api.example:443");

    // On-demand probe through the class's effective target. The count
    // assertion keeps the all() honest: an empty recording would pass it.
    let results = probe_now(&ctx, "dev").await;
    assert!(results.iter().all(|r| r.ok), "fake plane answers 204 to both forms");
    let requests = trace.requests();
    assert_eq!(
        requests.len(),
        results.len(),
        "every started plane must have recorded its request line"
    );
    assert!(
        requests
            .iter()
            .all(|line| line.starts_with("CONNECT api.example:443 ")),
        "every probe must use the class's CONNECT target: {requests:?}"
    );

    // The candidate pre-check (switch path) uses the same class target.
    let before = trace.requests().len();
    let outcome = switch_to(&ctx, &class, "alternate").await.unwrap();
    assert_eq!(outcome.installed, "alternate");
    let precheck_lines: Vec<String> = trace.requests()[before..].to_vec();
    assert!(
        precheck_lines
            .iter()
            .any(|line| line.starts_with("CONNECT api.example:443 ")),
        "the activation pre-check must CONNECT to the class target: {precheck_lines:?}"
    );

    // Without an override the same flow issues the global GET shape.
    let (ctx2, _class2, trace2, dir2) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("current", 204), ("alternate", 204)],
        1,
        0,
        "class-health-default",
    );
    let results2 = probe_now(&ctx2, "dev").await;
    assert!(results2.iter().all(|r| r.ok));
    let requests2 = trace2.requests();
    assert_eq!(
        requests2.len(),
        results2.len(),
        "every started plane must have recorded its request line"
    );
    assert!(
        requests2.iter().all(|line| line.starts_with("GET http://")),
        "no override keeps the global GET shape: {requests2:?}"
    );

    std::fs::remove_dir_all(dir).ok();
    std::fs::remove_dir_all(dir2).ok();
}

/// The pool-order contract, pinned deterministically: four nodes with
/// NON-MONOTONIC responder delays (pool positions 1-4 answer in
/// 200/600/400/100 ms) and a mixed verdict ("late" fails 503, so its rtt
/// is None), so pool order and the six re-rankings a collector could
/// apply — completion (delay-ascending), rtt-ascending (None ranked as
/// the worst latency, so "late" sorts last), rtt-descending (same None
/// rule, so "late" sorts first), name-sorted, failures-first,
/// successes-first — are seven distinct permutations. Mutation-verified
/// 2026-09-26: completion, name-sort, rtt-descending, failures-first and
/// successes-first all caught with their predicted signatures; an
/// rtt-ascending collector also differs from pool order ([last, current,
/// middle, late]) and dies on the same assert.
/// The teeth rely on two fixture invariants: PROBE_NOW_CONCURRENCY must
/// stay >= 3 for this fixture so probes overlap (measured threshold: at 2
/// the completion axis goes vacuous; the rtt/name/verdict axes bite at
/// any concurrency), and the largest delay (600 ms) must stay under the
/// fixture's health.timeout_ms (1000 ms) so no probe times out.
#[tokio::test]
async fn probe_now_results_follow_pool_order_not_completion_order() {
    let (ctx, _class, _trace, dir) = recovery_fixture_with_delays(
        vec![node("current"), node("middle"), node("late"), node("last")],
        [("current", 204), ("middle", 204), ("late", 503), ("last", 204)],
        1,
        0,
        "probe-pool-order",
        HashMap::from([
            ("current".to_string(), 200u64),
            ("middle".to_string(), 600),
            ("late".to_string(), 400),
            ("last".to_string(), 100),
        ]),
    );
    let results = probe_now(&ctx, "dev").await;
    assert_eq!(
        results
            .iter()
            .map(|r| (r.node.as_str(), r.ok))
            .collect::<Vec<_>>(),
        vec![("current", true), ("middle", true), ("late", false), ("last", true)],
        "wrong orderings: completion [last, current, late, middle]; name [current, last, late, middle]; rtt-asc [last, current, middle, late]; rtt-desc [late, middle, current, last]; failures-first [late, current, middle, last]; successes-first [current, middle, last, late]"
    );
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn per_class_pinned_override_holds_while_global_policy_stays_automatic() {
    // Mirror of pinned_mode_health_failure_stays_on_active_node with the
    // pin moved from the global flag to [classes.dev.selection]: the global
    // policy stays automatic, so only the per-class override can explain a
    // stay-put outcome.
    let (ctx, class, trace, dir) = recovery_fixture(
        vec![node("current"), node("alternate")],
        [("alternate", 204), ("current", 503)],
        2,
        0,
        "health-class-pinned",
    );
    let mut ctx = ctx;
    Arc::get_mut(&mut ctx).unwrap()
        .cfg
        .classes
        .get_mut("dev")
        .unwrap()
        .selection = Some(crate::config::ClassSelection {
        regions: None,
        auto_switch: Some(false),
    });
    recover_after_health_failure(&ctx, &class).await;
    assert_eq!(
        trace.starts(),
        Vec::<String>::new(),
        "the per-class pin must hold even though global policy is automatic"
    );
    // Manual switching stays available and unrestricted by the override.
    let outcome = switch_to(&ctx, &class, "alternate").await.unwrap();
    assert_eq!(outcome.installed, "alternate");
    assert_eq!(trace.starts(), vec!["alternate"]);
    stop_draining(&ctx).await;
    std::fs::remove_dir_all(dir).ok();
}
