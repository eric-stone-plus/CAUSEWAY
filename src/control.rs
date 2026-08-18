//! Local control socket: the one runtime control surface of the daemon.
//!
//! A Unix socket in the state dir (`<state_dir>/run/control.sock`, mode 0600)
//! speaking newline-delimited JSON. Used only by the bundled `causeway
//! switch` subcommand — same user, loopback-class isolation by filesystem
//! permissions, no network exposure. Deliberately not HTTP and not on TCP:
//! anything reachable from a socket is reachable from the network namespace.
//!
//! Request/response is one JSON object per line each way. A switch request
//! may take tens of seconds (candidate pre-checks), so clients must use a
//! generous timeout on `Switch` and a short one on `Ping`/`Status`.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::config::Config;
use crate::score::NodeStats;

/// Socket filename inside the daemon run dir (state dir + `/run`).
pub const SOCKET_NAME: &str = "control.sock";

/// One line per request, capped so a misbehaving peer cannot grow memory.
const MAX_REQUEST_BYTES: u64 = 4096;
/// A local socket connect should complete immediately. A timeout means its
/// ownership cannot be established safely, so startup fails closed.
const SOCKET_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

pub fn socket_path(cfg: &Config) -> PathBuf {
    cfg.state_file
        .parent()
        .map(|p| p.join("run"))
        .unwrap_or_else(|| PathBuf::from("/tmp/causeway-run"))
        .join(SOCKET_NAME)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct OwnedSocket {
    path: PathBuf,
    identity: SocketIdentity,
}

pub(crate) struct BoundControlSocket {
    listener: UnixListener,
    _owned_socket: OwnedSocket,
}

impl OwnedSocket {
    fn capture(path: PathBuf) -> anyhow::Result<Self> {
        use std::os::unix::fs::FileTypeExt;
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect bound control socket {}", path.display()))?;
        if !metadata.file_type().is_socket() {
            bail!(
                "bound control socket path {} is no longer a Unix socket",
                path.display()
            );
        }
        Ok(Self {
            path,
            identity: SocketIdentity::from_metadata(&metadata),
        })
    }
}

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if let Err(error) = remove_socket_if_owned(&self.path, self.identity) {
            warn!(path = %self.path.display(), error = %error, "failed to clean up owned control socket");
        }
    }
}

fn remove_socket_if_owned(path: &Path, expected: SocketIdentity) -> anyhow::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect control socket {}", path.display()))
        }
    };
    if metadata.file_type().is_socket() && SocketIdentity::from_metadata(&metadata) == expected {
        std::fs::remove_file(path)
            .with_context(|| format!("remove control socket {}", path.display()))?;
    }
    Ok(())
}

async fn remove_stale_control_socket(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect control socket {}", path.display()))
        }
    };
    if !metadata.file_type().is_socket() {
        bail!(
            "refusing to replace non-socket control path {}; move it aside and restart CAUSEWAY",
            path.display()
        );
    }
    let identity = SocketIdentity::from_metadata(&metadata);

    match tokio::time::timeout(SOCKET_CONNECT_TIMEOUT, UnixStream::connect(path)).await {
        Ok(Ok(_)) => bail!(
            "control socket {} is already active; use the running CAUSEWAY daemon",
            path.display()
        ),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            let current = std::fs::symlink_metadata(path)
                .with_context(|| format!("re-inspect stale control socket {}", path.display()))?;
            if !current.file_type().is_socket()
                || SocketIdentity::from_metadata(&current) != identity
            {
                bail!(
                    "control socket {} changed while checking it; refusing to remove it",
                    path.display()
                );
            }
            std::fs::remove_file(path)
                .with_context(|| format!("remove stale control socket {}", path.display()))
        }
        Ok(Err(error)) => Err(error).with_context(|| {
            format!(
                "cannot verify whether control socket {} is stale; refusing to remove it",
                path.display()
            )
        }),
        Err(_) => bail!(
            "timed out checking control socket {}; refusing to remove it",
            path.display()
        ),
    }
}

/// Claim the control socket before state, adapters, or TCP listeners start.
/// This is also the compatibility guard against older daemons that predate
/// the process lock but still own a live control socket.
pub(crate) async fn bind(path: PathBuf) -> anyhow::Result<BoundControlSocket> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create control socket dir {}", dir.display()))?;
    }
    remove_stale_control_socket(&path).await?;

    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind control socket {}", path.display()))?;
    let owned_socket = OwnedSocket::capture(path.clone())?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure control socket {}", path.display()))?;
    }
    info!(path = %path.display(), "control socket listening");
    Ok(BoundControlSocket {
        listener,
        _owned_socket: owned_socket,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Request {
    /// Liveness probe; replies ok with no payload.
    Ping,
    /// Live snapshot of one class: active path + in-memory node stats.
    Status { class: String },
    /// Switch a class to a node; falls back by score if the requested node
    /// fails its pre-check. No-op when the node is already active.
    Switch { class: String, node: String },
    /// Atomically switch every class to the named subscription profile. A
    /// request for the active profile refreshes it through the same staged,
    /// check-before-switch flow.
    SwitchSubscription { name: String },
    /// End-to-end latency test of every node (url-test style): a fresh data
    /// plane per node + generate_204 check, EMAs recorded, no switch. May
    /// take tens of seconds — use a generous client timeout.
    ProbeNow { class: String },
    /// Snapshot of the recent-events ring buffer (newest last).
    Events,
    /// Re-read the config file and subscription files; the node pool is
    /// applied live. Class/listen layout changes require a daemon restart
    /// and are reported as an error.
    Reload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchOutcome {
    /// Node the client asked for
    pub requested: String,
    /// Node actually installed
    pub installed: String,
    /// True when the requested node failed its pre-check and a scored
    /// fallback won instead
    pub fallback: bool,
}

/// One configured subscription profile exposed to control clients. Source
/// paths and URLs deliberately never cross the control socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionSummary {
    pub name: String,
    /// None when the daemon has not loaded this profile in the current
    /// session and therefore cannot report an authoritative count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_count: Option<usize>,
}

/// Result of an atomic subscription switch or refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionSwitchOutcome {
    pub previous: String,
    pub active: String,
    pub node_count: usize,
    /// True when the requested profile was already active and its source was
    /// fetched/re-read and reactivated.
    pub refreshed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub class: String,
    pub active_node: Option<String>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub generation: u64,
    /// Live stats including in-memory health-failure counters (the state
    /// file only carries them at save points)
    pub nodes: BTreeMap<String, NodeStats>,
    /// Cumulative bytes per node since daemon start (route-attributed at
    /// connection accept time; up = client → node, down = node → client).
    /// Session-only, not persisted.
    pub traffic: BTreeMap<String, NodeTraffic>,
    /// Connections currently piped by the listener
    pub active_conns: u64,
    /// Runtime-selected profile. None means an older daemon omitted this
    /// field, rather than implying a particular configured profile.
    #[serde(default)]
    pub active_subscription: Option<String>,
    /// Monotonic (within one daemon process) subscription publication
    /// generation. `None` means an older daemon cannot support safe
    /// reconciliation after a mutation reply is lost.
    #[serde(default)]
    pub subscription_generation: Option<u64>,
    /// Whether any subscription mutation is queued or executing. This is an
    /// option so an omitted field from an older daemon is not mistaken for an
    /// authoritative `false`.
    #[serde(default)]
    pub subscription_txn_in_progress: Option<bool>,
    /// Names and safe aggregate metadata only; subscription sources and
    /// credentials are never included.
    #[serde(default)]
    pub available_subscriptions: Vec<SubscriptionSummary>,
    /// Nodes in the active subscription pool, including nodes without stats.
    #[serde(default)]
    pub available_nodes: Vec<String>,
}

/// Cumulative byte counts for one node.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct NodeTraffic {
    /// client → node
    pub up: u64,
    /// node → client
    pub down: u64,
}

/// Result of one end-to-end node test (`ProbeNow`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub node: String,
    pub ok: bool,
    /// End-to-end RTT in milliseconds (None when the test failed)
    pub rtt_ms: Option<f64>,
    /// Non-2xx HTTP status, when that is why the test failed
    pub http_status: Option<u16>,
    /// Error detail (data plane start failure, timeout, …)
    pub error: Option<String>,
}

/// Notable daemon events, newest last. Served from a bounded in-memory ring
/// buffer; only for the TUI, never persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Event {
    /// A path was installed on a class (initial / manual / health-failures /
    /// challenger-wins)
    Switched {
        unix: i64,
        class: String,
        node: String,
        reason: String,
        generation: u64,
    },
    /// A candidate failed activation during a switch attempt
    ActivationFailed {
        unix: i64,
        class: String,
        node: String,
        error: String,
    },
    /// Health check failed on the active path
    HealthFailed {
        unix: i64,
        class: String,
        node: String,
        consecutive: u32,
    },
    /// A probe cycle finished (periodic / startup / on-demand)
    Probed {
        unix: i64,
        source: String,
        ok: usize,
        total: usize,
    },
    /// Config reload attempt finished
    Reloaded { unix: i64, detail: String },
    /// A subscription profile was atomically installed for every class.
    SubscriptionChanged {
        unix: i64,
        previous: String,
        active: String,
        node_count: usize,
        refreshed: bool,
    },
    /// A subscription change failed before commit. `error` must be sanitized
    /// by the producer and must never include a URL, path, or credential.
    SubscriptionChangeFailed {
        unix: i64,
        profile: String,
        error: String,
    },
}

impl Event {
    /// Unix timestamp carried by every variant (for age display).
    pub fn unix(&self) -> i64 {
        match self {
            Event::Switched { unix, .. }
            | Event::ActivationFailed { unix, .. }
            | Event::HealthFailed { unix, .. }
            | Event::Probed { unix, .. }
            | Event::Reloaded { unix, .. }
            | Event::SubscriptionChanged { unix, .. }
            | Event::SubscriptionChangeFailed { unix, .. } => *unix,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch: Option<SwitchOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_switch: Option<SubscriptionSwitchOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<Vec<ProbeResult>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<Event>>,
    /// Free-form success detail (reload summaries etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Reply {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            switch: None,
            subscription_switch: None,
            probe: None,
            events: None,
            message: None,
        }
    }

    pub fn ok_status(status: StatusSnapshot) -> Self {
        Self {
            ok: true,
            error: None,
            status: Some(status),
            switch: None,
            subscription_switch: None,
            probe: None,
            events: None,
            message: None,
        }
    }

    pub fn ok_switch(switch: SwitchOutcome) -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            switch: Some(switch),
            subscription_switch: None,
            probe: None,
            events: None,
            message: None,
        }
    }

    pub fn ok_subscription_switch(subscription_switch: SubscriptionSwitchOutcome) -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            switch: None,
            subscription_switch: Some(subscription_switch),
            probe: None,
            events: None,
            message: None,
        }
    }

    pub fn ok_probe(probe: Vec<ProbeResult>) -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            switch: None,
            subscription_switch: None,
            probe: Some(probe),
            events: None,
            message: None,
        }
    }

    pub fn ok_events(events: Vec<Event>) -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            switch: None,
            subscription_switch: None,
            probe: None,
            events: Some(events),
            message: None,
        }
    }

    pub fn ok_msg(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            switch: None,
            subscription_switch: None,
            probe: None,
            events: None,
            message: Some(message.into()),
        }
    }

    pub fn err(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
            status: None,
            switch: None,
            subscription_switch: None,
            probe: None,
            events: None,
            message: None,
        }
    }
}

/// Bind the control socket and serve requests until `shutdown` flips.
/// The handler runs per request; long-running `Switch` handlers serialize on
/// the supervisor's class lock.
pub async fn serve<F, Fut>(
    bound: BoundControlSocket,
    handler: F,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Reply> + Send,
{
    let BoundControlSocket {
        listener,
        _owned_socket,
    } = bound;

    let handler = std::sync::Arc::new(handler);
    let mut connections = JoinSet::new();
    let mut next_conn: u64 = 0;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                log_connection_result(completed.expect("guarded by non-empty connection set"));
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(error = %e, "control socket accept failed");
                        continue;
                    }
                };
                let conn = next_conn;
                next_conn += 1;
                let handler = std::sync::Arc::clone(&handler);
                let conn_shutdown = shutdown.clone();
                connections.spawn(async move {
                    (conn, handle_conn(stream, &*handler, conn_shutdown).await)
                });
            }
        }
    }
    // Dropping the listener closes the admission boundary. Requests that have
    // not supplied a complete line are cancelled by their shutdown receiver;
    // a parsed request is allowed to finish because cancelling a subscription
    // transaction between its durable and live commits is not rollback-safe.
    drop(listener);
    info!(in_flight = connections.len(), "control socket draining");
    while let Some(completed) = connections.join_next().await {
        log_connection_result(completed);
    }
    info!("control socket closed");
    Ok(())
}

fn log_connection_result(completed: Result<(u64, anyhow::Result<()>), tokio::task::JoinError>) {
    match completed {
        Ok((_, Ok(()))) => {}
        Ok((conn, Err(e))) => {
            warn!(conn, error = %format!("{e:#}"), "control connection error");
        }
        Err(e) => warn!(error = %e, "control connection task ended abnormally"),
    }
}

/// One connection = one request + one reply (KISS; the client reconnects).
async fn handle_conn<F, Fut>(
    stream: UnixStream,
    handler: &F,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()>
where
    F: Fn(Request) -> Fut,
    Fut: Future<Output = Reply>,
{
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd).take(MAX_REQUEST_BYTES);
    let mut line = String::new();
    if *shutdown.borrow() {
        return Ok(());
    }
    let read = tokio::select! {
        biased;
        _ = shutdown.changed() => return Ok(()),
        read = rd.read_line(&mut line) => read.context("read control request")?,
    };
    if read == 0 {
        return Ok(()); // client closed without a request
    }
    // No handler side effects have happened yet, so a request whose line races
    // with shutdown can still be rejected safely. Once dispatched below, the
    // server tracks and drains it before reporting that it has stopped.
    if *shutdown.borrow() {
        return Ok(());
    }
    let reply = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) => handler(req).await,
        Err(e) => Reply::err(format!("invalid request: {e}")),
    };
    let mut out = serde_json::to_string(&reply).context("serialize control reply")?;
    out.push('\n');
    wr.write_all(out.as_bytes())
        .await
        .context("write control reply")?;
    Ok(())
}

/// One-shot client for `causeway switch`.
pub struct Client {
    path: PathBuf,
}

impl Client {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Connect, send one request, read one reply. The timeout covers connect,
    /// write and read — a `Switch` may legitimately take tens of seconds.
    pub async fn request(&self, req: &Request, timeout: Duration) -> anyhow::Result<Reply> {
        let stream = tokio::time::timeout(timeout, UnixStream::connect(&self.path))
            .await
            .context("connect to control socket (is the daemon running?)")?
            .with_context(|| format!("connect to control socket {}", self.path.display()))?;
        let (rd, mut wr) = stream.into_split();

        let mut line = serde_json::to_string(req).context("serialize control request")?;
        line.push('\n');
        tokio::time::timeout(timeout, wr.write_all(line.as_bytes()))
            .await
            .context("timed out writing control request")?
            .context("write control request")?;

        let mut buf = String::new();
        if tokio::time::timeout(timeout, BufReader::new(rd).read_line(&mut buf))
            .await
            .context("timed out waiting for control reply")?
            .context("read control reply")?
            == 0
        {
            bail!("control socket closed without a reply");
        }
        serde_json::from_str(&buf).context("parse control reply")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SOCKET_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_socket_path(label: &str) -> PathBuf {
        let seq = TEST_SOCKET_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "causeway-control-test-{}-{seq}",
                std::process::id()
            ))
            .join(format!("{label}.sock"))
    }

    async fn wait_for_socket(path: &std::path::Path) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("control socket should be created");
    }

    fn remove_test_socket(path: &std::path::Path) {
        std::fs::remove_file(path).ok();
        if let Some(parent) = path.parent() {
            std::fs::remove_dir(parent).ok();
        }
    }

    fn roundtrip<T: Serialize + serde::de::DeserializeOwned>(val: &T) -> T {
        serde_json::from_str(&serde_json::to_string(val).unwrap()).unwrap()
    }

    #[test]
    fn request_tags_are_stable() {
        assert_eq!(
            serde_json::to_string(&Request::Ping).unwrap(),
            r#"{"cmd":"ping"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::Status {
                class: "dev".into()
            })
            .unwrap(),
            r#"{"cmd":"status","class":"dev"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::Switch {
                class: "dev".into(),
                node: "hk01".into()
            })
            .unwrap(),
            r#"{"cmd":"switch","class":"dev","node":"hk01"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::SwitchSubscription {
                name: "secondary".into()
            })
            .unwrap(),
            r#"{"cmd":"switch-subscription","name":"secondary"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::ProbeNow {
                class: "dev".into()
            })
            .unwrap(),
            r#"{"cmd":"probe-now","class":"dev"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::Events).unwrap(),
            r#"{"cmd":"events"}"#
        );
        assert_eq!(
            serde_json::to_string(&Request::Reload).unwrap(),
            r#"{"cmd":"reload"}"#
        );
    }

    #[test]
    fn event_tags_are_stable() {
        assert_eq!(
            serde_json::to_string(&Event::Switched {
                unix: 1,
                class: "dev".into(),
                node: "hk01".into(),
                reason: "manual".into(),
                generation: 4,
            })
            .unwrap(),
            r#"{"kind":"switched","unix":1,"class":"dev","node":"hk01","reason":"manual","generation":4}"#
        );
        assert_eq!(
            serde_json::to_string(&Event::SubscriptionChanged {
                unix: 2,
                previous: "primary".into(),
                active: "secondary".into(),
                node_count: 12,
                refreshed: false,
            })
            .unwrap(),
            r#"{"kind":"subscription-changed","unix":2,"previous":"primary","active":"secondary","node_count":12,"refreshed":false}"#
        );
        assert_eq!(
            serde_json::to_string(&Event::SubscriptionChangeFailed {
                unix: 3,
                profile: "secondary".into(),
                error: "profile refresh failed".into(),
            })
            .unwrap(),
            r#"{"kind":"subscription-change-failed","unix":3,"profile":"secondary","error":"profile refresh failed"}"#
        );
    }

    #[test]
    fn reply_roundtrips() {
        let mut nodes = BTreeMap::new();
        nodes.insert("hk01".to_string(), NodeStats::default());
        let snap = StatusSnapshot {
            class: "dev".into(),
            active_node: Some("hk01".into()),
            socks_port: Some(41381),
            http_port: Some(37965),
            generation: 3,
            nodes,
            traffic: BTreeMap::new(),
            active_conns: 0,
            active_subscription: Some("primary".into()),
            subscription_generation: Some(7),
            subscription_txn_in_progress: Some(false),
            available_subscriptions: vec![
                SubscriptionSummary {
                    name: "primary".into(),
                    node_count: Some(1),
                },
                SubscriptionSummary {
                    name: "secondary".into(),
                    node_count: None,
                },
            ],
            available_nodes: vec!["hk01".into()],
        };
        let status = roundtrip(&Reply::ok_status(snap)).status.unwrap();
        assert_eq!(status.active_subscription.as_deref(), Some("primary"));
        assert_eq!(status.subscription_generation, Some(7));
        assert_eq!(status.subscription_txn_in_progress, Some(false));
        assert_eq!(status.available_subscriptions.len(), 2);
        assert_eq!(status.available_nodes, ["hk01"]);

        let probed = vec![ProbeResult {
            node: "hk01".into(),
            ok: true,
            rtt_ms: Some(184.2),
            http_status: None,
            error: None,
        }];
        assert!(roundtrip(&Reply::ok_probe(probed)).probe.unwrap()[0].ok);

        let events = vec![Event::Probed {
            unix: 1,
            source: "on-demand".into(),
            ok: 3,
            total: 4,
        }];
        assert!(roundtrip(&Reply::ok_events(events)).events.is_some());

        assert_eq!(
            roundtrip(&Reply::ok_msg("config OK")).message.as_deref(),
            Some("config OK")
        );

        let outcome = SwitchOutcome {
            requested: "hk01".into(),
            installed: "hk01".into(),
            fallback: false,
        };
        assert!(
            !roundtrip(&Reply::ok_switch(outcome))
                .switch
                .unwrap()
                .fallback
        );

        let subscription_outcome = SubscriptionSwitchOutcome {
            previous: "primary".into(),
            active: "secondary".into(),
            node_count: 12,
            refreshed: false,
        };
        assert_eq!(
            roundtrip(&Reply::ok_subscription_switch(subscription_outcome))
                .subscription_switch
                .unwrap()
                .active,
            "secondary"
        );

        let err = roundtrip(&Reply::err("no candidates"));
        assert!(!err.ok);
        assert_eq!(err.error.as_deref(), Some("no candidates"));
    }

    #[test]
    fn old_status_snapshot_defaults_subscription_fields() {
        let old = r#"{
            "class":"dev",
            "active_node":null,
            "socks_port":null,
            "http_port":null,
            "generation":0,
            "nodes":{},
            "traffic":{},
            "active_conns":0
        }"#;
        let snap: StatusSnapshot = serde_json::from_str(old).unwrap();
        assert_eq!(snap.active_subscription, None);
        assert_eq!(snap.subscription_generation, None);
        assert_eq!(snap.subscription_txn_in_progress, None);
        assert!(snap.available_subscriptions.is_empty());
        assert!(snap.available_nodes.is_empty());
    }

    #[test]
    fn old_reply_defaults_subscription_switch() {
        let reply: Reply = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(reply.subscription_switch.is_none());
    }

    #[tokio::test]
    async fn regular_control_path_is_preserved() {
        let path = test_socket_path("regular-file");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"keep").unwrap();

        let error = bind(path.clone())
            .await
            .err()
            .expect("a regular control path must be rejected");
        assert!(error.to_string().contains("non-socket"));
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        remove_test_socket(&path);
    }

    #[tokio::test]
    async fn symlink_control_path_is_preserved() {
        use std::os::unix::fs::symlink;

        let path = test_socket_path("symlink");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let target = path.parent().unwrap().join("target");
        std::fs::write(&target, b"keep").unwrap();
        symlink(&target, &path).unwrap();

        let error = bind(path.clone())
            .await
            .err()
            .expect("a symlink control path must be rejected");
        assert!(error.to_string().contains("non-socket"));
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_file(&target).unwrap();
        remove_test_socket(&path);
    }

    #[tokio::test]
    async fn live_control_socket_is_preserved() {
        let path = test_socket_path("live");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

        let error = bind(path.clone())
            .await
            .err()
            .expect("a live control socket must be rejected");
        assert!(error.to_string().contains("already active"));
        assert!(path.exists());
        drop(listener);
        remove_test_socket(&path);
    }

    #[tokio::test]
    async fn stale_control_socket_is_removed_and_rebound() {
        let path = test_socket_path("stale");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(listener);

        let bound = bind(path.clone()).await.unwrap();
        assert!(path.exists(), "startup must replace the stale socket");
        drop(bound);
        assert!(!path.exists(), "owned socket must be removed on drop");
        remove_test_socket(&path);
    }

    #[test]
    fn owned_socket_cleanup_preserves_replacement() {
        let path = test_socket_path("replacement");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let owned = OwnedSocket::capture(path.clone()).unwrap();
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();

        drop(owned);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        remove_test_socket(&path);
    }

    #[tokio::test]
    async fn shutdown_cancels_a_connection_without_a_complete_request() {
        let path = test_socket_path("partial-request");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handler_called = std::sync::Arc::clone(&called);
        let bound = bind(path.clone()).await.unwrap();
        let server = tokio::spawn(async move {
            serve(
                bound,
                move |_| {
                    handler_called.store(true, std::sync::atomic::Ordering::SeqCst);
                    async { Reply::ok_msg("unexpected") }
                },
                shutdown_rx,
            )
            .await
        });
        wait_for_socket(&path).await;

        let mut stream = UnixStream::connect(&path).await.unwrap();
        stream.write_all(br#"{"cmd":"ping""#).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown_tx.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("partial connection must not delay shutdown")
            .expect("control server task should not panic")
            .expect("control server should stop cleanly");
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        remove_test_socket(&path);
    }

    #[tokio::test]
    async fn shutdown_drains_a_dispatched_request_before_server_exit() {
        let path = test_socket_path("drain-request");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let handler_started = std::sync::Arc::clone(&started);
        let handler_release = std::sync::Arc::clone(&release);
        let bound = bind(path.clone()).await.unwrap();
        let mut server = tokio::spawn(async move {
            serve(
                bound,
                move |_| {
                    let started = std::sync::Arc::clone(&handler_started);
                    let release = std::sync::Arc::clone(&handler_release);
                    async move {
                        started.notify_one();
                        release.notified().await;
                        Reply::ok_msg("completed")
                    }
                },
                shutdown_rx,
            )
            .await
        });
        wait_for_socket(&path).await;

        let client = Client::new(path.clone());
        let request =
            tokio::spawn(
                async move { client.request(&Request::Ping, Duration::from_secs(2)).await },
            );
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .expect("handler should start");
        shutdown_tx.send(true).unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut server)
                .await
                .is_err(),
            "server must wait for an already-dispatched request"
        );
        release.notify_one();
        let reply = tokio::time::timeout(Duration::from_secs(2), request)
            .await
            .expect("client should receive the drained reply")
            .expect("client task should not panic")
            .expect("request should complete");
        assert_eq!(reply.message.as_deref(), Some("completed"));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server should exit after the request drains")
            .expect("control server task should not panic")
            .expect("control server should stop cleanly");
        remove_test_socket(&path);
    }

    #[test]
    fn socket_path_lives_in_state_run_dir() {
        let mut cfg: crate::config::Config = toml::from_str(
            r#"
[subscriptions]
files = ["/nonexistent-test.yaml"]

[classes.dev]
listen = "127.0.0.1:17879"
"#,
        )
        .unwrap();
        cfg.state_file = std::env::temp_dir().join("state.json");
        let p = socket_path(&cfg);
        assert_eq!(p.file_name().and_then(|n| n.to_str()), Some(SOCKET_NAME));
        assert!(p.to_string_lossy().contains("/run/"));
    }
}
