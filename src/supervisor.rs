//! Orchestration core: the full lifecycle of listening, periodic probing,
//! health checking, and score-driven switching.
//!
//! Switch flow (the zero-downtime key is "check before switch"):
//!   1. Start a new data plane on fresh ports (the old path is untouched
//!      throughout);
//!   2. Run the generate_204 health check through the new data plane's http
//!      port — **check first**;
//!   3. On success, flip the route in a single write lock (new connections
//!      take the new node) — **switch second**;
//!   4. Keep the old data plane until its captured client connections finish,
//!      subject to a bounded retirement fail-safe.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
#[cfg(test)]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use anyhow::{bail, Context};
use tokio::net::TcpListener;
use tokio::sync::{watch, OwnedMutexGuard, OwnedRwLockWriteGuard, Semaphore};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::config::{Config, SubscriptionsConfig};
use crate::control;
use crate::daemon_lock::DaemonLock;
use crate::dataplane::{
    AdapterWorkspace, DataPlane, DataPlaneHandle, DispatchPlane, SingboxPlane, SslocalPlane,
    StartSpec,
};
use crate::egress::{self, EgressSignature, StableEgressObserver};
use crate::events::EventLog;
use crate::health;
use crate::listener::{self, ClassRoute, SharedRoute};
use crate::probe;
use crate::score::{challenger_wins, score_cmp};
use crate::siteprobe::{self, SiteStatus, SiteVerdict};
use crate::state::{self, StateFile};
use crate::subscription::{self, Node};

/// Maximum candidates tried per switch (highest score first)
const MAX_SWITCH_CANDIDATES: usize = 5;
/// Failed health-triggered recovery attempts back off per class. The first
/// retry waits long enough to skip at least one normal 30-second health tick;
/// the cap still retries periodically after a prolonged provider outage.
const AUTO_RECOVERY_INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);
const AUTO_RECOVERY_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(15 * 60);
/// A remote refresh and several adapter pre-checks must finish before systemd's
/// stop deadline. This is a transaction fuse, not a client timeout: expiry
/// happens before the durable state commit, so staged paths can be discarded.
const SUBSCRIPTION_PRECOMMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);
/// `/proc` polling is deliberately slow enough to avoid becoming a route
/// monitor in disguise. A route-manager transient must remain unchanged for
/// the full debounce window before it can rebuild a data plane.
const EGRESS_OBSERVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
const EGRESS_STABLE_FOR: std::time::Duration = std::time::Duration::from_secs(15);
const EGRESS_REBUILD_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);
/// A retired path may outlive the configured minimum grace while real client
/// pipes still use it, but an abandoned counter or indefinitely open tunnel
/// must not retain a child process forever.
const RETIRED_PATH_MAX_EXTENSION: std::time::Duration = std::time::Duration::from_secs(30 * 60);
const RETIRED_PATH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

struct ActiveNode {
    node: Node,
    handle: Box<dyn DataPlaneHandle>,
    path_connections: Arc<AtomicU64>,
}

#[derive(Debug, Default)]
struct AutoRecoveryBackoff {
    consecutive_failures: u32,
    retry_not_before: Option<std::time::Instant>,
}

impl AutoRecoveryBackoff {
    fn is_ready_at(&self, now: std::time::Instant) -> bool {
        self.retry_not_before.is_none_or(|deadline| now >= deadline)
    }

    fn record_failure_at(&mut self, now: std::time::Instant) -> std::time::Duration {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let mut delay = AUTO_RECOVERY_INITIAL_BACKOFF;
        let mut doublings = self.consecutive_failures.saturating_sub(1);
        while doublings > 0 && delay < AUTO_RECOVERY_MAX_BACKOFF {
            delay = delay.saturating_mul(2).min(AUTO_RECOVERY_MAX_BACKOFF);
            doublings -= 1;
        }
        self.retry_not_before = Some(now + delay);
        delay
    }

    fn reset(&mut self) {
        self.consecutive_failures = 0;
        self.retry_not_before = None;
    }
}

struct ClassRuntime {
    name: String,
    listen_addr: SocketAddr,
    route: SharedRoute,
    active: Option<ActiveNode>,
    auto_recovery: AutoRecoveryBackoff,
}

/// The active profile name and its pool must always be published together.
/// Keeping the configured catalog in the same snapshot also makes status and
/// switch validation observe one coherent reload generation.
struct SubscriptionRuntime {
    active: String,
    nodes: Vec<Node>,
    catalog: SubscriptionsConfig,
    generation: u64,
}

enum PreparedSubscription {
    Fresh(subscription::PreparedProfile),
    Cached(Vec<Node>),
}

struct CacheCommitOutcome {
    prepared: Result<PreparedSubscription, ()>,
    reconfiguration: OwnedRwLockWriteGuard<()>,
    class_guards: Vec<OwnedMutexGuard<ClassRuntime>>,
}

#[cfg(test)]
#[derive(Clone)]
struct CacheCommitTestHook {
    before: Arc<dyn Fn() + Send + Sync>,
    after: Arc<dyn Fn() + Send + Sync>,
    precommit_timeout: std::time::Duration,
}

#[cfg(test)]
static CACHE_COMMIT_TEST_HOOKS: OnceLock<Mutex<HashMap<String, CacheCommitTestHook>>> =
    OnceLock::new();

#[cfg(test)]
struct CacheCommitTestHookGuard {
    target: String,
}

#[cfg(test)]
impl CacheCommitTestHookGuard {
    fn install(target: &str, hook: CacheCommitTestHook) -> Self {
        let mut hooks = CACHE_COMMIT_TEST_HOOKS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(
            hooks.insert(target.to_string(), hook).is_none(),
            "cache commit hook already installed for {target}"
        );
        Self {
            target: target.to_string(),
        }
    }
}

#[cfg(test)]
impl Drop for CacheCommitTestHookGuard {
    fn drop(&mut self) {
        if let Some(hooks) = CACHE_COMMIT_TEST_HOOKS.get() {
            hooks
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&self.target);
        }
    }
}

fn subscription_precommit_timeout(_target: &str) -> std::time::Duration {
    #[cfg(test)]
    if let Some(timeout) = CACHE_COMMIT_TEST_HOOKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(_target)
        .map(|hook| hook.precommit_timeout)
    {
        return timeout;
    }
    SUBSCRIPTION_PRECOMMIT_TIMEOUT
}

struct StagedNodes(Vec<ActiveNode>);

impl StagedNodes {
    fn new(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn push(&mut self, active: ActiveNode) {
        self.0.push(active);
    }

    fn iter(&self) -> std::slice::Iter<'_, ActiveNode> {
        self.0.iter()
    }

    fn drain(&mut self) -> std::vec::Drain<'_, ActiveNode> {
        self.0.drain(..)
    }
}

impl Drop for StagedNodes {
    fn drop(&mut self) {
        // DataPlane handles use kill_on_drop as the cancellation backstop.
        // Explicit async stop remains the normal path, but a timed-out future
        // must not leak a staged child merely because it cannot await here.
        self.0.clear();
    }
}

impl PreparedSubscription {
    fn nodes(&self) -> &[Node] {
        match self {
            Self::Fresh(prepared) => prepared.nodes(),
            Self::Cached(nodes) => nodes,
        }
    }

    fn into_nodes(self) -> Vec<Node> {
        match self {
            Self::Fresh(prepared) => prepared.into_nodes(),
            Self::Cached(nodes) => nodes,
        }
    }
}

/// Read-only context shared by tasks + mutable state handle
struct Ctx {
    cfg: Config,
    config_path: PathBuf,
    subscriptions: Arc<RwLock<SubscriptionRuntime>>,
    /// Serializes prepare/stage/commit across manual switches and reloads.
    subscription_txn: Arc<tokio::sync::Mutex<()>>,
    /// Counts both queued and executing subscription mutations. Status uses
    /// this to prevent a lost-reply client from reconciling against an old
    /// snapshot while its transaction is still staging.
    subscription_txns_in_progress: Arc<AtomicU64>,
    /// Prevent old-pool probes and node switches from crossing a profile
    /// publication boundary and writing into the new profile's statistics.
    reconfiguration: Arc<tokio::sync::RwLock<()>>,
    state: Arc<Mutex<StateFile>>,
    plane: Arc<dyn DataPlane>,
    /// Notable-events ring buffer served to the TUI
    events: Arc<EventLog>,
    /// Session traffic counters attributed by the listener
    traffic: Arc<listener::TrafficCounters>,
    /// Connections currently piped by the listeners
    conns: Arc<AtomicU64>,
    /// Old data planes waiting for their drain grace period. Keeping these
    /// tasks owned by the supervisor prevents detached adapter processes from
    /// outliving shutdown or racing a later cleanup pass.
    draining: Arc<tokio::sync::Mutex<JoinSet<()>>>,
    /// Retired paths normally wait out their connection-drain grace period.
    /// Shutdown closes that wait early while preserving explicit handle stop
    /// and child reaping; cancelling the task would lose that ownership.
    drain_shutdown: watch::Sender<bool>,
}

struct SubscriptionTxnStatusGuard(Arc<AtomicU64>);

impl SubscriptionTxnStatusGuard {
    fn begin(counter: &Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, AtomicOrdering::SeqCst);
        Self(Arc::clone(counter))
    }
}

impl Drop for SubscriptionTxnStatusGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, AtomicOrdering::SeqCst);
    }
}

/// Snapshot of the current node pool.
fn pool(ctx: &Ctx) -> Vec<Node> {
    ctx.subscriptions
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .nodes
        .clone()
}

/// Recover from a poisoned state lock: a panicking task must not take down
/// the whole daemon.
fn lock_state(state: &Arc<Mutex<StateFile>>) -> MutexGuard<'_, StateFile> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

fn save_state(ctx: &Ctx) {
    let st = lock_state(&ctx.state);
    match state::save_atomic(&ctx.cfg.state_file, &st) {
        Ok(state::SaveOutcome::Durable) => {}
        Ok(state::SaveOutcome::CommittedNotDurable) => {
            warn!("state pathname was replaced but its directory sync failed; live state remains consistent, crash durability is uncertain");
        }
        Err(e) => error!(error = %e, "failed to save state file"),
    }
}

/// Retire an old path only after both the configured minimum grace and its
/// captured connections have finished. A high hard cap prevents a stuck
/// client or accounting bug from retaining the child forever.
async fn schedule_drain(ctx: &Ctx, active: ActiveNode) {
    schedule_drain_with(
        ctx,
        active,
        RETIRED_PATH_MAX_EXTENSION,
        RETIRED_PATH_POLL_INTERVAL,
    )
    .await;
}

async fn schedule_drain_with(
    ctx: &Ctx,
    mut active: ActiveNode,
    max_extension: std::time::Duration,
    poll_interval: std::time::Duration,
) {
    let grace = std::time::Duration::from_secs(ctx.cfg.health.drain_grace_secs);
    let hard_cap = grace.saturating_add(max_extension);
    let mut shutdown = ctx.drain_shutdown.subscribe();
    let mut draining = ctx.draining.lock().await;
    while draining.try_join_next().is_some() {}
    draining.spawn(async move {
        if !*shutdown.borrow() {
            tokio::select! {
                _ = tokio::time::sleep(grace) => {}
                _ = shutdown.changed() => {}
            }
        }
        let deadline = tokio::time::Instant::now() + hard_cap.saturating_sub(grace);
        while !*shutdown.borrow() && active.path_connections.load(AtomicOrdering::Acquire) != 0 {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    warn!(
                        node = %active.node.name(),
                        remaining = active.path_connections.load(AtomicOrdering::Acquire),
                        "retired path drain reached hard cap; stopping data plane"
                    );
                    break;
                }
                _ = tokio::time::sleep(poll_interval) => {}
                _ = shutdown.changed() => {}
            }
        }
        if let Err(e) = active.handle.stop().await {
            warn!(error = %format!("{e:#}"), "failed to stop old data plane");
        }
    });
}

/// Shutdown is allowed to skip the remaining grace period, but every retired
/// handle must still be dropped and its child stopped before the daemon exits.
async fn stop_draining(ctx: &Ctx) {
    let _ = ctx.drain_shutdown.send(true);
    let mut draining = ctx.draining.lock().await;
    while let Some(result) = draining.join_next().await {
        if let Err(e) = result {
            warn!(error = %e, "data-plane drain task ended abnormally");
        }
    }
}

/// Return probed nodes from highest to lowest score (stale statistics for
/// nodes no longer in the current subscription pool are filtered out).
fn ranked_candidates<'a>(
    nodes: &'a [Node],
    state: &StateFile,
    regions: &[String],
) -> Vec<&'a Node> {
    let mut probed: Vec<&Node> = nodes
        .iter()
        .filter(|n| {
            state
                .nodes
                .get(n.name())
                .map(|s| s.is_probed())
                .unwrap_or(false)
        })
        .collect();
    // Region preference: automatic selection stays inside the allowlist
    // (empty = all nodes). Manual switching via the control socket is
    // never restricted.
    if !regions.is_empty() {
        probed.retain(|n| regions.iter().any(|r| n.name().contains(r.as_str())));
    }
    // score_cmp has ascending semantics; swapping the arguments yields descending
    probed.sort_by(|a, b| score_cmp(&state.nodes[b.name()], &state.nodes[a.name()]));
    probed
}

/// Rank known nodes by score, then append unprobed nodes in a deterministic
/// order. Subscription transactions need the second half: a new profile must
/// remain switchable before it has accumulated probe history. Like
/// [`ranked_candidates`], automatic selection (initial activation and
/// subscription transactions) stays inside the region allowlist.
fn profile_candidates(
    nodes: &[Node],
    stats: Option<&BTreeMap<String, crate::score::NodeStats>>,
    preferred: Option<&str>,
    regions: &[String],
) -> Vec<Node> {
    let pool: Vec<&Node> = nodes
        .iter()
        .filter(|n| regions.is_empty() || regions.iter().any(|r| n.name().contains(r.as_str())))
        .collect();
    let mut probed: Vec<&Node> = pool
        .iter()
        .copied()
        .filter(|node| {
            stats
                .and_then(|all| all.get(node.name()))
                .is_some_and(|s| s.is_probed())
        })
        .collect();
    if let Some(stats) = stats {
        probed.sort_by(|a, b| score_cmp(&stats[b.name()], &stats[a.name()]));
    }

    let mut ordered = Vec::with_capacity(pool.len());
    if let Some(preferred) = preferred {
        if let Some(node) = pool.iter().find(|node| node.name() == preferred) {
            ordered.push((*node).clone());
        }
    }
    for node in probed {
        if !ordered.iter().any(|seen| seen.name() == node.name()) {
            ordered.push(node.clone());
        }
    }
    let mut unprobed: Vec<&Node> = pool
        .iter()
        .copied()
        .filter(|node| {
            !stats
                .and_then(|all| all.get(node.name()))
                .is_some_and(|s| s.is_probed())
        })
        .collect();
    unprobed.sort_by(|a, b| a.name().cmp(b.name()));
    for node in unprobed {
        if !ordered.iter().any(|seen| seen.name() == node.name()) {
            ordered.push(node.clone());
        }
    }
    ordered
}

/// Start and pre-check one candidate path; cleans up after itself on failure
/// (stops the data plane).
async fn try_activate(ctx: &Ctx, node: &Node) -> anyhow::Result<ActiveNode> {
    let spec = StartSpec::reserve(node.clone())?;
    let socks_port = spec.socks_addr().port();
    let http_port = spec.http_addr().port();
    let mut handle = ctx.plane.start(spec).await?;

    // Check before switch: probe straight through the new data plane's http
    // port (bypassing the listener, isolating variables)
    match health::http_get_status(
        handle.http_addr(),
        &ctx.cfg.health.url,
        std::time::Duration::from_millis(ctx.cfg.health.timeout_ms),
    )
    .await
    {
        Ok(code) if (200..300).contains(&code) => {
            info!(node = %node.name(), http_port, socks_port, "candidate path pre-check passed");
            Ok(ActiveNode {
                node: node.clone(),
                handle,
                path_connections: Arc::new(AtomicU64::new(0)),
            })
        }
        Ok(code) => {
            handle.stop().await.ok();
            bail!("candidate path pre-check returned HTTP {code}")
        }
        Err(e) => {
            handle.stop().await.ok();
            Err(e).context("candidate path pre-check failed")
        }
    }
}

/// Install an activated path onto a class: flip the route, record state,
/// drain the old path.
async fn install_active(ctx: &Ctx, rt: &mut ClassRuntime, new_active: ActiveNode, reason: &str) {
    let socks = new_active.handle.socks_addr();
    let http = new_active.handle.http_addr();
    let node_name = new_active.node.name().to_string();
    let path_desc = new_active.handle.describe();
    let path_connections = Arc::clone(&new_active.path_connections);
    let traffic_subscription = ctx
        .subscriptions
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .active
        .clone();
    let old = rt.active.replace(new_active);
    // Any successfully published path ends the previous automatic-recovery
    // failure streak. Manual switches are never delayed by the cooldown and
    // a successful one also gives subsequent health recovery a clean slate.
    rt.auto_recovery.reset();

    let generation = {
        let mut route = rt.route.write().unwrap_or_else(|e| e.into_inner());
        route.socks_upstream = Some(socks);
        route.http_upstream = Some(http);
        route.node_name = node_name.clone();
        route.generation += 1;
        route.path_connections = Some(path_connections);
        route.traffic_subscription = traffic_subscription;
        route.generation
    };

    {
        let mut st = lock_state(&ctx.state);
        let cs = st.classes.entry(rt.name.clone()).or_default();
        cs.active_node = Some(node_name.clone());
        cs.socks_port = Some(socks.port());
        cs.http_port = Some(http.port());
        cs.generation = generation;
        if let Some(stats) = st.nodes.get_mut(&node_name) {
            stats.consecutive_health_failures = 0;
        }
        st.updated_unix = state::now_unix();
    }
    save_state(ctx);

    ctx.events.push(control::Event::Switched {
        unix: state::now_unix(),
        class: rt.name.clone(),
        node: node_name.clone(),
        reason: reason.to_string(),
        generation,
    });
    info!(
        class = %rt.name,
        node = %node_name,
        path = %path_desc,
        generation,
        reason,
        old = old.as_ref().map(|a| a.node.name()).unwrap_or("<none>"),
        "path switch complete"
    );

    // New connections already take the new node. The retired data plane stays
    // available to captured pipes after the minimum grace, within a hard cap.
    if let Some(old) = old {
        schedule_drain(ctx, old).await;
    }
}

/// Try candidates in order, installing the first that passes its pre-check.
/// Returns the installed node name (None = all failed, status quo kept).
/// A failed activation records a probe failure so scoring quickly reflects
/// that the node is currently unreachable.
async fn try_candidates(
    ctx: &Ctx,
    rt: &mut ClassRuntime,
    candidates: &[Node],
    reason: &str,
) -> Option<String> {
    for cand in candidates {
        match try_activate(ctx, cand).await {
            Ok(active) => {
                let name = active.node.name().to_string();
                install_active(ctx, rt, active, reason).await;
                return Some(name);
            }
            Err(e) => {
                warn!(class = %rt.name, node = %cand.name(), error = %format!("{e:#}"), "candidate activation failed, trying next");
                {
                    let mut st = lock_state(&ctx.state);
                    st.nodes
                        .entry(cand.name().to_string())
                        .or_default()
                        .record_probe(None, ctx.cfg.selection.ema_alpha, state::now_unix());
                }
                ctx.events.push(control::Event::ActivationFailed {
                    unix: state::now_unix(),
                    class: rt.name.clone(),
                    node: cand.name().to_string(),
                    error: format!("{e:#}"),
                });
            }
        }
    }
    None
}

/// The automatic recovery flow: try other scored nodes first, then rebuild
/// the current logical node as a last resort. A physical egress change cannot
/// migrate an existing adapter TCP session; rebuilding gives the kernel a new
/// socket on the current default route without CAUSEWAY touching interfaces,
/// DNS, policy rules, or route tables.
async fn switch_node_locked(ctx: &Arc<Ctx>, rt: &mut ClassRuntime, reason: &str) -> bool {
    let current = rt.active.as_ref().map(|a| a.node.name().to_string());

    let (candidates, current_node): (Vec<Node>, Option<Node>) = {
        let pool = pool(ctx);
        let st = lock_state(&ctx.state);
        let candidates = ranked_candidates(&pool, &st, &ctx.cfg.selection.regions)
            .into_iter()
            .filter(|n| Some(n.name()) != current.as_deref())
            .take(MAX_SWITCH_CANDIDATES)
            .cloned()
            .collect();
        let current_node = current
            .as_deref()
            .and_then(|name| pool.iter().find(|node| node.name() == name))
            .cloned();
        (candidates, current_node)
    };

    if !candidates.is_empty() && try_candidates(ctx, rt, &candidates, reason).await.is_some() {
        return true;
    }

    if let Some(current_node) = current_node {
        info!(class = %rt.name, node = %current_node.name(), reason, "rebuilding current node after alternate candidates failed");
        if try_candidates(
            ctx,
            rt,
            std::slice::from_ref(&current_node),
            "path-recovery",
        )
        .await
        .is_some()
        {
            return true;
        }
    }
    error!(class = %rt.name, reason, "all candidates and current-node rebuild failed, keeping current path");
    false
}

async fn switch_node_inner(
    ctx: &Arc<Ctx>,
    class: &Arc<tokio::sync::Mutex<ClassRuntime>>,
    reason: &str,
) -> bool {
    let mut rt = class.lock().await;
    switch_node_locked(ctx, &mut rt, reason).await
}

/// Health failures are the only automatic path subject to retry cooldown.
/// Holding the per-class async mutex keeps the readiness check, attempt, and
/// result update coherent without retaining a std mutex guard across await.
async fn recover_after_health_failure(
    ctx: &Arc<Ctx>,
    class: &Arc<tokio::sync::Mutex<ClassRuntime>>,
) {
    let mut rt = class.lock().await;
    if rt.active.is_some() && !ctx.cfg.selection.auto_switch {
        warn!(
            class = %rt.name,
            node = %rt.active.as_ref().map(|a| a.node.name()).unwrap_or_default(),
            "automatic node switching is disabled (selection.auto_switch = false); staying on the active node"
        );
        return;
    }
    let now = std::time::Instant::now();
    if !rt.auto_recovery.is_ready_at(now) {
        let retry_in = rt
            .auto_recovery
            .retry_not_before
            .and_then(|deadline| deadline.checked_duration_since(now))
            .unwrap_or_default();
        tracing::debug!(class = %rt.name, retry_in_secs = retry_in.as_secs(), "automatic path recovery is cooling down");
        return;
    }

    if switch_node_locked(ctx, &mut rt, "health-failures").await {
        return;
    }
    let delay = rt
        .auto_recovery
        .record_failure_at(std::time::Instant::now());
    warn!(class = %rt.name, retry_in_secs = delay.as_secs(), "automatic path recovery failed; backing off");
}

async fn switch_node(ctx: &Arc<Ctx>, class: &Arc<tokio::sync::Mutex<ClassRuntime>>, reason: &str) {
    let _reconfiguration = ctx.reconfiguration.read().await;
    switch_node_inner(ctx, class, reason).await;
}

/// Manual switch requested over the control socket: try the requested node
/// first, then fall back by score. A request for the already-active node is
/// a no-op.
async fn switch_to(
    ctx: &Arc<Ctx>,
    class: &Arc<tokio::sync::Mutex<ClassRuntime>>,
    requested: &str,
) -> anyhow::Result<control::SwitchOutcome> {
    let _reconfiguration = ctx.reconfiguration.read().await;
    let mut rt = class.lock().await;
    // Snapshot only after taking the class lock. A subscription transaction
    // holds every class lock through publication, so this cannot retain an
    // old-profile Node and install it after a completed profile switch.
    let pool = pool(ctx);
    let node = pool
        .iter()
        .find(|n| n.name() == requested)
        .ok_or_else(|| anyhow::anyhow!("unknown node {requested:?}"))?
        .clone();
    let current = rt.active.as_ref().map(|a| a.node.name().to_string());

    if current.as_deref() == Some(requested) {
        return Ok(control::SwitchOutcome {
            requested: requested.to_string(),
            installed: requested.to_string(),
            fallback: false,
        });
    }
    if let Some(installed) =
        try_candidates(ctx, &mut rt, std::slice::from_ref(&node), "manual").await
    {
        return Ok(control::SwitchOutcome {
            requested: requested.to_string(),
            installed,
            fallback: false,
        });
    }
    // Requested node failed pre-check: fall back by score, excluding both the
    // failed request and the current node. Manual switching is never
    // restricted by the region allowlist, so the fallback pool is unfiltered.
    let candidates: Vec<Node> = {
        let st = lock_state(&ctx.state);
        ranked_candidates(&pool, &st, &[])
            .into_iter()
            .filter(|n| n.name() != requested && Some(n.name()) != current.as_deref())
            .take(MAX_SWITCH_CANDIDATES)
            .cloned()
            .collect()
    };
    match try_candidates(ctx, &mut rt, &candidates, "manual").await {
        Some(installed) => Ok(control::SwitchOutcome {
            requested: requested.to_string(),
            installed,
            fallback: true,
        }),
        None => anyhow::bail!("all candidates failed to activate, keeping current path"),
    }
}

async fn stop_staged(staged: &mut StagedNodes) {
    for mut active in staged.drain() {
        if let Err(e) = active.handle.stop().await {
            warn!(error = %format!("{e:#}"), "failed to stop staged data plane");
        }
    }
}

fn subscription_failure(ctx: &Ctx, profile: &str, message: &'static str) -> control::Reply {
    ctx.events.push(control::Event::SubscriptionChangeFailed {
        unix: state::now_unix(),
        profile: profile.to_string(),
        error: message.to_string(),
    });
    control::Reply::err(message)
}

async fn prepare_subscription(
    profile: crate::config::SubscriptionProfileConfig,
    allow_cached_fallback: bool,
    confirmed_slot: Option<String>,
) -> Result<PreparedSubscription, ()> {
    tokio::task::spawn_blocking(move || match subscription::prepare_profile(&profile) {
        Ok(prepared) => Ok(PreparedSubscription::Fresh(prepared)),
        Err(_) if allow_cached_fallback => {
            let nodes =
                subscription::load_profile_snapshot_from_slot(&profile, confirmed_slot.as_deref());
            if nodes.is_empty() {
                Err(())
            } else {
                Ok(PreparedSubscription::Cached(nodes))
            }
        }
        Err(_) => Err(()),
    })
    .await
    .map_err(|_| ())?
}

async fn commit_prepared_cache(
    prepared: PreparedSubscription,
    confirmed_slot: Option<String>,
    _target: &str,
    reconfiguration: OwnedRwLockWriteGuard<()>,
    class_guards: Vec<OwnedMutexGuard<ClassRuntime>>,
) -> Result<CacheCommitOutcome, ()> {
    #[cfg(test)]
    let hook = CACHE_COMMIT_TEST_HOOKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(_target)
        .cloned();
    let commit = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        if let Some(hook) = &hook {
            (hook.before)();
        }
        let result = match prepared {
            PreparedSubscription::Fresh(mut fresh) => {
                match fresh.commit_cache_slot(confirmed_slot.as_deref()) {
                    Ok(_) => Ok(PreparedSubscription::Fresh(fresh)),
                    Err(_) => Err(()),
                }
            }
            cached @ PreparedSubscription::Cached(_) => Ok(cached),
        };
        #[cfg(test)]
        if let Some(hook) = &hook {
            (hook.after)();
        }
        // Keep the write gate and every class mutex owned by this worker until
        // the filesystem operation has returned. If the async caller is
        // cancelled while awaiting this JoinHandle, Tokio continues running
        // spawn_blocking and these guards still exclude subsequent
        // subscription/reconfiguration work until the writer is done.
        CacheCommitOutcome {
            prepared: result,
            reconfiguration,
            class_guards,
        }
    });

    // A cache write is a commit barrier, not cancellable background work.
    // Dropping a spawn_blocking JoinHandle does not stop its thread, so the
    // reconfiguration and class guards must remain held until that exact worker
    // finishes. This also makes shutdown join the accepted transaction before
    // tearing down its staged data planes.
    match commit.await {
        Ok(result) => Ok(result),
        Err(error) => {
            error!(error = %error, "subscription cache commit worker failed");
            Err(())
        }
    }
}

/// Prepare a target profile and preactivate one independent data plane per
/// class. Nothing visible changes until every class and the pending remote
/// cache have succeeded.
async fn switch_subscription_locked(
    ctx: &Arc<Ctx>,
    classes: &HashMap<String, Arc<tokio::sync::Mutex<ClassRuntime>>>,
    target: &str,
    catalog: SubscriptionsConfig,
    allow_cached_fallback: bool,
    is_reload: bool,
) -> control::Reply {
    let deadline = tokio::time::Instant::now() + subscription_precommit_timeout(target);
    let profile = match catalog.profile(target) {
        Some(profile) => profile,
        None => return control::Reply::err("unknown subscription profile"),
    };
    let source_identity = match profile.source_identity() {
        Ok(identity) => identity,
        Err(_) => return control::Reply::err("invalid subscription source identity"),
    };
    let (previous, previous_catalog) = {
        let runtime = ctx.subscriptions.read().unwrap_or_else(|e| e.into_inner());
        (runtime.active.clone(), runtime.catalog.clone())
    };
    let refreshed = previous == target;
    let catalog_source_unchanged = previous_catalog
        .profile(target)
        .and_then(|profile| profile.source_identity().ok())
        .as_deref()
        == Some(source_identity.as_str());

    let (confirmed_slot, source_trusted) = {
        let state = lock_state(&ctx.state);
        (
            state.subscription_cache_slots.get(target).cloned(),
            state.source_is_trusted(target, &source_identity),
        )
    };
    let source_trusted = source_trusted && catalog_source_unchanged;
    let prepared = match tokio::time::timeout_at(
        deadline,
        prepare_subscription(
            profile,
            allow_cached_fallback && !refreshed && source_trusted,
            confirmed_slot.clone(),
        ),
    )
    .await
    {
        Err(_) => {
            return subscription_failure(
                ctx,
                target,
                "subscription transaction timed out before commit",
            )
        }
        Ok(result) => match result {
            Ok(prepared) if !prepared.nodes().is_empty() => prepared,
            _ => return subscription_failure(ctx, target, "subscription preparation failed"),
        },
    };
    if prepared.nodes().len() > subscription::MAX_PROFILE_NODES {
        return subscription_failure(ctx, target, "subscription node-count limit exceeded");
    }
    if matches!(prepared, PreparedSubscription::Cached(_)) {
        warn!(profile = %target, "subscription refresh failed; using last-known-good cache for inactive profile");
    }

    // An active-profile refresh from a stale config reload must not commit
    // after another request has changed the live selection. Reloads hold the
    // transaction mutex from config read onward, so this can only differ when
    // the caller passed an inconsistent target.
    if is_reload
        && ctx
            .subscriptions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .active
            != previous
    {
        return control::Reply::err("reload aborted: active subscription changed");
    }

    // The write gate waits for all old-pool probes and switches to finish,
    // then prevents new ones from starting until publication completes.
    let reconfiguration =
        match tokio::time::timeout_at(deadline, Arc::clone(&ctx.reconfiguration).write_owned())
            .await
        {
            Ok(guard) => guard,
            Err(_) => {
                return subscription_failure(
                    ctx,
                    target,
                    "subscription transaction timed out before commit",
                )
            }
        };
    let mut ordered: Vec<_> = classes.iter().collect();
    ordered.sort_by_key(|(name, _)| *name);
    let ordered: Vec<_> = ordered
        .into_iter()
        .map(|(_, class)| Arc::clone(class))
        .collect();
    let mut guards = Vec::with_capacity(ordered.len());
    for class in &ordered {
        match tokio::time::timeout_at(deadline, Arc::clone(class).lock_owned()).await {
            Ok(guard) => guards.push(guard),
            Err(_) => {
                return subscription_failure(
                    ctx,
                    target,
                    "subscription transaction timed out before commit",
                )
            }
        }
    }

    let stats = {
        let st = lock_state(&ctx.state);
        source_trusted
            .then(|| st.nodes_for_subscription(target).cloned())
            .flatten()
    };
    let mut staged = StagedNodes::new(guards.len());
    // Indexing avoids keeping a non-Sync slice iterator across the activation
    // await; the control handler future must remain Send for tokio::spawn.
    #[allow(clippy::needless_range_loop)]
    for index in 0..guards.len() {
        let class_name = guards[index].name.clone();
        let preferred = refreshed
            .then(|| {
                guards[index]
                    .active
                    .as_ref()
                    .map(|active| active.node.name().to_string())
            })
            .flatten();
        // A subscription switch (not a refresh) must bypass the region
        // allowlist: the new profile's node naming convention may not match
        // the operator's region filter designed for the incumbent profile.
        let effective_regions: &[String] = if refreshed {
            &ctx.cfg.selection.regions
        } else {
            &[]
        };
        let candidates = profile_candidates(
            prepared.nodes(),
            stats.as_ref(),
            preferred.as_deref(),
            effective_regions,
        );
        let mut activated = None;
        for candidate in candidates.into_iter().take(MAX_SWITCH_CANDIDATES) {
            match tokio::time::timeout_at(deadline, try_activate(ctx, &candidate)).await {
                Err(_) => {
                    stop_staged(&mut staged).await;
                    return subscription_failure(
                        ctx,
                        target,
                        "subscription transaction timed out before commit",
                    );
                }
                Ok(result) => match result {
                    Ok(active) => {
                        activated = Some(active);
                        break;
                    }
                    Err(e) => warn!(
                        class = %class_name,
                        node = %candidate.name(),
                        error = %format!("{e:#}"),
                        "subscription candidate pre-check failed"
                    ),
                },
            }
        }
        match activated {
            Some(active) => staged.push(active),
            None => {
                stop_staged(&mut staged).await;
                return subscription_failure(
                    ctx,
                    target,
                    "no candidate passed pre-check for a class",
                );
            }
        }
    }

    // The deadline may prevent commit from starting. Once spawn_blocking has
    // accepted the cache write, however, it must be joined without timeout:
    // cancelling the JoinHandle would only detach a late writer.
    if tokio::time::Instant::now() >= deadline {
        stop_staged(&mut staged).await;
        return subscription_failure(
            ctx,
            target,
            "subscription transaction timed out before commit",
        );
    }
    let CacheCommitOutcome {
        prepared,
        reconfiguration: _reconfiguration,
        class_guards: mut guards,
    } = match commit_prepared_cache(prepared, confirmed_slot, target, reconfiguration, guards).await
    {
        Ok(committed) => committed,
        Err(_) => {
            stop_staged(&mut staged).await;
            return subscription_failure(ctx, target, "subscription cache commit failed");
        }
    };
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(()) => {
            stop_staged(&mut staged).await;
            return subscription_failure(ctx, target, "subscription cache commit failed");
        }
    };
    let prepared_fresh = matches!(&prepared, PreparedSubscription::Fresh(_));
    let committed_slot = match &prepared {
        PreparedSubscription::Fresh(fresh) => fresh.committed_slot().map(str::to_string),
        PreparedSubscription::Cached(_) => None,
    };
    let nodes = prepared.into_nodes();
    let node_count = nodes.len();
    let now = state::now_unix();

    // Make the profile selection durable before any live route changes. A
    // committed cache is only an inactive last-known-good snapshot until this
    // succeeds. Staged ports are intentionally not persisted: a crash before
    // publication must never make them look live, and startup recreates them.
    let planned: Vec<_> = guards
        .iter()
        .zip(staged.iter())
        .map(|(rt, active)| {
            (
                rt.name.clone(),
                active.node.name().to_string(),
                active.handle.socks_addr(),
                active.handle.http_addr(),
                rt.route
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .generation
                    .wrapping_add(1),
            )
        })
        .collect();
    let mut next_state = lock_state(&ctx.state).clone();
    let previous_identities = previous_catalog.source_identities().unwrap_or_default();
    let next_identities = match catalog.source_identities() {
        Ok(identities) => identities,
        Err(_) => {
            stop_staged(&mut staged).await;
            return subscription_failure(ctx, target, "invalid subscription source identity");
        }
    };
    next_state.apply_subscription_catalog(
        &previous_identities,
        &next_identities,
        prepared_fresh.then_some(target),
    );
    next_state.activate_subscription(target);
    if let Some(slot) = committed_slot {
        next_state
            .subscription_cache_slots
            .insert(target.to_string(), slot);
    }
    for (class, node, _, _, generation) in &planned {
        let class_state = next_state.classes.entry(class.clone()).or_default();
        class_state.active_node = Some(node.clone());
        class_state.socks_port = None;
        class_state.http_port = None;
        class_state.generation = *generation;
        if let Some(stats) = next_state.nodes.get_mut(node) {
            stats.consecutive_health_failures = 0;
        }
    }
    next_state.updated_unix = now;
    match state::save_atomic(&ctx.cfg.state_file, &next_state) {
        Ok(state::SaveOutcome::Durable) => {}
        Ok(state::SaveOutcome::CommittedNotDurable) => {
            // rename(2) already made `next_state` authoritative. Rolling the
            // live publication back here would create a disk/live split brain.
            warn!("subscription state was committed but its directory sync failed; continuing matching live publication");
        }
        Err(e) => {
            error!(error = %e, "failed to persist subscription selection before publication");
            stop_staged(&mut staged).await;
            return subscription_failure(ctx, target, "subscription state commit failed");
        }
    }

    // Clone route Arcs before borrowing their write guards. Holding every
    // route guard blocks listeners from observing a partially flipped batch.
    let mut old = Vec::with_capacity(guards.len());
    let mut switched_events = Vec::with_capacity(guards.len());
    {
        let routes: Vec<_> = guards.iter().map(|rt| Arc::clone(&rt.route)).collect();
        let mut route_guards: Vec<_> = routes
            .iter()
            .map(|route| route.write().unwrap_or_else(|e| e.into_inner()))
            .collect();
        let mut st = lock_state(&ctx.state);
        *st = next_state;
        for (((rt, route), new_active), (_, _, socks, http, generation)) in guards
            .iter_mut()
            .zip(route_guards.iter_mut())
            .zip(staged.drain())
            .zip(planned.iter())
        {
            let node_name = new_active.node.name().to_string();
            let path_connections = Arc::clone(&new_active.path_connections);
            old.push(rt.active.replace(new_active));
            rt.auto_recovery.reset();
            route.socks_upstream = Some(*socks);
            route.http_upstream = Some(*http);
            route.node_name = node_name.clone();
            route.generation = *generation;
            route.path_connections = Some(path_connections);
            route.traffic_subscription = target.to_string();
            let class_state = st.classes.entry(rt.name.clone()).or_default();
            class_state.socks_port = Some(socks.port());
            class_state.http_port = Some(http.port());
            switched_events.push((rt.name.clone(), node_name, route.generation));
        }
        {
            let mut runtime = ctx.subscriptions.write().unwrap_or_else(|e| e.into_inner());
            runtime.active = target.to_string();
            runtime.nodes = nodes;
            runtime.catalog = catalog;
            runtime.generation = runtime.generation.wrapping_add(1);
        }
        ctx.traffic.select_subscription(target);
    }

    // Selection durability no longer depends on this diagnostic port update.
    save_state(ctx);

    for (class, node, generation) in switched_events {
        ctx.events.push(control::Event::Switched {
            unix: now,
            class,
            node,
            reason: "subscription-change".to_string(),
            generation,
        });
    }
    ctx.events.push(control::Event::SubscriptionChanged {
        unix: now,
        previous: previous.clone(),
        active: target.to_string(),
        node_count,
        refreshed,
    });
    info!(previous = %previous, active = %target, node_count, refreshed, "subscription change complete");

    for active in old.into_iter().flatten() {
        schedule_drain(ctx, active).await;
    }

    control::Reply::ok_subscription_switch(control::SubscriptionSwitchOutcome {
        previous,
        active: target.to_string(),
        node_count,
        refreshed,
    })
}

async fn switch_subscription(
    ctx: &Arc<Ctx>,
    classes: &HashMap<String, Arc<tokio::sync::Mutex<ClassRuntime>>>,
    target: &str,
) -> control::Reply {
    let _in_progress = SubscriptionTxnStatusGuard::begin(&ctx.subscription_txns_in_progress);
    let _transaction = ctx.subscription_txn.lock().await;
    let catalog = {
        ctx.subscriptions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .catalog
            .clone()
    };
    switch_subscription_locked(ctx, classes, target, catalog, true, false).await
}

/// Live snapshot of one class for the control socket.
fn class_snapshot(ctx: &Ctx, class: &str) -> Option<control::StatusSnapshot> {
    loop {
        let txn_before = ctx
            .subscription_txns_in_progress
            .load(AtomicOrdering::SeqCst);
        let (generation, active_subscription, available_nodes, available_subscriptions) = {
            let runtime = ctx.subscriptions.read().unwrap_or_else(|e| e.into_inner());
            let active_subscription = runtime.active.clone();
            let available_nodes = runtime
                .nodes
                .iter()
                .map(|node| node.name().to_string())
                .collect();
            let available_subscriptions = runtime
                .catalog
                .profile_names()
                .into_iter()
                .map(|name| control::SubscriptionSummary {
                    node_count: (name == runtime.active).then_some(runtime.nodes.len()),
                    name,
                })
                .collect();
            (
                runtime.generation,
                active_subscription,
                available_nodes,
                available_subscriptions,
            )
        };
        let (cs, nodes) = {
            let st = lock_state(&ctx.state);
            (st.classes.get(class)?.clone(), st.nodes.clone())
        };
        let unchanged = ctx
            .subscriptions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .generation
            == generation;
        if unchanged {
            let txn_after = ctx
                .subscription_txns_in_progress
                .load(AtomicOrdering::SeqCst);
            let generation_after = ctx
                .subscriptions
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .generation;
            if generation_after != generation {
                continue;
            }
            return Some(control::StatusSnapshot {
                class: class.to_string(),
                active_node: cs.active_node,
                socks_port: cs.socks_port,
                http_port: cs.http_port,
                generation: cs.generation,
                nodes,
                traffic: ctx.traffic.snapshot(),
                active_conns: ctx.conns.load(AtomicOrdering::Relaxed),
                active_subscription: Some(active_subscription),
                subscription_generation: Some(generation),
                subscription_txn_in_progress: Some(txn_before != 0 || txn_after != 0),
                available_subscriptions,
                available_nodes,
            });
        }
    }
}

/// Control socket dispatch: snapshots, manual switch, on-demand end-to-end
/// probing, the event log, and live config reload.
async fn handle_control(
    ctx: Arc<Ctx>,
    classes: Arc<HashMap<String, Arc<tokio::sync::Mutex<ClassRuntime>>>>,
    req: control::Request,
) -> control::Reply {
    match req {
        control::Request::Ping => control::Reply::ok(),
        control::Request::Status { class } => match class_snapshot(&ctx, &class) {
            Some(status) => control::Reply::ok_status(status),
            None => control::Reply::err(format!("unknown class {class:?}")),
        },
        control::Request::Switch { class, node } => {
            let Some(rt) = classes.get(&class).cloned() else {
                return control::Reply::err(format!("unknown class {class:?}"));
            };
            match switch_to(&ctx, &rt, &node).await {
                Ok(outcome) => control::Reply::ok_switch(outcome),
                Err(e) => control::Reply::err(format!("{e:#}")),
            }
        }
        control::Request::SwitchSubscription { name } => {
            switch_subscription(&ctx, &classes, &name).await
        }
        control::Request::ProbeNow { class } => {
            if !classes.contains_key(&class) {
                return control::Reply::err(format!("unknown class {class:?}"));
            }
            let results = probe_now(&ctx).await;
            let ok = results.iter().filter(|r| r.ok).count();
            ctx.events.push(control::Event::Probed {
                unix: state::now_unix(),
                source: "on-demand".into(),
                ok,
                total: results.len(),
            });
            info!(
                ok,
                total = results.len(),
                "on-demand end-to-end probe complete"
            );
            control::Reply::ok_probe(results)
        }
        control::Request::Events => control::Reply::ok_events(ctx.events.snapshot()),
        control::Request::Reload => reload(&ctx, &classes).await,
        control::Request::SiteProbe { site } => site_probe_request(&ctx, site).await,
        control::Request::SiteStatus => {
            let matrix = lock_state(&ctx.state).site_verdicts.clone();
            control::Reply::ok_site_matrix(matrix)
        }
        control::Request::SwitchForSite { class, site } => {
            switch_for_site(&ctx, &classes, &class, &site).await
        }
    }
}

/// Record one verdict into the freeze matrix (state write, no save; callers
/// batch their saves).
fn record_site_verdict(ctx: &Ctx, site: &str, node: &str, verdict: SiteVerdict) {
    let mut st = lock_state(&ctx.state);
    st.updated_unix = state::now_unix();
    st.site_verdicts
        .entry(site.to_string())
        .or_default()
        .insert(node.to_string(), verdict);
}

/// A verdict younger than the configured TTL is authoritative; anything
/// older is re-probed before it steers a switch.
fn fresh_verdict(ctx: &Ctx, site: &str, node: &str) -> Option<SiteVerdict> {
    let st = lock_state(&ctx.state);
    let verdict = st.site_verdicts.get(site)?.get(node)?.clone();
    let age = (state::now_unix() - verdict.checked_unix).max(0) as u64;
    (age <= ctx.cfg.sites.verdict_ttl_secs).then_some(verdict)
}

/// Probe one (site, node) pair through a temporary data plane and record
/// the verdict. Takes the reconfiguration read gate for the probe only, the
/// same boundary `probe_now_node` draws.
async fn probe_site_node(ctx: &Arc<Ctx>, node: &Node, site: &str, url: &str) -> SiteVerdict {
    let _reconfiguration = ctx.reconfiguration.read().await;
    let timeout = std::time::Duration::from_millis(ctx.cfg.sites.timeout_ms);
    let ua = ctx.cfg.sites.user_agent.clone();
    let now = state::now_unix();
    let mut verdict = SiteVerdict {
        status: SiteStatus::Unknown,
        http_status: None,
        checked_unix: now,
        detail: None,
    };
    let spec = match StartSpec::reserve(node.clone()) {
        Ok(spec) => spec,
        Err(e) => {
            verdict.detail = Some(format!("reserve adapter ports: {e:#}"));
            record_site_verdict(ctx, site, node.name(), verdict.clone());
            return verdict;
        }
    };
    let mut handle = match ctx.plane.start(spec).await {
        Ok(h) => h,
        Err(e) => {
            verdict.detail = Some(format!("start data plane: {e:#}"));
            record_site_verdict(ctx, site, node.name(), verdict.clone());
            return verdict;
        }
    };
    let res = siteprobe::https_get_status_via_proxy(handle.http_addr(), url, &ua, timeout).await;
    if let Err(e) = handle.stop().await {
        warn!(node = %node.name(), site, error = %format!("{e:#}"), "failed to stop site-probe data plane");
    }
    match res {
        Ok(code) => {
            verdict.status = siteprobe::classify_status(code);
            verdict.http_status = Some(code);
        }
        Err(e) => {
            verdict.detail = Some(format!("{e:#}"));
        }
    }
    record_site_verdict(ctx, site, node.name(), verdict.clone());
    verdict
}

/// `SiteProbe` request body: one site (or all configured sites) through
/// every pool node, bounded like `probe_now`.
async fn site_probe_request(ctx: &Arc<Ctx>, site: Option<String>) -> control::Reply {
    let sites: Vec<(String, String)> = match site.as_deref() {
        Some(name) => match ctx.cfg.sites.list.get(name) {
            Some(target) => vec![(name.to_string(), target.url.clone())],
            None => {
                let known: Vec<&String> = ctx.cfg.sites.list.keys().collect();
                return control::Reply::err(format!(
                    "unknown site {name:?}; configured sites: {known:?}"
                ));
            }
        },
        None => ctx
            .cfg
            .sites
            .list
            .iter()
            .map(|(name, target)| (name.clone(), target.url.clone()))
            .collect(),
    };
    if sites.is_empty() {
        return control::Reply::err("no sites configured under [sites.list]");
    }
    let nodes = pool(ctx);
    let sem = Arc::new(Semaphore::new(PROBE_NOW_CONCURRENCY.max(1)));
    let mut set: JoinSet<()> = JoinSet::new();
    for (name, url) in &sites {
        for node in &nodes {
            let ctx = Arc::clone(ctx);
            let sem = Arc::clone(&sem);
            let site_name = name.clone();
            let url = url.clone();
            let node = node.clone();
            set.spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore is never closed");
                probe_site_node(&ctx, &node, &site_name, &url).await;
            });
        }
    }
    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            warn!(error = %format!("{e:#}"), "site probe task ended abnormally");
        }
    }
    save_state(ctx);
    let total_pairs = sites.len() * nodes.len();
    let ok = sites
        .iter()
        .filter(|(name, _)| {
            lock_state(&ctx.state)
                .site_verdicts
                .get(name)
                .map(|m| m.values().any(|v| v.status == SiteStatus::Ok))
                .unwrap_or(false)
        })
        .count();
    ctx.events.push(control::Event::Probed {
        unix: state::now_unix(),
        source: format!(
            "site-probe:{}",
            sites
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
        ok,
        total: total_pairs,
    });
    let matrix = lock_state(&ctx.state).site_verdicts.clone();
    control::Reply::ok_site_matrix(matrix)
}

/// `SwitchForSite` request body: probe-first, switch only on a confirmed
/// freeze. Probing happens outside the class lock (it takes seconds); the
/// switch itself re-locks and re-checks the incumbent, so a concurrent
/// manual switch is never clobbered blindly.
async fn switch_for_site(
    ctx: &Arc<Ctx>,
    classes: &Arc<HashMap<String, Arc<tokio::sync::Mutex<ClassRuntime>>>>,
    class: &str,
    site: &str,
) -> control::Reply {
    let Some(target) = ctx.cfg.sites.list.get(site) else {
        let known: Vec<&String> = ctx.cfg.sites.list.keys().collect();
        return control::Reply::err(format!(
            "unknown site {site:?}; configured sites: {known:?}"
        ));
    };
    let url = target.url.clone();
    let Some(rt) = classes.get(class).cloned() else {
        return control::Reply::err(format!("unknown class {class:?}"));
    };
    let node_before: Option<String> = {
        let rt = rt.lock().await;
        rt.active.as_ref().map(|a| a.node.name().to_string())
    };

    // 1. The incumbent goes first: a fresh Ok verdict means the scrape
    //    failure was not the exit's fault and nothing should move.
    if let Some(current) = node_before.as_deref() {
        let verdict = match fresh_verdict(ctx, site, current) {
            Some(v) => v,
            None => {
                let node = pool(ctx).into_iter().find(|n| n.name() == current);
                match node {
                    Some(node) => probe_site_node(ctx, &node, site, &url).await,
                    // Pool changed under us; treat as unknown and let the
                    // candidate search run.
                    None => SiteVerdict {
                        status: SiteStatus::Unknown,
                        http_status: None,
                        checked_unix: state::now_unix(),
                        detail: Some("incumbent left the pool".into()),
                    },
                }
            }
        };
        if verdict.status == SiteStatus::Ok {
            return control::Reply::ok_site_switch(control::SwitchForSiteOutcome {
                site: site.to_string(),
                action: "kept".into(),
                node_before: node_before.clone(),
                node_after: node_before,
                detail: format!("incumbent serves the site (HTTP {:?})", verdict.http_status),
            });
        }
    }

    // 2. Search score-ordered candidates; stop at the first node the site
    //    actually serves. `regions` is not applied: this is an explicit,
    //    automation-requested switch, same freedom as the TUI.
    let current = node_before.clone();
    let candidates: Vec<Node> = {
        let pool = pool(ctx);
        let st = lock_state(&ctx.state);
        ranked_candidates(&pool, &st, &[])
            .into_iter()
            .filter(|n| Some(n.name()) != current.as_deref())
            .take(ctx.cfg.sites.max_candidates)
            .cloned()
            .collect()
    };
    for node in &candidates {
        let verdict = probe_site_node(ctx, node, site, &url).await;
        if verdict.status != SiteStatus::Ok {
            continue;
        }
        match switch_to(ctx, &rt, node.name()).await {
            Ok(_) => {
                save_state(ctx);
                return control::Reply::ok_site_switch(control::SwitchForSiteOutcome {
                    site: site.to_string(),
                    action: "switched".into(),
                    node_before: node_before.clone(),
                    node_after: Some(node.name().to_string()),
                    detail: format!(
                        "incumbent frozen; switched to a node the site serves (HTTP {:?})",
                        verdict.http_status
                    ),
                });
            }
            // Pre-check failure: the node passed the site probe but not the
            // generic path check; keep searching.
            Err(e) => {
                warn!(node = %node.name(), site, error = %format!("{e:#}"), "site-switch candidate failed activation");
            }
        }
    }
    save_state(ctx);
    control::Reply::ok_site_switch(control::SwitchForSiteOutcome {
        site: site.to_string(),
        action: "no-candidate".into(),
        node_before: node_before.clone(),
        node_after: node_before,
        detail: format!(
            "no probed candidate served the site among {} tried; staying put",
            candidates.len()
        ),
    })
}

/// End-to-end test of every node: fresh data plane on free ports, one
/// generate_204 through its http port, EMAs recorded, never switches.
/// Bounded concurrency — every probe spawns a whole data-plane process.
const PROBE_NOW_CONCURRENCY: usize = 8;

async fn probe_now_inner(ctx: &Arc<Ctx>) -> Vec<control::ProbeResult> {
    let nodes = pool(ctx);
    let total = nodes.len();
    let era = ctx
        .subscriptions
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .generation;
    let sem = Arc::new(Semaphore::new(PROBE_NOW_CONCURRENCY.min(total.max(1))));
    let mut set = JoinSet::new();
    for node in nodes {
        let ctx = Arc::clone(ctx);
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore is never closed");
            probe_now_node(&ctx, node, era).await
        });
    }
    let mut out = Vec::with_capacity(total);
    while let Some(res) = set.join_next().await {
        match res {
            Ok(r) => out.push(r),
            Err(e) => warn!(error = %format!("{e:#}"), "probe task panicked"),
        }
    }
    out
}

async fn probe_now(ctx: &Arc<Ctx>) -> Vec<control::ProbeResult> {
    let results = probe_now_inner(ctx).await;
    save_state(ctx);
    results
}

/// One on-demand probe task body. The reconfiguration read gate is scoped to
/// a single node test, not the whole run: holding it across every remaining
/// test lets a queued subscription transaction blow its precommit timeout on
/// a large pool, and the write-preferring lock then also stalls health
/// checks behind it. The pool era is revalidated under the gate so results
/// from a snapshot taken before a publication can never land in the new
/// profile's statistics — the same boundary the whole-run gate used to draw.
async fn probe_now_node(ctx: &Arc<Ctx>, node: Node, era: u64) -> control::ProbeResult {
    let _reconfiguration = ctx.reconfiguration.read().await;
    let still_current = ctx
        .subscriptions
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .generation
        == era;
    if !still_current {
        return control::ProbeResult {
            node: node.name().to_string(),
            ok: false,
            rtt_ms: None,
            http_status: None,
            error: Some("skipped: subscription changed".to_string()),
        };
    }
    test_node(ctx, &node).await
}

/// One node's end-to-end test: start → readiness → generate_204 → stop.
async fn test_node(ctx: &Ctx, node: &Node) -> control::ProbeResult {
    let fail = |http_status: Option<u16>, error: Option<String>| control::ProbeResult {
        node: node.name().to_string(),
        ok: false,
        rtt_ms: None,
        http_status,
        error,
    };
    let spec = match StartSpec::reserve(node.clone()) {
        Ok(spec) => spec,
        Err(e) => return fail(None, Some(format!("reserve adapter ports: {e:#}"))),
    };
    let mut handle = match ctx.plane.start(spec).await {
        Ok(h) => h,
        Err(e) => {
            record_probe_result(ctx, node, None);
            return fail(None, Some(format!("{e:#}")));
        }
    };
    let res = health::http_get_status_timed(
        handle.http_addr(),
        &ctx.cfg.health.url,
        std::time::Duration::from_millis(ctx.cfg.health.timeout_ms),
    )
    .await;
    if let Err(e) = handle.stop().await {
        warn!(node = %node.name(), error = %format!("{e:#}"), "failed to stop probe data plane");
    }
    match res {
        Ok((code, rtt)) if (200..300).contains(&code) => {
            record_probe_result(ctx, node, Some(rtt));
            control::ProbeResult {
                node: node.name().to_string(),
                ok: true,
                rtt_ms: Some(rtt.as_secs_f64() * 1000.0),
                http_status: None,
                error: None,
            }
        }
        Ok((code, _)) => {
            record_probe_result(ctx, node, None);
            fail(Some(code), None)
        }
        Err(e) => {
            record_probe_result(ctx, node, None);
            fail(None, Some(format!("{e:#}")))
        }
    }
}

/// Record one end-to-end test result into the node's EMAs — the same
/// machinery as periodic probes, so manual tests blend into the rolling stats.
fn record_probe_result(ctx: &Ctx, node: &Node, rtt: Option<std::time::Duration>) {
    let now = state::now_unix();
    let mut st = lock_state(&ctx.state);
    st.nodes
        .entry(node.name().to_string())
        .or_default()
        .record_probe(rtt, ctx.cfg.selection.ema_alpha, now);
    st.updated_unix = now;
}

/// Reload may replace only the subscription catalog. Every other field owns
/// runtime resources that are constructed once at startup.
fn non_subscription_config_changed(running: &Config, candidate: &Config) -> bool {
    let mut startup_shape = candidate.clone();
    startup_shape.subscriptions = running.subscriptions.clone();
    startup_shape != *running
}

/// Re-read the original config path, then refresh and reactivate the current
/// profile through the same all-class transaction as an explicit switch.
async fn reload(
    ctx: &Arc<Ctx>,
    classes: &HashMap<String, Arc<tokio::sync::Mutex<ClassRuntime>>>,
) -> control::Reply {
    let push = |detail: String| {
        ctx.events.push(control::Event::Reloaded {
            unix: state::now_unix(),
            detail,
        })
    };
    let _in_progress = SubscriptionTxnStatusGuard::begin(&ctx.subscription_txns_in_progress);
    let _transaction = ctx.subscription_txn.lock().await;
    let (cfg, warnings) = match crate::config::load(&ctx.config_path) {
        Ok(x) => x,
        Err(e) => {
            warn!(error = %format!("{e:#}"), "config reload failed");
            let detail = "reload failed: invalid configuration".to_string();
            push(detail.clone());
            return control::Reply::err(detail);
        }
    };
    // The runtime owns immutable listeners, intervals, adapter factories,
    // state/control paths and logging sinks. Publishing only a new catalog
    // while silently retaining any changed non-subscription value would make
    // validation describe a configuration that is not actually running.
    if non_subscription_config_changed(&ctx.cfg, &cfg) {
        let detail = "non-subscription configuration changed — daemon restart required".to_string();
        push(detail.clone());
        return control::Reply::err(detail);
    }
    let active = {
        ctx.subscriptions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .active
            .clone()
    };
    if cfg.subscriptions.profile(&active).is_none() {
        let detail = "reload aborted: active subscription is no longer configured".to_string();
        push(detail.clone());
        return control::Reply::err(detail);
    }
    for w in &warnings {
        warn!(warning = %w, "config warning (reload)");
    }

    let outcome = switch_subscription_locked(
        ctx,
        classes,
        &active,
        cfg.subscriptions.clone(),
        false,
        true,
    )
    .await;
    if !outcome.ok {
        let detail = outcome
            .error
            .unwrap_or_else(|| "reload failed: subscription refresh failed".to_string());
        push(detail.clone());
        return control::Reply::err(detail);
    }
    let node_count = outcome
        .subscription_switch
        .as_ref()
        .map(|outcome| outcome.node_count)
        .unwrap_or(0);
    let detail = format!(
        "config OK — {} node(s) in pool (interval changes take effect on restart)",
        node_count
    );
    push(detail.clone());
    control::Reply::ok_msg(detail)
}

/// Initial activation: prefer the incumbent recorded in the state file, then
/// fall back by score.
async fn activate_initial(ctx: &Arc<Ctx>, class: &Arc<tokio::sync::Mutex<ClassRuntime>>) {
    let mut rt = class.lock().await;
    let preferred: Option<String> = {
        let st = lock_state(&ctx.state);
        st.classes.get(&rt.name).and_then(|c| c.active_node.clone())
    };

    let candidates = {
        let pool = pool(ctx);
        let st = lock_state(&ctx.state);
        profile_candidates(
            &pool,
            Some(&st.nodes),
            preferred.as_deref(),
            &ctx.cfg.selection.regions,
        )
    };

    for cand in candidates {
        match try_activate(ctx, &cand).await {
            Ok(active) => {
                install_active(ctx, &mut rt, active, "initial").await;
                return;
            }
            Err(e) => {
                warn!(class = %rt.name, node = %cand.name(), error = %format!("{e:#}"), "initial activation failed, trying next")
            }
        }
    }
    // Not fatal: the listener answers 502 and the health-check loop keeps
    // retrying the switch
    error!(class = %rt.name, "all initial activations failed, waiting for the health-check loop to retry");
}

/// One full probe cycle: update EMAs and persist.
async fn probe_cycle_inner(ctx: &Ctx, source: &str) {
    let timeout = std::time::Duration::from_millis(ctx.cfg.probe.timeout_ms);
    let outcomes = probe::probe_all(pool(ctx), timeout, ctx.cfg.probe.concurrency).await;
    let ok = outcomes.iter().filter(|o| o.rtt.is_some()).count();
    let total = outcomes.len();
    {
        let now = state::now_unix();
        let mut st = lock_state(&ctx.state);
        for o in outcomes {
            st.nodes
                .entry(o.node.name().to_string())
                .or_default()
                .record_probe(o.rtt, ctx.cfg.selection.ema_alpha, now);
        }
        st.updated_unix = now;
    }
    save_state(ctx);
    ctx.events.push(control::Event::Probed {
        unix: state::now_unix(),
        source: source.to_string(),
        ok,
        total,
    });
    info!(ok, "probe cycle complete");
}

async fn probe_cycle(ctx: &Ctx, source: &str) {
    let _reconfiguration = ctx.reconfiguration.read().await;
    probe_cycle_inner(ctx, source).await;
}

/// Health-check loop (one per class): full-path check through our own
/// listener.
async fn health_loop(
    ctx: Arc<Ctx>,
    class: Arc<tokio::sync::Mutex<ClassRuntime>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (name, listen_addr) = {
        let rt = class.lock().await;
        (rt.name.clone(), rt.listen_addr)
    };
    let interval = std::time::Duration::from_secs(ctx.cfg.health.interval_secs);
    let timeout = std::time::Duration::from_millis(ctx.cfg.health.timeout_ms);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }

        let _reconfiguration = ctx.reconfiguration.read().await;
        let ok = health::is_healthy(listen_addr, &ctx.cfg.health.url, timeout).await;
        let (failures, has_active) = {
            let rt = class.lock().await;
            let active_name = rt.active.as_ref().map(|a| a.node.name().to_string());
            match &active_name {
                Some(n) => {
                    let mut st = lock_state(&ctx.state);
                    let stats = st.nodes.entry(n.clone()).or_default();
                    if ok {
                        stats.consecutive_health_failures = 0;
                    } else {
                        stats.consecutive_health_failures += 1;
                    }
                    let consecutive = stats.consecutive_health_failures;
                    if !ok && consecutive > 0 {
                        ctx.events.push(control::Event::HealthFailed {
                            unix: state::now_unix(),
                            class: name.clone(),
                            node: n.clone(),
                            consecutive,
                        });
                    }
                    (consecutive, true)
                }
                None => (ctx.cfg.health.fail_threshold, false), // no active path → try to establish one immediately
            }
        };

        if !ok {
            if has_active {
                warn!(class = %name, failures, threshold = ctx.cfg.health.fail_threshold, "health check failed");
            }
            if failures >= ctx.cfg.health.fail_threshold {
                // This cycle already holds the reconfiguration read gate;
                // taking it recursively could deadlock behind a queued writer.
                recover_after_health_failure(&ctx, &class).await;
            }
        }
    }
}

/// Periodic probe loop: refresh scores → hysteresis decision → switch when
/// warranted.
async fn probe_loop(
    ctx: Arc<Ctx>,
    classes: Vec<Arc<tokio::sync::Mutex<ClassRuntime>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = std::time::Duration::from_secs(ctx.cfg.probe.interval_secs);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => return,
        }
        probe_cycle(&ctx, "periodic").await;

        for class in &classes {
            let (class_name, current, challenger) = {
                let rt = class.lock().await;
                let Some(current) = rt.active.as_ref().map(|a| a.node.name().to_string()) else {
                    continue;
                };
                let pool = pool(&ctx);
                let st = lock_state(&ctx.state);
                let best = ranked_candidates(&pool, &st, &ctx.cfg.selection.regions)
                    .into_iter()
                    .find(|n| n.name() != current)
                    .map(|n| n.name().to_string());
                (rt.name.clone(), current, best)
            };
            let Some(challenger) = challenger else {
                continue;
            };
            if !ctx.cfg.selection.auto_switch {
                // Pinned mode: probe results refresh scores only; the active
                // node never moves without operator action.
                continue;
            }
            let should_switch = {
                let st = lock_state(&ctx.state);
                match (st.nodes.get(&challenger), st.nodes.get(&current)) {
                    (Some(c), Some(i)) => challenger_wins(c, i, ctx.cfg.selection.hysteresis),
                    (Some(_), None) => true,
                    _ => false,
                }
            };
            if should_switch {
                info!(class = %class_name, %current, %challenger, "challenger won by a clear margin");
                switch_node(&ctx, class, "challenger-wins").await;
            }
        }
    }
}

/// Rebuild one class on the same logical node after a stable host egress
/// transition. Every lock is non-blocking: explicit operator work and
/// subscription transactions take precedence over this opportunistic repair.
async fn rebuild_current_after_egress_change(
    ctx: &Arc<Ctx>,
    class: &Arc<tokio::sync::Mutex<ClassRuntime>>,
    expected_egress: &EgressSignature,
    shutdown: &mut watch::Receiver<bool>,
) {
    rebuild_current_after_egress_change_with(ctx, class, shutdown, || async {
        egress::read_signature()
            .await
            .is_ok_and(|signature| &signature == expected_egress)
    })
    .await;
}

async fn rebuild_current_after_egress_change_with<F, Fut>(
    ctx: &Arc<Ctx>,
    class: &Arc<tokio::sync::Mutex<ClassRuntime>>,
    shutdown: &mut watch::Receiver<bool>,
    validate_egress: F,
) where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    if *shutdown.borrow()
        || ctx
            .subscription_txns_in_progress
            .load(AtomicOrdering::SeqCst)
            != 0
    {
        return;
    }
    let Ok(_subscription_transaction) = Arc::clone(&ctx.subscription_txn).try_lock_owned() else {
        return;
    };
    if ctx
        .subscription_txns_in_progress
        .load(AtomicOrdering::SeqCst)
        != 0
    {
        return;
    }
    // A write gate excludes manual switches and all probe populations for the
    // short same-node staging window. All locks are try-only: explicit work
    // wins immediately and this observer never queues behind it.
    let Ok(_reconfiguration) = Arc::clone(&ctx.reconfiguration).try_write_owned() else {
        return;
    };
    let Ok(mut rt) = Arc::clone(class).try_lock_owned() else {
        return;
    };
    if *shutdown.borrow()
        || ctx
            .subscription_txns_in_progress
            .load(AtomicOrdering::SeqCst)
            != 0
    {
        return;
    }
    let Some(node) = rt.active.as_ref().map(|active| active.node.clone()) else {
        return;
    };

    let activation = tokio::select! {
        biased;
        _ = shutdown.changed() => return,
        result = try_activate(ctx, &node) => result,
    };
    let mut replacement = match activation {
        Ok(active) => active,
        Err(error) => {
            warn!(class = %rt.name, node = %node.name(), error = %format!("{error:#}"), "same-node egress rebuild failed; keeping current path");
            return;
        }
    };

    let egress_still_current = tokio::select! {
        biased;
        _ = shutdown.changed() => false,
        current = validate_egress() => current,
    };
    let still_current = !*shutdown.borrow()
        && ctx
            .subscription_txns_in_progress
            .load(AtomicOrdering::SeqCst)
            == 0
        && egress_still_current;
    if !still_current {
        if let Err(error) = replacement.handle.stop().await {
            warn!(error = %format!("{error:#}"), "failed to stop discarded egress rebuild");
        }
        return;
    }

    // The class mutex has remained owned from incumbent capture through this
    // final validation, so a manual switch cannot be overwritten by a stale
    // rebuild. Publication retains the exact logical node and uses the normal
    // make-before-break route flip and drain path.
    install_active(ctx, &mut rt, replacement, "egress-change").await;
}

async fn egress_observer_loop(
    ctx: Arc<Ctx>,
    classes: Vec<Arc<tokio::sync::Mutex<ClassRuntime>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut observer = StableEgressObserver::new(EGRESS_STABLE_FOR, EGRESS_REBUILD_COOLDOWN);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(EGRESS_OBSERVE_INTERVAL) => {}
        }
        let signature = match egress::read_signature().await {
            Ok(signature) => signature,
            Err(error) => {
                tracing::debug!(error = %error, "could not observe default egress routes");
                continue;
            }
        };
        let Some(confirmed) = observer.observe(signature, std::time::Instant::now()) else {
            continue;
        };
        info!(
            classes = classes.len(),
            "stable default egress change observed; rebuilding current paths"
        );
        for class in &classes {
            if *shutdown.borrow() {
                return;
            }
            rebuild_current_after_egress_change(&ctx, class, &confirmed, &mut shutdown).await;
        }
    }
}

/// Offline snapshot for daemon startup. Returns the nodes plus whether the
/// legacy bare cache was skipped because the profile carries a pending
/// same-name source change: the transaction path refuses to serve an
/// untrusted cache, and startup must not bypass that quarantine through the
/// `confirmed_slot = None` compatibility fallback.
fn startup_snapshot(
    st: &StateFile,
    startup_identities: &std::collections::BTreeMap<String, String>,
    active_profile: &str,
    profile: &crate::config::SubscriptionProfileConfig,
) -> (Vec<Node>, bool) {
    let confirmed_slot = st
        .subscription_cache_slots
        .get(active_profile)
        .map(String::as_str);
    let source_trusted = startup_identities
        .get(active_profile)
        .is_some_and(|identity| st.source_is_trusted(active_profile, identity));
    match confirmed_slot {
        Some(slot) => (
            subscription::load_profile_snapshot_from_slot(profile, Some(slot)),
            false,
        ),
        None if source_trusted => (
            subscription::load_profile_snapshot_from_slot(profile, None),
            false,
        ),
        None => (Vec::new(), true),
    }
}

pub async fn run(cfg: Config, config_path: PathBuf) -> anyhow::Result<()> {
    let _daemon_lock = DaemonLock::acquire(&cfg.state_file)?;
    let ctl_path = control::socket_path(&cfg);
    let ctl_socket = control::bind(ctl_path).await?;
    let mut st = match state::load(&cfg.state_file).context("load state file")? {
        Some(s) => {
            let probed = s.nodes.values().filter(|n| n.is_probed()).count();
            info!(probed, "state file loaded");
            s
        }
        None => {
            info!("no state file (first run)");
            StateFile::default()
        }
    };
    let startup_identities = cfg.subscriptions.source_identities()?;
    st.reconcile_startup_sources(&startup_identities);
    let default_profile = cfg.subscriptions.default_profile_name()?;
    let active_profile = st
        .active_subscription
        .as_deref()
        .filter(|name| cfg.subscriptions.profile(name).is_some())
        .unwrap_or(&default_profile)
        .to_string();
    st.activate_subscription(&active_profile);
    let profile = cfg
        .subscriptions
        .profile(&active_profile)
        .context("selected subscription profile disappeared")?;
    // Startup is deliberately offline: a remote source must use only its
    // last atomically committed cache so daemon availability never depends on
    // provider reachability.
    let (nodes, legacy_quarantined) =
        startup_snapshot(&st, &startup_identities, &active_profile, &profile);
    if nodes.is_empty() {
        if legacy_quarantined {
            bail!(
                "subscription profile {active_profile:?} has a pending source change and its \
                 previous-source cache is quarantined; start with a different default profile \
                 and complete the change via `causeway switch`, or delete the state file to \
                 reset source trust"
            );
        }
        if profile.files.is_empty() {
            bail!(
                "remote subscription profile {active_profile:?} has no local snapshot; startup \
                 never fetches — prime its cache file once with a supported manifest, or start \
                 with a local snapshot profile and switch"
            );
        }
        bail!("selected subscription has no supported nodes in its local snapshot");
    }
    info!(profile = %active_profile, total = nodes.len(), "node pool loaded");

    let work_dir = cfg
        .state_file
        .parent()
        .map(|p| p.join("run"))
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/causeway-run"));
    let workspace = AdapterWorkspace::create(&work_dir)?;
    let plane = Arc::new(DispatchPlane::new(
        SslocalPlane::new_with_direct_hosts(
            cfg.sslocal_bin.clone(),
            Arc::clone(&workspace),
            cfg.obfs_plugin_bin.clone(),
            cfg.routing.direct_hosts.clone(),
        ),
        SingboxPlane::new_with_direct_hosts(
            cfg.singbox_bin.clone(),
            Arc::clone(&workspace),
            cfg.routing.direct_hosts.clone(),
        ),
        workspace,
    ));
    let events = Arc::new(EventLog::new(200));
    let traffic = Arc::new(listener::TrafficCounters::default());
    traffic.select_subscription(&active_profile);
    let conns = Arc::new(AtomicU64::new(0));
    let (drain_shutdown, _) = watch::channel(false);
    let subscription_catalog = cfg.subscriptions.clone();
    let ctx = Arc::new(Ctx {
        cfg,
        config_path,
        subscriptions: Arc::new(RwLock::new(SubscriptionRuntime {
            active: active_profile,
            nodes,
            catalog: subscription_catalog,
            generation: 0,
        })),
        subscription_txn: Arc::new(tokio::sync::Mutex::new(())),
        subscription_txns_in_progress: Arc::new(AtomicU64::new(0)),
        reconfiguration: Arc::new(tokio::sync::RwLock::new(())),
        state: Arc::new(Mutex::new(st)),
        plane,
        events,
        traffic,
        conns,
        draining: Arc::new(tokio::sync::Mutex::new(JoinSet::new())),
        drain_shutdown,
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Bring up listeners first (stable endpoints matter most), then activate
    // paths (502s in the meantime)
    let mut classes = Vec::new();
    let mut classes_by_name = HashMap::new();
    let mut listener_tasks = Vec::new();
    for (name, class_cfg) in &ctx.cfg.classes {
        let listener = TcpListener::bind(class_cfg.listen).await.with_context(|| {
            format!("bind listen address {} (class {name:?})", class_cfg.listen)
        })?;
        let route: SharedRoute = Arc::new(std::sync::RwLock::new(ClassRoute::default()));
        let rt = Arc::new(tokio::sync::Mutex::new(ClassRuntime {
            name: name.clone(),
            listen_addr: class_cfg.listen,
            route: Arc::clone(&route),
            active: None,
            auto_recovery: AutoRecoveryBackoff::default(),
        }));
        listener_tasks.push(tokio::spawn(listener::serve(
            name.clone(),
            listener,
            route,
            Arc::clone(&ctx.traffic),
            Arc::clone(&ctx.conns),
            shutdown_rx.clone(),
        )));
        classes_by_name.insert(name.clone(), Arc::clone(&rt));
        classes.push(rt);
    }

    // First run (zero probe data) → run one full probe round before initial
    // activation to avoid a blind pick. It runs after the listeners are up so
    // a cold start answers 502s at the stable endpoints during the round
    // instead of refusing connections outright.
    if lock_state(&ctx.state)
        .nodes
        .values()
        .all(|n| !n.is_probed())
    {
        info!("state has no probe data, running a startup probe round (takes tens of seconds)…");
        probe_cycle(&ctx, "startup").await;
    }

    // Initial activation (serial per class, KISS)
    for class in &classes {
        activate_initial(&ctx, class).await;
    }

    // Background tasks: one health loop per class + one global probe loop
    let mut tasks = Vec::new();
    for class in &classes {
        tasks.push(tokio::spawn(health_loop(
            Arc::clone(&ctx),
            Arc::clone(class),
            shutdown_rx.clone(),
        )));
    }
    tasks.push(tokio::spawn(probe_loop(
        Arc::clone(&ctx),
        classes.clone(),
        shutdown_rx.clone(),
    )));
    tasks.push(tokio::spawn(egress_observer_loop(
        Arc::clone(&ctx),
        classes.clone(),
        shutdown_rx.clone(),
    )));

    // Control socket: the bundled `causeway switch` subcommand talks to it
    let ctl_ctx = Arc::clone(&ctx);
    let ctl_classes = Arc::new(classes_by_name);
    tasks.push(tokio::spawn(async move {
        if let Err(e) = control::serve(
            ctl_socket,
            move |req| {
                let ctx = Arc::clone(&ctl_ctx);
                let classes = Arc::clone(&ctl_classes);
                async move { handle_control(ctx, classes, req).await }
            },
            shutdown_rx,
        )
        .await
        {
            error!(error = %format!("{e:#}"), "control socket server failed");
        }
    }));

    info!("CAUSEWAY running");
    wait_for_shutdown_signal().await;
    info!("shutdown signal received, starting graceful exit");

    let _ = shutdown_tx.send(true);
    // Quiesce every route-mutating worker before tearing down active paths.
    // In particular, control::serve drains requests whose JSON was accepted
    // before shutdown; without this join a subscription transaction could
    // finish preparation and publish after the cleanup below.
    for task in tasks {
        if let Err(e) = task.await {
            warn!(error = %e, "background task ended abnormally during shutdown");
        }
    }
    // Listener ownership is separate from route-mutating workers: admission
    // closes on the same signal, then each listener gets its own bounded
    // session-drain window before any active adapter is stopped.
    for task in listener_tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!(error = %format!("{e:#}"), "listener ended abnormally during shutdown")
            }
            Err(e) => warn!(error = %e, "listener task ended abnormally during shutdown"),
        }
    }
    for class in &classes {
        let mut rt = class.lock().await;
        if let Some(mut active) = rt.active.take() {
            if let Err(e) = active.handle.stop().await {
                warn!(error = %format!("{e:#}"), "failed to stop data plane");
            }
        }
        {
            let mut st = lock_state(&ctx.state);
            let cs = st.classes.entry(rt.name.clone()).or_default();
            cs.socks_port = None;
            cs.http_port = None;
        }
    }
    stop_draining(&ctx).await;
    if let Err(e) = ctx.plane.cleanup_workspace() {
        warn!(error = %format!("{e:#}"), "adapter workspace was not empty; preserving it");
    }
    save_state(&ctx);
    // Give the listeners a beat to observe the shutdown signal
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    info!("exit complete");
    Ok(())
}

/// Wait for both SIGINT and SIGTERM (systemd sends SIGTERM).
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "cannot register SIGTERM handler, listening for SIGINT only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::io::AsyncWriteExt;

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
        next_handle: AtomicU64,
    }

    impl FakeTrace {
        fn starts(&self) -> Vec<String> {
            self.starts.lock().unwrap().clone()
        }

        fn stops(&self) -> Vec<String> {
            self.stops.lock().unwrap().clone()
        }
    }

    /// Each successful fake start owns a real loopback HTTP listener. This
    /// exercises the same pre-publication health request as production while
    /// keeping every test entirely local and deterministic.
    struct FakePlane {
        responses: Mutex<VecDeque<(String, u16)>>,
        trace: Arc<FakeTrace>,
    }

    impl FakePlane {
        fn new(responses: impl IntoIterator<Item = (&'static str, u16)>) -> (Self, Arc<FakeTrace>) {
            let trace = Arc::new(FakeTrace::default());
            let responses = responses
                .into_iter()
                .map(|(name, status)| (name.to_string(), status))
                .collect();
            (
                Self {
                    responses: Mutex::new(responses),
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

            let socks_addr = spec.socks_addr();
            let http_addr = spec.http_addr();
            // The real adapters release their reservation immediately before
            // spawning. The fake mirrors that boundary before binding its
            // loopback-only health responder.
            drop(spec);
            let listener = tokio::net::TcpListener::bind(http_addr).await?;
            let server = tokio::spawn(async move {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let response = format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
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
        let dir = test_dir(label);
        let cfg = test_config(dir.join("state.json"), drain_grace_secs);
        let catalog = cfg.subscriptions.clone();
        let (plane, trace) = FakePlane::new(responses);
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
        assert_eq!(
            trace.stops(),
            ["candidate-0-alternate", "candidate-1-current"]
        );
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
        let script = format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            body.replace('\\', "\\\\").replace('\'', "'\\''")
        );
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
        let result = probe_now_node(&ctx, node("current"), era).await;
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
        let result = probe_now_node(&ctx, node("current"), era).await;
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
        let script = format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            body.replace('\\', "\\\\").replace('\'', "'\\''")
        );
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
        tokio::time::timeout(Duration::from_secs(2), async {
            while !commit_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cache commit worker should start");

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
}
