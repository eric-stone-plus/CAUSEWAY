//! `causeway`'s primary interface: an nmtui-style dashboard.
//!
//! A full-screen TUI (ratatui + crossterm) with live data from the daemon's
//! control socket: an always-visible class strip (every listener and its
//! active node), a node table for the focused class (score, RTT, per-node
//! traffic), recent-events feed, Tab/←/→ to change class, arrow keys to
//! select a node, Enter to switch only the focused class (the daemon runs
//! the normal check-before-switch flow with reason "manual"), `t` to run
//! an end-to-end latency test of every node, `s` to switch subscription
//! profiles (`e` inside the picker replaces a remote profile's credential
//! URL via masked input — atomically written 0600, never rendered), `/` to
//! filter the node table, `c` to surface paste-ready proxy exports for the
//! focused class, `?` for the key table (derived from the same single
//! BINDINGS source as the footer hint, so they cannot drift), q to quit.
//!
//! Refresh spine: every daemon request — cadence refreshes and mutations
//! alike — runs on a background task whose reply is polled each tick, so a
//! slow or wedged daemon never freezes the interface. Each lane (status,
//! events, mutation) holds at most one request in flight, and superseded
//! replies (class changed, mutation landed in between) are discarded by an
//! epoch check instead of painting stale state. Data age is honest: the
//! strip title and footer stamp how old the last live snapshot is and turn
//! STALE past the refresh cadence (3× yellow, 10× red).
//!
//! When stdout is not a terminal, prints a plain status report instead —
//! safe in scripts and pipelines.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::prelude::Stylize;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, Paragraph, Row, Table, TableState};
use ratatui::{DefaultTerminal, Frame};
use tokio::sync::oneshot;

use crate::config::Config;
use crate::control::{self, Client, Request, StatusSnapshot};
use crate::score::{score_cmp, success_cmp};
use crate::state;
use crate::subscription;
use crate::{epln, pln};

/// Short timeout for cheap requests (snapshots, events)
const STATUS_TIMEOUT: Duration = Duration::from_secs(3);
/// Generous timeout for switch requests: pre-check plus up to 5 scored
/// fallbacks, each bounded by health.timeout_ms
const SWITCH_TIMEOUT: Duration = Duration::from_secs(120);
/// Subscription changes may fetch a remote profile and stage a checked path
/// for every class before committing.
const SUBSCRIPTION_SWITCH_TIMEOUT: Duration = Duration::from_secs(300);
/// An end-to-end probe tests every node (spawn + readiness + generate_204);
/// budget for a handful of waves at health.timeout_ms each
const PROBE_TIMEOUT: Duration = Duration::from_secs(300);
/// Poll the daemon for fresh data this often while idle
const REFRESH_EVERY: Duration = Duration::from_secs(2);
/// Input poll per draw-loop turn. Reply application happens on the next
/// turn after this window at the latest, so a TUI feels live without
/// redrawing hot.
const POLL_EVERY: Duration = Duration::from_millis(100);
/// A live snapshot older than 3 refresh intervals is suspect (yellow);
/// past 10 it is red and flagged STALE. "Fake-alive is worse than dead":
/// a slow daemon must be visible as slow, not painted as fresh.
const STALE_AFTER: u32 = 3;
const VERY_STALE_AFTER: u32 = 10;
/// Node-table filter input cap (chars); enough for any node-name fragment.
const FILTER_MAX_CHARS: usize = 64;
/// Event feed minimum height (rows, including the bordered block).
/// Leftover terminal rows go here instead of stretching the node table.
const EVENTS_MIN_ROWS: u16 = 4;
/// Footer height (rows)
const FOOTER_ROWS: u16 = 3;
/// Bordered block chrome (top/bottom borders + header row) for the class strip
/// and the node table.
const TABLE_CHROME: u16 = 3;
/// Floor for the node table so a tiny pool still has a usable pane.
const MIN_NODE_TABLE_ROWS: u16 = 6;

/// Single source of truth for the interactive keys: the footer hint and the
/// `?` overlay are both derived from this table, so neither can drift from
/// the actual bindings.
const BINDINGS: &[(&str, &str)] = &[
    ("Tab/←/→", "focus another class"),
    ("k/↑ j/↓", "move node selection"),
    ("Enter", "switch the focused class to the selected node"),
    ("t", "probe every node end-to-end"),
    ("s", "subscription profiles (e edits the URL)"),
    ("/", "filter the node table (Enter commit, Esc clear)"),
    ("c", "show proxy exports for the focused class"),
    ("?", "toggle this help"),
    ("q/Esc", "quit"),
];

/// Semantic color tokens: the only place raw palette values appear. Every
/// render site asks for a meaning (ok, warn, …), never a literal color.
mod tokens {
    use ratatui::style::{Color, Modifier, Style};

    pub const OK: Color = Color::Green;
    pub const WARN: Color = Color::Yellow;
    pub const ERROR: Color = Color::Red;
    pub const MUTED: Color = Color::DarkGray;
    pub const ACCENT: Color = Color::Cyan;

    pub fn ok_bold() -> Style {
        Style::default().fg(OK).add_modifier(Modifier::BOLD)
    }
    pub fn muted() -> Style {
        Style::default().fg(MUTED)
    }
    pub fn accent() -> Style {
        Style::default().fg(ACCENT)
    }
    /// Focused row/class emphasis (video reverse), shared by every table.
    pub fn focus() -> Style {
        Style::new().add_modifier(Modifier::REVERSED)
    }
}

/// Honest data-age verdict for the live snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Staleness {
    Fresh,
    Stale,
    VeryStale,
}

fn staleness(age: Option<Duration>) -> Staleness {
    let Some(age) = age else {
        return Staleness::VeryStale;
    };
    if age > REFRESH_EVERY * VERY_STALE_AFTER {
        Staleness::VeryStale
    } else if age > REFRESH_EVERY * STALE_AFTER {
        Staleness::Stale
    } else {
        Staleness::Fresh
    }
}

/// The mutation a background task is running, plus everything needed to
/// classify and apply its reply without touching shared state.
#[derive(Debug, Clone)]
enum MutationKind {
    NodeSwitch { node: String },
    ProbeAll {
        requested_tag: Option<ProbeRoundTag>,
    },
    SubscriptionSwitch {
        previous: String,
        requested: String,
        generation_before: u64,
    },
}

impl MutationKind {
    fn request(&self, class: &str) -> Request {
        match self {
            Self::NodeSwitch { node } => Request::Switch {
                class: class.to_string(),
                node: node.clone(),
            },
            Self::ProbeAll { .. } => Request::ProbeNow {
                class: class.to_string(),
            },
            Self::SubscriptionSwitch { requested, .. } => Request::SwitchSubscription {
                name: requested.clone(),
            },
        }
    }

    fn timeout(&self) -> Duration {
        match self {
            Self::NodeSwitch { .. } => SWITCH_TIMEOUT,
            Self::ProbeAll { .. } => PROBE_TIMEOUT,
            Self::SubscriptionSwitch { .. } => SUBSCRIPTION_SWITCH_TIMEOUT,
        }
    }

    fn busy_message(&self, class: &str) -> String {
        match self {
            Self::NodeSwitch { node } => {
                format!("switching to {node} — pre-check in progress…")
            }
            Self::ProbeAll { .. } => {
                format!("probing all nodes end-to-end (class {class})…")
            }
            Self::SubscriptionSwitch { requested, .. } => format!(
                "switching subscription to {requested} — staging checked paths…"
            ),
        }
    }
}

/// One request running on a background task. The draw loop polls the
/// receiver each turn; a reply is applied only when its guards still match
/// the world it was issued for.
struct InFlight {
    /// The mutation being run when this is the mutation lane.
    kind: Option<MutationKind>,
    /// Class the request was issued for. A status reply describing another
    /// class is a superseded frame and is discarded.
    class: String,
    /// Epoch at issue time; bumped on class change and mutation submission.
    /// A mismatch means the reply describes a world the operator has
    /// already moved past.
    epoch: u64,
    rx: oneshot::Receiver<anyhow::Result<control::Reply>>,
}

/// Run one control request on a background task. The returned receiver
/// completes with the reply (or the request error/timeout); dropping the
/// receiver just discards the answer — the daemon side is a checked
/// transaction either way.
fn spawn_request(
    socket: PathBuf,
    req: Request,
    timeout: Duration,
) -> oneshot::Receiver<anyhow::Result<control::Reply>> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let client = Client::new(socket);
        let reply = client.request(&req, timeout).await;
        let _ = tx.send(reply);
    });
    rx
}

struct SubscriptionPicker {
    entries: Vec<control::SubscriptionSummary>,
    selected: usize,
    /// Masked in-progress URL input; the edit target is `selected`. The raw
    /// URL is never rendered — the credential-bearing text must not reach
    /// screen logs, scrollback, or shoulder surfers.
    url_edit: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum PickerAction {
    None,
    Close,
    Switch(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SubscriptionOutcomeUnknown {
    previous: String,
    requested: String,
    subscription_generation_before_request: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeRoundTag {
    active_subscription: String,
    subscription_generation: u64,
    /// Canonical, complete identity of the pool tested by this round.
    pool: Vec<String>,
}

#[derive(Debug, Clone)]
struct ProbeRound {
    tag: ProbeRoundTag,
    results: BTreeMap<String, ProbeRoundResult>,
}

#[derive(Debug, Clone, Copy)]
struct ProbeRoundResult {
    ok: bool,
    rtt_ms: Option<f64>,
}

struct ProbeReplyOutcome {
    level: MessageLevel,
    message: String,
    round: Option<ProbeRound>,
    counts: Option<(usize, usize)>,
}

fn completed_probe_message(
    ok: usize,
    total: usize,
    round_applied: bool,
    recommended: Option<&str>,
) -> (MessageLevel, String) {
    let (level, suffix) = if !round_applied {
        (
            MessageLevel::Warning,
            "ranking unchanged (subscription or pool changed)".to_string(),
        )
    } else if ok == 0 {
        (
            MessageLevel::Warning,
            "no usable recommendation".to_string(),
        )
    } else {
        (
            MessageLevel::Success,
            recommended
                .map(|node| format!("recommended {node}"))
                .unwrap_or_else(|| "no usable recommendation".to_string()),
        )
    };
    (
        level,
        format!("end-to-end probe done: {ok}/{total} ok; {suffix}"),
    )
}

/// What the TUI knows about the profile before a compatible live daemon
/// supplies an authoritative snapshot. A configured default is useful for
/// browsing its catalog, but it is not evidence that the daemon ever
/// activated it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OfflineSubscription {
    Persisted(String),
    ConfiguredDefault(String),
    Unavailable,
}

impl OfflineSubscription {
    fn display_name(&self) -> Option<&str> {
        match self {
            Self::Persisted(name) | Self::ConfiguredDefault(name) => Some(name),
            Self::Unavailable => None,
        }
    }

    fn confirmed_name(&self) -> Option<&str> {
        match self {
            Self::Persisted(name) => Some(name),
            Self::ConfiguredDefault(_) | Self::Unavailable => None,
        }
    }
}

struct App {
    /// Class names from the config, in config order
    cfg_classes: Vec<String>,
    /// Gateway listen per class (index-aligned with `cfg_classes`)
    listens: Vec<String>,
    /// Per-class selection policy summary (index-aligned with `cfg_classes`),
    /// from local config for the offline-synthesis path
    class_selections: Vec<String>,
    class_idx: usize,
    /// State file — last known good when the daemon is unreachable
    state_file: PathBuf,
    /// Offline/old-daemon fallback for the last persistently confirmed profile.
    /// Live daemons provide the authoritative active pool in their snapshot.
    subs: Vec<String>,
    configured_default_subscription: Option<String>,
    offline_subscription: OfflineSubscription,
    fallback_subscriptions: Vec<control::SubscriptionSummary>,
    fallback_profiles: BTreeMap<String, crate::config::SubscriptionProfileConfig>,
    /// Credential-free node names per configured profile, used only when the
    /// daemon is unreachable and the persisted active profile is authoritative.
    fallback_profile_nodes: BTreeMap<String, Vec<String>>,
    subscription_picker: Option<SubscriptionPicker>,
    /// A request can commit server-side even when its reply is lost. Until a
    /// later authoritative status identifies the active profile, another
    /// mutation could race or overwrite an outcome the operator has not seen.
    subscription_outcome_unknown: Option<SubscriptionOutcomeUnknown>,
    /// Last complete, protocol-valid on-demand end-to-end probe. It is used
    /// only for TUI ranking and is discarded when its subscription/pool tag
    /// no longer matches live status.
    last_probe_round: Option<ProbeRound>,
    connected: bool,
    snapshot: Option<StatusSnapshot>,
    /// Whether the selected class was present in the source of `snapshot`.
    /// Live status always carries an authoritative generation; an offline
    /// state file can still provide useful global node data without it.
    generation_known: bool,
    /// Display order: scored first, unprobed last; narrowed by the filter
    order: Vec<String>,
    /// The same ordering before the filter, so recommendations and the
    /// "filtered n/m" count speak about the whole pool, not the visible
    /// subset.
    order_full: Vec<String>,
    selected: usize,
    /// Background-request lanes: at most one request per lane, replies
    /// applied on the draw loop.
    status_flight: Option<InFlight>,
    events_flight: Option<InFlight>,
    mutation_flight: Option<InFlight>,
    /// Bumped on class change and mutation boundaries; in-flight frames
    /// carrying an older epoch are discarded on landing.
    epoch: u64,
    /// When the last live snapshot landed (age/STALE honesty).
    last_live: Option<Instant>,
    /// Own cadence clock for the events lane. A shared clock would either
    /// starve events while status answers promptly or re-spawn them every
    /// tick while status hangs — each lane paces itself.
    last_events_refresh: Instant,
    /// `updated_unix` of the last state file the offline path could read.
    state_updated_unix: Option<i64>,
    /// Active node-table filter (`/`); None when unfiltered.
    filter: Option<String>,
    /// Whether filter keystrokes are being captured.
    filter_edit: bool,
    /// Whether the `?` key overlay is open.
    help_open: bool,
    /// Set when q/Esc is pressed while a mutation is in flight; quitting
    /// then requires a second keypress so an outcome is not casually
    /// abandoned (Ctrl-C stays the hard exit).
    quit_armed: bool,
    /// Diagnostics + count-test surface: requests issued per lane.
    status_spawns: u64,
    events_spawns: u64,
    message: String,
    message_level: MessageLevel,
    /// Recent daemon events (newest last)
    events: Vec<control::Event>,
    /// (up, down, captured-at) of the last snapshot — the rate baseline
    traffic_seed: Option<(u64, u64, Instant)>,
    total_up: u64,
    total_down: u64,
    rate_up: f64,
    rate_down: f64,
    last_refresh: Instant,
}

impl App {
    fn new(cfg: &Config, class: &str) -> Self {
        let cfg_classes: Vec<String> = cfg.classes.keys().cloned().collect();
        let listens = cfg_classes
            .iter()
            .map(|c| {
                cfg.classes
                    .get(c)
                    .map(|cc| cc.listen.to_string())
                    .unwrap_or_else(|| "-".into())
            })
            .collect();
        let class_selections = cfg_classes
            .iter()
            .map(|c| cfg.class_selection_summary(c))
            .collect();
        let class_idx = cfg_classes.iter().position(|c| c == class).unwrap_or(0);
        let persisted_state = state::load(&cfg.state_file).ok().flatten();
        let configured_default_subscription = cfg.subscriptions.default_profile_name().ok();
        let offline_subscription = offline_subscription(cfg, persisted_state.as_ref());
        let fallback_profiles: BTreeMap<_, _> = cfg
            .subscriptions
            .profile_names()
            .into_iter()
            .filter_map(|name| {
                cfg.subscriptions
                    .profile(&name)
                    .map(|profile| (name, profile))
            })
            .collect();
        let fallback_profile_nodes: BTreeMap<String, Vec<String>> = fallback_profiles
            .iter()
            .map(|(name, profile)| {
                let confirmed_slot = persisted_state
                    .as_ref()
                    .and_then(|st| st.subscription_cache_slots.get(name))
                    .map(String::as_str);
                let nodes = profile_node_names(profile, confirmed_slot);
                (name.clone(), nodes)
            })
            .collect();
        let subs = offline_subscription
            .display_name()
            .and_then(|name| fallback_profile_nodes.get(name))
            .cloned()
            .unwrap_or_default();
        let fallback_subscriptions = cfg
            .subscriptions
            .profile_names()
            .into_iter()
            .map(|name| control::SubscriptionSummary {
                node_count: fallback_profile_nodes.get(&name).map(Vec::len),
                name,
            })
            .collect();
        Self {
            cfg_classes,
            listens,
            class_selections,
            class_idx,
            state_file: cfg.state_file.clone(),
            subs,
            configured_default_subscription,
            offline_subscription,
            fallback_subscriptions,
            fallback_profiles,
            fallback_profile_nodes,
            subscription_picker: None,
            subscription_outcome_unknown: None,
            last_probe_round: None,
            connected: false,
            snapshot: None,
            generation_known: false,
            order: Vec::new(),
            order_full: Vec::new(),
            selected: 0,
            status_flight: None,
            events_flight: None,
            mutation_flight: None,
            epoch: 0,
            last_live: None,
            last_events_refresh: Instant::now(),
            state_updated_unix: None,
            filter: None,
            filter_edit: false,
            help_open: false,
            quit_armed: false,
            status_spawns: 0,
            events_spawns: 0,
            message: String::new(),
            message_level: MessageLevel::Info,
            events: Vec::new(),
            traffic_seed: None,
            total_up: 0,
            total_down: 0,
            rate_up: 0.0,
            rate_down: 0.0,
            last_refresh: Instant::now(),
        }
    }

    /// Whether a mutation is running on the background lane. Table
    /// navigation, filtering, help, and quit stay available; class
    /// switching and further mutations wait (the class guard keeps a
    /// mutation's outcome observable).
    fn busy(&self) -> bool {
        self.mutation_flight.is_some()
    }

    fn class(&self) -> &str {
        &self.cfg_classes[self.class_idx]
    }

    fn listen(&self) -> &str {
        &self.listens[self.class_idx]
    }

    fn active_subscription(&self) -> Option<&str> {
        self.authoritative_active_subscription().or_else(|| {
            if self.connected {
                // An old or partially compatible daemon cannot establish a
                // profile identity. Retain only a separately persisted fact.
                self.offline_subscription.confirmed_name()
            } else {
                self.snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.active_subscription.as_deref())
                    .or_else(|| self.offline_subscription.confirmed_name())
            }
        })
    }

    fn subscription_label(&self) -> String {
        if let Some(active) = self.active_subscription() {
            return active.to_string();
        }
        match &self.offline_subscription {
            OfflineSubscription::ConfiguredDefault(name) => {
                format!("{name} (configured default)")
            }
            OfflineSubscription::Persisted(name) => name.clone(),
            OfflineSubscription::Unavailable => "-".to_string(),
        }
    }

    fn authoritative_subscription_snapshot(&self) -> Option<&StatusSnapshot> {
        self.connected
            .then_some(())
            .and(self.snapshot.as_ref())
            .filter(|snapshot| authoritative_subscription_status(snapshot))
    }

    fn authoritative_active_subscription(&self) -> Option<&str> {
        self.authoritative_subscription_snapshot()
            .and_then(|snapshot| snapshot.active_subscription.as_deref())
    }

    fn subscription_mutation_allowed(&self) -> bool {
        self.authoritative_subscription_snapshot().is_some()
            && self
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.subscription_txn_in_progress == Some(false))
            && self.subscription_outcome_unknown.is_none()
    }

    fn set_message(&mut self, level: MessageLevel, message: impl Into<String>) {
        self.message = message.into();
        self.message_level = level;
    }

    fn subscription_choices(&self) -> Vec<control::SubscriptionSummary> {
        match self.authoritative_subscription_snapshot() {
            Some(snapshot) => snapshot.available_subscriptions.clone(),
            _ => self.fallback_subscriptions.clone(),
        }
    }
}

fn offline_subscription(cfg: &Config, persisted: Option<&state::StateFile>) -> OfflineSubscription {
    if let Some(state) = persisted {
        if let Some(name) = state
            .active_subscription
            .as_ref()
            .filter(|name| cfg.subscriptions.profile(name).is_some())
            .cloned()
        {
            return OfflineSubscription::Persisted(name);
        }
    }
    cfg.subscriptions
        .default_profile_name()
        .map(OfflineSubscription::ConfiguredDefault)
        .unwrap_or(OfflineSubscription::Unavailable)
}

fn profile_node_names(
    profile: &crate::config::SubscriptionProfileConfig,
    confirmed_slot: Option<&str>,
) -> Vec<String> {
    subscription::load_profile_snapshot_from_slot(profile, confirmed_slot)
        .into_iter()
        .map(|node| node.name().to_string())
        .collect()
}

/// Subscription fields are a protocol capability boundary. Serde defaults
/// make an old daemon's otherwise valid status look connected, so mutations
/// are authorized only when both the selected profile and a coherent,
/// nonempty catalog are supplied by the live daemon.
fn authoritative_subscription_status(snapshot: &StatusSnapshot) -> bool {
    let Some(active) = snapshot
        .active_subscription
        .as_deref()
        .filter(|name| !name.is_empty())
    else {
        return false;
    };
    snapshot.subscription_generation.is_some()
        && snapshot.subscription_txn_in_progress.is_some()
        && !snapshot.available_subscriptions.is_empty()
        && snapshot
            .available_subscriptions
            .iter()
            .all(|entry| !entry.name.is_empty())
        && snapshot
            .available_subscriptions
            .iter()
            .any(|entry| entry.name == active)
}

enum SubscriptionReplyResult {
    Success(control::SubscriptionSwitchOutcome),
    Failed(String),
    Unknown(String),
}

fn apply_subscription_reply_result(
    app: &mut App,
    result: SubscriptionReplyResult,
    previous: String,
    requested: String,
    subscription_generation_before_request: u64,
) -> bool {
    match result {
        SubscriptionReplyResult::Success(outcome) => {
            app.subscription_outcome_unknown = None;
            app.set_message(
                MessageLevel::Success,
                format!(
                    "subscription {} → {} — {} nodes",
                    outcome.previous, outcome.active, outcome.node_count
                ),
            );
            true
        }
        SubscriptionReplyResult::Failed(message) => {
            app.set_message(MessageLevel::Error, message);
            false
        }
        SubscriptionReplyResult::Unknown(message) => {
            app.subscription_outcome_unknown = Some(SubscriptionOutcomeUnknown {
                previous,
                requested,
                subscription_generation_before_request,
            });
            app.set_message(MessageLevel::Warning, message);
            false
        }
    }
}

fn classify_subscription_reply(reply: anyhow::Result<control::Reply>) -> SubscriptionReplyResult {
    match reply {
        Ok(reply) if reply.ok => match reply.subscription_switch {
            Some(outcome) => SubscriptionReplyResult::Success(outcome),
            None => SubscriptionReplyResult::Unknown(
                "subscription request outcome unknown: daemon replied ok without an outcome; further subscription changes are locked until authoritative status reconciles"
                    .to_string(),
            ),
        },
        Ok(reply) => SubscriptionReplyResult::Failed(reply.error.unwrap_or_else(|| {
            "subscription change failed; current paths kept".to_string()
        })),
        Err(error) => SubscriptionReplyResult::Unknown(format!(
            "subscription request outcome unknown; further subscription changes are locked until authoritative status reconciles: {error:#}"
        )),
    }
}

fn probe_round_tag(snapshot: &StatusSnapshot) -> Option<ProbeRoundTag> {
    let active_subscription = snapshot.active_subscription.clone()?;
    let subscription_generation = snapshot.subscription_generation?;
    if snapshot.available_nodes.is_empty() {
        return None;
    }
    let mut pool = snapshot.available_nodes.clone();
    pool.sort();
    pool.dedup();
    if pool.len() != snapshot.available_nodes.len() {
        return None;
    }
    Some(ProbeRoundTag {
        active_subscription,
        subscription_generation,
        pool,
    })
}

fn classify_probe_reply(
    reply: anyhow::Result<control::Reply>,
    requested_tag: Option<ProbeRoundTag>,
) -> ProbeReplyOutcome {
    match reply {
        Ok(reply) if reply.ok => match reply.probe {
            Some(results) => {
                let ok = results.iter().filter(|result| result.ok).count();
                // The honest denominator is the requested pool, not the
                // returned rows: a panic-shortened listing must not render
                // "2/2 ok" for a 3-node pool (same under-report class the
                // daemon-side Probed event total was fixed for).
                let total = requested_tag
                    .as_ref()
                    .map_or(results.len(), |tag| tag.pool.len());
                let round = requested_tag.and_then(|tag| {
                    let mut by_node = BTreeMap::new();
                    for result in results {
                        let valid_rtt = match (result.ok, result.rtt_ms) {
                            (true, Some(rtt)) => rtt.is_finite() && rtt >= 0.0,
                            (false, None) => true,
                            _ => false,
                        };
                        let projected = ProbeRoundResult {
                            ok: result.ok,
                            rtt_ms: result.rtt_ms,
                        };
                        if !valid_rtt || by_node.insert(result.node, projected).is_some() {
                            return None;
                        }
                    }
                    let result_nodes = by_node.keys().cloned().collect::<Vec<_>>();
                    (result_nodes == tag.pool).then_some(ProbeRound {
                        tag,
                        results: by_node,
                    })
                });
                let valid = round.is_some();
                ProbeReplyOutcome {
                    level: if valid {
                        MessageLevel::Success
                    } else {
                        MessageLevel::Warning
                    },
                    message: if valid {
                        format!("end-to-end probe done: {ok}/{total} ok")
                    } else {
                        format!(
                            "end-to-end probe done: {ok}/{total} ok; ranking unchanged (incomplete or malformed result set)"
                        )
                    },
                    round,
                    counts: valid.then_some((ok, total)),
                }
            }
            None => ProbeReplyOutcome {
                level: MessageLevel::Warning,
                message: "probe outcome unknown: daemon replied ok without results".to_string(),
                round: None,
                counts: None,
            },
        },
        Ok(reply) => ProbeReplyOutcome {
            level: MessageLevel::Error,
            message: reply.error.unwrap_or_else(|| "probe failed".to_string()),
            round: None,
            counts: None,
        },
        Err(error) => ProbeReplyOutcome {
            level: MessageLevel::Error,
            message: format!("probe request failed: {error:#}"),
            round: None,
            counts: None,
        },
    }
}

fn classify_switch_reply(
    reply: anyhow::Result<control::Reply>,
    requested: &str,
) -> (MessageLevel, String) {
    match reply {
        Ok(reply) if reply.ok => match reply.switch {
            Some(outcome) if outcome.fallback => (
                MessageLevel::Warning,
                format!(
                    "{requested} failed pre-check — fell back to {}",
                    outcome.installed
                ),
            ),
            Some(outcome) => (
                MessageLevel::Success,
                format!("switched to {}", outcome.installed),
            ),
            None => (
                MessageLevel::Warning,
                "node switch outcome unknown: daemon replied ok without an outcome".to_string(),
            ),
        },
        Ok(reply) => (
            MessageLevel::Error,
            reply.error.unwrap_or_else(|| "switch failed".to_string()),
        ),
        Err(error) => (
            MessageLevel::Error,
            format!("switch request failed: {error:#}"),
        ),
    }
}

/// Entry point. Stdout not a terminal → plain report (scripts/pipelines);
/// otherwise the interactive TUI.
/// Non-interactive automation client: one plain switch (`--node`), or the
/// probe-first site switch (`--for-site`). Prints one result line and exits;
/// exit code is nonzero when the daemon reports an error.
pub async fn run_noninteractive(
    cfg: &Config,
    class: &str,
    node: Option<String>,
    for_site: Option<String>,
) -> anyhow::Result<()> {
    let client = Client::new(control::socket_path(cfg));
    let request = match (&node, &for_site) {
        (Some(node), None) => control::Request::Switch {
            class: class.to_string(),
            node: node.clone(),
        },
        (None, Some(site)) => control::Request::SwitchForSite {
            class: class.to_string(),
            site: site.clone(),
        },
        _ => anyhow::bail!("exactly one of --node or --for-site is required"),
    };
    // A site switch may probe the incumbent plus several candidates; allow
    // minutes for the pathological case.
    let reply = client
        .request(&request, std::time::Duration::from_secs(600))
        .await?;
    if !reply.ok {
        anyhow::bail!("{}", reply.error.unwrap_or_else(|| "switch failed".into()));
    }
    if let Some(outcome) = reply.site_switch {
        println!(
            "site {} -> {} ({} -> {}): {}",
            outcome.site,
            outcome.action,
            outcome.node_before.as_deref().unwrap_or("-"),
            outcome.node_after.as_deref().unwrap_or("-"),
            outcome.detail
        );
        return Ok(());
    }
    if let Some(outcome) = reply.switch {
        println!(
            "switched {} -> {}{}",
            outcome.requested,
            outcome.installed,
            if outcome.fallback {
                " (score fallback after pre-check failure)"
            } else {
                ""
            }
        );
        return Ok(());
    }
    anyhow::bail!("daemon replied without a switch outcome")
}

pub async fn run(cfg: &Config, class: &str) -> anyhow::Result<()> {
    let socket = control::socket_path(cfg);
    let client = Client::new(socket.clone());
    if !std::io::stdout().is_terminal() {
        return print_plain(cfg, class, &client).await;
    }

    let mut app = App::new(cfg, class);
    // One blocking refresh before the alternate screen so the first frame is
    // populated; from here on every request runs on the spine.
    refresh(&client, &mut app).await;

    let mut terminal = ratatui::init();
    let res = tui_loop(&mut terminal, &socket, &mut app).await;
    ratatui::restore();
    res
}

async fn tui_loop(
    terminal: &mut DefaultTerminal,
    socket: &PathBuf,
    app: &mut App,
) -> anyhow::Result<()> {
    loop {
        poll_flights(app);
        terminal.draw(|f| ui(f, app))?;

        if event::poll(POLL_EVERY)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        return Ok(());
                    }
                    if app.help_open {
                        // Any key dismisses the overlay; it never mutates.
                        app.help_open = false;
                        continue;
                    }
                    if app.filter_edit {
                        filter_edit_key(app, key.code);
                        continue;
                    }
                    if app.subscription_picker.is_some() {
                        match picker_key(app, key.code) {
                            PickerAction::None | PickerAction::Close => {}
                            PickerAction::Switch(name) => {
                                if !app.subscription_mutation_allowed() {
                                    app.set_message(
                                        MessageLevel::Warning,
                                        "subscription switch blocked until a compatible live daemon reports authoritative status",
                                    );
                                    continue;
                                }
                                let previous = app
                                    .authoritative_active_subscription()
                                    .unwrap_or_default()
                                    .to_string();
                                let generation_before = app
                                    .authoritative_subscription_snapshot()
                                    .and_then(|snapshot| snapshot.subscription_generation)
                                    .expect(
                                        "mutation authorization requires reconciliation fields",
                                    );
                                submit_mutation(
                                    app,
                                    socket,
                                    MutationKind::SubscriptionSwitch {
                                        previous,
                                        requested: name,
                                        generation_before,
                                    },
                                );
                            }
                        }
                        continue;
                    }

                    match dashboard_key(app, socket, key.code) {
                        KeyAction::None => {}
                        KeyAction::Quit => return Ok(()),
                    }
                }
                _ => {}
            }
        }

        maybe_spawn_refresh(app, socket);
    }
}

/// Outcome of a dashboard key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAction {
    None,
    Quit,
}

/// Normal-mode key dispatch. Extracted from the draw loop so the key table
/// is testable one binding at a time (help stays derivable, never
/// hand-synced).
fn dashboard_key(app: &mut App, socket: &PathBuf, key: KeyCode) -> KeyAction {
    match key {
        KeyCode::Char('q') | KeyCode::Esc => {
            if app.busy() && !app.quit_armed {
                app.quit_armed = true;
                app.set_message(
                    MessageLevel::Warning,
                    "change in flight — press q again to quit (the daemon finishes it either way)",
                );
                return KeyAction::None;
            }
            KeyAction::Quit
        }
        KeyCode::Char('?') => {
            app.help_open = true;
            KeyAction::None
        }
        KeyCode::Char('k') | KeyCode::Up => {
            select_up(app);
            KeyAction::None
        }
        KeyCode::Char('j') | KeyCode::Down => {
            select_down(app);
            KeyAction::None
        }
        KeyCode::Char('/') => {
            app.filter = Some(app.filter.take().unwrap_or_default());
            app.filter_edit = true;
            KeyAction::None
        }
        KeyCode::Char('c') => {
            if !app.busy() {
                app.set_message(
                    MessageLevel::Info,
                    format!("copy: {}", proxy_export_line(app.listen())),
                );
            }
            KeyAction::None
        }
        KeyCode::Char('s') => {
            if !app.busy() {
                open_subscription_picker(app);
            }
            KeyAction::None
        }
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
            if app.busy() || app.cfg_classes.len() < 2 {
                return KeyAction::None;
            }
            change_class(app, matches!(key, KeyCode::Tab | KeyCode::Right));
            KeyAction::None
        }
        KeyCode::Char('t') => {
            if !app.busy() {
                let requested_tag = app.snapshot.as_ref().and_then(probe_round_tag);
                submit_mutation(app, socket, MutationKind::ProbeAll { requested_tag });
            }
            KeyAction::None
        }
        KeyCode::Enter => {
            if !app.busy() {
                if let Some(node) = app.order.get(app.selected).cloned() {
                    submit_mutation(app, socket, MutationKind::NodeSwitch { node });
                }
            }
            KeyAction::None
        }
        _ => KeyAction::None,
    }
}

/// Focus another class: clear every per-class view state (snapshot, probe
/// round, filter, rates), supersede in-flight status frames, and mark the
/// refresh due so the new class paints immediately.
fn change_class(app: &mut App, forward: bool) {
    let n = app.cfg_classes.len();
    app.class_idx = if forward {
        (app.class_idx + 1) % n
    } else {
        (app.class_idx + n - 1) % n
    };
    app.snapshot = None;
    app.generation_known = false;
    app.last_probe_round = None;
    app.order.clear();
    app.order_full.clear();
    app.selected = 0;
    app.traffic_seed = None;
    app.rate_up = 0.0;
    app.rate_down = 0.0;
    app.filter = None;
    app.filter_edit = false;
    app.set_message(MessageLevel::Info, format!("class {}", app.class()));
    app.epoch += 1;
    app.status_flight = None;
    app.last_refresh = Instant::now() - REFRESH_EVERY;
}

/// Whether the status lane should issue a request now: cadence due, no
/// request in flight (never overlap), independent of any pending mutation.
fn should_spawn_status(app: &App) -> bool {
    app.last_refresh.elapsed() >= REFRESH_EVERY && app.status_flight.is_none()
}

/// Events are advisory daemon-memory state: fetched on their OWN cadence
/// clock (a shared clock lets a fast status lane starve them and a slow one
/// turn them into a per-tick poller), only while connected, never twice at
/// once.
fn should_spawn_events(app: &App) -> bool {
    app.connected
        && app.events_flight.is_none()
        && app.last_events_refresh.elapsed() >= REFRESH_EVERY
}

fn maybe_spawn_refresh(app: &mut App, socket: &PathBuf) {
    if should_spawn_status(app) {
        app.last_refresh = Instant::now();
        app.status_spawns += 1;
        app.status_flight = Some(InFlight {
            kind: None,
            class: app.class().to_string(),
            epoch: app.epoch,
            rx: spawn_request(
                socket.clone(),
                Request::Status {
                    class: app.class().to_string(),
                },
                STATUS_TIMEOUT,
            ),
        });
    }
    if should_spawn_events(app) {
        app.last_events_refresh = Instant::now();
        app.events_spawns += 1;
        app.events_flight = Some(InFlight {
            kind: None,
            class: app.class().to_string(),
            epoch: app.epoch,
            rx: spawn_request(socket.clone(), Request::Events, STATUS_TIMEOUT),
        });
    }
}

/// The socket-free half of submitting a mutation: bump the epoch so status
/// frames already in flight (they describe the pre-mutation world) are
/// discarded on landing, and stage the lane slot around the caller's
/// receiver.
fn prepare_mutation(
    app: &mut App,
    kind: MutationKind,
    rx: oneshot::Receiver<anyhow::Result<control::Reply>>,
) -> InFlight {
    app.epoch += 1;
    InFlight {
        kind: Some(kind),
        class: app.class().to_string(),
        epoch: app.epoch,
        rx,
    }
}

/// Submit a mutation on the background lane. Refuses to overlap: a second
/// mutation while one runs would drop the first reply unobserved.
fn submit_mutation(app: &mut App, socket: &PathBuf, kind: MutationKind) {
    if app.mutation_flight.is_some() {
        app.set_message(
            MessageLevel::Warning,
            "another change is already in progress",
        );
        return;
    }
    app.set_message(MessageLevel::Info, kind.busy_message(app.class()));
    let rx = spawn_request(socket.clone(), kind.request(app.class()), kind.timeout());
    app.mutation_flight = Some(prepare_mutation(app, kind, rx));
}

/// Apply every completed background reply. Pending requests keep waiting;
/// a task that died without answering degrades like a request error.
fn poll_flights(app: &mut App) {
    if let Some((flight, result)) = take_completed(&mut app.status_flight) {
        complete_status_reply(app, flight, result);
    }
    if let Some((flight, result)) = take_completed(&mut app.events_flight) {
        complete_events_reply(app, flight, result);
    }
    if let Some((flight, result)) = take_completed(&mut app.mutation_flight) {
        complete_mutation(app, flight, result);
    }
}

fn take_completed(
    flight: &mut Option<InFlight>,
) -> Option<(InFlight, anyhow::Result<control::Reply>)> {
    let inflight = flight.as_mut()?;
    match inflight.rx.try_recv() {
        Ok(result) => {
            let inflight = flight.take().expect("receiver was Some");
            Some((inflight, result))
        }
        Err(oneshot::error::TryRecvError::Empty) => None,
        Err(oneshot::error::TryRecvError::Closed) => {
            let inflight = flight.take().expect("receiver was Some");
            Some((
                inflight,
                Err(anyhow::anyhow!("background request task failed")),
            ))
        }
    }
}

fn complete_status_reply(
    app: &mut App,
    flight: InFlight,
    result: anyhow::Result<control::Reply>,
) {
    if flight.class != app.class() || flight.epoch != app.epoch {
        // Superseded frame: the operator changed class or a mutation landed
        // in between; the next cadence tick repaints the current world.
        return;
    }
    match result {
        Ok(reply) if reply.ok => {
            if let Some(snap) = reply.status {
                apply_live_snapshot(app, snap);
                rebuild_order(app);
            }
            // ok-without-snapshot keeps the previous data; next tick retries
        }
        _ => {
            app.connected = false;
            // No live data anymore: the age display must not claim any.
            app.last_live = None;
            refresh_from_file(app);
            rebuild_order(app);
        }
    }
}

fn complete_events_reply(app: &mut App, flight: InFlight, result: anyhow::Result<control::Reply>) {
    if flight.epoch != app.epoch {
        return;
    }
    // Advisory: a failed fetch keeps the previous list.
    if let Ok(reply) = result {
        if reply.ok {
            if let Some(evs) = reply.events {
                app.events = evs;
            }
        }
    }
}

fn complete_mutation(app: &mut App, flight: InFlight, result: anyhow::Result<control::Reply>) {
    // Class switching is refused while a mutation runs, so a class mismatch
    // here is defensive only.
    if flight.class != app.class() {
        return;
    }
    let Some(kind) = flight.kind else {
        return;
    };
    match kind {
        MutationKind::NodeSwitch { node } => {
            let (level, message) = classify_switch_reply(result, &node);
            app.set_message(level, message);
        }
        MutationKind::ProbeAll { requested_tag } => {
            let outcome = classify_probe_reply(result, requested_tag);
            app.last_probe_round = outcome.round;
            app.set_message(outcome.level, outcome.message);
            rebuild_order(app);
            if let Some((ok, total)) = outcome.counts {
                let (level, message) = completed_probe_message(
                    ok,
                    total,
                    app.last_probe_round.is_some(),
                    recommended_node(app),
                );
                app.set_message(level, message);
            }
        }
        MutationKind::SubscriptionSwitch {
            previous,
            requested,
            generation_before,
        } => {
            let changed = apply_subscription_reply_result(
                app,
                classify_subscription_reply(result),
                previous,
                requested,
                generation_before,
            );
            if changed {
                app.selected = 0;
                app.traffic_seed = None;
                app.rate_up = 0.0;
                app.rate_down = 0.0;
                // The pool changed wholesale; a name fragment from the old
                // pool is noise, not a filter.
                app.filter = None;
                app.filter_edit = false;
            }
        }
    }
    // A status frame spawned during the mutation snapshots a pre-commit
    // world and carries the post-submission epoch, so the epoch guard alone
    // cannot catch it — supersede it explicitly, which also frees the lane
    // for the forced refresh below.
    app.epoch += 1;
    app.status_flight = None;
    app.quit_armed = false;
    // Server-side state changed; paint the authoritative world immediately.
    app.last_refresh = Instant::now() - REFRESH_EVERY;
}

/// Key handling while the `/` filter captures input.
fn filter_edit_key(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.filter = None;
            app.filter_edit = false;
            rebuild_order(app);
        }
        KeyCode::Enter => {
            app.filter_edit = false;
            if app
                .filter
                .as_ref()
                .is_some_and(|pattern| pattern.is_empty())
            {
                app.filter = None;
            }
            rebuild_order(app);
        }
        KeyCode::Backspace => {
            app.filter.get_or_insert_with(String::new).pop();
            rebuild_order(app);
        }
        KeyCode::Char(c) if !c.is_control() => {
            let pattern = app.filter.get_or_insert_with(String::new);
            if pattern.chars().count() < FILTER_MAX_CHARS {
                pattern.push(c);
            }
            rebuild_order(app);
        }
        _ => {}
    }
}

fn open_subscription_picker(app: &mut App) {
    let entries = app.subscription_choices();
    if entries.is_empty() {
        app.set_message(MessageLevel::Warning, "no subscription profiles available");
        return;
    }
    let selected = app
        .active_subscription()
        .and_then(|active| entries.iter().position(|entry| entry.name == active))
        .unwrap_or(0);
    app.subscription_picker = Some(SubscriptionPicker {
        entries,
        selected,
        url_edit: None,
    });
}

fn picker_key(app: &mut App, key: KeyCode) -> PickerAction {
    if app
        .subscription_picker
        .as_ref()
        .is_some_and(|picker| picker.url_edit.is_some())
    {
        return url_edit_key(app, key);
    }
    let Some(picker) = app.subscription_picker.as_mut() else {
        return PickerAction::None;
    };
    match key {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.subscription_picker = None;
            PickerAction::Close
        }
        KeyCode::Char('k') | KeyCode::Up => {
            picker.selected = picker.selected.saturating_sub(1);
            PickerAction::None
        }
        KeyCode::Char('j') | KeyCode::Down => {
            picker.selected = (picker.selected + 1).min(picker.entries.len().saturating_sub(1));
            PickerAction::None
        }
        KeyCode::Char('e') => {
            let target = picker.entries.get(picker.selected).map(|e| e.name.clone());
            let remote = target
                .as_ref()
                .and_then(|name| app.fallback_profiles.get(name))
                .is_some_and(|profile| profile.url_file.is_some());
            match (target, remote) {
                (Some(name), true) => {
                    picker.url_edit = Some(String::new());
                    app.set_message(
                        MessageLevel::Info,
                        format!("enter the new subscription URL for {name} — input is hidden"),
                    );
                }
                (Some(name), false) => {
                    app.set_message(
                        MessageLevel::Warning,
                        format!(
                            "subscription {name} is a local file profile; edit config.toml instead"
                        ),
                    );
                }
                (None, _) => {}
            }
            PickerAction::None
        }
        KeyCode::Enter => {
            let name = picker.entries.get(picker.selected).map(|e| e.name.clone());
            app.subscription_picker = None;
            match name {
                Some(name) if app.authoritative_active_subscription() == Some(name.as_str()) => {
                    app.set_message(
                        MessageLevel::Info,
                        format!("subscription {name} is already active"),
                    );
                    PickerAction::Close
                }
                Some(name) if app.subscription_mutation_allowed() => PickerAction::Switch(name),
                Some(_) => {
                    let message = if app.subscription_outcome_unknown.is_some() {
                        "subscription change blocked: the previous request's outcome has not yet been reconciled by authoritative live status"
                    } else if app.authoritative_subscription_snapshot().is_some() {
                        "subscription picker is view-only while another subscription change is in progress"
                    } else if app.connected {
                        "subscription picker is view-only: the connected daemon does not provide authoritative subscription status"
                    } else {
                        "subscription picker is view-only while the daemon is unreachable"
                    };
                    app.set_message(MessageLevel::Warning, message);
                    PickerAction::Close
                }
                None => PickerAction::None,
            }
        }
        _ => PickerAction::None,
    }
}

/// Key handling while the masked URL editor is open inside the picker.
fn url_edit_key(app: &mut App, key: KeyCode) -> PickerAction {
    match key {
        KeyCode::Esc => {
            if let Some(picker) = app.subscription_picker.as_mut() {
                picker.url_edit = None;
            }
            app.set_message(MessageLevel::Info, "subscription URL edit cancelled");
            PickerAction::None
        }
        KeyCode::Enter => submit_url_edit(app),
        KeyCode::Backspace => {
            if let Some(buffer) = app
                .subscription_picker
                .as_mut()
                .and_then(|picker| picker.url_edit.as_mut())
            {
                buffer.pop();
            }
            PickerAction::None
        }
        KeyCode::Char(c) if !c.is_control() => {
            if let Some(buffer) = app
                .subscription_picker
                .as_mut()
                .and_then(|picker| picker.url_edit.as_mut())
            {
                if (buffer.len() as u64) < subscription::MAX_SUBSCRIPTION_URL_BYTES {
                    buffer.push(c);
                }
            }
            PickerAction::None
        }
        _ => PickerAction::None,
    }
}

fn submit_url_edit(app: &mut App) -> PickerAction {
    let Some(picker) = app.subscription_picker.as_mut() else {
        return PickerAction::None;
    };
    let Some(buffer) = picker.url_edit.take() else {
        return PickerAction::None;
    };
    let Some(name) = picker
        .entries
        .get(picker.selected)
        .map(|entry| entry.name.clone())
    else {
        return PickerAction::None;
    };
    let url = buffer.trim();
    if let Err(reason) = validate_subscription_url(url) {
        app.set_message(
            MessageLevel::Warning,
            format!("invalid subscription URL: {reason}"),
        );
        return PickerAction::None;
    }
    let Some(url_file) = app
        .fallback_profiles
        .get(&name)
        .and_then(|profile| profile.url_file.clone())
    else {
        app.set_message(
            MessageLevel::Warning,
            format!("subscription {name} has no url_file; edit config.toml instead"),
        );
        return PickerAction::None;
    };
    if let Err(error) = write_subscription_url_atomic(&url_file, url) {
        app.set_message(
            MessageLevel::Warning,
            format!("failed to save subscription URL for {name}: {error}"),
        );
        return PickerAction::None;
    }
    if app.authoritative_active_subscription() == Some(name.as_str())
        && app.subscription_mutation_allowed()
    {
        // Replacing the active profile's URL must refetch and revalidate the
        // manifest before serving traffic; that is exactly the checked
        // switch transaction, so route through it rather than special-casing.
        app.subscription_picker = None;
        app.set_message(
            MessageLevel::Info,
            format!("subscription URL saved for {name}; refetching via the checked switch flow"),
        );
        PickerAction::Switch(name)
    } else {
        app.set_message(
            MessageLevel::Success,
            format!("subscription URL saved for {name}; press Enter on it to switch"),
        );
        PickerAction::None
    }
}

/// Same acceptance rules as the fetch path in `subscription`: a URL the
/// editor saves must not be rejected by the daemon's next fetch.
fn validate_subscription_url(url: &str) -> Result<(), &'static str> {
    if !url.starts_with("https://") {
        return Err("must start with https://");
    }
    if url.len() <= "https://".len() {
        return Err("nothing after https://");
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("must not contain whitespace or control characters");
    }
    if url.len() as u64 > subscription::MAX_SUBSCRIPTION_URL_BYTES {
        return Err("too long");
    }
    Ok(())
}

/// Replace a profile's URL secret atomically (tmp + rename, mode 0600) so a
/// concurrent daemon fetch never reads a half-written URL.
#[cfg(unix)]
fn write_subscription_url_atomic(path: &std::path::Path, url: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "url_file has no file name",
        )
    })?;
    let tmp = path.with_file_name(format!("{}.tmp", file_name.to_string_lossy()));
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(url.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
}

/// Fetch a live snapshot + events over the control socket; on snapshot
/// failure, degrade to the state file (last known good) and mark the daemon
/// unreachable.
/// Startup-only synchronous refresh: one status + events round before the
/// alternate screen so the first frame is populated. Once the TUI loop
/// starts, every request runs on the background spine instead.
async fn refresh(client: &Client, app: &mut App) {
    app.last_refresh = Instant::now();
    match client
        .request(
            &Request::Status {
                class: app.class().to_string(),
            },
            STATUS_TIMEOUT,
        )
        .await
    {
        Ok(reply) if reply.ok && reply.status.is_some() => {
            let Some(snap) = reply.status else {
                return;
            };
            apply_live_snapshot(app, snap);
        }
        _ => {
            app.connected = false;
            app.last_live = None;
            refresh_from_file(app);
        }
    }
    rebuild_order(app);
    // Events are advisory: a failed fetch just keeps the previous list
    if let Ok(reply) = client.request(&Request::Events, STATUS_TIMEOUT).await {
        if reply.ok {
            if let Some(evs) = reply.events {
                app.events = evs;
            }
        }
    }
}

fn apply_live_snapshot(app: &mut App, snap: StatusSnapshot) {
    update_traffic(app, &snap);
    if !snap.available_nodes.is_empty() {
        app.subs = snap.available_nodes.clone();
    }
    reconcile_subscription_outcome(app, &snap);
    app.snapshot = Some(snap);
    app.generation_known = true;
    app.connected = true;
    app.last_live = Some(Instant::now());
}

fn rebuild_order(app: &mut App) {
    let selected_node = app.order.get(app.selected).cloned();
    let current_tag = app.snapshot.as_ref().and_then(probe_round_tag);
    if app
        .last_probe_round
        .as_ref()
        .is_some_and(|round| Some(&round.tag) != current_tag.as_ref())
    {
        app.last_probe_round = None;
    }
    let mut order = ordered_names(
        app.snapshot.as_ref(),
        &app.subs,
        app.last_probe_round.as_ref(),
    );
    app.order_full = order.clone();
    if let Some(pattern) = app
        .filter
        .as_ref()
        .filter(|pattern| !pattern.is_empty())
        .map(|pattern| pattern.to_lowercase())
    {
        order.retain(|name| name.to_lowercase().contains(&pattern));
    }
    app.order = order;
    app.selected = selected_node
        .as_ref()
        .and_then(|node| app.order.iter().position(|candidate| candidate == node))
        .unwrap_or_else(|| app.selected.min(app.order.len().saturating_sub(1)));
}

/// The pool-wide recommendation, independent of the active filter: the
/// "recommended X" message and the BEST badge must speak about the whole
/// pool, not the visible subset.
fn recommended_node(app: &App) -> Option<&str> {
    let node = app.order_full.first()?;
    app.last_probe_round
        .as_ref()?
        .results
        .get(node)
        .is_some_and(|result| result.ok)
        .then_some(node.as_str())
}

fn refresh_from_file(app: &mut App) {
    if let Ok(Some(st)) = state::load(&app.state_file) {
        app.state_updated_unix = Some(st.updated_unix);
        let active_subscription = st
            .active_subscription
            .clone()
            .filter(|name| app.fallback_profiles.contains_key(name));
        app.offline_subscription = match active_subscription.clone() {
            Some(name) => OfflineSubscription::Persisted(name),
            None => app
                .configured_default_subscription
                .clone()
                .map(OfflineSubscription::ConfiguredDefault)
                .unwrap_or(OfflineSubscription::Unavailable),
        };
        if let Some(profile_name) = active_subscription.as_deref() {
            if let Some(profile) = app.fallback_profiles.get(profile_name) {
                let confirmed_slot = st
                    .subscription_cache_slots
                    .get(profile_name)
                    .map(String::as_str);
                app.fallback_profile_nodes.insert(
                    profile_name.to_string(),
                    profile_node_names(profile, confirmed_slot),
                );
            }
        }
        let available_nodes = active_subscription
            .as_ref()
            .and_then(|name| app.fallback_profile_nodes.get(name))
            .cloned()
            .unwrap_or_default();
        app.subs = available_nodes.clone();
        let cs = st.classes.get(app.class());
        app.generation_known = cs.is_some();
        let classes = class_overviews_from_state(app, &st);
        app.snapshot = Some(StatusSnapshot {
            class: app.class().to_string(),
            active_node: cs.and_then(|c| c.active_node.clone()),
            socks_port: cs.and_then(|c| c.socks_port),
            http_port: cs.and_then(|c| c.http_port),
            generation: cs.map(|c| c.generation).unwrap_or(0),
            nodes: st.nodes,
            traffic: Default::default(),
            active_conns: 0,
            active_subscription,
            subscription_generation: None,
            subscription_txn_in_progress: None,
            available_subscriptions: app.fallback_subscriptions.clone(),
            available_nodes,
            classes,
        });
    } else {
        // A missing, unreadable, or corrupt state file provides no evidence
        // about the active profile or node. Preserve the configured catalog
        // for view-only inspection, but clear every stale runtime assertion.
        app.state_updated_unix = None;
        app.offline_subscription = app
            .configured_default_subscription
            .clone()
            .map(OfflineSubscription::ConfiguredDefault)
            .unwrap_or(OfflineSubscription::Unavailable);
        app.subs = app
            .offline_subscription
            .display_name()
            .and_then(|name| app.fallback_profile_nodes.get(name))
            .cloned()
            .unwrap_or_default();
        app.snapshot = None;
        app.generation_known = false;
        app.last_probe_round = None;
    }
}

fn reconcile_subscription_outcome(app: &mut App, snapshot: &StatusSnapshot) {
    let Some(pending) = app.subscription_outcome_unknown.as_ref() else {
        return;
    };
    if !authoritative_subscription_status(snapshot) {
        return;
    }
    if snapshot.subscription_txn_in_progress != Some(false) {
        return;
    }
    let Some(subscription_generation) = snapshot.subscription_generation else {
        return;
    };
    let Some(active) = snapshot.active_subscription.as_deref() else {
        return;
    };
    let message = if active == pending.requested
        && subscription_generation
            == pending
                .subscription_generation_before_request
                .wrapping_add(1)
    {
        format!("previous subscription request reconciled: {active} is active (reply was lost)")
    } else if active == pending.previous
        && subscription_generation == pending.subscription_generation_before_request
    {
        format!("previous subscription request reconciled: {active} remains active")
    } else {
        // Without a request id, a different active profile or an unexpected
        // generation could be a concurrent mutation (or daemon restart), not
        // proof of this request's outcome. Stay fail-closed.
        return;
    };
    app.subscription_outcome_unknown = None;
    app.set_message(MessageLevel::Warning, message);
}

/// Track cumulative totals and compute the current rate between snapshots.
fn update_traffic(app: &mut App, snap: &StatusSnapshot) {
    let (up, down) = traffic_totals(snap);
    app.total_up = up;
    app.total_down = down;
    if let Some((prev_up, prev_down, at)) = app.traffic_seed {
        let dt = at.elapsed().as_secs_f64().max(0.5);
        app.rate_up = up.saturating_sub(prev_up) as f64 / dt;
        app.rate_down = down.saturating_sub(prev_down) as f64 / dt;
    }
    app.traffic_seed = Some((up, down, Instant::now()));
}

fn traffic_totals(snap: &StatusSnapshot) -> (u64, u64) {
    snap.traffic.values().fold((0, 0), |(u, d), t| {
        (u.saturating_add(t.up), d.saturating_add(t.down))
    })
}

/// Unicode sparkline of the last 10 samples, scaled to their own
/// min/max (a flat history renders as the floor block).
fn sparkline(samples: &[f64]) -> String {
    const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let window = &samples[samples.len().saturating_sub(10)..];
    let min = window.iter().copied().fold(f64::INFINITY, f64::min);
    let max = window.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let span = (max - min).max(1.0);
    window
        .iter()
        .map(|v| {
            let idx = (((v - min) / span) * (BLOCKS.len() as f64 - 1.0)).round() as usize;
            BLOCKS[idx.min(BLOCKS.len() - 1)]
        })
        .collect()
}

fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

fn fmt_rate(bytes_per_sec: f64) -> String {
    let bps = bytes_per_sec.max(0.0);
    let mut v = bps;
    for unit in ["B", "KiB", "MiB", "GiB"] {
        if v < 1024.0 {
            return format!("{v:.1} {unit}/s");
        }
        v /= 1024.0;
    }
    format!("{v:.1} TiB/s")
}

/// One line per event, newest last, with a coarse age prefix.
fn event_line(now: i64, e: &control::Event) -> String {
    let age = now.saturating_sub(e.unix());
    let age_s = if age < 60 {
        format!("{age}s")
    } else if age < 3600 {
        format!("{}m", age / 60)
    } else {
        format!("{}h", age / 3600)
    };
    match e {
        control::Event::Switched {
            class,
            node,
            reason,
            generation,
            ..
        } => format!("[{age_s}] {class} → {node} ({reason}, gen {generation})"),
        control::Event::ActivationFailed {
            class, node, error, ..
        } => format!("[{age_s}] {class}: {node} activation failed — {error}"),
        control::Event::HealthFailed {
            class,
            node,
            consecutive,
            ..
        } => format!("[{age_s}] {class}: {node} health check failed (×{consecutive})"),
        control::Event::Probed {
            source, ok, total, ..
        } => format!("[{age_s}] probe ({source}): {ok}/{total} ok"),
        control::Event::Reloaded { detail, .. } => {
            format!("[{age_s}] reload: {detail}")
        }
        control::Event::SubscriptionChanged {
            previous,
            active,
            node_count,
            refreshed,
            ..
        } => {
            if *refreshed {
                format!("[{age_s}] subscription {active} refreshed ({node_count} nodes)")
            } else {
                format!("[{age_s}] subscription {previous} → {active} ({node_count} nodes)")
            }
        }
        control::Event::SubscriptionChangeFailed { profile, error, .. } => {
            format!("[{age_s}] subscription {profile} unchanged — {error}")
        }
    }
}

/// Node display order: probed first by success EMA descending, then RTT
/// ascending; unprobed nodes sort last by name. Subscription names lead;
/// stats-only names (stale entries from a previous pool) are appended.
fn ordered_names(
    snapshot: Option<&StatusSnapshot>,
    subs: &[String],
    probe_round: Option<&ProbeRound>,
) -> Vec<String> {
    let mut names: Vec<String> = subs.to_vec();
    if let Some(snapshot) = snapshot {
        // New daemons explicitly identify the active pool. Append stats-only
        // names only for old snapshots, where the control protocol did not
        // yet carry `available_nodes`.
        if snapshot.available_nodes.is_empty() {
            for k in snapshot.nodes.keys() {
                if !names.iter().any(|n| n == k) {
                    names.push(k.clone());
                }
            }
        }
    }
    names.sort_by(|a, b| {
        let (sa, sb) = (
            snapshot.and_then(|s| s.nodes.get(a)),
            snapshot.and_then(|s| s.nodes.get(b)),
        );
        if let Some(round) = probe_round {
            let ra = round.results.get(a);
            let rb = round.results.get(b);
            match (ra.map(|r| r.ok), rb.map(|r| r.ok)) {
                (Some(true), Some(false)) => return Ordering::Less,
                (Some(false), Some(true)) => return Ordering::Greater,
                (Some(true), Some(true)) => {
                    let stability = match (sa, sb) {
                        (Some(sa), Some(sb)) => success_cmp(sb.success_ema, sa.success_ema),
                        (Some(_), None) => Ordering::Less,
                        (None, Some(_)) => Ordering::Greater,
                        (None, None) => Ordering::Equal,
                    };
                    if stability != Ordering::Equal {
                        return stability;
                    }
                    let round_rtt = ra
                        .and_then(|r| r.rtt_ms)
                        .unwrap_or(f64::INFINITY)
                        .total_cmp(&rb.and_then(|r| r.rtt_ms).unwrap_or(f64::INFINITY));
                    if round_rtt != Ordering::Equal {
                        return round_rtt;
                    }
                    return match (sa, sb) {
                        (Some(sa), Some(sb)) => score_cmp(sb, sa).then_with(|| a.cmp(b)),
                        _ => a.cmp(b),
                    };
                }
                (Some(false), Some(false)) => {
                    return match (sa, sb) {
                        (Some(sa), Some(sb)) => score_cmp(sb, sa).then_with(|| a.cmp(b)),
                        (Some(_), None) => Ordering::Less,
                        (None, Some(_)) => Ordering::Greater,
                        (None, None) => a.cmp(b),
                    };
                }
                // A valid round is complete, so absence is defensive only.
                (Some(_), None) => return Ordering::Less,
                (None, Some(_)) => return Ordering::Greater,
                (None, None) => {}
            }
        }
        match (sa.map(|s| s.is_probed()), sb.map(|s| s.is_probed())) {
            (Some(true), Some(true)) => match (sa, sb) {
                (Some(sa), Some(sb)) => score_cmp(sb, sa).then_with(|| a.cmp(b)),
                _ => Ordering::Equal,
            },
            (Some(true), _) => Ordering::Less,
            (_, Some(true)) => Ordering::Greater,
            _ => a.cmp(b),
        }
    });
    names
}

fn select_up(app: &mut App) {
    if !app.order.is_empty() {
        app.selected = app.selected.saturating_sub(1);
    }
}

fn select_down(app: &mut App) {
    if !app.order.is_empty() {
        app.selected = (app.selected + 1).min(app.order.len() - 1);
    }
}

/// Fit the seven node-table columns into the terminal while preserving usable
/// minima. Ten cells are reserved for borders, column gaps, and the selection
/// marker. Extremely small terminals may still clip, but normal 64+ column
/// layouts no longer lose the right-hand columns unnecessarily.
fn node_table_column_lengths(total_width: u16) -> [u16; 7] {
    let mut widths = [16, 20, 8, 8, 10, 10, 10];
    let minima = [10, 10, 6, 6, 7, 7, 6];
    let budget = total_width.saturating_sub(10).max(minima.iter().sum());
    let shrink_order = [1, 0, 6, 4, 5, 2, 3];
    while widths.iter().sum::<u16>() > budget {
        let mut changed = false;
        for index in shrink_order {
            if widths[index] > minima[index] {
                widths[index] -= 1;
                changed = true;
                if widths.iter().sum::<u16>() <= budget {
                    break;
                }
            }
        }
        if !changed {
            break;
        }
    }
    widths
}

#[cfg(test)]
fn generation_label(snapshot: Option<&StatusSnapshot>, generation_known: bool) -> String {
    snapshot
        .filter(|_| generation_known)
        .map(|snapshot| snapshot.generation.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn class_overviews_from_state(app: &App, st: &state::StateFile) -> Vec<control::ClassOverview> {
    app.cfg_classes
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let cs = st.classes.get(name);
            control::ClassOverview {
                name: name.clone(),
                listen: app
                    .listens
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| "-".into()),
                active_node: cs.and_then(|c| c.active_node.clone()),
                generation: cs.map(|c| c.generation).unwrap_or(0),
                selection: app
                    .class_selections
                    .get(i)
                    .cloned()
                    .unwrap_or_default(),
            }
        })
        .collect()
}

/// Prefer the daemon's all-class strip; synthesize from local config when an
/// older daemon omitted it so the operator still sees every configured
/// gateway.
fn class_overviews(app: &App) -> Vec<control::ClassOverview> {
    if let Some(classes) = app.snapshot.as_ref().map(|s| &s.classes) {
        if !classes.is_empty() {
            return classes.clone();
        }
    }
    synthesized_class_overviews(app)
}

fn synthesized_class_overviews(app: &App) -> Vec<control::ClassOverview> {
    app.cfg_classes
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let listen = app
                .listens
                .get(i)
                .cloned()
                .unwrap_or_else(|| "-".into());
            let focused = app.class() == name.as_str();
            let (active_node, generation) = if focused {
                app.snapshot
                    .as_ref()
                    .map(|s| (s.active_node.clone(), s.generation))
                    .unwrap_or((None, 0))
            } else {
                (None, 0)
            };
            control::ClassOverview {
                name: name.clone(),
                listen,
                active_node,
                generation,
                selection: app
                    .class_selections
                    .get(i)
                    .cloned()
                    .unwrap_or_default(),
            }
        })
        .collect()
}

/// Pane heights for the four-row dashboard. The node table sizes to its
/// content; leftover rows go to the events feed so a short pool does not
/// leave a giant empty table.
fn dashboard_pane_heights(total: u16, class_count: usize, node_count: usize) -> [u16; 4] {
    let footer_h = FOOTER_ROWS.min(total);
    let class_h = (TABLE_CHROME.saturating_add(class_count.max(1) as u16))
        .min(total.saturating_sub(footer_h));
    let rest = total.saturating_sub(class_h.saturating_add(footer_h));
    let events_min = EVENTS_MIN_ROWS.min(rest);
    let table_budget = rest.saturating_sub(events_min);
    let node_wanted = TABLE_CHROME
        .saturating_add(node_count as u16)
        .max(MIN_NODE_TABLE_ROWS);
    let table_h = node_wanted
        .min(table_budget)
        .max(MIN_NODE_TABLE_ROWS.min(table_budget));
    let events_h = rest.saturating_sub(table_h);
    [class_h, table_h, events_h, footer_h]
}

/// Column layout for the five-column class strip: CLASS, GATEWAY, NODE,
/// SELECTION, GEN. Shrinks toward per-column minima (SELECTION first — it
/// is pure annotation — then NODE, GATEWAY, CLASS) so the widths fit the
/// terminal budget down to the minima sum; below that ratatui clips rather
/// than wraps.
fn class_strip_column_lengths(total_width: u16) -> [u16; 5] {
    let mut widths = [12, 20, 26, 18, 6];
    let minima = [6, 10, 10, 0, 3];
    let budget = total_width.saturating_sub(8);
    let shrink_order = [3, 2, 1, 0, 4];
    while widths.iter().sum::<u16>() > budget {
        let mut changed = false;
        for index in shrink_order {
            if widths[index] > minima[index] {
                widths[index] -= 1;
                changed = true;
                if widths.iter().sum::<u16>() <= budget {
                    break;
                }
            }
        }
        if !changed {
            break;
        }
    }
    widths
}

fn ui(f: &mut Frame, app: &App) {
    let active = app.snapshot.as_ref().and_then(|s| s.active_node.as_deref());

    let rows: Vec<Row> = app
        .order
        .iter()
        .map(|name| {
            let stats = app.snapshot.as_ref().and_then(|s| s.nodes.get(name));
            let rtt = stats
                .map(|s| {
                    if s.recent_rtts_ms.is_empty() {
                        s.rtt_ema_ms
                            .map(|r| format!("- {r:>5.1}"))
                            .unwrap_or_else(|| "-".into())
                    } else {
                        let spark = sparkline(&s.recent_rtts_ms);
                        let last = s.recent_rtts_ms.last().copied().unwrap_or(0.0);
                        format!("{spark} {last:>5.1}")
                    }
                })
                .unwrap_or_else(|| "-".into());
            let succ = stats
                .map(|s| format!("{:.3}", s.success_ema))
                .unwrap_or_else(|| "-".into());
            let fail = stats
                .map(|s| s.consecutive_health_failures.to_string())
                .unwrap_or_else(|| "-".into());
            let (up, down) = app
                .snapshot
                .as_ref()
                .and_then(|s| s.traffic.get(name))
                .map(|t| (t.up, t.down))
                .unwrap_or((0, 0));
            let best = recommended_node(app) == Some(name.as_str());
            let (name_cell, status) = if active == Some(name.as_str()) {
                (
                    Cell::from(format!("◉ {name}")).style(tokens::ok_bold()),
                    if best { "A/BEST" } else { "ACTIVE" },
                )
            } else {
                (Cell::from(name.as_str()), if best { "BEST" } else { "" })
            };
            Row::new(vec![
                name_cell,
                Cell::from(rtt),
                Cell::from(succ),
                Cell::from(fail),
                Cell::from(fmt_bytes(up)),
                Cell::from(fmt_bytes(down)),
                Cell::from(status),
            ])
        })
        .collect();

    let overviews = class_overviews(app);
    let [class_h, table_h, events_h, footer_h] = dashboard_pane_heights(
        f.area().height,
        overviews.len(),
        app.order.len(),
    );
    let [class_area, table_area, events_area, footer_area] = Layout::vertical([
        Constraint::Length(class_h),
        Constraint::Length(table_h),
        Constraint::Length(events_h),
        Constraint::Length(footer_h),
    ])
    .areas(f.area());

    render_class_strip(f, app, class_area, &overviews);

    let column_lengths = node_table_column_lengths(table_area.width);
    let widths = column_lengths.map(Constraint::Length);
    let table = Table::new(rows, widths)
        .header(
            Row::new([
                "NODE",
                if column_lengths[1] >= 11 {
                    "LATENCY(ms)"
                } else {
                    "RTT(ms)"
                },
                "SUCC↓",
                "HLTH-F",
                "UP",
                "DOWN",
                "STATUS",
            ])
            .style(Style::default().bold()),
        )
        .block(Block::bordered().title(node_table_title(app)))
        .row_highlight_style(tokens::focus())
        .highlight_symbol("› ");

    let mut state = TableState::default();
    state.select(if app.order.is_empty() {
        None
    } else {
        Some(app.selected.min(app.order.len() - 1))
    });

    f.render_stateful_widget(table, table_area, &mut state);

    // Recent-events feed: the daemon's "what just happened" answer. Kind
    // coloring is per-event; history rows are never rewritten.
    let now = state::now_unix();
    let ev_capacity = events_area.height.saturating_sub(2) as usize;
    let ev_lines: Vec<Line> = if app.events.is_empty() {
        vec![Line::from(Span::styled("no events yet", tokens::muted()))]
    } else {
        let width = events_area.width.saturating_sub(2) as usize;
        app.events
            .iter()
            .rev()
            .take(ev_capacity.max(1))
            .map(|e| {
                let mut line = event_line(now, e);
                if line.chars().count() > width {
                    line = crate::truncate(&line, width);
                }
                Line::from(Span::styled(line, Style::default().fg(event_color(e))))
            })
            .collect()
    };
    f.render_widget(
        Paragraph::new(ev_lines).block(Block::bordered().title(" events ")),
        events_area,
    );

    let (message, color) = footer_message(app);
    let traffic = Span::styled(
        format!(
            "conns {} │ total ▲ {} ▼ {} │ rate ▲ {} ▼ {}",
            app.snapshot.as_ref().map(|s| s.active_conns).unwrap_or(0),
            fmt_bytes(app.total_up),
            fmt_bytes(app.total_down),
            fmt_rate(app.rate_up),
            fmt_rate(app.rate_down),
        ),
        tokens::muted(),
    );
    // Derived from BINDINGS so the hint and the `?` overlay cannot drift.
    let help = Span::styled(footer_keys_hint(), tokens::muted());
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(message, Style::default().fg(color))),
            Line::from(traffic),
            Line::from(help),
        ]),
        footer_area,
    );

    if let Some(picker) = &app.subscription_picker {
        render_subscription_picker(f, app, picker);
    }
    if app.help_open {
        render_help_overlay(f);
    }
}

/// Node-table title: plain, filter-editing (with the live pattern), or
/// filtered with an honest narrowed/total count.
fn node_table_title(app: &App) -> String {
    let active = app
        .filter
        .as_ref()
        .is_some_and(|pattern| !pattern.is_empty());
    if app.filter_edit {
        let pattern = app.filter.clone().unwrap_or_default();
        format!(" {} {} · filter: {pattern}▏ ", app.class(), app.listen())
    } else if active {
        format!(
            " {} {} · filtered {}/{} ",
            app.class(),
            app.listen(),
            app.order.len(),
            app.order_full.len()
        )
    } else {
        format!(" {} {} · Enter switches this class ", app.class(), app.listen())
    }
}

/// One foreground color per event kind: successes read green, failures red,
/// routine cycles stay muted, subscription changes accent.
fn event_color(e: &control::Event) -> Color {
    match e {
        control::Event::Switched { .. } => tokens::OK,
        control::Event::ActivationFailed { .. }
        | control::Event::HealthFailed { .. }
        | control::Event::SubscriptionChangeFailed { .. } => tokens::ERROR,
        control::Event::SubscriptionChanged { .. } => tokens::ACCENT,
        control::Event::Probed { .. } | control::Event::Reloaded { .. } => tokens::MUTED,
    }
}

/// The footer's compact key list, derived from BINDINGS.
fn footer_keys_hint() -> String {
    BINDINGS
        .iter()
        .map(|(keys, _)| *keys)
        .collect::<Vec<_>>()
        .join(" │ ")
}

/// Paste-ready proxy exports for the focused class's gateway. Displayed in
/// the message line only — no clipboard is claimed; copying is terminal
/// selection. socks5h keeps remote DNS resolution on the gateway.
fn proxy_export_line(listen: &str) -> String {
    format!("export http_proxy=http://{listen} https_proxy=http://{listen} all_proxy=socks5h://{listen}")
}

/// The `?` overlay: every row comes from BINDINGS, so help can never list a
/// key that does not exist or omit one that does.
fn render_help_overlay(f: &mut Frame) {
    let width = 64u16.min(f.area().width);
    let height = (BINDINGS.len() as u16).saturating_add(2);
    let area = centered_rect(width, height, f.area());
    let lines: Vec<Line> = BINDINGS
        .iter()
        .map(|(keys, action)| {
            Line::from(vec![
                Span::styled(format!("{keys:<12} "), tokens::accent()),
                Span::raw(*action),
            ])
        })
        .collect();
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" keys ")),
        area,
    );
}

fn render_class_strip(
    f: &mut Frame,
    app: &App,
    area: Rect,
    overviews: &[control::ClassOverview],
) {
    // Honest connection segment: live age when answering, STALE when slow,
    // the state file's age when offline. Never paint "connected" over old
    // or absent data.
    let (conn_text, conn_color) = if app.connected {
        match app.last_live.map(|at| at.elapsed()) {
            None => ("daemon live · no snapshot yet".to_string(), tokens::ERROR),
            Some(age) => {
                let age_text = state::human_duration(age.as_secs() as i64);
                match staleness(Some(age)) {
                    Staleness::Fresh => {
                        (format!("daemon live · {age_text} ago"), tokens::MUTED)
                    }
                    Staleness::Stale => (
                        format!("daemon live · STALE {age_text} ago"),
                        tokens::WARN,
                    ),
                    Staleness::VeryStale => (
                        format!("daemon live · STALE {age_text} ago"),
                        tokens::ERROR,
                    ),
                }
            }
        }
    } else {
        let saved = app
            .state_updated_unix
            .map(|unix| format!(" · last state {} old", state::human_age(unix, state::now_unix())))
            .unwrap_or_else(|| " · no state file".to_string());
        (format!("daemon unreachable · OFFLINE{saved}"), tokens::ERROR)
    };
    let title = Line::from(vec![
        Span::raw(format!(
            " CAUSEWAY │ subscription {} │ ",
            app.subscription_label()
        )),
        Span::styled(conn_text, Style::default().fg(conn_color)),
        Span::raw(" "),
    ]);
    let column_lengths = class_strip_column_lengths(area.width);
    let widths = column_lengths.map(Constraint::Length);
    let rows = overviews.iter().map(|class| {
        let focused = class.name == app.class();
        let marker = if focused { "› " } else { "  " };
        let node = class.active_node.as_deref().unwrap_or("<none>");
        let gen = if class.generation == 0 && class.active_node.is_none() {
            "-".to_string()
        } else {
            class.generation.to_string()
        };
        let style = if focused {
            tokens::focus()
        } else {
            Style::default()
        };
        let sel_w = column_lengths[3] as usize;
        let selection = if class.selection.is_empty() {
            "-".to_string()
        } else {
            crate::truncate(&class.selection, sel_w)
        };
        Row::new(vec![
            format!("{marker}{}", class.name),
            class.listen.clone(),
            node.to_string(),
            selection,
            gen,
        ])
        .style(style)
    });
    let table = Table::new(rows, widths)
        .header(
            Row::new(["CLASS", "GATEWAY", "NODE", "SEL", "GEN"]).style(Style::default().bold()),
        )
        .block(Block::bordered().title(title));
    f.render_widget(table, area);
}

fn render_subscription_picker(f: &mut Frame, app: &App, picker: &SubscriptionPicker) {
    let width = f.area().width.saturating_sub(4).clamp(24, 58);
    let visible_rows = picker.entries.len().min(10) as u16;
    let height = (visible_rows + 4)
        .min(f.area().height.saturating_sub(2))
        .max(5);
    let area = centered_rect(width, height, f.area());
    let active = app.active_subscription();
    let (widths, visible_columns) = subscription_picker_columns(area.width);
    let rows = picker.entries.iter().map(|entry| {
        let marker = if active == Some(entry.name.as_str()) {
            "●"
        } else {
            " "
        };
        let count = entry
            .node_count
            .map(|n| format!("{n} nodes"))
            .unwrap_or_else(|| "-".to_string());
        let status = if active == Some(entry.name.as_str()) {
            "ACTIVE".to_string()
        } else {
            String::new()
        };
        let mut cells = vec![format!("{marker} {}", entry.name)];
        if visible_columns >= 2 {
            cells.push(count);
        }
        if visible_columns >= 3 {
            cells.push(status);
        }
        Row::new(cells)
    });
    let headers = ["PROFILE", "NODES", "STATUS"]
        .into_iter()
        .take(visible_columns)
        .collect::<Vec<_>>();
    let table = Table::new(rows, widths)
        .header(Row::new(headers).style(Style::default().bold()))
        .block(Block::bordered().title(Line::from(" subscriptions ").alignment(Alignment::Center)))
        .row_highlight_style(tokens::focus())
        .highlight_symbol("› ");
    let mut state = TableState::default().with_selected(Some(
        picker.selected.min(picker.entries.len().saturating_sub(1)),
    ));
    f.render_widget(Clear, area);
    f.render_stateful_widget(table, area, &mut state);

    let help_area = Rect {
        x: area.x.saturating_add(2),
        y: area.y.saturating_add(area.height.saturating_sub(2)),
        width: area.width.saturating_sub(4),
        height: 1,
    };
    let (picker_help, help_color) = if let Some(buffer) = &picker.url_edit {
        let target = picker
            .entries
            .get(picker.selected)
            .map(|entry| entry.name.as_str())
            .unwrap_or("?");
        (
            format!(
                "URL for {target}: \u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022} ({} chars, hidden) \u{2502} Enter save \u{2502} Esc cancel",
                buffer.chars().count()
            ),
            tokens::MUTED,
        )
    } else if app.subscription_mutation_allowed() {
        (
            "k/\u{2191} up \u{2502} j/\u{2193} down \u{2502} Enter switch \u{2502} e edit URL \u{2502} Esc cancel".to_string(),
            tokens::MUTED,
        )
    } else {
        (
            "VIEW ONLY \u{2502} k/\u{2191} up \u{2502} j/\u{2193} down \u{2502} Esc close"
                .to_string(),
            tokens::WARN,
        )
    };
    f.render_widget(
        Paragraph::new(picker_help)
            .alignment(Alignment::Center)
            .style(Style::default().fg(help_color)),
        help_area,
    );
}

/// Keep the picker within its bordered popup. The active marker remains in
/// the profile cell, so STATUS can disappear first without losing meaning.
fn subscription_picker_columns(total_width: u16) -> (Vec<Constraint>, usize) {
    const CHROME_WIDTH: u16 = 4; // borders plus the row highlight symbol
    let visible_columns: usize = if total_width >= 38 {
        3
    } else if total_width >= 24 {
        2
    } else {
        1
    };
    let gaps = visible_columns.saturating_sub(1) as u16;
    let budget = total_width
        .saturating_sub(CHROME_WIDTH + gaps)
        .max(visible_columns as u16);
    let widths = match visible_columns {
        3 => vec![
            Constraint::Length(budget.saturating_sub(13).max(1)),
            Constraint::Length(7),
            Constraint::Length(6),
        ],
        2 => vec![
            Constraint::Length(budget.saturating_sub(7).max(1)),
            Constraint::Length(7),
        ],
        _ => vec![Constraint::Length(budget)],
    };
    (widths, visible_columns)
}

fn footer_message(app: &App) -> (String, Color) {
    if app.filter_edit {
        let pattern = app.filter.clone().unwrap_or_default();
        return (
            format!("filter: {pattern}▏ │ Enter commit │ Esc clear"),
            tokens::ACCENT,
        );
    }
    if !app.connected {
        if app.offline_subscription.confirmed_name().is_none() {
            return (
                "OFFLINE — daemon unreachable; no confirmed active subscription (configured catalog only)"
                    .to_string(),
                tokens::ERROR,
            );
        }
        let saved = app
            .state_updated_unix
            .map(|unix| format!(", saved {} ago", state::human_age(unix, state::now_unix())))
            .unwrap_or_default();
        return (
            format!(
                "OFFLINE — daemon unreachable; showing last known state{saved} (subscription changes disabled)"
            ),
            tokens::ERROR,
        );
    }
    if app.busy() {
        return (app.message.clone(), tokens::WARN);
    }
    if app
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.subscription_txn_in_progress == Some(true))
    {
        return (
            "subscription change in progress — subscription picker is temporarily view-only"
                .to_string(),
            tokens::WARN,
        );
    }
    if !app.message.is_empty() {
        let color = match app.message_level {
            MessageLevel::Info => tokens::MUTED,
            MessageLevel::Success => tokens::OK,
            MessageLevel::Warning => tokens::WARN,
            MessageLevel::Error => tokens::ERROR,
        };
        return (app.message.clone(), color);
    }
    if app.authoritative_subscription_snapshot().is_none() {
        return (
            "connected to an older/incompatible daemon — subscription changes disabled".to_string(),
            tokens::WARN,
        );
    }
    // Default: age-stamped liveness. A daemon that answers slowly must read
    // as slow, not as fresh. A connected app with no live snapshot yet is a
    // broken invariant — render it as very stale, never "0s ago".
    match app.last_live.map(|at| at.elapsed()) {
        None => (
            "STALE — no live snapshot this session".to_string(),
            tokens::ERROR,
        ),
        Some(age) => {
            let age_text = state::human_duration(age.as_secs() as i64);
            match staleness(Some(age)) {
                Staleness::Fresh => (
                    format!("live data via control socket · {age_text} ago"),
                    tokens::MUTED,
                ),
                Staleness::Stale => (
                    format!("STALE — last live snapshot {age_text} ago"),
                    tokens::WARN,
                ),
                Staleness::VeryStale => (
                    format!("STALE — daemon answering slowly; data {age_text} old"),
                    tokens::ERROR,
                ),
            }
        }
    }
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}

/// Non-TTY path: live snapshot when the daemon is up, state-file fallback
/// (the classic `causeway status` report) otherwise.
async fn print_plain(cfg: &Config, class: &str, client: &Client) -> anyhow::Result<()> {
    match client
        .request(
            &Request::Status {
                class: class.to_string(),
            },
            STATUS_TIMEOUT,
        )
        .await
    {
        Ok(reply) if reply.ok => {
            if let Some(s) = &reply.status {
                print_snapshot(s);
                return Ok(());
            }
            anyhow::bail!("daemon replied ok without a snapshot");
        }
        Ok(reply) => anyhow::bail!(
            "daemon replied with an error: {}",
            reply.error.unwrap_or_else(|| "unknown error".into())
        ),
        Err(e) => {
            epln!("warning: daemon not reachable ({e:#}); falling back to the state file");
            crate::cmd_status(cfg)
        }
    }
}

fn print_snapshot(s: &StatusSnapshot) {
    // Source first: a plain report must say where its data came from.
    pln!("source: live daemon via control socket");
    if !s.classes.is_empty() {
        pln!(
            "{:<12} {:<22} {:<32} {:<20} {:<6}",
            "CLASS",
            "GATEWAY",
            "NODE",
            "SELECTION",
            "GEN"
        );
        for class in &s.classes {
            let marker = if class.name == s.class { "› " } else { "  " };
            pln!(
                "{:<12} {:<22} {:<32} {:<20} {:<6}",
                format!("{marker}{}", class.name),
                crate::truncate(&class.listen, 22),
                class
                    .active_node
                    .as_deref()
                    .map(|n| crate::truncate(n, 32))
                    .unwrap_or_else(|| "<none>".into()),
                if class.selection.is_empty() {
                    "-".to_string()
                } else {
                    crate::truncate(&class.selection, 20)
                },
                class.generation,
            );
        }
        pln!("");
    }
    pln!(
        "focused class {}: active {}, generation {}",
        s.class,
        s.active_node.as_deref().unwrap_or("<none>"),
        s.generation,
    );
    pln!(
        "{:<44} {:>8} {:>10} {:>8} {:>10} {:>10}",
        "NODE",
        "SUCC↓",
        "RTT (ms)",
        "HLTH-F",
        "UP",
        "DOWN"
    );
    let names = ordered_names(Some(s), &s.available_nodes, None);
    for name in names {
        let stats = s.nodes.get(&name);
        let (up, down) = s
            .traffic
            .get(&name)
            .map(|t| (t.up, t.down))
            .unwrap_or((0, 0));
        pln!(
            "{:<44} {:>8} {:>10} {:>8} {:>10} {:>10}",
            crate::truncate(&name, 44),
            stats
                .map(|st| format!("{:.3}", st.success_ema))
                .unwrap_or_else(|| "-".into()),
            stats
                .and_then(|st| st.rtt_ema_ms)
                .map(|r| format!("{r:.0}"))
                .unwrap_or_else(|| "-".into()),
            stats
                .map(|st| st.consecutive_health_failures.to_string())
                .unwrap_or_else(|| "-".into()),
            fmt_bytes(up),
            fmt_bytes(down),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::NodeStats;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::collections::BTreeMap;

    fn stats(success: f64, rtt: Option<f64>, probed: bool) -> NodeStats {
        NodeStats {
            success_ema: success,
            rtt_ema_ms: rtt,
            recent_rtts_ms: Vec::new(),
            consecutive_health_failures: 0,
            probe_count: if probed { 1 } else { 0 },
            last_probe_unix: if probed { Some(0) } else { None },
        }
    }

    #[test]
    fn sparkline_scales_to_blocks() {
        // A flat history renders as the floor block.
        assert!(sparkline(&[10.0, 10.0, 10.0]).chars().all(|c| c == '▁'));
        // A rising pair spans the whole range: floor then roof.
        let rising: Vec<char> = sparkline(&[0.0, 10.0]).chars().collect();
        assert_eq!(rising.first(), Some(&'▁'));
        assert_eq!(rising.last(), Some(&'█'));
    }

    fn snapshot(nodes: BTreeMap<String, NodeStats>) -> StatusSnapshot {
        StatusSnapshot {
            class: "dev".into(),
            active_node: None,
            socks_port: None,
            http_port: None,
            generation: 0,
            nodes,
            traffic: BTreeMap::new(),
            active_conns: 0,
            active_subscription: None,
            subscription_generation: None,
            subscription_txn_in_progress: None,
            available_subscriptions: Vec::new(),
            available_nodes: Vec::new(),
            classes: Vec::new(),
        }
    }

    fn authoritative_snapshot(active: &str) -> StatusSnapshot {
        let mut snap = snapshot(BTreeMap::new());
        snap.active_subscription = Some(active.into());
        snap.subscription_generation = Some(0);
        snap.subscription_txn_in_progress = Some(false);
        snap.available_subscriptions = vec![
            control::SubscriptionSummary {
                name: "primary".into(),
                node_count: (active == "primary").then_some(10),
            },
            control::SubscriptionSummary {
                name: "secondary".into(),
                node_count: (active == "secondary").then_some(20),
            },
        ];
        snap
    }

    fn tagged_snapshot(active: &str, generation: u64, nodes: &[&str]) -> StatusSnapshot {
        let mut snap = authoritative_snapshot(active);
        snap.subscription_generation = Some(generation);
        snap.available_nodes = nodes.iter().map(|node| (*node).to_string()).collect();
        snap
    }

    fn probe_result(node: &str, rtt_ms: Option<f64>) -> control::ProbeResult {
        control::ProbeResult {
            node: node.into(),
            ok: rtt_ms.is_some(),
            rtt_ms,
            http_status: None,
            error: None,
        }
    }

    fn valid_probe_round(tag: ProbeRoundTag, results: Vec<control::ProbeResult>) -> ProbeRound {
        classify_probe_reply(Ok(control::Reply::ok_probe(results)), Some(tag))
            .round
            .expect("test probe round should be valid")
    }

    fn connect_authoritatively(app: &mut App, active: &str) {
        app.connected = true;
        app.snapshot = Some(authoritative_snapshot(active));
        app.generation_known = true;
    }

    fn app_for_order() -> App {
        App {
            cfg_classes: vec!["dev".into()],
            listens: vec!["127.0.0.1:20100".into()],
            class_selections: vec![String::new()],
            class_idx: 0,
            state_file: PathBuf::from("/nonexistent"),
            subs: Vec::new(),
            configured_default_subscription: None,
            offline_subscription: OfflineSubscription::Unavailable,
            fallback_subscriptions: Vec::new(),
            fallback_profiles: BTreeMap::new(),
            fallback_profile_nodes: BTreeMap::new(),
            subscription_picker: None,
            subscription_outcome_unknown: None,
            last_probe_round: None,
            connected: false,
            snapshot: None,
            generation_known: false,
            order: Vec::new(),
            order_full: Vec::new(),
            selected: 0,
            status_flight: None,
            events_flight: None,
            mutation_flight: None,
            epoch: 0,
            last_live: None,
            last_events_refresh: Instant::now(),
            state_updated_unix: None,
            filter: None,
            filter_edit: false,
            help_open: false,
            quit_armed: false,
            status_spawns: 0,
            events_spawns: 0,
            message: String::new(),
            message_level: MessageLevel::Info,
            events: Vec::new(),
            traffic_seed: None,
            total_up: 0,
            total_down: 0,
            rate_up: 0.0,
            rate_down: 0.0,
            last_refresh: Instant::now(),
        }
    }

    #[test]
    fn offline_profile_distinguishes_persisted_from_configured_default() {
        let cfg: Config = toml::from_str(
            r#"
[subscriptions]
default = "primary"

[subscriptions.profiles.primary]
files = ["/test/primary.yaml"]

[subscriptions.profiles.backup]
files = ["/test/backup.yaml"]

[classes.dev]
listen = "127.0.0.1:20100"
"#,
        )
        .unwrap();
        let mut persisted = state::StateFile::default();
        persisted.activate_subscription("backup");

        assert_eq!(
            offline_subscription(&cfg, Some(&persisted)),
            OfflineSubscription::Persisted("backup".into())
        );

        persisted.activate_subscription("removed");
        assert_eq!(
            offline_subscription(&cfg, Some(&persisted)),
            OfflineSubscription::ConfiguredDefault("primary".into()),
            "a removed persisted profile is not claimed as active"
        );
        assert_eq!(
            offline_subscription(&cfg, None),
            OfflineSubscription::ConfiguredDefault("primary".into()),
            "missing state leaves only an explicitly unconfirmed catalog default"
        );
    }

    #[test]
    fn missing_or_corrupt_state_never_claims_an_active_profile() {
        let mut app = app_for_order();
        app.configured_default_subscription = Some("primary".into());
        app.offline_subscription = OfflineSubscription::ConfiguredDefault("primary".into());

        assert_eq!(app.active_subscription(), None);
        assert_eq!(app.subscription_label(), "primary (configured default)");
        let (message, color) = footer_message(&app);
        assert!(message.contains("no confirmed active subscription"));
        assert!(!message.contains("last known"));
        assert_eq!(color, tokens::ERROR);

        // A corrupt state file follows the same branch as a missing one.
        // refresh_from_file must also erase a stale in-memory assertion.
        app.state_file = std::env::temp_dir().join(format!(
            "causeway-corrupt-tui-state-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&app.state_file, b"not json").unwrap();
        app.snapshot = Some(authoritative_snapshot("secondary"));
        refresh_from_file(&mut app);
        assert!(app.snapshot.is_none());
        assert_eq!(app.active_subscription(), None);
        assert_eq!(
            app.offline_subscription,
            OfflineSubscription::ConfiguredDefault("primary".into())
        );
        std::fs::remove_file(&app.state_file).ok();
    }

    #[test]
    fn ordered_names_scores_first_unprobed_last() {
        let mut nodes = BTreeMap::new();
        nodes.insert("fast".into(), stats(1.0, Some(50.0), true));
        nodes.insert("slow".into(), stats(1.0, Some(200.0), true));
        nodes.insert("never".into(), stats(0.0, None, false));
        let snap = snapshot(nodes);
        let subs = vec!["slow".to_string(), "never".to_string(), "fast".to_string()];
        // Scored order regardless of subscription order; unprobed sinks to the end
        assert_eq!(
            ordered_names(Some(&snap), &subs, None),
            vec!["fast", "slow", "never"]
        );
    }

    #[test]
    fn ordered_names_prioritizes_success_over_rtt() {
        let mut nodes = BTreeMap::new();
        nodes.insert("reliable-slow".into(), stats(0.95, Some(900.0), true));
        nodes.insert("flaky-fast".into(), stats(0.80, Some(10.0), true));
        let snap = snapshot(nodes);

        assert_eq!(
            ordered_names(Some(&snap), &[], None),
            vec!["reliable-slow", "flaky-fast"],
            "success EMA sorts descending before RTT is considered"
        );
    }

    #[test]
    fn ordered_names_breaks_equal_success_by_lower_rtt() {
        let mut nodes = BTreeMap::new();
        nodes.insert("higher-rtt".into(), stats(0.95, Some(250.0), true));
        nodes.insert("lower-rtt".into(), stats(0.95, Some(25.0), true));
        let snap = snapshot(nodes);

        assert_eq!(
            ordered_names(Some(&snap), &[], None),
            vec!["lower-rtt", "higher-rtt"],
            "equal success EMA sorts by RTT ascending"
        );
    }

    #[test]
    fn ordered_names_does_not_freeze_on_vanishing_success_ema_lead() {
        let mut nodes = BTreeMap::new();
        nodes.insert("rb-slow".into(), stats(0.999999992, Some(284.0), true));
        nodes.insert("rb-fast".into(), stats(0.999999991, Some(46.0), true));
        nodes.insert("ra".into(), stats(0.999999991, Some(50.0), true));
        let snap = snapshot(nodes);

        assert_eq!(
            ordered_names(Some(&snap), &[], None),
            vec!["rb-fast", "ra", "rb-slow"],
            "a 1e-10 success lead must not pin a slow node above faster ones"
        );
    }

    #[test]
    fn ordered_names_appends_stale_snapshot_nodes() {
        let mut nodes = BTreeMap::new();
        nodes.insert("a".into(), stats(1.0, Some(10.0), true));
        nodes.insert("stale".into(), stats(0.5, Some(500.0), true)); // not in the subscription
        let snap = snapshot(nodes);
        let subs = vec!["a".to_string()];
        assert_eq!(ordered_names(Some(&snap), &subs, None), vec!["a", "stale"]);
    }

    #[test]
    fn probe_round_validation_accepts_unordered_complete_unique_results() {
        let snap = tagged_snapshot("primary", 7, &["a", "b", "c"]);
        let outcome = classify_probe_reply(
            Ok(control::Reply::ok_probe(vec![
                probe_result("c", None),
                probe_result("a", Some(30.0)),
                probe_result("b", Some(20.0)),
            ])),
            probe_round_tag(&snap),
        );

        let round = outcome.round.expect("unordered complete reply is valid");
        assert_eq!(
            round.results.keys().cloned().collect::<Vec<_>>(),
            ["a", "b", "c"]
        );
        assert_eq!(round.results["a"].rtt_ms, Some(30.0));
        assert!(!round.results["c"].ok);
    }

    #[test]
    fn probe_round_validation_rejects_missing_duplicate_and_malformed_results() {
        let snap = tagged_snapshot("primary", 7, &["a", "b"]);
        let cases = vec![
            vec![probe_result("a", Some(10.0))],
            vec![probe_result("a", Some(10.0)), probe_result("a", Some(20.0))],
            vec![probe_result("a", Some(f64::NAN)), probe_result("b", None)],
            vec![probe_result("a", Some(-1.0)), probe_result("b", None)],
            vec![
                control::ProbeResult {
                    node: "a".into(),
                    ok: true,
                    rtt_ms: None,
                    http_status: None,
                    error: None,
                },
                probe_result("b", None),
            ],
            vec![
                control::ProbeResult {
                    node: "a".into(),
                    ok: false,
                    rtt_ms: Some(10.0),
                    http_status: None,
                    error: None,
                },
                probe_result("b", None),
            ],
        ];

        for results in cases {
            let outcome = classify_probe_reply(
                Ok(control::Reply::ok_probe(results)),
                probe_round_tag(&snap),
            );
            assert!(outcome.round.is_none());
            assert_eq!(outcome.level, MessageLevel::Warning);
            assert!(outcome.message.contains("ranking unchanged"));
        }
    }

    #[test]
    fn incomplete_probe_message_denominator_counts_the_pool_not_the_rows() {
        // A panic-shortened (or otherwise missing-row) listing must render
        // "2/3 ok", not "2/2 ok": the denominator is the requested pool,
        // the same under-report class fixed daemon-side in Probed.total.
        let snap = tagged_snapshot("primary", 7, &["a", "b", "c"]);
        let outcome = classify_probe_reply(
            Ok(control::Reply::ok_probe(vec![
                probe_result("a", Some(10.0)),
                probe_result("b", Some(20.0)),
            ])),
            probe_round_tag(&snap),
        );
        assert!(outcome.round.is_none());
        assert!(
            outcome.message.contains("2/3 ok"),
            "short listing must not shrink the denominator: {}",
            outcome.message
        );
    }

    #[test]
    fn valid_probe_round_ranks_success_before_failure_then_stability_and_round_rtt() {
        let mut nodes = BTreeMap::new();
        nodes.insert("failed-best-history".into(), stats(1.0, Some(1.0), true));
        nodes.insert("stable-slow".into(), stats(0.95, Some(900.0), true));
        nodes.insert("flaky-fast".into(), stats(0.80, Some(5.0), true));
        nodes.insert("equal-a".into(), stats(0.90, Some(10.0), true));
        nodes.insert("equal-b".into(), stats(0.90, Some(500.0), true));
        let mut snap = tagged_snapshot(
            "primary",
            2,
            &[
                "failed-best-history",
                "stable-slow",
                "flaky-fast",
                "equal-a",
                "equal-b",
            ],
        );
        snap.nodes = nodes;
        let round = valid_probe_round(
            probe_round_tag(&snap).unwrap(),
            vec![
                probe_result("equal-b", Some(20.0)),
                probe_result("failed-best-history", None),
                probe_result("flaky-fast", Some(1.0)),
                probe_result("stable-slow", Some(1000.0)),
                probe_result("equal-a", Some(200.0)),
            ],
        );

        assert_eq!(
            ordered_names(Some(&snap), &snap.available_nodes, Some(&round)),
            [
                "stable-slow",
                "equal-b",
                "equal-a",
                "flaky-fast",
                "failed-best-history"
            ]
        );
    }

    #[test]
    fn probe_round_sort_is_independent_of_reply_completion_order() {
        let mut snap = tagged_snapshot("primary", 1, &["a", "b"]);
        snap.nodes.insert("a".into(), stats(0.9, Some(100.0), true));
        snap.nodes.insert("b".into(), stats(0.9, Some(100.0), true));
        let tag = probe_round_tag(&snap).unwrap();
        let first = valid_probe_round(
            tag.clone(),
            vec![probe_result("a", Some(30.0)), probe_result("b", Some(10.0))],
        );
        let reversed = valid_probe_round(
            tag,
            vec![probe_result("b", Some(10.0)), probe_result("a", Some(30.0))],
        );

        assert_eq!(
            ordered_names(Some(&snap), &snap.available_nodes, Some(&first)),
            ordered_names(Some(&snap), &snap.available_nodes, Some(&reversed))
        );
    }

    #[test]
    fn selection_clamps_to_range() {
        let mut app = app_for_order();
        app.order = vec!["a".into(), "b".into()];
        app.selected = 5; // out of range on purpose
        select_down(&mut app);
        assert_eq!(app.selected, 1, "down clamps at the last row");
        select_up(&mut app);
        select_up(&mut app);
        assert_eq!(app.selected, 0, "up clamps at the first row");
    }

    #[test]
    fn picker_opens_on_active_profile_and_clamps_navigation() {
        let mut app = app_for_order();
        connect_authoritatively(&mut app, "secondary");

        open_subscription_picker(&mut app);
        assert_eq!(app.subscription_picker.as_ref().unwrap().selected, 1);
        assert_eq!(picker_key(&mut app, KeyCode::Down), PickerAction::None);
        assert_eq!(app.subscription_picker.as_ref().unwrap().selected, 1);
        assert_eq!(picker_key(&mut app, KeyCode::Up), PickerAction::None);
        assert_eq!(app.subscription_picker.as_ref().unwrap().selected, 0);
        assert_eq!(picker_key(&mut app, KeyCode::Up), PickerAction::None);
        assert_eq!(app.subscription_picker.as_ref().unwrap().selected, 0);
    }

    #[test]
    fn picker_enter_returns_profile_and_escape_only_closes() {
        let mut app = app_for_order();
        connect_authoritatively(&mut app, "primary");

        open_subscription_picker(&mut app);
        assert_eq!(picker_key(&mut app, KeyCode::Down), PickerAction::None);
        assert_eq!(
            picker_key(&mut app, KeyCode::Enter),
            PickerAction::Switch("secondary".into())
        );
        assert!(app.subscription_picker.is_none());

        open_subscription_picker(&mut app);
        assert_eq!(picker_key(&mut app, KeyCode::Esc), PickerAction::Close);
        assert!(app.subscription_picker.is_none());
    }

    #[test]
    fn picker_enter_on_active_profile_is_a_noop() {
        let mut app = app_for_order();
        connect_authoritatively(&mut app, "primary");

        open_subscription_picker(&mut app);
        assert_eq!(picker_key(&mut app, KeyCode::Enter), PickerAction::Close);
        assert_eq!(app.message, "subscription primary is already active");
        assert!(app.subscription_picker.is_none());
    }

    #[test]
    fn picker_reports_an_in_progress_transaction_as_busy() {
        let mut app = app_for_order();
        connect_authoritatively(&mut app, "primary");
        app.snapshot.as_mut().unwrap().subscription_txn_in_progress = Some(true);

        open_subscription_picker(&mut app);
        assert_eq!(picker_key(&mut app, KeyCode::Down), PickerAction::None);
        assert_eq!(picker_key(&mut app, KeyCode::Enter), PickerAction::Close);
        assert!(app.message.contains("in progress"));
        assert!(!app.message.contains("does not provide"));

        app.set_message(MessageLevel::Success, "stale completed transaction");
        let (message, color) = footer_message(&app);
        assert_eq!(
            message,
            "subscription change in progress — subscription picker is temporarily view-only"
        );
        assert_eq!(color, tokens::WARN);
    }

    #[test]
    fn subscription_picker_render_stays_within_narrow_terminals() {
        let mut app = app_for_order();
        connect_authoritatively(&mut app, "primary");
        open_subscription_picker(&mut app);

        for width in [20, 24, 42] {
            let mut terminal = Terminal::new(TestBackend::new(width, 12)).unwrap();
            terminal
                .draw(|frame| {
                    render_subscription_picker(
                        frame,
                        &app,
                        app.subscription_picker.as_ref().unwrap(),
                    );
                })
                .unwrap();

            let popup_width = width.saturating_sub(4).clamp(24, 58).min(width);
            let popup_height = 6;
            let area = centered_rect(popup_width, popup_height, Rect::new(0, 0, width, 12));
            let buffer = terminal.backend().buffer();
            assert_eq!(buffer.cell((area.x, area.y)).unwrap().symbol(), "┌");
            assert_eq!(
                buffer
                    .cell((area.x + area.width - 1, area.y))
                    .unwrap()
                    .symbol(),
                "┐"
            );

            let rendered = (area.y..area.y + area.height)
                .map(|y| {
                    (area.x..area.x + area.width)
                        .map(|x| buffer.cell((x, y)).unwrap().symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(rendered.contains("PROFILE"));
            assert_eq!(rendered.contains("NODES"), popup_width >= 24);
            assert_eq!(rendered.contains("STATUS"), popup_width >= 38);
        }
    }

    #[test]
    fn subscription_picker_column_budget_never_exceeds_popup() {
        for width in 1..=58 {
            let (columns, count) = subscription_picker_columns(width);
            let used = columns
                .iter()
                .map(|constraint| match constraint {
                    Constraint::Length(length) => *length,
                    _ => panic!("picker columns must have deterministic lengths"),
                })
                .sum::<u16>()
                + count.saturating_sub(1) as u16
                + 4;
            if width >= 5 {
                assert!(used <= width, "{width}-column popup uses {used} columns");
            }
        }
    }

    #[test]
    fn offline_and_old_daemon_pickers_are_view_only() {
        let mut app = app_for_order();
        app.offline_subscription = OfflineSubscription::Persisted("primary".into());
        app.fallback_subscriptions = vec![
            control::SubscriptionSummary {
                name: "primary".into(),
                node_count: Some(10),
            },
            control::SubscriptionSummary {
                name: "secondary".into(),
                node_count: Some(20),
            },
        ];

        open_subscription_picker(&mut app);
        assert_eq!(picker_key(&mut app, KeyCode::Down), PickerAction::None);
        assert_eq!(picker_key(&mut app, KeyCode::Enter), PickerAction::Close);
        assert_eq!(app.message_level, MessageLevel::Warning);

        app.connected = true;
        app.snapshot = Some(snapshot(BTreeMap::new()));
        open_subscription_picker(&mut app);
        assert_eq!(picker_key(&mut app, KeyCode::Down), PickerAction::None);
        assert_eq!(picker_key(&mut app, KeyCode::Enter), PickerAction::Close);
        assert!(app.message.contains("view-only"));
    }

    #[test]
    fn authoritative_subscription_status_requires_coherent_capability_fields() {
        let mut snap = snapshot(BTreeMap::new());
        assert!(!authoritative_subscription_status(&snap));
        snap.active_subscription = Some("primary".into());
        assert!(!authoritative_subscription_status(&snap));
        snap.available_subscriptions = vec![control::SubscriptionSummary {
            name: "secondary".into(),
            node_count: None,
        }];
        assert!(!authoritative_subscription_status(&snap));
        snap.available_subscriptions
            .push(control::SubscriptionSummary {
                name: "primary".into(),
                node_count: Some(1),
            });
        assert!(
            !authoritative_subscription_status(&snap),
            "an old daemon lacks safe lost-reply reconciliation fields"
        );
        snap.subscription_generation = Some(0);
        snap.subscription_txn_in_progress = Some(false);
        assert!(authoritative_subscription_status(&snap));
    }

    #[test]
    fn unknown_subscription_reply_locks_until_authoritative_reconciliation() {
        let mut app = app_for_order();
        connect_authoritatively(&mut app, "primary");
        let changed = apply_subscription_reply_result(
            &mut app,
            classify_subscription_reply(Err(anyhow::anyhow!("client timed out before reply"))),
            "primary".into(),
            "secondary".into(),
            0,
        );
        assert!(!changed);
        assert!(app.message.contains("outcome unknown"));
        assert!(!app.subscription_mutation_allowed());

        let old_status = snapshot(BTreeMap::new());
        reconcile_subscription_outcome(&mut app, &old_status);
        assert!(app.subscription_outcome_unknown.is_some());

        let mut still_staging = authoritative_snapshot("primary");
        still_staging.subscription_txn_in_progress = Some(true);
        reconcile_subscription_outcome(&mut app, &still_staging);
        assert!(
            app.subscription_outcome_unknown.is_some(),
            "the pre-transaction profile must not reconcile while staging is in progress"
        );

        let mut reconciled = authoritative_snapshot("secondary");
        reconciled.subscription_generation = Some(1);
        reconcile_subscription_outcome(&mut app, &reconciled);
        assert!(app.subscription_outcome_unknown.is_none());
        assert!(app.message.contains("reply was lost"));
    }

    #[test]
    fn unknown_subscription_reply_can_reconcile_a_completed_failure() {
        let mut app = app_for_order();
        connect_authoritatively(&mut app, "primary");
        app.subscription_outcome_unknown = Some(SubscriptionOutcomeUnknown {
            previous: "primary".into(),
            requested: "secondary".into(),
            subscription_generation_before_request: 4,
        });

        let mut completed = authoritative_snapshot("primary");
        completed.subscription_generation = Some(4);
        reconcile_subscription_outcome(&mut app, &completed);

        assert!(app.subscription_outcome_unknown.is_none());
        assert!(app.message.contains("remains active"));
    }

    #[test]
    fn unknown_subscription_reply_stays_locked_on_ambiguous_generation() {
        let mut app = app_for_order();
        connect_authoritatively(&mut app, "primary");
        app.subscription_outcome_unknown = Some(SubscriptionOutcomeUnknown {
            previous: "primary".into(),
            requested: "secondary".into(),
            subscription_generation_before_request: 4,
        });

        let mut wrong_generation = authoritative_snapshot("secondary");
        wrong_generation.subscription_generation = Some(4);
        reconcile_subscription_outcome(&mut app, &wrong_generation);
        assert!(app.subscription_outcome_unknown.is_some());

        let mut different_profile = authoritative_snapshot("tertiary");
        different_profile
            .available_subscriptions
            .push(control::SubscriptionSummary {
                name: "tertiary".into(),
                node_count: Some(3),
            });
        different_profile.subscription_generation = Some(5);
        reconcile_subscription_outcome(&mut app, &different_profile);
        assert!(app.subscription_outcome_unknown.is_some());
    }

    #[test]
    fn malformed_ok_mutation_replies_are_unknown_not_success() {
        match classify_subscription_reply(Ok(control::Reply::ok())) {
            SubscriptionReplyResult::Unknown(message) => {
                assert!(message.contains("without an outcome"));
            }
            _ => panic!("missing subscription outcome must be unknown"),
        }
        let (level, message) = classify_switch_reply(Ok(control::Reply::ok()), "node-a");
        assert_eq!(level, MessageLevel::Warning);
        assert!(message.contains("outcome unknown"));
        let outcome = classify_probe_reply(Ok(control::Reply::ok()), None);
        assert_eq!(outcome.level, MessageLevel::Warning);
        assert!(outcome.message.contains("outcome unknown"));
    }

    #[test]
    fn completed_probe_message_reports_recommendation_or_no_usable_node() {
        let (level, message) = completed_probe_message(2, 3, true, Some("node-b"));
        assert_eq!(level, MessageLevel::Success);
        assert!(message.contains("recommended node-b"));

        let (level, message) = completed_probe_message(0, 3, true, Some("failed-node"));
        assert_eq!(level, MessageLevel::Warning);
        assert!(message.contains("no usable recommendation"));
        assert!(!message.contains("failed-node"));
    }

    #[test]
    fn snapshot_tag_change_clears_probe_round_and_preserves_selected_node() {
        let mut app = app_for_order();
        let mut first = tagged_snapshot("primary", 4, &["a", "b"]);
        first
            .nodes
            .insert("a".into(), stats(0.9, Some(100.0), true));
        first
            .nodes
            .insert("b".into(), stats(0.9, Some(100.0), true));
        let round = valid_probe_round(
            probe_round_tag(&first).unwrap(),
            vec![probe_result("a", Some(50.0)), probe_result("b", Some(10.0))],
        );
        app.subs = first.available_nodes.clone();
        app.snapshot = Some(first);
        app.last_probe_round = Some(round);
        app.order = vec!["a".into(), "b".into()];
        app.selected = 0;

        rebuild_order(&mut app);
        assert_eq!(app.order, ["b", "a"]);
        assert_eq!(
            app.order[app.selected], "a",
            "selection follows node identity"
        );
        assert!(app.last_probe_round.is_some());

        let changed = tagged_snapshot("primary", 5, &["a", "b"]);
        apply_live_snapshot(&mut app, changed);
        rebuild_order(&mut app);
        assert!(app.last_probe_round.is_none());
        assert_eq!(app.order[app.selected], "a");

        let current = tagged_snapshot("primary", 5, &["a", "b"]);
        app.last_probe_round = Some(valid_probe_round(
            probe_round_tag(&current).unwrap(),
            vec![probe_result("a", Some(20.0)), probe_result("b", Some(10.0))],
        ));
        apply_live_snapshot(&mut app, tagged_snapshot("primary", 5, &["a", "c"]));
        rebuild_order(&mut app);
        assert!(
            app.last_probe_round.is_none(),
            "same generation with a different complete pool also invalidates the round"
        );
    }

    #[test]
    fn probe_apply_then_live_refresh_produces_and_keeps_round_order() {
        let mut app = app_for_order();
        let mut snap = tagged_snapshot("primary", 3, &["a", "b", "c"]);
        snap.nodes.insert("a".into(), stats(0.8, Some(10.0), true));
        snap.nodes.insert("b".into(), stats(0.9, Some(900.0), true));
        snap.nodes.insert("c".into(), stats(1.0, Some(1.0), true));
        let outcome = classify_probe_reply(
            Ok(control::Reply::ok_probe(vec![
                probe_result("c", None),
                probe_result("a", Some(5.0)),
                probe_result("b", Some(100.0)),
            ])),
            probe_round_tag(&snap),
        );
        app.last_probe_round = outcome.round;

        apply_live_snapshot(&mut app, snap.clone());
        rebuild_order(&mut app);
        assert_eq!(app.order, ["b", "a", "c"]);
        assert!(app.last_probe_round.is_some());

        apply_live_snapshot(&mut app, snap);
        rebuild_order(&mut app);
        assert_eq!(app.order, ["b", "a", "c"]);
        assert!(app.last_probe_round.is_some());
    }

    #[test]
    fn offline_banner_overrides_stale_success_message() {
        let mut app = app_for_order();
        app.message = "subscription changed".into();
        app.message_level = MessageLevel::Success;
        let (message, color) = footer_message(&app);
        assert!(message.starts_with("OFFLINE"));
        assert_eq!(color, tokens::ERROR);
    }

    #[test]
    fn current_pool_filters_stale_stats_from_display() {
        let mut nodes = BTreeMap::new();
        nodes.insert("current".into(), stats(0.8, Some(50.0), true));
        nodes.insert("stale".into(), stats(1.0, Some(1.0), true));
        let mut snap = snapshot(nodes);
        snap.available_nodes = vec!["current".into()];

        assert_eq!(
            ordered_names(Some(&snap), &snap.available_nodes, None),
            ["current"]
        );
    }

    #[test]
    fn current_pool_keeps_unprobed_nodes_in_plain_and_tui_order() {
        let mut nodes = BTreeMap::new();
        nodes.insert("probed".into(), stats(0.8, Some(50.0), true));
        let mut snap = snapshot(nodes);
        snap.available_nodes = vec!["unprobed".into(), "probed".into()];

        assert_eq!(
            ordered_names(Some(&snap), &snap.available_nodes, None),
            ["probed", "unprobed"]
        );
    }

    #[test]
    fn node_table_columns_shrink_to_fit_common_narrow_terminals() {
        assert_eq!(node_table_column_lengths(100), [16, 20, 8, 8, 10, 10, 10]);
        for width in [64, 72, 80, 90] {
            let columns = node_table_column_lengths(width);
            assert!(columns.iter().sum::<u16>() <= width - 10);
            assert!(columns.iter().all(|column| *column > 0));
        }
        assert!(node_table_column_lengths(80)[1] < 20);
    }

    #[test]
    fn dashboard_keeps_node_table_to_content_height() {
        let [class_h, table_h, events_h, footer_h] = dashboard_pane_heights(40, 3, 16);
        assert_eq!(class_h, 6, "3 chrome + 3 class rows");
        assert_eq!(table_h, 19, "3 chrome + 16 nodes, not stretched");
        assert_eq!(footer_h, 3);
        assert_eq!(class_h + table_h + events_h + footer_h, 40);
        assert!(events_h >= EVENTS_MIN_ROWS);

        let [_, short_table, leftover_events, _] = dashboard_pane_heights(40, 3, 2);
        assert_eq!(short_table, MIN_NODE_TABLE_ROWS);
        assert!(
            leftover_events > events_h,
            "leftover rows belong to events, not an empty node table"
        );
    }

    #[test]
    fn class_overviews_prefer_daemon_strip() {
        let mut app = app_for_order();
        app.cfg_classes = vec!["browser".into(), "dev".into()];
        app.listens = vec!["127.0.0.1:20120".into(), "127.0.0.1:20100".into()];
        app.class_idx = 1;
        let mut snap = snapshot(BTreeMap::new());
        snap.class = "dev".into();
        snap.active_node = Some("ra-dev".into());
        snap.classes = vec![
            control::ClassOverview {
                name: "browser".into(),
                listen: "127.0.0.1:20120".into(),
                active_node: Some("rb-browser".into()),
                generation: 4,
                selection: String::new(),
            },
            control::ClassOverview {
                name: "dev".into(),
                listen: "127.0.0.1:20100".into(),
                active_node: Some("ra-dev".into()),
                generation: 9,
                selection: String::new(),
            },
        ];
        app.snapshot = Some(snap);

        let overviews = class_overviews(&app);
        assert_eq!(overviews.len(), 2);
        assert_eq!(overviews[0].active_node.as_deref(), Some("rb-browser"));
        assert_eq!(overviews[1].active_node.as_deref(), Some("ra-dev"));
    }

    #[test]
    fn class_overviews_synthesize_from_config_when_daemon_omits_strip() {
        let mut app = app_for_order();
        app.cfg_classes = vec!["browser".into(), "dev".into()];
        app.listens = vec!["127.0.0.1:20120".into(), "127.0.0.1:20100".into()];
        app.class_idx = 1;
        let mut snap = snapshot(BTreeMap::new());
        snap.class = "dev".into();
        snap.active_node = Some("ra-dev".into());
        snap.generation = 9;
        app.snapshot = Some(snap);

        let overviews = class_overviews(&app);
        assert_eq!(overviews[0].name, "browser");
        assert_eq!(overviews[0].listen, "127.0.0.1:20120");
        assert_eq!(overviews[0].active_node, None);
        assert_eq!(overviews[1].name, "dev");
        assert_eq!(overviews[1].active_node.as_deref(), Some("ra-dev"));
        assert_eq!(overviews[1].generation, 9);
    }

    #[test]
    fn unknown_generation_uses_a_dash() {
        assert_eq!(generation_label(None, false), "-");
        let snap = snapshot(BTreeMap::new());
        assert_eq!(generation_label(Some(&snap), false), "-");
        assert_eq!(generation_label(Some(&snap), true), "0");
    }

    #[test]
    fn offline_state_missing_selected_class_keeps_generation_unknown() {
        let mut app = app_for_order();
        app.state_file = std::env::temp_dir().join(format!(
            "causeway-tui-missing-class-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut persisted = state::StateFile::default();
        persisted.classes.insert(
            "other".into(),
            state::ClassState {
                generation: 9,
                ..Default::default()
            },
        );
        state::save_atomic(&app.state_file, &persisted).unwrap();

        refresh_from_file(&mut app);

        assert!(
            app.snapshot.is_some(),
            "global offline data remains available"
        );
        assert!(!app.generation_known);
        assert_eq!(
            generation_label(app.snapshot.as_ref(), app.generation_known),
            "-"
        );
        std::fs::remove_file(&app.state_file).ok();
    }

    #[test]
    fn bytes_and_rate_formatting() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(15 * 1024 * 1024), "15.0 MiB");
        assert_eq!(fmt_rate(0.0), "0.0 B/s");
        assert_eq!(fmt_rate(2048.0), "2.0 KiB/s");
    }

    fn app_with_url_edit_target(active: &str) -> (App, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "causeway-url-edit-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut app = app_for_order();
        for profile in ["primary", "secondary"] {
            app.fallback_profiles.insert(
                profile.into(),
                crate::config::SubscriptionProfileConfig {
                    files: Vec::new(),
                    url_file: Some(dir.join(format!("{profile}.url"))),
                    cache_file: None,
                },
            );
        }
        app.fallback_profiles.insert(
            "local".into(),
            crate::config::SubscriptionProfileConfig {
                files: vec![dir.join("local.yaml")],
                url_file: None,
                cache_file: None,
            },
        );
        connect_authoritatively(&mut app, active);
        (app, dir)
    }

    #[test]
    fn url_edit_opens_only_for_remote_profiles() {
        let (mut app, dir) = app_with_url_edit_target("primary");

        open_subscription_picker(&mut app);
        assert_eq!(picker_key(&mut app, KeyCode::Char('e')), PickerAction::None);
        assert!(app.subscription_picker.as_ref().unwrap().url_edit.is_some());

        // A local file profile has no URL secret to edit.
        picker_key(&mut app, KeyCode::Esc);
        app.subscription_picker
            .as_mut()
            .unwrap()
            .entries
            .push(control::SubscriptionSummary {
                name: "local".into(),
                node_count: None,
            });
        let last = app.subscription_picker.as_ref().unwrap().entries.len() - 1;
        app.subscription_picker.as_mut().unwrap().selected = last;
        assert_eq!(picker_key(&mut app, KeyCode::Char('e')), PickerAction::None);
        assert!(app.subscription_picker.as_ref().unwrap().url_edit.is_none());
        assert!(app.message.contains("local file profile"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn url_edit_input_stays_masked_and_cancellable() {
        let (mut app, dir) = app_with_url_edit_target("primary");
        open_subscription_picker(&mut app);
        picker_key(&mut app, KeyCode::Char('e'));

        for c in "https://subscription.example/secret-marker".chars() {
            picker_key(&mut app, KeyCode::Char(c));
        }
        let buffer_len = app
            .subscription_picker
            .as_ref()
            .unwrap()
            .url_edit
            .as_ref()
            .unwrap()
            .len();
        assert_eq!(
            buffer_len,
            "https://subscription.example/secret-marker".len()
        );

        // Backspace works; the rendered frame never echoes the secret.
        picker_key(&mut app, KeyCode::Backspace);
        let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
        terminal
            .draw(|frame| {
                render_subscription_picker(frame, &app, app.subscription_picker.as_ref().unwrap());
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let rendered = (0..12)
            .map(|y| {
                (0..80)
                    .map(|x| buffer.cell((x, y)).unwrap().symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!rendered.contains("secret-marker"));
        assert!(!rendered.contains("subscription.example"));
        assert!(rendered.contains("hidden"));

        // Esc cancels without touching the URL file.
        picker_key(&mut app, KeyCode::Esc);
        assert!(app.subscription_picker.as_ref().unwrap().url_edit.is_none());
        assert!(!dir.join("primary.url").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn url_edit_rejects_invalid_urls_without_writing() {
        let (mut app, dir) = app_with_url_edit_target("primary");
        for attempt in [
            "http://insecure.example/sub",
            "https://",
            "https://has space.example/",
        ] {
            open_subscription_picker(&mut app);
            picker_key(&mut app, KeyCode::Char('e'));
            for c in attempt.chars() {
                picker_key(&mut app, KeyCode::Char(c));
            }
            assert_eq!(picker_key(&mut app, KeyCode::Enter), PickerAction::None);
            assert!(app.message.contains("invalid subscription URL"));
            assert!(!dir.join("primary.url").exists());
            assert!(app.subscription_picker.as_ref().unwrap().url_edit.is_none());
            picker_key(&mut app, KeyCode::Esc);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn url_edit_saves_atomically_and_keeps_picker_for_inactive_profile() {
        let (mut app, dir) = app_with_url_edit_target("primary");
        // The edit target is the inactive "secondary" profile: saving must not
        // trigger a switch; the operator confirms with Enter afterwards.
        open_subscription_picker(&mut app);
        picker_key(&mut app, KeyCode::Down);
        picker_key(&mut app, KeyCode::Char('e'));
        let url = "https://subscription.example/new?token=fixture";
        for c in url.chars() {
            picker_key(&mut app, KeyCode::Char(c));
        }
        assert_eq!(picker_key(&mut app, KeyCode::Enter), PickerAction::None);

        let url_file = dir.join("secondary.url");
        assert_eq!(
            std::fs::read_to_string(&url_file).unwrap(),
            format!("{url}\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&url_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!dir.join("secondary.url.tmp").exists());
        assert!(app.message.contains("press Enter on it to switch"));
        assert!(app.subscription_picker.is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn url_edit_on_active_profile_reroutes_through_checked_switch() {
        let (mut app, dir) = app_with_url_edit_target("primary");
        open_subscription_picker(&mut app);
        picker_key(&mut app, KeyCode::Char('e'));
        let url = "https://subscription.example/replacement?token=fixture";
        for c in url.chars() {
            picker_key(&mut app, KeyCode::Char(c));
        }
        assert_eq!(
            picker_key(&mut app, KeyCode::Enter),
            PickerAction::Switch("primary".into())
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("primary.url")).unwrap(),
            format!("{url}\n")
        );
        assert!(app.subscription_picker.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    // ---- refresh spine: cadence gating, never-overlap, epoch discard ----

    fn dropped_rx() -> oneshot::Receiver<anyhow::Result<control::Reply>> {
        let (_tx, rx) = oneshot::channel();
        rx
    }

    fn flight_for(
        kind: Option<MutationKind>,
        class: &str,
        epoch: u64,
    ) -> InFlight {
        InFlight {
            kind,
            class: class.to_string(),
            epoch,
            rx: dropped_rx(),
        }
    }

    #[test]
    fn status_lane_follows_cadence_and_never_overlaps() {
        let mut app = app_for_order();
        app.last_refresh = Instant::now();
        assert!(!should_spawn_status(&app), "cadence not due yet");
        app.last_refresh = Instant::now() - REFRESH_EVERY;
        assert!(should_spawn_status(&app));
        app.status_flight = Some(flight_for(None, "dev", 0));
        assert!(
            !should_spawn_status(&app),
            "at most one status request in flight"
        );
    }

    #[test]
    fn refresh_lane_is_independent_of_a_pending_mutation() {
        let mut app = app_for_order();
        app.last_refresh = Instant::now() - REFRESH_EVERY;
        app.mutation_flight = Some(flight_for(
            Some(MutationKind::ProbeAll { requested_tag: None }),
            "dev",
            0,
        ));
        assert!(app.busy());
        assert!(
            should_spawn_status(&app),
            "a pending mutation must not stall the refresh lane"
        );
    }

    #[test]
    fn events_lane_paces_itself_and_only_fetches_while_connected() {
        let mut app = app_for_order();
        app.last_events_refresh = Instant::now() - REFRESH_EVERY;
        assert!(
            !should_spawn_events(&app),
            "offline: events live only in daemon memory"
        );
        app.connected = true;
        assert!(should_spawn_events(&app));
        app.events_flight = Some(flight_for(None, "dev", 0));
        assert!(
            !should_spawn_events(&app),
            "at most one events request in flight"
        );
        // The status lane's clock must not gate events (nor reset it): a
        // healthy status lane used to starve the feed entirely.
        app.events_flight = None;
        app.last_refresh = Instant::now();
        assert!(
            should_spawn_events(&app),
            "events pace on their own clock, not the status clock"
        );
    }

    #[test]
    fn superseded_status_replies_are_discarded_by_class_and_epoch() {
        let mut app = app_for_order();
        let mut nodes = BTreeMap::new();
        nodes.insert("old".into(), stats(0.9, Some(10.0), true));
        app.snapshot = Some(snapshot(nodes));
        let fresh = snapshot(BTreeMap::new());

        complete_status_reply(
            &mut app,
            flight_for(None, "browser", 0),
            Ok(control::Reply::ok_status(fresh.clone())),
        );
        assert!(
            app.snapshot.as_ref().unwrap().nodes.contains_key("old"),
            "a reply for another class is a superseded frame"
        );

        complete_status_reply(
            &mut app,
            flight_for(None, "dev", 9),
            Ok(control::Reply::ok_status(fresh.clone())),
        );
        assert!(
            app.snapshot.as_ref().unwrap().nodes.contains_key("old"),
            "a reply from a superseded epoch is discarded"
        );

        complete_status_reply(
            &mut app,
            flight_for(None, "dev", 0),
            Ok(control::Reply::ok_status(fresh)),
        );
        assert!(
            !app.snapshot.as_ref().unwrap().nodes.contains_key("old"),
            "a current reply is applied"
        );
        assert!(app.connected);
        assert!(app.last_live.is_some());
    }

    #[test]
    fn failed_status_reply_degrades_to_the_state_file() {
        let mut app = app_for_order();
        app.connected = true;
        app.last_live = Some(Instant::now());

        complete_status_reply(
            &mut app,
            flight_for(None, "dev", 0),
            Err(anyhow::anyhow!("timed out")),
        );
        assert!(!app.connected);
        assert!(app.last_live.is_none());
        assert!(app.snapshot.is_none(), "no state file: no fake data");
    }

    #[test]
    fn completed_node_switch_reports_supersedes_and_forces_a_refresh() {
        let mut app = app_for_order();
        app.last_refresh = Instant::now();
        // A status frame issued during the mutation carries the
        // post-submission epoch; completion must still supersede it.
        app.epoch = 5;
        app.status_flight = Some(flight_for(None, "dev", 5));
        let mut reply = control::Reply::ok();
        reply.switch = Some(control::SwitchOutcome {
            requested: "a".into(),
            installed: "a".into(),
            fallback: false,
        });

        complete_mutation(
            &mut app,
            flight_for(Some(MutationKind::NodeSwitch { node: "a".into() }), "dev", 5),
            Ok(reply),
        );
        assert_eq!(app.message, "switched to a");
        assert!(!app.busy());
        assert_eq!(app.epoch, 6, "completion supersedes mid-mutation frames");
        assert!(
            app.status_flight.is_none(),
            "the lane frees immediately for the forced refresh"
        );
        assert!(
            app.last_refresh.elapsed() >= REFRESH_EVERY,
            "post-mutation refresh is due immediately"
        );
    }

    #[test]
    fn a_successful_subscription_change_clears_the_filter() {
        let mut app = app_for_order();
        app.filter = Some("ra".into());
        app.filter_edit = true;
        let mut reply = control::Reply::ok();
        reply.subscription_switch = Some(control::SubscriptionSwitchOutcome {
            previous: "primary".into(),
            active: "secondary".into(),
            node_count: 7,
            refreshed: false,
        });

        complete_mutation(
            &mut app,
            flight_for(
                Some(MutationKind::SubscriptionSwitch {
                    previous: "primary".into(),
                    requested: "secondary".into(),
                    generation_before: 0,
                }),
                "dev",
                0,
            ),
            Ok(reply),
        );
        assert_eq!(app.filter, None, "a pool-wide change invalidates the filter");
        assert!(!app.filter_edit);
        assert!(app.message.contains("secondary"));
    }

    #[test]
    fn recommendation_ignores_the_active_filter() {
        let mut app = app_for_order();
        let mut snap = tagged_snapshot("primary", 2, &["ra-2", "rb-1"]);
        snap.nodes
            .insert("ra-2".into(), stats(0.95, Some(40.0), true));
        snap.nodes.insert("rb-1".into(), stats(0.90, Some(30.0), true));
        let round = valid_probe_round(
            probe_round_tag(&snap).unwrap(),
            vec![
                probe_result("ra-2", Some(20.0)),
                probe_result("rb-1", Some(30.0)),
            ],
        );
        app.snapshot = Some(snap.clone());
        app.subs = snap.available_nodes.clone();
        app.last_probe_round = Some(round);
        app.filter = Some("rb".into());
        rebuild_order(&mut app);
        assert_eq!(app.order, ["rb-1"], "the visible view is filtered");
        assert_eq!(
            recommended_node(&app),
            Some("ra-2"),
            "the recommendation speaks about the whole pool"
        );
    }

    #[test]
    fn prepare_mutation_supersedes_in_flight_status_frames() {
        let mut app = app_for_order();
        app.status_flight = Some(flight_for(None, "dev", 4));
        app.epoch = 4;

        // The socket-free half of submit_mutation: the epoch bump is the
        // line that makes pre-mutation frames stale on landing.
        let flight = prepare_mutation(
            &mut app,
            MutationKind::NodeSwitch { node: "a".into() },
            dropped_rx(),
        );
        assert_eq!(app.epoch, 5);
        assert_eq!(flight.epoch, 5, "the flight carries the new epoch");
        assert_eq!(flight.class, "dev");

        let reply = control::Reply::ok_status(snapshot(BTreeMap::new()));
        complete_status_reply(&mut app, flight_for(None, "dev", 4), Ok(reply));
        assert!(
            app.snapshot.is_none(),
            "the pre-mutation status frame must not land"
        );
    }

    #[tokio::test]
    async fn submit_mutation_refuses_to_overlap_and_reports() {
        let mut app = app_for_order();
        let socket = PathBuf::from("/nonexistent-causeway-test.sock");
        submit_mutation(&mut app, &socket, MutationKind::NodeSwitch { node: "a".into() });
        assert!(app.busy());
        let first_epoch = app.epoch;

        submit_mutation(&mut app, &socket, MutationKind::NodeSwitch { node: "b".into() });
        assert_eq!(app.epoch, first_epoch, "a refused overlap bumps nothing");
        assert!(app.message.contains("already in progress"));
    }

    // ---- data age / STALE honesty ----

    #[test]
    fn staleness_thresholds_are_three_and_ten_cadences() {
        assert_eq!(staleness(Some(REFRESH_EVERY * 3)), Staleness::Fresh);
        assert_eq!(
            staleness(Some(REFRESH_EVERY * 3 + Duration::from_millis(1))),
            Staleness::Stale
        );
        assert_eq!(staleness(Some(REFRESH_EVERY * 10)), Staleness::Stale);
        assert_eq!(
            staleness(Some(REFRESH_EVERY * 10 + Duration::from_millis(1))),
            Staleness::VeryStale
        );
        assert_eq!(staleness(None), Staleness::VeryStale);
    }

    fn terminal_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.cell((x, y)).unwrap().symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn strip_title_flags_stale_live_data_and_offline_state_age() {
        let mut app = app_for_order();
        app.snapshot = Some(snapshot(BTreeMap::new()));
        app.connected = true;
        app.last_live = Some(Instant::now() - REFRESH_EVERY * 12);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| ui(f, &app)).unwrap();
        let rendered = terminal_text(&terminal);
        assert!(rendered.contains("STALE"), "{rendered}");

        app.connected = false;
        app.last_live = None;
        app.state_updated_unix = Some(state::now_unix() - 3600);
        terminal.draw(|f| ui(f, &app)).unwrap();
        let rendered = terminal_text(&terminal);
        assert!(rendered.contains("OFFLINE"), "{rendered}");
        assert!(rendered.contains("old"), "state age is stated, not implied: {rendered}");
    }

    // ---- event feed coloring ----

    #[test]
    fn event_feed_colors_by_kind() {
        assert_eq!(
            event_color(&control::Event::Switched {
                unix: 0,
                class: "dev".into(),
                node: "n".into(),
                reason: "manual".into(),
                generation: 1,
            }),
            tokens::OK
        );
        assert_eq!(
            event_color(&control::Event::HealthFailed {
                unix: 0,
                class: "dev".into(),
                node: "n".into(),
                consecutive: 1,
            }),
            tokens::ERROR
        );
        assert_eq!(
            event_color(&control::Event::Probed {
                unix: 0,
                source: "periodic".into(),
                ok: 1,
                total: 2,
            }),
            tokens::MUTED
        );
        assert_eq!(
            event_color(&control::Event::SubscriptionChanged {
                unix: 0,
                previous: "a".into(),
                active: "b".into(),
                node_count: 3,
                refreshed: false,
            }),
            tokens::ACCENT
        );
    }

    // ---- filter / help / copy verbs ----

    #[test]
    fn filter_narrows_the_table_and_keeps_selection_identity() {
        let mut app = app_for_order();
        app.subs = vec!["rb-1".into(), "ra-2".into(), "rc-3".into()];
        rebuild_order(&mut app);
        assert_eq!(app.order.len(), 3);
        app.selected = 1; // ra-2
        app.filter = Some("RA".into()); // case-insensitive match
        rebuild_order(&mut app);
        assert_eq!(app.order, ["ra-2"]);
        assert_eq!(app.order_full.len(), 3);
        assert_eq!(app.order[app.selected], "ra-2");
        app.filter = None;
        rebuild_order(&mut app);
        assert_eq!(app.order.len(), 3);
    }

    #[test]
    fn filter_edit_keys_commit_and_clear() {
        let mut app = app_for_order();
        app.subs = vec!["rb-1".into(), "ra-2".into()];
        app.filter_edit = true;
        for c in "ra".chars() {
            filter_edit_key(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.filter.as_deref(), Some("ra"));
        assert_eq!(app.order, ["ra-2"]);

        filter_edit_key(&mut app, KeyCode::Enter);
        assert!(!app.filter_edit);
        assert_eq!(
            app.filter.as_deref(),
            Some("ra"),
            "Enter commits, keeping the filter active"
        );

        app.filter_edit = true;
        filter_edit_key(&mut app, KeyCode::Esc);
        assert_eq!(app.filter, None, "Esc clears the filter entirely");
        rebuild_order(&mut app);
        assert_eq!(app.order.len(), 2);
    }

    #[test]
    fn footer_shows_the_live_filter_while_editing() {
        let mut app = app_for_order();
        app.filter_edit = true;
        app.filter = Some("rb".into());
        let (message, color) = footer_message(&app);
        assert!(message.contains("filter: rb"));
        assert_eq!(color, tokens::ACCENT);
    }

    #[test]
    fn footer_hint_and_help_overlay_share_one_bindings_table() {
        let hint = footer_keys_hint();
        for (keys, _) in BINDINGS {
            assert!(hint.contains(keys), "footer hint must list {keys}");
        }

        let mut app = app_for_order();
        app.help_open = true;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| ui(f, &app)).unwrap();
        let rendered = terminal_text(&terminal);
        for (_, action) in BINDINGS {
            assert!(
                rendered.contains(action),
                "help overlay must explain {action}: {rendered}"
            );
        }
    }

    #[test]
    fn proxy_export_line_targets_the_focused_gateway() {
        let line = proxy_export_line("127.0.0.1:20100");
        assert!(line.starts_with("export http_proxy=http://127.0.0.1:20100"));
        assert!(line.contains("https_proxy=http://127.0.0.1:20100"));
        assert!(line.contains("all_proxy=socks5h://127.0.0.1:20100"));
    }

    // ---- lane wiring: counts, starvation, overlap, closed-channel ----

    #[tokio::test]
    async fn both_lanes_spawn_on_the_same_due_tick() {
        // The starvation bug this pins: a shared clock reset by the status
        // spawn used to keep the events feed from EVER firing while the
        // daemon answered status promptly.
        let mut app = app_for_order();
        app.connected = true;
        app.last_refresh = Instant::now() - REFRESH_EVERY;
        app.last_events_refresh = Instant::now() - REFRESH_EVERY;
        let socket = PathBuf::from("/nonexistent-causeway-test.sock");
        maybe_spawn_refresh(&mut app, &socket);
        assert!(app.status_flight.is_some());
        assert!(app.events_flight.is_some(), "events must not wait for status");
        assert_eq!(app.status_spawns, 1);
        assert_eq!(app.events_spawns, 1);

        // Fresh clocks + occupied lanes: an immediate second pass spawns
        // nothing more.
        maybe_spawn_refresh(&mut app, &socket);
        assert_eq!(app.status_spawns, 1);
        assert_eq!(app.events_spawns, 1);
    }

    #[tokio::test]
    async fn status_lane_counts_spawns_over_real_wiring() {
        // Count-test discipline: drive the real poll/spawn wiring against a
        // dead socket and assert request COUNTS, not just predicates. A
        // per-tick poller or a stuck lane moves these numbers.
        let mut app = app_for_order();
        let socket = PathBuf::from("/nonexistent-causeway-test.sock");
        for _ in 0..22 {
            poll_flights(&mut app);
            maybe_spawn_refresh(&mut app, &socket);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            (1..=3).contains(&app.status_spawns),
            "2s cadence over a 2.2s window: expected ~2 spawns, got {}",
            app.status_spawns
        );
        assert_eq!(app.events_spawns, 0, "never connected: events stay off");
        assert!(!app.connected, "dead socket degrades to offline");
    }

    #[tokio::test]
    async fn held_lane_never_overlaps_and_a_dropped_task_fails_closed() {
        let mut app = app_for_order();
        app.connected = true;
        let (tx, rx) = oneshot::channel();
        app.events_flight = Some(InFlight {
            kind: None,
            class: "dev".into(),
            epoch: app.epoch,
            rx,
        });
        app.last_events_refresh = Instant::now() - REFRESH_EVERY;
        let socket = PathBuf::from("/nonexistent-causeway-test.sock");
        maybe_spawn_refresh(&mut app, &socket);
        assert_eq!(
            app.events_spawns, 0,
            "a held-open lane must not spawn a second request"
        );

        // The background task dying without answering (sender dropped
        // unsent) must clear the lane and degrade like an error, not stick.
        drop(tx);
        let before: Vec<i64> = app.events.iter().map(|e| e.unix()).collect();
        poll_flights(&mut app);
        assert!(app.events_flight.is_none(), "a closed channel frees the lane");
        let after: Vec<i64> = app.events.iter().map(|e| e.unix()).collect();
        assert_eq!(after, before, "advisory data survives the failure");
    }

    // ---- key dispatch: one binding at a time ----

    #[tokio::test]
    async fn every_binding_row_has_a_working_handler() {
        let socket = PathBuf::from("/nonexistent-causeway-test.sock");
        let mut app = app_for_order();
        app.cfg_classes = vec!["dev".into(), "browser".into()];
        app.listens = vec!["127.0.0.1:20100".into(), "127.0.0.1:20120".into()];
        app.class_selections = vec![String::new(), String::new()];
        app.subs = vec!["rb-1".into(), "ra-2".into()];
        rebuild_order(&mut app);

        // Tab/←/→ — class focus: state reset, epoch supersede, filter gone.
        app.epoch = 7;
        app.status_flight = Some(flight_for(None, "dev", 7));
        app.filter = Some("ra".into());
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Tab), KeyAction::None);
        assert_eq!(app.class(), "browser");
        assert_eq!(app.epoch, 8);
        assert!(app.status_flight.is_none(), "class change drops stale frames");
        assert_eq!(app.filter, None, "a class-local filter does not carry over");
        assert!(app.last_refresh.elapsed() >= REFRESH_EVERY);

        // k/j move the selection (no snapshot: plain name order).
        app.subs = vec!["rb-1".into(), "ra-2".into()];
        rebuild_order(&mut app);
        assert_eq!(app.order, ["ra-2", "rb-1"]);
        app.selected = 0;
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('j')), KeyAction::None);
        assert_eq!(app.order[app.selected], "rb-1");
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('k')), KeyAction::None);
        assert_eq!(app.order[app.selected], "ra-2");

        // t submits an end-to-end probe on the mutation lane.
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('t')), KeyAction::None);
        assert!(app.busy());
        app.mutation_flight = None; // simulate completion for the next rows

        // s opens the subscription picker.
        app.fallback_subscriptions = vec![control::SubscriptionSummary {
            name: "primary".into(),
            node_count: Some(1),
        }];
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('s')), KeyAction::None);
        assert!(app.subscription_picker.is_some());
        app.subscription_picker = None;

        // Enter submits a node switch on the mutation lane.
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Enter), KeyAction::None);
        assert!(app.busy());

        // q during a mutation arms instead of quitting; the second press quits.
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('q')), KeyAction::None);
        assert!(app.quit_armed);
        assert!(app.message.contains("change in flight"));
        // 'c' must not clobber the busy message while armed.
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('c')), KeyAction::None);
        assert!(app.message.contains("change in flight"), "c stays quiet while busy");
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('q')), KeyAction::Quit);

        // With no mutation in flight: c, ?, /, s all act.
        app.mutation_flight = None;
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('c')), KeyAction::None);
        assert!(app.message.contains("export http_proxy="));
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('?')), KeyAction::None);
        assert!(app.help_open);
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Char('/')), KeyAction::None);
        assert!(app.filter_edit);
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Esc), KeyAction::Quit);
    }

    #[tokio::test]
    async fn class_switching_is_blocked_while_a_mutation_runs() {
        let mut app = app_for_order();
        app.cfg_classes = vec!["dev".into(), "browser".into()];
        app.listens = vec!["127.0.0.1:20100".into(), "127.0.0.1:20120".into()];
        let socket = PathBuf::from("/nonexistent-causeway-test.sock");
        app.subs = vec!["a".into()];
        rebuild_order(&mut app);
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Enter), KeyAction::None);
        assert!(app.busy());
        assert_eq!(dashboard_key(&mut app, &socket, KeyCode::Tab), KeyAction::None);
        assert_eq!(app.class(), "dev", "the class guard keeps the outcome observable");
    }

    // ---- render-level pins ----

    fn row_text(buffer: &ratatui::buffer::Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer.cell((x, y)).unwrap().symbol())
            .collect()
    }

    fn row_has_fg(buffer: &ratatui::buffer::Buffer, y: u16, color: Color) -> bool {
        (0..buffer.area.width).any(|x| {
            buffer.cell((x, y)).unwrap().style().fg == Some(color)
        })
    }

    #[test]
    fn event_feed_colors_reach_the_screen() {
        let mut app = app_for_order();
        let now = state::now_unix();
        app.events = vec![
            control::Event::Switched {
                unix: now,
                class: "dev".into(),
                node: "n".into(),
                reason: "manual".into(),
                generation: 1,
            },
            control::Event::HealthFailed {
                unix: now,
                class: "dev".into(),
                node: "n".into(),
                consecutive: 1,
            },
        ];
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| ui(f, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut switched_checked = false;
        let mut health_checked = false;
        for y in 0..buffer.area.height {
            let text = row_text(buffer, y);
            if text.contains("→ n (manual") {
                assert!(
                    row_has_fg(buffer, y, tokens::OK),
                    "a switched event must render green: {text}"
                );
                switched_checked = true;
            }
            if text.contains("health check failed") {
                assert!(
                    row_has_fg(buffer, y, tokens::ERROR),
                    "a health failure must render red: {text}"
                );
                health_checked = true;
            }
        }
        assert!(switched_checked, "feed row rendered");
        assert!(health_checked, "health row rendered");
    }

    #[test]
    fn strip_renders_selection_policy_and_stale_bands_and_filtered_title() {
        let mut app = app_for_order();
        let mut snap = snapshot(BTreeMap::new());
        snap.classes = vec![control::ClassOverview {
            name: "dev".into(),
            listen: "127.0.0.1:20100".into(),
            active_node: Some("ra01".into()),
            generation: 3,
            selection: "regions=RA auto=off".into(),
        }];
        app.snapshot = Some(snap);
        app.connected = true;

        // Yellow band (between 3x and 10x cadence).
        app.last_live = Some(Instant::now() - REFRESH_EVERY * 4);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| ui(f, &app)).unwrap();
        let rendered = terminal_text(&terminal);
        assert!(rendered.contains("STALE"), "yellow band shows STALE: {rendered}");
        assert!(
            rendered.contains("regions=RA"),
            "daemon-supplied selection policy is visible: {rendered}"
        );

        // Filtered title with an honest narrowed/total count.
        app.last_live = Some(Instant::now());
        app.filter = Some("ra".into());
        app.order = vec!["ra-2".into()];
        app.order_full = vec!["ra-2".into(), "rb-1".into(), "rc-3".into()];
        terminal.draw(|f| ui(f, &app)).unwrap();
        let rendered = terminal_text(&terminal);
        assert!(
            rendered.contains("filtered 1/3"),
            "filter count in the table title: {rendered}"
        );
    }

    #[test]
    fn class_strip_columns_fit_their_budget() {
        for width in 40u16..=160 {
            let columns = class_strip_column_lengths(width);
            let sum: u16 = columns.iter().sum();
            assert!(
                sum + 8 <= width,
                "{width}-column strip uses {sum}+8 columns"
            );
        }
        // SELECTION is the sacrificial column: it shrinks before NODE does.
        assert!(class_strip_column_lengths(60)[3] < class_strip_column_lengths(100)[3]);
        assert!(class_strip_column_lengths(100)[2] >= 10, "NODE keeps a floor");
    }

    #[test]
    fn rebuild_order_clamps_selection_when_the_filter_hides_it() {
        let mut app = app_for_order();
        app.subs = vec!["rb-1".into(), "ra-2".into()];
        rebuild_order(&mut app);
        app.selected = 1; // ra-2
        app.filter = Some("rb".into());
        rebuild_order(&mut app);
        assert_eq!(app.order, ["rb-1"]);
        assert_eq!(
            app.order[app.selected], "rb-1",
            "selection clamps into the filtered view"
        );
    }

    // ---- module boundary ----

    #[test]
    fn ui_module_imports_only_the_control_protocol_surface() {
        // Allowlist, not denylist: every `crate::<ident>` path root used by
        // the dashboard must be one of the sanctioned surfaces (control
        // protocol, persistence, config, subscription catalog, scoring, and
        // the two shared main.rs helpers). A new engine module referenced
        // here fails this test by construction.
        let src = include_str!("switch.rs");
        let allowed = [
            "config", "control", "score", "state", "subscription", "truncate", "cmd_status",
        ];
        let mut roots = std::collections::BTreeSet::new();
        let mut rest = src;
        while let Some(pos) = rest.find("crate::") {
            rest = &rest[pos + "crate::".len()..];
            let ident: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !ident.is_empty() {
                roots.insert(ident);
            }
        }
        for root in &roots {
            assert!(
                allowed.contains(&root.as_str()),
                "switch.rs must not reach crate::{root}; the UI talks to the engine only through the control protocol"
            );
        }
        // The sanctioned surface must stay in use, or the allowlist rots.
        for expected in allowed {
            assert!(
                roots.contains(expected),
                "expected sanctioned import crate::{expected} not found — allowlist is stale"
            );
        }
    }

    // ---- single color source ----

    #[test]
    fn tokens_keep_the_original_palette() {
        // The palette values are pinned exactly once, here; everywhere else
        // asks tokens by meaning.
        assert_eq!(tokens::OK, Color::Green);
        assert_eq!(tokens::WARN, Color::Yellow);
        assert_eq!(tokens::ERROR, Color::Red);
        assert_eq!(tokens::MUTED, Color::DarkGray);
        assert_eq!(tokens::ACCENT, Color::Cyan);
    }

    #[test]
    fn raw_palette_literals_live_only_in_tokens() {
        let src = include_str!("switch.rs");
        for name in ["Green", "Yellow", "Red", "DarkGray", "Cyan"] {
            let needle = format!("Color::{name}");
            let count = src.matches(&needle).count();
            assert_eq!(
                count, 2,
                "{needle} must appear exactly twice: the tokens definition and the palette pin"
            );
        }
    }
}
