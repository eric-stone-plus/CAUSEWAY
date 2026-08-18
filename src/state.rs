//! Runtime state persistence: node statistics + current route per class.
//!
//! Atomic writes (tmp + rename) so a crash cannot leave half a JSON behind.
//! The state file enables manual inspection (`causeway status`) and lets a
//! restart skip blind probing.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::score::NodeStats;

pub const STATE_VERSION: u32 = 2;
const LEGACY_STATE_VERSION: u32 = 1;
const CACHE_SLOT_A: &str = "a";
const CACHE_SLOT_B: &str = "b";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassState {
    /// Name of the currently active node (None = no path established yet)
    pub active_node: Option<String>,
    /// Current data-plane local ports (diagnostic only; reallocated on restart)
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    /// Switch generation, +1 on every successful switch
    pub generation: u64,
}

/// In-memory runtime state.
///
/// `nodes` deliberately remains the active profile's flat view so the hot
/// probe/switch paths do not need profile lookups. `subscription_nodes` holds
/// inactive profiles only while the state is in memory. Serialization inserts
/// the active view into that map, and loading removes it again. There is thus
/// one authoritative copy of the active statistics at every point.
#[derive(Debug, Clone)]
pub struct StateFile {
    pub version: u32,
    pub updated_unix: i64,
    /// Subscription profile whose statistics are exposed through `nodes`.
    /// Version-1 state is loaded with None until it is explicitly migrated.
    pub active_subscription: Option<String>,
    /// class name -> route state
    pub classes: BTreeMap<String, ClassState>,
    /// Active subscription's node name -> rolling statistics.
    pub nodes: BTreeMap<String, NodeStats>,
    /// Remote profile -> cache slot confirmed by the same atomic state
    /// commit as the corresponding live publication. Values are deliberately
    /// tiny stable identifiers, never paths supplied by a provider.
    pub subscription_cache_slots: BTreeMap<String, String>,
    /// Profile -> credential-free identity of the source that produced its
    /// trusted statistics/cache generation.
    pub subscription_source_identities: BTreeMap<String, String>,
    /// Profile -> newly configured identity which has not completed a fresh
    /// prepare/check/publication transaction yet. This survives crashes and
    /// prevents a legacy cache from crossing a same-name source change.
    pub pending_subscription_sources: BTreeMap<String, String>,
    /// Inactive subscription profile -> node name -> rolling statistics.
    ///
    /// On disk this also contains the active profile; see the type-level
    /// invariant above. Keep access private so callers cannot create a second,
    /// stale copy of active statistics.
    subscription_nodes: BTreeMap<String, BTreeMap<String, NodeStats>>,
}

impl Default for StateFile {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            updated_unix: 0,
            active_subscription: None,
            classes: BTreeMap::new(),
            nodes: BTreeMap::new(),
            subscription_cache_slots: BTreeMap::new(),
            subscription_source_identities: BTreeMap::new(),
            pending_subscription_sources: BTreeMap::new(),
            subscription_nodes: BTreeMap::new(),
        }
    }
}

impl StateFile {
    /// Flat statistics view used by the existing probe and switch paths.
    /// Read a profile without activating it. The active profile is served
    /// directly from `nodes`; inactive profiles live in `subscription_nodes`.
    pub fn nodes_for_subscription(&self, name: &str) -> Option<&BTreeMap<String, NodeStats>> {
        if self.active_subscription.as_deref() == Some(name) {
            Some(&self.nodes)
        } else {
            self.subscription_nodes.get(name)
        }
    }

    /// Remove every persisted namespace owned by one profile. Active profile
    /// removal is intentionally supported for startup repair, although reload
    /// refuses removal of the live profile before reaching this operation.
    pub fn remove_subscription(&mut self, name: &str) {
        if self.active_subscription.as_deref() == Some(name) {
            self.nodes.clear();
            self.active_subscription = None;
        }
        self.subscription_nodes.remove(name);
        self.subscription_cache_slots.remove(name);
        self.subscription_source_identities.remove(name);
        self.pending_subscription_sources.remove(name);
    }

    /// Preserve the profile name but invalidate everything derived from its
    /// previous source. The pending marker makes the isolation crash-safe.
    pub fn invalidate_subscription_source(&mut self, name: &str, identity: String) {
        if self.active_subscription.as_deref() == Some(name) {
            self.nodes.clear();
        } else {
            self.subscription_nodes.remove(name);
        }
        self.subscription_cache_slots.remove(name);
        self.subscription_source_identities.remove(name);
        self.pending_subscription_sources
            .insert(name.to_string(), identity);
    }

    pub fn trust_subscription_source(&mut self, name: &str, identity: String) {
        self.pending_subscription_sources.remove(name);
        self.subscription_source_identities
            .insert(name.to_string(), identity);
    }

    pub fn source_is_trusted(&self, name: &str, identity: &str) -> bool {
        self.subscription_source_identities
            .get(name)
            .is_some_and(|stored| stored == identity)
            && !self.pending_subscription_sources.contains_key(name)
    }

    /// Reconcile persistent namespaces after a successfully published catalog
    /// reload. Same-name sources that changed (and newly introduced names
    /// which might collide with stale state) become pending. A freshly checked
    /// target is trusted in the same atomic state commit as its publication.
    pub fn apply_subscription_catalog(
        &mut self,
        previous: &BTreeMap<String, String>,
        next: &BTreeMap<String, String>,
        freshly_trusted: Option<&str>,
    ) {
        let known: std::collections::BTreeSet<String> = self
            .subscription_nodes
            .keys()
            .chain(self.subscription_cache_slots.keys())
            .chain(self.subscription_source_identities.keys())
            .chain(self.pending_subscription_sources.keys())
            .cloned()
            .collect();
        for removed in known.iter().filter(|name| !next.contains_key(*name)) {
            self.remove_subscription(removed);
        }

        for (name, identity) in next {
            let catalog_changed = previous.get(name) != Some(identity);
            let persisted_mismatch = self
                .subscription_source_identities
                .get(name)
                .is_some_and(|stored| stored != identity);
            let pending_mismatch = self
                .pending_subscription_sources
                .get(name)
                .is_some_and(|stored| stored != identity);
            if catalog_changed || persisted_mismatch || pending_mismatch {
                self.invalidate_subscription_source(name, identity.clone());
            }
            if freshly_trusted == Some(name.as_str()) {
                self.trust_subscription_source(name, identity.clone());
            }
        }
    }

    /// Upgrade identity-less v2 state at startup and enforce identities which
    /// were already persisted by a newer daemon. Missing identity fields are
    /// adopted only for backward compatibility; explicit pending markers are
    /// never cleared without a fresh successful transaction.
    pub fn reconcile_startup_sources(&mut self, current: &BTreeMap<String, String>) {
        let persisted: std::collections::BTreeSet<String> = self
            .subscription_nodes
            .keys()
            .chain(self.subscription_cache_slots.keys())
            .chain(self.subscription_source_identities.keys())
            .chain(self.pending_subscription_sources.keys())
            .cloned()
            .collect();
        for removed in persisted.iter().filter(|name| !current.contains_key(*name)) {
            self.remove_subscription(removed);
        }
        for (name, identity) in current {
            let mismatch = self
                .subscription_source_identities
                .get(name)
                .is_some_and(|stored| stored != identity)
                || self
                    .pending_subscription_sources
                    .get(name)
                    .is_some_and(|stored| stored != identity);
            if mismatch {
                self.invalidate_subscription_source(name, identity.clone());
            }
        }
        for (name, identity) in current {
            if self.pending_subscription_sources.contains_key(name) {
                continue;
            }
            match self.subscription_source_identities.get(name) {
                Some(stored) if stored == identity => {}
                Some(_) => self.invalidate_subscription_source(name, identity.clone()),
                None => self.trust_subscription_source(name, identity.clone()),
            }
        }
    }

    /// Bind statistics loaded from the version-1 flat format to a selected
    /// profile. Configuration, not the state file, knows which profile the old
    /// manifest represented, so `load` intentionally cannot guess this name.
    ///
    /// Returns true when a migration occurred. Calling this on version 2 is a
    /// no-op; use `activate_subscription` to change an existing selection.
    pub fn migrate_for_subscription(&mut self, selected: &str) -> bool {
        if self.version != LEGACY_STATE_VERSION {
            return false;
        }
        self.version = STATE_VERSION;
        self.active_subscription = Some(selected.to_string());
        true
    }

    /// Select a profile while preserving the current profile's statistics.
    ///
    /// The outgoing flat view is stored under its old profile and the incoming
    /// profile is removed from the inactive map into `nodes`. A version-1
    /// state is migrated in place on first activation, which keeps the daemon
    /// integration to a single startup call.
    ///
    /// Returns true when the active profile changed or a migration occurred.
    pub fn activate_subscription(&mut self, name: &str) -> bool {
        if self.migrate_for_subscription(name) {
            return true;
        }
        if self.active_subscription.as_deref() == Some(name) {
            return false;
        }

        if let Some(previous) = self.active_subscription.replace(name.to_string()) {
            let outgoing = std::mem::take(&mut self.nodes);
            self.subscription_nodes.insert(previous, outgoing);
        }
        self.nodes = self.subscription_nodes.remove(name).unwrap_or_default();
        true
    }

    /// Construct the on-disk profile map without mutating the live state.
    fn persisted_subscription_nodes(
        &self,
    ) -> Result<BTreeMap<String, BTreeMap<String, NodeStats>>, StateError> {
        if self.version != STATE_VERSION {
            return Err(StateError::NeedsMigration);
        }
        let mut all = self.subscription_nodes.clone();
        match &self.active_subscription {
            Some(active) => {
                all.insert(active.clone(), self.nodes.clone());
            }
            None if !self.nodes.is_empty() => return Err(StateError::UnboundNodes),
            None => {}
        }
        Ok(all)
    }
}

/// Exact version-1 wire shape. It is kept private so new code cannot
/// accidentally persist flat, cross-subscription statistics again.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFileV1 {
    version: u32,
    updated_unix: i64,
    classes: BTreeMap<String, ClassState>,
    nodes: BTreeMap<String, NodeStats>,
}

/// Version-2 wire shape. Unlike the runtime representation, the on-disk map
/// includes every profile, including `active_subscription`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFileV2 {
    version: u32,
    updated_unix: i64,
    active_subscription: Option<String>,
    classes: BTreeMap<String, ClassState>,
    subscription_nodes: BTreeMap<String, BTreeMap<String, NodeStats>>,
    #[serde(default)]
    subscription_cache_slots: BTreeMap<String, String>,
    #[serde(default)]
    subscription_source_identities: BTreeMap<String, String>,
    #[serde(default)]
    pending_subscription_sources: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct VersionOnly {
    version: u32,
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("failed to read state file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse state file {path} (delete it and restart to rebuild): {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "unsupported state version {version} in {path} (this build supports versions 1 and 2)"
    )]
    UnsupportedVersion { path: PathBuf, version: u32 },
    #[error("version-1 state must be migrated for the selected subscription before saving")]
    NeedsMigration,
    #[error("node statistics have no active subscription; activate a subscription before saving")]
    UnboundNodes,
    #[error("state version 2 names active subscription {active:?}, but its statistics entry is missing in {path}")]
    MissingActiveSubscription { path: PathBuf, active: String },
    #[error("state version 2 contains invalid subscription cache slot {slot:?} for profile {profile:?} in {path}")]
    InvalidSubscriptionCacheSlot {
        path: PathBuf,
        profile: String,
        slot: String,
    },
}

/// Result of an atomic replacement. Once `CommittedNotDurable` is returned,
/// the target pathname already refers to the new state. Callers must publish
/// the matching in-memory/live state rather than pretending the commit was
/// rolled back; only crash durability of the directory entry is uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveOutcome {
    Durable,
    CommittedNotDurable,
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn json_error(path: &Path, source: serde_json::Error) -> StateError {
    StateError::Json {
        path: path.to_path_buf(),
        source,
    }
}

/// Load the state file; missing returns None (first run), corrupted returns
/// Err (the caller decides the degradation strategy).
///
/// Version 1 remains flat and unbound in memory until
/// `migrate_for_subscription` or `activate_subscription` supplies the profile
/// name. Version 2 immediately exposes the selected profile through `nodes`.
pub fn load(path: &Path) -> Result<Option<StateFile>, StateError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(StateError::Io {
                path: path.to_path_buf(),
                source: e,
            })
        }
    };
    let version = serde_json::from_str::<VersionOnly>(&text)
        .map_err(|e| json_error(path, e))?
        .version;

    let state = match version {
        LEGACY_STATE_VERSION => {
            let old: StateFileV1 = serde_json::from_str(&text).map_err(|e| json_error(path, e))?;
            debug_assert_eq!(old.version, LEGACY_STATE_VERSION);
            StateFile {
                version: old.version,
                updated_unix: old.updated_unix,
                active_subscription: None,
                classes: old.classes,
                nodes: old.nodes,
                subscription_cache_slots: BTreeMap::new(),
                subscription_source_identities: BTreeMap::new(),
                pending_subscription_sources: BTreeMap::new(),
                subscription_nodes: BTreeMap::new(),
            }
        }
        STATE_VERSION => {
            let mut wire: StateFileV2 =
                serde_json::from_str(&text).map_err(|e| json_error(path, e))?;
            debug_assert_eq!(wire.version, STATE_VERSION);
            if let Some((profile, slot)) = wire
                .subscription_cache_slots
                .iter()
                .find(|(_, slot)| slot.as_str() != CACHE_SLOT_A && slot.as_str() != CACHE_SLOT_B)
            {
                return Err(StateError::InvalidSubscriptionCacheSlot {
                    path: path.to_path_buf(),
                    profile: profile.clone(),
                    slot: slot.clone(),
                });
            }
            let nodes = match wire.active_subscription.as_ref() {
                Some(active) => wire.subscription_nodes.remove(active).ok_or_else(|| {
                    StateError::MissingActiveSubscription {
                        path: path.to_path_buf(),
                        active: active.clone(),
                    }
                })?,
                None => BTreeMap::new(),
            };
            StateFile {
                version: wire.version,
                updated_unix: wire.updated_unix,
                active_subscription: wire.active_subscription,
                classes: wire.classes,
                nodes,
                subscription_cache_slots: wire.subscription_cache_slots,
                subscription_source_identities: wire.subscription_source_identities,
                pending_subscription_sources: wire.pending_subscription_sources,
                subscription_nodes: wire.subscription_nodes,
            }
        }
        version => {
            return Err(StateError::UnsupportedVersion {
                path: path.to_path_buf(),
                version,
            })
        }
    };
    Ok(Some(state))
}

/// Atomic save: snapshot the active statistics into their profile, write a
/// mode-0600 temp file in the same directory, then rename it over the target.
pub fn save_atomic(path: &Path, state: &StateFile) -> Result<SaveOutcome, StateError> {
    save_atomic_with_parent_sync(path, state, sync_parent_dir)
}

fn save_atomic_with_parent_sync<F>(
    path: &Path,
    state: &StateFile,
    sync_parent: F,
) -> Result<SaveOutcome, StateError>
where
    F: FnOnce(&Path) -> std::io::Result<()>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| StateError::Io {
        path: parent.to_path_buf(),
        source: e,
    })?;
    let tmp = path.with_extension("json.tmp");
    let wire = StateFileV2 {
        version: STATE_VERSION,
        updated_unix: state.updated_unix,
        active_subscription: state.active_subscription.clone(),
        classes: state.classes.clone(),
        subscription_nodes: state.persisted_subscription_nodes()?,
        subscription_cache_slots: state.subscription_cache_slots.clone(),
        subscription_source_identities: state.subscription_source_identities.clone(),
        pending_subscription_sources: state.pending_subscription_sources.clone(),
    };
    let text = serde_json::to_vec_pretty(&wire).expect("StateFile serialization should not fail");

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(|e| StateError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    #[cfg(unix)]
    file.set_permissions({
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o600)
    })
    .map_err(|e| StateError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    file.write_all(&text).map_err(|e| StateError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    file.sync_all().map_err(|e| StateError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    drop(file);

    std::fs::rename(&tmp, path).map_err(|e| StateError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if sync_parent(parent).is_err() {
        return Ok(SaveOutcome::CommittedNotDurable);
    }
    Ok(SaveOutcome::Durable)
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> std::io::Result<()> {
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "causeway-state-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    fn stats(success_ema: f64) -> NodeStats {
        NodeStats {
            success_ema,
            rtt_ema_ms: Some(88.5),
            recent_rtts_ms: vec![80.0, 88.5, 95.0],
            consecutive_health_failures: 0,
            probe_count: 7,
            last_probe_unix: Some(12300),
        }
    }

    #[test]
    fn version_two_roundtrip_uses_active_flat_view() {
        let dir = test_dir("roundtrip");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        let mut state = StateFile::default();
        assert!(state.activate_subscription("primary"));
        state.updated_unix = 12345;
        state.classes.insert(
            "dev".to_string(),
            ClassState {
                active_node: Some("Node A".into()),
                socks_port: Some(20001),
                http_port: Some(20002),
                generation: 3,
            },
        );
        state.nodes.insert("Node A".to_string(), stats(0.9));
        state
            .subscription_cache_slots
            .insert("primary".into(), "b".into());
        save_atomic(&path, &state).unwrap();

        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            raw.get("nodes").is_none(),
            "v2 must not persist a competing flat copy"
        );
        assert_eq!(raw["active_subscription"], "primary");
        assert!(raw["subscription_nodes"]["primary"]["Node A"].is_object());

        let loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded.version, STATE_VERSION);
        assert_eq!(loaded.active_subscription.as_deref(), Some("primary"));
        assert_eq!(loaded.classes["dev"].active_node.as_deref(), Some("Node A"));
        assert_eq!(loaded.classes["dev"].generation, 3);
        assert!((loaded.nodes["Node A"].success_ema - 0.9).abs() < 1e-9);
        assert_eq!(
            loaded
                .subscription_cache_slots
                .get("primary")
                .map(String::as_str),
            Some("b")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_node_name_is_isolated_between_subscriptions() {
        let mut state = StateFile::default();
        state.activate_subscription("alpha");
        state.nodes.insert("shared".into(), stats(0.9));

        assert!(state.activate_subscription("beta"));
        assert!(state.nodes.is_empty());
        state.nodes.insert("shared".into(), stats(0.2));
        assert_eq!(
            state.nodes_for_subscription("alpha").unwrap()["shared"].success_ema,
            0.9
        );

        assert!(state.activate_subscription("alpha"));
        assert_eq!(state.nodes["shared"].success_ema, 0.9);
        assert_eq!(
            state.nodes_for_subscription("beta").unwrap()["shared"].success_ema,
            0.2
        );
        assert!(!state.activate_subscription("alpha"));
        assert!(state.nodes_for_subscription("alpha").is_some());
        assert!(state.nodes_for_subscription("beta").is_some());
    }

    #[test]
    fn catalog_change_invalidates_old_source_namespace_and_survives_roundtrip() {
        let dir = test_dir("source-change");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let mut state = StateFile::default();
        state.activate_subscription("active");
        state.activate_subscription("inactive");
        state.nodes.insert("old-node".into(), stats(0.95));
        state.activate_subscription("active");
        state
            .subscription_cache_slots
            .insert("inactive".into(), CACHE_SLOT_A.into());
        state
            .subscription_source_identities
            .insert("inactive".into(), "old-id".into());
        state
            .subscription_source_identities
            .insert("removed".into(), "removed-id".into());
        state
            .subscription_cache_slots
            .insert("removed".into(), CACHE_SLOT_B.into());

        state.apply_subscription_catalog(
            &BTreeMap::from([
                ("active".into(), "active-id".into()),
                ("inactive".into(), "old-id".into()),
                ("removed".into(), "removed-id".into()),
            ]),
            &BTreeMap::from([
                ("active".into(), "active-id".into()),
                ("inactive".into(), "new-id".into()),
            ]),
            Some("active"),
        );

        assert!(state.nodes_for_subscription("inactive").is_none());
        assert!(!state.subscription_cache_slots.contains_key("inactive"));
        assert_eq!(
            state
                .pending_subscription_sources
                .get("inactive")
                .map(String::as_str),
            Some("new-id")
        );
        assert!(!state.source_is_trusted("inactive", "new-id"));
        assert!(!state.subscription_source_identities.contains_key("removed"));
        assert!(!state.subscription_cache_slots.contains_key("removed"));

        save_atomic(&path, &state).unwrap();
        let loaded = load(&path).unwrap().unwrap();
        assert!(!loaded.source_is_trusted("inactive", "new-id"));
        assert_eq!(
            loaded
                .pending_subscription_sources
                .get("inactive")
                .map(String::as_str),
            Some("new-id")
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn fresh_publication_trusts_new_source_but_never_restores_old_stats() {
        let mut state = StateFile::default();
        state.activate_subscription("active");
        state.activate_subscription("changed");
        state.nodes.insert("same-name".into(), stats(0.99));
        state.activate_subscription("active");
        let old = BTreeMap::from([
            ("active".into(), "active-id".into()),
            ("changed".into(), "old-id".into()),
        ]);
        let next = BTreeMap::from([
            ("active".into(), "active-id".into()),
            ("changed".into(), "new-id".into()),
        ]);
        state.apply_subscription_catalog(&old, &next, Some("active"));
        state.apply_subscription_catalog(&next, &next, Some("changed"));
        assert!(state.source_is_trusted("changed", "new-id"));
        assert!(state.nodes_for_subscription("changed").is_none());
    }

    #[test]
    fn identity_less_v2_wire_format_remains_compatible() {
        let dir = test_dir("identity-default");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(
            &path,
            r#"{"version":2,"updated_unix":1,"active_subscription":"p","classes":{},"subscription_nodes":{"p":{}},"subscription_cache_slots":{"p":"a"}}"#,
        )
        .unwrap();
        let loaded = load(&path).unwrap().unwrap();
        assert!(loaded.subscription_source_identities.is_empty());
        assert!(loaded.pending_subscription_sources.is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn version_two_rejects_invalid_cache_slot() {
        let dir = test_dir("invalid-cache-slot");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(
            &path,
            r#"{"version":2,"updated_unix":1,"active_subscription":"p","classes":{},"subscription_nodes":{"p":{}},"subscription_cache_slots":{"p":"causeway-a"}}"#,
        )
        .unwrap();
        assert!(matches!(
            load(&path),
            Err(StateError::InvalidSubscriptionCacheSlot { profile, slot, .. })
                if profile == "p" && slot == "causeway-a"
        ));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn startup_rejects_cache_and_stats_from_a_persisted_different_source() {
        let mut state = StateFile::default();
        state.activate_subscription("profile");
        state.nodes.insert("old-node".into(), stats(0.8));
        state
            .subscription_cache_slots
            .insert("profile".into(), CACHE_SLOT_A.into());
        state
            .subscription_source_identities
            .insert("profile".into(), "old-id".into());
        state.reconcile_startup_sources(&BTreeMap::from([("profile".into(), "new-id".into())]));
        assert!(state.nodes.is_empty());
        assert!(!state.subscription_cache_slots.contains_key("profile"));
        assert!(!state.source_is_trusted("profile", "new-id"));
        assert_eq!(
            state
                .pending_subscription_sources
                .get("profile")
                .map(String::as_str),
            Some("new-id")
        );
    }

    #[test]
    fn active_mutations_are_synchronized_only_in_saved_snapshot() {
        let dir = test_dir("snapshot");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");

        let mut state = StateFile::default();
        state.activate_subscription("alpha");
        state.nodes.insert("node".into(), stats(0.4));
        save_atomic(&path, &state).unwrap();
        state.nodes.get_mut("node").unwrap().success_ema = 0.8;
        save_atomic(&path, &state).unwrap();

        let loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded.nodes["node"].success_ema, 0.8);
        assert_eq!(state.nodes["node"].success_ema, 0.8);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn version_one_load_requires_explicit_profile_migration() {
        let dir = test_dir("v1-migration");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let old = serde_json::json!({
            "version": 1,
            "updated_unix": 12345,
            "classes": {
                "dev": {
                    "active_node": "Node A",
                    "socks_port": 20001,
                    "http_port": 20002,
                    "generation": 3
                }
            },
            "nodes": { "Node A": stats(0.75) }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&old).unwrap()).unwrap();

        let mut loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded.version, LEGACY_STATE_VERSION);
        assert_eq!(loaded.active_subscription, None);
        assert_eq!(loaded.nodes["Node A"].success_ema, 0.75);
        assert!(matches!(
            save_atomic(&path, &loaded),
            Err(StateError::NeedsMigration)
        ));

        assert!(loaded.migrate_for_subscription("legacy"));
        assert!(!loaded.migrate_for_subscription("ignored"));
        assert_eq!(loaded.version, STATE_VERSION);
        assert_eq!(loaded.active_subscription.as_deref(), Some("legacy"));
        save_atomic(&path, &loaded).unwrap();

        let migrated = load(&path).unwrap().unwrap();
        assert_eq!(migrated.active_subscription.as_deref(), Some("legacy"));
        assert_eq!(migrated.nodes["Node A"].success_ema, 0.75);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn activate_subscription_also_migrates_version_one() {
        let mut state = StateFile {
            version: LEGACY_STATE_VERSION,
            updated_unix: 1,
            active_subscription: None,
            classes: BTreeMap::new(),
            nodes: BTreeMap::from([("same".into(), stats(0.6))]),
            subscription_cache_slots: BTreeMap::new(),
            subscription_source_identities: BTreeMap::new(),
            pending_subscription_sources: BTreeMap::new(),
            subscription_nodes: BTreeMap::new(),
        };
        assert!(state.activate_subscription("selected"));
        assert_eq!(state.version, STATE_VERSION);
        assert_eq!(state.active_subscription.as_deref(), Some("selected"));
        assert_eq!(state.nodes["same"].success_ema, 0.6);
    }

    #[test]
    fn unbound_nonempty_nodes_are_not_silently_lost() {
        let dir = test_dir("unbound");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let mut state = StateFile::default();
        state.nodes.insert("orphan".into(), stats(1.0));
        assert!(matches!(
            save_atomic(&path, &state),
            Err(StateError::UnboundNodes)
        ));
        assert!(!path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_save_forces_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("permissions");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let mut state = StateFile::default();
        state.activate_subscription("profile");

        save_atomic(&path, &state).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rename_success_with_parent_sync_failure_is_reported_as_committed() {
        let dir = test_dir("committed-not-durable");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let mut state = StateFile::default();
        state.activate_subscription("profile");

        let outcome = save_atomic_with_parent_sync(&path, &state, |_| {
            Err(std::io::Error::other("injected directory sync failure"))
        })
        .unwrap();
        assert_eq!(outcome, SaveOutcome::CommittedNotDurable);
        assert_eq!(
            load(&path).unwrap().unwrap().active_subscription.as_deref(),
            Some("profile"),
            "rename already committed the new namespace entry"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn future_version_is_rejected() {
        let dir = test_dir("future-version");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(&path, r#"{"version":99}"#).unwrap();
        assert!(matches!(
            load(&path),
            Err(StateError::UnsupportedVersion { version: 99, .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_none() {
        let path = test_dir("missing").join("state.json");
        assert!(load(&path).unwrap().is_none());
    }

    #[test]
    fn version_two_rejects_missing_active_profile_entry() {
        let dir = test_dir("missing-active-entry");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(
            &path,
            r#"{
  "version": 2,
  "updated_unix": 1,
  "active_subscription": "missing",
  "classes": {},
  "subscription_nodes": {}
}"#,
        )
        .unwrap();

        assert!(matches!(
            load(&path),
            Err(StateError::MissingActiveSubscription { active, .. }) if active == "missing"
        ));
        std::fs::remove_dir_all(dir).ok();
    }
}
