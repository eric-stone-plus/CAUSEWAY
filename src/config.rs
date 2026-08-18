//! TOML config loading and validation. Default path
//! `~/.config/causeway/config.toml`, overridable with `--config`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub fn default_config_path() -> PathBuf {
    home_dir().join(".config/causeway/config.toml")
}

pub fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME environment variable not set"))
}

/// Expand a leading `~` in a path (home-relative paths are the norm in the
/// config; no global globbing).
fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if s == "~" {
        home_dir()
    } else if let Some(rest) = s.strip_prefix("~/") {
        home_dir().join(rest)
    } else {
        p.to_path_buf()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,
    #[serde(default = "default_state_file")]
    pub state_file: PathBuf,
    #[serde(default = "default_sslocal_bin")]
    pub sslocal_bin: PathBuf,
    /// simple-obfs plugin (SIP003) path; required by nodes carrying `plugin: obfs`
    /// in the subscription
    #[serde(default = "default_obfs_plugin_bin")]
    pub obfs_plugin_bin: PathBuf,
    /// sing-box path; required by `type: anytls` nodes in the subscription
    #[serde(default = "default_singbox_bin")]
    pub singbox_bin: PathBuf,
    pub subscriptions: SubscriptionsConfig,
    #[serde(default)]
    pub classes: BTreeMap<String, ClassConfig>,
    #[serde(default)]
    pub probe: ProbeConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub selection: SelectionConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SubscriptionsConfig {
    /// Legacy local-manifest form. When present it becomes the single
    /// implicit `default` profile, preserving the original configuration
    /// shape and its merge semantics.
    #[serde(default)]
    pub files: Vec<PathBuf>,
    /// Profile selected on first run. A persisted runtime selection may
    /// override this; omitted is accepted when there is exactly one profile.
    #[serde(default)]
    pub default: Option<String>,
    /// Named, mutually exclusive subscriptions. Only one profile contributes
    /// nodes to the live pool at a time.
    #[serde(default)]
    pub profiles: BTreeMap<String, SubscriptionProfileConfig>,
}

/// One named subscription source. Local profiles may merge several manifest
/// snapshots, matching the legacy `subscriptions.files` behavior. Remote
/// profiles keep their credential-bearing URL in a separate private file;
/// the main TOML therefore remains safe to inspect and copy.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SubscriptionProfileConfig {
    #[serde(default)]
    pub files: Vec<PathBuf>,
    #[serde(default)]
    pub url_file: Option<PathBuf>,
    #[serde(default)]
    pub cache_file: Option<PathBuf>,
}

/// Stable name exposed for an unchanged legacy `[subscriptions] files = ...`
/// configuration.
pub const LEGACY_SUBSCRIPTION_NAME: &str = "default";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ClassConfig {
    /// Loopback listen address for this class, e.g. 127.0.0.1:17878
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ProbeConfig {
    #[serde(default = "default_probe_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_probe_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_probe_concurrency")]
    pub concurrency: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HealthConfig {
    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_health_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_fail_threshold")]
    pub fail_threshold: u32,
    #[serde(default = "default_health_url")]
    pub url: String,
    /// Minimum drain grace period (seconds) for an old data plane after a
    /// switch. A path with captured client connections remains alive longer,
    /// subject to the supervisor's bounded retirement fail-safe.
    #[serde(default = "default_drain_grace")]
    pub drain_grace_secs: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SelectionConfig {
    /// Hysteresis ratio: a challenger must beat the incumbent by this clear
    /// margin
    #[serde(default = "default_hysteresis")]
    pub hysteresis: f64,
    /// EMA smoothing factor
    #[serde(default = "default_ema_alpha")]
    pub ema_alpha: f64,
    /// Node display-name substrings eligible for AUTOMATIC selection
    /// (initial activation, health-failure recovery, challenger-wins).
    /// Empty = all nodes. Manual switching via the control socket is never
    /// restricted. e.g. `regions = ["🇭🇰"]`.
    #[serde(default = "default_regions")]
    pub regions: Vec<String>,
    /// Automatic node switching without operator action. When false, a
    /// working active node never moves on its own — health-failure recovery
    /// and challenger-wins only log. Establishing a path when no node is
    /// active is still automatic (availability, not switching).
    #[serde(default = "default_auto_switch")]
    pub auto_switch: bool,
}

fn default_log_dir() -> PathBuf {
    home_dir().join(".local/share/causeway/logs")
}
fn default_state_file() -> PathBuf {
    home_dir().join(".local/share/causeway/state.json")
}
fn default_sslocal_bin() -> PathBuf {
    home_dir().join(".local/share/causeway/bin/sslocal")
}
fn default_obfs_plugin_bin() -> PathBuf {
    home_dir().join(".local/share/causeway/bin/obfs-local")
}
fn default_singbox_bin() -> PathBuf {
    home_dir().join(".local/share/causeway/bin/sing-box")
}
fn default_probe_interval() -> u64 {
    600
}
fn default_probe_timeout_ms() -> u64 {
    3000
}
fn default_probe_concurrency() -> usize {
    32
}
fn default_health_interval() -> u64 {
    30
}
fn default_health_timeout_ms() -> u64 {
    5000
}
fn default_health_fail_threshold() -> u32 {
    3
}
fn default_health_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}
fn default_drain_grace() -> u64 {
    10
}
fn default_hysteresis() -> f64 {
    0.30
}
fn default_ema_alpha() -> f64 {
    0.3
}
fn default_regions() -> Vec<String> {
    Vec::new()
}
fn default_auto_switch() -> bool {
    true
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_probe_interval(),
            timeout_ms: default_probe_timeout_ms(),
            concurrency: default_probe_concurrency(),
        }
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_health_interval(),
            timeout_ms: default_health_timeout_ms(),
            fail_threshold: default_health_fail_threshold(),
            url: default_health_url(),
            drain_grace_secs: default_drain_grace(),
        }
    }
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            hysteresis: default_hysteresis(),
            ema_alpha: default_ema_alpha(),
            regions: default_regions(),
            auto_switch: default_auto_switch(),
        }
    }
}

impl Config {
    /// Expand `~` in path fields.
    pub fn expand_paths(&mut self) {
        self.log_dir = expand_tilde(&self.log_dir);
        self.state_file = expand_tilde(&self.state_file);
        self.sslocal_bin = expand_tilde(&self.sslocal_bin);
        self.obfs_plugin_bin = expand_tilde(&self.obfs_plugin_bin);
        self.singbox_bin = expand_tilde(&self.singbox_bin);
        self.subscriptions.files = self
            .subscriptions
            .files
            .iter()
            .map(|path| expand_tilde(path))
            .collect();
        for profile in self.subscriptions.profiles.values_mut() {
            profile.files = profile
                .files
                .iter()
                .map(|path| expand_tilde(path))
                .collect();
            profile.url_file = profile.url_file.as_ref().map(|path| expand_tilde(path));
            profile.cache_file = profile.cache_file.as_ref().map(|path| expand_tilde(path));
        }
    }

    /// Hard validation (errors refuse startup); environment problems (missing
    /// files etc.) go to `warnings`.
    #[cfg(test)]
    fn validate(&self) -> anyhow::Result<Vec<String>> {
        self.validate_at(None)
    }

    fn validate_at(&self, config_path: Option<&Path>) -> anyhow::Result<Vec<String>> {
        let mut warnings = Vec::new();
        if self.classes.is_empty() {
            bail!("at least one [classes.<name>] section is required in the config");
        }
        for (name, class) in &self.classes {
            if !class.listen.ip().is_loopback() {
                // Design red line: listen on loopback only, never expose an
                // entry point to the outside
                bail!(
                    "listen address {} of class {name:?} is not a loopback address",
                    class.listen
                );
            }
        }
        self.validate_writable_path_spellings()?;
        let mut protected_paths = vec![
            (self.state_file.clone(), "persistent state file".to_string()),
            (
                self.state_file.with_extension("json.tmp"),
                "persistent state temporary file".to_string(),
            ),
            (
                self.sslocal_bin.clone(),
                "data-plane executable".to_string(),
            ),
            (
                self.obfs_plugin_bin.clone(),
                "transport-plugin executable".to_string(),
            ),
            (
                self.singbox_bin.clone(),
                "data-plane executable".to_string(),
            ),
        ];
        if let Some(config_path) = config_path {
            protected_paths.push((config_path.to_path_buf(), "main config file".to_string()));
        }
        self.subscriptions
            .validate(&mut warnings, &protected_paths)?;
        self.validate_filesystem_roles(config_path)?;
        if !self.sslocal_bin.exists() {
            warnings.push(format!(
                "sslocal does not exist: {} (run scripts/install-sslocal.sh first)",
                self.sslocal_bin.display()
            ));
        }
        if !self.obfs_plugin_bin.exists() {
            warnings.push(format!(
                "obfs plugin does not exist: {} (nodes with plugin: obfs in the subscription will fail to activate; run scripts/install-obfs.sh first)",
                self.obfs_plugin_bin.display()
            ));
        }
        if !self.singbox_bin.exists() {
            warnings.push(format!(
                "sing-box does not exist: {} (nodes of type anytls in the subscription will fail to activate; set singbox_bin or install sing-box first)",
                self.singbox_bin.display()
            ));
        }
        if self.probe.interval_secs == 0 || self.health.interval_secs == 0 {
            bail!("probe/health interval_secs must be > 0");
        }
        if self.probe.concurrency == 0 {
            bail!("probe.concurrency must be >= 1");
        }
        if self.probe.timeout_ms == 0 || self.health.timeout_ms == 0 {
            bail!("probe/health timeout_ms must be > 0");
        }
        if self.health.fail_threshold == 0 {
            bail!("health.fail_threshold must be >= 1");
        }
        if !(0.0..=1.0).contains(&self.selection.hysteresis) {
            bail!(
                "selection.hysteresis must be in [0,1], got {}",
                self.selection.hysteresis
            );
        }
        if !(0.0..=1.0).contains(&self.selection.ema_alpha) || self.selection.ema_alpha == 0.0 {
            bail!(
                "selection.ema_alpha must be in (0,1], got {}",
                self.selection.ema_alpha
            );
        }
        if !valid_health_url(&self.health.url) {
            // The health check deliberately uses plaintext HTTP only
            // (generate_204 semantics); HTTPS would add needless complexity
            bail!("health.url must be an absolute plaintext http:// URL without credentials, fragments, whitespace, or control characters");
        }
        Ok(warnings)
    }

    /// Paths below are opened for writing, truncated, renamed over, used as
    /// directories, or have permissions changed at runtime. Refuse `..`
    /// outright: resolving it lexically before a symlink is unsafe, while
    /// accepting it and relying on a one-time canonicalization leaves the
    /// eventual create/open target ambiguous.
    fn validate_writable_path_spellings(&self) -> anyhow::Result<()> {
        reject_unsafe_writable_path(&self.state_file, "state_file")?;
        reject_unsafe_writable_path(&self.log_dir, "log_dir")?;
        for (name, profile) in &self.subscriptions.profiles {
            if let Some(cache_file) = &profile.cache_file {
                reject_unsafe_writable_path(
                    cache_file,
                    &format!("cache_file of subscription profile {name:?}"),
                )?;
            }
        }
        Ok(())
    }

    /// Validate every filesystem role as one set. This deliberately lives
    /// outside `SubscriptionsConfig::validate`: the legacy `files` form may
    /// finish its shape validation early, but must never bypass collision
    /// checks against state, logs, runtime files, or executables.
    fn validate_filesystem_roles(&self, config_path: Option<&Path>) -> anyhow::Result<()> {
        const RUNTIME_NAMESPACE: &str = "runtime";

        let run_dir = self
            .state_file
            .parent()
            .map(|parent| parent.join("run"))
            .unwrap_or_else(|| PathBuf::from("/tmp/causeway-run"));
        let control_socket = run_dir.join("control.sock");

        let mut roles = vec![
            PathRole::writable_file(&self.state_file, "persistent state file")?,
            PathRole::writable_file(
                &self.state_file.with_extension("json.tmp"),
                "persistent state temporary file",
            )?,
            PathRole::writable_dir(&self.log_dir, "log directory namespace")?,
            // The socket and adapter credential files are intentional children
            // of the same private run directory. Their shared namespace tag lets
            // that one containment relationship through while still comparing
            // both paths against every outside role.
            PathRole::writable_file_in_namespace(
                &control_socket,
                "control socket",
                RUNTIME_NAMESPACE,
            )?,
            PathRole::writable_dir_in_namespace(
                &run_dir,
                "runtime and data-plane credential directory namespace",
                RUNTIME_NAMESPACE,
            )?,
            PathRole::read_only(&self.sslocal_bin, "sslocal executable")?,
            PathRole::read_only(&self.obfs_plugin_bin, "transport-plugin executable")?,
            PathRole::read_only(&self.singbox_bin, "sing-box executable")?,
        ];
        if let Some(path) = config_path {
            roles.push(PathRole::read_only(path, "main config file")?);
        }

        for (index, file) in self.subscriptions.files.iter().enumerate() {
            roles.push(PathRole::read_only(
                file,
                format!("legacy local subscription source #{}", index + 1),
            )?);
        }
        for (name, profile) in &self.subscriptions.profiles {
            for (index, file) in profile.files.iter().enumerate() {
                roles.push(PathRole::read_only(
                    file,
                    format!("local source #{} of profile {name:?}", index + 1),
                )?);
            }
            if let Some(url_file) = &profile.url_file {
                roles.push(PathRole::read_only(
                    url_file,
                    format!("URL secret of profile {name:?}"),
                )?);
            }
            if let Some(cache_file) = &profile.cache_file {
                roles.push(PathRole::writable_file(
                    cache_file,
                    format!("subscription cache of profile {name:?}"),
                )?);
                for (slot, label) in [("causeway-a", "A"), ("causeway-b", "B")] {
                    let slot_path =
                        derived_cache_slot_path(cache_file, slot).with_context(|| {
                            format!(
                            "derive cache slot {label} for subscription profile {name:?} from {}",
                            cache_file.display()
                        )
                        })?;
                    roles.push(PathRole::writable_file(
                        &slot_path,
                        format!("subscription cache slot {label} of profile {name:?}"),
                    )?);
                }
            }
        }

        validate_role_collisions(&roles)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PathAccess {
    ReadOnly,
    WritableFile,
    WritableDirectory,
}

impl PathAccess {
    fn is_writable(self) -> bool {
        self != Self::ReadOnly
    }
}

#[derive(Debug)]
struct PathRole {
    path: PathBuf,
    label: String,
    access: PathAccess,
    /// Roles in the same namespace may intentionally contain one another.
    namespace: Option<&'static str>,
}

impl PathRole {
    fn read_only(path: &Path, label: impl Into<String>) -> anyhow::Result<Self> {
        Self::new(path, label, PathAccess::ReadOnly, None)
    }

    fn writable_file(path: &Path, label: impl Into<String>) -> anyhow::Result<Self> {
        Self::new(path, label, PathAccess::WritableFile, None)
    }

    fn writable_file_in_namespace(
        path: &Path,
        label: impl Into<String>,
        namespace: &'static str,
    ) -> anyhow::Result<Self> {
        Self::new(path, label, PathAccess::WritableFile, Some(namespace))
    }

    fn writable_dir(path: &Path, label: impl Into<String>) -> anyhow::Result<Self> {
        Self::new(path, label, PathAccess::WritableDirectory, None)
    }

    fn writable_dir_in_namespace(
        path: &Path,
        label: impl Into<String>,
        namespace: &'static str,
    ) -> anyhow::Result<Self> {
        Self::new(path, label, PathAccess::WritableDirectory, Some(namespace))
    }

    fn new(
        path: &Path,
        label: impl Into<String>,
        access: PathAccess,
        namespace: Option<&'static str>,
    ) -> anyhow::Result<Self> {
        let label = label.into();
        let path =
            normalized_path(path).with_context(|| format!("normalize filesystem role {label}"))?;
        Ok(Self {
            path,
            label,
            access,
            namespace,
        })
    }
}

fn validate_role_collisions(roles: &[PathRole]) -> anyhow::Result<()> {
    // Exact aliases are reported before directory containment so a cache
    // named `control.sock`, for example, identifies the precise collision
    // instead of only its containing run directory.
    for exact_only in [true, false] {
        for (index, left) in roles.iter().enumerate() {
            for right in &roles[index + 1..] {
                if !left.access.is_writable() && !right.access.is_writable() {
                    continue;
                }
                let exact = left.path == right.path;
                if !exact && left.namespace.is_some() && left.namespace == right.namespace {
                    continue;
                }
                // Prefix collisions matter even when both configured roles
                // are files: creating one path's parent would turn the other
                // role into a directory (for example state `/x/state` and
                // cache `/x/state/cache`).
                let contains =
                    left.path.starts_with(&right.path) || right.path.starts_with(&left.path);
                if (exact_only && exact) || (!exact_only && !exact && contains) {
                    bail!(
                        "filesystem role conflict: {} ({}) conflicts with {} ({})",
                        left.label,
                        left.path.display(),
                        right.label,
                        right.path.display()
                    );
                }
            }
        }
    }
    Ok(())
}

fn reject_unsafe_writable_path(path: &Path, label: &str) -> anyhow::Result<()> {
    if path.as_os_str().is_empty() {
        bail!("{label} must not be empty");
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        bail!(
            "{label} must not contain '..' in writable path {}",
            path.display()
        );
    }
    Ok(())
}

fn derived_cache_slot_path(base: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let name = base
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("cache_file must name a file, got {}", base.display()))?;
    let mut slot_name = name.to_os_string();
    slot_name.push(".");
    slot_name.push(suffix);
    Ok(base.with_file_name(slot_name))
}

impl SubscriptionsConfig {
    /// Names visible to control clients. The legacy form deliberately looks
    /// like a normal single profile after normalization.
    pub fn profile_names(&self) -> Vec<String> {
        if !self.files.is_empty() {
            vec![LEGACY_SUBSCRIPTION_NAME.to_string()]
        } else {
            self.profiles.keys().cloned().collect()
        }
    }

    /// Startup selection before a persisted runtime choice is considered.
    pub fn default_profile_name(&self) -> anyhow::Result<String> {
        if !self.files.is_empty() {
            return Ok(LEGACY_SUBSCRIPTION_NAME.to_string());
        }
        if let Some(name) = &self.default {
            return Ok(name.clone());
        }
        match self.profiles.keys().next() {
            Some(name) if self.profiles.len() == 1 => Ok(name.clone()),
            _ => bail!("subscriptions.default is required when multiple profiles are configured"),
        }
    }

    /// Resolve either configuration shape to a profile without making callers
    /// special-case the old `files` field.
    pub fn profile(&self, name: &str) -> Option<SubscriptionProfileConfig> {
        if !self.files.is_empty() {
            return (name == LEGACY_SUBSCRIPTION_NAME).then(|| SubscriptionProfileConfig {
                files: self.files.clone(),
                url_file: None,
                cache_file: None,
            });
        }
        self.profiles.get(name).cloned()
    }

    /// Deterministic, credential-free identities for every configured source.
    /// The URL file's path is included, but its secret contents are never read.
    pub fn source_identities(&self) -> anyhow::Result<BTreeMap<String, String>> {
        self.profile_names()
            .into_iter()
            .map(|name| {
                let profile = self
                    .profile(&name)
                    .ok_or_else(|| anyhow::anyhow!("subscription profile {name:?} disappeared"))?;
                Ok((name, profile.source_identity()?))
            })
            .collect()
    }

    fn validate(
        &self,
        warnings: &mut Vec<String>,
        config_protected_paths: &[(PathBuf, String)],
    ) -> anyhow::Result<()> {
        if !self.files.is_empty() && !self.profiles.is_empty() {
            bail!(
                "subscriptions.files and subscriptions.profiles are mutually exclusive; use one configuration shape"
            );
        }
        if !self.files.is_empty() {
            if self
                .default
                .as_deref()
                .is_some_and(|n| n != LEGACY_SUBSCRIPTION_NAME)
            {
                bail!("legacy subscriptions.files only supports default = {LEGACY_SUBSCRIPTION_NAME:?}");
            }
            warn_missing_files(&self.files, warnings);
            return Ok(());
        }
        if self.profiles.is_empty() {
            bail!(
                "no subscriptions configured: set legacy subscriptions.files or add a named subscriptions.profiles entry"
            );
        }

        let mut protected_paths = config_protected_paths
            .iter()
            .map(|(path, label)| Ok((normalized_path(path)?, label.clone())))
            .collect::<anyhow::Result<Vec<_>>>()?;

        // Cache files are writable. Resolve every configured source first so
        // a cache cannot overwrite another profile's URL secret or manifest,
        // including through `..` components or an existing symlinked parent.
        for (name, profile) in &self.profiles {
            for file in &profile.files {
                protected_paths.push((
                    normalized_path(file)?,
                    format!("local source of profile {name:?}"),
                ));
            }
            if let Some(url_file) = &profile.url_file {
                protected_paths.push((
                    normalized_path(url_file)?,
                    format!("URL secret of profile {name:?}"),
                ));
            }
        }
        let mut cache_owners = std::collections::HashMap::<PathBuf, &str>::new();
        for (name, profile) in &self.profiles {
            validate_profile_name(name)?;
            let local = !profile.files.is_empty();
            let remote = profile.url_file.is_some();
            if local == remote {
                bail!(
                    "subscription profile {name:?} must configure exactly one source: files or url_file"
                );
            }
            if local {
                if profile.cache_file.is_some() {
                    bail!("local subscription profile {name:?} must not set cache_file");
                }
                warn_missing_files(&profile.files, warnings);
            } else {
                let url_file = profile.url_file.as_ref().expect("remote checked above");
                let Some(cache_file) = profile.cache_file.as_ref() else {
                    bail!("remote subscription profile {name:?} requires cache_file");
                };
                let normalized_cache = normalized_path(cache_file)?;
                if let Some((_, label)) = protected_paths
                    .iter()
                    .find(|(protected, _)| protected == &normalized_cache)
                {
                    bail!("remote subscription profile {name:?} cache_file conflicts with {label}");
                }
                if let Some(previous) = cache_owners.insert(normalized_cache, name) {
                    bail!(
                        "remote subscription profiles {previous:?} and {name:?} must not share cache_file {}",
                        cache_file.display()
                    );
                }
                if !url_file.exists() {
                    warnings.push(format!(
                        "subscription URL file does not exist for profile {name:?}: {}",
                        url_file.display()
                    ));
                } else {
                    validate_private_file(url_file, "subscription URL file")?;
                }
                if cache_file.exists() {
                    validate_private_file(cache_file, "subscription cache file")?;
                }
            }
        }

        let default = self.default_profile_name()?;
        if !self.profiles.contains_key(&default) {
            bail!("subscriptions.default names unknown profile {default:?}");
        }
        Ok(())
    }
}

impl SubscriptionProfileConfig {
    /// Identify the configured source without inspecting a manifest or the
    /// credential-bearing URL file. Paths are normalized by the same routine
    /// used for collision validation, so harmless aliases do not create a new
    /// identity while changes to a file list, URL file, or cache do.
    pub fn source_identity(&self) -> anyhow::Result<String> {
        #[derive(serde::Serialize)]
        #[serde(tag = "kind", rename_all = "kebab-case")]
        enum Identity {
            Local {
                files: Vec<PathBuf>,
            },
            Remote {
                url_file: PathBuf,
                cache_file: PathBuf,
            },
        }

        let identity = if !self.files.is_empty() {
            Identity::Local {
                files: self
                    .files
                    .iter()
                    .map(|path| normalized_path(path))
                    .collect::<anyhow::Result<_>>()?,
            }
        } else {
            Identity::Remote {
                url_file: normalized_path(
                    self.url_file
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("remote profile has no url_file"))?,
                )?,
                cache_file: normalized_path(
                    self.cache_file
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("remote profile has no cache_file"))?,
                )?,
            }
        };
        let canonical =
            serde_json::to_vec(&identity).context("serialize subscription source identity")?;
        Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
    }
}

/// Resolve an existing path, or the nearest existing ancestor plus the
/// remaining lexical components. This catches aliases through symlinked
/// parents without requiring a not-yet-created cache file to exist.
fn normalized_path(path: &Path) -> anyhow::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve current directory for subscription path validation")?
            .join(path)
    };
    // Find an existing prefix *before* doing any lexical normalization.
    // `/alias/../secret` must let the kernel resolve `alias` first: if it is
    // a symlink, collapsing `..` up front computes a different path.
    let mut existing = None;
    for candidate in absolute.ancestors() {
        match std::fs::symlink_metadata(candidate) {
            Ok(_) => {
                existing = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect path component {}", candidate.display()))
            }
        }
    }
    let existing = existing
        .ok_or_else(|| anyhow::anyhow!("cannot find an existing ancestor of {}", path.display()))?;
    let mut normalized = std::fs::canonicalize(existing)
        .with_context(|| format!("normalize path {}", path.display()))?;
    let missing = absolute.strip_prefix(existing).with_context(|| {
        format!(
            "resolve missing path suffix {} from {}",
            absolute.display(),
            existing.display()
        )
    })?;
    for component in missing.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                // This is used only once we reached a missing suffix. It is
                // conservative for read-only missing paths and unreachable
                // for configured writable paths, where `..` is rejected.
                normalized.pop();
            }
            Component::Normal(name) => normalized.push(name),
            Component::RootDir | Component::Prefix(_) => {
                bail!("invalid path suffix while normalizing {}", path.display())
            }
        }
    }
    Ok(normalized)
}

fn valid_health_url(url: &str) -> bool {
    if !url.starts_with("http://")
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
        || url.contains('#')
    {
        return false;
    }
    let authority = url["http://".len()..]
        .split(['/', '?'])
        .next()
        .unwrap_or_default();
    !authority.is_empty() && !authority.contains('@')
}

fn warn_missing_files(files: &[PathBuf], warnings: &mut Vec<String>) {
    for file in files {
        if !file.exists() {
            warnings.push(format!(
                "subscription file does not exist: {}",
                file.display()
            ));
        }
    }
}

fn validate_profile_name(name: &str) -> anyhow::Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphanumeric() || (i > 0 && matches!(b, b'.' | b'_' | b'-')));
    if !valid {
        bail!(
            "invalid subscription profile name {name:?}: use 1-64 ASCII letters/digits, then letters/digits/./_/-"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(path: &std::path::Path, label: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata =
        std::fs::metadata(path).with_context(|| format!("inspect {label} {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} is not a regular file: {}", path.display());
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "{label} must not be accessible by group or others: {} (use chmod 600)",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file(path: &std::path::Path, label: &str) -> anyhow::Result<()> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("inspect {label} {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} is not a regular file: {}", path.display());
    }
    Ok(())
}

pub fn load(path: &std::path::Path) -> anyhow::Result<(Config, Vec<String>)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read config file {}", path.display()))?;
    let mut cfg: Config =
        toml::from_str(&text).with_context(|| format!("parse config file {}", path.display()))?;
    cfg.expand_paths();
    let warnings = cfg.validate_at(Some(path))?;
    Ok((cfg, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[subscriptions]
files = ["~/sub.yaml"]

[classes.dev]
listen = "127.0.0.1:17878"
"#;

    #[test]
    fn minimal_config_gets_defaults() {
        let mut cfg: Config = toml::from_str(MINIMAL).unwrap();
        cfg.expand_paths();
        assert_eq!(cfg.probe.interval_secs, 600);
        assert_eq!(cfg.probe.timeout_ms, 3000);
        assert_eq!(cfg.probe.concurrency, 32);
        assert_eq!(cfg.health.interval_secs, 30);
        assert_eq!(cfg.health.fail_threshold, 3);
        assert_eq!(cfg.health.url, "http://www.gstatic.com/generate_204");
        assert!((cfg.selection.hysteresis - 0.30).abs() < 1e-9);
        assert!((cfg.selection.ema_alpha - 0.3).abs() < 1e-9);
        // ~ expansion
        let home = home_dir();
        assert_eq!(cfg.subscriptions.files[0], home.join("sub.yaml"));
        assert_eq!(
            cfg.state_file,
            home.join(".local/share/causeway/state.json")
        );
        assert_eq!(
            cfg.obfs_plugin_bin,
            home.join(".local/share/causeway/bin/obfs-local"),
            "obfs plugin default path"
        );
        assert_eq!(
            cfg.singbox_bin,
            home.join(".local/share/causeway/bin/sing-box"),
            "sing-box default path"
        );
    }

    #[test]
    fn non_loopback_listen_rejected() {
        let text = r#"
[subscriptions]
files = ["/tmp/x.yaml"]
[classes.bad]
listen = "0.0.0.0:17878"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn https_health_url_rejected() {
        let text = r#"
[subscriptions]
files = ["/tmp/x.yaml"]
[classes.dev]
listen = "127.0.0.1:17878"
[health]
url = "https://www.gstatic.com/generate_204"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn legacy_files_normalize_to_one_default_profile() {
        let cfg: Config = toml::from_str(MINIMAL).unwrap();
        assert_eq!(
            cfg.subscriptions.profile_names(),
            [LEGACY_SUBSCRIPTION_NAME]
        );
        assert_eq!(
            cfg.subscriptions.default_profile_name().unwrap(),
            LEGACY_SUBSCRIPTION_NAME
        );
        let profile = cfg
            .subscriptions
            .profile(LEGACY_SUBSCRIPTION_NAME)
            .expect("legacy profile");
        assert_eq!(profile.files, [PathBuf::from("~/sub.yaml")]);
        assert!(profile.url_file.is_none());
        assert!(profile.cache_file.is_none());
    }

    #[test]
    fn named_local_and_remote_profiles_parse_without_mixing() {
        let text = r#"
[subscriptions]
default = "remote"

[subscriptions.profiles.local]
files = ["~/local-a.yaml", "~/local-b.yaml"]

[subscriptions.profiles.remote]
url_file = "~/.config/causeway/remote.url"
cache_file = "~/.local/share/causeway/subscriptions/remote.yaml"

[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let mut cfg: Config = toml::from_str(text).unwrap();
        cfg.expand_paths();
        assert_eq!(cfg.subscriptions.profile_names(), ["local", "remote"]);
        assert_eq!(cfg.subscriptions.default_profile_name().unwrap(), "remote");
        let local = cfg.subscriptions.profile("local").unwrap();
        assert_eq!(local.files.len(), 2);
        assert!(local.files.iter().all(|p| p.starts_with(home_dir())));
        let remote = cfg.subscriptions.profile("remote").unwrap();
        assert!(remote.files.is_empty());
        assert!(remote.url_file.unwrap().starts_with(home_dir()));
        assert!(remote.cache_file.unwrap().starts_with(home_dir()));
    }

    #[test]
    fn source_identity_tracks_paths_without_reading_url_secret() {
        let dir =
            std::env::temp_dir().join(format!("causeway-source-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url_file = dir.join("provider.url");
        let other_url_file = dir.join("other.url");
        let cache_file = dir.join("cache.yaml");
        std::fs::write(&url_file, "first-secret").unwrap();
        let profile = SubscriptionProfileConfig {
            files: Vec::new(),
            url_file: Some(url_file.clone()),
            cache_file: Some(cache_file.clone()),
        };
        let identity = profile.source_identity().unwrap();
        assert!(identity.starts_with("sha256:"));
        assert!(!identity.contains("secret"));

        std::fs::write(&url_file, "different-secret").unwrap();
        assert_eq!(profile.source_identity().unwrap(), identity);
        let changed_url = SubscriptionProfileConfig {
            url_file: Some(other_url_file),
            ..profile.clone()
        };
        assert_ne!(changed_url.source_identity().unwrap(), identity);
        let changed_cache = SubscriptionProfileConfig {
            cache_file: Some(dir.join("other-cache.yaml")),
            ..profile
        };
        assert_ne!(changed_cache.source_identity().unwrap(), identity);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn legacy_and_named_profiles_are_mutually_exclusive() {
        let text = r#"
[subscriptions]
files = ["/tmp/legacy.yaml"]

[subscriptions.profiles.named]
files = ["/tmp/named.yaml"]

[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("mutually exclusive"));
    }

    #[test]
    fn multiple_profiles_require_a_known_default() {
        let missing = r#"
[subscriptions.profiles.a]
files = ["/tmp/a.yaml"]
[subscriptions.profiles.b]
files = ["/tmp/b.yaml"]
[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(missing).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("subscriptions.default"));

        let unknown = r#"
[subscriptions]
default = "missing"
[subscriptions.profiles.only]
files = ["/tmp/a.yaml"]
[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(unknown).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unknown profile"));
    }

    #[test]
    fn remote_profile_requires_url_and_cache_only() {
        let without_cache = r#"
[subscriptions.profiles.remote]
url_file = "/tmp/remote.url"
[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(without_cache).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires cache_file"));

        let mixed_source = r#"
[subscriptions.profiles.remote]
files = ["/tmp/a.yaml"]
url_file = "/tmp/remote.url"
cache_file = "/tmp/cache.yaml"
[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(mixed_source).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("exactly one source"));
    }

    #[test]
    fn invalid_profile_name_is_rejected() {
        let text = r#"
[subscriptions.profiles."not a name"]
files = ["/tmp/a.yaml"]
[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("invalid subscription profile name"));
    }

    #[test]
    fn remote_profiles_cannot_overwrite_secret_or_each_other() {
        let same_path = r#"
[subscriptions.profiles.remote]
url_file = "/tmp/shared"
cache_file = "/tmp/shared"
[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(same_path).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("conflicts with URL secret"));

        let shared_cache = r#"
[subscriptions]
default = "a"
[subscriptions.profiles.a]
url_file = "/tmp/a.url"
cache_file = "/tmp/shared.yaml"
[subscriptions.profiles.b]
url_file = "/tmp/b.url"
cache_file = "/tmp/shared.yaml"
[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(shared_cache).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must not share cache_file"));
    }

    #[test]
    fn cache_cannot_overwrite_another_profile_source_or_state() {
        let source_conflict = r#"
[subscriptions]
default = "local"
[subscriptions.profiles.local]
files = ["/tmp/source.yaml"]
[subscriptions.profiles.remote]
url_file = "/tmp/remote.url"
cache_file = "/tmp/a/../source.yaml"
[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(source_conflict).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must not contain '..'"));

        let state_conflict = r#"
state_file = "/tmp/state.json"
[subscriptions.profiles.remote]
url_file = "/tmp/remote.url"
cache_file = "/tmp/x/../state.json"
[classes.dev]
listen = "127.0.0.1:17878"
"#;
        let cfg: Config = toml::from_str(state_conflict).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must not contain '..'"));
    }

    fn config_with_legacy_source(state_file: &Path, log_dir: &Path, source: &Path) -> Config {
        let text = format!(
            r#"
state_file = {state_file:?}
log_dir = {log_dir:?}
[subscriptions]
files = [{source:?}]
[classes.dev]
listen = "127.0.0.1:17878"
"#
        );
        toml::from_str(&text).unwrap()
    }

    #[test]
    fn state_and_legacy_source_collision_is_rejected() {
        let dir = unique_test_dir("legacy-state-collision");
        let state = dir.join("state.json");
        let cfg = config_with_legacy_source(&state, &dir.join("logs"), &state);
        let error = cfg.validate().unwrap_err().to_string();
        assert!(error.contains("persistent state file"), "{error}");
        assert!(
            error.contains("legacy local subscription source"),
            "{error}"
        );
    }

    #[test]
    fn derived_cache_slot_cannot_collide_with_a_source() {
        let dir = unique_test_dir("derived-slot-collision");
        let text = format!(
            r#"
state_file = {state:?}
log_dir = {logs:?}
[subscriptions]
default = "remote"
[subscriptions.profiles.local]
files = [{slot:?}]
[subscriptions.profiles.remote]
url_file = {url:?}
cache_file = {cache:?}
[classes.dev]
listen = "127.0.0.1:17878"
"#,
            state = dir.join("state.json"),
            logs = dir.join("logs"),
            slot = dir.join("remote.yaml.causeway-a"),
            url = dir.join("missing.url"),
            cache = dir.join("remote.yaml"),
        );
        let cfg: Config = toml::from_str(&text).unwrap();
        let error = cfg.validate().unwrap_err().to_string();
        assert!(error.contains("cache slot A"), "{error}");
        assert!(error.contains("local source"), "{error}");
    }

    #[test]
    fn run_control_and_log_namespace_collisions_are_rejected() {
        let dir = unique_test_dir("run-log-collision");
        let state = dir.join("state.json");
        for log_dir in [dir.join("run"), dir.join("run/control.sock")] {
            let cfg = config_with_legacy_source(&state, &log_dir, &dir.join("source.yaml"));
            let error = cfg.validate().unwrap_err().to_string();
            assert!(error.contains("log directory namespace"), "{error}");
            assert!(
                error.contains("control socket")
                    || error.contains("runtime and data-plane credential directory"),
                "{error}"
            );
        }
    }

    #[test]
    fn every_configured_writable_path_rejects_parent_components() {
        let dir = unique_test_dir("parent-dir");
        let state = dir.join("state.json");
        let source = dir.join("source.yaml");

        let cfg =
            config_with_legacy_source(&dir.join("child/../state.json"), &dir.join("logs"), &source);
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("state_file must not contain '..'"));

        let cfg = config_with_legacy_source(&state, &dir.join("child/../logs"), &source);
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("log_dir must not contain '..'"));

        let text = format!(
            r#"
state_file = {state:?}
log_dir = {logs:?}
[subscriptions.profiles.remote]
url_file = {url:?}
cache_file = {cache:?}
[classes.dev]
listen = "127.0.0.1:17878"
"#,
            logs = dir.join("logs"),
            url = dir.join("missing.url"),
            cache = dir.join("child/../cache.yaml"),
        );
        let cfg: Config = toml::from_str(&text).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cache_file of subscription profile"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_alias_collision_is_rejected_without_lexical_precollapse() {
        use std::os::unix::fs::symlink;

        let dir = unique_test_dir("symlink-alias");
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        symlink(&real, dir.join("alias")).unwrap();
        let state = real.join("state.json");
        let cfg =
            config_with_legacy_source(&state, &dir.join("logs"), &dir.join("alias/state.json"));
        let error = cfg.validate().unwrap_err().to_string();
        assert!(error.contains("persistent state file"), "{error}");
        assert!(
            error.contains("legacy local subscription source"),
            "{error}"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "causeway-config-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn loaded_config_protects_its_own_path_from_cache_updates() {
        let dir = std::env::temp_dir().join(format!(
            "causeway-config-self-protect-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        let text = format!(
            r#"
[subscriptions.profiles.remote]
url_file = {url_file:?}
cache_file = {config_path:?}
[classes.dev]
listen = "127.0.0.1:17878"
"#,
            url_file = dir.join("missing.url")
        );
        std::fs::write(&config_path, text).unwrap();

        assert!(load(&config_path)
            .unwrap_err()
            .to_string()
            .contains("main config file"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn zero_intervals_and_malformed_health_urls_are_rejected() {
        for extra in [
            "[probe]\ninterval_secs = 0\n",
            "[health]\ninterval_secs = 0\n",
            "[health]\nurl = \"http://example.com\\r\\nX-Test: injected\"\n",
            "[health]\nurl = \"http://user@example.com/path\"\n",
            "[health]\nurl = \"http:///missing-host\"\n",
            "[health]\nurl = \"http://example.com/path#fragment\"\n",
        ] {
            let text = format!("{MINIMAL}\n{extra}");
            let cfg: Config = toml::from_str(&text).unwrap();
            assert!(
                cfg.validate().is_err(),
                "accepted invalid config: {extra:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_remote_secret_must_be_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "causeway-config-secret-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let url_file = dir.join("remote.url");
        std::fs::write(&url_file, "https://subscription.example/fixture").unwrap();
        std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o644)).unwrap();

        let text = format!(
            r#"
[subscriptions.profiles.remote]
url_file = {url_file:?}
cache_file = {cache_file:?}
[classes.dev]
listen = "127.0.0.1:17878"
"#,
            cache_file = dir.join("cache.yaml")
        );
        let cfg: Config = toml::from_str(&text).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("chmod 600"));
        std::fs::remove_dir_all(dir).ok();
    }
}
