//! Parsing and secure snapshot refresh of Clash-compatible YAML subscription
//! manifests.
//!
//! Entries with `type: ss` or `type: anytls` in the `proxies:` list are
//! extracted; all other protocols (trojan/...) are dropped by design.
//! Remote profile URLs live in separate private files and are passed to the
//! fetcher over stdin, never argv or logs. A downloaded manifest becomes the
//! new cache only after it parses to at least one supported node.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, warn};

use crate::config::SubscriptionProfileConfig;

/// A provider response is configuration data, not an unbounded download.
const MAX_REMOTE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_SUBSCRIPTION_URL_BYTES: u64 = 8192;
/// Bound staging time and resource use even when an otherwise valid provider
/// response contains an excessive number of supported entries.
pub const MAX_PROFILE_NODES: usize = 256;
static CACHE_TMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub const CACHE_SLOT_A: &str = "a";
pub const CACHE_SLOT_B: &str = "b";

/// Derive a private cache slot beside the configured legacy cache path. The
/// configured path remains the compatibility fallback until a state commit
/// explicitly confirms one of these slots.
pub fn cache_slot_path(base: &Path, slot: &str) -> Option<PathBuf> {
    let suffix = match slot {
        CACHE_SLOT_A => "causeway-a",
        CACHE_SLOT_B => "causeway-b",
        _ => return None,
    };
    let name = base.file_name()?.to_string_lossy();
    Some(base.with_file_name(format!("{name}.{suffix}")))
}

/// simple-obfs (SIP003 plugin) parameters, from clash's `plugin-opts` map.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObfsOpts {
    /// Transport obfuscation mode (as defined by simple-obfs: http / tls)
    pub mode: String,
    /// Obfuscated Host (optional on the simple-obfs side in http mode)
    pub host: Option<String>,
}

impl ObfsOpts {
    /// shadowsocks-rust plugin_opts string format: `obfs=http;obfs-host=example.com`
    pub fn to_plugin_opts(&self) -> String {
        match &self.host {
            Some(host) => format!("obfs={};obfs-host={host}", self.mode),
            None => format!("obfs={}", self.mode),
        }
    }
}

/// A Shadowsocks node (a `type: ss` entry in the subscription file).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SsNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    /// SIP003 plugin parameters; None = plain SS (backward compatible for
    /// plugin-free nodes)
    #[serde(default)]
    pub plugin: Option<ObfsOpts>,
}

/// An AnyTLS node (a `type: anytls` entry in the subscription file).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnytlsNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    /// TLS server name override; None = omit the field in the adapter config
    #[serde(default)]
    pub sni: Option<String>,
    /// TLS ALPN list; None = the adapter-side default ["h2", "http/1.1"]
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    /// Client hello fingerprint; None = the adapter-side default "chrome"
    #[serde(default)]
    pub client_fingerprint: Option<String>,
    /// Skip upstream certificate verification (default false)
    #[serde(default)]
    pub skip_cert_verify: bool,
}

/// A parsed node of any supported protocol. Flows through probe / score /
/// state / supervisor as one type; the data plane dispatches on the variant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Node {
    Ss(SsNode),
    Anytls(AnytlsNode),
}

impl Node {
    pub fn name(&self) -> &str {
        match self {
            Node::Ss(n) => &n.name,
            Node::Anytls(n) => &n.name,
        }
    }

    pub fn server(&self) -> &str {
        match self {
            Node::Ss(n) => &n.server,
            Node::Anytls(n) => &n.server,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Node::Ss(n) => n.port,
            Node::Anytls(n) => n.port,
        }
    }

    /// Protocol key, for logs and error messages
    pub fn kind(&self) -> &'static str {
        match self {
            Node::Ss(_) => "ss",
            Node::Anytls(_) => "anytls",
        }
    }
}

#[derive(Debug, Error)]
pub enum SubscriptionError {
    #[error("failed to read subscription file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse subscription file {path}: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("subscription URL file {path} is empty or invalid (expected one HTTPS URL)")]
    InvalidUrlFile { path: PathBuf },
    #[error("failed to start the subscription fetcher: {0}")]
    FetchStart(std::io::Error),
    #[error("failed to communicate with the subscription fetcher: {0}")]
    FetchIo(std::io::Error),
    #[error("subscription fetch failed: {detail}")]
    FetchFailed { detail: String },
    #[error("remote subscription exceeds the {limit} byte safety limit")]
    TooLarge { limit: u64 },
    #[error("remote subscription response was not valid YAML")]
    RemoteYaml,
    #[error("failed to update subscription cache {path}: {source}")]
    Cache {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Only the top-level `proxies:` key is consumed; proxy-groups / rules etc.
/// are all ignored.
/// Entries are converted one by one from Value, so a single malformed entry
/// does not affect the others (real-world subscriptions often carry dirty
/// data).
#[derive(Debug, Deserialize)]
struct RawFile {
    #[serde(default)]
    proxies: Vec<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct RawProxy {
    #[serde(rename = "type")]
    kind: String,
    name: Option<String>,
    server: Option<String>,
    /// Tolerates both numeric and quoted-string ports
    port: Option<serde_yaml::Value>,
    cipher: Option<String>,
    /// A purely numeric password may be parsed by YAML as a Number
    password: Option<serde_yaml::Value>,
    /// SIP003 plugin name (clash form, e.g. `obfs`)
    plugin: Option<String>,
    #[serde(rename = "plugin-opts")]
    plugin_opts: Option<RawPluginOpts>,
    // anytls optional fields. Properly typed on purpose: a dirty value type
    // fails the whole entry at RawProxy conversion — explicit failure beats
    // implicit degradation. `udp` is ignored entirely (P1 is TCP-only).
    sni: Option<String>,
    alpn: Option<Vec<String>>,
    #[serde(rename = "client-fingerprint")]
    client_fingerprint: Option<String>,
    #[serde(rename = "skip-cert-verify")]
    skip_cert_verify: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawPluginOpts {
    mode: Option<String>,
    host: Option<String>,
}

fn yaml_value_to_string(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn yaml_value_to_port(v: &serde_yaml::Value) -> Option<u16> {
    match v {
        serde_yaml::Value::Number(n) => n.as_u64().and_then(|u| u16::try_from(u).ok()),
        serde_yaml::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Parse all supported nodes (ss / anytls) out of YAML text.
///
/// - Entries of unsupported types: silently counted and skipped (designed
///   behavior, not an error).
/// - Supported entries with missing fields / wrong field types: warn and skip
///   that entry.
/// - Duplicate names: keep the first, warn and skip the rest (node names key
///   the state file and must be unique, across protocols too).
pub fn parse_str(text: &str) -> Result<Vec<Node>, serde_yaml::Error> {
    parse_str_with_logging(text, true)
}

/// Remote provider bodies are untrusted credential-bearing input. They use
/// the same tolerant parser, but no value-derived diagnostics may reach logs.
fn parse_remote_str(text: &str) -> Result<Vec<Node>, serde_yaml::Error> {
    parse_str_with_logging(text, false)
}

fn parse_str_with_logging(text: &str, log_values: bool) -> Result<Vec<Node>, serde_yaml::Error> {
    let raw: RawFile = serde_yaml::from_str(text)?;
    let mut nodes = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut skipped_type = 0usize;
    let mut skipped_bad = 0usize;

    for value in raw.proxies {
        let proxy: RawProxy = match serde_yaml::from_value(value) {
            Ok(p) => p,
            Err(e) => {
                skipped_bad += 1;
                if log_values {
                    debug!(error = %e, "skipping unparseable proxy entry");
                }
                continue;
            }
        };
        let node = match proxy.kind.as_str() {
            "ss" => match ss_node(proxy, log_values) {
                Some(n) => Node::Ss(n),
                None => {
                    skipped_bad += 1;
                    continue;
                }
            },
            "anytls" => match anytls_node(proxy, log_values) {
                Some(n) => Node::Anytls(n),
                None => {
                    skipped_bad += 1;
                    continue;
                }
            },
            _ => {
                skipped_type += 1;
                continue;
            }
        };
        if !seen.insert(node.name().to_string()) {
            if log_values {
                warn!(name = %node.name(), "duplicate node name, keeping the first and skipping this one");
            }
            continue;
        }
        nodes.push(node);
    }

    debug!(
        skipped_type,
        skipped_bad,
        parsed = nodes.len(),
        "subscription parse statistics"
    );
    Ok(nodes)
}

/// Convert a `type: ss` entry; None = missing fields / unknown plugin (the
/// caller counts and skips).
fn ss_node(proxy: RawProxy, log_values: bool) -> Option<SsNode> {
    let missing = proxy.name.is_none()
        || proxy.server.is_none()
        || proxy.port.as_ref().and_then(yaml_value_to_port).is_none()
        || proxy.cipher.is_none()
        || proxy
            .password
            .as_ref()
            .and_then(yaml_value_to_string)
            .is_none();
    if missing {
        if log_values {
            warn!(name = ?proxy.name, "ss entry has missing fields or wrong field types, skipped");
        }
        return None;
    }
    let mut node = SsNode {
        name: proxy.name.expect("checked above"),
        server: proxy.server.expect("checked above"),
        port: proxy
            .port
            .as_ref()
            .and_then(yaml_value_to_port)
            .expect("checked above"),
        cipher: proxy.cipher.expect("checked above"),
        password: proxy
            .password
            .as_ref()
            .and_then(yaml_value_to_string)
            .expect("checked above"),
        plugin: None,
    };
    // SIP003 plugins: only simple-obfs is recognized. An unknown plugin
    // type skips the node outright — silently falling back to a plain
    // connection would change the transport shape; explicit failure beats
    // implicit degradation (consistent with the routing layer's
    // "explicit over clever").
    match proxy.plugin.as_deref() {
        None => {}
        Some("obfs") => {
            let mode = proxy.plugin_opts.as_ref().and_then(|o| o.mode.clone());
            match mode {
                Some(mode) => {
                    node.plugin = Some(ObfsOpts {
                        mode,
                        host: proxy.plugin_opts.as_ref().and_then(|o| o.host.clone()),
                    });
                }
                None => {
                    if log_values {
                        warn!(name = %node.name, "plugin: obfs but plugin-opts lacks mode, skipped");
                    }
                    return None;
                }
            }
        }
        Some(other) => {
            if log_values {
                warn!(name = %node.name, plugin = %other, "unknown plugin type, node skipped");
            }
            return None;
        }
    }
    Some(node)
}

/// Convert a `type: anytls` entry; None = missing fields (the caller counts
/// and skips).
fn anytls_node(proxy: RawProxy, log_values: bool) -> Option<AnytlsNode> {
    let missing = proxy.name.is_none()
        || proxy.server.is_none()
        || proxy.port.as_ref().and_then(yaml_value_to_port).is_none()
        || proxy
            .password
            .as_ref()
            .and_then(yaml_value_to_string)
            .is_none();
    if missing {
        if log_values {
            warn!(name = ?proxy.name, "anytls entry has missing fields or wrong field types, skipped");
        }
        return None;
    }
    Some(AnytlsNode {
        name: proxy.name.expect("checked above"),
        server: proxy.server.expect("checked above"),
        port: proxy
            .port
            .as_ref()
            .and_then(yaml_value_to_port)
            .expect("checked above"),
        password: proxy
            .password
            .as_ref()
            .and_then(yaml_value_to_string)
            .expect("checked above"),
        sni: proxy.sni,
        alpn: proxy.alpn,
        client_fingerprint: proxy.client_fingerprint,
        skip_cert_verify: proxy.skip_cert_verify.unwrap_or(false),
    })
}

/// Parse a single subscription file.
pub fn parse_file(path: &Path) -> Result<Vec<Node>, SubscriptionError> {
    let text = std::fs::read_to_string(path).map_err(|e| SubscriptionError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_str(&text).map_err(|e| SubscriptionError::Yaml {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Load multiple subscription files, merged and deduplicated. A single
/// failing file only warns, never fatal (explicit degradation).
pub fn load_all(paths: &[PathBuf]) -> Vec<Node> {
    let mut all = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        match parse_file(path) {
            Ok(nodes) => {
                let ss = nodes.iter().filter(|n| matches!(n, Node::Ss(_))).count();
                tracing::info!(file = %path.display(), ss_nodes = ss, anytls_nodes = nodes.len() - ss, "subscription file parsed");
                for node in nodes {
                    if seen.insert(node.name().to_string()) {
                        all.push(node);
                    } else {
                        warn!(name = %node.name(), file = %path.display(), "duplicate node name across files, skipped");
                    }
                }
            }
            Err(e) => warn!(error = %e, "failed to load subscription file, skipped"),
        }
    }
    all
}

/// Load a profile without network access. Local profiles read their manifest
/// files; remote profiles read the last atomically committed cache snapshot.
/// This split lets the supervisor decide explicitly whether a failed refresh
/// may fall back to a cache or must abort a subscription-switch transaction.
#[cfg(test)]
fn load_profile_snapshot(profile: &SubscriptionProfileConfig) -> Vec<Node> {
    load_profile_snapshot_from_slot(profile, None)
}

/// Load only the cache generation confirmed by persistent state. `None`
/// intentionally retains compatibility with a pre-slot legacy cache.
pub fn load_profile_snapshot_from_slot(
    profile: &SubscriptionProfileConfig,
    confirmed_slot: Option<&str>,
) -> Vec<Node> {
    if !profile.files.is_empty() {
        return load_all(&profile.files);
    }
    profile
        .cache_file
        .as_ref()
        .and_then(|base| match confirmed_slot {
            Some(slot) => cache_slot_path(base, slot),
            None => Some(base.clone()),
        })
        .map(|path| load_all(std::slice::from_ref(&path)))
        .unwrap_or_default()
}

/// A fully parsed candidate profile. For a remote source the downloaded body
/// remains pending until `commit_cache`: the supervisor can therefore stage
/// and health-check data planes first, then make the cache part of the same
/// successful subscription-switch transaction. This type intentionally does
/// not implement `Debug`, so a manifest cannot be logged accidentally.
pub struct PreparedProfile {
    nodes: Vec<Node>,
    pending_cache: Option<(PathBuf, Vec<u8>)>,
    committed_slot: Option<String>,
}

impl PreparedProfile {
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Commit into the slot not currently referenced by state. The caller
    /// must persist the returned slot in StateFile before publishing live.
    pub fn commit_cache_slot(
        &mut self,
        confirmed_slot: Option<&str>,
    ) -> Result<Option<String>, SubscriptionError> {
        let Some((base, bytes)) = self.pending_cache.take() else {
            return Ok(None);
        };
        let next = if confirmed_slot == Some(CACHE_SLOT_A) {
            CACHE_SLOT_B
        } else {
            CACHE_SLOT_A
        };
        let path = cache_slot_path(&base, next).ok_or_else(|| SubscriptionError::Cache {
            path: base.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cache path has no file name",
            ),
        })?;
        if let Err(error) = save_private_cache(&path, &bytes) {
            self.pending_cache = Some((base, bytes));
            return Err(error);
        }
        self.committed_slot = Some(next.to_string());
        Ok(self.committed_slot.clone())
    }

    pub fn committed_slot(&self) -> Option<&str> {
        self.committed_slot.as_deref()
    }

    pub fn into_nodes(self) -> Vec<Node> {
        self.nodes
    }
}

/// Fetch and parse one profile without changing its cache. This is a blocking
/// operation (filesystem plus an external fetcher); async callers must use
/// `spawn_blocking` so the Tokio runtime remains responsive.
pub fn prepare_profile(profile: &SubscriptionProfileConfig) -> anyhow::Result<PreparedProfile> {
    if !profile.files.is_empty() {
        let nodes = load_all(&profile.files);
        anyhow::ensure!(
            !nodes.is_empty(),
            "no nodes parsed from local subscription profile"
        );
        return Ok(PreparedProfile {
            nodes,
            pending_cache: None,
            committed_slot: None,
        });
    }

    #[cfg(test)]
    let curl_bin = profile
        .url_file
        .as_deref()
        .and_then(test_curl_override)
        .unwrap_or_else(|| PathBuf::from("curl"));
    #[cfg(not(test))]
    let curl_bin = PathBuf::from("curl");
    prepare_remote_profile_with(profile, &curl_bin)
}

/// Per-URL fetcher injection for full supervisor transaction tests. Matching
/// by the test's unique URL-file path avoids process-wide PATH mutation and
/// prevents unrelated parallel tests from observing the override.
#[cfg(test)]
static TEST_CURL_OVERRIDES: OnceLock<Mutex<std::collections::HashMap<PathBuf, PathBuf>>> =
    OnceLock::new();

#[cfg(test)]
pub(crate) struct TestCurlOverride {
    url_file: PathBuf,
}

#[cfg(test)]
impl TestCurlOverride {
    pub(crate) fn install(url_file: PathBuf, curl_bin: PathBuf) -> Self {
        let mut overrides = TEST_CURL_OVERRIDES
            .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(
            overrides.insert(url_file.clone(), curl_bin).is_none(),
            "test curl override already installed for {}",
            url_file.display()
        );
        Self { url_file }
    }
}

#[cfg(test)]
impl Drop for TestCurlOverride {
    fn drop(&mut self) {
        if let Some(overrides) = TEST_CURL_OVERRIDES.get() {
            overrides
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&self.url_file);
        }
    }
}

#[cfg(test)]
fn test_curl_override(url_file: &Path) -> Option<PathBuf> {
    TEST_CURL_OVERRIDES
        .get()?
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(url_file)
        .cloned()
}

fn prepare_remote_profile_with(
    profile: &SubscriptionProfileConfig,
    curl_bin: &Path,
) -> anyhow::Result<PreparedProfile> {
    let url_file = profile
        .url_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("remote subscription profile has no url_file"))?;
    let cache_file = profile
        .cache_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("remote subscription profile has no cache_file"))?;
    let body = fetch_remote_manifest_with(curl_bin, url_file)?;
    // serde-yaml diagnostics can include fragments of malformed input. Do not
    // let a provider response (which may contain endpoint credentials) flow
    // into the daemon's logs or event ring.
    let nodes = parse_remote_str(&body).map_err(|_| SubscriptionError::RemoteYaml)?;
    anyhow::ensure!(
        !nodes.is_empty(),
        "remote subscription contained no supported nodes"
    );
    anyhow::ensure!(
        nodes.len() <= MAX_PROFILE_NODES,
        "remote subscription exceeded the supported node-count limit"
    );
    Ok(PreparedProfile {
        nodes,
        pending_cache: Some((cache_file.clone(), body.into_bytes())),
        committed_slot: None,
    })
}

fn fetch_remote_manifest_with(
    curl_bin: &Path,
    url_file: &Path,
) -> Result<String, SubscriptionError> {
    validate_secret_file(url_file)?;
    let secret_len = std::fs::metadata(url_file)
        .map_err(|source| SubscriptionError::Io {
            path: url_file.to_path_buf(),
            source,
        })?
        .len();
    if secret_len > MAX_SUBSCRIPTION_URL_BYTES {
        return Err(SubscriptionError::InvalidUrlFile {
            path: url_file.to_path_buf(),
        });
    }
    let raw = std::fs::read_to_string(url_file).map_err(|source| SubscriptionError::Io {
        path: url_file.to_path_buf(),
        source,
    })?;
    let url = raw.trim();
    if !url.starts_with("https://")
        || url.len() <= "https://".len()
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(SubscriptionError::InvalidUrlFile {
            path: url_file.to_path_buf(),
        });
    }

    // `--config -` keeps the credential-bearing URL out of argv and process
    // listings. Proxy variables are removed and `--noproxy *` is explicit:
    // fetching a replacement subscription through the currently broken
    // subscription would make recovery circular.
    let child = Command::new(curl_bin)
        .arg("--disable")
        .arg("--config")
        .arg("-")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail")
        .arg("--location")
        .arg("--globoff")
        .arg("--proto")
        .arg("=https")
        .arg("--proto-redir")
        .arg("=https")
        .arg("--connect-timeout")
        .arg("15")
        .arg("--max-time")
        .arg("60")
        .arg("--noproxy")
        .arg("*")
        .arg("--proxy")
        .arg("")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .env_remove("no_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("NO_PROXY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // curl may echo a hostname or URL in diagnostics. The public error is
        // status-only, so provider credentials cannot reach logs or events.
        .stderr(Stdio::null())
        .spawn()
        .map_err(SubscriptionError::FetchStart)?;

    let config = format!("url = \"{}\"\n", escape_curl_config(url));
    communicate_with_fetcher(child, config.as_bytes())
}

/// Own a fetcher from spawn through its final wait. Any early return while
/// the child may still be live kills only this exact `Child` and then reaps
/// it. A successful wait disarms cleanup, so the normal path never sends a
/// signal.
struct OwnedFetcher {
    child: Child,
    reaped: bool,
}

impl OwnedFetcher {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        match self.child.wait() {
            Ok(status) => {
                self.reaped = true;
                Ok(status)
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for OwnedFetcher {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // `kill` can legitimately fail when the process exited between the
        // failed operation and cleanup. `wait` is still required to reap it.
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn communicate_with_fetcher(child: Child, config: &[u8]) -> Result<String, SubscriptionError> {
    communicate_with_fetcher_limit(child, config, MAX_REMOTE_MANIFEST_BYTES)
}

fn communicate_with_fetcher_limit(
    child: Child,
    config: &[u8],
    max_response_bytes: u64,
) -> Result<String, SubscriptionError> {
    let mut fetcher = OwnedFetcher::new(child);
    let mut stdin = fetcher.child.stdin.take().ok_or_else(|| {
        SubscriptionError::FetchIo(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "subscription fetcher stdin was unavailable",
        ))
    })?;
    stdin
        .write_all(config)
        .map_err(SubscriptionError::FetchIo)?;
    // curl must see EOF before we wait for its response.
    drop(stdin);

    let mut stdout = fetcher.child.stdout.take().ok_or_else(|| {
        SubscriptionError::FetchIo(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "subscription fetcher stdout was unavailable",
        ))
    })?;
    let mut bytes = Vec::new();
    stdout
        .by_ref()
        .take(max_response_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(SubscriptionError::FetchIo)?;
    if bytes.len() as u64 > max_response_bytes {
        return Err(SubscriptionError::TooLarge {
            limit: max_response_bytes,
        });
    }
    let status = fetcher.wait().map_err(SubscriptionError::FetchIo)?;
    if !status.success() {
        return Err(SubscriptionError::FetchFailed {
            detail: status.to_string(),
        });
    }
    String::from_utf8(bytes).map_err(|_| SubscriptionError::FetchFailed {
        detail: "response was not UTF-8".to_string(),
    })
}

fn escape_curl_config(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn save_private_cache(path: &Path, bytes: &[u8]) -> Result<(), SubscriptionError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| SubscriptionError::Cache {
        path: parent.to_path_buf(),
        source,
    })?;
    let seq = CACHE_TMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".causeway-subscription-{}-{seq}.tmp",
        std::process::id()
    ));
    let result = (|| -> Result<(), SubscriptionError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|source| SubscriptionError::Cache {
                path: tmp.clone(),
                source,
            })?;
        file.write_all(bytes)
            .map_err(|source| SubscriptionError::Cache {
                path: tmp.clone(),
                source,
            })?;
        file.sync_all().map_err(|source| SubscriptionError::Cache {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, path).map_err(|source| SubscriptionError::Cache {
            path: path.to_path_buf(),
            source,
        })?;
        sync_parent_dir(parent).map_err(|source| SubscriptionError::Cache {
            path: parent.to_path_buf(),
            source,
        })?;
        Ok(())
    })();
    if result.is_err() {
        std::fs::remove_file(&tmp).ok();
    }
    result
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> std::io::Result<()> {
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

fn validate_secret_file(path: &Path) -> Result<(), SubscriptionError> {
    let metadata = std::fs::metadata(path).map_err(|source| SubscriptionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(SubscriptionError::InvalidUrlFile {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SubscriptionError::InvalidUrlFile {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        for _ in 0..100 {
            let seq = CACHE_TMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "causeway-subscription-test-{}-{seq}-{label}",
                std::process::id()
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => return dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("failed to create test directory {}: {error}", dir.display()),
            }
        }
        panic!("failed to allocate a unique subscription test directory");
    }

    fn one_node_manifest(name: &str) -> String {
        format!(
            r#"
proxies:
  - name: {name:?}
    type: ss
    server: 203.0.113.40
    port: 8388
    cipher: aes-256-gcm
    password: fixture-password
"#
        )
    }

    fn as_ss(node: &Node) -> &SsNode {
        match node {
            Node::Ss(n) => n,
            other => panic!("expected ss node, got {}", other.kind()),
        }
    }

    fn as_anytls(node: &Node) -> &AnytlsNode {
        match node {
            Node::Anytls(n) => n,
            other => panic!("expected anytls node, got {}", other.kind()),
        }
    }

    /// Hand-built fixture covering: ss (with numeric password, string port),
    /// anytls (with all optional fields), trojan (must be dropped), an ss and
    /// an anytls entry missing fields (both must be skipped), a duplicate
    /// name across protocols (must be deduplicated), and other top-level keys
    /// (must be ignored). All addresses are documentation placeholders
    /// (RFC 5737); real node data never enters the repo.
    const FIXTURE: &str = r#"
mixed-port: 7890
proxies:
  - name: "Node A"
    type: ss
    server: 203.0.113.10
    port: 8388
    cipher: aes-256-gcm
    password: "pass-a"
  - name: "Node B (numeric password)"
    type: ss
    server: 203.0.113.11
    port: "8389"
    cipher: chacha20-ietf-poly1305
    password: 12345678
  - name: "Node C"
    type: anytls
    server: anytls.example.com
    port: 443
    password: "pass-c"
    sni: "cdn.example.com"
    client-fingerprint: chrome
    alpn: ["h2", "http/1.1"]
    skip-cert-verify: true
    udp: true
  - name: "Trojan dropped"
    type: trojan
    server: 198.51.100.6
    port: 443
    password: x
  - name: "Broken SS missing cipher"
    type: ss
    server: 203.0.113.12
    port: 8388
    password: y
  - name: "Broken AnyTLS missing password"
    type: anytls
    server: 198.51.100.7
    port: 443
  - name: "Node A"
    type: anytls
    server: 198.51.100.99
    port: 443
    password: "dup"
proxy-groups:
  - name: PROXY
    type: select
rules:
  - MATCH,PROXY
"#;

    #[test]
    fn parses_ss_and_anytls_entries() {
        let nodes = parse_str(FIXTURE).unwrap();
        assert_eq!(
            nodes.len(),
            3,
            "2 valid ss + 1 valid anytls, non-duplicate nodes"
        );
        let a = as_ss(&nodes[0]);
        assert_eq!(a.name, "Node A");
        assert_eq!(a.server, "203.0.113.10");
        assert_eq!(a.port, 8388);
        assert_eq!(a.cipher, "aes-256-gcm");
        assert_eq!(a.password, "pass-a");
    }

    #[test]
    fn numeric_password_and_string_port_coerced() {
        let nodes = parse_str(FIXTURE).unwrap();
        let b = as_ss(&nodes[1]);
        assert_eq!(
            b.password, "12345678",
            "numeric password preserved as string"
        );
        assert_eq!(b.port, 8389, "quoted port parsed as number");
    }

    #[test]
    fn anytls_optional_fields_parsed() {
        let nodes = parse_str(FIXTURE).unwrap();
        let c = as_anytls(&nodes[2]);
        assert_eq!(c.name, "Node C");
        assert_eq!(c.server, "anytls.example.com");
        assert_eq!(c.port, 443);
        assert_eq!(c.password, "pass-c");
        assert_eq!(c.sni.as_deref(), Some("cdn.example.com"));
        assert_eq!(c.client_fingerprint.as_deref(), Some("chrome"));
        assert_eq!(
            c.alpn.as_deref(),
            Some(&["h2".to_string(), "http/1.1".to_string()][..])
        );
        assert!(c.skip_cert_verify);
    }

    #[test]
    fn anytls_minimal_entry_gets_defaults() {
        let text = r#"
proxies:
  - name: "Minimal AnyTLS"
    type: anytls
    server: 198.51.100.20
    port: 8443
    password: 987654321
"#;
        let nodes = parse_str(text).unwrap();
        assert_eq!(nodes.len(), 1);
        let n = as_anytls(&nodes[0]);
        assert_eq!(
            n.password, "987654321",
            "numeric password preserved as string"
        );
        assert!(n.sni.is_none());
        assert!(n.alpn.is_none());
        assert!(n.client_fingerprint.is_none());
        assert!(!n.skip_cert_verify);
    }

    #[test]
    fn unsupported_and_broken_entries_dropped() {
        let nodes = parse_str(FIXTURE).unwrap();
        assert!(nodes.iter().all(|n| !n.name().contains("dropped")));
        assert!(nodes.iter().all(|n| !n.name().contains("Broken")));
        // For duplicate "Node A" the first one wins, across protocols too
        assert_eq!(nodes.iter().filter(|n| n.name() == "Node A").count(), 1);
        assert_eq!(nodes[0].server(), "203.0.113.10");
    }

    #[test]
    fn empty_or_missing_proxies_is_ok() {
        assert!(parse_str("rules:\n  - MATCH,DIRECT\n").unwrap().is_empty());
        assert!(parse_str("proxies: []\n").unwrap().is_empty());
    }

    #[test]
    fn garbage_yaml_errors() {
        assert!(parse_str("proxies: [ {unclosed").is_err());
    }

    /// Plugin fixture: obfs plugin, no plugin (backward compatible), unknown
    /// plugin type (skipped), obfs missing plugin-opts (skipped). The obfs
    /// host uses a documentation placeholder domain; real node data never
    /// enters the repo.
    const FIXTURE_PLUGINS: &str = r#"
proxies:
  - name: "Obfs Node"
    type: ss
    server: 203.0.113.20
    port: 12022
    cipher: aes-128-gcm
    password: "pass-obfs"
    plugin: obfs
    plugin-opts: {mode: http, host: cdn.example.com}
    udp: true
  - name: "Plain Node"
    type: ss
    server: 203.0.113.21
    port: 8388
    cipher: aes-256-gcm
    password: "pass-plain"
  - name: "Unknown Plugin Node"
    type: ss
    server: 203.0.113.22
    port: 8388
    cipher: aes-256-gcm
    password: "pass-x"
    plugin: v2ray-plugin
    plugin-opts: {mode: websocket}
  - name: "Obfs Missing Opts"
    type: ss
    server: 203.0.113.23
    port: 8388
    cipher: aes-256-gcm
    password: "pass-y"
    plugin: obfs
"#;

    #[test]
    fn obfs_plugin_parsed_into_node() {
        let nodes = parse_str(FIXTURE_PLUGINS).unwrap();
        assert_eq!(
            nodes.len(),
            2,
            "unknown plugin types and obfs entries missing opts must be skipped"
        );
        let obfs_node = as_ss(&nodes[0]);
        assert_eq!(obfs_node.name, "Obfs Node");
        let plugin = obfs_node
            .plugin
            .as_ref()
            .expect("plugin parameters should be parsed");
        assert_eq!(plugin.mode, "http");
        assert_eq!(plugin.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(
            plugin.to_plugin_opts(),
            "obfs=http;obfs-host=cdn.example.com",
            "sslocal plugin_opts string format"
        );
    }

    #[test]
    fn plain_node_has_no_plugin() {
        let nodes = parse_str(FIXTURE_PLUGINS).unwrap();
        assert!(
            as_ss(&nodes[1]).plugin.is_none(),
            "plugin-free nodes stay backward compatible"
        );
    }

    #[test]
    fn unknown_plugin_type_skipped_not_bare() {
        let nodes = parse_str(FIXTURE_PLUGINS).unwrap();
        assert!(
            nodes.iter().all(|n| n.name() != "Unknown Plugin Node"),
            "unknown plugin types must be skipped explicitly, never silently connected plain"
        );
    }

    #[test]
    fn plugin_opts_string_without_host() {
        let opts = ObfsOpts {
            mode: "tls".to_string(),
            host: None,
        };
        assert_eq!(opts.to_plugin_opts(), "obfs=tls");
    }

    #[test]
    fn local_profile_loads_only_its_own_files() {
        let dir = temp_dir("local-profile");
        let a = dir.join("a.yaml");
        let b = dir.join("b.yaml");
        let outside = dir.join("outside.yaml");
        std::fs::write(&a, one_node_manifest("A")).unwrap();
        std::fs::write(&b, one_node_manifest("B")).unwrap();
        std::fs::write(&outside, one_node_manifest("Outside")).unwrap();
        let profile = SubscriptionProfileConfig {
            files: vec![a, b],
            url_file: None,
            cache_file: None,
        };
        let names: Vec<_> = load_profile_snapshot(&profile)
            .into_iter()
            .map(|n| n.name().to_string())
            .collect();
        assert_eq!(names, ["A", "B"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    fn write_private(path: &Path, text: &str) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    fn fake_fetcher(dir: &Path, body: &str, exit_code: u8) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let seq = CACHE_TMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("fake-curl-{seq}"));
        let script = format!(
            "#!/bin/sh\nscript_dir=$(dirname \"$0\")\nprintf '%s\\n' \"$@\" > \"$script_dir/args.txt\"\ncat > \"$script_dir/stdin.txt\"\nprintf '%s' '{}'\nexit {}\n",
            body.replace('\\', "\\\\").replace('\'', "'\\''"),
            exit_code
        );
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(target_os = "linux")]
    fn spawn_fetcher_script(script: &str) -> Child {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn wait_for_file(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("timed out waiting for test fetcher readiness");
    }

    #[cfg(target_os = "linux")]
    fn assert_child_reaped(pid: u32) {
        assert!(
            !Path::new("/proc").join(pid.to_string()).exists(),
            "owned fetcher {pid} must be waited and reaped"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fetcher_broken_stdin_is_killed_and_reaped() {
        let dir = temp_dir("fetcher-broken-stdin");
        let ready = dir.join("ready");
        let script = format!(
            "exec 0<&-; : > '{}'; exec sleep 30",
            ready.display().to_string().replace('\'', "'\\''")
        );
        let child = spawn_fetcher_script(&script);
        let pid = child.id();
        wait_for_file(&ready);

        let error = communicate_with_fetcher(child, &vec![b'x'; 1024 * 1024]).unwrap_err();

        assert!(matches!(error, SubscriptionError::FetchIo(_)));
        assert_child_reaped(pid);
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_fetcher_response_is_killed_and_reaped() {
        let child = spawn_fetcher_script(
            "IFS= read -r ignored; printf 'response-larger-than-limit'; exec sleep 30",
        );
        let pid = child.id();

        let error = communicate_with_fetcher_limit(child, b"config\n", 8).unwrap_err();

        assert!(matches!(error, SubscriptionError::TooLarge { limit: 8 }));
        assert_child_reaped(pid);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_fetcher_is_waited_and_reaped_without_cleanup_kill() {
        let child = spawn_fetcher_script("IFS= read -r ignored; printf 'fixture-response'");
        let pid = child.id();

        let response = communicate_with_fetcher_limit(child, b"config\n", 64).unwrap();

        assert_eq!(response, "fixture-response");
        assert_child_reaped(pid);
    }

    #[cfg(unix)]
    #[test]
    fn remote_prepare_keeps_secret_out_of_argv_and_commits_private_cache() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("remote-success");
        let url_file = dir.join("remote.url");
        let cache_file = dir.join("cache.yaml");
        let arg_log = dir.join("args.txt");
        let stdin_log = dir.join("stdin.txt");
        let secret = "https://subscription.example/fixture?credential=secret-marker";
        write_private(&url_file, secret);
        let fetcher = fake_fetcher(&dir, &one_node_manifest("Remote"), 0);
        let profile = SubscriptionProfileConfig {
            files: Vec::new(),
            url_file: Some(url_file),
            cache_file: Some(cache_file.clone()),
        };

        let mut prepared = prepare_remote_profile_with(&profile, &fetcher).unwrap();

        assert_eq!(prepared.nodes()[0].name(), "Remote");
        assert!(!std::fs::read_to_string(&arg_log).unwrap().contains(secret));
        assert!(std::fs::read_to_string(&stdin_log)
            .unwrap()
            .contains(secret));
        assert!(
            !cache_file.exists(),
            "prepare must not commit the cache early"
        );
        assert_eq!(
            prepared.commit_cache_slot(None).unwrap().as_deref(),
            Some(CACHE_SLOT_A)
        );
        let slot_path = cache_slot_path(&cache_file, CACHE_SLOT_A).unwrap();
        assert_eq!(
            std::fs::metadata(&slot_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_profile_snapshot_from_slot(&profile, Some(CACHE_SLOT_A))[0].name(),
            "Remote"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn cache_slots_alternate_and_only_the_confirmed_slot_is_loaded() {
        let dir = temp_dir("remote-slots");
        let url_file = dir.join("remote.url");
        let cache_file = dir.join("cache.yaml");
        write_private(&url_file, "https://subscription.example/fixture");
        let profile = SubscriptionProfileConfig {
            files: Vec::new(),
            url_file: Some(url_file),
            cache_file: Some(cache_file.clone()),
        };

        let fetch_a = fake_fetcher(&dir, &one_node_manifest("Generation A"), 0);
        let mut first = prepare_remote_profile_with(&profile, &fetch_a).unwrap();
        assert_eq!(
            first.commit_cache_slot(None).unwrap().as_deref(),
            Some(CACHE_SLOT_A)
        );

        // Replace the helper so a second preparation stages a different body.
        std::fs::remove_file(&fetch_a).unwrap();
        let fetch_b = fake_fetcher(&dir, &one_node_manifest("Generation B"), 0);
        let mut second = prepare_remote_profile_with(&profile, &fetch_b).unwrap();
        assert_eq!(
            second
                .commit_cache_slot(Some(CACHE_SLOT_A))
                .unwrap()
                .as_deref(),
            Some(CACHE_SLOT_B)
        );

        assert_eq!(
            load_profile_snapshot_from_slot(&profile, Some(CACHE_SLOT_A))[0].name(),
            "Generation A",
            "an unconfirmed newer slot must be ignored after a crash"
        );
        assert_eq!(
            load_profile_snapshot_from_slot(&profile, Some(CACHE_SLOT_B))[0].name(),
            "Generation B"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn invalid_confirmed_slot_never_falls_back_to_an_unconfirmed_cache() {
        let dir = temp_dir("invalid-slot");
        let base = dir.join("cache.yaml");
        std::fs::write(&base, one_node_manifest("Legacy")).unwrap();
        let profile = SubscriptionProfileConfig {
            files: Vec::new(),
            url_file: Some(dir.join("remote.url")),
            cache_file: Some(base),
        };
        assert!(load_profile_snapshot_from_slot(&profile, Some("invalid")).is_empty());
        assert_eq!(
            load_profile_snapshot_from_slot(&profile, None)[0].name(),
            "Legacy"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn failed_remote_prepare_preserves_last_known_good_cache_and_redacts_secret() {
        let dir = temp_dir("remote-failure");
        let url_file = dir.join("remote.url");
        let cache_file = dir.join("cache.yaml");
        let arg_log = dir.join("args.txt");
        let secret = "https://subscription.example/fixture?credential=never-report-this";
        write_private(&url_file, secret);
        write_private(&cache_file, &one_node_manifest("Last Good"));
        let before = std::fs::read(&cache_file).unwrap();
        let fetcher = fake_fetcher(&dir, "not: [valid", 0);
        let profile = SubscriptionProfileConfig {
            files: Vec::new(),
            url_file: Some(url_file),
            cache_file: Some(cache_file.clone()),
        };

        let error = match prepare_remote_profile_with(&profile, &fetcher) {
            Ok(_) => panic!("malformed remote manifest should fail preparation"),
            Err(error) => error,
        };

        assert!(!format!("{error:#}").contains(secret));
        assert!(!std::fs::read_to_string(&arg_log).unwrap().contains(secret));
        assert_eq!(std::fs::read(&cache_file).unwrap(), before);
        assert_eq!(load_profile_snapshot(&profile)[0].name(), "Last Good");
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn dropping_prepared_remote_profile_rolls_back_cache() {
        let dir = temp_dir("remote-staged-rollback");
        let url_file = dir.join("remote.url");
        let cache_file = dir.join("cache.yaml");
        write_private(&url_file, "https://subscription.example/fixture");
        write_private(&cache_file, &one_node_manifest("Last Good"));
        let before = std::fs::read(&cache_file).unwrap();
        let fetcher = fake_fetcher(&dir, &one_node_manifest("Candidate"), 0);
        let profile = SubscriptionProfileConfig {
            files: Vec::new(),
            url_file: Some(url_file),
            cache_file: Some(cache_file.clone()),
        };

        let prepared = prepare_remote_profile_with(&profile, &fetcher).unwrap();
        assert_eq!(prepared.nodes()[0].name(), "Candidate");
        drop(prepared); // simulates a later data-plane pre-check failure

        assert_eq!(std::fs::read(&cache_file).unwrap(), before);
        assert_eq!(load_profile_snapshot(&profile)[0].name(), "Last Good");
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn non_https_or_public_url_file_is_rejected_without_spawning_fetcher() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("remote-invalid-url");
        let url_file = dir.join("remote.url");
        let fetcher = dir.join("does-not-exist");
        write_private(&url_file, "http://subscription.example/not-secure");
        let error = fetch_remote_manifest_with(&fetcher, &url_file).unwrap_err();
        assert!(matches!(error, SubscriptionError::InvalidUrlFile { .. }));

        write_private(&url_file, "https://subscription.example/fixture");
        std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = fetch_remote_manifest_with(&fetcher, &url_file).unwrap_err();
        assert!(matches!(error, SubscriptionError::InvalidUrlFile { .. }));
        std::fs::remove_dir_all(dir).ok();
    }
}
