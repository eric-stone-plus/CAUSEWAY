//! Data-plane abstraction: everything behind "make a node reachable on local
//! ports".
//!
//! Two supervised subprocess adapters ship today — `SslocalPlane` for ss
//! nodes and `SingboxPlane` for anytls nodes — dispatched by node variant
//! (`DispatchPlane`). Both follow the same contract: one process per active
//! node, a generated config, identical readiness semantics. An in-process
//! implementation can still be added as one more `impl DataPlane`; the
//! listener, scoring, and routing stay untouched.
//!
//! Port layout note (a deliberate deviation from the original idea, recorded
//! explicitly): a single adapter instance can speak either socks or http,
//! never mixed. Therefore each active node runs **one adapter process with
//! two locals** (two adjacent ports): the CAUSEWAY listener pipes HTTP
//! traffic to the http port and SOCKS5 traffic to the socks port based on its
//! first-byte classification. Clients still see a single stable entry point;
//! upstream it remains byte-for-byte L4 passthrough.

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use async_trait::async_trait;
use tokio::process::{Child, Command};
use tracing::{debug, info};

use crate::subscription::{AnytlsNode, Node, SsNode};

const ADAPTERS_DIR_NAME: &str = "adapters";
const INSTANCE_PREFIX: &str = "causeway-instance-v1-";
const IDENTITY_FILE_NAME: &str = "identity-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessIdentity {
    boot_id: String,
    pid: u32,
    start_time: u64,
}

impl ProcessIdentity {
    #[cfg(target_os = "linux")]
    fn current() -> anyhow::Result<Self> {
        let pid = std::process::id();
        Ok(Self {
            boot_id: read_boot_id()?,
            pid,
            start_time: read_process_start_time(pid)?.context("current process disappeared")?,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn current() -> anyhow::Result<Self> {
        bail!("secure adapter workspace identity currently requires Linux /proc")
    }

    fn encode(&self) -> String {
        format!(
            "schema=1\nboot_id={}\npid={}\nstart_time={}\n",
            self.boot_id, self.pid, self.start_time
        )
    }

    fn parse(value: &str) -> Option<Self> {
        let mut lines = value.lines();
        if lines.next()? != "schema=1" {
            return None;
        }
        let boot_id = lines.next()?.strip_prefix("boot_id=")?.to_string();
        let pid = lines.next()?.strip_prefix("pid=")?.parse().ok()?;
        let start_time = lines.next()?.strip_prefix("start_time=")?.parse().ok()?;
        if lines.next().is_some() || !valid_boot_id(&boot_id) {
            return None;
        }
        let identity = Self {
            boot_id,
            pid,
            start_time,
        };
        (value == identity.encode()).then_some(identity)
    }
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

#[cfg(target_os = "linux")]
fn read_boot_id() -> anyhow::Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read kernel boot identity")?;
    let value = value.trim().to_ascii_lowercase();
    if !valid_boot_id(&value) {
        bail!("kernel boot identity has an unexpected format");
    }
    Ok(value)
}

#[cfg(not(target_os = "linux"))]
fn read_boot_id() -> anyhow::Result<String> {
    bail!("secure adapter workspace identity currently requires Linux /proc")
}

#[cfg(target_os = "linux")]
fn parse_process_start_time(stat: &str) -> Option<u64> {
    // The comm field may contain spaces and ')' characters. Splitting after
    // the final ')' leaves field 3 first; starttime is field 22, index 19.
    let after_comm = stat.rsplit_once(')')?.1.trim_start();
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "linux")]
fn read_process_start_time(pid: u32) -> anyhow::Result<Option<u64>> {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => parse_process_start_time(&value)
            .map(Some)
            .context("parse process start time"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("read process identity from /proc"),
    }
}

#[cfg(not(target_os = "linux"))]
fn read_process_start_time(_pid: u32) -> anyhow::Result<Option<u64>> {
    bail!("secure adapter workspace identity currently requires Linux /proc")
}

fn fill_kernel_random(bytes: &mut [u8]) -> anyhow::Result<()> {
    use std::io::Read;
    let mut source = std::fs::File::open("/dev/urandom").context("open kernel random source")?;
    source
        .read_exact(bytes)
        .context("read kernel random source")
}

fn strict_instance_name(identity: &ProcessIdentity, nonce_hex: &str) -> String {
    format!(
        "{INSTANCE_PREFIX}{}-{}-{}-{nonce_hex}",
        identity.boot_id, identity.pid, identity.start_time
    )
}

fn identity_from_instance_name(name: &str) -> Option<ProcessIdentity> {
    let rest = name.strip_prefix(INSTANCE_PREFIX)?;
    // UUID includes hyphens, so validate fixed slices rather than split it.
    let boot_id = rest.get(..36)?;
    if !valid_boot_id(boot_id) {
        return None;
    }
    let mut fields = rest.get(36..)?.strip_prefix('-')?.split('-');
    let pid_text = fields.next()?;
    let pid: u32 = pid_text.parse().ok()?;
    if pid.to_string() != pid_text {
        return None;
    }
    let start_time_text = fields.next()?;
    let start_time: u64 = start_time_text.parse().ok()?;
    if start_time.to_string() != start_time_text {
        return None;
    }
    let nonce = fields.next()?;
    if fields.next().is_some()
        || nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(ProcessIdentity {
        boot_id: boot_id.to_string(),
        pid,
        start_time,
    })
}

/// Adapter traffic must leave directly. Inheriting proxy variables from a
/// login shell or a future systemd manager environment could otherwise point
/// an adapter back at CAUSEWAY and create a proxy loop.
const PROXY_ENV_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

fn apply_direct_network_env(command: &mut Command) -> &mut Command {
    for name in PROXY_ENV_VARS {
        command.env_remove(name);
    }
    command
}

/// Per-daemon credential namespace. Only directories created under the new
/// `run/adapters/` namespace are ever considered for stale cleanup; legacy
/// credential JSON files directly under `run/` are intentionally invisible.
#[derive(Debug)]
pub struct AdapterWorkspace {
    instance_dir: PathBuf,
    identity_path: PathBuf,
    cleaned: AtomicBool,
}

impl AdapterWorkspace {
    pub fn create(run_dir: &Path) -> anyhow::Result<Arc<Self>> {
        let adapters_dir = run_dir.join(ADAPTERS_DIR_NAME);
        create_private_dir(run_dir)?;
        create_private_dir(&adapters_dir)?;
        cleanup_stale_instances(&adapters_dir)?;

        let identity = ProcessIdentity::current()?;
        const ATTEMPTS: usize = 32;
        for _ in 0..ATTEMPTS {
            let mut nonce = [0u8; 16];
            fill_kernel_random(&mut nonce)?;
            let nonce_hex: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            let instance_dir = adapters_dir.join(strict_instance_name(&identity, &nonce_hex));
            match std::fs::create_dir(&instance_dir) {
                Ok(()) => {
                    if let Err(error) = secure_private_dir(&instance_dir) {
                        std::fs::remove_dir(&instance_dir).ok();
                        return Err(error);
                    }
                    let identity_path = instance_dir.join(IDENTITY_FILE_NAME);
                    if let Err(error) =
                        write_new_private_file(&identity_path, identity.encode().as_bytes())
                    {
                        std::fs::remove_file(&identity_path).ok();
                        std::fs::remove_dir(&instance_dir).ok();
                        return Err(error);
                    }
                    return Ok(Arc::new(Self {
                        instance_dir,
                        identity_path,
                        cleaned: AtomicBool::new(false),
                    }));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("create adapter instance in {}", adapters_dir.display())
                    });
                }
            }
        }
        bail!("could not allocate a unique adapter instance directory")
    }

    fn path(&self) -> &Path {
        &self.instance_dir
    }

    /// Called only after every owned adapter handle has been explicitly
    /// stopped. Remove only strictly named regular files in this known
    /// instance, then the directory; unexpected entries are preserved.
    pub fn cleanup(&self) -> anyhow::Result<()> {
        if self.cleaned.load(Ordering::Acquire) {
            return Ok(());
        }
        let metadata = match std::fs::symlink_metadata(&self.instance_dir) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.cleaned.store(true, Ordering::Release);
                return Ok(());
            }
            Err(error) => return Err(error).context("inspect owned adapter workspace"),
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            bail!("owned adapter workspace is no longer a real directory");
        }
        let mut removable_files = Vec::new();
        for entry in std::fs::read_dir(&self.instance_dir)
            .with_context(|| format!("inspect adapter instance {}", self.instance_dir.display()))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                bail!("adapter instance has a non-UTF-8 entry; preserving it")
            };
            if name != IDENTITY_FILE_NAME && !strict_credential_name(name) {
                bail!("adapter instance has unexpected contents; preserving it")
            }
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!("adapter instance has a non-regular entry; preserving it")
            }
            removable_files.push(entry.path());
        }
        if !removable_files
            .iter()
            .any(|path| path == &self.identity_path)
        {
            bail!("adapter identity marker disappeared; preserving workspace")
        }
        for file in removable_files {
            std::fs::remove_file(&file)
                .with_context(|| format!("remove owned adapter file {}", file.display()))?;
        }
        match std::fs::remove_dir(&self.instance_dir) {
            Ok(()) => {
                self.cleaned.store(true, Ordering::Release);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.cleaned.store(true, Ordering::Release);
                Ok(())
            }
            Err(error) => Err(error).with_context(|| {
                format!(
                    "remove empty adapter instance directory {} (unexpected contents were preserved)",
                    self.instance_dir.display()
                )
            }),
        }
    }
}

impl Drop for AdapterWorkspace {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::warn!(error = %format!("{error:#}"), "adapter workspace was preserved during drop");
        }
    }
}

fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("create private directory {}", path.display()))?;
    secure_private_dir(path)
}

fn secure_private_dir(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect private directory {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "private workspace path is not a real directory: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("secure private directory {}", path.display()))?;
    }
    Ok(())
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create private file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write private file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync private file {}", path.display()))?;
    Ok(())
}

fn cleanup_stale_instances(adapters_dir: &Path) -> anyhow::Result<()> {
    let current_boot = read_boot_id()?;
    for entry in std::fs::read_dir(adapters_dir)
        .with_context(|| format!("list adapter workspace {}", adapters_dir.display()))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, "could not inspect an adapter workspace entry; preserving it");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(named_identity) = identity_from_instance_name(name) else {
            continue;
        };
        let path = entry.path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let marker_path = path.join(IDENTITY_FILE_NAME);
        let marker_meta = match std::fs::symlink_metadata(&marker_path) {
            Ok(metadata)
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() =>
            {
                metadata
            }
            _ => continue,
        };
        if marker_meta.len() > 512 {
            continue;
        }
        let marker = match std::fs::read_to_string(&marker_path)
            .ok()
            .and_then(|value| ProcessIdentity::parse(&value))
        {
            Some(marker) if marker == named_identity => marker,
            _ => continue,
        };

        let definitely_dead = if marker.boot_id != current_boot {
            true
        } else {
            match read_process_start_time(marker.pid) {
                Ok(None) => true,
                Ok(Some(start_time)) => start_time != marker.start_time,
                Err(_) => false,
            }
        };
        if definitely_dead {
            if let Err(error) = remove_strict_stale_instance(&path, &marker_path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %format!("{error:#}"),
                    "could not safely remove stale adapter instance; preserving remainder"
                );
            }
        }
    }
    Ok(())
}

/// A validated stale instance may contain only our marker and credential JSON
/// regular files. Anything else (directory, symlink, device, unexpected name)
/// makes cleanup fail-safe and preserves the whole instance.
fn remove_strict_stale_instance(path: &Path, marker_path: &Path) -> anyhow::Result<()> {
    let mut credential_files = Vec::new();
    let mut saw_marker = false;
    for entry in std::fs::read_dir(path)
        .with_context(|| format!("inspect stale adapter instance {}", path.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Ok(());
        };
        let metadata = std::fs::symlink_metadata(entry.path())?;
        let credential_name = strict_credential_name(name);
        if name == IDENTITY_FILE_NAME {
            saw_marker = true;
        } else if !credential_name {
            return Ok(());
        }
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Ok(());
        }
        if credential_name {
            credential_files.push(entry.path());
        }
    }
    if !saw_marker {
        return Ok(());
    }
    // Re-check the marker immediately before deletion; never follow links.
    if !matches!(
        std::fs::symlink_metadata(marker_path),
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink()
    ) {
        return Ok(());
    }
    for file in credential_files {
        std::fs::remove_file(&file)
            .with_context(|| format!("remove stale credential {}", file.display()))?;
    }
    std::fs::remove_file(marker_path)
        .with_context(|| format!("remove stale identity {}", marker_path.display()))?;
    std::fs::remove_dir(path)
        .with_context(|| format!("remove stale adapter instance {}", path.display()))
}

fn strict_credential_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    let Some(rest) = stem
        .strip_prefix("sslocal-")
        .or_else(|| stem.strip_prefix("singbox-"))
    else {
        return false;
    };
    let Some((pid, sequence)) = rest.split_once('-') else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && pid.parse::<u32>().is_ok()
        && pid
            .parse::<u32>()
            .is_ok_and(|value| value.to_string() == pid)
        && sequence.len() == 16
        && sequence
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Start parameters plus ownership of both reserved loopback ports.
///
/// The reservation closes the old "ask for a free port twice" race (including
/// accidentally selecting the same port). External adapters do not support
/// socket activation, so [`DataPlane::start`] releases the two sockets only
/// immediately before spawning the adapter. There is necessarily a tiny
/// release-to-bind window; readiness therefore also verifies, on Linux, that
/// the listening sockets appear in the spawned child's descriptor table.
#[derive(Debug)]
pub struct StartSpec {
    pub node: Node,
    ports: LoopbackPortPair,
}

impl StartSpec {
    /// Reserve two distinct IPv4 loopback ports and retain both sockets until
    /// the adapter config is complete and the child is ready to be spawned.
    pub fn reserve(node: Node) -> anyhow::Result<Self> {
        Ok(Self {
            node,
            ports: LoopbackPortPair::reserve()?,
        })
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.ports.socks_addr
    }

    pub fn http_addr(&self) -> SocketAddr {
        self.ports.http_addr
    }

    fn into_parts(self) -> (Node, LoopbackPortPair) {
        (self.node, self.ports)
    }
}

#[derive(Debug)]
struct LoopbackPortPair {
    socks: StdTcpListener,
    http: StdTcpListener,
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
}

impl LoopbackPortPair {
    fn reserve() -> anyhow::Result<Self> {
        // Binding port zero while retaining the first listener makes the
        // second allocation distinct by construction. Retry only covers
        // transient local resource pressure; it is deliberately bounded.
        const ATTEMPTS: usize = 8;
        let mut last_error = None;
        for _ in 0..ATTEMPTS {
            let socks = match StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
                Ok(listener) => listener,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let http = match StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
                Ok(listener) => listener,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let socks_addr = socks.local_addr().context("read reserved socks address")?;
            let http_addr = http.local_addr().context("read reserved http address")?;
            if socks_addr != http_addr {
                return Ok(Self {
                    socks,
                    http,
                    socks_addr,
                    http_addr,
                });
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "no distinct ports")
        }))
        .context("reserve two distinct loopback adapter ports")
    }

    fn release(self) -> (SocketAddr, SocketAddr) {
        let Self {
            socks,
            http,
            socks_addr,
            http_addr,
        } = self;
        drop((socks, http));
        (socks_addr, http_addr)
    }
}

#[async_trait]
pub trait DataPlaneHandle: Send {
    fn socks_addr(&self) -> SocketAddr;
    fn http_addr(&self) -> SocketAddr;
    fn describe(&self) -> String;
    /// Stop the data plane (idempotent; an already-exited process counts as
    /// success).
    async fn stop(&mut self) -> anyhow::Result<()>;
}

#[async_trait]
pub trait DataPlane: Send + Sync {
    /// Start and return a handle once ready. "Ready" = both local ports
    /// accept TCP connections; whether the upstream actually works is for the
    /// caller to confirm with a health check (check-before-switch principle).
    async fn start(&self, spec: StartSpec) -> anyhow::Result<Box<dyn DataPlaneHandle>>;

    /// Remove only this daemon's now-empty private credential workspace.
    /// Implementations without an external adapter need no cleanup.
    fn cleanup_workspace(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

static CONFIG_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// An adapter config contains an upstream credential. Its path is allocated
/// with `create_new`, and this guard removes it on every Rust exit path:
/// normal stop, spawn failure, cancelled start future, or handle drop.
#[derive(Debug)]
struct PrivateConfig {
    path: Option<PathBuf>,
}

impl PrivateConfig {
    fn create(work_dir: &Path, adapter: &str, bytes: &[u8]) -> anyhow::Result<Self> {
        std::fs::create_dir_all(work_dir)
            .with_context(|| format!("create data-plane work directory {}", work_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(work_dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| {
                    format!("secure data-plane work directory {}", work_dir.display())
                })?;
        }

        // PID + a process-local sequence is descriptive, while `create_new`
        // is the actual collision guarantee. A bounded retry also tolerates
        // stale files left by a prior crash and PID reuse without truncating
        // any credential file.
        const ATTEMPTS: usize = 256;
        for _ in 0..ATTEMPTS {
            let sequence = CONFIG_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = work_dir.join(format!(
                "{adapter}-{}-{sequence:016x}.json",
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    let guard = Self {
                        path: Some(path.clone()),
                    };
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        file.set_permissions(std::fs::Permissions::from_mode(0o600))
                            .with_context(|| {
                                format!("secure data-plane config {}", path.display())
                            })?;
                    }
                    file.write_all(bytes).with_context(|| {
                        format!("write private data-plane config {}", path.display())
                    })?;
                    file.sync_all().with_context(|| {
                        format!("sync private data-plane config {}", path.display())
                    })?;
                    // Close the writer before an adapter opens the file.
                    drop(file);
                    return Ok(guard);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("create private data-plane config in {}", work_dir.display())
                    });
                }
            }
        }
        bail!(
            "could not allocate a unique private data-plane config in {} after {ATTEMPTS} attempts",
            work_dir.display()
        )
    }

    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("private config path exists until cleanup")
    }

    fn cleanup(&mut self) -> anyhow::Result<()> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        let remove_result = std::fs::remove_file(&path);
        match remove_result {
            Ok(()) => {
                self.path = None;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.path = None;
                Ok(())
            }
            Err(error) => Err(error)
                .with_context(|| format!("remove private data-plane config {}", path.display())),
        }
    }
}

impl Drop for PrivateConfig {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::warn!(error = %format!("{error:#}"), "failed to remove private adapter config");
        }
    }
}

const CHILD_KILL_TIMEOUT: Duration = Duration::from_secs(3);

/// Stop only the process represented by this exact `Child` handle. Tokio does
/// not expose a portable handle-based TERM operation, and signalling its raw
/// numeric PID would introduce an exit/PID-reuse race. We therefore use the
/// owned handle's KILL operation directly and wait under a strict bound. The
/// service-level cgroup is a final orphan-containment backstop.
async fn stop_owned_child(child: &mut Child, adapter: &str) -> anyhow::Result<()> {
    match child.try_wait() {
        Ok(Some(status)) => {
            debug!(%status, %adapter, "adapter exited on its own");
            return Ok(());
        }
        Ok(None) => {}
        Err(error) => return Err(error).with_context(|| format!("query {adapter} status")),
    }

    child
        .start_kill()
        .with_context(|| format!("kill owned {adapter} process"))?;
    match tokio::time::timeout(CHILD_KILL_TIMEOUT, child.wait()).await {
        Ok(result) => {
            result.with_context(|| format!("wait for killed {adapter}"))?;
            Ok(())
        }
        Err(_) => {
            bail!("owned {adapter} process did not exit within {CHILD_KILL_TIMEOUT:?} after KILL")
        }
    }
}

/// Confirm that both listener sockets are owned by the child we spawned.
/// Linux exposes the required PID→fd→socket-inode mapping without privileges.
/// Other supported targets retain connect-based readiness because there is no
/// portable equivalent; the reservation still prevents duplicate selection.
#[cfg(target_os = "linux")]
fn child_owns_listeners(pid: u32, addrs: [SocketAddr; 2]) -> anyhow::Result<bool> {
    // `pid` is used only for a read-only readiness observation. A PID-reuse
    // race can at worst make readiness return false or (extremely briefly)
    // true for the reserved addresses; process termination never uses it.
    let mut wanted = BTreeSet::new();
    for addr in addrs {
        // /proc/net/tcp prints the __be32 address as a host-order u32, so the
        // octets must be read back in native byte order. A plain `to_le()` is
        // a no-op on little-endian hosts and never matches the procfs format.
        let ip = match addr.ip() {
            std::net::IpAddr::V4(ip) => u32::from_ne_bytes(ip.octets()),
            std::net::IpAddr::V6(_) => bail!("adapter ownership check supports IPv4 loopback only"),
        };
        wanted.insert(format!("{ip:08X}:{:04X}", addr.port()));
    }

    let mut listening_inodes = BTreeSet::new();
    for line in std::fs::read_to_string("/proc/net/tcp")
        .context("read /proc/net/tcp for adapter ownership")?
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() > 9 && fields[3] == "0A" && wanted.contains(fields[1]) {
            listening_inodes.insert(fields[9].to_string());
        }
    }
    if listening_inodes.len() != wanted.len() {
        return Ok(false);
    }

    let fd_dir = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect adapter file descriptors"),
    };
    let mut owned = BTreeSet::new();
    for entry in fd_dir.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy();
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
        {
            if listening_inodes.contains(inode) {
                owned.insert(inode.to_string());
            }
        }
    }
    Ok(owned == listening_inodes)
}

#[cfg(not(target_os = "linux"))]
fn child_owns_listeners(_pid: u32, _addrs: [SocketAddr; 2]) -> anyhow::Result<bool> {
    Ok(true)
}

async fn adapter_is_ready(
    child: &mut Child,
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
) -> anyhow::Result<bool> {
    let Some(pid) = child.id() else {
        return Ok(false);
    };
    if !child_owns_listeners(pid, [socks_addr, http_addr])? {
        return Ok(false);
    }
    let socks_ok = tokio::net::TcpStream::connect(socks_addr).await.is_ok();
    let http_ok = tokio::net::TcpStream::connect(http_addr).await.is_ok();
    Ok(socks_ok && http_ok)
}

// ---------------------------------------------------------------------------
// sslocal implementation
// ---------------------------------------------------------------------------

pub struct SslocalPlane {
    bin: PathBuf,
    /// Temporary config directory (one JSON per instance)
    workspace: Arc<AdapterWorkspace>,
    /// Absolute path of the simple-obfs plugin (SIP003); required to exist
    /// only when a node carries plugin parameters
    obfs_plugin_bin: PathBuf,
    ready_timeout: Duration,
}

impl SslocalPlane {
    pub fn new(bin: PathBuf, workspace: Arc<AdapterWorkspace>, obfs_plugin_bin: PathBuf) -> Self {
        Self {
            bin,
            workspace,
            obfs_plugin_bin,
            ready_timeout: Duration::from_secs(10),
        }
    }
}

/// Build the sslocal config (a pure function, so unit tests can assert the
/// shape of the plugin fields).
///
/// One process, two locals: socks + http, each embedding the same node config.
/// mode=tcp_only: P1 does not handle UDP (explicit beats implicit half-support).
/// When a node carries simple-obfs parameters, both locals get the SIP003
/// plugin/plugin_opts injected — without them sslocal would listen happily
/// while every upstream times out (a P0 incident on record).
fn build_sslocal_config(
    node: &SsNode,
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
    obfs_bin: &std::path::Path,
) -> serde_json::Value {
    let local = |addr: SocketAddr, protocol: &str| {
        let mut l = serde_json::json!({
            "local_address": addr.ip().to_string(),
            "local_port": addr.port(),
            "protocol": protocol,
            "server": node.server,
            "server_port": node.port,
            "password": node.password,
            "method": node.cipher,
            "mode": "tcp_only"
        });
        if let Some(obfs) = &node.plugin {
            // The plugin is referenced by absolute path (determinism first,
            // no reliance on PATH resolution)
            l["plugin"] = serde_json::Value::String(obfs_bin.to_string_lossy().into_owned());
            l["plugin_opts"] = serde_json::Value::String(obfs.to_plugin_opts());
        }
        l
    };
    serde_json::json!({
        "locals": [
            local(socks_addr, "socks"),
            local(http_addr, "http"),
        ]
    })
}

pub struct SslocalHandle {
    child: Child,
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
    config: PrivateConfig,
    node_name: String,
}

impl Drop for SslocalHandle {
    fn drop(&mut self) {
        // `kill_on_drop(true)` is the cancellation/panic backstop. The normal
        // path kills and reaps the owned child under a strict bound in `stop`;
        // the config guard always unlinks the credential file.
        self.config.cleanup().ok();
    }
}

#[async_trait]
impl DataPlaneHandle for SslocalHandle {
    fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }
    fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }
    fn describe(&self) -> String {
        format!(
            "sslocal[{}] socks={} http={} pid={:?}",
            self.node_name,
            self.socks_addr.port(),
            self.http_addr.port(),
            self.child.id()
        )
    }
    async fn stop(&mut self) -> anyhow::Result<()> {
        let process_result = stop_owned_child(&mut self.child, "sslocal").await;
        let config_result = self.config.cleanup();
        process_result?;
        config_result?;
        info!(node = %self.node_name, "sslocal stopped");
        Ok(())
    }
}

#[async_trait]
impl DataPlane for SslocalPlane {
    async fn start(&self, spec: StartSpec) -> anyhow::Result<Box<dyn DataPlaneHandle>> {
        let (node, ports) = spec.into_parts();
        let node_kind = node.kind();
        let Node::Ss(node) = node else {
            bail!("sslocal plane only serves ss nodes (got {node_kind})");
        };
        if !self.bin.exists() {
            bail!(
                "sslocal does not exist: {} (run scripts/install-dataplane.sh first)",
                self.bin.display()
            );
        }
        if node.plugin.is_some() && !self.obfs_plugin_bin.exists() {
            bail!(
                "node {} requires the simple-obfs plugin, but the binary does not exist: {} (run scripts/install-plugin.sh first)",
                node.name,
                self.obfs_plugin_bin.display()
            );
        }
        let socks_addr = ports.socks_addr;
        let http_addr = ports.http_addr;
        let config = build_sslocal_config(&node, socks_addr, http_addr, &self.obfs_plugin_bin);
        let private_config = PrivateConfig::create(
            self.workspace.path(),
            "sslocal",
            &serde_json::to_vec_pretty(&config)?,
        )?;

        // External adapters cannot inherit already-bound sockets. Keep both
        // reservations through config construction, then make release→spawn
        // adjacent. Ownership-aware readiness below detects a lost race.
        let (socks_addr, http_addr) = ports.release();
        let mut command = Command::new(&self.bin);
        command
            .arg("-c")
            .arg(private_config.path())
            // Logs go to its own stderr; the supervisor already records
            // lifecycle events via tracing
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let child = apply_direct_network_env(&mut command)
            .spawn()
            .with_context(|| format!("spawn sslocal ({})", self.bin.display()))?;
        let pid = child.id();

        let mut handle = SslocalHandle {
            child,
            socks_addr,
            http_addr,
            config: private_config,
            node_name: node.name.clone(),
        };

        // Readiness wait: both ports must accept connections before we call it
        // up (accepting does not mean the upstream works — that is the health
        // check's job)
        let deadline = tokio::time::Instant::now() + self.ready_timeout;
        loop {
            match adapter_is_ready(&mut handle.child, socks_addr, http_addr).await {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    handle.stop().await.ok();
                    return Err(error).context("verify sslocal listener ownership");
                }
            }
            match handle.child.try_wait() {
                Ok(Some(status)) => {
                    handle.stop().await.ok();
                    bail!(
                        "sslocal exited immediately after start ({status}), node {} (check whether the cipher/password is supported)",
                        node.name
                    );
                }
                Ok(None) => {}
                Err(error) => {
                    handle.stop().await.ok();
                    return Err(error).context("query sslocal during readiness");
                }
            }
            if tokio::time::Instant::now() >= deadline {
                handle.stop().await.ok();
                bail!(
                    "sslocal port readiness timed out ({:?})",
                    self.ready_timeout
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        debug!(pid = ?pid, node = %node.name, "sslocal ready");
        Ok(Box::new(handle))
    }
}

// ---------------------------------------------------------------------------
// sing-box implementation (anytls nodes)
// ---------------------------------------------------------------------------

pub struct SingboxPlane {
    bin: PathBuf,
    /// Temporary config directory (one JSON per instance)
    workspace: Arc<AdapterWorkspace>,
    ready_timeout: Duration,
}

impl SingboxPlane {
    pub fn new(bin: PathBuf, workspace: Arc<AdapterWorkspace>) -> Self {
        Self {
            bin,
            workspace,
            ready_timeout: Duration::from_secs(10),
        }
    }
}

/// Build the sing-box config (a pure function, so unit tests can assert the
/// outbound shape).
///
/// One process, two inbounds: socks + http — the same local layout as the
/// sslocal plane, so listener and supervisor stay protocol-agnostic.
fn build_singbox_config(
    node: &AnytlsNode,
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
) -> serde_json::Value {
    let inbound = |addr: SocketAddr, protocol: &str| {
        serde_json::json!({
            "type": protocol,
            "tag": format!("{protocol}-in"),
            "listen": addr.ip().to_string(),
            "listen_port": addr.port(),
        })
    };
    let mut tls = serde_json::json!({
        "enabled": true,
        "alpn": node
            .alpn
            .clone()
            .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()]),
        "utls": {
            "enabled": true,
            "fingerprint": node.client_fingerprint.clone().unwrap_or_else(|| "chrome".to_string()),
        },
    });
    if let Some(sni) = &node.sni {
        tls["server_name"] = serde_json::Value::String(sni.clone());
    }
    if node.skip_cert_verify {
        tls["insecure"] = serde_json::Value::Bool(true);
    }
    serde_json::json!({
        "log": {"level": "warn"},
        // Constrain the adapter shape explicitly. A provider manifest can
        // select only this outbound; it can never request TUN, auto-routing,
        // DNS interception, or a system proxy.
        "inbounds": [
            inbound(socks_addr, "socks"),
            inbound(http_addr, "http"),
        ],
        "outbounds": [{
            "type": "anytls",
            "tag": "out",
            "server": node.server,
            "server_port": node.port,
            "password": node.password,
            "tls": tls,
        }],
        "route": {
            "auto_detect_interface": false,
            "final": "out",
        },
    })
}

pub struct SingboxHandle {
    child: Child,
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
    config: PrivateConfig,
    node_name: String,
}

impl Drop for SingboxHandle {
    fn drop(&mut self) {
        self.config.cleanup().ok();
    }
}

#[async_trait]
impl DataPlaneHandle for SingboxHandle {
    fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }
    fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }
    fn describe(&self) -> String {
        format!(
            "sing-box[{}] socks={} http={} pid={:?}",
            self.node_name,
            self.socks_addr.port(),
            self.http_addr.port(),
            self.child.id()
        )
    }
    async fn stop(&mut self) -> anyhow::Result<()> {
        let process_result = stop_owned_child(&mut self.child, "sing-box").await;
        let config_result = self.config.cleanup();
        process_result?;
        config_result?;
        info!(node = %self.node_name, "sing-box stopped");
        Ok(())
    }
}

#[async_trait]
impl DataPlane for SingboxPlane {
    async fn start(&self, spec: StartSpec) -> anyhow::Result<Box<dyn DataPlaneHandle>> {
        let (node, ports) = spec.into_parts();
        let node_kind = node.kind();
        let Node::Anytls(node) = node else {
            bail!("sing-box plane only serves anytls nodes (got {node_kind})");
        };
        if !self.bin.exists() {
            bail!(
                "sing-box does not exist: {} (set singbox_bin in the config)",
                self.bin.display()
            );
        }
        let socks_addr = ports.socks_addr;
        let http_addr = ports.http_addr;
        let config = build_singbox_config(&node, socks_addr, http_addr);
        let private_config = PrivateConfig::create(
            self.workspace.path(),
            "singbox",
            &serde_json::to_vec_pretty(&config)?,
        )?;

        let (socks_addr, http_addr) = ports.release();
        let mut command = Command::new(&self.bin);
        command
            .arg("run")
            .arg("-c")
            .arg(private_config.path())
            // Logs go to its own stderr; the supervisor already records
            // lifecycle events via tracing
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let child = apply_direct_network_env(&mut command)
            .spawn()
            .with_context(|| format!("spawn sing-box ({})", self.bin.display()))?;
        let pid = child.id();

        let mut handle = SingboxHandle {
            child,
            socks_addr,
            http_addr,
            config: private_config,
            node_name: node.name.clone(),
        };

        // Readiness wait: both ports must accept connections before we call it
        // up (accepting does not mean the upstream works — that is the health
        // check's job)
        let deadline = tokio::time::Instant::now() + self.ready_timeout;
        loop {
            match adapter_is_ready(&mut handle.child, socks_addr, http_addr).await {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    handle.stop().await.ok();
                    return Err(error).context("verify sing-box listener ownership");
                }
            }
            match handle.child.try_wait() {
                Ok(Some(status)) => {
                    handle.stop().await.ok();
                    bail!(
                        "sing-box exited immediately after start ({status}), node {} (check the node fields)",
                        node.name
                    );
                }
                Ok(None) => {}
                Err(error) => {
                    handle.stop().await.ok();
                    return Err(error).context("query sing-box during readiness");
                }
            }
            if tokio::time::Instant::now() >= deadline {
                handle.stop().await.ok();
                bail!(
                    "sing-box port readiness timed out ({:?})",
                    self.ready_timeout
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        debug!(pid = ?pid, node = %node.name, "sing-box ready");
        Ok(Box::new(handle))
    }
}

// ---------------------------------------------------------------------------
// Dispatch by node type
// ---------------------------------------------------------------------------

/// Route a start request to the adapter matching the node's protocol, so the
/// supervisor stays protocol-agnostic.
pub struct DispatchPlane {
    ss: SslocalPlane,
    singbox: SingboxPlane,
    workspace: Arc<AdapterWorkspace>,
}

impl DispatchPlane {
    pub fn new(ss: SslocalPlane, singbox: SingboxPlane, workspace: Arc<AdapterWorkspace>) -> Self {
        Self {
            ss,
            singbox,
            workspace,
        }
    }
}

#[async_trait]
impl DataPlane for DispatchPlane {
    async fn start(&self, spec: StartSpec) -> anyhow::Result<Box<dyn DataPlaneHandle>> {
        match &spec.node {
            Node::Ss(_) => self.ss.start(spec).await,
            Node::Anytls(_) => self.singbox.start(spec).await,
        }
    }

    fn cleanup_workspace(&self) -> anyhow::Result<()> {
        self.workspace.cleanup()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::ObfsOpts;

    fn workspace_test_root(label: &str) -> PathBuf {
        let mut nonce = [0u8; 8];
        fill_kernel_random(&mut nonce).unwrap();
        let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        std::env::temp_dir().join(format!(
            "causeway-workspace-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn create_fixture_instance(
        adapters_dir: &Path,
        identity: &ProcessIdentity,
        nonce: &str,
    ) -> PathBuf {
        let path = adapters_dir.join(strict_instance_name(identity, nonce));
        std::fs::create_dir_all(&path).unwrap();
        write_new_private_file(&path.join(IDENTITY_FILE_NAME), identity.encode().as_bytes())
            .unwrap();
        path
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn crash_stale_workspace_is_removed_but_legacy_root_file_is_preserved() {
        let run_dir = workspace_test_root("stale");
        let adapters_dir = run_dir.join(ADAPTERS_DIR_NAME);
        std::fs::create_dir_all(&adapters_dir).unwrap();
        let legacy = run_dir.join("sslocal-123-456.json");
        std::fs::write(&legacy, b"legacy credential fixture").unwrap();
        let stale_identity = ProcessIdentity {
            boot_id: read_boot_id().unwrap(),
            pid: 4294967295,
            start_time: 1,
        };
        let stale = create_fixture_instance(
            &adapters_dir,
            &stale_identity,
            "11111111111111111111111111111111",
        );
        std::fs::write(stale.join("sslocal-123-0000000000000001.json"), b"secret").unwrap();

        cleanup_stale_instances(&adapters_dir).unwrap();
        assert!(!stale.exists(), "confirmed-dead strict instance is removed");
        assert!(legacy.exists(), "legacy shared-root file is out of scope");
        std::fs::remove_dir_all(&run_dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_workspace_and_malformed_stale_workspace_are_preserved() {
        let run_dir = workspace_test_root("live");
        let adapters_dir = run_dir.join(ADAPTERS_DIR_NAME);
        std::fs::create_dir_all(&adapters_dir).unwrap();
        let live_identity = ProcessIdentity::current().unwrap();
        let live = create_fixture_instance(
            &adapters_dir,
            &live_identity,
            "22222222222222222222222222222222",
        );
        let dead_identity = ProcessIdentity {
            boot_id: "00000000-0000-0000-0000-000000000000".to_string(),
            pid: 4294967295,
            start_time: 2,
        };
        let malformed = create_fixture_instance(
            &adapters_dir,
            &dead_identity,
            "33333333333333333333333333333333",
        );
        std::fs::write(malformed.join("unexpected"), b"preserve").unwrap();

        cleanup_stale_instances(&adapters_dir).unwrap();
        assert!(live.exists(), "matching live process identity is preserved");
        assert!(
            malformed.exists(),
            "unexpected contents make stale cleanup fail-safe"
        );
        std::fs::remove_dir_all(&run_dir).unwrap();
    }

    #[cfg(all(target_os = "linux", unix))]
    #[test]
    fn stale_cleanup_refuses_symlink_entries() {
        use std::os::unix::fs::symlink;

        let run_dir = workspace_test_root("symlink");
        let adapters_dir = run_dir.join(ADAPTERS_DIR_NAME);
        std::fs::create_dir_all(&adapters_dir).unwrap();
        let dead_identity = ProcessIdentity {
            boot_id: read_boot_id().unwrap(),
            pid: 4294967295,
            start_time: 3,
        };
        let stale = create_fixture_instance(
            &adapters_dir,
            &dead_identity,
            "55555555555555555555555555555555",
        );
        let outside = run_dir.join("outside");
        std::fs::write(&outside, b"must survive").unwrap();
        symlink(&outside, stale.join("sslocal-123-0000000000000001.json")).unwrap();

        cleanup_stale_instances(&adapters_dir).unwrap();
        assert!(stale.exists(), "symlink makes the whole instance fail-safe");
        assert_eq!(std::fs::read(&outside).unwrap(), b"must survive");
        std::fs::remove_dir_all(&run_dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_workspace_cleanup_removes_only_owned_instance() {
        let run_dir = workspace_test_root("normal");
        let workspace = AdapterWorkspace::create(&run_dir).unwrap();
        let own_dir = workspace.path().to_path_buf();
        let sibling_identity = ProcessIdentity::current().unwrap();
        let sibling = create_fixture_instance(
            &run_dir.join(ADAPTERS_DIR_NAME),
            &sibling_identity,
            "44444444444444444444444444444444",
        );
        let mut config = PrivateConfig::create(workspace.path(), "sslocal", b"secret").unwrap();
        config.cleanup().unwrap();

        workspace.cleanup().unwrap();
        assert!(!own_dir.exists());
        assert!(sibling.exists(), "normal cleanup never removes a sibling");
        std::fs::remove_dir_all(&run_dir).unwrap();
    }

    #[test]
    fn adapter_commands_remove_every_proxy_environment_spelling() {
        let mut command = Command::new("adapter-fixture");
        for name in PROXY_ENV_VARS {
            command.env(name, "http://127.0.0.1:1");
        }
        apply_direct_network_env(&mut command);
        let mutations: std::collections::BTreeMap<String, Option<String>> = command
            .as_std()
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for name in PROXY_ENV_VARS {
            assert_eq!(mutations.get(name), Some(&None), "{name} must be removed");
        }
    }

    #[cfg(unix)]
    #[test]
    fn generated_adapter_config_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "causeway-private-config-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut config =
            PrivateConfig::create(&dir, "adapter", br#"{"password":"fixture"}"#).unwrap();
        let path = config.path().to_path_buf();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        config.cleanup().unwrap();
        assert!(!path.exists(), "explicit cleanup removes credential file");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn private_configs_are_unique_and_drop_removes_them() {
        let dir = std::env::temp_dir().join(format!(
            "causeway-private-config-drop-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let first = PrivateConfig::create(&dir, "adapter", b"one").unwrap();
        let second = PrivateConfig::create(&dir, "adapter", b"two").unwrap();
        let first_path = first.path().to_path_buf();
        let second_path = second.path().to_path_buf();
        assert_ne!(first_path, second_path);
        assert_eq!(std::fs::read(&first_path).unwrap(), b"one");
        assert_eq!(std::fs::read(&second_path).unwrap(), b"two");
        drop((first, second));
        assert!(!first_path.exists());
        assert!(!second_path.exists());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn reserved_adapter_ports_are_distinct_and_held() {
        let reservation = LoopbackPortPair::reserve().unwrap();
        assert_ne!(reservation.socks_addr, reservation.http_addr);
        assert!(StdTcpListener::bind(reservation.socks_addr).is_err());
        assert!(StdTcpListener::bind(reservation.http_addr).is_err());
        let (socks_addr, http_addr) = reservation.release();
        let socks = StdTcpListener::bind(socks_addr).unwrap();
        let http = StdTcpListener::bind(http_addr).unwrap();
        drop((socks, http));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ownership_check_matches_procfs_address_format() {
        let first = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let second = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let owned = [first.local_addr().unwrap(), second.local_addr().unwrap()];
        assert!(child_owns_listeners(std::process::id(), owned).unwrap());

        // A port nobody listens on can never appear in the descriptor table.
        let vacant = {
            let probe = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            probe.local_addr().unwrap()
        };
        assert!(!child_owns_listeners(std::process::id(), [owned[0], vacant]).unwrap());
    }

    fn socks() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 21001))
    }

    fn http() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 21002))
    }

    fn ss_node(plugin: Option<ObfsOpts>) -> SsNode {
        SsNode {
            name: "T".to_string(),
            server: "203.0.113.1".to_string(),
            port: 12022,
            cipher: "aes-128-gcm".to_string(),
            password: "pw".to_string(),
            plugin,
        }
    }

    #[test]
    fn config_json_injects_plugin_on_both_locals() {
        let node = ss_node(Some(ObfsOpts {
            mode: "http".to_string(),
            host: Some("cdn.example.com".to_string()),
        }));
        let obfs_bin = std::path::Path::new("/home/u/.local/share/causeway/bin/obfs-local");
        let cfg = build_sslocal_config(&node, socks(), http(), obfs_bin);
        let locals = cfg["locals"].as_array().unwrap();
        assert_eq!(locals.len(), 2, "still one process with two locals");
        for l in locals {
            assert_eq!(
                l["plugin"].as_str().unwrap(),
                "/home/u/.local/share/causeway/bin/obfs-local",
                "plugin referenced by absolute path"
            );
            assert_eq!(
                l["plugin_opts"].as_str().unwrap(),
                "obfs=http;obfs-host=cdn.example.com",
                "plugin_opts semicolon-string format"
            );
        }
        // Existing fields survive the plugin injection
        assert_eq!(locals[0]["protocol"].as_str().unwrap(), "socks");
        assert_eq!(locals[1]["protocol"].as_str().unwrap(), "http");
        assert_eq!(locals[0]["server_port"].as_u64().unwrap(), 12022);
    }

    #[test]
    fn config_json_omits_plugin_when_node_has_none() {
        let node = ss_node(None);
        // A plugin-free node does not require the plugin binary to exist (any
        // path will do)
        let cfg = build_sslocal_config(
            &node,
            socks(),
            http(),
            std::path::Path::new("/nonexistent/obfs-local"),
        );
        let locals = cfg["locals"].as_array().unwrap();
        for l in locals {
            assert!(
                l.get("plugin").is_none(),
                "a plugin-free node must not gain a plugin key"
            );
            assert!(l.get("plugin_opts").is_none());
        }
    }

    fn anytls_node(
        sni: Option<&str>,
        alpn: Option<Vec<String>>,
        fingerprint: Option<&str>,
        skip_cert_verify: bool,
    ) -> AnytlsNode {
        AnytlsNode {
            name: "T".to_string(),
            server: "node.example.com".to_string(),
            port: 443,
            password: "pw".to_string(),
            sni: sni.map(str::to_string),
            alpn,
            client_fingerprint: fingerprint.map(str::to_string),
            skip_cert_verify,
        }
    }

    #[test]
    fn singbox_config_maps_node_fields() {
        let node = anytls_node(
            Some("cdn.example.com"),
            Some(vec!["h2".to_string()]),
            Some("firefox"),
            true,
        );
        let cfg = build_singbox_config(&node, socks(), http());

        let inbounds = cfg["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2, "one process with two inbounds");
        assert_eq!(inbounds[0]["type"].as_str().unwrap(), "socks");
        assert_eq!(inbounds[0]["tag"].as_str().unwrap(), "socks-in");
        assert_eq!(inbounds[0]["listen"].as_str().unwrap(), "127.0.0.1");
        assert_eq!(inbounds[0]["listen_port"].as_u64().unwrap(), 21001);
        assert_eq!(inbounds[1]["type"].as_str().unwrap(), "http");
        assert_eq!(inbounds[1]["listen_port"].as_u64().unwrap(), 21002);

        let out = &cfg["outbounds"][0];
        assert_eq!(out["type"].as_str().unwrap(), "anytls");
        assert_eq!(out["server"].as_str().unwrap(), "node.example.com");
        assert_eq!(out["server_port"].as_u64().unwrap(), 443);
        assert_eq!(out["password"].as_str().unwrap(), "pw");
        let tls = &out["tls"];
        assert!(tls["enabled"].as_bool().unwrap());
        assert_eq!(tls["server_name"].as_str().unwrap(), "cdn.example.com");
        assert_eq!(tls["alpn"], serde_json::json!(["h2"]));
        assert!(tls["insecure"].as_bool().unwrap());
        assert!(tls["utls"]["enabled"].as_bool().unwrap());
        assert_eq!(tls["utls"]["fingerprint"].as_str().unwrap(), "firefox");
        assert!(cfg.get("dns").is_none());
        assert_eq!(cfg["route"]["auto_detect_interface"], false);
        assert_eq!(cfg["route"]["final"], "out");
        assert!(inbounds.iter().all(|inbound| inbound["type"] != "tun"));
    }

    #[test]
    fn singbox_config_defaults_when_optional_fields_absent() {
        let node = anytls_node(None, None, None, false);
        let cfg = build_singbox_config(&node, socks(), http());
        let tls = &cfg["outbounds"][0]["tls"];
        assert!(
            tls.get("server_name").is_none(),
            "no sni → server_name omitted"
        );
        assert!(
            tls.get("insecure").is_none(),
            "skip_cert_verify=false → insecure omitted"
        );
        assert_eq!(
            tls["alpn"],
            serde_json::json!(["h2", "http/1.1"]),
            "default ALPN list"
        );
        assert_eq!(
            tls["utls"]["fingerprint"].as_str().unwrap(),
            "chrome",
            "default fingerprint"
        );
    }
}
