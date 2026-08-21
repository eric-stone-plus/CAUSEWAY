//! CAUSEWAY — headless loopback proxy gateway.
//!
//! Design red lines (learned from the mihomo experience, non-negotiable):
//! - Never touch TUN / system DNS / system routes / any system-level network
//!   state; userspace TCP only;
//! - No GUI, no HTTP/metrics servers; runtime control is exactly one local
//!   Unix socket (mode 0600, see `control.rs`) used by the bundled `switch`
//!   subcommand; one config file + one systemd user service;
//! - Stability over latency; explicit over clever (the listener does not
//!   inspect SNI or proxy targets; static exact-host routing is adapter-owned).

mod config;
mod control;
mod daemon_lock;
mod dataplane;
mod egress;
mod events;
mod health;
mod listener;
mod peek;
mod probe;
mod score;
mod siteprobe;
mod state;
mod subscription;
mod supervisor;
mod switch;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::prelude::*;

/// Print a line to stdout, ignoring write errors. A closed pipe — e.g.
/// `causeway status | head` — must end the program quietly, not panic
/// inside `println!`'s failed write.
macro_rules! pln {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

/// Same as `pln!`, for stderr.
macro_rules! epln {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

// Re-export so sibling modules (switch) can `use crate::{epln, pln};`
pub(crate) use {epln, pln};

#[derive(Parser)]
#[command(
    name = "causeway",
    version,
    about = "Headless loopback proxy gateway with supervised sslocal failover — run bare to open the node switcher TUI"
)]
struct Cli {
    /// Path to the config file (default ~/.config/causeway/config.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Subcommand; bare `causeway` opens the interactive node switcher
    /// (plain status table when stdout is not a terminal)
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run as a daemon (entry point for the systemd user service)
    Run,
    /// Probe all nodes once and print a scoring report (writes no state;
    /// intended for use while the daemon is stopped)
    Probe {
        /// Probe only the first N nodes (smoke test)
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Read the state file and print the active nodes and health summary
    Status,
    /// Interactive node switcher (nmtui-style); prints a plain status table
    /// when stdout is not a terminal. With --node/--for-site plus --yes it
    /// becomes a non-interactive automation client.
    Switch {
        /// Class to manage (default: the first class in the config)
        #[arg(long)]
        class: Option<String>,
        /// Switch to this node (non-interactive with --yes)
        #[arg(long, requires = "yes")]
        node: Option<String>,
        /// Switch for one configured site: keep the incumbent when it is
        /// not frozen, otherwise probe candidates and move to the first
        /// node the site serves (non-interactive with --yes)
        #[arg(long, requires = "yes", conflicts_with = "node")]
        for_site: Option<String>,
        /// Confirm a non-interactive switch
        #[arg(long)]
        yes: bool,
    },
    /// Anti-bot freeze matrix: which pool nodes each configured site
    /// currently serves. Probes are HTTPS GETs with a browser User-Agent.
    Sites {
        /// Refresh verdicts before printing: all sites, or one named site
        #[arg(long, num_args = 0..=1)]
        probe: Option<Option<String>>,
        /// Machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Configuration-related operations
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Load and validate the config, print a summary
    Check,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run_cli(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            epln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_cli(cli: Cli) -> anyhow::Result<()> {
    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(config::default_config_path);
    let command = cli.command.unwrap_or(Command::Switch {
        class: None,
        node: None,
        for_site: None,
        yes: false,
    });
    match &command {
        Command::Run => {
            let (cfg, warnings) = config::load(&config_path)?;
            // The guard must stay alive for the entire run
            let _guard = init_daemon_tracing(&cfg)?;
            for w in &warnings {
                tracing::warn!(warning = %w, "config warning");
            }
            supervisor::run(cfg, config_path).await
        }
        Command::Probe { limit } => {
            init_cli_tracing();
            let (cfg, warnings) = config::load(&config_path)?;
            for w in &warnings {
                epln!("warning: {w}");
            }
            cmd_probe(&cfg, *limit).await
        }
        Command::Status => {
            init_cli_tracing();
            let (cfg, _) = config::load(&config_path)?;
            cmd_status(&cfg)
        }
        Command::Switch {
            class,
            node,
            for_site,
            yes,
        } => {
            init_cli_tracing();
            let (cfg, _) = config::load(&config_path)?;
            let class = match class {
                Some(c) => c.clone(),
                None => cfg
                    .classes
                    .keys()
                    .next()
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("no classes configured"))?,
            };
            if !cfg.classes.contains_key(&class) {
                anyhow::bail!(
                    "unknown class {class:?} (configured: {})",
                    cfg.classes.keys().cloned().collect::<Vec<_>>().join(", ")
                );
            }
            if node.is_some() || for_site.is_some() {
                if !yes {
                    anyhow::bail!("--node/--for-site require --yes in non-interactive mode");
                }
                return switch::run_noninteractive(&cfg, &class, node.clone(), for_site.clone())
                    .await;
            }
            switch::run(&cfg, &class).await
        }
        Command::Sites { probe, json } => {
            init_cli_tracing();
            let (cfg, _) = config::load(&config_path)?;
            cmd_sites(&cfg, probe.clone(), *json).await
        }
        Command::Config {
            action: ConfigAction::Check,
        } => {
            init_cli_tracing();
            cmd_config_check(&config_path)
        }
    }
}

/// Daemon logging: compact lines on stdout (collected by journald) plus a
/// JSON Lines file (rotated daily).
fn init_daemon_tracing(
    cfg: &config::Config,
) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    std::fs::create_dir_all(&cfg.log_dir)
        .with_context(|| format!("create log directory {}", cfg.log_dir.display()))?;
    let file_appender = tracing_appender::rolling::daily(&cfg.log_dir, "causeway.jsonl");
    let (nb_file, guard) = tracing_appender::non_blocking(file_appender);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(nb_file)
        .with_filter(filter.clone());
    let stdout_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_writer(std::io::stdout)
        .with_filter(filter);
    tracing_subscriber::registry()
        .with(json_layer)
        .with(stdout_layer)
        .try_init()
        .context("initialize tracing")?;
    Ok(guard)
}

/// CLI subcommand logging: terse stderr output (so `pln!` results stay clean).
fn init_cli_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// `causeway probe`: one-shot probing + scoring report. Reads subscriptions
/// only; does not write the state file.
async fn cmd_probe(cfg: &config::Config, limit: Option<usize>) -> anyhow::Result<()> {
    let persisted = state::load(&cfg.state_file)?;
    let profile_name = persisted
        .as_ref()
        .and_then(|st| st.active_subscription.as_ref())
        .filter(|name| cfg.subscriptions.profile(name).is_some())
        .cloned()
        .unwrap_or(cfg.subscriptions.default_profile_name()?);
    let profile = cfg
        .subscriptions
        .profile(&profile_name)
        .ok_or_else(|| anyhow::anyhow!("unknown default subscription profile"))?;
    let confirmed_slot = persisted
        .as_ref()
        .and_then(|st| st.subscription_cache_slots.get(&profile_name))
        .map(String::as_str);
    let mut nodes = subscription::load_profile_snapshot_from_slot(&profile, confirmed_slot);
    if let Some(limit) = limit {
        nodes.truncate(limit);
    }
    if nodes.is_empty() {
        anyhow::bail!("no nodes parsed from the subscription files");
    }
    pln!(
        "probing {} nodes (timeout {}ms, concurrency {})…",
        nodes.len(),
        cfg.probe.timeout_ms,
        cfg.probe.concurrency
    );

    let outcomes = probe::probe_all(
        nodes,
        std::time::Duration::from_millis(cfg.probe.timeout_ms),
        cfg.probe.concurrency,
    )
    .await;

    let mut ok: Vec<_> = outcomes.iter().filter(|o| o.rtt.is_some()).collect();
    ok.sort_by_key(|o| o.rtt.unwrap());
    let failed = outcomes.len() - ok.len();

    pln!("\n{:<50} {:>10}", "NODE", "RTT (ms)");
    for o in ok.iter().take(20) {
        pln!(
            "{:<50} {:>10.0}",
            truncate(o.node.name(), 50),
            o.rtt.unwrap().as_secs_f64() * 1000.0
        );
    }
    if ok.len() > 20 {
        pln!("… and {} more", ok.len() - 20);
    }
    pln!(
        "\nsummary: {} ok / {} failed / {} total",
        ok.len(),
        failed,
        outcomes.len()
    );
    Ok(())
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        // saturating_sub: the TUI passes a dynamically computed width that
        // reaches 0 in terminals squeezed to two columns.
        let mut t: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// `causeway status`: read the state file and print a summary (works even
/// when the daemon is not running).
async fn cmd_sites(
    cfg: &config::Config,
    probe: Option<Option<String>>,
    json: bool,
) -> anyhow::Result<()> {
    let client = control::Client::new(control::socket_path(cfg));
    if let Some(scope) = probe {
        let req = match scope.clone() {
            Some(site) => control::Request::SiteProbe { site: Some(site) },
            None => control::Request::SiteProbe { site: None },
        };
        // Full-matrix probes walk every node; allow minutes, not seconds.
        let reply = client
            .request(&req, std::time::Duration::from_secs(600))
            .await?;
        if !reply.ok {
            anyhow::bail!("{}", reply.error.unwrap_or_else(|| "probe failed".into()));
        }
        if json {
            if let Some(matrix) = reply.site_matrix {
                println!("{}", serde_json::to_string_pretty(&matrix)?);
            }
            return Ok(());
        }
    }
    let reply = client
        .request(
            &control::Request::SiteStatus,
            std::time::Duration::from_secs(30),
        )
        .await?;
    if !reply.ok {
        anyhow::bail!("{}", reply.error.unwrap_or_else(|| "status failed".into()));
    }
    let matrix = reply
        .site_matrix
        .ok_or_else(|| anyhow::anyhow!("daemon did not return a site matrix"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&matrix)?);
        return Ok(());
    }
    if cfg.sites.list.is_empty() {
        epln!("no sites configured under [sites.list]");
        return Ok(());
    }
    println!(
        "{:<28} {:<10} {:<8} {:<12} CHECKED",
        "SITE", "NODE", "VERDICT", "HTTP"
    );
    for (site, nodes) in &matrix {
        for (node, verdict) in nodes {
            println!(
                "{:<28} {:<10} {:<8} {:<12} {}",
                site,
                truncate_str(node, 10),
                verdict.status.as_str(),
                verdict
                    .http_status
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into()),
                verdict.checked_unix,
            );
        }
    }
    Ok(())
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max - 1).collect();
        format!("{cut}…")
    }
}

fn cmd_status(cfg: &config::Config) -> anyhow::Result<()> {
    let Some(st) = state::load(&cfg.state_file)? else {
        pln!(
            "no state file at {} (daemon has not run yet)",
            cfg.state_file.display()
        );
        return Ok(());
    };
    pln!(
        "state file: {} (updated_unix={})",
        cfg.state_file.display(),
        st.updated_unix
    );

    if st.classes.is_empty() {
        pln!("\nclasses: <none recorded>");
    } else {
        pln!(
            "\n{:<12} {:<40} {:<10} {:<8} {:<6}",
            "CLASS",
            "ACTIVE NODE",
            "SOCKS",
            "HTTP",
            "GEN"
        );
        for (name, cs) in &st.classes {
            pln!(
                "{:<12} {:<40} {:<10} {:<8} {:<6}",
                name,
                cs.active_node
                    .as_deref()
                    .map(|n| truncate(n, 40))
                    .unwrap_or_else(|| "<none>".into()),
                cs.socks_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                cs.http_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                cs.generation,
            );
        }
    }

    let probed_count = st.nodes.values().filter(|s| s.is_probed()).count();
    if let Some(profile) = &st.active_subscription {
        pln!("\nactive subscription: {profile}");
    }
    pln!("\ntop nodes (of {probed_count} probed):");
    pln!(
        "{:<44} {:>8} {:>10} {:>8}",
        "NODE",
        "SUCC↓",
        "RTT (ms)",
        "HLTH-F"
    );
    // StateFile.nodes is keyed by node name; sort together with the key for printing
    let mut named: Vec<(&String, &score::NodeStats)> =
        st.nodes.iter().filter(|(_, s)| s.is_probed()).collect();
    named.sort_by(|(_, a), (_, b)| score::score_cmp(b, a));
    for (name, s) in named.iter().take(10) {
        pln!(
            "{:<44} {:>8.3} {:>10} {:>8}",
            truncate(name, 44),
            s.success_ema,
            s.rtt_ema_ms
                .map(|r| format!("{r:.0}"))
                .unwrap_or_else(|| "-".into()),
            s.consecutive_health_failures,
        );
    }
    Ok(())
}

/// `causeway config check`: load + validate + offline subscription parse summary.
fn cmd_config_check(path: &std::path::Path) -> anyhow::Result<()> {
    let (cfg, warnings) = config::load(path)?;
    pln!("config OK: {}", path.display());
    pln!("  log_dir      = {}", cfg.log_dir.display());
    pln!("  state_file   = {}", cfg.state_file.display());
    pln!("  sslocal_bin  = {}", cfg.sslocal_bin.display());
    pln!("  singbox_bin  = {}", cfg.singbox_bin.display());
    for (name, class) in &cfg.classes {
        pln!("  class {name:<10} listen = {}", class.listen);
    }
    pln!(
        "  probe: every {}s, timeout {}ms, concurrency {}",
        cfg.probe.interval_secs,
        cfg.probe.timeout_ms,
        cfg.probe.concurrency
    );
    pln!(
        "  health: every {}s, timeout {}ms, threshold {}, url {}",
        cfg.health.interval_secs,
        cfg.health.timeout_ms,
        cfg.health.fail_threshold,
        cfg.health.url
    );
    pln!(
        "  selection: hysteresis {:.2}, ema_alpha {:.2}",
        cfg.selection.hysteresis,
        cfg.selection.ema_alpha
    );
    pln!(
        "  routing: {} exact direct host(s)",
        cfg.routing.direct_hosts.len()
    );

    // Offline subscription parse (print counts only, never node details —
    // node data must not end up anywhere beyond terminal scrollback). Remote
    // profiles use their last-known-good cache; config check never fetches.
    let default_profile = cfg.subscriptions.default_profile_name()?;
    let profile = cfg
        .subscriptions
        .profile(&default_profile)
        .ok_or_else(|| anyhow::anyhow!("unknown default subscription profile"))?;
    let persisted = state::load(&cfg.state_file)?;
    let confirmed_slot = persisted
        .as_ref()
        .and_then(|st| st.subscription_cache_slots.get(&default_profile))
        .map(String::as_str);
    let nodes = subscription::load_profile_snapshot_from_slot(&profile, confirmed_slot);
    let ss = nodes
        .iter()
        .filter(|n| matches!(n, subscription::Node::Ss(_)))
        .count();
    let with_plugin = nodes
        .iter()
        .filter(|n| matches!(n, subscription::Node::Ss(s) if s.plugin.is_some()))
        .count();
    pln!(
        "  subscriptions: {} profile(s), default {}, {} cached/local node(s) parsed ({} ss, {} anytls), {} with obfs plugin",
        cfg.subscriptions.profile_names().len(),
        default_profile,
        nodes.len(),
        ss,
        nodes.len() - ss,
        with_plugin
    );

    if warnings.is_empty() {
        pln!("no warnings");
    } else {
        for w in &warnings {
            pln!("warning: {w}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncate_handles_zero_and_oversized_limits() {
        // width 0 comes from events_area.width.saturating_sub(2) in a
        // two-column terminal; it must not underflow.
        assert_eq!(truncate("event", 0), "…");
        assert_eq!(truncate("event", 1), "…");
        assert_eq!(truncate("event", 2), "e…");
        assert_eq!(truncate("event", 5), "event");
        assert_eq!(truncate("event", 9), "event");
        assert_eq!(truncate("", 0), "");
    }
}
