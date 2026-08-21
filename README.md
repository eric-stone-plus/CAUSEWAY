# CAUSEWAY

CAUSEWAY is a supervised local egress gateway for a 24/7 quantitative-research
workstation. It exposes a small set of stable loopback endpoints — one per
traffic class — and keeps each of them attached to a healthy upstream,
switching upstreams with zero client-visible downtime. Selection policy is
explicit config: a region allowlist (`selection.regions`, automatic paths
only) and a pinned mode (`selection.auto_switch = false`) where a working
active node never moves without operator action.

One Rust binary, one TOML config file, one systemd user unit. No GUI, no
HTTP/metrics servers — the only runtime control surface is a local Unix
socket used by the bundled `switch` subcommand.

## Principles

- **Userspace only.** The gateway never touches TUN devices, system DNS,
  system routes, or any other system-level network state. Every listener must
  bind a loopback address; anything else is rejected at config-load time.
- **Stability over latency.** A slightly slower healthy path is preferred
  over a marginally faster flaky one. In automatic mode, a challenger must
  beat the incumbent by a clear, configurable margin (hysteresis) before a
  switch is even considered; in pinned mode (`selection.auto_switch = false`)
  no challenger is ever considered — switching is an explicit operator act.
- **Check before switch.** A candidate path is brought up and validated
  end-to-end *before* the route table is flipped in a single atomic write.
  The old path drains in the background and is then retired. Clients observe
  no gap — only a new upstream behind the same local endpoint.
- **State across restarts.** Scores and current routes are persisted
  atomically (tmp + rename). Histories are isolated by subscription profile,
  so equal endpoint names from different sources never contaminate each
  other.
- **Explicit over clever.** The Rust listener performs no payload inspection,
  target parsing, or general-purpose rule evaluation. Each inbound connection
  is classified by its first byte and piped byte-for-byte from then on.
  An optional, exact-host allowlist (`routing.direct_hosts`) is compiled into
  the supervised adapters, so approved API destinations can connect directly
  while all unmatched destinations retain the active node. Changes to this
  list take effect after the daemon is restarted.

## Engineering

- **Class-scoped listeners.** Each traffic class owns one loopback listener
  that speaks both HTTP-CONNECT and SOCKS5, detected per connection by the
  first byte. Connections are piped (L4) into the active data plane, so the
  client-facing endpoint survives data-plane restarts and upstream failover.
- **Supervised data plane.** Upstream transport lives behind a `DataPlane`
  trait. The shipping implementation supervises an external adapter process
  (generated config, backoff restart, graceful drain); an in-process
  implementation can be added as a second `impl DataPlane` without touching
  the listener, scoring, or routing code.
- **Endpoint manifests.** Named subscription profiles are mutually exclusive:
  one profile supplies the live pool at a time. Sources may be local snapshots
  or a private credential file plus an atomic last-known-good cache. Remote
  candidates are fetched, parsed, and checked on staged paths before the live
  pool changes; malformed entries are skipped individually, and unsupported
  entry types are rejected explicitly rather than silently degraded.
- **Scoring.** Periodic bounded-concurrency probes feed a success-rate EMA
  (primary) and an RTT EMA (tiebreaker) per endpoint; the active path
  additionally gets a continuous full-path health check with a configurable
  failure threshold.
- **Observability.** Structured logs to stdout for journald plus a
  daily-rotated JSON Lines file; a `status` subcommand reads the state file
  and works whether or not the daemon is running.

## Build and test

```bash
cargo build                          # debug build
cargo build --release                # deployment build
cargo test --locked --all-features   # unit tests (#[cfg(test)] in each module)
cargo install --path . --locked      # installs the binary to ~/.cargo/bin/causeway
```

Requires Rust 1.85+ (edition 2021). Linux only.

## Run

```bash
cp config.example.toml ~/.config/causeway/config.toml   # adjust to your deployment
scripts/install-dataplane.sh                            # fetch the data-plane adapter
mkdir -p ~/.config/systemd/user
cp systemd/causeway.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now causeway
loginctl enable-linger "$USER"     # optional: run while logged out
```

CLI: `causeway run | probe | status | config check | switch`; bare
`causeway` opens the dashboard TUI — quality-ranked node table with per-node
traffic columns, events feed, `s` subscription picker, `t` end-to-end test of
all nodes, and Tab to cycle classes (plain table when piped) — see `--help`
for details. Logs:
`journalctl --user -u causeway -f`.

### Site freeze awareness (anti-bot)

Scraping stacks routinely share one egress until a site freezes that exit
IP. `[sites.list]` names the sites worth protecting; each entry is probed
per node with a real HTTPS GET (browser User-Agent, status line only) —
the same leg anti-bot systems fingerprint.

```bash
causeway sites                      # freeze matrix: site × node verdicts
causeway sites --probe www.cnbc.com # refresh one site across the pool
causeway switch --class crawler --for-site www.cnbc.com --yes
```

`--for-site` is probe-first automation: the incumbent node is re-probed
unless a verdict younger than `sites.verdict_ttl_secs` exists, and nothing
moves when the site still serves it — a failure inside the scraping stack
never rotates the exit. On a confirmed freeze (401/403/429/451) the next
`sites.max_candidates` score-ordered nodes are probed and the class moves
to the first one the site serves. 5xx and timeouts stay `unknown` and never
steer a switch. Verdicts persist in the state file as an advisory matrix.

A deployment whose default profile is remote-only needs one bootstrap step:
the daemon never fetches at startup, and a first fetch requires the running
daemon's control socket. Prime the profile's `cache_file` once with a
supported manifest (fetch it out of band), or start with a local snapshot
profile and switch.

## Project layout

```
src/
  main.rs          CLI subcommands + logging init
  config.rs        TOML loading and hard validation (loopback-only listeners, …)
  subscription.rs  endpoint-manifest parsing + transactional private cache
  peek.rs          first-byte protocol classifier
  listener.rs      mixed listener, atomic route table, L4 piping
  dataplane.rs     DataPlane trait + supervised external-adapter implementation
  probe.rs         bounded-concurrency TCP probing
  health.rs        minimal full-path health check
  score.rs         EMA statistics + hysteresis decision
  state.rs         atomic state-file persistence (tmp + rename)
  supervisor.rs    orchestration: activation, health loop, probe loop, switching
scripts/           data-plane dependency installers
systemd/           user unit (Restart=always + sandbox hardening)
config.example.toml  configuration reference; every field documented
```

## License

Apache-2.0. See `LICENSE`.
