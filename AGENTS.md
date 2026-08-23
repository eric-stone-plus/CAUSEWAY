# AGENTS.md — CAUSEWAY project conventions

## What this is

A supervised local egress gateway for a 24/7 quant research workstation
(Arch, x86_64). Single Rust crate, single binary: `src/main.rs` entry,
modules flat in `src/`.

## Build and test

```bash
cargo build
cargo build --release
cargo test --locked --all-features
cargo clippy           # before committing (not a hard gate)
```

- Rust 2021, `rust-version = 1.85`. Dependencies stay mainstream and mature;
  **justify every new dependency** — KISS.
- Toolchain/mirror config (if any) belongs in `~/.cargo/config.toml`, never in
  the repo.

## Design red lines (violation = rejection)

1. Userspace TCP only: never touch TUN / system DNS / system routes / any
   system-level network state. Loopback-only listeners, enforced by
   `config.rs` validation — do not relax it.
2. No GUI, no HTTP/metrics servers. Runtime control is exactly one local
   Unix socket in the state dir (`src/control.rs`, mode 0600, newline JSON),
   used only by the bundled `causeway switch` subcommand — nothing network
   reachable. Exactly one TOML config file.
3. Stability over latency: switch conservatively, never flap eagerly.
   Hysteresis lives in `src/score.rs`; any change must update its unit tests
   in the same commit.
4. Explicit over clever: the Rust gateway performs no payload inspection,
   target parsing, or general-purpose rule engine. Protocol detection is only
   the first-byte classifier in `src/peek.rs`. A user-configured exact-host
   allowlist may be compiled into supervised adapters for direct API egress;
   the listener itself never evaluates those destinations.
5. **No real endpoint data in the repo, ever** (servers, ports, credentials,
   manifest contents). Test fixtures must use documentation addresses
   (RFC 5737). Manifests are read at runtime only, from files outside the
   repo.
6. **Public-facing text (README, docs, package metadata) stays abstract**:
   engineering principles and architecture only — no listen ports, no
   data-plane implementation names, no deployment specifics.

## Code map

- `src/main.rs` — clap subcommands (run/probe/status/config check/switch) +
  tracing init.
- `src/control.rs` — the one runtime control surface: a 0600 Unix socket in
  the state dir, newline-delimited JSON (ping/status/switch), plus the
  one-shot client used by `causeway switch`.
- `src/switch.rs` — nmtui-style interactive node switcher (ratatui +
  crossterm); plain status report when stdout is not a terminal.
- `src/config.rs` — TOML loading, `~` expansion, hard validation.
- `src/subscription.rs` — offline endpoint-manifest parsing, per-entry fault
  tolerance; unsupported entry types are rejected explicitly at parse time.
- `src/peek.rs` — first-byte HTTP/SOCKS5 classifier.
- `src/listener.rs` — mixed listener + atomic route table +
  `copy_bidirectional` piping.
- `src/dataplane.rs` — `DataPlane` trait + supervised external-adapter
  implementations, dispatched by entry type (one process per active endpoint,
  generated config, transport-plugin injection when an endpoint declares one;
  never silently fall back to a plain connection).
- `src/probe.rs` — TCP connect RTT, semaphore-bounded concurrency.
- `src/health.rs` — minimal full-path health check (deliberately no HTTP
  client crate).
- `src/score.rs` — EMA + hysteresis decision (the stability core; keep test
  coverage intact).
- `src/state.rs` — atomic state-file read/write (tmp + rename).
- `src/supervisor.rs` — orchestration: activation, health loop, probe loop,
  check-then-switch, draining.
- `scripts/` — data-plane dependency installers.
- `docs/` — operational pitfalls and field notes (abstract; no deployment specifics).
- `systemd/causeway.service` — user unit (Restart=always + sandboxing).
- `config.example.toml` — configuration reference; any field change must be
  mirrored here.

## Conventions

- English only across the repo: identifiers, comments, docs, log/error
  strings. Comments explain *why*, never *what*.
- thiserror for library modules, anyhow at the application layer; startup
  failures must produce actionable messages.
- Logging via tracing; no `println!` on the `run` path (CLI reports
  excepted).
- New logic ships with unit tests; network-touching tests may only use
  `127.0.0.1`.
- **Agents never run `git commit` / `git push` / create remotes** unless the
  user explicitly asks in the moment. Standing exception (operator decision
  2026-08-23): commits and pushes authored as
  `eric-stone-plus <eric-stone-plus@users.noreply.github.com>` are
  pre-authorized.
- When explicitly authorized to commit, preserve contributor identity:
  agent-authored commits use the agent's GitHub-linked Git author identity,
  not the human operator or only a co-author trailer; human-authored commits
  retain the human author.

## Status

P1 complete and validated on the live host. Backlog: in-process data-plane
implementation, per-class endpoint-pool filtering, connection-counted
draining, UDP.
