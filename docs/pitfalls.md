# Operational pitfalls

Field notes on failure classes this design is meant to avoid. Entries stay
abstract: mechanism and lesson only, never deployment specifics.

## Synthetic-DNS system proxies vs. resolver-validating applications

A system-level proxy that answers every name query with a synthetic address
from a reserved range (a "fake IP" pool) makes resolution untruthful for the
whole host. Any application that resolves a name and then *validates the
answer* before connecting — SSRF guards, egress allow-lists, "private range"
refusals — sees a benchmark/private-class address and fails closed, even for
innocent public targets. The same holds for test suites: tests that exercise
unmocked URL-safety checks fail only while the system proxy is on and pass in
CI, which makes the failures look flaky or merge-related when they are purely
environmental.

Why a loopback-only gateway avoids this class: it never touches TUN, system
DNS, or routes, so name resolution stays truthful host-wide. Clients opt in
per endpoint; everything else keeps its native network semantics.

If such a system proxy must coexist with development workloads, scope its
synthetic answers: keep a filter list of names that must receive real DNS
results (reserved documentation domains, local/development TLDs, and any
domain local tooling is known to validate). Verify per-name after changes —
the synthetic pool must keep serving the names that actually need policy
routing, or the proxy silently loses traffic.

## Two latency populations sharing one EMA

The periodic probe measures TCP connect to the shared front server: fast,
coarse, and blind to egress quality. The on-demand end-to-end test (TUI
`t` / `ProbeNow`) measures a full generate_204 round trip through a fresh
data plane: slow, precise, the real egress health. Both feed the same
success/RTT EMAs, so after a manual test the displayed RTT is a blend of the
two populations and answers neither question cleanly.

Lesson: two measurement populations must not share one rolling statistic
without labelling it. Either keep them separate (display end-to-end RTT
alongside the connect RTT) or define the blended metric explicitly and show
which inputs fed it (last-probe source and age). The same trap applies to
any tool that merges connectivity checks of different depths.

## Subscription retrieval: HTTP success is not manifest success

A subscription link may be a short-lived signed request rather than a stable
file location. Queueing it for later, following a stale redirect, reusing it
after one fetch, or having a skewed system clock can make an otherwise valid
request expire. Keep the complete request target out of logs and shell traces:
its query string may be a credential even when it looks like ordinary URL
metadata.

The fetcher's environment is another independent input. Command-line tools and
services can inherit `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, or `NO_PROXY`
with different values. A provider-side risk control may then see a different
source address, geography, TLS fingerprint, or request sequence and return a
challenge. An HTTP 403 or robot-check page therefore demonstrates an HTTP-layer
policy decision, not that Linux is incompatible. Likewise, HTTP 200 only means
that a response was delivered: login pages, challenges, expired-link notices,
and generic HTML error documents are all commonly returned with status 200.

Diagnose this class without exposing the subscription credential:

- Record the status, redirect count, response size, content type, and request
  time, but redact the complete request target and all authorization material.
  Treat content type as a hint, never as proof.
- Check clock synchronization and compare the fetch time with any documented
  signature lifetime. Obtain a fresh signed link immediately before a retry;
  do not infer endpoint health from an old link.
- Inspect the proxy variables in the *actual fetch process or service*.
  Compare direct and explicitly proxied retrieval only when both paths are
  authorized; do not disable host-wide protections to run the comparison.
- Validate the body structurally before displaying or installing it. Reject
  HTML signatures, parse failures, missing expected top-level fields, and a
  manifest with no supported entries. Avoid dumping challenge bodies because
  they may contain request identifiers or reflected credentials.
- If browser and unattended retrieval differ, compare sanitized request and
  response metadata. Do not copy browser cookies into an automated service or
  attempt to bypass a challenge; use the provider's supported renewal path.

Cache updates must be transactional. Fetch into a mode-0600 temporary file in
the same directory as the cache, validate both the HTTP result and parsed
manifest, flush it, and atomically rename it over the cache only after every
check passes. Serialize concurrent refreshes and retain the last-known-good
manifest on timeouts, 403 responses, HTML bodies, expired signatures, or
zero-entry parses. Store sanitized freshness metadata separately so operators
can distinguish "serving an older valid manifest" from "a refresh succeeded";
never let a superficially successful error page destroy the working cache.

## Default-route changes do not migrate established tunnels

An interface becoming connected is not the same as it becoming the preferred
egress. When wired and Wi-Fi links are both active, the kernel normally keeps
the default route with the lower metric. Connectivity checks may briefly make
the other link the default and then restore the lower-metric route, producing
an apparent switch that lasts only seconds.

An established AnyTLS session cannot follow that change. It is a TLS-over-TCP
connection whose local address and path were selected when its socket was
created; losing the old egress leaves that session stalled until it fails or is
replaced. CAUSEWAY observes the kernel's preferred default-route identity
read-only. After a sustained, debounced change, it stages and checks a fresh
adapter for the same logical node, atomically sends only new connections to
that adapter, and drains the old path. A failed or superseded rebuild preserves
the old route. Health recovery retains the same-node rebuild as a fallback
after alternate candidates fail. Neither path changes link state, route
metrics, policy rules, DNS, or NetworkManager profiles.

Route observation is intentionally conservative: worse-metric backup routes
are ignored, short-lived changes are debounced, rebuilds are rate-limited, and
IPv4/IPv6 route publications for one handover are folded together during the
cooldown. Operator or subscription work takes precedence. This is connection
repair, not interface management. Existing TCP sessions still cannot migrate
and may need their client to reconnect after the old adapter's drain window
expires.
The observer reads the ordinary kernel default-route tables; source-specific,
marked, or policy-routed traffic may select a different egress and is outside
this signal. Full-path health checks remain the authoritative fallback for
those arrangements rather than CAUSEWAY trying to interpret or modify policy
rules it does not own.

Diagnose the two layers independently. Attribute the active default route and
every policy rule first, then inspect the network manager's link and
connectivity history. Separately compare the provider nodes from another
device and an unrelated access network. A failure that follows one host's
interface transition is a local path/reconnection problem; a failure that
follows the same provider across devices and access networks belongs at the
provider entrance, routing, or upstream layer.

## Network incidents: establish ownership before changing state

Several unrelated services can legitimately create proxy processes, network
namespaces, virtual interfaces, policy rules, and route tables on the same
machine. A familiar process or interface name is not proof that CAUSEWAY owns
it. Name-only cleanup can terminate an unrelated workload, while deleting an
unattributed rule or virtual interface can remove the only working management
path and destroy the evidence needed to find the original fault.

Start with read-only inspection. Correlate each process with its service or
cgroup, executable, parent process, start time, user, and network-namespace
identity. Correlate sockets and virtual interfaces with that same namespace
and record the interface index, kind, master, addresses, policy rules, and
route-table references. A process tree alone is insufficient when identical
binary names can run under different supervisors or in different namespaces.

The incident-response red lines are:

- Never use name-wide termination such as `pkill` until every matching PID has
  been attributed. Act through the owning service or exact, revalidated
  process identity when a stop is authorized.
- Never delete an unknown TUN-like interface, `ip rule`, or route table merely
  because it looks stale. Establish its owner and consumers first; preserve a
  read-only snapshot before any authorized change.
- Do not toggle physical links, rewrite DNS or routes, disable host-wide proxy
  protections, restart CAUSEWAY, or change its active node just to compare
  hypotheses. Those actions alter the failure and can interrupt unrelated
  traffic.
- Treat mutation as a separate, explicitly authorized recovery step. Define
  the exact target, expected effect, rollback path, and post-change checks
  before proceeding, and prefer the owning supervisor's normal lifecycle over
  ad-hoc process or network cleanup.

CAUSEWAY's service sandbox reinforces these boundaries by granting no Linux
capabilities, exposing no host network devices, denying namespace creation,
and allowing only Unix and ordinary IP socket families. This is defense in
depth, not an ownership signal: attribution still comes before remediation.

## Reimplementing a kernel text format: the byte-order trap

`/proc/net/tcp` prints each `__be32` address as a host-order u32, so on a
little-endian host loopback appears as `0100007F`, not `7F000001`. A
listener-ownership check that formatted the comparison key with
`u32::from(ip).to_le()` produced `7F000001` — `to_le()` is the identity
function on a little-endian host, so the key could never match anything in
procfs. The check failed closed on every attempt: each adapter process
started healthy and bound its ports correctly, the verifier simply could not
see it, every candidate timed out on readiness, and the gateway tore itself
down to no active path. Because adapter stderr is discarded by design and the
children never errored, the only log line was a readiness timeout with
nothing pointing at the verifier.

Two lessons. First, when matching a kernel-provided text format, construct
the key from the kernel's representation — read the address octets in native
byte order (`u32::from_ne_bytes(ip.octets())`), which reproduces the procfs
view on any host endianness — and never trust byte-order intuition:
`to_le()`/`to_be()` read as direction-of-conversion, not as byte swap, and
silently do nothing when host and target order already agree.

Second, a verification gate that fails closed on every path converts a
one-line formatting slip into a full outage, and it must therefore ship with
a regression test that exercises the real kernel interface (bind genuine
loopback listeners and assert the check finds them), not only pure-function
tests around it. When such a gate does fail, separate child health from
verifier health before changing further state: run the child manually with an
equivalent config, and run the supervisor once outside its sandbox. Here
both checks passed immediately, which isolated the fault to the observer
rather than the observed — without touching the network to find out.
