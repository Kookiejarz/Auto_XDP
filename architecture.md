# Auto XDP: workload-aware exposure

Auto XDP has two decisions in separate layers:

```text
operator intent + live endpoint + workload attribution + ingress zone
                              -> effective exposure
```

`LISTEN != AUTHORIZATION`. The control plane discovers runtime endpoints and
compiles only approved endpoints into the existing XDP or nftables backend.
The dataplane never needs to understand PIDs, systemd, containers, or policy
files.

## Runtime objects

`RuntimeEndpoint` records protocol, bind address, port, bind scope, ingress
zone, subject, attribution state, and evidence source. Bind scope is descriptive:
`0.0.0.0:5432` is a wildcard bind, not a public-access grant.

Attribution is evidence, not authentication:

| State | Evidence | Exposure behavior |
|---|---|---|
| `exact` | systemd cgroup or socket activation target | may match a grant |
| `delegated` | explicit process-name mapping | may match a grant |
| `shared` | more than one owner on a port | only compatible grants may match |
| `ambiguous` / `unknown` | no safe owner | deny; never widen exposure |

The Linux observer uses SOCK_DIAG, `/proc`, systemd socket listings, and
systemd cgroup paths. Docker/Podman attribution is not silently inferred; it is
a follow-up feature with its own runtime evidence.

## Policy

Policy is TOML because it is the project's existing configuration format:

```toml
[policy]
mode = "enforce" # observe | audit | enforce

[zones.public]
interfaces = []

[zones.trusted]
interfaces = ["tailscale0", "wg0"]

[unknown_subjects]
public = "deny"
trusted = "deny"

[subjects.minecraft.resolve]
systemd_unit = "minecraft.service"

[subjects.minecraft.exposure.public.tcp]
ports = [25565]

[subjects.minecraft.protection]
profile = "minecraft"
```

The resolver evaluates, in order:

1. a live endpoint exists;
2. its ownership matches a configured subject;
3. the subject has a grant for its zone, protocol, and port;
4. the optional protection profile is attached to that already-authorized port.

No listener, service-name catalog, trusted source, or protection profile can
create an exposure grant. Public grants use the global port maps; non-public
grants use interface-index/port maps (or equivalent nftables interface rules).
When several owners share one port, incompatible protection profiles close the
port because the runtime inventory cannot prove one compatible policy.

`observe` prints endpoint evidence and makes no backend changes. `audit` also
compares the runtime inventory with grants and makes no backend changes.
`enforce` reconciles the approved live set. Every decision can be printed with
`xdp_port_sync.py --mode audit --explain`; reconcile latency is logged in
milliseconds.

## Control and data planes

```text
systemd / sockets / containers
              |
              v
       Runtime endpoint observer
              |
              v
       Workload attribution
              |
              +--> Exposure grants
              +--> Protection profiles
              |
              v
       Policy reconciler + explanation
              |
              v
       XDP maps or atomic nftables ruleset
              |
              v
       XDP ingress -> Linux network stack
```

XDP consumes ingress-interface/protocol/port policy, source ACLs, rate limits,
and handler state. The `minecraft` profile automatically binds a per-port XDP
handler before exposure. It validates the Minecraft Java handshake and first
status/login packets, rate-limits status and login attempts by source prefix,
and uses Linux conntrack plus TC egress server progress to verify a session.
The bounded `mc_verified` LRU stores full 64-bit policy/profile generations;
the compact connmark is only a hint, never sufficient authorization. Generation
changes or missing proof records revoke an already verified flow without
reopening handshake probation. Server replies must traverse this host's egress
hook. If XDP or the handler is unavailable, the
profile's ports remain closed instead of silently falling back to generic
nftables protection.

The base XDP program also queries Linux conntrack for TCP/UDP IPv4/IPv6 replies
before checking service exposure, but after packet validation. Only confirmed
connections in REPLY direction receive this exception: inbound service traffic
in ORIGINAL direction still traverses authorization, limits and handlers.
The first UDP reply and TCP SYN-ACK need not have SEEN_REPLY/ESTABLISHED yet.
XDP lookup neither creates nor refreshes entries; the normal stack owns their
timeouts, TCP validation, NAT and teardown. No custom connection table or generic
TC egress tracker is maintained.

Startup activates namespace-local IPv4/IPv6 conntrack hooks using the owned
`inet auto_xdp_conntrack` nftables table (an output counter, no packet verdict).
Successful candidate loading verifies the lookup/release kfuncs before replacing
the running XDP program. Missing activation support fails startup; normal
transactional fallback rules still apply. Stop preserves this table with the
active data plane; full disable and uninstall remove it without flushing other
rules or connection entries. The 12-byte lookup ABI uses the ingress device's
network namespace and conntrack zone 0 (not an Auto XDP exposure zone).
NOTRACK, nonzero conntrack zones, or connections tracked only in another netns
do not get the reply exception. Host SNAT reply tuples are supported; arbitrary
cross-namespace/container routing requires separately verified hook placement.

The XDP backend requires Linux conntrack lookup kfuncs; unavailable
profile protection remains closed. Optional SYN-cookie request-socket handoff
also rejects NAT or unverifiable NAT state in its network namespace, since NAT
LOCAL_IN can clear the assignment before TCP consumes it. Auto XDP does not
implement IP fragment reassembly.

## Safety rules

- Malformed TCP/UDP packets, truncated Ethernet/VLAN/IP headers, and IP
  fragments that cannot be classified safely are dropped before policy lookup.
- Unsupported protected protocol cases are dropped or explicitly delegated to
  a backend that can classify them.
- A missing or failed discovery snapshot does not replace the last known-good
  backend state with an empty policy.
- New protection state is prepared before a newly authorized port is exposed;
  closing a port happens before its supporting state is removed.
- Relay, TUI, and packet telemetry are observability only and cannot widen or
  disable enforcement.

## Current implementation map

| Concern | Implementation |
|---|---|
| management commands, approvals and shared readers | `auto_xdp/admin/` |
| endpoint model | `auto_xdp/state.py` |
| socket and cgroup observation | `auto_xdp/discovery/listeners.py` |
| process/socket events and local service names | `auto_xdp/discovery/` |
| TOML policy validation | `auto_xdp/config.py` |
| grant compilation and explanations | `auto_xdp/policy.py` |
| observe/audit/enforce and latency | `auto_xdp/syncer.py`, `auto_xdp/cli.py` |
| fast ingress enforcement | `bpf/xdp_firewall.c`, `bpf/include/`, and zone-port maps |
| backend application | `auto_xdp/backends/xdp.py`, `nftables.py` |
| packet-event emission and loss counters | `bpf/include/telemetry.h`, `counters.h` |
| stable reason catalogue and v1/v2 event decoder | `auto_xdp/telemetry/events.py` |
| ring consumption, bounded replay, relay health | `pkt_relay.py` |
| socket client, session/sequence deduplication | `auto_xdp/telemetry/relay_client.py` |
| retained sample aggregation and diagnostic models | `auto_xdp/telemetry/traffic.py` |
| optional local country/ASN enrichment | `auto_xdp/telemetry/geoip.py` |
| observation rendering and shared curses primitives | `auto_xdp/tui/traffic.py`, `auto_xdp/tui/widgets.py` |
| TUI navigation, snapshots and management pages | `auto_xdp/tui/app.py` |

The package root keeps configuration, policy, state and reconciliation modules.
`auto_xdp.admin_cli` remains a compatibility command entry point; current callers
use `auto_xdp.admin.cli`. The installer preserves nested package paths, discovers
update candidates recursively, and validates imports against the installed
payload independently of the source checkout.

The observation path is `XDP/TC → counters/ringbuf → relay → client → views`.
TC handoff counters reuse the main pinned counter map. Built-in tail-call
programs account for their terminal verdict exactly once, since successful BPF
tail calls do not return to the main program's accounting wrapper. Custom
handlers must explicitly implement this shared-map contract to contribute to
the totals; loading arbitrary external handlers does not imply full coverage.

Event v2 keeps the original 48-byte prefix and appends ingress ifindex, original
frame length, and version metadata (64 bytes total). The new relay supports both
versions. Counter IDs are append-only, but increasing the counter array capacity
changes its map ABI and requires coordinated program/map loading. Diagnostic
stages overlap and must never be summed into packet totals. Unknown or absent
metrics remain unknown, including when reading older producers.

Source summaries use the same retained client window as DROP distributions.
Only displayed addresses are enriched, using local databases and a bounded
cache; neither the dataplane nor the ring consumer performs GeoIP lookup.
See the [observation guide](./plans/information-plane.md) for operational limits.

## V1 boundary

Implemented here: TCP/UDP/SCTP endpoint inventory, normal systemd and socket
activation attribution, separate bind scope and ingress zone, explicit grants,
explainable decisions, effective-port reconciliation, stale exposure removal,
latency measurement, and fail-closed structural parsing.

Implemented after the V1 baseline: Docker/Podman published-port attribution,
including NAT-only publications, and the approval workflow.

Deferred until separately evidenced: additional service-specific profiles,
optional kernel conntrack lookup, destination-address/CIDR zone keys, strict
per-packet workload authentication, full L7 inspection, custom BPF conntrack,
and upstream volumetric mitigation.
