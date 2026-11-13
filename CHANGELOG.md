# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Documentation
- Refreshed the README with a theme-aware logo, grouped icon badges, clearer
  navigation, and seven screenshots from real isolated Linux sessions.
  Screenshot captions now use consistent small italic text.
- Updated the roadmap around distribution compatibility, the operator panel,
  native packaging and repository inclusion, and protection-module quality.

## v26.11.12a - 2026-11-12

### Added
- **Service-aware authorization:** explicit workload grants matched against
  live listeners, service ownership, destination addresses, interfaces, and
  network zones. Discovery alone does not authorize incoming connections.
  The CLI and TUI support discovery, audit explanations, approval requests,
  and approval history.
- **Connection-aware reply admission:** Linux conntrack checks for replies to
  outgoing IPv4/IPv6 TCP and UDP connections, with managed activation rules
  and recovery if those rules disappear. Optional ICMP Echo Reply validation
  uses the bundled `axdp_icmp` kernel dependency.
- **Optional SYN-cookie protection:** service-aware IPv4/IPv6 challenges,
  listener handoff through a TC ingress companion, and shared challenge,
  validation, and handoff telemetry.
- **Protection-module management:** discovery, installation, configuration,
  draft/save/apply operations, and build/activation diagnostics for built-in
  and custom modules through the CLI and TUI. Modules can declare typed
  compiler settings and kernel dependencies.
- **Paired handler entries and compatible state reuse:** one module can share
  private state between XDP ingress and TC egress. Declared public maps and
  private-state contracts are checked before activation; compatible replacement
  preserves existing state, while incompatible replacement retains the running
  handler.
- **Operator visibility:** responsive dashboard, service approvals, packet
  decisions, handler inventory, and BPF map views; versioned packet events,
  explicit loss counters, bounded relay replay, and optional local GeoIP
  enrichment.

### Changed
- Policy reconciliation now uses a shared configuration snapshot and explicit
  observed, desired, and applied state. Revocation precedes preparation and
  admission, and failed or unconfirmed operations remain visible.
- SYN Cookie, ICMP, and protocol/port/profile handlers use a common module
  lifecycle with verified publication, rollback, and ownership-aware cleanup.
  Minecraft session proof is tied to full policy/profile generations and
  observed server progress.
- Dedicated notification reception and relay wakeups reduce avoidable discovery
  delays. XDP reply paths defer unnecessary timestamp/configuration reads;
  per-CPU traffic totals and batched map verification reduce repeated work.
- Interface discovery uses kernel attributes. Attachment mode and backend
  coverage are verified, container interfaces require explicit opt-in, and ENA
  fallback preserves the configured MTU.

### Fixed
- Grants tied to temporarily absent zone interfaces wait for those interfaces
  instead of widening access. Port inspection reports effective scoped policy.
- Corrected UDP policy structure writes and bounded transport parsing by the
  declared IP length rather than trailing packet bytes.
- Corrected SYN-cookie rate budgets, ACK grace handling, ECN negotiation,
  packet lengths, and native-XDP handoff tailroom. Unsupported or unverifiable
  NAT configurations are rejected before listener handoff.
- Relay reconnects retry while packet events are unavailable, reset retained
  socket history when sessions change, and report listener closure accurately.
- Improved vendor-kernel verifier diagnostics, host architecture build flags,
  and ICMP kfunc resolution on newer kernels. Installed payload validation,
  transactional reload/recovery, and configuration permissions were hardened.

### Upgrade notes
- Back up `/etc/auto_xdp/config.toml`. Non-empty legacy `permanent_ports` rules
  must be migrated to workload exposure grants and zones; empty legacy port
  sections remain accepted.
- Fresh installations start in audit mode. Authorize SSH and intended public
  services, inspect the decisions, then enable enforcement explicitly.
- Upgrade the controller, BPF objects, map manifests, and handlers together.
  Incompatible pinned programs/maps fail readiness checks.
- XDP requires the kernel conntrack lookup/release capabilities checked by the
  loader. Required XDP profiles and SYN-cookie protection remain closed when
  unavailable, including on nftables fallback. Optional SYN-cookie handoff
  also requires request-socket support and a verified NAT-free namespace.
- Optional ICMP validation needs the running kernel's development files and
  module BTF support when its dependency must be built. Secure Boot requires
  a trusted module signature; this dependency is not managed by DKMS.

### Validation
- Release validation passed **11/11 jobs**, including static/type/unit/component
  checks, installer smoke tests, and Ubuntu nftables fallback end-to-end checks.
- Installation, compilation, and overwrite reinstall passed on Debian, Ubuntu,
  Fedora, openSUSE, Arch, Alpine, AlmaLinux, and Rocky Linux containers. These
  share the runner kernel and do not establish eight separate kernel-support
  results.
- Ubuntu XDP lifecycle validation passed **35/35 real kernel integration cases**,
  including generic/native ICMP replies and SYN-cookie native handoff, plus
  upgrade/rollback, uninstall, and reinstall checks. These are functional
  results, not a new throughput or latency benchmark.

[Release and migration details](https://github.com/Kookiejarz/Auto_XDP/releases/tag/v26.11.12a)
· [Release validation](https://github.com/Kookiejarz/Auto_XDP/actions/runs/43178017402)

## 2026-08-31

### Added
- **Atomic nftables policy transactions** (`auto_xdp/backends/nftables.py`):
  the fallback backend now applies ports, ACLs, rate limits, and bogon
  filters as one versioned `nft` batch. Parse or kernel validation failure
  keeps the previous table; v1 → v2 migration preserves active admission
  sets so listeners never pass through an empty generation.
- **Shipped default configuration** (`auto_xdp/default_config.toml`):
  the installer now installs a documented default `config.toml` and the
  package ships it as package data. Operator CLI (`axdp`) no longer carries
  a second copy of the config schema.
- **Hardened BPF dataplane state** (`bpf/include/rate_limit.h`, `tc_flow_track.c`):
  long-lived TCP connections keep prefix and per-port aggregate counters
  alive; map capacities are shared via `map_sizes.h` across XDP, tc, and
  slot handlers.
- **Secured packet-relay lifecycle** (`pkt_relay.py`):
  the Unix event socket now checks peer credentials, locks a pidfile, and
  creates its socket directory with restricted permissions before accepting
  TUI/telemetry clients.

### Fixed
- **Discovery failures no longer wipe policy** (`auto_xdp/syncer.py`):
  initial and periodic `DiscoveryError` keep the last applied policy instead
  of reconciling to an empty port set.
- **Installer bootstrap and release validation** (`lib/setup/`):
  candidate runtime install now merges bootstrap and release checks so a
  staged tree cannot be activated without the packages, BPF objects, and
  service files it needs.

### Changed
- **Layered test suites** (`tests/run.sh`):
  tests register with `# auto-xdp-test-suite:` metadata. Suites are
  `static`, `unit`, `component`, `smoke`, `build`, `kernel`, `installed`,
  and `uninstall`. CI runs a single Full Validation workflow instead of
  separate typecheck / distro / e2e jobs.
- **Installed-lifecycle coverage**:
  new bash contracts cover nftables fallback, upgrade/rollback, installed
  runtime behavior, and complete uninstall residue checks.

## 2026-07-06

### Changed
- **Per-port rate-limit isolation via ARRAY_OF_MAPS** (`bpf/include/maps.h`):
  `syn4`, `syn6`, `udprt4`, `udprt6` are now `BPF_MAP_TYPE_ARRAY_OF_MAPS`
  outers indexed by destination port; the daemon creates one LRU inner map per
  rate-limited port (with fixed capacity matching the compiled inner-map ABI),
  so a flood on one port can no longer evict another port's rate-limit state.
  Pin names are unchanged, but external scripts reading these maps must now
  dereference the inner map by dport.
  Unsupported dynamic inner-map capacity settings are rejected instead of
  silently failing map installation.

### Added
- **Map update failure reporting and kernel state verification** (Python):
  `XdpBackend.apply_reconcile_plan` now counts failed BPF map updates
  (`last_apply_failures`) instead of silently ignoring them; userspace-owned map wrappers
  gain `verify()` which re-reads kernel contents, repairs the local cache, and reports
  discrepancies; the syncer triggers `verify_kernel_state()` after failed applies and on
  the periodic 30s health check, scheduling a corrective sync when drift is found.

## 2026-04-14

### Changed
- **Project renamed from `basic_xdp` to `auto_xdp`**: all paths, configs, nftables tables, and service names updated accordingly.
- **CLI tool renamed from `bxdp` to `axdp`**: installed at `/usr/local/bin/axdp`.
- **Helper module renamed** from `basic_xdp_bpf_helpers.py` to `auto_xdp_bpf_helpers.py`.
- Updated all installation paths: `/etc/auto_xdp/`, `/usr/local/lib/auto_xdp/`, `/run/auto_xdp/`.
- nftables table is now `inet auto_xdp` (was `inet basic_xdp`).

### 🌟 Added

1. Per-IP SYN Rate Limiting (Anti-Brute-Force)
   * xdp_firewall.c: Implemented a new rate-limiting mechanism that tracks SYNs per source IP within a 1-second window. It uses two new BPF maps:
     syn_rate_ports for configuration and syn_rate_map for tracking state.
   * xdp_port_sync.py: Automatically configures these rate limits based on the services detected on whitelisted ports (e.g., stricter limits for sshd and mysqld, higher for mail services).
   * bxdp: Added a new counter SYN_RATE_DROP to track packets dropped by this mechanism.

  2. VLAN Support (802.1Q and QinQ)
      * xdp_firewall.c: Added logic to strip and parse VLAN tags (including double-tagged QinQ). This ensures that firewall rules are correctly applied to the inner IP traffic instead of treating VLAN-tagged packets as generic non-IP traffic.

  3. Improved TCP State Handling

        * ECN-Aware SYN Matching: Updated SYN detection in both xdp_firewall.c and tc_flow_track.c to handle ECN-negotiating SYNs (e.g., flags with ECE or CWR set).

        * Connection Eviction:
            * RST Packets: Now evict conntrack entries and pass to the kernel (instead of dropping) to allow the OS to handle socket cleanup properly.
            * FIN Packets: Connections are now evicted immediately upon seeing a FIN+ACK or standalone FIN, freeing up map slots faster.

        * Scalability: Increased the max_entries for TCP and UDP conntrack maps from 64K to 256K entries.

  4. Build & Environment Updates

        * setup_xdp.sh: Added gcc-multilib to the package installation list to support cross-compilation or specific header requirements.

        * tc_flow_track.c: Increased conntrack map capacity to match the XDP

---

## v26.4.13 - 2026-04-13

### 🌟 Added

- ICMP Token-Bucket Rate Limiter: High-performance XDP-level protection against ICMP/Ping flood attacks.
- Smart IPv6 NDP Awareness: The rate limiter specifically targets Echo Requests while automatically whitelisting critical Neighbor Discovery Protocol (NDP) traffic (RS/RA/NS/NA) to ensure IPv6 connectivity.
- New `CNT_ICMP_DROP` counter for monitoring dropped ICMP packets via global packet counters.

### Improved
- Concurrency safety for rate limiting using `bpf_spin_lock` in XDP maps.
- Precision token refill logic using nanosecond-level time deltas to prevent over-accumulation.

## v26.4.7a - 2026-04-07

### 🌟 Added

- `axdp ports` subcommand to inspect currently allowed TCP/UDP ports.
- Daemon log-level support (`--log-level`) and `axdp log-level` management command.
- Multi-distro environment checks and dry-run validation flow in installer.

### Improved
- Installer package-manager/init-system detection across Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, and Alpine.
- Runtime fallback behavior between XDP and `nftables` backends.
- Conntrack seeding and flow-tracking integration for smoother XDP reload behavior.

### Notes
- This is the first date-based public release tag for Auto XDP.
