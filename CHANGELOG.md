# Changelog

All notable changes to this project are documented in this file.


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
