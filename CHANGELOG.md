# Changelog

All notable changes to this project are documented in this file.


## v26.4.13 - 2026-04-13

### Added
- ICMP Token-Bucket Rate Limiter: High-performance XDP-level protection against ICMP/Ping flood attacks.
- Smart IPv6 NDP Awareness: The rate limiter specifically targets Echo Requests while automatically whitelisting critical Neighbor Discovery Protocol (NDP) traffic (RS/RA/NS/NA) to ensure IPv6 connectivity.
- New `CNT_ICMP_DROP` counter for monitoring dropped ICMP packets via global packet counters.

### Improved
- Concurrency safety for rate limiting using `bpf_spin_lock` in XDP maps.
- Precision token refill logic using nanosecond-level time deltas to prevent over-accumulation.

## v26.4.7a - 2026-04-07

### Added
- `bxdp ports` subcommand to inspect currently allowed TCP/UDP ports.
- Daemon log-level support (`--log-level`) and `bxdp log-level` management command.
- Multi-distro environment checks and dry-run validation flow in installer.

### Improved
- Installer package-manager/init-system detection across Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, and Alpine.
- Runtime fallback behavior between XDP and `nftables` backends.
- Conntrack seeding and flow-tracking integration for smoother XDP reload behavior.

### Notes
- This is the first date-based public release tag for Basic XDP.
