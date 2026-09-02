# Auto XDP

**Automatically keep a Linux host's firewall policy aligned with the services actually listening on it.**
<p align="center">
  <a href="https://github.com/Kookiejarz/Auto_XDP/wiki"><strong>📑 Manuals & Wiki</strong></a>
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg?style=flat-square" alt="License"></a>
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <a href="https://www.kernel.org/"><img src="https://img.shields.io/badge/Kernel-%E2%89%A55.10-blue.svg?style=flat-square" alt="Kernel >= 5.10"></a>
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <a href="https://github.com/Kookiejarz/Auto_XDP/actions/workflows/distro-check.yml"><img src="https://github.com/Kookiejarz/Auto_XDP/actions/workflows/distro-check.yml/badge.svg" alt="Distro Checks"></a>
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/Init-systemd%20%7C%20OpenRC-555555.svg?style=flat-square" alt="systemd and OpenRC">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <a href="https://ebpf.io/"><img src="https://img.shields.io/badge/Tech-eBPF%2FXDP-brightgreen.svg?style=flat-square" alt="eBPF/XDP"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Debian%2FUbuntu-supported-A81D33.svg?style=flat-square" alt="Debian/Ubuntu supported">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/Fedora%2FRHEL-supported-294172.svg?style=flat-square" alt="Fedora/RHEL supported">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/openSUSE-supported-73BA25.svg?style=flat-square" alt="openSUSE supported">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/Arch-supported-1793D1.svg?style=flat-square" alt="Arch supported">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/Alpine-supported-0D597F.svg?style=flat-square" alt="Alpine supported">
</p>


Auto XDP is a host-side firewall for public and self-hosted Linux machines. It discovers the TCP and UDP sockets that services are listening on and keeps the active filtering policy in sync. When the host supports it, Auto XDP uses XDP/eBPF. It falls back to `nftables` when XDP cannot be attached safely.

It is designed for per-host protection on VPSes, cloud instances, homelabs, and other Internet-facing Linux machines.

> XDP only filters traffic that reaches the host's network interface. If an upstream link is already saturated by a volumetric attack, Auto XDP cannot remove that traffic. Large attacks still require upstream DDoS mitigation.

## Why Auto XDP?

Static firewall rules drift as services come and go. Auto XDP watches listening sockets and updates the policy when a service starts or stops:

- A newly listening service can become reachable without a new manual rule.
- A stopped service no longer remains open because of an old rule.
- Native XDP can drop unwanted packets before they enter the normal Linux networking path.
- The same listener policy can use `nftables` when native XDP is unavailable.

This keeps the firewall tied to what the host is actually exposing, while leaving explicit controls for permanent ports, exclusions, trusted sources, and CIDR-based access rules.

## Auto XDP compared with other firewalls

| Solution | How it gets its policy | Where it filters | Who maintains the rules |
|---|---|---|---|
| **Auto XDP** | Host listening sockets, plus explicit overrides | XDP when available, `nftables` fallback | Auto XDP and the operator's overrides |
| `nftables` | Explicit rules | Linux networking stack | The operator or another automation tool |
| UFW | Explicit rules through a simpler frontend | Its configured firewall backend | The operator or another automation tool |
| Raw XDP/eBPF | Custom program logic | XDP ingress | The program author |

Auto XDP is a good fit when a single Linux host needs a default-deny inbound policy that follows service lifecycle changes. It is not a replacement for upstream filtering, and it does not remove the need to understand which services should be public.

## Requirements

- Linux. Native XDP currently requires kernel 5.10 or newer.
- Python 3.10 or newer.
- `sudo` access.
- One of the supported distributions: Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, or Alpine.
- `nftables` for the fallback backend.

The installer checks and installs the required toolchain, including `clang`, `llvm`, `libbpf`, `bpftool`, and `iproute2`, on supported distributions. See the [compatibility notes](https://github.com/Kookiejarz/Auto_XDP/wiki/Installation-and-Upgrade) before installing on a production host.

## Installation

### Quick Install

Install the latest published release:

```bash
(
  set -e
  # quick-install-version:start
  AUTO_XDP_VERSION=v26.8.13a
  # quick-install-version:end
  auto_xdp_tmp=$(mktemp -d)
  trap 'rm -rf "$auto_xdp_tmp"' EXIT
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -sSfL \
    "https://github.com/Kookiejarz/Auto_XDP/archive/refs/tags/${AUTO_XDP_VERSION}.tar.gz" \
    | tar -xz -C "$auto_xdp_tmp" --strip-components=1
  cd "$auto_xdp_tmp"
  sudo bash setup_xdp.sh
)
```

The release archive keeps the installer, build inputs, Python runtime, and handlers on the same tag. For a source install, use the steps below.

### Install from source

```bash
git clone https://github.com/Kookiejarz/Auto_XDP.git
cd Auto_XDP

# Preview the detected OS, init system, packages, and interfaces
bash setup_xdp.sh --dry-run

# Auto-discover active host ingress interfaces
bash setup_xdp.sh
```

To select an interface explicitly:

```bash
bash setup_xdp.sh eth0
```

To protect all active non-loopback interfaces:

```bash
bash setup_xdp.sh --all-interfaces
```

For release archive installation, upgrades, backend selection, and recovery, see [Installation and Upgrade](https://github.com/Kookiejarz/Auto_XDP/wiki/Installation-and-Upgrade).

## Common commands

```bash
# Show the active backend and its health
sudo axdp backend

# List ports allowed by the current policy
sudo axdp ports

# Show packet counters
sudo axdp stats

# Open the live terminal interface
sudo axdp tui
```

A quick check of automatic synchronization:

```bash
sudo axdp ports
python3 -m http.server 8080 &
sudo axdp ports
kill %1
```

After the next policy sync, port 8080 should appear while the server is running and disappear after it stops.

## Important behavior

Auto XDP treats a socket bound to a non-loopback or wildcard address, such as `0.0.0.0` or `::`, as potentially public. Use discovery exclusions or explicit ACLs for private and management services. The [Configuration Reference](https://github.com/Kookiejarz/Auto_XDP/wiki/Configuration-Reference) covers these settings.

## Documentation

- [Wiki home](https://github.com/Kookiejarz/Auto_XDP/wiki)
- [CLI reference](https://github.com/Kookiejarz/Auto_XDP/wiki/CLI-Reference)
- [Configuration reference](https://github.com/Kookiejarz/Auto_XDP/wiki/Configuration-Reference)
- [Architecture and packet flow](https://github.com/Kookiejarz/Auto_XDP/wiki/Architecture-and-Packet-Flow)
- [Security policies and rate limits](https://github.com/Kookiejarz/Auto_XDP/wiki/Security-Policies-and-Rate-Limits)
- [Operations and troubleshooting](https://github.com/Kookiejarz/Auto_XDP/wiki/Operations-and-Troubleshooting)
- [Testing and development](https://github.com/Kookiejarz/Auto_XDP/wiki/Testing-and-Development)
- [Uninstall and recovery](https://github.com/Kookiejarz/Auto_XDP/wiki/Uninstall-and-Recovery)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines and local test commands.

## License

[MPL 2.0](./LICENSE) © 2026 Yunheng Liu
