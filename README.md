# Auto XDP

**Keep a Linux host's exposure aligned with explicit workload grants and live service state.**
<p align="center">
  <a href="https://axdp.dev/"><strong>🌐 Website</strong></a>
  ·
  <a href="https://github.com/Kookiejarz/Auto_XDP/wiki"><strong>📑 Manuals & Wiki</strong></a>
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg?style=flat-square" alt="License"></a>
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <a href="https://www.kernel.org/"><img src="https://img.shields.io/badge/Kernel-XDP_CT_kfuncs-blue.svg?style=flat-square" alt="Kernel with XDP conntrack kfuncs"></a>
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


Auto XDP is a host-side exposure controller and firewall for public and self-hosted Linux machines. It discovers TCP/UDP endpoints, attributes them to workloads when runtime evidence permits, and keeps only explicitly granted live exposure in sync. When the host supports it, Auto XDP uses XDP/eBPF. It falls back to `nftables` when XDP cannot be attached safely.

It is designed for per-host protection on VPSes, cloud instances, homelabs, and other Internet-facing Linux machines.

> XDP only filters traffic that reaches the host's network interface. If an upstream link is already saturated by a volumetric attack, Auto XDP cannot remove that traffic. Large attacks still require upstream DDoS mitigation.

## Why Auto XDP?

Static firewall rules drift as services come and go. Auto XDP watches runtime endpoints and updates the policy when a service starts or stops:

- A newly listening service becomes reachable only when a matching workload grant exists.
- A stopped service no longer remains open because its runtime justification disappeared.
- Native XDP can drop unwanted packets before they enter the normal Linux networking path.
- The `minecraft` profile validates Java handshakes/login traffic using Linux conntrack and observed server progress. Verified sessions require matching full policy/profile generations; loss of their bounded proof record revokes admission. Server replies must traverse the protected host's TC egress hook. Split or opaque initial frames receive only bounded probation, not verified status; use a TCP-reassembly-aware profile when that limit is unsuitable.
- The same listener policy can use `nftables` when native XDP is unavailable.

This keeps the firewall tied to both operator intent and current runtime state. Legacy `permanent_ports` configuration is rejected; exposure must use workload grants and zones.

A grant restricted to named zone interfaces waits while those interfaces are
absent; it never becomes an unrestricted grant. Other grants keep working. The
next reconciliation applies it when the interface appears, while interface
lookup errors remain explicit failures. This does not attach XDP to new devices.

Optional SYN-cookie listener handoff requires the kernel request-socket helper
(normally Linux 6.11+) and a verifiably NAT-free network namespace. NAT LOCAL_IN
can discard the assigned request socket before TCP accepts it; Auto XDP refuses
this combination instead of changing host NAT. Strict cookie mode fails closed.

SYN-cookie rate budgets count SYNs for the entire port. The default base is
`max(1000, per-source SYN limit)`; an explicit per-port base of zero disables
rate triggering while `always` still challenges every SYN. ACK validation keeps
a grace window after challenges, preserves existing and closing connections,
and negotiates ECN consistently with the host listener.

## Auto XDP compared with other firewalls

| Solution | How it gets its policy | Where it filters | Who maintains the rules |
|---|---|---|---|
| **Auto XDP** | Explicit workload grants intersected with live endpoints | XDP when available, `nftables` fallback | Auto XDP and the operator's grants |
| `nftables` | Explicit rules | Linux networking stack | The operator or another automation tool |
| UFW | Explicit rules through a simpler frontend | Its configured firewall backend | The operator or another automation tool |
| Raw XDP/eBPF | Custom program logic | XDP ingress | The program author |

Auto XDP is a good fit when a single Linux host needs a default-deny inbound policy that follows service lifecycle changes. It is not a replacement for upstream filtering, and it does not remove the need to understand which services should be public.

## Requirements

- Linux with XDP conntrack lookup/release kfuncs for the XDP backend; the installer verifies the actual kernel capability before attachment.
- Python 3.10 or newer.
- `sudo` access.
- One of the supported distributions: Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, or Alpine.
- `nftables` for the fallback backend and namespace-local conntrack activation on XDP.

TCP/UDP replies to outgoing connections are admitted by exact Linux conntrack
tuple and REPLY direction, without exposing local ephemeral ports. Incoming
service requests still require workload grants even after the server replies.
The XDP backend owns `inet auto_xdp_conntrack`, a counter-only activation table;
it does not replace your firewall or NAT rules. Full disable/uninstall removes
this table. Lookup currently supports conntrack zone 0 in the ingress network
namespace; NOTRACK and other conntrack zones do not receive this exception.

While enforcement is active, the daemon checks this activation table every five
seconds and restores it if removed or emptied. It leaves tables owned by other
software untouched and backs off failed checks, up to five minutes.

The installer checks and installs the required toolchain, including `clang`, `llvm`, `libbpf`, `bpftool`, and `iproute2`, on supported distributions. See the [compatibility notes](https://github.com/Kookiejarz/Auto_XDP/wiki/Installation-and-Upgrade) before installing on a production host.

`interfaces.xdp_mode = "auto"` prefers generic XDP on explicitly included veth
interfaces. Native veth XDP can disable the peer's TCP segmentation offloads and
introduce a receive-queue bottleneck, reducing permitted TCP throughput even
with a small BPF program. Other interfaces restore their last verified mode,
or try native first. The alternate mode is tried when the first mode is
unsupported, when the ENA driver reports a native-XDP MTU limit, or when a
verified native/generic conflict requires retaining the already active mode.
ENA fallback leaves the interface MTU unchanged. An explicit `native` or
`generic` setting stays strict.
Permission, resource, configuration, and unclassified attachment errors stop
activation and block automatic nftables fallback; diagnostics retain each
attempt's mode and error. Native attachment alone does not
guarantee faster permitted traffic.

Automatic discovery uses kernel interface types rather than name prefixes.
Loopback, veth, dummy, ifb, netkit, and non-Ethernet interfaces are excluded;
bridges, bonds, VLANs, TAP, and unknown types remain candidates. Use
`interfaces.exclude` for container bridges or other devices managed elsewhere.
Discovery failures stop installation instead of selecting only the default
route. `axdp backend` reports newly eligible interfaces without XDP coverage;
automatic selection is marked degraded until coverage or configuration is
updated. Explicitly excluded interfaces remain excluded when they appear later.
This XDP coverage check does not apply to the nftables INPUT hook.

Reload replaces programs within their active mode without detaching protection.
An already attached native veth program can therefore remain native during an
upgrade. Apply a mode change with a full `axdp disable` / `axdp enable` cycle;
this temporarily disables filtering. A clean start in auto mode chooses generic
for veth even if machine state recorded native previously.

The runtime, CLI, and TUI read numeric XDP modes from `ip -j -d link` output.
Interface names, aliases, and program names do not determine the attachment
mode. Unreadable state is reported as unknown; multiple attached modes are
reported separately from a single native or generic attachment.

## Installation

### Quick Install

Install the latest published release:

```bash
(
  set -e
  # quick-install-version:start
  AUTO_XDP_VERSION=v26.11.12a
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

# Inspect runtime ownership and grant decisions without changing the firewall
sudo xdp-port-sync --mode audit --explain

# Show packet counters
sudo axdp stats

# Open the live terminal interface
sudo axdp tui
```

Fresh installs remain audit-only until explicitly enabled. Review the live
inventory, grant required services (SSH first on remote hosts), then activate:

```bash
sudo axdp discover
sudo axdp allow ssh.service tcp/22 --zone public
sudo axdp allow paper.service tcp/25565 --zone public --profile minecraft
sudo axdp enable
```

All persistent policy changes go through `axdp`; BPF maps and the managed
nftables table are derived runtime state. Use `sudo axdp deny SERVICE PROTO/PORT`
to remove a grant and `sudo axdp disable` to detach the managed data plane while
continuing service discovery in audit mode.

A quick check of service-aware synchronization:

```bash
sudo axdp ports
python3 -m http.server 8080 &
sudo xdp-port-sync --mode observe --explain
kill %1
```

Port 8080 is reported as an unapproved endpoint unless its process is mapped by a matching subject grant. See [architecture.md](./architecture.md) for the policy format and the legacy compatibility boundary.

## Custom port handlers

Custom TCP/UDP port handlers can be loaded with
`sudo axdp port-handler load udp 30120 /path/to/handler.c` (or a compiled `.o`).
The loader inspects the object with libbpf and reuses only declared public maps:
`slot_ctx_map`, `hblk4`, `hblk6`, `udp_hv4`, `udp_hv6`, `pkt_counters`,
`byte_counters`, `pkt_ringbuf`, and `xdp_runtime_cfg`. Other maps remain private
to the handler. A declared public map requires an existing compatible pinned
instance; missing or incompatible maps reject the candidate before replacing
the active handler. A handler that parses packets and keeps its own state can
declare no shared maps. Loading a handler does not create a service grant or
automatically add its verdicts to the main counters. Built-in protocol handlers
and required TCP protection profiles retain their required-map checks.

## Packet observations

`sudo axdp tui` opens a dashboard with RX/TX history, current packet and bit
rates, protection mode, CPU/memory meters, allowed services, recent events, and
BPF map capacity. The layout adapts to terminals of at least 80 columns by 20
rows. Interface traffic comes from Linux network counters; XDP totals and drops
come from dedicated BPF counters. Initial or unavailable rates display `--`.
Fixed-size array maps display `fixed`, rather than a capacity warning; `~` marks
sampled or cached map counts.
In audit and observe mode, the dashboard remains available without an active
firewall. Its mode badge says `not filtering`, discovered ports are marked
`not active`, and Maps explains when XDP is inactive. Enforcement failures
remain visible as errors. Audit and observe commands use the configured mode
without requiring a packet-filtering backend.
All pages use the current terminal width and height, including Overview,
Sources, Events, Health, Maps, Audit, Requests, Handlers and handler forms.
Tables redistribute their columns as the window grows or shrinks; taller
windows show more rows. Overview panels and the navigation bar also expand
with the terminal. Input pages preserve typed text when resized, scroll long
paths horizontally, and support Enter, Esc, arrow keys and Ctrl-U.

The full Maps page sizes columns to the current terminal and map names. Wider
screens show map IDs, count sources and occupancy bars; narrow screens retain
the map name, type, used/max counts, usage and memory. Long names use an ellipsis
when they cannot fit. Resizing reallocates column widths immediately, and the
overview's smaller map panel also uses all its available width.
The memory column uses the kernel's `bytes_memlock` report, including
preallocated map storage. Press `b` on Maps to switch each row to exact bytes;
the footer also shows the total in bytes. Nested handler map pins are included,
and aliases to the same map ID count once. This is the reported memory of the
listed pinned maps; unpinned and map-in-map inner allocations are not included.
An unavailable memory report stays unknown rather than becoming zero.

Use `Tab` to focus ports, maps, or events, then the arrow keys to scroll. `t`/`u`
toggle TCP/UDP ports; `Enter` on a port filters retained events. `m` opens the
full maps table, `e` packet events and detailed DROP reasons, `v` retained source
samples and optional country/ASN information, and `c` SYN cookie diagnostics and
observation health. `h` opens Handlers & slots: actual protocol slots, TCP/UDP
port handlers, TCP profiles and the SYN-cookie dispatch entry, with program IDs,
names, ownership pins and configured paths. `loaded` means a live dispatch-map
entry; `pin only` and `configured` do not imply that packets reach the program.
`PROGRAM`, `STATE`, `HOOK / TARGET` and `PROG ID` show each module
and its hook, protocol, port or profile binding. Catalog candidates
show their intended target without claiming
an active hook. Navigation tabs stay compact even on wide terminals.
The main firewall, socket tracker, TC dispatcher and SYN handoff infrastructure
are hidden from this handler list; configurable modules remain visible.
The inventory refreshes while this page is open, without changing attachments.
`a` opens the authorization audit, `p` approval requests,
`o` returns to the overview, and `q` exits.
In Audit, select a denied endpoint and press Enter to review an approval.
Root access and explicit confirmation are required. The prompt identifies
the workload, zone, protocol and port and states that the grant covers all
addresses. Unknown identities and policy conflicts must be resolved first;
the endpoint is checked again after confirmation to reject stale selections.
Approval preserves audit or observe mode; enabling enforcement is separate.
Events retain live following across page changes and resizes; scrolling up
pauses the list, and scrolling back to the bottom resumes it.
Mouse support is enabled when the terminal supports it: click a tab to switch
pages, click a panel to focus it, click a port to select it, double-click a port
to open its retained events, and use the wheel to scroll the panel under the
pointer. Click the filtered event view's title to clear its port filter.
Clicking an approval request only selects it; approval actions retain
their keyboard controls. Hold `Shift` to select terminal text with the mouse,
or press `F2` for copy mode: the TUI releases the mouse and freezes the display
so ordinary dragging can select text without refreshes clearing the selection.
Use your terminal's copy shortcut, then press `F2` again to resume the display
and its previous mouse mode. Background collection and relay consumption
continue; other navigation and approval keys are ignored while copying.
Resizing redraws the paused display once, and `q` still exits.

When `[under_attack].enabled = true`, packet event recording is suppressed to
reduce overhead; packet/drop counters continue updating. The TUI checks the
runtime flag and shows why records are absent. Socket state notifications are
displayed separately from packet fields. Use `sudo axdp under-attack off` to
resume packet records when desired. `skip` in a map's entry count means its
contents were deliberately not sampled in this performance mode. Metadata is
matched by the full BPF pin path, so truncated or duplicate kernel map names do
not lose the type, capacity, or map ID.

The red `EVENTS SUPPRESSED` badge refers to packet records; socket notifications
can still arrive. Socket notifications are event history, not current listener
state; TCP4/TCP6 identify the address family. The kernel tracepoint also observes
other network namespaces, and these records do not identify the namespace or
prove which current service owned the event. Distinct events remain visible;
replaying the same relay event does not add another row. A new relay session
clears the old retained window so notices from an earlier helper generation do
not linger after an upgrade. With recording enabled, Recent events shows packet time,
PASS/DROP, protocol, source address/port, destination port and service, plus the
reason when space permits.
The full Events page also shows destination address, ingress interface index,
recorded packet length and reason details. The standard path records new TCP
SYN allows, drops and selected SYN cookie results; established TCP passes and
normal UDP passes are not a per-packet log. Custom handlers may have different
event coverage. The service label uses current discovered endpoints, matched by
protocol, destination address and port. `unknown`/`ambiguous` avoid guessing an
owner; `port:name` is only a services-database label for an active port. These
labels are current inventory, not historical ownership. Service inventory and
authorization decisions remain available in Ports and Audit independently of
packet recording.

Packet totals come from dedicated BPF counters. Event lists and source rankings
are bounded, potentially lossy samples, not full traffic or attacker attribution.
The health page separates BPF event loss, relay queue loss, and truncated replay.
With `--wait-for-ringbuf`, the relay serves its local socket while waiting
for XDP packet events. Audit and observe mode report `waiting for XDP`;
enforcement failures and permission errors remain visible. The relay retries
automatically and reports connected once the packet ring becomes available.
Cookie ACK validation and successful TC handoff do **not** prove application
acceptance. These changes do not enable SYN cookies or alter exposure grants.

GeoIP is disabled by default and uses local MMDB files only.

## Real-World Performance Benchmark

This historical benchmark simulates a volumetric UDP flood. An AMD EPYC™ 7Y43 server generated approximately 367k packets per second (188 Mbps) against a 1 vCPU AMD Ryzen 9 3900X instance protected by Auto XDP.

| Metric | Auto XDP off | Auto XDP on | Improvement |
|---|---:|---:|---:|
| Softirq CPU usage | **85.9%** | **3.0%** | **~28× reduction** |
| System responsiveness | Extremely laggy | **Smooth** | Significant |
| Packet handling | Kernel networking stack | Driver-level drop | — |

The result shows the expected difference between processing the flood in the kernel networking stack and dropping it at the XDP hook. It is a historical measurement, not a current performance guarantee; hardware, kernel, driver, traffic shape, and XDP mode affect the result.

### Test environment

- Attacker: AMD EPYC™ 7Y43 @ 2.55 GHz, approximately 367k PPS / 188 Mbps
- Target: AMD Ryzen 9 3900X @ 2.0 GHz, 1 vCPU, 1 GB RAM
- Tool: `pktgen` (Linux kernel packet generator)
- Attacker and target connected over the public internet

### How to reproduce

Run on a disposable, privileged Linux host. Replace `INTERFACE`, `TARGET_IP`, and `TARGET_MAC` with the target values:

```bash
modprobe pktgen

PGDEV=/proc/net/pktgen/INTERFACE
echo "rem_device_all" > /proc/net/pktgen/kpktgend_0
echo "add_device INTERFACE" > /proc/net/pktgen/kpktgend_0

echo "count 10000000" > "$PGDEV"
echo "pkt_size 64" > "$PGDEV"
echo "dst TARGET_IP" > "$PGDEV"
echo "dst_mac TARGET_MAC" > "$PGDEV"
echo "clone_skb 100" > "$PGDEV"
```

## Important behavior

Auto XDP treats bind scope and ingress zone as separate facts. A wildcard bind such as `0.0.0.0` or `::` is not authorization; service-aware mode requires a matching subject grant. Use `observe` or `audit` before enabling `enforce` on an existing host.

## Documentation

- [Wiki home](https://github.com/Kookiejarz/Auto_XDP/wiki)
- [CLI reference](https://github.com/Kookiejarz/Auto_XDP/wiki/CLI-Reference)
- [Configuration reference](https://github.com/Kookiejarz/Auto_XDP/wiki/Configuration-Reference)
- [Architecture and packet flow](https://github.com/Kookiejarz/Auto_XDP/wiki/Architecture-and-Packet-Flow)
- [Security policies and rate limits](https://github.com/Kookiejarz/Auto_XDP/wiki/Security-Policies-and-Rate-Limits)
- [Operations and troubleshooting](https://github.com/Kookiejarz/Auto_XDP/wiki/Operations-and-Troubleshooting)
- [Performance benchmark](https://github.com/Kookiejarz/Auto_XDP/wiki/Performance-Benchmark)
- [Testing and development](https://github.com/Kookiejarz/Auto_XDP/wiki/Testing-and-Development)
- [Uninstall and recovery](https://github.com/Kookiejarz/Auto_XDP/wiki/Uninstall-and-Recovery)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines and local test commands.

## License

[MPL 2.0](./LICENSE) © 2026 Yunheng Liu
