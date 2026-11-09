# Handler SDK

## Discover, install and configure

Open `axdp tui`, press **h**, and use **↑/↓** or click to select a row. **Enter**
or a double click opens its configuration page. **s** saves settings, **a**
saves and applies them, and **Esc** closes the page without applying unsaved
edits. **i** installs a local source, BPF object, or package directory; **r**
refreshes the inventory. Changes require root; discovery and inspection do not.

The list combines live dispatch entries and programs pinned under this
application's BPF root with bundled modules, files in the configured handlers
directory, installed packages, and paths referenced by the current config.
Internal firewall, socket-tracking, TC-dispatch and SYN-handoff programs are
excluded, including their pin aliases. Configurable modules such as SYN Cookie,
Minecraft and the protocol handlers remain available.
Source/object peers normally appear once; a source with a failed build can
also appear separately from its existing object so it remains available for retry.
An object without a matching source or
manifest is still listed. BPF entry types and map compatibility are checked
before activation. An unavailable artifact, an unreadable kernel table, a
configured target and a loaded program are distinct states. A pin alone does
not prove that a program is attached or dispatched. Unidentified runtime
programs have an inspection page; installing their source/object enables
configuration through a module entry.

Detectable files remain visible after a failed compilation or object check,
with a **⚠** icon and `build fail` state. If an older version is still running,
its row retains `loaded` and its actual program ID alongside the warning.
Open the configuration page and press **e** for scrollable compiler diagnostics;
**↑/↓** and **PgUp/PgDn** scroll, and **e/Esc** returns to the form. Invalid
manifests also receive a warning and diagnostic details.

The latest failed install/apply check is recorded under `HANDLERS_DIR/.diagnostics`
and is shared by TUI and `axdp handler list` (`build_error` in JSON output).
An unsuccessful install publishes no partial package, but its original file
remains a discoverable candidate while present. A successful retry clears the
warning; saving a draft or editing the source alone does not clear it. Discovery
does not compile every file: `available` means found, not build-verified, and
failures from unrelated external compiler commands are not automatically known.

The same operations are available from the command line:

```sh
axdp handler list
axdp handler list --json
sudo axdp handler install ./filter.c --name my-filter --kind udp --target 30120
axdp handler config my-filter
sudo axdp handler config my-filter --set target=30121
sudo axdp handler apply my-filter
sudo axdp handler apply my-filter --set enabled=false
sudo axdp handler apply gre
sudo axdp handler apply minecraft --set subject=paper
sudo axdp handler apply syncookie --set enabled=true --set default_mode=auto
```

`install` accepts `.c`, `.o`, or a directory containing `handler.json`. It
copies source and local quoted headers into `/etc/auto_xdp/handlers/catalog/`,
validates the object and leaves it inactive unless `--apply` is supplied.
Use a distinct module name to install another version alongside an existing
package. `--handlers-dir` selects a different catalog root when calling the
Python CLI directly. The installed `axdp` wrapper and TUI use `HANDLERS_DIR`
from the runtime environment.

Custom modules without a schema expose their binding and enable switch. A
source module may declare typed compiler parameters in `filter.handler.json`
beside `filter.c`, or in a package's `handler.json`:

```json
{
  "version": 1,
  "id": "my-filter",
  "name": "UDP packet filter",
  "entry": "filter.c",
  "kind": "udp",
  "target": 30120,
  "fields": [
    {
      "name": "max_packet_bytes",
      "label": "Maximum packet bytes",
      "type": "int",
      "default": 1200,
      "minimum": 64,
      "maximum": 65535,
      "define": "MAX_PACKET_BYTES"
    }
  ]
}
```

Use `#ifndef MAX_PACKET_BYTES` around the source's default definition, and
consume that constant in the packet checks. Custom fields currently support
`int` and `bool`, optional numeric bounds or choices, and a C identifier in
`define`. They are compiled into a fresh object when applied; arbitrary
configuration keys are rejected. Precompiled objects without source do not
offer compiler parameters. Private map state still follows the declared
state contract: a parameter change that alters its ABI must not reuse an
incompatible schema.

Module switches and parameters are stored in `[modules.<id>]`.
Save writes pending values to `[modules.<id>.draft]`; Apply publishes those
values to the module table and removes the draft. Applying a slot or
port module writes the normal `[slots]` / `[port_handlers]` startup config
and `[handler_bindings]` ownership metadata, then uses the common transaction
to activate it. If activation fails, the command reports **configuration
saved, activation failed**; the desired config remains available for retry,
and the loader's rollback rules protect the previous running generation.
Successful updates retire unreferenced catalog builds while preserving builds
used by other bindings. Choosing a new target adds a binding; it does not
remove the old target automatically.

Minecraft config selects an existing policy subject and changes its
`protection.profile`; it never creates exposure grants. SYN Cookie exposes its
existing policy modes, thresholds and per-port/process/service overrides.
These managed modules apply through the installed runtime's normal
reconciliation; observe/audit mode is reported as non-active. When the matching
installed controller is running, Apply stops that watcher, performs one sync,
and restarts it with the saved configuration. Existing BPF attachments remain
active during this operation. This avoids concurrent writers using different
policies. A running systemd event relay is also restored, because the service
manager stops it with its controller; an inactive relay stays inactive.
A failed sync also attempts to restart the controller, and reports
both failures if recovery fails. Unrelated controllers are left alone.
Activation errors, including both subprocess output streams, can be inspected
with **e** in the configuration page; **PgUp/PgDn** scrolls the full error.
Saving a draft retains the last activation error; a successful Apply clears it.
SYN Cookie uses the common module generation transaction for loading, replacing
and disabling its XDP program and TC ingress companion. Both objects must pass
entry-type and shared-map ABI checks before activation. TC ingress is prepared
before XDP dispatch; Disable withdraws XDP dispatch first. Every changed hook is
read back, and a failed switch restores the previous generation on all affected
interfaces. Failed rollback keeps recovery pins and the required sysctl ownership.
The module remains one row in Handlers, with both hooks reflected in its status;
the handoff program is a companion, not a separate configurable module.

SYN Cookie settings live in `[modules.syncookie]`;
`axdp handler apply syncookie` uses only the current module ownership pins.
Old root-level program pins are not adopted. Pins are retired only
after a verified switch/removal. New generations live under
`BPF_PIN_DIR/modules/syncookie/` (`prog` and `ingress`). Capability checks and
namespace-scoped sysctl ownership remain requirements of this module.

A handler object contains exactly one XDP program and optionally one TC egress
classifier. Use `SEC("xdp")` and `SEC("tc")` so libbpf can infer their different
program types when loading the object together. The entries share maps declared
in that object. Protocol parsing, dialogue validation and protocol state belong
in the handler, not the firewall or generic TC dispatcher.

```c
#include "xdp_slot_ctx.h"
#include "tc_handler_ctx.h"

SEC("xdp")
int ingress(struct xdp_md *packet)
{
    struct xdp_slot_ctx *ctx = get_slot_ctx(packet);
    /* Validate this protocol using the already parsed service tuple. */
    return ctx ? XDP_PASS : XDP_DROP;
}

SEC("tc")
int egress(struct __sk_buff *packet)
{
    struct tc_handler_ctx *ctx = get_tc_handler_ctx(packet);
    /* Observe bounded protocol data using ctx->payload_offset/payload_len.
     * skb data may be non-linear: use skb read helpers or a bounded pull. */
    (void)ctx;
    return tc_handler_continue();
}
char LICENSE[] SEC("license") = "GPL";
```

The TC context is a versioned, packet-local ABI. For TCP/UDP service handlers, its flow is the original
client-to-service tuple, even though TC sees a service-to-client reply. It also
includes the ingress interface, handler kind/target, TCP policy/profile
generations, payload bounds and a read-only Linux conntrack snapshot. It has a
separate scratch map from XDP. No conntrack reference crosses a tail call.

The XDP firewall authorizes the endpoint before service dispatch. For service handlers with an
egress entry it remembers that service/interface binding in a bounded LRU. TC
rechecks current zone and exact endpoint authorization, TCP policy generations,
and a confirmed Linux connection in REPLY direction before dispatching. The
binding is metadata, not another TCP state machine or permission to create a
connection. UDP uses current port/zone/scope policy; its existing allow map has
no generation field. Unsupported headers, fragments, missing bindings, expired
conntrack entries and changed wire tuples (including unsupported NAT paths)
produce observation misses. Handlers must not interpret a miss as protocol proof.
All maps and attached interfaces must belong to the same network namespace.

TC handlers normally return `tc_handler_continue()` (`TC_ACT_UNSPEC`) so filters
after Auto XDP still run. They can read their own private protocol maps and the
public SDK context/telemetry maps. Declared public maps must reuse the main
program's pinned instances with matching type, size, capacity and flags; missing
or incompatible pins reject the object. Protocol-private maps, including
Minecraft dialogue/proof maps, are allocated once per loaded object and shared
by its two entries.

Existing `axdp port-handler load tcp|udp PORT file.c|file.o` and
`axdp profile-handler load ID file.o` commands load both entries when present.
Protocol modules use `axdp slot load gre|esp|sctp` or
`axdp slot load PROTO file.c|file.o` through the same loader.
Single-XDP service objects remain supported, using `xdp/...` sections.
The parallel dispatch tables are:

| Service key | XDP table | TC table |
| --- | --- | --- |
| TCP profile ID | `tcp_profile_handlers` | `tc_profile_handlers` |
| TCP destination port | `tcp_port_handlers` | `tc_tcp_handlers` |
| UDP destination port | `udp_port_handlers` | `tc_udp_handlers` |
| IP protocol number | `proto_handlers` | `tc_proto_handlers` |

GRE, ESP and SCTP modules now share the same object loading, map ABI validation,
state contract, publication, rollback and unload lifecycle. Their canonical pins
are `protocol_handlers/PROTO/{prog,egress,state_contract}`. Existing `[slots]`
configuration and commands remain valid. The built-ins keep their stateless
XDP checks: GRE version, ESP SPI range and explicit SCTP destination-port grant.
SCTP also retains the firewall's exact endpoint scope check; `sctp_whitelist`
is shared public policy, not a private association table.

An optional TC entry receives complete outbound IPv4/IPv6 GRE, ESP or SCTP
packets as `HANDLER_ROUTE_PROTO` (target = IP protocol number). For this kind,
`flow` is the **outgoing wire tuple**; SCTP ports are wire source/destination,
and GRE/ESP ports are zero. `ingress_ifindex`, policy/profile generations,
`ct_status` and `ct_state` are zero; `ct_direction` is explicitly
`HANDLER_CT_UNAVAILABLE` (255). This is protocol observation, not evidence of
an admitted request, a confirmed connection, or a reply. The dispatcher does
not infer GRE keys, ESP security associations or SCTP associations from IP
address pairs. A module needing correlation must validate it in its own state.
Only protocols 47, 50 and 132 use this raw outbound dispatch path.

For GRE/ESP, `payload_offset` starts at the protocol header so the module can
parse GRE options or ESP metadata; for SCTP it follows the 12-byte common
header. `l4_offset` always points at the protocol header. Bounds exclude IP
padding; fragments and unsupported extension chains miss observation. This
raw protocol path does not query the TCP/UDP conntrack helper or service
binding cache. The built-in stateless modules do not need a TC entry.

All protocol, port and profile handlers use one transaction implementation,
including single-XDP objects on map sets without TC support. The loader
stages and validates the entire object, publishes TC and its
capability before XDP, and verifies both table entries and pins. On failure it
restores both previous entries; if rollback itself fails it retains recovery
pins. Unload removes XDP, the egress capability and TC before removing the
private-map pins. After a verified commit or unload, it also retires obsolete
staging and rollback generations for that target. Failed switches retain
recovery pins; foreign names are not swept. Protocol migration removes the
old flat pin, its recognized temporary pins, and the old directory once empty.
A private map lives under the generation's `maps/` directory
for dual-entry objects; single-entry objects retain their existing layout.

`handler_eg_stats` exposes parse,
binding, policy, conntrack and tail-call misses plus dispatch attempts; the TUI
handler inventory lists the XDP and TC entries separately.

## Preserving sessions during replacement

Opt in by declaring an explicit compatibility schema and every persistent
private map in the object. Keep packet-local scratch maps out of this list:

```c
#include "handler_state.h"
AXDP_STATE_SCHEMA("my-protocol-v1", "[\"sessions\",\"login_limits\"]");
```

The schema is a promise that old and new entries can concurrently read and
write the same records with the same meaning. Bump it for incompatible field
layouts, protocol-proof semantics or admission changes, even when byte sizes
stay equal. The loader also checks each listed map's type, key/value sizes,
capacity and flags. Only ordinary hash, array, LRU and their per-CPU data maps
are supported; public SDK maps and maps holding kernel-object references are
not valid persistent private state.

On a compatible replacement, both new entries reuse the actual pinned kernel
maps. There is no userspace dump/copy window that could lose concurrent packet
updates, reset deadlines or refresh rate-limit budgets. The candidate gets its
own pins to those same maps, verified by kernel map ID before publication. A
`state_contract` metadata map is committed with the program pins. Loading and
unloading are serialized on the BPF root directory. Failed publication restores
the previous entries while keeping packet updates made through either entry.
The hook switch itself is still not atomic; compatible code must tolerate the
brief old-XDP/new-TC overlap.

Minecraft opts in for pending login dialogue, verified proof and all four rate
limit maps. Its profile epoch derives from the state contract and map ABI;
the daemon separately hashes the object to detect code changes. Compatible
code updates therefore keep full proof generations, conntrack mark hints,
deadlines and the generic TC service bindings. Endpoint policy changes still
change the policy generation and revoke old proof. Linux owns the TCP socket
and conntrack lifetime throughout; no socket reconstruction or custom TCP
state machine is involved.

A schema/ABI mismatch, missing state pin, or replacement of a versioned object
by an unversioned one rejects the update and retains the previous handler.
There is no automatic field conversion across incompatible schemas. To discard
state deliberately, run the existing `port-handler unload` or
`profile-handler unload` or `slot unload` command before loading the new object. An active
object loaded before this contract existed has no compatibility marker, so its
first upgrade to a versioned object also requires that explicit reset.
A stateless protocol module may declare `AXDP_STATE_SCHEMA("name-v1", "[]")`.
Only current generation pins and state markers authorize replacement or
removal. Flat `handlers/proto_N`, `syncookie_prog` and
`tc_syncookie_handoff_prog` pins are not adopted or converted. An old live
attachment must be stopped with its matching release before a fresh start;
unknown ownership fails without replacing or deleting that attachment.
Objects without a state contract receive fresh private maps on replacement.
Compatible UDP port updates retain the public validation cache; updates
without a state contract and explicit unload flush that port's cache.

This contract covers handler replacement inside the same running XDP
map set. Restarting the host, recreating the main firewall maps, changing the
network namespace, unloading the handler, LRU eviction or conntrack expiry can
still remove state. A required ingress profile remains fail-closed.
