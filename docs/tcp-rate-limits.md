# TCP Rate Limit Configuration

This document describes how Auto XDP derives TCP rate-limit policy from
`config.toml`, what each knob protects, and what can or cannot be customized
per port today.

## Configuration Model

TCP policy is written into the `tcp_port_policies` BPF map. The map key is the
destination port, but `config.toml` does not currently expose direct
`port = value` tables. Instead, the daemon resolves a policy for each discovered
TCP listener using this order:

1. Process-name override, for example `sshd = 2`.
2. Service-name override from `/etc/services`, for example `ssh = 2`.
3. Default tier from `[xdp.runtime]`.

Process-name entries are broad. If multiple ports are owned by the same process
name, the same override applies to all of them. For example, `java = 50` affects
every TCP listener discovered as `java`.

Service-name entries depend on the local service database. If a port has no
matching service name in `/etc/services`, service-based overrides do not apply.

## TCP Layers

| Layer | TOML table | Runtime counter key | Meaning |
|---|---|---|---|
| L1 | `syn_by_proc`, `syn_by_service` | source IP or source prefix | New SYNs per source per window |
| L2 | `syn_agg_by_proc`, `syn_agg_by_service` | source prefix + destination port | Aggregate SYNs per prefix per port |
| L3 | `tcp_conn_by_proc`, `tcp_conn_by_service` | source IP + destination port | Concurrent established TCP sessions per source per port |
| L4 | `tcp_conn_prefix_by_proc`, `tcp_conn_prefix_by_service` | source prefix + destination port | Concurrent established TCP sessions per prefix per port |
| L5 | `tcp_conn_port_by_proc`, `tcp_conn_port_by_service` | destination port | Total concurrent established TCP sessions per port |

Important: L1 SYN rate is configured per listener port, but its runtime counter
is shared by source IP or source prefix and does not include the destination
port. If the same source hits multiple TCP ports with L1 enabled, those ports
share the same L1 source counter. Use L2 if you need a SYN-rate counter that is
isolated by destination port.

## Source Prefix

Prefix-based layers use:

```toml
[rate_limits]
source_cidr_v4 = 24
source_cidr_v6 = 64
```

With the defaults above, L2 and L4 aggregate IPv4 sources by `/24` and IPv6
sources by `/64`. L1 also uses these prefix values in the current BPF path.

Use `/32` for IPv4 or `/128` for IPv6 if you want per-address behavior rather
than per-prefix behavior:

```toml
[rate_limits]
source_cidr_v4 = 32
source_cidr_v6 = 128
```

## Process Overrides

Use process tables when the owning process name is stable and specific enough.

```toml
[rate_limits.syn_by_proc]
sshd = 2
java = 50

[rate_limits.syn_agg_by_proc]
sshd = 50
java = 1000

[rate_limits.tcp_conn_by_proc]
sshd = 5
java = 50

[rate_limits.tcp_conn_prefix_by_proc]
sshd = 20
java = 200

[rate_limits.tcp_conn_port_by_proc]
sshd = 200
java = 5000
```

The example above applies strict SSH caps and looser caps for every TCP port
owned by a process reported as `java`.

## Service Overrides

Use service tables when the port has a meaningful `/etc/services` name.

```toml
[rate_limits.syn_by_service]
ssh = 2
http = 100
https = 100

[rate_limits.syn_agg_by_service]
ssh = 50
http = 5000
https = 5000

[rate_limits.tcp_conn_by_service]
ssh = 5
http = 100
https = 100

[rate_limits.tcp_conn_prefix_by_service]
ssh = 20
http = 1000
https = 1000

[rate_limits.tcp_conn_port_by_service]
ssh = 200
http = 20000
https = 20000
```

## Default Tiers

Every auto-discovered TCP port gets default-on protection unless an explicit
override sets a knob to `0`.

```toml
[xdp.runtime]
sensitive_port_threshold = 5

default_tcp_syn_rate_strict = 5
default_tcp_syn_rate = 100

default_tcp_syn_agg_rate_strict = 50
default_tcp_syn_agg_rate = 1000

default_tcp_established_per_src_strict = 5
default_tcp_established_per_src = 50

default_tcp_established_per_prefix_strict = 20
default_tcp_established_per_prefix = 200

default_tcp_established_per_port_strict = 200
default_tcp_established_per_port = 5000
```

A listener is treated as sensitive when its process or service has an explicit
`syn_by_*` entry with a value greater than `0` and less than or equal to
`sensitive_port_threshold`. Sensitive listeners receive the strict defaults for
all five TCP layers unless a specific layer has an explicit override.

## Disabling A Layer

Set an explicit value to `0` to disable that layer for matching listeners.

```toml
[rate_limits.syn_by_proc]
mybenchmark = 0

[rate_limits.tcp_conn_port_by_proc]
mybenchmark = 0
```

`0` means "pin this layer off" for that process or service. Missing entries do
not disable protection; they fall back to the default tier.

## Per-Port Limitation

Direct per-port override tables are not supported yet. These examples do not
work:

```toml
[rate_limits.syn_by_port]
25565 = 20

[rate_limits.tcp_conn_port_by_port]
25565 = 5000
```

If you need special handling for one port today, use one of these approaches:

1. Run that listener under a distinct process name and configure `*_by_proc`.
2. Add or use a service name for the port and configure `*_by_service`.
3. Change the global default tier if the same policy is acceptable for all
   otherwise unconfigured listeners.

## Examples

### SSH

```toml
[rate_limits.syn_by_proc]
sshd = 2

[rate_limits.syn_agg_by_proc]
sshd = 50

[rate_limits.tcp_conn_by_proc]
sshd = 5

[rate_limits.tcp_conn_prefix_by_proc]
sshd = 20

[rate_limits.tcp_conn_port_by_proc]
sshd = 200
```

### High-Volume Web Server

```toml
[rate_limits.syn_by_service]
http = 200
https = 200

[rate_limits.syn_agg_by_service]
http = 10000
https = 10000

[rate_limits.tcp_conn_by_service]
http = 200
https = 200

[rate_limits.tcp_conn_prefix_by_service]
http = 2000
https = 2000

[rate_limits.tcp_conn_port_by_service]
http = 50000
https = 50000
```

### Game Server Owned By `java`

```toml
[rate_limits.syn_by_proc]
java = 50

[rate_limits.syn_agg_by_proc]
java = 1000

[rate_limits.tcp_conn_by_proc]
java = 50

[rate_limits.tcp_conn_prefix_by_proc]
java = 200

[rate_limits.tcp_conn_port_by_proc]
java = 5000
```

This applies to all discovered TCP ports owned by `java`. It is not isolated to
one game port unless that port is the only `java` listener.
