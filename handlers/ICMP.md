# ICMP module

`icmp_handler.c` checks IPv4 and IPv6 Echo Replies through Linux conntrack.
Its dependency, `axdp_icmp.c`, builds the small `axdp_icmp.ko` kernel module.
Both sources live beside SCTP and GRE in the Handler SDK and appear as one
**ICMP** module in `axdp handler list` and the TUI.

The kernel module exposes one XDP-only function, `bpf_axdp_icmp_reply()`.
It checks a confirmed request's REPLY tuple and releases the conntrack reference
internally. It owns no maps, timers, workers or private connection state. The
first reply passes before Linux sets `SEEN_REPLY`; lookup does not update or
prolong the flow.

## Enable and disable

```sh
sudo axdp handler apply icmp --set enabled=true
sudo axdp handler apply icmp --set enabled=false
```

The canonical setting is `[modules.icmp] enabled = true`. Apply uses the installed
runtime, preserving the configured policy mode: audit/observe does not attach
a filtering data plane. Configuration reload also prepares the handler before
enabling the runtime gate. No main-firewall recompilation is needed.

The BPF object's `.axdp_kmods` metadata declares `axdp_icmp`. The common loader
first runs `modprobe`, which also resolves dependencies such as `nf_conntrack`.
If the bundled module is missing for the running kernel, it builds in a temporary
directory, installs under `/lib/modules/<kernel>/extra/auto_xdp/`, runs `depmod`,
and retries loading. Both protocol bindings are published only after the BPF
program loads successfully. A dependency or verifier failure preserves existing
bindings; a failed publication rolls both families back.

The host needs its **running kernel's** development/build package, a compatible
C compiler, make, binutils, libelf development headers and pahole (`dwarves` on
RHEL). The kernel needs modules, conntrack, BPF and module BTF support, including
`CONFIG_DEBUG_INFO_BTF_MODULES`. Secure Boot hosts need a trusted module signature.
The dependency loader does not download packages or replace the kernel. An
already-installed module rejected by the kernel is reported without rebuilding.

For a manual build from this checkout:

```sh
make -C handlers -f Makefile.kmod
sudo make -C handlers -f Makefile.kmod install
```

Kbuild retains module BTF and strips debug sections. Where the build directory
lacks `vmlinux`, the Makefile generates split BTF using the running kernel's
`/sys/kernel/btf/vmlinux` and Kbuild's `resolve_btfids`. That fallback requires
the running kernel. After a kernel update, the next activation builds a missing
module for that kernel if its development files are installed. This is not DKMS;
kernel kfunc/internal API changes may still require source updates.

Only `[modules.icmp]` controls this module. Old config sections, installer
variables and release marker files are not migrated or used to enable it.
The main firewall has no reference to the custom kfunc. Only the ICMP handler
requires it, so disabling ICMP releases that BPF reference. The loader does not
force removal of the shared kernel module.

## Boundaries

- Lookup uses the ingress network namespace and conntrack zone 0, including
  the wire reply tuple after SNAT. NOTRACK and other zones do not qualify.
- Linux conntrack matches Echo ID, not the individual sequence or payload.
  A forged reply matching a live tuple can pass; this is not a packet budget
  or replay detector.
- Echo Request keeps its existing rate limiter. ICMP errors, PMTU feedback
  and IPv6 neighbour discovery keep their existing handling.
- Unmatched replies receive `XDP_DROP`, without an error response. Their
  telemetry reason/counter is `ICMP_REPLY_UNTRACKED` (66).
- An enabled but missing handler fails closed. ICMP requires XDP; activation
  cannot silently fall back to nftables. Disable clears the runtime gate and
  removes both bindings, restoring normal Echo Reply handling.

## Verification

These tests create private network and mount namespaces, without attaching XDP
to the host's public interface. They exercise automatic dependency loading:

```sh
sudo env KERNEL_TEST_ICMP=1 REQUIRE_KERNEL_TESTS=1 \
  KERNEL_TEST_FILTER=icmp_conntrack_replies bash tests/bash/test_integration.sh
sudo env KERNEL_TEST_ICMP=1 REQUIRE_KERNEL_TESTS=1 \
  KERNEL_TEST_FILTER=icmp_conntrack_native_replies bash tests/bash/test_integration.sh
```

Coverage includes IPv4/IPv6 ping, unsolicited reply rejection, first reply,
tuple/namespace/zone isolation, expiry, NOTRACK, SNAT, telemetry, control packets,
TCP/UDP regressions, missing dispatch and module Disable. The kernel dependency
itself was previously verified on RHEL 10.2, `6.12.0-211.73.1.el10_2.x86_64`.
