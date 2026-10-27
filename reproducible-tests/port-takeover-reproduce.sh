#!/usr/bin/env bash
# Standalone lifecycle experiment; requires root in an isolated Linux container.
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
if [[ "${AXDP_TAKEOVER_ISOLATED:-0}" != 1 ]]; then
    exec unshare --mount --net --propagation private bash -euc '
        mount -t sysfs sysfs /sys
        mount -t bpf bpf /sys/fs/bpf
        mkdir -p /run/netns /sys/kernel/tracing
        mount -t tmpfs tmpfs /run/netns
        mount -t tracefs tracefs /sys/kernel/tracing
        export AXDP_TAKEOVER_ISOLATED=1 PYTHONDONTWRITEBYTECODE=1
        exec bash "$@"
    ' bash "$0" "$@"
fi
out=${1:?output directory required}
mkdir -p "$out" /run/axdp_takeover /var/run/auto_xdp /sys/fs/bpf/axdp_takeover
cleanup() {
    [[ -z ${relay_pid:-} ]] || kill "$relay_pid" 2>/dev/null || true
    [[ -z ${relay_pid:-} ]] || wait "$relay_pid" 2>/dev/null || true
    ip link set axdp_take0 xdpgeneric off 2>/dev/null || true
    ip netns del axdp_takeover_client 2>/dev/null || true
    ip link del axdp_take0 2>/dev/null || true
    rm -rf /sys/fs/bpf/axdp_takeover
}
trap cleanup EXIT
ip netns add axdp_takeover_client
ip link add axdp_take0 type veth peer name axdp_take1
ip link set axdp_take1 netns axdp_takeover_client
ip addr add 10.98.0.1/24 dev axdp_take0
ip link set axdp_take0 up
ip link set lo up
ip netns exec axdp_takeover_client ip addr add 10.98.0.2/24 dev axdp_take1
ip netns exec axdp_takeover_client ip link set axdp_take1 up
ip netns exec axdp_takeover_client ip link set lo up
# Referencing conntrack in this private namespace loads its BTF/kfunc provider.
nft 'add table inet axdp_takeover'
nft 'add chain inet axdp_takeover input { type filter hook input priority 0; policy accept; }'
nft 'add rule inet axdp_takeover input ct state established,related accept'
multiarch="/usr/include/$(uname -m)-linux-gnu"
for source in xdp_firewall sock_state_track; do
    clang -O3 -g -target bpf -mcpu=v3 -fno-stack-protector \
        -I "$multiarch" -I "$repo_root/bpf/include" \
        -c "$repo_root/bpf/$source.c" -o "/run/axdp_takeover/$source.o"
done
cp /run/axdp_takeover/xdp_firewall.o /run/axdp_takeover/firewall.o
bpftool prog load /run/axdp_takeover/firewall.o /sys/fs/bpf/axdp_takeover/prog \
    type xdp pinmaps /sys/fs/bpf/axdp_takeover >"$out/load.log" 2>&1
bpftool prog load /run/axdp_takeover/sock_state_track.o \
    /sys/fs/bpf/axdp_takeover/sock_state_prog type tracepoint \
    pinmaps /sys/fs/bpf/axdp_takeover >>"$out/load.log" 2>&1
ip link set axdp_take0 xdpgeneric pinned /sys/fs/bpf/axdp_takeover/prog
python3 - "$repo_root" <<'PY' >"$out/relay.log" 2>&1 &
import sys
sys.path.insert(0, sys.argv[1])
import pkt_relay
import logging
import traceback
drop_client = pkt_relay.RelayServer._drop_client
def traced_drop(self, fd):
    logging.getLogger("takeover").warning("relay disconnect caller: %s health=%s", traceback.extract_stack(limit=3)[-2], self._health_status())
    return drop_client(self, fd)
pkt_relay.RelayServer._drop_client = traced_drop
pkt_relay.SOCK_STATE_PROG_PIN_PATH = "/sys/fs/bpf/axdp_takeover/sock_state_prog"
pkt_relay.SOCK_STATE_LINK_PIN_PATH = "/sys/fs/bpf/axdp_takeover/sock_state_link"
sys.argv = ["pkt_relay", "--config", "/dev/null", "--pin-path", "/sys/fs/bpf/axdp_takeover/pkt_ringbuf",
            "--sock-state-rb", "/sys/fs/bpf/axdp_takeover/sock_state_rb",
            "--socket", "/var/run/auto_xdp/pkt_events.sock", "--pid-file", "/run/axdp_takeover/relay.pid", "--debug"]
pkt_relay.main()
PY
relay_pid=$!
for attempt in {1..100}; do
    [[ ! -S /var/run/auto_xdp/pkt_events.sock ]] || break
    kill -0 "$relay_pid"
    sleep 0.05
done
[[ -S /var/run/auto_xdp/pkt_events.sock ]]
python3 "$repo_root/tests/python/kernel_port_takeover.py" --output "$out" --relay-pid "$relay_pid" "${@:2}"
