#!/bin/bash
# =============================================================
# setup_xdp.sh — One-click compilation / loading of XDP firewall + startup port synchronization daemon
# Usage: sudo bash setup_xdp.sh [interface]
#       sudo bash setup_xdp.sh eth0
#       If no parameters are provided, the default route network interface will be detected automatically.
# =============================================================
set -euo pipefail

# ── Colorful output ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }

# ── Spinner Animation ──────────────────────────────────────────────
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr="|/-\\"
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

run_with_spinner() {
    local msg="$1"
    shift
    info "$msg"
    "$@" > /tmp/xdp_install.log 2>&1 &
    local pid=$!
    spinner $pid
    wait $pid
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}[FAIL]${NC}"
        die "Command failed: $*\nCheck /tmp/xdp_install.log for details."
    else
        echo -e "${GREEN}[DONE]${NC}"
    fi
}

# ── Settings ─────────────────────────────────────────────────────
IFACE="${1:-}"
XDP_SRC="xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"
export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
SYNC_SCRIPT="/usr/local/bin/xdp-sync-ports.py"
SERVICE_NAME="xdp-port-sync"
SYNC_INTERVAL=30   # fallback poll interval (primary trigger is netlink proc events)
RAW_URL="https://raw.githubusercontent.com/Kookiejarz/basic_xdp/main"

# ── 1. Check root ──────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Please run this script with sudo."

# ── 2. Interface Detection ───────────────────────────────────────────
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    [[ -n "$IFACE" ]] || die "Unable to automatically detect the default network adapter. Please manually specify it: sudo bash $0 eth0"
    info "Network Interface detected: $IFACE"
fi
ip link show "$IFACE" &>/dev/null || die "Interface $IFACE does not exist"

# ── 3. Check and install dependencies ─────────────────────────────────────────
info "Checking dependencies..."
MISSING=()
for cmd in clang bpftool python3; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done
[[ -d /usr/include/linux ]] || MISSING+=("linux-headers")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing dependency: ${MISSING[*]}, Installing..."

    # 设置环境变量，强制 apt 进入非交互模式
    export DEBIAN_FRONTEND=noninteractive
    # 定义通用的强制静默参数
    APT_OPTS="-y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

    run_with_spinner "Updating system repositories..." \
    apt-get update -qq

    run_with_spinner "Installing core build tools (clang, llvm, etc.)..." \
    apt-get install $APT_OPTS clang llvm libbpf-dev build-essential iproute2 python3 python3-pip gcc-multilib || true

    run_with_spinner "Installing kernel specific tools (bpftool)..." \
    apt-get install $APT_OPTS linux-tools-common linux-tools-generic linux-tools-$(uname -r) linux-headers-$(uname -r) || true

    if ! command -v bpftool &>/dev/null; then
        REAL_BPFTOOL=$(find /usr/lib/linux-tools -name bpftool -type f -executable -print -quit 2>/dev/null || true)
        if [[ -n "$REAL_BPFTOOL" ]]; then
            ln -sf "$REAL_BPFTOOL" /usr/local/bin/bpftool
            ok "Found bpftool at $REAL_BPFTOOL and created symlink."
        fi
    fi
    
    unset DEBIAN_FRONTEND
fi

# Always ensure psutil is available (independent of the missing-deps block)
pip3 install --quiet psutil

command -v bpftool &>/dev/null || die "bpftool installation failed. Please run: apt install linux-tools-generic"
ok "Dependency check completed"

# ── 4. Getting Source Code ───────────────────────────────────────────
fetch_or_keep() {
    local filename="$1"
    local url="${RAW_URL}/${filename}"

    info "Fetching ${filename} from GitHub ..."
    if curl -fsSL "$url" -o "$filename" 2>/dev/null; then
        ok "Downloaded ${filename} from GitHub"
    else
        die "Failed to download ${filename} from ${url}"
    fi
}

fetch_or_keep "$XDP_SRC"

# ── 5. Compile XDP ──────────────────────────────────────────
info "Compiling $XDP_SRC ..."
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ASM_INC="/usr/include/x86_64-linux-gnu";  TARGET_ARCH="x86" ;;
    aarch64) ASM_INC="/usr/include/aarch64-linux-gnu";  TARGET_ARCH="arm64" ;;
    armv7*)  ASM_INC="/usr/include/arm-linux-gnueabihf"; TARGET_ARCH="arm" ;;
    *)       ASM_INC="/usr/include/${ARCH}-linux-gnu";   TARGET_ARCH="${ARCH}" ;;
esac
if [[ ! -d "$ASM_INC" ]]; then
    ASM_INC="/usr/src/linux-headers-$(uname -r)/arch/${TARGET_ARCH}/include/generated"
elif [[ -d "/usr/include/asm" ]]; then
    ASM_INC="/usr/include"
else
    ASM_INC=$(find /usr/src -name "asm" -type d -print -quit | xargs dirname 2>/dev/null || echo "")
fi
[[ -d "$ASM_INC" ]] || die "The asm header file directory cannot be found: apt install gcc-multilib"
info "Using the ASM header file directory: $ASM_INC"

clang -O3 -g \
    -target bpf \
    -mcpu=v3 \
    -D__TARGET_ARCH_${TARGET_ARCH} \
    -fno-stack-protector \
    -Wall -Wno-unused-value \
    -I/usr/include \
    -I"$ASM_INC" \
    -I/usr/include/bpf \
    -c "$XDP_SRC" -o "$XDP_OBJ"
ok "Compilation successful → $XDP_OBJ"

# ── 6. Ensure BPFFs are mounted ────────────────────────────────────
if ! mount | grep -q 'type bpf'; then
    info "mounting bpffs to /sys/fs/bpf ..."
    mount -t bpf bpf /sys/fs/bpf || die "bpffs mount failed"
fi

# ── 7. Detach old XDP program and rebuild pin directory ─────────────────────────────────────
if ip link show "$IFACE" | grep -q "xdp"; then
    warn "An XDP program has been detected. Uninstall it first...."
    ip link set dev "$IFACE" xdp off
fi
if [[ -d "$BPF_PIN_DIR" ]]; then
    warn "Cleaning $BPF_PIN_DIR ..."
    rm -rf "$BPF_PIN_DIR"
fi
mkdir -p "$BPF_PIN_DIR"

# ── 8. Load and attach XDP program ──────────────────────────────────────────────────────────
info "Loading XDP to $IFACE ..."

bpftool prog load "$XDP_OBJ" "$BPF_PIN_DIR/prog"

# Locate the ID of the newly loaded program, then pin all the maps it uses.
PROG_ID=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
info "Program ID: $PROG_ID"


bpftool -j prog show id "$PROG_ID" | python3 -c "
import json, sys, subprocess, os
prog = json.load(sys.stdin)
pin_dir = os.environ['BPF_PIN_DIR']
for map_id in prog.get('map_ids', []):
    info = json.loads(subprocess.check_output(['bpftool','-j','map','show','id',str(map_id)]))
    name = info.get('name', f'map_{map_id}')
    pin_path = f'{pin_dir}/{name}'
    subprocess.check_call(['bpftool','map','pin','id',str(map_id), pin_path])
    print(f'  pinned map [{name}] → {pin_path}')
" || die "map pin failed"

# attach to interface, try native mode first, fallback to generic if it fails
if ip link set dev "$IFACE" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
    ok "XDP using native mode $IFACE"
else
    warn "does not support native mode, falling back to generic mode..."
    ip link set dev "$IFACE" xdp generic pinned "$BPF_PIN_DIR/prog"
    ok "XDP using generic mode $IFACE"
fi
ip link show "$IFACE" | grep -q "xdp" || die "XDP program failed to attach to $IFACE"

info "BPF maps is pinned to :"
ls "$BPF_PIN_DIR/"
echo ""

# ── 9. Deploy Daemon ────────────────────────────────────────────────────────────────────────
info "Deploying Daemon → $SYNC_SCRIPT ..."
cat > "$SYNC_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""XDP Port Whitelist Auto-Sync Daemon

Port discovery  : psutil (no external process, no ss(8))
Map operations  : direct bpf(2) syscall via ctypes (no bpftool)
Event trigger   : Linux Netlink Process Connector (EXEC/EXIT events)
Fallback        : periodic poll every --interval seconds (default 30)

Architecture:
  kernel -> NETLINK_CONNECTOR (EXEC/EXIT) -> debounce 300 ms -> sync_once()
  + periodic fallback poll every --interval seconds
"""
from __future__ import annotations
import argparse, ctypes, ctypes.util, logging, os, platform
import select, socket, struct, sys, time
from dataclasses import dataclass, field

try:
    import psutil
except ImportError:
    sys.exit("psutil not installed. Run: pip3 install psutil")

TCP_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_whitelist"
UDP_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_whitelist"

# Ports that must always stay whitelisted regardless of whether a process
# is currently listening (e.g. SSH emergency fallback).
TCP_PERMANENT: dict[int, str] = {22: "SSH-fallback"}
UDP_PERMANENT: dict[int, str] = {}

# After a proc EXEC/EXIT event, wait this long before scanning.
DEBOUNCE_S = 0.3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ── BPF syscall interface ─────────────────────────────────────────────
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
# bpf(2) syscall numbers per architecture
_NR_BPF: int = {
    "x86_64":  321,
    "aarch64": 280,
    "armv7l":  386,
    "armv6l":  386,
}.get(platform.machine(), 321)

_BPF_MAP_LOOKUP_ELEM = 1
_BPF_MAP_UPDATE_ELEM = 2
_BPF_OBJ_GET         = 7


def _bpf(cmd: int, attr: ctypes.Array) -> int:
    ret = _libc.syscall(_NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def _obj_get(path: str) -> int:
    """Open a pinned BPF object and return its fd."""
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr   = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0,
                     ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return _bpf(_BPF_OBJ_GET, attr)


class BpfArrayMap:
    """Pinned BPF ARRAY map with key=__u32 (port) and value=__u32 (0/1).

    Maintains an in-memory write-through cache so that sync_once() only
    issues syscalls for ports that actually changed.  A one-time warmup
    scan at startup seeds the cache from the kernel map.
    """

    def __init__(self, path: str) -> None:
        self.path  = path
        self.fd    = _obj_get(path)
        self._cache: dict[int, int] = {}  # port → 1 (only active ports stored)

        # Pre-allocate reusable buffers and a single bpf_attr block.
        # bpf_attr layout for MAP_LOOKUP / MAP_UPDATE:
        #   offset  0 : map_fd  (u32)
        #   offset  4 : padding (4 bytes)
        #   offset  8 : key ptr (u64)
        #   offset 16 : value ptr (u64)
        #   offset 24 : flags   (u64)
        self._key  = ctypes.create_string_buffer(4)
        self._val  = ctypes.create_string_buffer(4)
        self._attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._attr, 0, self.fd, k_ptr, v_ptr, 0)

    # ── low-level helpers ────────────────────────────────────────────
    def _lookup(self, port: int) -> int:
        struct.pack_into("=I", self._key, 0, port)
        try:
            _bpf(_BPF_MAP_LOOKUP_ELEM, self._attr)
            return struct.unpack_from("=I", self._val, 0)[0]
        except OSError:
            return 0

    def _update(self, port: int, val: int) -> None:
        struct.pack_into("=I", self._key, 0, port)
        struct.pack_into("=I", self._val, 0, val)
        _bpf(_BPF_MAP_UPDATE_ELEM, self._attr)  # flags=0 → BPF_ANY

    # ── public API ───────────────────────────────────────────────────
    def warmup(self) -> None:
        """Scan all 65536 ARRAY slots once to seed the in-memory cache."""
        log.debug("Warming up cache from %s ...", self.path)
        for port in range(65536):
            if self._lookup(port):
                self._cache[port] = 1
        log.debug("  → %d active entries", len(self._cache))

    def set(self, port: int, val: int, dry_run: bool = False) -> bool:
        """Write val (0 or 1) for port into the map and update cache."""
        if dry_run:
            log.info("[DRY] map %s: %s port %d", self.path, "+allow" if val else "-block", port)
            if val:
                self._cache[port] = 1
            else:
                self._cache.pop(port, None)
            return True
        try:
            self._update(port, val)
            if val:
                self._cache[port] = 1
            else:
                self._cache.pop(port, None)
            return True
        except OSError as e:
            log.warning("map update failed port=%d: %s", port, e)
            return False

    def active_ports(self) -> set[int]:
        return set(self._cache)


# ── Port discovery via psutil ─────────────────────────────────────────
@dataclass
class PortState:
    tcp: set = field(default_factory=set)
    udp: set = field(default_factory=set)

    _net_conns = getattr(psutil, "connections", psutil.net_connections)


def get_listening_ports() -> PortState:
    state = PortState()
    for conn in _iter_connections():
        if not (conn.laddr and conn.laddr.port):
            continue
        if conn.type == socket.SOCK_STREAM and conn.status == "LISTEN":
            state.tcp.add(conn.laddr.port)
        elif conn.type == socket.SOCK_DGRAM:
            state.udp.add(conn.laddr.port)
    return state


# ── Sync logic ────────────────────────────────────────────────────────
def sync_once(tcp_map: BpfArrayMap, udp_map: BpfArrayMap, dry_run: bool) -> None:
    current    = get_listening_ports()
    tcp_target = current.tcp | set(TCP_PERMANENT)
    udp_target = current.udp | set(UDP_PERMANENT)

    changed = False

    for port in sorted(tcp_target - tcp_map.active_ports()):
        tag = " [" + TCP_PERMANENT[port] + "]" if port in TCP_PERMANENT else ""
        if tcp_map.set(port, 1, dry_run):
            log.info("TCP Whitelist +%d%s", port, tag)
            changed = True

    for port in sorted(tcp_map.active_ports() - tcp_target - set(TCP_PERMANENT)):
        if tcp_map.set(port, 0, dry_run):
            log.info("TCP Whitelist -%d  (stopped)", port)
            changed = True

    for port in sorted(udp_target - udp_map.active_ports()):
        tag = " [" + UDP_PERMANENT[port] + "]" if port in UDP_PERMANENT else ""
        if udp_map.set(port, 1, dry_run):
            log.info("UDP Whitelist +%d%s", port, tag)
            changed = True

    for port in sorted(udp_map.active_ports() - udp_target - set(UDP_PERMANENT)):
        if udp_map.set(port, 0, dry_run):
            log.info("UDP Whitelist -%d  (stopped)", port)
            changed = True

    if not changed:
        log.debug("Port whitelist is up-to-date")


# ── Netlink Process Connector ─────────────────────────────────────────
_NETLINK_CONNECTOR    = 11
_CN_IDX_PROC          = 1
_NLMSG_HDRLEN         = 16
_CN_MSG_HDRLEN        = 20   # idx(4)+val(4)+seq(4)+ack(4)+len(2)+flags(2)
_NLMSG_MIN_TYPE       = 0x10
_PROC_CN_MCAST_LISTEN = 1
_PROC_EVENT_EXEC      = 0x00000002
_PROC_EVENT_EXIT      = 0x80000000


def _make_subscribe_msg(pid: int) -> bytes:
    op  = struct.pack("I", _PROC_CN_MCAST_LISTEN)
    cn  = struct.pack("IIIIHH", _CN_IDX_PROC, 1, 0, 0, len(op), 0) + op
    hdr = struct.pack("IHHII", _NLMSG_HDRLEN + len(cn), _NLMSG_MIN_TYPE, 0, 0, pid)
    return hdr + cn


def open_proc_connector():
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM,
                             _NETLINK_CONNECTOR)
        sock.bind((os.getpid(), _CN_IDX_PROC))
        sock.send(_make_subscribe_msg(os.getpid()))
        log.info("Netlink proc connector active — event-driven mode enabled")
        return sock
    except OSError as exc:
        log.warning("Netlink proc connector unavailable (%s); poll-only mode", exc)
        return None


def drain_proc_events(sock: socket.socket) -> bool:
    """Drain all pending netlink messages; return True if EXEC or EXIT seen."""
    triggered = False
    while True:
        try:
            rdy, _, _ = select.select([sock], [], [], 0)
            if not rdy:
                break
            data = sock.recv(4096)
        except OSError:
            break
        offset = 0
        while offset + _NLMSG_HDRLEN <= len(data):
            nl_len = struct.unpack_from("I", data, offset)[0]
            if nl_len < _NLMSG_HDRLEN:
                break
            cn_off = offset + _NLMSG_HDRLEN
            if cn_off + _CN_MSG_HDRLEN <= offset + nl_len:
                idx     = struct.unpack_from("I", data, cn_off)[0]
                cn_data = cn_off + _CN_MSG_HDRLEN
                if idx == _CN_IDX_PROC and cn_data + 4 <= offset + nl_len:
                    what = struct.unpack_from("I", data, cn_data)[0]
                    if what in (_PROC_EVENT_EXEC, _PROC_EVENT_EXIT):
                        triggered = True
            offset += (nl_len + 3) & ~3  # NLMSG_ALIGN
    return triggered


# ── Watch loop ────────────────────────────────────────────────────────
def _open_maps() -> tuple[BpfArrayMap, BpfArrayMap]:
    tcp_map = BpfArrayMap(TCP_MAP_PATH)
    tcp_map.warmup()
    udp_map = BpfArrayMap(UDP_MAP_PATH)
    udp_map.warmup()
    return tcp_map, udp_map


def watch(interval: int, dry_run: bool) -> None:
    tcp_map, udp_map = _open_maps()
    nl = open_proc_connector()
    last_sync_t  = 0.0
    last_event_t = 0.0

    sync_once(tcp_map, udp_map, dry_run)
    last_sync_t = time.monotonic()

    while True:
        now      = time.monotonic()
        poll_due = last_sync_t + interval
        deb_due  = (last_event_t + DEBOUNCE_S) if last_event_t else float("inf")
        sleep_for = max(0.05, min(poll_due, deb_due) - now)

        try:
            if nl and not last_event_t:
                # Only listen for new events when NOT already debouncing,
                # to prevent spinning when the socket is continuously readable.
                rdy, _, _ = select.select([nl], [], [], sleep_for)
                if rdy and drain_proc_events(nl):
                    log.debug("Proc event received, debounce armed")
                    last_event_t = time.monotonic()
            else:
                time.sleep(sleep_for)
        except OSError as exc:
            log.warning("Netlink socket error (%s); disabling event-driven mode", exc)
            if nl:
                nl.close()
                nl = None
            continue
        except KeyboardInterrupt:
            log.info("exiting...")
            if nl:
                nl.close()
            break

        now = time.monotonic()
        debounce_fired = bool(last_event_t) and (now - last_event_t >= DEBOUNCE_S)
        fallback_fired = (now - last_sync_t >= interval)

        if debounce_fired or fallback_fired:
            reason = "event" if debounce_fired else "poll"
            log.debug("sync triggered by %s", reason)
            if nl:
                drain_proc_events(nl)  # flush accumulated events before re-arming
            try:
                sync_once(tcp_map, udp_map, dry_run)
            except Exception as exc:
                log.error("sync error: %s", exc)
            last_sync_t  = time.monotonic()
            last_event_t = 0.0


def main() -> None:
    p = argparse.ArgumentParser(
        description="XDP port-whitelist sync daemon")
    p.add_argument("--watch",    action="store_true",
                   help="Run as a daemon (event-driven + fallback poll)")
    p.add_argument("--interval", type=int, default=30,
                   help="Fallback poll interval in seconds (default: 30)")
    p.add_argument("--dry-run",  action="store_true",
                   help="Print operations without executing them")
    args = p.parse_args()
    if args.watch:
        watch(args.interval, args.dry_run)
    else:
        tcp_map, udp_map = _open_maps()
        sync_once(tcp_map, udp_map, args.dry_run)
        log.info("Sync completed")


if __name__ == "__main__":
    main()
PYEOF
chmod +x "$SYNC_SCRIPT"
ok "Script deployed: $SYNC_SCRIPT"

# ── 10. Enable systemd ───────────────────────────────
info "Enabling systemd: $SERVICE_NAME ..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=XDP BPF Port Whitelist Auto-Sync
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${SYNC_SCRIPT} --watch --interval ${SYNC_INTERVAL}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
ok "Daemon enabled: $SERVICE_NAME"

# ── 11. Initial sync ─────────────────────────────────
info "Syncing..."
python3 "$SYNC_SCRIPT"

# ── 12. Done ─────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment Completed! ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Interface:     $IFACE"
echo "  BPF maps: $BPF_PIN_DIR/"
  echo "  Daemon:  systemctl status $SERVICE_NAME"
echo ""
echo "  Current whitelisted TCP:"
bpftool -j map dump pinned "${BPF_PIN_DIR}/tcp_whitelist" 2>/dev/null \
  | python3 -c "
import json,sys
try:
    data = json.load(sys.stdin)
    items = data if isinstance(data, list) else data.get('items', [])
    for e in items:
        if not isinstance(e, dict):
            continue
        # Skip zero-value (unset) ARRAY slots
        v = e.get('value', 0)
        val = v if isinstance(v, int) else \
              (int(v[0], 16) if isinstance(v, list) and v else 0)
        if not val:
            continue
        k = e.get('key')
        if isinstance(k, int):
            print(f'    → TCP {k}')
        elif isinstance(k, list) and len(k) >= 2:
            b0 = int(k[0], 16) if isinstance(k[0], str) else k[0]
            b1 = int(k[1], 16) if isinstance(k[1], str) else k[1]
            print(f'    → TCP {b0 | (b1 << 8)}')
except:
    pass
" || echo "    (NULL)"
echo ""
echo "  Uninstall command: ip link set dev $IFACE xdp off"
echo ""
