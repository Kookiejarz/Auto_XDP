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
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
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
info "Cheching dependencies..."
MISSING=()
for cmd in clang llc bpftool python3; do
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
    apt-get install $APT_OPTS clang llvm libbpf-dev build-essential iproute2 python3 gcc-multilib || true

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

    # 4. Last Check
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
    ASM_INC="/usr/src/linux-headers-$(uname -r)/arch/x86/include/generated"
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

# ── 7. Uninstall the old XDP program and rebuild the directory. ──────────────────────────────
if ip link show "$IFACE" | grep -q "xdp"; then
    warn "An XDP program has been detected. Uninstall it first...."
    ip link set dev "$IFACE" xdp off
fi
if [[ -d "$BPF_PIN_DIR" ]]; then
    warn "Cleaning $BPF_PIN_DIR ..."
    rm -rf "$BPF_PIN_DIR"
fi
mkdir -p "$BPF_PIN_DIR"

# ── 8. Loading XDP  ──────────────────────────────────────────
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
" || die "map pin faild"

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

# ── 8. Deploy Daemon ───────────────────────────────────
info "Deploying Daemon → $SYNC_SCRIPT ..."
cat > "$SYNC_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""XDP Port Whitelist Auto-Sync Daemon

Event-driven via Linux Netlink Process Connector (NETLINK_CONNECTOR /
CN_IDX_PROC): the kernel pushes EXEC/EXIT events whenever any process
starts or exits, letting us react to port changes in < 1 ms instead of
waiting for a fixed poll interval.  A configurable fallback poll period
(default 30 s) catches any edge cases where events may be missed.

Architecture:
  kernel -> NETLINK_CONNECTOR (EXEC/EXIT) -> debounce 300 ms -> sync_once()
  + periodic fallback poll every --interval seconds (default 30)
"""
import subprocess, argparse, time, logging, sys, json, socket, struct, select, os
from dataclasses import dataclass, field

TCP_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_whitelist"
UDP_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_whitelist"

# Ports that must always stay whitelisted regardless of whether a process
# is currently listening (e.g. for port-knocking / SSH emergency fallback).
TCP_PERMANENT = {22: "SSH-fallback"}
UDP_PERMANENT = {}

# After a proc EXEC/EXIT event, wait this long before scanning — gives the
# new process time to call bind() before we query ss(8).
DEBOUNCE_S = 0.3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Netlink Process Connector constants ───────────────────────────────
_NETLINK_CONNECTOR    = 11
_CN_IDX_PROC          = 1
_CN_VAL_PROC          = 1
_NLMSG_HDRLEN         = 16
_CN_MSG_HDRLEN        = 20   # idx(4)+val(4)+seq(4)+ack(4)+len(2)+flags(2)
_NLMSG_MIN_TYPE       = 0x10  # first user-defined netlink message type
_PROC_CN_MCAST_LISTEN = 1
_PROC_EVENT_EXEC      = 0x00000002
_PROC_EVENT_EXIT      = 0x80000000


def _make_subscribe_msg(pid: int) -> bytes:
    """Build the NETLINK_CONNECTOR subscription message for proc events."""
    op  = struct.pack("I", _PROC_CN_MCAST_LISTEN)
    cn  = struct.pack("IIIIHH", _CN_IDX_PROC, _CN_VAL_PROC, 0, 0, len(op), 0) + op
    hdr = struct.pack("IHHII", _NLMSG_HDRLEN + len(cn), _NLMSG_MIN_TYPE, 0, 0, pid)
    return hdr + cn


def open_proc_connector():
    """Open and subscribe to the kernel proc-event netlink socket.

    Returns the socket on success, or None if unavailable (non-Linux,
    insufficient privileges, old kernel, etc.).
    """
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, _NETLINK_CONNECTOR)
        sock.bind((os.getpid(), _CN_IDX_PROC))
        sock.send(_make_subscribe_msg(os.getpid()))
        log.info("Netlink proc connector active — event-driven mode enabled")
        return sock
    except OSError as exc:
        log.warning(f"Netlink proc connector unavailable ({exc}); using poll-only mode")
        return None


def drain_proc_events(sock: socket.socket) -> bool:
    """Drain all pending netlink messages; return True if EXEC or EXIT seen."""
    triggered = False
    while True:
        try:
            ready, _, _ = select.select([sock], [], [], 0)
            if not ready:
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
                idx = struct.unpack_from("I", data, cn_off)[0]
                cn_data = cn_off + _CN_MSG_HDRLEN
                if idx == _CN_IDX_PROC and cn_data + 4 <= offset + nl_len:
                    what = struct.unpack_from("I", data, cn_data)[0]
                    if what in (_PROC_EVENT_EXEC, _PROC_EVENT_EXIT):
                        triggered = True
            offset += (nl_len + 3) & ~3  # NLMSG_ALIGN
    return triggered

@dataclass
class PortState:
    tcp: set = field(default_factory=set)
    udp: set = field(default_factory=set)

def get_listening_ports() -> PortState:
    state = PortState()
    try:
        out = subprocess.check_output(
            ["ss", "-lnH", "-t", "-u"], text=True, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        log.error("The `ss` command is not found. Please install iproute2.")
        sys.exit(1)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        try:
            port = int(local.rsplit(":", 1)[-1])
        except ValueError:
            continue
        if proto == "tcp":
            state.tcp.add(port)
        elif proto == "udp":
            state.udp.add(port)
    return state

def port_to_key(port: int):
    # ARRAY map key = __u32 (4 bytes, little-endian host byte order)
    lo = port & 0xFF
    hi = (port >> 8) & 0xFF
    return [f"0x{lo:02x}", f"0x{hi:02x}", "0x00", "0x00"]

def map_update(map_path, port, dry_run):
    # ARRAY map key = __u32 (4 bytes, little-endian host byte order)
    cmd = ["bpftool", "map", "update", "pinned", map_path,
           "key", *port_to_key(port),
           "value", "0x01", "0x00", "0x00", "0x00"]
    if dry_run:
        log.info(f"[DRY] {' '.join(cmd)}")
        return True
    try:
        subprocess.check_call(cmd, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        log.warning(f"update failed port={port}: {e}")
        return False

def map_delete(map_path, port, dry_run):
    # ARRAY maps do not support deletion; zero out the value instead.
    cmd = ["bpftool", "map", "update", "pinned", map_path,
           "key", *port_to_key(port),
           "value", "0x00", "0x00", "0x00", "0x00"]
    if dry_run:
        log.info(f"[DRY] {' '.join(cmd)}")
        return True
    try:
        subprocess.check_call(cmd, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        log.warning(f"delete (zero) failed port={port}: {e}")
        return False

def map_dump_ports(map_path) -> set:
    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", map_path],
            text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return set()
    try:
        entries = json.loads(out)
        ports = set()
        for e in entries:
            # ARRAY map dumps ALL 65536 entries; skip zero-value (unset) slots.
            v = e.get("value", 0)
            val = v if isinstance(v, int) else \
                  (int(v[0], 16) if isinstance(v, list) and v else 0)
            if not val:
                continue
            k = e.get("key")
            if isinstance(k, int):
                ports.add(k)
            elif isinstance(k, list) and len(k) >= 2:
                b0 = int(k[0], 16) if isinstance(k[0], str) else k[0]
                b1 = int(k[1], 16) if isinstance(k[1], str) else k[1]
                ports.add(b0 | (b1 << 8))
        return ports
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return set()

def sync_once(dry_run: bool):
    current    = get_listening_ports()
    tcp_target = current.tcp | set(TCP_PERMANENT)
    udp_target = current.udp | set(UDP_PERMANENT)
    tcp_in_map = map_dump_ports(TCP_MAP_PATH)
    udp_in_map = map_dump_ports(UDP_MAP_PATH)

    changed = False
    for port in sorted(tcp_target - tcp_in_map):
        tag = f" [{TCP_PERMANENT[port]}]" if port in TCP_PERMANENT else ""
        if map_update(TCP_MAP_PATH, port, dry_run):
            log.info(f"TCP Whitelist +{port}{tag}")
            changed = True

    for port in sorted(tcp_in_map - tcp_target - set(TCP_PERMANENT)):
        if map_delete(TCP_MAP_PATH, port, dry_run):
            log.info(f"TCP Whitelist -{port}  (Stopped)")
            changed = True

    for port in sorted(udp_target - udp_in_map):
        tag = f" [{UDP_PERMANENT[port]}]" if port in UDP_PERMANENT else ""
        if map_update(UDP_MAP_PATH, port, dry_run):
            log.info(f"UDP Whitelist +{port}{tag}")
            changed = True

    for port in sorted(udp_in_map - udp_target - set(UDP_PERMANENT)):
        if map_delete(UDP_MAP_PATH, port, dry_run):
            log.info(f"UDP Whitelist -{port}  (Stopped)")
            changed = True

    if not changed:
        log.debug("Port whitelist is up-to-date")

def watch(interval: int, dry_run: bool):
    """Event-driven watch loop.

    - Listens to kernel EXEC/EXIT proc events via NETLINK_CONNECTOR.
    - On event: arms a DEBOUNCE_S timer; syncs when the timer fires.
    - Every `interval` seconds: syncs unconditionally as a safety net.
    - Falls back to pure polling if the netlink socket is unavailable.
    """
    nl = open_proc_connector()
    last_sync_t  = 0.0
    last_event_t = 0.0

    sync_once(dry_run)
    last_sync_t = time.monotonic()

    while True:
        now = time.monotonic()
        poll_due  = last_sync_t + interval
        deb_due   = (last_event_t + DEBOUNCE_S) if last_event_t else float("inf")
        sleep_for = max(0.0, min(poll_due, deb_due) - now)

        try:
            if nl:
                ready, _, _ = select.select([nl], [], [], sleep_for)
                if ready and drain_proc_events(nl):
                    if not last_event_t:
                        log.debug("Proc event received, debounce armed")
                    last_event_t = time.monotonic()
            else:
                time.sleep(sleep_for)
        except OSError as exc:
            log.warning(f"Netlink socket error ({exc}); disabling event-driven mode")
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
            log.debug(f"sync triggered by {reason}")
            try:
                sync_once(dry_run)
            except Exception as exc:
                log.error(f"sync error: {exc}")
            last_sync_t  = time.monotonic()
            last_event_t = 0.0


def main():
    parser = argparse.ArgumentParser(
        description="XDP port-whitelist sync (event-driven via netlink proc connector)")
    parser.add_argument("--watch",    action="store_true",
                        help="Run as a daemon (event-driven + fallback poll)")
    parser.add_argument("--interval", type=int, default=30,
                        help="Fallback poll interval in seconds (default: 30)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Print bpftool commands without executing them")
    args = parser.parse_args()
    if args.watch:
        watch(args.interval, args.dry_run)
    else:
        sync_once(args.dry_run)
        log.info("Sync completed")

if __name__ == "__main__":
    main()
PYEOF
chmod +x "$SYNC_SCRIPT"
ok "Script deployed: $SYNC_SCRIPT"

# ── 9. Enable systemd ────────────────────────────────
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
ok "Deamon enabled: $SERVICE_NAME"

# ── 10. Start test ──────────────────────────────────────
info "Syncing..."
python3 "$SYNC_SCRIPT"

# ── 11. Done ────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment Completed! ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Interface:     $IFACE"
echo "  BPF maps: $BPF_PIN_DIR/"
echo "  Deamon: systemctl status $SERVICE_NAME"
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
