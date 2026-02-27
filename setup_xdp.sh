#!/bin/bash
# =============================================================
# setup_xdp.sh — One-click compilation / loading of XDP firewall + port-sync daemon
# Usage: sudo bash setup_xdp.sh [interface]
#        sudo bash setup_xdp.sh eth0
#        If no interface is given, the default-route interface is detected automatically.
# =============================================================
set -euo pipefail

# ── Coloured output ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }

# ── Settings ──────────────────────────────────────────────────────────
IFACE="${1:-}"
XDP_SRC="xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"
export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
SYNC_SCRIPT="/usr/local/bin/xdp_port_sync.py"
SERVICE_NAME="xdp-port-sync"
SYNC_INTERVAL=30
RAW_URL="https://raw.githubusercontent.com/Kookiejarz/basic_xdp/main"

# ── 1. Root check ─────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Please run this script with sudo."

# ── 2. Interface detection ────────────────────────────────────────────
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    [[ -n "$IFACE" ]] || die "Cannot detect default interface. Specify manually: sudo bash $0 eth0"
    info "Detected interface: $IFACE"
fi
ip link show "$IFACE" &>/dev/null || die "Interface $IFACE does not exist."

# ── 3. Dependency check & install ────────────────────────────────────
info "Checking dependencies..."
MISSING=()
for cmd in clang bpftool python3; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done
[[ -d /usr/include/linux ]] || MISSING+=("linux-headers")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing: ${MISSING[*]} — installing..."
    export DEBIAN_FRONTEND=noninteractive
    APT_OPTS="-y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

        apt-get update -qq

        apt-get install $APT_OPTS clang llvm libbpf-dev build-essential iproute2 \
                        python3 python3-pip gcc-multilib

        apt-get install $APT_OPTS linux-tools-common linux-tools-generic \
                        "linux-tools-$(uname -r)" "linux-headers-$(uname -r)"

    # Ensure pip is available for the psutil install below
        apt-get install $APT_OPTS python3-pip

    if ! command -v bpftool &>/dev/null; then
        REAL_BPFTOOL=$(find /usr/lib/linux-tools -name bpftool -type f -executable \
                       -print -quit 2>/dev/null || true)
        if [[ -n "$REAL_BPFTOOL" ]]; then
            ln -sf "$REAL_BPFTOOL" /usr/local/bin/bpftool
            ok "Symlinked bpftool from $REAL_BPFTOOL"
        fi
    fi
    unset DEBIAN_FRONTEND
fi

# Always ensure psutil is available.
# Prefer apt (respects the system-managed Python env); fall back to pip only if needed.
if ! python3 -c "import psutil" 2>/dev/null; then
    apt-get install -y -qq python3-psutil 2>/dev/null \
        || python3 -m pip install --quiet --break-system-packages psutil
fi

command -v bpftool &>/dev/null || die "bpftool not found. Run: apt install linux-tools-generic"
ok "All dependencies satisfied."

# ── 4. Fetch source ───────────────────────────────────────────────────
info "Fetching $XDP_SRC from GitHub..."
curl -fsSL "${RAW_URL}/${XDP_SRC}" -o "$XDP_SRC" || die "Failed to download $XDP_SRC"
ok "Downloaded $XDP_SRC"

# ── 5. Compile XDP program ────────────────────────────────────────────
info "Compiling $XDP_SRC..."
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ASM_INC="/usr/include/x86_64-linux-gnu";   TARGET_ARCH="x86"   ;;
    aarch64) ASM_INC="/usr/include/aarch64-linux-gnu";   TARGET_ARCH="arm64" ;;
    armv7*)  ASM_INC="/usr/include/arm-linux-gnueabihf"; TARGET_ARCH="arm"   ;;
    *)       ASM_INC="/usr/include/${ARCH}-linux-gnu";   TARGET_ARCH="$ARCH" ;;
esac

if [[ ! -d "$ASM_INC" ]]; then
    ASM_INC="/usr/src/linux-headers-$(uname -r)/arch/${TARGET_ARCH}/include/generated"
fi
if [[ ! -d "$ASM_INC" && -d "/usr/include/asm" ]]; then
    ASM_INC="/usr/include"
fi
if [[ ! -d "$ASM_INC" ]]; then
    ASM_INC=$(find /usr/src -name "asm" -type d -print -quit \
              | xargs dirname 2>/dev/null || echo "")
fi
[[ -d "$ASM_INC" ]] || die "ASM headers not found. Try: apt install gcc-multilib"
info "Using ASM headers: $ASM_INC"

clang -O3 -g \
    -target bpf \
    -mcpu=v3 \
    "-D__TARGET_ARCH_${TARGET_ARCH}" \
    -fno-stack-protector \
    -Wall -Wno-unused-value \
    -I/usr/include \
    -I"$ASM_INC" \
    -I/usr/include/bpf \
    -c "$XDP_SRC" -o "$XDP_OBJ"
ok "Compiled → $XDP_OBJ"

# ── 6. Mount bpffs ────────────────────────────────────────────────────
if ! mount | grep -q 'type bpf'; then
    info "Mounting bpffs on /sys/fs/bpf..."
    mount -t bpf bpf /sys/fs/bpf || die "bpffs mount failed."
fi

# ── 7. Clean up existing XDP programs & services ─────────────────────
info "Ensuring a clean slate..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
pkill -f "xdp_port_sync.py" || true
pkill -f "xdp-sync-ports.py" || true

if ip link show "$IFACE" | grep -q "xdp"; then
    warn "Existing XDP program detected on $IFACE — detaching..."
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    ip link set dev "$IFACE" xdp generic off 2>/dev/null || true
fi

if [[ -d "$BPF_PIN_DIR" ]]; then
    warn "Removing old BPF pin directory $BPF_PIN_DIR..."
    rm -rf "$BPF_PIN_DIR"
fi
mkdir -p "$BPF_PIN_DIR"

# ── 8. Load XDP program ───────────────────────────────────────────────
info "Loading XDP program onto $IFACE..."
bpftool prog load "$XDP_OBJ" "$BPF_PIN_DIR/prog"

PROG_ID=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" \
          | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
info "Loaded program ID: $PROG_ID"

# Pin all maps used by the program
bpftool -j prog show id "$PROG_ID" | python3 -c "
import json, subprocess, sys, os
prog    = json.load(sys.stdin)
pin_dir = os.environ['BPF_PIN_DIR']
for map_id in prog.get('map_ids', []):
    info     = json.loads(subprocess.check_output(['bpftool','-j','map','show','id',str(map_id)]))
    name     = info.get('name', f'map_{map_id}')
    pin_path = f'{pin_dir}/{name}'
    subprocess.check_call(['bpftool','map','pin','id',str(map_id), pin_path])
    print(f'  pinned [{name}] → {pin_path}')
" || die "Map pinning failed."

# Attach — prefer native mode, fall back to generic
if ip link set dev "$IFACE" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
    ok "XDP attached in native mode on $IFACE"
else
    warn "Native mode unsupported — falling back to generic mode..."
    ip link set dev "$IFACE" xdp generic pinned "$BPF_PIN_DIR/prog"
    ok "XDP attached in generic mode on $IFACE"
fi
ip link show "$IFACE" | grep -q "xdp" || die "XDP failed to attach to $IFACE"

info "Pinned BPF maps:"
ls "$BPF_PIN_DIR/"
echo ""

# ── 9. Deploy sync daemon ─────────────────────────────────────────────
info "Deploying daemon → $SYNC_SCRIPT..."

if [[ -f "xdp_port_sync.py" ]]; then
    cp "xdp_port_sync.py" "$SYNC_SCRIPT"
    info "Using local xdp_port_sync.py"
else
    info "Fetching xdp_port_sync.py from GitHub..."
    curl -fsSL "${RAW_URL}/xdp_port_sync.py" -o "$SYNC_SCRIPT" || die "Failed to download daemon"
fi

chmod +x "$SYNC_SCRIPT"
ok "Daemon deployed: $SYNC_SCRIPT"

# ── 10. Enable systemd service ────────────────────────────────────────
info "Creating systemd service: $SERVICE_NAME..."
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
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
ok "Service started and enabled: $SERVICE_NAME"

# ── 11. Initial sync ──────────────────────────────────────────────────
info "Running initial sync..."
python3 "$SYNC_SCRIPT"

# ── 12. Summary ───────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment Complete!                  ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Interface : $IFACE"
echo "  BPF maps  : $BPF_PIN_DIR/"
echo "  Service   : systemctl status $SERVICE_NAME"
echo ""
echo "  Whitelisted TCP ports:"
bpftool -j map dump pinned "${BPF_PIN_DIR}/tcp_whitelist" 2>/dev/null \
  | python3 -c "
import json, sys
try:
    for e in json.load(sys.stdin):
        if not isinstance(e, dict):
            continue
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
except Exception:
    pass
" || echo "    (none)"
echo ""
echo "  Uninstall : ip link set dev $IFACE xdp off"
echo ""
