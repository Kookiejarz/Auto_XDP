#!/bin/bash

AUTO_XDP_RUNTIME_COMMON_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AUTO_XDP_SYS_CLASS_NET_DIR="${AUTO_XDP_SYS_CLASS_NET_DIR:-/sys/class/net}"
AUTO_XDP_PROC_IRQ_DIR="${AUTO_XDP_PROC_IRQ_DIR:-/proc/irq}"
AUTO_XDP_PROC_INTERRUPTS="${AUTO_XDP_PROC_INTERRUPTS:-/proc/interrupts}"
AUTO_XDP_CPU_ONLINE_FILE="${AUTO_XDP_CPU_ONLINE_FILE:-/sys/devices/system/cpu/online}"

_auto_xdp_first_value() {
    local name=""
    for name in "$@"; do
        if [[ -n "${!name:-}" ]]; then
            printf '%s' "${!name}"
            return 0
        fi
    done
    return 1
}

_auto_xdp_iface_var_name() {
    local name=""
    for name in AUTO_XDP_IFACES _IFACES IFACES; do
        if declare -p "$name" >/dev/null 2>&1; then
            printf '%s' "$name"
            return 0
        fi
    done
    return 1
}

_auto_xdp_info() {
    if declare -F auto_xdp_shared_info >/dev/null 2>&1; then
        auto_xdp_shared_info "$@"
    fi
}

_auto_xdp_warn() {
    if declare -F auto_xdp_shared_warn >/dev/null 2>&1; then
        auto_xdp_shared_warn "$@"
    else
        printf '[auto_xdp] warning: %s\n' "$*" >&2
    fi
}

_auto_xdp_truthy() {
    case "${1:-}" in
        1|y|Y|yes|YES|true|TRUE|on|ON|enabled|ENABLED)
            return 0
            ;;
    esac
    return 1
}

_auto_xdp_expand_cpu_ranges() {
    local raw="${1:-}" part start end cpu
    IFS=',' read -ra _auto_xdp_parts <<< "$raw"
    for part in "${_auto_xdp_parts[@]}"; do
        [[ -n "$part" ]] || continue
        if [[ "$part" == *-* ]]; then
            start=${part%-*}
            end=${part#*-}
            [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ && $start -le $end ]] || continue
            for ((cpu = start; cpu <= end; cpu++)); do
                printf '%s\n' "$cpu"
            done
        elif [[ "$part" =~ ^[0-9]+$ ]]; then
            printf '%s\n' "$part"
        fi
    done
}

_auto_xdp_online_cpus() {
    local online="0"
    [[ -r "$AUTO_XDP_CPU_ONLINE_FILE" ]] && online=$(<"$AUTO_XDP_CPU_ONLINE_FILE")
    _auto_xdp_expand_cpu_ranges "$online"
}

auto_tune_queues_enabled() {
    _auto_xdp_truthy "${AUTO_TUNE_QUEUES:-1}"
}

_auto_xdp_numeric_field() {
    local text="$1" section="$2" field="$3"

    awk -v section="$section" -v field="$field" '
        $0 ~ ("^" section ":") { in_section=1; next }
        in_section && /^[[:alpha:]][[:alpha:] -]*:$/ { in_section=0 }
        in_section && $1 == field ":" { print $2; exit }
    ' <<< "$text"
}

_auto_xdp_tune_combined_channels() {
    local iface="$1" cpu_count="$2" channels max_combined current_combined target

    command -v ethtool >/dev/null 2>&1 || return 0
    channels=$(ethtool -l "$iface" 2>/dev/null) || return 0

    max_combined=$(_auto_xdp_numeric_field "$channels" "Pre-set maximums" "Combined")
    current_combined=$(_auto_xdp_numeric_field "$channels" "Current hardware settings" "Combined")

    [[ "$max_combined" =~ ^[0-9]+$ ]] || return 0

    target=$cpu_count
    (( target > max_combined )) && target=$max_combined
    (( target < 1 )) && target=1

    if [[ "$current_combined" =~ ^[0-9]+$ ]] && (( current_combined == target )); then
        return 0
    fi

    if ethtool -L "$iface" combined "$target" >/dev/null 2>&1; then
        _auto_xdp_info "Set $iface combined channels to $target."
    elif (( cpu_count > 1 && max_combined <= 1 )); then
        _auto_xdp_warn "$iface exposes only $max_combined combined queue; a single CPU may bottleneck receive load."
    fi
}

_auto_xdp_iface_irqs() {
    local iface="$1" irq irq_path
    local msi_dir="${AUTO_XDP_SYS_CLASS_NET_DIR}/${iface}/device/msi_irqs"

    if [[ -d "$msi_dir" ]]; then
        for irq_path in "$msi_dir"/*; do
            [[ -e "$irq_path" ]] || continue
            irq=${irq_path##*/}
            awk -v irq="$irq" -v iface="$iface" '
                $1 == irq ":" && index($0, iface) { print irq; found=1; exit }
                END { exit(found ? 0 : 1) }
            ' "$AUTO_XDP_PROC_INTERRUPTS" 2>/dev/null || continue
        done | sort -n -u
        return 0
    fi

    awk -v iface="$iface" '
        index($0, iface) {
            irq=$1
            sub(/:$/, "", irq)
            gsub(/^[[:space:]]+/, "", irq)
            if (irq ~ /^[0-9]+$/)
                print irq
        }
    ' "$AUTO_XDP_PROC_INTERRUPTS" 2>/dev/null | sort -n -u
}

_auto_xdp_balance_iface_irqs() {
    local iface="$1" irq idx cpu affinity_path
    local -a cpus=() irqs=()

    mapfile -t cpus < <(_auto_xdp_online_cpus)
    (( ${#cpus[@]} > 0 )) || return 0

    mapfile -t irqs < <(_auto_xdp_iface_irqs "$iface")
    (( ${#irqs[@]} > 0 )) || return 0

    for idx in "${!irqs[@]}"; do
        irq="${irqs[$idx]}"
        cpu="${cpus[$((idx % ${#cpus[@]}))]}"
        affinity_path="${AUTO_XDP_PROC_IRQ_DIR}/${irq}/smp_affinity_list"
        [[ -w "$affinity_path" ]] || continue
        printf '%s\n' "$cpu" > "$affinity_path" 2>/dev/null || true
    done

    _auto_xdp_info "Balanced ${#irqs[@]} IRQ(s) for $iface across ${#cpus[@]} CPU(s)."
}

auto_tune_interface_parallelism() {
    local iface_var iface
    local -a cpus=()

    auto_tune_queues_enabled || return 0

    iface_var=$(_auto_xdp_iface_var_name) || return 0
    local -n ifaces_ref="$iface_var"

    mapfile -t cpus < <(_auto_xdp_online_cpus)
    (( ${#cpus[@]} > 0 )) || return 0

    for iface in "${ifaces_ref[@]}"; do
        _auto_xdp_tune_combined_channels "$iface" "${#cpus[@]}"
        _auto_xdp_balance_iface_irqs "$iface"
    done
}

ensure_bpffs() {
    if ! mount | grep -q 'type bpf'; then
        _auto_xdp_info "Mounting bpffs on /sys/fs/bpf..."
        mount -t bpf bpf /sys/fs/bpf || {
            _auto_xdp_warn "bpffs mount failed."
            return 1
        }
    fi
}

cleanup_tc_egress_filter() {
    command -v tc &>/dev/null || return 0
    local iface_var iface
    iface_var=$(_auto_xdp_iface_var_name) || return 0
    local -n ifaces_ref="$iface_var"
    for iface in "${ifaces_ref[@]}"; do
        tc filter del dev "$iface" egress pref "${TC_FILTER_PREF:-49152}" 2>/dev/null || true
    done
}

xdp_maps_ready() {
    local map_name=""
    while IFS= read -r map_name; do
        [[ -n "$map_name" ]] || continue
        [[ -e "${BPF_PIN_DIR}/${map_name}" ]] || return 1
    done < <(xdp_required_map_names)
}

_auto_xdp_required_maps_file() {
    local candidate=""

    for candidate in \
        "${XDP_REQUIRED_MAPS_FILE:-}" \
        "${AUTO_XDP_RUNTIME_COMMON_DIR}/xdp_required_maps.txt" \
        "${AUTO_XDP_RUNTIME_COMMON_DIR}/../auto_xdp/xdp_required_maps.txt" \
        "${AUTO_XDP_PACKAGE_DIR:-}/xdp_required_maps.txt" \
        "${INSTALL_DIR:-}/xdp_required_maps.txt"; do
        [[ -n "$candidate" && -f "$candidate" ]] || continue
        printf '%s\n' "$candidate"
        return 0
    done

    return 1
}

xdp_required_map_names() {
    local maps_file="" line=""

    if maps_file=$(_auto_xdp_required_maps_file); then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line=${line%%#*}
            line=${line%$'\r'}
            [[ -n "$line" ]] && printf '%s\n' "$line"
        done < "$maps_file"
        return 0
    fi

    cat <<'EOF'
prog
pkt_counters
byte_counters
tcp_whitelist
udp_whitelist
sctp_whitelist
tcp_ct4
tcp_ct6
udp_ct4
udp_ct6
sctp_conntrack
trusted_ipv4
trusted_ipv6
tcp_port_policies
udp_port_policies
udp_global_rl
xdp_runtime_cfg
udp_percpu_acc
bogon_cfg
observability_cfg
proto_handlers
tcp_port_handlers
udp_port_handlers
tcp_pd4
tcp_pd6
hblk4
hblk6
udp_hv4
udp_hv6
slot_ctx_map
slot_def_action
EOF
}

seed_existing_tcp_conntrack() {
    local map_path_v4="${BPF_PIN_DIR}/tcp_ct4"
    local map_path_v6="${BPF_PIN_DIR}/tcp_ct6"
    local seeded=""
    local helper_script=""

    [[ -e "$map_path_v4" || -e "$map_path_v6" ]] || return 0

    helper_script=$(_auto_xdp_first_value BPF_HELPER_BOOTSTRAP BPF_HELPER_SCRIPT) || {
        _auto_xdp_warn "BPF helper is not available for conntrack seeding."
        return 0
    }

    if ! seeded=$("${PYTHON3_BIN:-python3}" "$helper_script" seed-tcp-conntrack --map-path-v4 "$map_path_v4" --map-path-v6 "$map_path_v6"); then
        _auto_xdp_warn "Failed to pre-seed tcp_ct4/tcp_ct6; established sessions may reconnect."
        return 0
    fi

    if [[ "$seeded" != "0" ]]; then
        _auto_xdp_info "Seeded ${seeded} existing TCP session(s) into tcp_ct4/tcp_ct6."
    fi
}

load_tc_egress_program() {
    local tc_prog_path="${BPF_PIN_DIR}/tc_egress_prog"
    local tc_obj_path=""
    local iface_var iface attached=0

    if ! command -v tc &>/dev/null; then
        _auto_xdp_warn "tc not found; TCP/UDP/SCTP reply tracking on egress will be skipped."
        return 1
    fi

    tc_obj_path=$(_auto_xdp_first_value TC_OBJ_PATH TC_OBJ_INSTALLED) || tc_obj_path=""
    # Remove the old filter before wiping the pin so the old program's
    # reference count reaches zero and it is freed immediately. If we only
    # remove the pin and tc filter replace later fails, the old program is
    # left with just its filter reference and becomes a zombie.
    cleanup_tc_egress_filter
    rm -f "$tc_prog_path"
    if [[ ! -f "$tc_obj_path" ]]; then
        _auto_xdp_warn "tc egress object not found; TCP/UDP/SCTP reply tracking on egress will be skipped."
        return 1
    fi

    if ! bpftool prog load "$tc_obj_path" "$tc_prog_path" \
        type classifier \
        map name tcp_ct4 pinned "${BPF_PIN_DIR}/tcp_ct4" \
        map name tcp_ct6 pinned "${BPF_PIN_DIR}/tcp_ct6" \
        map name udp_ct4 pinned "${BPF_PIN_DIR}/udp_ct4" \
        map name udp_ct6 pinned "${BPF_PIN_DIR}/udp_ct6" \
        map name sctp_conntrack pinned "${BPF_PIN_DIR}/sctp_conntrack" >/dev/null 2>&1; then
        _auto_xdp_warn "Failed to load tc egress program; outbound TCP/UDP/SCTP reply tracking will be limited."
        return 1
    fi

    iface_var=$(_auto_xdp_iface_var_name) || {
        _auto_xdp_warn "No interfaces configured for tc egress attach."
        return 1
    }
    local -n ifaces_ref="$iface_var"
    if [[ ${#ifaces_ref[@]} -eq 0 ]]; then
        _auto_xdp_warn "No interfaces configured for tc egress attach."
        return 1
    fi

    for iface in "${ifaces_ref[@]}"; do
        tc qdisc add dev "$iface" clsact 2>/dev/null || true
        if tc filter replace dev "$iface" egress pref "${TC_FILTER_PREF:-49152}" \
            bpf direct-action object-pinned "$tc_prog_path" >/dev/null 2>&1; then
            _auto_xdp_info "Attached tc egress TCP/UDP/SCTP tracker on $iface."
            attached=$((attached + 1))
        else
            _auto_xdp_warn "Failed to attach tc egress filter on $iface; reply tracking will be limited for this interface."
        fi
    done

    [[ $attached -gt 0 ]] && return 0 || return 1
}

load_slot_handlers() {
    local handlers_dir="${AUTO_XDP_HANDLERS_DIR:-${HANDLERS_DIR:-${INSTALL_DIR}/handlers}}"
    local py_bin="${PYTHON3_BIN:-python3}"

    [[ -e "${BPF_PIN_DIR}/proto_handlers" ]] || {
        _auto_xdp_warn "proto_handlers map not pinned; skipping slot handler loading."
        return 0
    }

    local default_action="pass"
    local enabled_json="[]"
    if command -v "$py_bin" &>/dev/null && [[ -f "$TOML_CONFIG" ]]; then
        IFS='|' read -r default_action enabled_json < <("$py_bin" -c "
import json, sys
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        print('pass|[]')
        sys.exit(0)
try:
    with open('${TOML_CONFIG}', 'rb') as f:
        cfg = tomllib.load(f)
    slots = cfg.get('slots', {})
    print(slots.get('default_action', 'pass') + '|' + json.dumps(slots.get('enabled', [])))
except (OSError, ValueError):
    print('pass|[]')
" 2>/dev/null) || true
        default_action="${default_action:-pass}"
        enabled_json="${enabled_json:-[]}"
    fi
    local action_val=0
    [[ "$default_action" == "drop" ]] && action_val=1
    bpftool map update pinned "${BPF_PIN_DIR}/slot_def_action" \
        key 0 0 0 0 value "$action_val" 0 0 0 2>/dev/null \
        && _auto_xdp_info "Slot default_action: ${default_action}" \
        || _auto_xdp_warn "Failed to set slot default_action"

    [[ "$enabled_json" == "[]" ]] && return 0
    [[ -d "$handlers_dir" ]] || {
        _auto_xdp_warn "Handlers dir $handlers_dir not found; skipping slot loading."
        return 0
    }

    local slot_pin_dir="${BPF_PIN_DIR}/handlers"
    mkdir -p "$slot_pin_dir"

    "$py_bin" - "$enabled_json" "$handlers_dir" "$slot_pin_dir" \
        "${BPF_PIN_DIR}" <<'PYEOF'
import sys, json, subprocess, os

enabled = json.loads(sys.argv[1])
handlers_dir = sys.argv[2]
slot_pin_dir = sys.argv[3]
bpf_pin_dir = sys.argv[4]

BUILTIN = {"gre": (47, "gre_handler.o"),
           "esp": (50, "esp_handler.o"),
           "sctp": (132, "sctp_handler.o")}

for entry in enabled:
    if isinstance(entry, str):
        if entry not in BUILTIN:
            print(f"  [WARN] Unknown built-in handler: {entry}", file=sys.stderr)
            continue
        proto, obj_name = BUILTIN[entry]
        obj_path = os.path.join(handlers_dir, obj_name)
    elif isinstance(entry, dict):
        proto = int(entry["proto"])
        obj_path = entry["path"]
    else:
        continue

    if not os.path.exists(obj_path):
        print(f"  [WARN] Handler not found: {obj_path}", file=sys.stderr)
        continue

    pin_path = os.path.join(slot_pin_dir, f"proto_{proto}")
    ctx_map = os.path.join(bpf_pin_dir, "slot_ctx_map")
    load_cmd = [
        "bpftool", "prog", "load", obj_path, pin_path,
        "type", "xdp",
        "map", "name", "slot_ctx_map", "pinned", ctx_map,
    ]
    if proto == 132:
        sctp_whitelist = os.path.join(bpf_pin_dir, "sctp_whitelist")
        sctp_conntrack = os.path.join(bpf_pin_dir, "sctp_conntrack")
        if not (os.path.exists(sctp_whitelist) and os.path.exists(sctp_conntrack)):
            print("  [WARN] Shared SCTP maps not pinned; skipping proto 132", file=sys.stderr)
            continue
        load_cmd.extend([
            "map", "name", "sctp_whitelist", "pinned", sctp_whitelist,
            "map", "name", "sctp_conntrack", "pinned", sctp_conntrack,
        ])

    r = subprocess.run(load_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  [WARN] Failed to load proto {proto}: {r.stderr.strip()}", file=sys.stderr)
        continue

    k = f"{proto} 0 0 0"
    r2 = subprocess.run(
        ["bpftool", "map", "update", "pinned",
         os.path.join(bpf_pin_dir, "proto_handlers"),
         "key", *k.split(), "value", "pinned", pin_path],
        capture_output=True, text=True)
    if r2.returncode != 0:
        print(f"  [WARN] Failed to register proto {proto}: {r2.stderr.strip()}", file=sys.stderr)
        os.unlink(pin_path)
    else:
        print(f"  Loaded slot handler: proto {proto} ({obj_path})")
PYEOF
}

load_port_handlers() {
    local py_bin="${PYTHON3_BIN:-python3}"
    local install_dir="${INSTALL_DIR:-/usr/local/lib/auto_xdp}"

    [[ -e "${BPF_PIN_DIR}/slot_ctx_map" ]] || {
        _auto_xdp_warn "slot_ctx_map not pinned; skipping per-port handler loading."
        return 0
    }

    [[ -f "$TOML_CONFIG" ]] || return 0

    "$py_bin" - "$TOML_CONFIG" "${BPF_PIN_DIR}" "$install_dir" <<'PYEOF'
import json
import os
import subprocess
import sys

config_path, bpf_pin_dir, install_dir = sys.argv[1:4]

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        raise SystemExit(0)

try:
    with open(config_path, "rb") as fh:
        cfg = tomllib.load(fh)
except (OSError, ValueError):
    raise SystemExit(0)

entries = []
for proto in ("tcp", "udp"):
    table = cfg.get("port_handlers", {}).get(proto, {})
    if not isinstance(table, dict):
        continue
    for raw_port, raw_path in table.items():
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            print(f"  [WARN] Invalid {proto} port handler key: {raw_port!r}", file=sys.stderr)
            continue
        path = str(raw_path)
        if not path:
            continue
        entries.append((proto, port, path))

for proto, port, path in sorted(entries):
    cmd = [
        sys.executable,
        "-m",
        "auto_xdp.admin_cli",
        "--config",
        config_path,
        "--bpf-pin-dir",
        bpf_pin_dir,
        "--install-dir",
        install_dir,
        "port-handler",
        "load",
        "--no-config-update",
        proto,
        str(port),
        path,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        print(f"  [WARN] Failed to load {proto}/{port}: {detail}", file=sys.stderr)
        continue
    print(f"  Loaded per-port handler: {proto}/{port} ({path})")
PYEOF
}
