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

_auto_xdp_use_bpftool() {
    local candidate="$1" candidate_dir

    BPFTOOL_BIN="$candidate"
    export BPFTOOL_BIN
    if [[ "$candidate" == /* ]]; then
        candidate_dir=${candidate%/*}
        case ":${PATH:-}:" in
            *":${candidate_dir}:"*) ;;
            *) PATH="${candidate_dir}${PATH:+:${PATH}}"; export PATH ;;
        esac
        hash -r 2>/dev/null || true
    fi
}

_auto_xdp_resolve_bpftool() {
    local candidate kernel_release tools_root

    if [[ -n "${BPFTOOL_BIN:-}" ]]; then
        if [[ "$BPFTOOL_BIN" == /* && -x "$BPFTOOL_BIN" ]] \
                && "$BPFTOOL_BIN" version >/dev/null 2>&1; then
            _auto_xdp_use_bpftool "$BPFTOOL_BIN"
            return 0
        fi
        if [[ "$BPFTOOL_BIN" != /* ]] \
                && command -v "$BPFTOOL_BIN" >/dev/null 2>&1 \
                && "$BPFTOOL_BIN" version >/dev/null 2>&1; then
            _auto_xdp_use_bpftool "$BPFTOOL_BIN"
            return 0
        fi
    fi

    candidate=$(command -v bpftool 2>/dev/null || true)
    if [[ "$candidate" == /* ]]; then
        if "$candidate" version >/dev/null 2>&1; then
            _auto_xdp_use_bpftool "$candidate"
            return 0
        fi
    elif [[ -n "$candidate" ]] && bpftool version >/dev/null 2>&1; then
        _auto_xdp_use_bpftool "$candidate"
        return 0
    fi

    kernel_release=$(uname -r)
    tools_root="${AUTO_XDP_LINUX_TOOLS_DIR:-/usr/lib/linux-tools}"
    candidate="${tools_root}/${kernel_release}/bpftool"
    if [[ -x "$candidate" ]] && "$candidate" version >/dev/null 2>&1; then
        _auto_xdp_use_bpftool "$candidate"
        return 0
    fi

    for candidate in "${tools_root}"/*/bpftool; do
        [[ -x "$candidate" ]] || continue
        "$candidate" version >/dev/null 2>&1 || continue
        _auto_xdp_use_bpftool "$candidate"
        return 0
    done

    return 1
}

_auto_xdp_print_verifier_summary() {
    local verifier_log="$1" summary

    summary=$(awk '
        /found program .*code size [0-9]+ insns/ {
            for (i = 1; i <= NF; i++)
                if ($i == "size") static_insns += $(i + 1)
        }
        /^verification time [0-9]+ usec$/ { verification_time_usec = $3 }
        /^stack depth [0-9]+(\+[0-9]+)*$/ {
            stack_depth = $3
            sub(/\+.*/, "", stack_depth)
        }
        /^processed [0-9]+ insns / {
            processed_insns = $2
            for (i = 1; i <= NF; i++) {
                if ($i == "max_states_per_insn") max_states_per_insn = $(i + 1)
                if ($i == "total_states") total_states = $(i + 1)
                if ($i == "peak_states") peak_states = $(i + 1)
            }
        }
        END {
            printf "static_insns=%s processed_insns=%s max_states_per_insn=%s total_states=%s peak_states=%s verification_time_usec=%s stack_depth=%s\n",
                   static_insns ? static_insns : "-",
                   processed_insns ? processed_insns : "-",
                   max_states_per_insn ? max_states_per_insn : "-",
                   total_states ? total_states : "-",
                   peak_states ? peak_states : "-",
                   verification_time_usec ? verification_time_usec : "-",
                   stack_depth ? stack_depth : "-"
        }
    ' "$verifier_log" 2>/dev/null || true)
    printf '[auto_xdp] verifier summary: %s\n' "${summary:-unavailable}" >&2
}

_auto_xdp_truthy() {
    case "${1:-}" in
        1|y|Y|yes|YES|true|TRUE|on|ON|enabled|ENABLED)
            return 0
            ;;
    esac
    return 1
}

_auto_xdp_resolve_preferred_backend() {
    local config_path="${1:-${TOML_CONFIG:-}}"
    local default="${2:-${PREFERRED_BACKEND:-auto}}"

    [[ -f "$config_path" ]] || {
        printf '%s\n' "$default"
        return 0
    }
    local python_root="${PYTHON_LIB_DIR:-${AUTO_XDP_RUNTIME_COMMON_DIR}/..}"
    PYTHONPATH="$python_root${PYTHONPATH:+:$PYTHONPATH}" "${PYTHON3_BIN:-python3}" - "$config_path" "$default" <<'PY'
import sys
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        print(sys.argv[2])
        raise SystemExit(0)

try:
    with open(sys.argv[1], "rb") as handle:
        config = tomllib.load(handle)
        from auto_xdp.config import module_configs
        try:
            modules = module_configs(config)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        value = str(config.get("daemon", {}).get("preferred_backend", sys.argv[2])).lower()
    if modules.get("icmp", {}).get("enabled", False):
        if value == "nftables":
            raise SystemExit("ICMP reply protection requires the XDP backend")
        value = "xdp"  # A requested kernel module must not silently disappear in fallback.
except Exception:
    value = sys.argv[2]
print(value if value in {"auto", "xdp", "nftables"} else sys.argv[2])
PY
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

# Return CPUs on the NUMA node local to the given NIC, one per line.
# Falls back to empty output (caller should then use all online CPUs).
_auto_xdp_iface_numa_cpus() {
    local iface="$1"
    local numa_node_path="${AUTO_XDP_SYS_CLASS_NET_DIR}/${iface}/device/numa_node"

    [[ -r "$numa_node_path" ]] || return 1
    local node
    node=$(<"$numa_node_path")
    # -1 means the platform doesn't expose NUMA topology
    [[ "$node" =~ ^[0-9]+$ ]] || return 1

    local cpulist_path="/sys/devices/system/node/node${node}/cpulist"
    [[ -r "$cpulist_path" ]] || return 1
    _auto_xdp_expand_cpu_ranges "$(<"$cpulist_path")"
}

_auto_xdp_check_irqbalance() {
    local running=0
    if systemctl is-active --quiet irqbalance 2>/dev/null; then
        running=1
    elif pgrep -x irqbalance >/dev/null 2>&1; then
        running=1
    fi
    (( running )) || return 0

    _auto_xdp_warn "irqbalance is running and will override IRQ affinity settings."

    if _auto_xdp_truthy "${FORCE:-0}"; then
        _auto_xdp_info "Stopping irqbalance (--force)."
        systemctl stop irqbalance 2>/dev/null \
            || service irqbalance stop 2>/dev/null \
            || _auto_xdp_warn "Could not stop irqbalance; IRQ affinity may be overridden at next rebalance."
        return 0
    fi

    # Only prompt if we're in a setup context where confirm_yes_no is available.
    if declare -F confirm_yes_no >/dev/null 2>&1; then
        if confirm_yes_no "Stop irqbalance now to preserve IRQ affinity settings? [y/N] "; then
            systemctl stop irqbalance 2>/dev/null \
                || service irqbalance stop 2>/dev/null \
                || _auto_xdp_warn "Could not stop irqbalance."
        else
            _auto_xdp_warn "irqbalance left running; IRQ affinity settings may be overridden. Re-run with --force to stop automatically."
        fi
    else
        _auto_xdp_warn "Run 'systemctl stop irqbalance' to allow IRQ affinity pinning to take effect."
    fi
}

_auto_xdp_balance_iface_irqs() {
    local iface="$1" irq idx cpu affinity_path
    local -a cpus=() irqs=() all_cpus=()

    # Prefer CPUs on the NIC's NUMA node; fall back to all online CPUs.
    mapfile -t cpus < <(_auto_xdp_iface_numa_cpus "$iface" 2>/dev/null)
    local numa_local=${#cpus[@]}
    if (( numa_local == 0 )); then
        mapfile -t cpus < <(_auto_xdp_online_cpus)
    fi
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

    if (( numa_local > 0 )); then
        mapfile -t all_cpus < <(_auto_xdp_online_cpus)
        _auto_xdp_info "Balanced ${#irqs[@]} IRQ(s) for $iface across ${#cpus[@]} NUMA-local CPU(s) (node $(< "${AUTO_XDP_SYS_CLASS_NET_DIR}/${iface}/device/numa_node"), ${#all_cpus[@]} total online)."
    else
        _auto_xdp_info "Balanced ${#irqs[@]} IRQ(s) for $iface across ${#cpus[@]} CPU(s) (no NUMA topology available)."
    fi
}

auto_tune_interface_parallelism() {
    local iface_var iface
    local -a cpus=()

    auto_tune_queues_enabled || return 0

    iface_var=$(_auto_xdp_iface_var_name) || return 0
    local -n ifaces_ref="$iface_var"

    mapfile -t cpus < <(_auto_xdp_online_cpus)
    (( ${#cpus[@]} > 0 )) || return 0

    _auto_xdp_check_irqbalance

    for iface in "${ifaces_ref[@]}"; do
        _auto_xdp_tune_combined_channels "$iface" "${#cpus[@]}"
        _auto_xdp_balance_iface_irqs "$iface"
    done
}

ensure_bpffs() {
    if ! mountpoint -q /sys/fs/bpf; then
        _auto_xdp_info "Mounting bpffs on /sys/fs/bpf..."
        mount -t bpf bpf /sys/fs/bpf || {
            _auto_xdp_warn "bpffs mount failed."
            return 1
        }
    fi
}

_map_value_size_ok() {
    local _path="$1" _want="$2" _got=""
    _got=$(bpftool map show pinned "$_path" 2>/dev/null \
               | sed -n 's/.*\bvalue \([0-9]*\)B.*/\1/p')
    # If bpftool can't query the map (unavailable or old format), skip the guard.
    [[ -z "$_got" || "$_got" == "$_want" ]]
}

_map_max_entries_ok() {
    local _path="$1" _want="$2" _got=""
    _got=$(bpftool map show pinned "$_path" 2>/dev/null \
               | sed -n 's/.*max_entries \([0-9]*\).*/\1/p')
    # Keep non-Linux/unit-test environments compatible when bpftool cannot
    # inspect a placeholder pin; real Linux pins report max_entries here.
    [[ -z "$_got" || "$_got" == "$_want" ]]
}

_map_abi_shape_ok() {
    local path="$1" type="$2" key="$3" value="$4" info=""
    info=$(bpftool map show pinned "$path" 2>/dev/null) || return 0
    [[ "$info" =~ (^|[[:space:]])$type[[:space:]]+name[[:space:]] ]] || return 1
    [[ "$info" =~ key[[:space:]]${key}B([[:space:]]|$) ]] || return 1
    [[ "$info" =~ value[[:space:]]${value}B([[:space:]]|$) ]]
}

_xdp_map_abi_file() {
    local candidate=""
    for candidate in \
        "${XDP_MAP_ABI_FILE:-}" \
        "${BPF_PIN_DIR}/xdp_map_abi.txt" \
        "${AUTO_XDP_RUNTIME_COMMON_DIR}/xdp_map_abi.txt" \
        "${AUTO_XDP_RUNTIME_COMMON_DIR}/../auto_xdp/xdp_map_abi.txt" \
        "${INSTALL_DIR:-}/xdp_map_abi.txt"; do
        [[ -n "$candidate" && -f "$candidate" ]] || continue
        printf '%s\n' "$candidate"
        return 0
    done
    return 1
}

_xdp_map_abi_ready() {
    local abi_file="" map_name="" field2="" field3="" field4="" field5=""
    abi_file=$(_xdp_map_abi_file) || {
        _auto_xdp_warn "XDP map ABI manifest is missing; forcing runtime reload"
        return 1
    }
    while read -r map_name field2 field3 field4 field5; do
        [[ -z "$map_name" || "$map_name" == \#* ]] && continue
        if [[ -n "$field5" ]]; then
            [[ "$field3" =~ ^[0-9]+$ && "$field4" =~ ^[0-9]+$ && "$field5" =~ ^[0-9]+$ ]] || return 1
            _map_abi_shape_ok "${BPF_PIN_DIR}/${map_name}" "$field2" "$field3" "$field4" || return 1
            _map_max_entries_ok "${BPF_PIN_DIR}/${map_name}" "$field5" || return 1
            continue
        fi
        [[ "$field2" =~ ^[0-9]+$ ]] || return 1
        _map_max_entries_ok "${BPF_PIN_DIR}/${map_name}" "$field2" || {
            _auto_xdp_warn "${map_name} max_entries mismatch; forcing XDP reload"
            return 1
        }
    done <"$abi_file"
}

xdp_maps_ready() {
    local map_name=""
    while IFS= read -r map_name; do
        [[ -n "$map_name" ]] || continue
        [[ -e "${BPF_PIN_DIR}/${map_name}" ]] || return 1
    done < <(xdp_required_map_names)

    # Value-size guard: catches pinned maps from an older build before the
    # caller skips reload.  Sizes are derived from the C structs in bpf/include/:
    #   tcp_endpoint_policy / xdp_profile_ctx                      = 24 B
    #   xdp_runtime_cfg  8 × __u64 + 2 × __u32 (cfg_flags + _pad) = 72 B
    #   udp_global_state bpf_spin_lock(4) + __u32(4) + 4×__u64     = 40 B
    #   xdp_traffic_totals 4 × __u64                              = 32 B
    # Update these numbers whenever the corresponding struct gains or loses fields.
    for map_name in tcp_whitelist tcp_zone_whitelist profile_ctx_map; do
        _map_value_size_ok "${BPF_PIN_DIR}/${map_name}" 24 || {
            _auto_xdp_warn "${map_name} value_size mismatch; forcing XDP reload"
            return 1
        }
    done
    _map_value_size_ok "${BPF_PIN_DIR}/xdp_runtime_cfg" 72 || {
        _auto_xdp_warn "xdp_runtime_cfg value_size mismatch; forcing XDP reload"
        return 1
    }
    _map_value_size_ok "${BPF_PIN_DIR}/udp_global_rl" 40 || {
        _auto_xdp_warn "udp_global_rl value_size mismatch; forcing XDP reload"
        return 1
    }
    # Also check outside the manifest: an old pinned generation may carry its
    # own manifest without the consolidated traffic-counter layout.
    if ! _map_value_size_ok "${BPF_PIN_DIR}/byte_counters" 32 ||
       ! _map_max_entries_ok "${BPF_PIN_DIR}/byte_counters" 1; then
        _auto_xdp_warn "byte_counters layout mismatch; forcing XDP reload"
        return 1
    fi
    _xdp_map_abi_ready || return 1
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

	cat <<-'EOF'
	prog
	xdp_runtime_cfg
	pkt_counters
	pkt_ringbuf
	byte_counters
	trusted_ipv4
	trusted_ipv6
	tcp_whitelist
	endpoint_scopes
	udp_whitelist
	tcp_zone_whitelist
	udp_zone_whitelist
	sctp_whitelist
	icmp_tb
	udp_global_rl
	udp_percpu_acc
	tcp_port_policies
	tcp_synck_policy
	sync_run_cfg
	sync_port_rate
	sync_port_state
	sync_port_limit
	sync_handoff4
	sync_handoff6
	syn4
	syn6
	udp_port_policies
	udprt4
	udprt6
	synag4
	synag6
	udpag4
	udpag6
	tcp_acl_v4
	tcp_acl_v6
	udp_acl_v4
	udp_acl_v6
	sit4_endpoints
	proto_handlers
	tcp_profile_handlers
	tcp_port_handlers
	udp_port_handlers
	syncookie_prog_array
	hblk4
	hblk6
	udp_hv4
	udp_hv6
	abuseipdb_v4
	slot_ctx_map
	profile_ctx_map
	tc_handler_ctx
	handler_egress
	handler_flows
	tc_profile_handlers
	tc_tcp_handlers
	tc_udp_handlers
	tc_proto_handlers
	handler_eg_stats
	EOF
}

_auto_xdp_parse_link_mode() {
    local python_root="${AUTO_XDP_RUNTIME_COMMON_DIR}/.."
    if [[ ! -f "${python_root}/auto_xdp/xdp_link.py" ]]; then
        python_root="${AUTO_XDP_RUNTIME_COMMON_DIR}/python"
    fi
    if [[ ! -f "${python_root}/auto_xdp/xdp_link.py" ]]; then
        python_root="${PYTHON_LIB_DIR:-}"
    fi
    PYTHONPATH="${python_root}${PYTHONPATH:+:$PYTHONPATH}" \
        "${PYTHON3_BIN:-python3}" -m auto_xdp.xdp_link
}

_auto_xdp_iface_xdp_mode() {
    local details="" mode="unknown"
    if details=$(LC_ALL=C ip -j -d link show dev "$1" 2>&1); then
        mode=$(_auto_xdp_parse_link_mode <<< "$details" 2>/dev/null) || mode="unknown"
    elif [[ "$details" == *"does not exist"* || "$details" == *"No such device"* \
            || "$details" == *"Cannot find device"* ]]; then
        mode="missing"
    fi
    case "$mode" in
        off|missing) printf 'none' ;;
        native|generic|offload|multi) printf '%s' "$mode" ;;
        *) printf 'unknown' ;;
    esac
}

_auto_xdp_any_target_has_xdp() {
    local iface_var="" iface
    iface_var=$(_auto_xdp_iface_var_name) || return 1
    local -n active_ifaces="$iface_var"
    for iface in "${active_ifaces[@]}"; do
        [[ "$(_auto_xdp_iface_xdp_mode "$iface")" == "none" ]] || return 0
    done
    return 1
}

_auto_xdp_detach_mode() {
    local iface="$1" mode="$2"
    case "$mode" in
        native)  ip link set dev "$iface" xdp off 2>/dev/null || true ;;
        generic) ip link set dev "$iface" xdpgeneric off 2>/dev/null || true ;;
        offload) ip link set dev "$iface" xdpoffload off 2>/dev/null || true ;;
    esac
}

_auto_xdp_attach_mode() {
    local iface="$1" prog="$2" mode="$3" attach_type=""
    case "$mode" in
        native)  attach_type="xdpdrv" ;;
        generic) attach_type="xdpgeneric" ;;
        offload) attach_type="xdpoffload" ;;
        *) return 1 ;;
    esac

    # iproute2 refuses to replace an attached XDP program. bpftool's explicit
    # overwrite flag performs the kernel's atomic old-or-new replacement.
    LC_ALL=C bpftool net attach "$attach_type" pinned "$prog" dev "$iface" overwrite
}

_auto_xdp_attach_error_class() {
    local error="${1,,}"
    case "$error" in
        *"operation not permitted"*|*"permission denied"*) printf 'permission' ;;
        *"cannot allocate memory"*|*"no space left on device"*|*"no buffer space available"*|*"too many open files"*)
            printf 'resource' ;;
        *"no such device"*|*"cannot find device"*|*"invalid devname"*) printf 'device' ;;
        *"interface xdpdrv attach failed: operation not supported"*|*"interface xdpgeneric attach failed: operation not supported"*)
            printf 'unsupported' ;;
        *"native and generic xdp can't be active at the same time"*|*"interface xdpdrv attach failed: file exists"*|*"interface xdpgeneric attach failed: file exists"*)
            printf 'mode-conflict' ;;
        *"device or resource busy"*|*"file exists"*) printf 'busy' ;;
        *"invalid argument"*|*"argument list too long"*) printf 'configuration' ;;
        *"command not found"*|*"no such file or directory"*|*"not found for kernel"*) printf 'tooling' ;;
        *) printf 'unknown' ;;
    esac
}

_auto_xdp_iface_is_veth() {
    # Link names are arbitrary (a container's veth is often named eth0).
    # Inspect the kernel-reported kind rather than matching a name prefix.
    local details=""
    details=$(ip -j -d link show dev "$1" 2>/dev/null) || return 1
    "${PYTHON3_BIN:-python3}" -c '
import json, sys
try:
    links = json.load(sys.stdin)
    kind = links[0].get("linkinfo", {}).get("info_kind")
except (ValueError, IndexError, KeyError, TypeError, AttributeError):
    raise SystemExit(1)
raise SystemExit(0 if kind == "veth" else 1)
' <<< "$details"
}

_auto_xdp_attach_candidate() {
    local iface="$1" prog="$2"
    local preference="auto:auto" requested="auto" preferred="auto"
    local attach_error="" error_class="" active_mode="" is_veth=0 status index
    AUTO_XDP_LAST_ATTACH_MODE=""
    AUTO_XDP_LAST_ATTACH_ERRORS=""
    AUTO_XDP_LAST_ATTACH_ERROR_CLASS=""
    AUTO_XDP_ATTACH_FATAL=0
    preference=$(_auto_xdp_saved_iface_mode "$iface") || preference="auto:auto"
    if [[ "$preference" == *:* ]]; then
        requested=${preference%%:*}
        preferred=${preference#*:}
    else
        preferred="$preference"
    fi
    _auto_xdp_iface_is_veth "$iface" && is_veth=1
    local -a modes=(native generic)
    case "$requested" in
        native) modes=(native) ;;
        generic) modes=(generic) ;;
        *)
            # veth native XDP queues already-allocated skbs and can disable
            # peer segmentation offloads. A previously verified native attach
            # is not evidence of better throughput. Prefer generic even when
            # restoring a saved native mode; keep native as an available
            # fallback without detaching an existing program to change modes.
            if [[ $is_veth -eq 1 || "$preferred" == "generic" ]]; then
                modes=(generic native)
            fi
            ;;
    esac
    local mode next_mode
    for ((index = 0; index < ${#modes[@]}; index++)); do
        mode="${modes[$index]}"
        if attach_error=$(_auto_xdp_attach_mode "$iface" "$prog" "$mode" 2>&1); then
            AUTO_XDP_LAST_ATTACH_MODE="$mode"
            if [[ $is_veth -eq 1 && "$mode" == "native" ]]; then
                _auto_xdp_warn "Native XDP on veth $iface can disable peer TSO and bottleneck its receive queue; prefer generic mode. An existing native attachment is preserved during reload; generic takes effect after a full disable/enable."
            fi
            return 0
        else
            status=$?
        fi
        error_class=$(_auto_xdp_attach_error_class "$attach_error")
        AUTO_XDP_LAST_ATTACH_ERROR_CLASS="$error_class"
        [[ -z "$attach_error" ]] || attach_error=${attach_error//$'\n'/; }
        [[ -n "$attach_error" ]] || attach_error="attach command returned no diagnostic"
        AUTO_XDP_LAST_ATTACH_ERRORS+="${AUTO_XDP_LAST_ATTACH_ERRORS:+$'\n'}${mode} [${error_class}, exit ${status}]: ${attach_error}"
        _auto_xdp_warn "XDP attach failed on $iface: $mode [$error_class, exit $status]: $attach_error"

        # Only a known unsupported mode permits an automatic downgrade. On
        # reload, an opposite-mode EEXIST may instead retry the already active
        # mode, without detaching protection to change hooks.
        if [[ "$requested" == "auto" && "$error_class" == "unsupported" ]]; then
            continue
        fi
        if [[ "$requested" == "auto" && "$error_class" == "mode-conflict" \
                && $((index + 1)) -lt ${#modes[@]} ]]; then
            next_mode="${modes[$((index + 1))]}"
            active_mode=$(_auto_xdp_iface_xdp_mode "$iface")
            if [[ "$active_mode" == "$next_mode" ]]; then
                continue
            fi
        fi
        AUTO_XDP_ATTACH_FATAL=1
        break
    done
    AUTO_XDP_LAST_ATTACH_MODE=""
    return 1
}

_auto_xdp_saved_iface_mode() {
    local iface="$1" state_path="${MACHINE_STATE:-/etc/auto_xdp/machine-state.json}"
    [[ -f "$state_path" ]] || {
        printf 'auto:auto\n'
        return 0
    }
    "${PYTHON3_BIN:-python3}" - "$state_path" "$iface" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as handle:
        state = json.load(handle).get("interfaces", {}).get(sys.argv[2], {})
        requested = state.get("requested_mode", "auto")
        mode = state.get("xdp_mode", "auto")
except Exception:
    requested = "auto"
    mode = "auto"
if requested not in {"auto", "native", "generic"}:
    requested = "auto"
if mode not in {"native", "generic"}:
    mode = "auto"
print(f"{requested}:{mode}")
PY
}

_auto_xdp_runtime_generation() {
    local metadata=""
    for metadata in \
        "${INSTALL_DIR:-}/release.json" \
        "${CURRENT_LINK:-/usr/local/lib/auto_xdp/current}/release.json"; do
        [[ -f "$metadata" ]] || continue
        "${PYTHON3_BIN:-python3}" - "$metadata" <<'PY' 2>/dev/null && return 0
import json, sys
with open(sys.argv[1]) as handle:
    value = json.load(handle).get("release")
if not isinstance(value, str) or not value:
    raise SystemExit(1)
print(value)
PY
    done
    printf '%s\n' "${RUNTIME_GENERATION:-${RELEASE_NAME:-verified}}"
}

_auto_xdp_record_xdp_state() {
    local prog="$1" program_id="" iface_var="" iface mode generation
    local machine_state="${MACHINE_STATE:-/etc/auto_xdp/machine-state.json}"
    local runtime_state="${RUNTIME_STATE:-/etc/auto_xdp/runtime-state.json}"
    local requested="${REQUESTED_BACKEND:-${PREFERRED_BACKEND:-auto}}"
    local python_root="${PYTHON_LIB_DIR:-${AUTO_XDP_RUNTIME_COMMON_DIR}/..}"
    program_id=$(_auto_xdp_pinned_prog_id "$prog") || return 1
    generation=$(_auto_xdp_runtime_generation)
    iface_var=$(_auto_xdp_iface_var_name) || return 1
    local -n state_ifaces="$iface_var"
    local -a args=()
    for iface in "${state_ifaces[@]}"; do
        mode=$(_auto_xdp_iface_xdp_mode "$iface")
        [[ "$mode" == "native" || "$mode" == "generic" ]] || return 1
        args+=(--interface-state "${iface}=${mode}:${program_id}")
    done
    PYTHONPATH="$python_root${PYTHONPATH:+:$PYTHONPATH}" \
        "${PYTHON3_BIN:-python3}" -m auto_xdp.install_state record \
        --machine-state "$machine_state" \
        --runtime-state "$runtime_state" \
        --requested-backend "$requested" \
        --active-backend xdp \
        --generation "$generation" \
        "${args[@]}" >/dev/null
}

_auto_xdp_pinned_prog_id() {
    bpftool -j prog show pinned "$1" 2>/dev/null | "${PYTHON3_BIN:-python3}" -c '
import json, sys
try:
    data = json.load(sys.stdin)
    if isinstance(data, list):
        data = data[0]
    value = data.get("id") if isinstance(data, dict) else None
    if not isinstance(value, int):
        raise ValueError
    print(value)
except (IndexError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
'
}

_auto_xdp_iface_prog_id() {
    ip -j -d link show dev "$1" 2>/dev/null | "${PYTHON3_BIN:-python3}" -c '
import json, sys

def ids(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if (key == "id" or key.endswith("prog_id")) and isinstance(child, int):
                yield child
            else:
                yield from ids(child)
    elif isinstance(value, list):
        for child in value:
            yield from ids(child)

try:
    data = json.load(sys.stdin)
    if isinstance(data, list):
        data = data[0]
    xdp = data.get("xdp") if isinstance(data, dict) else None
    found = list(ids(xdp))
    if not found:
        raise ValueError
    print(found[0])
except (IndexError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
'
}

_auto_xdp_verify_iface_program() {
    local iface="$1" prog="$2" expected_id="" actual_id=""
    expected_id=$(_auto_xdp_pinned_prog_id "$prog") || return 1
    actual_id=$(_auto_xdp_iface_prog_id "$iface") || return 1
    [[ "$actual_id" == "$expected_id" ]]
}

_auto_xdp_rollback_iface() {
    local iface="$1" old_mode="$2" new_mode="$3" old_prog="$4"

    if [[ "$old_mode" == "none" ]]; then
        _auto_xdp_detach_mode "$iface" "$new_mode"
        [[ "$(_auto_xdp_iface_xdp_mode "$iface")" == "none" ]]
        return
    fi

    # Replacing the candidate with the old pin is atomic even if the attach
    # mode changed. If this fails, the candidate remains attached and both pin
    # generations are retained by the caller for recovery.
    _auto_xdp_attach_mode "$iface" "$old_prog" "$old_mode" \
        >/dev/null 2>&1 && _auto_xdp_verify_iface_program "$iface" "$old_prog" || {
        _auto_xdp_warn "Failed to restore previous XDP on $iface; candidate remains attached."
        return 1
    }
}

preseed_xdp_candidate_policy() {
    local candidate_dir="$1"
    local syncookie_expected="${2:-0}"
    local py_bin="${PYTHON3_BIN:-python3}"
    local config_path="${TOML_CONFIG:-/etc/auto_xdp/config.toml}"
    local python_path="${PYTHON_LIB_DIR:-${AUTO_XDP_RUNTIME_COMMON_DIR}/..}"

    AUTO_XDP_SYNCOOKIE_EXPECTED="$syncookie_expected" \
    PYTHONPATH="$python_path${PYTHONPATH:+:$PYTHONPATH}" \
        "$py_bin" - "$candidate_dir" "$config_path" <<'PYEOF'
import os
import sys

from auto_xdp import config as cfg
from auto_xdp.backends.xdp import XdpBackend
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.syncer import sync_once

pin_dir, config_path = sys.argv[1:]
apply_toml_config(load_toml_config(config_path))
cfg._set_bpf_pin_dir(pin_dir)
with XdpBackend() as backend:
    # The optional cookie program is loaded into this generation only after
    # the switch. Without the runtime's decision, every cookie endpoint would
    # be closed across it, established connections included.
    backend.syncookie_program_expected = os.environ.get("AUTO_XDP_SYNCOOKIE_EXPECTED") == "1"
    sync_once(backend, dry_run=False)
    if backend.last_apply_failures:
        print(
            f"candidate policy pre-seed had {backend.last_apply_failures} BPF map update failure(s)",
            file=sys.stderr,
        )
        raise SystemExit(1)
PYEOF
}

_auto_xdp_record_switch_mode() {
    local mode="$1"
    if [[ -z "${AUTO_XDP_SWITCH_MODE:-}" ]]; then
        AUTO_XDP_SWITCH_MODE="$mode"
    elif [[ "$AUTO_XDP_SWITCH_MODE" != "$mode" ]]; then
        AUTO_XDP_SWITCH_MODE="mixed"
    fi
}

_auto_xdp_finish_interrupted_reload() {
    local live_dir="$BPF_PIN_DIR"
    local candidate_dir="${BPF_PIN_DIR}_next"
    local rollback_dir="${BPF_PIN_DIR}_rollback"
    local iface_var="" iface saved_pin_dir saved_tc_rollback saved_tc_allow

    AUTO_XDP_RECOVERY_HANDLED=0
    [[ -e "$candidate_dir" || -e "$rollback_dir" ]] || return 0

    iface_var=$(_auto_xdp_iface_var_name) || return 1
    local -n recovery_ifaces="$iface_var"
    [[ ${#recovery_ifaces[@]} -gt 0 ]] || return 1

    # The old live directory may already have been renamed during the final
    # two-directory commit. Restore its name before resuming the candidate.
    if [[ -e "$candidate_dir" && ! -e "$live_dir" && -e "$rollback_dir" ]]; then
        mv "$rollback_dir" "$live_dir" || return 1
    fi

    if [[ -e "$candidate_dir" ]]; then
        _auto_xdp_warn "Interrupted XDP reload detected; resuming the staged candidate generation."
        saved_pin_dir="$BPF_PIN_DIR"
        BPF_PIN_DIR="$candidate_dir"
        if ! preseed_xdp_candidate_handlers; then
            BPF_PIN_DIR="$saved_pin_dir"
            _auto_xdp_warn "Could not validate candidate handlers; retaining both generations."
            return 1
        fi
        BPF_PIN_DIR="$saved_pin_dir"
        AUTO_XDP_SWITCH_MODE=""
        for iface in "${recovery_ifaces[@]}"; do
            if ! _auto_xdp_attach_candidate "$iface" "$candidate_dir/prog" \
                    || ! _auto_xdp_verify_iface_program "$iface" "$candidate_dir/prog"; then
                _auto_xdp_warn "Could not resume candidate XDP on $iface; retaining both generations."
                return 1
            fi
            _auto_xdp_record_switch_mode "$AUTO_XDP_LAST_ATTACH_MODE"
        done

        if [[ -e "$live_dir" ]]; then
            [[ ! -e "$rollback_dir" ]] || return 1
            mv "$live_dir" "$rollback_dir" || return 1
        fi
        mv "$candidate_dir" "$live_dir" || return 1
        if ! _auto_xdp_record_xdp_state "$live_dir/prog"; then
            _auto_xdp_warn "Could not persist verified per-interface XDP state; retaining rollback generation."
            return 1
        fi
        rm -rf "$rollback_dir"
        AUTO_XDP_HANDLERS_PRELOADED=1
        AUTO_XDP_RECOVERY_HANDLED=1
        return 0
    fi

    # Candidate was already renamed to live; repeat the idempotent program
    # replacement before deleting the rollback generation.
    [[ -e "$live_dir/prog" && -e "$rollback_dir/prog" ]] || return 1
    _auto_xdp_warn "Interrupted XDP commit detected; verifying the live generation before cleanup."
    preseed_xdp_candidate_handlers || return 1
    AUTO_XDP_SWITCH_MODE=""
    for iface in "${recovery_ifaces[@]}"; do
        if ! _auto_xdp_attach_candidate "$iface" "$live_dir/prog" \
                || ! _auto_xdp_verify_iface_program "$iface" "$live_dir/prog"; then
            _auto_xdp_warn "Could not verify live XDP on $iface; retaining the rollback generation."
            return 1
        fi
        _auto_xdp_record_switch_mode "$AUTO_XDP_LAST_ATTACH_MODE"
    done
    if ! _auto_xdp_record_xdp_state "$live_dir/prog"; then
        _auto_xdp_warn "Could not persist verified per-interface XDP state; retaining the rollback generation."
        return 1
    fi
    rm -rf "$rollback_dir"
    AUTO_XDP_HANDLERS_PRELOADED=1
    AUTO_XDP_RECOVERY_HANDLED=1
}

_auto_xdp_restore_interrupted_reload() {
    local live_dir="$BPF_PIN_DIR"
    local candidate_dir="${BPF_PIN_DIR}_next"
    local rollback_dir="${BPF_PIN_DIR}_rollback"
    local stable_dir="" discard_dir="" stable_id="" discard_id=""
    local iface_var="" iface mode actual_id=""
    local replacement_dir="${BPF_PIN_DIR}_failed_${BASHPID:-$$}"

    if [[ -e "$live_dir" && -e "$candidate_dir" && -e "$rollback_dir" ]]; then
        _auto_xdp_warn "Live, candidate, and rollback XDP generations all exist; refusing ambiguous recovery."
        return 1
    fi

    if [[ -e "$candidate_dir" ]]; then
        stable_dir="$live_dir"
        discard_dir="$candidate_dir"
    elif [[ -e "$rollback_dir" ]]; then
        # The candidate was already renamed to live. The rollback directory is
        # the last fully committed generation and is therefore the safe side.
        stable_dir="$rollback_dir"
        discard_dir="$live_dir"
    else
        return 0
    fi

    [[ -e "$stable_dir/prog" && -e "$discard_dir/prog" ]] || {
        _auto_xdp_warn "Interrupted XDP pins are incomplete; refusing unsafe cleanup."
        return 1
    }
    stable_id=$(_auto_xdp_pinned_prog_id "$stable_dir/prog") || {
        _auto_xdp_warn "Could not identify stable XDP program at $stable_dir/prog."
        return 1
    }
    discard_id=$(_auto_xdp_pinned_prog_id "$discard_dir/prog") || {
        _auto_xdp_warn "Could not identify interrupted XDP program at $discard_dir/prog."
        return 1
    }

    iface_var=$(_auto_xdp_iface_var_name) || return 1
    local -n restore_ifaces="$iface_var"
    for iface in "${restore_ifaces[@]}"; do
        mode=$(_auto_xdp_iface_xdp_mode "$iface")
        [[ "$mode" != "none" ]] || continue
        actual_id=$(_auto_xdp_iface_prog_id "$iface") || {
            _auto_xdp_warn "Could not identify the XDP program attached to $iface; recovery pins were retained."
            return 1
        }
        if [[ "$actual_id" == "$stable_id" ]]; then
            continue
        fi
        if [[ "$actual_id" != "$discard_id" ]]; then
            _auto_xdp_warn "XDP program $actual_id on $iface belongs to neither recovery generation; refusing replacement."
            return 1
        fi
        if ! _auto_xdp_attach_mode "$iface" "$stable_dir/prog" "$mode" >/dev/null 2>&1 \
                || ! _auto_xdp_verify_iface_program "$iface" "$stable_dir/prog"; then
            _auto_xdp_warn "Could not restore stable XDP program $stable_id on $iface; recovery pins were retained."
            return 1
        fi
    done

    if [[ "$stable_dir" == "$rollback_dir" ]]; then
        [[ ! -e "$replacement_dir" ]] || return 1
        mv "$live_dir" "$replacement_dir" || return 1
        if ! mv "$rollback_dir" "$live_dir"; then
            mv "$replacement_dir" "$live_dir" 2>/dev/null || true
            return 1
        fi
        rm -rf "$replacement_dir"
    else
        rm -rf "$candidate_dir"
        [[ ! -e "$rollback_dir" ]] || rm -rf "$rollback_dir"
    fi

    AUTO_XDP_HANDLERS_PRELOADED=0
    AUTO_XDP_RECOVERY_HANDLED=0
    _auto_xdp_warn "Restored the last committed XDP generation; continuing with a fresh candidate."
    return 0
}

_auto_xdp_bpftool_host_tooling_error() {
    local log_path="${1:-}"
    [[ -f "$log_path" ]] || return 1
    grep -Eqi \
        'bpftool not found|command not found|not found for kernel' \
        "$log_path"
}

_auto_xdp_report_xdp_load_failure() {
    local log_path="${1:-}"
    local kernel_release
    kernel_release=$(uname -r)

    if _auto_xdp_bpftool_host_tooling_error "$log_path"; then
        _auto_xdp_warn "Unable to invoke bpftool for running kernel ${kernel_release}."
        _auto_xdp_warn "This is a host tooling issue, not a BPF verifier rejection."
        _auto_xdp_warn "Missing package: linux-tools-${kernel_release}"
        cat "$log_path" >&2
        return 0
    fi

    _auto_xdp_warn "BPF verifier rejected candidate program; bpftool log follows."
    cat "$log_path" >&2
}

syncookie_sysctl_state_path() {
    printf '%s\n' "${SYNCOOKIE_SYSCTL_STATE:-${RUN_STATE_DIR:-/run/auto_xdp}/syncookie-sysctl.json}"
}

syncookie_sysctl_acquire() {
    local state_path
    state_path=$(syncookie_sysctl_state_path)
    "${PYTHON3_BIN:-python3}" - "$state_path" <<'PY'
import sys
from auto_xdp.bpf.syncookie import acquire_sysctl
acquire_sysctl(sys.argv[1])
PY
}

syncookie_sysctl_release() {
    local state_path
    state_path=$(syncookie_sysctl_state_path)
    [[ -f "$state_path" ]] || return 0
    "${PYTHON3_BIN:-python3}" - "$state_path" <<'PY'
import sys
from auto_xdp.bpf.syncookie import release_sysctl
raise SystemExit(0 if release_sysctl(sys.argv[1]) else 1)
PY
}

# The installer and runtime use the same module transaction as the handler catalog.
_auto_xdp_syncookie_module() {
    local action="$1" iface_var="" iface=""
    shift
    local -a arguments=("$action" syncookie --root "$BPF_PIN_DIR")
    if iface_var=$(_auto_xdp_iface_var_name); then
        local -n module_ifaces="$iface_var"
        for iface in "${module_ifaces[@]}"; do arguments+=(--iface "$iface"); done
    fi
    local python_root="${PYTHON_LIB_DIR:-${AUTO_XDP_RUNTIME_COMMON_DIR}/..}"
    PYTHONPATH="$python_root${PYTHONPATH:+:$PYTHONPATH}" \
        "${PYTHON3_BIN:-python3}" -m auto_xdp.admin.module_runtime "${arguments[@]}" "$@"
}

cleanup_syncookie_handoff() {
    _auto_xdp_syncookie_module remove || return 1
    [[ ${1:-0} -eq 0 ]] || syncookie_sysctl_release || true
}

# Prints two lines: 1 when [modules.syncookie] enabled, and 1 when any mode is "always".
_auto_xdp_syncookie_config_flags() {
    local python_root="${PYTHON_LIB_DIR:-${AUTO_XDP_RUNTIME_COMMON_DIR}/..}"
    PYTHONPATH="$python_root${PYTHONPATH:+:$PYTHONPATH}" "${PYTHON3_BIN:-python3}" - "$TOML_CONFIG" <<'PY'
import sys
from auto_xdp.config import module_configs
try:
    import tomllib
except ImportError:
    import tomli as tomllib
try:
    with open(sys.argv[1], "rb") as handle:
        cfg = module_configs(tomllib.load(handle)).get("syncookie", {})
    modes = [cfg.get("default_mode", "auto")]
    for scope in ("by_proc", "by_service", "by_port"):
        values = cfg.get(scope, {})
        if isinstance(values, dict):
            modes.extend(values.values())
    print("1" if cfg.get("enabled", False) else "0")
    print("1" if any(str(mode).lower() == "always" for mode in modes) else "0")
except OSError:
    print("0")
    print("0")
PY
}

# Prints three lines: capability level, reason, handoff environment readiness.
_auto_xdp_syncookie_capability() {
    "${PYTHON3_BIN:-python3}" - <<'PY'
from auto_xdp.bpf.syncookie import probe_syncookie_capability
cap = probe_syncookie_capability()
print(cap.level)
print(cap.reason)
print(int(cap.handoff_environment_ready))
PY
}

# Succeeds when load_syncookie_program is expected to install the optional
# program: enabled in config, both objects present, Level 2 handoff verified.
# A transactional reload uses this to pre-seed cookie endpoints as available.
# The probe result is kept for the following load, so both decisions agree
# and the (slow) probe runs once per reload.
syncookie_program_expected() {
    local xdp_obj="" tc_obj="" capability=""
    local -a flags=() details=()
    xdp_obj=$(_auto_xdp_first_value SYNCOOKIE_OBJ_PATH SYNCOOKIE_OBJ_INSTALLED) || return 1
    tc_obj=$(_auto_xdp_first_value TC_SYNCOOKIE_OBJ_PATH TC_SYNCOOKIE_OBJ_INSTALLED) || return 1
    [[ -f "$xdp_obj" && -f "$tc_obj" ]] || return 1
    readarray -t flags < <(_auto_xdp_syncookie_config_flags)
    [[ "${flags[0]:-0}" == 1 ]] || return 1
    capability=$(_auto_xdp_syncookie_capability) || return 1
    AUTO_XDP_SYNCOOKIE_CAPABILITY=$capability
    readarray -t details <<< "$capability"
    [[ "${details[0]:-0}" == 2 && "${details[2]:-0}" == 1 ]]
}

# Restores "cookie endpoints only while the cookie program exists" after a
# reload pre-seeded them on an expectation that the load did not meet, for any
# reason (strict failure, non-strict fallback, changed environment).
_auto_xdp_settle_syncookie_preseed() {
    [[ "${AUTO_XDP_SYNCOOKIE_PRESEEDED:-0}" == 1 ]] || return 0
    AUTO_XDP_SYNCOOKIE_PRESEEDED=0
    _auto_xdp_syncookie_module verify >/dev/null 2>&1 && return 0
    _auto_xdp_warn "SYN-cookie program was not installed; closing the cookie endpoints pre-seeded for it."
    preseed_xdp_candidate_policy "$BPF_PIN_DIR" 0 || \
        _auto_xdp_warn "Could not close pre-seeded cookie endpoints; the daemon closes them on its first sync."
}

load_syncookie_program() {
    local status=0
    _auto_xdp_load_syncookie_program || status=$?
    _auto_xdp_settle_syncookie_preseed
    return "$status"
}

_auto_xdp_load_syncookie_program() {
    local xdp_obj="" tc_obj="" capability="${AUTO_XDP_SYNCOOKIE_CAPABILITY:-}"
    xdp_obj=$(_auto_xdp_first_value SYNCOOKIE_OBJ_PATH SYNCOOKIE_OBJ_INSTALLED) || true
    tc_obj=$(_auto_xdp_first_value TC_SYNCOOKIE_OBJ_PATH TC_SYNCOOKIE_OBJ_INSTALLED) || true
    AUTO_XDP_SYNCOOKIE_CAPABILITY=""
    _auto_xdp_syncookie_module apply --config "$TOML_CONFIG" \
        --xdp "$xdp_obj" --tc "$tc_obj" --sysctl-state "$(syncookie_sysctl_state_path)" \
        --capability "$capability"
}

ensure_linux_conntrack() {
    if [[ "${NFT_FAMILY:-inet}" == inet && "${NFT_TABLE:-auto_xdp}" == auto_xdp_conntrack ]]; then
        _auto_xdp_warn "inet auto_xdp_conntrack is reserved for XDP tracking, not the fallback policy."
        return 1
    fi
    local python_root="${PYTHON_LIB_DIR:-${AUTO_XDP_RUNTIME_COMMON_DIR}/..}"
    PYTHONPATH="$python_root${PYTHONPATH:+:$PYTHONPATH}" \
        "${PYTHON3_BIN:-python3}" -m auto_xdp.bpf.conntrack || {
        _auto_xdp_warn "Linux conntrack is required for XDP outbound replies; current attachment preserved."
        return 1
    }
}

transactional_reload_xdp() {
    AUTO_XDP_ATTACH_FATAL=0
    AUTO_XDP_LAST_ATTACH_ERRORS=""
    local xdp_obj_path=""
    xdp_obj_path=$(_auto_xdp_first_value XDP_OBJ_PATH XDP_OBJ_INSTALLED) || xdp_obj_path=""
    [[ -f "$xdp_obj_path" ]] || {
        _auto_xdp_warn "XDP object not found; transactional reload unavailable."
        return 1
    }

    local iface_var=""
    iface_var=$(_auto_xdp_iface_var_name) || {
        _auto_xdp_warn "No interfaces configured for XDP reload."
        return 1
    }
    local -n switch_ifaces="$iface_var"
    [[ ${#switch_ifaces[@]} -gt 0 ]] || return 1

    ensure_linux_conntrack || return 1

    local live_dir="$BPF_PIN_DIR"
    # bpffs rejects directory names containing dots on supported kernels, so
    # generation directories use underscores rather than `.next`/`.rollback`.
    local candidate_dir="${BPF_PIN_DIR}_next"
    local rollback_dir="${BPF_PIN_DIR}_rollback"
    local had_old=0 iface mode index switched=0 rollback_ok=1
    local -a old_modes=() new_modes=()

    AUTO_XDP_SWITCH_MODE=""
    AUTO_XDP_SWITCH_ROLLED_BACK=0
    AUTO_XDP_HANDLERS_PRELOADED=0
    AUTO_XDP_SYNCOOKIE_PRESEEDED=0
    AUTO_XDP_SYNCOOKIE_CAPABILITY=""

    if [[ -e "$rollback_dir" || -e "$candidate_dir" ]]; then
        if ! _auto_xdp_finish_interrupted_reload; then
            _auto_xdp_warn "Interrupted candidate could not be committed; restoring the last committed generation."
            _auto_xdp_restore_interrupted_reload || return 1
        fi
        [[ ${AUTO_XDP_RECOVERY_HANDLED:-0} -eq 1 ]] && return 0
    fi

    for iface in "${switch_ifaces[@]}"; do
        mode=$(_auto_xdp_iface_xdp_mode "$iface")
        case "$mode" in
            none|native|generic) ;;
            *)
                _auto_xdp_warn "Cannot confirm a single XDP mode on $iface ($mode); refusing replacement."
                AUTO_XDP_ATTACH_FATAL=1
                return 1
                ;;
        esac
        old_modes+=("$mode")
        if [[ "$mode" != "none" && ! -e "$live_dir/prog" ]]; then
            _auto_xdp_warn "XDP is active on $iface but its previous program is not pinned at $live_dir/prog; refusing unsafe replacement."
            return 1
        fi
    done

    mkdir -p "$candidate_dir" || return 1

    local saved_pin_dir="$BPF_PIN_DIR" verifier_log=""
    BPF_PIN_DIR="$candidate_dir"
    verifier_log=$(mktemp) || {
        BPF_PIN_DIR="$saved_pin_dir"
        rm -rf "$candidate_dir"
        return 1
    }
    if bpftool -d prog load "$xdp_obj_path" "$candidate_dir/prog" type xdp \
            pinmaps "$candidate_dir" >"$verifier_log" 2>&1; then
        _auto_xdp_print_verifier_summary "$verifier_log"
    else
        BPF_PIN_DIR="$saved_pin_dir"
        _auto_xdp_print_verifier_summary "$verifier_log"
        _auto_xdp_report_xdp_load_failure "$verifier_log"
        rm -f "$verifier_log"
        rm -rf "$candidate_dir"
        return 1
    fi
    rm -f "$verifier_log"
    if ! xdp_maps_ready; then
        BPF_PIN_DIR="$saved_pin_dir"
        _auto_xdp_warn "Candidate XDP map validation failed; current protection was not changed."
        rm -rf "$candidate_dir"
        return 1
    fi
    local syncookie_expected=0
    syncookie_program_expected && syncookie_expected=1
    if ! preseed_xdp_candidate_policy "$candidate_dir" "$syncookie_expected"; then
        BPF_PIN_DIR="$saved_pin_dir"
        _auto_xdp_warn "Candidate XDP policy pre-seeding failed; current protection was not changed."
        rm -rf "$candidate_dir"
        return 1
    fi
    if ! preseed_xdp_candidate_handlers; then
        BPF_PIN_DIR="$saved_pin_dir"
        _auto_xdp_warn "Candidate XDP handler pre-seeding failed; current protection was not changed."
        rm -rf "$candidate_dir"
        return 1
    fi
    BPF_PIN_DIR="$saved_pin_dir"

    # One-time migration also recognizes the retired Minecraft-specific pin.
    # Keep the preceding egress program pinned across the map-directory switch
    # so a later dispatcher attach failure can restore it on every interface.
    local previous_egress=""
    for previous_egress in tc_egress_dispatch_prog minecraft_egress_prog; do
        [[ -e "${live_dir}/${previous_egress}" ]] || continue
        if ! bpftool prog pin pinned "${live_dir}/${previous_egress}" \
                "${candidate_dir}/tc_egress_dispatch_prog" >/dev/null 2>&1; then
            rm -rf "$candidate_dir"
            _auto_xdp_warn "Cannot retain the previous TC dispatcher for rollback."
            return 1
        fi
        break
    done

    # TC ingress still refers to the old module while the main root changes.
    # Retain its ownership pins so the common module transaction can roll back.
    if [[ -d "$live_dir/modules/syncookie" ]]; then
        if ! _auto_xdp_syncookie_module retain --candidate "$candidate_dir"; then
            rm -rf "$candidate_dir"
            _auto_xdp_warn "Cannot retain the previous SYN Cookie module for rollback."
            return 1
        fi
    fi

    [[ -d "$live_dir" ]] && had_old=1

    for iface in "${switch_ifaces[@]}"; do
        ethtool -K "$iface" lro off 2>/dev/null || true
        if _auto_xdp_attach_candidate "$iface" "$candidate_dir/prog"; then
            new_modes+=("$AUTO_XDP_LAST_ATTACH_MODE")
            switched=$((switched + 1))
            if _auto_xdp_verify_iface_program "$iface" "$candidate_dir/prog"; then
                continue
            fi
            _auto_xdp_warn "Candidate XDP attach on $iface could not be verified."
        fi
        _auto_xdp_warn "Failed to attach candidate XDP to $iface; rolling back switched interfaces."
        for ((index = 0; index < switched; index++)); do
            _auto_xdp_rollback_iface "${switch_ifaces[$index]}" \
                "${old_modes[$index]}" "${new_modes[$index]}" \
                "$live_dir/prog" || rollback_ok=0
        done
        if [[ $rollback_ok -eq 1 ]]; then
            rm -rf "$candidate_dir"
        else
            _auto_xdp_warn "XDP rollback was incomplete; retaining both pin generations for recovery."
        fi
        AUTO_XDP_SWITCH_ROLLED_BACK=$rollback_ok
        return 1
    done

    local saved_pin_dir="$BPF_PIN_DIR"
    BPF_PIN_DIR="$saved_pin_dir"
    # Every interface now runs the candidate, whose cookie endpoints may have
    # been admitted ahead of the cookie program; load_syncookie_program closes
    # them again if that program is not installed.
    AUTO_XDP_SYNCOOKIE_PRESEEDED=$syncookie_expected

    if [[ $had_old -eq 1 ]]; then
        mv "$live_dir" "$rollback_dir" || return 1
    fi
    mv "$candidate_dir" "$live_dir" || return 1
    if ! _auto_xdp_record_xdp_state "$live_dir/prog"; then
        _auto_xdp_warn "Could not persist verified per-interface XDP state; retaining rollback generation."
        return 1
    fi
    rm -rf "$rollback_dir"
    AUTO_XDP_SWITCH_MODE=""
    for mode in "${new_modes[@]}"; do
        _auto_xdp_record_switch_mode "$mode"
    done
    AUTO_XDP_HANDLERS_PRELOADED=1
    return 0
}

cleanup_tc_egress_dispatch() {
    local iface_var="" iface=""
    command -v tc >/dev/null 2>&1 || return 0
    iface_var=$(_auto_xdp_iface_var_name) || return 0
    local -n cleanup_ifaces="$iface_var"
    for iface in "${cleanup_ifaces[@]}"; do
        tc filter del dev "$iface" egress protocol all pref 49153 handle 2 bpf 2>/dev/null || true
    done
    rm -f "${BPF_PIN_DIR}/tc_egress_dispatch_prog" \
          "${BPF_PIN_DIR}/tc_egress_dispatch_next" \
          "${BPF_PIN_DIR}/minecraft_egress_prog" \
          "${BPF_PIN_DIR}/minecraft_egress_next" 2>/dev/null || true
}

load_tc_egress_dispatch() {
    local object_path="" next_pin="${BPF_PIN_DIR}/tc_egress_dispatch_next"
    local live_pin="${BPF_PIN_DIR}/tc_egress_dispatch_prog" iface_var="" iface=""
    local -a switched=()

    command -v tc >/dev/null 2>&1 || {
        _auto_xdp_warn "tc is required for handler egress dispatch."
        return 1
    }
    object_path=$(_auto_xdp_first_value TC_EGRESS_OBJ_PATH TC_EGRESS_OBJ_INSTALLED) || object_path=""
    [[ -f "$object_path" ]] || {
        _auto_xdp_warn "Handler egress dispatcher object not found."
        return 1
    }
    rm -f "$next_pin"
    local name
    local -a load_cmd=(bpftool prog load "$object_path" "$next_pin" type classifier)
    for name in slot_ctx_map profile_ctx_map xdp_runtime_cfg pkt_counters byte_counters pkt_ringbuf \
                endpoint_scopes tcp_whitelist udp_whitelist tcp_zone_whitelist udp_zone_whitelist \
                tc_handler_ctx handler_egress handler_flows tc_profile_handlers tc_tcp_handlers \
                tc_udp_handlers tc_proto_handlers handler_eg_stats; do
        [[ -e "${BPF_PIN_DIR}/$name" ]] || {
            _auto_xdp_warn "Missing shared dispatcher map: $name"
            return 1
        }
        load_cmd+=(map name "$name" pinned "${BPF_PIN_DIR}/$name")
    done
    if ! "${load_cmd[@]}" >/dev/null 2>&1; then
        _auto_xdp_warn "Kernel rejected the Linux-conntrack handler egress dispatcher."
        rm -f "$next_pin"
        return 1
    fi
    iface_var=$(_auto_xdp_iface_var_name) || { rm -f "$next_pin"; return 1; }
    local -n egress_ifaces="$iface_var"
    for iface in "${egress_ifaces[@]}"; do
        tc qdisc add dev "$iface" clsact 2>/dev/null || true
        if tc filter replace dev "$iface" egress pref 49153 handle 2 \
                bpf direct-action object-pinned "$next_pin" >/dev/null 2>&1; then
            switched+=("$iface")
            continue
        fi
        for iface in "${switched[@]}"; do
            if [[ -e "$live_pin" ]]; then
                tc filter replace dev "$iface" egress pref 49153 handle 2 \
                    bpf direct-action object-pinned "$live_pin" >/dev/null 2>&1 || true
            else
                tc filter del dev "$iface" egress protocol all pref 49153 handle 2 bpf 2>/dev/null || true
            fi
        done
        rm -f "$next_pin"
        _auto_xdp_warn "Failed to attach the Handler egress dispatcher on $iface."
        return 1
    done
    rm -f "$live_pin"
    mv "$next_pin" "$live_pin"
    rm -f "${BPF_PIN_DIR}/minecraft_egress_prog" "${BPF_PIN_DIR}/minecraft_egress_next"
    _auto_xdp_info "Handler egress dispatcher attached on ${egress_ifaces[*]}."
    return 0
}

load_sock_state_tracker() {
    local obj_path=""
    local prog_pin="${BPF_PIN_DIR}/sock_state_prog"
    local link_pin="${BPF_PIN_DIR}/sock_state_link"

    obj_path=$(_auto_xdp_first_value SOCK_STATE_OBJ_PATH SOCK_STATE_OBJ_INSTALLED) || obj_path=""

    rm -f "$link_pin" "$prog_pin"
    rm -f "${BPF_PIN_DIR}/sock_state_rb"

    if [[ ! -f "$obj_path" ]]; then
        _auto_xdp_warn "sock_state_track.o not found; falling back to proc_connector sync only."
        return 1
    fi

    if ! command -v bpftool &>/dev/null; then
        _auto_xdp_warn "bpftool not found; sock_state tracker unavailable."
        return 1
    fi

    if ! bpftool prog load "$obj_path" "$prog_pin" \
            type tracepoint \
            pinmaps "${BPF_PIN_DIR}/" >/dev/null 2>&1; then
        _auto_xdp_warn "Failed to load sock_state tracker (kernel may be too old for this BPF feature)."
        return 1
    fi

    if ! bpftool link create type tracepoint \
            event sock/inet_sock_set_state \
            prog pinned "$prog_pin" \
            pinned "$link_pin" >/dev/null 2>&1; then
        _auto_xdp_warn "bpftool link create unavailable; tracepoint will be attached by pkt_relay via perf_event_open."
        # Keep prog + map pins so pkt_relay can attach the tracepoint itself.
        return 0
    fi

    _auto_xdp_info "sock_state tracker loaded (tracepoint will be attached by pkt_relay)."
    return 0
}

load_icmp_module() {
    local install_dir="${INSTALL_DIR:-/usr/local/lib/auto_xdp/current}"
    local handlers_dir="${AUTO_XDP_BUILTIN_HANDLERS_DIR:-${install_dir}/handlers}"
    local python_root="${PYTHON_LIB_DIR:-${AUTO_XDP_RUNTIME_COMMON_DIR}/..}"
    [[ -f "${TOML_CONFIG:-}" ]] || return 0
    if ! PYTHONPATH="$python_root${PYTHONPATH:+:$PYTHONPATH}" "${PYTHON3_BIN:-python3}" \
            -m auto_xdp.admin.module_runtime apply icmp --root "$BPF_PIN_DIR" \
            --config "$TOML_CONFIG" --xdp "$handlers_dir/icmp_handler.o"; then
        AUTO_XDP_ATTACH_FATAL=1
        AUTO_XDP_LAST_ATTACH_ERRORS="ICMP module or its kernel dependency could not be activated"
        return 1
    fi
}

load_slot_handlers() {
    local handlers_dir="${AUTO_XDP_BUILTIN_HANDLERS_DIR:-${INSTALL_DIR}/handlers}"
    local py_bin="${PYTHON3_BIN:-python3}"
    local strict="${AUTO_XDP_STRICT_HANDLERS:-0}"

    [[ -e "${BPF_PIN_DIR}/proto_handlers" ]] || {
        _auto_xdp_warn "proto_handlers map not pinned; skipping slot handler loading."
        [[ "$strict" -eq 0 ]]
        return
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
    _auto_xdp_info "Slot default_action: ${default_action} (managed by xdp_runtime_cfg)"

    [[ "$enabled_json" == "[]" ]] && return 0
    [[ -d "$handlers_dir" ]] || {
        _auto_xdp_warn "Handlers dir $handlers_dir not found; skipping slot loading."
        [[ "$strict" -eq 0 ]]
        return
    }

    PYTHONPATH="${INSTALL_DIR}:${PYTHONPATH:-}" "$py_bin" - "$enabled_json" "$handlers_dir" \
        "${BPF_PIN_DIR}" "$strict" <<'PYEOF'
import sys, json
from pathlib import Path
from auto_xdp.admin import handlers

enabled = json.loads(sys.argv[1])
handlers_dir, root = Path(sys.argv[2]), Path(sys.argv[3])
strict = sys.argv[4] == "1"
failures = 0
for entry in enabled:
    try:
        if isinstance(entry, str):
            proto, name = handlers.BUILTIN_SLOT_INFO[entry]
            obj = handlers_dir / name
        elif isinstance(entry, dict):
            proto, obj = int(entry["proto"]), Path(entry["path"])
        else:
            raise ValueError(f"Invalid handler entry: {entry!r}")
        handlers.load_protocol_handler(root, proto, obj)
        print(f"  Loaded slot handler: proto {proto} ({obj})")
    except (KeyError, TypeError, ValueError, OSError, RuntimeError) as exc:
        print(f"  [WARN] Failed to load protocol handler {entry!r}: {exc}", file=sys.stderr)
        failures += 1
if strict and failures:
    raise SystemExit(1)
PYEOF
}

preseed_xdp_candidate_handlers() {
    AUTO_XDP_STRICT_HANDLERS=1 load_slot_handlers \
        && load_icmp_module \
        && AUTO_XDP_STRICT_HANDLERS=1 load_port_handlers
}

load_port_handlers() {
    local py_bin="${PYTHON3_BIN:-python3}"
    local install_dir="${INSTALL_DIR:-/usr/local/lib/auto_xdp/current}"
    local strict="${AUTO_XDP_STRICT_HANDLERS:-0}"

    [[ -f "$TOML_CONFIG" ]] || return 0

    "$py_bin" - "$TOML_CONFIG" "${BPF_PIN_DIR}" "$install_dir" "$strict" <<'PYEOF'
import json
import os
import subprocess
import sys

config_path, bpf_pin_dir, install_dir = sys.argv[1:4]
strict = sys.argv[4] == "1"
failures = 0

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
            failures += 1
            continue
        path = str(raw_path)
        if not path:
            continue
        entries.append((proto, port, path))

for proto, port, path in sorted(entries):
    cmd = [
        sys.executable,
        "-m",
        "auto_xdp.admin.cli",
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
        failures += 1
        continue
    print(f"  Loaded per-port handler: {proto}/{port} ({path})")

if strict and failures:
    raise SystemExit(1)
PYEOF
}
