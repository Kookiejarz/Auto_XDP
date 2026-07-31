#!/bin/bash
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/auto_xdp/auto_xdp.env}"
RUN_STATE_DIR="${RUN_STATE_DIR:-/run/auto_xdp}"
RUNTIME_COMMON_SCRIPT="${RUNTIME_COMMON_SCRIPT:-/usr/local/lib/auto_xdp/auto_xdp_runtime_common.sh}"

append_pythonpath_once() {
    local path="$1"

    [[ -n "$path" ]] || return 0
    case ":${PYTHONPATH:-}:" in
        *":${path}:"*)
            return 0
            ;;
    esac
    PYTHONPATH="${path}${PYTHONPATH:+:${PYTHONPATH}}"
}

discover_python_lib_dir() {
    local script_dir candidate
    local -a candidates=()

    if [[ -n "${PYTHON_LIB_DIR:-}" ]]; then
        candidates+=("${PYTHON_LIB_DIR}")
    fi
    if [[ -n "${INSTALL_DIR:-}" ]]; then
        candidates+=("${INSTALL_DIR}/python" "${INSTALL_DIR}")
    fi

    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    script_dir="$(cd "${script_dir}/.." && pwd)"
    candidates+=("${script_dir}" "${script_dir}/python")

    for candidate in "${candidates[@]}"; do
        [[ -f "${candidate}/auto_xdp/__init__.py" ]] || continue
        printf '%s\n' "$candidate"
        return 0
    done

    if [[ -n "${PYTHON_LIB_DIR:-}" ]]; then
        printf '%s\n' "${PYTHON_LIB_DIR}"
    elif [[ -n "${INSTALL_DIR:-}" ]]; then
        printf '%s\n' "${INSTALL_DIR}/python"
    fi
}

auto_xdp_shared_info() {
    echo "[auto_xdp] $*" >&2
}

auto_xdp_shared_warn() {
    echo "[auto_xdp] warning: $*" >&2
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    [[ -f "$CONFIG_FILE" ]] || {
        echo "[auto_xdp] missing config: $CONFIG_FILE" >&2
        exit 1
    }
    # shellcheck disable=SC1091
    source "$CONFIG_FILE"

    PYTHON_LIB_DIR="$(discover_python_lib_dir)"
    export PYTHON_LIB_DIR
    append_pythonpath_once "${PYTHON_LIB_DIR}"
    export PYTHONPATH="${PYTHONPATH:-}"

    [[ -f "$RUNTIME_COMMON_SCRIPT" ]] || {
        echo "[auto_xdp] missing runtime library: $RUNTIME_COMMON_SCRIPT" >&2
        exit 1
    }
    # shellcheck disable=SC1091
    source "$RUNTIME_COMMON_SCRIPT"

    # Normalize _IFACES array — supports both new IFACES= and legacy IFACE= configs.
    IFS=' ' read -ra _IFACES <<< "${IFACES:-${IFACE:-}}"
    [[ ${#_IFACES[@]} -gt 0 ]] || {
        echo "[auto_xdp] no interfaces configured (IFACES or IFACE missing from config)" >&2
        exit 1
    }
fi

resolve_preferred_backend() {
    local preferred="${PREFERRED_BACKEND:-auto}"

    [[ -f "${TOML_CONFIG:-}" ]] || {
        printf '%s\n' "$preferred"
        return 0
    }

    preferred=$("$PYTHON3_BIN" - "$TOML_CONFIG" "$preferred" <<'PY'
import os
import sys

path, default = sys.argv[1], sys.argv[2]

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        print(default)
        raise SystemExit(0)

if not os.path.exists(path):
    print(default)
    raise SystemExit(0)

try:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
except Exception:
    print(default)
    raise SystemExit(0)

preferred = str(cfg.get("daemon", {}).get("preferred_backend", default)).lower()
if preferred not in {"auto", "xdp", "nftables"}:
    preferred = default
print(preferred)
PY
) || preferred="${PREFERRED_BACKEND:-auto}"

    printf '%s\n' "$preferred"
}

run_sync_script() {
    local mode="$1"
    shift || true
    local backend
    backend=$(cat "${RUN_STATE_DIR}/backend")

    if [[ "$mode" == "watch" ]]; then
        exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --watch --backend "$backend" "$@"
    fi
    exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --backend "$backend" "$@"
}

ensure_xdp_loaded() {
    command -v bpftool &>/dev/null || return 1
    [[ -f "$XDP_OBJ_PATH" ]] || return 1

    ensure_bpffs

    # A killed loader can leave a staged or rollback generation behind. Resume
    # or verify it before the healthy fast path accepts existing attachments.
    if [[ -e "${BPF_PIN_DIR}_next" || -e "${BPF_PIN_DIR}_rollback" ]]; then
        _auto_xdp_finish_interrupted_reload || return 1
    fi

    # If the prog is already pinned and maps are intact, just re-attach any
    # interface that has lost its XDP program (e.g. after a link bounce).
    if [[ -f "$BPF_PIN_DIR/prog" ]] && xdp_maps_ready; then
        local _iface _any_missing=0 _xdp_mode="native"
        for _iface in "${_IFACES[@]}"; do
            if ! ip link show "$_iface" 2>/dev/null | grep -q "xdp"; then
                _any_missing=1
                if ip link set dev "$_iface" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
                    echo "[auto_xdp] re-attached XDP (native) on $_iface" >&2
                elif ip link set dev "$_iface" xdpgeneric pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
                    echo "[auto_xdp] re-attached XDP (generic) on $_iface" >&2
                    _xdp_mode="generic"
                else
                    echo "[auto_xdp] warning: could not re-attach XDP to $_iface" >&2
                fi
            elif ip -d link show dev "$_iface" 2>/dev/null | grep -q "xdpgeneric"; then
                _xdp_mode="generic"
            fi
        done
        [[ -f "$BPF_PIN_DIR/sock_state_link" ]] || load_sock_state_tracker || true
        load_port_handlers || true
        auto_tune_interface_parallelism || true
        [[ $_any_missing -eq 1 ]] && echo "[auto_xdp] re-attached XDP to missing interfaces" >&2
        echo "$_xdp_mode" > "${RUN_STATE_DIR}/xdp_mode"
        return 0
    fi

    [[ -f "$BPF_PIN_DIR/prog" ]] && echo "[auto_xdp] existing XDP maps incomplete; reloading runtime objects" >&2

    # Build and seed a candidate map generation while the current XDP/tc
    # programs remain attached. The shared switch helper restores every
    # interface and filter if any replace operation fails.
    if ! transactional_reload_xdp; then
        echo "[auto_xdp] transactional XDP/tc reload failed; previous protection preserved or restored" >&2
        if _auto_xdp_any_target_has_xdp; then
            echo "[auto_xdp] refusing nftables fallback while XDP remains attached" >&2
            return 2
        fi
        return 1
    fi

    load_sock_state_tracker || true
    auto_tune_interface_parallelism || true
    echo "$AUTO_XDP_SWITCH_MODE" > "${RUN_STATE_DIR}/xdp_mode"
    return 0
}

select_backend() {
    mkdir -p "$RUN_STATE_DIR"
    local preferred_backend xdp_status=1
    preferred_backend=$(resolve_preferred_backend)

    if [[ "$preferred_backend" != "nftables" ]]; then
        if ensure_xdp_loaded; then
            xdp_status=0
        else
            xdp_status=$?
        fi
        if [[ $xdp_status -eq 0 ]]; then
            echo "xdp" > "${RUN_STATE_DIR}/backend"
            if command -v nft &>/dev/null && nft list table inet auto_xdp &>/dev/null 2>&1; then
                if nft delete table inet auto_xdp 2>/dev/null; then
                    echo "[auto_xdp] nftables inet auto_xdp table removed (replaced by XDP)"
                fi
            fi
            return 0
        fi
        if [[ $xdp_status -eq 2 ]]; then
            echo "[auto_xdp] XDP reload failed with an attachment still active; backend selection aborted" >&2
            return 1
        fi
    fi

    command -v nft &>/dev/null || {
        echo "[auto_xdp] nft not found and XDP unavailable" >&2
        exit 1
    }
    echo "nftables" > "${RUN_STATE_DIR}/backend"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "${1:-}" == "--sync-once" ]]; then
        shift
        select_backend
        run_sync_script once "$@"
    fi

    select_backend
    run_sync_script watch
fi
