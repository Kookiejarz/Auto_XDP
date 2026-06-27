#!/bin/bash

# setup_xdp.sh — Auto XDP installer / loader / fallback bootstrap
# Usage: bash setup_xdp.sh [--check-update] [--force] [--check-env] [--dry-run] [interface]
# Runs as an ordinary user and escalates with sudo only for the steps that need
# it; running the whole script with sudo still works.
# Supports Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, and Alpine.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

IN_STEP=0
_STEP_NEWLINED=0
_PENDING_NL=0
# Prefix used to indent sub-lines inside a step (aligns with label text).
_STEP_INDENT="             "
OK_MARK="${GREEN}✓${NC}"
WARN_MARK="${YELLOW}!${NC}"
FAIL_MARK="${RED}✗${NC}"

info()  {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then printf "\n"; _STEP_NEWLINED=1; fi
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; fi
        printf "${_STEP_INDENT}${CYAN}[INFO]${NC}  %s" "$*"
        _PENDING_NL=1
    else
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi
        echo -e "${CYAN}[INFO]${NC}  $*"
    fi
}
ok()    { if [[ $IN_STEP -eq 0 ]]; then echo -e "${GREEN}[OK]${NC}    $*"; fi; }
warn()  {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then printf "\n"; _STEP_NEWLINED=1; fi
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi
        printf "${_STEP_INDENT}${YELLOW}[WARN]${NC}  %s\n" "$*"
    else
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi
        echo -e "${YELLOW}[WARN]${NC}  $*"
    fi
}
die()   {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then
            printf " ${FAIL_MARK}\n"
        else
            if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; fi
            printf "${_STEP_INDENT}${FAIL_MARK}\n"
        fi
        IN_STEP=0; _STEP_NEWLINED=0; _PENDING_NL=0
    fi
    echo -e "${RED}[ERR ]${NC}  $*" >&2
    exit 1
}

die_with_next() {
    local message="$1"
    local next_step="$2"

    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then
            printf " ${FAIL_MARK}\n"
        else
            if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; fi
            printf "${_STEP_INDENT}${FAIL_MARK}\n"
        fi
        IN_STEP=0; _STEP_NEWLINED=0; _PENDING_NL=0
    fi
    echo -e "${RED}[ERR ]${NC}  $message" >&2
    echo "       Next: $next_step" >&2
    exit 1
}

IFACE=""
IFACES=()
ALL_IFACES=0
XDP_SRC="bpf/xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"
TC_SRC="tc_flow_track.c"
TC_OBJ="tc_flow_track.o"

INSTALL_DIR="/usr/local/lib/auto_xdp"
PYTHON_LIB_DIR="${INSTALL_DIR}/python"
AUTO_XDP_PACKAGE_DIR="${PYTHON_LIB_DIR}/auto_xdp"
CONFIG_DIR="/etc/auto_xdp"
CONFIG_FILE="${CONFIG_DIR}/auto_xdp.env"
TOML_CONFIG="${CONFIG_DIR}/config.toml"
SYNC_SCRIPT="/usr/local/bin/xdp_port_sync.py"
RELAY_SCRIPT="/usr/local/bin/pkt_relay.py"
AXDP_CMD="/usr/local/bin/axdp"
RUNNER_SCRIPT="/usr/local/bin/auto_xdp_start.sh"
RUNNER_SRC="runtime/auto_xdp_start.sh"
RUNTIME_COMMON_SRC="runtime/auto_xdp_runtime_common.sh"
XDP_OBJ_INSTALLED="${INSTALL_DIR}/xdp_firewall.o"
TC_OBJ_INSTALLED="${INSTALL_DIR}/tc_flow_track.o"
SOCK_STATE_SRC="bpf/sock_state_track.c"
SOCK_STATE_OBJ="sock_state_track.o"
SOCK_STATE_OBJ_INSTALLED="${INSTALL_DIR}/sock_state_track.o"
BPF_RUNTIME_COMMON_INSTALLED="${INSTALL_DIR}/auto_xdp_runtime_common.sh"
BPF_HELPER_SRC="auto_xdp_bpf_helpers.py"
BPF_HELPER_INSTALLED="${INSTALL_DIR}/auto_xdp_bpf_helpers.py"
BPF_HELPER_BOOTSTRAP=""
BUILD_STAGING_DIR=""

export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
SERVICE_NAME="xdp-port-sync"
RELAY_SERVICE_NAME="auto-xdp-relay"
RAW_URL="https://raw.githubusercontent.com/Kookiejarz/auto_xdp/main"
TC_FILTER_PREF=49152
PREFER_REMOTE_SOURCES=0
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"
SYSTEMD_RUN_DIR="${SYSTEMD_RUN_DIR:-/run/systemd/system}"

case "${BASH_SOURCE[0]:-}" in
    stdin|/dev/stdin|/dev/fd/*|/proc/self/fd/*)
        # curl | bash should use the matching GitHub sources instead of stale
        # files from the caller's working directory.
        PREFER_REMOTE_SOURCES=1
        ;;
esac
if [[ $PREFER_REMOTE_SOURCES -eq 0 ]]; then
    # Some shells expose stdin execution as "bash" instead of /dev/fd/*.
    # Also prefer remote sources when the script path is not a readable file.
    if [[ "${BASH_SOURCE[0]:-}" == "bash" || ! -r "${BASH_SOURCE[0]:-}" ]]; then
        PREFER_REMOTE_SOURCES=1
    fi
fi

PKG_MANAGER=""
INIT_SYSTEM="none"
SYSTEMD_AVAILABLE=0
OPENRC_AVAILABLE=0
ACTIVE_BACKEND="nftables"
ACTIVE_XDP_MODE="none"
XDP_FALLBACK_REASON=""
PYTHON3_BIN=""
CHECK_UPDATES=0
FORCE=0
CHECK_ENV=0
DRY_RUN=0
INTERNAL_PHASE2=0
RESULT_FILE=""
DISTRO_ID="unknown"
DISTRO_NAME="unknown"
DISTRO_LIKE=""
DISTRO_FAMILY="unknown"

_SETUP_TMPFILES=()
_cleanup_setup_tmpfiles() {
    local f
    for f in "${_SETUP_TMPFILES[@]:-}"; do
        [[ -f "$f" ]] && rm -f "$f"
    done
    return 0
}
_cleanup_on_exit() {
    _cleanup_setup_tmpfiles
    if declare -F _stop_priv_keepalive >/dev/null 2>&1; then
        _stop_priv_keepalive
    fi
}
trap '_cleanup_on_exit' EXIT

source_setup_lib() {
    local relative_path="$1"
    local source_path="$relative_path"
    if [[ $PREFER_REMOTE_SOURCES -eq 1 || ! -r "$source_path" ]]; then
        source_path=$(mktemp)
        _SETUP_TMPFILES+=("$source_path")
        curl -fsSL "${RAW_URL}/${relative_path}" -o "$source_path" \
            || die "Failed to load ${relative_path}"
    fi
    # shellcheck disable=SC1090
    source "$source_path"
}

source_setup_lib "lib/setup/core.sh"
source_setup_lib "lib/setup/detect.sh"
source_setup_lib "lib/setup/packages.sh"
source_setup_lib "lib/setup/fetch.sh"
source_setup_lib "lib/setup/build.sh"
source_setup_lib "lib/setup/backend_xdp.sh"
source_setup_lib "lib/setup/backend_nft.sh"

auto_xdp_shared_info() {
    info "$@"
}

auto_xdp_shared_warn() {
    warn "$@"
}

load_runtime_common_lib() {
    local lib_path="$RUNTIME_COMMON_SRC"
    if [[ $PREFER_REMOTE_SOURCES -eq 1 || ! -r "$lib_path" ]]; then
        lib_path=$(mktemp)
        _SETUP_TMPFILES+=("$lib_path")
        if ! fetch_local_or_remote "$RUNTIME_COMMON_SRC" "$RUNTIME_COMMON_SRC" "$lib_path"; then
            die "Failed to load ${RUNTIME_COMMON_SRC}"
        fi
    fi
    # shellcheck disable=SC1090
    source "$lib_path"
}

load_runtime_common_lib
source_setup_lib "lib/setup/install.sh"

# The backend bring-up: load the XDP/nftables backend, register handlers, seed
# conntrack, and install + start the system service. These steps run the shared
# runtime library in-process, so they execute as a single privileged unit.
run_backend_phase() {
    deploy_backend_step
    load_configured_slot_handlers_step
    load_configured_port_handlers_step
    run_initial_sync_step
    install_runtime_service_step
}

# Persist the backend outcome so a sudo re-exec can hand it back to the
# unprivileged parent for the deployment summary.
_emit_backend_results() {
    local rf="$1"
    [[ -n "$rf" ]] || return 0
    {
        printf 'ACTIVE_BACKEND=%q\n' "$ACTIVE_BACKEND"
        printf 'ACTIVE_XDP_MODE=%q\n' "$ACTIVE_XDP_MODE"
        printf 'XDP_FALLBACK_REASON=%q\n' "$XDP_FALLBACK_REASON"
    } > "$rf"
}

# Resolve a runnable path to this installer for the privileged re-exec. When the
# installer is being piped from curl there is no file on disk, so materialize a
# copy from GitHub.
_resolve_self_path() {
    if [[ $PREFER_REMOTE_SOURCES -eq 0 && -r "${BASH_SOURCE[0]:-}" ]]; then
        printf '%s' "${BASH_SOURCE[0]}"
        return 0
    fi
    local self
    self=$(mktemp)
    _SETUP_TMPFILES+=("$self")
    curl -fsSL "${RAW_URL}/setup_xdp.sh" -o "$self" || return 1
    printf '%s' "$self"
}

# Run run_backend_phase as a single privileged unit. Already root: in-process.
# Non-root: re-exec just this phase under sudo (one elevated process) and import
# the resulting backend state, so the shared runtime library never has to
# escalate command-by-command.
run_backend_phase_dispatch() {
    if [[ "$PRIV_MODE" == "root" ]]; then
        run_backend_phase
        return 0
    fi

    local self rf
    self=$(_resolve_self_path) || die "Could not locate the installer to escalate the backend phase."
    rf=$(mktemp)
    _SETUP_TMPFILES+=("$rf")

    local -a force_arg=()
    [[ $FORCE -eq 1 ]] && force_arg=(--force)

    as_root bash "$self" --internal-phase2 --result-file "$rf" \
        "${force_arg[@]}" "${IFACES[@]}" \
        || die "Backend bring-up failed under sudo."

    # shellcheck disable=SC1090
    [[ -s "$rf" ]] && source "$rf"
}

# Privileged continuation invoked via --internal-phase2 under sudo. Almost all
# install paths are constants set when this script is sourced; only a handful of
# values need re-deriving before running the backend phase.
run_internal_phase2() {
    PRIV_MODE="root"
    [[ ${#IFACES[@]} -gt 0 ]] || die "Internal backend phase requires target interfaces."
    IFACE="${IFACES[0]}"
    detect_os_release
    detect_pkg_manager || true
    detect_init_system
    PYTHON3_BIN="$(command -v python3 || echo python3)"
    BPF_HELPER_BOOTSTRAP="$BPF_HELPER_INSTALLED"
    run_backend_phase
    _emit_backend_results "$RESULT_FILE"
}

main() {
    parse_args "$@"

    if [[ $INTERNAL_PHASE2 -eq 1 ]]; then
        run_internal_phase2
        exit 0
    fi

    if [[ $CHECK_ENV -eq 1 ]]; then
        detect_os_release
        detect_pkg_manager || die "No supported package manager found."
        detect_init_system
        echo "distro_id=$DISTRO_ID"
        echo "distro_name=$DISTRO_NAME"
        echo "distro_family=$DISTRO_FAMILY"
        echo "package_manager=$PKG_MANAGER"
        echo "init_system=$INIT_SYSTEM"
        exit 0
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        dry_run_report
        exit 0
    fi

    print_installer_banner
    detect_privilege_mode
    check_github_updates_once
    resolve_target_interfaces_step
    detect_environment_step
    print_setup_plan
    # First system-mutating step ahead: acquire sudo once (no-op when root).
    priv_init
    check_required_tools_step
    bootstrap_bpf_helper_step
    confirm_existing_install_step
    stop_existing_service_step
    compile_bpf_objects_step
    install_xdp_required_maps_step
    install_runtime_files_step
    restore_compiled_slot_handlers_step
    # Backend bring-up runs as a single privileged unit (root in-process, or one
    # sudo re-exec when started as a normal user).
    run_backend_phase_dispatch
    cleanup_build_artifacts_step
    print_deployment_summary
}

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    main "$@"
fi
