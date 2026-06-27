_step_tag() {
    printf "${CYAN}[INFO]${NC}     "
}

step_begin() {
    IN_STEP=1
    _STEP_NEWLINED=0
    _PENDING_NL=0
    _step_tag "${2:-INFO}"
    printf " %-60s" "$1 …"
}

step_ok() {
    local nl=$_STEP_NEWLINED
    local pending=$_PENDING_NL
    IN_STEP=0
    _STEP_NEWLINED=0
    _PENDING_NL=0
    if [[ $pending -eq 1 ]]; then
        printf " ${OK_MARK}%s\n" "${1:+  ($1)}"
    elif [[ $nl -eq 1 ]]; then
        printf "${_STEP_INDENT}${OK_MARK}%s\n" "${1:+  ($1)}"
    else
        [[ -n "${1:-}" ]] && printf "${GREEN}($1)${NC} ${OK_MARK}\n" || printf " ${OK_MARK}\n"
    fi
}

step_fail() {
    local nl=$_STEP_NEWLINED
    IN_STEP=0
    _STEP_NEWLINED=0
    if [[ $_PENDING_NL -eq 1 ]]; then
        printf "\n"
        _PENDING_NL=0
    elif [[ $nl -eq 0 ]]; then
        printf " ${FAIL_MARK}\n"
    fi
    printf "${_STEP_INDENT}${RED}[ERROR]${NC}  %s\n" "${1:-Failed}" >&2
}

step_warn() {
    local nl=$_STEP_NEWLINED
    local pending=$_PENDING_NL
    IN_STEP=0
    _STEP_NEWLINED=0
    _PENDING_NL=0
    if [[ $pending -eq 1 ]]; then
        printf " ${WARN_MARK}%s\n" "${1:+  ($1)}"
    elif [[ $nl -eq 1 ]]; then
        printf "${_STEP_INDENT}${WARN_MARK}%s\n" "${1:+  ($1)}"
    else
        printf " ${WARN_MARK}%s\n" "${1:+  ($1)}"
    fi
}

substep_run() {
    local label="$1"
    shift

    if [[ $IN_STEP -eq 1 && $_STEP_NEWLINED -eq 0 ]]; then
        printf "\n"
        _STEP_NEWLINED=1
    fi

    if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi

    printf "${_STEP_INDENT}${CYAN}[INFO]${NC}  %-46s" "${label} …"
    _STEP_NEWLINED=0

    if "$@"; then
        if [[ $_PENDING_NL -eq 1 ]]; then
            printf " ${OK_MARK}\n"
            _PENDING_NL=0
        else
            printf " ${OK_MARK}\n"
        fi
        _STEP_NEWLINED=1
        return 0
    else
        local status=$?
        if [[ $_PENDING_NL -eq 1 ]]; then
            printf " ${FAIL_MARK}\n"
            _PENDING_NL=0
        else
            printf " ${FAIL_MARK}\n"
        fi
        _STEP_NEWLINED=1
        return "$status"
    fi
}

# ---------------------------------------------------------------------------
# Privilege handling
#
# The installer launches as an ordinary user and only escalates for the steps
# that genuinely need it: package installs, writes under /usr/local/lib & /etc,
# service management, and loading the BPF/XDP backend. PRIV_MODE is resolved
# once, without prompting, by detect_privilege_mode:
#   root  -> already EUID 0; the helpers run commands directly
#   sudo  -> sudo is on PATH; the helpers escalate per command
# The first password prompt is deferred to priv_init, called right before the
# first system-mutating step, so the banner/detection/plan run as the user.
# ---------------------------------------------------------------------------
PRIV_MODE="root"
PRIV_PRIMED=0
_PRIV_KEEPALIVE_PID=""

detect_privilege_mode() {
    step_begin "Checking privileges"
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        PRIV_MODE="root"
        step_ok "running as root"
        return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
        PRIV_MODE="sudo"
        step_ok "non-root; will escalate via sudo when needed"
        return 0
    fi
    die_with_next "Some steps need root, but neither root nor sudo is available." \
        "re-run as root (su -) or install sudo, then run: bash $0 ${IFACES[*]:-}"
}

# Run a command with root privileges (direct when already root).
as_root() {
    if [[ "$PRIV_MODE" == "root" ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Prime the sudo timestamp once (single password prompt) and keep it warm for
# the rest of the run so long steps never re-prompt. No-op when already root.
priv_init() {
    [[ "$PRIV_MODE" == "sudo" ]] || return 0
    [[ $PRIV_PRIMED -eq 1 ]] && return 0
    info "Some steps need administrative privileges; requesting sudo access..."
    sudo -v || die "Could not obtain sudo privileges."
    PRIV_PRIMED=1
    ( while true; do sudo -n -v 2>/dev/null || exit 0; sleep 50; done ) &
    _PRIV_KEEPALIVE_PID=$!
}

_stop_priv_keepalive() {
    [[ -n "$_PRIV_KEEPALIVE_PID" ]] || return 0
    kill "$_PRIV_KEEPALIVE_PID" 2>/dev/null || true
    _PRIV_KEEPALIVE_PID=""
}

# True when the current user can write PATH (the nearest existing ancestor for
# a not-yet-created path), i.e. no escalation is needed to create/replace it.
_can_write_path() {
    local p="$1"
    if [[ -e "$p" ]]; then
        [[ -w "$p" ]]
        return
    fi
    local dir
    dir="$(dirname "$p")"
    while [[ -n "$dir" && "$dir" != "/" && ! -e "$dir" ]]; do
        dir="$(dirname "$dir")"
    done
    [[ -w "$dir" ]]
}

# mkdir -p that escalates only when the target tree is not user-writable.
priv_mkdir() {
    local dir="$1"
    if _can_write_path "$dir"; then
        mkdir -p "$dir"
    else
        as_root mkdir -p "$dir"
    fi
}

# Write stdin to DEST, escalating only when DEST is not user-writable.
write_file() {
    local dest="$1"
    priv_mkdir "$(dirname "$dest")"
    if _can_write_path "$dest"; then
        cat > "$dest"
    else
        as_root tee "$dest" >/dev/null
    fi
}

# Copy SRC to DEST, escalating only when DEST is not user-writable.
place_file() {
    local src="$1" dest="$2"
    priv_mkdir "$(dirname "$dest")"
    if _can_write_path "$dest"; then
        cp "$src" "$dest"
    else
        as_root cp "$src" "$dest"
    fi
}

usage() {
    cat <<'EOF'
Usage: bash setup_xdp.sh [--check-update] [--force] [--all-interfaces] [interface...]

Runs as an ordinary user and escalates with sudo only for the steps that need
it (package installs, writes under /usr/local/lib & /etc, service management,
and loading the XDP backend). Running the whole script with sudo still works.

Options:
  --check-update     Compare local files with GitHub by SHA-256 and ask before pulling
  --force            Skip confirmations and apply update/replace actions automatically
  --check-env        Print detected package manager and init system, then exit
  --dry-run          Report planned actions without changing the system
  --all-interfaces   Deploy to all active non-loopback interfaces automatically
  -h, --help         Show this help

Examples:
  bash setup_xdp.sh                    # auto-detect default route interface
  bash setup_xdp.sh --all-interfaces   # deploy to all active interfaces
  bash setup_xdp.sh eth0 eth1          # deploy to specific interfaces
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check-update)
                CHECK_UPDATES=1
                shift
                ;;
            --force)
                FORCE=1
                shift
                ;;
            --check-env)
                CHECK_ENV=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --internal-phase2)
                # Hidden: privileged backend continuation re-exec'd via sudo.
                INTERNAL_PHASE2=1
                shift
                ;;
            --result-file)
                RESULT_FILE="$2"
                shift 2
                ;;
            --all-interfaces|-a)
                ALL_IFACES=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                die "Unknown option: $1"
                ;;
            *)
                IFACES+=("$1")
                shift
                ;;
        esac
    done

    if [[ $# -gt 0 ]]; then
        die "Unexpected argument: $1"
    fi
}

print_installer_banner() {
    echo -e "\n${BOLD}${CYAN}  ╔═══════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}  ║      Auto XDP Installer           ║${NC}"
    echo -e "${BOLD}${CYAN}  ╚═══════════════════════════════════╝${NC}\n"
}

print_setup_plan() {
    echo -e "${BOLD}Auto XDP setup plan${NC}"
    if [[ ${#IFACES[@]} -eq 1 ]]; then
        echo "  interface      : ${IFACES[0]}"
    else
        echo "  interfaces     : ${IFACES[*]}"
    fi
    echo "  backend        : auto (XDP preferred, nftables fallback)"
    echo "  package manager: $PKG_MANAGER"
    echo "  service manager: $INIT_SYSTEM"
    echo "  install dir    : $INSTALL_DIR"
    echo "  config dir     : $CONFIG_DIR"
    echo ""
}

get_active_interfaces() {
    ip -o link show up 2>/dev/null \
        | awk -F': ' '{print $2}' \
        | awk '{print $1}' \
        | grep -v '^lo$' \
        | grep -v '@' \
        | grep -v '^dummy' \
        | grep -v '^virbr' \
        | grep -v '^docker' \
        | grep -v '^veth' \
        | grep -v '^br-' \
        | grep -v '^tun' \
        | grep -v '^tap' \
        | grep -v '^wg' \
        | grep -v '^bond' \
        | grep -v '^team' \
        || true
}

resolve_target_interfaces_step() {
    step_begin "Detecting network interfaces"
    if [[ $ALL_IFACES -eq 1 ]]; then
        mapfile -t IFACES < <(get_active_interfaces)
        [[ ${#IFACES[@]} -gt 0 ]] || die "No active non-loopback interfaces found."
    elif [[ ${#IFACES[@]} -eq 0 ]]; then
        local _default_iface
        _default_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
        [[ -n "$_default_iface" ]] || die "Cannot detect default interface. Specify manually: sudo bash $0 eth0"
        IFACES=("$_default_iface")
    fi

    local _iface
    for _iface in "${IFACES[@]}"; do
        ip link show "$_iface" &>/dev/null || die "Interface '$_iface' does not exist."
    done

    IFACE="${IFACES[0]}"
    step_ok "Found: ${IFACES[*]}"
}

# Backward-compatible alias; the up-front root requirement is gone. Privilege
# is resolved by detect_privilege_mode and acquired lazily via priv_init.
check_root_privileges() {
    detect_privilege_mode
}

print_deployment_summary() {
    echo ""
    cat <<'EOF'
      █████████   █████  █████ ███████████    ███████       █████ █████ ██████████   ███████████
     ███▒▒▒▒▒███ ▒▒███  ▒▒███ ▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███    ▒▒███ ▒▒███ ▒▒███▒▒▒▒███ ▒▒███▒▒▒▒▒███
    ▒███    ▒███  ▒███   ▒███ ▒   ▒███  ▒  ███     ▒▒███    ▒▒███ ███   ▒███   ▒▒███ ▒███    ▒███
    ▒███████████  ▒███   ▒███     ▒███    ▒███      ▒███     ▒▒█████    ▒███    ▒███ ▒██████████
    ▒███▒▒▒▒▒███  ▒███   ▒███     ▒███    ▒███      ▒███      ███▒███   ▒███    ▒███ ▒███▒▒▒▒▒▒
    ▒███    ▒███  ▒███   ▒███     ▒███    ▒▒███     ███      ███ ▒▒███  ▒███    ███  ▒███
    █████   █████ ▒▒████████      █████    ▒▒▒███████▒      █████ █████ ██████████   █████
    ▒▒▒▒▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒▒      ▒▒▒▒▒       ▒▒▒▒▒▒▒       ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒
EOF
    echo ""
    echo -e "${GREEN}Deployment summary${NC}"
    echo -e "  Status         : ${OK_MARK} complete"
    if [[ ${#IFACES[@]} -eq 1 ]]; then
        echo "  Interface      : ${IFACES[0]}"
    else
        echo "  Interfaces     : ${IFACES[*]}"
    fi
    if [[ "$ACTIVE_BACKEND" == "xdp" ]]; then
        echo "  Backend        : XDP ($ACTIVE_XDP_MODE mode)"
        echo "  BPF maps       : $BPF_PIN_DIR/"
        echo "  TC egress obj  : $TC_OBJ_INSTALLED"
    else
        echo "  Backend        : nftables fallback"
        echo "  Fallback reason: ${XDP_FALLBACK_REASON:-XDP unavailable}"
        echo "  nftables table : inet auto_xdp"
    fi
    echo "  Init system    : $INIT_SYSTEM"
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        echo "  Sync service   : systemd $SERVICE_NAME"
        echo "  Relay service  : systemd ${RELAY_SERVICE_NAME:-auto-xdp-relay}"
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        echo "  Sync service   : openrc $SERVICE_NAME"
        echo "  Relay service  : openrc ${RELAY_SERVICE_NAME:-auto-xdp-relay}"
    else
        echo "  Sync service   : not installed"
        echo "  Relay service  : not installed"
    fi
    echo "  Config         : $TOML_CONFIG"
    echo "  Launcher       : $RUNNER_SCRIPT"
    echo "  Command        : $AXDP_CMD"
    echo ""
    echo "Next commands"
    echo "  status         : sudo axdp status"
    echo "  dashboard      : sudo axdp"
    echo "  live stats     : sudo axdp stats --watch --rates --interval 2"
    echo "  sync ports     : sudo axdp sync"
    echo "  list ports     : sudo axdp ports"
    if [[ "$INIT_SYSTEM" == "systemd" || "$INIT_SYSTEM" == "openrc" ]]; then
        echo "  service restart: sudo axdp restart"
    fi
}

dry_run_report() {
    detect_pkg_manager || die "No supported package manager found."
    detect_init_system

    local detected_ifaces=""
    if [[ $ALL_IFACES -eq 1 ]]; then
        detected_ifaces=$(get_active_interfaces | tr '\n' ' ' | sed 's/[[:space:]]*$//')
    elif [[ ${#IFACES[@]} -gt 0 ]]; then
        detected_ifaces="${IFACES[*]}"
    else
        detected_ifaces=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)
    fi

    echo "mode=dry-run"
    echo "distro_id=$DISTRO_ID"
    echo "distro_name=$DISTRO_NAME"
    echo "distro_family=$DISTRO_FAMILY"
    echo "package_manager=$PKG_MANAGER"
    echo "init_system=$INIT_SYSTEM"
    echo "interfaces=${detected_ifaces:-undetected}"
    echo "missing_commands=$(for cmd in clang bpftool python3 curl ip tc nft; do command -v "$cmd" >/dev/null 2>&1 || printf '%s ' "$cmd"; done | sed 's/[[:space:]]*$//')"
    echo "planned_packages=$(package_list_for_manager; optional_package_list_for_manager; printf ' python3-psutil python3-tomli-if-python310')"
    echo "planned_actions=check-dependencies,compile-xdp,deploy-backend,install-runtime,initial-sync,install-service"
    echo "note=dry-run performs no installs, no downloads, and no system changes"
}
