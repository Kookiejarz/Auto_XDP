cleanup_existing_xdp() {
    cleanup_tc_egress_filter

    local iface any_xdp=0
    for iface in "${IFACES[@]}"; do
        if ip -d link show dev "$iface" 2>/dev/null | grep -Eq 'xdp|xdpgeneric|xdpoffload'; then
            any_xdp=1
            break
        fi
    done

    if [[ $any_xdp -eq 1 ]]; then
        local iface_list="${IFACES[*]}"
        warn "Existing XDP program detected on one or more interfaces: $iface_list"
        if confirm_yes_no "Unload the existing XDP program from all interfaces and continue? [y/N] " "abort"; then
            :
        else
            confirm_rc=$?
            case "$confirm_rc" in
                2)
                    die "Cannot confirm unloading because no interactive TTY is available. Re-run with --force."
                    ;;
                *)
                    die "Aborted before unloading the existing XDP program."
                    ;;
            esac
        fi

        for iface in "${IFACES[@]}"; do
            info "Detaching XDP from $iface..."
            ip link set dev "$iface" xdp off 2>/dev/null || true
            ip link set dev "$iface" xdp generic off 2>/dev/null || true
        done

        for iface in "${IFACES[@]}"; do
            if ip -d link show dev "$iface" 2>/dev/null | grep -Eq 'xdp|xdpgeneric|xdpoffload'; then
                die "Failed to clear the existing XDP program from $iface. Detach it manually and rerun."
            fi
        done
        ok "Existing XDP program removed from all interfaces."
    fi

    if [[ -d "$BPF_PIN_DIR" ]]; then
        warn "Removing old BPF pin directory $BPF_PIN_DIR..."
        rm -rf "$BPF_PIN_DIR"
    fi
    mkdir -p "$BPF_PIN_DIR"
}

deploy_xdp_backend() {
    if [[ ! -f "$XDP_OBJ_INSTALLED" ]]; then
        warn "Compiled XDP object not found; skipping XDP backend."
        return 1
    fi

    ensure_bpffs
    cleanup_existing_xdp

    info "Loading XDP program (shared across ${#IFACES[@]} interface(s))..."
    if ! bpftool prog load "$XDP_OBJ_INSTALLED" "$BPF_PIN_DIR/prog" type xdp \
            pinmaps "$BPF_PIN_DIR"; then
        warn "bpftool prog load failed; falling back from XDP."
        rm -rf "$BPF_PIN_DIR"
        return 1
    fi

    if ! xdp_maps_ready; then
        warn "Pinned XDP maps are incomplete after pinning; falling back from XDP."
        rm -rf "$BPF_PIN_DIR"
        return 1
    fi

    seed_existing_tcp_conntrack
    load_tc_egress_program || true
    load_slot_handlers || true

    local iface attached=0
    ACTIVE_XDP_MODE="native"
    for iface in "${IFACES[@]}"; do
        if ip link set dev "$iface" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
            ok "XDP attached in native mode on $iface"
            attached=$((attached + 1))
        elif ip link set dev "$iface" xdp generic pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
            ok "XDP attached in generic mode on $iface"
            ACTIVE_XDP_MODE="generic"
            attached=$((attached + 1))
        else
            warn "Failed to attach XDP to $iface (skipping this interface)"
        fi
    done

    if [[ $attached -gt 0 ]]; then
        ACTIVE_BACKEND="xdp"
        return 0
    fi

    warn "XDP could not be attached to any interface — using nftables fallback."
    cleanup_tc_egress_filter
    for iface in "${IFACES[@]}"; do
        ip link set dev "$iface" xdp off 2>/dev/null || true
    done
    rm -rf "$BPF_PIN_DIR"
    return 1
}

ensure_nftables_available() {
    if command -v nft &>/dev/null; then
        return 0
    fi

    warn "nft not found — attempting to install nftables..."
    pkg_install_optional nftables
    command -v nft &>/dev/null
}

cleanup_existing_nftables() {
    command -v nft &>/dev/null || return 0
    nft list table inet auto_xdp &>/dev/null || return 0
    if nft delete table inet auto_xdp 2>/dev/null; then
        info "nftables inet auto_xdp table removed (replaced by XDP)"
    else
        warn "Could not remove inet auto_xdp table; remove manually if needed."
    fi
}

stop_existing_service() {
    case "$INIT_SYSTEM" in
        systemd)
            systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            ;;
        openrc)
            rc-service "$SERVICE_NAME" stop 2>/dev/null || true
            ;;
    esac

    pkill -f "auto_xdp_start.sh" 2>/dev/null || true
    pkill -f "xdp_port_sync.py" 2>/dev/null || true
}

write_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<EOF_CFG
IFACES="${IFACES[*]}"
IFACE="${IFACES[0]}"
SYNC_INTERVAL="${SYNC_INTERVAL}"
LOG_LEVEL="${LOG_LEVEL}"
SYNC_SCRIPT="${SYNC_SCRIPT}"
PYTHON3_BIN="${PYTHON3_BIN}"
BPF_PIN_DIR="${BPF_PIN_DIR}"
XDP_OBJ_PATH="${XDP_OBJ_INSTALLED}"
TC_OBJ_PATH="${TC_OBJ_INSTALLED}"
PREFERRED_BACKEND="auto"
BPF_HELPER_SCRIPT="${BPF_HELPER_INSTALLED}"
TOML_CONFIG="${CONFIG_DIR}/config.toml"
HANDLERS_DIR="${INSTALL_DIR}/handlers"
PYTHONPATH="${PYTHON_LIB_DIR}"
export BPF_PIN_DIR
EOF_CFG
}

install_python_support_package() {
    local pkg_root="${AUTO_XDP_PACKAGE_DIR}"
    local bpf_root="${pkg_root}/bpf"

    mkdir -p "$bpf_root"

    fetch_local_or_remote "auto_xdp/__init__.py" "auto_xdp/__init__.py" "${pkg_root}/__init__.py" || return 1
    fetch_local_or_remote "auto_xdp/config.py" "auto_xdp/config.py" "${pkg_root}/config.py" || return 1
    fetch_local_or_remote "auto_xdp/bpf/__init__.py" "auto_xdp/bpf/__init__.py" "${bpf_root}/__init__.py" || return 1
    fetch_local_or_remote "auto_xdp/bpf/maps.py" "auto_xdp/bpf/maps.py" "${bpf_root}/maps.py" || return 1
    fetch_local_or_remote "auto_xdp/bpf/syscall.py" "auto_xdp/bpf/syscall.py" "${bpf_root}/syscall.py" || return 1
}

install_runner_script() {
    if ! fetch_local_or_remote "$RUNNER_SRC" "$RUNNER_SRC" "$RUNNER_SCRIPT"; then
        die "Failed to install ${RUNNER_SRC}"
    fi
    chmod +x "$RUNNER_SCRIPT"
}

install_runtime_common_script() {
    if ! fetch_local_or_remote "$RUNTIME_COMMON_SRC" "$RUNTIME_COMMON_SRC" "$BPF_RUNTIME_COMMON_INSTALLED"; then
        die "Failed to install ${RUNTIME_COMMON_SRC}"
    fi
    chmod +x "$BPF_RUNTIME_COMMON_INSTALLED"
}

install_sync_script() {
    if ! fetch_local_or_remote "xdp_port_sync.py" "xdp_port_sync.py" "$SYNC_SCRIPT"; then
        die "Failed to install xdp_port_sync.py"
    fi
    chmod +x "$SYNC_SCRIPT"
}

install_relay_script() {
    if ! fetch_local_or_remote "pkt_relay.py" "pkt_relay.py" "$RELAY_SCRIPT"; then
        die "Failed to install pkt_relay.py"
    fi
    chmod +x "$RELAY_SCRIPT"
}

install_bpf_helper() {
    if ! fetch_local_or_remote "$BPF_HELPER_SRC" "$BPF_HELPER_SRC" "$BPF_HELPER_INSTALLED"; then
        die "Failed to install ${BPF_HELPER_SRC}"
    fi
    chmod +x "$BPF_HELPER_INSTALLED"
}

install_axdp_command() {
    if ! fetch_local_or_remote "axdp" "axdp" "$AXDP_CMD"; then
        die "Failed to install axdp"
    fi
    chmod +x "$AXDP_CMD"
}

install_toml_config() {
    local toml_target="${CONFIG_DIR}/config.toml"
    mkdir -p "$CONFIG_DIR"

    if [[ -f "$toml_target" ]]; then
        if confirm_yes_no "config.toml already exists at ${toml_target}. Replace with repo default? [y/N] "; then
            info "Replacing config.toml with repo default."
        else
            info "Keeping existing config.toml."
            return 0
        fi
    fi

    if ! fetch_local_or_remote "config.toml" "config.toml" "$toml_target"; then
        die "Failed to install config.toml"
    fi
}

install_runtime_files() {
    info "Installing runtime files..."
    mkdir -p "$INSTALL_DIR"
    install_sync_script
    install_python_support_package
    install_relay_script
    install_bpf_helper
    install_axdp_command
    install_runtime_common_script
    write_config
    install_toml_config
    install_runner_script
    ok "Runtime installed under $INSTALL_DIR and $CONFIG_DIR"
}

install_systemd_service() {
    info "Creating systemd service: $SERVICE_NAME..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF_UNIT
[Unit]
Description=Auto XDP Loader + Port Whitelist Auto-Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${RUNNER_SCRIPT}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF_UNIT

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    ok "Service started and enabled: $SERVICE_NAME"
}

install_openrc_service() {
    info "Creating OpenRC service: $SERVICE_NAME..."
    cat > "/etc/init.d/${SERVICE_NAME}" <<EOF_OPENRC
#!/sbin/openrc-run
description="Auto XDP loader + port whitelist auto-sync"
command="${RUNNER_SCRIPT}"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"

depend() {
    need net
}
EOF_OPENRC

    chmod +x "/etc/init.d/${SERVICE_NAME}"
    rc-update add "$SERVICE_NAME" default >/dev/null 2>&1 || true
    rc-service "$SERVICE_NAME" restart
    ok "OpenRC service started and enabled: $SERVICE_NAME"
}

run_initial_sync() {
    info "Running initial sync..."
    "$RUNNER_SCRIPT" --sync-once
}
