#!/bin/bash

# lib/setup/install.sh — runtime file installation and system service setup
# Sourced by setup_xdp.sh after backend_xdp.sh and backend_nft.sh.

stop_existing_service() {
    case "$INIT_SYSTEM" in
        systemd)
            as_root systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            as_root systemctl stop "${RELAY_SERVICE_NAME:-auto-xdp-relay}" 2>/dev/null || true
            ;;
        openrc)
            as_root rc-service "$SERVICE_NAME" stop 2>/dev/null || true
            as_root rc-service "${RELAY_SERVICE_NAME:-auto-xdp-relay}" stop 2>/dev/null || true
            ;;
    esac

    as_root pkill -f "auto_xdp_start.sh" 2>/dev/null || true
    as_root pkill -f "xdp_port_sync.py" 2>/dev/null || true
    as_root pkill -f "pkt_relay.py" 2>/dev/null || true
}

existing_install_detected() {
    local runtime_paths=(
        "$CONFIG_FILE"
        "$SYNC_SCRIPT"
        "$AXDP_CMD"
        "$RUNNER_SCRIPT"
        "$BPF_RUNTIME_COMMON_INSTALLED"
        "${INSTALL_DIR}/xdp_required_maps.txt"
        "$BPF_HELPER_INSTALLED"
        "$XDP_OBJ_INSTALLED"
        "$TC_OBJ_INSTALLED"
        "${INSTALL_DIR}/handlers"
        "${CONFIG_DIR}/config.toml"
    )
    local path=""

    for path in "${runtime_paths[@]}"; do
        [[ -e "$path" ]] && return 0
    done

    case "$INIT_SYSTEM" in
        systemd)
            [[ -e "/etc/systemd/system/${SERVICE_NAME}.service" ]] && return 0
            [[ -e "/etc/systemd/system/${RELAY_SERVICE_NAME:-auto-xdp-relay}.service" ]] && return 0
            ;;
        openrc)
            [[ -e "/etc/init.d/${SERVICE_NAME}" ]] && return 0
            [[ -e "/etc/init.d/${RELAY_SERVICE_NAME:-auto-xdp-relay}" ]] && return 0
            ;;
    esac

    return 1
}

confirm_existing_install_step() {
    if ! existing_install_detected; then
        return 0
    fi

    step_begin "Checking existing installation"
    if confirm_yes_no "Existing Auto XDP installation detected. Replace installed runtime files and restart the service? [y/N] " "abort"; then
        step_ok "confirmed"
        return 0
    fi

    step_warn "aborted"
    die "Installation aborted; existing deployment left untouched."
}

stop_existing_service_step() {
    step_begin "Stopping existing service"
    stop_existing_service
    step_ok
}

write_config() {
    priv_mkdir "$CONFIG_DIR"
    write_file "$CONFIG_FILE" <<EOF_CFG
IFACES="${IFACES[*]}"
IFACE="${IFACES[0]}"
SYNC_SCRIPT="${SYNC_SCRIPT}"
PYTHON3_BIN="${PYTHON3_BIN}"
BPF_PIN_DIR="${BPF_PIN_DIR}"
XDP_OBJ_PATH="${XDP_OBJ_INSTALLED}"
TC_OBJ_PATH="${TC_OBJ_INSTALLED}"
SOCK_STATE_OBJ_PATH="${SOCK_STATE_OBJ_INSTALLED}"
PREFERRED_BACKEND="auto"
AUTO_TUNE_QUEUES="1"
BPF_HELPER_SCRIPT="${BPF_HELPER_INSTALLED}"
TOML_CONFIG="${CONFIG_DIR}/config.toml"
INSTALL_DIR="${INSTALL_DIR}"
HANDLERS_DIR="${INSTALL_DIR}/handlers"
PYTHON_LIB_DIR="${PYTHON_LIB_DIR}"
PYTHONPATH="${PYTHON_LIB_DIR}"
export BPF_PIN_DIR
EOF_CFG
}

cleanup_installed_python_support_package() {
    local pkg_root="${AUTO_XDP_PACKAGE_DIR}"

    [[ -n "$pkg_root" ]] || return 0
    if [[ -d "$pkg_root" ]]; then
        as_root rm -rf "$pkg_root"
    fi
    priv_mkdir "$pkg_root"
}

cleanup_installed_handler_sdk() {
    local handlers_root="${INSTALL_DIR}/handlers"
    local config_path="${CONFIG_DIR}/config.toml"
    local installed_file=""
    local base_name=""
    local resolved_file=""
    local keep_file=0
    local preserved_path=""
    local -a preserve_paths=()

    priv_mkdir "$handlers_root"

    if command -v "${PYTHON3_BIN:-python3}" >/dev/null 2>&1 && [[ -f "$config_path" ]]; then
        mapfile -t preserve_paths < <("${PYTHON3_BIN:-python3}" - "$config_path" "$handlers_root" <<'PY'
import os
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
handlers_root = Path(sys.argv[2]).resolve()
preserved = set()

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        raise SystemExit(0)

try:
    with config_path.open("rb") as fh:
        cfg = tomllib.load(fh)
except Exception:
    raise SystemExit(0)

for entry in cfg.get("slots", {}).get("enabled", []):
    if isinstance(entry, dict):
        raw_path = entry.get("path")
        if raw_path:
            try:
                path = Path(str(raw_path)).resolve()
            except OSError:
                continue
            if path.parent == handlers_root:
                preserved.add(str(path))

for proto in ("tcp", "udp"):
    table = cfg.get("port_handlers", {}).get(proto, {})
    if not isinstance(table, dict):
        continue
    for raw_path in table.values():
        if not raw_path:
            continue
        try:
            path = Path(str(raw_path)).resolve()
        except OSError:
            continue
        if path.parent == handlers_root:
            preserved.add(str(path))

for path in sorted(preserved):
    print(path)
PY
)
    fi

    while IFS= read -r installed_file; do
        base_name="$(basename "$installed_file")"
        resolved_file="$(cd "$(dirname "$installed_file")" && pwd -P)/${base_name}"
        keep_file=0

        case "$base_name" in
            custom_*)
                continue
                ;;
        esac

        for preserved_path in "${preserve_paths[@]}"; do
            if [[ "$resolved_file" == "$preserved_path" ]]; then
                keep_file=1
                break
            fi
        done
        [[ $keep_file -eq 1 ]] && continue

        as_root rm -f "$installed_file"
    done < <(find "$handlers_root" -maxdepth 1 -type f)
}

install_python_support_package() {
    local pkg_root="${AUTO_XDP_PACKAGE_DIR}"
    local files rel target

    cleanup_installed_python_support_package

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        local api_url
        api_url="$(sed \
            -e 's|https://raw\.githubusercontent\.com/|https://api.github.com/repos/|' \
            -e 's|/\([^/]*\)$|/git/trees/\1?recursive=1|' \
            <<< "$RAW_URL")"
        mapfile -t files < <(
            curl -fsSL "$api_url" \
            | python3 -c "
import json, sys
try:
    tree = json.load(sys.stdin).get('tree', [])
except Exception:
    raise SystemExit(1)
for e in tree:
    p = e['path']
    if p.startswith('auto_xdp/') and p.endswith('.py'):
        print(p)
" | sort
        )
        if [[ ${#files[@]} -eq 0 ]]; then
            warn "GitHub API returned no auto_xdp Python files (rate limited or network error); aborting Python package install"
            return 1
        fi
    else
        mapfile -t files < <(find auto_xdp -name "*.py" -type f | sort)
    fi

    for rel in "${files[@]}"; do
        target="${pkg_root}/${rel#auto_xdp/}"
        priv_mkdir "$(dirname "$target")"
        fetch_local_or_remote "$rel" "$rel" "$target" || return 1
    done

    fetch_local_or_remote \
        "auto_xdp/xdp_required_maps.txt" \
        "auto_xdp/xdp_required_maps.txt" \
        "${pkg_root}/xdp_required_maps.txt" || return 1
}

install_runner_script() {
    if ! fetch_local_or_remote "$RUNNER_SRC" "$RUNNER_SRC" "$RUNNER_SCRIPT"; then
        die "Failed to install ${RUNNER_SRC}"
    fi
    as_root chmod +x "$RUNNER_SCRIPT"
}

install_xdp_required_maps() {
    priv_mkdir "$INSTALL_DIR"
    if ! fetch_local_or_remote \
            "auto_xdp/xdp_required_maps.txt" \
            "auto_xdp/xdp_required_maps.txt" \
            "${INSTALL_DIR}/xdp_required_maps.txt"; then
        die "Failed to install auto_xdp/xdp_required_maps.txt"
    fi
}

install_xdp_required_maps_step() {
    step_begin "Installing XDP required maps list"
    install_xdp_required_maps
    step_ok
}

install_runtime_common_script() {
    if ! fetch_local_or_remote "$RUNTIME_COMMON_SRC" "$RUNTIME_COMMON_SRC" "$BPF_RUNTIME_COMMON_INSTALLED"; then
        die "Failed to install ${RUNTIME_COMMON_SRC}"
    fi
    as_root chmod +x "$BPF_RUNTIME_COMMON_INSTALLED"
}

install_sync_script() {
    if ! fetch_local_or_remote "xdp_port_sync.py" "xdp_port_sync.py" "$SYNC_SCRIPT"; then
        die "Failed to install xdp_port_sync.py"
    fi
    as_root chmod +x "$SYNC_SCRIPT"
}

install_relay_script() {
    if ! fetch_local_or_remote "pkt_relay.py" "pkt_relay.py" "$RELAY_SCRIPT"; then
        die "Failed to install pkt_relay.py"
    fi
    as_root chmod +x "$RELAY_SCRIPT"
}

install_bpf_helper() {
    if ! fetch_local_or_remote "$BPF_HELPER_SRC" "$BPF_HELPER_SRC" "$BPF_HELPER_INSTALLED"; then
        die "Failed to install ${BPF_HELPER_SRC}"
    fi
    as_root chmod +x "$BPF_HELPER_INSTALLED"
}

install_axdp_command() {
    if ! fetch_local_or_remote "axdp" "axdp" "$AXDP_CMD"; then
        die "Failed to install axdp"
    fi
    as_root chmod +x "$AXDP_CMD"
}

validate_installed_python_support_package() {
    PYTHONPATH="${PYTHON_LIB_DIR}" "${PYTHON3_BIN:-python3}" - <<'PY'
import sys

try:
    import auto_xdp.tui  # noqa: F401
    from auto_xdp import admin_cli
except Exception as exc:
    raise SystemExit(f"failed to import installed auto_xdp TUI modules: {exc}")

parser = admin_cli.build_parser()
required_options = {"--run-state-dir", "--nft-family", "--nft-table", "--iface"}
missing_options = sorted(required_options - set(parser._option_string_actions))
if missing_options:
    raise SystemExit(
        "installed auto_xdp.admin_cli is missing required wrapper options: "
        + ", ".join(missing_options)
    )
command_action = next(
    (action for action in parser._actions if getattr(action, "dest", None) == "command"),
    None,
)
choices = set(getattr(command_action, "choices", {}) or {})
if "tui" not in choices:
    raise SystemExit("installed auto_xdp.admin_cli does not expose the tui command")
PY
}

install_slot_handler_sdk() {
    local handlers_root="${INSTALL_DIR}/handlers"
    local -a handler_files=()
    local rel=""

    cleanup_installed_handler_sdk

    if [[ -n "${BUILD_STAGING_DIR:-}" && -d "${BUILD_STAGING_DIR}/handlers" ]]; then
        local _staged=()
        mapfile -t -d '' _staged < <(find "${BUILD_STAGING_DIR}/handlers" -maxdepth 1 \
            -type f \( -name 'Makefile' -o -name '*.c' -o -name '*.h' \) -print0)
        if [[ ${#_staged[@]} -gt 0 ]]; then
            local _sf
            for _sf in "${_staged[@]}"; do
                place_file "$_sf" "${handlers_root}/$(basename "$_sf")"
            done
            return 0
        fi
    fi

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        local api_url
        api_url="$(sed \
            -e 's|https://raw\.githubusercontent\.com/|https://api.github.com/repos/|' \
            -e 's|/\([^/]*\)$|/git/trees/\1?recursive=1|' \
            <<< "$RAW_URL")"
        mapfile -t handler_files < <(
            curl -fsSL "$api_url" \
            | python3 -c "
import json, sys
for e in json.load(sys.stdin).get('tree', []):
    p = e['path']
    if not p.startswith('handlers/'):
        continue
    tail = p.split('/')[-1]
    if tail == 'Makefile' or p.endswith('.c') or p.endswith('.h'):
        print(p)
" | sort
        )
    else
        mapfile -t handler_files < <(
            find handlers -maxdepth 1 -type f \
                \( -name 'Makefile' -o -name '*.c' -o -name '*.h' \) \
                | sort
        )
    fi

    if [[ ${#handler_files[@]} -eq 0 ]]; then
        warn "Handler SDK files not found (GitHub API unavailable or repo empty); skipping SDK install"
        return 1
    fi

    for rel in "${handler_files[@]}"; do
        if ! fetch_local_or_remote "$rel" "$rel" "${handlers_root}/${rel#handlers/}"; then
            die "Failed to install ${rel}"
        fi
    done
}

install_toml_config() {
    local toml_target="${CONFIG_DIR}/config.toml"
    priv_mkdir "$CONFIG_DIR"

    if [[ -f "$toml_target" ]]; then
        if ! confirm_yes_no "config.toml already exists at ${toml_target}. Replace with repo default? [y/N] "; then
            return 0
        fi
    fi

    if ! fetch_local_or_remote "config.toml" "config.toml" "$toml_target"; then
        die "Failed to install config.toml"
    fi
}

install_runtime_files() {
    priv_mkdir "$INSTALL_DIR"

    _install_runtime_common_assets() {
        install_runtime_common_script
        write_config
    }

    substep_run "Installing sync daemon" install_sync_script
    substep_run "Installing Python support package" install_python_support_package
    substep_run "Installing relay helper" install_relay_script
    substep_run "Installing BPF helper script" install_bpf_helper
    substep_run "Installing axdp command" install_axdp_command
    substep_run "Validating Python support package" validate_installed_python_support_package
    substep_run "Installing slot handler SDK" install_slot_handler_sdk
    substep_run "Installing shared runtime library" _install_runtime_common_assets
    substep_run "Installing default TOML config" install_toml_config
    substep_run "Installing launcher script" install_runner_script

    unset -f _install_runtime_common_assets
}

install_runtime_files_step() {
    step_begin "Installing runtime files"
    install_runtime_files
    IN_STEP=0; _STEP_NEWLINED=0
}

load_configured_slot_handlers_step() {
    [[ "${ACTIVE_BACKEND:-nftables}" == "xdp" ]] || return 0

    step_begin "Loading configured slot handlers"
    if load_slot_handlers; then
        step_ok
    else
        step_warn "slot handlers unavailable"
    fi
}

load_configured_port_handlers_step() {
    [[ "${ACTIVE_BACKEND:-nftables}" == "xdp" ]] || return 0

    step_begin "Loading configured per-port handlers"
    if load_port_handlers; then
        step_ok
    else
        step_warn "per-port handlers unavailable"
    fi
}

install_systemd_service() {
    write_file "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF_UNIT
[Unit]
Description=Auto XDP Loader + Port Whitelist Auto-Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${RUNNER_SCRIPT}
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF_UNIT

    write_file "/etc/systemd/system/${RELAY_SERVICE_NAME}.service" <<EOF_RELAY_UNIT
[Unit]
Description=Auto XDP packet event relay
After=${SERVICE_NAME}.service
Wants=${SERVICE_NAME}.service

[Service]
Type=simple
Environment=PYTHONPATH=${PYTHON_LIB_DIR}
ExecStart=${RELAY_SCRIPT} --config ${TOML_CONFIG} --pin-path ${BPF_PIN_DIR}/pkt_ringbuf
Restart=on-failure
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF_RELAY_UNIT

    as_root systemctl daemon-reload
    as_root systemctl enable "$SERVICE_NAME"
    as_root systemctl enable "$RELAY_SERVICE_NAME"
    as_root systemctl restart "$SERVICE_NAME"
    as_root systemctl restart "$RELAY_SERVICE_NAME"
}

install_openrc_service() {
    write_file "/etc/init.d/${SERVICE_NAME}" <<EOF_OPENRC
#!/sbin/openrc-run
description="Auto XDP loader + port whitelist auto-sync"
command="${RUNNER_SCRIPT}"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"

depend() {
    need net
}
EOF_OPENRC

    write_file "/etc/init.d/${RELAY_SERVICE_NAME}" <<EOF_RELAY_OPENRC
#!/sbin/openrc-run
description="Auto XDP packet event relay"
command="${RELAY_SCRIPT}"
command_args="--config ${TOML_CONFIG} --pin-path ${BPF_PIN_DIR}/pkt_ringbuf"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"

depend() {
    need net
    after ${SERVICE_NAME}
}
EOF_RELAY_OPENRC

    as_root chmod +x "/etc/init.d/${SERVICE_NAME}"
    as_root chmod +x "/etc/init.d/${RELAY_SERVICE_NAME}"
    as_root rc-update add "$SERVICE_NAME" default >/dev/null 2>&1 || true
    as_root rc-update add "$RELAY_SERVICE_NAME" default >/dev/null 2>&1 || true
    as_root rc-service "$SERVICE_NAME" restart
    as_root rc-service "$RELAY_SERVICE_NAME" restart
}

run_initial_sync() {
    info "Running initial sync..."
    as_root "$RUNNER_SCRIPT" --sync-once
}

run_initial_sync_step() {
    step_begin "Pre-seeding IPv4/IPv6 established TCP sessions"
    run_initial_sync >/dev/null 2>&1 || true
    step_ok
}

install_runtime_service_step() {
    step_begin "Installing and enabling system service"
    case "$INIT_SYSTEM" in
        systemd)
            install_systemd_service
            step_ok "systemd: $SERVICE_NAME"
            ;;
        openrc)
            install_openrc_service
            step_ok "openrc: $SERVICE_NAME"
            ;;
        *)
            step_warn "no init system detected — start manually: $RUNNER_SCRIPT"
            ;;
    esac
}
