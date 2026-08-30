#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
BASE_PATH="${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"
# shellcheck source=tests/bash/testlib.sh
source "$REPO_ROOT/tests/bash/testlib.sh"

test_detect_os_release_maps_supported_families() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)

    local cases=(
        'ubuntu|Ubuntu|debian|debian'
        'fedora|Fedora Linux||rpm'
        'opensuse-leap|openSUSE Leap||suse'
        'arch|Arch Linux||arch'
        'alpine|Alpine Linux||alpine'
    )
    local entry id name like expected

    for entry in "${cases[@]}"; do
        IFS='|' read -r id name like expected <<<"$entry"
        cat >"$tmpdir/os-release" <<EOF_CASE
ID=$id
NAME="$name"
ID_LIKE="$like"
EOF_CASE
        OS_RELEASE_FILE="$tmpdir/os-release"
        DISTRO_ID=""
        DISTRO_NAME=""
        DISTRO_LIKE=""
        DISTRO_FAMILY=""
        detect_os_release
        assert_eq "$DISTRO_FAMILY" "$expected" "$id" || return 1
    done
)

test_detect_pkg_manager_prefers_family_order() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin"
    cat >"$tmpdir/os-release" <<'EOF_OS'
ID=fedora
NAME="Fedora Linux"
EOF_OS

    cat >"$tmpdir/bin/yum" <<'EOF_YUM'
#!/bin/sh
exit 0
EOF_YUM
    cat >"$tmpdir/bin/apt-get" <<'EOF_APT'
#!/bin/sh
exit 0
EOF_APT
    chmod +x "$tmpdir/bin/yum" "$tmpdir/bin/apt-get"

    PATH="$tmpdir/bin"
    OS_RELEASE_FILE="$tmpdir/os-release"
    PKG_MANAGER=""

    detect_pkg_manager || return 1
    assert_eq "$PKG_MANAGER" "yum"
)

test_detect_pkg_manager_fails_when_no_manager_exists() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin"

    PATH="$tmpdir/bin"
    OS_RELEASE_FILE="$tmpdir/missing-os-release"
    PKG_MANAGER=""

    detect_pkg_manager >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1"
)

test_detect_init_system_supports_systemd_and_openrc() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)

    mkdir -p "$tmpdir/bin-systemd" "$tmpdir/run-systemd/system"
    cat >"$tmpdir/bin-systemd/systemctl" <<'EOF_SYSTEMCTL'
#!/bin/sh
exit 0
EOF_SYSTEMCTL
    chmod +x "$tmpdir/bin-systemd/systemctl"

    PATH="$tmpdir/bin-systemd:$BASE_PATH"
    SYSTEMD_RUN_DIR="$tmpdir/run-systemd/system"
    INIT_SYSTEM="none"
    SYSTEMD_AVAILABLE=0
    OPENRC_AVAILABLE=0
    detect_init_system
    assert_eq "$INIT_SYSTEM" "systemd" || return 1
    assert_eq "$SYSTEMD_AVAILABLE" "1" || return 1

    mkdir -p "$tmpdir/bin-openrc"
    cat >"$tmpdir/bin-openrc/rc-service" <<'EOF_RCSERVICE'
#!/bin/sh
exit 0
EOF_RCSERVICE
    cat >"$tmpdir/bin-openrc/rc-update" <<'EOF_RCUPDATE'
#!/bin/sh
exit 0
EOF_RCUPDATE
    chmod +x "$tmpdir/bin-openrc/rc-service" "$tmpdir/bin-openrc/rc-update"

    PATH="$tmpdir/bin-openrc:$BASE_PATH"
    SYSTEMD_RUN_DIR="$tmpdir/missing-systemd"
    INIT_SYSTEM="none"
    SYSTEMD_AVAILABLE=0
    OPENRC_AVAILABLE=0
    detect_init_system
    assert_eq "$INIT_SYSTEM" "openrc" || return 1
    assert_eq "$OPENRC_AVAILABLE" "1"
)

test_package_lists_cover_all_supported_managers() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local managers=(apt-get dnf yum zypper pacman apk)
    local pm packages optional

    for pm in "${managers[@]}"; do
        PKG_MANAGER="$pm"
        packages=$(package_list_for_manager)
        optional=$(optional_package_list_for_manager)
        assert_contains "$packages" "curl" "$pm packages" || return 1
        assert_contains "$packages" "python" "$pm packages" || return 1
        [[ -n "$optional" ]] || {
            printf 'optional package list empty for [%s]\n' "$pm"
            return 1
        }
    done
)

test_dry_run_report_emits_ci_fields() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    detect_pkg_manager() { PKG_MANAGER="apk"; }
    detect_init_system() { INIT_SYSTEM="openrc"; }
    package_list_for_manager() { echo "pkg-a pkg-b"; }
    optional_package_list_for_manager() { echo "pkg-opt"; }
    ip() { echo "default via 192.0.2.1 dev eth9"; }

    DISTRO_ID="alpine"
    DISTRO_NAME="Alpine Linux"
    DISTRO_FAMILY="alpine"
    IFACE=""

    local output
    output=$(dry_run_report)

    assert_contains "$output" "mode=dry-run" || return 1
    assert_contains "$output" "package_manager=apk" || return 1
    assert_contains "$output" "init_system=openrc" || return 1
    assert_contains "$output" "interfaces=eth9" || return 1
    assert_contains "$output" "planned_packages=pkg-a pkg-b" || return 1
    assert_contains "$output" "planned_actions=check-dependencies,compile-xdp,deploy-backend,install-runtime,initial-sync,install-service"
)

test_confirm_yes_no_force_and_no_tty_abort_modes() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    FORCE=1
    confirm_yes_no "force prompt" || return 1

    FORCE=0
    confirm_yes_no "abort prompt" abort >/dev/null 2>&1
    local status=$?
    [[ $status -ne 0 ]] || {
        printf 'expected non-zero status when no confirmation input is available\n'
        return 1
    }
)

test_replace_existing_install_step_replaces_without_prompt() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir log status output
    tmpdir=$(mktemp -d)
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    : >"$CONFIG_FILE"

    confirm_yes_no() { echo "PROMPTED"; return 1; }
    stop_existing_service() { :; }

    log="$tmpdir/output.log"
    set +e
    ( replace_existing_install_step ) >"$log" 2>&1
    status=$?
    set -e
    output=$(<"$log")

    [[ $status -eq 0 ]] || {
        printf 'expected replace_existing_install_step to proceed without prompting\n'
        return 1
    }
    assert_contains "$output" "Replacing existing installation" || return 1
    [[ "$output" != *PROMPTED* ]] || {
        printf 'unexpected confirmation prompt during existing-install replacement\n'
        return 1
    }
)

test_fetch_local_or_remote_uses_local_copy_without_network() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir src dst
    tmpdir=$(mktemp -d)
    src="$tmpdir/local.txt"
    dst="$tmpdir/target.txt"

    printf 'local copy\n' > "$src"

    PREFER_REMOTE_SOURCES=0
    CHECK_UPDATES=0
    fetch_local_or_remote "$src" "remote.txt" "$dst" || return 1

    assert_file_contains "$dst" "local copy"
)

test_local_source_defaults_to_main_ref() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    assert_eq "$AUTO_XDP_SOURCE_REF" "refs/heads/main" || return 1
    assert_eq "$RAW_URL" "https://raw.githubusercontent.com/Kookiejarz/Auto_XDP/refs/heads/main"
)

test_explicit_source_ref_selects_matching_remote_tree() (
    AUTO_XDP_SOURCE_REF="refs/tags/v26.7.7a"
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    assert_eq "$RAW_URL" "https://raw.githubusercontent.com/Kookiejarz/Auto_XDP/refs/tags/v26.7.7a"
)

test_remote_stdin_install_requires_explicit_ref() (
    set +e

    local output status
    output=$(env -u AUTO_XDP_SOURCE_REF -u AUTO_XDP_FORCE_REMOTE \
        bash -s -- --help < "$REPO_ROOT/setup_xdp.sh" 2>&1)
    status=$?

    [[ $status -ne 0 ]] || {
        printf 'expected stdin install without a source ref to fail\n'
        return 1
    }
    assert_contains "$output" "Remote installation requires AUTO_XDP_SOURCE_REF"
)

test_backend_phase_dispatch_preserves_remote_ref_across_sudo() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    PREFER_REMOTE_SOURCES=1
    AUTO_XDP_SOURCE_REF="refs/tags/v26.7.7a"
    PRIV_MODE="sudo"
    IFACES=(eth0)
    FORCE=0

    _resolve_self_path() { printf '%s' "$tmpdir/setup_xdp.sh"; }
    as_root() {
        printf '%s\n' "$*" > "$tmpdir/as-root.log"
        local previous="" arg
        for arg in "$@"; do
            if [[ "$previous" == "--result-file" ]]; then
                printf 'ACTIVE_BACKEND=%q\n' "xdp" > "$arg"
                break
            fi
            previous="$arg"
        done
    }

    run_backend_phase_dispatch || return 1

    assert_file_contains "$tmpdir/as-root.log" "AUTO_XDP_SOURCE_REF=refs/tags/v26.7.7a" || return 1
    assert_file_contains "$tmpdir/as-root.log" "AUTO_XDP_FORCE_REMOTE=1"
)

test_readme_release_install_uses_one_local_archive_tree() (
    local readme
    readme=$(<"$REPO_ROOT/README.md")

    assert_contains "$readme" "Auto_XDP/archive/refs/tags/" || return 1
    assert_contains "$readme" 'cd "$auto_xdp_tmp"' || return 1
    [[ "$readme" != *"raw.githubusercontent.com/Kookiejarz/Auto_XDP/refs/tags/"* ]] || {
        printf 'README still recommends a raw tag entry script\n'
        return 1
    }
)

test_check_github_updates_lists_and_confirms_once() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir remote_root output
    tmpdir=$(mktemp -d)
    remote_root="$tmpdir/remote"
    output=""
    mkdir -p "$tmpdir/bin" "$remote_root"

    cd "$tmpdir" || return 1
    printf 'local axdp\n' >axdp
    printf 'same config\n' >config.toml
    printf 'remote axdp\n' >"$remote_root/axdp"
    printf 'same config\n' >"$remote_root/config.toml"

    cat >"$tmpdir/bin/curl" <<'EOF_CURL'
#!/bin/sh
out=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            out="$2"
            shift 2
            ;;
        -*)
            shift
            ;;
        *)
            url="$1"
            shift
            ;;
    esac
done
rel="${url#https://example.test/}"
cp "${REMOTE_ROOT}/${rel}" "$out"
EOF_CURL
    chmod +x "$tmpdir/bin/curl"

    PATH="$tmpdir/bin:$BASE_PATH"
    RAW_URL="https://example.test"
    REMOTE_ROOT="$remote_root"
    export REMOTE_ROOT
    CHECK_UPDATES=1
    PREFER_REMOTE_SOURCES=0
    FORCE=0
    confirm_yes_no() {
        output="${output}${1}"$'\n'
        return 0
    }

    check_github_updates_once || return 1
    assert_file_contains "$tmpdir/axdp" "remote axdp" || return 1
    assert_file_contains "$tmpdir/config.toml" "same config" || return 1
    assert_contains "$output" "Pull GitHub versions for all listed files? [y/N] " || return 1
    assert_eq "$(printf '%s' "$output" | grep -c 'Pull GitHub versions')" "1" || return 1
    assert_eq "$CHECK_UPDATES" "0"
)

test_write_config_enables_queue_auto_tuning() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_DIR="$tmpdir/etc"
    CONFIG_FILE="$CONFIG_DIR/auto_xdp.env"
    IFACES=(eth0 eth1)
    SYNC_SCRIPT="/tmp/xdp_port_sync.py"
    PYTHON3_BIN="/usr/bin/python3"
    BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
    XDP_OBJ_INSTALLED="/tmp/xdp_firewall.o"
    TC_OBJ_INSTALLED="/tmp/tc_flow_track.o"
    BPF_HELPER_INSTALLED="/tmp/auto_xdp_bpf_helpers.py"
    INSTALL_DIR="/tmp/auto_xdp"
    CURRENT_LINK="/tmp/auto_xdp"
    PYTHON_LIB_DIR="/tmp/auto_xdp/python"

    write_config || return 1

    assert_file_contains "$CONFIG_FILE" 'AUTO_TUNE_QUEUES="1"'
    assert_file_contains "$CONFIG_FILE" 'PYTHON_LIB_DIR="/tmp/auto_xdp/python"'
)

test_auto_tune_interface_parallelism_sets_combined_channels() (
    set +e

    local tmpdir log
    tmpdir=$(mktemp -d)
    log="$tmpdir/ethtool.log"

    export AUTO_XDP_CPU_ONLINE_FILE="$tmpdir/cpu_online"
    printf '0-5\n' > "$AUTO_XDP_CPU_ONLINE_FILE"

    # shellcheck disable=SC1090
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"

    IFACES=(eth0)
    AUTO_TUNE_QUEUES=1

    ethtool() {
        if [[ "$1" == "-l" ]]; then
            cat <<'EOF_ETHTOOL'
Channel parameters for eth0:
Pre-set maximums:
RX:             0
TX:             0
Other:          1
Combined:       4
Current hardware settings:
RX:             0
TX:             0
Other:          1
Combined:       1
EOF_ETHTOOL
            return 0
        fi
        if [[ "$1" == "-L" ]]; then
            printf '%s\n' "$*" > "$log"
            return 0
        fi
        return 1
    }

    auto_tune_interface_parallelism || return 1
    assert_file_contains "$log" "-L eth0 combined 4"
)

test_auto_tune_interface_parallelism_balances_irqs() (
    set +e

    local tmpdir irq
    tmpdir=$(mktemp -d)

    export AUTO_XDP_SYS_CLASS_NET_DIR="$tmpdir/sys/class/net"
    export AUTO_XDP_PROC_IRQ_DIR="$tmpdir/proc/irq"
    export AUTO_XDP_PROC_INTERRUPTS="$tmpdir/proc/interrupts"
    export AUTO_XDP_CPU_ONLINE_FILE="$tmpdir/sys/devices/system/cpu/online"

    mkdir -p "$AUTO_XDP_SYS_CLASS_NET_DIR/eth0/device/msi_irqs"
    mkdir -p "$AUTO_XDP_PROC_IRQ_DIR"
    mkdir -p "$(dirname "$AUTO_XDP_CPU_ONLINE_FILE")"

    printf '0-2\n' > "$AUTO_XDP_CPU_ONLINE_FILE"
    cat > "$AUTO_XDP_PROC_INTERRUPTS" <<'EOF_IRQS'
 32: 10 0 0 0 PCI-MSI  eth0-TxRx-0
 33: 0 10 0 0 PCI-MSI  eth0-TxRx-1
 34: 0 0 10 0 PCI-MSI  eth0-TxRx-2
EOF_IRQS

    for irq in 32 33 34; do
        : > "$AUTO_XDP_SYS_CLASS_NET_DIR/eth0/device/msi_irqs/$irq"
        mkdir -p "$AUTO_XDP_PROC_IRQ_DIR/$irq"
        : > "$AUTO_XDP_PROC_IRQ_DIR/$irq/smp_affinity_list"
    done

    # shellcheck disable=SC1090
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"

    IFACES=(eth0)
    AUTO_TUNE_QUEUES=1
    ethtool() { return 1; }

    auto_tune_interface_parallelism || return 1

    assert_file_contains "$AUTO_XDP_PROC_IRQ_DIR/32/smp_affinity_list" "0" || return 1
    assert_file_contains "$AUTO_XDP_PROC_IRQ_DIR/33/smp_affinity_list" "1" || return 1
    assert_file_contains "$AUTO_XDP_PROC_IRQ_DIR/34/smp_affinity_list" "2"
)

test_bpf_header_exists_checks_multiple_include_roots() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/inc-a/linux" "$tmpdir/inc-b/bpf"
    : >"$tmpdir/inc-a/linux/bpf.h"
    : >"$tmpdir/inc-b/bpf/bpf_helpers.h"

    bpf_header_exists "linux/bpf.h" "$tmpdir/inc-b" "$tmpdir/inc-a" || return 1
    bpf_header_exists "bpf/bpf_helpers.h" "$tmpdir/inc-a" "$tmpdir/inc-b" || return 1

    bpf_header_exists "linux/missing.h" "$tmpdir/inc-a" "$tmpdir/inc-b" >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1"
)

test_warn_from_log_file_prefixes_and_truncates_output() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir log output
    tmpdir=$(mktemp -d)
    log="$tmpdir/handler.log"
    printf 'line one\nline two\nline three\n' >"$log"

    output=$(warn_from_log_file "$log" "handler build: " 2)

    assert_contains "$output" "handler build: line one" || return 1
    assert_contains "$output" "handler build: line two" || return 1
    assert_contains "$output" "handler build: (additional output truncated)"
)

test_prepare_slot_handler_sources_uses_staging_dir() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir fetched
    tmpdir=$(mktemp -d)
    fetched="$tmpdir/fetched.log"
    BUILD_STAGING_DIR="$tmpdir/stage"

    fetch_local_or_remote() {
        printf '%s -> %s\n' "$1" "$3" >>"$fetched"
        mkdir -p "$(dirname "$3")"
        : >"$3"
    }

    cd "$tmpdir" || return 1
    prepare_slot_handler_sources || return 1
    assert_file_contains "$fetched" "handlers/Makefile -> $BUILD_STAGING_DIR/handlers/Makefile" || return 1
    assert_file_contains "$fetched" "handlers/minecraft_handler.c -> $BUILD_STAGING_DIR/handlers/minecraft_handler.c" || return 1
    [[ ! -e "$tmpdir/handlers/Makefile" ]] || {
        printf 'expected handlers/Makefile to stay out of the current working directory\n'
        return 1
    }
)

test_info_prints_within_active_step() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local output
    output=$(
        step_begin "Testing info output"
        info "Preparing runtime files"
        step_ok
    )

    assert_contains "$output" "[INFO]" || return 1
    assert_contains "$output" "Preparing runtime files"
)

test_substep_run_prints_success_and_failure_markers() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local success_output failure_output status

    success_output=$(
        step_begin "Testing substep success"
        substep_run "Installing thing" true
        step_ok
    )
    assert_contains "$success_output" "Installing thing" || return 1
    assert_contains "$success_output" "✓" || return 1

    local failure_log
    failure_log=$(mktemp)
    set +e
    (
        step_begin "Testing substep failure"
        substep_run "Installing broken thing" false
    ) >"$failure_log" 2>&1
    status=$?
    set -e
    failure_output=$(<"$failure_log")
    assert_eq "$status" "1" || return 1
    assert_contains "$failure_output" "Installing broken thing" || return 1
    assert_contains "$failure_output" "✗"
)

test_xdp_maps_ready_requires_all_expected_pins() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir map_name
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir"

    map_name=$(xdp_required_map_names | head -n 1)
    [[ -n "$map_name" ]] || {
        printf 'expected shared XDP map manifest to be readable\n'
        return 1
    }

    touch "$tmpdir/$map_name"

    xdp_maps_ready >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1

    while IFS= read -r map_name; do
        [[ -n "$map_name" ]] || continue
        touch "$tmpdir/$map_name"
    done < <(xdp_required_map_names)

    xdp_maps_ready >/dev/null 2>&1
    status=$?
    assert_eq "$status" "0"
)

test_xdp_required_map_manifest_matches_program_maps() (
    local manifest="$REPO_ROOT/auto_xdp/xdp_required_maps.txt"

    python3 - "$REPO_ROOT" "$manifest" <<'PY'
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
sources = (
    repo_root / "bpf/include/common.h",
    repo_root / "bpf/include/maps.h",
    repo_root / "handlers/xdp_slot_ctx.h",
)

declared = set()
for source in sources:
    text = source.read_text()
    declared.update(re.findall(r"}\s*([A-Za-z_][A-Za-z0-9_]*)\s+SEC\(\"\.maps\"\);", text))
    declared.update(re.findall(r"DEFINE_RATE_OUTER_V[46]\(([A-Za-z_][A-Za-z0-9_]*)\);", text))

manifest = {
    line.split("#", 1)[0].strip()
    for line in manifest_path.read_text().splitlines()
    if line.split("#", 1)[0].strip()
}
manifest.discard("prog")

missing = sorted(declared - manifest)
extra = sorted(manifest - declared)
if missing or extra:
    if missing:
        print("maps missing from xdp_required_maps.txt: " + ", ".join(missing))
    if extra:
        print("unknown maps in xdp_required_maps.txt: " + ", ".join(extra))
    raise SystemExit(1)
PY
)

test_xdp_required_map_fallback_matches_manifest() (
    local tmpdir
    tmpdir=$(mktemp -d)
    cp "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh" "$tmpdir/runtime_common.sh"

    XDP_REQUIRED_MAPS_FILE="$tmpdir/missing"
    AUTO_XDP_PACKAGE_DIR="$tmpdir/missing-package"
    INSTALL_DIR="$tmpdir/missing-install"
    source "$tmpdir/runtime_common.sh"

    diff -u \
        <(sed 's/#.*//; /^[[:space:]]*$/d' "$REPO_ROOT/auto_xdp/xdp_required_maps.txt") \
        <(xdp_required_map_names)
)

test_load_tc_egress_program_reuses_sctp_conntrack_map() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    TC_OBJ_INSTALLED="$tmpdir/tc_flow_track.o"
    IFACE="eth9"
    IFACES=("eth9")
    mkdir -p "$BPF_PIN_DIR" "$tmpdir/bin"
    touch "$TC_OBJ_INSTALLED" \
        "$BPF_PIN_DIR/tcp_ct4" \
        "$BPF_PIN_DIR/tcp_ct6" \
        "$BPF_PIN_DIR/udp_ct4" \
        "$BPF_PIN_DIR/udp_ct6" \
        "$BPF_PIN_DIR/sctp_conntrack"

    cat >"$tmpdir/bin/bpftool" <<EOF_BPFSH
#!/bin/sh
printf '%s\n' "\$*" >> "$tmpdir/bpftool.log"
exit 0
EOF_BPFSH
    cat >"$tmpdir/bin/tc" <<EOF_TCSH
#!/bin/sh
printf '%s\n' "\$*" >> "$tmpdir/tc.log"
exit 0
EOF_TCSH
    chmod +x "$tmpdir/bin/bpftool" "$tmpdir/bin/tc"

    PATH="$tmpdir/bin:$BASE_PATH"
    load_tc_egress_program || return 1

    assert_file_contains "$tmpdir/bpftool.log" "map name sctp_conntrack pinned $BPF_PIN_DIR/sctp_conntrack"
    assert_file_contains "$tmpdir/tc.log" \
        "filter replace dev eth9 egress pref 49152 handle 1 bpf direct-action"
)

test_tc_switch_failure_restores_previous_filter() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    TC_OBJ_INSTALLED="$tmpdir/tc_flow_track.o"
    TC_ROLLBACK_PROG_PATH="$tmpdir/rollback/tc_egress_prog"
    IFACES=("eth0" "eth1")
    mkdir -p "$BPF_PIN_DIR" "$tmpdir/rollback"
    touch "$TC_OBJ_INSTALLED" "$TC_ROLLBACK_PROG_PATH" \
        "$BPF_PIN_DIR/tcp_ct4" "$BPF_PIN_DIR/tcp_ct6" \
        "$BPF_PIN_DIR/udp_ct4" "$BPF_PIN_DIR/udp_ct6" \
        "$BPF_PIN_DIR/sctp_conntrack"

    bpftool() {
        printf 'bpftool %s\n' "$*" >> "$tmpdir/ops.log"
        touch "$BPF_PIN_DIR/tc_egress_prog"
        return 0
    }
    tc() {
        printf 'tc %s\n' "$*" >> "$tmpdir/ops.log"
        case "$*" in
            "filter show dev "*" egress pref "*) printf 'old filter\n'; return 0 ;;
            "filter replace dev eth1 "*"object-pinned $BPF_PIN_DIR/tc_egress_prog") return 1 ;;
        esac
        return 0
    }

    load_tc_egress_program >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    assert_file_contains "$tmpdir/ops.log" \
        "filter replace dev eth0 egress pref 49152 handle 1 bpf direct-action object-pinned $TC_ROLLBACK_PROG_PATH" || return 1
    if grep -q "filter del dev eth0" "$tmpdir/ops.log"; then
        printf 'tc rollback deleted eth0 instead of restoring its previous filter\n'
        return 1
    fi
)

test_tc_rollback_failure_retains_candidate_program() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    TC_OBJ_INSTALLED="$tmpdir/tc_flow_track.o"
    TC_ROLLBACK_PROG_PATH="$tmpdir/rollback/tc_egress_prog"
    IFACES=("eth0" "eth1")
    mkdir -p "$BPF_PIN_DIR" "$tmpdir/rollback"
    touch "$TC_OBJ_INSTALLED" "$TC_ROLLBACK_PROG_PATH" \
        "$BPF_PIN_DIR/tcp_ct4" "$BPF_PIN_DIR/tcp_ct6" \
        "$BPF_PIN_DIR/udp_ct4" "$BPF_PIN_DIR/udp_ct6" \
        "$BPF_PIN_DIR/sctp_conntrack"

    bpftool() { touch "$BPF_PIN_DIR/tc_egress_prog"; return 0; }
    tc() {
        case "$*" in
            "filter show dev "*) printf 'old filter\n'; return 0 ;;
            "filter replace dev eth1 "*"object-pinned $BPF_PIN_DIR/tc_egress_prog") return 1 ;;
            "filter replace dev eth0 "*"object-pinned $TC_ROLLBACK_PROG_PATH") return 1 ;;
        esac
        return 0
    }

    load_tc_egress_program >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    assert_eq "$AUTO_XDP_TC_ROLLBACK_COMPLETE" "0" || return 1
    [[ -e "$BPF_PIN_DIR/tc_egress_prog" ]]
)

test_transaction_retains_candidate_after_incomplete_tc_rollback() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    XDP_OBJ_INSTALLED="$tmpdir/xdp.o"
    IFACES=("eth0")
    mkdir -p "$BPF_PIN_DIR"
    printf 'old\n' > "$BPF_PIN_DIR/prog"
    touch "$XDP_OBJ_INSTALLED"

    _auto_xdp_iface_xdp_mode() { printf 'native'; }
    bpftool() { printf 'new\n' > "${BPF_PIN_DIR}/prog"; return 0; }
    xdp_maps_ready() { return 0; }
    preseed_xdp_candidate_policy() { return 0; }
    preseed_xdp_candidate_handlers() { return 0; }
    _auto_xdp_attach_candidate() { AUTO_XDP_LAST_ATTACH_MODE="native"; return 0; }
    _auto_xdp_verify_iface_program() { return 0; }
    _auto_xdp_attach_mode() { return 0; }
    load_tc_egress_program() {
        AUTO_XDP_TC_ROLLBACK_COMPLETE=0
        return 1
    }

    transactional_reload_xdp >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    assert_eq "$AUTO_XDP_SWITCH_ROLLED_BACK" "0" || return 1
    assert_eq "$(cat "$BPF_PIN_DIR/prog")" "old" || return 1
    assert_eq "$(cat "${BPF_PIN_DIR}_next/prog")" "new"
)

test_xdp_attach_mode_uses_atomic_bpftool_overwrite() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    bpftool() {
        printf '%s\n' "$*" >> "$tmpdir/ops.log"
        return 0
    }

    _auto_xdp_attach_mode eth0 /pins/prog native || return 1
    _auto_xdp_attach_mode eth1 /pins/prog generic || return 1
    _auto_xdp_attach_mode eth2 /pins/prog offload || return 1

    assert_file_contains "$tmpdir/ops.log" \
        "net attach xdpdrv pinned /pins/prog dev eth0 overwrite" || return 1
    assert_file_contains "$tmpdir/ops.log" \
        "net attach xdpgeneric pinned /pins/prog dev eth1 overwrite" || return 1
    assert_file_contains "$tmpdir/ops.log" \
        "net attach xdpoffload pinned /pins/prog dev eth2 overwrite"
)

test_transactional_xdp_validation_failure_keeps_current_generation() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    XDP_OBJ_INSTALLED="$tmpdir/xdp.o"
    IFACES=("eth0")
    mkdir -p "$BPF_PIN_DIR"
    printf 'old\n' > "$BPF_PIN_DIR/prog"
    touch "$XDP_OBJ_INSTALLED"

    _auto_xdp_iface_xdp_mode() { printf 'native'; }
    bpftool() { touch "${BPF_PIN_DIR}/prog"; return 0; }
    xdp_maps_ready() { return 0; }
    preseed_xdp_candidate_policy() { return 1; }
    ip() { printf 'unexpected ip mutation: %s\n' "$*" >> "$tmpdir/ip.log"; return 0; }

    transactional_reload_xdp >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    assert_eq "$(cat "$BPF_PIN_DIR/prog")" "old" || return 1
    [[ ! -e "${BPF_PIN_DIR}_next" ]] || {
        printf 'candidate pins were not cleaned after validation failure\n'
        return 1
    }
    [[ ! -e "$tmpdir/ip.log" ]] || {
        printf 'validation failure mutated an active interface\n'
        return 1
    }
)

test_transactional_handler_failure_keeps_current_generation() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    XDP_OBJ_INSTALLED="$tmpdir/xdp.o"
    IFACES=("eth0")
    mkdir -p "$BPF_PIN_DIR"
    printf 'old\n' > "$BPF_PIN_DIR/prog"
    touch "$XDP_OBJ_INSTALLED"

    _auto_xdp_iface_xdp_mode() { printf 'native'; }
    bpftool() { printf 'new\n' > "${BPF_PIN_DIR}/prog"; return 0; }
    xdp_maps_ready() { return 0; }
    preseed_xdp_candidate_policy() { return 0; }
    preseed_xdp_candidate_handlers() { return 1; }
    _auto_xdp_attach_candidate() {
        printf 'unexpected XDP attach\n' >> "$tmpdir/ops.log"
        return 0
    }

    transactional_reload_xdp >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    assert_eq "$(cat "$BPF_PIN_DIR/prog")" "old" || return 1
    [[ ! -e "${BPF_PIN_DIR}_next" ]] || return 1
    [[ ! -e "$tmpdir/ops.log" ]]
)

test_candidate_preseed_rejects_map_update_failures() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/python/auto_xdp/backends" "$tmpdir/candidate"
    touch "$tmpdir/config.toml" \
        "$tmpdir/python/auto_xdp/__init__.py" \
        "$tmpdir/python/auto_xdp/backends/__init__.py"

    cat > "$tmpdir/python/auto_xdp/config.py" <<'PY'
def apply_toml_config(_config):
    return None

def load_toml_config(_path):
    return {}

def _set_bpf_pin_dir(_path):
    return None
PY
    cat > "$tmpdir/python/auto_xdp/backends/xdp.py" <<'PY'
class XdpBackend:
    def __init__(self):
        self.last_apply_failures = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None
PY
    cat > "$tmpdir/python/auto_xdp/syncer.py" <<'PY'
def sync_once(backend, dry_run):
    assert dry_run is False
    backend.last_apply_failures = 1
PY

    PYTHON_LIB_DIR="$tmpdir/python"
    PYTHON3_BIN="/usr/bin/python3"
    TOML_CONFIG="$tmpdir/config.toml"
    cd "$tmpdir" || return 1
    local output
    output=$(preseed_xdp_candidate_policy "$tmpdir/candidate" 2>&1)
    local status=$?
    [[ $status -ne 0 ]] || {
        printf 'candidate pre-seed accepted a failed map update\n'
        return 1
    }
    assert_contains "$output" "candidate policy pre-seed had 1 BPF map update failure(s)"
)

test_transactional_xdp_attach_failure_restores_switched_interfaces() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    XDP_OBJ_INSTALLED="$tmpdir/xdp.o"
    IFACES=("eth0" "eth1")
    mkdir -p "$BPF_PIN_DIR"
    printf 'old\n' > "$BPF_PIN_DIR/prog"
    touch "$XDP_OBJ_INSTALLED"

    _auto_xdp_iface_xdp_mode() { printf 'native'; }
    bpftool() { printf 'new\n' > "${BPF_PIN_DIR}/prog"; return 0; }
    xdp_maps_ready() { return 0; }
    preseed_xdp_candidate_policy() { return 0; }
    preseed_xdp_candidate_handlers() { return 0; }
    _auto_xdp_attach_candidate() {
        printf 'candidate %s %s\n' "$1" "$2" >> "$tmpdir/ops.log"
        [[ "$1" == "eth0" ]] || return 1
        AUTO_XDP_LAST_ATTACH_MODE="native"
        return 0
    }
    _auto_xdp_verify_iface_program() { return 0; }
    _auto_xdp_detach_mode() {
        printf 'detach %s %s\n' "$1" "$2" >> "$tmpdir/ops.log"
    }
    _auto_xdp_attach_mode() {
        printf 'restore %s %s %s\n' "$1" "$2" "$3" >> "$tmpdir/ops.log"
        return 0
    }
    load_tc_egress_program() {
        printf 'unexpected tc switch\n' >> "$tmpdir/ops.log"
        return 0
    }

    transactional_reload_xdp >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    assert_eq "$AUTO_XDP_SWITCH_ROLLED_BACK" "1" || return 1
    assert_eq "$(cat "$BPF_PIN_DIR/prog")" "old" || return 1
    assert_file_contains "$tmpdir/ops.log" \
        "restore eth0 ${BPF_PIN_DIR}/prog native" || return 1
    if grep -q "detach eth0 native" "$tmpdir/ops.log"; then
        printf 'same-mode rollback detached XDP before restoring the previous program\n'
        return 1
    fi
    if grep -q "unexpected tc switch" "$tmpdir/ops.log"; then
        printf 'tc switch ran after XDP attach failure\n'
        return 1
    fi
)

test_transactional_tc_failure_restores_xdp_generation() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    XDP_OBJ_INSTALLED="$tmpdir/xdp.o"
    IFACES=("eth0")
    mkdir -p "$BPF_PIN_DIR"
    printf 'old\n' > "$BPF_PIN_DIR/prog"
    touch "$XDP_OBJ_INSTALLED"

    _auto_xdp_iface_xdp_mode() { printf 'native'; }
    bpftool() { printf 'new\n' > "${BPF_PIN_DIR}/prog"; return 0; }
    xdp_maps_ready() { return 0; }
    preseed_xdp_candidate_policy() { return 0; }
    preseed_xdp_candidate_handlers() { return 0; }
    _auto_xdp_attach_candidate() {
        printf 'candidate %s %s\n' "$1" "$2" >> "$tmpdir/ops.log"
        AUTO_XDP_LAST_ATTACH_MODE="native"
        return 0
    }
    _auto_xdp_verify_iface_program() { return 0; }
    _auto_xdp_detach_mode() {
        printf 'detach %s %s\n' "$1" "$2" >> "$tmpdir/ops.log"
    }
    _auto_xdp_attach_mode() {
        printf 'restore %s %s %s\n' "$1" "$2" "$3" >> "$tmpdir/ops.log"
        return 0
    }
    load_tc_egress_program() {
        printf 'tc failed\n' >> "$tmpdir/ops.log"
        return 1
    }

    transactional_reload_xdp >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    assert_eq "$AUTO_XDP_SWITCH_ROLLED_BACK" "1" || return 1
    assert_eq "$(cat "$BPF_PIN_DIR/prog")" "old" || return 1
    assert_file_contains "$tmpdir/ops.log" "tc failed" || return 1
    assert_file_contains "$tmpdir/ops.log" \
        "restore eth0 ${BPF_PIN_DIR}/prog native" || return 1
    if grep -q "detach eth0 native" "$tmpdir/ops.log"; then
        printf 'tc failure rollback detached XDP before restoring the previous program\n'
        return 1
    fi
)

test_transactional_xdp_success_commits_candidate_generation() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    XDP_OBJ_INSTALLED="$tmpdir/xdp.o"
    IFACES=("eth0")
    mkdir -p "$BPF_PIN_DIR"
    printf 'old\n' > "$BPF_PIN_DIR/prog"
    touch "$XDP_OBJ_INSTALLED"

    _auto_xdp_iface_xdp_mode() { printf 'native'; }
    bpftool() { printf 'new\n' > "${BPF_PIN_DIR}/prog"; return 0; }
    xdp_maps_ready() { return 0; }
    preseed_xdp_candidate_policy() { return 0; }
    preseed_xdp_candidate_handlers() { return 0; }
    _auto_xdp_attach_candidate() { AUTO_XDP_LAST_ATTACH_MODE="native"; return 0; }
    _auto_xdp_verify_iface_program() { return 0; }
    _auto_xdp_record_xdp_state() { return 0; }
    load_tc_egress_program() { return 0; }

    transactional_reload_xdp >/dev/null 2>&1 || return 1
    assert_eq "$(cat "$BPF_PIN_DIR/prog")" "new" || return 1
    assert_eq "$AUTO_XDP_SWITCH_MODE" "native" || return 1
    [[ ! -e "${BPF_PIN_DIR}_rollback" ]] || {
        printf 'rollback generation remained after successful commit\n'
        return 1
    }
)

test_interrupted_xdp_reload_resumes_candidate_generation() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    IFACES=("eth0" "eth1")
    mkdir -p "$BPF_PIN_DIR" "${BPF_PIN_DIR}_next"
    printf 'old\n' > "$BPF_PIN_DIR/prog"
    printf 'new\n' > "${BPF_PIN_DIR}_next/prog"

    preseed_xdp_candidate_handlers() { return 0; }
    _auto_xdp_attach_candidate() {
        printf 'candidate %s %s\n' "$1" "$2" >> "$tmpdir/ops.log"
        AUTO_XDP_LAST_ATTACH_MODE="native"
        return 0
    }
    _auto_xdp_verify_iface_program() { return 0; }
    _auto_xdp_record_xdp_state() { return 0; }
    load_tc_egress_program() {
        printf 'tc %s %s\n' "$BPF_PIN_DIR" "$TC_ROLLBACK_PROG_PATH" >> "$tmpdir/ops.log"
        return 0
    }

    _auto_xdp_finish_interrupted_reload >/dev/null 2>&1 || return 1
    assert_eq "$(cat "$BPF_PIN_DIR/prog")" "new" || return 1
    assert_eq "$AUTO_XDP_RECOVERY_HANDLED" "1" || return 1
    assert_file_contains "$tmpdir/ops.log" "candidate eth0 ${BPF_PIN_DIR}_next/prog" || return 1
    assert_file_contains "$tmpdir/ops.log" "candidate eth1 ${BPF_PIN_DIR}_next/prog" || return 1
    assert_file_contains "$tmpdir/ops.log" "tc ${BPF_PIN_DIR}_next ${BPF_PIN_DIR}/tc_egress_prog" || return 1
    [[ ! -e "${BPF_PIN_DIR}_next" && ! -e "${BPF_PIN_DIR}_rollback" ]]
)

test_resolve_target_interfaces_uses_default_route_interface() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    ALL_IFACES=0
    IFACE=""
    IFACES=()
    # Keep a real installed auto_xdp.env from feeding saved interfaces in.
    CONFIG_FILE="/nonexistent/auto_xdp.env"

    ip() {
        case "$*" in
            "route show default")
                echo "default via 192.0.2.1 dev eth9"
                ;;
            "link show eth9")
                return 0
                ;;
            *)
                return 1
                ;;
        esac
    }

    resolve_target_interfaces >/dev/null || return 1
    assert_eq "$IFACE" "eth9" || return 1
    assert_eq "${IFACES[*]}" "eth9"
)

test_resolve_target_interfaces_reuses_installed_env_ifaces() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    printf 'IFACES="eth7 eth8"\nIFACE="eth7"\n' >"$CONFIG_FILE"

    ALL_IFACES=0
    IFACES=()
    IFACE=""

    ip() {
        case "$*" in
            "link show eth7"|"link show eth8") return 0 ;;
            *) return 1 ;;
        esac
    }

    resolve_target_interfaces || return 1
    assert_eq "${IFACES[*]}" "eth7 eth8" || return 1
    assert_eq "$IFACE_SOURCE" "existing install"
)

test_resolve_target_interfaces_drops_missing_saved_ifaces() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    printf 'IFACES="eth7 gone0"\n' >"$CONFIG_FILE"

    ALL_IFACES=0
    IFACES=()
    IFACE=""

    ip() {
        case "$*" in
            "link show eth7") return 0 ;;
            *) return 1 ;;
        esac
    }

    resolve_target_interfaces || return 1
    assert_eq "${IFACES[*]}" "eth7" || return 1
    assert_contains "$IFACE_SOURCE" "dropped missing: gone0"
)

test_resolve_target_interfaces_detects_when_saved_ifaces_all_gone() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    printf 'IFACES="gone0 gone1"\n' >"$CONFIG_FILE"

    ALL_IFACES=0
    IFACES=()
    IFACE=""

    ip() {
        case "$*" in
            "route show default") echo "default via 192.0.2.1 dev eth9" ;;
            "link show eth9") return 0 ;;
            *) return 1 ;;
        esac
    }

    resolve_target_interfaces || return 1
    assert_eq "${IFACES[*]}" "eth9" || return 1
    assert_eq "$IFACE_SOURCE" "default route auto-detect"
)

test_install_toml_config_preserves_existing_local_config() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_DIR="$tmpdir/etc"
    mkdir -p "$CONFIG_DIR"
    printf 'user_setting = 1\n' >"$CONFIG_DIR/config.toml"

    FORCE=1
    fetch_local_or_remote() { printf 'repo_default = 1\n' >"$3"; }

    install_toml_config >/dev/null || return 1
    assert_file_contains "$CONFIG_DIR/config.toml" "user_setting = 1" || return 1
    ! grep -q 'repo_default' "$CONFIG_DIR/config.toml" || return 1
    local backup
    backup=$(find "$CONFIG_DIR/backups" -type f -name 'config.toml.*' | head -n 1)
    [[ -n "$backup" ]] || return 1
    assert_file_contains "$backup" "user_setting = 1"
)

test_check_required_tools_step_only_requires_runtime_commands() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin"

    local cmd
    for cmd in python3 curl ip tc nft; do
        cat >"$tmpdir/bin/$cmd" <<'EOF_CMD'
#!/bin/sh
exit 0
EOF_CMD
        chmod +x "$tmpdir/bin/$cmd"
    done

    PATH="$tmpdir/bin"
    PKG_MANAGER="apk"
    PYTHON3_BIN=""

    install_packages() { :; }
    ensure_psutil() { :; }

    check_required_tools_step >/dev/null || return 1
    assert_eq "$PYTHON3_BIN" "$tmpdir/bin/python3"
)

test_deploy_backend_step_falls_back_to_nftables() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    IFACES=("eth9")
    ACTIVE_BACKEND="xdp"
    ACTIVE_XDP_MODE="native"

    deploy_xdp_backend() { return 1; }
    ensure_nftables_available() { return 0; }

    deploy_backend_step >/dev/null || return 1
    assert_eq "$ACTIVE_BACKEND" "nftables" || return 1
    assert_eq "$ACTIVE_XDP_MODE" "none"
)

test_deploy_backend_step_refuses_fallback_with_active_xdp() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    XDP_FALLBACK_BLOCKED=0
    deploy_xdp_backend() {
        XDP_FALLBACK_BLOCKED=1
        return 1
    }
    ensure_nftables_available() {
        printf 'unexpected nftables fallback\n'
        return 0
    }

    deploy_backend_step >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1
    assert_eq "$XDP_FALLBACK_BLOCKED" "1"
)

test_deploy_xdp_removes_tc_filter_from_removed_interface() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    XDP_OBJ_INSTALLED="$tmpdir/xdp.o"
    touch "$XDP_OBJ_INSTALLED"
    IFACES=("eth0")

    ensure_bpffs() { return 0; }
    cleanup_existing_xdp() { XDP_PREVIOUS_IFACES=("eth0" "old0"); }
    transactional_reload_xdp() { AUTO_XDP_SWITCH_MODE="native"; return 0; }
    load_sock_state_tracker() { return 0; }
    auto_tune_interface_parallelism() { return 0; }
    ip() { printf 'ip %s\n' "$*" >> "$tmpdir/ops.log"; return 0; }
    tc() { printf 'tc %s\n' "$*" >> "$tmpdir/ops.log"; return 0; }

    deploy_xdp_backend >/dev/null 2>&1 || return 1
    assert_file_contains "$tmpdir/ops.log" \
        "tc filter del dev old0 egress pref 49152 handle 1" || return 1
    if grep -q "tc filter del dev eth0" "$tmpdir/ops.log"; then
        printf 'tc filter was removed from an active target interface\n'
        return 1
    fi
)

test_install_runtime_service_step_warns_without_init_system() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    INIT_SYSTEM="none"
    RUNNER_SCRIPT="/tmp/auto_xdp_start.sh"

    local output
    output=$(install_runtime_service_step)
    assert_contains "$output" "start manually: $RUNNER_SCRIPT"
)

test_load_configured_slot_handlers_step_only_runs_for_xdp() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local called=0
    load_slot_handlers() { called=$((called + 1)); }

    ACTIVE_BACKEND="nftables"
    load_configured_slot_handlers_step >/dev/null || return 1
    assert_eq "$called" "0" || return 1

    ACTIVE_BACKEND="xdp"
    load_configured_slot_handlers_step >/dev/null || return 1
    assert_eq "$called" "1"
)

test_cleanup_build_artifacts_step_preserves_local_sources() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)

    XDP_OBJ="$tmpdir/xdp_firewall.o"
    TC_OBJ="$tmpdir/tc_flow_track.o"
    XDP_SRC="$tmpdir/xdp_firewall.c"
    TC_SRC="$tmpdir/tc_flow_track.c"
    BPF_HELPER_SRC="$tmpdir/auto_xdp_bpf_helpers.py"
    BPF_HELPER_BOOTSTRAP="$tmpdir/bootstrap-helper.py"
    PREFER_REMOTE_SOURCES=0

    : >"$XDP_OBJ"
    : >"$TC_OBJ"
    : >"$XDP_SRC"
    : >"$TC_SRC"
    : >"$BPF_HELPER_SRC"
    : >"$BPF_HELPER_BOOTSTRAP"

    cleanup_build_artifacts_step >/dev/null || return 1

    [[ ! -f "$XDP_OBJ" && ! -f "$TC_OBJ" && ! -f "$BPF_HELPER_BOOTSTRAP" ]] || {
        printf 'expected objects and bootstrap helper to be removed\n'
        return 1
    }
    [[ -f "$XDP_SRC" && -f "$TC_SRC" && -f "$BPF_HELPER_SRC" ]] || {
        printf 'expected local source files to be preserved\n'
        return 1
    }
)

test_restore_compiled_slot_handlers_reinstalls_builtin_objects() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BUILD_STAGING_DIR="$tmpdir/stage"
    INSTALL_DIR="$tmpdir/install"

    mkdir -p "$BUILD_STAGING_DIR/handlers" "$INSTALL_DIR/handlers"
    printf 'gre' >"$BUILD_STAGING_DIR/handlers/gre_handler.o"
    printf 'esp' >"$BUILD_STAGING_DIR/handlers/esp_handler.o"

    restore_compiled_slot_handlers >/dev/null || return 1

    [[ -s "$INSTALL_DIR/handlers/gre_handler.o" ]] || {
        printf 'expected gre handler object to be restored after SDK install\n'
        return 1
    }
    [[ -s "$INSTALL_DIR/handlers/esp_handler.o" ]] || {
        printf 'expected esp handler object to be restored after SDK install\n'
        return 1
    }
)

test_install_python_support_package_includes_state_module() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir fetched
    tmpdir=$(mktemp -d)
    AUTO_XDP_PACKAGE_DIR="$tmpdir/auto_xdp"
    fetched="$tmpdir/fetched.log"

    fetch_local_or_remote() {
        printf '%s -> %s\n' "$1" "$3" >>"$fetched"
        mkdir -p "$(dirname "$3")"
        : >"$3"
    }

    install_python_support_package || return 1
    assert_file_contains "$fetched" "auto_xdp/state.py -> ${AUTO_XDP_PACKAGE_DIR}/state.py"
    assert_file_contains "$fetched" "auto_xdp/xdp_required_maps.txt -> ${AUTO_XDP_PACKAGE_DIR}/xdp_required_maps.txt"
)

test_install_python_support_package_removes_stale_files() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir fetched
    tmpdir=$(mktemp -d)
    AUTO_XDP_PACKAGE_DIR="$tmpdir/auto_xdp"
    fetched="$tmpdir/fetched.log"

    mkdir -p "$AUTO_XDP_PACKAGE_DIR/obsolete"
    : >"$AUTO_XDP_PACKAGE_DIR/stale.py"
    : >"$AUTO_XDP_PACKAGE_DIR/obsolete/old.txt"

    fetch_local_or_remote() {
        printf '%s -> %s\n' "$1" "$3" >>"$fetched"
        mkdir -p "$(dirname "$3")"
        printf 'fresh\n' >"$3"
    }

    install_python_support_package || return 1
    [[ ! -e "$AUTO_XDP_PACKAGE_DIR/stale.py" ]] || {
        printf 'expected stale package file to be removed\n'
        return 1
    }
    [[ ! -e "$AUTO_XDP_PACKAGE_DIR/obsolete/old.txt" ]] || {
        printf 'expected stale package subdirectory to be removed\n'
        return 1
    }
    assert_file_contains "$AUTO_XDP_PACKAGE_DIR/state.py" "fresh"
)

test_install_slot_handler_sdk_cleans_stale_files_and_preserves_configured_custom_handlers() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir fetched
    tmpdir=$(mktemp -d)
    INSTALL_DIR="$tmpdir/install"
    CONFIG_DIR="$tmpdir/etc"
    PYTHON3_BIN="${PYTHON3_BIN:-python3}"
    fetched="$tmpdir/fetched.log"

    mkdir -p "$INSTALL_DIR/handlers" "$CONFIG_DIR"
    cat >"$CONFIG_DIR/config.toml" <<EOF_CFG
[slots]
enabled = [{ proto = 99, path = "${INSTALL_DIR}/handlers/custom_99_keep.o" }]

[port_handlers.tcp]
"25565" = "${INSTALL_DIR}/handlers/minecraft_handler.o"
EOF_CFG

    : >"$INSTALL_DIR/handlers/gre_handler.o"
    : >"$INSTALL_DIR/handlers/old_removed_handler.o"
    : >"$INSTALL_DIR/handlers/custom_99_keep.o"
    : >"$INSTALL_DIR/handlers/minecraft_handler.o"
    : >"$INSTALL_DIR/handlers/xdp_slot_ctx.h"
    : >"$INSTALL_DIR/handlers/Makefile"

    fetch_local_or_remote() {
        printf '%s -> %s\n' "$1" "$3" >>"$fetched"
        mkdir -p "$(dirname "$3")"
        printf 'sdk\n' >"$3"
    }

    install_slot_handler_sdk || return 1
    [[ ! -e "$INSTALL_DIR/handlers/gre_handler.o" ]] || {
        printf 'expected old built-in handler object to be removed\n'
        return 1
    }
    [[ ! -e "$INSTALL_DIR/handlers/old_removed_handler.o" ]] || {
        printf 'expected stale unconfigured handler object to be removed\n'
        return 1
    }
    [[ -e "$INSTALL_DIR/handlers/custom_99_keep.o" ]] || {
        printf 'expected configured custom slot handler to be preserved\n'
        return 1
    }
    [[ -e "$INSTALL_DIR/handlers/minecraft_handler.o" ]] || {
        printf 'expected configured custom port handler to be preserved\n'
        return 1
    }
    assert_file_contains "$INSTALL_DIR/handlers/Makefile" "sdk"
)

# Write a fake sudo onto PATH that logs its invocation and then runs the wrapped
# command, so escalation can be observed without real privileges.
_install_fake_sudo() {
    local bindir="$1" log="$2"
    mkdir -p "$bindir"
    cat >"$bindir/sudo" <<EOF_SUDO
#!/bin/sh
echo "sudo \$*" >> "$log"
case "\$1" in
    -v|-n) exit 0 ;;
esac
exec "\$@"
EOF_SUDO
    chmod +x "$bindir/sudo"
}

test_detect_privilege_mode_uses_sudo_when_not_root() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    # EUID is read-only in bash; sudo-mode selection is untestable as root.
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        return 0
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    _install_fake_sudo "$tmpdir/bin" "$tmpdir/sudo.log"

    PRIV_MODE="unset"
    PATH="$tmpdir/bin:$BASE_PATH"
    detect_privilege_mode >/dev/null 2>&1 || return 1
    assert_eq "$PRIV_MODE" "sudo"
)

test_detect_privilege_mode_fails_without_root_or_sudo() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    # EUID is read-only in bash; the no-root-no-sudo case is untestable as root.
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        return 0
    fi

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin"

    # die exits the shell, so isolate detect_privilege_mode in a nested subshell.
    ( PATH="$tmpdir/bin"; detect_privilege_mode ) >/dev/null 2>&1
    assert_eq "$?" "1"
)

test_as_root_runs_directly_when_root() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    _install_fake_sudo "$tmpdir/bin" "$tmpdir/sudo.log"

    PRIV_MODE="root"
    PATH="$tmpdir/bin:$BASE_PATH"
    as_root touch "$tmpdir/marker" || return 1
    [[ -f "$tmpdir/marker" ]] || { printf 'command did not run\n'; return 1; }
    [[ ! -f "$tmpdir/sudo.log" ]] || { printf 'sudo was used in root mode\n'; return 1; }
)

test_as_root_escalates_in_sudo_mode() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    _install_fake_sudo "$tmpdir/bin" "$tmpdir/sudo.log"

    PRIV_MODE="sudo"
    PATH="$tmpdir/bin:$BASE_PATH"
    as_root touch "$tmpdir/marker" || return 1
    [[ -f "$tmpdir/marker" ]] || { printf 'command did not run\n'; return 1; }
    assert_file_contains "$tmpdir/sudo.log" "sudo touch"
)

test_can_write_path_detects_unwritable_destinations() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    # Root writes through chmod 000; the unwritable case is untestable as root.
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        return 0
    fi

    local tmpdir
    tmpdir=$(mktemp -d)

    # Writable directory -> new file is creatable without escalation.
    _can_write_path "$tmpdir/new" || { printf 'expected writable\n'; return 1; }

    # Unwritable parent -> escalation required.
    local locked="$tmpdir/locked"
    mkdir -p "$locked"
    chmod 000 "$locked"
    local rc=0
    _can_write_path "$locked/file" || rc=$?
    chmod 700 "$locked"
    assert_eq "$rc" "1" "unwritable parent"
)

test_write_file_writes_content_without_escalation() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    _install_fake_sudo "$tmpdir/bin" "$tmpdir/sudo.log"

    PRIV_MODE="sudo"
    PATH="$tmpdir/bin:$BASE_PATH"
    printf 'hello\n' | write_file "$tmpdir/nested/out.txt" || return 1
    assert_file_contains "$tmpdir/nested/out.txt" "hello" || return 1
    [[ ! -f "$tmpdir/sudo.log" ]] || { printf 'unexpected escalation for writable dest\n'; return 1; }
)

test_priv_init_is_noop_when_root() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    _install_fake_sudo "$tmpdir/bin" "$tmpdir/sudo.log"

    PRIV_MODE="root"
    PRIV_PRIMED=0
    PATH="$tmpdir/bin:$BASE_PATH"
    priv_init || return 1
    [[ ! -f "$tmpdir/sudo.log" ]] || { printf 'sudo invoked while root\n'; return 1; }
)

test_priv_init_primes_sudo_once() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    _install_fake_sudo "$tmpdir/bin" "$tmpdir/sudo.log"

    PRIV_MODE="sudo"
    PRIV_PRIMED=0
    PATH="$tmpdir/bin:$BASE_PATH"
    priv_init || return 1
    _stop_priv_keepalive
    assert_eq "$PRIV_PRIMED" "1" || return 1
    assert_file_contains "$tmpdir/sudo.log" "sudo -v"
)

test_parse_args_accepts_internal_phase2_flags() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    INTERNAL_PHASE2=0
    RESULT_FILE=""
    IFACES=()
    parse_args --internal-phase2 --result-file /tmp/result.env eth0 || return 1
    assert_eq "$INTERNAL_PHASE2" "1" || return 1
    assert_eq "$RESULT_FILE" "/tmp/result.env" || return 1
    assert_eq "${IFACES[0]}" "eth0"
)

test_emit_backend_results_roundtrips_state() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)

    ACTIVE_BACKEND="nftables"
    ACTIVE_XDP_MODE="none"
    XDP_FALLBACK_REASON="XDP attach failed on all target interfaces"
    _emit_backend_results "$tmpdir/result.env" || return 1

    ACTIVE_BACKEND=""
    ACTIVE_XDP_MODE=""
    XDP_FALLBACK_REASON=""
    # shellcheck disable=SC1090
    source "$tmpdir/result.env"
    assert_eq "$ACTIVE_BACKEND" "nftables" || return 1
    assert_eq "$XDP_FALLBACK_REASON" "XDP attach failed on all target interfaces"
)

test_backend_phase_dispatch_runs_inline_when_root() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)

    PRIV_MODE="root"
    run_backend_phase() { touch "$tmpdir/backend_ran"; }
    run_backend_phase_dispatch || return 1
    [[ -f "$tmpdir/backend_ran" ]] || { printf 'backend phase did not run inline\n'; return 1; }
)

test_package_list_gates_gcc_multilib_by_arch() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    PKG_MANAGER="apt-get"

    uname() { echo "x86_64"; }
    local x86_list
    x86_list=$(package_list_for_manager)

    uname() { echo "aarch64"; }
    local arm_list
    arm_list=$(package_list_for_manager)

    assert_contains "$x86_list" "gcc-multilib" || return 1
    [[ "$arm_list" != *gcc-multilib* ]] || {
        printf 'gcc-multilib must not be requested on non-x86_64 (apt aborts the whole transaction)\n'
        return 1
    }
    assert_contains "$arm_list" "build-essential"
)

test_install_packages_propagates_required_install_failure() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    PKG_MANAGER="apt-get"
    package_list_for_manager() { echo "pkg-a pkg-b"; }
    optional_package_list_for_manager() { echo "pkg-opt"; }
    pkg_update() { :; }
    pkg_install() { return 100; }
    pkg_install_optional() { printf 'optional install must not run after required failure\n'; return 0; }

    install_packages >/dev/null 2>&1
    assert_eq "$?" "1"
)

test_install_packages_succeeds_on_non_apt_managers() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    package_list_for_manager() { echo "pkg-a"; }
    optional_package_list_for_manager() { echo "pkg-opt"; }
    pkg_update() { :; }
    pkg_install() { :; }
    pkg_install_optional() { :; }

    local mgr
    for mgr in dnf zypper pacman apk; do
        PKG_MANAGER="$mgr"
        install_packages >/dev/null 2>&1 || {
            printf 'install_packages must return 0 on %s when installs succeed\n' "$mgr"
            return 1
        }
    done
)

test_check_required_tools_step_dies_when_install_fails() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir log status output cmd
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin"
    for cmd in clang python3 curl ip tc nft; do
        printf '#!/bin/sh\nexit 0\n' >"$tmpdir/bin/$cmd"
        chmod +x "$tmpdir/bin/$cmd"
    done

    PKG_MANAGER="apk"
    install_packages() { return 1; }

    log="$tmpdir/out.log"
    ( PATH="$tmpdir/bin"; check_required_tools_step ) >"$log" 2>&1
    status=$?
    output=$(<"$log")

    [[ $status -ne 0 ]] || {
        printf 'expected check_required_tools_step to die when package install fails\n'
        return 1
    }
    assert_contains "$output" "bpftool" || return 1
    assert_contains "$output" "Package installation failed."
)

test_check_required_tools_step_rechecks_missing_tools() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir output cmd
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin" "$tmpdir/extra"
    for cmd in clang bpftool python3 curl ip tc; do
        printf '#!/bin/sh\nexit 0\n' >"$tmpdir/bin/$cmd"
        chmod +x "$tmpdir/bin/$cmd"
    done
    printf '#!/bin/sh\nexit 0\n' >"$tmpdir/extra/nft"
    chmod +x "$tmpdir/extra/nft"

    PKG_MANAGER="apk"
    EXTRA_BIN="$tmpdir/extra"
    install_packages() { PATH="$PATH:$EXTRA_BIN"; }
    ensure_psutil() { :; }

    output=$( PATH="$tmpdir/bin"; check_required_tools_step 2>&1 ) || return 1
    assert_contains "$output" "nft (after install)"
)

test_replace_existing_install_step_reports_fresh_install() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    existing_install_detected() { return 1; }
    stop_existing_service() { :; }

    local output
    output=$(replace_existing_install_step 2>&1) || return 1
    assert_contains "$output" "Checking existing installation" || return 1
    assert_contains "$output" "none found"
)

test_print_basic_info_renders_required_fields() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    PRIV_MODE="root"
    DISTRO_NAME="TestOS"
    DISTRO_FAMILY="debian"
    PKG_MANAGER="apt-get"
    INIT_SYSTEM="systemd"
    IFACES=(eth9)

    local output
    EXISTING_INSTALL=1
    output=$(print_basic_info)
    assert_contains "$output" "TestOS" || return 1
    assert_contains "$output" "eth9" || return 1
    assert_contains "$output" "privilege      : root" || return 1
    assert_contains "$output" "runtime files will be replaced" || return 1

    EXISTING_INSTALL=0
    output=$(print_basic_info)
    assert_contains "$output" "none (fresh install)"
)

# Anti-drift: the hardcoded header list used by curl|bash installs must cover
# every header in bpf/include/, or remote installs silently compile without
# newly added headers.
test_remote_bpf_header_list_matches_repo_headers() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local listed hdr base
    listed=$(grep -o '_bpf_headers=([^)]*)' "$REPO_ROOT/lib/setup/build.sh" \
        | sed 's/_bpf_headers=(//; s/)//')
    [[ -n "$listed" ]] || {
        printf '_bpf_headers list not found in lib/setup/build.sh\n'
        return 1
    }

    for hdr in "$REPO_ROOT"/bpf/include/*.h; do
        base=$(basename "$hdr")
        [[ " $listed " == *" $base "* || "$listed" == "$base "* || "$listed" == *" $base" || "$listed" == "$base" ]] || {
            printf 'bpf/include/%s missing from _bpf_headers curl|bash list in lib/setup/build.sh\n' "$base"
            return 1
        }
    done
)

# Anti-drift: --check-update must keep covering every installed source tree;
# a rename or new directory outside these globs would silently skip updates.
test_check_update_candidates_cover_installed_sources() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    cd "$REPO_ROOT" || return 1
    local list f
    list=$(_check_update_candidate_files)
    for f in \
        setup_xdp.sh \
        axdp \
        config.toml \
        xdp_port_sync.py \
        pkt_relay.py \
        auto_xdp_bpf_helpers.py \
        tc_flow_track.c \
        lib/setup/install.sh \
        lib/setup/packages.sh \
        runtime/auto_xdp_start.sh \
        runtime/auto_xdp_runtime_common.sh \
        bpf/xdp_firewall.c \
        bpf/include/maps.h \
        handlers/Makefile \
        auto_xdp/admin/main.py \
        auto_xdp/backends/xdp.py \
        auto_xdp/bpf/maps.py \
        auto_xdp/xdp_required_maps.txt; do
        [[ "$list" == *"$f"* ]] || {
            printf '%s missing from check-update candidate files\n' "$f"
            return 1
        }
    done
)

# Anti-drift: installer output contract — basic info first, per-item checks and
# install steps in the middle, LOGO + deployment summary last.
test_main_orders_basic_info_checks_then_summary() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local body prefix
    body=$(declare -f main)

    [[ "$body" != *print_installer_banner* ]] || {
        printf 'main must not print the old banner box\n'
        return 1
    }

    local -a ordered=(
        detect_privilege_mode
        detect_environment
        priv_init
        acquire_install_lock_step
        recover_interrupted_install_step
        check_required_tools_step
        resolve_target_interfaces
        existing_install_detected
        print_basic_info
        compile_bpf_objects_step
        stage_runtime_release_step
        replace_existing_install_step
        begin_install_transaction_step
        activate_candidate_release_step
        run_backend_phase_dispatch
        commit_install_transaction_step
        print_deployment_summary
    )
    local prev_pos=-1 name pos
    for name in "${ordered[@]}"; do
        prefix=${body%%"$name"*}
        pos=${#prefix}
        [[ $pos -lt ${#body} ]] || {
            printf 'main no longer calls %s\n' "$name"
            return 1
        }
        [[ $pos -gt $prev_pos ]] || {
            printf 'main calls %s out of order\n' "$name"
            return 1
        }
        prev_pos=$pos
    done
)

run_test "setup_xdp detects distro families" test_detect_os_release_maps_supported_families
run_test "setup_xdp prefers distro package-manager order" test_detect_pkg_manager_prefers_family_order
run_test "setup_xdp reports missing package managers" test_detect_pkg_manager_fails_when_no_manager_exists
run_test "setup_xdp detects systemd and openrc" test_detect_init_system_supports_systemd_and_openrc
run_test "setup_xdp package lists cover supported managers" test_package_lists_cover_all_supported_managers
run_test "setup_xdp dry-run report emits CI fields" test_dry_run_report_emits_ci_fields
run_test "setup_xdp confirmation handles force and no-tty abort" test_confirm_yes_no_force_and_no_tty_abort_modes
run_test "setup_xdp replaces existing install without prompting" test_replace_existing_install_step_replaces_without_prompt
run_test "setup_xdp prefers local files when available" test_fetch_local_or_remote_uses_local_copy_without_network
run_test "setup_xdp local source defaults to main ref" test_local_source_defaults_to_main_ref
run_test "setup_xdp explicit ref selects matching remote tree" test_explicit_source_ref_selects_matching_remote_tree
run_test "setup_xdp stdin install requires explicit ref" test_remote_stdin_install_requires_explicit_ref
run_test "setup_xdp preserves remote ref across sudo" test_backend_phase_dispatch_preserves_remote_ref_across_sudo
run_test "README release install uses one local archive tree" test_readme_release_install_uses_one_local_archive_tree
run_test "setup_xdp check-update confirms all changed files once" test_check_github_updates_lists_and_confirms_once
run_test "setup_xdp writes queue auto tuning into runtime config" test_write_config_enables_queue_auto_tuning
run_test "setup_xdp sizes combined channels to available CPUs" test_auto_tune_interface_parallelism_sets_combined_channels
run_test "setup_xdp balances interface irqs across CPUs" test_auto_tune_interface_parallelism_balances_irqs
run_test "setup_xdp detects required BPF headers across include roots" test_bpf_header_exists_checks_multiple_include_roots
run_test "setup_xdp surfaces truncated handler build logs" test_warn_from_log_file_prefixes_and_truncates_output
run_test "setup_xdp stages handler sources outside the current directory" test_prepare_slot_handler_sources_uses_staging_dir
run_test "setup_xdp prints info lines within active step output" test_info_prints_within_active_step
run_test "setup_xdp prints substep success and failure markers" test_substep_run_prints_success_and_failure_markers
run_test "setup_xdp validates pinned map set completeness" test_xdp_maps_ready_requires_all_expected_pins
run_test "required map manifest matches the XDP program maps" test_xdp_required_map_manifest_matches_program_maps
run_test "required map fallback matches the installed manifest" test_xdp_required_map_fallback_matches_manifest
run_test "setup_xdp reuses SCTP conntrack map for tc egress" test_load_tc_egress_program_reuses_sctp_conntrack_map
run_test "tc switch failure restores the previous filter" test_tc_switch_failure_restores_previous_filter
run_test "tc rollback failure retains the candidate program" test_tc_rollback_failure_retains_candidate_program
run_test "XDP transaction retains candidate after incomplete tc rollback" test_transaction_retains_candidate_after_incomplete_tc_rollback
run_test "XDP attach uses atomic bpftool overwrite" test_xdp_attach_mode_uses_atomic_bpftool_overwrite
run_test "XDP candidate validation failure keeps the current generation" test_transactional_xdp_validation_failure_keeps_current_generation
run_test "XDP candidate handler failure keeps the current generation" test_transactional_handler_failure_keeps_current_generation
run_test "XDP candidate pre-seed rejects map update failures" test_candidate_preseed_rejects_map_update_failures
run_test "XDP attach failure restores switched interfaces" test_transactional_xdp_attach_failure_restores_switched_interfaces
run_test "tc failure restores the previous XDP generation" test_transactional_tc_failure_restores_xdp_generation
run_test "successful XDP switch commits the candidate generation" test_transactional_xdp_success_commits_candidate_generation
run_test "interrupted XDP reload resumes the candidate generation" test_interrupted_xdp_reload_resumes_candidate_generation
run_test "setup_xdp resolves default route interface for step helper" test_resolve_target_interfaces_uses_default_route_interface
run_test "setup_xdp reuses installed env interfaces on reinstall" test_resolve_target_interfaces_reuses_installed_env_ifaces
run_test "setup_xdp drops missing saved interfaces with note" test_resolve_target_interfaces_drops_missing_saved_ifaces
run_test "setup_xdp re-detects when all saved interfaces are gone" test_resolve_target_interfaces_detects_when_saved_ifaces_all_gone
run_test "setup_xdp preserves existing config.toml on reinstall" test_install_toml_config_preserves_existing_local_config
run_test "setup_xdp keeps clang and bpftool optional for runtime tool checks" test_check_required_tools_step_only_requires_runtime_commands
run_test "setup_xdp backend step falls back to nftables" test_deploy_backend_step_falls_back_to_nftables
run_test "setup_xdp refuses nftables fallback while XDP remains attached" test_deploy_backend_step_refuses_fallback_with_active_xdp
run_test "setup_xdp removes tc filter from removed interface" test_deploy_xdp_removes_tc_filter_from_removed_interface
run_test "setup_xdp service step warns when no init system exists" test_install_runtime_service_step_warns_without_init_system
run_test "setup_xdp loads configured slot handlers only for xdp backend" test_load_configured_slot_handlers_step_only_runs_for_xdp
run_test "setup_xdp cleanup step preserves local sources" test_cleanup_build_artifacts_step_preserves_local_sources
run_test "setup_xdp restores compiled builtin slot handlers after runtime install" test_restore_compiled_slot_handlers_reinstalls_builtin_objects
run_test "setup_xdp installs auto_xdp state module into runtime package" test_install_python_support_package_includes_state_module
run_test "setup_xdp selects sudo mode when not root" test_detect_privilege_mode_uses_sudo_when_not_root
run_test "setup_xdp fails when neither root nor sudo is available" test_detect_privilege_mode_fails_without_root_or_sudo
run_test "setup_xdp as_root runs directly in root mode" test_as_root_runs_directly_when_root
run_test "setup_xdp as_root escalates with sudo in sudo mode" test_as_root_escalates_in_sudo_mode
run_test "setup_xdp detects unwritable destinations" test_can_write_path_detects_unwritable_destinations
run_test "setup_xdp write_file writes to writable paths without sudo" test_write_file_writes_content_without_escalation
run_test "setup_xdp priv_init is a no-op when root" test_priv_init_is_noop_when_root
run_test "setup_xdp priv_init primes sudo once" test_priv_init_primes_sudo_once
run_test "setup_xdp gates gcc-multilib by architecture" test_package_list_gates_gcc_multilib_by_arch
run_test "setup_xdp propagates required package install failures" test_install_packages_propagates_required_install_failure
run_test "setup_xdp package install succeeds on non-apt managers" test_install_packages_succeeds_on_non_apt_managers
run_test "setup_xdp dies when tool package install fails" test_check_required_tools_step_dies_when_install_fails
run_test "setup_xdp rechecks missing tools after package install" test_check_required_tools_step_rechecks_missing_tools
run_test "setup_xdp reports fresh install when nothing is installed" test_replace_existing_install_step_reports_fresh_install
run_test "setup_xdp basic info block renders required fields" test_print_basic_info_renders_required_fields
run_test "setup_xdp remote header list matches bpf/include" test_remote_bpf_header_list_matches_repo_headers
run_test "setup_xdp check-update candidates cover installed sources" test_check_update_candidates_cover_installed_sources
run_test "setup_xdp main keeps info-checks-summary output order" test_main_orders_basic_info_checks_then_summary
run_test "setup_xdp parses internal phase2 flags" test_parse_args_accepts_internal_phase2_flags
run_test "setup_xdp round-trips backend results" test_emit_backend_results_roundtrips_state
run_test "setup_xdp runs backend phase inline when root" test_backend_phase_dispatch_runs_inline_when_root

finish_tests
