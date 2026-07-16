pkg_update() {
    case "$PKG_MANAGER" in
        apt-get)
            as_root apt-get update -qq
            ;;
        dnf|yum)
            as_root "$PKG_MANAGER" -y makecache
            ;;
        zypper)
            as_root zypper --non-interactive refresh
            ;;
        pacman)
            as_root pacman -Sy --noconfirm
            ;;
        apk)
            as_root apk update
            ;;
        *)
            return 1
            ;;
    esac
}

pkg_install() {
    case "$PKG_MANAGER" in
        apt-get)
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
            ;;
        dnf)
            as_root dnf install -y "$@"
            ;;
        yum)
            as_root yum install -y "$@"
            ;;
        zypper)
            as_root zypper --non-interactive install -y "$@"
            ;;
        pacman)
            as_root pacman -S --noconfirm --needed "$@"
            ;;
        apk)
            as_root apk add --no-cache "$@"
            ;;
        *)
            return 1
            ;;
    esac
}

pkg_install_optional() {
    if ! pkg_install "$@"; then
        warn "Optional packages could not be installed: $*"
    fi
}

package_list_for_manager() {
    case "$PKG_MANAGER" in
        apt-get)
            # gcc-multilib only exists on x86_64; requesting it elsewhere makes
            # apt abort the whole install transaction.
            local multilib=""
            if [[ "$(uname -m)" == "x86_64" ]]; then
                multilib=" gcc-multilib"
            fi
            echo "clang llvm libbpf-dev build-essential iproute2 curl python3 python3-pip nftables${multilib}"
            ;;
        dnf|yum)
            # tc lives in iproute-tc on Fedora/RHEL, not in iproute.
            echo "clang llvm libbpf-devel bpftool iproute iproute-tc curl python3 python3-pip gcc make nftables"
            ;;
        zypper)
            echo "clang llvm libbpf-devel bpftool iproute2 curl python3 python3-pip gcc make nftables"
            ;;
        pacman)
            echo "clang llvm libbpf iproute2 curl python python-pip bpf base-devel nftables"
            ;;
        apk)
            echo "clang llvm libbpf-dev bpftool iproute2 curl python3 py3-pip build-base nftables"
            ;;
        *)
            return 1
            ;;
    esac
}

optional_package_list_for_manager() {
    case "$PKG_MANAGER" in
        apt-get)
            echo "linux-headers-$(uname -r)"
            ;;
        dnf|yum)
            echo "kernel-headers kernel-devel"
            ;;
        zypper)
            echo "kernel-devel"
            ;;
        pacman|apk)
            echo "linux-headers"
            ;;
        *)
            return 1
            ;;
    esac
}

install_bpftool_apt() {
    command -v bpftool &>/dev/null && return 0
    if as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bpftool 2>/dev/null; then
        return 0
    fi
    pkg_install_optional "linux-tools-$(uname -r)" linux-tools-common
}

install_packages() {
    local package_list=()
    local optional_list=()

    mapfile -t package_list < <(package_list_for_manager | tr ' ' '\n')
    mapfile -t optional_list < <(optional_package_list_for_manager | tr ' ' '\n')

    pkg_update || warn "Package index refresh failed; trying install with cached index"
    pkg_install "${package_list[@]}" || return 1
    for optional_package in "${optional_list[@]}"; do
        [[ -n "$optional_package" ]] || continue
        pkg_install_optional "$optional_package"
    done

    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        install_bpftool_apt
    fi
    return 0
}

ensure_psutil() {
    if python3 -c "import psutil" 2>/dev/null; then
        return 0
    fi

    case "$PKG_MANAGER" in
        apt-get)
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        dnf|yum)
            as_root "$PKG_MANAGER" install -y python3-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        zypper)
            as_root zypper --non-interactive install -y python3-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        pacman)
            as_root pacman -S --noconfirm --needed python-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        apk)
            as_root apk add --no-cache py3-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        *)
            as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
    esac
}

ensure_python_runtime() {
    python3 - <<'PY' || die "Auto XDP requires Python 3.10 or newer."
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
}

ensure_tomli_for_python310() {
    if python3 - <<'PY'
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
    then
        return 0
    fi

    if python3 -c "import tomli" 2>/dev/null; then
        return 0
    fi

    case "$PKG_MANAGER" in
        apt-get)
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        dnf|yum)
            as_root "$PKG_MANAGER" install -y python3-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        zypper)
            as_root zypper --non-interactive install -y python3-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        pacman)
            as_root pacman -S --noconfirm --needed python-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        apk)
            as_root apk add --no-cache py3-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        *)
            as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
    esac
}

_tool_present() {
    command -v "$1" &>/dev/null
}

# One checklist line per tool: ✓ when present, ✗ when missing. Missing tools
# are installed via the package manager, then re-checked line by line.
check_required_tools_step() {
    local missing=()
    local cmd

    step_begin "Checking required tools"
    for cmd in clang bpftool python3 curl ip tc nft; do
        substep_run "$cmd" _tool_present "$cmd" || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        substep_run "Installing via $PKG_MANAGER: ${missing[*]}" install_packages \
            || die_with_next "Package installation failed." "install the missing packages manually, then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
        for cmd in "${missing[@]}"; do
            if ! substep_run "$cmd (after install)" _tool_present "$cmd"; then
                case "$cmd" in
                    clang|bpftool)
                        warn "$cmd still missing — XDP backend may be unavailable"
                        ;;
                    tc)
                        warn "tc still missing — TCP/UDP/SCTP egress reply tracking will be skipped"
                        ;;
                    nft)
                        warn "nft still missing — nftables fallback backend will be unavailable"
                        ;;
                esac
            fi
        done
    fi

    _tool_present python3 || die_with_next "python3 not found after installation." "install Python 3.10 or newer, then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    _tool_present curl || die_with_next "curl not found after installation." "install curl, then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    _tool_present ip || die_with_next "ip command not found after installation." "install iproute2/iproute, then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    substep_run "python3 >= 3.10" ensure_python_runtime
    substep_run "python3 psutil module" ensure_psutil \
        || die_with_next "Failed to install the psutil Python module." "install python3-psutil (or pip install psutil), then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    substep_run "python3 TOML support" ensure_tomli_for_python310 \
        || die_with_next "Failed to install the tomli Python module." "install python3-tomli (or pip install tomli), then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    PYTHON3_BIN=$(command -v python3)
    IN_STEP=0; _STEP_NEWLINED=0; _PENDING_NL=0
}
