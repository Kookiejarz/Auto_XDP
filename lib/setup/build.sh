# lib/setup/build.sh — BPF compilation helpers
# Sourced by setup_xdp.sh after fetch.sh and runtime_common.

ensure_bpf_helper_bootstrap() {
    local helper_path="$BPF_HELPER_SRC"
    if [[ ! -f "$helper_path" ]]; then
        helper_path=$(mktemp)
    fi
    if ! fetch_local_or_remote "$BPF_HELPER_SRC" "$BPF_HELPER_SRC" "$helper_path"; then
        warn "Failed to fetch ${BPF_HELPER_SRC}; helper-based map operations will be unavailable."
        return 1
    fi
    BPF_HELPER_BOOTSTRAP="$helper_path"
    return 0
}

compile_bpf_object() {
    local src_path="$1"
    local obj_path="$2"

    if ! clang -O3 -g \
        -target bpf \
        -mcpu=v3 \
        "-D__TARGET_ARCH_${TARGET_ARCH}" \
        ${HOST_ARCH_FLAG:+"$HOST_ARCH_FLAG"} \
        -fno-stack-protector \
        -Wall -Wno-unused-value \
        -I/usr/include \
        -I"$ASM_INC" \
        -I/usr/include/bpf \
        -Ibpf/include \
        -I. \
        -c "$src_path" -o "$obj_path"; then
        return 1
    fi
    return 0
}

resolve_bpf_target_arch() {
    local arch
    arch=$(uname -m)

    case "$arch" in
        x86_64)
            TARGET_ARCH="x86"
            HOST_ARCH_FLAG="-D__x86_64__"
            ;;
        aarch64|arm64)
            TARGET_ARCH="arm64"
            HOST_ARCH_FLAG="-D__aarch64__"
            ;;
        armv7*|armv6*|arm)
            TARGET_ARCH="arm"
            HOST_ARCH_FLAG="-D__arm__"
            ;;
        *)
            TARGET_ARCH="$arch"
            HOST_ARCH_FLAG=""
            ;;
    esac
}

resolve_bpf_asm_include() {
    local multiarch=""
    local candidates=()

    if command -v gcc &>/dev/null; then
        multiarch=$(gcc -print-multiarch 2>/dev/null || true)
    fi

    if [[ -n "$multiarch" ]]; then
        candidates+=("/usr/include/${multiarch}")
    fi

    case "$DISTRO_FAMILY:$TARGET_ARCH" in
        debian:x86)
            candidates+=("/usr/include/x86_64-linux-gnu")
            ;;
        debian:arm64)
            candidates+=("/usr/include/aarch64-linux-gnu")
            ;;
        debian:arm)
            candidates+=("/usr/include/arm-linux-gnueabihf")
            ;;
    esac

    candidates+=(
        "/usr/src/linux-headers-$(uname -r)/arch/${TARGET_ARCH}/include/generated"
        "/usr/include"
    )

    local candidate
    for candidate in "${candidates[@]}"; do
        [[ -d "$candidate" ]] || continue
        if [[ -d "$candidate/asm" || "$candidate" == "/usr/include" ]]; then
            ASM_INC="$candidate"
            return 0
        fi
    done

    ASM_INC=""
    return 1
}

resolve_bpf_build_env() {
    resolve_bpf_target_arch
    resolve_bpf_asm_include
}

compile_xdp_program() {
    if ! command -v clang &>/dev/null || ! command -v bpftool &>/dev/null; then
        warn "clang or bpftool missing; XDP backend will be skipped."
        return 1
    fi

    if ! fetch_local_or_remote "$XDP_SRC" "$XDP_SRC" "$XDP_SRC"; then
        warn "Unable to fetch ${XDP_SRC}; XDP backend will be skipped."
        return 1
    fi

    local _bpf_headers=(common.h keys.h maps.h trust_acl.h rate_limit.h conntrack.h parse.h slots.h)
    local _hdr
    for _hdr in "${_bpf_headers[@]}"; do
        fetch_local_or_remote "bpf/include/${_hdr}" "bpf/include/${_hdr}" "bpf/include/${_hdr}" || true
    done

    info "Compiling ${XDP_SRC}..."
    if ! resolve_bpf_build_env || [[ -z "$ASM_INC" ]]; then
        warn "ASM headers not found; XDP backend will be skipped."
        return 1
    fi
    info "Using ASM headers: $ASM_INC"

    if ! compile_bpf_object "$XDP_SRC" "$XDP_OBJ"; then
        warn "Failed to compile ${XDP_SRC}; XDP backend will be skipped."
        return 1
    fi

    mkdir -p "$INSTALL_DIR"
    cp "$XDP_OBJ" "$XDP_OBJ_INSTALLED"
    ok "Compiled -> $XDP_OBJ"

    if ! fetch_local_or_remote "$TC_SRC" "$TC_SRC" "$TC_SRC"; then
        warn "Unable to fetch ${TC_SRC}; TCP/UDP tc egress tracker will be skipped."
        return 0
    fi
    if ! compile_bpf_object "$TC_SRC" "$TC_OBJ"; then
        warn "Failed to compile ${TC_SRC}; TCP/UDP tc egress tracker will be skipped."
        return 0
    fi
    cp "$TC_OBJ" "$TC_OBJ_INSTALLED"
    ok "Compiled -> $TC_OBJ"

    if [[ -d "handlers" ]] && command -v make &>/dev/null; then
        info "Compiling slot handlers..."
        if make -C handlers --no-print-directory \
                CLANG="clang" \
                ASM_INC="$ASM_INC" \
                ARCH_FLAGS="-D__TARGET_ARCH_${TARGET_ARCH} ${HOST_ARCH_FLAG}" \
                2>/dev/null; then
            mkdir -p "${INSTALL_DIR}/handlers"
            cp handlers/*.o "${INSTALL_DIR}/handlers/" 2>/dev/null || true
            ok "Slot handlers compiled and installed"
        else
            warn "Slot handler compilation failed; handlers will be unavailable"
        fi
    fi
    return 0
}
