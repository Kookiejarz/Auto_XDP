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

    local host_arch_flag=""
    case "$TARGET_ARCH" in
        x86)   host_arch_flag="-D__x86_64__"   ;;
        arm64) host_arch_flag="-D__aarch64__"  ;;
        arm)   host_arch_flag="-D__arm__"      ;;
    esac

    if ! clang -O3 -g \
        -target bpf \
        -mcpu=v3 \
        "-D__TARGET_ARCH_${TARGET_ARCH}" \
        ${host_arch_flag:+"$host_arch_flag"} \
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

compile_xdp_program() {
    if ! command -v clang &>/dev/null || ! command -v bpftool &>/dev/null; then
        warn "clang or bpftool missing; XDP backend will be skipped."
        return 1
    fi

    if ! fetch_local_or_remote "$XDP_SRC" "$XDP_SRC" "$XDP_SRC"; then
        warn "Unable to fetch ${XDP_SRC}; XDP backend will be skipped."
        return 1
    fi

    info "Compiling ${XDP_SRC}..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ASM_INC="/usr/include/x86_64-linux-gnu";   TARGET_ARCH="x86"   ;;
        aarch64) ASM_INC="/usr/include/aarch64-linux-gnu";  TARGET_ARCH="arm64" ;;
        armv7*)  ASM_INC="/usr/include/arm-linux-gnueabihf"; TARGET_ARCH="arm"  ;;
        *)       ASM_INC="/usr/include/${ARCH}-linux-gnu";  TARGET_ARCH="$ARCH" ;;
    esac

    if [[ ! -d "$ASM_INC" ]]; then
        ASM_INC="/usr/src/linux-headers-$(uname -r)/arch/${TARGET_ARCH}/include/generated"
    fi
    if [[ ! -d "$ASM_INC" && -d "/usr/include/asm" ]]; then
        ASM_INC="/usr/include"
    fi
    if [[ ! -d "$ASM_INC" ]]; then
        ASM_INC=$(find /usr/src -name "asm" -type d -print -quit | xargs dirname 2>/dev/null || echo "")
    fi
    if [[ ! -d "$ASM_INC" ]]; then
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
                CLANG="clang" 2>/dev/null; then
            mkdir -p "${INSTALL_DIR}/handlers"
            cp handlers/*.o "${INSTALL_DIR}/handlers/" 2>/dev/null || true
            ok "Slot handlers compiled and installed"
        else
            warn "Slot handler compilation failed; handlers will be unavailable"
        fi
    fi
    return 0
}
