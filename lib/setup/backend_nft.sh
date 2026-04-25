# lib/setup/backend_nft.sh — nftables fallback backend helpers
# Sourced by setup_xdp.sh after build.sh.

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
