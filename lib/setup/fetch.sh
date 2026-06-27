sha256_of_file() {
    python3 -c "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())" "$1"
}

# Download URL into TARGET, escalating only when TARGET is a system path. The
# download itself runs unprivileged into a user temp, then place_file installs
# it (with sudo if needed).
_curl_to_target() {
    local url="$1" target="$2" tmp
    tmp=$(mktemp)
    _SETUP_TMPFILES+=("$tmp")
    if ! curl -fsSL "$url" -o "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    place_file "$tmp" "$target"
    rm -f "$tmp"
}

confirm_yes_no() {
    local prompt="$1"
    local no_tty_mode="${2:-deny}"
    local reply=""

    if [[ $FORCE -eq 1 ]]; then
        info "Force mode enabled; proceeding without confirmation."
        return 0
    fi

    if [[ -r /dev/tty ]]; then
        printf "%s" "$prompt" > /dev/tty
        read -r reply < /dev/tty
    elif [[ -t 0 ]]; then
        read -r -p "$prompt" reply
    else
        case "$no_tty_mode" in
            abort)
                return 2
                ;;
            *)
                return 1
                ;;
        esac
    fi

    case "$reply" in
        y|Y|yes|YES|Yes)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

prompt_pull_github() {
    local remote_name="$1"
    local local_hash="$2"
    local remote_hash="$3"

    warn "${remote_name} differs from GitHub."
    warn "  local : ${local_hash}"
    warn "  github: ${remote_hash}"

    if confirm_yes_no "Pull GitHub version for ${remote_name}? [y/N] "; then
        return 0
    fi

    warn "Keeping local ${remote_name}."
    return 1
}

_check_update_candidate_files() {
    local path
    local fixed_files=(
        "setup_xdp.sh"
        "axdp"
        "config.toml"
        "xdp_port_sync.py"
        "pkt_relay.py"
        "auto_xdp_bpf_helpers.py"
        "tc_flow_track.c"
    )

    for path in "${fixed_files[@]}"; do
        [[ -f "$path" ]] && printf '%s\n' "$path"
    done

    for path in lib/setup/*.sh runtime/*.sh bpf/*.c bpf/include/*.h handlers/Makefile handlers/*.c handlers/*.h auto_xdp/*.py auto_xdp/admin/*.py auto_xdp/backends/*.py auto_xdp/bpf/*.py auto_xdp/xdp_required_maps.txt; do
        [[ -f "$path" ]] && printf '%s\n' "$path"
    done | sort -u
}

check_github_updates_once() {
    [[ $CHECK_UPDATES -eq 1 ]] || return 0
    [[ $PREFER_REMOTE_SOURCES -eq 0 ]] || return 0

    local -a changed_files=()
    local -a changed_tmp_files=()
    local -a failed_files=()
    local rel tmp_file local_hash remote_hash

    info "Scanning local files for GitHub updates..."

    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        tmp_file=$(mktemp)
        _SETUP_TMPFILES+=("$tmp_file")
        if ! curl -fsSL "${RAW_URL}/${rel}" -o "$tmp_file"; then
            failed_files+=("$rel")
            continue
        fi

        local_hash=$(sha256_of_file "$rel")
        remote_hash=$(sha256_of_file "$tmp_file")
        if [[ "$local_hash" != "$remote_hash" ]]; then
            changed_files+=("$rel")
            changed_tmp_files+=("$tmp_file")
        fi
    done < <(_check_update_candidate_files)

    if [[ ${#failed_files[@]} -gt 0 ]]; then
        warn "Could not check these files against GitHub:"
        for rel in "${failed_files[@]}"; do
            warn "  ${rel}"
        done
    fi

    if [[ ${#changed_files[@]} -eq 0 ]]; then
        info "All checked local files match GitHub."
        CHECK_UPDATES=0
        return 0
    fi

    warn "The following local files differ from GitHub:"
    for rel in "${changed_files[@]}"; do
        warn "  ${rel}"
    done

    if confirm_yes_no "Pull GitHub versions for all listed files? [y/N] "; then
        local i
        for i in "${!changed_files[@]}"; do
            cp "${changed_tmp_files[$i]}" "${changed_files[$i]}"
            info "Updated local ${changed_files[$i]} from GitHub."
        done
    else
        warn "Keeping local files."
    fi

    CHECK_UPDATES=0
    return 0
}

fetch_local_or_remote() {
    local local_path="$1"
    local remote_name="$2"
    local target_path="$3"
    local tmp_file=""
    local local_hash=""
    local remote_hash=""

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        info "Installer is running from stdin; fetching ${remote_name} from GitHub..."
        _curl_to_target "${RAW_URL}/${remote_name}" "$target_path" || return 1
        return 0
    fi

    if [[ -f "$local_path" ]]; then
        if [[ $CHECK_UPDATES -eq 1 ]]; then
            tmp_file=$(mktemp)
            info "Checking GitHub version of ${remote_name}..."
            if ! curl -fsSL "${RAW_URL}/${remote_name}" -o "$tmp_file"; then
                warn "Could not fetch ${remote_name} from GitHub for comparison; keeping local copy."
                rm -f "$tmp_file"
                if [[ "$local_path" != "$target_path" ]]; then
                    place_file "$local_path" "$target_path"
                fi
                return 0
            fi

            local_hash=$(sha256_of_file "$local_path")
            remote_hash=$(sha256_of_file "$tmp_file")

            if [[ "$local_hash" == "$remote_hash" ]]; then
                info "Local ${remote_name} matches GitHub."
                rm -f "$tmp_file"
                if [[ "$local_path" != "$target_path" ]]; then
                    place_file "$local_path" "$target_path"
                fi
                return 0
            fi

            if prompt_pull_github "$remote_name" "$local_hash" "$remote_hash"; then
                cp "$tmp_file" "$local_path"
                info "Updated local ${remote_name} from GitHub."
            else
                info "Keeping local ${remote_name}."
            fi

            rm -f "$tmp_file"
        fi

        if [[ "$local_path" != "$target_path" ]]; then
            place_file "$local_path" "$target_path"
        fi
        info "Using local ${remote_name}"
        return 0
    fi

    if [[ $CHECK_UPDATES -eq 1 && -f "$target_path" ]]; then
        tmp_file=$(mktemp)
        info "Checking GitHub version of ${remote_name}..."
        if ! curl -fsSL "${RAW_URL}/${remote_name}" -o "$tmp_file"; then
            warn "Could not fetch ${remote_name} from GitHub; keeping installed copy."
            rm -f "$tmp_file"
            return 0
        fi
        local_hash=$(sha256_of_file "$target_path")
        remote_hash=$(sha256_of_file "$tmp_file")
        if [[ "$local_hash" == "$remote_hash" ]]; then
            info "Installed ${remote_name} matches GitHub."
            rm -f "$tmp_file"
            return 0
        fi
        if prompt_pull_github "$remote_name" "$local_hash" "$remote_hash"; then
            place_file "$tmp_file" "$target_path"
            info "Updated ${remote_name}."
        else
            info "Keeping installed ${remote_name}."
        fi
        rm -f "$tmp_file"
        return 0
    fi

    info "Fetching ${remote_name} from GitHub..."
    _curl_to_target "${RAW_URL}/${remote_name}" "$target_path"
}
