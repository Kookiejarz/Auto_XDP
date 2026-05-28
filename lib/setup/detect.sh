detect_pkg_manager() {
    detect_os_release

    local candidates=()
    case "$DISTRO_FAMILY" in
        debian)
            candidates=(apt-get dnf yum zypper pacman apk)
            ;;
        rpm)
            candidates=(dnf yum apt-get zypper pacman apk)
            ;;
        suse)
            candidates=(zypper dnf yum apt-get pacman apk)
            ;;
        arch)
            candidates=(pacman apt-get dnf yum zypper apk)
            ;;
        alpine)
            candidates=(apk apt-get dnf yum zypper pacman)
            ;;
        *)
            candidates=(apt-get dnf yum zypper pacman apk)
            ;;
    esac

    for pm in "${candidates[@]}"; do
        if command -v "$pm" &>/dev/null; then
            PKG_MANAGER="$pm"
            return 0
        fi
    done
    return 1
}

detect_os_release() {
    local _id="" _name="" _id_like=""
    local _line _key _value

    if [[ -r "$OS_RELEASE_FILE" ]]; then
        while IFS= read -r _line; do
            case "$_line" in
                ID=*|NAME=*|ID_LIKE=*)
                    _key="${_line%%=*}"
                    _value="${_line#*=}"
                    _value="${_value%\"}"
                    _value="${_value#\"}"
                    case "$_key" in
                        ID) [[ -z "$_id" ]] && _id="$_value" ;;
                        NAME) [[ -z "$_name" ]] && _name="$_value" ;;
                        ID_LIKE) [[ -z "$_id_like" ]] && _id_like="$_value" ;;
                    esac
                    ;;
            esac
        done <"$OS_RELEASE_FILE"
    fi

    DISTRO_ID="${_id:-unknown}"
    DISTRO_NAME="${_name:-$DISTRO_ID}"
    DISTRO_LIKE="${_id_like:-}"

    case " ${DISTRO_ID} ${DISTRO_LIKE} " in
        *" ubuntu "*|*" debian "*)
            DISTRO_FAMILY="debian"
            ;;
        *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" alma "*|*" amzn "*)
            DISTRO_FAMILY="rpm"
            ;;
        *" opensuse"*|*" suse "*)
            DISTRO_FAMILY="suse"
            ;;
        *" arch "*)
            DISTRO_FAMILY="arch"
            ;;
        *" alpine "*)
            DISTRO_FAMILY="alpine"
            ;;
        *)
            DISTRO_FAMILY="unknown"
            ;;
    esac
}

detect_init_system() {
    if command -v systemctl &>/dev/null && [[ -d "$SYSTEMD_RUN_DIR" ]]; then
        SYSTEMD_AVAILABLE=1
        INIT_SYSTEM="systemd"
        return
    fi

    if command -v rc-service &>/dev/null && command -v rc-update &>/dev/null; then
        OPENRC_AVAILABLE=1
        INIT_SYSTEM="openrc"
        return
    fi
}

detect_environment_step() {
    step_begin "Detecting default package manager"
    detect_pkg_manager || die "No supported package manager found."
    detect_init_system
    step_ok "Found: $PKG_MANAGER"
}
