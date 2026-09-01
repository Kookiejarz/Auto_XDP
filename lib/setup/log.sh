# Shared installer output and color configuration.

log_printf() {
    local rendered
    local format="$1"
    shift
    printf -v rendered "$format" "$@"
    printf '%b' "$rendered"
}

log_eprintf() {
    local rendered
    local format="$1"
    shift
    printf -v rendered "$format" "$@"
    printf '%b' "$rendered" >&2
}

log_init_colors() {
    if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
        C_GREEN=$'\033[0;32m'
        C_RED=$'\033[0;31m'
        C_YELLOW=$'\033[0;33m'
        C_BLUE=$'\033[0;34m'
        C_CYAN=$'\033[0;36m'
        C_BOLD=$'\033[1m'
        C_RESET=$'\033[0m'
    else
        C_GREEN=''
        C_RED=''
        C_YELLOW=''
        C_BLUE=''
        C_CYAN=''
        C_BOLD=''
        C_RESET=''
    fi

    # Keep the existing names as aliases for the setup helpers.
    GREEN="$C_GREEN"
    RED="$C_RED"
    YELLOW="$C_YELLOW"
    CYAN="$C_CYAN"
    BOLD="$C_BOLD"
    NC="$C_RESET"
    OK_MARK="${C_GREEN}✓${C_RESET}"
    WARN_MARK="${C_YELLOW}!${C_RESET}"
    FAIL_MARK="${C_RED}✗${C_RESET}"
}
