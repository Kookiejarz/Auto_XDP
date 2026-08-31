#!/usr/bin/env bash

set -Eeuo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/.." && pwd)
cd "$REPO_ROOT"
# shellcheck source=tests/bash/diagnostics.sh
source "$REPO_ROOT/tests/bash/diagnostics.sh"
enable_test_error_diagnostics

export PYTHONDONTWRITEBYTECODE=1
ACTIVE_SUITE="${1:-distro}"

log_info() { printf '[INFO] %s\n' "$*"; }
log_warning() { printf '[WARNING] %s\n' "$*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }

format_command() {
    local argument="" quoted="" rendered=""
    for argument in "$@"; do
        printf -v quoted '%q' "$argument"
        rendered+="${rendered:+ }$quoted"
    done
    printf '%s\n' "$rendered"
}

run_stage() {
    local label="$1"
    shift
    local started=$SECONDS status=0 command_line=""
    command_line=$(format_command "$@")

    log_info "BEGIN stage=$label suite=$ACTIVE_SUITE"
    log_info "command: $command_line"
    if "$@"; then
        log_info "PASS stage=$label elapsed_seconds=$((SECONDS - started))"
        return 0
    else
        status=$?
    fi

    log_error "FAIL stage=$label suite=$ACTIVE_SUITE"
    log_error "command: $command_line"
    log_error "exit_status: $status"
    log_error "working_directory: $PWD"
    log_error "host: $(uname -a 2>&1)"
    log_error "bash_version: ${BASH_VERSION:-unknown}"
    log_error "python_version: $(python3 --version 2>&1 || printf unavailable)"
    return "$status"
}

usage() {
    cat <<'EOF'
Usage: bash tests/run.sh SUITE

Suites:
  static     Syntax and test metadata contracts
  check      static + mypy
  unit       Deterministic in-process contracts
  component  CLI, filesystem, and fake-adapter contracts
  smoke      Installer dry-run and command entry points
  distro     static + unit + component + smoke
  type       mypy
  build      Native BPF build contracts
  kernel     Privileged kernel/XDP integration contracts
  installed  Contracts for an already installed runtime
  uninstall  Complete uninstall and residue contracts
  all        distro + type + build + kernel
  list       Show registered Bash test programs
EOF
}

test_program_suite() {
    sed -n 's/^# auto-xdp-test-suite: \([[:alnum:]_-]*\)$/\1/p' "$1" | head -n 1
}

list_test_programs() {
    local script="" suite=""
    log_info "registered Bash test programs"
    while IFS= read -r script; do
        suite=$(test_program_suite "$script")
        [[ -n "$suite" ]] || suite="UNREGISTERED"
        printf '%-10s %s\n' "$suite" "$script"
    done < <(find tests/bash -maxdepth 1 -type f -name 'test_*.sh' | sort)
}

run_bash_programs() {
    local wanted="$1" script="" suite="" found=0
    while IFS= read -r script; do
        suite=$(test_program_suite "$script")
        [[ "$suite" == "$wanted" ]] || continue
        found=1
        run_stage "bash:$script" bash "$script"
    done < <(find tests/bash -maxdepth 1 -type f -name 'test_*.sh' | sort)

    if [[ $found -eq 0 ]]; then
        log_error "no Bash test programs registered for suite: $wanted"
        return 1
    fi
}

run_static() {
    local script="" suite=""
    local -a shell_files=()

    while IFS= read -r script; do
        shell_files+=("$script")
    done < <(
        find . -type f -name '*.sh' \
            -not -path './.git/*' \
            -not -path './.superpowers/*' \
            -not -path './website/*' \
            | sort
    )
    [[ -f ./axdp ]] && shell_files+=(./axdp)
    run_stage "syntax:shell" bash -n "${shell_files[@]}"
    log_info "shell syntax files=${#shell_files[@]}"

    local metadata_count=0
    while IFS= read -r script; do
        metadata_count=$((metadata_count + 1))
        suite=$(test_program_suite "$script")
        case "$suite" in
            unit|component|build|kernel|installed|uninstall) ;;
            *)
                log_error "invalid or missing test-suite metadata: $script"
                log_error "discovered_metadata: ${suite:-<empty>}"
                return 1
                ;;
        esac
    done < <(find tests/bash -maxdepth 1 -type f -name 'test_*.sh' | sort)
    log_info "test metadata files=$metadata_count status=valid"

    run_stage "syntax:structured-sources" python3 tests/contracts/check_source_syntax.py
}

run_unit() {
    run_bash_programs unit
    run_stage "pytest:unit" python3 -m pytest tests/python -m 'not component'
}

run_component() {
    run_bash_programs component
    run_stage "pytest:component" python3 -m pytest tests/python -m component
}

run_smoke() {
    if [[ "$(uname -s)" == "Linux" ]]; then
        local check_log="${TMPDIR:-/tmp}/auto_xdp_check_env.log"
        local dry_run_log="${TMPDIR:-/tmp}/auto_xdp_dry_run.log"

        run_stage "smoke:installer-environment" bash ./setup_xdp.sh --check-env \
            | tee "$check_log"
        run_stage "smoke:environment-distro-id" grep -q '^distro_id=' "$check_log"
        run_stage "smoke:environment-package-manager" grep -q '^package_manager=' "$check_log"
        run_stage "smoke:environment-init-system" grep -q '^init_system=' "$check_log"

        run_stage "smoke:installer-dry-run" bash ./setup_xdp.sh --dry-run \
            | tee "$dry_run_log"
        run_stage "smoke:dry-run-mode" grep -q '^mode=dry-run$' "$dry_run_log"
        run_stage "smoke:dry-run-package-manager" grep -q '^package_manager=' "$dry_run_log"
        run_stage "smoke:dry-run-actions" grep -q '^planned_actions=' "$dry_run_log"
        run_stage "smoke:dry-run-packages" grep -q '^planned_packages=' "$dry_run_log"
    else
        log_warning "SKIP installer smoke checks require Linux"
    fi

    run_stage "smoke:setup-help" bash ./setup_xdp.sh --help
    run_stage "smoke:axdp-help" bash ./axdp help
    run_stage "smoke:sync-help" python3 ./xdp_port_sync.py --help
    run_stage "smoke:bpf-helper-help" python3 ./auto_xdp_bpf_helpers.py --help
}

run_suite() {
    case "$1" in
        static) run_static ;;
        check) run_static; run_stage "type:mypy" mypy ;;
        unit) run_unit ;;
        component) run_component ;;
        smoke) run_smoke ;;
        distro) run_static; run_unit; run_component; run_smoke ;;
        type) run_stage "type:mypy" mypy ;;
        build) run_bash_programs build ;;
        kernel) run_bash_programs kernel ;;
        installed) run_bash_programs installed ;;
        uninstall) run_bash_programs uninstall ;;
        all) run_static; run_unit; run_component; run_smoke; run_stage "type:mypy" mypy; run_bash_programs build; run_bash_programs kernel ;;
        list) list_test_programs ;;
        -h|--help|help) usage ;;
        *) usage >&2; return 2 ;;
    esac
}

log_info "TEST RUN START suite=$ACTIVE_SUITE"
log_info "repository=$REPO_ROOT"
log_info "host=$(uname -a 2>&1)"
log_info "bash_version=${BASH_VERSION:-unknown}"
log_info "python_version=$(python3 --version 2>&1 || printf unavailable)"
run_suite "$ACTIVE_SUITE"
log_info "TEST RUN COMPLETE suite=$ACTIVE_SUITE status=passed"
