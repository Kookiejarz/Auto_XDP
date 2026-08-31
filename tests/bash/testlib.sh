#!/usr/bin/env bash

set -uo pipefail

TESTS_RUN=0
TESTS_FAILED=0

test_log_info() {
    printf '[INFO] %s\n' "$*"
}

test_log_warning() {
    printf '[WARNING] %s\n' "$*"
}

test_log_error() {
    printf '[ERROR] %s\n' "$*" >&2
}

_test_format_command() {
    local argument="" quoted="" rendered=""
    for argument in "$@"; do
        printf -v quoted '%q' "$argument"
        rendered+="${rendered:+ }$quoted"
    done
    printf '%s\n' "$rendered"
}

_test_emit_success_output() {
    local output="$1" line=""
    [[ -n "$output" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            *[Ww][Aa][Rr][Nn][Ii][Nn][Gg]*|[Ss][Kk][Ii][Pp]:*)
                test_log_warning "OUTPUT $line"
                ;;
            *)
                test_log_info "OUTPUT $line"
                ;;
        esac
    done <<<"$output"
}

_test_emit_failure_diagnostics() {
    local name="$1" status="$2" command_line="$3" output="$4" line=""
    test_log_error "FAIL $name"
    test_log_error "command: $command_line"
    test_log_error "exit_status: $status"
    test_log_error "working_directory: $PWD"
    test_log_error "bash_version: ${BASH_VERSION:-unknown}"
    if [[ -n "$output" ]]; then
        test_log_error "captured_output_begin"
        while IFS= read -r line || [[ -n "$line" ]]; do
            test_log_error "| $line"
        done <<<"$output"
        test_log_error "captured_output_end"
    else
        test_log_error "captured_output: <empty>"
    fi
}

run_test() {
    local name="$1"
    shift

    TESTS_RUN=$((TESTS_RUN + 1))

    local output=""
    local status=0
    local had_errexit=0
    local command_line=""

    command_line=$(_test_format_command "$@")
    test_log_info "START $name"
    test_log_info "command: $command_line"

    if [[ $- == *e* ]]; then
        had_errexit=1
        set +e
    fi

    output=$("$@" 2>&1)
    status=$?

    if [[ $had_errexit -eq 1 ]]; then
        set -e
    fi

    if [[ $status -eq 0 ]]; then
        _test_emit_success_output "$output"
        test_log_info "PASS $name"
        return 0
    fi

    TESTS_FAILED=$((TESTS_FAILED + 1))
    _test_emit_failure_diagnostics "$name" "$status" "$command_line" "$output"
    return 0
}

discover_test_functions() {
    sed -nE \
        's/^[[:space:]]*(test_[[:alnum:]_]+)\(\)[[:space:]]*[({].*/\1/p' \
        "$1"
}

run_discovered_tests() {
    local source_file="$1"
    local label_prefix="${2:-}"
    local function_name="" label=""
    local discovered=0

    while IFS= read -r function_name; do
        [[ -n "$function_name" ]] || continue
        if ! declare -F "$function_name" >/dev/null 2>&1; then
            TESTS_FAILED=$((TESTS_FAILED + 1))
            test_log_error "discovered test function is not loaded: $function_name"
            test_log_error "source_file: $source_file"
            continue
        fi

        label="${function_name#test_}"
        label="${label//_/ }"
        [[ -n "$label_prefix" ]] && label="${label_prefix}: ${label}"
        run_test "$label" "$function_name"
        discovered=$((discovered + 1))
    done < <(discover_test_functions "$source_file")

    if [[ $discovered -eq 0 ]]; then
        TESTS_FAILED=$((TESTS_FAILED + 1))
        test_log_error "no test functions discovered in $source_file"
    fi
}

assert_eq() {
    local actual="${1-}"
    local expected="${2-}"
    local message="${3:-}"

    if [[ "$actual" == "$expected" ]]; then
        return 0
    fi

    printf 'expected [%s], got [%s]' "$expected" "$actual"
    if [[ -n "$message" ]]; then
        printf ' (%s)' "$message"
    fi
    printf '\n'
    return 1
}

assert_contains() {
    local haystack="${1-}"
    local needle="${2-}"
    local message="${3:-}"

    if [[ "$haystack" == *"$needle"* ]]; then
        return 0
    fi

    printf 'missing substring [%s]' "$needle"
    if [[ -n "$message" ]]; then
        printf ' (%s)' "$message"
    fi
    printf '\n'
    printf 'haystack was:\n%s\n' "$haystack"
    return 1
}

assert_file_contains() {
    local file="$1"
    local needle="$2"
    local message="${3:-}"

    [[ -f "$file" ]] || {
        printf 'missing file [%s]\n' "$file"
        return 1
    }

    local content
    content=$(<"$file")
    assert_contains "$content" "$needle" "$message"
}

finish_tests() {
    if [[ $TESTS_FAILED -ne 0 ]]; then
        test_log_error "SUMMARY failed=$TESTS_FAILED total=$TESTS_RUN"
        return 1
    fi
    if [[ $TESTS_RUN -eq 0 ]]; then
        test_log_error "SUMMARY failed=0 total=0"
        test_log_error "no tests ran"
        return 1
    fi

    test_log_info "SUMMARY passed=$TESTS_RUN failed=0 total=$TESTS_RUN"
}
