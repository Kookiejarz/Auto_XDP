#!/usr/bin/env bash

# Shared diagnostics for standalone test programs that use `set -e` instead of
# the per-test run_test() harness.

test_unhandled_error_diagnostics() {
    local status="$1" line="$2" command="$3"
    local frame=0 callsite=""

    trap - ERR
    printf '[ERROR] UNHANDLED TEST COMMAND FAILURE\n' >&2
    printf '[ERROR] command: %s\n' "$command" >&2
    printf '[ERROR] exit_status: %s\n' "$status" >&2
    printf '[ERROR] source: %s:%s\n' "${BASH_SOURCE[2]:-${BASH_SOURCE[1]:-unknown}}" "$line" >&2
    printf '[ERROR] working_directory: %s\n' "$PWD" >&2
    printf '[ERROR] host: %s\n' "$(uname -a 2>&1)" >&2
    printf '[ERROR] bash_version: %s\n' "${BASH_VERSION:-unknown}" >&2
    printf '[ERROR] python_version: %s\n' "$(python3 --version 2>&1 || printf unavailable)" >&2
    printf '[ERROR] call_stack_begin\n' >&2
    while callsite=$(caller "$frame"); do
        printf '[ERROR] | %s\n' "$callsite" >&2
        frame=$((frame + 1))
    done
    printf '[ERROR] call_stack_end\n' >&2
    return "$status"
}

enable_test_error_diagnostics() {
    set -E
    trap 'test_unhandled_error_diagnostics "$?" "$LINENO" "$BASH_COMMAND"' ERR
}
