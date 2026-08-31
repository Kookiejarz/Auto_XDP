#!/usr/bin/env bash
# auto-xdp-test-suite: unit

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
# shellcheck source=tests/bash/testlib.sh
source "$REPO_ROOT/tests/bash/testlib.sh"

test_discovers_functions_in_definition_order() (
    local tmpdir fixture output
    tmpdir=$(mktemp -d)
    fixture="$tmpdir/fixture.sh"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'source %q\n' "$REPO_ROOT/tests/bash/testlib.sh"
        printf 'test_second_name() ( :; )\n'
        printf 'test_first_name() { :; }\n'
        printf 'run_discovered_tests "$0" "fixture"\n'
        printf 'finish_tests\n'
    } >"$fixture"

    output=$(bash "$fixture")
    assert_contains "$output" "[INFO] START fixture: second name" || return 1
    assert_contains "$output" "[INFO] PASS fixture: second name" || return 1
    assert_contains "$output" "[INFO] START fixture: first name" || return 1
    assert_contains "$output" "[INFO] PASS fixture: first name" || return 1
    assert_contains "$output" "[INFO] SUMMARY passed=2 failed=0 total=2"
)

test_rejects_a_test_program_without_tests() (
    local tmpdir fixture output status
    tmpdir=$(mktemp -d)
    fixture="$tmpdir/empty.sh"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'source %q\n' "$REPO_ROOT/tests/bash/testlib.sh"
        printf 'run_discovered_tests "$0" "empty"\n'
        printf 'finish_tests\n'
    } >"$fixture"

    set +e
    output=$(bash "$fixture" 2>&1)
    status=$?
    set -e
    [[ $status -ne 0 ]] || return 1
    assert_contains "$output" "no test functions discovered"
)

test_finish_tests_fails_when_nothing_ran() (
    local tmpdir fixture output status
    tmpdir=$(mktemp -d)
    fixture="$tmpdir/none.sh"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'source %q\n' "$REPO_ROOT/tests/bash/testlib.sh"
        printf 'finish_tests\n'
    } >"$fixture"

    set +e
    output=$(bash "$fixture" 2>&1)
    status=$?
    set -e
    [[ $status -ne 0 ]] || return 1
    assert_contains "$output" "no tests ran"
)

test_prints_info_and_warning_output_for_success() (
    local tmpdir fixture output
    tmpdir=$(mktemp -d)
    fixture="$tmpdir/output.sh"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'source %q\n' "$REPO_ROOT/tests/bash/testlib.sh"
        printf 'test_output() ( printf "normal detail\\nwarning: expected warning\\n"; )\n'
        printf 'run_discovered_tests "$0" "fixture"\n'
        printf 'finish_tests\n'
    } >"$fixture"

    output=$(bash "$fixture")
    assert_contains "$output" "[INFO] OUTPUT normal detail" || return 1
    assert_contains "$output" "[WARNING] OUTPUT warning: expected warning"
)

test_failure_prints_command_context_and_complete_output() (
    local tmpdir fixture output status
    tmpdir=$(mktemp -d)
    fixture="$tmpdir/failure.sh"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'source %q\n' "$REPO_ROOT/tests/bash/testlib.sh"
        printf 'test_failure() ( printf "first diagnostic\\nsecond diagnostic\\n"; return 7; )\n'
        printf 'run_discovered_tests "$0" "fixture"\n'
        printf 'finish_tests\n'
    } >"$fixture"

    set +e
    output=$(bash "$fixture" 2>&1)
    status=$?
    set -e
    [[ $status -ne 0 ]] || return 1
    assert_contains "$output" "[ERROR] FAIL fixture: failure" || return 1
    assert_contains "$output" "[ERROR] command: test_failure" || return 1
    assert_contains "$output" "[ERROR] exit_status: 7" || return 1
    assert_contains "$output" "[ERROR] working_directory:" || return 1
    assert_contains "$output" "[ERROR] captured_output_begin" || return 1
    assert_contains "$output" "[ERROR] | first diagnostic" || return 1
    assert_contains "$output" "[ERROR] | second diagnostic" || return 1
    assert_contains "$output" "[ERROR] captured_output_end"
)

test_unhandled_error_trap_prints_command_stack_and_environment() (
    local tmpdir fixture output status
    tmpdir=$(mktemp -d)
    fixture="$tmpdir/unhandled.sh"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'set -Eeuo pipefail\n'
        printf 'source %q\n' "$REPO_ROOT/tests/bash/diagnostics.sh"
        printf 'enable_test_error_diagnostics\n'
        printf 'failing_stage() { false; }\n'
        printf 'failing_stage\n'
    } >"$fixture"

    set +e
    output=$(bash "$fixture" 2>&1)
    status=$?
    set -e
    [[ $status -ne 0 ]] || return 1
    assert_contains "$output" "[ERROR] UNHANDLED TEST COMMAND FAILURE" || return 1
    assert_contains "$output" "[ERROR] command: false" || return 1
    assert_contains "$output" "[ERROR] exit_status: 1" || return 1
    assert_contains "$output" "[ERROR] source:" || return 1
    assert_contains "$output" "[ERROR] host:" || return 1
    assert_contains "$output" "[ERROR] call_stack_begin" || return 1
    assert_contains "$output" "failing_stage" || return 1
    assert_contains "$output" "[ERROR] call_stack_end"
)

run_discovered_tests "${BASH_SOURCE[0]}" "testlib"
finish_tests
