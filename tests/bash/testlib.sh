#!/usr/bin/env bash

set -uo pipefail

TESTS_RUN=0
TESTS_FAILED=0

run_test() {
    local name="$1"
    shift

    TESTS_RUN=$((TESTS_RUN + 1))

    local output=""
    local status=0
    local had_errexit=0

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
        printf 'ok - %s\n' "$name"
        return 0
    fi

    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf 'not ok - %s\n' "$name"
    if [[ -n "$output" ]]; then
        printf '%s\n' "$output"
    fi
    return 0
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
        printf '%d of %d tests failed\n' "$TESTS_FAILED" "$TESTS_RUN"
        return 1
    fi

    printf 'all %d tests passed\n' "$TESTS_RUN"
}
