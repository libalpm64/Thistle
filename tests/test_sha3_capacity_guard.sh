#!/bin/zsh

set -uo pipefail

guard_dir=$(mktemp -d)
trap 'rm -rf -- "$guard_dir"' EXIT

check_guard() {
    local assert_mode="$1"
    local source_file="$2"
    local guard_name="$3"
    local expected_message="$4"
    local guard_binary="$guard_dir/$guard_name-$assert_mode"
    local guard_log="$guard_dir/$guard_name-$assert_mode.log"

    mojo build -O3 -D ASSERT="$assert_mode" -I src/ \
        "$source_file" -o "$guard_binary" \
        >/dev/null 2>&1

    if "$guard_binary" >"$guard_log" 2>&1; then
        echo "$guard_name failed with ASSERT=$assert_mode" >&2
        exit 1
    fi

    grep -q "$expected_message" "$guard_log"
}

for assert_mode in safe none; do
    check_guard "$assert_mode" tests/test_sha3_capacity_guard.mojo \
        sha3-capacity-guard "SHAKE output length exceeds destination capacity"
    check_guard "$assert_mode" tests/test_sha3_rate_guard.mojo \
        sha3-rate-guard "SHA-3 rate must be a positive multiple of 64"
done
