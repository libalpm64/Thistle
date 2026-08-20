#!/bin/zsh

set -uo pipefail

guard_dir=$(mktemp -d)
trap 'rm -rf -- "$guard_dir"' EXIT

for assert_mode in safe none; do
    guard_binary="$guard_dir/sha3-capacity-guard-$assert_mode"
    guard_log="$guard_dir/run-$assert_mode.log"

    mojo build -O3 -D ASSERT="$assert_mode" -I src/ \
        tests/test_sha3_capacity_guard.mojo -o "$guard_binary" \
        >/dev/null 2>&1

    if "$guard_binary" >"$guard_log" 2>&1; then
        echo "SHAKE capacity guard failed with ASSERT=$assert_mode" >&2
        exit 1
    fi

    grep -q "SHAKE output length exceeds destination capacity" "$guard_log"
done
