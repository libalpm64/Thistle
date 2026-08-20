#!/bin/zsh

set -uo pipefail

guard_dir=$(mktemp -d)
guard_binary="$guard_dir/sha3-capacity-guard"
guard_log="$guard_dir/run.log"
trap 'rm -rf -- "$guard_dir"' EXIT

mojo build -O3 -I src/ tests/test_sha3_capacity_guard.mojo \
    -o "$guard_binary" >/dev/null 2>&1

if "$guard_binary" >"$guard_log" 2>&1; then
    echo "SHAKE capacity guard did not reject an oversized output" >&2
    exit 1
fi

grep -q "SHAKE output length exceeds destination capacity" "$guard_log"
