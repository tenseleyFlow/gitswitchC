#!/bin/sh
# Verify the exact Linux release consumers before later QA work can mutate the
# build tree. The workflow pins the enclosing Make target and its adjacency;
# that target holds the publisher mutex through this complete inspection.

set -eu

fail()
{
    printf 'ci-symbols: ERROR: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail "usage: $0 RELEASE_BINARY RELEASE_PUBLISHER"

for binary do
    [ -x "$binary" ] || fail "missing or non-executable binary: $binary"
    symbols=$(/usr/bin/nm -D --undefined-only "$binary") ||
        fail "nm failed: $binary"
    if printf '%s\n' "$symbols" |
        /usr/bin/grep -E '(^| )(system|popen)(@|$)' >/dev/null; then
        fail "forbidden process symbol referenced by $binary"
    else
        grep_status=$?
        [ "$grep_status" -eq 1 ] || fail "grep failed: $binary"
    fi
done

printf 'ci-symbols: PASS\n'
