#!/bin/sh
# Fail-closed static and native-parser checks for every shipped shell asset.

set -eu

fail()
{
    printf 'shell-static: ERROR: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail "usage: $0 PROJECT_ROOT"
root=$1
[ -d "$root/tests" ] || fail "test-script directory missing: $root/tests"
[ -d "$root/completions" ] ||
    fail "completion directory missing: $root/completions"

missing=0
for tool in shellcheck bash zsh fish dash; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'shell-static: ERROR: required tool is unavailable: %s\n' \
            "$tool" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || exit 1

set -- "$root"/tests/*.sh
[ -e "$1" ] || fail "no POSIX test scripts discovered under $root/tests"
script_count=$#

printf 'ShellCheck: %s POSIX test scripts (severity info)...\n' "$script_count"
shellcheck --severity=info --shell=sh -- "$@"

bash_completion=$root/completions/gitswitch.bash
zsh_completion=$root/completions/gitswitch.zsh
fish_completion=$root/completions/gitswitch.fish
for completion in "$bash_completion" "$zsh_completion" "$fish_completion"; do
    [ -f "$completion" ] || fail "completion missing: $completion"
done

printf 'ShellCheck: Bash completion (severity info)...\n'
shellcheck --severity=info --shell=bash -- "$bash_completion"

printf 'Native parse: POSIX scripts with dash...\n'
for script in "$@"; do
    dash -n "$script"
done

printf 'Native parse: Bash, Zsh, and Fish completions...\n'
bash -n "$bash_completion"
zsh -n "$zsh_completion"
fish -n "$fish_completion"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-shell-static.XXXXXX") ||
    fail "cannot create negative-control directory"
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    rm -rf "$tmp"
    exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

# A syntactically valid unquoted expansion must make the semantic analyzer
# fail at the same severity used above. Verify the diagnostic as well as the
# nonzero exit so an unrelated tool failure cannot satisfy the control.
semantic_bad=$tmp/semantic-bad.sh
printf '%s\n' '#!/bin/sh' "value=\$1" "printf '%s\\n' \$value" \
    >"$semantic_bad"
semantic_out=$tmp/semantic.out
if shellcheck --severity=info --shell=sh "$semantic_bad" \
        >"$semantic_out" 2>&1; then
    fail "ShellCheck accepted the semantic negative control"
fi
grep -F 'SC2086' "$semantic_out" >/dev/null || {
    sed -n '1,120p' "$semantic_out" >&2
    fail "ShellCheck negative control did not report SC2086"
}

# Each native parser must reject a malformed fixture in its own language. This
# catches a missing/no-op parser hidden behind a command of the expected name.
posix_bad=$tmp/native-bad.sh
bash_bad=$tmp/native-bad.bash
zsh_bad=$tmp/native-bad.zsh
fish_bad=$tmp/native-bad.fish
printf '%s\n' '#!/bin/sh' 'if true; then' '    :' >"$posix_bad"
printf '%s\n' '#!/usr/bin/env bash' 'if true; then' '    :' >"$bash_bad"
printf '%s\n' '#!/usr/bin/env zsh' 'if true; then' '    :' >"$zsh_bad"
printf '%s\n' '#!/usr/bin/env fish' 'if true' '    true' >"$fish_bad"

expect_rejection()
{
    parser=$1
    fixture=$2
    out=$tmp/$parser.out
    if "$parser" -n "$fixture" >"$out" 2>&1; then
        fail "$parser accepted its malformed native-syntax control"
    fi
}

expect_rejection dash "$posix_bad"
expect_rejection bash "$bash_bad"
expect_rejection zsh "$zsh_bad"
expect_rejection fish "$fish_bad"

printf 'Shell asset static checks passed.\n'
