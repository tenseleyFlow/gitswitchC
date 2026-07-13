#!/bin/sh
# Causal negative control for gcovr line/branch coverage thresholds.

set -eu

fail()
{
    printf 'coverage-contract: ERROR: %s\n' "$*" >&2
    exit 1
}

show_logs()
{
    label=$1
    stdout_file=$2
    stderr_file=$3

    printf '%s\n' "--- $label stdout ---" >&2
    cat "$stdout_file" >&2
    printf '%s\n' "--- $label stderr ---" >&2
    cat "$stderr_file" >&2
}

run_threshold_check()
{
    label=$1
    expected_status=$2
    minimum_lines=$3
    minimum_branches=$4
    stdout_file=$tmp/$label.stdout
    stderr_file=$tmp/$label.stderr
    report_file=$tmp/$label.txt

    if "$gcovr_cmd" --root "$tmp" \
        --gcov-executable "$gcov_cmd" \
        --txt "$report_file" --print-summary \
        --fail-under-line "$minimum_lines" \
        --fail-under-branch "$minimum_branches" \
        "$tmp" >"$stdout_file" 2>"$stderr_file"; then
        actual_status=0
    else
        actual_status=$?
    fi

    if [ "$actual_status" -ne "$expected_status" ]; then
        show_logs "$label" "$stdout_file" "$stderr_file"
        fail "$label returned $actual_status; expected $expected_status"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"

cc_name=${COVERAGE_CC:-gcc}
gcov_name=${COVERAGE_GCOV:-gcov}
gcovr_name=${GCOVR:-gcovr}

for tool in "$cc_name" "$gcov_name" "$gcovr_name" mktemp chmod rm cat grep; do
    command -v "$tool" >/dev/null 2>&1 ||
        fail "required tool is unavailable: $tool"
done

cc_cmd=$(command -v "$cc_name") || fail "cannot resolve compiler: $cc_name"
gcov_cmd=$(command -v "$gcov_name") || fail "cannot resolve gcov: $gcov_name"
gcovr_cmd=$(command -v "$gcovr_name") || fail "cannot resolve gcovr: $gcovr_name"

export LC_ALL=C
umask 077
tmp_parent=$(CDPATH='' cd "${TMPDIR:-/tmp}" && pwd -P) ||
    fail "cannot resolve temporary-directory parent"
tmp=$(mktemp -d "$tmp_parent/gitswitch-coverage-contract.XXXXXX") ||
    fail "cannot create private coverage fixture directory"
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    if [ -d "$tmp" ] && [ ! -L "$tmp" ]; then
        rm -rf "$tmp" ||
            printf 'coverage-contract: WARNING: cleanup failed: %s\n' \
                "$tmp" >&2
    else
        printf 'coverage-contract: WARNING: fixture root identity changed: %s\n' \
            "$tmp" >&2
    fi
    exit "$status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 131' 3
trap 'exit 143' 15

chmod 0700 "$tmp" || fail "cannot secure coverage fixture directory"
[ -d "$tmp" ] && [ ! -L "$tmp" ] ||
    fail "coverage fixture root is not a private directory"

cat >"$tmp/fixture.c" <<'EOF'
#include <stdlib.h>

static int choose_result(int value)
{
    if (value == 42) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    (void)argv;
    return choose_result(argc);
}
EOF

(
    CDPATH='' cd "$tmp"
    "$cc_cmd" -std=c11 -O0 -g --coverage -fprofile-abs-path \
        fixture.c -o fixture
    ./fixture
) || fail "cannot compile and execute the GCC coverage fixture"

# gcovr documents status 2 for a failed line threshold and status 4 for a
# failed branch threshold. When both fail, it bitwise-ORs them into status 6.
line_failure_status=2
branch_failure_status=4
combined_failure_status=$((line_failure_status | branch_failure_status))

# The zero-threshold control proves gcovr can read this fixture before any
# deliberately failing assertion is accepted as evidence.
run_threshold_check baseline 0 0 0
grep -F 'fixture.c' "$tmp/baseline.txt" >/dev/null || {
    show_logs baseline "$tmp/baseline.stdout" "$tmp/baseline.stderr"
    fail "gcovr baseline did not discover the fixture source"
}

# Each component status proves that the corresponding metric is genuinely
# below 100%; the combined assertion then verifies gcovr's ORed exit contract.
run_threshold_check line-only "$line_failure_status" 100 0
grep -F 'Failed minimum line coverage' "$tmp/line-only.stderr" >/dev/null ||
    fail "line-only control lacked gcovr's threshold diagnostic"

run_threshold_check branch-only "$branch_failure_status" 0 100
grep -F 'Failed minimum branch coverage' \
    "$tmp/branch-only.stderr" >/dev/null ||
    fail "branch-only control lacked gcovr's threshold diagnostic"

run_threshold_check combined "$combined_failure_status" 100 100
grep -F 'Failed minimum line coverage' "$tmp/combined.stderr" >/dev/null ||
    fail "combined control lacked gcovr's line-threshold diagnostic"
grep -F 'Failed minimum branch coverage' "$tmp/combined.stderr" >/dev/null ||
    fail "combined control lacked gcovr's branch-threshold diagnostic"

printf 'Coverage threshold contract passed (line=%d, branch=%d, combined=%d).\n' \
    "$line_failure_status" "$branch_failure_status" \
    "$combined_failure_status"
