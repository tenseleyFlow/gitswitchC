#!/bin/sh
# AR-17 test integrity: production code must not grow new branches on
# "am I running under a test runner".
#
# run_uses_default_runner() is literally `g_runner == run_argv_real`, so it is
# ALWAYS true in production. Every production site that consults it therefore
# has one arm that ships and one arm that only a test can ever execute. The
# worst instance is Git credential rollback (git_ops.c): under a fake runner
# it silently takes a non-atomic restore that never ships, while ~890 test
# sites install fake runners. Forcing the shipped (atomic) arm fails 64 of
# 69 rollback tests, which is the measure of how much of that suite asserts
# against an implementation nobody runs. This is precisely the mechanism by
# which the AR-16 legacy-migration defect survived fifteen audits.
#
# Retiring the existing sites is a structural refactor of the fake-runner
# harness (deferred; tracked in .docs/sprints). This guard freezes the count
# so the class cannot grow silently: adding a site fails CI until the author
# either removes another or deliberately raises the baseline here, in review.

set -eu

root=${1:-.}
baseline=11

fail()
{
    printf 'runner-mode-policy: ERROR: %s\n' "$*" >&2
    exit 1
}

[ -d "$root/src" ] || fail "source tree not found under $root"

# Count call sites in production code only; utils.c defines the function.
sites=$(grep -n 'run_uses_default_runner()' "$root"/src/*.c \
    | grep -v '/src/utils\.c:' | wc -l | tr -d ' ')

case "$sites" in
    ''|*[!0-9]*) fail "could not count runner-identity sites" ;;
esac

if [ "$sites" -gt "$baseline" ]; then
    printf 'runner-mode-policy: production sites branching on run_uses_default_runner(): %s (baseline %s)\n' \
        "$sites" "$baseline" >&2
    grep -n 'run_uses_default_runner()' "$root"/src/*.c \
        | grep -v '/src/utils\.c:' >&2
    fail "new production branch on test-runner identity; this hides real defects from the suite (see tests/test_runner_mode_policy.sh)"
fi

if [ "$sites" -lt "$baseline" ]; then
    printf 'runner-mode-policy: NOTE: sites dropped to %s; lower the baseline in tests/test_runner_mode_policy.sh to lock in the gain\n' \
        "$sites" >&2
fi

printf 'runner-mode-policy: OK (%s production sites, baseline %s)\n' "$sites" "$baseline"
