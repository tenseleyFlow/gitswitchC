#!/bin/sh
# Negative-path contracts for Make QA and distribution recipes.

set -eu

fail()
{
    printf 'qa-contract: ERROR: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail "usage: $0 PROJECT_ROOT MAKE"
root=$1
make_cmd=$2

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-qa-contract.XXXXXX")
qa_archive=$root/qa-contract-$$.tar.gz
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    rm -rf "$tmp"
    rm -f "$qa_archive"
    exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

shim_dir=$tmp/shims
mkdir "$shim_dir"
for tool in cppcheck flawfinder valgrind; do
    printf '%s\n' \
        '#!/bin/sh' \
        'if [ -n "${QA_ARG_LOG:-}" ]; then printf "%s\n" "$*" >"$QA_ARG_LOG"; fi' \
        'if [ -n "${QA_REQUIRE_ARG:-}" ]; then' \
        '    case " $* " in *" $QA_REQUIRE_ARG "*) ;; *) exit 0 ;; esac' \
        'fi' \
        'exit "${QA_TOOL_EXIT:-70}"' >"$shim_dir/$tool"
    chmod 0700 "$shim_dir/$tool"
done

out=$tmp/qa.out
arg_log=$tmp/cppcheck.args
if PATH="$shim_dir:$PATH" QA_TOOL_EXIT=71 QA_ARG_LOG="$arg_log" \
    QA_REQUIRE_ARG=--error-exitcode=1 \
    "$make_cmd" -C "$root" analyze >"$out" 2>&1; then
    fail "analyze succeeded after an installed cppcheck failed"
fi
grep -F -- "--enable=warning,performance,portability" "$arg_log" >/dev/null ||
    fail "analyze did not enable actionable cppcheck diagnostics"
grep -F -- "--error-exitcode=1" "$arg_log" >/dev/null ||
    fail "analyze did not configure cppcheck findings as fatal"
if grep -F "not installed" "$out" >/dev/null; then
    fail "analyze misreported an installed failing cppcheck as absent"
fi

arg_log=$tmp/flawfinder.args
if PATH="$shim_dir:$PATH" QA_TOOL_EXIT=72 QA_ARG_LOG="$arg_log" \
    "$make_cmd" -C "$root" security-scan >"$out" 2>&1; then
    fail "security-scan succeeded after an installed flawfinder failed"
fi
grep -F -- "--error-level=4" "$arg_log" >/dev/null ||
    fail "security-scan did not configure flawfinder findings as fatal at level 4 (AR-05 L1)"
if grep -F "not installed" "$out" >/dev/null; then
    fail "security-scan misreported an installed failing flawfinder as absent"
fi

# The memcheck recipe has real binary prerequisites. Build those in release
# mode first so the injected Valgrind failure tests the recipe contract rather
# than a missing/stale prerequisite.
"$make_cmd" -C "$root" clean >/dev/null
"$make_cmd" -C "$root" BUILD_TYPE=release \
    build/bin/gitswitch build/bin/test_runner build/bin/test_security >/dev/null
arg_log=$tmp/valgrind.args
if PATH="$shim_dir:$PATH" QA_TOOL_EXIT=73 \
    QA_REQUIRE_ARG=--error-exitcode=99 QA_ARG_LOG="$arg_log" \
    "$make_cmd" -C "$root" BUILD_TYPE=release memcheck >"$out" 2>&1; then
    fail "memcheck succeeded after an installed valgrind failed"
fi
grep -F -- "--error-exitcode=99" "$arg_log" >/dev/null ||
    fail "memcheck did not configure Valgrind findings as fatal"
if grep -F "not installed" "$out" >/dev/null; then
    fail "memcheck misreported an installed failing valgrind as absent"
fi

mkdir "$tmp/empty-tests"
if "$make_cmd" -C "$root" TESTDIR="$tmp/empty-tests" test >"$out" 2>&1; then
    fail "test target succeeded with zero discovered C tests"
fi
grep -F "no C tests discovered" "$out" >/dev/null ||
    fail "zero-test failure did not explain the discovery problem"
if grep -F "All tests passed!" "$out" >/dev/null; then
    fail "zero-test failure printed a false success banner"
fi

# `dist` runs before the validator. A deliberately invalid prefix must fail
# and the validator's earliest exit path must still delete the new archive.
if "$make_cmd" -C "$root" DIST_ARCHIVE="$(basename "$qa_archive")" \
    DIST_ROOT="gitswitcher-qa-$$" PREFIX=relative distcheck >"$out" 2>&1; then
    fail "distcheck accepted a relative installation prefix"
fi
[ ! -e "$qa_archive" ] || fail "failed distcheck left its source archive behind"

# Even malformed direct invocations must install cleanup before validating
# argc, because the archive path may already name a generated artifact.
printf 'usage-path fixture\n' >"$qa_archive"
if sh "$root/tests/test_dist.sh" "$qa_archive" "gitswitcher-qa-$$" /usr/local \
    >"$out" 2>&1; then
    fail "dist validator accepted a malformed three-argument invocation"
fi
[ ! -e "$qa_archive" ] ||
    fail "dist validator usage failure left its supplied archive behind"

printf 'qa-contract: PASS (tool failures, zero tests, and dist cleanup are fatal)\n'
