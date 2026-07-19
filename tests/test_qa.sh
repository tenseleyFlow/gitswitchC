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
qa_version=$(sed -n '1p' "$root/VERSION")
[ -n "$qa_version" ] || fail "VERSION is empty"
qa_root=gitswitcher-$qa_version
qa_archive=$root/build/dist/$qa_root.tar.gz
qa_preserved=
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    rm -f "$qa_archive"
    if [ -n "$qa_preserved" ]; then
        mkdir -p "$(dirname "$qa_archive")"
        mv "$qa_preserved" "$qa_archive" || status=1
    fi
    rm -rf "$tmp"
    exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

# AR-10 L29: this contract test exercises clean/dist/distcheck against the
# real project tree, so it used to destroy exactly the artifact `make dist`
# had just produced (its own rm -f, plus the interior `make clean`). Park any
# pre-existing operator artifact outside the build tree and restore it on
# every exit path above.
if [ -e "$qa_archive" ] || [ -L "$qa_archive" ]; then
    mv "$qa_archive" "$tmp/parked-dist-artifact" ||
        fail "cannot park pre-existing distribution artifact"
    qa_preserved=$tmp/parked-dist-artifact
fi

shim_dir=$tmp/shims
mkdir "$shim_dir"
for tool in cppcheck flawfinder valgrind; do
    # These expansions belong to the generated shim and must remain literal
    # until that shim is executed by the contract test.
    # shellcheck disable=SC2016
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
"$make_cmd" -C "$root" BUILD_TYPE=release READLINE=0 \
    build/bin/gitswitch build/bin/test_runner build/bin/test_security >/dev/null
arg_log=$tmp/valgrind.args
if PATH="$shim_dir:$PATH" QA_TOOL_EXIT=73 \
    QA_REQUIRE_ARG=--error-exitcode=99 QA_ARG_LOG="$arg_log" \
    "$make_cmd" -C "$root" BUILD_TYPE=release READLINE=0 memcheck >"$out" 2>&1; then
    fail "memcheck succeeded after an installed valgrind failed"
fi
grep -F -- "--error-exitcode=99" "$arg_log" >/dev/null ||
    fail "memcheck did not configure Valgrind findings as fatal"
if grep -F "not installed" "$out" >/dev/null; then
    fail "memcheck misreported an installed failing valgrind as absent"
fi

# AR-05 L16: the other direction — each QA tool GENUINELY ABSENT from PATH
# must take the explicit skip branch: exit 0 and print the "not installed"
# banner (AR-04 L3 acceptance). Previously only the installed-but-failing
# direction was tested, so a regression that turned a missing optional tool
# into a build failure shipped undetected (CI installs the tools, hiding it).
# Build a curated PATH holding just what make's parse-time $(shell) calls and
# the recipes need, with cppcheck/flawfinder/valgrind nowhere on it. The
# release prerequisites were built above, so nothing needs a compiler.
make_abs=$(command -v "$make_cmd" 2>/dev/null || printf '%s' "$make_cmd")
notools_dir=$tmp/notools
mkdir "$notools_dir"
for basic in sh uname git gcc cc clang as brew awk cksum sha256sum shasum sha256 \
             wc tr grep sed printf echo cat cmp find mkdir mkfifo mv rm touch head tail \
             sort expr test; do
    basic_path=$(command -v "$basic" 2>/dev/null) || continue
    case $basic_path in /*) ln -s "$basic_path" "$notools_dir/$basic" ;; esac
done
build_stamp=$root/build/obj/.buildconfig
qa_cc_identity=$(sed -n 's/^cc_resolved=//p' "$build_stamp")
[ -f "$qa_cc_identity" ] ||
    fail "release build stamp lacks stable toolchain identity"
for pair in "analyze:cppcheck" "security-scan:flawfinder" "memcheck:valgrind"; do
    absent_target=${pair%%:*}
    absent_tool=${pair##*:}
    if ! PATH="$notools_dir" "$make_abs" -C "$root" BUILD_TYPE=release READLINE=0 \
        CC_IDENTITY_FILE="$qa_cc_identity" \
        TOOLCHAIN_IDENTITY_FILES="$qa_cc_identity" \
        "$absent_target" >"$out" 2>&1; then
        sed -n '1,200p' "$out" >&2
        fail "$absent_target failed with $absent_tool genuinely absent from PATH"
    fi
    grep -F "not installed" "$out" >/dev/null ||
        fail "$absent_target did not print its skip banner with $absent_tool absent"
done

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
rm -f "$qa_archive"
if "$make_cmd" -C "$root" PREFIX=relative distcheck >"$out" 2>&1; then
    fail "distcheck accepted a relative installation prefix"
fi
grep -F 'PREFIX must be absolute' "$out" >/dev/null ||
    fail "distcheck failed before exercising the invalid-prefix cleanup path"
[ ! -e "$qa_archive" ] || fail "failed distcheck left its source archive behind"

# Even malformed direct invocations must install cleanup before validating
# argc, because the archive path may already name a generated artifact.
mkdir -p "$(dirname "$qa_archive")"
printf 'usage-path fixture\n' >"$qa_archive"
if sh "$root/tests/test_dist.sh" "$qa_archive" "$qa_root" /usr/local \
    >"$out" 2>&1; then
    fail "dist validator accepted a malformed three-argument invocation"
fi
[ ! -e "$qa_archive" ] ||
    fail "dist validator usage failure left its supplied archive behind"

printf 'qa-contract: PASS (tool failures, zero tests, and dist cleanup are fatal)\n'
