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
qa_git_dir=$(git -C "$root" rev-parse --absolute-git-dir) ||
    fail "cannot resolve QA checkout Git directory"
qa_release_lock=$qa_git_dir/gitswitch-release-publish.lock
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

# Distcheck generates and consumes an unnamed/private archive, so even its
# validator-failure path must ignore a byte-distinct canonical sentinel. This
# also proves the release mutex is held and retired without granting cleanup
# authority over an existing caller path.
mkdir -p "$(dirname "$qa_archive")"
printf 'pre-existing canonical sentinel\n' >"$qa_archive"
cp "$qa_archive" "$tmp/pre-existing-canonical.before"
if "$make_cmd" -C "$root" PREFIX=relative distcheck >"$out" 2>&1; then
    fail "distcheck accepted a relative installation prefix"
fi
grep -F 'PREFIX must be absolute' "$out" >/dev/null ||
    fail "distcheck failed before exercising private archive validation"
cmp -s "$tmp/pre-existing-canonical.before" "$qa_archive" ||
    fail "failed private distcheck changed a canonical caller sentinel"
[ ! -e "$qa_release_lock" ] && [ ! -L "$qa_release_lock" ] ||
    fail "failed distcheck retained the release mutex"

# Direct validator input is borrowed, never owned. Preserve exact bytes across
# malformed argc, invalid prefix, and invalid gzip failures; the old trap
# unlinked this arbitrary caller path before it had even validated argc.
caller_archive=$tmp/caller-owned.tar.gz
caller_before=$tmp/caller-owned.before
printf 'caller-owned archive sentinel\n' >"$caller_archive"
cp "$caller_archive" "$caller_before"
if sh "$root/tests/test_dist.sh" "$caller_archive" "$qa_root" /usr/local \
    >"$out" 2>&1; then
    fail "dist validator accepted a malformed three-argument invocation"
fi
grep -F 'usage:' "$out" >/dev/null ||
    fail "dist validator usage failure missed its argument gate"
cmp -s "$caller_before" "$caller_archive" ||
    fail "dist validator usage failure changed caller-owned input"

if sh "$root/tests/test_dist.sh" "$caller_archive" "$qa_root" relative \
    "$make_cmd" -- VERSION >"$out" 2>&1; then
    fail "direct dist validator accepted a relative prefix"
fi
grep -F 'PREFIX must be absolute' "$out" >/dev/null ||
    fail "direct dist validator missed its invalid-prefix gate"
cmp -s "$caller_before" "$caller_archive" ||
    fail "dist validator prefix failure changed caller-owned input"

caller_home=$tmp/caller-home
mkdir "$caller_home"
chmod 0700 "$caller_home"
if HOME="$caller_home" sh "$root/tests/test_dist.sh" \
    "$caller_archive" "$qa_root" /usr/local \
    "$make_cmd" -- VERSION >"$out" 2>&1; then
    fail "dist validator accepted a non-gzip caller archive"
fi
grep -F 'not a complete gzip stream' "$out" >/dev/null ||
    fail "direct dist validator missed its gzip-integrity gate"
cmp -s "$caller_before" "$caller_archive" ||
    fail "dist validator gzip failure changed caller-owned input"
set -- "$caller_home"/.gitswitch-distcheck.*
if [ "$#" -ne 1 ] || [ -e "$1" ] || [ -L "$1" ]; then
    fail "dist validator gzip failure retained a private build tree"
fi

# The internal descriptor is intentionally O_RDWR for portable anonymous-file
# support, so no pre-snapshot descendant may inherit it. Instrument the actual
# committed validator: mktemp/chmod must receive fd 3 closed, the one snapshot
# cat must receive it open, and both Git metadata children must see it closed.
# The invalid gzip then ends the run before any expensive extraction/build.
fd_shim_dir=$tmp/fd-shims
fd_trace=$tmp/fd-inheritance.trace
fd_expected=$tmp/fd-inheritance.expected
mkdir "$fd_shim_dir"
for fd_tool in mktemp chmod cat git rm; do
    fd_real=$(command -v "$fd_tool") ||
        fail "cannot resolve $fd_tool for descriptor-inheritance fixture"
    # These variables and descriptor checks belong to the generated shim.
    # shellcheck disable=SC2016
    case $fd_tool in
        cat)
            printf '%s\n' \
                '#!/bin/sh' \
                'set -eu' \
                'if ! /bin/sh -c '\'' : <&3'\'' 2>/dev/null; then exit 82; fi' \
                'printf "%s\n" cat-open >>"$AR11_FD_TRACE"' \
                '[ "${AR11_FD_CAT_FAIL-}" != 1 ] || exit 84' \
                'exec "$AR11_FD_REAL_CAT" "$@"' \
                >"$fd_shim_dir/$fd_tool"
            ;;
        *)
            printf '%s\n' \
                '#!/bin/sh' \
                'set -eu' \
                'if /bin/sh -c '\'' : <&3'\'' 2>/dev/null; then exit 83; fi' \
                "printf '%s\\n' '$fd_tool-closed' >>\"\$AR11_FD_TRACE\"" \
                "exec \"\$AR11_FD_REAL_$(printf '%s' "$fd_tool" | tr '[:lower:]' '[:upper:]')\" \"\$@\"" \
                >"$fd_shim_dir/$fd_tool"
            ;;
    esac
    chmod 0700 "$fd_shim_dir/$fd_tool"
    case $fd_tool in
        mktemp) AR11_FD_REAL_MKTEMP=$fd_real ;;
        chmod) AR11_FD_REAL_CHMOD=$fd_real ;;
        cat) AR11_FD_REAL_CAT=$fd_real ;;
        git) AR11_FD_REAL_GIT=$fd_real ;;
        rm) AR11_FD_REAL_RM=$fd_real ;;
    esac
done
export AR11_FD_REAL_MKTEMP AR11_FD_REAL_CHMOD AR11_FD_REAL_CAT \
    AR11_FD_REAL_GIT AR11_FD_REAL_RM
printf '%s\n' mktemp-closed chmod-closed cat-open git-closed git-closed \
    rm-closed \
    >"$fd_expected"
if AR11_FD_TRACE=$fd_trace PATH="$fd_shim_dir:$PATH" HOME="$caller_home" \
    sh "$root/tests/test_dist.sh" @GITSWITCH_PRIVATE_ARCHIVE_FD@ \
    "$qa_root" /usr/local "$make_cmd" -- VERSION \
    3<"$caller_archive" >"$out" 2>&1; then
    fail "fd-backed dist validator accepted a non-gzip private archive"
fi
grep -F 'not a complete gzip stream' "$out" >/dev/null || {
    sed -n '1,120p' "$out" >&2
    fail "fd-backed validator failed before its post-snapshot gzip gate"
}
cmp -s "$fd_expected" "$fd_trace" || {
    sed -n '1,40p' "$fd_trace" >&2
    fail "dist validator leaked fd 3 across its snapshot ownership boundary"
}
set -- "$caller_home"/.gitswitch-distcheck.*
if [ "$#" -ne 1 ] || [ -e "$1" ] || [ -L "$1" ]; then
    fail "fd-backed validator failure retained a private build tree"
fi

# Force the only fd-consuming helper to fail before the parent can close fd 3.
# The exit trap's rm child must still receive that descriptor closed and retire
# the invocation-private tree; otherwise an error path recreates the leak.
printf '%s\n' mktemp-closed chmod-closed cat-open rm-closed >"$fd_expected"
: >"$fd_trace"
if AR11_FD_CAT_FAIL=1 AR11_FD_TRACE=$fd_trace \
    PATH="$fd_shim_dir:$PATH" HOME="$caller_home" \
    sh "$root/tests/test_dist.sh" @GITSWITCH_PRIVATE_ARCHIVE_FD@ \
    "$qa_root" /usr/local "$make_cmd" -- VERSION \
    3<"$caller_archive" >"$out" 2>&1; then
    fail "fd-backed validator accepted a failed private snapshot"
fi
grep -F 'cannot snapshot private archive descriptor' "$out" >/dev/null ||
    fail "fd-backed validator missed its forced snapshot failure"
cmp -s "$fd_expected" "$fd_trace" || {
    sed -n '1,40p' "$fd_trace" >&2
    fail "dist validator cleanup inherited fd 3 after snapshot failure"
}
set -- "$caller_home"/.gitswitch-distcheck.*
if [ "$#" -ne 1 ] || [ -e "$1" ] || [ -L "$1" ]; then
    fail "failed fd snapshot retained a private build tree"
fi

# This archive passes the gzip, exact-root, containment, duplicate, and
# exclusion gates, then fails only the commit-derived exact manifest. The
# borrowed input and validator-private snapshot must both retire correctly at
# that deepest pre-extraction failure boundary.
manifest_tree=$tmp/caller-manifest-tree
manifest_archive=$tmp/caller-manifest.tar.gz
manifest_before=$tmp/caller-manifest.before
mkdir -p "$manifest_tree/$qa_root" ||
    fail "cannot create manifest-mismatch fixture"
cp "$root/VERSION" "$manifest_tree/$qa_root/VERSION" ||
    fail "cannot seed manifest-mismatch VERSION"
printf 'unexpected member\n' >"$manifest_tree/$qa_root/unexpected" ||
    fail "cannot seed unexpected manifest member"
tar -czf "$manifest_archive" -C "$manifest_tree" "$qa_root" ||
    fail "cannot create manifest-mismatch archive"
cp "$manifest_archive" "$manifest_before" ||
    fail "cannot preserve manifest-mismatch archive"
if HOME="$caller_home" sh "$root/tests/test_dist.sh" \
    "$manifest_archive" "$qa_root" /usr/local "$make_cmd" -- VERSION \
    >"$out" 2>&1; then
    fail "dist validator accepted an unexpected in-root manifest member"
fi
grep -F 'archive members differ from the exact committed release manifest' \
    "$out" >/dev/null ||
    fail "manifest-mismatch fixture missed the exact-membership gate"
cmp -s "$manifest_before" "$manifest_archive" ||
    fail "manifest failure changed caller-owned input"
set -- "$caller_home"/.gitswitch-distcheck.*
if [ "$#" -ne 1 ] || [ -e "$1" ] || [ -L "$1" ]; then
    fail "manifest failure retained a private build tree"
fi

dangling_archive=$tmp/caller-dangling.tar.gz
ln -s missing-caller-target "$dangling_archive" ||
    fail "cannot create dangling caller-archive fixture"
if sh "$root/tests/test_dist.sh" "$dangling_archive" "$qa_root" /usr/local \
    "$make_cmd" -- VERSION >"$out" 2>&1; then
    fail "dist validator accepted a dangling caller archive"
fi
grep -F 'archive not found' "$out" >/dev/null ||
    fail "dangling caller archive missed the existence gate"
[ -L "$dangling_archive" ] &&
    [ "$(readlink "$dangling_archive")" = missing-caller-target ] ||
    fail "dist validator removed or changed a dangling caller archive"

# A lightweight committed validator proves the success path without rebuilding
# the extracted project. It snapshots inherited fd 3, closes it before spawning
# a descendant, verifies the live lock owner, and returns success. No canonical
# archive is published; pre-existing canonical and sibling sentinels survive.
ownership_repo=$tmp/ownership-success
git clone --quiet "$root" "$ownership_repo" ||
    fail "cannot clone distcheck ownership fixture"
cp "$root/Makefile" "$ownership_repo/Makefile" ||
    fail "cannot install current Make ownership contract"
cp "$root/tools/release_publish.c" "$ownership_repo/tools/release_publish.c" ||
    fail "cannot install current release-publisher ownership contract"
# These expansions belong to the generated validator and must remain literal
# until that validator runs under the distcheck lock.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    '[ "$#" -ge 1 ] && [ "$1" = @GITSWITCH_PRIVATE_ARCHIVE_FD@ ] || exit 91' \
    '[ -n "${GITSWITCH_L42_MARKER-}" ] || exit 92' \
    '[ -n "${GITSWITCH_L42_CAPTURE-}" ] || exit 98' \
    'cat <&3 >"$GITSWITCH_L42_CAPTURE" || exit 99' \
    'exec 3<&-' \
    '[ -s "$GITSWITCH_L42_CAPTURE" ] || exit 100' \
    'if /bin/sh -c '\'': <&3'\'' 2>/dev/null; then exit 101; fi' \
    '[ -n "${GITSWITCH_RELEASE_LOCK_TOKEN-}" ] || exit 93' \
    '[ -d "$GITSWITCH_DIST_PUBLISH_LOCK_PATH" ] || exit 94' \
    '[ ! -L "$GITSWITCH_DIST_PUBLISH_LOCK_PATH" ] || exit 95' \
    'IFS= read -r owner <"$GITSWITCH_DIST_PUBLISH_LOCK_PATH/owner" || exit 96' \
    '[ "$owner" = "$GITSWITCH_RELEASE_LOCK_TOKEN" ] || exit 97' \
    'if [ "${GITSWITCH_L42_SIGNAL_PARENT-}" = 1 ]; then' \
    '    printf "%s\n" signal-ready >"$GITSWITCH_L42_MARKER"' \
    '    kill -TERM "$PPID" || exit 102' \
    '    exit 0' \
    'fi' \
    'printf "%s\n" validated >"$GITSWITCH_L42_MARKER"' \
    >"$ownership_repo/tests/test_dist.sh"
chmod 0755 "$ownership_repo/tests/test_dist.sh"
git -C "$ownership_repo" add Makefile tools/release_publish.c \
    tests/test_dist.sh ||
    fail "cannot stage distcheck ownership fixture"
git -C "$ownership_repo" -c user.name='AR-11 L42' \
    -c user.email='ar11-l42@example.invalid' -c commit.gpgsign=false \
    commit --quiet -m 'L42 ownership fixture' ||
    fail "cannot commit distcheck ownership fixture"

ownership_version=$(git -C "$ownership_repo" show HEAD:VERSION) ||
    fail "cannot read ownership-fixture VERSION"
ownership_root=gitswitcher-$ownership_version
ownership_dist=$ownership_repo/build/dist
ownership_archive=$ownership_dist/$ownership_root.tar.gz
ownership_sibling=$ownership_dist/caller-sibling.sentinel
ownership_before=$tmp/caller-sibling.before
ownership_marker=$tmp/ownership-validator.marker
ownership_capture=$tmp/ownership-validator.archive
ownership_archive_before=$tmp/ownership-canonical.before
mkdir -p "$ownership_dist"
chmod 0700 "$ownership_repo/build" "$ownership_dist"
printf 'pre-existing canonical sentinel\n' >"$ownership_archive"
cp "$ownership_archive" "$ownership_archive_before"
printf 'unrelated sibling sentinel\n' >"$ownership_sibling"
cp "$ownership_sibling" "$ownership_before"
if ! GITSWITCH_L42_MARKER="$ownership_marker" \
    GITSWITCH_L42_CAPTURE="$ownership_capture" \
    "$make_cmd" -C "$ownership_repo" distcheck >"$out" 2>&1; then
    sed -n '1,160p' "$out" >&2
    fail "successful distcheck ownership fixture failed"
fi
[ "$(sed -n '1p' "$ownership_marker")" = validated ] ||
    fail "distcheck ownership fixture did not invoke its validator"
[ -s "$ownership_capture" ] ||
    fail "distcheck ownership fixture received an empty private archive"
cmp -s "$ownership_archive_before" "$ownership_archive" ||
    fail "successful private distcheck changed the canonical sentinel"
cmp -s "$ownership_before" "$ownership_sibling" ||
    fail "successful distcheck changed an unrelated sibling"
ownership_git_dir=$(git -C "$ownership_repo" rev-parse --absolute-git-dir) ||
    fail "cannot resolve ownership-fixture Git directory"
[ ! -e "$ownership_git_dir/gitswitch-release-publish.lock" ] &&
    [ ! -L "$ownership_git_dir/gitswitch-release-publish.lock" ] ||
    fail "successful distcheck retained the release mutex"

# The validator signals its immediate publisher parent only after it has read
# the archive and proved the live lock generation. The helper must forward the
# fatal transition, publish no canonical output, preserve unrelated names, and
# let the outer lock supervisor retire its mutex.
rm -f "$ownership_marker" "$ownership_capture"
if GITSWITCH_L42_MARKER="$ownership_marker" \
   GITSWITCH_L42_CAPTURE="$ownership_capture" \
   GITSWITCH_L42_SIGNAL_PARENT=1 \
    "$make_cmd" -C "$ownership_repo" distcheck >"$out" 2>&1; then
    fail "signalled private distcheck unexpectedly succeeded"
fi
[ "$(sed -n '1p' "$ownership_marker")" = signal-ready ] ||
    fail "private distcheck signal fixture missed its locked boundary"
[ -s "$ownership_capture" ] ||
    fail "signalled private distcheck received an empty archive"
cmp -s "$ownership_archive_before" "$ownership_archive" ||
    fail "signalled private distcheck changed the canonical sentinel"
cmp -s "$ownership_before" "$ownership_sibling" ||
    fail "signalled private distcheck changed an unrelated sibling"
[ ! -e "$ownership_git_dir/gitswitch-release-publish.lock" ] &&
    [ ! -L "$ownership_git_dir/gitswitch-release-publish.lock" ] ||
    fail "signalled private distcheck retained the release mutex"

printf 'qa-contract: PASS (QA failures, private archives, and borrowed inputs)\n'
