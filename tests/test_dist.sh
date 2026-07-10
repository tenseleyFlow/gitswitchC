#!/bin/sh
# Validate the generated source archive in a VCS-free, isolated directory.

set -eu

fail()
{
    printf 'distcheck: ERROR: %s\n' "$*" >&2
    exit 1
}

# `make distcheck` creates the archive before entering this script. Install the
# exit trap before validating any caller-supplied value so every success and
# failure path removes that generated artifact. `tmp` remains empty until
# mktemp succeeds, making the same cleanup safe for early validation failures.
archive=${1-}
tmp=
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    if [ -n "$tmp" ]; then
        rm -rf "$tmp"
    fi
    if [ -n "$archive" ]; then
        rm -f "$archive"
    fi
    exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

if [ "$#" -ne 4 ]; then
    fail "usage: $0 ARCHIVE DIST_ROOT PREFIX MAKE"
fi

dist_root=$2
prefix=$3
make_cmd=$4

[ -f "$archive" ] || fail "archive not found: $archive"
case $prefix in
    /*) ;;
    *) fail "PREFIX must be absolute: $prefix" ;;
esac

# Count COMMITTED tests via git ls-files, not the live filesystem: dist now
# archives HEAD (AR-05 L5), so an untracked stray under tests/ must neither
# ship nor skew this baseline — with a filesystem count, the same dirty tree
# was counted on both sides and contamination was undetectable.
git rev-parse --git-dir >/dev/null 2>&1 || fail "distcheck requires a git checkout"
checkout_test_count=$(git ls-files 'tests/test_*.c' | wc -l)
[ "$checkout_test_count" -gt 0 ] || fail "no committed C tests discovered"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-distcheck.XXXXXX")

members=$tmp/archive-members.txt
tar -tzf "$archive" >"$members"

root_entries=$(grep -Ec "^${dist_root}/?$" "$members" || true)
[ "$root_entries" -eq 1 ] || fail "archive must contain exactly one top-level $dist_root directory"
if grep -Ev "^${dist_root}(/|$)" "$members" >/dev/null; then
    fail "archive contains a member outside $dist_root"
fi
if LC_ALL=C sort "$members" | uniq -d | grep . >/dev/null; then
    fail "archive contains duplicate member names"
fi
if grep -E '(^|/)(\.git|\.omx)(/|$)|(^|/)build(/|$)|\.(o|core|tar\.gz)$|(^|/)valgrind[^/]*\.log$' "$members" >/dev/null; then
    fail "archive contains excluded build, VCS, OMX, core, log, or archive content"
fi

tar -xzf "$archive" -C "$tmp"
source_root=$tmp/$dist_root

for required in src tests completions VERSION LICENSE README.md Makefile gitswitcher.spec; do
    [ -e "$source_root/$required" ] || fail "required manifest entry missing: $required"
done
for completion in gitswitch.bash gitswitch.zsh gitswitch.fish; do
    [ -f "$source_root/completions/$completion" ] || fail "completion missing: $completion"
done

archive_test_count=0
for source in "$source_root"/tests/test_*.c; do
    [ -f "$source" ] || continue
    archive_test_count=$((archive_test_count + 1))
done
[ "$archive_test_count" -gt 0 ] || fail "archive contains no C tests"
[ "$archive_test_count" -eq "$checkout_test_count" ] ||
    fail "archive test count $archive_test_count differs from checkout count $checkout_test_count"

expected_version=$(sed -n '1p' "$source_root/VERSION")
[ -n "$expected_version" ] || fail "VERSION is empty"

"$make_cmd" -C "$source_root" BUILD_TYPE=debug test

built_test_count=0
for binary in "$source_root"/build/bin/test_*; do
    [ -x "$binary" ] || continue
    built_test_count=$((built_test_count + 1))
done
[ "$built_test_count" -eq "$checkout_test_count" ] ||
    fail "built test count $built_test_count differs from checkout count $checkout_test_count"

"$make_cmd" -C "$source_root" clean
"$make_cmd" -C "$source_root" BUILD_TYPE=release all

# AR-05 L9: assert the hardening properties the Makefile claims. PIE and
# RELRO/NOW were previously inherited from the host toolchain's defaults with
# no post-build check, so a non-default-PIE compiler could ship an
# ASLR-defeating binary with QA green.
release_bin=$source_root/build/bin/gitswitch
if command -v readelf >/dev/null 2>&1; then
    readelf -h "$release_bin" | grep -Eq 'Type:[[:space:]]+DYN' ||
        fail "release binary is not PIE (ET_DYN)"
    readelf -d "$release_bin" | grep -Eq 'BIND_NOW|FLAGS(_1)?.*\bNOW\b' ||
        fail "release binary lacks BIND_NOW"
    readelf -l "$release_bin" | grep -q 'GNU_RELRO' ||
        fail "release binary lacks GNU_RELRO"
    # -W: without wide mode readelf truncates long names to "[...]", hiding
    # __stack_chk_fail entirely.
    readelf -W --dyn-syms "$release_bin" | grep -q '__stack_chk_fail' ||
        fail "release binary lacks stack-protector instrumentation"
else
    printf 'distcheck: readelf not available - hardening assertions skipped\n'
fi

version_output=$("$release_bin" --version)
case $version_output in
    *" $expected_version ("*) ;;
    *) fail "binary version '$version_output' does not contain VERSION '$expected_version'" ;;
esac

stage=$tmp/stage
"$make_cmd" -C "$source_root" BUILD_TYPE=release install DESTDIR="$stage" PREFIX="$prefix"

[ -x "$stage$prefix/bin/gitswitch" ] || fail "installed binary missing"
[ -f "$stage$prefix/share/bash-completion/completions/gitswitch" ] ||
    fail "installed Bash completion missing"
[ -f "$stage$prefix/share/zsh/site-functions/_gitswitch" ] ||
    fail "installed zsh completion missing"
[ -f "$stage$prefix/share/fish/vendor_completions.d/gitswitch.fish" ] ||
    fail "installed fish completion missing"

# AR-05 L17: the H4 manifest fix exists because the source archive once could
# not satisfy its own RPM spec (%install ran make install against missing
# completions). When rpmbuild is available, prove the archive still can:
# build the RPM from the archive + extracted spec in an isolated _topdir.
# --nodeps: BuildRequires resolution needs an rpmdb that non-RPM CI hosts do
# not have; the property under test is the spec's %build/%install/%files
# contract against the archive, not dependency metadata. Absence is recorded
# explicitly, never misreported as an executed success.
if command -v rpmbuild >/dev/null 2>&1; then
    rpmtop=$tmp/rpmbuild
    mkdir -p "$rpmtop/BUILD" "$rpmtop/RPMS" "$rpmtop/SOURCES" \
        "$rpmtop/SPECS" "$rpmtop/SRPMS"
    cp "$archive" "$rpmtop/SOURCES/"
    cp "$source_root/gitswitcher.spec" "$rpmtop/SPECS/"
    if ! rpmbuild --define "_topdir $rpmtop" --nodeps -ba \
        "$rpmtop/SPECS/gitswitcher.spec" >"$tmp/rpmbuild.log" 2>&1; then
        tail -40 "$tmp/rpmbuild.log" >&2
        fail "source archive cannot satisfy gitswitcher.spec under rpmbuild"
    fi
    rpm_count=0
    for built_rpm in "$rpmtop"/RPMS/*/*.rpm; do
        [ -f "$built_rpm" ] || continue
        rpm_count=$((rpm_count + 1))
    done
    [ "$rpm_count" -ge 1 ] || fail "rpmbuild reported success but produced no binary RPM"
    rpm_status="rpmbuild OK"
else
    printf 'distcheck: rpmbuild not available - RPM build skipped\n'
    rpm_status="rpmbuild skipped"
fi

printf 'distcheck: PASS (%s C tests, version %s, complete staged install, %s)\n' \
    "$checkout_test_count" "$expected_version" "$rpm_status"
