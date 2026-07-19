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

if [ "$#" -lt 6 ] || [ "$5" != -- ]; then
    fail "usage: $0 ARCHIVE DIST_ROOT PREFIX MAKE -- MANIFEST_PATH [PATH ...]"
fi

dist_root=$2
prefix=$3
make_cmd=$4
shift 5

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

# The executable-trust boundary rejects every helper below sticky /tmp even
# when a deeper mktemp leaf is 0700.  Distcheck builds and runs every test
# binary from its extraction tree, and several suites deliberately re-exec
# their own binary; putting that tree under /tmp would make a valid production
# rejection look like a test failure.  Use the operator's private HOME
# ancestry intentionally (not TMPDIR, whose conventional default is /tmp).
case ${HOME-} in
    /*) ;;
    *) fail "distcheck requires an absolute HOME for its trusted build root" ;;
esac
[ -d "$HOME" ] || fail "HOME is not a directory: $HOME"
tmp=$(mktemp -d "$HOME/.gitswitch-distcheck.XXXXXX")
chmod 0700 "$tmp" || fail "cannot make distcheck build root private"

members=$tmp/archive-members.txt
gzip -t "$archive" || fail "archive is not a complete gzip stream"
tar -tzf "$archive" >"$members" || fail "cannot list archive members"

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

# AR-11 M40: membership must equal the selected commit manifest exactly, not
# merely contain a short required subset. Directory headers are archive
# structure; every non-directory member must correspond one-for-one to a blob
# or symlink selected from the immutable release commit.
expected_members=$tmp/expected-members.txt
expected_paths=$tmp/expected-paths.txt
expected_prefixed=$tmp/expected-prefixed.txt
actual_members=$tmp/actual-members.txt
actual_unsorted=$tmp/actual-members-unsorted.txt
git ls-tree -r --name-only HEAD -- "$@" >"$expected_paths" ||
    fail "cannot derive exact committed release manifest"
sed "s#^#${dist_root}/#" <"$expected_paths" >"$expected_prefixed" ||
    fail "cannot prefix exact committed release manifest"
LC_ALL=C sort "$expected_prefixed" >"$expected_members" ||
    fail "cannot sort exact committed release manifest"
grep -v '/$' "$members" >"$actual_unsorted" ||
    fail "cannot normalize archive member manifest"
LC_ALL=C sort "$actual_unsorted" >"$actual_members" ||
    fail "cannot sort archive member manifest"
cmp -s "$expected_members" "$actual_members" ||
    fail "archive members differ from the exact committed release manifest"

tar -xzf "$archive" -C "$tmp"
source_root=$tmp/$dist_root

for required in src tests completions VERSION LICENSE README.md Makefile gitswitcher.spec; do
    [ -e "$source_root/$required" ] || fail "required manifest entry missing: $required"
done
# Release publication is built before distcheck enters the archive, so a
# mutable DIST_MANIFEST could omit its source without breaking the ordinary
# debug/release build below. Keep this independent completeness assertion tied
# to the release operation that a consumer of the archive must reproduce.
[ -f "$source_root/tools/release_publish.c" ] ||
    fail "required release publisher source missing: tools/release_publish.c"
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
[ "$dist_root" = "gitswitcher-$expected_version" ] ||
    fail "archive root $dist_root disagrees with VERSION $expected_version"
spec_version=$(sed -n 's/^Version:[[:space:]]*//p' \
    "$source_root/gitswitcher.spec" | sed -n '1p')
[ "$spec_version" = "$expected_version" ] ||
    fail "RPM spec Version $spec_version disagrees with VERSION $expected_version"

"$make_cmd" -C "$source_root" BUILD_TYPE=debug test

built_test_count=0
for binary in "$source_root"/build/bin/test_*; do
    [ -x "$binary" ] || continue
    # test_public_api.c deliberately links twice: once with the testing API
    # surface and once against the production-only surface. Count the latter
    # independently so the one-source/one-primary-binary manifest invariant
    # remains exact without rejecting that required second link profile.
    case ${binary##*/} in
        test_public_api_production) continue ;;
    esac
    built_test_count=$((built_test_count + 1))
done
[ "$built_test_count" -eq "$checkout_test_count" ] ||
    fail "built test count $built_test_count differs from checkout count $checkout_test_count"
[ -x "$source_root/build/bin/test_public_api_production" ] ||
    fail "production public-API link test was not built"

"$make_cmd" -C "$source_root" clean
"$make_cmd" -C "$source_root" BUILD_TYPE=release all

release_bin=$source_root/build/bin/gitswitch
version_output=$("$release_bin" --version)
case $version_output in
    *" $expected_version ("*) ;;
    *) fail "binary version '$version_output' does not contain VERSION '$expected_version'" ;;
esac

# AR-11 M39: exercise the same atomic staged-install boundary from the
# extracted, commit-pinned source tree consumed by RPM %install. The focused
# mode rejects a corrupted private copy and proves a post-validation source
# replacement cannot change the bytes ultimately published.
sh "$source_root/tests/test_ar07_release.sh" install "$source_root" \
    "$make_cmd" "$release_bin" "$source_root/build" "$prefix"

stage=$tmp/stage
"$make_cmd" -C "$source_root" BUILD_TYPE=release install DESTDIR="$stage" PREFIX="$prefix"

[ -x "$stage$prefix/bin/gitswitch" ] || fail "installed binary missing"
[ -f "$stage$prefix/share/bash-completion/completions/gitswitch" ] ||
    fail "installed Bash completion missing"
[ -f "$stage$prefix/share/zsh/site-functions/_gitswitch" ] ||
    fail "installed zsh completion missing"
[ -f "$stage$prefix/share/fish/vendor_completions.d/gitswitch.fish" ] ||
    fail "installed fish completion missing"

# Inspect both the exact release artifact and its byte-identical staged copy.
# The helper selects native ELF checks on Linux/FreeBSD and Mach-O checks on
# Darwin, so platform CI exercises the flags selected by that platform branch.
sh "$source_root/tests/test_ar07_release.sh" artifact "$release_bin" \
    "$stage$prefix/bin/gitswitch"

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
    # AR-06 F80: "an .rpm exists" is far too weak — a spec that packaged an
    # empty %files, or dropped the binary/completions, would still emit an RPM
    # and pass. Locate the MAIN package RPM (skip -debuginfo/-debugsource/-devel
    # subpackages) and assert its payload actually carries every path the spec's
    # %files promises. rpm -qlp lists the archived paths without installing.
    rpm_count=0
    main_rpm=
    for built_rpm in "$rpmtop"/RPMS/*/*.rpm; do
        [ -f "$built_rpm" ] || continue
        rpm_count=$((rpm_count + 1))
        case ${built_rpm##*/} in
            *-debuginfo-*|*-debugsource-*|*-devel-*) ;;
            *) main_rpm=$built_rpm ;;
        esac
    done
    [ "$rpm_count" -ge 1 ] || fail "rpmbuild reported success but produced no binary RPM"
    [ -n "$main_rpm" ] || fail "rpmbuild produced only debug/devel subpackages, no main RPM"

    payload=$(rpm -qlp "$main_rpm" 2>/dev/null) ||
        fail "cannot list payload of $main_rpm"
    for want in \
        /usr/bin/gitswitch \
        /usr/share/bash-completion/completions/gitswitch \
        /usr/share/zsh/site-functions/_gitswitch \
        /usr/share/fish/vendor_completions.d/gitswitch.fish; do
        printf '%s\n' "$payload" | grep -Fx -- "$want" >/dev/null ||
            fail "built RPM payload is missing $want"
    done
    if printf '%s\n' "$payload" | grep -E '^/usr/local(/|$)' >/dev/null; then
        fail "built RPM payload incorrectly owns /usr/local content"
    fi
    license_payload=$(rpm -qL -p "$main_rpm" 2>/dev/null) ||
        fail "cannot query license ownership of $main_rpm"
    documentation_payload=$(rpm -qd -p "$main_rpm" 2>/dev/null) ||
        fail "cannot query documentation ownership of $main_rpm"
    package_name=$(rpm -qp --qf '%{NAME}' "$main_rpm" 2>/dev/null) ||
        fail "cannot query package name of $main_rpm"
    package_version=$(rpm -qp --qf '%{VERSION}' "$main_rpm" 2>/dev/null) ||
        fail "cannot query package version of $main_rpm"
    license_path=
    for owned_path in $license_payload; do
        case $owned_path in
            "/usr/share/licenses/$package_name/LICENSE"|\
            "/usr/share/licenses/$package_name-$package_version/LICENSE")
                [ -z "$license_path" ] ||
                    fail "built RPM declares LICENSE more than once"
                license_path=$owned_path
                ;;
        esac
    done
    [ -n "$license_path" ] ||
        fail "built RPM does not declare LICENSE with %license under /usr"
    documentation_path=
    for owned_path in $documentation_payload; do
        case $owned_path in
            "/usr/share/doc/$package_name/README.md"|\
            "/usr/share/doc/$package_name-$package_version/README.md")
                [ -z "$documentation_path" ] ||
                    fail "built RPM declares README.md more than once"
                documentation_path=$owned_path
                ;;
        esac
    done
    [ -n "$documentation_path" ] ||
        fail "built RPM does not declare README.md with %doc under /usr"
    for metadata_path in "$license_path" "$documentation_path"; do
        printf '%s\n' "$payload" | grep -Fx -- "$metadata_path" >/dev/null ||
            fail "built RPM metadata path is absent from its payload: $metadata_path"
    done
    requirements=$(rpm -qp --requires "$main_rpm" 2>/dev/null) ||
        fail "cannot query runtime requirements of $main_rpm"
    printf '%s\n' "$requirements" | grep -E '^libreadline\.so' >/dev/null ||
        fail "built RPM does not link the explicitly required Readline feature"
    for required_command in /usr/bin/gpg /usr/bin/gpgconf; do
        printf '%s\n' "$requirements" | grep -Fx "$required_command" >/dev/null ||
            fail "built RPM does not require $required_command"
    done

    # Metadata presence alone does not prove RPM's transaction solver enforces
    # these file requirements. Test-install into a deliberately empty root and
    # require dependency resolution to reject the package while naming both
    # missing commands. --test performs no installation.
    rpm_root=$tmp/rpm-empty-root
    rpm_db=/var/lib/rpm
    mkdir -p "$rpm_root$rpm_db"
    if ! rpm --root "$rpm_root" --dbpath "$rpm_db" --initdb \
        >"$tmp/rpm-initdb.log" 2>&1; then
        cat "$tmp/rpm-initdb.log" >&2
        fail "cannot initialize isolated empty RPM database"
    fi
    if LC_ALL=C rpm --root "$rpm_root" --dbpath "$rpm_db" --test \
        -i "$main_rpm" >"$tmp/rpm-transaction.log" 2>&1; then
        fail "built RPM installed into an empty root despite runtime dependencies"
    fi
    grep -F 'Failed dependencies:' "$tmp/rpm-transaction.log" >/dev/null || {
        cat "$tmp/rpm-transaction.log" >&2
        fail "empty-root RPM transaction failed before dependency resolution"
    }
    for required_command in /usr/bin/gpg /usr/bin/gpgconf; do
        grep -F "$required_command is needed by" \
            "$tmp/rpm-transaction.log" >/dev/null || {
            cat "$tmp/rpm-transaction.log" >&2
            fail "empty-root transaction did not enforce $required_command"
        }
    done
    rpm_status="rpmbuild OK, payload and enforced GPG dependencies verified"
else
    printf 'distcheck: rpmbuild not available - RPM build skipped\n'
    rpm_status="rpmbuild skipped"
fi

printf 'distcheck: PASS (%s C tests, version %s, complete staged install, %s)\n' \
    "$checkout_test_count" "$expected_version" "$rpm_status"
