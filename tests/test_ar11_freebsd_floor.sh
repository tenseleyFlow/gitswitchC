#!/bin/sh
# AR-11 M23: the declared FreeBSD floor must match the hosted compatibility
# gate, compile with its required APIs, and reject older headers deliberately.

set -eu
LC_ALL=C
export LC_ALL

fail()
{
    printf 'freebsd floor contract: ERROR: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail "usage: $0 REPOSITORY_ROOT"
root=$(CDPATH='' cd -- "$1" && pwd -P) || fail "cannot enter repository root"
contract=$root/src/freebsd_compat.h
workflow=$root/.github/workflows/ci.yml
cc_command=${FREEBSD_CONTRACT_CC:-cc}
freebsd_cppflag=-D__FreeBSD__
case $(uname -s) in
    FreeBSD) freebsd_cppflag= ;;
esac

[ -f "$contract" ] || fail "missing FreeBSD compatibility contract"
[ -f "$workflow" ] || fail "missing hosted CI workflow"
grep -F '#include "freebsd_compat.h"' "$root/src/gitswitch.h" >/dev/null ||
    fail "application headers do not consume the FreeBSD floor contract"
grep -F '#include "../src/freebsd_compat.h"' \
    "$root/tools/release_publish.c" >/dev/null ||
    fail "release publisher does not consume the FreeBSD floor contract"

min_version=$(sed -n \
    's/^#define GITSWITCH_FREEBSD_MIN_VERSION \([0-9][0-9]*\)$/\1/p' \
    "$contract")
min_release=$(sed -n \
    's/^#define GITSWITCH_FREEBSD_MIN_RELEASE "\([0-9][0-9.]*\)"$/\1/p' \
    "$contract")
ci_release=$(sed -n \
    "s/^[[:space:]]*version:[[:space:]]*'\([^']*\)'[[:space:]]*$/\1/p" \
    "$workflow")

case $min_version in
    ''|*[!0-9]*) fail "minimum __FreeBSD_version is missing or ambiguous" ;;
esac
[ -n "$min_release" ] || fail "minimum release label is missing"
[ "$ci_release" = "$min_release" ] ||
    fail "hosted FreeBSD $ci_release does not exercise declared floor $min_release"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-freebsd-floor.XXXXXX") ||
    fail "cannot create temporary directory"
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    rm -rf "$tmp"
    exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

probe=$tmp/probe.c
printf '%s\n' \
    '#include "freebsd_compat.h"' \
    'int main(void) { return 0; }' >"$probe"

make_headers()
{
    destination=$1
    version=$2
    opath=$3
    mkdir -p "$destination/sys"
    if [ "$version" = missing ]; then
        printf '%s\n' '/* deliberately missing __FreeBSD_version */' \
            >"$destination/sys/param.h"
    else
        printf '#define __FreeBSD_version %s\n' "$version" \
            >"$destination/sys/param.h"
    fi
    if [ "$opath" = present ]; then
        printf '%s\n' \
            '#if !defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)' \
            '#define O_PATH 0x00400000' \
            '#endif' >"$destination/fcntl.h"
    else
        printf '%s\n' '/* deliberately missing O_PATH */' \
            >"$destination/fcntl.h"
    fi
}

compile_probe()
{
    compile_source "$probe" "$@"
}

compile_source()
{
    source=$1
    headers=$2
    output=$3
    log=$4
    set -f
    # FREEBSD_CONTRACT_CC deliberately follows Make's compiler selection.
    # Word splitting permits the same launcher-plus-compiler form as CC.
    # shellcheck disable=SC2086
    $cc_command -std=c11 -Wall -Wextra -Werror $freebsd_cppflag \
        -I"$headers" -I"$root/src" "$source" -o "$output" \
        >"$log.stdout" 2>"$log.stderr"
}

expect_rejected()
{
    headers=$1
    label=$2
    diagnostic=$3
    log=$tmp/$label
    if compile_probe "$headers" "$tmp/$label.bin" "$log"; then
        fail "$label headers were accepted"
    fi
    if ! grep -F "$diagnostic" "$log.stderr" >/dev/null; then
        cat "$log.stderr" >&2
        fail "$label headers lacked the required diagnostic"
    fi
}

minimum_headers=$tmp/minimum
newer_headers=$tmp/newer
old_headers=$tmp/old
missing_version_headers=$tmp/missing-version
missing_opath_headers=$tmp/missing-opath
make_headers "$minimum_headers" "$min_version" present
make_headers "$newer_headers" 1501000 present
make_headers "$old_headers" "$((min_version - 1000))" present
make_headers "$missing_version_headers" missing present
make_headers "$missing_opath_headers" "$min_version" missing

if ! compile_probe "$minimum_headers" "$tmp/minimum.bin" "$tmp/minimum"; then
    cat "$tmp/minimum.stderr" >&2
    fail "declared minimum headers do not compile"
fi
"$tmp/minimum.bin" || fail "declared minimum probe failed"
if ! compile_probe "$newer_headers" "$tmp/newer.bin" "$tmp/newer"; then
    cat "$tmp/newer.stderr" >&2
    fail "newer supported headers do not compile"
fi
"$tmp/newer.bin" || fail "newer supported probe failed"

# Reproduce the real application prologues rather than testing only the
# compatibility header in isolation. FreeBSD's O_PATH is in the default BSD
# namespace, so a source that selects strict POSIX/XSI before project headers
# would hide the required API even on the declared release floor.
for production_source in "$root/src/accounts.c" "$root/src/publication.c"; do
    source_name=${production_source##*/}
    source_probe=$tmp/$source_name.probe.c
    sed '/^#include /,$d' "$production_source" >"$source_probe" ||
        fail "cannot extract $source_name feature-selection prologue"
    printf '%s\n' '#include "freebsd_compat.h"' \
        'int main(void) { return 0; }' >>"$source_probe"
    if ! compile_source "$source_probe" "$minimum_headers" \
        "$tmp/$source_name.bin" "$tmp/$source_name"; then
        cat "$tmp/$source_name.stderr" >&2
        fail "$source_name hides required FreeBSD APIs"
    fi
    "$tmp/$source_name.bin" || fail "$source_name feature probe failed"
done

expect_rejected "$old_headers" old-release \
    "gitswitch requires FreeBSD $min_release or newer"
expect_rejected "$missing_version_headers" missing-version \
    "gitswitch requires <sys/param.h> to define __FreeBSD_version"
expect_rejected "$missing_opath_headers" missing-O_PATH \
    "gitswitch requires FreeBSD headers exposing O_PATH"

printf 'FreeBSD floor contract passed: %s (__FreeBSD_version %s)\n' \
    "$min_release" "$min_version"
