#!/bin/sh
# AR-07 T18 release-input and native artifact contracts.

set -eu

fail()
{
    printf 'ar07-release: ERROR: %s\n' "$*" >&2
    exit 1
}

check_elf()
{
    binary=$1
    readelf_cmd=${READELF-}
    if [ -n "$readelf_cmd" ]; then
        if [ ! -x "$readelf_cmd" ] &&
            ! command -v "$readelf_cmd" >/dev/null 2>&1; then
            fail "configured readelf is unavailable: $readelf_cmd"
        fi
    else
        for candidate in readelf llvm-readelf greadelf; do
            if command -v "$candidate" >/dev/null 2>&1; then
                readelf_cmd=$candidate
                break
            fi
        done
    fi
    [ -n "$readelf_cmd" ] ||
        fail "readelf (GNU, LLVM, or FreeBSD) is required to inspect $binary"

    elf_header=$("$readelf_cmd" -h "$binary") ||
        fail "readelf could not read ELF header: $binary"
    printf '%s\n' "$elf_header" | grep -Eq 'Type:[[:space:]]+DYN' ||
        fail "release binary is not PIE (ET_DYN): $binary"

    elf_dynamic=$("$readelf_cmd" -d "$binary") ||
        fail "readelf could not read dynamic section: $binary"
    printf '%s\n' "$elf_dynamic" |
        grep -Eq 'BIND_NOW|FLAGS(_1)?[[:space:]].*NOW' ||
        fail "release binary lacks immediate binding (NOW): $binary"

    elf_programs=$("$readelf_cmd" -W -l "$binary") ||
        fail "readelf could not read program headers: $binary"
    printf '%s\n' "$elf_programs" | grep -q 'GNU_RELRO' ||
        fail "release binary lacks GNU_RELRO: $binary"
    elf_stack=$(printf '%s\n' "$elf_programs" |
        awk '$1 == "GNU_STACK" { print; found = 1 } END { if (!found) exit 1 }') ||
        fail "release binary lacks a GNU_STACK program header: $binary"
    case $elf_stack in
        *RWE*) fail "release binary requests an executable stack: $binary" ;;
    esac

    # FreeBSD base readelf does not implement GNU --dyn-syms. The portable
    # short form lists every available symbol table, including .dynsym in a
    # stripped release executable.
    elf_symbols=$("$readelf_cmd" -W -s "$binary") ||
        fail "readelf could not read symbols: $binary"
    printf '%s\n' "$elf_symbols" | grep -q '__stack_chk_fail' ||
        fail "release binary lacks stack-protector instrumentation: $binary"
}

check_macho()
{
    binary=$1
    command -v otool >/dev/null 2>&1 ||
        fail "otool is required to inspect $binary"
    command -v nm >/dev/null 2>&1 ||
        fail "nm is required to inspect $binary"

    macho_header=$(otool -hv "$binary") ||
        fail "otool could not read Mach-O header: $binary"
    printf '%s\n' "$macho_header" |
        grep -Eq '(^|[[:space:]])PIE([[:space:]]|$)' ||
        fail "release binary lacks the Mach-O PIE flag: $binary"
    if printf '%s\n' "$macho_header" | grep -q 'ALLOW_STACK_EXECUTION'; then
        fail "release binary permits an executable stack: $binary"
    fi

    macho_symbols=$(nm -u "$binary") ||
        fail "nm could not read undefined symbols: $binary"
    printf '%s\n' "$macho_symbols" | grep -q 'stack_chk_fail' ||
        fail "release binary lacks stack-protector instrumentation: $binary"
}

check_artifact_pair()
{
    [ "$#" -eq 2 ] ||
        fail "usage: $0 artifact BUILT_BINARY STAGED_BINARY"
    built=$1
    staged=$2

    [ -x "$built" ] || fail "built release binary is missing: $built"
    [ -x "$staged" ] || fail "staged release binary is missing: $staged"
    cmp -s "$built" "$staged" ||
        fail "staged binary is not byte-identical to the inspected build"

    built_version=$("$built" --version) || fail "built binary --version failed"
    staged_version=$("$staged" --version) || fail "staged binary --version failed"
    [ "$built_version" = "$staged_version" ] ||
        fail "built and staged binaries report different versions"

    platform=$(uname -s)
    case $platform in
        Linux|FreeBSD)
            check_elf "$built"
            check_elf "$staged"
            ;;
        Darwin)
            check_macho "$built"
            check_macho "$staged"
            ;;
        *)
            fail "unsupported artifact-inspection platform: $platform"
            ;;
    esac

    printf 'ar07-release: PASS (%s built and staged artifacts verified)\n' \
        "$platform"
}

expect_artifact_rejection()
{
    label=$1
    script=$2
    built=$3
    staged=$4
    expected=$5
    out=$6

    if sh "$script" artifact "$built" "$staged" >"$out" 2>&1; then
        fail "$label fixture was accepted by the release artifact checker"
    fi
    grep -Eq "$expected" "$out" || {
        printf '%s\n' "$(cat "$out")" >&2
        fail "$label fixture failed for an unrelated reason"
    }
}

check_neuter_contract()
{
    [ "$#" -eq 2 ] ||
        fail "usage: $0 neuter COMPILER RELEASE_SECURITY_CFLAGS"
    compiler=$1
    release_security_cflags=$2
    command -v "$compiler" >/dev/null 2>&1 ||
        fail "neuter compiler is unavailable: $compiler"

    # This assertion is intentionally coupled to the Makefile's real release
    # compile flags. Artifact inspection cannot portably observe FORTIFY on all
    # supported libcs, so removing the requested level from the build recipe
    # must instead break this compile-intent contract.
    fortify_define=
    for release_flag in $release_security_cflags; do
        case $release_flag in
            -D_FORTIFY_SOURCE=2) fortify_define=$release_flag ;;
        esac
    done
    [ "$fortify_define" = "-D_FORTIFY_SOURCE=2" ] ||
        fail "release compile flags do not request _FORTIFY_SOURCE=2"

    script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd) ||
        fail "cannot resolve release-check script directory"
    script=$script_dir/$(basename "$0")
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-release-neuter.XXXXXX") ||
        fail "cannot create temporary hardening-neuter directory"
    cleanup()
    {
        status=$?
        trap - 0 1 2 3 15
        rm -rf "$tmp"
        exit "$status"
    }
    trap cleanup 0
    trap 'exit 1' 1 2 3 15

    source_file=$tmp/neuter.c
    printf '%s\n' \
        '#include <stdio.h>' \
        'int main(int argc, char **argv)' \
        '{' \
        '    volatile char canary_witness[64];' \
        '    (void)argv;' \
        '    canary_witness[0] = (char)argc;' \
        '    puts("gitswitch-neuter 0.0.0");' \
        '    return canary_witness[0] == 127;' \
        '}' >"$source_file"

    fortify_source=$tmp/fortify.c
    printf '%s\n' \
        '#ifndef _FORTIFY_SOURCE' \
        '#error AR07_FORTIFY_REQUIRED' \
        '#elif _FORTIFY_SOURCE < 2' \
        '#error AR07_FORTIFY_LEVEL_TOO_LOW' \
        '#endif' \
        '#include <string.h>' \
        'int ar07_fortify_witness(char *dest, const char *source)' \
        '{' \
        '    strcpy(dest, source);' \
        '    return dest[0];' \
        '}' >"$fortify_source"

    # Prove the witness is genuinely mutation-sensitive before accepting the
    # configured positive compile. A compiler that accepts the source without
    # the release define would make the contract vacuous.
    # Some hosted toolchains inject a distro-default FORTIFY level through
    # compiler specs. Explicitly undefine it so this negative control measures
    # the Makefile flag we own, not ambient compiler policy. The positive
    # control applies the audited definition after the undefine.
    if "$compiler" -std=c11 -O2 -U_FORTIFY_SOURCE -c "$fortify_source" \
        -o "$tmp/fortify-neutered.o" >"$tmp/fortify-neutered.log" 2>&1; then
        fail "FORTIFY-neutered compile fixture was accepted"
    fi
    grep -F 'AR07_FORTIFY_REQUIRED' "$tmp/fortify-neutered.log" >/dev/null || {
        cat "$tmp/fortify-neutered.log" >&2
        fail "FORTIFY-neutered fixture failed for an unrelated reason"
    }
    if ! "$compiler" -std=c11 -O2 -U_FORTIFY_SOURCE "$fortify_define" \
        -c "$fortify_source" \
        -o "$tmp/fortify-enabled.o" >"$tmp/fortify-enabled.log" 2>&1; then
        cat "$tmp/fortify-enabled.log" >&2
        fail "configured FORTIFY compile intent is not accepted by the compiler"
    fi

    platform=$(uname -s)
    nonpie=$tmp/neuter-nonpie
    nocanary=$tmp/neuter-no-canary
    norelro=$tmp/neuter-no-relro
    nonow=$tmp/neuter-no-now
    execstack=$tmp/neuter-exec-stack
    have_nonpie_neuter=false
    have_execstack_neuter=false
    case $platform in
        Linux|FreeBSD)
            if ! "$compiler" -std=c11 -O0 -fno-stack-protector -fno-pie \
                "$source_file" -no-pie -o "$nonpie" >"$tmp/nonpie.log" 2>&1; then
                cat "$tmp/nonpie.log" >&2
                fail "cannot build ELF non-PIE neuter fixture"
            fi
            have_nonpie_neuter=true
            if ! "$compiler" -std=c11 -O0 -fno-stack-protector -fPIE \
                "$source_file" -pie -Wl,-z,relro -Wl,-z,now \
                -Wl,-z,noexecstack -o "$nocanary" \
                >"$tmp/nocanary.log" 2>&1; then
                cat "$tmp/nocanary.log" >&2
                fail "cannot build ELF no-canary neuter fixture"
            fi
            if ! "$compiler" -std=c11 -O0 -fstack-protector-strong -fPIE \
                "$source_file" -pie -Wl,-z,norelro -Wl,-z,now \
                -Wl,-z,noexecstack -o "$norelro" \
                >"$tmp/norelro.log" 2>&1; then
                cat "$tmp/norelro.log" >&2
                fail "cannot build ELF no-RELRO neuter fixture"
            fi
            if ! "$compiler" -std=c11 -O0 -fstack-protector-strong -fPIE \
                "$source_file" -pie -Wl,-z,relro -Wl,-z,lazy \
                -Wl,-z,noexecstack -o "$nonow" \
                >"$tmp/nonow.log" 2>&1; then
                cat "$tmp/nonow.log" >&2
                fail "cannot build ELF lazy-binding neuter fixture"
            fi
            if ! "$compiler" -std=c11 -O0 -fstack-protector-strong -fPIE \
                "$source_file" -pie -Wl,-z,relro -Wl,-z,now \
                -Wl,-z,execstack -o "$execstack" \
                >"$tmp/execstack.log" 2>&1; then
                cat "$tmp/execstack.log" >&2
                fail "cannot build ELF executable-stack neuter fixture"
            fi
            have_execstack_neuter=true
            ;;
        Darwin)
            # Apple ld forces arm64 dynamic executables to be PIE and accepts
            # -no_pie only with a warning. A real non-PIE negative fixture is
            # therefore constructible only on Intel Darwin; the positive PIE
            # assertion above still applies to every supported architecture.
            case $(uname -m) in
                x86_64|i386)
                    if ! "$compiler" -std=c11 -O0 -fno-stack-protector \
                        "$source_file" -Wl,-no_pie -o "$nonpie" \
                        >"$tmp/nonpie.log" 2>&1; then
                        cat "$tmp/nonpie.log" >&2
                        fail "cannot build Mach-O non-PIE neuter fixture"
                    fi
                    have_nonpie_neuter=true
                    ;;
                arm64|arm64e)
                    # There is no native negative artifact to construct: the
                    # architecture contract itself requires MH_PIE.
                    ;;
                *)
                    fail "unsupported Darwin architecture: $(uname -m)"
                    ;;
            esac
            if ! "$compiler" -std=c11 -O0 -fno-stack-protector \
                "$source_file" -Wl,-pie -o "$nocanary" \
                >"$tmp/nocanary.log" 2>&1; then
                cat "$tmp/nocanary.log" >&2
                fail "cannot build Mach-O no-canary neuter fixture"
            fi
            # Apple ld only accepts -allow_stack_execute on Intel targets.
            # arm64 kernels do not support this opt-out, so the positive
            # absence check remains applicable there but no negative binary
            # can be constructed with native supported linker options.
            case $(uname -m) in
                x86_64|i386)
                    if ! "$compiler" -std=c11 -O0 \
                        -fstack-protector-strong "$source_file" -Wl,-pie \
                        -Wl,-allow_stack_execute -o "$execstack" \
                        >"$tmp/execstack.log" 2>&1; then
                        cat "$tmp/execstack.log" >&2
                        fail "cannot build Mach-O executable-stack neuter fixture"
                    fi
                    have_execstack_neuter=true
                    ;;
            esac
            ;;
        *)
            fail "unsupported hardening-neuter platform: $platform"
            ;;
    esac

    if [ "$have_nonpie_neuter" = true ]; then
        cp "$nonpie" "$tmp/neuter-nonpie-staged"
        expect_artifact_rejection "non-PIE" "$script" "$nonpie" \
            "$tmp/neuter-nonpie-staged" \
            'not PIE|lacks the Mach-O PIE flag' "$tmp/nonpie-check.log"
    fi

    cp "$nocanary" "$tmp/neuter-no-canary-staged"
    expect_artifact_rejection "no-canary" "$script" "$nocanary" \
        "$tmp/neuter-no-canary-staged" \
        'lacks stack-protector instrumentation' "$tmp/nocanary-check.log"

    case $platform in
        Linux|FreeBSD)
            cp "$norelro" "$tmp/neuter-no-relro-staged"
            expect_artifact_rejection "no-RELRO" "$script" "$norelro" \
                "$tmp/neuter-no-relro-staged" \
                'lacks GNU_RELRO' "$tmp/norelro-check.log"

            cp "$nonow" "$tmp/neuter-no-now-staged"
            expect_artifact_rejection "lazy-binding" "$script" "$nonow" \
                "$tmp/neuter-no-now-staged" \
                'lacks immediate binding' "$tmp/nonow-check.log"
            ;;
    esac

    if [ "$have_execstack_neuter" = true ]; then
        cp "$execstack" "$tmp/neuter-exec-stack-staged"
        expect_artifact_rejection "executable-stack" "$script" "$execstack" \
            "$tmp/neuter-exec-stack-staged" \
            'requests an executable stack|permits an executable stack' \
            "$tmp/execstack-check.log"
    fi

    printf 'ar07-release: PASS (%s FORTIFY and artifact neuters rejected)\n' \
        "$platform"
}

assert_archive_metadata()
{
    archive=$1
    dist_root=$2
    version=$3

    [ -f "$archive" ] || fail "release archive not produced: $archive"
    members=$(tar -tzf "$archive") || fail "cannot list release archive"
    root_entries=$(printf '%s\n' "$members" |
        grep -Ec "^${dist_root}/?$" || true)
    [ "$root_entries" -eq 1 ] ||
        fail "archive does not contain exactly one $dist_root root entry"
    if printf '%s\n' "$members" | grep -Ev "^${dist_root}(/|$)" >/dev/null; then
        fail "archive contains a path outside $dist_root"
    fi

    embedded_version=$(tar -xOf "$archive" "$dist_root/VERSION") ||
        fail "cannot read archived VERSION"
    [ "$embedded_version" = "$version" ] ||
        fail "archive root/version mismatch: $dist_root contains $embedded_version"

    embedded_spec=$(tar -xOf "$archive" "$dist_root/gitswitcher.spec") ||
        fail "cannot read archived RPM spec"
    spec_version=$(printf '%s\n' "$embedded_spec" |
        sed -n 's/^Version:[[:space:]]*//p' | sed -n '1p')
    [ "$spec_version" = "$version" ] ||
        fail "archived spec Version $spec_version differs from VERSION $version"
    spec_requires=$(printf '%s\n' "$embedded_spec" |
        sed -n 's/^Requires:[[:space:]]*//p')
    for required_command in /usr/bin/gpg /usr/bin/gpgconf; do
        printf '%s\n' "$spec_requires" | grep -Fx "$required_command" >/dev/null ||
            fail "archived RPM spec does not require $required_command"
    done
}

expect_dirty_rejected()
{
    label=$1
    repo=$2
    make_cmd=$3
    archive=$4
    out=$5

    if "$make_cmd" -C "$repo" dist >"$out" 2>&1; then
        fail "$label release unexpectedly succeeded"
    fi
    grep -F 'ERROR: release manifest' "$out" >/dev/null ||
        fail "$label rejection did not identify the release manifest"
    [ ! -e "$archive" ] ||
        fail "$label rejection left a release archive behind"
}

check_manifest_contract()
{
    [ "$#" -eq 2 ] ||
        fail "usage: $0 manifest PROJECT_ROOT MAKE"
    root=$1
    make_cmd=$2
    root=$(cd "$root" && pwd) || fail "project root is unavailable: $root"
    git -C "$root" rev-parse --git-dir >/dev/null 2>&1 ||
        fail "manifest contract requires a git checkout"

    tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-release-contract.XXXXXX") ||
        fail "cannot create temporary release-contract directory"
    cleanup()
    {
        status=$?
        trap - 0 1 2 3 15
        rm -rf "$tmp"
        exit "$status"
    }
    trap cleanup 0
    trap 'exit 1' 1 2 3 15

    clean_repo=$tmp/clean
    git clone --quiet "$root" "$clean_repo" || fail "cannot clone clean HEAD"
    commit=$(git -C "$clean_repo" rev-parse --verify HEAD^{commit}) ||
        fail "cannot resolve cloned HEAD"
    version=$(git -C "$clean_repo" show "$commit:VERSION") ||
        fail "cannot read committed VERSION"
    dist_root=gitswitcher-$version
    archive=$clean_repo/$dist_root.tar.gz
    out=$tmp/make.out

    "$make_cmd" -C "$clean_repo" dist >"$out" 2>&1 ||
        fail "clean committed release failed"
    assert_archive_metadata "$archive" "$dist_root" "$version"

    # Developer VERSION/DIST_ROOT overrides must not rename committed payload.
    rm -f "$archive"
    "$make_cmd" -C "$clean_repo" VERSION=9.9.9-uncommitted \
        DIST_ROOT=gitswitcher-9.9.9-uncommitted dist >"$out" 2>&1 ||
        fail "commit-pinned release failed under irrelevant live overrides"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    [ ! -e "$clean_repo/gitswitcher-9.9.9-uncommitted.tar.gz" ] ||
        fail "VERSION/DIST_ROOT override renamed committed release payload"

    # The RPM target must consume the spec embedded in that same archive.
    shim_dir=$tmp/shims
    rpm_home=$tmp/rpm-home
    mkdir -p "$shim_dir" "$rpm_home"
    printf '%s\n' '#!/bin/sh' 'exit 0' >"$shim_dir/rpmbuild"
    chmod 0700 "$shim_dir/rpmbuild"
    HOME="$rpm_home" PATH="$shim_dir:$PATH" \
        "$make_cmd" -C "$clean_repo" rpm >"$out" 2>&1 ||
        fail "RPM source/spec consistency fixture failed"
    tar -xOf "$archive" "$dist_root/gitswitcher.spec" >"$tmp/archived.spec" ||
        fail "cannot extract archive spec for RPM comparison"
    cmp -s "$tmp/archived.spec" \
        "$rpm_home/rpmbuild/SPECS/gitswitcher.spec" ||
        fail "RPM target did not consume the archive-embedded spec"

    dirty_version=$tmp/dirty-version
    git clone --quiet "$root" "$dirty_version" || fail "cannot clone VERSION fixture"
    printf '%s\n' '9.9.9-dirty' >"$dirty_version/VERSION"
    expect_dirty_rejected "dirty VERSION" "$dirty_version" "$make_cmd" \
        "$dirty_version/$dist_root.tar.gz" "$out"

    dirty_spec=$tmp/dirty-spec
    git clone --quiet "$root" "$dirty_spec" || fail "cannot clone spec fixture"
    printf '%s\n' '# uncommitted RPM instruction' >>"$dirty_spec/gitswitcher.spec"
    expect_dirty_rejected "dirty spec" "$dirty_spec" "$make_cmd" \
        "$dirty_spec/$dist_root.tar.gz" "$out"

    dirty_manifest=$tmp/dirty-manifest
    git clone --quiet "$root" "$dirty_manifest" || fail "cannot clone manifest fixture"
    printf '%s\n' '# uncommitted release text' >>"$dirty_manifest/README.md"
    expect_dirty_rejected "dirty tracked manifest" "$dirty_manifest" \
        "$make_cmd" "$dirty_manifest/$dist_root.tar.gz" "$out"

    untracked_manifest=$tmp/untracked-manifest
    git clone --quiet "$root" "$untracked_manifest" ||
        fail "cannot clone untracked manifest fixture"
    printf '%s\n' 'uncommitted release input' >"$untracked_manifest/src/.ar07-untracked"
    expect_dirty_rejected "untracked manifest" "$untracked_manifest" \
        "$make_cmd" "$untracked_manifest/$dist_root.tar.gz" "$out"

    printf 'ar07-release: PASS (commit-pinned metadata and dirty-input refusal)\n'
}

[ "$#" -ge 1 ] || fail "usage: $0 {manifest|artifact|neuter} ..."
mode=$1
shift
case $mode in
    manifest) check_manifest_contract "$@" ;;
    artifact) check_artifact_pair "$@" ;;
    neuter) check_neuter_contract "$@" ;;
    *) fail "unknown mode '$mode' (expected manifest, artifact, or neuter)" ;;
esac
