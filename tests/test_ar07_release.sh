#!/bin/sh
# AR-07 T18 release-input and native artifact contracts.

set -eu

fail()
{
    printf 'ar07-release: ERROR: %s\n' "$*" >&2
    exit 1
}

elf_has_immediate_binding()
{
    # Accept DT_BIND_NOW itself, or an exact NOW/BIND_NOW flag token carried
    # by DT_FLAGS/DT_FLAGS_1. Dynamic strings in unrelated tags (RUNPATH,
    # SONAME, NEEDED, and so on) are data, not binding-policy evidence.
    awk '
        function has_now_token(value, count, position, tokens) {
            gsub(/[^[:alnum:]_]+/, " ", value)
            count = split(value, tokens, /[[:space:]]+/)
            for (position = 1; position <= count; position++) {
                if (tokens[position] == "NOW" ||
                    tokens[position] == "BIND_NOW") {
                    return 1
                }
            }
            return 0
        }
        /^[[:space:]]*(0x)?[[:xdigit:]]+[[:space:]]+(\(BIND_NOW\)|BIND_NOW)([[:space:]]|$)/ {
            found = 1
        }
        {
            if (match($0, /^[[:space:]]*(0x)?[[:xdigit:]]+[[:space:]]+(\(FLAGS(_1)?\)|FLAGS(_1)?)([[:space:]]|$)/)) {
                value = substr($0, RLENGTH + 1)
                if (has_now_token(value)) {
                    found = 1
                }
            }
        }
        END { exit found ? 0 : 1 }
    '
}

check_elf()
{
    binary=$1
    expected_triple=${2-}
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
    if [ -n "$expected_triple" ]; then
        expected_arch=${expected_triple%%-*}
        elf_machine=$(printf '%s\n' "$elf_header" |
            sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')
        case $expected_arch in
            x86_64|amd64)
                case $elf_machine in
                    *'X86-64'*|*'x86-64'*) ;;
                    *) fail "ELF machine '$elf_machine' disagrees with $expected_triple" ;;
                esac ;;
            i386|i486|i586|i686)
                case $elf_machine in
                    *'80386'*) ;;
                    *) fail "ELF machine '$elf_machine' disagrees with $expected_triple" ;;
                esac ;;
            aarch64|arm64)
                case $elf_machine in
                    *'AArch64'*) ;;
                    *) fail "ELF machine '$elf_machine' disagrees with $expected_triple" ;;
                esac ;;
            arm*)
                case $elf_machine in
                    *'ARM'*) ;;
                    *) fail "ELF machine '$elf_machine' disagrees with $expected_triple" ;;
                esac ;;
            riscv*)
                case $elf_machine in
                    *'RISC-V'*) ;;
                    *) fail "ELF machine '$elf_machine' disagrees with $expected_triple" ;;
                esac ;;
            powerpc64*|ppc64*)
                case $elf_machine in
                    *'PowerPC64'*) ;;
                    *) fail "ELF machine '$elf_machine' disagrees with $expected_triple" ;;
                esac ;;
            s390x)
                case $elf_machine in
                    *'S/390'*) ;;
                    *) fail "ELF machine '$elf_machine' disagrees with $expected_triple" ;;
                esac ;;
            *) fail "unsupported ELF target architecture in $expected_triple" ;;
        esac
    fi

    elf_dynamic=$("$readelf_cmd" -d "$binary") ||
        fail "readelf could not read dynamic section: $binary"
    printf '%s\n' "$elf_dynamic" | elf_has_immediate_binding ||
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
    expected_triple=${2-}
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
    if [ -n "$expected_triple" ]; then
        command -v lipo >/dev/null 2>&1 ||
            fail "lipo is required to bind Mach-O architecture to the compiler target"
        expected_arch=${expected_triple%%-*}
        case $expected_arch in
            aarch64|arm64|arm64e) expected_arch=arm64 ;;
            x86_64|amd64) expected_arch=x86_64 ;;
            i386|i486|i586|i686) expected_arch=i386 ;;
            *) fail "unsupported Mach-O target architecture in $expected_triple" ;;
        esac
        macho_arches=$(lipo -archs "$binary") ||
            fail "lipo could not inspect Mach-O architecture: $binary"
        case " $macho_arches " in
            *" $expected_arch "*) ;;
            *) fail "Mach-O architectures '$macho_arches' disagree with $expected_triple" ;;
        esac
    fi

    macho_symbols=$(nm -u "$binary") ||
        fail "nm could not read undefined symbols: $binary"
    printf '%s\n' "$macho_symbols" | grep -q 'stack_chk_fail' ||
        fail "release binary lacks stack-protector instrumentation: $binary"
}

check_artifact_pair()
{
    { [ "$#" -eq 2 ] || [ "$#" -eq 3 ]; } ||
        fail "usage: $0 artifact BUILT_BINARY STAGED_BINARY [TARGET_TRIPLE]"
    built=$1
    staged=$2
    expected_triple=${3-}

    [ "$built" != "$staged" ] ||
        fail "built and staged release paths must be distinct"
    [ -x "$built" ] || fail "built release binary is missing: $built"
    [ -x "$staged" ] || fail "staged release binary is missing: $staged"
    cmp -s "$built" "$staged" ||
        fail "staged binary is not byte-identical to the inspected build"

    built_version=$("$built" --version) || fail "built binary --version failed"
    staged_version=$("$staged" --version) || fail "staged binary --version failed"
    [ "$built_version" = "$staged_version" ] ||
        fail "built and staged binaries report different versions"

    format=${GITSWITCH_RELEASE_FORMAT-}
    if [ -z "$format" ]; then
        case $(uname -s) in
            Linux|FreeBSD) format=elf ;;
            Darwin) format=macho ;;
            *) fail "unsupported artifact-inspection platform: $(uname -s)" ;;
        esac
    fi
    case $format in
        elf)
            check_elf "$built" "$expected_triple"
            check_elf "$staged" "$expected_triple"
            ;;
        macho)
            check_macho "$built" "$expected_triple"
            check_macho "$staged" "$expected_triple"
            ;;
        *)
            fail "unsupported artifact-inspection format: $format"
            ;;
    esac

    printf 'ar07-release: PASS (%s built and staged artifacts verified)\n' \
        "$format"
}

check_install_publication_paths()
{
    [ "$#" -eq 3 ] ||
        fail "internal install publication path contract"
    install_publish_built=$1
    install_publish_staged=$2
    install_publish_final=$3

    [ "$install_publish_built" != "$install_publish_staged" ] &&
        [ "$install_publish_built" != "$install_publish_final" ] &&
        [ "$install_publish_staged" != "$install_publish_final" ] ||
        fail "install publication paths must be distinct"
    install_publish_staged_parent=${install_publish_staged%/*}
    install_publish_final_parent=${install_publish_final%/*}
    [ -n "$install_publish_staged_parent" ] &&
        [ "$install_publish_staged_parent" = "$install_publish_final_parent" ] ||
        fail "staged and final install paths must share one directory"
    [ -f "$install_publish_staged" ] && [ ! -L "$install_publish_staged" ] ||
        fail "staged install artifact is not a regular private file"
}

publish_install_copy()
{
    [ "$#" -eq 3 ] ||
        fail "usage: $0 copy-publish BUILT STAGED FINAL"
    install_publish_built=$1
    install_publish_staged=$2
    install_publish_final=$3

    check_install_publication_paths "$install_publish_built" \
        "$install_publish_staged" "$install_publish_final"
    [ -x "$install_publish_built" ] ||
        fail "built install binary is missing: $install_publish_built"
    [ -x "$install_publish_staged" ] ||
        fail "staged install binary is missing: $install_publish_staged"
    cmp -s "$install_publish_built" "$install_publish_staged" ||
        fail "staged install binary is not byte-identical to selected build"
    mv -f "$install_publish_staged" "$install_publish_final" ||
        fail "cannot atomically publish staged install binary"
}

publish_release_artifact()
{
    [ "$#" -eq 4 ] ||
        fail "usage: $0 artifact-publish BUILT STAGED FINAL TRIPLE"
    install_publish_built=$1
    install_publish_staged=$2
    install_publish_final=$3
    install_publish_triple=$4

    check_install_publication_paths "$install_publish_built" \
        "$install_publish_staged" "$install_publish_final"
    check_artifact_pair "$install_publish_built" \
        "$install_publish_staged" "$install_publish_triple"
    mv -f "$install_publish_staged" "$install_publish_final" ||
        fail "cannot atomically publish validated release artifact"
}

# AR-11 M39: the install recipe must publish the exact private copy inspected
# by the release validator, not reopen the mutable build pathname afterward.
# A PATH-local `sh` wrapper lets the real validator finish and then atomically
# replaces its built-path argument and, if still named, its staged argument.
# Correct install logic has already published and retired the staged name in
# the validator operation; split validate-then-publish logic installs the
# replacement instead.
check_install_staging_contract()
{
    [ "$#" -eq 5 ] ||
        fail "usage: $0 install ROOT MAKE BUILT_BINARY BUILDDIR PREFIX"
    install_root=$1
    install_make=$2
    install_seed_built=$3
    install_seed_builddir=$4
    install_prefix=$5

    case $install_seed_built in
        /*) ;;
        *) install_seed_built=$install_root/$install_seed_built ;;
    esac
    case $install_seed_builddir in
        /*) ;;
        *) install_seed_builddir=$install_root/$install_seed_builddir ;;
    esac
    install_target=${install_seed_built##*/}
    [ -x "$install_seed_built" ] ||
        fail "install-race built binary is missing: $install_seed_built"
    [ -f "$install_seed_builddir/obj/.buildconfig" ] ||
        fail "install-race release build stamp is missing"

    install_real_sh=$(command -v sh) || fail "install-race sh is unavailable"
    install_real_cp=$(command -v cp) || fail "install-race cp is unavailable"
    install_real_chmod=$(command -v chmod) ||
        fail "install-race chmod is unavailable"
    install_real_mv=$(command -v mv) || fail "install-race mv is unavailable"
    install_tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-install-contract.XXXXXX") ||
        fail "cannot create install-race temporary directory"
    install_builddir=$install_tmp/build
    install_built=$install_builddir/bin/$install_target
    install_expected=$install_tmp/built.expected
    install_replacement=$install_tmp/built.replacement
    install_sentinel=$install_tmp/installed.sentinel
    install_reject_stage=$install_tmp/reject-stage
    install_swap_stage=$install_tmp/swap-stage
    install_shims=$install_tmp/shims
    install_report=$install_tmp/validator.args
    install_stage_state=$install_tmp/validator.stage-state
    install_out=$install_tmp/install.out
    mkdir -p "$install_builddir/bin" "$install_builddir/obj" ||
        fail "cannot create private install-race build"
    "$install_real_cp" "$install_seed_built" "$install_built" ||
        fail "cannot seed private install-race binary"
    "$install_real_cp" "$install_seed_built" "$install_expected" ||
        fail "cannot preserve expected install-race bytes"
    "$install_real_cp" "$install_seed_builddir/obj/.buildconfig" \
        "$install_builddir/obj/.buildconfig" ||
        fail "cannot seed private install-race build stamp"
    printf '%s\n' '#!/bin/sh' 'exit 97' >"$install_replacement" ||
        fail "cannot create install-race replacement"
    "$install_real_chmod" 0755 "$install_replacement" ||
        fail "cannot make install-race replacement executable"
    printf '%s\n' '#!/bin/sh' 'exit 96' >"$install_sentinel" ||
        fail "cannot create install-race destination sentinel"
    "$install_real_chmod" 0755 "$install_sentinel" ||
        fail "cannot make install-race destination sentinel executable"
    mkdir "$install_shims" || fail "cannot create install-race shim directory"

    install_contract_cleanup()
    {
        install_cleanup_status=$?
        trap - 0 1 2 3 15
        rm -rf "$install_tmp"
        exit "$install_cleanup_status"
    }
    trap install_contract_cleanup 0
    trap 'exit 1' 1 2 3 15

cat >"$install_shims/sh" <<'EOF'
#!/bin/sh
case ${2-} in
    artifact|artifact-publish) install_validator=true ;;
    *) install_validator=false ;;
esac
if [ "${1-}" = tests/test_ar07_release.sh ] &&
   [ "$install_validator" = true ] &&
   [ ! -e "$AR11_INSTALL_SWAP_REPORT" ]; then
    printf '%s\n%s\n' "$3" "$4" >"$AR11_INSTALL_SWAP_REPORT" ||
        exit 98
    if [ "$AR11_INSTALL_SWAP_MODE" = corrupt-staged ] &&
       [ "$3" != "$4" ]; then
        "$AR11_INSTALL_REAL_CP" "$AR11_INSTALL_SWAP_BINARY" "$4" ||
            exit 98
        "$AR11_INSTALL_REAL_CHMOD" 0755 "$4" || exit 98
        exec "$AR11_INSTALL_REAL_SH" "$@"
    fi
fi
"$AR11_INSTALL_REAL_SH" "$@"
status=$?
if [ "$status" -eq 0 ] &&
   [ "${1-}" = tests/test_ar07_release.sh ] &&
   [ "$install_validator" = true ] &&
   [ "$AR11_INSTALL_SWAP_MODE" = swap-after-validation ]; then
    swap_tmp=$3.ar11-install-swap.$$
    "$AR11_INSTALL_REAL_CP" "$AR11_INSTALL_SWAP_BINARY" "$swap_tmp" ||
        exit 98
    "$AR11_INSTALL_REAL_CHMOD" 0755 "$swap_tmp" || exit 98
    "$AR11_INSTALL_REAL_MV" -f "$swap_tmp" "$3" || exit 98
    swap_tmp=$4.ar11-install-swap.$$
    "$AR11_INSTALL_REAL_CP" "$AR11_INSTALL_SWAP_BINARY" "$swap_tmp" ||
        exit 98
    "$AR11_INSTALL_REAL_CHMOD" 0755 "$swap_tmp" || exit 98
    "$AR11_INSTALL_REAL_MV" -f "$swap_tmp" "$4" || exit 98
    printf '%s\n' replaced >"$AR11_INSTALL_STAGE_STATE" || exit 98
fi
exit "$status"
EOF
    chmod 0755 "$install_shims/sh" || fail "cannot activate install-race shim"

    # Corrupt only the validator's distinct staged argument. The fixed recipe
    # must reject it before atomic publication, preserve a pre-existing final
    # binary, and remove the private temporary. The old self-comparison never
    # exposes a distinct staged argument and proceeds to overwrite the final.
    install_reject_bin=$install_reject_stage$install_prefix/bin
    mkdir -p "$install_reject_bin" ||
        fail "cannot create rejecting install destination"
    "$install_real_cp" "$install_sentinel" \
        "$install_reject_bin/$install_target" ||
        fail "cannot seed rejecting install sentinel"
    "$install_real_chmod" 0755 "$install_reject_bin/$install_target" ||
        fail "cannot set rejecting install sentinel mode"
    "$install_real_cp" "$install_sentinel" \
        "$install_tmp/reject.expected" ||
        fail "cannot preserve rejecting install sentinel"
    if PATH="$install_shims:$PATH" \
        AR11_INSTALL_REAL_SH="$install_real_sh" \
        AR11_INSTALL_REAL_CP="$install_real_cp" \
        AR11_INSTALL_REAL_CHMOD="$install_real_chmod" \
        AR11_INSTALL_REAL_MV="$install_real_mv" \
        AR11_INSTALL_SWAP_BINARY="$install_replacement" \
        AR11_INSTALL_SWAP_REPORT="$install_report" \
        AR11_INSTALL_STAGE_STATE="$install_stage_state" \
        AR11_INSTALL_SWAP_MODE=corrupt-staged \
        GITSWITCH_RELEASE_FORMAT="${GITSWITCH_RELEASE_FORMAT-}" \
        "$install_make" -C "$install_root" BUILD_TYPE=release \
            BUILDDIR="$install_builddir" TARGET="$install_target" \
            install DESTDIR="$install_reject_stage" PREFIX="$install_prefix" \
            >"$install_out" 2>&1; then
        fail "install accepted a corrupted private staged binary"
    fi
    [ -s "$install_report" ] ||
        fail "install recipe did not execute the artifact validator"
    install_built_arg=$(sed -n '1p' "$install_report")
    install_staged_arg=$(sed -n '2p' "$install_report")
    [ "$install_built_arg" = "$install_built" ] ||
        fail "install validator inspected an unexpected build path"
    [ -n "$install_staged_arg" ] &&
        [ "$install_staged_arg" != "$install_built_arg" ] ||
        fail "install validator arguments are not distinct"
    case $install_staged_arg in
        "$install_reject_bin/.${install_target}.install."*) ;;
        *) fail "install validator did not inspect a private destination temporary" ;;
    esac
    grep -F 'staged binary is not byte-identical' "$install_out" >/dev/null || {
        sed -n '1,200p' "$install_out" >&2
        fail "corrupted staged install failed for an unrelated reason"
    }
    cmp -s "$install_tmp/reject.expected" \
        "$install_reject_bin/$install_target" ||
        fail "failed staged validation replaced the prior installed binary"
    reject_mode=$(find "$install_reject_bin/$install_target" -prune \
        -type f -perm 0755 -print 2>/dev/null) ||
        fail "cannot inspect preserved install destination mode"
    [ "$reject_mode" = "$install_reject_bin/$install_target" ] ||
        fail "failed staged validation changed the prior installed binary mode"
    set -- "$install_reject_bin/.${install_target}.install."*
    { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
        fail "failed install left a private binary temporary"
    [ ! -e "$install_reject_stage$install_prefix/share" ] ||
        fail "failed binary validation installed completion assets"

    # Then let the real validator succeed and replace the private source plus
    # any still-named staged path afterward. Publication must already have
    # atomically consumed the validated temporary before control returns.
    rm -f "$install_report" "$install_stage_state"
    if ! PATH="$install_shims:$PATH" \
        AR11_INSTALL_REAL_SH="$install_real_sh" \
        AR11_INSTALL_REAL_CP="$install_real_cp" \
        AR11_INSTALL_REAL_CHMOD="$install_real_chmod" \
        AR11_INSTALL_REAL_MV="$install_real_mv" \
        AR11_INSTALL_SWAP_BINARY="$install_replacement" \
        AR11_INSTALL_SWAP_REPORT="$install_report" \
        AR11_INSTALL_STAGE_STATE="$install_stage_state" \
        AR11_INSTALL_SWAP_MODE=swap-after-validation \
        GITSWITCH_RELEASE_FORMAT="${GITSWITCH_RELEASE_FORMAT-}" \
        "$install_make" -C "$install_root" BUILD_TYPE=release \
            BUILDDIR="$install_builddir" TARGET="$install_target" \
            install DESTDIR="$install_swap_stage" PREFIX="$install_prefix" \
            >"$install_out" 2>&1; then
        sed -n '1,200p' "$install_out" >&2
        fail "staged install failed during the post-validation source swap"
    fi
    [ -s "$install_report" ] ||
        fail "source-swap install did not execute the artifact validator"
    install_built_arg=$(sed -n '1p' "$install_report")
    install_staged_arg=$(sed -n '2p' "$install_report")
    [ "$install_built_arg" = "$install_built" ] ||
        fail "source-swap validator inspected an unexpected build path"
    [ -n "$install_staged_arg" ] &&
        [ "$install_staged_arg" != "$install_built_arg" ] ||
        fail "source-swap validator arguments are not distinct"
    case $install_staged_arg in
        "$install_swap_stage$install_prefix/bin/.${install_target}.install."*) ;;
        *) fail "source-swap validator missed its private destination temporary" ;;
    esac
    install_final=$install_swap_stage$install_prefix/bin/$install_target
    cmp -s "$install_expected" "$install_final" ||
        fail "install published bytes replaced after validation"
    cmp -s "$install_replacement" "$install_built" ||
        fail "install-race wrapper did not replace the validated source"
    [ "$(sed -n '1p' "$install_stage_state")" = replaced ] ||
        fail "install-race wrapper did not replace the retired staged pathname"
    install_mode=$(find "$install_final" -prune -type f -perm 0755 \
        -print 2>/dev/null) || fail "cannot inspect installed binary mode"
    [ "$install_mode" = "$install_final" ] ||
        fail "installed binary is not a regular file with exact mode 0755"
    set -- "$install_swap_stage$install_prefix/bin/.${install_target}.install."*
    { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
        fail "successful install left a private binary temporary"

    trap - 0 1 2 3 15
    rm -rf "$install_tmp"
    printf 'ar07-release: PASS (staged install rejects corruption and seals publication)\n'
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
    { [ "$#" -ge 5 ] && [ "$4" = -- ]; } ||
        fail "usage: $0 neuter RELEASE_SECURITY_CFLAGS HARDENING_HEADER MAKE -- COMPILER [ARG...]"
    release_security_cflags=$1
    hardening_header=$2
    make_cmd=$3
    shift 4
    compiler_launcher=$1
    compiler_command=$*
    command -v "$compiler_launcher" >/dev/null 2>&1 ||
        fail "neuter compiler launcher is unavailable: $compiler_launcher"
    [ -f "$hardening_header" ] ||
        fail "release hardening header is unavailable: $hardening_header"

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

    script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd) ||
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
    if "$@" -std=c11 -O2 -U_FORTIFY_SOURCE -c "$fortify_source" \
        -o "$tmp/fortify-neutered.o" >"$tmp/fortify-neutered.log" 2>&1; then
        fail "FORTIFY-neutered compile fixture was accepted"
    fi
    grep -F 'AR07_FORTIFY_REQUIRED' "$tmp/fortify-neutered.log" >/dev/null || {
        cat "$tmp/fortify-neutered.log" >&2
        fail "FORTIFY-neutered fixture failed for an unrelated reason"
    }
    if ! "$@" -std=c11 -O2 -U_FORTIFY_SOURCE "$fortify_define" \
        -c "$fortify_source" \
        -o "$tmp/fortify-enabled.o" >"$tmp/fortify-enabled.log" 2>&1; then
        cat "$tmp/fortify-enabled.log" >&2
        fail "configured FORTIFY compile intent is not accepted by the compiler"
    fi

    format=${GITSWITCH_RELEASE_FORMAT-}
    if [ -z "$format" ]; then
        case $(uname -s) in
            Linux|FreeBSD) format=elf ;;
            Darwin) format=macho ;;
            *) fail "unsupported hardening-neuter platform: $(uname -s)" ;;
        esac
    fi
    nonpie=$tmp/neuter-nonpie
    nocanary=$tmp/neuter-no-canary
    norelro=$tmp/neuter-no-relro
    nonow=$tmp/neuter-no-now
    execstack=$tmp/neuter-exec-stack
    have_nonpie_neuter=false
    have_execstack_neuter=false
    case $format in
        elf)
            if ! "$@" -std=c11 -O0 -fno-stack-protector -fno-pie \
                "$source_file" -no-pie -o "$nonpie" >"$tmp/nonpie.log" 2>&1; then
                cat "$tmp/nonpie.log" >&2
                fail "cannot build ELF non-PIE neuter fixture"
            fi
            have_nonpie_neuter=true
            if ! "$@" -std=c11 -O0 -fno-stack-protector -fPIE \
                "$source_file" -pie -Wl,-z,relro -Wl,-z,now \
                -Wl,-z,noexecstack -o "$nocanary" \
                >"$tmp/nocanary.log" 2>&1; then
                cat "$tmp/nocanary.log" >&2
                fail "cannot build ELF no-canary neuter fixture"
            fi
            if ! "$@" -std=c11 -O0 -fstack-protector-strong -fPIE \
                "$source_file" -pie -Wl,-z,norelro -Wl,-z,now \
                -Wl,-z,noexecstack -o "$norelro" \
                >"$tmp/norelro.log" 2>&1; then
                cat "$tmp/norelro.log" >&2
                fail "cannot build ELF no-RELRO neuter fixture"
            fi
            if ! "$@" -std=c11 -O0 -fstack-protector-strong -fPIE \
                "$source_file" -pie -Wl,-z,relro -Wl,-z,lazy \
                -Wl,-z,noexecstack -Wl,-rpath,BIND_NOW -o "$nonow" \
                >"$tmp/nonow.log" 2>&1; then
                cat "$tmp/nonow.log" >&2
                fail "cannot build ELF lazy-binding neuter fixture"
            fi
            if ! "$@" -std=c11 -O0 -fstack-protector-strong -fPIE \
                "$source_file" -pie -Wl,-z,relro -Wl,-z,now \
                -Wl,-z,execstack -o "$execstack" \
                >"$tmp/execstack.log" 2>&1; then
                cat "$tmp/execstack.log" >&2
                fail "cannot build ELF executable-stack neuter fixture"
            fi
            have_execstack_neuter=true
            ;;
        macho)
            # Apple ld forces arm64 dynamic executables to be PIE and accepts
            # -no_pie only with a warning. A real non-PIE negative fixture is
            # therefore constructible only on Intel Darwin; the positive PIE
            # assertion above still applies to every supported architecture.
            case $(uname -m) in
                x86_64|i386)
                    if ! "$@" -std=c11 -O0 -fno-stack-protector \
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
            if ! "$@" -std=c11 -O0 -fno-stack-protector \
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
                    if ! "$@" -std=c11 -O0 \
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
            fail "unsupported hardening-neuter format: $format"
            ;;
    esac

    # Per-translation-unit proof. A mixed build whose second object disables
    # protection must fail at compilation, before a canary from the first
    # object can make the final executable look protected. The fully protected
    # two-object control must link and satisfy the native artifact inspector.
    printf '%s\n' \
        'extern volatile char *ar08_hardening_escape;' \
        'int ar08_hardened_helper(int value)' \
        '{' \
        '    volatile char witness[64];' \
        '    witness[0] = (char)value;' \
        '    ar08_hardening_escape = witness;' \
        '    return witness[0];' \
        '}' >"$tmp/hardened-helper.c"
    printf '%s\n' \
        'volatile char *ar08_hardening_escape;' \
        'int ar08_hardened_helper(int);' \
        'int main(int argc, char **argv)' \
        '{' \
        '    volatile char witness[64];' \
        '    (void)argv;' \
        '    witness[0] = (char)argc;' \
        '    ar08_hardening_escape = witness;' \
        '    return ar08_hardened_helper(witness[0]) == 127;' \
        '}' >"$tmp/hardened-main.c"
    "$@" -std=c11 -O2 -DGITSWITCH_REQUIRE_STRONG_SSP=1 \
        -include "$hardening_header" -fstack-protector-strong \
        -c "$tmp/hardened-main.c" -o "$tmp/hardened-main.o" ||
        fail "fully protected main translation unit did not compile"
    if "$@" -std=c11 -O2 -DGITSWITCH_REQUIRE_STRONG_SSP=1 \
        -include "$hardening_header" -fstack-protector-strong \
        -fno-stack-protector \
        -c "$tmp/hardened-helper.c" -o "$tmp/mixed-unprotected.o" \
        >"$tmp/mixed.log" 2>&1; then
        fail "mixed protected/unprotected translation units passed the compile gate"
    fi
    grep -F 'release translation unit lacks required stack-protector policy' \
        "$tmp/mixed.log" >/dev/null || {
        cat "$tmp/mixed.log" >&2
        fail "mixed translation-unit fixture failed for an unrelated reason"
    }
    "$@" -std=c11 -O2 -DGITSWITCH_REQUIRE_STRONG_SSP=1 \
        -include "$hardening_header" -fstack-protector-strong \
        -c "$tmp/hardened-helper.c" -o "$tmp/hardened-helper.o" ||
        fail "fully protected helper translation unit did not compile"
    full_binary=$tmp/hardened-multi-tu
    case $format in
        elf)
            "$@" -fPIE "$tmp/hardened-main.o" "$tmp/hardened-helper.o" \
                -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack \
                -o "$full_binary" || fail "fully protected ELF fixture did not link"
            ;;
        macho)
            "$@" "$tmp/hardened-main.o" "$tmp/hardened-helper.o" \
                -Wl,-pie -o "$full_binary" ||
                fail "fully protected Mach-O fixture did not link"
            ;;
    esac
    cp "$full_binary" "$tmp/hardened-multi-tu-staged"
    GITSWITCH_RELEASE_FORMAT=$format sh "$script" artifact "$full_binary" \
        "$tmp/hardened-multi-tu-staged" >"$tmp/hardened-check.log" 2>&1 || {
        cat "$tmp/hardened-check.log" >&2
        fail "fully protected multi-translation-unit fixture was rejected"
    }

    # Exercise the real Make boundary, not only hand-constructed compiler
    # fixtures. Every named suffix below used to be command-line overrideable;
    # emptying them together produced a nominal release that was ET_EXEC and
    # had no canary. CI invokes this contract once with GCC and once with
    # Clang, and the native artifact inspector proves the hostile caller flags
    # lose to the final policy.
    make_fixture=$tmp/make-neuter
    mkdir -p "$make_fixture/src"
    cp "$(dirname "$hardening_header")/../Makefile" "$make_fixture/Makefile" ||
        fail "cannot copy Makefile into hardening-neuter fixture"
    cp "$(dirname "$hardening_header")/../VERSION" "$make_fixture/VERSION" ||
        fail "cannot copy VERSION into hardening-neuter fixture"
    cp "$hardening_header" "$make_fixture/src/release_hardening.h" ||
        fail "cannot copy hardening header into Make fixture"

    # The build stamp must never bless a partial identity list. Make's
    # $(shell ...) discards command status, so the recipe emits one explicit
    # sentinel and the release-policy target rejects it before compilation.
    identity_one=$tmp/toolchain-identity-one
    identity_two=$tmp/toolchain-identity-two
    identity_missing=$tmp/toolchain-identity-missing
    printf '%s\n' launcher-v1 >"$identity_one"
    printf '%s\n' compiler-v1 >"$identity_two"
    identity_files="$identity_one $identity_two"
    read_toolchain_fingerprint()
    {
        identity_list=$1
        "$make_cmd" -s -C "$make_fixture" CC="$compiler_command" \
            BUILD_TYPE=release TOOLCHAIN_IDENTITY_FILES="$identity_list" \
            info | sed -n 's/^Toolchain fingerprint: //p'
    }
    expect_toolchain_rejection()
    {
        identity_label=$1
        identity_list=$2
        identity_log=$tmp/toolchain-$identity_label.log

        if "$make_cmd" -s -C "$make_fixture" CC="$compiler_command" \
            BUILD_TYPE=release TOOLCHAIN_IDENTITY_FILES="$identity_list" \
            release-policy-check >"$identity_log" 2>&1; then
            fail "$identity_label toolchain identity list passed release policy"
        fi
        grep -F 'complete compiler content fingerprint is required' \
            "$identity_log" >/dev/null || {
            cat "$identity_log" >&2
            fail "$identity_label toolchain list failed for an unrelated reason"
        }
    }

    fingerprint_before=$(read_toolchain_fingerprint "$identity_files")
    case $fingerprint_before in
        *"$identity_one="*"$identity_two="*) ;;
        *) fail "complete toolchain identity list produced an incomplete fingerprint" ;;
    esac
    "$make_cmd" -s -C "$make_fixture" CC="$compiler_command" \
        BUILD_TYPE=release TOOLCHAIN_IDENTITY_FILES="$identity_files" \
        release-policy-check ||
        fail "complete toolchain identity list failed release policy"

    missing_fingerprint=$(read_toolchain_fingerprint \
        "$identity_one $identity_missing")
    [ "$missing_fingerprint" = __GITSWITCH_INCOMPLETE_TOOLCHAIN_IDENTITY__ ] ||
        fail "missing identity file produced a valid-looking partial fingerprint"
    expect_toolchain_rejection missing "$identity_one $identity_missing"

    empty_fingerprint=$(read_toolchain_fingerprint "")
    [ "$empty_fingerprint" = __GITSWITCH_INCOMPLETE_TOOLCHAIN_IDENTITY__ ] ||
        fail "empty identity list did not produce the failure sentinel"
    expect_toolchain_rejection empty ""

    chmod 000 "$identity_two" || fail "cannot make identity fixture unreadable"
    if [ ! -r "$identity_two" ]; then
        unreadable_fingerprint=$(read_toolchain_fingerprint "$identity_files")
        [ "$unreadable_fingerprint" = __GITSWITCH_INCOMPLETE_TOOLCHAIN_IDENTITY__ ] ||
            fail "unreadable identity file produced a valid-looking fingerprint"
        expect_toolchain_rejection unreadable "$identity_files"
    fi
    chmod 600 "$identity_two" || fail "cannot restore identity fixture mode"

    printf '%s\n' compiler-v2 >"$identity_two"
    fingerprint_after=$(read_toolchain_fingerprint "$identity_files")
    [ "$fingerprint_after" != "$fingerprint_before" ] ||
        fail "changed identity file did not change the complete fingerprint"
    case $fingerprint_after in
        *"$identity_one="*"$identity_two="*) ;;
        *) fail "changed complete identity list lost one of its inputs" ;;
    esac

    cat >"$make_fixture/src/neuter.c" <<'EOF'
#include <stdio.h>
static volatile char *ar08_make_escape;
int main(int argc, char **argv)
{
    volatile char witness[64];
    (void)argv;
    witness[0] = (char)argc;
    ar08_make_escape = witness;
    puts("gitswitch-neuter 0.0.0");
    return witness[0] == 127;
}
EOF
    case $format in
        elf) hostile_ldflags=-no-pie ;;
        macho) hostile_ldflags=-Wl,-no_pie ;;
    esac
    make_log=$tmp/make-neuter.log
    if ! "$make_cmd" -C "$make_fixture" CC="$compiler_command" \
        TARGET=neuter-probe SOURCES=src/neuter.c \
        BUILDDIR=build \
        VERSION=0.0.0 COMMIT=neuter BUILD_TYPE=release READLINE=0 \
        CFLAGS='-std=gnu11 -O2 -fno-stack-protector -fno-pie' \
        LDFLAGS="$hostile_ldflags" \
        SECURITY_CFLAGS_RELEASE= SECURITY_LDFLAGS_RELEASE= \
        RELEASE_FLAGS= RELEASE_LDFLAGS= \
        RELEASE_ENFORCED_CFLAGS= RELEASE_ENFORCED_LDFLAGS= \
        RELEASE_REQUIRED_CFLAGS= TU_HARDENING_FLAGS= \
        CF_PROTECTION= TARGET_ARCH=unknown all >"$make_log" 2>&1; then
        cat "$make_log" >&2
        fail "real Make hardening policy did not survive command-line neutering"
    fi
    make_binary=$make_fixture/build/bin/neuter-probe
    cp "$make_binary" "$tmp/make-neuter-staged"
    make_target_triple=$("$@" -dumpmachine) ||
        fail "cannot read compiler target for Make hardening fixture"
    GITSWITCH_RELEASE_FORMAT=$format sh "$script" artifact "$make_binary" \
        "$tmp/make-neuter-staged" "$make_target_triple" \
        >"$tmp/make-neuter-check.log" 2>&1 || {
        cat "$tmp/make-neuter-check.log" >&2
        fail "command-line-neutered Make build escaped final hardening"
    }

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

    case $format in
        elf)
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
        "$format"
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
    printf '%s\n' "$embedded_spec" |
        grep -Eq '^BuildRequires:[[:space:]]+readline-devel[[:space:]]*$' ||
        fail "archived RPM spec does not declare readline-devel"
    printf '%s\n' "$embedded_spec" |
        grep -E '^make .*BUILD_TYPE=release .*READLINE=1' >/dev/null ||
        fail "archived RPM spec does not force Readline in its release build"
}

inspect_dist_residue()
{
    residue_archive=$1
    residue_platform=$2
    residue_archive_dir=${residue_archive%/*}
    residue_archive_name=${residue_archive##*/}

    set -- "$residue_archive_dir/.$residue_archive_name.tmp."*
    if [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; then
        [ "$residue_platform" != Darwin ] ||
            fail "Darwin publication did not retain its private clone source"
        return
    fi
    { [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]; } ||
        fail "distribution publication left an unexpected staging namespace"
    case $residue_platform in
        FreeBSD)
            fail "FreeBSD publication retained a temporary despite funlinkat"
            ;;
        Darwin)
            cmp -s "$residue_archive" "$1" ||
                fail "Darwin retained clone source differs from its artifact"
            ;;
        *)
            cmp -s "$residue_archive" "$1" ||
                fail "retained distribution source differs from its artifact"
            ;;
    esac

    # The publisher deliberately avoids a racy pathname deletion on platforms
    # without funlinkat. This isolated contract owns the directory after the
    # helper exits, so it can remove the inspected residue between cases.
    rm -f "$1"
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
    { [ ! -e "$archive" ] && [ ! -L "$archive" ]; } ||
        fail "$label rejection left a release archive behind"
}

expect_output_rejected()
{
    label=$1
    repo=$2
    make_cmd=$3
    requested=$4
    out=$5

    if "$make_cmd" -C "$repo" DIST_ARCHIVE="$requested" dist >"$out" 2>&1; then
        fail "$label output alias unexpectedly succeeded"
    fi
    grep -F 'ERROR: DIST_ARCHIVE must be exactly build/dist/' "$out" >/dev/null ||
        fail "$label rejection did not identify the output boundary"
}

check_manifest_contract()
{
    [ "$#" -eq 3 ] ||
        fail "usage: $0 manifest PROJECT_ROOT MAKE NAMED_PUBLISH_HELPER"
    root=$1
    make_cmd=$2
    named_publish_helper=$3
    root=$(cd "$root" && pwd) || fail "project root is unavailable: $root"
    git -C "$root" rev-parse --git-dir >/dev/null 2>&1 ||
        fail "manifest contract requires a git checkout"

    tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-release-contract.XXXXXX") ||
        fail "cannot create temporary release-contract directory"
    copy_pid=
    copy_watchdog_pid=
    copy_watchdog_cancel=
    copy_status_descendant_pid=
    copy_status_release=
    copy_group_descendant_pid=
    copy_group_release=
    copy_group_finish=
    copy_signal_producer_pid=
    lock_dist_pid=
    lock_gate_pid=
    lock_contender_pid=
    stop_background()
    {
        background_pid=$1
        [ -n "$background_pid" ] || return 0
        kill -TERM "$background_pid" 2>/dev/null || :
        background_tries=0
        while kill -0 "$background_pid" 2>/dev/null &&
              [ "$background_tries" -lt 50 ]; do
            sleep 0.1
            background_tries=$((background_tries + 1))
        done
        if kill -0 "$background_pid" 2>/dev/null; then
            kill -KILL "$background_pid" 2>/dev/null || :
        fi
        wait "$background_pid" 2>/dev/null || :
    }
    cancel_watchdog()
    {
        watchdog_pid=$1
        watchdog_cancel=$2
        [ -n "$watchdog_pid" ] || return 0
        if [ -n "$watchdog_cancel" ]; then
            : >"$watchdog_cancel" 2>/dev/null || :
        fi
        wait "$watchdog_pid" 2>/dev/null || :
    }
    cleanup()
    {
        status=$?
        trap - 0 1 2 3 15
        stop_background "$lock_gate_pid"
        stop_background "$lock_contender_pid"
        stop_background "$lock_dist_pid"
        if [ -n "$copy_status_release" ]; then
            : >"$copy_status_release" 2>/dev/null || :
        fi
        if [ -n "$copy_group_release" ]; then
            : >"$copy_group_release" 2>/dev/null || :
        fi
        if [ -n "$copy_group_finish" ]; then
            : >"$copy_group_finish" 2>/dev/null || :
        fi
        cancel_watchdog "$copy_watchdog_pid" "$copy_watchdog_cancel"
        if [ -n "$copy_pid" ]; then
            kill "$copy_pid" 2>/dev/null || true
            wait "$copy_pid" 2>/dev/null || true
        fi
        stop_background "$copy_status_descendant_pid"
        stop_background "$copy_group_descendant_pid"
        stop_background "$copy_signal_producer_pid"
        rm -rf "$tmp"
        exit "$status"
    }
    trap cleanup 0
    trap 'exit 1' 1 2 3 15

    clean_repo=$tmp/clean
    git clone --quiet "$root" "$clean_repo" || fail "cannot clone clean HEAD"
    commit=$(git -C "$clean_repo" rev-parse --verify 'HEAD^{commit}') ||
        fail "cannot resolve cloned HEAD"
    version=$(git -C "$clean_repo" show "$commit:VERSION") ||
        fail "cannot read committed VERSION"
    dist_root=gitswitcher-$version
    archive=$clean_repo/build/dist/$dist_root.tar.gz
    out=$tmp/make.out
    status_before=$(git -C "$clean_repo" status --porcelain=v1 --untracked-files=all)
    cp "$clean_repo/VERSION" "$tmp/VERSION.before"
    cp "$clean_repo/README.md" "$tmp/README.before"
    cp "$clean_repo/src/main.c" "$tmp/main.before"

    # Exercise publication from a named temporary on every host: success,
    # occupied-output refusal, producer failure, and cleanup must preserve
    # established or foreign state. FreeBSD identity-seals the private name
    # around its atomic no-replace link because unprivileged descriptor linking
    # is unavailable there, then removes the exact open vnode with funlinkat.
    # Linux and Darwin intentionally retain the private name because neither
    # has a descriptor-conditioned unlink. The complete source is retained: a
    # same-UID writer can hard-link it after any user-space proof, making even
    # descriptor truncation unsafe. Hosted macOS runs this contract through
    # fclonefileat.
    [ -x "$named_publish_helper" ] ||
        fail "named-publish helper is unavailable: $named_publish_helper"
    "$named_publish_helper" --test-sha256 ||
        fail "release publisher SHA-256 known-answer vectors failed"
    copy_dir=$tmp/copy-publish
    mkdir "$copy_dir"
    copy_canonical=$(cd "$copy_dir" && pwd -P) ||
        fail "cannot resolve copy-publish fixture directory"
    copy_archive=$copy_dir/archive.tar.gz
    "$named_publish_helper" "$copy_dir" "$copy_canonical" archive.tar.gz \
        -- /bin/sh -c 'printf original-payload' ||
        fail "descriptor-bound publication failed"
    [ "$(cat "$copy_archive")" = original-payload ] ||
        fail "descriptor-bound publication changed payload"
    [ "$(find "$copy_archive" -prune -type f -perm 0444 -print)" = \
        "$copy_archive" ] ||
        fail "descriptor-bound publication did not publish read-only bytes"
    copy_platform=$(uname -s)
    copy_retained_temp=
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
                fail "FreeBSD publication did not retire its exact named temporary"
            ;;
        Darwin)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "Darwin publication did not retain exactly one private source"
            copy_retained_temp=$1
            [ "$(cat "$copy_retained_temp")" = original-payload ] ||
                fail "Darwin retained clone source changed payload"
            [ "$(find "$copy_retained_temp" -prune -type f -perm 0444 -print)" = \
                "$copy_retained_temp" ] ||
                fail "Darwin retained clone source is not read-only"
            ;;
        *)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "named publication did not retain exactly one private source"
            copy_retained_temp=$1
            [ "$(cat "$copy_retained_temp")" = original-payload ] ||
                fail "retained named source changed payload"
            [ "$(find "$copy_retained_temp" -prune -type f -perm 0444 -print)" = \
                "$copy_retained_temp" ] ||
                fail "retained named source is not read-only"
            ;;
    esac
    if "$named_publish_helper" "$copy_dir" "$copy_canonical" archive.tar.gz \
        -- /bin/sh -c 'printf replacement' >"$out" 2>&1; then
        fail "descriptor-bound publication replaced an existing artifact"
    fi
    [ "$(cat "$copy_archive")" = original-payload ] ||
        fail "occupied descriptor-bound output changed bytes"
    rm -f "$copy_archive"
    if [ -n "$copy_retained_temp" ]; then
        rm -f "$copy_retained_temp"
    fi

    # AR-10 M2: exec'd with stdout+stderr closed, the publisher's working
    # descriptors used to land in the standard slots, so on this named-temp
    # path the post-publication retire WARNING (fd 2) appended into the
    # staging inode — a hard link to the just-published archive — after
    # fsync, while still exiting 0. The publisher must reserve fds 0/1/2
    # before its first open; the published payload must stay byte-exact for
    # every closed-descriptor shape.
    "$named_publish_helper" "$copy_dir" "$copy_canonical" archive.tar.gz \
        -- /bin/sh -c 'printf closed-fd-payload' 1>&- 2>&- ||
        fail "closed stdout/stderr publication failed"
    [ "$(cat "$copy_archive")" = closed-fd-payload ] ||
        fail "closed stdout/stderr publication corrupted the published artifact"
    rm -f "$copy_archive" "$copy_dir"/.archive.tar.gz.tmp.*
    "$named_publish_helper" "$copy_dir" "$copy_canonical" archive.tar.gz \
        -- /bin/sh -c 'printf closed-fd-payload' 0<&- 1>&- 2>&- ||
        fail "fully closed-descriptor publication failed"
    [ "$(cat "$copy_archive")" = closed-fd-payload ] ||
        fail "fully closed-descriptor publication corrupted the published artifact"
    rm -f "$copy_archive" "$copy_dir"/.archive.tar.gz.tmp.*

    # AR-10 L30 / AR-11 M44: the producer's own process group is the helper's
    # lifetime boundary, but it also removes the producer from the terminal
    # foreground group. Every fatal signal handled by the publisher must tear
    # down that group before the publisher truthfully dies by the same signal.
    # Keep the publisher in the foreground: POSIX shells may start asynchronous
    # jobs with SIGINT or SIGQUIT ignored, which would invalidate this fixture.
    copy_signal_violations=
    copy_signal_expected=$tmp/copy-signal.expected
    printf '%s' partial >"$copy_signal_expected" ||
        fail "cannot create fatal-signal expected payload"
    # shellcheck disable=SC3045
    ulimit -c 0 2>/dev/null ||
        fail "cannot disable core files for the fatal-signal fixture"
    # The spawned producer, not this parent shell, expands these variables.
    # shellcheck disable=SC2016
    copy_signal_command='
        printf partial
        printf "%s\n" "$$" >"$AR11_COPY_SIGNAL_PID"
        attempt=0
        while [ "$attempt" -lt 50 ]; do
            set -- "$AR11_COPY_SIGNAL_DIR"/.archive.tar.gz.tmp.*
            if [ "$#" -eq 1 ] && [ -f "$1" ] &&
               cmp -s "$AR11_COPY_SIGNAL_EXPECTED" "$1"; then
                break
            fi
            sleep 0.1
            attempt=$((attempt + 1))
        done
        [ "$attempt" -lt 50 ] || exit 24
        kill -s "$AR11_COPY_SIGNAL" "$PPID"
        sleep 1
        : >"$AR11_COPY_SIGNAL_DELAYED"
    '
    for copy_signal in HUP INT QUIT TERM; do
        copy_signal_pid_file=$tmp/copy-signal-$copy_signal.pid
        copy_signal_delayed=$tmp/copy-signal-$copy_signal.delayed
        copy_signal_producer_pid=
        rm -f "$copy_signal_pid_file" "$copy_signal_delayed" \
            "$copy_archive" "$copy_dir"/.archive.tar.gz.tmp.*
        copy_signal_status=0
        if AR11_COPY_SIGNAL=$copy_signal \
            AR11_COPY_SIGNAL_PID=$copy_signal_pid_file \
            AR11_COPY_SIGNAL_DELAYED=$copy_signal_delayed \
            AR11_COPY_SIGNAL_DIR=$copy_dir \
            AR11_COPY_SIGNAL_EXPECTED=$copy_signal_expected \
            GITSWITCH_RELEASE_TEST_FATAL_DEFAULTS=1 \
            "$named_publish_helper" "$copy_dir" "$copy_canonical" \
                archive.tar.gz -- /bin/sh -c "$copy_signal_command" \
                >"$out" 2>&1; then
            copy_signal_status=0
        else
            copy_signal_status=$?
        fi
        if [ ! -s "$copy_signal_pid_file" ]; then
            copy_signal_violations="$copy_signal_violations $copy_signal-no-pid"
        else
            IFS= read -r copy_signal_producer_pid <"$copy_signal_pid_file" ||
                fail "cannot read the $copy_signal producer PID"
            case $copy_signal_producer_pid in
                ''|0|*[!0-9]*)
                    fail "$copy_signal fixture published an invalid producer PID"
                    ;;
            esac
        fi
        if [ "$copy_signal_status" -le 128 ]; then
            copy_signal_violations="$copy_signal_violations $copy_signal-status-$copy_signal_status"
        else
            copy_signal_observed=$(kill -l "$copy_signal_status" 2>/dev/null || :)
            case $copy_signal_observed in
                "$copy_signal"|"SIG$copy_signal") ;;
                *)
                    copy_signal_violations="$copy_signal_violations $copy_signal-status-$copy_signal_status"
                    ;;
            esac
        fi
        attempt=0
        while [ ! -e "$copy_signal_delayed" ] &&
              [ -n "$copy_signal_producer_pid" ] &&
              kill -0 "$copy_signal_producer_pid" 2>/dev/null &&
              [ "$attempt" -lt 30 ]; do
            sleep 0.1
            attempt=$((attempt + 1))
        done
        if [ -e "$copy_signal_delayed" ]; then
            copy_signal_violations="$copy_signal_violations $copy_signal-delayed"
        fi
        if [ -n "$copy_signal_producer_pid" ] &&
           kill -0 "$copy_signal_producer_pid" 2>/dev/null; then
            copy_signal_violations="$copy_signal_violations $copy_signal-live"
            stop_background "$copy_signal_producer_pid"
        fi
        copy_signal_producer_pid=
        { [ ! -e "$copy_archive" ] && [ ! -L "$copy_archive" ]; } ||
            copy_signal_violations="$copy_signal_violations $copy_signal-published"
        set -- "$copy_dir"/.archive.tar.gz.tmp.*
        if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
            copy_signal_violations="$copy_signal_violations $copy_signal-temp-shape"
        else
            cmp -s "$copy_signal_expected" "$1" ||
                copy_signal_violations="$copy_signal_violations $copy_signal-temp-bytes"
            [ "$(find "$1" -prune -type f -perm 0600 -print)" = "$1" ] ||
                copy_signal_violations="$copy_signal_violations $copy_signal-temp-mode"
        fi
        rm -f "$copy_archive" "$copy_dir"/.archive.tar.gz.tmp.*
        set -- "$copy_dir"/.archive.tar.gz.tmp.*
        { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
            copy_signal_violations="$copy_signal_violations $copy_signal-temp-residue"
    done
    [ -z "$copy_signal_violations" ] ||
        fail "fatal-signal forwarding violations:$copy_signal_violations"

    # An ignored disposition is an intentional caller policy (for example,
    # nohup), not a request for the publisher to install a forwarding handler.
    copy_quit_expected=$tmp/copy-quit-ignored.expected
    printf '%s' quit-ignored-payload >"$copy_quit_expected" ||
        fail "cannot create ignored-SIGQUIT expected payload"
    if ! (
        trap '' QUIT
        unset GITSWITCH_RELEASE_TEST_FATAL_DEFAULTS
        # The spawned producer, not this parent shell, expands PPID.
        # shellcheck disable=SC2016
        exec "$named_publish_helper" "$copy_dir" "$copy_canonical" \
            archive.tar.gz -- /bin/sh -c '
                kill -s QUIT "$PPID" || exit 25
                printf quit-ignored-payload
            '
    ) >"$out" 2>&1; then
        fail "publisher replaced an inherited ignored SIGQUIT disposition"
    fi
    cmp -s "$copy_quit_expected" "$copy_archive" ||
        fail "ignored-SIGQUIT publication changed captured bytes"
    [ "$(find "$copy_archive" -prune -type f -perm 0444 -print)" = \
        "$copy_archive" ] ||
        fail "ignored-SIGQUIT publication was not read-only"
    rm -f "$copy_archive"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
                fail "FreeBSD ignored-SIGQUIT publication did not retire its exact temporary"
            ;;
        *)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "ignored-SIGQUIT publication did not retain one private source"
            cmp -s "$copy_quit_expected" "$1" ||
                fail "ignored-SIGQUIT retained source changed captured bytes"
            [ "$(find "$1" -prune -type f -perm 0444 -print)" = "$1" ] ||
                fail "ignored-SIGQUIT retained source was not read-only"
            rm -f "$1"
            ;;
    esac

    # The direct producer may exit while a background descendant still owns
    # its stdout. Success is not complete until that inherited stream reaches
    # EOF: otherwise the helper can publish and return while the descendant is
    # still extending the supposedly completed artifact.
    copy_stream_marker=$tmp/copy-stream.marker
    # The spawned descendant, not this parent shell, expands the marker.
    # shellcheck disable=SC2016
    AR09_COPY_STREAM_MARKER=$copy_stream_marker \
        "$named_publish_helper" "$copy_dir" "$copy_canonical" \
        archive.tar.gz -- /bin/sh -c '
            printf stream-prefix
            (
                sleep 1
                printf -- "-suffix"
                : >"$AR09_COPY_STREAM_MARKER"
            ) &
        ' >"$out" 2>&1 ||
        fail "publisher rejected a delayed inherited producer stream"
    [ -e "$copy_stream_marker" ] ||
        fail "publisher returned before the inherited producer stream closed"
    [ "$(cat "$copy_archive")" = stream-prefix-suffix ] ||
        fail "publisher reported success before capturing the complete stream"
    rm -f "$copy_archive"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
                fail "FreeBSD stream publication did not retire its exact temporary"
            ;;
        *)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "stream publication did not retain exactly one private source"
            [ "$(cat "$1")" = stream-prefix-suffix ] ||
                fail "retained stream source is incomplete"
            rm -f "$1"
            ;;
    esac

    # AR-11 M42: a known direct-producer failure outranks an inherited stdout
    # descriptor that remains open in a descendant. The publisher must observe
    # exit 23 while supervising the stream, tear down the producer group before
    # the delayed marker, and retain only the already-captured partial bytes.
    copy_status_ready=$tmp/copy-status-priority.ready
    copy_status_pid_file=$tmp/copy-status-priority.pid
    copy_status_release=$tmp/copy-status-priority.release
    copy_status_delayed=$tmp/copy-status-priority.delayed
    copy_status_deadline=$tmp/copy-status-priority.deadline
    copy_watchdog_cancel=$tmp/copy-status-priority.watchdog-cancel
    rm -f "$copy_status_ready" "$copy_status_pid_file" \
        "$copy_status_release" \
        "$copy_status_delayed" "$copy_status_deadline" \
        "$copy_watchdog_cancel"
    # The background descendant, not this parent shell, expands the marker.
    # shellcheck disable=SC2016
    AR11_COPY_STATUS_READY=$copy_status_ready \
        AR11_COPY_STATUS_PID=$copy_status_pid_file \
        AR11_COPY_STATUS_RELEASE=$copy_status_release \
        AR11_COPY_STATUS_DELAYED=$copy_status_delayed \
        "$named_publish_helper" "$copy_dir" "$copy_canonical" \
        archive.tar.gz -- /bin/sh -c '
            printf failed-stream
            (
                : >"$AR11_COPY_STATUS_READY"
                attempt=0
                while [ ! -e "$AR11_COPY_STATUS_RELEASE" ] &&
                      [ "$attempt" -lt 300 ]; do
                    sleep 0.1
                    attempt=$((attempt + 1))
                done
                [ -e "$AR11_COPY_STATUS_RELEASE" ] || exit 0
                : >"$AR11_COPY_STATUS_DELAYED"
            ) &
            descendant_pid=$!
            printf "%s\n" "$descendant_pid" >"$AR11_COPY_STATUS_PID"
            attempt=0
            while [ ! -e "$AR11_COPY_STATUS_READY" ] &&
                  kill -0 "$descendant_pid" 2>/dev/null &&
                  [ "$attempt" -lt 20 ]; do
                sleep 0.1
                attempt=$((attempt + 1))
            done
            if [ ! -e "$AR11_COPY_STATUS_READY" ]; then
                kill "$descendant_pid" 2>/dev/null || :
                wait "$descendant_pid" 2>/dev/null || :
                exit 24
            fi
            exit 23
        ' >"$out" 2>&1 &
    copy_pid=$!
    attempt=0
    while { [ ! -e "$copy_status_ready" ] ||
            [ ! -s "$copy_status_pid_file" ]; } &&
        kill -0 "$copy_pid" 2>/dev/null && [ "$attempt" -lt 100 ]; do
        sleep 0.1
        attempt=$((attempt + 1))
    done
    [ -e "$copy_status_ready" ] && [ -s "$copy_status_pid_file" ] ||
        fail "status-priority descendant did not reach its ready boundary"
    IFS= read -r copy_status_descendant_pid <"$copy_status_pid_file" ||
        fail "cannot read the status-priority descendant PID"
    case $copy_status_descendant_pid in
        ''|0|*[!0-9]*)
            fail "status-priority fixture published an invalid descendant PID"
            ;;
    esac
    (
        watchdog_attempt=0
        while [ ! -e "$copy_watchdog_cancel" ] &&
              kill -0 "$copy_pid" 2>/dev/null &&
              [ "$watchdog_attempt" -lt 30 ]; do
            sleep 0.1
            watchdog_attempt=$((watchdog_attempt + 1))
        done
        if [ ! -e "$copy_watchdog_cancel" ] &&
           kill -0 "$copy_pid" 2>/dev/null; then
            : >"$copy_status_deadline"
            kill -TERM "$copy_pid" 2>/dev/null || :
        fi
    ) &
    copy_watchdog_pid=$!
    if wait "$copy_pid"; then
        copy_pid=
        cancel_watchdog "$copy_watchdog_pid" "$copy_watchdog_cancel"
        copy_watchdog_pid=
        copy_watchdog_cancel=
        : >"$copy_status_release"
        stop_background "$copy_status_descendant_pid"
        copy_status_descendant_pid=
        copy_status_release=
        fail "publisher accepted a failed producer with inherited stdout"
    fi
    copy_pid=
    cancel_watchdog "$copy_watchdog_pid" "$copy_watchdog_cancel"
    copy_watchdog_pid=
    copy_watchdog_cancel=
    [ ! -e "$copy_status_deadline" ] ||
        fail "publisher did not return promptly for a known producer failure"
    grep -F 'archive command exited with status 23' "$out" >/dev/null ||
        fail "inherited stdout hid the direct producer exit status"
    if grep -F 'archive command timed out before output stream completion' \
        "$out" >/dev/null; then
        fail "known producer failure was also reported as a stream timeout"
    fi
    : >"$copy_status_release"
    attempt=0
    while [ ! -e "$copy_status_delayed" ] && [ "$attempt" -lt 20 ]; do
        sleep 0.1
        attempt=$((attempt + 1))
    done
    [ ! -e "$copy_status_delayed" ] ||
        fail "status-priority failure left a producer-group descendant alive"
    attempt=0
    while kill -0 "$copy_status_descendant_pid" 2>/dev/null &&
          [ "$attempt" -lt 20 ]; do
        sleep 0.1
        attempt=$((attempt + 1))
    done
    if kill -0 "$copy_status_descendant_pid" 2>/dev/null; then
        stop_background "$copy_status_descendant_pid"
        fail "status-priority fixture could not retire its descendant"
    fi
    copy_status_descendant_pid=
    copy_status_release=
    { [ ! -e "$copy_archive" ] && [ ! -L "$copy_archive" ]; } ||
        fail "status-priority failure left a canonical artifact"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
                fail "FreeBSD status-priority failure did not retire its exact temporary"
            ;;
        *)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "status-priority failure did not retain one private source"
            [ "$(cat "$1")" = failed-stream ] ||
                fail "status-priority failure changed captured producer bytes"
            rm -f "$1"
            ;;
    esac

    # AR-11 M43: after complete output, successful publication issues
    # uncatchable in-group teardown before releasing the direct PID. Cover a
    # descendant that contributes inherited output before closing stdout and
    # one that detaches stdout immediately; neither may continue useful work
    # after the publisher returns.
    copy_group_violations=
    for copy_group_shape in holding detached; do
        copy_group_ready=$tmp/copy-group-$copy_group_shape.ready
        copy_group_pid_file=$tmp/copy-group-$copy_group_shape.pid
        copy_group_release=$tmp/copy-group-$copy_group_shape.release
        copy_group_delayed=$tmp/copy-group-$copy_group_shape.delayed
        copy_group_finish=$tmp/copy-group-$copy_group_shape.finish
        copy_group_deadline=$tmp/copy-group-$copy_group_shape.deadline
        copy_group_expected=$tmp/copy-group-$copy_group_shape.expected
        copy_watchdog_cancel=$tmp/copy-group-$copy_group_shape.watchdog-cancel
        copy_group_descendant_pid=
        rm -f "$copy_group_ready" "$copy_group_pid_file" \
            "$copy_group_release" "$copy_group_delayed" \
            "$copy_group_finish" "$copy_group_deadline" \
            "$copy_group_expected" "$copy_watchdog_cancel"
        case $copy_group_shape in
            holding)
                copy_group_payload=group-prefix-suffix
                printf '%s' "$copy_group_payload" >"$copy_group_expected" ||
                    fail "cannot create holding expected payload"
                # The background descendant, not this parent shell, expands
                # the fixture paths.
                # shellcheck disable=SC2016
                AR11_COPY_GROUP_READY=$copy_group_ready \
                    AR11_COPY_GROUP_PID=$copy_group_pid_file \
                    AR11_COPY_GROUP_RELEASE=$copy_group_release \
                    AR11_COPY_GROUP_DELAYED=$copy_group_delayed \
                    AR11_COPY_GROUP_FINISH=$copy_group_finish \
                    "$named_publish_helper" "$copy_dir" "$copy_canonical" \
                    archive.tar.gz -- /bin/sh -c '
                        printf group-prefix
                        (
                            printf -- "-suffix"
                            exec 1>&-
                            : >"$AR11_COPY_GROUP_READY"
                            attempt=0
                            while [ ! -e "$AR11_COPY_GROUP_RELEASE" ] &&
                                  [ "$attempt" -lt 300 ]; do
                                sleep 0.1
                                attempt=$((attempt + 1))
                            done
                            [ -e "$AR11_COPY_GROUP_RELEASE" ] || exit 0
                            : >"$AR11_COPY_GROUP_DELAYED"
                            attempt=0
                            while [ ! -e "$AR11_COPY_GROUP_FINISH" ] &&
                                  [ "$attempt" -lt 300 ]; do
                                sleep 0.1
                                attempt=$((attempt + 1))
                            done
                        ) &
                        descendant_pid=$!
                        printf "%s\n" "$descendant_pid" >"$AR11_COPY_GROUP_PID"
                        attempt=0
                        while [ ! -e "$AR11_COPY_GROUP_READY" ] &&
                              kill -0 "$descendant_pid" 2>/dev/null &&
                              [ "$attempt" -lt 20 ]; do
                            sleep 0.1
                            attempt=$((attempt + 1))
                        done
                        [ -e "$AR11_COPY_GROUP_READY" ] || exit 24
                    ' >"$out" 2>&1 &
                ;;
            detached)
                copy_group_payload=detached-payload
                printf '%s' "$copy_group_payload" >"$copy_group_expected" ||
                    fail "cannot create detached expected payload"
                # The background descendant, not this parent shell, expands
                # the fixture paths.
                # shellcheck disable=SC2016
                AR11_COPY_GROUP_READY=$copy_group_ready \
                    AR11_COPY_GROUP_PID=$copy_group_pid_file \
                    AR11_COPY_GROUP_RELEASE=$copy_group_release \
                    AR11_COPY_GROUP_DELAYED=$copy_group_delayed \
                    AR11_COPY_GROUP_FINISH=$copy_group_finish \
                    "$named_publish_helper" "$copy_dir" "$copy_canonical" \
                    archive.tar.gz -- /bin/sh -c '
                        printf detached-payload
                        (
                            : >"$AR11_COPY_GROUP_READY"
                            attempt=0
                            while [ ! -e "$AR11_COPY_GROUP_RELEASE" ] &&
                                  [ "$attempt" -lt 300 ]; do
                                sleep 0.1
                                attempt=$((attempt + 1))
                            done
                            [ -e "$AR11_COPY_GROUP_RELEASE" ] || exit 0
                            : >"$AR11_COPY_GROUP_DELAYED"
                            attempt=0
                            while [ ! -e "$AR11_COPY_GROUP_FINISH" ] &&
                                  [ "$attempt" -lt 300 ]; do
                                sleep 0.1
                                attempt=$((attempt + 1))
                            done
                        ) </dev/null >/dev/null 2>&1 &
                        descendant_pid=$!
                        printf "%s\n" "$descendant_pid" >"$AR11_COPY_GROUP_PID"
                        attempt=0
                        while [ ! -e "$AR11_COPY_GROUP_READY" ] &&
                              kill -0 "$descendant_pid" 2>/dev/null &&
                              [ "$attempt" -lt 20 ]; do
                            sleep 0.1
                            attempt=$((attempt + 1))
                        done
                        [ -e "$AR11_COPY_GROUP_READY" ] || exit 24
                    ' >"$out" 2>&1 &
                ;;
        esac
        copy_pid=$!
        attempt=0
        while { [ ! -e "$copy_group_ready" ] ||
                [ ! -s "$copy_group_pid_file" ]; } &&
            kill -0 "$copy_pid" 2>/dev/null && [ "$attempt" -lt 100 ]; do
            sleep 0.1
            attempt=$((attempt + 1))
        done
        if [ ! -e "$copy_group_ready" ] || [ ! -s "$copy_group_pid_file" ]; then
            fail "$copy_group_shape descendant did not reach its ready boundary"
        fi
        IFS= read -r copy_group_descendant_pid <"$copy_group_pid_file" ||
            fail "cannot read the $copy_group_shape descendant PID"
        case $copy_group_descendant_pid in
            ''|0|*[!0-9]*)
                fail "$copy_group_shape fixture published an invalid descendant PID"
                ;;
        esac
        (
            watchdog_attempt=0
            while [ ! -e "$copy_watchdog_cancel" ] &&
                  kill -0 "$copy_pid" 2>/dev/null &&
                  [ "$watchdog_attempt" -lt 30 ]; do
                sleep 0.1
                watchdog_attempt=$((watchdog_attempt + 1))
            done
            if [ ! -e "$copy_watchdog_cancel" ] &&
               kill -0 "$copy_pid" 2>/dev/null; then
                : >"$copy_group_deadline"
                kill -TERM "$copy_pid" 2>/dev/null || :
            fi
        ) &
        copy_watchdog_pid=$!
        if ! wait "$copy_pid"; then
            copy_pid=
            cancel_watchdog "$copy_watchdog_pid" "$copy_watchdog_cancel"
            copy_watchdog_pid=
            copy_watchdog_cancel=
            fail "publisher rejected the $copy_group_shape descendant fixture"
        fi
        copy_pid=
        cancel_watchdog "$copy_watchdog_pid" "$copy_watchdog_cancel"
        copy_watchdog_pid=
        copy_watchdog_cancel=
        [ ! -e "$copy_group_deadline" ] ||
            fail "publisher did not finish the $copy_group_shape group promptly"
        cmp -s "$copy_group_expected" "$copy_archive" ||
            fail "$copy_group_shape descendant publication changed captured bytes"
        [ "$(find "$copy_archive" -prune -type f -perm 0444 -print)" = \
            "$copy_archive" ] ||
            fail "$copy_group_shape descendant publication was not read-only"

        # Open the work gate immediately after the publication proof. A killed
        # orphan may remain visible to kill -0 as a zombie, but it cannot write
        # the delayed marker; a merely deferred teardown is exposed at once.
        : >"$copy_group_release"
        attempt=0
        while [ ! -e "$copy_group_delayed" ] &&
              kill -0 "$copy_group_descendant_pid" 2>/dev/null &&
              [ "$attempt" -lt 20 ]; do
            sleep 0.1
            attempt=$((attempt + 1))
        done
        if [ -e "$copy_group_delayed" ]; then
            copy_group_violations="$copy_group_violations $copy_group_shape-delayed"
        fi
        if kill -0 "$copy_group_descendant_pid" 2>/dev/null; then
            copy_group_violations="$copy_group_violations $copy_group_shape-live"
        fi
        : >"$copy_group_finish"
        attempt=0
        while kill -0 "$copy_group_descendant_pid" 2>/dev/null &&
              [ "$attempt" -lt 20 ]; do
            sleep 0.1
            attempt=$((attempt + 1))
        done
        if kill -0 "$copy_group_descendant_pid" 2>/dev/null; then
            stop_background "$copy_group_descendant_pid"
        fi
        if kill -0 "$copy_group_descendant_pid" 2>/dev/null; then
            fail "$copy_group_shape fixture could not retire its descendant"
        fi
        copy_group_descendant_pid=
        copy_group_release=
        copy_group_finish=
        rm -f "$copy_archive"
        set -- "$copy_dir"/.archive.tar.gz.tmp.*
        case $copy_platform in
            FreeBSD)
                { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
                    fail "FreeBSD $copy_group_shape publication did not retire its exact temporary"
                ;;
            *)
                { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                    fail "$copy_group_shape publication did not retain one private source"
                cmp -s "$copy_group_expected" "$1" ||
                    fail "$copy_group_shape retained source changed captured bytes"
                [ "$(find "$1" -prune -type f -perm 0444 -print)" = "$1" ] ||
                    fail "$copy_group_shape retained source was not read-only"
                rm -f "$1"
                ;;
        esac
    done
    [ -z "$copy_group_violations" ] ||
        fail "successful publication left producer descendants:$copy_group_violations"

    # AR-11 M45: waitpid makes the producer PID reusable, so every fatal
    # handler must remain blocked until handler-visible ownership is retired.
    # The named-only checkpoint writes B after independently observing all
    # four signals blocked, raises the selected signal immediately after reap,
    # and safely exits 90 before any kill if a stale positive PID is visible.
    copy_reap_expected=$tmp/copy-reap.expected
    copy_reap_report_expected=$tmp/copy-reap-report.expected
    printf '%s' reap-transition-payload >"$copy_reap_expected" ||
        fail "cannot create reap-transition expected payload"
    printf '%s' B >"$copy_reap_report_expected" ||
        fail "cannot create reap-transition expected report"
    copy_reap_violations=
    for copy_reap_signal in HUP INT QUIT TERM; do
        copy_reap_report=$tmp/copy-reap-$copy_reap_signal.report
        rm -f "$copy_reap_report" "$copy_archive" \
            "$copy_dir"/.archive.tar.gz.tmp.*
        copy_reap_status=0
        if GITSWITCH_RELEASE_TEST_FATAL_DEFAULTS=1 \
            GITSWITCH_RELEASE_TEST_REAP_SIGNAL=$copy_reap_signal \
            GITSWITCH_RELEASE_TEST_REAP_REPORT_FD=9 \
            "$named_publish_helper" "$copy_dir" "$copy_canonical" \
                archive.tar.gz -- /bin/sh -c \
                'printf reap-transition-payload' \
                9>"$copy_reap_report" >"$out" 2>&1; then
            copy_reap_status=0
        else
            copy_reap_status=$?
        fi
        if [ "$copy_reap_status" -le 128 ]; then
            copy_reap_violations="$copy_reap_violations $copy_reap_signal-status-$copy_reap_status"
        else
            copy_reap_observed=$(kill -l "$copy_reap_status" 2>/dev/null || :)
            case $copy_reap_observed in
                "$copy_reap_signal"|"SIG$copy_reap_signal") ;;
                *)
                    copy_reap_violations="$copy_reap_violations $copy_reap_signal-status-$copy_reap_status"
                    ;;
            esac
        fi
        cmp -s "$copy_reap_report_expected" "$copy_reap_report" ||
            copy_reap_violations="$copy_reap_violations $copy_reap_signal-guard"
        { [ ! -e "$copy_archive" ] && [ ! -L "$copy_archive" ]; } ||
            copy_reap_violations="$copy_reap_violations $copy_reap_signal-published"
        set -- "$copy_dir"/.archive.tar.gz.tmp.*
        if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
            copy_reap_violations="$copy_reap_violations $copy_reap_signal-temp-shape"
        else
            cmp -s "$copy_reap_expected" "$1" ||
                copy_reap_violations="$copy_reap_violations $copy_reap_signal-temp-bytes"
            [ "$(find "$1" -prune -type f -perm 0600 -print)" = "$1" ] ||
                copy_reap_violations="$copy_reap_violations $copy_reap_signal-temp-mode"
        fi
        rm -f "$copy_archive" "$copy_dir"/.archive.tar.gz.tmp.*
        set -- "$copy_dir"/.archive.tar.gz.tmp.*
        { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
            copy_reap_violations="$copy_reap_violations $copy_reap_signal-temp-residue"
    done
    [ -z "$copy_reap_violations" ] ||
        fail "guarded producer-reap violations:$copy_reap_violations"

    # An ignored SIGCHLD disposition survives exec on supported POSIX hosts
    # and may auto-reap children. The publisher must establish its own wait
    # ownership before fork so the same guarded retirement proof still runs.
    copy_reap_chld_report=$tmp/copy-reap-sigchld.report
    rm -f "$copy_reap_chld_report" "$copy_archive" \
        "$copy_dir"/.archive.tar.gz.tmp.*
    copy_reap_status=0
    if (
        trap '' CHLD
        GITSWITCH_RELEASE_TEST_FATAL_DEFAULTS=1
        GITSWITCH_RELEASE_TEST_REAP_SIGNAL=TERM
        GITSWITCH_RELEASE_TEST_REAP_REPORT_FD=9
        export GITSWITCH_RELEASE_TEST_FATAL_DEFAULTS
        export GITSWITCH_RELEASE_TEST_REAP_SIGNAL
        export GITSWITCH_RELEASE_TEST_REAP_REPORT_FD
        exec "$named_publish_helper" "$copy_dir" "$copy_canonical" \
            archive.tar.gz -- /bin/sh -c 'printf reap-transition-payload' \
            9>"$copy_reap_chld_report" >"$out" 2>&1
    ); then
        copy_reap_status=0
    else
        copy_reap_status=$?
    fi
    [ "$copy_reap_status" -gt 128 ] ||
        fail "inherited-SIGCHLD publisher did not die by its deferred signal"
    copy_reap_observed=$(kill -l "$copy_reap_status" 2>/dev/null || :)
    case $copy_reap_observed in
        TERM|SIGTERM) ;;
        *)
            fail "inherited-SIGCHLD publisher died with status $copy_reap_status"
            ;;
    esac
    cmp -s "$copy_reap_report_expected" "$copy_reap_chld_report" ||
        fail "inherited SIGCHLD bypassed guarded producer retirement"
    { [ ! -e "$copy_archive" ] && [ ! -L "$copy_archive" ]; } ||
        fail "inherited-SIGCHLD transition left a canonical artifact"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
        fail "inherited-SIGCHLD transition did not retain one private temporary"
    cmp -s "$copy_reap_expected" "$1" ||
        fail "inherited-SIGCHLD transition changed captured bytes"
    [ "$(find "$1" -prune -type f -perm 0600 -print)" = "$1" ] ||
        fail "inherited-SIGCHLD transition left a non-private temporary"
    rm -f "$copy_archive" "$copy_dir"/.archive.tar.gz.tmp.*

    # Restoring the exact entry mask matters: a signal blocked by the caller
    # must remain pending and blocked after retirement, not be unconditionally
    # released by the helper. The checkpoint report proves it actually ran.
    copy_reap_preblocked_report=$tmp/copy-reap-preblocked.report
    rm -f "$copy_reap_preblocked_report" "$copy_archive" \
        "$copy_dir"/.archive.tar.gz.tmp.*
    if ! GITSWITCH_RELEASE_TEST_FATAL_DEFAULTS=1 \
        GITSWITCH_RELEASE_TEST_REAP_SIGNAL=TERM \
        GITSWITCH_RELEASE_TEST_REAP_REPORT_FD=9 \
        GITSWITCH_RELEASE_TEST_REAP_PREBLOCKED=1 \
        "$named_publish_helper" "$copy_dir" "$copy_canonical" \
            archive.tar.gz -- /bin/sh -c 'printf reap-transition-payload' \
            9>"$copy_reap_preblocked_report" >"$out" 2>&1; then
        fail "publisher released an inherited blocked fatal signal"
    fi
    cmp -s "$copy_reap_report_expected" "$copy_reap_preblocked_report" ||
        fail "preblocked reap transition did not run under the complete guard"
    cmp -s "$copy_reap_expected" "$copy_archive" ||
        fail "preblocked reap transition changed the published bytes"
    [ "$(find "$copy_archive" -prune -type f -perm 0444 -print)" = \
        "$copy_archive" ] ||
        fail "preblocked reap transition did not publish read-only bytes"
    rm -f "$copy_archive"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
                fail "FreeBSD preblocked reap transition did not retire its exact temporary"
            ;;
        *)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "preblocked reap transition did not retain one private source"
            cmp -s "$copy_reap_expected" "$1" ||
                fail "preblocked reap transition changed its retained source"
            [ "$(find "$1" -prune -type f -perm 0444 -print)" = "$1" ] ||
                fail "preblocked reap transition retained a writable source"
            rm -f "$1"
            ;;
    esac

    # Exercise the second reap owner as well. Closing stdout while the direct
    # producer remains alive drives the bounded wait into terminate_producer;
    # that cleanup must use the same atomic retirement primitive.
    copy_reap_terminate_expected=$tmp/copy-reap-terminate.expected
    copy_reap_terminate_report=$tmp/copy-reap-terminate.report
    copy_reap_terminate_delayed=$tmp/copy-reap-terminate.delayed
    printf '%s' reap-terminate-payload >"$copy_reap_terminate_expected" ||
        fail "cannot create terminate-reap expected payload"
    rm -f "$copy_reap_terminate_report" \
        "$copy_reap_terminate_delayed" "$copy_archive" \
        "$copy_dir"/.archive.tar.gz.tmp.*
    copy_reap_status=0
    # The producer, not this parent shell, expands the fixture variables.
    # shellcheck disable=SC2016
    if AR11_COPY_REAP_DELAYED=$copy_reap_terminate_delayed \
        GITSWITCH_RELEASE_TEST_FATAL_DEFAULTS=1 \
        GITSWITCH_RELEASE_TEST_REAP_SIGNAL=TERM \
        GITSWITCH_RELEASE_TEST_REAP_REPORT_FD=9 \
        "$named_publish_helper" "$copy_dir" "$copy_canonical" \
            archive.tar.gz -- /bin/sh -c '
                printf reap-terminate-payload
                exec 1>&-
                sleep 30
                : >"$AR11_COPY_REAP_DELAYED"
            ' 9>"$copy_reap_terminate_report" >"$out" 2>&1; then
        copy_reap_status=0
    else
        copy_reap_status=$?
    fi
    [ "$copy_reap_status" -gt 128 ] ||
        fail "terminate-reap publisher did not die by its deferred signal"
    copy_reap_observed=$(kill -l "$copy_reap_status" 2>/dev/null || :)
    case $copy_reap_observed in
        TERM|SIGTERM) ;;
        *) fail "terminate-reap publisher died with status $copy_reap_status" ;;
    esac
    cmp -s "$copy_reap_report_expected" "$copy_reap_terminate_report" ||
        fail "terminate-reap transition exposed stale producer ownership"
    [ ! -e "$copy_reap_terminate_delayed" ] ||
        fail "terminate-reap producer survived group teardown"
    { [ ! -e "$copy_archive" ] && [ ! -L "$copy_archive" ]; } ||
        fail "terminate-reap transition left a canonical artifact"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
        fail "terminate-reap transition did not retain one private temporary"
    cmp -s "$copy_reap_terminate_expected" "$1" ||
        fail "terminate-reap transition changed captured bytes"
    [ "$(find "$1" -prune -type f -perm 0600 -print)" = "$1" ] ||
        fail "terminate-reap transition left a non-private temporary"
    rm -f "$copy_archive" "$copy_dir"/.archive.tar.gz.tmp.*
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
        fail "terminate-reap transition left temporary residue"

    # A descendant that never closes the inherited stream must not hang the
    # release indefinitely or leave a canonical artifact. The named test
    # helper uses a five-second build-time deadline; production retains a much
    # larger bounded deadline suitable for real archives.
    copy_timeout_marker=$tmp/copy-stream-timeout.marker
    # shellcheck disable=SC2016
    if AR09_COPY_TIMEOUT_MARKER=$copy_timeout_marker \
        "$named_publish_helper" "$copy_dir" "$copy_canonical" \
        archive.tar.gz -- /bin/sh -c '
            printf partial-stream
            (
                : >"$AR09_COPY_TIMEOUT_MARKER"
                sleep 30
                printf late-stream
            ) &
        ' >"$out" 2>&1; then
        fail "publisher accepted a producer stream that never reached EOF"
    fi
    [ -e "$copy_timeout_marker" ] ||
        fail "stream-timeout descendant did not start"
    grep -F 'archive command timed out before output stream completion' \
        "$out" >/dev/null ||
        fail "stream timeout did not report its incomplete-output boundary"
    { [ ! -e "$copy_archive" ] && [ ! -L "$copy_archive" ]; } ||
        fail "stream timeout left a canonical artifact"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
                fail "FreeBSD stream timeout did not retire its exact temporary"
            ;;
        *)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "stream timeout did not retain exactly one private source"
            [ "$(cat "$1")" = partial-stream ] ||
                fail "stream-timeout retained source changed bytes"
            rm -f "$1"
            ;;
    esac

    # On Darwin, race fclonefileat's committed clone before the helper adopts
    # it: replace the final with a hard link to the named source. Clone ID,
    # bytes, mode, and pathname identity all match, so the explicit distinct-
    # inode proof is essential. The helper must fail without truncating either
    # complete path.
    if [ "$copy_platform" = Darwin ]; then
        copy_adoption_marker=$tmp/copy-adoption.marker
        copy_adoption_release=$tmp/copy-adoption.release
        GITSWITCH_RELEASE_TEST_ADOPTION_MARKER=$copy_adoption_marker \
            GITSWITCH_RELEASE_TEST_ADOPTION_RELEASE=$copy_adoption_release \
            "$named_publish_helper" "$copy_dir" "$copy_canonical" \
            archive.tar.gz -- /bin/sh -c 'printf original-payload' \
            >"$out" 2>&1 &
        copy_pid=$!
        attempt=0
        while [ ! -e "$copy_adoption_marker" ] && \
            kill -0 "$copy_pid" 2>/dev/null && [ "$attempt" -lt 100 ]; do
            sleep 0.1
            attempt=$((attempt + 1))
        done
        [ -e "$copy_adoption_marker" ] ||
            fail "Darwin publication did not reach its adoption race boundary"
        [ "$(cat "$copy_archive")" = original-payload ] ||
            fail "Darwin adoption boundary did not publish the complete clone"
        set -- "$copy_dir"/.archive.tar.gz.tmp.*
        { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
            fail "Darwin adoption race did not expose one private source"
        copy_temp=$1
        rm -f "$copy_archive"
        ln "$copy_temp" "$copy_archive" ||
            fail "cannot install Darwin hard-link adoption fixture"
        : >"$copy_adoption_release"
        if wait "$copy_pid"; then
            copy_pid=
            fail "Darwin publisher adopted its source inode as the final clone"
        fi
        copy_pid=
        grep -F 'complete artifact and private source retained' "$out" \
            >/dev/null ||
            fail "Darwin adoption race did not report retained uncertainty"
        copy_archive_identity=$(stat -f '%d:%i' "$copy_archive") ||
            fail "cannot identify the Darwin adoption artifact"
        copy_temp_identity=$(stat -f '%d:%i' "$copy_temp") ||
            fail "cannot identify the Darwin adoption source"
        [ "$copy_archive_identity" = "$copy_temp_identity" ] ||
            fail "Darwin adoption fixture did not preserve the hard-link alias"
        { [ "$(cat "$copy_archive")" = original-payload ] &&
            [ "$(cat "$copy_temp")" = original-payload ]; } ||
            fail "Darwin adoption rejection changed a complete source"
        rm -f "$copy_archive" "$copy_temp"
    fi

    # FreeBSD cannot hard-link an open descriptor as an unprivileged process:
    # AT_EMPTY_PATH is privilege-gated and fdescfs crosses a mount boundary.
    # Race its identity-sealed named fallback after the pre-link proof. A
    # substituted source may be linked, but the descriptor comparison must
    # reject it without claiming success or changing either complete source.
    if [ "$copy_platform" = FreeBSD ]; then
        copy_publication_marker=$tmp/copy-publication.marker
        copy_publication_release=$tmp/copy-publication.release
        GITSWITCH_RELEASE_TEST_PUBLICATION_MARKER=$copy_publication_marker \
            GITSWITCH_RELEASE_TEST_PUBLICATION_RELEASE=$copy_publication_release \
            "$named_publish_helper" "$copy_dir" "$copy_canonical" \
            archive.tar.gz -- /bin/sh -c 'printf original-payload' \
            >"$out" 2>&1 &
        copy_pid=$!
        attempt=0
        while [ ! -e "$copy_publication_marker" ] && \
            kill -0 "$copy_pid" 2>/dev/null && [ "$attempt" -lt 100 ]; do
            sleep 0.1
            attempt=$((attempt + 1))
        done
        [ -e "$copy_publication_marker" ] ||
            fail "FreeBSD publication did not reach its named-link race boundary"
        set -- "$copy_dir"/.archive.tar.gz.tmp.*
        { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
            fail "FreeBSD publication race did not expose one private source"
        copy_temp=$1
        mv "$copy_temp" "$tmp/original-publication-temp"
        printf '%s' foreign-payload >"$copy_temp"
        : >"$copy_publication_release"
        if wait "$copy_pid"; then
            copy_pid=
            fail "FreeBSD publication accepted a substituted named source"
        fi
        copy_pid=
        grep -F 'published distribution output changed identity' "$out" \
            >/dev/null ||
            fail "FreeBSD publication race did not report identity loss"
        copy_archive_identity=$(stat -f '%d:%i' "$copy_archive") ||
            fail "cannot identify the substituted FreeBSD artifact"
        copy_temp_identity=$(stat -f '%d:%i' "$copy_temp") ||
            fail "cannot identify the substituted FreeBSD source"
        [ "$copy_archive_identity" = "$copy_temp_identity" ] ||
            fail "FreeBSD publication fixture did not link the substituted source"
        { [ "$(cat "$copy_archive")" = foreign-payload ] &&
            [ "$(cat "$copy_temp")" = foreign-payload ]; } ||
            fail "FreeBSD publication rejection changed the foreign source"
        [ "$(cat "$tmp/original-publication-temp")" = original-payload ] ||
            fail "FreeBSD publication rejection changed the pinned source"
        rm -f "$copy_archive" "$copy_temp" "$tmp/original-publication-temp"
    fi

    # Replace the named temporary while its producer still owns the open
    # stdout descriptor.  Publication must read that descriptor, never the
    # replacement path; cleanup must preserve the foreign replacement and
    # fail closed rather than leave a canonical artifact.
    copy_marker=$tmp/copy-producer.marker
    copy_release=$tmp/copy-producer.release
    # The spawned child, not this parent shell, expands these variables.
    # shellcheck disable=SC2016
    AR08_COPY_MARKER=$copy_marker AR08_COPY_RELEASE=$copy_release \
        "$named_publish_helper" "$copy_dir" "$copy_canonical" \
        archive.tar.gz -- /bin/sh -c '
            printf original-payload
            : >"$AR08_COPY_MARKER"
            attempt=0
            while [ ! -e "$AR08_COPY_RELEASE" ] && [ "$attempt" -lt 100 ]; do
                sleep 0.1
                attempt=$((attempt + 1))
            done
            [ -e "$AR08_COPY_RELEASE" ]
        ' >"$out" 2>&1 &
    copy_pid=$!
    attempt=0
    while [ ! -e "$copy_marker" ] && kill -0 "$copy_pid" 2>/dev/null &&
        [ "$attempt" -lt 100 ]; do
        sleep 0.1
        attempt=$((attempt + 1))
    done
    [ -e "$copy_marker" ] || fail "copy producer did not reach substitution boundary"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
        fail "copy publication did not expose exactly one named temporary"
    copy_temp=$1
    mv "$copy_temp" "$tmp/original-copy-temp"
    printf '%s' foreign-payload >"$copy_temp"
    : >"$copy_release"
    if wait "$copy_pid"; then
        copy_pid=
        fail "copy publication accepted a replaced temporary name"
    fi
    copy_pid=
    { [ ! -e "$copy_archive" ] && [ ! -L "$copy_archive" ]; } ||
        fail "replaced temporary left a canonical artifact"
    [ "$(cat "$copy_temp")" = foreign-payload ] ||
        fail "copy cleanup removed or changed the foreign temporary"
    [ "$(cat "$tmp/original-copy-temp")" = original-payload ] ||
        fail "descriptor publication reopened the substituted temporary path"
    rm -f "$copy_temp" "$tmp/original-copy-temp"

    # Race the private-name cleanup after its first identity proof.  The
    # publisher must re-prove the name, preserve the replacement, and retain
    # the already committed complete artifact rather than compensating with a
    # check-then-unlink of the public output.
    copy_cleanup_marker=$tmp/copy-cleanup.marker
    copy_cleanup_release=$tmp/copy-cleanup.release
    GITSWITCH_RELEASE_TEST_CLEANUP_MARKER=$copy_cleanup_marker \
        GITSWITCH_RELEASE_TEST_CLEANUP_RELEASE=$copy_cleanup_release \
        "$named_publish_helper" "$copy_dir" "$copy_canonical" \
        archive.tar.gz -- /bin/sh -c 'printf original-payload' \
        >"$out" 2>&1 &
    copy_pid=$!
    attempt=0
    while [ ! -e "$copy_cleanup_marker" ] && \
        kill -0 "$copy_pid" 2>/dev/null && [ "$attempt" -lt 100 ]; do
        sleep 0.1
        attempt=$((attempt + 1))
    done
    [ -e "$copy_cleanup_marker" ] ||
        fail "copy cleanup did not reach its post-check race boundary"
    [ "$(cat "$copy_archive")" = original-payload ] ||
        fail "copy cleanup boundary did not retain the committed artifact"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
        fail "copy cleanup did not expose exactly one named temporary"
    copy_temp=$1
    mv "$copy_temp" "$tmp/original-cleanup-temp"
    printf '%s' foreign-payload >"$copy_temp"
    : >"$copy_cleanup_release"
    if wait "$copy_pid"; then
        copy_pid=
        fail "copy cleanup accepted a post-check temporary replacement"
    fi
    copy_pid=
    grep -F 'published artifact and temporary name retained' "$out" \
        >/dev/null ||
        fail "copy cleanup did not report its retained commit truthfully"
    [ "$(cat "$copy_archive")" = original-payload ] ||
        fail "failed copy cleanup removed the committed artifact"
    [ "$(cat "$copy_temp")" = foreign-payload ] ||
        fail "failed copy cleanup removed the foreign replacement"
    [ "$(cat "$tmp/original-cleanup-temp")" = original-payload ] ||
        fail "failed copy cleanup changed the pinned source"
    rm -f "$copy_archive" "$copy_temp" "$tmp/original-cleanup-temp"

    # AR-11 M41: the final identity check must bind the bytes, not only the
    # device/inode/type tuple. Pause after publication, retain a write-capable
    # descriptor, restore the intended read-only mode, and replace the payload
    # with equal-length bytes through that descriptor. Path identity, size,
    # and final mode all remain unchanged; only a descriptor digest can reject
    # the late mutation before the publisher reports success.
    copy_content_marker=$tmp/copy-content.marker
    copy_content_release=$tmp/copy-content.release
    GITSWITCH_RELEASE_TEST_CLEANUP_MARKER=$copy_content_marker \
        GITSWITCH_RELEASE_TEST_CLEANUP_RELEASE=$copy_content_release \
        "$named_publish_helper" "$copy_dir" "$copy_canonical" \
        archive.tar.gz -- /bin/sh -c 'printf original-payload' \
        >"$out" 2>&1 &
    copy_pid=$!
    attempt=0
    while [ ! -e "$copy_content_marker" ] && \
        kill -0 "$copy_pid" 2>/dev/null && [ "$attempt" -lt 100 ]; do
        sleep 0.1
        attempt=$((attempt + 1))
    done
    [ -e "$copy_content_marker" ] ||
        fail "copy publication did not reach its content-proof boundary"
    [ "$(cat "$copy_archive")" = original-payload ] ||
        fail "content-proof boundary did not publish the complete artifact"
    [ "$(find "$copy_archive" -prune -type f -perm 0444 -print)" = \
        "$copy_archive" ] ||
        fail "content-proof boundary exposed writable artifact mode"
    chmod 0644 "$copy_archive" ||
        fail "cannot prepare the content-change fixture"
    exec 9<>"$copy_archive" ||
        fail "cannot pin a write-capable content-change descriptor"
    chmod 0444 "$copy_archive" ||
        fail "cannot restore the content-change fixture mode"
    printf '%s' 'mutated-payload!' >&9 ||
        fail "cannot apply the equal-length content change"
    exec 9>&-
    [ "$(cat "$copy_archive")" = 'mutated-payload!' ] ||
        fail "content-change fixture did not replace the published bytes"
    : >"$copy_content_release"
    if wait "$copy_pid"; then
        copy_pid=
        fail "publisher accepted same-inode equal-length content change"
    fi
    copy_pid=
    grep -F 'published distribution output changed content before completion' \
        "$out" >/dev/null ||
        fail "content change did not report the failed final byte proof"
    [ "$(cat "$copy_archive")" = 'mutated-payload!' ] ||
        fail "content-change rejection altered the retained artifact"
    rm -f "$copy_archive" "$copy_dir"/.archive.tar.gz.tmp.*

    if "$named_publish_helper" "$copy_dir" "$copy_canonical" archive.tar.gz \
        -- /bin/sh -c 'printf partial; exit 9' >"$out" 2>&1; then
        fail "descriptor-bound publication accepted producer failure"
    fi
    { [ ! -e "$copy_archive" ] && [ ! -L "$copy_archive" ]; } ||
        fail "failed descriptor-bound publication left an artifact"
    set -- "$copy_dir"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
                fail "FreeBSD producer failure did not retire its exact temporary"
            ;;
        Darwin)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "Darwin producer failure did not retain exactly one private source"
            [ "$(cat "$1")" = partial ] ||
                fail "Darwin failed-producer source changed bytes"
            rm -f "$1"
            ;;
        *)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "producer failure did not retain exactly one private source"
            [ "$(cat "$1")" = partial ] ||
                fail "failed-producer retained source changed bytes"
            rm -f "$1"
            ;;
    esac
    if find "$copy_dir" -name '.*.tmp.*' -print | grep . >/dev/null; then
        fail "release contract did not remove its inspected test residue"
    fi

    "$make_cmd" -C "$clean_repo" dist >"$out" 2>&1 ||
        fail "clean committed release failed"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"

    # The root-local mutex must cover the verified helper's use, not merely
    # generation. Gate A inside `git archive`, then prove an independent Make
    # process with a different HOSTCC cannot compile or replace the shared
    # helper generation until A finishes consuming it.
    lock_shims=$tmp/release-lock-shims
    lock_ready=$tmp/release-lock.ready
    lock_release=$tmp/release-lock.release
    lock_status=$tmp/release-lock.status
    lock_a_out=$tmp/release-lock-a.out
    lock_b_out=$tmp/release-lock-b.out
    lock_hostcc_log=$tmp/release-lock-hostcc.log
    mkdir "$lock_shims"
    real_git=$(command -v git) || fail "git is unavailable for lock fixture"
    real_hostcc=$(command -v cc 2>/dev/null ||
        command -v gcc 2>/dev/null || command -v clang 2>/dev/null) ||
        fail "a host C compiler is unavailable for lock fixture"
    cat >"$lock_shims/git" <<'EOF'
#!/bin/sh
: "${AR11_LOCK_REAL_GIT:?}"
: "${AR11_LOCK_REPO:?}"
: "${AR11_LOCK_READY:?}"
: "${AR11_LOCK_RELEASE:?}"
if [ "${1-}" = -C ] && [ "${2-}" = "$AR11_LOCK_REPO" ] &&
   [ "${3-}" = archive ]; then
    ready_tmp=$AR11_LOCK_READY.tmp.$$
    printf '%s\n' "$$" >"$ready_tmp" || exit 91
    mv -f "$ready_tmp" "$AR11_LOCK_READY" || exit 92
    gate_tries=0
    while [ ! -s "$AR11_LOCK_RELEASE" ]; do
        gate_tries=$((gate_tries + 1))
        [ "$gate_tries" -lt 300 ] || exit 93
        sleep 0.1
    done
fi
exec "$AR11_LOCK_REAL_GIT" "$@"
EOF
    cat >"$lock_shims/hostcc-b" <<'EOF'
#!/bin/sh
: "${AR11_LOCK_REAL_HOSTCC:?}"
: "${AR11_LOCK_HOSTCC_LOG:?}"
if [ "${1-}" = --version ]; then
    exec "$AR11_LOCK_REAL_HOSTCC" "$@"
fi
printf '%s\n' compile >>"$AR11_LOCK_HOSTCC_LOG" || exit 94
exec "$AR11_LOCK_REAL_HOSTCC" "$@"
EOF
    chmod 0700 "$lock_shims/git" "$lock_shims/hostcc-b"
    lock_hostcc=$(CDPATH='' cd "$lock_shims" && pwd -P)/hostcc-b
    cp "$clean_repo/build/tools/.release-publish.provenance" \
        "$tmp/release-lock.receipt.before"
    rm -f "$archive" "$lock_ready" "$lock_release" "$lock_status" \
        "$lock_hostcc_log"
    (
        lock_a_status=0
        PATH="$lock_shims:$PATH" \
            AR11_LOCK_REAL_GIT="$real_git" \
            AR11_LOCK_REPO="$clean_repo" \
            AR11_LOCK_READY="$lock_ready" \
            AR11_LOCK_RELEASE="$lock_release" \
            "$make_cmd" -C "$clean_repo" dist >"$lock_a_out" 2>&1 ||
            lock_a_status=$?
        status_tmp=$lock_status.tmp.$$
        printf '%s\n' "$lock_a_status" >"$status_tmp" || exit 95
        mv -f "$status_tmp" "$lock_status" || exit 96
        exit "$lock_a_status"
    ) &
    lock_dist_pid=$!
    lock_wait_tries=0
    while [ ! -s "$lock_ready" ]; do
        if ! kill -0 "$lock_dist_pid" 2>/dev/null; then
            sed -n '1,200p' "$lock_a_out" >&2
            fail "first release process exited before its archive gate"
        fi
        lock_wait_tries=$((lock_wait_tries + 1))
        [ "$lock_wait_tries" -lt 300 ] ||
            fail "first release process did not reach its archive gate"
        sleep 0.1
    done
    lock_gate_pid=$(sed -n '1p' "$lock_ready")
    case $lock_gate_pid in
        ''|*[!0-9]*) fail "archive gate did not publish a valid PID" ;;
    esac
    kill -0 "$lock_gate_pid" 2>/dev/null ||
        fail "archive gate exited before contention"
    [ -s "$clean_repo/.gitswitch-release-publish.lock/owner" ] ||
        fail "first release process reached use without owning the mutex"

    : >"$lock_hostcc_log"
    if GITSWITCH_RELEASE_LOCK_ATTEMPTS=1 \
        AR11_LOCK_REAL_HOSTCC="$real_hostcc" \
        AR11_LOCK_HOSTCC_LOG="$lock_hostcc_log" \
        "$make_cmd" -C "$clean_repo" HOSTCC="$lock_hostcc" \
        release-publish-helpers >"$lock_b_out" 2>&1; then
        fail "contending helper generation bypassed active release use"
    fi
    grep -F 'release publisher is busy or its lock is stale' \
        "$lock_b_out" >/dev/null ||
        fail "contending helper generation lacked a precise busy result"
    [ ! -s "$lock_hostcc_log" ] ||
        fail "contending helper generation invoked its compiler"
    cmp -s "$clean_repo/build/tools/.release-publish.provenance" \
        "$tmp/release-lock.receipt.before" ||
        fail "contending helper generation changed shared provenance"
    [ -d "$clean_repo/.gitswitch-release-publish.lock" ] ||
        fail "contender removed the first release process mutex"

    lock_release_tmp=$lock_release.tmp.$$
    printf '%s\n' release >"$lock_release_tmp" ||
        fail "cannot publish archive-gate release"
    mv -f "$lock_release_tmp" "$lock_release" ||
        fail "cannot release archive gate"
    lock_wait_tries=0
    while [ ! -s "$lock_status" ]; do
        if ! kill -0 "$lock_dist_pid" 2>/dev/null; then
            sed -n '1,200p' "$lock_a_out" >&2
            fail "first release process exited without a completion status"
        fi
        lock_wait_tries=$((lock_wait_tries + 1))
        [ "$lock_wait_tries" -lt 300 ] ||
            fail "first release process did not finish after gate release"
        sleep 0.1
    done
    [ "$(cat "$lock_status")" -eq 0 ] || {
        sed -n '1,200p' "$lock_a_out" >&2
        fail "first release process failed after gate release"
    }
    wait "$lock_dist_pid" || fail "first release process returned failure"
    lock_dist_pid=
    lock_gate_pid=
    [ ! -e "$clean_repo/.gitswitch-release-publish.lock" ] &&
        [ ! -L "$clean_repo/.gitswitch-release-publish.lock" ] ||
        fail "successful release retained its mutex"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"

    : >"$lock_hostcc_log"
    AR11_LOCK_REAL_HOSTCC="$real_hostcc" \
        AR11_LOCK_HOSTCC_LOG="$lock_hostcc_log" \
        "$make_cmd" -C "$clean_repo" HOSTCC="$lock_hostcc" \
        release-publish-helpers >"$lock_b_out" 2>&1 || {
        sed -n '1,200p' "$lock_b_out" >&2
        fail "helper generation did not recover after mutex release"
    }
    [ "$(wc -l <"$lock_hostcc_log")" -eq 2 ] ||
        fail "post-release helper generation did not compile both profiles"
    grep -F "hostcc_resolved=$lock_hostcc" \
        "$clean_repo/build/tools/.release-publish.provenance" >/dev/null ||
        fail "post-release provenance did not bind the contending HOSTCC"
    [ ! -e "$clean_repo/.gitswitch-release-publish.lock" ] &&
        [ ! -L "$clean_repo/.gitswitch-release-publish.lock" ] ||
        fail "post-release helper generation retained its mutex"

    # The helper target is a release-use provenance gate, not a timestamp
    # hint. A future-dated foreign executable must be rebuilt before dist
    # invokes it; otherwise /usr/bin/true lets Make report success without
    # producing any archive.
    foreign_publish_helper=
    for candidate in /usr/bin/true /bin/true; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            foreign_publish_helper=$candidate
            break
        fi
    done
    [ -n "$foreign_publish_helper" ] ||
        fail "cannot find a regular true executable for helper provenance"
    rm -f "$archive"
    cp "$foreign_publish_helper" \
        "$clean_repo/build/tools/release-publish" ||
        fail "cannot install foreign publisher fixture"
    touch -t 203501010000 "$clean_repo/build/tools/release-publish" ||
        fail "cannot future-date foreign publisher fixture"
    "$make_cmd" -C "$clean_repo" dist >"$out" 2>&1 || {
        sed -n '1,200p' "$out" >&2
        fail "dist did not recover a future-dated foreign publisher"
    }
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"

    # The helper target itself is fixed inside the ignored build namespace.
    # Before that boundary was override-protected, `-B
    # DIST_PUBLISH_HELPER=VERSION` compiled the helper over tracked VERSION and
    # still returned success. Exercise both primary documentation inputs and
    # the helper-directory variable while forcing a rebuild.
    rm -f "$archive"
    "$make_cmd" -B -C "$clean_repo" DIST_PUBLISH_HELPER=VERSION \
        TOOLBUILDDIR=. dist >"$out" 2>&1 ||
        fail "fixed publisher target rejected a hostile VERSION override"
    cmp -s "$clean_repo/VERSION" "$tmp/VERSION.before" ||
        fail "publisher target override changed tracked VERSION"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"
    rm -f "$archive"
    "$make_cmd" -B -C "$clean_repo" DIST_PUBLISH_HELPER=README.md \
        TOOLBUILDDIR=src dist >"$out" 2>&1 ||
        fail "fixed publisher target rejected a hostile README override"
    cmp -s "$clean_repo/README.md" "$tmp/README.before" ||
        fail "publisher target override changed tracked README"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"

    # An existing artifact is never replaced, even by a byte-identical rerun.
    cp "$archive" "$tmp/archive.before"
    if "$make_cmd" -C "$clean_repo" dist >"$out" 2>&1; then
        fail "existing release archive was overwritten"
    fi
    grep -F 'ERROR: distribution archive already exists' "$out" >/dev/null ||
        fail "existing archive rejection was not precise"
    cmp -s "$archive" "$tmp/archive.before" ||
        fail "existing archive bytes changed after rejection"

    # Caller-controlled output may never alias a tracked/manifest path, an
    # absolute source path, or a lexical escape from the artifact directory.
    rm -f "$archive"
    expect_output_rejected "VERSION" "$clean_repo" "$make_cmd" VERSION "$out"
    expect_output_rejected "absolute README" "$clean_repo" "$make_cmd" \
        "$clean_repo/README.md" "$out"
    expect_output_rejected "manifest member" "$clean_repo" "$make_cmd" \
        src/main.c "$out"
    expect_output_rejected "lexical escape" "$clean_repo" "$make_cmd" \
        "build/dist/../../VERSION" "$out"
    cmp -s "$clean_repo/VERSION" "$tmp/VERSION.before" ||
        fail "VERSION bytes changed during output-alias rejection"
    cmp -s "$clean_repo/README.md" "$tmp/README.before" ||
        fail "README bytes changed during output-alias rejection"
    cmp -s "$clean_repo/src/main.c" "$tmp/main.before" ||
        fail "manifest source bytes changed during output-alias rejection"

    # A symlink at the one valid publication name survives unchanged and its
    # source target is never truncated or removed.
    mkdir -p "$(dirname "$archive")"
    ln -s ../../README.md "$archive"
    if "$make_cmd" -C "$clean_repo" dist >"$out" 2>&1; then
        fail "symlink release output was replaced"
    fi
    { [ -L "$archive" ] &&
        [ "$(readlink "$archive")" = ../../README.md ]; } ||
        fail "release output symlink changed after rejection"
    cmp -s "$clean_repo/README.md" "$tmp/README.before" ||
        fail "release output symlink target was modified"
    rm -f "$archive"

    # The physical absolute spelling of the dedicated output is also valid;
    # publication still lands at the one canonical path from a fresh temp.
    archive_physical_dir=$(CDPATH='' cd "${archive%/*}" && pwd -P) ||
        fail "cannot resolve physical distribution directory"
    archive_physical=$archive_physical_dir/${archive##*/}
    "$make_cmd" -C "$clean_repo" DIST_ARCHIVE="$archive_physical" dist \
        >"$out" 2>&1 ||
        fail "valid absolute artifact path was rejected"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"
    status_after=$(git -C "$clean_repo" status --porcelain=v1 --untracked-files=all)
    [ "$status_after" = "$status_before" ] ||
        fail "distribution output matrix changed Git status"

    # Developer VERSION/DIST_ROOT overrides must not rename committed payload.
    rm -f "$archive"
    "$make_cmd" -C "$clean_repo" VERSION=9.9.9-uncommitted \
        DIST_ROOT=gitswitcher-9.9.9-uncommitted dist >"$out" 2>&1 ||
        fail "commit-pinned release failed under irrelevant live overrides"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"
    [ ! -e "$clean_repo/build/dist/gitswitcher-9.9.9-uncommitted.tar.gz" ] ||
        fail "VERSION/DIST_ROOT override renamed committed release payload"

    # The RPM target must consume the spec embedded in that same archive.
    rm -f "$archive"
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
    inspect_dist_residue "$archive" "$copy_platform"

    # The archive producer must never receive a reopenable temporary path.
    # This wrapper reproduces the original same-uid substitution: when it sees
    # git archive -o PATH, it replaces PATH with a symlink to tracked VERSION
    # immediately before the real Git opens it. Descriptor-streamed output has
    # no such argument, so the attempted swap cannot identify any temp name.
    race_repo=$tmp/dist-race
    git clone --quiet "$root" "$race_repo" ||
        fail "cannot clone distribution temp-race fixture"
    race_shims=$tmp/dist-race-shims
    race_marker=$tmp/dist-race.marker
    mkdir "$race_shims"
    real_git=$(command -v git) || fail "git is unavailable for dist race"
    cat >"$race_shims/git" <<'EOF'
#!/bin/sh
: "${AR08_REAL_GIT:?}"
output=
previous=
is_archive=false
for arg do
    if [ "$previous" = -o ]; then
        output=$arg
    fi
    case $arg in
        archive) is_archive=true ;;
        --output=*) output=${arg#--output=} ;;
    esac
    previous=$arg
done
if [ "$is_archive" = true ]; then
    printf '%s\n' invoked >>"$AR08_DIST_RACE_MARKER"
    if [ -n "${AR08_DIST_SWAP_DIR-}" ]; then
        mv "$AR08_DIST_SWAP_DIR" "$AR08_DIST_SWAP_DIR.pinned"
        mkdir "$AR08_DIST_SWAP_DIR"
    fi
    if [ -n "$output" ]; then
        rm -f "$output"
        ln -s "$AR08_DIST_RACE_TARGET" "$output"
    fi
fi
exec "$AR08_REAL_GIT" "$@"
EOF
    chmod 0700 "$race_shims/git"
    cp "$race_repo/VERSION" "$tmp/race.VERSION.before"
    cp "$race_repo/README.md" "$tmp/race.README.before"
    race_version=$(cat "$race_repo/VERSION")
    race_archive=$race_repo/build/dist/gitswitcher-$race_version.tar.gz
    PATH="$race_shims:$PATH" AR08_REAL_GIT="$real_git" \
        AR08_DIST_RACE_MARKER="$race_marker" \
        AR08_DIST_RACE_TARGET="$race_repo/VERSION" \
        "$make_cmd" -C "$race_repo" dist >"$out" 2>&1 || {
        sed -n '1,200p' "$out" >&2
        fail "descriptor-pinned distribution race fixture failed"
    }
    [ -s "$race_marker" ] || fail "distribution race wrapper was not exercised"
    cmp -s "$race_repo/VERSION" "$tmp/race.VERSION.before" ||
        fail "distribution temp substitution changed tracked VERSION"
    cmp -s "$race_repo/README.md" "$tmp/race.README.before" ||
        fail "distribution temp substitution changed tracked README"
    { [ -f "$race_archive" ] && [ ! -L "$race_archive" ]; } ||
        fail "distribution race published a non-regular archive"
    inspect_dist_residue "$race_archive" "$copy_platform"
    rm -f "$race_archive"
    : >"$race_marker"
    if PATH="$race_shims:$PATH" AR08_REAL_GIT="$real_git" \
        AR08_DIST_RACE_MARKER="$race_marker" \
        AR08_DIST_RACE_TARGET="$race_repo/VERSION" \
        AR08_DIST_SWAP_DIR="$race_repo/build/dist" \
        "$make_cmd" -C "$race_repo" dist >"$out" 2>&1; then
        fail "distribution succeeded after its canonical directory was replaced"
    fi
    grep -F 'canonical distribution directory changed' "$out" >/dev/null ||
        fail "distribution directory-race rejection was not precise"
    cmp -s "$race_repo/VERSION" "$tmp/race.VERSION.before" ||
        fail "distribution directory substitution changed tracked VERSION"
    { [ ! -e "$race_archive" ] && [ ! -L "$race_archive" ]; } ||
        fail "distribution directory substitution published into the replacement directory"
    race_pinned_archive=$race_repo/build/dist.pinned/gitswitcher-$race_version.tar.gz
    { [ -f "$race_pinned_archive" ] && [ ! -L "$race_pinned_archive" ]; } ||
        fail "post-commit directory uncertainty did not retain the complete artifact"
    assert_archive_metadata "$race_pinned_archive" "$dist_root" "$version"
    inspect_dist_residue "$race_pinned_archive" "$copy_platform"
    rm -f "$race_pinned_archive"

    dirty_version=$tmp/dirty-version
    git clone --quiet "$root" "$dirty_version" || fail "cannot clone VERSION fixture"
    printf '%s\n' '9.9.9-dirty' >"$dirty_version/VERSION"
    expect_dirty_rejected "dirty VERSION" "$dirty_version" "$make_cmd" \
        "$dirty_version/build/dist/$dist_root.tar.gz" "$out"

    dirty_spec=$tmp/dirty-spec
    git clone --quiet "$root" "$dirty_spec" || fail "cannot clone spec fixture"
    printf '%s\n' '# uncommitted RPM instruction' >>"$dirty_spec/gitswitcher.spec"
    expect_dirty_rejected "dirty spec" "$dirty_spec" "$make_cmd" \
        "$dirty_spec/build/dist/$dist_root.tar.gz" "$out"

    dirty_manifest=$tmp/dirty-manifest
    git clone --quiet "$root" "$dirty_manifest" || fail "cannot clone manifest fixture"
    printf '%s\n' '# uncommitted release text' >>"$dirty_manifest/README.md"
    expect_dirty_rejected "dirty tracked manifest" "$dirty_manifest" \
        "$make_cmd" "$dirty_manifest/build/dist/$dist_root.tar.gz" "$out"

    untracked_manifest=$tmp/untracked-manifest
    git clone --quiet "$root" "$untracked_manifest" ||
        fail "cannot clone untracked manifest fixture"
    printf '%s\n' 'uncommitted release input' >"$untracked_manifest/src/.ar07-untracked"
    expect_dirty_rejected "untracked manifest" "$untracked_manifest" \
        "$make_cmd" "$untracked_manifest/build/dist/$dist_root.tar.gz" "$out"

    printf 'ar07-release: PASS (commit-pinned metadata and dirty-input refusal)\n'
}

[ "$#" -ge 1 ] ||
    fail "usage: $0 {manifest|artifact|artifact-publish|copy-publish|install|neuter} ..."
mode=$1
shift
case $mode in
    manifest) check_manifest_contract "$@" ;;
    artifact) check_artifact_pair "$@" ;;
    artifact-publish) publish_release_artifact "$@" ;;
    copy-publish) publish_install_copy "$@" ;;
    install) check_install_staging_contract "$@" ;;
    neuter) check_neuter_contract "$@" ;;
    *) fail "unknown mode '$mode'" ;;
esac
