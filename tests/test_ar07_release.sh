#!/bin/sh
# AR-07 T18 release-input and native artifact contracts.

set -eu

fail()
{
    printf 'ar07-release: ERROR: %s\n' "$*" >&2
    exit 1
}

# VERSION permits ERE metacharacters such as '+' and '.', so archive roots
# must be compared as literal path components rather than interpolated into a
# regular expression (AR-11 M48).
archive_root_entry_count()
{
    LC_ALL=C awk -v root="$1" '
        $0 == root || $0 == root "/" { count++ }
        END { print count + 0 }
    '
}

archive_members_within_root()
{
    LC_ALL=C awk -v root="$1" '
        $0 != root && index($0, root "/") != 1 { outside = 1; exit }
        END { exit outside ? 1 : 0 }
    '
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
    gzip -t "$archive" || fail "release archive is not a complete gzip stream"
    members=$(tar -tzf "$archive") || fail "cannot list release archive"
    root_entries=$(printf '%s\n' "$members" |
        archive_root_entry_count "$dist_root")
    [ "$root_entries" -eq 1 ] ||
        fail "archive does not contain exactly one $dist_root root entry"
    if ! printf '%s\n' "$members" |
        archive_members_within_root "$dist_root"; then
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

check_literal_archive_root_contract()
(
    m48_work=$1
    m48_source=$2
    m48_make=$3
    m48_version=1.8.0+meta
    m48_dist_root=gitswitcher-$m48_version
    m48_regex_alias=gitswitcher-1x8y00meta
    m48_repo=$m48_work/m48-literal-version
    m48_out=$m48_work/m48-literal.out
    m48_home=$m48_work/m48-home
    m48_stop_make=$m48_work/m48-stop-make

    m48_make_mutant()
    {
        m48_mutant_label=$1
        m48_mutant_archive=$2
        m48_mutant_tree=$m48_work/m48-mutant-$m48_mutant_label

        rm -rf "$m48_mutant_tree"
        mkdir -p "$m48_mutant_tree" ||
            fail "cannot create M48 $m48_mutant_label fixture"
        case $m48_mutant_label in
            prefix)
                mkdir -p "$m48_mutant_tree/$m48_dist_root" \
                    "$m48_mutant_tree/$m48_dist_root-prefix" ||
                    fail "cannot create M48 prefix fixture roots"
                : >"$m48_mutant_tree/$m48_dist_root-prefix/marker"
                tar -czf "$m48_mutant_archive" -C "$m48_mutant_tree" \
                    "$m48_dist_root" "$m48_dist_root-prefix" ||
                    fail "cannot create M48 prefix archive"
                ;;
            regex-alias)
                mkdir -p "$m48_mutant_tree/$m48_regex_alias" ||
                    fail "cannot create M48 regex-alias fixture root"
                : >"$m48_mutant_tree/$m48_regex_alias/marker"
                tar -czf "$m48_mutant_archive" -C "$m48_mutant_tree" \
                    "$m48_regex_alias" ||
                    fail "cannot create M48 regex-alias archive"
                ;;
            outside)
                mkdir -p "$m48_mutant_tree/$m48_dist_root" \
                    "$m48_mutant_tree/outside-root" ||
                    fail "cannot create M48 outside-root fixture roots"
                : >"$m48_mutant_tree/outside-root/marker"
                tar -czf "$m48_mutant_archive" -C "$m48_mutant_tree" \
                    "$m48_dist_root" outside-root ||
                    fail "cannot create M48 outside-root archive"
                ;;
            *) fail "unknown M48 archive mutant: $m48_mutant_label" ;;
        esac
    }

    m48_expect_rejected()
    {
        m48_reject_label=$1
        m48_reject_archive=$2
        m48_metadata_message=$3
        m48_dist_message=$4
        m48_metadata_out=$m48_work/m48-$m48_reject_label-metadata.out
        m48_dist_out=$m48_work/m48-$m48_reject_label-dist.out
        m48_dist_archive=$m48_work/m48-$m48_reject_label-dist.tar.gz

        if (assert_archive_metadata "$m48_reject_archive" \
            "$m48_dist_root" "$m48_version") >"$m48_metadata_out" 2>&1; then
            fail "M48 $m48_reject_label metadata mutant unexpectedly passed"
        fi
        grep -F "$m48_metadata_message" "$m48_metadata_out" >/dev/null || {
            sed -n '1,120p' "$m48_metadata_out" >&2
            fail "M48 $m48_reject_label metadata mutant missed its exact gate"
        }

        cp "$m48_reject_archive" "$m48_dist_archive" ||
            fail "cannot copy M48 $m48_reject_label dist fixture"
        m48_dist_status=0
        (CDPATH='' cd "$m48_repo" && HOME="$m48_home" \
            sh "$m48_source/tests/test_dist.sh" "$m48_dist_archive" \
                "$m48_dist_root" \
                /usr/local "$m48_stop_make" -- VERSION gitswitcher.spec) \
                >"$m48_dist_out" 2>&1 || m48_dist_status=$?
        [ "$m48_dist_status" -ne 0 ] ||
            fail "M48 $m48_reject_label dist mutant unexpectedly passed"
        grep -F "$m48_dist_message" "$m48_dist_out" >/dev/null || {
            sed -n '1,120p' "$m48_dist_out" >&2
            fail "M48 $m48_reject_label dist mutant missed its exact gate"
        }
        cmp -s "$m48_reject_archive" "$m48_dist_archive" ||
            fail "M48 $m48_reject_label failure changed caller-owned archive"
    }

    git clone --quiet "$m48_source" "$m48_repo" ||
        fail "cannot clone M48 literal-version fixture"
    printf '%s\n' "$m48_version" >"$m48_repo/VERSION" ||
        fail "cannot write M48 literal VERSION"
    awk -v version="$m48_version" '
        !changed && /^Version:[[:space:]]*/ {
            print "Version:        " version
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$m48_repo/gitswitcher.spec" >"$m48_repo/gitswitcher.spec.updated" ||
        fail "cannot rewrite M48 literal spec version"
    mv "$m48_repo/gitswitcher.spec.updated" "$m48_repo/gitswitcher.spec" ||
        fail "cannot install M48 literal spec version"
    git -C "$m48_repo" add VERSION gitswitcher.spec ||
        fail "cannot stage M48 literal-version fixture"
    git -C "$m48_repo" -c user.name='AR-11 M48' \
        -c user.email='ar11-m48@example.invalid' -c commit.gpgsign=false \
        commit --quiet -m 'M48 literal version fixture' ||
        fail "cannot commit M48 literal-version fixture"

    "$m48_make" -C "$m48_repo" dist >"$m48_out" 2>&1 || {
        sed -n '1,160p' "$m48_out" >&2
        fail "M48 literal-version distribution failed"
    }
    m48_archive=$m48_repo/build/dist/$m48_dist_root.tar.gz
    assert_archive_metadata "$m48_archive" "$m48_dist_root" "$m48_version"

    mkdir -p "$m48_home" || fail "cannot create M48 private HOME"
    chmod 0700 "$m48_home" || fail "cannot protect M48 private HOME"
    cat >"$m48_stop_make" <<'EOF'
#!/bin/sh
printf '%s\n' M48_ARCHIVE_VALIDATION_COMPLETE
exit 79
EOF
    chmod 0755 "$m48_stop_make" || fail "cannot make M48 stop shim executable"
    m48_dist_archive=$m48_work/m48-valid-dist.tar.gz
    cp "$m48_archive" "$m48_dist_archive" ||
        fail "cannot copy M48 valid dist fixture"
    m48_dist_status=0
    (CDPATH='' cd "$m48_repo" && HOME="$m48_home" \
        sh "$m48_source/tests/test_dist.sh" "$m48_dist_archive" \
            "$m48_dist_root" \
            /usr/local "$m48_stop_make" -- src tests tools completions \
            VERSION LICENSE README.md Makefile gitswitcher.spec) \
            >"$m48_out" 2>&1 || m48_dist_status=$?
    [ "$m48_dist_status" -eq 79 ] || {
        sed -n '1,160p' "$m48_out" >&2
        fail "M48 literal root did not reach the distcheck build boundary"
    }
    grep -Fx M48_ARCHIVE_VALIDATION_COMPLETE "$m48_out" >/dev/null ||
        fail "M48 distcheck did not complete literal archive validation"
    cmp -s "$m48_archive" "$m48_dist_archive" ||
        fail "M48 build-boundary failure changed caller-owned archive"

    # Drive the validator's TERM trap only after a valid archive has crossed
    # every metadata gate and reached the extracted build boundary. The child
    # make shim signals its direct test_dist.sh parent; trapped status 1 is
    # distinct from the shim's fallback 79 if TERM is lost or ignored.
    m48_signal_make=$m48_work/m48-signal-make
    m48_signal_marker=$m48_work/m48-signal.marker
    cat >"$m48_signal_make" <<'EOF'
#!/bin/sh
set -eu
: "${GITSWITCH_L42_SIGNAL_MARKER:?}"
printf '%s\n' ready >"$GITSWITCH_L42_SIGNAL_MARKER"
kill -TERM "$PPID" || exit 78
exit 79
EOF
    chmod 0755 "$m48_signal_make" ||
        fail "cannot activate M48 distcheck signal shim"
    m48_signal_archive=$m48_work/m48-signal-dist.tar.gz
    cp "$m48_archive" "$m48_signal_archive" ||
        fail "cannot copy M48 signal archive fixture"
    m48_signal_status=0
    (CDPATH='' cd "$m48_repo" && HOME="$m48_home" \
        GITSWITCH_L42_SIGNAL_MARKER="$m48_signal_marker" \
        sh "$m48_source/tests/test_dist.sh" "$m48_signal_archive" \
            "$m48_dist_root" /usr/local "$m48_signal_make" -- \
            src tests tools completions VERSION LICENSE README.md Makefile \
            gitswitcher.spec) >"$m48_out" 2>&1 || m48_signal_status=$?
    [ "$m48_signal_status" -eq 1 ] || {
        sed -n '1,160p' "$m48_out" >&2
        fail "M48 TERM did not reach the validator cleanup trap"
    }
    [ "$(sed -n '1p' "$m48_signal_marker")" = ready ] ||
        fail "M48 signal shim did not reach the build boundary"
    cmp -s "$m48_archive" "$m48_signal_archive" ||
        fail "M48 TERM changed caller-owned archive bytes"
    set -- "$m48_home"/.gitswitch-distcheck.*
    if [ "$#" -ne 1 ] || [ -e "$1" ] || [ -L "$1" ]; then
        fail "M48 TERM retained a private distcheck build tree"
    fi

    m48_prefix_archive=$m48_work/m48-prefix.tar.gz
    m48_make_mutant prefix "$m48_prefix_archive"
    m48_expect_rejected prefix "$m48_prefix_archive" \
        'archive contains a path outside' \
        'archive contains a member outside'

    m48_alias_archive=$m48_work/m48-regex-alias.tar.gz
    m48_make_mutant regex-alias "$m48_alias_archive"
    m48_expect_rejected regex-alias "$m48_alias_archive" \
        'archive does not contain exactly one' \
        'archive must contain exactly one top-level'

    m48_outside_archive=$m48_work/m48-outside.tar.gz
    m48_make_mutant outside "$m48_outside_archive"
    m48_expect_rejected outside "$m48_outside_archive" \
        'archive contains a path outside' \
        'archive contains a member outside'
)

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

inspect_failed_dist_residue()
{
    residue_archive=$1
    residue_platform=$2
    residue_archive_dir=${residue_archive%/*}
    residue_archive_name=${residue_archive##*/}

    { [ ! -e "$residue_archive" ] && [ ! -L "$residue_archive" ]; } ||
        fail "failed archive validation published a canonical artifact"

    set -- "$residue_archive_dir/.$residue_archive_name.tmp."*
    if [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; then
        [ "$residue_platform" != Darwin ] ||
            fail "Darwin archive rejection did not retain its private source"
        return
    fi
    { [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]; } ||
        fail "failed archive validation left an unexpected staging namespace"
    [ "$residue_platform" != FreeBSD ] ||
        fail "FreeBSD archive rejection retained a temporary despite funlinkat"

    # Platforms without descriptor-conditioned unlink deliberately retain the
    # failed private source. This isolated fixture owns the directory and can
    # remove that inspected diagnostic residue before the next case.
    rm -f "$1"
}

expect_archive_validation_rejected()
{
    label=$1
    expected=$2
    repo=$3
    make_cmd=$4
    archive=$5
    out=$6
    shim_dir=$7
    platform=$8

    rm -f "$archive"
    if PATH="$shim_dir:$PATH" \
        "$make_cmd" -C "$repo" dist >"$out" 2>&1; then
        fail "$label archive validation unexpectedly succeeded"
    fi
    grep -F "$expected" "$out" >/dev/null || {
        sed -n '1,200p' "$out" >&2
        fail "$label rejection did not identify the failed validation gate"
    }
    inspect_failed_dist_residue "$archive" "$platform"
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
    private_fork_pid=
    private_child_pid=
    durability_swap_pid=
    lock_dist_pid=
    lock_gate_pid=
    lock_contender_pid=
    rpm_alpha_pid=
    rpm_beta_pid=
    rpm_retire_pid=
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
        stop_background "$rpm_alpha_pid"
        stop_background "$rpm_beta_pid"
        stop_background "$rpm_retire_pid"
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
        if [ -n "$private_fork_pid" ]; then
            kill -KILL "-$private_fork_pid" 2>/dev/null || :
            stop_background "$private_fork_pid"
        fi
        if [ -n "$private_child_pid" ]; then
            kill -KILL "-$private_child_pid" 2>/dev/null || :
            stop_background "$private_child_pid"
        fi
        stop_background "$durability_swap_pid"
        rm -rf "$tmp"
        exit "$status"
    }
    trap cleanup 0
    trap 'exit 1' 1 2 3 15

    clean_repo=$tmp/clean
    git clone --quiet "$root" "$clean_repo" || fail "cannot clone clean HEAD"
    clean_git_dir=$(git -C "$clean_repo" rev-parse --absolute-git-dir) ||
        fail "cannot resolve cloned Git directory"
    clean_tools_dir=$clean_git_dir/gitswitch-release-tools
    clean_publish_helper=$clean_tools_dir/release-publish
    clean_publish_receipt=$clean_tools_dir/.release-publish.provenance
    clean_publish_lock=$clean_git_dir/gitswitch-release-publish.lock
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

    # AR-11 M48: the committed VERSION grammar includes ERE metacharacters.
    # Prove both archive validators accept the literal '+' root and reject a
    # shared-prefix component, an old-ERE alias, and an unrelated top level.
    check_literal_archive_root_contract "$tmp" "$root" "$make_cmd"

    # Git-backed state must follow the current worktree's real Git directory,
    # including gitfile worktrees and paths containing spaces and literal dollar
    # signs.  The persistent verified cache survives clean, while the transient
    # lock and artifact tree do not.  A source export nested in another
    # repository must not select that outer repository's state root.
    linked_bare=$tmp/"linked \$base.git"
    linked_checkout=$tmp/"linked \$checkout"
    git clone --bare --quiet "$root" "$linked_bare" ||
        fail "cannot create linked-worktree release fixture"
    git --git-dir="$linked_bare" worktree add --quiet --detach \
        "$linked_checkout" "$commit" ||
        fail "cannot create linked checkout with spaces"
    linked_git_dir=$(git -C "$linked_checkout" rev-parse \
        --absolute-git-dir) || fail "cannot resolve linked-checkout Git dir"
    linked_common_git_dir=$(git -C "$linked_checkout" rev-parse \
        --git-common-dir) || fail "cannot resolve linked-checkout common Git dir"
    linked_common_git_dir=$(CDPATH='' cd "$linked_common_git_dir" && pwd -P) ||
        fail "cannot resolve physical linked-checkout common Git dir"
    linked_bare_physical=$(CDPATH='' cd "$linked_bare" && pwd -P) ||
        fail "cannot resolve physical linked bare repository"
    [ "$linked_common_git_dir" = "$linked_bare_physical" ] ||
        fail "linked checkout selected the wrong common Git directory"
    grep -Fx "gitdir: $linked_git_dir" "$linked_checkout/.git" >/dev/null ||
        fail "linked checkout gitfile did not retain its exact Git directory"
    for linked_dollar_path in "$linked_checkout" "$linked_common_git_dir" \
        "$linked_git_dir"; do
        case $linked_dollar_path in
            *'$'*) ;;
            *) fail "linked Git fixture lost its literal dollar sign: $linked_dollar_path" ;;
        esac
    done
    case $linked_git_dir in
        "$linked_bare"/worktrees/*) ;;
        *) fail "linked checkout selected the wrong Git-private state root" ;;
    esac
    linked_tools=$linked_git_dir/gitswitch-release-tools
    linked_lock=$linked_git_dir/gitswitch-release-publish.lock
    linked_archive=$linked_checkout/build/dist/$dist_root.tar.gz

    # A root-local .git directory or gitfile proves that this is a checkout even
    # when the first Git command fails.  Both the initial top-level probe and
    # the later absolute-Git-dir probe must therefore fail closed rather than
    # redirecting the mutex/helpers to the exported-source fallback.
    gitdir_probe_shims=$tmp/gitdir-probe-shims
    mkdir "$gitdir_probe_shims" ||
        fail "cannot create Git-directory probe shim"
    probe_real_git=$(command -v git) ||
        fail "git is unavailable for Git-directory probe fixture"
    printf '%s\n' "$probe_real_git" >"$gitdir_probe_shims/real-git" ||
        fail "cannot record Git-directory probe executable"
    printf '%s\n' "$gitdir_probe_shims/probe-mode" \
        >"$gitdir_probe_shims/probe-mode-path" ||
        fail "cannot record Git-directory probe mode path"
    cat >"$gitdir_probe_shims/git" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r real_git <"$shim_dir/real-git" || exit 97
IFS= read -r probe_mode_path <"$shim_dir/probe-mode-path" || exit 96
IFS= read -r probe_mode <"$probe_mode_path" || exit 95
if [ "$#" -eq 2 ] && [ "$1" = rev-parse ]; then
    case $probe_mode:$2 in
        show-toplevel:--show-toplevel|
        absolute-git-dir:--absolute-git-dir) exit 75 ;;
    esac
fi
exec "$real_git" "$@"
EOF
    chmod 0700 "$gitdir_probe_shims/git" ||
        fail "cannot make Git-directory probe shim executable"
    expect_release_git_probe_rejected()
    {
        probe_repo=$1
        probe_tools=$2
        probe_lock=$3
        probe_label=$4
        probe_out=$tmp/gitdir-probe-$probe_label.out

        if PATH="$gitdir_probe_shims:$PATH" \
            "$make_cmd" -C "$probe_repo" release-publish-helpers \
            >"$probe_out" 2>&1; then
            fail "$probe_label accepted an unresolved Git directory"
        fi
        grep -F 'cannot resolve the physical Git directory for release state' \
            "$probe_out" >/dev/null || {
            sed -n '1,120p' "$probe_out" >&2
            fail "$probe_label lacked the exact fail-closed diagnostic"
        }
        [ ! -e "$probe_tools" ] && [ ! -L "$probe_tools" ] &&
        [ ! -e "$probe_lock" ] && [ ! -L "$probe_lock" ] &&
        [ ! -e "$probe_repo/build" ] && [ ! -L "$probe_repo/build" ] &&
        [ ! -e "$probe_repo/.gitswitch-release-publish.lock" ] &&
        [ ! -L "$probe_repo/.gitswitch-release-publish.lock" ] ||
            fail "$probe_label created fallback or Git-private release state"
    }

    [ -d "$clean_repo/.git" ] && [ ! -L "$clean_repo/.git" ] ||
        fail "ordinary checkout lacks its real .git directory"
    [ -f "$linked_checkout/.git" ] && [ ! -L "$linked_checkout/.git" ] ||
        fail "linked checkout lacks its real .git gitfile"
    printf '%s\n' show-toplevel >"$gitdir_probe_shims/probe-mode" ||
        fail "cannot arm initial Git-probe failure"
    expect_release_git_probe_rejected "$clean_repo" "$clean_tools_dir" \
        "$clean_publish_lock" ordinary-show-toplevel
    expect_release_git_probe_rejected "$linked_checkout" "$linked_tools" \
        "$linked_lock" linked-show-toplevel
    printf '%s\n' absolute-git-dir >"$gitdir_probe_shims/probe-mode" ||
        fail "cannot arm absolute Git-dir probe failure"
    expect_release_git_probe_rejected "$linked_checkout" "$linked_tools" \
        "$linked_lock" linked-absolute-git-dir

    # The historical file targets would otherwise bypass goal-sensitive Git
    # discovery and recreate the helper inside build/. Reject them explicitly
    # in checkouts; exported source trees retain that compatibility surface.
    for obsolete_helper_goal in build/tools/release-publish \
        build/tools/release-publish-named-test; do
        if "$make_cmd" -C "$linked_checkout" "$obsolete_helper_goal" \
            >"$tmp/obsolete-helper.out" 2>&1; then
            fail "Git checkout accepted obsolete helper goal: $obsolete_helper_goal"
        fi
        grep -F 'release helpers in Git checkouts are private state' \
            "$tmp/obsolete-helper.out" >/dev/null || {
            sed -n '1,120p' "$tmp/obsolete-helper.out" >&2
            fail "obsolete helper goal lacked its migration diagnostic"
        }
    done
    [ ! -e "$linked_checkout/build" ] &&
    [ ! -L "$linked_checkout/build" ] ||
        fail "obsolete helper goal created an in-tree helper namespace"

    "$make_cmd" -C "$linked_checkout" dist >"$tmp/linked-dist.out" 2>&1 || {
        sed -n '1,200p' "$tmp/linked-dist.out" >&2
        fail "linked checkout release failed"
    }
    (assert_archive_metadata "$linked_archive" "$dist_root" "$version")
    [ -x "$linked_tools/release-publish" ] &&
    [ -x "$linked_tools/release-publish-named-test" ] &&
    [ -f "$linked_tools/.release-publish.provenance" ] ||
        fail "linked checkout did not publish Git-private verified helpers"
    [ ! -e "$linked_lock" ] && [ ! -L "$linked_lock" ] ||
        fail "linked checkout retained its Git-private mutex"
    cp "$linked_tools/release-publish" "$tmp/linked-helper.before" ||
        fail "cannot preserve linked helper before stale-cache cleanup"
    cp "$linked_tools/release-publish-named-test" \
        "$tmp/linked-named-helper.before" ||
        fail "cannot preserve linked named helper before stale-cache cleanup"
    cp "$linked_tools/.release-publish.provenance" \
        "$tmp/linked-receipt.before" ||
        fail "cannot preserve linked receipt before stale-cache cleanup"

    # A killed compiler can strand only mktemp's exact six-character directory
    # shape.  The next lock owner retires that stale private tree, but similarly
    # prefixed foreign names and the verified canonical generation are not its
    # cleanup authority.
    linked_stale_tmp=$linked_tools/release-publish.tmp.A1b2C3
    linked_short_sentinel=$linked_tools/release-publish.tmp.A1b2C
    linked_long_sentinel=$linked_tools/release-publish.tmp.A1b2C34
    mkdir "$linked_stale_tmp" ||
        fail "cannot create stale release-helper temporary directory"
    chmod 0700 "$linked_stale_tmp" ||
        fail "cannot secure stale release-helper temporary directory"
    printf '%s\n' stale >"$linked_stale_tmp/residue" ||
        fail "cannot populate stale release-helper temporary directory"
    printf '%s\n' preserve-short >"$linked_short_sentinel" ||
        fail "cannot create short release-helper prefix sentinel"
    printf '%s\n' preserve-long >"$linked_long_sentinel" ||
        fail "cannot create long release-helper prefix sentinel"
    "$make_cmd" -C "$linked_checkout" release-publish-helpers \
        >"$tmp/linked-stale-cleanup.out" 2>&1 || {
        sed -n '1,200p' "$tmp/linked-stale-cleanup.out" >&2
        fail "linked checkout could not retire stale helper state"
    }
    [ ! -e "$linked_stale_tmp" ] && [ ! -L "$linked_stale_tmp" ] ||
        fail "verified helper bootstrap retained exact-shape stale state"
    [ "$(cat "$linked_short_sentinel")" = preserve-short ] &&
    [ "$(cat "$linked_long_sentinel")" = preserve-long ] ||
        fail "stale helper cleanup changed similarly prefixed foreign state"
    if ! cmp -s "$linked_tools/release-publish" \
            "$tmp/linked-helper.before" ||
       ! cmp -s "$linked_tools/release-publish-named-test" \
            "$tmp/linked-named-helper.before" ||
       ! cmp -s "$linked_tools/.release-publish.provenance" \
            "$tmp/linked-receipt.before"; then
        fail "stale helper cleanup changed the verified canonical generation"
    fi
    [ ! -e "$linked_lock" ] && [ ! -L "$linked_lock" ] ||
        fail "stale helper cleanup retained its Git-private mutex"

    linked_clean_stale_tmp=$linked_tools/release-publish.tmp.D4e5F6
    mkdir "$linked_clean_stale_tmp" ||
        fail "cannot create clean-path stale helper temporary directory"
    chmod 0700 "$linked_clean_stale_tmp" ||
        fail "cannot secure clean-path stale helper temporary directory"
    printf '%s\n' stale-clean >"$linked_clean_stale_tmp/residue" ||
        fail "cannot populate clean-path stale helper temporary directory"
    "$make_cmd" -C "$linked_checkout" clean >"$tmp/linked-clean.out" 2>&1 || {
        sed -n '1,200p' "$tmp/linked-clean.out" >&2
        fail "linked checkout clean failed"
    }
    [ ! -e "$linked_checkout/build" ] &&
    [ ! -L "$linked_checkout/build" ] ||
        fail "linked checkout clean retained the artifact tree"
    [ ! -e "$linked_clean_stale_tmp" ] &&
    [ ! -L "$linked_clean_stale_tmp" ] ||
        fail "linked checkout clean retained exact-shape stale helper state"
    [ "$(cat "$linked_short_sentinel")" = preserve-short ] &&
    [ "$(cat "$linked_long_sentinel")" = preserve-long ] ||
        fail "linked checkout clean changed similarly prefixed foreign state"
    if ! cmp -s "$linked_tools/release-publish" \
            "$tmp/linked-helper.before" ||
       ! cmp -s "$linked_tools/release-publish-named-test" \
            "$tmp/linked-named-helper.before" ||
       ! cmp -s "$linked_tools/.release-publish.provenance" \
            "$tmp/linked-receipt.before"; then
        fail "linked checkout clean removed or changed persistent helpers"
    fi
    [ ! -e "$linked_lock" ] && [ ! -L "$linked_lock" ] ||
        fail "linked checkout clean retained its Git-private mutex"
    [ -z "$(git -C "$linked_checkout" status --porcelain=v1 \
        --untracked-files=all)" ] ||
        fail "linked checkout release state leaked into worktree status"
    nested_export=$linked_checkout/'nested export'
    mkdir -p "$nested_export/src" "$nested_export/tools" ||
        fail "cannot create nested source-export fixture"
    cp "$root/Makefile" "$root/VERSION" "$nested_export/" ||
        fail "cannot copy nested source-export metadata"
    cp "$root/src/freebsd_compat.h" "$nested_export/src/" ||
        fail "cannot copy nested source-export header"
    cp "$root/tools/release_publish.c" \
        "$root/tools/release_publish_lock.sh" "$nested_export/tools/" ||
        fail "cannot copy nested source-export helpers"
    "$make_cmd" -C "$nested_export" release-publish-helpers \
        >"$tmp/nested-export.out" 2>&1 || {
        sed -n '1,200p' "$tmp/nested-export.out" >&2
        fail "nested source export helper build failed"
    }
    [ -x "$nested_export/build/tools/release-publish" ] &&
    [ -f "$nested_export/build/tools/.release-publish.provenance" ] ||
        fail "nested source export did not use its local fallback state"
    [ ! -e "$nested_export/.gitswitch-release-publish.lock" ] &&
    [ ! -L "$nested_export/.gitswitch-release-publish.lock" ] ||
        fail "nested source export retained its local mutex"
    rm -rf "$nested_export" || fail "cannot retire nested source export"
    [ -z "$(git -C "$linked_checkout" status --porcelain=v1 \
        --untracked-files=all)" ] ||
        fail "nested source export leaked into linked checkout status"

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
    copy_platform=$(uname -s) ||
        fail "cannot identify release publisher test platform"

    # AR-11 L42: distcheck consumes a descriptor-pinned private archive and
    # never publishes the canonical name. Force the named fallback on every
    # host to prove normal retirement/retention, post-validation substitution,
    # fixed-fd closure, and fatal-signal retention independently of O_TMPFILE.
    private_consume_root=$tmp/private-consume
    private_consumer=$tmp/private-consumer.sh
    private_capture=$tmp/private-consumer.capture
    private_marker=$tmp/private-consumer.marker
    private_release=$tmp/private-consumer.release
    private_out=$tmp/private-consumer.out
    private_original=$tmp/private-consumer.original
    mkdir "$private_consume_root" ||
        fail "cannot create private-consumer root"
    cat >"$private_consumer" <<'EOF'
#!/bin/sh
set -eu
[ "${1-}" = @GITSWITCH_PRIVATE_ARCHIVE_FD@ ] || exit 91
: "${AR11_PRIVATE_CAPTURE:?}"
private_mode=${AR11_PRIVATE_MODE-success}
case $private_mode in
    preclose)
        while :; do sleep 1; done
        ;;
    timeout)
        : "${AR11_PRIVATE_MARKER:?}"
        printf '%s\n' "$$" >"$AR11_PRIVATE_MARKER" || exit 96
        while :; do sleep 1; done
        ;;
esac
cat <&3 >"$AR11_PRIVATE_CAPTURE" || exit 92
if [ "$private_mode" = mutate ]; then
    printf '%s' '-mutated' >&3 || exit 98
    exec 3<&-
    exit 0
fi
exec 3<&-
if /bin/sh -c ': <&3' 2>/dev/null; then
    exit 93
fi
case $private_mode in
    success) exit 0 ;;
    replace)
        : "${AR11_PRIVATE_MARKER:?}" "${AR11_PRIVATE_RELEASE:?}"
        printf '%s\n' ready >"$AR11_PRIVATE_MARKER" || exit 94
        attempt=0
        while [ ! -s "$AR11_PRIVATE_RELEASE" ]; do
            attempt=$((attempt + 1))
            [ "$attempt" -lt 80 ] || exit 95
            sleep 0.05
        done
        ;;
    signal)
        : "${AR11_PRIVATE_MARKER:?}"
        printf '%s\n' "$$" >"$AR11_PRIVATE_MARKER" || exit 96
        while :; do sleep 1; done
        ;;
    *) exit 97 ;;
esac
EOF
    chmod 0700 "$private_consumer" ||
        fail "cannot activate private-consumer fixture"

    # Consume-mode grammar is an ownership boundary too: malformed separators
    # must fail before creating a source, while zero or multiple descriptor
    # sentinels may clean only the exact private source just generated.
    private_parser_sentinel=$private_consume_root/parser-sibling.sentinel
    private_parser_before=$tmp/private-parser-sibling.before
    printf '%s\n' parser-sibling >"$private_parser_sentinel" ||
        fail "cannot create private-parser sibling"
    cp "$private_parser_sentinel" "$private_parser_before" ||
        fail "cannot preserve private-parser sibling"
    if "$named_publish_helper" --internal-release-tree-consume-v1 \
        "$private_consume_root" build dist archive.tar.gz -- /bin/true \
        >"$private_out" 2>&1; then
        fail "private consume parser accepted a missing separator"
    fi
    grep -F 'usage:' "$private_out" >/dev/null ||
        fail "missing private-consumer separator lacked usage diagnostics"
    set -- "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
    [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ] ||
        fail "missing private-consumer separator created a private source"

    if "$named_publish_helper" --internal-release-tree-consume-v1 \
        "$private_consume_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf private-consume-payload' \
        --internal-consumer-v1 /bin/true \
        @GITSWITCH_PRIVATE_ARCHIVE_FD@ \
        --internal-consumer-v1 /bin/true >"$private_out" 2>&1; then
        fail "private consume parser accepted duplicate separators"
    fi
    grep -F 'usage:' "$private_out" >/dev/null ||
        fail "duplicate private-consumer separator lacked usage diagnostics"
    set -- "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
    [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ] ||
        fail "duplicate private-consumer separator created a private source"

    for private_parser_shape in zero multiple; do
        case $private_parser_shape in
            zero)
                if "$named_publish_helper" \
                    --internal-release-tree-consume-v1 \
                    "$private_consume_root" build dist archive.tar.gz -- \
                    /bin/sh -c 'printf private-consume-payload' \
                    --internal-consumer-v1 /bin/true \
                    >"$private_out" 2>&1; then
                    fail "private consumer accepted zero archive sentinels"
                fi
                ;;
            multiple)
                if "$named_publish_helper" \
                    --internal-release-tree-consume-v1 \
                    "$private_consume_root" build dist archive.tar.gz -- \
                    /bin/sh -c 'printf private-consume-payload' \
                    --internal-consumer-v1 /bin/true \
                    @GITSWITCH_PRIVATE_ARCHIVE_FD@ \
                    @GITSWITCH_PRIVATE_ARCHIVE_FD@ \
                    >"$private_out" 2>&1; then
                    fail "private consumer accepted multiple archive sentinels"
                fi
                ;;
        esac
        grep -F 'requires exactly one archive-fd sentinel' \
            "$private_out" >/dev/null ||
            fail "$private_parser_shape-sentinel rejection lacked its exact diagnostic"
        [ ! -e "$private_consume_root/build/dist/archive.tar.gz" ] &&
        [ ! -L "$private_consume_root/build/dist/archive.tar.gz" ] ||
            fail "$private_parser_shape-sentinel rejection published a canonical name"
        set -- "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
        case $copy_platform in
            FreeBSD)
                [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ] ||
                    fail "FreeBSD retained a $private_parser_shape-sentinel source"
                ;;
            Linux|Darwin)
                { [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]; } ||
                    fail "$copy_platform did not retain one $private_parser_shape-sentinel source"
                [ "$(cat "$1")" = private-consume-payload ] ||
                    fail "$copy_platform retained wrong $private_parser_shape-sentinel bytes"
                grep -F 'private distcheck archive safely retained' \
                    "$private_out" >/dev/null ||
                    fail "$copy_platform $private_parser_shape-sentinel retention lacked a warning"
                rm -f "$1" ||
                    fail "cannot retire $private_parser_shape-sentinel fixture source"
                ;;
            *) fail "unsupported private-parser platform: $copy_platform" ;;
        esac
    done
    cmp -s "$private_parser_before" "$private_parser_sentinel" ||
        fail "private consume parser changed an unrelated sibling"

    AR11_PRIVATE_CAPTURE=$private_capture \
        "$named_publish_helper" --internal-release-tree-consume-v1 \
        "$private_consume_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf private-consume-payload' \
        --internal-consumer-v1 "$private_consumer" \
        @GITSWITCH_PRIVATE_ARCHIVE_FD@ >"$private_out" 2>&1 || {
        sed -n '1,160p' "$private_out" >&2
        fail "private archive consumer success fixture failed"
    }
    [ "$(cat "$private_capture")" = private-consume-payload ] ||
        fail "private archive consumer received wrong or empty bytes"
    [ ! -e "$private_consume_root/build/dist/archive.tar.gz" ] &&
    [ ! -L "$private_consume_root/build/dist/archive.tar.gz" ] ||
        fail "private archive consumer published a canonical name"
    set -- "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ] ||
                fail "FreeBSD private consumer retained a normally retired source"
            ;;
        Linux|Darwin)
            { [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]; } ||
                fail "$copy_platform private consumer did not safely retain one named source"
            [ "$(cat "$1")" = private-consume-payload ] ||
                fail "$copy_platform retained private source changed bytes"
            grep -F 'private distcheck archive safely retained' \
                "$private_out" >/dev/null ||
                fail "$copy_platform private retention lacked a warning"
            rm -f "$1" || fail "cannot retire private-consumer fixture source"
            ;;
        *) fail "unsupported private-consumer platform: $copy_platform" ;;
    esac

    # The portable handoff descriptor is internally O_RDWR. A consumer that
    # writes through fd 3 and exits successfully must still fail the helper's
    # post-consumer byte proof without publishing or deleting foreign state.
    rm -f "$private_capture" "$private_marker" "$private_release"
    if AR11_PRIVATE_MODE=mutate AR11_PRIVATE_CAPTURE=$private_capture \
        "$named_publish_helper" --internal-release-tree-consume-v1 \
        "$private_consume_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf private-consume-payload' \
        --internal-consumer-v1 "$private_consumer" \
        @GITSWITCH_PRIVATE_ARCHIVE_FD@ >"$private_out" 2>&1; then
        fail "private consumer mutation escaped the post-validation digest"
    fi
    [ "$(cat "$private_capture")" = private-consume-payload ] ||
        fail "private mutation consumer received wrong source bytes"
    [ ! -e "$private_consume_root/build/dist/archive.tar.gz" ] &&
    [ ! -L "$private_consume_root/build/dist/archive.tar.gz" ] ||
        fail "private mutation consumer published a canonical name"
    grep -F 'private distcheck archive changed during validation' \
        "$private_out" >/dev/null ||
        fail "private consumer mutation lacked a digest diagnostic"
    set -- "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ] ||
                fail "FreeBSD retained a privately mutated source"
            ;;
        Linux|Darwin)
            { [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]; } ||
                fail "$copy_platform did not safely retain the privately mutated source"
            [ "$(cat "$1")" = private-consume-payload-mutated ] ||
                fail "$copy_platform retained wrong private mutation bytes"
            grep -F 'private distcheck archive safely retained' \
                "$private_out" >/dev/null ||
                fail "$copy_platform private mutation retention lacked a warning"
            rm -f "$1" || fail "cannot retire private mutation fixture source"
            ;;
        *) fail "unsupported private mutation platform: $copy_platform" ;;
    esac

    # Fork, process-group creation, and handler-visible PID publication are a
    # single fatal-signal ownership transition for both supervised children.
    # The named-only hook raises each forwarded signal while independently
    # proving the full set is blocked, before the selected PID is published.
    # Exact-mask restoration must deliver it only after publication, killing
    # either the blocked producer or the pre-close consumer that still owns
    # fd 3. Omitting either guard leaves the reported PID alive and is causal.
    private_fork_violations=
    for private_fork_target in producer consumer; do
        for private_fork_signal in HUP INT QUIT TERM; do
            private_fork_label=$private_fork_target-$private_fork_signal
            private_fork_report=$tmp/private-fork-$private_fork_label.report
            rm -f "$private_capture" "$private_marker" "$private_release" \
                "$private_fork_report" \
                "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
            private_fork_status=0
            # The selected producer child, not this test shell, expands its
            # mode after the guarded fork boundary.
            # shellcheck disable=SC2016
            if AR11_PRIVATE_MODE=preclose \
                AR11_PRIVATE_CAPTURE=$private_capture \
                AR11_PRIVATE_PRODUCER_MODE=$private_fork_target \
                GITSWITCH_RELEASE_TEST_FATAL_DEFAULTS=1 \
                GITSWITCH_RELEASE_TEST_FORK_SIGNAL=$private_fork_signal \
                GITSWITCH_RELEASE_TEST_FORK_REPORT_FD=9 \
                GITSWITCH_RELEASE_TEST_FORK_TARGET=$private_fork_target \
                "$named_publish_helper" --internal-release-tree-consume-v1 \
                "$private_consume_root" build dist archive.tar.gz -- \
                /bin/sh -c '
                    if [ "$AR11_PRIVATE_PRODUCER_MODE" = producer ]; then
                        while :; do sleep 1; done
                    fi
                    printf private-consume-payload
                ' \
                --internal-consumer-v1 "$private_consumer" \
                @GITSWITCH_PRIVATE_ARCHIVE_FD@ \
                9>"$private_fork_report" >"$private_out" 2>&1; then
                private_fork_status=0
            else
                private_fork_status=$?
            fi
            if [ "$private_fork_status" -le 128 ]; then
                private_fork_violations="$private_fork_violations $private_fork_label-status-$private_fork_status"
            else
                private_fork_observed=$(kill -l "$private_fork_status" 2>/dev/null || :)
                case $private_fork_observed in
                    "$private_fork_signal"|"SIG$private_fork_signal") ;;
                    *)
                        private_fork_violations="$private_fork_violations $private_fork_label-status-$private_fork_status"
                        ;;
                esac
            fi
            private_fork_proof=
            private_fork_pid=
            if [ -f "$private_fork_report" ]; then
                IFS=' ' read -r private_fork_proof private_fork_pid \
                    <"$private_fork_report" || :
            fi
            case $private_fork_pid in
                ''|*[!0-9]*) private_fork_pid= ;;
            esac
            if [ "$private_fork_proof" != B ] ||
               [ -z "$private_fork_pid" ]; then
                private_fork_violations="$private_fork_violations $private_fork_label-guard"
            fi
            if [ -n "$private_fork_pid" ]; then
                attempt=0
                while kill -0 "$private_fork_pid" 2>/dev/null &&
                      [ "$attempt" -lt 80 ]; do
                    sleep 0.05
                    attempt=$((attempt + 1))
                done
                if kill -0 "$private_fork_pid" 2>/dev/null; then
                    private_fork_violations="$private_fork_violations $private_fork_label-live-$private_fork_pid"
                    kill -KILL "-$private_fork_pid" 2>/dev/null || :
                    stop_background "$private_fork_pid"
                fi
                private_fork_pid=
            fi
            [ ! -e "$private_consume_root/build/dist/archive.tar.gz" ] &&
            [ ! -L "$private_consume_root/build/dist/archive.tar.gz" ] ||
                private_fork_violations="$private_fork_violations $private_fork_label-published"
            set -- "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
            if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ -L "$1" ]; then
                private_fork_violations="$private_fork_violations $private_fork_label-temp-shape"
            else
                if [ "$private_fork_target" = consumer ] &&
                   [ "$(cat "$1")" != private-consume-payload ]; then
                    private_fork_violations="$private_fork_violations $private_fork_label-temp-bytes"
                fi
                rm -f "$1" ||
                    private_fork_violations="$private_fork_violations $private_fork_label-temp-cleanup"
            fi
        done
    done
    [ -z "$private_fork_violations" ] ||
        fail "guarded release-child fork violations:$private_fork_violations"

    # Consumer supervision has a distinct production budget from archive
    # generation. The named helper's five-second budget makes the timeout path
    # causal: the blocking consumer must be group-killed, its exact status must
    # fail closed, and cleanup follows the same platform ownership policy.
    rm -f "$private_capture" "$private_marker" "$private_release" \
        "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
    private_timeout_status=0
    if AR11_PRIVATE_MODE=timeout AR11_PRIVATE_CAPTURE=$private_capture \
        AR11_PRIVATE_MARKER=$private_marker \
        "$named_publish_helper" --internal-release-tree-consume-v1 \
        "$private_consume_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf private-consume-payload' \
        --internal-consumer-v1 "$private_consumer" \
        @GITSWITCH_PRIVATE_ARCHIVE_FD@ >"$private_out" 2>&1; then
        private_timeout_status=0
    else
        private_timeout_status=$?
    fi
    [ "$private_timeout_status" -ne 0 ] ||
        fail "timed-out private consumer unexpectedly succeeded"
    grep -F 'distcheck consumer timed out' "$private_out" >/dev/null ||
        fail "private consumer timeout lacked its exact diagnostic"
    private_child_pid=$(sed -n '1p' "$private_marker")
    case $private_child_pid in
        ''|*[!0-9]*)
            private_child_pid=
            fail "private timeout consumer reported an invalid PID"
            ;;
    esac
    attempt=0
    while kill -0 "$private_child_pid" 2>/dev/null &&
          [ "$attempt" -lt 80 ]; do
        sleep 0.05
        attempt=$((attempt + 1))
    done
    if kill -0 "$private_child_pid" 2>/dev/null; then
        kill -KILL "-$private_child_pid" 2>/dev/null || :
        stop_background "$private_child_pid"
        private_child_pid=
        fail "timed-out private consumer survived group teardown"
    fi
    private_child_pid=
    [ ! -e "$private_consume_root/build/dist/archive.tar.gz" ] &&
    [ ! -L "$private_consume_root/build/dist/archive.tar.gz" ] ||
        fail "timed-out private consumer published a canonical name"
    set -- "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
    case $copy_platform in
        FreeBSD)
            [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ] ||
                fail "FreeBSD retained a timed-out private source"
            ;;
        Linux|Darwin)
            { [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]; } ||
                fail "$copy_platform did not safely retain the timed-out private source"
            [ "$(cat "$1")" = private-consume-payload ] ||
                fail "$copy_platform retained wrong private-timeout bytes"
            grep -F 'private distcheck archive safely retained' \
                "$private_out" >/dev/null ||
                fail "$copy_platform private timeout retention lacked a warning"
            rm -f "$1" || fail "cannot retire private timeout fixture source"
            ;;
        *) fail "unsupported private timeout platform: $copy_platform" ;;
    esac

    rm -f "$private_capture" "$private_marker" "$private_release"
    AR11_PRIVATE_MODE=replace AR11_PRIVATE_CAPTURE=$private_capture \
    AR11_PRIVATE_MARKER=$private_marker \
    AR11_PRIVATE_RELEASE=$private_release \
        "$named_publish_helper" --internal-release-tree-consume-v1 \
        "$private_consume_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf private-consume-payload' \
        --internal-consumer-v1 "$private_consumer" \
        @GITSWITCH_PRIVATE_ARCHIVE_FD@ >"$private_out" 2>&1 &
    copy_pid=$!
    attempt=0
    while [ ! -s "$private_marker" ] && kill -0 "$copy_pid" 2>/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 80 ] ||
            fail "private consumer did not reach replacement boundary"
        sleep 0.05
    done
    [ -s "$private_marker" ] ||
        fail "private consumer exited before replacement boundary"
    set -- "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
    { [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]; } ||
        fail "private consumer did not expose one pinned named source"
    private_temp=$1
    mv "$private_temp" "$private_original" ||
        fail "cannot preserve pinned private-consumer source"
    printf 'foreign-private-replacement' >"$private_temp" ||
        fail "cannot install private-consumer replacement"
    printf '%s\n' release >"$private_release" ||
        fail "cannot release private-consumer replacement fixture"
    if wait "$copy_pid"; then
        copy_pid=
        fail "private consumer accepted a replaced staging name"
    fi
    copy_pid=
    [ "$(cat "$private_capture")" = private-consume-payload ] &&
    [ "$(cat "$private_original")" = private-consume-payload ] ||
        fail "private staging substitution changed the pinned source"
    [ "$(cat "$private_temp")" = foreign-private-replacement ] ||
        fail "private staging substitution changed the replacement"
    [ ! -e "$private_consume_root/build/dist/archive.tar.gz" ] &&
    [ ! -L "$private_consume_root/build/dist/archive.tar.gz" ] ||
        fail "private staging substitution published a canonical name"
    grep -F 'private distcheck archive name changed during validation' \
        "$private_out" >/dev/null ||
        fail "private staging substitution lacked an ownership diagnostic"
    rm -f "$private_temp" "$private_original"

    rm -f "$private_capture" "$private_marker" "$private_release"
    AR11_PRIVATE_MODE=signal AR11_PRIVATE_CAPTURE=$private_capture \
    AR11_PRIVATE_MARKER=$private_marker \
        "$named_publish_helper" --internal-release-tree-consume-v1 \
        "$private_consume_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf private-consume-payload' \
        --internal-consumer-v1 "$private_consumer" \
        @GITSWITCH_PRIVATE_ARCHIVE_FD@ >"$private_out" 2>&1 &
    copy_pid=$!
    attempt=0
    while [ ! -s "$private_marker" ] && kill -0 "$copy_pid" 2>/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 80 ] ||
            fail "private consumer did not reach signal boundary"
        sleep 0.05
    done
    [ -s "$private_marker" ] ||
        fail "private consumer exited before signal boundary"
    private_child_pid=$(sed -n '1p' "$private_marker")
    case $private_child_pid in
        ''|*[!0-9]*)
            private_child_pid=
            fail "private consumer reported an invalid signal-boundary PID"
            ;;
    esac
    kill -TERM "$copy_pid" || fail "cannot signal private archive helper"
    if wait "$copy_pid"; then
        private_signal_status=0
    else
        private_signal_status=$?
    fi
    copy_pid=
    attempt=0
    while kill -0 "$private_child_pid" 2>/dev/null &&
          [ "$attempt" -lt 80 ]; do
        attempt=$((attempt + 1))
        sleep 0.05
    done
    if kill -0 "$private_child_pid" 2>/dev/null; then
        kill -KILL "-$private_child_pid" 2>/dev/null || :
        stop_background "$private_child_pid"
        private_child_pid=
        fail "private archive helper left its consumer alive after TERM"
    fi
    private_child_pid=
    [ "$private_signal_status" -eq 143 ] ||
        fail "private archive helper did not preserve TERM status"
    [ "$(cat "$private_capture")" = private-consume-payload ] ||
        fail "signalled private consumer received wrong archive bytes"
    set -- "$private_consume_root/build/dist"/.archive.tar.gz.tmp.*
    { [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]; } ||
        fail "signalled named private archive was not safely retained"
    [ "$(cat "$1")" = private-consume-payload ] ||
        fail "signalled named private archive changed bytes"
    [ ! -e "$private_consume_root/build/dist/archive.tar.gz" ] &&
    [ ! -L "$private_consume_root/build/dist/archive.tar.gz" ] ||
        fail "signalled private consumer published a canonical name"
    rm -f "$1" || fail "cannot retire signalled private archive fixture"

    # AR-11 M46: the publisher owns the fixed repository -> build -> dist
    # hierarchy.  A fresh root proves both components are created through the
    # pinned descriptor chain, while the trace proves each durability barrier
    # targets the intended inode in strict leaf-to-root order.  Every injected
    # barrier failure is causal: omitting or ignoring that fsync makes the
    # corresponding case falsely succeed.
    durability_root=$tmp/durability-tree
    durability_trace=$tmp/durability.trace
    durability_out=$tmp/durability.out
    mkdir "$durability_root" ||
        fail "cannot create release durability fixture root"
    printf '%s\n' unrelated >"$durability_root/sentinel" ||
        fail "cannot create release durability sentinel"
    (
        # Exact private modes are publisher policy, not ambient-umask output.
        umask 000
        GITSWITCH_RELEASE_TEST_SYNC_REPORT_FD=9 \
            "$named_publish_helper" --internal-release-tree-v1 \
            "$durability_root" build dist archive.tar.gz -- \
            /bin/sh -c 'printf durability-payload' \
            9>"$durability_trace" >"$durability_out" 2>&1
    ) || {
        sed -n '1,160p' "$durability_out" >&2
        fail "fresh-tree descriptor-bound publication failed"
    }
    [ "$(find "$durability_root/build" -prune -type d \
        -perm 0700 -print 2>/dev/null)" = "$durability_root/build" ] ||
        fail "fresh publisher build directory mode is not exactly 0700"
    [ "$(find "$durability_root/build/dist" -prune -type d \
        -perm 0700 -print 2>/dev/null)" = "$durability_root/build/dist" ] ||
        fail "fresh publisher dist directory mode is not exactly 0700"
    case $copy_platform in
        Darwin) durability_expected=FADBR ;;
        *) durability_expected=FDBR ;;
    esac
    durability_actual=$(awk '{ printf "%s", $1 }' "$durability_trace") ||
        fail "cannot inspect release durability trace"
    [ "$durability_actual" = "$durability_expected" ] || {
        sed -n '1,160p' "$durability_trace" >&2
        fail "release durability order was $durability_actual; expected $durability_expected"
    }
    case $copy_platform in
        Darwin|FreeBSD)
            durability_archive_identity=$(stat -f '%d:%i' \
                "$durability_root/build/dist/archive.tar.gz") ||
                fail "cannot identify durability archive"
            durability_dist_identity=$(stat -f '%d:%i' \
                "$durability_root/build/dist") ||
                fail "cannot identify durability dist directory"
            durability_build_identity=$(stat -f '%d:%i' \
                "$durability_root/build") ||
                fail "cannot identify durability build directory"
            durability_root_identity=$(stat -f '%d:%i' \
                "$durability_root") ||
                fail "cannot identify durability repository root"
            ;;
        *)
            durability_archive_identity=$(stat -c '%d:%i' \
                "$durability_root/build/dist/archive.tar.gz") ||
                fail "cannot identify durability archive"
            durability_dist_identity=$(stat -c '%d:%i' \
                "$durability_root/build/dist") ||
                fail "cannot identify durability dist directory"
            durability_build_identity=$(stat -c '%d:%i' \
                "$durability_root/build") ||
                fail "cannot identify durability build directory"
            durability_root_identity=$(stat -c '%d:%i' \
                "$durability_root") ||
                fail "cannot identify durability repository root"
            ;;
    esac
    [ "$(awk '$1 == "D" { print $2 }' "$durability_trace")" = \
        "$durability_dist_identity" ] ||
        fail "dist durability barrier targeted the wrong descriptor"
    [ "$(awk '$1 == "B" { print $2 }' "$durability_trace")" = \
        "$durability_build_identity" ] ||
        fail "build durability barrier targeted the wrong descriptor"
    [ "$(awk '$1 == "R" { print $2 }' "$durability_trace")" = \
        "$durability_root_identity" ] ||
        fail "repository durability barrier targeted the wrong descriptor"
    case $copy_platform in
        Darwin)
            [ "$(awk '$1 == "A" { print $2 }' "$durability_trace")" = \
                "$durability_archive_identity" ] ||
                fail "adopted-file barrier targeted the wrong descriptor"
            set -- "$durability_root/build/dist"/.archive.tar.gz.tmp.*
            { [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]; } ||
                fail "Darwin durability fixture lost its retained source"
            durability_source_identity=$(stat -f '%d:%i' "$1") ||
                fail "cannot identify Darwin durability source"
            [ "$(awk '$1 == "F" { print $2 }' "$durability_trace")" = \
                "$durability_source_identity" ] ||
                fail "file barrier targeted the wrong Darwin source descriptor"
            ;;
        *)
            [ "$(awk '$1 == "F" { print $2 }' "$durability_trace")" = \
                "$durability_archive_identity" ] ||
                fail "file barrier targeted the wrong published inode"
            ;;
    esac
    [ "$(cat "$durability_root/build/dist/archive.tar.gz")" = \
        durability-payload ] ||
        fail "fresh-tree durability publication changed payload"
    [ "$(cat "$durability_root/sentinel")" = unrelated ] ||
        fail "fresh-tree durability publication changed unrelated state"

    durability_fail_stages='F D B R'
    [ "$copy_platform" != Darwin ] || durability_fail_stages='F A D B R'
    for durability_fail_stage in $durability_fail_stages; do
        durability_case_root=$tmp/durability-fail-$durability_fail_stage
        durability_case_trace=$tmp/durability-fail-$durability_fail_stage.trace
        mkdir "$durability_case_root" ||
            fail "cannot create durability failure fixture root"
        printf '%s\n' unrelated >"$durability_case_root/sentinel" ||
            fail "cannot create durability failure sentinel"
        if GITSWITCH_RELEASE_TEST_SYNC_REPORT_FD=9 \
           GITSWITCH_RELEASE_TEST_SYNC_FAIL_STAGE=$durability_fail_stage \
            "$named_publish_helper" --internal-release-tree-v1 \
            "$durability_case_root" build dist archive.tar.gz -- \
            /bin/sh -c 'printf durability-payload' \
            9>"$durability_case_trace" >"$durability_out" 2>&1; then
            fail "durability barrier $durability_fail_stage failure was accepted"
        fi
        case $copy_platform:$durability_fail_stage in
            Darwin:F) durability_prefix=F ;;
            Darwin:A) durability_prefix=FA ;;
            Darwin:D) durability_prefix=FAD ;;
            Darwin:B) durability_prefix=FADB ;;
            Darwin:R) durability_prefix=FADBR ;;
            *:F) durability_prefix=F ;;
            *:D) durability_prefix=FD ;;
            *:B) durability_prefix=FDB ;;
            *:R) durability_prefix=FDBR ;;
            *) fail "invalid durability failure stage: $durability_fail_stage" ;;
        esac
        durability_actual=$(awk '{ printf "%s", $1 }' \
            "$durability_case_trace") ||
            fail "cannot inspect durability failure trace"
        [ "$durability_actual" = "$durability_prefix" ] || {
            sed -n '1,160p' "$durability_case_trace" >&2
            fail "durability failure trace was $durability_actual; expected $durability_prefix"
        }
        case $durability_fail_stage in
            F)
                [ ! -e "$durability_case_root/build/dist/archive.tar.gz" ] &&
                [ ! -L "$durability_case_root/build/dist/archive.tar.gz" ] ||
                    fail "pre-publication sync failure left a canonical artifact"
                ;;
            *)
                [ "$(cat "$durability_case_root/build/dist/archive.tar.gz")" = \
                    durability-payload ] ||
                    fail "post-publication sync failure did not retain complete bytes"
                ;;
        esac
        [ "$(cat "$durability_case_root/sentinel")" = unrelated ] ||
            fail "durability failure changed unrelated state"
        grep -F "durability stage $durability_fail_stage" \
            "$durability_out" >/dev/null || {
            sed -n '1,160p' "$durability_out" >&2
            fail "durability failure lacked its stage diagnostic"
        }
    done

    # A failed file barrier may leave only private staging residue and the
    # newly created directory chain.  Retrying in that exact tree must still
    # execute every ancestor barrier rather than treating existence as proof
    # that the parent entry is already durable.
    durability_retry_root=$tmp/durability-fail-F
    GITSWITCH_RELEASE_TEST_SYNC_REPORT_FD=9 \
        "$named_publish_helper" --internal-release-tree-v1 \
        "$durability_retry_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf durability-payload' \
        9>"$durability_trace" >"$durability_out" 2>&1 || {
        sed -n '1,160p' "$durability_out" >&2
        fail "release durability retry failed"
    }
    durability_actual=$(awk '{ printf "%s", $1 }' "$durability_trace") ||
        fail "cannot inspect release durability retry trace"
    [ "$durability_actual" = "$durability_expected" ] ||
        fail "release durability retry skipped an ancestor barrier"

    # Invalid names and hostile directory shapes must fail before the producer
    # can publish through an escape, symlink, or non-directory component.
    durability_shape_root=$tmp/durability-shapes
    durability_outside=$tmp/durability-outside
    mkdir "$durability_shape_root" "$durability_outside" ||
        fail "cannot create durability shape fixtures"
    if "$named_publish_helper" --internal-release-tree-v1 \
        "$durability_shape_root" ../escape dist archive.tar.gz -- \
        /bin/sh -c 'printf escaped' >"$durability_out" 2>&1; then
        fail "release tree accepted a multi-component build name"
    fi
    [ ! -e "$tmp/escape" ] && [ ! -L "$tmp/escape" ] ||
        fail "invalid release component escaped its root"

    ln -s "$durability_outside" "$durability_shape_root/build" ||
        fail "cannot install symlinked build fixture"
    if "$named_publish_helper" --internal-release-tree-v1 \
        "$durability_shape_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf escaped' >"$durability_out" 2>&1; then
        fail "release tree accepted a symlinked build directory"
    fi
    [ ! -e "$durability_outside/dist" ] &&
    [ ! -L "$durability_outside/dist" ] ||
        fail "symlinked build fixture changed its target"
    rm -f "$durability_shape_root/build"
    printf '%s\n' not-a-directory >"$durability_shape_root/build" ||
        fail "cannot install non-directory build fixture"
    if "$named_publish_helper" --internal-release-tree-v1 \
        "$durability_shape_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf escaped' >"$durability_out" 2>&1; then
        fail "release tree accepted a non-directory build component"
    fi
    rm -f "$durability_shape_root/build"
    mkdir "$durability_shape_root/build" ||
        fail "cannot restore durability build fixture"
    ln -s "$durability_outside" "$durability_shape_root/build/dist" ||
        fail "cannot install symlinked dist fixture"
    if "$named_publish_helper" --internal-release-tree-v1 \
        "$durability_shape_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf escaped' >"$durability_out" 2>&1; then
        fail "release tree accepted a symlinked dist directory"
    fi
    rm -f "$durability_shape_root/build/dist"
    printf '%s\n' not-a-directory >"$durability_shape_root/build/dist" ||
        fail "cannot install non-directory dist fixture"
    if "$named_publish_helper" --internal-release-tree-v1 \
        "$durability_shape_root" build dist archive.tar.gz -- \
        /bin/sh -c 'printf escaped' >"$durability_out" 2>&1; then
        fail "release tree accepted a non-directory dist component"
    fi

    # Replace the public build component while the producer is paused.  The
    # publisher may finish only inside its pinned old tree; it must reject the
    # chain before D/B/R and never publish into the replacement namespace.
    durability_swap_root=$tmp/durability-build-swap
    durability_swap_ready=$tmp/durability-build-swap.ready
    durability_swap_release=$tmp/durability-build-swap.release
    durability_swap_trace=$tmp/durability-build-swap.trace
    mkdir "$durability_swap_root" ||
        fail "cannot create durability build-swap root"
    # The spawned producer, not this parent shell, expands the gate variables.
    # shellcheck disable=SC2016
    AR11_DURABILITY_SWAP_READY=$durability_swap_ready \
    AR11_DURABILITY_SWAP_RELEASE=$durability_swap_release \
    GITSWITCH_RELEASE_TEST_SYNC_REPORT_FD=8 \
        "$named_publish_helper" --internal-release-tree-v1 \
        "$durability_swap_root" build dist archive.tar.gz -- \
        /bin/sh -c '
            printf durability-swap-payload
            : >"$AR11_DURABILITY_SWAP_READY"
            attempt=0
            while [ ! -s "$AR11_DURABILITY_SWAP_RELEASE" ]; do
                attempt=$((attempt + 1))
                [ "$attempt" -lt 100 ] || exit 90
                sleep 0.1
            done
        ' 8>"$durability_swap_trace" >"$durability_out" 2>&1 &
    durability_swap_pid=$!
    durability_swap_tries=0
    while [ ! -e "$durability_swap_ready" ]; do
        durability_swap_tries=$((durability_swap_tries + 1))
        [ "$durability_swap_tries" -lt 100 ] ||
            fail "timed out waiting for build-swap producer"
        sleep 0.1
    done
    mv "$durability_swap_root/build" "$durability_swap_root/build.pinned" ||
        fail "cannot move pinned durability build directory"
    mkdir "$durability_swap_root/build" \
        "$durability_swap_root/build/dist" ||
        fail "cannot install replacement durability build directory"
    printf '%s\n' replacement >"$durability_swap_root/build/sentinel" ||
        fail "cannot create replacement build sentinel"
    printf '%s\n' release >"$durability_swap_release" ||
        fail "cannot release build-swap producer"
    if wait "$durability_swap_pid"; then
        durability_swap_status=0
    else
        durability_swap_status=$?
    fi
    durability_swap_pid=
    [ "$durability_swap_status" -ne 0 ] ||
        fail "publisher accepted a replaced build component"
    case $copy_platform in
        Darwin) durability_swap_expected=FA ;;
        *) durability_swap_expected=F ;;
    esac
    durability_actual=$(awk '{ printf "%s", $1 }' \
        "$durability_swap_trace") ||
        fail "cannot inspect build-swap durability trace"
    [ "$durability_actual" = "$durability_swap_expected" ] ||
        fail "build replacement reached an ancestor durability barrier"
    [ ! -e "$durability_swap_root/build/dist/archive.tar.gz" ] &&
    [ ! -L "$durability_swap_root/build/dist/archive.tar.gz" ] ||
        fail "publisher wrote through the replacement build component"
    [ "$(cat "$durability_swap_root/build/sentinel")" = replacement ] ||
        fail "publisher changed replacement build state"
    [ "$(cat "$durability_swap_root/build.pinned/dist/archive.tar.gz")" = \
        durability-swap-payload ] ||
        fail "build replacement did not retain complete pinned artifact"
    grep -F 'chain changed before durability barriers' \
        "$durability_out" >/dev/null || {
        sed -n '1,160p' "$durability_out" >&2
        fail "build replacement lacked a precise chain diagnostic"
    }

    # The post-R check is not the end of publication: the final content digest
    # can be long-running.  Replace each independently verified component after
    # that check so deleting any one of the final root/build/dist proofs makes
    # its exact matrix case falsely succeed.
    for durability_final_component in root build dist; do
        durability_final_root=$tmp/durability-final-$durability_final_component
        durability_final_marker=$tmp/durability-final-$durability_final_component.marker
        durability_final_release=$tmp/durability-final-$durability_final_component.release
        durability_final_trace=$tmp/durability-final-$durability_final_component.trace
        durability_final_out=$tmp/durability-final-$durability_final_component.out
        mkdir "$durability_final_root" ||
            fail "cannot create final-$durability_final_component durability root"
        GITSWITCH_RELEASE_TEST_FINAL_TREE_MARKER=$durability_final_marker \
        GITSWITCH_RELEASE_TEST_FINAL_TREE_RELEASE=$durability_final_release \
        GITSWITCH_RELEASE_TEST_SYNC_REPORT_FD=8 \
            "$named_publish_helper" --internal-release-tree-v1 \
            "$durability_final_root" build dist archive.tar.gz -- \
            /bin/sh -c 'printf durability-final-tree-payload' \
            8>"$durability_final_trace" >"$durability_final_out" 2>&1 &
        durability_swap_pid=$!
        durability_swap_tries=0
        while [ ! -e "$durability_final_marker" ]; do
            kill -0 "$durability_swap_pid" 2>/dev/null || {
                sed -n '1,160p' "$durability_final_out" >&2
                fail "final-$durability_final_component publisher exited before its race boundary"
            }
            durability_swap_tries=$((durability_swap_tries + 1))
            [ "$durability_swap_tries" -lt 100 ] ||
                fail "final-$durability_final_component publisher did not reach its race boundary"
            sleep 0.1
        done
        case $durability_final_component in
            root)
                durability_final_pinned_root=$durability_final_root.pinned
                mv "$durability_final_root" "$durability_final_pinned_root" ||
                    fail "cannot move final pinned root directory"
                mkdir "$durability_final_root" ||
                    fail "cannot install final replacement root directory"
                durability_final_sentinel=$durability_final_root/sentinel
                durability_final_replacement_archive=$durability_final_root/build/dist/archive.tar.gz
                durability_final_pinned_archive=$durability_final_pinned_root/build/dist/archive.tar.gz
                ;;
            build)
                mv "$durability_final_root/build" \
                    "$durability_final_root/build.pinned" ||
                    fail "cannot move final pinned build directory"
                mkdir "$durability_final_root/build" \
                    "$durability_final_root/build/dist" ||
                    fail "cannot install final replacement build directory"
                durability_final_sentinel=$durability_final_root/build/sentinel
                durability_final_replacement_archive=$durability_final_root/build/dist/archive.tar.gz
                durability_final_pinned_archive=$durability_final_root/build.pinned/dist/archive.tar.gz
                ;;
            dist)
                mv "$durability_final_root/build/dist" \
                    "$durability_final_root/build/dist.pinned" ||
                    fail "cannot move final pinned dist directory"
                mkdir "$durability_final_root/build/dist" ||
                    fail "cannot install final replacement dist directory"
                durability_final_sentinel=$durability_final_root/build/dist/sentinel
                durability_final_replacement_archive=$durability_final_root/build/dist/archive.tar.gz
                durability_final_pinned_archive=$durability_final_root/build/dist.pinned/archive.tar.gz
                ;;
        esac
        printf '%s\n' replacement >"$durability_final_sentinel" ||
            fail "cannot create final-$durability_final_component replacement sentinel"
        printf '%s\n' release >"$durability_final_release" ||
            fail "cannot release final-$durability_final_component race boundary"
        if wait "$durability_swap_pid"; then
            durability_swap_pid=
            fail "publisher accepted a post-R $durability_final_component replacement"
        fi
        durability_swap_pid=
        durability_actual=$(awk '{ printf "%s", $1 }' \
            "$durability_final_trace") ||
            fail "cannot inspect final-$durability_final_component durability trace"
        [ "$durability_actual" = "$durability_expected" ] ||
            fail "final-$durability_final_component replacement skipped a durability barrier"
        [ ! -e "$durability_final_replacement_archive" ] &&
        [ ! -L "$durability_final_replacement_archive" ] ||
            fail "final-$durability_final_component replacement received the pinned artifact"
        [ "$(cat "$durability_final_sentinel")" = replacement ] ||
            fail "final-$durability_final_component replacement state changed"
        [ "$(cat "$durability_final_pinned_archive")" = \
            durability-final-tree-payload ] ||
            fail "final-$durability_final_component rejection changed the pinned artifact"
        grep -F 'chain changed before completion' "$durability_final_out" \
            >/dev/null || {
            sed -n '1,160p' "$durability_final_out" >&2
            fail "final-$durability_final_component replacement lacked its completion diagnostic"
        }
    done

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

    # AR-11 M40: repository-private attributes and archive-format commands are
    # operator state, not release inputs. A clean archive is the byte oracle;
    # each independently poisoned rerun must remain identical to it. The Git
    # wrapper also proves one publication performs the two generations needed
    # for the producer's pre-publication byte-repeat check.
    cp "$archive" "$tmp/hermetic-archive.baseline" ||
        fail "cannot preserve hermetic archive baseline"

    # The complete Make flow must delegate both artifact-directory components
    # to mkdirat in the publisher.  Its provenance-bound helpers live under the
    # clone's Git directory, so a genuinely absent build tree needs no shell
    # namespace bootstrap inside the repository.
    mkdir_shims=$tmp/m46-mkdir-shims
    mkdir_marker=$tmp/m46-pathname-mkdir
    mkdir "$mkdir_shims" || fail "cannot create M46 mkdir shim directory"
    real_mkdir=$(command -v mkdir) || fail "mkdir is unavailable"
    printf '%s\n' "$real_mkdir" >"$mkdir_shims/real-mkdir" ||
        fail "cannot record real mkdir for M46 fixture"
    printf '%s\n' "$mkdir_marker" >"$mkdir_shims/marker" ||
        fail "cannot record M46 mkdir marker"
    cat >"$mkdir_shims/mkdir" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r real_mkdir <"$shim_dir/real-mkdir" || exit 95
IFS= read -r marker <"$shim_dir/marker" || exit 96
for argument do
    if [ "$argument" = build ] || [ "$argument" = build/dist ]; then
        printf '%s\n' "$argument" >"$marker" || exit 97
        exit 98
    fi
done
exec "$real_mkdir" "$@"
EOF
    chmod 0700 "$mkdir_shims/mkdir" ||
        fail "cannot make M46 mkdir shim executable"
    real_hostcc=$(command -v cc 2>/dev/null ||
        command -v gcc 2>/dev/null || command -v clang 2>/dev/null) ||
        fail "a host C compiler is unavailable for M46"
    cat >"$mkdir_shims/hostcc" <<'EOF'
#!/bin/sh
: "${AR11_M46_REAL_HOSTCC:?}"
case ${1-} in
    --version) exec "$AR11_M46_REAL_HOSTCC" "$@" ;;
esac
exec "$AR11_M46_REAL_HOSTCC" \
    -DGITSWITCH_RELEASE_TEST_DURABILITY=1 "$@"
EOF
    chmod 0700 "$mkdir_shims/hostcc" ||
        fail "cannot make M46 HOSTCC wrapper executable"
    durability_make_hostcc=$mkdir_shims/hostcc
    durability_make_trace=$tmp/m46-make.trace
    rm -f "$archive"
    rm -rf "$clean_tools_dir" "$clean_repo/build" ||
        fail "cannot reset first-use release state for M46 fixture"
    if PATH="$mkdir_shims:$PATH" \
        "$make_cmd" -C "$clean_repo" HOSTCC=false dist \
        >"$out" 2>&1; then
        fail "first-use publisher bootstrap accepted an invalid compiler"
    fi
    [ ! -e "$clean_repo/build" ] && [ ! -L "$clean_repo/build" ] ||
        fail "failed publisher bootstrap created the artifact tree"
    [ ! -e "$clean_publish_lock" ] && [ ! -L "$clean_publish_lock" ] ||
        fail "failed publisher bootstrap retained its Git-private mutex"
    rm -rf "$clean_repo/build" ||
        fail "cannot reset the fresh artifact tree for M46 fixture"
    AR11_M46_REAL_HOSTCC=$real_hostcc \
    GITSWITCH_RELEASE_TEST_SYNC_REPORT_FD=8 \
    PATH="$mkdir_shims:$PATH" \
        "$make_cmd" -C "$clean_repo" HOSTCC="$durability_make_hostcc" \
        dist 8>"$durability_make_trace" >"$out" 2>&1 || {
        sed -n '1,200p' "$out" >&2
        fail "descriptor-relative distribution creation failed"
    }
    [ ! -e "$mkdir_marker" ] ||
        fail "Make still pathname-created an artifact-directory component"
    [ "$(find "$clean_repo/build" -prune -type d -perm 0700 \
        -print 2>/dev/null)" = "$clean_repo/build" ] ||
        fail "real Make publisher build directory mode is not exactly 0700"
    [ "$(find "$clean_repo/build/dist" -prune -type d -perm 0700 \
        -print 2>/dev/null)" = "$clean_repo/build/dist" ] ||
        fail "real Make publisher dist directory mode is not exactly 0700"
    cmp -s "$archive" "$tmp/hermetic-archive.baseline" ||
        fail "descriptor-relative directory creation changed release bytes"
    durability_make_actual=$(awk '{ printf "%s", $1 }' \
        "$durability_make_trace") ||
        fail "cannot inspect real Make durability trace"
    [ "$durability_make_actual" = "$durability_expected" ] || {
        sed -n '1,160p' "$durability_make_trace" >&2
        fail "real Make durability order was $durability_make_actual; expected $durability_expected"
    }
    case $copy_platform in
        Darwin|FreeBSD)
            durability_make_dist_identity=$(stat -f '%d:%i' \
                "$clean_repo/build/dist") ||
                fail "cannot identify real Make dist directory"
            durability_make_build_identity=$(stat -f '%d:%i' \
                "$clean_repo/build") ||
                fail "cannot identify real Make build directory"
            durability_make_root_identity=$(stat -f '%d:%i' \
                "$clean_repo") || fail "cannot identify real Make root"
            ;;
        *)
            durability_make_dist_identity=$(stat -c '%d:%i' \
                "$clean_repo/build/dist") ||
                fail "cannot identify real Make dist directory"
            durability_make_build_identity=$(stat -c '%d:%i' \
                "$clean_repo/build") ||
                fail "cannot identify real Make build directory"
            durability_make_root_identity=$(stat -c '%d:%i' \
                "$clean_repo") || fail "cannot identify real Make root"
            ;;
    esac
    [ "$(awk '$1 == "D" { print $2 }' "$durability_make_trace")" = \
        "$durability_make_dist_identity" ] ||
        fail "real Make dist barrier targeted the wrong descriptor"
    [ "$(awk '$1 == "B" { print $2 }' "$durability_make_trace")" = \
        "$durability_make_build_identity" ] ||
        fail "real Make build barrier targeted the wrong descriptor"
    [ "$(awk '$1 == "R" { print $2 }' "$durability_make_trace")" = \
        "$durability_make_root_identity" ] ||
        fail "real Make root barrier targeted the wrong descriptor"
    [ ! -e "$clean_publish_lock" ] && [ ! -L "$clean_publish_lock" ] ||
        fail "real Make durability flow retained its Git-private mutex"
    real_nm=$(command -v nm 2>/dev/null) ||
        fail "nm is required to prove production fsync imports"
    for durability_helper in "$clean_publish_helper" \
        "$clean_tools_dir/release-publish-named-test"; do
        "$real_nm" -u "$durability_helper" >"$tmp/m46-nm.out" 2>&1 || {
            sed -n '1,160p' "$tmp/m46-nm.out" >&2
            fail "cannot inspect publisher imports: $durability_helper"
        }
        grep -E '(^|[[:space:]])_?fsync(@[^[:space:]]*)?([[:space:]]|$)' \
            "$tmp/m46-nm.out" >/dev/null || {
            sed -n '1,160p' "$tmp/m46-nm.out" >&2
            fail "publisher does not import fsync: $durability_helper"
        }
    done
    inspect_dist_residue "$archive" "$copy_platform"
    rm -f "$archive"

    # Exercise the production Make path, not only the direct named fixture, at
    # every required barrier.  Each injected fault must reach its exact prefix,
    # fail the wrapper, and still release the Git-private mutex for the retry.
    for durability_make_fail_stage in F D B R; do
        : >"$durability_make_trace"
        if AR11_M46_REAL_HOSTCC=$real_hostcc \
           GITSWITCH_RELEASE_TEST_SYNC_REPORT_FD=8 \
           GITSWITCH_RELEASE_TEST_SYNC_FAIL_STAGE=$durability_make_fail_stage \
            "$make_cmd" -C "$clean_repo" \
            HOSTCC="$durability_make_hostcc" dist \
            8>"$durability_make_trace" >"$out" 2>&1; then
            fail "real Make accepted durability stage $durability_make_fail_stage failure"
        fi
        case $copy_platform:$durability_make_fail_stage in
            Darwin:F) durability_make_prefix=F ;;
            Darwin:D) durability_make_prefix=FAD ;;
            Darwin:B) durability_make_prefix=FADB ;;
            Darwin:R) durability_make_prefix=FADBR ;;
            *:F) durability_make_prefix=F ;;
            *:D) durability_make_prefix=FD ;;
            *:B) durability_make_prefix=FDB ;;
            *:R) durability_make_prefix=FDBR ;;
        esac
        durability_make_actual=$(awk '{ printf "%s", $1 }' \
            "$durability_make_trace") ||
            fail "cannot inspect failed real Make durability trace"
        [ "$durability_make_actual" = "$durability_make_prefix" ] || {
            sed -n '1,160p' "$durability_make_trace" >&2
            fail "failed real Make durability order was $durability_make_actual; expected $durability_make_prefix"
        }
        grep -F "durability stage $durability_make_fail_stage" "$out" \
            >/dev/null || {
            sed -n '1,200p' "$out" >&2
            fail "real Make failure lacked durability stage $durability_make_fail_stage"
        }
        [ ! -e "$clean_publish_lock" ] && [ ! -L "$clean_publish_lock" ] ||
            fail "failed real Make durability flow retained its mutex"
        case $durability_make_fail_stage in
            F) inspect_failed_dist_residue "$archive" "$copy_platform" ;;
            *)
                assert_archive_metadata "$archive" "$dist_root" "$version"
                inspect_dist_residue "$archive" "$copy_platform"
                rm -f "$archive"
                ;;
        esac
    done

    printf '%s\n' 'README.md export-ignore' >"$clean_git_dir/info/attributes" ||
        fail "cannot install repository-private attribute fixture"
    rm -f "$archive"
    "$make_cmd" -C "$clean_repo" dist >"$out" 2>&1 || {
        sed -n '1,200p' "$out" >&2
        fail "repository-private attributes changed release generation"
    }
    assert_archive_metadata "$archive" "$dist_root" "$version"
    cmp -s "$archive" "$tmp/hermetic-archive.baseline" ||
        fail "repository-private attributes changed release bytes"
    rm -f "$archive" "$clean_git_dir/info/attributes"

    # A workspace root can be created successfully while its first child path
    # exceeds PATH_MAX. Cleanup must then remove only the root it actually
    # created; uninitialized derived fields may never become root-relative
    # /config, /HEAD, or /refs removal attempts.
    path_max=$(getconf PATH_MAX "$tmp" 2>/dev/null) ||
        fail "cannot resolve PATH_MAX for archive workspace fixture"
    name_max=$(getconf NAME_MAX "$tmp" 2>/dev/null) ||
        fail "cannot resolve NAME_MAX for archive workspace fixture"
    case $path_max:$name_max in
        *[!0-9:]*|:*|*:) fail "invalid archive workspace path limits" ;;
    esac
    archive_workspace_suffix=/gitswitch-release-archive.XXXXXX
    long_tmp_target=$((path_max - ${#archive_workspace_suffix} - 2))
    long_tmp=$tmp
    [ "$long_tmp_target" -gt $((${#long_tmp} + 2)) ] ||
        fail "PATH_MAX is too small for archive workspace fixture"
    component_limit=$name_max
    [ "$component_limit" -le 128 ] || component_limit=128
    while [ "${#long_tmp}" -lt "$long_tmp_target" ]; do
        component_length=$((long_tmp_target - ${#long_tmp} - 1))
        [ "$component_length" -gt 0 ] ||
            fail "cannot extend archive workspace fixture path"
        [ "$component_length" -le "$component_limit" ] ||
            component_length=$component_limit
        long_component=$(awk -v count="$component_length" '
            BEGIN { for (position = 0; position < count; position++) printf "w" }
        ') || fail "cannot generate archive workspace path component"
        [ "${#long_component}" -eq "$component_length" ] ||
            fail "archive workspace path component was truncated"
        long_tmp=$long_tmp/$long_component
        mkdir "$long_tmp" || fail "cannot create long archive workspace path"
    done
    [ $((${#long_tmp} + ${#archive_workspace_suffix})) -lt "$path_max" ] &&
        [ $((${#long_tmp} + ${#archive_workspace_suffix} + 5)) -ge "$path_max" ] ||
        fail "archive workspace fixture does not straddle PATH_MAX"
    printf '%s\n' caller-owned >"$long_tmp/caller-sentinel" ||
        fail "cannot create archive workspace ownership sentinel"
    if TMPDIR="$long_tmp" \
        "$make_cmd" -C "$clean_repo" dist >"$out" 2>&1; then
        fail "overlong archive workspace child unexpectedly succeeded"
    fi
    grep -F 'cannot create private archive workspace' "$out" >/dev/null || {
        sed -n '1,200p' "$out" >&2
        fail "overlong archive workspace failure was not diagnosed"
    }
    [ "$(cat "$long_tmp/caller-sentinel")" = caller-owned ] ||
        fail "archive workspace cleanup changed its caller-owned TMPDIR"
    set -- "$long_tmp"/gitswitch-release-archive.*
    { [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; } ||
        fail "failed archive workspace creation left a private root"
    inspect_failed_dist_residue "$archive" "$copy_platform"

    hermetic_shims=$tmp/hermetic-git-shims
    mkdir "$hermetic_shims" || fail "cannot create hermetic Git shim directory"
    real_git=$(command -v git) || fail "git is unavailable for hermetic fixture"
    real_gzip=$(command -v gzip) ||
        fail "gzip is unavailable for hermetic fixture"
    printf '%s\n' "$real_git" >"$hermetic_shims/real-git" ||
        fail "cannot record hermetic fixture Git path"
    printf '%s\n' "$real_gzip" >"$hermetic_shims/real-gzip" ||
        fail "cannot record hermetic fixture gzip path"
    cat >"$hermetic_shims/git" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r real_git <"$shim_dir/real-git" || exit 91
is_archive=false
is_ls_tree=false
for argument do
    case $argument in
        archive) is_archive=true ;;
        ls-tree) is_ls_tree=true ;;
    esac
done
if [ "$is_archive" = true ]; then
    printf '%s\n' archive >>"$shim_dir/archive-calls" || exit 92
fi
mode=
if [ -f "$shim_dir/git-mode" ]; then
    IFS= read -r mode <"$shim_dir/git-mode" || exit 93
fi
if [ "$mode" = manifest-missing-actual ] && [ "$is_ls_tree" = true ]; then
    "$real_git" "$@" || exit $?
    printf '%s\000' tests/.ar11-m40-unexpected
    exit 0
fi
if [ "$mode" = manifest-unexpected-actual ] && [ "$is_ls_tree" = true ]; then
    # Keep both archive streams unchanged while removing one committed member
    # from the independent manifest oracle. Query each other manifest operand
    # separately; the validator sorts and deduplicates the resulting NUL list.
    [ "$#" -ge 6 ] && [ "$1" = ls-tree ] && [ "$5" = -- ] || exit 94
    tree_command=$1
    tree_recursive=$2
    tree_names=$3
    tree_commit=$4
    shift 5
    for tree_path do
        [ "$tree_path" = README.md ] && continue
        "$real_git" "$tree_command" "$tree_recursive" "$tree_names" \
            "$tree_commit" -- "$tree_path" || exit $?
    done
    exit 0
fi
exec "$real_git" "$@"
EOF
    cat >"$hermetic_shims/gzip" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r real_gzip <"$shim_dir/real-gzip" || exit 94
mode=
if [ -f "$shim_dir/gzip-mode" ]; then
    IFS= read -r mode <"$shim_dir/gzip-mode" || exit 95
fi
if [ "$#" -eq 2 ] && [ "$1" = -n ] && [ "$2" = -9 ]; then
    printf '%s\n' 'compress:-n:-9' >>"$shim_dir/gzip-calls" || exit 96
    if [ "$mode" = repeat-diverge ]; then
        if mkdir "$shim_dir/first-compression" 2>/dev/null; then
            exec "$real_gzip" -n -9
        else
            # Keep the stream valid and exactly the same length while changing
            # only gzip's informational OS header byte. Length-only or
            # decompressed-payload comparisons therefore cannot satisfy the
            # repeated-byte gate.
            "$real_gzip" -n -9 | {
                dd bs=1 count=9 2>/dev/null
                dd bs=1 count=1 of=/dev/null 2>/dev/null
                printf '\377'
                cat
            }
            exit $?
        fi
    fi
elif [ "$#" -eq 1 ] && [ "$1" = -t ]; then
    printf '%s\n' 'integrity:-t' >>"$shim_dir/gzip-calls" || exit 97
    [ "$mode" != integrity-fail ] || exit 73
fi
exec "$real_gzip" "$@"
EOF
    real_tar=$(command -v tar) || fail "tar is unavailable for hermetic fixture"
    printf '%s\n' "$real_tar" >"$hermetic_shims/real-tar" ||
        fail "cannot record hermetic fixture tar path"
    cat >"$hermetic_shims/tar" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r real_tar <"$shim_dir/real-tar" || exit 98
mode=
if [ -f "$shim_dir/tar-mode" ]; then
    IFS= read -r mode <"$shim_dir/tar-mode" || exit 99
fi
if [ "$#" -eq 2 ] && [ "$1" = -tf ] && [ "$2" = - ]; then
    printf '%s\n' 'list:-tf:-' >>"$shim_dir/tar-calls" || exit 100
    "$real_tar" "$@" || exit $?
    [ "$mode" != status-fail ] || exit 74
    exit 0
fi
exec "$real_tar" "$@"
EOF
    cat >"$hermetic_shims/configured-compressor" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
printf '%s\n' invoked >"$shim_dir/compressor-invoked" || exit 93
printf '%s\n' locally-configured-encoding
EOF
    chmod 0700 "$hermetic_shims/git" "$hermetic_shims/gzip" \
        "$hermetic_shims/tar" \
        "$hermetic_shims/configured-compressor" ||
        fail "cannot make hermetic fixture shims executable"
    git -C "$clean_repo" config --local tar.tar.gz.command \
        "$hermetic_shims/configured-compressor" ||
        fail "cannot install repository-local compressor fixture"
    git -C "$clean_repo" config --local tar.umask 077 ||
        fail "cannot install repository-local tar umask fixture"
    PATH="$hermetic_shims:$PATH" \
        "$make_cmd" -C "$clean_repo" dist >"$out" 2>&1 || {
        sed -n '1,200p' "$out" >&2
        fail "repository-local archive configuration changed release generation"
    }
    git -C "$clean_repo" config --local --unset-all tar.tar.gz.command ||
        fail "cannot remove repository-local compressor fixture"
    git -C "$clean_repo" config --local --unset-all tar.umask ||
        fail "cannot remove repository-local tar umask fixture"
    [ ! -e "$hermetic_shims/compressor-invoked" ] ||
        fail "release invoked the repository-local archive compressor"
    [ "$(wc -l <"$hermetic_shims/archive-calls")" -eq 2 ] ||
        fail "release did not compare two independently generated archives"
    [ "$(grep -Fxc 'compress:-n:-9' \
        "$hermetic_shims/gzip-calls" || true)" -eq 2 ] ||
        fail "release did not use fixed gzip -n -9 for both archive streams"
    [ "$(grep -Fxc 'integrity:-t' \
        "$hermetic_shims/gzip-calls" || true)" -eq 1 ] ||
        fail "release did not integrity-check its completed gzip stream"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    cmp -s "$archive" "$tmp/hermetic-archive.baseline" ||
        fail "repository-local archive configuration changed release bytes"

    # Each validation gate gets a causal failure mode. The compressor shim
    # makes two valid but byte-distinct gzip streams, the Git shim perturbs only
    # the manifest oracle after both archives are complete, and the integrity
    # mode fails only gzip -t, and the tar shim emits a full valid listing
    # before failing its terminal status. None may create the canonical name.
    rm -f "$hermetic_shims/gzip-calls"
    rmdir "$hermetic_shims/first-compression" 2>/dev/null || :
    printf '%s\n' repeat-diverge >"$hermetic_shims/gzip-mode" ||
        fail "cannot arm repeated-byte divergence fixture"
    expect_archive_validation_rejected \
        "repeated-byte" \
        "repeated archive byte check exited with status 1" \
        "$clean_repo" "$make_cmd" "$archive" "$out" \
        "$hermetic_shims" "$copy_platform"
    [ "$(grep -Fxc 'compress:-n:-9' \
        "$hermetic_shims/gzip-calls" || true)" -eq 2 ] ||
        fail "repeated-byte fixture did not exercise both fixed compressors"

    rm -f "$hermetic_shims/gzip-mode" "$hermetic_shims/gzip-calls" \
        "$hermetic_shims/archive-calls"
    rmdir "$hermetic_shims/first-compression" 2>/dev/null || :
    printf '%s\n' manifest-missing-actual >"$hermetic_shims/git-mode" ||
        fail "cannot arm missing-actual manifest fixture"
    expect_archive_validation_rejected \
        "missing-actual manifest" \
        "completed archive differs from the exact committed release manifest" \
        "$clean_repo" "$make_cmd" "$archive" "$out" \
        "$hermetic_shims" "$copy_platform"
    [ "$(wc -l <"$hermetic_shims/archive-calls")" -eq 2 ] ||
        fail "missing-actual manifest fixture did not complete both archive streams"

    rm -f "$hermetic_shims/git-mode" "$hermetic_shims/gzip-calls" \
        "$hermetic_shims/archive-calls"
    printf '%s\n' manifest-unexpected-actual >"$hermetic_shims/git-mode" ||
        fail "cannot arm unexpected-actual manifest fixture"
    expect_archive_validation_rejected \
        "unexpected-actual manifest" \
        "completed archive differs from the exact committed release manifest" \
        "$clean_repo" "$make_cmd" "$archive" "$out" \
        "$hermetic_shims" "$copy_platform"
    [ "$(wc -l <"$hermetic_shims/archive-calls")" -eq 2 ] ||
        fail "unexpected-actual manifest fixture did not complete both archive streams"

    rm -f "$hermetic_shims/git-mode" "$hermetic_shims/gzip-calls" \
        "$hermetic_shims/archive-calls"
    printf '%s\n' integrity-fail >"$hermetic_shims/gzip-mode" ||
        fail "cannot arm gzip-integrity failure fixture"
    expect_archive_validation_rejected \
        "gzip-integrity" \
        "completed gzip integrity check exited with status 73" \
        "$clean_repo" "$make_cmd" "$archive" "$out" \
        "$hermetic_shims" "$copy_platform"
    [ "$(grep -Fxc 'integrity:-t' \
        "$hermetic_shims/gzip-calls" || true)" -eq 1 ] ||
        fail "gzip-integrity fixture did not exercise the completed-stream check"
    rm -f "$hermetic_shims/gzip-mode" "$hermetic_shims/gzip-calls" \
        "$hermetic_shims/tar-calls"

    printf '%s\n' status-fail >"$hermetic_shims/tar-mode" ||
        fail "cannot arm completed-tar status fixture"
    expect_archive_validation_rejected \
        "completed-tar status" \
        "completed tar member check exited with status 74" \
        "$clean_repo" "$make_cmd" "$archive" "$out" \
        "$hermetic_shims" "$copy_platform"
    [ "$(grep -Fxc 'list:-tf:-' \
        "$hermetic_shims/tar-calls" || true)" -eq 1 ] ||
        fail "completed-tar fixture did not exercise the listing child"
    rm -f "$hermetic_shims/tar-mode" "$hermetic_shims/tar-calls"

    # The Git-private mutex must cover the verified helper's use, not merely
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
    printf '%s\n' "$real_git" >"$lock_shims/real-git"
    printf '%s\n' "$lock_ready" >"$lock_shims/ready"
    printf '%s\n' "$lock_release" >"$lock_shims/release"
    cat >"$lock_shims/git" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r real_git <"$shim_dir/real-git" || exit 90
IFS= read -r ready <"$shim_dir/ready" || exit 91
IFS= read -r release <"$shim_dir/release" || exit 92
is_archive=false
for argument do
    if [ "$argument" = archive ]; then
        is_archive=true
    fi
done
if [ "$is_archive" = true ]; then
    ready_tmp=$ready.tmp.$$
    printf '%s\n' "$$" >"$ready_tmp" || exit 91
    mv -f "$ready_tmp" "$ready" || exit 93
    gate_tries=0
    while [ ! -s "$release" ]; do
        gate_tries=$((gate_tries + 1))
        [ "$gate_tries" -lt 300 ] || exit 94
        sleep 0.1
    done
fi
exec "$real_git" "$@"
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
    cp "$clean_publish_receipt" \
        "$tmp/release-lock.receipt.before"
    rm -f "$archive" "$lock_ready" "$lock_release" "$lock_status" \
        "$lock_hostcc_log"
    (
        lock_a_status=0
        PATH="$lock_shims:$PATH" \
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
    [ -s "$clean_publish_lock/owner" ] ||
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
    cmp -s "$clean_publish_receipt" \
        "$tmp/release-lock.receipt.before" ||
        fail "contending helper generation changed shared provenance"
    [ -d "$clean_publish_lock" ] ||
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
    [ ! -e "$clean_publish_lock" ] &&
        [ ! -L "$clean_publish_lock" ] ||
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
        "$clean_publish_receipt" >/dev/null ||
        fail "post-release provenance did not bind the contending HOSTCC"
    [ ! -e "$clean_publish_lock" ] &&
        [ ! -L "$clean_publish_lock" ] ||
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
    cp "$foreign_publish_helper" "$clean_publish_helper" ||
        fail "cannot install foreign publisher fixture"
    touch -t 203501010000 "$clean_publish_helper" ||
        fail "cannot future-date foreign publisher fixture"
    "$make_cmd" -C "$clean_repo" dist >"$out" 2>&1 || {
        sed -n '1,200p' "$out" >&2
        fail "dist did not recover a future-dated foreign publisher"
    }
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"

    # The helper target itself is fixed inside the Git-private state namespace.
    # Before that boundary was override-protected, `-B
    # DIST_PUBLISH_HELPER=VERSION` compiled the helper over tracked VERSION and
    # still returned success. Exercise both primary documentation inputs and
    # the helper-directory and Git-state discovery variables while forcing a
    # rebuild.
    hostile_release_state=$tmp/hostile-release-state
    mkdir "$hostile_release_state" ||
        fail "cannot create hostile release-state fixture"
    printf '%s\n' preserve >"$hostile_release_state/sentinel" ||
        fail "cannot create hostile release-state sentinel"
    rm -f "$archive"
    "$make_cmd" -B -C "$clean_repo" DIST_PUBLISH_HELPER=VERSION \
        TOOLBUILDDIR=. RELEASE_GIT_DIR_AVAILABLE=0 \
        RELEASE_GIT_DIR="$hostile_release_state" dist >"$out" 2>&1 ||
        fail "fixed publisher target rejected a hostile VERSION override"
    cmp -s "$clean_repo/VERSION" "$tmp/VERSION.before" ||
        fail "publisher target override changed tracked VERSION"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"
    rm -f "$archive"
    "$make_cmd" -B -C "$clean_repo" DIST_PUBLISH_HELPER=README.md \
        TOOLBUILDDIR=src RELEASE_GIT_DIR_AVAILABLE=1 \
        RELEASE_GIT_DIR="$hostile_release_state" dist >"$out" 2>&1 ||
        fail "fixed publisher target rejected a hostile README override"
    cmp -s "$clean_repo/README.md" "$tmp/README.before" ||
        fail "publisher target override changed tracked README"
    assert_archive_metadata "$archive" "$dist_root" "$version"
    inspect_dist_residue "$archive" "$copy_platform"
    [ "$(cat "$hostile_release_state/sentinel")" = preserve ] ||
        fail "hostile Git-state override changed its target"
    [ ! -e "$clean_repo/build/tools" ] &&
    [ ! -L "$clean_repo/build/tools" ] ||
        fail "hostile release-state override restored in-tree helper bootstrap"

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

    # AR-11 M47: two same-version RPM builds must overlap without sharing any
    # rpmbuild input, output, or scratch pathname.  Each clone commits a
    # distinct source/spec marker while retaining the same VERSION.  The shim
    # uses a two-phase barrier: both private topdirs and their exact inputs must
    # coexist before either invocation is allowed to produce an RPM.  This is
    # causal concurrency evidence, rather than a scheduler-dependent timing
    # assertion.
    rpm_fixture=$tmp/rpm-isolation
    rpm_shims=$rpm_fixture/shims
    rpm_state=$rpm_fixture/state
    rpm_home=$rpm_fixture/"home \$shared"
    rpm_alpha_repo=$rpm_fixture/"alpha \$checkout"
    rpm_beta_repo=$rpm_fixture/"beta \$checkout"
    mkdir -p "$rpm_shims" "$rpm_state" "$rpm_home" ||
        fail "cannot create RPM isolation fixture"
    rpm_home=$(CDPATH='' cd "$rpm_home" && pwd -P) ||
        fail "cannot resolve physical RPM fixture HOME"
    [ -d "$rpm_home" ] && [ ! -L "$rpm_home" ] ||
        fail "RPM fixture HOME is not a physical directory"
    mkdir "$rpm_home/rpmbuild" ||
        fail "cannot create shared-rpmbuild sentinel directory"
    printf '%s\n' 'caller-owned HOME/rpmbuild sentinel' \
        >"$rpm_home/rpmbuild/sentinel" ||
        fail "cannot create shared-rpmbuild sentinel"
    cp "$rpm_home/rpmbuild/sentinel" "$rpm_fixture/rpmbuild.expected" ||
        fail "cannot preserve shared-rpmbuild sentinel"
    rpm_poison=$rpm_state/macro-poison
    {
        printf '%%_topdir %s\n' "$rpm_poison/top"
        printf '%%_builddir %s\n' "$rpm_poison/build"
        printf '%%_buildrootdir %s\n' "$rpm_poison/buildroot"
        printf '%%_rpmdir %s\n' "$rpm_poison/rpms"
        printf '%%_sourcedir %s\n' "$rpm_poison/sources"
        printf '%%_specdir %s\n' "$rpm_poison/specs"
        printf '%%_srcrpmdir %s\n' "$rpm_poison/srpms"
        printf '%%_tmppath %s\n' "$rpm_poison/tmp"
        printf '%%_rpmfilename poison/%%{NAME}.rpm\n'
    } >"$rpm_home/.rpmmacros" ||
        fail "cannot create hostile user RPM macro fixture"
    cp "$rpm_home/.rpmmacros" "$rpm_fixture/rpmmacros.expected" ||
        fail "cannot preserve hostile user RPM macros"
    rpm_real_cmp=$(command -v cmp) || fail "cmp is unavailable for RPM fixture"
    printf '%s\n' "$rpm_real_cmp" >"$rpm_shims/real-cmp" ||
        fail "cannot record real cmp for RPM fixture"
    cat >"$rpm_shims/cmp" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r real_cmp <"$shim_dir/real-cmp" || exit 96
"$real_cmp" "$@"
cmp_status=$?
if [ "$cmp_status" -eq 0 ] &&
   [ "${AR11_RPM_MODE-}" = symlink-srpms ] &&
   [ "$#" -eq 3 ] && [ "$1" = -s ]; then
    cmp_canonical=false
    cmp_private=false
    case $2 in
        "$AR11_RPM_REPO_ROOT/build/dist/"*.tar.gz) cmp_canonical=true ;;
    esac
    case $3 in
        "$AR11_RPM_HOME/.gitswitch-rpmbuild."??????/SOURCES/*.tar.gz)
            cmp_private=true ;;
    esac
    if [ "$cmp_canonical" = true ] && [ "$cmp_private" = true ] &&
       [ ! -e "$AR11_RPM_STATE/archive-swap.marker" ]; then
        cp "$2" "$AR11_RPM_STATE/archive-swap.original" || exit 95
        chmod 0600 "$2" || exit 94
        printf '%s\n' 'canonical archive replaced after private-copy proof' \
            >"$2" || exit 93
        : >"$AR11_RPM_STATE/archive-swap.marker" || exit 92
    fi
fi
exit "$cmp_status"
EOF
    chmod 0700 "$rpm_shims/cmp" ||
        fail "cannot activate canonical-archive swap shim"

    git clone --quiet "$root" "$rpm_alpha_repo" ||
        fail "cannot clone alpha RPM fixture"
    git clone --quiet "$root" "$rpm_beta_repo" ||
        fail "cannot clone beta RPM fixture"
    for rpm_lane in alpha beta; do
        case $rpm_lane in
            alpha) rpm_lane_repo=$rpm_alpha_repo ;;
            beta) rpm_lane_repo=$rpm_beta_repo ;;
        esac
        printf '\n# AR11_RPM_LANE: %s\n' "$rpm_lane" \
            >>"$rpm_lane_repo/gitswitcher.spec" ||
            fail "cannot mark $rpm_lane RPM spec"
        printf '\nAR11_RPM_SOURCE: %s\n' "$rpm_lane" \
            >>"$rpm_lane_repo/README.md" ||
            fail "cannot mark $rpm_lane RPM source"
        git -C "$rpm_lane_repo" add -- gitswitcher.spec README.md ||
            fail "cannot stage $rpm_lane RPM fixture"
        git -C "$rpm_lane_repo" \
            -c user.name='AR-11 RPM fixture' \
            -c user.email='ar11-rpm@example.invalid' \
            -c commit.gpgsign=false commit --quiet --no-gpg-sign \
            -m "AR-11 RPM $rpm_lane fixture" ||
            fail "cannot commit $rpm_lane RPM fixture"
    done
    rpm_alpha_root=$(CDPATH='' cd "$rpm_alpha_repo" && pwd -P) ||
        fail "cannot resolve alpha RPM fixture root"
    rpm_beta_root=$(CDPATH='' cd "$rpm_beta_repo" && pwd -P) ||
        fail "cannot resolve beta RPM fixture root"
    rpm_fixture_version=$(git -C "$rpm_alpha_repo" show HEAD:VERSION) ||
        fail "cannot read alpha RPM fixture version"
    [ "$rpm_fixture_version" = \
        "$(git -C "$rpm_beta_repo" show HEAD:VERSION)" ] ||
        fail "concurrent RPM fixtures do not retain one package version"
    rpm_alpha_spec_hash=$(git hash-object \
        "$rpm_alpha_repo/gitswitcher.spec") ||
        fail "cannot hash alpha RPM spec"
    rpm_beta_spec_hash=$(git hash-object \
        "$rpm_beta_repo/gitswitcher.spec") ||
        fail "cannot hash beta RPM spec"
    [ "$rpm_alpha_spec_hash" != "$rpm_beta_spec_hash" ] ||
        fail "concurrent RPM fixture specs are not byte-distinct"

    cat >"$rpm_shims/rpmbuild" <<'EOF'
#!/bin/sh
set -eu

rpm_die()
{
    printf 'ar11-rpmbuild-shim: ERROR: %s\n' "$*" >&2
    exit 97
}

: "${AR11_RPM_STATE:?}"
: "${AR11_RPM_MODE:?}"
: "${AR11_RPM_REPO_ROOT:?}"
: "${AR11_RPM_HOME:?}"
[ "$HOME" = "$AR11_RPM_HOME" ] || rpm_die "fixture HOME changed in transit"
[ -f "$HOME/.rpmmacros" ] && [ ! -L "$HOME/.rpmmacros" ] ||
    rpm_die "hostile user RPM macros were not installed"

rpm_topdir=
rpm_builddir=
rpm_buildrootdir=
rpm_rpmdir=
rpm_sourcedir=
rpm_specdir=
rpm_srcrpmdir=
rpm_tmppath=
rpm_filename_macro=
rpm_spec=
rpm_define_count=0
rpm_ba_count=0
while [ "$#" -gt 0 ]; do
    case $1 in
        --define)
            [ "$#" -ge 2 ] || rpm_die "--define lacks its value"
            shift
            case $1 in
                "_topdir "*)
                    rpm_define_count=$((rpm_define_count + 1))
                    [ -z "$rpm_topdir" ] || rpm_die "duplicate _topdir"
                    rpm_topdir=${1#"_topdir "}
                    ;;
                "_builddir "*)
                    rpm_define_count=$((rpm_define_count + 1))
                    [ -z "$rpm_builddir" ] || rpm_die "duplicate _builddir"
                    rpm_builddir=${1#"_builddir "}
                    ;;
                "_buildrootdir "*)
                    rpm_define_count=$((rpm_define_count + 1))
                    [ -z "$rpm_buildrootdir" ] || rpm_die "duplicate _buildrootdir"
                    rpm_buildrootdir=${1#"_buildrootdir "}
                    ;;
                "_rpmdir "*)
                    rpm_define_count=$((rpm_define_count + 1))
                    [ -z "$rpm_rpmdir" ] || rpm_die "duplicate _rpmdir"
                    rpm_rpmdir=${1#"_rpmdir "}
                    ;;
                "_sourcedir "*)
                    rpm_define_count=$((rpm_define_count + 1))
                    [ -z "$rpm_sourcedir" ] || rpm_die "duplicate _sourcedir"
                    rpm_sourcedir=${1#"_sourcedir "}
                    ;;
                "_specdir "*)
                    rpm_define_count=$((rpm_define_count + 1))
                    [ -z "$rpm_specdir" ] || rpm_die "duplicate _specdir"
                    rpm_specdir=${1#"_specdir "}
                    ;;
                "_srcrpmdir "*)
                    rpm_define_count=$((rpm_define_count + 1))
                    [ -z "$rpm_srcrpmdir" ] || rpm_die "duplicate _srcrpmdir"
                    rpm_srcrpmdir=${1#"_srcrpmdir "}
                    ;;
                "_tmppath "*)
                    rpm_define_count=$((rpm_define_count + 1))
                    [ -z "$rpm_tmppath" ] || rpm_die "duplicate _tmppath"
                    rpm_tmppath=${1#"_tmppath "}
                    ;;
                "_rpmfilename "*)
                    rpm_define_count=$((rpm_define_count + 1))
                    [ -z "$rpm_filename_macro" ] ||
                        rpm_die "duplicate _rpmfilename"
                    rpm_filename_macro=${1#"_rpmfilename "}
                    ;;
            esac
            ;;
        -ba)
            [ "$#" -ge 2 ] || rpm_die "-ba lacks its spec path"
            rpm_ba_count=$((rpm_ba_count + 1))
            shift
            rpm_spec=$1
            ;;
    esac
    shift
done
[ "$rpm_define_count" -eq 9 ] ||
    rpm_die "expected nine explicit private RPM macro definitions"
[ "$rpm_ba_count" -eq 1 ] || rpm_die "expected one -ba spec argument"
[ -n "$rpm_topdir" ] || rpm_die "private _topdir is empty"
case $rpm_topdir in
    "$AR11_RPM_HOME/.gitswitch-rpmbuild."??????) ;;
    *) rpm_die "_topdir is outside the physical private HOME namespace" ;;
esac
[ "$rpm_builddir" = "$rpm_topdir/BUILD" ] &&
[ "$rpm_buildrootdir" = "$rpm_topdir/BUILDROOT" ] &&
[ "$rpm_rpmdir" = "$rpm_topdir/RPMS" ] &&
[ "$rpm_sourcedir" = "$rpm_topdir/SOURCES" ] &&
[ "$rpm_specdir" = "$rpm_topdir/SPECS" ] &&
[ "$rpm_srcrpmdir" = "$rpm_topdir/SRPMS" ] &&
[ "$rpm_tmppath" = "$rpm_topdir/TMP" ] ||
    rpm_die "subordinate RPM macros escaped the private _topdir"
[ "$rpm_filename_macro" = \
    '%{ARCH}/%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm' ] ||
    rpm_die "RPM output filename layout was not pinned"
[ -d "$rpm_topdir" ] && [ ! -L "$rpm_topdir" ] ||
    rpm_die "_topdir is not a private directory"
[ "$(find "$rpm_topdir" -prune -type d -perm 0700 -print 2>/dev/null)" = \
    "$rpm_topdir" ] || rpm_die "_topdir is not mode 0700"
for rpm_component in BUILD BUILDROOT PUBLISH RPMS SOURCES SPECS SRPMS TMP; do
    rpm_component_path=$rpm_topdir/$rpm_component
    [ -d "$rpm_component_path" ] && [ ! -L "$rpm_component_path" ] ||
        rpm_die "missing private $rpm_component directory"
    [ "$(find "$rpm_component_path" -prune -type d -perm 0700 \
        -print 2>/dev/null)" = "$rpm_component_path" ] ||
        rpm_die "private $rpm_component directory is not mode 0700"
done
[ "$rpm_spec" = "$rpm_topdir/SPECS/gitswitcher.spec" ] ||
    rpm_die "-ba did not receive the private spec"
[ -f "$rpm_spec" ] && [ ! -L "$rpm_spec" ] ||
    rpm_die "private spec is not a regular file"

rpm_lane=$(sed -n 's/^# AR11_RPM_LANE: //p' "$rpm_spec" | sed -n '1p')
case $rpm_lane in
    alpha|beta) ;;
    *) rpm_die "private spec lacks its lane identity" ;;
esac
rpm_package=$(sed -n 's/^Name:[[:space:]]*//p' "$rpm_spec" | sed -n '1p')
rpm_version=$(sed -n 's/^Version:[[:space:]]*//p' "$rpm_spec" | sed -n '1p')
[ "$rpm_package" = gitswitcher ] && [ -n "$rpm_version" ] ||
    rpm_die "private spec metadata is invalid"
rpm_source=$rpm_topdir/SOURCES/$rpm_package-$rpm_version.tar.gz
rpm_canonical_source=$AR11_RPM_REPO_ROOT/build/dist/$rpm_package-$rpm_version.tar.gz
[ -f "$rpm_source" ] && [ ! -L "$rpm_source" ] ||
    rpm_die "private Source0 is not a regular file"
rpm_source_oracle=$rpm_canonical_source
if [ "$AR11_RPM_MODE" = symlink-srpms ] &&
   [ -f "$AR11_RPM_STATE/archive-swap.marker" ]; then
    rpm_source_oracle=$AR11_RPM_STATE/archive-swap.original
    if cmp -s "$rpm_canonical_source" "$rpm_source"; then
        rpm_die "canonical archive swap did not separate the private source"
    fi
fi
cmp -s "$rpm_source_oracle" "$rpm_source" ||
    rpm_die "private Source0 differs from this checkout's archive"
cmp -s "$AR11_RPM_REPO_ROOT/$rpm_package.spec" "$rpm_spec" ||
    rpm_die "private spec differs from this checkout's committed spec"
rpm_archived_spec=$AR11_RPM_STATE/.archived-spec.$AR11_RPM_MODE.$rpm_lane.$$
rpm_archived_readme=$AR11_RPM_STATE/.archived-readme.$AR11_RPM_MODE.$rpm_lane.$$
tar -xOf "$rpm_source" \
    "$rpm_package-$rpm_version/$rpm_package.spec" >"$rpm_archived_spec" ||
    rpm_die "cannot extract the private archive spec"
tar -xOf "$rpm_source" \
    "$rpm_package-$rpm_version/README.md" >"$rpm_archived_readme" ||
    rpm_die "cannot extract the private archive source marker"
cmp -s "$rpm_archived_spec" "$rpm_spec" ||
    rpm_die "rpmbuild spec is not the archive-embedded spec"
grep -Fx "AR11_RPM_SOURCE: $rpm_lane" "$rpm_archived_readme" >/dev/null ||
    rpm_die "private Source0 belongs to the other build"
rm -f "$rpm_archived_spec" "$rpm_archived_readme"
if [ "$AR11_RPM_MODE" = symlink-srpms ]; then
    cp "$AR11_RPM_STATE/archive-swap.original" "$rpm_canonical_source" ||
        rpm_die "cannot restore canonical archive after private extraction"
    chmod 0444 "$rpm_canonical_source" ||
        rpm_die "cannot restore canonical archive mode"
    cmp -s "$AR11_RPM_STATE/archive-swap.original" "$rpm_canonical_source" ||
        rpm_die "restored canonical archive changed bytes"
    : >"$AR11_RPM_STATE/archive-swap.restored" ||
        rpm_die "cannot record private archive extraction proof"
fi

rpm_source_hash=$(git hash-object "$rpm_source") ||
    rpm_die "cannot hash private Source0"
rpm_spec_hash=$(git hash-object "$rpm_spec") ||
    rpm_die "cannot hash private spec"
rpm_report=$AR11_RPM_STATE/$AR11_RPM_MODE.$rpm_lane.observed
rpm_report_tmp=$rpm_report.tmp.$$
printf '%s\n%s\n%s\n%s\n%s\n' \
    "$rpm_topdir" "$rpm_source_hash" "$rpm_spec_hash" \
    "$rpm_source" "$rpm_spec" >"$rpm_report_tmp" ||
    rpm_die "cannot record private RPM inputs"
mv "$rpm_report_tmp" "$rpm_report" ||
    rpm_die "cannot publish private RPM input report"

rpm_wait_for_pair()
{
    rpm_barrier_suffix=$1
    rpm_barrier_tries=0
    while { [ ! -f "$AR11_RPM_STATE/alpha.$rpm_barrier_suffix" ] ||
            [ ! -f "$AR11_RPM_STATE/beta.$rpm_barrier_suffix" ]; } &&
          [ "$rpm_barrier_tries" -lt 300 ]; do
        sleep 0.1
        rpm_barrier_tries=$((rpm_barrier_tries + 1))
    done
    [ -f "$AR11_RPM_STATE/alpha.$rpm_barrier_suffix" ] &&
    [ -f "$AR11_RPM_STATE/beta.$rpm_barrier_suffix" ] ||
        rpm_die "timed out at concurrent $rpm_barrier_suffix barrier"
}

if [ "$AR11_RPM_MODE" = concurrent ]; then
    : >"$AR11_RPM_STATE/$rpm_lane.ready" ||
        rpm_die "cannot enter concurrent ready barrier"
    rpm_wait_for_pair ready
    case $rpm_lane in
        alpha) rpm_other_lane=beta ;;
        beta) rpm_other_lane=alpha ;;
    esac
    IFS= read -r rpm_other_topdir \
        <"$AR11_RPM_STATE/concurrent.$rpm_other_lane.observed" ||
        rpm_die "cannot read the other build's private topdir"
    [ "$rpm_other_topdir" != "$rpm_topdir" ] ||
        rpm_die "concurrent builds received the same _topdir"
    [ -d "$rpm_other_topdir" ] && [ ! -L "$rpm_other_topdir" ] ||
        rpm_die "other private topdir did not coexist at the barrier"
    printf '%s\n' "$rpm_other_topdir" \
        >"$AR11_RPM_STATE/$rpm_lane.checked" ||
        rpm_die "cannot enter concurrent identity barrier"
    rpm_wait_for_pair checked
fi

rpm_binary_dir=$rpm_topdir/RPMS/noarch
mkdir -m 0700 "$rpm_binary_dir" || rpm_die "cannot create binary RPM directory"
rpm_binary_name=$rpm_package-$rpm_version-1.noarch.rpm
rpm_binary=$rpm_binary_dir/$rpm_binary_name
printf 'kind=binary\nlane=%s\nmode=%s\nsource=%s\nspec=%s\n' \
    "$rpm_lane" "$AR11_RPM_MODE" "$rpm_source_hash" "$rpm_spec_hash" \
    >"$rpm_binary" || rpm_die "cannot create causal binary RPM"
cp "$rpm_binary" \
    "$AR11_RPM_STATE/$AR11_RPM_MODE.$rpm_lane.binary.expected" ||
    rpm_die "cannot preserve expected binary RPM"

if [ "$AR11_RPM_MODE" = symlink-srpms ]; then
    rpm_escape_dir=$AR11_RPM_STATE/symlink-srpms.$rpm_lane.escape
    mkdir -m 0700 "$rpm_escape_dir" ||
        rpm_die "cannot create escaped SRPM directory"
    rm -rf "$rpm_topdir/SRPMS" || rpm_die "cannot replace private SRPMS"
    ln -s "$rpm_escape_dir" "$rpm_topdir/SRPMS" ||
        rpm_die "cannot substitute private SRPMS with a symlink"
fi
rpm_source_name=$rpm_package-$rpm_version-1.src.rpm
rpm_built_source=$rpm_topdir/SRPMS/$rpm_source_name
printf 'kind=source\nlane=%s\nmode=%s\nsource=%s\nspec=%s\n' \
    "$rpm_lane" "$AR11_RPM_MODE" "$rpm_source_hash" "$rpm_spec_hash" \
    >"$rpm_built_source" || rpm_die "cannot create causal source RPM"
cp "$rpm_built_source" \
    "$AR11_RPM_STATE/$AR11_RPM_MODE.$rpm_lane.source.expected" ||
    rpm_die "cannot preserve expected source RPM"
printf '%s\n' 'must not be published' >"$rpm_topdir/RPMS/ignored.txt" ||
    rpm_die "cannot create non-RPM output decoy"
EOF
    chmod 0700 "$rpm_shims/rpmbuild" ||
        fail "cannot activate private-rpmbuild shim"

    rpm_assert_private_retirement()
    {
        rpm_retirement_path=$1
        rpm_retirement_out=$2
        case $copy_platform in
            FreeBSD)
                [ ! -e "$rpm_retirement_path" ] &&
                [ ! -L "$rpm_retirement_path" ] ||
                    fail "FreeBSD RPM target retained a descriptor-retirable namespace"
                if grep -F 'private RPM namespace safely retained:' \
                    "$rpm_retirement_out" >/dev/null 2>&1; then
                    fail "FreeBSD RPM target reported unsupported retirement"
                fi
                ;;
            Linux|Darwin)
                [ -d "$rpm_retirement_path" ] &&
                [ ! -L "$rpm_retirement_path" ] ||
                    fail "RPM target lost its safely retained private namespace"
                [ "${rpm_retirement_path%/*}" = "$rpm_home" ] ||
                    fail "RPM target retained a namespace outside fixture HOME"
                rpm_retirement_name=${rpm_retirement_path##*/}
                case $rpm_retirement_name in
                    .gitswitch-rpmbuild.??????) ;;
                    *) fail "RPM target retained an unbounded namespace name" ;;
                esac
                rpm_retirement_suffix=${rpm_retirement_name#.gitswitch-rpmbuild.}
                case $rpm_retirement_suffix in
                    *[!A-Za-z0-9]*)
                        fail "RPM target retained an unsafe namespace suffix"
                        ;;
                esac
                [ "$(CDPATH='' cd "$rpm_retirement_path" && pwd -P)" = \
                    "$rpm_retirement_path" ] ||
                    fail "RPM target retained a nonphysical namespace"
                [ "$(find "$rpm_retirement_path" -prune -type d -perm 0700 \
                    -print 2>/dev/null)" = "$rpm_retirement_path" ] ||
                    fail "RPM target retained a namespace without exact mode 0700"
                grep -F 'private RPM namespace safely retained:' \
                    "$rpm_retirement_out" >/dev/null ||
                    fail "RPM target silently retained its private namespace"
                grep -F 'release-rpm: WARNING: private namespace safely retained' \
                    "$rpm_retirement_out" >/dev/null ||
                    fail "RPM workflow hid its retained-namespace disposition"
                # Linux and Darwin cannot condition removal on the open vnode.
                # The isolated test owns this exact HOME and removes the
                # already-validated residue only after the workflow returns.
                rm -rf "$rpm_retirement_path" ||
                    fail "cannot retire fixture-owned private RPM namespace"
                ;;
            *) fail "unsupported RPM retirement fixture platform" ;;
        esac
    }

    rpm_assert_no_private_residue()
    {
        rpm_residue_repo=$1
        for rpm_residue in \
            "$rpm_home"/.gitswitch-rpmbuild.* \
            "$rpm_residue_repo/build"/.rpmbuild.* \
            "$rpm_residue_repo/build"/.rpm-publish.*; do
            [ ! -e "$rpm_residue" ] && [ ! -L "$rpm_residue" ] ||
                fail "RPM target retained private residue: $rpm_residue"
        done
    }

    rpm_inspect_leaf_residue()
    {
        rpm_residue_final=$1
        rpm_residue_expected=$2
        rpm_residue_dir=${rpm_residue_final%/*}
        rpm_residue_name=${rpm_residue_final##*/}
        set -- "$rpm_residue_dir/.$rpm_residue_name.tmp."*
        if [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; then
            return
        fi
        [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ] ||
            fail "RPM publisher left an unexpected private leaf residue"
        cmp -s "$rpm_residue_expected" "$1" ||
            fail "retained RPM publisher residue changed bytes"
        # Descriptor retirement is preferred.  A platform that cannot unlink
        # the still-open private name may retain this one byte-identical source;
        # the isolated fixture owns the directory and retires it after proof.
        rm -f "$1" || fail "cannot retire inspected RPM publisher residue"
    }

    rpm_assert_publication()
    {
        rpm_assert_repo=$1
        rpm_assert_lane=$2
        rpm_assert_mode=$3
        rpm_assert_output=$rpm_assert_repo/build/dist
        rpm_assert_binary=gitswitcher-$rpm_fixture_version-1.noarch.rpm
        rpm_assert_source=gitswitcher-$rpm_fixture_version-1.src.rpm
        [ -d "$rpm_assert_output" ] && [ ! -L "$rpm_assert_output" ] ||
            fail "$rpm_assert_lane RPM publication is not a real directory"
        set -- "$rpm_assert_output"/*.rpm
        [ "$#" -eq 2 ] ||
            fail "$rpm_assert_lane RPM publication did not contain exactly two outputs"
        for rpm_assert_file do
            [ -f "$rpm_assert_file" ] && [ ! -L "$rpm_assert_file" ] ||
                fail "$rpm_assert_lane RPM publication contains a non-regular output"
            [ "$(find "$rpm_assert_file" -prune -type f -perm 0444 \
                -print 2>/dev/null)" = "$rpm_assert_file" ] ||
                fail "$rpm_assert_lane published an RPM without mode 0444"
        done
        cmp -s "$rpm_assert_output/$rpm_assert_binary" \
            "$rpm_state/$rpm_assert_mode.$rpm_assert_lane.binary.expected" ||
            fail "$rpm_assert_lane published another build's binary RPM"
        cmp -s "$rpm_assert_output/$rpm_assert_source" \
            "$rpm_state/$rpm_assert_mode.$rpm_assert_lane.source.expected" ||
            fail "$rpm_assert_lane published another build's source RPM"
        rpm_inspect_leaf_residue "$rpm_assert_output/$rpm_assert_binary" \
            "$rpm_state/$rpm_assert_mode.$rpm_assert_lane.binary.expected"
        rpm_inspect_leaf_residue "$rpm_assert_output/$rpm_assert_source" \
            "$rpm_state/$rpm_assert_mode.$rpm_assert_lane.source.expected"
        [ ! -e "$rpm_assert_repo/build/rpm" ] &&
        [ ! -L "$rpm_assert_repo/build/rpm" ] ||
            fail "$rpm_assert_lane escaped the canonical build/dist namespace"
    }

    rpm_alpha_out=$rpm_fixture/alpha.out
    rpm_beta_out=$rpm_fixture/beta.out
    (
        HOME="$rpm_home" PATH="$rpm_shims:$PATH" \
        AR11_RPM_STATE="$rpm_state" AR11_RPM_MODE=concurrent \
        AR11_RPM_HOME="$rpm_home" \
        AR11_RPM_REPO_ROOT="$rpm_alpha_root" \
            "$make_cmd" -C "$rpm_alpha_repo" rpm \
            >"$rpm_alpha_out" 2>&1
    ) &
    rpm_alpha_pid=$!
    (
        HOME="$rpm_home" PATH="$rpm_shims:$PATH" \
        AR11_RPM_STATE="$rpm_state" AR11_RPM_MODE=concurrent \
        AR11_RPM_HOME="$rpm_home" \
        AR11_RPM_REPO_ROOT="$rpm_beta_root" \
            "$make_cmd" -C "$rpm_beta_repo" rpm \
            >"$rpm_beta_out" 2>&1
    ) &
    rpm_beta_pid=$!
    rpm_alpha_status=0
    wait "$rpm_alpha_pid" || rpm_alpha_status=$?
    rpm_alpha_pid=
    if [ "$rpm_alpha_status" -ne 0 ]; then
        sed -n '1,240p' "$rpm_alpha_out" >&2
        sed -n '1,240p' "$rpm_beta_out" >&2
        fail "alpha concurrent RPM build failed"
    fi
    rpm_beta_status=0
    wait "$rpm_beta_pid" || rpm_beta_status=$?
    rpm_beta_pid=
    if [ "$rpm_beta_status" -ne 0 ]; then
        sed -n '1,240p' "$rpm_alpha_out" >&2
        sed -n '1,240p' "$rpm_beta_out" >&2
        fail "beta concurrent RPM build failed"
    fi

    for rpm_barrier_lane in alpha beta; do
        [ -f "$rpm_state/$rpm_barrier_lane.ready" ] &&
        [ -f "$rpm_state/$rpm_barrier_lane.checked" ] ||
            fail "$rpm_barrier_lane build did not cross both concurrency barriers"
    done
    rpm_alpha_report=$rpm_state/concurrent.alpha.observed
    rpm_beta_report=$rpm_state/concurrent.beta.observed
    rpm_alpha_topdir=$(sed -n '1p' "$rpm_alpha_report")
    rpm_beta_topdir=$(sed -n '1p' "$rpm_beta_report")
    [ -n "$rpm_alpha_topdir" ] && [ -n "$rpm_beta_topdir" ] &&
    [ "$rpm_alpha_topdir" != "$rpm_beta_topdir" ] ||
        fail "concurrent RPM builds did not record distinct private topdirs"
    rpm_assert_private_retirement "$rpm_alpha_topdir" "$rpm_alpha_out"
    rpm_assert_private_retirement "$rpm_beta_topdir" "$rpm_beta_out"
    rpm_alpha_archive=$rpm_alpha_repo/build/dist/gitswitcher-$rpm_fixture_version.tar.gz
    rpm_beta_archive=$rpm_beta_repo/build/dist/gitswitcher-$rpm_fixture_version.tar.gz
    rpm_alpha_source_hash=$(sed -n '2p' "$rpm_alpha_report")
    rpm_beta_source_hash=$(sed -n '2p' "$rpm_beta_report")
    [ "$rpm_alpha_source_hash" = "$(git hash-object "$rpm_alpha_archive")" ] &&
    [ "$rpm_beta_source_hash" = "$(git hash-object "$rpm_beta_archive")" ] ||
        fail "private RPM Source0 hash did not match its checkout archive"
    [ "$rpm_alpha_source_hash" != "$rpm_beta_source_hash" ] ||
        fail "concurrent RPM fixture source archives are not byte-distinct"
    [ "$(sed -n '3p' "$rpm_alpha_report")" = "$rpm_alpha_spec_hash" ] &&
    [ "$(sed -n '3p' "$rpm_beta_report")" = "$rpm_beta_spec_hash" ] ||
        fail "private RPM spec hash did not match its checkout spec"
    rpm_assert_publication "$rpm_alpha_repo" alpha concurrent
    rpm_assert_publication "$rpm_beta_repo" beta concurrent
    rpm_assert_no_private_residue "$rpm_alpha_repo"
    rpm_assert_no_private_residue "$rpm_beta_repo"
    cmp -s "$rpm_alpha_repo/build/dist/gitswitcher-$rpm_fixture_version-1.noarch.rpm" \
        "$rpm_beta_repo/build/dist/gitswitcher-$rpm_fixture_version-1.noarch.rpm" &&
        fail "concurrent RPM publications lost their causal input identity"
    inspect_dist_residue "$rpm_alpha_archive" "$copy_platform"
    inspect_dist_residue "$rpm_beta_archive" "$copy_platform"

    rpm_beta_git_dir=$(git -C "$rpm_beta_repo" rev-parse \
        --absolute-git-dir) ||
        fail "cannot resolve beta RPM fixture Git directory"
    rpm_beta_publisher=$rpm_beta_git_dir/gitswitch-release-tools/release-publish
    [ -x "$rpm_beta_publisher" ] && [ -f "$rpm_beta_publisher" ] &&
    [ ! -L "$rpm_beta_publisher" ] ||
        fail "beta RPM fixture lacks its production release publisher"
    rpm_beta_named_publisher=$rpm_beta_git_dir/gitswitch-release-tools/release-publish-named-test
    [ -x "$rpm_beta_named_publisher" ] &&
    [ -f "$rpm_beta_named_publisher" ] &&
    [ ! -L "$rpm_beta_named_publisher" ] ||
        fail "beta RPM fixture lacks its named-test release publisher"
    rpm_helper=$rpm_beta_repo/tools/release_rpm.sh
    [ -f "$rpm_helper" ] && [ ! -L "$rpm_helper" ] ||
        fail "RPM release helper is unavailable to direct fixtures"
    rpm_archive_name=gitswitcher-$rpm_fixture_version.tar.gz
    rpm_fixture_dist_root=gitswitcher-$rpm_fixture_version
    rpm_binary_name=gitswitcher-$rpm_fixture_version-1.noarch.rpm
    rpm_source_name=gitswitcher-$rpm_fixture_version-1.src.rpm

    # A wrong generation must not begin a partial walk. FreeBSD can condition
    # recursive removal on an open vnode; Linux and Darwin deliberately retain
    # the complete tree because pathname unlink cannot reject a post-proof
    # same-UID substitution.
    rpm_retire_tree=$rpm_home/.gitswitch-rpmbuild.Ret123
    rpm_retire_nested=$rpm_retire_tree/nested
    rpm_retire_external=$rpm_state/retire-external.sentinel
    rpm_retire_wrong_out=$rpm_fixture/retire-wrong.out
    rpm_retire_exact_out=$rpm_fixture/retire-exact.out
    mkdir -m 0700 "$rpm_retire_tree" ||
        fail "cannot create private RPM retirement fixture"
    mkdir -m 0700 "$rpm_retire_nested" ||
        fail "cannot create nested RPM retirement fixture"
    printf '%s\n' 'private nested retirement data' \
        >"$rpm_retire_nested/data" ||
        fail "cannot create nested RPM retirement data"
    cp "$rpm_retire_nested/data" "$rpm_fixture/retire-data.expected" ||
        fail "cannot preserve nested RPM retirement data"
    printf '%s\n' 'external retirement sentinel' >"$rpm_retire_external" ||
        fail "cannot create external RPM retirement sentinel"
    cp "$rpm_retire_external" "$rpm_fixture/retire-external.expected" ||
        fail "cannot preserve external RPM retirement sentinel"
    ln -s "$rpm_retire_external" "$rpm_retire_nested/external-link" ||
        fail "cannot link private RPM tree to external sentinel"
    case $copy_platform in
        Darwin|FreeBSD)
            rpm_retire_identity=$(stat -f '%d:%i' "$rpm_retire_tree") ||
                fail "cannot identify private RPM retirement fixture"
            ;;
        *)
            rpm_retire_identity=$(stat -c '%d:%i' "$rpm_retire_tree") ||
                fail "cannot identify private RPM retirement fixture"
            ;;
    esac
    rpm_retire_device=${rpm_retire_identity%%:*}
    rpm_retire_inode=${rpm_retire_identity#*:}
    if [ "$rpm_retire_inode" -gt 0 ]; then
        rpm_retire_wrong_inode=$((rpm_retire_inode - 1))
    else
        rpm_retire_wrong_inode=1
    fi
    if "$rpm_beta_publisher" --internal-retire-tree-v1 \
        "$rpm_home" "${rpm_retire_tree##*/}" \
        "$rpm_retire_device" "$rpm_retire_wrong_inode" \
        >"$rpm_retire_wrong_out" 2>&1; then
        fail "RPM retirement accepted the wrong directory generation"
    fi
    case $copy_platform in
        Darwin|FreeBSD)
            rpm_retire_after=$(stat -f '%d:%i' "$rpm_retire_tree") ||
                fail "wrong-generation retirement removed its directory"
            ;;
        *)
            rpm_retire_after=$(stat -c '%d:%i' "$rpm_retire_tree") ||
                fail "wrong-generation retirement removed its directory"
            ;;
    esac
    [ "$rpm_retire_after" = "$rpm_retire_identity" ] ||
        fail "wrong-generation retirement replaced the private directory"
    cmp -s "$rpm_retire_nested/data" "$rpm_fixture/retire-data.expected" ||
        fail "wrong-generation retirement changed nested private data"
    [ -L "$rpm_retire_nested/external-link" ] &&
    [ "$(readlink "$rpm_retire_nested/external-link")" = \
        "$rpm_retire_external" ] ||
        fail "wrong-generation retirement changed the external symlink"
    cmp -s "$rpm_retire_external" "$rpm_fixture/retire-external.expected" ||
        fail "wrong-generation retirement changed the external target"
    if "$rpm_beta_publisher" --internal-retire-tree-v1 \
        "$rpm_home" "${rpm_retire_tree##*/}" \
        "$rpm_retire_device" "$rpm_retire_inode" \
        >"$rpm_retire_exact_out" 2>&1; then
        rpm_retire_status=0
    else
        rpm_retire_status=$?
    fi
    case $copy_platform in
        FreeBSD)
            [ "$rpm_retire_status" -eq 0 ] || {
                sed -n '1,160p' "$rpm_retire_exact_out" >&2
                fail "FreeBSD matching-generation RPM retirement failed"
            }
            [ ! -e "$rpm_retire_tree" ] && [ ! -L "$rpm_retire_tree" ] ||
                fail "FreeBSD matching-generation retirement retained its namespace"
            ;;
        Linux|Darwin)
            [ "$rpm_retire_status" -eq 2 ] || {
                sed -n '1,160p' "$rpm_retire_exact_out" >&2
                fail "unsupported descriptor retirement lacked retained status"
            }
            [ -d "$rpm_retire_tree" ] && [ ! -L "$rpm_retire_tree" ] ||
                fail "unsupported descriptor retirement removed its namespace"
            case $copy_platform in
                Darwin)
                    rpm_retire_after=$(stat -f '%d:%i' "$rpm_retire_tree") ||
                        fail "cannot re-identify retained RPM namespace"
                    ;;
                *)
                    rpm_retire_after=$(stat -c '%d:%i' "$rpm_retire_tree") ||
                        fail "cannot re-identify retained RPM namespace"
                    ;;
            esac
            [ "$rpm_retire_after" = "$rpm_retire_identity" ] ||
                fail "unsupported retirement replaced the private namespace"
            cmp -s "$rpm_retire_nested/data" \
                "$rpm_fixture/retire-data.expected" ||
                fail "unsupported retirement partially removed nested data"
            [ -L "$rpm_retire_nested/external-link" ] ||
                fail "unsupported retirement partially removed a symlink"
            grep -F 'private RPM namespace safely retained:' \
                "$rpm_retire_exact_out" >/dev/null ||
                fail "unsupported retirement silently retained its namespace"
            rm -rf "$rpm_retire_tree" ||
                fail "cannot remove fixture-owned retained RPM namespace"
            ;;
    esac
    cmp -s "$rpm_retire_external" "$rpm_fixture/retire-external.expected" ||
        fail "matching-generation RPM retirement followed the external symlink"

    # Pause at the helper's final retirement boundary. A same-UID writer then
    # swaps in an empty replacement that the old pathname-only rmdir deleted.
    # The supported outcomes are descriptor-conditioned refusal on FreeBSD and
    # pre-mutation safe retention on Linux/Darwin; neither may delete the
    # replacement.
    rpm_retire_race_tree=$rpm_home/.gitswitch-rpmbuild.Rac123
    rpm_retire_race_original=$rpm_home/.gitswitch-rpmbuild.Rac123.original
    rpm_retire_race_nested=$rpm_retire_race_tree/nested
    rpm_retire_race_marker=$rpm_fixture/retire-race.marker
    rpm_retire_race_release=$rpm_fixture/retire-race.release
    rpm_retire_race_out=$rpm_fixture/retire-race.out
    mkdir -m 0700 "$rpm_retire_race_tree" \
        "$rpm_retire_race_nested" ||
        fail "cannot create RPM retirement-race fixture"
    printf '%s\n' 'retirement race private data' \
        >"$rpm_retire_race_nested/data" ||
        fail "cannot seed RPM retirement-race fixture"
    cp "$rpm_retire_race_nested/data" \
        "$rpm_fixture/retire-race.expected" ||
        fail "cannot preserve RPM retirement-race data"
    case $copy_platform in
        Darwin|FreeBSD)
            rpm_retire_race_identity=$(stat -f '%d:%i' \
                "$rpm_retire_race_tree") ||
                fail "cannot identify RPM retirement-race fixture"
            ;;
        *)
            rpm_retire_race_identity=$(stat -c '%d:%i' \
                "$rpm_retire_race_tree") ||
                fail "cannot identify RPM retirement-race fixture"
            ;;
    esac
    rpm_retire_race_device=${rpm_retire_race_identity%%:*}
    rpm_retire_race_inode=${rpm_retire_race_identity#*:}
    GITSWITCH_RELEASE_TEST_CLEANUP_MARKER=$rpm_retire_race_marker \
    GITSWITCH_RELEASE_TEST_CLEANUP_RELEASE=$rpm_retire_race_release \
        "$rpm_beta_named_publisher" --internal-retire-tree-v1 \
        "$rpm_home" "${rpm_retire_race_tree##*/}" \
        "$rpm_retire_race_device" "$rpm_retire_race_inode" \
        >"$rpm_retire_race_out" 2>&1 &
    rpm_retire_pid=$!
    rpm_retire_wait=0
    while [ ! -e "$rpm_retire_race_marker" ] &&
          kill -0 "$rpm_retire_pid" 2>/dev/null &&
          [ "$rpm_retire_wait" -lt 100 ]; do
        sleep 0.1
        rpm_retire_wait=$((rpm_retire_wait + 1))
    done
    [ -f "$rpm_retire_race_marker" ] || {
        sed -n '1,160p' "$rpm_retire_race_out" >&2
        fail "RPM retirement-race helper missed its final boundary"
    }
    case $copy_platform in
        FreeBSD)
            [ ! -e "$rpm_retire_race_nested" ] &&
            [ ! -L "$rpm_retire_race_nested" ] ||
                fail "FreeBSD retirement race paused before recursive removal"
            ;;
        Linux|Darwin)
            cmp -s "$rpm_retire_race_nested/data" \
                "$rpm_fixture/retire-race.expected" ||
                fail "unsupported retirement mutated before safe retention"
            ;;
    esac
    mv "$rpm_retire_race_tree" "$rpm_retire_race_original" ||
        fail "cannot move the pinned RPM namespace generation"
    mkdir -m 0700 "$rpm_retire_race_tree" ||
        fail "cannot install replacement RPM namespace"
    case $copy_platform in
        Darwin|FreeBSD)
            rpm_retire_replacement_identity=$(stat -f '%d:%i' \
                "$rpm_retire_race_tree") ||
                fail "cannot identify replacement RPM namespace"
            ;;
        *)
            rpm_retire_replacement_identity=$(stat -c '%d:%i' \
                "$rpm_retire_race_tree") ||
                fail "cannot identify replacement RPM namespace"
            ;;
    esac
    [ "$rpm_retire_replacement_identity" != "$rpm_retire_race_identity" ] ||
        fail "RPM retirement race reused the pinned generation"
    : >"$rpm_retire_race_release" ||
        fail "cannot release RPM retirement-race helper"
    if wait "$rpm_retire_pid"; then
        rpm_retire_race_status=0
    else
        rpm_retire_race_status=$?
    fi
    rpm_retire_pid=
    [ "$rpm_retire_race_status" -ne 0 ] ||
        fail "RPM retirement accepted a post-proof replacement"
    grep -F 'final retirement boundary' "$rpm_retire_race_out" >/dev/null || {
        sed -n '1,160p' "$rpm_retire_race_out" >&2
        fail "RPM retirement race lacked a causal final-boundary diagnostic"
    }
    case $copy_platform in
        Darwin|FreeBSD)
            rpm_retire_replacement_after=$(stat -f '%d:%i' \
                "$rpm_retire_race_tree") ||
                fail "RPM retirement deleted its replacement"
            rpm_retire_original_after=$(stat -f '%d:%i' \
                "$rpm_retire_race_original") ||
                fail "RPM retirement deleted its pinned generation"
            ;;
        *)
            rpm_retire_replacement_after=$(stat -c '%d:%i' \
                "$rpm_retire_race_tree") ||
                fail "RPM retirement deleted its replacement"
            rpm_retire_original_after=$(stat -c '%d:%i' \
                "$rpm_retire_race_original") ||
                fail "RPM retirement deleted its pinned generation"
            ;;
    esac
    [ "$rpm_retire_replacement_after" = \
        "$rpm_retire_replacement_identity" ] ||
        fail "RPM retirement replaced the post-proof substitution"
    [ "$rpm_retire_original_after" = "$rpm_retire_race_identity" ] ||
        fail "RPM retirement changed the pinned generation identity"
    [ -z "$(find "$rpm_retire_race_tree" -mindepth 1 -print -quit)" ] ||
        fail "replacement RPM namespace was not the empty race object"
    case $copy_platform in
        FreeBSD)
            [ -z "$(find "$rpm_retire_race_original" -mindepth 1 \
                -print -quit)" ] ||
                fail "FreeBSD pinned namespace was not recursively retired"
            rmdir "$rpm_retire_race_original" ||
                fail "cannot remove fixture-owned retired namespace"
            ;;
        Linux|Darwin)
            cmp -s "$rpm_retire_race_original/nested/data" \
                "$rpm_fixture/retire-race.expected" ||
                fail "unsupported retirement partially changed pinned data"
            rm -rf "$rpm_retire_race_original" ||
                fail "cannot remove fixture-owned retained generation"
            ;;
    esac
    rmdir "$rpm_retire_race_tree" ||
        fail "cannot remove fixture-owned replacement namespace"

    # HOME is transported as data into mktemp and then into RPM macro values.
    # An otherwise exact physical HOME containing RPM expansion syntax must be
    # rejected before mktemp or rpmbuild can interpret it.  A dedicated command
    # marker and exact directory-shape proof distinguish that boundary from a
    # later build failure.
    rpm_invalid_home=$rpm_fixture/"literal %{_tmppath} \$home"
    rpm_invalid_shims=$rpm_fixture/invalid-home-shims
    rpm_invalid_marker=$rpm_fixture/invalid-home-rpmbuild.marker
    rpm_invalid_mktemp_marker=$rpm_fixture/invalid-home-mktemp.marker
    rpm_invalid_out=$rpm_fixture/invalid-home.out
    mkdir -p "$rpm_invalid_home" "$rpm_invalid_shims" ||
        fail "cannot create literal-macro HOME fixture"
    rpm_invalid_home=$(CDPATH='' cd "$rpm_invalid_home" && pwd -P) ||
        fail "cannot resolve literal-macro HOME fixture"
    printf '%s\n' 'literal-macro HOME sentinel' \
        >"$rpm_invalid_home/sentinel" ||
        fail "cannot seed literal-macro HOME fixture"
    printf '%s\n' "$rpm_invalid_marker" \
        >"$rpm_invalid_shims/marker-path" ||
        fail "cannot record invalid-HOME rpmbuild marker"
    printf '%s\n' "$rpm_invalid_mktemp_marker" \
        >"$rpm_invalid_shims/mktemp-marker-path" ||
        fail "cannot record invalid-HOME mktemp marker"
    cat >"$rpm_invalid_shims/rpmbuild" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r marker <"$shim_dir/marker-path" || exit 96
: >"$marker" || exit 95
exit 94
EOF
    chmod 0700 "$rpm_invalid_shims/rpmbuild" ||
        fail "cannot activate invalid-HOME rpmbuild marker"
    cat >"$rpm_invalid_shims/mktemp" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r marker <"$shim_dir/mktemp-marker-path" || exit 96
: >"$marker" || exit 95
exit 93
EOF
    chmod 0700 "$rpm_invalid_shims/mktemp" ||
        fail "cannot activate invalid-HOME mktemp marker"
    if HOME="$rpm_invalid_home" PATH="$rpm_invalid_shims:$PATH" \
        sh "$rpm_helper" "$rpm_beta_root" "$rpm_beta_archive" \
        "$rpm_archive_name" "$rpm_fixture_dist_root" gitswitcher \
        "$rpm_beta_publisher" >"$rpm_invalid_out" 2>&1; then
        fail "RPM helper accepted HOME containing literal RPM macro syntax"
    fi
    grep -E 'HOME.*(RPM|macro)' "$rpm_invalid_out" >/dev/null || {
        sed -n '1,160p' "$rpm_invalid_out" >&2
        fail "literal-macro HOME rejection lacked a causal diagnostic"
    }
    [ ! -e "$rpm_invalid_marker" ] && [ ! -L "$rpm_invalid_marker" ] ||
        fail "literal-macro HOME reached rpmbuild"
    [ ! -e "$rpm_invalid_mktemp_marker" ] &&
    [ ! -L "$rpm_invalid_mktemp_marker" ] ||
        fail "literal-macro HOME reached mktemp"
    for rpm_invalid_residue in \
        "$rpm_invalid_home"/.gitswitch-rpmbuild.*; do
        [ ! -e "$rpm_invalid_residue" ] && [ ! -L "$rpm_invalid_residue" ] ||
            fail "literal-macro HOME created a private RPM namespace"
    done
    set -- "$rpm_invalid_home"/*
    [ "$#" -eq 1 ] && [ "$1" = "$rpm_invalid_home/sentinel" ] ||
        fail "literal-macro HOME rejection left unexpected residue"

    rpm_assert_incomplete_set()
    {
        rpm_incomplete_log=$1
        if ! grep -F 'RPM set publication is incomplete' \
            "$rpm_incomplete_log" >/dev/null; then
            sed -n '1,200p' "$rpm_incomplete_log" >&2
            fail "partial RPM publication lacked explicit recovery guidance"
        fi
        if ! grep -E 'inspect and remove only .*exact no-replace outputs' \
            "$rpm_incomplete_log" >/dev/null; then
            sed -n '1,200p' "$rpm_incomplete_log" >&2
            fail "partial RPM publication lacked exact cleanup guidance"
        fi
        for rpm_incomplete_name in "$rpm_binary_name" "$rpm_source_name"; do
            grep -F "build/dist/$rpm_incomplete_name" \
                "$rpm_incomplete_log" >/dev/null || {
                sed -n '1,200p' "$rpm_incomplete_log" >&2
                fail "partial RPM diagnostic omitted $rpm_incomplete_name"
            }
        done
    }

    # The publisher may report failure only after an earlier leaf has become
    # canonical, so automatic replacement/resume is unsafe.  Fail the wrapper
    # before its second call: the helper must enumerate the complete intended
    # set, retain the byte-exact first leaf, reject an immediate retry without
    # changing its inode, and succeed only after this isolated owner removes
    # both explicitly named leaves.
    rpm_beta_binary=$rpm_beta_repo/build/dist/$rpm_binary_name
    rpm_beta_source=$rpm_beta_repo/build/dist/$rpm_source_name
    rm -f "$rpm_beta_binary" "$rpm_beta_source" ||
        fail "cannot reset beta RPM leaves for partial-publication fixture"
    rpm_partial_publisher=$rpm_shims/partial-publisher
    rpm_partial_calls=$rpm_state/partial-publisher.calls
    rpm_partial_count=$rpm_state/partial-publisher.count
    cat >"$rpm_partial_publisher" <<'EOF'
#!/bin/sh
set -u
: "${AR11_RPM_REAL_PUBLISHER:?}"
: "${AR11_RPM_PUBLISH_CALLS:?}"
: "${AR11_RPM_PUBLISH_COUNT:?}"
if [ "${1-}" = --internal-retire-tree-v1 ]; then
    exec "$AR11_RPM_REAL_PUBLISHER" "$@"
fi
[ "${1-}" = --internal-release-tree-v1 ] || exit 93
partial_count=0
if [ -f "$AR11_RPM_PUBLISH_COUNT" ]; then
    IFS= read -r partial_count <"$AR11_RPM_PUBLISH_COUNT" || exit 96
fi
partial_count=$((partial_count + 1))
printf '%s\n' "$partial_count" >"$AR11_RPM_PUBLISH_COUNT" || exit 95
printf '%s\n' "${5-}" >>"$AR11_RPM_PUBLISH_CALLS" || exit 94
if [ "$partial_count" -eq 2 ]; then
    printf '%s\n' 'injected second RPM publication failure' >&2
    exit 75
fi
exec "$AR11_RPM_REAL_PUBLISHER" "$@"
EOF
    chmod 0700 "$rpm_partial_publisher" ||
        fail "cannot activate partial RPM publisher"
    rpm_partial_out=$rpm_fixture/partial-publication.out
    if HOME="$rpm_home" PATH="$rpm_shims:$PATH" \
        AR11_RPM_STATE="$rpm_state" AR11_RPM_MODE=partial \
        AR11_RPM_HOME="$rpm_home" AR11_RPM_REPO_ROOT="$rpm_beta_root" \
        AR11_RPM_REAL_PUBLISHER="$rpm_beta_publisher" \
        AR11_RPM_PUBLISH_CALLS="$rpm_partial_calls" \
        AR11_RPM_PUBLISH_COUNT="$rpm_partial_count" \
        sh "$rpm_helper" "$rpm_beta_root" "$rpm_beta_archive" \
        "$rpm_archive_name" "$rpm_fixture_dist_root" gitswitcher \
        "$rpm_partial_publisher" >"$rpm_partial_out" 2>&1; then
        fail "injected second-leaf RPM publication failure returned success"
    fi
    rpm_assert_incomplete_set "$rpm_partial_out"
    [ "$(sed -n '1p' "$rpm_partial_calls")" = "$rpm_binary_name" ] &&
    [ "$(sed -n '2p' "$rpm_partial_calls")" = "$rpm_source_name" ] &&
    [ "$(sed -n '3p' "$rpm_partial_calls")" = '' ] ||
        fail "partial publisher did not receive the exact ordered RPM set"
    cmp -s "$rpm_beta_binary" "$rpm_state/partial.beta.binary.expected" ||
        fail "partial publication did not retain the exact first RPM leaf"
    [ ! -e "$rpm_beta_source" ] && [ ! -L "$rpm_beta_source" ] ||
        fail "failed second publication exposed the second RPM leaf"
    [ "$(find "$rpm_beta_binary" -prune -type f -perm 0444 \
        -print 2>/dev/null)" = "$rpm_beta_binary" ] ||
        fail "retained first RPM leaf is not sealed mode 0444"
    rpm_partial_topdir=$(sed -n '1p' "$rpm_state/partial.beta.observed")
    [ -n "$rpm_partial_topdir" ] ||
        fail "partial RPM publication omitted its private topdir"
    rpm_assert_private_retirement "$rpm_partial_topdir" "$rpm_partial_out"
    rpm_assert_no_private_residue "$rpm_beta_repo"
    rpm_inspect_leaf_residue "$rpm_beta_binary" \
        "$rpm_state/partial.beta.binary.expected"
    case $copy_platform in
        Darwin|FreeBSD)
            rpm_partial_identity=$(stat -f '%d:%i' "$rpm_beta_binary") ||
                fail "cannot identify retained first RPM leaf"
            ;;
        *)
            rpm_partial_identity=$(stat -c '%d:%i' "$rpm_beta_binary") ||
                fail "cannot identify retained first RPM leaf"
            ;;
    esac

    rpm_blocked_retry_out=$rpm_fixture/partial-retry-blocked.out
    if HOME="$rpm_home" PATH="$rpm_shims:$PATH" \
        AR11_RPM_STATE="$rpm_state" AR11_RPM_MODE=partial-retry \
        AR11_RPM_HOME="$rpm_home" AR11_RPM_REPO_ROOT="$rpm_beta_root" \
        sh "$rpm_helper" "$rpm_beta_root" "$rpm_beta_archive" \
        "$rpm_archive_name" "$rpm_fixture_dist_root" gitswitcher \
        "$rpm_beta_publisher" >"$rpm_blocked_retry_out" 2>&1; then
        fail "RPM helper auto-resumed an incomplete publication set"
    fi
    rpm_assert_incomplete_set "$rpm_blocked_retry_out"
    cmp -s "$rpm_beta_binary" "$rpm_state/partial.beta.binary.expected" ||
        fail "blocked RPM retry replaced the retained first leaf"
    case $copy_platform in
        Darwin|FreeBSD)
            rpm_blocked_identity=$(stat -f '%d:%i' "$rpm_beta_binary") ||
                fail "cannot re-identify retained first RPM leaf"
            ;;
        *)
            rpm_blocked_identity=$(stat -c '%d:%i' "$rpm_beta_binary") ||
                fail "cannot re-identify retained first RPM leaf"
            ;;
    esac
    [ "$rpm_blocked_identity" = "$rpm_partial_identity" ] ||
        fail "blocked RPM retry replaced the retained leaf inode"
    [ ! -e "$rpm_beta_source" ] && [ ! -L "$rpm_beta_source" ] ||
        fail "blocked RPM retry published the missing second leaf"
    rpm_blocked_topdir=$(sed -n '1p' \
        "$rpm_state/partial-retry.beta.observed")
    [ -n "$rpm_blocked_topdir" ] ||
        fail "blocked RPM retry omitted its private topdir"
    rpm_assert_private_retirement "$rpm_blocked_topdir" \
        "$rpm_blocked_retry_out"
    rpm_assert_no_private_residue "$rpm_beta_repo"

    rm -f "$rpm_beta_binary" ||
        fail "cannot replace retained RPM with mismatch sentinel"
    printf '%s\n' 'foreign mismatched RPM leaf' >"$rpm_beta_binary" ||
        fail "cannot create mismatched RPM sentinel"
    chmod 0444 "$rpm_beta_binary" ||
        fail "cannot seal mismatched RPM sentinel"
    cp "$rpm_beta_binary" "$rpm_fixture/mismatched-rpm.expected" ||
        fail "cannot preserve mismatched RPM sentinel"
    case $copy_platform in
        Darwin|FreeBSD)
            rpm_mismatch_identity=$(stat -f '%d:%i' "$rpm_beta_binary") ||
                fail "cannot identify mismatched RPM sentinel"
            ;;
        *)
            rpm_mismatch_identity=$(stat -c '%d:%i' "$rpm_beta_binary") ||
                fail "cannot identify mismatched RPM sentinel"
            ;;
    esac
    rpm_mismatch_out=$rpm_fixture/partial-retry-mismatch.out
    if HOME="$rpm_home" PATH="$rpm_shims:$PATH" \
        AR11_RPM_STATE="$rpm_state" AR11_RPM_MODE=partial-mismatch \
        AR11_RPM_HOME="$rpm_home" AR11_RPM_REPO_ROOT="$rpm_beta_root" \
        sh "$rpm_helper" "$rpm_beta_root" "$rpm_beta_archive" \
        "$rpm_archive_name" "$rpm_fixture_dist_root" gitswitcher \
        "$rpm_beta_publisher" >"$rpm_mismatch_out" 2>&1; then
        fail "RPM helper replaced a mismatched incomplete-set leaf"
    fi
    rpm_assert_incomplete_set "$rpm_mismatch_out"
    cmp -s "$rpm_beta_binary" "$rpm_fixture/mismatched-rpm.expected" ||
        fail "mismatched RPM retry changed foreign bytes"
    case $copy_platform in
        Darwin|FreeBSD)
            rpm_mismatch_after=$(stat -f '%d:%i' "$rpm_beta_binary") ||
                fail "cannot re-identify mismatched RPM sentinel"
            ;;
        *)
            rpm_mismatch_after=$(stat -c '%d:%i' "$rpm_beta_binary") ||
                fail "cannot re-identify mismatched RPM sentinel"
            ;;
    esac
    [ "$rpm_mismatch_after" = "$rpm_mismatch_identity" ] ||
        fail "mismatched RPM retry replaced the foreign inode"
    [ ! -e "$rpm_beta_source" ] && [ ! -L "$rpm_beta_source" ] ||
        fail "mismatched RPM retry published the missing second leaf"
    rpm_mismatch_topdir=$(sed -n '1p' \
        "$rpm_state/partial-mismatch.beta.observed")
    [ -n "$rpm_mismatch_topdir" ] ||
        fail "mismatched RPM retry omitted its private topdir"
    rpm_assert_private_retirement "$rpm_mismatch_topdir" "$rpm_mismatch_out"
    rpm_assert_no_private_residue "$rpm_beta_repo"

    rm -f "$rpm_beta_binary" "$rpm_beta_source" ||
        fail "cannot perform explicit incomplete-set RPM cleanup"
    rpm_partial_final_out=$rpm_fixture/partial-retry-final.out
    HOME="$rpm_home" PATH="$rpm_shims:$PATH" \
    AR11_RPM_STATE="$rpm_state" AR11_RPM_MODE=partial-final \
    AR11_RPM_HOME="$rpm_home" AR11_RPM_REPO_ROOT="$rpm_beta_root" \
        sh "$rpm_helper" "$rpm_beta_root" "$rpm_beta_archive" \
        "$rpm_archive_name" "$rpm_fixture_dist_root" gitswitcher \
        "$rpm_beta_publisher" >"$rpm_partial_final_out" 2>&1 || {
        sed -n '1,240p' "$rpm_partial_final_out" >&2
        fail "explicitly cleaned RPM publication set did not retry"
    }
    rpm_assert_publication "$rpm_beta_repo" beta partial-final
    rpm_partial_final_topdir=$(sed -n '1p' \
        "$rpm_state/partial-final.beta.observed")
    [ -n "$rpm_partial_final_topdir" ] ||
        fail "completed partial-publication retry omitted its private topdir"
    rpm_assert_private_retirement "$rpm_partial_final_topdir" \
        "$rpm_partial_final_out"
    rpm_assert_no_private_residue "$rpm_beta_repo"

    # A hostile rpmbuild replaces SRPMS with a symlink after the recipe creates
    # and validates the private directory tree.  The binary is otherwise ready
    # to enter private PUBLISH staging, so the intermediate-directory identity
    # check must reject the build without exposing either output.  Cleanup and
    # retry must then use a fresh topdir and publish a complete set.
    rpm_binary_name=gitswitcher-$rpm_fixture_version-1.noarch.rpm
    rpm_source_name=gitswitcher-$rpm_fixture_version-1.src.rpm
    rm -f "$rpm_alpha_repo/build/dist/$rpm_binary_name" \
        "$rpm_alpha_repo/build/dist/$rpm_source_name" ||
        fail "cannot reset alpha public RPM outputs"
    rm -f "$rpm_alpha_archive" || fail "cannot reset alpha RPM archive"
    rpm_symlink_out=$rpm_fixture/symlink-srpms.out
    if HOME="$rpm_home" PATH="$rpm_shims:$PATH" \
        AR11_RPM_STATE="$rpm_state" AR11_RPM_MODE=symlink-srpms \
        AR11_RPM_HOME="$rpm_home" \
        AR11_RPM_REPO_ROOT="$rpm_alpha_root" \
        "$make_cmd" -C "$rpm_alpha_repo" rpm \
        >"$rpm_symlink_out" 2>&1; then
        fail "RPM target accepted a substituted private SRPMS directory"
    fi
    rpm_symlink_report=$rpm_state/symlink-srpms.alpha.observed
    [ -s "$rpm_symlink_report" ] || {
        sed -n '1,240p' "$rpm_symlink_out" >&2
        fail "SRPMS substitution fixture failed before rpmbuild"
    }
    [ -f "$rpm_state/archive-swap.marker" ] &&
    [ -f "$rpm_state/archive-swap.original" ] &&
    [ -f "$rpm_state/archive-swap.restored" ] ||
        fail "private-source fixture did not replace the canonical archive"
    cmp -s "$rpm_state/archive-swap.original" "$rpm_alpha_archive" ||
        fail "private-source fixture did not restore the canonical archive"
    rpm_symlink_topdir=$(sed -n '1p' "$rpm_symlink_report")
    [ -n "$rpm_symlink_topdir" ] ||
        fail "failed RPM build omitted its private topdir"
    rpm_assert_private_retirement "$rpm_symlink_topdir" "$rpm_symlink_out"
    [ ! -e "$rpm_alpha_repo/build/dist/$rpm_binary_name" ] &&
    [ ! -L "$rpm_alpha_repo/build/dist/$rpm_binary_name" ] &&
    [ ! -e "$rpm_alpha_repo/build/dist/$rpm_source_name" ] &&
    [ ! -L "$rpm_alpha_repo/build/dist/$rpm_source_name" ] ||
        fail "failed RPM build exposed a partial public RPM"
    rpm_escaped_source=$rpm_state/symlink-srpms.alpha.escape/$rpm_source_name
    cmp -s "$rpm_escaped_source" \
        "$rpm_state/symlink-srpms.alpha.source.expected" ||
        fail "failed RPM cleanup changed the escaped SRPM sentinel"
    rpm_assert_no_private_residue "$rpm_alpha_repo"
    inspect_dist_residue "$rpm_alpha_archive" "$copy_platform"

    mkdir -m 0700 "$rpm_symlink_topdir" ||
        fail "cannot reserve failed RPM topdir identity for retry"
    printf '%s\n' 'failed topdir identity sentinel' \
        >"$rpm_symlink_topdir/sentinel" ||
        fail "cannot mark failed RPM topdir identity"
    cp "$rpm_symlink_topdir/sentinel" \
        "$rpm_fixture/failed-topdir.expected" ||
        fail "cannot preserve failed-topdir sentinel"
    rm -f "$rpm_alpha_archive" || fail "cannot reset retry RPM archive"
    rpm_retry_out=$rpm_fixture/retry.out
    HOME="$rpm_home" PATH="$rpm_shims:$PATH" \
    AR11_RPM_STATE="$rpm_state" AR11_RPM_MODE=retry \
    AR11_RPM_HOME="$rpm_home" \
    AR11_RPM_REPO_ROOT="$rpm_alpha_root" \
        "$make_cmd" -C "$rpm_alpha_repo" rpm \
        >"$rpm_retry_out" 2>&1 || {
        sed -n '1,240p' "$rpm_retry_out" >&2
        fail "RPM retry after private validation failure failed"
    }
    rpm_retry_topdir=$(sed -n '1p' "$rpm_state/retry.alpha.observed")
    [ -n "$rpm_retry_topdir" ] &&
    [ "$rpm_retry_topdir" != "$rpm_symlink_topdir" ] ||
        fail "RPM retry reused the failed private topdir identity"
    cmp -s "$rpm_symlink_topdir/sentinel" \
        "$rpm_fixture/failed-topdir.expected" ||
        fail "RPM retry changed a caller-reserved old topdir identity"
    rpm_assert_private_retirement "$rpm_retry_topdir" "$rpm_retry_out"
    rm -rf "$rpm_symlink_topdir" ||
        fail "cannot remove failed-topdir retry sentinel"
    rpm_assert_publication "$rpm_alpha_repo" alpha retry
    rpm_assert_no_private_residue "$rpm_alpha_repo"
    inspect_dist_residue "$rpm_alpha_archive" "$copy_platform"
    cmp -s "$rpm_home/rpmbuild/sentinel" "$rpm_fixture/rpmbuild.expected" ||
        fail "RPM builds touched the caller's shared HOME/rpmbuild path"
    [ -d "$rpm_home/rpmbuild" ] && [ ! -L "$rpm_home/rpmbuild" ] ||
        fail "RPM builds replaced the caller's shared HOME/rpmbuild directory"
    set -- "$rpm_home/rpmbuild"/*
    [ "$#" -eq 1 ] && [ "$1" = "$rpm_home/rpmbuild/sentinel" ] ||
        fail "RPM builds populated the caller's shared HOME/rpmbuild directory"
    cmp -s "$rpm_home/.rpmmacros" "$rpm_fixture/rpmmacros.expected" ||
        fail "RPM builds changed the caller's hostile user macro file"
    [ ! -e "$rpm_poison" ] && [ ! -L "$rpm_poison" ] ||
        fail "user RPM macros redirected output outside the private topdir"

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
    printf '%s\n' "$real_git" >"$race_shims/real-git"
    printf '%s\n' "$race_marker" >"$race_shims/marker"
    printf '%s\n' "$race_repo/VERSION" >"$race_shims/target"
    cat >"$race_shims/git" <<'EOF'
#!/bin/sh
shim_dir=${0%/*}
IFS= read -r real_git <"$shim_dir/real-git" || exit 90
IFS= read -r marker <"$shim_dir/marker" || exit 91
IFS= read -r target <"$shim_dir/target" || exit 92
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
    printf '%s\n' invoked >>"$marker"
    swap_dir=
    if [ -f "$shim_dir/swap-dir" ]; then
        IFS= read -r swap_dir <"$shim_dir/swap-dir" || exit 93
    fi
    if [ -n "$swap_dir" ]; then
        mv "$swap_dir" "$swap_dir.pinned"
        mkdir "$swap_dir"
        rm -f "$shim_dir/swap-dir"
    fi
    if [ -n "$output" ]; then
        rm -f "$output"
        ln -s "$target" "$output"
    fi
fi
exec "$real_git" "$@"
EOF
    chmod 0700 "$race_shims/git"
    cp "$race_repo/VERSION" "$tmp/race.VERSION.before"
    cp "$race_repo/README.md" "$tmp/race.README.before"
    race_version=$(cat "$race_repo/VERSION")
    race_archive=$race_repo/build/dist/gitswitcher-$race_version.tar.gz
    PATH="$race_shims:$PATH" \
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
    printf '%s\n' "$race_repo/build/dist" >"$race_shims/swap-dir" ||
        fail "cannot arm distribution-directory substitution fixture"
    if PATH="$race_shims:$PATH" \
        "$make_cmd" -C "$race_repo" dist >"$out" 2>&1; then
        fail "distribution succeeded after its canonical directory was replaced"
    fi
    grep -F 'pinned release directory chain changed before durability barriers' \
        "$out" >/dev/null ||
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
