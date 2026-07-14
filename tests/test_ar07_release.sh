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
    cleanup()
    {
        status=$?
        trap - 0 1 2 3 15
        if [ -n "$copy_pid" ]; then
            kill "$copy_pid" 2>/dev/null || true
            wait "$copy_pid" 2>/dev/null || true
        fi
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
            ;;
        *)
            { [ "$#" -eq 1 ] && [ -f "$1" ]; } ||
                fail "named publication did not retain exactly one private source"
            copy_retained_temp=$1
            [ "$(cat "$copy_retained_temp")" = original-payload ] ||
                fail "retained named source changed payload"
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

    # AR-10 L30: the producer's own process group is the helper's lifetime
    # boundary, but it also removes the producer from the terminal foreground
    # group — a SIGTERM/SIGINT to the helper used to kill only the helper and
    # abandon the still-running producer group (which then wrote the marker).
    # The forwarding handler must take the group down with the helper.
    orphan_marker=$tmp/orphan.marker
    rm -f "$orphan_marker"
    # The spawned producer, not this parent shell, expands the marker.
    # shellcheck disable=SC2016
    AR10_ORPHAN_MARKER=$orphan_marker \
        "$named_publish_helper" "$copy_dir" "$copy_canonical" archive.tar.gz \
        -- /bin/sh -c 'printf partial; sleep 3; : >"$AR10_ORPHAN_MARKER"' \
        >"$out" 2>&1 &
    orphan_publisher=$!
    sleep 1
    kill -TERM "$orphan_publisher" 2>/dev/null || :
    orphan_status=0
    wait "$orphan_publisher" 2>/dev/null || orphan_status=$?
    [ "$orphan_status" -ge 128 ] ||
        fail "signalled publisher did not die by its forwarded signal"
    sleep 3
    [ ! -e "$orphan_marker" ] ||
        fail "signalled publisher abandoned its producer process group"
    rm -f "$copy_archive" "$copy_dir"/.archive.tar.gz.tmp.*

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

[ "$#" -ge 1 ] || fail "usage: $0 {manifest|artifact|neuter} ..."
mode=$1
shift
case $mode in
    manifest) check_manifest_contract "$@" ;;
    artifact) check_artifact_pair "$@" ;;
    neuter) check_neuter_contract "$@" ;;
    *) fail "unknown mode '$mode' (expected manifest, artifact, or neuter)" ;;
esac
