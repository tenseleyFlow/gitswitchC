#!/bin/sh
# AR-07 T19 / AR-11 M38: application and release-helper provenance gates.
# ShellCheck 0.9 misclassifies deliberate fail-closed assertion chains.
# shellcheck disable=SC2015

set -eu

fail()
{
    printf 'ar07-build: ERROR: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail "usage: $0 PROJECT_ROOT MAKE"
root=$1
make_cmd=$2

# GNU make 3.81 (the system Make on supported macOS runners) treats `#` inside
# $(shell ...) as a Make comment even when it belongs to a shell parameter such
# as $#. Keep the fingerprint block free of that parser hazard.
if sed -n '/^TOOLCHAIN_FILE_FINGERPRINT := /,/^CC_VERSION_ID := /p' \
    "$root/Makefile" | grep -F '$$#' >/dev/null; then
    fail "toolchain fingerprint uses a GNU make 3.81-incompatible shell count"
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-ar07-build.XXXXXX") ||
    fail "cannot create temporary directory"
host_build_pid=
gate_process_pid=
fifo_writer_pid=
release_done=
terminate_and_reap()
{
    terminate_pid=$1
    kill "$terminate_pid" 2>/dev/null || :
    terminate_tries=0
    while kill -0 "$terminate_pid" 2>/dev/null; do
        terminate_tries=$((terminate_tries + 1))
        if [ "$terminate_tries" -ge 40 ]; then
            kill -KILL "$terminate_pid" 2>/dev/null || :
            break
        fi
        sleep 0.05
    done
    wait "$terminate_pid" 2>/dev/null || :
}
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    if [ -n "$gate_process_pid" ] && [ -n "$release_done" ] &&
       [ -f "$release_done" ] &&
       grep -x '0' "$release_done" >/dev/null 2>&1; then
        gate_process_pid=
    fi
    if [ -n "$gate_process_pid" ]; then
        kill "$gate_process_pid" 2>/dev/null || true
    fi
    if [ -n "$fifo_writer_pid" ]; then
        terminate_and_reap "$fifo_writer_pid"
    fi
    if [ -n "$host_build_pid" ]; then
        terminate_and_reap "$host_build_pid"
    fi
    rm -rf "$tmp"
    exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

real_cc=$(command -v "${CC:-cc}") || fail "C compiler not found"
real_ar=$(command -v ar) || fail "ar not found"
real_git=$(command -v git) || fail "git not found"
real_cat=$(command -v cat) || fail "cat not found"
real_uname=$(command -v uname) || fail "uname not found"
AR07_REAL_UNAME=$real_uname
export AR07_REAL_UNAME
real_dd=$(command -v dd) || fail "dd not found"
real_mv=$(command -v mv) || fail "mv not found"
if real_sha_tool=$(command -v sha256sum 2>/dev/null); then
    real_sha_kind=sha256sum
elif real_sha_tool=$(command -v shasum 2>/dev/null); then
    real_sha_kind=shasum
elif real_sha_tool=$(command -v sha256 2>/dev/null); then
    real_sha_kind=sha256
else
    fail "SHA-256 tool not found"
fi

fixture=$tmp/project
mkdir -p "$fixture/src" "$fixture/tests" "$fixture/tools" "$tmp/shims" \
    "$tmp/mv-shims" "$tmp/hash-shims" \
    "$tmp/fake-readline/include/readline" "$tmp/fake-readline/lib"
cp "$root/Makefile" "$fixture/Makefile"
cp "$root/VERSION" "$fixture/VERSION"
cp "$root/src/release_hardening.h" "$fixture/src/release_hardening.h"
cp "$root/src/freebsd_compat.h" "$fixture/src/freebsd_compat.h"
cp "$root/tools/release_publish.c" "$fixture/tools/release_publish.c"
cp "$root/tools/release_publish_lock.sh" \
    "$fixture/tools/release_publish_lock.sh"
cp "$root/tests/test_ci_symbols.sh" "$fixture/tests/test_ci_symbols.sh"

cat >"$fixture/src/narrow.h" <<'EOF'
#ifndef AR07_NARROW_H
#define AR07_NARROW_H
int helper_value(void);
#endif
EOF
cat >"$fixture/src/helper.h" <<'EOF'
#ifndef AR07_HELPER_H
#define AR07_HELPER_H
int helper_value(void);
#endif
EOF
cat >"$fixture/src/helper.c" <<'EOF'
#include "helper.h"
int helper_value(void)
{
    return 7;
}
EOF
cat >"$fixture/src/main.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "narrow.h"

#ifndef AR07_CFLAG
#define AR07_CFLAG 0
#endif
#ifndef AR07_CPPFLAG
#define AR07_CPPFLAG 0
#endif
#ifndef AR07_PLATFORM
#define AR07_PLATFORM 0
#endif

#ifdef AR07_USE_LIB
int ar07_lib_marker(void);
#endif

#ifdef HAVE_READLINE
#include <readline/readline.h>
#endif

int main(void)
{
    int library_marker = 0;
    int readline_marker = 0;

#ifdef AR07_USE_LIB
    library_marker = ar07_lib_marker();
#endif
#ifdef HAVE_READLINE
    char *line = readline("");
    if (line == NULL) {
        return 2;
    }
    free(line);
    readline_marker = 1;
#endif
    printf("cflag=%d cppflag=%d platform=%d lib=%d readline=%d helper=%d\n",
           AR07_CFLAG, AR07_CPPFLAG, AR07_PLATFORM, library_marker,
           readline_marker, helper_value());
    return helper_value() == 7 ? 0 : 1;
}
EOF

cat >"$tmp/fake-readline/include/readline/readline.h" <<'EOF'
#ifndef AR07_FAKE_READLINE_H
#define AR07_FAKE_READLINE_H
extern int rl_inhibit_completion;
char *readline(const char *prompt);
#endif
EOF
cat >"$tmp/fake-readline/include/readline/history.h" <<'EOF'
#ifndef AR07_FAKE_HISTORY_H
#define AR07_FAKE_HISTORY_H
#endif
EOF
cat >"$tmp/readline.c" <<'EOF'
#include <stdlib.h>
#include <readline/readline.h>
int rl_inhibit_completion;
char *readline(const char *prompt)
{
    char *line = malloc(1);
    (void)prompt;
    if (line != NULL) {
        line[0] = '\0';
    }
    return line;
}
EOF
"$real_cc" -fPIE -I"$tmp/fake-readline/include" -c "$tmp/readline.c" \
    -o "$tmp/readline.o"
"$real_ar" rcs "$tmp/fake-readline/lib/libreadline.a" "$tmp/readline.o"

cat >"$tmp/lib-one.c" <<'EOF'
int ar07_lib_marker(void) { return 1; }
EOF
cat >"$tmp/lib-two.c" <<'EOF'
int ar07_lib_marker(void) { return 2; }
EOF
"$real_cc" -c "$tmp/lib-one.c" -o "$tmp/lib-one.o"
"$real_cc" -c "$tmp/lib-two.c" -o "$tmp/lib-two.o"
"$real_ar" rcs "$tmp/lib-one.a" "$tmp/lib-one.o"
"$real_ar" rcs "$tmp/lib-two.a" "$tmp/lib-two.o"

cc_log=$tmp/compiler.log
for wrapper in cc-a cc-b; do
cat >"$tmp/shims/$wrapper" <<'EOF'
#!/bin/sh
: "${AR07_REAL_CC:?}"
: "${AR07_CC_LOG:?}"
if [ "${1-}" = "-dumpmachine" ] && [ -n "${AR07_FAKE_TRIPLE:-}" ]; then
    printf '%s\n' "$AR07_FAKE_TRIPLE"
    exit 0
fi
kind=other
has_object=0
is_probe=0
for arg do
    if [ "$arg" = "-c" ]; then
        kind=compile
    fi
    case $arg in
        *.o) has_object=1 ;;
        -|/dev/null) is_probe=1 ;;
    esac
done
if [ "$kind" = compile ] && [ "$is_probe" -eq 1 ]; then
    kind=probe
fi
if [ "$kind" = other ] && [ "$has_object" -eq 1 ]; then
    kind=link
fi
printf '%s wrapper=%s' "$kind" "${0##*/}" >>"$AR07_CC_LOG"
for arg do
    printf ' <%s>' "$arg" >>"$AR07_CC_LOG"
done
printf '\n' >>"$AR07_CC_LOG"
if [ "${AR07_DROP_TARGET_FLAGS:-0}" -eq 1 ]; then
    args_file=$AR07_CC_LOG.args.$$
    trap 'rm -f "$args_file"' 0 1 2 3 15
    : >"$args_file"
    for arg do
        case $arg in
            -fcf-protection|-mbranch-protection=standard) continue ;;
        esac
        printf '%s\n' "$arg" >>"$args_file"
    done
    set --
    while IFS= read -r arg; do
        set -- "$@" "$arg"
    done <"$args_file"
    rm -f "$args_file"
fi
exec "$AR07_REAL_CC" "$@"
EOF
    chmod 0700 "$tmp/shims/$wrapper"
done

cat >"$tmp/shims/uname" <<'EOF'
#!/bin/sh
: "${AR07_REAL_UNAME:?}"
if [ "${1-}" = -s ] && [ -n "${AR07_FAKE_UNAME_S-}" ]; then
    printf '%s\n' "$AR07_FAKE_UNAME_S"
    exit 0
fi
exec "$AR07_REAL_UNAME" "$@"
EOF
chmod 0700 "$tmp/shims/uname"

target=build/bin/ar07-probe
sources='src/main.c src/helper.c'
out=$tmp/make.out

invoke_build()
{
    : >"$cc_log"
    AR07_REAL_CC="$real_cc" AR07_CC_LOG="$cc_log" \
        AR07_REAL_UNAME="$real_uname" PATH="$tmp/shims:$PATH" \
        AR07_FAKE_TRIPLE="${AR07_FAKE_TRIPLE-}" \
        AR07_FAKE_UNAME_S="${AR07_FAKE_UNAME_S-}" \
        AR07_DROP_TARGET_FLAGS="${AR07_DROP_TARGET_FLAGS-0}" \
        "$make_cmd" -C "$fixture" TARGET=ar07-probe SOURCES="$sources" \
        VERSION=fixture-version COMMIT=fixture-commit "$@" "$target" \
        >"$out" 2>&1
}

require_build()
{
    label=$1
    shift
    if ! invoke_build "$@"; then
        sed -n '1,200p' "$out" >&2
        fail "$label build failed"
    fi
}

assert_rebuilt()
{
    label=$1
    grep '^compile ' "$cc_log" >/dev/null ||
        fail "$label did not recompile after its fingerprint changed"
    grep '^link ' "$cc_log" >/dev/null ||
        fail "$label did not relink after its fingerprint changed"
}

assert_output()
{
    expected=$1
    actual=$("$fixture/$target") || fail "probe binary failed"
    case $actual in
        *"$expected"*) ;;
        *) fail "probe output '$actual' lacks '$expected'" ;;
    esac
}

cc_a=$tmp/shims/cc-a
cc_b=$tmp/shims/cc-b

# CFLAGS and CPPFLAGS changes must rebuild, while an identical invocation is a
# true no-op. Explicit minimal flags keep this fixture independent of the
# production sanitizer/linker configuration.
require_build "initial CFLAGS" BUILD_TYPE=debug READLINE=0 CC="$cc_a" \
    CFLAGS='-std=gnu11 -DAR07_CFLAG=1' CPPFLAGS=-DAR07_CPPFLAG=1 \
    LDFLAGS= LIBS=
assert_rebuilt "initial CFLAGS"
assert_output 'cflag=1 cppflag=1'
cp "$fixture/build/obj/.buildconfig" "$tmp/buildconfig.before-noop"

require_build "no-op" BUILD_TYPE=debug READLINE=0 CC="$cc_a" \
    CFLAGS='-std=gnu11 -DAR07_CFLAG=1' CPPFLAGS=-DAR07_CPPFLAG=1 \
    LDFLAGS= LIBS=
if grep -E '^(compile|link) ' "$cc_log" >/dev/null; then
    diff -u "$tmp/buildconfig.before-noop" \
        "$fixture/build/obj/.buildconfig" >&2 || true
    fail "identical configuration rebuilt instead of remaining a no-op"
fi

require_build "CFLAGS" BUILD_TYPE=debug READLINE=0 CC="$cc_a" \
    CFLAGS='-std=gnu11 -DAR07_CFLAG=2' CPPFLAGS=-DAR07_CPPFLAG=1 \
    LDFLAGS= LIBS=
assert_rebuilt "CFLAGS"
assert_output 'cflag=2 cppflag=1'

require_build "CPPFLAGS" BUILD_TYPE=debug READLINE=0 CC="$cc_a" \
    CFLAGS='-std=gnu11 -DAR07_CFLAG=2' CPPFLAGS=-DAR07_CPPFLAG=2 \
    LDFLAGS= LIBS=
assert_rebuilt "CPPFLAGS"
assert_output 'cflag=2 cppflag=2'

# LDFLAGS must force a fresh link before the requested new map is observable.
require_build "first LDFLAGS" BUILD_TYPE=debug READLINE=0 CC="$cc_a" \
    CFLAGS='-std=gnu11 -DAR07_CFLAG=2' CPPFLAGS=-DAR07_CPPFLAG=2 \
    LDFLAGS="-Wl,-Map,$tmp/link-one.map" LIBS=
assert_rebuilt "first LDFLAGS"
[ -s "$tmp/link-one.map" ] || fail "first LDFLAGS were not applied"
require_build "second LDFLAGS" BUILD_TYPE=debug READLINE=0 CC="$cc_a" \
    CFLAGS='-std=gnu11 -DAR07_CFLAG=2' CPPFLAGS=-DAR07_CPPFLAG=2 \
    LDFLAGS="-Wl,-Map,$tmp/link-two.map" LIBS=
assert_rebuilt "second LDFLAGS"
[ -s "$tmp/link-two.map" ] || fail "changed LDFLAGS were not applied"

# Changing only LIBS must replace the linked implementation.
require_build "first LIBS" BUILD_TYPE=debug READLINE=0 CC="$cc_a" \
    CFLAGS='-std=gnu11 -DAR07_USE_LIB' CPPFLAGS= LDFLAGS= \
    LIBS="$tmp/lib-one.a"
assert_rebuilt "first LIBS"
assert_output 'lib=1'
require_build "second LIBS" BUILD_TYPE=debug READLINE=0 CC="$cc_a" \
    CFLAGS='-std=gnu11 -DAR07_USE_LIB' CPPFLAGS= LDFLAGS= \
    LIBS="$tmp/lib-two.a"
assert_rebuilt "second LIBS"
assert_output 'lib=2'

# A compiler command change is itself part of the toolchain fingerprint.
require_build "compiler" BUILD_TYPE=debug READLINE=0 CC="$cc_b" \
    CFLAGS='-std=gnu11 -DAR07_USE_LIB' CPPFLAGS= LDFLAGS= \
    LIBS="$tmp/lib-two.a"
assert_rebuilt "compiler"
grep '^compile wrapper=cc-b ' "$cc_log" >/dev/null ||
    fail "changed compiler wrapper did not compile the objects"

# Changing the same wrapper file in place must also invalidate the stamp: the
# command spelling/path/version/triple remain identical, only policy bytes
# change.
cp "$fixture/build/obj/.buildconfig" "$tmp/buildconfig.before-wrapper-mutation"
printf '%s\n' '# in-place policy mutation' >>"$cc_b"
require_build "in-place compiler wrapper" BUILD_TYPE=debug READLINE=0 CC="$cc_b" \
    CFLAGS='-std=gnu11 -DAR07_USE_LIB' CPPFLAGS= LDFLAGS= \
    LIBS="$tmp/lib-two.a"
if ! grep '^compile ' "$cc_log" >/dev/null; then
    diff -u "$tmp/buildconfig.before-wrapper-mutation" \
        "$fixture/build/obj/.buildconfig" >&2 || true
    sed -n '/^cc_/p' "$fixture/build/obj/.buildconfig" >&2
fi
assert_rebuilt "in-place compiler wrapper"
grep -F "cc_file_fingerprint=$cc_b=" \
    "$fixture/build/obj/.buildconfig" >/dev/null ||
    fail "build fingerprint omits the resolved wrapper content digest"

# Exercise the audited unsupported-platform input through the real release
# expansion. Supported-platform security flags are intentionally immutable;
# unknown platforms retain an acknowledged extension surface whose complete
# minimum is validated and reasserted after caller input.
AR07_FAKE_UNAME_S=AlienOS \
    require_build "first platform flags" BUILD_TYPE=release READLINE=0 CC="$cc_b" \
    UNSUPPORTED_RELEASE_ACK=I_ACKNOWLEDGE_UNSUPPORTED_RELEASE \
    RELEASE_ARTIFACT_FORMAT=elf \
    SECURITY_CFLAGS_RELEASE='-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -DAR07_PLATFORM=1' \
    SECURITY_LDFLAGS_RELEASE='-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack'
assert_rebuilt "first platform flags"
assert_output 'platform=1'
AR07_FAKE_UNAME_S=AlienOS \
    require_build "second platform flags" BUILD_TYPE=release READLINE=0 CC="$cc_b" \
    UNSUPPORTED_RELEASE_ACK=I_ACKNOWLEDGE_UNSUPPORTED_RELEASE \
    RELEASE_ARTIFACT_FORMAT=elf \
    SECURITY_CFLAGS_RELEASE='-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -DAR07_PLATFORM=2' \
    SECURITY_LDFLAGS_RELEASE='-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack'
assert_rebuilt "second platform flags"
assert_output 'platform=2'

# Host architecture must not influence destination hardening. These wrappers
# report the opposite target and strip the foreign ISA flag only when invoking
# the native fixture compiler; the compiler log therefore proves Make selected
# the destination flag while the real compile/link still completes.
AR07_FAKE_TRIPLE=aarch64-unknown-linux-gnu AR07_DROP_TARGET_FLAGS=1 \
    require_build "AArch64 target on x86 host" BUILD_TYPE=release READLINE=0 \
    CC="$cc_b" UNAME_M=x86_64
assert_rebuilt "AArch64 target on x86 host"
grep '<-mbranch-protection=standard>' "$cc_log" >/dev/null ||
    fail "AArch64 target did not select branch protection"
if grep '<-fcf-protection>' "$cc_log" >/dev/null; then
    fail "AArch64 target inherited x86 host CET flags"
fi
grep -F 'target_triple=aarch64-unknown-linux-gnu' \
    "$fixture/build/obj/.buildconfig" >/dev/null ||
    fail "AArch64 target triple missing from build fingerprint"

AR07_FAKE_TRIPLE=x86_64-unknown-linux-gnu AR07_DROP_TARGET_FLAGS=1 \
    require_build "x86 target on AArch64 host" BUILD_TYPE=release READLINE=0 \
    CC="$cc_b" UNAME_M=aarch64
assert_rebuilt "x86 target on AArch64 host"
grep '<-fcf-protection>' "$cc_log" >/dev/null ||
    fail "x86 target did not select CET protection"
if grep '<-mbranch-protection=standard>' "$cc_log" >/dev/null; then
    fail "x86 target inherited AArch64 host branch-protection flags"
fi

# TARGET_TRIPLE/TARGET_ARCH/CF_PROTECTION are derived policy, not caller
# metadata. A syntactically valid lie used to suppress native CET while the
# compiler still emitted x86 code. Force a rebuild and prove all three hostile
# command-line values lose to the compiler's own report.
AR07_FAKE_TRIPLE=x86_64-unknown-linux-gnu \
    require_build "claimed target mismatch" BUILD_TYPE=release READLINE=0 \
    CC="$cc_b" TARGET_TRIPLE=aarch64-unknown-linux-gnu \
    TARGET_TRIPLE_DETECTED=s390x-unknown-linux-gnu \
    TARGET_ARCH=aarch64 CF_PROTECTION= \
    CFLAGS='-std=gnu11 -DAR07_TARGET_OVERRIDE=1'
assert_rebuilt "claimed target mismatch"
grep -F 'target_triple=x86_64-unknown-linux-gnu' \
    "$fixture/build/obj/.buildconfig" >/dev/null ||
    fail "command-line target replaced the compiler-reported target"
grep '<-fcf-protection>' "$cc_log" >/dev/null ||
    fail "command-line target controls suppressed compiler-target CET"

# Host/platform facts and the shell-facing policy snapshot are derived inside
# Make. Command-line assignments must not relabel the host or replace the
# effective hardening evidence consumed by release-policy-check.
host_os=$($real_uname -s)
require_build "claimed OS and policy snapshot" BUILD_TYPE=release READLINE=0 \
    CC="$cc_b" UNAME_S=AlienOS UNAME_M=host-lie \
    GITSWITCH_RELEASE_POLICY_OS=AlienOS \
    GITSWITCH_RELEASE_POLICY_FORMAT=invalid \
    GITSWITCH_RELEASE_POLICY_TRIPLE=forged-invalid \
    GITSWITCH_RELEASE_POLICY_DETECTED_TRIPLE=other-invalid \
    GITSWITCH_RELEASE_EFFECTIVE_CFLAGS= \
    GITSWITCH_RELEASE_EFFECTIVE_LDFLAGS=
grep -F "platform_os=$host_os" "$fixture/build/obj/.buildconfig" >/dev/null ||
    fail "command-line UNAME_S replaced the detected host OS"

# The selection fixtures above intentionally log and strip a foreign flag so
# they can link natively. Complement them with a real Clang cross-object: the
# compiler itself must report the destination, accept its branch-protection
# flag, and emit an object whose ELF machine agrees with that report.
if [ "$(uname -s)" = Linux ]; then
    cross_clang=$(command -v clang 2>/dev/null) ||
        fail "clang is required for the real cross-target contract"
    cross_readelf=$(command -v readelf 2>/dev/null ||
        command -v llvm-readelf 2>/dev/null) ||
        fail "readelf is required for the real cross-target contract"
    case $(uname -m) in
        x86_64|amd64)
            cross_triple=aarch64-unknown-linux-gnu
            cross_machine=AArch64
            cross_flag=-mbranch-protection=standard
            ;;
        *)
            cross_triple=x86_64-unknown-linux-gnu
            cross_machine=X86-64
            cross_flag=-fcf-protection
            ;;
    esac
    cross_wrapper=$tmp/shims/cc-real-cross
    cross_log=$tmp/real-cross.log
    cat >"$cross_wrapper" <<'EOF'
#!/bin/sh
: "${AR07_REAL_CROSS_CC:?}"
: "${AR07_REAL_CROSS_TRIPLE:?}"
: "${AR07_REAL_CROSS_LOG:?}"
printf '%s' cross >>"$AR07_REAL_CROSS_LOG"
for arg do
    printf ' <%s>' "$arg" >>"$AR07_REAL_CROSS_LOG"
done
printf '\n' >>"$AR07_REAL_CROSS_LOG"
exec "$AR07_REAL_CROSS_CC" --target="$AR07_REAL_CROSS_TRIPLE" "$@"
EOF
    chmod 0700 "$cross_wrapper"
    cat >"$fixture/src/cross.c" <<'EOF'
int ar08_real_cross_object(int value);
int ar08_real_cross_object(int value)
{
    volatile char witness[64];
    witness[0] = (char)value;
    return witness[0];
}
EOF
    : >"$cross_log"
    if ! AR07_REAL_CROSS_CC="$cross_clang" \
        AR07_REAL_CROSS_TRIPLE="$cross_triple" \
        AR07_REAL_CROSS_LOG="$cross_log" \
        "$make_cmd" -C "$fixture" TARGET=ar07-cross \
        SOURCES=src/cross.c VERSION=fixture-version COMMIT=fixture-commit \
        BUILD_TYPE=release READLINE=0 CC="$cross_wrapper" WERROR=1 \
        build/obj/cross.o >"$out" 2>&1; then
        sed -n '1,200p' "$out" >&2
        fail "real cross-target object build failed"
    fi
    grep -F "<$cross_flag>" "$cross_log" >/dev/null ||
        fail "real cross compiler did not receive destination protection"
    "$cross_readelf" -h "$fixture/build/obj/cross.o" |
        grep -F "Machine:" | grep -F "$cross_machine" >/dev/null ||
        fail "real cross object machine disagrees with compiler target"
    grep -F "target_triple=$cross_triple" \
        "$fixture/build/obj/.buildconfig" >/dev/null ||
        fail "real cross compiler target missing from build fingerprint"
fi

# Unknown operating systems fail closed. Even acknowledgement is insufficient
# without an explicit inspector and the complete minimum compile/link policy;
# the audited override then proves the escape hatch is deliberate and usable.
if AR07_FAKE_TRIPLE=x86_64-unknown-linux-gnu AR07_FAKE_UNAME_S=AlienOS \
    invoke_build BUILD_TYPE=release READLINE=0 CC="$cc_b"; then
    fail "unsupported OS produced a nominal release without acknowledgement"
fi
grep -F 'requires explicit acknowledgement' "$out" >/dev/null ||
    fail "unsupported OS rejection did not identify acknowledgement"

if AR07_FAKE_TRIPLE=x86_64-unknown-linux-gnu AR07_FAKE_UNAME_S=AlienOS \
    invoke_build BUILD_TYPE=release READLINE=0 CC="$cc_b" \
    UNSUPPORTED_RELEASE_ACK=I_ACKNOWLEDGE_UNSUPPORTED_RELEASE \
    RELEASE_ARTIFACT_FORMAT=elf SECURITY_CFLAGS_RELEASE= \
    SECURITY_LDFLAGS_RELEASE=; then
    fail "unsupported OS accepted empty explicit hardening flags"
fi
grep -F 'unsupported release C flags omit' "$out" >/dev/null ||
    fail "unsupported OS empty-flag rejection was not precise"

# Required tokens followed by their negations are not an effective policy.
# This exact presence-only bypass previously produced ET_EXEC, lazy binding,
# no RELRO, and an executable stack while release-policy-check returned zero.
if AR07_FAKE_TRIPLE=x86_64-unknown-linux-gnu AR07_FAKE_UNAME_S=AlienOS \
    invoke_build BUILD_TYPE=release READLINE=0 CC="$cc_b" \
    UNSUPPORTED_RELEASE_ACK=I_ACKNOWLEDGE_UNSUPPORTED_RELEASE \
    RELEASE_ARTIFACT_FORMAT=elf \
    SECURITY_CFLAGS_RELEASE='-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -U_FORTIFY_SOURCE -fno-stack-protector -fno-pie' \
    SECURITY_LDFLAGS_RELEASE='-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -no-pie -Wl,-z,norelro -Wl,-z,lazy -Wl,-z,execstack'; then
    fail "unsupported OS accepted required tokens followed by neuters"
fi
grep -F 'conflict with' "$out" >/dev/null ||
    fail "unsupported OS contradictory-policy rejection was not precise"

AR07_FAKE_TRIPLE=x86_64-unknown-linux-gnu AR07_FAKE_UNAME_S=AlienOS \
    require_build "acknowledged unsupported OS" BUILD_TYPE=release READLINE=0 \
    CC="$cc_b" \
    UNSUPPORTED_RELEASE_ACK=I_ACKNOWLEDGE_UNSUPPORTED_RELEASE \
    RELEASE_ARTIFACT_FORMAT=elf \
    SECURITY_CFLAGS_RELEASE='-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE' \
    SECURITY_LDFLAGS_RELEASE='-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack'
assert_rebuilt "acknowledged unsupported OS"

if AR07_FAKE_TRIPLE=x86_64-unknown-linux-gnu \
    AR07_FAKE_UNAME_S=AlienOS AR07_REAL_UNAME="$real_uname" \
    AR07_REAL_CC="$real_cc" AR07_CC_LOG="$cc_log" \
    PATH="$tmp/shims:$PATH" \
    "$make_cmd" -C "$fixture" TARGET=ar07-probe SOURCES="$sources" \
    VERSION=fixture-version COMMIT=fixture-commit BUILD_TYPE=release \
    READLINE=0 CC="$cc_b" install \
    DESTDIR="$tmp/unsupported-install" PREFIX=/usr >"$out" 2>&1; then
    fail "unsupported OS installed a nominal release without policy"
fi
grep -F 'requires explicit acknowledgement' "$out" >/dev/null ||
    fail "unsupported release install did not fail at the policy boundary"

# Stabilize the fake readline search hints while disabled, then change only the
# READLINE request. Both 0->1 and 1->0 must replace the conditional code path.
readline_cflags=-I$tmp/fake-readline/include
readline_libs=-L$tmp/fake-readline/lib
require_build "readline baseline" BUILD_TYPE=release READLINE=0 CC="$cc_b" \
    READLINE_HINT_CFLAGS="$readline_cflags" READLINE_HINT_LIBS="$readline_libs"
assert_rebuilt "readline baseline"
assert_output 'readline=0'
require_build "READLINE 0 to 1" BUILD_TYPE=release READLINE=1 CC="$cc_b" \
    READLINE_HINT_CFLAGS="$readline_cflags" READLINE_HINT_LIBS="$readline_libs"
assert_rebuilt "READLINE 0 to 1"
assert_output 'readline=1'
require_build "READLINE 1 to 0" BUILD_TYPE=release READLINE=0 CC="$cc_b" \
    READLINE_HINT_CFLAGS="$readline_cflags" READLINE_HINT_LIBS="$readline_libs"
assert_rebuilt "READLINE 1 to 0"
assert_output 'readline=0'

# Compiler-generated dependency files should name only actual includes. A
# narrow header edit recompiles main.c but not the unrelated helper.c.
[ -s "$fixture/build/obj/main.d" ] || fail "main dependency file missing"
[ -s "$fixture/build/obj/helper.d" ] || fail "helper dependency file missing"
grep -F 'src/narrow.h' "$fixture/build/obj/main.d" >/dev/null ||
    fail "main dependency file omits narrow.h"
grep -F 'src/helper.h' "$fixture/build/obj/helper.d" >/dev/null ||
    fail "helper dependency file omits helper.h"
sleep 1
touch "$fixture/src/narrow.h"
require_build "narrow header" BUILD_TYPE=release READLINE=0 CC="$cc_b" \
    READLINE_HINT_CFLAGS="$readline_cflags" READLINE_HINT_LIBS="$readline_libs"
grep '^compile .*<src/main.c>' "$cc_log" >/dev/null ||
    fail "narrow header edit did not rebuild its dependent"
if grep '^compile .*<src/helper.c>' "$cc_log" >/dev/null; then
    fail "narrow header edit rebuilt an unrelated translation unit"
fi

# -MP should turn a removed header into a compiler diagnostic, not a stale
# success or Make's premature "no rule" error before the dependent compiles.
mv "$fixture/src/narrow.h" "$fixture/src/narrow.h.saved"
if invoke_build BUILD_TYPE=release READLINE=0 CC="$cc_b" \
    READLINE_HINT_CFLAGS="$readline_cflags" READLINE_HINT_LIBS="$readline_libs"; then
    fail "build succeeded after a required header was removed"
fi
grep '^compile .*<src/main.c>' "$cc_log" >/dev/null ||
    fail "removed header did not drive the dependent back through the compiler"
mv "$fixture/src/narrow.h.saved" "$fixture/src/narrow.h"

# Default metadata lookups execute exactly once. Explicit overrides execute no
# Git/VERSION probes and are preserved verbatim in the generated stamp.
probe_dir=$tmp/probes
mkdir "$probe_dir"
git_log=$tmp/git.log
cat_log=$tmp/cat.log
cat >"$probe_dir/git" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$AR07_GIT_LOG"
exec "$AR07_REAL_GIT" "$@"
EOF
cat >"$probe_dir/cat" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$AR07_CAT_LOG"
exec "$AR07_REAL_CAT" "$@"
EOF
chmod 0700 "$probe_dir/git" "$probe_dir/cat"
: >"$git_log"
: >"$cat_log"
if ! PATH="$probe_dir:$PATH" AR07_REAL_GIT="$real_git" \
    AR07_REAL_CAT="$real_cat" AR07_GIT_LOG="$git_log" AR07_CAT_LOG="$cat_log" \
    "$make_cmd" -C "$fixture" info >"$out" 2>&1; then
    sed -n '1,200p' "$out" >&2
    fail "default metadata probe invocation failed"
fi
[ "$(wc -l <"$git_log" | tr -d ' ')" -eq 1 ] ||
    fail "default COMMIT lookup executed more than once"
[ "$(wc -l <"$cat_log" | tr -d ' ')" -eq 1 ] ||
    fail "default VERSION lookup executed more than once"

: >"$git_log"
: >"$cat_log"
if ! PATH="$probe_dir:$PATH" AR07_REAL_GIT="$real_git" \
    AR07_REAL_CAT="$real_cat" AR07_GIT_LOG="$git_log" AR07_CAT_LOG="$cat_log" \
    AR07_REAL_CC="$real_cc" AR07_CC_LOG="$cc_log" \
    "$make_cmd" -C "$fixture" TARGET=ar07-probe SOURCES="$sources" \
    VERSION=override-version COMMIT=override-commit BUILD_TYPE=debug READLINE=0 \
    CC="$cc_a" CFLAGS='-std=gnu11' CPPFLAGS= LDFLAGS= LIBS= "$target" \
    >"$out" 2>&1; then
    sed -n '1,200p' "$out" >&2
    fail "metadata override build failed"
fi
[ ! -s "$git_log" ] || fail "COMMIT override still executed Git"
[ ! -s "$cat_log" ] || fail "VERSION override still read VERSION"
grep -F 'version=override-version' "$fixture/build/obj/.buildconfig" >/dev/null ||
    fail "VERSION override was not preserved in the build fingerprint"
grep -F 'commit=override-commit' "$fixture/build/obj/.buildconfig" >/dev/null ||
    fail "COMMIT override was not preserved in the build fingerprint"

# Release helpers live outside redirected application build directories and
# are executed by dist/release-contract targets. Their provenance therefore
# needs an always-run content check of source/header bytes, HOSTCC command and
# launcher bytes, immutable compile policy, profile macros, and the resulting
# helper itself. Timestamp-only prerequisites accept future-dated foreign
# executables and silently skip a changed compiler or recipe.
hostcc_log=$tmp/hostcc.log
GITSWITCH_RELEASE_LOCK_ATTEMPTS=1
export GITSWITCH_RELEASE_LOCK_ATTEMPTS
for wrapper in hostcc-a hostcc-b hostcc-fail-named hostcc-signal hostcc-block; do
cat >"$tmp/shims/$wrapper" <<'EOF'
#!/bin/sh
: "${AR11_REAL_HOSTCC:?}"
: "${AR11_HOSTCC_LOG:?}"
output=
previous=
is_helper_compile=0
helper_source=
for arg do
    if [ "$previous" = -o ]; then
        output=$arg
    fi
    case $arg in
        tools/release_publish.c|build/tools/release-publish.tmp.*/tools/release_publish.c)
            is_helper_compile=1
            helper_source=$arg
            ;;
    esac
    previous=$arg
done
case $is_helper_compile:$output in
    1:build/tools/*)
        printf 'host-compile wrapper=%s output=%s' "${0##*/}" "$output" \
            >>"$AR11_HOSTCC_LOG"
        for arg do
            printf ' <%s>' "$arg" >>"$AR11_HOSTCC_LOG"
        done
        printf '\n' >>"$AR11_HOSTCC_LOG"
        ;;
esac
case $is_helper_compile:$helper_source in
    1:build/tools/release-publish.tmp.*/tools/release_publish.c) ;;
    1:*)
        printf '%s\n' 'host compiler received an unpinned source path' >&2
        exit 88
        ;;
esac
case ${0##*/}:$output in
    hostcc-fail-named:build/tools/*/release-publish-named-test)
        exit 86
        ;;
    hostcc-signal:build/tools/*/release-publish)
        kill -TERM "$PPID"
        exit 0
        ;;
    hostcc-block:build/tools/*/release-publish)
        : "${AR11_BLOCK_READY:?}"
        : "${AR11_BLOCK_FIFO:?}"
        printf '%s\n' "$$" >"$AR11_BLOCK_READY"
        IFS= read -r _ <"$AR11_BLOCK_FIFO" || exit 89
        ;;
esac
exec "$AR11_REAL_HOSTCC" "$@"
EOF
    chmod 0700 "$tmp/shims/$wrapper"
done

cat >"$tmp/mv-shims/mv" <<'EOF'
#!/bin/sh
: "${AR11_REAL_MV:?}"
last_arg=
for arg do
    last_arg=$arg
done
"$AR11_REAL_MV" "$@" || exit $?
if [ "${AR11_MV_BLOCK-}" = 1 ] &&
   [ "$last_arg" = build/tools/.release-publish.provenance ]; then
    : "${AR11_MV_READY:?}"
    : "${AR11_MV_FIFO:?}"
    printf '%s\n' "$$" >"$AR11_MV_READY"
    IFS= read -r _ <"$AR11_MV_FIFO" || exit 90
fi
EOF
chmod 0700 "$tmp/mv-shims/mv"

cat >"$tmp/hash-shims/sha256sum" <<'EOF'
#!/bin/sh
: "${AR11_REAL_SHA_TOOL:?}"
: "${AR11_REAL_SHA_KIND:?}"
if [ "${AR11_HASH_BLOCK-}" = 1 ] &&
   [ "${1-}" = build/tools/release-publish ]; then
    : "${AR11_HASH_READY:?}"
    : "${AR11_HASH_FIFO:?}"
    printf '%s\n' "$$" >"$AR11_HASH_READY"
    IFS= read -r _ <"$AR11_HASH_FIFO" || exit 91
fi
case $AR11_REAL_SHA_KIND in
    sha256sum) exec "$AR11_REAL_SHA_TOOL" "$@" ;;
    shasum) exec "$AR11_REAL_SHA_TOOL" -a 256 "$@" ;;
    sha256)
        for sha_path do
            sha_value=$("$AR11_REAL_SHA_TOOL" -q "$sha_path") || exit 1
            printf '%s  %s\n' "$sha_value" "$sha_path"
        done
        ;;
    *) exit 92 ;;
esac
EOF
chmod 0700 "$tmp/hash-shims/sha256sum"

hostcc_a=$tmp/shims/hostcc-a
hostcc_b=$tmp/shims/hostcc-b
hostcc_signal=$tmp/shims/hostcc-signal
hostcc_block=$tmp/shims/hostcc-block
publish_helper=build/tools/release-publish
named_publish_helper=build/tools/release-publish-named-test
host_tool_receipt=build/tools/.release-publish.provenance

invoke_host_helper()
{
    host_target=$1
    shift
    hostcc_path=$tmp/shims:$PATH
    if [ -n "${AR11_HOSTCC_PATH_OVERRIDE-}" ]; then
        hostcc_path=$AR11_HOSTCC_PATH_OVERRIDE
    fi
    : >"$hostcc_log"
    AR11_REAL_HOSTCC="$real_cc" AR11_HOSTCC_LOG="$hostcc_log" \
        PATH="$hostcc_path" \
        "$make_cmd" -C "$fixture" VERSION=fixture-version \
        COMMIT=fixture-commit "$@" "$host_target" >"$out" 2>&1
}

require_host_helper()
{
    host_label=$1
    host_target=$2
    shift 2
    if ! invoke_host_helper "$host_target" "$@"; then
        sed -n '1,240p' "$out" >&2
        fail "$host_label host-helper build failed"
    fi
}

require_host_failure()
{
    host_label=$1
    host_target=$2
    shift 2
    if invoke_host_helper "$host_target" "$@"; then
        sed -n '1,240p' "$out" >&2
        fail "$host_label host-helper build unexpectedly succeeded"
    fi
}

assert_host_compiles()
{
    expected=$1
    host_label=$2
    actual=$(grep -c '^host-compile ' "$hostcc_log" || :)
    [ "$actual" -eq "$expected" ] || {
        cat "$hostcc_log" >&2
        fail "$host_label invoked HOSTCC $actual time(s), expected $expected"
    }
}

sha256_file()
{
    sha_path=$1
    sha_value=
    if command -v sha256sum >/dev/null 2>&1; then
        sha_output=$(sha256sum "$sha_path") || return 1
        sha_value=${sha_output%% *}
    elif command -v shasum >/dev/null 2>&1; then
        sha_output=$(shasum -a 256 "$sha_path") || return 1
        sha_value=${sha_output%% *}
    elif command -v sha256 >/dev/null 2>&1; then
        sha_value=$(sha256 -q "$sha_path") || return 1
    else
        return 1
    fi
    case $sha_value in
        ''|*[!0-9A-Fa-f]*) return 1 ;;
    esac
    [ "${#sha_value}" -eq 64 ] || return 1
    printf '%s' "$sha_value"
}

assert_host_receipt_digests()
{
    receipt_path=$fixture/$host_tool_receipt
    [ -f "$receipt_path" ] || fail "host-tool receipt is unavailable"
    production_count=$(grep -c '^production_helper_sha256=' \
        "$receipt_path" || :)
    named_count=$(grep -c '^named_helper_sha256=' "$receipt_path" || :)
    [ "$production_count" -eq 1 ] ||
        fail "host-tool receipt has $production_count production digests"
    [ "$named_count" -eq 1 ] ||
        fail "host-tool receipt has $named_count named-profile digests"
    receipt_production=$(sed -n \
        's/^production_helper_sha256=//p' "$receipt_path")
    receipt_named=$(sed -n \
        's/^named_helper_sha256=//p' "$receipt_path")
    actual_production=$(sha256_file "$fixture/$publish_helper") ||
        fail "cannot independently digest production helper"
    actual_named=$(sha256_file "$fixture/$named_publish_helper") ||
        fail "cannot independently digest named-profile helper"
    [ "$receipt_production" = "$actual_production" ] ||
        fail "receipt does not contain the exact production-helper digest"
    [ "$receipt_named" = "$actual_named" ] ||
        fail "receipt does not contain the exact named-helper digest"
}

assert_host_file_modes()
{
    production_mode=$(find "$fixture/$publish_helper" -prune -type f \
        -perm 0755 -print 2>/dev/null || :)
    named_mode=$(find "$fixture/$named_publish_helper" -prune -type f \
        -perm 0755 -print 2>/dev/null || :)
    receipt_mode=$(find "$fixture/$host_tool_receipt" -prune -type f \
        -perm 0644 -print 2>/dev/null || :)
    tools_mode=$(find "$fixture/build/tools" -prune -type d \
        -perm 0700 -print 2>/dev/null || :)
    peer_writable_build=$(find "$fixture/build" -prune -type d \
        \( -perm -0020 -o -perm -0002 \) -print 2>/dev/null || :)
    [ "$production_mode" = "$fixture/$publish_helper" ] ||
        fail "production helper mode is not exactly 0755"
    [ "$named_mode" = "$fixture/$named_publish_helper" ] ||
        fail "named helper mode is not exactly 0755"
    [ "$receipt_mode" = "$fixture/$host_tool_receipt" ] ||
        fail "host-tool receipt mode is not exactly 0644"
    [ "$tools_mode" = "$fixture/build/tools" ] ||
        fail "host-tool directory mode is not exactly 0700"
    [ -z "$peer_writable_build" ] ||
        fail "build namespace remains writable by group or other users"
}

start_blocked_host_build()
{
    block_label=$1
    shift
    block_ready=$tmp/hostcc-block.ready
    block_fifo=$tmp/hostcc-block.fifo
    rm -f "$block_ready" "$block_fifo"
    mkfifo "$block_fifo" || fail "$block_label cannot create compiler gate"
    : >"$hostcc_log"
    AR11_REAL_HOSTCC="$real_cc" AR11_HOSTCC_LOG="$hostcc_log" \
        AR11_BLOCK_READY="$block_ready" AR11_BLOCK_FIFO="$block_fifo" \
        PATH="$tmp/shims:$PATH" \
        "$make_cmd" -C "$fixture" VERSION=fixture-version \
        COMMIT=fixture-commit HOSTCC="$hostcc_block" \
        "$@" "$publish_helper" >"$out" 2>&1 &
    host_build_pid=$!
    block_tries=0
    while [ ! -s "$block_ready" ]; do
        if ! kill -0 "$host_build_pid" 2>/dev/null; then
            wait "$host_build_pid" 2>/dev/null || :
            host_build_pid=
            sed -n '1,240p' "$out" >&2
            fail "$block_label compiler exited before its controlled gate"
        fi
        block_tries=$((block_tries + 1))
        [ "$block_tries" -lt 200 ] ||
            fail "$block_label compiler gate timed out"
        sleep 0.05
    done
    gate_process_pid=$(sed -n '1p' "$block_ready")
    case $gate_process_pid in
        ''|*[!0-9]*) fail "$block_label gate did not publish a valid PID" ;;
    esac
    kill -0 "$gate_process_pid" 2>/dev/null ||
        fail "$block_label gate process exited before mutation"
}

start_blocked_publication()
{
    block_label=$1
    block_kind=$2
    block_ready=$tmp/publication-$block_kind.ready
    block_fifo=$tmp/publication-$block_kind.fifo
    rm -f "$block_ready" "$block_fifo"
    mkfifo "$block_fifo" || fail "$block_label cannot create publication gate"
    : >"$hostcc_log"
    case $block_kind in
        mv)
            AR11_REAL_HOSTCC="$real_cc" AR11_HOSTCC_LOG="$hostcc_log" \
                AR11_REAL_MV="$real_mv" AR11_MV_BLOCK=1 \
                AR11_MV_READY="$block_ready" AR11_MV_FIFO="$block_fifo" \
                PATH="$tmp/mv-shims:$tmp/shims:$PATH" \
                "$make_cmd" -B -C "$fixture" VERSION=fixture-version \
                COMMIT=fixture-commit HOSTCC="$hostcc_b" \
                "$publish_helper" >"$out" 2>&1 &
            ;;
        hash)
            AR11_REAL_HOSTCC="$real_cc" AR11_HOSTCC_LOG="$hostcc_log" \
                AR11_REAL_SHA_TOOL="$real_sha_tool" \
                AR11_REAL_SHA_KIND="$real_sha_kind" AR11_HASH_BLOCK=1 \
                AR11_HASH_READY="$block_ready" AR11_HASH_FIFO="$block_fifo" \
                PATH="$tmp/hash-shims:$tmp/shims:$PATH" \
                "$make_cmd" -B -C "$fixture" VERSION=fixture-version \
                COMMIT=fixture-commit HOSTCC="$hostcc_b" \
                "$publish_helper" >"$out" 2>&1 &
            ;;
        *) fail "$block_label has an unknown publication gate" ;;
    esac
    host_build_pid=$!
    block_tries=0
    while [ ! -s "$block_ready" ]; do
        if ! kill -0 "$host_build_pid" 2>/dev/null; then
            wait "$host_build_pid" 2>/dev/null || :
            host_build_pid=
            sed -n '1,240p' "$out" >&2
            fail "$block_label exited before its controlled gate"
        fi
        block_tries=$((block_tries + 1))
        [ "$block_tries" -lt 200 ] ||
            fail "$block_label publication gate timed out"
        sleep 0.05
    done
    gate_process_pid=$(sed -n '1p' "$block_ready")
    case $gate_process_pid in
        ''|*[!0-9]*) fail "$block_label gate did not publish a valid PID" ;;
    esac
    kill -0 "$gate_process_pid" 2>/dev/null ||
        fail "$block_label gate process exited before mutation"
}

finish_blocked_host_failure()
{
    block_label=$1
    release_done=$tmp/gate-release.done
    rm -f "$release_done"
    (
        if printf '%s\n' release >"$block_fifo"; then
            writer_status=0
        else
            writer_status=$?
        fi
        printf '%s\n' "$writer_status" >"$release_done"
        exit "$writer_status"
    ) &
    fifo_writer_pid=$!
    release_tries=0
    while [ ! -s "$release_done" ]; do
        kill -0 "$gate_process_pid" 2>/dev/null ||
            fail "$block_label gate exited before accepting release"
        kill -0 "$host_build_pid" 2>/dev/null ||
            fail "$block_label build exited before accepting release"
        release_tries=$((release_tries + 1))
        [ "$release_tries" -lt 200 ] ||
            fail "$block_label release gate timed out"
        sleep 0.05
    done
    writer_status=$(sed -n '1p' "$release_done")
    writer_ok=1
    wait "$fifo_writer_pid" || writer_ok=0
    fifo_writer_pid=
    case $writer_status:$writer_ok in
        0:1) ;;
        *) fail "$block_label release writer failed" ;;
    esac
    # A successful write to the opened FIFO unblocks the gated read. The gate
    # may now be reaped and its PID reused, so never probe or signal it again.
    gate_process_pid=
    completion_tries=0
    while kill -0 "$host_build_pid" 2>/dev/null; do
        completion_tries=$((completion_tries + 1))
        if [ "$completion_tries" -ge 400 ]; then
            terminate_and_reap "$host_build_pid"
            host_build_pid=
            fail "$block_label build did not finish after gate release"
        fi
        sleep 0.05
    done
    block_succeeded=0
    if wait "$host_build_pid"; then
        block_succeeded=1
    fi
    host_build_pid=
    rm -f "$block_ready" "$block_fifo" "$release_done"
    release_done=
    if [ "$block_succeeded" -eq 1 ]; then
        sed -n '1,240p' "$out" >&2
        fail "$block_label unexpectedly succeeded"
    fi
}

foreign_true=
for candidate in /usr/bin/true /bin/true; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
        foreign_true=$candidate
        break
    fi
done
[ -n "$foreign_true" ] || fail "cannot find a regular true executable"

require_host_helper "initial production" "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "initial production"
require_host_helper "initial named" "$named_publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 0 "initial named"
[ -f "$fixture/$host_tool_receipt" ] ||
    fail "release helpers have no shared provenance receipt"
assert_host_receipt_digests
assert_host_file_modes

cp "$fixture/$publish_helper" "$tmp/publish.before-noop"
cp "$fixture/$named_publish_helper" "$tmp/named-publish.before-noop"
cp "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-noop"
require_host_helper "production no-op" "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 0 "production no-op"
cmp -s "$fixture/$publish_helper" "$tmp/publish.before-noop" ||
    fail "production no-op changed helper bytes"
cmp -s "$fixture/$named_publish_helper" "$tmp/named-publish.before-noop" ||
    fail "production no-op changed named-helper bytes"
cmp -s "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-noop" ||
    fail "production no-op changed receipt bytes"
assert_host_receipt_digests

# Exact output bytes own reuse. Change one byte without changing the file size
# and restore a fixed future mtime so neither size nor timestamp can stand in
# for the receipt's strong helper digest.
production_size=$(wc -c <"$fixture/$publish_helper")
touch -t 203501010000 "$fixture/$publish_helper"
printf 'X' | "$real_dd" of="$fixture/$publish_helper" bs=1 count=1 \
    conv=notrunc 2>/dev/null
touch -t 203501010000 "$fixture/$publish_helper"
[ "$(wc -c <"$fixture/$publish_helper")" -eq "$production_size" ] ||
    fail "production-helper byte mutation changed its size"
require_host_helper "equal-size production mutation" \
    "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "equal-size production mutation"
assert_host_receipt_digests

named_size=$(wc -c <"$fixture/$named_publish_helper")
touch -t 203501010000 "$fixture/$named_publish_helper"
printf 'X' | "$real_dd" of="$fixture/$named_publish_helper" bs=1 count=1 \
    conv=notrunc 2>/dev/null
touch -t 203501010000 "$fixture/$named_publish_helper"
[ "$(wc -c <"$fixture/$named_publish_helper")" -eq "$named_size" ] ||
    fail "named-helper byte mutation changed its size"
require_host_helper "equal-size named mutation" \
    "$named_publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "equal-size named mutation"
assert_host_receipt_digests

# Mode drift must never be silently reused. The private namespace is repaired
# first; both profiles and their receipt are then republished at exact modes.
chmod 0777 "$fixture/build" "$fixture/build/tools" "$fixture/$publish_helper" \
    "$fixture/$named_publish_helper"
chmod 0666 "$fixture/$host_tool_receipt"
require_host_helper "permissive host-tool modes" \
    "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "permissive host-tool modes"
assert_host_receipt_digests
assert_host_file_modes

# Darwin and FreeBSD ACLs can grant access independently of the displayed mode
# bits. Install a live access/inheritance ACL on hosted ACL-capable filesystems,
# then require the always-run controller to strip it without recompiling the
# otherwise current helper generation.
host_os=$("$real_uname" -s)
case $host_os in
    Darwin)
        darwin_acl='everyone allow list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit'
        chmod +a "$darwin_acl" "$fixture/build" ||
            fail "cannot install Darwin build ACL fixture"
        chmod +a "$darwin_acl" "$fixture/build/tools" ||
            fail "cannot install Darwin tools ACL fixture"
        darwin_build_listing=$(ls -lde "$fixture/build") ||
            fail "cannot inspect Darwin build ACL fixture"
        darwin_tools_listing=$(ls -lde "$fixture/build/tools") ||
            fail "cannot inspect Darwin tools ACL fixture"
        case ${darwin_build_listing%% *}:${darwin_tools_listing%% *} in
            *+:*+) ;;
            *) fail "Darwin namespace ACL fixtures were not installed" ;;
        esac
        require_host_helper "Darwin namespace ACL normalization" \
            "$publish_helper" HOSTCC="$hostcc_a"
        assert_host_compiles 0 "Darwin namespace ACL normalization"
        darwin_build_listing=$(ls -lde "$fixture/build") ||
            fail "cannot inspect normalized Darwin build ACL"
        darwin_tools_listing=$(ls -lde "$fixture/build/tools") ||
            fail "cannot inspect normalized Darwin tools ACL"
        case ${darwin_build_listing%% *}:${darwin_tools_listing%% *} in
            *+*) fail "Darwin namespace ACL was not removed" ;;
        esac
        mkdir "$fixture/build/tools/acl-inheritance-probe" ||
            fail "cannot create Darwin ACL inheritance probe"
        darwin_probe_listing=$(ls -lde \
            "$fixture/build/tools/acl-inheritance-probe") ||
            fail "cannot inspect Darwin ACL inheritance probe"
        case ${darwin_probe_listing%% *} in
            *+) fail "Darwin tools ACL remained inheritable" ;;
        esac
        rmdir "$fixture/build/tools/acl-inheritance-probe"
        ;;
    FreeBSD)
        freebsd_acl_nfs4=$(getconf ACL_NFS4 "$fixture/build") ||
            fail "cannot query FreeBSD NFSv4 ACL support"
        freebsd_acl_extended=$(getconf ACL_EXTENDED "$fixture/build") ||
            fail "cannot query FreeBSD POSIX ACL support"
        case $freebsd_acl_nfs4:$freebsd_acl_extended in
            1:0|1:1|0:1)
                acl_ref_build=$tmp/acl-ref-build
                acl_ref_tools=$tmp/acl-ref-tools
                mkdir "$acl_ref_build" "$acl_ref_tools"
                chmod 0755 "$acl_ref_build"
                chmod 0700 "$acl_ref_tools"
                setfacl -b "$acl_ref_build" "$acl_ref_tools" ||
                    fail "cannot normalize FreeBSD ACL references"
                ;;
            0:0) ;;
            *) fail "invalid FreeBSD ACL capability result" ;;
        esac
        case $freebsd_acl_nfs4:$freebsd_acl_extended in
            1:0|1:1)
                setfacl -a 0 'everyone@:rwx:fd:allow' \
                    "$fixture/build" ||
                    fail "cannot install FreeBSD build NFSv4 ACL fixture"
                setfacl -a 0 'everyone@:rwx:fd:allow' \
                    "$fixture/build/tools" ||
                    fail "cannot install FreeBSD tools NFSv4 ACL fixture"
                getfacl -q "$acl_ref_build" >"$tmp/ref-build.acl"
                getfacl -q "$acl_ref_tools" >"$tmp/ref-tools.acl"
                getfacl -q "$fixture/build" >"$tmp/dirty-build.acl"
                getfacl -q "$fixture/build/tools" >"$tmp/dirty-tools.acl"
                cmp -s "$tmp/ref-build.acl" "$tmp/dirty-build.acl" &&
                    fail "FreeBSD build NFSv4 ACL fixture was not installed"
                cmp -s "$tmp/ref-tools.acl" "$tmp/dirty-tools.acl" &&
                    fail "FreeBSD tools NFSv4 ACL fixture was not installed"
                require_host_helper "FreeBSD NFSv4 ACL normalization" \
                    "$publish_helper" HOSTCC="$hostcc_a"
                assert_host_compiles 0 "FreeBSD NFSv4 ACL normalization"
                getfacl -q "$fixture/build" >"$tmp/actual-build.acl"
                getfacl -q "$fixture/build/tools" >"$tmp/actual-tools.acl"
                cmp -s "$tmp/ref-build.acl" "$tmp/actual-build.acl" ||
                    fail "FreeBSD build NFSv4 ACL was not normalized"
                cmp -s "$tmp/ref-tools.acl" "$tmp/actual-tools.acl" ||
                    fail "FreeBSD tools NFSv4 ACL was not normalized"
                ;;
            0:1)
                setfacl -k "$acl_ref_build" "$acl_ref_tools" ||
                    fail "cannot clear FreeBSD reference default ACLs"
                freebsd_uid=$(id -u)
                setfacl -m "u:$freebsd_uid:rwx" \
                    "$fixture/build" "$fixture/build/tools" ||
                    fail "cannot install FreeBSD POSIX access ACL fixtures"
                setfacl -d -m \
                    "u::rwx,u:$freebsd_uid:rwx,g::---,m::rwx,o::---" \
                    "$fixture/build" "$fixture/build/tools" ||
                    fail "cannot install FreeBSD POSIX default ACL fixtures"
                getfacl -q "$acl_ref_build" >"$tmp/ref-build.acl"
                getfacl -q "$acl_ref_tools" >"$tmp/ref-tools.acl"
                getfacl -q "$fixture/build" >"$tmp/dirty-build.acl"
                getfacl -q "$fixture/build/tools" >"$tmp/dirty-tools.acl"
                cmp -s "$tmp/ref-build.acl" "$tmp/dirty-build.acl" &&
                    fail "FreeBSD build POSIX access ACL fixture was not installed"
                cmp -s "$tmp/ref-tools.acl" "$tmp/dirty-tools.acl" &&
                    fail "FreeBSD tools POSIX access ACL fixture was not installed"
                capture_default_acl()
                {
                    if getfacl -dq "$1" >"$2" 2>/dev/null; then
                        captured_acl_status=0
                    else
                        captured_acl_status=$?
                    fi
                }
                capture_default_acl "$acl_ref_build" \
                    "$tmp/ref-build.default"
                ref_build_default_status=$captured_acl_status
                capture_default_acl "$acl_ref_tools" \
                    "$tmp/ref-tools.default"
                ref_tools_default_status=$captured_acl_status
                capture_default_acl "$fixture/build" \
                    "$tmp/dirty-build.default"
                dirty_build_default_status=$captured_acl_status
                capture_default_acl "$fixture/build/tools" \
                    "$tmp/dirty-tools.default"
                dirty_tools_default_status=$captured_acl_status
                if [ "$dirty_build_default_status" -eq \
                     "$ref_build_default_status" ] &&
                   cmp -s "$tmp/dirty-build.default" \
                       "$tmp/ref-build.default"; then
                    fail "FreeBSD build default ACL fixture was not installed"
                fi
                if [ "$dirty_tools_default_status" -eq \
                     "$ref_tools_default_status" ] &&
                   cmp -s "$tmp/dirty-tools.default" \
                       "$tmp/ref-tools.default"; then
                    fail "FreeBSD tools default ACL fixture was not installed"
                fi
                require_host_helper "FreeBSD POSIX ACL normalization" \
                    "$publish_helper" HOSTCC="$hostcc_a"
                assert_host_compiles 0 "FreeBSD POSIX ACL normalization"
                getfacl -q "$fixture/build" >"$tmp/actual-build.acl"
                getfacl -q "$fixture/build/tools" >"$tmp/actual-tools.acl"
                cmp -s "$tmp/ref-build.acl" "$tmp/actual-build.acl" ||
                    fail "FreeBSD build POSIX access ACL was not normalized"
                cmp -s "$tmp/ref-tools.acl" "$tmp/actual-tools.acl" ||
                    fail "FreeBSD tools POSIX access ACL was not normalized"
                capture_default_acl "$fixture/build" \
                    "$tmp/actual-build.default"
                actual_build_default_status=$captured_acl_status
                capture_default_acl "$fixture/build/tools" \
                    "$tmp/actual-tools.default"
                actual_tools_default_status=$captured_acl_status
                if [ "$actual_build_default_status" -ne \
                     "$ref_build_default_status" ] ||
                   ! cmp -s "$tmp/actual-build.default" \
                       "$tmp/ref-build.default"; then
                    fail "FreeBSD build default ACL was not removed"
                fi
                if [ "$actual_tools_default_status" -ne \
                     "$ref_tools_default_status" ] ||
                   ! cmp -s "$tmp/actual-tools.default" \
                       "$tmp/ref-tools.default"; then
                    fail "FreeBSD tools default ACL was not removed"
                fi
                ;;
            0:0) ;;
        esac
        ;;
esac

# GNU Make -B is the CI real-build gate and must continue to invoke HOSTCC
# even though ordinary target requests use a cheap provenance validator.
require_host_helper "forced production" "$publish_helper" -B HOSTCC="$hostcc_a"
assert_host_compiles 2 "forced production"

cp "$foreign_true" "$fixture/$publish_helper"
touch -t 203501010000 "$fixture/$publish_helper"
require_host_helper "future foreign production" "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "future foreign production"
cmp -s "$fixture/$publish_helper" "$foreign_true" &&
    fail "future-dated foreign production helper was reused"

sentinel=$tmp/helper-sentinel
printf '%s\n' 'sentinel-bytes' >"$sentinel"
rm -f "$fixture/$publish_helper"
ln -s "$sentinel" "$fixture/$publish_helper"
require_host_helper "symlink production target" "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "symlink production target"
[ ! -L "$fixture/$publish_helper" ] ||
    fail "production helper remained a symlink"
[ "$(cat "$sentinel")" = sentinel-bytes ] ||
    fail "production compilation followed a target symlink"

printf '%s\n' 'hardlink-sentinel-bytes' >"$sentinel"
rm -f "$fixture/$publish_helper"
ln "$sentinel" "$fixture/$publish_helper"
require_host_helper "hardlink production target" "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "hardlink production target"
[ "$(cat "$sentinel")" = hardlink-sentinel-bytes ] ||
    fail "production compilation overwrote a hard-linked sentinel"
cmp -s "$fixture/$publish_helper" "$sentinel" &&
    fail "production helper remained a hard link to the sentinel"

rm -f "$fixture/$host_tool_receipt"
touch -t 203501010000 "$fixture/$publish_helper"
require_host_helper "missing production receipt" "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "missing production receipt"
printf '%s\n' 'garbled receipt' >"$fixture/$host_tool_receipt"
require_host_helper "garbled production receipt" "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "garbled production receipt"

# Content, not mtime, owns the source generation.
printf '%s\n' '/* AR-11 source provenance mutation */' \
    >>"$fixture/tools/release_publish.c"
touch -t 200001010000 "$fixture/tools/release_publish.c"
require_host_helper "old-mtime source mutation" "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "old-mtime source mutation"

printf '%s\n' '/* AR-11 compatibility-header provenance mutation */' \
    >>"$fixture/src/freebsd_compat.h"
touch -t 200001010000 "$fixture/src/freebsd_compat.h"
require_host_helper "old-mtime compatibility-header mutation" \
    "$publish_helper" HOSTCC="$hostcc_a"
assert_host_compiles 2 "old-mtime compatibility-header mutation"

require_host_helper "HOSTCC command change" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "HOSTCC command change"
printf '%s\n' '# AR-11 in-place HOSTCC policy mutation' >>"$hostcc_b"
touch -t 200001010000 "$hostcc_b"
require_host_helper "HOSTCC content change" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "HOSTCC content change"

# Isolate the resolved-launcher field: command spelling, --version output,
# launcher bytes, and the explicit identity-file digest are all identical.
# Only PATH resolution changes, so dropping the resolved path turns this red.
mkdir "$tmp/host-path-a" "$tmp/host-path-b"
cp "$hostcc_b" "$tmp/host-path-a/hostcc-shared"
cp "$hostcc_b" "$tmp/host-path-b/hostcc-shared"
cp "$hostcc_b" "$tmp/hostcc-shared.identity"
chmod 0700 "$tmp/host-path-a/hostcc-shared" \
    "$tmp/host-path-b/hostcc-shared" "$tmp/hostcc-shared.identity"
cmp -s "$tmp/host-path-a/hostcc-shared" \
    "$tmp/host-path-b/hostcc-shared" ||
    fail "resolved-HOSTCC fixtures are not byte-identical"
AR11_HOSTCC_PATH_OVERRIDE="$tmp/host-path-a:$PATH" \
    require_host_helper "resolved HOSTCC path A" "$publish_helper" \
    HOSTCC=hostcc-shared \
    HOSTCC_IDENTITY_FILES="$tmp/hostcc-shared.identity"
assert_host_compiles 2 "resolved HOSTCC path A"
AR11_HOSTCC_PATH_OVERRIDE="$tmp/host-path-b:$PATH" \
    require_host_helper "resolved HOSTCC path B" "$publish_helper" \
    HOSTCC=hostcc-shared \
    HOSTCC_IDENTITY_FILES="$tmp/hostcc-shared.identity"
assert_host_compiles 2 "resolved HOSTCC path B"
require_host_helper "restored HOSTCC B" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "restored HOSTCC B"

# A changed compiler that fails must not report up to date or bless/overwrite
# the previously valid pair. A subsequent valid invocation remains reusable.
cp "$fixture/$publish_helper" "$tmp/publish.before-false"
cp "$fixture/$named_publish_helper" "$tmp/named-publish.before-false"
cp "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-false"
require_host_failure "false compiler" "$publish_helper" HOSTCC=false
cmp -s "$fixture/$publish_helper" "$tmp/publish.before-false" ||
    fail "failed HOSTCC changed the valid production helper"
cmp -s "$fixture/$named_publish_helper" "$tmp/named-publish.before-false" ||
    fail "failed HOSTCC changed the valid named helper"
cmp -s "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-false" ||
    fail "failed HOSTCC changed the valid production receipt"
require_host_helper "post-failure reuse" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "post-failure reuse"

# This compiler has a valid identity/version, completes the production build,
# then rejects the named profile. Neither canonical helper nor the receipt may
# change merely because the first private compile succeeded.
cp "$fixture/$publish_helper" "$tmp/publish.before-named-failure"
cp "$fixture/$named_publish_helper" "$tmp/named-publish.before-named-failure"
cp "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-named-failure"
require_host_failure "named-profile compiler failure" \
    "$publish_helper" HOSTCC="$tmp/shims/hostcc-fail-named"
assert_host_compiles 2 "named-profile compiler failure"
cmp -s "$fixture/$publish_helper" "$tmp/publish.before-named-failure" ||
    fail "named compile failure changed the production helper"
cmp -s "$fixture/$named_publish_helper" \
    "$tmp/named-publish.before-named-failure" ||
    fail "named compile failure changed the named helper"
cmp -s "$fixture/$host_tool_receipt" \
    "$tmp/publish-receipt.before-named-failure" ||
    fail "named compile failure changed the host-tool receipt"
require_host_helper "post-named-failure reuse" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "post-named-failure reuse"

# Signal traps must map termination to failure instead of reusing the shell's
# pre-trap zero status. The compiler sends TERM to the controller during the
# first private compile; canonical state remains untouched and temp state dies.
cp "$fixture/$publish_helper" "$tmp/publish.before-signal"
cp "$fixture/$named_publish_helper" "$tmp/named-publish.before-signal"
cp "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-signal"
require_host_failure "signalled compiler" \
    "$publish_helper" HOSTCC="$hostcc_signal"
assert_host_compiles 1 "signalled compiler"
cmp -s "$fixture/$publish_helper" "$tmp/publish.before-signal" ||
    fail "signalled compile changed the production helper"
cmp -s "$fixture/$named_publish_helper" "$tmp/named-publish.before-signal" ||
    fail "signalled compile changed the named helper"
cmp -s "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-signal" ||
    fail "signalled compile changed the host-tool receipt"
set -- "$fixture/build/tools"/*.tmp.*
{ [ "$#" -eq 1 ] && [ ! -e "$1" ]; } ||
    fail "signalled compile retained private temporary state"
require_host_helper "post-signal reuse" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "post-signal reuse"

# The compiler consumes a private source/header snapshot. If the canonical
# source changes while compilation is blocked, post-compile validation fails
# before any canonical helper or receipt is published.
cp "$fixture/tools/release_publish.c" "$tmp/release-publish.before-race"
cp "$fixture/$publish_helper" "$tmp/publish.before-source-race"
cp "$fixture/$named_publish_helper" "$tmp/named-publish.before-source-race"
cp "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-source-race"
start_blocked_host_build "source-generation race"
printf '%s\n' '/* AR-11 concurrent source generation */' \
    >>"$fixture/tools/release_publish.c"
finish_blocked_host_failure "source-generation race"
assert_host_compiles 2 "source-generation race"
grep -F 'ERROR: release-helper inputs changed during compilation' \
    "$out" >/dev/null ||
    fail "source-generation race did not report input invalidation"
cmp -s "$fixture/$publish_helper" "$tmp/publish.before-source-race" ||
    fail "source-generation race changed the production helper"
cmp -s "$fixture/$named_publish_helper" \
    "$tmp/named-publish.before-source-race" ||
    fail "source-generation race changed the named helper"
cmp -s "$fixture/$host_tool_receipt" \
    "$tmp/publish-receipt.before-source-race" ||
    fail "source-generation race changed the host-tool receipt"
cp "$tmp/release-publish.before-race" \
    "$fixture/tools/release_publish.c"
require_host_helper "post-source-race reuse" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "post-source-race reuse"

# Revalidate the compiler bytes across compilation too. Mutating the selected
# launcher at the same controlled breakpoint must fail before publication.
cp "$hostcc_block" "$tmp/hostcc-block.before-race"
cp "$fixture/$publish_helper" "$tmp/publish.before-hostcc-race"
cp "$fixture/$named_publish_helper" "$tmp/named-publish.before-hostcc-race"
cp "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-hostcc-race"
start_blocked_host_build "HOSTCC identity race"
printf '%s\n' '# AR-11 concurrent HOSTCC generation' >>"$hostcc_block"
finish_blocked_host_failure "HOSTCC identity race"
assert_host_compiles 2 "HOSTCC identity race"
grep -F 'ERROR: release-helper inputs changed during compilation' \
    "$out" >/dev/null ||
    fail "HOSTCC identity race did not report input invalidation"
cmp -s "$fixture/$publish_helper" "$tmp/publish.before-hostcc-race" ||
    fail "HOSTCC identity race changed the production helper"
cmp -s "$fixture/$named_publish_helper" \
    "$tmp/named-publish.before-hostcc-race" ||
    fail "HOSTCC identity race changed the named helper"
cmp -s "$fixture/$host_tool_receipt" \
    "$tmp/publish-receipt.before-hostcc-race" ||
    fail "HOSTCC identity race changed the host-tool receipt"
cp "$tmp/hostcc-block.before-race" "$hostcc_block"
chmod 0700 "$hostcc_block"
require_host_helper "post-HOSTCC-race reuse" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "post-HOSTCC-race reuse"

# A caller-supplied secondary identity list is independently causal: keep the
# resolved launcher fixed and mutate only the additional identity file while
# both private profiles compile.
cp "$hostcc_b" "$tmp/secondary-hostcc.identity"
cp "$fixture/$publish_helper" "$tmp/publish.before-secondary-race"
cp "$fixture/$named_publish_helper" "$tmp/named-publish.before-secondary-race"
cp "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-secondary-race"
start_blocked_host_build "secondary HOSTCC identity race" \
    HOSTCC_IDENTITY_FILES="$tmp/secondary-hostcc.identity"
printf '%s\n' '# AR-11 secondary identity generation' \
    >>"$tmp/secondary-hostcc.identity"
finish_blocked_host_failure "secondary HOSTCC identity race"
assert_host_compiles 2 "secondary HOSTCC identity race"
grep -F 'ERROR: release-helper inputs changed during compilation' \
    "$out" >/dev/null ||
    fail "secondary identity race did not report input invalidation"
cmp -s "$fixture/$publish_helper" "$tmp/publish.before-secondary-race" ||
    fail "secondary identity race changed the production helper"
cmp -s "$fixture/$named_publish_helper" \
    "$tmp/named-publish.before-secondary-race" ||
    fail "secondary identity race changed the named helper"
cmp -s "$fixture/$host_tool_receipt" \
    "$tmp/publish-receipt.before-secondary-race" ||
    fail "secondary identity race changed the host-tool receipt"
require_host_helper "post-secondary-race reuse" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "post-secondary-race reuse"

cp "$fixture/Makefile" "$tmp/Makefile.before-host-policy"
sed 's/^override DIST_PUBLISH_COMMON_FLAGS := -std=c11 -O2 /override DIST_PUBLISH_COMMON_FLAGS := -std=c11 -O1 /' \
    "$tmp/Makefile.before-host-policy" >"$fixture/Makefile"
require_host_helper "common helper flags" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "common helper flags"
grep -F '<-O1>' "$hostcc_log" >/dev/null ||
    fail "changed common helper flags did not reach HOSTCC"
cp "$tmp/Makefile.before-host-policy" "$fixture/Makefile"
require_host_helper "restored common helper flags" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "restored common helper flags"

sed 's/GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS=5000/GITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS=5001/' \
    "$tmp/Makefile.before-host-policy" >"$fixture/Makefile"
require_host_helper "named helper macro" "$named_publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "named helper macro"
grep -F '<-DGITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS=5001>' \
    "$hostcc_log" >/dev/null ||
    fail "changed named helper macro did not reach HOSTCC"
grep 'output=build/tools/[^ ]*/release-publish-named-test ' \
    "$hostcc_log" | \
    grep -F '<-DGITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS=5001>' >/dev/null ||
    fail "changed named helper macro did not reach the named profile"
if grep 'output=build/tools/[^ ]*/release-publish ' "$hostcc_log" | \
    grep -F '<-DGITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS=5001>' >/dev/null; then
    fail "named helper macro leaked into the production profile"
fi
cp "$tmp/Makefile.before-host-policy" "$fixture/Makefile"
require_host_helper "restored named helper macro" "$named_publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "restored named helper macro"

sed 's/^override DIST_PUBLISH_POLICY_VERSION := host-tool-v1$/override DIST_PUBLISH_POLICY_VERSION := host-tool-v2/' \
    "$tmp/Makefile.before-host-policy" >"$fixture/Makefile"
require_host_helper "helper policy schema" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "helper policy schema"
cp "$tmp/Makefile.before-host-policy" "$fixture/Makefile"
require_host_helper "restored helper policy schema" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "restored helper policy schema"

# A receipt is profile-specific and binds the helper bytes; production bytes
# copied over the named test helper must not pass its named-macro contract.
cp "$fixture/$publish_helper" "$fixture/$named_publish_helper"
touch -t 203501010000 "$fixture/$named_publish_helper"
require_host_helper "cross-profile named helper" "$named_publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "cross-profile named helper"

# Failed replacement of an unreceipted foreign binary leaves no receipt that
# could bless it. A valid compiler then recovers atomically.
cp "$foreign_true" "$fixture/$publish_helper"
rm -f "$fixture/$host_tool_receipt"
require_host_failure "foreign helper with false compiler" \
    "$publish_helper" HOSTCC=false
[ ! -e "$fixture/$host_tool_receipt" ] ||
    fail "failed compiler published a host-tool receipt"
cmp -s "$fixture/$publish_helper" "$foreign_true" ||
    fail "failed compiler partially replaced the foreign helper"
require_host_helper "production recovery" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "production recovery"

# Gate the third canonical move after the receipt is visible. A source change
# at that exact point must be caught by the post-publication input check, and
# the next ordinary request must repair the now-stale published generation.
start_blocked_publication "post-publication source race" mv
printf '%s\n' '/* AR-11 post-publication source generation */' \
    >>"$fixture/tools/release_publish.c"
finish_blocked_host_failure "post-publication source race"
assert_host_compiles 2 "post-publication source race"
grep -F 'ERROR: release-helper inputs changed during publication' \
    "$out" >/dev/null ||
    fail "post-publication source race missed its input check"
require_host_helper "post-publication source repair" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "post-publication source repair"
assert_host_receipt_digests

# Pause the first canonical helper digest after the receipt move. An
# equal-size helper rewrite must invalidate the receipt comparison itself.
start_blocked_publication "post-publication helper race" hash
late_helper_size=$(wc -c <"$fixture/$publish_helper")
printf 'X' | "$real_dd" of="$fixture/$publish_helper" bs=1 count=1 \
    conv=notrunc 2>/dev/null
[ "$(wc -c <"$fixture/$publish_helper")" -eq "$late_helper_size" ] ||
    fail "post-publication helper race changed helper size"
finish_blocked_host_failure "post-publication helper race"
assert_host_compiles 2 "post-publication helper race"
grep -F 'ERROR: release-helper provenance changed during publication' \
    "$out" >/dev/null ||
    fail "post-publication helper race missed the receipt comparison"
require_host_helper "post-publication helper repair" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "post-publication helper repair"
assert_host_receipt_digests

# The canonical inputs are checked once more after both helper digests and the
# receipt comparison. A source change during that final digest window cannot
# escape as a successful build with already-stale provenance.
start_blocked_publication "finalization source race" hash
printf '%s\n' '/* AR-11 finalization source generation */' \
    >>"$fixture/tools/release_publish.c"
finish_blocked_host_failure "finalization source race"
assert_host_compiles 2 "finalization source race"
grep -F 'ERROR: release-helper inputs changed during finalization' \
    "$out" >/dev/null ||
    fail "finalization source race missed the final input check"
require_host_helper "finalization source repair" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 2 "finalization source repair"
assert_host_receipt_digests

cp "$fixture/$publish_helper" "$tmp/publish.before-final-noop"
cp "$fixture/$named_publish_helper" "$tmp/named-publish.before-final-noop"
cp "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-final-noop"
require_host_helper "final production no-op" "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "final production no-op"
cmp -s "$fixture/$publish_helper" "$tmp/publish.before-final-noop" ||
    fail "final production no-op changed helper bytes"
cmp -s "$fixture/$named_publish_helper" "$tmp/named-publish.before-final-noop" ||
    fail "final production no-op changed named-helper bytes"
cmp -s "$fixture/$host_tool_receipt" "$tmp/publish-receipt.before-final-noop" ||
    fail "final production no-op changed receipt bytes"

# A shared controller must execute once when both file targets are requested
# concurrently. The fixed host-tool namespace must also be removed by clean
# even when the application BUILDDIR is redirected elsewhere.
rm -rf "$fixture/build/tools"
: >"$hostcc_log"
if ! AR11_REAL_HOSTCC="$real_cc" AR11_HOSTCC_LOG="$hostcc_log" \
    PATH="$tmp/shims:$PATH" \
    "$make_cmd" -C "$fixture" -j8 VERSION=fixture-version \
    COMMIT=fixture-commit HOSTCC="$hostcc_b" \
    "$publish_helper" "$named_publish_helper" >"$out" 2>&1; then
    sed -n '1,240p' "$out" >&2
    fail "parallel host-helper build failed"
fi
assert_host_compiles 2 "parallel host-helper build"
[ -f "$fixture/$host_tool_receipt" ] ||
    fail "parallel host-helper build omitted its shared receipt"
assert_host_receipt_digests
require_host_helper "parallel production no-op" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "parallel production no-op"
require_host_helper "parallel named no-op" \
    "$named_publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "parallel named no-op"
assert_host_receipt_digests

set -- "$fixture/build/tools"/*.tmp.*
{ [ "$#" -eq 1 ] && [ ! -e "$1" ]; } ||
    fail "host-helper build left temporary artifacts"

# Every fixed namespace component is a boundary. Neither publication nor a
# redirected application clean may follow build/build-tools symlinks into an
# external directory.
rm -rf "$fixture/build"
build_victim=$tmp/build-victim
mkdir "$build_victim"
printf '%s\n' build-victim >"$build_victim/sentinel"
ln -s "$build_victim" "$fixture/build"
require_host_failure "symlinked build namespace" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "symlinked build namespace"
[ "$(cat "$build_victim/sentinel")" = build-victim ] ||
    fail "helper build changed the symlinked build victim"
[ ! -e "$build_victim/tools" ] ||
    fail "helper build published through a symlinked build namespace"
for clean_alias in build/ ./build// "$fixture/build///"; do
    [ -L "$fixture/build" ] || ln -s "$build_victim" "$fixture/build"
    : >"$hostcc_log"
    if ! AR11_REAL_HOSTCC="$real_cc" AR11_HOSTCC_LOG="$hostcc_log" \
        PATH="$tmp/shims:$PATH" \
        "$make_cmd" -C "$fixture" BUILDDIR="$clean_alias" \
        HOSTCC="$hostcc_b" clean >"$out" 2>&1; then
        sed -n '1,240p' "$out" >&2
        fail "symlinked-build clean alias failed: $clean_alias"
    fi
    [ "$(cat "$build_victim/sentinel")" = build-victim ] ||
        fail "clean alias traversed the symlinked build: $clean_alias"
    [ ! -e "$fixture/build" ] && [ ! -L "$fixture/build" ] ||
        fail "clean alias retained the build symlink: $clean_alias"
done

mkdir "$fixture/build"
tools_victim=$tmp/tools-victim
mkdir "$tools_victim"
printf '%s\n' tools-victim >"$tools_victim/sentinel"
ln -s "$tools_victim" "$fixture/build/tools"
require_host_failure "symlinked tools namespace" \
    "$publish_helper" HOSTCC="$hostcc_b"
assert_host_compiles 0 "symlinked tools namespace"
[ "$(cat "$tools_victim/sentinel")" = tools-victim ] ||
    fail "helper build changed the symlinked tools victim"
[ ! -e "$tools_victim/release-publish" ] ||
    fail "helper build published through a symlinked tools namespace"

: >"$hostcc_log"
if ! AR11_REAL_HOSTCC="$real_cc" AR11_HOSTCC_LOG="$hostcc_log" \
    PATH="$tmp/shims:$PATH" \
    "$make_cmd" -C "$fixture" BUILDDIR="$tmp/redirected-build" \
    HOSTCC="$hostcc_b" clean >"$out" 2>&1; then
    sed -n '1,240p' "$out" >&2
    fail "redirected-BUILDDIR clean failed"
fi
[ ! -e "$fixture/build/tools" ] ||
    fail "redirected-BUILDDIR clean retained fixed host-tool artifacts"
[ "$(cat "$tools_victim/sentinel")" = tools-victim ] ||
    fail "redirected clean traversed the symlinked tools namespace"

# Redirected application roots are private destructive namespaces. Claiming
# an absent final component publishes an exact checkout/build binding; every
# later prepare or clean must fail closed when that binding is absent,
# transferable, malformed, symlinked, or made group/world accessible.
build_root_marker_name=.gitswitch-build-root
fixture_physical=$(CDPATH='' cd "$fixture" && pwd -P) ||
    fail "cannot resolve fixture physical path"

run_build_root_target()
{
    build_root_target=$1
    build_root_path=$2
    "$make_cmd" -C "$fixture" VERSION=fixture-version \
        COMMIT=fixture-commit BUILDDIR="$build_root_path" \
        "$build_root_target" >"$out" 2>&1
}

require_build_root_failure()
{
    build_root_label=$1
    build_root_path=$2
    build_root_target=$3
    build_root_diagnostic=$4
    if run_build_root_target "$build_root_target" "$build_root_path"; then
        sed -n '1,240p' "$out" >&2
        fail "$build_root_label unexpectedly succeeded"
    fi
    grep -F "$build_root_diagnostic" "$out" >/dev/null || {
        sed -n '1,240p' "$out" >&2
        fail "$build_root_label missed its ownership diagnostic"
    }
}

assert_redirected_root_preserved()
{
    preserved_label=$1
    preserved_root=$2
    [ -d "$preserved_root" ] && [ ! -L "$preserved_root" ] ||
        fail "$preserved_label replaced or removed the redirected root"
    [ -f "$preserved_root/sentinel" ] &&
        [ "$(cat "$preserved_root/sentinel")" = ar11-build-root ] ||
        fail "$preserved_label changed data in the redirected root"
}

write_build_root_marker()
{
    marker_root=$1
    marker_schema=$2
    marker_project=$3
    marker_build=$4
    {
        printf 'schema=%s\n' "$marker_schema"
        printf 'project=%s\n' "$marker_project"
        printf 'build=%s\n' "$marker_build"
    } >"$marker_root/$build_root_marker_name"
    chmod 0600 "$marker_root/$build_root_marker_name"
}

require_invalid_marker_rejections()
{
    invalid_label=$1
    invalid_root=$2
    require_build_root_failure "$invalid_label prepare" "$invalid_root" \
        prepare-build-root \
        'ERROR: application build-root marker is invalid:'
    require_build_root_failure "$invalid_label clean" "$invalid_root" \
        clean 'ERROR: refusing unowned redirected BUILDDIR cleanup:'
    assert_redirected_root_preserved "$invalid_label" "$invalid_root"
}

claimed_root=$tmp/redirected-owned
[ ! -e "$claimed_root" ] && [ ! -L "$claimed_root" ] ||
    fail "redirected ownership fixture unexpectedly exists"

# A failed marker publication must roll back only the empty final directory
# created by this invocation. Otherwise one transient filesystem/tool failure
# strands an unowned path that every later prepare correctly refuses.
real_chmod=$(command -v chmod) || fail "cannot resolve chmod"
failure_shims=$tmp/build-root-failure-shims
mkdir "$failure_shims"
cat >"$failure_shims/chmod" <<'EOF'
#!/bin/sh
for chmod_arg do
    case $chmod_arg in
        */.gitswitch-build-root.tmp.*) exit 97 ;;
    esac
done
exec "$AR11_REAL_CHMOD" "$@"
EOF
chmod +x "$failure_shims/chmod"
failed_claim_root=$tmp/redirected-failed-claim
if AR11_REAL_CHMOD="$real_chmod" PATH="$failure_shims:$PATH" \
    "$make_cmd" -C "$fixture" VERSION=fixture-version \
    COMMIT=fixture-commit BUILDDIR="$failed_claim_root" \
    prepare-build-root >"$out" 2>&1; then
    sed -n '1,240p' "$out" >&2
    fail "injected marker-publication failure unexpectedly succeeded"
fi
[ ! -e "$failed_claim_root" ] && [ ! -L "$failed_claim_root" ] ||
    fail "failed marker publication stranded its empty redirected root"

# Signals delivered after mkdir creates the final component are deferred just
# long enough to record ownership, so the EXIT cleanup can remove that empty
# unmarked directory instead of making the transient interruption permanent.
real_mkdir=$(command -v mkdir) || fail "cannot resolve mkdir"
signal_shims=$tmp/build-root-signal-shims
mkdir "$signal_shims"
cat >"$signal_shims/mkdir" <<'EOF'
#!/bin/sh
signal_final_root=0
for mkdir_arg do
    if [ "$mkdir_arg" = "$AR11_SIGNAL_ROOT" ]; then
        signal_final_root=1
    fi
done
"$AR11_REAL_MKDIR" "$@" || exit $?
if [ "$signal_final_root" -eq 1 ]; then
    printf '%s\n' delivered >"$AR11_SIGNAL_SENT"
    kill -TERM "$PPID"
fi
EOF
chmod +x "$signal_shims/mkdir"
signal_claim_root=$tmp/redirected-signalled-claim
signal_claim_sent=$tmp/redirected-signalled-claim.sent
if AR11_REAL_MKDIR="$real_mkdir" \
    AR11_SIGNAL_ROOT="$signal_claim_root" \
    AR11_SIGNAL_SENT="$signal_claim_sent" PATH="$signal_shims:$PATH" \
    "$make_cmd" -C "$fixture" VERSION=fixture-version \
    COMMIT=fixture-commit BUILDDIR="$signal_claim_root" \
    prepare-build-root >"$out" 2>&1; then
    sed -n '1,240p' "$out" >&2
    fail "post-mkdir TERM unexpectedly allowed build-root preparation"
fi
grep -F 'Error 143' "$out" >/dev/null || {
    sed -n '1,240p' "$out" >&2
    fail "post-mkdir TERM did not preserve the signal status"
}
[ -f "$signal_claim_sent" ] ||
    fail "post-mkdir TERM fixture did not reach the ownership seam"
[ ! -e "$signal_claim_root" ] && [ ! -L "$signal_claim_root" ] ||
    fail "post-mkdir TERM stranded its empty redirected root"
if ! run_build_root_target prepare-build-root "$signal_claim_root"; then
    sed -n '1,240p' "$out" >&2
    fail "post-mkdir TERM rollback did not permit a clean retry"
fi
if ! run_build_root_target clean "$signal_claim_root"; then
    sed -n '1,240p' "$out" >&2
    fail "post-mkdir TERM retry root was not cleanable"
fi

if ! run_build_root_target prepare-build-root "$claimed_root"; then
    sed -n '1,240p' "$out" >&2
    fail "absent redirected root was not atomically claimed"
fi
[ -d "$claimed_root" ] && [ ! -L "$claimed_root" ] ||
    fail "redirected claim did not publish a regular directory"
claimed_marker=$claimed_root/$build_root_marker_name
[ -f "$claimed_marker" ] && [ ! -L "$claimed_marker" ] ||
    fail "redirected claim did not publish a regular marker"
claimed_marker_mode=$(find "$claimed_marker" -prune -type f -perm 0600 \
    -print 2>/dev/null)
[ "$claimed_marker_mode" = "$claimed_marker" ] ||
    fail "redirected claim marker mode is not exactly 0600"
claimed_root_physical=$(CDPATH='' cd "$claimed_root" && pwd -P) ||
    fail "cannot resolve claimed build root"
{
    printf '%s\n' 'schema=gitswitch-build-root-v1'
    printf 'project=%s\n' "$fixture_physical"
    printf 'build=%s\n' "$claimed_root_physical"
} >"$tmp/claimed-marker.expected"
[ "$(wc -l <"$claimed_marker" | tr -d '[:space:]')" = 3 ] ||
    fail "redirected claim marker does not have exactly three lines"
cmp -s "$claimed_marker" "$tmp/claimed-marker.expected" ||
    fail "redirected claim marker does not exactly bind project/build paths"

if ! run_build_root_target prepare-build-root "$claimed_root"; then
    sed -n '1,240p' "$out" >&2
    fail "exact build-root marker failed repeat preparation"
fi
printf '%s\n' ar11-build-root >"$claimed_root/sentinel"
if ! run_build_root_target clean "$claimed_root"; then
    sed -n '1,240p' "$out" >&2
    fail "exact redirected ownership marker was not cleanable"
fi
[ ! -e "$claimed_root" ] && [ ! -L "$claimed_root" ] ||
    fail "owned redirected root survived clean"

unmarked_root=$tmp/redirected-unmarked
mkdir "$unmarked_root"
printf '%s\n' ar11-build-root >"$unmarked_root/sentinel"
require_build_root_failure "unmarked redirected root prepare" \
    "$unmarked_root" prepare-build-root \
    'ERROR: refusing unowned existing application build root:'
require_build_root_failure "unmarked redirected root clean" \
    "$unmarked_root" clean \
    'ERROR: refusing unowned redirected BUILDDIR cleanup:'
assert_redirected_root_preserved "unmarked redirected root" "$unmarked_root"
[ ! -e "$unmarked_root/$build_root_marker_name" ] &&
    [ ! -L "$unmarked_root/$build_root_marker_name" ] ||
    fail "unmarked redirected root was silently claimed"

cp "$fixture/src/main.c" "$tmp/main.c.before-src-builddir"
require_build_root_failure "source-tree build root prepare" src \
    prepare-build-root \
    'ERROR: refusing unowned existing application build root:'
require_build_root_failure "source-tree build root clean" src clean \
    'ERROR: refusing unowned redirected BUILDDIR cleanup:'
[ -d "$fixture/src" ] && [ ! -L "$fixture/src" ] ||
    fail "BUILDDIR=src replaced or removed the source tree"
cmp -s "$fixture/src/main.c" "$tmp/main.c.before-src-builddir" ||
    fail "BUILDDIR=src changed a source file"
[ ! -e "$fixture/src/$build_root_marker_name" ] &&
    [ ! -L "$fixture/src/$build_root_marker_name" ] ||
    fail "BUILDDIR=src silently claimed the source tree"

wrong_schema_root=$tmp/redirected-wrong-schema
mkdir "$wrong_schema_root"
printf '%s\n' ar11-build-root >"$wrong_schema_root/sentinel"
wrong_schema_physical=$(CDPATH='' cd "$wrong_schema_root" && pwd -P) ||
    fail "cannot resolve wrong-schema root"
write_build_root_marker "$wrong_schema_root" gitswitch-build-root-v2 \
    "$fixture_physical" "$wrong_schema_physical"
cp "$wrong_schema_root/$build_root_marker_name" \
    "$tmp/wrong-schema-marker.before"
require_invalid_marker_rejections "wrong-schema marker" "$wrong_schema_root"
cmp -s "$wrong_schema_root/$build_root_marker_name" \
    "$tmp/wrong-schema-marker.before" ||
    fail "wrong-schema rejection changed its marker"

trailing_bytes_root=$tmp/redirected-trailing-marker-bytes
mkdir "$trailing_bytes_root"
printf '%s\n' ar11-build-root >"$trailing_bytes_root/sentinel"
trailing_bytes_physical=$(
    CDPATH='' cd "$trailing_bytes_root" && pwd -P
) || fail "cannot resolve trailing-marker root"
write_build_root_marker "$trailing_bytes_root" gitswitch-build-root-v1 \
    "$fixture_physical" "$trailing_bytes_physical"
printf '%s' 'unterminated-extra-record' \
    >>"$trailing_bytes_root/$build_root_marker_name"
cp "$trailing_bytes_root/$build_root_marker_name" \
    "$tmp/trailing-marker.before"
require_invalid_marker_rejections "trailing marker bytes" \
    "$trailing_bytes_root"
cmp -s "$trailing_bytes_root/$build_root_marker_name" \
    "$tmp/trailing-marker.before" ||
    fail "trailing-byte rejection changed its marker"

wrong_project_root=$tmp/redirected-wrong-project
mkdir "$wrong_project_root"
printf '%s\n' ar11-build-root >"$wrong_project_root/sentinel"
wrong_project_physical=$(CDPATH='' cd "$wrong_project_root" && pwd -P) ||
    fail "cannot resolve wrong-project root"
write_build_root_marker "$wrong_project_root" gitswitch-build-root-v1 \
    "$tmp/not-this-project" "$wrong_project_physical"
cp "$wrong_project_root/$build_root_marker_name" \
    "$tmp/wrong-project-marker.before"
require_invalid_marker_rejections "wrong-project marker" "$wrong_project_root"
cmp -s "$wrong_project_root/$build_root_marker_name" \
    "$tmp/wrong-project-marker.before" ||
    fail "wrong-project rejection changed its marker"

wrong_build_root=$tmp/redirected-wrong-build
mkdir "$wrong_build_root"
printf '%s\n' ar11-build-root >"$wrong_build_root/sentinel"
write_build_root_marker "$wrong_build_root" gitswitch-build-root-v1 \
    "$fixture_physical" "$tmp/not-this-build"
cp "$wrong_build_root/$build_root_marker_name" \
    "$tmp/wrong-build-marker.before"
require_invalid_marker_rejections "wrong-build marker" "$wrong_build_root"
cmp -s "$wrong_build_root/$build_root_marker_name" \
    "$tmp/wrong-build-marker.before" ||
    fail "wrong-build rejection changed its marker"

copy_origin=$tmp/redirected-copy-origin
if ! run_build_root_target prepare-build-root "$copy_origin"; then
    sed -n '1,240p' "$out" >&2
    fail "copy-marker origin could not be claimed"
fi
copied_marker_root=$tmp/redirected-copied-marker
mkdir "$copied_marker_root"
printf '%s\n' ar11-build-root >"$copied_marker_root/sentinel"
cp "$copy_origin/$build_root_marker_name" \
    "$copied_marker_root/$build_root_marker_name"
chmod 0600 "$copied_marker_root/$build_root_marker_name"
require_invalid_marker_rejections "copied marker" "$copied_marker_root"
cmp -s "$copy_origin/$build_root_marker_name" \
    "$copied_marker_root/$build_root_marker_name" ||
    fail "copied-marker rejection changed marker bytes"

move_origin=$tmp/redirected-move-origin
if ! run_build_root_target prepare-build-root "$move_origin"; then
    sed -n '1,240p' "$out" >&2
    fail "move-marker origin could not be claimed"
fi
moved_marker_root=$tmp/redirected-moved-marker
mkdir "$moved_marker_root"
printf '%s\n' ar11-build-root >"$moved_marker_root/sentinel"
mv "$move_origin/$build_root_marker_name" \
    "$moved_marker_root/$build_root_marker_name"
require_invalid_marker_rejections "moved marker" "$moved_marker_root"
[ ! -e "$move_origin/$build_root_marker_name" ] &&
    [ ! -L "$move_origin/$build_root_marker_name" ] ||
    fail "moved-marker fixture did not move the origin marker"

symlink_marker_root=$tmp/redirected-symlink-marker
mkdir "$symlink_marker_root"
printf '%s\n' ar11-build-root >"$symlink_marker_root/sentinel"
symlink_marker_physical=$(CDPATH='' cd "$symlink_marker_root" && pwd -P) ||
    fail "cannot resolve symlink-marker root"
write_build_root_marker "$tmp" gitswitch-build-root-v1 \
    "$fixture_physical" "$symlink_marker_physical"
mv "$tmp/$build_root_marker_name" "$tmp/symlink-marker-target"
ln -s "$tmp/symlink-marker-target" \
    "$symlink_marker_root/$build_root_marker_name"
require_invalid_marker_rejections "symlink marker" "$symlink_marker_root"
[ -L "$symlink_marker_root/$build_root_marker_name" ] ||
    fail "symlink-marker rejection replaced its marker"

permissive_marker_root=$tmp/redirected-permissive-marker
mkdir "$permissive_marker_root"
printf '%s\n' ar11-build-root >"$permissive_marker_root/sentinel"
permissive_marker_physical=$(
    CDPATH='' cd "$permissive_marker_root" && pwd -P
) || fail "cannot resolve permissive-marker root"
write_build_root_marker "$permissive_marker_root" gitswitch-build-root-v1 \
    "$fixture_physical" "$permissive_marker_physical"
chmod 0666 "$permissive_marker_root/$build_root_marker_name"
require_invalid_marker_rejections "mode-0666 marker" \
    "$permissive_marker_root"
permissive_marker_mode=$(find \
    "$permissive_marker_root/$build_root_marker_name" -prune \
    -type f -perm 0666 -print 2>/dev/null)
[ "$permissive_marker_mode" = \
    "$permissive_marker_root/$build_root_marker_name" ] ||
    fail "mode-0666 rejection changed marker permissions"

# Restoring only the exact private mode repairs the otherwise exact marker;
# the same root must then pass preparation and its destructive clean gate.
chmod 0600 "$permissive_marker_root/$build_root_marker_name"
if ! run_build_root_target prepare-build-root "$permissive_marker_root"; then
    sed -n '1,240p' "$out" >&2
    fail "restored exact build-root marker failed preparation"
fi
if ! run_build_root_target clean "$permissive_marker_root"; then
    sed -n '1,240p' "$out" >&2
    fail "restored exact build-root marker failed clean"
fi
[ ! -e "$permissive_marker_root" ] &&
    [ ! -L "$permissive_marker_root" ] ||
    fail "restored exact build-root marker did not authorize clean"

# The public CI symbol contract must retain the release-publisher mutex through
# the consumer itself, not merely through helper generation. Hold the fixture
# consumer at a deterministic gate and prove an independent clean cannot enter.
cat >"$fixture/tests/test_ci_symbols.sh" <<'EOF'
#!/bin/sh
set -eu
: "${AR11_SYMBOL_READY:?}"
: "${AR11_SYMBOL_RELEASE:?}"
printf '%s\n' ready >"$AR11_SYMBOL_READY"
while [ ! -f "$AR11_SYMBOL_RELEASE" ]; do
    sleep 0.05
done
EOF
chmod +x "$fixture/tests/test_ci_symbols.sh"
symbol_ready=$tmp/symbol-contract.ready
symbol_release=$tmp/symbol-contract.release
symbol_out=$tmp/symbol-contract.out
symbol_contender_out=$tmp/symbol-contract-contender.out
rm -f "$symbol_ready" "$symbol_release"
: >"$hostcc_log"
AR11_REAL_HOSTCC="$real_cc" AR11_HOSTCC_LOG="$hostcc_log" \
    AR11_SYMBOL_READY="$symbol_ready" AR11_SYMBOL_RELEASE="$symbol_release" \
    PATH="$tmp/shims:$PATH" \
    "$make_cmd" -C "$fixture" VERSION=fixture-version \
    COMMIT=fixture-commit HOSTCC="$hostcc_b" \
    release-symbol-contract-test >"$symbol_out" 2>&1 &
host_build_pid=$!
symbol_tries=0
while [ ! -s "$symbol_ready" ]; do
    if ! kill -0 "$host_build_pid" 2>/dev/null; then
        wait "$host_build_pid" 2>/dev/null || :
        host_build_pid=
        sed -n '1,240p' "$symbol_out" >&2
        fail "locked symbol contract exited before its consumer gate"
    fi
    symbol_tries=$((symbol_tries + 1))
    [ "$symbol_tries" -lt 200 ] ||
        fail "locked symbol contract consumer gate timed out"
    sleep 0.05
done
if GITSWITCH_RELEASE_LOCK_ATTEMPTS=1 \
    "$make_cmd" -C "$fixture" clean >"$symbol_contender_out" 2>&1; then
    sed -n '1,240p' "$symbol_contender_out" >&2
    fail "clean entered while the symbol consumer held the publisher lock"
fi
grep -F 'release publisher is busy or its lock is stale:' \
    "$symbol_contender_out" >/dev/null || {
    sed -n '1,240p' "$symbol_contender_out" >&2
    fail "symbol-consumer contention missed the lock diagnostic"
}
: >"$symbol_release"
symbol_tries=0
while kill -0 "$host_build_pid" 2>/dev/null; do
    symbol_tries=$((symbol_tries + 1))
    [ "$symbol_tries" -lt 200 ] || {
        terminate_and_reap "$host_build_pid"
        host_build_pid=
        fail "locked symbol contract did not finish after gate release"
    }
    sleep 0.05
done
if ! wait "$host_build_pid"; then
    host_build_pid=
    sed -n '1,240p' "$symbol_out" >&2
    fail "locked symbol contract failed after gate release"
fi
host_build_pid=
[ ! -e "$fixture/.gitswitch-release-publish.lock" ] &&
    [ ! -L "$fixture/.gitswitch-release-publish.lock" ] ||
    fail "locked symbol contract left its publisher mutex behind"

for args_residue in "$cc_log".args.*; do
    [ ! -e "$args_residue" ] ||
        fail "compiler wrapper left argument scratch behind"
done

printf '%s\n' \
    'ar07-build: PASS (application and host-tool provenance, precise depfiles, frozen probes)'
