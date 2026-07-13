#!/bin/sh
# AR-07 T19: build-fingerprint, precise-dependency, and metadata-probe gates.

set -eu

fail()
{
    printf 'ar07-build: ERROR: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail "usage: $0 PROJECT_ROOT MAKE"
root=$1
make_cmd=$2

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-ar07-build.XXXXXX") ||
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

real_cc=$(command -v "${CC:-cc}") || fail "C compiler not found"
real_ar=$(command -v ar) || fail "ar not found"
real_git=$(command -v git) || fail "git not found"
real_cat=$(command -v cat) || fail "cat not found"
real_uname=$(command -v uname) || fail "uname not found"

fixture=$tmp/project
mkdir -p "$fixture/src" "$fixture/tests" "$tmp/shims" \
    "$tmp/fake-readline/include/readline" "$tmp/fake-readline/lib"
cp "$root/Makefile" "$fixture/Makefile"
cp "$root/VERSION" "$fixture/VERSION"
cp "$root/src/release_hardening.h" "$fixture/src/release_hardening.h"

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
    args_file=${TMPDIR:-/tmp}/gitswitch-ar07-cc-args.$$
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

printf '%s\n' \
    'ar07-build: PASS (complete fingerprints, precise depfiles, frozen probes)'
