#!/bin/sh
# AR-11: deterministic cross-process and signal regressions for the portable
# release-publisher lock supervisor.
# ShellCheck 0.9 misclassifies deliberate fail-closed assertion chains.
# shellcheck disable=SC2015

set -u

fail()
{
    printf 'release-publish-lock-test: ERROR: %s\n' "$*" >&2
    exit 1
}

wait_for_file()
{
    wait_path=$1
    wait_label=$2
    wait_count=0
    while [ ! -s "$wait_path" ] || [ ! -f "$wait_path" ] ||
          [ -L "$wait_path" ]; do
        wait_count=$((wait_count + 1))
        [ "$wait_count" -lt 10 ] ||
            fail "timed out waiting for $wait_label"
        sleep 1
    done
}

assert_absent()
{
    absent_path=$1
    absent_label=$2
    [ ! -e "$absent_path" ] && [ ! -L "$absent_path" ] ||
        fail "$absent_label retained lock state"
}

show_failure_log()
{
    failure_log=$1
    if [ -s "$failure_log" ]; then
        sed -n '1,160p' "$failure_log" >&2
    fi
}

expect_status()
{
    status_label=$1
    expected_status=$2
    actual_status=$3
    status_log=$4
    if [ "$actual_status" -ne "$expected_status" ]; then
        show_failure_log "$status_log"
        fail "$status_label returned $actual_status; expected $expected_status"
    fi
}

wait_for_release()
{
    release_path=$1
    release_label=$2
    release_count=0
    while [ ! -f "$release_path" ] || [ -L "$release_path" ]; do
        release_count=$((release_count + 1))
        [ "$release_count" -lt 15 ] ||
            fail "timed out waiting to release $release_label"
        sleep 1
    done
}

wait_for_pid_exit()
{
    exit_pid=$1
    exit_label=$2
    exit_count=0
    while kill -0 "$exit_pid" 2>/dev/null; do
        exit_count=$((exit_count + 1))
        [ "$exit_count" -lt 12 ] ||
            fail "timed out waiting for $exit_label to exit"
        sleep 1
    done
}

# The same file is installed under private `mkdir` and `chmod` names. These
# modes pause at precise supervisor setup seams without depending on tracing,
# scheduler timing, or platform-specific lock commands.
case ${0##*/} in
    mkdir)
        shim_last_arg=
        for shim_arg do
            shim_last_arg=$shim_arg
        done
        "$AR11_LOCK_REAL_MKDIR" "$@"
        shim_status=$?
        if [ "$shim_status" -ne 0 ] &&
           [ "$shim_last_arg" = "$AR11_LOCK_GATE_PATH" ]; then
            printf '%s\n' ready >"$AR11_LOCK_GATE_READY" || exit 96
            wait_for_release "$AR11_LOCK_GATE_RELEASE" \
                'EEXIST handoff gate'
        fi
        exit "$shim_status"
        ;;
    chmod)
        if [ "$#" -eq 2 ] && [ "$1" = 0700 ] &&
           [ "$2" = "$AR11_LOCK_GATE_PATH" ] &&
           "$AR11_LOCK_REAL_MKDIR" "$AR11_LOCK_GATE_ONCE" \
               2>/dev/null; then
            printf '%s\n' ready >"$AR11_LOCK_GATE_READY" || exit 96
            wait_for_release "$AR11_LOCK_GATE_RELEASE" \
                'post-mkdir signal gate'
        fi
        exec "$AR11_LOCK_REAL_CHMOD" "$@"
        ;;
esac

# Private child modes run beneath the supervisor and validate only state in
# this test's temporary namespace.
case ${1-} in
    --lease-descendant-worker)
        [ "$#" -eq 3 ] || fail 'invalid lease-worker fixture invocation'
        [ "${GITSWITCH_RELEASE_LOCK_LEASE_FD-}" = 7 ] ||
            fail 'lease worker did not inherit the reserved descriptor'
        trap '' 1 2 3 15
        printf '%s\n' noise >&7 || fail 'lease worker cannot write its lease'
        printf '%s\n' "$$" >"$2" ||
            fail 'lease worker cannot publish readiness'
        wait_for_release "$3" 'lease worker'
        exit 0
        ;;
    --lease-parent)
        [ "$#" -eq 6 ] || fail 'invalid lease-parent fixture invocation'
        [ "${GITSWITCH_RELEASE_LOCK_LEASE_FD-}" = 7 ] ||
            fail 'lease parent did not inherit the reserved descriptor'
        lease_worker_ready=$2
        lease_worker_release=$3
        lease_parent_ready=$4
        lease_parent_pid_file=$5
        lease_parent_term=$6
        sh "$0" --lease-descendant-worker "$lease_worker_ready" \
            "$lease_worker_release" &
        printf '%s\n' "$$" >"$lease_parent_pid_file" ||
            fail 'lease parent cannot publish its PID'
        wait_for_file "$lease_worker_ready" 'lease-worker readiness'
        printf '%s\n' ready >"$lease_parent_ready" ||
            fail 'lease parent cannot publish readiness'
        lease_parent_signal()
        {
            printf '%s\n' terminated >"$lease_parent_term" 2>/dev/null || :
            exit 0
        }
        trap lease_parent_signal 1 2 3 15
        while :; do
            sleep 1
        done
        ;;
    --hold-lock)
        [ "$#" -eq 3 ] || fail 'invalid hold-lock fixture invocation'
        printf '%s\n' ready >"$2" || fail 'cannot publish holder readiness'
        wait_for_release "$3" 'lock holder'
        exit 0
        ;;
    --validate-token)
        [ "$#" -eq 2 ] || fail 'invalid token fixture invocation'
        fixture_lock=$2
        fixture_token=${GITSWITCH_RELEASE_LOCK_TOKEN-}
        [ -n "$fixture_token" ] && [ -d "$fixture_token" ] &&
        [ ! -L "$fixture_token" ] || fail 'supervisor omitted a real token'
        case $fixture_token in
            "$fixture_lock"/token.*) ;;
            *) fail 'supervisor token escaped its lock root' ;;
        esac
        [ -f "$fixture_lock/owner" ] &&
        [ ! -L "$fixture_lock/owner" ] ||
            fail 'supervisor omitted a regular owner record'
        fixture_owner=
        IFS= read -r fixture_owner <"$fixture_lock/owner" ||
            fail 'cannot read supervisor owner record'
        [ "$fixture_owner" = "$fixture_token" ] ||
            fail 'supervisor owner does not name its token'
        exit 0
        ;;
    --retain-token-residue)
        [ "$#" -eq 1 ] || fail 'invalid residue fixture invocation'
        fixture_token=${GITSWITCH_RELEASE_LOCK_TOKEN-}
        [ -n "$fixture_token" ] && [ -d "$fixture_token" ] &&
        [ ! -L "$fixture_token" ] || fail 'residue fixture lacks a real token'
        printf '%s\n' forensic-residue >"$fixture_token/residue" ||
            fail 'cannot create token residue'
        exit 0
        ;;
    --catch-signal)
        [ "$#" -eq 3 ] || fail 'invalid signal-catch fixture invocation'
        fixture_signal=$2
        fixture_status=$3
        case $fixture_signal:$fixture_status in
            INT:42|QUIT:43) ;;
            *) fail 'invalid signal-catch fixture values' ;;
        esac
        trap 'exit "$fixture_status"' "$fixture_signal"
        kill -"$fixture_signal" "$$" ||
            fail 'signal-catch fixture cannot signal itself'
        exit 99
        ;;
    --expect-ignored-signal)
        [ "$#" -eq 2 ] || fail 'invalid ignored-signal fixture invocation'
        fixture_signal=$2
        case $fixture_signal in
            INT|QUIT) ;;
            *) fail 'invalid ignored-signal fixture value' ;;
        esac
        trap 'exit 98' "$fixture_signal"
        kill -"$fixture_signal" "$$" ||
            fail 'ignored-signal fixture cannot signal itself'
        exit 0
        ;;
esac

[ "$#" -eq 1 ] || fail "usage: $0 PROJECT_ROOT"
project_root=$1
project_root=$(CDPATH='' cd "$project_root" 2>/dev/null && pwd -P) ||
    fail "project root is not a readable directory: $1"
lock_script=$project_root/tools/release_publish_lock.sh
[ -f "$lock_script" ] && [ ! -L "$lock_script" ] &&
[ -r "$lock_script" ] || fail 'release-publisher lock script is unavailable'

case $0 in
    /*) self=$0 ;;
    *) self=$PWD/$0 ;;
esac
self_dir=${self%/*}
self_name=${self##*/}
self_dir=$(CDPATH='' cd "$self_dir" 2>/dev/null && pwd -P) ||
    fail 'cannot resolve test script directory'
self=$self_dir/$self_name

real_mkdir=$(command -v mkdir 2>/dev/null) || fail 'mkdir is unavailable'
real_chmod=$(command -v chmod 2>/dev/null) || fail 'chmod is unavailable'
case $real_mkdir:$real_chmod in
    /*:/*) ;;
    *) fail 'mkdir and chmod must resolve to absolute paths' ;;
esac
original_path=${PATH:-/usr/bin:/bin}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-release-lock.XXXXXX") ||
    fail 'cannot create private temporary directory'
holder_pid=
contender_pid=
signal_pid=
delayed_wrapper_pid=
delayed_supervisor_pid=
delayed_worker_pid=
long_wrapper_pid=
long_supervisor_pid=
long_worker_pid=
holder_release=
contender_release=
signal_release=
delayed_worker_release=
long_worker_release=

terminate_and_reap()
{
    terminate_pid=$1
    kill -TERM "$terminate_pid" 2>/dev/null || :
    terminate_count=0
    while kill -0 "$terminate_pid" 2>/dev/null; do
        terminate_count=$((terminate_count + 1))
        if [ "$terminate_count" -ge 5 ]; then
            kill -KILL "$terminate_pid" 2>/dev/null || :
            break
        fi
        sleep 1
    done
    wait "$terminate_pid" 2>/dev/null || :
}

cleanup()
{
    cleanup_status=$?
    trap - 0 1 2 3 15
    for cleanup_release in "$holder_release" "$contender_release" \
        "$signal_release" "$delayed_worker_release" \
        "$long_worker_release"; do
        if [ -n "$cleanup_release" ]; then
            printf '%s\n' release >"$cleanup_release" 2>/dev/null || :
        fi
    done
    for cleanup_pid in "$holder_pid" "$contender_pid" "$signal_pid" \
        "$delayed_supervisor_pid" "$delayed_wrapper_pid" \
        "$delayed_worker_pid" "$long_supervisor_pid" \
        "$long_wrapper_pid" "$long_worker_pid"; do
        if [ -n "$cleanup_pid" ]; then
            terminate_and_reap "$cleanup_pid"
        fi
    done
    rm -rf "$tmp"
    exit "$cleanup_status"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

# A normal child sees the unique token and matching owner. Successful cleanup
# removes the owner, token, and root lock as one completed retirement.
normal_lock=$tmp/normal.lock
normal_log=$tmp/normal.err
if sh "$lock_script" "$normal_lock" sh "$self" \
    --validate-token "$normal_lock" >"$tmp/normal.out" 2>"$normal_log"; then
    normal_status=0
else
    normal_status=$?
fi
expect_status 'normal lock cleanup' 0 "$normal_status" "$normal_log"
assert_absent "$normal_lock" 'normal cleanup'

# POSIX shells may add SIGINT/SIGQUIT ignores when launching an asynchronous
# list. The supervisor itself needs a background child so it can forward
# signals, but those shell-added ignores must not prevent the exec'd command
# from installing its own handlers. Each child self-signals after installing a
# distinct handler; a leaked ignore would instead fall through to status 99.
for signal_case in INT:42 QUIT:43; do
    signal_name=${signal_case%:*}
    expected_status=${signal_case#*:}
    disposition_lock=$tmp/disposition-$signal_name.lock
    disposition_log=$tmp/disposition-$signal_name.err
    if sh "$lock_script" "$disposition_lock" sh "$self" \
        --catch-signal "$signal_name" "$expected_status" \
        >"$tmp/disposition-$signal_name.out" 2>"$disposition_log"; then
        disposition_status=0
    else
        disposition_status=$?
    fi
    expect_status "$signal_name child disposition" "$expected_status" \
        "$disposition_status" "$disposition_log"
    assert_absent "$disposition_lock" "$signal_name disposition cleanup"
done

# Conversely, an ignore policy that predates this supervisor is authoritative.
# Enter the supervisor through a shell that explicitly ignores one signal;
# POSIX shells keep such an inherited ignore unchangeable. The child attempts
# to replace it with a handler and self-signals: status 0 proves the signal
# remained ignored, while status 98 would expose an accidental resurrection.
for signal_name in INT QUIT; do
    inherited_lock=$tmp/inherited-$signal_name.lock
    inherited_log=$tmp/inherited-$signal_name.err
    if sh -c '
        inherited_signal=$1
        shift
        trap "" "$inherited_signal"
        exec "$@"
    ' sh "$signal_name" sh "$lock_script" "$inherited_lock" \
        sh "$self" --expect-ignored-signal "$signal_name" \
        >"$tmp/inherited-$signal_name.out" 2>"$inherited_log"; then
        inherited_status=0
    else
        inherited_status=$?
    fi
    expect_status "inherited $signal_name ignore" 0 "$inherited_status" \
        "$inherited_log"
    assert_absent "$inherited_lock" "$signal_name inherited-ignore cleanup"
done

# Contender B receives EEXIST while A owns the root and pauses before returning
# that result. A then exits and removes the root. B must recognize that the
# path disappeared during handoff, retry mkdir, acquire, and clean normally.
handoff_lock=$tmp/handoff.lock
holder_ready=$tmp/holder.ready
holder_release=$tmp/holder.release
contender_ready=$tmp/contender.ready
contender_release=$tmp/contender.release
handoff_bin=$tmp/handoff-bin
"$real_mkdir" "$handoff_bin" || fail 'cannot create handoff shim directory'
ln -s "$self" "$handoff_bin/mkdir" || fail 'cannot install mkdir shim'
sh "$lock_script" "$handoff_lock" sh "$self" \
    --hold-lock "$holder_ready" "$holder_release" \
    >"$tmp/holder.out" 2>"$tmp/holder.err" &
holder_pid=$!
wait_for_file "$holder_ready" 'lock-holder readiness'
wait_for_file "$handoff_lock/owner" 'lock-holder owner record'
AR11_LOCK_REAL_MKDIR=$real_mkdir \
AR11_LOCK_GATE_PATH=$handoff_lock \
AR11_LOCK_GATE_READY=$contender_ready \
AR11_LOCK_GATE_RELEASE=$contender_release \
PATH=$handoff_bin:$original_path \
GITSWITCH_RELEASE_LOCK_ATTEMPTS=5 \
    sh "$lock_script" "$handoff_lock" sh -c ':' \
    >"$tmp/contender.out" 2>"$tmp/contender.err" &
contender_pid=$!
wait_for_file "$contender_ready" 'EEXIST contender gate'
printf '%s\n' release >"$holder_release" ||
    fail 'cannot release lock holder'
if wait "$holder_pid"; then
    holder_status=0
else
    holder_status=$?
fi
holder_pid=
expect_status 'EEXIST handoff holder' 0 "$holder_status" "$tmp/holder.err"
assert_absent "$handoff_lock" 'released EEXIST holder'
printf '%s\n' release >"$contender_release" ||
    fail 'cannot release EEXIST contender gate'
if wait "$contender_pid"; then
    contender_status=0
else
    contender_status=$?
fi
contender_pid=
expect_status 'EEXIST handoff contender' 0 "$contender_status" \
    "$tmp/contender.err"
assert_absent "$handoff_lock" 'EEXIST handoff'

# Gate the first exact chmod 0700 after the root mkdir. TERM arrives while no
# token or owner exists. Once chmod returns, the recorded signal must make the
# supervisor exit 143 and retire the root instead of leaking stale state.
signal_lock=$tmp/signal.lock
signal_ready=$tmp/signal.ready
signal_release=$tmp/signal.release
signal_once=$tmp/signal.once
signal_bin=$tmp/signal-bin
"$real_mkdir" "$signal_bin" || fail 'cannot create signal shim directory'
ln -s "$self" "$signal_bin/chmod" || fail 'cannot install chmod shim'
AR11_LOCK_REAL_MKDIR=$real_mkdir \
AR11_LOCK_REAL_CHMOD=$real_chmod \
AR11_LOCK_GATE_PATH=$signal_lock \
AR11_LOCK_GATE_READY=$signal_ready \
AR11_LOCK_GATE_RELEASE=$signal_release \
AR11_LOCK_GATE_ONCE=$signal_once \
PATH=$signal_bin:$original_path \
    sh "$lock_script" "$signal_lock" sh -c ':' \
    >"$tmp/signal.out" 2>"$tmp/signal.err" &
signal_pid=$!
wait_for_file "$signal_ready" 'post-mkdir signal gate'
[ -d "$signal_lock" ] && [ ! -L "$signal_lock" ] ||
    fail 'post-mkdir signal gate omitted its root lock'
[ ! -e "$signal_lock/owner" ] && [ ! -L "$signal_lock/owner" ] ||
    fail 'post-mkdir signal gate published an owner too early'
set -- "$signal_lock"/token.*
[ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ] ||
    fail 'post-mkdir signal gate created a token too early'
kill -TERM "$signal_pid" || fail 'cannot terminate setup-gated supervisor'
printf '%s\n' release >"$signal_release" ||
    fail 'cannot release post-mkdir signal gate'
if wait "$signal_pid"; then
    signal_status=0
else
    signal_status=$?
fi
signal_pid=
expect_status 'post-mkdir TERM' 143 "$signal_status" "$tmp/signal.err"
assert_absent "$signal_lock" 'post-mkdir TERM cleanup'

# The direct child may leave an inherited descendant alive after TERM. A
# newline written on descriptor 9 proves the observer drains until EOF instead
# of treating one read as completion. Releasing that descendant within the
# bound must let the supervisor return the original signal status and retire
# the complete lock only afterward.
delayed_lock=$tmp/delayed-descendant.lock
delayed_parent_ready=$tmp/delayed-parent.ready
delayed_parent_pid_file=$tmp/delayed-parent.pid
delayed_parent_term=$tmp/delayed-parent.term
delayed_worker_ready=$tmp/delayed-worker.ready
delayed_worker_release=$tmp/delayed-worker.release
delayed_supervisor_pid_file=$tmp/delayed-supervisor.pid
delayed_status=$tmp/delayed-supervisor.status
delayed_log=$tmp/delayed-supervisor.err
(
    wrapped_status=0
    GITSWITCH_RELEASE_LOCK_LEASE_ATTEMPTS=10 \
        sh "$lock_script" "$delayed_lock" sh "$self" --lease-parent \
        "$delayed_worker_ready" "$delayed_worker_release" \
        "$delayed_parent_ready" "$delayed_parent_pid_file" \
        "$delayed_parent_term" >"$tmp/delayed-supervisor.out" \
        2>"$delayed_log" &
    wrapped_supervisor_pid=$!
    wrapped_pid_tmp=$delayed_supervisor_pid_file.tmp.$$
    printf '%s\n' "$wrapped_supervisor_pid" >"$wrapped_pid_tmp" || exit 95
    mv -f "$wrapped_pid_tmp" "$delayed_supervisor_pid_file" || exit 96
    wait "$wrapped_supervisor_pid" || wrapped_status=$?
    wrapped_status_tmp=$delayed_status.tmp.$$
    printf '%s\n' "$wrapped_status" >"$wrapped_status_tmp" || exit 97
    mv -f "$wrapped_status_tmp" "$delayed_status" || exit 98
    exit "$wrapped_status"
) &
delayed_wrapper_pid=$!
wait_for_file "$delayed_supervisor_pid_file" 'delayed supervisor PID'
wait_for_file "$delayed_parent_ready" 'delayed lease-parent readiness'
wait_for_file "$delayed_parent_pid_file" 'delayed lease-parent PID'
wait_for_file "$delayed_worker_ready" 'delayed lease-worker readiness'
delayed_supervisor_pid=$(sed -n '1p' "$delayed_supervisor_pid_file")
delayed_parent_pid=$(sed -n '1p' "$delayed_parent_pid_file")
delayed_worker_pid=$(sed -n '1p' "$delayed_worker_ready")
case $delayed_supervisor_pid:$delayed_parent_pid:$delayed_worker_pid in
    *[!0-9:]*|::*|:*:|:*) fail 'delayed lease fixture published invalid PIDs' ;;
esac
wait_for_file "$delayed_lock/owner" 'delayed descendant owner record'
kill -TERM "$delayed_supervisor_pid" ||
    fail 'cannot terminate delayed-descendant supervisor'
wait_for_file "$delayed_parent_term" 'delayed lease-parent TERM'
wait_for_pid_exit "$delayed_parent_pid" 'delayed direct child'
sleep 1
[ ! -e "$delayed_status" ] && [ ! -L "$delayed_status" ] ||
    fail 'supervisor completed while its delayed descendant held the lease'
[ -d "$delayed_lock" ] && [ ! -L "$delayed_lock" ] &&
[ -s "$delayed_lock/owner" ] ||
    fail 'supervisor released ownership before its delayed descendant'
printf '%s\n' release >"$delayed_worker_release" ||
    fail 'cannot release delayed lease worker'
wait_for_file "$delayed_status" 'delayed supervisor status'
if wait "$delayed_wrapper_pid"; then
    delayed_wrapper_status=0
else
    delayed_wrapper_status=$?
fi
delayed_wrapper_pid=
delayed_supervisor_pid=
expect_status 'delayed-descendant TERM' 143 "$delayed_wrapper_status" \
    "$delayed_log"
expect_status 'delayed-descendant status record' 143 \
    "$(sed -n '1p' "$delayed_status")" "$delayed_log"
assert_absent "$delayed_lock" 'delayed-descendant cleanup'
wait_for_pid_exit "$delayed_worker_pid" 'released delayed descendant'
delayed_worker_pid=

# A descendant that outlives the bounded wait is still using the protected
# generation. The supervisor must return TERM while retaining the exact root,
# owner, token, and FIFO. A later descendant exit cannot trigger delayed
# cleanup after the supervisor has deliberately failed closed.
long_lock=$tmp/long-descendant.lock
long_parent_ready=$tmp/long-parent.ready
long_parent_pid_file=$tmp/long-parent.pid
long_parent_term=$tmp/long-parent.term
long_worker_ready=$tmp/long-worker.ready
long_worker_release=$tmp/long-worker.release
long_supervisor_pid_file=$tmp/long-supervisor.pid
long_status=$tmp/long-supervisor.status
long_log=$tmp/long-supervisor.err
(
    wrapped_status=0
    GITSWITCH_RELEASE_LOCK_LEASE_ATTEMPTS=1 \
        sh "$lock_script" "$long_lock" sh "$self" --lease-parent \
        "$long_worker_ready" "$long_worker_release" \
        "$long_parent_ready" "$long_parent_pid_file" \
        "$long_parent_term" >"$tmp/long-supervisor.out" \
        2>"$long_log" &
    wrapped_supervisor_pid=$!
    wrapped_pid_tmp=$long_supervisor_pid_file.tmp.$$
    printf '%s\n' "$wrapped_supervisor_pid" >"$wrapped_pid_tmp" || exit 95
    mv -f "$wrapped_pid_tmp" "$long_supervisor_pid_file" || exit 96
    wait "$wrapped_supervisor_pid" || wrapped_status=$?
    wrapped_status_tmp=$long_status.tmp.$$
    printf '%s\n' "$wrapped_status" >"$wrapped_status_tmp" || exit 97
    mv -f "$wrapped_status_tmp" "$long_status" || exit 98
    exit "$wrapped_status"
) &
long_wrapper_pid=$!
wait_for_file "$long_supervisor_pid_file" 'long supervisor PID'
wait_for_file "$long_parent_ready" 'long lease-parent readiness'
wait_for_file "$long_worker_ready" 'long lease-worker readiness'
long_supervisor_pid=$(sed -n '1p' "$long_supervisor_pid_file")
long_worker_pid=$(sed -n '1p' "$long_worker_ready")
case $long_supervisor_pid:$long_worker_pid in
    *[!0-9:]*|:*|*:) fail 'long lease fixture published invalid PIDs' ;;
esac
wait_for_file "$long_lock/owner" 'long descendant owner record'
kill -TERM "$long_supervisor_pid" ||
    fail 'cannot terminate long-descendant supervisor'
wait_for_file "$long_status" 'long-descendant timeout status'
if wait "$long_wrapper_pid"; then
    long_wrapper_status=0
else
    long_wrapper_status=$?
fi
long_wrapper_pid=
long_supervisor_pid=
expect_status 'long-descendant TERM' 143 "$long_wrapper_status" "$long_log"
expect_status 'long-descendant status record' 143 \
    "$(sed -n '1p' "$long_status")" "$long_log"
grep -F 'descendant lease remained active after TERM; retaining lock ownership:' \
    "$long_log" >/dev/null || {
    show_failure_log "$long_log"
    fail 'long descendant lacked a precise retained-lock diagnostic'
}
[ -d "$long_lock" ] && [ ! -L "$long_lock" ] ||
    fail 'long-descendant timeout removed its lock root'
[ -f "$long_lock/owner" ] && [ ! -L "$long_lock/owner" ] ||
    fail 'long-descendant timeout removed its owner record'
long_owner=
IFS= read -r long_owner <"$long_lock/owner" ||
    fail 'cannot read long-descendant owner record'
set -- "$long_lock"/token.*
[ "$#" -eq 1 ] && [ -d "$1" ] && [ ! -L "$1" ] ||
    fail 'long-descendant timeout did not retain exactly one token'
long_token=$1
[ "$long_owner" = "$long_token" ] ||
    fail 'long-descendant timeout changed token ownership'
[ -p "$long_token/descendant.lease" ] &&
[ ! -L "$long_token/descendant.lease" ] ||
    fail 'long-descendant timeout removed its inherited lease FIFO'
printf '%s\n' release >"$long_worker_release" ||
    fail 'cannot release long lease worker'
wait_for_pid_exit "$long_worker_pid" 'released long descendant'
long_worker_pid=
sleep 1
[ -d "$long_lock" ] && [ ! -L "$long_lock" ] &&
[ -f "$long_lock/owner" ] && [ ! -L "$long_lock/owner" ] &&
[ -d "$long_token" ] && [ ! -L "$long_token" ] &&
[ -p "$long_token/descendant.lease" ] &&
[ ! -L "$long_token/descendant.lease" ] ||
    fail 'long-descendant exit triggered delayed lock cleanup'

# Unexpected token contents make rmdir fail. Cleanup must return failure and
# retain the exact owner, token, root, and residue for forensic recovery; it
# must not erase ownership evidence before proving the token is empty.
residue_lock=$tmp/residue.lock
residue_log=$tmp/residue.err
if sh "$lock_script" "$residue_lock" sh "$self" \
    --retain-token-residue >"$tmp/residue.out" 2>"$residue_log"; then
    residue_status=0
else
    residue_status=$?
fi
expect_status 'token-residue cleanup' 1 "$residue_status" "$residue_log"
[ -d "$residue_lock" ] && [ ! -L "$residue_lock" ] ||
    fail 'token-residue cleanup removed its root lock'
[ -f "$residue_lock/owner" ] && [ ! -L "$residue_lock/owner" ] ||
    fail 'token-residue cleanup erased its owner record'
residue_owner=
IFS= read -r residue_owner <"$residue_lock/owner" ||
    fail 'cannot read retained token-residue owner record'
set -- "$residue_lock"/token.*
[ "$#" -eq 1 ] && [ -d "$1" ] && [ ! -L "$1" ] ||
    fail 'token-residue cleanup did not retain exactly one real token'
residue_token=$1
[ "$residue_owner" = "$residue_token" ] ||
    fail 'retained owner no longer names the retained token'
[ -f "$residue_token/residue" ] && [ ! -L "$residue_token/residue" ] ||
    fail 'token-residue cleanup lost its forensic residue'
residue_value=
IFS= read -r residue_value <"$residue_token/residue" ||
    fail 'cannot read retained forensic residue'
[ "$residue_value" = forensic-residue ] ||
    fail 'retained forensic residue changed'

printf '%s\n' \
    'release-publish-lock-test: PASS (cleanup, handoff, signal leases, retention)'
