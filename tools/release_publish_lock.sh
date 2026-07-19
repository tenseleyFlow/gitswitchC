#!/bin/sh
# Serialize release-publisher generation, use, and cleanup across Make processes.

set -u
umask 077

fail()
{
    printf 'release-publish-lock: ERROR: %s\n' "$*" >&2
    exit 2
}

[ "$#" -ge 2 ] || fail "usage: $0 LOCK_DIRECTORY COMMAND [ARG ...]"
lock_dir=$1
shift

case $lock_dir in
    ''|/|.|..|*'/../'*|../*|*/..)
        fail "unsafe lock directory: $lock_dir"
        ;;
esac
case $lock_dir in
    */*) lock_parent=${lock_dir%/*} ;;
    *) lock_parent=. ;;
esac
[ -d "$lock_parent" ] && [ ! -L "$lock_parent" ] ||
    fail "lock parent is not a real directory: $lock_parent"

host_os=$(uname -s 2>/dev/null) || fail "cannot identify host platform"
normalize_private_acl()
{
    private_path=$1
    case $host_os in
        Linux) : ;;
        Darwin) chmod -N "$private_path" || return 1 ;;
        FreeBSD)
            private_nfs4=$(getconf ACL_NFS4 "$private_path" 2>/dev/null) ||
                return 1
            private_extended=$(getconf ACL_EXTENDED "$private_path" 2>/dev/null) ||
                return 1
            case $private_nfs4:$private_extended in
                1:0|1:1) setfacl -b "$private_path" || return 1 ;;
                0:1)
                    setfacl -b "$private_path" &&
                        setfacl -k "$private_path" || return 1
                    ;;
                0:0) : ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
    chmod 0700 "$private_path"
}
token_dir=
lock_owned=0
owner_published=0
child_pid=
pending_signal_name=
pending_signal_status=
lease_path=
lease_done=
lease_done_tmp=
lease_reader_pid=
lease_started=0
command_launched=0
preserve_owned_lock=0
lease_wait_context='command completion'

lease_attempt_limit=${GITSWITCH_RELEASE_LOCK_LEASE_ATTEMPTS:-5}
case $lease_attempt_limit in
    [1-9]|[1-5][0-9]|60) ;;
    *) fail "invalid descendant-lease attempt limit" ;;
esac

stop_lease_reader()
{
    if [ -n "$lease_reader_pid" ]; then
        kill -TERM "$lease_reader_pid" 2>/dev/null || :
        wait "$lease_reader_pid" 2>/dev/null || :
        lease_reader_pid=
    fi
}

lease_marker_is_closed()
{
    if [ ! -e "$lease_done" ] && [ ! -L "$lease_done" ]; then
        return 1
    fi
    [ -s "$lease_done" ] && [ -f "$lease_done" ] &&
    [ ! -L "$lease_done" ] || return 2
    lease_done_value=
    {
        IFS= read -r lease_done_value || return 2
        if IFS= read -r _; then
            return 2
        fi
    } <"$lease_done"
    [ "$lease_done_value" = closed ] || return 2
    return 0
}

preserve_descendant_lease()
{
    preserve_reason=$1
    printf 'release-publish-lock: ERROR: %s; retaining lock ownership: %s\n' \
        "$preserve_reason" "$lock_dir" >&2
    preserve_owned_lock=1
    stop_lease_reader
    return 1
}

remove_unlaunched_lease()
{
    stop_lease_reader
    for unlaunched_path in "$lease_done_tmp" "$lease_done"; do
        if [ -e "$unlaunched_path" ] || [ -L "$unlaunched_path" ]; then
            [ -f "$unlaunched_path" ] && [ ! -L "$unlaunched_path" ] ||
                return 1
            rm -f "$unlaunched_path" || return 1
        fi
    done
    if [ -e "$lease_path" ] || [ -L "$lease_path" ]; then
        [ -p "$lease_path" ] && [ ! -L "$lease_path" ] || return 1
        rm -f "$lease_path" || return 1
    fi
    lease_started=0
    return 0
}

settle_descendant_lease()
{
    [ "$lease_started" -eq 1 ] || return 0
    if [ "$command_launched" -eq 0 ]; then
        remove_unlaunched_lease ||
            preserve_descendant_lease \
                'descendant lease setup could not be retired'
        return $?
    fi

    lease_fast_attempt=0
    lease_wait_attempt=0
    while :; do
        if lease_marker_is_closed; then
            break
        else
            lease_marker_status=$?
        fi
        if [ "$lease_marker_status" -eq 2 ]; then
            preserve_descendant_lease \
                'descendant lease completion marker is invalid'
            return $?
        fi
        if [ "$lease_fast_attempt" -lt 10 ]; then
            lease_fast_attempt=$((lease_fast_attempt + 1))
            sleep 0
            continue
        fi
        if [ "$lease_wait_attempt" -ge "$lease_attempt_limit" ]; then
            stop_lease_reader
            if lease_marker_is_closed; then
                break
            else
                lease_marker_status=$?
            fi
            if [ "$lease_marker_status" -eq 2 ]; then
                preserve_descendant_lease \
                    'descendant lease completion marker is invalid'
                return $?
            fi
            preserve_descendant_lease \
                "descendant lease remained active after $lease_wait_context"
            return $?
        fi
        sleep 1
        lease_wait_attempt=$((lease_wait_attempt + 1))
    done

    stop_lease_reader
    lease_marker_is_closed || {
        preserve_descendant_lease \
            'descendant lease completion marker changed during retirement'
        return $?
    }
    [ ! -e "$lease_done_tmp" ] && [ ! -L "$lease_done_tmp" ] || {
        preserve_descendant_lease \
            'descendant lease retained an incomplete completion marker'
        return $?
    }
    [ -p "$lease_path" ] && [ ! -L "$lease_path" ] || {
        preserve_descendant_lease \
            'descendant lease path changed during retirement'
        return $?
    }
    rm -f "$lease_done" || {
        preserve_descendant_lease \
            'descendant lease completion marker could not be removed'
        return $?
    }
    rm -f "$lease_path" || {
        preserve_descendant_lease \
            'descendant lease path could not be removed'
        return $?
    }
    lease_started=0
    return 0
}

cleanup_lock()
{
    cleanup_status=$1
    trap - 0
    trap '' 1 2 3 15
    cleanup_failed=0
    settle_descendant_lease || cleanup_failed=1
    if [ "$lock_owned" -eq 1 ]; then
        remove_owned_lock=1
        remove_owner_file=0
        owner_value=
        if [ -f "$lock_dir/owner" ] && [ ! -L "$lock_dir/owner" ]; then
            IFS= read -r owner_value <"$lock_dir/owner" || cleanup_failed=1
        elif [ "$owner_published" -eq 1 ] ||
             [ -e "$lock_dir/owner" ] || [ -L "$lock_dir/owner" ]; then
            cleanup_failed=1
        fi
        if [ -n "$token_dir" ] && [ "$owner_value" = "$token_dir" ]; then
            remove_owner_file=1
        elif [ "$owner_published" -eq 0 ] &&
             [ ! -e "$lock_dir/owner" ] && [ ! -L "$lock_dir/owner" ]; then
            :
        else
            printf '%s\n' \
                'release-publish-lock: ERROR: lock ownership changed during use' \
                >&2
            cleanup_failed=1
            remove_owned_lock=0
        fi
        if [ "$preserve_owned_lock" -eq 1 ]; then
            cleanup_failed=1
            remove_owned_lock=0
        fi
        if [ "$remove_owned_lock" -eq 1 ]; then
            if [ -n "$token_dir" ]; then
                if rmdir "$token_dir" 2>/dev/null; then
                    token_dir=
                else
                    cleanup_failed=1
                    remove_owned_lock=0
                fi
            fi
        fi
        if [ "$remove_owned_lock" -eq 1 ] &&
           [ "$remove_owner_file" -eq 1 ]; then
            if ! rm -f "$lock_dir/owner"; then
                cleanup_failed=1
                remove_owned_lock=0
            fi
        fi
        if [ "$remove_owned_lock" -eq 1 ]; then
            rmdir "$lock_dir" || cleanup_failed=1
        fi
    fi
    if [ "$lock_owned" -eq 0 ] && [ -n "$token_dir" ]; then
        rmdir "$token_dir" 2>/dev/null || cleanup_failed=1
    fi
    if [ "$cleanup_failed" -ne 0 ] && [ "$cleanup_status" -eq 0 ]; then
        cleanup_status=1
    fi
    exit "$cleanup_status"
}

# shellcheck disable=SC2329
terminate_child()
{
    terminate_signal=$1
    kill -"$terminate_signal" "$child_pid" 2>/dev/null || :
    terminate_tries=0
    while kill -0 "$child_pid" 2>/dev/null; do
        terminate_tries=$((terminate_tries + 1))
        if [ "$terminate_tries" -ge 5 ]; then
            kill -KILL "$child_pid" 2>/dev/null || :
            break
        fi
        sleep 1
    done
    wait "$child_pid" 2>/dev/null || :
    child_pid=
}

# shellcheck disable=SC2329
forward_signal()
{
    forward_signal_name=$1
    forward_status=$2
    trap - 0
    trap '' 1 2 3 15
    lease_wait_context=$forward_signal_name
    if [ -n "$child_pid" ]; then
        terminate_child "$forward_signal_name"
    fi
    cleanup_lock "$forward_status"
}

# During setup and child launch, record signals instead of exiting between an
# atomic resource creation and the shell assignment that records ownership.
# The next boundary observes the pending signal with enough state to clean up.
# shellcheck disable=SC2329
record_signal()
{
    pending_signal_name=$1
    pending_signal_status=$2
}

abort_if_signalled()
{
    if [ -n "$pending_signal_name" ]; then
        abort_signal_name=$pending_signal_name
        abort_signal_status=$pending_signal_status
        pending_signal_name=
        pending_signal_status=
        forward_signal "$abort_signal_name" "$abort_signal_status"
    fi
}

trap 'cleanup_lock $?' 0
trap 'record_signal HUP 129' 1
trap 'record_signal INT 130' 2
trap 'record_signal QUIT 131' 3
trap 'record_signal TERM 143' 15

lock_attempt_limit=${GITSWITCH_RELEASE_LOCK_ATTEMPTS:-30}
case $lock_attempt_limit in
    [1-9]|[1-5][0-9]|60) ;;
    *) fail "invalid lock-attempt limit" ;;
esac
lock_attempt=0
disappeared_attempt=0
while :; do
    if mkdir -m 0700 "$lock_dir" 2>/dev/null; then
        lock_owned=1
        abort_if_signalled
        break
    fi
    abort_if_signalled
    if [ -L "$lock_dir" ]; then
        fail "lock path is a symlink: $lock_dir"
    fi
    if [ ! -e "$lock_dir" ] && [ ! -L "$lock_dir" ]; then
        disappeared_attempt=$((disappeared_attempt + 1))
        if [ "$disappeared_attempt" -gt "$lock_attempt_limit" ]; then
            fail "release publisher lock changed too often: $lock_dir"
        fi
        continue
    fi
    [ -d "$lock_dir" ] || {
        fail "lock path has an invalid shape: $lock_dir"
    }
    lock_attempt=$((lock_attempt + 1))
    if [ "$lock_attempt" -ge "$lock_attempt_limit" ]; then
        fail "release publisher is busy or its lock is stale: $lock_dir"
    fi
    sleep 1
    abort_if_signalled
done
if ! normalize_private_acl "$lock_dir"; then
    abort_if_signalled
    fail "cannot secure release-publisher lock"
fi
abort_if_signalled
token_dir=$(mktemp -d "$lock_dir/token.XXXXXX") ||
    fail "cannot create unique lock token"
abort_if_signalled
if ! normalize_private_acl "$token_dir"; then
    abort_if_signalled
    fail "cannot secure unique lock token"
fi
abort_if_signalled
if ! printf '%s\n' "$token_dir" >"$lock_dir/owner"; then
    abort_if_signalled
    fail "cannot publish release-publisher lock ownership"
fi
abort_if_signalled
if ! chmod 0600 "$lock_dir/owner"; then
    abort_if_signalled
    fail "cannot secure release-publisher lock ownership"
fi
owner_published=1
abort_if_signalled

lease_path=$token_dir/descendant.lease
lease_done=$token_dir/descendant.closed
lease_done_tmp=$token_dir/descendant.closed.tmp
if ! mkfifo -m 0600 "$lease_path"; then
    abort_if_signalled
    fail "cannot create descendant lease"
fi
lease_started=1
abort_if_signalled
(
    trap - 0 1 2 3 15
    trap 'exit 1' 1 2 3 15
    while IFS= read -r _; do
        :
    done <"$lease_path"
    printf '%s\n' closed >"$lease_done_tmp" &&
        mv -f "$lease_done_tmp" "$lease_done"
) &
lease_reader_pid=$!
abort_if_signalled

GITSWITCH_RELEASE_LOCK_TOKEN=$token_dir
GITSWITCH_RELEASE_LOCK_LEASE_FD=9
export GITSWITCH_RELEASE_LOCK_TOKEN
export GITSWITCH_RELEASE_LOCK_LEASE_FD

# A non-job-control shell makes SIGINT and SIGQUIT ignored for an asynchronous
# list. Reset those shell-added dispositions in a short-lived subshell before
# exec so the owned command can install its own handlers. POSIX shells keep a
# signal that was already ignored when this supervisor started unchangeable,
# preserving an outer nohup/supervisor policy. exec retains the child PID that
# this script publishes and forwards signals to below.
(
    trap - INT QUIT
    exec "$@" 9>"$lease_path"
) &
child_pid=$!
command_launched=1
trap 'forward_signal HUP 129' 1
trap 'forward_signal INT 130' 2
trap 'forward_signal QUIT 131' 3
trap 'forward_signal TERM 143' 15
abort_if_signalled

if wait "$child_pid"; then
    command_status=0
else
    command_status=$?
fi
child_pid=
cleanup_lock "$command_status"
