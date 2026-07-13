#!/bin/sh
# Deterministic end-to-end repro for the audit findings fixed in accounts.c:
#
#   SIG-01: SIGINT mid-switch (delivered while `git config user.email` is being
#           written) must leave a CONSISTENT identity — fully-old or fully-new,
#           never user.name=new/user.email=old — and must exit by SIGINT.
#   F4:     a switch that fails at the git-config step must leave the
#           previously-active account's SSH agent and current.sock working
#           (ssh-add -l still succeeds), including when the failed target had
#           its own SSH key (previous agent is re-activated on rollback).
#   SIG-02: the interrupted switch must leave no accounts.toml.tmp.* /
#           ~/.ssh/config.gitswitch.* scratch orphans.
#
# Everything runs in one throwaway sandbox below a trusted, pre-existing
# per-user runtime directory: private HOME, XDG_RUNTIME_DIR, keys, and PATH
# shims.  The invoking user's real HOME is never used as a fixture root or
# write target.
# Catchable exits remove the sandbox; even SIGKILL can only strand that private
# runtime directory, never a shim or config file in the invoking HOME.  The
# `git` shim delegates to the real git but can sleep on / fail the identity
# writes (that's what makes the race deterministic). Real ssh-agent/ssh-add are
# used; `ssh` itself is stubbed so no network is touched. Run from anywhere:
#
#   sh tests/repro_sig01.sh
#
# Exits 0 and prints PASS for each check; any failure exits 1.

set -u
# The caller's umask must not weaken generated keys, configuration, or trusted
# executable shims.  Exact chmods below retain the public contract where a
# specific mode is required.
umask 077

ROOT=$(CDPATH='' cd "$(dirname "$0")/.." && pwd -P)
BIN="$ROOT/build/bin/gitswitch"
[ -x "$BIN" ] || { echo "build first: make (missing $BIN)"; exit 1; }

REAL_GIT=$(command -v git) || { echo "git not found"; exit 1; }
command -v ssh-agent >/dev/null || { echo "ssh-agent not found"; exit 1; }

FAILURES=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

SBX=
ACTIVE_PID=
# Invoked indirectly by the EXIT and signal traps installed below.
# shellcheck disable=SC2317,SC2329
cleanup() {
    [ -n "$SBX" ] || return 0
    case $ACTIVE_PID in
        ''|*[!0-9]*) ;;
        *)
            if [ "$ACTIVE_PID" -gt 1 ]; then
                kill "$ACTIVE_PID" 2>/dev/null
                wait "$ACTIVE_PID" 2>/dev/null
            fi
            ;;
    esac
    # Reap any agents the sandbox started (pid sidecars are authoritative).
    for f in "$SBX"/run/gitswitch-ssh/*.pid; do
        [ -f "$f" ] || continue
        pid=$(cat "$f" 2>/dev/null) || continue
        case $pid in
            ''|*[!0-9]*) continue ;;
        esac
        [ "$pid" -gt 1 ] && kill "$pid" 2>/dev/null
    done
    rm -rf "$SBX"
}

# Invoked indirectly by the signal traps installed below.
# shellcheck disable=SC2317,SC2329
on_signal() {
    status=$1
    trap - 0 HUP INT TERM
    cleanup
    exit "$status"
}

# Preserve the triggering status on every ordinary/error exit.  Catchable
# termination uses conventional 128+signal statuses after the same cleanup.
trap 'status=$?; trap - 0 HUP INT TERM; cleanup; exit "$status"' 0
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

# Resolve candidates without changing the caller's working directory.  The
# canonical spelling is used for both ancestry validation and the new root, so
# a lexical symlink cannot smuggle the fixture below HOME or the worktree.
canonical_dir() {
    (CDPATH='' cd "$1" 2>/dev/null && pwd -P)
}

# Match the production executable resolver's ownership and basic mode policy:
# every canonical ancestor must be a directory owned by root or this uid and
# must reject group/other writes.  The real switch below remains the final ACL
# and executable-admission check.
trusted_dir_chain() {
    candidate=$1
    uid=$2
    current=
    rest=${candidate#/}

    while [ -n "$rest" ]; do
        component=${rest%%/*}
        if [ "$rest" = "$component" ]; then
            rest=
        else
            rest=${rest#*/}
        fi
        [ -n "$component" ] || continue
        current=$current/$component
        checked=$(find "$current" -prune -type d \
            \( -user 0 -o -user "$uid" \) \
            ! -perm -020 ! -perm -002 -print 2>/dev/null)
        [ "$checked" = "$current" ] || return 1
    done
}

REAL_HOME=
case ${HOME-} in
    /*) REAL_HOME=$(canonical_dir "$HOME") || REAL_HOME= ;;
esac

# Clear inherited repository, trace-output, and agent channels before the first
# real Git invocation (the worktree-admission probe below).  Several Git trace
# variables are writable path destinations, so delaying this until after root
# selection could already mutate an operator-owned file.
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE \
    GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
    GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM \
    GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS \
    GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT GIT_ASKPASS \
    GIT_TRACE GIT_TRACE_SETUP GIT_TRACE_SHALLOW GIT_TRACE_PACKET \
    GIT_TRACE_PACK_ACCESS GIT_TRACE_CURL GIT_TRACE_CURL_NO_DATA \
    GIT_TRACE_PERFORMANCE GIT_TRACE_REFS GIT_TRACE_FSMONITOR \
    GIT_TRACE2 GIT_TRACE2_EVENT GIT_TRACE2_PERF \
    SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE \
    GPG_AGENT_INFO 2>/dev/null

select_private_root() {
    candidate=$1
    [ -n "$candidate" ] && [ -d "$candidate" ] || return 1
    base=$(canonical_dir "$candidate") || return 1

    if [ -n "$REAL_HOME" ]; then
        case $base in
            "$REAL_HOME"|"$REAL_HOME"/*) return 1 ;;
        esac
    fi
    case $base in
        "$ROOT"|"$ROOT"/*) return 1 ;;
    esac

    uid=$(id -u) || return 1
    trusted_dir_chain "$base" "$uid" || return 1
    SBX=$(mktemp -d "$base/gitswitch-repro.XXXXXX") || {
        SBX=
        return 1
    }
    chmod 700 "$SBX" || {
        rm -rf "$SBX"
        SBX=
        return 1
    }

    # XDG_RUNTIME_DIR is caller-controlled and may itself sit below an
    # unrelated worktree.  Detect that with the pinned real Git while hiding
    # caller repository overrides and global configuration.  Rejecting the
    # candidate lets the selection chain try the conventional runtime roots.
    if (
        unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_CEILING_DIRECTORIES
        inside=$(
            HOME=$SBX GIT_CONFIG_GLOBAL=/dev/null \
                GIT_CONFIG_NOSYSTEM=1 \
                GIT_DISCOVERY_ACROSS_FILESYSTEM=1 \
                "$REAL_GIT" -c 'safe.directory=*' -C "$SBX" \
                    rev-parse --is-inside-work-tree 2>/dev/null
        ) || exit 1
        [ "$inside" = true ]
    ); then
        rm -rf "$SBX"
        SBX=
        return 1
    fi
}

# /tmp itself cannot host positive-control shims: its writable ancestor is
# intentionally rejected by the production resolver.  Prefer the caller's
# runtime directory, then conventional per-user runtime locations; TMPDIR is a
# portable final candidate only when it independently passes the same checks.
uid=$(id -u) || exit 1
select_private_root "${XDG_RUNTIME_DIR-}" ||
    select_private_root "/run/user/$uid" ||
    select_private_root "/var/run/user/$uid" ||
    select_private_root "${TMPDIR-}" || {
        echo "no trusted writable runtime directory outside HOME/worktree" >&2
        echo "set XDG_RUNTIME_DIR to a private directory with trusted ancestry" >&2
        exit 1
    }

# Replace every caller-controlled user-data destination immediately after
# constructing the root and before making any user-relative file.  This keeps
# XDG, Git, GPG, SSH-agent, and generic temporary artifacts inside SBX even
# when the invoking environment points them back into the operator's HOME.
export HOME="$SBX/home"
export XDG_RUNTIME_DIR="$SBX/run"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_STATE_HOME="$HOME/.local/state"
export GNUPGHOME="$HOME/.gnupg"
export TMPDIR="$SBX/tmp"
SHIM_DIR="$SBX/shims"

# --- sandbox ----------------------------------------------------------------
mkdir -m 700 "$HOME" "$XDG_RUNTIME_DIR" "$SHIM_DIR" "$TMPDIR" || exit 1
mkdir -m 700 "$HOME/.ssh" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" \
    "$HOME/.local" "$GNUPGHOME" || exit 1
mkdir -m 700 "$XDG_CONFIG_HOME/gitswitch" "$XDG_DATA_HOME" \
    "$XDG_STATE_HOME" || exit 1
# Switches use global scope, but the reproducer must still start outside Git.
cd "$SBX" || exit 1
# The inherited repository context was cleared before admission.  This ceiling
# additionally prevents later parent changes from becoming discoverable.
export GIT_CEILING_DIRECTORIES="$SBX"
export GIT_CONFIG_NOSYSTEM=1

# git shim: delegates to the real git, but
#   - GS_SLEEP_EMAIL=1: sleeps 4s before the first `config <scope> user.email X`
#     write (marker-once so the rollback's own restore write doesn't re-sleep),
#     creating a wide deterministic window to deliver SIGINT mid-switch;
#   - GS_FAIL_NAME=1: fails the `config <scope> user.name X` write, forcing the
#     switch to fail exactly at the git-config step.
cat > "$SHIM_DIR/git" <<EOF
#!/bin/sh
if [ "\${1:-}" = "config" ] && [ \$# -eq 4 ]; then
    if [ "\$3" = "user.email" ] && [ -n "\${GS_SLEEP_EMAIL:-}" ] && [ ! -e "$SBX/email.mark" ]; then
        : > "$SBX/email.mark"
        sleep 4
    fi
    if [ "\$3" = "user.name" ] && [ -n "\${GS_FAIL_NAME:-}" ]; then
        exit 1
    fi
fi
exec "$REAL_GIT" "\$@"
EOF
chmod 700 "$SHIM_DIR/git"
# ssh stub: the post-switch connection test must not hit the network.
printf '#!/bin/sh\nexit 1\n' > "$SHIM_DIR/ssh"
chmod 700 "$SHIM_DIR/ssh"
export PATH="$SHIM_DIR:$PATH"

# Two passphrase-less test keys (never leave the sandbox).
ssh-keygen -q -t ed25519 -N "" -C "keyA" -f "$SBX/keyA" || exit 1
ssh-keygen -q -t ed25519 -N "" -C "keyB" -f "$SBX/keyB" || exit 1
FP_A=$(ssh-keygen -lf "$SBX/keyA" | awk '{print $2}')
FP_B=$(ssh-keygen -lf "$SBX/keyB" | awk '{print $2}')

cat > "$XDG_CONFIG_HOME/gitswitch/accounts.toml" <<EOF
[settings]
default_scope = "global"

[accounts.1]
name = "old"
email = "old@example.com"
description = "previous identity"

[accounts.2]
name = "new"
email = "new@example.com"
description = "target identity"

[accounts.3]
name = "ssha"
email = "ssha@example.com"
description = "ssh account A"
ssh_key = "$SBX/keyA"

[accounts.4]
name = "sshb"
email = "sshb@example.com"
description = "ssh account B"
ssh_key = "$SBX/keyB"
EOF
chmod 600 "$XDG_CONFIG_HOME/gitswitch/accounts.toml"

CUR_SOCK="$XDG_RUNTIME_DIR/gitswitch-ssh/current.sock"
agent_ls() { SSH_AUTH_SOCK="$CUR_SOCK" ssh-add -l 2>/dev/null; }

# =============================================================================
echo "== SIG-01: signal during the git-config write =="
# NB: the signal is SIGTERM here, not SIGINT, because POSIX shells start
# background (&) jobs with SIGINT set to SIG_IGN — and gitswitch deliberately
# honors an inherited SIG_IGN (same convention that keeps nohup working).
# A real terminal Ctrl-C arrives with the default disposition and takes the
# exact same guard path (covered by raise(SIGINT) in tests/test_signals.c
# and tests/test_switch_rollback.c).

"$BIN" --global --yes old >/dev/null 2>&1 || { echo "baseline switch failed"; exit 1; }
[ "$(git config --global user.name)" = "old" ] || { echo "baseline identity wrong"; exit 1; }

GS_SLEEP_EMAIL=1 "$BIN" --global --yes new >/dev/null 2>&1 &
GS_PID=$!
ACTIVE_PID=$GS_PID
# Wait for the shim to enter the user.email write (user.name=new is already
# on disk at this instant — the half-applied window is OPEN), then interrupt.
i=0
while [ ! -e "$SBX/email.mark" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
[ -e "$SBX/email.mark" ] || { echo "shim never reached user.email write"; exit 1; }
kill -TERM "$GS_PID"
wait "$GS_PID"
RC=$?
ACTIVE_PID=

NAME=$(git config --global user.name)
EMAIL=$(git config --global user.email)
if { [ "$NAME" = "old" ] && [ "$EMAIL" = "old@example.com" ]; } ||
   { [ "$NAME" = "new" ] && [ "$EMAIL" = "new@example.com" ]; }; then
    pass "identity consistent after signal mid-switch ($NAME <$EMAIL>)"
else
    fail "MIXED identity after signal: $NAME <$EMAIL>"
fi
if [ "$RC" -eq 143 ]; then
    pass "gitswitch exited by SIGTERM (128+15)"
else
    fail "expected exit 143 (SIGTERM), got $RC"
fi

# SIG-02: no scratch orphans from the interrupted run.
ORPHANS=$(find "$XDG_CONFIG_HOME/gitswitch" -name "*.tmp.*" 2>/dev/null;
          find "$HOME/.ssh" -name "config.gitswitch.*" 2>/dev/null)
if [ -z "$ORPHANS" ]; then
    pass "no scratch temp-file orphans (SIG-02)"
else
    fail "scratch orphans left behind: $ORPHANS"
fi

# =============================================================================
echo "== F4: failed git-config write must not orphan the previous SSH agent =="

"$BIN" --global --yes ssha >/dev/null 2>&1 || { echo "switch to ssha failed"; exit 1; }
agent_ls | grep -q "$FP_A" || { echo "ssha agent not serving keyA"; exit 1; }

# (a) Failed switch to an SSH-DISABLED target: teardown of ssha's agent must
#     be deferred past the git-config write, so the failure leaves it alive.
if GS_FAIL_NAME=1 "$BIN" --global --yes new >/dev/null 2>&1; then
    echo "switch to 'new' unexpectedly succeeded"; exit 1
fi
if agent_ls | grep -q "$FP_A"; then
    pass "previous agent + current.sock survive failed switch to no-SSH target"
else
    fail "previous agent lost after failed switch to no-SSH target"
fi
rolled_back_name=$(git config --global user.name)
if [ "$rolled_back_name" = "ssha" ]; then
    pass "git identity rolled back to ssha"
else
    fail "git identity not rolled back (got $rolled_back_name)"
fi

# (b) Failed switch to an SSH-ENABLED target: starting keyB's agent reaps
#     keyA's, so the rollback must RE-ACTIVATE the previous agent.
if GS_FAIL_NAME=1 "$BIN" --global --yes sshb >/dev/null 2>&1; then
    echo "switch to 'sshb' unexpectedly succeeded"; exit 1
fi
LISTING=$(agent_ls)
if echo "$LISTING" | grep -q "$FP_A" && ! echo "$LISTING" | grep -q "$FP_B"; then
    pass "previous agent re-activated (keyA back, keyB gone) after failed SSH switch"
else
    fail "agent state wrong after failed SSH switch: ${LISTING:-<no agent>}"
fi

# =============================================================================
echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
    exit 0
else
    echo "$FAILURES CHECK(S) FAILED"
    exit 1
fi
