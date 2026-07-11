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
# Everything runs in a throwaway sandbox: private HOME, private
# XDG_RUNTIME_DIR, and PATH shims below the operator's trusted HOME ancestry.
# The `git` shim delegates to the real git but can sleep on / fail the identity
# writes (that's what makes the race deterministic). Real ssh-agent/ssh-add are
# used; `ssh` itself is stubbed so no network is touched. Run from anywhere:
#
#   sh tests/repro_sig01.sh
#
# Exits 0 and prints PASS for each check; any failure exits 1.

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/build/bin/gitswitch"
[ -x "$BIN" ] || { echo "build first: make (missing $BIN)"; exit 1; }

REAL_GIT=$(command -v git) || { echo "git not found"; exit 1; }
command -v ssh-agent >/dev/null || { echo "ssh-agent not found"; exit 1; }

case ${HOME-} in
    /*) ;;
    *) echo "absolute HOME required for trusted PATH shims"; exit 1 ;;
esac
TRUSTED_HOME=$(CDPATH= cd "$HOME" 2>/dev/null && pwd -P) \
    || { echo "cannot resolve HOME: $HOME"; exit 1; }
SBX=$(mktemp -d /tmp/gsw_repro.XXXXXX) || exit 1
SHIM_DIR=$(mktemp -d "$TRUSTED_HOME/.gsw-repro-shims.XXXXXX") \
    || { rm -rf "$SBX"; exit 1; }
chmod 700 "$SHIM_DIR" \
    || { rm -rf "$SBX" "$SHIM_DIR"; exit 1; }

FAILURES=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

cleanup() {
    # Reap any agents the sandbox started (pid sidecars are authoritative).
    for f in "$SBX"/run/gitswitch-ssh/*.pid; do
        [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null
    done
    rm -rf "$SBX" "$SHIM_DIR"
}
trap cleanup EXIT INT TERM

# --- sandbox ----------------------------------------------------------------
export HOME="$SBX/home"
export XDG_RUNTIME_DIR="$SBX/run"
mkdir -p "$HOME/.ssh" "$HOME/.config/gitswitch"
mkdir -m 700 "$XDG_RUNTIME_DIR"
chmod 700 "$HOME/.ssh"
cd "$SBX" # must not run inside a git repo: switches use --global scope
unset GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM 2>/dev/null

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
chmod +x "$SHIM_DIR/git"
# ssh stub: the post-switch connection test must not hit the network.
printf '#!/bin/sh\nexit 1\n' > "$SHIM_DIR/ssh"
chmod +x "$SHIM_DIR/ssh"
export PATH="$SHIM_DIR:$PATH"

# Two passphrase-less test keys (never leave the sandbox).
ssh-keygen -q -t ed25519 -N "" -C "keyA" -f "$SBX/keyA" || exit 1
ssh-keygen -q -t ed25519 -N "" -C "keyB" -f "$SBX/keyB" || exit 1
FP_A=$(ssh-keygen -lf "$SBX/keyA" | awk '{print $2}')
FP_B=$(ssh-keygen -lf "$SBX/keyB" | awk '{print $2}')

cat > "$HOME/.config/gitswitch/accounts.toml" <<EOF
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
chmod 600 "$HOME/.config/gitswitch/accounts.toml"

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
# Wait for the shim to enter the user.email write (user.name=new is already
# on disk at this instant — the half-applied window is OPEN), then interrupt.
i=0
while [ ! -e "$SBX/email.mark" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
[ -e "$SBX/email.mark" ] || { echo "shim never reached user.email write"; exit 1; }
kill -TERM "$GS_PID"
wait "$GS_PID"
RC=$?

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
ORPHANS=$(find "$HOME/.config/gitswitch" -name "*.tmp.*" 2>/dev/null;
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
[ "$(git config --global user.name)" = "ssha" ] \
    && pass "git identity rolled back to ssha" \
    || fail "git identity not rolled back (got $(git config --global user.name))"

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
