#!/bin/sh
# AR-08 T17: immutable actions, least privilege, and supported-platform policy.

set -eu

fail()
{
    printf 'ci-policy: ERROR: %s\n' "$*" >&2
    exit 1
}

check_policy()
{
    workflow=$1
    policy_date=$2

    [ -f "$workflow" ] || fail "workflow not found: $workflow"

    # All external actions must use a full immutable Git object name and keep
    # the human-maintained release tag in a comment for update tooling/review.
    action_count=0
    sed -n 's/^[[:space:]]*-[[:space:]]*uses:[[:space:]]*//p; s/^[[:space:]]*uses:[[:space:]]*//p' \
        "$workflow" >"$work_actions"
    while IFS= read -r action_line; do
        [ -n "$action_line" ] || continue
        action_count=$((action_count + 1))
        action=${action_line%%#*}
        action=$(printf '%s' "$action" | tr -d '[:space:]')
        case $action in
            *@*) ;;
            *) fail "external action lacks an immutable ref: $action_line" ;;
        esac
        ref=${action##*@}
        if [ "${#ref}" -ne 40 ] ||
            printf '%s\n' "$ref" | grep '[^0-9a-f]' >/dev/null; then
            fail "external action is not pinned to a full lowercase SHA: $action_line"
        fi
        case $action_line in
            *'# v'*) ;;
            *) fail "pinned action lacks a maintained version comment: $action_line" ;;
        esac
    done <"$work_actions"
    [ "$action_count" -gt 0 ] || fail "workflow contains no externally pinned actions"

    awk '
        $0 == "permissions:" { in_permissions = 1; found = 1; next }
        in_permissions && /^[^[:space:]]/ { in_permissions = 0 }
        in_permissions && $0 == "  contents: read" { contents_read = 1; next }
        in_permissions && /^[[:space:]]+[A-Za-z0-9_-]+:/ { extra = 1 }
        END { exit !(found && contents_read && !extra) }
    ' "$workflow" || fail "top-level permissions must be exactly contents: read"
    if grep -E '^[[:space:]]+[A-Za-z0-9_-]+:[[:space:]]*(write|write-all)[[:space:]]*$' \
        "$workflow" >/dev/null; then
        fail "workflow grants a write permission"
    fi

    # Close each checkout step at the next step boundary and require its
    # credential policy inside that exact block.
    awk '
        function close_checkout() {
            if (checkout && !no_credentials) bad = 1
            checkout = 0
            no_credentials = 0
        }
        /^[[:space:]]*-[[:space:]]+(name|uses|run):/ {
            if ($0 !~ /uses:[[:space:]]*actions\/checkout@/) close_checkout()
        }
        /uses:[[:space:]]*actions\/checkout@/ {
            close_checkout()
            checkout = 1
            count++
            next
        }
        checkout && /persist-credentials:[[:space:]]*false([[:space:]]|$)/ {
            no_credentials = 1
        }
        END {
            close_checkout()
            exit !(count > 0 && !bad)
        }
    ' "$workflow" || fail "every checkout must set persist-credentials: false"

    freebsd_version=$(awk '
        /operating_system:[[:space:]]*freebsd/ { found = 1; next }
        found && /version:/ {
            line = $0
            sub(/^.*version:[[:space:]]*/, "", line)
            gsub(/[[:space:]'\''"]/, "", line)
            print line
            exit
        }
    ' "$workflow")
    [ -n "$freebsd_version" ] || fail "FreeBSD CI version is not explicit"
    case $freebsd_version in
        14.4) freebsd_eol=2026-12-31 ;;
        *) fail "FreeBSD $freebsd_version is unreviewed or no longer supported" ;;
    esac
    printf '%s\n' "$policy_date" | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' \
        >/dev/null || fail "invalid policy date: $policy_date"
    latest=$(printf '%s\n%s\n' "$policy_date" "$freebsd_eol" |
        LC_ALL=C sort | tail -n 1)
    [ "$latest" = "$freebsd_eol" ] ||
        fail "FreeBSD $freebsd_version passed its $freebsd_eol support deadline"
}

expect_rejected()
{
    label=$1
    workflow=$2
    policy_date=$3
    if WORK_ACTIONS="$tmp/check-actions" "$script" --check "$workflow" \
        "$policy_date" >"$tmp/out" 2>&1; then
        fail "$label fixture was accepted"
    fi
}

if [ "${1-}" = "--check" ]; then
    [ "$#" -eq 3 ] || fail "usage: $0 --check WORKFLOW YYYY-MM-DD"
    work_actions=${WORK_ACTIONS-"${TMPDIR:-/tmp}/gitswitch-ci-actions.$$"}
    trap 'rm -f "$work_actions"' 0 1 2 3 15
    check_policy "$2" "$3"
    exit 0
fi

[ "$#" -eq 1 ] || fail "usage: $0 PROJECT_ROOT"
root=$1
workflow=$root/.github/workflows/ci.yml
today=${GITSWITCH_CI_POLICY_DATE-$(date -u +%F)}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-ci-policy.XXXXXX") ||
    fail "cannot create policy fixture directory"
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    rm -rf "$tmp"
    exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15
work_actions=$tmp/actions
check_policy "$workflow" "$today"

# Mutation-sensitive controls make this a policy gate, not a grep that merely
# happens to accept the current workflow.
script=$(CDPATH='' cd "$(dirname "$0")" && pwd)/$(basename "$0")
sed 's/@11bd71901bbe5b1630ceea73d27597364c9af683/@v4/g' \
    "$workflow" >"$tmp/mutable.yml"
expect_rejected "mutable action" "$tmp/mutable.yml" "$today"

sed 's/persist-credentials: false/persist-credentials: true/g' \
    "$workflow" >"$tmp/credentials.yml"
expect_rejected "persisted checkout credential" "$tmp/credentials.yml" "$today"

sed 's/contents: read/contents: write/g' "$workflow" >"$tmp/write.yml"
expect_rejected "write permission" "$tmp/write.yml" "$today"

sed "s/version: '14.4'/version: '14.2'/g" \
    "$workflow" >"$tmp/eol.yml"
expect_rejected "EOL FreeBSD" "$tmp/eol.yml" "$today"
expect_rejected "expired support window" "$workflow" 2027-01-01

printf 'ci-policy: PASS (immutable, least-privilege, supported-platform workflow)\n'
