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

    # Close each checkout step at the next YAML sequence-item boundary and
    # require exactly one effective credential policy inside that step's
    # `with` mapping. Comments are not configuration: accepting a commented
    # `persist-credentials: false` beside an effective true value made this
    # gate trivially bypassable.
    awk '
        function strip_comment(line) {
            sub(/[[:space:]]*#.*/, "", line)
            sub(/[[:space:]]+$/, "", line)
            return line
        }
        function indentation(line, prefix) {
            prefix = line
            sub(/[^ ].*$/, "", prefix)
            return length(prefix)
        }
        function close_step() {
            if (checkout &&
                (credential_count != 1 || credential_value != "false" ||
                 !credential_in_with)) bad = 1
            checkout = 0
            credential_count = 0
            credential_value = ""
            credential_in_with = 0
            in_with = 0
            with_indent = -1
        }
        {
            code = strip_comment($0)
            if (code == "") next
            if (code ~ /^[[:space:]]*-[[:space:]]+[A-Za-z0-9_-]+:/)
                close_step()
            if (code ~ /uses:[[:space:]]*actions\/checkout@/) {
                if (checkout) bad = 1
                checkout = 1
                count++
            }
            if (!checkout) next
            current_indent = indentation(code)
            if (code ~ /^[[:space:]]+with:[[:space:]]*$/) {
                in_with = 1
                with_indent = current_indent
                next
            }
            if (in_with && current_indent <= with_indent) in_with = 0
            if (code ~ /^[[:space:]]+persist-credentials:[[:space:]]*/) {
                credential_count++
                value = code
                sub(/^[[:space:]]*persist-credentials:[[:space:]]*/, "", value)
                sub(/[[:space:]]+$/, "", value)
                credential_value = value
                if (in_with && current_indent > with_indent)
                    credential_in_with = 1
            }
        }
        END {
            close_step()
            exit !(count > 0 && !bad)
        }
    ' "$workflow" ||
        fail "every checkout must set exactly one effective persist-credentials: false"

    # Artifact inspection must consume the same WERROR=1 configuration that
    # passed the full release suite. Omitting the knob changes .buildconfig and
    # silently rebuilds a different production binary before inspection.
    awk '
        function strip_comment(line) {
            sub(/[[:space:]]*#.*/, "", line)
            sub(/[[:space:]]+$/, "", line)
            return line
        }
        {
            code = strip_comment($0)
            command_count = split(code, commands, /[;&|]/)
            for (i = 1; i <= command_count; i++) {
                command = commands[i]
                target_at = match(command,
                    /(^|[[:space:]])release-artifact-test([[:space:]]|$)/)
                if (!target_at) continue
                count++
                make_at = match(command, /(^|[[:space:]])g?make[[:space:]]/)
                werror_at = match(command,
                    /(^|[[:space:]])WERROR=1([[:space:]]|$)/)
                if (!make_at || !werror_at ||
                    make_at > werror_at || werror_at > target_at) bad = 1
            }
        }
        END { exit !(count > 0 && !bad) }
    ' "$workflow" ||
        fail "every release-artifact-test invocation must preserve WERROR=1"

    # Linux descriptor publication normally uses AT_EMPTY_PATH/O_TMPFILE.
    # Darwin and FreeBSD have distinct fclonefileat/funlinkat paths, so both
    # hosted jobs must execute the release contract. Parse only effective run
    # scalars: comments, env values, names, and other job text are not commands.
    awk '
        function strip_comment(line) {
            sub(/[[:space:]]*#.*/, "", line)
            sub(/[[:space:]]+$/, "", line)
            return line
        }
        function indentation(line, prefix) {
            prefix = line
            sub(/[^ ].*$/, "", prefix)
            return length(prefix)
        }
        function inspect_command(code, command_count, commands, i,
                                 command, target_at, normalized) {
            command_count = split(code, commands, /[;&|]/)
            for (i = 1; i <= command_count; i++) {
                command = commands[i]
                target_at = match(command,
                    /(^|[[:space:]])release-contract-test([[:space:]]|$)/)
                if (!target_at) continue
                normalized = command
                sub(/^[[:space:]]+/, "", normalized)
                sub(/[[:space:]]+$/, "", normalized)
                if (normalized !~ /^g?make[[:space:]]+release-contract-test$/)
                    bad = 1
                if (job == "macos") macos_count++
                if (job == "freebsd") freebsd_count++
            }
        }
        {
            code = strip_comment($0)
            if (code ~ /^  [A-Za-z0-9_-]+:[[:space:]]*$/) {
                job = code
                sub(/^  /, "", job)
                sub(/:[[:space:]]*$/, "", job)
                in_run = 0
                if (job == "macos") macos_jobs++
                if (job == "freebsd") freebsd_jobs++
                next
            }
            if (job != "macos" && job != "freebsd") next
            if (in_run) {
                if (code == "" || indentation(code) > run_indent) {
                    if (code != "") {
                        sub(/^[[:space:]]+/, "", code)
                        inspect_command(code)
                    }
                    next
                }
                in_run = 0
            }
            if (code ~ /^[[:space:]]+run:[[:space:]]*/) {
                run_indent = indentation(code)
                sub(/^[[:space:]]+run:[[:space:]]*/, "", code)
                if (code ~ /^[|>][-+0-9]*[[:space:]]*$/) {
                    in_run = 1
                } else if (code != "") {
                    inspect_command(code)
                }
            }
        }
        END {
            exit !(macos_jobs == 1 && freebsd_jobs == 1 &&
                   macos_count == 1 && freebsd_count == 1 && !bad)
        }
    ' "$workflow" ||
        fail "macOS and FreeBSD CI must each execute one release-contract-test"

    # Parse the FreeBSD version only from the uncommented `with` mapping of the
    # cross-platform action step. The old forward search accepted a stale real
    # value when a preceding comment happened to mention the supported one.
    freebsd_version=$(awk '
        function strip_comment(line) {
            sub(/[[:space:]]*#.*/, "", line)
            sub(/[[:space:]]+$/, "", line)
            return line
        }
        function indentation(line, prefix) {
            prefix = line
            sub(/[^ ].*$/, "", prefix)
            return length(prefix)
        }
        function scalar(line, value, quote) {
            value = line
            sub(/^[^:]*:[[:space:]]*/, "", value)
            gsub(/[[:space:]"]/, "", value)
            quote = sprintf("%c", 39)
            gsub(quote, "", value)
            return value
        }
        function close_step() {
            if (cross_action) {
                if (os_count != 1 || !os_in_with) bad = 1
                if (os_value == "freebsd") {
                    freebsd_count++
                    if (version_count != 1 || !version_in_with ||
                        version_value !~ /^[0-9]+\.[0-9]+$/) bad = 1
                    else print version_value
                }
            }
            cross_action = 0
            os_count = 0
            os_value = ""
            os_in_with = 0
            version_count = 0
            version_value = ""
            version_in_with = 0
            in_with = 0
            with_indent = -1
        }
        {
            code = strip_comment($0)
            if (code == "") next
            if (code ~ /^[[:space:]]*-[[:space:]]+[A-Za-z0-9_-]+:/)
                close_step()
            if (code ~ /uses:[[:space:]]*cross-platform-actions\/action@/)
                cross_action = 1
            if (!cross_action) next
            current_indent = indentation(code)
            if (code ~ /^[[:space:]]+with:[[:space:]]*$/) {
                in_with = 1
                with_indent = current_indent
                next
            }
            if (in_with && current_indent <= with_indent) in_with = 0
            if (code ~ /^[[:space:]]+operating_system:[[:space:]]*/) {
                os_count++
                os_value = scalar(code)
                if (in_with && current_indent > with_indent) os_in_with = 1
            }
            if (code ~ /^[[:space:]]+version:[[:space:]]*/) {
                version_count++
                version_value = scalar(code)
                if (in_with && current_indent > with_indent) version_in_with = 1
            }
        }
        END {
            close_step()
            if (freebsd_count != 1 || bad) exit 1
        }
    ' "$workflow") || fail "FreeBSD action policy is missing or structurally ambiguous"
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
    reject_label=$1
    reject_workflow=$2
    reject_policy_date=$3
    if WORK_ACTIONS="$tmp/check-actions" "$script" --check "$reject_workflow" \
        "$reject_policy_date" >"$tmp/out" 2>&1; then
        fail "$reject_label fixture was accepted"
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

# A false value in a comment must not bless an effective true value.
awk '
    !changed && /persist-credentials:[[:space:]]*false/ {
        line = $0
        sub(/persist-credentials:[[:space:]]*false/,
            "persist-credentials: true", line)
        print line
        match($0, /^[ ]*/)
        indent = substr($0, 1, RLENGTH)
        print indent "# persist-credentials: false"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/credentials-comment.yml"
expect_rejected "comment-masked persisted checkout credential" \
    "$tmp/credentials-comment.yml" "$today"

sed 's/contents: read/contents: write/g' "$workflow" >"$tmp/write.yml"
expect_rejected "write permission" "$tmp/write.yml" "$today"

sed "s/version: '14.4'/version: '14.2'/g" \
    "$workflow" >"$tmp/eol.yml"
expect_rejected "EOL FreeBSD" "$tmp/eol.yml" "$today"

# Likewise, a supported release mentioned only in a comment must not mask the
# stale effective version in the action's `with` block.
awk '
    /operating_system:[[:space:]]*freebsd/ && !commented {
        print
        match($0, /^[ ]*/)
        indent = substr($0, 1, RLENGTH)
        print indent "# version: '\''14.4'\''"
        commented = 1
        next
    }
    commented && /version:[[:space:]]*'\''14\.4'\''/ && !changed {
        sub(/14\.4/, "14.2")
        changed = 1
    }
    { print }
    END { if (!commented || !changed) exit 1 }
' "$workflow" >"$tmp/eol-comment.yml"
expect_rejected "comment-masked EOL FreeBSD" "$tmp/eol-comment.yml" "$today"
expect_rejected "expired support window" "$workflow" 2027-01-01

# Dropping WERROR from even one artifact command changes the build stamp and
# causes inspection to consume a freshly rebuilt, non-WERROR binary.
awk '
    !changed && /release-artifact-test/ && /WERROR=1/ {
        sub(/WERROR=1[[:space:]]*/, "")
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/artifact-no-werror.yml"
expect_rejected "artifact rebuild without WERROR" \
    "$tmp/artifact-no-werror.yml" "$today"

# Removing the effective Darwin publication exercise must be detected even
# while the Linux release-contract lane remains present.
awk '
    /^  macos:[[:space:]]*$/ { in_macos = 1 }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ && $0 !~ /^  macos:/ {
        in_macos = 0
    }
    in_macos && !changed && /release-contract-test/ {
        sub(/make[[:space:]]+release-contract-test/, "true")
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/macos-no-release-contract.yml"
expect_rejected "macOS without release contract" \
    "$tmp/macos-no-release-contract.yml" "$today"

# Non-command text in the same job must not mask removal of the executable
# macOS contract command.
awk '
    /^  macos:[[:space:]]*$/ { in_macos = 1 }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ && $0 !~ /^  macos:/ {
        in_macos = 0
    }
    in_macos && !changed && /make[[:space:]]+release-contract-test/ {
        sub(/make[[:space:]]+release-contract-test/, "true")
        changed = 1
    }
    in_macos && changed && !injected && /^[[:space:]]+env:[[:space:]]*$/ {
        print
        print "          FAKE_POLICY_TEXT: make release-contract-test"
        injected = 1
        next
    }
    { print }
    END { if (!changed || !injected) exit 1 }
' "$workflow" >"$tmp/macos-env-text-only.yml"
expect_rejected "macOS env text without release contract" \
    "$tmp/macos-env-text-only.yml" "$today"

# Mentioning the make command as echo data is not execution either.
awk '
    /^  macos:[[:space:]]*$/ { in_macos = 1 }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ && $0 !~ /^  macos:/ {
        in_macos = 0
    }
    in_macos && !changed && /make[[:space:]]+release-contract-test/ {
        sub(/make[[:space:]]+release-contract-test/,
            "echo make release-contract-test")
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/macos-echo-release-contract.yml"
expect_rejected "macOS echo without release contract" \
    "$tmp/macos-echo-release-contract.yml" "$today"

# The FreeBSD funlinkat path must remain both Werror-compiled and executed.
awk '
    /^  freebsd:[[:space:]]*$/ { in_freebsd = 1 }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ && $0 !~ /^  freebsd:/ {
        in_freebsd = 0
    }
    in_freebsd && !changed && /gmake[[:space:]]+release-contract-test/ {
        sub(/gmake[[:space:]]+release-contract-test/, "true")
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-no-release-contract.yml"
expect_rejected "FreeBSD without release contract" \
    "$tmp/freebsd-no-release-contract.yml" "$today"

printf 'ci-policy: PASS (immutable, least-privilege, supported-platform workflow)\n'
