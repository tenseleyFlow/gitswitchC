#!/bin/sh
# Fail-closed static and native-parser checks for every shipped shell asset.

set -eu

fail()
{
    printf 'shell-static: ERROR: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail "usage: $0 PROJECT_ROOT"
root=$1
[ -d "$root/tests" ] || fail "test-script directory missing: $root/tests"
[ -d "$root/completions" ] ||
    fail "completion directory missing: $root/completions"

missing=0
for tool in shellcheck bash zsh fish dash ksh awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'shell-static: ERROR: required tool is unavailable: %s\n' \
            "$tool" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || exit 1

set -- "$root"/tests/*.sh "$root"/tools/*.sh
[ -e "$1" ] || fail "no POSIX test scripts discovered under $root/tests"
script_count=$#

printf 'ShellCheck: %s POSIX test scripts (severity info)...\n' "$script_count"
shellcheck --severity=info --shell=sh -- "$@"

bash_completion=$root/completions/gitswitch.bash
zsh_completion=$root/completions/gitswitch.zsh
fish_completion=$root/completions/gitswitch.fish
for completion in "$bash_completion" "$zsh_completion" "$fish_completion"; do
    [ -f "$completion" ] || fail "completion missing: $completion"
done

printf 'ShellCheck: Bash completion (severity info)...\n'
shellcheck --severity=info --shell=bash -- "$bash_completion"

printf 'Native parse: POSIX scripts with dash...\n'
for script in "$@"; do
    dash -n "$script"
done

printf 'Native parse: Bash, Zsh, and Fish completions...\n'
bash -n "$bash_completion"
zsh -n "$zsh_completion"
fish -n "$fish_completion"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gitswitch-shell-static.XXXXXX") ||
    fail "cannot create negative-control directory"
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    rm -rf "$tmp"
    exit "$status"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

# AR-11 L39: execute the commands that users actually copy from README rather
# than a duplicate maintained in this test. Empty and partial generator
# failures must retain their distinct statuses and install nothing; healthy
# multiline output must be evaluated/sourced without leaking the capture
# variable. The production E2E shell suite separately binds the real
# missing-runtime failure and generated snippets, while this deterministic shim
# makes documentation drift causal.
extract_readme_init_block()
{
    language=$1
    marker=$2
    output=$3
    awk -v opening="\`\`\`$language" -v marker="$marker" '
        capture {
            if ($0 == "```") {
                capture = 0
                closed++
                next
            }
            print
            next
        }
        candidate {
            candidate = 0
            if ($0 == marker) {
                found++
                capture = 1
            }
            next
        }
        $0 == opening { candidate = 1 }
        END {
            if (found != 1 || closed != 1 || capture) exit 1
        }
    ' "$root/README.md" >"$output" ||
        fail "README $language init block is missing, duplicated, or unclosed"
    [ -s "$output" ] || fail "README $language init block is empty"
}

doc_bin=$tmp/bin
mkdir "$doc_bin" || fail "cannot create README init shim directory"
cat >"$doc_bin/gitswitch" <<'EOF'
#!/bin/sh
[ "$#" -eq 2 ] && [ "$1" = init ] || exit 97
[ -n "${GS_DOC_EXPECTED_TARGET-}" ] &&
    [ "$2" = "$GS_DOC_EXPECTED_TARGET" ] || exit 96
case ${GS_DOC_MODE-} in
    fail-empty)
        exit 23
        ;;
    fail-partial)
        case $2 in
            fish)
                printf '%s\n' 'set -g __gitswitch_doc_marker installed'
                ;;
            *)
                printf '%s\n' '__gitswitch_doc_marker=installed'
                ;;
        esac
        exit 47
        ;;
    healthy)
        case $2 in
            bash|zsh|sh)
                printf '%s\n' \
                    '__gitswitch_doc_install() {' \
                    '    __gitswitch_doc_marker=installed' \
                    '}' \
                    '__gitswitch_doc_install'
                ;;
            fish)
                printf '%s\n' \
                    'function __gitswitch_doc_install' \
                    '    set -g __gitswitch_doc_marker installed' \
                    'end' \
                    '__gitswitch_doc_install'
                ;;
            *)
                exit 98
                ;;
        esac
        ;;
    *)
        exit 99
        ;;
esac
EOF
chmod 0700 "$doc_bin/gitswitch" || fail "cannot make README init shim executable"

bash_init=$tmp/readme-init.bash
zsh_init=$tmp/readme-init.zsh
fish_init=$tmp/readme-init.fish
posix_init=$tmp/readme-init.sh
extract_readme_init_block bash '# ~/.bashrc' "$bash_init"
extract_readme_init_block zsh '# ~/.zshrc' "$zsh_init"
extract_readme_init_block fish '# ~/.config/fish/config.fish' "$fish_init"
extract_readme_init_block sh '# ~/.profile (sh, dash, or ksh)' "$posix_init"

check_posix_readme_init()
{
    shell_name=$1
    init_file=$2
    expected_target=$3
    shift 3

    for doc_mode in fail-empty fail-partial; do
        case $doc_mode in
            fail-empty) expected_status=23 ;;
            fail-partial) expected_status=47 ;;
        esac
        # The single-quoted program is intentionally expanded by the child
        # shell.
        # shellcheck disable=SC2016
        if ! GS_DOC_MODE=$doc_mode GS_DOC_EXPECTED_TARGET=$expected_target \
                GS_DOC_EXPECTED_STATUS=$expected_status \
                PATH="$doc_bin:$PATH" \
                "$shell_name" "$@" -c '
            . "$1"
            init_status=$?
            [ "$init_status" -eq "$GS_DOC_EXPECTED_STATUS" ] || exit 90
            [ "${__gitswitch_doc_marker+x}" != x ] || exit 91
            [ "${__gitswitch_init_output+x}" != x ] || exit 92
        ' readme-init "$init_file"; then
            fail "README $shell_name init block mishandled $doc_mode generation"
        fi
    done

    # shellcheck disable=SC2016
    GS_DOC_MODE=healthy GS_DOC_EXPECTED_TARGET=$expected_target \
            PATH="$doc_bin:$PATH" "$shell_name" "$@" -c '
        . "$1"
        init_status=$?
        [ "$init_status" -eq 0 ] || exit 93
        [ "${__gitswitch_doc_marker-}" = installed ] || exit 94
        [ "${__gitswitch_init_output+x}" != x ] || exit 95
    ' readme-init "$init_file" ||
        fail "README $shell_name init block rejected healthy generated output"
}

check_fish_readme_init()
{
    init_file=$1

    for doc_mode in fail-empty fail-partial; do
        case $doc_mode in
            fail-empty) expected_status=23 ;;
            fail-partial) expected_status=47 ;;
        esac
        # The single-quoted program is intentionally expanded by Fish.
        # shellcheck disable=SC2016
        if ! GS_DOC_MODE=$doc_mode GS_DOC_EXPECTED_TARGET=fish \
                GS_DOC_EXPECTED_STATUS=$expected_status \
                PATH="$doc_bin:$PATH" fish --no-config -c '
            source $argv[1]
            set -l init_status $status
            test $init_status -eq $GS_DOC_EXPECTED_STATUS; or exit 90
            set -q __gitswitch_doc_marker; and exit 91
            set -q __gitswitch_init_output; and exit 92
            true
        ' "$init_file"; then
            fail "README fish init block mishandled $doc_mode generation"
        fi
    done

    # shellcheck disable=SC2016
    GS_DOC_MODE=healthy GS_DOC_EXPECTED_TARGET=fish \
            PATH="$doc_bin:$PATH" fish --no-config -c '
        source $argv[1]
        set -l init_status $status
        test $init_status -eq 0; or exit 93
        test "$__gitswitch_doc_marker" = installed; or exit 94
        set -q __gitswitch_init_output; and exit 95
        true
    ' "$init_file" ||
        fail "README fish init block rejected healthy generated output"
}

check_posix_readme_init bash "$bash_init" bash --noprofile --norc
check_posix_readme_init zsh "$zsh_init" zsh -f
check_fish_readme_init "$fish_init"
check_posix_readme_init sh "$posix_init" sh
check_posix_readme_init dash "$posix_init" sh
check_posix_readme_init ksh "$posix_init" sh

# A syntactically valid unquoted expansion must make the semantic analyzer
# fail at the same severity used above. Verify the diagnostic as well as the
# nonzero exit so an unrelated tool failure cannot satisfy the control.
semantic_bad=$tmp/semantic-bad.sh
printf '%s\n' '#!/bin/sh' "value=\$1" "printf '%s\\n' \$value" \
    >"$semantic_bad"
semantic_out=$tmp/semantic.out
if shellcheck --severity=info --shell=sh "$semantic_bad" \
        >"$semantic_out" 2>&1; then
    fail "ShellCheck accepted the semantic negative control"
fi
grep -F 'SC2086' "$semantic_out" >/dev/null || {
    sed -n '1,120p' "$semantic_out" >&2
    fail "ShellCheck negative control did not report SC2086"
}

# Each native parser must reject a malformed fixture in its own language. This
# catches a missing/no-op parser hidden behind a command of the expected name.
posix_bad=$tmp/native-bad.sh
bash_bad=$tmp/native-bad.bash
zsh_bad=$tmp/native-bad.zsh
fish_bad=$tmp/native-bad.fish
printf '%s\n' '#!/bin/sh' 'if true; then' '    :' >"$posix_bad"
printf '%s\n' '#!/usr/bin/env bash' 'if true; then' '    :' >"$bash_bad"
printf '%s\n' '#!/usr/bin/env zsh' 'if true; then' '    :' >"$zsh_bad"
printf '%s\n' '#!/usr/bin/env fish' 'if true' '    true' >"$fish_bad"

expect_rejection()
{
    parser=$1
    fixture=$2
    out=$tmp/$parser.out
    if "$parser" -n "$fixture" >"$out" 2>&1; then
        fail "$parser accepted its malformed native-syntax control"
    fi
}

expect_rejection dash "$posix_bad"
expect_rejection bash "$bash_bad"
expect_rejection zsh "$zsh_bad"
expect_rejection fish "$fish_bad"

printf 'Shell asset static checks passed.\n'
