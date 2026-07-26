#!/bin/sh
# Causal contract for the repository's gcovr line/branch coverage thresholds.

set -eu

fail()
{
    printf 'coverage-contract: ERROR: %s\n' "$*" >&2
    exit 1
}

show_logs()
{
    label=$1
    stdout_file=$2
    stderr_file=$3

    printf '%s\n' "--- $label stdout ---" >&2
    cat "$stdout_file" >&2
    printf '%s\n' "--- $label stderr ---" >&2
    cat "$stderr_file" >&2
}

run_threshold_check()
{
    label=$1
    expected_status=$2
    minimum_lines=$3
    minimum_branches=$4
    stdout_file=$tmp/$label.stdout
    stderr_file=$tmp/$label.stderr
    report_file=$tmp/$label.txt

    if "$gcovr_cmd" --root "$tmp" \
        --gcov-executable "$gcov_cmd" \
        --txt "$report_file" --print-summary \
        --fail-under-line "$minimum_lines" \
        --fail-under-branch "$minimum_branches" \
        "$tmp" >"$stdout_file" 2>"$stderr_file"; then
        actual_status=0
    else
        actual_status=$?
    fi

    if [ "$actual_status" -ne "$expected_status" ]; then
        show_logs "$label" "$stdout_file" "$stderr_file"
        fail "$label returned $actual_status; expected $expected_status"
    fi
}

read_default_floor()
{
    makefile=$1
    variable=$2

    awk -v variable="$variable" '
        BEGIN {
            any_pattern = variable "[[:space:]]*(\\?|:|\\+)?="
            default_pattern = "^[[:space:]]*" variable "[[:space:]]*\\?="
            assignment_count = 0
            default_count = 0
        }
        {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)
            if (line ~ any_pattern) {
                assignment_count++
            }
            if (line ~ default_pattern) {
                sub(default_pattern, "", line)
                sub(/^[[:space:]]*/, "", line)
                sub(/[[:space:]]*$/, "", line)
                value = line
                default_count++
            }
        }
        END {
            if (assignment_count != 1 || default_count != 1 || value == "") {
                exit 1
            }
            print value
        }
    ' "$makefile"
}

validate_make_semantics()
{
    makefile=$1

    awk '
        {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)
            if (index(line, "." "IGNORE") != 0 ||
                index(line, "." "ONESHELL") != 0 ||
                index(line, "$" "(eval") != 0 ||
                line ~ /(^|[[:space:]:])(MAKEFLAGS|MFLAGS|SHELL|[.]SHELLFLAGS)[[:space:]]*(\?|:|\+)?=/) {
                exit 1
            }
        }
    ' "$makefile"
}

resolve_gnu_make()
{
    if [ -n "${COVERAGE_POLICY_MAKE-}" ]; then
        candidate=$COVERAGE_POLICY_MAKE
        [ -x "$candidate" ] ||
            fail "configured GNU Make is not executable: $candidate"
        "$candidate" --version 2>/dev/null |
            grep -F 'GNU Make' >/dev/null ||
            fail "configured coverage policy Make is not GNU Make"
        printf '%s\n' "$candidate"
        return
    fi

    for candidate in /usr/bin/make gmake make; do
        if command -v "$candidate" >/dev/null 2>&1; then
            candidate_path=$(command -v "$candidate") || continue
            if "$candidate_path" --version 2>/dev/null |
                grep -F 'GNU Make' >/dev/null; then
                printf '%s\n' "$candidate_path"
                return
            fi
        fi
    done
    fail "GNU Make is required for evaluated coverage policy validation"
}

write_behavioral_probe_makefiles()
{
    capability_makefile=$tmp/coverage-capability-probe.mk
    behavior_makefile=$tmp/coverage-behavior-probe.mk

    cat >"$capability_makefile" <<'EOF'
.PHONY: coverage-contract-test coverage
coverage-contract-test coverage:
	@$(info GITSWITCH_COVERAGE_CONTROL|makeflags=$(MAKEFLAGS)|mflags=$(MFLAGS)|shell=$(SHELL)|shellflags=$(.SHELLFLAGS)) :
EOF

    cat >"$behavior_makefile" <<'EOF'
ifeq ($(PROBE_KIND),contract)
coverage-contract-test:
	@$(info GITSWITCH_COVERAGE_BEHAVIOR|kind=contract|lines=$(COVERAGE_MIN_LINES)|branches=$(COVERAGE_MIN_BRANCHES)|makeflags=$(MAKEFLAGS)|mflags=$(MFLAGS)|shell=$(SHELL)|shellflags=$(.SHELLFLAGS)) false
	@:
else ifeq ($(PROBE_KIND),coverage)
coverage-contract-test:
	@:
coverage:
	@$(info GITSWITCH_COVERAGE_BEHAVIOR|kind=coverage|lines=$(COVERAGE_MIN_LINES)|branches=$(COVERAGE_MIN_BRANCHES)|makeflags=$(MAKEFLAGS)|mflags=$(MFLAGS)|shell=$(SHELL)|shellflags=$(.SHELLFLAGS)) false
	@:
else
$(error unsupported coverage behavioral probe kind)
endif
EOF
}

validate_behavioral_make()
{
    makefile=$1
    probe_default_lines=$(read_default_floor \
        "$makefile" COVERAGE_MIN_LINES) || return 1
    probe_default_branches=$(read_default_floor \
        "$makefile" COVERAGE_MIN_BRANCHES) || return 1
    valid_percentage "$probe_default_lines" || return 1
    valid_percentage "$probe_default_branches" || return 1
    [ "$probe_default_lines" -ge "$contract_min_lines" ] || return 1
    [ "$probe_default_branches" -ge "$contract_min_branches" ] || return 1

    for kind in contract coverage; do
        marker=$tmp/$kind-behavior.marker
        control=$tmp/$kind-control.marker
        stdout_file=$tmp/$kind-behavior.stdout
        stderr_file=$tmp/$kind-behavior.stderr
        if [ "$kind" = contract ]; then
            target=coverage-contract-test
        else
            target=coverage
        fi

        if ! MAKEFLAGS='' MFLAGS='' "$policy_make" \
            -rR --no-print-directory -f "$capability_makefile" \
            "PROBE_KIND=$kind" "$target" \
            >"$stdout_file" 2>"$stderr_file"; then
            return 1
        fi
        grep -F 'GITSWITCH_COVERAGE_CONTROL|' "$stdout_file" \
            >"$control" || return 1
        [ "$(awk 'END { print NR }' "$control")" -eq 1 ] || return 1
        control_value=$(cat "$control") || return 1
        control_value=${control_value#GITSWITCH_COVERAGE_CONTROL|}

        expected_marker=$(printf \
            'GITSWITCH_COVERAGE_BEHAVIOR|kind=%s|lines=%s|branches=%s|%s' \
            "$kind" "$probe_default_lines" "$probe_default_branches" \
            "$control_value") || return 1

        if MAKEFLAGS='' MFLAGS='' "$policy_make" \
            -rR --no-print-directory -f "$makefile" \
            -f "$behavior_makefile" \
            "PROBE_KIND=$kind" "$target" \
            >"$stdout_file" 2>"$stderr_file"; then
            status=0
        else
            status=$?
        fi
        [ "$status" -eq 2 ] || return 1
        grep -F 'GITSWITCH_COVERAGE_BEHAVIOR|' "$stdout_file" \
            >"$marker" || return 1
        [ "$(awk 'END { print NR }' "$marker")" -eq 1 ] || return 1
        [ "$(cat "$marker")" = "$expected_marker" ] || return 1
    done
}

expect_behavioral_rejected()
{
    makefile=$1
    description=$2
    parse_stdout=$tmp/behavior-witness-parse.stdout
    parse_stderr=$tmp/behavior-witness-parse.stderr

    if ! MAKEFLAGS='' MFLAGS='' "$policy_make" -prRn -f "$makefile" \
        >"$parse_stdout" 2>"$parse_stderr"; then
        fail "behavioral witness did not parse: $description"
    fi
    if validate_behavioral_make "$makefile"; then
        fail "behavioral policy accepted $description"
    fi
}

probe_weak_effective_floor()
{
    variable=$1
    stdout_file=$tmp/weak-$variable.stdout
    stderr_file=$tmp/weak-$variable.stderr
    expected='coverage-contract: ERROR: Makefile coverage recipe or coverage floors violate the contract'

    if MAKEFLAGS='' MFLAGS='' "$policy_make" -f "$contract_makefile" \
        "$variable=0" coverage-contract-test \
        >"$stdout_file" 2>"$stderr_file"; then
        fail "weak effective $variable unexpectedly passed"
    fi
    grep -F -x -- "$expected" "$stderr_file" >/dev/null ||
        fail "weak effective $variable lacked the causal contract diagnostic"
}

write_coverage_commands()
{
    makefile=$1
    output=$2

    awk '
        BEGIN {
            active = 0
            found = 0
            command = ""
        }
        /^coverage[[:space:]]*:/ {
            active = 1
            found++
            next
        }
        active && /^[^[:space:]#][^:]*:/ {
            active = 0
        }
        active {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            if (line ~ /^#/) {
                next
            }
            sub(/[[:space:]]+#.*$/, "", line)
            continued = sub(/[[:space:]]*\\[[:space:]]*$/, "", line)
            if (line != "") {
                if (command == "") {
                    command = line
                } else {
                    command = command " " line
                }
            }
            if (!continued && command != "") {
                print command
                command = ""
            }
        }
        END {
            if (found != 1) {
                exit 1
            }
            if (command != "") {
                print command
            }
        }
    ' "$makefile" >"$output"
}

valid_percentage()
{
    value=$1

    case $value in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#value}" -le 3 ] || return 1
    [ "$value" -le 100 ]
}

validate_contract()
{
    makefile=$1
    effective_lines=$2
    effective_branches=$3
    commands_file=$tmp/contract-commands

    validate_make_semantics "$makefile" || return 1
    default_lines=$(read_default_floor "$makefile" COVERAGE_MIN_LINES) ||
        return 1
    default_branches=$(read_default_floor "$makefile" COVERAGE_MIN_BRANCHES) ||
        return 1
    valid_percentage "$default_lines" || return 1
    valid_percentage "$default_branches" || return 1
    valid_percentage "$effective_lines" || return 1
    valid_percentage "$effective_branches" || return 1

    # These are the ratchets established by the measured repository baseline.
    # Runtime overrides may strengthen them, but may not weaken either the
    # checked-in defaults or the established policy.
    [ "$default_lines" -ge "$contract_min_lines" ] || return 1
    [ "$default_branches" -ge "$contract_min_branches" ] || return 1
    [ "$effective_lines" -ge "$default_lines" ] || return 1
    [ "$effective_branches" -ge "$default_branches" ] || return 1

    write_coverage_commands "$makefile" "$commands_file" || return 1
    # shellcheck disable=SC2016 # Literal Make expressions are the contract.
    expected_threshold='@$(GCOVR) --root "$(CURDIR)" --json-add-tracefile "$(COVERAGE_REPORT_DIR)/coverage.json" --txt="$(COVERAGE_REPORT_DIR)/threshold.txt" --fail-under-line "$(COVERAGE_MIN_LINES)" --fail-under-branch "$(COVERAGE_MIN_BRANCHES)"'
    [ "$(grep -F -x -c -- "$expected_threshold" "$commands_file")" -eq 1 ] ||
        return 1
    terminal_command=$(awk 'NF { command = $0 } END { print command }' \
        "$commands_file") || return 1
    [ "$terminal_command" = "$expected_threshold" ] || return 1
}

mutate_coverage_flag()
{
    input=$1
    output=$2
    flag=$3

    awk -v flag="$flag" '
        BEGIN {
            active = 0
            changed = 0
        }
        /^coverage[[:space:]]*:/ {
            active = 1
            print
            next
        }
        active && /^[^[:space:]#][^:]*:/ {
            active = 0
        }
        {
            if (active && index($0, flag) != 0) {
                sub(flag, "--contract-removed")
                changed++
                print
                if (flag == "--fail-under-line") {
                    print "\t# decoy: --fail-under-line \"$(COVERAGE_MIN_LINES)\""
                } else {
                    print "\t# decoy: --fail-under-branch \"$(COVERAGE_MIN_BRANCHES)\""
                }
                next
            }
            print
        }
        END {
            if (changed != 1) {
                exit 1
            }
        }
    ' "$input" >"$output"
}

mutate_default_floor()
{
    input=$1
    output=$2
    variable=$3
    replacement=$4

    awk -v variable="$variable" -v replacement="$replacement" '
        BEGIN {
            pattern = "^[[:space:]]*" variable "[[:space:]]*\\?="
            changed = 0
        }
        {
            if ($0 ~ pattern) {
                prefix = $0
                sub(/=.*/, "=", prefix)
                print prefix " " replacement
                changed++
            } else {
                print
            }
        }
        END {
            if (changed != 1) {
                exit 1
            }
        }
    ' "$input" >"$output"
}

mutate_threshold_suffix()
{
    input=$1
    output=$2
    suffix=$3

    awk -v suffix="$suffix" '
        BEGIN {
            active = 0
            changed = 0
        }
        /^coverage[[:space:]]*:/ {
            active = 1
            print
            next
        }
        active && /--fail-under-branch/ {
            print $0 " " suffix
            changed++
            next
        }
        active && /^[^[:space:]#][^:]*:/ {
            active = 0
        }
        {
            print
        }
        END {
            if (changed != 1) {
                exit 1
            }
        }
    ' "$input" >"$output"
}

mutate_threshold_prefix()
{
    input=$1
    output=$2

    awk '
        BEGIN {
            active = 0
            changed = 0
        }
        /^coverage[[:space:]]*:/ {
            active = 1
            print
            next
        }
        active && /--fail-under-line/ {
            print "\t\t; true \\"
            print
            changed++
            next
        }
        active && /^[^[:space:]#][^:]*:/ {
            active = 0
        }
        {
            print
        }
        END {
            if (changed != 1) {
                exit 1
            }
        }
    ' "$input" >"$output"
}

mutate_later_coverage_command()
{
    input=$1
    output=$2

    awk '
        BEGIN {
            active = 0
            changed = 0
        }
        /^coverage[[:space:]]*:/ {
            active = 1
            print
            next
        }
        active && /--fail-under-branch/ {
            print
            print "\t@true"
            changed++
            next
        }
        active && /^[^[:space:]#][^:]*:/ {
            active = 0
        }
        {
            print
        }
        END {
            if (changed != 1) {
                exit 1
            }
        }
    ' "$input" >"$output"
}

append_make_line()
{
    input=$1
    output=$2
    line=$3

    awk '{ print }' "$input" >"$output" || return 1
    printf '%s\n' "$line" >>"$output"
}

execution_mode=dynamic
case ${1-} in
--static)
    [ "$#" -eq 2 ] || fail "usage: $0 --static MAKEFILE"
    execution_mode=behavioral-static
    contract_makefile=$2
    effective_lines=$(read_default_floor \
        "$contract_makefile" COVERAGE_MIN_LINES) ||
        fail "cannot read the checked-in line coverage floor"
    effective_branches=$(read_default_floor \
        "$contract_makefile" COVERAGE_MIN_BRANCHES) ||
        fail "cannot read the checked-in branch coverage floor"
    ;;
--source-static)
    [ "$#" -eq 2 ] || fail "usage: $0 --source-static MAKEFILE"
    execution_mode=source-static
    contract_makefile=$2
    effective_lines=$(read_default_floor \
        "$contract_makefile" COVERAGE_MIN_LINES) ||
        fail "cannot read the checked-in line coverage floor"
    effective_branches=$(read_default_floor \
        "$contract_makefile" COVERAGE_MIN_BRANCHES) ||
        fail "cannot read the checked-in branch coverage floor"
    ;;
*)
    [ "$#" -eq 1 ] || fail "usage: $0 MAKEFILE"
    contract_makefile=$1
    effective_lines=${COVERAGE_CONTRACT_LINES-}
    effective_branches=${COVERAGE_CONTRACT_BRANCHES-}
    ;;
esac
[ -f "$contract_makefile" ] ||
    fail "coverage Makefile is not a regular file: $contract_makefile"

contract_min_lines=69
contract_min_branches=58

cc_name=${COVERAGE_CC:-gcc}
gcov_name=${COVERAGE_GCOV:-gcov}
gcovr_name=${GCOVR:-gcovr}

for tool in mktemp chmod rm cat grep awk; do
    command -v "$tool" >/dev/null 2>&1 ||
        fail "required tool is unavailable: $tool"
done

if [ "$execution_mode" = behavioral-static ]; then
    policy_make=$(resolve_gnu_make)
fi

export LC_ALL=C
umask 077
tmp_parent=$(CDPATH='' cd "${TMPDIR:-/tmp}" && pwd -P) ||
    fail "cannot resolve temporary-directory parent"
tmp=$(mktemp -d "$tmp_parent/gitswitch-coverage-contract.XXXXXX") ||
    fail "cannot create private coverage fixture directory"
cleanup()
{
    status=$?
    trap - 0 1 2 3 15
    if [ -d "$tmp" ] && [ ! -L "$tmp" ]; then
        rm -rf "$tmp" ||
            printf 'coverage-contract: WARNING: cleanup failed: %s\n' \
                "$tmp" >&2
    else
        printf 'coverage-contract: WARNING: fixture root identity changed: %s\n' \
            "$tmp" >&2
    fi
    exit "$status"
}
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 131' 3
trap 'exit 143' 15

chmod 0700 "$tmp" || fail "cannot secure coverage fixture directory"
{ [ -d "$tmp" ] && [ ! -L "$tmp" ]; } ||
    fail "coverage fixture root is not a private directory"

validate_contract "$contract_makefile" \
    "$effective_lines" "$effective_branches" ||
    fail "Makefile coverage recipe or coverage floors violate the contract"
configured_lines=$effective_lines
configured_branches=$effective_branches

# Mutation witnesses prove that validation is causally attached to the real
# coverage target and checked-in floors, rather than to lookalike test data.
for flag in --fail-under-line --fail-under-branch; do
    mutation=$tmp/missing-${flag#--}.mk
    mutate_coverage_flag "$contract_makefile" "$mutation" "$flag" ||
        fail "cannot construct $flag mutation witness"
    if validate_contract "$mutation" \
        "$effective_lines" "$effective_branches"; then
        fail "contract accepted coverage recipe without $flag"
    fi
done

mutation=$tmp/suppressed-threshold.mk
mutate_threshold_suffix "$contract_makefile" "$mutation" '|| :' ||
    fail "cannot construct threshold-suppression mutation witness"
if validate_contract "$mutation" "$effective_lines" "$effective_branches"; then
    fail "contract accepted suppressed threshold command"
fi

mutation=$tmp/prefixed-threshold.mk
mutate_threshold_prefix "$contract_makefile" "$mutation" ||
    fail "cannot construct threshold-prefix mutation witness"
if validate_contract "$mutation" "$effective_lines" "$effective_branches"; then
    fail "contract accepted command termination before threshold flags"
fi

mutation=$tmp/later-coverage-command.mk
mutate_later_coverage_command "$contract_makefile" "$mutation" ||
    fail "cannot construct nonterminal-threshold mutation witness"
if validate_contract "$mutation" "$effective_lines" "$effective_branches"; then
    fail "contract accepted a nonterminal threshold command"
fi

for directive in '.IGNORE:' '.IGNORE: coverage' '.ONESHELL:'; do
    mutation=$tmp/directive-${directive%%:*}.mk
    append_make_line "$contract_makefile" "$mutation" "$directive" ||
        fail "cannot construct $directive mutation witness"
    if validate_contract "$mutation" \
        "$effective_lines" "$effective_branches"; then
        fail "contract accepted active $directive"
    fi
done

mutation=$tmp/eval-ignore.mk
# shellcheck disable=SC2016 # Literal Make expression is the mutation.
append_make_line "$contract_makefile" "$mutation" \
    '$(eval .IGNORE: coverage coverage-contract-test)' ||
    fail "cannot construct eval-ignore mutation witness"
if validate_contract "$mutation" \
    "$effective_lines" "$effective_branches"; then
    fail "contract accepted eval-created .IGNORE targets"
fi

mutation=$tmp/indirect-ignore.mk
append_make_line "$contract_makefile" "$mutation" \
    'COVERAGE_SPECIAL := .IGNORE' ||
    fail "cannot construct indirect-ignore variable witness"
# shellcheck disable=SC2016 # Literal Make expression is the mutation.
printf '%s\n' \
    '$(COVERAGE_SPECIAL): coverage coverage-contract-test' >>"$mutation"
if validate_contract "$mutation" \
    "$effective_lines" "$effective_branches"; then
    fail "contract accepted indirectly named .IGNORE target"
fi

assignment_index=0
for assignment in \
    'MAKEFLAGS += -i' \
    'MFLAGS := -i' \
    'coverage: private SHELL := /bin/true' \
    '.SHELLFLAGS := -c'; do
    assignment_index=$((assignment_index + 1))
    mutation=$tmp/make-control-assignment-$assignment_index.mk
    append_make_line "$contract_makefile" "$mutation" "$assignment" ||
        fail "cannot construct Make control-assignment witness"
    if validate_contract "$mutation" \
        "$effective_lines" "$effective_branches"; then
        fail "contract accepted active Make control assignment: $assignment"
    fi
done

mutation=$tmp/weakened-lines.mk
mutate_default_floor "$contract_makefile" "$mutation" \
    COVERAGE_MIN_LINES "$((contract_min_lines - 1))" ||
    fail "cannot construct line-floor mutation witness"
if validate_contract "$mutation" \
    "$((contract_min_lines - 1))" "$effective_branches"; then
    fail "contract accepted weakened line coverage floor"
fi

mutation=$tmp/weakened-branches.mk
mutate_default_floor "$contract_makefile" "$mutation" \
    COVERAGE_MIN_BRANCHES "$((contract_min_branches - 1))" ||
    fail "cannot construct branch-floor mutation witness"
if validate_contract "$mutation" \
    "$effective_lines" "$((contract_min_branches - 1))"; then
    fail "contract accepted weakened branch coverage floor"
fi

mutation=$tmp/overridden-lines.mk
append_make_line "$contract_makefile" "$mutation" \
    'coverage: COVERAGE_MIN_LINES := 0' ||
    fail "cannot construct target-specific line-floor witness"
if validate_contract "$mutation" \
    "$effective_lines" "$effective_branches"; then
    fail "contract accepted target-specific line coverage assignment"
fi

mutation=$tmp/overridden-branches.mk
append_make_line "$contract_makefile" "$mutation" \
    'coverage: private COVERAGE_MIN_BRANCHES := 0' ||
    fail "cannot construct private branch-floor witness"
if validate_contract "$mutation" \
    "$effective_lines" "$effective_branches"; then
    fail "contract accepted private branch coverage assignment"
fi

# Reject unbounded digit strings before passing them to the shell's integer
# comparison operator, whose supported range is implementation-defined.
mutation=$tmp/out-of-range-lines.mk
mutate_default_floor "$contract_makefile" "$mutation" \
    COVERAGE_MIN_LINES 999999999999999999999999999999999999 ||
    fail "cannot construct out-of-range floor witness"
if validate_contract "$mutation" \
    999999999999999999999999999999999999 "$effective_branches"; then
    fail "contract accepted out-of-range line coverage floor"
fi

if [ "$execution_mode" = source-static ]; then
    printf 'Coverage Makefile source-static contract passed.\n'
    exit 0
fi

if [ "$execution_mode" = behavioral-static ]; then
    write_behavioral_probe_makefiles

    mutation=$tmp/evaluated-brace-ignore.mk
    append_make_line "$contract_makefile" "$mutation" 'DOT := .' ||
        fail "cannot construct evaluated brace-ignore witness"
    # shellcheck disable=SC2016 # Literal Make expressions are mutations.
    printf '%s\n' \
        'IGNORE_WORD := IGNORE' \
        '${eval ${DOT}${IGNORE_WORD}: coverage coverage-contract-test}' \
        >>"$mutation"
    expect_behavioral_rejected "$mutation" \
        "brace-eval computed .IGNORE"

    mutation=$tmp/evaluated-target-ignore.mk
    append_make_line "$contract_makefile" "$mutation" 'DOT := .' ||
        fail "cannot construct evaluated target-ignore witness"
    # shellcheck disable=SC2016 # Literal Make expressions are mutations.
    printf '%s\n' \
        'IGNORE_WORD := IGNORE' \
        '$(DOT)$(IGNORE_WORD): coverage coverage-contract-test' \
        >>"$mutation"
    expect_behavioral_rejected "$mutation" \
        "computed .IGNORE target"

    mutation=$tmp/evaluated-target-floor.mk
    append_make_line "$contract_makefile" "$mutation" \
        'TARGET_NAME := coverage' ||
        fail "cannot construct evaluated target-floor witness"
    # shellcheck disable=SC2016 # Literal Make expressions are mutations.
    printf '%s\n' \
        'FLOOR_NAME := COVERAGE_MIN_LINES' \
        '${TARGET_NAME}: ${FLOOR_NAME} := 0' \
        >>"$mutation"
    expect_behavioral_rejected "$mutation" \
        "computed target-specific floor"

    mutation=$tmp/evaluated-pattern-floor.mk
    append_make_line "$contract_makefile" "$mutation" \
        '%age: private COVERAGE_MIN_LINES := 0' ||
        fail "cannot construct evaluated pattern-floor witness"
    expect_behavioral_rejected "$mutation" \
        "private pattern-specific floor"

    mutation=$tmp/evaluated-makeflags.mk
    append_make_line "$contract_makefile" "$mutation" \
        'FLAGS_NAME := MAKEFLAGS' ||
        fail "cannot construct evaluated MAKEFLAGS witness"
    # shellcheck disable=SC2016 # Literal Make expression is the mutation.
    printf '%s\n' '${eval ${FLAGS_NAME} += -i}' >>"$mutation"
    expect_behavioral_rejected "$mutation" \
        "computed MAKEFLAGS ignore mode"

    mutation=$tmp/evaluated-shell.mk
    append_make_line "$contract_makefile" "$mutation" \
        'SHELL_NAME := SHELL' ||
        fail "cannot construct evaluated SHELL witness"
    # shellcheck disable=SC2016 # Literal Make expression is the mutation.
    printf '%s\n' '${eval ${SHELL_NAME} := /bin/true}' >>"$mutation"
    expect_behavioral_rejected "$mutation" "computed SHELL"

    mutation=$tmp/evaluated-define-shell.mk
    append_make_line "$contract_makefile" "$mutation" \
        'SHELL_NAME := SHELL' ||
        fail "cannot construct evaluated define-SHELL witness"
    # shellcheck disable=SC2016 # Literal Make expressions are mutations.
    printf '%s\n' \
        'define SET_COVERAGE_SHELL' \
        '${SHELL_NAME} := /bin/true' \
        'endef' \
        '${eval ${SET_COVERAGE_SHELL}}' \
        >>"$mutation"
    expect_behavioral_rejected "$mutation" "define-created SHELL"

    validate_behavioral_make "$contract_makefile" ||
        fail "behavioral GNU Make coverage policy is unsafe"
    probe_weak_effective_floor COVERAGE_MIN_LINES
    probe_weak_effective_floor COVERAGE_MIN_BRANCHES
    printf 'Coverage Makefile static contract passed.\n'
    exit 0
fi

for tool in "$cc_name" "$gcov_name" "$gcovr_name"; do
    command -v "$tool" >/dev/null 2>&1 ||
        fail "required tool is unavailable: $tool"
done
cc_cmd=$(command -v "$cc_name") ||
    fail "cannot resolve compiler: $cc_name"
gcov_cmd=$(command -v "$gcov_name") ||
    fail "cannot resolve gcov: $gcov_name"
gcovr_cmd=$(command -v "$gcovr_name") ||
    fail "cannot resolve gcovr: $gcovr_name"

cat >"$tmp/fixture.c" <<'EOF'
#include <stdlib.h>

int deliberately_uncovered(int value)
{
    int result = value;
    if (value > 0) {
        result += 1;
    }
    if (value > 1) {
        result += 2;
    }
    if (value > 2) {
        result += 3;
    }
    if (value > 3) {
        result += 4;
    }
    if (value > 4) {
        result += 5;
    }
    return result;
}

static int choose_result(int value)
{
    if (value == 42) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    (void)argv;
    return choose_result(argc);
}
EOF

(
    CDPATH='' cd "$tmp"
    "$cc_cmd" -std=c11 -O0 -g --coverage -fprofile-abs-path \
        fixture.c -o fixture
    ./fixture
) || fail "cannot compile and execute the GCC coverage fixture"

# gcovr documents status 2 for a failed line threshold and status 4 for a
# failed branch threshold. When both fail, it bitwise-ORs them into status 6.
line_failure_status=2
branch_failure_status=4
combined_failure_status=$((line_failure_status | branch_failure_status))

# The zero-threshold control proves gcovr can read this fixture before any
# deliberately failing assertion is accepted as evidence.
run_threshold_check baseline 0 0 0
grep -F 'fixture.c' "$tmp/baseline.txt" >/dev/null || {
    show_logs baseline "$tmp/baseline.stdout" "$tmp/baseline.stderr"
    fail "gcovr baseline did not discover the fixture source"
}

# Each component status proves that the corresponding metric is genuinely
# below 100%; the combined assertion then verifies gcovr's ORed exit contract.
# gcovr 7.x/8.0 logs "failed minimum ..." while newer releases capitalize
# "Failed". Match that presentation-only difference without relaxing the exact
# metric-specific diagnostic or the authoritative status-bit checks above.
run_threshold_check line-only "$line_failure_status" 100 0
grep -F -i 'failed minimum line coverage' "$tmp/line-only.stderr" >/dev/null ||
    fail "line-only control lacked gcovr's threshold diagnostic"

run_threshold_check branch-only "$branch_failure_status" 0 100
grep -F -i 'failed minimum branch coverage' \
    "$tmp/branch-only.stderr" >/dev/null ||
    fail "branch-only control lacked gcovr's threshold diagnostic"

run_threshold_check combined "$combined_failure_status" 100 100
grep -F -i 'failed minimum line coverage' "$tmp/combined.stderr" >/dev/null ||
    fail "combined control lacked gcovr's line-threshold diagnostic"
grep -F -i 'failed minimum branch coverage' "$tmp/combined.stderr" >/dev/null ||
    fail "combined control lacked gcovr's branch-threshold diagnostic"

# The configured project floors must also trip both status bits on the fixture.
# This prevents the recipe/floor parser and the synthetic 100% controls from
# becoming two self-consistent but disconnected assertions.
run_threshold_check configured "$combined_failure_status" \
    "$configured_lines" "$configured_branches"

printf 'Coverage threshold contract passed (line=%d, branch=%d, combined=%d).\n' \
    "$line_failure_status" "$branch_failure_status" \
    "$combined_failure_status"
