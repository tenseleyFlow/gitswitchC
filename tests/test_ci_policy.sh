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

    # Parse the workflow's action and permission surface as a deliberately
    # small YAML subset. This is dependency-free for release tarballs while
    # still being structural: comments and quotes are lexed, block and simple
    # flow permission/step/input mappings are equivalent, job overrides are
    # inspected, and ambiguous constructs (aliases, merges, duplicate critical
    # keys) fail closed. Required release gates receive an additional executable
    # subset: exact commands must be reachable, standalone run entries on the
    # reviewed runner/configuration rather than comments or inert YAML text.
    awk '
        function reject(reason) {
            rejected = 1
            if (reason == "") reason = "unsupported policy structure"
            print reason " at line " NR
            exit 1
        }
        function ltrim(value) {
            sub(/^[[:space:]]+/, "", value)
            return value
        }
        function rtrim(value) {
            sub(/[[:space:]]+$/, "", value)
            return value
        }
        function trim(value) {
            return rtrim(ltrim(value))
        }
        function indentation(line, prefix) {
            prefix = line
            sub(/[^ ].*$/, "", prefix)
            return length(prefix)
        }
        function lex(line, i, c, next_c, quote, escaped, output) {
            lex_ok = 1
            lex_comment = ""
            quote = 0
            escaped = 0
            output = ""
            for (i = 1; i <= length(line); i++) {
                c = substr(line, i, 1)
                next_c = substr(line, i + 1, 1)
                if (quote == 1) {
                    output = output c
                    if (c == single_quote) {
                        if (next_c == single_quote) {
                            output = output next_c
                            i++
                        } else {
                            quote = 0
                        }
                    }
                    continue
                }
                if (quote == 2) {
                    output = output c
                    if (escaped) {
                        escaped = 0
                    } else if (c == "\\") {
                        escaped = 1
                    } else if (c == "\"") {
                        quote = 0
                    }
                    continue
                }
                if (c == single_quote) {
                    quote = 1
                    output = output c
                    continue
                }
                if (c == "\"") {
                    quote = 2
                    output = output c
                    continue
                }
                if (c == "#" &&
                    (i == 1 || substr(line, i - 1, 1) ~ /[[:space:]]/)) {
                    lex_comment = trim(substr(line, i + 1))
                    break
                }
                output = output c
            }
            if (quote != 0 || escaped) lex_ok = 0
            return rtrim(output)
        }
        function decode_scalar(value, i, c, next_c, output) {
            scalar_ok = 1
            scalar_quoted = 0
            value = trim(value)
            if (value == "") {
                scalar_value = ""
                return
            }
            c = substr(value, 1, 1)
            if (c == single_quote) {
                scalar_quoted = 1
                if (length(value) < 2 ||
                    substr(value, length(value), 1) != single_quote) {
                    scalar_ok = 0
                    return
                }
                output = ""
                for (i = 2; i < length(value); i++) {
                    c = substr(value, i, 1)
                    next_c = substr(value, i + 1, 1)
                    if (c == single_quote) {
                        if (next_c != single_quote || i + 1 >= length(value)) {
                            scalar_ok = 0
                            return
                        }
                        output = output single_quote
                        i++
                    } else {
                        output = output c
                    }
                }
                scalar_value = output
                return
            }
            if (c == "\"") {
                scalar_quoted = 1
                if (length(value) < 2 ||
                    substr(value, length(value), 1) != "\"") {
                    scalar_ok = 0
                    return
                }
                output = substr(value, 2, length(value) - 2)
                # Escaped critical scalars are valid YAML but outside this
                # canonical subset; rejecting them avoids implementing the
                # complete YAML escape and Unicode rules incorrectly.
                if (output ~ /\\/) {
                    scalar_ok = 0
                    return
                }
                scalar_value = output
                return
            }
            scalar_value = value
        }
        function find_colon(value, i, c, next_c, quote, escaped) {
            quote = 0
            escaped = 0
            for (i = 1; i <= length(value); i++) {
                c = substr(value, i, 1)
                next_c = substr(value, i + 1, 1)
                if (quote == 1) {
                    if (c == single_quote) {
                        if (next_c == single_quote) i++
                        else quote = 0
                    }
                    continue
                }
                if (quote == 2) {
                    if (escaped) escaped = 0
                    else if (c == "\\") escaped = 1
                    else if (c == "\"") quote = 0
                    continue
                }
                if (c == single_quote) quote = 1
                else if (c == "\"") quote = 2
                else if (c == ":") return i
            }
            return 0
        }
        function parse_entry(value, colon) {
            entry_ok = 0
            entry_sequence = 0
            entry_scalar_sequence = 0
            entry_key = ""
            entry_value = ""
            value = ltrim(value)
            if (substr(value, 1, 1) == "-" &&
                (length(value) == 1 || substr(value, 2, 1) ~ /[[:space:]]/)) {
                entry_sequence = 1
                value = ltrim(substr(value, 2))
            }
            if (value == "" || substr(value, 1, 1) == "{" ||
                substr(value, 1, 1) == "[") return
            colon = find_colon(value)
            if (!colon) {
                if (entry_sequence && value ~ /^[A-Za-z0-9_.-]+$/) {
                    entry_scalar_sequence = 1
                    entry_ok = 1
                }
                return
            }
            decode_scalar(trim(substr(value, 1, colon - 1)))
            if (!scalar_ok || scalar_value !~ /^[A-Za-z0-9_-]+$/) return
            entry_key = scalar_value
            entry_value = trim(substr(value, colon + 1))
            entry_ok = 1
        }
        function clear_permissions(key) {
            for (key in permission_value) delete permission_value[key]
            permission_count = 0
        }
        function add_permission(key_text, value_text, key) {
            decode_scalar(key_text)
            if (!scalar_ok || scalar_value !~ /^[A-Za-z0-9_-]+$/) reject()
            key = scalar_value
            if (key in permission_value) reject()
            decode_scalar(value_text)
            if (!scalar_ok || scalar_value == "") reject()
            permission_value[key] = scalar_value
            permission_count++
        }
        function validate_permissions(scope, key, value) {
            if (scope == "top") {
                if (permission_count != 1 ||
                    !("contents" in permission_value) ||
                    permission_value["contents"] != "read") reject()
                return
            }
            # A job may only preserve/narrow the top-level contents:read
            # grant. Values for every other scope must remain explicitly none.
            for (key in permission_value) {
                value = permission_value[key]
                if (value == "write" || value == "write-all") reject()
                if (value != "none" &&
                    !(key == "contents" && value == "read")) reject()
            }
        }
        function parse_flow_permission_piece(piece, colon) {
            piece = trim(piece)
            if (piece == "") reject()
            colon = find_colon(piece)
            if (!colon) reject()
            add_permission(trim(substr(piece, 1, colon - 1)),
                           trim(substr(piece, colon + 1)))
        }
        function parse_flow_permissions(value, scope, inner, i, c, next_c,
                                        quote, escaped, piece) {
            if (substr(value, 1, 1) != "{" ||
                substr(value, length(value), 1) != "}") reject()
            inner = trim(substr(value, 2, length(value) - 2))
            clear_permissions()
            if (inner == "") {
                validate_permissions(scope)
                return
            }
            quote = 0
            escaped = 0
            piece = ""
            for (i = 1; i <= length(inner); i++) {
                c = substr(inner, i, 1)
                next_c = substr(inner, i + 1, 1)
                if (quote == 1) {
                    piece = piece c
                    if (c == single_quote) {
                        if (next_c == single_quote) {
                            piece = piece next_c
                            i++
                        } else quote = 0
                    }
                    continue
                }
                if (quote == 2) {
                    piece = piece c
                    if (escaped) escaped = 0
                    else if (c == "\\") escaped = 1
                    else if (c == "\"") quote = 0
                    continue
                }
                if (c == single_quote) quote = 1
                else if (c == "\"") quote = 2
                else if (c == "{" || c == "}" || c == "[" || c == "]")
                    reject()
                if (c == "," && quote == 0) {
                    parse_flow_permission_piece(piece)
                    piece = ""
                } else {
                    piece = piece c
                }
            }
            if (quote != 0 || escaped || trim(piece) == "") reject()
            parse_flow_permission_piece(piece)
            validate_permissions(scope)
        }
        function start_permissions(scope, indent, value) {
            clear_permissions()
            if (value == "") {
                permissions_active = 1
                permissions_scope = scope
                permissions_indent = indent
                return
            }
            if (substr(value, 1, 1) == "{") {
                parse_flow_permissions(value, scope)
                return
            }
            decode_scalar(value)
            if (!scalar_ok || scalar_value == "" ||
                scalar_value == "write-all" || scalar_value == "read-all")
                reject()
            # Scalar permission forms other than read-all/write-all are not
            # part of the Actions schema and are rejected rather than guessed.
            reject()
        }
        function close_permissions() {
            if (!permissions_active) return
            if (permission_count == 0) reject()
            validate_permissions(permissions_scope)
            permissions_active = 0
        }
        function close_branch_sequence() {
            if (!branch_sequence_active) return
            if (branch_item_count == 0)
                reject("on.push.branches must contain at least one item")
            branch_sequence_active = 0
        }
        function required_release_job(job) {
            return job == "linux" || job == "macos" || job == "freebsd"
        }
        function clear_step_commands(i) {
            for (i in step_command_text) delete step_command_text[i]
            for (i in step_command_source) delete step_command_source[i]
            for (i in step_command_eligible) delete step_command_eligible[i]
            for (i in step_command_serial) delete step_command_serial[i]
            step_command_count = 0
        }
        function add_step_command(text, source, eligible) {
            if (text == "") return
            step_command_count++
            command_serial++
            step_command_text[step_command_count] = text
            step_command_source[step_command_count] = source
            step_command_eligible[step_command_count] = eligible
            step_command_serial[step_command_count] = command_serial
        }
        function shell_trailing_continuation(value, count, i) {
            value = rtrim(value)
            if (value ~ /(&&|\|\||\|)$/) return 1
            count = 0
            for (i = length(value); i > 0 && substr(value, i, 1) == "\\"; i--)
                count++
            return count % 2
        }
        function mutates_executable_resolution(command) {
            # AR-12 L25: overwriting a tool in its canonical root
            # (/usr/bin, /usr/sbin, /bin, /sbin) is the same substitution
            # the /usr/local fixtures already reject; ban mutation verbs
            # and redirections that target those roots. Reviewed apt/pkg
            # provisioning never spells such paths.
            if (command ~ /(^|[;&|[:space:]])(sudo[[:space:]]+)?(install|cp|mv|ln|rsync)([[:space:]][^;&|]*)?[[:space:]]\/(usr\/)?s?bin\/[^[:space:];&|]*[[:space:]]*($|[;&|])/)
                return 1
            # AR-13 M5: install -t DIR / --target-directory DIR names the
            # canonical root with no trailing slash, so the destination-argument
            # rule above misses it. The match is scoped to the install target
            # flag so legitimate /usr/bin/make invocations are untouched.
            if (command ~ /(^|[;&|[:space:]])(sudo[[:space:]]+)?install[[:space:]]([^;&|]*[[:space:]])?(-t|--target-directory)[[:space:]]+\/(usr\/)?s?bin(\/|[[:space:]]|[;&|]|$)/)
                return 1
            # AR-13 M5: `cd` into a canonical bin root sets up a relative-name
            # overwrite (`cd /usr/bin && cp evil make`) the destination rule
            # cannot see; mirror the /usr/local cd handling for the canonical
            # roots. Reviewed CI never changes into these directories.
            if (command ~ /(^|[;&|[:space:]])cd[[:space:]]+\/(usr\/)?s?bin(\/|[[:space:]]|[;&|]|$)/)
                return 1
            if (command ~ /(^|[;&|[:space:]])(sudo[[:space:]]+)?tee[[:space:]]([^;&|]*[[:space:]])?\/(usr\/)?s?bin\//)
                return 1
            if (command ~ /of=\/(usr\/)?s?bin\//)
                return 1
            if (command ~ /(^|[;&|[:space:]])(sudo[[:space:]]+)?(chmod|chown|touch)[[:space:]]([^;&|]*[[:space:]])?\/(usr\/)?s?bin\//)
                return 1
            if (command ~ />>?[[:space:]]*\/(usr\/)?s?bin\//)
                return 1
            return command ~ /^(alias|eval|source|trap)[[:space:]]/ ||
                command ~ /^\.[[:space:]]/ ||
                command ~ /^(export[[:space:]]+)?(PATH|MAKEFLAGS|MFLAGS|BASH_ENV|ENV|SHELLOPTS|BASHOPTS)=/ ||
                command ~ /\/usr\/local\/(bin|sbin)([^A-Za-z0-9_.-]|$)/ ||
                command ~ /^(function[[:space:]]+)?g?make[[:space:]]*(\(\))?[[:space:]]*\{/ ||
                command ~ /^hash[[:space:]].*g?make/ ||
                (command ~ /\/usr\/(local\/)?bin\/g?make/ &&
                 command !~ /^\/usr\/bin\/make([[:space:]]|$)/)
        }
        function record_block_command(raw_line, source, line, i, c, escaped,
                                      quote_at_start, continued_at_start,
                                      depth_at_start, eligible) {
            line = ltrim(raw_line)
            quote_at_start = shell_quote
            continued_at_start = shell_continued
            depth_at_start = shell_control_depth
            escaped = 0
            shell_code = ""
            for (i = 1; i <= length(line); i++) {
                c = substr(line, i, 1)
                if (shell_quote == 1) {
                    shell_code = shell_code c
                    if (c == single_quote) shell_quote = 0
                    continue
                }
                if (shell_quote == 2) {
                    shell_code = shell_code c
                    if (escaped) escaped = 0
                    else if (c == "\\") escaped = 1
                    else if (c == "\"") shell_quote = 0
                    continue
                }
                if (c == single_quote) shell_quote = 1
                else if (c == "\"") shell_quote = 2
                else if (c == "#" &&
                         (i == 1 || substr(line, i - 1, 1) ~ /[[:space:]]/))
                    break
                shell_code = shell_code c
            }
            shell_code = trim(shell_code)
            if (shell_code == "") return

            if (shell_code ~ /<</ || shell_code ~ /`/)
                step_unsafe_script = 1
            if (shell_code ~ /[({][[:space:]]*$/)
                step_unsafe_script = 1
            if (source == "direct" && current_job == "freebsd" &&
                (shell_code ~ /^(alias|eval|source|trap)[[:space:]]/ ||
                 shell_code ~ /^\.[[:space:]]/ ||
                 shell_code ~ /^(export[[:space:]]+)?(PATH|MAKEFLAGS|MFLAGS|BASH_ENV|ENV|SHELLOPTS|BASHOPTS)=/ ||
                 shell_code ~ /^(function[[:space:]]+)?g?make[[:space:]]*(\(\))?[[:space:]]*\{/ ||
                 shell_code ~ /^hash[[:space:]].*g?make/ ||
                 shell_code ~ /^set[[:space:]]+\+e([[:space:]]|$)/ ||
                 shell_code ~ /^set[[:space:]]+\+o[[:space:]]+errexit([[:space:]]|$)/ ||
                 shell_code ~ /^shopt[[:space:]].*expand_aliases/))
                step_unsafe_script = 1
            if (source == "direct" && required_release_job(current_job) &&
                mutates_executable_resolution(shell_code))
                release_job_resolver_mutation[current_job] = 1
            if (required_release_job(current_job) &&
                shell_code ~ /GITHUB_(ENV|PATH)/)
                release_job_dynamic_env[current_job] = 1
            if (depth_at_start == 0 &&
                shell_code ~ /(^|[;&|][[:space:]]*)(exit|return)([[:space:]]|$)/)
                step_terminates_early = 1
            if (depth_at_start == 0 &&
                shell_code ~ /(^|[;&|][[:space:]]*)exec[[:space:]]+[^0-9<]/)
                step_terminates_early = 1

            if (shell_code ~ /^(fi|done|esac)([;[:space:]]|$)/ ||
                shell_code == "}") {
                if (shell_control_depth > 0) shell_control_depth--
            }
            eligible = quote_at_start == 0 && shell_quote == 0 &&
                !continued_at_start &&
                !shell_trailing_continuation(shell_code) &&
                shell_control_depth == 0
            add_step_command(shell_code, source, eligible)
            if (shell_code ~ /^(if|for|while|until|case|select)[[:space:]]/ ||
                shell_code ~ /^[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)[[:space:]]*\{/) {
                shell_control_depth++
            }
            shell_continued = shell_trailing_continuation(shell_code)
        }
        function start_run_block(source, style) {
            if (source == "direct") {
                step_direct_run_count++
                step_direct_run_style = style
            } else {
                step_action_run_count++
            }
            block_scalar_purpose = source
            shell_quote = 0
            shell_continued = 0
            shell_control_depth = 0
            if (substr(style, 1, 1) != "|") step_unsafe_script = 1
        }
        function record_scalar_run(source, value) {
            decode_scalar(value)
            if (!scalar_ok || scalar_value == "") reject()
            if (source == "direct") {
                step_direct_run_count++
                step_direct_run_style = "scalar"
            } else {
                step_action_run_count++
            }
            if (required_release_job(current_job) &&
                scalar_value ~ /GITHUB_(ENV|PATH)/)
                release_job_dynamic_env[current_job] = 1
            if (source == "direct" && required_release_job(current_job) &&
                mutates_executable_resolution(scalar_value))
                release_job_resolver_mutation[current_job] = 1
            add_step_command(scalar_value, source, 1)
        }
        function add_release_gate(key, serial) {
            release_gate_count[key]++
            if (release_gate_count[key] == 1) {
                release_gate_serial[key] = serial
                release_gate_step_serial[key] = step_serial
            }
        }
        function classify_release_step(i, command, source,
                                       gate, step_gate_count,
                                       freebsd_errexit_count,
                                       freebsd_errexit_serial,
                                       first_gate_serial,
                                       direct_release_test,
                                       sanitizer_release_test,
                                       repro_release_test) {
            step_gate_count = 0
            first_gate_serial = 0
            for (i = 1; i <= step_command_count; i++) {
                if (!step_command_eligible[i]) continue
                command = step_command_text[i]
                source = step_command_source[i]
                gate = ""
                if (current_job == "freebsd" && source == "direct" &&
                    command == "set -eu") {
                    freebsd_errexit_count++
                    freebsd_errexit_serial = step_command_serial[i]
                }
                if (current_job == "freebsd" && source == "direct" &&
                    command ~ /^export GITSWITCH_TEST_REQUIRED_CAPS=/) {
                    freebsd_caps_count++
                    freebsd_caps_serial = step_command_serial[i]
                    if (command != "export GITSWITCH_TEST_REQUIRED_CAPS=pty,readline,bash,zsh,fish,sh,dash,openssh,gpg,unix-sockets,freebsd-nullfs")
                        reject("FreeBSD required test capabilities are missing or unsafe")
                }
                if (current_job == "linux" && source == "direct") {
                    if (command ~ /(^|[;&|][[:space:]]*)(sudo[[:space:]]+)?make([[:space:]]|$)/)
                        linux_unqualified_make = 1
                    if (command ~ /^\/usr\/bin\/make([[:space:]]|$)/ &&
                        !linux_first_make_serial)
                        linux_first_make_serial = step_command_serial[i]
                    if (command == "/usr/bin/dpkg --verify make")
                        gate = "linux-make-provenance"
                    else if (command == "/bin/sh tests/test_ci_policy.sh .")
                        gate = "linux-policy"
                    else if (command == "/usr/bin/make coverage") {
                        gate = "linux-coverage"
                        direct_release_test = 1
                    } else if (command == "test \"$(/usr/bin/sed -n '\''1s/|.*//p'\'' build/obj/.buildconfig)\" = coverage && test -s build/coverage/coverage.json") {
                        gate = "linux-coverage-provenance"
                    } else if (command == "/usr/bin/make clean") {
                        linux_clean_count++
                        if (linux_clean_count == 1)
                            gate = "linux-gcc-clean"
                        else if (linux_clean_count == 2)
                            gate = "linux-clang-clean"
                        else
                            gate = "linux-extra-clean"
                    } else if (command == "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test")
                        gate = "linux-gcc-test"
                    else if (command == "/usr/bin/make BUILD_TYPE=debug READLINE=1 WERROR=1 test") {
                        # AR-12 M9: the debug ASan/UBSan lane and the QA/
                        # memory-safety lanes below could be silently deleted
                        # from ci.yml without failing this guardian.
                        gate = "linux-asan-test"
                        sanitizer_release_test = 1
                    } else if (command == "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 memcheck")
                        gate = "linux-memcheck"
                    else if (command == "/usr/bin/make distcheck")
                        gate = "linux-distcheck"
                    else if (command == "/usr/bin/make qa-contract-test")
                        gate = "linux-qa-contract"
                    else if (command == "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 sig-repro-test") {
                        gate = "linux-sig-repro"
                        repro_release_test = 1
                    } else if (command == "/usr/bin/make analyze")
                        gate = "linux-analyze"
                    else if (command == "/usr/bin/make security-scan")
                        gate = "linux-security-scan"
                    else if (command == "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test")
                        gate = "linux-gcc-artifact"
                    else if (command == "/usr/bin/make -B release-symbol-contract-test")
                        gate = "linux-symbol-contract"
                    else if (command == "/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 test")
                        gate = "linux-clang-test"
                    else if (command == "/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test")
                        gate = "linux-clang-artifact"
                    else if (command == "/usr/bin/make release-contract-test")
                        gate = "linux-contract"
                } else if (current_job == "macos" && source == "direct") {
                    # AR-12 L25: macOS gates bind to the SIP-protected
                    # /usr/bin/make so a brew-shadowed make on PATH cannot
                    # substitute the build tool.
                    if (command ~ /(^|[;&|][[:space:]]*)(sudo[[:space:]]+)?make([[:space:]]|$)/)
                        macos_unqualified_make = 1
                    if (command == "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test")
                        gate = "macos-test"
                    else if (command == "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test")
                        gate = "macos-artifact"
                    else if (command == "/usr/bin/make release-contract-test")
                        gate = "macos-contract"
                } else if (current_job == "freebsd" && source == "direct") {
                    if (command == "gmake BUILD_TYPE=release WERROR=1 test")
                        gate = "freebsd-test"
                    else if (command == "gmake BUILD_TYPE=release WERROR=1 release-artifact-test")
                        gate = "freebsd-artifact"
                    else if (command == "gmake release-contract-test")
                        gate = "freebsd-contract"
                }
                if (gate != "") {
                    add_release_gate(gate, step_command_serial[i])
                    step_gate_count++
                    if (!first_gate_serial)
                        first_gate_serial = step_command_serial[i]
                    if (gate == "linux-gcc-test" ||
                        gate == "linux-clang-test" || gate == "macos-test")
                        direct_release_test = 1
                }
            }
            if (step_gate_count == 0) return
            if (step_if_count != 0)
                reject("required release gate step must be unconditional")
            if (step_continue_count > 1 ||
                (step_continue_count == 1 && step_continue_value != "false"))
                reject("required release gate step cannot continue on error")
            if (step_workdir_count != 0)
                reject("required release gate step cannot set working-directory")
            if (current_job != "freebsd" && step_shell_count != 0)
                reject("required release gate step cannot override its shell")
            if (step_unsafe_script || step_terminates_early)
                reject("required release gate command is not provably reachable")
            if (current_job == "freebsd") {
                freebsd_release_step_count++
                if (step_use_count != 0 || step_direct_run_count != 1 ||
                    step_direct_run_style != "|" ||
                    step_action_run_count != 0)
                    reject("FreeBSD release gates must share one literal cpa shell step")
                if (step_shell_count != 1 ||
                    step_shell_value != "cpa.sh {0}")
                    reject("FreeBSD release gate step must use exact shell: cpa.sh {0}")
                if (step_serial != freebsd_action_step_serial + 1)
                    reject("FreeBSD cpa shell step must immediately follow the VM action")
                if (step_env_unsafe || step_env_map_count != 0 ||
                    step_env_count != 0)
                    reject("required release gate environment is missing or unsafe")
                if (freebsd_errexit_count != 1 ||
                    freebsd_errexit_serial >= first_gate_serial)
                    reject("FreeBSD release gates require an earlier set -eu")
            } else if (step_direct_run_count != 1 || step_action_run_count != 0 ||
                       step_command_count != 1 || step_gate_count != 1) {
                reject("required release gate must be the sole command in its step")
            } else if (step_env_unsafe ||
                       (direct_release_test &&
                        (step_env_map_count != 1 || step_env_count != 1 ||
                         step_caps_count != 1 ||
                         step_caps_value != (current_job == "linux" ? \
                             "pty,readline,bash,zsh,fish,sh,dash,ksh,openssh,gpg,unix-sockets,mount-namespace" : \
                             "pty,readline,bash,zsh,fish,sh,dash,ksh,openssh,gpg,unix-sockets"))) ||
                       (sanitizer_release_test &&
                        (step_env_map_count != 1 || step_env_count != 3 ||
                         step_sanitizer_env_count != 2 ||
                         step_asan_env_count != 1 || step_ubsan_env_count != 1 ||
                         step_caps_count != 1 ||
                         step_caps_value != "pty,readline,bash,zsh,fish,sh,dash,ksh,openssh,gpg,unix-sockets,mount-namespace")) ||
                       (repro_release_test &&
                        (step_env_map_count != 1 || step_env_count != 1 ||
                         step_caps_count != 1 ||
                         step_caps_value != "openssh")) ||
                       (!direct_release_test && !sanitizer_release_test &&
                        !repro_release_test &&
                        (step_env_map_count != 0 || step_env_count != 0))) {
                reject("required release gate environment is missing or unsafe")
            }
        }
        function require_release_gate(key) {
            if (release_gate_count[key] != 1)
                reject("missing or duplicate exact release gate: " key)
        }
        function require_release_order(earlier, later) {
            if (release_gate_serial[earlier] >= release_gate_serial[later])
                reject("required release gates are out of order")
        }
        function last_at(value, i, at) {
            at = 0
            for (i = 1; i <= length(value); i++)
                if (substr(value, i, 1) == "@") at = i
            return at
        }
        function valid_path_components(path, count, i, components) {
            if (path == "" || substr(path, 1, 1) == "/" ||
                substr(path, length(path), 1) == "/" || path ~ /\/\//)
                return 0
            count = split(path, components, "/")
            for (i = 1; i <= count; i++)
                if (components[i] == "" || components[i] == "." ||
                    components[i] == "..") return 0
            return 1
        }
        function validate_use(value, comment, at, action, ref, local_path) {
            decode_scalar(value)
            if (!scalar_ok || scalar_value == "") reject()
            action = scalar_value
            use_count++
            if (substr(action, 1, 2) == "./") {
                local_path = substr(action, 3)
                if (local_path !~ /^[A-Za-z0-9_.\/-]+$/ ||
                    !valid_path_components(local_path))
                    reject("action path has an empty, dot, or dot-dot component")
                return
            }
            at = last_at(action)
            if (!at) reject("external action lacks an immutable ref")
            ref = substr(action, at + 1)
            action = substr(action, 1, at - 1)
            if (!valid_path_components(action))
                reject("action path has an empty, dot, or dot-dot component")
            if (action !~ /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*$/)
                reject("external action path contains unsupported characters")
            if (length(ref) != 40 || ref !~ /^[0-9a-f]+$/)
                reject("external action is not pinned to a full lowercase SHA")
            if (trim(comment) !~ /^v[0-9]/)
                reject("pinned action lacks a maintained version comment")
            external_use_count++
        }
        function reset_step() {
            step_serial++
            step_active = 1
            step_use_count = 0
            step_action = ""
            step_action_comment = ""
            step_with_seen = 0
            step_in_with = 0
            step_with_indent = -1
            step_with_input_count = 0
            step_persist_count = 0
            step_persist_value = ""
            step_persist_in_with = 0
            step_os_count = 0
            step_os_value = ""
            step_os_in_with = 0
            step_version_count = 0
            step_version_value = ""
            step_version_in_with = 0
            step_memory_count = 0
            step_memory_value = ""
            step_memory_in_with = 0
            step_input_name_count = 0
            step_input_name_value = ""
            step_input_name_in_with = 0
            step_path_count = 0
            step_path_value = ""
            step_path_in_with = 0
            step_if_no_files_count = 0
            step_if_no_files_value = ""
            step_if_no_files_in_with = 0
            step_action_shell_count = 0
            step_action_shell_value = ""
            step_action_shell_in_with = 0
            step_direct_run_count = 0
            step_action_run_count = 0
            step_direct_run_style = ""
            step_if_count = 0
            step_continue_count = 0
            step_continue_value = ""
            step_shell_count = 0
            step_shell_value = ""
            step_workdir_count = 0
            step_workdir_value = ""
            step_unsafe_script = 0
            step_terminates_early = 0
            step_in_env = 0
            step_env_indent = -1
            step_env_map_count = 0
            step_env_count = 0
            step_env_unsafe = 0
            step_sanitizer_env_count = 0
            step_asan_env_count = 0
            step_ubsan_env_count = 0
            step_caps_count = 0
            step_caps_value = ""
            block_scalar_purpose = ""
            clear_step_commands()
        }
        function close_step(normalized_action) {
            if (!step_active) return
            if (step_use_count > 1) reject()
            normalized_action = tolower(step_action)
            if (normalized_action ~ /^actions\/checkout@/) {
                checkout_count++
                checkout_job_count[current_job]++
                if (checkout_job_count[current_job] == 1)
                    checkout_step_serial[current_job] = step_serial
                if (step_with_input_count != 1 ||
                    step_persist_count != 1 ||
                    step_persist_value != "false" ||
                    !step_persist_in_with)
                    reject("checkout action must set persist-credentials: false")
                if (step_action != canonical_checkout_action ||
                    step_action_comment != canonical_checkout_comment)
                    reject("checkout action/ref/comment must match canonical v7.0.0 pin")
            }
            if (normalized_action ~ /^cross-platform-actions\/action@/) {
                # The reviewed VM memory is pinned: pkg catalogue processing
                # OOMs at the action default, and an unreviewed value could
                # silently shrink the lane back into deterministic 137s.
                if (current_job != "freebsd" ||
                    step_with_input_count != 3 ||
                    step_os_count != 1 || !step_os_in_with ||
                    step_os_value != "freebsd" ||
                    step_version_count != 1 || !step_version_in_with ||
                    step_version_value !~ /^[0-9]+\.[0-9]+$/ ||
                    step_memory_count != 1 || !step_memory_in_with ||
                    step_memory_value != "8G")
                    reject("FreeBSD VM action configuration is missing or unsafe")
                if (step_action_run_count != 0 ||
                    step_direct_run_count != 0 ||
                    step_action_shell_count != 0 || step_shell_count != 0)
                    reject("FreeBSD VM action cannot carry run or shell inputs")
                if (step_if_count != 0)
                    reject("FreeBSD VM action must be unconditional")
                if (step_continue_count > 1 ||
                    (step_continue_count == 1 &&
                     step_continue_value != "false"))
                    reject("FreeBSD VM action cannot continue on error")
                freebsd_action_count++
                freebsd_version = step_version_value
                freebsd_action_step_serial = step_serial
            }
            if (normalized_action ~ /^actions\/upload-artifact@/) {
                if (current_job != "linux" ||
                    step_action != canonical_upload_action ||
                    step_action_comment != canonical_upload_comment)
                    reject("coverage upload action/ref/comment must match canonical v7.0.1 pin")
                if (step_with_input_count != 3 ||
                    step_input_name_count != 1 ||
                    step_input_name_value != "linux-gcc-coverage" ||
                    !step_input_name_in_with ||
                    step_path_count != 1 ||
                    step_path_value != "build/coverage/" ||
                    !step_path_in_with ||
                    step_if_no_files_count != 1 ||
                    step_if_no_files_value != "error" ||
                    !step_if_no_files_in_with)
                    reject("coverage upload inputs must match the exact reviewed artifact contract")
                if (step_if_count != 0 || step_continue_count != 0)
                    reject("coverage upload must be unconditional and failure-fatal")
                if (step_direct_run_count != 0 ||
                    step_action_run_count != 0 ||
                    step_shell_count != 0 ||
                    step_action_shell_count != 0 ||
                    step_env_map_count != 0 || step_env_count != 0 ||
                    step_workdir_count != 0)
                    reject("coverage upload step contains unsupported execution overrides")
                linux_coverage_upload_count++
                linux_coverage_upload_step_serial = step_serial
            }
            if (current_job == "freebsd" && step_shell_count == 1 &&
                step_shell_value == "cpa.sh {0}")
                freebsd_cpa_shell_step_count++
            classify_release_step()
            if (required_release_job(current_job) &&
                step_direct_run_count != 0 && step_workdir_count != 0)
                reject("direct steps in required release jobs cannot set working-directory")
            step_active = 0
            step_in_with = 0
            step_in_env = 0
            block_scalar_purpose = ""
        }
        function close_job() {
            close_step()
            if (job_use_count > 1) reject()
            if (job_use_count && job_has_steps) reject()
            current_job = ""
            in_steps = 0
            job_use_count = 0
            job_has_steps = 0
        }
        function record_step_input(key, value, inside) {
            if (inside) step_with_input_count++
            if (key == "persist-credentials") {
                step_persist_count++
                decode_scalar(value)
                if (!scalar_ok) reject()
                step_persist_value = scalar_value
                if (inside) step_persist_in_with = 1
            } else if (key == "operating_system") {
                step_os_count++
                decode_scalar(value)
                if (!scalar_ok) reject()
                step_os_value = scalar_value
                if (inside) step_os_in_with = 1
            } else if (key == "version") {
                step_version_count++
                decode_scalar(value)
                if (!scalar_ok) reject()
                step_version_value = scalar_value
                if (inside) step_version_in_with = 1
            } else if (key == "memory") {
                step_memory_count++
                decode_scalar(value)
                if (!scalar_ok) reject()
                step_memory_value = scalar_value
                if (inside) step_memory_in_with = 1
            } else if (key == "name") {
                step_input_name_count++
                decode_scalar(value)
                if (!scalar_ok) reject()
                step_input_name_value = scalar_value
                if (inside) step_input_name_in_with = 1
            } else if (key == "path") {
                step_path_count++
                decode_scalar(value)
                if (!scalar_ok) reject()
                step_path_value = scalar_value
                if (inside) step_path_in_with = 1
            } else if (key == "if-no-files-found") {
                step_if_no_files_count++
                decode_scalar(value)
                if (!scalar_ok) reject()
                step_if_no_files_value = scalar_value
                if (inside) step_if_no_files_in_with = 1
            } else if (key == "shell") {
                step_action_shell_count++
                decode_scalar(value)
                if (!scalar_ok) reject()
                step_action_shell_value = scalar_value
                if (inside) step_action_shell_in_with = 1
            }
        }
        function parse_flow_with_piece(piece, colon, key, value) {
            piece = trim(piece)
            if (piece == "") reject()
            colon = find_colon(piece)
            if (!colon) reject()
            decode_scalar(trim(substr(piece, 1, colon - 1)))
            if (!scalar_ok || scalar_value !~ /^[A-Za-z0-9_-]+$/) reject()
            key = scalar_value
            if (key in flow_with_key_seen) reject()
            flow_with_key_seen[key] = 1
            value = trim(substr(piece, colon + 1))
            if (substr(value, 1, 1) == "{" ||
                substr(value, 1, 1) == "[") reject()
            decode_scalar(value)
            if (!scalar_ok || scalar_value == "") reject()
            record_step_input(key, value, 1)
        }
        function parse_flow_with(value, inner, i, c, next_c, quote, escaped,
                                 piece, key) {
            if (substr(value, 1, 1) != "{" ||
                substr(value, length(value), 1) != "}") reject()
            for (key in flow_with_key_seen) delete flow_with_key_seen[key]
            inner = trim(substr(value, 2, length(value) - 2))
            if (inner == "") return
            quote = 0
            escaped = 0
            piece = ""
            for (i = 1; i <= length(inner); i++) {
                c = substr(inner, i, 1)
                next_c = substr(inner, i + 1, 1)
                if (quote == 1) {
                    piece = piece c
                    if (c == single_quote) {
                        if (next_c == single_quote) {
                            piece = piece next_c
                            i++
                        } else quote = 0
                    }
                    continue
                }
                if (quote == 2) {
                    piece = piece c
                    if (escaped) escaped = 0
                    else if (c == "\\") escaped = 1
                    else if (c == "\"") quote = 0
                    continue
                }
                if (c == single_quote) quote = 1
                else if (c == "\"") quote = 2
                else if (c == "{" || c == "}" || c == "[" || c == "]")
                    reject()
                if (c == "," && quote == 0) {
                    parse_flow_with_piece(piece)
                    piece = ""
                } else {
                    piece = piece c
                }
            }
            if (quote != 0 || escaped || trim(piece) == "") reject()
            parse_flow_with_piece(piece)
        }
        function parse_flow_step_piece(piece, comment, colon, key, value) {
            piece = trim(piece)
            if (piece == "") reject()
            colon = find_colon(piece)
            if (!colon) reject()
            decode_scalar(trim(substr(piece, 1, colon - 1)))
            if (!scalar_ok || scalar_value !~ /^[A-Za-z0-9_-]+$/) reject()
            key = scalar_value
            if (key in flow_step_key_seen) reject()
            flow_step_key_seen[key] = 1
            value = trim(substr(piece, colon + 1))
            if (key == "uses") {
                validate_use(value, comment)
                step_use_count++
                step_action = scalar_value
                step_action_comment = trim(comment)
                return
            }
            if (key == "with") {
                if (step_with_seen) reject()
                step_with_seen = 1
                parse_flow_with(value)
                return
            }
            if (key == "env") {
                step_env_map_count++
                step_env_unsafe = 1
                return
            }
            if (substr(value, 1, 1) == "{" ||
                substr(value, 1, 1) == "[") reject()
            decode_scalar(value)
            if (!scalar_ok || scalar_value == "") reject()
            if (key == "if") {
                step_if_count++
            } else if (key == "continue-on-error") {
                step_continue_count++
                step_continue_value = scalar_value
            } else if (key == "shell") {
                step_shell_count++
                step_shell_value = scalar_value
            } else if (key == "working-directory") {
                step_workdir_count++
                step_workdir_value = scalar_value
            } else if (key == "run") {
                record_scalar_run("direct", value)
            }
        }
        function parse_flow_step(value, comment, inner, i, c, next_c, quote,
                                 escaped, depth, piece, key) {
            if (substr(value, 1, 1) != "{" ||
                substr(value, length(value), 1) != "}") reject()
            for (key in flow_step_key_seen) delete flow_step_key_seen[key]
            inner = trim(substr(value, 2, length(value) - 2))
            if (inner == "") reject()
            quote = 0
            escaped = 0
            depth = 0
            piece = ""
            for (i = 1; i <= length(inner); i++) {
                c = substr(inner, i, 1)
                next_c = substr(inner, i + 1, 1)
                if (quote == 1) {
                    piece = piece c
                    if (c == single_quote) {
                        if (next_c == single_quote) {
                            piece = piece next_c
                            i++
                        } else quote = 0
                    }
                    continue
                }
                if (quote == 2) {
                    piece = piece c
                    if (escaped) escaped = 0
                    else if (c == "\\") escaped = 1
                    else if (c == "\"") quote = 0
                    continue
                }
                if (c == single_quote) quote = 1
                else if (c == "\"") quote = 2
                else if (c == "{") depth++
                else if (c == "}") {
                    if (depth == 0) reject()
                    depth--
                } else if (c == "[" || c == "]") reject()
                if (c == "," && quote == 0 && depth == 0) {
                    parse_flow_step_piece(piece, comment)
                    piece = ""
                } else {
                    piece = piece c
                }
            }
            if (quote != 0 || escaped || depth != 0 || trim(piece) == "")
                reject()
            parse_flow_step_piece(piece, comment)
        }
        BEGIN {
            single_quote = sprintf("%c", 39)
            block_scalar_indent = -1
            canonical_checkout_action = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
            canonical_checkout_comment = "v7.0.0"
            canonical_upload_action = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
            canonical_upload_comment = "v7.0.1"
        }
        {
            raw = $0
            if (raw ~ /\t/) reject()
            if (block_scalar_indent >= 0) {
                if (raw ~ /^[[:space:]]*$/ ||
                    indentation(raw) > block_scalar_indent) {
                    if (block_scalar_purpose != "")
                        record_block_command(raw, block_scalar_purpose)
                    next
                }
                block_scalar_indent = -1
                block_scalar_purpose = ""
            }
            code = lex(raw)
            if (!lex_ok) reject()
            if (trim(code) == "") next
            current_indent = indentation(code)
            code_trimmed = trim(code)
            if (code_trimmed == "---" || code_trimmed == "..." ||
                substr(code_trimmed, 1, 1) == "%") reject()

            # This canonical subset supports one scalar sequence surface:
            # on.push.branches. Do not close that parent before diagnosing a
            # dedented sequence item; it must fail as a wrongly indented child
            # instead of falling through as a free-standing YAML node.
            sequence_line = substr(code_trimmed, 1, 1) == "-" &&
                (length(code_trimmed) == 1 ||
                 substr(code_trimmed, 2, 1) ~ /[[:space:]]/)
            if (branch_sequence_active &&
                current_indent <= branch_sequence_indent && !sequence_line)
                close_branch_sequence()
            if (!branch_sequence_active && push_trigger_active &&
                current_indent <= push_trigger_indent)
                push_trigger_active = 0
            if (!push_trigger_active && on_trigger_active &&
                current_indent <= on_trigger_indent)
                on_trigger_active = 0

            if (permissions_active && current_indent <= permissions_indent)
                close_permissions()
            if (permissions_active) {
                if (current_indent != permissions_indent + 2) reject()
                parse_entry(code_trimmed)
                if (!entry_ok || entry_sequence) reject()
                add_permission(entry_key, entry_value)
                next
            }

            if (in_steps && current_indent == 6 &&
                substr(code_trimmed, 1, 1) == "-") {
                flow_step = ltrim(substr(code_trimmed, 2))
                if (substr(flow_step, 1, 1) == "{") {
                    close_step()
                    reset_step()
                    parse_flow_step(flow_step, lex_comment)
                    close_step()
                    next
                }
            }

            parse_entry(code_trimmed)
            if (!entry_ok) reject()
            if (branch_sequence_active) {
                if (!entry_scalar_sequence)
                    reject("on.push.branches accepts only scalar sequence items")
                if (current_indent != branch_sequence_indent + 2)
                    reject("on.push.branches sequence item has incorrect indentation")
                branch_item_count++
                next
            }
            if (entry_scalar_sequence) {
                reject("scalar sequence item lacks supported on.push.branches parent")
            }
            if (entry_key == "<<" || substr(entry_key, 1, 1) == "?") reject()
            if (entry_value ~ /^[&*!]/)
                reject("YAML anchors, aliases, and tags are unsupported")

            if (current_job != "" && current_indent <= 2) close_job()
            else if (in_steps && current_indent <= 4) {
                close_step()
                in_steps = 0
            }

            if (entry_key == "on" && current_indent == 0 &&
                !entry_sequence) {
                if (on_trigger_seen || entry_value != "") reject()
                on_trigger_seen = 1
                on_trigger_active = 1
                on_trigger_indent = current_indent
                next
            }
            if (on_trigger_active && current_indent == on_trigger_indent + 2 &&
                entry_key == "push" && !entry_sequence) {
                if (push_trigger_seen || entry_value != "") reject()
                push_trigger_seen = 1
                push_trigger_active = 1
                push_trigger_indent = current_indent
                next
            }
            if (push_trigger_active &&
                current_indent == push_trigger_indent + 2 &&
                entry_key == "branches" && !entry_sequence) {
                if (branch_sequence_seen || entry_value != "") reject()
                branch_sequence_seen = 1
                branch_sequence_active = 1
                branch_sequence_indent = current_indent
                branch_item_count = 0
                next
            }

            if (entry_key == "jobs" && current_indent == 0 && !entry_sequence) {
                if (jobs_seen || entry_value != "") reject()
                jobs_seen = 1
                in_jobs = 1
                next
            }
            if (current_indent == 0 && entry_key != "permissions")
                in_jobs = 0

            if (in_jobs && current_indent == 2 && !entry_sequence) {
                if (entry_value != "" || (entry_key in job_seen)) reject()
                job_seen[entry_key] = 1
                job_count++
                current_job = entry_key
                job_use_count = 0
                job_has_steps = 0
                next
            }

            if (entry_key == "defaults" && current_indent == 0)
                reject("workflow shell defaults are unsupported")
            if (entry_key == "env" && current_indent == 0)
                reject("workflow environment overrides are unsupported")
            if (current_job != "" && current_indent == 4 &&
                required_release_job(current_job)) {
                if (entry_key == "runs-on") {
                    release_runner_count[current_job]++
                    decode_scalar(entry_value)
                    if (!scalar_ok || scalar_value == "") reject()
                    release_runner_value[current_job] = scalar_value
                } else if (entry_key == "if") {
                    reject("required release job must be unconditional")
                } else if (entry_key == "defaults") {
                    reject("required release job cannot override shell defaults")
                } else if (entry_key == "env") {
                    reject("required release job cannot override its environment")
                } else if (entry_key == "container") {
                    reject("required release job cannot override its execution container")
                }
            }

            if (entry_key == "permissions") {
                if (entry_sequence) reject()
                if (current_indent == 0) {
                    if (top_permissions_seen) reject()
                    top_permissions_seen = 1
                    start_permissions("top", current_indent, entry_value)
                    next
                }
                if (current_job != "" && current_indent == 4) {
                    if (job_permissions_seen[current_job]) reject()
                    job_permissions_seen[current_job] = 1
                    start_permissions("job", current_indent, entry_value)
                    next
                }
                reject()
            }

            if (current_job != "" && current_indent == 4 &&
                entry_key == "steps" && !entry_sequence) {
                if (entry_value != "" || job_steps_seen[current_job]) reject()
                job_steps_seen[current_job] = 1
                job_has_steps = 1
                in_steps = 1
                next
            }

            if (in_steps && current_indent == 6 && entry_sequence) {
                close_step()
                reset_step()
            }
            if (step_active && step_in_with &&
                current_indent <= step_with_indent) step_in_with = 0
            if (step_active && step_in_env &&
                current_indent <= step_env_indent) step_in_env = 0

            step_direct_field = step_active &&
                ((current_indent == 6 && entry_sequence) ||
                 (current_indent == 8 && !entry_sequence))
            step_action_input = step_active && step_in_with &&
                current_indent == step_with_indent + 2 && !entry_sequence

            if (step_active && step_in_env &&
                current_indent == step_env_indent + 2 && !entry_sequence) {
                step_env_count++
                decode_scalar(entry_value)
                if (!scalar_ok || scalar_value == "") step_env_unsafe = 1
                if (required_release_job(current_job) &&
                    entry_key ~ /^(PATH|MAKEFLAGS|MFLAGS|BASH_ENV|ENV|SHELLOPTS|BASHOPTS)$/)
                    release_job_resolver_mutation[current_job] = 1
                if (entry_key == "GITSWITCH_TEST_REQUIRED_CAPS") {
                    step_caps_count++
                    step_caps_value = scalar_value
                } else if (entry_key == "ASAN_OPTIONS") {
                    # AR-12 M9: the sanitizer lane pins its exact strictness;
                    # a weakened option set is the same silent-deletion class.
                    # AR-13 M4: count ASAN and UBSAN independently (not one
                    # shared sanitizer counter) so a duplicated ASAN_OPTIONS can
                    # no longer stand in for a dropped UBSAN_OPTIONS.
                    step_sanitizer_env_count++
                    step_asan_env_count++
                    if (scalar_value != "detect_leaks=1:abort_on_error=1:strict_string_checks=1")
                        step_env_unsafe = 1
                } else if (entry_key == "UBSAN_OPTIONS") {
                    step_sanitizer_env_count++
                    step_ubsan_env_count++
                    if (scalar_value != "halt_on_error=1:print_stacktrace=1")
                        step_env_unsafe = 1
                } else {
                    step_env_unsafe = 1
                }
                next
            }

            if (step_direct_field && entry_key == "env") {
                step_env_map_count++
                if (entry_value != "") {
                    step_env_unsafe = 1
                    if (required_release_job(current_job) &&
                        entry_value ~ /(PATH|MAKEFLAGS|MFLAGS|BASH_ENV|ENV|SHELLOPTS|BASHOPTS)[[:space:]]*:/)
                        release_job_resolver_mutation[current_job] = 1
                } else {
                    step_in_env = 1
                    step_env_indent = current_indent
                }
                next
            }

            if (step_direct_field && entry_key == "if") {
                step_if_count++
                decode_scalar(entry_value)
                if (!scalar_ok || scalar_value == "") reject()
                next
            }
            if (step_direct_field && entry_key == "continue-on-error") {
                step_continue_count++
                decode_scalar(entry_value)
                if (!scalar_ok || scalar_value == "") reject()
                step_continue_value = scalar_value
                next
            }
            if (step_direct_field && entry_key == "shell") {
                step_shell_count++
                decode_scalar(entry_value)
                if (!scalar_ok || scalar_value == "") reject()
                step_shell_value = scalar_value
                next
            }
            if (step_direct_field && entry_key == "working-directory") {
                step_workdir_count++
                decode_scalar(entry_value)
                if (!scalar_ok || scalar_value == "") reject()
                step_workdir_value = scalar_value
                next
            }
            if ((step_direct_field || step_action_input) &&
                entry_key == "run") {
                run_source = step_direct_field ? "direct" : "action"
                if (entry_value ~ /^[|>][-+0-9]*$/) {
                    start_run_block(run_source, entry_value)
                    block_scalar_indent = current_indent
                } else {
                    record_scalar_run(run_source, entry_value)
                }
                next
            }

            if (entry_key == "uses") {
                validate_use(entry_value, lex_comment)
                if (current_job != "" && current_indent == 4 &&
                    !entry_sequence && !in_steps) {
                    job_use_count++
                    job_action = scalar_value
                } else if (step_active &&
                           ((current_indent == 6 && entry_sequence) ||
                            (current_indent == 8 && !entry_sequence))) {
                    step_use_count++
                    step_action = scalar_value
                    step_action_comment = trim(lex_comment)
                } else reject()
                next
            }

            if (step_active && current_indent == 8 && !entry_sequence &&
                entry_key == "with") {
                if (step_with_seen) reject()
                step_with_seen = 1
                if (entry_value == "") {
                    step_in_with = 1
                    step_with_indent = current_indent
                } else if (substr(entry_value, 1, 1) == "{") {
                    parse_flow_with(entry_value)
                } else reject()
                next
            }
            if (step_active && step_action_input) {
                record_step_input(entry_key, entry_value, 1)
                next
            }
            if (step_active &&
                (entry_key == "persist-credentials" ||
                 entry_key == "operating_system" || entry_key == "version" ||
                 entry_key == "shell")) {
                record_step_input(entry_key, entry_value, 0)
                next
            }

            if (entry_key == "steps" && entry_value != "") reject()
            if (substr(entry_value, 1, 1) == "{" ||
                substr(entry_value, 1, 1) == "[") reject()
            if (entry_value ~ /^[|>][-+0-9]*$/)
                block_scalar_indent = current_indent
        }
        END {
            if (rejected) exit 1
            close_branch_sequence()
            close_permissions()
            close_job()
            require_release_gate("linux-make-provenance")
            require_release_gate("linux-policy")
            require_release_gate("linux-asan-test")
            require_release_gate("linux-memcheck")
            require_release_gate("linux-distcheck")
            require_release_gate("linux-qa-contract")
            require_release_gate("linux-sig-repro")
            require_release_gate("linux-analyze")
            require_release_gate("linux-security-scan")
            require_release_gate("linux-coverage")
            require_release_gate("linux-coverage-provenance")
            require_release_gate("linux-gcc-clean")
            require_release_gate("linux-gcc-test")
            require_release_gate("linux-gcc-artifact")
            require_release_gate("linux-symbol-contract")
            require_release_gate("linux-contract")
            require_release_gate("linux-clang-clean")
            require_release_gate("linux-clang-test")
            require_release_gate("linux-clang-artifact")
            require_release_gate("macos-test")
            require_release_gate("macos-artifact")
            require_release_gate("macos-contract")
            require_release_gate("freebsd-test")
            require_release_gate("freebsd-artifact")
            require_release_gate("freebsd-contract")
            if (release_runner_count["linux"] != 1 ||
                release_runner_value["linux"] != "ubuntu-latest" ||
                release_runner_count["macos"] != 1 ||
                release_runner_value["macos"] != "macos-latest" ||
                release_runner_count["freebsd"] != 1 ||
                release_runner_value["freebsd"] != "ubuntu-latest")
                reject("required release job runner is missing or incorrect")
            if (release_job_dynamic_env["linux"] ||
                release_job_dynamic_env["macos"] ||
                release_job_dynamic_env["freebsd"])
                reject("required release jobs cannot persist environment overrides")
            if (release_job_resolver_mutation["linux"] ||
                release_job_resolver_mutation["macos"] ||
                release_job_resolver_mutation["freebsd"])
                reject("required release jobs cannot mutate executable resolution")
            if (freebsd_action_count != 1)
                reject("FreeBSD release job needs exactly one reviewed VM action")
            if (freebsd_release_step_count != 1 ||
                freebsd_cpa_shell_step_count != 1)
                reject("FreeBSD release gates need exactly one cpa shell step")
            if (freebsd_caps_count != 1 ||
                freebsd_caps_serial >= release_gate_serial["freebsd-test"])
                reject("FreeBSD required test capabilities are missing or unsafe")
            if (!linux_first_make_serial ||
                release_gate_serial["linux-make-provenance"] >= linux_first_make_serial)
                reject("Linux build-tool provenance must precede every make invocation")
            if (release_gate_serial["linux-policy"] >= linux_first_make_serial)
                reject("Linux CI policy validation must precede every make invocation")
            if (checkout_step_serial["linux"] + 1 != release_gate_step_serial["linux-policy"])
                reject("Linux CI policy self-check must immediately follow checkout")
            if (linux_unqualified_make)
                reject("Linux build commands must use verified /usr/bin/make")
            if (macos_unqualified_make)
                reject("macOS build commands must use pinned /usr/bin/make")
            if (linux_coverage_upload_count != 1 ||
                release_gate_step_serial["linux-coverage"] + 1 != release_gate_step_serial["linux-coverage-provenance"] ||
                release_gate_step_serial["linux-coverage-provenance"] + 1 != linux_coverage_upload_step_serial ||
                linux_coverage_upload_step_serial >= release_gate_step_serial["linux-gcc-clean"])
                reject("Linux coverage upload must follow its build gate before cleanup")
            if (release_gate_step_serial["linux-gcc-clean"] + 1 != release_gate_step_serial["linux-gcc-test"] ||
                release_gate_step_serial["linux-gcc-test"] + 1 != release_gate_step_serial["linux-gcc-artifact"] ||
                release_gate_step_serial["linux-gcc-artifact"] + 1 != release_gate_step_serial["linux-symbol-contract"])
                reject("Linux GCC release provenance gates must remain adjacent")
            if (release_gate_step_serial["linux-clang-clean"] + 1 != release_gate_step_serial["linux-clang-test"] ||
                release_gate_step_serial["linux-clang-test"] + 1 != release_gate_step_serial["linux-clang-artifact"])
                reject("Linux clang release provenance gates must remain adjacent")
            require_release_order("linux-policy", "linux-make-provenance")
            require_release_order("linux-make-provenance", "linux-coverage")
            require_release_order("linux-coverage", "linux-coverage-provenance")
            require_release_order("linux-coverage-provenance", "linux-gcc-clean")
            require_release_order("linux-gcc-clean", "linux-gcc-test")
            require_release_order("linux-gcc-test", "linux-gcc-artifact")
            require_release_order("linux-gcc-artifact", "linux-symbol-contract")
            require_release_order("linux-symbol-contract", "linux-contract")
            require_release_order("linux-contract", "linux-clang-clean")
            require_release_order("linux-clang-clean", "linux-clang-test")
            require_release_order("linux-clang-test", "linux-clang-artifact")
            require_release_order("macos-test", "macos-artifact")
            require_release_order("macos-artifact", "macos-contract")
            require_release_order("freebsd-test", "freebsd-artifact")
            require_release_order("freebsd-artifact", "freebsd-contract")
            if (checkout_count != 3 ||
                checkout_job_count["linux"] != 1 ||
                checkout_job_count["macos"] != 1 ||
                checkout_job_count["freebsd"] != 1)
                reject("each required release job needs exactly one canonical checkout step")
            if (!top_permissions_seen || !jobs_seen || job_count == 0 ||
                use_count == 0 || external_use_count == 0 ||
                checkout_count == 0) exit 1
            print "freebsd-version=" freebsd_version
        }
    ' "$workflow" >"$work_actions" || {
        policy_detail=$(sed -n '1p' "$work_actions")
        fail "workflow action/permission YAML is unsafe, ambiguous, or unsupported${policy_detail:+: $policy_detail}"
    }
    freebsd_version=$(sed -n 's/^freebsd-version=//p' "$work_actions")
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
    if WORK_ACTIONS="$tmp/check-actions" sh "$script" --check "$reject_workflow" \
        "$reject_policy_date" >"$tmp/out" 2>&1; then
        fail "$reject_label fixture was accepted"
    fi
}

expect_structural_rejected()
{
    expect_rejected "$@"
    grep -F 'workflow action/permission YAML is unsafe' "$tmp/out" >/dev/null ||
        fail "$1 fixture failed for the wrong policy reason"
}

expect_structural_rejected_for()
{
    structural_label=$1
    structural_workflow=$2
    structural_date=$3
    structural_reason=$4
    expect_structural_rejected "$structural_label" "$structural_workflow" \
        "$structural_date"
    grep -F "$structural_reason" "$tmp/out" >/dev/null ||
        fail "$structural_label fixture missed expected reason: $structural_reason"
}

expect_accepted()
{
    accept_label=$1
    accept_workflow=$2
    accept_policy_date=$3
    if ! WORK_ACTIONS="$tmp/check-actions" sh "$script" --check "$accept_workflow" \
        "$accept_policy_date" >"$tmp/out" 2>&1; then
        fail "$accept_label fixture was rejected: $(sed -n '1p' "$tmp/out")"
    fi
}

mutate_release_command()
{
    mutate_job=$1
    mutate_from=$2
    mutate_to=$3
    mutate_output=$4
    awk -v wanted_job="$mutate_job" -v from="$mutate_from" -v to="$mutate_to" '
        function ltrim(value) {
            sub(/^[[:space:]]+/, "", value)
            return value
        }
        /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            job = $0
            sub(/^  /, "", job)
            sub(/:[[:space:]]*$/, "", job)
        }
        job == wanted_job && !changed {
            body = ltrim($0)
            if (body == "run: " from) {
                match($0, /^[ ]*/)
                print substr($0, 1, RLENGTH) "run: " to
                changed = 1
                next
            }
            if (body == from) {
                match($0, /^[ ]*/)
                print substr($0, 1, RLENGTH) to
                changed = 1
                next
            }
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$mutate_output"
}

mutate_release_runner()
{
    mutate_job=$1
    mutate_runner=$2
    mutate_output=$3
    awk -v wanted_job="$mutate_job" -v runner="$mutate_runner" '
        /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            job = $0
            sub(/^  /, "", job)
            sub(/:[[:space:]]*$/, "", job)
        }
        job == wanted_job && !changed &&
            /^    runs-on:[[:space:]]*/ {
            print "    runs-on: " runner
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$mutate_output"
}

rename_release_job()
{
    mutate_job=$1
    mutate_output=$2
    awk -v wanted_job="$mutate_job" '
        $0 == "  " wanted_job ":" && !changed {
            print "  disabled-" wanted_job ":"
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$mutate_output"
}

add_release_job_field()
{
    mutate_job=$1
    mutate_field=$2
    mutate_output=$3
    awk -v wanted_job="$mutate_job" -v field="$mutate_field" '
        { print }
        $0 == "  " wanted_job ":" && !changed {
            print "    " field
            changed = 1
        }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$mutate_output"
}

add_release_step_field()
{
    mutate_job=$1
    mutate_command=$2
    mutate_field=$3
    mutate_output=$4
    awk -v wanted_job="$mutate_job" -v command="$mutate_command" \
        -v field="$mutate_field" '
        function ltrim(value) {
            sub(/^[[:space:]]+/, "", value)
            return value
        }
        /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            job = $0
            sub(/^  /, "", job)
            sub(/:[[:space:]]*$/, "", job)
        }
        {
            print
            if (job != wanted_job || changed) next
            body = ltrim($0)
            if (wanted_job == "freebsd" &&
                body == "shell: cpa.sh {0}") {
                match($0, /^[ ]*/)
                print substr($0, 1, RLENGTH) field
                changed = 1
            } else if (body == "run: " command) {
                match($0, /^[ ]*/)
                print substr($0, 1, RLENGTH) field
                changed = 1
            }
        }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$mutate_output"
}

mutate_release_caps()
{
    mutate_job=$1
    mutate_command=$2
    mutate_output=$3
    awk -v wanted_job="$mutate_job" -v command="$mutate_command" '
        function ltrim(value) {
            sub(/^[[:space:]]+/, "", value)
            return value
        }
        /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            job = $0
            sub(/^  /, "", job)
            sub(/:[[:space:]]*$/, "", job)
        }
        job == wanted_job && ltrim($0) == "run: " command { target = 1 }
        target && !changed &&
            ltrim($0) ~ /^GITSWITCH_TEST_REQUIRED_CAPS:/ {
            match($0, /^[ ]*/)
            print substr($0, 1, RLENGTH) "GITSWITCH_TEST_REQUIRED_CAPS: pty"
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$mutate_output"
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

# A full, immutable SHA is necessary but not sufficient for the foundational
# checkout action. All required jobs must use the single reviewed release,
# including its exact human-auditable version comment.
awk -v current_ref=9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 \
    -v old_ref=11bd71901bbe5b1630ceea73d27597364c9af683 '
    !changed && index($0, "uses: actions/checkout@" current_ref) {
        line = $0
        sub("actions/checkout@" current_ref,
            "actions/checkout@" old_ref, line)
        sub(/# v7[.]0[.]0/, "# v4.2.2", line)
        if (line == $0) exit 1
        print line
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/older-checkout.yml"
expect_structural_rejected_for "older immutable checkout pin" \
    "$tmp/older-checkout.yml" "$today" \
    "checkout action/ref/comment must match canonical v7.0.0 pin"

# The only scalar block sequence in the canonical workflow subset is the
# direct child list at on.push.branches. Multiple items close cleanly when the
# next trigger key dedents back to the `on` mapping.
awk '
    { print }
    $0 == "      - trunk" && !changed {
        print "      - release-audit"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/safe-branch-sequence.yml"
expect_accepted "safe on.push.branches block sequence" \
    "$tmp/safe-branch-sequence.yml" "$today"

# The original parent-tracking bypass accepted a scalar item after it had
# escaped the branches mapping entirely. Keep that exact malformed dedent, plus
# valid-YAML neighboring cases for the wrong parent, indentless sequence style,
# and a branches mapping that closes without an item.
awk '
    $0 == "      - trunk" && !changed {
        print "- trunk"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/dedented-branch-sequence.yml"
expect_structural_rejected_for "dedented branch sequence" \
    "$tmp/dedented-branch-sequence.yml" "$today" \
    "on.push.branches sequence item has incorrect indentation"

awk '
    $0 == "    branches:" && !changed {
        print "    tags:"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/wrong-parent-branch-sequence.yml"
expect_structural_rejected_for "scalar sequence under wrong trigger parent" \
    "$tmp/wrong-parent-branch-sequence.yml" "$today" \
    "scalar sequence item lacks supported on.push.branches parent"

awk '
    $0 == "      - trunk" && !changed {
        print "    - trunk"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/wrong-indent-branch-sequence.yml"
expect_structural_rejected_for "indentless branch sequence" \
    "$tmp/wrong-indent-branch-sequence.yml" "$today" \
    "on.push.branches sequence item has incorrect indentation"

awk '
    $0 == "      - trunk" && !changed {
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/empty-branch-sequence.yml"
expect_structural_rejected_for "empty branch sequence" \
    "$tmp/empty-branch-sequence.yml" "$today" \
    "on.push.branches must contain at least one item"

# Equivalent safe block, flow, comment, and quoted permission spellings must
# be interpreted as the same effective map rather than accidentally accepted
# or rejected by line shape.
awk '
    $0 == "permissions:" && !changed {
        print "permissions: { \"contents\": \"read\" } # safe equivalent"
        skip_contents = 1
        changed = 1
        next
    }
    skip_contents {
        if ($0 != "  contents: read") exit 1
        skip_contents = 0
        next
    }
    { print }
    END { if (!changed || skip_contents) exit 1 }
' "$workflow" >"$tmp/safe-flow-permissions.yml"
expect_accepted "safe flow permissions" "$tmp/safe-flow-permissions.yml" "$today"

awk '
    $0 == "permissions:" && !changed {
        print "\"permissions\":"
        changed = 1
        next
    }
    changed && !quoted && $0 == "  contents: read" {
        print "  \"contents\": \"read\" # safe equivalent"
        quoted = 1
        next
    }
    { print }
    END { if (!changed || !quoted) exit 1 }
' "$workflow" >"$tmp/safe-quoted-permissions.yml"
expect_accepted "safe quoted permissions" \
    "$tmp/safe-quoted-permissions.yml" "$today"

awk '
    { print }
    $0 == "  linux:" && !changed {
        print "    permissions: { contents: read }"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/safe-job-permissions.yml"
expect_accepted "safe job permission override" \
    "$tmp/safe-job-permissions.yml" "$today"

awk '
    !changed && /uses:[ ]*actions\/upload-artifact@/ {
        line = $0
        match(line, /^[ ]*/)
        indent = substr(line, 1, RLENGTH)
        sub(/^[ ]*uses:[ ]*/, "", line)
        comment = line
        sub(/^[^#]*#[ ]*/, "", comment)
        sub(/[ ]*#.*/, "", line)
        print indent "\"uses\": \"" line "\" # " comment
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/safe-quoted-action.yml"
expect_accepted "safe quoted action" "$tmp/safe-quoted-action.yml" "$today"

# A checkout step and its `with` inputs may each use YAML flow mappings. These
# are semantically identical to the block spelling in the checked-in workflow.
awk '
    !changed && /^[ ]*-[ ]*uses:[ ]*actions\/checkout@/ {
        line = $0
        match(line, /^[ ]*/)
        indent = substr(line, 1, RLENGTH)
        sub(/^[ ]*-[ ]*uses:[ ]*/, "", line)
        comment = line
        sub(/^[^#]*#[ ]*/, "", comment)
        sub(/[ ]*#.*/, "", line)
        print indent "- { uses: " line \
            ", with: { persist-credentials: false } } # " comment
        skip_with = 1
        changed = 1
        next
    }
    skip_with == 1 {
        if ($0 !~ /^[ ]*with:[ ]*$/) exit 1
        skip_with = 2
        next
    }
    skip_with == 2 {
        if ($0 !~ /^[ ]*persist-credentials:[ ]*false[ ]*$/) exit 1
        skip_with = 0
        next
    }
    { print }
    END { if (!changed || skip_with) exit 1 }
' "$workflow" >"$tmp/safe-flow-checkout-step.yml"
expect_accepted "safe flow checkout step" \
    "$tmp/safe-flow-checkout-step.yml" "$today"

awk '
    !changed && /^[ ]*with:[ ]*$/ && previous_checkout {
        match($0, /^[ ]*/)
        indent = substr($0, 1, RLENGTH)
        print indent "with: { persist-credentials: false }"
        skip_input = 1
        changed = 1
        next
    }
    skip_input {
        if ($0 !~ /^[ ]*persist-credentials:[ ]*false[ ]*$/) exit 1
        skip_input = 0
        next
    }
    { print }
    /^[ ]*-[ ]*uses:[ ]*actions\/checkout@/ { previous_checkout = 1; next }
    { previous_checkout = 0 }
    END { if (!changed || skip_input) exit 1 }
' "$workflow" >"$tmp/safe-flow-with.yml"
expect_accepted "safe flow checkout inputs" "$tmp/safe-flow-with.yml" "$today"

# Unsafe values inside otherwise supported, valid flow mappings must reach the
# same semantic checks as their block equivalents.
awk '
    !changed && /- [{] uses: actions\/checkout@/ {
        line = $0
        sub(/@[0-9a-f]+/, "@main", line)
        if (line == $0) exit 1
        print line
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$tmp/safe-flow-checkout-step.yml" >"$tmp/flow-mutable-action.yml"
expect_structural_rejected_for "mutable flow action" \
    "$tmp/flow-mutable-action.yml" "$today" \
    "external action is not pinned to a full lowercase SHA"

awk '
    !changed && /- [{] uses: actions\/checkout@/ {
        line = $0
        sub(/persist-credentials: false/, "persist-credentials: true", line)
        if (line == $0) exit 1
        print line
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$tmp/safe-flow-checkout-step.yml" >"$tmp/flow-credentials.yml"
expect_structural_rejected_for "persisted flow checkout credential" \
    "$tmp/flow-credentials.yml" "$today" \
    "checkout action must set persist-credentials: false"

awk '
    !changed && /^[ ]*-[ ]*uses:[ ]*/ {
        line = $0
        sub(/@[0-9a-f]+/, "@main", line)
        if (line == $0) exit 1
        print line
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/mutable.yml"
expect_structural_rejected "mutable action" "$tmp/mutable.yml" "$today"

# The parser must inspect action nodes other than checkout, including quoted
# keys/values, and must not mistake a version comment for the effective ref.
awk '
    !changed && /uses:[ ]*actions\/upload-artifact@/ {
        line = $0
        match(line, /^[ ]*/)
        indent = substr(line, 1, RLENGTH)
        sub(/^[ ]*uses:[ ]*/, "", line)
        comment = line
        sub(/^[^#]*#[ ]*/, "", comment)
        sub(/[ ]*#.*/, "", line)
        sub(/@[0-9a-f]+/, "@main", line)
        print indent "\"uses\": \"" line "\" # " comment
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/quoted-mutable-action.yml"
expect_structural_rejected "quoted mutable non-checkout action" \
    "$tmp/quoted-mutable-action.yml" "$today"

# Action paths are slash-separated identifiers, not filesystem normalization
# requests. Empty, dot, and dot-dot components are rejected for local and
# remote forms before any aggregate checkout count can mask them.
for path_case in empty dot dotdot; do
    case $path_case in
        empty) local_action=./audit//action; remote_action=actions//upload-artifact ;;
        dot) local_action=./audit/./action; remote_action=actions/./upload-artifact ;;
        dotdot) local_action=./audit/../action; remote_action=actions/../upload-artifact ;;
    esac
    awk -v replacement="$local_action" '
        !changed && /uses:[ ]*actions\/upload-artifact@/ {
            sub(/actions\/upload-artifact@[0-9a-f]+/, replacement)
            changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$tmp/local-path-$path_case.yml"
    expect_structural_rejected_for "local action $path_case path component" \
        "$tmp/local-path-$path_case.yml" "$today" \
        "action path has an empty, dot, or dot-dot component"

    awk -v replacement="$remote_action" '
        !changed && /uses:[ ]*actions\/upload-artifact@/ {
            sub(/actions\/upload-artifact/, replacement)
            changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$tmp/remote-path-$path_case.yml"
    expect_structural_rejected_for "remote action $path_case path component" \
        "$tmp/remote-path-$path_case.yml" "$today" \
        "action path has an empty, dot, or dot-dot component"
done

# GitHub resolves action owner/repository names case-insensitively. A variant
# spelling must still receive the checkout input policy even when other valid
# checkout steps satisfy the aggregate count.
awk '
    !variant && /uses:[ ]*actions\/checkout@/ {
        sub(/actions\/checkout/, "Actions/Checkout")
        print
        variant = 1
        next
    }
    variant && !changed && /persist-credentials:[[:space:]]*false/ {
        sub(/false/, "true")
        changed = 1
    }
    { print }
    END { if (!variant || !changed) exit 1 }
' "$workflow" >"$tmp/case-checkout-input.yml"
expect_structural_rejected "case-variant checkout credential policy" \
    "$tmp/case-checkout-input.yml" "$today"

# Pair an unsafe case-variant FreeBSD action with a second valid lowercase
# instance. An exact-case classifier would ignore the unsafe action and let the
# valid decoy satisfy its one-action aggregate requirement.
awk '
    !variant && /uses:[ ]*cross-platform-actions\/action@/ {
        action_text = $0
        sub(/^[ ]*/, "", action_text)
        sub(/^-[ ]*/, "", action_text)
        sub(/^uses:[ ]*/, "", action_text)
        sub(/cross-platform-actions\/action/,
            "Cross-Platform-Actions/Action")
        print
        variant = 1
        next
    }
    variant && !changed && /operating_system:[[:space:]]*freebsd/ {
        sub(/freebsd/, "openbsd")
        changed = 1
    }
    $0 == "  macos:" && changed && !added {
        print "      - uses: " action_text
        print "        with:"
        print "          operating_system: freebsd"
        print "          version: \"14.4\""
        added = 1
    }
    { print }
    END { if (!variant || !changed || !added) exit 1 }
' "$workflow" >"$tmp/case-freebsd-input.yml"
expect_structural_rejected "case-variant FreeBSD input policy" \
    "$tmp/case-freebsd-input.yml" "$today"

# Valid YAML flow-style job permissions override the workflow default. Both a
# flow grant and comment/quote variants of a block grant must be rejected.
awk '
    { print }
    $0 == "  linux:" && !changed {
        print "    permissions: { contents: write }"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/flow-write-permissions.yml"
expect_structural_rejected "flow-style job write permission" \
    "$tmp/flow-write-permissions.yml" "$today"

awk '
    { print }
    $0 == "  linux:" && !changed {
        print "    permissions:"
        print "      contents: write # job override"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/commented-write-permissions.yml"
expect_structural_rejected "comment-suffixed job write permission" \
    "$tmp/commented-write-permissions.yml" "$today"

awk '
    { print }
    $0 == "  linux:" && !changed {
        print "    \"permissions\":"
        print "      \"contents\": \"write\""
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/quoted-write-permissions.yml"
expect_structural_rejected "quoted job write permission" \
    "$tmp/quoted-write-permissions.yml" "$today"

awk '
    { print }
    $0 == "  linux:" && !changed {
        print "    permissions: write-all"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/write-all-permissions.yml"
expect_structural_rejected "job write-all permission" \
    "$tmp/write-all-permissions.yml" "$today"

# Duplicate critical keys and YAML indirection have implementation-dependent
# merge/last-key behavior, so the canonical subset rejects them outright.
awk '
    { print }
    $0 == "  contents: read" && !changed {
        print "permissions: { contents: read }"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/duplicate-top-permissions.yml"
expect_structural_rejected "duplicate top-level permissions" \
    "$tmp/duplicate-top-permissions.yml" "$today"

awk '
    { print }
    $0 == "  linux:" && !changed {
        print "    permissions: { contents: read, contents: write }"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/duplicate-flow-permissions.yml"
expect_structural_rejected "duplicate flow permission key" \
    "$tmp/duplicate-flow-permissions.yml" "$today"

awk '
    $0 == "permissions:" && !changed {
        print "permissions: &permission_defaults"
        changed = 1
        next
    }
    { print }
    $0 == "  linux:" && changed && !aliased {
        print "    permissions: *permission_defaults"
        aliased = 1
    }
    END { if (!changed || !aliased) exit 1 }
' "$workflow" >"$tmp/aliased-permissions.yml"
[ "$(grep -c '^jobs:$' "$tmp/aliased-permissions.yml")" -eq 1 ] ||
    fail "aliased permission fixture duplicated the jobs mapping"
expect_structural_rejected_for "aliased permission mapping" \
    "$tmp/aliased-permissions.yml" "$today" \
    "YAML anchors, aliases, and tags are unsupported"

awk '
    !changed && /^[ ]*-[ ]*uses:[ ]*/ {
        print
        duplicate = $0
        sub(/^[ ]*-[ ]*/, "        ", duplicate)
        print duplicate
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/duplicate-uses.yml"
expect_structural_rejected "duplicate uses key" \
    "$tmp/duplicate-uses.yml" "$today"

sed 's/persist-credentials: false/persist-credentials: true/g' \
    "$workflow" >"$tmp/credentials.yml"
expect_structural_rejected "persisted checkout credential" \
    "$tmp/credentials.yml" "$today"

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
expect_structural_rejected "comment-masked persisted checkout credential" \
    "$tmp/credentials-comment.yml" "$today"

# Inputs nested under a decoy map are not direct action inputs. Indentation
# greater than `with` is insufficient: effective inputs must be exactly one
# mapping level below it.
awk '
    !changed && /persist-credentials:[[:space:]]*false/ {
        line = $0
        match(line, /^[ ]*/)
        indent = substr(line, 1, RLENGTH)
        sub(/^[ ]*/, "", line)
        print indent "decoy:"
        print indent "  " line
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/nested-checkout-input.yml"
expect_structural_rejected "nested checkout credential decoy" \
    "$tmp/nested-checkout-input.yml" "$today"

awk '
    !nested && /operating_system:[[:space:]]*freebsd/ {
        line = $0
        match(line, /^[ ]*/)
        indent = substr(line, 1, RLENGTH)
        sub(/^[ ]*/, "", line)
        print indent "decoy:"
        print indent "  " line
        nested = 1
        next
    }
    nested && !changed && /version:[[:space:]]*/ && /14[.]4/ {
        line = $0
        sub(/^[ ]*/, "", line)
        print indent "  " line
        changed = 1
        next
    }
    { print }
    END { if (!nested || !changed) exit 1 }
' "$workflow" >"$tmp/nested-freebsd-inputs.yml"
expect_structural_rejected "nested FreeBSD input decoys" \
    "$tmp/nested-freebsd-inputs.yml" "$today"

sed 's/contents: read/contents: write/g' "$workflow" >"$tmp/write.yml"
expect_structural_rejected "write permission" "$tmp/write.yml" "$today"

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

# Every required platform/configuration/command tuple is an independent policy
# fact. Replacing any one command must fail even when an identical command is
# still present in another job or non-executable text mentions the target.
release_matrix_index=0
while IFS='|' read -r matrix_job matrix_gate matrix_command; do
    release_matrix_index=$((release_matrix_index + 1))
    matrix_fixture=$tmp/release-command-$release_matrix_index.yml
    mutate_release_command "$matrix_job" "$matrix_command" true \
        "$matrix_fixture"
    expect_structural_rejected_for "missing $matrix_gate executable gate" \
        "$matrix_fixture" "$today" \
        "missing or duplicate exact release gate: $matrix_gate"
done <<'EOF'
linux|linux-make-provenance|/usr/bin/dpkg --verify make
linux|linux-policy|/bin/sh tests/test_ci_policy.sh .
linux|linux-coverage|/usr/bin/make coverage
linux|linux-gcc-test|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test
linux|linux-gcc-artifact|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test
linux|linux-symbol-contract|/usr/bin/make -B release-symbol-contract-test
linux|linux-contract|/usr/bin/make release-contract-test
linux|linux-clang-test|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 test
linux|linux-clang-artifact|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test
macos|macos-test|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test
macos|macos-artifact|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test
macos|macos-contract|/usr/bin/make release-contract-test
freebsd|freebsd-test|gmake BUILD_TYPE=release WERROR=1 test
freebsd|freebsd-artifact|gmake BUILD_TYPE=release WERROR=1 release-artifact-test
freebsd|freebsd-contract|gmake release-contract-test
EOF

awk '
    skip { skip = 0; next }
    $0 == "      - name: Verify coverage build provenance" && !changed {
        changed = 1
        skip = 1
        next
    }
    { print }
    END { if (!changed || skip) exit 1 }
' "$workflow" >"$tmp/missing-coverage-provenance.yml"
expect_structural_rejected_for "missing Linux coverage provenance" \
    "$tmp/missing-coverage-provenance.yml" "$today" \
    "missing or duplicate exact release gate: linux-coverage-provenance"

# Coverage evidence is useful only when the exact GCC report is uploaded as a
# required artifact. A different path or a conditional action must not satisfy
# the adjacency check by occupying the expected step position.
awk '
    !changed && $0 == "          path: build/coverage/" {
        print "          path: build/unrelated/"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/wrong-coverage-upload-path.yml"
expect_structural_rejected_for "wrong Linux coverage upload path" \
    "$tmp/wrong-coverage-upload-path.yml" "$today" \
    "coverage upload inputs must match the exact reviewed artifact contract"

awk '
    { print }
    !changed && $0 == "      - name: Upload source coverage reports" {
        print "        if: false"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/conditional-coverage-upload.yml"
expect_structural_rejected_for "conditional Linux coverage upload" \
    "$tmp/conditional-coverage-upload.yml" "$today" \
    "coverage upload must be unconditional and failure-fatal"

awk '
    !changed && $0 == "          if-no-files-found: error" {
        print "          if-no-files-found: ignore"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/ignored-missing-coverage-upload.yml"
expect_structural_rejected_for "ignored missing Linux coverage artifact" \
    "$tmp/ignored-missing-coverage-upload.yml" "$today" \
    "coverage upload inputs must match the exact reviewed artifact contract"

# AR-11 M36: literal command text is evidence only when Linux first verifies
# the package-owned build tool and keeps executable resolution immutable. This
# is the original causal fixture: preseeded outputs plus a replacement earlier
# on PATH used to satisfy every lexical gate.
awk '
    $0 == "      - name: Shell assets (ShellCheck + native parsers)" &&
        !changed {
        print "      - name: Resolver replacement fixture"
        print "        run: |"
        print "          mkdir -p build/bin build/tools build/coverage"
        print "          cp /bin/true build/bin/gitswitch"
        print "          cp /bin/true build/tools/release-publish"
        print "          touch build/coverage/empty.txt"
        print "          sudo install -m 0755 /bin/true /usr/local/bin/make"
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/linux-resolver-replacement.yml"
expect_structural_rejected_for "Linux resolver replacement" \
    "$tmp/linux-resolver-replacement.yml" "$today" \
    "required release jobs cannot mutate executable resolution"

# Package provenance for /usr/bin/make is insufficient when make recipes
# resolve their own QA tools through PATH. A preceding step can otherwise put
# successful no-op binaries in the higher-precedence local executable roots.
awk '
    $0 == "      - name: Shell assets (ShellCheck + native parsers)" &&
        !changed {
        print "      - name: QA tool shadow fixture"
        print "        run: |"
        print "          sudo install -m 0755 /bin/true /usr/local/bin/valgrind"
        print "          sudo install -m 0755 /bin/true /usr/local/bin/cppcheck"
        print "          sudo install -m 0755 /bin/true /usr/local/bin/flawfinder"
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/linux-qa-tool-shadows.yml"
expect_structural_rejected_for "Linux QA tool shadows" \
    "$tmp/linux-qa-tool-shadows.yml" "$today" \
    "required release jobs cannot mutate executable resolution"

# Cover the ordinary filesystem mutation spellings rather than keying the
# policy to one `install` fixture. References to these executable roots are
# forbidden in required-job run steps, so quoting, directory changes, and
# redirection do not create parser-dependent exceptions.
tool_shadow_index=0
while IFS='|' read -r matrix_label matrix_command; do
    tool_shadow_index=$((tool_shadow_index + 1))
    matrix_fixture=$tmp/linux-tool-shadow-$tool_shadow_index.yml
    awk -v command="$matrix_command" '
        $0 == "      - name: Shell assets (ShellCheck + native parsers)" &&
            !changed {
            print "      - name: Executable-root mutation fixture"
            print "        run: " command
            changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$matrix_fixture"
    expect_structural_rejected_for \
        "Linux executable-root $matrix_label mutation" \
        "$matrix_fixture" "$today" \
        "required release jobs cannot mutate executable resolution"
done <<'EOF'
copy|sudo cp /bin/true /usr/local/bin/valgrind
move|sudo cp /bin/true /tmp/ci-tool-shadow && sudo mv /tmp/ci-tool-shadow /usr/local/bin/cppcheck
link|sudo ln -sf /bin/true /usr/local/bin/flawfinder
redirection|sudo sh -c 'echo true > /usr/local/bin/cppcheck; chmod 0755 /usr/local/bin/cppcheck'
quoted install|sudo install -m 0755 /bin/true "/usr/local/bin/valgrind"
directory change|cd /usr/local/bin && sudo cp /bin/true valgrind
sbin install|sudo install -m 0755 /bin/true /usr/local/sbin/valgrind
canonical directory change|cd /usr/bin && sudo cp /bin/true make
canonical install target|sudo install -m 0755 -t /usr/bin /bin/true
canonical install target-directory|sudo install --target-directory /sbin /bin/true
EOF

awk '
    $0 == "      - name: Shell assets (ShellCheck + native parsers)" &&
        !changed {
        print "      - name: PATH replacement fixture"
        print "        run: PATH=/tmp/ci-tools:$PATH"
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/linux-path-replacement.yml"
expect_structural_rejected_for "Linux PATH replacement" \
    "$tmp/linux-path-replacement.yml" "$today" \
    "required release jobs cannot mutate executable resolution"

mutate_release_command linux \
    "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test" \
    "make BUILD_TYPE=release READLINE=1 WERROR=1 test" \
    "$tmp/linux-unqualified-make.yml"
expect_structural_rejected_for "Linux command-name build tool" \
    "$tmp/linux-unqualified-make.yml" "$today" \
    "missing or duplicate exact release gate: linux-gcc-test"

# Outputs seeded immediately before the release lane must not survive by
# deleting the required clean gate. Coverage and publisher production are also
# independently required above, so artifact existence alone is never enough.
awk '
    $0 == "      - name: Clean before the GCC release build" && !changed {
        print "      - name: Pre-existing output fixture"
        print "        run: |"
        print "          mkdir -p build/bin build/tools build/coverage"
        print "          cp /bin/true build/bin/gitswitch"
        print "          cp /bin/true build/tools/release-publish"
        print "          touch build/coverage/empty.txt"
        print
        getline
        if ($0 != "        run: /usr/bin/make clean") exit 1
        print "        run: true"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/linux-preexisting-outputs-no-clean.yml"
expect_structural_rejected "Linux pre-existing outputs without clean provenance" \
    "$tmp/linux-preexisting-outputs-no-clean.yml" "$today"

# The clang lane has the same clean-production-consumption provenance rule as
# GCC. A future-dated stale binary inserted after the clean must not survive as
# the artifact exercised by the exact command text that follows.
awk '
    { print }
    $0 == "        run: /usr/bin/make clean" { clean_count++ }
    clean_count == 2 && !changed {
        print "      - name: Future-dated stale clang artifact fixture"
        print "        run: touch -d 2100-01-01 build/bin/gitswitch"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/linux-clang-stale-artifact.yml"
expect_structural_rejected_for "Linux clang stale artifact insertion" \
    "$tmp/linux-clang-stale-artifact.yml" "$today" \
    "Linux clang release provenance gates must remain adjacent"

# The locked symbol contract must immediately consume the GCC artifact. A
# replacement step inserted between those gates would otherwise inspect a
# different application binary even though helper production/use is locked.
awk '
    { print }
    !changed && $0 == "        run: /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test" {
        print "      - name: Pre-symbol replacement fixture"
        print "        run: |"
        print "          cp /bin/true build/bin/gitswitch"
        print "          cp /bin/true build/tools/release-publish"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/linux-pre-symbol-replacement.yml"
expect_structural_rejected_for "Linux pre-symbol replacement" \
    "$tmp/linux-pre-symbol-replacement.yml" "$today" \
    "Linux GCC release provenance gates must remain adjacent"

add_release_step_field linux \
    "/usr/bin/make -B release-symbol-contract-test" \
    "if: false" "$tmp/conditional-symbol-contract.yml"
expect_structural_rejected_for "conditional Linux symbol contract" \
    "$tmp/conditional-symbol-contract.yml" "$today" \
    "required release gate step must be unconditional"

# AR-11 M37: the policy checker is itself one exact hosted gate. Conditions,
# ignored failures, duplication, command removal, or a preceding rewrite cannot
# silently retire it. Canonical checkout is its immutable producer, so the
# consumer must run in the immediately following step.
awk '
    !changed && $0 == "      - name: CI policy self-check" {
        print "      - name: Neuter checked policy fixture"
        print "        run: printf '\''%s\\n'\'' '\''#!/bin/sh'\'' '\''exit 0'\'' > tests/test_ci_policy.sh"
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/pre-invocation-policy-neuter.yml"
expect_structural_rejected_for "pre-invocation policy self-check rewrite" \
    "$tmp/pre-invocation-policy-neuter.yml" "$today" \
    "Linux CI policy self-check must immediately follow checkout"

add_release_step_field linux "/bin/sh tests/test_ci_policy.sh ." "if: false" \
    "$tmp/conditional-policy-self-check.yml"
expect_structural_rejected_for "conditional policy self-check" \
    "$tmp/conditional-policy-self-check.yml" "$today" \
    "required release gate step must be unconditional"

add_release_step_field linux "/bin/sh tests/test_ci_policy.sh ." \
    "continue-on-error: true" "$tmp/ignored-policy-self-check.yml"
expect_structural_rejected_for "ignored policy self-check failure" \
    "$tmp/ignored-policy-self-check.yml" "$today" \
    "required release gate step cannot continue on error"

awk '
    { print }
    $0 == "        run: /bin/sh tests/test_ci_policy.sh ." && !changed {
        print "      - name: Duplicate CI policy self-check"
        print "        run: /bin/sh tests/test_ci_policy.sh ."
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/duplicate-policy-self-check.yml"
expect_structural_rejected_for "duplicate policy self-check" \
    "$tmp/duplicate-policy-self-check.yml" "$today" \
    "missing or duplicate exact release gate: linux-policy"

# The exact configuration is part of each build/test and artifact gate. Exercise
# every required knob on every affected platform/compiler/command combination.
config_matrix_index=0
while IFS='|' read -r matrix_job matrix_gate matrix_command matrix_token \
    matrix_replacement matrix_reason; do
    config_matrix_index=$((config_matrix_index + 1))
    matrix_fixture=$tmp/release-config-$config_matrix_index.yml
    matrix_mutated=$(printf '%s\n' "$matrix_command" |
        sed "s/$matrix_token/$matrix_replacement/")
    [ "$matrix_mutated" != "$matrix_command" ] ||
        fail "release configuration mutation did not change $matrix_gate"
    [ -n "$matrix_reason" ] ||
        matrix_reason="missing or duplicate exact release gate: $matrix_gate"
    mutate_release_command "$matrix_job" "$matrix_command" "$matrix_mutated" \
        "$matrix_fixture"
    expect_structural_rejected_for \
        "$matrix_gate with mutated $matrix_token configuration" \
        "$matrix_fixture" "$today" \
        "$matrix_reason"
done <<'EOF'
linux|linux-gcc-test|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test|BUILD_TYPE=release|BUILD_TYPE=debug|required release gate environment is missing or unsafe
linux|linux-gcc-test|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test|READLINE=1|READLINE=0
linux|linux-gcc-test|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test|WERROR=1|WERROR=0
linux|linux-gcc-artifact|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|BUILD_TYPE=release|BUILD_TYPE=debug
linux|linux-gcc-artifact|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|READLINE=1|READLINE=0
linux|linux-gcc-artifact|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|WERROR=1|WERROR=0
linux|linux-clang-test|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 test|CC=clang|CC=gcc
linux|linux-clang-test|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 test|BUILD_TYPE=release|BUILD_TYPE=debug
linux|linux-clang-test|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 test|READLINE=1|READLINE=0
linux|linux-clang-test|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 test|WERROR=1|WERROR=0
linux|linux-clang-artifact|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|CC=clang|CC=gcc
linux|linux-clang-artifact|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|BUILD_TYPE=release|BUILD_TYPE=debug
linux|linux-clang-artifact|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|READLINE=1|READLINE=0
linux|linux-clang-artifact|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|WERROR=1|WERROR=0
macos|macos-test|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test|BUILD_TYPE=release|BUILD_TYPE=debug
macos|macos-test|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test|READLINE=1|READLINE=0
macos|macos-test|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test|WERROR=1|WERROR=0
macos|macos-artifact|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|BUILD_TYPE=release|BUILD_TYPE=debug
macos|macos-artifact|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|READLINE=1|READLINE=0
macos|macos-artifact|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test|WERROR=1|WERROR=0
freebsd|freebsd-test|gmake BUILD_TYPE=release WERROR=1 test|BUILD_TYPE=release|BUILD_TYPE=debug
freebsd|freebsd-test|gmake BUILD_TYPE=release WERROR=1 test|WERROR=1|WERROR=0
freebsd|freebsd-artifact|gmake BUILD_TYPE=release WERROR=1 release-artifact-test|BUILD_TYPE=release|BUILD_TYPE=debug
freebsd|freebsd-artifact|gmake BUILD_TYPE=release WERROR=1 release-artifact-test|WERROR=1|WERROR=0
EOF

# Required jobs are exact platform facts: a renamed/missing job, a wrong runner,
# or any job-level condition makes the release evidence non-mandatory.
for matrix_job in linux macos freebsd; do
    rename_release_job "$matrix_job" "$tmp/missing-$matrix_job-job.yml"
    expect_structural_rejected "missing $matrix_job release job" \
        "$tmp/missing-$matrix_job-job.yml" "$today"
    mutate_release_runner "$matrix_job" windows-latest \
        "$tmp/wrong-$matrix_job-runner.yml"
    expect_structural_rejected_for "wrong $matrix_job release runner" \
        "$tmp/wrong-$matrix_job-runner.yml" "$today" \
        "required release job runner is missing or incorrect"
    add_release_job_field "$matrix_job" "if: false" \
        "$tmp/false-$matrix_job-job.yml"
    expect_structural_rejected_for "false $matrix_job release job condition" \
        "$tmp/false-$matrix_job-job.yml" "$today" \
        "required release job must be unconditional"
done

awk '
    { print }
    $0 == "  linux:" && !changed {
        print "    defaults:"
        print "      run:"
        print "        shell: bash"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/linux-job-shell-default.yml"
expect_structural_rejected_for "Linux job release shell default" \
    "$tmp/linux-job-shell-default.yml" "$today" \
    "required release job cannot override shell defaults"

awk '
    { print }
    $0 == "  linux:" && !changed {
        print "    defaults:"
        print "      run:"
        print "        working-directory: fixtures/noop"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/linux-job-working-directory-default.yml"
expect_structural_rejected_for "Linux job release working-directory default" \
    "$tmp/linux-job-working-directory-default.yml" "$today" \
    "required release job cannot override shell defaults"

add_release_job_field linux "container: alpine:latest" \
    "$tmp/linux-release-container.yml"
expect_structural_rejected_for "Linux release execution container" \
    "$tmp/linux-release-container.yml" "$today" \
    "required release job cannot override its execution container"

# Step-level conditions, error suppression, shell overrides, and working
# directories are checked on all three execution surfaces. Explicit
# continue-on-error:false remains safe.
while IFS='|' read -r matrix_job matrix_command; do
    add_release_step_field "$matrix_job" "$matrix_command" "if: false" \
        "$tmp/false-$matrix_job-release-step.yml"
    expect_structural_rejected_for "false $matrix_job release step condition" \
        "$tmp/false-$matrix_job-release-step.yml" "$today" \
        "required release gate step must be unconditional"
    add_release_step_field "$matrix_job" "$matrix_command" \
        "continue-on-error: true" \
        "$tmp/continue-$matrix_job-release-step.yml"
    expect_structural_rejected_for "$matrix_job release error suppression" \
        "$tmp/continue-$matrix_job-release-step.yml" "$today" \
        "required release gate step cannot continue on error"
    add_release_step_field "$matrix_job" "$matrix_command" "shell: bash" \
        "$tmp/shell-$matrix_job-release-step.yml"
    case $matrix_job in
        freebsd)
            shell_reason="FreeBSD release gate step must use exact shell: cpa.sh {0}"
            ;;
        *) shell_reason="required release gate step cannot override its shell" ;;
    esac
    expect_structural_rejected_for "$matrix_job release shell override" \
        "$tmp/shell-$matrix_job-release-step.yml" "$today" \
        "$shell_reason"
    add_release_step_field "$matrix_job" "$matrix_command" \
        "working-directory: fixtures/noop" \
        "$tmp/workdir-$matrix_job-release-step.yml"
    expect_structural_rejected_for \
        "$matrix_job release working-directory override" \
        "$tmp/workdir-$matrix_job-release-step.yml" "$today" \
        "required release gate step cannot set working-directory"
done <<'EOF'
linux|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test
macos|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test
freebsd|gmake BUILD_TYPE=release WERROR=1 test
EOF

# The ban is release-job-wide, not limited to the small set of commands used
# to establish ordering. Otherwise a fake Makefile in a redirected directory
# can turn the remaining policy, QA, and security steps into successful no-ops.
add_release_step_field linux "/bin/sh tests/test_ci_policy.sh ." \
    "working-directory: fixtures/noop" \
    "$tmp/workdir-linux-policy-self-check.yml"
expect_structural_rejected_for "redirected Linux policy self-check" \
    "$tmp/workdir-linux-policy-self-check.yml" "$today" \
    "required release gate step cannot set working-directory"

# AR-12 M9: the QA/memory-safety lanes are now exact release gates, so their
# redirection trips the gate-specific check; non-gate direct steps keep the
# job-wide message.
linux_workdir_index=0
while IFS='|' read -r matrix_label matrix_command matrix_reason; do
    linux_workdir_index=$((linux_workdir_index + 1))
    matrix_fixture=$tmp/workdir-linux-$linux_workdir_index.yml
    [ -n "$matrix_reason" ] ||
        matrix_reason="direct steps in required release jobs cannot set working-directory"
    add_release_step_field linux "$matrix_command" \
        "working-directory: fixtures/noop" "$matrix_fixture"
    expect_structural_rejected_for \
        "redirected Linux $matrix_label step" \
        "$matrix_fixture" "$today" \
        "$matrix_reason"
done <<'EOF'
shell static policy|/usr/bin/make shell-static-test
debug sanitizer suite|/usr/bin/make BUILD_TYPE=debug READLINE=1 WERROR=1 test|required release gate step cannot set working-directory
Valgrind suite|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 memcheck|required release gate step cannot set working-directory
distribution check|/usr/bin/make distcheck|required release gate step cannot set working-directory
static analysis|/usr/bin/make analyze|required release gate step cannot set working-directory
security scan|/usr/bin/make security-scan|required release gate step cannot set working-directory
QA negative contracts|/usr/bin/make qa-contract-test|required release gate step cannot set working-directory
signal repro|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 sig-repro-test|required release gate step cannot set working-directory
EOF

awk '
    { print }
    !changed && $0 == "      - name: No-shell gate (source tripwire)" {
        print "        working-directory: fixtures/noop"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/workdir-linux-source-tripwire.yml"
expect_structural_rejected_for "redirected Linux source tripwire" \
    "$tmp/workdir-linux-source-tripwire.yml" "$today" \
    "direct steps in required release jobs cannot set working-directory"

add_release_step_field linux \
    "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test" \
    "continue-on-error: false" "$tmp/explicit-no-continue.yml"
expect_accepted "explicit release continue-on-error false" \
    "$tmp/explicit-no-continue.yml" "$today"

# Environment and shell defaults can change what an otherwise exact command
# means. The canonical release subset forbids workflow/job overrides, allows
# only the exact runtime-capability env on release test steps, and pins FreeBSD
# execution to the reviewed cpa shell.
awk '
    $0 == "jobs:" && !changed {
        print "env:"
        print "  MAKEFLAGS: -i"
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/workflow-env-override.yml"
expect_structural_rejected_for "workflow release environment override" \
    "$tmp/workflow-env-override.yml" "$today" \
    "workflow environment overrides are unsupported"

awk '
    $0 == "jobs:" && !changed {
        print "defaults:"
        print "  run:"
        print "    shell: bash"
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/workflow-shell-default.yml"
expect_structural_rejected_for "workflow release shell default" \
    "$tmp/workflow-shell-default.yml" "$today" \
    "workflow shell defaults are unsupported"

for matrix_job in linux macos freebsd; do
    awk -v wanted_job="$matrix_job" '
        { print }
        $0 == "  " wanted_job ":" && !changed {
            print "    env:"
            print "      MAKEFLAGS: -i"
            changed = 1
        }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$tmp/job-env-$matrix_job.yml"
    expect_structural_rejected_for "$matrix_job job environment override" \
        "$tmp/job-env-$matrix_job.yml" "$today" \
        "required release job cannot override its environment"
done

while IFS='|' read -r matrix_job matrix_command; do
    mutate_release_caps "$matrix_job" "$matrix_command" \
        "$tmp/caps-$matrix_job-$(printf '%s' "$matrix_command" | cksum | awk '{print $1}').yml"
    matrix_fixture=$tmp/caps-$matrix_job-$(printf '%s' "$matrix_command" |
        cksum | awk '{print $1}').yml
    expect_structural_rejected_for "$matrix_job release runtime-capability downgrade" \
        "$matrix_fixture" "$today" \
        "required release gate environment is missing or unsafe"
done <<'EOF'
linux|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test
linux|/usr/bin/make CC=clang BUILD_TYPE=release READLINE=1 WERROR=1 test
macos|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test
EOF

awk '
    !changed &&
        $0 == "          export GITSWITCH_TEST_REQUIRED_CAPS=pty,readline,bash,zsh,fish,sh,dash,openssh,gpg,unix-sockets,freebsd-nullfs" {
        print "          export GITSWITCH_TEST_REQUIRED_CAPS=pty,readline,bash,zsh,fish,sh,dash,openssh,gpg,unix-sockets"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-capability-downgrade.yml"
expect_structural_rejected_for "FreeBSD nullfs capability downgrade" \
    "$tmp/freebsd-capability-downgrade.yml" "$today" \
    "FreeBSD required test capabilities are missing or unsafe"

# Count the env mapping itself as well as its entries. Duplicate YAML keys have
# loader-dependent first/last-key semantics; neither an empty map before nor an
# empty map after the exact capability map may erase or ambiguously shadow it.
awk '
    { print }
    $0 == "        run: /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test" {
        target = 1
    }
    target && !changed &&
        $0 ~ /^          GITSWITCH_TEST_REQUIRED_CAPS:/ {
        print "        env:"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/duplicate-env-after-caps.yml"
expect_structural_rejected_for "duplicate release env after exact caps" \
    "$tmp/duplicate-env-after-caps.yml" "$today" \
    "required release gate environment is missing or unsafe"

awk '
    !changed &&
        $0 == "        run: /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test" {
        print "        env:"
        print
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/duplicate-env-before-caps.yml"
expect_structural_rejected_for "duplicate release env before exact caps" \
    "$tmp/duplicate-env-before-caps.yml" "$today" \
    "required release gate environment is missing or unsafe"

awk '
    $0 == "        run: /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test" {
        target = 1
    }
    target && !changed &&
        $0 ~ /^          GITSWITCH_TEST_REQUIRED_CAPS:/ {
        print "          GITSWITCH_TEST_REQUIRED_CAPS: '\''pty,readline,bash,zsh,fish,sh,dash,ksh,openssh,gpg,unix-sockets,mount-namespace'\''"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/single-quoted-release-env.yml"
expect_accepted "single exact release env mapping" \
    "$tmp/single-quoted-release-env.yml" "$today"

while IFS='|' read -r matrix_job matrix_command; do
    add_release_step_field "$matrix_job" "$matrix_command" \
        "env: { MAKEFLAGS: -i }" "$tmp/step-env-$matrix_job.yml"
    expect_structural_rejected_for "$matrix_job release step environment override" \
        "$tmp/step-env-$matrix_job.yml" "$today" \
        "required release gate environment is missing or unsafe"
done <<'EOF'
linux|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test
macos|/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test
freebsd|gmake BUILD_TYPE=release WERROR=1 release-artifact-test
EOF

awk '
    !changed && $0 == "        shell: cpa.sh {0}" {
        print "        shell: bash"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-wrong-shell.yml"
expect_structural_rejected_for "wrong FreeBSD cpa shell" \
    "$tmp/freebsd-wrong-shell.yml" "$today" \
    "FreeBSD release gate step must use exact shell: cpa.sh {0}"

awk '
    !changed && $0 == "        shell: cpa.sh {0}" {
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-missing-shell.yml"
expect_structural_rejected_for "missing FreeBSD cpa shell" \
    "$tmp/freebsd-missing-shell.yml" "$today" \
    "FreeBSD release gate step must use exact shell: cpa.sh {0}"

# v1.3.0 starts the VM in the action step; commands belong only in the
# immediately following cpa.sh step. Both the deprecated scalar input and a
# legacy command-bearing block must fail before their text can count as gates.
awk '
    { print }
    !changed && $0 == "          version: '\''14.4'\''" {
        print "          run: true"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-deprecated-action-run.yml"
expect_structural_rejected_for "deprecated FreeBSD action run input" \
    "$tmp/freebsd-deprecated-action-run.yml" "$today" \
    "FreeBSD VM action cannot carry run or shell inputs"

# Inputs beyond the reviewed operating-system/version pair can change VM
# publication and synchronization behavior, so the policy rejects them rather
# than silently treating an unfamiliar action configuration as canonical.
awk '
    { print }
    !changed && $0 == "          version: '\''14.4'\''" {
        print "          sync_files: false"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-extra-action-input.yml"
expect_structural_rejected_for "extra FreeBSD action input" \
    "$tmp/freebsd-extra-action-input.yml" "$today" \
    "FreeBSD VM action configuration is missing or unsafe"

awk '
    { print }
    !changed && $0 == "          version: '\''14.4'\''" {
        print "          run: |"
        print "            gmake release-contract-test"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-command-in-action.yml"
expect_structural_rejected_for "FreeBSD command left in action text" \
    "$tmp/freebsd-command-in-action.yml" "$today" \
    "FreeBSD VM action cannot carry run or shell inputs"

awk '
    { print }
    !changed && $0 == "          memory: 8G" {
        print "      - name: Intervening host step"
        print "        run: true"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-nonadjacent-cpa.yml"
expect_structural_rejected_for "nonadjacent FreeBSD cpa shell step" \
    "$tmp/freebsd-nonadjacent-cpa.yml" "$today" \
    "FreeBSD cpa shell step must immediately follow the VM action"

awk '
    { print }
    !changed && $0 == "        shell: cpa.sh {0}" {
        print "      - name: Duplicate FreeBSD cpa shell"
        print "        run: true"
        print "        shell: cpa.sh {0}"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-duplicate-cpa.yml"
expect_structural_rejected_for "duplicate FreeBSD cpa shell step" \
    "$tmp/freebsd-duplicate-cpa.yml" "$today" \
    "FreeBSD release gates need exactly one cpa shell step"

# A prior step cannot persist MAKEFLAGS/PATH through the runner environment and
# silently reinterpret later exact commands.
awk '
    $0 == "      - name: Clean before the GCC release build" && !changed {
        print "      - name: Persisted release override decoy"
        print "        run: printf '\''%s\\n'\'' '\''MAKEFLAGS=-i'\'' >> \"$GITHUB_ENV\""
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/persisted-release-env.yml"
expect_structural_rejected_for "persisted release environment override" \
    "$tmp/persisted-release-env.yml" "$today" \
    "required release jobs cannot persist environment overrides"

# The shared FreeBSD cpa shell script must establish fatal command failures
# before every gate and cannot redefine gmake or its controlling environment.
mutate_release_command freebsd "set -eu" true "$tmp/freebsd-no-errexit.yml"
expect_structural_rejected_for "FreeBSD release gates without errexit" \
    "$tmp/freebsd-no-errexit.yml" "$today" \
    "FreeBSD release gates require an earlier set -eu"

for unsafe_line in "alias gmake=true" "gmake() { true; }" \
    "export MAKEFLAGS=-i" "hash -p /usr/bin/true gmake"; do
    unsafe_id=$(printf '%s\n' "$unsafe_line" | cksum | awk '{print $1}')
    awk -v injected="$unsafe_line" '
        { print }
        !changed && $0 == "          set -eu" {
            print "          " injected
            changed = 1
        }
        END { if (!changed) exit 1 }
    ' "$workflow" >"$tmp/freebsd-command-override-$unsafe_id.yml"
    expect_structural_rejected "FreeBSD gmake override: $unsafe_line" \
        "$tmp/freebsd-command-override-$unsafe_id.yml" "$today"
done

awk '
    !changed &&
        $0 == "          gmake BUILD_TYPE=release WERROR=1 test" {
        print "          cat <<'\''POLICY'\''"
        print "          gmake BUILD_TYPE=release WERROR=1 test"
        print "          POLICY"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-quoted-heredoc.yml"
expect_structural_rejected_for "FreeBSD quoted-heredoc release decoy" \
    "$tmp/freebsd-quoted-heredoc.yml" "$today" \
    "required release gate command is not provably reachable"

# Same-line shell control operators cannot turn inert or suppressed commands into
# evidence. Exact commands in comments, names, env values, or echo arguments are
# likewise non-executable decoys.
mutate_release_command linux \
    "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test" \
    "false && /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test" \
    "$tmp/linux-false-and.yml"
expect_structural_rejected_for "Linux false-and release bypass" \
    "$tmp/linux-false-and.yml" "$today" \
    "missing or duplicate exact release gate: linux-gcc-test"

mutate_release_command macos "/usr/bin/make release-contract-test" \
    "/usr/bin/make release-contract-test || true" "$tmp/macos-or-true.yml"
expect_structural_rejected_for "macOS suppressed release contract" \
    "$tmp/macos-or-true.yml" "$today" \
    "missing or duplicate exact release gate: macos-contract"

mutate_release_command linux \
    "/usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test" \
    "true # /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test" \
    "$tmp/linux-comment-decoy.yml"
expect_structural_rejected_for "Linux comment-only artifact decoy" \
    "$tmp/linux-comment-decoy.yml" "$today" \
    "missing or duplicate exact release gate: linux-gcc-artifact"

mutate_release_command freebsd "gmake release-contract-test" \
    "# gmake release-contract-test" "$tmp/freebsd-comment-decoy.yml"
expect_structural_rejected_for "FreeBSD block comment contract decoy" \
    "$tmp/freebsd-comment-decoy.yml" "$today" \
    "missing or duplicate exact release gate: freebsd-contract"

mutate_release_command macos "/usr/bin/make release-contract-test" \
    "echo /usr/bin/make release-contract-test" "$tmp/macos-echo-decoy.yml"
expect_structural_rejected_for "macOS echo contract decoy" \
    "$tmp/macos-echo-decoy.yml" "$today" \
    "missing or duplicate exact release gate: macos-contract"

awk '
    /^  macos:[[:space:]]*$/ { in_macos = 1 }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ && $0 !~ /^  macos:/ {
        in_macos = 0
    }
    in_macos && !named &&
        $0 == "      - name: Release input consistency and dirty-tree refusal" {
        print "      - name: /usr/bin/make release-contract-test"
        named = 1
        next
    }
    in_macos && !changed && $0 == "        run: /usr/bin/make release-contract-test" {
        print "        run: true"
        changed = 1
        next
    }
    { print }
    END { if (!named || !changed) exit 1 }
' "$workflow" >"$tmp/macos-name-decoy.yml"
expect_structural_rejected_for "macOS name-only contract decoy" \
    "$tmp/macos-name-decoy.yml" "$today" \
    "missing or duplicate exact release gate: macos-contract"

awk '
    /^  macos:[[:space:]]*$/ { in_macos = 1 }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ && $0 !~ /^  macos:/ {
        in_macos = 0
    }
    in_macos && !changed && $0 == "        run: /usr/bin/make release-contract-test" {
        print "        run: true"
        print "        env:"
        print "          FAKE_POLICY_TEXT: /usr/bin/make release-contract-test"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/macos-env-decoy.yml"
expect_structural_rejected_for "macOS env-only contract decoy" \
    "$tmp/macos-env-decoy.yml" "$today" \
    "missing or duplicate exact release gate: macos-contract"

# A direct gate must be the only command in its run step. Folded scripts and
# FreeBSD block commands hidden behind continuations/conditionals are rejected.
awk '
    !changed &&
        $0 == "        run: /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test" {
        print "        run: |"
        print "          false"
        print "          /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 test"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/linux-multicommand-gate.yml"
expect_structural_rejected_for "Linux multi-command release step" \
    "$tmp/linux-multicommand-gate.yml" "$today" \
    "required release gate must be the sole command in its step"

awk '
    /^  freebsd:[[:space:]]*$/ { in_freebsd = 1 }
    in_freebsd && !changed && $0 == "        run: |" {
        print "        run: >"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-folded-run.yml"
expect_structural_rejected_for "folded FreeBSD release script" \
    "$tmp/freebsd-folded-run.yml" "$today" \
    "required release gate command is not provably reachable"

awk '
    !changed &&
        $0 == "          gmake BUILD_TYPE=release WERROR=1 test" {
        print "          false && \\"
        print "            gmake BUILD_TYPE=release WERROR=1 test"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-continuation-bypass.yml"
expect_structural_rejected_for "FreeBSD continuation release bypass" \
    "$tmp/freebsd-continuation-bypass.yml" "$today" \
    "missing or duplicate exact release gate: freebsd-test"

awk '
    !changed &&
        $0 == "          gmake BUILD_TYPE=release WERROR=1 test" {
        print "          if false; then"
        print "            gmake BUILD_TYPE=release WERROR=1 test"
        print "          fi"
        changed = 1
        next
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-conditional-bypass.yml"
expect_structural_rejected_for "FreeBSD conditional release bypass" \
    "$tmp/freebsd-conditional-bypass.yml" "$today" \
    "missing or duplicate exact release gate: freebsd-test"

awk '
    !changed &&
        $0 == "          gmake BUILD_TYPE=release WERROR=1 test" {
        print "          exit 0"
        print
        changed = 1
    }
    { print }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/freebsd-early-exit.yml"
expect_structural_rejected_for "FreeBSD early-exit release bypass" \
    "$tmp/freebsd-early-exit.yml" "$today" \
    "required release gate command is not provably reachable"

# A duplicated fact and a reordered test/artifact pair are both invalid: passing
# the artifact check must follow the exact release suite it is inspecting.
awk '
    { print }
    !changed &&
        $0 == "        run: /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test" {
        print "      - name: Duplicate release artifact decoy"
        print "        run: /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test"
        changed = 1
    }
    END { if (!changed) exit 1 }
' "$workflow" >"$tmp/duplicate-linux-release-gate.yml"
expect_structural_rejected_for "duplicate Linux release gate" \
    "$tmp/duplicate-linux-release-gate.yml" "$today" \
    "missing or duplicate exact release gate: linux-gcc-artifact"

awk '
    /^  macos:[[:space:]]*$/ { in_macos = 1 }
    /^  [A-Za-z0-9_-]+:[[:space:]]*$/ && $0 !~ /^  macos:/ {
        in_macos = 0
    }
    !first &&
        in_macos &&
        $0 == "        run: /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test" {
        print "        run: /usr/bin/make release-contract-test"
        first = 1
        next
    }
    in_macos && first && !second &&
        $0 == "        run: /usr/bin/make release-contract-test" {
        print "        run: /usr/bin/make BUILD_TYPE=release READLINE=1 WERROR=1 release-artifact-test"
        second = 1
        next
    }
    { print }
    END { if (!first || !second) exit 1 }
' "$workflow" >"$tmp/reordered-macos-release-gates.yml"
expect_structural_rejected_for "reordered macOS release gates" \
    "$tmp/reordered-macos-release-gates.yml" "$today" \
    "required release gates are out of order"

# AR-13 M4: the sanitizer lane pins one ASAN_OPTIONS and one UBSAN_OPTIONS at
# exact values. Duplicating ASAN_OPTIONS to stand in for a dropped
# UBSAN_OPTIONS keeps env_count==3 and the old shared sanitizer counter at 2,
# but silently disables the UBSAN strictness. The per-key counts must reject it.
awk '
    $0 == "          UBSAN_OPTIONS: halt_on_error=1:print_stacktrace=1" {
        print "          ASAN_OPTIONS: detect_leaks=1:abort_on_error=1:strict_string_checks=1"
        dropped = 1
        next
    }
    { print }
    END { if (!dropped) exit 1 }
' "$workflow" >"$tmp/sanitizer-dup-asan.yml" ||
    fail "could not build the duplicated-ASAN sanitizer fixture"
expect_rejected "duplicated ASAN_OPTIONS dropping UBSAN_OPTIONS" \
    "$tmp/sanitizer-dup-asan.yml" "$today"

printf 'ci-policy: PASS (immutable, least-privilege, supported-platform workflow)\n'
