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
    # keys) fail closed. Block scalar bodies are skipped so shell text cannot
    # masquerade as YAML nodes.
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
            step_active = 1
            step_use_count = 0
            step_action = ""
            step_with_seen = 0
            step_in_with = 0
            step_with_indent = -1
            step_persist_count = 0
            step_persist_value = ""
            step_persist_in_with = 0
            step_os_count = 0
            step_os_value = ""
            step_os_in_with = 0
            step_version_count = 0
            step_version_value = ""
            step_version_in_with = 0
        }
        function close_step(normalized_action) {
            if (!step_active) return
            if (step_use_count > 1) reject()
            normalized_action = tolower(step_action)
            if (normalized_action ~ /^actions\/checkout@/) {
                checkout_count++
                if (step_persist_count != 1 ||
                    step_persist_value != "false" ||
                    !step_persist_in_with)
                    reject("checkout action must set persist-credentials: false")
            }
            if (normalized_action ~ /^cross-platform-actions\/action@/) {
                if (step_os_count != 1 || !step_os_in_with ||
                    step_os_value != "freebsd" ||
                    step_version_count != 1 || !step_version_in_with ||
                    step_version_value !~ /^[0-9]+\.[0-9]+$/) reject()
                freebsd_action_count++
                freebsd_version = step_version_value
            }
            step_active = 0
            step_in_with = 0
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
                return
            }
            if (key == "with") {
                if (step_with_seen) reject()
                step_with_seen = 1
                parse_flow_with(value)
                return
            }
            if (substr(value, 1, 1) == "{" ||
                substr(value, 1, 1) == "[") reject()
            decode_scalar(value)
            if (!scalar_ok || scalar_value == "") reject()
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
        }
        {
            raw = $0
            if (block_scalar_indent >= 0) {
                if (raw ~ /^[[:space:]]*$/ || raw ~ /^[[:space:]]*#/) next
                if (indentation(raw) > block_scalar_indent) next
                block_scalar_indent = -1
            }
            if (raw ~ /\t/) reject()
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
            if (step_active &&
                (entry_key == "persist-credentials" ||
                 entry_key == "operating_system" || entry_key == "version")) {
                record_step_input(entry_key, entry_value,
                    step_in_with && current_indent == step_with_indent + 2)
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
            if (!top_permissions_seen || !jobs_seen || job_count == 0 ||
                use_count == 0 || external_use_count == 0 ||
                checkout_count == 0 || freebsd_action_count != 1) exit 1
            print "freebsd-version=" freebsd_version
        }
    ' "$workflow" >"$work_actions" || {
        policy_detail=$(sed -n '1p' "$work_actions")
        fail "workflow action/permission YAML is unsafe, ambiguous, or unsupported${policy_detail:+: $policy_detail}"
    }
    freebsd_version=$(sed -n 's/^freebsd-version=//p' "$work_actions")
    [ -n "$freebsd_version" ] || fail "FreeBSD CI version is not explicit"

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
