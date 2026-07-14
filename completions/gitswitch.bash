# bash completion for gitswitch
#
# Completes subcommands, options, and — for the switch/edit/remove positions —
# the live account names reported by `gitswitch --names list`.
#
# NOTE: account names may contain spaces, parentheses, and other shell
# metacharacters (see validate_name in the source). We therefore read them into
# an array one-per-line and prefix-match with [[ ]], and never feed them through
# `compgen -W`, which word-splits AND re-expands its wordlist — the latter would
# execute a name like `$(...)` on TAB and mangle any name containing a space.

# Backslash-quote only shell metacharacters, leaving every other byte intact.
# Bash's printf %q switches to $'\ooo' fragments for UTF-8 bytes in the C
# locale; on the next TAB those fragments become the prefix and no longer
# match the raw name. `complete -o filenames` would make Bash quote raw values,
# but also appends '/' when an account happens to name a local directory.
# This byte-preserving form works in Bash 3.2 and is exactly reversible below.
_gitswitch_quote_candidate() {
    local value=$1 quoted="" ch
    while [[ -n $value ]]; do
        ch=${value%"${value#?}"}
        value=${value#?}
        case $ch in
        ' '|"'"|'"'|\\|'('|')'|'['|']'|'{'|'}'|'*'|'?'|'!'|'$'|'`'|'&'|'|'|';'|'<'|'>'|'#'|'~')
            quoted+="\\$ch"
            ;;
        *)
            quoted+=$ch
            ;;
        esac
    done
    _gitswitch_quote_result=$quoted
}

_gitswitch_unquote_candidate() {
    local value=$1 unquoted="" ch escaped=0
    while [[ -n $value ]]; do
        ch=${value%"${value#?}"}
        value=${value#?}
        if ((escaped)); then
            unquoted+=$ch
            escaped=0
        elif [[ $ch == \\ ]]; then
            escaped=1
        else
            unquoted+=$ch
        fi
    done
    # Preserve a literal trailing backslash instead of silently deleting it.
    if ((escaped)); then
        unquoted+=\\
    fi
    _gitswitch_unquote_result=$unquoted
}

# Populate COMPREPLY with the live account names that prefix-match "$cur".
_gitswitch_complete_accounts() {
    local original_cur=$1 cur=$1 n quote="" prefix
    local _gitswitch_quote_result _gitswitch_unquote_result
    local -a names=()
    # Read one name per line WITHOUT mapfile: mapfile is bash >= 4, but stock
    # macOS ships bash 3.2, where it fails with a visible error (AR-06 F37).
    while IFS= read -r n; do
        names+=("$n")
    done < <(command gitswitch --names list 2>/dev/null)
    # AR-10 L24: a user-opened quote ('Jane, "Jane) arrives as part of $cur;
    # the backslash decoder alone left it in the match prefix, so quoted
    # partial names never matched. Strip it for matching and emit RAW names —
    # the still-open quote already protects metacharacters on the line.
    if [[ $cur == \'* || $cur == \"* ]]; then
        quote=${cur:0:1}
        cur=${cur:1}
    fi
    if [[ $quote == "'" ]]; then
        # Inside single quotes every byte is literal; do not decode pairs.
        prefix=$cur
    else
        # A previous TAB can feed our backslash-quoted common prefix back as
        # $cur. Decode pairs rather than deleting every backslash: `\\`
        # represents one literal backslash while `\ `, `\'`, etc. represent
        # shell metacharacters.
        _gitswitch_unquote_candidate "$cur"
        prefix=$_gitswitch_unquote_result
    fi
    for n in "${names[@]}"; do
        if [[ -z $prefix || $n == "$prefix"* ]]; then
            if [[ -n $quote ]]; then
                COMPREPLY+=("$n")
            else
                _gitswitch_quote_candidate "$n"
                COMPREPLY+=("$_gitswitch_quote_result")
            fi
        fi
    done
    # AR-10 L23: with COMP_WORDBREAKS splitting suppressed for `:`/`=` below,
    # readline still treats the text before a colon as a fixed prefix; trim it
    # from the candidates so the inserted text is not duplicated.
    if declare -F __ltrim_colon_completions >/dev/null 2>&1; then
        __ltrim_colon_completions "$original_cur"
    fi
}

_gitswitch_complete_words() {
    local wordlist=$1 cur=$2 candidate
    # `mapfile` is unavailable in Bash 3.2. Read compgen's one-candidate-per-
    # line output without command-substitution word splitting instead.
    while IFS= read -r candidate; do
        COMPREPLY+=("$candidate")
    done < <(compgen -W "$wordlist" -- "$cur")
}

_gitswitch() {
    # `_init_completion` populates `prev` as part of its standard caller
    # contract even though this completion does not need to inspect it.
    # shellcheck disable=SC2034
    local cur prev words cword
    if declare -F _init_completion >/dev/null 2>&1; then
        # AR-10 L22: a nonzero return from an EXISTING _init_completion means
        # it already handled this completion (redirect target, $variable, …);
        # the old `|| fallback` misread that as "bash-completion absent" and
        # wiped the stock behavior with an empty COMPREPLY. AR-10 L23:
        # -n := keeps account names containing colons/equals as one word so
        # the operand scanner and prefix match see the real name.
        _init_completion -n := || return
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local subcommands="add edit list ls remove rm delete status doctor health config init resume reset switch"
    local options="--global --local --dry-run --yes --names --verbose --debug --color --no-color --help --version -g -l -n -y -V -d -c -C -h -v"

    COMPREPLY=()

    # Scan complete words with getopt_long's permutation rules. Every public
    # option is argument-free, so options can be skipped before or after both
    # the command and its operand. The exact `--` delimiter disables option
    # recognition; following dash-prefixed words are positional.
    local i token seen_cmd="" operand_count=0 options_enabled=1
    for ((i = 1; i < cword; i++)); do
        token=${words[i]}
        if ((options_enabled)); then
            if [[ $token == -- ]]; then
                options_enabled=0
                continue
            fi
            if [[ $token == -?* ]]; then
                continue
            fi
        fi
        if [[ -z $seen_cmd ]]; then
            seen_cmd=$token
        else
            ((operand_count++))
        fi
    done

    # Options complete anywhere before `--`. These are fixed literals, so
    # compgen -W is safe (unlike the account-name path above).
    if ((options_enabled)) && [[ $cur == -* ]]; then
        _gitswitch_complete_words "$options" "$cur"
        return
    fi

    # No positional command yet: accept a subcommand or the established bare
    # account switch form. Options may have appeared before this position.
    if [[ -z $seen_cmd ]]; then
        _gitswitch_complete_words "$subcommands" "$cur"
        _gitswitch_complete_accounts "$cur"
        return
    fi

    # Complete exactly one operand. An intervening option does not consume the
    # slot, while an already completed operand suppresses duplicate accounts.
    if ((operand_count == 0)); then
        case "$seen_cmd" in
        edit|remove|rm|delete|reset|switch)
            _gitswitch_complete_accounts "$cur"
            return
            ;;
        init)
            _gitswitch_complete_words "fish bash zsh sh dash ksh" "$cur"
            return
            ;;
        esac
    fi
}

complete -F _gitswitch gitswitch
