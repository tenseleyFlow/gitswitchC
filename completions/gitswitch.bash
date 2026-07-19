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

# Encode a candidate relative to the quote context that remains open at the
# cursor. COMPREPLY is inserted as shell source, so returning a raw account
# name from inside quotes can still expand `$`, backticks, or `$()` and an
# apostrophe can terminate the command. Keep the representation byte-preserving
# and Bash 3.2-compatible; printf %q is locale-sensitive and may emit $'\ooo'.
_gitswitch_quote_candidate() {
    local value=$1 quote_context=${2-} quoted="" ch
    # Interactive Bash leaves `histchars` unset while still using `!` as its
    # default expansion character. This preserves an explicitly empty value,
    # which disables history expansion, while covering the unset default.
    local history_chars=${histchars-!} history_char
    history_char=${history_chars:0:1}
    while [[ -n $value ]]; do
        ch=${value%"${value#?}"}
        value=${value#?}
        case $quote_context in
        "\$'")
            # ANSI-C quotes make backslash and apostrophe syntactic. Account
            # names reject control bytes, so these two reversible escapes are
            # sufficient for every admitted candidate byte.
            if [[ -n $history_char && $ch == "$history_char" ]]; then
                # Bash 3.2 may history-expand inside ANSI-C quotes. Close the
                # quote, escape the active character unquoted, and reopen it.
                if [[ -n $value ]]; then
                    quoted+="'\\$ch\$'"
                else
                    quoted+="'\\$ch"
                    quoted+="''"
                fi
            else
                case $ch in
                "'"|\\)
                    if [[ -n $value ]]; then
                        quoted+="\\$ch"
                    else
                        # A final syntactic byte can make Readline mistake the
                        # escaped byte for its closing delimiter. Close the
                        # active context, emit the byte unquoted, then end in
                        # a closed empty quote that Readline can recognize.
                        quoted+="'\\$ch"
                        quoted+="''"
                    fi
                    ;;
                *) quoted+=$ch ;;
                esac
            fi
            ;;
        "'")
            if [[ $ch == "'" ]]; then
                # Close the active quote, insert one escaped apostrophe, and
                # reopen it so Readline can append the final closing quote.
                if [[ -n $value ]]; then
                    quoted+="'\\''"
                else
                    quoted+="'\\$ch"
                fi
            else
                quoted+=$ch
            fi
            ;;
        '"')
            if [[ -n $history_char && $ch == "$history_char" ]]; then
                # A backslash inside double quotes remains an argv byte for
                # the history character. Close the quote, escape it in the
                # unquoted context, and reopen the active double quote.
                if [[ -n $value ]]; then
                    quoted+="\"\\$ch\""
                else
                    quoted+="\"\\$ch"
                    quoted+='""'
                fi
            else
                case $ch in
                '$'|'`'|'"'|\\)
                    if [[ -n $value ]]; then
                        quoted+="\\$ch"
                    else
                        quoted+="\"\\$ch"
                        quoted+='""'
                    fi
                    ;;
                *)
                    quoted+=$ch
                    ;;
                esac
            fi
            ;;
        *)
            if [[ -n $history_char && $ch == "$history_char" ]]; then
                quoted+="\\$ch"
            else
                case $ch in
                ' '|"'"|'"'|\\|'('|')'|'['|']'|'{'|'}'|'*'|'?'|'!'|'$'|'`'|'&'|'|'|';'|'<'|'>'|'#'|'~')
                    quoted+="\\$ch"
                    ;;
                *)
                    quoted+=$ch
                    ;;
                esac
            fi
            ;;
        esac
    done
    _gitswitch_quote_result=$quoted
}

# Decode one ANSI-C escape without eval. The input starts immediately after
# the backslash. The bounded whitelist covers Bash's printable, control,
# octal, hexadecimal, and Unicode forms; control bytes cannot match admitted
# account names, while an unrepresentable NUL remains a nonmatching source
# fragment instead of collapsing to an empty prefix.
_gitswitch_decode_ansi_escape() {
    local value=$1 kind rest digits="" piece="" max=0 count=0 ch
    _gitswitch_ansi_result=""
    _gitswitch_ansi_consumed=0
    [[ -n $value ]] || return
    kind=${value%"${value#?}"}
    case $kind in
    "'"|'"'|'?'|\\)
        _gitswitch_ansi_result=$kind
        _gitswitch_ansi_consumed=1
        return
        ;;
    a|b|e|E|f|n|r|t|v)
        _gitswitch_ansi_consumed=1
        if ! printf -v piece '%b' "\\$kind" 2>/dev/null; then
            piece=""
        fi
        ;;
    x|u|U)
        case $kind in
        x) max=2 ;;
        u) max=4 ;;
        U) max=8 ;;
        esac
        rest=${value#?}
        while ((count < max)) && [[ -n $rest ]]; do
            ch=${rest%"${rest#?}"}
            case $ch in
            [0-9a-fA-F])
                digits+=$ch
                rest=${rest#?}
                ((count++))
                ;;
            *) break ;;
            esac
        done
        if [[ -z $digits ]]; then
            _gitswitch_ansi_result="\\$kind"
            _gitswitch_ansi_consumed=1
            return
        fi
        _gitswitch_ansi_consumed=$((1 + count))
        if ! printf -v piece '%b' "\\$kind$digits" 2>/dev/null; then
            piece=""
        fi
        ;;
    [0-7])
        rest=$value
        while ((count < 3)) && [[ -n $rest ]]; do
            ch=${rest%"${rest#?}"}
            case $ch in
            [0-7])
                digits+=$ch
                rest=${rest#?}
                ((count++))
                ;;
            *) break ;;
            esac
        done
        _gitswitch_ansi_consumed=$count
        if ! printf -v piece '%b' "\\0$digits" 2>/dev/null; then
            piece=""
        fi
        ;;
    *)
        _gitswitch_ansi_result="\\$kind"
        _gitswitch_ansi_consumed=1
        return
        ;;
    esac
    if [[ -n $piece ]]; then
        _gitswitch_ansi_result=$piece
    else
        _gitswitch_ansi_result="\\${value:0:_gitswitch_ansi_consumed}"
    fi
}

# Decode the shell representation supplied by Readline and remember the quote
# context (and decoded prefix before its opening delimiter) that is still
# active at the cursor. This also reverses our quote-splice encodings on a
# later TAB without evaluating any account-name bytes.
_gitswitch_decode_candidate() {
    local value=$1 decoded="" quote_context="" quote_prefix=""
    local wordbreak_prefix="" ch next i
    local _gitswitch_ansi_result _gitswitch_ansi_consumed
    while [[ -n $value ]]; do
        ch=${value%"${value#?}"}
        value=${value#?}
        case $quote_context in
        "")
            case $ch in
            \\)
                if [[ -n $value ]]; then
                    next=${value%"${value#?}"}
                    value=${value#?}
                    decoded+=$next
                fi
                ;;
            "'")
                quote_context="'"
                quote_prefix=$decoded
                ;;
            '"')
                quote_context='"'
                quote_prefix=$decoded
                ;;
            '$')
                if [[ -n $value ]]; then
                    next=${value%"${value#?}"}
                    case $next in
                    "'")
                        value=${value#?}
                        quote_context="\$'"
                        quote_prefix=$decoded
                        ;;
                    '"')
                        value=${value#?}
                        quote_context="\$\""
                        quote_prefix=$decoded
                        ;;
                    *)
                        decoded+=$ch
                        ;;
                    esac
                else
                    decoded+=$ch
                fi
                ;;
            *)
                decoded+=$ch
                if [[ ${COMP_WORDBREAKS-} == *"$ch"* ]]; then
                    case $ch in
                    :|=)
                        # Readline retains these delimiters and replaces the
                        # source that follows them.
                        wordbreak_prefix=$decoded
                        ;;
                    @)
                        # Readline removes '@' with the replaceable suffix.
                        wordbreak_prefix=${decoded%?}
                        ;;
                    esac
                fi
                ;;
            esac
            ;;
        "'")
            if [[ $ch == "'" ]]; then
                quote_context=""
                quote_prefix=""
            else
                decoded+=$ch
            fi
            ;;
        "\$'")
            case $ch in
            "'")
                quote_context=""
                quote_prefix=""
                ;;
            \\)
                _gitswitch_decode_ansi_escape "$value"
                for ((i = 0; i < _gitswitch_ansi_consumed; i++)); do
                    value=${value#?}
                done
                decoded+=$_gitswitch_ansi_result
                ;;
            *)
                decoded+=$ch
                ;;
            esac
            ;;
        '"'|"\$\"")
            case $ch in
            '"')
                quote_context=""
                quote_prefix=""
                ;;
            \\)
                if [[ -n $value ]]; then
                    next=${value%"${value#?}"}
                    case $next in
                    '$'|'`'|'"'|\\)
                        value=${value#?}
                        decoded+=$next
                        ;;
                    *)
                        decoded+=\\
                        ;;
                    esac
                fi
                ;;
            *)
                decoded+=$ch
                ;;
            esac
            ;;
        esac
    done
    _gitswitch_decode_result=$decoded
    _gitswitch_decode_quote=$quote_context
    _gitswitch_decode_retained=$quote_prefix
    _gitswitch_decode_wordbreak=$wordbreak_prefix
}

_gitswitch_named_fd_token() {
    local value=$1 inner
    # `{name}>file` variable-fd redirections were introduced in Bash 4.1. On
    # 3.2 the brace word remains a positional argv element.
    if ((BASH_VERSINFO[0] < 4 ||
         (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1))); then
        return 1
    fi
    case $value in
    \{*\}) ;;
    *) return 1 ;;
    esac
    inner=${value#\{}
    inner=${inner%\}}
    case $inner in
    ""|[0-9]*|*[!a-zA-Z0-9_]*) return 1 ;;
    *) return 0 ;;
    esac
}

# Classify an unquoted raw redirection token. The result is the source suffix
# attached to the operator; an empty suffix means the following word is its
# target. Numeric file descriptors cover Bash 3.2; named descriptors are also
# recognized when the completion runs under newer Bash.
_gitswitch_redirection_token() {
    local value=$1 ch fd_token
    # Process substitutions are ordinary argv words, not redirections. Check
    # them before stripping a possible numeric file-descriptor prefix.
    case $value in
    \<\(*|\>\(*) return 1 ;;
    esac
    case $value in
    \{*\}*)
        fd_token=${value%%\}*}
        fd_token+=\}
        if _gitswitch_named_fd_token "$fd_token"; then
            value=${value#"$fd_token"}
        fi
        ;;
    esac
    while [[ -n $value ]]; do
        ch=${value%"${value#?}"}
        case $ch in
        [0-9]) value=${value#?} ;;
        *) break ;;
        esac
    done
    # Bash also treats `2<(:)` / `2>(:)` as a literal numeric prefix joined to
    # a process-substitution word, rather than as an fd redirection.
    case $value in
    \<\(*|\>\(*) return 1 ;;
    esac
    case $value in
    '&>>'*) _gitswitch_redirection_suffix=${value#'&>>'} ;;
    '<<<'*) _gitswitch_redirection_suffix=${value#'<<<'} ;;
    '&>'*) _gitswitch_redirection_suffix=${value#'&>'} ;;
    '>>'*) _gitswitch_redirection_suffix=${value#'>>'} ;;
    '>|'*) _gitswitch_redirection_suffix=${value#'>|'} ;;
    '<>'*) _gitswitch_redirection_suffix=${value#'<>'} ;;
    '<<-'*) _gitswitch_redirection_suffix=${value#'<<-'} ;;
    '<<'*) _gitswitch_redirection_suffix=${value#'<<'} ;;
    '<&'*) _gitswitch_redirection_suffix=${value#'<&'} ;;
    '>&'*) _gitswitch_redirection_suffix=${value#'>&'} ;;
    '>'*) _gitswitch_redirection_suffix=${value#'>'} ;;
    '<'*) _gitswitch_redirection_suffix=${value#'<'} ;;
    *) return 1 ;;
    esac
    return 0
}

# Parse the command line up to the cursor when bash-completion is unavailable.
# COMP_WORDS splits at ':'/'=' and retains redirections before our function
# runs, which loses account prefixes and corrupts operand state. Preserve raw
# shell words for quote decoding, then remove redirection operators and their
# targets with the same observable command-state result as _init_completion.
_gitswitch_split_line() {
    local line=$1 token="" quote_context="" ch next raw i
    local _gitswitch_decode_result _gitswitch_decode_quote
    local _gitswitch_decode_retained _gitswitch_decode_wordbreak
    local _gitswitch_redirection_suffix
    local skip_target=0 token_redirect=0 last
    local -a raw_words=() parsed_words=()
    while [[ -n $line ]]; do
        ch=${line%"${line#?}"}
        line=${line#?}
        case $quote_context in
        "")
            case $ch in
            [[:space:]])
                if [[ -n $token ]]; then
                    raw_words+=("$token")
                    token=""
                    token_redirect=0
                fi
                ;;
            '<'|'>')
                # Redirection operators are shell-token boundaries even when
                # they touch the command or operand (`edit>/tmp/out`). Keep an
                # all-digit prefix as the operator's optional file descriptor;
                # every other prefix remains a normal command word.
                if ((!token_redirect)) && [[ -n $token ]]; then
                    case $token in
                    *[!0-9]*)
                        if ! _gitswitch_named_fd_token "$token"; then
                            raw_words+=("$token")
                            token=""
                        fi
                        ;;
                    esac
                fi
                token+=$ch
                token_redirect=1
                ;;
            '&')
                # `&>` and `&>>` redirect both stdout and stderr. A bare '&'
                # is outside this single-command completion grammar.
                if [[ -n $line && ${line%"${line#?}"} == '>' ]]; then
                    if [[ -n $token ]]; then
                        raw_words+=("$token")
                        token=""
                    fi
                    token=$ch
                    token_redirect=1
                else
                    token+=$ch
                fi
                ;;
            \\)
                token+=$ch
                if [[ -n $line ]]; then
                    next=${line%"${line#?}"}
                    line=${line#?}
                    token+=$next
                fi
                ;;
            "'")
                token+=$ch
                quote_context="'"
                ;;
            '"')
                token+=$ch
                quote_context='"'
                ;;
            '$')
                if [[ -n $line ]]; then
                    next=${line%"${line#?}"}
                    case $next in
                    "'")
                        line=${line#?}
                        token+="$ch$next"
                        quote_context="\$'"
                        ;;
                    '"')
                        line=${line#?}
                        token+="$ch$next"
                        quote_context="\$\""
                        ;;
                    *)
                        token+=$ch
                        ;;
                    esac
                else
                    token+=$ch
                fi
                ;;
            *)
                token+=$ch
                ;;
            esac
            ;;
        "'")
            token+=$ch
            [[ $ch == "'" ]] && quote_context=""
            ;;
        "\$'")
            token+=$ch
            if [[ $ch == "'" ]]; then
                quote_context=""
            elif [[ $ch == \\ && -n $line ]]; then
                next=${line%"${line#?}"}
                line=${line#?}
                token+=$next
            fi
            ;;
        '"'|"\$\"")
            token+=$ch
            if [[ $ch == '"' ]]; then
                quote_context=""
            elif [[ $ch == \\ && -n $line ]]; then
                next=${line%"${line#?}"}
                line=${line#?}
                token+=$next
            fi
            ;;
        esac
    done

    raw_words+=("$token")
    _gitswitch_line_cur=$token
    _gitswitch_line_redirect=0
    last=$((${#raw_words[@]} - 1))
    for ((i = 0; i <= last; i++)); do
        raw=${raw_words[i]}
        if ((skip_target)); then
            ((i == last)) && _gitswitch_line_redirect=1
            skip_target=0
            continue
        fi
        if _gitswitch_redirection_token "$raw"; then
            if ((i == last)); then
                _gitswitch_line_redirect=1
                _gitswitch_line_cur=$_gitswitch_redirection_suffix
            elif [[ -z $_gitswitch_redirection_suffix ]]; then
                skip_target=1
            fi
            continue
        fi
        _gitswitch_decode_candidate "$raw"
        parsed_words+=("$_gitswitch_decode_result")
        if ((i == last)); then
            _gitswitch_line_cur=$raw
        fi
    done
    if ((${#parsed_words[@]} == 0)); then
        parsed_words+=("")
        _gitswitch_line_cur=""
    fi
    _gitswitch_line_words=("${parsed_words[@]}")
    _gitswitch_line_cword=$((${#parsed_words[@]} - 1))
}

# Populate COMPREPLY with the live account names that prefix-match "$cur".
_gitswitch_complete_accounts() {
    local cur=$1 n prefix quote_context retained_prefix wordbreak_prefix
    local _gitswitch_quote_result _gitswitch_decode_result
    local _gitswitch_decode_quote _gitswitch_decode_retained
    local _gitswitch_decode_wordbreak
    local -a names=() account_replies=()
    # Read one name per line WITHOUT mapfile: mapfile is bash >= 4, but stock
    # macOS ships bash 3.2, where it fails with a visible error (AR-06 F37).
    while IFS= read -r n; do
        names+=("$n")
    done < <(command gitswitch --names list 2>/dev/null)

    _gitswitch_decode_candidate "$cur"
    prefix=$_gitswitch_decode_result
    quote_context=$_gitswitch_decode_quote
    retained_prefix=$_gitswitch_decode_retained
    wordbreak_prefix=$_gitswitch_decode_wordbreak
    # `$"..."` may translate its contents through gettext. Decline this quote
    # context instead of returning bytes whose executed argv could differ from
    # the stored candidate under an active message catalog.
    [[ $quote_context == "\$\"" ]] && return
    for n in "${names[@]}"; do
        if [[ -z $prefix || $n == "$prefix"* ]]; then
            account_replies+=("$n")
        fi
    done

    for n in "${account_replies[@]}"; do
        # Readline preserves text before the currently active opening quote.
        # Without one, it preserves a delimiter-specific prefix at the last
        # unquoted ':', '=', or '@' in COMP_WORDBREAKS. Trim exactly that fixed
        # source prefix before adding shell quoting; the legacy colon helper
        # cannot distinguish quotes and does not cover '='/'@'.
        if [[ -n $quote_context && -n $retained_prefix &&
              $n == "$retained_prefix"* ]]; then
            n=${n#"$retained_prefix"}
        elif [[ -z $quote_context && -n $wordbreak_prefix &&
                $n == "$wordbreak_prefix"* ]]; then
            n=${n#"$wordbreak_prefix"}
        fi
        _gitswitch_quote_candidate "$n" "$quote_context"
        COMPREPLY+=("$_gitswitch_quote_result")
    done
}

_gitswitch_complete_words() {
    local wordlist=$1 cur=$2 candidate prefix quote_context
    local retained_prefix wordbreak_prefix
    local _gitswitch_quote_result _gitswitch_decode_result
    local _gitswitch_decode_quote _gitswitch_decode_retained
    local _gitswitch_decode_wordbreak

    _gitswitch_decode_candidate "$cur"
    prefix=$_gitswitch_decode_result
    quote_context=$_gitswitch_decode_quote
    retained_prefix=$_gitswitch_decode_retained
    wordbreak_prefix=$_gitswitch_decode_wordbreak
    [[ $quote_context == "\$\"" ]] && return
    # `mapfile` is unavailable in Bash 3.2. Read compgen's one-candidate-per-
    # line output without command-substitution word splitting instead.
    while IFS= read -r candidate; do
        if [[ -n $quote_context && -n $retained_prefix &&
              $candidate == "$retained_prefix"* ]]; then
            candidate=${candidate#"$retained_prefix"}
        elif [[ -z $quote_context && -n $wordbreak_prefix &&
                $candidate == "$wordbreak_prefix"* ]]; then
            candidate=${candidate#"$wordbreak_prefix"}
        fi
        _gitswitch_quote_candidate "$candidate" "$quote_context"
        COMPREPLY+=("$_gitswitch_quote_result")
    done < <(compgen -W "$wordlist" -- "$prefix")
}

# Direct filename fallback for Bash 3.2, where `compopt` and the dynamic
# completion retry protocol do not exist. This still completes regular files
# and shell-quotes every candidate in the active context. Newer Bash uses the
# retry handler below to obtain native filename directory/nospace behavior.
_gitswitch_complete_redirect_files() {
    local cur=$1 candidate prefix quote_context retained_prefix
    local wordbreak_prefix tilde_prefix
    local _gitswitch_quote_result _gitswitch_decode_result
    local _gitswitch_decode_quote _gitswitch_decode_retained
    local _gitswitch_decode_wordbreak

    _gitswitch_decode_candidate "$cur"
    prefix=$_gitswitch_decode_result
    quote_context=$_gitswitch_decode_quote
    retained_prefix=$_gitswitch_decode_retained
    wordbreak_prefix=$_gitswitch_decode_wordbreak
    [[ $quote_context == "\$\"" ]] && return
    # Without native `-o filenames`, account-safe quoting would escape a
    # leading `~/` and turn HOME expansion into a literal tilde pathname.
    # Preserve only this unambiguous form; decline other leading-tilde forms
    # rather than silently changing their shell meaning on Bash 3.2.
    if [[ -z $quote_context && $prefix == \~* && $prefix != \~/* ]]; then
        return
    fi
    while IFS= read -r candidate; do
        tilde_prefix=""
        [[ -d $candidate ]] && candidate+=/
        if [[ -z $quote_context && $prefix == \~/* &&
              $candidate == \~/* ]]; then
            tilde_prefix=${candidate:0:2}
            candidate=${candidate:2}
        fi
        if [[ -n $quote_context && -n $retained_prefix &&
              $candidate == "$retained_prefix"* ]]; then
            candidate=${candidate#"$retained_prefix"}
        elif [[ -z $quote_context && -n $wordbreak_prefix &&
                $candidate == "$wordbreak_prefix"* ]]; then
            candidate=${candidate#"$wordbreak_prefix"}
        fi
        _gitswitch_quote_candidate "$candidate" "$quote_context"
        COMPREPLY+=("$tilde_prefix$_gitswitch_quote_result")
    done < <(compgen -f -- "$prefix")
}

# Bash >=4.1 retries programmable completion when a function changes its
# compspec and returns 124. Use that one-shot retry to apply `-o filenames`
# only to a redirect target; restore the account-safe base spec before doing
# any work so filename mode cannot leak into the next TAB.
_gitswitch_filename_retry() {
    local cur="${COMP_WORDS[COMP_CWORD]}" candidate prefix quote_context
    local retained_prefix wordbreak_prefix directory_replies=0
    local _gitswitch_line_cur _gitswitch_line_cword
    local _gitswitch_line_redirect=0
    local _gitswitch_quote_result
    local _gitswitch_decode_result _gitswitch_decode_quote
    local _gitswitch_decode_retained _gitswitch_decode_wordbreak
    local -a _gitswitch_line_words=()
    complete -F _gitswitch gitswitch
    COMPREPLY=()

    # A return-124 retry receives COMP_WORDS after Readline has split its
    # default word-break characters. Reparse the original line so filenames
    # containing ':', '=', or '@' keep the complete redirect-target prefix.
    if [[ -n ${COMP_LINE-} ]]; then
        _gitswitch_split_line "${COMP_LINE:0:COMP_POINT}"
        cur=$_gitswitch_line_cur
    fi
    _gitswitch_decode_candidate "$cur"
    prefix=$_gitswitch_decode_result
    quote_context=$_gitswitch_decode_quote
    retained_prefix=$_gitswitch_decode_retained
    wordbreak_prefix=$_gitswitch_decode_wordbreak
    [[ $quote_context == "\$\"" ]] && return
    while IFS= read -r candidate; do
        if [[ -d $candidate ]] ||
           [[ $candidate == \~/* && -d ${HOME-}${candidate:1} ]]; then
            candidate+=/
            ((directory_replies++))
        fi
        if [[ -n $quote_context && -n $retained_prefix &&
              $candidate == "$retained_prefix"* ]]; then
            candidate=${candidate#"$retained_prefix"}
        elif [[ -z $quote_context && -n $wordbreak_prefix &&
                $candidate == "$wordbreak_prefix"* ]]; then
            candidate=${candidate#"$wordbreak_prefix"}
        fi
        # Native filename mode quotes unquoted words, but inside an already
        # open quote it can leave expansion bytes active (for example `$X` in
        # double quotes). Encode against that live context before Readline
        # inserts the candidate; keep unquoted candidates raw so filename-mode
        # tilde and directory behavior remain native.
        if [[ -n $quote_context ]]; then
            _gitswitch_quote_candidate "$candidate" "$quote_context"
            candidate=$_gitswitch_quote_result
        fi
        COMPREPLY+=("$candidate")
    done < <(compgen -f -- "$prefix")
    if ((${#COMPREPLY[@]} == 1 && directory_replies == 1)); then
        # A word-break prefix may be absent from COMPREPLY, so filename mode
        # cannot stat the emitted suffix to infer that it is a directory.
        # The slash above carries that fact; suppress the otherwise-added
        # space so the next component can be completed.
        compopt -o nospace 2>/dev/null || :
    fi
}

_gitswitch() {
    # `_init_completion` populates `prev` as part of its standard caller
    # contract even though this completion does not need to inspect it.
    # shellcheck disable=SC2034
    local cur prev words cword current_value
    local _gitswitch_decode_result _gitswitch_decode_quote
    local _gitswitch_decode_retained _gitswitch_decode_wordbreak
    local _gitswitch_line_cur _gitswitch_line_cword parsed_line=0
    local _gitswitch_line_redirect=0
    local -a _gitswitch_line_words=()

    # Parse the original source before delegating to bash-completion. Its
    # `_init_completion` filename shortcut returns nonzero for redirects and
    # can insert expansion-active bytes inside an open quote. M35 owns only
    # that redirect path; all other handled cases (such as `$variable`) still
    # keep the stock return contract below.
    if [[ -n ${COMP_LINE-} ]]; then
        _gitswitch_split_line "${COMP_LINE:0:COMP_POINT}"
        parsed_line=1
    fi
    if ((_gitswitch_line_redirect)); then
        cur=$_gitswitch_line_cur
        words=("${_gitswitch_line_words[@]}")
        cword=$_gitswitch_line_cword
    elif declare -F _init_completion >/dev/null 2>&1; then
        # AR-10 L22: a nonzero return from an EXISTING _init_completion means
        # it already handled this completion (redirect target, $variable, …);
        # the old `|| fallback` misread that as "bash-completion absent" and
        # wiped the stock behavior with an empty COMPREPLY. AR-10 L23:
        # -n := keeps account names containing colons/equals as one word so
        # the operand scanner and prefix match see the real name.
        _init_completion -n := || return
    else
        if ((parsed_line)); then
            cur=$_gitswitch_line_cur
            words=("${_gitswitch_line_words[@]}")
            cword=$_gitswitch_line_cword
        else
            # Direct callers and older completion harnesses may provide only
            # Bash's standard COMP_WORDS/COMP_CWORD pair.
            cur="${COMP_WORDS[COMP_CWORD]}"
            words=("${COMP_WORDS[@]}")
            cword=$COMP_CWORD
        fi
    fi

    local subcommands="add edit list ls remove rm delete status doctor health config init resume reset switch"
    local options="--global --local --dry-run --yes --names --verbose --debug --color --no-color --help --version -g -l -n -y -V -d -c -C -h -v"

    COMPREPLY=()
    _gitswitch_decode_candidate "$cur"
    current_value=$_gitswitch_decode_result
    if ((_gitswitch_line_redirect)); then
        [[ $_gitswitch_decode_quote == "\$\"" ]] && return
        if [[ -n ${COMP_TYPE-} ]] &&
           ((BASH_VERSINFO[0] > 4 ||
             (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 1))) &&
           complete -o filenames -F _gitswitch_filename_retry gitswitch; then
            return 124
        fi
        _gitswitch_complete_redirect_files "$cur"
        return
    fi

    # Scan complete words with getopt_long's permutation rules. Every public
    # option is argument-free, so options can be skipped before or after both
    # the command and its operand. The exact `--` delimiter disables option
    # recognition; following dash-prefixed words are positional.
    local i token seen_cmd="" seen_cmd_set=0
    local operand_count=0 options_enabled=1
    for ((i = 1; i < cword; i++)); do
        token=${words[i]}
        _gitswitch_decode_candidate "$token"
        token=$_gitswitch_decode_result
        if ((options_enabled)); then
            if [[ $token == -- ]]; then
                options_enabled=0
                continue
            fi
            if [[ $token == -?* ]]; then
                continue
            fi
        fi
        if ((!seen_cmd_set)); then
            seen_cmd=$token
            seen_cmd_set=1
        else
            ((operand_count++))
        fi
    done

    # Options complete anywhere before `--`. These are fixed literals, so
    # compgen -W is safe (unlike the account-name path above).
    if ((options_enabled)) && [[ $current_value == -* ]]; then
        _gitswitch_complete_words "$options" "$cur"
        return
    fi

    # No positional command yet: accept a subcommand or the established bare
    # account switch form. Options may have appeared before this position.
    if ((!seen_cmd_set)); then
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
