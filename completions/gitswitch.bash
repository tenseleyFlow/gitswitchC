# bash completion for gitswitch
#
# Completes subcommands, options, and — for the switch/edit/remove positions —
# the live account names reported by `gitswitch list --names`.
#
# NOTE: account names may contain spaces, parentheses, and other shell
# metacharacters (see validate_name in the source). We therefore read them into
# an array one-per-line and prefix-match with [[ ]], and never feed them through
# `compgen -W`, which word-splits AND re-expands its wordlist — the latter would
# execute a name like `$(...)` on TAB and mangle any name containing a space.

# Populate COMPREPLY with the live account names that prefix-match "$cur",
# quoting each candidate so names with spaces complete as a single word.
_gitswitch_complete_accounts() {
    local cur=$1 n
    local -a names=()
    # Read one name per line WITHOUT mapfile: mapfile is bash >= 4, but stock
    # macOS ships bash 3.2, where it fails with a visible error (AR-06 F37).
    while IFS= read -r n; do
        names+=("$n")
    done < <(gitswitch list --names 2>/dev/null)
    # $cur carries readline's own backslash-escapes once a previous TAB has
    # completed a name containing spaces/metacharacters (our printf '%q' output
    # inserted them). Prefix-matching the raw, unescaped names against that
    # escaped $cur matched nothing on the SECOND TAB (AR-06 F13). Strip the
    # escapes for the comparison; the emitted candidate is still %q-quoted.
    local dq=${cur//\\/}
    for n in "${names[@]}"; do
        if [[ -z $dq || $n == "$dq"* ]]; then
            COMPREPLY+=("$(printf '%q' "$n")")
        fi
    done
}

_gitswitch() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    local subcommands="add edit list ls remove rm delete status doctor health config init resume reset"
    local options="--global --local --dry-run --yes --names --verbose --debug --color --no-color --help --version"

    COMPREPLY=()

    # Options complete anywhere. These are fixed literals, so compgen -W is safe.
    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "$options" -- "$cur"))
        return
    fi

    # Argument to the command in the previous position.
    case "$prev" in
        edit|remove|rm|delete|reset)
            _gitswitch_complete_accounts "$cur"
            return
            ;;
        init)
            COMPREPLY=($(compgen -W "fish bash zsh sh dash ksh" -- "$cur"))
            return
            ;;
    esac

    # First non-option word: a subcommand or a bare account name to switch to.
    local i seen_cmd=""
    for ((i = 1; i < cword; i++)); do
        case "${words[i]}" in
            -*) ;;
            *) seen_cmd="${words[i]}"; break ;;
        esac
    done

    if [[ -z $seen_cmd ]]; then
        # Subcommands (safe literals) plus live account names.
        COMPREPLY=($(compgen -W "$subcommands" -- "$cur"))
        _gitswitch_complete_accounts "$cur"
    fi
}

complete -F _gitswitch gitswitch
