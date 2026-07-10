# bash completion for gitswitch
#
# Completes subcommands, options, and — for the switch/edit/remove positions —
# the live account names reported by `gitswitch list --names`.

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

    # `gitswitch list --names` is the machine-readable account list. Suppress
    # errors so completion degrades to nothing rather than spewing on a broken
    # config or missing binary.
    local accounts
    accounts=$(gitswitch list --names 2>/dev/null)

    # Options complete anywhere.
    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "$options" -- "$cur"))
        return
    fi

    # Argument to the command in the previous position.
    case "$prev" in
        edit|remove|rm|delete)
            COMPREPLY=($(compgen -W "$accounts" -- "$cur"))
            return
            ;;
        init)
            COMPREPLY=($(compgen -W "fish bash zsh sh dash ksh" -- "$cur"))
            return
            ;;
        reset)
            COMPREPLY=($(compgen -W "$accounts" -- "$cur"))
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
        COMPREPLY=($(compgen -W "$subcommands $accounts" -- "$cur"))
    fi
}

complete -F _gitswitch gitswitch
