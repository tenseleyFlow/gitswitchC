#compdef gitswitch
#
# zsh completion for gitswitch. Completes subcommands, options, and the live
# account names from `gitswitch list --names`.

_gitswitch() {
    local -a subcommands options accounts

    subcommands=(
        'add:Add new account interactively'
        'edit:Edit an existing account interactively'
        'list:List all configured accounts'
        'ls:List all configured accounts'
        'remove:Remove specified account'
        'rm:Remove specified account'
        'delete:Remove specified account'
        'status:Show current account status'
        'doctor:Run comprehensive health check'
        'health:Run comprehensive health check'
        'config:Show configuration file information'
        'init:Emit shell integration'
        'resume:Re-activate the last-used account'
        'reset:Kill agents and delete isolated GPG/SSH state'
    )

    options=(
        '--global[Use global git scope]'
        '--local[Use local git scope]'
        '--dry-run[Show what would be done without executing]'
        '--yes[Assume yes to confirmation prompts]'
        '--names[With list: print only account names]'
        '--verbose[Enable verbose output]'
        '--debug[Enable debug logging]'
        '--color[Force color output]'
        '--no-color[Disable color output]'
        '--help[Show help]'
        '--version[Show version]'
    )

    # Live account names; silence errors so a broken config yields no matches
    # rather than an error. Escape any ':' in a name: _describe reads each item
    # as 'value:description', so an unescaped colon truncated the name to the
    # text before it (AR-06 F38).
    accounts=("${(@)${(f)\"$(gitswitch list --names 2>/dev/null)\"}//:/\\:}")

    # Find the first non-option word AFTER the command name (mirrors the bash
    # loop). getopt_long parses options before the subcommand, so `gitswitch
    # --local <TAB>` puts words[2]='--local' and the old `words[2]` dispatch
    # offered only more options — never the subcommands/accounts this position
    # accepts (AR-06 F14). Scan for the effective subcommand instead.
    local seen_cmd="" i
    for (( i = 2; i < CURRENT; i++ )); do
        case "${words[i]}" in
            -*) ;;
            *) seen_cmd="${words[i]}"; break ;;
        esac
    done

    # The word being completed is itself an option: offer options.
    if [[ "${words[CURRENT]}" == -* ]]; then
        _values 'option' $options
        return
    fi

    # No subcommand yet (only options seen): this position takes a subcommand
    # or a bare account name to switch to.
    if [[ -z "$seen_cmd" ]]; then
        _describe -t commands 'gitswitch command' subcommands
        _describe -t accounts 'account' accounts
        _values 'option' $options
        return
    fi

    case "$seen_cmd" in
        edit|remove|rm|delete|reset)
            _describe -t accounts 'account' accounts
            ;;
        init)
            _values 'shell' fish bash zsh sh dash ksh
            ;;
        *)
            _values 'option' $options
            ;;
    esac
}

_gitswitch "$@"
