#compdef gitswitch
#
# zsh completion for gitswitch. Completes subcommands, options, and the live
# account names from `gitswitch --names list`.

# Scan the complete words preceding CURRENT. Keeping this state machine in a
# small helper makes the getopt-style permutation contract independently
# testable without requiring an interactive ZLE instance.
_gitswitch_scan() {
    local -i limit=$1 i
    local token

    _gitswitch_seen_cmd=""
    _gitswitch_operand_count=0
    _gitswitch_options_enabled=1
    for (( i = 2; i < limit; i++ )); do
        token=${words[i]}
        if (( _gitswitch_options_enabled )); then
            if [[ $token == -- ]]; then
                _gitswitch_options_enabled=0
                continue
            fi
            if [[ $token == -?* ]]; then
                continue
            fi
        fi
        if [[ -z $_gitswitch_seen_cmd ]]; then
            _gitswitch_seen_cmd=$token
        else
            (( _gitswitch_operand_count++ ))
        fi
    done
}

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
        'doctor:Run local configuration/key readiness checks'
        'health:Run local configuration/key readiness checks'
        'config:Show configuration file information'
        'init:Emit shell integration'
        'resume:Re-activate the last-used account'
        'reset:Kill agents and delete isolated GPG/SSH state'
        'switch:Switch to an account explicitly'
    )

    options=(
        '--global[Use global git scope]'
        '-g[Use global git scope]'
        '--local[Use local git scope]'
        '-l[Use local git scope]'
        '--dry-run[Show what would be done without executing]'
        '-n[Show what would be done without executing]'
        '--yes[Assume yes to confirmation prompts]'
        '-y[Assume yes to confirmation prompts]'
        '--names[With list: print only account names]'
        '--verbose[Enable verbose output]'
        '-V[Enable verbose output]'
        '--debug[Enable debug logging]'
        '-d[Enable debug logging]'
        '--color[Force color output]'
        '-c[Force color output]'
        '--no-color[Disable color output]'
        '-C[Disable color output]'
        '--help[Show help]'
        '-h[Show help]'
        '--version[Show version]'
        '-v[Show version]'
    )

    # Live account names; silence errors so a broken config yields no matches
    # rather than an error. Escape any ':' in a name: _describe reads each item
    # as 'value:description', so an unescaped colon truncated the name to the
    # text before it (AR-06 F38).
    accounts=("${(@)${(f)$(command gitswitch --names list 2>/dev/null)}//:/\\:}")

    # Scan complete words with getopt_long's permutation rules. All public
    # options are argument-free and can occur before/after operands. The exact
    # `--` delimiter ends option recognition, so a following dash-prefixed word
    # is positional rather than silently skipped.
    local _gitswitch_seen_cmd=""
    local -i _gitswitch_operand_count=0 _gitswitch_options_enabled=1
    _gitswitch_scan $CURRENT
    local seen_cmd=$_gitswitch_seen_cmd
    local -i operand_count=$_gitswitch_operand_count
    local -i options_enabled=$_gitswitch_options_enabled

    # The word being completed is itself an option: offer options only before
    # the explicit delimiter.
    if (( options_enabled )) && [[ "${words[CURRENT]}" == -* ]]; then
        _values 'option' $options
        return
    fi

    # No subcommand yet (only options seen): this position takes a subcommand
    # or a bare account name to switch to.
    if [[ -z "$seen_cmd" ]]; then
        _describe -t commands 'gitswitch command' subcommands
        _describe -t accounts 'account' accounts
        if (( options_enabled )); then
            _values 'option' $options
        fi
        return
    fi

    if (( operand_count == 0 )); then
        case "$seen_cmd" in
        edit|remove|rm|delete|reset|switch)
            _describe -t accounts 'account' accounts
            ;;
        init)
            _values 'shell' fish bash zsh sh dash ksh
            ;;
        *)
            if (( options_enabled )); then
                _values 'option' $options
            fi
            ;;
        esac
    elif (( options_enabled )); then
        _values 'option' $options
    fi
}

_gitswitch "$@"
