# fish completion for gitswitch
#
# Completes subcommands, options, and the live account names reported by
# `gitswitch list --names`.

function __gitswitch_accounts
    # Silence errors so a broken config or missing binary yields no candidates
    # rather than noise.
    gitswitch list --names 2>/dev/null
end

function __gitswitch_no_subcommand
    # True until a subcommand (or a bare account name) has been typed.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    for token in $cmd
        switch $token
            case '-*'
                continue
            case '*'
                return 1
        end
    end
    return 0
end

set -l subcommands add edit list ls remove rm delete status doctor health config init resume reset

# Subcommands and bare account names in the first position.
complete -c gitswitch -f -n __gitswitch_no_subcommand -a add    -d 'Add new account interactively'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a edit   -d 'Edit an existing account'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a list   -d 'List all configured accounts'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a ls     -d 'List all configured accounts'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a remove -d 'Remove specified account'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a rm     -d 'Remove specified account'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a delete -d 'Remove specified account'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a status -d 'Show current account status'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a doctor -d 'Run comprehensive health check'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a health -d 'Run comprehensive health check'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a config -d 'Show configuration file information'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a init   -d 'Emit shell integration'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a resume -d 'Re-activate the last-used account'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a reset  -d 'Kill agents and delete isolated state'
complete -c gitswitch -f -n __gitswitch_no_subcommand -a '(__gitswitch_accounts)' -d 'Switch to account'

# Account names as the argument to edit/remove/reset.
complete -c gitswitch -f -n '__fish_seen_subcommand_from edit remove rm delete reset' -a '(__gitswitch_accounts)' -d 'Account'

# Shells for `init`.
complete -c gitswitch -f -n '__fish_seen_subcommand_from init' -a 'fish bash zsh sh dash ksh' -d 'Shell'

# Options (available everywhere).
complete -c gitswitch -f -l global   -d 'Use global git scope'
complete -c gitswitch -f -l local    -d 'Use local git scope'
complete -c gitswitch -f -l dry-run  -s n -d 'Show what would be done without executing'
complete -c gitswitch -f -l yes      -s y -d 'Assume yes to confirmation prompts'
complete -c gitswitch -f -l names    -d 'With list: print only account names'
complete -c gitswitch -f -l verbose  -s V -d 'Enable verbose output'
complete -c gitswitch -f -l debug    -s d -d 'Enable debug logging'
complete -c gitswitch -f -l color    -s c -d 'Force color output'
complete -c gitswitch -f -l no-color -s C -d 'Disable color output'
complete -c gitswitch -f -l help     -s h -d 'Show help'
complete -c gitswitch -f -l version  -s v -d 'Show version'
