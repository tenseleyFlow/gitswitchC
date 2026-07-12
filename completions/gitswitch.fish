# fish completion for gitswitch
#
# Completes subcommands, options, and the live account names reported by
# `gitswitch --names list`.

function __gitswitch_accounts
    # Silence errors so a broken config or missing binary yields no candidates
    # rather than noise.
    command gitswitch --names list 2>/dev/null
end

function __gitswitch_state --argument-names wanted
    # Inspect only complete tokens before the word being completed. All public
    # options are argument-free, so getopt-style permutation reduces to
    # skipping option tokens until the exact `--` delimiter is seen.
    set -l tokens (commandline -opc)
    set -e tokens[1]
    set -l options_enabled 1
    set -l seen_command ''
    set -l operand_count 0

    for token in $tokens
        if test $options_enabled -eq 1
            if test "$token" = --
                set options_enabled 0
                continue
            end
            switch $token
                case '-*'
                    # A lone '-' is a positional; every longer dash-prefixed
                    # token is an option before the delimiter.
                    if test "$token" != '-'
                        continue
                    end
            end
        end
        if test -z "$seen_command"
            set seen_command "$token"
        else
            set operand_count (math $operand_count + 1)
        end
    end

    switch $wanted
        case options
            test $options_enabled -eq 1
        case command
            test -z "$seen_command"
        case account
            if test -z "$seen_command"
                return 0
            end
            if contains -- "$seen_command" edit remove rm delete reset switch
                test $operand_count -eq 0
                return $status
            end
            return 1
        case shell
            test "$seen_command" = init; and test $operand_count -eq 0
        case '*'
            return 1
    end
end

# Account/command grammar owns every positional slot. Disable fish's fallback
# filename completion even when a completed operand leaves no candidates.
complete -c gitswitch -f

# Subcommands and bare account names in the first position.
complete -c gitswitch -f -n '__gitswitch_state command' -a add    -d 'Add new account interactively'
complete -c gitswitch -f -n '__gitswitch_state command' -a edit   -d 'Edit an existing account'
complete -c gitswitch -f -n '__gitswitch_state command' -a list   -d 'List all configured accounts'
complete -c gitswitch -f -n '__gitswitch_state command' -a ls     -d 'List all configured accounts'
complete -c gitswitch -f -n '__gitswitch_state command' -a remove -d 'Remove specified account'
complete -c gitswitch -f -n '__gitswitch_state command' -a rm     -d 'Remove specified account'
complete -c gitswitch -f -n '__gitswitch_state command' -a delete -d 'Remove specified account'
complete -c gitswitch -f -n '__gitswitch_state command' -a status -d 'Show current account status'
complete -c gitswitch -f -n '__gitswitch_state command' -a doctor -d 'Run comprehensive health check'
complete -c gitswitch -f -n '__gitswitch_state command' -a health -d 'Run comprehensive health check'
complete -c gitswitch -f -n '__gitswitch_state command' -a config -d 'Show configuration file information'
complete -c gitswitch -f -n '__gitswitch_state command' -a init   -d 'Emit shell integration'
complete -c gitswitch -f -n '__gitswitch_state command' -a resume -d 'Re-activate the last-used account'
complete -c gitswitch -f -n '__gitswitch_state command' -a reset  -d 'Kill agents and delete isolated state'
complete -c gitswitch -f -n '__gitswitch_state command' -a switch -d 'Switch to an account explicitly'

# Bare account names in the command position and exactly one account operand
# for edit/remove/reset/switch.
complete -c gitswitch -f -n '__gitswitch_state account' -a '(__gitswitch_accounts)' -d 'Account'

# Shells for `init`.
complete -c gitswitch -f -n '__gitswitch_state shell' -a 'fish bash zsh sh dash ksh' -d 'Shell'

# Options (available everywhere).
complete -c gitswitch -f -n '__gitswitch_state options' -l global   -s g -d 'Use global git scope'
complete -c gitswitch -f -n '__gitswitch_state options' -l local    -s l -d 'Use local git scope'
complete -c gitswitch -f -n '__gitswitch_state options' -l dry-run  -s n -d 'Show what would be done without executing'
complete -c gitswitch -f -n '__gitswitch_state options' -l yes      -s y -d 'Assume yes to confirmation prompts'
complete -c gitswitch -f -n '__gitswitch_state options' -l names    -d 'With list: print only account names'
complete -c gitswitch -f -n '__gitswitch_state options' -l verbose  -s V -d 'Enable verbose output'
complete -c gitswitch -f -n '__gitswitch_state options' -l debug    -s d -d 'Enable debug logging'
complete -c gitswitch -f -n '__gitswitch_state options' -l color    -s c -d 'Force color output'
complete -c gitswitch -f -n '__gitswitch_state options' -l no-color -s C -d 'Disable color output'
complete -c gitswitch -f -n '__gitswitch_state options' -l help     -s h -d 'Show help'
complete -c gitswitch -f -n '__gitswitch_state options' -l version  -s v -d 'Show version'
