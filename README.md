# gitswitch C
(noun) : SSDD for your SSDs' SDDM

## what is this?
this is another port. The original python version introduced some oddities with the ssh-agent. The C implementation avoids those oddities.

```
Usage: gitswitch [OPTIONS] [COMMAND] [ARGS]

Commands:
  add                  Add new account interactively
  list, ls             List all configured accounts
  remove <account>     Remove specified account
  status               Show current account status
  doctor, health       Run comprehensive health check
  config               Show configuration file information
  <account>            Switch to specified account

Options:
  --global, -g         Use global git scope
  --local, -l          Use local git scope (default)
  --dry-run, -n        Show what would be done without executing
  --verbose, -V        Enable verbose output
  --debug, -d          Enable debug logging
  --color, -c          Force color output
  --no-color, -C       Disable color output
  --help, -h           Show this help message
  --version, -v        Show version information

Examples:
  gitswitch add                    # Add new account interactively
  gitswitch list                   # List all accounts
  gitswitch 1                      # Switch to account ID 1
  gitswitch work                   # Switch to account matching 'work'
  gitswitch remove 2               # Remove account ID 2
  gitswitch doctor                 # Run health check
```
