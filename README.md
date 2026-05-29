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
  init <shell>         Emit shell integration (fish|bash|zsh|sh)
  resume               Re-activate the last-used account (used on login)
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

## shell integration

gitswitch maintains stable paths at fixed locations — an SSH agent socket and,
for accounts with GPG signing, a per-account `GNUPGHOME` — so your shell can
point `SSH_AUTH_SOCK` and `GNUPGHOME` at them once and have every `gitswitch
<account>` switch transparently. Add the matching line to your shell rc:

```fish
# ~/.config/fish/config.fish
gitswitch init fish | source
```

```bash
# ~/.bashrc
eval "$(gitswitch init bash)"
```

```zsh
# ~/.zshrc
eval "$(gitswitch init zsh)"
```

The snippet guards on each path's existence, so sourcing it before the first
switch (or after `/tmp` has been wiped) is a silent no-op rather than an error.

### Persistence across reboots

gitswitch's live state (SSH agent, isolated GPG home) lives under
`$XDG_RUNTIME_DIR`, which is wiped on reboot. So on the **first login after a
boot** the integration auto-runs `gitswitch resume` to re-activate the account
you last switched to — reloading its SSH key, reasserting your git identity, and
rebuilding its isolated GPG home.

> **That GPG PIN prompt at first login is gitswitch, not an error.** Rebuilding
> the isolated GPG keyring re-imports your secret key, which prompts your PIN
> once per boot. The integration prints a heads-up line right before it. This
> requires `GPG_TTY` to be set before the integration line, e.g. in fish:
> `set -x GPG_TTY (tty)`. You can also run `gitswitch resume` manually anytime.

> **GPG scoping:** when an account uses GPG signing, the snippet points
> `GNUPGHOME` at a per-account keyring containing only that account's key. That
> is the isolation — but it means *all* gpg in that shell is scoped to the
> active account (no other public keys, contacts, or ownertrust). For general
> gpg work, use a shell that doesn't source the integration.

> **Migrating from the Python gitswitch?** The old `gitswitch --ssh-agent-info`
> invocation still works as a compat alias that auto-detects your shell from
> `$SHELL`, but prefer the explicit `init <shell>` form in new rc files.

