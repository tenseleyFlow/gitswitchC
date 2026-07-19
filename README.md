# gitswitch C
(noun) : SSDD for your SSDs' SDDM

## what is this?
this is another port. The original python version introduced some oddities with the ssh-agent. The C implementation avoids those oddities.

```
Usage: gitswitch [OPTIONS] [COMMAND] [ARGS]

Commands:
  add                  Add new account interactively
  edit <account>       Edit an existing account interactively
  list, ls             List all configured accounts
  remove, rm, delete <account>  Remove specified account
  status               Show current account status
  doctor, health       Run local configuration/key readiness checks
  config               Show configuration file information
  init <shell>         Emit shell integration (bash|zsh|fish|sh|dash|ksh)
  resume               Restore saved boot-volatile SSH/GPG state (never rewrites Git config)
  reset [account]      Kill agents and delete isolated GPG/SSH state (all, or one)
  switch <account>     Switch to specified account
  <account>            Switch to specified account

Options:
  --global, -g         Use global git scope
  --local, -l          Use local git scope (default)
  --dry-run, -n        Show what would be done without executing
  --yes, -y            Assume 'yes' to confirmation prompts (remove/reset)
  --names              With 'list': print only account names (one per line)
  --verbose, -V        Enable verbose output
  --debug, -d          Enable debug logging
  --color, -c          Force color output
  --no-color, -C       Disable color output
  --help, -h           Show this help message
  --version, -v        Show version information

Examples:
  gitswitch add                    # Add new account interactively
  gitswitch edit work              # Edit the 'work' account
  gitswitch list                   # List all accounts
  gitswitch list --names           # Print just account names (scripts/completion)
  gitswitch 1                      # Switch to account ID 1
  gitswitch switch work            # Explicitly switch to the 'work' account
  gitswitch work                   # Switch to account matching 'work'
  gitswitch remove 2 --yes         # Remove account ID 2 without confirmation
  gitswitch doctor                 # Check local configuration/key readiness
```

When built against GNU readline (auto-detected by the Makefile), terminal-to-
terminal `add`/`edit` prompts get line editing, and the SSH key path prompt gets
TAB filename completion. Redirected prompts and builds without readline use
bounded plain stdio input.

### command-line completion

`make install` ships bash, zsh, and fish completion scripts (also under
`completions/`). They complete subcommands, options, and — for the switch,
`edit`, `remove`, and `reset` positions — your live account names, sourced from
`gitswitch list --names`.

## shell integration

gitswitch maintains stable paths at fixed locations — an SSH agent socket and,
for accounts with GPG signing, a per-account `GNUPGHOME` — so your shell can
point `SSH_AUTH_SOCK` and `GNUPGHOME` at them once and have every `gitswitch
<account>` switch transparently. Add the matching block to your shell rc.

The supported init targets are exactly `bash`, `zsh`, `fish`, `sh`, `dash`,
and `ksh`. Each loader captures the generated program and checks the generator
status before evaluating it. A failed generator therefore returns nonzero and
neither empty nor partial output is installed. Completion scripts remain
available for bash, zsh, and fish only.

```bash
# ~/.bashrc
__gitswitch_load() {
    local __gitswitch_init_output
    __gitswitch_init_output="$(command gitswitch init bash)" || return "$?"
    eval "$__gitswitch_init_output"
}
__gitswitch_load
```

```zsh
# ~/.zshrc
__gitswitch_load() {
    local __gitswitch_init_output
    __gitswitch_init_output="$(command gitswitch init zsh)" || return "$?"
    eval "$__gitswitch_init_output"
}
__gitswitch_load
```

```fish
# ~/.config/fish/config.fish
function __gitswitch_load
    set -l __gitswitch_init_output (command gitswitch init fish)
    or return $status
    string join \n -- $__gitswitch_init_output | source
end
__gitswitch_load
```

```sh
# ~/.profile (sh, dash, or ksh)
__gitswitch_load() {
    __gitswitch_init_output="$(command gitswitch init sh)"
    set -- "$?" "$__gitswitch_init_output"
    unset __gitswitch_init_output
    [ "$1" -eq 0 ] || return "$1"
    eval "$2"
}
__gitswitch_load
```

The `sh` target emits the shared POSIX integration used by sh, dash, and ksh.
The loader functions are intentionally reusable when a shell rc file is
sourced again; their captured output is fresh and function-local (or cleared)
on every call.

The snippet guards optional paths, so an SSH or GPG runtime that is not
configured—or has never been created—is omitted without an error. A saved
account whose boot-volatile runtime disappeared after a reboot or runtime wipe
is different: the integration consults its bounded resume hint, runs
`gitswitch resume`, and then exports the restored paths.

### Persistence across reboots

gitswitch's live state (SSH agent, isolated GPG home) lives under
`$XDG_RUNTIME_DIR`, which is wiped on reboot. So on the **first login after a
boot** the integration auto-runs `gitswitch resume` to re-activate the account
you last switched to—reloading its SSH key and, when configured, rebuilding its
isolated GPG home. Resume restores only boot-volatile SSH/GPG state; it never
rewrites Git configuration.

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

> **Secret keys on disk:** isolating GPG works by exporting each account's
> secret key into a per-account `GNUPGHOME` under `$XDG_RUNTIME_DIR/gitswitch-gpg/`
> (or `/tmp/gitswitch-gpg-<uid>/`). These homes **persist** so switching back
> doesn't re-prompt for your PIN — meaning a copy of each account's private key
> stays in that directory (mode 0700). Run `gitswitch reset` to kill the agents
> and delete all isolated homes, or `gitswitch reset <account>` for one. They
> are also cleared when `$XDG_RUNTIME_DIR` is wiped at reboot. gitswitch
> refuses to place these homes on non-memory-backed storage unless you opt in
> with `GITSWITCH_ALLOW_TMP_GPG=1`; note that on that opt-in path deletion is a
> plain unlink, so the key bytes may remain recoverable from the disk until
> overwritten — true erasure is only guaranteed on tmpfs-backed storage.

> **Migrating from the Python gitswitch?** The old `gitswitch --ssh-agent-info`
> invocation still works as a compat alias that auto-detects your shell from
> `$SHELL`, but prefer the explicit `init <shell>` form in new rc files.
