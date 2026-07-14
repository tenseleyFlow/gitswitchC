Name:           gitswitcher
Version:        1.8.0
Release:        1%{?dist}
Summary:        Secure Git identity and SSH/GPG key management tool for seamless account switching

# AR-06 F40: 'GPL-3.0' is a deprecated SPDX identifier; the current form is
# GPL-3.0-or-later (the LICENSE ships the standard "version 3 or any later
# version" notice).
License:        GPL-3.0-or-later
URL:            https://github.com/tenseleyFlow/gitswitchC
Source0:        %{name}-%{version}.tar.gz

# BuildArch is not specified to allow building on all architectures including aarch64
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  readline-devel
# AR-10 L28: %check runs the C suite; several integration suites drive the
# real git binary inside sandboxed HOMEs.
BuildRequires:  git

%global debug_package %{nil}
Requires:       git
Requires:       openssh-clients
# GPG account activation imports/queries keys with gpg, while isolated-home
# reset invokes gpgconf. File requirements guarantee the exact executables the
# runtime resolves instead of assuming a distribution package name.
Requires:       /usr/bin/gpg
Requires:       /usr/bin/gpgconf

%description
gitswitcher is a secure Git identity and SSH/GPG key management tool that enables
seamless switching between multiple Git accounts with complete environment isolation.
Built for developers working with multiple identities, it provides robust security
hardening to prevent credential leakage between accounts.

This is a standalone tool, not related to the existing gitswitch package.

Features:
- Secure Git identity management
- Complete SSH key isolation per account  
- GPG environment separation and management
- Configuration validation and health checking
- Interactive account management interface
- Security-focused design with comprehensive hardening

%prep
%autosetup

%build
# Build release version with security hardening. Pass VERSION explicitly so
# the binary reports the RPM version even when .git isn't present in %{_builddir}.
make BUILD_TYPE=release READLINE=1 VERSION=%{version} COMMIT=rpm %{?_smp_mflags}

%install
# PREFIX=%{_prefix}: RPM content belongs under /usr, not the Makefile's
# /usr/local default — /usr/local is reserved for the sysadmin, rpmlint flags
# it, and completions installed there are inert (bash-completion only scans
# /usr/share/bash-completion/completions, and Fedora zsh's fpath omits
# /usr/local/share/zsh/site-functions) (AR-05 L6).
# BUILD_TYPE=release: install no longer rebuilds (AR-06 F01 decoupled install
# from the build, so it just packages the binary %build produced), but pass it
# explicitly so the stamp/binary contract is unambiguous and a clean chroot
# never repackages a debug/ASan binary.
make install BUILD_TYPE=release READLINE=1 DESTDIR=%{buildroot} PREFIX=%{_prefix}

%check
# AR-10 L28: the package ships from a tests-first repository yet the RPM never
# ran a single test in the build chroot, so an arch-specific miscompile could
# produce a green RPM. Run the C suite against the exact release objects
# %build produced (flags must match %build so the build-config stamp reuses
# them). Runtime-dependent suites (shells, gpg, ssh, ptys) skip gracefully
# when the chroot lacks those runtimes; the assertion suites always run.
make test BUILD_TYPE=release READLINE=1 VERSION=%{version} COMMIT=rpm

%files
%license LICENSE
# AR-06 F40: %doc owns the platform-canonical docdir tree it installs README
# into (commonly %{name} or %{name}-%{version}), so the containing directory is
# no longer unowned (the prior manual install + bare file listing left it out).
%doc README.md
%{_bindir}/gitswitch
%{_datadir}/bash-completion/completions/gitswitch
%{_datadir}/zsh/site-functions/_gitswitch
%{_datadir}/fish/vendor_completions.d/gitswitch.fish

%changelog
* Thu Jul 09 2026 mfw <espadonne@outlook.com> - 1.8.0-1
- Security/correctness: fixes from a full adversarial audit (46 findings), incl. a core.sshCommand injection, unescaped TOML writes that could brick the config, silent account loss on save, and SSH/GPG teardown and concurrency races.
- Feature: `gitswitch edit <account>` to edit an account interactively.
- Feature: bash/zsh/fish shell completions (backed by `gitswitch list --names`).
- Feature: `--yes` to skip confirmations, `--names` for scriptable listing, and GNU readline line-editing/TAB completion on the interactive prompts.
- Build: fix flock detection on macOS/FreeBSD.

* Thu Jul 09 2026 mfw <espadonne@outlook.com> - 1.7.3-1
- Fix: the shell integration no longer prints the "restoring your last account" notice on every new shell when no account has ever been switched; the notice now comes from `gitswitch resume` itself, only when there is a saved account to restore.

* Sat May 30 2026 mfw <espadonne@outlook.com> - 1.7.2-1
- Fix: isolated GPG homes now inherit your real ~/.gnupg/gpg-agent.conf, so a configured (e.g. GUI) pinentry is preserved instead of reverting to a detected default.
- Fix: tidy switch output (removed stray blank lines around the switch summary).

* Fri May 29 2026 mfw <espadonne@outlook.com> - 1.7.1-1
- Fix: build on glibc/Linux (incl. Arch/AUR) — nftw() needs _XOPEN_SOURCE; 1.7.0 failed to compile there. macOS/BSD were unaffected.
- CI: run the FreeBSD job's tests in release mode (ASan is incompatible with the VM's ASLR).

* Fri May 29 2026 mfw <espadonne@outlook.com> - 1.7.0-1
- SECURITY: fix an arbitrary command-execution vulnerability — a crafted ssh_key path in accounts.toml could inject a shell command via ssh-add. All external commands (git/ssh/gpg) now run via execvp with explicit argv, never a shell. Versions <= 1.6.0 are affected.
- Security: SSH host-alias config no longer disables host-key checking (StrictHostKeyChecking/UserKnownHostsFile), is written idempotently, and validates the alias.
- Security: isolated SSH/GPG dirs are verified (owner/mode/not-a-symlink) before use; symlinks updated atomically; umask 077 at startup.
- Safety: account resolution prefers exact id/name/email and rejects ambiguous matches; switches are validate-first with git-config snapshot/restore rollback (no half-applied identity); local->global never silent (prompt or --global).
- Feature: `gitswitch reset [account]` tears down isolated agents/homes (wiping on-disk key copies).
- Robustness: TOML parser errors on over-long input instead of truncating; assorted correctness fixes. Initial test suite + CI added.

* Fri May 29 2026 mfw <espadonne@outlook.com> - 1.6.0-1
- Feat: boot persistence — the last-active account is recorded and auto-resumed on the first interactive login after a reboot (via `gitswitch init`), restoring the SSH agent, git identity, and isolated GPG home. A heads-up line precedes the one-per-boot GPG PIN prompt.
- Feat: new `gitswitch resume` command to re-activate the last-active account manually.
- Fix: detect a dead SSH agent via `ssh-add -l` instead of a socket-file test, so resume reliably fires after a reboot even when a stale socket lingers (e.g. on macOS, which doesn't wipe /tmp).
- `gitswitch status` now reports the saved account after a reboot, before any resume has run.

* Fri May 29 2026 mfw <espadonne@outlook.com> - 1.5.0-1
- Feat: GPG isolation now persists into the shell — `gitswitch init` exports GNUPGHOME alongside SSH_AUTH_SOCK, backed by a stable per-account GNUPGHOME symlink retargeted on each switch.
- Fix: detect the pinentry program instead of hardcoding /usr/bin/pinentry-curses, which broke the signing self-test on FreeBSD and macOS.
- Fix: skip GPG secret-key re-import when the key is already in the isolated home, avoiding a PIN prompt on every switch.
- Fix: replace the interactive signing self-test with a non-interactive capability check (no PIN, no pinentry dependency).
- Change: isolated GPG homes now persist and are reused rather than deleted, so a shell pointed at the stable GNUPGHOME is never orphaned.

* Thu May 29 2026 mfw <espadonne@outlook.com> - 1.4.0-1
- Build: VERSION file is now the single source of truth for the binary version stamp.
- Build: drop the stale gitswitch.spec; gitswitcher.spec is the sole maintained spec.

* Thu Apr 16 2026 mfw <espadonne@outlook.com> - 1.3.1-1
- Fix: version string resolves to the tagged release when built from a source tarball (no .git) via new VERSION file fallback in the Makefile.
- Build: RPM spec now passes VERSION=%{version} explicitly.

* Thu Apr 16 2026 mfw <espadonne@outlook.com> - 1.3.0-1
- Feature: `gitswitch init <shell>` subcommand emits SSH_AUTH_SOCK wiring for fish/bash/zsh/sh/dash/ksh
- Feature: `--ssh-agent-info` compat alias auto-detects shell from $SHELL for Python-era rc files
- Fix: silence spurious "Failed to get terminal size" stderr when stdout is piped/command-substituted

* Tue Jan 07 2026 mfw <espadonne@outlook.com> - 1.1.9-1
- Fix: Use WARNING log level for release builds (was INFO)
- Fix: Silence error logs for missing optional config fields
- Fix: Improve SSH connection testing for git hosting services
- Feature: Persistent SSH agents with session state tracking
- Fix: Account detection from SSH socket symlinks
- Fix: Version stamping from git tags for tarball builds
- Multi-architecture support (aarch64, x86_64, etc.)

* Thu Sep 12 2024 mfw <espadonne@outlook.com> - 1.0.2-1
- Clean production build with zero compiler warnings
- Eliminated hundreds of variadic macro warnings from release builds
- Maintained pedantic warnings for development builds
- Production-ready build for AUR and RPM distribution

* Thu Sep 12 2024 mfw <espadonne@outlook.com> - 1.0.1-1
- Initial RPM release for gitswitcher
- Renamed from gitswitch to avoid confusion with existing unrelated package
- C implementation with security hardening
- Complete SSH and GPG isolation features
- Compiler warning fixes and production-ready build
