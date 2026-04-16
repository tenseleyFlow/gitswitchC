Name:           gitswitcher
Version:        1.3.1
Release:        1%{?dist}
Summary:        Secure Git identity and SSH/GPG key management tool for seamless account switching

License:        GPL-3.0
URL:            https://github.com/tenseleyFlow/gitswitchC
Source0:        %{name}-%{version}.tar.gz

# BuildArch is not specified to allow building on all architectures including aarch64
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  openssl-devel

%global debug_package %{nil}
Requires:       git
Requires:       openssh-clients
Requires:       openssl

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
make BUILD_TYPE=release VERSION=%{version} COMMIT=rpm %{?_smp_mflags}

%install
# Install to buildroot
make install DESTDIR=%{buildroot}

# Install documentation
install -d %{buildroot}%{_docdir}/%{name}
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/

%files
/usr/local/bin/gitswitch
%{_docdir}/%{name}/README.md

%changelog
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