Name:           gitswitch
Version:        1.1.4
Release:        1%{?dist}
Summary:        Safe Git identity switching with SSH/GPG isolation

License:        GPL-3.0
URL:            https://github.com/tenseleyFlow/gitswitch
Source0:        %{name}-%{version}.tar.gz

BuildArch:      x86_64

# Disable debug package
%global debug_package %{nil}

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  openssl-devel
Requires:       git
Requires:       openssh-clients
Requires:       openssl

%description
gitswitch is a C port of the original Python tool for safely switching between
Git identities with complete SSH and GPG isolation. It provides secure 
environment separation for developers working with multiple Git accounts,
ensuring credentials never leak between different identities.

Features:
- Safe Git identity switching
- SSH key isolation per account  
- GPG environment separation
- Configuration health checking
- Interactive account management
- Comprehensive security hardening

%prep
%autosetup

%build
# Build release version with security hardening
make BUILD_TYPE=release %{?_smp_mflags}

%install
# Install to buildroot
make install DESTDIR=%{buildroot}

# Install documentation
install -d %{buildroot}%{_docdir}/%{name}
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/

%files
%doc README.md
/usr/local/bin/gitswitch

%changelog
* Fri Dec 20 2024 mfw <espadonne@outlook.com> - 1.1.4-1
- Feat: persistent SSH agents with session state tracking
- Docs: add fish shell syntax to SSH integration tip

* Fri Dec 20 2024 mfw <espadonne@outlook.com> - 1.1.0-1
- Fix: use rotating buffers in display_colorize to prevent overwrite
- Fix: flush stdout after display_status to ensure output is shown

* Fri Dec 20 2024 mfw <espadonne@outlook.com> - 1.0.8-1
- Feat: improve account switch status messages

* Fri Dec 20 2024 mfw <espadonne@outlook.com> - 1.0.7-1
- Fix: improve SSH connection test for git hosting services

* Fri Dec 20 2024 mfw <espadonne@outlook.com> - 1.0.5-1
- Fix: remove stale ssh agent sockets before starting new agent

* Fri Dec 20 2024 mfw <espadonne@outlook.com> - 1.0.3-1
- Fix: use warn log level for release builds
- Fix: silence errors for missing optional config fields
- Fix: verify git config against correct scope and suppress ssh logging

* Sun Aug 24 2025 mfw <espadonne@outlook.com> - 1.0.0-1
- Initial RPM release
- C port with security hardening
- SSH and GPG isolation features