Name:           gitswitch
Version:        1.0.0
Release:        1%{?dist}
Summary:        Safe Git identity switching with SSH/GPG isolation

License:        GPL-3.0
URL:            https://github.com/tenseleyFlow/gitswitch
Source0:        %{name}-%{version}.tar.gz

BuildArch:      x86_64
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
%{_docdir}/%{name}/

%changelog
* Sun Aug 24 2025 mfw <espadonne@outlook.com> - 1.0.0-1
- Initial RPM release
- C port with security hardening
- SSH and GPG isolation features