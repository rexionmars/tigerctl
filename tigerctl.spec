%define name            tigerctl
%define version         1.0
%define release         1
%define buildroot       %{_tmppath}/%{name}-%{version}-root

Summary:        A CLI tool for fast password management
Name:           %{name}
Version:        %{version}
Release:        %{release}
License:        GPL-2.0 license
Group:          Applications/System
URL:            https://github.com/rexionmars/tigerctl
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %{buildroot}

%description
A CLI tool for fast password management

%prep
%setup -q

%build
# No build is needed for this example

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin
cp -a * %{buildroot}/usr/bin

%files
%defattr(-,root,root)
/usr/bin/tigerctl

%changelog
