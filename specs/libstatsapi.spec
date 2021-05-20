# https://fedoraproject.org/wiki/PackagingDrafts/Go
Name:           LibStatsAPI
Version:        1.0.0
Release:        6%{?dist}
Summary:        LibStatsAPI
License:        ASL 2.0
URL:            https://gammabyte.xyz/

BuildRequires: gcc
BuildRequires: golang
BuildRequires: libvirt-devel
BuildRequires: libvirt
Source0: main.go

%description
LibStatsAPI is a Restful HTTP API for Libvirt

%prep
%setup -q -n LibStatsAPI-%{version}

%build
# set up temporary build gopath, and put our directory there
mkdir -p ./_build/src/lsapi
ln -s $(pwd) ./_build/src/lsapi

export GOPATH=$(pwd)/_build:%{gopath}
go build -o lsapi .

%install
install -d %{buildroot}%{_bindir}
install -p -m 0755 ./lsapi %{buildroot}%{_bindir}/lsapi

%files
%defattr(-,root,root,-)
%{_bindir}/lsapi

