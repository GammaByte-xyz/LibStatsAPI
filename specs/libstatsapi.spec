Name:       LibStatsAPI 
Version:    1
Release:    1
Summary:    Restful Libvirt API
URL:        https://gammabyte.xyz/
BuildRequires:  gcc
BuildRequires:  golang >= 1.15
BuildRequires:  libvirt-devel
BuildRequires:  libvirt
BuildRequires:  go

%description
Restful Libvirt API

%prep
# we have no source, so nothing here

%build
mkdir ../build
go build ../
mv libstatsapi ../build/

%install
cp ../build/libstatsapi /usr/bin/lsapi
bash setup

