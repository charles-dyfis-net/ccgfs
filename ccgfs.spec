
Name:           ccgfs
Version:        0.68
Release:        0
Group:          Productivity/Networking
Summary:        Transport-agnostic network filesystem
License:        GPL
URL:            http://computergmbh.de/

Source:         %name-%version.tar.bz2
BuildRoot:      %_tmppath/%name-%version-build
BuildRequires:	libattr-devel, fuse-devel >= 2.6.5, libxml2-devel
BuildRequires:	openssl-devel, pkg-config, libHX >= 1.10

%description
ccgfs is a transport-agnostic filesystem. Common transport modes are
"pull" and "push", the latter of which makes it possible to export a
filesystem located in a LAN to a DMZ host without needing to allow
connections from the DMZ as would be the case with the pull model.
Any transport can be used, e.g. ssh for encryption.

Author:
-------
	Jan Engelhardt <jengelh [at] computergmbh de>

%debug_package
%prep
%setup

%build
./autogen.sh;
%configure
make %{?jobs:-j%jobs};

%install
b="%buildroot";
rm -Rf "$b";
make install DESTDIR="$b";

%clean
rm -Rf "%buildroot";

%files
%defattr(-,root,root)
%_sysconfdir/init.d/*
%_sbindir/*
%doc doc/*

%changelog -n ccgfs
