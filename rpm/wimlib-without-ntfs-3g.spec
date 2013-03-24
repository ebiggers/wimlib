Summary:   Library to extract, create, and modify WIM files
Name:      wimlib
Version:   1.3.2
Release:   1
License:   GPLv3+
Group:     System/Libraries
URL:       http://wimlib.sourceforge.net
Packager:  Eric Biggers <ebiggers3@gmail.com>
Source:    http://downloads.sourceforge.net/wimlib/wimlib-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Requires: libxml2, fuse-libs, fuse, openssl
BuildRequires: libxml2-devel, fuse-devel, openssl-devel, libattr-devel, fuse
%description
wimlib is a library that can be used to create, extract, and modify files in the
Windows Imaging Format. These files are normally created by the 'imagex.exe'
program on Windows, but this library provides a free implementation of 'imagex'
for UNIX-based systems. wimlib supports mounting WIM files, just like
imagex.exe.

%package devel
Summary:  Development files for wimlib
Group:    Development/Libraries
Requires: %{name} = %{version}-%{release}
%description devel
Development files for wimlib

%prep
%setup -q -n %{name}-%{version}

%build
%configure --prefix=/usr                 \
           --disable-rpath               \
	   --with-libcrypto              \
	   --without-ntfs-3g		 \
	   --enable-xattr                \
           --disable-verify-compression
%__make %{?_smp_mflags}

%check
make check

%install
%__rm -rf %{buildroot}
%__make DESTDIR=%{buildroot} install

%clean
%__rm -rf %{buildroot}

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(-, root, root)
%doc AUTHORS COPYING README TODO
%{_bindir}/imagex
%{_bindir}/mkwinpeimg
%{_libdir}/libwim.so*
%doc %{_mandir}/man1/*.1.gz

%files devel
%defattr(-, root, root)
%{_libdir}/libwim.a
%{_libdir}/libwim.la
%{_includedir}/wimlib.h
%{_libdir}/pkgconfig/wimlib.pc
