Summary:   Library to extract, create, modify, and mount WIM files
Name:      wimlib
Version:   1.4.1
Release:   1
License:   GPLv3+
Group:     System/Libraries
URL:       http://sourceforge.net/projects/wimlib
Packager:  Eric Biggers <ebiggers3@gmail.com>
Source:    http://downloads.sourceforge.net/wimlib/wimlib-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Requires: libxml2, openssl
BuildRequires: libxml2-devel, openssl-devel
%description
wimlib is a C library for creating, extracting, modifying, and mounting files in
the Windows Imaging Format (WIM files).  It is similar to Microsoft's WIMGAPI
but is designed for both UNIX and Windows.

%package devel
Summary:  Development files for wimlib
Group:    Development/Libraries
Requires: %{name} = %{version}-%{release}
%description devel
Development files for wimlib

%package -n wimtools
Summary: Tools to create, extract, modify, and mount WIM files
Group:    Applications/System
Requires: %{name} = %{version}-%{release}
%description -n wimtools
Tools to create, extract, modify, and mount files in the Windows Imaging Format
(WIM files).  These files are normally created by using the `imagex.exe' utility
on Windows, but this package contains a free implementation of ImageX called
"wimlib-imagex" that is designed to work on both UNIX and Windows.

%prep
%setup -q -n %{name}-%{version}

%build
%configure --prefix=/usr		\
           --disable-rpath		\
	   --with-libcrypto		\
	   --without-ntfs-3g		\
	   --without-fuse		\
	   --disable-xattr
make %{?_smp_mflags}

%check
make check

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(-, root, root)
%doc AUTHORS COPYING README
%{_libdir}/libwim.so.*

%files -n wimtools
%defattr(-, root, root)
%{_bindir}/wimlib-imagex
%{_bindir}/mkwinpeimg
%doc %{_mandir}/man1/*.1.gz

%files devel
%defattr(-, root, root)
%{_libdir}/libwim.a
%{_libdir}/libwim.so
%exclude %{_libdir}/libwim.la
%{_includedir}/wimlib.h
%{_libdir}/pkgconfig/wimlib.pc
