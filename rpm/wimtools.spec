Name:      wimtools
Summary:   Tools to create, extract, modify, and mount WIM files
Version:   1.9.1
Release:   1
License:   GPLv3+
URL:       https://wimlib.net
Packager:  Eric Biggers <ebiggers3@gmail.com>
Source:    https://wimlib.net/downloads/wimlib-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root


Group:  Applications/System
Requires: libwim15
%description
Tools to extract, create, modify, and mount WIM (Windows Imaging) files.  WIM is
an archive format designed primarily for archiving Windows filesystems.  It
features single-instancing and LZ77-based compression and is used by Microsoft
to distribute and deploy Windows Vista and later.  WIM files are normally
created by using the `imagex.exe' utility on Windows, but this package contains
a free implementation of ImageX called "wimlib-imagex" that is designed to work
on both UNIX-like systems and Windows.

In addition to the usual extract/create/update support, wimlib-imagex allows you
to mount WIM images readonly or read-write, and it even allows you to extract or
create a WIM image directly to/from an unmounted NTFS volume.  This makes it
possible to, from Linux, back up or deploy a Windows OS directly to or from a
WIM file, such as the install.wim distributed on the Windows installation media.

This package also contains a script to make a customized Windows PE image based
on the capabilities provided by wimlib-imagex.

%package -n libwim15-devel
Summary:  Development files for wimlib
Group:  Development/Libraries
%description -n libwim15-devel
Development files for wimlib

%package -n libwim15
Summary:  Library to extract, create, modify, and mount WIM files
Group:  System Environment/Libraries
Requires:  fuse
BuildRequires: libxml2-devel, fuse, fuse-devel, openssl-devel, libattr-devel
BuildRequires: ntfs-3g-devel, ntfsprogs, libtool, pkgconfig
%description -n libwim15
wimlib is a C library for extracting, creating, modifying, and mounting WIM
(Windows Imaging) files.  WIM is an archive format designed primarily for
archiving Windows filesystems.  It features single-instancing and LZ77-based
compression, and is used by Microsoft to distribute and deploy Windows Vista and
later.  wimlib is an independent implementation of an API for handling WIM
files, available on both UNIX-like systems and Windows, that provides features
similar to Microsoft's WIMGAPI, as well as additional features such as support
for pipable WIM files and programatically making changes to WIM images without
mounting them.
%post -n libwim15 -p /sbin/ldconfig
%postun -n libwim15 -p /sbin/ldconfig

%prep
%setup -q -n wimlib-%{version}

%build
%configure --prefix=/usr		\
           --disable-rpath		\
	   --with-libcrypto		\
	   --with-ntfs-3g		\
	   --with-fuse
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%files
%defattr(-, root, root)
%{_bindir}/*
%doc %{_mandir}/man1/*.1.gz
%doc README COPYING COPYING.GPLv3

%files -n libwim15-devel
%defattr(-, root, root)
%{_libdir}/libwim.a
%{_libdir}/libwim.so
%exclude %{_libdir}/libwim.la
%{_includedir}/wimlib.h
%{_libdir}/pkgconfig/wimlib.pc

%files -n libwim15
%defattr(-, root, root)
%{_libdir}/libwim.so.*
%doc COPYING COPYING.GPLv3 COPYING.LGPLv3
