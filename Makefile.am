ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS	= -I$(top_srcdir)/src

AM_CFLAGS	= -std=gnu99 -D_LARGEFILE_SOURCE \
		   -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE

lib_LTLIBRARIES = libwim.la

libwim_la_SOURCES =		\
	src/comp.c		\
	src/comp.h		\
	src/decomp.c		\
	src/decomp.h		\
	src/dentry.c		\
	src/dentry.h		\
	src/endianness.h	\
	src/extract.c		\
	src/hardlink.c		\
	src/header.c		\
	src/integrity.c		\
	src/io.h		\
	src/join.c		\
	src/list.h		\
	src/lookup_table.c	\
	src/lookup_table.h	\
	src/lz.c		\
	src/lzx-common.c	\
	src/lzx-comp.c		\
	src/lzx-decomp.c	\
	src/lzx.h		\
	src/modify.c		\
	src/mount.c		\
	src/ntfs-apply.c	\
	src/ntfs-capture.c	\
	src/resource.c		\
	src/security.c		\
	src/security.h		\
	src/sha1.c		\
	src/sha1.h		\
	src/split.c		\
	src/symlink.c		\
	src/timestamp.h		\
	src/util.c		\
	src/util.h		\
	src/wim.c		\
	src/wimlib.h		\
	src/wimlib_internal.h	\
	src/write.c		\
	src/xml.c		\
	src/xml.h		\
	src/xpress-comp.c	\
	src/xpress-decomp.c	\
	src/xpress.h

if WITH_NTFS_3G
if !WITH_NEW_NTFS_3G
libwim_la_SOURCES += src/ntfs-3g_security.c
endif
endif


EXTRA_libwim_la_SOURCES = src/sha1-ssse3.asm
libwim_la_DEPENDENCIES = $(SSSE3_SHA1_OBJ)
STRIP_FPIC = sh $(top_srcdir)/build-aux/strip_fPIC.sh

sha1-ssse3.lo:src/sha1-ssse3.asm
	$(LIBTOOL) --mode=compile --tag=CC $(STRIP_FPIC) $(NASM) -f elf64 \
	-DINTEL_SHA1_UPDATE_DEFAULT_DISPATCH=ssse3_not_found \
	$<

libwim_la_LIBADD =		\
	$(LIBXML2_LDADD)	\
	$(LIBFUSE_LDADD)	\
	$(LIBNTFS_3G_LDADD)	\
	$(LTLIBICONV)		\
	$(LIBCRYPTO_LDADD)	\
	$(SSSE3_SHA1_OBJ)

libwim_la_CFLAGS =		\
	$(AM_CFLAGS)		\
	-fvisibility=hidden	\
	$(LIBXML2_CFLAGS)	\
	$(LIBFUSE_CFLAGS)	\
	$(LIBNTFS_3G_CFLAGS)	\
	$(LIBCRYPTO_CFLAGS)


bin_PROGRAMS	 = imagex
imagex_SOURCES   = programs/imagex.c
imagex_LDADD	 = $(top_builddir)/libwim.la

dist_bin_SCRIPTS = programs/mkwinpeimg

include_HEADERS = src/wimlib.h

EXTRA_DIST =			\
	build-aux/strip_fPIC.sh	\
	debian			\
	programs/install.cmd

pkgconfigdir	= @pkgconfigdir@
pkgconfig_DATA	= wimlib.pc

$(pkgconfig_DATA): config.status

man1_MANS =			\
	doc/imagex.1		\
	doc/imagex-append.1	\
	doc/imagex-apply.1	\
	doc/imagex-capture.1	\
	doc/imagex-delete.1	\
	doc/imagex-dir.1	\
	doc/imagex-export.1	\
	doc/imagex-info.1	\
	doc/imagex-join.1	\
	doc/imagex-mount.1	\
	doc/imagex-mountrw.1	\
	doc/imagex-split.1	\
	doc/imagex-unmount.1	\
	doc/mkwinpeimg.1

$(man1_MANS): config.status

dist_check_SCRIPTS = tests/test-imagex tests/test-imagex-ntfs
TESTS = $(dist_check_SCRIPTS)

