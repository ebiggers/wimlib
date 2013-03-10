ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS	= -I$(top_srcdir)/src

AM_CFLAGS	= -std=gnu99 -D_LARGEFILE_SOURCE \
		   -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE

lib_LTLIBRARIES = libwim.la

libwim_la_LDFLAGS = -version-info 4:0:2 $(CYGWIN_EXTRA_LDFLAGS)

libwim_la_SOURCES =		\
	src/add_image.c		\
	src/buffer_io.h		\
	src/compress.c		\
	src/compress.h		\
	src/decompress.c	\
	src/decompress.h	\
	src/delete_image.c	\
	src/dentry.c		\
	src/dentry.h		\
	src/encoding.c		\
	src/endianness.h	\
	src/export_image.c	\
	src/extract_image.c	\
	src/hardlink.c		\
	src/header.c		\
	src/integrity.c		\
	src/join.c		\
	src/list.h		\
	src/lookup_table.c	\
	src/lookup_table.h	\
	src/lz77.c		\
	src/lzx-common.c	\
	src/lzx-compress.c	\
	src/lzx-decompress.c	\
	src/lzx.h		\
	src/metadata_resource.c	\
	src/mount_image.c	\
	src/resource.c		\
	src/rbtree.c		\
	src/rbtree.h		\
	src/security.c		\
	src/security.h		\
	src/sha1.c		\
	src/sha1.h		\
	src/split.c		\
	src/symlink.c		\
	src/timestamp.h		\
	src/util.c		\
	src/util.h		\
	src/verify.c		\
	src/wim.c		\
	src/wimlib.h		\
	src/wimlib_internal.h	\
	src/win32.c		\
	src/write.c		\
	src/xml.c		\
	src/xml.h		\
	src/xpress-compress.c	\
	src/xpress-decompress.c	\
	src/xpress.h

if WITH_NTFS_3G
libwim_la_SOURCES += src/ntfs-apply.c	\
		     src/ntfs-capture.c
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
	$(SSSE3_SHA1_OBJ)	\
	$(PTHREAD_LDADD)

libwim_la_CFLAGS =		\
	$(AM_CFLAGS)		\
	$(VISIBILITY_CFLAGS)	\
	$(LIBXML2_CFLAGS)	\
	$(LIBFUSE_CFLAGS)	\
	$(LIBNTFS_3G_CFLAGS)	\
	$(LIBCRYPTO_CFLAGS)


bin_PROGRAMS	 = imagex
imagex_SOURCES   = programs/imagex.c
imagex_LDADD	 = $(top_builddir)/libwim.la

dist_bin_SCRIPTS = programs/mkwinpeimg

include_HEADERS = src/wimlib.h

EXTRA_DIST =					\
	build-aux/strip_fPIC.sh			\
	archlinux				\
	debian					\
	rpm					\
	README.WINDOWS				\
	programs/install.cmd			\
	programs/wimapply.c			\
	tests/common_tests.sh			\
	tests/tests-common.sh			\
	tests/security_descriptor_1.base64	\
	tests/security_descriptor_1.bin		\
	tests/security_descriptor_2.base64	\
	tests/security_descriptor_2.bin

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
	doc/imagex-optimize.1	\
	doc/imagex-split.1	\
	doc/imagex-unmount.1	\
	doc/mkwinpeimg.1

$(man1_MANS): config.status

check_PROGRAMS = tests/tree-cmp
tests_tree_cmp_SOURCES = tests/tree-cmp.c

dist_check_SCRIPTS = tests/test-imagex \
		     tests/test-imagex-capture_and_apply

if WITH_FUSE
dist_check_SCRIPTS += tests/test-imagex-mount
endif

if WITH_NTFS_3G
dist_check_SCRIPTS += tests/test-imagex-ntfs
endif

TESTS = $(dist_check_SCRIPTS)

