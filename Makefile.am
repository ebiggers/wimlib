ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS	= -I$(top_srcdir)/include $(WINDOWS_CPPFLAGS) \
		  -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE

AM_CFLAGS	= -std=gnu99 -Wmissing-prototypes -Wstrict-prototypes	\
		  -Werror-implicit-function-declaration			\
		  -fno-common -Wundef -Wno-pointer-sign

if WINDOWS_NATIVE_BUILD
# This option is needed to make packed structures work as expected
# with gcc 4.7+ (mingw) on Windows.
AM_CFLAGS += -mno-ms-bitfields
endif

lib_LTLIBRARIES = libwim.la

libwim_la_LDFLAGS = -version-info 12:0:3 $(WINDOWS_LDFLAGS)

libwim_la_SOURCES =		\
	src/add_image.c		\
	src/capture_common.c	\
	src/compat.c		\
	src/compress.c		\
	src/compress_common.c	\
	src/compress_parallel.c	\
	src/compress_serial.c	\
	src/decompress.c	\
	src/decompress_common.c	\
	src/delete_image.c	\
	src/dentry.c		\
	src/encoding.c		\
	src/export_image.c	\
	src/extract.c		\
	src/file_io.c		\
	src/hardlink.c		\
	src/header.c		\
	src/integrity.c		\
	src/join.c		\
	src/lookup_table.c	\
	src/lzms-common.c	\
	src/lzms-compress.c	\
	src/lzms-decompress.c	\
	src/lz_hash.c		\
	src/lz_sarray.c		\
	src/divsufsort/divsufsort.c		\
	src/divsufsort/divsufsort.h		\
	src/divsufsort/divsufsort_private.h	\
	src/divsufsort/sssort.c	\
	src/divsufsort/trsort.c	\
	src/lzx-common.c	\
	src/lzx-compress.c	\
	src/lzx-decompress.c	\
	src/metadata_resource.c	\
	src/mount_image.c	\
	src/pathlist.c		\
	src/paths.c		\
	src/resource.c		\
	src/rbtree.c		\
	src/security.c		\
	src/sha1.c		\
	src/split.c		\
	src/reparse.c		\
	src/timestamp.c		\
	src/update_image.c	\
	src/util.c		\
	src/verify.c		\
	src/wildcard.c		\
	src/wim.c		\
	src/write.c		\
	src/xml.c		\
	src/xpress-compress.c	\
	src/xpress-decompress.c \
	include/wimlib/apply.h		\
	include/wimlib/assert.h		\
	include/wimlib/callback.h	\
	include/wimlib/capture.h	\
	include/wimlib/compiler.h	\
	include/wimlib/compressor_ops.h	\
	include/wimlib/compress_common.h	\
	include/wimlib/chunk_compressor.h	\
	include/wimlib/decompressor_ops.h	\
	include/wimlib/decompress_common.h	\
	include/wimlib/dentry.h		\
	include/wimlib/encoding.h	\
	include/wimlib/endianness.h	\
	include/wimlib/error.h		\
	include/wimlib/file_io.h	\
	include/wimlib/glob.h		\
	include/wimlib/header.h		\
	include/wimlib/integrity.h	\
	include/wimlib/list.h		\
	include/wimlib/lookup_table.h	\
	include/wimlib/lz.h		\
	include/wimlib/lz_hash.h	\
	include/wimlib/lz_optimal	\
	include/wimlib/lz_sarray.h	\
	include/wimlib/lzms.h		\
	include/wimlib/lzx.h		\
	include/wimlib/metadata.h	\
	include/wimlib/pathlist.h	\
	include/wimlib/paths.h		\
	include/wimlib/rbtree.h		\
	include/wimlib/reparse.h	\
	include/wimlib/resource.h	\
	include/wimlib/security.h	\
	include/wimlib/security_descriptor.h	\
	include/wimlib/sha1.h		\
	include/wimlib/timestamp.h	\
	include/wimlib/types.h		\
	include/wimlib/util.h		\
	include/wimlib/version.h	\
	include/wimlib/wildcard.h	\
	include/wimlib/wim.h		\
	include/wimlib/write.h		\
	include/wimlib/xml.h		\
	include/wimlib/xpress.h

if WITH_NTFS_3G
libwim_la_SOURCES += src/ntfs-3g_apply.c	\
		     src/ntfs-3g_capture.c	\
		     include/wimlib/ntfs_3g.h
endif

if WINDOWS_NATIVE_BUILD
libwim_la_SOURCES += src/win32_common.c			\
		     src/win32_apply.c			\
		     src/win32_capture.c		\
		     src/win32_replacements.c		\
		     include/wimlib/win32_common.h	\
		     include/wimlib/win32.h
else
libwim_la_SOURCES += src/unix_apply.c		\
		     src/unix_capture.c
endif



EXTRA_libwim_la_SOURCES = src/sha1-ssse3.asm
libwim_la_DEPENDENCIES = $(SSSE3_SHA1_OBJ)
STRIP_FPIC = sh $(top_srcdir)/build-aux/strip_fPIC.sh

sha1-ssse3.lo:src/sha1-ssse3.asm
	$(LIBTOOL) --mode=compile --tag=CC $(STRIP_FPIC) $(NASM) -f elf64 \
	-DINTEL_SHA1_UPDATE_DEFAULT_DISPATCH=ssse3_not_found \
	$<

libwim_la_LIBADD =		\
	$(LIBXML2_LIBS)		\
	$(LIBFUSE_LIBS)		\
	$(LIBRT_LIBS)		\
	$(LIBNTFS_3G_LIBS)	\
	$(LTLIBICONV)		\
	$(LIBCRYPTO_LIBS)	\
	$(SSSE3_SHA1_OBJ)	\
	$(PTHREAD_LDADD)	\
	$(WINDOWS_LDADD)

libwim_la_CFLAGS =		\
	$(AM_CFLAGS)		\
	$(VISIBILITY_CFLAGS)	\
	$(LIBXML2_CFLAGS)	\
	$(LIBFUSE_CFLAGS)	\
	$(LIBNTFS_3G_CFLAGS)	\
	$(LIBCRYPTO_CFLAGS)


bin_PROGRAMS	 = imagex
imagex_SOURCES   = programs/imagex.c	\
		   include/wimlib.h	\
		   include/wimlib_tchar.h
imagex_LDADD	 = $(top_builddir)/libwim.la
imagex_CFLAGS    = $(AM_CFLAGS) $(WINDOWS_CFLAGS) -Wno-deprecated-declarations

if WINDOWS_NATIVE_BUILD
imagex_SOURCES += programs/imagex-win32.c	\
		  programs/imagex-win32.h	\
		  programs/wgetopt.c		\
		  programs/wgetopt.h
endif

imagex_cmds =	append	\
		apply	\
		capture	\
		delete	\
		dir	\
		export	\
		extract	\
		info	\
		join	\
		mount	\
		mountrw	\
		optimize\
		split	\
		unmount	\
		update

install-exec-hook:
	if [ "@IMAGEX_PROGNAME@" != imagex ]; then			    \
		cd $(DESTDIR)$(bindir) && mv -f imagex "@IMAGEX_PROGNAME@"; \
	fi
	for cmd in $(imagex_cmds); do				\
		cd $(DESTDIR)$(bindir) &&			\
			ln -f "@IMAGEX_PROGNAME@" wim$${cmd};	\
	done

install-data-hook:
	for cmd in $(imagex_cmds); do					    \
		cd $(DESTDIR)$(mandir)/man1 &&				    \
			ln -sf "@IMAGEX_PROGNAME@-$${cmd}.1" wim$${cmd}.1;  \
	done

uninstall-hook:
	if [ "@IMAGEX_PROGNAME@" != imagex ]; then		\
		rm -f $(DESTDIR)$(bindir)/"@IMAGEX_PROGNAME@";	\
		rm -f $(DESTDIR)$(bindir)/imagex;		\
	fi
	for cmd in $(imagex_cmds); do				\
		rm -f $(DESTDIR)$(bindir)/wim$${cmd};		\
	done
	for cmd in $(imagex_cmds); do				\
		rm -f $(DESTDIR)$(mandir)/man1/wim$${cmd}.1; 	\
	done


dist_bin_SCRIPTS = programs/mkwinpeimg

include_HEADERS = include/wimlib.h

EXTRA_DIST =					\
	build-aux/strip_fPIC.sh			\
	archlinux				\
	debian					\
	rpm					\
	examples				\
	README.WINDOWS				\
	tests/common_tests.sh			\
	tests/tests-common.sh			\
	tests/security_descriptor_1.base64	\
	tests/security_descriptor_1.bin		\
	tests/security_descriptor_2.base64	\
	tests/security_descriptor_2.bin

pkgconfigdir	= @pkgconfigdir@
pkgconfig_DATA	= wimlib.pc

$(pkgconfig_DATA): config.status

wimlib_manpages =				\
	doc/@IMAGEX_PROGNAME@.1			\
	doc/@IMAGEX_PROGNAME@-append.1		\
	doc/@IMAGEX_PROGNAME@-apply.1		\
	doc/@IMAGEX_PROGNAME@-capture.1		\
	doc/@IMAGEX_PROGNAME@-delete.1		\
	doc/@IMAGEX_PROGNAME@-dir.1		\
	doc/@IMAGEX_PROGNAME@-export.1		\
	doc/@IMAGEX_PROGNAME@-extract.1		\
	doc/@IMAGEX_PROGNAME@-info.1		\
	doc/@IMAGEX_PROGNAME@-join.1		\
	doc/@IMAGEX_PROGNAME@-mount.1		\
	doc/@IMAGEX_PROGNAME@-mountrw.1		\
	doc/@IMAGEX_PROGNAME@-optimize.1	\
	doc/@IMAGEX_PROGNAME@-split.1		\
	doc/@IMAGEX_PROGNAME@-unmount.1		\
	doc/@IMAGEX_PROGNAME@-update.1		\
	doc/mkwinpeimg.1

man1_MANS = $(wimlib_manpages)
DISTCLEANFILES = $(wimlib_manpages)

$(man1_MANS): config.status

check_PROGRAMS = tests/tree-cmp
tests_tree_cmp_SOURCES = tests/tree-cmp.c

dist_check_SCRIPTS = tests/test-imagex \
		     tests/test-imagex-capture_and_apply \
		     tests/test-imagex-update_and_extract

if WITH_FUSE
dist_check_SCRIPTS += tests/test-imagex-mount
endif

if WITH_NTFS_3G
dist_check_SCRIPTS += tests/test-imagex-ntfs
endif

if WINDOWS_NATIVE_BUILD
# Tests are run manually for Windows builds.
TESTS =
else
TESTS = $(dist_check_SCRIPTS)
endif

