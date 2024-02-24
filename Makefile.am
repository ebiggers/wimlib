##############################################################################
#				General					     #
##############################################################################


ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS	= -I$(top_srcdir)/include $(PLATFORM_CPPFLAGS)	\
		  -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE

# Note: -std=gnu99 instead of -std=c99 is needed for unnamed structs and unions,
# which are in C11 but not C99.  But we can't yet actually use -std=c11 because
# we want to support older versions of gcc.
AM_CFLAGS	= -std=gnu99 $(PLATFORM_CFLAGS) -fno-common	\
		  -Wmissing-prototypes -Wstrict-prototypes	\
		  -Wundef -Wno-pointer-sign

AM_LDFLAGS	= $(PLATFORM_LDFLAGS)

EXTRA_DIST	= README.md README.WINDOWS.md NEWS.md		\
		  COPYING COPYING.GPLv3	COPYING.LGPLv3		\
		  examples					\
		  tools/get-version-number.sh tools/windows-build.sh

##############################################################################
#				Library					     #
##############################################################################

lib_LTLIBRARIES = libwim.la
include_HEADERS = include/wimlib.h

pkgconfigdir	= @pkgconfigdir@
pkgconfig_DATA	= wimlib.pc
wimlib.pc: config.status

libwim_la_SOURCES =		\
	src/add_image.c		\
	src/avl_tree.c		\
	src/blob_table.c	\
	src/compress.c		\
	src/compress_common.c	\
	src/compress_parallel.c	\
	src/compress_serial.c	\
	src/cpu_features.c	\
	src/decompress.c	\
	src/decompress_common.c	\
	src/delete_image.c	\
	src/dentry.c		\
	src/divsufsort.c	\
	src/encoding.c		\
	src/error.c		\
	src/export_image.c	\
	src/extract.c		\
	src/file_io.c		\
	src/header.c		\
	src/inode.c		\
	src/inode_fixup.c	\
	src/inode_table.c	\
	src/integrity.c		\
	src/iterate_dir.c	\
	src/join.c		\
	src/lcpit_matchfinder.c	\
	src/lzms_common.c	\
	src/lzms_compress.c	\
	src/lzms_decompress.c	\
	src/lzx_common.c	\
	src/lzx_compress.c	\
	src/lzx_decompress.c	\
	src/metadata_resource.c	\
	src/mount_image.c	\
	src/pathlist.c		\
	src/paths.c		\
	src/pattern.c		\
	src/progress.c		\
	src/reference.c		\
	src/registry.c		\
	src/reparse.c		\
	src/resource.c		\
	src/scan.c		\
	src/security.c		\
	src/sha1.c		\
	src/solid.c		\
	src/split.c		\
	src/tagged_items.c	\
	src/template.c		\
	src/textfile.c		\
	src/threads.c		\
	src/timestamp.c		\
	src/update_image.c	\
	src/util.c		\
	src/verify.c		\
	src/wim.c		\
	src/write.c		\
	src/xml.c		\
	src/xml_windows.c	\
	src/xmlproc.c		\
	src/xpress_compress.c	\
	src/xpress_decompress.c \
	include/wimlib/alloca.h		\
	include/wimlib/apply.h		\
	include/wimlib/assert.h		\
	include/wimlib/avl_tree.h	\
	include/wimlib/bitops.h		\
	include/wimlib/blob_table.h	\
	include/wimlib/bt_matchfinder.h	\
	include/wimlib/case.h		\
	include/wimlib/compiler.h	\
	include/wimlib/compressor_ops.h	\
	include/wimlib/compress_common.h	\
	include/wimlib/chunk_compressor.h	\
	include/wimlib/cpu_features.h	\
	include/wimlib/decompressor_ops.h	\
	include/wimlib/decompress_common.h	\
	include/wimlib/dentry.h		\
	include/wimlib/divsufsort.h	\
	include/wimlib/encoding.h	\
	include/wimlib/endianness.h	\
	include/wimlib/error.h		\
	include/wimlib/file_io.h	\
	include/wimlib/glob.h		\
	include/wimlib/guid.h		\
	include/wimlib/hc_matchfinder.h	\
	include/wimlib/header.h		\
	include/wimlib/inode.h		\
	include/wimlib/inode_table.h	\
	include/wimlib/integrity.h	\
	include/wimlib/lcpit_matchfinder.h	\
	include/wimlib/list.h		\
	include/wimlib/lzms_common.h	\
	include/wimlib/lzms_constants.h	\
	include/wimlib/lzx_common.h	\
	include/wimlib/lzx_constants.h	\
	include/wimlib/matchfinder_common.h	\
	include/wimlib/metadata.h	\
	include/wimlib/object_id.h	\
	include/wimlib/pathlist.h	\
	include/wimlib/paths.h		\
	include/wimlib/pattern.h	\
	include/wimlib/progress.h	\
	include/wimlib/registry.h	\
	include/wimlib/reparse.h	\
	include/wimlib/resource.h	\
	include/wimlib/scan.h		\
	include/wimlib/security.h	\
	include/wimlib/security_descriptor.h	\
	include/wimlib/sha1.h		\
	include/wimlib/solid.h		\
	include/wimlib/tagged_items.h	\
	include/wimlib/textfile.h	\
	include/wimlib/threads.h	\
	include/wimlib/timestamp.h	\
	include/wimlib/types.h		\
	include/wimlib/unaligned.h	\
	include/wimlib/unix_data.h	\
	include/wimlib/util.h		\
	include/wimlib/wim.h		\
	include/wimlib/write.h		\
	include/wimlib/xattr.h		\
	include/wimlib/xml.h		\
	include/wimlib/xml_windows.h	\
	include/wimlib/xmlproc.h	\
	include/wimlib/xpress_constants.h

if WITH_NTFS_3G
libwim_la_SOURCES += src/ntfs-3g_apply.c	\
		     src/ntfs-3g_capture.c	\
		     include/wimlib/ntfs_3g.h
endif

if WINDOWS_NATIVE_BUILD
libwim_la_SOURCES += src/wimboot.c			\
		     src/win32_common.c			\
		     src/win32_apply.c			\
		     src/win32_capture.c		\
		     src/win32_replacements.c		\
		     src/win32_vss.c			\
		     include/wimlib/wimboot.h		\
		     include/wimlib/win32.h		\
		     include/wimlib/win32_common.h	\
		     include/wimlib/win32_vss.h		\
		     include/wimlib/wof.h
PLATFORM_LIBS = -lntdll
else
libwim_la_SOURCES += src/unix_apply.c		\
		     src/unix_capture.c
PLATFORM_LIBS =
endif

if ENABLE_TEST_SUPPORT
libwim_la_SOURCES += src/test_support.c		\
		     include/wimlib/test_support.h
if !WINDOWS_NATIVE_BUILD
PLATFORM_LIBS += -lm
endif
endif

libwim_la_CFLAGS =		\
	-DBUILDING_WIMLIB	\
	$(AM_CFLAGS)		\
	$(PTHREAD_CFLAGS)	\
	$(LIBNTFS_3G_CFLAGS)	\
	$(LIBFUSE_CFLAGS)

libwim_la_LDFLAGS = $(AM_LDFLAGS) -version-info 41:0:26

libwim_la_LIBADD =		\
	$(PTHREAD_LIBS)		\
	$(LIBNTFS_3G_LIBS)	\
	$(LIBFUSE_LIBS)		\
	$(LIBRT_LIBS)		\
	$(PLATFORM_LIBS)

##############################################################################
#				Programs				     #
##############################################################################

bin_PROGRAMS = wimlib-imagex
dist_bin_SCRIPTS = programs/mkwinpeimg

wimlib_imagex_SOURCES =		\
	programs/imagex.c	\
	include/wimlib.h	\
	include/wimlib_tchar.h

if WINDOWS_NATIVE_BUILD
wimlib_imagex_SOURCES +=	\
	programs/imagex-win32.c	\
	programs/imagex-win32.h	\
	programs/wgetopt.c	\
	programs/wgetopt.h
endif

wimlib_imagex_CFLAGS = $(AM_CFLAGS) -Wno-deprecated-declarations

wimlib_imagex_LDADD = $(top_builddir)/libwim.la

wimlib_imagex_cmds =	\
	append		\
	apply		\
	capture		\
	delete		\
	dir		\
	export		\
	extract		\
	info		\
	join		\
	mount		\
	mountrw		\
	optimize	\
	split		\
	unmount		\
	update		\
	verify

##############################################################################
#				  Hooks					     #
##############################################################################

install-exec-hook:
	for cmd in $(wimlib_imagex_cmds); do				\
		cd $(DESTDIR)$(bindir) &&				\
			ln -f wimlib-imagex wim$${cmd};			\
	done

install-data-hook:
	for cmd in $(wimlib_imagex_cmds); do				\
		cd $(DESTDIR)$(mandir)/man1 &&				\
			ln -sf wim$${cmd}.1 wimlib-imagex-$${cmd}.1;	\
	done

uninstall-hook:
	for cmd in $(wimlib_imagex_cmds); do				\
		rm -f $(DESTDIR)$(bindir)/wim$${cmd};			\
		rm -f $(DESTDIR)$(mandir)/man1/wim$${cmd}.1;		\
	done

##############################################################################
#				Documentation				     #
##############################################################################

man1_MANS =				\
	doc/man1/wimlib-imagex.1	\
	doc/man1/wimappend.1		\
	doc/man1/wimapply.1		\
	doc/man1/wimcapture.1		\
	doc/man1/wimdelete.1		\
	doc/man1/wimdir.1		\
	doc/man1/wimexport.1		\
	doc/man1/wimextract.1		\
	doc/man1/wiminfo.1		\
	doc/man1/wimjoin.1		\
	doc/man1/wimmount.1		\
	doc/man1/wimmountrw.1		\
	doc/man1/wimoptimize.1		\
	doc/man1/wimsplit.1		\
	doc/man1/wimunmount.1		\
	doc/man1/wimupdate.1		\
	doc/man1/wimverify.1		\
	doc/man1/mkwinpeimg.1

EXTRA_DIST += $(man1_MANS)

##############################################################################
#				  Tests					     #
##############################################################################

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

EXTRA_DIST +=					\
	tests/common_tests.sh			\
	tests/exclusionlists			\
	tests/test_utils.sh			\
	tests/security_descriptor_1.base64	\
	tests/security_descriptor_1.bin		\
	tests/security_descriptor_2.base64	\
	tests/security_descriptor_2.bin		\
	tests/wims

if WINDOWS_NATIVE_BUILD
# Tests are run manually for Windows builds.
TESTS =
else
TESTS = $(dist_check_SCRIPTS)
endif

# Extra test programs (not run by 'make check')
EXTRA_PROGRAMS = tests/wlfuzz
tests_wlfuzz_SOURCES = tests/wlfuzz.c
tests_wlfuzz_LDADD = $(top_builddir)/libwim.la

##############################################################################
