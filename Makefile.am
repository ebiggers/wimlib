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

libwim_la_LDFLAGS = -version-info 16:0:1 $(WINDOWS_LDFLAGS)

libwim_la_SOURCES =		\
	src/add_image.c		\
	src/avl_tree.c		\
	src/capture_common.c	\
	src/compress.c		\
	src/compress_common.c	\
	src/compress_parallel.c	\
	src/compress_serial.c	\
	src/decompress.c	\
	src/decompress_common.c	\
	src/delete_image.c	\
	src/dentry.c		\
	src/divsufsort.c	\
	src/encoding.c		\
	src/export_image.c	\
	src/extract.c		\
	src/file_io.c		\
	src/header.c		\
	src/inode.c		\
	src/inode_fixup.c	\
	src/integrity.c		\
	src/iterate_dir.c	\
	src/join.c		\
	src/lookup_table.c	\
	src/lz_binary_trees.c	\
	src/lz_brute_force.c	\
	src/lz_hash_chains.c	\
	src/lz_lcp_interval_tree.c	\
	src/lz_linked_suffix_array.c	\
	src/lz_mf.c		\
	src/lz_null.c		\
	src/lz_suffix_array_utils.c	\
	src/lzms-common.c	\
	src/lzms-compress.c	\
	src/lzms-decompress.c	\
	src/lzx-common.c	\
	src/lzx-compress.c	\
	src/lzx-decompress.c	\
	src/metadata_resource.c	\
	src/mount_image.c	\
	src/pathlist.c		\
	src/paths.c		\
	src/resource.c		\
	src/reference.c		\
	src/security.c		\
	src/sha1.c		\
	src/split.c		\
	src/reparse.c		\
	src/tagged_items.c	\
	src/template.c		\
	src/textfile.c		\
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
	include/wimlib/avl_tree.h	\
	include/wimlib/callback.h	\
	include/wimlib/capture.h	\
	include/wimlib/case.h		\
	include/wimlib/compiler.h	\
	include/wimlib/compressor_ops.h	\
	include/wimlib/compress_common.h	\
	include/wimlib/chunk_compressor.h	\
	include/wimlib/decompressor_ops.h	\
	include/wimlib/decompress_common.h	\
	include/wimlib/dentry.h		\
	include/wimlib/divsufsort.h	\
	include/wimlib/encoding.h	\
	include/wimlib/endianness.h	\
	include/wimlib/error.h		\
	include/wimlib/file_io.h	\
	include/wimlib/glob.h		\
	include/wimlib/header.h		\
	include/wimlib/inode.h		\
	include/wimlib/inode_table.h	\
	include/wimlib/integrity.h	\
	include/wimlib/list.h		\
	include/wimlib/lookup_table.h	\
	include/wimlib/lz_mf.h		\
	include/wimlib/lz_mf_ops.h	\
	include/wimlib/lz_suffix_array_utils.h	\
	include/wimlib/lzms.h		\
	include/wimlib/lzx.h		\
	include/wimlib/metadata.h	\
	include/wimlib/pathlist.h	\
	include/wimlib/paths.h		\
	include/wimlib/progress.h	\
	include/wimlib/reparse.h	\
	include/wimlib/resource.h	\
	include/wimlib/security.h	\
	include/wimlib/security_descriptor.h	\
	include/wimlib/sha1.h		\
	include/wimlib/textfile.h	\
	include/wimlib/timestamp.h	\
	include/wimlib/types.h		\
	include/wimlib/unix_data.h	\
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
		     src/wimboot.c			\
		     include/wimlib/win32_common.h	\
		     include/wimlib/win32.h		\
		     include/wimlib/wimboot.h		\
		     include/wimlib/wof.h
else
libwim_la_SOURCES += src/unix_apply.c		\
		     src/unix_capture.c
endif



EXTRA_libwim_la_SOURCES = src/sha1-ssse3.asm
libwim_la_DEPENDENCIES = $(SSSE3_SHA1_OBJ)

src/sha1-ssse3.lo:src/sha1-ssse3.asm
	$(LIBTOOL) --mode=compile --tag NASM $(srcdir)/build-aux/nasm_lt.sh \
	$(NASM) $(NAFLAGS) $(NASM_WINDOWS_FLAGS)			    \
	-DINTEL_SHA1_UPDATE_FUNCNAME=$(NASM_SYMBOL_PREFIX)sha1_transform_blocks_ssse3	    \
	-DINTEL_SHA1_UPDATE_DEFAULT_DISPATCH=$(NASM_SYMBOL_PREFIX)sha1_transform_blocks_default  \
	$< -o $@

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
	build-aux/nasm_lt.sh			\
	archlinux				\
	debian					\
	rpm					\
	examples				\
	COPYING					\
	COPYING.GPLv3				\
	COPYING.LGPLv3				\
	README					\
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
	doc/man1/@IMAGEX_PROGNAME@.1			\
	doc/man1/@IMAGEX_PROGNAME@-append.1		\
	doc/man1/@IMAGEX_PROGNAME@-apply.1		\
	doc/man1/@IMAGEX_PROGNAME@-capture.1		\
	doc/man1/@IMAGEX_PROGNAME@-delete.1		\
	doc/man1/@IMAGEX_PROGNAME@-dir.1		\
	doc/man1/@IMAGEX_PROGNAME@-export.1		\
	doc/man1/@IMAGEX_PROGNAME@-extract.1		\
	doc/man1/@IMAGEX_PROGNAME@-info.1		\
	doc/man1/@IMAGEX_PROGNAME@-join.1		\
	doc/man1/@IMAGEX_PROGNAME@-mount.1		\
	doc/man1/@IMAGEX_PROGNAME@-mountrw.1		\
	doc/man1/@IMAGEX_PROGNAME@-optimize.1	\
	doc/man1/@IMAGEX_PROGNAME@-split.1		\
	doc/man1/@IMAGEX_PROGNAME@-unmount.1		\
	doc/man1/@IMAGEX_PROGNAME@-update.1		\
	doc/man1/mkwinpeimg.1

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

