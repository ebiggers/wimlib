lib_LTLIBRARIES = libwim.la

AM_CFLAGS = -std=gnu99 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE \
	    	-fvisibility=hidden $(LIBXML2_CFLAGS) $(LIBFUSE_CFLAGS) \
		$(LIBCRYPTO_CFLAGS)
AM_CPPFLAGS = -D_GNU_SOURCE


compression_srcs = \
	comp.c \
	comp.h \
	decomp.c \
	decomp.h \
	huffman.c \
	huffman.h \
	lz.c \
	lzx.h  \
	lzx-common.c \
	lzx-comp.c \
	lzx-decomp.c \
	xpress.h \
	xpress-comp.c \
	xpress-decomp.c

other_srcs = \
	dentry.c \
	dentry.h \
	endianness.h \
	extract.c \
	header.c \
	integrity.c \
	io.h \
	join.c \
	lookup_table.c \
	lookup_table.h \
	modify.c \
	mount.c \
	resource.c \
	sha1.c \
	sha1.h \
	timestamp.h \
	util.c \
	util.h \
	wim.c  \
	wimlib.h \
	wimlib_internal.h \
	write.c \
	xml.c \
	xml.h


STRIP_FPIC = sh $(top_srcdir)/strip_fPIC.sh

sha1-ssse3.lo:sha1-ssse3.asm
	$(LIBTOOL) --mode=compile --tag=CC $(STRIP_FPIC) $(NASM) -f elf64 \
	-DINTEL_SHA1_UPDATE_DEFAULT_DISPATCH=ssse3_not_found  $<

EXTRA_libwim_la_SOURCES = sha1-ssse3.asm
EXTRA_libwim_la_DEPENDENCIES = $(SSSE3_SHA1_OBJ)

libwim_la_SOURCES = $(compression_srcs) $(other_srcs)
libwim_la_LIBADD = $(LIBXML2_LDADD) $(LIBFUSE_LDADD) $(LTLIBICONV) \
		   	$(LIBCRYPTO_LDADD) $(SSSE3_SHA1_OBJ)

EXTRA_DIST = security.c security.h

include_HEADERS = wimlib.h
