LDADD = $(top_builddir)/src/libwim.la
AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CFLAGS = -std=gnu99 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE

bin_PROGRAMS = imagex
dist_bin_SCRIPTS = mkwinpeimg

EXTRA_DIST = install.cmd
