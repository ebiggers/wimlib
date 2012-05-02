SUBDIRS = src programs doc 
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = COPYING.LIB strip_fPIC.sh debian rpm archlinux

pkgconfigdir = @pkgconfigdir@
pkgconfig_DATA = wimlib.pc

$(pkgconfig_DATA): config.status
