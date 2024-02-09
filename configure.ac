###############################################################################

AC_INIT([wimlib], m4_esyscmd_s([tools/get-version-number.sh]),
	[https://wimlib.net/forums/])
AC_CONFIG_SRCDIR([src/wim.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects foreign])
AM_SILENT_RULES([yes])
AC_C_BIGENDIAN
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT
PKG_PROG_PKG_CONFIG

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile] [doc/Doxyfile] [wimlib.pc])
AC_CONFIG_FILES([programs/mkwinpeimg], [chmod +x programs/mkwinpeimg])

PKGCONFIG_PRIVATE_REQUIRES=""
PKGCONFIG_PRIVATE_LIBS=""

###############################################################################
#			  General platform features			      #
###############################################################################

AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST

WINDOWS_NATIVE_BUILD="no"
PLATFORM_CPPFLAGS=""
PLATFORM_CFLAGS="-fvisibility=hidden"
PLATFORM_LDFLAGS=""

case "$host_os" in
mingw*)
	# Native Windows
	WINDOWS_NATIVE_BUILD="yes"
	# -D__MINGW_USE_VC2005_COMPAT: make time_t 64-bit on 32-bit Windows.
	PLATFORM_CPPFLAGS="-D_POSIX -D_POSIX_THREAD_SAFE_FUNCTIONS -DUNICODE -D_UNICODE -D_CRT_NON_CONFORMING_SWPRINTFS -D__MINGW_USE_VC2005_COMPAT -D_WIN32_WINNT=0x0600"
	PLATFORM_CFLAGS="-municode -mno-ms-bitfields"
	PLATFORM_LDFLAGS="-no-undefined"
	WITH_NTFS_3G_DEFAULT="no"
	WITH_FUSE_DEFAULT="no"
	;;
linux*)
	# Linux
	WITH_NTFS_3G_DEFAULT="yes"
	WITH_FUSE_DEFAULT="yes"
	;;
*)
	# Other UNIX
	WITH_NTFS_3G_DEFAULT="yes"
	WITH_FUSE_DEFAULT="no"
	;;
esac

AC_SUBST([PLATFORM_CPPFLAGS], [$PLATFORM_CPPFLAGS])
AC_SUBST([PLATFORM_CFLAGS], [$PLATFORM_CFLAGS])
AC_SUBST([PLATFORM_LDFLAGS], [$PLATFORM_LDFLAGS])
AM_CONDITIONAL([WINDOWS_NATIVE_BUILD], [test "$WINDOWS_NATIVE_BUILD" = "yes"])

# Useful functions which we can do without.
AC_CHECK_FUNCS([futimens utimensat flock mempcpy	\
		openat fstatat readlinkat fdopendir posix_fallocate \
		llistxattr lgetxattr fsetxattr lsetxattr getopt_long_only])

# Header checks, most of which are only here to satisfy conditional includes
# made by the libntfs-3g headers.
AC_CHECK_HEADERS([alloca.h		\
		  byteswap.h		\
		  endian.h		\
		  errno.h		\
		  glob.h		\
		  machine/endian.h	\
		  stdarg.h		\
		  stddef.h		\
		  stdlib.h		\
		  sys/byteorder.h	\
		  sys/endian.h		\
		  sys/file.h		\
		  sys/syscall.h		\
		  sys/sysctl.h		\
		  sys/times.h		\
		  sys/xattr.h		\
		  time.h		\
		  utime.h])

# Does stat() support nanosecond-precision timestamps?  (This is relevant on
# UNIX but not on Windows.)
AC_CHECK_MEMBER([struct stat.st_mtim],
		[AC_DEFINE([HAVE_STAT_NANOSECOND_PRECISION], [1],
			   [Define to 1 if stat() supports nanosecond precision
			    timestamps])],
		[],
		[#include <sys/stat.h>])

###############################################################################
#			     Required libraries				      #
###############################################################################

# ------------------------------ pthreads -------------------------------------
if test "$WINDOWS_NATIVE_BUILD" != "yes"; then
	AX_PTHREAD([], [AC_MSG_ERROR(["cannot find pthreads library"])])
fi

###############################################################################
#			  Configuration options				      #
###############################################################################

# ------------------------- ntfs-3g support -----------------------------------

AC_MSG_CHECKING([whether to include support for ntfs-3g])
AC_ARG_WITH([ntfs-3g],
	    [AS_HELP_STRING([--without-ntfs-3g],
			    [build without libntfs-3g.  This will disable the
			     ability to capture or apply a WIM image directly
			     from/to an unmounted NTFS volume.])],
	    [WITH_NTFS_3G=$withval],
	    [WITH_NTFS_3G=$WITH_NTFS_3G_DEFAULT])
AC_MSG_RESULT([$WITH_NTFS_3G])

if test "$WITH_NTFS_3G" = "yes"; then
	PKG_CHECK_MODULES([LIBNTFS_3G], [libntfs-3g >= 2011.4.12], [],
		[AC_MSG_ERROR([Cannot find libntfs-3g version 2011-4-12 or
		 later!  Without libntfs-3g, wimlib cannot include support for
		 capturing or applying a WIM image directly from/to an unmounted
		 NTFS volume while preserving NTFS-specific data such as
		 security descriptors and named data streams.  Either install
		 libntfs-3g, or configure --without-ntfs-3g to disable this
		 feature.  If your operating system packages development files
		 separately, the package you need to install may be called
		 ntfs-3g-dev, ntfs-3g-devel, or similar.])])
	PKGCONFIG_PRIVATE_REQUIRES="$PKGCONFIG_PRIVATE_REQUIRES libntfs-3g"
	AC_DEFINE([WITH_NTFS_3G], [1], [Define to 1 if using NTFS-3G support])
fi
AM_CONDITIONAL([WITH_NTFS_3G], [test "$WITH_NTFS_3G" = "yes"])

# ------------------------ FUSE mount support ---------------------------------

AC_MSG_CHECKING([whether to include support for mounting WIMs])
AC_ARG_WITH([fuse],
	    [AS_HELP_STRING([--without-fuse],
			    [build without libfuse3.  This will disable the
			     ability to mount WIM images.])],
	    [WITH_FUSE=$withval],
	    [WITH_FUSE=$WITH_FUSE_DEFAULT])
AC_MSG_RESULT([$WITH_FUSE])

if test "$WITH_FUSE" = "yes"; then

	PKG_CHECK_MODULES([LIBFUSE], [fuse3], [],
		[AC_MSG_ERROR([Cannot find libfuse3!
		Without libfuse3, wimlib cannot include support for mounting WIM
		images.  Either install libfuse3, or configure --without-fuse to
		disable this feature.  If your operating system packages
		development files separately, the package you need to install
		may be called libfuse3-dev, fuse-devel, or similar.])])
	PKGCONFIG_PRIVATE_REQUIRES="$PKGCONFIG_PRIVATE_REQUIRES fuse"
	AC_DEFINE([WITH_FUSE], [1], [Define to 1 if using FUSE support])

	AC_CHECK_LIB([rt], [mq_open], [],
		     [AC_MSG_ERROR([Cannot find librt (the POSIX.1b Realtime
	Extensions Library)!  wimlib needs this for the POSIX message queue
	functions, which are used in the code for mounting WIM images.  Recent
	versions of glibc include this library.  Either install this library, or
	configure --without-fuse to disable support for mounting WIM images.])])

	PKGCONFIG_PRIVATE_LIBS="$PKGCONFIG_PRIVATE_LIBS -lrt"
	AC_SUBST([LIBRT_LIBS], [-lrt])
fi
AM_CONDITIONAL([WITH_FUSE], [test "$WITH_FUSE" = "yes"])

# ----------------------------- Other options ---------------------------------

AC_ARG_WITH(pkgconfigdir,
            [  --with-pkgconfigdir=DIR      pkgconfig file in DIR @<:@LIBDIR/pkgconfig@:>@],
            [pkgconfigdir=$withval],
            [pkgconfigdir='${libdir}/pkgconfig'])
AC_SUBST(pkgconfigdir)

AC_MSG_CHECKING([whether to enable supporting code for tests])
AC_ARG_ENABLE([test-support],
	      [AS_HELP_STRING([--enable-test-support],
			      [Enable supporting code for tests (developers only)])],
	      [ENABLE_TEST_SUPPORT=$enableval],
	      [ENABLE_TEST_SUPPORT=no])
AC_MSG_RESULT([$ENABLE_TEST_SUPPORT])
if test "$ENABLE_TEST_SUPPORT" = "yes" ; then
	AC_DEFINE([ENABLE_TEST_SUPPORT], [1],
		  [Define to 1 to enable supporting code for tests])
fi
AM_CONDITIONAL([ENABLE_TEST_SUPPORT], [test "$ENABLE_TEST_SUPPORT" = "yes"])

###############################################################################

AC_SUBST([PKGCONFIG_PRIVATE_REQUIRES], [$PKGCONFIG_PRIVATE_REQUIRES])
AC_SUBST([PKGCONFIG_PRIVATE_LIBS], [$PKGCONFIG_PRIVATE_LIBS])
AC_OUTPUT
