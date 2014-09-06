AC_INIT([wimlib], [1.7.2-BETA], [ebiggers3@gmail.com])
AC_CONFIG_SRCDIR([src/wim.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects foreign])
AC_C_BIGENDIAN
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT

PKGCONFIG_PRIVATE_REQUIRES=""
PKGCONFIG_PRIVATE_LIBS=""

AC_ARG_WITH(imagex-progname,
            [AS_HELP_STRING([--with-imagex-progname=NAME],
			    [Set the name of installed ImageX program (default: wimlib-imagex)])],
            [IMAGEX_PROGNAME=$withval],
            [IMAGEX_PROGNAME="wimlib-imagex"])

AC_SUBST([IMAGEX_PROGNAME], [$IMAGEX_PROGNAME])
AC_DEFINE_UNQUOTED([IMAGEX_PROGNAME], ["$IMAGEX_PROGNAME"],
		   [Binary name for the implementation of ImageX distributed with wimlib])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile]
		[doc/Doxyfile]
		[wimlib.pc]
		[doc/man1/"$IMAGEX_PROGNAME".1:doc/man1/imagex.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-append.1:doc/man1/imagex-append.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-apply.1:doc/man1/imagex-apply.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-capture.1:doc/man1/imagex-capture.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-delete.1:doc/man1/imagex-delete.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-dir.1:doc/man1/imagex-dir.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-export.1:doc/man1/imagex-export.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-extract.1:doc/man1/imagex-extract.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-info.1:doc/man1/imagex-info.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-join.1:doc/man1/imagex-join.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-mount.1:doc/man1/imagex-mount.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-mountrw.1:doc/man1/imagex-mountrw.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-optimize.1:doc/man1/imagex-optimize.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-split.1:doc/man1/imagex-split.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-unmount.1:doc/man1/imagex-unmount.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-update.1:doc/man1/imagex-update.1.in]
		[doc/man1/"$IMAGEX_PROGNAME"-verify.1:doc/man1/imagex-verify.1.in]
		[doc/man1/mkwinpeimg.1])

AC_CONFIG_FILES([programs/mkwinpeimg], [chmod +x programs/mkwinpeimg])

AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST

AC_CHECK_FUNCS([futimens utimensat utime flock mempcpy	\
		openat fstatat readlinkat fdopendir])

# Note: some of the following header checks are only to define the appropriate
# HAVE_*_H macro so that the NTFS-3g headers don't get confused and try to skip
# including certain headers.
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
		  sys/param.h		\
		  sys/sysctl.h		\
		  sys/times.h		\
		  time.h		\
		  utime.h])

AC_CHECK_MEMBER([struct stat.st_mtim],
		[AC_DEFINE([HAVE_STAT_NANOSECOND_PRECISION], [1],
			  [Define to 1 if nanosecond precision timestamps are
			   supported])],
		[],
		[[#include <sys/stat.h>]])


AC_ARG_WITH(pkgconfigdir,
            [  --with-pkgconfigdir=DIR      pkgconfig file in DIR @<:@LIBDIR/pkgconfig@:>@],
            [pkgconfigdir=$withval],
            [pkgconfigdir='${libdir}/pkgconfig'])
AC_SUBST(pkgconfigdir)

AC_CHECK_LIB([xml2], [xmlParseFile], [have_libxml=true],
	     [AC_MSG_ERROR(["cannot find libxml2"])])
PKG_CHECK_MODULES([LIBXML2], [libxml-2.0])
PKGCONFIG_PRIVATE_REQUIRES="$PKGCONFIG_PRIVATE_REQUIRES libxml-2.0"

AC_MSG_CHECKING([whether to include debugging messages])
AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug], [include lots of debugging messages]),
	[ENABLE_DEBUG=$enableval],
	[ENABLE_DEBUG=no]
	)
AC_MSG_RESULT([$ENABLE_DEBUG])
if test "x$ENABLE_DEBUG" = "xyes"; then
	AC_DEFINE([ENABLE_DEBUG], [1],
			[Define to 1 if including lots of debug messages.])
fi

AC_MSG_CHECKING([whether to include error messages])
AC_ARG_ENABLE([error_messages],
	AS_HELP_STRING([--disable-error-messages],
			[do not compile in error messsages]),
	[ENABLE_ERROR_MESSAGES=$enableval],
	[ENABLE_ERROR_MESSAGES=yes]
	)
AC_MSG_RESULT([$ENABLE_ERROR_MESSAGES])
if test "x$ENABLE_ERROR_MESSAGES" = "xyes"; then
	AC_DEFINE([ENABLE_ERROR_MESSAGES], [1],
			[Define to 1 if including error messages])
fi

AC_MSG_CHECKING([whether to include assertions])
AC_ARG_ENABLE([assertions],
	AS_HELP_STRING([--disable-assertions], [do not include assertions]),
	[ENABLE_ASSERTIONS=$enableval],
	[ENABLE_ASSERTIONS=yes]
	)
AC_MSG_RESULT([$ENABLE_ASSERTIONS])
if test "x$ENABLE_ASSERTIONS" = "xyes"; then
	AC_DEFINE([ENABLE_ASSERTIONS], [1], [Define to 1 if including assertions.])
fi

AC_MSG_CHECKING([whether to include more assertions])
AC_ARG_ENABLE([more-assertions],
	AS_HELP_STRING([--enable-more-assertions], [include even more assertions]),
	[ENABLE_MORE_ASSERTIONS=$enableval],
	[ENABLE_MORE_ASSERTIONS=no]
	)
AC_MSG_RESULT([$ENABLE_MORE_ASSERTIONS])
if test "x$ENABLE_MORE_ASSERTIONS" = "xyes"; then
	AC_DEFINE([ENABLE_MORE_ASSERTIONS], [1], [Define to 1 if including more assertions.])
fi


AC_MSG_CHECKING([whether to include automatic compression verification])
AC_ARG_ENABLE([verify_compression],
	      AS_HELP_STRING([--enable-verify-compression], [always
				check if blocks we compress can be correctly
				decompressed]),
	[ENABLE_VERIFY_COMPRESSION=$enableval],
	[ENABLE_VERIFY_COMPRESSION=no]
	)
AC_MSG_RESULT([$ENABLE_VERIFY_COMPRESSION])
if test "x$ENABLE_VERIFY_COMPRESSION" = "xyes"; then
	AC_DEFINE([ENABLE_VERIFY_COMPRESSION], [1], [Define to 1 to verify
		   compressed data])
fi

AC_MSG_CHECKING([whether to include support for multi-threaded compression])
AC_ARG_ENABLE([multithreaded-compression],
	AS_HELP_STRING([--disable-multithreaded-compression],
			[do not compile in the code for multi-threaded compression]),
	[ENABLE_MULTITHREADED_COMPRESSION=$enableval],
	[ENABLE_MULTITHREADED_COMPRESSION=yes]
	)
AC_MSG_RESULT([$ENABLE_MULTITHREADED_COMPRESSION])
if test "x$ENABLE_MULTITHREADED_COMPRESSION" = "xyes"; then
	AC_DEFINE([ENABLE_MULTITHREADED_COMPRESSION], [1],
			[Define to 1 if including support for multithreaded
			 compression])
fi

PTHREAD_LDADD="-lpthread"
AC_SUBST([PTHREAD_LDADD], [$PTHREAD_LDADD])

WITH_NTFS_3G_DEFAULT="no"
WITH_FUSE_DEFAULT="no"
WINDOWS_NATIVE_BUILD="no"
VISIBILITY_CFLAGS="-fvisibility=hidden"
WINDOWS_CFLAGS=""
WINDOWS_CPPFLAGS=""
WINDOWS_LDFLAGS=""

case "$host_os" in
	mingw*)
		# Native Windows
		WINDOWS_NATIVE_BUILD="yes"
		VISIBILITY_CFLAGS=""
		WINDOWS_CFLAGS="-municode"
		WINDOWS_CPPFLAGS="-D_POSIX -DUNICODE -D_UNICODE -D_CRT_NON_CONFORMING_SWPRINTFS"
		WINDOWS_LDFLAGS="-no-undefined"
		;;
	linux*)
		# Linux
		WITH_FUSE_DEFAULT="yes"
		WITH_NTFS_3G_DEFAULT="yes"
		;;
	*)
		# Other UNIX
		WITH_NTFS_3G_DEFAULT="yes"
		;;
esac

AC_SUBST([VISIBILITY_CFLAGS], [$VISIBILITY_CFLAGS])
AC_SUBST([WINDOWS_LDFLAGS], [$WINDOWS_LDFLAGS])
AC_SUBST([WINDOWS_CPPFLAGS], [$WINDOWS_CPPFLAGS])
AC_SUBST([WINDOWS_CFLAGS], [$WINDOWS_CFLAGS])
AM_CONDITIONAL([WINDOWS_NATIVE_BUILD], [test "x$WINDOWS_NATIVE_BUILD" = "xyes"])


AM_ICONV
if test "x$am_cv_func_iconv" != "xyes"; then
	AC_MSG_ERROR([Cannot find the iconv() function.  iconv() is used to
		      convert between encodings of WIM filenames and XML data.
		      wimlib cannot be compiled without it.  iconv() is
		      available in the latest version of glibc and sometimes in
		      other libraries.])
fi

AC_MSG_CHECKING([whether to include support for ntfs-3g])
AC_ARG_WITH([ntfs-3g],
	    [AS_HELP_STRING([--without-ntfs-3g],
			    [build without libntfs-3g.  This will disable the
			     ability to capture or apply a WIM image directly
			     from/to an unmounted NTFS volume.])],
	    [WITH_NTFS_3G=$withval],
	    [WITH_NTFS_3G=$WITH_NTFS_3G_DEFAULT])

AC_MSG_RESULT([$WITH_NTFS_3G])
if test "x$WITH_NTFS_3G" = "xyes"; then
	AC_DEFINE([WITH_NTFS_3G], [1], [Define to 1 to enable NTFS-3g support.])

	dnl This effectively checks for NTFS-3g 2011.4.12 or later
	AC_CHECK_LIB([ntfs-3g], [ntfs_xattr_system_setxattr], [],
			[AC_MSG_ERROR([Cannot find libntfs-3g version 2011-4-12
	or later!  Without libntfs-3g, wimlib cannot include support for
	capturing or applying a WIM image directly from/to an unmounted NTFS
	volume while preserving NTFS-specific data such as security descriptors
	and named data streams.  Either install libntfs-3g, or configure
	--without-ntfs-3g to disable this feature.])])

	PKG_CHECK_MODULES([LIBNTFS_3G], [libntfs-3g])
	PKGCONFIG_PRIVATE_REQUIRES="$PKGCONFIG_PRIVATE_REQUIRES libntfs-3g"

	dnl This checks for an NTFS-3g interface that was changed in the
	dnl 2013.1.13 release
	AC_CHECK_DECL([NTFS_MNT_RDONLY],
		      [AC_DEFINE([HAVE_NTFS_MNT_RDONLY],
				 [1],
				 [Define to 1 if ntfs_mount() takes the flag NTFS_MNT_RDONLY])],
		      [],
		      [#include <ntfs-3g/volume.h>])
fi
AM_CONDITIONAL([WITH_NTFS_3G], [test "x$WITH_NTFS_3G" = "xyes"])

AC_MSG_CHECKING([whether to include support for mounting WIMs])
AC_ARG_WITH([fuse],
	[AS_HELP_STRING([--without-fuse],
			[build without libfuse.  This will disable the ability
			 to mount WIM images.])],
	[WITH_FUSE=$withval],
	[WITH_FUSE=$WITH_FUSE_DEFAULT])

AC_MSG_RESULT([$WITH_FUSE])
if test "x$WITH_FUSE" = "xyes"; then
	AC_DEFINE([WITH_FUSE], [1], [Define to 1 if using FUSE.])

	AC_CHECK_LIB([fuse], [fuse_main_real], [],
			[AC_MSG_ERROR([Cannot find libfuse!
	Without libfuse, wimlib cannot include support for mounting WIM images.
	Either install libfuse, or configure --without-fuse to disable this
	feature.])])

	AC_CHECK_LIB([rt], [mq_open], [],
		     [AC_MSG_ERROR([Cannot find librt (the POSIX.1b Realtime
	Extensions Library)!  wimlib needs this for the POSIX message queue
	functions, which are used in the code for mounting WIM images.  Recent
	versions of glibc include this library.  Either install this library, or
	configure --without-fuse to disable support for mounting WIM images.])])

	AC_CHECK_LIB([attr], [getxattr], [],
		     [AC_MSG_ERROR([Cannot find libattr!
	wimlib needs this for the extended attribute functions, which are used
	in the code for mounting WIM images.  Either install this library, or
	configure --without-fuse to disable support for mounting WIM images.])])

	PKG_CHECK_MODULES([LIBFUSE], [fuse])
	PKGCONFIG_PRIVATE_REQUIRES="$PKGCONFIG_PRIVATE_REQUIRES fuse"
	PKGCONFIG_PRIVATE_LIBS="$PKGCONFIG_PRIVATE_LIBS -lrt"
	AC_SUBST([LIBRT_LIBS], [-lrt])
fi
AM_CONDITIONAL([WITH_FUSE], [test "x$WITH_FUSE" = "xyes"])

AC_MSG_CHECKING([whether to use SSSE3-accelerated SHA-1])
AC_ARG_ENABLE([ssse3-sha1],
	      [AS_HELP_STRING([--enable-ssse3-sha1],
			      [Include SSSE3-accelerated SHA-1 implementation by
			       Intel.  This implies --without-libcrypto.])],
	      [ENABLE_SSSE3_SHA1=$enableval],
	      [ENABLE_SSSE3_SHA1=no])

AC_MSG_RESULT([$ENABLE_SSSE3_SHA1])
if test "x$ENABLE_SSSE3_SHA1" = "xyes"; then
	AC_DEFINE([ENABLE_SSSE3_SHA1], [1],
		  [Define to 1 if using SSSE3 implementation of SHA-1])
	SSSE3_SHA1_OBJ=src/sha1-ssse3.lo
	AC_PROG_NASM
	NASM_SYMBOL_PREFIX=""
	NASM_WINDOWS_FLAGS=
	if test "x$WINDOWS_NATIVE_BUILD" = "xyes"; then
		NASM_WINDOWS_FLAGS="-DWIN_ABI"
	fi
	case "$host_os" in
		darwin* | rhapsody* | nextstep* | openstep* | macos*)
			NASM_SYMBOL_PREFIX="_"
			;;
	esac
	AC_SUBST([NASM_WINDOWS_FLAGS], $NASM_WINDOWS_FLAGS)
	AC_SUBST([NASM_SYMBOL_PREFIX], $NASM_SYMBOL_PREFIX)
else
	SSSE3_SHA1_OBJ=
fi
AC_SUBST([SSSE3_SHA1_OBJ], [$SSSE3_SHA1_OBJ])

if test "x$ENABLE_SSSE3_SHA1" = "xyes"; then
	WITH_LIBCRYPTO=no
else
	AC_ARG_WITH([libcrypto],
		    [AS_HELP_STRING([--without-libcrypto],
				    [build in the SHA-1 algorithm, rather than
				     use external libcrypto from OpenSSL
				     (default is autodetect)])],
	[WITH_LIBCRYPTO=$withval],
	[AC_CHECK_LIB([crypto],
		      [SHA1],
		      [WITH_LIBCRYPTO=yes],
		      [AC_MSG_WARN([Cannot find libcrypto: using stand-alone
				    SHA-1 code instead of OpenSSL])
		       WITH_LIBCRYPTO=no])])
fi
AC_MSG_CHECKING([whether to use SHA-1 implementation from system libcrypto])
AC_MSG_RESULT([$WITH_LIBCRYPTO])

if test "x$WITH_LIBCRYPTO" = "xyes" -a "x$ENABLE_SSSE3_SHA1" = "xno"; then
	AC_DEFINE([WITH_LIBCRYPTO], [1], [Define to 1 if using libcrypto SHA-1])
	PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])
	PKGCONFIG_PRIVATE_REQUIRES="$PKGCONFIG_PRIVATE_REQUIRES libcrypto"
fi

AC_SUBST([PKGCONFIG_PRIVATE_REQUIRES], [$PKGCONFIG_PRIVATE_REQUIRES])
AC_SUBST([PKGCONFIG_PRIVATE_LIBS], [$PKGCONFIG_PRIVATE_LIBS])

AC_OUTPUT
