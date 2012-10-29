AC_INIT([wimlib], [1.0.4], [ebiggers3@gmail.com])
AC_CONFIG_SRCDIR([src/wim.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects])
AC_C_BIGENDIAN
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile
		doc/Doxyfile
		wimlib.pc
		doc/imagex.1
		doc/imagex-append.1
		doc/imagex-apply.1
		doc/imagex-capture.1
		doc/imagex-delete.1
		doc/imagex-dir.1
		doc/imagex-export.1
		doc/imagex-info.1
		doc/imagex-join.1
		doc/imagex-mount.1
		doc/imagex-mountrw.1
		doc/imagex-split.1
		doc/imagex-unmount.1
		doc/mkwinpeimg.1
		])
AC_PROG_CC
AM_PROG_CC_C_O

AC_CHECK_FUNCS([utimensat lutimes utime])
AC_CHECK_HEADERS([endian.h byteswap.h sys/byteorder.h sys/endian.h \
		  sys/param.h machine/endian.h alloca.h stdlib.h stdarg.h \
		  errno.h attr/xattr.h utime.h])


AM_ICONV
if test "x$am_cv_func_iconv" != "xyes"; then
	AC_MSG_ERROR([Cannot find the iconv() function.
	iconv() is used to convert between UTF-8 and UTF-16 encodings of WIM
	filenames and XML data.  Wimlib cannot be compiled without it.  iconv()
	is available in the latest version of glibc and sometimes in other
	libraries.])
fi


AC_ARG_WITH(pkgconfigdir,
            [  --with-pkgconfigdir=DIR      pkgconfig file in DIR @<:@LIBDIR/pkgconfig@:>@],
            [pkgconfigdir=$withval],
            [pkgconfigdir='${libdir}/pkgconfig'])
AC_SUBST(pkgconfigdir)

AC_CHECK_LIB([xml2], [xmlParseFile], [have_libxml=true],
	     [AC_MSG_ERROR(["cannot find libxml2"])])
LIBXML2_LDADD=`pkg-config libxml-2.0 --libs`
LIBXML2_CFLAGS=`pkg-config libxml-2.0 --cflags`
AC_SUBST([LIBXML2_LDADD], [$LIBXML2_LDADD])
AC_SUBST([LIBXML2_CFLAGS], [$LIBXML2_CFLAGS])

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

AC_MSG_CHECKING([whether to include more debugging messages])
AC_ARG_ENABLE([more_debug],
	AS_HELP_STRING([--enable-more-debug],
		       	[include even more debugging messages]),
	[ENABLE_MORE_DEBUG=$enableval],
	[ENABLE_MORE_DEBUG=no]
	)
AC_MSG_RESULT([$ENABLE_MORE_DEBUG])
if test "x$ENABLE_MORE_DEBUG" = "xyes"; then
	AC_DEFINE([ENABLE_MORE_DEBUG], [1],
		  	[Define to 1 if including even more debug messages.])
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

AC_MSG_CHECKING([whether to support custom memory allocation functions])
AC_ARG_ENABLE([custom_memory_allocator],
	AS_HELP_STRING([--disable-custom-memory-allocator],
		       [do not support the use of custom memory allocation
			functions]),
	[ENABLE_CUSTOM_MEMORY_ALLOCATOR=$enableval],
	[ENABLE_CUSTOM_MEMORY_ALLOCATOR=yes]
	)
AC_MSG_RESULT([$ENABLE_CUSTOM_MEMORY_ALLOCATOR])
if test "x$ENABLE_CUSTOM_MEMORY_ALLOCATOR" = "xyes"; then
	AC_DEFINE([ENABLE_CUSTOM_MEMORY_ALLOCATOR], [1],
		[Define to 1 if supporting custom memory allocation functions])
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


AC_MSG_CHECKING([whether to include compression verification])
AC_ARG_ENABLE([verify_compression],
	      AS_HELP_STRING([--disable-verify-compression], [disable
				checking if blocks we compress can be correctly
				decompressed]),
	[ENABLE_VERIFY_COMPRESSION=$enableval],
	[ENABLE_VERIFY_COMPRESSION=yes]
	)
AC_MSG_RESULT([$ENABLE_VERIFY_COMPRESSION])
if test "x$ENABLE_VERIFY_COMPRESSION" = "xyes"; then
	AC_DEFINE([ENABLE_VERIFY_COMPRESSION], [1], [Define to 1 to verify
		   compressed data])
fi

AC_MSG_CHECKING([whether to include support for ntfs-3g])
AC_ARG_WITH([ntfs-3g],
	      AS_HELP_STRING([--without-ntfs-3g], [build without NTFS-3g.
			      This will disable the ability to use NTFS-specific
			      information when capturing or applying WIMs to a
			      NTFS filesystem.]),
	[WITH_NTFS_3G=$withval],
	[WITH_NTFS_3G=yes]
	)
AC_MSG_RESULT([$WITH_NTFS_3G])
if test "x$WITH_NTFS_3G" = "xyes"; then
	AC_DEFINE([WITH_NTFS_3G], [1], [Define to 1 to enable support for
		   NTFS-specific information])

	AC_CHECK_LIB([ntfs-3g], [ntfs_mount], [],
			[AC_MSG_ERROR([Cannot find libntfs-3g.
	Without libntfs-3g, wimlib cannot include support for capturing and
	applying WIMs on NTFS filesystems while preserving NTFS-specific data
	such as security descriptors and alternate data streams.  You should
	either install libntfs-3g, or configure with --without-ntfs-3g to
	disable support for these NTFS-specific features.])])
	LIBNTFS_3G_LDADD="`pkg-config --libs libntfs-3g`"
	LIBNTFS_3G_CFLAGS="`pkg-config --cflags libntfs-3g`"
else
	LIBNTFS_3G_LDADD=
	LIBNTFS_3G_CFLAGS=
fi
AM_CONDITIONAL([WITH_NTFS_3G], [test "x$WITH_NTFS_3G" = "xyes"])

AC_SUBST([LIBNTFS_3G_LDADD], [$LIBNTFS_3G_LDADD])
AC_SUBST([LIBNTFS_3G_CFLAGS], [$LIBNTFS_3G_CFLAGS])

AC_MSG_CHECKING([whether to include support for mounting WIMs])
AC_ARG_WITH([fuse],
		AS_HELP_STRING([--without-fuse], [build without libfuse.
					This will disable the ability to mount
					WIM files.]),
	[WITH_FUSE=$withval],
	[WITH_FUSE=yes]
	)
AC_MSG_RESULT([$WITH_FUSE])
if test "x$WITH_FUSE" = "xyes"; then
	AC_DEFINE([WITH_FUSE], [1], [Define to 1 if using FUSE.])


	AC_CHECK_LIB([fuse], [fuse_main_real], [have_fuse=true],
			[AC_MSG_ERROR([Cannot find libfuse.
	Without libfuse, wimlib cannot include support for mounting WIMs.  You
	should either install libfuse, or configure with --without-fuse to
	disable support for mounting WIMs.])
	])
	AC_CHECK_LIB([rt], [mq_open], [have_posix_mq=true],
		     [AC_MSG_ERROR([Cannot find librt for POSIX message queue
	functions.  Without these functions, wimlib cannot include support for
	mounting WIMs.  You should either update your C library to a recent
	version of glibc, or configure with --without-fuse to disable support
	for mounting WIMs.])
	])
	LIBFUSE_LDADD="`pkg-config --libs fuse` -lrt"
	LIBFUSE_CFLAGS="`pkg-config --cflags fuse`"
else
	LIBFUSE_LDADD=
	LIBFUSE_CFLAGS=
fi
AM_CONDITIONAL([WITH_FUSE], [test "x$WITH_FUSE" = "xyes"])
AC_SUBST([LIBFUSE_LDADD], [$LIBFUSE_LDADD])
AC_SUBST([LIBFUSE_CFLAGS], [$LIBFUSE_CFLAGS])

ENABLE_XATTR=no
AC_ARG_ENABLE([xattr],
	[AS_HELP_STRING([--enable-xattr], [Enable the xattr interface to access WIM
			alternate data streams (default: autodetect)])],
	[ENABLE_XATTR=$enableval],
	[AC_CHECK_FUNC([setxattr],
		[AC_CHECK_HEADER([attr/xattr.h],
			[ENABLE_XATTR=yes],
			[AC_MSG_WARN([Cannot find the "attr/xattr.h" header.  You will not be
			 able to use the xattr interface to access WIM alternate data
			 streams.])])],
		[AC_MSG_WARN([Cannot find the setxattr() function.  You will not be
		 able to use the xattr interface to access WIM alternate data
		 streams.])])])

if test "x$ENABLE_XATTR" = "xyes"; then
	AC_DEFINE([ENABLE_XATTR], [1], [Define to 1 if using the xattr
			interface to WIM alternate data streams])
fi

AC_MSG_CHECKING([whether to use SSSE3-accelerated SHA1 ])
AC_ARG_ENABLE([ssse3-sha1],
	    AS_HELP_STRING([--enable-ssse3-sha1], [use assembly language implementation
			    	of SHA1 from Intel, accelerated with vector
				instructions (SSSE3-enabled CPU required)]),
	[ENABLE_SSSE3_SHA1=$enableval],
	[ENABLE_SSSE3_SHA1=no]
	)

AC_MSG_RESULT([$ENABLE_SSSE3_SHA1])
if test "x$ENABLE_SSSE3_SHA1" = "xyes"; then
	AC_DEFINE([ENABLE_SSSE3_SHA1], [1],
		  	[Define to 1 if using vectorized implementation of SHA1])
	SSSE3_SHA1_OBJ=sha1-ssse3.lo
	AX_PROG_NASM
	AC_SUBST([NASM], [$nasm])
else
	SSSE3_SHA1_OBJ=
fi
AC_SUBST([SSSE3_SHA1_OBJ], [$SSSE3_SHA1_OBJ])

if test "x$ENABLE_SSSE3_SHA1" = "xyes"; then
	WITH_LIBCRYPTO=no
else
	AC_ARG_WITH([libcrypto],
	    AS_HELP_STRING([--without-libcrypto], [build in the SHA1 algorithm,
			    		rather than use external libcrypto from
					OpenSSL (default is autodetect)]),
	[WITH_LIBCRYPTO=$withval],
	[AC_CHECK_LIB([crypto], [SHA1],
		     [WITH_LIBCRYPTO=yes],
		     [AC_MSG_WARN([Cannot find libcrypto: using stand-alone SHA1 code instead of OpenSSL])
		     WITH_LIBCRYPTO=no
		     ])])
fi
AC_MSG_CHECKING([whether to use SHA1 function from system libcrypto])
AC_MSG_RESULT([$WITH_LIBCRYPTO])

if test "x$WITH_LIBCRYPTO" = "xyes" -a "x$ENABLE_SSSE3_SHA1" = "xno"; then
	AC_DEFINE([WITH_LIBCRYPTO], [1], [Define to 1 if using libcrypto SHA1])
	LIBCRYPTO_LDADD=`pkg-config --libs libcrypto 2>/dev/null`
	if test $? -ne 0; then
		LIBCRYPTO_LDADD=-lcrypto;
	fi
	LIBCRYPTO_CFLAGS=`pkg-config --cflags libcrypto 2>/dev/null`
else
	LIBCRYPTO_LDADD=
	LIBCRYPTO_CFLAGS=
fi
AC_SUBST([LIBCRYPTO_LDADD], [$LIBCRYPTO_LDADD])
AC_SUBST([LIBCRYPTO_CFLAGS], [$LIBCRYPTO_CFLAGS])
AC_SUBST([SHA1_SOURCES], [$SHA1_SOURCES])

AC_OUTPUT
