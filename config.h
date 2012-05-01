/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define to 1 if including assertions. */
#define ENABLE_ASSERTIONS 1

/* Define to 1 if supporting custom memory allocation functions */
#define ENABLE_CUSTOM_MEMORY_ALLOCATOR 1

/* Define to 1 if including lots of debug messages. */
/* #undef ENABLE_DEBUG */

/* Define to 1 if including error messages */
#define ENABLE_ERROR_MESSAGES 1

/* Define to 1 if including even more debug messages. */
/* #undef ENABLE_MORE_DEBUG */

/* Define to 1 if using vectorized implementation of SHA1 */
/* #undef ENABLE_SSSE3_SHA1 */

/* Define to 1 to verify compressed data */
#define ENABLE_VERIFY_COMPRESSION 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define if you have the iconv() function and it works. */
#define HAVE_ICONV 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define as const if the declaration of iconv() needs const. */
#define ICONV_CONST 

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "wimlib"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "ebiggers3@gmail.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "wimlib"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "wimlib 0.6.2"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "wimlib"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.6.2"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "0.6.2"

/* Define to 1 if using FUSE. */
#define WITH_FUSE 1

/* Define to 1 if using libcrypto SHA1 */
#define WITH_LIBCRYPTO 1

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif
