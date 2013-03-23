#ifndef _WIMLIB_UTIL_H
#define _WIMLIB_UTIL_H

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/types.h>
#include "config.h"

#ifdef __GNUC__
#	if defined(__CYGWIN__) || defined(__WIN32__)
#		define WIMLIBAPI __declspec(dllexport)
#	else
#		define WIMLIBAPI __attribute__((visibility("default")))
#	endif
#	define ALWAYS_INLINE inline __attribute__((always_inline))
#	define PACKED __attribute__((packed))
//#	define FORMAT(type, format_str, args_start) \
			//__attribute__((format(type, format_str, args_start)))
#	define FORMAT(type, format_str, args_start)
#	if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)
#		define COLD     __attribute__((cold))
#	else
#		define COLD
#	endif
#else
#	define WIMLIBAPI
#	define ALWAYS_INLINE inline
#	define FORMAT(type, format_str, args_start)
#	define COLD
#	define PACKED
#endif /* __GNUC__ */


#if 0
#ifdef WITH_FUSE
#define atomic_inc(ptr) \
	__sync_fetch_and_add(ptr, 1)

#define atomic_dec(ptr) \
	__sync_sub_and_fetch(ptr, 1)
#endif
#endif

#ifndef _NTFS_TYPES_H
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif


/* A pointer to 'utf16lechar' indicates a UTF-16LE encoded string */
typedef u16 utf16lechar;

typedef u8 utf8char;

#ifdef __WIN32__
/* For Windows builds, the "tchar" type will be 2 bytes and will be equivalent
 * to "wchar_t" and "utf16lechar".  All indicate one code unit of a UTF16-LE
 * string. */
typedef wchar_t tchar;
#  define TCHAR_IS_UTF16LE 1
#  define T(text) L##text /* Make a string literal into a wide string */
#  define TS "ls" /* Format a string of "tchar" */
#  define WS "ls" /* Format a UTF-16LE string (same as above) */

/* For Windows builds, the following definitions replace the "tchar" functions
 * with the "wide-character" functions. */
#  define tmemchr  wmemchr
#  define tmemcpy  wmemcpy
#  define tstrcpy  wcscpy
#  define tprintf  wprintf
#  define tsprintf swprintf
#  define tfprintf fwprintf
#  define tvfprintf vfwprintf
#  define istalpha iswalpha
#  define tstrcmp  wcscmp
#  define tstrchr  wcschr
#  define tstrrchr wcsrchr
#  define tstrlen  wcslen
#  define tmemcmp  wmemcmp
#  define tstrftime wcsftime
#  define tputchar putwchar
#  define tputc    putwc
#  define tputs    _putws
#  define tfputs   fputws
#  define tfopen   _wfopen
#  define tstat    _wstati64
#  define tstrtol  wcstol
#  define tunlink  _wunlink
/* The following "tchar" functions do not have exact wide-character equivalents
 * on Windows so require parameter rearrangement or redirection to a replacement
 * function defined ourselves. */
#  define TSTRDUP  WSTRDUP
#  define tmkdir(path, mode) _wmkdir(path)
#  define tstrerror_r(errnum, buf, bufsize) _wcserror_s(buf, bufsize, errnum)
#  define trename  win32_rename_replacement
#  define ttruncate win32_truncate_replacement
#else
/* For non-Windows builds, the "tchar" type will be one byte and will specify a
 * string in the locale-dependent multibyte encoding.  However, only UTF-8 is
 * well supported in this library. */
typedef char tchar;
#  define TCHAR_IS_UTF16LE 0
#  define T(text) text /* In this case, strings of "tchar" are simply strings of
			  char */
#  define TS "s"       /* Similarly, a string of "tchar" is printed just as a
			  normal string. */
#  define WS "W"       /* UTF-16LE strings must be printed using a special
			  extension implemented by wimlib itself.  Note that
			  "ls" will not work here because a string of wide
			  characters on non-Windows systems is typically not
			  UTF-16LE. */
/* For non-Windows builds, replace the "tchar" functions with the regular old
 * string functions. */
#  define tmemchr  memchr
#  define tmemcpy  memcpy
#  define tstrcpy  strcpy
#  define tprintf  printf
#  define tsprintf sprintf
#  define tfprintf fprintf
#  define tvfprintf vfprintf
#  define istalpha isalpha
#  define tstrcmp  strcmp
#  define tstrchr  strchr
#  define tstrrchr strrchr
#  define tstrlen  strlen
#  define tmemcmp  memcmp
#  define tstrftime strftime
#  define tputchar putchar
#  define tputc    putc
#  define tputs    puts
#  define tfputs   fputs
#  define tfopen   fopen
#  define tstat    stat
#  define tunlink  unlink
#  define tstrtol  strtol
#  define tmkdir   mkdir
#  define TSTRDUP  STRDUP
#  define tstrerror_r strerror_r
#  define trename  rename
#  define ttruncate truncate
#endif

#define TMALLOC(n) MALLOC((n) * sizeof(tchar))

extern size_t
utf16le_strlen(const utf16lechar *s);

/* encoding.c */
extern void
iconv_global_cleanup();

extern bool wimlib_mbs_is_utf8;

#define DECLARE_CHAR_CONVERSION_FUNCTIONS(varname1, varname2,		\
					  chartype1, chartype2)		\
									\
extern int								\
varname1##_to_##varname2##_nbytes(const chartype1 *in, size_t in_nbytes,\
				  size_t *out_nbytes_ret);		\
									\
extern int								\
varname1##_to_##varname2##_buf(const chartype1 *in, size_t in_nbytes,	\
			       chartype2 *out);				\
									\
extern int								\
varname1##_to_##varname2(const chartype1 *in, size_t in_nbytes,		\
			 chartype2 **out_ret,				\
			 size_t *out_nbytes_ret);			\

#if !TCHAR_IS_UTF16LE
DECLARE_CHAR_CONVERSION_FUNCTIONS(utf16le, tstr, utf16lechar, tchar);
#endif

extern int
utf8_to_tstr_simple(const utf8char *utf8str, tchar **out);

extern int
tstr_to_utf8_simple(const tchar *tstr, utf8char **out);

#ifndef min
#define min(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); \
					(__a < __b) ? __a : __b; })
#endif

#ifndef max
#define max(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); \
					(__a > __b) ? __a : __b; })
#endif

#ifndef swap
#define swap(a, b) ({typeof(a) _a = a; (a) = (b); (b) = _a;})
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#ifndef container_of
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define DIV_ROUND_UP(numerator, denominator) \
	(((numerator) + (denominator) - 1) / (denominator))

#define MODULO_NONZERO(numerator, denominator) \
	(((numerator) % (denominator)) ? ((numerator) % (denominator)) : (denominator))

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

#define ZERO_ARRAY(array) memset(array, 0, sizeof(array))

/* Used for buffering FILE IO in a few places */
#define BUFFER_SIZE 4096

static inline void FORMAT(printf, 1, 2)
dummy_printf(const char *format, ...)
{
}

#ifdef ENABLE_ERROR_MESSAGES
extern void
wimlib_error(const tchar *format, ...) FORMAT(printf, 1, 2) COLD;

extern void
wimlib_error_with_errno(const tchar *format, ...) FORMAT(printf, 1, 2) COLD;

extern void
wimlib_warning(const tchar *format, ...) FORMAT(printf, 1, 2) COLD;

extern void
wimlib_warning_with_errno(const tchar *format, ...) FORMAT(printf, 1, 2) COLD;
#  define ERROR(format, ...)			wimlib_error(T(format), ## __VA_ARGS__)
#  define ERROR_WITH_ERRNO(format, ...) 	wimlib_error_with_errno(T(format), ## __VA_ARGS__)
#  define WARNING(format, ...)			wimlib_warning(T(format), ## __VA_ARGS__)
#  define WARNING_WITH_ERRNO(format, ...)	wimlib_warning(T(format), ## __VA_ARGS__)
#else /* ENABLE_ERROR_MESSAGES */
#  define ERROR(format, ...)			dummy_printf(format, ## __VA_ARGS__)
#  define ERROR_WITH_ERRNO(format, ...)		dummy_printf(format, ## __VA_ARGS__)
#  define WARNING(format, ...)			dummy_printf(format, ## __VA_ARGS__)
#  define WARNING_WITH_ERRNO(format, ...)	dummy_printf(format, ## __VA_ARGS__)
#endif /* !ENABLE_ERROR_MESSAGES */

#if defined(ENABLE_MORE_DEBUG) && !defined(ENABLE_DEBUG)
#  define ENABLE_DEBUG 1
#endif

#if defined(ENABLE_MORE_ASSERTIONS) && !defined(ENABLE_ASSERTIONS)
#  define ENABLE_ASSERTIONS 1
#endif

#ifdef ENABLE_DEBUG
extern void
wimlib_debug(const tchar *file, int line, const char *func,
	     const tchar *format, ...);
#  define DEBUG(format, ...) \
	 	wimlib_debug(T(__FILE__), __LINE__, __func__, T(format), ## __VA_ARGS__);

#else
#  define DEBUG(format, ...) dummy_printf(format, ## __VA_ARGS__)
#endif /* !ENABLE_DEBUG */

#ifdef ENABLE_MORE_DEBUG
#  define DEBUG2(format, ...) DEBUG(format, ## __VA_ARGS__)
#else
#  define DEBUG2(format, ...) dummy_printf(format, ## __VA_ARGS__)
#endif /* !ENABLE_MORE_DEBUG */

#ifdef ENABLE_ASSERTIONS
#include <assert.h>
#  define wimlib_assert(expr) assert(expr)
#else
#  define wimlib_assert(expr)
#endif /* !ENABLE_ASSERTIONS */

#ifdef ENABLE_MORE_ASSERTIONS
#  define wimlib_assert2(expr) wimlib_assert(expr)
#else
#  define wimlib_assert2(expr)
#endif /* !ENABLE_MORE_ASSERTIONS */

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#ifdef ENABLE_CUSTOM_MEMORY_ALLOCATOR
extern void *(*wimlib_malloc_func)(size_t);
extern void (*wimlib_free_func)(void *);
extern void *(*wimlib_realloc_func)(void *, size_t);
extern void *wimlib_calloc(size_t nmemb, size_t size);
#ifdef __WIN32__
extern wchar_t *wimlib_wcsdup(const wchar_t *str);
#endif
extern char *wimlib_strdup(const char *str);
#  define	MALLOC	wimlib_malloc_func
#  define	FREE	wimlib_free_func
#  define	REALLOC	wimlib_realloc_func
#  define	CALLOC	wimlib_calloc
#  define	STRDUP	wimlib_strdup
#  define	WSTRDUP wimlib_wcsdup
#else /* ENABLE_CUSTOM_MEMORY_ALLOCATOR */
#  include <stdlib.h>
#  include <string.h>
#  define	MALLOC	malloc
#  define	FREE	free
#  define	REALLOC	realloc
#  define	CALLOC	calloc
#  define	STRDUP	strdup
#  define       WSTRDUP wcsdup
#endif /* !ENABLE_CUSTOM_MEMORY_ALLOCATOR */


/* util.c */
extern void
randomize_byte_array(u8 *p, size_t n);

extern void
randomize_char_array_with_alnum(tchar p[], size_t n);

extern const tchar *
path_next_part(const tchar *path, size_t *first_part_len_ret);

const tchar *
path_basename_with_len(const tchar *path, size_t len);

const tchar *
path_basename(const tchar *path);

extern const tchar *
path_stream_name(const tchar *path);

extern void
to_parent_name(tchar *buf, size_t len);

extern void
print_string(const void *string, size_t len);

extern int
get_num_path_components(const char *path);

static inline void
print_byte_field(const u8 field[], size_t len)
{
	while (len--)
		tprintf(T("%02hhx"), *field++);
}

static inline u32
bsr32(u32 n)
{
#if defined(__x86__) || defined(__x86_64__)
	asm("bsrl %0, %0;"
			: "=r"(n)
			: "0" (n));
	return n;
#else
	u32 pow = 0;
	while ((n >>= 1) != 0)
		pow++;
	return pow;
#endif
}

extern int
wimlib_fprintf(FILE *fp, const tchar *format, ...)
	//FORMAT(printf, 2, 3)
	;

extern int
wimlib_printf(const tchar *format, ...)
	//FORMAT(printf, 1, 2)
	;

#endif /* _WIMLIB_UTIL_H */
