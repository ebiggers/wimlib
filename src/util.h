#ifndef _WIMLIB_UTIL_H
#define _WIMLIB_UTIL_H

#include "config.h"
#include "wimlib_tchar.h"

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/types.h>

#ifdef __GNUC__
#	if defined(__CYGWIN__) || defined(__WIN32__)
#		define WIMLIBAPI __declspec(dllexport)
#	else
#		define WIMLIBAPI __attribute__((visibility("default")))
#	endif
#	define ALWAYS_INLINE inline __attribute__((always_inline))
#	define PACKED __attribute__((packed))
#	define FORMAT(type, format_str, args_start) \
			/*__attribute__((format(type, format_str, args_start))) */
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

#define TMALLOC(n) MALLOC((n) * sizeof(tchar))

/* encoding.c */
extern void
iconv_global_cleanup();

extern bool wimlib_mbs_is_utf8;

#define DECLARE_CHAR_CONVERSION_FUNCTIONS(varname1, varname2,		\
					  chartype1, chartype2)		\
									\
extern int								\
varname1##_to_##varname2(const chartype1 *in, size_t in_nbytes,		\
			 chartype2 **out_ret,				\
			 size_t *out_nbytes_ret);			\
									\
extern int								\
varname1##_to_##varname2##_nbytes(const chartype1 *in, size_t in_nbytes,\
				  size_t *out_nbytes_ret);		\
									\
extern int								\
varname1##_to_##varname2##_buf(const chartype1 *in, size_t in_nbytes,	\
			       chartype2 *out);


#if !TCHAR_IS_UTF16LE
DECLARE_CHAR_CONVERSION_FUNCTIONS(utf16le, tstr, utf16lechar, tchar);
DECLARE_CHAR_CONVERSION_FUNCTIONS(tstr, utf16le, tchar, utf16lechar);
#endif

extern int
utf8_to_tstr_simple(const char *utf8str, tchar **out);

extern int
tstr_to_utf8_simple(const tchar *tstr, char **out);

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
dummy_tprintf(const tchar *format, ...)
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
#  define ERROR(format, ...)			dummy_tprintf(T(format), ## __VA_ARGS__)
#  define ERROR_WITH_ERRNO(format, ...)		dummy_tprintf(T(format), ## __VA_ARGS__)
#  define WARNING(format, ...)			dummy_tprintf(T(format), ## __VA_ARGS__)
#  define WARNING_WITH_ERRNO(format, ...)	dummy_tprintf(T(format), ## __VA_ARGS__)
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
#  define DEBUG(format, ...) dummy_tprintf(T(format), ## __VA_ARGS__)
#endif /* !ENABLE_DEBUG */

#ifdef ENABLE_MORE_DEBUG
#  define DEBUG2(format, ...) DEBUG(format, ## __VA_ARGS__)
#else
#  define DEBUG2(format, ...) dummy_tprintf(T(format), ## __VA_ARGS__)
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

const tchar *
path_basename_with_len(const tchar *path, size_t len);

const tchar *
path_basename(const tchar *path);

extern const tchar *
path_stream_name(const tchar *path);

static inline void
print_byte_field(const u8 field[], size_t len, FILE *out)
{
	while (len--)
		tfprintf(out, T("%02hhx"), *field++);
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

#ifdef __WIN32__
#  define wimlib_fprintf fwprintf
#  define wimlib_printf	 wprintf
#else /* __WIN32__ */
extern int
wimlib_fprintf(FILE *fp, const tchar *format, ...) FORMAT(printf, 2, 3);

extern int
wimlib_printf(const tchar *format, ...) FORMAT(printf, 1, 2);
#endif /* !__WIN32__ */

extern void
zap_backslashes(tchar *s);

static inline u64
hash_u64(u64 n)
{
	return n * 0x9e37fffffffc0001ULL;
}

#endif /* _WIMLIB_UTIL_H */
