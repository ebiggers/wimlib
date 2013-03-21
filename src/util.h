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
#	define FORMAT(type, format_str, args_start) \
			__attribute__((format(type, format_str, args_start)))
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

/* A pointer to 'mbchar' indicates a string of "multibyte characters" provided
 * in the default encoding of the user's locale, which may be "UTF-8",
 * "ISO-8859-1", "C", or any other ASCII-compatible encoding.
 * "ASCII-compatible" here means any encoding where all ASCII-representable
 * characters have the same representation as in ASCII itself, and any non-ASCII
 * character is represented as a sequence of one or more bytes not already used
 * by any ASCII character. */
typedef char mbchar;

/* A pointer to 'utf8char' indicates a UTF-8 encoded string */
typedef char utf8char;

/* Note: in some places in the code, strings of plain old 'char' are still used.
 * This means that the string is being operated on in an ASCII-compatible way,
 * and may be either a multibyte or UTF-8 string.  */

/* A pointer to 'utf16lechar' indicates a UTF-16LE encoded string */
typedef u16 utf16lechar;

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

/* multi-byte string to UTF16-LE string */
DECLARE_CHAR_CONVERSION_FUNCTIONS(mbs, utf16le, mbchar, utf16lechar);

/* UTF16-LE string to multi-byte string */
DECLARE_CHAR_CONVERSION_FUNCTIONS(utf16le, mbs, utf16lechar, mbchar);

/* UTF-8 string to multi-byte string */
DECLARE_CHAR_CONVERSION_FUNCTIONS(utf8, mbs, utf8char, mbchar);

extern bool
utf8_str_contains_nonascii_chars(const utf8char *utf8_str);

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
wimlib_error(const char *format, ...) FORMAT(printf, 1, 2) COLD;

extern void
wimlib_error_with_errno(const char *format, ...) FORMAT(printf, 1, 2) COLD;

extern void
wimlib_warning(const char *format, ...) FORMAT(printf, 1, 2) COLD;

extern void
wimlib_warning_with_errno(const char *format, ...) FORMAT(printf, 1, 2) COLD;
#  define ERROR			wimlib_error
#  define ERROR_WITH_ERRNO 	wimlib_error_with_errno
#  define WARNING		wimlib_warning
#  define WARNING_WITH_ERRNO	wimlib_warning
#else /* ENABLE_ERROR_MESSAGES */
#  define ERROR(format, ...)			dummy_printf(format, ## __VA_ARGS__)
#  define ERROR_WITH_ERRNO(format, ...)		dummy_printf(format, ## __VA_ARGS__)
#  define WARNING(format, ...)			dummy_printf(format, ## __VA_ARGS__)
#  define WARNING_WITH_ERRNO(format, ...)	dummy_printf(format, ## __VA_ARGS__)
#endif /* !ENABLE_ERROR_MESSAGES */

#if defined(ENABLE_DEBUG) || defined(ENABLE_MORE_DEBUG)
extern void
wimlib_debug(const char *file, int line, const char *func,
	     const char *format, ...);
#  define DEBUG(format, ...) \
	 	wimlib_debug(__FILE__, __LINE__, __func__, format, ## __VA_ARGS__);

#else
#  define DEBUG(format, ...) dummy_printf(format, ## __VA_ARGS__)
#endif /* ENABLE_DEBUG || ENABLE_MORE_DEBUG */

#ifdef ENABLE_MORE_DEBUG
#  define DEBUG2(format, ...) DEBUG(format, ## __VA_ARGS__)
#else
#  define DEBUG2(format, ...) dummy_printf(format, ## __VA_ARGS__)
#endif /* ENABLE_DEBUG */

#ifdef ENABLE_ASSERTIONS
#include <assert.h>
#  define wimlib_assert(expr) assert(expr)
#else
#  define wimlib_assert(expr)
#endif

#ifdef ENABLE_MORE_ASSERTIONS
#  define wimlib_assert2(expr) wimlib_assert(expr)
#else
#  define wimlib_assert2(expr)
#endif

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#ifdef ENABLE_CUSTOM_MEMORY_ALLOCATOR
extern void *(*wimlib_malloc_func)(size_t);
extern void (*wimlib_free_func)(void *);
extern void *(*wimlib_realloc_func)(void *, size_t);
extern void *wimlib_calloc(size_t nmemb, size_t size);
extern char *wimlib_strdup(const char *str);
#  define	MALLOC	wimlib_malloc_func
#  define	FREE	wimlib_free_func
#  define	REALLOC	wimlib_realloc_func
#  define	CALLOC	wimlib_calloc
#  define	STRDUP	wimlib_strdup
#else /* ENABLE_CUSTOM_MEMORY_ALLOCATOR */
#  include <stdlib.h>
#  include <string.h>
#  define	MALLOC	malloc
#  define	FREE	free
#  define	REALLOC	realloc
#  define	CALLOC	calloc
#  define	STRDUP	strdup
#endif /* !ENABLE_CUSTOM_MEMORY_ALLOCATOR */


/* util.c */
extern void
randomize_byte_array(u8 *p, size_t n);

extern void
randomize_char_array_with_alnum(char p[], size_t n);

extern const char *
path_next_part(const char *path, size_t *first_part_len_ret);

extern const char *
path_basename(const char *path);

extern const char *
path_stream_name(const char *path);

extern void
to_parent_name(char buf[], size_t len);

extern void
print_string(const void *string, size_t len);

extern int
get_num_path_components(const char *path);

static inline void
print_byte_field(const u8 field[], size_t len)
{
	while (len--)
		printf("%02hhx", *field++);
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
wimlib_fprintf(FILE *fp, const char *format, ...)
	//FORMAT(printf, 2, 3)
	;

extern int
wimlib_printf(const char *format, ...)
	//FORMAT(printf, 1, 2)
	;

#endif /* _WIMLIB_UTIL_H */
