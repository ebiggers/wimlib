#ifndef _WIMLIB_UTIL_H
#define _WIMLIB_UTIL_H

#include "wimlib/types.h"
#include "wimlib/compiler.h"

#include <stdio.h>
#include <stddef.h>

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
#define BUFFER_SIZE 32768

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#ifdef ENABLE_CUSTOM_MEMORY_ALLOCATOR
extern void *
wimlib_malloc(size_t) _malloc_attribute;

extern void
wimlib_free_memory(void *p);

extern void *
wimlib_realloc(void *, size_t) _warn_unused_result_attribute;

extern void *
wimlib_calloc(size_t nmemb, size_t size) _malloc_attribute;

#ifdef __WIN32__
extern wchar_t *
wimlib_wcsdup(const wchar_t *str) _malloc_attribute;

#endif
extern char *
wimlib_strdup(const char *str) _malloc_attribute;

#  define	MALLOC	wimlib_malloc
#  define	FREE	wimlib_free_memory
#  define	REALLOC	wimlib_realloc
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

extern void *
memdup(const void *mem, size_t size) _malloc_attribute;

/* util.c */
extern void
randomize_byte_array(u8 *p, size_t n);

extern void
randomize_char_array_with_alnum(tchar p[], size_t n);

extern void
print_byte_field(const u8 field[], size_t len, FILE *out);

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

static inline u64
hash_u64(u64 n)
{
	return n * 0x9e37fffffffc0001ULL;
}

#ifdef __WIN32__
#  define OS_PREFERRED_PATH_SEPARATOR L'\\'
#else
#  define OS_PREFERRED_PATH_SEPARATOR '/'
#endif

#endif /* _WIMLIB_UTIL_H */
