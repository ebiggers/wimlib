/*
 * util.h - utility functions and macros
 */
#ifndef _WIMLIB_UTIL_H
#define _WIMLIB_UTIL_H

#include "wimlib/compiler.h"
#include "wimlib/types.h"

/****************
 * General macros
 *****************/

/* Cast a pointer to a struct member to a pointer to the containing struct.  */
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))

/* Calculate 'n / d', but round up instead of down.  */
#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))

/* Calculate 'n % d', but return 'd' if the result would be 0.  */
#define MODULO_NONZERO(n, d)	(((n) % (d)) ? ((n) % (d)) : (d))

/* Get the number of elements of an array type.  */
#define ARRAY_LEN(array)	(sizeof(array) / sizeof((array)[0]))

/* Round 'v' up to the next 'alignment'-byte aligned boundary.  'alignment' must
 * be a power of 2.  */
#define ALIGN(v, alignment)	(((v) + ((alignment) - 1)) & ~((alignment) - 1))

/* Maximum number of bytes that can be allocated on the stack.
 *
 * Note: this isn't a hard bound on the stack space used, since this is just for
 * individual arrays.  The full call stack could use more than this.  */
#define STACK_MAX 32768

/* Default size of file I/O buffer.  Currently assumed to be <= STACK_MAX.  */
#define BUFFER_SIZE 32768

/*******************
 * Memory allocation
 *******************/

extern void *
wimlib_malloc(size_t size) _malloc_attribute;

extern void
wimlib_free_memory(void *p);

extern void *
wimlib_realloc(void *ptr, size_t size);

extern void *
wimlib_calloc(size_t nmemb, size_t size) _malloc_attribute;

extern char *
wimlib_strdup(const char *str) _malloc_attribute;

#ifdef __WIN32__
extern wchar_t *
wimlib_wcsdup(const wchar_t *str) _malloc_attribute;
#endif

extern void *
wimlib_aligned_malloc(size_t size, size_t alignment) _malloc_attribute;

extern void
wimlib_aligned_free(void *ptr);

extern void *
memdup(const void *mem, size_t size) _malloc_attribute;

#define MALLOC		wimlib_malloc
#define FREE		wimlib_free_memory
#define REALLOC		wimlib_realloc
#define CALLOC		wimlib_calloc
#define STRDUP		wimlib_strdup
#define WCSDUP		wimlib_wcsdup
#define ALIGNED_MALLOC	wimlib_aligned_malloc
#define ALIGNED_FREE	wimlib_aligned_free

/*******************
 * String utilities
 *******************/

#ifndef HAVE_MEMPCPY
extern void *
mempcpy(void *dst, const void *src, size_t n);
#endif

extern void
randomize_byte_array(u8 *p, size_t n);

extern void
randomize_char_array_with_alnum(tchar *p, size_t n);

/************************
 * Hashing and comparison
 ************************/

static inline bool
is_power_of_2(unsigned long n)
{
	return (n != 0 && (n & (n - 1)) == 0);

}

static inline u64
hash_u64(u64 n)
{
	return n * 0x9e37fffffffc0001ULL;
}

static inline int
cmp_u32(u32 n1, u32 n2)
{
	if (n1 < n2)
		return -1;
	if (n1 > n2)
		return 1;
	return 0;
}

static inline int
cmp_u64(u64 n1, u64 n2)
{
	if (n1 < n2)
		return -1;
	if (n1 > n2)
		return 1;
	return 0;
}

/************************
 * System information
 ************************/

unsigned
get_available_cpus(void);

u64
get_available_memory(void);

#endif /* _WIMLIB_UTIL_H */
