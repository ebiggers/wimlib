/*
 * util.h
 *
 * Header for util.c.
 *
 * Copyright (C) 2012 Eric Biggers
 *
 * wimlib - Library for working with WIM files 
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef _WIMLIB_UTIL_H
#define _WIMLIB_UTIL_H

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/types.h>
#include "config.h"


typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned uint;

#define min(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); \
					(__a < __b) ? __a : __b; })
#define max(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); \
					(__a > __b) ? __a : __b; })
#define swap(a, b) ({typeof(a) _a = a; (a) = (b); (b) = _a;})

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

#define ZERO_ARRAY(array) memset(array, 0, sizeof(array))

#ifdef ENABLE_ERROR_MESSAGES
extern bool __wimlib_print_errors;
extern void wimlib_error(const char *format, ...);
#  define ERROR wimlib_error
#else
#  define ERROR(format, ...)
#endif /* ENABLE_ERROR_MESSAGES */

#if defined(ENABLE_DEBUG) || defined(ENABLE_MORE_DEBUG)
#include <errno.h>
#  define DEBUG(format, ...)  \
({ \
 	int __errno_save = errno; \
	fprintf(stdout, "[%s %d] %s(): " format, \
		__FILE__, __LINE__, __func__, ## __VA_ARGS__); \
	fflush(stdout); \
	errno = __errno_save; \
	})

#else
#  define DEBUG(format, ...)
#endif /* ENABLE_DEBUG || ENABLE_MORE_DEBUG */

#ifdef ENABLE_MORE_DEBUG
#  define DEBUG2(format, ...) DEBUG(format, ## __VA_ARGS__)
#else
#  define DEBUG2(format, ...)
#endif /* ENABLE_DEBUG */

#ifdef ENABLE_ASSERTIONS
#include <assert.h>
#	define wimlib_assert(expr) assert(expr)
#else
#	define wimlib_assert(expr)
#endif

#ifdef __GNUC__
#  define WIMLIBAPI __attribute__((visibility("default")))
#  define NOINLINE __attribute__((noinline))
#  define ALWAYS_INLINE inline __attribute__((always_inline))
#  define COLD     __attribute__((cold))
#  define HOT      __attribute__((hot))
#else
#  define WIMLIBAPI
#  define NOINLINE
#  define ALWAYS_INLINE inline
#  define COLD
#  define HOT
#endif /* __GNUC__ */

#ifdef ENABLE_CUSTOM_MEMORY_ALLOCATOR
extern void *(*wimlib_malloc_func)(size_t);
extern void (*wimlib_free_func)(void *);
extern void *(*wimlib_realloc)(void *, size_t);
extern void *wimlib_calloc(size_t nmemb, size_t size);
extern char *wimlib_strdup(const char *str);
#  define MALLOC wimlib_malloc_func
#  define FREE wimlib_free_func
#  define REALLOC wimlib_realloc_func
#  define CALLOC wimlib_calloc
#  define STRDUP wimlib_strdup
#else
#include <stdlib.h>
#include <string.h>
#  define MALLOC malloc
#  define FREE free
#  define REALLOC realloc
#  define CALLOC calloc
#  define STRDUP strdup
#endif /* ENABLE_CUSTOM_MEMORY_ALLOCATOR */


extern char *utf16_to_utf8(const char *utf16_str, size_t utf16_len,
			   size_t *utf8_len_ret);

extern char *utf8_to_utf16(const char *utf8_str, size_t utf8_len, 
			   size_t *utf16_len_ret);

extern void randomize_byte_array(void *p, size_t n);

extern void randomize_char_array_with_alnum(char p[], size_t n);

extern int sha1sum(const char *filename, void *buf);

extern const char *path_next_part(const char *path, 
				  size_t *first_part_len_ret);

extern const char *path_basename(const char *path);

extern void to_parent_name(char buf[], size_t len);

extern void print_string(const void *string, size_t len);

extern int get_num_path_components(const char *path);

extern ssize_t full_write(int fd, const void *buf, size_t n);


static inline void print_byte_field(const u8 field[], size_t len)
{
	while (len--)
		printf("%02hhx", *field++);
}


#endif /* _WIMLIB_UTIL_H */
