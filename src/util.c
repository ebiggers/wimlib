/*
 * util.c - utility functions
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wimlib.h"
#include "wimlib/assert.h"
#include "wimlib/timestamp.h"
#include "wimlib/util.h"
#include "wimlib/xml.h"

/*******************
 * Memory allocation
 *******************/

static void *(*wimlib_malloc_func) (size_t)	    = malloc;
static void  (*wimlib_free_func)   (void *)	    = free;
static void *(*wimlib_realloc_func)(void *, size_t) = realloc;

void *
wimlib_malloc(size_t size)
{
	void *ptr;

retry:
	ptr = (*wimlib_malloc_func)(size);
	if (unlikely(!ptr)) {
		if (size == 0) {
			size = 1;
			goto retry;
		}
	}
	return ptr;
}

void
wimlib_free_memory(void *ptr)
{
	(*wimlib_free_func)(ptr);
}

void *
wimlib_realloc(void *ptr, size_t size)
{
	if (size == 0)
		size = 1;
	return (*wimlib_realloc_func)(ptr, size);
}

void *
wimlib_calloc(size_t nmemb, size_t size)
{
	size_t total_size = nmemb * size;
	void *p = MALLOC(total_size);
	if (p)
		p = memset(p, 0, total_size);
	return p;
}

char *
wimlib_strdup(const char *str)
{
	size_t size;
	char *p;

	size = strlen(str);
	p = MALLOC(size + 1);
	if (p)
		p = memcpy(p, str, size + 1);
	return p;
}

#ifdef __WIN32__
wchar_t *
wimlib_wcsdup(const wchar_t *str)
{
	size_t size;
	wchar_t *p;

	size = wcslen(str);
	p = MALLOC((size + 1) * sizeof(wchar_t));
	if (p)
		p = wmemcpy(p, str, size + 1);
	return p;
}
#endif

void *
wimlib_aligned_malloc(size_t size, size_t alignment)
{
	wimlib_assert(alignment != 0 && is_power_of_2(alignment) &&
		      alignment <= 4096);

	const uintptr_t mask = alignment - 1;
	char *ptr = NULL;
	char *raw_ptr;

	raw_ptr = MALLOC(mask + sizeof(size_t) + size);
	if (raw_ptr) {
		ptr = (char *)raw_ptr + sizeof(size_t);
		ptr = (void *)(((uintptr_t)ptr + mask) & ~mask);
		*((size_t *)ptr - 1) = ptr - raw_ptr;
	}
	return ptr;
}

void
wimlib_aligned_free(void *ptr)
{
	if (ptr)
		FREE((char *)ptr - *((size_t *)ptr - 1));
}

void *
memdup(const void *mem, size_t size)
{
	void *ptr = MALLOC(size);
	if (ptr)
		ptr = memcpy(ptr, mem, size);
	return ptr;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_memory_allocator(void *(*malloc_func)(size_t),
			    void (*free_func)(void *),
			    void *(*realloc_func)(void *, size_t))
{
	wimlib_malloc_func  = malloc_func  ? malloc_func  : malloc;
	wimlib_free_func    = free_func    ? free_func    : free;
	wimlib_realloc_func = realloc_func ? realloc_func : realloc;

	xml_set_memory_allocator(wimlib_malloc_func, wimlib_free_func,
				 wimlib_realloc_func);
	return 0;
}

/*******************
 * String utilities
 *******************/

#ifndef HAVE_MEMPCPY
void *mempcpy(void *dst, const void *src, size_t n)
{
	return memcpy(dst, src, n) + n;
}
#endif

static bool seeded = false;

static void
seed_random(void)
{
	srand(now_as_wim_timestamp());
	seeded = true;
}

/* Fills @n characters pointed to by @p with random alphanumeric characters. */
void
randomize_char_array_with_alnum(tchar *p, size_t n)
{
	if (!seeded)
		seed_random();
	while (n--) {
		int r = rand() % 62;
		if (r < 26)
			*p++ = r + 'a';
		else if (r < 52)
			*p++ = r - 26 + 'A';
		else
			*p++ = r - 52 + '0';
	}
}

/* Fills @n bytes pointer to by @p with random numbers. */
void
randomize_byte_array(u8 *p, size_t n)
{
	if (!seeded)
		seed_random();
	while (n--)
		*p++ = rand();
}
