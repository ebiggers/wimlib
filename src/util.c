/*
 * util.c
 *
 * Copyright (C) 2010 Carl Thijssen
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

#include "wimlib_internal.h"
#include "endianness.h"
#include "sha1.h"


#include <iconv.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

/* True if WIMLIB is to print an informational message when an error occurs.
 * This can be turned off by calling wimlib_set_error_messages(false). */
#ifdef ENABLE_ERROR_MESSAGES
#include <stdarg.h>
bool __wimlib_print_errors = false;

void wimlib_error(const char *format, ...)
{
 	if (__wimlib_print_errors) {
		va_list va;
		int errno_save;

		va_start(va, format);
		errno_save = errno;
		fputs("ERROR: ", stderr);
		vfprintf(stderr, format, va);
		errno = errno_save;
		va_end(va);
	}
}
#endif

WIMLIBAPI int wimlib_set_print_errors(bool show_error_messages)
{
#ifdef ENABLE_ERROR_MESSAGES
	__wimlib_print_errors = show_error_messages;
	return 0;
#else
	if (show_error_messages)
		return WIMLIB_ERR_UNSUPPORTED;
#endif
}

static const char *error_strings[] = {
	[WIMLIB_ERR_SUCCESS] 
		= "Success",
	[WIMLIB_ERR_COMPRESSED_LOOKUP_TABLE] 
		= "Lookup table is compressed",
	[WIMLIB_ERR_DECOMPRESSION] 
		= "Failed to decompress compressed data",
	[WIMLIB_ERR_DELETE_STAGING_DIR] 
		= "Failed to delete staging directory",
	[WIMLIB_ERR_FORK] 
		= "Failed to fork another process",
	[WIMLIB_ERR_FUSE] 
		= "An error was returned by fuse_main()",
	[WIMLIB_ERR_FUSERMOUNT] 
		= "Could not execute the `fusermount' program, or it exited "
			"with a failure status",
	[WIMLIB_ERR_IMAGE_COUNT] 
		= "Inconsistent image count among the metadata "
			"resources, the WIM header, and/or the XML data",
	[WIMLIB_ERR_IMAGE_NAME_COLLISION] 
		= "Tried to add an image with a name that is already in use",
	[WIMLIB_ERR_INTEGRITY] 
		= "The WIM failed an integrity check",
	[WIMLIB_ERR_INVALID_CHUNK_SIZE] 
		= "The WIM is compressed but does not have a chunk "
			"size of 32768",
	[WIMLIB_ERR_INVALID_COMPRESSION_TYPE] 
		= "The WIM is compressed, but is not marked as having LZX or "
			"XPRESS compression",
	[WIMLIB_ERR_INVALID_DENTRY] 
		= "A directory entry in the WIM was invalid",
	[WIMLIB_ERR_INVALID_HEADER_SIZE] 
		= "The WIM header was not 208 bytes",
	[WIMLIB_ERR_INVALID_IMAGE] 
		= "Tried to select an image that does not exist in the WIM",
	[WIMLIB_ERR_INVALID_INTEGRITY_TABLE] 
		= "The WIM's integrity table is invalid",
	[WIMLIB_ERR_INVALID_PARAM] 
		= "An invalid parameter was given",
	[WIMLIB_ERR_INVALID_RESOURCE_SIZE] 
		= "A resource entry in the WIM is invalid",
	[WIMLIB_ERR_LINK] 
		= "Failed to create a hard or symbolic link when extracting "
			"a file from the WIM",
	[WIMLIB_ERR_MKDIR] 
		= "Failed to create a directory",
	[WIMLIB_ERR_MQUEUE] 
		= "Failed to create or use a POSIX message queue",
	[WIMLIB_ERR_NOMEM] 
		= "Ran out of memory",
	[WIMLIB_ERR_NOTDIR] 
		= "Expected a directory",
	[WIMLIB_ERR_NOT_A_WIM_FILE] 
		= "The file did not begin with the magic characters that "
			"identify a WIM file",
	[WIMLIB_ERR_NO_FILENAME] 
		= "The WIM is not identified with a filename",
	[WIMLIB_ERR_OPEN] 
		= "Failed to open a file",
	[WIMLIB_ERR_OPENDIR] 
		= "Failed to open a directory",
	[WIMLIB_ERR_READ] 
		= "Could not read data from a file",
	[WIMLIB_ERR_RENAME] 
		= "Could not rename a file",
	[WIMLIB_ERR_SPLIT] 
		= "The WIM is part of a split WIM, which Wimlib does not support",
	[WIMLIB_ERR_STAT] 
		= "Could not read the metadata for a file or directory",
	[WIMLIB_ERR_TIMEOUT] 
		= "Timed out",
	[WIMLIB_ERR_UNKNOWN_VERSION] 
		= "The WIM file is marked with an unknown version number",
	[WIMLIB_ERR_UNSUPPORTED] 
		= "The requested operation is unsupported",
	[WIMLIB_ERR_WRITE] 
		= "Failed to write data to a file",
	[WIMLIB_ERR_XML] 
		= "The XML data of the WIM is invalid",
};

WIMLIBAPI const char *wimlib_get_error_string(enum wimlib_error_code code)
{
	if (code < WIMLIB_ERR_SUCCESS || code > WIMLIB_ERR_XML)
		return NULL;
	else
		return error_strings[code];
}



#ifdef ENABLE_CUSTOM_MEMORY_ALLOCATOR
void *(*wimlib_malloc_func)(size_t) = malloc;
void (*wimlib_free_func)(void *) = free;
void *(*wimlib_realloc_func)(void *, size_t) = realloc;

void *wimlib_calloc(size_t nmemb, size_t size)
{
	size_t total_size = nmemb * size;
	void *p = MALLOC(total_size);
	if (p)
		memset(p, 0, total_size);
	return p;
}

char *wimlib_strdup(const char *str)
{
	size_t size;
	char *p;
	
	size = strlen(str); 
	p = MALLOC(size + 1);
	if (p)
		memcpy(p, str, size + 1);
	return p;
}

extern void xml_set_memory_allocator(void *(*malloc_func)(size_t),
				   void (*free_func)(void *),
				   void *(*realloc_func)(void *, size_t));
#endif

WIMLIBAPI int wimlib_set_memory_allocator(void *(*malloc_func)(size_t),
					   void (*free_func)(void *),
					   void *(*realloc_func)(void *, size_t))
{
#ifdef ENABLE_CUSTOM_MEMORY_ALLOCATOR
	wimlib_malloc_func  = malloc_func  ? malloc_func  : malloc;
	wimlib_free_func    = free_func    ? free_func    : free;
	wimlib_realloc_func = realloc_func ? realloc_func : realloc;

	xml_set_memory_allocator(wimlib_malloc_func, wimlib_free_func, 
				 wimlib_realloc_func);
#else
	ERROR("Cannot set custom memory allocator functions:\n");
	ERROR("wimlib was compiled with the "
			"--without-custom-memory-allocator flag\n");
	return WIMLIB_ERR_UNSUPPORTED;
#endif
}



static iconv_t cd_utf16_to_utf8 = (iconv_t)(-1);

/* Converts a string in the UTF-16 encoding to a newly allocated string in the
 * UTF-8 encoding.  */
char *utf16_to_utf8(const char *utf16_str, size_t utf16_len,
				size_t *utf8_len_ret)
{
	if (cd_utf16_to_utf8 == (iconv_t)(-1)) {
		cd_utf16_to_utf8 = iconv_open("UTF-8", "UTF-16LE");
		if (cd_utf16_to_utf8 == (iconv_t)-1) {
			ERROR("Failed to get conversion descriptor for "
					"converting UTF-16LE to UTF-8: %m\n");
			return NULL;
		}
	}
	size_t utf16_bytes_left  = utf16_len;
	size_t utf8_bytes_left   = utf16_len;

	char *utf8_str = MALLOC(utf8_bytes_left);
	if (!utf8_str)
		return NULL;

	char *orig_utf8_str = utf8_str;

	size_t num_chars_converted = iconv(cd_utf16_to_utf8, (char**)&utf16_str, 
			&utf16_bytes_left, &utf8_str, &utf8_bytes_left);

	if (num_chars_converted == (size_t)(-1)) {
		ERROR("Failed to convert UTF-16LE string to UTF-8 string: "
				"%m\n");
		FREE(orig_utf8_str);
		return NULL;
	}

	size_t utf8_len = utf16_len - utf8_bytes_left;

	*utf8_len_ret = utf8_len;
	orig_utf8_str[utf8_len] = '\0';
	return orig_utf8_str;
}

static iconv_t cd_utf8_to_utf16 = (iconv_t)(-1);

/* Converts a string in the UTF-8 encoding to a newly allocated string in the
 * UTF-16 encoding.  */
char *utf8_to_utf16(const char *utf8_str, size_t utf8_len, 
						size_t *utf16_len_ret)
{
	if (cd_utf8_to_utf16 == (iconv_t)(-1)) {
		cd_utf8_to_utf16 = iconv_open("UTF-16LE", "UTF-8");
		if (cd_utf8_to_utf16 == (iconv_t)-1) {
			ERROR("Failed to get conversion descriptor for "
					"converting UTF-8 to UTF-16LE: %m\n");
			return NULL;
		}
	}

	size_t utf8_bytes_left   = utf8_len;
	size_t utf16_capacity    = utf8_len * 4;
	size_t utf16_bytes_left  = utf16_capacity;

	char *utf16_str = MALLOC(utf16_capacity + 2);
	if (!utf16_str)
		return NULL;

	char *orig_utf16_str = utf16_str;

	size_t num_chars_converted = iconv(cd_utf8_to_utf16, (char**)&utf8_str, 
			&utf8_bytes_left, &utf16_str, &utf16_bytes_left);

	if (num_chars_converted == (size_t)(-1)) {
		ERROR("Failed to convert UTF-8 string to UTF-16LE string: "
				"%s\n", 
				(errno == E2BIG) ? 
					"Not enough room in output buffer" : 
					strerror(errno));
		FREE(orig_utf16_str);
		return NULL;
	}

	size_t utf16_len = utf16_capacity - utf16_bytes_left;

	*utf16_len_ret = utf16_len;
	orig_utf16_str[utf16_len] = '\0';
	orig_utf16_str[utf16_len + 1] = '\0';
	return orig_utf16_str;
}

/* Write @n bytes from @buf to the file descriptor @fd, retrying on interupt and
 * on short writes.
 *
 * Returns short count and set errno on failure. */
ssize_t full_write(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	ssize_t ret;
	ssize_t total = 0;

	while (total != n) {
		ret = write(fd, p, n);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			else
				break;
		}
		total += ret;
		p += ret;
	}
	return total;
}


static bool seeded = false;

/* Fills @n bytes pointed to by @p with random alphanumeric characters. */
void randomize_char_array_with_alnum(char p[], size_t n)
{
	int r;

	if (!seeded) {
		srand(time(NULL));
		seeded = true;
	}
	while (n--) {
		r = rand() % 62;
		if (r < 26)
			*p++ = r + 'a';
		else if (r < 52)
			*p++ = r - 26 + 'A';
		else
			*p++ = r - 52 + '0';
	}
}

/* Fills @n bytes pointer to by @p with random numbers. */
void randomize_byte_array(void *__p, size_t n)
{
	u8 *p = __p;

	if (!seeded) {
		srand(time(NULL));
		seeded = true;
	}
	while (n--)
		*p++ = rand();
}

/* Takes in a path of length @len in @buf, and transforms it into a string for
 * the path of its parent directory. */
void to_parent_name(char buf[], size_t len)
{
	ssize_t i = (ssize_t)len - 1;
	while (i >= 0 && buf[i] == '/')
		i--;
	while (i >= 0 && buf[i] != '/')
		i--;
	while (i >= 0 && buf[i] == '/')
		i--;
	buf[i + 1] = '\0';
}

/* Like the basename() function, but does not modify @path; it just returns a
 * pointer to it. */
const char *path_basename(const char *path)
{
	const char *p = path;
	while (*p)
		p++;
	p--;

	/* Trailing slashes. */
	while ((p != path - 1) && *p == '/')
		p--;

	while ((p != path - 1) && *p != '/')
		p--;

	return p + 1;
}

/* 
 * Splits a file path into the part before the first '/', or the entire name if
 * there is no '/', and the part after the first sequence of '/' characters.
 *
 * @path:  		The file path to split.
 * @first_part_len_ret: A pointer to a `size_t' into which the length of the
 * 				first part of the path will be returned.
 * @return:  		A pointer to the next part of the path, after the first
 * 				sequence of '/', or a pointer to the terminating 
 * 				null byte in the case of a path without any '/'.
 */
const char *path_next_part(const char *path, size_t *first_part_len_ret)
{
	size_t i;
	const char *next_part;

	i = 0;
	while (path[i] != '/' && path[i] != '\0')
		i++;
	if (first_part_len_ret)
		*first_part_len_ret = i;
	next_part = &path[i];
	while (*next_part == '/')
		next_part++;
	return next_part;
}

/* Returns the number of components of @path.  */
int get_num_path_components(const char *path)
{
	int num_components = 0;
	while (*path) {
		while (*path == '/')
			path++;
		if (*path)
			num_components++;
		while (*path && *path != '/')
			path++;
	}
	return num_components;
}


/* 
 * Prints a string.  Printable characters are printed as-is, while unprintable
 * characters are printed as their octal escape codes. 
 */
void print_string(const void *string, size_t len)
{
	const u8 *p = string;

	while (len--) {
		if (isprint(*p))
			putchar(*p);
		else
			printf("\\%03hho", *p);
		p++;
	}
}

/* Calculates the SHA1 message digest given the name of a file.
 * @buf must point to a buffer of length 20 bytes into which the message digest
 * is written.
 */
int sha1sum(const char *filename, void *buf)
{
	FILE *fp;
	int ret;

	fp = fopen(filename, "rb");
	if (!fp) {
		ERROR("Cannot open the file `%s' for reading: %m\n", filename);
		return WIMLIB_ERR_OPEN;
	}
	ret = sha1_stream(fp, buf);
	fclose(fp);
	return ret;
}
