/*
 * util.c
 */

/*
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "wimlib_internal.h"
#include "endianness.h"
#include "timestamp.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* for getpid() */

/* True if wimlib is to print an informational message when an error occurs.
 * This can be turned off by calling wimlib_set_print_errors(false). */
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
		fputs("[ERROR] ", stderr);
		vfprintf(stderr, format, va);
		putc('\n', stderr);
		errno = errno_save;
		va_end(va);
	}
}

void wimlib_error_with_errno(const char *format, ...)
{
 	if (__wimlib_print_errors) {
		va_list va;
		int errno_save;

		va_start(va, format);
		errno_save = errno;
		fflush(stdout);
		fputs("[ERROR] ", stderr);
		vfprintf(stderr, format, va);
		if (errno_save != 0)
			fprintf(stderr, ": %s", strerror(errno_save));
		putc('\n', stderr);
		errno = errno_save;
		va_end(va);
	}
}

void wimlib_warning(const char *format, ...)
{
 	if (__wimlib_print_errors) {
		va_list va;
		int errno_save;

		va_start(va, format);
		errno_save = errno;
		fflush(stdout);
		fputs("[WARNING] ", stderr);
		vfprintf(stderr, format, va);
		putc('\n', stderr);
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
	else
		return 0;
#endif
}

static const char *error_strings[] = {
	[WIMLIB_ERR_SUCCESS]
		= "Success",
	[WIMLIB_ERR_ALREADY_LOCKED]
		= "The WIM is already locked for writing",
	[WIMLIB_ERR_COMPRESSED_LOOKUP_TABLE]
		= "Lookup table is compressed",
	[WIMLIB_ERR_DECOMPRESSION]
		= "Failed to decompress compressed data",
	[WIMLIB_ERR_DELETE_STAGING_DIR]
		= "Failed to delete staging directory",
	[WIMLIB_ERR_FILESYSTEM_DAEMON_CRASHED]
		= "The process servicing the mounted WIM has crashed",
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
	[WIMLIB_ERR_INVALID_CAPTURE_CONFIG]
		= "The capture configuration string was invalid",
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
	[WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY]
		= "An entry in the WIM's lookup table is invalid",
	[WIMLIB_ERR_INVALID_PARAM]
		= "An invalid parameter was given",
	[WIMLIB_ERR_INVALID_PART_NUMBER]
		= "The part number or total parts of the WIM is invalid",
	[WIMLIB_ERR_INVALID_RESOURCE_HASH]
		= "The SHA1 message digest of a WIM resource did not match the expected value",
	[WIMLIB_ERR_ICONV_NOT_AVAILABLE]
		= "The iconv() function does not seem to work. "
		  "Maybe check to make sure the directory /usr/lib/gconv exists",
	[WIMLIB_ERR_INVALID_RESOURCE_SIZE]
		= "A resource entry in the WIM has an invalid size",
	[WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE]
		= "The version of wimlib that has mounted a WIM image is incompatible with the "
		  "version being used to unmount it",
	[WIMLIB_ERR_INVALID_UTF8_STRING]
		= "A string provided as input by the user was not a valid UTF-8 string",
	[WIMLIB_ERR_INVALID_UTF16_STRING]
		= "A string in a WIM dentry is not a valid UTF-16LE string",
	[WIMLIB_ERR_LIBXML_UTF16_HANDLER_NOT_AVAILABLE]
		= "libxml2 was unable to find a character encoding conversion handler "
		  "for UTF-16LE",
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
	[WIMLIB_ERR_NTFS_3G]
		= "NTFS-3g encountered an error (check errno)",
	[WIMLIB_ERR_OPEN]
		= "Failed to open a file",
	[WIMLIB_ERR_OPENDIR]
		= "Failed to open a directory",
	[WIMLIB_ERR_READ]
		= "Could not read data from a file",
	[WIMLIB_ERR_READLINK]
		= "Could not read the target of a symbolic link",
	[WIMLIB_ERR_RENAME]
		= "Could not rename a file",
	[WIMLIB_ERR_REOPEN]
		= "Could not re-open the WIM after overwriting it",
	[WIMLIB_ERR_RESOURCE_ORDER]
		= "The components of the WIM were arranged in an unexpected order",
	[WIMLIB_ERR_SPECIAL_FILE]
		= "Encountered a special file that cannot be archived",
	[WIMLIB_ERR_SPLIT_INVALID]
		= "The WIM is part of an invalid split WIM",
	[WIMLIB_ERR_SPLIT_UNSUPPORTED]
		= "The WIM is part of a split WIM, which is not supported for this operation",
	[WIMLIB_ERR_STAT]
		= "Could not read the metadata for a file or directory",
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
void *(*wimlib_malloc_func) (size_t)	     = malloc;
void  (*wimlib_free_func)   (void *)	     = free;
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
	return 0;
#else
	ERROR("Cannot set custom memory allocator functions:");
	ERROR("wimlib was compiled with the --without-custom-memory-allocator "
	      "flag");
	return WIMLIB_ERR_UNSUPPORTED;
#endif
}

static bool seeded = false;

static void seed_random()
{
	srand(time(NULL) * getpid());
	seeded = true;
}

/* Fills @n bytes pointed to by @p with random alphanumeric characters. */
void randomize_char_array_with_alnum(char p[], size_t n)
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
void randomize_byte_array(u8 *p, size_t n)
{
	if (!seeded)
		seed_random();
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
	while (1) {
		if (p == path - 1)
			return "";
		if (*p != '/')
			break;
		p--;
	}

	while ((p != path - 1) && *p != '/')
		p--;

	return p + 1;
}

/*
 * Returns a pointer to the part of @path following the first colon in the last
 * path component, or NULL if the last path component does not contain a colon.
 */
const char *path_stream_name(const char *path)
{
	const char *base = path_basename(path);
	const char *stream_name = strchr(base, ':');
	if (!stream_name)
		return NULL;
	else
		return stream_name + 1;
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

u64 get_wim_timestamp()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return timeval_to_wim_timestamp(&tv);
}

void wim_timestamp_to_str(u64 timestamp, char *buf, size_t len)
{
	struct tm tm;
	time_t t = wim_timestamp_to_unix(timestamp);
	gmtime_r(&t, &tm);
	strftime(buf, len, "%a %b %d %H:%M:%S %Y UTC", &tm);
}
