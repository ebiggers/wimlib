/*
 * util.c
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef _GNU_SOURCE
#  define _GNU_SOURCE_DEFINED 1
#  undef _GNU_SOURCE
#endif
/* Make sure the POSIX-compatible strerror_r() is declared, rather than the GNU
 * version, which has a different return type. */
#include <string.h>
#ifdef _GNU_SOURCE_DEFINED
#  define _GNU_SOURCE
#endif

#include "wimlib.h"
#include "wimlib/compiler.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/types.h"
#include "wimlib/util.h"
#include "wimlib/xml.h"

#ifdef __WIN32__
#  include "wimlib/win32.h" /* win32_strerror_r_replacement */
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static size_t
utf16le_strlen(const utf16lechar *s)
{
	const utf16lechar *p = s;
	while (*p)
		p++;
	return (p - s) * sizeof(utf16lechar);
}

#ifdef __WIN32__
#  define wimlib_vfprintf vfwprintf
#else
/* Handle %W for UTF16-LE printing.
 *
 * TODO: this is not yet done properly--- it's assumed that if the format string
 * contains %W, then it contains no other format specifiers.
 */
static int
wimlib_vfprintf(FILE *fp, const tchar *format, va_list va)
{
	const tchar *p;
	int n;

	for (p = format; *p; p++)
		if (*p == T('%') && *(p + 1) == T('W'))
			goto special;
	return tvfprintf(fp, format, va);
special:
	n = 0;
	for (p = format; *p; p++) {
		if (*p == T('%') && (*(p + 1) == T('W'))) {
			int ret;
			tchar *tstr;
			size_t tstr_nbytes;
			utf16lechar *ucs = va_arg(va, utf16lechar*);

			if (ucs) {
				size_t ucs_nbytes = utf16le_strlen(ucs);

				ret = utf16le_to_tstr(ucs, ucs_nbytes,
						      &tstr, &tstr_nbytes);
				if (ret) {
					ret = tfprintf(fp, T("??????"));
				} else {
					ret = tfprintf(fp, T("%"TS), tstr);
					FREE(tstr);
				}
				if (ret < 0)
					return -1;
				else
					n += ret;
			} else {
				n += tfprintf(fp, T("(null)"));
			}
			p++;
		} else {
			if (tputc(*p, fp) == EOF)
				return -1;
			n++;
		}
	}
	return n;
}

int
wimlib_printf(const tchar *format, ...)
{
	int ret;
	va_list va;

	va_start(va, format);
	ret = wimlib_vfprintf(stdout, format, va);
	va_end(va);
	return ret;
}

int
wimlib_fprintf(FILE *fp, const tchar *format, ...)
{
	int ret;
	va_list va;

	va_start(va, format);
	ret = wimlib_vfprintf(fp, format, va);
	va_end(va);
	return ret;
}

#endif /* __WIN32__ */

#ifdef ENABLE_ERROR_MESSAGES
bool wimlib_print_errors = false;
#endif

#if defined(ENABLE_ERROR_MESSAGES) || defined(ENABLE_DEBUG)
static void
wimlib_vmsg(const tchar *tag, const tchar *format,
	    va_list va, bool perror)
{
#if !defined(ENABLE_DEBUG)
	if (wimlib_print_errors)
#endif
	{
		int errno_save = errno;
		fflush(stdout);
		tfputs(tag, stderr);
		wimlib_vfprintf(stderr, format, va);
		if (perror && errno_save != 0) {
			tchar buf[50];
			int res;
			res = tstrerror_r(errno_save, buf, sizeof(buf));
			if (res) {
				tsprintf(buf,
					 T("unknown error (errno=%d)"),
					 errno_save);
			}
		#ifdef WIN32
			if (errno_save == EBUSY)
				tstrcpy(buf, T("Resource busy"));
		#endif
			tfprintf(stderr, T(": %"TS), buf);
		}
		tputc(T('\n'), stderr);
		fflush(stderr);
		errno = errno_save;
	}
}
#endif

/* True if wimlib is to print an informational message when an error occurs.
 * This can be turned off by calling wimlib_set_print_errors(false). */
#ifdef ENABLE_ERROR_MESSAGES
void
wimlib_error(const tchar *format, ...)
{
	va_list va;

	va_start(va, format);
	wimlib_vmsg(T("\r[ERROR] "), format, va, false);
	va_end(va);
}

void
wimlib_error_with_errno(const tchar *format, ...)
{
	va_list va;

	va_start(va, format);
	wimlib_vmsg(T("\r[ERROR] "), format, va, true);
	va_end(va);
}

void
wimlib_warning(const tchar *format, ...)
{
	va_list va;

	va_start(va, format);
	wimlib_vmsg(T("\r[WARNING] "), format, va, false);
	va_end(va);
}

void
wimlib_warning_with_errno(const tchar *format, ...)
{
	va_list va;

	va_start(va, format);
	wimlib_vmsg(T("\r[WARNING] "), format, va, true);
	va_end(va);
}

#endif

#if defined(ENABLE_DEBUG) || defined(ENABLE_MORE_DEBUG)
void wimlib_debug(const tchar *file, int line, const char *func,
		  const tchar *format, ...)
{
	va_list va;
	tchar buf[tstrlen(file) + strlen(func) + 30];

	static bool debug_enabled = false;
	if (!debug_enabled) {
		char *value = getenv("WIMLIB_DEBUG");
		if (!value || strcmp(value, "0"))
			debug_enabled = true;
		else
			return;
	}

	tsprintf(buf, T("[%"TS" %d] %s(): "), file, line, func);

	va_start(va, format);
	wimlib_vmsg(buf, format, va, false);
	va_end(va);
}
#endif

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_print_errors(bool show_error_messages)
{
#ifdef ENABLE_ERROR_MESSAGES
	wimlib_print_errors = show_error_messages;
	return 0;
#else
	if (show_error_messages)
		return WIMLIB_ERR_UNSUPPORTED;
	else
		return 0;
#endif
}

static const tchar *error_strings[] = {
	[WIMLIB_ERR_SUCCESS]
		= T("Success"),
	[WIMLIB_ERR_ALREADY_LOCKED]
		= T("The WIM is already locked for writing"),
	[WIMLIB_ERR_DECOMPRESSION]
		= T("Failed to decompress compressed data"),
	[WIMLIB_ERR_DELETE_STAGING_DIR]
		= T("Failed to delete staging directory"),
	[WIMLIB_ERR_FILESYSTEM_DAEMON_CRASHED]
		= T("The process servicing the mounted WIM has crashed"),
	[WIMLIB_ERR_FORK]
		= T("Failed to fork another process"),
	[WIMLIB_ERR_FUSE]
		= T("An error was returned by fuse_main()"),
	[WIMLIB_ERR_FUSERMOUNT]
		= T("Could not execute the `fusermount' program, or it exited "
			"with a failure status"),
	[WIMLIB_ERR_GLOB_HAD_NO_MATCHES]
		= T("The provided file glob did not match any files"),
	[WIMLIB_ERR_ICONV_NOT_AVAILABLE]
		= T("The iconv() function does not seem to work. "
		  "Maybe check to make sure the directory /usr/lib/gconv exists"),
	[WIMLIB_ERR_IMAGE_COUNT]
		= T("Inconsistent image count among the metadata "
			"resources, the WIM header, and/or the XML data"),
	[WIMLIB_ERR_IMAGE_NAME_COLLISION]
		= T("Tried to add an image with a name that is already in use"),
	[WIMLIB_ERR_INSUFFICIENT_PRIVILEGES]
		= T("The user does not have sufficient privileges"),
	[WIMLIB_ERR_INTEGRITY]
		= T("The WIM failed an integrity check"),
	[WIMLIB_ERR_INVALID_CAPTURE_CONFIG]
		= T("The capture configuration string was invalid"),
	[WIMLIB_ERR_INVALID_CHUNK_SIZE]
		= T("The WIM chunk size was invalid"),
	[WIMLIB_ERR_INVALID_COMPRESSION_TYPE]
		= T("The WIM is compressed, but is not marked as having LZX or "
			"XPRESS compression"),
	[WIMLIB_ERR_INVALID_HEADER]
		= T("The WIM header was invalid"),
	[WIMLIB_ERR_INVALID_IMAGE]
		= T("Tried to select an image that does not exist in the WIM"),
	[WIMLIB_ERR_INVALID_INTEGRITY_TABLE]
		= T("The WIM's integrity table is invalid"),
	[WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY]
		= T("An entry in the WIM's lookup table is invalid"),
	[WIMLIB_ERR_INVALID_MULTIBYTE_STRING]
		= T("A string was not valid in the current locale's character encoding"),
	[WIMLIB_ERR_INVALID_OVERLAY]
		= T("Conflicting files in overlay when creating a WIM image"),
	[WIMLIB_ERR_INVALID_PARAM]
		= T("An invalid parameter was given"),
	[WIMLIB_ERR_INVALID_PART_NUMBER]
		= T("The part number or total parts of the WIM is invalid"),
	[WIMLIB_ERR_INVALID_PIPABLE_WIM]
		= T("The pipable WIM is invalid"),
	[WIMLIB_ERR_INVALID_REPARSE_DATA]
		= T("The reparse data of a reparse point was invalid"),
	[WIMLIB_ERR_INVALID_RESOURCE_HASH]
		= T("The SHA1 message digest of a WIM resource did not match the expected value"),
	[WIMLIB_ERR_INVALID_METADATA_RESOURCE]
		= T("The metadata resource is invalid"),
	[WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE]
		= T("The version of wimlib that has mounted a WIM image is incompatible with the "
		  "version being used to unmount it"),
	[WIMLIB_ERR_INVALID_UTF8_STRING]
		= T("A string provided as input by the user was not a valid UTF-8 string"),
	[WIMLIB_ERR_INVALID_UTF16_STRING]
		= T("A string in a WIM dentry is not a valid UTF-16LE string"),
	[WIMLIB_ERR_IS_DIRECTORY]
		= T("One of the specified paths to delete was a directory"),
	[WIMLIB_ERR_IS_SPLIT_WIM]
		= T("The WIM is part of a split WIM, which is not supported for this operation"),
	[WIMLIB_ERR_LIBXML_UTF16_HANDLER_NOT_AVAILABLE]
		= T("libxml2 was unable to find a character encoding conversion handler "
		  "for UTF-16LE"),
	[WIMLIB_ERR_LINK]
		= T("Failed to create a hard or symbolic link when extracting "
			"a file from the WIM"),
	[WIMLIB_ERR_METADATA_NOT_FOUND]
		= T("A required metadata resource could not be located"),
	[WIMLIB_ERR_MKDIR]
		= T("Failed to create a directory"),
	[WIMLIB_ERR_MQUEUE]
		= T("Failed to create or use a POSIX message queue"),
	[WIMLIB_ERR_NOMEM]
		= T("Ran out of memory"),
	[WIMLIB_ERR_NOTDIR]
		= T("Expected a directory"),
	[WIMLIB_ERR_NOTEMPTY]
		= T("Directory was not empty"),
	[WIMLIB_ERR_NOT_A_WIM_FILE]
		= T("The file did not begin with the magic characters that "
			"identify a WIM file"),
	[WIMLIB_ERR_NOT_A_REGULAR_FILE]
		= T("One of the specified paths to extract did not "
		    "correspond to a regular file"),
	[WIMLIB_ERR_NO_FILENAME]
		= T("The WIM is not identified with a filename"),
	[WIMLIB_ERR_NOT_PIPABLE]
		= T("The WIM was not captured such that it can be "
		    "applied from a pipe"),
	[WIMLIB_ERR_NTFS_3G]
		= T("NTFS-3g encountered an error (check errno)"),
	[WIMLIB_ERR_OPEN]
		= T("Failed to open a file"),
	[WIMLIB_ERR_OPENDIR]
		= T("Failed to open a directory"),
	[WIMLIB_ERR_PATH_DOES_NOT_EXIST]
		= T("The path does not exist in the WIM image"),
	[WIMLIB_ERR_READ]
		= T("Could not read data from a file"),
	[WIMLIB_ERR_READLINK]
		= T("Could not read the target of a symbolic link"),
	[WIMLIB_ERR_RENAME]
		= T("Could not rename a file"),
	[WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED]
		= T("Unable to complete reparse point fixup"),
	[WIMLIB_ERR_RESOURCE_NOT_FOUND]
		= T("A file resource needed to complete the operation was missing from the WIM"),
	[WIMLIB_ERR_RESOURCE_ORDER]
		= T("The components of the WIM were arranged in an unexpected order"),
	[WIMLIB_ERR_SET_ATTRIBUTES]
		= T("Failed to set attributes on extracted file"),
	[WIMLIB_ERR_SET_REPARSE_DATA]
		= T("Failed to set reparse data on extracted file"),
	[WIMLIB_ERR_SET_SECURITY]
		= T("Failed to set file owner, group, or other permissions on extracted file"),
	[WIMLIB_ERR_SET_SHORT_NAME]
		= T("Failed to set short name on extracted file"),
	[WIMLIB_ERR_SET_TIMESTAMPS]
		= T("Failed to set timestamps on extracted file"),
	[WIMLIB_ERR_SPLIT_INVALID]
		= T("The WIM is part of an invalid split WIM"),
	[WIMLIB_ERR_STAT]
		= T("Could not read the metadata for a file or directory"),
	[WIMLIB_ERR_TIMEOUT]
		= T("Timed out while waiting for a message to arrive from another process"),
	[WIMLIB_ERR_UNEXPECTED_END_OF_FILE]
		= T("Unexpectedly reached the end of the file"),
	[WIMLIB_ERR_UNICODE_STRING_NOT_REPRESENTABLE]
		= T("A Unicode string could not be represented in the current locale's encoding"),
	[WIMLIB_ERR_UNKNOWN_VERSION]
		= T("The WIM file is marked with an unknown version number"),
	[WIMLIB_ERR_UNSUPPORTED]
		= T("The requested operation is unsupported"),
	[WIMLIB_ERR_UNSUPPORTED_FILE]
		= T("A file in the directory tree to archive was not of a supported type"),
	[WIMLIB_ERR_VOLUME_LACKS_FEATURES]
		= T("The volume did not support a feature necessary to complete the operation"),
	[WIMLIB_ERR_WIM_IS_READONLY]
		= T("The WIM is read-only (file permissions, header flag, or split WIM)"),
	[WIMLIB_ERR_WRITE]
		= T("Failed to write data to a file"),
	[WIMLIB_ERR_XML]
		= T("The XML data of the WIM is invalid"),
};

/* API function documented in wimlib.h  */
WIMLIBAPI const tchar *
wimlib_get_error_string(enum wimlib_error_code code)
{
	if ((int)code < 0 || code >= ARRAY_LEN(error_strings))
		return NULL;
	else
		return error_strings[code];
}



#ifdef ENABLE_CUSTOM_MEMORY_ALLOCATOR
static void *(*wimlib_malloc_func) (size_t)	     = malloc;
static void  (*wimlib_free_func)   (void *)	     = free;
static void *(*wimlib_realloc_func)(void *, size_t) = realloc;

void *
wimlib_malloc(size_t size)
{
	if (size == 0)
		size = 1;
	void *ptr = (*wimlib_malloc_func)(size);
	if (ptr == NULL)
		ERROR("memory exhausted");
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
	ptr = (*wimlib_realloc_func)(ptr, size);
	if (ptr == NULL)
		ERROR("memory exhausted");
	return ptr;
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

#endif /* ENABLE_CUSTOM_MEMORY_ALLOCATOR */

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

static void
seed_random(void)
{
	srand(time(NULL) * getpid());
	seeded = true;
}

/* Fills @n characters pointed to by @p with random alphanumeric characters. */
void
randomize_char_array_with_alnum(tchar p[], size_t n)
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


void print_byte_field(const u8 field[], size_t len, FILE *out)
{
	while (len--)
		tfprintf(out, T("%02hhx"), *field++);
}

#ifndef HAVE_MEMPCPY
void *mempcpy(void *dst, const void *src, size_t n)
{
	return memcpy(dst, src, n) + n;
}
#endif
