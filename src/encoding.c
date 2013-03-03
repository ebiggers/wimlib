/*
 * encoding.c:  Convert UTF-8 to UTF-16LE strings and vice versa
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

#include "wimlib.h"
#include "util.h"
#include "endianness.h"

#include <errno.h>

#ifdef WITH_NTFS_3G
#include <ntfs-3g/volume.h>
#include <ntfs-3g/unistr.h>
#else
#include <iconv.h>
#endif

/*
 * NOTE:
 *
 * utf16_to_utf8_size() and utf8_to_utf16_size() were taken from
 * libntfs-3g/unistr.c in the NTFS-3g sources.  (Modified slightly to remove
 * unneeded functionality.)
 */
#ifndef WITH_NTFS_3G
/*
 * Return the amount of 8-bit elements in UTF-8 needed (without the terminating
 * null) to store a given UTF-16LE string.
 *
 * Return -1 with errno set if string has invalid byte sequence or too long.
 */
static int utf16_to_utf8_size(const u16 *ins, const int ins_len)
{
	int i, ret = -1;
	int count = 0;
	bool surrog;

	surrog = false;
	for (i = 0; i < ins_len && ins[i]; i++) {
		unsigned short c = le16_to_cpu(ins[i]);
		if (surrog) {
			if ((c >= 0xdc00) && (c < 0xe000)) {
				surrog = false;
				count += 4;
			} else
				goto fail;
		} else
			if (c < 0x80)
				count++;
			else if (c < 0x800)
				count += 2;
			else if (c < 0xd800)
				count += 3;
			else if (c < 0xdc00)
				surrog = true;
#if NOREVBOM
			else if ((c >= 0xe000) && (c < 0xfffe))
#else
			else if (c >= 0xe000)
#endif
				count += 3;
			else
				goto fail;
	}
	if (surrog)
		goto fail;

	ret = count;
out:
	return ret;
fail:
	errno = EILSEQ;
	goto out;
}

/*
 * Return the amount of 16-bit elements in UTF-16LE needed
 * (without the terminating null) to store given UTF-8 string.
 *
 * Return -1 with errno set if it's longer than PATH_MAX or string is invalid.
 *
 * Note: This does not check whether the input sequence is a valid utf8 string,
 *	 and should be used only in context where such check is made!
 */
static int utf8_to_utf16_size(const char *s)
{
	unsigned int byte;
	size_t count = 0;
	while ((byte = *((const unsigned char *)s++))) {
		count++;
		if (byte >= 0xc0) {
			if (byte >= 0xF5) {
				errno = EILSEQ;
				return -1;
			}
			if (!*s)
				break;
			if (byte >= 0xC0)
				s++;
			if (!*s)
				break;
			if (byte >= 0xE0)
				s++;
			if (!*s)
				break;
			if (byte >= 0xF0) {
				s++;
				count++;
			}
		}
	}
	return count;
}
#endif /* !WITH_NTFS_3G */

#ifndef WITH_NTFS_3G
static iconv_t cd_utf8_to_utf16 = (iconv_t)(-1);
static iconv_t cd_utf16_to_utf8 = (iconv_t)(-1);

int iconv_global_init()
{
	if (cd_utf16_to_utf8 == (iconv_t)(-1)) {
		cd_utf16_to_utf8 = iconv_open("UTF-8", "UTF-16LE");
		if (cd_utf16_to_utf8 == (iconv_t)-1) {
			ERROR_WITH_ERRNO("Failed to get conversion descriptor "
					 "for converting UTF-16LE to UTF-8");
			if (errno == ENOMEM)
				return WIMLIB_ERR_NOMEM;
			else
				return WIMLIB_ERR_ICONV_NOT_AVAILABLE;
		}
	}

	if (cd_utf8_to_utf16 == (iconv_t)(-1)) {
		cd_utf8_to_utf16 = iconv_open("UTF-16LE", "UTF-8");
		if (cd_utf8_to_utf16 == (iconv_t)-1) {
			ERROR_WITH_ERRNO("Failed to get conversion descriptor "
					 "for converting UTF-8 to UTF-16LE");
			if (errno == ENOMEM)
				return WIMLIB_ERR_NOMEM;
			else
				return WIMLIB_ERR_ICONV_NOT_AVAILABLE;
		}
	}
	return 0;
}

void iconv_global_cleanup()
{
	if (cd_utf8_to_utf16 != (iconv_t)(-1))
		iconv_close(cd_utf8_to_utf16);
	if (cd_utf16_to_utf8 != (iconv_t)(-1))
		iconv_close(cd_utf16_to_utf8);
}
#endif

/* Converts a string in the UTF-16LE encoding to a newly allocated string in the
 * UTF-8 encoding.
 *
 * If available, do so by calling a similar function from libntfs-3g.
 * Otherwise, use iconv() along with the helper function utf16_to_utf8_size().
 */
int utf16_to_utf8(const char *utf16_str, size_t utf16_nbytes,
		  char **utf8_str_ret, size_t *utf8_nbytes_ret)
{
	int ret;

	if (utf16_nbytes == 0) {
		*utf8_str_ret = NULL;
		*utf8_nbytes_ret = 0;
		return 0;
	}

	if (utf16_nbytes & 1) {
		ERROR("UTF-16LE string is invalid (odd number of bytes)!");
		return WIMLIB_ERR_INVALID_UTF16_STRING;
	}
#ifdef WITH_NTFS_3G
	char *outs = NULL;
	int outs_len = ntfs_ucstombs((const ntfschar*)utf16_str,
				     utf16_nbytes / 2, &outs, 0);
	if (outs_len >= 0) {
		*utf8_str_ret = outs;
		*utf8_nbytes_ret = outs_len;
		ret = 0;
	} else {
		if (errno == ENOMEM)
			ret = WIMLIB_ERR_NOMEM;
		else
			ret = WIMLIB_ERR_INVALID_UTF16_STRING;
	}
#else /* !WITH_NTFS_3G */

	ret = iconv_global_init();
	if (ret != 0)
		return ret;

	ret = utf16_to_utf8_size((const u16*)utf16_str, utf16_nbytes / 2);
	if (ret >= 0) {
		size_t utf8_expected_nbytes;
		char  *utf8_str;
		size_t utf8_bytes_left;
		size_t utf16_bytes_left;
		size_t num_chars_converted;
		char  *utf8_str_save;
		const char *utf16_str_save;

		utf8_expected_nbytes = ret;
 		utf8_str = MALLOC(utf8_expected_nbytes + 1);
		if (utf8_str) {
			utf8_bytes_left = utf8_expected_nbytes;
			utf16_bytes_left = utf16_nbytes;
			utf8_str_save = utf8_str;
			utf16_str_save = utf16_str;
			num_chars_converted = iconv(cd_utf16_to_utf8,
						    (char**)&utf16_str,
						    &utf16_bytes_left,
						    &utf8_str,
						    &utf8_bytes_left);
			utf8_str = utf8_str_save;
			utf16_str = utf16_str_save;
			if (utf16_bytes_left == 0 &&
			    utf8_bytes_left == 0 &&
			    num_chars_converted != (size_t)(-1))
			{
				utf8_str[utf8_expected_nbytes] = '\0';
				*utf8_str_ret = utf8_str;
				*utf8_nbytes_ret = utf8_expected_nbytes;
				ret = 0;
			} else {
				FREE(utf8_str);
				ret = WIMLIB_ERR_INVALID_UTF16_STRING;
			}
		} else
			ret = WIMLIB_ERR_NOMEM;
	} else
		ret = WIMLIB_ERR_INVALID_UTF16_STRING;
#endif /* WITH_NTFS_3G */

#ifdef ENABLE_ERROR_MESSAGES
	if (ret != 0) {
		ERROR_WITH_ERRNO("Error converting UTF-16LE string to UTF-8");
		ERROR("The failing string was:");
		print_string(utf16_str, utf16_nbytes);
		putchar('\n');
	}
#endif /* ENABLE_ERROR_MESSAGES */
	return ret;
}


/* Converts a string in the UTF-8 encoding to a newly allocated string in the
 * UTF-16 encoding.
 *
 * If available, do so by calling a similar function from libntfs-3g.
 * Otherwise, use iconv() along with the helper function utf8_to_utf16_size().
 */
int utf8_to_utf16(const char *utf8_str, size_t utf8_nbytes,
		  char **utf16_str_ret, size_t *utf16_nbytes_ret)
{
	int ret;
	if (utf8_nbytes == 0) {
		*utf16_str_ret = NULL;
		*utf16_nbytes_ret = 0;
		return 0;
	}
#ifdef WITH_NTFS_3G
	char *outs = NULL;
	int outs_nchars = ntfs_mbstoucs(utf8_str, (ntfschar**)&outs);
	if (outs_nchars >= 0) {
		*utf16_str_ret = outs;
		*utf16_nbytes_ret = (size_t)outs_nchars * 2;
		ret = 0;
	} else {
		if (errno == ENOMEM)
			ret = WIMLIB_ERR_NOMEM;
		else
			ret = WIMLIB_ERR_INVALID_UTF8_STRING;
	}
#else /* !WITH_NTFS_3G */

	ret = iconv_global_init();
	if (ret != 0)
		return ret;
	ret = utf8_to_utf16_size(utf8_str);
	if (ret >= 0) {
		size_t utf16_expected_nbytes;
		char  *utf16_str;
		size_t utf16_bytes_left;
		size_t utf8_bytes_left;
		size_t num_chars_converted;
		const char *utf8_str_save;
		char  *utf16_str_save;

		utf16_expected_nbytes = (size_t)ret * 2;
 		utf16_str = MALLOC(utf16_expected_nbytes + 2);
		if (utf16_str) {
			utf16_bytes_left = utf16_expected_nbytes;
			utf8_bytes_left = utf8_nbytes;
			utf8_str_save = utf8_str;
			utf16_str_save = utf16_str;
			num_chars_converted = iconv(cd_utf8_to_utf16,
						    (char**)&utf8_str,
						    &utf8_bytes_left,
						    &utf16_str,
						    &utf16_bytes_left);
			utf8_str = utf8_str_save;
			utf16_str = utf16_str_save;
			if (utf16_bytes_left == 0 &&
			    utf8_bytes_left == 0 &&
			    num_chars_converted != (size_t)(-1))
			{
				utf16_str[utf16_expected_nbytes] = '\0';
				utf16_str[utf16_expected_nbytes + 1] = '\0';
				*utf16_str_ret = utf16_str;
				*utf16_nbytes_ret = utf16_expected_nbytes;
				ret = 0;
			} else {
				FREE(utf16_str);
				ret = WIMLIB_ERR_INVALID_UTF8_STRING;
			}
		} else
			ret = WIMLIB_ERR_NOMEM;
	} else
		ret = WIMLIB_ERR_INVALID_UTF8_STRING;
#endif /* WITH_NTFS_3G */

#ifdef ENABLE_ERROR_MESSAGES
	if (ret != 0) {
		ERROR_WITH_ERRNO("Error converting UTF-8 string to UTF-16LE");
		ERROR("The failing string was:");
		print_string(utf8_str, utf8_nbytes);
		putchar('\n');
		ERROR("Length: %zu bytes", utf8_nbytes);
	}
#endif /* ENABLE_ERROR_MESSAGES */
	return ret;
}
