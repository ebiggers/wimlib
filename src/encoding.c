/*
 * encoding.c:  Convert "multibyte" strings (the locale-default encoding---
 * generally, UTF-8 or something like ISO-8859-1) to UTF-16LE strings, and vice
 * versa.
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

#include "config.h"
#include "wimlib_internal.h"
#include <pthread.h>
#include "list.h"

#include <iconv.h>
#include <stdlib.h>

bool wimlib_mbs_is_utf8 = false;

struct iconv_list_head {
	const char *from_encoding;
	const char *to_encoding;
	struct list_head list;
	pthread_mutex_t mutex;
};

struct iconv_node {
	iconv_t cd;
	struct list_head list;
	struct iconv_list_head *head;
};

#define ICONV_LIST(name, from, to)			\
struct iconv_list_head name = {				\
	.from_encoding = from,				\
	.to_encoding = to,				\
	.list = LIST_HEAD_INIT(name.list),		\
	.mutex = PTHREAD_MUTEX_INITIALIZER,		\
}

static ICONV_LIST(iconv_mbs_to_utf16le, "", "UTF-16LE");
static ICONV_LIST(iconv_utf16le_to_mbs, "UTF-16LE", "");

static iconv_t *
get_iconv(struct iconv_list_head *head)
{
	iconv_t cd;
	struct iconv_node *i;

	pthread_mutex_lock(&head->mutex);
	if (list_empty(&head->list)) {
		cd = iconv_open(head->to_encoding, head->from_encoding);
		if (cd == (iconv_t)-1) {
			goto out_unlock;
		} else {
			i = MALLOC(sizeof(struct iconv_node));
			if (!i) {
				iconv_close(cd);
				cd = (iconv_t)-1;
				goto out_unlock;
			}
			i->head = head;
		}
	} else {
		i = container_of(head->list.next, struct iconv_node, list);
		list_del(head->list.next);
	}
	cd = i->cd;
out_unlock:
	pthread_mutex_unlock(&head->mutex);
	return cd;
}

static void
put_iconv(iconv_t *cd)
{
	struct iconv_node *i = container_of(cd, struct iconv_node, cd);
	struct iconv_list_head *head = i->head;
	
	pthread_mutex_lock(&head->mutex);
	list_add(&i->list, &head->list);
	pthread_mutex_unlock(&head->mutex);
}

int
mbs_to_utf16le_nbytes(const mbchar *mbs, size_t mbs_nbytes,
		      size_t *utf16le_nbytes_ret)
{
	iconv_t *cd = get_iconv(&iconv_mbs_to_utf16le);
	if (*cd == (iconv_t)-1)
		return WIMLIB_ERR_ICONV_NOT_AVAILABLE;

	/* Worst case length */
	utf16lechar buf[mbs_nbytes * 2];
	char *inbuf = (char*)mbs;
	char *outbuf = (char*)buf;
	size_t outbytesleft = sizeof(buf);
	size_t inbytesleft = mbs_nbytes;
	size_t len;
	int ret;

	len = iconv(*cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
	if (len == (size_t)-1) {
		ret = WIMLIB_ERR_INVALID_MULTIBYTE_STRING;
	} else {
		*utf16le_nbytes_ret = sizeof(buf) - outbytesleft;
		ret = 0;
	}
	put_iconv(cd);
	return ret;
}


int
utf16le_to_mbs_nbytes(const utf16lechar *utf16le_str, size_t utf16le_nbytes,
		      size_t *mbs_nbytes_ret)
{
	iconv_t *cd = get_iconv(&iconv_utf16le_to_mbs);
	if (*cd == (iconv_t)-1)
		return WIMLIB_ERR_ICONV_NOT_AVAILABLE;

	/* Worst case length */
	mbchar buf[utf16le_nbytes / 2 * MB_CUR_MAX];
	char *inbuf = (char*)utf16le_str;
	char *outbuf = (char*)buf;
	size_t outbytesleft = sizeof(buf);
	size_t inbytesleft = utf16le_nbytes;
	size_t len;
	int ret;

	len = iconv(*cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
	if (len == (size_t)-1) {
		ERROR("Could not convert \"%W\" to encoding of current locale",
		      utf16le_str);
		/* EILSEQ is supposed to mean that the *input* is invalid, but
		 * it's also returned if any input characters are not
		 * representable in the output encoding.  (The actual behavior
		 * in this case is undefined for some reason...).  Assume it's
		 * the latter error case. */
		ret = WIMLIB_ERR_UNICODE_STRING_NOT_REPRESENTABLE;
	} else {
		*mbs_nbytes_ret  = sizeof(buf) - outbytesleft;
		ret = 0;
	}
	put_iconv(cd);
	return ret;
}

int
mbs_to_utf16le_buf(const mbchar *mbs, size_t mbs_nbytes,
		   utf16lechar *utf16le_str)
{
	iconv_t *cd = get_iconv(&iconv_mbs_to_utf16le);
	if (*cd == (iconv_t)-1)
		return WIMLIB_ERR_ICONV_NOT_AVAILABLE;

	char *inbuf = (char*)mbs;
	size_t inbytesleft = mbs_nbytes;
	char *outbuf = (char*)utf16le_str;
	size_t outbytesleft = SIZE_MAX;
	size_t len;
	int ret;

	len = iconv(*cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
	if (len == (size_t)-1) {
		ret = WIMLIB_ERR_INVALID_MULTIBYTE_STRING;
	} else {
		ret = 0;
	}
	put_iconv(cd);
	return ret;
}

int
utf16le_to_mbs_buf(const utf16lechar *utf16le_str, size_t utf16le_nbytes,
		   mbchar *mbs)
{
	int ret;
	iconv_t *cd = get_iconv(&iconv_utf16le_to_mbs);
	if (*cd == (iconv_t)-1)
		return WIMLIB_ERR_ICONV_NOT_AVAILABLE;

	char *inbuf = (char*)utf16le_str;
	size_t inbytesleft;
	char *outbuf = (char*)mbs;
	size_t outbytesleft = SIZE_MAX;
	size_t len;

	len = iconv(*cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
	if (len == (size_t)-1) {
		ret = WIMLIB_ERR_INVALID_UTF16_STRING;
	} else {
		ret = 0;
	}
	mbs[SIZE_MAX - inbytesleft] = '\0';
	put_iconv(cd);
	return ret;
}

int
mbs_to_utf16le(const mbchar *mbs, size_t mbs_nbytes,
	       utf16lechar **utf16le_ret, size_t *utf16le_nbytes_ret)
{
	int ret;
	utf16lechar *utf16le_str;
	size_t utf16le_nbytes;

	ret = mbs_to_utf16le_nbytes(mbs, mbs_nbytes,
				    &utf16le_nbytes);
	if (ret)
		return ret;

	utf16le_str = MALLOC(utf16le_nbytes + 1);
	if (!utf16le_str)
		return WIMLIB_ERR_NOMEM;

	ret = mbs_to_utf16le_buf(mbs, mbs_nbytes, utf16le_str);
	if (ret) {
		FREE(utf16le_str);
	} else {
		*utf16le_ret = utf16le_str;
		*utf16le_nbytes_ret = utf16le_nbytes;
	}
	return ret;
}


int
utf16le_to_mbs(const utf16lechar *utf16le_str, size_t utf16le_nbytes,
	       mbchar **mbs_ret, size_t *mbs_nbytes_ret)
{
	int ret;
	mbchar *mbs;
	size_t mbs_nbytes;

	ret = utf16le_to_mbs_nbytes(utf16le_str, utf16le_nbytes,
				    &mbs_nbytes);
	if (ret)
		return ret;

	mbs = MALLOC(mbs_nbytes + 1);
	if (!mbs)
		return WIMLIB_ERR_NOMEM;

	ret = utf16le_to_mbs_buf(utf16le_str, utf16le_nbytes, mbs);
	if (ret) {
		FREE(mbs);
	} else {
		*mbs_ret = mbs;
		*mbs_nbytes_ret = mbs_nbytes;
	}
	return ret;
}

bool
utf8_str_contains_nonascii_chars(const utf8char *utf8_str)
{
	do {
		if ((unsigned char)*utf8_str > 127)
			return false;
	} while (*++utf8_str);
	return true;
}
