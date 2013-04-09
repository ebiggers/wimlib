/*
 * encoding.c
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

#include "wimlib_internal.h"

#include <errno.h>
#include <iconv.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

bool wimlib_mbs_is_utf8 = !TCHAR_IS_UTF16LE;

/* List of iconv_t conversion descriptors for a specific character conversion.
 * The idea is that it is not thread-safe to have just one conversion
 * descriptor, but it also is inefficient to open a new conversion descriptor to
 * convert every string.  Both these problems can be solved by maintaining a
 * list of conversion descriptors; then, a thread can use an existing conversion
 * descriptor if available. */
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

static iconv_t *
get_iconv(struct iconv_list_head *head)
{
	iconv_t cd;
	iconv_t *cd_p;
	struct iconv_node *i;

	pthread_mutex_lock(&head->mutex);
	if (list_empty(&head->list)) {
		cd = iconv_open(head->to_encoding, head->from_encoding);
		if (cd == (iconv_t)-1) {
			ERROR_WITH_ERRNO("Failed to open iconv from %s to %s",
					 head->from_encoding, head->to_encoding);
			cd_p = NULL;
		} else {
			i = MALLOC(sizeof(struct iconv_node));
			if (i) {
				i->head = head;
				i->cd = cd;
				cd_p = &i->cd;
			} else {
				iconv_close(cd);
				cd_p = NULL;
			}
		}
	} else {
		i = container_of(head->list.next, struct iconv_node, list);
		list_del(head->list.next);
		cd_p = &i->cd;
	}
	pthread_mutex_unlock(&head->mutex);
	return cd_p;
}

static void
put_iconv(iconv_t *cd)
{
	int errno_save = errno;
	struct iconv_node *i = container_of(cd, struct iconv_node, cd);
	struct iconv_list_head *head = i->head;

	pthread_mutex_lock(&head->mutex);
	list_add(&i->list, &head->list);
	pthread_mutex_unlock(&head->mutex);
	errno = errno_save;
}

/* Prevent printing an error message if a character conversion error occurs
 * while printing an error message.  (This variable is not per-thread but it
 * doesn't matter too much since it's just the error messages.) */
static bool error_message_being_printed = false;

#define DEFINE_CHAR_CONVERSION_FUNCTIONS(varname1, longname1, chartype1,\
					 varname2, longname2, chartype2,\
					 earlyreturn_on_utf8_locale,	\
					 earlyreturn_expr,		\
					 worst_case_len_expr,		\
					 err_return,			\
					 err_msg,			\
					 modifier)			\
static ICONV_LIST(iconv_##varname1##_to_##varname2,			\
		  longname1, longname2);				\
									\
modifier int								\
varname1##_to_##varname2##_nbytes(const chartype1 *in, size_t in_nbytes,\
				  size_t *out_nbytes_ret)		\
{									\
	iconv_t *cd = get_iconv(&iconv_##varname1##_to_##varname2);	\
	if (cd == NULL)							\
		return WIMLIB_ERR_ICONV_NOT_AVAILABLE;			\
									\
	/* Worst case length */						\
	chartype2 buf[worst_case_len_expr];				\
	char *inbuf = (char*)in;					\
	size_t inbytesleft = in_nbytes;					\
	char *outbuf = (char*)buf;					\
	size_t outbytesleft = sizeof(buf);				\
	size_t len;							\
	int ret;							\
									\
	len = iconv(*cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);	\
	if (len == (size_t)-1) {					\
		if (!error_message_being_printed) {			\
			error_message_being_printed = true;		\
			err_msg;					\
			error_message_being_printed = false;		\
		}							\
		ret = err_return;					\
	} else {							\
		*out_nbytes_ret = sizeof(buf) - outbytesleft;		\
		ret = 0;						\
	}								\
	put_iconv(cd);							\
	return ret;							\
}									\
									\
modifier int								\
varname1##_to_##varname2##_buf(const chartype1 *in, size_t in_nbytes,	\
			       chartype2 *out)				\
{									\
	iconv_t *cd = get_iconv(&iconv_##varname1##_to_##varname2);	\
	if (cd == NULL)							\
		return WIMLIB_ERR_ICONV_NOT_AVAILABLE;			\
									\
	char *inbuf = (char*)in;					\
	size_t inbytesleft = in_nbytes;					\
	char *outbuf = (char*)out;					\
	const size_t LARGE_NUMBER = 1000000000;				\
	size_t outbytesleft = LARGE_NUMBER;				\
	size_t len;							\
	int ret;							\
									\
	len = iconv(*cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);	\
	if (len == (size_t)-1) {					\
		if (!error_message_being_printed) {			\
			error_message_being_printed = true;		\
			err_msg;					\
			error_message_being_printed = false;		\
		}							\
		ret = err_return;					\
	} else {							\
		out[(LARGE_NUMBER-outbytesleft)/sizeof(chartype2)] = 0;	\
		ret = 0;						\
	}								\
	put_iconv(cd);							\
	return ret;							\
}									\
									\
modifier int								\
varname1##_to_##varname2(const chartype1 *in, size_t in_nbytes,		\
			 chartype2 **out_ret,				\
			 size_t *out_nbytes_ret)			\
{									\
	int ret;							\
	chartype2 *out;							\
	size_t out_nbytes;						\
									\
	if (earlyreturn_on_utf8_locale && wimlib_mbs_is_utf8) {		\
		earlyreturn_expr;					\
		/* Out same as in */					\
		out = MALLOC(in_nbytes + sizeof(chartype2));		\
		if (!out)						\
			return WIMLIB_ERR_NOMEM;			\
		memcpy(out, in, in_nbytes);				\
		out[in_nbytes / sizeof(chartype2)] = 0;			\
		*out_ret = out;						\
		*out_nbytes_ret = in_nbytes;				\
		return 0;						\
	}								\
									\
	ret = varname1##_to_##varname2##_nbytes(in, in_nbytes,		\
						&out_nbytes);		\
	if (ret)							\
		return ret;						\
									\
	out = MALLOC(out_nbytes + sizeof(chartype2));			\
	if (!out)							\
		return WIMLIB_ERR_NOMEM;				\
									\
	ret = varname1##_to_##varname2##_buf(in, in_nbytes, out);	\
	if (ret) {							\
		FREE(out);						\
	} else {							\
		*out_ret = out;						\
		*out_nbytes_ret = out_nbytes;				\
	}								\
	return ret;							\
}

#if !TCHAR_IS_UTF16LE

/* UNIX */

DEFINE_CHAR_CONVERSION_FUNCTIONS(utf8, "UTF-8", tchar,
				 utf16le, "UTF-16LE", utf16lechar,
				 false,
				 ,
				 in_nbytes * 2,
				 WIMLIB_ERR_INVALID_UTF8_STRING,
				 ERROR_WITH_ERRNO("Failed to convert UTF-8 string "
						  "to UTF-16LE string!"),
				 static)

DEFINE_CHAR_CONVERSION_FUNCTIONS(utf16le, "UTF-16LE", utf16lechar,
				 utf8, "UTF-8", tchar,
				 false,
				 ,
				 in_nbytes * 2,
				 WIMLIB_ERR_INVALID_UTF16_STRING,
				 ERROR_WITH_ERRNO("Failed to convert UTF-16LE string "
						  "to UTF-8 string!"),
				 static)

DEFINE_CHAR_CONVERSION_FUNCTIONS(tstr, "", tchar,
				 utf16le, "UTF-16LE", utf16lechar,
				 true,
				 return utf8_to_utf16le(in, in_nbytes, out_ret, out_nbytes_ret),
				 in_nbytes * 2,
				 WIMLIB_ERR_INVALID_MULTIBYTE_STRING,
				 ERROR_WITH_ERRNO("Failed to convert multibyte "
						  "string \"%"TS"\" to UTF-16LE string!", in);
				 ERROR("If the data you provided was UTF-8, please make sure "
				       "the character encoding\n"
				       "        of your current locale is UTF-8."),
				 )

DEFINE_CHAR_CONVERSION_FUNCTIONS(utf16le, "UTF-16LE", utf16lechar,
				 tstr, "", tchar,
				 true,
				 return utf16le_to_utf8(in, in_nbytes, out_ret, out_nbytes_ret),
				 in_nbytes * 2,
				 WIMLIB_ERR_UNICODE_STRING_NOT_REPRESENTABLE,
				 ERROR("Failed to convert UTF-16LE string to "
				       "multibyte string!");
				 ERROR("This may be because the UTF-16LE string "
				       "could not be represented\n"
				       "        in your locale's character encoding."),
				 )
#endif

/* tchar to UTF-8 and back */
#if TCHAR_IS_UTF16LE

/* Windows */
DEFINE_CHAR_CONVERSION_FUNCTIONS(tstr, "UTF-16LE", tchar,
				 utf8, "UTF-8", char,
				 false,
				 ,
				 in_nbytes * 2,
				 WIMLIB_ERR_INVALID_UTF16_STRING,
				 ERROR_WITH_ERRNO("Failed to convert UTF-16LE "
						  "string \"%"TS"\" to UTF-8 string!", in),
				 static)

DEFINE_CHAR_CONVERSION_FUNCTIONS(utf8, "UTF-8", char,
				 tstr, "UTF-16LE", tchar,
				 false,
				 ,
				 in_nbytes * 2,
				 WIMLIB_ERR_INVALID_UTF8_STRING,
				 ERROR_WITH_ERRNO("Failed to convert UTF-8 string "
						  "to UTF-16LE string!"),
				 static)
#else

/* UNIX */

DEFINE_CHAR_CONVERSION_FUNCTIONS(tstr, "", tchar,
				 utf8, "UTF-8", char,
				 true,
				 ,
				 in_nbytes * 4,
				 WIMLIB_ERR_INVALID_MULTIBYTE_STRING,
				 ERROR_WITH_ERRNO("Failed to convert multibyte "
						  "string \"%"TS"\" to UTF-8 string!", in);
				 ERROR("If the data you provided was UTF-8, please make sure "
				       "the character\n"
				       "        encoding of your current locale is UTF-8."),
				 static)

DEFINE_CHAR_CONVERSION_FUNCTIONS(utf8, "UTF-8", char,
				 tstr, "", tchar,
				 true,
				 ,
				 in_nbytes * 4,
				 WIMLIB_ERR_UNICODE_STRING_NOT_REPRESENTABLE,
				 ERROR("Failed to convert UTF-8 string to "
				       "multibyte string!");
				 ERROR("This may be because the UTF-8 data "
				       "could not be represented\n"
				       "        in your locale's character encoding."),
				 static)
#endif

int
tstr_to_utf8_simple(const tchar *tstr, char **out)
{
	size_t out_nbytes;
	return tstr_to_utf8(tstr, tstrlen(tstr) * sizeof(tchar),
			    out, &out_nbytes);
}

int
utf8_to_tstr_simple(const char *utf8str, tchar **out)
{
	size_t out_nbytes;
	return utf8_to_tstr(utf8str, strlen(utf8str), out, &out_nbytes);
}

static void
iconv_cleanup(struct iconv_list_head *head)
{
	pthread_mutex_destroy(&head->mutex);
	while (!list_empty(&head->list)) {
		struct iconv_node *i;

		i = container_of(head->list.next, struct iconv_node, list);
		list_del(&i->list);
		iconv_close(i->cd);
		FREE(i);
	}
}

void
iconv_global_cleanup()
{
	iconv_cleanup(&iconv_utf8_to_tstr);
	iconv_cleanup(&iconv_tstr_to_utf8);
#if !TCHAR_IS_UTF16LE
	iconv_cleanup(&iconv_utf16le_to_tstr);
	iconv_cleanup(&iconv_tstr_to_utf16le);
#endif
}
