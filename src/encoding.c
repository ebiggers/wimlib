/*
 * encoding.c
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include <errno.h>
#include <iconv.h>
#include <pthread.h>
#include <string.h>

#include "wimlib.h"
#include "wimlib/alloca.h"
#include "wimlib/assert.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/list.h"
#include "wimlib/util.h"


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
	chartype2 *buf;							\
	size_t bufsize;							\
	bool buf_onheap;						\
	bufsize = (worst_case_len_expr) * sizeof(chartype2);		\
	/* Worst case length */						\
	if (bufsize <= STACK_MAX) {					\
		buf = alloca(bufsize);					\
		buf_onheap = false;					\
	} else {							\
		buf = MALLOC(bufsize);					\
		if (!buf)						\
			return WIMLIB_ERR_NOMEM;			\
		buf_onheap = true;					\
	}								\
									\
	char *inbuf = (char*)in;					\
	size_t inbytesleft = in_nbytes;					\
	char *outbuf = (char*)buf;					\
	size_t outbytesleft = bufsize;					\
	size_t len;							\
	int ret;							\
									\
	len = iconv(*cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);	\
	if (len == (size_t)-1) {					\
		err_msg;						\
		ret = err_return;					\
	} else {							\
		*out_nbytes_ret = bufsize - outbytesleft;		\
		ret = 0;						\
	}								\
	put_iconv(cd);							\
	if (buf_onheap)							\
		FREE(buf);						\
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
		err_msg;						\
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
				 )

DEFINE_CHAR_CONVERSION_FUNCTIONS(utf8, "UTF-8", char,
				 tstr, "UTF-16LE", tchar,
				 false,
				 ,
				 in_nbytes * 2,
				 WIMLIB_ERR_INVALID_UTF8_STRING,
				 ERROR_WITH_ERRNO("Failed to convert UTF-8 string "
						  "to UTF-16LE string!"),
				 )
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
				 )

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
				 )
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
iconv_init(struct iconv_list_head *head)
{
	pthread_mutex_init(&head->mutex, NULL);
	INIT_LIST_HEAD(&head->list);
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
iconv_global_init(void)
{
	iconv_init(&iconv_utf8_to_tstr);
	iconv_init(&iconv_tstr_to_utf8);
#if !TCHAR_IS_UTF16LE
	iconv_init(&iconv_utf16le_to_tstr);
	iconv_init(&iconv_tstr_to_utf16le);
	iconv_init(&iconv_utf16le_to_utf8);
	iconv_init(&iconv_utf8_to_utf16le);
#endif
}

void
iconv_global_cleanup(void)
{
	iconv_cleanup(&iconv_utf8_to_tstr);
	iconv_cleanup(&iconv_tstr_to_utf8);
#if !TCHAR_IS_UTF16LE
	iconv_cleanup(&iconv_utf16le_to_tstr);
	iconv_cleanup(&iconv_tstr_to_utf16le);
	iconv_cleanup(&iconv_utf16le_to_utf8);
	iconv_cleanup(&iconv_utf8_to_utf16le);
#endif
}

/* A table that maps from UCS-2 characters to their upper case equivalents.
 * Index and array values are both CPU endian.
 * Note: this is only an *approximation* of real UTF-16 case folding.
 */
u16 upcase[65536];

void
init_upcase(void)
{
	/* This is the table used in NTFS volumes formatted by Windows 10.
	 * It was compressed by tools/compress_upcase_table.c.  */
	static const u16 upcase_compressed[] = {
		0x0000, 0x0000, 0x0060, 0x0000, 0x0000, 0xffe0, 0x0019, 0x0061,
		0x0061, 0x0000, 0x001b, 0x005d, 0x0008, 0x0060, 0x0000, 0x0079,
		0x0000, 0x0000, 0x0000, 0xffff, 0x002f, 0x0100, 0x0002, 0x0000,
		0x0007, 0x012b, 0x0011, 0x0121, 0x002f, 0x0103, 0x0006, 0x0101,
		0x0000, 0x00c3, 0x0006, 0x0131, 0x0007, 0x012e, 0x0004, 0x0000,
		0x0003, 0x012f, 0x0000, 0x0061, 0x0004, 0x0130, 0x0000, 0x00a3,
		0x0003, 0x0000, 0x0000, 0x0082, 0x000b, 0x0131, 0x0006, 0x0189,
		0x0008, 0x012f, 0x0007, 0x012e, 0x0000, 0x0038, 0x0006, 0x0000,
		0x0000, 0xfffe, 0x0007, 0x01c4, 0x000f, 0x0101, 0x0000, 0xffb1,
		0x0015, 0x011e, 0x0004, 0x01cc, 0x002a, 0x0149, 0x0014, 0x0149,
		0x0007, 0x0000, 0x0009, 0x018c, 0x000b, 0x0138, 0x0000, 0x2a1f,
		0x0000, 0x2a1c, 0x0000, 0x0000, 0x0000, 0xff2e, 0x0000, 0xff32,
		0x0000, 0x0000, 0x0000, 0xff33, 0x0000, 0xff33, 0x0000, 0x0000,
		0x0000, 0xff36, 0x0000, 0x0000, 0x0000, 0xff35, 0x0004, 0x0000,
		0x0002, 0x0257, 0x0000, 0x0000, 0x0000, 0xff31, 0x0004, 0x0000,
		0x0000, 0xff2f, 0x0000, 0xff2d, 0x0000, 0x0000, 0x0000, 0x29f7,
		0x0003, 0x0000, 0x0002, 0x0269, 0x0000, 0x29fd, 0x0000, 0xff2b,
		0x0002, 0x0000, 0x0000, 0xff2a, 0x0007, 0x0000, 0x0000, 0x29e7,
		0x0002, 0x0000, 0x0000, 0xff26, 0x0005, 0x027e, 0x0003, 0x027e,
		0x0000, 0xffbb, 0x0000, 0xff27, 0x0000, 0xff27, 0x0000, 0xffb9,
		0x0005, 0x0000, 0x0000, 0xff25, 0x0065, 0x007b, 0x0079, 0x0293,
		0x0008, 0x012d, 0x0003, 0x019c, 0x0002, 0x037b, 0x002e, 0x0000,
		0x0000, 0xffda, 0x0000, 0xffdb, 0x0002, 0x03ad, 0x0012, 0x0060,
		0x000a, 0x0060, 0x0000, 0xffc0, 0x0000, 0xffc1, 0x0000, 0xffc1,
		0x0008, 0x0000, 0x0000, 0xfff8, 0x001a, 0x0118, 0x0000, 0x0007,
		0x0008, 0x018d, 0x0009, 0x0233, 0x0046, 0x0035, 0x0006, 0x0061,
		0x0000, 0xffb0, 0x000f, 0x0450, 0x0025, 0x010e, 0x000a, 0x036b,
		0x0032, 0x048b, 0x000e, 0x0100, 0x0000, 0xfff1, 0x0037, 0x048a,
		0x0026, 0x0465, 0x0034, 0x0000, 0x0000, 0xffd0, 0x0025, 0x0561,
		0x00de, 0x0293, 0x1714, 0x0587, 0x0000, 0x8a04, 0x0003, 0x0000,
		0x0000, 0x0ee6, 0x0087, 0x02ee, 0x0092, 0x1e01, 0x0069, 0x1df7,
		0x0000, 0x0008, 0x0007, 0x1f00, 0x0008, 0x0000, 0x000e, 0x1f02,
		0x0008, 0x1f0e, 0x0010, 0x1f06, 0x001a, 0x1f06, 0x0002, 0x1f0f,
		0x0007, 0x1f50, 0x0017, 0x1f19, 0x0000, 0x004a, 0x0000, 0x004a,
		0x0000, 0x0056, 0x0003, 0x1f72, 0x0000, 0x0064, 0x0000, 0x0064,
		0x0000, 0x0080, 0x0000, 0x0080, 0x0000, 0x0070, 0x0000, 0x0070,
		0x0000, 0x007e, 0x0000, 0x007e, 0x0028, 0x1f1e, 0x000c, 0x1f06,
		0x0000, 0x0000, 0x0000, 0x0009, 0x000f, 0x0000, 0x000d, 0x1fb3,
		0x000d, 0x1f44, 0x0008, 0x1fcd, 0x0006, 0x03f2, 0x0015, 0x1fbb,
		0x014e, 0x0587, 0x0000, 0xffe4, 0x0021, 0x0000, 0x0000, 0xfff0,
		0x000f, 0x2170, 0x000a, 0x0238, 0x0346, 0x0587, 0x0000, 0xffe6,
		0x0019, 0x24d0, 0x0746, 0x0587, 0x0026, 0x0561, 0x000b, 0x057e,
		0x0004, 0x012f, 0x0000, 0xd5d5, 0x0000, 0xd5d8, 0x000c, 0x022e,
		0x000e, 0x03f8, 0x006e, 0x1e33, 0x0011, 0x0000, 0x0000, 0xe3a0,
		0x0025, 0x2d00, 0x17f2, 0x0587, 0x6129, 0x2d26, 0x002e, 0x0201,
		0x002a, 0x1def, 0x0098, 0xa5b7, 0x0040, 0x1dff, 0x000e, 0x0368,
		0x000d, 0x022b, 0x034c, 0x2184, 0x5469, 0x2d26, 0x007f, 0x0061,
		0x0040, 0x0000,
	};

	/* Simple LZ decoder  */
	const u16 *in_next = upcase_compressed;
	for (u32 i = 0; i < ARRAY_LEN(upcase); ) {
		u16 length = *in_next++;
		u16 src_pos = *in_next++;
		if (length == 0) {
			/* Literal */
			upcase[i++] = src_pos;
		} else {
			/* Match */
			do {
				upcase[i++] = upcase[src_pos++];
			} while (--length);
		}
	}

	/* Delta filter  */
	for (u32 i = 0; i < ARRAY_LEN(upcase); i++)
		upcase[i] += i;

#if 0
	/* Sanity checks  */
	wimlib_assert(upcase['a'] == 'A');
	wimlib_assert(upcase['A'] == 'A');
	wimlib_assert(upcase['z'] == 'Z');
	wimlib_assert(upcase['Z'] == 'Z');
	wimlib_assert(upcase['1'] == '1');
	wimlib_assert(upcase[0x00e9] == 0x00c9); /* Latin letter e, with acute accent  */
	wimlib_assert(upcase[0x00c9] == 0x00c9);
	wimlib_assert(upcase[0x03c1] == 0x03a1); /* Greek letter rho  */
	wimlib_assert(upcase[0x03a1] == 0x03a1);
	wimlib_assert(upcase[0x0436] == 0x0416); /* Cyrillic letter zhe  */
	wimlib_assert(upcase[0x0416] == 0x0416);
	wimlib_assert(upcase[0x0567] == 0x0537); /* Armenian letter eh  */
	wimlib_assert(upcase[0x0537] == 0x0537);
	wimlib_assert(upcase[0x24d0] == 0x24b6); /* Circled Latin letter A
						    (is that a real character???)  */
	wimlib_assert(upcase[0x24b6] == 0x24b6);
	wimlib_assert(upcase[0x2603] == 0x2603); /* Note to self: Upper case
						    snowman symbol does not
						    exist.  */
#endif
}

/* Compare UTF-16LE strings case-sensitively (%ignore_case == false) or
 * case-insensitively (%ignore_case == true).
 *
 * This is implemented using the default upper-case table used by NTFS.  It does
 * not handle all possible cases allowed by UTF-16LE.  For example, different
 * normalizations of the same sequence of "characters" are not considered equal.
 * It hopefully does the right thing most of the time though.  */
int
cmp_utf16le_strings(const utf16lechar *s1, size_t n1,
		    const utf16lechar *s2, size_t n2,
		    bool ignore_case)
{
	size_t n = min(n1, n2);

	if (ignore_case) {
		for (size_t i = 0; i < n; i++) {
			u16 c1 = upcase[le16_to_cpu(s1[i])];
			u16 c2 = upcase[le16_to_cpu(s2[i])];
			if (c1 != c2)
				return (c1 < c2) ? -1 : 1;
		}
	} else {
		for (size_t i = 0; i < n; i++) {
			u16 c1 = le16_to_cpu(s1[i]);
			u16 c2 = le16_to_cpu(s2[i]);
			if (c1 != c2)
				return (c1 < c2) ? -1 : 1;
		}
	}
	if (n1 == n2)
		return 0;
	return (n1 < n2) ? -1 : 1;
}

/* Like cmp_utf16le_strings(), but assumes the strings are null terminated.  */
int
cmp_utf16le_strings_z(const utf16lechar *s1, const utf16lechar *s2,
		      bool ignore_case)
{
	if (ignore_case) {
		for (;;) {
			u16 c1 = upcase[le16_to_cpu(*s1)];
			u16 c2 = upcase[le16_to_cpu(*s2)];
			if (c1 != c2)
				return (c1 < c2) ? -1 : 1;
			if (c1 == 0)
				return 0;
			s1++, s2++;
		}
	} else {
		while (*s1 && *s1 == *s2)
			s1++, s2++;
		if (*s1 == *s2)
			return 0;
		return (le16_to_cpu(*s1) < le16_to_cpu(*s2)) ? -1 : 1;
	}
}

/* Duplicate a UTF-16LE string.  The input string might not be null terminated
 * and might be misaligned, but the returned string is guaranteed to be null
 * terminated and properly aligned.  */
utf16lechar *
utf16le_dupz(const void *ustr, size_t usize)
{
	utf16lechar *dup = MALLOC(usize + sizeof(utf16lechar));
	if (dup) {
		memcpy(dup, ustr, usize);
		dup[usize / sizeof(utf16lechar)] = 0;
	}
	return dup;
}

/* Duplicate a null-terminated UTF-16LE string.  */
utf16lechar *
utf16le_dup(const utf16lechar *ustr)
{
	const utf16lechar *p = ustr;
	while (*p++)
		;
	return memdup(ustr, (const u8 *)p - (const u8 *)ustr);
}

/* Return the length, in bytes, of a UTF-null terminated UTF-16 string,
 * excluding the null terminator.  */
size_t
utf16le_len_bytes(const utf16lechar *s)
{
	const utf16lechar *p = s;
	while (*p)
		p++;
	return (p - s) * sizeof(utf16lechar);
}

/* Return the length, in UTF-16 coding units, of a UTF-null terminated UTF-16
 * string, excluding the null terminator.  */
size_t
utf16le_len_chars(const utf16lechar *s)
{
	return utf16le_len_bytes(s) / sizeof(utf16lechar);
}
