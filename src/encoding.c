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
static u16 upcase[65536];

/*
 * Initialize the 'upcase' table.
 *
 * Code modified from NTFS-3g, original copyright notices below:
 *
 * Copyright (c) 2000-2004 Anton Altaparmakov
 * Copyright (c) 2002-2009 Szabolcs Szakacsits
 * Copyright (c) 2008-2011 Jean-Pierre Andre
 * Copyright (c) 2008      Bernhard Kaindl
 *
 * License GPLv2 or later.
 *
 * The expanded table itself is the same as that used by Windows Vista for
 * NTFS case insensitivity.
 */
void
init_upcase(void)
{
	/*
	 *	This is the table as defined by Vista
	 */
	/*
	 * "Start" is inclusive and "End" is exclusive, every value has the
	 * value of "Add" added to it.
	 */
	static const u16 uc_run_table[][3] = { /* Start, End, Add */
	{0x0061, 0x007b,   -32}, {0x00e0, 0x00f7,  -32}, {0x00f8, 0x00ff, -32},
	{0x0256, 0x0258,  -205}, {0x028a, 0x028c, -217}, {0x037b, 0x037e, 130},
	{0x03ac, 0x03ad,   -38}, {0x03ad, 0x03b0,  -37}, {0x03b1, 0x03c2, -32},
	{0x03c2, 0x03c3,   -31}, {0x03c3, 0x03cc,  -32}, {0x03cc, 0x03cd, -64},
	{0x03cd, 0x03cf,   -63}, {0x0430, 0x0450,  -32}, {0x0450, 0x0460, -80},
	{0x0561, 0x0587,   -48}, {0x1f00, 0x1f08,    8}, {0x1f10, 0x1f16,   8},
	{0x1f20, 0x1f28,     8}, {0x1f30, 0x1f38,    8}, {0x1f40, 0x1f46,   8},
	{0x1f51, 0x1f52,     8}, {0x1f53, 0x1f54,    8}, {0x1f55, 0x1f56,   8},
	{0x1f57, 0x1f58,     8}, {0x1f60, 0x1f68,    8}, {0x1f70, 0x1f72,  74},
	{0x1f72, 0x1f76,    86}, {0x1f76, 0x1f78,  100}, {0x1f78, 0x1f7a, 128},
	{0x1f7a, 0x1f7c,   112}, {0x1f7c, 0x1f7e,  126}, {0x1f80, 0x1f88,   8},
	{0x1f90, 0x1f98,     8}, {0x1fa0, 0x1fa8,    8}, {0x1fb0, 0x1fb2,   8},
	{0x1fb3, 0x1fb4,     9}, {0x1fcc, 0x1fcd,   -9}, {0x1fd0, 0x1fd2,   8},
	{0x1fe0, 0x1fe2,     8}, {0x1fe5, 0x1fe6,    7}, {0x1ffc, 0x1ffd,  -9},
	{0x2170, 0x2180,   -16}, {0x24d0, 0x24ea,  -26}, {0x2c30, 0x2c5f, -48},
	{0x2d00, 0x2d26, -7264}, {0xff41, 0xff5b,  -32},
	};
	/*
	 * "Start" is exclusive and "End" is inclusive, every second value is
	 * decremented by one.
	 */
	static const u16 uc_dup_table[][2] = { /* Start, End */
	{0x0100, 0x012f}, {0x0132, 0x0137}, {0x0139, 0x0149}, {0x014a, 0x0178},
	{0x0179, 0x017e}, {0x01a0, 0x01a6}, {0x01b3, 0x01b7}, {0x01cd, 0x01dd},
	{0x01de, 0x01ef}, {0x01f4, 0x01f5}, {0x01f8, 0x01f9}, {0x01fa, 0x0220},
	{0x0222, 0x0234}, {0x023b, 0x023c}, {0x0241, 0x0242}, {0x0246, 0x024f},
	{0x03d8, 0x03ef}, {0x03f7, 0x03f8}, {0x03fa, 0x03fb}, {0x0460, 0x0481},
	{0x048a, 0x04bf}, {0x04c1, 0x04c4}, {0x04c5, 0x04c8}, {0x04c9, 0x04ce},
	{0x04ec, 0x04ed}, {0x04d0, 0x04eb}, {0x04ee, 0x04f5}, {0x04f6, 0x0513},
	{0x1e00, 0x1e95}, {0x1ea0, 0x1ef9}, {0x2183, 0x2184}, {0x2c60, 0x2c61},
	{0x2c67, 0x2c6c}, {0x2c75, 0x2c76}, {0x2c80, 0x2ce3},
	};
	/*
	 * Set the Unicode character at offset "Offset" to "Value".  Note,
	 * "Value" is host endian.
	 */
	static const u16 uc_byte_table[][2] = { /* Offset, Value */
	{0x00ff, 0x0178}, {0x0180, 0x0243}, {0x0183, 0x0182}, {0x0185, 0x0184},
	{0x0188, 0x0187}, {0x018c, 0x018b}, {0x0192, 0x0191}, {0x0195, 0x01f6},
	{0x0199, 0x0198}, {0x019a, 0x023d}, {0x019e, 0x0220}, {0x01a8, 0x01a7},
	{0x01ad, 0x01ac}, {0x01b0, 0x01af}, {0x01b9, 0x01b8}, {0x01bd, 0x01bc},
	{0x01bf, 0x01f7}, {0x01c6, 0x01c4}, {0x01c9, 0x01c7}, {0x01cc, 0x01ca},
	{0x01dd, 0x018e}, {0x01f3, 0x01f1}, {0x023a, 0x2c65}, {0x023e, 0x2c66},
	{0x0253, 0x0181}, {0x0254, 0x0186}, {0x0259, 0x018f}, {0x025b, 0x0190},
	{0x0260, 0x0193}, {0x0263, 0x0194}, {0x0268, 0x0197}, {0x0269, 0x0196},
	{0x026b, 0x2c62}, {0x026f, 0x019c}, {0x0272, 0x019d}, {0x0275, 0x019f},
	{0x027d, 0x2c64}, {0x0280, 0x01a6}, {0x0283, 0x01a9}, {0x0288, 0x01ae},
	{0x0289, 0x0244}, {0x028c, 0x0245}, {0x0292, 0x01b7}, {0x03f2, 0x03f9},
	{0x04cf, 0x04c0}, {0x1d7d, 0x2c63}, {0x214e, 0x2132},
	};

	for (u32 i = 0; i < 65536; i++)
		upcase[i] = i;

	for (u32 r = 0; r < ARRAY_LEN(uc_run_table); r++)
		for (u32 i = uc_run_table[r][0]; i < uc_run_table[r][1]; i++)
			upcase[i] = i + uc_run_table[r][2];

	for (u32 r = 0; r < ARRAY_LEN(uc_dup_table); r++)
		for (u32 i = uc_dup_table[r][0]; i < uc_dup_table[r][1]; i += 2)
			upcase[i + 1] = i;

	for (u32 r = 0; r < ARRAY_LEN(uc_byte_table); r++)
		upcase[uc_byte_table[r][0]] = uc_byte_table[r][1];

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
