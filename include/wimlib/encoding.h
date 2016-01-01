#ifndef _WIMLIB_ENCODING_H
#define _WIMLIB_ENCODING_H

#include <string.h>

#include "wimlib/error.h"
#include "wimlib/util.h"
#include "wimlib/types.h"

extern void
iconv_global_init(void);

extern void
iconv_global_cleanup(void);

extern u16 upcase[65536];

extern void
init_upcase(void);

extern bool wimlib_mbs_is_utf8;

#define DECLARE_CHAR_CONVERSION_FUNCTIONS(varname1, varname2,		\
					  chartype1, chartype2)		\
									\
extern int								\
varname1##_to_##varname2(const chartype1 *in, size_t in_nbytes,		\
			 chartype2 **out_ret,				\
			 size_t *out_nbytes_ret);			\
									\
extern int								\
varname1##_to_##varname2##_nbytes(const chartype1 *in, size_t in_nbytes,\
				  size_t *out_nbytes_ret);		\
									\
extern int								\
varname1##_to_##varname2##_buf(const chartype1 *in, size_t in_nbytes,	\
			       chartype2 *out);

extern utf16lechar *
utf16le_dupz(const void *ustr, size_t usize);

extern utf16lechar *
utf16le_dup(const utf16lechar *ustr);

extern size_t
utf16le_len_bytes(const utf16lechar *s);

extern size_t
utf16le_len_chars(const utf16lechar *s);

#if !TCHAR_IS_UTF16LE
DECLARE_CHAR_CONVERSION_FUNCTIONS(utf16le, tstr, utf16lechar, tchar);
DECLARE_CHAR_CONVERSION_FUNCTIONS(tstr, utf16le, tchar, utf16lechar);
#else

static inline int
tstr_to_utf16le(const tchar *tstr, size_t tsize,
		utf16lechar **ustr_ret, size_t *usize_ret)
{
	utf16lechar *ustr = utf16le_dupz(tstr, tsize);
	if (!ustr)
		return WIMLIB_ERR_NOMEM;
	*ustr_ret = ustr;
	*usize_ret = tsize;
	return 0;
}

#define utf16le_to_tstr tstr_to_utf16le

#endif

DECLARE_CHAR_CONVERSION_FUNCTIONS(utf8, tstr, char, tchar);
DECLARE_CHAR_CONVERSION_FUNCTIONS(tstr, utf8, tchar, char);

extern int
utf8_to_tstr_simple(const char *utf8str, tchar **out);

extern int
tstr_to_utf8_simple(const tchar *tstr, char **out);

extern int
cmp_utf16le_strings(const utf16lechar *s1, size_t n1,
		    const utf16lechar *s2, size_t n2,
		    bool ignore_case);

extern int
cmp_utf16le_strings_z(const utf16lechar *s1, const utf16lechar *s2,
		      bool ignore_case);

/* Convert a string in the platform-dependent encoding to UTF-16LE, but if both
 * encodings are UTF-16LE, simply re-use the string.  Release with
 * tstr_put_utf16le() when done.  */
static inline int
tstr_get_utf16le_and_len(const tchar *tstr,
			 const utf16lechar **ustr_ret, size_t *usize_ret)
{
	size_t tsize = tstrlen(tstr) * sizeof(tchar);
#if TCHAR_IS_UTF16LE
	/* No conversion or copy needed  */
	*ustr_ret = tstr;
	*usize_ret = tsize;
	return 0;
#else
	return tstr_to_utf16le(tstr, tsize, (utf16lechar **)ustr_ret, usize_ret);
#endif
}

/* Convert a string in the platform-dependent encoding to UTF-16LE, but if both
 * encodings are UTF-16LE, simply re-use the string.  Release with
 * tstr_put_utf16le() when done.  */
static inline int
tstr_get_utf16le(const tchar *tstr, const utf16lechar **ustr_ret)
{
#if TCHAR_IS_UTF16LE
	/* No conversion or copy needed  */
	*ustr_ret = tstr;
	return 0;
#else
	size_t tsize = tstrlen(tstr) * sizeof(tchar);
	size_t dummy;
	return tstr_to_utf16le(tstr, tsize, (utf16lechar **)ustr_ret, &dummy);
#endif
}

/* Release a string acquired with tstr_get_utf16le() or
 * tstr_get_utf16le_and_len().  */
static inline void
tstr_put_utf16le(const utf16lechar *ustr)
{
#if !TCHAR_IS_UTF16LE
	FREE((void *)ustr);
#endif
}

/* Convert a UTF16-LE string to the platform-dependent encoding, but if both
 * encodings are UTF-16LE, simply re-use the string.  Release with
 * utf16le_put_tstr() when done.  */
static inline int
utf16le_get_tstr(const utf16lechar *ustr, size_t usize,
		 const tchar **tstr_ret, size_t *tsize_ret)
{
#if TCHAR_IS_UTF16LE
	/* No conversion or copy needed  */
	*tstr_ret = ustr;
	*tsize_ret = usize;
	return 0;
#else
	return utf16le_to_tstr(ustr, usize, (tchar **)tstr_ret, tsize_ret);
#endif
}

/* Release a string acquired with utf16le_get_tstr().  */
static inline void
utf16le_put_tstr(const tchar *tstr)
{
#if !TCHAR_IS_UTF16LE
	FREE((void *)tstr);
#endif
}

#endif /* _WIMLIB_ENCODING_H */
