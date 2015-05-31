#ifndef _WIMLIB_ERROR_H
#define _WIMLIB_ERROR_H

#include <stdio.h>

#include "wimlib.h" /* Get error code definitions */
#include "wimlib/compiler.h"
#include "wimlib/types.h"

static inline int _format_attribute(printf, 1, 2)
dummy_tprintf(const tchar *format, ...)
{
	return 0;
}

#ifdef ENABLE_ERROR_MESSAGES
extern void
wimlib_error(const tchar *format, ...)
	_format_attribute(printf, 1, 2) _cold_attribute;

extern void
wimlib_error_with_errno(const tchar *format, ...)
		_format_attribute(printf, 1, 2) _cold_attribute;

extern void
wimlib_warning(const tchar *format, ...)
		_format_attribute(printf, 1, 2) _cold_attribute;

extern void
wimlib_warning_with_errno(const tchar *format, ...)
		_format_attribute(printf, 1, 2) _cold_attribute;
#  define ERROR(format, ...)			wimlib_error(T(format), ## __VA_ARGS__)
#  define ERROR_WITH_ERRNO(format, ...)		wimlib_error_with_errno(T(format), ## __VA_ARGS__)
#  define WARNING(format, ...)			wimlib_warning(T(format), ## __VA_ARGS__)
#  define WARNING_WITH_ERRNO(format, ...)	wimlib_warning_with_errno(T(format), ## __VA_ARGS__)
extern bool wimlib_print_errors;
extern FILE *wimlib_error_file;
#else /* ENABLE_ERROR_MESSAGES */
#  define wimlib_print_errors 0
#  define wimlib_error_file NULL
#  define ERROR(format, ...)			dummy_tprintf(T(format), ## __VA_ARGS__)
#  define ERROR_WITH_ERRNO(format, ...)		dummy_tprintf(T(format), ## __VA_ARGS__)
#  define WARNING(format, ...)			dummy_tprintf(T(format), ## __VA_ARGS__)
#  define WARNING_WITH_ERRNO(format, ...)	dummy_tprintf(T(format), ## __VA_ARGS__)
#endif /* !ENABLE_ERROR_MESSAGES */

extern void
print_byte_field(const u8 *field, size_t len, FILE *out);

#endif /* _WIMLIB_ERROR_H */
