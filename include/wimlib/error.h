#ifndef _WIMLIB_ERROR_H
#define _WIMLIB_ERROR_H

#include "wimlib.h" /* Get error code definitions */
#include "wimlib/compiler.h"
#include "wimlib/types.h"

#include <stdio.h>

#ifdef __WIN32__
#  define wimlib_fprintf fwprintf
#  define wimlib_printf	 wprintf
#else /* __WIN32__ */
extern int
wimlib_fprintf(FILE *fp, const tchar *format, ...) _format_attribute(printf, 2, 3);

extern int
wimlib_printf(const tchar *format, ...) _format_attribute(printf, 1, 2);
#endif /* !__WIN32__ */


static inline int
dummy_tprintf(const tchar *format, ...) _format_attribute(printf, 1, 2)
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
#  define ERROR_WITH_ERRNO(format, ...) 	wimlib_error_with_errno(T(format), ## __VA_ARGS__)
#  define WARNING(format, ...)			wimlib_warning(T(format), ## __VA_ARGS__)
#  define WARNING_WITH_ERRNO(format, ...)	wimlib_warning_with_errno(T(format), ## __VA_ARGS__)
#else /* ENABLE_ERROR_MESSAGES */
#  define ERROR(format, ...)			dummy_tprintf(T(format), ## __VA_ARGS__)
#  define ERROR_WITH_ERRNO(format, ...)		dummy_tprintf(T(format), ## __VA_ARGS__)
#  define WARNING(format, ...)			dummy_tprintf(T(format), ## __VA_ARGS__)
#  define WARNING_WITH_ERRNO(format, ...)	dummy_tprintf(T(format), ## __VA_ARGS__)
#endif /* !ENABLE_ERROR_MESSAGES */

#if defined(ENABLE_MORE_DEBUG) && !defined(ENABLE_DEBUG)
#  define ENABLE_DEBUG 1
#endif

#if defined(ENABLE_MORE_ASSERTIONS) && !defined(ENABLE_ASSERTIONS)
#  define ENABLE_ASSERTIONS 1
#endif

#ifdef ENABLE_DEBUG
extern void
wimlib_debug(const tchar *file, int line, const char *func,
	     const tchar *format, ...);
#  define DEBUG(format, ...) \
	 	wimlib_debug(T(__FILE__), __LINE__, __func__, T(format), ## __VA_ARGS__)

#else
#  define DEBUG(format, ...) dummy_tprintf(T(format), ## __VA_ARGS__)
#endif /* !ENABLE_DEBUG */

#ifdef ENABLE_MORE_DEBUG
#  define DEBUG2(format, ...) DEBUG(format, ## __VA_ARGS__)
#else
#  define DEBUG2(format, ...) dummy_tprintf(T(format), ## __VA_ARGS__)
#endif /* !ENABLE_MORE_DEBUG */

#endif /* _WIMLIB_ERROR_H */
