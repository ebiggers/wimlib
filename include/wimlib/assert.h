#ifndef _WIMLIB_ASSERT_H
#define _WIMLIB_ASSERT_H

#ifdef ENABLE_ASSERTIONS
#include <assert.h>
#  define wimlib_assert(expr) assert(expr)
#else
#  define wimlib_assert(expr)
#endif

#endif /* _WIMLIB_ASSERT_H */
