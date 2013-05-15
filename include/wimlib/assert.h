#ifndef _WIMLIB_ASSERT_H
#define _WIMLIB_ASSERT_H

#ifdef ENABLE_ASSERTIONS
#include <assert.h>
#  define wimlib_assert(expr) assert(expr)
#else
#  define wimlib_assert(expr)
#endif

#ifdef ENABLE_MORE_ASSERTIONS
#  define wimlib_assert2(expr) wimlib_assert(expr)
#else
#  define wimlib_assert2(expr)
#endif

#endif /* _WIMLIB_ASSERT_H */
