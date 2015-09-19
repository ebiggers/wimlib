/*
 * compiler-gcc.h
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_COMPILER_GCC_H
#define _WIMLIB_COMPILER_GCC_H

#ifdef __WIN32__
#  define WIMLIBAPI __declspec(dllexport)
#else
#  define WIMLIBAPI __attribute__((visibility("default")))
#endif

#define _packed_attribute	__attribute__((packed))
#define _aligned_attribute(n)	__attribute__((aligned(n)))
#define _may_alias_attribute	__attribute__((may_alias))
#define likely(expr)		__builtin_expect(!!(expr), 1)
#define unlikely(expr)		__builtin_expect(!!(expr), 0)
#define prefetchr(addr)		__builtin_prefetch((addr), 0)
#define prefetchw(addr)		__builtin_prefetch((addr), 1)
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)
#  define _cold_attribute	__attribute__((cold))
#endif
#define _malloc_attribute	__attribute__((malloc))
#define inline			inline __attribute__((always_inline))
#define noinline		__attribute__((noinline))

/* Newer gcc supports __BYTE_ORDER__.  Older gcc doesn't.  */
#ifdef __BYTE_ORDER__
#  define CPU_IS_BIG_ENDIAN	(__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#elif defined(HAVE_CONFIG_H)
#  include "config.h"
#  ifdef WORDS_BIGENDIAN
#    define CPU_IS_BIG_ENDIAN 1
#  else
#    define CPU_IS_BIG_ENDIAN 0
#  endif
#endif

#if defined(__x86_64__) || defined(__i386__)
#  define UNALIGNED_ACCESS_SPEED 3
#elif defined(__ARM_FEATURE_UNALIGNED) && (__ARM_FEATURE_UNALIGNED == 1)
#  define UNALIGNED_ACCESS_SPEED 2
#else
#  define UNALIGNED_ACCESS_SPEED 0
#endif

#define typeof     __typeof__

#ifndef min
#  define min(a, b)  ({ typeof(a) _a = (a); typeof(b) _b = (b); \
			(_a < _b) ? _a : _b; })
#endif

#ifndef max
#  define max(a, b)  ({ typeof(a) _a = (a); typeof(b) _b = (b); \
			(_a > _b) ? _a : _b; })
#endif

#ifndef swap
#  define swap(a, b) ({ typeof(a) _a = (a); (a) = (b); (b) = _a; })
#endif

#if (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#  define compiler_bswap32 __builtin_bswap32
#  define compiler_bswap64 __builtin_bswap64
#endif

#if (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)
#  define compiler_bswap16 __builtin_bswap16
#endif

#define compiler_fls32(n)	(31 - __builtin_clz(n))
#define compiler_fls64(n)	(63 - __builtin_clzll(n))
#define compiler_ffs32(n)	__builtin_ctz(n)
#define compiler_ffs64(n)	__builtin_ctzll(n)

#endif /* _WIMLIB_COMPILER_GCC_H */
