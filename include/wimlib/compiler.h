/*
 * compiler.h
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_COMPILER_H
#define _WIMLIB_COMPILER_H

#ifdef __GNUC__
#  include "wimlib/compiler-gcc.h"
#else
#  error "Unrecognized compiler.  Please add a header file for your compiler."
#endif

#ifndef WIMLIBAPI
#  define WIMLIBAPI
#endif

#ifndef _packed_attribute
#  error "missing required definition of _packed_attribute"
#endif

#ifndef _aligned_attribute
#  error "missing required definition of _aligned_attribute"
#endif

#ifndef _may_alias_attribute
#  error "missing required definition of _may_alias_attribute"
#endif

#ifndef likely
#  define likely(expr)		(expr)
#endif

#ifndef unlikely
#  define unlikely(expr)	(expr)
#endif

/* prefetchr() - prefetch into L1 cache for read  */
#ifndef prefetchr
#  define prefetchr(addr)
#endif

/* prefetchw() - prefetch into L1 cache for write  */
#ifndef prefetchw
#  define prefetchw(addr)
#endif

#ifndef _cold_attribute
#  define _cold_attribute
#endif

#ifndef _malloc_attribute
#  define _malloc_attribute
#endif

#ifndef _format_attribute
#  define _format_attribute(type, format_str, format_start)
#endif

#ifndef noinline
#  define noinline
#endif

/* Same as 'noinline', but 'noinline_for_stack' documents that 'noinline' is
 * being used to prevent the annotated function from being inlined into a
 * recursive function and increasing its stack usage.  */
#define noinline_for_stack	noinline

#ifndef CPU_IS_BIG_ENDIAN
#  error "missing required endianness definition"
#endif

#define CPU_IS_LITTLE_ENDIAN (!CPU_IS_BIG_ENDIAN)

#ifndef UNALIGNED_ACCESS_SPEED
#  define UNALIGNED_ACCESS_SPEED 0
#endif

#define UNALIGNED_ACCESS_IS_ALLOWED	(UNALIGNED_ACCESS_SPEED >= 1)
#define UNALIGNED_ACCESS_IS_FAST	(UNALIGNED_ACCESS_SPEED >= 2)
#define UNALIGNED_ACCESS_IS_VERY_FAST	(UNALIGNED_ACCESS_SPEED >= 3)

#ifndef typeof
#  error "missing required definition of typeof"
#endif

#if !defined(min) || !defined(max) || !defined(swap)
#  error "missing required definitions of min(), max(), and swap() macros"
#endif

#ifdef __CHECKER__
#  define _bitwise_attr	__attribute__((bitwise))
#  define _force_attr	__attribute__((force))
#else
#  define _bitwise_attr
#  define _force_attr
#endif

/* STATIC_ASSERT() - verify the truth of an expression at compilation time.  */
#if __STDC_VERSION__ >= 201112L
#  define STATIC_ASSERT(expr)	_Static_assert((expr), "")
#else
#  define STATIC_ASSERT(expr)	((void)sizeof(char[1 - 2 * !(expr)]))
#endif

#endif /* _WIMLIB_COMPILER_H */
