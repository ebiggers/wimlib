/*
 * compiler.h
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_COMPILER_H
#define _WIMLIB_COMPILER_H

#ifdef __GNUC__
#	if defined(__CYGWIN__) || defined(__WIN32__)
#		define WIMLIBAPI __declspec(dllexport)
#	else
#		define WIMLIBAPI __attribute__((visibility("default")))
#	endif
#	define _always_inline_attribute inline __attribute__((always_inline))
#	define _no_inline_attribute __attribute__((noinline))
#	define _packed_attribute __attribute__((packed))
#	define _format_attribute(type, format_str, args_start) \
			/*__attribute__((format(type, format_str, args_start))) */
#	if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)
#		define _cold_attribute     __attribute__((cold))
#	else
#		define _cold_attribute
#	endif
#	define _malloc_attribute __attribute__((malloc))
#	define _warn_unused_result_attribute __attribute__((warn_unused_result))
#	define _aligned_attribute(size) __attribute__((aligned(size)))
#	define likely(x) __builtin_expect(!!(x), 1)
#	define unlikely(x) __builtin_expect(!!(x), 0)
#	define inline inline __attribute__((always_inline))
#	define prefetch(x) __builtin_prefetch(x)
#	define is_constant(x) __builtin_constant_p(x)
#else
#	define WIMLIBAPI
#	define _always_inline_attribute inline
#	define _no_inline_attribute
#	define _format_attribute(type, format_str, args_start)
#	define _cold_attribute
#	define _packed_attribute
#	define _malloc_attribute
#	define _warn_unused_result_attribute
#	define _aligned_attribute(size)
#	define likely(x) (x)
#	define unlikely(x) (x)
#	define prefetch(x)
#	define is_constant(x) (0)
#endif /* __GNUC__ */

#ifdef __CHECKER__
#  define _bitwise_attr	__attribute__((bitwise))
#  define _force_attr	__attribute__((force))
#else
#  define _bitwise_attr
#  define _force_attr
#endif

#endif /* _WIMLIB_COMPILER_H */
