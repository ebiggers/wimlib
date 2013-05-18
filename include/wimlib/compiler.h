#ifndef _WIMLIB_COMPILER_H
#define _WIMLIB_COMPILER_H

#ifdef __GNUC__
#	if defined(__CYGWIN__) || defined(__WIN32__)
#		define WIMLIBAPI __declspec(dllexport)
#	else
#		define WIMLIBAPI __attribute__((visibility("default")))
#	endif
#	define _always_inline_attribute inline __attribute__((always_inline))
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
#else
#	define WIMLIBAPI
#	define _always_inline_attribute inline
#	define _format_attribute(type, format_str, args_start)
#	define _cold_attribute
#	define _packed_attribute
#	define _malloc_attribute
#	define _warn_unused_result_attribute
#	define _aligned_attribute(size)
#	define likely(x) (x)
#	define unlikely(x) (x)
#endif /* __GNUC__ */

#endif /* _WIMLIB_COMPILER_H */
