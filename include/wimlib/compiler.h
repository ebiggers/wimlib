#ifndef _WIMLIB_COMPILER_H
#define _WIMLIB_COMPILER_H

#ifdef __GNUC__
#	if defined(__CYGWIN__) || defined(__WIN32__)
#		define WIMLIBAPI __declspec(dllexport)
#	else
#		define WIMLIBAPI __attribute__((visibility("default")))
#	endif
#	define ALWAYS_INLINE inline __attribute__((always_inline))
#	define PACKED __attribute__((packed))
#	define FORMAT(type, format_str, args_start) \
			/*__attribute__((format(type, format_str, args_start))) */
#	if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)
#		define COLD     __attribute__((cold))
#	else
#		define COLD
#	endif
#else
#	define WIMLIBAPI
#	define ALWAYS_INLINE inline
#	define FORMAT(type, format_str, args_start)
#	define COLD
#	define PACKED
#endif /* __GNUC__ */

#endif /* _WIMLIB_COMPILER_H */
