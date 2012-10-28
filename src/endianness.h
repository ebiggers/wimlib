#ifndef _WIMLIB_ENDIANNESS_H
#define _WIMLIB_ENDIANNESS_H


#include "config.h"
#include <inttypes.h>

/* Watch out for conflicts with ntfs-3g headers... */

#ifndef bswap16
static inline uint16_t bswap16(uint16_t n)
{
	return (n << 8) | (n >> 8);
}
#endif /* ifndef bswap16 */

#ifndef bswap32
static inline uint32_t bswap32(uint32_t n)
{
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
	return __builtin_bswap32(n);
#else
	return (n << 24) | ((n & 0xff00) << 8) | ((n & 0xff0000) >> 8) |
							(n >> 24);
#endif
}
#endif /* ifndef bswap32 */

#ifndef bswap64
static inline uint64_t bswap64(uint64_t n)
{
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
	return __builtin_bswap64(n);
#else
	return (n << 56) | ((n & 0xff00) << 40) | ((n & 0xff0000) << 24) |
			((n & 0xff000000) << 8) | ((n & 0xff00000000) >> 8) |
			((n & 0xff0000000000) >> 24) |
			((n & 0xff000000000000) >> 40) | (n >> 56);
#endif
}
#endif /* ifndef bswap64 */


#ifndef _NTFS_ENDIANS_H
#	ifdef WORDS_BIGENDIAN
#		define le16_to_cpu(n) bswap16(n)
#		define le32_to_cpu(n) bswap32(n)
#		define le64_to_cpu(n) bswap64(n)
#		define cpu_to_le16(n) bswap16(n)
#		define cpu_to_le32(n) bswap32(n)
#		define cpu_to_le64(n) bswap64(n)
#	else
#		define cpu_to_le16(n) (n)
#		define cpu_to_le32(n) (n)
#		define cpu_to_le64(n) (n)
#		define le16_to_cpu(n) (n)
#		define le32_to_cpu(n) (n)
#		define le64_to_cpu(n) (n)
#	endif
#endif

static inline void array_cpu_to_le32(uint32_t *p, uint64_t n)
{
	while (n--)
		*p++ = cpu_to_le32(*p);
}

static inline void array_le32_to_cpu(uint32_t *p, uint64_t n)
{
	while (n--)
		*p++ = le32_to_cpu(*p);
}

static inline void array_cpu_to_le64(uint64_t *p, uint64_t n)
{
	while (n--)
		*p++ = cpu_to_le64(*p);
}

static inline void array_le64_to_cpu(uint64_t *p, uint64_t n)
{
	while (n--)
		*p++ = le64_to_cpu(*p);
}

#endif /* _WIMLIB_ENDIANNESS_H */
