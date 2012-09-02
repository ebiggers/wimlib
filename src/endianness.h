#ifndef _WIMLIB_ENDIANNESS_H
#define _WIMLIB_ENDIANNESS_H


#include "config.h"
#include <inttypes.h>

#ifdef WORDS_BIGENDIAN

#ifndef bswap16
static inline uint16_t bswap16(uint16_t n)
{
	return (n << 8) | (n >> 8);
}
#endif

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
#endif


#ifndef bswap64
static inline uint64_t bswap64(uint64_t n)
{
#ifdef __GNUC__
	return __builtin_bswap64(n);
#else
	return (n << 56) | ((n & 0xff00) << 40) | ((n & 0xff0000) << 24) | 
			((n & 0xff000000) << 8) | ((n & 0xff00000000) >> 8) | 
			((n & 0xff0000000000) >> 24) | 
			((n & 0xff000000000000) >> 40) | (n >> 56);
#endif
}
#endif

/* Not in place */
#define to_le16(n) bswap16(n)
#define to_le32(n) bswap32(n)
#define to_le64(n) bswap64(n)

#ifndef _NTFS_ENDIANS_H
#define le16_to_cpu(n) bswap16(n)
#define le32_to_cpu(n) bswap32(n)
#define le64_to_cpu(n) bswap64(n)
#endif

/* In place */
#define TO_LE16(n) ((n) = to_le16(n))
#define TO_LE32(n) ((n) = to_le32(n))
#define TO_LE64(n) ((n) = to_le64(n))

static inline void array_to_le16(uint16_t *p, uint64_t n)
{
	while (n--)
		*p++ = to_le16(*p);
}
static inline void array_to_le32(uint32_t *p, uint64_t n)
{
	while (n--)
		*p++ = to_le32(*p);
}
static inline void array_to_le64(uint64_t *p, uint64_t n)
{
	while (n--)
		*p++ = to_le64(*p);
}

#else

/* Little endian. */

/* Not in place */
#define to_le16(n) (n)
#define to_le32(n) (n)
#define to_le64(n) (n)

#ifndef _NTFS_ENDIANS_H
#define le16_to_cpu(n) (n)
#define le32_to_cpu(n) (n)
#define le64_to_cpu(n) (n)
#endif

/* In place */
#define TO_LE16(n)
#define TO_LE32(n)
#define TO_LE64(n)

#define array_to_le16(p, n)
#define array_to_le32(p, n)
#define array_to_le64(p, n)

#endif


#endif /* _WIMLIB_ENDIANNESS_H */
