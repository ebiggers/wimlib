/*
 * endianness.h
 *
 * Macros and inline functions for endianness conversion.
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_ENDIANNESS_H
#define _WIMLIB_ENDIANNESS_H

#include "wimlib/compiler.h"
#include "wimlib/types.h"

/* Watch out for conflict with ntfs-3g/endians.h ... */
#ifndef _NTFS_ENDIANS_H

static inline u16 bswap16(u16 n)
{
#ifdef compiler_bswap16
	return compiler_bswap16(n);
#else
	return (n << 8) | (n >> 8);
#endif
}

static inline u32 bswap32(u32 n)
{
#ifdef compiler_bswap32
	return compiler_bswap32(n);
#else
	return (n << 24) |
	       ((n & 0xFF00) << 8) |
	       ((n & 0xFF0000) >> 8) |
	       (n >> 24);
#endif
}

static inline u64 bswap64(u64 n)
{
#ifdef compiler_bswap64
	return compiler_bswap64(n);
#else
	return (n << 56) |
	       ((n & 0xFF00) << 40) |
	       ((n & 0xFF0000) << 24) |
	       ((n & 0xFF000000) << 8) |
	       ((n & 0xFF00000000) >> 8) |
	       ((n & 0xFF0000000000) >> 24) |
	       ((n & 0xFF000000000000) >> 40) |
	       (n >> 56);
#endif
}

#if CPU_IS_BIG_ENDIAN
#  define cpu_to_le16(n) ((_force_attr le16)bswap16(n))
#  define cpu_to_le32(n) ((_force_attr le32)bswap32(n))
#  define cpu_to_le64(n) ((_force_attr le64)bswap64(n))
#  define le16_to_cpu(n) bswap16((_force_attr u16)(le16)(n))
#  define le32_to_cpu(n) bswap32((_force_attr u32)(le32)(n))
#  define le64_to_cpu(n) bswap64((_force_attr u64)(le64)(n))
#  define cpu_to_be16(n) ((_force_attr be16)(u16)(n))
#  define cpu_to_be32(n) ((_force_attr be32)(u32)(n))
#  define cpu_to_be64(n) ((_force_attr be64)(u64)(n))
#  define be16_to_cpu(n) ((_force_attr u16)(be16)(n))
#  define be32_to_cpu(n) ((_force_attr u32)(be32)(n))
#  define be64_to_cpu(n) ((_force_attr u64)(be64)(n))
#else
#  define cpu_to_le16(n) ((_force_attr le16)(u16)(n))
#  define cpu_to_le32(n) ((_force_attr le32)(u32)(n))
#  define cpu_to_le64(n) ((_force_attr le64)(u64)(n))
#  define le16_to_cpu(n) ((_force_attr u16)(le16)(n))
#  define le32_to_cpu(n) ((_force_attr u32)(le32)(n))
#  define le64_to_cpu(n) ((_force_attr u64)(le64)(n))
#  define cpu_to_be16(n) ((_force_attr be16)bswap16(n))
#  define cpu_to_be32(n) ((_force_attr be32)bswap32(n))
#  define cpu_to_be64(n) ((_force_attr be64)bswap64(n))
#  define be16_to_cpu(n) bswap16((_force_attr u16)(be16)(n))
#  define be32_to_cpu(n) bswap32((_force_attr u32)(be32)(n))
#  define be64_to_cpu(n) bswap64((_force_attr u64)(be64)(n))
#endif

#endif /* _NTFS_ENDIANS_H */
#endif /* _WIMLIB_ENDIANNESS_H */
