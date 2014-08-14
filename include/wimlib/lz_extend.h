/*
 * lz_extend.h
 *
 * Fast match extension for Lempel-Ziv matchfinding.
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_LZ_EXTEND_H
#define _WIMLIB_LZ_EXTEND_H

#include "wimlib/types.h"

#if (defined(__x86_64__) || defined(__i386__)) && defined(__GNUC__)
#  define HAVE_FAST_LZ_EXTEND 1
#else
#  define HAVE_FAST_LZ_EXTEND 0
#endif

/* Return the number of bytes at @matchptr that match the bytes at @strptr, up
 * to a maximum of @max_len.  Initially, @start_len bytes are matched.  */
static inline u32
lz_extend(const u8 * const strptr, const u8 * const matchptr,
	  const u32 start_len, const u32 max_len)
{
	u32 len = start_len;

#if HAVE_FAST_LZ_EXTEND

	while (len + sizeof(unsigned long) <= max_len) {
		unsigned long x;

		x = *(const unsigned long *)&matchptr[len] ^
		    *(const unsigned long *)&strptr[len];
		if (x != 0)
			return len + (__builtin_ctzl(x) >> 3);
		len += sizeof(unsigned long);
	}

	if (sizeof(unsigned int) < sizeof(unsigned long) &&
	    len + sizeof(unsigned int) <= max_len)
	{
		unsigned int x;

		x = *(const unsigned int *)&matchptr[len] ^
		    *(const unsigned int *)&strptr[len];
		if (x != 0)
			return len + (__builtin_ctz(x) >> 3);
		len += sizeof(unsigned int);
	}

	if (sizeof(unsigned int) == 4) {
		if (len < max_len && matchptr[len] == strptr[len]) {
			len++;
			if (len < max_len && matchptr[len] == strptr[len]) {
				len++;
				if (len < max_len && matchptr[len] == strptr[len]) {
					len++;
				}
			}
		}
		return len;
	}

#endif /* HAVE_FAST_LZ_EXTEND */

	while (len < max_len && matchptr[len] == strptr[len])
		len++;

	return len;
}

#endif /* _WIMLIB_LZ_EXTEND_H */
