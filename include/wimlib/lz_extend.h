/*
 * lz_extend.h - fast match extension for Lempel-Ziv matchfinding
 *
 * The following copying information applies to this specific source code file:
 *
 * Written in 2014-2016 by Eric Biggers <ebiggers3@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide via the Creative Commons Zero 1.0 Universal Public Domain
 * Dedication (the "CC0").
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the CC0 for more details.
 *
 * You should have received a copy of the CC0 along with this software; if not
 * see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef _WIMLIB_LZ_EXTEND_H
#define _WIMLIB_LZ_EXTEND_H

#include "wimlib/bitops.h"
#include "wimlib/unaligned.h"

/*
 * Return the number of bytes at @matchptr that match the bytes at @strptr, up
 * to a maximum of @max_len.  Initially, @len bytes are matched.
 */
static inline u32
lz_extend(const u8 * const strptr, const u8 * const matchptr,
	  u32 len, const u32 max_len)
{
	while (UNALIGNED_ACCESS_IS_FAST && len + WORDBYTES <= max_len) {
		machine_word_t v = load_word_unaligned(matchptr + len) ^
				   load_word_unaligned(strptr + len);
		if (v != 0) {
			if (CPU_IS_LITTLE_ENDIAN)
				len += ffsw(v) >> 3;
			else
				len += (WORDBITS - 1 - flsw(v)) >> 3;
			return len;
		}
		len += WORDBYTES;
	}

	while (len < max_len && matchptr[len] == strptr[len])
		len++;
	return len;
}

#endif /* _WIMLIB_LZ_EXTEND_H */
