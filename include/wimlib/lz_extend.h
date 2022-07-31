/*
 * lz_extend.h - fast match extension for Lempel-Ziv matchfinding
 *
 * Copyright 2022 Eric Biggers
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _WIMLIB_LZ_EXTEND_H
#define _WIMLIB_LZ_EXTEND_H

#include "wimlib/bitops.h"
#include "wimlib/unaligned.h"

/*
 * Return the number of bytes at @matchptr that match the bytes at @strptr, up
 * to a maximum of @max_len.  Initially, @len bytes are matched.
 */
static forceinline u32
lz_extend(const u8 * const strptr, const u8 * const matchptr,
	  u32 len, const u32 max_len)
{
	while (UNALIGNED_ACCESS_IS_FAST && len + WORDBYTES <= max_len) {
		machine_word_t v = load_word_unaligned(matchptr + len) ^
				   load_word_unaligned(strptr + len);
		if (v != 0) {
			if (CPU_IS_LITTLE_ENDIAN)
				len += bsfw(v) >> 3;
			else
				len += (WORDBITS - 1 - bsrw(v)) >> 3;
			return len;
		}
		len += WORDBYTES;
	}

	while (len < max_len && matchptr[len] == strptr[len])
		len++;
	return len;
}

#endif /* _WIMLIB_LZ_EXTEND_H */
