/*
 * lz_extend.h
 *
 * Fast match extension for Lempel-Ziv matchfinding.
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_LZ_EXTEND_H
#define _WIMLIB_LZ_EXTEND_H

#include "wimlib/bitops.h"
#include "wimlib/unaligned.h"

/* Return the number of bytes at @matchptr that match the bytes at @strptr, up
 * to a maximum of @max_len.  Initially, @start_len bytes are matched.  */
static inline u32
lz_extend(const u8 * const strptr, const u8 * const matchptr,
	  const u32 start_len, const u32 max_len)
{
	u32 len = start_len;
	machine_word_t v_word;

	if (UNALIGNED_ACCESS_IS_FAST) {

		if (likely(max_len - len >= 4 * WORDSIZE)) {

		#define COMPARE_WORD_STEP					\
			v_word = load_word_unaligned(&matchptr[len]) ^		\
				 load_word_unaligned(&strptr[len]);		\
			if (v_word != 0)					\
				goto word_differs;				\
			len += WORDSIZE;					\

			COMPARE_WORD_STEP
			COMPARE_WORD_STEP
			COMPARE_WORD_STEP
			COMPARE_WORD_STEP
		#undef COMPARE_WORD_STEP
		}

		while (len + WORDSIZE <= max_len) {
			v_word = load_word_unaligned(&matchptr[len]) ^
				 load_word_unaligned(&strptr[len]);
			if (v_word != 0)
				goto word_differs;
			len += WORDSIZE;
		}
	}

	while (len < max_len && matchptr[len] == strptr[len])
		len++;
	return len;

word_differs:
	if (CPU_IS_LITTLE_ENDIAN)
		len += (ffsw(v_word) >> 3);
	else
		len += (8 * WORDSIZE - 1 - flsw(v_word)) >> 3;
	return len;
}

#endif /* _WIMLIB_LZ_EXTEND_H */
