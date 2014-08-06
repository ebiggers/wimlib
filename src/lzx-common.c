/*
 * lzx-common.c - Common data for LZX compression and decompression.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/endianness.h"
#include "wimlib/lzx.h"
#include "wimlib/util.h"

#ifdef __SSE2__
#  include <emmintrin.h>
#endif

/* Mapping: position slot => first match offset that uses that position slot.
 */
const u32 lzx_position_base[LZX_MAX_POSITION_SLOTS] = {
	0      , 1      , 2      , 3      , 4      ,	/* 0  --- 4  */
	6      , 8      , 12     , 16     , 24     ,	/* 5  --- 9  */
	32     , 48     , 64     , 96     , 128    ,    /* 10 --- 14 */
	192    , 256    , 384    , 512    , 768    ,    /* 15 --- 19 */
	1024   , 1536   , 2048   , 3072   , 4096   ,    /* 20 --- 24 */
	6144   , 8192   , 12288  , 16384  , 24576  ,    /* 25 --- 29 */
	32768  , 49152  , 65536  , 98304  , 131072 ,    /* 30 --- 34 */
	196608 , 262144 , 393216 , 524288 , 655360 ,    /* 35 --- 39 */
	786432 , 917504 , 1048576, 1179648, 1310720,    /* 40 --- 44 */
	1441792, 1572864, 1703936, 1835008, 1966080,    /* 45 --- 49 */
	2097152						/* 50	     */
};

/* Mapping: position slot => how many extra bits must be read and added to the
 * corresponding position base to decode the match offset.  */
#ifdef USE_LZX_EXTRA_BITS_ARRAY
const u8 lzx_extra_bits[LZX_MAX_POSITION_SLOTS] = {
	0 , 0 , 0 , 0 , 1 ,
	1 , 2 , 2 , 3 , 3 ,
	4 , 4 , 5 , 5 , 6 ,
	6 , 7 , 7 , 8 , 8 ,
	9 , 9 , 10, 10, 11,
	11, 12, 12, 13, 13,
	14, 14, 15, 15, 16,
	16, 17, 17, 17, 17,
	17, 17, 17, 17, 17,
	17, 17, 17, 17, 17,
	17
};
#endif

/* LZX window size must be a power of 2 between 2^15 and 2^21, inclusively.  */
bool
lzx_window_size_valid(size_t window_size)
{
	if (window_size == 0 || (u32)window_size != window_size)
		return false;
	u32 order = bsr32(window_size);
	if (window_size != 1U << order)
		return false;
	return (order >= LZX_MIN_WINDOW_ORDER && order <= LZX_MAX_WINDOW_ORDER);
}

/* Given a valid LZX window size, return the number of symbols that will exist
 * in the main Huffman code.  */
unsigned
lzx_get_num_main_syms(u32 window_size)
{
	/* NOTE: the calculation *should* be as follows:
	 *
	 * u32 max_offset = window_size - LZX_MIN_MATCH_LEN;
	 * u32 max_formatted_offset = max_offset + LZX_OFFSET_OFFSET;
	 * u32 num_position_slots = 1 + lzx_get_position_slot_raw(max_formatted_offset);
	 *
	 * However since LZX_MIN_MATCH_LEN == LZX_OFFSET_OFFSET, we would get
	 * max_formatted_offset == window_size, which would bump the number of
	 * position slots up by 1 since every valid LZX window size is equal to
	 * a position base value.  The format doesn't do this, and instead
	 * disallows matches with minimum length and maximum offset.  This sets
	 * max_formatted_offset = window_size - 1, so instead we must calculate:
	 *
	 * num_position_slots = 1 + lzx_get_position_slot_raw(window_size - 1);
	 *
	 * ... which is the same as
	 *
	 * num_position_slots = lzx_get_position_slot_raw(window_size);
	 *
	 * ... since every valid window size is equal to a position base value.
	 */
	unsigned num_position_slots = lzx_get_position_slot_raw(window_size);

	/* Now calculate the number of main symbols as LZX_NUM_CHARS literal
	 * symbols, plus 8 symbols per position slot (since there are 8 possible
	 * length headers, and we need all (position slot, length header)
	 * combinations).  */
	return LZX_NUM_CHARS + (num_position_slots << 3);
}

static void
do_translate_target(s32 *target, s32 input_pos)
{
	s32 abs_offset, rel_offset;

	/* XXX: This assumes unaligned memory accesses are okay.  */
	rel_offset = le32_to_cpu(*target);
	if (rel_offset >= -input_pos && rel_offset < LZX_WIM_MAGIC_FILESIZE) {
		if (rel_offset < LZX_WIM_MAGIC_FILESIZE - input_pos) {
			/* "good translation" */
			abs_offset = rel_offset + input_pos;
		} else {
			/* "compensating translation" */
			abs_offset = rel_offset - LZX_WIM_MAGIC_FILESIZE;
		}
		*target = cpu_to_le32(abs_offset);
	}
}

static void
undo_translate_target(s32 *target, s32 input_pos)
{
	s32 abs_offset, rel_offset;

	/* XXX: This assumes unaligned memory accesses are okay.  */
	abs_offset = le32_to_cpu(*target);
	if (abs_offset >= 0) {
		if (abs_offset < LZX_WIM_MAGIC_FILESIZE) {
			/* "good translation" */
			rel_offset = abs_offset - input_pos;

			*target = cpu_to_le32(rel_offset);
		}
	} else {
		if (abs_offset >= -input_pos) {
			/* "compensating translation" */
			rel_offset = abs_offset + LZX_WIM_MAGIC_FILESIZE;

			*target = cpu_to_le32(rel_offset);
		}
	}
}

/*
 * Do or undo the 'E8' preprocessing used in LZX.  Before compression, the
 * uncompressed data is preprocessed by changing the targets of x86 CALL
 * instructions from relative offsets to absolute offsets.  After decompression,
 * the translation is undone by changing the targets of x86 CALL instructions
 * from absolute offsets to relative offsets.
 *
 * Note that despite its intent, E8 preprocessing can be done on any data even
 * if it is not actually x86 machine code.  In fact, E8 preprocessing appears to
 * always be used in LZX-compressed resources in WIM files; there is no bit to
 * indicate whether it is used or not, unlike in the LZX compressed format as
 * used in cabinet files, where a bit is reserved for that purpose.
 *
 * E8 preprocessing is disabled in the last 6 bytes of the uncompressed data,
 * which really means the 5-byte call instruction cannot start in the last 10
 * bytes of the uncompressed data.  This is one of the errors in the LZX
 * documentation.
 *
 * E8 preprocessing does not appear to be disabled after the 32768th chunk of a
 * WIM resource, which apparently is another difference from the LZX compression
 * used in cabinet files.
 *
 * E8 processing is supposed to take the file size as a parameter, as it is used
 * in calculating the translated jump targets.  But in WIM files, this file size
 * is always the same (LZX_WIM_MAGIC_FILESIZE == 12000000).
 */
static
#ifndef __SSE2__
inline  /* Although inlining the 'process_target' function still speeds up the
	   SSE2 case, it bloats the binary more.  */
#endif
void
lzx_e8_filter(u8 *data, u32 size, void (*process_target)(s32 *, s32))
{
#ifdef __SSE2__
	/* SSE2 vectorized implementation for x86_64.  This speeds up LZX
	 * decompression by about 5-8% overall.  (Usually --- the performance
	 * actually regresses slightly in the degenerate case that the data
	 * consists entirely of 0xe8 bytes.  Also, this optimization affects
	 * compression as well, but the percentage improvement is less because
	 * LZX compression is much slower than LZX decompression. ) */
	__m128i *p128 = (__m128i *)data;
	u32 valid_mask = 0xFFFFFFFF;

	if (size >= 32 && (uintptr_t)data % 16 == 0) {
		__m128i * const end128 = p128 + size / 16 - 1;

		/* Create a vector of all 0xe8 bytes  */
		const __m128i e8_bytes = _mm_set1_epi8(0xe8);

		/* Iterate through the 16-byte vectors in the input.  */
		do {
			/* Compare the current 16-byte vector with the vector of
			 * all 0xe8 bytes.  This produces 0xff where the byte is
			 * 0xe8 and 0x00 where it is not.  */
			__m128i cmpresult = _mm_cmpeq_epi8(*p128, e8_bytes);

			/* Map the comparison results into a single 16-bit
			 * number.  It will contain a 1 bit when the
			 * corresponding byte in the current 16-byte vector is
			 * an e8 byte.  Note: the low-order bit corresponds to
			 * the first (lowest address) byte.  */
			u32 e8_mask = _mm_movemask_epi8(cmpresult);

			if (!e8_mask) {
				/* If e8_mask is 0, then none of these 16 bytes
				 * have value 0xe8.  No e8 translation is
				 * needed, and there is no restriction that
				 * carries over to the next 16 bytes.  */
				valid_mask = 0xFFFFFFFF;
			} else {
				/* At least one byte has value 0xe8.
				 *
				 * The AND with valid_mask accounts for the fact
				 * that we can't start an e8 translation that
				 * overlaps the previous one.  */
				while ((e8_mask &= valid_mask)) {

					/* Count the number of trailing zeroes
					 * in e8_mask.  This will produce the
					 * index of the byte, within the 16, at
					 * which the next e8 translation should
					 * be done.  */
					u32 bit = __builtin_ctz(e8_mask);

					/* Do (or undo) the e8 translation.  */
					u8 *p8 = (u8 *)p128 + bit;
					(*process_target)((s32 *)(p8 + 1),
							  p8 - data);

					/* Don't start an e8 translation in the
					 * next 4 bytes.  */
					valid_mask &= ~((u32)0x1F << bit);
				}
				/* Moving on to the next vector.  Shift and set
				 * valid_mask accordingly.  */
				valid_mask >>= 16;
				valid_mask |= 0xFFFF0000;
			}
		} while (++p128 < end128);
	}

	u8 *p8 = (u8 *)p128;
	while (!(valid_mask & 1)) {
		p8++;
		valid_mask >>= 1;
	}
#else /* __SSE2__  */
	u8 *p8 = data;
#endif /* !__SSE2__  */

	if (size > 10) {
		/* Finish any bytes that weren't processed by the vectorized
		 * implementation.  */
		u8 *p8_end = data + size - 10;
		do {
			if (*p8 == 0xe8) {
				(*process_target)((s32 *)(p8 + 1), p8 - data);
				p8 += 5;
			} else {
				p8++;
			}
		} while (p8 < p8_end);
	}
}

void
lzx_do_e8_preprocessing(u8 *data, u32 size)
{
	lzx_e8_filter(data, size, do_translate_target);
}

void
lzx_undo_e8_preprocessing(u8 *data, u32 size)
{
	lzx_e8_filter(data, size, undo_translate_target);
}
