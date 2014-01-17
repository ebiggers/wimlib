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

#include "wimlib/lzx.h"
#include "wimlib/util.h"

/* LZX uses what it calls 'position slots' to represent match offsets.
 * What this means is that a small 'position slot' number and a small
 * offset from that slot are encoded instead of one large offset for
 * every match.
 * - lzx_position_base is an index to the position slot bases
 * - lzx_extra_bits states how many bits of offset-from-base data is needed.
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
