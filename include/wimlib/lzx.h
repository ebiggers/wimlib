/*
 * lzx.h
 *
 * Declarations shared between LZX compression and decompression.
 */

#ifndef _WIMLIB_LZX_H
#define _WIMLIB_LZX_H

#include "wimlib/assert.h"
#include "wimlib/compiler.h"
#include "wimlib/lzx_constants.h"
#include "wimlib/util.h"
#include "wimlib/types.h"

//#define ENABLE_LZX_DEBUG
#ifdef ENABLE_LZX_DEBUG
#       define LZX_ASSERT wimlib_assert
#else
#	define LZX_ASSERT(...)
#endif

#define USE_LZX_EXTRA_BITS_ARRAY

#ifdef USE_LZX_EXTRA_BITS_ARRAY
extern const u8 lzx_extra_bits[LZX_MAX_POSITION_SLOTS];
#endif

/* Given the number of an LZX position slot, return the number of extra bits that
 * are needed to encode the match offset. */
static inline unsigned
lzx_get_num_extra_bits(unsigned position_slot)
{
#ifdef USE_LZX_EXTRA_BITS_ARRAY
	/* Use a table */
	return lzx_extra_bits[position_slot];
#else
	/* Calculate directly using a shift and subtraction. */
	LZX_ASSERT(position_slot >= 2 && position_slot <= 37);
	return (position_slot >> 1) - 1;
#endif
}

extern const u32 lzx_position_base[LZX_MAX_POSITION_SLOTS];

/* Returns the LZX position slot that corresponds to a given formatted offset.
 *
 * Logically, this returns the smallest i such that
 * formatted_offset >= lzx_position_base[i].
 *
 * The actual implementation below takes advantage of the regularity of the
 * numbers in the lzx_position_base array to calculate the slot directly from
 * the formatted offset without actually looking at the array.
 */
static inline unsigned
lzx_get_position_slot_raw(u32 formatted_offset)
{
	if (formatted_offset >= 196608) {
		return (formatted_offset >> 17) + 34;
	} else {
		LZX_ASSERT(2 <= formatted_offset && formatted_offset < 655360);
		unsigned mssb_idx = bsr32(formatted_offset);
		return (mssb_idx << 1) |
			((formatted_offset >> (mssb_idx - 1)) & 1);
	}
}

extern unsigned lzx_get_window_order(size_t max_block_size);

extern unsigned lzx_get_num_main_syms(unsigned window_order);

/* Least-recently used queue for match offsets.  */
struct lzx_lru_queue {
	u32 R[LZX_NUM_RECENT_OFFSETS];
}
#ifdef __x86_64__
_aligned_attribute(8)  /* Improves performance of LZX compression by 1% - 2%;
			  specifically, this speeds up
			  lzx_choose_near_optimal_item().  */
#endif
;

/* Initialize the LZX least-recently-used match offset queue at the beginning of
 * a new window for either decompression or compression.  */
static inline void
lzx_lru_queue_init(struct lzx_lru_queue *queue)
{
	for (unsigned i = 0; i < LZX_NUM_RECENT_OFFSETS; i++)
		queue->R[i] = 1;
}

extern void
lzx_do_e8_preprocessing(u8 *data, u32 size);

extern void
lzx_undo_e8_preprocessing(u8 *data, u32 size);

#endif /* _WIMLIB_LZX_H */
