#ifndef _WIMLIB_LZMS_H
#define _WIMLIB_LZMS_H

/* Constants for the LZMS data compression format.  See the comments in
 * lzms-decompress.c for more information about this format.  */

//#define ENABLE_LZMS_DEBUG
#ifdef ENABLE_LZMS_DEBUG
#	define LZMS_DEBUG DEBUG
#       define LZMS_ASSERT wimlib_assert
#       include "wimlib/assert.h"
#       include "wimlib/error.h"
#else
#	define LZMS_DEBUG(format, ...)
#	define LZMS_ASSERT(...)
#endif

#define LZMS_NUM_RECENT_OFFSETS			3

#define LZMS_PROBABILITY_BITS			6
#define LZMS_PROBABILITY_MAX			(1U << LZMS_PROBABILITY_BITS)
#define LZMS_INITIAL_PROBABILITY		48
#define LZMS_INITIAL_RECENT_BITS		0x0000000055555555ULL

#define LZMS_NUM_MAIN_STATES			16
#define LZMS_NUM_MATCH_STATES			32
#define LZMS_NUM_LZ_MATCH_STATES		64
#define LZMS_NUM_LZ_REPEAT_MATCH_STATES		64
#define LZMS_NUM_DELTA_MATCH_STATES		64
#define LZMS_NUM_DELTA_REPEAT_MATCH_STATES	64
#define LZMS_MAX_NUM_STATES			64

#define LZMS_NUM_LITERAL_SYMS			256
#define LZMS_NUM_LEN_SYMS			54
#define LZMS_NUM_DELTA_POWER_SYMS		8
#define LZMS_MAX_NUM_OFFSET_SYMS		799
#define LZMS_MAX_NUM_SYMS			799

#define LZMS_MAX_CODEWORD_LEN			15

#define LZMS_LITERAL_CODE_REBUILD_FREQ		1024
#define LZMS_LZ_OFFSET_CODE_REBUILD_FREQ	1024
#define LZMS_LENGTH_CODE_REBUILD_FREQ		512
#define LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ	1024
#define LZMS_DELTA_POWER_CODE_REBUILD_FREQ	512

#define LZMS_X86_MAX_GOOD_TARGET_OFFSET		65535
#define LZMS_X86_MAX_TRANSLATION_OFFSET		1023

/* Code shared between the LZMS decompressor and compressor.  */

#include <wimlib/util.h>

extern void
lzms_x86_filter(u8 data[], s32 size, s32 last_target_usages[], bool undo);

/* Probability entry for use by the range coder when in a specific state.  */
struct lzms_probability_entry {

	/* Number of zeroes in the most recent LZMS_PROBABILITY_MAX bits that
	 * have been coded using this probability entry.  This is a cached value
	 * because it can be computed as LZMS_PROBABILITY_MAX minus the Hamming
	 * weight of the low-order LZMS_PROBABILITY_MAX bits of @recent_bits.
	 * */
	u32 num_recent_zero_bits;

	/* The most recent LZMS_PROBABILITY_MAX bits that have been coded using
	 * this probability entry.  The size of this variable, in bits, must be
	 * at least LZMS_PROBABILITY_MAX.  */
	u64 recent_bits;
};

/* LRU queues for LZ matches.  */
struct lzms_lz_lru_queues {

        /* Recent LZ match offsets  */
	u32 recent_offsets[LZMS_NUM_RECENT_OFFSETS + 1];

        /* These variables are used to delay updates to the LRU queues by one
         * decoded item.  */
	u32 prev_offset;
	u32 upcoming_offset;
};

/* LRU queues for delta matches.  */
struct lzms_delta_lru_queues {

        /* Recent delta match powers and offsets  */
	u32 recent_powers[LZMS_NUM_RECENT_OFFSETS + 1];
	u32 recent_offsets[LZMS_NUM_RECENT_OFFSETS + 1];

        /* These variables are used to delay updates to the LRU queues by one
         * decoded item.  */
	u32 prev_power;
	u32 prev_offset;
	u32 upcoming_power;
	u32 upcoming_offset;
};

/* LRU (least-recently-used) queues for match information.  */
struct lzms_lru_queues {
        struct lzms_lz_lru_queues lz;
        struct lzms_delta_lru_queues delta;
};

extern u32 lzms_position_slot_base[LZMS_MAX_NUM_OFFSET_SYMS + 1];

extern u8 lzms_extra_position_bits[LZMS_MAX_NUM_OFFSET_SYMS];

extern u16 lzms_order_to_position_slot_bounds[30][2];

extern u32 lzms_length_slot_base[LZMS_NUM_LEN_SYMS + 1];

#define LZMS_NUM_FAST_LENGTHS 1024
extern u8 lzms_length_slot_fast[LZMS_NUM_FAST_LENGTHS];

extern u8 lzms_extra_length_bits[LZMS_NUM_LEN_SYMS];

extern void
lzms_init_slots(void);

/* Return the slot for the specified value.  */
extern u32
lzms_get_slot(u32 value, const u32 slot_base_tab[], u32 num_slots);

static inline u32
lzms_get_position_slot(u32 position)
{
	u32 order = bsr32(position);
	u32 l = lzms_order_to_position_slot_bounds[order][0];
	u32 r = lzms_order_to_position_slot_bounds[order][1];

	for (;;) {
		u32 slot = (l + r) / 2;
		if (position >= lzms_position_slot_base[slot]) {
			if (position < lzms_position_slot_base[slot + 1])
				return slot;
			else
				l = slot + 1;
		} else {
			r = slot - 1;
		}
	}
}

static inline u32
lzms_get_length_slot(u32 length)
{
	if (likely(length < LZMS_NUM_FAST_LENGTHS))
		return lzms_length_slot_fast[length];
	else
		return lzms_get_slot(length, lzms_length_slot_base,
				     LZMS_NUM_LEN_SYMS);
}

extern void
lzms_init_lru_queues(struct lzms_lru_queues *lru);

extern void
lzms_update_lz_lru_queues(struct lzms_lz_lru_queues *lz);

extern void
lzms_update_delta_lru_queues(struct lzms_delta_lru_queues *delta);

extern void
lzms_update_lru_queues(struct lzms_lru_queues *lru);

#endif /* _WIMLIB_LZMS_H  */
