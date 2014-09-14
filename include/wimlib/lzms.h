/*
 * lzms.h
 *
 * Declarations shared between LZMS compression and decompression.
 */

#ifndef _WIMLIB_LZMS_H
#define _WIMLIB_LZMS_H

#include "wimlib/lzms_constants.h"
#include "wimlib/util.h"

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

extern void
lzms_x86_filter(u8 data[], s32 size, s32 last_target_usages[], bool undo);

/* Probability entry for use by the range coder when in a specific state.  */
struct lzms_probability_entry {

	/* Number of zeroes in the most recent LZMS_PROBABILITY_MAX bits that
	 * have been coded using this probability entry.  This is a cached value
	 * because it can be computed as LZMS_PROBABILITY_MAX minus the number
	 * of bits set in the low-order LZMS_PROBABILITY_MAX bits of
	 * @recent_bits.  */
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

/* Offset slot tables  */
extern u32 lzms_offset_slot_base[LZMS_MAX_NUM_OFFSET_SYMS + 1];
extern u8 lzms_extra_offset_bits[LZMS_MAX_NUM_OFFSET_SYMS];

/* Length slot tables  */
extern u32 lzms_length_slot_base[LZMS_NUM_LEN_SYMS + 1];
extern u8 lzms_extra_length_bits[LZMS_NUM_LEN_SYMS];

extern void
lzms_init_slots(void);

extern unsigned
lzms_get_slot(u32 value, const u32 slot_base_tab[], unsigned num_slots);

/* Return the offset slot for the specified offset  */
static inline unsigned
lzms_get_offset_slot(u32 offset)
{
	return lzms_get_slot(offset, lzms_offset_slot_base, LZMS_MAX_NUM_OFFSET_SYMS);
}

/* Return the length slot for the specified length  */
static inline unsigned
lzms_get_length_slot(u32 length)
{
	return lzms_get_slot(length, lzms_length_slot_base, LZMS_NUM_LEN_SYMS);
}

extern void
lzms_init_lz_lru_queues(struct lzms_lz_lru_queues *lz);

extern void
lzms_init_delta_lru_queues(struct lzms_delta_lru_queues *delta);

extern void
lzms_init_lru_queues(struct lzms_lru_queues *lru);

extern void
lzms_update_lz_lru_queue(struct lzms_lz_lru_queues *lz);

extern void
lzms_update_delta_lru_queues(struct lzms_delta_lru_queues *delta);

extern void
lzms_update_lru_queues(struct lzms_lru_queues *lru);

/* Given a decoded bit, update the probability entry.  */
static inline void
lzms_update_probability_entry(struct lzms_probability_entry *prob_entry, int bit)
{
	s32 delta_zero_bits;

	BUILD_BUG_ON(LZMS_PROBABILITY_MAX != sizeof(prob_entry->recent_bits) * 8);

	delta_zero_bits = (s32)(prob_entry->recent_bits >> (LZMS_PROBABILITY_MAX - 1)) - bit;

	prob_entry->num_recent_zero_bits += delta_zero_bits;
	prob_entry->recent_bits <<= 1;
	prob_entry->recent_bits |= bit;
}

/* Given a probability entry, return the chance out of LZMS_PROBABILITY_MAX that
 * the next decoded bit will be a 0.  */
static inline u32
lzms_get_probability(const struct lzms_probability_entry *prob_entry)
{
	u32 prob;

	prob = prob_entry->num_recent_zero_bits;

	/* 0% and 100% probabilities aren't allowed.  */
	if (prob == 0)
		prob++;
	if (prob == LZMS_PROBABILITY_MAX)
		prob--;
	return prob;
}

#endif /* _WIMLIB_LZMS_H  */
