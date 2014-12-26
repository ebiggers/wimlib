/*
 * lzms.h
 *
 * Declarations shared between LZMS compression and decompression.
 */

#ifndef _WIMLIB_LZMS_H
#define _WIMLIB_LZMS_H

#include "wimlib/compiler.h"
#include "wimlib/lzms_constants.h"
#include "wimlib/types.h"

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

/* Offset slot tables  */
extern const u32 lzms_offset_slot_base[LZMS_MAX_NUM_OFFSET_SYMS + 1];
extern const u8 lzms_extra_offset_bits[LZMS_MAX_NUM_OFFSET_SYMS];

/* Length slot tables  */
extern const u32 lzms_length_slot_base[LZMS_NUM_LENGTH_SYMS + 1];
extern const u8 lzms_extra_length_bits[LZMS_NUM_LENGTH_SYMS];

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
	return lzms_get_slot(length, lzms_length_slot_base, LZMS_NUM_LENGTH_SYMS);
}

extern unsigned
lzms_get_num_offset_slots(size_t uncompressed_size);

extern void
lzms_init_probability_entries(struct lzms_probability_entry *entries, size_t count);

extern void
lzms_init_symbol_frequencies(u32 freqs[], size_t num_syms);

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
