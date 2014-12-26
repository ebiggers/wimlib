/*
 * lzms-compress.c
 *
 * A compressor that produces output compatible with the LZMS compression format.
 */

/*
 * Copyright (C) 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/compress_common.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lz_mf.h"
#include "wimlib/lz_repsearch.h"
#include "wimlib/lzms.h"
#include "wimlib/unaligned.h"
#include "wimlib/util.h"

#include <string.h>
#include <limits.h>
#include <pthread.h>

/* Stucture used for writing raw bits as a series of 16-bit little endian coding
 * units.  This starts at the *end* of the compressed data buffer and proceeds
 * backwards.  */
struct lzms_output_bitstream {

	/* Bits that haven't yet been written to the output buffer.  */
	u64 bitbuf;

	/* Number of bits currently held in @bitbuf.  */
	unsigned bitcount;

	/* Pointer to one past the next position in the compressed data buffer
	 * at which to output a 16-bit coding unit.  */
	le16 *next;

	/* Pointer to the beginning of the output buffer.  (The "end" when
	 * writing backwards!)  */
	le16 *begin;
};

/* Stucture used for range encoding (raw version).  This starts at the
 * *beginning* of the compressed data buffer and proceeds forward.  */
struct lzms_range_encoder_raw {

	/* A 33-bit variable that holds the low boundary of the current range.
	 * The 33rd bit is needed to catch carries.  */
	u64 low;

	/* Size of the current range.  */
	u32 range;

	/* Next 16-bit coding unit to output.  */
	u16 cache;

	/* Number of 16-bit coding units whose output has been delayed due to
	 * possible carrying.  The first such coding unit is @cache; all
	 * subsequent such coding units are 0xffff.  */
	u32 cache_size;

	/* Pointer to the beginning of the output buffer.  */
	le16 *begin;

	/* Pointer to the position in the output buffer at which the next coding
	 * unit must be written.  */
	le16 *next;

	/* Pointer just past the end of the output buffer.  */
	le16 *end;
};

/* Structure used for range encoding.  This wraps around `struct
 * lzms_range_encoder_raw' to use and maintain probability entries.  */
struct lzms_range_encoder {

	/* Pointer to the raw range encoder, which has no persistent knowledge
	 * of probabilities.  Multiple lzms_range_encoder's share the same
	 * lzms_range_encoder_raw.  */
	struct lzms_range_encoder_raw *rc;

	/* Bits recently encoded by this range encoder.  This is used as an
	 * index into @prob_entries.  */
	u32 state;

	/* Bitmask for @state to prevent its value from exceeding the number of
	 * probability entries.  */
	u32 mask;

	/* Probability entries being used for this range encoder.  */
	struct lzms_probability_entry prob_entries[LZMS_MAX_NUM_STATES];
};

/* Structure used for Huffman encoding.  */
struct lzms_huffman_encoder {

	/* Bitstream to write Huffman-encoded symbols and verbatim bits to.
	 * Multiple lzms_huffman_encoder's share the same lzms_output_bitstream.
	 */
	struct lzms_output_bitstream *os;

	/* Number of symbols that have been written using this code far.  Reset
	 * to 0 whenever the code is rebuilt.  */
	u32 num_syms_written;

	/* When @num_syms_written reaches this number, the Huffman code must be
	 * rebuilt.  */
	u32 rebuild_freq;

	/* Number of symbols in the represented Huffman code.  */
	unsigned num_syms;

	/* Running totals of symbol frequencies.  These are diluted slightly
	 * whenever the code is rebuilt.  */
	u32 sym_freqs[LZMS_MAX_NUM_SYMS];

	/* The length, in bits, of each symbol in the Huffman code.  */
	u8 lens[LZMS_MAX_NUM_SYMS];

	/* The codeword of each symbol in the Huffman code.  */
	u32 codewords[LZMS_MAX_NUM_SYMS];
};

/* Internal compression parameters  */
struct lzms_compressor_params {
	u32 min_match_length;
	u32 nice_match_length;
	u32 max_search_depth;
	u32 optim_array_length;
};

/* State of the LZMS compressor  */
struct lzms_compressor {

	/* Internal compression parameters  */
	struct lzms_compressor_params params;

	/* Data currently being compressed  */
	u8 *cur_window;
	u32 cur_window_size;

	/* Lempel-Ziv match-finder  */
	struct lz_mf *mf;

	/* Temporary space to store found matches  */
	struct lz_match *matches;

	/* Per-position data for near-optimal parsing  */
	struct lzms_mc_pos_data *optimum;
	struct lzms_mc_pos_data *optimum_end;

	/* Raw range encoder which outputs to the beginning of the compressed
	 * data buffer, proceeding forwards  */
	struct lzms_range_encoder_raw rc;

	/* Bitstream which outputs to the end of the compressed data buffer,
	 * proceeding backwards  */
	struct lzms_output_bitstream os;

	/* Range encoders  */
	struct lzms_range_encoder main_range_encoder;
	struct lzms_range_encoder match_range_encoder;
	struct lzms_range_encoder lz_match_range_encoder;
	struct lzms_range_encoder lz_repeat_match_range_encoders[LZMS_NUM_RECENT_OFFSETS - 1];
	struct lzms_range_encoder delta_match_range_encoder;
	struct lzms_range_encoder delta_repeat_match_range_encoders[LZMS_NUM_RECENT_OFFSETS - 1];

	/* Huffman encoders  */
	struct lzms_huffman_encoder literal_encoder;
	struct lzms_huffman_encoder lz_offset_encoder;
	struct lzms_huffman_encoder length_encoder;
	struct lzms_huffman_encoder delta_power_encoder;
	struct lzms_huffman_encoder delta_offset_encoder;

	/* Used for preprocessing  */
	s32 last_target_usages[65536];

#define LZMS_NUM_FAST_LENGTHS 256
	/* Table: length => length slot for small lengths  */
	u8 length_slot_fast[LZMS_NUM_FAST_LENGTHS];

	/* Table: length => current cost for small match lengths  */
	u32 length_cost_fast[LZMS_NUM_FAST_LENGTHS];

#define LZMS_NUM_FAST_OFFSETS 32768
	/* Table: offset => offset slot for small offsets  */
	u8 offset_slot_fast[LZMS_NUM_FAST_OFFSETS];
};

struct lzms_lz_lru_queue {
	u32 recent_offsets[LZMS_NUM_RECENT_OFFSETS + 1];
	u32 prev_offset;
	u32 upcoming_offset;
};

static void
lzms_init_lz_lru_queue(struct lzms_lz_lru_queue *queue)
{
	for (int i = 0; i < LZMS_NUM_RECENT_OFFSETS + 1; i++)
		queue->recent_offsets[i] = i + 1;

	queue->prev_offset = 0;
	queue->upcoming_offset = 0;
}

static void
lzms_update_lz_lru_queue(struct lzms_lz_lru_queue *queue)
{
	if (queue->prev_offset != 0) {
		for (int i = LZMS_NUM_RECENT_OFFSETS - 1; i >= 0; i--)
			queue->recent_offsets[i + 1] = queue->recent_offsets[i];
		queue->recent_offsets[0] = queue->prev_offset;
	}
	queue->prev_offset = queue->upcoming_offset;
}

/*
 * Match chooser position data:
 *
 * An array of these structures is used during the near-optimal match-choosing
 * algorithm.  They correspond to consecutive positions in the window and are
 * used to keep track of the cost to reach each position, and the match/literal
 * choices that need to be chosen to reach that position.
 */
struct lzms_mc_pos_data {

	/* The cost, in bits, of the lowest-cost path that has been found to
	 * reach this position.  This can change as progressively lower cost
	 * paths are found to reach this position.  */
	u32 cost;
#define MC_INFINITE_COST UINT32_MAX

	/* The match or literal that was taken to reach this position.  This can
	 * change as progressively lower cost paths are found to reach this
	 * position.
	 *
	 * This variable is divided into two bitfields.
	 *
	 * Literals:
	 *	Low bits are 1, high bits are the literal.
	 *
	 * Explicit offset matches:
	 *	Low bits are the match length, high bits are the offset plus 2.
	 *
	 * Repeat offset matches:
	 *	Low bits are the match length, high bits are the queue index.
	 */
	u64 mc_item_data;
#define MC_OFFSET_SHIFT 32
#define MC_LEN_MASK (((u64)1 << MC_OFFSET_SHIFT) - 1)

	/* The LZMS adaptive state that exists at this position.  This is filled
	 * in lazily, only after the minimum-cost path to this position is
	 * found.
	 *
	 * Note: the way we handle this adaptive state in the "minimum-cost"
	 * parse is actually only an approximation.  It's possible for the
	 * globally optimal, minimum cost path to contain a prefix, ending at a
	 * position, where that path prefix is *not* the minimum cost path to
	 * that position.  This can happen if such a path prefix results in a
	 * different adaptive state which results in lower costs later.  We do
	 * not solve this problem; we only consider the lowest cost to reach
	 * each position, which seems to be an acceptable approximation.
	 *
	 * Note: this adaptive state also does not include the probability
	 * entries or current Huffman codewords.  Those aren't maintained
	 * per-position and are only updated occassionally.  */
	struct lzms_adaptive_state {
		struct lzms_lz_lru_queue lru;
		u8 main_state;
		u8 match_state;
		u8 lz_match_state;
		u8 lz_repeat_match_state[LZMS_NUM_RECENT_OFFSETS - 1];
	} state;
};

static void
lzms_init_fast_slots(struct lzms_compressor *c)
{
	/* Create table mapping small lengths to length slots.  */
	for (unsigned slot = 0, i = 0; i < LZMS_NUM_FAST_LENGTHS; i++) {
		while (i >= lzms_length_slot_base[slot + 1])
			slot++;
		c->length_slot_fast[i] = slot;
	}

	/* Create table mapping small offsets to offset slots.  */
	for (unsigned slot = 0, i = 0; i < LZMS_NUM_FAST_OFFSETS; i++) {
		while (i >= lzms_offset_slot_base[slot + 1])
			slot++;
		c->offset_slot_fast[i] = slot;
	}
}

static inline unsigned
lzms_get_length_slot_fast(const struct lzms_compressor *c, u32 length)
{
	if (likely(length < LZMS_NUM_FAST_LENGTHS))
		return c->length_slot_fast[length];
	else
		return lzms_get_length_slot(length);
}

static inline unsigned
lzms_get_offset_slot_fast(const struct lzms_compressor *c, u32 offset)
{
	if (offset < LZMS_NUM_FAST_OFFSETS)
		return c->offset_slot_fast[offset];
	else
		return lzms_get_offset_slot(offset);
}

/* Initialize the output bitstream @os to write backwards to the specified
 * compressed data buffer @out that is @out_limit 16-bit integers long.  */
static void
lzms_output_bitstream_init(struct lzms_output_bitstream *os,
			   le16 *out, size_t out_limit)
{
	os->bitbuf = 0;
	os->bitcount = 0;
	os->next = out + out_limit;
	os->begin = out;
}

/*
 * Write some bits, contained in the low @num_bits bits of @bits (ordered from
 * high-order to low-order), to the output bitstream @os.
 *
 * @max_num_bits is a compile-time constant that specifies the maximum number of
 * bits that can ever be written at this call site.
 */
static inline void
lzms_output_bitstream_put_varbits(struct lzms_output_bitstream *os,
				  u32 bits, unsigned num_bits,
				  unsigned max_num_bits)
{
	LZMS_ASSERT(num_bits <= 48);

	/* Add the bits to the bit buffer variable.  */
	os->bitcount += num_bits;
	os->bitbuf = (os->bitbuf << num_bits) | bits;

	/* Check whether any coding units need to be written.  */
	while (os->bitcount >= 16) {

		os->bitcount -= 16;

		/* Write a coding unit, unless it would underflow the buffer. */
		if (os->next != os->begin)
			put_unaligned_u16_le(os->bitbuf >> os->bitcount, --os->next);

		/* Optimization for call sites that never write more than 16
		 * bits at once.  */
		if (max_num_bits <= 16)
			break;
	}
}

/* Flush the output bitstream, ensuring that all bits written to it have been
 * written to memory.  Returns %true if all bits have been output successfully,
 * or %false if an overrun occurred.  */
static bool
lzms_output_bitstream_flush(struct lzms_output_bitstream *os)
{
	if (os->next == os->begin)
		return false;

	if (os->bitcount != 0)
		put_unaligned_u16_le(os->bitbuf << (16 - os->bitcount), --os->next);

	return true;
}

/* Initialize the range encoder @rc to write forwards to the specified
 * compressed data buffer @out that is @out_limit 16-bit integers long.  */
static void
lzms_range_encoder_raw_init(struct lzms_range_encoder_raw *rc,
			    le16 *out, size_t out_limit)
{
	rc->low = 0;
	rc->range = 0xffffffff;
	rc->cache = 0;
	rc->cache_size = 1;
	rc->begin = out;
	rc->next = out - 1;
	rc->end = out + out_limit;
}

/*
 * Attempt to flush bits from the range encoder.
 *
 * Note: this is based on the public domain code for LZMA written by Igor
 * Pavlov.  The only differences in this function are that in LZMS the bits must
 * be output in 16-bit coding units instead of 8-bit coding units, and that in
 * LZMS the first coding unit is not ignored by the decompressor, so the encoder
 * cannot output a dummy value to that position.
 *
 * The basic idea is that we're writing bits from @rc->low to the output.
 * However, due to carrying, the writing of coding units with value 0xffff, as
 * well as one prior coding unit, must be delayed until it is determined whether
 * a carry is needed.
 */
static void
lzms_range_encoder_raw_shift_low(struct lzms_range_encoder_raw *rc)
{
	if ((u32)(rc->low) < 0xffff0000 ||
	    (u32)(rc->low >> 32) != 0)
	{
		/* Carry not needed (rc->low < 0xffff0000), or carry occurred
		 * ((rc->low >> 32) != 0, a.k.a. the carry bit is 1).  */
		do {
			if (likely(rc->next >= rc->begin)) {
				if (rc->next != rc->end) {
					put_unaligned_u16_le(rc->cache +
							     (u16)(rc->low >> 32),
							     rc->next++);
				}
			} else {
				rc->next++;
			}
			rc->cache = 0xffff;
		} while (--rc->cache_size != 0);

		rc->cache = (rc->low >> 16) & 0xffff;
	}
	++rc->cache_size;
	rc->low = (rc->low & 0xffff) << 16;
}

static void
lzms_range_encoder_raw_normalize(struct lzms_range_encoder_raw *rc)
{
	if (rc->range <= 0xffff) {
		rc->range <<= 16;
		lzms_range_encoder_raw_shift_low(rc);
	}
}

static bool
lzms_range_encoder_raw_flush(struct lzms_range_encoder_raw *rc)
{
	for (unsigned i = 0; i < 4; i++)
		lzms_range_encoder_raw_shift_low(rc);
	return rc->next != rc->end;
}

/* Encode the next bit using the range encoder (raw version).
 *
 * @prob is the chance out of LZMS_PROBABILITY_MAX that the next bit is 0.  */
static inline void
lzms_range_encoder_raw_encode_bit(struct lzms_range_encoder_raw *rc,
				  int bit, u32 prob)
{
	lzms_range_encoder_raw_normalize(rc);

	u32 bound = (rc->range >> LZMS_PROBABILITY_BITS) * prob;
	if (bit == 0) {
		rc->range = bound;
	} else {
		rc->low += bound;
		rc->range -= bound;
	}
}

/* Encode a bit using the specified range encoder. This wraps around
 * lzms_range_encoder_raw_encode_bit() to handle using and updating the
 * appropriate state and probability entry.  */
static void
lzms_range_encode_bit(struct lzms_range_encoder *enc, int bit)
{
	struct lzms_probability_entry *prob_entry;
	u32 prob;

	/* Load the probability entry corresponding to the current state.  */
	prob_entry = &enc->prob_entries[enc->state];

	/* Update the state based on the next bit.  */
	enc->state = ((enc->state << 1) | bit) & enc->mask;

	/* Get the probability that the bit is 0.  */
	prob = lzms_get_probability(prob_entry);

	/* Update the probability entry.  */
	lzms_update_probability_entry(prob_entry, bit);

	/* Encode the bit.  */
	lzms_range_encoder_raw_encode_bit(enc->rc, bit, prob);
}

/* Called when an adaptive Huffman code needs to be rebuilt.  */
static void
lzms_rebuild_huffman_code(struct lzms_huffman_encoder *enc)
{
	make_canonical_huffman_code(enc->num_syms,
				    LZMS_MAX_CODEWORD_LEN,
				    enc->sym_freqs,
				    enc->lens,
				    enc->codewords);

	/* Dilute the frequencies.  */
	for (unsigned i = 0; i < enc->num_syms; i++) {
		enc->sym_freqs[i] >>= 1;
		enc->sym_freqs[i] += 1;
	}
	enc->num_syms_written = 0;
}

/* Encode a symbol using the specified Huffman encoder.  */
static inline void
lzms_huffman_encode_symbol(struct lzms_huffman_encoder *enc, unsigned sym)
{
	lzms_output_bitstream_put_varbits(enc->os,
					  enc->codewords[sym],
					  enc->lens[sym],
					  LZMS_MAX_CODEWORD_LEN);
	++enc->sym_freqs[sym];
	if (++enc->num_syms_written == enc->rebuild_freq)
		lzms_rebuild_huffman_code(enc);
}

static void
lzms_update_fast_length_costs(struct lzms_compressor *c);

/* Encode a match length.  */
static void
lzms_encode_length(struct lzms_compressor *c, u32 length)
{
	unsigned slot;
	unsigned num_extra_bits;
	u32 extra_bits;

	slot = lzms_get_length_slot_fast(c, length);

	extra_bits = length - lzms_length_slot_base[slot];
	num_extra_bits = lzms_extra_length_bits[slot];

	lzms_huffman_encode_symbol(&c->length_encoder, slot);
	if (c->length_encoder.num_syms_written == 0)
		lzms_update_fast_length_costs(c);

	lzms_output_bitstream_put_varbits(c->length_encoder.os,
					  extra_bits, num_extra_bits, 30);
}

/* Encode an LZ match offset.  */
static void
lzms_encode_lz_offset(struct lzms_compressor *c, u32 offset)
{
	unsigned slot;
	unsigned num_extra_bits;
	u32 extra_bits;

	slot = lzms_get_offset_slot_fast(c, offset);

	extra_bits = offset - lzms_offset_slot_base[slot];
	num_extra_bits = lzms_extra_offset_bits[slot];

	lzms_huffman_encode_symbol(&c->lz_offset_encoder, slot);
	lzms_output_bitstream_put_varbits(c->lz_offset_encoder.os,
					  extra_bits, num_extra_bits, 30);
}

/* Encode a literal byte.  */
static void
lzms_encode_literal(struct lzms_compressor *c, unsigned literal)
{
	/* Main bit: 0 = a literal, not a match.  */
	lzms_range_encode_bit(&c->main_range_encoder, 0);

	/* Encode the literal using the current literal Huffman code.  */
	lzms_huffman_encode_symbol(&c->literal_encoder, literal);
}

/* Encode an LZ repeat offset match.  */
static void
lzms_encode_lz_repeat_offset_match(struct lzms_compressor *c,
				   u32 length, unsigned rep_index)
{
	unsigned i;

	/* Main bit: 1 = a match, not a literal.  */
	lzms_range_encode_bit(&c->main_range_encoder, 1);

	/* Match bit: 0 = an LZ match, not a delta match.  */
	lzms_range_encode_bit(&c->match_range_encoder, 0);

	/* LZ match bit: 1 = repeat offset, not an explicit offset.  */
	lzms_range_encode_bit(&c->lz_match_range_encoder, 1);

	/* Encode the repeat offset index.  A 1 bit is encoded for each index
	 * passed up.  This sequence of 1 bits is terminated by a 0 bit, or
	 * automatically when (LZMS_NUM_RECENT_OFFSETS - 1) 1 bits have been
	 * encoded.  */
	for (i = 0; i < rep_index; i++)
		lzms_range_encode_bit(&c->lz_repeat_match_range_encoders[i], 1);

	if (i < LZMS_NUM_RECENT_OFFSETS - 1)
		lzms_range_encode_bit(&c->lz_repeat_match_range_encoders[i], 0);

	/* Encode the match length.  */
	lzms_encode_length(c, length);
}

/* Encode an LZ explicit offset match.  */
static void
lzms_encode_lz_explicit_offset_match(struct lzms_compressor *c,
				     u32 length, u32 offset)
{
	/* Main bit: 1 = a match, not a literal.  */
	lzms_range_encode_bit(&c->main_range_encoder, 1);

	/* Match bit: 0 = an LZ match, not a delta match.  */
	lzms_range_encode_bit(&c->match_range_encoder, 0);

	/* LZ match bit: 0 = explicit offset, not a repeat offset.  */
	lzms_range_encode_bit(&c->lz_match_range_encoder, 0);

	/* Encode the match offset.  */
	lzms_encode_lz_offset(c, offset);

	/* Encode the match length.  */
	lzms_encode_length(c, length);
}

static void
lzms_encode_item(struct lzms_compressor *c, u64 mc_item_data)
{
	u32 len = mc_item_data & MC_LEN_MASK;
	u32 offset_data = mc_item_data >> MC_OFFSET_SHIFT;

	if (len == 1)
		lzms_encode_literal(c, offset_data);
	else if (offset_data < LZMS_NUM_RECENT_OFFSETS)
		lzms_encode_lz_repeat_offset_match(c, len, offset_data);
	else
		lzms_encode_lz_explicit_offset_match(c, len, offset_data - LZMS_OFFSET_OFFSET);
}

/* Encode a list of matches and literals chosen by the parsing algorithm.  */
static void
lzms_encode_item_list(struct lzms_compressor *c,
		      struct lzms_mc_pos_data *cur_optimum_ptr)
{
	struct lzms_mc_pos_data *end_optimum_ptr;
	u64 saved_item;
	u64 item;

	/* The list is currently in reverse order (last item to first item).
	 * Reverse it.  */
	end_optimum_ptr = cur_optimum_ptr;
	saved_item = cur_optimum_ptr->mc_item_data;
	do {
		item = saved_item;
		cur_optimum_ptr -= item & MC_LEN_MASK;
		saved_item = cur_optimum_ptr->mc_item_data;
		cur_optimum_ptr->mc_item_data = item;
	} while (cur_optimum_ptr != c->optimum);

	/* Walk the list of items from beginning to end, encoding each item.  */
	do {
		lzms_encode_item(c, cur_optimum_ptr->mc_item_data);
		cur_optimum_ptr += (cur_optimum_ptr->mc_item_data) & MC_LEN_MASK;
	} while (cur_optimum_ptr != end_optimum_ptr);
}

/* Each bit costs 1 << LZMS_COST_SHIFT units.  */
#define LZMS_COST_SHIFT 6

/*#define LZMS_RC_COSTS_USE_FLOATING_POINT*/

static u32
lzms_rc_costs[LZMS_PROBABILITY_MAX + 1];

#ifdef LZMS_RC_COSTS_USE_FLOATING_POINT
#  include <math.h>
#endif

static void
lzms_do_init_rc_costs(void)
{
	/* Fill in a table that maps range coding probabilities needed to code a
	 * bit X (0 or 1) to the number of bits (scaled by a constant factor, to
	 * handle fractional costs) needed to code that bit X.
	 *
	 * Consider the range of the range decoder.  To eliminate exactly half
	 * the range (logical probability of 0.5), we need exactly 1 bit.  For
	 * lower probabilities we need more bits and for higher probabilities we
	 * need fewer bits.  In general, a logical probability of N will
	 * eliminate the proportion 1 - N of the range; this information takes
	 * log2(1 / N) bits to encode.
	 *
	 * The below loop is simply calculating this number of bits for each
	 * possible probability allowed by the LZMS compression format, but
	 * without using real numbers.  To handle fractional probabilities, each
	 * cost is multiplied by (1 << LZMS_COST_SHIFT).  These techniques are
	 * based on those used by LZMA.
	 *
	 * Note that in LZMS, a probability x really means x / 64, and 0 / 64 is
	 * really interpreted as 1 / 64 and 64 / 64 is really interpreted as
	 * 63 / 64.
	 */
	for (u32 i = 0; i <= LZMS_PROBABILITY_MAX; i++) {
		u32 prob = i;

		if (prob == 0)
			prob = 1;
		else if (prob == LZMS_PROBABILITY_MAX)
			prob = LZMS_PROBABILITY_MAX - 1;

	#ifdef LZMS_RC_COSTS_USE_FLOATING_POINT
		lzms_rc_costs[i] = log2((double)LZMS_PROBABILITY_MAX / prob) *
					(1 << LZMS_COST_SHIFT);
	#else
		u32 w = prob;
		u32 bit_count = 0;
		for (u32 j = 0; j < LZMS_COST_SHIFT; j++) {
			w *= w;
			bit_count <<= 1;
			while (w >= ((u32)1 << 16)) {
				w >>= 1;
				++bit_count;
			}
		}
		lzms_rc_costs[i] = (LZMS_PROBABILITY_BITS << LZMS_COST_SHIFT) -
				   (15 + bit_count);
	#endif
	}
}

static void
lzms_init_rc_costs(void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	pthread_once(&once, lzms_do_init_rc_costs);
}

/* Return the cost to range-encode the specified bit from the specified state.*/
static inline u32
lzms_rc_bit_cost(const struct lzms_range_encoder *enc, u8 cur_state, int bit)
{
	u32 prob_zero;
	u32 prob_correct;

	prob_zero = enc->prob_entries[cur_state].num_recent_zero_bits;

	if (bit == 0)
		prob_correct = prob_zero;
	else
		prob_correct = LZMS_PROBABILITY_MAX - prob_zero;

	return lzms_rc_costs[prob_correct];
}

/* Return the cost to Huffman-encode the specified symbol.  */
static inline u32
lzms_huffman_symbol_cost(const struct lzms_huffman_encoder *enc, unsigned sym)
{
	return (u32)enc->lens[sym] << LZMS_COST_SHIFT;
}

/* Return the cost to encode the specified literal byte.  */
static inline u32
lzms_literal_cost(const struct lzms_compressor *c, unsigned literal,
		  const struct lzms_adaptive_state *state)
{
	return lzms_rc_bit_cost(&c->main_range_encoder, state->main_state, 0) +
	       lzms_huffman_symbol_cost(&c->literal_encoder, literal);
}

/* Update the table that directly provides the costs for small lengths.  */
static void
lzms_update_fast_length_costs(struct lzms_compressor *c)
{
	u32 len;
	int slot = -1;
	u32 cost = 0;

	for (len = 1; len < LZMS_NUM_FAST_LENGTHS; len++) {

		while (len >= lzms_length_slot_base[slot + 1]) {
			slot++;
			cost = (u32)(c->length_encoder.lens[slot] +
				     lzms_extra_length_bits[slot]) << LZMS_COST_SHIFT;
		}

		c->length_cost_fast[len] = cost;
	}
}

/* Return the cost to encode the specified match length, which must be less than
 * LZMS_NUM_FAST_LENGTHS.  */
static inline u32
lzms_fast_length_cost(const struct lzms_compressor *c, u32 length)
{
	LZMS_ASSERT(length < LZMS_NUM_FAST_LENGTHS);
	return c->length_cost_fast[length];
}

/* Return the cost to encode the specified LZ match offset.  */
static inline u32
lzms_lz_offset_cost(const struct lzms_compressor *c, u32 offset)
{
	unsigned slot = lzms_get_offset_slot_fast(c, offset);

	return (u32)(c->lz_offset_encoder.lens[slot] +
		     lzms_extra_offset_bits[slot]) << LZMS_COST_SHIFT;
}

/*
 * Consider coding the match at repeat offset index @rep_idx.  Consider each
 * length from the minimum (2) to the full match length (@rep_len).
 */
static inline void
lzms_consider_lz_repeat_offset_match(const struct lzms_compressor *c,
				     struct lzms_mc_pos_data *cur_optimum_ptr,
				     u32 rep_len, unsigned rep_idx)
{
	u32 len;
	u32 base_cost;
	u32 cost;
	unsigned i;

	base_cost = cur_optimum_ptr->cost;

	base_cost += lzms_rc_bit_cost(&c->main_range_encoder,
				      cur_optimum_ptr->state.main_state, 1);

	base_cost += lzms_rc_bit_cost(&c->match_range_encoder,
				      cur_optimum_ptr->state.match_state, 0);

	base_cost += lzms_rc_bit_cost(&c->lz_match_range_encoder,
				      cur_optimum_ptr->state.lz_match_state, 1);

	for (i = 0; i < rep_idx; i++)
		base_cost += lzms_rc_bit_cost(&c->lz_repeat_match_range_encoders[i],
					      cur_optimum_ptr->state.lz_repeat_match_state[i], 1);

	if (i < LZMS_NUM_RECENT_OFFSETS - 1)
		base_cost += lzms_rc_bit_cost(&c->lz_repeat_match_range_encoders[i],
					      cur_optimum_ptr->state.lz_repeat_match_state[i], 0);

	len = 2;
	do {
		cost = base_cost + lzms_fast_length_cost(c, len);
		if (cost < (cur_optimum_ptr + len)->cost) {
			(cur_optimum_ptr + len)->mc_item_data =
				((u64)rep_idx << MC_OFFSET_SHIFT) | len;
			(cur_optimum_ptr + len)->cost = cost;
		}
	} while (++len <= rep_len);
}

/*
 * Consider coding each match in @matches as an explicit offset match.
 *
 * @matches must be sorted by strictly increasing length and strictly increasing
 * offset.  This is guaranteed by the match-finder.
 *
 * We consider each length from the minimum (2) to the longest
 * (matches[num_matches - 1].len).  For each length, we consider only the
 * smallest offset for which that length is available.  Although this is not
 * guaranteed to be optimal due to the possibility of a larger offset costing
 * less than a smaller offset to code, this is a very useful heuristic.
 */
static inline void
lzms_consider_lz_explicit_offset_matches(const struct lzms_compressor *c,
					 struct lzms_mc_pos_data *cur_optimum_ptr,
					 const struct lz_match matches[],
					 u32 num_matches)
{
	u32 len;
	u32 i;
	u32 base_cost;
	u32 position_cost;
	u32 cost;

	base_cost = cur_optimum_ptr->cost;

	base_cost += lzms_rc_bit_cost(&c->main_range_encoder,
				      cur_optimum_ptr->state.main_state, 1);

	base_cost += lzms_rc_bit_cost(&c->match_range_encoder,
				      cur_optimum_ptr->state.match_state, 0);

	base_cost += lzms_rc_bit_cost(&c->lz_match_range_encoder,
				      cur_optimum_ptr->state.lz_match_state, 0);
	len = 2;
	i = 0;
	do {
		position_cost = base_cost + lzms_lz_offset_cost(c, matches[i].offset);
		do {
			cost = position_cost + lzms_fast_length_cost(c, len);
			if (cost < (cur_optimum_ptr + len)->cost) {
				(cur_optimum_ptr + len)->mc_item_data =
					((u64)(matches[i].offset + LZMS_OFFSET_OFFSET)
						<< MC_OFFSET_SHIFT) | len;
				(cur_optimum_ptr + len)->cost = cost;
			}
		} while (++len <= matches[i].len);
	} while (++i != num_matches);
}

static void
lzms_init_adaptive_state(struct lzms_adaptive_state *state)
{
	unsigned i;

	lzms_init_lz_lru_queue(&state->lru);
	state->main_state = 0;
	state->match_state = 0;
	state->lz_match_state = 0;
	for (i = 0; i < LZMS_NUM_RECENT_OFFSETS - 1; i++)
		state->lz_repeat_match_state[i] = 0;
}

static inline void
lzms_update_main_state(struct lzms_adaptive_state *state, int is_match)
{
	state->main_state = ((state->main_state << 1) | is_match) % LZMS_NUM_MAIN_STATES;
}

static inline void
lzms_update_match_state(struct lzms_adaptive_state *state, int is_delta)
{
	state->match_state = ((state->match_state << 1) | is_delta) % LZMS_NUM_MATCH_STATES;
}

static inline void
lzms_update_lz_match_state(struct lzms_adaptive_state *state, int is_repeat_offset)
{
	state->lz_match_state = ((state->lz_match_state << 1) | is_repeat_offset) % LZMS_NUM_LZ_MATCH_STATES;
}

static inline void
lzms_update_lz_repeat_match_state(struct lzms_adaptive_state *state, int rep_idx)
{
	int i;

	for (i = 0; i < rep_idx; i++)
		state->lz_repeat_match_state[i] =
			((state->lz_repeat_match_state[i] << 1) | 1) %
				LZMS_NUM_LZ_REPEAT_MATCH_STATES;

	if (i < LZMS_NUM_RECENT_OFFSETS - 1)
		state->lz_repeat_match_state[i] =
			((state->lz_repeat_match_state[i] << 1) | 0) %
				LZMS_NUM_LZ_REPEAT_MATCH_STATES;
}

/*
 * The main near-optimal parsing routine.
 *
 * Briefly, the algorithm does an approximate minimum-cost path search to find a
 * "near-optimal" sequence of matches and literals to output, based on the
 * current cost model.  The algorithm steps forward, position by position (byte
 * by byte), and updates the minimum cost path to reach each later position that
 * can be reached using a match or literal from the current position.  This is
 * essentially Dijkstra's algorithm in disguise: the graph nodes are positions,
 * the graph edges are possible matches/literals to code, and the cost of each
 * edge is the estimated number of bits that will be required to output the
 * corresponding match or literal.  But one difference is that we actually
 * compute the lowest-cost path in pieces, where each piece is terminated when
 * there are no choices to be made.
 *
 * Notes:
 *
 * - This does not output any delta matches.
 *
 * - The costs of literals and matches are estimated using the range encoder
 *   states and the semi-adaptive Huffman codes.  Except for range encoding
 *   states, costs are assumed to be constant throughout a single run of the
 *   parsing algorithm, which can parse up to @optim_array_length bytes of data.
 *   This introduces a source of inaccuracy because the probabilities and
 *   Huffman codes can change over this part of the data.
 */
static void
lzms_near_optimal_parse(struct lzms_compressor *c)
{
	const u8 *window_ptr;
	const u8 *window_end;
	struct lzms_mc_pos_data *cur_optimum_ptr;
	struct lzms_mc_pos_data *end_optimum_ptr;
	u32 num_matches;
	u32 longest_len;
	u32 rep_max_len;
	unsigned rep_max_idx;
	unsigned literal;
	unsigned i;
	u32 cost;
	u32 len;
	u32 offset_data;

	window_ptr = c->cur_window;
	window_end = window_ptr + c->cur_window_size;

	lzms_init_adaptive_state(&c->optimum[0].state);

begin:
	/* Start building a new list of items, which will correspond to the next
	 * piece of the overall minimum-cost path.  */

	cur_optimum_ptr = c->optimum;
	cur_optimum_ptr->cost = 0;
	end_optimum_ptr = cur_optimum_ptr;

	/* States should currently be consistent with the encoders.  */
	LZMS_ASSERT(cur_optimum_ptr->state.main_state == c->main_range_encoder.state);
	LZMS_ASSERT(cur_optimum_ptr->state.match_state == c->match_range_encoder.state);
	LZMS_ASSERT(cur_optimum_ptr->state.lz_match_state == c->lz_match_range_encoder.state);
	for (i = 0; i < LZMS_NUM_RECENT_OFFSETS - 1; i++)
		LZMS_ASSERT(cur_optimum_ptr->state.lz_repeat_match_state[i] ==
			    c->lz_repeat_match_range_encoders[i].state);

	if (window_ptr == window_end)
		return;

	/* The following loop runs once for each per byte in the window, except
	 * in a couple shortcut cases.  */
	for (;;) {

		/* Find explicit offset matches with the current position.  */
		num_matches = lz_mf_get_matches(c->mf, c->matches);

		if (num_matches) {
			/*
			 * Find the longest repeat offset match with the current
			 * position.
			 *
			 * Heuristics:
			 *
			 * - Only search for repeat offset matches if the
			 *   match-finder already found at least one match.
			 *
			 * - Only consider the longest repeat offset match.  It
			 *   seems to be rare for the optimal parse to include a
			 *   repeat offset match that doesn't have the longest
			 *   length (allowing for the possibility that not all
			 *   of that length is actually used).
			 */
			if (likely(window_ptr - c->cur_window >= LZMS_MAX_INIT_RECENT_OFFSET)) {
				BUILD_BUG_ON(LZMS_NUM_RECENT_OFFSETS != 3);
				rep_max_len = lz_repsearch3(window_ptr,
							    window_end - window_ptr,
							    cur_optimum_ptr->state.lru.recent_offsets,
							    &rep_max_idx);
			} else {
				rep_max_len = 0;
			}

			if (rep_max_len) {
				/* If there's a very long repeat offset match,
				 * choose it immediately.  */
				if (rep_max_len >= c->params.nice_match_length) {

					lz_mf_skip_positions(c->mf, rep_max_len - 1);
					window_ptr += rep_max_len;

					if (cur_optimum_ptr != c->optimum)
						lzms_encode_item_list(c, cur_optimum_ptr);

					lzms_encode_lz_repeat_offset_match(c, rep_max_len,
									   rep_max_idx);

					c->optimum[0].state = cur_optimum_ptr->state;

					lzms_update_main_state(&c->optimum[0].state, 1);
					lzms_update_match_state(&c->optimum[0].state, 0);
					lzms_update_lz_match_state(&c->optimum[0].state, 1);
					lzms_update_lz_repeat_match_state(&c->optimum[0].state,
									  rep_max_idx);

					c->optimum[0].state.lru.upcoming_offset =
						c->optimum[0].state.lru.recent_offsets[rep_max_idx];

					for (i = rep_max_idx; i < LZMS_NUM_RECENT_OFFSETS; i++)
						c->optimum[0].state.lru.recent_offsets[i] =
							c->optimum[0].state.lru.recent_offsets[i + 1];

					lzms_update_lz_lru_queue(&c->optimum[0].state.lru);
					goto begin;
				}

				/* If reaching any positions for the first time,
				 * initialize their costs to "infinity".  */
				while (end_optimum_ptr < cur_optimum_ptr + rep_max_len)
					(++end_optimum_ptr)->cost = MC_INFINITE_COST;

				/* Consider coding a repeat offset match.  */
				lzms_consider_lz_repeat_offset_match(c, cur_optimum_ptr,
								     rep_max_len, rep_max_idx);
			}

			longest_len = c->matches[num_matches - 1].len;

			/* If there's a very long explicit offset match, choose
			 * it immediately.  */
			if (longest_len >= c->params.nice_match_length) {

				lz_mf_skip_positions(c->mf, longest_len - 1);
				window_ptr += longest_len;

				if (cur_optimum_ptr != c->optimum)
					lzms_encode_item_list(c, cur_optimum_ptr);

				lzms_encode_lz_explicit_offset_match(c, longest_len,
								     c->matches[num_matches - 1].offset);

				c->optimum[0].state = cur_optimum_ptr->state;

				lzms_update_main_state(&c->optimum[0].state, 1);
				lzms_update_match_state(&c->optimum[0].state, 0);
				lzms_update_lz_match_state(&c->optimum[0].state, 0);

				c->optimum[0].state.lru.upcoming_offset =
					c->matches[num_matches - 1].offset;

				lzms_update_lz_lru_queue(&c->optimum[0].state.lru);
				goto begin;
			}

			/* If reaching any positions for the first time,
			 * initialize their costs to "infinity".  */
			while (end_optimum_ptr < cur_optimum_ptr + longest_len)
				(++end_optimum_ptr)->cost = MC_INFINITE_COST;

			/* Consider coding an explicit offset match.  */
			lzms_consider_lz_explicit_offset_matches(c, cur_optimum_ptr,
								 c->matches, num_matches);
		} else {
			/* No matches found.  The only choice at this position
			 * is to code a literal.  */

			if (end_optimum_ptr == cur_optimum_ptr)
				(++end_optimum_ptr)->cost = MC_INFINITE_COST;
		}

		/* Consider coding a literal.

		 * To avoid an extra unpredictable brench, actually checking the
		 * preferability of coding a literal is integrated into the
		 * adaptive state update code below.  */
		literal = *window_ptr++;
		cost = cur_optimum_ptr->cost +
		       lzms_literal_cost(c, literal, &cur_optimum_ptr->state);

		/* Advance to the next position.  */
		cur_optimum_ptr++;

		/* The lowest-cost path to the current position is now known.
		 * Finalize the adaptive state that results from taking this
		 * lowest-cost path.  */

		if (cost < cur_optimum_ptr->cost) {
			/* Literal  */
			cur_optimum_ptr->cost = cost;
			cur_optimum_ptr->mc_item_data = ((u64)literal << MC_OFFSET_SHIFT) | 1;

			cur_optimum_ptr->state = (cur_optimum_ptr - 1)->state;

			lzms_update_main_state(&cur_optimum_ptr->state, 0);

			cur_optimum_ptr->state.lru.upcoming_offset = 0;
		} else {
			/* LZ match  */
			len = cur_optimum_ptr->mc_item_data & MC_LEN_MASK;
			offset_data = cur_optimum_ptr->mc_item_data >> MC_OFFSET_SHIFT;

			cur_optimum_ptr->state = (cur_optimum_ptr - len)->state;

			lzms_update_main_state(&cur_optimum_ptr->state, 1);
			lzms_update_match_state(&cur_optimum_ptr->state, 0);

			if (offset_data >= LZMS_NUM_RECENT_OFFSETS) {

				/* Explicit offset LZ match  */

				lzms_update_lz_match_state(&cur_optimum_ptr->state, 0);

				cur_optimum_ptr->state.lru.upcoming_offset =
					offset_data - LZMS_OFFSET_OFFSET;
			} else {
				/* Repeat offset LZ match  */

				lzms_update_lz_match_state(&cur_optimum_ptr->state, 1);
				lzms_update_lz_repeat_match_state(&cur_optimum_ptr->state,
								  offset_data);

				cur_optimum_ptr->state.lru.upcoming_offset =
					cur_optimum_ptr->state.lru.recent_offsets[offset_data];

				for (i = offset_data; i < LZMS_NUM_RECENT_OFFSETS; i++)
					cur_optimum_ptr->state.lru.recent_offsets[i] =
						cur_optimum_ptr->state.lru.recent_offsets[i + 1];
			}
		}

		lzms_update_lz_lru_queue(&cur_optimum_ptr->state.lru);

		/*
		 * This loop will terminate when either of the following
		 * conditions is true:
		 *
		 * (1) cur_optimum_ptr == end_optimum_ptr
		 *
		 *	There are no paths that extend beyond the current
		 *	position.  In this case, any path to a later position
		 *	must pass through the current position, so we can go
		 *	ahead and choose the list of items that led to this
		 *	position.
		 *
		 * (2) cur_optimum_ptr == c->optimum_end
		 *
		 *	This bounds the number of times the algorithm can step
		 *	forward before it is guaranteed to start choosing items.
		 *	This limits the memory usage.  It also guarantees that
		 *	the parser will not go too long without updating the
		 *	probability tables.
		 *
		 * Note: no check for end-of-window is needed because
		 * end-of-window will trigger condition (1).
		 */
		if (cur_optimum_ptr == end_optimum_ptr ||
		    cur_optimum_ptr == c->optimum_end)
		{
			c->optimum[0].state = cur_optimum_ptr->state;
			break;
		}
	}

	/* Output the current list of items that constitute the minimum-cost
	 * path to the current position.  */
	lzms_encode_item_list(c, cur_optimum_ptr);
	goto begin;
}

static void
lzms_init_range_encoder(struct lzms_range_encoder *enc,
			struct lzms_range_encoder_raw *rc, u32 num_states)
{
	enc->rc = rc;
	enc->state = 0;
	LZMS_ASSERT(is_power_of_2(num_states));
	enc->mask = num_states - 1;
	lzms_init_probability_entries(enc->prob_entries, num_states);
}

static void
lzms_init_huffman_encoder(struct lzms_huffman_encoder *enc,
			  struct lzms_output_bitstream *os,
			  unsigned num_syms,
			  unsigned rebuild_freq)
{
	enc->os = os;
	enc->num_syms_written = 0;
	enc->rebuild_freq = rebuild_freq;
	enc->num_syms = num_syms;
	for (unsigned i = 0; i < num_syms; i++)
		enc->sym_freqs[i] = 1;

	make_canonical_huffman_code(enc->num_syms,
				    LZMS_MAX_CODEWORD_LEN,
				    enc->sym_freqs,
				    enc->lens,
				    enc->codewords);
}

/* Prepare the LZMS compressor for compressing a block of data.  */
static void
lzms_prepare_compressor(struct lzms_compressor *c, const u8 *udata, u32 ulen,
			le16 *cdata, u32 clen16)
{
	unsigned num_offset_slots;

	/* Copy the uncompressed data into the @c->cur_window buffer.  */
	memcpy(c->cur_window, udata, ulen);
	c->cur_window_size = ulen;

	/* Initialize the raw range encoder (writing forwards).  */
	lzms_range_encoder_raw_init(&c->rc, cdata, clen16);

	/* Initialize the output bitstream for Huffman symbols and verbatim bits
	 * (writing backwards).  */
	lzms_output_bitstream_init(&c->os, cdata, clen16);

	/* Calculate the number of offset slots required.  */
	num_offset_slots = lzms_get_offset_slot(ulen - 1) + 1;

	/* Initialize a Huffman encoder for each alphabet.  */
	lzms_init_huffman_encoder(&c->literal_encoder, &c->os,
				  LZMS_NUM_LITERAL_SYMS,
				  LZMS_LITERAL_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&c->lz_offset_encoder, &c->os,
				  num_offset_slots,
				  LZMS_LZ_OFFSET_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&c->length_encoder, &c->os,
				  LZMS_NUM_LENGTH_SYMS,
				  LZMS_LENGTH_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&c->delta_offset_encoder, &c->os,
				  num_offset_slots,
				  LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&c->delta_power_encoder, &c->os,
				  LZMS_NUM_DELTA_POWER_SYMS,
				  LZMS_DELTA_POWER_CODE_REBUILD_FREQ);

	/* Initialize range encoders, all of which wrap around the same
	 * lzms_range_encoder_raw.  */
	lzms_init_range_encoder(&c->main_range_encoder,
				&c->rc, LZMS_NUM_MAIN_STATES);

	lzms_init_range_encoder(&c->match_range_encoder,
				&c->rc, LZMS_NUM_MATCH_STATES);

	lzms_init_range_encoder(&c->lz_match_range_encoder,
				&c->rc, LZMS_NUM_LZ_MATCH_STATES);

	for (unsigned i = 0; i < ARRAY_LEN(c->lz_repeat_match_range_encoders); i++)
		lzms_init_range_encoder(&c->lz_repeat_match_range_encoders[i],
					&c->rc, LZMS_NUM_LZ_REPEAT_MATCH_STATES);

	lzms_init_range_encoder(&c->delta_match_range_encoder,
				&c->rc, LZMS_NUM_DELTA_MATCH_STATES);

	for (unsigned i = 0; i < ARRAY_LEN(c->delta_repeat_match_range_encoders); i++)
		lzms_init_range_encoder(&c->delta_repeat_match_range_encoders[i],
					&c->rc, LZMS_NUM_DELTA_REPEAT_MATCH_STATES);

	/* Set initial length costs for lengths < LZMS_NUM_FAST_LENGTHS.  */
	lzms_update_fast_length_costs(c);
}

/* Flush the output streams, prepare the final compressed data, and return its
 * size in bytes.
 *
 * A return value of 0 indicates that the data could not be compressed to fit in
 * the available space.  */
static size_t
lzms_finalize(struct lzms_compressor *c, u8 *cdata, size_t csize_avail)
{
	size_t num_forwards_bytes;
	size_t num_backwards_bytes;

	/* Flush both the forwards and backwards streams, and make sure they
	 * didn't cross each other and start overwriting each other's data.  */
	if (!lzms_output_bitstream_flush(&c->os))
		return 0;

	if (!lzms_range_encoder_raw_flush(&c->rc))
		return 0;

	if (c->rc.next > c->os.next)
		return 0;

	/* Now the compressed buffer contains the data output by the forwards
	 * bitstream, then empty space, then data output by the backwards
	 * bitstream.  Move the data output by the backwards bitstream to be
	 * adjacent to the data output by the forward bitstream, and calculate
	 * the compressed size that this results in.  */
	num_forwards_bytes = (u8*)c->rc.next - (u8*)cdata;
	num_backwards_bytes = ((u8*)cdata + csize_avail) - (u8*)c->os.next;

	memmove(cdata + num_forwards_bytes, c->os.next, num_backwards_bytes);

	return num_forwards_bytes + num_backwards_bytes;
}

/* Set internal compression parameters for the specified compression level and
 * maximum window size.  */
static void
lzms_build_params(unsigned int compression_level,
		  struct lzms_compressor_params *params)
{
	/* Allow length 2 matches if the compression level is sufficiently high.
	 */
	if (compression_level >= 45)
		params->min_match_length = 2;
	else
		params->min_match_length = 3;

	/* Scale nice_match_length and max_search_depth with the compression
	 * level.  But to allow an optimization on length cost calculations,
	 * don't allow nice_match_length to exceed LZMS_NUM_FAST_LENGTH.  */
	params->nice_match_length = ((u64)compression_level * 32) / 50;
	if (params->nice_match_length < params->min_match_length)
		params->nice_match_length = params->min_match_length;
	if (params->nice_match_length > LZMS_NUM_FAST_LENGTHS)
		params->nice_match_length = LZMS_NUM_FAST_LENGTHS;
	params->max_search_depth = compression_level;

	params->optim_array_length = 1024;
}

/* Given the internal compression parameters and maximum window size, build the
 * Lempel-Ziv match-finder parameters.  */
static void
lzms_build_mf_params(const struct lzms_compressor_params *lzms_params,
		     u32 max_window_size, struct lz_mf_params *mf_params)
{
	memset(mf_params, 0, sizeof(*mf_params));

	/* Choose an appropriate match-finding algorithm.  */
	if (max_window_size <= 2097152)
		mf_params->algorithm = LZ_MF_BINARY_TREES;
	else if (max_window_size <= 33554432)
		mf_params->algorithm = LZ_MF_LCP_INTERVAL_TREE;
	else
		mf_params->algorithm = LZ_MF_LINKED_SUFFIX_ARRAY;

	mf_params->max_window_size = max_window_size;
	mf_params->min_match_len = lzms_params->min_match_length;
	mf_params->max_search_depth = lzms_params->max_search_depth;
	mf_params->nice_match_len = lzms_params->nice_match_length;
}

static void
lzms_free_compressor(void *_c);

static u64
lzms_get_needed_memory(size_t max_block_size, unsigned int compression_level)
{
	struct lzms_compressor_params params;
	struct lz_mf_params mf_params;
	u64 size = 0;

	if (max_block_size >= INT32_MAX)
		return 0;

	lzms_build_params(compression_level, &params);
	lzms_build_mf_params(&params, max_block_size, &mf_params);

	size += sizeof(struct lzms_compressor);

	/* cur_window */
	size += max_block_size;

	/* mf */
	size += lz_mf_get_needed_memory(mf_params.algorithm, max_block_size);

	/* matches */
	size += min(params.max_search_depth, params.nice_match_length) *
		sizeof(struct lz_match);

	/* optimum */
	size += (params.optim_array_length + params.nice_match_length) *
		sizeof(struct lzms_mc_pos_data);

	return size;
}

static int
lzms_create_compressor(size_t max_block_size, unsigned int compression_level,
		       void **ctx_ret)
{
	struct lzms_compressor *c;
	struct lzms_compressor_params params;
	struct lz_mf_params mf_params;

	if (max_block_size >= INT32_MAX)
		return WIMLIB_ERR_INVALID_PARAM;

	lzms_build_params(compression_level, &params);
	lzms_build_mf_params(&params, max_block_size, &mf_params);
	if (!lz_mf_params_valid(&mf_params))
		return WIMLIB_ERR_INVALID_PARAM;

	c = CALLOC(1, sizeof(struct lzms_compressor));
	if (!c)
		goto oom;

	c->params = params;

	c->cur_window = MALLOC(max_block_size);
	if (!c->cur_window)
		goto oom;

	c->mf = lz_mf_alloc(&mf_params);
	if (!c->mf)
		goto oom;

	c->matches = MALLOC(min(params.max_search_depth,
				params.nice_match_length) *
			    sizeof(struct lz_match));
	if (!c->matches)
		goto oom;

	c->optimum = MALLOC((params.optim_array_length +
			     params.nice_match_length) *
			    sizeof(struct lzms_mc_pos_data));
	if (!c->optimum)
		goto oom;
	c->optimum_end = &c->optimum[params.optim_array_length];

	lzms_init_rc_costs();

	lzms_init_fast_slots(c);

	*ctx_ret = c;
	return 0;

oom:
	lzms_free_compressor(c);
	return WIMLIB_ERR_NOMEM;
}

static size_t
lzms_compress(const void *uncompressed_data, size_t uncompressed_size,
	      void *compressed_data, size_t compressed_size_avail, void *_c)
{
	struct lzms_compressor *c = _c;

	/* Don't bother compressing extremely small inputs.  */
	if (uncompressed_size < 4)
		return 0;

	/* Cap the available compressed size to a 32-bit integer and round it
	 * down to the nearest multiple of 2.  */
	if (compressed_size_avail > UINT32_MAX)
		compressed_size_avail = UINT32_MAX;
	if (compressed_size_avail & 1)
		compressed_size_avail--;

	/* Initialize the compressor structures.  */
	lzms_prepare_compressor(c, uncompressed_data, uncompressed_size,
				compressed_data, compressed_size_avail / 2);

	/* Preprocess the uncompressed data.  */
	lzms_x86_filter(c->cur_window, c->cur_window_size,
			c->last_target_usages, false);

	/* Load the window into the match-finder.  */
	lz_mf_load_window(c->mf, c->cur_window, c->cur_window_size);

	/* Compute and encode a literal/match sequence that decompresses to the
	 * preprocessed data.  */
	lzms_near_optimal_parse(c);

	/* Return the compressed data size or 0.  */
	return lzms_finalize(c, compressed_data, compressed_size_avail);
}

static void
lzms_free_compressor(void *_c)
{
	struct lzms_compressor *c = _c;

	if (c) {
		FREE(c->cur_window);
		lz_mf_free(c->mf);
		FREE(c->matches);
		FREE(c->optimum);
		FREE(c);
	}
}

const struct compressor_ops lzms_compressor_ops = {
	.get_needed_memory  = lzms_get_needed_memory,
	.create_compressor  = lzms_create_compressor,
	.compress	    = lzms_compress,
	.free_compressor    = lzms_free_compressor,
};
