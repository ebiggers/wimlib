/*
 * lzms-compress.c
 */

/*
 * Copyright (C) 2013, 2014 Eric Biggers
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

/* This a compressor for the LZMS compression format.  More details about this
 * format can be found in lzms-decompress.c.
 *
 * Also see lzx-compress.c for general information about match-finding and
 * match-choosing that also applies to this LZMS compressor.
 *
 * NOTE: this compressor currently does not code any delta matches.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/assert.h"
#include "wimlib/compiler.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/compress_common.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lz.h"
#include "wimlib/lz_bt.h"
#include "wimlib/lzms.h"
#include "wimlib/util.h"

#include <string.h>
#include <limits.h>
#include <pthread.h>

/* Stucture used for writing raw bits to the end of the LZMS-compressed data as
 * a series of 16-bit little endian coding units.  */
struct lzms_output_bitstream {
	/* Buffer variable containing zero or more bits that have been logically
	 * written to the bitstream but not yet written to memory.  This must be
	 * at least as large as the coding unit size.  */
	u16 bitbuf;

	/* Number of bits in @bitbuf that are valid.  */
	unsigned num_free_bits;

	/* Pointer to one past the next position in the compressed data buffer
	 * at which to output a 16-bit coding unit.  */
	le16 *out;

	/* Maximum number of 16-bit coding units that can still be output to
	 * the compressed data buffer.  */
	size_t num_le16_remaining;

	/* Set to %true if not all coding units could be output due to
	 * insufficient space.  */
	bool overrun;
};

/* Stucture used for range encoding (raw version).  */
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

	/* Pointer to the next position in the compressed data buffer at which
	 * to output a 16-bit coding unit.  */
	le16 *out;

	/* Maximum number of 16-bit coding units that can still be output to
	 * the compressed data buffer.  */
	size_t num_le16_remaining;

	/* %true when the very first coding unit has not yet been output.  */
	bool first;

	/* Set to %true if not all coding units could be output due to
	 * insufficient space.  */
	bool overrun;
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

/* State of the LZMS compressor.  */
struct lzms_compressor {
	struct wimlib_lzms_compressor_params params;

	/* Pointer to a buffer holding the preprocessed data to compress.  */
	u8 *window;

	/* Current position in @buffer.  */
	u32 cur_window_pos;

	/* Size of the data in @buffer.  */
	u32 window_size;

	/* Binary tree match-finder.  */
	struct lz_bt mf;

	/* Temporary space to store found matches.  */
	struct lz_match *matches;

	/* Match-chooser data.  */
	struct lzms_mc_pos_data *optimum;
	unsigned optimum_cur_idx;
	unsigned optimum_end_idx;

	/* Maximum block size this compressor instantiation allows.  This is the
	 * allocated size of @window.  */
	u32 max_block_size;

	/* Raw range encoder which outputs to the beginning of the compressed
	 * data buffer, proceeding forwards.  */
	struct lzms_range_encoder_raw rc;

	/* Bitstream which outputs to the end of the compressed data buffer,
	 * proceeding backwards.  */
	struct lzms_output_bitstream os;

	/* Range encoders.  */
	struct lzms_range_encoder main_range_encoder;
	struct lzms_range_encoder match_range_encoder;
	struct lzms_range_encoder lz_match_range_encoder;
	struct lzms_range_encoder lz_repeat_match_range_encoders[LZMS_NUM_RECENT_OFFSETS - 1];
	struct lzms_range_encoder delta_match_range_encoder;
	struct lzms_range_encoder delta_repeat_match_range_encoders[LZMS_NUM_RECENT_OFFSETS - 1];

	/* Huffman encoders.  */
	struct lzms_huffman_encoder literal_encoder;
	struct lzms_huffman_encoder lz_offset_encoder;
	struct lzms_huffman_encoder length_encoder;
	struct lzms_huffman_encoder delta_power_encoder;
	struct lzms_huffman_encoder delta_offset_encoder;

	/* LRU (least-recently-used) queues for match information.  */
	struct lzms_lru_queues lru;

	/* Used for preprocessing.  */
	s32 last_target_usages[65536];
};

struct lzms_mc_pos_data {
	u32 cost;
#define MC_INFINITE_COST ((u32)~0UL)
	union {
		struct {
			u32 link;
			u32 match_offset;
		} prev;
		struct {
			u32 link;
			u32 match_offset;
		} next;
	};
	struct lzms_adaptive_state {
		struct lzms_lz_lru_queues lru;
		u8 main_state;
		u8 match_state;
		u8 lz_match_state;
		u8 lz_repeat_match_state[LZMS_NUM_RECENT_OFFSETS - 1];
	} state;
};

/* Initialize the output bitstream @os to write forwards to the specified
 * compressed data buffer @out that is @out_limit 16-bit integers long.  */
static void
lzms_output_bitstream_init(struct lzms_output_bitstream *os,
			   le16 *out, size_t out_limit)
{
	os->bitbuf = 0;
	os->num_free_bits = 16;
	os->out = out + out_limit;
	os->num_le16_remaining = out_limit;
	os->overrun = false;
}

/* Write @num_bits bits, contained in the low @num_bits bits of @bits (ordered
 * from high-order to low-order), to the output bitstream @os.  */
static void
lzms_output_bitstream_put_bits(struct lzms_output_bitstream *os,
			       u32 bits, unsigned num_bits)
{
	bits &= (1U << num_bits) - 1;

	while (num_bits > os->num_free_bits) {

		if (unlikely(os->num_le16_remaining == 0)) {
			os->overrun = true;
			return;
		}

		unsigned num_fill_bits = os->num_free_bits;

		os->bitbuf <<= num_fill_bits;
		os->bitbuf |= bits >> (num_bits - num_fill_bits);

		*--os->out = cpu_to_le16(os->bitbuf);
		--os->num_le16_remaining;

		os->num_free_bits = 16;
		num_bits -= num_fill_bits;
		bits &= (1U << num_bits) - 1;
	}
	os->bitbuf <<= num_bits;
	os->bitbuf |= bits;
	os->num_free_bits -= num_bits;
}

/* Flush the output bitstream, ensuring that all bits written to it have been
 * written to memory.  Returns %true if all bits were output successfully, or
 * %false if an overrun occurred.  */
static bool
lzms_output_bitstream_flush(struct lzms_output_bitstream *os)
{
	if (os->num_free_bits != 16)
		lzms_output_bitstream_put_bits(os, 0, os->num_free_bits + 1);
	return !os->overrun;
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
	rc->out = out;
	rc->num_le16_remaining = out_limit;
	rc->first = true;
	rc->overrun = false;
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
	LZMS_DEBUG("low=%"PRIx64", cache=%"PRIx64", cache_size=%u",
		   rc->low, rc->cache, rc->cache_size);
	if ((u32)(rc->low) < 0xffff0000 ||
	    (u32)(rc->low >> 32) != 0)
	{
		/* Carry not needed (rc->low < 0xffff0000), or carry occurred
		 * ((rc->low >> 32) != 0, a.k.a. the carry bit is 1).  */
		do {
			if (!rc->first) {
				if (rc->num_le16_remaining == 0) {
					rc->overrun = true;
					return;
				}
				*rc->out++ = cpu_to_le16(rc->cache +
							 (u16)(rc->low >> 32));
				--rc->num_le16_remaining;
			} else {
				rc->first = false;
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
	return !rc->overrun;
}

/* Encode the next bit using the range encoder (raw version).
 *
 * @prob is the chance out of LZMS_PROBABILITY_MAX that the next bit is 0.  */
static void
lzms_range_encoder_raw_encode_bit(struct lzms_range_encoder_raw *rc, int bit,
				  u32 prob)
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
 * appropriate probability table.  */
static void
lzms_range_encode_bit(struct lzms_range_encoder *enc, int bit)
{
	struct lzms_probability_entry *prob_entry;
	u32 prob;

	/* Load the probability entry corresponding to the current state.  */
	prob_entry = &enc->prob_entries[enc->state];

	/* Treat the number of zero bits in the most recently encoded
	 * LZMS_PROBABILITY_MAX bits with this probability entry as the chance,
	 * out of LZMS_PROBABILITY_MAX, that the next bit will be a 0.  However,
	 * don't allow 0% or 100% probabilities.  */
	prob = prob_entry->num_recent_zero_bits;
	if (prob == 0)
		prob = 1;
	else if (prob == LZMS_PROBABILITY_MAX)
		prob = LZMS_PROBABILITY_MAX - 1;

	/* Encode the next bit.  */
	lzms_range_encoder_raw_encode_bit(enc->rc, bit, prob);

	/* Update the state based on the newly encoded bit.  */
	enc->state = ((enc->state << 1) | bit) & enc->mask;

	/* Update the recent bits, including the cached count of 0's.  */
	BUILD_BUG_ON(LZMS_PROBABILITY_MAX > sizeof(prob_entry->recent_bits) * 8);
	if (bit == 0) {
		if (prob_entry->recent_bits & (1ULL << (LZMS_PROBABILITY_MAX - 1))) {
			/* Replacing 1 bit with 0 bit; increment the zero count.
			 */
			prob_entry->num_recent_zero_bits++;
		}
	} else {
		if (!(prob_entry->recent_bits & (1ULL << (LZMS_PROBABILITY_MAX - 1)))) {
			/* Replacing 0 bit with 1 bit; decrement the zero count.
			 */
			prob_entry->num_recent_zero_bits--;
		}
	}
	prob_entry->recent_bits = (prob_entry->recent_bits << 1) | bit;
}

/* Encode a symbol using the specified Huffman encoder.  */
static void
lzms_huffman_encode_symbol(struct lzms_huffman_encoder *enc, u32 sym)
{
	LZMS_ASSERT(sym < enc->num_syms);
	lzms_output_bitstream_put_bits(enc->os,
				       enc->codewords[sym],
				       enc->lens[sym]);
	++enc->sym_freqs[sym];
	if (++enc->num_syms_written == enc->rebuild_freq) {
		/* Adaptive code needs to be rebuilt.  */
		LZMS_DEBUG("Rebuilding code (num_syms=%u)", enc->num_syms);
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
}

static void
lzms_encode_length(struct lzms_huffman_encoder *enc, u32 length)
{
	unsigned slot;
	unsigned num_extra_bits;
	u32 extra_bits;

	slot = lzms_get_length_slot(length);

	num_extra_bits = lzms_extra_length_bits[slot];

	extra_bits = length - lzms_length_slot_base[slot];

	lzms_huffman_encode_symbol(enc, slot);
	lzms_output_bitstream_put_bits(enc->os, extra_bits, num_extra_bits);
}

static void
lzms_encode_offset(struct lzms_huffman_encoder *enc, u32 offset)
{
	unsigned slot;
	unsigned num_extra_bits;
	u32 extra_bits;

	slot = lzms_get_position_slot(offset);

	num_extra_bits = lzms_extra_position_bits[slot];

	extra_bits = offset - lzms_position_slot_base[slot];

	lzms_huffman_encode_symbol(enc, slot);
	lzms_output_bitstream_put_bits(enc->os, extra_bits, num_extra_bits);
}

static void
lzms_begin_encode_item(struct lzms_compressor *ctx)
{
	ctx->lru.lz.upcoming_offset = 0;
	ctx->lru.delta.upcoming_offset = 0;
	ctx->lru.delta.upcoming_power = 0;
}

static void
lzms_end_encode_item(struct lzms_compressor *ctx, u32 length)
{
	LZMS_ASSERT(ctx->window_size - ctx->cur_window_pos >= length);
	ctx->cur_window_pos += length;
	lzms_update_lru_queues(&ctx->lru);
}

/* Encode a literal byte.  */
static void
lzms_encode_literal(struct lzms_compressor *ctx, u8 literal)
{
	LZMS_DEBUG("Position %u: Encoding literal 0x%02x ('%c')",
		   ctx->cur_window_pos, literal, literal);

	lzms_begin_encode_item(ctx);

	/* Main bit: 0 = a literal, not a match.  */
	lzms_range_encode_bit(&ctx->main_range_encoder, 0);

	/* Encode the literal using the current literal Huffman code.  */
	lzms_huffman_encode_symbol(&ctx->literal_encoder, literal);

	lzms_end_encode_item(ctx, 1);
}

/* Encode a (length, offset) pair (LZ match).  */
static void
lzms_encode_lz_match(struct lzms_compressor *ctx, u32 length, u32 offset)
{
	int recent_offset_idx;

	LZMS_DEBUG("Position %u: Encoding LZ match {length=%u, offset=%u}",
		   ctx->cur_window_pos, length, offset);

	LZMS_ASSERT(length <= ctx->window_size - ctx->cur_window_pos);
	LZMS_ASSERT(offset <= ctx->cur_window_pos);
	LZMS_ASSERT(!memcmp(&ctx->window[ctx->cur_window_pos],
			    &ctx->window[ctx->cur_window_pos - offset],
			    length));

	lzms_begin_encode_item(ctx);

	/* Main bit: 1 = a match, not a literal.  */
	lzms_range_encode_bit(&ctx->main_range_encoder, 1);

	/* Match bit: 0 = an LZ match, not a delta match.  */
	lzms_range_encode_bit(&ctx->match_range_encoder, 0);

	/* Determine if the offset can be represented as a recent offset.  */
	for (recent_offset_idx = 0;
	     recent_offset_idx < LZMS_NUM_RECENT_OFFSETS;
	     recent_offset_idx++)
		if (offset == ctx->lru.lz.recent_offsets[recent_offset_idx])
			break;

	if (recent_offset_idx == LZMS_NUM_RECENT_OFFSETS) {
		/* Explicit offset.  */

		/* LZ match bit: 0 = explicit offset, not a recent offset.  */
		lzms_range_encode_bit(&ctx->lz_match_range_encoder, 0);

		/* Encode the match offset.  */
		lzms_encode_offset(&ctx->lz_offset_encoder, offset);
	} else {
		int i;

		/* Recent offset.  */

		/* LZ match bit: 1 = recent offset, not an explicit offset.  */
		lzms_range_encode_bit(&ctx->lz_match_range_encoder, 1);

		/* Encode the recent offset index.  A 1 bit is encoded for each
		 * index passed up.  This sequence of 1 bits is terminated by a
		 * 0 bit, or automatically when (LZMS_NUM_RECENT_OFFSETS - 1) 1
		 * bits have been encoded.  */
		for (i = 0; i < recent_offset_idx; i++)
			lzms_range_encode_bit(&ctx->lz_repeat_match_range_encoders[i], 1);

		if (i < LZMS_NUM_RECENT_OFFSETS - 1)
			lzms_range_encode_bit(&ctx->lz_repeat_match_range_encoders[i], 0);

		/* Initial update of the LZ match offset LRU queue.  */
		for (; i < LZMS_NUM_RECENT_OFFSETS; i++)
			ctx->lru.lz.recent_offsets[i] = ctx->lru.lz.recent_offsets[i + 1];
	}

	/* Encode the match length.  */
	lzms_encode_length(&ctx->length_encoder, length);

	/* Save the match offset for later insertion at the front of the LZ
	 * match offset LRU queue.  */
	ctx->lru.lz.upcoming_offset = offset;

	lzms_end_encode_item(ctx, length);
}

#define LZMS_COST_SHIFT 5

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
			while (w >= (1U << 16)) {
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

/*
 * Return the cost to range-encode the specified bit when in the specified
 * state.
 *
 * @enc		The range encoder to use.
 * @cur_state	Current state, which indicates the probability entry to choose.
 *		Updated by this function.
 * @bit		The bit to encode (0 or 1).
 */
static u32
lzms_rc_bit_cost(const struct lzms_range_encoder *enc, u8 *cur_state, int bit)
{
	u32 prob_zero;
	u32 prob_correct;

	prob_zero = enc->prob_entries[*cur_state & enc->mask].num_recent_zero_bits;

	*cur_state = (*cur_state << 1) | bit;

	if (bit == 0)
		prob_correct = prob_zero;
	else
		prob_correct = LZMS_PROBABILITY_MAX - prob_zero;

	return lzms_rc_costs[prob_correct];
}

static u32
lzms_huffman_symbol_cost(const struct lzms_huffman_encoder *enc, u32 sym)
{
	return enc->lens[sym] << LZMS_COST_SHIFT;
}

static u32
lzms_offset_cost(const struct lzms_huffman_encoder *enc, u32 offset)
{
	u32 slot;
	u32 num_extra_bits;
	u32 cost = 0;

	slot = lzms_get_position_slot(offset);

	cost += lzms_huffman_symbol_cost(enc, slot);

	num_extra_bits = lzms_extra_position_bits[slot];

	cost += num_extra_bits << LZMS_COST_SHIFT;

	return cost;
}

static u32
lzms_get_length_cost(const struct lzms_huffman_encoder *enc, u32 length)
{
	u32 slot;
	u32 num_extra_bits;
	u32 cost = 0;

	slot = lzms_get_length_slot(length);

	cost += lzms_huffman_symbol_cost(enc, slot);

	num_extra_bits = lzms_extra_length_bits[slot];

	cost += num_extra_bits << LZMS_COST_SHIFT;

	return cost;
}

static u32
lzms_get_matches(struct lzms_compressor *ctx, struct lz_match **matches_ret)
{
	*matches_ret = ctx->matches;
	return lz_bt_get_matches(&ctx->mf, ctx->matches);
}

static void
lzms_skip_bytes(struct lzms_compressor *ctx, u32 n)
{
	lz_bt_skip_positions(&ctx->mf, n);
}

static u32
lzms_get_literal_cost(struct lzms_compressor *ctx,
		      struct lzms_adaptive_state *state, u8 literal)
{
	u32 cost = 0;

	state->lru.upcoming_offset = 0;
	lzms_update_lz_lru_queues(&state->lru);

	cost += lzms_rc_bit_cost(&ctx->main_range_encoder,
				 &state->main_state, 0);

	cost += lzms_huffman_symbol_cost(&ctx->literal_encoder, literal);

	return cost;
}

static u32
lzms_get_lz_match_cost_nolen(struct lzms_compressor *ctx,
			     struct lzms_adaptive_state *state, u32 offset)
{
	u32 cost = 0;
	int recent_offset_idx;

	cost += lzms_rc_bit_cost(&ctx->main_range_encoder,
				 &state->main_state, 1);
	cost += lzms_rc_bit_cost(&ctx->match_range_encoder,
				 &state->match_state, 0);

	for (recent_offset_idx = 0;
	     recent_offset_idx < LZMS_NUM_RECENT_OFFSETS;
	     recent_offset_idx++)
		if (offset == state->lru.recent_offsets[recent_offset_idx])
			break;

	if (recent_offset_idx == LZMS_NUM_RECENT_OFFSETS) {
		/* Explicit offset.  */
		cost += lzms_rc_bit_cost(&ctx->lz_match_range_encoder,
					 &state->lz_match_state, 0);

		cost += lzms_offset_cost(&ctx->lz_offset_encoder, offset);
	} else {
		int i;

		/* Recent offset.  */
		cost += lzms_rc_bit_cost(&ctx->lz_match_range_encoder,
					 &state->lz_match_state, 1);

		for (i = 0; i < recent_offset_idx; i++)
			cost += lzms_rc_bit_cost(&ctx->lz_repeat_match_range_encoders[i],
						 &state->lz_repeat_match_state[i], 0);

		if (i < LZMS_NUM_RECENT_OFFSETS - 1)
			cost += lzms_rc_bit_cost(&ctx->lz_repeat_match_range_encoders[i],
						 &state->lz_repeat_match_state[i], 1);


		/* Initial update of the LZ match offset LRU queue.  */
		for (; i < LZMS_NUM_RECENT_OFFSETS; i++)
			state->lru.recent_offsets[i] = state->lru.recent_offsets[i + 1];
	}


	state->lru.upcoming_offset = offset;
	lzms_update_lz_lru_queues(&state->lru);

	return cost;
}

static u32
lzms_get_lz_match_cost(struct lzms_compressor *ctx,
		       struct lzms_adaptive_state *state,
		       u32 length, u32 offset)
{
	return lzms_get_lz_match_cost_nolen(ctx, state, offset) +
	       lzms_get_length_cost(&ctx->length_encoder, length);
}

static struct lz_match
lzms_match_chooser_reverse_list(struct lzms_compressor *ctx, unsigned cur_pos)
{
	unsigned prev_link, saved_prev_link;
	unsigned prev_match_offset, saved_prev_match_offset;

	ctx->optimum_end_idx = cur_pos;

	saved_prev_link = ctx->optimum[cur_pos].prev.link;
	saved_prev_match_offset = ctx->optimum[cur_pos].prev.match_offset;

	do {
		prev_link = saved_prev_link;
		prev_match_offset = saved_prev_match_offset;

		saved_prev_link = ctx->optimum[prev_link].prev.link;
		saved_prev_match_offset = ctx->optimum[prev_link].prev.match_offset;

		ctx->optimum[prev_link].next.link = cur_pos;
		ctx->optimum[prev_link].next.match_offset = prev_match_offset;

		cur_pos = prev_link;
	} while (cur_pos != 0);

	ctx->optimum_cur_idx = ctx->optimum[0].next.link;

	return (struct lz_match)
		{ .len = ctx->optimum_cur_idx,
		  .offset = ctx->optimum[0].next.match_offset,
		};
}

/* This is similar to lzx_get_near_optimal_match() in lzx-compress.c.
 * Read that one if you want to understand it.  */
static struct lz_match
lzms_get_near_optimal_match(struct lzms_compressor *ctx)
{
	u32 num_matches;
	struct lz_match *matches;
	struct lz_match match;
	u32 longest_len;
	u32 longest_rep_len;
	u32 longest_rep_offset;
	unsigned cur_pos;
	unsigned end_pos;
	struct lzms_adaptive_state initial_state;

	if (ctx->optimum_cur_idx != ctx->optimum_end_idx) {
		match.len = ctx->optimum[ctx->optimum_cur_idx].next.link -
				    ctx->optimum_cur_idx;
		match.offset = ctx->optimum[ctx->optimum_cur_idx].next.match_offset;

		ctx->optimum_cur_idx = ctx->optimum[ctx->optimum_cur_idx].next.link;
		return match;
	}

	ctx->optimum_cur_idx = 0;
	ctx->optimum_end_idx = 0;

	longest_rep_len = ctx->params.min_match_length - 1;
	if (lz_bt_get_position(&ctx->mf) >= LZMS_MAX_INIT_RECENT_OFFSET) {
		u32 limit = min(ctx->params.max_match_length,
				lz_bt_get_remaining_size(&ctx->mf));
		for (int i = 0; i < LZMS_NUM_RECENT_OFFSETS; i++) {
			u32 offset = ctx->lru.lz.recent_offsets[i];
			const u8 *strptr = lz_bt_get_window_ptr(&ctx->mf);
			const u8 *matchptr = strptr - offset;
			u32 len = 0;
			while (len < limit && strptr[len] == matchptr[len])
				len++;
			if (len > longest_rep_len) {
				longest_rep_len = len;
				longest_rep_offset = offset;
			}
		}
	}

	if (longest_rep_len >= ctx->params.nice_match_length) {
		lzms_skip_bytes(ctx, longest_rep_len);
		return (struct lz_match) {
			.len = longest_rep_len,
			.offset = longest_rep_offset,
		};
	}

	num_matches = lzms_get_matches(ctx, &matches);

	if (num_matches) {
		longest_len = matches[num_matches - 1].len;
		if (longest_len >= ctx->params.nice_match_length) {
			lzms_skip_bytes(ctx, longest_len - 1);
			return matches[num_matches - 1];
		}
	} else {
		longest_len = 1;
	}

	initial_state.lru = ctx->lru.lz;
	initial_state.main_state = ctx->main_range_encoder.state;
	initial_state.match_state = ctx->match_range_encoder.state;
	initial_state.lz_match_state = ctx->lz_match_range_encoder.state;
	for (int i = 0; i < LZMS_NUM_RECENT_OFFSETS - 1; i++)
		initial_state.lz_repeat_match_state[i] = ctx->lz_repeat_match_range_encoders[i].state;

	ctx->optimum[1].state = initial_state;
	ctx->optimum[1].cost = lzms_get_literal_cost(ctx,
						     &ctx->optimum[1].state,
						     *(lz_bt_get_window_ptr(&ctx->mf) - 1));
	ctx->optimum[1].prev.link = 0;

	for (u32 i = 0, len = 2; i < num_matches; i++) {
		u32 offset = matches[i].offset;
		struct lzms_adaptive_state state;
		u32 position_cost;

		state = initial_state;
		position_cost = 0;
		position_cost += lzms_get_lz_match_cost_nolen(ctx, &state, offset);

		do {
			u32 cost;

			cost = position_cost;
			cost += lzms_get_length_cost(&ctx->length_encoder, len);

			ctx->optimum[len].state = state;
			ctx->optimum[len].prev.link = 0;
			ctx->optimum[len].prev.match_offset = offset;
			ctx->optimum[len].cost = cost;
		} while (++len <= matches[i].len);
	}
	end_pos = longest_len;

	if (longest_rep_len >= ctx->params.min_match_length) {
		struct lzms_adaptive_state state;
		u32 cost;

		while (end_pos < longest_rep_len)
			ctx->optimum[++end_pos].cost = MC_INFINITE_COST;

		state = initial_state;
		cost = lzms_get_lz_match_cost(ctx,
					      &state,
					      longest_rep_len,
					      longest_rep_offset);
		if (cost <= ctx->optimum[longest_rep_len].cost) {
			ctx->optimum[longest_rep_len].state = state;
			ctx->optimum[longest_rep_len].prev.link = 0;
			ctx->optimum[longest_rep_len].prev.match_offset = longest_rep_offset;
			ctx->optimum[longest_rep_len].cost = cost;
		}
	}

	cur_pos = 0;
	for (;;) {
		u32 cost;
		struct lzms_adaptive_state state;

		cur_pos++;

		if (cur_pos == end_pos || cur_pos == ctx->params.optim_array_length)
			return lzms_match_chooser_reverse_list(ctx, cur_pos);

		longest_rep_len = ctx->params.min_match_length - 1;
		if (lz_bt_get_position(&ctx->mf) >= LZMS_MAX_INIT_RECENT_OFFSET) {
			u32 limit = min(ctx->params.max_match_length,
					lz_bt_get_remaining_size(&ctx->mf));
			for (int i = 0; i < LZMS_NUM_RECENT_OFFSETS; i++) {
				u32 offset = ctx->optimum[cur_pos].state.lru.recent_offsets[i];
				const u8 *strptr = lz_bt_get_window_ptr(&ctx->mf);
				const u8 *matchptr = strptr - offset;
				u32 len = 0;
				while (len < limit && strptr[len] == matchptr[len])
					len++;
				if (len > longest_rep_len) {
					longest_rep_len = len;
					longest_rep_offset = offset;
				}
			}
		}

		if (longest_rep_len >= ctx->params.nice_match_length) {
			match = lzms_match_chooser_reverse_list(ctx, cur_pos);

			ctx->optimum[cur_pos].next.match_offset = longest_rep_offset;
			ctx->optimum[cur_pos].next.link = cur_pos + longest_rep_len;
			ctx->optimum_end_idx = cur_pos + longest_rep_len;

			lzms_skip_bytes(ctx, longest_rep_len);

			return match;
		}

		num_matches = lzms_get_matches(ctx, &matches);

		if (num_matches) {
			longest_len = matches[num_matches - 1].len;
			if (longest_len >= ctx->params.nice_match_length) {
				match = lzms_match_chooser_reverse_list(ctx, cur_pos);

				ctx->optimum[cur_pos].next.match_offset =
					matches[num_matches - 1].offset;
				ctx->optimum[cur_pos].next.link = cur_pos + longest_len;
				ctx->optimum_end_idx = cur_pos + longest_len;

				lzms_skip_bytes(ctx, longest_len - 1);

				return match;
			}
		} else {
			longest_len = 1;
		}

		while (end_pos < cur_pos + longest_len)
			ctx->optimum[++end_pos].cost = MC_INFINITE_COST;

		state = ctx->optimum[cur_pos].state;
		cost = ctx->optimum[cur_pos].cost +
			lzms_get_literal_cost(ctx,
					      &state,
					      *(lz_bt_get_window_ptr(&ctx->mf) - 1));
		if (cost < ctx->optimum[cur_pos + 1].cost) {
			ctx->optimum[cur_pos + 1].state = state;
			ctx->optimum[cur_pos + 1].cost = cost;
			ctx->optimum[cur_pos + 1].prev.link = cur_pos;
		}

		for (u32 i = 0, len = 2; i < num_matches; i++) {
			u32 offset = matches[i].offset;
			struct lzms_adaptive_state state;
			u32 position_cost;

			state = ctx->optimum[cur_pos].state;
			position_cost = ctx->optimum[cur_pos].cost;
			position_cost += lzms_get_lz_match_cost_nolen(ctx, &state, offset);

			do {
				u32 cost;

				cost = position_cost;
				cost += lzms_get_length_cost(&ctx->length_encoder, len);

				if (cost < ctx->optimum[cur_pos + len].cost) {
					ctx->optimum[cur_pos + len].state = state;
					ctx->optimum[cur_pos + len].prev.link = cur_pos;
					ctx->optimum[cur_pos + len].prev.match_offset = offset;
					ctx->optimum[cur_pos + len].cost = cost;
				}
			} while (++len <= matches[i].len);
		}

		if (longest_rep_len >= ctx->params.min_match_length) {

			while (end_pos < cur_pos + longest_rep_len)
				ctx->optimum[++end_pos].cost = MC_INFINITE_COST;

			state = ctx->optimum[cur_pos].state;

			cost = ctx->optimum[cur_pos].cost +
				lzms_get_lz_match_cost(ctx,
						       &state,
						       longest_rep_len,
						       longest_rep_offset);
			if (cost <= ctx->optimum[cur_pos + longest_rep_len].cost) {
				ctx->optimum[cur_pos + longest_rep_len].state =
					state;
				ctx->optimum[cur_pos + longest_rep_len].prev.link =
					cur_pos;
				ctx->optimum[cur_pos + longest_rep_len].prev.match_offset =
					longest_rep_offset;
				ctx->optimum[cur_pos + longest_rep_len].cost =
					cost;
			}
		}
	}
}

/*
 * The main loop for the LZMS compressor.
 *
 * Notes:
 *
 * - This uses near-optimal LZ parsing backed by a binary tree match-finder.
 *
 * - This does not output any delta matches.
 *
 * - The costs of literals and matches are estimated using the range encoder
 *   states and the semi-adaptive Huffman codes.  Except for range encoding
 *   states, costs are assumed to be constant throughout a single run of the
 *   parsing algorithm, which can parse up to @optim_array_length (from the
 *   `struct wimlib_lzms_compressor_params') bytes of data.  This introduces a
 *   source of inaccuracy because the probabilities and Huffman codes can change
 *   over this part of the data.
 */
static void
lzms_encode(struct lzms_compressor *ctx)
{
	struct lz_match match;

	/* Load window into the binary tree match-finder.  */
	lz_bt_load_window(&ctx->mf, ctx->window, ctx->window_size);

	/* Reset the match-chooser.  */
	ctx->optimum_cur_idx = 0;
	ctx->optimum_end_idx = 0;

	while (ctx->cur_window_pos != ctx->window_size) {
		match = lzms_get_near_optimal_match(ctx);
		if (match.len <= 1)
			lzms_encode_literal(ctx, ctx->window[ctx->cur_window_pos]);
		else
			lzms_encode_lz_match(ctx, match.len, match.offset);
	}
}

static void
lzms_init_range_encoder(struct lzms_range_encoder *enc,
			struct lzms_range_encoder_raw *rc, u32 num_states)
{
	enc->rc = rc;
	enc->state = 0;
	enc->mask = num_states - 1;
	for (u32 i = 0; i < num_states; i++) {
		enc->prob_entries[i].num_recent_zero_bits = LZMS_INITIAL_PROBABILITY;
		enc->prob_entries[i].recent_bits = LZMS_INITIAL_RECENT_BITS;
	}
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

/* Initialize the LZMS compressor.  */
static void
lzms_init_compressor(struct lzms_compressor *ctx, const u8 *udata, u32 ulen,
		     le16 *cdata, u32 clen16)
{
	unsigned num_position_slots;

	/* Copy the uncompressed data into the @ctx->window buffer.  */
	memcpy(ctx->window, udata, ulen);
	ctx->cur_window_pos = 0;
	ctx->window_size = ulen;

	/* Initialize the raw range encoder (writing forwards).  */
	lzms_range_encoder_raw_init(&ctx->rc, cdata, clen16);

	/* Initialize the output bitstream for Huffman symbols and verbatim bits
	 * (writing backwards).  */
	lzms_output_bitstream_init(&ctx->os, cdata, clen16);

	/* Calculate the number of position slots needed for this compressed
	 * block.  */
	num_position_slots = lzms_get_position_slot(ulen - 1) + 1;

	LZMS_DEBUG("Using %u position slots", num_position_slots);

	/* Initialize Huffman encoders for each alphabet used in the compressed
	 * representation.  */
	lzms_init_huffman_encoder(&ctx->literal_encoder, &ctx->os,
				  LZMS_NUM_LITERAL_SYMS,
				  LZMS_LITERAL_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&ctx->lz_offset_encoder, &ctx->os,
				  num_position_slots,
				  LZMS_LZ_OFFSET_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&ctx->length_encoder, &ctx->os,
				  LZMS_NUM_LEN_SYMS,
				  LZMS_LENGTH_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&ctx->delta_offset_encoder, &ctx->os,
				  num_position_slots,
				  LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&ctx->delta_power_encoder, &ctx->os,
				  LZMS_NUM_DELTA_POWER_SYMS,
				  LZMS_DELTA_POWER_CODE_REBUILD_FREQ);

	/* Initialize range encoders, all of which wrap around the same
	 * lzms_range_encoder_raw.  */
	lzms_init_range_encoder(&ctx->main_range_encoder,
				&ctx->rc, LZMS_NUM_MAIN_STATES);

	lzms_init_range_encoder(&ctx->match_range_encoder,
				&ctx->rc, LZMS_NUM_MATCH_STATES);

	lzms_init_range_encoder(&ctx->lz_match_range_encoder,
				&ctx->rc, LZMS_NUM_LZ_MATCH_STATES);

	for (size_t i = 0; i < ARRAY_LEN(ctx->lz_repeat_match_range_encoders); i++)
		lzms_init_range_encoder(&ctx->lz_repeat_match_range_encoders[i],
					&ctx->rc, LZMS_NUM_LZ_REPEAT_MATCH_STATES);

	lzms_init_range_encoder(&ctx->delta_match_range_encoder,
				&ctx->rc, LZMS_NUM_DELTA_MATCH_STATES);

	for (size_t i = 0; i < ARRAY_LEN(ctx->delta_repeat_match_range_encoders); i++)
		lzms_init_range_encoder(&ctx->delta_repeat_match_range_encoders[i],
					&ctx->rc, LZMS_NUM_DELTA_REPEAT_MATCH_STATES);

	/* Initialize LRU match information.  */
	lzms_init_lru_queues(&ctx->lru);
}

/* Flush the output streams, prepare the final compressed data, and return its
 * size in bytes.
 *
 * A return value of 0 indicates that the data could not be compressed to fit in
 * the available space.  */
static size_t
lzms_finalize(struct lzms_compressor *ctx, u8 *cdata, size_t csize_avail)
{
	size_t num_forwards_bytes;
	size_t num_backwards_bytes;
	size_t compressed_size;

	/* Flush both the forwards and backwards streams, and make sure they
	 * didn't cross each other and start overwriting each other's data.  */
	if (!lzms_output_bitstream_flush(&ctx->os)) {
		LZMS_DEBUG("Backwards bitstream overrun.");
		return 0;
	}

	if (!lzms_range_encoder_raw_flush(&ctx->rc)) {
		LZMS_DEBUG("Forwards bitstream overrun.");
		return 0;
	}

	if (ctx->rc.out > ctx->os.out) {
		LZMS_DEBUG("Two bitstreams crossed.");
		return 0;
	}

	/* Now the compressed buffer contains the data output by the forwards
	 * bitstream, then empty space, then data output by the backwards
	 * bitstream.  Move the data output by the backwards bitstream to be
	 * adjacent to the data output by the forward bitstream, and calculate
	 * the compressed size that this results in.  */
	num_forwards_bytes = (u8*)ctx->rc.out - (u8*)cdata;
	num_backwards_bytes = ((u8*)cdata + csize_avail) - (u8*)ctx->os.out;

	memmove(cdata + num_forwards_bytes, ctx->os.out, num_backwards_bytes);

	compressed_size = num_forwards_bytes + num_backwards_bytes;
	LZMS_DEBUG("num_forwards_bytes=%zu, num_backwards_bytes=%zu, "
		   "compressed_size=%zu",
		   num_forwards_bytes, num_backwards_bytes, compressed_size);
	LZMS_ASSERT(compressed_size % 2 == 0);
	return compressed_size;
}

static size_t
lzms_compress(const void *uncompressed_data, size_t uncompressed_size,
	      void *compressed_data, size_t compressed_size_avail, void *_ctx)
{
	struct lzms_compressor *ctx = _ctx;
	size_t compressed_size;

	LZMS_DEBUG("uncompressed_size=%zu, compressed_size_avail=%zu",
		   uncompressed_size, compressed_size_avail);

	/* Make sure the uncompressed size is compatible with this compressor.
	 */
	if (uncompressed_size > ctx->max_block_size) {
		LZMS_DEBUG("Can't compress %zu bytes: LZMS context "
			   "only supports %u bytes",
			   uncompressed_size, ctx->max_block_size);
		return 0;
	}

	/* Don't bother compressing extremely small inputs.  */
	if (uncompressed_size < 4) {
		LZMS_DEBUG("Input too small to bother compressing.");
		return 0;
	}

	/* Cap the available compressed size to a 32-bit integer and round it
	 * down to the nearest multiple of 2.  */
	if (compressed_size_avail > UINT32_MAX)
		compressed_size_avail = UINT32_MAX;
	if (compressed_size_avail & 1)
		compressed_size_avail--;

	/* Initialize the compressor structures.  */
	lzms_init_compressor(ctx, uncompressed_data, uncompressed_size,
			     compressed_data, compressed_size_avail / 2);

	/* Preprocess the uncompressed data.  */
	lzms_x86_filter(ctx->window, ctx->window_size,
			ctx->last_target_usages, false);

	/* Compute and encode a literal/match sequence that decompresses to the
	 * preprocessed data.  */
	lzms_encode(ctx);

	/* Get and return the compressed data size.  */
	compressed_size = lzms_finalize(ctx, compressed_data,
					compressed_size_avail);

	if (compressed_size == 0) {
		LZMS_DEBUG("Data did not compress to requested size or less.");
		return 0;
	}

	LZMS_DEBUG("Compressed %zu => %zu bytes",
		   uncompressed_size, compressed_size);

#if defined(ENABLE_VERIFY_COMPRESSION) || defined(ENABLE_LZMS_DEBUG)
	/* Verify that we really get the same thing back when decompressing.  */
	{
		struct wimlib_decompressor *decompressor;

		LZMS_DEBUG("Verifying LZMS compression.");

		if (0 == wimlib_create_decompressor(WIMLIB_COMPRESSION_TYPE_LZMS,
						    ctx->max_block_size,
						    NULL,
						    &decompressor))
		{
			int ret;
			ret = wimlib_decompress(compressed_data,
						compressed_size,
						ctx->window,
						uncompressed_size,
						decompressor);
			wimlib_free_decompressor(decompressor);

			if (ret) {
				ERROR("Failed to decompress data we "
				      "compressed using LZMS algorithm");
				wimlib_assert(0);
				return 0;
			}
			if (memcmp(uncompressed_data, ctx->window,
				   uncompressed_size))
			{
				ERROR("Data we compressed using LZMS algorithm "
				      "didn't decompress to original");
				wimlib_assert(0);
				return 0;
			}
		} else {
			WARNING("Failed to create decompressor for "
				"data verification!");
		}
	}
#endif /* ENABLE_LZMS_DEBUG || ENABLE_VERIFY_COMPRESSION  */

	return compressed_size;
}

static void
lzms_free_compressor(void *_ctx)
{
	struct lzms_compressor *ctx = _ctx;

	if (ctx) {
		FREE(ctx->window);
		FREE(ctx->matches);
		lz_bt_destroy(&ctx->mf);
		FREE(ctx->optimum);
		FREE(ctx);
	}
}

static const struct wimlib_lzms_compressor_params lzms_default = {
	.hdr = {
		.size = sizeof(struct wimlib_lzms_compressor_params),
	},
	.min_match_length = 2,
	.max_match_length = UINT32_MAX,
	.nice_match_length = 32,
	.max_search_depth = 50,
	.optim_array_length = 1024,
};

static bool
lzms_params_valid(const struct wimlib_compressor_params_header *);

static const struct wimlib_lzms_compressor_params *
lzms_get_params(const struct wimlib_compressor_params_header *_params)
{
	const struct wimlib_lzms_compressor_params *params =
		(const struct wimlib_lzms_compressor_params*)_params;

	if (params == NULL)
		params = &lzms_default;

	LZMS_ASSERT(lzms_params_valid(&params->hdr));

	return params;
}

static int
lzms_create_compressor(size_t max_block_size,
		       const struct wimlib_compressor_params_header *_params,
		       void **ctx_ret)
{
	struct lzms_compressor *ctx;
	const struct wimlib_lzms_compressor_params *params = lzms_get_params(_params);

	if (max_block_size == 0 || max_block_size >= INT32_MAX) {
		LZMS_DEBUG("Invalid max_block_size (%u)", max_block_size);
		return WIMLIB_ERR_INVALID_PARAM;
	}

	ctx = CALLOC(1, sizeof(struct lzms_compressor));
	if (ctx == NULL)
		goto oom;

	ctx->window = MALLOC(max_block_size);
	if (ctx->window == NULL)
		goto oom;

	ctx->matches = MALLOC(min(params->max_match_length -
					params->min_match_length + 1,
				  params->max_search_depth + 2) *
				sizeof(ctx->matches[0]));
	if (ctx->matches == NULL)
		goto oom;

	if (!lz_bt_init(&ctx->mf,
			max_block_size,
			params->min_match_length,
			params->max_match_length,
			params->nice_match_length,
			params->max_search_depth))
		goto oom;

	ctx->optimum = MALLOC((params->optim_array_length +
			       min(params->nice_match_length,
				   params->max_match_length)) *
					sizeof(ctx->optimum[0]));
	if (!ctx->optimum)
		goto oom;

	/* Initialize position and length slot data if not done already.  */
	lzms_init_slots();

	/* Initialize range encoding cost table if not done already.  */
	lzms_init_rc_costs();

	ctx->max_block_size = max_block_size;
	memcpy(&ctx->params, params, sizeof(*params));

	*ctx_ret = ctx;
	return 0;

oom:
	lzms_free_compressor(ctx);
	return WIMLIB_ERR_NOMEM;
}

static u64
lzms_get_needed_memory(size_t max_block_size,
		       const struct wimlib_compressor_params_header *_params)
{
	const struct wimlib_lzms_compressor_params *params = lzms_get_params(_params);

	u64 size = 0;

	size += max_block_size;
	size += sizeof(struct lzms_compressor);
	size += lz_bt_get_needed_memory(max_block_size);
	size += (params->optim_array_length +
		 min(params->nice_match_length,
		     params->max_match_length)) *
			 sizeof(((struct lzms_compressor *)0)->optimum[0]);
	size += min(params->max_match_length - params->min_match_length + 1,
		    params->max_search_depth + 2) *
		sizeof(((struct lzms_compressor*)0)->matches[0]);
	return size;
}

static bool
lzms_params_valid(const struct wimlib_compressor_params_header *_params)
{
	const struct wimlib_lzms_compressor_params *params =
		(const struct wimlib_lzms_compressor_params*)_params;

	if (params->hdr.size != sizeof(*params) ||
	    params->max_match_length < params->min_match_length ||
	    params->min_match_length < 2 ||
	    params->optim_array_length == 0 ||
	    min(params->max_match_length, params->nice_match_length) > 65536)
		return false;

	return true;
}

const struct compressor_ops lzms_compressor_ops = {
	.params_valid	    = lzms_params_valid,
	.get_needed_memory  = lzms_get_needed_memory,
	.create_compressor  = lzms_create_compressor,
	.compress	    = lzms_compress,
	.free_compressor    = lzms_free_compressor,
};
