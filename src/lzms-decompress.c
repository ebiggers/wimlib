/*
 * lzms-decompress.c
 */

/*
 * Copyright (C) 2013 Eric Biggers
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

/*
 * This is a decompressor for the LZMS compression format used by Microsoft.
 * This format is not documented, but it is one of the formats supported by the
 * compression API available in Windows 8, and as of Windows 8 it is one of the
 * formats that can be used in WIM files.
 *
 * This decompressor only implements "raw" decompression, which decompresses a
 * single LZMS-compressed block.  This behavior is the same as that of
 * Decompress() in the Windows 8 compression API when using a compression handle
 * created with CreateDecompressor() with the Algorithm parameter specified as
 * COMPRESS_ALGORITHM_LZMS | COMPRESS_RAW.  Presumably, non-raw LZMS data
 * is a container format from which the locations and sizes (both compressed and
 * uncompressed) of the constituent blocks can be determined.
 *
 * An LZMS-compressed block must be read in 16-bit little endian units from both
 * directions.  One logical bitstream starts at the front of the block and
 * proceeds forwards.  Another logical bitstream starts at the end of the block
 * and proceeds backwards.  Bits read from the forwards bitstream constitute
 * range-encoded data, whereas bits read from the backwards bitstream constitute
 * Huffman-encoded symbols or verbatim bits.  For both bitstreams, the ordering
 * of the bits within the 16-bit coding units is such that the first bit is the
 * high-order bit and the last bit is the low-order bit.
 *
 * From these two logical bitstreams, an LZMS decompressor can reconstitute the
 * series of items that make up the LZMS data representation.  Each such item
 * may be a literal byte or a match.  Matches may be either traditional LZ77
 * matches or "delta" matches, either of which can have its offset encoded
 * explicitly or encoded via a reference to a recently used (repeat) offset.
 *
 * A traditional LZ match consists of a length and offset; it asserts that the
 * sequence of bytes beginning at the current position and extending for the
 * length is exactly equal to the equal-length sequence of bytes at the offset
 * back in the window.  On the other hand, a delta match consists of a length,
 * raw offset, and power.  It asserts that the sequence of bytes beginning at
 * the current position and extending for the length is equal to the bytewise
 * sum of the two equal-length sequences of bytes (2**power) and (raw_offset *
 * 2**power) bytes before the current position, minus bytewise the sequence of
 * bytes beginning at (2**power + raw_offset * 2**power) bytes before the
 * current position.  Although not generally as useful as traditional LZ
 * matches, delta matches can be helpful on some types of data.  Both LZ and
 * delta matches may overlap with the current position; in fact, the minimum
 * offset is 1, regardless of match length.
 *
 * For LZ matches, up to 3 repeat offsets are allowed, similar to some other
 * LZ-based formats such as LZX and LZMA.  They must updated in an LRU fashion,
 * except for a quirk: updates to the queue must be delayed by one LZMS item,
 * except for the removal of a repeat match.  As a result, 4 entries are
 * actually needed in the queue, even though it is only possible to decode
 * references to the first 3 at any given time.  The queue must be initialized
 * to the offsets {1, 2, 3, 4}.
 *
 * Repeat delta matches are handled similarly, but for them there are two queues
 * updated in lock-step: one for powers and one for raw offsets.  The power
 * queue must be initialized to {0, 0, 0, 0}, and the raw offset queue must be
 * initialized to {1, 2, 3, 4}.
 *
 * Bits from the range decoder must be used to disambiguate item types.  The
 * range decoder must hold two state variables: the range, which must initially
 * be set to 0xffffffff, and the current code, which must initially be set to
 * the first 32 bits read from the forwards bitstream.  The range must be
 * maintained above 0xffff; when it falls below 0xffff, both the range and code
 * must be left-shifted by 16 bits and the low 16 bits of the code must be
 * filled in with the next 16 bits from the forwards bitstream.
 *
 * To decode each bit, the range decoder requires a probability that is
 * logically a real number between 0 and 1.  Multiplying this probability by the
 * current range and taking the floor gives the bound between the 0-bit region
 * of the range and the 1-bit region of the range.  However, in LZMS,
 * probabilities are restricted to values of n/64 where n is an integer is
 * between 1 and 63 inclusively, so the implementation may use integer
 * operations instead.  Following calculation of the bound, if the current code
 * is in the 0-bit region, the new range becomes the current code and the
 * decoded bit is 0; otherwise, the bound must be subtracted from both the range
 * and the code, and the decoded bit is 1.  More information about range coding
 * can be found at https://en.wikipedia.org/wiki/Range_encoding.  Furthermore,
 * note that the LZMA format also uses range coding and has public domain code
 * available for it.
 *
 * The probability used to range-decode each bit must be taken from a table, of
 * which one instance must exist for each distinct context in which a
 * range-decoded bit is needed.  At each call of the range decoder, the
 * appropriate probability must be obtained by indexing the appropriate
 * probability table with the last 4 (in the context disambiguating literals
 * from matches), 5 (in the context disambiguating LZ matches from delta
 * matches), or 6 (in all other contexts) bits recently range-decoded in that
 * context, ordered such that the most recently decoded bit is the low-order bit
 * of the index.
 *
 * Furthermore, each probability entry itself is variable, as its value must be
 * maintained as n/64 where n is the number of 0 bits in the most recently
 * decoded 64 bits with that same entry.  This allows the compressed
 * representation to adapt to the input and use fewer bits to represent the most
 * likely data; note that LZMA uses a similar scheme.  Initially, the most
 * recently 64 decoded bits for each probability entry are assumed to be
 * 0x0000000055555555 (high order to low order); therefore, all probabilities
 * are initially 48/64.  During the course of decoding, each probability may be
 * updated to as low as 0/64 (as a result of reading many consecutive 1 bits
 * with that entry) or as high as 64/64 (as a result of reading many consecutive
 * 0 bits with that entry); however, probabilities of 0/64 and 64/64 cannot be
 * used as-is but rather must be adjusted to 1/64 and 63/64, respectively,
 * before being used for range decoding.
 *
 * Representations of the LZMS items themselves must be read from the backwards
 * bitstream.  For this, there are 5 different Huffman codes used:
 *
 *  - The literal code, used for decoding literal bytes.  Each of the 256
 *    symbols represents a literal byte.  This code must be rebuilt whenever
 *    1024 symbols have been decoded with it.
 *
 *  - The LZ offset code, used for decoding the offsets of standard LZ77
 *    matches.  Each symbol represents a position slot, which corresponds to a
 *    base value and some number of extra bits which must be read and added to
 *    the base value to reconstitute the full offset.  The number of symbols in
 *    this code is the number of position slots needed to represent all possible
 *    offsets in the uncompressed block.  This code must be rebuilt whenever
 *    1024 symbols have been decoded with it.
 *
 *  - The length code, used for decoding length symbols.  Each of the 54 symbols
 *    represents a length slot, which corresponds to a base value and some
 *    number of extra bits which must be read and added to the base value to
 *    reconstitute the full length.  This code must be rebuilt whenever 512
 *    symbols have been decoded with it.
 *
 *  - The delta offset code, used for decoding the offsets of delta matches.
 *    Each symbol corresponds to a position slot, which corresponds to a base
 *    value and some number of extra bits which must be read and added to the
 *    base value to reconstitute the full offset.  The number of symbols in this
 *    code is equal to the number of symbols in the LZ offset code.  This code
 *    must be rebuilt whenever 1024 symbols have been decoded with it.
 *
 *  - The delta power code, used for decoding the powers of delta matches.  Each
 *    of the 8 symbols corresponds to a power.  This code must be rebuilt
 *    whenever 512 symbols have been decoded with it.
 *
 * All the LZMS Huffman codes must be built adaptively based on symbol
 * frequencies.  Initially, each code must be built assuming that all symbols
 * have equal frequency.  Following that, each code must be rebuilt whenever a
 * certain number of symbols has been decoded with it.
 *
 * In general, multiple valid Huffman codes can be constructed from a set of
 * symbol frequencies.  Like other compression formats such as XPRESS, LZX, and
 * DEFLATE, the LZMS format solves this ambiguity by requiring that all Huffman
 * codes be constructed in canonical form.  This form requires that same-length
 * codewords be lexicographically ordered the same way as the corresponding
 * symbols and that all shorter codewords lexicographically precede longer
 * codewords.
 *
 * Codewords in all the LZMS Huffman codes are limited to 15 bits.  If the
 * canonical code for a given set of symbol frequencies has any codewords longer
 * than 15 bits, then all frequencies must be divided by 2, rounding up, and the
 * code construction must be attempted again.
 *
 * An LZMS-compressed block seemingly cannot have a compressed size greater than
 * or equal to the uncompressed size.  In such cases the block must be stored
 * uncompressed.
 *
 * After all LZMS items have been decoded, the data must be postprocessed to
 * translate absolute address encoded in x86 instructions into their original
 * relative addresses.
 *
 * Details omitted above can be found in the code.  Note that in the absence of
 * an official specification there is no guarantee that this decompressor
 * handles all possible cases.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/compress_common.h"
#include "wimlib/decompressor_ops.h"
#include "wimlib/decompress_common.h"
#include "wimlib/lzms.h"
#include "wimlib/util.h"

#include <limits.h>

#define LZMS_DECODE_TABLE_BITS	10

/* Structure used for range decoding, reading bits forwards.  This is the first
 * logical bitstream mentioned above.  */
struct lzms_range_decoder_raw {
	/* The relevant part of the current range.  Although the logical range
	 * for range decoding is a very large integer, only a small portion
	 * matters at any given time, and it can be normalized (shifted left)
	 * whenever it gets too small.  */
	u32 range;

	/* The current position in the range encoded by the portion of the input
	 * read so far.  */
	u32 code;

	/* Pointer to the next little-endian 16-bit integer in the compressed
	 * input data (reading forwards).  */
	const le16 *in;

	/* Number of 16-bit integers remaining in the compressed input data
	 * (reading forwards).  */
	size_t num_le16_remaining;
};

/* Structure used for reading raw bits backwards.  This is the second logical
 * bitstream mentioned above.  */
struct lzms_input_bitstream {
	/* Holding variable for bits that have been read from the compressed
	 * data.  The bits are ordered from high-order to low-order.  */
	/* XXX:  Without special-case code to handle reading more than 17 bits
	 * at a time, this needs to be 64 bits rather than 32 bits.  */
	u64 bitbuf;

	/* Number of bits in @bitbuf that are used.  */
	unsigned num_filled_bits;

	/* Pointer to the one past the next little-endian 16-bit integer in the
	 * compressed input data (reading backwards).  */
	const le16 *in;

	/* Number of 16-bit integers remaining in the compressed input data
	 * (reading backwards).  */
	size_t num_le16_remaining;
};

/* Structure used for range decoding.  This wraps around `struct
 * lzms_range_decoder_raw' to use and maintain probability entries.  */
struct lzms_range_decoder {
	/* Pointer to the raw range decoder, which has no persistent knowledge
	 * of probabilities.  Multiple lzms_range_decoder's share the same
	 * lzms_range_decoder_raw.  */
	struct lzms_range_decoder_raw *rd;

	/* Bits recently decoded by this range decoder.  This are used as in
	 * index into @prob_entries.  */
	u32 state;

	/* Bitmask for @state to prevent its value from exceeding the number of
	 * probability entries.  */
	u32 mask;

	/* Probability entries being used for this range decoder.  */
	struct lzms_probability_entry prob_entries[LZMS_MAX_NUM_STATES];
};

/* Structure used for Huffman decoding, optionally using the decoded symbols as
 * slots into a base table to determine how many extra bits need to be read to
 * reconstitute the full value.  */
struct lzms_huffman_decoder {

	/* Bitstream to read Huffman-encoded symbols and verbatim bits from.
	 * Multiple lzms_huffman_decoder's share the same lzms_input_bitstream.
	 */
	struct lzms_input_bitstream *is;

	/* Pointer to the slot base table to use.  It is indexed by the decoded
	 * Huffman symbol that specifies the slot.  The entry specifies the base
	 * value to use, and the position of its high bit is the number of
	 * additional bits that must be read to reconstitute the full value.
	 *
	 * This member need not be set if only raw Huffman symbols are being
	 * read using this decoder.  */
	const u32 *slot_base_tab;

	const u8 *extra_bits_tab;

	/* Number of symbols that have been read using this code far.  Reset to
	 * 0 whenever the code is rebuilt.  */
	u32 num_syms_read;

	/* When @num_syms_read reaches this number, the Huffman code must be
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

	/* A table for quickly decoding symbols encoded using the Huffman code.
	 */
	u16 decode_table[(1U << LZMS_DECODE_TABLE_BITS) + 2 * LZMS_MAX_NUM_SYMS]
				_aligned_attribute(DECODE_TABLE_ALIGNMENT);
};

/* State of the LZMS decompressor.  */
struct lzms_decompressor {

	/* Pointer to the beginning of the uncompressed data buffer.  */
	u8 *out_begin;

	/* Pointer to the next position in the uncompressed data buffer.  */
	u8 *out_next;

	/* Pointer to one past the end of the uncompressed data buffer.  */
	u8 *out_end;

	/* Range decoder, which reads bits from the beginning of the compressed
	 * block, going forwards.  */
	struct lzms_range_decoder_raw rd;

	/* Input bitstream, which reads from the end of the compressed block,
	 * going backwards.  */
	struct lzms_input_bitstream is;

	/* Range decoders.  */
	struct lzms_range_decoder main_range_decoder;
	struct lzms_range_decoder match_range_decoder;
	struct lzms_range_decoder lz_match_range_decoder;
	struct lzms_range_decoder lz_repeat_match_range_decoders[LZMS_NUM_RECENT_OFFSETS - 1];
	struct lzms_range_decoder delta_match_range_decoder;
	struct lzms_range_decoder delta_repeat_match_range_decoders[LZMS_NUM_RECENT_OFFSETS - 1];

	/* Huffman decoders.  */
	struct lzms_huffman_decoder literal_decoder;
	struct lzms_huffman_decoder lz_offset_decoder;
	struct lzms_huffman_decoder length_decoder;
	struct lzms_huffman_decoder delta_power_decoder;
	struct lzms_huffman_decoder delta_offset_decoder;

	/* LRU (least-recently-used) queues for match information.  */
	struct lzms_lru_queues lru;

	/* Used for postprocessing.  */
	s32 last_target_usages[65536];
};

/* Initialize the input bitstream @is to read forwards from the specified
 * compressed data buffer @in that is @in_limit 16-bit integers long.  */
static void
lzms_input_bitstream_init(struct lzms_input_bitstream *is,
			  const le16 *in, size_t in_limit)
{
	is->bitbuf = 0;
	is->num_filled_bits = 0;
	is->in = in + in_limit;
	is->num_le16_remaining = in_limit;
}

/* Ensures that @num_bits bits are buffered in the input bitstream.  */
static int
lzms_input_bitstream_ensure_bits(struct lzms_input_bitstream *is,
				 unsigned num_bits)
{
	while (is->num_filled_bits < num_bits) {
		u64 next;

		LZMS_ASSERT(is->num_filled_bits + 16 <= sizeof(is->bitbuf) * 8);

		if (unlikely(is->num_le16_remaining == 0))
			return -1;

		next = le16_to_cpu(*--is->in);
		is->num_le16_remaining--;

		is->bitbuf |= next << (sizeof(is->bitbuf) * 8 - is->num_filled_bits - 16);
		is->num_filled_bits += 16;
	}
	return 0;

}

/* Returns the next @num_bits bits that are buffered in the input bitstream.  */
static u32
lzms_input_bitstream_peek_bits(struct lzms_input_bitstream *is,
			       unsigned num_bits)
{
	LZMS_ASSERT(is->num_filled_bits >= num_bits);
	return is->bitbuf >> (sizeof(is->bitbuf) * 8 - num_bits);
}

/* Removes the next @num_bits bits that are buffered in the input bitstream.  */
static void
lzms_input_bitstream_remove_bits(struct lzms_input_bitstream *is,
				 unsigned num_bits)
{
	LZMS_ASSERT(is->num_filled_bits >= num_bits);
	is->bitbuf <<= num_bits;
	is->num_filled_bits -= num_bits;
}

/* Removes and returns the next @num_bits bits that are buffered in the input
 * bitstream.  */
static u32
lzms_input_bitstream_pop_bits(struct lzms_input_bitstream *is,
			      unsigned num_bits)
{
	u32 bits = lzms_input_bitstream_peek_bits(is, num_bits);
	lzms_input_bitstream_remove_bits(is, num_bits);
	return bits;
}

/* Reads the next @num_bits from the input bitstream.  */
static u32
lzms_input_bitstream_read_bits(struct lzms_input_bitstream *is,
			       unsigned num_bits)
{
	if (unlikely(lzms_input_bitstream_ensure_bits(is, num_bits)))
		return 0;
	return lzms_input_bitstream_pop_bits(is, num_bits);
}

/* Initialize the range decoder @rd to read forwards from the specified
 * compressed data buffer @in that is @in_limit 16-bit integers long.  */
static void
lzms_range_decoder_raw_init(struct lzms_range_decoder_raw *rd,
			    const le16 *in, size_t in_limit)
{
	rd->range = 0xffffffff;
	rd->code = ((u32)le16_to_cpu(in[0]) << 16) |
		   ((u32)le16_to_cpu(in[1]) <<  0);
	rd->in = in + 2;
	rd->num_le16_remaining = in_limit - 2;
}

/* Ensures the current range of the range decoder has at least 16 bits of
 * precision.  */
static int
lzms_range_decoder_raw_normalize(struct lzms_range_decoder_raw *rd)
{
	if (rd->range <= 0xffff) {
		rd->range <<= 16;
		if (unlikely(rd->num_le16_remaining == 0))
			return -1;
		rd->code = (rd->code << 16) | le16_to_cpu(*rd->in++);
		rd->num_le16_remaining--;
	}
	return 0;
}

/* Decode and return the next bit from the range decoder (raw version).
 *
 * @prob is the chance out of LZMS_PROBABILITY_MAX that the next bit is 0.
 */
static int
lzms_range_decoder_raw_decode_bit(struct lzms_range_decoder_raw *rd, u32 prob)
{
	u32 bound;

	/* Ensure the range has at least 16 bits of precision.  */
	lzms_range_decoder_raw_normalize(rd);

	/* Based on the probability, calculate the bound between the 0-bit
	 * region and the 1-bit region of the range.  */
	bound = (rd->range >> LZMS_PROBABILITY_BITS) * prob;

	if (rd->code < bound) {
		/* Current code is in the 0-bit region of the range.  */
		rd->range = bound;
		return 0;
	} else {
		/* Current code is in the 1-bit region of the range.  */
		rd->range -= bound;
		rd->code -= bound;
		return 1;
	}
}

/* Decode and return the next bit from the range decoder.  This wraps around
 * lzms_range_decoder_raw_decode_bit() to handle using and updating the
 * appropriate probability table.  */
static int
lzms_range_decode_bit(struct lzms_range_decoder *dec)
{
	struct lzms_probability_entry *prob_entry;
	u32 prob;
	int bit;

	/* Load the probability entry corresponding to the current state.  */
	prob_entry = &dec->prob_entries[dec->state];

	/* Treat the number of zero bits in the most recently decoded
	 * LZMS_PROBABILITY_MAX bits with this probability entry as the chance,
	 * out of LZMS_PROBABILITY_MAX, that the next bit will be a 0.  However,
	 * don't allow 0% or 100% probabilities.  */
	prob = prob_entry->num_recent_zero_bits;
	if (prob == LZMS_PROBABILITY_MAX)
		prob = LZMS_PROBABILITY_MAX - 1;
	else if (prob == 0)
		prob = 1;

	/* Decode the next bit.  */
	bit = lzms_range_decoder_raw_decode_bit(dec->rd, prob);

	/* Update the state based on the newly decoded bit.  */
	dec->state = (((dec->state << 1) | bit) & dec->mask);

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

	/* Return the decoded bit.  */
	return bit;
}


/* Build the decoding table for a new adaptive Huffman code using the alphabet
 * used in the specified Huffman decoder, with the symbol frequencies
 * dec->sym_freqs.  */
static void
lzms_rebuild_adaptive_huffman_code(struct lzms_huffman_decoder *dec)
{

	/* XXX:  This implementation makes use of code already implemented for
	 * the XPRESS and LZX compression formats.  However, since for the
	 * adaptive codes used in LZMS we don't actually need the explicit codes
	 * themselves, only the decode tables, it may be possible to optimize
	 * this by somehow directly building or updating the Huffman decode
	 * table.  This may be a worthwhile optimization because the adaptive
	 * codes change many times throughout a decompression run.  */
	LZMS_DEBUG("Rebuilding adaptive Huffman code (num_syms=%u)",
		   dec->num_syms);
	make_canonical_huffman_code(dec->num_syms, LZMS_MAX_CODEWORD_LEN,
				    dec->sym_freqs, dec->lens, dec->codewords);
#if defined(ENABLE_LZMS_DEBUG)
	int ret =
#endif
	make_huffman_decode_table(dec->decode_table, dec->num_syms,
				  LZMS_DECODE_TABLE_BITS, dec->lens,
				  LZMS_MAX_CODEWORD_LEN);
	LZMS_ASSERT(ret == 0);
}

/* Decode and return the next Huffman-encoded symbol from the LZMS-compressed
 * block using the specified Huffman decoder.  */
static u32
lzms_huffman_decode_symbol(struct lzms_huffman_decoder *dec)
{
	const u16 *decode_table = dec->decode_table;
	struct lzms_input_bitstream *is = dec->is;
	u16 entry;
	u16 key_bits;
	u16 sym;

	/* The Huffman codes used in LZMS are adaptive and must be rebuilt
	 * whenever a certain number of symbols have been read.  Each such
	 * rebuild uses the current symbol frequencies, but the format also
	 * requires that the symbol frequencies be halved after each code
	 * rebuild.  This diminishes the effect of old symbols on the current
	 * Huffman codes, thereby causing the Huffman codes to be more locally
	 * adaptable.  */
	if (dec->num_syms_read == dec->rebuild_freq) {
		lzms_rebuild_adaptive_huffman_code(dec);
		for (unsigned i = 0; i < dec->num_syms; i++) {
			dec->sym_freqs[i] >>= 1;
			dec->sym_freqs[i] += 1;
		}
		dec->num_syms_read = 0;
	}

	/* XXX: Copied from read_huffsym() (decompress_common.h), since this
	 * uses a different input bitstream type.  Should unify the
	 * implementations.  */
	lzms_input_bitstream_ensure_bits(is, LZMS_MAX_CODEWORD_LEN);

	/* Index the decode table by the next table_bits bits of the input.  */
	key_bits = lzms_input_bitstream_peek_bits(is, LZMS_DECODE_TABLE_BITS);
	entry = decode_table[key_bits];
	if (likely(entry < 0xC000)) {
		/* Fast case: The decode table directly provided the symbol and
		 * codeword length.  The low 11 bits are the symbol, and the
		 * high 5 bits are the codeword length.  */
		lzms_input_bitstream_remove_bits(is, entry >> 11);
		sym = entry & 0x7FF;
	} else {
		/* Slow case: The codeword for the symbol is longer than
		 * table_bits, so the symbol does not have an entry directly in
		 * the first (1 << table_bits) entries of the decode table.
		 * Traverse the appropriate binary tree bit-by-bit in order to
		 * decode the symbol.  */
		lzms_input_bitstream_remove_bits(is, LZMS_DECODE_TABLE_BITS);
		do {
			key_bits = (entry & 0x3FFF) + lzms_input_bitstream_pop_bits(is, 1);
		} while ((entry = decode_table[key_bits]) >= 0xC000);
		sym = entry;
	}

	/* Tally and return the decoded symbol.  */
	++dec->sym_freqs[sym];
	++dec->num_syms_read;
	return sym;
}

/* Decode a number from the LZMS bitstream, encoded as a Huffman-encoded symbol
 * specifying a "slot" (whose corresponding value is looked up in a static
 * table) plus the number specified by a number of extra bits depending on the
 * slot.  */
static u32
lzms_decode_value(struct lzms_huffman_decoder *dec)
{
	unsigned slot;
	unsigned num_extra_bits;
	u32 extra_bits;

	LZMS_ASSERT(dec->slot_base_tab != NULL);
	LZMS_ASSERT(dec->extra_bits_tab != NULL);

	/* Read the slot (position slot, length slot, etc.), which is encoded as
	 * a Huffman symbol.  */
	slot = lzms_huffman_decode_symbol(dec);

	/* Get the number of extra bits needed to represent the range of values
	 * that share the slot.  */
	num_extra_bits = dec->extra_bits_tab[slot];

	/* Read the number of extra bits and add them to the slot base to form
	 * the final decoded value.  */
	extra_bits = lzms_input_bitstream_read_bits(dec->is, num_extra_bits);
	return dec->slot_base_tab[slot] + extra_bits;
}

/* Copy a literal to the output buffer.  */
static int
lzms_copy_literal(struct lzms_decompressor *ctx, u8 literal)
{
	*ctx->out_next++ = literal;
	return 0;
}

/* Validate an LZ match and copy it to the output buffer.  */
static int
lzms_copy_lz_match(struct lzms_decompressor *ctx, u32 length, u32 offset)
{
	u8 *out_next;

	if (length > ctx->out_end - ctx->out_next) {
		LZMS_DEBUG("Match overrun!");
		return -1;
	}
	if (offset > ctx->out_next - ctx->out_begin) {
		LZMS_DEBUG("Match underrun!");
		return -1;
	}

	out_next = ctx->out_next;

	lz_copy(out_next, length, offset, ctx->out_end);
	ctx->out_next = out_next + length;

	return 0;
}

/* Validate a delta match and copy it to the output buffer.  */
static int
lzms_copy_delta_match(struct lzms_decompressor *ctx, u32 length,
		      u32 power, u32 raw_offset)
{
	u32 offset1 = 1U << power;
	u32 offset2 = raw_offset << power;
	u32 offset = offset1 + offset2;
	u8 *out_next;
	u8 *matchptr1;
	u8 *matchptr2;
	u8 *matchptr;

	if (length > ctx->out_end - ctx->out_next) {
		LZMS_DEBUG("Match overrun!");
		return -1;
	}
	if (offset > ctx->out_next - ctx->out_begin) {
		LZMS_DEBUG("Match underrun!");
		return -1;
	}

	out_next = ctx->out_next;
	matchptr1 = out_next - offset1;
	matchptr2 = out_next - offset2;
	matchptr = out_next - offset;

	while (length--)
		*out_next++ = *matchptr1++ + *matchptr2++ - *matchptr++;

	ctx->out_next = out_next;
	return 0;
}

/* Decode a (length, offset) pair from the input.  */
static int
lzms_decode_lz_match(struct lzms_decompressor *ctx)
{
	int bit;
	u32 length, offset;

	/* Decode the match offset.  The next range-encoded bit indicates
	 * whether it's a repeat offset or an explicit offset.  */

	bit = lzms_range_decode_bit(&ctx->lz_match_range_decoder);
	if (bit == 0) {
		/* Explicit offset.  */
		offset = lzms_decode_value(&ctx->lz_offset_decoder);
	} else {
		/* Repeat offset.  */
		int i;

		for (i = 0; i < LZMS_NUM_RECENT_OFFSETS - 1; i++)
			if (!lzms_range_decode_bit(&ctx->lz_repeat_match_range_decoders[i]))
				break;

		offset = ctx->lru.lz.recent_offsets[i];

		for (; i < LZMS_NUM_RECENT_OFFSETS; i++)
			ctx->lru.lz.recent_offsets[i] = ctx->lru.lz.recent_offsets[i + 1];
	}

	/* Decode match length, which is always given explicitly (there is no
	 * LRU queue for repeat lengths).  */
	length = lzms_decode_value(&ctx->length_decoder);

	ctx->lru.lz.upcoming_offset = offset;

	LZMS_DEBUG("Decoded %s LZ match: length=%u, offset=%u",
		   (bit ? "repeat" : "explicit"), length, offset);

	/* Validate the match and copy it to the output.  */
	return lzms_copy_lz_match(ctx, length, offset);
}

/* Decodes a "delta" match from the input.  */
static int
lzms_decode_delta_match(struct lzms_decompressor *ctx)
{
	int bit;
	u32 length, power, raw_offset;

	/* Decode the match power and raw offset.  The next range-encoded bit
	 * indicates whether these data are a repeat, or given explicitly.  */

	bit = lzms_range_decode_bit(&ctx->delta_match_range_decoder);
	if (bit == 0) {
		power = lzms_huffman_decode_symbol(&ctx->delta_power_decoder);
		raw_offset = lzms_decode_value(&ctx->delta_offset_decoder);
	} else {
		int i;

		for (i = 0; i < LZMS_NUM_RECENT_OFFSETS - 1; i++)
			if (!lzms_range_decode_bit(&ctx->delta_repeat_match_range_decoders[i]))
				break;

		power = ctx->lru.delta.recent_powers[i];
		raw_offset = ctx->lru.delta.recent_offsets[i];

		for (; i < LZMS_NUM_RECENT_OFFSETS; i++) {
			ctx->lru.delta.recent_powers[i] = ctx->lru.delta.recent_powers[i + 1];
			ctx->lru.delta.recent_offsets[i] = ctx->lru.delta.recent_offsets[i + 1];
		}
	}

	length = lzms_decode_value(&ctx->length_decoder);

	ctx->lru.delta.upcoming_power = power;
	ctx->lru.delta.upcoming_offset = raw_offset;

	LZMS_DEBUG("Decoded %s delta match: length=%u, power=%u, raw_offset=%u",
		   (bit ? "repeat" : "explicit"), length, power, raw_offset);

	/* Validate the match and copy it to the output.  */
	return lzms_copy_delta_match(ctx, length, power, raw_offset);
}

/* Decode an LZ or delta match.  */
static int
lzms_decode_match(struct lzms_decompressor *ctx)
{
	if (!lzms_range_decode_bit(&ctx->match_range_decoder))
		return lzms_decode_lz_match(ctx);
	else
		return lzms_decode_delta_match(ctx);
}

/* Decode a literal byte encoded using the literal Huffman code.  */
static int
lzms_decode_literal(struct lzms_decompressor *ctx)
{
	u8 literal = lzms_huffman_decode_symbol(&ctx->literal_decoder);
	LZMS_DEBUG("Decoded literal: 0x%02x", literal);
	return lzms_copy_literal(ctx, literal);
}

/* Decode the next LZMS match or literal.  */
static int
lzms_decode_item(struct lzms_decompressor *ctx)
{
	int ret;

	ctx->lru.lz.upcoming_offset = 0;
	ctx->lru.delta.upcoming_power = 0;
	ctx->lru.delta.upcoming_offset = 0;

	if (lzms_range_decode_bit(&ctx->main_range_decoder))
		ret = lzms_decode_match(ctx);
	else
		ret = lzms_decode_literal(ctx);

	if (ret)
		return ret;

	lzms_update_lru_queues(&ctx->lru);
	return 0;
}

static void
lzms_init_range_decoder(struct lzms_range_decoder *dec,
			struct lzms_range_decoder_raw *rd, u32 num_states)
{
	dec->rd = rd;
	dec->state = 0;
	dec->mask = num_states - 1;
	for (u32 i = 0; i < num_states; i++) {
		dec->prob_entries[i].num_recent_zero_bits = LZMS_INITIAL_PROBABILITY;
		dec->prob_entries[i].recent_bits = LZMS_INITIAL_RECENT_BITS;
	}
}

static void
lzms_init_huffman_decoder(struct lzms_huffman_decoder *dec,
			  struct lzms_input_bitstream *is,
			  const u32 *slot_base_tab,
			  const u8 *extra_bits_tab,
			  unsigned num_syms,
			  unsigned rebuild_freq)
{
	dec->is = is;
	dec->slot_base_tab = slot_base_tab;
	dec->extra_bits_tab = extra_bits_tab;
	dec->num_syms = num_syms;
	dec->num_syms_read = rebuild_freq;
	dec->rebuild_freq = rebuild_freq;
	for (unsigned i = 0; i < num_syms; i++)
		dec->sym_freqs[i] = 1;
}

/* Prepare to decode items from an LZMS-compressed block.  */
static void
lzms_init_decompressor(struct lzms_decompressor *ctx,
		       const void *cdata, unsigned clen,
		       void *ubuf, unsigned ulen)
{
	unsigned num_position_slots;

	LZMS_DEBUG("Initializing decompressor (clen=%u, ulen=%u)", clen, ulen);

	/* Initialize output pointers.  */
	ctx->out_begin = ubuf;
	ctx->out_next = ubuf;
	ctx->out_end = (u8*)ubuf + ulen;

	/* Initialize the raw range decoder (reading forwards).  */
	lzms_range_decoder_raw_init(&ctx->rd, cdata, clen / 2);

	/* Initialize the input bitstream for Huffman symbols (reading
	 * backwards)  */
	lzms_input_bitstream_init(&ctx->is, cdata, clen / 2);

	/* Calculate the number of position slots needed for this compressed
	 * block.  */
	num_position_slots = lzms_get_position_slot(ulen - 1) + 1;

	LZMS_DEBUG("Using %u position slots", num_position_slots);

	/* Initialize Huffman decoders for each alphabet used in the compressed
	 * representation.  */
	lzms_init_huffman_decoder(&ctx->literal_decoder, &ctx->is,
				  NULL, NULL, LZMS_NUM_LITERAL_SYMS,
				  LZMS_LITERAL_CODE_REBUILD_FREQ);

	lzms_init_huffman_decoder(&ctx->lz_offset_decoder, &ctx->is,
				  lzms_position_slot_base,
				  lzms_extra_position_bits,
				  num_position_slots,
				  LZMS_LZ_OFFSET_CODE_REBUILD_FREQ);

	lzms_init_huffman_decoder(&ctx->length_decoder, &ctx->is,
				  lzms_length_slot_base,
				  lzms_extra_length_bits,
				  LZMS_NUM_LEN_SYMS,
				  LZMS_LENGTH_CODE_REBUILD_FREQ);

	lzms_init_huffman_decoder(&ctx->delta_offset_decoder, &ctx->is,
				  lzms_position_slot_base,
				  lzms_extra_position_bits,
				  num_position_slots,
				  LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ);

	lzms_init_huffman_decoder(&ctx->delta_power_decoder, &ctx->is,
				  NULL, NULL, LZMS_NUM_DELTA_POWER_SYMS,
				  LZMS_DELTA_POWER_CODE_REBUILD_FREQ);


	/* Initialize range decoders, all of which wrap around the same
	 * lzms_range_decoder_raw.  */
	lzms_init_range_decoder(&ctx->main_range_decoder,
				&ctx->rd, LZMS_NUM_MAIN_STATES);

	lzms_init_range_decoder(&ctx->match_range_decoder,
				&ctx->rd, LZMS_NUM_MATCH_STATES);

	lzms_init_range_decoder(&ctx->lz_match_range_decoder,
				&ctx->rd, LZMS_NUM_LZ_MATCH_STATES);

	for (size_t i = 0; i < ARRAY_LEN(ctx->lz_repeat_match_range_decoders); i++)
		lzms_init_range_decoder(&ctx->lz_repeat_match_range_decoders[i],
					&ctx->rd, LZMS_NUM_LZ_REPEAT_MATCH_STATES);

	lzms_init_range_decoder(&ctx->delta_match_range_decoder,
				&ctx->rd, LZMS_NUM_DELTA_MATCH_STATES);

	for (size_t i = 0; i < ARRAY_LEN(ctx->delta_repeat_match_range_decoders); i++)
		lzms_init_range_decoder(&ctx->delta_repeat_match_range_decoders[i],
					&ctx->rd, LZMS_NUM_DELTA_REPEAT_MATCH_STATES);

	/* Initialize LRU match information.  */
	lzms_init_lru_queues(&ctx->lru);

	LZMS_DEBUG("Decompressor successfully initialized");
}

/* Decode the series of literals and matches from the LZMS-compressed data.
 * Returns 0 on success; nonzero if the compressed data is invalid.  */
static int
lzms_decode_items(const u8 *cdata, size_t clen, u8 *ubuf, size_t ulen,
		  struct lzms_decompressor *ctx)
{
	/* Initialize the LZMS decompressor.  */
	lzms_init_decompressor(ctx, cdata, clen, ubuf, ulen);

	/* Decode the sequence of items.  */
	while (ctx->out_next != ctx->out_end) {
		LZMS_DEBUG("Position %u", ctx->out_next - ctx->out_begin);
		if (lzms_decode_item(ctx))
			return -1;
	}
	return 0;
}

static int
lzms_decompress(const void *compressed_data, size_t compressed_size,
		void *uncompressed_data, size_t uncompressed_size, void *_ctx)
{
	struct lzms_decompressor *ctx = _ctx;

	/* The range decoder requires that a minimum of 4 bytes of compressed
	 * data be initially available.  */
	if (compressed_size < 4) {
		LZMS_DEBUG("Compressed size too small (got %zu, expected >= 4)",
			   compressed_size);
		return -1;
	}

	/* An LZMS-compressed data block should be evenly divisible into 16-bit
	 * integers.  */
	if (compressed_size % 2 != 0) {
		LZMS_DEBUG("Compressed size not divisible by 2 (got %zu)",
			   compressed_size);
		return -1;
	}

	/* Handle the trivial case where nothing needs to be decompressed.
	 * (Necessary because a window of size 0 does not have a valid position
	 * slot.)  */
	if (uncompressed_size == 0)
		return 0;

	/* The x86 post-processor requires that the uncompressed length fit into
	 * a signed 32-bit integer.  Also, the position slot table cannot be
	 * searched for a position of INT32_MAX or greater.  */
	if (uncompressed_size >= INT32_MAX) {
		LZMS_DEBUG("Uncompressed length too large "
			   "(got %zu, expected < INT32_MAX)",
			   uncompressed_size);
		return -1;
	}

	/* Decode the literals and matches.  */
	if (lzms_decode_items(compressed_data, compressed_size,
			      uncompressed_data, uncompressed_size, ctx))
		return -1;

	/* Postprocess the data.  */
	lzms_x86_filter(uncompressed_data, uncompressed_size,
			ctx->last_target_usages, true);

	LZMS_DEBUG("Decompression successful.");
	return 0;
}

static void
lzms_free_decompressor(void *_ctx)
{
	struct lzms_decompressor *ctx = _ctx;

	ALIGNED_FREE(ctx);
}

static int
lzms_create_decompressor(size_t max_block_size,
			 const struct wimlib_decompressor_params_header *params,
			 void **ctx_ret)
{
	struct lzms_decompressor *ctx;

	ctx = ALIGNED_MALLOC(sizeof(struct lzms_decompressor),
			     DECODE_TABLE_ALIGNMENT);
	if (ctx == NULL)
		return WIMLIB_ERR_NOMEM;

	/* Initialize position and length slot data if not done already.  */
	lzms_init_slots();

	*ctx_ret = ctx;
	return 0;
}

const struct decompressor_ops lzms_decompressor_ops = {
	.create_decompressor  = lzms_create_decompressor,
	.decompress	      = lzms_decompress,
	.free_decompressor    = lzms_free_decompressor,
};
