/*
 * lzx-compress.c
 *
 * A compressor that produces output compatible with the LZX compression format.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
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
 * This file contains a compressor for the LZX ("Lempel-Ziv eXtended")
 * compression format, as used in the WIM (Windows IMaging) file format.
 *
 * Two different parsing algorithms are implemented: "near-optimal" and "lazy".
 * "Near-optimal" is significantly slower than "lazy", but results in a better
 * compression ratio.  The "near-optimal" algorithm is used at the default
 * compression level.
 *
 * This file may need some slight modifications to be used outside of the WIM
 * format.  In particular, in other situations the LZX block header might be
 * slightly different, and a sliding window rather than a fixed-size window
 * might be required.
 *
 * Note: LZX is a compression format derived from DEFLATE, the format used by
 * zlib and gzip.  Both LZX and DEFLATE use LZ77 matching and Huffman coding.
 * Certain details are quite similar, such as the method for storing Huffman
 * codes.  However, the main differences are:
 *
 * - LZX preprocesses the data to attempt to make x86 machine code slightly more
 *   compressible before attempting to compress it further.
 *
 * - LZX uses a "main" alphabet which combines literals and matches, with the
 *   match symbols containing a "length header" (giving all or part of the match
 *   length) and an "offset slot" (giving, roughly speaking, the order of
 *   magnitude of the match offset).
 *
 * - LZX does not have static Huffman blocks (that is, the kind with preset
 *   Huffman codes); however it does have two types of dynamic Huffman blocks
 *   ("verbatim" and "aligned").
 *
 * - LZX has a minimum match length of 2 rather than 3.  Length 2 matches can be
 *   useful, but generally only if the parser is smart about choosing them.
 *
 * - In LZX, offset slots 0 through 2 actually represent entries in an LRU queue
 *   of match offsets.  This is very useful for certain types of files, such as
 *   binary files that have repeating records.
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
#include "wimlib/lzx.h"
#include "wimlib/util.h"

#include <string.h>
#include <limits.h>

#define LZX_OPTIM_ARRAY_LENGTH	4096

#define LZX_DIV_BLOCK_SIZE	32768

#define LZX_CACHE_PER_POS	8

#define LZX_MAX_MATCHES_PER_POS	(LZX_MAX_MATCH_LEN - LZX_MIN_MATCH_LEN + 1)

#define LZX_CACHE_LEN (LZX_DIV_BLOCK_SIZE * (LZX_CACHE_PER_POS + 1))

struct lzx_compressor;

/* Codewords for the LZX Huffman codes.  */
struct lzx_codewords {
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u32 len[LZX_LENCODE_NUM_SYMBOLS];
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Codeword lengths (in bits) for the LZX Huffman codes.
 * A zero length means the corresponding codeword has zero frequency.  */
struct lzx_lens {
	u8 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u8 len[LZX_LENCODE_NUM_SYMBOLS];
	u8 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Estimated cost, in bits, to output each symbol in the LZX Huffman codes.  */
struct lzx_costs {
	u8 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u8 len[LZX_LENCODE_NUM_SYMBOLS];
	u8 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Codewords and lengths for the LZX Huffman codes.  */
struct lzx_codes {
	struct lzx_codewords codewords;
	struct lzx_lens lens;
};

/* Symbol frequency counters for the LZX Huffman codes.  */
struct lzx_freqs {
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u32 len[LZX_LENCODE_NUM_SYMBOLS];
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Intermediate LZX match/literal format  */
struct lzx_item {

	/* Bits 0  -  9: Main symbol
	 * Bits 10 - 17: Length symbol
	 * Bits 18 - 22: Number of extra offset bits
	 * Bits 23+    : Extra offset bits  */
	u64 data;
};

/* Internal compression parameters  */
struct lzx_compressor_params {
	u32 (*choose_items_for_block)(struct lzx_compressor *, u32, u32);
	u32 num_optim_passes;
	enum lz_mf_algo mf_algo;
	u32 min_match_length;
	u32 nice_match_length;
	u32 max_search_depth;
};

/*
 * Match chooser position data:
 *
 * An array of these structures is used during the near-optimal match-choosing
 * algorithm.  They correspond to consecutive positions in the window and are
 * used to keep track of the cost to reach each position, and the match/literal
 * choices that need to be chosen to reach that position.
 */
struct lzx_mc_pos_data {

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
	u32 mc_item_data;
#define MC_OFFSET_SHIFT 9
#define MC_LEN_MASK ((1 << MC_OFFSET_SHIFT) - 1)

	/* The state of the LZX recent match offsets queue at this position.
	 * This is filled in lazily, only after the minimum-cost path to this
	 * position is found.
	 *
	 * Note: the way we handle this adaptive state in the "minimum-cost"
	 * parse is actually only an approximation.  It's possible for the
	 * globally optimal, minimum cost path to contain a prefix, ending at a
	 * position, where that path prefix is *not* the minimum cost path to
	 * that position.  This can happen if such a path prefix results in a
	 * different adaptive state which results in lower costs later.  We do
	 * not solve this problem; we only consider the lowest cost to reach
	 * each position, which seems to be an acceptable approximation.  */
	struct lzx_lru_queue queue _aligned_attribute(16);

} _aligned_attribute(16);

/* State of the LZX compressor  */
struct lzx_compressor {

	/* Internal compression parameters  */
	struct lzx_compressor_params params;

	/* The preprocessed buffer of data being compressed  */
	u8 *cur_window;

	/* Number of bytes of data to be compressed, which is the number of
	 * bytes of data in @cur_window that are actually valid.  */
	u32 cur_window_size;

	/* log2 order of the LZX window size for LZ match offset encoding
	 * purposes.  Will be >= LZX_MIN_WINDOW_ORDER and <=
	 * LZX_MAX_WINDOW_ORDER.
	 *
	 * Note: 1 << @window_order is normally equal to @max_window_size,
	 * a.k.a. the allocated size of @cur_window, but it will be greater than
	 * @max_window_size in the event that the compressor was created with a
	 * non-power-of-2 block size.  (See lzx_get_window_order().)  */
	unsigned window_order;

	/* Number of symbols in the main alphabet.  This depends on
	 * @window_order, since @window_order determines the maximum possible
	 * offset.  It does not, however, depend on the *actual* size of the
	 * current data buffer being processed, which might be less than 1 <<
	 * @window_order.  */
	unsigned num_main_syms;

	/* Lempel-Ziv match-finder  */
	struct lz_mf *mf;

	/* Match-finder wrapper functions and data for near-optimal parsing.
	 *
	 * When doing more than one match-choosing pass over the data, matches
	 * found by the match-finder are cached to achieve a slight speedup when
	 * the same matches are needed on subsequent passes.  This is suboptimal
	 * because different matches may be preferred with different cost
	 * models, but it is a very worthwhile speedup.  */
	unsigned (*get_matches_func)(struct lzx_compressor *, const struct lz_match **);
	void (*skip_bytes_func)(struct lzx_compressor *, unsigned n);
	u32 match_window_pos;
	u32 match_window_end;
	struct lz_match *cached_matches;
	struct lz_match *cache_ptr;
	struct lz_match *cache_limit;

	/* Position data for near-optimal parsing.  */
	struct lzx_mc_pos_data optimum[LZX_OPTIM_ARRAY_LENGTH + LZX_MAX_MATCH_LEN];

	/* The cost model currently being used for near-optimal parsing.  */
	struct lzx_costs costs;

	/* The current match offset LRU queue.  */
	struct lzx_lru_queue queue;

	/* Frequency counters for the current block.  */
	struct lzx_freqs freqs;

	/* The Huffman codes for the current and previous blocks.  */
	struct lzx_codes codes[2];

	/* Which 'struct lzx_codes' is being used for the current block.  The
	 * other was used for the previous block (if this isn't the first
	 * block).  */
	unsigned int codes_index;

	/* Dummy lengths that are always 0.  */
	struct lzx_lens zero_lens;

	/* Matches/literals that were chosen for the current block.  */
	struct lzx_item chosen_items[LZX_DIV_BLOCK_SIZE];

	/* Table mapping match offset => offset slot for small offsets  */
#define LZX_NUM_FAST_OFFSETS 32768
	u8 offset_slot_fast[LZX_NUM_FAST_OFFSETS];
};

/*
 * Structure to keep track of the current state of sending bits to the
 * compressed output buffer.
 *
 * The LZX bitstream is encoded as a sequence of 16-bit coding units.
 */
struct lzx_output_bitstream {

	/* Bits that haven't yet been written to the output buffer.  */
	u32 bitbuf;

	/* Number of bits currently held in @bitbuf.  */
	u32 bitcount;

	/* Pointer to the start of the output buffer.  */
	le16 *start;

	/* Pointer to the position in the output buffer at which the next coding
	 * unit should be written.  */
	le16 *next;

	/* Pointer past the end of the output buffer.  */
	le16 *end;
};

/*
 * Initialize the output bitstream.
 *
 * @os
 *	The output bitstream structure to initialize.
 * @buffer
 *	The buffer being written to.
 * @size
 *	Size of @buffer, in bytes.
 */
static void
lzx_init_output(struct lzx_output_bitstream *os, void *buffer, u32 size)
{
	os->bitbuf = 0;
	os->bitcount = 0;
	os->start = buffer;
	os->next = os->start;
	os->end = os->start + size / sizeof(le16);
}

/*
 * Write some bits to the output bitstream.
 *
 * The bits are given by the low-order @num_bits bits of @bits.  Higher-order
 * bits in @bits cannot be set.  At most 17 bits can be written at once.
 *
 * @max_num_bits is a compile-time constant that specifies the maximum number of
 * bits that can ever be written at the call site.  Currently, it is used to
 * optimize away the conditional code for writing a second 16-bit coding unit
 * when writing fewer than 17 bits.
 *
 * If the output buffer space is exhausted, then the bits will be ignored, and
 * lzx_flush_output() will return 0 when it gets called.
 */
static inline void
lzx_write_varbits(struct lzx_output_bitstream *os,
		  const u32 bits, const unsigned int num_bits,
		  const unsigned int max_num_bits)
{
	/* This code is optimized for LZX, which never needs to write more than
	 * 17 bits at once.  */
	LZX_ASSERT(num_bits <= 17);
	LZX_ASSERT(num_bits <= max_num_bits);
	LZX_ASSERT(os->bitcount <= 15);

	/* Add the bits to the bit buffer variable.  @bitcount will be at most
	 * 15, so there will be just enough space for the maximum possible
	 * @num_bits of 17.  */
	os->bitcount += num_bits;
	os->bitbuf = (os->bitbuf << num_bits) | bits;

	/* Check whether any coding units need to be written.  */
	if (os->bitcount >= 16) {

		os->bitcount -= 16;

		/* Write a coding unit, unless it would overflow the buffer.  */
		if (os->next != os->end)
			*os->next++ = cpu_to_le16(os->bitbuf >> os->bitcount);

		/* If writing 17 bits, a second coding unit might need to be
		 * written.  But because 'max_num_bits' is a compile-time
		 * constant, the compiler will optimize away this code at most
		 * call sites.  */
		if (max_num_bits == 17 && os->bitcount == 16) {
			if (os->next != os->end)
				*os->next++ = cpu_to_le16(os->bitbuf);
			os->bitcount = 0;
		}
	}
}

/* Use when @num_bits is a compile-time constant.  Otherwise use
 * lzx_write_varbits().  */
static inline void
lzx_write_bits(struct lzx_output_bitstream *os,
	       const u32 bits, const unsigned int num_bits)
{
	lzx_write_varbits(os, bits, num_bits, num_bits);
}

/*
 * Flush the last coding unit to the output buffer if needed.  Return the total
 * number of bytes written to the output buffer, or 0 if an overflow occurred.
 */
static u32
lzx_flush_output(struct lzx_output_bitstream *os)
{
	if (os->next == os->end)
		return 0;

	if (os->bitcount != 0)
		*os->next++ = cpu_to_le16(os->bitbuf << (16 - os->bitcount));

	return (const u8 *)os->next - (const u8 *)os->start;
}

/* Build the main, length, and aligned offset Huffman codes used in LZX.
 *
 * This takes as input the frequency tables for each code and produces as output
 * a set of tables that map symbols to codewords and codeword lengths.  */
static void
lzx_make_huffman_codes(const struct lzx_freqs *freqs, struct lzx_codes *codes,
		       unsigned num_main_syms)
{
	make_canonical_huffman_code(num_main_syms,
				    LZX_MAX_MAIN_CODEWORD_LEN,
				    freqs->main,
				    codes->lens.main,
				    codes->codewords.main);

	make_canonical_huffman_code(LZX_LENCODE_NUM_SYMBOLS,
				    LZX_MAX_LEN_CODEWORD_LEN,
				    freqs->len,
				    codes->lens.len,
				    codes->codewords.len);

	make_canonical_huffman_code(LZX_ALIGNEDCODE_NUM_SYMBOLS,
				    LZX_MAX_ALIGNED_CODEWORD_LEN,
				    freqs->aligned,
				    codes->lens.aligned,
				    codes->codewords.aligned);
}

static unsigned
lzx_compute_precode_items(const u8 lens[restrict],
			  const u8 prev_lens[restrict],
			  const unsigned num_lens,
			  u32 precode_freqs[restrict],
			  unsigned precode_items[restrict])
{
	unsigned *itemptr;
	unsigned run_start;
	unsigned run_end;
	unsigned extra_bits;
	int delta;
	u8 len;

	itemptr = precode_items;
	run_start = 0;
	do {
		/* Find the next run of codeword lengths.  */

		/* len = the length being repeated  */
		len = lens[run_start];

		run_end = run_start + 1;

		/* Fast case for a single length.  */
		if (likely(run_end == num_lens || len != lens[run_end])) {
			delta = prev_lens[run_start] - len;
			if (delta < 0)
				delta += 17;
			precode_freqs[delta]++;
			*itemptr++ = delta;
			run_start++;
			continue;
		}

		/* Extend the run.  */
		do {
			run_end++;
		} while (run_end != num_lens && len == lens[run_end]);

		if (len == 0) {
			/* Run of zeroes.  */

			/* Symbol 18: RLE 20 to 51 zeroes at a time.  */
			while ((run_end - run_start) >= 20) {
				extra_bits = min((run_end - run_start) - 20, 0x1f);
				precode_freqs[18]++;
				*itemptr++ = 18 | (extra_bits << 5);
				run_start += 20 + extra_bits;
			}

			/* Symbol 17: RLE 4 to 19 zeroes at a time.  */
			if ((run_end - run_start) >= 4) {
				extra_bits = min((run_end - run_start) - 4, 0xf);
				precode_freqs[17]++;
				*itemptr++ = 17 | (extra_bits << 5);
				run_start += 4 + extra_bits;
			}
		} else {

			/* A run of nonzero lengths. */

			/* Symbol 19: RLE 4 to 5 of any length at a time.  */
			while ((run_end - run_start) >= 4) {
				extra_bits = (run_end - run_start) > 4;
				delta = prev_lens[run_start] - len;
				if (delta < 0)
					delta += 17;
				precode_freqs[19]++;
				precode_freqs[delta]++;
				*itemptr++ = 19 | (extra_bits << 5) | (delta << 6);
				run_start += 4 + extra_bits;
			}
		}

		/* Output any remaining lengths without RLE.  */
		while (run_start != run_end) {
			delta = prev_lens[run_start] - len;
			if (delta < 0)
				delta += 17;
			precode_freqs[delta]++;
			*itemptr++ = delta;
			run_start++;
		}
	} while (run_start != num_lens);

	return itemptr - precode_items;
}

/*
 * Output a Huffman code in the compressed form used in LZX.
 *
 * The Huffman code is represented in the output as a logical series of codeword
 * lengths from which the Huffman code, which must be in canonical form, can be
 * reconstructed.
 *
 * The codeword lengths are themselves compressed using a separate Huffman code,
 * the "precode", which contains a symbol for each possible codeword length in
 * the larger code as well as several special symbols to represent repeated
 * codeword lengths (a form of run-length encoding).  The precode is itself
 * constructed in canonical form, and its codeword lengths are represented
 * literally in 20 4-bit fields that immediately precede the compressed codeword
 * lengths of the larger code.
 *
 * Furthermore, the codeword lengths of the larger code are actually represented
 * as deltas from the codeword lengths of the corresponding code in the previous
 * block.
 *
 * @os:
 *	Bitstream to which to write the compressed Huffman code.
 * @lens:
 *	The codeword lengths, indexed by symbol, in the Huffman code.
 * @prev_lens:
 *	The codeword lengths, indexed by symbol, in the corresponding Huffman
 *	code in the previous block, or all zeroes if this is the first block.
 * @num_lens:
 *	The number of symbols in the Huffman code.
 */
static void
lzx_write_compressed_code(struct lzx_output_bitstream *os,
			  const u8 lens[restrict],
			  const u8 prev_lens[restrict],
			  unsigned num_lens)
{
	u32 precode_freqs[LZX_PRECODE_NUM_SYMBOLS];
	u8 precode_lens[LZX_PRECODE_NUM_SYMBOLS];
	u32 precode_codewords[LZX_PRECODE_NUM_SYMBOLS];
	unsigned precode_items[num_lens];
	unsigned num_precode_items;
	unsigned precode_item;
	unsigned precode_sym;
	unsigned i;

	for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++)
		precode_freqs[i] = 0;

	/* Compute the "items" (RLE / literal tokens and extra bits) with which
	 * the codeword lengths in the larger code will be output.  */
	num_precode_items = lzx_compute_precode_items(lens,
						      prev_lens,
						      num_lens,
						      precode_freqs,
						      precode_items);

	/* Build the precode.  */
	make_canonical_huffman_code(LZX_PRECODE_NUM_SYMBOLS,
				    LZX_MAX_PRE_CODEWORD_LEN,
				    precode_freqs, precode_lens,
				    precode_codewords);

	/* Output the lengths of the codewords in the precode.  */
	for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++)
		lzx_write_bits(os, precode_lens[i], LZX_PRECODE_ELEMENT_SIZE);

	/* Output the encoded lengths of the codewords in the larger code.  */
	for (i = 0; i < num_precode_items; i++) {
		precode_item = precode_items[i];
		precode_sym = precode_item & 0x1F;
		lzx_write_varbits(os, precode_codewords[precode_sym],
				  precode_lens[precode_sym],
				  LZX_MAX_PRE_CODEWORD_LEN);
		if (precode_sym >= 17) {
			if (precode_sym == 17) {
				lzx_write_bits(os, precode_item >> 5, 4);
			} else if (precode_sym == 18) {
				lzx_write_bits(os, precode_item >> 5, 5);
			} else {
				lzx_write_bits(os, (precode_item >> 5) & 1, 1);
				precode_sym = precode_item >> 6;
				lzx_write_varbits(os, precode_codewords[precode_sym],
						  precode_lens[precode_sym],
						  LZX_MAX_PRE_CODEWORD_LEN);
			}
		}
	}
}

/* Output a match or literal.  */
static inline void
lzx_write_item(struct lzx_output_bitstream *os, struct lzx_item item,
	       unsigned ones_if_aligned, const struct lzx_codes *codes)
{
	u64 data = item.data;
	unsigned main_symbol;
	unsigned len_symbol;
	unsigned num_extra_bits;
	u32 extra_bits;

	main_symbol = data & 0x3FF;

	lzx_write_varbits(os, codes->codewords.main[main_symbol],
			  codes->lens.main[main_symbol],
			  LZX_MAX_MAIN_CODEWORD_LEN);

	if (main_symbol < LZX_NUM_CHARS)  /* Literal?  */
		return;

	len_symbol = (data >> 10) & 0xFF;

	if (len_symbol != LZX_LENCODE_NUM_SYMBOLS) {
		lzx_write_varbits(os, codes->codewords.len[len_symbol],
				  codes->lens.len[len_symbol],
				  LZX_MAX_LEN_CODEWORD_LEN);
	}

	num_extra_bits = (data >> 18) & 0x1F;
	if (num_extra_bits == 0)  /* Small offset or repeat offset match?  */
		return;

	extra_bits = data >> 23;

	/*if (block_type == LZX_BLOCKTYPE_ALIGNED && num_extra_bits >= 3) {*/
	if ((num_extra_bits & ones_if_aligned) >= 3) {

		/* Aligned offset blocks: The low 3 bits of the extra offset
		 * bits are Huffman-encoded using the aligned offset code.  The
		 * remaining bits are output literally.  */

		lzx_write_varbits(os, extra_bits >> 3, num_extra_bits - 3, 14);

		lzx_write_varbits(os, codes->codewords.aligned[extra_bits & 7],
				  codes->lens.aligned[extra_bits & 7],
				  LZX_MAX_ALIGNED_CODEWORD_LEN);
	} else {
		/* Verbatim blocks, or fewer than 3 extra bits:  All extra
		 * offset bits are output literally.  */
		lzx_write_varbits(os, extra_bits, num_extra_bits, 17);
	}
}

/*
 * Write all matches and literal bytes (which were precomputed) in an LZX
 * compressed block to the output bitstream in the final compressed
 * representation.
 *
 * @os
 *	The output bitstream.
 * @block_type
 *	The chosen type of the LZX compressed block (LZX_BLOCKTYPE_ALIGNED or
 *	LZX_BLOCKTYPE_VERBATIM).
 * @items
 *	The array of matches/literals to output.
 * @num_items
 *	Number of matches/literals to output (length of @items).
 * @codes
 *	The main, length, and aligned offset Huffman codes for the current
 *	LZX compressed block.
 */
static void
lzx_write_items(struct lzx_output_bitstream *os, int block_type,
		const struct lzx_item items[], u32 num_items,
		const struct lzx_codes *codes)
{
	unsigned ones_if_aligned = 0U - (block_type == LZX_BLOCKTYPE_ALIGNED);

	for (u32 i = 0; i < num_items; i++)
		lzx_write_item(os, items[i], ones_if_aligned, codes);
}

/* Write an LZX aligned offset or verbatim block to the output bitstream.  */
static void
lzx_write_compressed_block(int block_type,
			   u32 block_size,
			   unsigned window_order,
			   unsigned num_main_syms,
			   struct lzx_item * chosen_items,
			   u32 num_chosen_items,
			   const struct lzx_codes * codes,
			   const struct lzx_lens * prev_lens,
			   struct lzx_output_bitstream * os)
{
	LZX_ASSERT(block_type == LZX_BLOCKTYPE_ALIGNED ||
		   block_type == LZX_BLOCKTYPE_VERBATIM);

	/* The first three bits indicate the type of block and are one of the
	 * LZX_BLOCKTYPE_* constants.  */
	lzx_write_bits(os, block_type, 3);

	/* Output the block size.
	 *
	 * The original LZX format seemed to always encode the block size in 3
	 * bytes.  However, the implementation in WIMGAPI, as used in WIM files,
	 * uses the first bit to indicate whether the block is the default size
	 * (32768) or a different size given explicitly by the next 16 bits.
	 *
	 * By default, this compressor uses a window size of 32768 and therefore
	 * follows the WIMGAPI behavior.  However, this compressor also supports
	 * window sizes greater than 32768 bytes, which do not appear to be
	 * supported by WIMGAPI.  In such cases, we retain the default size bit
	 * to mean a size of 32768 bytes but output non-default block size in 24
	 * bits rather than 16.  The compatibility of this behavior is unknown
	 * because WIMs created with chunk size greater than 32768 can seemingly
	 * only be opened by wimlib anyway.  */
	if (block_size == LZX_DEFAULT_BLOCK_SIZE) {
		lzx_write_bits(os, 1, 1);
	} else {
		lzx_write_bits(os, 0, 1);

		if (window_order >= 16)
			lzx_write_bits(os, block_size >> 16, 8);

		lzx_write_bits(os, block_size & 0xFFFF, 16);
	}

	/* If it's an aligned offset block, output the aligned offset code.  */
	if (block_type == LZX_BLOCKTYPE_ALIGNED) {
		for (int i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
			lzx_write_bits(os, codes->lens.aligned[i],
				       LZX_ALIGNEDCODE_ELEMENT_SIZE);
		}
	}

	/* Output the main code (two parts).  */
	lzx_write_compressed_code(os, codes->lens.main,
				  prev_lens->main,
				  LZX_NUM_CHARS);
	lzx_write_compressed_code(os, codes->lens.main + LZX_NUM_CHARS,
				  prev_lens->main + LZX_NUM_CHARS,
				  num_main_syms - LZX_NUM_CHARS);

	/* Output the length code.  */
	lzx_write_compressed_code(os, codes->lens.len,
				  prev_lens->len,
				  LZX_LENCODE_NUM_SYMBOLS);

	/* Output the compressed matches and literals.  */
	lzx_write_items(os, block_type, chosen_items, num_chosen_items, codes);
}

/* Don't allow matches to span the end of an LZX block.  */
static inline unsigned
maybe_truncate_matches(struct lz_match matches[], unsigned num_matches,
		       struct lzx_compressor *c)
{
	if (c->match_window_end < c->cur_window_size && num_matches != 0) {
		u32 limit = c->match_window_end - c->match_window_pos;

		if (limit >= LZX_MIN_MATCH_LEN) {

			unsigned i = num_matches - 1;
			do {
				if (matches[i].len >= limit) {
					matches[i].len = limit;

					/* Truncation might produce multiple
					 * matches with length 'limit'.  Keep at
					 * most 1.  */
					num_matches = i + 1;
				}
			} while (i--);
		} else {
			num_matches = 0;
		}
	}
	return num_matches;
}

static unsigned
lzx_get_matches_fillcache_singleblock(struct lzx_compressor *c,
				      const struct lz_match **matches_ret)
{
	struct lz_match *cache_ptr;
	struct lz_match *matches;
	unsigned num_matches;

	cache_ptr = c->cache_ptr;
	matches = cache_ptr + 1;
	if (likely(cache_ptr <= c->cache_limit)) {
		num_matches = lz_mf_get_matches(c->mf, matches);
		cache_ptr->len = num_matches;
		c->cache_ptr = matches + num_matches;
	} else {
		num_matches = 0;
	}
	c->match_window_pos++;
	*matches_ret = matches;
	return num_matches;
}

static unsigned
lzx_get_matches_fillcache_multiblock(struct lzx_compressor *c,
				     const struct lz_match **matches_ret)
{
	struct lz_match *cache_ptr;
	struct lz_match *matches;
	unsigned num_matches;

	cache_ptr = c->cache_ptr;
	matches = cache_ptr + 1;
	if (likely(cache_ptr <= c->cache_limit)) {
		num_matches = lz_mf_get_matches(c->mf, matches);
		num_matches = maybe_truncate_matches(matches, num_matches, c);
		cache_ptr->len = num_matches;
		c->cache_ptr = matches + num_matches;
	} else {
		num_matches = 0;
	}
	c->match_window_pos++;
	*matches_ret = matches;
	return num_matches;
}

static unsigned
lzx_get_matches_usecache(struct lzx_compressor *c,
			 const struct lz_match **matches_ret)
{
	struct lz_match *cache_ptr;
	struct lz_match *matches;
	unsigned num_matches;

	cache_ptr = c->cache_ptr;
	matches = cache_ptr + 1;
	if (cache_ptr <= c->cache_limit) {
		num_matches = cache_ptr->len;
		c->cache_ptr = matches + num_matches;
	} else {
		num_matches = 0;
	}
	c->match_window_pos++;
	*matches_ret = matches;
	return num_matches;
}

static unsigned
lzx_get_matches_usecache_nocheck(struct lzx_compressor *c,
				 const struct lz_match **matches_ret)
{
	struct lz_match *cache_ptr;
	struct lz_match *matches;
	unsigned num_matches;

	cache_ptr = c->cache_ptr;
	matches = cache_ptr + 1;
	num_matches = cache_ptr->len;
	c->cache_ptr = matches + num_matches;
	c->match_window_pos++;
	*matches_ret = matches;
	return num_matches;
}

static unsigned
lzx_get_matches_nocache_singleblock(struct lzx_compressor *c,
				    const struct lz_match **matches_ret)
{
	struct lz_match *matches;
	unsigned num_matches;

	matches = c->cache_ptr;
	num_matches = lz_mf_get_matches(c->mf, matches);
	c->match_window_pos++;
	*matches_ret = matches;
	return num_matches;
}

static unsigned
lzx_get_matches_nocache_multiblock(struct lzx_compressor *c,
				   const struct lz_match **matches_ret)
{
	struct lz_match *matches;
	unsigned num_matches;

	matches = c->cache_ptr;
	num_matches = lz_mf_get_matches(c->mf, matches);
	num_matches = maybe_truncate_matches(matches, num_matches, c);
	c->match_window_pos++;
	*matches_ret = matches;
	return num_matches;
}

/*
 * Find matches at the next position in the window.
 *
 * This uses a wrapper function around the underlying match-finder.
 *
 * Returns the number of matches found and sets *matches_ret to point to the
 * matches array.  The matches will be sorted by strictly increasing length and
 * offset.
 */
static inline unsigned
lzx_get_matches(struct lzx_compressor *c, const struct lz_match **matches_ret)
{
	return (*c->get_matches_func)(c, matches_ret);
}

static void
lzx_skip_bytes_fillcache(struct lzx_compressor *c, unsigned n)
{
	struct lz_match *cache_ptr;

	cache_ptr = c->cache_ptr;
	c->match_window_pos += n;
	lz_mf_skip_positions(c->mf, n);
	if (cache_ptr <= c->cache_limit) {
		do {
			cache_ptr->len = 0;
			cache_ptr += 1;
		} while (--n && cache_ptr <= c->cache_limit);
	}
	c->cache_ptr = cache_ptr;
}

static void
lzx_skip_bytes_usecache(struct lzx_compressor *c, unsigned n)
{
	struct lz_match *cache_ptr;

	cache_ptr = c->cache_ptr;
	c->match_window_pos += n;
	if (cache_ptr <= c->cache_limit) {
		do {
			cache_ptr += 1 + cache_ptr->len;
		} while (--n && cache_ptr <= c->cache_limit);
	}
	c->cache_ptr = cache_ptr;
}

static void
lzx_skip_bytes_usecache_nocheck(struct lzx_compressor *c, unsigned n)
{
	struct lz_match *cache_ptr;

	cache_ptr = c->cache_ptr;
	c->match_window_pos += n;
	do {
		cache_ptr += 1 + cache_ptr->len;
	} while (--n);
	c->cache_ptr = cache_ptr;
}

static void
lzx_skip_bytes_nocache(struct lzx_compressor *c, unsigned n)
{
	c->match_window_pos += n;
	lz_mf_skip_positions(c->mf, n);
}

/*
 * Skip the specified number of positions in the window (don't search for
 * matches at them).
 *
 * This uses a wrapper function around the underlying match-finder.
 */
static inline void
lzx_skip_bytes(struct lzx_compressor *c, unsigned n)
{
	return (*c->skip_bytes_func)(c, n);
}

/* Tally, and optionally record, the specified literal byte.  */
static inline void
lzx_declare_literal(struct lzx_compressor *c, unsigned literal,
		    struct lzx_item **next_chosen_item)
{
	unsigned main_symbol = literal;

	c->freqs.main[main_symbol]++;

	if (next_chosen_item) {
		*(*next_chosen_item)++ = (struct lzx_item) {
			.data = main_symbol,
		};
	}
}

/* Tally, and optionally record, the specified repeat offset match.  */
static inline void
lzx_declare_repeat_offset_match(struct lzx_compressor *c,
				unsigned len, unsigned rep_index,
				struct lzx_item **next_chosen_item)
{
	unsigned len_header;
	unsigned main_symbol;
	unsigned len_symbol;

	if (len - LZX_MIN_MATCH_LEN < LZX_NUM_PRIMARY_LENS) {
		len_header = len - LZX_MIN_MATCH_LEN;
		len_symbol = LZX_LENCODE_NUM_SYMBOLS;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_symbol = len - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS;
		c->freqs.len[len_symbol]++;
	}

	main_symbol = LZX_NUM_CHARS + ((rep_index << 3) | len_header);

	c->freqs.main[main_symbol]++;

	if (next_chosen_item) {
		*(*next_chosen_item)++ = (struct lzx_item) {
			.data = (u64)main_symbol | ((u64)len_symbol << 10),
		};
	}
}

/* Tally, and optionally record, the specified explicit offset match.  */
static inline void
lzx_declare_explicit_offset_match(struct lzx_compressor *c, unsigned len, u32 offset,
				  struct lzx_item **next_chosen_item)
{
	unsigned len_header;
	unsigned main_symbol;
	unsigned len_symbol;
	unsigned offset_slot;
	unsigned num_extra_bits;
	u32 extra_bits;

	if (len - LZX_MIN_MATCH_LEN < LZX_NUM_PRIMARY_LENS) {
		len_header = len - LZX_MIN_MATCH_LEN;
		len_symbol = LZX_LENCODE_NUM_SYMBOLS;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_symbol = len - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS;
		c->freqs.len[len_symbol]++;
	}

	offset_slot = lzx_get_offset_slot_raw(offset + LZX_OFFSET_OFFSET);

	main_symbol = LZX_NUM_CHARS + ((offset_slot << 3) | len_header);

	c->freqs.main[main_symbol]++;

	if (offset_slot >= 8)
		c->freqs.aligned[(offset + LZX_OFFSET_OFFSET) & 7]++;

	if (next_chosen_item) {

		num_extra_bits = lzx_extra_offset_bits[offset_slot];

		extra_bits = (offset + LZX_OFFSET_OFFSET) -
			     lzx_offset_slot_base[offset_slot];

		*(*next_chosen_item)++ = (struct lzx_item) {
			.data = (u64)main_symbol |
				((u64)len_symbol << 10) |
				((u64)num_extra_bits << 18) |
				((u64)extra_bits << 23),
		};
	}
}

/* Tally, and optionally record, the specified match or literal.  */
static inline void
lzx_declare_item(struct lzx_compressor *c, u32 mc_item_data,
		 struct lzx_item **next_chosen_item)
{
	u32 len = mc_item_data & MC_LEN_MASK;
	u32 offset_data = mc_item_data >> MC_OFFSET_SHIFT;

	if (len == 1)
		lzx_declare_literal(c, offset_data, next_chosen_item);
	else if (offset_data < LZX_NUM_RECENT_OFFSETS)
		lzx_declare_repeat_offset_match(c, len, offset_data,
						next_chosen_item);
	else
		lzx_declare_explicit_offset_match(c, len,
						  offset_data - LZX_OFFSET_OFFSET,
						  next_chosen_item);
}

static inline void
lzx_record_item_list(struct lzx_compressor *c,
		     struct lzx_mc_pos_data *cur_optimum_ptr,
		     struct lzx_item **next_chosen_item)
{
	struct lzx_mc_pos_data *end_optimum_ptr;
	u32 saved_item;
	u32 item;

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

	/* Walk the list of items from beginning to end, tallying and recording
	 * each item.  */
	do {
		lzx_declare_item(c, cur_optimum_ptr->mc_item_data, next_chosen_item);
		cur_optimum_ptr += (cur_optimum_ptr->mc_item_data) & MC_LEN_MASK;
	} while (cur_optimum_ptr != end_optimum_ptr);
}

static inline void
lzx_tally_item_list(struct lzx_compressor *c, struct lzx_mc_pos_data *cur_optimum_ptr)
{
	/* Since we're just tallying the items, we don't need to reverse the
	 * list.  Processing the items in reverse order is fine.  */
	do {
		lzx_declare_item(c, cur_optimum_ptr->mc_item_data, NULL);
		cur_optimum_ptr -= (cur_optimum_ptr->mc_item_data & MC_LEN_MASK);
	} while (cur_optimum_ptr != c->optimum);
}

/* Tally, and optionally (if next_chosen_item != NULL) record, in order, all
 * items in the current list of items found by the match-chooser.  */
static void
lzx_declare_item_list(struct lzx_compressor *c, struct lzx_mc_pos_data *cur_optimum_ptr,
		      struct lzx_item **next_chosen_item)
{
	if (next_chosen_item)
		lzx_record_item_list(c, cur_optimum_ptr, next_chosen_item);
	else
		lzx_tally_item_list(c, cur_optimum_ptr);
}

/* Set the cost model @c->costs from the Huffman codeword lengths specified in
 * @lens.
 *
 * The cost model and codeword lengths are almost the same thing, but the
 * Huffman codewords with length 0 correspond to symbols with zero frequency
 * that still need to be assigned actual costs.  The specific values assigned
 * are arbitrary, but they should be fairly high (near the maximum codeword
 * length) to take into account the fact that uses of these symbols are expected
 * to be rare.  */
static void
lzx_set_costs(struct lzx_compressor *c, const struct lzx_lens * lens)
{
	unsigned i;

	/* Main code  */
	for (i = 0; i < c->num_main_syms; i++)
		c->costs.main[i] = lens->main[i] ? lens->main[i] : 15;

	/* Length code  */
	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
		c->costs.len[i] = lens->len[i] ? lens->len[i] : 15;

	/* Aligned offset code  */
	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
		c->costs.aligned[i] = lens->aligned[i] ? lens->aligned[i] : 7;
}

/* Set default LZX Huffman symbol costs to bootstrap the iterative optimization
 * algorithm.  */
static void
lzx_set_default_costs(struct lzx_costs * costs, unsigned num_main_syms)
{
	unsigned i;

	/* Main code (part 1): Literal symbols  */
	for (i = 0; i < LZX_NUM_CHARS; i++)
		costs->main[i] = 8;

	/* Main code (part 2): Match header symbols  */
	for (; i < num_main_syms; i++)
		costs->main[i] = 10;

	/* Length code  */
	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
		costs->len[i] = 8;

	/* Aligned offset code  */
	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
		costs->aligned[i] = 3;
}

/* Return the cost, in bits, to output a literal byte using the specified cost
 * model.  */
static inline u32
lzx_literal_cost(unsigned literal, const struct lzx_costs * costs)
{
	return costs->main[literal];
}

/* Return the cost, in bits, to output a match of the specified length and
 * offset slot using the specified cost model.  Does not take into account
 * extra offset bits.  */
static inline u32
lzx_match_cost_raw(unsigned len, unsigned offset_slot,
		   const struct lzx_costs *costs)
{
	u32 cost;
	unsigned len_header;
	unsigned main_symbol;

	if (len - LZX_MIN_MATCH_LEN < LZX_NUM_PRIMARY_LENS) {
		len_header = len - LZX_MIN_MATCH_LEN;
		cost = 0;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;

		/* Account for length symbol.  */
		cost = costs->len[len - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS];
	}

	/* Account for main symbol.  */
	main_symbol = LZX_NUM_CHARS + ((offset_slot << 3) | len_header);
	cost += costs->main[main_symbol];

	return cost;
}

/* Equivalent to lzx_match_cost_raw(), but assumes the length is small enough
 * that it doesn't require a length symbol.  */
static inline u32
lzx_match_cost_raw_smalllen(unsigned len, unsigned offset_slot,
			    const struct lzx_costs *costs)
{
	LZX_ASSERT(len < LZX_MIN_MATCH_LEN + LZX_NUM_PRIMARY_LENS);
	return costs->main[LZX_NUM_CHARS +
			   ((offset_slot << 3) | (len - LZX_MIN_MATCH_LEN))];
}

/*
 * Consider coding the match at repeat offset index @rep_idx.  Consider each
 * length from the minimum (2) to the full match length (@rep_len).
 */
static inline void
lzx_consider_repeat_offset_match(struct lzx_compressor *c,
				 struct lzx_mc_pos_data *cur_optimum_ptr,
				 unsigned rep_len, unsigned rep_idx)
{
	u32 base_cost = cur_optimum_ptr->cost;
	u32 cost;
	unsigned len;

#if 1   /* Optimized version */

	if (rep_len < LZX_MIN_MATCH_LEN + LZX_NUM_PRIMARY_LENS) {
		/* All lengths being considered are small.  */
		len = 2;
		do {
			cost = base_cost +
			       lzx_match_cost_raw_smalllen(len, rep_idx, &c->costs);
			if (cost < (cur_optimum_ptr + len)->cost) {
				(cur_optimum_ptr + len)->mc_item_data =
					(rep_idx << MC_OFFSET_SHIFT) | len;
				(cur_optimum_ptr + len)->cost = cost;
			}
		} while (++len <= rep_len);
	} else {
		/* Some lengths being considered are small, and some are big.
		 * Start with the optimized loop for small lengths, then switch
		 * to the optimized loop for big lengths.  */
		len = 2;
		do {
			cost = base_cost +
			       lzx_match_cost_raw_smalllen(len, rep_idx, &c->costs);
			if (cost < (cur_optimum_ptr + len)->cost) {
				(cur_optimum_ptr + len)->mc_item_data =
					(rep_idx << MC_OFFSET_SHIFT) | len;
				(cur_optimum_ptr + len)->cost = cost;
			}
		} while (++len < LZX_MIN_MATCH_LEN + LZX_NUM_PRIMARY_LENS);

		/* The main symbol is now fixed.  */
		base_cost += c->costs.main[LZX_NUM_CHARS +
					   ((rep_idx << 3) | LZX_NUM_PRIMARY_LENS)];
		do {
			cost = base_cost +
			       c->costs.len[len - LZX_MIN_MATCH_LEN -
					    LZX_NUM_PRIMARY_LENS];
			if (cost < (cur_optimum_ptr + len)->cost) {
				(cur_optimum_ptr + len)->mc_item_data =
					(rep_idx << MC_OFFSET_SHIFT) | len;
				(cur_optimum_ptr + len)->cost = cost;
			}
		} while (++len <= rep_len);
	}

#else   /* Unoptimized version  */

	len = 2;
	do {
		cost = base_cost +
		       lzx_match_cost_raw(len, rep_idx, &c->costs);
		if (cost < (cur_optimum_ptr + len)->cost) {
			(cur_optimum_ptr + len)->mc_item_data =
				(rep_idx << MC_OFFSET_SHIFT) | len;
			(cur_optimum_ptr + len)->cost = cost;
		}
	} while (++len <= rep_len);
#endif
}

/*
 * Consider coding each match in @matches as an explicit offset match.
 *
 * @matches must be sorted by strictly increasing length and strictly
 * increasing offset.  This is guaranteed by the match-finder.
 *
 * We consider each length from the minimum (2) to the longest
 * (matches[num_matches - 1].len).  For each length, we consider only
 * the smallest offset for which that length is available.  Although
 * this is not guaranteed to be optimal due to the possibility of a
 * larger offset costing less than a smaller offset to code, this is a
 * very useful heuristic.
 */
static inline void
lzx_consider_explicit_offset_matches(struct lzx_compressor *c,
				     struct lzx_mc_pos_data *cur_optimum_ptr,
				     const struct lz_match matches[],
				     unsigned num_matches)
{
	LZX_ASSERT(num_matches > 0);

	unsigned i;
	unsigned len;
	unsigned offset_slot;
	u32 position_cost;
	u32 cost;
	u32 offset_data;


#if 1	/* Optimized version */

	if (matches[num_matches - 1].offset < LZX_NUM_FAST_OFFSETS) {

		/*
		 * Offset is small; the offset slot can be looked up directly in
		 * c->offset_slot_fast.
		 *
		 * Additional optimizations:
		 *
		 * - Since the offset is small, it falls in the exponential part
		 *   of the offset slot bases and the number of extra offset
		 *   bits can be calculated directly as (offset_slot >> 1) - 1.
		 *
		 * - Just consider the number of extra offset bits; don't
		 *   account for the aligned offset code.  Usually this has
		 *   almost no effect on the compression ratio.
		 *
		 * - Start out in a loop optimized for small lengths.  When the
		 *   length becomes high enough that a length symbol will be
		 *   needed, jump into a loop optimized for big lengths.
		 */

		LZX_ASSERT(offset_slot <= 37); /* for extra bits formula  */

		len = 2;
		i = 0;
		do {
			offset_slot = c->offset_slot_fast[matches[i].offset];
			position_cost = cur_optimum_ptr->cost +
					((offset_slot >> 1) - 1);
			offset_data = matches[i].offset + LZX_OFFSET_OFFSET;
			do {
				if (len >= LZX_MIN_MATCH_LEN + LZX_NUM_PRIMARY_LENS)
					goto biglen;
				cost = position_cost +
				       lzx_match_cost_raw_smalllen(len, offset_slot,
								   &c->costs);
				if (cost < (cur_optimum_ptr + len)->cost) {
					(cur_optimum_ptr + len)->cost = cost;
					(cur_optimum_ptr + len)->mc_item_data =
						(offset_data << MC_OFFSET_SHIFT) | len;
				}
			} while (++len <= matches[i].len);
		} while (++i != num_matches);

		return;

		do {
			offset_slot = c->offset_slot_fast[matches[i].offset];
	biglen:
			position_cost = cur_optimum_ptr->cost +
					((offset_slot >> 1) - 1) +
					c->costs.main[LZX_NUM_CHARS +
						      ((offset_slot << 3) |
						       LZX_NUM_PRIMARY_LENS)];
			offset_data = matches[i].offset + LZX_OFFSET_OFFSET;
			do {
				cost = position_cost +
				       c->costs.len[len - LZX_MIN_MATCH_LEN -
						    LZX_NUM_PRIMARY_LENS];
				if (cost < (cur_optimum_ptr + len)->cost) {
					(cur_optimum_ptr + len)->cost = cost;
					(cur_optimum_ptr + len)->mc_item_data =
						(offset_data << MC_OFFSET_SHIFT) | len;
				}
			} while (++len <= matches[i].len);
		} while (++i != num_matches);
	} else {
		len = 2;
		i = 0;
		do {
			offset_data = matches[i].offset + LZX_OFFSET_OFFSET;
			offset_slot = lzx_get_offset_slot_raw(offset_data);
			position_cost = cur_optimum_ptr->cost +
					lzx_extra_offset_bits[offset_slot];
			do {
				cost = position_cost +
				       lzx_match_cost_raw(len, offset_slot, &c->costs);
				if (cost < (cur_optimum_ptr + len)->cost) {
					(cur_optimum_ptr + len)->cost = cost;
					(cur_optimum_ptr + len)->mc_item_data =
						(offset_data << MC_OFFSET_SHIFT) | len;
				}
			} while (++len <= matches[i].len);
		} while (++i != num_matches);
	}

#else	/* Unoptimized version */

	unsigned num_extra_bits;

	len = 2;
	i = 0;
	do {
		offset_data = matches[i].offset + LZX_OFFSET_OFFSET;
		position_cost = cur_optimum_ptr->cost;
		offset_slot = lzx_get_offset_slot_raw(offset_data);
		num_extra_bits = lzx_extra_offset_bits[offset_slot];
		if (num_extra_bits >= 3) {
			position_cost += num_extra_bits - 3;
			position_cost += c->costs.aligned[offset_data & 7];
		} else {
			position_cost += num_extra_bits;
		}
		do {
			cost = position_cost +
			       lzx_match_cost_raw(len, offset_slot, &c->costs);
			if (cost < (cur_optimum_ptr + len)->cost) {
				(cur_optimum_ptr + len)->cost = cost;
				(cur_optimum_ptr + len)->mc_item_data =
					(offset_data << MC_OFFSET_SHIFT) | len;
			}
		} while (++len <= matches[i].len);
	} while (++i != num_matches);
#endif
}

/*
 * Search for repeat offset matches with the current position.
 */
static inline unsigned
lzx_repsearch(const u8 * const strptr, const u32 bytes_remaining,
	      const struct lzx_lru_queue *queue, unsigned *rep_max_idx_ret)
{
	BUILD_BUG_ON(LZX_NUM_RECENT_OFFSETS != 3);
	return lz_repsearch3(strptr, min(bytes_remaining, LZX_MAX_MATCH_LEN),
			     queue->R, rep_max_idx_ret);
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
 * This function will run this algorithm on the portion of the window from
 * &c->cur_window[c->match_window_pos] to &c->cur_window[c->match_window_end].
 *
 * On entry, c->queue must be the current state of the match offset LRU queue,
 * and c->costs must be the current cost model to use for Huffman symbols.
 *
 * On exit, c->queue will be the state that the LRU queue would be in if the
 * chosen items were to be coded.
 *
 * If next_chosen_item != NULL, then all items chosen will be recorded (saved in
 * the chosen_items array).  Otherwise, all items chosen will only be tallied
 * (symbol frequencies tallied in c->freqs).
 */
static void
lzx_optim_pass(struct lzx_compressor *c, struct lzx_item **next_chosen_item)
{
	const u8 *block_end;
	struct lzx_lru_queue *begin_queue;
	const u8 *window_ptr;
	struct lzx_mc_pos_data *cur_optimum_ptr;
	struct lzx_mc_pos_data *end_optimum_ptr;
	const struct lz_match *matches;
	unsigned num_matches;
	unsigned longest_len;
	unsigned rep_max_len;
	unsigned rep_max_idx;
	unsigned literal;
	unsigned len;
	u32 cost;
	u32 offset_data;

	block_end = &c->cur_window[c->match_window_end];
	begin_queue = &c->queue;
begin:
	/* Start building a new list of items, which will correspond to the next
	 * piece of the overall minimum-cost path.
	 *
	 * *begin_queue is the current state of the match offset LRU queue.  */

	window_ptr = &c->cur_window[c->match_window_pos];

	if (window_ptr == block_end) {
		c->queue = *begin_queue;
		return;
	}

	cur_optimum_ptr = c->optimum;
	cur_optimum_ptr->cost = 0;
	cur_optimum_ptr->queue = *begin_queue;

	end_optimum_ptr = cur_optimum_ptr;

	/* The following loop runs once for each per byte in the window, except
	 * in a couple shortcut cases.  */
	for (;;) {

		/* Find explicit offset matches with the current position.  */
		num_matches = lzx_get_matches(c, &matches);

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
			rep_max_len = lzx_repsearch(window_ptr,
						    block_end - window_ptr,
						    &cur_optimum_ptr->queue,
						    &rep_max_idx);

			if (rep_max_len) {
				/* If there's a very long repeat offset match,
				 * choose it immediately.  */
				if (rep_max_len >= c->params.nice_match_length) {

					swap(cur_optimum_ptr->queue.R[0],
					     cur_optimum_ptr->queue.R[rep_max_idx]);
					begin_queue = &cur_optimum_ptr->queue;

					cur_optimum_ptr += rep_max_len;
					cur_optimum_ptr->mc_item_data =
						(rep_max_idx << MC_OFFSET_SHIFT) |
						rep_max_len;

					lzx_skip_bytes(c, rep_max_len - 1);
					break;
				}

				/* If reaching any positions for the first time,
				 * initialize their costs to "infinity".  */
				while (end_optimum_ptr < cur_optimum_ptr + rep_max_len)
					(++end_optimum_ptr)->cost = MC_INFINITE_COST;

				/* Consider coding a repeat offset match.  */
				lzx_consider_repeat_offset_match(c,
								 cur_optimum_ptr,
								 rep_max_len,
								 rep_max_idx);
			}

			longest_len = matches[num_matches - 1].len;

			/* If there's a very long explicit offset match, choose
			 * it immediately.  */
			if (longest_len >= c->params.nice_match_length) {

				cur_optimum_ptr->queue.R[2] =
					cur_optimum_ptr->queue.R[1];
				cur_optimum_ptr->queue.R[1] =
					cur_optimum_ptr->queue.R[0];
				cur_optimum_ptr->queue.R[0] =
					matches[num_matches - 1].offset;
				begin_queue = &cur_optimum_ptr->queue;

				offset_data = matches[num_matches - 1].offset +
					      LZX_OFFSET_OFFSET;
				cur_optimum_ptr += longest_len;
				cur_optimum_ptr->mc_item_data =
					(offset_data << MC_OFFSET_SHIFT) |
					longest_len;

				lzx_skip_bytes(c, longest_len - 1);
				break;
			}

			/* If reaching any positions for the first time,
			 * initialize their costs to "infinity".  */
			while (end_optimum_ptr < cur_optimum_ptr + longest_len)
				(++end_optimum_ptr)->cost = MC_INFINITE_COST;

			/* Consider coding an explicit offset match.  */
			lzx_consider_explicit_offset_matches(c, cur_optimum_ptr,
							     matches, num_matches);
		} else {
			/* No matches found.  The only choice at this position
			 * is to code a literal.  */

			if (end_optimum_ptr == cur_optimum_ptr) {
			#if 1
				/* Optimization for single literals.  */
				if (likely(cur_optimum_ptr == c->optimum)) {
					lzx_declare_literal(c, *window_ptr++,
							    next_chosen_item);
					if (window_ptr == block_end) {
						c->queue = cur_optimum_ptr->queue;
						return;
					}
					continue;
				}
			#endif
				(++end_optimum_ptr)->cost = MC_INFINITE_COST;
			}
		}

		/* Consider coding a literal.

		 * To avoid an extra unpredictable brench, actually checking the
		 * preferability of coding a literal is integrated into the
		 * queue update code below.  */
		literal = *window_ptr++;
		cost = cur_optimum_ptr->cost + lzx_literal_cost(literal, &c->costs);

		/* Advance to the next position.  */
		cur_optimum_ptr++;

		/* The lowest-cost path to the current position is now known.
		 * Finalize the recent offsets queue that results from taking
		 * this lowest-cost path.  */

		if (cost < cur_optimum_ptr->cost) {
			/* Literal: queue remains unchanged.  */
			cur_optimum_ptr->cost = cost;
			cur_optimum_ptr->mc_item_data = (literal << MC_OFFSET_SHIFT) | 1;
			cur_optimum_ptr->queue = (cur_optimum_ptr - 1)->queue;
		} else {
			/* Match: queue update is needed.  */
			len = cur_optimum_ptr->mc_item_data & MC_LEN_MASK;
			offset_data = cur_optimum_ptr->mc_item_data >> MC_OFFSET_SHIFT;
			if (offset_data >= LZX_NUM_RECENT_OFFSETS) {
				/* Explicit offset match: offset is inserted at front  */
				cur_optimum_ptr->queue.R[0] = offset_data - LZX_OFFSET_OFFSET;
				cur_optimum_ptr->queue.R[1] = (cur_optimum_ptr - len)->queue.R[0];
				cur_optimum_ptr->queue.R[2] = (cur_optimum_ptr - len)->queue.R[1];
			} else {
				/* Repeat offset match: offset is swapped to front  */
				cur_optimum_ptr->queue = (cur_optimum_ptr - len)->queue;
				swap(cur_optimum_ptr->queue.R[0],
				     cur_optimum_ptr->queue.R[offset_data]);
			}
		}

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
		 * (2) cur_optimum_ptr == &c->optimum[LZX_OPTIM_ARRAY_LENGTH]
		 *
		 *	This bounds the number of times the algorithm can step
		 *	forward before it is guaranteed to start choosing items.
		 *	This limits the memory usage.  But
		 *	LZX_OPTIM_ARRAY_LENGTH is high enough that on most
		 *	inputs this limit is never reached.
		 *
		 * Note: no check for end-of-block is needed because
		 * end-of-block will trigger condition (1).
		 */
		if (cur_optimum_ptr == end_optimum_ptr ||
		    cur_optimum_ptr == &c->optimum[LZX_OPTIM_ARRAY_LENGTH])
		{
			begin_queue = &cur_optimum_ptr->queue;
			break;
		}
	}

	/* Choose the current list of items that constitute the minimum-cost
	 * path to the current position.  */
	lzx_declare_item_list(c, cur_optimum_ptr, next_chosen_item);
	goto begin;
}

/* Fast heuristic scoring for lazy parsing: how "good" is this match?  */
static inline unsigned
lzx_explicit_offset_match_score(unsigned len, u32 adjusted_offset)
{
	unsigned score = len;

	if (adjusted_offset < 2048)
		score++;

	if (adjusted_offset < 1024)
		score++;

	return score;
}

static inline unsigned
lzx_repeat_offset_match_score(unsigned len, unsigned slot)
{
	return len + 3;
}

/* Lazy parsing  */
static u32
lzx_choose_lazy_items_for_block(struct lzx_compressor *c,
				u32 block_start_pos, u32 block_size)
{
	const u8 *window_ptr;
	const u8 *block_end;
	struct lz_mf *mf;
	struct lz_match *matches;
	unsigned num_matches;
	unsigned cur_len;
	u32 cur_offset_data;
	unsigned cur_score;
	unsigned rep_max_len;
	unsigned rep_max_idx;
	unsigned rep_score;
	unsigned prev_len;
	unsigned prev_score;
	u32 prev_offset_data;
	unsigned skip_len;
	struct lzx_item *next_chosen_item;

	window_ptr = &c->cur_window[block_start_pos];
	block_end = window_ptr + block_size;
	matches = c->cached_matches;
	mf = c->mf;
	next_chosen_item = c->chosen_items;

	prev_len = 0;
	prev_offset_data = 0;
	prev_score = 0;

	while (window_ptr != block_end) {

		/* Find explicit offset matches with the current position.  */
		num_matches = lz_mf_get_matches(mf, matches);
		window_ptr++;

		if (num_matches == 0 ||
		    (matches[num_matches - 1].len == 3 &&
		     matches[num_matches - 1].offset >= 8192 - LZX_OFFSET_OFFSET &&
		     matches[num_matches - 1].offset != c->queue.R[0] &&
		     matches[num_matches - 1].offset != c->queue.R[1] &&
		     matches[num_matches - 1].offset != c->queue.R[2]))
		{
			/* No match found, or the only match found was a distant
			 * length 3 match.  Output the previous match if there
			 * is one; otherwise output a literal.  */

		no_match_found:

			if (prev_len) {
				skip_len = prev_len - 2;
				goto output_prev_match;
			} else {
				lzx_declare_literal(c, *(window_ptr - 1),
						    &next_chosen_item);
				continue;
			}
		}

		/* Find the longest repeat offset match with the current
		 * position.  */
		if (likely(block_end - (window_ptr - 1) >= 2)) {
			rep_max_len = lzx_repsearch((window_ptr - 1),
						    block_end - (window_ptr - 1),
						    &c->queue, &rep_max_idx);
		} else {
			rep_max_len = 0;
		}

		cur_len = matches[num_matches - 1].len;
		cur_offset_data = matches[num_matches - 1].offset + LZX_OFFSET_OFFSET;
		cur_score = lzx_explicit_offset_match_score(cur_len, cur_offset_data);

		/* Select the better of the explicit and repeat offset matches.  */
		if (rep_max_len >= 3 &&
		    (rep_score = lzx_repeat_offset_match_score(rep_max_len,
							       rep_max_idx)) >= cur_score)
		{
			cur_len = rep_max_len;
			cur_offset_data = rep_max_idx;
			cur_score = rep_score;
		}

		if (unlikely(cur_len > block_end - (window_ptr - 1))) {
			/* Nearing end of block.  */
			cur_len = block_end - (window_ptr - 1);
			if (cur_len < 3)
				goto no_match_found;
		}

		if (prev_len == 0 || cur_score > prev_score) {
			/* No previous match, or the current match is better
			 * than the previous match.
			 *
			 * If there's a previous match, then output a literal in
			 * its place.
			 *
			 * In both cases, if the current match is very long,
			 * then output it immediately.  Otherwise, attempt a
			 * lazy match by waiting to see if there's a better
			 * match at the next position.  */

			if (prev_len)
				lzx_declare_literal(c, *(window_ptr - 2), &next_chosen_item);

			prev_len = cur_len;
			prev_offset_data = cur_offset_data;
			prev_score = cur_score;

			if (prev_len >= c->params.nice_match_length) {
				skip_len = prev_len - 1;
				goto output_prev_match;
			}
			continue;
		}

		/* Current match is not better than the previous match, so
		 * output the previous match.  */

		skip_len = prev_len - 2;

	output_prev_match:
		if (prev_offset_data < LZX_NUM_RECENT_OFFSETS) {
			lzx_declare_repeat_offset_match(c, prev_len,
							prev_offset_data,
							&next_chosen_item);
			swap(c->queue.R[0], c->queue.R[prev_offset_data]);
		} else {
			lzx_declare_explicit_offset_match(c, prev_len,
							  prev_offset_data - LZX_OFFSET_OFFSET,
							  &next_chosen_item);
			c->queue.R[2] = c->queue.R[1];
			c->queue.R[1] = c->queue.R[0];
			c->queue.R[0] = prev_offset_data - LZX_OFFSET_OFFSET;
		}
		lz_mf_skip_positions(mf, skip_len);
		window_ptr += skip_len;
		prev_len = 0;
	}

	return next_chosen_item - c->chosen_items;
}

/* Given the frequencies of symbols in an LZX-compressed block and the
 * corresponding Huffman codes, return LZX_BLOCKTYPE_ALIGNED or
 * LZX_BLOCKTYPE_VERBATIM if an aligned offset or verbatim block, respectively,
 * will take fewer bits to output.  */
static int
lzx_choose_verbatim_or_aligned(const struct lzx_freqs * freqs,
			       const struct lzx_codes * codes)
{
	u32 aligned_cost = 0;
	u32 verbatim_cost = 0;

	/* A verbatim block requires 3 bits in each place that an aligned symbol
	 * would be used in an aligned offset block.  */
	for (unsigned i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
		verbatim_cost += 3 * freqs->aligned[i];
		aligned_cost += codes->lens.aligned[i] * freqs->aligned[i];
	}

	/* Account for output of the aligned offset code.  */
	aligned_cost += LZX_ALIGNEDCODE_ELEMENT_SIZE * LZX_ALIGNEDCODE_NUM_SYMBOLS;

	if (aligned_cost < verbatim_cost)
		return LZX_BLOCKTYPE_ALIGNED;
	else
		return LZX_BLOCKTYPE_VERBATIM;
}

/* Near-optimal parsing  */
static u32
lzx_choose_near_optimal_items_for_block(struct lzx_compressor *c,
					u32 block_start_pos, u32 block_size)
{
	u32 num_passes_remaining = c->params.num_optim_passes;
	struct lzx_lru_queue orig_queue;
	struct lzx_item *next_chosen_item;
	struct lzx_item **next_chosen_item_ptr;

	/* Choose appropriate match-finder wrapper functions.  */
	if (num_passes_remaining > 1) {
		if (block_size == c->cur_window_size)
			c->get_matches_func = lzx_get_matches_fillcache_singleblock;
		else
			c->get_matches_func = lzx_get_matches_fillcache_multiblock;
		c->skip_bytes_func = lzx_skip_bytes_fillcache;
	} else {
		if (block_size == c->cur_window_size)
			c->get_matches_func = lzx_get_matches_nocache_singleblock;
		else
			c->get_matches_func = lzx_get_matches_nocache_multiblock;
		c->skip_bytes_func = lzx_skip_bytes_nocache;
	}

	/* No matches will extend beyond the end of the block.  */
	c->match_window_end = block_start_pos + block_size;

	/* The first optimization pass will use a default cost model.  Each
	 * additional optimization pass will use a cost model computed from the
	 * previous pass.
	 *
	 * To improve performance we only generate the array containing the
	 * matches and literals in intermediate form on the final pass.  For
	 * earlier passes, tallying symbol frequencies is sufficient.  */
	lzx_set_default_costs(&c->costs, c->num_main_syms);

	next_chosen_item_ptr = NULL;
	orig_queue = c->queue;
	do {
		/* Reset the match-finder wrapper.  */
		c->match_window_pos = block_start_pos;
		c->cache_ptr = c->cached_matches;

		if (num_passes_remaining == 1) {
			/* Last pass: actually generate the items.  */
			next_chosen_item = c->chosen_items;
			next_chosen_item_ptr = &next_chosen_item;
		}

		/* Choose the items.  */
		lzx_optim_pass(c, next_chosen_item_ptr);

		if (num_passes_remaining > 1) {
			/* This isn't the last pass.  */

			/* Make the Huffman codes from the symbol frequencies.  */
			lzx_make_huffman_codes(&c->freqs, &c->codes[c->codes_index],
					       c->num_main_syms);

			/* Update symbol costs.  */
			lzx_set_costs(c, &c->codes[c->codes_index].lens);

			/* Reset symbol frequencies.  */
			memset(&c->freqs, 0, sizeof(c->freqs));

			/* Reset the match offset LRU queue to what it was at
			 * the beginning of the block.  */
			c->queue = orig_queue;

			/* Choose appopriate match-finder wrapper functions.  */
			if (c->cache_ptr <= c->cache_limit) {
				c->get_matches_func = lzx_get_matches_usecache_nocheck;
				c->skip_bytes_func = lzx_skip_bytes_usecache_nocheck;
			} else {
				c->get_matches_func = lzx_get_matches_usecache;
				c->skip_bytes_func = lzx_skip_bytes_usecache;
			}
		}
	} while (--num_passes_remaining);

	/* Return the number of items chosen.  */
	return next_chosen_item - c->chosen_items;
}

/*
 * Choose the matches/literals with which to output the block of data beginning
 * at '&c->cur_window[block_start_pos]' and extending for 'block_size' bytes.
 *
 * The frequences of the Huffman symbols in the block will be tallied in
 * 'c->freqs'.
 *
 * 'c->queue' must specify the state of the queue at the beginning of this block.
 * This function will update it to the state of the queue at the end of this
 * block.
 *
 * Returns the number of matches/literals that were chosen and written to
 * 'c->chosen_items' in the 'struct lzx_item' intermediate representation.
 */
static u32
lzx_choose_items_for_block(struct lzx_compressor *c,
			   u32 block_start_pos, u32 block_size)
{
	return (*c->params.choose_items_for_block)(c, block_start_pos, block_size);
}

/* Initialize c->offset_slot_fast.  */
static void
lzx_init_offset_slot_fast(struct lzx_compressor *c)
{
	u8 slot = 0;

	for (u32 offset = 0; offset < LZX_NUM_FAST_OFFSETS; offset++) {

		while (offset + LZX_OFFSET_OFFSET >= lzx_offset_slot_base[slot + 1])
			slot++;

		c->offset_slot_fast[offset] = slot;
	}
}

/* Set internal compression parameters for the specified compression level and
 * maximum window size.  */
static void
lzx_build_params(unsigned int compression_level, u32 max_window_size,
		 struct lzx_compressor_params *lzx_params)
{
	if (compression_level < 25) {

		/* Fast compression: Use lazy parsing.  */

		lzx_params->choose_items_for_block = lzx_choose_lazy_items_for_block;
		lzx_params->num_optim_passes = 1;

		/* When lazy parsing, the hash chain match-finding algorithm is
		 * fastest unless the window is too large.
		 *
		 * TODO: something like hash arrays would actually be better
		 * than binary trees on large windows.  */
		if (max_window_size <= 262144)
			lzx_params->mf_algo = LZ_MF_HASH_CHAINS;
		else
			lzx_params->mf_algo = LZ_MF_BINARY_TREES;

		/* When lazy parsing, don't bother with length 2 matches.  */
		lzx_params->min_match_length = 3;

		/* Scale nice_match_length and max_search_depth with the
		 * compression level.  */
		lzx_params->nice_match_length = 25 + compression_level * 2;
		lzx_params->max_search_depth = 25 + compression_level;
	} else {

		/* Normal / high compression: Use near-optimal parsing.  */

		lzx_params->choose_items_for_block = lzx_choose_near_optimal_items_for_block;

		/* Set a number of optimization passes appropriate for the
		 * compression level.  */

		lzx_params->num_optim_passes = 1;

		if (compression_level >= 40)
			lzx_params->num_optim_passes++;

		/* Use more optimization passes for higher compression levels.
		 * But the more passes there are, the less they help --- so
		 * don't add them linearly.  */
		if (compression_level >= 70) {
			lzx_params->num_optim_passes++;
			if (compression_level >= 100)
				lzx_params->num_optim_passes++;
			if (compression_level >= 150)
				lzx_params->num_optim_passes++;
			if (compression_level >= 200)
				lzx_params->num_optim_passes++;
			if (compression_level >= 300)
				lzx_params->num_optim_passes++;
		}

		/* When doing near-optimal parsing, the hash chain match-finding
		 * algorithm is good if the window size is small and we're only
		 * doing one optimization pass.  Otherwise, the binary tree
		 * algorithm is the way to go.  */
		if (max_window_size <= 32768 && lzx_params->num_optim_passes == 1)
			lzx_params->mf_algo = LZ_MF_HASH_CHAINS;
		else
			lzx_params->mf_algo = LZ_MF_BINARY_TREES;

		/* When doing near-optimal parsing, allow length 2 matches if
		 * the compression level is sufficiently high.  */
		if (compression_level >= 45)
			lzx_params->min_match_length = 2;
		else
			lzx_params->min_match_length = 3;

		/* Scale nice_match_length and max_search_depth with the
		 * compression level.  */
		lzx_params->nice_match_length = min(((u64)compression_level * 32) / 50,
						    LZX_MAX_MATCH_LEN);
		lzx_params->max_search_depth = min(((u64)compression_level * 50) / 50,
						   LZX_MAX_MATCH_LEN);
	}
}

/* Given the internal compression parameters and maximum window size, build the
 * Lempel-Ziv match-finder parameters.  */
static void
lzx_build_mf_params(const struct lzx_compressor_params *lzx_params,
		    u32 max_window_size, struct lz_mf_params *mf_params)
{
	memset(mf_params, 0, sizeof(*mf_params));

	mf_params->algorithm = lzx_params->mf_algo;
	mf_params->max_window_size = max_window_size;
	mf_params->min_match_len = lzx_params->min_match_length;
	mf_params->max_match_len = LZX_MAX_MATCH_LEN;
	mf_params->max_search_depth = lzx_params->max_search_depth;
	mf_params->nice_match_len = lzx_params->nice_match_length;
}

static void
lzx_free_compressor(void *_c);

static u64
lzx_get_needed_memory(size_t max_block_size, unsigned int compression_level)
{
	struct lzx_compressor_params params;
	u64 size = 0;
	unsigned window_order;
	u32 max_window_size;

	window_order = lzx_get_window_order(max_block_size);
	if (window_order == 0)
		return 0;
	max_window_size = max_block_size;

	lzx_build_params(compression_level, max_window_size, &params);

	size += sizeof(struct lzx_compressor);

	/* cur_window */
	size += max_window_size;

	/* mf */
	size += lz_mf_get_needed_memory(params.mf_algo, max_window_size);

	/* cached_matches */
	if (params.num_optim_passes > 1)
		size += LZX_CACHE_LEN * sizeof(struct lz_match);
	else
		size += LZX_MAX_MATCHES_PER_POS * sizeof(struct lz_match);
	return size;
}

static int
lzx_create_compressor(size_t max_block_size, unsigned int compression_level,
		      void **c_ret)
{
	struct lzx_compressor *c;
	struct lzx_compressor_params params;
	struct lz_mf_params mf_params;
	unsigned window_order;
	u32 max_window_size;

	window_order = lzx_get_window_order(max_block_size);
	if (window_order == 0)
		return WIMLIB_ERR_INVALID_PARAM;
	max_window_size = max_block_size;

	lzx_build_params(compression_level, max_window_size, &params);
	lzx_build_mf_params(&params, max_window_size, &mf_params);
	if (!lz_mf_params_valid(&mf_params))
		return WIMLIB_ERR_INVALID_PARAM;

	c = CALLOC(1, sizeof(struct lzx_compressor));
	if (!c)
		goto oom;

	c->params = params;
	c->num_main_syms = lzx_get_num_main_syms(window_order);
	c->window_order = window_order;

	/* The window is allocated as 16-byte aligned to speed up memcpy() and
	 * enable lzx_e8_filter() optimization on x86_64.  */
	c->cur_window = ALIGNED_MALLOC(max_window_size, 16);
	if (!c->cur_window)
		goto oom;

	c->mf = lz_mf_alloc(&mf_params);
	if (!c->mf)
		goto oom;

	if (params.num_optim_passes > 1) {
		c->cached_matches = MALLOC(LZX_CACHE_LEN *
					   sizeof(struct lz_match));
		if (!c->cached_matches)
			goto oom;
		c->cache_limit = c->cached_matches + LZX_CACHE_LEN -
				 (LZX_MAX_MATCHES_PER_POS + 1);
	} else {
		c->cached_matches = MALLOC(LZX_MAX_MATCHES_PER_POS *
					   sizeof(struct lz_match));
		if (!c->cached_matches)
			goto oom;
	}

	lzx_init_offset_slot_fast(c);

	*c_ret = c;
	return 0;

oom:
	lzx_free_compressor(c);
	return WIMLIB_ERR_NOMEM;
}

static size_t
lzx_compress(const void *uncompressed_data, size_t uncompressed_size,
	     void *compressed_data, size_t compressed_size_avail, void *_c)
{
	struct lzx_compressor *c = _c;
	struct lzx_output_bitstream os;
	u32 num_chosen_items;
	const struct lzx_lens *prev_lens;
	u32 block_start_pos;
	u32 block_size;
	int block_type;

	/* Don't bother compressing very small inputs.  */
	if (uncompressed_size < 100)
		return 0;

	/* The input data must be preprocessed.  To avoid changing the original
	 * input data, copy it to a temporary buffer.  */
	memcpy(c->cur_window, uncompressed_data, uncompressed_size);
	c->cur_window_size = uncompressed_size;

	/* Preprocess the data.  */
	lzx_do_e8_preprocessing(c->cur_window, c->cur_window_size);

	/* Load the window into the match-finder.  */
	lz_mf_load_window(c->mf, c->cur_window, c->cur_window_size);

	/* Initialize the match offset LRU queue.  */
	lzx_lru_queue_init(&c->queue);

	/* Initialize the output bitstream.  */
	lzx_init_output(&os, compressed_data, compressed_size_avail);

	/* Compress the data block by block.
	 *
	 * TODO: The compression ratio could be slightly improved by performing
	 * data-dependent block splitting instead of using fixed-size blocks.
	 * Doing so well is a computationally hard problem, however.  */
	block_start_pos = 0;
	c->codes_index = 0;
	prev_lens = &c->zero_lens;
	do {
		/* Compute the block size.  */
		block_size = min(LZX_DIV_BLOCK_SIZE,
				 uncompressed_size - block_start_pos);

		/* Reset symbol frequencies.  */
		memset(&c->freqs, 0, sizeof(c->freqs));

		/* Prepare the matches/literals for the block.  */
		num_chosen_items = lzx_choose_items_for_block(c,
							      block_start_pos,
							      block_size);

		/* Make the Huffman codes from the symbol frequencies.  */
		lzx_make_huffman_codes(&c->freqs, &c->codes[c->codes_index],
				       c->num_main_syms);

		/* Choose the best block type.
		 *
		 * Note: we currently don't consider uncompressed blocks.  */
		block_type = lzx_choose_verbatim_or_aligned(&c->freqs,
							    &c->codes[c->codes_index]);

		/* Write the compressed block to the output buffer.  */
		lzx_write_compressed_block(block_type,
					   block_size,
					   c->window_order,
					   c->num_main_syms,
					   c->chosen_items,
					   num_chosen_items,
					   &c->codes[c->codes_index],
					   prev_lens,
					   &os);

		/* The current codeword lengths become the previous lengths.  */
		prev_lens = &c->codes[c->codes_index].lens;
		c->codes_index ^= 1;

		block_start_pos += block_size;

	} while (block_start_pos != uncompressed_size);

	return lzx_flush_output(&os);
}

static void
lzx_free_compressor(void *_c)
{
	struct lzx_compressor *c = _c;

	if (c) {
		ALIGNED_FREE(c->cur_window);
		lz_mf_free(c->mf);
		FREE(c->cached_matches);
		FREE(c);
	}
}

const struct compressor_ops lzx_compressor_ops = {
	.get_needed_memory  = lzx_get_needed_memory,
	.create_compressor  = lzx_create_compressor,
	.compress	    = lzx_compress,
	.free_compressor    = lzx_free_compressor,
};
