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
 * This file contains a compressor for the LZX ("Lempel-Ziv eXtended"?)
 * compression format, as used in the WIM (Windows IMaging) file format.  This
 * code may need some slight modifications to be used outside of the WIM format.
 * In particular, in other situations the LZX block header might be slightly
 * different, and a sliding window rather than a fixed-size window might be
 * required.
 *
 * ----------------------------------------------------------------------------
 *
 *				 Format Overview
 *
 * The primary reference for LZX is the specification released by Microsoft.
 * However, the comments in lzx-decompress.c provide more information about LZX
 * and note some errors in the Microsoft specification.
 *
 * LZX shares many similarities with DEFLATE, the format used by zlib and gzip.
 * Both LZX and DEFLATE use LZ77 matching and Huffman coding.  Certain details
 * are quite similar, such as the method for storing Huffman codes.  However,
 * the main differences are:
 *
 * - LZX preprocesses the data to attempt to make x86 machine code slightly more
 *   compressible before attempting to compress it further.
 *
 * - LZX uses a "main" alphabet which combines literals and matches, with the
 *   match symbols containing a "length header" (giving all or part of the match
 *   length) and a "position slot" (giving, roughly speaking, the order of
 *   magnitude of the match offset).
 *
 * - LZX does not have static Huffman blocks (that is, the kind with preset
 *   Huffman codes); however it does have two types of dynamic Huffman blocks
 *   ("verbatim" and "aligned").
 *
 * - LZX has a minimum match length of 2 rather than 3.
 *
 * - In LZX, match offsets 0 through 2 actually represent entries in an LRU
 *   queue of match offsets.  This is very useful for certain types of files,
 *   such as binary files that have repeating records.
 *
 * ----------------------------------------------------------------------------
 *
 *			      Algorithmic Overview
 *
 * At a high level, any implementation of LZX compression must operate as
 * follows:
 *
 * 1. Preprocess the input data to translate the targets of 32-bit x86 call
 *    instructions to absolute offsets.  (Actually, this is required for WIM,
 *    but might not be in other places LZX is used.)
 *
 * 2. Find a sequence of LZ77-style matches and literal bytes that expands to
 *    the preprocessed data.
 *
 * 3. Divide the match/literal sequence into one or more LZX blocks, each of
 *    which may be "uncompressed", "verbatim", or "aligned".
 *
 * 4. Output each LZX block.
 *
 * Step (1) is fairly straightforward.  It requires looking for 0xe8 bytes in
 * the input data and performing a translation on the 4 bytes following each
 * one.
 *
 * Step (4) is complicated, but it is mostly determined by the LZX format.  The
 * only real choice we have is what algorithm to use to build the length-limited
 * canonical Huffman codes.  See lzx_write_all_blocks() for details.
 *
 * That leaves steps (2) and (3) as where all the hard stuff happens.  Focusing
 * on step (2), we need to do LZ77-style parsing on the input data, or "window",
 * to divide it into a sequence of matches and literals.  Each position in the
 * window might have multiple matches associated with it, and we need to choose
 * which one, if any, to actually use.  Therefore, the problem can really be
 * divided into two areas of concern: (a) finding matches at a given position,
 * which we shall call "match-finding", and (b) choosing whether to use a
 * match or a literal at a given position, and if using a match, which one (if
 * there is more than one available).  We shall call this "match-choosing".  We
 * first consider match-finding, then match-choosing.
 *
 * ----------------------------------------------------------------------------
 *
 *				 Match-finding
 *
 * Given a position in the window, we want to find LZ77-style "matches" with
 * that position at previous positions in the window.  With LZX, the minimum
 * match length is 2 and the maximum match length is 257.  The only restriction
 * on offsets is that LZX does not allow the last 2 bytes of the window to match
 * the beginning of the window.
 *
 * There are a number of algorithms that can be used for this, including hash
 * chains, binary trees, and suffix arrays.  Binary trees generally work well
 * for LZX compression since it uses medium-size windows (2^15 to 2^21 bytes).
 * However, when compressing in a fast mode where many positions are skipped
 * (not searched for matches), hash chains are faster.
 *
 * Since the match-finders are not specific to LZX, I will not explain them in
 * detail here.  Instead, see lz_hash_chains.c and lz_binary_trees.c.
 *
 * ----------------------------------------------------------------------------
 *
 *				 Match-choosing
 *
 * Usually, choosing the longest match is best because it encodes the most data
 * in that one item.  However, sometimes the longest match is not optimal
 * because (a) choosing a long match now might prevent using an even longer
 * match later, or (b) more generally, what we actually care about is the number
 * of bits it will ultimately take to output each match or literal, which is
 * actually dependent on the entropy encoding using by the underlying
 * compression format.  Consequently, a longer match usually, but not always,
 * takes fewer bits to encode than multiple shorter matches or literals that
 * cover the same data.
 *
 * This problem of choosing the truly best match/literal sequence is probably
 * impossible to solve efficiently when combined with entropy encoding.  If we
 * knew how many bits it takes to output each match/literal, then we could
 * choose the optimal sequence using shortest-path search a la Dijkstra's
 * algorithm.  However, with entropy encoding, the chosen match/literal sequence
 * affects its own encoding.  Therefore, we can't know how many bits it will
 * take to actually output any one match or literal until we have actually
 * chosen the full sequence of matches and literals.
 *
 * Notwithstanding the entropy encoding problem, we also aren't guaranteed to
 * choose the optimal match/literal sequence unless the match-finder (see
 * section "Match-finder") provides the match-chooser with all possible matches
 * at each position.  However, this is not computationally efficient.  For
 * example, there might be many matches of the same length, and usually (but not
 * always) the best choice is the one with the smallest offset.  So in practice,
 * it's fine to only consider the smallest offset for a given match length at a
 * given position.  (Actually, for LZX, it's also worth considering repeat
 * offsets.)
 *
 * In addition, as mentioned earlier, in LZX we have the choice of using
 * multiple blocks, each of which resets the Huffman codes.  This expands the
 * search space even further.  Therefore, to simplify the problem, we currently
 * we don't attempt to actually choose the LZX blocks based on the data.
 * Instead, we just divide the data into fixed-size blocks of LZX_DIV_BLOCK_SIZE
 * bytes each, and always use verbatim or aligned blocks (never uncompressed).
 * A previous version of this code recursively split the input data into
 * equal-sized blocks, up to a maximum depth, and chose the lowest-cost block
 * divisions.  However, this made compression much slower and did not actually
 * help very much.  It remains an open question whether a sufficiently fast and
 * useful block-splitting algorithm is possible for LZX.  Essentially the same
 * problem also applies to DEFLATE.  The Microsoft LZX compressor seemingly does
 * do block splitting, although I don't know how fast or useful it is,
 * specifically.
 *
 * Now, back to the entropy encoding problem.  The "solution" is to use an
 * iterative approach to compute a good, but not necessarily optimal,
 * match/literal sequence.  Start with a fixed assignment of symbol costs and
 * choose an "optimal" match/literal sequence based on those costs, using
 * shortest-path seach a la Dijkstra's algorithm.  Then, for each iteration of
 * the optimization, update the costs based on the entropy encoding of the
 * current match/literal sequence, then choose a new match/literal sequence
 * based on the updated costs.  Usually, the actual cost to output the current
 * match/literal sequence will decrease in each iteration until it converges on
 * a fixed point.  This result may not be the truly optimal match/literal
 * sequence, but it usually is much better than one chosen by doing a "greedy"
 * parse where we always chooe the longest match.
 *
 * An alternative to both greedy parsing and iterative, near-optimal parsing is
 * "lazy" parsing.  Briefly, "lazy" parsing considers just the longest match at
 * each position, but it waits to choose that match until it has also examined
 * the next position.  This is actually a useful approach; it's used by zlib,
 * for example.  Therefore, for fast compression we combine lazy parsing with
 * the hash chain max-finder.  For normal/high compression we combine
 * near-optimal parsing with the binary tree match-finder.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/compressor_ops.h"
#include "wimlib/compress_common.h"
#include "wimlib/error.h"
#include "wimlib/lz_mf.h"
#include "wimlib/lzx.h"
#include "wimlib/util.h"
#include <string.h>

#define LZX_OPTIM_ARRAY_LENGTH	4096

#define LZX_DIV_BLOCK_SIZE	32768

#define LZX_CACHE_PER_POS	8

#define LZX_MAX_MATCHES_PER_POS	(LZX_MAX_MATCH_LEN - LZX_MIN_MATCH_LEN + 1)

#define LZX_CACHE_LEN (LZX_DIV_BLOCK_SIZE * (LZX_CACHE_PER_POS + 1))

/* Codewords for the LZX main, length, and aligned offset Huffman codes  */
struct lzx_codewords {
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u32 len[LZX_LENCODE_NUM_SYMBOLS];
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Codeword lengths (in bits) for the LZX main, length, and aligned offset
 * Huffman codes.
 *
 * A 0 length means the codeword has zero frequency.
 */
struct lzx_lens {
	u8 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u8 len[LZX_LENCODE_NUM_SYMBOLS];
	u8 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Costs for the LZX main, length, and aligned offset Huffman symbols.
 *
 * If a codeword has zero frequency, it must still be assigned some nonzero cost
 * --- generally a high cost, since even if it gets used in the next iteration,
 * it probably will not be used very many times.  */
struct lzx_costs {
	u8 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u8 len[LZX_LENCODE_NUM_SYMBOLS];
	u8 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* The LZX main, length, and aligned offset Huffman codes  */
struct lzx_codes {
	struct lzx_codewords codewords;
	struct lzx_lens lens;
};

/* Tables for tallying symbol frequencies in the three LZX alphabets  */
struct lzx_freqs {
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u32 len[LZX_LENCODE_NUM_SYMBOLS];
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* LZX intermediate match/literal format  */
struct lzx_item {
	/* Bit     Description
	 *
	 * 31      1 if a match, 0 if a literal.
	 *
	 * 30-25   position slot.  This can be at most 50, so it will fit in 6
	 *         bits.
	 *
	 * 8-24    position footer.  This is the offset of the real formatted
	 *         offset from the position base.  This can be at most 17 bits
	 *         (since lzx_extra_bits[LZX_MAX_POSITION_SLOTS - 1] is 17).
	 *
	 * 0-7     length of match, minus 2.  This can be at most
	 *         (LZX_MAX_MATCH_LEN - 2) == 255, so it will fit in 8 bits.  */
	u32 data;
};

/* Specification for an LZX block.  */
struct lzx_block_spec {

	/* One of the LZX_BLOCKTYPE_* constants indicating which type of this
	 * block.  */
	int block_type;

	/* 0-based position in the window at which this block starts.  */
	u32 window_pos;

	/* The number of bytes of uncompressed data this block represents.  */
	u32 block_size;

	/* The match/literal sequence for this block.  */
	struct lzx_item *chosen_items;

	/* The length of the @chosen_items sequence.  */
	u32 num_chosen_items;

	/* Huffman codes for this block.  */
	struct lzx_codes codes;
};

struct lzx_compressor;

struct lzx_compressor_params {
	struct lz_match (*choose_item_func)(struct lzx_compressor *);
	enum lz_mf_algo mf_algo;
	u32 num_optim_passes;
	u32 min_match_length;
	u32 nice_match_length;
	u32 max_search_depth;
};

/* State of the LZX compressor.  */
struct lzx_compressor {

	/* The buffer of data to be compressed.
	 *
	 * 0xe8 byte preprocessing is done directly on the data here before
	 * further compression.
	 *
	 * Note that this compressor does *not* use a real sliding window!!!!
	 * It's not needed in the WIM format, since every chunk is compressed
	 * independently.  This is by design, to allow random access to the
	 * chunks.  */
	u8 *cur_window;

	/* Number of bytes of data to be compressed, which is the number of
	 * bytes of data in @cur_window that are actually valid.  */
	u32 cur_window_size;

	/* Allocated size of @cur_window.  */
	u32 max_window_size;

	/* Compression parameters.  */
	struct lzx_compressor_params params;

	unsigned (*get_matches_func)(struct lzx_compressor *, const struct lz_match **);
	void (*skip_bytes_func)(struct lzx_compressor *, unsigned n);

	/* Number of symbols in the main alphabet (depends on the
	 * @max_window_size since it determines the maximum allowed offset).  */
	unsigned num_main_syms;

	/* The current match offset LRU queue.  */
	struct lzx_lru_queue queue;

	/* Space for the sequences of matches/literals that were chosen for each
	 * block.  */
	struct lzx_item *chosen_items;

	/* Information about the LZX blocks the preprocessed input was divided
	 * into.  */
	struct lzx_block_spec *block_specs;

	/* Number of LZX blocks the input was divided into; a.k.a. the number of
	 * elements of @block_specs that are valid.  */
	unsigned num_blocks;

	/* This is simply filled in with zeroes and used to avoid special-casing
	 * the output of the first compressed Huffman code, which conceptually
	 * has a delta taken from a code with all symbols having zero-length
	 * codewords.  */
	struct lzx_codes zero_codes;

	/* The current cost model.  */
	struct lzx_costs costs;

	/* Lempel-Ziv match-finder.  */
	struct lz_mf *mf;

	/* Position in window of next match to return.  */
	u32 match_window_pos;

	/* The end-of-block position.  We can't allow any matches to span this
	 * position.  */
	u32 match_window_end;

	/* When doing more than one match-choosing pass over the data, matches
	 * found by the match-finder are cached in the following array to
	 * achieve a slight speedup when the same matches are needed on
	 * subsequent passes.  This is suboptimal because different matches may
	 * be preferred with different cost models, but seems to be a worthwhile
	 * speedup.  */
	struct lz_match *cached_matches;
	struct lz_match *cache_ptr;
	struct lz_match *cache_limit;

	/* Match-chooser state, used when doing near-optimal parsing.
	 *
	 * When matches have been chosen, optimum_cur_idx is set to the position
	 * in the window of the next match/literal to return and optimum_end_idx
	 * is set to the position in the window at the end of the last
	 * match/literal to return.  */
	struct lzx_mc_pos_data *optimum;
	unsigned optimum_cur_idx;
	unsigned optimum_end_idx;

	/* Previous match, used when doing lazy parsing.  */
	struct lz_match prev_match;
};

/*
 * Match chooser position data:
 *
 * An array of these structures is used during the match-choosing algorithm.
 * They correspond to consecutive positions in the window and are used to keep
 * track of the cost to reach each position, and the match/literal choices that
 * need to be chosen to reach that position.
 */
struct lzx_mc_pos_data {
	/* The approximate minimum cost, in bits, to reach this position in the
	 * window which has been found so far.  */
	u32 cost;
#define MC_INFINITE_COST ((u32)~0UL)

	/* The union here is just for clarity, since the fields are used in two
	 * slightly different ways.  Initially, the @prev structure is filled in
	 * first, and links go from later in the window to earlier in the
	 * window.  Later, @next structure is filled in and links go from
	 * earlier in the window to later in the window.  */
	union {
		struct {
			/* Position of the start of the match or literal that
			 * was taken to get to this position in the approximate
			 * minimum-cost parse.  */
			u32 link;

			/* Offset (as in an LZ (length, offset) pair) of the
			 * match or literal that was taken to get to this
			 * position in the approximate minimum-cost parse.  */
			u32 match_offset;
		} prev;
		struct {
			/* Position at which the match or literal starting at
			 * this position ends in the minimum-cost parse.  */
			u32 link;

			/* Offset (as in an LZ (length, offset) pair) of the
			 * match or literal starting at this position in the
			 * approximate minimum-cost parse.  */
			u32 match_offset;
		} next;
	};

	/* Adaptive state that exists after an approximate minimum-cost path to
	 * reach this position is taken.  */
	struct lzx_lru_queue queue;
};

/* Returns the LZX position slot that corresponds to a given match offset,
 * taking into account the recent offset queue and updating it if the offset is
 * found in it.  */
static unsigned
lzx_get_position_slot(u32 offset, struct lzx_lru_queue *queue)
{
	unsigned position_slot;

	/* See if the offset was recently used.  */
	for (int i = 0; i < LZX_NUM_RECENT_OFFSETS; i++) {
		if (offset == queue->R[i]) {
			/* Found it.  */

			/* Bring the repeat offset to the front of the
			 * queue.  Note: this is, in fact, not a real
			 * LRU queue because repeat matches are simply
			 * swapped to the front.  */
			swap(queue->R[0], queue->R[i]);

			/* The resulting position slot is simply the first index
			 * at which the offset was found in the queue.  */
			return i;
		}
	}

	/* The offset was not recently used; look up its real position slot.  */
	position_slot = lzx_get_position_slot_raw(offset + LZX_OFFSET_OFFSET);

	/* Bring the new offset to the front of the queue.  */
	for (int i = LZX_NUM_RECENT_OFFSETS - 1; i > 0; i--)
		queue->R[i] = queue->R[i - 1];
	queue->R[0] = offset;

	return position_slot;
}

/* Build the main, length, and aligned offset Huffman codes used in LZX.
 *
 * This takes as input the frequency tables for each code and produces as output
 * a set of tables that map symbols to codewords and codeword lengths.  */
static void
lzx_make_huffman_codes(const struct lzx_freqs *freqs,
		       struct lzx_codes *codes,
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

/*
 * Output a precomputed LZX match.
 *
 * @out:
 *	The bitstream to which to write the match.
 * @block_type:
 *	The type of the LZX block (LZX_BLOCKTYPE_ALIGNED or
 *	LZX_BLOCKTYPE_VERBATIM)
 * @match:
 *	The match data.
 * @codes:
 *	Pointer to a structure that contains the codewords for the main, length,
 *	and aligned offset Huffman codes for the current LZX compressed block.
 */
static void
lzx_write_match(struct output_bitstream *out, int block_type,
		struct lzx_item match, const struct lzx_codes *codes)
{
	/* low 8 bits are the match length minus 2 */
	unsigned match_len_minus_2 = match.data & 0xff;
	/* Next 17 bits are the position footer */
	unsigned position_footer = (match.data >> 8) & 0x1ffff;	/* 17 bits */
	/* Next 6 bits are the position slot. */
	unsigned position_slot = (match.data >> 25) & 0x3f;	/* 6 bits */
	unsigned len_header;
	unsigned len_footer;
	unsigned main_symbol;
	unsigned num_extra_bits;
	unsigned verbatim_bits;
	unsigned aligned_bits;

	/* If the match length is less than MIN_MATCH_LEN (= 2) +
	 * NUM_PRIMARY_LENS (= 7), the length header contains
	 * the match length minus MIN_MATCH_LEN, and there is no
	 * length footer.
	 *
	 * Otherwise, the length header contains
	 * NUM_PRIMARY_LENS, and the length footer contains
	 * the match length minus NUM_PRIMARY_LENS minus
	 * MIN_MATCH_LEN. */
	if (match_len_minus_2 < LZX_NUM_PRIMARY_LENS) {
		len_header = match_len_minus_2;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_footer = match_len_minus_2 - LZX_NUM_PRIMARY_LENS;
	}

	/* Combine the position slot with the length header into a single symbol
	 * that will be encoded with the main code.
	 *
	 * The actual main symbol is offset by LZX_NUM_CHARS because values
	 * under LZX_NUM_CHARS are used to indicate a literal byte rather than a
	 * match.  */
	main_symbol = ((position_slot << 3) | len_header) + LZX_NUM_CHARS;

	/* Output main symbol. */
	bitstream_put_bits(out, codes->codewords.main[main_symbol],
			   codes->lens.main[main_symbol]);

	/* If there is a length footer, output it using the
	 * length Huffman code. */
	if (len_header == LZX_NUM_PRIMARY_LENS)
		bitstream_put_bits(out, codes->codewords.len[len_footer],
				   codes->lens.len[len_footer]);

	num_extra_bits = lzx_get_num_extra_bits(position_slot);

	/* For aligned offset blocks with at least 3 extra bits, output the
	 * verbatim bits literally, then the aligned bits encoded using the
	 * aligned offset code.  Otherwise, only the verbatim bits need to be
	 * output. */
	if ((block_type == LZX_BLOCKTYPE_ALIGNED) && (num_extra_bits >= 3)) {

		verbatim_bits = position_footer >> 3;
		bitstream_put_bits(out, verbatim_bits,
				   num_extra_bits - 3);

		aligned_bits = (position_footer & 7);
		bitstream_put_bits(out,
				   codes->codewords.aligned[aligned_bits],
				   codes->lens.aligned[aligned_bits]);
	} else {
		/* verbatim bits is the same as the position
		 * footer, in this case. */
		bitstream_put_bits(out, position_footer, num_extra_bits);
	}
}

/* Output an LZX literal (encoded with the main Huffman code).  */
static void
lzx_write_literal(struct output_bitstream *out, u8 literal,
		  const struct lzx_codes *codes)
{
	bitstream_put_bits(out,
			   codes->codewords.main[literal],
			   codes->lens.main[literal]);
}

static unsigned
lzx_build_precode(const u8 lens[restrict],
		  const u8 prev_lens[restrict],
		  const unsigned num_syms,
		  u32 precode_freqs[restrict LZX_PRECODE_NUM_SYMBOLS],
		  u8 output_syms[restrict num_syms],
		  u8 precode_lens[restrict LZX_PRECODE_NUM_SYMBOLS],
		  u32 precode_codewords[restrict LZX_PRECODE_NUM_SYMBOLS],
		  unsigned *num_additional_bits_ret)
{
	memset(precode_freqs, 0,
	       LZX_PRECODE_NUM_SYMBOLS * sizeof(precode_freqs[0]));

	/* Since the code word lengths use a form of RLE encoding, the goal here
	 * is to find each run of identical lengths when going through them in
	 * symbol order (including runs of length 1).  For each run, as many
	 * lengths are encoded using RLE as possible, and the rest are output
	 * literally.
	 *
	 * output_syms[] will be filled in with the length symbols that will be
	 * output, including RLE codes, not yet encoded using the precode.
	 *
	 * cur_run_len keeps track of how many code word lengths are in the
	 * current run of identical lengths.  */
	unsigned output_syms_idx = 0;
	unsigned cur_run_len = 1;
	unsigned num_additional_bits = 0;
	for (unsigned i = 1; i <= num_syms; i++) {

		if (i != num_syms && lens[i] == lens[i - 1]) {
			/* Still in a run--- keep going. */
			cur_run_len++;
			continue;
		}

		/* Run ended! Check if it is a run of zeroes or a run of
		 * nonzeroes. */

		/* The symbol that was repeated in the run--- not to be confused
		 * with the length *of* the run (cur_run_len) */
		unsigned len_in_run = lens[i - 1];

		if (len_in_run == 0) {
			/* A run of 0's.  Encode it in as few length
			 * codes as we can. */

			/* The magic length 18 indicates a run of 20 + n zeroes,
			 * where n is an uncompressed literal 5-bit integer that
			 * follows the magic length. */
			while (cur_run_len >= 20) {
				unsigned additional_bits;

				additional_bits = min(cur_run_len - 20, 0x1f);
				num_additional_bits += 5;
				precode_freqs[18]++;
				output_syms[output_syms_idx++] = 18;
				output_syms[output_syms_idx++] = additional_bits;
				cur_run_len -= 20 + additional_bits;
			}

			/* The magic length 17 indicates a run of 4 + n zeroes,
			 * where n is an uncompressed literal 4-bit integer that
			 * follows the magic length. */
			while (cur_run_len >= 4) {
				unsigned additional_bits;

				additional_bits = min(cur_run_len - 4, 0xf);
				num_additional_bits += 4;
				precode_freqs[17]++;
				output_syms[output_syms_idx++] = 17;
				output_syms[output_syms_idx++] = additional_bits;
				cur_run_len -= 4 + additional_bits;
			}

		} else {

			/* A run of nonzero lengths. */

			/* The magic length 19 indicates a run of 4 + n
			 * nonzeroes, where n is a literal bit that follows the
			 * magic length, and where the value of the lengths in
			 * the run is given by an extra length symbol, encoded
			 * with the precode, that follows the literal bit.
			 *
			 * The extra length symbol is encoded as a difference
			 * from the length of the codeword for the first symbol
			 * in the run in the previous code.
			 * */
			while (cur_run_len >= 4) {
				unsigned additional_bits;
				signed char delta;

				additional_bits = (cur_run_len > 4);
				num_additional_bits += 1;
				delta = (signed char)prev_lens[i - cur_run_len] -
					(signed char)len_in_run;
				if (delta < 0)
					delta += 17;
				precode_freqs[19]++;
				precode_freqs[(unsigned char)delta]++;
				output_syms[output_syms_idx++] = 19;
				output_syms[output_syms_idx++] = additional_bits;
				output_syms[output_syms_idx++] = delta;
				cur_run_len -= 4 + additional_bits;
			}
		}

		/* Any remaining lengths in the run are outputted without RLE,
		 * as a difference from the length of that codeword in the
		 * previous code. */
		while (cur_run_len > 0) {
			signed char delta;

			delta = (signed char)prev_lens[i - cur_run_len] -
				(signed char)len_in_run;
			if (delta < 0)
				delta += 17;

			precode_freqs[(unsigned char)delta]++;
			output_syms[output_syms_idx++] = delta;
			cur_run_len--;
		}

		cur_run_len = 1;
	}

	/* Build the precode from the frequencies of the length symbols. */

	make_canonical_huffman_code(LZX_PRECODE_NUM_SYMBOLS,
				    LZX_MAX_PRE_CODEWORD_LEN,
				    precode_freqs, precode_lens,
				    precode_codewords);

	*num_additional_bits_ret = num_additional_bits;

	return output_syms_idx;
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
 * @out:
 *	Bitstream to which to write the compressed Huffman code.
 * @lens:
 *	The codeword lengths, indexed by symbol, in the Huffman code.
 * @prev_lens:
 *	The codeword lengths, indexed by symbol, in the corresponding Huffman
 *	code in the previous block, or all zeroes if this is the first block.
 * @num_syms:
 *	The number of symbols in the Huffman code.
 */
static void
lzx_write_compressed_code(struct output_bitstream *out,
			  const u8 lens[restrict],
			  const u8 prev_lens[restrict],
			  unsigned num_syms)
{
	u32 precode_freqs[LZX_PRECODE_NUM_SYMBOLS];
	u8 output_syms[num_syms];
	u8 precode_lens[LZX_PRECODE_NUM_SYMBOLS];
	u32 precode_codewords[LZX_PRECODE_NUM_SYMBOLS];
	unsigned i;
	unsigned num_output_syms;
	u8 precode_sym;
	unsigned dummy;

	num_output_syms = lzx_build_precode(lens,
					    prev_lens,
					    num_syms,
					    precode_freqs,
					    output_syms,
					    precode_lens,
					    precode_codewords,
					    &dummy);

	/* Write the lengths of the precode codes to the output. */
	for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++)
		bitstream_put_bits(out, precode_lens[i],
				   LZX_PRECODE_ELEMENT_SIZE);

	/* Write the length symbols, encoded with the precode, to the output. */

	for (i = 0; i < num_output_syms; ) {
		precode_sym = output_syms[i++];

		bitstream_put_bits(out, precode_codewords[precode_sym],
				   precode_lens[precode_sym]);
		switch (precode_sym) {
		case 17:
			bitstream_put_bits(out, output_syms[i++], 4);
			break;
		case 18:
			bitstream_put_bits(out, output_syms[i++], 5);
			break;
		case 19:
			bitstream_put_bits(out, output_syms[i++], 1);
			bitstream_put_bits(out,
					   precode_codewords[output_syms[i]],
					   precode_lens[output_syms[i]]);
			i++;
			break;
		default:
			break;
		}
	}
}

/*
 * Write all matches and literal bytes (which were precomputed) in an LZX
 * compressed block to the output bitstream in the final compressed
 * representation.
 *
 * @ostream
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
lzx_write_items(struct output_bitstream *ostream, int block_type,
		const struct lzx_item items[], u32 num_items,
		const struct lzx_codes *codes)
{
	for (u32 i = 0; i < num_items; i++) {
		/* The high bit of the 32-bit intermediate representation
		 * indicates whether the item is an actual LZ-style match (1) or
		 * a literal byte (0).  */
		if (items[i].data & 0x80000000)
			lzx_write_match(ostream, block_type, items[i], codes);
		else
			lzx_write_literal(ostream, items[i].data, codes);
	}
}

/* Write an LZX aligned offset or verbatim block to the output.  */
static void
lzx_write_compressed_block(int block_type,
			   unsigned block_size,
			   unsigned max_window_size,
			   unsigned num_main_syms,
			   struct lzx_item * chosen_items,
			   unsigned num_chosen_items,
			   const struct lzx_codes * codes,
			   const struct lzx_codes * prev_codes,
			   struct output_bitstream * ostream)
{
	unsigned i;

	LZX_ASSERT(block_type == LZX_BLOCKTYPE_ALIGNED ||
		   block_type == LZX_BLOCKTYPE_VERBATIM);

	/* The first three bits indicate the type of block and are one of the
	 * LZX_BLOCKTYPE_* constants.  */
	bitstream_put_bits(ostream, block_type, 3);

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
		bitstream_put_bits(ostream, 1, 1);
	} else {
		bitstream_put_bits(ostream, 0, 1);

		if (max_window_size >= 65536)
			bitstream_put_bits(ostream, block_size >> 16, 8);

		bitstream_put_bits(ostream, block_size, 16);
	}

	/* Write out lengths of the main code. Note that the LZX specification
	 * incorrectly states that the aligned offset code comes after the
	 * length code, but in fact it is the very first code to be written
	 * (before the main code).  */
	if (block_type == LZX_BLOCKTYPE_ALIGNED)
		for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
			bitstream_put_bits(ostream, codes->lens.aligned[i],
					   LZX_ALIGNEDCODE_ELEMENT_SIZE);

	/* Write the precode and lengths for the first LZX_NUM_CHARS symbols in
	 * the main code, which are the codewords for literal bytes.  */
	lzx_write_compressed_code(ostream,
				  codes->lens.main,
				  prev_codes->lens.main,
				  LZX_NUM_CHARS);

	/* Write the precode and lengths for the rest of the main code, which
	 * are the codewords for match headers.  */
	lzx_write_compressed_code(ostream,
				  codes->lens.main + LZX_NUM_CHARS,
				  prev_codes->lens.main + LZX_NUM_CHARS,
				  num_main_syms - LZX_NUM_CHARS);

	/* Write the precode and lengths for the length code.  */
	lzx_write_compressed_code(ostream,
				  codes->lens.len,
				  prev_codes->lens.len,
				  LZX_LENCODE_NUM_SYMBOLS);

	/* Write the actual matches and literals.  */
	lzx_write_items(ostream, block_type,
			chosen_items, num_chosen_items, codes);
}

/* Write out the LZX blocks that were computed.  */
static void
lzx_write_all_blocks(struct lzx_compressor *c, struct output_bitstream *ostream)
{

	const struct lzx_codes *prev_codes = &c->zero_codes;
	for (unsigned i = 0; i < c->num_blocks; i++) {
		const struct lzx_block_spec *spec = &c->block_specs[i];

		LZX_DEBUG("Writing block %u/%u (type=%d, size=%u, num_chosen_items=%u)...",
			  i + 1, c->num_blocks,
			  spec->block_type, spec->block_size,
			  spec->num_chosen_items);

		lzx_write_compressed_block(spec->block_type,
					   spec->block_size,
					   c->max_window_size,
					   c->num_main_syms,
					   spec->chosen_items,
					   spec->num_chosen_items,
					   &spec->codes,
					   prev_codes,
					   ostream);

		prev_codes = &spec->codes;
	}
}

/* Constructs an LZX match from a literal byte and updates the main code symbol
 * frequencies.  */
static inline u32
lzx_tally_literal(u8 lit, struct lzx_freqs *freqs)
{
	freqs->main[lit]++;
	return (u32)lit;
}

/* Constructs an LZX match from an offset and a length, and updates the LRU
 * queue and the frequency of symbols in the main, length, and aligned offset
 * alphabets.  The return value is a 32-bit number that provides the match in an
 * intermediate representation documented below.  */
static inline u32
lzx_tally_match(unsigned match_len, u32 match_offset,
		struct lzx_freqs *freqs, struct lzx_lru_queue *queue)
{
	unsigned position_slot;
	unsigned position_footer;
	u32 len_header;
	unsigned main_symbol;
	unsigned len_footer;
	unsigned adjusted_match_len;

	LZX_ASSERT(match_len >= LZX_MIN_MATCH_LEN && match_len <= LZX_MAX_MATCH_LEN);

	/* The match offset shall be encoded as a position slot (itself encoded
	 * as part of the main symbol) and a position footer.  */
	position_slot = lzx_get_position_slot(match_offset, queue);
	position_footer = (match_offset + LZX_OFFSET_OFFSET) &
				((1U << lzx_get_num_extra_bits(position_slot)) - 1);

	/* The match length shall be encoded as a length header (itself encoded
	 * as part of the main symbol) and an optional length footer.  */
	adjusted_match_len = match_len - LZX_MIN_MATCH_LEN;
	if (adjusted_match_len < LZX_NUM_PRIMARY_LENS) {
		/* No length footer needed.  */
		len_header = adjusted_match_len;
	} else {
		/* Length footer needed.  It will be encoded using the length
		 * code.  */
		len_header = LZX_NUM_PRIMARY_LENS;
		len_footer = adjusted_match_len - LZX_NUM_PRIMARY_LENS;
		freqs->len[len_footer]++;
	}

	/* Account for the main symbol.  */
	main_symbol = ((position_slot << 3) | len_header) + LZX_NUM_CHARS;

	freqs->main[main_symbol]++;

	/* In an aligned offset block, 3 bits of the position footer are output
	 * as an aligned offset symbol.  Account for this, although we may
	 * ultimately decide to output the block as verbatim.  */

	/* The following check is equivalent to:
	 *
	 * if (lzx_extra_bits[position_slot] >= 3)
	 *
	 * Note that this correctly excludes position slots that correspond to
	 * recent offsets.  */
	if (position_slot >= 8)
		freqs->aligned[position_footer & 7]++;

	/* Pack the position slot, position footer, and match length into an
	 * intermediate representation.  See `struct lzx_item' for details.
	 */
	LZX_ASSERT(LZX_MAX_POSITION_SLOTS <= 64);
	LZX_ASSERT(lzx_get_num_extra_bits(LZX_MAX_POSITION_SLOTS - 1) <= 17);
	LZX_ASSERT(LZX_MAX_MATCH_LEN - LZX_MIN_MATCH_LEN + 1 <= 256);

	LZX_ASSERT(position_slot      <= (1U << (31 - 25)) - 1);
	LZX_ASSERT(position_footer    <= (1U << (25 -  8)) - 1);
	LZX_ASSERT(adjusted_match_len <= (1U << (8  -  0)) - 1);
	return 0x80000000 |
		(position_slot << 25) |
		(position_footer << 8) |
		(adjusted_match_len);
}

/* Returns the cost, in bits, to output a literal byte using the specified cost
 * model.  */
static u32
lzx_literal_cost(u8 c, const struct lzx_costs * costs)
{
	return costs->main[c];
}

/* Given a (length, offset) pair that could be turned into a valid LZX match as
 * well as costs for the codewords in the main, length, and aligned Huffman
 * codes, return the approximate number of bits it will take to represent this
 * match in the compressed output.  Take into account the match offset LRU
 * queue and also updates it.  */
static u32
lzx_match_cost(unsigned length, u32 offset, const struct lzx_costs *costs,
	       struct lzx_lru_queue *queue)
{
	unsigned position_slot;
	unsigned len_header, main_symbol;
	unsigned num_extra_bits;
	u32 cost = 0;

	position_slot = lzx_get_position_slot(offset, queue);

	len_header = min(length - LZX_MIN_MATCH_LEN, LZX_NUM_PRIMARY_LENS);
	main_symbol = ((position_slot << 3) | len_header) + LZX_NUM_CHARS;

	/* Account for main symbol.  */
	cost += costs->main[main_symbol];

	/* Account for extra position information.  */
	num_extra_bits = lzx_get_num_extra_bits(position_slot);
	if (num_extra_bits >= 3) {
		cost += num_extra_bits - 3;
		cost += costs->aligned[(offset + LZX_OFFSET_OFFSET) & 7];
	} else {
		cost += num_extra_bits;
	}

	/* Account for extra length information.  */
	if (len_header == LZX_NUM_PRIMARY_LENS)
		cost += costs->len[length - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS];

	return cost;

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
lzx_set_costs(struct lzx_compressor *c, const struct lzx_lens * lens,
	      unsigned nostat)
{
	unsigned i;

	/* Main code  */
	for (i = 0; i < c->num_main_syms; i++)
		c->costs.main[i] = lens->main[i] ? lens->main[i] : nostat;

	/* Length code  */
	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
		c->costs.len[i] = lens->len[i] ? lens->len[i] : nostat;

	/* Aligned offset code  */
	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
		c->costs.aligned[i] = lens->aligned[i] ? lens->aligned[i] : nostat / 2;
}

/* Don't allow matches to span the end of an LZX block.  */
static inline u32
maybe_truncate_matches(struct lz_match matches[], u32 num_matches,
		       struct lzx_compressor *c)
{
	if (c->match_window_end < c->cur_window_size && num_matches != 0) {
		u32 limit = c->match_window_end - c->match_window_pos;

		if (limit >= LZX_MIN_MATCH_LEN) {

			u32 i = num_matches - 1;
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
 * Returns the number of matches found and sets *matches_ret to point to the
 * matches array.  The matches will be sorted by strictly increasing length and
 * offset.
 */
static inline unsigned
lzx_get_matches(struct lzx_compressor *c,
		const struct lz_match **matches_ret)
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
 */
static inline void
lzx_skip_bytes(struct lzx_compressor *c, unsigned n)
{
	return (*c->skip_bytes_func)(c, n);
}

/*
 * Reverse the linked list of near-optimal matches so that they can be returned
 * in forwards order.
 *
 * Returns the first match in the list.
 */
static struct lz_match
lzx_match_chooser_reverse_list(struct lzx_compressor *c, unsigned cur_pos)
{
	unsigned prev_link, saved_prev_link;
	unsigned prev_match_offset, saved_prev_match_offset;

	c->optimum_end_idx = cur_pos;

	saved_prev_link = c->optimum[cur_pos].prev.link;
	saved_prev_match_offset = c->optimum[cur_pos].prev.match_offset;

	do {
		prev_link = saved_prev_link;
		prev_match_offset = saved_prev_match_offset;

		saved_prev_link = c->optimum[prev_link].prev.link;
		saved_prev_match_offset = c->optimum[prev_link].prev.match_offset;

		c->optimum[prev_link].next.link = cur_pos;
		c->optimum[prev_link].next.match_offset = prev_match_offset;

		cur_pos = prev_link;
	} while (cur_pos != 0);

	c->optimum_cur_idx = c->optimum[0].next.link;

	return (struct lz_match)
		{ .len = c->optimum_cur_idx,
		  .offset = c->optimum[0].next.match_offset,
		};
}

/*
 * lzx_choose_near_optimal_match() -
 *
 * Choose an approximately optimal match or literal to use at the next position
 * in the string, or "window", being LZ-encoded.
 *
 * This is based on algorithms used in 7-Zip, including the DEFLATE encoder
 * and the LZMA encoder, written by Igor Pavlov.
 *
 * Unlike a greedy parser that always takes the longest match, or even a "lazy"
 * parser with one match/literal look-ahead like zlib, the algorithm used here
 * may look ahead many matches/literals to determine the approximately optimal
 * match/literal to code next.  The motivation is that the compression ratio is
 * improved if the compressor can do things like use a shorter-than-possible
 * match in order to allow a longer match later, and also take into account the
 * estimated real cost of coding each match/literal based on the underlying
 * entropy encoding.
 *
 * Still, this is not a true optimal parser for several reasons:
 *
 * - Real compression formats use entropy encoding of the literal/match
 *   sequence, so the real cost of coding each match or literal is unknown until
 *   the parse is fully determined.  It can be approximated based on iterative
 *   parses, but the end result is not guaranteed to be globally optimal.
 *
 * - Very long matches are chosen immediately.  This is because locations with
 *   long matches are likely to have many possible alternatives that would cause
 *   slow optimal parsing, but also such locations are already highly
 *   compressible so it is not too harmful to just grab the longest match.
 *
 * - Not all possible matches at each location are considered because the
 *   underlying match-finder limits the number and type of matches produced at
 *   each position.  For example, for a given match length it's usually not
 *   worth it to only consider matches other than the lowest-offset match,
 *   except in the case of a repeat offset.
 *
 * - Although we take into account the adaptive state (in LZX, the recent offset
 *   queue), coding decisions made with respect to the adaptive state will be
 *   locally optimal but will not necessarily be globally optimal.  This is
 *   because the algorithm only keeps the least-costly path to get to a given
 *   location and does not take into account that a slightly more costly path
 *   could result in a different adaptive state that ultimately results in a
 *   lower global cost.
 *
 * - The array space used by this function is bounded, so in degenerate cases it
 *   is forced to start returning matches/literals before the algorithm has
 *   really finished.
 *
 * Each call to this function does one of two things:
 *
 * 1. Build a sequence of near-optimal matches/literals, up to some point, that
 *    will be returned by subsequent calls to this function, then return the
 *    first one.
 *
 * OR
 *
 * 2. Return the next match/literal previously computed by a call to this
 *    function.
 *
 * The return value is a (length, offset) pair specifying the match or literal
 * chosen.  For literals, the length is 0 or 1 and the offset is meaningless.
 */
static struct lz_match
lzx_choose_near_optimal_item(struct lzx_compressor *c)
{
	unsigned num_matches;
	const struct lz_match *matches;
	struct lz_match match;
	unsigned longest_len;
	unsigned longest_rep_len;
	u32 longest_rep_offset;
	unsigned cur_pos;
	unsigned end_pos;

	if (c->optimum_cur_idx != c->optimum_end_idx) {
		/* Case 2: Return the next match/literal already found.  */
		match.len = c->optimum[c->optimum_cur_idx].next.link -
				    c->optimum_cur_idx;
		match.offset = c->optimum[c->optimum_cur_idx].next.match_offset;

		c->optimum_cur_idx = c->optimum[c->optimum_cur_idx].next.link;
		return match;
	}

	/* Case 1:  Compute a new list of matches/literals to return.  */

	c->optimum_cur_idx = 0;
	c->optimum_end_idx = 0;

	/* Search for matches at recent offsets.  Only keep the one with the
	 * longest match length.  */
	longest_rep_len = LZX_MIN_MATCH_LEN - 1;
	if (c->match_window_pos >= 1) {
		unsigned limit = min(LZX_MAX_MATCH_LEN,
				     c->match_window_end - c->match_window_pos);
		for (int i = 0; i < LZX_NUM_RECENT_OFFSETS; i++) {
			u32 offset = c->queue.R[i];
			const u8 *strptr = &c->cur_window[c->match_window_pos];
			const u8 *matchptr = strptr - offset;
			unsigned len = 0;
			while (len < limit && strptr[len] == matchptr[len])
				len++;
			if (len > longest_rep_len) {
				longest_rep_len = len;
				longest_rep_offset = offset;
			}
		}
	}

	/* If there's a long match with a recent offset, take it.  */
	if (longest_rep_len >= c->params.nice_match_length) {
		lzx_skip_bytes(c, longest_rep_len);
		return (struct lz_match) {
			.len = longest_rep_len,
			.offset = longest_rep_offset,
		};
	}

	/* Search other matches.  */
	num_matches = lzx_get_matches(c, &matches);

	/* If there's a long match, take it.  */
	if (num_matches) {
		longest_len = matches[num_matches - 1].len;
		if (longest_len >= c->params.nice_match_length) {
			lzx_skip_bytes(c, longest_len - 1);
			return matches[num_matches - 1];
		}
	} else {
		longest_len = 1;
	}

	/* Calculate the cost to reach the next position by coding a literal.
	 */
	c->optimum[1].queue = c->queue;
	c->optimum[1].cost = lzx_literal_cost(c->cur_window[c->match_window_pos - 1],
					      &c->costs);
	c->optimum[1].prev.link = 0;

	/* Calculate the cost to reach any position up to and including that
	 * reached by the longest match.
	 *
	 * Note: We consider only the lowest-offset match that reaches each
	 * position.
	 *
	 * Note: Some of the cost calculation stays the same for each offset,
	 * regardless of how many lengths it gets used for.  Therefore, to
	 * improve performance, we hand-code the cost calculation instead of
	 * calling lzx_match_cost() to do a from-scratch cost evaluation at each
	 * length.  */
	for (unsigned i = 0, len = 2; i < num_matches; i++) {
		u32 offset;
		struct lzx_lru_queue queue;
		u32 position_cost;
		unsigned position_slot;
		unsigned num_extra_bits;

		offset = matches[i].offset;
		queue = c->queue;
		position_cost = 0;

		position_slot = lzx_get_position_slot(offset, &queue);
		num_extra_bits = lzx_get_num_extra_bits(position_slot);
		if (num_extra_bits >= 3) {
			position_cost += num_extra_bits - 3;
			position_cost += c->costs.aligned[(offset + LZX_OFFSET_OFFSET) & 7];
		} else {
			position_cost += num_extra_bits;
		}

		do {
			unsigned len_header;
			unsigned main_symbol;
			u32 cost;

			cost = position_cost;

			len_header = min(len - LZX_MIN_MATCH_LEN, LZX_NUM_PRIMARY_LENS);
			main_symbol = ((position_slot << 3) | len_header) + LZX_NUM_CHARS;
			cost += c->costs.main[main_symbol];
			if (len_header == LZX_NUM_PRIMARY_LENS)
				cost += c->costs.len[len - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS];

			c->optimum[len].queue = queue;
			c->optimum[len].prev.link = 0;
			c->optimum[len].prev.match_offset = offset;
			c->optimum[len].cost = cost;
		} while (++len <= matches[i].len);
	}
	end_pos = longest_len;

	if (longest_rep_len >= LZX_MIN_MATCH_LEN) {
		struct lzx_lru_queue queue;
		u32 cost;

		while (end_pos < longest_rep_len)
			c->optimum[++end_pos].cost = MC_INFINITE_COST;

		queue = c->queue;
		cost = lzx_match_cost(longest_rep_len, longest_rep_offset,
				      &c->costs, &queue);
		if (cost <= c->optimum[longest_rep_len].cost) {
			c->optimum[longest_rep_len].queue = queue;
			c->optimum[longest_rep_len].prev.link = 0;
			c->optimum[longest_rep_len].prev.match_offset = longest_rep_offset;
			c->optimum[longest_rep_len].cost = cost;
		}
	}

	/* Step forward, calculating the estimated minimum cost to reach each
	 * position.  The algorithm may find multiple paths to reach each
	 * position; only the lowest-cost path is saved.
	 *
	 * The progress of the parse is tracked in the @c->optimum array, which
	 * for each position contains the minimum cost to reach that position,
	 * the index of the start of the match/literal taken to reach that
	 * position through the minimum-cost path, the offset of the match taken
	 * (not relevant for literals), and the adaptive state that will exist
	 * at that position after the minimum-cost path is taken.  The @cur_pos
	 * variable stores the position at which the algorithm is currently
	 * considering coding choices, and the @end_pos variable stores the
	 * greatest position at which the costs of coding choices have been
	 * saved.  (Actually, the algorithm guarantees that all positions up to
	 * and including @end_pos are reachable by at least one path.)
	 *
	 * The loop terminates when any one of the following conditions occurs:
	 *
	 * 1. A match with length greater than or equal to @nice_match_length is
	 *    found.  When this occurs, the algorithm chooses this match
	 *    unconditionally, and consequently the near-optimal match/literal
	 *    sequence up to and including that match is fully determined and it
	 *    can begin returning the match/literal list.
	 *
	 * 2. @cur_pos reaches a position not overlapped by a preceding match.
	 *    In such cases, the near-optimal match/literal sequence up to
	 *    @cur_pos is fully determined and it can begin returning the
	 *    match/literal list.
	 *
	 * 3. Failing either of the above in a degenerate case, the loop
	 *    terminates when space in the @c->optimum array is exhausted.
	 *    This terminates the algorithm and forces it to start returning
	 *    matches/literals even though they may not be globally optimal.
	 *
	 * Upon loop termination, a nonempty list of matches/literals will have
	 * been produced and stored in the @optimum array.  These
	 * matches/literals are linked in reverse order, so the last thing this
	 * function does is reverse this list and return the first
	 * match/literal, leaving the rest to be returned immediately by
	 * subsequent calls to this function.
	 */
	cur_pos = 0;
	for (;;) {
		u32 cost;

		/* Advance to next position.  */
		cur_pos++;

		/* Check termination conditions (2) and (3) noted above.  */
		if (cur_pos == end_pos || cur_pos == LZX_OPTIM_ARRAY_LENGTH)
			return lzx_match_chooser_reverse_list(c, cur_pos);

		/* Search for matches at recent offsets.  */
		longest_rep_len = LZX_MIN_MATCH_LEN - 1;
		unsigned limit = min(LZX_MAX_MATCH_LEN,
				     c->match_window_end - c->match_window_pos);
		for (int i = 0; i < LZX_NUM_RECENT_OFFSETS; i++) {
			u32 offset = c->optimum[cur_pos].queue.R[i];
			const u8 *strptr = &c->cur_window[c->match_window_pos];
			const u8 *matchptr = strptr - offset;
			unsigned len = 0;
			while (len < limit && strptr[len] == matchptr[len])
				len++;
			if (len > longest_rep_len) {
				longest_rep_len = len;
				longest_rep_offset = offset;
			}
		}

		/* If we found a long match at a recent offset, choose it
		 * immediately.  */
		if (longest_rep_len >= c->params.nice_match_length) {
			/* Build the list of matches to return and get
			 * the first one.  */
			match = lzx_match_chooser_reverse_list(c, cur_pos);

			/* Append the long match to the end of the list.  */
			c->optimum[cur_pos].next.match_offset = longest_rep_offset;
			c->optimum[cur_pos].next.link = cur_pos + longest_rep_len;
			c->optimum_end_idx = cur_pos + longest_rep_len;

			/* Skip over the remaining bytes of the long match.  */
			lzx_skip_bytes(c, longest_rep_len);

			/* Return first match in the list.  */
			return match;
		}

		/* Search other matches.  */
		num_matches = lzx_get_matches(c, &matches);

		/* If there's a long match, take it.  */
		if (num_matches) {
			longest_len = matches[num_matches - 1].len;
			if (longest_len >= c->params.nice_match_length) {
				/* Build the list of matches to return and get
				 * the first one.  */
				match = lzx_match_chooser_reverse_list(c, cur_pos);

				/* Append the long match to the end of the list.  */
				c->optimum[cur_pos].next.match_offset =
					matches[num_matches - 1].offset;
				c->optimum[cur_pos].next.link = cur_pos + longest_len;
				c->optimum_end_idx = cur_pos + longest_len;

				/* Skip over the remaining bytes of the long match.  */
				lzx_skip_bytes(c, longest_len - 1);

				/* Return first match in the list.  */
				return match;
			}
		} else {
			longest_len = 1;
		}

		while (end_pos < cur_pos + longest_len)
			c->optimum[++end_pos].cost = MC_INFINITE_COST;

		/* Consider coding a literal.  */
		cost = c->optimum[cur_pos].cost +
			lzx_literal_cost(c->cur_window[c->match_window_pos - 1],
					 &c->costs);
		if (cost < c->optimum[cur_pos + 1].cost) {
			c->optimum[cur_pos + 1].queue = c->optimum[cur_pos].queue;
			c->optimum[cur_pos + 1].cost = cost;
			c->optimum[cur_pos + 1].prev.link = cur_pos;
		}

		/* Consider coding a match.
		 *
		 * The hard-coded cost calculation is done for the same reason
		 * stated in the comment for the similar loop earlier.
		 * Actually, it is *this* one that has the biggest effect on
		 * performance; overall LZX compression is > 10% faster with
		 * this code compared to calling lzx_match_cost() with each
		 * length.  */
		for (unsigned i = 0, len = 2; i < num_matches; i++) {
			u32 offset;
			struct lzx_lru_queue queue;
			u32 position_cost;
			unsigned position_slot;
			unsigned num_extra_bits;

			offset = matches[i].offset;
			queue = c->optimum[cur_pos].queue;
			position_cost = c->optimum[cur_pos].cost;

			position_slot = lzx_get_position_slot(offset, &queue);
			num_extra_bits = lzx_get_num_extra_bits(position_slot);
			if (num_extra_bits >= 3) {
				position_cost += num_extra_bits - 3;
				position_cost += c->costs.aligned[
						(offset + LZX_OFFSET_OFFSET) & 7];
			} else {
				position_cost += num_extra_bits;
			}

			do {
				unsigned len_header;
				unsigned main_symbol;
				u32 cost;

				cost = position_cost;

				len_header = min(len - LZX_MIN_MATCH_LEN,
						 LZX_NUM_PRIMARY_LENS);
				main_symbol = ((position_slot << 3) | len_header) +
						LZX_NUM_CHARS;
				cost += c->costs.main[main_symbol];
				if (len_header == LZX_NUM_PRIMARY_LENS) {
					cost += c->costs.len[len -
							LZX_MIN_MATCH_LEN -
							LZX_NUM_PRIMARY_LENS];
				}
				if (cost < c->optimum[cur_pos + len].cost) {
					c->optimum[cur_pos + len].queue = queue;
					c->optimum[cur_pos + len].prev.link = cur_pos;
					c->optimum[cur_pos + len].prev.match_offset = offset;
					c->optimum[cur_pos + len].cost = cost;
				}
			} while (++len <= matches[i].len);
		}

		if (longest_rep_len >= LZX_MIN_MATCH_LEN) {
			struct lzx_lru_queue queue;

			while (end_pos < cur_pos + longest_rep_len)
				c->optimum[++end_pos].cost = MC_INFINITE_COST;

			queue = c->optimum[cur_pos].queue;

			cost = c->optimum[cur_pos].cost +
				lzx_match_cost(longest_rep_len, longest_rep_offset,
					       &c->costs, &queue);
			if (cost <= c->optimum[cur_pos + longest_rep_len].cost) {
				c->optimum[cur_pos + longest_rep_len].queue =
					queue;
				c->optimum[cur_pos + longest_rep_len].prev.link =
					cur_pos;
				c->optimum[cur_pos + longest_rep_len].prev.match_offset =
					longest_rep_offset;
				c->optimum[cur_pos + longest_rep_len].cost =
					cost;
			}
		}
	}
}

static struct lz_match
lzx_choose_lazy_item(struct lzx_compressor *c)
{
	const struct lz_match *matches;
	struct lz_match cur_match;
	struct lz_match next_match;
	u32 num_matches;

	if (c->prev_match.len) {
		cur_match = c->prev_match;
		c->prev_match.len = 0;
	} else {
		num_matches = lzx_get_matches(c, &matches);
		if (num_matches == 0 ||
		    (matches[num_matches - 1].len <= 3 &&
		     (matches[num_matches - 1].len <= 2 ||
		      matches[num_matches - 1].offset > 4096)))
		{
			return (struct lz_match) { };
		}

		cur_match = matches[num_matches - 1];
	}

	if (cur_match.len >= c->params.nice_match_length) {
		lzx_skip_bytes(c, cur_match.len - 1);
		return cur_match;
	}

	num_matches = lzx_get_matches(c, &matches);
	if (num_matches == 0 ||
	    (matches[num_matches - 1].len <= 3 &&
	     (matches[num_matches - 1].len <= 2 ||
	      matches[num_matches - 1].offset > 4096)))
	{
		lzx_skip_bytes(c, cur_match.len - 2);
		return cur_match;
	}

	next_match = matches[num_matches - 1];

	if (next_match.len <= cur_match.len) {
		lzx_skip_bytes(c, cur_match.len - 2);
		return cur_match;
	} else {
		c->prev_match = next_match;
		return (struct lz_match) { };
	}
}

/*
 * Return the next match or literal to use, delegating to the currently selected
 * match-choosing algorithm.
 *
 * If the length of the returned 'struct lz_match' is less than
 * LZX_MIN_MATCH_LEN, then it is really a literal.
 */
static inline struct lz_match
lzx_choose_item(struct lzx_compressor *c)
{
	return (*c->params.choose_item_func)(c);
}

/* Set default symbol costs for the LZX Huffman codes.  */
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

/* Given the frequencies of symbols in an LZX-compressed block and the
 * corresponding Huffman codes, return LZX_BLOCKTYPE_ALIGNED or
 * LZX_BLOCKTYPE_VERBATIM if an aligned offset or verbatim block, respectively,
 * will take fewer bits to output.  */
static int
lzx_choose_verbatim_or_aligned(const struct lzx_freqs * freqs,
			       const struct lzx_codes * codes)
{
	unsigned aligned_cost = 0;
	unsigned verbatim_cost = 0;

	/* Verbatim blocks have a constant 3 bits per position footer.  Aligned
	 * offset blocks have an aligned offset symbol per position footer, plus
	 * an extra 24 bits per block to output the lengths necessary to
	 * reconstruct the aligned offset code itself.  */
	for (unsigned i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
		verbatim_cost += 3 * freqs->aligned[i];
		aligned_cost += codes->lens.aligned[i] * freqs->aligned[i];
	}
	aligned_cost += LZX_ALIGNEDCODE_ELEMENT_SIZE * LZX_ALIGNEDCODE_NUM_SYMBOLS;
	if (aligned_cost < verbatim_cost)
		return LZX_BLOCKTYPE_ALIGNED;
	else
		return LZX_BLOCKTYPE_VERBATIM;
}

/* Find a sequence of matches/literals with which to output the specified LZX
 * block, then set the block's type to that which has the minimum cost to output
 * (either verbatim or aligned).  */
static void
lzx_choose_items_for_block(struct lzx_compressor *c, struct lzx_block_spec *spec)
{
	const struct lzx_lru_queue orig_queue = c->queue;
	u32 num_passes_remaining = c->params.num_optim_passes;
	struct lzx_freqs freqs;
	const u8 *window_ptr;
	const u8 *window_end;
	struct lzx_item *next_chosen_item;
	struct lz_match lz_match;
	struct lzx_item lzx_item;

	LZX_ASSERT(num_passes >= 1);
	LZX_ASSERT(lz_mf_get_position(c->mf) == spec->window_pos);

	c->match_window_end = spec->window_pos + spec->block_size;

	if (c->params.num_optim_passes > 1) {
		if (spec->block_size == c->cur_window_size)
			c->get_matches_func = lzx_get_matches_fillcache_singleblock;
		else
			c->get_matches_func = lzx_get_matches_fillcache_multiblock;
		c->skip_bytes_func = lzx_skip_bytes_fillcache;
	} else {
		if (spec->block_size == c->cur_window_size)
			c->get_matches_func = lzx_get_matches_nocache_singleblock;
		else
			c->get_matches_func = lzx_get_matches_nocache_multiblock;
		c->skip_bytes_func = lzx_skip_bytes_nocache;
	}

	/* The first optimal parsing pass is done using the cost model already
	 * set in c->costs.  Each later pass is done using a cost model
	 * computed from the previous pass.
	 *
	 * To improve performance we only generate the array containing the
	 * matches and literals in intermediate form on the final pass.  */

	while (--num_passes_remaining) {
		c->match_window_pos = spec->window_pos;
		c->cache_ptr = c->cached_matches;
		memset(&freqs, 0, sizeof(freqs));
		window_ptr = &c->cur_window[spec->window_pos];
		window_end = window_ptr + spec->block_size;

		while (window_ptr != window_end) {

			lz_match = lzx_choose_item(c);

			LZX_ASSERT(!(lz_match.len == LZX_MIN_MATCH_LEN &&
				     lz_match.offset == c->max_window_size -
							 LZX_MIN_MATCH_LEN));
			if (lz_match.len >= LZX_MIN_MATCH_LEN) {
				lzx_tally_match(lz_match.len, lz_match.offset,
						&freqs, &c->queue);
				window_ptr += lz_match.len;
			} else {
				lzx_tally_literal(*window_ptr, &freqs);
				window_ptr += 1;
			}
		}
		lzx_make_huffman_codes(&freqs, &spec->codes, c->num_main_syms);
		lzx_set_costs(c, &spec->codes.lens, 15);
		c->queue = orig_queue;
		if (c->cache_ptr <= c->cache_limit) {
			c->get_matches_func = lzx_get_matches_usecache_nocheck;
			c->skip_bytes_func = lzx_skip_bytes_usecache_nocheck;
		} else {
			c->get_matches_func = lzx_get_matches_usecache;
			c->skip_bytes_func = lzx_skip_bytes_usecache;
		}
	}

	c->match_window_pos = spec->window_pos;
	c->cache_ptr = c->cached_matches;
	memset(&freqs, 0, sizeof(freqs));
	window_ptr = &c->cur_window[spec->window_pos];
	window_end = window_ptr + spec->block_size;

	spec->chosen_items = &c->chosen_items[spec->window_pos];
	next_chosen_item = spec->chosen_items;

	unsigned unseen_cost = 9;
	while (window_ptr != window_end) {

		lz_match = lzx_choose_item(c);

		LZX_ASSERT(!(lz_match.len == LZX_MIN_MATCH_LEN &&
			     lz_match.offset == c->max_window_size -
						 LZX_MIN_MATCH_LEN));
		if (lz_match.len >= LZX_MIN_MATCH_LEN) {
			lzx_item.data = lzx_tally_match(lz_match.len,
							 lz_match.offset,
							 &freqs, &c->queue);
			window_ptr += lz_match.len;
		} else {
			lzx_item.data = lzx_tally_literal(*window_ptr, &freqs);
			window_ptr += 1;
		}
		*next_chosen_item++ = lzx_item;

		/* When doing one-pass "near-optimal" parsing, update the cost
		 * model occassionally.  */
		if (unlikely((next_chosen_item - spec->chosen_items) % 2048 == 0) &&
		    c->params.choose_item_func == lzx_choose_near_optimal_item &&
		    c->params.num_optim_passes == 1)
		{
			lzx_make_huffman_codes(&freqs, &spec->codes, c->num_main_syms);
			lzx_set_costs(c, &spec->codes.lens, unseen_cost);
			if (unseen_cost < 15)
				unseen_cost++;
		}
	}
	spec->num_chosen_items = next_chosen_item - spec->chosen_items;
	lzx_make_huffman_codes(&freqs, &spec->codes, c->num_main_syms);
	spec->block_type = lzx_choose_verbatim_or_aligned(&freqs, &spec->codes);
}

/* Prepare the input window into one or more LZX blocks ready to be output.  */
static void
lzx_prepare_blocks(struct lzx_compressor *c)
{
	/* Set up a default cost model.  */
	if (c->params.choose_item_func == lzx_choose_near_optimal_item)
		lzx_set_default_costs(&c->costs, c->num_main_syms);

	/* Set up the block specifications.
	 * TODO: The compression ratio could be slightly improved by performing
	 * data-dependent block splitting instead of using fixed-size blocks.
	 * Doing so well is a computationally hard problem, however.  */
	c->num_blocks = DIV_ROUND_UP(c->cur_window_size, LZX_DIV_BLOCK_SIZE);
	for (unsigned i = 0; i < c->num_blocks; i++) {
		u32 pos = LZX_DIV_BLOCK_SIZE * i;
		c->block_specs[i].window_pos = pos;
		c->block_specs[i].block_size = min(c->cur_window_size - pos,
						   LZX_DIV_BLOCK_SIZE);
	}

	/* Load the window into the match-finder.  */
	lz_mf_load_window(c->mf, c->cur_window, c->cur_window_size);

	/* Determine sequence of matches/literals to output for each block.  */
	lzx_lru_queue_init(&c->queue);
	c->optimum_cur_idx = 0;
	c->optimum_end_idx = 0;
	c->prev_match.len = 0;
	for (unsigned i = 0; i < c->num_blocks; i++)
		lzx_choose_items_for_block(c, &c->block_specs[i]);
}

static void
lzx_build_params(unsigned int compression_level,
		 u32 max_window_size,
		 struct lzx_compressor_params *lzx_params)
{
	if (compression_level < 25) {
		lzx_params->choose_item_func = lzx_choose_lazy_item;
		lzx_params->num_optim_passes  = 1;
		if (max_window_size <= 262144)
			lzx_params->mf_algo = LZ_MF_HASH_CHAINS;
		else
			lzx_params->mf_algo = LZ_MF_BINARY_TREES;
		lzx_params->min_match_length  = 3;
		lzx_params->nice_match_length = 25 + compression_level * 2;
		lzx_params->max_search_depth  = 25 + compression_level;
	} else {
		lzx_params->choose_item_func = lzx_choose_near_optimal_item;
		lzx_params->num_optim_passes  = compression_level / 20;
		if (max_window_size <= 32768 && lzx_params->num_optim_passes == 1)
			lzx_params->mf_algo = LZ_MF_HASH_CHAINS;
		else
			lzx_params->mf_algo = LZ_MF_BINARY_TREES;
		lzx_params->min_match_length  = (compression_level >= 45) ? 2 : 3;
		lzx_params->nice_match_length = min(((u64)compression_level * 32) / 50,
						    LZX_MAX_MATCH_LEN);
		lzx_params->max_search_depth  = min(((u64)compression_level * 50) / 50,
						    LZX_MAX_MATCH_LEN);
	}
}

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
lzx_get_needed_memory(size_t max_window_size, unsigned int compression_level)
{
	struct lzx_compressor_params params;
	u64 size = 0;

	if (!lzx_window_size_valid(max_window_size))
		return 0;

	lzx_build_params(compression_level, max_window_size, &params);

	size += sizeof(struct lzx_compressor);

	size += max_window_size;

	size += DIV_ROUND_UP(max_window_size, LZX_DIV_BLOCK_SIZE) *
		sizeof(struct lzx_block_spec);

	size += max_window_size * sizeof(struct lzx_item);

	size += lz_mf_get_needed_memory(params.mf_algo, max_window_size);
	if (params.choose_item_func == lzx_choose_near_optimal_item) {
		size += (LZX_OPTIM_ARRAY_LENGTH + params.nice_match_length) *
			sizeof(struct lzx_mc_pos_data);
	}
	if (params.num_optim_passes > 1)
		size += LZX_CACHE_LEN * sizeof(struct lz_match);
	else
		size += LZX_MAX_MATCHES_PER_POS * sizeof(struct lz_match);
	return size;
}

static int
lzx_create_compressor(size_t max_window_size, unsigned int compression_level,
		      void **c_ret)
{
	struct lzx_compressor *c;
	struct lzx_compressor_params params;
	struct lz_mf_params mf_params;

	if (!lzx_window_size_valid(max_window_size))
		return WIMLIB_ERR_INVALID_PARAM;

	lzx_build_params(compression_level, max_window_size, &params);
	lzx_build_mf_params(&params, max_window_size, &mf_params);
	if (!lz_mf_params_valid(&mf_params))
		return WIMLIB_ERR_INVALID_PARAM;

	c = CALLOC(1, sizeof(struct lzx_compressor));
	if (!c)
		goto oom;

	c->params = params;
	c->num_main_syms = lzx_get_num_main_syms(max_window_size);
	c->max_window_size = max_window_size;

	c->cur_window = ALIGNED_MALLOC(max_window_size, 16);
	if (!c->cur_window)
		goto oom;

	c->block_specs = MALLOC(DIV_ROUND_UP(max_window_size,
					     LZX_DIV_BLOCK_SIZE) *
				sizeof(struct lzx_block_spec));
	if (!c->block_specs)
		goto oom;

	c->chosen_items = MALLOC(max_window_size * sizeof(struct lzx_item));
	if (!c->chosen_items)
		goto oom;

	c->mf = lz_mf_alloc(&mf_params);
	if (!c->mf)
		goto oom;

	if (params.choose_item_func == lzx_choose_near_optimal_item) {
		c->optimum = MALLOC((LZX_OPTIM_ARRAY_LENGTH +
				     params.nice_match_length) *
				    sizeof(struct lzx_mc_pos_data));
		if (!c->optimum)
			goto oom;
	}

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
	struct output_bitstream ostream;
	size_t compressed_size;

	if (uncompressed_size < 100) {
		LZX_DEBUG("Too small to bother compressing.");
		return 0;
	}

	LZX_DEBUG("Attempting to compress %zu bytes...",
		  uncompressed_size);

	/* The input data must be preprocessed.  To avoid changing the original
	 * input, copy it to a temporary buffer.  */
	memcpy(c->cur_window, uncompressed_data, uncompressed_size);
	c->cur_window_size = uncompressed_size;

	/* Before doing any actual compression, do the call instruction (0xe8
	 * byte) translation on the uncompressed data.  */
	lzx_do_e8_preprocessing(c->cur_window, c->cur_window_size);

	/* Prepare the compressed data.  */
	lzx_prepare_blocks(c);

	/* Generate the compressed data.  */
	init_output_bitstream(&ostream, compressed_data, compressed_size_avail);
	lzx_write_all_blocks(c, &ostream);

	compressed_size = flush_output_bitstream(&ostream);
	if (compressed_size == (u32)~0UL) {
		LZX_DEBUG("Data did not compress to %zu bytes or less!",
			  compressed_size_avail);
		return 0;
	}

	LZX_DEBUG("Done: compressed %zu => %zu bytes.",
		  uncompressed_size, compressed_size);

	return compressed_size;
}

static void
lzx_free_compressor(void *_c)
{
	struct lzx_compressor *c = _c;

	if (c) {
		ALIGNED_FREE(c->cur_window);
		FREE(c->block_specs);
		FREE(c->chosen_items);
		lz_mf_free(c->mf);
		FREE(c->optimum);
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
