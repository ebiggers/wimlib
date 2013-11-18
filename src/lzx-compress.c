/*
 * lzx-compress.c
 *
 * LZX compression routines
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


/*
 * This file contains a compressor for the LZX compression format, as used in
 * the WIM file format.
 *
 * Format
 * ======
 *
 * First, the primary reference for the LZX compression format is the
 * specification released by Microsoft.
 *
 * Second, the comments in lzx-decompress.c provide some more information about
 * the LZX compression format, including errors in the Microsoft specification.
 *
 * Do note that LZX shares many similarities with DEFLATE, the algorithm used by
 * zlib and gzip.  Both LZX and DEFLATE use LZ77 matching and Huffman coding,
 * and certain other details are quite similar, such as the method for storing
 * Huffman codes.  However, some of the main differences are:
 *
 * - LZX preprocesses the data before attempting to compress it.
 * - LZX uses a "main" alphabet which combines literals and matches, with the
 *   match symbols containing a "length header" (giving all or part of the match
 *   length) and a "position footer" (giving, roughly speaking, the order of
 *   magnitude of the match offset).
 * - LZX does not have static Huffman blocks; however it does have two types of
 *   dynamic Huffman blocks ("aligned offset" and "verbatim").
 * - LZX has a minimum match length of 2 rather than 3.
 * - In LZX, match offsets 0 through 2 actually represent entries in a LRU queue
 *   of match offsets.
 *
 * Algorithms
 * ==========
 *
 * There are actually two distinct overall algorithms implemented here.  We
 * shall refer to them as the "slow" algorithm and the "fast" algorithm.  The
 * "slow" algorithm spends more time compressing to achieve a higher compression
 * ratio compared to the "fast" algorithm.  More details are presented below.
 *
 * Slow algorithm
 * --------------
 *
 * The "slow" algorithm to generate LZX-compressed data is roughly as follows:
 *
 * 1. Preprocess the input data to translate the targets of x86 call instructions
 *    to absolute offsets.
 *
 * 2. Determine the best known sequence of LZ77 matches ((offset, length) pairs)
 *    and literal bytes to divide the input into.  Raw match-finding is done
 *    using a very clever binary tree search based on the "Bt3" algorithm from
 *    7-Zip.  Parsing, or match-choosing, is solved essentially as a
 *    minimum-cost path problem, but using a heuristic forward search based on
 *    the Deflate encoder from 7-Zip rather than a more intuitive backward
 *    search, the latter of which would naively require that all matches be
 *    found.  This heuristic search, as well as other heuristics such as limits
 *    on the matches considered, considerably speed up this part of the
 *    algorithm, which is the main bottleneck.  Finally, after matches and
 *    literals are chosen, the needed Huffman codes needed to output them are
 *    built.
 *
 * 3. Up to a certain number of iterations, use the resulting Huffman codes to
 *    refine a cost model and go back to Step #2 to determine an improved
 *    sequence of matches and literals.
 *
 * 4. Up to a certain depth, try splitting the current block to see if the
 *    compression ratio can be improved.  This may be the case if parts of the
 *    input differ greatly from each other and could benefit from different
 *    Huffman codes.
 *
 * 5. Output the resulting block(s) using the match/literal sequences and the
 *    Huffman codes that were computed for each block.
 *
 * Fast algorithm
 * --------------
 *
 * The fast algorithm (and the only one available in wimlib v1.5.1 and earlier)
 * spends much less time on the main bottlenecks of the compression process ---
 * that is the match finding, match choosing, and block splitting.  Matches are
 * found and chosen with hash chains using a greedy parse with one position of
 * look-ahead.  No block splitting is done; only compressing the full input into
 * an aligned offset block is considered.
 *
 * API
 * ===
 *
 * The old API (retained for backward compatibility) consists of just one function:
 *
 *	wimlib_lzx_compress()
 *
 * The new compressor has more potential parameters and needs more memory, so
 * the new API ties up memory allocations and compression parameters into a
 * context:
 *
 *	wimlib_lzx_alloc_context()
 *	wimlib_lzx_compress2()
 *	wimlib_lzx_free_context()
 *
 * Both wimlib_lzx_compress() and wimlib_lzx_compress2() are designed to
 * compress an in-memory buffer of up to 32768 bytes.  There is no sliding
 * window.  This is suitable for the WIM format, which uses fixed-size chunks
 * that are seemingly always 32768 bytes.  If needed, the compressor potentially
 * could be extended to support a larger and/or sliding window.
 *
 * Both wimlib_lzx_compress() and wimlib_lzx_compress2() return 0 if the data
 * could not be compressed to less than the size of the uncompressed data.
 * Again, this is suitable for the WIM format, which stores such data chunks
 * uncompressed.
 *
 * The functions in this API are exported from the library, although this is
 * only in case other programs happen to have uses for it other than WIM
 * reading/writing as already handled through the rest of the library.
 *
 * Acknowledgments
 * ===============
 *
 * Acknowledgments to several other open-source projects that made it possible
 * to implement this code:
 *
 * - 7-Zip (author: Igor Pavlov), for the binary tree match-finding
 *   algorithm, the heuristic near-optimal forward match-choosing
 *   algorithm, and the block splitting algorithm.
 *
 * - zlib (author: Jean-loup Gailly and Mark Adler), for the hash table
 *   match-finding algorithm.
 *
 * - lzx-compress (author: Matthew T. Russotto), on which some parts of this
 *   code were originally based.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/compress.h"
#include "wimlib/error.h"
#include "wimlib/lzx.h"
#include "wimlib/util.h"

#ifdef ENABLE_LZX_DEBUG
#  include <wimlib/decompress.h>
#endif

#include <string.h>

/* Experimental parameters not exposed through the API  */
#define LZX_PARAM_OPTIM_ARRAY_SIZE	1024
#define LZX_PARAM_ACCOUNT_FOR_LRU	1
#define LZX_PARAM_DONT_SKIP_MATCHES	0
#define LZX_PARAM_USE_EMPIRICAL_DEFAULT_COSTS 1

/* Currently, this constant can't simply be changed because the code currently
 * uses a static number of position slots (and may make other assumptions as
 * well).  */
#define LZX_MAX_WINDOW_SIZE	32768

/* This may be WIM-specific  */
#define LZX_DEFAULT_BLOCK_SIZE  32768

#define LZX_LZ_HASH_BITS	15
#define LZX_LZ_HASH_SIZE	(1 << LZX_LZ_HASH_BITS)
#define LZX_LZ_HASH_MASK	(LZX_LZ_HASH_SIZE - 1)
#define LZX_LZ_HASH_SHIFT	5

/* Codewords for the LZX main, length, and aligned offset Huffman codes  */
struct lzx_codewords {
	u16 main[LZX_MAINTREE_NUM_SYMBOLS];
	u16 len[LZX_LENTREE_NUM_SYMBOLS];
	u16 aligned[LZX_ALIGNEDTREE_NUM_SYMBOLS];
};

/* Lengths for the LZX main, length, and aligned offset Huffman codes  */
struct lzx_lens {
	u8 main[LZX_MAINTREE_NUM_SYMBOLS];
	u8 len[LZX_LENTREE_NUM_SYMBOLS];
	u8 aligned[LZX_ALIGNEDTREE_NUM_SYMBOLS];
};

/* The LZX main, length, and aligned offset Huffman codes  */
struct lzx_codes {
	struct lzx_codewords codewords;
	struct lzx_lens lens;
};

/* Tables for tallying symbol frequencies in the three LZX alphabets  */
struct lzx_freqs {
	freq_t main[LZX_MAINTREE_NUM_SYMBOLS];
	freq_t len[LZX_LENTREE_NUM_SYMBOLS];
	freq_t aligned[LZX_ALIGNEDTREE_NUM_SYMBOLS];
};

/* LZX intermediate match/literal format  */
struct lzx_match {
	/* Bit     Description
	 *
	 * 31      1 if a match, 0 if a literal.
	 *
	 * 30-25   position slot.  This can be at most 50, so it will fit in 6
	 *         bits.
	 *
	 * 8-24    position footer.  This is the offset of the real formatted
	 *         offset from the position base.  This can be at most 17 bits
	 *         (since lzx_extra_bits[LZX_NUM_POSITION_SLOTS - 1] is 17).
	 *
	 * 0-7     length of match, minus 2.  This can be at most
	 *         (LZX_MAX_MATCH - 2) == 255, so it will fit in 8 bits.  */
	u32 data;
};

/* Raw LZ match/literal format: just a length and offset.
 *
 * The length is the number of bytes of the match, and the offset is the number
 * of bytes back in the input the match is from the matched text.
 *
 * If @len < LZX_MIN_MATCH, then it's really just a literal byte and @offset is
 * meaningless.  */
struct raw_match {
	u16 len;
	u16 offset;
};

/* Specification for a LZX block  */
struct lzx_block_spec {

	/* Set to 1 if this block has been split (in two --- we only considser
	 * binary splits).  In such cases the rest of the fields are
	 * unimportant, since the relevant information is rather in the
	 * structures for the sub-blocks.  */
	u8 is_split : 1;

	/* One of the LZX_BLOCKTYPE_* constants indicating which type of this
	 * block.  */
	u8 block_type : 2;

	/* 0-based position in the window at which this block starts.  */
	u16 window_pos;

	/* The number of bytes of uncompressed data this block represents.  */
	u16 block_size;

	/* The position in the 'chosen_matches' array in the `struct
	 * lzx_compressor' at which the match/literal specifications for
	 * this block begin.  */
	unsigned chosen_matches_start_pos;

	/* The number of match/literal specifications for this block.  */
	u16 num_chosen_matches;

	/* Huffman codes for this block.  */
	struct lzx_codes codes;
};

/*
 * An array of these structures is used during the match-choosing algorithm.
 * They correspond to consecutive positions in the window and are used to keep
 * track of the cost to reach each position, and the match/literal choices that
 * need to be chosen to reach that position.
 */
struct lzx_optimal {
	/* The approximate minimum cost, in bits, to reach this position in the
	 * window which has been found so far.  */
	u32 cost;

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
			u16 link;

			/* Offset (as in a LZ (length, offset) pair) of the
			 * match or literal that was taken to get to this
			 * position in the approximate minimum-cost parse.  */
			u16 match_offset;
		} prev;
		struct {
			/* Position at which the match or literal starting at
			 * this position ends in the minimum-cost parse.  */
			u16 link;

			/* Offset (as in a LZ (length, offset) pair) of the
			 * match or literal starting at this position in the
			 * approximate minimum-cost parse.  */
			u16 match_offset;
		} next;
	};
#if LZX_PARAM_ACCOUNT_FOR_LRU
	struct lzx_lru_queue queue;
#endif
};

/* State of the LZX compressor  */
struct lzx_compressor {

	/* The parameters that were used to create the compressor.  */
	struct wimlib_lzx_params params;

	/* The buffer of data to be compressed.
	 *
	 * 0xe8 byte preprocessing is done directly on the data here before
	 * further compression.
	 *
	 * Note that this compressor does *not* use a sliding window!!!!
	 * It's not needed in the WIM format, since every chunk is compressed
	 * independently.  This is by design, to allow random access to the
	 * chunks.
	 *
	 * We reserve a few extra bytes to potentially allow reading off the end
	 * of the array in the match-finding code for optimization purposes.
	 */
	u8 window[LZX_MAX_WINDOW_SIZE + 12];

	/* Number of bytes of data to be compressed, which is the number of
	 * bytes of data in @window that are actually valid.  */
	unsigned window_size;

	/* The current match offset LRU queue.  */
	struct lzx_lru_queue queue;

	/* Space for sequence of matches/literals that were chosen.
	 *
	 * Each LZX_MAX_WINDOW_SIZE-sized portion of this array is used for a
	 * different block splitting level.  */
	struct lzx_match *chosen_matches;

	/* Structures used during block splitting.
	 *
	 * This can be thought of as a binary tree.  block_specs[(1) - 1]
	 * represents to the top-level block (root node), and block_specs[(i*2)
	 * - 1] and block_specs[(i*2+1) - 1] represent the sub-blocks (child
	 * nodes) resulting from a binary split of the block represented by
	 * block_spec[(i) - 1].
	 */
	struct lzx_block_spec *block_specs;

	/* This is simply filled in with zeroes and used to avoid special-casing
	 * the output of the first compressed Huffman code, which conceptually
	 * has a delta taken from a code with all symbols having zero-length
	 * codewords.  */
	struct lzx_codes zero_codes;

	/* Slow algorithm only: The current cost model.  */
	struct lzx_lens costs;

	/* Slow algorithm only:  Table that maps the hash codes for 3 character
	 * sequences to the most recent position that sequence (or a sequence
	 * sharing the same hash code) appeared in the window.  */
	u16 *hash_tab;

	/* Slow algorithm only:  Table that maps 2-character sequences to the
	 * most recent position that sequence appeared in the window.  */
	u16 *digram_tab;

	/* Slow algorithm only: Table that contains the logical child pointers
	 * in the binary trees in the match-finding code.
	 *
	 * child_tab[i*2] and child_tab[i*2+1] are the left and right pointers,
	 * respectively, from the binary tree root corresponding to window
	 * position i.  */
	u16 *child_tab;

	/* Slow algorithm only: Matches that were already found and are saved in
	 * memory for subsequent queries (e.g. when block splitting).  */
	struct raw_match *cached_matches;

	/* Slow algorithm only: Next position in 'cached_matches' to either
	 * return or fill in.  */
	unsigned cached_matches_pos;

	/* Slow algorithm only: %true if reading from 'cached_matches'; %false
	 * if writing to 'cached_matches'.  */
	bool matches_already_found;

	/* Slow algorithm only: Position in window of next match to return.  */
	unsigned match_window_pos;

	/* Slow algorithm only: No matches returned shall reach past this
	 * position.  */
	unsigned match_window_end;

	/* Slow algorithm only: Temporary space used for match-choosing
	 * algorithm.
	 *
	 * The size of this array must be at least LZX_MAX_MATCH but otherwise
	 * is arbitrary.  More space simply allows the match-choosing algorithm
	 * to find better matches (depending on the input, as always).  */
	struct lzx_optimal *optimum;

	/* Slow algorithm only: Variables used by the match-choosing algorithm.
	 *
	 * When matches have been chosen, optimum_cur_idx is set to the position
	 * in the window of the next match/literal to return and optimum_end_idx
	 * is set to the position in the window at the end of the last
	 * match/literal to return.  */
	u32 optimum_cur_idx;
	u32 optimum_end_idx;
};

/* Returns the LZX position slot that corresponds to a given formatted offset.
 *
 * Logically, this returns the smallest i such that
 * formatted_offset >= lzx_position_base[i].
 *
 * The actual implementation below takes advantage of the regularity of the
 * numbers in the lzx_position_base array to calculate the slot directly from
 * the formatted offset without actually looking at the array.
 */
static unsigned
lzx_get_position_slot(unsigned formatted_offset)
{
#if 0
	/*
	 * Slots 36-49 (formatted_offset >= 262144) can be found by
	 * (formatted_offset/131072) + 34 == (formatted_offset >> 17) + 34;
	 * however, this check for formatted_offset >= 262144 is commented out
	 * because WIM chunks cannot be that large.
	 */
	if (formatted_offset >= 262144) {
		return (formatted_offset >> 17) + 34;
	} else
#endif
	{
		/* Note: this part here only works if:
		 *
		 *    2 <= formatted_offset < 655360
		 *
		 * It is < 655360 because the frequency of the position bases
		 * increases starting at the 655360 entry, and it is >= 2
		 * because the below calculation fails if the most significant
		 * bit is lower than the 2's place. */
		LZX_ASSERT(2 <= formatted_offset  && formatted_offset < 655360);
		unsigned mssb_idx = bsr32(formatted_offset);
		return (mssb_idx << 1) |
			((formatted_offset >> (mssb_idx - 1)) & 1);
	}
}

/* Compute the hash code for the next 3-character sequence in the window.  */
static unsigned
lzx_lz_compute_hash(const u8 *window)
{
	unsigned hash;

	hash = window[0];
	hash <<= LZX_LZ_HASH_SHIFT;
	hash ^= window[1];
	hash <<= LZX_LZ_HASH_SHIFT;
	hash ^= window[2];
	return hash & LZX_LZ_HASH_MASK;
}

/* Build the main, length, and aligned offset Huffman codes used in LZX.
 *
 * This takes as input the frequency tables for each code and produces as output
 * a set of tables that map symbols to codewords and lengths.  */
static void
lzx_make_huffman_codes(const struct lzx_freqs *freqs,
		       struct lzx_codes *codes)
{
	make_canonical_huffman_code(LZX_MAINTREE_NUM_SYMBOLS,
				    LZX_MAX_CODEWORD_LEN,
				    freqs->main,
				    codes->lens.main,
				    codes->codewords.main);

	make_canonical_huffman_code(LZX_LENTREE_NUM_SYMBOLS,
				    LZX_MAX_CODEWORD_LEN,
				    freqs->len,
				    codes->lens.len,
				    codes->codewords.len);

	make_canonical_huffman_code(LZX_ALIGNEDTREE_NUM_SYMBOLS, 8,
				    freqs->aligned,
				    codes->lens.aligned,
				    codes->codewords.aligned);
}

/*
 * Output a LZX match.
 *
 * @out:         The bitstream to write the match to.
 * @block_type:  The type of the LZX block (LZX_BLOCKTYPE_ALIGNED or LZX_BLOCKTYPE_VERBATIM)
 * @match:	 The match.
 * @codes:	 Pointer to a structure that contains the codewords for the
 *		 main, length, and aligned offset Huffman codes.
 */
static void
lzx_write_match(struct output_bitstream *out, int block_type,
		struct lzx_match match, const struct lzx_codes *codes)
{
	/* low 8 bits are the match length minus 2 */
	unsigned match_len_minus_2 = match.data & 0xff;
	/* Next 17 bits are the position footer */
	unsigned position_footer = (match.data >> 8) & 0x1ffff;	/* 17 bits */
	/* Next 6 bits are the position slot. */
	unsigned position_slot = (match.data >> 25) & 0x3f;	/* 6 bits */
	unsigned len_header;
	unsigned len_footer;
	unsigned len_pos_header;
	unsigned main_symbol;
	unsigned num_extra_bits;
	unsigned verbatim_bits;
	unsigned aligned_bits;

	/* If the match length is less than MIN_MATCH (= 2) +
	 * NUM_PRIMARY_LENS (= 7), the length header contains
	 * the match length minus MIN_MATCH, and there is no
	 * length footer.
	 *
	 * Otherwise, the length header contains
	 * NUM_PRIMARY_LENS, and the length footer contains
	 * the match length minus NUM_PRIMARY_LENS minus
	 * MIN_MATCH. */
	if (match_len_minus_2 < LZX_NUM_PRIMARY_LENS) {
		len_header = match_len_minus_2;
		/* No length footer-- mark it with a special
		 * value. */
		len_footer = (unsigned)(-1);
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_footer = match_len_minus_2 - LZX_NUM_PRIMARY_LENS;
	}

	/* Combine the position slot with the length header into
	 * a single symbol that will be encoded with the main
	 * tree. */
	len_pos_header = (position_slot << 3) | len_header;

	/* The actual main symbol is offset by LZX_NUM_CHARS because
	 * values under LZX_NUM_CHARS are used to indicate a literal
	 * byte rather than a match. */
	main_symbol = len_pos_header + LZX_NUM_CHARS;

	/* Output main symbol. */
	bitstream_put_bits(out, codes->codewords.main[main_symbol],
			   codes->lens.main[main_symbol]);

	/* If there is a length footer, output it using the
	 * length Huffman code. */
	if (len_footer != (unsigned)(-1)) {
		bitstream_put_bits(out, codes->codewords.len[len_footer],
				   codes->lens.len[len_footer]);
	}

	num_extra_bits = lzx_get_num_extra_bits(position_slot);

	/* For aligned offset blocks with at least 3 extra bits, output the
	 * verbatim bits literally, then the aligned bits encoded using the
	 * aligned offset tree.  Otherwise, only the verbatim bits need to be
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

static unsigned
lzx_build_precode(const u8 lens[restrict],
		  const u8 prev_lens[restrict],
		  unsigned num_syms,
		  freq_t precode_freqs[restrict LZX_PRETREE_NUM_SYMBOLS],
		  u8 output_syms[restrict num_syms],
		  u8 precode_lens[restrict LZX_PRETREE_NUM_SYMBOLS],
		  u16 precode_codewords[restrict LZX_PRETREE_NUM_SYMBOLS],
		  unsigned * num_additional_bits_ret)
{
	unsigned output_syms_idx;
	unsigned cur_run_len;
	unsigned i;
	unsigned len_in_run;
	unsigned additional_bits;
	signed char delta;
	unsigned num_additional_bits = 0;

	memset(precode_freqs, 0,
	       LZX_PRETREE_NUM_SYMBOLS * sizeof(precode_freqs[0]));

	/* Since the code word lengths use a form of RLE encoding, the goal here
	 * is to find each run of identical lengths when going through them in
	 * symbol order (including runs of length 1).  For each run, as many
	 * lengths are encoded using RLE as possible, and the rest are output
	 * literally.
	 *
	 * output_syms[] will be filled in with the length symbols that will be
	 * output, including RLE codes, not yet encoded using the pre-tree.
	 *
	 * cur_run_len keeps track of how many code word lengths are in the
	 * current run of identical lengths.
	 */
	output_syms_idx = 0;
	cur_run_len = 1;
	for (i = 1; i <= num_syms; i++) {

		if (i != num_syms && lens[i] == lens[i - 1]) {
			/* Still in a run--- keep going. */
			cur_run_len++;
			continue;
		}

		/* Run ended! Check if it is a run of zeroes or a run of
		 * nonzeroes. */

		/* The symbol that was repeated in the run--- not to be confused
		 * with the length *of* the run (cur_run_len) */
		len_in_run = lens[i - 1];

		if (len_in_run == 0) {
			/* A run of 0's.  Encode it in as few length
			 * codes as we can. */

			/* The magic length 18 indicates a run of 20 + n zeroes,
			 * where n is an uncompressed literal 5-bit integer that
			 * follows the magic length. */
			while (cur_run_len >= 20) {

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
			 * in the run in the previous tree.
			 * */
			while (cur_run_len >= 4) {
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
		 * previous tree. */
		while (cur_run_len > 0) {
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

	make_canonical_huffman_code(LZX_PRETREE_NUM_SYMBOLS,
				    LZX_MAX_CODEWORD_LEN,
				    precode_freqs, precode_lens,
				    precode_codewords);

	if (num_additional_bits_ret)
		*num_additional_bits_ret = num_additional_bits;

	return output_syms_idx;
}

/*
 * Writes a compressed Huffman code to the output, preceded by the precode for
 * it.
 *
 * The Huffman code is represented in the output as a series of path lengths
 * from which the canonical Huffman code can be reconstructed.  The path lengths
 * themselves are compressed using a separate Huffman code, the precode, which
 * consists of LZX_PRETREE_NUM_SYMBOLS (= 20) symbols that cover all possible
 * code lengths, plus extra codes for repeated lengths.  The path lengths of the
 * precode precede the path lengths of the larger code and are uncompressed,
 * consisting of 20 entries of 4 bits each.
 *
 * @out:		Bitstream to write the code to.
 * @lens:		The code lengths for the Huffman code, indexed by symbol.
 * @prev_lens:		Code lengths for this Huffman code, indexed by symbol,
 *			in the *previous block*, or all zeroes if this is the
 *			first block.
 * @num_syms:		The number of symbols in the code.
 */
static void
lzx_write_compressed_code(struct output_bitstream *out,
			  const u8 lens[restrict],
			  const u8 prev_lens[restrict],
			  unsigned num_syms)
{
	freq_t precode_freqs[LZX_PRETREE_NUM_SYMBOLS];
	u8 output_syms[num_syms];
	u8 precode_lens[LZX_PRETREE_NUM_SYMBOLS];
	u16 precode_codewords[LZX_PRETREE_NUM_SYMBOLS];
	unsigned i;
	unsigned num_output_syms;
	u8 precode_sym;

	num_output_syms = lzx_build_precode(lens,
					    prev_lens,
					    num_syms,
					    precode_freqs,
					    output_syms,
					    precode_lens,
					    precode_codewords,
					    NULL);

	/* Write the lengths of the precode codes to the output. */
	for (i = 0; i < LZX_PRETREE_NUM_SYMBOLS; i++)
		bitstream_put_bits(out, precode_lens[i],
				   LZX_PRETREE_ELEMENT_SIZE);

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
 * Writes all compressed matches and literal bytes in a LZX block to the the
 * output bitstream.
 *
 * @ostream
 *	The output bitstream.
 * @block_type
 *	The type of the block (LZX_BLOCKTYPE_ALIGNED or LZX_BLOCKTYPE_VERBATIM).
 * @match_tab
 *	The array of matches/literals that will be output (length @match_count).
 * @match_count
 *	Number of matches/literals to be output.
 * @codes
 *	Pointer to a structure that contains the codewords for the main, length,
 *	and aligned offset Huffman codes.
 */
static void
lzx_write_matches_and_literals(struct output_bitstream *ostream,
			       int block_type,
			       const struct lzx_match match_tab[],
			       unsigned match_count,
			       const struct lzx_codes *codes)
{
	for (unsigned i = 0; i < match_count; i++) {
		struct lzx_match match = match_tab[i];

		/* High bit of the match indicates whether the match is an
		 * actual match (1) or a literal uncompressed byte (0)  */
		if (match.data & 0x80000000) {
			/* match */
			lzx_write_match(ostream, block_type,
					match, codes);
		} else {
			/* literal byte */
			bitstream_put_bits(ostream,
					   codes->codewords.main[match.data],
					   codes->lens.main[match.data]);
		}
	}
}


static void
lzx_assert_codes_valid(const struct lzx_codes * codes)
{
#ifdef ENABLE_LZX_DEBUG
	unsigned i;

	for (i = 0; i < LZX_MAINTREE_NUM_SYMBOLS; i++)
		LZX_ASSERT(codes->lens.main[i] <= LZX_MAX_CODEWORD_LEN);

	for (i = 0; i < LZX_LENTREE_NUM_SYMBOLS; i++)
		LZX_ASSERT(codes->lens.len[i] <= LZX_MAX_CODEWORD_LEN);

	for (i = 0; i < LZX_ALIGNEDTREE_NUM_SYMBOLS; i++)
		LZX_ASSERT(codes->lens.aligned[i] <= 8);

	const unsigned tablebits = 10;
	u16 decode_table[(1 << tablebits) +
			 (2 * max(LZX_MAINTREE_NUM_SYMBOLS, LZX_LENTREE_NUM_SYMBOLS))]
			 _aligned_attribute(DECODE_TABLE_ALIGNMENT);
	LZX_ASSERT(0 == make_huffman_decode_table(decode_table,
						  LZX_MAINTREE_NUM_SYMBOLS,
						  tablebits,
						  codes->lens.main,
						  LZX_MAX_CODEWORD_LEN));
	LZX_ASSERT(0 == make_huffman_decode_table(decode_table,
						  LZX_LENTREE_NUM_SYMBOLS,
						  tablebits,
						  codes->lens.len,
						  LZX_MAX_CODEWORD_LEN));
	LZX_ASSERT(0 == make_huffman_decode_table(decode_table,
						  LZX_ALIGNEDTREE_NUM_SYMBOLS,
						  min(tablebits, 6),
						  codes->lens.aligned,
						  8));
#endif /* ENABLE_LZX_DEBUG */
}

/* Write a LZX aligned offset or verbatim block to the output.  */
static void
lzx_write_compressed_block(int block_type,
			   unsigned block_size,
			   struct lzx_match * chosen_matches,
			   unsigned num_chosen_matches,
			   const struct lzx_codes * codes,
			   const struct lzx_codes * prev_codes,
			   struct output_bitstream * ostream)
{
	unsigned i;

	LZX_ASSERT(block_type == LZX_BLOCKTYPE_ALIGNED ||
		   block_type == LZX_BLOCKTYPE_VERBATIM);
	LZX_ASSERT(block_size <= LZX_MAX_WINDOW_SIZE);
	LZX_ASSERT(num_chosen_matches <= LZX_MAX_WINDOW_SIZE);
	lzx_assert_codes_valid(codes);

	/* The first three bits indicate the type of block and are one of the
	 * LZX_BLOCKTYPE_* constants.  */
	bitstream_put_bits(ostream, block_type, LZX_BLOCKTYPE_NBITS);

	/* The next bit indicates whether the block size is the default (32768),
	 * indicated by a 1 bit, or whether the block size is given by the next
	 * 16 bits, indicated by a 0 bit.  */
	if (block_size == LZX_DEFAULT_BLOCK_SIZE) {
		bitstream_put_bits(ostream, 1, 1);
	} else {
		bitstream_put_bits(ostream, 0, 1);
		bitstream_put_bits(ostream, block_size, LZX_BLOCKSIZE_NBITS);
	}

	/* Write out lengths of the main code. Note that the LZX specification
	 * incorrectly states that the aligned offset code comes after the
	 * length code, but in fact it is the very first tree to be written
	 * (before the main code).  */
	if (block_type == LZX_BLOCKTYPE_ALIGNED)
		for (i = 0; i < LZX_ALIGNEDTREE_NUM_SYMBOLS; i++)
			bitstream_put_bits(ostream, codes->lens.aligned[i],
					   LZX_ALIGNEDTREE_ELEMENT_SIZE);

	LZX_DEBUG("Writing main code...");

	/* Write the pre-tree and lengths for the first LZX_NUM_CHARS symbols in
	 * the main code, which are the codewords for literal bytes.  */
	lzx_write_compressed_code(ostream,
				  codes->lens.main,
				  prev_codes->lens.main,
				  LZX_NUM_CHARS);

	/* Write the pre-tree and lengths for the rest of the main code, which
	 * are the codewords for match headers.  */
	lzx_write_compressed_code(ostream,
				  codes->lens.main + LZX_NUM_CHARS,
				  prev_codes->lens.main + LZX_NUM_CHARS,
				  LZX_MAINTREE_NUM_SYMBOLS - LZX_NUM_CHARS);

	LZX_DEBUG("Writing length code...");

	/* Write the pre-tree and lengths for the length code.  */
	lzx_write_compressed_code(ostream,
				  codes->lens.len,
				  prev_codes->lens.len,
				  LZX_LENTREE_NUM_SYMBOLS);

	LZX_DEBUG("Writing matches and literals...");

	/* Write the actual matches and literals.  */
	lzx_write_matches_and_literals(ostream, block_type,
				       chosen_matches, num_chosen_matches,
				       codes);

	LZX_DEBUG("Done writing block.");
}

/* Write the LZX block of index @block_number, or write its children recursively
 * if it is a split block.
 *
 * @prev_codes is a pointer to the Huffman codes for the most recent block
 * written, or all zeroes if this is the first block.
 *
 * Return a pointer to the Huffman codes for the last block written.  */
static struct lzx_codes *
lzx_write_block_recursive(struct lzx_compressor *ctx,
			  unsigned block_number,
			  struct lzx_codes * prev_codes,
			  struct output_bitstream *ostream)
{
	struct lzx_block_spec *spec = &ctx->block_specs[block_number - 1];

	if (spec->is_split) {
		prev_codes = lzx_write_block_recursive(ctx, block_number * 2 + 0,
						       prev_codes, ostream);
		prev_codes = lzx_write_block_recursive(ctx, block_number * 2 + 1,
						       prev_codes, ostream);
	} else {
		LZX_DEBUG("Writing block #%u (type=%d, size=%u, num_chosen_matches=%u)...",
			  block_number, spec->block_type, spec->block_size,
			  spec->num_chosen_matches);
		lzx_write_compressed_block(spec->block_type,
					   spec->block_size,
					   &ctx->chosen_matches[spec->chosen_matches_start_pos],
					   spec->num_chosen_matches,
					   &spec->codes,
					   prev_codes,
					   ostream);
		prev_codes = &spec->codes;
	}
	return prev_codes;
}

/* Write out the LZX blocks that were computed.  */
static void
lzx_write_all_blocks(struct lzx_compressor *ctx, struct output_bitstream *ostream)
{
	lzx_write_block_recursive(ctx, 1, &ctx->zero_codes, ostream);
}

static u32
lzx_record_literal(u8 literal, void *_freqs)
{
	struct lzx_freqs *freqs = _freqs;

	freqs->main[literal]++;

	return (u32)literal;
}

/* Constructs a match from an offset and a length, and updates the LRU queue and
 * the frequency of symbols in the main, length, and aligned offset alphabets.
 * The return value is a 32-bit number that provides the match in an
 * intermediate representation documented below.  */
static u32
lzx_record_match(unsigned match_offset, unsigned match_len,
		 void *_freqs, void *_queue)
{
	struct lzx_freqs *freqs = _freqs;
	struct lzx_lru_queue *queue = _queue;
	unsigned position_slot;
	unsigned position_footer = 0;
	u32 len_header;
	u32 len_pos_header;
	unsigned len_footer;
	unsigned adjusted_match_len;

	LZX_ASSERT(match_len >= LZX_MIN_MATCH && match_len <= LZX_MAX_MATCH);

	/* If possible, encode this offset as a repeated offset. */
	if (match_offset == queue->R0) {
		position_slot = 0;
	} else if (match_offset == queue->R1) {
		swap(queue->R0, queue->R1);
		position_slot = 1;
	} else if (match_offset == queue->R2) {
		swap(queue->R0, queue->R2);
		position_slot = 2;
	} else {
		/* Not a repeated offset. */

		/* offsets of 0, 1, and 2 are reserved for the repeated offset
		 * codes, so non-repeated offsets must be encoded as 3+.  The
		 * minimum offset is 1, so encode the offsets offset by 2. */
		unsigned formatted_offset = match_offset + 2;

		queue->R2 = queue->R1;
		queue->R1 = queue->R0;
		queue->R0 = match_offset;

		/* The (now-formatted) offset will actually be encoded as a
		 * small position slot number that maps to a certain hard-coded
		 * offset (position base), followed by a number of extra bits---
		 * the position footer--- that are added to the position base to
		 * get the original formatted offset. */

		position_slot = lzx_get_position_slot(formatted_offset);
		position_footer = formatted_offset &
				  ((1 << lzx_get_num_extra_bits(position_slot)) - 1);
	}

	adjusted_match_len = match_len - LZX_MIN_MATCH;


	/* The match length must be at least 2, so let the adjusted match length
	 * be the match length minus 2.
	 *
	 * If it is less than 7, the adjusted match length is encoded as a 3-bit
	 * number offset by 2.  Otherwise, the 3-bit length header is all 1's
	 * and the actual adjusted length is given as a symbol encoded with the
	 * length tree, offset by 7.
	 */
	if (adjusted_match_len < LZX_NUM_PRIMARY_LENS) {
		len_header = adjusted_match_len;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_footer = adjusted_match_len - LZX_NUM_PRIMARY_LENS;
		freqs->len[len_footer]++;
	}
	len_pos_header = (position_slot << 3) | len_header;

	freqs->main[len_pos_header + LZX_NUM_CHARS]++;

	/* Equivalent to:
	 * if (lzx_extra_bits[position_slot] >= 3) */
	if (position_slot >= 8)
		freqs->aligned[position_footer & 7]++;

	/* Pack the position slot, position footer, and match length into an
	 * intermediate representation.
	 *
	 * bits    description
	 * ----    -----------------------------------------------------------
	 *
	 * 31      1 if a match, 0 if a literal.
	 *
	 * 30-25   position slot.  This can be at most 50, so it will fit in 6
	 *         bits.
	 *
	 * 8-24    position footer.  This is the offset of the real formatted
	 *         offset from the position base.  This can be at most 17 bits
	 *         (since lzx_extra_bits[LZX_NUM_POSITION_SLOTS - 1] is 17).
	 *
	 * 0-7     length of match, offset by 2.  This can be at most
	 *         (LZX_MAX_MATCH - 2) == 255, so it will fit in 8 bits.  */
	return 0x80000000 |
		(position_slot << 25) |
		(position_footer << 8) |
		(adjusted_match_len);
}

/* Set the cost model @ctx->costs from the Huffman codeword lengths specified in
 * @lens.
 *
 * These are basically the same thing, except that the Huffman codewords with
 * length 0 correspond to symbols with zero frequency that still need to be
 * assigned actual costs.  The specific values assigned are arbitrary, but they
 * should be fairly high (near the maximum codeword length) to take into account
 * the fact that uses of these symbols are expected to be rare.
 */
static void
lzx_set_costs(struct lzx_compressor * ctx, const struct lzx_lens * lens)
{
	unsigned i;

	memcpy(&ctx->costs, lens, sizeof(struct lzx_lens));

	for (i = 0; i < LZX_MAINTREE_NUM_SYMBOLS; i++)
		if (ctx->costs.main[i] == 0)
			ctx->costs.main[i] = ctx->params.alg_params.slow.main_nostat_cost;

	for (i = 0; i < LZX_LENTREE_NUM_SYMBOLS; i++)
		if (ctx->costs.len[i] == 0)
			ctx->costs.len[i] = ctx->params.alg_params.slow.len_nostat_cost;

	for (i = 0; i < LZX_ALIGNEDTREE_NUM_SYMBOLS; i++)
		if (ctx->costs.aligned[i] == 0)
			ctx->costs.aligned[i] = ctx->params.alg_params.slow.aligned_nostat_cost;
}

static u32
lzx_literal_cost(u8 c, const struct lzx_lens * costs)
{
	return costs->main[c];
}

/* Given a (length, offset) pair that could be turned into a valid LZX match as
 * well as costs for the codewords in the main, length, and aligned Huffman
 * codes, return the approximate number of bits it will take to represent this
 * match in the compressed output.  */
static unsigned
lzx_match_cost(unsigned length, unsigned offset, const struct lzx_lens *costs

#if LZX_PARAM_ACCOUNT_FOR_LRU
	       , struct lzx_lru_queue *queue
#endif
	)
{
	unsigned position_slot, len_header, main_symbol;
	unsigned cost = 0;

	/* Calculate position slot and length header, then combine them into the
	 * main symbol.  */

#if LZX_PARAM_ACCOUNT_FOR_LRU
	if (offset == queue->R0) {
		position_slot = 0;
	} else if (offset == queue->R1) {
		swap(queue->R0, queue->R1);
		position_slot = 1;
	} else if (offset == queue->R2) {
		swap(queue->R0, queue->R2);
		position_slot = 2;
	} else
#endif
		position_slot = lzx_get_position_slot(offset + 2);

	len_header = min(length - LZX_MIN_MATCH, LZX_NUM_PRIMARY_LENS);
	main_symbol = ((position_slot << 3) | len_header) + LZX_NUM_CHARS;

	/* Account for main symbol.  */
	cost += costs->main[main_symbol];

	/* Account for extra position information.  */
	unsigned num_extra_bits = lzx_get_num_extra_bits(position_slot);
	if (num_extra_bits >= 3) {
		cost += num_extra_bits - 3;
		cost += costs->aligned[(offset + LZX_MIN_MATCH) & 7];
	} else {
		cost += num_extra_bits;
	}

	/* Account for extra length information.  */
	if (length - LZX_MIN_MATCH >= LZX_NUM_PRIMARY_LENS)
		cost += costs->len[length - LZX_MIN_MATCH - LZX_NUM_PRIMARY_LENS];

	return cost;
}

/* This procedure effectively creates a new binary tree corresponding to the
 * current string at the same time that it searches the existing tree nodes for
 * matches.  This is the same algorithm as that used in GetMatchesSpec1() in
 * 7-Zip, but it is hopefully explained a little more clearly below.  */
static unsigned
lzx_lz_get_matches(const u8 window[restrict],
		   const unsigned bytes_remaining,
		   const unsigned strstart,
		   const unsigned max_length,
		   u16 child_tab[restrict],
		   unsigned cur_match,
		   const unsigned prev_len,
		   struct raw_match * const matches)
{
	u16 *new_tree_lt_ptr = &child_tab[strstart * 2];
	u16 *new_tree_gt_ptr = &child_tab[strstart * 2 + 1];

	u16 longest_lt_match_len = 0;
	u16 longest_gt_match_len = 0;

	/* Maximum number of nodes to walk down before stopping  */
	unsigned depth = max_length;

	/* Length of longest match found so far  */
	unsigned longest_match_len = prev_len;

	/* Maximum length of match to return  */
	unsigned len_limit = min(bytes_remaining, max_length);

	/* Number of matches found so far  */
	unsigned num_matches = 0;

	for (;;) {

		/* Stop if too many nodes were traversed or if there is no next
		 * node  */
		if (depth-- == 0 || cur_match == 0) {
			*new_tree_gt_ptr = 0;
			*new_tree_lt_ptr = 0;
			return num_matches;
		}

		/* Load the pointers to the children of the binary tree node
		 * corresponding to the current match  */
		u16 * const cur_match_ptrs = &child_tab[cur_match * 2];

		/* Set up pointers to the current match and to the current
		 * string  */
		const u8 * const matchptr = &window[cur_match];
		const u8 * const strptr = &window[strstart];

		/* Determine position at which to start comparing  */
		u16 len = min(longest_lt_match_len,
			      longest_gt_match_len);

		if (matchptr[len] == strptr[len]) {

			/* Extend the match as far as possible.  */
			while (++len != len_limit)
				if (matchptr[len] != strptr[len])
					break;

			/* Record this match if it is the longest found so far.
			 */
			if (len > longest_match_len) {
				longest_match_len = len;
				matches[num_matches].len = len;
				matches[num_matches].offset = strstart - cur_match;
				num_matches++;

				if (len == len_limit) {
					/* Length limit was reached.  Link left pointer
					 * in the new tree with left subtree of current
					 * match tree, and link the right pointer in the
					 * new tree with the right subtree of the
					 * current match tree.  This in effect deletes
					 * the node for the currrent match, which is
					 * desirable because the current match is the
					 * same as the current string up until the
					 * length limit, so in subsequent queries it
					 * will never be preferable to the current
					 * position.  */
					*new_tree_lt_ptr = cur_match_ptrs[0];
					*new_tree_gt_ptr = cur_match_ptrs[1];
					return num_matches;
				}
			}
		}

		if (matchptr[len] < strptr[len]) {
			/* Case 1:  The current match is lexicographically less
			 * than the current string.
			 *
			 * Since we are searching the binary tree structures, we
			 * need to walk down to the *right* subtree of the
			 * current match's node to get to a match that is
			 * lexicographically *greater* than the current match
			 * but still lexicographically *lesser* than the current
			 * string.
			 *
			 * At the same time, we link the entire binary tree
			 * corresponding to the current match into the
			 * appropriate place in the new binary tree being built
			 * for the current string.  */
			*new_tree_lt_ptr = cur_match;
			new_tree_lt_ptr = &cur_match_ptrs[1];
			cur_match = *new_tree_lt_ptr;
			longest_lt_match_len = len;
		} else {
			/* Case 2:  The current match is lexicographically
			 * greater than the current string.
			 *
			 * This is analogous to Case 1 above, but everything
			 * happens in the other direction.
			 */
			*new_tree_gt_ptr = cur_match;
			new_tree_gt_ptr = &cur_match_ptrs[0];
			cur_match = *new_tree_gt_ptr;
			longest_gt_match_len = len;
		}
	}
}

/* Equivalent to lzx_lz_get_matches(), but only updates the tree and doesn't
 * return matches.  See that function for details (including comments).  */
static void
lzx_lz_skip_matches(const u8 window[restrict],
		    const unsigned bytes_remaining,
		    const unsigned strstart,
		    const unsigned max_length,
		    u16 child_tab[restrict],
		    unsigned cur_match,
		    const unsigned prev_len)
{
	u16 *new_tree_lt_ptr = &child_tab[strstart * 2];
	u16 *new_tree_gt_ptr = &child_tab[strstart * 2 + 1];

	u16 longest_lt_match_len = 0;
	u16 longest_gt_match_len = 0;

	unsigned depth = max_length;

	unsigned longest_match_len = prev_len;

	unsigned len_limit = min(bytes_remaining, max_length);

	for (;;) {
		if (depth-- == 0 || cur_match == 0) {
			*new_tree_gt_ptr = 0;
			*new_tree_lt_ptr = 0;
			return;
		}

		u16 * const cur_match_ptrs = &child_tab[cur_match * 2];

		const u8 * const matchptr = &window[cur_match];
		const u8 * const strptr = &window[strstart];

		u16 len = min(longest_lt_match_len,
			      longest_gt_match_len);

		if (matchptr[len] == strptr[len]) {
			while (++len != len_limit)
				if (matchptr[len] != strptr[len])
					break;

			if (len > longest_match_len) {
				longest_match_len = len;

				if (len == len_limit) {
					*new_tree_lt_ptr = cur_match_ptrs[0];
					*new_tree_gt_ptr = cur_match_ptrs[1];
					return;
				}
			}
		}

		if (matchptr[len] < strptr[len]) {
			*new_tree_lt_ptr = cur_match;
			new_tree_lt_ptr = &cur_match_ptrs[1];
			cur_match = *new_tree_lt_ptr;
			longest_lt_match_len = len;
		} else {
			*new_tree_gt_ptr = cur_match;
			new_tree_gt_ptr = &cur_match_ptrs[0];
			cur_match = *new_tree_gt_ptr;
			longest_gt_match_len = len;
		}
	}
}

static unsigned
lzx_lz_get_matches_caching(struct lzx_compressor *ctx,
			   struct raw_match **matches_ret);

/* Tell the match-finder to skip the specified number of bytes (@n) in the
 * input.  */
static void
lzx_lz_skip_bytes(struct lzx_compressor *ctx, unsigned n)
{

#if LZX_PARAM_DONT_SKIP_MATCHES
	/* Option 1: Still cache the matches from the positions skipped.  They
	 * will then be available in later passes.  */
	struct raw_match *matches;
	while (n--)
		lzx_lz_get_matches_caching(ctx, &matches);
#else
	/* Option 2: Mark the positions skipped as having no matches available,
	 * but we still need to update the binary tree in case subsequent
	 * positions have matches at the current position.  */
	LZX_ASSERT(n <= ctx->match_window_end - ctx->match_window_pos);
	if (ctx->matches_already_found) {
		while (n--) {
			LZX_ASSERT(ctx->cached_matches[ctx->cached_matches_pos].offset ==
				   ctx->match_window_pos);
			ctx->cached_matches_pos += ctx->cached_matches[ctx->cached_matches_pos].len + 1;
			ctx->match_window_pos++;
		}
	} else {
		while (n--) {
			if (ctx->params.alg_params.slow.use_len2_matches &&
			    ctx->match_window_end - ctx->match_window_pos >= 2) {
				unsigned c1 = ctx->window[ctx->match_window_pos];
				unsigned c2 = ctx->window[ctx->match_window_pos + 1];
				unsigned digram = c1 | (c2 << 8);
				ctx->digram_tab[digram] = ctx->match_window_pos;
			}
			if (ctx->match_window_end - ctx->match_window_pos >= 3) {
				unsigned hash;
				unsigned cur_match;

				hash = lzx_lz_compute_hash(&ctx->window[ctx->match_window_pos]);

				cur_match = ctx->hash_tab[hash];
				ctx->hash_tab[hash] = ctx->match_window_pos;

				lzx_lz_skip_matches(ctx->window,
						    ctx->match_window_end - ctx->match_window_pos,
						    ctx->match_window_pos,
						    ctx->params.alg_params.slow.num_fast_bytes,
						    ctx->child_tab,
						    cur_match, 1);
			}
			ctx->cached_matches[ctx->cached_matches_pos].len = 0;
			ctx->cached_matches[ctx->cached_matches_pos].offset = ctx->match_window_pos;
			ctx->cached_matches_pos++;
			ctx->match_window_pos++;
		}
	}
#endif /* !LZX_PARAM_DONT_SKIP_MATCHES */
}

/* Retrieve a list of matches available at the next position in the input.
 *
 * The return value is the number of matches found, and a pointer to them is
 * written to @matches_ret.  The matches will be sorted in order by length.
 *
 * This is essentially a wrapper around lzx_lz_get_matches() that caches its
 * output the first time and also performs the needed hashing.
 */
static unsigned
lzx_lz_get_matches_caching(struct lzx_compressor *ctx,
			   struct raw_match **matches_ret)
{
	unsigned num_matches;
	struct raw_match *matches;

	LZX_ASSERT(ctx->match_window_end >= ctx->match_window_pos);

	matches = &ctx->cached_matches[ctx->cached_matches_pos + 1];

	if (ctx->matches_already_found) {
		num_matches = ctx->cached_matches[ctx->cached_matches_pos].len;
		LZX_ASSERT(ctx->cached_matches[ctx->cached_matches_pos].offset == ctx->match_window_pos);

		for (int i = (int)num_matches - 1; i >= 0; i--) {
			if (ctx->match_window_pos + matches[i].len > ctx->match_window_end)
				matches[i].len = ctx->match_window_end - ctx->match_window_pos;
			else
				break;
		}
	} else {
		unsigned prev_len = 1;
		struct raw_match * matches_ret = &ctx->cached_matches[ctx->cached_matches_pos + 1];
		num_matches = 0;

		if (ctx->params.alg_params.slow.use_len2_matches &&
		    ctx->match_window_end - ctx->match_window_pos >= 3) {
			unsigned c1 = ctx->window[ctx->match_window_pos];
			unsigned c2 = ctx->window[ctx->match_window_pos + 1];
			unsigned digram = c1 | (c2 << 8);
			unsigned cur_match;

			cur_match = ctx->digram_tab[digram];
			ctx->digram_tab[digram] = ctx->match_window_pos;
			if (cur_match != 0 &&
			    ctx->window[cur_match + 2] != ctx->window[ctx->match_window_pos + 2])
			{
				matches_ret->len = 2;
				matches_ret->offset = ctx->match_window_pos - cur_match;
				matches_ret++;
				num_matches++;
				prev_len = 2;
			}
		}
		if (ctx->match_window_end - ctx->match_window_pos >= 3) {
			unsigned hash;
			unsigned cur_match;

			hash = lzx_lz_compute_hash(&ctx->window[ctx->match_window_pos]);

			cur_match = ctx->hash_tab[hash];
			ctx->hash_tab[hash] = ctx->match_window_pos;
			num_matches += lzx_lz_get_matches(ctx->window,
							  ctx->match_window_end - ctx->match_window_pos,
							  ctx->match_window_pos,
							  ctx->params.alg_params.slow.num_fast_bytes,
							  ctx->child_tab,
							  cur_match,
							  prev_len,
							  matches_ret);
		}

		ctx->cached_matches[ctx->cached_matches_pos].len = num_matches;
		ctx->cached_matches[ctx->cached_matches_pos].offset = ctx->match_window_pos;

		if (num_matches) {
			struct raw_match *longest_match_ptr =
				&ctx->cached_matches[ctx->cached_matches_pos + 1 +
						     num_matches - 1];
			u16 len = longest_match_ptr->len;

			/* If the longest match returned by the match-finder
			 * reached the number of fast bytes, extend it as much
			 * as possible.  */
			if (len == ctx->params.alg_params.slow.num_fast_bytes) {
				const unsigned maxlen =
					min(ctx->match_window_end - ctx->match_window_pos,
					    LZX_MAX_MATCH);

				const u8 * const matchptr =
					&ctx->window[ctx->match_window_pos - longest_match_ptr->offset];

				const u8 * const strptr =
					&ctx->window[ctx->match_window_pos];

				while (len < maxlen && matchptr[len] == strptr[len])
					len++;
			}
			longest_match_ptr->len = len;
		}
	}
	ctx->cached_matches_pos += num_matches + 1;
	*matches_ret = matches;

#if 0
	printf("\n");
	for (unsigned i = 0; i < num_matches; i++)
	{
		printf("Len %u Offset %u\n", matches[i].len, matches[i].offset);
	}
#endif

	for (unsigned i = 0; i < num_matches; i++) {
		LZX_ASSERT(matches[i].len <= LZX_MAX_MATCH);
		if (matches[i].len >= LZX_MIN_MATCH) {
			LZX_ASSERT(matches[i].offset <= ctx->match_window_pos);
			LZX_ASSERT(matches[i].len <= ctx->match_window_end - ctx->match_window_pos);
			LZX_ASSERT(!memcmp(&ctx->window[ctx->match_window_pos],
					   &ctx->window[ctx->match_window_pos - matches[i].offset],
					   matches[i].len));
		}
	}

	ctx->match_window_pos++;
	return num_matches;
}

/*
 * Reverse the linked list of near-optimal matches so that they can be returned
 * in forwards order.
 *
 * Returns the first match in the list.
 */
static struct raw_match
lzx_lz_reverse_near_optimal_match_list(struct lzx_compressor *ctx,
				       unsigned cur_pos)
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

	return (struct raw_match)
		{ .len = ctx->optimum_cur_idx,
		  .offset = ctx->optimum[0].next.match_offset,
		};
}

/*
 * lzx_lz_get_near_optimal_match() -
 *
 * Choose the "best" match or literal to use at the next position in the input.
 *
 * Unlike a "greedy" parser that always takes the longest match, or even a
 * parser with one match/literal look-ahead like zlib, the algorithm used here
 * may look ahead many matches/literals to determine the best match/literal to
 * output next.  The motivation is that the compression ratio is improved if the
 * compressor can do things like use a shorter-than-possible match in order to
 * allow a longer match later, and also take into account the Huffman code cost
 * model rather than simply assuming that longer is better.  It is not a true
 * "optimal" parser, however, since some shortcuts can be taken; for example, if
 * a match is very long, the parser just chooses it immediately before too much
 * time is wasting considering many different alternatives that are unlikely to
 * be better.
 *
 * This algorithm is based on that used in 7-Zip's DEFLATE encoder.
 *
 * Each call to this function does one of two things:
 *
 * 1. Build a near-optimal sequence of matches/literals, up to some point, that
 *    will be returned by subsequent calls to this function, then return the
 *    first one.
 *
 * OR
 *
 * 2. Return the next match/literal previously computed by a call to this
 *    function;
 *
 * This function relies on the following state in the compressor context:
 *
 *	ctx->window	     (read-only: preprocessed data being compressed)
 *	ctx->cost	     (read-only: cost model to use)
 *	ctx->optimum	     (internal state; leave uninitialized)
 *	ctx->optimum_cur_idx (must set to 0 before first call)
 *	ctx->optimum_end_idx (must set to 0 before first call)
 *	ctx->hash_tab	     (must set to 0 before first call)
 *	ctx->cached_matches  (internal state; leave uninitialized)
 *	ctx->cached_matches_pos (initialize to 0 before first call; save and
 *				 restore value if restarting parse from a
 *				 certain position)
 *	ctx->match_window_pos (must initialize to position of next match to
 *			       return; subsequent calls return subsequent
 *			       matches)
 *	ctx->match_window_end (must initialize to limit of match-finding region;
 *			       subsequent calls use the same limit)
 *
 * The return value is a (length, offset) pair specifying the match or literal
 * chosen.  For literals, length is either 0 or 1 and offset is meaningless.
 */
static struct raw_match
lzx_lz_get_near_optimal_match(struct lzx_compressor * ctx)
{
#if 0
	/* Testing: literals only  */
	ctx->match_window_pos++;
	return (struct raw_match) { .len = 0 };
#elif 0
	/* Testing: greedy parsing  */
	struct raw_match *matches;
	unsigned num_matches;
	struct raw_match match = {.len = 0};

	num_matches = lzx_lz_get_matches_caching(ctx, &matches);
	if (num_matches) {
		match = matches[num_matches - 1];
		lzx_lz_skip_bytes(ctx, match.len - 1);
	}
	return match;
#else
	unsigned num_possible_matches;
	struct raw_match *possible_matches;
	struct raw_match match;
	unsigned longest_match_len;
	unsigned len, match_idx;

	if (ctx->optimum_cur_idx != ctx->optimum_end_idx) {
		/* Case 2: Return the next match/literal already found.  */
		match.len = ctx->optimum[ctx->optimum_cur_idx].next.link -
				    ctx->optimum_cur_idx;
		match.offset = ctx->optimum[ctx->optimum_cur_idx].next.match_offset;

		ctx->optimum_cur_idx = ctx->optimum[ctx->optimum_cur_idx].next.link;
		return match;
	}

	/* Case 1:  Compute a new list of matches/literals to return.  */

	ctx->optimum_cur_idx = 0;
	ctx->optimum_end_idx = 0;

	/* Get matches at this position.  */
	num_possible_matches = lzx_lz_get_matches_caching(ctx, &possible_matches);

	/* If no matches found, return literal.  */
	if (num_possible_matches == 0)
		return (struct raw_match){ .len = 0 };

	/* The matches that were found are sorted by length.  Get the length of
	 * the longest one.  */
	longest_match_len = possible_matches[num_possible_matches - 1].len;

	/* Greedy heuristic:  if the longest match that was found is greater
	 * than the number of fast bytes, return it immediately; don't both
	 * doing more work.  */
	if (longest_match_len > ctx->params.alg_params.slow.num_fast_bytes) {
		lzx_lz_skip_bytes(ctx, longest_match_len - 1);
		return possible_matches[num_possible_matches - 1];
	}

	/* Calculate the cost to reach the next position by outputting a
	 * literal.  */
#if LZX_PARAM_ACCOUNT_FOR_LRU
	ctx->optimum[0].queue = ctx->queue;
	ctx->optimum[1].queue = ctx->optimum[0].queue;
#endif
	ctx->optimum[1].cost = lzx_literal_cost(ctx->window[ctx->match_window_pos],
						&ctx->costs);
	ctx->optimum[1].prev.link = 0;

	/* Calculate the cost to reach any position up to and including that
	 * reached by the longest match, using the shortest (i.e. closest) match
	 * that reaches each position.  */
	match_idx = 0;
	BUILD_BUG_ON(LZX_MIN_MATCH != 2);
	for (len = LZX_MIN_MATCH; len <= longest_match_len; len++) {

		LZX_ASSERT(match_idx < num_possible_matches);

	#if LZX_PARAM_ACCOUNT_FOR_LRU
		ctx->optimum[len].queue = ctx->optimum[0].queue;
	#endif
		ctx->optimum[len].prev.link = 0;
		ctx->optimum[len].prev.match_offset = possible_matches[match_idx].offset;
		ctx->optimum[len].cost = lzx_match_cost(len,
							possible_matches[match_idx].offset,
							&ctx->costs
						#if LZX_PARAM_ACCOUNT_FOR_LRU
							, &ctx->optimum[len].queue
						#endif
							);
		if (len == possible_matches[match_idx].len)
			match_idx++;
	}

	unsigned cur_pos = 0;

	/* len_end: greatest index forward at which costs have been calculated
	 * so far  */
	unsigned len_end = longest_match_len;


	for (;;) {
		/* Advance to next position.  */
		cur_pos++;

		if (cur_pos == len_end || cur_pos == LZX_PARAM_OPTIM_ARRAY_SIZE)
			return lzx_lz_reverse_near_optimal_match_list(ctx, cur_pos);

		/* retrieve the number of matches available at this position  */
		num_possible_matches = lzx_lz_get_matches_caching(ctx,
								  &possible_matches);

		unsigned new_len = 0;

		if (num_possible_matches != 0) {
			new_len = possible_matches[num_possible_matches - 1].len;

			/* Greedy heuristic:  if we found a match greater than
			 * the number of fast bytes, stop immediately.  */
			if (new_len > ctx->params.alg_params.slow.num_fast_bytes) {

				/* Build the list of matches to return and get
				 * the first one.  */
				match = lzx_lz_reverse_near_optimal_match_list(ctx, cur_pos);

				/* Append the long match to the end of the list.  */
				ctx->optimum[cur_pos].next.match_offset =
					possible_matches[num_possible_matches - 1].offset;
				ctx->optimum[cur_pos].next.link = cur_pos + new_len;
				ctx->optimum_end_idx = cur_pos + new_len;

				/* Skip over the remaining bytes of the long match.  */
				lzx_lz_skip_bytes(ctx, new_len - 1);

				/* Return first match in the list  */
				return match;
			}
		}

		/* Consider proceeding with a literal byte.  */
		u32 cur_cost = ctx->optimum[cur_pos].cost;
		u32 cur_plus_literal_cost = cur_cost +
			lzx_literal_cost(ctx->window[ctx->match_window_pos - 1],
					 &ctx->costs);
		if (cur_plus_literal_cost < ctx->optimum[cur_pos + 1].cost) {
			ctx->optimum[cur_pos + 1].cost = cur_plus_literal_cost;
			ctx->optimum[cur_pos + 1].prev.link = cur_pos;
		#if LZX_PARAM_ACCOUNT_FOR_LRU
			ctx->optimum[cur_pos + 1].queue = ctx->optimum[cur_pos].queue;
		#endif
		}

		if (num_possible_matches == 0)
			continue;

		/* Consider proceeding with a match.  */

		while (len_end < cur_pos + new_len)
			ctx->optimum[++len_end].cost = ~(u32)0;

		match_idx = 0;
		for (len = LZX_MIN_MATCH; len <= new_len; len++) {
			LZX_ASSERT(match_idx < num_possible_matches);
		#if LZX_PARAM_ACCOUNT_FOR_LRU
			struct lzx_lru_queue q = ctx->optimum[cur_pos].queue;
		#endif
			u32 cost = cur_cost + lzx_match_cost(len,
							     possible_matches[match_idx].offset,
							     &ctx->costs
							#if LZX_PARAM_ACCOUNT_FOR_LRU
							     , &q
							#endif
							     );

			if (cost < ctx->optimum[cur_pos + len].cost) {
				ctx->optimum[cur_pos + len].cost = cost;
				ctx->optimum[cur_pos + len].prev.link = cur_pos;
				ctx->optimum[cur_pos + len].prev.match_offset =
						possible_matches[match_idx].offset;
			#if LZX_PARAM_ACCOUNT_FOR_LRU
				ctx->optimum[cur_pos + len].queue = q;
			#endif
			}

			if (len == possible_matches[match_idx].len)
				match_idx++;
		}
	}
#endif
}

static unsigned
lzx_huffman_code_output_cost(const u8 lens[restrict],
			     const freq_t freqs[restrict],
			     unsigned num_syms)
{
	unsigned cost = 0;

	for (unsigned i = 0; i < num_syms; i++)
		cost += (unsigned)lens[i] * (unsigned)freqs[i];

	return cost;
}

/* Return the number of bits required to output the lengths for the specified
 * Huffman code in compressed format (encoded with a precode).  */
static unsigned
lzx_code_cost(const u8 lens[], const u8 prev_lens[], unsigned num_syms)
{
	u8 output_syms[num_syms];
	freq_t precode_freqs[LZX_PRETREE_NUM_SYMBOLS];
	u8 precode_lens[LZX_PRETREE_NUM_SYMBOLS];
	u16 precode_codewords[LZX_PRETREE_NUM_SYMBOLS];
	unsigned cost = 0;
	unsigned num_additional_bits;

	/* Acount for the lengths of the precode itself.  */
	cost += LZX_PRETREE_NUM_SYMBOLS * LZX_PRETREE_ELEMENT_SIZE;

	lzx_build_precode(lens, prev_lens, num_syms,
			  precode_freqs, output_syms,
			  precode_lens, precode_codewords,
			  &num_additional_bits);

	/* Account for all precode symbols output.  */
	cost += lzx_huffman_code_output_cost(precode_lens, precode_freqs,
					     LZX_PRETREE_NUM_SYMBOLS);

	/* Account for additional bits.  */
	cost += num_additional_bits;

	return cost;
}

/* Account for extra bits in the main symbols.  */
static void
lzx_update_mainsym_match_costs(int block_type,
			       u8 main_lens[LZX_MAINTREE_NUM_SYMBOLS])
{
	unsigned i;

	LZX_ASSERT(block_type == LZX_BLOCKTYPE_ALIGNED ||
		   block_type == LZX_BLOCKTYPE_VERBATIM);

	for (i = LZX_NUM_CHARS; i < LZX_MAINTREE_NUM_SYMBOLS; i++) {
		unsigned position_slot = (i >> 3) & 0x1f;

		/* If it's a verbatim block, add the number of extra bits
		 * corresponding to the position slot.
		 *
		 * If it's an aligned block and there would normally be at least
		 * 3 extra bits, count 3 less because they will be output as an
		 * aligned offset symbol instead.  */
		unsigned num_extra_bits = lzx_get_num_extra_bits(position_slot);

		if (block_type == LZX_BLOCKTYPE_ALIGNED && num_extra_bits >= 3)
			num_extra_bits -= 3;
		main_lens[i] += num_extra_bits;
	}
}

/*
 * Compute the costs, in bits, to output a compressed block as aligned offset
 * and verbatim.
 *
 * @block_size
 *	Number of bytes of uncompressed data the block represents.
 * @codes
 *	Huffman codes that will be used when outputting the block.
 * @prev_codes
 *	Huffman codes for the previous block, or all zeroes if this is the first
 *	block.
 * @freqs
 *	Frequencies of Huffman symbols that will be output in the block.
 * @aligned_cost_ret
 *	Cost of aligned block will be returned here.
 * @verbatim_cost_ret
 *	Cost of verbatim block will be returned here.
 */
static void
lzx_compute_compressed_block_costs(unsigned block_size,
				   const struct lzx_codes *codes,
				   const struct lzx_codes *prev_codes,
				   const struct lzx_freqs *freqs,
				   unsigned * aligned_cost_ret,
				   unsigned * verbatim_cost_ret)
{
	unsigned common_cost = 0;
	unsigned aligned_cost = 0;
	unsigned verbatim_cost = 0;

	u8 updated_main_lens[LZX_MAINTREE_NUM_SYMBOLS];

	/* Account for cost of block header.  */
	common_cost += LZX_BLOCKTYPE_NBITS;
	if (block_size == LZX_DEFAULT_BLOCK_SIZE)
		common_cost += 1;
	else
		common_cost += LZX_BLOCKSIZE_NBITS;

	/* Account for cost of outputting aligned offset code.  */
	aligned_cost += LZX_ALIGNEDTREE_NUM_SYMBOLS * LZX_ALIGNEDTREE_ELEMENT_SIZE;

	/* Account for cost of outputting main and length codes.  */
	common_cost += lzx_code_cost(codes->lens.main,
				     prev_codes->lens.main,
				     LZX_NUM_CHARS);
	common_cost += lzx_code_cost(codes->lens.main + LZX_NUM_CHARS,
				     prev_codes->lens.main + LZX_NUM_CHARS,
				     LZX_MAINTREE_NUM_SYMBOLS - LZX_NUM_CHARS);
	common_cost += lzx_code_cost(codes->lens.len,
				     prev_codes->lens.len,
				     LZX_LENTREE_NUM_SYMBOLS);

	/* Account for cost to output main, length, and aligned symbols, taking
	 * into account extra position bits.  */

	memcpy(updated_main_lens, codes->lens.main, LZX_MAINTREE_NUM_SYMBOLS);
	lzx_update_mainsym_match_costs(LZX_BLOCKTYPE_VERBATIM, updated_main_lens);
	verbatim_cost += lzx_huffman_code_output_cost(updated_main_lens,
						      freqs->main,
						      LZX_MAINTREE_NUM_SYMBOLS);
	memcpy(updated_main_lens, codes->lens.main, LZX_MAINTREE_NUM_SYMBOLS);
	lzx_update_mainsym_match_costs(LZX_BLOCKTYPE_ALIGNED, updated_main_lens);
	aligned_cost += lzx_huffman_code_output_cost(updated_main_lens,
						     freqs->main,
						     LZX_MAINTREE_NUM_SYMBOLS);

	common_cost += lzx_huffman_code_output_cost(codes->lens.len,
						    freqs->len,
						    LZX_LENTREE_NUM_SYMBOLS);

	aligned_cost += lzx_huffman_code_output_cost(codes->lens.aligned,
						     freqs->aligned,
						     LZX_ALIGNEDTREE_NUM_SYMBOLS);

	*aligned_cost_ret = aligned_cost + common_cost;
	*verbatim_cost_ret = verbatim_cost + common_cost;
}

/* Prepare a (nonsplit) compressed block.  */
static unsigned
lzx_prepare_compressed_block(struct lzx_compressor *ctx, unsigned block_number,
			     struct lzx_codes *prev_codes)
{
	struct lzx_block_spec *spec = &ctx->block_specs[block_number - 1];
	unsigned orig_cached_matches_pos = ctx->cached_matches_pos;
	struct lzx_lru_queue orig_queue = ctx->queue;
	struct lzx_freqs freqs;
	unsigned cost;

	/* Here's where the real work happens.  The following loop runs one or
	 * more times, each time using a cost model based on the Huffman codes
	 * computed from the previous iteration (the first iteration uses a
	 * default model).  Each iteration of the loop uses a heuristic
	 * algorithm to divide the block into near-optimal matches/literals from
	 * beginning to end.  */
	LZX_ASSERT(ctx->params.alg_params.slow.num_optim_passes >= 1);
	spec->num_chosen_matches = 0;
	for (unsigned pass = 0; pass < ctx->params.alg_params.slow.num_optim_passes; pass++)
	{
		LZX_DEBUG("Block %u: Match-choosing pass %u of %u",
			  block_number, pass + 1,
			  ctx->params.alg_params.slow.num_optim_passes);

		/* Reset frequency tables.  */
		memset(&freqs, 0, sizeof(freqs));

		/* Reset match offset LRU queue.  */
		ctx->queue = orig_queue;

		/* Reset match-finding position.  */
		ctx->cached_matches_pos = orig_cached_matches_pos;
		ctx->match_window_pos = spec->window_pos;
		ctx->match_window_end = spec->window_pos + spec->block_size;

		/* Set cost model.  */
		lzx_set_costs(ctx, &spec->codes.lens);

		unsigned window_pos = spec->window_pos;
		unsigned end = window_pos + spec->block_size;

		while (window_pos < end) {
			struct raw_match match;
			struct lzx_match lzx_match;

			match = lzx_lz_get_near_optimal_match(ctx);

			if (match.len >= LZX_MIN_MATCH) {

				/* Best to output a match here.  */

				LZX_ASSERT(match.len <= LZX_MAX_MATCH);
				LZX_ASSERT(!memcmp(&ctx->window[window_pos],
						   &ctx->window[window_pos - match.offset],
						   match.len));

				/* Tally symbol frequencies.  */
				lzx_match.data = lzx_record_match(match.offset,
								  match.len,
								  &freqs,
								  &ctx->queue);

				window_pos += match.len;
			} else {
				/* Best to output a literal here.  */

				/* Tally symbol frequencies.  */
				lzx_match.data = lzx_record_literal(ctx->window[window_pos],
								    &freqs);

				window_pos += 1;
			}

			/* If it's the last pass, save the match/literal in
			 * intermediate form.  */
			if (pass == ctx->params.alg_params.slow.num_optim_passes - 1) {
				ctx->chosen_matches[spec->chosen_matches_start_pos +
						    spec->num_chosen_matches] = lzx_match;

				spec->num_chosen_matches++;
			}
		}
		LZX_ASSERT(window_pos == end);

		/* Build Huffman codes using the new frequencies.  */
		lzx_make_huffman_codes(&freqs, &spec->codes);

		/* The first time we get here is when the full input has been
		 * processed, so the match-finding is done.  */
		ctx->matches_already_found = true;
	}

	LZX_DEBUG("Block %u: saved %u matches/literals @ %u",
		  block_number, spec->num_chosen_matches,
		  spec->chosen_matches_start_pos);

	unsigned aligned_cost;
	unsigned verbatim_cost;

	lzx_compute_compressed_block_costs(spec->block_size,
					   &spec->codes,
					   prev_codes,
					   &freqs,
					   &aligned_cost,
					   &verbatim_cost);

	/* Choose whether to make the block aligned offset or verbatim.  */
	if (aligned_cost < verbatim_cost) {
		spec->block_type = LZX_BLOCKTYPE_ALIGNED;
		cost = aligned_cost;
		LZX_DEBUG("Using aligned block (cost %u vs %u for verbatim)",
			  aligned_cost, verbatim_cost);
	} else {
		spec->block_type = LZX_BLOCKTYPE_VERBATIM;
		cost = verbatim_cost;
		LZX_DEBUG("Using verbatim block (cost %u vs %u for aligned)",
			  verbatim_cost, aligned_cost);
	}

	LZX_DEBUG("Block %u is %u => %u bytes unsplit.",
		  block_number, spec->block_size, cost / 8);

	return cost;
}

/*
 * lzx_prepare_block_recursive() -
 *
 * Given a (possibly nonproper) sub-sequence of the preprocessed input, compute
 * the LZX block(s) that it should be output as.
 *
 * This function initially considers the case where the given sub-sequence of
 * the preprocessed input be output as a single block.  This block is calculated
 * and its cost (number of bits required to output it) is computed.
 *
 * Then, if @max_split_level is greater than zero, a split into two evenly sized
 * subblocks is considered.  The block is recursively split in this way,
 * potentially up to the depth specified by @max_split_level.  The cost of the
 * split block is compared to the cost of the single block, and the lower cost
 * solution is used.
 *
 * For each compressed output block computed, the sequence of matches/literals
 * and the corresponding Huffman codes for the block are produced and saved.
 *
 * The return value is the approximate number of bits the block (or all
 * subblocks, in the case that the split block had lower cost), will take up
 * when written to the compressed output.
 */
static unsigned
lzx_prepare_block_recursive(struct lzx_compressor * ctx,
			    unsigned block_number,
			    unsigned max_split_level,
			    struct lzx_codes **prev_codes_p)
{
	struct lzx_block_spec *spec = &ctx->block_specs[block_number - 1];
	unsigned cost;
	unsigned orig_cached_matches_pos;
	struct lzx_lru_queue orig_queue, nonsplit_queue;
	struct lzx_codes *prev_codes = *prev_codes_p;

	LZX_DEBUG("Preparing block %u...", block_number);

	/* Save positions of chosen and cached matches, and the match offset LRU
	 * queue, so that they can be restored if splitting is attempted.  */
	orig_cached_matches_pos = ctx->cached_matches_pos;
	orig_queue = ctx->queue;

	/* Consider outputting the input subsequence as a single block.  */
	spec->is_split = 0;
	cost = lzx_prepare_compressed_block(ctx, block_number, prev_codes);
	nonsplit_queue = ctx->queue;

	*prev_codes_p = &spec->codes;

	/* If the maximum split level is at least one, consider splitting the
	 * block in two.  */
	if (max_split_level--) {

		LZX_DEBUG("Calculating split of block %u...", block_number);

		struct lzx_block_spec *spec1, *spec2;
		unsigned split_cost;

		ctx->cached_matches_pos = orig_cached_matches_pos;
		ctx->queue = orig_queue;

		/* Prepare and get the cost of the first sub-block.  */
		spec1 = &ctx->block_specs[block_number * 2 - 1];
		spec1->codes.lens = spec->codes.lens;
		spec1->window_pos = spec->window_pos;
		spec1->block_size = spec->block_size / 2;
		spec1->chosen_matches_start_pos = spec->chosen_matches_start_pos +
						  LZX_MAX_WINDOW_SIZE;
		split_cost = lzx_prepare_block_recursive(ctx,
							 block_number * 2,
							 max_split_level,
							 &prev_codes);

		/* Prepare and get the cost of the second sub-block.  */
		spec2 = spec1 + 1;
		spec2->codes.lens = spec->codes.lens;
		spec2->window_pos = spec->window_pos + spec1->block_size;
		spec2->block_size = spec->block_size - spec1->block_size;
		spec2->chosen_matches_start_pos = spec1->chosen_matches_start_pos +
						  spec1->block_size;
		split_cost += lzx_prepare_block_recursive(ctx,
							  block_number * 2 + 1,
							  max_split_level,
							  &prev_codes);

		/* Compare the cost of the whole block with that of the split
		 * block.  Choose the lower cost solution.  */
		if (split_cost < cost) {
			LZX_DEBUG("Splitting block %u is worth it "
				  "(%u => %u bytes).",
				  block_number, cost / 8, split_cost / 8);
			spec->is_split = 1;
			cost = split_cost;
			*prev_codes_p = prev_codes;
		} else {
			LZX_DEBUG("Splitting block %u is NOT worth it "
				  "(%u => %u bytes).",
				  block_number, cost / 8, split_cost / 8);
			ctx->queue = nonsplit_queue;
		}
	}

	return cost;
}

/* Empirical averages  */
static const u8 lzx_default_mainsym_costs[LZX_MAINTREE_NUM_SYMBOLS] = {
	7, 9, 9, 10, 9, 10, 10, 10, 9, 10, 9, 10, 10, 9, 10, 10, 9, 10, 10, 11,
	10, 10, 10, 11, 10, 11, 11, 11, 10, 11, 11, 11, 8, 11, 9, 10, 9, 10, 11,
	11, 9, 9, 11, 10, 10, 9, 9, 9, 8, 8, 8, 8, 8, 9, 9, 9, 8, 8, 9, 9, 9, 9,
	10, 10, 10, 8, 9, 8, 8, 8, 8, 9, 9, 9, 10, 10, 8, 8, 9, 9, 8, 10, 9, 8,
	8, 9, 8, 9, 9, 10, 10, 10, 9, 10, 11, 9, 10, 8, 9, 8, 8, 8, 8, 9, 8, 8,
	9, 9, 8, 8, 8, 8, 8, 10, 8, 8, 7, 8, 9, 9, 9, 9, 10, 11, 10, 10, 11, 11,
	10, 11, 11, 10, 10, 11, 11, 11, 10, 10, 11, 10, 11, 10, 11, 11, 10, 11,
	11, 12, 11, 11, 11, 12, 11, 11, 11, 11, 11, 11, 11, 12, 10, 11, 11, 11,
	11, 11, 11, 12, 11, 11, 11, 11, 11, 12, 11, 11, 10, 11, 11, 11, 11, 11,
	11, 11, 10, 11, 11, 11, 11, 11, 11, 11, 10, 11, 11, 11, 11, 11, 11, 11,
	10, 11, 11, 11, 11, 11, 11, 11, 10, 11, 11, 11, 11, 12, 11, 11, 10, 11,
	11, 11, 11, 12, 11, 11, 10, 11, 11, 11, 10, 12, 11, 11, 10, 10, 11, 10,
	10, 11, 11, 11, 10, 11, 11, 11, 10, 11, 11, 11, 10, 11, 11, 11, 10, 11,
	10, 9, 8, 7, 10, 10, 11, 10, 11, 7, 9, 9, 11, 11, 11, 12, 11, 9, 10, 10,
	12, 12, 13, 13, 12, 11, 10, 12, 12, 14, 14, 14, 13, 12, 9, 12, 13, 14,
	14, 14, 14, 14, 9, 10, 13, 14, 14, 14, 14, 14, 9, 9, 11, 11, 13, 13, 13,
	14, 9, 9, 11, 12, 12, 13, 13, 13, 8, 8, 11, 11, 12, 12, 12, 11, 9, 9,
	10, 11, 12, 12, 12, 11, 8, 9, 10, 10, 11, 12, 11, 10, 9, 9, 10, 11, 11,
	12, 11, 10, 8, 9, 10, 10, 11, 11, 11, 9, 9, 9, 10, 11, 11, 11, 11, 9, 8,
	8, 10, 10, 11, 11, 11, 9, 9, 9, 10, 10, 11, 11, 11, 9, 9, 8, 9, 10, 11,
	11, 11, 9, 10, 9, 10, 11, 11, 11, 11, 9, 14, 9, 9, 10, 10, 11, 10, 9,
	14, 9, 10, 11, 11, 11, 11, 9, 14, 9, 10, 10, 11, 11, 11, 9, 14, 10, 10,
	11, 11, 12, 11, 10, 14, 10, 10, 10, 11, 11, 11, 10, 14, 11, 11, 11, 11,
	12, 12, 10, 14, 10, 11, 11, 11, 12, 11, 10, 14, 11, 11, 11, 12, 12, 12,
	11, 15, 11, 11, 11, 12, 12, 12, 11, 14, 12, 12, 12, 12, 13, 12, 11, 15,
	12, 12, 12, 13, 13, 13, 12, 15, 14, 13, 14, 14, 14, 14, 13,
};

/* Empirical averages  */
static const u8 lzx_default_lensym_costs[LZX_LENTREE_NUM_SYMBOLS] = {
	5, 5, 5, 5, 5, 6, 5, 5, 6, 7, 7, 7, 8, 8, 7, 8, 9, 9, 9, 9, 10, 9, 9,
	10, 9, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 12, 12, 12, 11, 12, 12,
	12, 12, 12, 12, 13, 12, 12, 12, 13, 12, 13, 13, 12, 12, 13, 12, 13, 13,
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 13, 14, 13, 14, 13,
	14, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 10,
};

/*
 * Set default symbol costs.
 */
static void
lzx_set_default_costs(struct lzx_lens * lens)
{
	unsigned i;

#if LZX_PARAM_USE_EMPIRICAL_DEFAULT_COSTS
	memcpy(&lens->main, lzx_default_mainsym_costs, LZX_MAINTREE_NUM_SYMBOLS);
	memcpy(&lens->len, lzx_default_lensym_costs, LZX_LENTREE_NUM_SYMBOLS);

#else
	/* Literal symbols  */
	for (i = 0; i < LZX_NUM_CHARS; i++)
		lens->main[i] = 8;

	/* Match header symbols  */
	for (; i < LZX_MAINTREE_NUM_SYMBOLS; i++)
		lens->main[i] = 10;

	/* Length symbols  */
	for (i = 0; i < LZX_LENTREE_NUM_SYMBOLS; i++)
		lens->len[i] = 8;
#endif

	/* Aligned offset symbols  */
	for (i = 0; i < LZX_ALIGNEDTREE_NUM_SYMBOLS; i++)
		lens->aligned[i] = 3;
}

/*
 * lzx_prepare_blocks() -
 *
 * Calculate the blocks to split the preprocessed data into.
 *
 * Input ---  the preprocessed data:
 *
 *	ctx->window[]
 *	ctx->window_size
 *
 * Working space:
 *	Match finding:
 *		ctx->hash_tab
 *		ctx->child_tab
 *		ctx->cached_matches
 *		ctx->cached_matches_pos
 *		ctx->matches_already_found
 *
 *	Block cost modeling:
 *		ctx->costs
 *		ctx->block_specs (also an output)
 *
 *	Match choosing:
 *		ctx->optimum
 *		ctx->optimum_cur_idx
 *		ctx->optimum_end_idx
 *		ctx->chosen_matches (also an output)
 *
 * Output --- the block specifications and the corresponding match/literal data:
 *
 *	ctx->block_specs[]
 *	ctx->chosen_matches[]
 *
 * The return value is the approximate number of bits the compressed data will
 * take up.
 */
static unsigned
lzx_prepare_blocks(struct lzx_compressor * ctx)
{
	/* This function merely does some initializations, then passes control
	 * to lzx_prepare_block_recursive().  */

	/* 1. Initialize match-finding variables.  */

	/* Zero all entries in the hash table, indicating that no length-3
	 * character sequences have been discovered in the input yet.  */
	memset(ctx->hash_tab, 0, LZX_LZ_HASH_SIZE * 2 * sizeof(ctx->hash_tab[0]));
	if (ctx->params.alg_params.slow.use_len2_matches)
		memset(ctx->digram_tab, 0, 256 * 256 * sizeof(ctx->digram_tab[0]));
	/* Note: ctx->child_tab need not be initialized.  */

	/* No matches have been found and cached yet.  */
	ctx->cached_matches_pos = 0;
	ctx->matches_already_found = false;

	/* 2. Initialize match-choosing variables.  */
	ctx->optimum_cur_idx = 0;
	ctx->optimum_end_idx = 0;
	/* Note: ctx->optimum need not be initialized.  */
	ctx->block_specs[0].chosen_matches_start_pos = 0;

	/* 3. Set block 1 (index 0) to represent the entire input data.  */
	ctx->block_specs[0].block_size = ctx->window_size;
	ctx->block_specs[0].window_pos = 0;

	/* 4. Set up a default Huffman symbol cost model for block 1 (index 0).
	 * The model will be refined later.  */
	lzx_set_default_costs(&ctx->block_specs[0].codes.lens);

	/* 5. Initialize the match offset LRU queue.  */
	ctx->queue = (struct lzx_lru_queue){1, 1, 1};

	/* 6. Pass control to recursive procedure.  */
	struct lzx_codes * prev_codes = &ctx->zero_codes;
	return lzx_prepare_block_recursive(ctx, 1,
					   ctx->params.alg_params.slow.num_split_passes,
					   &prev_codes);
}

/*
 * This is the fast version of lzx_prepare_blocks().  This version "quickly"
 * prepares a single compressed block containing the entire input.  See the
 * description of the "Fast algorithm" at the beginning of this file for more
 * information.
 *
 * Input ---  the preprocessed data:
 *
 *	ctx->window[]
 *	ctx->window_size
 *
 * Working space:
 *	ctx->queue
 *
 * Output --- the block specifications and the corresponding match/literal data:
 *
 *	ctx->block_specs[]
 *	ctx->chosen_matches[]
 */
static void
lzx_prepare_block_fast(struct lzx_compressor * ctx)
{
	unsigned num_matches;
	struct lzx_freqs freqs;
	struct lzx_block_spec *spec;

	/* Parameters to hash chain LZ match finder  */
	static const struct lz_params lzx_lz_params = {
		/* LZX_MIN_MATCH == 2, but 2-character matches are rarely
		 * useful; the minimum match for compression is set to 3
		 * instead. */
		.min_match      = 3,
		.max_match      = LZX_MAX_MATCH,
		.good_match     = LZX_MAX_MATCH,
		.nice_match     = LZX_MAX_MATCH,
		.max_chain_len  = LZX_MAX_MATCH,
		.max_lazy_match = LZX_MAX_MATCH,
		.too_far        = 4096,
	};

	/* Initialize symbol frequencies and match offset LRU queue.  */
	memset(&freqs, 0, sizeof(struct lzx_freqs));
	ctx->queue = (struct lzx_lru_queue){ 1, 1, 1 };

	/* Determine series of matches/literals to output.  */
	num_matches = lz_analyze_block(ctx->window,
				       ctx->window_size,
				       (u32*)ctx->chosen_matches,
				       lzx_record_match,
				       lzx_record_literal,
				       &freqs,
				       &ctx->queue,
				       &freqs,
				       &lzx_lz_params);


	/* Set up block specification.  */
	spec = &ctx->block_specs[0];
	spec->is_split = 0;
	spec->block_type = LZX_BLOCKTYPE_ALIGNED;
	spec->window_pos = 0;
	spec->block_size = ctx->window_size;
	spec->num_chosen_matches = num_matches;
	spec->chosen_matches_start_pos = 0;
	lzx_make_huffman_codes(&freqs, &spec->codes);
}

static void
do_call_insn_translation(u32 *call_insn_target, int input_pos,
			 s32 file_size)
{
	s32 abs_offset;
	s32 rel_offset;

	rel_offset = le32_to_cpu(*call_insn_target);
	if (rel_offset >= -input_pos && rel_offset < file_size) {
		if (rel_offset < file_size - input_pos) {
			/* "good translation" */
			abs_offset = rel_offset + input_pos;
		} else {
			/* "compensating translation" */
			abs_offset = rel_offset - file_size;
		}
		*call_insn_target = cpu_to_le32(abs_offset);
	}
}

/* This is the reverse of undo_call_insn_preprocessing() in lzx-decompress.c.
 * See the comment above that function for more information.  */
static void
do_call_insn_preprocessing(u8 data[], int size)
{
	for (int i = 0; i < size - 10; i++) {
		if (data[i] == 0xe8) {
			do_call_insn_translation((u32*)&data[i + 1], i,
						 LZX_WIM_MAGIC_FILESIZE);
			i += 4;
		}
	}
}

/* API function documented in wimlib.h  */
WIMLIBAPI unsigned
wimlib_lzx_compress2(const void			* const restrict uncompressed_data,
		     unsigned			  const          uncompressed_len,
		     void			* const restrict compressed_data,
		     struct wimlib_lzx_context	* const restrict lzx_ctx)
{
	struct lzx_compressor *ctx = (struct lzx_compressor*)lzx_ctx;
	struct output_bitstream ostream;
	unsigned compressed_len;

	if (uncompressed_len < 100) {
		LZX_DEBUG("Too small to bother compressing.");
		return 0;
	}

	if (uncompressed_len > 32768) {
		LZX_DEBUG("Only up to 32768 bytes of uncompressed data are supported.");
		return 0;
	}

	wimlib_assert(lzx_ctx != NULL);

	LZX_DEBUG("Attempting to compress %u bytes...", uncompressed_len);

	/* The input data must be preprocessed.  To avoid changing the original
	 * input, copy it to a temporary buffer.  */
	memcpy(ctx->window, uncompressed_data, uncompressed_len);
	ctx->window_size = uncompressed_len;

	/* This line is unnecessary; it just avoids inconsequential accesses of
	 * uninitialized memory that would show up in memory-checking tools such
	 * as valgrind.  */
	memset(&ctx->window[ctx->window_size], 0, 12);

	LZX_DEBUG("Preprocessing data...");

	/* Before doing any actual compression, do the call instruction (0xe8
	 * byte) translation on the uncompressed data.  */
	do_call_insn_preprocessing(ctx->window, ctx->window_size);

	LZX_DEBUG("Preparing blocks...");

	/* Prepare the compressed data.  */
	if (ctx->params.algorithm == WIMLIB_LZX_ALGORITHM_FAST)
		lzx_prepare_block_fast(ctx);
	else
		lzx_prepare_blocks(ctx);

	LZX_DEBUG("Writing compressed blocks...");

	/* Generate the compressed data.  */
	init_output_bitstream(&ostream, compressed_data, ctx->window_size - 1);
	lzx_write_all_blocks(ctx, &ostream);

	LZX_DEBUG("Flushing bitstream...");
	if (flush_output_bitstream(&ostream)) {
		/* If the bitstream cannot be flushed, then the output space was
		 * exhausted.  */
		LZX_DEBUG("Data did not compress to less than original length!");
		return 0;
	}

	/* Compute the length of the compressed data.  */
	compressed_len = ostream.bit_output - (u8*)compressed_data;

	LZX_DEBUG("Done: compressed %u => %u bytes.",
		  uncompressed_len, compressed_len);

#if defined(ENABLE_LZX_DEBUG) || defined(ENABLE_VERIFY_COMPRESSION)
	/* Verify that we really get the same thing back when decompressing.  */
	{
		u8 buf[uncompressed_len];
		int ret;
		unsigned i;

		ret = wimlib_lzx_decompress(compressed_data, compressed_len,
					    buf, uncompressed_len);
		if (ret) {
			ERROR("Failed to decompress data we "
			      "compressed using LZX algorithm");
			wimlib_assert(0);
			return 0;
		}

		bool bad = false;
		const u8 * udata = uncompressed_data;
		for (i = 0; i < uncompressed_len; i++) {
			if (buf[i] != udata[i]) {
				bad = true;
				ERROR("Data we compressed using LZX algorithm "
				      "didn't decompress to original "
				      "(difference at idx %u: c %#02x, u %#02x)",
				      i, buf[i], udata[i]);
			}
		}
		if (bad) {
			wimlib_assert(0);
			return 0;
		}
	}
#endif
	return compressed_len;
}

static bool
lzx_params_compatible(const struct wimlib_lzx_params *oldparams,
		      const struct wimlib_lzx_params *newparams)
{
	return 0 == memcmp(oldparams, newparams, sizeof(struct wimlib_lzx_params));
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_lzx_alloc_context(const struct wimlib_lzx_params *params,
			 struct wimlib_lzx_context **ctx_pp)
{

	LZX_DEBUG("Allocating LZX context...");

	struct lzx_compressor *ctx;

	static const struct wimlib_lzx_params fast_default = {
		.size_of_this = sizeof(struct wimlib_lzx_params),
		.algorithm = WIMLIB_LZX_ALGORITHM_FAST,
		.use_defaults = 0,
		.alg_params = {
			.fast = {
			},
		},
	};
	static const struct wimlib_lzx_params slow_default = {
		.size_of_this = sizeof(struct wimlib_lzx_params),
		.algorithm = WIMLIB_LZX_ALGORITHM_SLOW,
		.use_defaults = 0,
		.alg_params = {
			.slow = {
				.use_len2_matches = 1,
				.num_fast_bytes = 32,
				.num_optim_passes = 3,
				.num_split_passes = 3,
				.main_nostat_cost = 15,
				.len_nostat_cost = 15,
				.aligned_nostat_cost = 7,
			},
		},
	};

	if (params == NULL) {
		LZX_DEBUG("Using default algorithm and parameters.");
		params = &fast_default;
	}

	if (params->algorithm != WIMLIB_LZX_ALGORITHM_SLOW &&
	    params->algorithm != WIMLIB_LZX_ALGORITHM_FAST)
	{
		LZX_DEBUG("Invalid algorithm.");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if (params->use_defaults) {
		if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW)
			params = &slow_default;
		else
			params = &fast_default;
	}

	if (params->size_of_this != sizeof(struct wimlib_lzx_params)) {
		LZX_DEBUG("Invalid parameter structure size!");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW) {
		if (params->alg_params.slow.num_fast_bytes < 3 ||
		    params->alg_params.slow.num_fast_bytes > 257)
		{
			LZX_DEBUG("Invalid number of fast bytes!");
			return WIMLIB_ERR_INVALID_PARAM;
		}

		if (params->alg_params.slow.num_optim_passes < 1)
		{
			LZX_DEBUG("Invalid number of optimization passes!");
			return WIMLIB_ERR_INVALID_PARAM;
		}

		if (params->alg_params.slow.main_nostat_cost < 1 ||
		    params->alg_params.slow.main_nostat_cost > 16)
		{
			LZX_DEBUG("Invalid main_nostat_cost!");
			return WIMLIB_ERR_INVALID_PARAM;
		}

		if (params->alg_params.slow.len_nostat_cost < 1 ||
		    params->alg_params.slow.len_nostat_cost > 16)
		{
			LZX_DEBUG("Invalid len_nostat_cost!");
			return WIMLIB_ERR_INVALID_PARAM;
		}

		if (params->alg_params.slow.aligned_nostat_cost < 1 ||
		    params->alg_params.slow.aligned_nostat_cost > 8)
		{
			LZX_DEBUG("Invalid aligned_nostat_cost!");
			return WIMLIB_ERR_INVALID_PARAM;
		}
	}

	if (ctx_pp == NULL) {
		LZX_DEBUG("Check parameters only.");
		return 0;
	}

	ctx = *(struct lzx_compressor**)ctx_pp;

	if (ctx && lzx_params_compatible(&ctx->params, params))
		return 0;

	LZX_DEBUG("Allocating memory.");

	ctx = MALLOC(sizeof(struct lzx_compressor));
	if (ctx == NULL)
		goto err;

	size_t block_specs_length;

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW)
		block_specs_length = ((1 << (params->alg_params.slow.num_split_passes + 1)) - 1);
	else
		block_specs_length = 1;
	ctx->block_specs = MALLOC(block_specs_length * sizeof(ctx->block_specs[0]));
	if (ctx->block_specs == NULL)
		goto err_free_ctx;

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW) {
		ctx->hash_tab = MALLOC((LZX_LZ_HASH_SIZE + 2 * LZX_MAX_WINDOW_SIZE) *
				        sizeof(ctx->hash_tab[0]));
		if (ctx->hash_tab == NULL)
			goto err_free_block_specs;
		ctx->child_tab = ctx->hash_tab + LZX_LZ_HASH_SIZE;
	} else {
		ctx->hash_tab = NULL;
		ctx->child_tab = NULL;
	}

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW &&
	    params->alg_params.slow.use_len2_matches)
	{
		ctx->digram_tab = MALLOC(256 * 256 * sizeof(ctx->digram_tab[0]));
		if (ctx->digram_tab == NULL)
			goto err_free_hash_tab;
	} else {
		ctx->digram_tab = NULL;
	}

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW) {
		ctx->cached_matches = MALLOC(10 * LZX_MAX_WINDOW_SIZE *
					     sizeof(ctx->cached_matches[0]));
		if (ctx->cached_matches == NULL)
			goto err_free_digram_tab;
	} else {
		ctx->cached_matches = NULL;
	}

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW) {
		ctx->optimum = MALLOC((LZX_PARAM_OPTIM_ARRAY_SIZE + LZX_MAX_MATCH) *
				       sizeof(ctx->optimum[0]));
		if (ctx->optimum == NULL)
			goto err_free_cached_matches;
	} else {
		ctx->optimum = NULL;
	}

	size_t chosen_matches_length;
	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW)
		chosen_matches_length = LZX_MAX_WINDOW_SIZE *
					(params->alg_params.slow.num_split_passes + 1);
	else
		chosen_matches_length = LZX_MAX_WINDOW_SIZE;

	ctx->chosen_matches = MALLOC(chosen_matches_length *
				     sizeof(ctx->chosen_matches[0]));
	if (ctx->chosen_matches == NULL)
		goto err_free_optimum;

	memcpy(&ctx->params, params, sizeof(struct wimlib_lzx_params));
	memset(&ctx->zero_codes, 0, sizeof(ctx->zero_codes));

	LZX_DEBUG("Successfully allocated new LZX context.");

	wimlib_lzx_free_context(*ctx_pp);
	*ctx_pp = (struct wimlib_lzx_context*)ctx;
	return 0;

err_free_optimum:
	FREE(ctx->optimum);
err_free_cached_matches:
	FREE(ctx->cached_matches);
err_free_digram_tab:
	FREE(ctx->digram_tab);
err_free_hash_tab:
	FREE(ctx->hash_tab);
err_free_block_specs:
	FREE(ctx->block_specs);
err_free_ctx:
	FREE(ctx);
err:
	LZX_DEBUG("Ran out of memory.");
	return WIMLIB_ERR_NOMEM;
}

/* API function documented in wimlib.h  */
WIMLIBAPI void
wimlib_lzx_free_context(struct wimlib_lzx_context *_ctx)
{
	struct lzx_compressor *ctx = (struct lzx_compressor*)_ctx;

	if (ctx) {
		FREE(ctx->chosen_matches);
		FREE(ctx->optimum);
		FREE(ctx->cached_matches);
		FREE(ctx->digram_tab);
		FREE(ctx->hash_tab);
		FREE(ctx->block_specs);
		FREE(ctx);
	}
}

/* API function documented in wimlib.h  */
WIMLIBAPI unsigned
wimlib_lzx_compress(const void * const restrict uncompressed_data,
		    unsigned	 const		uncompressed_len,
		    void       * const restrict compressed_data)
{
	int ret;
	struct wimlib_lzx_context *ctx = NULL;
	unsigned compressed_len;

	ret = wimlib_lzx_alloc_context(NULL, &ctx);
	if (ret) {
		wimlib_assert(ret != WIMLIB_ERR_INVALID_PARAM);
		WARNING("Couldn't allocate LZX compression context: %"TS"",
			wimlib_get_error_string(ret));
		return 0;
	}

	compressed_len = wimlib_lzx_compress2(uncompressed_data,
					      uncompressed_len,
					      compressed_data,
					      ctx);

	wimlib_lzx_free_context(ctx);

	return compressed_len;
}
