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
 * - LZX preprocesses the data to attempt to make x86 machine code slightly more
 *   compressible before attempting to compress it further.
 * - LZX uses a "main" alphabet which combines literals and matches, with the
 *   match symbols containing a "length header" (giving all or part of the match
 *   length) and a "position slot" (giving, roughly speaking, the order of
 *   magnitude of the match offset).
 * - LZX does not have static Huffman blocks; however it does have two types of
 *   dynamic Huffman blocks ("aligned offset" and "verbatim").
 * - LZX has a minimum match length of 2 rather than 3.
 * - In LZX, match offsets 0 through 2 actually represent entries in an LRU
 *   queue of match offsets.  This is very useful for certain types of files,
 *   such as binary files that have repeating records.
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
 * 1. Preprocess the input data to translate the targets of x86 call
 *    instructions to absolute offsets.
 *
 * 2. Build the suffix array and inverse suffix array for the input data.  The
 *    suffix array contains the indices of all suffixes of the input data,
 *    sorted lexcographically by the corresponding suffixes.  The "position" of
 *    a suffix is the index of that suffix in the original string, whereas the
 *    "rank" of a suffix is the index at which that suffix's position is found
 *    in the suffix array.
 *
 * 3. Build the longest common prefix array corresponding to the suffix array.
 *
 * 4. For each suffix, find the highest lower ranked suffix that has a lower
 *    position, the lowest higher ranked suffix that has a lower position, and
 *    the length of the common prefix shared between each.   This information is
 *    later used to link suffix ranks into a doubly-linked list for searching
 *    the suffix array.
 *
 * 5. Set a default cost model for matches/literals.
 *
 * 6. Determine the lowest cost sequence of LZ77 matches ((offset, length)
 *    pairs) and literal bytes to divide the input into.  Raw match-finding is
 *    done by searching the suffix array using a linked list to avoid
 *    considering any suffixes that start after the current position.  Each run
 *    of the match-finder returns the approximate lowest-cost longest match as
 *    well as any shorter matches that have even lower approximate costs.  Each
 *    such run also adds the suffix rank of the current position into the linked
 *    list being used to search the suffix array.  Parsing, or match-choosing,
 *    is solved as a minimum-cost path problem using a forward "optimal parsing"
 *    algorithm based on the Deflate encoder from 7-Zip.  This algorithm moves
 *    forward calculating the minimum cost to reach each byte until either a
 *    very long match is found or until a position is found at which no matches
 *    start or overlap.
 *
 * 7. Build the Huffman codes needed to output the matches/literals.
 *
 * 8. Up to a certain number of iterations, use the resulting Huffman codes to
 *    refine a cost model and go back to Step #6 to determine an improved
 *    sequence of matches and literals.
 *
 * 9. Output the resulting block using the match/literal sequences and the
 *    Huffman codes that were computed for the block.
 *
 * Note: the algorithm does not yet attempt to split the input into multiple LZX
 * blocks, instead using a series of blocks of LZX_DIV_BLOCK_SIZE bytes.
 *
 * Fast algorithm
 * --------------
 *
 * The fast algorithm (and the only one available in wimlib v1.5.1 and earlier)
 * spends much less time on the main bottlenecks of the compression process ---
 * that is, the match finding and match choosing.  Matches are found and chosen
 * with hash chains using a greedy parse with one position of look-ahead.  No
 * block splitting is done; only compressing the full input into an aligned
 * offset block is considered.
 *
 * API
 * ===
 *
 * The old API (retained for backward compatibility) consists of just one
 * function:
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
 *	wimlib_lzx_set_default_params()
 *
 * Both wimlib_lzx_compress() and wimlib_lzx_compress2() are designed to
 * compress an in-memory buffer of up to the window size, which can be any power
 * of two between 2^15 and 2^21 inclusively.  However, by default, the WIM
 * format uses 2^15, and this is seemingly the only value that is compatible
 * with WIMGAPI.  In any case, the window is not a true "sliding window" since
 * no data is ever "slid out" of the window.  This is needed for the WIM format,
 * which is designed such that chunks may be randomly accessed.
 *
 * Both wimlib_lzx_compress() and wimlib_lzx_compress2() return 0 if the data
 * could not be compressed to less than the size of the uncompressed data.
 * Again, this is suitable for the WIM format, which stores such data chunks
 * uncompressed.
 *
 * The functions in this LZX compression API are exported from the library,
 * although with the possible exception of wimlib_lzx_set_default_params(), this
 * is only in case other programs happen to have uses for it other than WIM
 * reading/writing as already handled through the rest of the library.
 *
 * Acknowledgments
 * ===============
 *
 * Acknowledgments to several open-source projects and research papers that made
 * it possible to implement this code:
 *
 * - divsufsort (author: Yuta Mori), for the suffix array construction code,
 *   located in a separate directory (divsufsort/).
 *
 * - "Linear-Time Longest-Common-Prefix Computation in Suffix Arrays and Its
 *   Applications" (Kasai et al. 2001), for the LCP array computation.
 *
 * - "LPF computation revisited" (Crochemore et al. 2009) for the prev and next
 *   array computations.
 *
 * - 7-Zip (author: Igor Pavlov) for the algorithm for forward optimal parsing
 *   (match-choosing).
 *
 * - zlib (author: Jean-loup Gailly and Mark Adler), for the hash table
 *   match-finding algorithm (used in lz77.c).
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
#include <pthread.h>
#include <math.h>
#include <string.h>

#ifdef ENABLE_LZX_DEBUG
#  include "wimlib/decompress.h"
#endif

#include "divsufsort/divsufsort.h"

typedef u32 block_cost_t;
#define INFINITE_BLOCK_COST	((block_cost_t)~0U)

#define LZX_OPTIM_ARRAY_SIZE	4096

#define LZX_DIV_BLOCK_SIZE	32768

#define LZX_MAX_CACHE_PER_POS	10

/* Codewords for the LZX main, length, and aligned offset Huffman codes  */
struct lzx_codewords {
	u16 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u16 len[LZX_LENCODE_NUM_SYMBOLS];
	u16 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
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
 * it probably will not be used very times.  */
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
	freq_t main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	freq_t len[LZX_LENCODE_NUM_SYMBOLS];
	freq_t aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
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
	 *         (since lzx_extra_bits[LZX_MAX_POSITION_SLOTS - 1] is 17).
	 *
	 * 0-7     length of match, minus 2.  This can be at most
	 *         (LZX_MAX_MATCH_LEN - 2) == 255, so it will fit in 8 bits.  */
	u32 data;
};

/* Raw LZ match/literal format: just a length and offset.
 *
 * The length is the number of bytes of the match, and the offset is the number
 * of bytes back in the input the match is from the current position.
 *
 * If @len < LZX_MIN_MATCH_LEN, then it's really just a literal byte and @offset is
 * meaningless.  */
struct raw_match {
	u16 len;
	input_idx_t offset;
};

/* Specification for an LZX block.  */
struct lzx_block_spec {

	/* One of the LZX_BLOCKTYPE_* constants indicating which type of this
	 * block.  */
	int block_type;

	/* 0-based position in the window at which this block starts.  */
	input_idx_t window_pos;

	/* The number of bytes of uncompressed data this block represents.  */
	input_idx_t block_size;

	/* The position in the 'chosen_matches' array in the `struct
	 * lzx_compressor' at which the match/literal specifications for
	 * this block begin.  */
	input_idx_t chosen_matches_start_pos;

	/* The number of match/literal specifications for this block.  */
	input_idx_t num_chosen_matches;

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
	block_cost_t cost;

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
			input_idx_t link;

			/* Offset (as in an LZ (length, offset) pair) of the
			 * match or literal that was taken to get to this
			 * position in the approximate minimum-cost parse.  */
			input_idx_t match_offset;
		} prev;
		struct {
			/* Position at which the match or literal starting at
			 * this position ends in the minimum-cost parse.  */
			input_idx_t link;

			/* Offset (as in an LZ (length, offset) pair) of the
			 * match or literal starting at this position in the
			 * approximate minimum-cost parse.  */
			input_idx_t match_offset;
		} next;
	};

	/* The match offset LRU queue that will exist when the approximate
	 * minimum-cost path to reach this position is taken.  */
	struct lzx_lru_queue queue;
};

/* Suffix array link  */
struct salink {
	/* Rank of highest ranked suffix that has rank lower than the suffix
	 * corresponding to this structure and either has a lower position
	 * (initially) or has a position lower than the highest position at
	 * which matches have been searched for so far, or -1 if there is no
	 * such suffix.  */
	input_idx_t prev;

	/* Rank of lowest ranked suffix that has rank greater than the suffix
	 * corresponding to this structure and either has a lower position
	 * (intially) or has a position lower than the highest position at which
	 * matches have been searched for so far, or -1 if there is no such
	 * suffix.  */
	input_idx_t next;

	/* Length of longest common prefix between the suffix corresponding to
	 * this structure and the suffix with rank @prev, or 0 if @prev is -1.
	 */
	input_idx_t lcpprev;

	/* Length of longest common prefix between the suffix corresponding to
	 * this structure and the suffix with rank @next, or 0 if @next is -1.
	 */
	input_idx_t lcpnext;
};

/* State of the LZX compressor.  */
struct lzx_compressor {

	/* The parameters that were used to create the compressor.  */
	struct wimlib_lzx_params params;

	/* The buffer of data to be compressed.
	 *
	 * 0xe8 byte preprocessing is done directly on the data here before
	 * further compression.
	 *
	 * Note that this compressor does *not* use a real sliding window!!!!
	 * It's not needed in the WIM format, since every chunk is compressed
	 * independently.  This is by design, to allow random access to the
	 * chunks.
	 *
	 * We reserve a few extra bytes to potentially allow reading off the end
	 * of the array in the match-finding code for optimization purposes.
	 */
	u8 *window;

	/* Number of bytes of data to be compressed, which is the number of
	 * bytes of data in @window that are actually valid.  */
	input_idx_t window_size;

	/* Allocated size of the @window.  */
	input_idx_t max_window_size;

	/* Number of symbols in the main alphabet (depends on the
	 * @max_window_size since it determines the maximum allowed offset).  */
	unsigned num_main_syms;

	/* The current match offset LRU queue.  */
	struct lzx_lru_queue queue;

	/* Space for the sequences of matches/literals that were chosen for each
	 * block.  */
	struct lzx_match *chosen_matches;

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

	/* Fast algorithm only:  Array of hash table links.  */
	input_idx_t *prev_tab;

	/* Suffix array for window.
	 * This is a mapping from suffix rank to suffix position.  */
	input_idx_t *SA;

	/* Inverse suffix array for window.
	 * This is a mapping from suffix position to suffix rank.
	 * If 0 <= r < window_size, then ISA[SA[r]] == r.  */
	input_idx_t *ISA;

	/* Longest common prefix array corresponding to the suffix array SA.
	 * LCP[i] is the length of the longest common prefix between the
	 * suffixes with positions SA[i - 1] and  SA[i].  LCP[0] is undefined.
	 */
	input_idx_t *LCP;

	/* Suffix array links.
	 *
	 * During a linear scan of the input string to find matches, this array
	 * used to keep track of which rank suffixes in the suffix array appear
	 * before the current position.  Instead of searching in the original
	 * suffix array, scans for matches at a given position traverse a linked
	 * list containing only suffixes that appear before that position.  */
	struct salink *salink;

	/* Position in window of next match to return.  */
	input_idx_t match_window_pos;

	/* The match-finder shall ensure the length of matches does not exceed
	 * this position in the input.  */
	input_idx_t match_window_end;

	/* Matches found by the match-finder are cached in the following array
	 * to achieve a slight speedup when the same matches are needed on
	 * subsequent passes.  This is suboptimal because different matches may
	 * be preferred with different cost models, but seems to be a worthwhile
	 * speedup.  */
	struct raw_match *cached_matches;
	unsigned cached_matches_pos;
	bool matches_cached;

	/* Slow algorithm only: Temporary space used for match-choosing
	 * algorithm.
	 *
	 * The size of this array must be at least LZX_MAX_MATCH_LEN but
	 * otherwise is arbitrary.  More space simply allows the match-choosing
	 * algorithm to potentially find better matches (depending on the input,
	 * as always).  */
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

/* Returns the LZX position slot that corresponds to a given match offset,
 * taking into account the recent offset queue and updating it if the offset is
 * found in it.  */
static unsigned
lzx_get_position_slot(unsigned offset, struct lzx_lru_queue *queue)
{
	unsigned position_slot;

	/* See if the offset was recently used.  */
	for (unsigned i = 0; i < LZX_NUM_RECENT_OFFSETS; i++) {
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
	for (unsigned i = LZX_NUM_RECENT_OFFSETS - 1; i > 0; i--)
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
 * Output an LZX match.
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
		/* No length footer-- mark it with a special
		 * value. */
		len_footer = (unsigned)(-1);
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
	if (len_footer != (unsigned)(-1)) {
		bitstream_put_bits(out, codes->codewords.len[len_footer],
				   codes->lens.len[len_footer]);
	}

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

static unsigned
lzx_build_precode(const u8 lens[restrict],
		  const u8 prev_lens[restrict],
		  const unsigned num_syms,
		  freq_t precode_freqs[restrict LZX_PRECODE_NUM_SYMBOLS],
		  u8 output_syms[restrict num_syms],
		  u8 precode_lens[restrict LZX_PRECODE_NUM_SYMBOLS],
		  u16 precode_codewords[restrict LZX_PRECODE_NUM_SYMBOLS],
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
 * Writes a compressed Huffman code to the output, preceded by the precode for
 * it.
 *
 * The Huffman code is represented in the output as a series of path lengths
 * from which the canonical Huffman code can be reconstructed.  The path lengths
 * themselves are compressed using a separate Huffman code, the precode, which
 * consists of LZX_PRECODE_NUM_SYMBOLS (= 20) symbols that cover all possible
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
	freq_t precode_freqs[LZX_PRECODE_NUM_SYMBOLS];
	u8 output_syms[num_syms];
	u8 precode_lens[LZX_PRECODE_NUM_SYMBOLS];
	u16 precode_codewords[LZX_PRECODE_NUM_SYMBOLS];
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
 * Writes all compressed matches and literal bytes in an LZX block to the the
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
lzx_assert_codes_valid(const struct lzx_codes * codes, unsigned num_main_syms)
{
#ifdef ENABLE_LZX_DEBUG
	unsigned i;

	for (i = 0; i < num_main_syms; i++)
		LZX_ASSERT(codes->lens.main[i] <= LZX_MAX_MAIN_CODEWORD_LEN);

	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
		LZX_ASSERT(codes->lens.len[i] <= LZX_MAX_LEN_CODEWORD_LEN);

	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
		LZX_ASSERT(codes->lens.aligned[i] <= LZX_MAX_ALIGNED_CODEWORD_LEN);

	const unsigned tablebits = 10;
	u16 decode_table[(1 << tablebits) +
			 (2 * max(num_main_syms, LZX_LENCODE_NUM_SYMBOLS))]
			 _aligned_attribute(DECODE_TABLE_ALIGNMENT);
	LZX_ASSERT(0 == make_huffman_decode_table(decode_table,
						  num_main_syms,
						  min(tablebits, LZX_MAINCODE_TABLEBITS),
						  codes->lens.main,
						  LZX_MAX_MAIN_CODEWORD_LEN));
	LZX_ASSERT(0 == make_huffman_decode_table(decode_table,
						  LZX_LENCODE_NUM_SYMBOLS,
						  min(tablebits, LZX_LENCODE_TABLEBITS),
						  codes->lens.len,
						  LZX_MAX_LEN_CODEWORD_LEN));
	LZX_ASSERT(0 == make_huffman_decode_table(decode_table,
						  LZX_ALIGNEDCODE_NUM_SYMBOLS,
						  min(tablebits, LZX_ALIGNEDCODE_TABLEBITS),
						  codes->lens.aligned,
						  LZX_MAX_ALIGNED_CODEWORD_LEN));
#endif /* ENABLE_LZX_DEBUG */
}

/* Write an LZX aligned offset or verbatim block to the output.  */
static void
lzx_write_compressed_block(int block_type,
			   unsigned block_size,
			   unsigned max_window_size,
			   unsigned num_main_syms,
			   struct lzx_match * chosen_matches,
			   unsigned num_chosen_matches,
			   const struct lzx_codes * codes,
			   const struct lzx_codes * prev_codes,
			   struct output_bitstream * ostream)
{
	unsigned i;

	LZX_ASSERT(block_type == LZX_BLOCKTYPE_ALIGNED ||
		   block_type == LZX_BLOCKTYPE_VERBATIM);
	lzx_assert_codes_valid(codes, num_main_syms);

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

	LZX_DEBUG("Writing main code...");

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

	LZX_DEBUG("Writing length code...");

	/* Write the precode and lengths for the length code.  */
	lzx_write_compressed_code(ostream,
				  codes->lens.len,
				  prev_codes->lens.len,
				  LZX_LENCODE_NUM_SYMBOLS);

	LZX_DEBUG("Writing matches and literals...");

	/* Write the actual matches and literals.  */
	lzx_write_matches_and_literals(ostream, block_type,
				       chosen_matches, num_chosen_matches,
				       codes);

	LZX_DEBUG("Done writing block.");
}

/* Write out the LZX blocks that were computed.  */
static void
lzx_write_all_blocks(struct lzx_compressor *ctx, struct output_bitstream *ostream)
{

	const struct lzx_codes *prev_codes = &ctx->zero_codes;
	for (unsigned i = 0; i < ctx->num_blocks; i++) {
		const struct lzx_block_spec *spec = &ctx->block_specs[i];

		LZX_DEBUG("Writing block %u/%u (type=%d, size=%u, num_chosen_matches=%u)...",
			  i + 1, ctx->num_blocks,
			  spec->block_type, spec->block_size,
			  spec->num_chosen_matches);

		lzx_write_compressed_block(spec->block_type,
					   spec->block_size,
					   ctx->max_window_size,
					   ctx->num_main_syms,
					   &ctx->chosen_matches[spec->chosen_matches_start_pos],
					   spec->num_chosen_matches,
					   &spec->codes,
					   prev_codes,
					   ostream);

		prev_codes = &spec->codes;
	}
}

/* Constructs an LZX match from a literal byte and updates the main code symbol
 * frequencies.  */
static u32
lzx_tally_literal(u8 lit, struct lzx_freqs *freqs)
{
	freqs->main[lit]++;
	return (u32)lit;
}

/* Constructs an LZX match from an offset and a length, and updates the LRU
 * queue and the frequency of symbols in the main, length, and aligned offset
 * alphabets.  The return value is a 32-bit number that provides the match in an
 * intermediate representation documented below.  */
static u32
lzx_tally_match(unsigned match_len, unsigned match_offset,
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
	 * intermediate representation.  See `struct lzx_match' for details.
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

struct lzx_record_ctx {
	struct lzx_freqs freqs;
	struct lzx_lru_queue queue;
	struct lzx_match *matches;
};

static void
lzx_record_match(unsigned len, unsigned offset, void *_ctx)
{
	struct lzx_record_ctx *ctx = _ctx;

	(ctx->matches++)->data = lzx_tally_match(len, offset, &ctx->freqs, &ctx->queue);
}

static void
lzx_record_literal(u8 lit, void *_ctx)
{
	struct lzx_record_ctx *ctx = _ctx;

	(ctx->matches++)->data = lzx_tally_literal(lit, &ctx->freqs);
}

/* Returns the cost, in bits, to output a literal byte using the specified cost
 * model.  */
static unsigned
lzx_literal_cost(u8 c, const struct lzx_costs * costs)
{
	return costs->main[c];
}

/* Given a (length, offset) pair that could be turned into a valid LZX match as
 * well as costs for the codewords in the main, length, and aligned Huffman
 * codes, return the approximate number of bits it will take to represent this
 * match in the compressed output.  Take into account the match offset LRU
 * queue and optionally update it.  */
static unsigned
lzx_match_cost(unsigned length, unsigned offset, const struct lzx_costs *costs,
	       struct lzx_lru_queue *queue)
{
	unsigned position_slot;
	unsigned len_header, main_symbol;
	unsigned cost = 0;

	position_slot = lzx_get_position_slot(offset, queue);

	len_header = min(length - LZX_MIN_MATCH_LEN, LZX_NUM_PRIMARY_LENS);
	main_symbol = ((position_slot << 3) | len_header) + LZX_NUM_CHARS;

	/* Account for main symbol.  */
	cost += costs->main[main_symbol];

	/* Account for extra position information.  */
	unsigned num_extra_bits = lzx_get_num_extra_bits(position_slot);
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

/* Fast heuristic cost evaluation to use in the inner loop of the match-finder.
 * Unlike lzx_match_cost() which does a true cost evaluation, this simply
 * prioritize matches based on their offset.  */
static block_cost_t
lzx_match_cost_fast(unsigned offset, const struct lzx_lru_queue *queue)
{
	/* It seems well worth it to take the time to give priority to recently
	 * used offsets.  */
	for (unsigned i = 0; i < LZX_NUM_RECENT_OFFSETS; i++)
		if (offset == queue->R[i])
			return i;

	BUILD_BUG_ON(LZX_MAX_WINDOW_SIZE >= (block_cost_t)~0U);
	return offset;
}

/* Set the cost model @ctx->costs from the Huffman codeword lengths specified in
 * @lens.
 *
 * The cost model and codeword lengths are almost the same thing, but the
 * Huffman codewords with length 0 correspond to symbols with zero frequency
 * that still need to be assigned actual costs.  The specific values assigned
 * are arbitrary, but they should be fairly high (near the maximum codeword
 * length) to take into account the fact that uses of these symbols are expected
 * to be rare.  */
static void
lzx_set_costs(struct lzx_compressor * ctx, const struct lzx_lens * lens)
{
	unsigned i;
	unsigned num_main_syms = ctx->num_main_syms;

	/* Main code  */
	for (i = 0; i < num_main_syms; i++) {
		ctx->costs.main[i] = lens->main[i];
		if (ctx->costs.main[i] == 0)
			ctx->costs.main[i] = ctx->params.alg_params.slow.main_nostat_cost;
	}

	/* Length code  */
	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++) {
		ctx->costs.len[i] = lens->len[i];
		if (ctx->costs.len[i] == 0)
			ctx->costs.len[i] = ctx->params.alg_params.slow.len_nostat_cost;
	}

	/* Aligned offset code  */
	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
		ctx->costs.aligned[i] = lens->aligned[i];
		if (ctx->costs.aligned[i] == 0)
			ctx->costs.aligned[i] = ctx->params.alg_params.slow.aligned_nostat_cost;
	}
}

/* Advance the suffix array match-finder to the next position.  */
static void
lzx_lz_update_salink(input_idx_t i,
		     const input_idx_t SA[restrict],
		     const input_idx_t ISA[restrict],
		     struct salink link[restrict])
{
	/* r = Rank of the suffix at the current position.  */
	const input_idx_t r = ISA[i];

	/* next = rank of LOWEST ranked suffix that is ranked HIGHER than the
	 * current suffix AND has a LOWER position, or -1 if none exists.  */
	const input_idx_t next = link[r].next;

	/* prev = rank of HIGHEST ranked suffix that is ranked LOWER than the
	 * current suffix AND has a LOWER position, or -1 if none exists.  */
	const input_idx_t prev = link[r].prev;

	/* Link the suffix at the current position into the linked list that
	 * contains all suffixes in the suffix array that are appear at or
	 * before the current position, sorted by rank.
	 *
	 * Save the values of all fields we overwrite so that rollback is
	 * possible.  */
	if (next != (input_idx_t)~0U) {

		link[next].prev = r;
		link[next].lcpprev = link[r].lcpnext;
	}

	if (prev != (input_idx_t)~0U) {

		link[prev].next = r;
		link[prev].lcpnext = link[r].lcpprev;
	}
}

/*
 * Use the suffix array match-finder to retrieve a list of LZ matches at the
 * current position.
 *
 * [in]    @i		Current position in the window.
 * [in]    @SA		Suffix array for the window.
 * [in]    @ISA		Inverse suffix array for the window.
 * [inout] @link	Suffix array links used internally by the match-finder.
 * [out]   @matches	The (length, offset) pairs of the resulting matches will
 *				be written here, sorted in decreasing order by
 *				length.  All returned lengths will be unique.
 * [in]    @queue	Recently used match offsets, used when evaluating the
 *				cost of matches.
 * [in]	   @min_match_len	Minimum match length to return.
 * [in]	   @max_matches_to_consider	Maximum number of matches to consider at
 *					the position.
 * [in]	   @max_matches_to_return	Maximum number of matches to return.
 *
 * The return value is the number of matches found and written to @matches.
 */
static unsigned
lzx_lz_get_matches(const input_idx_t i,
		   const input_idx_t SA[const restrict],
		   const input_idx_t ISA[const restrict],
		   struct salink link[const restrict],
		   struct raw_match matches[const restrict],
		   const struct lzx_lru_queue * const restrict queue,
		   const unsigned min_match_len,
		   const u32 max_matches_to_consider,
		   const u32 max_matches_to_return)
{
	/* r = Rank of the suffix at the current position.  */
	const input_idx_t r = ISA[i];

	/* Prepare for searching the current position.  */
	lzx_lz_update_salink(i, SA, ISA, link);

	/* L = rank of next suffix to the left;
	 * R = rank of next suffix to the right;
	 * lenL = length of match between current position and the suffix with rank L;
	 * lenR = length of match between current position and the suffix with rank R.
	 *
	 * This is left and right relative to the rank of the current suffix.
	 * Since the suffixes in the suffix array are sorted, the longest
	 * matches are immediately to the left and right (using the linked list
	 * to ignore all suffixes that occur later in the window).  The match
	 * length decreases the farther left and right we go.  We shall keep the
	 * length on both sides in sync in order to choose the lowest-cost match
	 * of each length.
	 */
	input_idx_t L = link[r].prev;
	input_idx_t R = link[r].next;
	input_idx_t lenL = link[r].lcpprev;
	input_idx_t lenR = link[r].lcpnext;

	/* nmatches = number of matches found so far.  */
	unsigned nmatches = 0;

	/* best_cost = cost of lowest-cost match found so far.
	 *
	 * We keep track of this so that we can ignore shorter matches that do
	 * not have lower costs than a longer matches already found.
	 */
	block_cost_t best_cost = INFINITE_BLOCK_COST;

	/* count_remaining = maximum number of possible matches remaining to be
	 * considered.  */
	u32 count_remaining = max_matches_to_consider;

	/* pending = match currently being considered for a specific length.  */
	struct raw_match pending;
	block_cost_t pending_cost;

	while (lenL >= min_match_len || lenR >= min_match_len)
	{
		pending.len = lenL;
		pending_cost = INFINITE_BLOCK_COST;
		block_cost_t cost;

		/* Extend left.  */
		if (lenL >= min_match_len && lenL >= lenR) {
			for (;;) {

				if (--count_remaining == 0)
					goto out_save_pending;

				input_idx_t offset = i - SA[L];

				/* Save match if it has smaller cost.  */
				cost = lzx_match_cost_fast(offset, queue);
				if (cost < pending_cost) {
					pending.offset = offset;
					pending_cost = cost;
				}

				if (link[L].lcpprev < lenL) {
					/* Match length decreased.  */

					lenL = link[L].lcpprev;

					/* Save the pending match unless the
					 * right side still may have matches of
					 * this length to be scanned, or if a
					 * previous (longer) match had lower
					 * cost.  */
					if (pending.len > lenR) {
						if (pending_cost < best_cost) {
							best_cost = pending_cost;
							matches[nmatches++] = pending;
							if (nmatches == max_matches_to_return)
								return nmatches;
						}
						pending.len = lenL;
						pending_cost = INFINITE_BLOCK_COST;
					}
					if (lenL < min_match_len || lenL < lenR)
						break;
				}
				L = link[L].prev;
			}
		}

		pending.len = lenR;

		/* Extend right.  */
		if (lenR >= min_match_len && lenR > lenL) {
			for (;;) {

				if (--count_remaining == 0)
					goto out_save_pending;

				input_idx_t offset = i - SA[R];

				/* Save match if it has smaller cost.  */
				cost = lzx_match_cost_fast(offset, queue);
				if (cost < pending_cost) {
					pending.offset = offset;
					pending_cost = cost;
				}

				if (link[R].lcpnext < lenR) {
					/* Match length decreased.  */

					lenR = link[R].lcpnext;

					/* Save the pending match unless a
					 * previous (longer) match had lower
					 * cost.  */
					if (pending_cost < best_cost) {
						matches[nmatches++] = pending;
						best_cost = pending_cost;
						if (nmatches == max_matches_to_return)
							return nmatches;
					}

					if (lenR < min_match_len || lenR <= lenL)
						break;

					pending.len = lenR;
					pending_cost = INFINITE_BLOCK_COST;
				}
				R = link[R].next;
			}
		}
	}
	goto out;

out_save_pending:
	if (pending_cost != INFINITE_BLOCK_COST)
		matches[nmatches++] = pending;

out:
	return nmatches;
}


/* Tell the match-finder to skip the specified number of bytes (@n) in the
 * input.  */
static void
lzx_lz_skip_bytes(struct lzx_compressor *ctx, unsigned n)
{
	LZX_ASSERT(n <= ctx->match_window_end - ctx->match_window_pos);
	if (ctx->matches_cached) {
		ctx->match_window_pos += n;
		while (n--) {
			ctx->cached_matches_pos +=
				ctx->cached_matches[ctx->cached_matches_pos].len + 1;
		}
	} else {
		while (n--) {
			ctx->cached_matches[ctx->cached_matches_pos++].len = 0;
			lzx_lz_update_salink(ctx->match_window_pos++, ctx->SA,
					     ctx->ISA, ctx->salink);
		}
	}
}

/* Retrieve a list of matches available at the next position in the input.
 *
 * The matches are written to ctx->matches in decreasing order of length, and
 * the return value is the number of matches found.  */
static unsigned
lzx_lz_get_matches_caching(struct lzx_compressor *ctx,
			   const struct lzx_lru_queue *queue,
			   struct raw_match **matches_ret)
{
	unsigned num_matches;
	struct raw_match *matches;

	LZX_ASSERT(ctx->match_window_pos <= ctx->match_window_end);

	matches = &ctx->cached_matches[ctx->cached_matches_pos + 1];

	if (ctx->matches_cached) {
		num_matches = matches[-1].len;
	} else {
		unsigned min_match_len = LZX_MIN_MATCH_LEN;
		if (!ctx->params.alg_params.slow.use_len2_matches)
			min_match_len = max(min_match_len, 3);
		const u32 max_search_depth = ctx->params.alg_params.slow.max_search_depth;
		const u32 max_matches_per_pos = ctx->params.alg_params.slow.max_matches_per_pos;

		if (unlikely(max_search_depth == 0 || max_matches_per_pos == 0))
			num_matches = 0;
		else
			num_matches = lzx_lz_get_matches(ctx->match_window_pos,
							 ctx->SA,
							 ctx->ISA,
							 ctx->salink,
							 matches,
							 queue,
							 min_match_len,
							 max_search_depth,
							 max_matches_per_pos);
		matches[-1].len = num_matches;
	}
	ctx->cached_matches_pos += num_matches + 1;
	*matches_ret = matches;

	/* Cap the length of returned matches to the number of bytes remaining,
	 * if it is not the whole window.  */
	if (ctx->match_window_end < ctx->window_size) {
		unsigned maxlen = ctx->match_window_end - ctx->match_window_pos;
		for (unsigned i = 0; i < num_matches; i++)
			if (matches[i].len > maxlen)
				matches[i].len = maxlen;
	}
#if 0
	fprintf(stderr, "Pos %u/%u: %u matches\n",
		ctx->match_window_pos, ctx->match_window_end, num_matches);
	for (unsigned i = 0; i < num_matches; i++)
		fprintf(stderr, "\tLen %u Offset %u\n", matches[i].len, matches[i].offset);
#endif

#ifdef ENABLE_LZX_DEBUG
	for (unsigned i = 0; i < num_matches; i++) {
		LZX_ASSERT(matches[i].len >= LZX_MIN_MATCH_LEN);
		LZX_ASSERT(matches[i].len <= LZX_MAX_MATCH_LEN);
		LZX_ASSERT(matches[i].len <= ctx->match_window_end - ctx->match_window_pos);
		LZX_ASSERT(matches[i].offset > 0);
		LZX_ASSERT(matches[i].offset <= ctx->match_window_pos);
		LZX_ASSERT(!memcmp(&ctx->window[ctx->match_window_pos],
				   &ctx->window[ctx->match_window_pos - matches[i].offset],
				   matches[i].len));
	}
#endif

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
 * Choose the optimal match or literal to use at the next position in the input.
 *
 * Unlike a greedy parser that always takes the longest match, or even a
 * parser with one match/literal look-ahead like zlib, the algorithm used here
 * may look ahead many matches/literals to determine the optimal match/literal to
 * output next.  The motivation is that the compression ratio is improved if the
 * compressor can do things like use a shorter-than-possible match in order to
 * allow a longer match later, and also take into account the Huffman code cost
 * model rather than simply assuming that longer is better.
 *
 * Still, this is not truly an optimal parser because very long matches are
 * taken immediately, and the raw match-finder takes some shortcuts.  This is
 * done to avoid considering many different alternatives that are unlikely to
 * be significantly better.
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
 *
 *	Plus any state used by the raw match-finder.
 *
 * The return value is a (length, offset) pair specifying the match or literal
 * chosen.  For literals, the length is less than LZX_MIN_MATCH_LEN and the
 * offset is meaningless.
 */
static struct raw_match
lzx_lz_get_near_optimal_match(struct lzx_compressor * ctx)
{
	unsigned num_possible_matches;
	struct raw_match *possible_matches;
	struct raw_match match;
	unsigned longest_match_len;

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
	num_possible_matches = lzx_lz_get_matches_caching(ctx, &ctx->queue, &possible_matches);

	/* If no matches found, return literal.  */
	if (num_possible_matches == 0)
		return (struct raw_match){ .len = 0 };

	/* The matches that were found are sorted in decreasing order by length.
	 * Get the length of the longest one.  */
	longest_match_len = possible_matches[0].len;

	/* Greedy heuristic:  if the longest match that was found is greater
	 * than the number of fast bytes, return it immediately; don't both
	 * doing more work.  */
	if (longest_match_len > ctx->params.alg_params.slow.num_fast_bytes) {
		lzx_lz_skip_bytes(ctx, longest_match_len - 1);
		return possible_matches[0];
	}

	/* Calculate the cost to reach the next position by outputting a
	 * literal.  */
	ctx->optimum[0].queue = ctx->queue;
	ctx->optimum[1].queue = ctx->optimum[0].queue;
	ctx->optimum[1].cost = lzx_literal_cost(ctx->window[ctx->match_window_pos],
						&ctx->costs);
	ctx->optimum[1].prev.link = 0;

	/* Calculate the cost to reach any position up to and including that
	 * reached by the longest match, using the shortest (i.e. closest) match
	 * that reaches each position.  */
	BUILD_BUG_ON(LZX_MIN_MATCH_LEN != 2);
	for (unsigned len = LZX_MIN_MATCH_LEN, match_idx = num_possible_matches - 1;
	     len <= longest_match_len; len++) {

		LZX_ASSERT(match_idx < num_possible_matches);

		ctx->optimum[len].queue = ctx->optimum[0].queue;
		ctx->optimum[len].prev.link = 0;
		ctx->optimum[len].prev.match_offset = possible_matches[match_idx].offset;
		ctx->optimum[len].cost = lzx_match_cost(len,
							possible_matches[match_idx].offset,
							&ctx->costs,
							&ctx->optimum[len].queue);
		if (len == possible_matches[match_idx].len)
			match_idx--;
	}

	unsigned cur_pos = 0;

	/* len_end: greatest index forward at which costs have been calculated
	 * so far  */
	unsigned len_end = longest_match_len;

	for (;;) {
		/* Advance to next position.  */
		cur_pos++;

		if (cur_pos == len_end || cur_pos == LZX_OPTIM_ARRAY_SIZE)
			return lzx_lz_reverse_near_optimal_match_list(ctx, cur_pos);

		/* retrieve the number of matches available at this position  */
		num_possible_matches = lzx_lz_get_matches_caching(ctx, &ctx->optimum[cur_pos].queue,
								  &possible_matches);

		unsigned new_len = 0;

		if (num_possible_matches != 0) {
			new_len = possible_matches[0].len;

			/* Greedy heuristic:  if we found a match greater than
			 * the number of fast bytes, stop immediately.  */
			if (new_len > ctx->params.alg_params.slow.num_fast_bytes) {

				/* Build the list of matches to return and get
				 * the first one.  */
				match = lzx_lz_reverse_near_optimal_match_list(ctx, cur_pos);

				/* Append the long match to the end of the list.  */
				ctx->optimum[cur_pos].next.match_offset =
					possible_matches[0].offset;
				ctx->optimum[cur_pos].next.link = cur_pos + new_len;
				ctx->optimum_end_idx = cur_pos + new_len;

				/* Skip over the remaining bytes of the long match.  */
				lzx_lz_skip_bytes(ctx, new_len - 1);

				/* Return first match in the list  */
				return match;
			}
		}

		/* Consider proceeding with a literal byte.  */
		block_cost_t cur_cost = ctx->optimum[cur_pos].cost;
		block_cost_t cur_plus_literal_cost = cur_cost +
			lzx_literal_cost(ctx->window[ctx->match_window_pos - 1],
					 &ctx->costs);
		if (cur_plus_literal_cost < ctx->optimum[cur_pos + 1].cost) {
			ctx->optimum[cur_pos + 1].cost = cur_plus_literal_cost;
			ctx->optimum[cur_pos + 1].prev.link = cur_pos;
			ctx->optimum[cur_pos + 1].queue = ctx->optimum[cur_pos].queue;
		}

		if (num_possible_matches == 0)
			continue;

		/* Consider proceeding with a match.  */

		while (len_end < cur_pos + new_len)
			ctx->optimum[++len_end].cost = INFINITE_BLOCK_COST;

		for (unsigned len = LZX_MIN_MATCH_LEN, match_idx = num_possible_matches - 1;
		     len <= new_len; len++) {
			LZX_ASSERT(match_idx < num_possible_matches);
			struct lzx_lru_queue q = ctx->optimum[cur_pos].queue;
			block_cost_t cost = cur_cost + lzx_match_cost(len,
								      possible_matches[match_idx].offset,
								      &ctx->costs,
								      &q);

			if (cost < ctx->optimum[cur_pos + len].cost) {
				ctx->optimum[cur_pos + len].cost = cost;
				ctx->optimum[cur_pos + len].prev.link = cur_pos;
				ctx->optimum[cur_pos + len].prev.match_offset =
						possible_matches[match_idx].offset;
				ctx->optimum[cur_pos + len].queue = q;
			}

			if (len == possible_matches[match_idx].len)
				match_idx--;
		}
	}
}

/*
 * Set default symbol costs.
 */
static void
lzx_set_default_costs(struct lzx_costs * costs, unsigned num_main_syms)
{
	unsigned i;

	/* Literal symbols  */
	for (i = 0; i < LZX_NUM_CHARS; i++)
		costs->main[i] = 8;

	/* Match header symbols  */
	for (; i < num_main_syms; i++)
		costs->main[i] = 10;

	/* Length symbols  */
	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
		costs->len[i] = 8;

	/* Aligned offset symbols  */
	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
		costs->aligned[i] = 3;
}

/* Given the frequencies of symbols in a compressed block and the corresponding
 * Huffman codes, return LZX_BLOCKTYPE_ALIGNED or LZX_BLOCKTYPE_VERBATIM if an
 * aligned offset or verbatim block, respectively, will take fewer bits to
 * output.  */
static int
lzx_choose_verbatim_or_aligned(const struct lzx_freqs * freqs,
			       const struct lzx_codes * codes)
{
	unsigned aligned_cost = 0;
	unsigned verbatim_cost = 0;

	/* Verbatim blocks have a constant 3 bits per position footer.  Aligned
	 * offset blocks have an aligned offset symbol per position footer, plus
	 * an extra 24 bits to output the lengths necessary to reconstruct the
	 * aligned offset code itself.  */
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

/* Find a near-optimal sequence of matches/literals with which to output the
 * specified LZX block, then set its type to that which has the minimum cost to
 * output.  */
static void
lzx_optimize_block(struct lzx_compressor *ctx, struct lzx_block_spec *spec,
		   unsigned num_passes)
{
	const struct lzx_lru_queue orig_queue = ctx->queue;
	struct lzx_freqs freqs;

	unsigned orig_window_pos = spec->window_pos;
	unsigned orig_cached_pos = ctx->cached_matches_pos;

	LZX_ASSERT(ctx->match_window_pos == spec->window_pos);

	ctx->match_window_end = spec->window_pos + spec->block_size;
	spec->chosen_matches_start_pos = spec->window_pos;

	LZX_ASSERT(num_passes >= 1);

	/* The first optimal parsing pass is done using the cost model already
	 * set in ctx->costs.  Each later pass is done using a cost model
	 * computed from the previous pass.  */
	for (unsigned pass = 0; pass < num_passes; pass++) {

		ctx->match_window_pos = orig_window_pos;
		ctx->cached_matches_pos = orig_cached_pos;
		ctx->queue = orig_queue;
		spec->num_chosen_matches = 0;
		memset(&freqs, 0, sizeof(freqs));

		for (unsigned i = spec->window_pos; i < spec->window_pos + spec->block_size; ) {
			struct raw_match raw_match;
			struct lzx_match lzx_match;

			raw_match = lzx_lz_get_near_optimal_match(ctx);
			if (raw_match.len >= LZX_MIN_MATCH_LEN) {
				lzx_match.data = lzx_tally_match(raw_match.len, raw_match.offset,
								 &freqs, &ctx->queue);
				i += raw_match.len;
			} else {
				lzx_match.data = lzx_tally_literal(ctx->window[i], &freqs);
				i += 1;
			}
			ctx->chosen_matches[spec->chosen_matches_start_pos +
					    spec->num_chosen_matches++] = lzx_match;
		}

		lzx_make_huffman_codes(&freqs, &spec->codes,
				       ctx->num_main_syms);
		if (pass < num_passes - 1)
			lzx_set_costs(ctx, &spec->codes.lens);
		ctx->matches_cached = true;
	}
	spec->block_type = lzx_choose_verbatim_or_aligned(&freqs, &spec->codes);
	ctx->matches_cached = false;
}

static void
lzx_optimize_blocks(struct lzx_compressor *ctx)
{
	lzx_lru_queue_init(&ctx->queue);
	ctx->optimum_cur_idx = 0;
	ctx->optimum_end_idx = 0;

	const unsigned num_passes = ctx->params.alg_params.slow.num_optim_passes;

	for (unsigned i = 0; i < ctx->num_blocks; i++)
		lzx_optimize_block(ctx, &ctx->block_specs[i], num_passes);
}

/* Initialize the suffix array match-finder for the specified input.  */
static void
lzx_lz_init_matchfinder(const u8 T[const restrict],
			const input_idx_t n,
			input_idx_t SA[const restrict],
			input_idx_t ISA[const restrict],
			input_idx_t LCP[const restrict],
			struct salink link[const restrict],
			const unsigned max_match_len)
{
	/* Compute SA (Suffix Array).  */

	{
		/* ISA and link are used as temporary space.  */
		BUILD_BUG_ON(LZX_MIN_WINDOW_SIZE * sizeof(ISA[0]) < 256 * sizeof(saidx_t));
		BUILD_BUG_ON(LZX_MIN_WINDOW_SIZE * 2 * sizeof(link[0]) < 256 * 256 * sizeof(saidx_t));

		if (sizeof(input_idx_t) == sizeof(saidx_t)) {
			divsufsort(T, SA, n, (saidx_t*)ISA, (saidx_t*)link);
		} else {
			saidx_t sa[n];
			divsufsort(T, sa, n, (saidx_t*)ISA, (saidx_t*)link);
			for (input_idx_t i = 0; i < n; i++)
				SA[i] = sa[i];
		}
	}

#ifdef ENABLE_LZX_DEBUG

	LZX_ASSERT(n > 0);

	/* Verify suffix array.  */
	{
		bool found[n];
		ZERO_ARRAY(found);
		for (input_idx_t r = 0; r < n; r++) {
			input_idx_t i = SA[r];
			LZX_ASSERT(i < n);
			LZX_ASSERT(!found[i]);
			found[i] = true;
		}
	}

	for (input_idx_t r = 0; r < n - 1; r++) {

		input_idx_t i1 = SA[r];
		input_idx_t i2 = SA[r + 1];

		input_idx_t n1 = n - i1;
		input_idx_t n2 = n - i2;

		LZX_ASSERT(memcmp(&T[i1], &T[i2], min(n1, n2)) <= 0);
	}
	LZX_DEBUG("Verified SA (len %u)", n);
#endif /* ENABLE_LZX_DEBUG */

	/* Compute ISA (Inverse Suffix Array)  */
	for (input_idx_t r = 0; r < n; r++)
		ISA[SA[r]] = r;

	/* Compute LCP (longest common prefix) array.
	 *
	 * Algorithm adapted from Kasai et al. 2001: "Linear-Time
	 * Longest-Common-Prefix Computation in Suffix Arrays and Its
	 * Applications".  */
	{
		input_idx_t h = 0;
		for (input_idx_t i = 0; i < n; i++) {
			input_idx_t r = ISA[i];
			if (r > 0) {
				input_idx_t j = SA[r - 1];

				input_idx_t lim = min(n - i, n - j);

				while (h < lim && T[i + h] == T[j + h])
					h++;
				LCP[r] = h;
				if (h > 0)
					h--;
			}
		}
	}

#ifdef ENABLE_LZX_DEBUG
	/* Verify LCP array.  */
	for (input_idx_t r = 0; r < n - 1; r++) {
		LZX_ASSERT(ISA[SA[r]] == r);
		LZX_ASSERT(ISA[SA[r + 1]] == r + 1);

		input_idx_t i1 = SA[r];
		input_idx_t i2 = SA[r + 1];
		input_idx_t lcp = LCP[r + 1];

		input_idx_t n1 = n - i1;
		input_idx_t n2 = n - i2;

		LZX_ASSERT(lcp <= min(n1, n2));

		LZX_ASSERT(memcmp(&T[i1], &T[i2], lcp) == 0);
		if (lcp < min(n1, n2))
			LZX_ASSERT(T[i1 + lcp] != T[i2 + lcp]);
	}
#endif /* ENABLE_LZX_DEBUG */

	/* Compute salink.next and salink.lcpnext.
	 *
	 * Algorithm adapted from Crochemore et al. 2009:
	 * "LPF computation revisited".
	 *
	 * Note: we cap lcpnext to the maximum match length so that the
	 * match-finder need not worry about it later.  */
	link[n - 1].next = (input_idx_t)~0U;
	link[n - 1].prev = (input_idx_t)~0U;
	link[n - 1].lcpnext = 0;
	link[n - 1].lcpprev = 0;
	for (input_idx_t r = n - 2; r != (input_idx_t)~0U; r--) {
		input_idx_t t = r + 1;
		input_idx_t l = LCP[t];
		while (t != (input_idx_t)~0 && SA[t] > SA[r]) {
			l = min(l, link[t].lcpnext);
			t = link[t].next;
		}
		link[r].next = t;
		link[r].lcpnext = min(l, max_match_len);
		LZX_ASSERT(t == (input_idx_t)~0U || l <= n - SA[t]);
		LZX_ASSERT(l <= n - SA[r]);
		LZX_ASSERT(memcmp(&T[SA[r]], &T[SA[t]], l) == 0);
	}

	/* Compute salink.prev and salink.lcpprev.
	 *
	 * Algorithm adapted from Crochemore et al. 2009:
	 * "LPF computation revisited".
	 *
	 * Note: we cap lcpprev to the maximum match length so that the
	 * match-finder need not worry about it later.  */
	link[0].prev = (input_idx_t)~0;
	link[0].next = (input_idx_t)~0;
	link[0].lcpprev = 0;
	link[0].lcpnext = 0;
	for (input_idx_t r = 1; r < n; r++) {
		input_idx_t t = r - 1;
		input_idx_t l = LCP[r];
		while (t != (input_idx_t)~0 && SA[t] > SA[r]) {
			l = min(l, link[t].lcpprev);
			t = link[t].prev;
		}
		link[r].prev = t;
		link[r].lcpprev = min(l, max_match_len);
		LZX_ASSERT(t == (input_idx_t)~0 || l <= n - SA[t]);
		LZX_ASSERT(l <= n - SA[r]);
		LZX_ASSERT(memcmp(&T[SA[r]], &T[SA[t]], l) == 0);
	}
}

/* Prepare the input window into one or more LZX blocks ready to be output.  */
static void
lzx_prepare_blocks(struct lzx_compressor * ctx)
{
	/* Initialize the match-finder.  */
	lzx_lz_init_matchfinder(ctx->window, ctx->window_size,
				ctx->SA, ctx->ISA, ctx->LCP, ctx->salink,
				LZX_MAX_MATCH_LEN);
	ctx->cached_matches_pos = 0;
	ctx->matches_cached = false;
	ctx->match_window_pos = 0;

	/* Set up a default cost model.  */
	lzx_set_default_costs(&ctx->costs, ctx->num_main_syms);

	ctx->num_blocks = DIV_ROUND_UP(ctx->window_size, LZX_DIV_BLOCK_SIZE);
	for (unsigned i = 0; i < ctx->num_blocks; i++) {
		unsigned pos = LZX_DIV_BLOCK_SIZE * i;
		ctx->block_specs[i].window_pos = pos;
		ctx->block_specs[i].block_size = min(ctx->window_size - pos, LZX_DIV_BLOCK_SIZE);
	}

	/* Determine sequence of matches/literals to output for each block.  */
	lzx_optimize_blocks(ctx);
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
 * Output --- the block specification and the corresponding match/literal data:
 *
 *	ctx->block_specs[]
 *	ctx->num_blocks
 *	ctx->chosen_matches[]
 */
static void
lzx_prepare_block_fast(struct lzx_compressor * ctx)
{
	struct lzx_record_ctx record_ctx;
	struct lzx_block_spec *spec;

	/* Parameters to hash chain LZ match finder
	 * (lazy with 1 match lookahead)  */
	static const struct lz_params lzx_lz_params = {
		/* Although LZX_MIN_MATCH_LEN == 2, length 2 matches typically
		 * aren't worth choosing when using greedy or lazy parsing.  */
		.min_match      = 3,
		.max_match      = LZX_MAX_MATCH_LEN,
		.max_offset	= 32768,
		.good_match     = LZX_MAX_MATCH_LEN,
		.nice_match     = LZX_MAX_MATCH_LEN,
		.max_chain_len  = LZX_MAX_MATCH_LEN,
		.max_lazy_match = LZX_MAX_MATCH_LEN,
		.too_far        = 4096,
	};

	/* Initialize symbol frequencies and match offset LRU queue.  */
	memset(&record_ctx.freqs, 0, sizeof(struct lzx_freqs));
	lzx_lru_queue_init(&record_ctx.queue);
	record_ctx.matches = ctx->chosen_matches;

	/* Determine series of matches/literals to output.  */
	lz_analyze_block(ctx->window,
			 ctx->window_size,
			 lzx_record_match,
			 lzx_record_literal,
			 &record_ctx,
			 &lzx_lz_params,
			 ctx->prev_tab);

	/* Set up block specification.  */
	spec = &ctx->block_specs[0];
	spec->block_type = LZX_BLOCKTYPE_ALIGNED;
	spec->window_pos = 0;
	spec->block_size = ctx->window_size;
	spec->num_chosen_matches = (record_ctx.matches - ctx->chosen_matches);
	spec->chosen_matches_start_pos = 0;
	lzx_make_huffman_codes(&record_ctx.freqs, &spec->codes,
			       ctx->num_main_syms);
	ctx->num_blocks = 1;
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
	input_idx_t compressed_len;

	if (uncompressed_len < 100) {
		LZX_DEBUG("Too small to bother compressing.");
		return 0;
	}

	if (uncompressed_len > ctx->max_window_size) {
		LZX_DEBUG("Can't compress %u bytes using window of %u bytes!",
			  uncompressed_len, ctx->max_window_size);
		return 0;
	}

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
	compressed_len = flush_output_bitstream(&ostream);
	if (compressed_len == ~(input_idx_t)0) {
		LZX_DEBUG("Data did not compress to less than original length!");
		return 0;
	}

	LZX_DEBUG("Done: compressed %u => %u bytes.",
		  uncompressed_len, compressed_len);

	/* Verify that we really get the same thing back when decompressing.
	 * Although this could be disabled by default in all cases, it only
	 * takes around 2-3% of the running time of the slow algorithm to do the
	 * verification.  */
	if (ctx->params.algorithm == WIMLIB_LZX_ALGORITHM_SLOW
	#if defined(ENABLE_LZX_DEBUG) || defined(ENABLE_VERIFY_COMPRESSION)
	    || 1
	#endif
	    )
	{
		/* The decompression buffer can be any temporary space that's no
		 * longer needed.  */
		u8 *buf = (u8*)(ctx->SA ? ctx->SA : ctx->prev_tab);

		if (wimlib_lzx_decompress2(compressed_data, compressed_len,
					   buf, uncompressed_len, ctx->max_window_size))
		{
			ERROR("Failed to decompress data we "
			      "compressed using LZX algorithm");
			wimlib_assert(0);
			return 0;
		}

		if (memcmp(uncompressed_data, buf, uncompressed_len)) {
			ERROR("Data we compressed using LZX algorithm "
			      "didn't decompress to original");
			wimlib_assert(0);
			return 0;
		}
	}
	return compressed_len;
}

static bool
lzx_params_compatible(const struct wimlib_lzx_params *oldparams,
		      const struct wimlib_lzx_params *newparams)
{
	return 0 == memcmp(oldparams, newparams, sizeof(struct wimlib_lzx_params));
}

static struct wimlib_lzx_params lzx_user_default_params;
static struct wimlib_lzx_params *lzx_user_default_params_ptr;

static bool
lzx_params_valid(const struct wimlib_lzx_params *params)
{
	/* Validate parameters.  */
	if (params->size_of_this != sizeof(struct wimlib_lzx_params)) {
		LZX_DEBUG("Invalid parameter structure size!");
		return false;
	}

	if (params->algorithm != WIMLIB_LZX_ALGORITHM_SLOW &&
	    params->algorithm != WIMLIB_LZX_ALGORITHM_FAST)
	{
		LZX_DEBUG("Invalid algorithm.");
		return false;
	}

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW) {
		if (params->alg_params.slow.num_optim_passes < 1)
		{
			LZX_DEBUG("Invalid number of optimization passes!");
			return false;
		}

		if (params->alg_params.slow.main_nostat_cost < 1 ||
		    params->alg_params.slow.main_nostat_cost > 16)
		{
			LZX_DEBUG("Invalid main_nostat_cost!");
			return false;
		}

		if (params->alg_params.slow.len_nostat_cost < 1 ||
		    params->alg_params.slow.len_nostat_cost > 16)
		{
			LZX_DEBUG("Invalid len_nostat_cost!");
			return false;
		}

		if (params->alg_params.slow.aligned_nostat_cost < 1 ||
		    params->alg_params.slow.aligned_nostat_cost > 8)
		{
			LZX_DEBUG("Invalid aligned_nostat_cost!");
			return false;
		}
	}
	return true;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_lzx_set_default_params(const struct wimlib_lzx_params * params)
{
	if (params) {
		if (!lzx_params_valid(params))
			return WIMLIB_ERR_INVALID_PARAM;
		lzx_user_default_params = *params;
		lzx_user_default_params_ptr = &lzx_user_default_params;
	} else {
		lzx_user_default_params_ptr = NULL;
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_lzx_alloc_context(u32 window_size,
			 const struct wimlib_lzx_params *params,
			 struct wimlib_lzx_context **ctx_pp)
{

	LZX_DEBUG("Allocating LZX context...");

	if (!lzx_window_size_valid(window_size))
		return WIMLIB_ERR_INVALID_PARAM;

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
				.num_optim_passes = 2,
				.max_search_depth = 50,
				.max_matches_per_pos = 3,
				.main_nostat_cost = 15,
				.len_nostat_cost = 15,
				.aligned_nostat_cost = 7,
			},
		},
	};

	if (params) {
		if (!lzx_params_valid(params))
			return WIMLIB_ERR_INVALID_PARAM;
	} else {
		LZX_DEBUG("Using default algorithm and parameters.");
		if (lzx_user_default_params_ptr)
			params = lzx_user_default_params_ptr;
		else
			params = &slow_default;
	}

	if (params->use_defaults) {
		if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW)
			params = &slow_default;
		else
			params = &fast_default;
	}

	if (ctx_pp) {
		ctx = *(struct lzx_compressor**)ctx_pp;

		if (ctx &&
		    lzx_params_compatible(&ctx->params, params) &&
		    ctx->max_window_size == window_size)
			return 0;
	} else {
		LZX_DEBUG("Check parameters only.");
		return 0;
	}

	LZX_DEBUG("Allocating memory.");

	ctx = CALLOC(1, sizeof(struct lzx_compressor));
	if (ctx == NULL)
		goto err;

	ctx->num_main_syms = lzx_get_num_main_syms(window_size);
	ctx->max_window_size = window_size;
	ctx->window = MALLOC(window_size + 12);
	if (ctx->window == NULL)
		goto err;

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_FAST) {
		ctx->prev_tab = MALLOC(window_size * sizeof(ctx->prev_tab[0]));
		if (ctx->prev_tab == NULL)
			goto err;
	}

	size_t block_specs_length = DIV_ROUND_UP(window_size, LZX_DIV_BLOCK_SIZE);
	ctx->block_specs = MALLOC(block_specs_length * sizeof(ctx->block_specs[0]));
	if (ctx->block_specs == NULL)
		goto err;

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW) {
		ctx->SA = MALLOC(3U * window_size * sizeof(ctx->SA[0]));
		if (ctx->SA == NULL)
			goto err;
		ctx->ISA = ctx->SA + window_size;
		ctx->LCP = ctx->ISA + window_size;

		ctx->salink = MALLOC(window_size * sizeof(ctx->salink[0]));
		if (ctx->salink == NULL)
			goto err;
	}

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW) {
		ctx->optimum = MALLOC((LZX_OPTIM_ARRAY_SIZE + LZX_MAX_MATCH_LEN) *
				       sizeof(ctx->optimum[0]));
		if (ctx->optimum == NULL)
			goto err;
	}

	if (params->algorithm == WIMLIB_LZX_ALGORITHM_SLOW) {
		u32 cache_per_pos;

		cache_per_pos = params->alg_params.slow.max_matches_per_pos;
		if (cache_per_pos > LZX_MAX_CACHE_PER_POS)
			cache_per_pos = LZX_MAX_CACHE_PER_POS;

		ctx->cached_matches = MALLOC(window_size * (cache_per_pos + 1) *
					     sizeof(ctx->cached_matches[0]));
		if (ctx->cached_matches == NULL)
			goto err;
	}

	ctx->chosen_matches = MALLOC(window_size * sizeof(ctx->chosen_matches[0]));
	if (ctx->chosen_matches == NULL)
		goto err;

	memcpy(&ctx->params, params, sizeof(struct wimlib_lzx_params));
	memset(&ctx->zero_codes, 0, sizeof(ctx->zero_codes));

	LZX_DEBUG("Successfully allocated new LZX context.");

	wimlib_lzx_free_context(*ctx_pp);
	*ctx_pp = (struct wimlib_lzx_context*)ctx;
	return 0;

err:
	wimlib_lzx_free_context((struct wimlib_lzx_context*)ctx);
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
		FREE(ctx->cached_matches);
		FREE(ctx->optimum);
		FREE(ctx->salink);
		FREE(ctx->SA);
		FREE(ctx->block_specs);
		FREE(ctx->prev_tab);
		FREE(ctx->window);
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

	ret = wimlib_lzx_alloc_context(32768, NULL, &ctx);
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
