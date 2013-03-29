/*
 * lzx-compress.c
 *
 * LZX compression routines, originally based on code written by Matthew T.
 * Russotto (liblzxcomp), but heavily modified.
 */

/*
 * Copyright (C) 2002 Matthew T. Russotto
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
 * This file provides wimlib_lzx_compress(), a function to compress an in-memory
 * buffer of data using LZX compression, as used in the WIM file format.
 *
 * Please see the comments in lzx-decompress.c for more information about this
 * compression format.
 *
 * One thing to keep in mind is that there is no sliding window, since the
 * window is always the entirety of a WIM chunk, which is at most WIM_CHUNK_SIZE
 * ( = 32768) bytes.
 *
 * The basic compression algorithm used here should be familiar if you are
 * familiar with Huffman trees and with other LZ77 and Huffman-based formats
 * such as DEFLATE.  Otherwise it can be quite tricky to understand.  Basically
 * it is the following:
 *
 * - Preprocess the input data (LZX-specific)
 * - Go through the input data and determine matches.  This part is based on
 *       code from zlib, and a hash table of 3-character strings is used to
 *       accelerate the process of finding matches.
 * - Build the Huffman trees based on the frequencies of symbols determined
 *       while recording matches.
 * - Output the block header, including the Huffman trees; then output the
 *       compressed stream of matches and literal characters.
 *
 * It is possible for a WIM chunk to include multiple LZX blocks, since for some
 * input data this will produce a better compression ratio (especially since
 * each block can include new Huffman codes).  However, producing multiple LZX
 * blocks from one input chunk is not yet implemented.
 */

#include "wimlib.h"
#include "lzx.h"
#include "compress.h"
#include <stdlib.h>
#include <string.h>


/* Structure to contain the Huffman codes for the main, length, and aligned
 * offset trees. */
struct lzx_codes {
	u16 main_codewords[LZX_MAINTREE_NUM_SYMBOLS];
	u8  main_lens[LZX_MAINTREE_NUM_SYMBOLS];

	u16 len_codewords[LZX_LENTREE_NUM_SYMBOLS];
	u8  len_lens[LZX_LENTREE_NUM_SYMBOLS];

	u16 aligned_codewords[LZX_ALIGNEDTREE_NUM_SYMBOLS];
	u8  aligned_lens[LZX_ALIGNEDTREE_NUM_SYMBOLS];
};

struct lzx_freq_tables {
	freq_t main_freq_table[LZX_MAINTREE_NUM_SYMBOLS];
	freq_t len_freq_table[LZX_LENTREE_NUM_SYMBOLS];
	freq_t aligned_freq_table[LZX_ALIGNEDTREE_NUM_SYMBOLS];
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
static inline unsigned
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
		wimlib_assert(formatted_offset >= 2 && formatted_offset < 655360);
		unsigned mssb_idx = bsr32(formatted_offset);
		return (mssb_idx << 1) |
			((formatted_offset >> (mssb_idx - 1)) & 1);
	}
}

static u32
lzx_record_literal(u8 literal, void *__main_freq_tab)
{
	freq_t *main_freq_tab = __main_freq_tab;
	main_freq_tab[literal]++;
	return literal;
}

/* Constructs a match from an offset and a length, and updates the LRU queue and
 * the frequency of symbols in the main, length, and aligned offset alphabets.
 * The return value is a 32-bit number that provides the match in an
 * intermediate representation documented below. */
static u32
lzx_record_match(unsigned match_offset, unsigned match_len,
		 void *__freq_tabs, void *__queue)
{
	struct lzx_freq_tables *freq_tabs = __freq_tabs;
	struct lru_queue *queue = __queue;
	unsigned position_slot;
	unsigned position_footer = 0;
	u32 match;
	u32 len_header;
	u32 len_pos_header;
	unsigned len_footer;
	unsigned adjusted_match_len;

	wimlib_assert(match_len >= LZX_MIN_MATCH && match_len <= LZX_MAX_MATCH);
	wimlib_assert(match_offset != 0);

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
		unsigned formatted_offset = match_offset + LZX_MIN_MATCH;

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
	match = 0x80000000 |
		(position_slot << 25) |
		(position_footer << 8) |
		(adjusted_match_len);

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
		freq_tabs->len_freq_table[len_footer]++;
	}
	len_pos_header = (position_slot << 3) | len_header;

	wimlib_assert(len_pos_header < LZX_MAINTREE_NUM_SYMBOLS - LZX_NUM_CHARS);

	freq_tabs->main_freq_table[len_pos_header + LZX_NUM_CHARS]++;

	/* Equivalent to:
	 * if (lzx_extra_bits[position_slot] >= 3) */
	if (position_slot >= 8)
		freq_tabs->aligned_freq_table[position_footer & 7]++;

	return match;
}

/*
 * Writes a compressed literal match to the output.
 *
 * @out:         The output bitstream.
 * @block_type:  The type of the block (LZX_BLOCKTYPE_ALIGNED or LZX_BLOCKTYPE_VERBATIM)
 * @match:   	 The match, encoded as a 32-bit number.
 * @codes:	Pointer to a structure that contains the codewords for the
 * 			main, length, and aligned offset Huffman codes.
 */
static int
lzx_write_match(struct output_bitstream *out, int block_type,
		u32 match, const struct lzx_codes *codes)
{
	/* low 8 bits are the match length minus 2 */
	unsigned match_len_minus_2 = match & 0xff;
	/* Next 17 bits are the position footer */
	unsigned position_footer = (match >> 8) & 0x1ffff;	/* 17 bits */
	/* Next 6 bits are the position slot. */
	unsigned position_slot = (match >> 25) & 0x3f;	/* 6 bits */
	unsigned len_header;
	unsigned len_footer;
	unsigned len_pos_header;
	unsigned main_symbol;
	unsigned num_extra_bits;
	unsigned verbatim_bits;
	unsigned aligned_bits;
	int ret;

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
	ret = bitstream_put_bits(out, codes->main_codewords[main_symbol],
				 codes->main_lens[main_symbol]);
	if (ret != 0)
		return ret;

	/* If there is a length footer, output it using the
	 * length Huffman code. */
	if (len_footer != (unsigned)(-1)) {
		ret = bitstream_put_bits(out, codes->len_codewords[len_footer],
					 codes->len_lens[len_footer]);
		if (ret != 0)
			return ret;
	}

	wimlib_assert(position_slot < LZX_NUM_POSITION_SLOTS);

	num_extra_bits = lzx_get_num_extra_bits(position_slot);

	/* For aligned offset blocks with at least 3 extra bits, output the
	 * verbatim bits literally, then the aligned bits encoded using the
	 * aligned offset tree.  Otherwise, only the verbatim bits need to be
	 * output. */
	if ((block_type == LZX_BLOCKTYPE_ALIGNED) && (num_extra_bits >= 3)) {

		verbatim_bits = position_footer >> 3;
		ret = bitstream_put_bits(out, verbatim_bits,
					 num_extra_bits - 3);
		if (ret != 0)
			return ret;

		aligned_bits = (position_footer & 7);
		ret = bitstream_put_bits(out,
					 codes->aligned_codewords[aligned_bits],
					 codes->aligned_lens[aligned_bits]);
		if (ret != 0)
			return ret;
	} else {
		/* verbatim bits is the same as the position
		 * footer, in this case. */
		ret = bitstream_put_bits(out, position_footer, num_extra_bits);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/*
 * Writes all compressed literals in a block, both matches and literal bytes, to
 * the output bitstream.
 *
 * @out:         The output bitstream.
 * @block_type:  The type of the block (LZX_BLOCKTYPE_ALIGNED or LZX_BLOCKTYPE_VERBATIM)
 * @match_tab[]:   The array of matches that will be output.  It has length
 * 			of @num_compressed_literals.
 * @num_compressed_literals:  Number of compressed literals to be output.
 * @codes:	Pointer to a structure that contains the codewords for the
 * 			main, length, and aligned offset Huffman codes.
 */
static int
lzx_write_compressed_literals(struct output_bitstream *ostream,
			      int block_type,
			      const u32 match_tab[],
			      unsigned  num_compressed_literals,
			      const struct lzx_codes *codes)
{
	unsigned i;
	u32 match;
	int ret;

	for (i = 0; i < num_compressed_literals; i++) {
		match = match_tab[i];

		/* High bit of the match indicates whether the match is an
		 * actual match (1) or a literal uncompressed byte (0) */
		if (match & 0x80000000) {
			/* match */
			ret = lzx_write_match(ostream, block_type, match,
					      codes);
			if (ret != 0)
				return ret;
		} else {
			/* literal byte */
			wimlib_assert(match < LZX_NUM_CHARS);
			ret = bitstream_put_bits(ostream,
						 codes->main_codewords[match],
						 codes->main_lens[match]);
			if (ret != 0)
				return ret;
		}
	}
	return 0;
}

/*
 * Writes a compressed Huffman tree to the output, preceded by the pretree for
 * it.
 *
 * The Huffman tree is represented in the output as a series of path lengths
 * from which the canonical Huffman code can be reconstructed.  The path lengths
 * themselves are compressed using a separate Huffman code, the pretree, which
 * consists of LZX_PRETREE_NUM_SYMBOLS (= 20) symbols that cover all possible code
 * lengths, plus extra codes for repeated lengths.  The path lengths of the
 * pretree precede the path lengths of the larger code and are uncompressed,
 * consisting of 20 entries of 4 bits each.
 *
 * @out:	The bitstream for the compressed output.
 * @lens:	The code lengths for the Huffman tree, indexed by symbol.
 * @num_symbols:	The number of symbols in the code.
 */
static int
lzx_write_compressed_tree(struct output_bitstream *out,
			  const u8 lens[], unsigned num_symbols)
{
	/* Frequencies of the length symbols, including the RLE symbols (NOT the
	 * actual lengths themselves). */
	freq_t pretree_freqs[LZX_PRETREE_NUM_SYMBOLS];
	u8 pretree_lens[LZX_PRETREE_NUM_SYMBOLS];
	u16 pretree_codewords[LZX_PRETREE_NUM_SYMBOLS];
	u8 output_syms[num_symbols * 2];
	unsigned output_syms_idx;
	unsigned cur_run_len;
	unsigned i;
	unsigned len_in_run;
	unsigned additional_bits;
	char delta;
	u8 pretree_sym;

	ZERO_ARRAY(pretree_freqs);

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
	for (i = 1; i <= num_symbols; i++) {

		if (i != num_symbols && lens[i] == lens[i - 1]) {
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
				pretree_freqs[18]++;
				output_syms[output_syms_idx++] = 18;
				output_syms[output_syms_idx++] = additional_bits;
				cur_run_len -= 20 + additional_bits;
			}

			/* The magic length 17 indicates a run of 4 + n zeroes,
			 * where n is an uncompressed literal 4-bit integer that
			 * follows the magic length. */
			while (cur_run_len >= 4) {
				additional_bits = min(cur_run_len - 4, 0xf);
				pretree_freqs[17]++;
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
			 * with the pretree, that follows the literal bit.
			 *
			 * The extra length symbol is encoded as a difference
			 * from the length of the codeword for the first symbol
			 * in the run in the previous tree.
			 * */
			while (cur_run_len >= 4) {
				additional_bits = (cur_run_len > 4);
				delta = -(char)len_in_run;
				if (delta < 0)
					delta += 17;
				pretree_freqs[19]++;
				pretree_freqs[(unsigned char)delta]++;
				output_syms[output_syms_idx++] = 19;
				output_syms[output_syms_idx++] = additional_bits;
				output_syms[output_syms_idx++] = delta;
				cur_run_len -= 4 + additional_bits;
			}
		}

		/* Any remaining lengths in the run are outputted without RLE,
		 * as a difference from the length of that codeword in the
		 * previous tree. */
		while (cur_run_len--) {
			delta = -(char)len_in_run;
			if (delta < 0)
				delta += 17;

			pretree_freqs[(unsigned char)delta]++;
			output_syms[output_syms_idx++] = delta;
		}

		cur_run_len = 1;
	}

	wimlib_assert(output_syms_idx < ARRAY_LEN(output_syms));

	/* Build the pretree from the frequencies of the length symbols. */

	make_canonical_huffman_code(LZX_PRETREE_NUM_SYMBOLS,
				    LZX_MAX_CODEWORD_LEN,
				    pretree_freqs, pretree_lens,
				    pretree_codewords);

	/* Write the lengths of the pretree codes to the output. */
	for (i = 0; i < LZX_PRETREE_NUM_SYMBOLS; i++)
		bitstream_put_bits(out, pretree_lens[i],
				   LZX_PRETREE_ELEMENT_SIZE);

	/* Write the length symbols, encoded with the pretree, to the output. */

	i = 0;
	while (i < output_syms_idx) {
		pretree_sym = output_syms[i++];

		bitstream_put_bits(out, pretree_codewords[pretree_sym],
				   pretree_lens[pretree_sym]);
		switch (pretree_sym) {
		case 17:
			bitstream_put_bits(out, output_syms[i++], 4);
			break;
		case 18:
			bitstream_put_bits(out, output_syms[i++], 5);
			break;
		case 19:
			bitstream_put_bits(out, output_syms[i++], 1);
			bitstream_put_bits(out,
					   pretree_codewords[output_syms[i]],
					   pretree_lens[output_syms[i]]);
			i++;
			break;
		default:
			break;
		}
	}
	return 0;
}

/* Builds the canonical Huffman code for the main tree, the length tree, and the
 * aligned offset tree. */
static void
lzx_make_huffman_codes(const struct lzx_freq_tables *freq_tabs,
		       struct lzx_codes *codes)
{
	make_canonical_huffman_code(LZX_MAINTREE_NUM_SYMBOLS,
					LZX_MAX_CODEWORD_LEN,
					freq_tabs->main_freq_table,
					codes->main_lens,
					codes->main_codewords);

	make_canonical_huffman_code(LZX_LENTREE_NUM_SYMBOLS,
					LZX_MAX_CODEWORD_LEN,
					freq_tabs->len_freq_table,
					codes->len_lens,
					codes->len_codewords);

	make_canonical_huffman_code(LZX_ALIGNEDTREE_NUM_SYMBOLS, 8,
					freq_tabs->aligned_freq_table,
					codes->aligned_lens,
					codes->aligned_codewords);
}

static void
do_call_insn_translation(u32 *call_insn_target, int input_pos,
			 int32_t file_size)
{
	int32_t abs_offset;
	int32_t rel_offset;

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
 * See the comment above that function for more information. */
static void
do_call_insn_preprocessing(u8 uncompressed_data[], int uncompressed_data_len)
{
	for (int i = 0; i < uncompressed_data_len - 10; i++) {
		if (uncompressed_data[i] == 0xe8) {
			do_call_insn_translation((u32*)&uncompressed_data[i + 1],
						 i,
						 LZX_WIM_MAGIC_FILESIZE);
			i += 4;
		}
	}
}


static const struct lz_params lzx_lz_params = {

	 /* LZX_MIN_MATCH == 2, but 2-character matches are rarely useful; the
	  * minimum match for compression is set to 3 instead. */
	.min_match      = 3,

	.max_match      = LZX_MAX_MATCH,
	.good_match	= LZX_MAX_MATCH,
	.nice_match     = LZX_MAX_MATCH,
	.max_chain_len  = LZX_MAX_MATCH,
	.max_lazy_match = LZX_MAX_MATCH,
	.too_far        = 4096,
};

/* Documented in wimlib.h */
WIMLIBAPI unsigned
wimlib_lzx_compress(const void *__uncompressed_data, unsigned uncompressed_len,
		    void *compressed_data)
{
	struct output_bitstream ostream;
	u8 uncompressed_data[uncompressed_len + 8];
	struct lzx_freq_tables freq_tabs;
	struct lzx_codes codes;
	u32 match_tab[uncompressed_len];
	struct lru_queue queue;
	unsigned num_matches;
	unsigned compressed_len;
	unsigned i;
	int ret;
	int block_type = LZX_BLOCKTYPE_ALIGNED;

	wimlib_assert(uncompressed_len <= 32768);

	if (uncompressed_len < 100)
		return 0;

	memset(&freq_tabs, 0, sizeof(freq_tabs));
	queue.R0 = 1;
	queue.R1 = 1;
	queue.R2 = 1;

	/* The input data must be preprocessed. To avoid changing the original
	 * input, copy it to a temporary buffer. */
	memcpy(uncompressed_data, __uncompressed_data, uncompressed_len);

	/* Before doing any actual compression, do the call instruction (0xe8
	 * byte) translation on the uncompressed data. */
	do_call_insn_preprocessing(uncompressed_data, uncompressed_len);

	/* Determine the sequence of matches and literals that will be output,
	 * and in the process, keep counts of the number of times each symbol
	 * will be output, so that the Huffman trees can be made. */

	num_matches = lz_analyze_block(uncompressed_data, uncompressed_len,
				       match_tab, lzx_record_match,
				       lzx_record_literal, &freq_tabs,
				       &queue, freq_tabs.main_freq_table,
				       &lzx_lz_params);

	lzx_make_huffman_codes(&freq_tabs, &codes);

	/* Initialize the output bitstream. */
	init_output_bitstream(&ostream, compressed_data, uncompressed_len - 1);

	/* The first three bits tell us what kind of block it is, and are one
	 * of the LZX_BLOCKTYPE_* values.  */
	bitstream_put_bits(&ostream, block_type, 3);

	/* The next bit indicates whether the block size is the default (32768),
	 * indicated by a 1 bit, or whether the block size is given by the next
	 * 16 bits, indicated by a 0 bit. */
	if (uncompressed_len == 32768) {
		bitstream_put_bits(&ostream, 1, 1);
	} else {
		bitstream_put_bits(&ostream, 0, 1);
		bitstream_put_bits(&ostream, uncompressed_len, 16);
	}

	/* Write out the aligned offset tree. Note that M$ lies and says that
	 * the aligned offset tree comes after the length tree, but that is
	 * wrong; it actually is before the main tree.  */
	if (block_type == LZX_BLOCKTYPE_ALIGNED)
		for (i = 0; i < LZX_ALIGNEDTREE_NUM_SYMBOLS; i++)
			bitstream_put_bits(&ostream, codes.aligned_lens[i],
					   LZX_ALIGNEDTREE_ELEMENT_SIZE);

	/* Write the pre-tree and lengths for the first LZX_NUM_CHARS symbols in the
	 * main tree. */
	ret = lzx_write_compressed_tree(&ostream, codes.main_lens,
				        LZX_NUM_CHARS);
	if (ret)
		return 0;

	/* Write the pre-tree and symbols for the rest of the main tree. */
	ret = lzx_write_compressed_tree(&ostream, codes.main_lens +
					LZX_NUM_CHARS,
					LZX_MAINTREE_NUM_SYMBOLS -
						LZX_NUM_CHARS);
	if (ret)
		return 0;

	/* Write the pre-tree and symbols for the length tree. */
	ret = lzx_write_compressed_tree(&ostream, codes.len_lens,
					LZX_LENTREE_NUM_SYMBOLS);
	if (ret)
		return 0;

	/* Write the compressed literals. */
	ret = lzx_write_compressed_literals(&ostream, block_type,
					    match_tab, num_matches, &codes);
	if (ret)
		return 0;

	ret = flush_output_bitstream(&ostream);
	if (ret)
		return 0;

	compressed_len = ostream.bit_output - (u8*)compressed_data;

#ifdef ENABLE_VERIFY_COMPRESSION
	/* Verify that we really get the same thing back when decompressing. */
	u8 buf[uncompressed_len];
	ret = wimlib_lzx_decompress(compressed_data, compressed_len,
				    buf, uncompressed_len);
	if (ret != 0) {
		ERROR("lzx_compress(): Failed to decompress data we compressed");
		abort();
	}

	for (i = 0; i < uncompressed_len; i++) {
		if (buf[i] != *((u8*)__uncompressed_data + i)) {
			ERROR("lzx_compress(): Data we compressed didn't "
			      "decompress to the original data (difference at "
			      "byte %u of %u)", i + 1, uncompressed_len);
			abort();
		}
	}
#endif
	return compressed_len;
}
