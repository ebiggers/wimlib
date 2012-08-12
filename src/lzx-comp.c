/*
 * lzx-comp.c
 *
 * LZX compression routines.  
 *
 * This code was originally based on code written by Matthew T. Russotto
 * 	(liblzxcomp).
 */

/*
 * Copyright (C) 2002 Matthew T. Russotto
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */



/* 
 * This file provides lzx_compress(), a function to compress an in-memory buffer
 * of data using LZX compression, as used in the WIM file format.
 *
 * There is no sliding window, as for the compressed chunks in WIM resources,
 * the window is always the length of the input.
 *
 * The basic algorithm should be familiar if you are familiar with Huffman trees
 * and with other LZ77-based formats such as DEFLATE.  Otherwise it can be quite
 * tricky to understand.  Basically it is the following:
 *
 * - Preprocess the input data (LZX-specific)
 * - Go through the input data and determine matches.  This part is based on 
 *       code from zlib, and a hash table of 3-character strings is used to
 *       accelerate the process of finding matches.
 * - Build the Huffman trees based on the frequencies of symbols determined
 *       while recording matches.
 * - Output the block header, including the Huffman trees; then output the
 *       compressed stream of matches and literal characters.
 */


#include "lzx.h"
#include "comp.h"
#include <math.h>
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
	u32 main_freq_table[LZX_MAINTREE_NUM_SYMBOLS]; 
	u32 len_freq_table[LZX_LENTREE_NUM_SYMBOLS];
	u32 aligned_freq_table[LZX_ALIGNEDTREE_NUM_SYMBOLS];
};




/* Returns the position slot that corresponds to a given formatted offset.  This
 * means searching the lzx_position_base array to find what slot contains a
 * position base that is less than or equal to formatted_offset, where the next
 * slot contains a position base that is greater than or equal to
 * formatted_offset. */
static uint lzx_get_position_slot(uint formatted_offset)
{
	int left;
	int right;
	int mid;

	/* Calculate position base using binary search of table; if log2 can be
	 * done in hardware, approximation might work; 
	 * trunc(log2(formatted_offset*formatted_offset)) gets either the proper
	 * position slot or the next one, except for slots 0, 1, and 39-49
	 *
	 * Slots 0-1 are handled by the R0-R1 procedures
	 *
	 * Slots 36-49 (formatted_offset >= 262144) can be found by 
	 * (formatted_offset/131072) + 34 == (formatted_offset >> 17) + 34;
	 */
	if (formatted_offset >= 262144) {
		return (formatted_offset >> 17) + 34;
	} else {
		left = 3;
		right = LZX_NUM_POSITION_SLOTS - 1;
		while (1) {
			mid = (left + right) >> 1;
			if ((lzx_position_base[mid] <= formatted_offset) &&
			    lzx_position_base[mid + 1] > formatted_offset) {
				return mid;
			}
			if (formatted_offset > lzx_position_base[mid])
				/* too low */
				left = mid + 1;
			else	/* too high */
				right = mid;
		}
	}
}

static u32 lzx_record_literal(u8 literal, void *__main_freq_tab)
{
	u32 *main_freq_tab = __main_freq_tab;
	main_freq_tab[literal]++;
	return literal;
}

/* Constructs a match from an offset and a length, and updates the LRU queue
 * and the frequency of symbols in the main, length, and aligned offset
 * alphabets.  The return value is a 32-bit integer that, if the high bit is
 * set, contains the match length, the position slot, and the position footer
 * for the match.  */
static u32 lzx_record_match(uint match_offset, uint match_len, 
			    void *__freq_tabs, void *__queue)
{
	struct lzx_freq_tables *freq_tabs = __freq_tabs;
	struct lru_queue *queue = __queue;
	uint formatted_offset;
	uint position_slot;
	uint position_footer = 0;
	u32 match;
	u32 len_header;
	u32 len_pos_header;
	uint len_footer;

	wimlib_assert(match_len >= LZX_MIN_MATCH && match_len <= LZX_MAX_MATCH);


	if (match_offset == queue->R0) {
		formatted_offset = 0;
		position_slot    = 0;
	} else if (match_offset == queue->R1) {
		swap(queue->R0, queue->R1);
		formatted_offset = 1;
		position_slot    = 1;
	} else if (match_offset == queue->R2) {
		swap(queue->R0, queue->R2);
		formatted_offset = 2;
		position_slot    = 2;
	} else {
		/* Not a repeated offset. */

		formatted_offset = match_offset + LZX_MIN_MATCH;

		queue->R2 = queue->R1;
		queue->R1 = queue->R0;
		queue->R0 = match_offset;

		position_slot = lzx_get_position_slot(formatted_offset);

		/* Just the extra bits of the formatted offset. */
		position_footer = ((1UL << lzx_extra_bits[position_slot]) - 1) &
								formatted_offset;
	}

	/* (match length - 2) = 8 bits */
	/* position_slot = 6 bits */
	/* position_footer = 17 bits */
	/* total = 31 bits */
	/* plus one to say whether it's a literal or not */

	match = 0x80000000 | /* bit 31 in intelligent bit ordering */
		(position_slot << 25) | /* bits 30-25 */
		(position_footer << 8) | /* bits 8-24 */
		(match_len - LZX_MIN_MATCH); /* bits 0-7 */

	/* Update the frequency for the main tree, the length tree (only if a
	 * length symbol is to be output), and the aligned tree (only if an
	 * aligned symbol is to be output.) */
	if (match_len < (LZX_NUM_PRIMARY_LENS + LZX_MIN_MATCH)) {
		len_header = match_len - LZX_MIN_MATCH;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_footer = match_len - (LZX_NUM_PRIMARY_LENS + LZX_MIN_MATCH);
		freq_tabs->len_freq_table[len_footer]++;
	}
	len_pos_header = (position_slot << 3) | len_header;

	wimlib_assert(len_pos_header < LZX_MAINTREE_NUM_SYMBOLS - LZX_NUM_CHARS);

	freq_tabs->main_freq_table[len_pos_header + LZX_NUM_CHARS]++;

	if (lzx_extra_bits[position_slot] >= 3)
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
static int lzx_write_match(struct output_bitstream *out, int block_type,
				u32 match, const struct lzx_codes *codes)
{
	/* low 8 bits are the match length minus 2 */
	uint match_len_minus_2 = match & 0xff;
	/* Next 17 bits are the position footer */
	uint position_footer = (match >> 8) & 0x1ffff;	/* 17 bits */
	/* Next 6 bits are the position slot. */
	uint position_slot = (match >> 25) & 0x3f;	/* 6 bits */
	uint len_header;
	uint len_footer;
	uint len_pos_header;
	uint main_symbol;
	uint num_extra_bits;
	uint verbatim_bits;
	uint aligned_bits;
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
		len_footer = (uint)(-1);
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
	if (len_footer != (uint)(-1)) {
		ret = bitstream_put_bits(out, codes->len_codewords[len_footer],
					 codes->len_lens[len_footer]);
		if (ret != 0)
			return ret;
	}

	wimlib_assert(position_slot < LZX_NUM_POSITION_SLOTS);

	num_extra_bits = lzx_extra_bits[position_slot];

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
static int lzx_write_compressed_literals(struct output_bitstream *ostream, 
					 int block_type,
			 		 const u32 match_tab[], 
					 uint  num_compressed_literals,
					 const struct lzx_codes *codes)
{
	uint i;
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
static int lzx_write_compressed_tree(struct output_bitstream *out, 
				const u8 lens[], 
				uint num_symbols)
{
	/* Frequencies of the length symbols, including the RLE symbols (NOT the
	 * actual lengths themselves). */
	uint pretree_freqs[LZX_PRETREE_NUM_SYMBOLS];
	u8 pretree_lens[LZX_PRETREE_NUM_SYMBOLS];
	u16 pretree_codewords[LZX_PRETREE_NUM_SYMBOLS];
	u8 output_syms[num_symbols * 2];
	uint output_syms_idx;
	uint cur_run_len;
	uint i;
	uint len_in_run;
	uint additional_bits;
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
				pretree_freqs[delta]++;
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

			pretree_freqs[delta]++;
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
static void lzx_make_huffman_codes(const struct lzx_freq_tables *freq_tabs,
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

/* Do the 'E8' preprocessing, where the targets of x86 CALL instructions were
 * changed from relative offsets to absolute offsets.  This type of
 * preprocessing can be used on any binary data even if it is not actually
 * machine code.  It seems to always be used in WIM files, even though there is
 * no bit to indicate that it actually is used, unlike in the LZX compressed
 * format as used in other file formats such as the cabinet format, where a bit
 * is reserved for that purpose. */
static void do_call_insn_preprocessing(u8 uncompressed_data[], 
						uint uncompressed_data_len)
{
	int i = 0;
	int file_size = LZX_MAGIC_FILESIZE;
	int32_t rel_offset;
	int32_t abs_offset;

	/* Not enabled in the last 6 bytes, which means the 5-byte call
	 * instruction cannot start in the last *10* bytes. */
	while (i < uncompressed_data_len - 10) { 
		if (uncompressed_data[i] != 0xe8) {
			i++;
			continue;
		}
		rel_offset = to_le32(*(int32_t*)(uncompressed_data + i + 1));

		if (rel_offset >= -i && rel_offset < file_size) {
			if (rel_offset < file_size - i) {
				/* "good translation" */
				abs_offset = rel_offset + i;
			} else {
				/* "compensating translation" */
				abs_offset = rel_offset - file_size;
			}
			*(int32_t*)(uncompressed_data + i + 1) = to_le32(abs_offset);
		}
		i += 5;
	}
}


static const struct lz_params lzx_lz_params = {
	.min_match      = 3,
	.max_match      = LZX_MAX_MATCH,
	.good_match	= LZX_MAX_MATCH,
	.nice_match     = LZX_MAX_MATCH,
	.max_chain_len  = LZX_MAX_MATCH,
	.max_lazy_match = LZX_MAX_MATCH,
	.too_far        = 4096,
};

/* 
 * Performs LZX compression on a block of data.
 *
 * @__uncompressed_data:  Pointer to the data to be compressed.
 * @uncompressed_len:	  Length, in bytes, of the data to be compressed.
 * @compressed_data:	  Pointer to a location at least (@uncompressed_len - 1)
 * 				bytes long into which the compressed data may be
 * 				written.
 * @compressed_len_ret:	  A pointer to an unsigned int into which the length of
 * 				the compressed data may be returned.
 *
 * Returns zero if compression was successfully performed.  In that case
 * @compressed_data and @compressed_len_ret will contain the compressed data and
 * its length.  A return value of nonzero means that compressing the data did
 * not reduce its size, and @compressed_data will not contain the full
 * compressed data. 
 */
int lzx_compress(const void *__uncompressed_data, uint uncompressed_len,
		 void *compressed_data, uint *compressed_len_ret)
{
	struct output_bitstream ostream;
	u8 uncompressed_data[uncompressed_len + LZX_MAX_MATCH];
	struct lzx_freq_tables freq_tabs;
	struct lzx_codes codes;
	u32 match_tab[uncompressed_len];
	struct lru_queue queue = {.R0 = 1, .R1 = 1, .R2 = 1};
	uint num_matches;
	uint compressed_len;
	uint i;
	int ret;

	LZX_DEBUG("uncompressed_len = %u\n", uncompressed_len);

	if (uncompressed_len < 100)
		return 1;


	memset(&freq_tabs, 0, sizeof(freq_tabs));

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

	LZX_DEBUG("using %u matches\n", num_matches);


	lzx_make_huffman_codes(&freq_tabs, &codes);

	/* Initialize the output bitstream. */
	init_output_bitstream(&ostream, compressed_data, uncompressed_len - 1);

	/* The first three bits tell us what kind of block it is, and are one
	 * of the LZX_BLOCKTYPE_* values.  */
	bitstream_put_bits(&ostream, LZX_BLOCKTYPE_ALIGNED, 3);

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
	for (i = 0; i < LZX_ALIGNEDTREE_NUM_SYMBOLS; i++)
		bitstream_put_bits(&ostream, codes.aligned_lens[i], 
				   LZX_ALIGNEDTREE_ELEMENT_SIZE);

	/* Write the pre-tree and lengths for the first LZX_NUM_CHARS symbols in the
	 * main tree. */
	ret = lzx_write_compressed_tree(&ostream, codes.main_lens, 
				        LZX_NUM_CHARS);
	if (ret != 0)
		return ret;

	/* Write the pre-tree and symbols for the rest of the main tree. */
	ret = lzx_write_compressed_tree(&ostream, codes.main_lens + 
					LZX_NUM_CHARS, 
					LZX_MAINTREE_NUM_SYMBOLS - 
						LZX_NUM_CHARS);
	if (ret != 0)
		return ret;

	/* Write the pre-tree and symbols for the length tree. */
	ret = lzx_write_compressed_tree(&ostream, codes.len_lens, 
					LZX_LENTREE_NUM_SYMBOLS);
	if (ret != 0)
		return ret;

	/* Write the compressed literals. */
	ret = lzx_write_compressed_literals(&ostream, LZX_BLOCKTYPE_ALIGNED,
					    match_tab, num_matches, &codes);
	if (ret != 0)
		return ret;

	ret = flush_output_bitstream(&ostream);
	if (ret != 0)
		return ret;

	compressed_len = ostream.bit_output - (u8*)compressed_data;

	LZX_DEBUG("Compressed %u => %u bytes\n",
			uncompressed_len, compressed_len);

	*compressed_len_ret = compressed_len;

#ifdef ENABLE_VERIFY_COMPRESSION
	/* Verify that we really get the same thing back when decompressing. */
	u8 buf[uncompressed_len];
	ret = lzx_decompress(compressed_data, compressed_len, buf, 
			     uncompressed_len);
	if (ret != 0) {
		ERROR("ERROR: Failed to decompress data we compressed!\n");
		exit(0);
		abort();
	}

	for (i = 0; i < uncompressed_len; i++) {
		if (buf[i] != *((u8*)__uncompressed_data + i)) {
			ERROR("Data we compressed didn't decompress to "
				"the original data (difference at byte %u of "
				"%u)\n", i + 1, uncompressed_len);
			abort();
		}
	}
	LZX_DEBUG("Compression verified to be correct.\n");
#endif

	return 0;
}
