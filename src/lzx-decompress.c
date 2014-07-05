/*
 * lzx-decompress.c
 *
 * LZX decompression routines, originally based on code taken from cabextract
 * v0.5, which was, itself, a modified version of the lzx decompression code
 * from unlzx.
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
 * LZX is an LZ77 and Huffman-code based compression format that has many
 * similarities to the DEFLATE format used in zlib.  The compression ratio is as
 * good or better than DEFLATE.
 *
 * Some notes on the LZX compression format as used in Windows Imaging (WIM)
 * files:
 *
 * A compressed WIM resource consists of a table of chunk offsets followed by
 * the compressed chunks themselves.  All compressed chunks except possibly the
 * last decompress to a fixed number of bytes, by default 32768.  This is quite
 * similar to the cabinet (.cab) file format, but they are not the same.
 * According to the cabinet format documentation, the LZX block size is
 * independent from the CFDATA blocks, and an LZX block may span several CFDATA
 * blocks.  However, in WIMs, LZX blocks do not appear to ever span multiple WIM
 * chunks.  Note that this means any WIM chunk may be decompressed or compressed
 * independently from any other chunk, which allows random access.
 *
 * An LZX compressed WIM chunk contains one or more LZX blocks of the aligned,
 * verbatim, or uncompressed block types.  For aligned and verbatim blocks, the
 * size of the block in uncompressed bytes is specified by a bit following the 3
 * bits that specify the block type, possibly followed by an additional 16 bits.
 * '1' means to use the default block size (equal to 32768, the default size of
 * a WIM chunk), while '0' means that the block size is provided by the next 16
 * bits.
 *
 * The cabinet format, as documented, allows for the possibility that a
 * compressed CFDATA chunk is up to 6144 bytes larger than the data it
 * uncompresses to.  However, in the WIM format it appears that every chunk that
 * would be 32768 bytes or more when compressed is actually stored fully
 * uncompressed.
 *
 * The 'e8' preprocessing step that changes x86 call instructions to use
 * absolute offsets instead of relative offsets relies on a filesize parameter.
 * There is no such parameter for this in the WIM files (even though the size of
 * the file resource could be used for this purpose), and instead a magic file
 * size of 12000000 is used.  The 'e8' preprocessing is always done, and there
 * is no bit to indicate whether it is done or not.
 */

/*
 * Some more notes about errors in Microsoft's LZX documentation:
 *
 * Microsoft's LZX document and their implementation of the com.ms.util.cab Java
 * package do not concur.
 *
 * In the LZX document, there is a table showing the correlation between window
 * size and the number of position slots. It states that the 1MB window = 40
 * slots and the 2MB window = 42 slots. In the implementation, 1MB = 42 slots,
 * 2MB = 50 slots. The actual calculation is 'find the first slot whose position
 * base is equal to or more than the required window size'. This would explain
 * why other tables in the document refer to 50 slots rather than 42.
 *
 * The constant NUM_PRIMARY_LENS used in the decompression pseudocode is not
 * defined in the specification.
 *
 * The LZX document states that aligned offset blocks have their aligned offset
 * Huffman tree AFTER the main and length trees. The implementation suggests
 * that the aligned offset tree is BEFORE the main and length trees.
 *
 * The LZX document decoding algorithm states that, in an aligned offset block,
 * if an extra_bits value is 1, 2 or 3, then that number of bits should be read
 * and the result added to the match offset. This is correct for 1 and 2, but
 * not 3, where just a Huffman symbol (using the aligned tree) should be read.
 *
 * Regarding the E8 preprocessing, the LZX document states 'No translation may
 * be performed on the last 6 bytes of the input block'. This is correct.
 * However, the pseudocode provided checks for the *E8 leader* up to the last 6
 * bytes. If the leader appears between -10 and -7 bytes from the end, this
 * would cause the next four bytes to be modified, at least one of which would
 * be in the last 6 bytes, which is not allowed according to the spec.
 *
 * The specification states that the Huffman trees must always contain at least
 * one element. However, many CAB files contain blocks where the length tree is
 * completely empty (because there are no matches), and this is expected to
 * succeed.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/decompressor_ops.h"
#include "wimlib/decompress_common.h"
#include "wimlib/error.h"
#include "wimlib/lzx.h"
#include "wimlib/util.h"

#include <string.h>

/* Huffman decoding tables and maps from symbols to code lengths. */
struct lzx_tables {

	u16 maintree_decode_table[(1 << LZX_MAINCODE_TABLEBITS) +
					(LZX_MAINCODE_MAX_NUM_SYMBOLS * 2)]
					_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	u8 maintree_lens[LZX_MAINCODE_MAX_NUM_SYMBOLS];


	u16 lentree_decode_table[(1 << LZX_LENCODE_TABLEBITS) +
					(LZX_LENCODE_NUM_SYMBOLS * 2)]
					_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	u8 lentree_lens[LZX_LENCODE_NUM_SYMBOLS];


	u16 alignedtree_decode_table[(1 << LZX_ALIGNEDCODE_TABLEBITS) +
					(LZX_ALIGNEDCODE_NUM_SYMBOLS * 2)]
					_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	u8 alignedtree_lens[LZX_ALIGNEDCODE_NUM_SYMBOLS];
} _aligned_attribute(DECODE_TABLE_ALIGNMENT);

struct lzx_decompressor {
	u32 max_window_size;
	unsigned num_main_syms;
	struct lzx_tables tables;
};

/*
 * Reads a Huffman-encoded symbol using the pre-tree.
 */
static inline u16
read_huffsym_using_pretree(struct input_bitstream *istream,
			   const u16 pretree_decode_table[])
{
	return read_huffsym(istream, pretree_decode_table,
			    LZX_PRECODE_TABLEBITS, LZX_MAX_PRE_CODEWORD_LEN);
}

/* Reads a Huffman-encoded symbol using the main tree. */
static inline u16
read_huffsym_using_maintree(struct input_bitstream *istream,
			    const struct lzx_tables *tables)
{
	return read_huffsym(istream, tables->maintree_decode_table,
			    LZX_MAINCODE_TABLEBITS, LZX_MAX_MAIN_CODEWORD_LEN);
}

/* Reads a Huffman-encoded symbol using the length tree. */
static inline u16
read_huffsym_using_lentree(struct input_bitstream *istream,
			   const struct lzx_tables *tables)
{
	return read_huffsym(istream, tables->lentree_decode_table,
			    LZX_LENCODE_TABLEBITS, LZX_MAX_LEN_CODEWORD_LEN);
}

/* Reads a Huffman-encoded symbol using the aligned offset tree. */
static inline u16
read_huffsym_using_alignedtree(struct input_bitstream *istream,
			       const struct lzx_tables *tables)
{
	return read_huffsym(istream, tables->alignedtree_decode_table,
			    LZX_ALIGNEDCODE_TABLEBITS, LZX_MAX_ALIGNED_CODEWORD_LEN);
}

/*
 * Reads the pretree from the input, then uses the pretree to decode @num_lens
 * code length values from the input.
 *
 * @istream:	The bit stream for the input.  It is positioned on the beginning
 *			of the pretree for the code length values.
 * @lens:	An array that contains the length values from the previous time
 *			the code lengths for this Huffman tree were read, or all
 *			0's if this is the first time.
 * @num_lens:	Number of length values to decode and return.
 *
 */
static int
lzx_read_code_lens(struct input_bitstream *istream, u8 lens[],
		   unsigned num_lens)
{
	/* Declare the decoding table and length table for the pretree. */
	u16 pretree_decode_table[(1 << LZX_PRECODE_TABLEBITS) +
					(LZX_PRECODE_NUM_SYMBOLS * 2)]
					_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	u8 pretree_lens[LZX_PRECODE_NUM_SYMBOLS];
	unsigned i;
	int ret;

	/* Read the code lengths of the pretree codes.  There are 20 lengths of
	 * 4 bits each. */
	for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++) {
		pretree_lens[i] = bitstream_read_bits(istream,
						      LZX_PRECODE_ELEMENT_SIZE);
	}

	/* Make the decoding table for the pretree. */
	ret = make_huffman_decode_table(pretree_decode_table,
					LZX_PRECODE_NUM_SYMBOLS,
					LZX_PRECODE_TABLEBITS,
					pretree_lens,
					LZX_MAX_PRE_CODEWORD_LEN);
	if (ret)
		return ret;

	/* Pointer past the last length value that needs to be filled in. */
	u8 *lens_end = lens + num_lens;

	while (1) {

		/* Decode a symbol from the input.  If the symbol is between 0
		 * and 16, it is the difference from the old length.  If it is
		 * between 17 and 19, it is a special code that indicates that
		 * some number of the next lengths are all 0, or some number of
		 * the next lengths are all equal to the next symbol in the
		 * input. */
		unsigned tree_code;
		u32 num_zeroes;
		unsigned code;
		u32 num_same;
		signed char value;

		tree_code = read_huffsym_using_pretree(istream,
						       pretree_decode_table);
		switch (tree_code) {
		case 17: /* Run of 0's */
			num_zeroes = bitstream_read_bits(istream, 4);
			num_zeroes += 4;
			while (num_zeroes--) {
				*lens = 0;
				if (++lens == lens_end)
					return 0;
			}
			break;
		case 18: /* Longer run of 0's */
			num_zeroes = bitstream_read_bits(istream, 5);
			num_zeroes += 20;
			while (num_zeroes--) {
				*lens = 0;
				if (++lens == lens_end)
					return 0;
			}
			break;
		case 19: /* Run of identical lengths */
			num_same = bitstream_read_bits(istream, 1);
			num_same += 4;
			code = read_huffsym_using_pretree(istream,
							  pretree_decode_table);
			value = (signed char)*lens - (signed char)code;
			if (value < 0)
				value += 17;
			while (num_same--) {
				*lens = value;
				if (++lens == lens_end)
					return 0;
			}
			break;
		default: /* Difference from old length. */
			value = (signed char)*lens - (signed char)tree_code;
			if (value < 0)
				value += 17;
			*lens = value;
			if (++lens == lens_end)
				return 0;
			break;
		}
	}
}

/*
 * Reads the header for an LZX-compressed block.
 *
 * @istream:		The input bitstream.
 * @block_size_ret:	A pointer to an int into which the size of the block,
 *				in bytes, will be returned.
 * @block_type_ret:	A pointer to an int into which the type of the block
 *				(LZX_BLOCKTYPE_*) will be returned.
 * @tables:		A pointer to an lzx_tables structure in which the
 *				main tree, the length tree, and possibly the
 *				aligned offset tree will be constructed.
 * @queue:	A pointer to the least-recently-used queue into which
 *			R0, R1, and R2 will be written (only for uncompressed
 *			blocks, which contain this information in the header)
 */
static int
lzx_read_block_header(struct input_bitstream *istream,
		      unsigned num_main_syms,
		      unsigned max_window_size,
		      unsigned *block_size_ret,
		      unsigned *block_type_ret,
		      struct lzx_tables *tables,
		      struct lzx_lru_queue *queue)
{
	int ret;
	unsigned block_type;
	unsigned block_size;

	bitstream_ensure_bits(istream, 4);

	/* The first three bits tell us what kind of block it is, and are one
	 * of the LZX_BLOCKTYPE_* values.  */
	block_type = bitstream_pop_bits(istream, 3);

	/* Read the block size.  This mirrors the behavior
	 * lzx_write_compressed_block() in lzx-compress.c; see that for more
	 * details.  */
	if (bitstream_pop_bits(istream, 1)) {
		block_size = LZX_DEFAULT_BLOCK_SIZE;
	} else {
		u32 tmp;
		block_size = 0;

		tmp = bitstream_read_bits(istream, 8);
		block_size |= tmp;
		tmp = bitstream_read_bits(istream, 8);
		block_size <<= 8;
		block_size |= tmp;

		if (max_window_size >= 65536) {
			tmp = bitstream_read_bits(istream, 8);
			block_size <<= 8;
			block_size |= tmp;
		}
	}

	switch (block_type) {
	case LZX_BLOCKTYPE_ALIGNED:
		/* Read the path lengths for the elements of the aligned tree,
		 * then build it. */

		for (unsigned i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
			tables->alignedtree_lens[i] =
				bitstream_read_bits(istream,
						    LZX_ALIGNEDCODE_ELEMENT_SIZE);
		}

		LZX_DEBUG("Building the aligned tree.");
		ret = make_huffman_decode_table(tables->alignedtree_decode_table,
						LZX_ALIGNEDCODE_NUM_SYMBOLS,
						LZX_ALIGNEDCODE_TABLEBITS,
						tables->alignedtree_lens,
						LZX_MAX_ALIGNED_CODEWORD_LEN);
		if (ret) {
			LZX_DEBUG("Failed to make the decode table for the "
				  "aligned offset tree");
			return ret;
		}

		/* Fall though, since the rest of the header for aligned offset
		 * blocks is the same as that for verbatim blocks */

	case LZX_BLOCKTYPE_VERBATIM:
		if (block_type == LZX_BLOCKTYPE_VERBATIM)
			LZX_DEBUG("Found verbatim block.");

		LZX_DEBUG("Reading path lengths for main tree.");
		/* Read the path lengths for the first 256 elements of the main
		 * tree. */
		ret = lzx_read_code_lens(istream, tables->maintree_lens,
					 LZX_NUM_CHARS);
		if (ret) {
			LZX_DEBUG("Failed to read the code lengths for the "
				  "first 256 elements of the main tree");
			return ret;
		}

		/* Read the path lengths for the remaining elements of the main
		 * tree. */
		LZX_DEBUG("Reading path lengths for remaining elements of "
			  "main tree (%d elements).",
			  num_main_syms - LZX_NUM_CHARS);
		ret = lzx_read_code_lens(istream,
					 tables->maintree_lens + LZX_NUM_CHARS,
					 num_main_syms - LZX_NUM_CHARS);
		if (ret) {
			LZX_DEBUG("Failed to read the path lengths for the "
				  "remaining elements of the main tree");
			return ret;
		}

		LZX_DEBUG("Building the Huffman decoding "
			  "table for the main tree.");

		ret = make_huffman_decode_table(tables->maintree_decode_table,
						num_main_syms,
						LZX_MAINCODE_TABLEBITS,
						tables->maintree_lens,
						LZX_MAX_MAIN_CODEWORD_LEN);
		if (ret) {
			LZX_DEBUG("Failed to make the decode "
				  "table for the main tree");
			return ret;
		}

		LZX_DEBUG("Reading path lengths for the length tree.");
		ret = lzx_read_code_lens(istream, tables->lentree_lens,
					 LZX_LENCODE_NUM_SYMBOLS);
		if (ret) {
			LZX_DEBUG("Failed to read the path "
				  "lengths for the length tree");
			return ret;
		}

		LZX_DEBUG("Building the length tree.");
		ret = make_huffman_decode_table(tables->lentree_decode_table,
						LZX_LENCODE_NUM_SYMBOLS,
						LZX_LENCODE_TABLEBITS,
						tables->lentree_lens,
						LZX_MAX_LEN_CODEWORD_LEN);
		if (ret) {
			LZX_DEBUG("Failed to build the length Huffman tree");
			return ret;
		}
		/* The bitstream of compressed literals and matches for this
		 * block directly follows and will be read in
		 * lzx_decompress_block(). */
		break;
	case LZX_BLOCKTYPE_UNCOMPRESSED:
		LZX_DEBUG("Found uncompressed block.");
		/* Before reading the three LRU match offsets from the
		 * uncompressed block header, the stream needs to be aligned on
		 * a 16-bit boundary.  But, unexpectedly, if the stream is
		 * *already* aligned, the correct thing to do is to throw away
		 * the next 16 bits. */
		if (istream->bitsleft == 0) {
			if (istream->data_bytes_left < 14) {
				LZX_DEBUG("Insufficient length in "
					  "uncompressed block");
				return -1;
			}
			istream->data += 2;
			istream->data_bytes_left -= 2;
		} else {
			if (istream->data_bytes_left < 12) {
				LZX_DEBUG("Insufficient length in "
					  "uncompressed block");
				return -1;
			}
			istream->bitsleft = 0;
			istream->bitbuf = 0;
		}
		queue->R[0] = le32_to_cpu(*(le32*)(istream->data + 0));
		queue->R[1] = le32_to_cpu(*(le32*)(istream->data + 4));
		queue->R[2] = le32_to_cpu(*(le32*)(istream->data + 8));
		istream->data += 12;
		istream->data_bytes_left -= 12;
		/* The uncompressed data of this block directly follows and will
		 * be read in lzx_decompress(). */
		break;
	default:
		LZX_DEBUG("Found invalid block");
		return -1;
	}
	*block_type_ret = block_type;
	*block_size_ret = block_size;
	return 0;
}

/*
 * Decodes a compressed match from a block of LZX-compressed data.  A match
 * refers to some match_offset to a point earlier in the window as well as some
 * match_len, for which the data is to be copied to the current position in the
 * window.
 *
 * @main_element:	The start of the match data, as decoded using the main
 *			tree.
 *
 * @block_type:		The type of the block (LZX_BLOCKTYPE_ALIGNED or
 *			LZX_BLOCKTYPE_VERBATIM)
 *
 * @bytes_remaining:	The amount of uncompressed data remaining to be
 *			uncompressed in this block.  It is an error if the match
 *			is longer than this number.
 *
 * @window:		A pointer to the window into which the uncompressed
 *			data is being written.
 *
 * @window_pos:		The current byte offset in the window.
 *
 * @tables:		The Huffman decoding tables for this LZX block (main
 *			code, length code, and for LZX_BLOCKTYPE_ALIGNED blocks,
 *			also the aligned offset code).
 *
 * @queue:		The least-recently used queue for match offsets.
 *
 * @istream:		The input bitstream.
 *
 * Returns the length of the match, or a negative number on error.  The possible
 * error cases are:
 *	- Match would exceed the amount of data remaining to be uncompressed.
 *	- Match refers to data before the window.
 *	- The input bitstream ended unexpectedly.
 */
static int
lzx_decode_match(unsigned main_element, int block_type,
		 unsigned bytes_remaining, u8 *window,
		 unsigned window_pos,
		 const struct lzx_tables *tables,
		 struct lzx_lru_queue *queue,
		 struct input_bitstream *istream)
{
	unsigned length_header;
	unsigned position_slot;
	unsigned match_len;
	unsigned match_offset;
	unsigned num_extra_bits;
	u32 verbatim_bits;
	u32 aligned_bits;

	/* The main element is offset by 256 because values under 256 indicate a
	 * literal value. */
	main_element -= LZX_NUM_CHARS;

	/* The length header consists of the lower 3 bits of the main element.
	 * The position slot is the rest of it. */
	length_header = main_element & LZX_NUM_PRIMARY_LENS;
	position_slot = main_element >> 3;

	/* If the length_header is less than LZX_NUM_PRIMARY_LENS (= 7), it
	 * gives the match length as the offset from LZX_MIN_MATCH_LEN.
	 * Otherwise, the length is given by an additional symbol encoded using
	 * the length tree, offset by 9 (LZX_MIN_MATCH_LEN +
	 * LZX_NUM_PRIMARY_LENS) */
	match_len = LZX_MIN_MATCH_LEN + length_header;
	if (length_header == LZX_NUM_PRIMARY_LENS)
		match_len += read_huffsym_using_lentree(istream, tables);

	/* If the position_slot is 0, 1, or 2, the match offset is retrieved
	 * from the LRU queue.  Otherwise, the match offset is not in the LRU
	 * queue. */
	if (position_slot <= 2) {
		/* Note: This isn't a real LRU queue, since using the R2 offset
		 * doesn't bump the R1 offset down to R2.  This quirk allows all
		 * 3 recent offsets to be handled by the same code.  (For R0,
		 * the swap is a no-op.)  */
		match_offset = queue->R[position_slot];
		queue->R[position_slot] = queue->R[0];
		queue->R[0] = match_offset;
	} else {
		/* Otherwise, the offset was not encoded as one the offsets in
		 * the queue.  Depending on the position slot, there is a
		 * certain number of extra bits that need to be read to fully
		 * decode the match offset. */

		/* Look up the number of extra bits that need to be read. */
		num_extra_bits = lzx_get_num_extra_bits(position_slot);

		/* For aligned blocks, if there are at least 3 extra bits, the
		 * actual number of extra bits is 3 less, and they encode a
		 * number of 8-byte words that are added to the offset; there
		 * is then an additional symbol read using the aligned tree that
		 * specifies the actual byte alignment. */
		if (block_type == LZX_BLOCKTYPE_ALIGNED && num_extra_bits >= 3) {

			/* There is an error in the LZX "specification" at this
			 * point; it indicates that a Huffman symbol is to be
			 * read only if num_extra_bits is greater than 3, but
			 * actually it is if num_extra_bits is greater than or
			 * equal to 3.  (Note that in the case with
			 * num_extra_bits == 3, the assignment to verbatim_bits
			 * will just set it to 0. ) */
			verbatim_bits = bitstream_read_bits(istream,
							    num_extra_bits - 3);
			verbatim_bits <<= 3;
			aligned_bits = read_huffsym_using_alignedtree(istream,
								      tables);
		} else {
			/* For non-aligned blocks, or for aligned blocks with
			 * less than 3 extra bits, the extra bits are added
			 * directly to the match offset, and the correction for
			 * the alignment is taken to be 0. */
			verbatim_bits = bitstream_read_bits(istream, num_extra_bits);
			aligned_bits = 0;
		}

		/* Calculate the match offset. */
		match_offset = lzx_position_base[position_slot] +
			       verbatim_bits + aligned_bits - LZX_OFFSET_OFFSET;

		/* Update the LRU queue. */
		queue->R[2] = queue->R[1];
		queue->R[1] = queue->R[0];
		queue->R[0] = match_offset;
	}

	/* Verify that the match is in the bounds of the part of the window
	 * currently in use, then copy the source of the match to the current
	 * position. */

	if (unlikely(match_len > bytes_remaining)) {
		LZX_DEBUG("Match of length %u bytes overflows "
			  "uncompressed block size", match_len);
		return -1;
	}

	if (unlikely(match_offset > window_pos)) {
		LZX_DEBUG("Match of length %u bytes references "
			  "data before window (match_offset = %u, "
			  "window_pos = %u)",
			  match_len, match_offset, window_pos);
		return -1;
	}

	lz_copy(&window[window_pos], match_len, match_offset,
		&window[window_pos + bytes_remaining]);

	return match_len;
}

/*
 * Decompresses an LZX-compressed block of data from which the header has already
 * been read.
 *
 * @block_type:	The type of the block (LZX_BLOCKTYPE_VERBATIM or
 *		LZX_BLOCKTYPE_ALIGNED)
 * @block_size:	The size of the block, in bytes.
 * @window:	Pointer to the decompression window.
 * @window_pos:	The current position in the window.  Will be 0 for the first
 *			block.
 * @tables:	The Huffman decoding tables for the block (main, length, and
 *			aligned offset, the latter only for LZX_BLOCKTYPE_ALIGNED)
 * @queue:	The least-recently-used queue for match offsets.
 * @istream:	The input bitstream for the compressed literals.
 */
static int
lzx_decompress_block(int block_type, unsigned block_size,
		     u8 *window,
		     unsigned window_pos,
		     const struct lzx_tables *tables,
		     struct lzx_lru_queue *queue,
		     struct input_bitstream *istream)
{
	unsigned main_element;
	unsigned end;
	int match_len;

	end = window_pos + block_size;
	while (window_pos < end) {
		main_element = read_huffsym_using_maintree(istream, tables);
		if (main_element < LZX_NUM_CHARS) {
			/* literal: 0 to LZX_NUM_CHARS - 1 */
			window[window_pos++] = main_element;
		} else {
			/* match: LZX_NUM_CHARS to num_main_syms - 1 */
			match_len = lzx_decode_match(main_element,
						     block_type,
						     end - window_pos,
						     window,
						     window_pos,
						     tables,
						     queue,
						     istream);
			if (unlikely(match_len < 0))
				return match_len;
			window_pos += match_len;
		}
	}
	return 0;
}

static int
lzx_decompress(const void *compressed_data, size_t compressed_size,
	       void *uncompressed_data, size_t uncompressed_size,
	       void *_ctx)
{
	struct lzx_decompressor *ctx = _ctx;
	struct input_bitstream istream;
	struct lzx_lru_queue queue;
	unsigned window_pos;
	unsigned block_size;
	unsigned block_type;
	int ret;
	bool e8_preprocessing_done;

	LZX_DEBUG("compressed_data = %p, compressed_size = %zu, "
		  "uncompressed_data = %p, uncompressed_size = %zu, "
		  "max_window_size=%u).",
		  compressed_data, compressed_size,
		  uncompressed_data, uncompressed_size,
		  ctx->max_window_size);

	if (uncompressed_size > ctx->max_window_size) {
		LZX_DEBUG("Uncompressed size of %zu exceeds "
			  "window size of %u!",
			  uncompressed_size, ctx->max_window_size);
		return -1;
	}

	memset(ctx->tables.maintree_lens, 0, sizeof(ctx->tables.maintree_lens));
	memset(ctx->tables.lentree_lens, 0, sizeof(ctx->tables.lentree_lens));
	lzx_lru_queue_init(&queue);
	init_input_bitstream(&istream, compressed_data, compressed_size);

	e8_preprocessing_done = false; /* Set to true if there may be 0xe8 bytes
					  in the uncompressed data. */

	/* The compressed data will consist of one or more blocks.  The
	 * following loop decompresses one block, and it runs until there all
	 * the compressed data has been decompressed, so there are no more
	 * blocks.  */

	for (window_pos = 0;
	     window_pos < uncompressed_size;
	     window_pos += block_size)
	{
		LZX_DEBUG("Reading block header.");
		ret = lzx_read_block_header(&istream, ctx->num_main_syms,
					    ctx->max_window_size, &block_size,
					    &block_type, &ctx->tables, &queue);
		if (ret)
			return ret;

		LZX_DEBUG("block_size = %u, window_pos = %u",
			  block_size, window_pos);

		if (block_size > uncompressed_size - window_pos) {
			LZX_DEBUG("Expected a block size of at "
				  "most %zu bytes (found %u bytes)",
				  uncompressed_size - window_pos, block_size);
			return -1;
		}

		switch (block_type) {
		case LZX_BLOCKTYPE_VERBATIM:
		case LZX_BLOCKTYPE_ALIGNED:
			if (block_type == LZX_BLOCKTYPE_VERBATIM)
				LZX_DEBUG("LZX_BLOCKTYPE_VERBATIM");
			else
				LZX_DEBUG("LZX_BLOCKTYPE_ALIGNED");
			ret = lzx_decompress_block(block_type,
						   block_size,
						   uncompressed_data,
						   window_pos,
						   &ctx->tables,
						   &queue,
						   &istream);
			if (ret)
				return ret;

			if (ctx->tables.maintree_lens[0xe8] != 0)
				e8_preprocessing_done = true;
			break;
		case LZX_BLOCKTYPE_UNCOMPRESSED:
			LZX_DEBUG("LZX_BLOCKTYPE_UNCOMPRESSED");
			if (istream.data_bytes_left < block_size) {
				LZX_DEBUG("Unexpected end of input when "
					  "reading %u bytes from LZX bitstream "
					  "(only have %u bytes left)",
					  block_size, istream.data_bytes_left);
				return -1;
			}
			memcpy(&((u8*)uncompressed_data)[window_pos], istream.data,
			       block_size);
			istream.data += block_size;
			istream.data_bytes_left -= block_size;
			/* Re-align bitstream if an odd number of bytes were
			 * read.  */
			if (istream.data_bytes_left && (block_size & 1)) {
				istream.data_bytes_left--;
				istream.data++;
			}
			e8_preprocessing_done = true;
			break;
		}
	}
	if (e8_preprocessing_done)
		lzx_undo_e8_preprocessing(uncompressed_data, uncompressed_size);
	return 0;
}

static void
lzx_free_decompressor(void *_ctx)
{
	struct lzx_decompressor *ctx = _ctx;

	ALIGNED_FREE(ctx);
}

static int
lzx_create_decompressor(size_t max_window_size,
			const struct wimlib_decompressor_params_header *params,
			void **ctx_ret)
{
	struct lzx_decompressor *ctx;

	if (!lzx_window_size_valid(max_window_size))
		return WIMLIB_ERR_INVALID_PARAM;

	ctx = ALIGNED_MALLOC(sizeof(struct lzx_decompressor),
			     DECODE_TABLE_ALIGNMENT);
	if (ctx == NULL)
		return WIMLIB_ERR_NOMEM;

	ctx->max_window_size = max_window_size;
	ctx->num_main_syms = lzx_get_num_main_syms(max_window_size);

	*ctx_ret = ctx;
	return 0;
}

const struct decompressor_ops lzx_decompressor_ops = {
	.create_decompressor = lzx_create_decompressor,
	.decompress	     = lzx_decompress,
	.free_decompressor   = lzx_free_decompressor,
};
