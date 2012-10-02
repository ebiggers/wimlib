/*
 * lzx-decomp.c
 *
 * Routines for LZX decompression.  The LZX format has many similarities to the
 * DEFLATE format used in zlib and gzip, but it's not quite the same.
 *
 */

/*
 * Copyright (C) 2012 Eric Biggers
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
 * This file has been modified from code taken from cabextract v0.5, which was,
 * itself, a modified version of the lzx decompression code from unlzx.  The
 * code has been customized for wimlib.
 *
 * Some notes on the LZX compression format as used in Windows Imaging (WIM)
 * files:
 *
 * A compressed WIM file resource consists of a table of chunk offsets followed
 * by compressed chunks.  All compressed chunks except the last decompress to
 * WIM_CHUNK_SIZE (= 32768) bytes.  This is quite similar to the cabinet (.cab)
 * file format, but they are not the same (at least based on M$'s
 * documentation).  According to the documentation, in the cabinet format, the
 * LZX block size is independent from the CFDATA blocks and may span several
 * CFDATA blocks.  However, for WIM file resources, I have seen no case of a LZX
 * block spanning multiple WIM chunks.  This is probably done to make it easier
 * to randomly access the compressed file resources.  WIMLIB in fact makes use
 * of this feature to allow semi-random access to file resources in the
 * read_resource() function.
 *
 * Usually a WIM chunk will contain only one LZX block, but on rare occasions it
 * may contain multiple LZX block. The LZX block are usually the aligned block
 * type or verbatim block type, but can (very rarely) be the uncompressed block
 * type.  The size of a LZX block is specified by 1 or 17 bits following the 3
 * bits that specify the block type.  A '1' means to use the default block size
 * (equal to 32768), while a '0' means that the block size is given by the next
 * 16 bits.
 *
 * The cabinet format, as documented, allows for the possibility that a CFDATA
 * chunk is up to 6144 bytes larger than the uncompressed data.  In the WIM
 * format, however, it appears that every chunk that would be 32768 bytes or
 * more when compressed, is actually stored uncompressed.  This is not
 * documented by M$.
 *
 * The 'e8' preprocessing step that changes x86 call instructions to use
 * absolute offsets instead of relative offsets relies on a filesize parameter.
 * There is no such parameter for this in the WIM files (even though the size of
 * the file resource could be used for this purpose), and instead a magic file
 * size of 12000000 is used.  The 'e8' preprocessing is always done, and there
 * is no bit to indicate whether it is done or not.
 *
 */

/* 
 * Some more notes about errors in Microsoft's documentation:
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
 * huffman tree AFTER the main and length trees. The implementation suggests
 * that the aligned offset tree is BEFORE the main and length trees.
 *
 * The LZX document decoding algorithm states that, in an aligned offset block,
 * if an extra_bits value is 1, 2 or 3, then that number of bits should be read
 * and the result added to the match offset. This is correct for 1 and 2, but
 * not 3, where just a huffman symbol (using the aligned tree) should be read.
 *
 * Regarding the E8 preprocessing, the LZX document states 'No translation may
 * be performed on the last 6 bytes of the input block'. This is correct.
 * However, the pseudocode provided checks for the *E8 leader* up to the last 6
 * bytes. If the leader appears between -10 and -7 bytes from the end, this
 * would cause the next four bytes to be modified, at least one of which would
 * be in the last 6 bytes, which is not allowed according to the spec.
 *
 * The specification states that the huffman trees must always contain at least
 * one element. However, many CAB files contain blocks where the length tree is
 * completely empty (because there are no matches), and this is expected to
 * succeed.
 */

#include "util.h"
#include "lzx.h"

#include "decomp.h"

#include <string.h>

/* Huffman decoding tables and maps from symbols to code lengths. */
struct lzx_tables {

	u16 maintree_decode_table[(1 << LZX_MAINTREE_TABLEBITS) + 
					(LZX_MAINTREE_NUM_SYMBOLS * 2)];
	u8 maintree_lens[LZX_MAINTREE_NUM_SYMBOLS];


	u16 lentree_decode_table[(1 << LZX_LENTREE_TABLEBITS) + 
					(LZX_LENTREE_NUM_SYMBOLS * 2)];
	u8 lentree_lens[LZX_LENTREE_NUM_SYMBOLS];


	u16 alignedtree_decode_table[(1 << LZX_ALIGNEDTREE_TABLEBITS) + 
					(LZX_ALIGNEDTREE_NUM_SYMBOLS * 2)];
	u8 alignedtree_lens[LZX_ALIGNEDTREE_NUM_SYMBOLS];
};


/* 
 * Reads a Huffman-encoded symbol using the pre-tree. 
 */
static inline int read_huffsym_using_pretree(struct input_bitstream *istream, 
					     const u16 pretree_decode_table[],
					     const u8 pretree_lens[], uint *n)
{
	return read_huffsym(istream, pretree_decode_table, pretree_lens, 
			    LZX_PRETREE_NUM_SYMBOLS, LZX_PRETREE_TABLEBITS, n,
			    LZX_MAX_CODEWORD_LEN);
}

/* Reads a Huffman-encoded symbol using the main tree. */
static inline int read_huffsym_using_maintree(struct input_bitstream *istream, 
					      const struct lzx_tables *tables, 
					      uint *n)
{
	return read_huffsym(istream, tables->maintree_decode_table, 
			    tables->maintree_lens, LZX_MAINTREE_NUM_SYMBOLS,
			    LZX_MAINTREE_TABLEBITS, n, LZX_MAX_CODEWORD_LEN);
}

/* Reads a Huffman-encoded symbol using the length tree. */
static inline int read_huffsym_using_lentree(struct input_bitstream *istream, 
					     const struct lzx_tables *tables, 
					     uint *n)
{
	return read_huffsym(istream, tables->lentree_decode_table, 
			    tables->lentree_lens, LZX_LENTREE_NUM_SYMBOLS, 
			    LZX_LENTREE_TABLEBITS, n, LZX_MAX_CODEWORD_LEN);
}

/* Reads a Huffman-encoded symbol using the aligned offset tree. */
static inline int read_huffsym_using_alignedtree(struct input_bitstream *istream, 
						 const struct lzx_tables *tables, 
						 uint *n)
{
	return read_huffsym(istream, tables->alignedtree_decode_table, 
			    tables->alignedtree_lens,
			    LZX_ALIGNEDTREE_NUM_SYMBOLS, 
			    LZX_ALIGNEDTREE_TABLEBITS, n, 8);
}

/* 
 * Reads the pretree from the input, then uses the pretree to decode @num_lens
 * code length values from the input. 
 *
 * @istream:	The bit stream for the input.  It is positioned on the beginning
 * 			of the pretree for the code length values.
 * @lens:	An array that contains the length values from the previous time
 * 			the code lengths for this Huffman tree were read, or all
 * 			0's if this is the first time.  
 * @num_lens:	Number of length values to decode and return.
 *
 */
static int lzx_read_code_lens(struct input_bitstream *istream, u8 lens[], 
			      uint num_lens)
{
	/* Declare the decoding table and length table for the pretree. */
	u16 pretree_decode_table[(1 << LZX_PRETREE_TABLEBITS) + 
					(LZX_PRETREE_NUM_SYMBOLS * 2)];
	u8 pretree_lens[LZX_PRETREE_NUM_SYMBOLS];
	uint i;
	uint len;
	int ret;

	/* Read the code lengths of the pretree codes.  There are 20 lengths of
	 * 4 bits each. */
	for (i = 0; i < LZX_PRETREE_NUM_SYMBOLS; i++) {
		ret = bitstream_read_bits(istream, LZX_PRETREE_ELEMENT_SIZE, 
					  &len);
		if (ret != 0)
			return ret;
		pretree_lens[i] = len;
	}

	/* Make the decoding table for the pretree. */
	ret = make_huffman_decode_table(pretree_decode_table, 
					LZX_PRETREE_NUM_SYMBOLS, 
					LZX_PRETREE_TABLEBITS, 
					pretree_lens, 
					LZX_MAX_CODEWORD_LEN);
	if (ret != 0)
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
		uint tree_code;
		uint num_zeroes;
		uint code; 
		uint num_same;
		char value;

		ret = read_huffsym_using_pretree(istream, pretree_decode_table, 
						pretree_lens, &tree_code);
		if (ret != 0)
			return ret;
		switch (tree_code) {
		case 17: /* Run of 0's */
			ret = bitstream_read_bits(istream, 4, &num_zeroes);
			if (ret != 0)
				return ret;
			num_zeroes += 4;
			while (num_zeroes--) {
				*lens = 0;
				if (++lens == lens_end)
					return 0;
			}
			break;
		case 18: /* Longer run of 0's */
			ret = bitstream_read_bits(istream, 5, &num_zeroes);
			if (ret != 0)
				return ret;
			num_zeroes += 20;
			while (num_zeroes--) {
				*lens = 0;
				if (++lens == lens_end)
					return 0;
			}
			break;
		case 19: /* Run of identical lengths */
			ret = bitstream_read_bits(istream, 1, &num_same);
			if (ret != 0)
				return ret;
			num_same += 4;

			ret = read_huffsym_using_pretree(istream, 
						pretree_decode_table, 
						pretree_lens, &code);
			if (ret != 0)
				return ret;
			value = (char)*lens - (char)code;
			if (value < 0)
				value += 17;
			while (num_same--) {
				*lens = value;
				if (++lens == lens_end)
					return 0;
			}
			break;
		default: /* Difference from old length. */
			value = (char)*lens - (char)tree_code;
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
 * 				in bytes, will be returned.
 * @block_type_ret:	A pointer to an int into which the type of the block
 * 				(LZX_BLOCKTYPE_*) will be returned.
 * @tables:		A pointer to a lzx_tables structure in which the 
 * 				main tree, the length tree, and possibly the
 * 				aligned offset tree will be constructed.
 * @queue:	A pointer to the least-recently-used queue into which
 * 			R0, R1, and R2 will be written (only for uncompressed
 * 			blocks, which contain this information in the header)
 */
static int lzx_read_block_header(struct input_bitstream *istream, 
				 int *block_size_ret, int *block_type_ret, 
				 struct lzx_tables *tables, 
				 struct lru_queue *queue)
{
	int ret;
	int block_type;
	uint block_size;
	int s;
	int i;
	uint len;
	int32_t R[3];

	ret = bitstream_ensure_bits(istream, 4);
	if (ret != 0) {
		ERROR("LZX input stream overrun");
		return ret;
	}

	/* The first three bits tell us what kind of block it is, and are one
	 * of the LZX_BLOCKTYPE_* values.  */
	block_type = bitstream_read_bits_nocheck(istream, 3);

	/* The next bit indicates whether the block size is the default (32768),
	 * indicated by a 1 bit, or whether the block size is given by the next
	 * 16 bits, indicated by a 0 bit. */
	s = bitstream_read_bits_nocheck(istream, 1);

	if (s == 1) {
		block_size = 1 << 15;
	} else {
		ret = bitstream_read_bits(istream, 16, &block_size);
		if (ret != 0)
			return ret;
		block_size = le16_to_cpu(block_size);
	}

	switch (block_type) {
	case LZX_BLOCKTYPE_ALIGNED:
		/* Read the path lengths for the elements of the aligned tree,
		 * then build it. */

		for (i = 0; i < LZX_ALIGNEDTREE_NUM_SYMBOLS; i++) {
			ret = bitstream_read_bits(istream, 
						  LZX_ALIGNEDTREE_ELEMENT_SIZE, 
						  &len);
			if (ret != 0)
				return ret;
			tables->alignedtree_lens[i] = len;
		}
		
		LZX_DEBUG("Building the aligned tree.");
		ret = make_huffman_decode_table(tables->alignedtree_decode_table,
						LZX_ALIGNEDTREE_NUM_SYMBOLS, 
						LZX_ALIGNEDTREE_TABLEBITS,
						tables->alignedtree_lens,
						8);
		if (ret != 0) {
			ERROR("lzx_decompress(): Failed to make the decode "
			      "table for the aligned offset tree");
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
		if (ret != 0) {
			ERROR("lzx_decompress(): Failed to read the code "
			      "lengths for the first 256 elements of the "
			      "main tree");
			return ret;
		}

		/* Read the path lengths for the remaining elements of the main
		 * tree. */
		LZX_DEBUG("Reading path lengths for remaining elements of "
			  "main tree (%d elements).",
			  LZX_MAINTREE_NUM_SYMBOLS - LZX_NUM_CHARS);
		ret = lzx_read_code_lens(istream, 
					 tables->maintree_lens + LZX_NUM_CHARS, 
					 LZX_MAINTREE_NUM_SYMBOLS - LZX_NUM_CHARS);
		if (ret != 0) {
			ERROR("lzx_decompress(): Failed to read the path "
			      "lengths for the remaining elements of the main "
			      "tree");
			return ret;
		}

		LZX_DEBUG("Building the Huffman decoding "
			  "table for the main tree.");

		ret = make_huffman_decode_table(tables->maintree_decode_table,
						LZX_MAINTREE_NUM_SYMBOLS,
						LZX_MAINTREE_TABLEBITS,
						tables->maintree_lens, 
						LZX_MAX_CODEWORD_LEN);
		if (ret != 0) {
			ERROR("lzx_decompress(): Failed to make the decode "
			      "table for the main tree");
			return ret;
		}

		LZX_DEBUG("Reading path lengths for the length tree.");
		ret = lzx_read_code_lens(istream, tables->lentree_lens, 
					 LZX_LENTREE_NUM_SYMBOLS);
		if (ret != 0) {
			ERROR("lzx_decompress(): Failed to read the path "
			      "lengths for the length tree");
			return ret;
		}

		LZX_DEBUG("Building the length tree.");
		ret = make_huffman_decode_table(tables->lentree_decode_table,
						LZX_LENTREE_NUM_SYMBOLS, 
						LZX_LENTREE_TABLEBITS,
						tables->lentree_lens, 
						LZX_MAX_CODEWORD_LEN);
		if (ret != 0) {
			ERROR("lzx_decompress(): Failed to build the length "
			      "Huffman tree");
			return ret;
		}

		break;

	case LZX_BLOCKTYPE_UNCOMPRESSED:
		LZX_DEBUG("Found uncompressed block.");
		ret = align_input_bitstream(istream, true);
		if (ret != 0)
			return ret;
		ret = bitstream_read_bytes(istream, sizeof(R), R);
		if (ret != 0)
			return ret;
		queue->R0 = le32_to_cpu(R[0]);
		queue->R1 = le32_to_cpu(R[1]);
		queue->R2 = le32_to_cpu(R[2]);
		break;
	default:
		LZX_DEBUG("Found invalid block.");
		return 1;
	}
	*block_type_ret = block_type;
	*block_size_ret = block_size;
	return 0;
}

/* 
 * Decodes a compressed literal match value.  It refers to some match_offset to
 * a point earlier in the window, and some match_len, for which the data is to
 * be copied to the current position in the window.
 *
 * @main_element:	The start of the match data, as decoded using the main
 * 				tree.
 * @block_type:	The type of the block (LZX_BLOCKTYPE_ALIGNED or
 *			LZX_BLOCKTYPE_VERBATIM)
 * @bytes_remaining:	The amount of uncompressed data remaining to be
 * 				uncompressed.  It is an error if the match
 * 				is longer than @bytes_remaining.
 * @window:	A pointer to the window into which the uncompressed
 * 			data is being written.
 * @window_pos:	The current position in the window.
 * @tables:	Contains the Huffman tables for the block (main,
 * 			length, and also aligned offset only for
 * 			LZX_BLOCKTYPE_ALIGNED)
 * @queue:	The least-recently used queue for match offsets.
 * @istream:	The input bitstream.
 *
 * Returns the length of the match, or -1 on error (match would exceed
 * the amount of data needing to be uncompressed, or match refers to data before
 * the window, or the input bitstream ended unexpectedly).
 */
static int lzx_decode_match(int main_element, int block_type, 
			    int bytes_remaining, u8 *window, int window_pos, 
			    const struct lzx_tables *tables, 
			    struct lru_queue *queue, 
			    struct input_bitstream *istream)
{
	uint length_header;
	uint position_slot;
	uint match_len;
	uint match_offset;
	uint additional_len;
	uint num_extra_bits;
	uint verbatim_bits;
	uint aligned_bits;
	int ret;
	int i;
	u8 *match_dest;
	u8 *match_src;

	/* The main element is offset by 256 because values under 256 indicate a
	 * literal value. */
	main_element -= LZX_NUM_CHARS;

	/* The length header consists of the lower 3 bits of the main element.
	 * The position slot is the rest of it. */
	length_header = main_element & LZX_NUM_PRIMARY_LENS;
	position_slot = main_element >> 3;

	/* If the length_header is less than LZX_NUM_PRIMARY_LENS (= 7), it
	 * gives the match length as the offset from LZX_MIN_MATCH.  Otherwise,
	 * the length is given by an additional symbol encoded using the length
	 * tree, offset by 9 (LZX_MIN_MATCH + LZX_NUM_PRIMARY_LENS) */
	match_len = LZX_MIN_MATCH + length_header;
	if (length_header == LZX_NUM_PRIMARY_LENS) {
		ret = read_huffsym_using_lentree(istream, tables, 
						&additional_len);
		if (ret != 0)
			return -1;
		match_len += additional_len;
	}


	/* If the position_slot is 0, 1, or 2, the match offset is retrieved
	 * from the LRU queue.  Otherwise, the match offset is not in the LRU
	 * queue. */
	switch (position_slot) {
	case 0:
		match_offset = queue->R0;
		break;
	case 1:
		match_offset = queue->R1;
		swap(queue->R0, queue->R1);
		break;
	case 2:
		/* The queue doesn't work quite the same as a real LRU queue,
		 * since using the R2 offset doesn't bump the R1 offset down to
		 * R2. */
		match_offset = queue->R2;
		swap(queue->R0, queue->R2);
		break;
	default:
		/* Otherwise, the offset was not encoded as one the offsets in
		 * the queue.  Depending on the position slot, there is a
		 * certain number of extra bits that need to be read to fully
		 * decode the match offset. */

		/* Look up the number of extra bits that need to be read. */
		num_extra_bits = lzx_extra_bits[position_slot];

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
			ret = bitstream_read_bits(istream, num_extra_bits - 3, 
								&verbatim_bits);
			if (ret != 0)
				return -1;

			verbatim_bits <<= 3;

			ret = read_huffsym_using_alignedtree(istream, tables, 
							     &aligned_bits);
			if (ret != 0)
				return -1;
		} else {
			/* For non-aligned blocks, or for aligned blocks with
			 * less than 3 extra bits, the extra bits are added
			 * directly to the match offset, and the correction for
			 * the alignment is taken to be 0. */
			ret = bitstream_read_bits(istream, num_extra_bits, 
						  &verbatim_bits);
			if (ret != 0)
				return -1;

			aligned_bits = 0;
		}

		/* Calculate the match offset. */
		match_offset = lzx_position_base[position_slot] + verbatim_bits + 
							aligned_bits - 2;

		/* Update the LRU queue. */
		queue->R2 = queue->R1;
		queue->R1 = queue->R0;
		queue->R0 = match_offset;
		break;
	}

	/* Verify that the match is in the bounds of the part of the window
	 * currently in use, then copy the source of the match to the current
	 * position. */
	match_dest = window + window_pos;
	match_src = match_dest - match_offset;

	if (match_len > bytes_remaining) {
		ERROR("lzx_decode_match(): Match of length %d bytes overflows "
		      "uncompressed block size", match_len);
		return -1;
	}

	if (match_src < window) {
		ERROR("lzx_decode_match(): Match of length %d bytes references "
		      "data before window (match_offset = %d, window_pos = %d)",
		      match_len, match_offset, window_pos);
		return -1;
	}

#if 0
	printf("Match: src %u, dst %u, len %u\n", match_src - window,
						match_dest - window,
						match_len);
	putchar('|');
	for (i = 0; i < match_len; i++) {
		match_dest[i] = match_src[i];
		putchar(match_src[i]);
	}
	putchar('|');
	putchar('\n');
#else
	for (i = 0; i < match_len; i++)
		match_dest[i] = match_src[i];
#endif

	return match_len;
}



/* Undo the 'E8' preprocessing, where the targets of x86 CALL instructions were
 * changed from relative offsets to absolute offsets.  This type of
 * preprocessing can be used on any binary data even if it is not actually
 * machine code.  It seems to always be used in WIM files, even though there is
 * no bit to indicate that it actually is used, unlike in the LZX compressed
 * format as used in other file formats, where a bit is reserved for that
 * purpose. */
static void undo_call_insn_preprocessing(u8 uncompressed_data[], 
					 uint uncompressed_data_len)
{
	int i = 0;
	int file_size = LZX_MAGIC_FILESIZE;
	int32_t abs_offset;
	int32_t rel_offset;

	/* Not enabled in the last 6 bytes, which means the 5-byte call
	 * instruction cannot start in the last *10* bytes. */
	while (i < uncompressed_data_len - 10) { 
		if (uncompressed_data[i] != 0xe8) {
			i++;
			continue;
		}
		abs_offset = le32_to_cpu(*(int32_t*)(uncompressed_data + i + 1));

		if (abs_offset >= -i && abs_offset < file_size) {
			if (abs_offset >= 0) {
				/* "good translation" */
				rel_offset = abs_offset - i;
			} else {
				/* "compensating translation" */
				rel_offset = abs_offset + file_size;
			}
			*(int32_t*)(uncompressed_data + i + 1) = 
						cpu_to_le32(rel_offset);
		}
		i += 5;
	}
}

/* 
 * Decompresses a compressed block of data from which the header has already
 * been read.
 *
 * @block_type:	The type of the block (LZX_BLOCKTYPE_VERBATIM or
 * 		LZX_BLOCKTYPE_ALIGNED)
 * @block_size:	The size of the block, in bytes.
 * @window:	Pointer to the decompression window.
 * @window_pos:	The current position in the window.  Will be 0 for the first
 * 			block.	
 * @tables:	The Huffman decoding tables for the block (main, length, and
 * 			aligned offset, the latter only for LZX_BLOCKTYPE_ALIGNED)
 * @queue:	The least-recently-used queue for match offsets.
 * @istream:	The input bitstream for the compressed literals.
 */
static int lzx_decompress_block(int block_type, int block_size, u8 *window, 
				int window_pos, 
				const struct lzx_tables *tables, 
				struct lru_queue *queue, 
				struct input_bitstream *istream)
{
	uint bytes_remaining;
	uint main_element;
	int match_len;
	int ret;

	bytes_remaining = block_size;
	while (bytes_remaining > 0) {

		ret = read_huffsym_using_maintree(istream, tables, 
						  &main_element);
		if (ret != 0)
			return ret;

		if (main_element < LZX_NUM_CHARS) {
			/* literal: 0 to LZX_NUM_CHARS - 1 */
			window[window_pos + block_size - bytes_remaining] = 
							main_element;
			bytes_remaining--;
		} else {
			/* match: LZX_NUM_CHARS to LZX_MAINTREE_NUM_SYMBOLS - 1 */
			match_len = lzx_decode_match(main_element, 
						block_type, bytes_remaining, window,
						block_size + window_pos - 
							bytes_remaining,
						tables, queue, istream);
			if (match_len == -1)
				return 1;

			bytes_remaining -= match_len;
		}
	}
	return 0;
}

/* 
 * Decompresses a block of LZX-compressed data using a window size of 32768.
 *
 * @compressed_data:	A pointer to the compressed data.
 * @compressed_len:	The length of the compressed data, in bytes.  
 * @uncompressed_data:	A pointer to the buffer into which to write the
 * 				uncompressed data.
 * @uncompressed_len:	The length of the uncompressed data.
 *
 * Return non-zero on failure.
 */
int lzx_decompress(const void *compressed_data, uint compressed_len, 
		   void *uncompressed_data, uint uncompressed_len)
{
	struct lzx_tables 	tables;
	struct input_bitstream 	istream;
	struct lru_queue 	queue;
	uint 			bytes_remaining;
	int ret;
	int block_size;
	int block_type;

	LZX_DEBUG("lzx_decompress (compressed_data = %p, compressed_len = %d, "
		  "uncompressed_data = %p, uncompressed_len = %d).",
		  compressed_data, compressed_len,
		  uncompressed_data, uncompressed_len);

	wimlib_assert(uncompressed_len <= 32768);

	memset(tables.maintree_lens, 0, sizeof(tables.maintree_lens));
	memset(tables.lentree_lens, 0, sizeof(tables.lentree_lens));
	queue.R0 = 1;
	queue.R1 = 1;
	queue.R2 = 1;
	bytes_remaining = uncompressed_len;

	init_input_bitstream(&istream, compressed_data, compressed_len);

	/* The compressed data will consist of one or more blocks.  The
	 * following loop decompresses one block, and it runs until there all
	 * the compressed data has been decompressed, so there are no more
	 * blocks.  */

	while (bytes_remaining != 0) {

		LZX_DEBUG("Reading block header.");
		ret = lzx_read_block_header(&istream, &block_size, &block_type, 
							&tables, &queue);
		if (ret != 0)
			return ret;

		LZX_DEBUG("block_size = %d, bytes_remaining = %d.",
			  block_size, bytes_remaining);

		if (block_size > bytes_remaining) {
			ERROR("lzx_decompress(): Expected a block size of at "
			      "most %d bytes (found %d bytes)",
			      bytes_remaining, block_size);
			return 1;
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
						   uncompressed_len -
						       bytes_remaining, 
						   &tables, &queue, &istream);
			if (ret != 0)
				return ret;
			break;
		case LZX_BLOCKTYPE_UNCOMPRESSED:
			LZX_DEBUG("LZX_BLOCKTYPE_UNCOMPRESSED");
			ret = bitstream_read_bytes(&istream, block_size, 
						   uncompressed_data + 
						   uncompressed_len - 
						   bytes_remaining);
			if (ret != 0)
				return ret;
			if (block_size & 1)
				align_input_bitstream(&istream, false);
			break;
		default:
			wimlib_assert(0);
			break;
		}

		bytes_remaining -= block_size;

		if (bytes_remaining != 0)
			LZX_DEBUG("%d bytes remaining.", bytes_remaining);

	}

	if (uncompressed_len >= 10)
		undo_call_insn_preprocessing(uncompressed_data,
					     uncompressed_len);

	return 0;
}
