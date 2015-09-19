/*
 * lzx_decompress.c
 *
 * A decompressor for the LZX compression format, as used in WIM files.
 */

/*
 * Copyright (C) 2012, 2013, 2014, 2015 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

/*
 * LZX is an LZ77 and Huffman-code based compression format that has many
 * similarities to DEFLATE (the format used by zlib/gzip).  The compression
 * ratio is as good or better than DEFLATE.  See lzx_compress.c for a format
 * overview, and see https://en.wikipedia.org/wiki/LZX_(algorithm) for a
 * historical overview.  Here I make some pragmatic notes.
 *
 * The old specification for LZX is the document "Microsoft LZX Data Compression
 * Format" (1997).  It defines the LZX format as used in cabinet files.  Allowed
 * window sizes are 2^n where 15 <= n <= 21.  However, this document contains
 * several errors, so don't read too much into it...
 *
 * The new specification for LZX is the document "[MS-PATCH]: LZX DELTA
 * Compression and Decompression" (2014).  It defines the LZX format as used by
 * Microsoft's binary patcher.  It corrects several errors in the 1997 document
 * and extends the format in several ways --- namely, optional reference data,
 * up to 2^25 byte windows, and longer match lengths.
 *
 * WIM files use a more restricted form of LZX.  No LZX DELTA extensions are
 * present, the window is not "sliding", E8 preprocessing is done
 * unconditionally with a fixed file size, and the maximum window size is always
 * 2^15 bytes (equal to the size of each "chunk" in a compressed WIM resource).
 * This code is primarily intended to implement this form of LZX.  But although
 * not compatible with WIMGAPI, this code also supports maximum window sizes up
 * to 2^21 bytes.
 *
 * TODO: Add support for window sizes up to 2^25 bytes.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>

#include "wimlib/decompressor_ops.h"
#include "wimlib/decompress_common.h"
#include "wimlib/error.h"
#include "wimlib/lzx_common.h"
#include "wimlib/util.h"

/* These values are chosen for fast decompression.  */
#define LZX_MAINCODE_TABLEBITS		11
#define LZX_LENCODE_TABLEBITS		10
#define LZX_PRECODE_TABLEBITS		6
#define LZX_ALIGNEDCODE_TABLEBITS	7

#define LZX_READ_LENS_MAX_OVERRUN 50

/* Huffman decoding tables, and arrays that map symbols to codeword lengths.  */
struct lzx_tables {

	u16 maincode_decode_table[(1 << LZX_MAINCODE_TABLEBITS) +
					(LZX_MAINCODE_MAX_NUM_SYMBOLS * 2)]
					_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	u8 maincode_lens[LZX_MAINCODE_MAX_NUM_SYMBOLS + LZX_READ_LENS_MAX_OVERRUN];


	u16 lencode_decode_table[(1 << LZX_LENCODE_TABLEBITS) +
					(LZX_LENCODE_NUM_SYMBOLS * 2)]
					_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	u8 lencode_lens[LZX_LENCODE_NUM_SYMBOLS + LZX_READ_LENS_MAX_OVERRUN];


	u16 alignedcode_decode_table[(1 << LZX_ALIGNEDCODE_TABLEBITS) +
					(LZX_ALIGNEDCODE_NUM_SYMBOLS * 2)]
					_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	u8 alignedcode_lens[LZX_ALIGNEDCODE_NUM_SYMBOLS];
} _aligned_attribute(DECODE_TABLE_ALIGNMENT);

/* Least-recently used queue for match offsets.  */
struct lzx_lru_queue {
	u32 R[LZX_NUM_RECENT_OFFSETS];
};

static inline void
lzx_lru_queue_init(struct lzx_lru_queue *queue)
{
	for (unsigned i = 0; i < LZX_NUM_RECENT_OFFSETS; i++)
		queue->R[i] = 1;
}

/* The main LZX decompressor structure.
 *
 * Note: we keep track of most of the decompression state outside this
 * structure.  This structure only exists so that (1) we can store @window_order
 * and @num_main_syms for multiple calls to lzx_decompress(); and (2) so that we
 * don't have to allocate the large 'struct lzx_tables' on the stack.  */
struct lzx_decompressor {
	unsigned window_order;
	unsigned num_main_syms;
	struct lzx_tables tables;
};

/* Read a Huffman-encoded symbol using the precode.  */
static inline unsigned
read_huffsym_using_precode(struct input_bitstream *istream,
			   const u16 precode_decode_table[])
{
	return read_huffsym(istream, precode_decode_table,
			    LZX_PRECODE_TABLEBITS, LZX_MAX_PRE_CODEWORD_LEN);
}

/* Read a Huffman-encoded symbol using the main code.  */
static inline unsigned
read_huffsym_using_maincode(struct input_bitstream *istream,
			    const struct lzx_tables *tables)
{
	return read_huffsym(istream, tables->maincode_decode_table,
			    LZX_MAINCODE_TABLEBITS, LZX_MAX_MAIN_CODEWORD_LEN);
}

/* Read a Huffman-encoded symbol using the length code.  */
static inline unsigned
read_huffsym_using_lencode(struct input_bitstream *istream,
			   const struct lzx_tables *tables)
{
	return read_huffsym(istream, tables->lencode_decode_table,
			    LZX_LENCODE_TABLEBITS, LZX_MAX_LEN_CODEWORD_LEN);
}

/* Read a Huffman-encoded symbol using the aligned offset code.  */
static inline unsigned
read_huffsym_using_alignedcode(struct input_bitstream *istream,
			       const struct lzx_tables *tables)
{
	return read_huffsym(istream, tables->alignedcode_decode_table,
			    LZX_ALIGNEDCODE_TABLEBITS, LZX_MAX_ALIGNED_CODEWORD_LEN);
}

/*
 * Read the precode from the compressed input bitstream, then use it to decode
 * @num_lens codeword length values.
 *
 * @istream:
 *	The input bitstream.
 *
 * @lens:
 *	An array that contains the length values from the previous time the
 *	codeword lengths for this Huffman code were read, or all 0's if this is
 *	the first time.  This array must have at least (@num_lens +
 *	LZX_READ_LENS_MAX_OVERRUN) entries.
 *
 * @num_lens:
 *	Number of length values to decode.
 *
 * Returns 0 on success, or -1 if the data was invalid.
 */
static int
lzx_read_codeword_lens(struct input_bitstream *istream, u8 *lens, unsigned num_lens)
{
	u16 precode_decode_table[(1 << LZX_PRECODE_TABLEBITS) +
					(LZX_PRECODE_NUM_SYMBOLS * 2)]
					_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	u8 precode_lens[LZX_PRECODE_NUM_SYMBOLS];
	u8 *len_ptr = lens;
	u8 *lens_end = lens + num_lens;
	int ret;

	/* Read the lengths of the precode codewords.  These are given
	 * explicitly.  */
	for (int i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++) {
		precode_lens[i] = bitstream_read_bits(istream,
						      LZX_PRECODE_ELEMENT_SIZE);
	}

	/* Make the decoding table for the precode.  */
	ret = make_huffman_decode_table(precode_decode_table,
					LZX_PRECODE_NUM_SYMBOLS,
					LZX_PRECODE_TABLEBITS,
					precode_lens,
					LZX_MAX_PRE_CODEWORD_LEN);
	if (ret)
		return ret;

	/* Decode the codeword lengths.  */
	do {
		unsigned presym;
		u8 len;

		/* Read the next precode symbol.  */
		presym = read_huffsym_using_precode(istream,
						    precode_decode_table);
		if (presym < 17) {
			/* Difference from old length  */
			len = *len_ptr - presym;
			if ((s8)len < 0)
				len += 17;
			*len_ptr++ = len;
		} else {
			/* Special RLE values  */

			unsigned run_len;

			if (presym == 17) {
				/* Run of 0's  */
				run_len = 4 + bitstream_read_bits(istream, 4);
				len = 0;
			} else if (presym == 18) {
				/* Longer run of 0's  */
				run_len = 20 + bitstream_read_bits(istream, 5);
				len = 0;
			} else {
				/* Run of identical lengths  */
				run_len = 4 + bitstream_read_bits(istream, 1);
				presym = read_huffsym_using_precode(istream,
								    precode_decode_table);
				if (unlikely(presym > 17))
					return -1;
				len = *len_ptr - presym;
				if ((s8)len < 0)
					len += 17;
			}

			do {
				*len_ptr++ = len;
			} while (--run_len);
			/* Worst case overrun is when presym == 18,
			 * run_len == 20 + 31, and only 1 length was remaining.
			 * So LZX_READ_LENS_MAX_OVERRUN == 50.
			 *
			 * Overrun while reading the first half of maincode_lens
			 * can corrupt the previous values in the second half.
			 * This doesn't really matter because the resulting
			 * lengths will still be in range, and data that
			 * generates overruns is invalid anyway.  */
		}
	} while (len_ptr < lens_end);
	return 0;
}

/*
 * Read the header of an LZX block and save the block type and size in
 * *block_type_ret and *block_size_ret, respectively.
 *
 * If the block is compressed, also update the Huffman decode @tables with the
 * new Huffman codes.
 *
 * If the block is uncompressed, also update the match offset @queue with the
 * new match offsets.
 *
 * Return 0 on success, or -1 if the data was invalid.
 */
static int
lzx_read_block_header(struct input_bitstream *istream,
		      unsigned num_main_syms,
		      unsigned window_order,
		      int *block_type_ret,
		      u32 *block_size_ret,
		      struct lzx_tables *tables,
		      struct lzx_lru_queue *queue)
{
	int block_type;
	u32 block_size;
	int ret;

	bitstream_ensure_bits(istream, 4);

	/* The first three bits tell us what kind of block it is, and should be
	 * one of the LZX_BLOCKTYPE_* values.  */
	block_type = bitstream_pop_bits(istream, 3);

	/* Read the block size.  This mirrors the behavior of
	 * lzx_write_compressed_block() in lzx_compress.c; see that for more
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

		if (window_order >= 16) {
			tmp = bitstream_read_bits(istream, 8);
			block_size <<= 8;
			block_size |= tmp;
		}
	}

	switch (block_type) {

	case LZX_BLOCKTYPE_ALIGNED:

		/* Read the aligned offset code and prepare its decode table.
		 */

		for (int i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
			tables->alignedcode_lens[i] =
				bitstream_read_bits(istream,
						    LZX_ALIGNEDCODE_ELEMENT_SIZE);
		}

		ret = make_huffman_decode_table(tables->alignedcode_decode_table,
						LZX_ALIGNEDCODE_NUM_SYMBOLS,
						LZX_ALIGNEDCODE_TABLEBITS,
						tables->alignedcode_lens,
						LZX_MAX_ALIGNED_CODEWORD_LEN);
		if (ret)
			return ret;

		/* Fall though, since the rest of the header for aligned offset
		 * blocks is the same as that for verbatim blocks.  */

	case LZX_BLOCKTYPE_VERBATIM:

		/* Read the main code and prepare its decode table.
		 *
		 * Note that the codeword lengths in the main code are encoded
		 * in two parts: one part for literal symbols, and one part for
		 * match symbols.  */

		ret = lzx_read_codeword_lens(istream, tables->maincode_lens,
					     LZX_NUM_CHARS);
		if (ret)
			return ret;

		ret = lzx_read_codeword_lens(istream,
					     tables->maincode_lens + LZX_NUM_CHARS,
					     num_main_syms - LZX_NUM_CHARS);
		if (ret)
			return ret;

		ret = make_huffman_decode_table(tables->maincode_decode_table,
						num_main_syms,
						LZX_MAINCODE_TABLEBITS,
						tables->maincode_lens,
						LZX_MAX_MAIN_CODEWORD_LEN);
		if (ret)
			return ret;

		/* Read the length code and prepare its decode table.  */

		ret = lzx_read_codeword_lens(istream, tables->lencode_lens,
					     LZX_LENCODE_NUM_SYMBOLS);
		if (ret)
			return ret;

		ret = make_huffman_decode_table(tables->lencode_decode_table,
						LZX_LENCODE_NUM_SYMBOLS,
						LZX_LENCODE_TABLEBITS,
						tables->lencode_lens,
						LZX_MAX_LEN_CODEWORD_LEN);
		if (ret)
			return ret;

		break;

	case LZX_BLOCKTYPE_UNCOMPRESSED:

		/* Before reading the three LRU match offsets from the
		 * uncompressed block header, the stream must be aligned on a
		 * 16-bit boundary.  But, unexpectedly, if the stream is
		 * *already* aligned, the correct thing to do is to throw away
		 * the next 16 bits.  */

		bitstream_ensure_bits(istream, 1);
		bitstream_align(istream);
		queue->R[0] = bitstream_read_u32(istream);
		queue->R[1] = bitstream_read_u32(istream);
		queue->R[2] = bitstream_read_u32(istream);

		/* Offsets of 0 are invalid.  */
		if (queue->R[0] == 0 || queue->R[1] == 0 || queue->R[2] == 0)
			return -1;
		break;

	default:
		/* Unrecognized block type.  */
		return -1;
	}

	*block_type_ret = block_type;
	*block_size_ret = block_size;
	return 0;
}

/*
 * Decompress a block of LZX-compressed data.
 *
 * @block_type:
 *	The type of the block (LZX_BLOCKTYPE_VERBATIM or LZX_BLOCKTYPE_ALIGNED).
 * @out_begin
 *	The beginning of the (uncompressed) output buffer.
 * @out_next
 *	Pointer to the location in the (uncompressed) output buffer at which
 *	this block will start.
 * @out_block_end
 *	Pointer to the location in the (uncompressed) output buffer at which
 *	this block will end.
 * @tables:
 *	The Huffman decoding tables for this block.
 * @queue:
 *	The least-recently-used queue for match offsets.
 * @istream:
 *	The input bitstream, positioned at the start of the block data.
 *
 * Returns 0 on success, or -1 if the data was invalid.
 */
static int
lzx_decompress_block(int block_type, u8 * const out_begin,
		     u8 * out_next, u8 * const out_block_end,
		     const struct lzx_tables *tables,
		     struct lzx_lru_queue *queue,
		     struct input_bitstream *istream)
{
	unsigned mainsym;
	u32 match_len;
	unsigned offset_slot;
	u32 match_offset;
	unsigned num_extra_bits;
	unsigned ones_if_aligned = 0U - (block_type == LZX_BLOCKTYPE_ALIGNED);

	while (out_next != out_block_end) {

		mainsym = read_huffsym_using_maincode(istream, tables);
		if (mainsym < LZX_NUM_CHARS) {
			/* Literal  */
			*out_next++ = mainsym;
			continue;
		}

		/* Match  */

		/* Decode the length header and offset slot.  */
		mainsym -= LZX_NUM_CHARS;
		match_len = mainsym % LZX_NUM_LEN_HEADERS;
		offset_slot = mainsym / LZX_NUM_LEN_HEADERS;

		/* If needed, read a length symbol to decode the full length. */
		if (match_len == LZX_NUM_PRIMARY_LENS)
			match_len += read_huffsym_using_lencode(istream, tables);
		match_len += LZX_MIN_MATCH_LEN;

		if (offset_slot < LZX_NUM_RECENT_OFFSETS) {
			/* Repeat offset  */

			/* Note: This isn't a real LRU queue, since using the R2
			 * offset doesn't bump the R1 offset down to R2.  This
			 * quirk allows all 3 recent offsets to be handled by
			 * the same code.  (For R0, the swap is a no-op.)  */
			match_offset = queue->R[offset_slot];
			queue->R[offset_slot] = queue->R[0];
			queue->R[0] = match_offset;
		} else {
			/* Explicit offset  */

			/* Look up the number of extra bits that need to be read
			 * to decode offsets with this offset slot.  */
			num_extra_bits = lzx_extra_offset_bits[offset_slot];

			/* Start with the offset slot base value.  */
			match_offset = lzx_offset_slot_base[offset_slot];

			/* In aligned offset blocks, the low-order 3 bits of
			 * each offset are encoded using the aligned offset
			 * code.  Otherwise, all the extra bits are literal.  */

			if ((num_extra_bits & ones_if_aligned) >= LZX_NUM_ALIGNED_OFFSET_BITS) {
				match_offset +=
					bitstream_read_bits(istream,
							    num_extra_bits -
								LZX_NUM_ALIGNED_OFFSET_BITS)
							<< LZX_NUM_ALIGNED_OFFSET_BITS;
				match_offset += read_huffsym_using_alignedcode(istream, tables);
			} else {
				match_offset += bitstream_read_bits(istream, num_extra_bits);
			}

			/* Adjust the offset.  */
			match_offset -= LZX_OFFSET_ADJUSTMENT;

			/* Update the match offset LRU queue.  */
			STATIC_ASSERT(LZX_NUM_RECENT_OFFSETS == 3);
			queue->R[2] = queue->R[1];
			queue->R[1] = queue->R[0];
			queue->R[0] = match_offset;
		}

		/* Validate the match, then copy it to the current position.  */

		if (unlikely(match_len > out_block_end - out_next))
			return -1;

		if (unlikely(match_offset > out_next - out_begin))
			return -1;

		lz_copy(out_next, match_len, match_offset, out_block_end,
			LZX_MIN_MATCH_LEN);

		out_next += match_len;
	}
	return 0;
}

static int
lzx_decompress(const void *restrict compressed_data, size_t compressed_size,
	       void *restrict uncompressed_data, size_t uncompressed_size,
	       void *restrict _dec)
{
	struct lzx_decompressor *dec = _dec;
	struct input_bitstream istream;
	struct lzx_lru_queue queue;
	u8 * const out_begin = uncompressed_data;
	u8 *out_next = out_begin;
	u8 * const out_end = out_begin + uncompressed_size;
	int block_type;
	u32 block_size;
	bool may_have_e8_byte;
	int ret;

	init_input_bitstream(&istream, compressed_data, compressed_size);

	/* Initialize the recent offsets queue.  */
	lzx_lru_queue_init(&queue);

	/* Codeword lengths begin as all 0's for delta encoding purposes.  */
	memset(dec->tables.maincode_lens, 0, dec->num_main_syms);
	memset(dec->tables.lencode_lens, 0, LZX_LENCODE_NUM_SYMBOLS);

	/* Set this to true if there may be 0xe8 bytes in the uncompressed data.
	 */
	may_have_e8_byte = false;

	/* The compressed data will consist of one or more blocks.  The
	 * following loop decompresses one block, and it runs until there all
	 * the compressed data has been decompressed, so there are no more
	 * blocks.  */

	while (out_next != out_end) {

		ret = lzx_read_block_header(&istream, dec->num_main_syms,
					    dec->window_order, &block_type,
					    &block_size, &dec->tables, &queue);
		if (ret)
			return ret;

		if (block_size > out_end - out_next)
			return -1;

		if (block_type != LZX_BLOCKTYPE_UNCOMPRESSED) {

			/* Compressed block.  */

			ret = lzx_decompress_block(block_type,
						   out_begin,
						   out_next,
						   out_next + block_size,
						   &dec->tables,
						   &queue,
						   &istream);
			if (ret)
				return ret;

			/* If the first 0xe8 byte was in this block, it must
			 * have been encoded as a literal using mainsym 0xe8. */
			if (dec->tables.maincode_lens[0xe8] != 0)
				may_have_e8_byte = true;

			out_next += block_size;
		} else {

			/* Uncompressed block.  */
			out_next = bitstream_read_bytes(&istream, out_next, block_size);
			if (!out_next)
				return -1;

			/* Re-align the bitstream if an odd number of bytes was
			 * read.  */
			if (block_size & 1)
				bitstream_read_byte(&istream);

			may_have_e8_byte = true;
		}
	}

	/* Postprocess the data unless it cannot possibly contain 0xe8 bytes  */
	if (may_have_e8_byte)
		lzx_postprocess(uncompressed_data, uncompressed_size);

	return 0;
}

static void
lzx_free_decompressor(void *_dec)
{
	struct lzx_decompressor *dec = _dec;

	ALIGNED_FREE(dec);
}

static int
lzx_create_decompressor(size_t max_block_size, void **dec_ret)
{
	struct lzx_decompressor *dec;
	unsigned window_order;

	window_order = lzx_get_window_order(max_block_size);
	if (window_order == 0)
		return WIMLIB_ERR_INVALID_PARAM;

	/* The aligned allocation is needed to ensure that the lzx_tables are
	 * aligned properly.  */
	dec = ALIGNED_MALLOC(sizeof(struct lzx_decompressor),
			     DECODE_TABLE_ALIGNMENT);
	if (!dec)
		return WIMLIB_ERR_NOMEM;

	dec->window_order = window_order;
	dec->num_main_syms = lzx_get_num_main_syms(window_order);

	*dec_ret = dec;
	return 0;
}

const struct decompressor_ops lzx_decompressor_ops = {
	.create_decompressor = lzx_create_decompressor,
	.decompress	     = lzx_decompress,
	.free_decompressor   = lzx_free_decompressor,
};
