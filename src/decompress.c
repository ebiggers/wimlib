/*
 * decompress.c
 *
 * Functions used for decompression.
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

#include "decompress.h"
#include <string.h>

/* Reads @n bytes from the bitstream @stream into the location pointed to by @dest.
 * The bitstream must be 16-bit aligned. */
int bitstream_read_bytes(struct input_bitstream *stream, size_t n, void *dest)
{
	/* Precondition:  The bitstream is 16-byte aligned. */
	wimlib_assert(stream->bitsleft % 16 == 0);

	u8 *p = dest;

	/* Get the bytes currently in the buffer variable. */
	while (stream->bitsleft != 0) {
		if (n-- == 0)
			return 0;
		*p++ = bitstream_peek_bits(stream, 8);
		bitstream_remove_bits(stream, 8);
	}

	/* Get the rest directly from the pointer to the data.  Of course, it's
	 * necessary to check there are really n bytes available. */
	if (n > stream->data_bytes_left) {
		ERROR("Unexpected end of input when reading %zu bytes from "
		      "bitstream (only have %u bytes left)",
		      n, stream->data_bytes_left);
		return 1;
	}
	memcpy(p, stream->data, n);
	stream->data += n;
	stream->data_bytes_left -= n;

	/* It's possible to copy an odd number of bytes and leave the stream in
	 * an inconsistent state. Fix it by reading the next byte, if it is
	 * there. */
	if ((n & 1) && stream->data_bytes_left != 0) {
		stream->bitsleft = 8;
		stream->data_bytes_left--;
		stream->bitbuf |= (input_bitbuf_t)(*stream->data) <<
					(sizeof(input_bitbuf_t) * 8 - 8);
		stream->data++;
	}
	return 0;
}

/* Aligns the bitstream on a 16-bit boundary.
 *
 * Note: M$'s idea of "alignment" means that for some reason, a 16-bit word
 * should be skipped over if the buffer happens to already be aligned on such a
 * boundary.  This only applies for realigning the stream after the blocktype
 * and length fields of an uncompressed block, however; it does not apply when
 * realigning the stream after the end of the uncompressed block.
 */
int align_input_bitstream(struct input_bitstream *stream,
			  bool skip_word_if_aligned)
{
	int ret;
	if (stream->bitsleft % 16 != 0) {
		bitstream_remove_bits(stream, stream->bitsleft % 16);
	} else if (skip_word_if_aligned) {
		if (stream->bitsleft == 0) {
			ret = bitstream_ensure_bits(stream, 16);
			if (ret != 0) {
				ERROR("Unexpected end of input when "
				      "aligning bitstream");
				return ret;
			}
		}
		bitstream_remove_bits(stream, 16);
	}
	return 0;
}

/*
 * Builds a fast huffman decoding table from a canonical huffman code lengths
 * table.  Based on code written by David Tritscher.
 *
 * @decode_table:	The array in which to create the fast huffman decoding
 * 				table.  It must have a length of at least
 * 				(2**num_bits) + 2 * num_syms to guarantee
 * 				that there is enough space.
 *
 * @num_syms: 	Total number of symbols in the Huffman tree.
 *
 * @num_bits:	Any symbols with a code length of num_bits or less can be
 * 			decoded in one lookup of the table.  2**num_bits
 * 			must be greater than or equal to @num_syms if there are
 * 			any Huffman codes longer than @num_bits.
 *
 * @lens:	An array of length @num_syms, indexable by symbol, that
 * 			gives the length of that symbol.  Because the Huffman
 * 			tree is in canonical form, it can be reconstructed by
 * 			only knowing the length of the code for each symbol.
 *
 * @make_codeword_len:	An integer that gives the longest possible codeword
 * 			length.
 *
 * Returns 0 on success; returns 1 if the length values do not correspond to a
 * valid Huffman tree, or if there are codes of length greater than @num_bits
 * but 2**num_bits < num_syms.
 *
 * What exactly is the format of the fast Huffman decoding table?  The first
 * (1 << num_bits) entries of the table are indexed by chunks of the input of
 * size @num_bits.  If the next Huffman code in the input happens to have a
 * length of exactly @num_bits, the symbol is simply read directly from the
 * decoding table.  Alternatively, if the next Huffman code has length _less
 * than_ @num_bits, the symbol is also read directly from the decode table; this
 * is possible because every entry in the table that is indexed by an integer
 * that has the shorter code as a binary prefix is filled in with the
 * appropriate symbol.  If a code has length n <= num_bits, it will have
 * 2**(num_bits - n) possible suffixes, and thus that many entries in the
 * decoding table.
 *
 * It's a bit more complicated if the next Huffman code has length of more than
 * @num_bits.  The table entry indexed by the first @num_bits of that code
 * cannot give the appropriate symbol directly, because that entry is guaranteed
 * to be referenced by the Huffman codes for multiple symbols.  And while the
 * LZX compression format does not allow codes longer than 16 bits, a table of
 * size (2 ** 16) = 65536 entries would be too slow to create.
 *
 * There are several different ways to make it possible to look up the symbols
 * for codes longer than @num_bits.  A common way is to make the entries for the
 * prefixes of length @num_bits of those entries be pointers to additional
 * decoding tables that are indexed by some number of additional bits of the
 * code symbol.  The technique used here is a bit simpler, however.  We just
 * store the needed subtrees of the Huffman tree in the decoding table after the
 * lookup entries, beginning at index (2**num_bits).  Real pointers are
 * replaced by indices into the decoding table, and we distinguish symbol
 * entries from pointers by the fact that values less than @num_syms must be
 * symbol values.
 */
int make_huffman_decode_table(u16 decode_table[],  uint num_syms,
			      uint num_bits, const u8 lens[],
			      uint max_code_len)
{
	/* Number of entries in the decode table. */
	u32 table_num_entries = 1 << num_bits;

	/* Current position in the decode table. */
	u32 decode_table_pos = 0;

	/* Fill entries for codes short enough for a direct mapping.  Here we
	 * are taking advantage of the ordering of the codes, since they are for
	 * a canonical Huffman tree.  It must be the case that all the codes of
	 * some length @code_length, zero-extended or one-extended, numerically
	 * precede all the codes of length @code_length + 1.  Furthermore, if we
	 * have 2 symbols A and B, such that A is listed before B in the lens
	 * array, and both symbols have the same code length, then we know that
	 * the code for A numerically precedes the code for B.
	 * */
	for (uint code_len = 1; code_len <= num_bits; code_len++) {

		/* Number of entries that a code of length @code_length would
		 * need.  */
		u32 code_num_entries = 1 << (num_bits - code_len);


		/* For each symbol of length @code_len, fill in its entries in
		 * the decode table. */
		for (uint sym = 0; sym < num_syms; sym++) {

			if (lens[sym] != code_len)
				continue;


			/* Check for table overrun.  This can only happen if the
			 * given lengths do not correspond to a valid Huffman
			 * tree.  */
			if (decode_table_pos >= table_num_entries) {
				ERROR("Huffman decoding table overrun: "
				      "pos = %u, num_entries = %u",
				      decode_table_pos, table_num_entries);
				return 1;
			}

			/* Fill all possible lookups of this symbol with
			 * the symbol itself. */
			for (uint i = 0; i < code_num_entries; i++)
				decode_table[decode_table_pos + i] = sym;

			/* Increment the position in the decode table by
			 * the number of entries that were just filled
			 * in. */
			decode_table_pos += code_num_entries;
		}
	}

	/* If all entries of the decode table have been filled in, there are no
	 * codes longer than num_bits, so we are done filling in the decode
	 * table. */
	if (decode_table_pos == table_num_entries)
		return 0;

	/* Otherwise, fill in the remaining entries, which correspond to codes longer
	 * than @num_bits. */


	/* First, zero out the rest of the entries; this is necessary so
	 * that the entries appear as "unallocated" in the next part.  */
	for (uint i = decode_table_pos; i < table_num_entries; i++)
		decode_table[i] = 0;

	/* Assert that 2**num_bits is at least num_syms.  If this wasn't the
	 * case, we wouldn't be able to distinguish pointer entries from symbol
	 * entries. */
	wimlib_assert((1 << num_bits) >= num_syms);


	/* The current Huffman code.  */
	uint current_code = decode_table_pos;

	/* The tree nodes are allocated starting at
	 * decode_table[table_num_entries].  Remember that the full size of the
	 * table, including the extra space for the tree nodes, is actually
	 * 2**num_bits + 2 * num_syms slots, while table_num_entries is only
	 * 2**num_bits. */
	uint next_free_tree_slot = table_num_entries;

	/* Go through every codeword of length greater than @num_bits.  Note:
	 * the LZX format guarantees that the codeword length can be at most 16
	 * bits. */
	for (uint code_len = num_bits + 1; code_len <= max_code_len;
							code_len++)
	{
		current_code <<= 1;
		for (uint sym = 0; sym < num_syms; sym++) {
			if (lens[sym] != code_len)
				continue;


			/* i is the index of the current node; find it from the
			 * prefix of the current Huffman code. */
			uint i = current_code >> (code_len - num_bits);

			if (i >= (1 << num_bits)) {
				ERROR("Invalid canonical Huffman code");
				return 1;
			}

			/* Go through each bit of the current Huffman code
			 * beyond the prefix of length num_bits and walk the
			 * tree, "allocating" slots that have not yet been
			 * allocated. */
			for (int bit_num = num_bits + 1; bit_num <= code_len; bit_num++) {

				/* If the current tree node points to nowhere
				 * but we need to follow it, allocate a new node
				 * for it to point to. */
				if (decode_table[i] == 0) {
					decode_table[i] = next_free_tree_slot;
					decode_table[next_free_tree_slot++] = 0;
					decode_table[next_free_tree_slot++] = 0;
				}

				i = decode_table[i];

				/* Is the next bit 0 or 1? If 0, go left;
				 * otherwise, go right (by incrementing i by 1) */
				int bit_pos = code_len - bit_num;

				int bit = (current_code & (1 << bit_pos)) >>
								bit_pos;
				i += bit;
			}

			/* i is now the index of the leaf entry into which the
			 * actual symbol will go. */
			decode_table[i] = sym;

			/* Increment decode_table_pos only if the prefix of the
			 * Huffman code changes. */
			if (current_code >> (code_len - num_bits) !=
					(current_code + 1) >> (code_len - num_bits))
				decode_table_pos++;

			/* current_code is always incremented because this is
			 * how canonical Huffman codes are generated (add 1 for
			 * each code, then left shift whenever the code length
			 * increases) */
			current_code++;
		}
	}


	/* If the lengths really represented a valid Huffman tree, all
	 * @table_num_entries in the table will have been filled.  However, it
	 * is also possible that the tree is completely empty (as noted
	 * earlier) with all 0 lengths, and this is expected to succeed. */

	if (decode_table_pos != table_num_entries) {

		for (uint i = 0; i < num_syms; i++) {
			if (lens[i] != 0) {
				ERROR("Lengths do not form a valid canonical "
				      "Huffman tree (only filled %u of %u "
				      "decode table slots)",
				      decode_table_pos, table_num_entries);
				return 1;
			}
		}
	}
	return 0;
}

/* Reads a Huffman-encoded symbol when it is known there are less than
 * MAX_CODE_LEN bits remaining in the bitstream. */
static int read_huffsym_near_end_of_input(struct input_bitstream *istream,
					  const u16 decode_table[],
					  const u8 lens[],
					  uint num_syms,
					  uint table_bits,
					  uint *n)
{
	uint bitsleft = istream->bitsleft;
	uint key_size;
	u16 sym;
	u16 key_bits;

	if (table_bits > bitsleft) {
		key_size = bitsleft;
		bitsleft = 0;
		key_bits = bitstream_peek_bits(istream, key_size) <<
						(table_bits - key_size);
	} else {
		key_size = table_bits;
		bitsleft -= table_bits;
		key_bits = bitstream_peek_bits(istream, table_bits);
	}

	sym = decode_table[key_bits];
	if (sym >= num_syms) {
		bitstream_remove_bits(istream, key_size);
		do {
			if (bitsleft == 0) {
				ERROR("Input stream exhausted");
				return 1;
			}
			key_bits = sym + bitstream_peek_bits(istream, 1);
			bitstream_remove_bits(istream, 1);
			bitsleft--;
		} while ((sym = decode_table[key_bits]) >= num_syms);
	} else {
		bitstream_remove_bits(istream, lens[sym]);
	}
	*n = sym;
	return 0;
}

/*
 * Reads a Huffman-encoded symbol from a bitstream.
 *
 * This function may be called hundreds of millions of times when extracting a
 * large WIM file.  I'm not sure it could be made much faster that it is,
 * especially since there isn't enough time to make a big table that allows
 * decoding multiple symbols per lookup.  But if extracting files to a hard
 * disk, the IO will be the bottleneck anyway.
 *
 * @buf:	The input buffer from which the symbol will be read.
 * @decode_table:	The fast Huffman decoding table for the Huffman tree.
 * @lengths:		The table that gives the length of the code for each
 * 				symbol.
 * @num_symbols:	The number of symbols in the Huffman code.
 * @table_bits:		Huffman codes this length or less can be looked up
 * 				directory in the decode_table, as the
 * 				decode_table contains 2**table_bits entries.
 */
int read_huffsym(struct input_bitstream *stream,
		 const u16 decode_table[],
		 const u8 lengths[],
		 unsigned num_symbols,
		 unsigned table_bits,
		 uint *n,
		 unsigned max_codeword_len)
{
	/* In the most common case, there are at least max_codeword_len bits
	 * remaining in the stream. */
	if (bitstream_ensure_bits(stream, max_codeword_len) == 0) {

		/* Use the next table_bits of the input as an index into the
		 * decode_table. */
		u16 key_bits = bitstream_peek_bits(stream, table_bits);

		u16 sym = decode_table[key_bits];

		/* If the entry in the decode table is not a valid symbol, it is
		 * the offset of the root of its Huffman subtree. */
		if (sym >= num_symbols) {
			bitstream_remove_bits(stream, table_bits);
			do {
				key_bits = sym + bitstream_peek_bits(stream, 1);
				bitstream_remove_bits(stream, 1);

				wimlib_assert(key_bits < num_symbols * 2 +
							(1 << table_bits));
			} while ((sym = decode_table[key_bits]) >= num_symbols);
		} else {
			wimlib_assert(lengths[sym] <= table_bits);
			bitstream_remove_bits(stream, lengths[sym]);
		}
		*n = sym;
		return 0;
	} else {
		/* Otherwise, we must be careful to use only the bits that are
		 * actually remaining.  */
		return read_huffsym_near_end_of_input(stream, decode_table,
						      lengths, num_symbols,
						      table_bits, n);
	}
}
