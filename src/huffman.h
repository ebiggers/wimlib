/*
 * huffman.h
 *
 * Copyright (C) 2012 Eric Biggers
 *
 * wimlib - Library for working with WIM files 
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */
#ifndef _WIMLIB_HUFFMAN_H
#define _WIMLIB_HUFFMAN_H

#include "util.h"
#include "decomp.h"

extern void make_canonical_huffman_code(uint num_syms, uint max_codeword_len, 
					const u32 freq_tab[], u8 lens[], 
					u16 codewords[]);

extern int make_huffman_decode_table(u16 decode_table[], uint num_syms, 
				     uint num_bits, const u8 lengths[],
				     uint max_codeword_len);

extern int read_huffsym_near_end_of_input(struct input_bitstream *istream, 
					  const u16 decode_table[], 
					  const u8 lengths[], 
					  uint num_symbols, 
					  uint table_bits, 
					  uint *n);

/* 
 * Reads a Huffman-encoded symbol from a bitstream.
 *
 * This function may be called hundreds of millions of times when extracting a
 * large WIM file, and it is declared to be always inlined for improved
 * performance.  I'm not sure it could be made much faster that it is,
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
static int ALWAYS_INLINE 
read_huffsym(struct input_bitstream *stream, 
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
		 * actually remaining.  Don't inline this part since it is very
		 * rarely used. */
		return read_huffsym_near_end_of_input(stream, decode_table, lengths,
					num_symbols, table_bits, n);
	}
}



#endif /* _WIMLIB_HUFFMAN_H */
