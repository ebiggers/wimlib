/*
 * decompress.c
 *
 * Functions used for decompression.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/decompress.h"
#include "wimlib/util.h"

#include <string.h>

/*
 * make_huffman_decode_table: - Builds a fast huffman decoding table from an
 * array that gives the length of the codeword for each symbol in the alphabet.
 * Originally based on code written by David Tritscher (taken the original LZX
 * decompression code); also heavily modified to add some optimizations used in
 * the zlib code, as well as more comments.
 *
 * @decode_table:	The array in which to create the fast huffman decoding
 * 			table.  It must have a length of at least
 * 			(2**table_bits) + 2 * num_syms to guarantee
 * 			that there is enough space.
 *
 * @num_syms: 		Number of symbols in the alphabet, including symbols
 *			that do not appear in this particular input chunk.
 *
 * @table_bits:		Any symbols with a code length of table_bits or less can
 * 			be decoded in one lookup of the table.  2**table_bits
 * 			must be greater than or equal to @num_syms if there are
 * 			any Huffman codes longer than @table_bits.
 *
 * @lens:		An array of length @num_syms, indexable by symbol, that
 * 			gives the length of the Huffman codeword for that
 * 			symbol.  Because the Huffman tree is in canonical form,
 * 			it can be reconstructed by only knowing the length of
 * 			the codeword for each symbol.  It is assumed, but not
 * 			checked, that every length is less than
 * 			@max_codeword_len.
 *
 * @max_codeword_len:	The longest codeword length allowed in the compression
 * 			format.
 *
 * Returns 0 on success; returns -1 if the length values do not correspond to a
 * valid Huffman tree.
 *
 * The format of the Huffamn decoding table is as follows.  The first (1 <<
 * table_bits) entries of the table are indexed by chunks of the input of size
 * @table_bits.  If the next Huffman codeword in the input happens to have a
 * length of exactly @table_bits, the symbol is simply read directly from the
 * decoding table.  Alternatively, if the next Huffman codeword has length _less
 * than_ @table_bits, the symbol is also read directly from the decode table;
 * this is possible because every entry in the table that is indexed by an
 * integer that has the shorter codeword as a binary prefix is filled in with
 * the appropriate symbol.  If a codeword has length n <= table_bits, it will
 * have 2**(table_bits - n) possible suffixes, and thus that many entries in the
 * decoding table.
 *
 * It's a bit more complicated if the next Huffman codeword has length of more
 * than @table_bits.  The table entry indexed by the first @table_bits of that
 * codeword cannot give the appropriate symbol directly, because that entry is
 * guaranteed to be referenced by the Huffman codewords of multiple symbols.
 * And while the LZX compression format does not allow codes longer than 16
 * bits, a table of size (2 ** 16) = 65536 entries would be too slow to create.
 *
 * There are several different ways to make it possible to look up the symbols
 * for codewords longer than @table_bits.  One way is to make the entries for
 * the prefixes of length @table_bits of those entries be pointers to additional
 * decoding tables that are indexed by some number of additional bits of the
 * codeword.  The technique used here is a bit simpler, however: just store the
 * needed subtrees of the Huffman tree in the decoding table after the lookup
 * entries, beginning at index (2**table_bits).  Real pointers are replaced by
 * indices into the decoding table, and symbol entries are distinguished from
 * pointers by the fact that values less than @num_syms must be symbol values.
 */
int
make_huffman_decode_table(u16 decode_table[],  unsigned num_syms,
			  unsigned table_bits, const u8 lens[],
			  unsigned max_codeword_len)
{
	unsigned len_counts[max_codeword_len + 1];
	u16 sorted_syms[num_syms];
	unsigned offsets[max_codeword_len + 1];
	const unsigned table_num_entries = 1 << table_bits;

	/* accumulate lengths for codes */
	for (unsigned i = 0; i <= max_codeword_len; i++)
		len_counts[i] = 0;

	for (unsigned sym = 0; sym < num_syms; sym++) {
		wimlib_assert2(lens[sym] <= max_codeword_len);
		len_counts[lens[sym]]++;
	}

	/* check for an over-subscribed or incomplete set of lengths */
	int left = 1;
	for (unsigned len = 1; len <= max_codeword_len; len++) {
		left <<= 1;
		left -= len_counts[len];
		if (left < 0) { /* over-subscribed */
			ERROR("Invalid Huffman code (over-subscribed)");
			return -1;
		}
	}
	if (left != 0) /* incomplete set */{
		if (left == 1 << max_codeword_len) {
			/* Empty code--- okay in XPRESS and LZX */
			memset(decode_table, 0,
			       table_num_entries * sizeof(decode_table[0]));
			return 0;
		} else {
			ERROR("Invalid Huffman code (incomplete set)");
			return -1;
		}
	}

	/* Generate offsets into symbol table for each length for sorting */
	offsets[1] = 0;
	for (unsigned len = 1; len < max_codeword_len; len++)
		offsets[len + 1] = offsets[len] + len_counts[len];

	/* Sort symbols primarily by length and secondarily by symbol order.
	 * This is basically a count-sort over the codeword lengths.
	 * In the process, calculate the number of symbols that have nonzero
	 * length and are therefore used in the symbol stream. */
	unsigned num_used_syms = 0;
	for (unsigned sym = 0; sym < num_syms; sym++) {
		if (lens[sym] != 0) {
			sorted_syms[offsets[lens[sym]]++] = sym;
			num_used_syms++;
		}
	}

	/* Fill entries for codewords short enough for a direct mapping.  We can
	 * take advantage of the ordering of the codewords, since the Huffman
	 * code is canonical.  It must be the case that all the codewords of
	 * some length L numerically precede all the codewords of length L + 1.
	 * Furthermore, if we have 2 symbols A and B with the same codeword
	 * length but symbol A is sorted before symbol B, then then we know that
	 * the codeword for A numerically precedes the codeword for B. */
	unsigned decode_table_pos = 0;
	unsigned i = 0;

	wimlib_assert2(num_used_syms != 0);
	while (1) {
		unsigned sym = sorted_syms[i];
		unsigned codeword_len = lens[sym];
		if (codeword_len > table_bits)
			break;

		unsigned num_entries = 1 << (table_bits - codeword_len);
		const unsigned entries_per_long = sizeof(unsigned long) /
						  sizeof(decode_table[0]);
		if (num_entries >= entries_per_long) {
			/* Fill in the Huffman decode table entries one unsigned
			 * long at a time.  On 32-bit systems this is 2 entries
			 * per store, while on 64-bit systems this is 4 entries
			 * per store. */
			wimlib_assert2(decode_table_pos % entries_per_long == 0);
			BUILD_BUG_ON(sizeof(unsigned long) != 4 &&
				     sizeof(unsigned long) != 8);

			unsigned long *p = (unsigned long *)&decode_table[decode_table_pos];
			unsigned n = num_entries / entries_per_long;
			unsigned long v = sym;
			if (sizeof(unsigned long) >= 4)
				v |= v << 16;
			if (sizeof(unsigned long) >= 8) {
				/* This may produce a compiler warning if an
				 * unsigned long is 32 bits, but this won't be
				 * executed unless an unsigned long is at least
				 * 64 bits anyway. */
				v |= v << 32;
			}
			do {
				*p++ = v;
			} while (--n);

			decode_table_pos += num_entries;
		} else {
			/* Fill in the Huffman decode table entries one 16-bit
			 * integer at a time. */
			do {
				decode_table[decode_table_pos++] = sym;
			} while (--num_entries);
		}
		wimlib_assert2(decode_table_pos <= table_num_entries);
		if (++i == num_used_syms) {
			wimlib_assert2(decode_table_pos == table_num_entries);
			/* No codewords were longer than @table_bits, so the
			 * table is now entirely filled with the codewords. */
			return 0;
		}
	}

	wimlib_assert2(i < num_used_syms);
	wimlib_assert2(decode_table_pos < table_num_entries);

	/* Fill in the remaining entries, which correspond to codes longer than
	 * @table_bits.
	 *
	 * First, zero out the rest of the entries.  This is necessary so that
	 * the entries appear as "unallocated" in the next part. */
	{
		unsigned j = decode_table_pos;
		do {
			decode_table[j] = 0;
		} while (++j != table_num_entries);
	}

	/* Assert that 2**table_bits is at least num_syms.  If this wasn't the
	 * case, we wouldn't be able to distinguish pointer entries from symbol
	 * entries. */
	wimlib_assert2(table_num_entries >= num_syms);

	/* The current Huffman codeword  */
	unsigned cur_codeword = decode_table_pos;

	/* The tree nodes are allocated starting at decode_table[1 <<
	 * table_bits].  Remember that the full size of the table, including the
	 * extra space for the tree nodes, is actually 2**table_bits + 2 *
	 * num_syms slots, while table_num_entries is only 2**table_Bits. */
	unsigned next_free_tree_slot = table_num_entries;

	/* Go through every codeword of length greater than @table_bits,
	 * primarily in order of codeword length and secondarily in order of
	 * symbol. */
	unsigned prev_codeword_len = table_bits;
	do {
		unsigned sym = sorted_syms[i];
		unsigned codeword_len = lens[sym];
		unsigned extra_bits = codeword_len - table_bits;

		cur_codeword <<= (codeword_len - prev_codeword_len);
		prev_codeword_len = codeword_len;

		/* index of the current node; find it from the prefix of the
		 * current Huffman codeword. */
		unsigned node_idx = cur_codeword >> extra_bits;
		wimlib_assert2(node_idx < table_num_entries);

		/* Go through each bit of the current Huffman codeword beyond
		 * the prefix of length @table_bits and walk the tree,
		 * allocating any slots that have not yet been allocated. */
		do {

			/* If the current tree node points to nowhere
			 * but we need to follow it, allocate a new node
			 * for it to point to. */
			if (decode_table[node_idx] == 0) {
				decode_table[node_idx] = next_free_tree_slot;
				decode_table[next_free_tree_slot++] = 0;
				decode_table[next_free_tree_slot++] = 0;
				wimlib_assert2(next_free_tree_slot <=
					       table_num_entries + 2 * num_syms);
			}

			/* Set node_idx to left child */
			node_idx = decode_table[node_idx];

			/* Is the next bit 0 or 1? If 0, go left (already done).
			 * If 1, go right by incrementing node_idx. */
			--extra_bits;
			node_idx += (cur_codeword >> extra_bits) & 1;
		} while (extra_bits != 0);

		/* node_idx is now the index of the leaf entry into which the
		 * actual symbol will go. */
		decode_table[node_idx] = sym;

		/* cur_codeword is always incremented because this is
		 * how canonical Huffman codes are generated (add 1 for
		 * each code, then left shift whenever the code length
		 * increases) */
		cur_codeword++;
	} while (++i != num_used_syms);
	return 0;
}

/* Reads a Huffman-encoded symbol from the bistream when the number of remaining
 * bits is less than the maximum codeword length. */
int
read_huffsym_near_end_of_input(struct input_bitstream *istream,
			       const u16 decode_table[],
			       const u8 lens[],
			       unsigned num_syms,
			       unsigned table_bits,
			       unsigned *n)
{
	unsigned bitsleft = istream->bitsleft;
	unsigned key_size;
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
				return -1;
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
