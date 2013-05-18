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

#ifdef __GNUC__
#  ifdef __SSE2__
#    define USE_SSE2_FILL
#    include <emmintrin.h>
#  else
#    define USE_LONG_FILL
#  endif
#endif

/*
 * make_huffman_decode_table: - Builds a fast huffman decoding table from an
 * array that gives the length of the codeword for each symbol in the alphabet.
 * Originally based on code written by David Tritscher (taken the original LZX
 * decompression code); also heavily modified to add some optimizations used in
 * the zlib code, as well as more comments; also added some optimizations to
 * make filling in the decode table entries faster (may not help significantly
 * though).
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
make_huffman_decode_table(u16 *decode_table,  unsigned num_syms,
			  unsigned table_bits, const u8 *lens,
			  unsigned max_codeword_len)
{
	unsigned len_counts[max_codeword_len + 1];
	u16 sorted_syms[num_syms];
	unsigned offsets[max_codeword_len + 1];
	const unsigned table_num_entries = 1 << table_bits;
	int left;
	unsigned decode_table_pos;
	void *decode_table_ptr;
	unsigned sym_idx;
	unsigned codeword_len;
	unsigned stores_per_loop;

#ifdef USE_LONG_FILL
	const unsigned entries_per_long = sizeof(unsigned long) / sizeof(decode_table[0]);
#endif

#ifdef USE_SSE2_FILL
	const unsigned entries_per_xmm = sizeof(__m128i) / sizeof(decode_table[0]);
#endif

	wimlib_assert2((uintptr_t)decode_table % DECODE_TABLE_ALIGNMENT == 0);

	/* accumulate lengths for codes */
	for (unsigned i = 0; i <= max_codeword_len; i++)
		len_counts[i] = 0;

	for (unsigned sym = 0; sym < num_syms; sym++) {
		wimlib_assert2(lens[sym] <= max_codeword_len);
		len_counts[lens[sym]]++;
	}

	/* check for an over-subscribed or incomplete set of lengths */
	left = 1;
	for (unsigned len = 1; len <= max_codeword_len; len++) {
		left <<= 1;
		left -= len_counts[len];
		if (unlikely(left < 0)) { /* over-subscribed */
			ERROR("Invalid Huffman code (over-subscribed)");
			return -1;
		}
	}

	if (unlikely(left != 0)) /* incomplete set */{
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
	 * This is basically a count-sort over the codeword lengths. */
	for (unsigned sym = 0; sym < num_syms; sym++)
		if (lens[sym] != 0)
			sorted_syms[offsets[lens[sym]]++] = sym;

	/* Fill entries for codewords short enough for a direct mapping.  We can
	 * take advantage of the ordering of the codewords, since the Huffman
	 * code is canonical.  It must be the case that all the codewords of
	 * some length L numerically precede all the codewords of length L + 1.
	 * Furthermore, if we have 2 symbols A and B with the same codeword
	 * length but symbol A is sorted before symbol B, then then we know that
	 * the codeword for A numerically precedes the codeword for B. */
	decode_table_ptr = decode_table;
	sym_idx = 0;
	codeword_len = 1;
#ifdef USE_SSE2_FILL
	/* Fill in the Huffman decode table entries one 128-bit vector at a
	 * time.  This is 8 entries per store. */
	stores_per_loop = (1 << (table_bits - codeword_len)) / entries_per_xmm;
	for (; stores_per_loop != 0; codeword_len++, stores_per_loop >>= 1) {
		unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
		for (; sym_idx < end_sym_idx; sym_idx++) {
			/* Note: unlike in the 'long' version below, the __m128i
			 * type already has __attribute__((may_alias)), so using
			 * it to access the decode table, which is an array of
			 * unsigned shorts, will not violate strict aliasing. */
			u16 sym;
			__m128i v;
			__m128i *p;
			unsigned n;

			sym = sorted_syms[sym_idx];

			v = _mm_set1_epi16(sym);
			p = (__m128i*)decode_table_ptr;
			n = stores_per_loop;
			do {
				*p++ = v;
			} while (--n);
			decode_table_ptr = p;
		}
	}
#endif /* USE_SSE2_FILL */

#ifdef USE_LONG_FILL
	/* Fill in the Huffman decode table entries one 'unsigned long' at a
	 * time.  On 32-bit systems this is 2 entries per store, while on 64-bit
	 * systems this is 4 entries per store. */
	stores_per_loop = (1 << (table_bits - codeword_len)) / entries_per_long;
	for (; stores_per_loop != 0; codeword_len++, stores_per_loop >>= 1) {
		unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
		for (; sym_idx < end_sym_idx; sym_idx++) {

			/* Accessing the array of unsigned shorts as unsigned
			 * longs would violate strict aliasing and would require
			 * compiling the code with -fno-strict-aliasing to
			 * guarantee correctness.  To work around this problem,
			 * use the gcc 'may_alias' extension to define a special
			 * unsigned long type that may alias any other in-memory
			 * variable.  */
			typedef unsigned long __attribute__((may_alias)) aliased_long_t;

			u16 sym;
			aliased_long_t *p;
			aliased_long_t v;
			unsigned n;

			sym = sorted_syms[sym_idx];

			BUILD_BUG_ON(sizeof(aliased_long_t) != 4 &&
				     sizeof(aliased_long_t) != 8);

			v = sym;
			if (sizeof(aliased_long_t) >= 4)
				v |= v << 16;
			if (sizeof(aliased_long_t) >= 8) {
				/* This may produce a compiler warning if an
				 * aliased_long_t is 32 bits, but this won't be
				 * executed unless an aliased_long_t is at least
				 * 64 bits anyway. */
				v |= v << 32;
			}

			p = (aliased_long_t *)decode_table_ptr;
			n = stores_per_loop;

			do {
				*p++ = v;
			} while (--n);
			decode_table_ptr = p;
		}
	}
#endif /* USE_LONG_FILL */

	/* Fill in the Huffman decode table entries one 16-bit integer at a
	 * time. */
	stores_per_loop = (1 << (table_bits - codeword_len));
	for (; stores_per_loop != 0; codeword_len++, stores_per_loop >>= 1) {
		unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
		for (; sym_idx < end_sym_idx; sym_idx++) {
			u16 sym;
			u16 *p;
			unsigned n;

			sym = sorted_syms[sym_idx];

			p = (u16*)decode_table_ptr;
			n = stores_per_loop;

			do {
				*p++ = sym;
			} while (--n);

			decode_table_ptr = p;
		}
	}

	/* If we've filled in the entire table, we are done.  Otherwise, there
	 * are codes longer than table bits that we need to store in the
	 * tree-like structure at the end of the table rather than directly in
	 * the main decode table itself. */

	decode_table_pos = (u16*)decode_table_ptr - decode_table;
	if (decode_table_pos != table_num_entries) {
		unsigned j;
		unsigned next_free_tree_slot;
		unsigned cur_codeword;

		wimlib_assert2(decode_table_pos < table_num_entries);

		/* Fill in the remaining entries, which correspond to codes
		 * longer than @table_bits.
		 *
		 * First, zero out the rest of the entries.  This is necessary
		 * so that the entries appear as "unallocated" in the next part.
		 * */
		j = decode_table_pos;
		do {
			decode_table[j] = 0;
		} while (++j != table_num_entries);

		/* Assert that 2**table_bits is at least num_syms.  If this
		 * wasn't the case, we wouldn't be able to distinguish pointer
		 * entries from symbol entries. */
		wimlib_assert2(table_num_entries >= num_syms);


		/* The tree nodes are allocated starting at decode_table[1 <<
		 * table_bits].  Remember that the full size of the table,
		 * including the extra space for the tree nodes, is actually
		 * 2**table_bits + 2 * num_syms slots, while table_num_entries
		 * is only 2**table_bits. */
		next_free_tree_slot = table_num_entries;

		/* The current Huffman codeword  */
		cur_codeword = decode_table_pos << 1;

		/* Go through every codeword of length greater than @table_bits,
		 * primarily in order of codeword length and secondarily in
		 * order of symbol. */
		wimlib_assert2(codeword_len == table_bits + 1);
		for (; codeword_len <= max_codeword_len; codeword_len++, cur_codeword <<= 1)
		{
			unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
			for (; sym_idx < end_sym_idx; sym_idx++, cur_codeword++) {
				unsigned sym = sorted_syms[sym_idx];
				unsigned extra_bits = codeword_len - table_bits;

				/* index of the current node; find it from the
				 * prefix of the current Huffman codeword. */
				unsigned node_idx = cur_codeword >> extra_bits;
				wimlib_assert2(node_idx < table_num_entries);

				/* Go through each bit of the current Huffman
				 * codeword beyond the prefix of length
				 * @table_bits and walk the tree, allocating any
				 * slots that have not yet been allocated. */
				do {

					/* If the current tree node points to
					 * nowhere but we need to follow it,
					 * allocate a new node for it to point
					 * to. */
					if (decode_table[node_idx] == 0) {
						decode_table[node_idx] = next_free_tree_slot;
						decode_table[next_free_tree_slot++] = 0;
						decode_table[next_free_tree_slot++] = 0;
						wimlib_assert2(next_free_tree_slot <=
							       table_num_entries + 2 * num_syms);
					}

					/* Set node_idx to left child */
					node_idx = decode_table[node_idx];

					/* Is the next bit 0 or 1? If 0, go left
					 * (already done).  If 1, go right by
					 * incrementing node_idx. */
					--extra_bits;
					node_idx += (cur_codeword >> extra_bits) & 1;
				} while (extra_bits != 0);

				/* node_idx is now the index of the leaf entry
				 * into which the actual symbol will go. */
				decode_table[node_idx] = sym;

				/* Note: cur_codeword is always incremented at
				 * the end of this loop because this is how
				 * canonical Huffman codes are generated (add 1
				 * for each code, then left shift whenever the
				 * code length increases) */
			}
		}
	}
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
