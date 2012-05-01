/*
 * huffman.c
 *
 * Make a canonical Huffman code from symbol frequencies; reconstruct  a
 * canonical Huffman code from codeword lengths, making it into a table for fast
 * decoding of the input.
 *
 * Copyright (C) 2012 Eric Biggers
 * Copyright (C) 2002 Matthew T. Russotto
 *
 * wimlib - Library for working with WIM files 
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "util.h"
#include "huffman.h"
#include <string.h>
#include <stdlib.h>

/* Intermediate (non-leaf) node in a Huffman tree. */
typedef struct HuffmanNode {
	u32 freq;
	u16 sym;
	union {
		u16 path_len;
		u16 height;
	};
	struct HuffmanNode *left_child;
	struct HuffmanNode *right_child;
} HuffmanNode;

/* Leaf node in a Huffman tree.  The fields are in the same order as the
 * HuffmanNode, so it can be cast to a HuffmanNode.  There are no pointers to
 * the children in the leaf node. */
typedef struct {
	u32 freq;
	u16 sym;
	union {
		u16 path_len;
		u16 height;
	};
} HuffmanLeafNode;

/* Comparator function for HuffmanLeafNodes.  Sorts primarily by symbol
 * frequency and secondarily by symbol value. */
static int cmp_leaves_by_freq(const void *__leaf1, const void *__leaf2)
{
	const HuffmanLeafNode *leaf1 = __leaf1;
	const HuffmanLeafNode *leaf2 = __leaf2;

	int freq_diff = (int)leaf1->freq - (int)leaf2->freq;

	if (freq_diff == 0)
		return (int)leaf1->sym - (int)leaf2->sym;
	else
		return freq_diff;
}

/* Comparator function for HuffmanLeafNodes.  Sorts primarily by code length and
 * secondarily by symbol value. */
static int cmp_leaves_by_code_len(const void *__leaf1, const void *__leaf2)
{
	const HuffmanLeafNode *leaf1 = __leaf1;
	const HuffmanLeafNode *leaf2 = __leaf2;

	int code_len_diff = (int)leaf1->path_len - (int)leaf2->path_len;

	if (code_len_diff == 0)
		return (int)leaf1->sym - (int)leaf2->sym;
	else
		return code_len_diff;
}

/* Recursive function to calculate the depth of the leaves in a Huffman tree.
 * */
static void huffman_tree_compute_path_lengths(HuffmanNode *node, u16 cur_len)
{
	if (node->sym == (u16)(-1)) {
		/* Intermediate node. */
		huffman_tree_compute_path_lengths(node->left_child, cur_len + 1);
		huffman_tree_compute_path_lengths(node->right_child, cur_len + 1);
	} else {
		/* Leaf node. */
		node->path_len = cur_len;
	}
}

/* Creates a canonical Huffman code from an array of symbol frequencies. 
 *
 * The algorithm used is similar to the well-known algorithm that builds a
 * Huffman tree using a minheap.  In that algorithm, the leaf nodes are
 * initialized and inserted into the minheap with the frequency as the key.
 * Repeatedly, the top two nodes (nodes with the lowest frequency) are taken out
 * of the heap and made the children of a new node that has a frequency equal to
 * the sum of the two frequencies of its children.  This new node is inserted
 * into the heap.  When all the nodes have been removed from the heap, what
 * remains is the Huffman tree. The Huffman code for a symbol is given by the
 * path to it in the tree, where each left pointer is mapped to a 0 bit and each
 * right pointer is mapped to a 1 bit.
 *
 * The algorithm used here uses an optimization that removes the need to
 * actually use a heap.  The leaf nodes are first sorted by frequency, as
 * opposed to being made into a heap.  Note that this sorting step takes O(n log
 * n) time vs.  O(n) time for heapifying the array, where n is the number of
 * symbols.  However, the heapless method is probably faster overall, due to the
 * time saved later.  In the heapless method, whenever an intermediate node is
 * created, it is not inserted into the sorted array.  Instead, the intermediate
 * nodes are kept in a separate array, which is easily kept sorted because every
 * time an intermediate node is initialized, it will have a frequency at least
 * as high as that of the previous intermediate node that was initialized.  So
 * whenever we want the 2 nodes, leaf or intermediate, that have the lowest
 * frequency, we check the low-frequency ends of both arrays, which is an O(1)
 * operation.
 *
 * The function builds a canonical Huffman code, not just any Huffman code.  A
 * Huffman code is canonical if the codeword for each symbol numerically
 * precedes the codeword for all other symbols of the same length that are
 * numbered higher than the symbol, and additionally, all shorter codewords,
 * 0-extended, numerically precede longer codewords.  A canonical Huffman code
 * is useful because it can be reconstructed by only knowing the path lengths in
 * the tree.  See the make_huffman_decode_table() function to see how to
 * reconstruct a canonical Huffman code from only the lengths of the codes.
 *
 * @num_syms:  The number of symbols in the alphabet.
 *
 * @max_codeword_len:  The maximum allowed length of a codeword in the code.
 * 			Note that if the code being created runs up against
 * 			this restriction, the code ultimately created will be
 * 			suboptimal, although there are some advantages for
 * 			limiting the length of the codewords.
 *
 * @freq_tab:  An array of length @num_syms that contains the frequencies
 * 			of each symbol in the uncompressed data.
 *
 * @lens:	   An array of length @num_syms into which the lengths of the
 * 			codewords for each symbol will be written.
 *
 * @codewords:	   An array of @num_syms short integers into which the
 * 			codewords for each symbol will be written.  The first 
 * 			lens[i] bits of codewords[i] will contain the codeword 
 * 			for symbol i.
 */
void make_canonical_huffman_code(uint num_syms, uint max_codeword_len, 
				 const u32 freq_tab[], u8 lens[], 
				 u16 codewords[])
{
	/* We require at least 2 possible symbols in the alphabet to produce a
	 * valid Huffman decoding table. It is allowed that fewer than 2 symbols
	 * are actually used, though. */
	wimlib_assert(num_syms >= 2);

	/* Initialize the lengths and codewords to 0 */
	memset(lens, 0, num_syms * sizeof(lens[0]));
	memset(codewords, 0, num_syms * sizeof(codewords[0]));

	/* Calculate how many symbols have non-zero frequency.  These are the
	 * symbols that actually appeared in the input. */
	uint num_used_symbols = 0;
	for (uint i = 0; i < num_syms; i++)
		if (freq_tab[i] != 0)
			num_used_symbols++;


	/* It is impossible to make a code for num_used_symbols symbols if there
	 * aren't enough code bits to uniquely represent all of them. */
	wimlib_assert((1 << max_codeword_len) > num_used_symbols);

	/* Initialize the array of leaf nodes with the symbols and their
	 * frequencies. */
	HuffmanLeafNode leaves[num_used_symbols];
	uint leaf_idx = 0;
	for (uint i = 0; i < num_syms; i++) {
		if (freq_tab[i] != 0) {
			leaves[leaf_idx].freq = freq_tab[i];
			leaves[leaf_idx].sym  = i;
			leaves[leaf_idx].height = 0;
			leaf_idx++;
		}
	}

	/* Deal with the special cases where num_used_symbols < 2. */
	if (num_used_symbols < 2) {
		if (num_used_symbols == 0) {
			/* If num_used_symbols is 0, there are no symbols in the
			 * input, so it must be empty.  This should be an error,
			 * but the LZX format expects this case to succeed.  All
			 * the codeword lengths are simply marked as 0 (which
			 * was already done.) */
		} else {
			/* If only one symbol is present, the LZX format
			 * requires that the Huffman code include two codewords.
			 * One is not used.  Note that this doesn't make the
			 * encoded data take up more room anyway, since binary
			 * data itself has 2 symbols. */

			uint sym = leaves[0].sym;

			codewords[0] = 0;
			lens[0]      = 1;
			if (sym == 0) {
				/* dummy symbol is 1, real symbol is 0 */
				codewords[1] = 1;
				lens[1]      = 1;
			} else {
				/* dummy symbol is 0, real symbol is sym */
				codewords[sym] = 1;
				lens[sym]      = 1;
			}
		}
		return;
	}

	/* Otherwise, there are at least 2 symbols in the input, so we need to
	 * find a real Huffman code. */


	/* Declare the array of intermediate nodes.  An intermediate node is not
	 * associated with a symbol. Instead, it represents some binary code
	 * prefix that is shared between at least 2 codewords.  There can be at
	 * most num_used_symbols - 1 intermediate nodes when creating a Huffman
	 * code.  This is because if there were at least num_used_symbols nodes,
	 * the code would be suboptimal because there would be at least one
	 * unnecessary intermediate node.  
	 *
	 * The worst case (greatest number of intermediate nodes) would be if
	 * all the intermediate nodes were chained together.  This results in
	 * num_used_symbols - 1 intermediate nodes.  If num_used_symbols is at
	 * least 17, this configuration would not be allowed because the LZX
	 * format constrains codes to 16 bits or less each.  However, it is
	 * still possible for there to be more than 16 intermediate nodes, as
	 * long as no leaf has a depth of more than 16.  */
	HuffmanNode inodes[num_used_symbols - 1];


	/* Pointer to the leaf node of lowest frequency that hasn't already been
	 * added as the child of some intermediate note. */
	HuffmanLeafNode *cur_leaf = &leaves[0];

	/* Pointer past the end of the array of leaves. */
	HuffmanLeafNode *end_leaf = &leaves[num_used_symbols];

	/* Pointer to the intermediate node of lowest frequency. */
	HuffmanNode     *cur_inode = &inodes[0];

	/* Pointer to the next unallocated intermediate node. */
	HuffmanNode     *next_inode = &inodes[0];

	/* Only jump back to here if the maximum length of the codewords allowed
	 * by the LZX format (16 bits) is exceeded. */
try_building_tree_again:

	/* Sort the leaves from those that correspond to the least frequent
	 * symbol, to those that correspond to the most frequent symbol.  If two
	 * leaves have the same frequency, they are sorted by symbol. */
	qsort(leaves, num_used_symbols, sizeof(leaves[0]), cmp_leaves_by_freq);

	cur_leaf   = &leaves[0];
	cur_inode  = &inodes[0];
	next_inode = &inodes[0];

	/* The following loop takes the two lowest frequency nodes of those
	 * remaining and makes them the children of the next available
	 * intermediate node.  It continues until all the leaf nodes and
	 * intermediate nodes have been used up, or the maximum allowed length
	 * for the codewords is exceeded.  For the latter case, we must adjust
	 * the frequencies to be more equal and then execute this loop again. */
	while (1) {

		/* Lowest frequency node. */
		HuffmanNode *f1 = NULL; 

		/* Second lowest frequency node. */
		HuffmanNode *f2 = NULL;

		/* Get the lowest and second lowest frequency nodes from
		 * the remaining leaves or from the intermediate nodes.
		 * */

		if (cur_leaf != end_leaf && (cur_inode == next_inode || 
					cur_leaf->freq <= cur_inode->freq)) {
			f1 = (HuffmanNode*)cur_leaf++;
		} else if (cur_inode != next_inode) {
			f1 = cur_inode++;
		}

		if (cur_leaf != end_leaf && (cur_inode == next_inode || 
					cur_leaf->freq <= cur_inode->freq)) {
			f2 = (HuffmanNode*)cur_leaf++;
		} else if (cur_inode != next_inode) {
			f2 = cur_inode++;
		}

		/* All nodes used up! */
		if (f1 == NULL || f2 == NULL)
			break;

		/* next_inode becomes the parent of f1 and f2. */

		next_inode->freq   = f1->freq + f2->freq;
		next_inode->sym    = (u16)(-1); /* Invalid symbol. */
		next_inode->left_child   = f1;
		next_inode->right_child  = f2;

		/* We need to keep track of the height so that we can detect if
		 * the length of a codeword has execeed max_codeword_len.   The
		 * parent node has a height one higher than the maximum height
		 * of its children. */
		next_inode->height = max(f1->height, f2->height) + 1;

		/* Check to see if the code length of the leaf farthest away
		 * from next_inode has exceeded the maximum code length. */
		if (next_inode->height > max_codeword_len) {
			/* The code lengths can be made more uniform by making
			 * the frequencies more uniform.  Divide all the
			 * frequencies by 2, leaving 1 as the minimum frequency.
			 * If this keeps happening, the symbol frequencies will
			 * approach equality, which makes their Huffman
			 * codewords approach the length
			 * log_2(num_used_symbols).
			 * */
			for (uint i = 0; i < num_used_symbols; i++)
				if (leaves[i].freq > 1)
					leaves[i].freq >>= 1;
			goto try_building_tree_again;
		} 
		next_inode++;
	}

	/* The Huffman tree is now complete, and its height is no more than
	 * max_codeword_len.  */

	HuffmanNode *root = next_inode - 1;
	wimlib_assert(root->height <= max_codeword_len);

	/* Compute the path lengths for the leaf nodes. */
	huffman_tree_compute_path_lengths(root, 0);

	/* Sort the leaf nodes primarily by code length and secondarily by
	 * symbol.  */
	qsort(leaves, num_used_symbols, sizeof(leaves[0]), cmp_leaves_by_code_len);

	u16 cur_codeword = 0;
	uint cur_codeword_len = 0;
	for (uint i = 0; i < num_used_symbols; i++) {

		/* Each time a codeword becomes one longer, the current codeword
		 * is left shifted by one place.  This is part of the procedure
		 * for enumerating the canonical Huffman code.  Additionally,
		 * whenever a codeword is used, 1 is added to the current
		 * codeword.  */

		uint len_diff = leaves[i].path_len - cur_codeword_len;
		cur_codeword <<= len_diff;
		cur_codeword_len += len_diff;

		u16 sym = leaves[i].sym;
		codewords[sym] = cur_codeword;
		lens[sym] = cur_codeword_len;

		cur_codeword++;
	}
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
						"pos = %u, num_entries = %u\n",
						decode_table_pos, 
						table_num_entries);
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
				ERROR("Invalid canonical Huffman code!\n");
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
				ERROR("Lengths do not form a valid "
						"canonical Huffman tree "
						"(only filled %u of %u decode "
						"table slots)!\n", decode_table_pos, 
						table_num_entries);
				return 1;
			}
		}
	}
	return 0;
}

/* Reads a Huffman-encoded symbol when it is known there are less than
 * MAX_CODE_LEN bits remaining in the bitstream. */
int NOINLINE COLD
read_huffsym_near_end_of_input(struct input_bitstream *istream, 
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
				ERROR("Input stream exhausted!\n");
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
