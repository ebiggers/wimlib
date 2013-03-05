/*
 * compress.c
 *
 * Functions used for compression.
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

#include "compress.h"
#include <stdlib.h>
#include <string.h>

static inline void flush_bits(struct output_bitstream *ostream)
{
	*(u16*)ostream->bit_output = cpu_to_le16(ostream->bitbuf);
	ostream->bit_output = ostream->next_bit_output;
	ostream->next_bit_output = ostream->output;
	ostream->output += 2;
	ostream->num_bytes_remaining -= 2;
}

/* Writes @num_bits bits, given by the @num_bits least significant bits of
 * @bits, to the output @ostream. */
int bitstream_put_bits(struct output_bitstream *ostream, output_bitbuf_t bits,
		       unsigned num_bits)
{
	unsigned rem_bits;

	wimlib_assert(num_bits <= 16);
	if (num_bits <= ostream->free_bits) {
		ostream->bitbuf = (ostream->bitbuf << num_bits) | bits;
		ostream->free_bits -= num_bits;
	} else {

		if (ostream->num_bytes_remaining + (ostream->output -
						ostream->bit_output) < 2)
			return 1;

		/* It is tricky to output the bits correctly.  The correct way
		 * is to output little-endian 2-byte words, such that the bits
		 * in the SECOND byte logically precede those in the FIRST byte.
		 * While the byte order is little-endian, the bit order is
		 * big-endian; the first bit in a byte is the high-order one.
		 * Any multi-bit numbers are in bit-big-endian form, so the
		 * low-order bit of a multi-bit number is the LAST bit to be
		 * output. */
		rem_bits = num_bits - ostream->free_bits;
		ostream->bitbuf <<= ostream->free_bits;
		ostream->bitbuf |= bits >> rem_bits;
		flush_bits(ostream);
		ostream->free_bits = 16 - rem_bits;
		ostream->bitbuf = bits;

	}
	return 0;
}

/* Flushes any remaining bits in the output buffer to the output byte stream. */
int flush_output_bitstream(struct output_bitstream *ostream)
{
	if (ostream->num_bytes_remaining + (ostream->output -
					ostream->bit_output) < 2)
		return 1;
	if (ostream->free_bits != 16) {
		ostream->bitbuf <<= ostream->free_bits;
		flush_bits(ostream);
	}
	return 0;
}

/* Initializes an output bit buffer to write its output to the memory location
 * pointer to by @data. */
void init_output_bitstream(struct output_bitstream *ostream, void *data,
			   unsigned num_bytes)
{
	wimlib_assert(num_bytes >= 4);

	ostream->bitbuf              = 0;
	ostream->free_bits           = 16;
	ostream->bit_output          = (u8*)data;
	ostream->next_bit_output     = (u8*)data + 2;
	ostream->output              = (u8*)data + 4;
	ostream->num_bytes_remaining = num_bytes - 4;
}

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

/* make_canonical_huffman_code: - Creates a canonical Huffman code from an array
 *				  of symbol frequencies.
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
void make_canonical_huffman_code(unsigned num_syms, unsigned max_codeword_len,
				 const freq_t freq_tab[], u8 lens[],
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
	unsigned num_used_symbols = 0;
	for (unsigned i = 0; i < num_syms; i++)
		if (freq_tab[i] != 0)
			num_used_symbols++;


	/* It is impossible to make a code for num_used_symbols symbols if there
	 * aren't enough code bits to uniquely represent all of them. */
	wimlib_assert((1 << max_codeword_len) > num_used_symbols);

	/* Initialize the array of leaf nodes with the symbols and their
	 * frequencies. */
	HuffmanLeafNode leaves[num_used_symbols];
	unsigned leaf_idx = 0;
	for (unsigned i = 0; i < num_syms; i++) {
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

			unsigned sym = leaves[0].sym;

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
	HuffmanLeafNode *cur_leaf;

	/* Pointer past the end of the array of leaves. */
	HuffmanLeafNode *end_leaf = &leaves[num_used_symbols];

	/* Pointer to the intermediate node of lowest frequency. */
	HuffmanNode     *cur_inode;

	/* Pointer to the next unallocated intermediate node. */
	HuffmanNode     *next_inode;

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
		HuffmanNode *f1;

		/* Second lowest frequency node. */
		HuffmanNode *f2;

		/* Get the lowest and second lowest frequency nodes from the
		 * remaining leaves or from the intermediate nodes. */

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
		} else {
			/* All nodes used up! */
			break;
		}

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
			for (unsigned i = 0; i < num_used_symbols; i++)
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
	unsigned cur_codeword_len = 0;
	for (unsigned i = 0; i < num_used_symbols; i++) {

		/* Each time a codeword becomes one longer, the current codeword
		 * is left shifted by one place.  This is part of the procedure
		 * for enumerating the canonical Huffman code.  Additionally,
		 * whenever a codeword is used, 1 is added to the current
		 * codeword.  */

		unsigned len_diff = leaves[i].path_len - cur_codeword_len;
		cur_codeword <<= len_diff;
		cur_codeword_len += len_diff;

		u16 sym = leaves[i].sym;
		codewords[sym] = cur_codeword;
		lens[sym] = cur_codeword_len;

		cur_codeword++;
	}
}
