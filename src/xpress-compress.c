/*
 * xpress-compress.c
 *
 * A compressor that produces output compatible with the XPRESS (Huffman
 * version) compression format.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/compress_common.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lz_mf.h"
#include "wimlib/util.h"
#include "wimlib/xpress.h"

#include <string.h>
#include <limits.h>

#define XPRESS_CACHE_PER_POS		8
#define XPRESS_OPTIM_ARRAY_LENGTH	4096

struct xpress_compressor;
struct xpress_item;
struct xpress_mc_pos_data;

/* Internal compression parameters  */
struct xpress_compressor_params {

	/* See xpress_choose_items()  */
	u32 (*choose_items_func)(struct xpress_compressor *);

	/* For near-optimal parsing only  */
	u32 num_optim_passes;

	/* Match-finding algorithm and parameters  */
	enum lz_mf_algo mf_algo;
	u32 max_search_depth;
	u32 nice_match_length;
};

/* State of the XPRESS compressor  */
struct xpress_compressor {

	/* Internal compression parameters  */
	struct xpress_compressor_params params;

	/* Data currently being compressed  */
	const u8 *cur_window;
	u32 cur_window_size;

	/* Lempel-Ziv match-finder  */
	struct lz_mf *mf;

	/* Optimal parsing data  */
	unsigned (*get_matches_func)(struct xpress_compressor *,
				     const struct lz_match **);
	void (*skip_bytes_func)(struct xpress_compressor *, unsigned n);
	struct lz_match *cached_matches;
	struct lz_match *cache_ptr;
	struct lz_match *cache_limit;
	struct xpress_mc_pos_data *optimum;
	u8 costs[XPRESS_NUM_SYMBOLS];

	/* The selected sequence of matches/literals  */
	struct xpress_item *chosen_items;

	/* Symbol frequency counters  */
	u32 freqs[XPRESS_NUM_SYMBOLS];

	/* The current Huffman code  */
	u32 codewords[XPRESS_NUM_SYMBOLS];
	u8 lens[XPRESS_NUM_SYMBOLS];
};

/* Intermediate XPRESS match/literal format  */
struct xpress_item {

	/* Bits 0  -  8: Symbol
	 * Bits 9  - 24: Length - XPRESS_MIN_MATCH_LEN
	 * Bits 25 - 28: Number of extra offset bits
	 * Bits 29+    : Extra offset bits  */

	u64 data;
};

/*
 * Match chooser position data:
 *
 * An array of these structures is used during the near-optimal match-choosing
 * algorithm.  They correspond to consecutive positions in the window and are
 * used to keep track of the cost to reach each position, and the match/literal
 * choices that need to be chosen to reach that position.
 */
struct xpress_mc_pos_data {

	/* The cost, in bits, of the lowest-cost path that has been found to
	 * reach this position.  This can change as progressively lower cost
	 * paths are found to reach this position.  */
	u32 cost;
#define MC_INFINITE_COST UINT32_MAX

	/* The match or literal that was taken to reach this position.  This can
	 * change as progressively lower cost paths are found to reach this
	 * position.
	 *
	 * This variable is divided into two bitfields.
	 *
	 * Literals:
	 *	Low bits are 1, high bits are the literal.
	 *
	 * Matches:
	 *	Low bits are the match length, high bits are the offset.
	 */
	u32 mc_item_data;
#define MC_OFFSET_SHIFT 16
#define MC_LEN_MASK (((u32)1 << MC_OFFSET_SHIFT) - 1)
};


/*
 * Structure to keep track of the current state of sending data to the
 * compressed output buffer.
 *
 * The XPRESS bitstream is encoded as a sequence of little endian 16-bit coding
 * units interwoven with literal bytes.
 */
struct xpress_output_bitstream {

	/* Bits that haven't yet been written to the output buffer.  */
	u32 bitbuf;

	/* Number of bits currently held in @bitbuf.  */
	u32 bitcount;

	/* Pointer to the start of the output buffer.  */
	u8 *start;

	/* Pointer to the location in the ouput buffer at which to write the
	 * next 16 bits.  */
	u8 *next_bits;

	/* Pointer to the location in the output buffer at which to write the
	 * next 16 bits, after @next_bits.  */
	u8 *next_bits2;

	/* Pointer to the location in the output buffer at which to write the
	 * next literal byte.  */
	u8 *next_byte;

	/* Pointer to the end of the output buffer.  */
	u8 *end;
};

/*
 * Initialize the output bitstream.
 *
 * @os
 *	The output bitstream structure to initialize.
 * @buffer
 *	The buffer to write to.
 * @size
 *	Size of @buffer, in bytes.  Must be at least 4.
 */
static void
xpress_init_output(struct xpress_output_bitstream *os, void *buffer, u32 size)
{
	os->bitbuf = 0;
	os->bitcount = 0;
	os->start = buffer;
	os->next_bits = os->start;
	os->next_bits2 = os->start + 2;
	os->next_byte = os->start + 4;
	os->end = os->start + size;
}

/*
 * Write some bits to the output bitstream.
 *
 * The bits are given by the low-order @num_bits bits of @bits.  Higher-order
 * bits in @bits cannot be set.  At most 16 bits can be written at once.
 *
 * If the output buffer space is exhausted, then the bits will be ignored, and
 * xpress_flush_output() will return 0 when it gets called.
 */
static inline void
xpress_write_bits(struct xpress_output_bitstream *os,
		  const u32 bits, const unsigned int num_bits)
{
	/* This code is optimized for XPRESS, which never needs to write more
	 * than 16 bits at once.  */

	os->bitcount += num_bits;
	os->bitbuf = (os->bitbuf << num_bits) | bits;

	if (os->bitcount > 16) {
		os->bitcount -= 16;
		if (os->end - os->next_byte >= 2) {
			*(le16 *)os->next_bits = cpu_to_le16(os->bitbuf >> os->bitcount);
			os->next_bits = os->next_bits2;
			os->next_bits2 = os->next_byte;
			os->next_byte += 2;
		}
	}
}

/*
 * Interweave a literal byte into the output bitstream.
 */
static inline void
xpress_write_byte(struct xpress_output_bitstream *os, u8 byte)
{
	if (os->next_byte < os->end)
		*os->next_byte++ = byte;
}

/*
 * Flush the last coding unit to the output buffer if needed.  Return the total
 * number of bytes written to the output buffer, or 0 if an overflow occurred.
 */
static u32
xpress_flush_output(struct xpress_output_bitstream *os)
{
	if (unlikely(os->end - os->next_byte < 2))
		return 0;

	*(le16 *)os->next_bits = cpu_to_le16(os->bitbuf << (16 - os->bitcount));
	*(le16 *)os->next_bits2 = cpu_to_le16(0);

	return os->next_byte - os->start;
}

/* Output a match or literal.  */
static inline void
xpress_write_item(struct xpress_item item, struct xpress_output_bitstream *os,
		  const u32 codewords[], const u8 lens[])
{
	u64 data = item.data;
	unsigned symbol;
	unsigned adjusted_len;
	unsigned num_extra_bits;
	unsigned extra_bits;

	symbol = data & 0x1FF;

	xpress_write_bits(os, codewords[symbol], lens[symbol]);

	if (symbol < XPRESS_NUM_CHARS)  /* Literal?  */
		return;

	adjusted_len = (data >> 9) & 0xFFFF;

	/* If length >= 18, one extra length byte.
	 * If length >= 273, three (total) extra length bytes.  */
	if (adjusted_len >= 0xf) {
		u8 byte1 = min(adjusted_len - 0xf, 0xff);
		xpress_write_byte(os, byte1);
		if (byte1 == 0xff) {
			xpress_write_byte(os, adjusted_len & 0xff);
			xpress_write_byte(os, adjusted_len >> 8);
		}
	}

	num_extra_bits = (data >> 25) & 0xF;
	extra_bits = data >> 29;

	xpress_write_bits(os, extra_bits, num_extra_bits);
}

/* Output a sequence of XPRESS matches and literals.  */
static void
xpress_write_items(struct xpress_output_bitstream *os,
		   const struct xpress_item items[], u32 num_items,
		   const u32 codewords[], const u8 lens[])
{
	for (u32 i = 0; i < num_items; i++)
		xpress_write_item(items[i], os, codewords, lens);

	/* End-of-data symbol (required for MS compatibility)  */
	xpress_write_bits(os, codewords[XPRESS_END_OF_DATA], lens[XPRESS_END_OF_DATA]);
}

/* Make the Huffman code for XPRESS.
 *
 * Takes as input c->freqs and produces as output c->lens and c->codewords.  */
static void
xpress_make_huffman_code(struct xpress_compressor *c)
{
	make_canonical_huffman_code(XPRESS_NUM_SYMBOLS, XPRESS_MAX_CODEWORD_LEN,
				    c->freqs, c->lens, c->codewords);
}

/* Tally, and optionally record, the specified literal byte.  */
static inline void
xpress_declare_literal(struct xpress_compressor *c, unsigned literal,
		       struct xpress_item **next_chosen_item)
{
	c->freqs[literal]++;

	if (next_chosen_item) {
		*(*next_chosen_item)++ = (struct xpress_item) {
			.data = literal,
		};
	}
}

/* Tally, and optionally record, the specified match.  */
static inline void
xpress_declare_match(struct xpress_compressor *c,
		     unsigned len, unsigned offset,
		     struct xpress_item **next_chosen_item)
{
	unsigned adjusted_len = len - XPRESS_MIN_MATCH_LEN;
	unsigned len_hdr = min(adjusted_len, 0xf);
	unsigned offset_bsr = bsr32(offset);
	unsigned sym = XPRESS_NUM_CHARS + ((offset_bsr << 4) | len_hdr);

	c->freqs[sym]++;

	if (next_chosen_item) {
		*(*next_chosen_item)++ = (struct xpress_item) {
			.data = (u64)sym |
				((u64)adjusted_len << 9) |
				((u64)offset_bsr << 25) |
				((u64)(offset ^ (1U << offset_bsr)) << 29),
		};
	}
}

/* Tally, and optionally record, the specified match or literal.  */
static inline void
xpress_declare_item(struct xpress_compressor *c, u32 mc_item_data,
		    struct xpress_item **next_chosen_item)
{
	unsigned len = mc_item_data & MC_LEN_MASK;
	unsigned offset_data = mc_item_data >> MC_OFFSET_SHIFT;

	if (len == 1)
		xpress_declare_literal(c, offset_data, next_chosen_item);
	else
		xpress_declare_match(c, len, offset_data, next_chosen_item);
}

static inline void
xpress_record_item_list(struct xpress_compressor *c,
			struct xpress_mc_pos_data *cur_optimum_ptr,
			struct xpress_item **next_chosen_item)
{
	struct xpress_mc_pos_data *end_optimum_ptr;
	u32 saved_item;
	u32 item;

	/* The list is currently in reverse order (last item to first item).
	 * Reverse it.  */
	end_optimum_ptr = cur_optimum_ptr;
	saved_item = cur_optimum_ptr->mc_item_data;
	do {
		item = saved_item;
		cur_optimum_ptr -= item & MC_LEN_MASK;
		saved_item = cur_optimum_ptr->mc_item_data;
		cur_optimum_ptr->mc_item_data = item;
	} while (cur_optimum_ptr != c->optimum);

	/* Walk the list of items from beginning to end, tallying and recording
	 * each item.  */
	do {
		xpress_declare_item(c, cur_optimum_ptr->mc_item_data, next_chosen_item);
		cur_optimum_ptr += (cur_optimum_ptr->mc_item_data) & MC_LEN_MASK;
	} while (cur_optimum_ptr != end_optimum_ptr);
}

static inline void
xpress_tally_item_list(struct xpress_compressor *c,
		       struct xpress_mc_pos_data *cur_optimum_ptr)
{
	/* Since we're just tallying the items, we don't need to reverse the
	 * list.  Processing the items in reverse order is fine.  */
	do {
		xpress_declare_item(c, cur_optimum_ptr->mc_item_data, NULL);
		cur_optimum_ptr -= (cur_optimum_ptr->mc_item_data & MC_LEN_MASK);
	} while (cur_optimum_ptr != c->optimum);
}

/* Tally, and optionally (if next_chosen_item != NULL) record, in order, all
 * items in the current list of items found by the match-chooser.  */
static void
xpress_declare_item_list(struct xpress_compressor *c,
			 struct xpress_mc_pos_data *cur_optimum_ptr,
			 struct xpress_item **next_chosen_item)
{
	if (next_chosen_item)
		xpress_record_item_list(c, cur_optimum_ptr, next_chosen_item);
	else
		xpress_tally_item_list(c, cur_optimum_ptr);
}

static unsigned
xpress_get_matches_fillcache(struct xpress_compressor *c,
			     const struct lz_match **matches_ret)
{
	struct lz_match *cache_ptr;
	struct lz_match *matches;
	unsigned num_matches;

	cache_ptr = c->cache_ptr;
	matches = cache_ptr + 1;
	if (likely(cache_ptr <= c->cache_limit)) {
		num_matches = lz_mf_get_matches(c->mf, matches);
		cache_ptr->len = num_matches;
		c->cache_ptr = matches + num_matches;
	} else {
		num_matches = 0;
	}
	*matches_ret = matches;
	return num_matches;
}

static unsigned
xpress_get_matches_usecache(struct xpress_compressor *c,
			    const struct lz_match **matches_ret)
{
	struct lz_match *cache_ptr;
	struct lz_match *matches;
	unsigned num_matches;

	cache_ptr = c->cache_ptr;
	matches = cache_ptr + 1;
	if (cache_ptr <= c->cache_limit) {
		num_matches = cache_ptr->len;
		c->cache_ptr = matches + num_matches;
	} else {
		num_matches = 0;
	}
	*matches_ret = matches;
	return num_matches;
}

static unsigned
xpress_get_matches_usecache_nocheck(struct xpress_compressor *c,
				    const struct lz_match **matches_ret)
{
	struct lz_match *cache_ptr;
	struct lz_match *matches;
	unsigned num_matches;

	cache_ptr = c->cache_ptr;
	matches = cache_ptr + 1;
	num_matches = cache_ptr->len;
	c->cache_ptr = matches + num_matches;
	*matches_ret = matches;
	return num_matches;
}

static unsigned
xpress_get_matches_noncaching(struct xpress_compressor *c,
			      const struct lz_match **matches_ret)
{
	*matches_ret = c->cached_matches;
	return lz_mf_get_matches(c->mf, c->cached_matches);
}

/*
 * Find matches at the next position in the window.
 *
 * This uses a wrapper function around the underlying match-finder.
 *
 * Returns the number of matches found and sets *matches_ret to point to the
 * matches array.  The matches will be sorted by strictly increasing length and
 * offset.
 */
static inline unsigned
xpress_get_matches(struct xpress_compressor *c,
		   const struct lz_match **matches_ret)
{
	return (*c->get_matches_func)(c, matches_ret);
}

static void
xpress_skip_bytes_fillcache(struct xpress_compressor *c, unsigned n)
{
	struct lz_match *cache_ptr;

	cache_ptr = c->cache_ptr;
	lz_mf_skip_positions(c->mf, n);
	if (cache_ptr <= c->cache_limit) {
		do {
			cache_ptr->len = 0;
			cache_ptr += 1;
		} while (--n && likely(cache_ptr <= c->cache_limit));
	}
	c->cache_ptr = cache_ptr;
}

static void
xpress_skip_bytes_usecache(struct xpress_compressor *c, unsigned n)
{
	struct lz_match *cache_ptr;

	cache_ptr = c->cache_ptr;
	if (likely(cache_ptr <= c->cache_limit)) {
		do {
			cache_ptr += 1 + cache_ptr->len;
		} while (--n && likely(cache_ptr <= c->cache_limit));
	}
	c->cache_ptr = cache_ptr;
}

static void
xpress_skip_bytes_usecache_nocheck(struct xpress_compressor *c, unsigned n)
{
	struct lz_match *cache_ptr;

	cache_ptr = c->cache_ptr;
	do {
		cache_ptr += 1 + cache_ptr->len;
	} while (--n);
	c->cache_ptr = cache_ptr;
}

static void
xpress_skip_bytes_noncaching(struct xpress_compressor *c, unsigned n)
{
	lz_mf_skip_positions(c->mf, n);
}

/*
 * Skip the specified number of positions in the window (don't search for
 * matches at them).
 *
 * This uses a wrapper function around the underlying match-finder.
 */
static inline void
xpress_skip_bytes(struct xpress_compressor *c, unsigned n)
{
	return (*c->skip_bytes_func)(c, n);
}

/* Set default XPRESS Huffman symbol costs to bootstrap the iterative
 * optimization algorithm.  */
static void
xpress_set_default_costs(u8 costs[])
{
	unsigned i;

	/* Literal symbols  */
	for (i = 0; i < XPRESS_NUM_CHARS; i++)
		costs[i] = 8;

	/* Match symbols  */
	for (; i < XPRESS_NUM_SYMBOLS; i++)
		costs[i] = 10;
}

/* Copy the Huffman codeword lengths array @lens to the Huffman symbol costs
 * array @costs, but also assign a default cost to each 0-length (unused)
 * codeword.  */
static void
xpress_set_costs(u8 costs[], const u8 lens[])
{
	for (unsigned i = 0; i < XPRESS_NUM_SYMBOLS; i++)
		costs[i] = lens[i] ? lens[i] : XPRESS_MAX_CODEWORD_LEN;
}

/*
 * Consider coding each match in @matches.
 *
 * @matches must be sorted by strictly increasing length and strictly
 * increasing offset.  This is guaranteed by the match-finder.
 *
 * We consider each length from the minimum (3) to the longest
 * (matches[num_matches - 1].len).  For each length, we consider only
 * the smallest offset for which that length is available.  Although
 * this is not guaranteed to be optimal due to the possibility of a
 * larger offset costing less than a smaller offset to code, this is a
 * very useful heuristic.
 */
static inline void
xpress_consider_matches(struct xpress_compressor *c,
			struct xpress_mc_pos_data *cur_optimum_ptr,
			const struct lz_match matches[],
			unsigned num_matches)
{
	unsigned i = 0;
	unsigned len = XPRESS_MIN_MATCH_LEN;
	u32 cost;
	u32 position_cost;
	unsigned offset;
	unsigned offset_bsr;
	unsigned adjusted_len;
	unsigned len_hdr;
	unsigned sym;

	if (matches[num_matches - 1].len < 0xf + XPRESS_MIN_MATCH_LEN) {
		/* All lengths are small.  Optimize accordingly.  */
		do {
			offset = matches[i].offset;
			offset_bsr = bsr32(offset);
			len_hdr = len - XPRESS_MIN_MATCH_LEN;
			sym = XPRESS_NUM_CHARS + ((offset_bsr << 4) | len_hdr);

			position_cost = cur_optimum_ptr->cost + offset_bsr;
			do {
				cost = position_cost + c->costs[sym];
				if (cost < (cur_optimum_ptr + len)->cost) {
					(cur_optimum_ptr + len)->cost = cost;
					(cur_optimum_ptr + len)->mc_item_data =
						(offset << MC_OFFSET_SHIFT) | len;
				}
				sym++;
			} while (++len <= matches[i].len);
		} while (++i != num_matches);
	} else {
		/* Some lengths are big.  */
		do {
			offset = matches[i].offset;
			offset_bsr = bsr32(offset);
			position_cost = cur_optimum_ptr->cost + offset_bsr;
			do {
				adjusted_len = len - XPRESS_MIN_MATCH_LEN;
				len_hdr = min(adjusted_len, 0xf);
				sym = XPRESS_NUM_CHARS + ((offset_bsr << 4) | len_hdr);

				cost = position_cost + c->costs[sym];
				if (adjusted_len >= 0xf) {
					cost += 8;
					if (adjusted_len - 0xf >= 0xff)
						cost += 16;
				}

				if (cost < (cur_optimum_ptr + len)->cost) {
					(cur_optimum_ptr + len)->cost = cost;
					(cur_optimum_ptr + len)->mc_item_data =
						(offset << MC_OFFSET_SHIFT) | len;
				}
			} while (++len <= matches[i].len);
		} while (++i != num_matches);
	}
}

/*
 * The main near-optimal parsing routine.
 *
 * Briefly, the algorithm does an approximate minimum-cost path search to find a
 * "near-optimal" sequence of matches and literals to output, based on the
 * current cost model.  The algorithm steps forward, position by position (byte
 * by byte), and updates the minimum cost path to reach each later position that
 * can be reached using a match or literal from the current position.  This is
 * essentially Dijkstra's algorithm in disguise: the graph nodes are positions,
 * the graph edges are possible matches/literals to code, and the cost of each
 * edge is the estimated number of bits that will be required to output the
 * corresponding match or literal.  But one difference is that we actually
 * compute the lowest-cost path in pieces, where each piece is terminated when
 * there are no choices to be made.
 *
 * If next_chosen_item != NULL, then all items chosen will be recorded (saved in
 * the chosen_items array).  Otherwise, all items chosen will only be tallied
 * (symbol frequencies tallied in c->freqs).
 */
static void
xpress_optim_pass(struct xpress_compressor *c,
		  struct xpress_item **next_chosen_item)
{
	const u8 *window_end;
	const u8 *window_ptr;
	struct xpress_mc_pos_data *cur_optimum_ptr;
	struct xpress_mc_pos_data *end_optimum_ptr;
	const struct lz_match *matches;
	unsigned num_matches;
	unsigned longest_len;
	unsigned literal;
	u32 cost;

	window_ptr = c->cur_window;
	window_end = &c->cur_window[c->cur_window_size];

begin:
	/* Start building a new list of items, which will correspond to the next
	 * piece of the overall minimum-cost path.  */

	if (window_ptr == window_end)
		return;

	cur_optimum_ptr = c->optimum;
	cur_optimum_ptr->cost = 0;
	end_optimum_ptr = cur_optimum_ptr;

	/* The following loop runs once for each per byte in the window, except
	 * in a couple shortcut cases.  */
	for (;;) {

		/* Find matches with the current position.  */
		num_matches = xpress_get_matches(c, &matches);

		if (num_matches) {

			longest_len = matches[num_matches - 1].len;

			/* If there's a very long match, choose it immediately.
			 */
			if (longest_len >= c->params.nice_match_length) {

				xpress_skip_bytes(c, longest_len - 1);
				window_ptr += longest_len;

				if (cur_optimum_ptr != c->optimum)
					xpress_declare_item_list(c, cur_optimum_ptr,
								 next_chosen_item);

				xpress_declare_match(c, longest_len,
						     matches[num_matches - 1].offset,
						     next_chosen_item);
				goto begin;
			}

			/* If reaching any positions for the first time,
			 * initialize their costs to "infinity".  */
			while (end_optimum_ptr < cur_optimum_ptr + longest_len)
				(++end_optimum_ptr)->cost = MC_INFINITE_COST;

			/* Consider coding a match.  */
			xpress_consider_matches(c, cur_optimum_ptr,
						matches, num_matches);
		} else {
			/* No matches found.  The only choice at this position
			 * is to code a literal.  */

			if (end_optimum_ptr == cur_optimum_ptr) {
			#if 1
				/* Optimization for single literals.  */
				if (likely(cur_optimum_ptr == c->optimum)) {
					xpress_declare_literal(c, *window_ptr++,
							       next_chosen_item);
					if (window_ptr == window_end)
						return;
					continue;
				}
			#endif
				(++end_optimum_ptr)->cost = MC_INFINITE_COST;
			}
		}

		/* Consider coding a literal.  */
		literal = *window_ptr++;
		cost = cur_optimum_ptr->cost + c->costs[literal];
		if (cost < (cur_optimum_ptr + 1)->cost) {
			(cur_optimum_ptr + 1)->cost = cost;
			(cur_optimum_ptr + 1)->mc_item_data =
				((u32)literal << MC_OFFSET_SHIFT) | 1;
		}

		/* Advance to the next position.  */
		cur_optimum_ptr++;

		/*
		 * This loop will terminate when either of the following
		 * conditions is true:
		 *
		 * (1) cur_optimum_ptr == end_optimum_ptr
		 *
		 *	There are no paths that extend beyond the current
		 *	position.  In this case, any path to a later position
		 *	must pass through the current position, so we can go
		 *	ahead and choose the list of items that led to this
		 *	position.
		 *
		 * (2) cur_optimum_ptr == &c->optimum[XPRESS_OPTIM_ARRAY_LENGTH]
		 *
		 *	This bounds the number of times the algorithm can step
		 *	forward before it is guaranteed to start choosing items.
		 *	This limits the memory usage.  But
		 *	XPRESS_OPTIM_ARRAY_LENGTH is high enough that on most
		 *	inputs this limit is never reached.
		 *
		 * Note: no check for end-of-window is needed because
		 * end-of-window will trigger condition (1).
		 */
		if (cur_optimum_ptr == end_optimum_ptr ||
		    cur_optimum_ptr == &c->optimum[XPRESS_OPTIM_ARRAY_LENGTH])
			break;
	}

	/* Choose the current list of items that constitute the minimum-cost
	 * path to the current position.  */
	xpress_declare_item_list(c, cur_optimum_ptr, next_chosen_item);
	goto begin;
}

/* Near-optimal parsing  */
static u32
xpress_choose_near_optimal_items(struct xpress_compressor *c)
{
	u32 num_passes_remaining = c->params.num_optim_passes;
	struct xpress_item *next_chosen_item;
	struct xpress_item **next_chosen_item_ptr;

	/* Choose appropriate match-finder wrapper functions.  */
	if (c->params.num_optim_passes > 1) {
		c->get_matches_func = xpress_get_matches_fillcache;
		c->skip_bytes_func = xpress_skip_bytes_fillcache;
	} else {
		c->get_matches_func = xpress_get_matches_noncaching;
		c->skip_bytes_func = xpress_skip_bytes_noncaching;
	}

	/* The first optimization pass will use a default cost model.  Each
	 * additional optimization pass will use a cost model computed from the
	 * previous pass.
	 *
	 * To improve performance, we only generate the array containing the
	 * matches and literals in intermediate form on the final pass.  For
	 * earlier passes, tallying symbol frequencies is sufficient.  */
	xpress_set_default_costs(c->costs);

	next_chosen_item_ptr = NULL;
	do {
		/* Reset the match-finder wrapper.  */
		c->cache_ptr = c->cached_matches;

		if (num_passes_remaining == 1) {
			/* Last pass: actually generate the items.  */
			next_chosen_item = c->chosen_items;
			next_chosen_item_ptr = &next_chosen_item;
		}

		/* Choose the items.  */
		xpress_optim_pass(c, next_chosen_item_ptr);

		if (num_passes_remaining > 1) {
			/* This isn't the last pass.  */

			/* Make the Huffman code from the symbol frequencies.  */
			c->freqs[XPRESS_END_OF_DATA]++;
			xpress_make_huffman_code(c);

			/* Reset symbol frequencies.  */
			memset(c->freqs, 0, sizeof(c->freqs));

			/* Update symbol costs.  */
			xpress_set_costs(c->costs, c->lens);

			/* Choose appopriate match-finder wrapper functions.  */
			if (c->cache_ptr <= c->cache_limit) {
				c->get_matches_func = xpress_get_matches_usecache_nocheck;
				c->skip_bytes_func = xpress_skip_bytes_usecache_nocheck;
			} else {
				c->get_matches_func = xpress_get_matches_usecache;
				c->skip_bytes_func = xpress_skip_bytes_usecache;
			}
		}
	} while (--num_passes_remaining);

	/* Return the number of items chosen.  */
	return next_chosen_item - c->chosen_items;
}

/* Lazy parsing  */
static u32
xpress_choose_lazy_items(struct xpress_compressor *c)
{
	const u8 *window_ptr = c->cur_window;
	const u8 *window_end = &c->cur_window[c->cur_window_size];
	struct xpress_item *next_chosen_item = c->chosen_items;
	u32 len_3_too_far;
	struct lz_mf *mf = c->mf;
	struct lz_match *matches = c->cached_matches;
	unsigned num_matches;
	struct lz_match prev_match;

	if (c->cur_window_size <= 8192)
		len_3_too_far = 2048;
	else
		len_3_too_far = 4096;

	do {
		/* Don't have match at previous position  */

		num_matches = lz_mf_get_matches(mf, matches);
		window_ptr++;

		if (num_matches == 0 ||
		    (matches[num_matches - 1].len == 3 &&
		     matches[num_matches - 1].offset >= len_3_too_far))
		{
			/* No matches found => output literal  */
			xpress_declare_literal(c, *(window_ptr - 1),
					       &next_chosen_item);
			continue;
		}

		prev_match = matches[num_matches - 1];

	have_prev_match:
		/* Have match at previous position  */

		if (prev_match.len >= c->params.nice_match_length) {
			/* Very long match found => output immediately  */
			xpress_declare_match(c, prev_match.len,
					     prev_match.offset,
					     &next_chosen_item);
			lz_mf_skip_positions(mf, prev_match.len - 1);
			window_ptr += prev_match.len - 1;
			continue;
		}

		num_matches = lz_mf_get_matches(mf, matches);
		window_ptr++;

		if (num_matches == 0 ||
		    (matches[num_matches - 1].len <= prev_match.len))
		{
			/* Next match is not longer => output previous match  */
			xpress_declare_match(c, prev_match.len,
					     prev_match.offset,
					     &next_chosen_item);
			lz_mf_skip_positions(mf, prev_match.len - 2);
			window_ptr += prev_match.len - 2;
			continue;
		}

		/* Next match is longer => output literal  */

		xpress_declare_literal(c, *(window_ptr - 2), &next_chosen_item);

		prev_match = matches[num_matches - 1];

		goto have_prev_match;

	} while (window_ptr != window_end);

	return next_chosen_item - c->chosen_items;
}

/* Greedy parsing  */
static u32
xpress_choose_greedy_items(struct xpress_compressor *c)
{
	const u8 *window_ptr = c->cur_window;
	const u8 *window_end = &c->cur_window[c->cur_window_size];
	struct xpress_item *next_chosen_item = c->chosen_items;
	u32 len_3_too_far;
	struct lz_mf *mf = c->mf;
	struct lz_match *matches = c->cached_matches;
	unsigned num_matches;

	if (c->cur_window_size <= 8192)
		len_3_too_far = 2048;
	else
		len_3_too_far = 4096;

	do {
		/* Get longest match at the current position.  */
		num_matches = lz_mf_get_matches(mf, matches);

		if (num_matches == 0 ||
		    (matches[num_matches - 1].len == 3 &&
		     matches[num_matches - 1].offset >= len_3_too_far))
		{
			/* No match, or length 3 match with large offset.
			 * Choose a literal.  */
			xpress_declare_literal(c, *window_ptr, &next_chosen_item);
			window_ptr += 1;
		} else {
			/* Match found.  Choose it.  */
			unsigned len = matches[num_matches - 1].len;
			unsigned offset = matches[num_matches - 1].offset;

			xpress_declare_match(c, len, offset, &next_chosen_item);
			lz_mf_skip_positions(mf, len - 1);
			window_ptr += len;
		}
	} while (window_ptr != window_end);

	return next_chosen_item - c->chosen_items;
}

/* Literals-only parsing  */
static u32
xpress_choose_literals(struct xpress_compressor *c)
{
	const u8 *window_ptr = c->cur_window;
	const u8 *window_end = &c->cur_window[c->cur_window_size];
	struct xpress_item *next_chosen_item = c->chosen_items;

	do {
		xpress_declare_literal(c, *window_ptr++, &next_chosen_item);
	} while (window_ptr != window_end);

	return next_chosen_item - c->chosen_items;
}

/*
 * 'choose_items_func' is provided a data buffer c->cur_window of length
 * c->cur_window_size bytes.  This data buffer will have already been loaded
 * into the match-finder c->mf.  'choose_items_func' must choose the
 * match/literal sequence to output to represent this data buffer.  The
 * intermediate representation of this match/literal sequence must be recorded
 * in c->chosen_items, and the Huffman symbols used must be tallied in c->freqs.
 * The return value must be the number of items written to c->chosen_items.
 */
static u32
xpress_choose_items(struct xpress_compressor *c)
{
	return (*c->params.choose_items_func)(c);
}

/* Set internal compression parameters for the specified compression level and
 * maximum window size.  */
static void
xpress_build_params(unsigned int compression_level, u32 max_window_size,
		    struct xpress_compressor_params *xpress_params)
{
	memset(xpress_params, 0, sizeof(*xpress_params));
	xpress_params->num_optim_passes = 1;

	if (compression_level == 1) {

		/* Literal-only parsing  */
		xpress_params->choose_items_func = xpress_choose_literals;
		xpress_params->mf_algo = LZ_MF_NULL;

	} else if (compression_level < 30) {

		/* Greedy parsing  */
		xpress_params->choose_items_func = xpress_choose_greedy_items;
		xpress_params->mf_algo = LZ_MF_HASH_CHAINS;
		xpress_params->nice_match_length = compression_level;
		xpress_params->max_search_depth = compression_level / 2;

	} else if (compression_level < 60) {

		/* Lazy parsing  */
		xpress_params->choose_items_func = xpress_choose_lazy_items;
		xpress_params->mf_algo = LZ_MF_HASH_CHAINS;
		xpress_params->nice_match_length = compression_level;
		xpress_params->max_search_depth = compression_level / 2;

	} else {

		/* Near-optimal parsing  */
		xpress_params->choose_items_func = xpress_choose_near_optimal_items;
		if (max_window_size >= 16384)
			xpress_params->mf_algo = LZ_MF_BINARY_TREES;
		else
			xpress_params->mf_algo = LZ_MF_HASH_CHAINS;
		xpress_params->num_optim_passes = compression_level / 40;
		xpress_params->nice_match_length = min(compression_level / 2,
						       XPRESS_MAX_MATCH_LEN);
		xpress_params->max_search_depth = min(compression_level,
						      XPRESS_MAX_MATCH_LEN);
	}
}

/* Given the internal compression parameters and maximum window size, build the
 * Lempel-Ziv match-finder parameters.  */
static void
xpress_build_mf_params(const struct xpress_compressor_params *xpress_params,
		       u32 max_window_size, struct lz_mf_params *mf_params)
{
	memset(mf_params, 0, sizeof(*mf_params));

	mf_params->algorithm = xpress_params->mf_algo;
	mf_params->max_window_size = max_window_size;
	mf_params->min_match_len = XPRESS_MIN_MATCH_LEN;
	mf_params->max_match_len = XPRESS_MAX_MATCH_LEN;
	mf_params->max_search_depth = xpress_params->max_search_depth;
	mf_params->nice_match_len = xpress_params->nice_match_length;
}

static void
xpress_free_compressor(void *_c);

static u64
xpress_get_needed_memory(size_t max_window_size, unsigned int compression_level)
{
	u64 size = 0;
	struct xpress_compressor_params params;

	if (max_window_size > XPRESS_MAX_OFFSET + 1)
		return 0;

	xpress_build_params(compression_level, max_window_size, &params);

	size += sizeof(struct xpress_compressor);

	/* mf */
	size += lz_mf_get_needed_memory(params.mf_algo, max_window_size);

	/* optimum */
	if (params.choose_items_func == xpress_choose_near_optimal_items) {
		size += (XPRESS_OPTIM_ARRAY_LENGTH + params.nice_match_length) *
			sizeof(struct xpress_mc_pos_data);
	}

	/* cached_matches */
	if (params.num_optim_passes > 1) {
		size_t cache_len = max(max_window_size * XPRESS_CACHE_PER_POS,
				       params.max_search_depth + 1);
		size += cache_len * sizeof(struct lz_match);
	} else {
		size += params.max_search_depth * sizeof(struct lz_match);
	}

	/* chosen_items */
	size += max_window_size * sizeof(struct xpress_item);

	return size;
}

static int
xpress_create_compressor(size_t max_window_size, unsigned int compression_level,
			 void **c_ret)
{
	struct xpress_compressor *c;
	struct xpress_compressor_params params;
	struct lz_mf_params mf_params;

	if (max_window_size > XPRESS_MAX_OFFSET + 1)
		return WIMLIB_ERR_INVALID_PARAM;

	xpress_build_params(compression_level, max_window_size, &params);
	xpress_build_mf_params(&params, max_window_size, &mf_params);

	c = CALLOC(1, sizeof(struct xpress_compressor));
	if (!c)
		goto oom;

	c->params = params;

	c->mf = lz_mf_alloc(&mf_params);
	if (!c->mf)
		goto oom;

	if (params.choose_items_func == xpress_choose_near_optimal_items) {
		c->optimum = MALLOC((XPRESS_OPTIM_ARRAY_LENGTH +
				     params.nice_match_length) *
				      sizeof(struct xpress_mc_pos_data));
		if (!c->optimum)
			goto oom;
	}

	if (params.num_optim_passes > 1) {
		size_t cache_len = max(max_window_size * XPRESS_CACHE_PER_POS,
				       params.max_search_depth + 1);
		c->cached_matches = MALLOC(cache_len * sizeof(struct lz_match));
		if (!c->cached_matches)
			goto oom;
		c->cache_limit = c->cached_matches + cache_len -
				   (params.max_search_depth + 1);
	} else {
		c->cached_matches = MALLOC(params.max_search_depth *
					   sizeof(struct lz_match));
		if (!c->cached_matches)
			goto oom;
	}

	c->chosen_items = MALLOC(max_window_size * sizeof(struct xpress_item));
	if (!c->chosen_items)
		goto oom;

	*c_ret = c;
	return 0;

oom:
	xpress_free_compressor(c);
	return WIMLIB_ERR_NOMEM;
}

static size_t
xpress_compress(const void *uncompressed_data, size_t uncompressed_size,
		void *compressed_data, size_t compressed_size_avail, void *_c)
{
	struct xpress_compressor *c = _c;
	u32 num_chosen_items;
	u8 *cptr;
	struct xpress_output_bitstream os;
	u32 compressed_size;

	/* XPRESS requires 256 bytes of overhead for the Huffman code, so it's
	 * impossible to compress 256 bytes or less of data to less than the
	 * input size.  */
	if (compressed_size_avail < XPRESS_NUM_SYMBOLS / 2 + 50)
		return 0;

	/* Determine match/literal sequence.  */
	c->cur_window = uncompressed_data;
	c->cur_window_size = uncompressed_size;
	lz_mf_load_window(c->mf, c->cur_window, c->cur_window_size);
	memset(c->freqs, 0, sizeof(c->freqs));

	num_chosen_items = xpress_choose_items(c);

	c->freqs[XPRESS_END_OF_DATA]++;
	xpress_make_huffman_code(c);

	/* Output the Huffman code as a series of 512 4-bit lengths.  */
	cptr = compressed_data;
	for (unsigned i = 0; i < XPRESS_NUM_SYMBOLS; i += 2)
		*cptr++ = (c->lens[i + 1] << 4) | c->lens[i];

	/* Output the encoded matches/literals.  */
	xpress_init_output(&os, cptr,
			   compressed_size_avail - XPRESS_NUM_SYMBOLS / 2);
	xpress_write_items(&os, c->chosen_items, num_chosen_items,
			   c->codewords, c->lens);

	/* Flush any pending data and get the length of the compressed data.  */
	compressed_size = xpress_flush_output(&os);
	if (compressed_size == 0)
		return 0;

	/* Return the length of the compressed data.  */
	return compressed_size + XPRESS_NUM_SYMBOLS / 2;
}

static void
xpress_free_compressor(void *_c)
{
	struct xpress_compressor *c = _c;

	if (c) {
		lz_mf_free(c->mf);
		FREE(c->optimum);
		FREE(c->cached_matches);
		FREE(c->chosen_items);
		FREE(c);
	}
}

const struct compressor_ops xpress_compressor_ops = {
	.get_needed_memory  = xpress_get_needed_memory,
	.create_compressor  = xpress_create_compressor,
	.compress	    = xpress_compress,
	.free_compressor    = xpress_free_compressor,
};
