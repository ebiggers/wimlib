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

#include "wimlib/compressor_ops.h"
#include "wimlib/compress_common.h"
#include "wimlib/error.h"
#include "wimlib/lz_mf.h"
#include "wimlib/util.h"
#include "wimlib/xpress.h"

#include <string.h>

#define XPRESS_CACHE_PER_POS		8
#define XPRESS_OPTIM_ARRAY_LENGTH	4096

struct xpress_compressor;
struct xpress_item;
struct xpress_mc_pos_data;

struct xpress_compressor_params {
	struct lz_match (*choose_item_func)(struct xpress_compressor *);
	u32 num_optim_passes;
	enum lz_mf_algo mf_algo;
	u32 nice_match_length;
	u32 max_search_depth;
};

/* XPRESS compressor state.  */
struct xpress_compressor {

	/* Parameters determined based on the compression level.  */
	struct xpress_compressor_params params;

	unsigned (*get_matches_func)(struct xpress_compressor *,
				     const struct lz_match **);
	void (*skip_bytes_func)(struct xpress_compressor *, u32 n);
	u32 len_3_too_far;

	/* Data currently being compressed  */
	const u8 *cur_window;
	u32 cur_window_size;

	/* Lempel-Ziv match-finder  */
	struct lz_mf *mf;

	const u8 *cur_window_ptr;

	/* Match cache, used when doing multiple optimization passes.  */
	struct lz_match *cached_matches;
	struct lz_match *cache_ptr;
	struct lz_match *cache_limit;

	/* Optimal parsing data  */
	struct xpress_mc_pos_data *optimum;
	unsigned optimum_cur_idx;
	unsigned optimum_end_idx;
	u8 costs[XPRESS_NUM_SYMBOLS];

	/* Lazy parsing data  */
	struct lz_match prev_match;

	/* The selected sequence of matches/literals  */
	struct xpress_item *chosen_items;

	/* Symbol frequency counters  */
	u32 freqs[XPRESS_NUM_SYMBOLS];

	/* The current Huffman code  */
	u32 codewords[XPRESS_NUM_SYMBOLS];
	u8 lens[XPRESS_NUM_SYMBOLS];
};

/* Match-chooser position data.
 * See corresponding declaration in lzx-compress.c for more information.  */
struct xpress_mc_pos_data {
	u32 cost;
#define MC_INFINITE_COST ((u32)~0UL)

	union {
		struct {
			u32 link;
			u32 match_offset;
		} prev;
		struct {
			u32 link;
			u32 match_offset;
		} next;
	};
};

/* Intermediate XPRESS match/literal representation.  */
struct xpress_item {
	u16 adjusted_len;  /* Match length minus XPRESS_MIN_MATCH_LEN */
	u16 offset;        /* Match offset */
	/* For literals, offset == 0 and adjusted_len is the literal byte.  */
};

/* Output an XPRESS match.  */
static void
xpress_write_match(struct xpress_item match, struct output_bitstream *ostream,
		   const u32 codewords[], const u8 lens[])
{
	unsigned len_hdr = min(match.adjusted_len, 0xf);
	unsigned offset_bsr = bsr32(match.offset);
	unsigned sym = XPRESS_NUM_CHARS + ((offset_bsr << 4) | len_hdr);

	/* Huffman symbol  */
	bitstream_put_bits(ostream, codewords[sym], lens[sym]);

	/* If length >= 18, one extra length byte.
	 * If length >= 273, three (total) extra length bytes.  */
	if (match.adjusted_len >= 0xf) {
		u8 byte1 = min(match.adjusted_len - 0xf, 0xff);
		bitstream_put_byte(ostream, byte1);
		if (byte1 == 0xff) {
			bitstream_put_byte(ostream, match.adjusted_len & 0xff);
			bitstream_put_byte(ostream, match.adjusted_len >> 8);
		}
	}

	/* Offset bits  */
	bitstream_put_bits(ostream, match.offset ^ (1U << offset_bsr), offset_bsr);
}

/* Output a sequence of XPRESS matches and literals.  */
static void
xpress_write_items(struct output_bitstream *ostream,
		   const struct xpress_item items[], u32 num_items,
		   const u32 codewords[], const u8 lens[])
{
	for (u32 i = 0; i < num_items; i++) {
		if (items[i].offset) {
			/* Match  */
			xpress_write_match(items[i], ostream, codewords, lens);
		} else {
			/* Literal  */
			unsigned lit = items[i].adjusted_len;
			bitstream_put_bits(ostream, codewords[lit], lens[lit]);
		}
	}
	/* End-of-data symbol (required for MS compatibility)  */
	bitstream_put_bits(ostream, codewords[XPRESS_END_OF_DATA], lens[XPRESS_END_OF_DATA]);
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

/* Account for the Huffman symbol that would be produced by outputting the
 * specified literal.  Returns the intermediate representation of the literal.
 */
static inline struct xpress_item
xpress_tally_literal(u8 lit, u32 freqs[])
{
	freqs[lit]++;
	return (struct xpress_item) { .offset = 0, .adjusted_len = lit };
}

/* Account for the Huffman symbol that would be produced by outputting the
 * specified match.  Returns the intermediate representation of the match.  */
static inline struct xpress_item
xpress_tally_match(u32 len, u32 offset, u32 freqs[])
{
	u32 adjusted_len = len - XPRESS_MIN_MATCH_LEN;
	unsigned len_hdr = min(adjusted_len, 0xf);
	unsigned sym = XPRESS_NUM_CHARS + ((bsr32(offset) << 4) | len_hdr);

	freqs[sym]++;
	return (struct xpress_item) { .offset = offset,
				      .adjusted_len = adjusted_len };
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
	c->cur_window_ptr++;
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
	if (likely(cache_ptr <= c->cache_limit)) {
		num_matches = cache_ptr->len;
		c->cache_ptr = matches + num_matches;
	} else {
		num_matches = 0;
	}
	c->cur_window_ptr++;
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
	c->cur_window_ptr++;
	*matches_ret = matches;
	return num_matches;
}

static unsigned
xpress_get_matches_noncaching(struct xpress_compressor *c,
			      const struct lz_match **matches_ret)
{
	c->cur_window_ptr++;
	*matches_ret = c->cached_matches;
	return lz_mf_get_matches(c->mf, c->cached_matches);
}

/*
 * Find matches at the next position in the window.
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
xpress_skip_bytes_fillcache(struct xpress_compressor *c, u32 n)
{
	struct lz_match *cache_ptr;

	c->cur_window_ptr += n;
	cache_ptr = c->cache_ptr;
	lz_mf_skip_positions(c->mf, n);
	if (likely(cache_ptr <= c->cache_limit)) {
		do {
			cache_ptr->len = 0;
			cache_ptr += 1;
		} while (--n && likely(cache_ptr <= c->cache_limit));
	}
	c->cache_ptr = cache_ptr;
}

static void
xpress_skip_bytes_usecache(struct xpress_compressor *c, u32 n)
{
	struct lz_match *cache_ptr;

	c->cur_window_ptr += n;
	cache_ptr = c->cache_ptr;
	if (likely(cache_ptr <= c->cache_limit)) {
		do {
			cache_ptr += 1 + cache_ptr->len;
		} while (--n && likely(cache_ptr <= c->cache_limit));
	}
	c->cache_ptr = cache_ptr;
}

static void
xpress_skip_bytes_usecache_nocheck(struct xpress_compressor *c, u32 n)
{
	struct lz_match *cache_ptr;

	c->cur_window_ptr += n;
	cache_ptr = c->cache_ptr;
	do {
		cache_ptr += 1 + cache_ptr->len;
	} while (--n);
	c->cache_ptr = cache_ptr;
}

static void
xpress_skip_bytes_noncaching(struct xpress_compressor *c, u32 n)
{
	c->cur_window_ptr += n;
	lz_mf_skip_positions(c->mf, n);
}

/*
 * Skip the specified number of positions in the window (don't search for
 * matches at them).
 */
static inline void
xpress_skip_bytes(struct xpress_compressor *c, u32 n)
{
	return (*c->skip_bytes_func)(c, n);
}

/*
 * Returns the cost, in bits, required to output the literal from the previous
 * window position (the position at which matches were last searched).
 */
static inline u32
xpress_prev_literal_cost(const struct xpress_compressor *c)
{
	return c->costs[*(c->cur_window_ptr - 1)];
}

/*
 * Reverse the linked list of near-optimal matches so that they can be returned
 * in forwards order.
 *
 * Returns the first match in the list.
 */
static struct lz_match
xpress_match_chooser_reverse_list(struct xpress_compressor *c, unsigned cur_pos)
{
	unsigned prev_link, saved_prev_link;
	u32 prev_match_offset, saved_prev_match_offset;

	c->optimum_end_idx = cur_pos;

	saved_prev_link = c->optimum[cur_pos].prev.link;
	saved_prev_match_offset = c->optimum[cur_pos].prev.match_offset;

	do {
		prev_link = saved_prev_link;
		prev_match_offset = saved_prev_match_offset;

		saved_prev_link = c->optimum[prev_link].prev.link;
		saved_prev_match_offset = c->optimum[prev_link].prev.match_offset;

		c->optimum[prev_link].next.link = cur_pos;
		c->optimum[prev_link].next.match_offset = prev_match_offset;

		cur_pos = prev_link;
	} while (cur_pos != 0);

	c->optimum_cur_idx = c->optimum[0].next.link;

	return (struct lz_match)
		{ .len = c->optimum_cur_idx,
		  .offset = c->optimum[0].next.match_offset,
		};
}

/*
 * Near-optimal parsing.
 *
 * This does a forward lowest-cost path search.  The search is terminated when a
 * sufficiently long match is found, when the search reaches a position with no
 * alternatives, or when the temporary 'optimum' array fills up.  After
 * termination of the search, matches/literals will be returned one by one by
 * successive calls to this function.  Once all the matches/literals are used
 * up, the next call to this function will begin a new search.
 */
static struct lz_match
xpress_choose_near_optimal_item(struct xpress_compressor *c)
{
	const struct lz_match *matches;
	unsigned num_matches;
	struct lz_match match;
	unsigned cur_pos;
	unsigned end_pos;
	struct xpress_mc_pos_data * const optimum = c->optimum;

	if (c->optimum_cur_idx != c->optimum_end_idx) {
		/* Return previously computed match or literal.  */
		match.len = optimum[c->optimum_cur_idx].next.link -
				    c->optimum_cur_idx;
		match.offset = optimum[c->optimum_cur_idx].next.match_offset;

		c->optimum_cur_idx = optimum[c->optimum_cur_idx].next.link;
		return match;
	}

	c->optimum_cur_idx = 0;
	c->optimum_end_idx = 0;

	num_matches = xpress_get_matches(c, &matches);

	if (num_matches == 0)
		return (struct lz_match) {};

	if (matches[num_matches - 1].len >= c->params.nice_match_length) {
		/* Take the long match immediately.  */
		xpress_skip_bytes(c, matches[num_matches - 1].len - 1);
		return matches[num_matches - 1];
	}

	/* Consider coding a literal.  */
	optimum[1].cost = xpress_prev_literal_cost(c);
	optimum[1].prev.link = 0;

	optimum[2].cost = MC_INFINITE_COST;

	{
		/* Consider coding a match.  Cost evaluation is hand-inlined so
		 * that we can do some performance hacks.  */

		unsigned i = 0;
		unsigned len = 3;
		struct xpress_mc_pos_data *optimum_ptr = &optimum[len];

		if (matches[num_matches - 1].len < 0xf + XPRESS_MIN_MATCH_LEN) {
			do {
				u32 offset = matches[i].offset;
				u32 offset_bsr = bsr32(offset);
				unsigned len_hdr = len - XPRESS_MIN_MATCH_LEN;
				unsigned sym = XPRESS_NUM_CHARS +
						((offset_bsr << 4) | len_hdr);
				do {
					optimum_ptr->prev.link = 0;
					optimum_ptr->prev.match_offset = offset;
					optimum_ptr->cost = offset_bsr + c->costs[sym];
					sym++;
					optimum_ptr++;
				} while (++len <= matches[i].len);
			} while (++i != num_matches);
		} else {
			do {
				u32 offset = matches[i].offset;
				u32 offset_bsr = bsr32(offset);
				do {
					u32 adjusted_len = len - XPRESS_MIN_MATCH_LEN;
					unsigned len_hdr = min(adjusted_len, 0xf);
					unsigned sym = XPRESS_NUM_CHARS +
							((offset_bsr << 4) | len_hdr);
					u32 cost = offset_bsr + c->costs[sym];
					if (adjusted_len >= 0xf) {
						cost += 8;
						if (adjusted_len - 0xf >= 0xff)
							cost += 16;
					}

					optimum_ptr->prev.link = 0;
					optimum_ptr->prev.match_offset = offset;
					optimum_ptr->cost = cost;
					optimum_ptr++;
				} while (++len <= matches[i].len);
			} while (++i != num_matches);
		}
	}

	end_pos = matches[num_matches - 1].len;
	cur_pos = 1;
	do {
		u32 cost;
		u32 longest_len;

		num_matches = xpress_get_matches(c, &matches);

		if (num_matches) {
			longest_len = matches[num_matches - 1].len;
			if (longest_len >= c->params.nice_match_length) {
				/* Take the long match immediately.  */
				match = xpress_match_chooser_reverse_list(c, cur_pos);

				optimum[cur_pos].next.match_offset =
					matches[num_matches - 1].offset;
				optimum[cur_pos].next.link = cur_pos + longest_len;
				c->optimum_end_idx = cur_pos + longest_len;

				xpress_skip_bytes(c, longest_len - 1);

				return match;
			}
		} else {
			longest_len = 1;
		}

		while (end_pos < cur_pos + longest_len)
			optimum[++end_pos].cost = MC_INFINITE_COST;

		/* Consider coding a literal.  */
		cost = optimum[cur_pos].cost + xpress_prev_literal_cost(c);
		if (cost < optimum[cur_pos + 1].cost) {
			optimum[cur_pos + 1].cost = cost;
			optimum[cur_pos + 1].prev.link = cur_pos;
		}

		if (num_matches) {
			/* Consider coding a match.  Cost evaluation is
			 * hand-inlined so that we can do some performance
			 * hacks.  */
			unsigned i = 0;
			unsigned len = 3;
			struct xpress_mc_pos_data *optimum_ptr = &optimum[cur_pos + 3];
			u32 cur_cost = optimum[cur_pos].cost;

			if (matches[num_matches - 1].len < 0xf + XPRESS_MIN_MATCH_LEN) {
				do {
					u32 offset = matches[i].offset;
					u32 offset_bsr = bsr32(offset);
					unsigned len_hdr = len - XPRESS_MIN_MATCH_LEN;
					unsigned sym = XPRESS_NUM_CHARS +
							((offset_bsr << 4) | len_hdr);

					u32 base_cost = cur_cost + offset_bsr;
					do {
						cost = base_cost + c->costs[sym];
						if (cost < optimum_ptr->cost) {
							optimum_ptr->prev.link = cur_pos;
							optimum_ptr->prev.match_offset = offset;
							optimum_ptr->cost = cost;
						}
						sym++;
						optimum_ptr++;
					} while (++len <= matches[i].len);
				} while (++i != num_matches);
			} else {
				do {
					u32 offset = matches[i].offset;
					u32 offset_bsr = bsr32(offset);

					u32 base_cost = cur_cost + offset_bsr;
					do {
						u32 adjusted_len = len - XPRESS_MIN_MATCH_LEN;
						unsigned len_hdr = min(adjusted_len, 0xf);
						unsigned sym = XPRESS_NUM_CHARS +
								((offset_bsr << 4) | len_hdr);

						cost = base_cost + c->costs[sym];
						if (adjusted_len >= 0xf) {
							cost += 8;
							if (adjusted_len - 0xf >= 0xff)
								cost += 16;
						}

						if (cost < optimum_ptr->cost) {
							optimum_ptr->prev.link = cur_pos;
							optimum_ptr->prev.match_offset = offset;
							optimum_ptr->cost = cost;
						}
						optimum_ptr++;
					} while (++len <= matches[i].len);
				} while (++i != num_matches);
			}
		}

		cur_pos++;

	} while (cur_pos != end_pos && cur_pos != XPRESS_OPTIM_ARRAY_LENGTH);

	return xpress_match_chooser_reverse_list(c, cur_pos);
}

/* Lazy parsing.  */
static struct lz_match
xpress_choose_lazy_item(struct xpress_compressor *c)
{
	const struct lz_match *matches;
	struct lz_match cur_match;
	struct lz_match next_match;
	u32 num_matches;

	if (c->prev_match.len) {
		cur_match = c->prev_match;
		c->prev_match.len = 0;
	} else {
		num_matches = xpress_get_matches(c, &matches);
		if (num_matches == 0 ||
		    (matches[num_matches - 1].len == 3 &&
		     matches[num_matches - 1].offset >= c->len_3_too_far))
		{
			cur_match.len = 0;
			return cur_match;
		}

		/* With lazy parsing we only consider the longest match at each
		 * position.  */
		cur_match = matches[num_matches - 1];
	}

	if (cur_match.len >= c->params.nice_match_length) {
		xpress_skip_bytes(c, cur_match.len - 1);
		return cur_match;
	}

	num_matches = xpress_get_matches(c, &matches);
	if (num_matches == 0 ||
	    (matches[num_matches - 1].len == 3 &&
	     matches[num_matches - 1].offset >= c->len_3_too_far))
	{
		xpress_skip_bytes(c, cur_match.len - 2);
		return cur_match;
	}

	next_match = matches[num_matches - 1];

	if (next_match.len <= cur_match.len) {
		xpress_skip_bytes(c, cur_match.len - 2);
		return cur_match;
	} else {
		/* Longer match at next position.  Choose a literal here so we
		 * will get to use the longer match.  */
		c->prev_match = next_match;
		cur_match.len = 0;
		return cur_match;
	}
}

/* Greedy parsing.  */
static struct lz_match
xpress_choose_greedy_item(struct xpress_compressor *c)
{
	const struct lz_match *matches;
	u32 num_matches;

	num_matches = xpress_get_matches(c, &matches);
	if (num_matches == 0 ||
	    (matches[num_matches - 1].len == 3 &&
	     matches[num_matches - 1].offset >= c->len_3_too_far))
		return (struct lz_match) {};

	xpress_skip_bytes(c, matches[num_matches - 1].len - 1);
	return matches[num_matches - 1];
}

/* Always choose a literal.  */
static struct lz_match
xpress_choose_literal(struct xpress_compressor *c)
{
	return (struct lz_match) {};
}

/*
 * Return the next match or literal to use, delegating to the currently selected
 * match-choosing algorithm.
 *
 * If the length of the returned 'struct lz_match' is less than
 * XPRESS_MIN_MATCH_LEN, then it is really a literal.
 */
static inline struct lz_match
xpress_choose_item(struct xpress_compressor *c)
{
	return (*c->params.choose_item_func)(c);
}

/* Set default XPRESS Huffman symbol costs to kick-start the iterative
 * optimization algorithm.  */
static void
xpress_set_default_costs(u8 costs[])
{
	unsigned i;

	for (i = 0; i < XPRESS_NUM_CHARS; i++)
		costs[i] = 8;

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
 * Given the data to compress (c->cur_window, c->cur_window_size), fills in
 * c->chosen_items with the intermediate representation of the match/literal
 * sequence to output.  Also fills in c->codewords and c->lens to provide the
 * Huffman code with which these items should be output.
 *
 * Returns the number of items written to c->chosen_items.  This can be at most
 * c->cur_window_size.  (The worst case is all literals, no matches.)
 */
static u32
xpress_choose_items(struct xpress_compressor *c)
{
	u32 num_passes_remaining = c->params.num_optim_passes;
	const u8 *window_ptr;
	const u8 *window_end;
	struct xpress_item *next_chosen_item;
	struct lz_match raw_item;
	struct xpress_item xpress_item;

	if (c->params.choose_item_func == xpress_choose_near_optimal_item) {
		xpress_set_default_costs(c->costs);
		c->optimum_cur_idx = 0;
		c->optimum_end_idx = 0;
	} else {
		c->prev_match.len = 0;
		if (c->cur_window_size <= 8192)
			c->len_3_too_far = 2048;
		else
			c->len_3_too_far = 4096;
	}

	if (c->params.num_optim_passes > 1) {
		c->get_matches_func = xpress_get_matches_fillcache;
		c->skip_bytes_func = xpress_skip_bytes_fillcache;
	} else {
		c->get_matches_func = xpress_get_matches_noncaching;
		c->skip_bytes_func = xpress_skip_bytes_noncaching;
	}

	lz_mf_load_window(c->mf, c->cur_window, c->cur_window_size);

	while (--num_passes_remaining) {
		window_ptr = c->cur_window_ptr = c->cur_window;
		window_end = window_ptr + c->cur_window_size;
		c->cache_ptr = c->cached_matches;
		memset(c->freqs, 0, sizeof(c->freqs));

		while (window_ptr != window_end) {
			raw_item = xpress_choose_item(c);
			if (raw_item.len >= XPRESS_MIN_MATCH_LEN) {
				xpress_tally_match(raw_item.len,
						   raw_item.offset, c->freqs);
				window_ptr += raw_item.len;
			} else {
				xpress_tally_literal(*window_ptr, c->freqs);
				window_ptr += 1;
			}
		}
		c->freqs[XPRESS_END_OF_DATA]++;
		xpress_make_huffman_code(c);
		xpress_set_costs(c->costs, c->lens);
		if (c->cache_ptr <= c->cache_limit) {
			c->get_matches_func = xpress_get_matches_usecache_nocheck;
			c->skip_bytes_func = xpress_skip_bytes_usecache_nocheck;
		} else {
			c->get_matches_func = xpress_get_matches_usecache;
			c->skip_bytes_func = xpress_skip_bytes_usecache;
		}
	}

	window_ptr = c->cur_window_ptr = c->cur_window;
	window_end = window_ptr + c->cur_window_size;
	c->cache_ptr = c->cached_matches;
	memset(c->freqs, 0, sizeof(c->freqs));
	next_chosen_item = c->chosen_items;

	u32 unseen_cost = 9;
	while (window_ptr != window_end) {
		raw_item = xpress_choose_item(c);
		if (raw_item.len >= XPRESS_MIN_MATCH_LEN) {
			xpress_item = xpress_tally_match(raw_item.len,
							 raw_item.offset,
							 c->freqs);
			window_ptr += raw_item.len;
		} else {
			xpress_item = xpress_tally_literal(*window_ptr,
							   c->freqs);
			window_ptr += 1;
		}
		*next_chosen_item++ = xpress_item;

		/* When doing one-pass near-optimal parsing, rebuild the Huffman
		 * code occasionally.  */
		if (unlikely((next_chosen_item - c->chosen_items) % 2048 == 0) &&
		    c->params.choose_item_func == xpress_choose_near_optimal_item &&
		    c->cur_window_size >= 16384 &&
		    c->params.num_optim_passes == 1)
		{
			xpress_make_huffman_code(c);
			for (unsigned i = 0; i < XPRESS_NUM_SYMBOLS; i++)
				c->costs[i] = c->lens[i] ? c->lens[i] : unseen_cost;
			if (unseen_cost < 15)
				unseen_cost++;
		}
	}
	c->freqs[XPRESS_END_OF_DATA]++;
	xpress_make_huffman_code(c);
	return next_chosen_item - c->chosen_items;
}

/* Given the specified compression level and maximum window size, build the
 * parameters to use for XPRESS compression.  */
static void
xpress_build_params(unsigned int compression_level, u32 max_window_size,
		    struct xpress_compressor_params *xpress_params)
{
	memset(xpress_params, 0, sizeof(*xpress_params));

	if (compression_level == 1) {

		/* Huffman only (no Lempel-Ziv matches)  */
		xpress_params->mf_algo = LZ_MF_NULL;
		xpress_params->choose_item_func = xpress_choose_literal;
		xpress_params->num_optim_passes = 1;

	} else if (compression_level < 30) {

		/* Greedy parsing  */
		xpress_params->mf_algo = LZ_MF_HASH_CHAINS;
		xpress_params->choose_item_func = xpress_choose_greedy_item;
		xpress_params->num_optim_passes = 1;
		xpress_params->nice_match_length = compression_level;
		xpress_params->max_search_depth = compression_level / 2;

	} else if (compression_level < 60) {

		/* Lazy parsing  */
		xpress_params->mf_algo = LZ_MF_HASH_CHAINS;
		xpress_params->choose_item_func = xpress_choose_lazy_item;
		xpress_params->num_optim_passes = 1;
		xpress_params->nice_match_length = compression_level;
		xpress_params->max_search_depth = compression_level / 2;

	} else {

		/* Near-optimal parsing  */
		xpress_params->choose_item_func = xpress_choose_near_optimal_item;
		if (max_window_size >= 32768)
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

/* Given the specified XPRESS parameters and maximum window size, build the
 * parameters to use for match-finding.  */
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

static inline bool
xpress_window_size_valid(size_t window_size)
{
	return (window_size > 0 && window_size <= XPRESS_MAX_OFFSET + 1);
}

static void
xpress_free_compressor(void *_c);

static u64
xpress_get_needed_memory(size_t max_window_size, unsigned int compression_level)
{
	u64 size = 0;
	struct xpress_compressor_params params;

	if (!xpress_window_size_valid(max_window_size))
		return 0;

	xpress_build_params(compression_level, max_window_size, &params);

	size += sizeof(struct xpress_compressor);

	size += lz_mf_get_needed_memory(params.mf_algo, max_window_size);

	if (params.num_optim_passes > 1) {
		size_t cache_len = max(max_window_size * XPRESS_CACHE_PER_POS,
				       params.max_search_depth + 1);
		size += cache_len * sizeof(struct lz_match);
	} else {
		size += params.max_search_depth * sizeof(struct lz_match);
	}

	if (params.choose_item_func == xpress_choose_near_optimal_item) {
		size += (XPRESS_OPTIM_ARRAY_LENGTH + params.nice_match_length) *
				      sizeof(struct xpress_mc_pos_data);
	}

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

	if (!xpress_window_size_valid(max_window_size))
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

	if (params.choose_item_func == xpress_choose_near_optimal_item) {
		c->optimum = MALLOC((XPRESS_OPTIM_ARRAY_LENGTH +
				     params.nice_match_length) *
				      sizeof(struct xpress_mc_pos_data));
		if (!c->optimum)
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
	struct output_bitstream ostream;
	u32 compressed_size;

	/* XPRESS requires 256 bytes of overhead for the Huffman code, so it's
	 * impossible to compress 256 bytes or less of data to less than the
	 * input size.
	 *
	 * +1 to take into account that the buffer for compressed data is 1 byte
	 * smaller than the buffer for uncompressed data.
	 *
	 * +4 to take into account that init_output_bitstream() requires at
	 * least 4 bytes of data.  */
	if (compressed_size_avail < XPRESS_NUM_SYMBOLS / 2 + 1 + 4)
		return 0;

	/* Determine match/literal sequence to divide the data into.  */
	c->cur_window = uncompressed_data;
	c->cur_window_size = uncompressed_size;
	num_chosen_items = xpress_choose_items(c);

	/* Output the Huffman code as a series of 512 4-bit lengths.  */
	cptr = compressed_data;
	for (unsigned i = 0; i < XPRESS_NUM_SYMBOLS; i += 2)
		*cptr++ = (c->lens[i] & 0xf) | (c->lens[i + 1] << 4);

	/* Output the encoded matches/literals.  */
	init_output_bitstream(&ostream, cptr,
			      compressed_size_avail - XPRESS_NUM_SYMBOLS / 2 - 1);
	xpress_write_items(&ostream, c->chosen_items, num_chosen_items,
			   c->codewords, c->lens);

	/* Flush any pending data and get the length of the compressed data.  */
	compressed_size = flush_output_bitstream(&ostream);
	if (compressed_size == (u32)~0UL)
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
		FREE(c->cached_matches);
		FREE(c->optimum);
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
