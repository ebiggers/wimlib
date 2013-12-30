/*
 * lz_optimal.h
 *
 * Near-optimal LZ (Lempel-Ziv) parsing, or "match choosing".
 *
 * This is based on the algorithm used in 7-Zip's DEFLATE encoder, written by
 * Igor Pavlov.
 */

/*
 * Copyright (C) 2013 Eric Biggers
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

/* Define the following structures before including this:
 *
 * LZ_COMPRESSOR
 * LZ_FORMAT_STATE  */

#ifndef _LZ_OPTIMAL_H
#define _LZ_OPTIMAL_H

#include "wimlib/lz.h"

typedef input_idx_t lz_mc_cost_t;

#define LZ_MC_INFINITE_COST (~(lz_mc_cost_t)0)

/*
 * Match chooser position data:
 *
 * An array of these structures is used during the match-choosing algorithm.
 * They correspond to consecutive positions in the window and are used to keep
 * track of the cost to reach each position, and the match/literal choices that
 * need to be chosen to reach that position.
 */
struct lz_mc_pos_data {
	/* The approximate minimum cost, in bits, to reach this position in the
	 * window which has been found so far.  */
	lz_mc_cost_t cost;

	/* The union here is just for clarity, since the fields are used in two
	 * slightly different ways.  Initially, the @prev structure is filled in
	 * first, and links go from later in the window to earlier in the
	 * window.  Later, @next structure is filled in and links go from
	 * earlier in the window to later in the window.  */
	union {
		struct {
			/* Position of the start of the match or literal that
			 * was taken to get to this position in the approximate
			 * minimum-cost parse.  */
			input_idx_t link;

			/* Offset (as in an LZ (length, offset) pair) of the
			 * match or literal that was taken to get to this
			 * position in the approximate minimum-cost parse.  */
			input_idx_t match_offset;
		} prev;
		struct {
			/* Position at which the match or literal starting at
			 * this position ends in the minimum-cost parse.  */
			input_idx_t link;

			/* Offset (as in an LZ (length, offset) pair) of the
			 * match or literal starting at this position in the
			 * approximate minimum-cost parse.  */
			input_idx_t match_offset;
		} next;
	};

	/* Format-dependent state that exists after an approximate minimum-cost
	 * path to reach this position is taken.  For example, for LZX this is
	 * the list of recently used match offsets.  This could be 0 bytes if
	 * the format does not have any state that affects match costs.  */
	LZ_FORMAT_STATE state;
};

struct lz_match_chooser {
	/* Temporary space used for the match-choosing algorithm.  The size of
	 * this array must be at least one more than greedy_len but otherwise is
	 * arbitrary.  More space simply allows the match-choosing algorithm to
	 * potentially find better matches (depending on the input, as always).
	 */
	struct lz_mc_pos_data *optimum;
	input_idx_t array_space;

	/* When a match greater than this length is found, choose it immediately
	 * without further consideration.  */
	input_idx_t greedy_len;

	/* When matches have been chosen, optimum_cur_idx is set to the position
	 * in the window of the next match/literal to return and optimum_end_idx
	 * is set to the position in the window at the end of the last
	 * match/literal to return.  */
	input_idx_t optimum_cur_idx;
	input_idx_t optimum_end_idx;
};

/* Initialize the match-chooser.
 *
 * After calling this, multiple data buffers can be scanned with it if each is
 * preceded with a call to lz_match_chooser_begin().  */
static bool
lz_match_chooser_init(struct lz_match_chooser *mc,
		      input_idx_t array_space,
		      input_idx_t greedy_len, input_idx_t max_match_len)
{
	input_idx_t extra_len = min(greedy_len, max_match_len);

	LZ_ASSERT(array_space > 0);
	mc->optimum = MALLOC((array_space + extra_len) * sizeof(mc->optimum[0]));
	if (mc->optimum == NULL)
		return false;
	mc->array_space = array_space;
	mc->greedy_len = greedy_len;
	return true;
}

static void
lz_match_chooser_destroy(struct lz_match_chooser *mc)
{
	FREE(mc->optimum);
}

static void
lz_match_chooser_begin(struct lz_match_chooser *mc)
{
	mc->optimum_cur_idx = 0;
	mc->optimum_end_idx = 0;
}

/*
 * Reverse the linked list of near-optimal matches so that they can be returned
 * in forwards order.
 *
 * Returns the first match in the list.
 */
static _always_inline_attribute struct raw_match
lz_match_chooser_reverse_list(struct lz_match_chooser *mc, input_idx_t cur_pos)
{
	unsigned prev_link, saved_prev_link;
	unsigned prev_match_offset, saved_prev_match_offset;

	mc->optimum_end_idx = cur_pos;

	saved_prev_link = mc->optimum[cur_pos].prev.link;
	saved_prev_match_offset = mc->optimum[cur_pos].prev.match_offset;

	do {
		prev_link = saved_prev_link;
		prev_match_offset = saved_prev_match_offset;

		saved_prev_link = mc->optimum[prev_link].prev.link;
		saved_prev_match_offset = mc->optimum[prev_link].prev.match_offset;

		mc->optimum[prev_link].next.link = cur_pos;
		mc->optimum[prev_link].next.match_offset = prev_match_offset;

		cur_pos = prev_link;
	} while (cur_pos != 0);

	mc->optimum_cur_idx = mc->optimum[0].next.link;

	return (struct raw_match)
		{ .len = mc->optimum_cur_idx,
		  .offset = mc->optimum[0].next.match_offset,
		};
}

/* Format-specific functions inlined into lz_get_near_optimal_match().  */

/* Get the list of possible matches at the next position.  The return value must
 * be the number of matches found (which may be 0) and a pointer to the returned
 * matches must be written into @matches_ret.  Matches must be of distinct
 * lengths and sorted in decreasing order by length.  */
typedef u32 (*lz_get_matches_t)(LZ_COMPRESSOR *ctx,
				const LZ_FORMAT_STATE *state,
				struct raw_match **matches_ret);

/* Skip the specified number of bytes (don't search for matches at them).  */
typedef void (*lz_skip_bytes_t)(LZ_COMPRESSOR *ctx, input_idx_t n);

/* Get the cost of the literal located at the position at which matches have
 * most recently been searched.  This can optionally update the @state to take
 * into account format-dependent state that affects match costs, such as repeat
 * offsets.  */
typedef u32 (lz_get_prev_literal_cost_t)(LZ_COMPRESSOR *ctx,
					 LZ_FORMAT_STATE *state);

/* Get the cost of a match.  This can optionally update the @state to take into
 * account format-dependent state that affects match costs, such as repeat
 * offsets.  */
typedef u32 (lz_get_match_cost_t)(LZ_COMPRESSOR *ctx, LZ_FORMAT_STATE *state,
				  input_idx_t length,
				  input_idx_t offset);

/*
 * lz_get_near_optimal_match() -
 *
 * Choose the optimal match or literal to use at the next position in the input.
 *
 * Unlike a greedy parser that always takes the longest match, or even a
 * parser with one match/literal look-ahead like zlib, the algorithm used here
 * may look ahead many matches/literals to determine the optimal match/literal to
 * output next.  The motivation is that the compression ratio is improved if the
 * compressor can do things like use a shorter-than-possible match in order to
 * allow a longer match later, and also take into account the Huffman code cost
 * model rather than simply assuming that longer is better.
 *
 * Still, this is not truly an optimal parser because very long matches are
 * taken immediately, and the raw match-finder takes some shortcuts.  This is
 * done to avoid considering many different alternatives that are unlikely to
 * be significantly better.
 *
 * This algorithm is based on that used in 7-Zip's DEFLATE encoder.
 *
 * Each call to this function does one of two things:
 *
 * 1. Build a near-optimal sequence of matches/literals, up to some point, that
 *    will be returned by subsequent calls to this function, then return the
 *    first one.
 *
 * OR
 *
 * 2. Return the next match/literal previously computed by a call to this
 *    function;
 *
 * The return value is a (length, offset) pair specifying the match or literal
 * chosen.  For literals, the length is 0 or 1 and the offset is meaningless.
 */
static _always_inline_attribute struct raw_match
lz_get_near_optimal_match(struct lz_match_chooser *mc,
			  lz_get_matches_t get_matches,
			  lz_skip_bytes_t skip_bytes,
			  lz_get_prev_literal_cost_t get_prev_literal_cost,
			  lz_get_match_cost_t get_match_cost,
			  LZ_COMPRESSOR *ctx,
			  const LZ_FORMAT_STATE *initial_state)
{
	u32 num_possible_matches;
	struct raw_match *possible_matches;
	struct raw_match match;
	input_idx_t longest_match_len;

	if (mc->optimum_cur_idx != mc->optimum_end_idx) {
		/* Case 2: Return the next match/literal already found.  */
		match.len = mc->optimum[mc->optimum_cur_idx].next.link -
				    mc->optimum_cur_idx;
		match.offset = mc->optimum[mc->optimum_cur_idx].next.match_offset;

		mc->optimum_cur_idx = mc->optimum[mc->optimum_cur_idx].next.link;
		return match;
	}

	/* Case 1:  Compute a new list of matches/literals to return.  */

	mc->optimum_cur_idx = 0;
	mc->optimum_end_idx = 0;

	/* Get matches at this position.  */
	num_possible_matches = (*get_matches)(ctx,
					      initial_state,
					      &possible_matches);

	/* If no matches found, return literal.  */
	if (num_possible_matches == 0)
		return (struct raw_match){ .len = 0 };

	/* The matches that were found are sorted in decreasing order by length.
	 * Get the length of the longest one.  */
	longest_match_len = possible_matches[0].len;

	/* Greedy heuristic:  if the longest match that was found is greater
	 * than the number of fast bytes, return it immediately; don't both
	 * doing more work.  */
	if (longest_match_len > mc->greedy_len) {
		(*skip_bytes)(ctx, longest_match_len - 1);
		return possible_matches[0];
	}

	/* Calculate the cost to reach the next position by outputting a
	 * literal.  */
	mc->optimum[0].state = *initial_state;
	mc->optimum[1].state = mc->optimum[0].state;
	mc->optimum[1].cost = (*get_prev_literal_cost)(ctx, &mc->optimum[1].state);
	mc->optimum[1].prev.link = 0;

	/* Calculate the cost to reach any position up to and including that
	 * reached by the longest match, using the shortest (i.e. closest) match
	 * that reaches each position.  */
	for (input_idx_t len = 2, match_idx = num_possible_matches - 1;
	     len <= longest_match_len; len++)
	{

		LZ_ASSERT(match_idx < num_possible_matches);

		mc->optimum[len].state = mc->optimum[0].state;
		mc->optimum[len].prev.link = 0;
		mc->optimum[len].prev.match_offset = possible_matches[match_idx].offset;
		mc->optimum[len].cost = (*get_match_cost)(ctx,
							  &mc->optimum[len].state,
							  len,
							  possible_matches[match_idx].offset);
		if (len == possible_matches[match_idx].len)
			match_idx--;
	}

	input_idx_t cur_pos = 0;

	/* len_end: greatest index forward at which costs have been calculated
	 * so far  */
	input_idx_t len_end = longest_match_len;

	for (;;) {
		/* Advance to next position.  */
		cur_pos++;

		if (cur_pos == len_end || cur_pos == mc->array_space)
			return lz_match_chooser_reverse_list(mc, cur_pos);

		/* retrieve the number of matches available at this position  */
		num_possible_matches = (*get_matches)(ctx,
						      &mc->optimum[cur_pos].state,
						      &possible_matches);

		input_idx_t new_len = 0;

		if (num_possible_matches != 0) {
			new_len = possible_matches[0].len;

			/* Greedy heuristic:  if we found a match greater than
			 * the number of fast bytes, stop immediately.  */
			if (new_len > mc->greedy_len) {

				/* Build the list of matches to return and get
				 * the first one.  */
				match = lz_match_chooser_reverse_list(mc, cur_pos);

				/* Append the long match to the end of the list.  */
				mc->optimum[cur_pos].next.match_offset =
					possible_matches[0].offset;
				mc->optimum[cur_pos].next.link = cur_pos + new_len;
				mc->optimum_end_idx = cur_pos + new_len;

				/* Skip over the remaining bytes of the long match.  */
				(*skip_bytes)(ctx, new_len - 1);

				/* Return first match in the list  */
				return match;
			}
		}

		/* Consider proceeding with a literal byte.  */
		lz_mc_cost_t cur_cost = mc->optimum[cur_pos].cost;
		LZ_FORMAT_STATE cur_plus_literal_state = mc->optimum[cur_pos].state;
		lz_mc_cost_t cur_plus_literal_cost = cur_cost +
				(*get_prev_literal_cost)(ctx,
							 &cur_plus_literal_state);
		if (cur_plus_literal_cost < mc->optimum[cur_pos + 1].cost) {
			mc->optimum[cur_pos + 1].cost = cur_plus_literal_cost;
			mc->optimum[cur_pos + 1].prev.link = cur_pos;
			mc->optimum[cur_pos + 1].state = cur_plus_literal_state;
		}

		if (num_possible_matches == 0)
			continue;

		/* Consider proceeding with a match.  */

		while (len_end < cur_pos + new_len)
			mc->optimum[++len_end].cost = LZ_MC_INFINITE_COST;

		for (input_idx_t len = 2, match_idx = num_possible_matches - 1;
		     len <= new_len; len++)
		{
			LZ_ASSERT(match_idx < num_possible_matches);

			LZ_FORMAT_STATE state = mc->optimum[cur_pos].state;
			lz_mc_cost_t cost;

			cost = cur_cost + (*get_match_cost)(ctx,
							    &state,
							    len,
							    possible_matches[match_idx].offset);

			if (cost < mc->optimum[cur_pos + len].cost) {
				mc->optimum[cur_pos + len].cost = cost;
				mc->optimum[cur_pos + len].prev.link = cur_pos;
				mc->optimum[cur_pos + len].prev.match_offset =
						possible_matches[match_idx].offset;
				mc->optimum[cur_pos + len].state = state;
			}

			if (len == possible_matches[match_idx].len)
				match_idx--;
		}
	}
}

#endif /* _LZ_OPTIMAL_H  */
