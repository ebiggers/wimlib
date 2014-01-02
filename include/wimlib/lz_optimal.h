/*
 * lz_optimal.h
 *
 * Near-optimal LZ (Lempel-Ziv) parsing, or "match choosing".
 * See lz_get_near_optimal_match() for details of the algorithm.
 *
 * This code is not concerned with actually *finding* LZ matches, as it relies
 * on an underlying match-finder implementation that can do so.
 */

/*
 * Copyright (c) 2013 Eric Biggers.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Define the following structures before including this header:
 *
 * LZ_COMPRESSOR
 * LZ_ADAPTIVE_STATE
 *
 * Also, the type lz_mc_cost_t can be optionally overridden by providing an
 * appropriate typedef and defining LZ_MC_COST_T_DEFINED.  */

#ifndef _LZ_OPTIMAL_H
#define _LZ_OPTIMAL_H

#include "wimlib/lz.h"

#ifndef LZ_MC_COST_T_DEFINED
   typedef input_idx_t lz_mc_cost_t;
#endif

#define LZ_MC_INFINITE_COST (~(lz_mc_cost_t)0)

struct lz_mc_pos_data;

/* State of the Lempel-Ziv match-chooser.
 *
 * This is defined here for benefit of the inlined code.  It's not intended for
 * code outside the match-chooser itself to read or write members from this
 * structure.  */
struct lz_match_chooser {
	/* Temporary space used for the match-choosing algorithm.  The size of
	 * this array must be at least one more than @nice_len but otherwise is
	 * arbitrary.  More space decreases the frequency at which the algorithm
	 * is forced to terminate early.  4096 spaces seems sufficient for most
	 * real data.  */
	struct lz_mc_pos_data *optimum;
	input_idx_t array_space;

	/* When a match with length greater than or equal to this length is
	 * found, choose it immediately without further consideration.  */
	input_idx_t nice_len;

	/* When matches have been chosen, optimum_cur_idx is set to the position
	 * in the window of the next match/literal to return and optimum_end_idx
	 * is set to the position in the window at the end of the last
	 * match/literal to return.  */
	input_idx_t optimum_cur_idx;
	input_idx_t optimum_end_idx;
};

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

	/* Format-dependent adaptive state that exists after an approximate
	 * minimum-cost path to reach this position is taken.  For example, for
	 * LZX this is the list of recently used match offsets.  If the format
	 * does not have any adaptive state that affects match costs,
	 * LZ_ADAPTIVE_STATE could be set to a dummy structure of size 0.  */
	LZ_ADAPTIVE_STATE state;
};

/* Initialize the match-chooser.
 *
 * After calling this, multiple data buffers can be scanned with it if each is
 * preceded with a call to lz_match_chooser_begin().  */
static bool
lz_match_chooser_init(struct lz_match_chooser *mc,
		      input_idx_t array_space,
		      input_idx_t nice_len, input_idx_t max_match_len)
{
	input_idx_t extra_len = min(nice_len, max_match_len);

	LZ_ASSERT(array_space > 0);
	mc->optimum = MALLOC((array_space + extra_len) * sizeof(mc->optimum[0]));
	if (mc->optimum == NULL)
		return false;
	mc->array_space = array_space;
	mc->nice_len = nice_len;
	return true;
}

static inline u64
lz_match_chooser_get_needed_memory(input_idx_t array_space,
				   input_idx_t nice_len,
				   input_idx_t max_match_len)
{
	input_idx_t extra_len = min(nice_len, max_match_len);
	return ((u64)(array_space + extra_len) *
		sizeof(((struct lz_match_chooser*)0)->optimum[0]));
}

/* Free memory allocated in lz_match_chooser_init().  */
static void
lz_match_chooser_destroy(struct lz_match_chooser *mc)
{
	FREE(mc->optimum);
}

/* Call this before starting to parse each new input string.  */
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
 * lengths and sorted in decreasing order by length.  Furthermore, match lengths
 * may not exceed the @max_match_len passed to lz_match_chooser_init(), and all
 * match lengths must be at least 2.  */
typedef u32 (*lz_get_matches_t)(LZ_COMPRESSOR *ctx,
				const LZ_ADAPTIVE_STATE *state,
				struct raw_match **matches_ret);

/* Skip the specified number of bytes (don't search for matches at them).  This
 * is expected to be faster than simply getting the matches at each position,
 * but the exact performance difference will be dependent on the match-finder
 * implementation.  */
typedef void (*lz_skip_bytes_t)(LZ_COMPRESSOR *ctx, input_idx_t n);

/* Get the cost of the literal located at the position at which matches have
 * most recently been searched.  This can optionally update the @state to take
 * into account format-dependent state that affects match costs, such as repeat
 * offsets.  */
typedef lz_mc_cost_t (lz_get_prev_literal_cost_t)(LZ_COMPRESSOR *ctx,
						  LZ_ADAPTIVE_STATE *state);

/* Get the cost of a match.  This can optionally update the @state to take into
 * account format-dependent state that affects match costs, such as repeat
 * offsets.  */
typedef lz_mc_cost_t (lz_get_match_cost_t)(LZ_COMPRESSOR *ctx,
					   LZ_ADAPTIVE_STATE *state,
					   input_idx_t length,
					   input_idx_t offset);

/*
 * lz_get_near_optimal_match() -
 *
 * Choose an approximately optimal match or literal to use at the next position
 * in the string, or "window", being LZ-encoded.
 *
 * This is based on the algorithm used in 7-Zip's DEFLATE encoder, written by
 * Igor Pavlov.  However it also attempts to account for adaptive state, such as
 * a LRU queue of recent match offsets.
 *
 * Unlike a greedy parser that always takes the longest match, or even a "lazy"
 * parser with one match/literal look-ahead like zlib, the algorithm used here
 * may look ahead many matches/literals to determine the approximately optimal
 * match/literal to code next.  The motivation is that the compression ratio is
 * improved if the compressor can do things like use a shorter-than-possible
 * match in order to allow a longer match later, and also take into account the
 * estimated real cost of coding each match/literal based on the underlying
 * entropy encoding.
 *
 * Still, this is not a true optimal parser for several reasons:
 *
 * - Very long matches (at least @nice_len) are taken immediately.  This is
 *   because locations with long matches are likely to have many possible
 *   alternatives that would cause slow optimal parsing, but also such locations
 *   are already highly compressible so it is not too harmful to just grab the
 *   longest match.
 *
 * - Not all possible matches at each location are considered.  Users of this
 *   code are expected to provide a @get_matches() function that returns a list
 *   of potentially good matches at the current position, but no more than one
 *   per length.  It therefore must use some sort of heuristic (e.g. smallest or
 *   repeat offset) to choose a good match to consider for a given length, if
 *   multiple exist.  Furthermore, the @get_matches() implementation may limit
 *   the total number of matches returned and/or the number of computational
 *   steps spent searching for matches at each position.
 *
 * - This function relies on the user-provided @get_match_cost() and
 *   @get_prev_literal_cost() functions to evaluate match and literal costs,
 *   respectively, but real compression formats use entropy encoding of the
 *   literal/match sequence, so the real cost of coding each match or literal is
 *   unknown until the parse is fully determined.  It can be approximated based
 *   on iterative parses, but the end result is not guaranteed to be globally
 *   optimal.
 *
 * - Although this function allows @get_match_cost() and
 *   @get_prev_literal_cost() to take into account adaptive state, coding
 *   decisions made with respect to the adaptive state will be locally optimal
 *   but will not necessarily be globally optimal.  This is because the
 *   algorithm only keeps the least-costly path to get to a given location and
 *   does not take into account that a slightly more costly path could result in
 *   a different adaptive state that ultimately results in a lower global cost.
 *
 * - The array space used by this function is bounded, so in degenerate cases it
 *   is forced to start returning matches/literals before the algorithm has
 *   really finished.
 *
 * Each call to this function does one of two things:
 *
 * 1. Build a sequence of near-optimal matches/literals, up to some point, that
 *    will be returned by subsequent calls to this function, then return the
 *    first one.
 *
 * OR
 *
 * 2. Return the next match/literal previously computed by a call to this
 *    function.
 *
 * The return value is a (length, offset) pair specifying the match or literal
 * chosen.  For literals, the length is 0 or 1 and the offset is meaningless.
 *
 * NOTE: this code has been factored out of the LZX compressor so that it can be
 * shared by other formats such as LZMS.  It is inlined so there is no loss of
 * performance, especially with the different implementations of match-finding,
 * cost evaluation, and adaptive state.
 */
static _always_inline_attribute struct raw_match
lz_get_near_optimal_match(struct lz_match_chooser *mc,
			  lz_get_matches_t get_matches,
			  lz_skip_bytes_t skip_bytes,
			  lz_get_prev_literal_cost_t get_prev_literal_cost,
			  lz_get_match_cost_t get_match_cost,
			  LZ_COMPRESSOR *ctx,
			  const LZ_ADAPTIVE_STATE *initial_state)
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
	 * than nice_len, return it immediately; don't both doing more work.  */
	if (longest_match_len >= mc->nice_len) {
		(*skip_bytes)(ctx, longest_match_len - 1);
		return possible_matches[0];
	}

	/* Calculate the cost to reach the next position by coding a literal.
	 */
	mc->optimum[1].state = *initial_state;
	mc->optimum[1].cost = (*get_prev_literal_cost)(ctx, &mc->optimum[1].state);
	mc->optimum[1].prev.link = 0;

	/* Calculate the cost to reach any position up to and including that
	 * reached by the longest match.  Use the shortest available match that
	 * reaches each position, assuming that @get_matches() only returned
	 * shorter matches because their estimated costs were less than that of
	 * the longest match.  */
	for (input_idx_t len = 2, match_idx = num_possible_matches - 1;
	     len <= longest_match_len; len++)
	{

		LZ_ASSERT(match_idx < num_possible_matches);
		LZ_ASSERT(len <= possible_matches[match_idx].len);

		mc->optimum[len].state = *initial_state;
		mc->optimum[len].prev.link = 0;
		mc->optimum[len].prev.match_offset = possible_matches[match_idx].offset;
		mc->optimum[len].cost = (*get_match_cost)(ctx,
							  &mc->optimum[len].state,
							  len,
							  possible_matches[match_idx].offset);
		if (len == possible_matches[match_idx].len)
			match_idx--;
	}

	/* Step forward, calculating the estimated minimum cost to reach each
	 * position.  The algorithm may find multiple paths to reach each
	 * position; only the lowest-cost path is saved.
	 *
	 * The progress of the parse is tracked in the @mc->optimum array, which
	 * for each position contains the minimum cost to reach that position,
	 * the index of the start of the match/literal taken to reach that
	 * position through the minimum-cost path, the offset of the match taken
	 * (not relevant for literals), and the adaptive state that will exist
	 * at that position after the minimum-cost path is taken.  The @cur_pos
	 * variable stores the position at which the algorithm is currently
	 * considering coding choices, and the @len_end variable stores the
	 * greatest offset at which the costs of coding choices have been saved.
	 * (The algorithm guarantees that all positions before @len_end are
	 * reachable by at least one path and therefore have costs computed.)
	 *
	 * The loop terminates when any one of the following conditions occurs:
	 *
	 * 1. A match greater than @nice_len is found.  When this is found, the
	 *    algorithm chooses this match unconditionally, and consequently the
	 *    near-optimal match/literal sequence up to and including that match
	 *    is fully determined.
	 *
	 * 2. @cur_pos reaches a position not overlapped by a preceding match.
	 *    In such cases, the near-optimal match/literal sequence up to
	 *    @cur_pos is fully determined.
	 *
	 * 3. Failing either of the above in a degenerate case, the loop
	 *    terminates when space in the @mc->optimum array is exhausted.
	 *    This terminates the algorithm and forces it to start returning
	 *    matches/literals even though they may not be globally optimal.
	 *
	 * Upon loop termination, a nonempty list of matches/literals has been
	 * produced and stored in the @optimum array.  They are linked in
	 * reverse order, so the last thing this function does is reverse the
	 * links and return the first match/literal, leaving the rest to be
	 * returned immediately by subsequent calls to this function.
	 */
	input_idx_t cur_pos = 0;
	input_idx_t len_end = longest_match_len;
	for (;;) {
		/* Advance to next position.  */
		cur_pos++;

		/* Check termination conditions (2) and (3) noted above.  */
		if (cur_pos == len_end || cur_pos == mc->array_space)
			return lz_match_chooser_reverse_list(mc, cur_pos);

		/* Retrieve a (possibly empty) list of potentially useful
		 * matches available at this position.  */
		num_possible_matches = (*get_matches)(ctx,
						      &mc->optimum[cur_pos].state,
						      &possible_matches);

		if (num_possible_matches == 0)
			longest_match_len = 0;
		else
			longest_match_len = possible_matches[0].len;

		/* Greedy heuristic and termination condition (1) noted above:
		 * if we found a match greater than @nice_len, choose it
		 * unconditionally and begin returning matches/literals.  */
		if (longest_match_len >= mc->nice_len) {
			/* Build the list of matches to return and get
			 * the first one.  */
			match = lz_match_chooser_reverse_list(mc, cur_pos);

			/* Append the long match to the end of the list.  */
			mc->optimum[cur_pos].next.match_offset =
				possible_matches[0].offset;
			mc->optimum[cur_pos].next.link = cur_pos + longest_match_len;
			mc->optimum_end_idx = cur_pos + longest_match_len;

			/* Skip over the remaining bytes of the long match.  */
			(*skip_bytes)(ctx, longest_match_len - 1);

			/* Return first match in the list.  */
			return match;
		}

		/* Load minimum cost to reach the current position.  */
		input_idx_t cur_cost = mc->optimum[cur_pos].cost;

		/* Consider proceeding with a literal byte.  */
		{
			LZ_ADAPTIVE_STATE state;
			lz_mc_cost_t cost;

			state = mc->optimum[cur_pos].state;
			cost = cur_cost + (*get_prev_literal_cost)(ctx, &state);

			if (cost < mc->optimum[cur_pos + 1].cost) {
				mc->optimum[cur_pos + 1].cost = cost;
				mc->optimum[cur_pos + 1].prev.link = cur_pos;
				mc->optimum[cur_pos + 1].state = state;
			}
		}

		/* If no matches were found, continue to the next position.
		 * Otherwise, consider proceeding with a match.  */

		if (num_possible_matches == 0)
			continue;

		/* Initialize any uninitialized costs up to the length of the
		 * longest match found.  */
		while (len_end < cur_pos + longest_match_len)
			mc->optimum[++len_end].cost = LZ_MC_INFINITE_COST;

		/* Calculate the minimum cost to reach any position up to and
		 * including that reached by the longest match.  Use the
		 * shortest available match that reaches each position, assuming
		 * that @get_matches() only returned shorter matches because
		 * their estimated costs were less than that of the longest
		 * match.  */
		for (input_idx_t len = 2, match_idx = num_possible_matches - 1;
		     len <= longest_match_len; len++)
		{
			LZ_ASSERT(match_idx < num_possible_matches);
			LZ_ASSERT(len <= possible_matches[match_idx].len);

			LZ_ADAPTIVE_STATE state;
			lz_mc_cost_t cost;

			state = mc->optimum[cur_pos].state;
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
