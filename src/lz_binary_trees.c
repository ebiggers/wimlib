/*
 * lz_binary_trees.c
 *
 * Binary tree match-finder for Lempel-Ziv compression.
 *
 * Copyright (c) 2014 Eric Biggers.  All rights reserved.
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

/*
 * Note: the binary tree search/update algorithm is based on LzFind.c from
 * 7-Zip, which was written by Igor Pavlov and released into the public domain.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/lz_extend.h"
#include "wimlib/lz_hash3.h"
#include "wimlib/lz_mf.h"
#include "wimlib/util.h"

#include <string.h>

/* log2 of the number of buckets in the hash table.  This can be changed.  */
#define LZ_BT_HASH_ORDER 16

#define LZ_BT_HASH_LEN (1 << LZ_BT_HASH_ORDER)

/* Number of entries in the digram table.
 *
 * Note:  You rarely get length-2 matches if you use length-3 hashing.  But
 * since binary trees are typically used for higher compression ratios than hash
 * chains, it is helpful for this match-finder to find length-2 matches as well.
 * Therefore this match-finder also uses a digram table to find length-2 matches
 * when the minimum match length is 2.  */
#define LZ_BT_DIGRAM_TAB_LEN	(256 * 256)

struct lz_bt {
	struct lz_mf base;
	u32 *hash_tab;
	u32 *digram_tab;
	u32 *child_tab;
	u32 next_hash;
	u16 next_digram;
};

static inline u32
lz_bt_hash(const u8 *p)
{
	return lz_hash(p, LZ_BT_HASH_ORDER);
}

static void
lz_bt_set_default_params(struct lz_mf_params *params)
{
	if (params->min_match_len == 0)
		params->min_match_len = 2;

	if (params->max_match_len == 0)
		params->max_match_len = UINT32_MAX;

	if (params->max_search_depth == 0)
		params->max_search_depth = 50;

	if (params->nice_match_len == 0)
		params->nice_match_len = 24;

	if (params->nice_match_len < params->min_match_len)
		params->nice_match_len = params->min_match_len;

	if (params->nice_match_len > params->max_match_len)
		params->nice_match_len = params->max_match_len;
}

static bool
lz_bt_params_valid(const struct lz_mf_params *params)
{
	return true;
}

static u64
lz_bt_get_needed_memory(u32 max_window_size)
{
	u64 len = 0;

	len += LZ_BT_HASH_LEN;		 /* hash_tab */
	len += LZ_BT_DIGRAM_TAB_LEN;	 /* digram_tab */
	len += 2 * (u64)max_window_size; /* child_tab */

	return len * sizeof(u32);
}

static bool
lz_bt_init(struct lz_mf *_mf)
{
	struct lz_bt *mf = (struct lz_bt *)_mf;
	struct lz_mf_params *params = &mf->base.params;
	size_t len = 0;

	lz_bt_set_default_params(params);

	/* Allocate space for 'hash_tab', 'digram_tab', and 'child_tab'.  */

	len += LZ_BT_HASH_LEN;
	if (params->min_match_len == 2)
		len += LZ_BT_DIGRAM_TAB_LEN;
	len += 2 * params->max_window_size;

	mf->hash_tab = MALLOC(len * sizeof(u32));
	if (!mf->hash_tab)
		return false;

	if (params->min_match_len == 2) {
		mf->digram_tab = mf->hash_tab + LZ_BT_HASH_LEN;
		mf->child_tab = mf->digram_tab + LZ_BT_DIGRAM_TAB_LEN;
	} else {
		mf->child_tab = mf->hash_tab + LZ_BT_HASH_LEN;
	}

	return true;
}

static void
lz_bt_load_window(struct lz_mf *_mf, const u8 window[], u32 size)
{
	struct lz_bt *mf = (struct lz_bt *)_mf;
	size_t clear_len;

	/* Clear hash_tab and digram_tab.
	 * Note: child_tab need not be cleared.  */
	clear_len = LZ_BT_HASH_LEN;
	if (mf->digram_tab)
		clear_len += LZ_BT_DIGRAM_TAB_LEN;
	memset(mf->hash_tab, 0, clear_len * sizeof(u32));
}

/*
 * Search the binary tree of the current hash code for matches.  At the same
 * time, update this tree to add the current position in the window.
 *
 * @window
 *	The window being searched.
 * @cur_pos
 *	The current position in the window.
 * @child_tab
 *	Table of child pointers for the binary tree.  The children of the node
 *	for position 'i' in the window are child_tab[i * 2] and child_tab[i*2 +
 *	1].  Zero is reserved for the 'null' value (no child).  Consequently, we
 *	don't recognize matches beginning at position 0.   In fact, the node for
 *	position 0 in the window will not be used at all, which is just as well
 *	because we use 0-based indices which don't work for position 0.
 * @cur_match
 *	The position in the window at which the binary tree for the current hash
 *	code is rooted.  This can be 0, which indicates that the binary tree for
 *	the current hash code is empty.
 * @min_len
 *	Ignore matches shorter than this length.  This must be at least 1.
 * @nice_len
 *	Stop searching if a match of this length or longer is found.  This must
 *	be less than or equal to @max_len.
 * @max_len
 *	Maximum length of matches to return.  This can be longer than @nice_len,
 *	in which case a match of length @nice_len will still cause the search to
 *	be terminated, but the match will be extended up to @max_len bytes
 *	first.
 * @max_search_depth
 *	Stop if we reach this depth in the binary tree.
 * @matches
 *	The array in which to produce the matches.  The matches will be produced
 *	in order of increasing length and increasing offset.  No more than one
 *	match shall have any given length, nor shall any match be shorter than
 *	@min_len, nor shall any match be longer than @max_len, nor shall any two
 *	matches have the same offset.
 *
 * Returns a pointer to the next free slot in @matches.
 */
static struct lz_match *
do_search(const u8 window[restrict],
	  const u32 cur_pos,
	  u32 child_tab[restrict],
	  u32 cur_match,
	  const u32 min_len,
	  const u32 nice_len,
	  const u32 max_len,
	  const u32 max_search_depth,
	  struct lz_match *lz_matchptr)
{
	/*
	 * Here's my explanation of how this code actually works.  Beware: this
	 * algorithm is a *lot* trickier than searching for matches via hash
	 * chains.  But it can be significantly better, especially when doing
	 * "optimal" parsing, which is why it gets used, e.g. in LZMA as well as
	 * here.
	 *
	 * ---------------------------------------------------------------------
	 *
	 *				Data structure
	 *
	 * Basically, there is not just one binary tree, but rather one binary
	 * tree per hash code.  For a given hash code, the binary tree indexes
	 * previous positions in the window that have that same hash code.  The
	 * key for each node is the "string", or byte sequence, beginning at the
	 * corresponding position in the window.
	 *
	 * Each tree maintains the invariant that if node C is a child of node
	 * P, then the window position represented by node C is smaller than
	 * ("left of") the window position represented by node P.  Equivalently,
	 * while descending into a tree, the match distances ("offsets") from
	 * the current position are non-decreasing --- actually strictly
	 * increasing, because each node represents a unique position.
	 *
	 * In addition, not all previous positions sharing the same hash code
	 * will necessarily be represented in each binary tree; see the
	 * "Updating" section.
	 *
	 * ---------------------------------------------------------------------
	 *
	 *				  Searching
	 *
	 * Suppose we want to search for LZ77-style matches with the string
	 * beginning at the current window position and extending for @max_len
	 * bytes.  To do this, we can search for this string in the binary tree
	 * for this string's hash code.  Each node visited during the search is
	 * a potential match.  This method will find the matches efficiently
	 * because they will converge on the current string, due to the nature
	 * of the binary search.
	 *
	 * Naively, when visiting a node that represents a match of length N, we
	 * must compare N + 1 bytes in order to determine the length of that
	 * match and the lexicographic ordering of that match relative to the
	 * current string (which determines whether we need to step left or
	 * right into the next level of the tree, as per the standard binary
	 * tree search algorithm).  However, as an optimization, we need not
	 * explicitly examine the full length of the match at each node.  To see
	 * that this is true, suppose that we examine a node during the search,
	 * and we find that the corresponding match is less (alt. greater) than
	 * the current string.  Then, because of how binary tree search
	 * operates, the match must be lexicographically greater (alt. lesser)
	 * than any ancestor node that corresponded to a match lexicographically
	 * lesser (alt. greater) than the current string.  Therefore, the match
	 * must be at least as long as the match for any such ancestor node.
	 * Therefore, the lengths of lexicographically-lesser (alt. greater)
	 * matches must be non-decreasing as they are encountered by the tree
	 * search.
	 *
	 * Using this observation, we can maintain two variables, 'best_lt_len'
	 * and 'best_gt_len', that represent the length of the longest
	 * lexicographically lesser and greater, respectively, match that has
	 * been examined so far.   Then, when examining a new match, we need
	 * only start comparing at the index min(best_lt_len, best_gt_len) byte.
	 * Note that we cannot know beforehand whether the match will be
	 * lexicographically lesser or greater, hence the need for taking the
	 * minimum of these two lengths.
	 *
	 * As noted earlier, as we descend into the tree, the potential matches
	 * will have strictly increasing offsets.  To make things faster for
	 * higher-level parsing / match-choosing code, we do not want to return
	 * a shorter match that has a larger offset than a longer match.  This
	 * is because a longer match can always be truncated to a shorter match
	 * if needed, and smaller offsets usually (depending on the compression
	 * format) take fewer bits to encode than larger offsets.
	 * Consequently, we keep a potential match only if it is longer than the
	 * previous longest match that has been found.  This has the added
	 * advantage of producing the array of matches sorted by strictly
	 * increasing lengths as well as strictly decreasing offsets.
	 *
	 * In degenerate cases, the binary tree might become severely
	 * unbalanced.  To prevent excessive running times, we stop immediately
	 * (and return any matches that happen to have been found so far) if the
	 * current depth exceeds @max_search_depth.  Note that this cutoff can
	 * occur before the longest match has been found, which is usually bad
	 * for the compression ratio.
	 *
	 * ---------------------------------------------------------------------
	 *
	 *				Updating
	 *
	 * I've explained how to find matches by searching the binary tree of
	 * the current hash code.  But how do we get the binary tree in the
	 * first place?  Since the tree is built incrementally, the real
	 * question is how do we update the tree to "add" the current window
	 * position.
	 *
	 * The tree maintains the invariant that a node's parent always has a
	 * larger position (a.k.a. smaller match offset) than itself.
	 * Therefore, the root node must always have the largest position; and
	 * since the current position is larger than any previous position, the
	 * current position must become the root of the tree.
	 *
	 * A correct, but silly, approach is to simply add the previous root as
	 * a child of the new root, using either the left or right child pointer
	 * depending on the lexicographic ordering of the strings.  This works,
	 * but it really just produces a linked list, so it's not sufficient.
	 *
	 * Instead, we can initially mark the new root's left child pointer as
	 * "pending (less than)" and its right child pointer as "pending
	 * (greater than)".  Then, during the search, when we examine a match
	 * that is lexicographically less than the current string, we link the
	 * "pending (less than)" pointer to the node of that match, then set the
	 * right child pointer of *that* node as "pending (less than)".
	 * Similarly, when we examine a match that is lexicographically greater
	 * than the current string, we link the "pending (greater than)" pointer
	 * to the node of that match, then set the left child pointer of *that*
	 * node as "pending (greater than)".
	 *
	 * If the search terminates before the current string is found (up to a
	 * precision of @nice_len bytes), then we set "pending (less than)" and
	 * "pending (greater than)" to point to nothing.  Alternatively, if the
	 * search terminates due to finding the current string (up to a
	 * precision of @nice_len bytes), then we set "pending (less than)" and
	 * "pending (greater than)" to point to the appropriate children of that
	 * match.
	 *
	 * Why does this work?  Well, we can think of it this way: the "pending
	 * (less than)" pointer is reserved for the next match we find that is
	 * lexicographically *less than* the current string, and the "pending
	 * (greater than)" pointer is reserved for the next match we find that
	 * is lexicographically *greater than* the current string.  This
	 * explains why when we find a match that is lexicographically less than
	 * the current string, we set the "pending (less than)" pointer to point
	 * to that match.  And the reason we change "pending (less than)" to the
	 * right pointer of the match in that case is because we're walking down
	 * into that subtree, and the next match lexicographically *less than*
	 * the current string is guaranteed to be lexicographically *greater
	 * than* that match, so it should be set as the right subtree of that
	 * match.  But the next match in that subtree that is lexicographically
	 * *greater than* the current string will need to be moved to the
	 * "pending (greater than)" pointer farther up the tree.
	 *
	 * It's complicated, but it should make sense if you think about it.
	 * The algorithm basically just moves subtrees into the correct
	 * locations as it walks down the tree for the search.  But also, if the
	 * algorithm actually finds a match of length @nice_len with the current
	 * string, it no longer needs that match node and can discard it.  The
	 * algorithm also will discard nodes if the search terminates due to the
	 * depth limit.  For these reasons, the binary tree might not, in fact,
	 * contain all valid positions.
	 */

	u32 best_lt_len = 0;
	u32 best_gt_len = 0;
	u32 best_len = min_len - 1;
	u32 *pending_lt_ptr = &child_tab[cur_pos * 2 + 0];
	u32 *pending_gt_ptr = &child_tab[cur_pos * 2 + 1];
	const u8 * const strptr = &window[cur_pos];
	u32 depth_remaining = max_search_depth;

	for (;;) {
		const u8 *matchptr;
		u32 len;

		if (cur_match == 0 || depth_remaining-- == 0) {
			*pending_lt_ptr = 0;
			*pending_gt_ptr = 0;
			return lz_matchptr;
		}

		matchptr = &window[cur_match];
		len = min(best_lt_len, best_gt_len);

		if (matchptr[len] == strptr[len]) {

			len = lz_extend(strptr, matchptr, len + 1, max_len);

			if (len > best_len) {
				best_len = len;

				*lz_matchptr++ = (struct lz_match) {
					.len = len,
					.offset = strptr - matchptr,
				};

				if (len >= nice_len) {
					*pending_lt_ptr = child_tab[cur_match * 2 + 0];
					*pending_gt_ptr = child_tab[cur_match * 2 + 1];
					return lz_matchptr;
				}
			}
		}

		if (matchptr[len] < strptr[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = &child_tab[cur_match * 2 + 1];
			cur_match = *pending_lt_ptr;
			best_lt_len = len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = &child_tab[cur_match * 2 + 0];
			cur_match = *pending_gt_ptr;
			best_gt_len = len;
		}
	}
}

static u32
lz_bt_get_matches(struct lz_mf *_mf, struct lz_match matches[])
{
	struct lz_bt *mf = (struct lz_bt *)_mf;
	const u8 * const window = mf->base.cur_window;
	const u32 cur_pos = mf->base.cur_window_pos++;
	const u32 bytes_remaining = mf->base.cur_window_size - cur_pos;
	u32 min_len;
	const u32 max_len = min(bytes_remaining, mf->base.params.max_match_len);
	const u32 nice_len = min(max_len, mf->base.params.nice_match_len);
	u32 hash;
	u32 cur_match;
	struct lz_match *lz_matchptr = matches;

	if (unlikely(bytes_remaining < LZ_HASH_REQUIRED_NBYTES + 1))
		return 0;

	if (mf->digram_tab) {
		/* Search the digram table for a length 2 match.  */

		const u16 digram = mf->next_digram;
		mf->next_digram = *(const u16 *)(&window[cur_pos + 1]);
		prefetch(&mf->digram_tab[mf->next_digram]);
		cur_match = mf->digram_tab[digram];
		mf->digram_tab[digram] = cur_pos;

		/* We're only interested in matches of length exactly 2, since
		 * those won't be found during the binary tree search.
		 *
		 * Note: it's possible to extend this match as much as possible,
		 * then use its length plus 1 as min_len for the binary tree
		 * search.  However I found this actually *reduced* performance
		 * slightly, evidently because the binary tree still needs to be
		 * searched/updated starting from the root in either case.  */
		if (cur_match != 0 && window[cur_match + 2] != window[cur_pos + 2]) {
			*lz_matchptr++ = (struct lz_match) {
				.len = 2,
				.offset = cur_pos - cur_match,
			};
		}
		min_len = 3;
	} else {
		min_len = mf->base.params.min_match_len;
	}

	hash = mf->next_hash;
	mf->next_hash = lz_bt_hash(&window[cur_pos + 1]);
	prefetch(&mf->hash_tab[mf->next_hash]);
	cur_match = mf->hash_tab[hash];
	mf->hash_tab[hash] = cur_pos;

	/* Search the binary tree of 'hash' for matches while re-rooting it at
	 * the current position.  */
	lz_matchptr = do_search(window,
				cur_pos,
				mf->child_tab,
				cur_match,
				min_len,
				nice_len,
				max_len,
				mf->base.params.max_search_depth,
				lz_matchptr);

	/* Return the number of matches found.  */
	return lz_matchptr - matches;
}

/* This is very similar to do_search(), but it does not save any matches.
 * See do_search() for explanatory comments.  */
static void
do_skip(const u8 window[restrict],
	const u32 cur_pos,
	u32 child_tab[restrict],
	u32 cur_match,
	const u32 nice_len,
	const u32 max_search_depth)
{
	u32 best_lt_len = 0;
	u32 best_gt_len = 0;
	u32 *pending_lt_ptr = &child_tab[cur_pos * 2 + 0];
	u32 *pending_gt_ptr = &child_tab[cur_pos * 2 + 1];
	const u8 * const strptr = &window[cur_pos];
	u32 depth_remaining = max_search_depth;
	for (;;) {
		const u8 *matchptr;
		u32 len;

		if (cur_match == 0 || depth_remaining-- == 0) {
			*pending_lt_ptr = 0;
			*pending_gt_ptr = 0;
			return;
		}

		matchptr = &window[cur_match];
		len = min(best_lt_len, best_gt_len);

		if (matchptr[len] == strptr[len]) {
			len = lz_extend(strptr, matchptr, len + 1, nice_len);
			if (len == nice_len) {
				*pending_lt_ptr = child_tab[cur_match * 2 + 0];
				*pending_gt_ptr = child_tab[cur_match * 2 + 1];
				return;
			}
		}
		if (matchptr[len] < strptr[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = &child_tab[cur_match * 2 + 1];
			cur_match = *pending_lt_ptr;
			best_lt_len = len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = &child_tab[cur_match * 2 + 0];
			cur_match = *pending_gt_ptr;
			best_gt_len = len;
		}
	}
}

static void
lz_bt_skip_positions(struct lz_mf *_mf, u32 n)
{
	struct lz_bt *mf = (struct lz_bt *)_mf;
	const u8 * const window = mf->base.cur_window;
	u32 cur_pos = mf->base.cur_window_pos;
	u32 end_pos = cur_pos + n;
	u32 bytes_remaining = mf->base.cur_window_size - cur_pos;
	u32 hash;
	u32 next_hash;
	u32 cur_match;
	u16 digram;
	u16 next_digram;

	mf->base.cur_window_pos = end_pos;

	if (unlikely(bytes_remaining < n + (LZ_HASH_REQUIRED_NBYTES + 1) - 1)) {
	        /* Nearing end of window.  */
	        if (unlikely(bytes_remaining < (LZ_HASH_REQUIRED_NBYTES + 1)))
	                return;

	        end_pos = cur_pos + bytes_remaining - (LZ_HASH_REQUIRED_NBYTES + 1) + 1;
	}

	next_hash = mf->next_hash;
	next_digram = mf->next_digram;
	do {
		if (mf->digram_tab) {
			digram = next_digram;
			next_digram = *(const u16 *)(&window[cur_pos + 1]);
			mf->digram_tab[digram] = cur_pos;
		}

		hash = next_hash;
		next_hash = lz_bt_hash(&window[cur_pos + 1]);
		cur_match = mf->hash_tab[hash];
		mf->hash_tab[hash] = cur_pos;

		/* Update the binary tree for the appropriate hash code.  */
		do_skip(window,
			cur_pos,
			mf->child_tab,
			cur_match,
			min(bytes_remaining, mf->base.params.nice_match_len),
			mf->base.params.max_search_depth);

		bytes_remaining--;
	} while (++cur_pos != end_pos);

	if (mf->digram_tab) {
		prefetch(&mf->digram_tab[next_digram]);
		mf->next_digram = next_digram;
	}

	prefetch(&mf->hash_tab[next_hash]);
	mf->next_hash = next_hash;
}

static void
lz_bt_destroy(struct lz_mf *_mf)
{
	struct lz_bt *mf = (struct lz_bt *)_mf;

	FREE(mf->hash_tab);
	/* mf->hash_tab shares storage with mf->digram_tab and mf->child_tab. */
}

const struct lz_mf_ops lz_binary_trees_ops = {
	.params_valid      = lz_bt_params_valid,
	.get_needed_memory = lz_bt_get_needed_memory,
	.init		   = lz_bt_init,
	.load_window       = lz_bt_load_window,
	.get_matches       = lz_bt_get_matches,
	.skip_positions    = lz_bt_skip_positions,
	.destroy           = lz_bt_destroy,
	.struct_size	   = sizeof(struct lz_bt),
};
