/*
 * lz_bt.c
 *
 * Binary tree match-finder for Lempel-Ziv compression.
 *
 * Author:  Eric Biggers
 * Year:    2014
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

/*
 * Note: the binary tree search/update algorithm is based on code from the
 * public domain LZMA SDK (authors: Igor Pavlov, Lasse Collin).
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/lz.h"
#include "wimlib/lz_bt.h"
#include "wimlib/util.h"
#include <string.h>
#include <pthread.h>

#define LZ_BT_HASH_BITS		16
#define LZ_BT_HASH_SIZE		(1 << LZ_BT_HASH_BITS)
#define LZ_BT_HASH_MASK		(LZ_BT_HASH_SIZE - 1)
#define LZ_BT_DIGRAM_TAB_SIZE	(256 * 256)

static u32 crc32_table[256];
static pthread_once_t crc32_table_filled = PTHREAD_ONCE_INIT;

static void
crc32_init(void)
{
        for (u32 b = 0; b < 256; b++) {
                u32 r = b;
                for (int i = 0; i < 8; i++) {
                        if (r & 1)
                                r = (r >> 1) ^ 0xEDB88320;
                        else
                                r >>= 1;
                }
                crc32_table[b] = r;
        }
}

/*
 * Compute the hash code for the next 3-byte sequence in the window.
 *
 * @p
 *	A pointer to the next 3-byte sequence in the window.
 *
 * Returns the resulting hash code.
 */
static inline u32
lz_bt_hash(const u8 *p)
{
	u32 hash = 0;

	hash ^= crc32_table[p[0]];
	hash ^= p[1];
	hash ^= (u32)p[2] << 8;

	return hash & LZ_BT_HASH_MASK;
}

/*
 * Compute the number of bytes of memory that would be needed to initialize a
 * binary tree match-finder with the specified maximum window size.
 *
 * @max_window_size
 *	The maximum window size, in bytes, to query.
 *
 * Returns the number of bytes that would be allocated by lz_bt_init(),
 * excluding the size of the 'struct lz_bt' itself.
 */
u64
lz_bt_get_needed_memory(lz_bt_pos_t max_window_size)
{
	u64 len;

	len = LZ_BT_HASH_SIZE + LZ_BT_DIGRAM_TAB_SIZE;
	len += 2 * (u64)max_window_size;

	return len * sizeof(lz_bt_pos_t);
}

/*
 * Initialize a binary tree match-finder.
 *
 * @mf
 *	The match-finder structure to initialize.
 * @max_window_size
 *	The maximum window size that shall be supported by subsequent calls to
 *	lz_bt_load_window().
 * @min_match_len
 *	The minimum length of matches that shall be produced by subsequent calls
 *	to lz_bt_get_matches().  This must be at least 2.
 * @max_match_len
 *	The maximum length of matches that shall be produced by subsequent calls
 *	to lz_bt_get_matches().  This must be at least @min_match_len.
 * @num_fast_bytes
 *	The maximum length of matches that shall be produced just using the
 *	binary tree search algorithm.  If the longest match has this length,
 *	then lz_bt_get_matches() will extend it up to @max_match_len.  This must
 *	be at least @min_match_len and no more than @max_match_len.
 * @max_search_depth
 *	The maximum depth to descend into the binary search tree before halting
 *	the search.
 *
 * Returns %true if successful; %false if out of memory.
 */
bool
lz_bt_init(struct lz_bt *mf,
	   lz_bt_pos_t max_window_size,
	   lz_bt_len_t min_match_len,
	   lz_bt_len_t max_match_len,
	   lz_bt_len_t num_fast_bytes,
	   u32 max_search_depth)
{
	u64 len;

	/* Check and set parameters.  */
	LZ_ASSERT(min_match_len >= 2);
	LZ_ASSERT(max_match_len >= min_match_len);
	LZ_ASSERT(num_fast_bytes >= min_match_len);
	LZ_ASSERT(num_fast_bytes <= max_match_len);

	mf->max_window_size = max_window_size;
	mf->min_match_len = min_match_len;
	mf->max_match_len = max_match_len;
	mf->num_fast_bytes = num_fast_bytes;
	mf->max_search_depth = max_search_depth;

	/* Allocate space for 'hash_tab', 'digram_tab', and 'child_tab'.  */
	len = LZ_BT_HASH_SIZE + (2 * (u64)max_window_size);
	if (mf->min_match_len <= 2)
		len += LZ_BT_DIGRAM_TAB_SIZE;
	len *= sizeof(lz_bt_pos_t);
	if ((size_t)len != len || !(mf->hash_tab = MALLOC(len)))
		return false;
	if (mf->min_match_len <= 2) {
		mf->digram_tab = mf->hash_tab + LZ_BT_HASH_SIZE;
		mf->child_tab = mf->digram_tab + LZ_BT_DIGRAM_TAB_SIZE;
	} else {
		mf->child_tab = mf->hash_tab + LZ_BT_HASH_SIZE;
	}

	/* Fill in the CRC32 table if not done already.  */
	pthread_once(&crc32_table_filled, crc32_init);

	return true;
}

/*
 * Destroy a binary tree match-finder.
 *
 * @mf
 *	The match-finder structure to destroy.
 */
void
lz_bt_destroy(struct lz_bt *mf)
{
	FREE(mf->hash_tab);
	/* mf->hash_tab shares storage with mf->digram_tab and mf->child_tab. */
}

/*
 * Load a window into a binary tree match-finder.
 *
 * @mf
 *	The match-finder structure into which to load the window.
 * @window
 *	Pointer to the window to load.  This memory must remain available,
 *	unmodified, while the match-finder is being used.
 * @window_size
 *	The size of the window, in bytes.  This can't be larger than the
 *	@max_window_size with which lz_bt_init() was called.
 */
void
lz_bt_load_window(struct lz_bt *mf, const u8 *window, lz_bt_pos_t window_size)
{
	LZ_ASSERT(window_size <= mf->max_window_size);
	size_t clear_len;

	mf->cur_window = window;
	mf->cur_window_pos = 0;
	mf->cur_window_size = window_size;

	/* Clear the hash and digram tables.
	 * Note: The child table need not be cleared.  */
	clear_len = LZ_BT_HASH_SIZE;
	if (mf->min_match_len <= 2)
		clear_len += LZ_BT_DIGRAM_TAB_SIZE;
	memset(mf->hash_tab, 0, clear_len * sizeof(lz_bt_pos_t));
}

/*
 * Search the binary tree of the current hash code for matches.  At the same
 * time, update this tree to add the current position in the window.
 *
 * @window
 *	The window being searched.
 * @cur_window_pos
 *	The current position in the window.
 * @min_len
 *	Ignore matches shorter than this length.  This must be at least 1.
 * @max_len
 *	Don't produce any matches longer than this length.  If we find a match
 *	this long, terminate the search and return.
 * @max_depth
 *	Stop if we reach this depth in the binary tree.
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
 * @matches
 *	The array in which to produce the matches.  The matches will be produced
 *	in order of increasing length and increasing offset.  No more than one
 *	match shall have any given length, nor shall any match be shorter than
 *	@min_len, nor shall any match be longer than @max_len, nor shall any two
 *	matches have the same offset.
 *
 * Returns the number of matches found and written to @matches.
 */
static lz_bt_len_t
do_search(const u8 window[restrict],
	  const lz_bt_pos_t cur_window_pos,
	  const lz_bt_len_t min_len,
	  const lz_bt_len_t max_len,
	  const u32 max_depth,
	  lz_bt_pos_t child_tab[restrict],
	  lz_bt_pos_t cur_match,
	  struct lz_match matches[restrict])
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
	 * Using this observation, we can maintain two variables,
	 * 'longest_lt_match_len' and 'longest_gt_match_len', that represent the
	 * length of the longest lexicographically lesser and greater,
	 * respectively, match that has been examined so far.   Then, when
	 * examining a new match, we need only start comparing at the index
	 * min(longest_lt_match_len, longest_gt_match_len) byte.  Note that we
	 * cannot know beforehand whether the match will be lexicographically
	 * lesser or greater, hence the need for taking the minimum of these two
	 * lengths.
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
	 * current depth exceeds @max_depth.  Note that this cutoff can occur
	 * before the longest match has been found, which is usually bad for the
	 * compression ratio.
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
	 * precision of @max_len bytes), then we set "pending (less than)" and
	 * "pending (greater than)" to point to nothing.  Alternatively, if the
	 * search terminates due to finding the current string (up to a
	 * precision of @max_len bytes), then we set "pending (less than)" and
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
	 * algorithm actually finds a match of length @max_len with the current
	 * string, it no longer needs that match node and can discard it.  The
	 * algorithm also will discard nodes if the search terminates due to the
	 * depth limit.  For these reasons, the binary tree might not, in fact,
	 * contain all valid positions.
	 */

	lz_bt_len_t num_matches = 0;
	lz_bt_len_t longest_lt_match_len = 0;
	lz_bt_len_t longest_gt_match_len = 0;
	lz_bt_len_t longest_match_len = min_len - 1;
	lz_bt_pos_t *pending_lt_ptr = &child_tab[cur_window_pos * 2 + 0];
	lz_bt_pos_t *pending_gt_ptr = &child_tab[cur_window_pos * 2 + 1];
	const u8 *strptr = &window[cur_window_pos];
	u32 depth_remaining = max_depth;
	for (;;) {
		const u8 *matchptr;
		lz_bt_len_t len;

		if (depth_remaining-- == 0 || cur_match == 0) {
			*pending_lt_ptr = 0;
			*pending_gt_ptr = 0;
			return num_matches;
		}

		matchptr = &window[cur_match];
		len = min(longest_lt_match_len, longest_gt_match_len);

		if (matchptr[len] == strptr[len]) {

			while (++len != max_len)
				if (matchptr[len] != strptr[len])
					break;

			if (len > longest_match_len) {
				longest_match_len = len;

				matches[num_matches++] = (struct lz_match) {
					.len = len,
					.offset = cur_window_pos - cur_match,
				};

				if (len == max_len) {
					*pending_lt_ptr = child_tab[cur_match * 2 + 0];
					*pending_gt_ptr = child_tab[cur_match * 2 + 1];
					return num_matches;
				}
			}
		}

		if (matchptr[len] < strptr[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = &child_tab[cur_match * 2 + 1];
			cur_match = *pending_lt_ptr;
			longest_lt_match_len = len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = &child_tab[cur_match * 2 + 0];
			cur_match = *pending_gt_ptr;
			longest_gt_match_len = len;
		}
	}
}

/*
 * Retrieve a list of matches at the next position in the window.
 *
 * @mf
 *	The binary tree match-finder structure into which a window has been
 *	loaded using lz_bt_load_window().
 * @matches
 *	The array into which the matches will be returned.  The length of this
 *	array must be at least (@mf->num_fast_bytes - @mf->min_match_len + 1).
 *
 * The return value is the number of matches that were found and stored in the
 * 'matches' array.  The matches will be ordered by strictly increasing length
 * and strictly increasing offset.  No match shall have length less than
 * @min_match_len, and no match shall have length greater than @max_match_len.
 * The return value may be 0, which indicates that no matches were found.
 *
 * On completion, the binary tree match-finder is advanced to the next position
 * in the window.
 */
lz_bt_len_t
lz_bt_get_matches(struct lz_bt *mf, struct lz_match matches[])
{
	lz_bt_pos_t bytes_remaining;
	lz_bt_len_t num_matches;
	lz_bt_pos_t cur_match;
	u32 hash;

	LZ_ASSERT(mf->cur_window_pos < mf->cur_window_size);

	bytes_remaining = lz_bt_get_remaining_size(mf);

	/* If there are fewer than 3 bytes remaining, we can't even compute a
	 * hash to look up a binary tree root.  If there are exactly 2 bytes
	 * remaining we could still search for a length-2 match using the digram
	 * table, but it's not worth bothering.  (Note: this is also useful for
	 * LZX, since this excludes the length 2 match having the maximum
	 * offset, which isn't allowed.)  */
	if (bytes_remaining < 3) {
		mf->cur_window_pos++;
		return 0;
	}

	num_matches = 0;

	/* Search the digram table for a length 2 match.  */
	if (mf->min_match_len <= 2) {
		u8 c1, c2;
		u16 digram;

		c1 = mf->cur_window[mf->cur_window_pos];
		c2 = mf->cur_window[mf->cur_window_pos + 1];
		digram = (u16)c1 | ((u16)c2 << 8);
		cur_match = mf->digram_tab[digram];
		mf->digram_tab[digram] = mf->cur_window_pos;

		/* We're only interested in matches of length exactly 2, since
		 * those won't be found during the binary tree search.  */
		if (cur_match != 0 && mf->cur_window[cur_match + 2] !=
				      mf->cur_window[mf->cur_window_pos + 2])
		{
			matches[num_matches++] = (struct lz_match) {
				.len = 2,
				.offset = mf->cur_window_pos - cur_match,
			};
		}
	}

	/* Hash the length-3 byte sequence beginning at the current position in
	 * the window.  */
	hash = lz_bt_hash(&mf->cur_window[mf->cur_window_pos]);

	/* The corresponding hash bucket in 'hash_tab' contains the root of the
	 * binary tree of previous window positions that have the same hash
	 * code.  */
	cur_match = mf->hash_tab[hash];

	/* Update the hash bucket to point to the binary tree rooted at the
	 * current position, which we will construct in do_search().  */
	mf->hash_tab[hash] = mf->cur_window_pos;

	/* Search the binary tree for matches.  At the same time, build the
	 * binary tree rooted at the current position, which replaces the one we
	 * search.  */
	num_matches += do_search(mf->cur_window,
				 mf->cur_window_pos,
				 max(3, mf->min_match_len),
				 min(bytes_remaining, mf->num_fast_bytes),
				 mf->max_search_depth,
				 mf->child_tab,
				 cur_match,
				 &matches[num_matches]);

	/* If the longest match is @num_fast_bytes in length, it may have been
	 * truncated.  Try extending it up to the maximum match length.  */
	if (num_matches != 0 && matches[num_matches - 1].len == mf->num_fast_bytes) {
		lz_bt_pos_t limit;
		const u8 *strptr, *matchptr;
		lz_bt_len_t len;

		limit = min(bytes_remaining, mf->max_match_len);
		strptr = &mf->cur_window[mf->cur_window_pos];
		matchptr = strptr - matches[num_matches - 1].offset;
		len = matches[num_matches - 1].len;
		while (len < limit && strptr[len] == matchptr[len])
			len++;
		matches[num_matches - 1].len = len;
	}

#ifdef ENABLE_LZ_DEBUG
	/* Check the matches.  */
	for (lz_bt_len_t i = 0; i < num_matches; i++) {
		const u8 *matchptr, *strptr;

		/* Length valid?  */
		LZ_ASSERT(matches[i].len >= mf->min_match_len);
		LZ_ASSERT(matches[i].len <= min(mf->max_match_len, bytes_remaining));

		/* Offset valid?  */
		LZ_ASSERT(matches[i].offset >= 1);
		LZ_ASSERT(matches[i].offset <= lz_bt_get_position(mf));

		/* Lengths and offsets strictly increasing?  */
		if (i > 0) {
			LZ_ASSERT(matches[i].len > matches[i - 1].len);
			LZ_ASSERT(matches[i].offset > matches[i - 1].offset);
		}

		/* Actually a match?  */
		strptr = lz_bt_get_window_ptr(mf);
		matchptr = strptr - matches[i].offset;
		LZ_ASSERT(!memcmp(strptr, matchptr, matches[i].len));

		/* Match can't be extended further?  */
		LZ_ASSERT(matches[i].len == min(mf->max_match_len, bytes_remaining) ||
			  strptr[matches[i].len] != matchptr[matches[i].len]);
	}
#endif /* ENABLE_LZ_DEBUG  */

	/* Advance to the next position in the window.  */
	mf->cur_window_pos++;

	/* Return the number of matches found.  */
	return num_matches;
}

/* This is the same as do_search(), but it does not save any matches.
 * See do_search() for explanatory comments.  */
static void
do_skip(const u8 window[restrict],
	const lz_bt_pos_t cur_window_pos,
	const lz_bt_len_t max_len,
	u32 depth_remaining,
	lz_bt_pos_t child_tab[restrict],
	lz_bt_pos_t cur_match)
{
	lz_bt_len_t longest_lt_match_len = 0;
	lz_bt_len_t longest_gt_match_len = 0;
	lz_bt_pos_t *pending_lt_ptr = &child_tab[cur_window_pos * 2 + 0];
	lz_bt_pos_t *pending_gt_ptr = &child_tab[cur_window_pos * 2 + 1];
	const u8 * const strptr = &window[cur_window_pos];
	for (;;) {
		const u8 *matchptr;
		lz_bt_len_t len;

		if (depth_remaining-- == 0 || cur_match == 0) {
			*pending_lt_ptr = 0;
			*pending_gt_ptr = 0;
			return;
		}

		matchptr = &window[cur_match];
		len = min(longest_lt_match_len, longest_gt_match_len);

		if (matchptr[len] == strptr[len]) {
			do {
				if (++len == max_len) {
					*pending_lt_ptr = child_tab[cur_match * 2 + 0];
					*pending_gt_ptr = child_tab[cur_match * 2 + 1];
					return;
				}
			} while (matchptr[len] == strptr[len]);
		}
		if (matchptr[len] < strptr[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = &child_tab[cur_match * 2 + 1];
			cur_match = *pending_lt_ptr;
			longest_lt_match_len = len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = &child_tab[cur_match * 2 + 0];
			cur_match = *pending_gt_ptr;
			longest_gt_match_len = len;
		}
	}
}

/* Skip the current position in the binary tree match-finder.  */
static void
lz_bt_skip_position(struct lz_bt *mf)
{
	lz_bt_pos_t bytes_remaining;
	u32 hash;
	lz_bt_pos_t cur_match;

	LZ_ASSERT(mf->cur_window_pos < mf->cur_window_size);

	bytes_remaining = lz_bt_get_remaining_size(mf);

	/* As explained in lz_bt_get_matches(), we don't search for matches if
	 * there are fewer than 3 bytes remaining in the window.  */
	if (bytes_remaining < 3) {
		mf->cur_window_pos++;
		return;
	}

	/* Update the digram table.  */
	if (mf->min_match_len <= 2) {
		u8 c1, c2;
		u16 digram;

		c1 = mf->cur_window[mf->cur_window_pos];
		c2 = mf->cur_window[mf->cur_window_pos + 1];
		digram = (u16)c1 | ((u16)c2 << 8);
		mf->digram_tab[digram] = mf->cur_window_pos;
	}

	/* Update the hash table.  */
	hash = lz_bt_hash(&mf->cur_window[mf->cur_window_pos]);
	cur_match = mf->hash_tab[hash];
	mf->hash_tab[hash] = mf->cur_window_pos;

	/* Update the binary tree for the appropriate hash code.  */
	do_skip(mf->cur_window,
		mf->cur_window_pos,
		min(bytes_remaining, mf->num_fast_bytes),
		mf->max_search_depth,
		mf->child_tab,
		cur_match);

	/* Advance to the next position.  */
	mf->cur_window_pos++;
}

/* Skip 'n' positions in the binary tree match-finder.  */
void
lz_bt_skip_positions(struct lz_bt *mf, unsigned n)
{
	while (n--)
		lz_bt_skip_position(mf);
}
