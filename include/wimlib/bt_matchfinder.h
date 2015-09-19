/*
 * bt_matchfinder.h
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 *
 * ----------------------------------------------------------------------------
 *
 * This is a Binary Trees (bt) based matchfinder.
 *
 * The data structure is a hash table where each hash bucket contains a binary
 * tree of sequences whose first 3 bytes share the same hash code.  Each
 * sequence is identified by its starting position in the input buffer.  Each
 * binary tree is always sorted such that each left child represents a sequence
 * lexicographically lesser than its parent and each right child represents a
 * sequence lexicographically greater than its parent.
 *
 * The algorithm processes the input buffer sequentially.  At each byte
 * position, the hash code of the first 3 bytes of the sequence beginning at
 * that position (the sequence being matched against) is computed.  This
 * identifies the hash bucket to use for that position.  Then, a new binary tree
 * node is created to represent the current sequence.  Then, in a single tree
 * traversal, the hash bucket's binary tree is searched for matches and is
 * re-rooted at the new node.
 *
 * Compared to the simpler algorithm that uses linked lists instead of binary
 * trees (see hc_matchfinder.h), the binary tree version gains more information
 * at each node visitation.  Ideally, the binary tree version will examine only
 * 'log(n)' nodes to find the same matches that the linked list version will
 * find by examining 'n' nodes.  In addition, the binary tree version can
 * examine fewer bytes at each node by taking advantage of the common prefixes
 * that result from the sort order, whereas the linked list version may have to
 * examine up to the full length of the match at each node.
 *
 * However, it is not always best to use the binary tree version.  It requires
 * nearly twice as much memory as the linked list version, and it takes time to
 * keep the binary trees sorted, even at positions where the compressor does not
 * need matches.  Generally, when doing fast compression on small buffers,
 * binary trees are the wrong approach.  They are best suited for thorough
 * compression and/or large buffers.
 *
 * ----------------------------------------------------------------------------
 */


#include <string.h>

#include "wimlib/lz_extend.h"
#include "wimlib/lz_hash.h"

#define BT_MATCHFINDER_HASH_ORDER 16

/* TEMPLATED functions and structures have MF_SUFFIX appended to their name.  */
#undef TEMPLATED
#define TEMPLATED(name)		CONCAT(name, MF_SUFFIX)

#ifndef _WIMLIB_BT_MATCHFINDER_H
#define _WIMLIB_BT_MATCHFINDER_H

/* Non-templated definitions  */

/* Representation of a match found by the bt_matchfinder  */
struct lz_match {

	/* The number of bytes matched.  */
	u32 length;

	/* The offset back from the current position that was matched.  */
	u32 offset;
};

static inline u32
bt_matchfinder_hash_3_bytes(const u8 *in_next)
{
	return lz_hash_3_bytes(in_next, BT_MATCHFINDER_HASH_ORDER);
}

#endif /* _WIMLIB_BT_MATCHFINDER_H */

struct TEMPLATED(bt_matchfinder) {
	pos_t hash_tab[1UL << BT_MATCHFINDER_HASH_ORDER];
	pos_t child_tab[];
};

/* Return the number of bytes that must be allocated for a 'bt_matchfinder' that
 * can work with buffers up to the specified size.  */
static inline size_t
TEMPLATED(bt_matchfinder_size)(size_t max_bufsize)
{
	return sizeof(struct TEMPLATED(bt_matchfinder)) +
		(2 * max_bufsize * sizeof(pos_t));
}

/* Prepare the matchfinder for a new input buffer.  */
static inline void
TEMPLATED(bt_matchfinder_init)(struct TEMPLATED(bt_matchfinder) *mf)
{
	memset(mf, 0, sizeof(*mf));
}

static inline pos_t *
TEMPLATED(bt_child)(struct TEMPLATED(bt_matchfinder) *mf, pos_t node, int offset)
{
	return &mf->child_tab[(node << 1) + offset];
}

static inline pos_t *
TEMPLATED(bt_left_child)(struct TEMPLATED(bt_matchfinder) *mf, pos_t node)
{
	return TEMPLATED(bt_child)(mf, node, 0);
}

static inline pos_t *
TEMPLATED(bt_right_child)(struct TEMPLATED(bt_matchfinder) *mf, pos_t node)
{
	return TEMPLATED(bt_child)(mf, node, 1);
}

/*
 * Retrieve a list of matches with the current position.
 *
 * @mf
 *	The matchfinder structure.
 * @in_begin
 *	Pointer to the beginning of the input buffer.
 * @in_next
 *	Pointer to the next byte in the input buffer to process.  This is the
 *	pointer to the sequence being matched against.
 * @min_len
 *	Only record matches that are at least this long.
 * @max_len
 *	The maximum permissible match length at this position.
 * @nice_len
 *	Stop searching if a match of at least this length is found.
 *	Must be <= @max_len.
 * @max_search_depth
 *	Limit on the number of potential matches to consider.  Must be >= 1.
 * @next_hash
 *	Pointer to the hash code for the current sequence, which was computed
 *	one position in advance so that the binary tree root could be
 *	prefetched.  This is an input/output parameter.
 * @best_len_ret
 *	The length of the longest match found is written here.  (This is
 *	actually redundant with the 'struct lz_match' array, but this is easier
 *	for the compiler to optimize when inlined and the caller immediately
 *	does a check against 'best_len'.)
 * @lz_matchptr
 *	An array in which this function will record the matches.  The recorded
 *	matches will be sorted by strictly increasing length and strictly
 *	increasing offset.  The maximum number of matches that may be found is
 *	'min(nice_len, max_len) - 3 + 1'.
 *
 * The return value is a pointer to the next available slot in the @lz_matchptr
 * array.  (If no matches were found, this will be the same as @lz_matchptr.)
 */
static inline struct lz_match *
TEMPLATED(bt_matchfinder_get_matches)(struct TEMPLATED(bt_matchfinder) * const restrict mf,
				      const u8 * const in_begin,
				      const u8 * const in_next,
				      const unsigned min_len,
				      const unsigned max_len,
				      const unsigned nice_len,
				      const unsigned max_search_depth,
				      u32 * restrict next_hash,
				      unsigned * restrict best_len_ret,
				      struct lz_match * restrict lz_matchptr)
{
	unsigned depth_remaining = max_search_depth;
	u32 hash;
	pos_t cur_node;
	const u8 *matchptr;
	pos_t *pending_lt_ptr, *pending_gt_ptr;
	unsigned best_lt_len, best_gt_len;
	unsigned len;
	unsigned best_len = min_len - 1;

	if (unlikely(max_len < LZ_HASH3_REQUIRED_NBYTES + 1)) {
		*best_len_ret = best_len;
		return lz_matchptr;
	}

	hash = *next_hash;
	*next_hash = bt_matchfinder_hash_3_bytes(in_next + 1);
	cur_node = mf->hash_tab[hash];
	mf->hash_tab[hash] = in_next - in_begin;
	prefetchw(&mf->hash_tab[*next_hash]);

	pending_lt_ptr = TEMPLATED(bt_left_child)(mf, in_next - in_begin);
	pending_gt_ptr = TEMPLATED(bt_right_child)(mf, in_next - in_begin);
	best_lt_len = 0;
	best_gt_len = 0;
	len = 0;

	if (!cur_node) {
		*pending_lt_ptr = 0;
		*pending_gt_ptr = 0;
		*best_len_ret = best_len;
		return lz_matchptr;
	}

	for (;;) {
		matchptr = &in_begin[cur_node];

		if (matchptr[len] == in_next[len]) {
			len = lz_extend(in_next, matchptr, len + 1, max_len);
			if (len > best_len) {
				best_len = len;
				lz_matchptr->length = len;
				lz_matchptr->offset = in_next - matchptr;
				lz_matchptr++;
				if (len >= nice_len) {
					*pending_lt_ptr = *TEMPLATED(bt_left_child)(mf, cur_node);
					*pending_gt_ptr = *TEMPLATED(bt_right_child)(mf, cur_node);
					*best_len_ret = best_len;
					return lz_matchptr;
				}
			}
		}

		if (matchptr[len] < in_next[len]) {
			*pending_lt_ptr = cur_node;
			pending_lt_ptr = TEMPLATED(bt_right_child)(mf, cur_node);
			cur_node = *pending_lt_ptr;
			best_lt_len = len;
			if (best_gt_len < len)
				len = best_gt_len;
		} else {
			*pending_gt_ptr = cur_node;
			pending_gt_ptr = TEMPLATED(bt_left_child)(mf, cur_node);
			cur_node = *pending_gt_ptr;
			best_gt_len = len;
			if (best_lt_len < len)
				len = best_lt_len;
		}

		if (!cur_node || !--depth_remaining) {
			*pending_lt_ptr = 0;
			*pending_gt_ptr = 0;
			*best_len_ret = best_len;
			return lz_matchptr;
		}
	}
}

/*
 * Advance the matchfinder, but don't record any matches.
 *
 * @mf
 *	The matchfinder structure.
 * @in_begin
 *	Pointer to the beginning of the input buffer.
 * @in_next
 *	Pointer to the next byte in the input buffer to process.
 * @in_end
 *	Pointer to the end of the input buffer.
 * @nice_len
 *	Stop searching if a match of at least this length is found.
 * @max_search_depth
 *	Limit on the number of potential matches to consider.
 * @next_hash
 *	Pointer to the hash code for the current sequence, which was computed
 *	one position in advance so that the binary tree root could be
 *	prefetched.  This is an input/output parameter.
 *
 * Note: this is very similar to bt_matchfinder_get_matches() because both
 * functions must do hashing and tree re-rooting.  This version just doesn't
 * actually record any matches.
 */
static inline void
TEMPLATED(bt_matchfinder_skip_position)(struct TEMPLATED(bt_matchfinder) * const restrict mf,
					const u8 * const in_begin,
					const u8 * const in_next,
					const u8 * const in_end,
					const unsigned nice_len,
					const unsigned max_search_depth,
					u32 * restrict next_hash)
{
	unsigned depth_remaining = max_search_depth;
	u32 hash;
	pos_t cur_node;
	const u8 *matchptr;
	pos_t *pending_lt_ptr, *pending_gt_ptr;
	unsigned best_lt_len, best_gt_len;
	unsigned len;

	if (unlikely(in_end - in_next < LZ_HASH3_REQUIRED_NBYTES + 1))
		return;

	hash = *next_hash;
	*next_hash = bt_matchfinder_hash_3_bytes(in_next + 1);
	cur_node = mf->hash_tab[hash];
	mf->hash_tab[hash] = in_next - in_begin;
	prefetchw(&mf->hash_tab[*next_hash]);

	depth_remaining = max_search_depth;
	pending_lt_ptr = TEMPLATED(bt_left_child)(mf, in_next - in_begin);
	pending_gt_ptr = TEMPLATED(bt_right_child)(mf, in_next - in_begin);
	best_lt_len = 0;
	best_gt_len = 0;
	len = 0;

	if (!cur_node) {
		*pending_lt_ptr = 0;
		*pending_gt_ptr = 0;
		return;
	}

	for (;;) {
		matchptr = &in_begin[cur_node];

		if (matchptr[len] == in_next[len]) {
			len = lz_extend(in_next, matchptr, len + 1, nice_len);
			if (len == nice_len) {
				*pending_lt_ptr = *TEMPLATED(bt_left_child)(mf, cur_node);
				*pending_gt_ptr = *TEMPLATED(bt_right_child)(mf, cur_node);
				return;
			}
		}

		if (matchptr[len] < in_next[len]) {
			*pending_lt_ptr = cur_node;
			pending_lt_ptr = TEMPLATED(bt_right_child)(mf, cur_node);
			cur_node = *pending_lt_ptr;
			best_lt_len = len;
			if (best_gt_len < len)
				len = best_gt_len;
		} else {
			*pending_gt_ptr = cur_node;
			pending_gt_ptr = TEMPLATED(bt_left_child)(mf, cur_node);
			cur_node = *pending_gt_ptr;
			best_gt_len = len;
			if (best_lt_len < len)
				len = best_lt_len;
		}

		if (!cur_node || !--depth_remaining) {
			*pending_lt_ptr = 0;
			*pending_gt_ptr = 0;
			return;
		}
	}
}
