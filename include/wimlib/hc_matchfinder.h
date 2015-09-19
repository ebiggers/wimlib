/*
 * hc_matchfinder.h
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 *
 * ---------------------------------------------------------------------------
 *
 *				   Algorithm
 *
 * This is a Hash Chains (hc) based matchfinder.
 *
 * The data structure is a hash table where each hash bucket contains a linked
 * list (or "chain") of sequences whose first 3 bytes share the same hash code.
 * Each sequence is identified by its starting position in the input buffer.
 *
 * The algorithm processes the input buffer sequentially.  At each byte
 * position, the hash code of the first 3 bytes of the sequence beginning at
 * that position (the sequence being matched against) is computed.  This
 * identifies the hash bucket to use for that position.  Then, this hash
 * bucket's linked list is searched for matches.  Then, a new linked list node
 * is created to represent the current sequence and is prepended to the list.
 *
 * This algorithm has several useful properties:
 *
 * - It only finds true Lempel-Ziv matches; i.e., those where the matching
 *   sequence occurs prior to the sequence being matched against.
 *
 * - The sequences in each linked list are always sorted by decreasing starting
 *   position.  Therefore, the closest (smallest offset) matches are found
 *   first, which in many compression formats tend to be the cheapest to encode.
 *
 * - Although fast running time is not guaranteed due to the possibility of the
 *   lists getting very long, the worst degenerate behavior can be easily
 *   prevented by capping the number of nodes searched at each position.
 *
 * - If the compressor decides not to search for matches at a certain position,
 *   then that position can be quickly inserted without searching the list.
 *
 * - The algorithm is adaptable to sliding windows: just store the positions
 *   relative to a "base" value that is updated from time to time, and stop
 *   searching each list when the sequences get too far away.
 *
 * ---------------------------------------------------------------------------
 *
 *				Notes on usage
 *
 * You must define MATCHFINDER_MAX_WINDOW_ORDER before including this header
 * because that determines which integer type to use for positions.  Since
 * 16-bit integers are faster than 32-bit integers due to reduced memory usage
 * (and therefore reduced cache pressure), the code only uses 32-bit integers if
 * they are needed to represent all possible positions.
 *
 * The number of bytes that must be allocated for a given 'struct
 * hc_matchfinder' must be gotten by calling hc_matchfinder_size().
 *
 * ----------------------------------------------------------------------------
 *
 *				 Optimizations
 *
 * The longest_match() and skip_positions() functions are inlined into the
 * compressors that use them.  This isn't just about saving the overhead of a
 * function call.  These functions are intended to be called from the inner
 * loops of compressors, where giving the compiler more control over register
 * allocation is very helpful.  There is also significant benefit to be gained
 * from allowing the CPU to predict branches independently at each call site.
 * For example, "lazy"-style compressors can be written with two calls to
 * longest_match(), each of which starts with a different 'best_len' and
 * therefore has significantly different performance characteristics.
 *
 * Although any hash function can be used, a multiplicative hash is fast and
 * works well.
 *
 * On some processors, it is significantly faster to extend matches by whole
 * words (32 or 64 bits) instead of by individual bytes.  For this to be the
 * case, the processor must implement unaligned memory accesses efficiently and
 * must have either a fast "find first set bit" instruction or a fast "find last
 * set bit" instruction, depending on the processor's endianness.
 *
 * The code uses one loop for finding the first match and one loop for finding a
 * longer match.  Each of these loops is tuned for its respective task and in
 * combination are faster than a single generalized loop that handles both
 * tasks.
 *
 * The code also uses a tight inner loop that only compares the last and first
 * bytes of a potential match.  It is only when these bytes match that a full
 * match extension is attempted.
 *
 * ----------------------------------------------------------------------------
 */

#ifndef _HC_MATCHFINDER_H
#define _HC_MATCHFINDER_H

#ifndef MATCHFINDER_MAX_WINDOW_ORDER
#  error "MATCHFINDER_MAX_WINDOW_ORDER must be defined!"
#endif

#include <string.h>

#include "wimlib/lz_extend.h"
#include "wimlib/lz_hash.h"
#include "wimlib/unaligned.h"

#if MATCHFINDER_MAX_WINDOW_ORDER < 14
#  define HC_MATCHFINDER_HASH_ORDER 14
#else
#  define HC_MATCHFINDER_HASH_ORDER 15
#endif

#if MATCHFINDER_MAX_WINDOW_ORDER <= 16
typedef u16 pos_t;
#else
typedef u32 pos_t;
#endif

struct hc_matchfinder {
	pos_t hash_tab[1UL << HC_MATCHFINDER_HASH_ORDER];
	pos_t next_tab[];
};

/* Return the number of bytes that must be allocated for a 'hc_matchfinder' that
 * can work with buffers up to the specified size.  */
static inline size_t
hc_matchfinder_size(size_t max_bufsize)
{
	return sizeof(struct hc_matchfinder) + (max_bufsize * sizeof(pos_t));
}

/* Prepare the matchfinder for a new input buffer.  */
static inline void
hc_matchfinder_init(struct hc_matchfinder *mf)
{
	memset(mf, 0, sizeof(*mf));
}

/*
 * Find the longest match longer than 'best_len' bytes.
 *
 * @mf
 *	The matchfinder structure.
 * @in_begin
 *	Pointer to the beginning of the input buffer.
 * @in_next
 *	Pointer to the next byte in the input buffer to process.  This is the
 *	pointer to the sequence being matched against.
 * @best_len
 *	Require a match longer than this length.
 * @max_len
 *	The maximum permissible match length at this position.
 * @nice_len
 *	Stop searching if a match of at least this length is found.
 *	Must be <= @max_len.
 * @max_search_depth
 *	Limit on the number of potential matches to consider.  Must be >= 1.
 * @offset_ret
 *	If a match is found, its offset is returned in this location.
 *
 * Return the length of the match found, or 'best_len' if no match longer than
 * 'best_len' was found.
 */
static inline unsigned
hc_matchfinder_longest_match(struct hc_matchfinder * const restrict mf,
			     const u8 * const in_begin,
			     const u8 * const in_next,
			     unsigned best_len,
			     const unsigned max_len,
			     const unsigned nice_len,
			     const unsigned max_search_depth,
			     unsigned *offset_ret)
{
	unsigned depth_remaining = max_search_depth;
	const u8 *best_matchptr = best_matchptr; /* uninitialized */
	const u8 *matchptr;
	unsigned len;
	u32 first_3_bytes;
	u32 hash;
	pos_t cur_node;

	/* Insert the current sequence into the appropriate linked list.  */
	if (unlikely(max_len < LOAD_U24_REQUIRED_NBYTES))
		goto out;
	first_3_bytes = load_u24_unaligned(in_next);
	hash = lz_hash(first_3_bytes, HC_MATCHFINDER_HASH_ORDER);
	cur_node = mf->hash_tab[hash];
	mf->next_tab[in_next - in_begin] = cur_node;
	mf->hash_tab[hash] = in_next - in_begin;

	if (unlikely(best_len >= max_len))
		goto out;

	/* Search the appropriate linked list for matches.  */

	if (!cur_node)
		goto out;

	if (best_len < 3) {
		for (;;) {
			/* No length 3 match found yet.
			 * Check the first 3 bytes.  */
			matchptr = &in_begin[cur_node];

			if (load_u24_unaligned(matchptr) == first_3_bytes)
				break;

			/* The first 3 bytes did not match.  Keep trying.  */
			cur_node = mf->next_tab[cur_node];
			if (!cur_node || !--depth_remaining)
				goto out;
		}

		/* Found a match of length >= 3.  Extend it to its full length.  */
		best_matchptr = matchptr;
		best_len = lz_extend(in_next, best_matchptr, 3, max_len);
		if (best_len >= nice_len)
			goto out;
		cur_node = mf->next_tab[cur_node];
		if (!cur_node || !--depth_remaining)
			goto out;
	}

	for (;;) {
		for (;;) {
			matchptr = &in_begin[cur_node];

			/* Already found a length 3 match.  Try for a longer
			 * match; start by checking either the last 4 bytes and
			 * the first 4 bytes, or the last byte.  (The last byte,
			 * the one which would extend the match length by 1, is
			 * the most important.)  */
		#if UNALIGNED_ACCESS_IS_FAST
			if ((load_u32_unaligned(matchptr + best_len - 3) ==
			     load_u32_unaligned(in_next + best_len - 3)) &&
			    (load_u32_unaligned(matchptr) ==
			     load_u32_unaligned(in_next)))
		#else
			if (matchptr[best_len] == in_next[best_len])
		#endif
				break;

			cur_node = mf->next_tab[cur_node];
			if (!cur_node || !--depth_remaining)
				goto out;
		}

	#if UNALIGNED_ACCESS_IS_FAST
		len = 4;
	#else
		len = 0;
	#endif
		len = lz_extend(in_next, matchptr, len, max_len);
		if (len > best_len) {
			best_len = len;
			best_matchptr = matchptr;
			if (best_len >= nice_len)
				goto out;
		}
		cur_node = mf->next_tab[cur_node];
		if (!cur_node || !--depth_remaining)
			goto out;
	}
out:
	*offset_ret = in_next - best_matchptr;
	return best_len;
}

/*
 * Advance the matchfinder, but don't search for matches.
 *
 * @mf
 *	The matchfinder structure.
 * @in_begin
 *	Pointer to the beginning of the input buffer.
 * @in_next
 *	Pointer to the next byte in the input buffer to process.
 * @in_end
 *	Pointer to the end of the input buffer.
 * @count
 *	The number of bytes to advance.  Must be > 0.
 */
static inline void
hc_matchfinder_skip_positions(struct hc_matchfinder * restrict mf,
			      const u8 *in_begin,
			      const u8 *in_next,
			      const u8 *in_end,
			      unsigned count)
{
	u32 hash;

	if (unlikely(in_next + count >= in_end - LZ_HASH3_REQUIRED_NBYTES))
		return;

	do {
		hash = lz_hash_3_bytes(in_next, HC_MATCHFINDER_HASH_ORDER);
		mf->next_tab[in_next - in_begin] = mf->hash_tab[hash];
		mf->hash_tab[hash] = in_next - in_begin;
		in_next++;
	} while (--count);
}

#endif /* _HC_MATCHFINDER_H */
