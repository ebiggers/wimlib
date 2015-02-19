/*
 * lcpit_matchfinder.c
 *
 * A match-finder for Lempel-Ziv compression based on bottom-up construction and
 * traversal of the Longest Common Prefix (LCP) interval tree.
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <limits.h>

#include "wimlib/divsufsort.h"
#include "wimlib/lcpit_matchfinder.h"
#include "wimlib/util.h"

#define LCP_BITS		6
#define LCP_MAX			(((u32)1 << LCP_BITS) - 1)
#define POS_MASK		(((u32)1 << (32 - LCP_BITS)) - 1)
#define LCP_SHIFT		(32 - LCP_BITS)
#define LCP_MASK		(LCP_MAX << LCP_SHIFT)
#define MAX_NORMAL_BUFSIZE	(POS_MASK + 1)

#define HUGE_LCP_BITS		7
#define HUGE_LCP_MAX		(((u32)1 << HUGE_LCP_BITS) - 1)
#define HUGE_LCP_SHIFT		(64 - HUGE_LCP_BITS)
#define HUGE_POS_MASK		0xFFFFFFFF
#define MAX_HUGE_BUFSIZE	((u64)HUGE_POS_MASK + 1)
#define HUGE_UNVISITED_TAG	0x100000000

#define PREFETCH_SAFETY		5

/*
 * Build the LCP (Longest Common Prefix) array in linear time.
 *
 * LCP[r] will be the length of the longest common prefix between the suffixes
 * with positions SA[r - 1] and SA[r].  LCP[0] will be undefined.
 *
 * Algorithm taken from Kasai et al. (2001), but modified slightly:
 *
 *  - With bytes there is no realistic way to reserve a unique symbol for
 *    end-of-buffer, so use explicit checks for end-of-buffer.
 *
 *  - For decreased memory usage and improved memory locality, pack the two
 *    logically distinct SA and LCP arrays into a single array SA_and_LCP.
 *
 *  - Since SA_and_LCP is accessed randomly, improve the cache behavior by
 *    reading several entries ahead in ISA and prefetching the upcoming
 *    SA_and_LCP entry.
 *
 *  - If an LCP value is less than the minimum match length, then store 0.  This
 *    avoids having to do comparisons against the minimum match length later.
 *
 *  - If an LCP value is greater than the "nice match length", then store the
 *    "nice match length".  This caps the number of bits needed to store each
 *    LCP value, and this caps the depth of the LCP-interval tree, without
 *    usually hurting the compression ratio too much.
 *
 * References:
 *
 *	Kasai et al.  2001.  Linear-Time Longest-Common-Prefix Computation in
 *	Suffix Arrays and Its Applications.  CPM '01 Proceedings of the 12th
 *	Annual Symposium on Combinatorial Pattern Matching pp. 181-192.
 */
static void
build_LCP(u32 SA_and_LCP[restrict], const u32 ISA[restrict],
	  const u8 T[restrict], const u32 n,
	  const u32 min_lcp, const u32 max_lcp)
{
	u32 h = 0;
	for (u32 i = 0; i < n; i++) {
		const u32 r = ISA[i];
		prefetch(&SA_and_LCP[ISA[i + PREFETCH_SAFETY]]);
		if (r > 0) {
			const u32 j = SA_and_LCP[r - 1] & POS_MASK;
			const u32 lim = min(n - i, n - j);
			while (h < lim && T[i + h] == T[j + h])
				h++;
			u32 stored_lcp = h;
			if (stored_lcp < min_lcp)
				stored_lcp = 0;
			else if (stored_lcp > max_lcp)
				stored_lcp = max_lcp;
			SA_and_LCP[r] |= stored_lcp << LCP_SHIFT;
			if (h > 0)
				h--;
		}
	}
}

/*
 * Use the suffix array accompanied with the longest-common-prefix array ---
 * which in combination can be called the "enhanced suffix array" --- to
 * simulate a bottom-up traversal of the corresponding suffix tree, or
 * equivalently the lcp-interval tree.  Do so in suffix rank order, but save the
 * superinterval references needed for later bottom-up traversal of the tree in
 * suffix position order.
 *
 * To enumerate the lcp-intervals, this algorithm scans the suffix array and its
 * corresponding LCP array linearly.  While doing so, it maintains a stack of
 * lcp-intervals that are currently open, meaning that their left boundaries
 * have been seen but their right boundaries have not.  The bottom of the stack
 * is the interval which covers the entire suffix array (this has lcp=0), and
 * the top of the stack is the deepest interval that is currently open (this has
 * the greatest lcp of any interval on the stack).  When this algorithm opens an
 * lcp-interval, it assigns it a unique index in intervals[] and pushes it onto
 * the stack.  When this algorithm closes an interval, it pops it from the stack
 * and sets the intervals[] entry of that interval to the index and lcp of that
 * interval's superinterval, which is the new top of the stack.
 *
 * This algorithm also set pos_data[pos] for each suffix position 'pos' to the
 * index and lcp of the deepest lcp-interval containing it.  Alternatively, we
 * can interpret each suffix as being associated with a singleton lcp-interval,
 * or leaf of the suffix tree.  With this interpretation, an entry in pos_data[]
 * is the superinterval reference for one of these singleton lcp-intervals and
 * therefore is not fundamentally different from an entry in intervals[].
 *
 * To reduce memory usage, this algorithm re-uses the suffix array's memory to
 * store the generated intervals[] array.  This is possible because SA and LCP
 * are accessed linearly, and no more than one interval is generated per suffix.
 *
 * The techniques used in this algorithm are described in various published
 * papers.  The generation of lcp-intervals from the suffix array (SA) and the
 * longest-common-prefix array (LCP) is given as Algorithm BottomUpTraverse in
 * Kasai et al. (2001) and Algorithm 4.1 ("Computation of lcp-intervals") in
 * Abouelhoda et al. (2004).  Both these papers note the equivalence between
 * lcp-intervals (including the singleton lcp-interval for each suffix) and
 * nodes of the suffix tree.  Abouelhoda et al. (2004) furthermore applies
 * bottom-up traversal of the lcp-interval tree to Lempel-Ziv factorization, as
 * does Chen at al. (2008).  Algorithm CPS1b of Chen et al. (2008) dynamically
 * re-uses the suffix array during bottom-up traversal of the lcp-interval tree.
 *
 * References:
 *
 *	Kasai et al. Linear-Time Longest-Common-Prefix Computation in Suffix
 *	Arrays and Its Applications.  2001.  CPM '01 Proceedings of the 12th
 *	Annual Symposium on Combinatorial Pattern Matching pp. 181-192.
 *
 *	M.I. Abouelhoda, S. Kurtz, E. Ohlebusch.  2004.  Replacing Suffix Trees
 *	With Enhanced Suffix Arrays.  Journal of Discrete Algorithms Volume 2
 *	Issue 1, March 2004, pp. 53-86.
 *
 *	G. Chen, S.J. Puglisi, W.F. Smyth.  2008.  Lempel-Ziv Factorization
 *	Using Less Time & Space.  Mathematics in Computer Science June 2008,
 *	Volume 1, Issue 4, pp. 605-623.
 */
static void
build_LCPIT(u32 intervals[restrict], u32 pos_data[restrict], const u32 n)
{
	u32 * const SA_and_LCP = intervals;
	u32 next_interval_idx;
	u32 open_intervals[LCP_MAX + 1];
	u32 *top = open_intervals;
	u32 prev_pos = SA_and_LCP[0] & POS_MASK;

	*top = 0;
	intervals[0] = 0;
	next_interval_idx = 1;

	for (u32 r = 1; r < n; r++) {
		const u32 next_pos = SA_and_LCP[r] & POS_MASK;
		const u32 next_lcp = SA_and_LCP[r] >> LCP_SHIFT;
		const u32 top_lcp = *top >> LCP_SHIFT;

		if (next_lcp == top_lcp) {
			/* Continuing the deepest open interval  */
			pos_data[prev_pos] = *top;
		} else if (next_lcp > top_lcp) {
			/* Opening a new interval  */
			*++top = (next_lcp << LCP_SHIFT) | next_interval_idx++;
			pos_data[prev_pos] = *top;
		} else {
			/* Closing the deepest open interval  */
			pos_data[prev_pos] = *top;
			for (;;) {
				const u32 closed_interval_idx = *top-- & POS_MASK;
				const u32 superinterval_lcp = *top >> LCP_SHIFT;

				if (next_lcp == superinterval_lcp) {
					/* Continuing the superinterval */
					intervals[closed_interval_idx] = *top;
					break;
				} else if (next_lcp > superinterval_lcp) {
					/* Creating a new interval that is a
					 * superinterval of the one being
					 * closed, but still a subinterval of
					 * its superinterval  */
					*++top = (next_lcp << LCP_SHIFT) | next_interval_idx++;
					intervals[closed_interval_idx] = *top;
					break;
				} else {
					/* Also closing the superinterval  */
					intervals[closed_interval_idx] = *top;
				}
			}
		}
		prev_pos = next_pos;
	}

	/* Close any still-open intervals.  */
	pos_data[prev_pos] = *top;
	for (; top > open_intervals; top--)
		intervals[*top & POS_MASK] = *(top - 1);
}

/*
 * Advance the LCP-interval tree matchfinder by one byte.
 *
 * If @record_matches is true, then matches are written to the @matches array
 * sorted by strictly decreasing length and strictly decreasing offset, and the
 * return value is the number of matches found.  Otherwise, @matches is ignored
 * and the return value is always 0.
 *
 * How this algorithm works:
 *
 * 'cur_pos' is the position of the current suffix, which is the suffix being
 * matched against.  'cur_pos' starts at 0 and is incremented each time this
 * function is called.  This function finds each suffix with position less than
 * 'cur_pos' that shares a prefix with the current suffix, but for each distinct
 * prefix length it finds only the suffix with the greatest position (i.e. the
 * most recently seen in the linear traversal by position).  This function
 * accomplishes this using the lcp-interval tree data structure that was built
 * by build_LCPIT() and is updated dynamically by this function.
 *
 * The first step is to read 'pos_data[cur_pos]', which gives the index and lcp
 * value of the deepest lcp-interval containing the current suffix --- or,
 * equivalently, the parent of the conceptual singleton lcp-interval that
 * contains the current suffix.
 *
 * The second step is to ascend the lcp-interval tree until reaching an interval
 * that has not yet been visited, and link the intervals to the current suffix
 * along the way.   An lcp-interval has been visited if and only if it has been
 * linked to a suffix.  Initially, no lcp-intervals are linked to suffixes.
 *
 * The third step is to continue ascending the lcp-interval tree, but indirectly
 * through suffix links rather than through the original superinterval
 * references, and continuing to form links with the current suffix along the
 * way.  Each suffix visited during this step, except in a special case to
 * handle outdated suffixes, is a match which can be written to matches[].  Each
 * intervals[] entry contains the position of the next suffix to visit, which we
 * shall call 'match_pos'; this is the most recently seen suffix that belongs to
 * that lcp-interval.  'pos_data[match_pos]' then contains the lcp and interval
 * index of the next lcp-interval that should be visited.
 *
 * We can view these arrays as describing a new set of links that gets overlaid
 * on top of the original superinterval references of the lcp-interval tree.
 * Each such link can connect a node of the lcp-interval tree to an ancestor
 * more than one generation removed.
 *
 * For each one-byte advance, the current position becomes the most recently
 * seen suffix for a continuous sequence of lcp-intervals from a leaf interval
 * to the root interval.  Conceptually, this algorithm needs to update all these
 * nodes to link to 'cur_pos', and then update 'pos_data[cur_pos]' to a "null"
 * link.  But actually, if some of these nodes have the same most recently seen
 * suffix, then this algorithm just visits the pos_data[] entry for that suffix
 * and skips over all these nodes in one step.  Updating the extra nodes is
 * accomplished by creating a redirection from the previous suffix to the
 * current suffix.
 *
 * Using this shortcutting scheme, it's possible for a suffix to become out of
 * date, which means that it is no longer the most recently seen suffix for the
 * lcp-interval under consideration.  This case is detected by noticing when the
 * next lcp-interval link actually points deeper in the tree, and it is worked
 * around by just continuing until we get to a link that actually takes us
 * higher in the tree.  This can be described as a lazy-update scheme.
 */
static inline u32
lcpit_advance_one_byte(const u32 cur_pos,
		       u32 pos_data[restrict],
		       u32 intervals[restrict],
		       struct lz_match matches[restrict],
		       const bool record_matches)
{
	u32 lcp;
	u32 interval_idx;
	u32 match_pos;
	struct lz_match *matchptr;

	/* Get the deepest lcp-interval containing the current suffix. */
	lcp = pos_data[cur_pos] >> LCP_SHIFT;
	interval_idx = pos_data[cur_pos] & POS_MASK;
	prefetch(&intervals[pos_data[cur_pos + 1] & POS_MASK]);
	pos_data[cur_pos] = 0;

	/* Ascend until we reach a visited interval, linking the unvisited
	 * intervals to the current suffix as we go.  */
	while (intervals[interval_idx] & LCP_MASK) {
		const u32 superinterval_lcp = intervals[interval_idx] >> LCP_SHIFT;
		const u32 superinterval_idx = intervals[interval_idx] & POS_MASK;
		intervals[interval_idx] = cur_pos;
		lcp = superinterval_lcp;
		interval_idx = superinterval_idx;
	}

	match_pos = intervals[interval_idx] & POS_MASK;
	if (match_pos == 0) {
		/* Ambiguous case; just don't allow matches with position 0. */
		if (interval_idx != 0)
			intervals[interval_idx] = cur_pos;
		return 0;
	}
	matchptr = matches;
	/* Ascend indirectly via pos_data[] links.  */
	for (;;) {
		u32 next_lcp;
		u32 next_interval_idx;

		for (;;) {
			next_lcp = pos_data[match_pos] >> LCP_SHIFT;
			next_interval_idx = pos_data[match_pos] & POS_MASK;
			if (next_lcp < lcp)
				break;
			/* Suffix was out of date.  */
			match_pos = intervals[next_interval_idx];
		}
		intervals[interval_idx] = cur_pos;
		pos_data[match_pos] = (lcp << LCP_SHIFT) | interval_idx;
		if (record_matches) {
			matchptr->length = lcp;
			matchptr->offset = cur_pos - match_pos;
			matchptr++;
		}
		if (next_interval_idx == 0)
			break;
		match_pos = intervals[next_interval_idx];
		interval_idx = next_interval_idx;
		lcp = next_lcp;
	}
	return matchptr - matches;
}

/* Expand SA from 32 bits to 64 bits.  */
static void
expand_SA(void *p, u32 n)
{
	typedef u32 _may_alias_attribute aliased_u32_t;
	typedef u64 _may_alias_attribute aliased_u64_t;

	aliased_u32_t *SA = p;
	aliased_u64_t *SA64 = p;

	u32 r = n - 1;
	do {
		SA64[r] = SA[r];
	} while (r--);
}

/* Like build_LCP(), but for buffers larger than MAX_NORMAL_BUFSIZE.  */
static void
build_LCP_huge(u64 SA_and_LCP64[restrict], const u32 ISA[restrict],
	       const u8 T[restrict], const u32 n,
	       const u32 min_lcp, const u32 max_lcp)
{
	u32 h = 0;
	for (u32 i = 0; i < n; i++) {
		const u32 r = ISA[i];
		prefetch(&SA_and_LCP64[ISA[i + PREFETCH_SAFETY]]);
		if (r > 0) {
			const u32 j = SA_and_LCP64[r - 1] & HUGE_POS_MASK;
			const u32 lim = min(n - i, n - j);
			while (h < lim && T[i + h] == T[j + h])
				h++;
			u32 stored_lcp = h;
			if (stored_lcp < min_lcp)
				stored_lcp = 0;
			else if (stored_lcp > max_lcp)
				stored_lcp = max_lcp;
			SA_and_LCP64[r] |= (u64)stored_lcp << HUGE_LCP_SHIFT;
			if (h > 0)
				h--;
		}
	}
}

/*
 * Like build_LCPIT(), but for buffers larger than MAX_NORMAL_BUFSIZE.
 *
 * This "huge" version is also slightly different in that the lcp value stored
 * in each intervals[] entry is the lcp value for that interval, not its
 * superinterval.  This lcp value stays put in intervals[] and doesn't get moved
 * to pos_data[] during lcpit_advance_one_byte_huge().  One consequence of this
 * is that we have to use a special flag to distinguish visited from unvisited
 * intervals.  But overall, this scheme keeps the memory usage at 12n instead of
 * 16n.  (The non-huge version is 8n.)
 */
static void
build_LCPIT_huge(u64 intervals64[restrict], u32 pos_data[restrict], const u32 n)
{
	u64 * const SA_and_LCP64 = intervals64;
	u32 next_interval_idx;
	u32 open_intervals[HUGE_LCP_MAX + 1];
	u32 *top = open_intervals;
	u32 prev_pos = SA_and_LCP64[0] & HUGE_POS_MASK;

	*top = 0;
	intervals64[0] = 0;
	next_interval_idx = 1;

	for (u32 r = 1; r < n; r++) {
		const u32 next_pos = SA_and_LCP64[r] & HUGE_POS_MASK;
		const u32 next_lcp = SA_and_LCP64[r] >> HUGE_LCP_SHIFT;
		const u32 top_lcp = intervals64[*top] >> HUGE_LCP_SHIFT;

		if (next_lcp == top_lcp) {
			/* Continuing the deepest open interval  */
			pos_data[prev_pos] = *top;
		} else if (next_lcp > top_lcp) {
			/* Opening a new interval  */
			intervals64[next_interval_idx] = (u64)next_lcp << HUGE_LCP_SHIFT;
			pos_data[prev_pos] = next_interval_idx;
			*++top = next_interval_idx++;
		} else {
			/* Closing the deepest open interval  */
			pos_data[prev_pos] = *top;
			for (;;) {
				const u32 closed_interval_idx = *top--;
				const u32 superinterval_lcp = intervals64[*top] >> HUGE_LCP_SHIFT;

				if (next_lcp == superinterval_lcp) {
					/* Continuing the superinterval */
					intervals64[closed_interval_idx] |=
						HUGE_UNVISITED_TAG | *top;
					break;
				} else if (next_lcp > superinterval_lcp) {
					/* Creating a new interval that is a
					 * superinterval of the one being
					 * closed, but still a subinterval of
					 * its superinterval  */
					intervals64[next_interval_idx] =
						(u64)next_lcp << HUGE_LCP_SHIFT;
					intervals64[closed_interval_idx] |=
						HUGE_UNVISITED_TAG | next_interval_idx;
					*++top = next_interval_idx++;
					break;
				} else {
					/* Also closing the superinterval  */
					intervals64[closed_interval_idx] |=
						HUGE_UNVISITED_TAG | *top;
				}
			}
		}
		prev_pos = next_pos;
	}

	/* Close any still-open intervals.  */
	pos_data[prev_pos] = *top;
	for (; top > open_intervals; top--)
		intervals64[*top] |= HUGE_UNVISITED_TAG | *(top - 1);
}

/* Like lcpit_advance_one_byte(), but for buffers larger than
 * MAX_NORMAL_BUFSIZE.  */
static inline u32
lcpit_advance_one_byte_huge(const u32 cur_pos,
			    u32 pos_data[restrict],
			    u64 intervals64[restrict],
			    struct lz_match matches[restrict],
			    const bool record_matches)
{
	u32 interval_idx;
	u32 lcp;
	u32 match_pos;
	struct lz_match *matchptr;

	interval_idx = pos_data[cur_pos];
	prefetch(&intervals64[pos_data[cur_pos + 1]]);
	pos_data[cur_pos] = 0;

	while (intervals64[interval_idx] & HUGE_UNVISITED_TAG) {
		lcp = intervals64[interval_idx] >> HUGE_LCP_SHIFT;
		if (lcp == 0)
			return 0;
		const u32 superinterval_idx = intervals64[interval_idx] & HUGE_POS_MASK;
		intervals64[interval_idx] = ((u64)lcp << HUGE_LCP_SHIFT) | cur_pos;
		interval_idx = superinterval_idx;
	}

	match_pos = intervals64[interval_idx] & HUGE_POS_MASK;
	lcp = intervals64[interval_idx] >> HUGE_LCP_SHIFT;
	matchptr = matches;
	while (lcp != 0) {
		u32 next_interval_idx;
		u32 next_lcp;

		for (;;) {
			next_interval_idx = pos_data[match_pos];
			next_lcp = intervals64[next_interval_idx] >> HUGE_LCP_SHIFT;
			if (next_lcp < lcp)
				break;
			match_pos = intervals64[next_interval_idx] & HUGE_POS_MASK;
		}
		intervals64[interval_idx] = ((u64)lcp << HUGE_LCP_SHIFT) | cur_pos;
		pos_data[match_pos] = interval_idx;
		if (record_matches) {
			matchptr->length = lcp;
			matchptr->offset = cur_pos - match_pos;
			matchptr++;
		}
		match_pos = intervals64[next_interval_idx] & HUGE_POS_MASK;
		interval_idx = next_interval_idx;
		lcp = next_lcp;
	}
	return matchptr - matches;
}

static inline u64
get_pos_data_size(size_t max_bufsize)
{
	return (u64)max((u64)max_bufsize + PREFETCH_SAFETY,
			DIVSUFSORT_TMP_LEN) * sizeof(u32);
}

static inline u64
get_intervals_size(size_t max_bufsize)
{
	return (u64)max_bufsize * (max_bufsize <= MAX_NORMAL_BUFSIZE ?
				   sizeof(u32) : sizeof(u64));
}

/*
 * Calculate the number of bytes of memory needed for the LCP-interval tree
 * matchfinder.
 *
 * @max_bufsize - maximum buffer size to support
 *
 * Returns the number of bytes required.
 */
u64
lcpit_matchfinder_get_needed_memory(size_t max_bufsize)
{
	return get_pos_data_size(max_bufsize) + get_intervals_size(max_bufsize);
}

/*
 * Initialize the LCP-interval tree matchfinder.
 *
 * @mf - the matchfinder structure to initialize
 * @max_bufsize - maximum buffer size to support
 * @min_match_len - minimum match length in bytes
 * @nice_match_len - only consider this many bytes of each match
 *
 * Returns true if successfully initialized; false if out of memory.
 */
bool
lcpit_matchfinder_init(struct lcpit_matchfinder *mf, size_t max_bufsize,
		       u32 min_match_len, u32 nice_match_len)
{
	if (lcpit_matchfinder_get_needed_memory(max_bufsize) > SIZE_MAX)
		return false;
	if (max_bufsize > MAX_HUGE_BUFSIZE - PREFETCH_SAFETY)
		return false;

	mf->pos_data = MALLOC(get_pos_data_size(max_bufsize));
	mf->intervals = MALLOC(get_intervals_size(max_bufsize));
	if (!mf->pos_data || !mf->intervals) {
		lcpit_matchfinder_destroy(mf);
		return false;
	}

	mf->min_match_len = min_match_len;
	mf->nice_match_len = min(nice_match_len,
				 (max_bufsize <= MAX_NORMAL_BUFSIZE) ?
				 LCP_MAX : HUGE_LCP_MAX);
	for (u32 i = 0; i < PREFETCH_SAFETY; i++)
		mf->pos_data[max_bufsize + i] = 0;
	return true;
}

/*
 * Build the suffix array SA for the specified byte array T of length n.
 *
 * The suffix array is a sorted array of the byte array's suffixes, represented
 * by indices into the byte array.  It can equivalently be viewed as a mapping
 * from suffix rank to suffix position.
 *
 * To build the suffix array, we use libdivsufsort, which uses an
 * induced-sorting-based algorithm.  In practice, this seems to be the fastest
 * suffix array construction algorithm currently available.
 *
 * References:
 *
 *	Y. Mori.  libdivsufsort, a lightweight suffix-sorting library.
 *	https://code.google.com/p/libdivsufsort/.
 *
 *	G. Nong, S. Zhang, and W.H. Chan.  2009.  Linear Suffix Array
 *	Construction by Almost Pure Induced-Sorting.  Data Compression
 *	Conference, 2009.  DCC '09.  pp. 193 - 202.
 *
 *	S.J. Puglisi, W.F. Smyth, and A. Turpin.  2007.  A Taxonomy of Suffix
 *	Array Construction Algorithms.  ACM Computing Surveys (CSUR) Volume 39
 *	Issue 2, 2007 Article No. 4.
 */
static void
build_SA(u32 SA[], const u8 T[], u32 n, u32 *tmp)
{
	/* Note: divsufsort() requires a fixed amount of temporary space.  The
	 * implementation of divsufsort() has been modified from the original to
	 * use the provided temporary space instead of allocating its own, since
	 * we don't want to have to deal with malloc() failures here.  */
	divsufsort(T, SA, n, tmp);
}

/*
 * Build the inverse suffix array ISA from the suffix array SA.
 *
 * Whereas the suffix array is a mapping from suffix rank to suffix position,
 * the inverse suffix array is a mapping from suffix position to suffix rank.
 */
static void
build_ISA(u32 ISA[restrict], const u32 SA[restrict], u32 n)
{
	for (u32 r = 0; r < n; r++)
		ISA[SA[r]] = r;
}

/*
 * Prepare the LCP-interval tree matchfinder for a new input buffer.
 *
 * @mf - the initialized matchfinder structure
 * @T - the input buffer
 * @n - size of the input buffer in bytes.  This must be nonzero and can be at
 *	most the max_bufsize with which lcpit_matchfinder_init() was called.
 */
void
lcpit_matchfinder_load_buffer(struct lcpit_matchfinder *mf, const u8 *T, u32 n)
{
	/* intervals[] temporarily stores SA and LCP packed together.
	 * pos_data[] temporarily stores ISA.
	 * pos_data[] is also used as the temporary space for divsufsort().  */

	build_SA(mf->intervals, T, n, mf->pos_data);
	build_ISA(mf->pos_data, mf->intervals, n);
	if (n <= MAX_NORMAL_BUFSIZE) {
		build_LCP(mf->intervals, mf->pos_data, T, n,
			  mf->min_match_len, mf->nice_match_len);
		build_LCPIT(mf->intervals, mf->pos_data, n);
		mf->huge_mode = false;
	} else {
		expand_SA(mf->intervals, n);
		build_LCP_huge(mf->intervals64, mf->pos_data, T, n,
			       mf->min_match_len, mf->nice_match_len);
		build_LCPIT_huge(mf->intervals64, mf->pos_data, n);
		mf->huge_mode = true;
	}
	mf->cur_pos = 0; /* starting at beginning of input buffer  */
}

/*
 * Retrieve a list of matches with the next position.
 *
 * The matches will be recorded in the @matches array, ordered by strictly
 * decreasing length and strictly decreasing offset.
 *
 * The return value is the number of matches found and written to @matches.
 * This can be any value in [0, nice_match_len - min_match_len + 1].
 */
u32
lcpit_matchfinder_get_matches(struct lcpit_matchfinder *mf,
			      struct lz_match *matches)
{
	if (mf->huge_mode)
		return lcpit_advance_one_byte_huge(mf->cur_pos++, mf->pos_data,
						   mf->intervals64, matches, true);
	else
		return lcpit_advance_one_byte(mf->cur_pos++, mf->pos_data,
					      mf->intervals, matches, true);
}

/*
 * Skip the next @count bytes (don't search for matches at them).  @count is
 * assumed to be > 0.
 */
void
lcpit_matchfinder_skip_bytes(struct lcpit_matchfinder *mf, u32 count)
{
	if (mf->huge_mode) {
		do {
			lcpit_advance_one_byte_huge(mf->cur_pos++, mf->pos_data,
						    mf->intervals64, NULL, false);
		} while (--count);
	} else {
		do {
			lcpit_advance_one_byte(mf->cur_pos++, mf->pos_data,
					       mf->intervals, NULL, false);
		} while (--count);
	}
}

/*
 * Destroy an LCP-interval tree matchfinder that was previously initialized with
 * lcpit_matchfinder_init().
 */
void
lcpit_matchfinder_destroy(struct lcpit_matchfinder *mf)
{
	FREE(mf->pos_data);
	FREE(mf->intervals);
}
