/*
 * lcpit_matchfinder.h
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

#include <limits.h>
#include <string.h>

#include "wimlib/divsufsort.h"
#include "wimlib/lcpit_matchfinder.h"
#include "wimlib/util.h"

#define LCP_BITS		6
#define LCP_MASK		((1 << LCP_BITS) - 1)
#define LCP_MAX			LCP_MASK
#define NORMAL_UNVISITED_TAG	((u32)1 << 31)
#define MAX_NORMAL_BUFSIZE	((u32)1 << (31 - LCP_BITS))
#define HUGE_UNVISITED_TAG	((u64)1 << 63)
#define SA_and_LCP_LCP_SHIFT	(32 - LCP_BITS)
#define SA_and_LCP_POS_MASK	(((u32)1 << SA_and_LCP_LCP_SHIFT) - 1)

/*
 * Include the template header to define the functions build_LCP(),
 * build_LCPIT(), and lcpit_advance_one_byte().  There are "normal" and "huge"
 * versions of each function.  The normal versions assume that a buffer position
 * and LCP value can be packed into a 32-bit integer, whereas the huge versions
 * assume that 64 bits is needed.
 *
 * Both versions cap LCP values to 6 bits. This limits the depth of the
 * lcp-interval tree without hurting the compression ratio too much.  Matches of
 * length 63 are sufficiently long that the compression ratio doesn't change
 * significantly if we choose one such match over another.
 */
#define HUGE_MODE 1
#include "lcpit_matchfinder_templates.h"
#undef HUGE_MODE

#define HUGE_MODE 0
#include "lcpit_matchfinder_templates.h"
#undef HUGE_MODE

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
	u64 size = 0;

	/* pos_data (+1 is for prefetch) */
	size += ((u64)max_bufsize + 1) * sizeof(u32);

	/* intervals or intervals64  */
	size += max((u64)max_bufsize, DIVSUFSORT_TMP_LEN) *
		(max_bufsize <= MAX_NORMAL_BUFSIZE ? sizeof(u32) : sizeof(u64));

	/* SA */
	size += (u64)max_bufsize * sizeof(u32);

	return size;
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

	mf->pos_data = MALLOC((max_bufsize + 1) * sizeof(u32));
	mf->intervals = MALLOC(max((u64)max_bufsize, DIVSUFSORT_TMP_LEN) *
			       (max_bufsize <= MAX_NORMAL_BUFSIZE ?
				sizeof(u32) : sizeof(u64)));
	mf->SA = MALLOC(max_bufsize * sizeof(u32));

	if (!mf->pos_data || !mf->intervals || !mf->SA) {
		lcpit_matchfinder_destroy(mf);
		return false;
	}

	mf->min_match_len = min_match_len;
	mf->nice_match_len = min(nice_match_len, LCP_MAX);
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
	/* Note: divsufsort() needs temporary space --- one array with 256
	 * spaces and one array with 65536 spaces.  The implementation of
	 * divsufsort() has been modified from the original to use the provided
	 * temporary space instead of allocating its own, since we don't want to
	 * have to deal with malloc() failures here.  */
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
 * @n - size of the input buffer in bytes.  This may be at most the max_bufsize
 *	with which lcpit_matchfinder_init() was called.
 */
void
lcpit_matchfinder_load_buffer(struct lcpit_matchfinder *mf, const u8 *T, u32 n)
{
	if (n == 0)
		return;

	build_SA(mf->SA, T, n, mf->intervals);
	build_ISA(mf->pos_data, mf->SA, n);
	if (n <= MAX_NORMAL_BUFSIZE) {
		/* "Normal" sized buffer  */

		/* Build LCP, packing it into ->SA  */
		build_LCP_normal(mf->SA, mf->pos_data, T, n,
				 mf->min_match_len, mf->nice_match_len);
		/* Prepare ->intervals and ->pos_data  */
		build_LCPIT_normal(mf->SA, mf->intervals, mf->pos_data, n);
		mf->huge_mode = false;
	} else {
		/* "Huge" sized buffer  */

		/* Build LCP in the second half of ->intervals64.  It may be
		 * partially overwritten in build_LCPIT_huge(), but this is okay
		 * since each LCP entry is guaranteed to be consumed before it
		 * can possibly be overwritten.  */
		build_LCP_huge(mf->intervals + n, mf->SA, mf->pos_data, T, n,
			       mf->min_match_len, mf->nice_match_len);
		/* Prepare ->intervals64 and ->pos_data  */
		build_LCPIT_huge(mf->SA, mf->intervals + n, mf->intervals64,
				 mf->pos_data, n);
		mf->huge_mode = true;
	}
	mf->cur_pos = 0; /* starting at beginning of input buffer  */
	mf->pos_data[n] = 0; /* safety entry for prefetch() overrun  */
}

/*
 * Retrieve a list of matches with the next position.
 *
 * The matches will be recorded in the @matches array, ordered by strictly
 * decreasing length and strictly decreasing offset.
 *
 * The return value is the number of matches found and written to @matches.
 * This can be any value in [0, nice_match_len - min_match_len + 1].
 *
 * If the caller attempts to advance beyond the end of the input buffer, the
 * behavior is undefined.
 */
u32
lcpit_matchfinder_get_matches(struct lcpit_matchfinder *mf,
			      struct lz_match *matches)
{
	if (mf->huge_mode)
		return lcpit_advance_one_byte_huge(mf, matches, true);
	else
		return lcpit_advance_one_byte_normal(mf, matches, true);
}

/*
 * Skip the next @count bytes (don't search for matches at them).  @count is
 * assumed to be > 0.
 *
 * If the caller attempts to advance beyond the end of the input buffer, the
 * behavior is undefined.
 */
void
lcpit_matchfinder_skip_bytes(struct lcpit_matchfinder *mf, u32 count)
{
	if (mf->huge_mode) {
		do {
			lcpit_advance_one_byte_huge(mf, NULL, false);
		} while (--count);
	} else {
		do {
			lcpit_advance_one_byte_normal(mf, NULL, false);
		} while (--count);
	}
}

/*
 * Destroy an LCP-interval tree matchfinder that was previously initialized with
 * lcpit_matchfinder_init().
 *
 * If the struct has been zeroed out, this has no effect.
 */
void
lcpit_matchfinder_destroy(struct lcpit_matchfinder *mf)
{
	FREE(mf->pos_data);
	FREE(mf->intervals);
	FREE(mf->SA);
	memset(mf, 0, sizeof(*mf));
}
