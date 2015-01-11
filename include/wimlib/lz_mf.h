/*
 * lz_mf.h
 *
 * Interface for Lempel-Ziv match-finders.
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
 * Example usage of the match-finder API:
 *
 * ----------------------------------------------------------------------------
 *
 * Fill in a 'struct lz_mf_params'.
 * (Optional) Call lz_mf_params_valid() to validate the parameters.
 * Call lz_mf_alloc() to allocate the match-finder.
 * For each block of data to be compressed:
 *	Call lz_mf_load_window() to load the block into the match finder.
 *	While the block is not yet fully compressed:
 *		Call lz_mf_get_matches() to get matches at the current position.
 *		If matches were found:
 *			Output the longest match.
 *			Call lz_mf_skip_positions() to skip the remaining length of the match.
 *		Else:
 *			Output a literal.
 *		End If
 *	End While
 * End For
 * Call lz_mf_free() to free the match-finder.
 *
 * ----------------------------------------------------------------------------
 *
 * That example did "greedy parsing" --- that is, always choosing the longest
 * match at each position.  However, this interface can be (and is intended to
 * be) used for "optimal parsing" as well.  It can also be used for in-between
 * strategies such as "lazy parsing" and "flexible parsing".  For the best
 * performance try different match-finding algorithms and parameters to see what
 * works best for your parsing strategy, and your typical data and block sizes.
 */

/*
 * TODO: this API is going to go away eventually.  It has too much indirection
 * and is not flexible enough.
 */

#ifndef _WIMLIB_LZ_MF_H
#define _WIMLIB_LZ_MF_H

#include "wimlib/types.h"

/* When ENABLE_LZ_DEBUG is defined, we check all matches for correctness and
 * perform other validations.  Use for debugging only, as it slows things down
 * significantly.  */

//#define ENABLE_LZ_DEBUG
#ifdef ENABLE_LZ_DEBUG
#  include <assert.h>
#  include <string.h>
#  define LZ_ASSERT assert
#else
#  define LZ_ASSERT(...)
#endif

struct lz_mf;

/* Representation of a Lempel-Ziv match.  */
struct lz_match {

	/* The number of bytes matched.  */
	u32 len;

	/* The offset back from the current position that was matched.  */
	u32 offset;
};

/*
 * Specifies a match-finding algorithm.
 */
enum lz_mf_algo {
	/*
	 * Longest Common Prefix Interval Tree match-finding algorithm.
	 *
	 * This is a suffix array-based algorithm.  It works well on medium to
	 * large windows.  However, due to an implementation detail, it is
	 * currently limited to a maximum window size of 33554432 bytes.
	 *
	 * The memory usage is 12 bytes per position.
	 */
	LZ_MF_LCP_INTERVAL_TREE,

	/*
	 * Linked Suffix Array match-finding algorithm.
	 *
	 * This can be used on very large windows.
	 *
	 * The memory usage is 14 bytes per position.
	 *
	 * Currently, this method usually performs slightly worse than the LCP
	 * interval tree algorithm.  However, it can be used on windows
	 * exceeding the 33554432 byte limit of the LCP interval tree algorithm.
	 */
	LZ_MF_LINKED_SUFFIX_ARRAY,
};

/* Parameters for Lempel-Ziv match-finding.  */
struct lz_mf_params {

	/*
	 * The match-finding algorithm to use.  This must be one of the 'enum
	 * lz_mf_algo' constants defined above.
	 */
	u32 algorithm;

	/*
	 * The maximum window size, in bytes, that shall be supported by the
	 * match-finder.  This is the maximum size that can be passed to
	 * subsequent calls to lz_mf_load_window().
	 *
	 * Note: this interface is intended to be used for block compression, so
	 * none of the match-finding algorithms support sliding windows.  It's
	 * expected that the window for LZ match-finding simply be the block of
	 * data being compressed.
	 *
	 * Match-finders generally require an amount of memory proportional to
	 * this parameter.  Use lz_mf_get_needed_memory() to query the needed
	 * memory size for a specific match-finding algorithm and maximum window
	 * size.
	 *
	 * This parameter cannot be 0; there is no default value.
	 *
	 * Match-finding algorithms may place additional restrictions on this
	 * parameter.  However, currently only the LCP interval tree
	 * match-finding algorithm places such a restriction (it doesn't support
	 * windows larger than 33554432 bytes).
	 */
	u32 max_window_size;

	/*
	 * The minimum length, in bytes, of matches that can be produced by the
	 * match-finder (by a call to lz_mf_get_matches()).
	 *
	 * If this parameter is not 0, it must be 2 or greater.
	 *
	 * If this parameter is 0, the match-finding algorithm sets it to a
	 * default value.  The default value will be at least 2 and at most 16.
	 */
	u32 min_match_len;

	/*
	 * The maximum length, in bytes, of matches that can be produced by the
	 * match-finder (by a call to lz_mf_get_matches()).
	 *
	 * If this parameter is not 0, it must be greater than or equal to
	 * @min_match_len, or the default value the match-finding algorithm
	 * selected for @min_match_len in the case that @min_match_len was
	 * specified as 0.
	 *
	 * If this parameter is 0, the match-finding algorithm sets it to a
	 * default value.  In general, the caller must be prepared to handle
	 * arbitrarily long matches (up to the window size minus 1) in this
	 * case.
	 */
	u32 max_match_len;

	/*
	 * This value describes the maximum amount of work that the
	 * match-finding algorithm will do at each position.  A typical value to
	 * use is 32.  Higher values result in better matches and slower
	 * performance.
	 *
	 * If this parameter is 0, the match-finding algorithm sets it to a
	 * default value.
	 */
	u32 max_search_depth;

	/*
	 * This parameter defines the maximum match length to which the full
	 * algorithm will be applied.  This can also be thought of as the length
	 * above which the algorithm will not try to search for additional
	 * matches.
	 *
	 * Usually, setting this parameter to a reasonable value (such as 24,
	 * 32, or 48) will speed up match-finding but will not hurt the
	 * compression ratio too much.  This is because these settings of this
	 * parameter cause the match-finder to not waste too much time examining
	 * very long matches, which are already highly compressible.
	 *
	 * In addition, if the longest match exceeds this length, the
	 * match-finding algorithm will still report its full length.
	 *
	 * The linked suffix array match-finding algorithm ignores this
	 * parameter.
	 *
	 * If this parameter is 0, the match-finding algorithm sets it to a
	 * default value.
	 */
	u32 nice_match_len;
};

/*
 * Lempel-Ziv match-finder operations structure.
 *
 * Match-finding algorithms must fill in all members.  None can be left as 0 or
 * NULL.
 *
 * Don't directly access any of the members outside of lz_mf.h and lz_mf.c.
 * Instead, use the lz_mf_*() wrappers.
 */
struct lz_mf_ops {
	bool (*params_valid)(const struct lz_mf_params *);

	u64 (*get_needed_memory)(u32 max_window_size);

	bool (*init)(struct lz_mf *);

	void (*load_window)(struct lz_mf *mf, const u8 *, u32);

	u32 (*get_matches)(struct lz_mf *, struct lz_match *);

	void (*skip_positions)(struct lz_mf *, u32);

	void (*destroy)(struct lz_mf *);

	size_t struct_size;
};

/*
 * Lempel-Ziv match-finder structure.
 *
 * Match-finding algorithms must embed this structure inside a private
 * structure.
 *
 * Don't directly access any of the members outside of lz_mf.h, lz_mf.c, and
 * match-finding algorithms.  Instead, use the lz_mf_*() wrappers.
 */
struct lz_mf {
	struct lz_mf_params params;
	struct lz_mf_ops ops;
	const u8 *cur_window;
	u32 cur_window_pos;
	u32 cur_window_size;
};

extern bool
lz_mf_params_valid(const struct lz_mf_params *params);

extern u64
lz_mf_get_needed_memory(enum lz_mf_algo algorithm, u32 max_window_size);

extern struct lz_mf *
lz_mf_alloc(const struct lz_mf_params *params);

extern void
lz_mf_load_window(struct lz_mf *mf, const u8 *window, u32 size);

#ifdef ENABLE_LZ_DEBUG
extern u32
lz_mf_get_matches(struct lz_mf *mf, struct lz_match *matches);
#else
/* See non-inline definition for comment  */
static inline u32
lz_mf_get_matches(struct lz_mf *mf, struct lz_match *matches)
{
	return mf->ops.get_matches(mf, matches);
}
#endif

#ifdef ENABLE_LZ_DEBUG
extern void
lz_mf_skip_positions(struct lz_mf *mf, u32 n);
#else
/* See non-inline definition for comment  */
static inline void
lz_mf_skip_positions(struct lz_mf *mf, u32 n)
{
	mf->ops.skip_positions(mf, n);
}
#endif

extern void
lz_mf_free(struct lz_mf *mf);

/*
 * Returns the match-finder's current position in the window.
 *
 * The current position begins at 0.  It increases by 1 when lz_mf_get_matches()
 * is called, and by 'n' when lz_mf_skip_positions() is called.
 *
 * Note: The behavior is undefined if the match-finder is advanced beyond the
 * end of the window.  (If this happens in ENABLE_LZ_DEBUG mode, an assertion
 * will be triggered.)
 */
static inline u32
lz_mf_get_position(const struct lz_mf *mf)
{
	return mf->cur_window_pos;
}

/*
 * Returns the number of bytes remaining in the window.
 */
static inline u32
lz_mf_get_bytes_remaining(const struct lz_mf *mf)
{
	return mf->cur_window_size - mf->cur_window_pos;
}

/*
 * Returns a pointer to the current window, offset by the current position.
 * Equivalently, this returns a pointer to the byte sequence that the next call
 * to lz_mf_get_matches() will match against.
 */
static inline const u8 *
lz_mf_get_window_ptr(const struct lz_mf *mf)
{
	return &mf->cur_window[mf->cur_window_pos];
}

#endif /* _WIMLIB_LZ_MF_H */
