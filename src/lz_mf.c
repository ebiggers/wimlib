/*
 * lz_mf.c
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/lz_mf.h"
#include "wimlib/lz_mf_ops.h"
#include "wimlib/util.h"

/* Available match-finding algorithms.  */
static const struct lz_mf_ops *mf_ops[] = {
	[LZ_MF_LCP_INTERVAL_TREE]	= &lz_lcp_interval_tree_ops,
	[LZ_MF_LINKED_SUFFIX_ARRAY]	= &lz_linked_suffix_array_ops,
};

static const struct lz_mf_ops *
get_mf_ops(enum lz_mf_algo algorithm)
{
	if ((unsigned int)algorithm >= ARRAY_LEN(mf_ops))
		return NULL;
	return mf_ops[(unsigned int)algorithm];
}

/*
 * Returns an upper bound on the number of bytes of memory that will be consumed
 * by a match-finder allocated with the specified algorithm and maximum window
 * size.
 *
 * The returned value does not include the size of the window itself.  The
 * caller must account for this separately if needed.
 *
 * If @algorithm is invalid, returns 0.
 */
u64
lz_mf_get_needed_memory(enum lz_mf_algo algorithm, u32 max_window_size)
{
	const struct lz_mf_ops *ops;

	ops = get_mf_ops(algorithm);
	if (!ops)
		return 0;
	return ops->struct_size + ops->get_needed_memory(max_window_size);
}
/*
 * Returns %true if and only if the specified parameters can be validly used to
 * create a match-finder using lz_mf_alloc().
 */
bool
lz_mf_params_valid(const struct lz_mf_params *params)
{
	const struct lz_mf_ops *ops;

	/* Require that a valid algorithm be specified.  */
	ops = get_mf_ops(params->algorithm);
	if (!ops)
		return false;

	/* Don't allow empty windows.  Otherwise, some match-finding algorithms
	 * might need special-case code to handle empty windows.  */
	if (params->max_window_size == 0)
		return false;

	/* Don't allow length-1 matches, so that match-finding algorithms don't
	 * need to worry about this case.  Most LZ-based compression formats
	 * don't allow length-1 matches, since they usually aren't helpful for
	 * compression.  Also, if a compressor really does need length-1
	 * matches, it can easily maintain its own table of length 256
	 * containing the most-recently-seen position for each byte value.
	 *
	 * min_match_len == 0 is valid, since that means the match-finding
	 * algorithm will fill in a default value.  */
	if (params->min_match_len == 1)
		return false;

	if (params->max_match_len != 0) {

		/* Don't allow length-1 matches (same reason as above).  */
		if (params->max_match_len == 1)
			return false;

		/* Don't allow the maximum match length to be shorter than the
		 * minimum match length.  */
		if (params->max_match_len < params->min_match_len)
			return false;
	}

	/* Don't allow the needed memory size to overflow a 'size_t'.  */
	if (sizeof(size_t) < sizeof(u64)) {
		u64 needed_mem = ops->get_needed_memory(params->max_window_size);
		if ((size_t)needed_mem != needed_mem)
			return false;
	}

	/* Call the algorithm-specific routine to finish the validation.  */
	return ops->params_valid(params);
}

/*
 * Allocate a new match-finder.
 *
 * @params
 *	The parameters for the match-finder.  See the declaration of 'struct
 *	lz_mf_params' for more information.
 *
 * Returns a pointer to the new match-finder, or NULL if out of memory or the
 * parameters are invalid.  Call lz_mf_params_valid() beforehand to test the
 * parameter validity separately.
 */
struct lz_mf *
lz_mf_alloc(const struct lz_mf_params *params)
{
	struct lz_mf *mf;
	const struct lz_mf_ops *ops;

	/* Validate the parameters.  */
	if (!lz_mf_params_valid(params))
		return NULL;

	/* Get the match-finder operations structure.  Since we just validated
	 * the parameters, this is guaranteed to return a valid structure.  */
	ops = get_mf_ops(params->algorithm);
	LZ_ASSERT(ops != NULL);

	/* Allocate memory for the match-finder structure.  */
	LZ_ASSERT(ops->struct_size >= sizeof(struct lz_mf));
	mf = CALLOC(1, ops->struct_size);
	if (!mf)
		return NULL;

	/* Set the parameters and operations fields.  */
	mf->params = *params;
	mf->ops = *ops;

	/* Perform algorithm-specific initialization.  Normally this is where
	 * most of the necessary memory is allocated.  */
	if (!mf->ops.init(mf)) {
		FREE(mf);
		return NULL;
	}

	/* The algorithm must have set min_match_len and max_match_len if either
	 * was 0.  */
	LZ_ASSERT(mf->params.min_match_len >= 2);
	LZ_ASSERT(mf->params.max_match_len >= mf->params.min_match_len);

	return mf;
}

/*
 * Load a window into the match-finder.
 *
 * @mf
 *	The match-finder into which to load the window.
 * @window
 *	Pointer to the window to load.  This memory must remain available,
 *	unmodified, while the match-finder is being used.
 * @size
 *	The size of the window, in bytes.  This can't be larger than the
 *	@max_window_size parameter.  In addition, this can't be 0.
 *
 * Note: this interface does not support sliding windows!
 */
void
lz_mf_load_window(struct lz_mf *mf, const u8 *window, u32 size)
{
	/* Can't be an empty window, and can't be larger than the maximum window
	 * size with which the match-finder was allocated.  */
	LZ_ASSERT(size > 0);
	LZ_ASSERT(size <= mf->params.max_window_size);

	/* Save the window and initialize the current position.  */
	mf->cur_window = window;
	mf->cur_window_size = size;
	mf->cur_window_pos = 0;

	/* Call into the algorithm-specific window load code.  */
	mf->ops.load_window(mf, window, size);
}

/*
 * Retrieve a list of matches at the next position in the window.
 *
 * @mf
 *	The match-finder into which a window has been loaded using
 *	lz_mf_load_window().
 * @matches
 *	The array into which the matches will be returned.  The returned match
 *	count will not exceed the minimum of @max_search_depth and (@len_limit -
 *	@min_match_len + 1), where @len_limit is itself defined as
 *	min(@max_match_len, @nice_match_len).
 *
 * The return value is the number of matches that were found and stored in the
 * 'matches' array.  The matches will be ordered by strictly increasing length
 * and strictly increasing offset.  No match shall have length less than
 * @min_match_len, and no match shall have length greater than @max_match_len.
 * The return value may be 0, which indicates that no matches were found.
 *
 * On completion, the match-finder is advanced to the next position in the
 * window.
 *
 * Note: in-non-debug mode, the inline definition of this gets used instead.
 * They are the same, except that the non-inline version below validates the
 * results to help debug match-finding algorithms.
 */
#ifdef ENABLE_LZ_DEBUG
u32
lz_mf_get_matches(struct lz_mf *mf, struct lz_match *matches)
{
	LZ_ASSERT(mf->cur_window_pos < mf->cur_window_size);

	const u32 orig_pos = mf->cur_window_pos;
	const u32 len_limit = min(mf->params.max_match_len,
				  lz_mf_get_bytes_remaining(mf));
	const u8 * const strptr = lz_mf_get_window_ptr(mf);

	const u32 num_matches = mf->ops.get_matches(mf, matches);

	LZ_ASSERT(mf->cur_window_pos == orig_pos + 1);

#if 0
	fprintf(stderr, "Pos %"PRIu32"/%"PRIu32": %"PRIu32" matches\n",
		orig_pos, mf->cur_window_size, num_matches);
	for (u32 i = 0; i < num_matches; i++) {
		fprintf(stderr, "\tLen %"PRIu32" Offset %"PRIu32"\n",
			matches[i].len, matches[i].offset);
	}
#endif

	/* Validate the matches.  */
	for (u32 i = 0; i < num_matches; i++) {
		const u32 len = matches[i].len;
		const u32 offset = matches[i].offset;
		const u8 *matchptr;

		/* Length valid?  */
		LZ_ASSERT(len >= mf->params.min_match_len);
		LZ_ASSERT(len <= len_limit);

		/* Offset valid?  */
		LZ_ASSERT(offset >= 1);
		LZ_ASSERT(offset <= orig_pos);

		/* Lengths and offsets strictly increasing?  */
		if (i > 0) {
			LZ_ASSERT(len > matches[i - 1].len);
			LZ_ASSERT(offset > matches[i - 1].offset);
		}

		/* Actually a match?  */
		matchptr = strptr - offset;
		LZ_ASSERT(!memcmp(strptr, matchptr, len));

		/* Match can't be extended further?  */
		LZ_ASSERT(len == len_limit || strptr[len] != matchptr[len]);
	}

	return num_matches;
}
#endif /* ENABLE_LZ_DEBUG */

/*
 * Skip 'n' positions in the match-finder.  This is a faster alternative to
 * calling lz_mf_get_matches() at each position to advance the match-finder.
 *
 * 'n' must be greater than 0.
 *
 * Note: in-non-debug mode, the inline definition of this gets used instead.
 * They are the same, except the non-inline version below does extra checks.
 */
#ifdef ENABLE_LZ_DEBUG
void
lz_mf_skip_positions(struct lz_mf *mf, const u32 n)
{
	LZ_ASSERT(n > 0);
	LZ_ASSERT(n <= lz_mf_get_bytes_remaining(mf));

	const u32 orig_pos = mf->cur_window_pos;

	mf->ops.skip_positions(mf, n);

	LZ_ASSERT(mf->cur_window_pos == orig_pos + n);
}
#endif

/*
 * Free the match-finder.
 *
 * This frees all memory that was allocated by the call to lz_mf_alloc().
 */
void
lz_mf_free(struct lz_mf *mf)
{
	if (mf) {
		mf->ops.destroy(mf);
	#ifdef ENABLE_LZ_DEBUG
		memset(mf, 0, mf->ops.struct_size);
	#endif
		FREE(mf);
	}
}
