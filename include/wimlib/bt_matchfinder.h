/*
 * bt_matchfinder.h
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

#ifndef _BT_MATCHFINDER_H
#define _BT_MATCHFINDER_H

#include "wimlib/lz_extend.h"
#include "wimlib/lz_hash3.h"
#include "wimlib/matchfinder_common.h"
#include "wimlib/unaligned.h"

#ifndef BT_MATCHFINDER_HASH_ORDER
#  if MATCHFINDER_WINDOW_ORDER < 14
#    define BT_MATCHFINDER_HASH_ORDER 14
#  else
#    define BT_MATCHFINDER_HASH_ORDER 15
#  endif
#endif

#define BT_MATCHFINDER_HASH_LENGTH	(1UL << BT_MATCHFINDER_HASH_ORDER)

#define BT_MATCHFINDER_TOTAL_LENGTH	\
	(BT_MATCHFINDER_HASH_LENGTH + (2UL * MATCHFINDER_WINDOW_SIZE))

struct bt_matchfinder {
	union {
		pos_t mf_data[BT_MATCHFINDER_TOTAL_LENGTH];
		struct {
			pos_t hash_tab[BT_MATCHFINDER_HASH_LENGTH];
			pos_t child_tab[2UL * MATCHFINDER_WINDOW_SIZE];
		};
	};
} _aligned_attribute(MATCHFINDER_ALIGNMENT);

static inline void
bt_matchfinder_init(struct bt_matchfinder *mf)
{
	matchfinder_init(mf->hash_tab, BT_MATCHFINDER_HASH_LENGTH);
}

#if MATCHFINDER_IS_SLIDING
static inline void
bt_matchfinder_slide_window(struct bt_matchfinder *mf)
{
	matchfinder_rebase(mf->mf_data, BT_MATCHFINDER_TOTAL_LENGTH);
}
#endif

static inline unsigned
bt_matchfinder_get_matches(struct bt_matchfinder * const restrict mf,
			   const u8 * const in_base,
			   const u8 * const in_next,
			   const unsigned min_len,
			   const unsigned max_len,
			   const unsigned nice_len,
			   const unsigned max_search_depth,
			   unsigned long *prev_hash,
			   struct lz_match * const restrict matches)
{
	struct lz_match *lz_matchptr = matches;
	unsigned depth_remaining = max_search_depth;
	unsigned hash;
	pos_t cur_match;
	const u8 *matchptr;
	unsigned best_len;
	pos_t *pending_lt_ptr, *pending_gt_ptr;
	unsigned best_lt_len, best_gt_len;
	unsigned len;
	pos_t *children;

	if (unlikely(max_len < LZ_HASH_REQUIRED_NBYTES + 1))
		return 0;

	hash = *prev_hash;
	*prev_hash = lz_hash(in_next + 1, BT_MATCHFINDER_HASH_ORDER);
	prefetch(&mf->hash_tab[*prev_hash]);
	cur_match = mf->hash_tab[hash];
	mf->hash_tab[hash] = in_next - in_base;

	best_len = min_len - 1;
	pending_lt_ptr = &mf->child_tab[(in_next - in_base) << 1];
	pending_gt_ptr = &mf->child_tab[((in_next - in_base) << 1) + 1];
	best_lt_len = 0;
	best_gt_len = 0;
	for (;;) {
		if (!matchfinder_match_in_window(cur_match,
						 in_base, in_next) ||
		    !depth_remaining--)
		{
			*pending_lt_ptr = MATCHFINDER_INITVAL;
			*pending_gt_ptr = MATCHFINDER_INITVAL;
			return lz_matchptr - matches;
		}

		matchptr = &in_base[cur_match];
		len = min(best_lt_len, best_gt_len);

		children = &mf->child_tab[(unsigned long)
				matchfinder_slot_for_match(cur_match) << 1];

		if (matchptr[len] == in_next[len]) {

			len = lz_extend(in_next, matchptr, len + 1, max_len);

			if (len > best_len) {
				best_len = len;

				lz_matchptr->length = len;
				lz_matchptr->offset = in_next - matchptr;
				lz_matchptr++;

				if (len >= nice_len) {
					*pending_lt_ptr = children[0];
					*pending_gt_ptr = children[1];
					return lz_matchptr - matches;
				}
			}
		}

		if (matchptr[len] < in_next[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = &children[1];
			cur_match = *pending_lt_ptr;
			best_lt_len = len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = &children[0];
			cur_match = *pending_gt_ptr;
			best_gt_len = len;
		}
	}
}

static inline void
bt_matchfinder_skip_position(struct bt_matchfinder * const restrict mf,
			     const u8 * const in_base,
			     const u8 * const in_next,
			     const u8 * const in_end,
			     const unsigned nice_len,
			     const unsigned max_search_depth,
			     unsigned long *prev_hash)
{
	unsigned depth_remaining = max_search_depth;
	unsigned hash;
	pos_t cur_match;
	const u8 *matchptr;
	pos_t *pending_lt_ptr, *pending_gt_ptr;
	unsigned best_lt_len, best_gt_len;
	unsigned len;
	pos_t *children;

	if (unlikely(in_end - in_next < LZ_HASH_REQUIRED_NBYTES + 1))
		return;

	hash = *prev_hash;
	*prev_hash = lz_hash(in_next + 1, BT_MATCHFINDER_HASH_ORDER);
	prefetch(&mf->hash_tab[*prev_hash]);
	cur_match = mf->hash_tab[hash];
	mf->hash_tab[hash] = in_next - in_base;

	depth_remaining = max_search_depth;
	pending_lt_ptr = &mf->child_tab[(in_next - in_base) << 1];
	pending_gt_ptr = &mf->child_tab[((in_next - in_base) << 1) + 1];
	best_lt_len = 0;
	best_gt_len = 0;
	for (;;) {
		if (!matchfinder_match_in_window(cur_match,
						 in_base, in_next) ||
		    !depth_remaining--)
		{
			*pending_lt_ptr = MATCHFINDER_INITVAL;
			*pending_gt_ptr = MATCHFINDER_INITVAL;
			return;
		}

		matchptr = &in_base[cur_match];
		len = min(best_lt_len, best_gt_len);

		children = &mf->child_tab[(unsigned long)
				matchfinder_slot_for_match(cur_match) << 1];

		if (matchptr[len] == in_next[len]) {
			len = lz_extend(in_next, matchptr, len + 1, nice_len);
			if (len == nice_len) {
				*pending_lt_ptr = children[0];
				*pending_gt_ptr = children[1];
				return;
			}
		}

		if (matchptr[len] < in_next[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = &children[1];
			cur_match = *pending_lt_ptr;
			best_lt_len = len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = &children[0];
			cur_match = *pending_gt_ptr;
			best_gt_len = len;
		}
	}
}

#endif /* _BT_MATCHFINDER_H */
