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

#ifndef _LCPIT_MATCHFINDER_H
#define _LCPIT_MATCHFINDER_H

#include "wimlib/types.h"

struct lcpit_matchfinder {
	bool huge_mode;
	u32 cur_pos;
	u32 *pos_data;
	union {
		u32 *intervals;
		u64 *intervals64;
	};
	u32 min_match_len;
	u32 nice_match_len;
	u32 next[2];
};

struct lz_match {
	u32 length;
	u32 offset;
};

extern u64
lcpit_matchfinder_get_needed_memory(size_t max_bufsize);

extern bool
lcpit_matchfinder_init(struct lcpit_matchfinder *mf, size_t max_bufsize,
		       u32 min_match_len, u32 nice_match_len);

extern void
lcpit_matchfinder_load_buffer(struct lcpit_matchfinder *mf, const u8 *T, u32 n);

extern u32
lcpit_matchfinder_get_matches(struct lcpit_matchfinder *mf,
                              struct lz_match *matches);

extern void
lcpit_matchfinder_skip_bytes(struct lcpit_matchfinder *mf, u32 count);

extern void
lcpit_matchfinder_destroy(struct lcpit_matchfinder *mf);

#endif /* _LCPIT_MATCHFINDER_H */
