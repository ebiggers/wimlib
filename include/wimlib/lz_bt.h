/*
 * lz_bt.h
 *
 * Binary tree match-finder for Lempel-Ziv compression.
 *
 * Author:  Eric Biggers
 * Year:    2014
 *
 * The author hereby releases this file into the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_LZ_BT_H
#define _WIMLIB_LZ_BT_H

#include "wimlib/types.h"

/* Position type for the binary tree match-finder.
 * This can be changed to 'u16' if no window will exceed 65536 bytes.  */
typedef u32 lz_bt_pos_t;

/* Match length type for the binary tree match-finder.  */
typedef unsigned lz_bt_len_t;

/* The binary tree match-finder structure.  */
struct lz_bt {
	lz_bt_pos_t *hash_tab;
	lz_bt_pos_t *digram_tab;
	lz_bt_pos_t *child_tab;
	const u8 *cur_window;
	lz_bt_pos_t cur_window_pos;
	lz_bt_pos_t cur_window_size;
	lz_bt_pos_t max_window_size;
	lz_bt_len_t min_match_len;
	lz_bt_len_t max_match_len;
	lz_bt_len_t num_fast_bytes;
	u32 max_search_depth;
};

struct raw_match;

extern u64
lz_bt_get_needed_memory(lz_bt_pos_t max_window_size);

extern bool
lz_bt_init(struct lz_bt *mf,
	   lz_bt_pos_t max_window_size,
	   lz_bt_len_t min_match_len,
	   lz_bt_len_t max_match_len,
	   lz_bt_len_t num_fast_bytes,
	   u32 max_search_depth);

extern void
lz_bt_load_window(struct lz_bt *mf, const u8 *window, lz_bt_pos_t window_size);

extern lz_bt_len_t
lz_bt_get_matches(struct lz_bt *mf, struct raw_match *matches);

static inline lz_bt_pos_t
lz_bt_get_position(const struct lz_bt *mf)
{
	return mf->cur_window_pos;
}

static inline const u8 *
lz_bt_get_window_ptr(const struct lz_bt *mf)
{
	return &mf->cur_window[mf->cur_window_pos];
}

static inline lz_bt_pos_t
lz_bt_get_remaining_size(const struct lz_bt *mf)
{
	return mf->cur_window_size - mf->cur_window_pos;
}

extern void
lz_bt_skip_positions(struct lz_bt *mf, unsigned n);

extern void
lz_bt_destroy(struct lz_bt *mf);

#endif /* _WIMLIB_LZ_BT_H */
