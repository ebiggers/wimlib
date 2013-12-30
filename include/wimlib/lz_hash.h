#ifndef _WIMLIB_LZ_HASH_H
#define _WIMLIB_LZ_HASH_H

#include "wimlib/compress_common.h"

struct lz_params {
	unsigned min_match;
	unsigned max_match;
	unsigned max_offset;
	unsigned nice_match;
	unsigned good_match;
	unsigned max_chain_len;
	unsigned max_lazy_match;
	unsigned too_far;
};

typedef void (*lz_record_match_t)(unsigned len, unsigned offset, void *ctx);
typedef void (*lz_record_literal_t)(u8 lit, void *ctx);

extern void
lz_analyze_block(const u8 window[restrict],
		 input_idx_t window_size,
		 lz_record_match_t record_match,
		 lz_record_literal_t record_literal,
		 void *record_ctx,
		 const struct lz_params *params,
		 input_idx_t prev_tab[restrict]);


#endif /* _WIMLIB_LZ_HASH_H  */
