/*
 * compress_common.h
 *
 * Header for compression code shared by multiple compression formats.
 */

#ifndef _WIMLIB_COMPRESS_COMMON_H
#define _WIMLIB_COMPRESS_COMMON_H

#include "wimlib/types.h"

extern void
make_canonical_huffman_code(unsigned num_syms,
			    unsigned max_codeword_len,
			    const u32 freq_tab[restrict],
			    u8 lens[restrict],
			    u32 codewords[restrict]);

#endif /* _WIMLIB_COMPRESS_COMMON_H */
