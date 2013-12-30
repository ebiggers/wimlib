#ifndef _WIMLIB_LZ_H
#define _WIMLIB_LZ_H

#include "wimlib/compress_common.h"

//#define ENABLE_LZ_DEBUG
#ifdef ENABLE_LZ_DEBUG
#  define LZ_DEBUG DEBUG
#  define LZ_ASSERT wimlib_assert
#  include "wimlib/assert.h"
#  include "wimlib/error.h"
#else
#  define LZ_DEBUG(...)
#  define LZ_ASSERT(...)
#endif


/* Raw LZ match/literal format: just a length and offset.
 *
 * The length is the number of bytes of the match, and the offset is the number
 * of bytes back in the input the match is from the current position.
 *
 * This can alternatively be used to represent a literal byte if @len is less
 * than the minimum match length.  */
struct raw_match {
	input_idx_t len;
	input_idx_t offset;
};

#endif /* _WIMLIB_LZ_H */
