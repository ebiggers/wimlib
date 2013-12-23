#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/compress_chunks.h"
#include "wimlib/error.h"
#include "wimlib/assert.h"

unsigned
compress_chunk(const void * uncompressed_data,
	       unsigned uncompressed_len,
	       void *compressed_data,
	       int out_ctype,
	       struct wimlib_lzx_context *comp_ctx)
{
	switch (out_ctype) {
	case WIMLIB_COMPRESSION_TYPE_XPRESS:
		return wimlib_xpress_compress(uncompressed_data,
					      uncompressed_len,
					      compressed_data);
	case WIMLIB_COMPRESSION_TYPE_LZX:
		return wimlib_lzx_compress2(uncompressed_data,
					    uncompressed_len,
					    compressed_data,
					    comp_ctx);
	case WIMLIB_COMPRESSION_TYPE_LZMS:
		WARNING("LZMS compression not implemented!  Writing uncompressed data.");
		return 0;

	default:
		wimlib_assert(0);
		WARNING("Unknown compression type!");
		return 0;
	}
}
