/*
 * compressor_ops.h
 *
 * Interface implemented by compressors for specific formats.
 */

#ifndef _WIMLIB_COMPRESSOR_OPS_H
#define _WIMLIB_COMPRESSOR_OPS_H

#include <stddef.h>

struct compressor_ops {

	int (*create_compressor)(size_t max_block_size,
				 const struct wimlib_compressor_params_header *extra_params,
				 void **private_ret);

	size_t (*compress)(const void *uncompressed_data,
			   size_t uncompressed_size,
			   void *compressed_data,
			   size_t compressed_size_avail,
			   void *private);

	void (*free_compressor)(void *private);
};

extern const struct compressor_ops lzx_compressor_ops;
extern const struct compressor_ops xpress_compressor_ops;
extern const struct compressor_ops lzms_compressor_ops;

extern void
cleanup_compressor_params(void);

#endif /* _WIMLIB_COMPRESSOR_OPS_H */
