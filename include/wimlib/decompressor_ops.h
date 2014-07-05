/*
 * decompressor_ops.h
 *
 * Interface implemented by decompressors for specific formats.
 */

#ifndef _WIMLIB_DECOMPRESSOR_OPS_H
#define _WIMLIB_DECOMPRESSOR_OPS_H

#include <stddef.h>

struct wimlib_decompressor_params_header;

struct decompressor_ops {

	int (*create_decompressor)(size_t max_block_size,
				   const struct wimlib_decompressor_params_header *extra_params,
				   void **private_ret);

	int (*decompress)(const void *compressed_data,
			  size_t compressed_size,
			  void *uncompressed_data,
			  size_t uncompressed_size,
			  void *private);

	void (*free_decompressor)(void *private);
};

extern const struct decompressor_ops lzx_decompressor_ops;
extern const struct decompressor_ops xpress_decompressor_ops;
extern const struct decompressor_ops lzms_decompressor_ops;

extern void
cleanup_decompressor_params(void);

#endif /* _WIMLIB_DECOMPRESSOR_OPS_H */
