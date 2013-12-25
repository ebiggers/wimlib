/* TODO: Deprecated stuff to delete when shared library version is bumped up  */

#include "wimlib.h"
#include "wimlib/compiler.h"

WIMLIBAPI int
wimlib_lzx_set_default_params(const struct wimlib_lzx_params_old *params)
{
	return wimlib_set_default_compressor_params(WIMLIB_COMPRESSION_TYPE_LZX,
						    (const struct wimlib_compressor_params_header*)params);
}

WIMLIBAPI int
wimlib_lzx_alloc_context(const struct wimlib_lzx_params_old *params,
			 struct wimlib_lzx_context_old **ctx_pp)
{
	wimlib_lzx_free_context(*ctx_pp);
	*ctx_pp = NULL;
	return wimlib_create_compressor(WIMLIB_COMPRESSION_TYPE_LZX,
					32768,
					(const struct wimlib_compressor_params_header*)params,
					(struct wimlib_compressor**)ctx_pp);
}

WIMLIBAPI void
wimlib_lzx_free_context(struct wimlib_lzx_context_old *ctx)
{
	wimlib_free_compressor((struct wimlib_compressor*)ctx);
}

WIMLIBAPI unsigned
wimlib_lzx_compress2(const void *udata, unsigned ulen, void *cdata,
		     struct wimlib_lzx_context_old *ctx)
{
	return wimlib_compress(udata, ulen, cdata, ulen - 1,
			       (struct wimlib_compressor*)ctx);
}

static unsigned
do_compress(const void *udata, unsigned ulen, void *cdata, int ctype)
{
	struct wimlib_compressor *c;
	unsigned clen;

	if (wimlib_create_compressor(ctype, 32768, NULL, &c))
		return 0;
	clen = wimlib_compress(udata, ulen, cdata, ulen - 1, c);
	wimlib_free_compressor(c);
	return clen;
}

WIMLIBAPI unsigned
wimlib_lzx_compress(const void *udata, unsigned ulen, void *cdata)
{
	return do_compress(udata, ulen, cdata, WIMLIB_COMPRESSION_TYPE_LZX);
}

WIMLIBAPI unsigned
wimlib_xpress_compress(const void *udata, unsigned ulen, void *cdata)
{
	return do_compress(udata, ulen, cdata, WIMLIB_COMPRESSION_TYPE_XPRESS);
}

static int
do_decompress(const void *cdata, unsigned clen,
	      void *udata, unsigned ulen, int ctype)
{
	int ret;
	struct wimlib_decompressor *dec;

	if (wimlib_create_decompressor(ctype, 32768, NULL, &dec))
		return -1;
	ret = wimlib_decompress(cdata, clen, udata, ulen, dec);
	wimlib_free_decompressor(dec);
	return ret;
}

WIMLIBAPI int
wimlib_lzx_decompress(const void *cdata, unsigned clen,
		      void *udata, unsigned ulen)
{
	return do_decompress(cdata, clen, udata, ulen, WIMLIB_COMPRESSION_TYPE_LZX);
}


WIMLIBAPI int
wimlib_xpress_decompress(const void *cdata, unsigned clen,
			 void *udata, unsigned ulen)
{
	return do_decompress(cdata, clen, udata, ulen, WIMLIB_COMPRESSION_TYPE_XPRESS);
}
