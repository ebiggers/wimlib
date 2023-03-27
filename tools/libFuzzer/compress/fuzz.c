#include "../fuzzer.h"

/* Fuzz the compression and decompression round trip. */
int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
	int ctype;
	int level;
	struct wimlib_compressor *c;
	struct wimlib_decompressor *d;
	size_t csize_avail = insize;
	uint8_t *cbuf;
	uint8_t *decompressed;
	size_t csize;
	int ret;

	if (insize < 2)
		return 0;
	ctype = 1 + ((uint8_t)(in[0] - 1) % 3); /* 1-3 */
	level = 1 + (in[1] % 100); /* 1-100 */
	in += 2;
	insize -= 2;

	cbuf = malloc(csize_avail);
	decompressed = malloc(insize);

	ret = wimlib_create_compressor(ctype, insize, level, &c);
	if (ret == 0) {
		ret = wimlib_create_decompressor(ctype, insize, &d);
		assert(ret == 0);

		csize = wimlib_compress(in, insize, cbuf, csize_avail, c);
		if (csize) {
			ret = wimlib_decompress(cbuf, csize,
						decompressed, insize, d);
			assert(ret == 0);
			assert(memcmp(in, decompressed, insize) == 0);
		}
		wimlib_free_compressor(c);
		wimlib_free_decompressor(d);
	}
	free(cbuf);
	free(decompressed);
	return 0;
}
