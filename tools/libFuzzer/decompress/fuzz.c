#include "../fuzzer.h"

/* Fuzz decompression. */
int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
	int ctype;
	struct wimlib_decompressor *d;
	const size_t outsize_avail = 3 * insize;
	uint8_t *out;
	int ret;

	if (insize < 1)
		return 0;
	ctype = 1 + ((uint8_t)(in[0] - 1) % 3); /* 1-3 */
	in++;
	insize--;

	ret = wimlib_create_decompressor(ctype, insize, &d);
	if (ret == 0) {
		out = malloc(outsize_avail);
		wimlib_decompress(in, insize, out, outsize_avail, d);
		wimlib_free_decompressor(d);
		free(out);
	}
	return 0;
}
