#include "../fuzzer.h"

/*
 * "UTF-8" (actually "WTF-8") to UTF-16LE (actually "arbitrary sequence of
 * 16-bit wchars") and back again should be lossless, unless the initial string
 * isn't valid WTF-8, in which case WIMLIB_ERR_INVALID_UTF8_STRING is expected.
 */
static void
fuzz_utf8_roundtrip(const u8 *in, size_t insize)
{
	utf16lechar *utf16;
	size_t utf16_size;
	int ret;
	char *result;
	size_t result_size;

	ret = wimlib_utf8_to_utf16le((const char *)in, insize,
				     &utf16, &utf16_size);
	if (ret) {
		assert(ret == WIMLIB_ERR_INVALID_UTF8_STRING);
		return;
	}
	assert(ret == 0);
	ret = wimlib_utf16le_to_utf8(utf16, utf16_size, &result, &result_size);
	assert(ret == 0);
	assert(result_size == insize);
	assert(memcmp(result, in, insize) == 0);
	free(result);
	free(utf16);
}

/*
 * "UTF-16LE" (actually "arbitrary sequence of 16-bit wchars") to UTF-8
 * (actually "WTF-8") and back again should be lossless, unless the initial
 * length isn't a multiple of 2 bytes, in which case
 * WIMLIB_ERR_INVALID_UTF16_STRING is expected.
 */
static void
fuzz_utf16_roundtrip(const u8 *in, size_t insize)
{
	utf16lechar *in_aligned = malloc(insize);
	char *utf8;
	size_t utf8_size;
	int ret;
	utf16lechar *result;
	size_t result_size;

	memcpy(in_aligned, in, insize);
	ret = wimlib_utf16le_to_utf8(in_aligned, insize, &utf8, &utf8_size);
	if (insize % 2) {
		assert(ret == WIMLIB_ERR_INVALID_UTF16_STRING);
		free(in_aligned);
		return;
	}
	assert(ret == 0);
	ret = wimlib_utf8_to_utf16le(utf8, utf8_size, &result, &result_size);
	assert(ret == 0);
	assert(result_size == insize);
	assert(memcmp(result, in, insize) == 0);
	free(result);
	free(utf8);
	free(in_aligned);
}

/* Fuzz character encoding conversion. */
int LLVMFuzzerTestOneInput(const u8 *in, size_t insize)
{
	int which;

	if (insize < 1)
		return 0;
	which = *in++;
	insize--;
	switch (which) {
	case 0:
		fuzz_utf8_roundtrip(in, insize);
		break;
	case 1:
		fuzz_utf16_roundtrip(in, insize);
		break;
	}
	return 0;
}
