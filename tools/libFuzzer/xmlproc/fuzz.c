#include "../fuzzer.h"

/* Fuzz XML parsing and writing. */
int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
	uint16_t fault_nth;
	char *in_str;
	char *out_str = NULL;
	int ret;

	if (!setup_fault_nth(&in, &insize, &fault_nth))
		return 0;

	in_str = malloc(insize + 1);
	memcpy(in_str, in, insize);
	in_str[insize] = '\0';
	ret = wimlib_parse_and_write_xml_doc(in_str, &out_str);
	if (ret == 0) {
		char *out2_str = NULL;

		/*
		 * If the first parse+write succeeded, we now should be able to
		 * parse+write the result without changing it further.
		 */
		ret = wimlib_parse_and_write_xml_doc(out_str, &out2_str);
		if (ret != 0)
			assert(ret == WIMLIB_ERR_NOMEM && fault_nth);
		else
			assert(strcmp(out_str, out2_str) == 0);
		free(out2_str);
	} else {
		assert(ret == WIMLIB_ERR_XML ||
		       (fault_nth && ret == WIMLIB_ERR_NOMEM));
	}
	free(in_str);
	free(out_str);
	return 0;
}
