#include "../fuzzer.h"

/* Fuzz WIM file reading. */
int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
	uint16_t fault_nth;
	char tmp_wim[128];
	char tmp_dir[128];
	int fd;
	WIMStruct *wim;
	int ret;

	if (!setup_fault_nth(&in, &insize, &fault_nth))
		return 0;

	sprintf(tmp_wim, "/tmp/wim-fuzz-%d.wim", getpid());
	sprintf(tmp_dir, "/tmp/wim-fuzz-%d", getpid());

	fd = open(tmp_wim, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	assert(fd >= 0);
	ret = write(fd, in, insize);
	assert(ret == insize);
	close(fd);

	ret = wimlib_open_wim(tmp_wim, 0, &wim);
	if (ret == 0) {
		wimlib_extract_image(wim, 1, tmp_dir, 0);
		wimlib_add_image(wim, tmp_dir, "name", NULL, 0);
		wimlib_free(wim);
	}
	return 0;
}
