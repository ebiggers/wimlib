#include "../fuzzer.h"

#include <sys/stat.h>

#define TMPDIR "/tmp/fuzz-xml-windows/"

static void
write_file(const char *path, const void *data, size_t size)
{
	int fd;
	ssize_t res;

	fd = open(path, O_WRONLY|O_TRUNC|O_CREAT, 0600);
	assert(fd >= 0);
	res = write(fd, data, size);
	assert(res == size);
	close(fd);
}

/* Fuzz set_windows_specific_info() in xml_windows.c. */
int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
	WIMStruct *wim;
	int ret;

	mkdir(TMPDIR, 0700);
	mkdir(TMPDIR "Windows", 0700);
	mkdir(TMPDIR "Windows", 0700);
	mkdir(TMPDIR "Windows/System32", 0700);
	mkdir(TMPDIR "Windows/System32/config", 0700);
	write_file(TMPDIR "Windows/System32/kernel32.dll", in, insize);
	write_file(TMPDIR "Windows/System32/config/SYSTEM", in, insize);
	write_file(TMPDIR "Windows/System32/config/SOFTWARE", in, insize);

	ret = wimlib_create_new_wim(WIMLIB_COMPRESSION_TYPE_NONE, &wim);
	assert(!ret);

	ret = wimlib_add_image(wim, TMPDIR, NULL, NULL, 0);
	assert(!ret);

	wimlib_free(wim);
	return 0;
}
