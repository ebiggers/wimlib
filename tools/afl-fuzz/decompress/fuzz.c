#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wimlib.h>

int main(int argc, char *argv[])
{
	int fd;
	struct stat stbuf;
	uint8_t ctype;
	size_t csize, uspace;
	void *cdata, *udata;
	struct wimlib_decompressor *d;
	int ret;

	fd = open(argv[1], O_RDONLY);
	assert(fd >= 0);
	ret = fstat(fd, &stbuf);
	assert(!ret);

	if (stbuf.st_size < 1)
		return 0;
	ret = read(fd, &ctype, 1);
	assert(ret == 1);
	ctype = 1 + ((uint8_t)(ctype - 1) % 3); /* 1-3 */
	csize = stbuf.st_size - 1;
	uspace = csize * 8;

	cdata = malloc(csize);
	udata = malloc(uspace);

	ret = read(fd, cdata, csize);
	assert(ret == csize);

	ret = wimlib_create_decompressor(ctype, uspace, &d);
	if (ret == 0)
		wimlib_decompress(cdata, csize, udata, uspace, d);

	free(udata);
	free(cdata);
	wimlib_free_decompressor(d);
	return 0;
}
