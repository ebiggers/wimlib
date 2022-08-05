#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
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
	uint8_t level;
	struct wimlib_compressor *c;
	struct wimlib_decompressor *d;
	size_t usize, csize;
	void *udata, *cdata, *decompressed;
	int ret;

	fd = open(argv[1], O_RDONLY);
	assert(fd >= 0);
	ret = fstat(fd, &stbuf);
	assert(!ret);

	if (stbuf.st_size < 2)
		return 0;
	ret = read(fd, &ctype, 1);
	assert(ret == 1);
	ret = read(fd, &level, 1);
	assert(ret == 1);
	ctype = 1 + ((ctype - 1) % 3); /* 1-3 */
	level = 1 + (level % 100); /* 1-100 */
	usize = stbuf.st_size - 2;

	udata = malloc(usize);
	cdata = malloc(usize);
	decompressed = malloc(usize);

	ret = read(fd, udata, usize);
	assert(ret == usize);

	ret = wimlib_create_compressor(ctype, usize, level, &c);
	if (ret == 0) {
		ret = wimlib_create_decompressor(ctype, usize, &d);
		assert(ret == 0);

		csize = wimlib_compress(udata, usize, cdata, usize, c);
		if (csize) {
			ret = wimlib_decompress(cdata, csize,
						decompressed, usize, d);
			assert(ret == 0);
			assert(memcmp(udata, decompressed, usize) == 0);
		}
		wimlib_free_compressor(c);
		wimlib_free_decompressor(d);
	}
	free(udata);
	free(cdata);
	free(decompressed);
	return 0;
}
