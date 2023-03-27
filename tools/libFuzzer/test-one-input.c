#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize);

int main(int argc, char *argv[])
{
	int fd;
	struct stat stbuf;
	uint8_t *in;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror(argv[1]);
		return 1;
	}
	if (fstat(fd, &stbuf) != 0) {
		perror("fstat");
		return 1;
	}
	in = malloc(stbuf.st_size);
	if (read(fd, in, stbuf.st_size) != stbuf.st_size) {
		perror("read");
		return 1;
	}
	LLVMFuzzerTestOneInput(in, stbuf.st_size);
	close(fd);
	free(in);
	return 0;
}
