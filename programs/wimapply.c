/*
 * wimapply.c
 *
 * This is a "minimal" program to apply an image from a stand-alone WIM file.
 * It's intended to be statically linked to the WIM library to create a small
 * executable containing only the functions needed to apply a WIM file.
 *
 * This is not installed by default since the 'apply' subcommand of 'imagex'
 * covers all this functionality and more.
 *
 * Compile with something like:
 * 	$ cd wimlib-1.2.0
 * 	$ ./configure --without-fuse --disable-error-messages \
 * 	  --disable-assertions --disable-custom-memory-allocator
 * 	$ cd programs
 * 	$ gcc -O2 -fwhole-program -flto -s wimapply.c -o wimapply \
 * 	  ../src/*.c -I/usr/include/libxml2 -I.. -D_FILE_OFFSET_BITS=64 \
 * 	  -D_GNU_SOURCE -std=gnu99 -lxml2 -lcrypto -lpthread -lntfs-3g
 * 	$ stat -c %s wimapply
 *	48880
 *
 * Compare this to:
 * 	$ stat -c %s /usr/lib/libwim.so.1.0.0
 * 	196720
 * 	$ stat -c %s /usr/bin/imagex
 * 	35384
 *
 * Use with:
 * 	$ wimapply install.wim 5 /dev/sda2
 */

#include "wimlib.h"
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv)
{
	const char *wimfile;
	const char *image_num;
	const char *target;
	int image;
	int ret;
	WIMStruct *w;
	struct stat stbuf;
	int extract_flags = WIMLIB_EXTRACT_FLAG_SEQUENTIAL;

	if (argc != 4) {
		fprintf(stderr, "Usage: wimapply WIMFILE IMAGE_NUM TARGET\n");
		return 2;
	}

	wimfile = argv[1];
	image_num = argv[2];
	target = argv[3];

	image = atoi(image_num);

	ret = stat(target, &stbuf);
	if (ret != 0) {
		fprintf(stderr, "Cannot stat `%s': %s\n",
			target, strerror(errno));
		return -1;
	}

	if (!S_ISDIR(stbuf.st_mode))
		extract_flags |= WIMLIB_EXTRACT_FLAG_NTFS;

	ret = wimlib_open_wim(wimfile, 0, &w, NULL);
	if (ret != 0) {
		fprintf(stderr, "Failed to open `%s'!\n", wimfile);
		fprintf(stderr, "Error code: %s\n", wimlib_get_error_string(ret));
		return ret;
	}

	ret = wimlib_extract_image(w, image, target, extract_flags, NULL);
	if (ret != 0) {
		fputs("Failed to apply WIM image\n", stderr);
		fprintf(stderr, "Error code: %s\n", wimlib_get_error_string(ret));
	}

	/* Not calling wimlib_free() because the process is ending anyway. */

	return ret;
}
