/*
 * makewim.c - A simple program to make a LZX-compressed WIM file from a
 * directory.
 */

#include <wimlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	int ret;
	WIMStruct *wim;

	if (argc != 3) {
		fprintf(stderr, "Usage: makewim DIR WIM\n");
		ret = 2;
		goto out;
	}

	/* Initialize the library. */
	ret = wimlib_global_init(0);
	if (ret)
		goto out;

	/* Create a WIMStruct for a LZX-compressed WIM. */
	ret = wimlib_create_new_wim(WIMLIB_COMPRESSION_TYPE_LZX, &wim);
	if (ret)
		goto out_wimlib_global_cleanup;

	/* Add the directory tree to the WIMStruct as an image. */
	ret = wimlib_add_image(wim, argv[1], "1", NULL, 0, NULL);
	if (ret)
		goto out_wimlib_free;

	/* Write the desired WIM file. */
	ret = wimlib_write(wim, argv[2], WIMLIB_ALL_IMAGES, 0, 0, NULL);

out_wimlib_free:
	/* Free the WIM file */
	wimlib_free(wim);

out_wimlib_global_cleanup:
	/* Finalize the library */
	wimlib_global_cleanup();
out:
	return ret;
}
