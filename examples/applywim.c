/*
 * applywim.c - A simple program to extract all images from a WIM file to a
 * directory.
 */

#include <wimlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	int ret;
	WIMStruct *wim;

	if (argc != 3) {
		fprintf(stderr, "Usage: applywim WIM DIR\n");
		ret = 2;
		goto out;
	}

	/* Initialize the library. */
	ret = wimlib_global_init(0);
	if (ret)
		goto out;

	/* Open the WIM file. */
	ret = wimlib_open_wim(argv[1], 0, &wim, NULL);
	if (ret)
		goto out_wimlib_global_cleanup;

	/* Extract all the images. */
	ret = wimlib_extract_image(wim, WIMLIB_ALL_IMAGES, argv[2], 0, NULL);

	/* Free the WIM file */
	wimlib_free(wim);

out_wimlib_global_cleanup:
	/* Finalize the library */
	wimlib_global_cleanup();
out:
	return ret;
}
