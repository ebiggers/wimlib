/*
 * capturewim.c - A program to capture a directory tree into a WIM file.
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#include <wimlib.h>
#include <stdio.h>

#define TO_PERCENT(numerator, denominator) \
	((float)(((denominator) == 0) ? 0 : ((numerator) * 100 / (float)(denominator))))

static enum wimlib_progress_status
write_progress(enum wimlib_progress_msg msg,
	       union wimlib_progress_info *info, void *progctx)
{
	switch (msg) {
	case WIMLIB_PROGRESS_MSG_WRITE_STREAMS:
		printf("Writing WIM: %.2f%% complete\n",
		       TO_PERCENT(info->write_streams.completed_bytes,
				  info->write_streams.total_bytes));
		break;
	default:
		break;
	}
	return WIMLIB_PROGRESS_STATUS_CONTINUE;
}

int main(int argc, char **argv)
{
	int ret;
	WIMStruct *wim = NULL;
	const char *srcdir;
	const char *wimpath;

	/* Check for the correct number of arguments.  */
	if (argc != 3) {
		fprintf(stderr, "Usage: capturewim DIR WIM\n");
		return 2;
	}

	srcdir = argv[1];
	wimpath = argv[2];

	/* Create a WIMStruct for a WIM.  */
	ret = wimlib_create_new_wim(WIMLIB_COMPRESSION_TYPE_LZX, &wim);
	if (ret != 0)  /* Always should check the error codes.  */
		goto out;

	/* Register our progress function.  */
	wimlib_register_progress_function(wim, write_progress, NULL);

	/* Add the directory tree to the WIMStruct as an image.  */

	ret = wimlib_add_image(wim,     /* WIMStruct to which to add the image    */
			       srcdir,  /* Directory from which to add the image  */
			       NULL,    /* Name to give the image (NULL means none)  */
			       NULL,    /* Capture configuration structure (NULL means none)  */
			       0);      /* WIMLIB_ADD_FLAG_* flags (0 means all defaults)  */
	if (ret != 0)
		goto out;

	/* Write the WIM file.  */

	ret = wimlib_write(wim,      /* WIMStruct from which to write a WIM  */
			   wimpath,  /* Path to write the WIM to             */
			   WIMLIB_ALL_IMAGES, /*  Image(s) in the WIM to write */
			   0,        /* WIMLIB_WRITE_FLAG_* flags (0 means all defaults)   */
			   0);       /* Number of compressor threads (0 means default)  */

out:
	/* Free the WIMStruct.  Has no effect if the pointer to it is NULL.  */
	wimlib_free(wim);

	/* Check for error status.  */
	if (ret != 0) {
		fprintf(stderr, "wimlib error %d: %s\n",
			ret, wimlib_get_error_string(ret));
	}

	/* Free global memory (optional).  */
	wimlib_global_cleanup();

	return ret;
}
