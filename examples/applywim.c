/*
 * applywim.c - A program to extract the first image from a WIM file.
 */

#include <wimlib.h>
#include <stdio.h>

#define TO_PERCENT(numerator, denominator) \
	((float)(((denominator) == 0) ? 0 : ((numerator) * 100 / (float)(denominator))))

static int
extract_progress(enum wimlib_progress_msg msg,
		 const union wimlib_progress_info *info)
{
	switch (msg) {
	case WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS:
		printf("Extracting files: %.2f%% complete\n",
		       TO_PERCENT(info->extract.completed_bytes,
				  info->extract.total_bytes));
		break;
	default:
		break;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	WIMStruct *wim = NULL;
	const char *wimpath;
	const char *destdir;

	/* Check for the correct number of arguments.  */
	if (argc != 3) {
		fprintf(stderr, "Usage: applywim WIM DIR\n");
		return 2;
	}

	wimpath = argv[1];
	destdir = argv[2];

	/* Open the WIM file as a WIMStruct.  */
	ret = wimlib_open_wim(wimpath,  /* Path of WIM file to open  */
			      0,        /* WIMLIB_OPEN_FLAG_* flags (0 means all defaults)  */
			      &wim,     /* Return the WIMStruct pointer in this location  */
			      NULL);    /* Progress function (NULL means none)  */
	if (ret != 0) /* Always should check the error codes.  */
		goto out;

	/* Extract the first image.  */
	ret = wimlib_extract_image(wim,     /* WIMStruct from which to extract the image  */
				   1,       /* Image to extract  */
				   destdir, /* Directory to extract the image to  */
				   0,       /* WIMLIB_EXTRACT_FLAG_* flags (0 means all defaults)  */
				   extract_progress);  /* Progress function  */

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
