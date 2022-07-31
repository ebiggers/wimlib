/*
 * applywim.c - A program to extract the first image from a WIM file.
 *
 * Copyright 2022 Eric Biggers
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <wimlib.h>
#include <stdio.h>

/*
 * Windows compatibility defines for string encoding.  Applications using wimlib
 * that need to run on both UNIX and Windows will need to do something similar
 * to this, whereas applications that only need to run on one or the other can
 * just use their platform's convention directly.
 */
#ifdef _WIN32
#  define main		wmain
   typedef wchar_t	tchar;
#  define TS		"ls"
#else
   typedef char		tchar;
#  define TS		"s"
#endif

#define TO_PERCENT(numerator, denominator) \
	((float)(((denominator) == 0) ? 0 : ((numerator) * 100 / (float)(denominator))))

static enum wimlib_progress_status
extract_progress(enum wimlib_progress_msg msg,
		 union wimlib_progress_info *info, void *progctx)
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
	return WIMLIB_PROGRESS_STATUS_CONTINUE;
}

int main(int argc, tchar **argv)
{
	int ret;
	WIMStruct *wim = NULL;
	const tchar *wimpath;
	const tchar *destdir;

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
			      &wim);    /* Return the WIMStruct pointer in this location  */
	if (ret != 0) /* Always should check the error codes.  */
		goto out;

	/* Register our progress function.  */
	wimlib_register_progress_function(wim, extract_progress, NULL);

	/* Extract the first image.  */
	ret = wimlib_extract_image(wim,     /* WIMStruct from which to extract the image  */
				   1,       /* Image to extract  */
				   destdir, /* Directory to extract the image to  */
				   0);      /* WIMLIB_EXTRACT_FLAG_* flags (0 means all defaults)  */

out:
	/* Free the WIMStruct.  Has no effect if the pointer to it is NULL.  */
	wimlib_free(wim);

	/* Check for error status.  */
	if (ret != 0) {
		fprintf(stderr, "wimlib error %d: %" TS"\n",
			ret, wimlib_get_error_string((enum wimlib_error_code)ret));
	}

	/* Free global memory (optional).  */
	wimlib_global_cleanup();

	return ret;
}
