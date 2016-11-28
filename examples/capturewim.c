/*
 * capturewim.c - A program to capture a directory tree into a WIM file.
 *
 * The following copying information applies to this specific source code file:
 *
 * Written in 2014-2016 by Eric Biggers <ebiggers3@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide via the Creative Commons Zero 1.0 Universal Public Domain
 * Dedication (the "CC0").
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the CC0 for more details.
 *
 * You should have received a copy of the CC0 along with this software; if not
 * see <http://creativecommons.org/publicdomain/zero/1.0/>.
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

int main(int argc, tchar **argv)
{
	int ret;
	WIMStruct *wim = NULL;
	const tchar *srcdir;
	const tchar *wimpath;

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
		fprintf(stderr, "wimlib error %d: %" TS"\n",
			ret, wimlib_get_error_string((enum wimlib_error_code)ret));
	}

	/* Free global memory (optional).  */
	wimlib_global_cleanup();

	return ret;
}
