/*
 * updatewim.c - A program to add a file or directory tree to the first image of
 * a WIM file.
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
#include <string.h>

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

int main(int argc, tchar **argv)
{
	int ret;
	tchar *wimfile;
	tchar *wim_target_path;
	tchar *fs_source_path;
	WIMStruct *wim = NULL;
	struct wimlib_update_command cmds[1];

	/* Check for the correct number of arguments.  */
	if (argc != 4) {
		fprintf(stderr, "Usage: updatewim WIMFILE WIM_PATH EXTERNAL_PATH\n");
		return 2;
	}

	wimfile = argv[1];
	wim_target_path = argv[2];
	fs_source_path = argv[3];

	/* Open the WIM file.  */
	ret = wimlib_open_wim(wimfile, 0, &wim);
	if (ret != 0)  /* Always should check the error codes.  */
		goto out;

	/* Update the WIM image.  In this simple example, we add a single file
	 * or directory tree to the specified location in the first image of the
	 * WIM file, using the default options.
	 *
	 * wimlib_add_tree() is actually sufficient for this case, but for the
	 * sake of demonstration we will use the more general function
	 * wimlib_update_image().  */

	memset(cmds, 0, sizeof(cmds));

	/* Set up an "add" operation.
	 *
	 * Other available operations include WIMLIB_UPDATE_OP_RENAME and
	 * WIMLIB_UPDATE_OP_DELETE.  */
	cmds[0].op = WIMLIB_UPDATE_OP_ADD;

	/* Set the arguments to the operation.
	 *
	 * Make sure to fill in 'rename' or 'delete_' instead of 'add' if doing
	 * a rename or delete operation instead!  */
	cmds[0].add.wim_target_path = wim_target_path;
	cmds[0].add.fs_source_path = fs_source_path;

	/* Note: we don't need to explicitly set 'cmds[0].add.config_file' and
	 * 'cmds[0].add.add_flags' because we zeroed the 'struct
	 * wimlib_update_command', and zero means use the defaults.  */

	ret = wimlib_update_image(wim,  /* WIMStruct to update  */
				  1,	/* 1-based index of the image to update  */
				  cmds, /* Array of command structures  */
				  1,    /* Number of command structures in array  */
				  0);   /* WIMLIB_UPDATE_FLAG_* flags (0 for defaults)  */
	if (ret != 0)
		goto out;

	/* Overwrite the WIM file.
	 *
	 * Normally, this will append new data to the file, rather than
	 * rebuilding the entire file.
	 *
	 * Changes do not take effect on-disk until this is done.  */

	ret = wimlib_overwrite(wim, /* WIMStruct to commit to the underlying file  */
			       0,   /* WIMLIB_WRITE_FLAG_* flags (0 for defaults)   */
			       0);  /* Number of compressor threads (0 means default)  */

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
