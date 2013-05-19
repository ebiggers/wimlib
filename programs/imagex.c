/*
 * imagex.c
 *
 * Use wimlib to create, modify, extract, mount, unmount, or display information
 * about a WIM file
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h" /* Need for PACKAGE_VERSION, etc. */
#endif

#include "wimlib.h"
#include "wimlib_tchar.h"

#include <ctype.h>
#include <errno.h>

#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <locale.h>

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif

#ifdef __WIN32__
#  include "imagex-win32.h"
#  define tbasename	win32_wbasename
#  define tglob		win32_wglob
#else /* __WIN32__ */
#  include <glob.h>
#  include <getopt.h>
#  include <langinfo.h>
#  define tbasename	basename
#  define tglob		glob
#endif /* !__WIN32 */


#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

#define for_opt(c, opts) while ((c = getopt_long_only(argc, (tchar**)argv, T(""), \
				opts, NULL)) != -1)

enum imagex_op_type {
	APPEND = 0,
	APPLY,
	CAPTURE,
	DELETE,
	DIR,
	EXPORT,
	EXTRACT,
	INFO,
	JOIN,
	MOUNT,
	MOUNTRW,
	OPTIMIZE,
	SPLIT,
	UNMOUNT,
	UPDATE,
};

static void usage(int cmd_type);
static void usage_all(void);

static bool imagex_be_quiet = false;


static const tchar *usage_strings[] = {
[APPEND] =
T(
IMAGEX_PROGNAME" append (DIRECTORY | NTFS_VOLUME) WIMFILE [IMAGE_NAME]\n"
"                     [DESCRIPTION] [--boot] [--check] [--flags EDITION_ID]\n"
"                     [--verbose] [--dereference] [--config=FILE]\n"
"                     [--threads=NUM_THREADS] [--rebuild] [--unix-data]\n"
"                     [--source-list] [--no-acls] [--strict-acls]\n"
"                     [--rpfix] [--norpfix]\n"
),
[APPLY] =
T(
IMAGEX_PROGNAME" apply WIMFILE [IMAGE_NUM | IMAGE_NAME | all]\n"
"                    (DIRECTORY | NTFS_VOLUME) [--check] [--hardlink]\n"
"                    [--symlink] [--verbose] [--ref=\"GLOB\"] [--unix-data]\n"
"                    [--no-acls] [--strict-acls] [--rpfix] [--norpfix]\n"
),
[CAPTURE] =
T(
IMAGEX_PROGNAME" capture (DIRECTORY | NTFS_VOLUME) WIMFILE [IMAGE_NAME]\n"
"                      [DESCRIPTION] [--boot] [--check] [--compress=TYPE]\n"
"                      [--flags EDITION_ID] [--verbose] [--dereference]\n"
"                      [--config=FILE] [--threads=NUM_THREADS] [--unix-data]\n"
"                      [--source-list] [--no-acls] [--strict-acls]\n"
"                      [--rpfix] [--norpfix]\n"
),
[DELETE] =
T(
IMAGEX_PROGNAME" delete WIMFILE (IMAGE_NUM | IMAGE_NAME | all) [--check] [--soft]\n"
),
[DIR] =
T(
IMAGEX_PROGNAME" dir WIMFILE (IMAGE_NUM | IMAGE_NAME | all)\n"
),
[EXPORT] =
T(
IMAGEX_PROGNAME" export SRC_WIMFILE (SRC_IMAGE_NUM | SRC_IMAGE_NAME | all ) \n"
"              DEST_WIMFILE [DEST_IMAGE_NAME] [DEST_IMAGE_DESCRIPTION]\n"
"              [--boot] [--check] [--compress=TYPE] [--ref=\"GLOB\"]\n"
"              [--threads=NUM_THREADS] [--rebuild]\n"
),
[EXTRACT] =
T(
IMAGEX_PROGNAME" extract WIMFILE (IMAGE_NUM | IMAGE_NAME) [PATH...]\n"
"              [--check] [--ref=\"GLOB\"] [--verbose] [--unix-data]\n"
"              [--no-acls] [--strict-acls] [--to-stdout] [--dest-dir=DIR]\n"
),
[INFO] =
T(
IMAGEX_PROGNAME" info WIMFILE [IMAGE_NUM | IMAGE_NAME] [NEW_NAME]\n"
"                   [NEW_DESC] [--boot] [--check] [--header] [--lookup-table]\n"
"                   [--xml] [--extract-xml FILE] [--metadata]\n"
),
[JOIN] =
T(
IMAGEX_PROGNAME" join [--check] WIMFILE SPLIT_WIM...\n"
),
[MOUNT] =
T(
IMAGEX_PROGNAME" mount WIMFILE (IMAGE_NUM | IMAGE_NAME) DIRECTORY\n"
"                    [--check] [--debug] [--streams-interface=INTERFACE]\n"
"                    [--ref=\"GLOB\"] [--unix-data] [--allow-other]\n"
),
[MOUNTRW] =
T(
IMAGEX_PROGNAME" mountrw WIMFILE [IMAGE_NUM | IMAGE_NAME] DIRECTORY\n"
"                      [--check] [--debug] [--streams-interface=INTERFACE]\n"
"                      [--staging-dir=DIR] [--unix-data] [--allow-other]\n"
),
[OPTIMIZE] =
T(
IMAGEX_PROGNAME" optimize WIMFILE [--check] [--recompress]\n"
"                      [--threads=NUM_THREADS]\n"
),
[SPLIT] =
T(
IMAGEX_PROGNAME" split WIMFILE SPLIT_WIMFILE PART_SIZE_MB [--check]\n"
),
[UNMOUNT] =
T(
IMAGEX_PROGNAME" unmount DIRECTORY [--commit] [--check] [--rebuild] [--lazy]\n"
),
[UPDATE] =
T(
IMAGEX_PROGNAME" update WIMFILE [IMAGE_NUM | IMAGE_NAME] [--check] [--rebuild]\n"
"                       [--threads=NUM_THREADS] [DEFAULT_ADD_OPTIONS]\n"
"                       [DEFAULT_DELETE_OPTIONS] < CMDFILE\n"
),
};


static void
recommend_man_page(const tchar *cmd_name)
{
	const tchar *format_str;
#ifdef __WIN32__
	format_str = T("See "IMAGEX_PROGNAME"%"TS"%"TS".pdf in the "
		       "doc directory for more details.\n");
#else
	format_str = T("Try `man "IMAGEX_PROGNAME"%"TS"%"TS"' "
		       "for more details.\n");
#endif
	tprintf(format_str, *cmd_name ? T("-") : T(""), cmd_name);
}

enum {
	IMAGEX_ALLOW_OTHER_OPTION,
	IMAGEX_BOOT_OPTION,
	IMAGEX_CHECK_OPTION,
	IMAGEX_COMMIT_OPTION,
	IMAGEX_COMPRESS_OPTION,
	IMAGEX_CONFIG_OPTION,
	IMAGEX_DEBUG_OPTION,
	IMAGEX_DEREFERENCE_OPTION,
	IMAGEX_DEST_DIR_OPTION,
	IMAGEX_EXTRACT_XML_OPTION,
	IMAGEX_FLAGS_OPTION,
	IMAGEX_FORCE_OPTION,
	IMAGEX_HARDLINK_OPTION,
	IMAGEX_HEADER_OPTION,
	IMAGEX_LAZY_OPTION,
	IMAGEX_LOOKUP_TABLE_OPTION,
	IMAGEX_METADATA_OPTION,
	IMAGEX_NORPFIX_OPTION,
	IMAGEX_NO_ACLS_OPTION,
	IMAGEX_REBUILD_OPTION,
	IMAGEX_RECOMPRESS_OPTION,
	IMAGEX_RECURSIVE_OPTION,
	IMAGEX_REF_OPTION,
	IMAGEX_RPFIX_OPTION,
	IMAGEX_SOFT_OPTION,
	IMAGEX_SOURCE_LIST_OPTION,
	IMAGEX_STAGING_DIR_OPTION,
	IMAGEX_STREAMS_INTERFACE_OPTION,
	IMAGEX_STRICT_ACLS_OPTION,
	IMAGEX_SYMLINK_OPTION,
	IMAGEX_THREADS_OPTION,
	IMAGEX_TO_STDOUT_OPTION,
	IMAGEX_UNIX_DATA_OPTION,
	IMAGEX_VERBOSE_OPTION,
	IMAGEX_XML_OPTION,
};

static const struct option apply_options[] = {
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("hardlink"),    no_argument,       NULL, IMAGEX_HARDLINK_OPTION},
	{T("symlink"),     no_argument,       NULL, IMAGEX_SYMLINK_OPTION},
	{T("verbose"),     no_argument,       NULL, IMAGEX_VERBOSE_OPTION},
	{T("ref"),         required_argument, NULL, IMAGEX_REF_OPTION},
	{T("unix-data"),   no_argument,       NULL, IMAGEX_UNIX_DATA_OPTION},
	{T("noacls"),      no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("no-acls"),     no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("strict-acls"), no_argument,       NULL, IMAGEX_STRICT_ACLS_OPTION},
	{T("rpfix"),       no_argument,       NULL, IMAGEX_RPFIX_OPTION},
	{T("norpfix"),     no_argument,       NULL, IMAGEX_NORPFIX_OPTION},
	{NULL, 0, NULL, 0},
};
static const struct option capture_or_append_options[] = {
	{T("boot"),        no_argument,       NULL, IMAGEX_BOOT_OPTION},
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("compress"),    required_argument, NULL, IMAGEX_COMPRESS_OPTION},
	{T("config"),      required_argument, NULL, IMAGEX_CONFIG_OPTION},
	{T("dereference"), no_argument,       NULL, IMAGEX_DEREFERENCE_OPTION},
	{T("flags"),       required_argument, NULL, IMAGEX_FLAGS_OPTION},
	{T("verbose"),     no_argument,       NULL, IMAGEX_VERBOSE_OPTION},
	{T("threads"),     required_argument, NULL, IMAGEX_THREADS_OPTION},
	{T("rebuild"),     no_argument,       NULL, IMAGEX_REBUILD_OPTION},
	{T("unix-data"),   no_argument,       NULL, IMAGEX_UNIX_DATA_OPTION},
	{T("source-list"), no_argument,       NULL, IMAGEX_SOURCE_LIST_OPTION},
	{T("noacls"),      no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("no-acls"),     no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("strict-acls"), no_argument,       NULL, IMAGEX_STRICT_ACLS_OPTION},
	{T("rpfix"),       no_argument,       NULL, IMAGEX_RPFIX_OPTION},
	{T("norpfix"),     no_argument,       NULL, IMAGEX_NORPFIX_OPTION},
	{NULL, 0, NULL, 0},
};
static const struct option delete_options[] = {
	{T("check"), no_argument, NULL, IMAGEX_CHECK_OPTION},
	{T("soft"),  no_argument, NULL, IMAGEX_SOFT_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option export_options[] = {
	{T("boot"),       no_argument,       NULL, IMAGEX_BOOT_OPTION},
	{T("check"),      no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("compress"),   required_argument, NULL, IMAGEX_COMPRESS_OPTION},
	{T("ref"),        required_argument, NULL, IMAGEX_REF_OPTION},
	{T("threads"),    required_argument, NULL, IMAGEX_THREADS_OPTION},
	{T("rebuild"),    no_argument,       NULL, IMAGEX_REBUILD_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option extract_options[] = {
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("verbose"),     no_argument,       NULL, IMAGEX_VERBOSE_OPTION},
	{T("ref"),         required_argument, NULL, IMAGEX_REF_OPTION},
	{T("unix-data"),   no_argument,       NULL, IMAGEX_UNIX_DATA_OPTION},
	{T("noacls"),      no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("no-acls"),     no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("strict-acls"), no_argument,       NULL, IMAGEX_STRICT_ACLS_OPTION},
	{T("dest-dir"),    required_argument, NULL, IMAGEX_DEST_DIR_OPTION},
	{T("to-stdout"),   no_argument,       NULL, IMAGEX_TO_STDOUT_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option info_options[] = {
	{T("boot"),         no_argument,       NULL, IMAGEX_BOOT_OPTION},
	{T("check"),        no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("extract-xml"),  required_argument, NULL, IMAGEX_EXTRACT_XML_OPTION},
	{T("header"),       no_argument,       NULL, IMAGEX_HEADER_OPTION},
	{T("lookup-table"), no_argument,       NULL, IMAGEX_LOOKUP_TABLE_OPTION},
	{T("metadata"),     no_argument,       NULL, IMAGEX_METADATA_OPTION},
	{T("xml"),          no_argument,       NULL, IMAGEX_XML_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option join_options[] = {
	{T("check"), no_argument, NULL, IMAGEX_CHECK_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option mount_options[] = {
	{T("check"),             no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("debug"),             no_argument,       NULL, IMAGEX_DEBUG_OPTION},
	{T("streams-interface"), required_argument, NULL, IMAGEX_STREAMS_INTERFACE_OPTION},
	{T("ref"),               required_argument, NULL, IMAGEX_REF_OPTION},
	{T("staging-dir"),       required_argument, NULL, IMAGEX_STAGING_DIR_OPTION},
	{T("unix-data"),         no_argument,       NULL, IMAGEX_UNIX_DATA_OPTION},
	{T("allow-other"),       no_argument,       NULL, IMAGEX_ALLOW_OTHER_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option optimize_options[] = {
	{T("check"),      no_argument, NULL, IMAGEX_CHECK_OPTION},
	{T("recompress"), no_argument, NULL, IMAGEX_RECOMPRESS_OPTION},
	{T("threads"),    required_argument, NULL, IMAGEX_THREADS_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option split_options[] = {
	{T("check"), no_argument, NULL, IMAGEX_CHECK_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option unmount_options[] = {
	{T("commit"),  no_argument, NULL, IMAGEX_COMMIT_OPTION},
	{T("check"),   no_argument, NULL, IMAGEX_CHECK_OPTION},
	{T("rebuild"), no_argument, NULL, IMAGEX_REBUILD_OPTION},
	{T("lazy"),    no_argument, NULL, IMAGEX_LAZY_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option update_options[] = {
	/* Careful: some of the options here set the defaults for update
	 * commands, but the flags given to an actual update command (and not to
	 * `imagex update' itself are also handled in
	 * update_command_add_option().  */
	{T("threads"),     required_argument, NULL, IMAGEX_THREADS_OPTION},
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("rebuild"),     no_argument,       NULL, IMAGEX_REBUILD_OPTION},

	/* Default delete options */
	{T("force"),       no_argument,       NULL, IMAGEX_FORCE_OPTION},
	{T("recursive"),   no_argument,       NULL, IMAGEX_RECURSIVE_OPTION},

	/* Global add option */
	{T("config"),      required_argument, NULL, IMAGEX_CONFIG_OPTION},

	/* Default add options */
	{T("verbose"),     no_argument,       NULL, IMAGEX_VERBOSE_OPTION},
	{T("dereference"), no_argument,       NULL, IMAGEX_DEREFERENCE_OPTION},
	{T("unix-data"),   no_argument,       NULL, IMAGEX_UNIX_DATA_OPTION},
	{T("noacls"),      no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("no-acls"),     no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("strict-acls"), no_argument,       NULL, IMAGEX_STRICT_ACLS_OPTION},
	{NULL, 0, NULL, 0},
};

/* Print formatted error message to stderr. */
static void
imagex_error(const tchar *format, ...)
{
	va_list va;
	va_start(va, format);
	tfputs(T("ERROR: "), stderr);
	tvfprintf(stderr, format, va);
	tputc(T('\n'), stderr);
	va_end(va);
}

/* Print formatted error message to stderr. */
static void
imagex_error_with_errno(const tchar *format, ...)
{
	int errno_save = errno;
	va_list va;
	va_start(va, format);
	tfputs(T("ERROR: "), stderr);
	tvfprintf(stderr, format, va);
	tfprintf(stderr, T(": %"TS"\n"), tstrerror(errno_save));
	va_end(va);
}

static int
verify_image_exists(int image, const tchar *image_name, const tchar *wim_name)
{
	if (image == WIMLIB_NO_IMAGE) {
		imagex_error(T("\"%"TS"\" is not a valid image in \"%"TS"\"!\n"
			     "       Please specify a 1-based image index or "
			     "image name.\n"
			     "       You may use `"IMAGEX_PROGNAME" info' to list the images "
			     "contained in a WIM."),
			     image_name, wim_name);
		return -1;
	}
	return 0;
}

static int
verify_image_is_single(int image)
{
	if (image == WIMLIB_ALL_IMAGES) {
		imagex_error(T("Cannot specify all images for this action!"));
		return -1;
	}
	return 0;
}

static int
verify_image_exists_and_is_single(int image, const tchar *image_name,
				  const tchar *wim_name)
{
	int ret;
	ret = verify_image_exists(image, image_name, wim_name);
	if (ret == 0)
		ret = verify_image_is_single(image);
	return ret;
}

/* Parse the argument to --compress */
static int
get_compression_type(const tchar *optarg)
{
	if (!tstrcasecmp(optarg, T("maximum")) || !tstrcasecmp(optarg, T("lzx")))
		return WIMLIB_COMPRESSION_TYPE_LZX;
	else if (!tstrcasecmp(optarg, T("fast")) || !tstrcasecmp(optarg, T("xpress")))
		return WIMLIB_COMPRESSION_TYPE_XPRESS;
	else if (!tstrcasecmp(optarg, T("none")))
		return WIMLIB_COMPRESSION_TYPE_NONE;
	else {
		imagex_error(T("Invalid compression type \"%"TS"\"! Must be "
			     "\"maximum\", \"fast\", or \"none\"."), optarg);
		return WIMLIB_COMPRESSION_TYPE_INVALID;
	}
}

/* Returns the size of a file given its name, or -1 if the file does not exist
 * or its size cannot be determined.  */
static off_t
file_get_size(const tchar *filename)
{
	struct stat st;
	if (tstat(filename, &st) == 0)
		return st.st_size;
	else
		return (off_t)-1;
}

tchar pat_ntfs_log[]                  = T("/$ntfs.log");
tchar pat_hiberfil_sys[]              = T("/hiberfil.sys");
tchar pat_pagefile_sys[]              = T("/pagefile.sys");
tchar pat_system_volume_information[] = T("/System Volume Information");
tchar pat_recycler[]                  = T("/RECYCLER");
tchar pat_windows_csc[]               = T("/Windows/CSC");

tchar *default_pats[] = {
	pat_ntfs_log,
	pat_hiberfil_sys,
	pat_pagefile_sys,
	pat_system_volume_information,
	pat_recycler,
	pat_windows_csc,
};

static struct wimlib_capture_config default_capture_config = {
	.exclusion_pats = {
		.num_pats = sizeof(default_pats) / sizeof(*default_pats),
		.pats = default_pats,
	},
};

enum {
	PARSE_STRING_SUCCESS = 0,
	PARSE_STRING_FAILURE = 1,
	PARSE_STRING_NONE = 2,
};

/*
 * Parses a string token from an array of characters.
 *
 * Tokens are either whitespace-delimited, or double or single-quoted.
 *
 * @line_p:  Pointer to the pointer to the line of data.  Will be updated
 *           to point past the string token iff the return value is
 *           PARSE_STRING_SUCCESS.  If *len_p > 0, (*line_p)[*len_p - 1] must
 *           be '\0'.
 *
 * @len_p:   @len_p initially stores the length of the line of data, which may
 *           be 0, and it will be updated to the number of bytes remaining in
 *           the line iff the return value is PARSE_STRING_SUCCESS.
 *
 * @fn_ret:  Iff the return value is PARSE_STRING_SUCCESS, a pointer to the
 *           parsed string token will be returned here.
 *
 * Returns: PARSE_STRING_SUCCESS if a string token was successfully parsed; or
 *          PARSE_STRING_FAILURE if the data was invalid due to a missing
 *          closing quote; or PARSE_STRING_NONE if the line ended before the
 *          beginning of a string token was found.
 */
static int
parse_string(tchar **line_p, size_t *len_p, tchar **fn_ret)
{
	size_t len = *len_p;
	tchar *line = *line_p;
	tchar *fn;
	tchar quote_char;

	/* Skip leading whitespace */
	for (;;) {
		if (len == 0)
			return PARSE_STRING_NONE;
		if (!istspace(*line) && *line != T('\0'))
			break;
		line++;
		len--;
	}
	quote_char = *line;
	if (quote_char == T('"') || quote_char == T('\'')) {
		/* Quoted string */
		line++;
		len--;
		fn = line;
		line = tmemchr(line, quote_char, len);
		if (!line) {
			imagex_error(T("Missing closing quote: %"TS), fn - 1);
			return PARSE_STRING_FAILURE;
		}
	} else {
		/* Unquoted string.  Go until whitespace.  Line is terminated
		 * by '\0', so no need to check 'len'. */
		fn = line;
		do {
			line++;
		} while (!istspace(*line) && *line != T('\0'));
	}
	*line = T('\0');
	len -= line - fn;
	*len_p = len;
	*line_p = line;
	*fn_ret = fn;
	return PARSE_STRING_SUCCESS;
}

/* Parses a line of data (not an empty line or comment) in the source list file
 * format.  (See the man page for 'wimlib-imagex capture' for details on this
 * format and the meaning.)
 *
 * @line:  Line of data to be parsed.  line[len - 1] must be '\0', unless
 *         len == 0.  The data in @line will be modified by this function call.
 *
 * @len:   Length of the line of data.
 *
 * @source:  On success, the capture source and target described by the line is
 *           written into this destination.  Note that it will contain pointers
 *           to data in the @line array.
 *
 * Returns true if the line was valid; false otherwise.  */
static bool
parse_source_list_line(tchar *line, size_t len,
		       struct wimlib_capture_source *source)
{
	/* SOURCE [DEST] */
	int ret;
	ret = parse_string(&line, &len, &source->fs_source_path);
	if (ret != PARSE_STRING_SUCCESS)
		return false;
	ret = parse_string(&line, &len, &source->wim_target_path);
	if (ret == PARSE_STRING_NONE)
		source->wim_target_path = source->fs_source_path;
	return ret != PARSE_STRING_FAILURE;
}

/* Returns %true if the given line of length @len > 0 is a comment or empty line
 * in the source list file format. */
static bool
is_comment_line(const tchar *line, size_t len)
{
	for (;;) {
		if (*line == T('#'))
			return true;
		if (!istspace(*line) && *line != T('\0'))
			return false;
		++line;
		--len;
		if (len == 0)
			return true;
	}
}

static ssize_t
text_file_count_lines(tchar **contents_p, size_t *nchars_p)
{
	ssize_t nlines = 0;
	tchar *contents = *contents_p;
	size_t nchars = *nchars_p;
	size_t i;

	for (i = 0; i < nchars; i++)
		if (contents[i] == T('\n'))
			nlines++;

	/* Handle last line not terminated by a newline */
	if (nchars != 0 && contents[nchars - 1] != T('\n')) {
		contents = realloc(contents, (nchars + 1) * sizeof(tchar));
		if (!contents) {
			imagex_error(T("Out of memory!"));
			return -1;
		}
		contents[nchars] = T('\n');
		*contents_p = contents;
		nchars++;
		nlines++;
	}
	*nchars_p = nchars;
	return nlines;
}

/* Parses a file in the source list format.  (See the man page for
 * 'wimlib-imagex capture' for details on this format and the meaning.)
 *
 * @source_list_contents:  Contents of the source list file.  Note that this
 *                         buffer will be modified to save memory allocations,
 *                         and cannot be freed until the returned array of
 *                         wimlib_capture_source's has also been freed.
 *
 * @source_list_nbytes:    Number of bytes of data in the @source_list_contents
 *                         buffer.
 *
 * @nsources_ret:          On success, the length of the returned array is
 *                         returned here.
 *
 * Returns:   An array of `struct wimlib_capture_source's that can be passed to
 * the wimlib_add_image_multisource() function to specify how a WIM image is to
 * be created.  */
static struct wimlib_capture_source *
parse_source_list(tchar **source_list_contents_p, size_t source_list_nchars,
		  size_t *nsources_ret)
{
	ssize_t nlines;
	tchar *p;
	struct wimlib_capture_source *sources;
	size_t i, j;

	nlines = text_file_count_lines(source_list_contents_p,
				       &source_list_nchars);
	if (nlines < 0)
		return NULL;

	/* Always allocate at least 1 slot, just in case the implementation of
	 * calloc() returns NULL if 0 bytes are requested. */
	sources = calloc(nlines ?: 1, sizeof(*sources));
	if (!sources) {
		imagex_error(T("out of memory"));
		return NULL;
	}
	p = *source_list_contents_p;
	j = 0;
	for (i = 0; i < nlines; i++) {
		/* XXX: Could use rawmemchr() here instead, but it may not be
		 * available on all platforms. */
		tchar *endp = tmemchr(p, T('\n'), source_list_nchars);
		size_t len = endp - p + 1;
		*endp = T('\0');
		if (!is_comment_line(p, len)) {
			if (!parse_source_list_line(p, len, &sources[j++])) {
				free(sources);
				return NULL;
			}
		}
		p = endp + 1;

	}
	*nsources_ret = j;
	return sources;
}


enum capture_config_section {
	CAPTURE_CONFIG_NO_SECTION,
	CAPTURE_CONFIG_EXCLUSION_SECTION,
	CAPTURE_CONFIG_EXCLUSION_EXCEPTION_SECTION,
	CAPTURE_CONFIG_IGNORE_SECTION,
};

enum {
	CAPTURE_CONFIG_INVALID_SECTION,
	CAPTURE_CONFIG_CHANGED_SECTION,
	CAPTURE_CONFIG_SAME_SECTION,
};

static int
check_config_section(tchar *line, size_t len,
		     enum capture_config_section *cur_section)
{
	while (istspace(*line))
		line++;

	if (*line != T('['))
		return CAPTURE_CONFIG_SAME_SECTION;

	line++;
	tchar *endbrace = tstrrchr(line, T(']'));
	if (!endbrace)
		return CAPTURE_CONFIG_SAME_SECTION;

	if (!tmemcmp(line, T("ExclusionList"), endbrace - line)) {
		*cur_section = CAPTURE_CONFIG_EXCLUSION_SECTION;
	} else if (!tmemcmp(line, T("ExclusionException"), endbrace - line)) {
		*cur_section = CAPTURE_CONFIG_EXCLUSION_EXCEPTION_SECTION;
	} else if (!tmemcmp(line, T("CompressionExclusionList"), endbrace - line)) {
		*cur_section = CAPTURE_CONFIG_IGNORE_SECTION;
		tfputs(T("WARNING: Ignoring [CompressionExclusionList] section "
			 "of capture config file\n"),
		       stderr);
	} else if (!tmemcmp(line, T("AlignmentList"), endbrace - line)) {
		*cur_section = CAPTURE_CONFIG_IGNORE_SECTION;
		tfputs(T("WARNING: Ignoring [AlignmentList] section "
			 "of capture config file\n"),
		       stderr);
	} else {
		imagex_error(T("Invalid capture config file section \"%"TS"\""),
			     line - 1);
		return CAPTURE_CONFIG_INVALID_SECTION;
	}
	return CAPTURE_CONFIG_CHANGED_SECTION;
}


static bool
pattern_list_add_pattern(struct wimlib_pattern_list *pat_list,
			 tchar *pat)
{
	if (pat_list->num_pats == pat_list->num_allocated_pats) {
		tchar **pats;
		size_t num_allocated_pats = pat_list->num_pats + 8;

		pats = realloc(pat_list->pats,
			       num_allocated_pats * sizeof(pat_list->pats[0]));
		if (!pats) {
			imagex_error(T("Out of memory!"));
			return false;
		}
		pat_list->pats = pats;
		pat_list->num_allocated_pats = num_allocated_pats;
	}
	pat_list->pats[pat_list->num_pats++] = pat;
	return true;
}

static bool
parse_capture_config_line(tchar *line, size_t len,
			  enum capture_config_section *cur_section,
			  struct wimlib_capture_config *config)
{
	tchar *filename;
	int ret;

	ret = check_config_section(line, len, cur_section);
	if (ret == CAPTURE_CONFIG_INVALID_SECTION)
		return false;
	if (ret == CAPTURE_CONFIG_CHANGED_SECTION)
		return true;

	switch (*cur_section) {
	case CAPTURE_CONFIG_NO_SECTION:
		imagex_error(T("Line \"%"TS"\" is not in a section "
			       "(such as [ExclusionList]"), line);
		return false;
	case CAPTURE_CONFIG_EXCLUSION_SECTION:
		if (parse_string(&line, &len, &filename) != PARSE_STRING_SUCCESS)
			return false;
		return pattern_list_add_pattern(&config->exclusion_pats,
						filename);
	case CAPTURE_CONFIG_EXCLUSION_EXCEPTION_SECTION:
		if (parse_string(&line, &len, &filename) != PARSE_STRING_SUCCESS)
			return false;
		return pattern_list_add_pattern(&config->exclusion_exception_pats,
						filename);
	case CAPTURE_CONFIG_IGNORE_SECTION:
		return true;
	}
	return false;
}

static int
parse_capture_config(tchar **contents_p, size_t nchars,
		     struct wimlib_capture_config *config)
{
	ssize_t nlines;
	tchar *p;
	size_t i;
	enum capture_config_section cur_section;

	memset(config, 0, sizeof(*config));

	nlines = text_file_count_lines(contents_p, &nchars);
	if (nlines < 0)
		return -1;

	cur_section = CAPTURE_CONFIG_NO_SECTION;
	p = *contents_p;
	for (i = 0; i < nlines; i++) {
		tchar *endp = tmemchr(p, T('\n'), nchars);
		size_t len = endp - p + 1;
		*endp = T('\0');
		if (!is_comment_line(p, len))
			if (!parse_capture_config_line(p, len, &cur_section, config))
				return -1;
		p = endp + 1;

	}
	return 0;
}

/* Reads the contents of a file into memory. */
static char *
file_get_contents(const tchar *filename, size_t *len_ret)
{
	struct stat stbuf;
	void *buf = NULL;
	size_t len;
	FILE *fp;

	if (tstat(filename, &stbuf) != 0) {
		imagex_error_with_errno(T("Failed to stat the file \"%"TS"\""), filename);
		goto out;
	}
	len = stbuf.st_size;

	fp = tfopen(filename, T("rb"));
	if (!fp) {
		imagex_error_with_errno(T("Failed to open the file \"%"TS"\""), filename);
		goto out;
	}

	buf = malloc(len);
	if (!buf) {
		imagex_error(T("Failed to allocate buffer of %zu bytes to hold "
			       "contents of file \"%"TS"\""), len, filename);
		goto out_fclose;
	}
	if (fread(buf, 1, len, fp) != len) {
		imagex_error_with_errno(T("Failed to read %zu bytes from the "
					  "file \"%"TS"\""), len, filename);
		goto out_free_buf;
	}
	*len_ret = len;
	goto out_fclose;
out_free_buf:
	free(buf);
	buf = NULL;
out_fclose:
	fclose(fp);
out:
	return buf;
}

/* Read standard input until EOF and return the full contents in a malloc()ed
 * buffer and the number of bytes of data in @len_ret.  Returns NULL on read
 * error. */
static char *
stdin_get_contents(size_t *len_ret)
{
	/* stdin can, of course, be a pipe or other non-seekable file, so the
	 * total length of the data cannot be pre-determined */
	char *buf = NULL;
	size_t newlen = 1024;
	size_t pos = 0;
	size_t inc = 1024;
	for (;;) {
		char *p = realloc(buf, newlen);
		size_t bytes_read, bytes_to_read;
		if (!p) {
			imagex_error(T("out of memory while reading stdin"));
			break;
		}
		buf = p;
		bytes_to_read = newlen - pos;
		bytes_read = fread(&buf[pos], 1, bytes_to_read, stdin);
		pos += bytes_read;
		if (bytes_read != bytes_to_read) {
			if (feof(stdin)) {
				*len_ret = pos;
				return buf;
			} else {
				imagex_error_with_errno(T("error reading stdin"));
				break;
			}
		}
		newlen += inc;
		inc *= 3;
		inc /= 2;
	}
	free(buf);
	return NULL;
}


static tchar *
translate_text_to_tstr(char *text, size_t num_bytes, size_t *num_tchars_ret)
{
#ifndef __WIN32__
	/* On non-Windows, assume an ASCII-compatible encoding, such as UTF-8.
	 * */
	*num_tchars_ret = num_bytes;
	return text;
#else /* !__WIN32__ */
	/* On Windows, translate the text to UTF-16LE */
	wchar_t *text_wstr;
	size_t num_wchars;

	if (num_bytes >= 2 &&
	    ((text[0] == 0xff && text[1] == 0xfe) ||
	     (text[0] <= 0x7f && text[1] == 0x00)))
	{
		/* File begins with 0xfeff, the BOM for UTF-16LE, or it begins
		 * with something that looks like an ASCII character encoded as
		 * a UTF-16LE code unit.  Assume the file is encoded as
		 * UTF-16LE.  This is not a 100% reliable check. */
		num_wchars = num_bytes / 2;
		text_wstr = (wchar_t*)text;
	} else {
		/* File does not look like UTF-16LE.  Assume it is encoded in
		 * the current Windows code page.  I think these are always
		 * ASCII-compatible, so any so-called "plain-text" (ASCII) files
		 * should work as expected. */
		text_wstr = win32_mbs_to_wcs(text,
					     num_bytes,
					     &num_wchars);
		free(text);
	}
	*num_tchars_ret = num_wchars;
	return text_wstr;
#endif /* __WIN32__ */
}

static tchar *
file_get_text_contents(const tchar *filename, size_t *num_tchars_ret)
{
	char *contents;
	size_t num_bytes;

	contents = file_get_contents(filename, &num_bytes);
	if (!contents)
		return NULL;
	return translate_text_to_tstr(contents, num_bytes, num_tchars_ret);
}

static tchar *
stdin_get_text_contents(size_t *num_tchars_ret)
{
	char *contents;
	size_t num_bytes;

	contents = stdin_get_contents(&num_bytes);
	if (!contents)
		return NULL;
	return translate_text_to_tstr(contents, num_bytes, num_tchars_ret);
}

/* Return 0 if a path names a file to which the current user has write access;
 * -1 otherwise (and print an error message). */
static int
file_writable(const tchar *path)
{
	int ret;
	ret = taccess(path, W_OK);
	if (ret != 0)
		imagex_error_with_errno(T("Can't modify \"%"TS"\""), path);
	return ret;
}

#define TO_PERCENT(numerator, denominator) \
	(((denominator) == 0) ? 0 : ((numerator) * 100 / (denominator)))

/* Given an enumerated value for WIM compression type, return a descriptive
 * string. */
static const tchar *
get_data_type(int ctype)
{
	switch (ctype) {
	case WIMLIB_COMPRESSION_TYPE_NONE:
		return T("uncompressed");
	case WIMLIB_COMPRESSION_TYPE_LZX:
		return T("LZX-compressed");
	case WIMLIB_COMPRESSION_TYPE_XPRESS:
		return T("XPRESS-compressed");
	}
	return NULL;
}

/* Progress callback function passed to various wimlib functions. */
static int
imagex_progress_func(enum wimlib_progress_msg msg,
		     const union wimlib_progress_info *info)
{
	unsigned percent_done;
	if (imagex_be_quiet)
		return 0;
	switch (msg) {
	case WIMLIB_PROGRESS_MSG_WRITE_STREAMS:
		percent_done = TO_PERCENT(info->write_streams.completed_bytes,
					  info->write_streams.total_bytes);
		if (info->write_streams.completed_streams == 0) {
			const tchar *data_type;

			data_type = get_data_type(info->write_streams.compression_type);
			tprintf(T("Writing %"TS" data using %u thread%"TS"\n"),
				data_type, info->write_streams.num_threads,
				(info->write_streams.num_threads == 1) ? T("") : T("s"));
		}
		tprintf(T("\r%"PRIu64" MiB of %"PRIu64" MiB (uncompressed) "
			"written (%u%% done)"),
			info->write_streams.completed_bytes >> 20,
			info->write_streams.total_bytes >> 20,
			percent_done);
		if (info->write_streams.completed_bytes >= info->write_streams.total_bytes)
			tputchar(T('\n'));
		break;
	case WIMLIB_PROGRESS_MSG_SCAN_BEGIN:
		tprintf(T("Scanning \"%"TS"\""), info->scan.source);
		if (*info->scan.wim_target_path) {
			tprintf(T(" (loading as WIM path: \"/%"TS"\")...\n"),
			       info->scan.wim_target_path);
		} else {
			tprintf(T(" (loading as root of WIM image)...\n"));
		}
		break;
	case WIMLIB_PROGRESS_MSG_SCAN_DENTRY:
		if (info->scan.excluded)
			tprintf(T("Excluding \"%"TS"\" from capture\n"), info->scan.cur_path);
		else
			tprintf(T("Scanning \"%"TS"\"\n"), info->scan.cur_path);
		break;
	/*case WIMLIB_PROGRESS_MSG_SCAN_END:*/
		/*break;*/
	case WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY:
		percent_done = TO_PERCENT(info->integrity.completed_bytes,
					  info->integrity.total_bytes);
		tprintf(T("\rVerifying integrity of \"%"TS"\": %"PRIu64" MiB "
			"of %"PRIu64" MiB (%u%%) done"),
			info->integrity.filename,
			info->integrity.completed_bytes >> 20,
			info->integrity.total_bytes >> 20,
			percent_done);
		if (info->integrity.completed_bytes == info->integrity.total_bytes)
			tputchar(T('\n'));
		break;
	case WIMLIB_PROGRESS_MSG_CALC_INTEGRITY:
		percent_done = TO_PERCENT(info->integrity.completed_bytes,
					  info->integrity.total_bytes);
		tprintf(T("\rCalculating integrity table for WIM: %"PRIu64" MiB "
			  "of %"PRIu64" MiB (%u%%) done"),
			info->integrity.completed_bytes >> 20,
			info->integrity.total_bytes >> 20,
			percent_done);
		if (info->integrity.completed_bytes == info->integrity.total_bytes)
			tputchar(T('\n'));
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN:
		tprintf(T("Applying image %d (\"%"TS"\") from \"%"TS"\" "
			  "to %"TS" \"%"TS"\"\n"),
			info->extract.image,
			info->extract.image_name,
			info->extract.wimfile_name,
			((info->extract.extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) ?
			 T("NTFS volume") : T("directory")),
			info->extract.target);
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN:
		tprintf(T("Extracting \"%"TS"\" from image %d (\"%"TS"\") "
			  "in \"%"TS"\" to \"%"TS"\"\n"),
			info->extract.extract_root_wim_source_path,
			info->extract.image,
			info->extract.image_name,
			info->extract.wimfile_name,
			info->extract.target);
		break;
	/*case WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN:*/
		/*tprintf(T("Applying directory structure to %"TS"\n"),*/
			/*info->extract.target);*/
		/*break;*/
	case WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS:
		percent_done = TO_PERCENT(info->extract.completed_bytes,
					  info->extract.total_bytes);
		tprintf(T("\rExtracting files: "
			  "%"PRIu64" MiB of %"PRIu64" MiB (%u%%) done"),
			info->extract.completed_bytes >> 20,
			info->extract.total_bytes >> 20,
			percent_done);
		if (info->extract.completed_bytes >= info->extract.total_bytes)
			tputchar(T('\n'));
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY:
		tprintf(T("%"TS"\n"), info->extract.cur_path);
		break;
	case WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS:
		if (info->extract.extract_root_wim_source_path[0] == T('\0'))
			tprintf(T("Setting timestamps on all extracted files...\n"));
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END:
		if (info->extract.extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
			tprintf(T("Unmounting NTFS volume \"%"TS"\"...\n"),
				info->extract.target);
		}
		break;
	case WIMLIB_PROGRESS_MSG_JOIN_STREAMS:
		percent_done = TO_PERCENT(info->join.completed_bytes,
					  info->join.total_bytes);
		tprintf(T("Writing resources from part %u of %u: "
			  "%"PRIu64 " MiB of %"PRIu64" MiB (%u%%) written\n"),
			(info->join.completed_parts == info->join.total_parts) ?
			info->join.completed_parts : info->join.completed_parts + 1,
			info->join.total_parts,
			info->join.completed_bytes >> 20,
			info->join.total_bytes >> 20,
			percent_done);
		break;
	case WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART:
		percent_done = TO_PERCENT(info->split.completed_bytes,
					  info->split.total_bytes);
		tprintf(T("Writing \"%"TS"\": %"PRIu64" MiB of "
			  "%"PRIu64" MiB (%u%%) written\n"),
			info->split.part_name,
			info->split.completed_bytes >> 20,
			info->split.total_bytes >> 20,
			percent_done);
		break;
	case WIMLIB_PROGRESS_MSG_SPLIT_END_PART:
		if (info->split.completed_bytes == info->split.total_bytes) {
			tprintf(T("Finished writing %u split WIM parts\n"),
				info->split.cur_part_number);
		}
		break;
	default:
		break;
	}
	fflush(stdout);
	return 0;
}

/* Open all the split WIM parts that correspond to a file glob.
 *
 * @first_part specifies the first part of the split WIM and it may be either
 * included or omitted from the glob. */
static int
open_swms_from_glob(const tchar *swm_glob,
		    const tchar *first_part,
		    int open_flags,
		    WIMStruct ***additional_swms_ret,
		    unsigned *num_additional_swms_ret)
{
	unsigned num_additional_swms = 0;
	WIMStruct **additional_swms = NULL;
	glob_t globbuf;
	int ret;

	/* Warning: glob() is replaced in Windows native builds */
	ret = tglob(swm_glob, GLOB_ERR | GLOB_NOSORT, NULL, &globbuf);
	if (ret != 0) {
		if (ret == GLOB_NOMATCH) {
			imagex_error(T("Found no files for glob \"%"TS"\""),
				     swm_glob);
		} else {
			imagex_error_with_errno(T("Failed to process glob \"%"TS"\""),
						swm_glob);
		}
		ret = -1;
		goto out;
	}
	num_additional_swms = globbuf.gl_pathc;
	additional_swms = calloc(num_additional_swms, sizeof(additional_swms[0]));
	if (!additional_swms) {
		imagex_error(T("Out of memory"));
		ret = -1;
		goto out_globfree;
	}
	unsigned offset = 0;
	for (unsigned i = 0; i < num_additional_swms; i++) {
		if (tstrcmp(globbuf.gl_pathv[i], first_part) == 0) {
			offset++;
			continue;
		}
		ret = wimlib_open_wim(globbuf.gl_pathv[i],
				      open_flags | WIMLIB_OPEN_FLAG_SPLIT_OK,
				      &additional_swms[i - offset],
				      imagex_progress_func);
		if (ret != 0)
			goto out_close_swms;
	}
	*additional_swms_ret = additional_swms;
	*num_additional_swms_ret = num_additional_swms - offset;
	ret = 0;
	goto out_globfree;
out_close_swms:
	for (unsigned i = 0; i < num_additional_swms; i++)
		wimlib_free(additional_swms[i]);
	free(additional_swms);
out_globfree:
	globfree(&globbuf);
out:
	return ret;
}


static unsigned
parse_num_threads(const tchar *optarg)
{
	tchar *tmp;
	unsigned long ul_nthreads = tstrtoul(optarg, &tmp, 10);
	if (ul_nthreads >= UINT_MAX || *tmp || tmp == optarg) {
		imagex_error(T("Number of threads must be a non-negative integer!"));
		return UINT_MAX;
	} else {
		return ul_nthreads;
	}
}

/*
 * Parse an option passed to an update command.
 *
 * @op:		One of WIMLIB_UPDATE_OP_* that indicates the command being
 *		parsed.
 *
 * @option:	Text string for the option (beginning with --)
 *
 * @cmd:	`struct wimlib_update_command' that is being constructed for
 *		this command.
 *
 * Returns true if the option was recognized; false if not.
 */
static bool
update_command_add_option(int op, const tchar *option,
			  struct wimlib_update_command *cmd)
{
	bool recognized = true;
	switch (op) {
	case WIMLIB_UPDATE_OP_ADD:
		if (!tstrcmp(option, T("--verbose")))
			cmd->add.add_flags |= WIMLIB_ADD_IMAGE_FLAG_VERBOSE;
		else if (!tstrcmp(option, T("--unix-data")))
			cmd->add.add_flags |= WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA;
		else if (!tstrcmp(option, T("--no-acls")) || !tstrcmp(option, T("--noacls")))
			cmd->add.add_flags |= WIMLIB_ADD_IMAGE_FLAG_NO_ACLS;
		else if (!tstrcmp(option, T("--strict-acls")))
			cmd->add.add_flags |= WIMLIB_ADD_IMAGE_FLAG_STRICT_ACLS;
		else if (!tstrcmp(option, T("--dereference")))
			cmd->add.add_flags |= WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE;
		else
			recognized = false;
		break;
	case WIMLIB_UPDATE_OP_DELETE:
		if (!tstrcmp(option, T("--force")))
			cmd->delete.delete_flags |= WIMLIB_DELETE_FLAG_FORCE;
		else if (!tstrcmp(option, T("--recursive")))
			cmd->delete.delete_flags |= WIMLIB_DELETE_FLAG_RECURSIVE;
		else
			recognized = false;
		break;
	default:
		recognized = false;
		break;
	}
	return recognized;
}

/* How many nonoption arguments each `imagex update' command expects */
static const unsigned update_command_num_nonoptions[] = {
	[WIMLIB_UPDATE_OP_ADD] = 2,
	[WIMLIB_UPDATE_OP_DELETE] = 1,
	[WIMLIB_UPDATE_OP_RENAME] = 2,
};

static void
update_command_add_nonoption(int op, const tchar *nonoption,
			     struct wimlib_update_command *cmd,
			     unsigned num_nonoptions)
{
	switch (op) {
	case WIMLIB_UPDATE_OP_ADD:
		if (num_nonoptions == 0)
			cmd->add.fs_source_path = (tchar*)nonoption;
		else
			cmd->add.wim_target_path = (tchar*)nonoption;
		break;
	case WIMLIB_UPDATE_OP_DELETE:
		cmd->delete.wim_path = (tchar*)nonoption;
		break;
	case WIMLIB_UPDATE_OP_RENAME:
		if (num_nonoptions == 0)
			cmd->rename.wim_source_path = (tchar*)nonoption;
		else
			cmd->rename.wim_target_path = (tchar*)nonoption;
		break;
	}
}

/*
 * Parse a command passed on stdin to `imagex update'.
 *
 * @line:	Text of the command.
 * @len:	Length of the line, including a null terminator
 *		at line[len - 1].
 *
 * @command:	A `struct wimlib_update_command' to fill in from the parsed
 *		line.
 *
 * @line_number: Line number of the command, for diagnostics.
 *
 * Returns true on success; returns false on parse error.
 */
static bool
parse_update_command(tchar *line, size_t len,
		     struct wimlib_update_command *command,
		     size_t line_number)
{
	int ret;
	tchar *command_name;
	int op;
	size_t num_nonoptions;

	/* Get the command name ("add", "delete", "rename") */
	ret = parse_string(&line, &len, &command_name);
	if (ret != PARSE_STRING_SUCCESS)
		return false;

	if (!tstrcasecmp(command_name, T("add"))) {
		op = WIMLIB_UPDATE_OP_ADD;
	} else if (!tstrcasecmp(command_name, T("delete"))) {
		op = WIMLIB_UPDATE_OP_DELETE;
	} else if (!tstrcasecmp(command_name, T("rename"))) {
		op = WIMLIB_UPDATE_OP_RENAME;
	} else {
		imagex_error(T("Unknown update command \"%"TS"\" on line %zu"),
			     command_name, line_number);
		return false;
	}
	command->op = op;

	/* Parse additional options and non-options as needed */
	num_nonoptions = 0;
	for (;;) {
		tchar *next_string;

		ret = parse_string(&line, &len, &next_string);
		if (ret == PARSE_STRING_NONE) /* End of line */
			break;
		else if (ret != PARSE_STRING_SUCCESS) /* Parse failure */
			return false;
		if (next_string[0] == T('-') && next_string[1] == T('-')) {
			/* Option */
			if (!update_command_add_option(op, next_string, command))
			{
				imagex_error(T("Unrecognized option \"%"TS"\" to "
					       "update command \"%"TS"\" on line %zu"),
					     next_string, command_name, line_number);

				return false;
			}
		} else {
			/* Nonoption */
			if (num_nonoptions == update_command_num_nonoptions[op])
			{
				imagex_error(T("Unexpected argument \"%"TS"\" in "
					       "update command on line %zu\n"
					       "       (The \"%"TS"\" command only "
					       "takes %u nonoption arguments!)\n"),
					     next_string, line_number,
					     command_name, num_nonoptions);
				return false;
			}
			update_command_add_nonoption(op, next_string,
						     command, num_nonoptions);
			num_nonoptions++;
		}
	}

	if (num_nonoptions != update_command_num_nonoptions[op]) {
		imagex_error(T("Not enough arguments to update command "
			       "\"%"TS"\" on line %zu"), command_name, line_number);
		return false;
	}
	return true;
}

static struct wimlib_update_command *
parse_update_command_file(tchar **cmd_file_contents_p, size_t cmd_file_nchars,
			  size_t *num_cmds_ret)
{
	ssize_t nlines;
	tchar *p;
	struct wimlib_update_command *cmds;
	size_t i, j;

	nlines = text_file_count_lines(cmd_file_contents_p,
				       &cmd_file_nchars);
	if (nlines < 0)
		return NULL;

	/* Always allocate at least 1 slot, just in case the implementation of
	 * calloc() returns NULL if 0 bytes are requested. */
	cmds = calloc(nlines ?: 1, sizeof(struct wimlib_update_command));
	if (!cmds) {
		imagex_error(T("out of memory"));
		return NULL;
	}
	p = *cmd_file_contents_p;
	j = 0;
	for (i = 0; i < nlines; i++) {
		/* XXX: Could use rawmemchr() here instead, but it may not be
		 * available on all platforms. */
		tchar *endp = tmemchr(p, T('\n'), cmd_file_nchars);
		size_t len = endp - p + 1;
		*endp = T('\0');
		if (!is_comment_line(p, len)) {
			if (!parse_update_command(p, len, &cmds[j++], i + 1)) {
				free(cmds);
				return NULL;
			}
		}
		p = endp + 1;
	}
	*num_cmds_ret = j;
	return cmds;
}

/* Apply one image, or all images, from a WIM file into a directory, OR apply
 * one image from a WIM file to a NTFS volume. */
static int
imagex_apply(int argc, tchar **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int image;
	int num_images;
	WIMStruct *w;
	int ret;
	const tchar *wimfile;
	const tchar *target;
	const tchar *image_num_or_name;
	int extract_flags = WIMLIB_EXTRACT_FLAG_SEQUENTIAL;

	const tchar *swm_glob = NULL;
	WIMStruct **additional_swms = NULL;
	unsigned num_additional_swms = 0;

	for_opt(c, apply_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_HARDLINK_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_HARDLINK;
			break;
		case IMAGEX_SYMLINK_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_SYMLINK;
			break;
		case IMAGEX_VERBOSE_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_VERBOSE;
			break;
		case IMAGEX_REF_OPTION:
			swm_glob = optarg;
			break;
		case IMAGEX_UNIX_DATA_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_UNIX_DATA;
			break;
		case IMAGEX_NO_ACLS_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_NO_ACLS;
			break;
		case IMAGEX_STRICT_ACLS_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_STRICT_ACLS;
			break;
		case IMAGEX_NORPFIX_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_NORPFIX;
			break;
		case IMAGEX_RPFIX_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_RPFIX;
			break;
		default:
			usage(APPLY);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 && argc != 3) {
		usage(APPLY);
		return -1;
	}

	wimfile = argv[0];
	if (argc == 2) {
		image_num_or_name = T("1");
		target = argv[1];
	} else {
		image_num_or_name = argv[1];
		target = argv[2];
	}

	ret = wimlib_open_wim(wimfile, open_flags, &w, imagex_progress_func);
	if (ret != 0)
		return ret;

	image = wimlib_resolve_image(w, image_num_or_name);
	ret = verify_image_exists(image, image_num_or_name, wimfile);
	if (ret != 0)
		goto out;

	num_images = wimlib_get_num_images(w);
	if (argc == 2 && num_images != 1) {
		imagex_error(T("\"%"TS"\" contains %d images; Please select one "
			       "(or all)."), wimfile, num_images);
		usage(APPLY);
		ret = -1;
		goto out;
	}

	if (swm_glob) {
		ret = open_swms_from_glob(swm_glob, wimfile, open_flags,
					  &additional_swms,
					  &num_additional_swms);
		if (ret != 0)
			goto out;
	}

	struct stat stbuf;

	ret = tstat(target, &stbuf);
	if (ret == 0) {
		if (S_ISBLK(stbuf.st_mode) || S_ISREG(stbuf.st_mode))
			extract_flags |= WIMLIB_EXTRACT_FLAG_NTFS;
	} else {
		if (errno != ENOENT) {
			imagex_error_with_errno(T("Failed to stat \"%"TS"\""),
						target);
			ret = -1;
			goto out;
		}
	}

#ifdef __WIN32__
	win32_acquire_restore_privileges();
#endif
	ret = wimlib_extract_image(w, image, target, extract_flags,
				   additional_swms, num_additional_swms,
				   imagex_progress_func);
	if (ret == 0)
		tprintf(T("Done applying WIM image.\n"));
#ifdef __WIN32__
	win32_release_restore_privileges();
#endif
out:
	wimlib_free(w);
	if (additional_swms) {
		for (unsigned i = 0; i < num_additional_swms; i++)
			wimlib_free(additional_swms[i]);
		free(additional_swms);
	}
	return ret;
}

/* Create a WIM image from a directory tree, NTFS volume, or multiple files or
 * directory trees.  'wimlib-imagex capture': create a new WIM file containing
 * the desired image.  'wimlib-imagex append': add a new image to an existing
 * WIM file. */
static int
imagex_capture_or_append(int argc, tchar **argv)
{
	int c;
	int open_flags = 0;
	int add_image_flags = WIMLIB_ADD_IMAGE_FLAG_EXCLUDE_VERBOSE;
	int write_flags = 0;
	int compression_type = WIMLIB_COMPRESSION_TYPE_XPRESS;
	const tchar *wimfile;
	const tchar *name;
	const tchar *desc;
	const tchar *flags_element = NULL;
	WIMStruct *w;
	int ret;
	int cur_image;
	int cmd = tstrcmp(argv[0], T("append")) ? CAPTURE : APPEND;
	unsigned num_threads = 0;

	tchar *source;
	size_t source_name_len;
	tchar *source_copy;

	const tchar *config_file = NULL;
	tchar *config_str;
	struct wimlib_capture_config *config = NULL;

	bool source_list = false;
	size_t source_list_nchars;
	tchar *source_list_contents;
	bool capture_sources_malloced;
	struct wimlib_capture_source *capture_sources;
	size_t num_sources;

	for_opt(c, capture_or_append_options) {
		switch (c) {
		case IMAGEX_BOOT_OPTION:
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_BOOT;
			break;
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_CONFIG_OPTION:
			config_file = optarg;
			break;
		case IMAGEX_COMPRESS_OPTION:
			compression_type = get_compression_type(optarg);
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				return -1;
			break;
		case IMAGEX_FLAGS_OPTION:
			flags_element = optarg;
			break;
		case IMAGEX_DEREFERENCE_OPTION:
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE;
			break;
		case IMAGEX_VERBOSE_OPTION:
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_VERBOSE;
			break;
		case IMAGEX_THREADS_OPTION:
			num_threads = parse_num_threads(optarg);
			if (num_threads == UINT_MAX)
				return -1;
			break;
		case IMAGEX_REBUILD_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_REBUILD;
			break;
		case IMAGEX_UNIX_DATA_OPTION:
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA;
			break;
		case IMAGEX_SOURCE_LIST_OPTION:
			source_list = true;
			break;
		case IMAGEX_NO_ACLS_OPTION:
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_NO_ACLS;
			break;
		case IMAGEX_STRICT_ACLS_OPTION:
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_STRICT_ACLS;
			break;
		case IMAGEX_RPFIX_OPTION:
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_RPFIX;
			break;
		case IMAGEX_NORPFIX_OPTION:
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_NORPFIX;
			break;
		default:
			usage(cmd);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2 || argc > 4) {
		usage(cmd);
		return -1;
	}

	source = argv[0];
	wimfile = argv[1];

	if (argc >= 3) {
		name = argv[2];
	} else {
		/* Set default name to SOURCE argument, omitting any directory
		 * prefixes and trailing slashes.  This requires making a copy
		 * of @source. */
		source_name_len = tstrlen(source);
		source_copy = alloca((source_name_len + 1) * sizeof(tchar));
		name = tbasename(tstrcpy(source_copy, source));
	}
	/* Image description defaults to NULL if not given. */
	desc = (argc >= 4) ? argv[3] : NULL;

	if (source_list) {
		/* Set up capture sources in source list mode */
		if (source[0] == T('-') && source[1] == T('\0')) {
			source_list_contents = stdin_get_text_contents(&source_list_nchars);
		} else {
			source_list_contents = file_get_text_contents(source,
								      &source_list_nchars);
		}
		if (!source_list_contents)
			return -1;

		capture_sources = parse_source_list(&source_list_contents,
						    source_list_nchars,
						    &num_sources);
		if (!capture_sources) {
			ret = -1;
			goto out_free_source_list_contents;
		}
		capture_sources_malloced = true;
	} else {
		/* Set up capture source in non-source-list mode (could be
		 * either "normal" mode or "NTFS mode"--- see the man page). */
		capture_sources = alloca(sizeof(struct wimlib_capture_source));
		capture_sources[0].fs_source_path = source;
		capture_sources[0].wim_target_path = NULL;
		capture_sources[0].reserved = 0;
		num_sources = 1;
		capture_sources_malloced = false;
		source_list_contents = NULL;
	}

	if (config_file) {
		size_t config_len;

		config_str = file_get_text_contents(config_file, &config_len);
		if (!config_str) {
			ret = -1;
			goto out_free_capture_sources;
		}

		config = alloca(sizeof(*config));
		ret = parse_capture_config(&config_str, config_len, config);
		if (ret)
			goto out_free_config;
	} else {
		config = &default_capture_config;
	}

	if (cmd == APPEND)
		ret = wimlib_open_wim(wimfile, open_flags, &w,
				      imagex_progress_func);
	else
		ret = wimlib_create_new_wim(compression_type, &w);
	if (ret)
		goto out_free_config;

	if (!source_list) {
		struct stat stbuf;
		ret = tstat(source, &stbuf);
		if (ret == 0) {
			if (S_ISBLK(stbuf.st_mode) || S_ISREG(stbuf.st_mode)) {
				tprintf(T("Capturing WIM image from NTFS "
					  "filesystem on \"%"TS"\"\n"), source);
				add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_NTFS;
			}
		} else {
			if (errno != ENOENT) {
				imagex_error_with_errno(T("Failed to stat "
							  "\"%"TS"\""), source);
				ret = -1;
				goto out_wimlib_free;
			}
		}
	}
#ifdef __WIN32__
	win32_acquire_capture_privileges();
#endif

	ret = wimlib_add_image_multisource(w,
					   capture_sources,
					   num_sources,
					   name,
					   config,
					   add_image_flags,
					   imagex_progress_func);
	if (ret != 0)
		goto out_release_privs;
	cur_image = wimlib_get_num_images(w);
	if (desc) {
		ret = wimlib_set_image_descripton(w, cur_image, desc);
		if (ret != 0)
			goto out_release_privs;
	}
	if (flags_element) {
		ret = wimlib_set_image_flags(w, cur_image, flags_element);
		if (ret != 0)
			goto out_release_privs;
	}
	if (cmd == APPEND) {
		ret = wimlib_overwrite(w, write_flags, num_threads,
				       imagex_progress_func);
	} else {
		ret = wimlib_write(w, wimfile, WIMLIB_ALL_IMAGES, write_flags,
				   num_threads, imagex_progress_func);
	}
	if (ret == WIMLIB_ERR_REOPEN)
		ret = 0;
	if (ret != 0)
		imagex_error(T("Failed to write the WIM file \"%"TS"\""),
			     wimfile);
out_release_privs:
#ifdef __WIN32__
	win32_release_capture_privileges();
#endif
out_wimlib_free:
	wimlib_free(w);
out_free_config:
	if (config != NULL && config != &default_capture_config) {
		free(config->exclusion_pats.pats);
		free(config->exclusion_exception_pats.pats);
		free(config_str);
	}
out_free_capture_sources:
	if (capture_sources_malloced)
		free(capture_sources);
out_free_source_list_contents:
	free(source_list_contents);
	return ret;
}

/* Remove image(s) from a WIM. */
static int
imagex_delete(int argc, tchar **argv)
{
	int c;
	int open_flags = 0;
	int write_flags = 0;
	const tchar *wimfile;
	const tchar *image_num_or_name;
	WIMStruct *w;
	int image;
	int ret;

	for_opt(c, delete_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_SOFT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_SOFT_DELETE;
			break;
		default:
			usage(DELETE);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2) {
		if (argc < 1)
			imagex_error(T("Must specify a WIM file"));
		if (argc < 2)
			imagex_error(T("Must specify an image"));
		usage(DELETE);
		return -1;
	}
	wimfile = argv[0];
	image_num_or_name = argv[1];

	ret = file_writable(wimfile);
	if (ret != 0)
		return ret;

	ret = wimlib_open_wim(wimfile, open_flags, &w,
			      imagex_progress_func);
	if (ret != 0)
		return ret;

	image = wimlib_resolve_image(w, image_num_or_name);

	ret = verify_image_exists(image, image_num_or_name, wimfile);
	if (ret != 0)
		goto out;

	ret = wimlib_delete_image(w, image);
	if (ret != 0) {
		imagex_error(T("Failed to delete image from \"%"TS"\""), wimfile);
		goto out;
	}

	ret = wimlib_overwrite(w, write_flags, 0, imagex_progress_func);
	if (ret == WIMLIB_ERR_REOPEN)
		ret = 0;
	if (ret != 0) {
		imagex_error(T("Failed to write the file \"%"TS"\" with image "
			       "deleted"), wimfile);
	}
out:
	wimlib_free(w);
	return ret;
}

/* Print the files contained in an image(s) in a WIM file. */
static int
imagex_dir(int argc, tchar **argv)
{
	const tchar *wimfile;
	WIMStruct *w;
	int image;
	int ret;
	int num_images;

	if (argc < 2) {
		imagex_error(T("Must specify a WIM file"));
		usage(DIR);
		return -1;
	}
	if (argc > 3) {
		imagex_error(T("Too many arguments"));
		usage(DIR);
		return -1;
	}

	wimfile = argv[1];
	ret = wimlib_open_wim(wimfile, WIMLIB_OPEN_FLAG_SPLIT_OK, &w,
			      imagex_progress_func);
	if (ret != 0)
		return ret;

	if (argc == 3) {
		image = wimlib_resolve_image(w, argv[2]);
		ret = verify_image_exists(image, argv[2], wimfile);
		if (ret != 0)
			goto out;
	} else {
		/* Image was not specified.  If the WIM only contains one image,
		 * choose that one; otherwise, print an error. */
		num_images = wimlib_get_num_images(w);
		if (num_images != 1) {
			imagex_error(T("The file \"%"TS"\" contains %d images; Please "
				       "select one."), wimfile, num_images);
			usage(DIR);
			ret = -1;
			goto out;
		}
		image = 1;
	}

	ret = wimlib_print_files(w, image);
out:
	wimlib_free(w);
	return ret;
}

/* Exports one, or all, images from a WIM file to a new WIM file or an existing
 * WIM file. */
static int
imagex_export(int argc, tchar **argv)
{
	int c;
	int open_flags = 0;
	int export_flags = 0;
	int write_flags = 0;
	int compression_type = WIMLIB_COMPRESSION_TYPE_NONE;
	bool compression_type_specified = false;
	const tchar *src_wimfile;
	const tchar *src_image_num_or_name;
	const tchar *dest_wimfile;
	const tchar *dest_name;
	const tchar *dest_desc;
	WIMStruct *src_w = NULL;
	WIMStruct *dest_w = NULL;
	int ret;
	int image;
	struct stat stbuf;
	bool wim_is_new;
	const tchar *swm_glob = NULL;
	WIMStruct **additional_swms = NULL;
	unsigned num_additional_swms = 0;
	unsigned num_threads = 0;

	for_opt(c, export_options) {
		switch (c) {
		case IMAGEX_BOOT_OPTION:
			export_flags |= WIMLIB_EXPORT_FLAG_BOOT;
			break;
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_COMPRESS_OPTION:
			compression_type = get_compression_type(optarg);
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				return -1;
			compression_type_specified = true;
			break;
		case IMAGEX_REF_OPTION:
			swm_glob = optarg;
			break;
		case IMAGEX_THREADS_OPTION:
			num_threads = parse_num_threads(optarg);
			if (num_threads == UINT_MAX)
				return -1;
			break;
		case IMAGEX_REBUILD_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_REBUILD;
			break;
		default:
			usage(EXPORT);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 3 || argc > 5) {
		usage(EXPORT);
		return -1;
	}
	src_wimfile           = argv[0];
	src_image_num_or_name = argv[1];
	dest_wimfile          = argv[2];
	dest_name             = (argc >= 4) ? argv[3] : NULL;
	dest_desc             = (argc >= 5) ? argv[4] : NULL;
	ret = wimlib_open_wim(src_wimfile,
			      open_flags | WIMLIB_OPEN_FLAG_SPLIT_OK, &src_w,
			      imagex_progress_func);
	if (ret != 0)
		return ret;

	/* Determine if the destination is an existing file or not.
	 * If so, we try to append the exported image(s) to it; otherwise, we
	 * create a new WIM containing the exported image(s). */
	if (tstat(dest_wimfile, &stbuf) == 0) {
		int dest_ctype;

		wim_is_new = false;
		/* Destination file exists. */

		if (!S_ISREG(stbuf.st_mode)) {
			imagex_error(T("\"%"TS"\" is not a regular file"),
				     dest_wimfile);
			ret = -1;
			goto out;
		}
		ret = wimlib_open_wim(dest_wimfile, open_flags, &dest_w,
				      imagex_progress_func);
		if (ret != 0)
			goto out;

		ret = file_writable(dest_wimfile);
		if (ret != 0)
			goto out;

		dest_ctype = wimlib_get_compression_type(dest_w);
		if (compression_type_specified
		    && compression_type != dest_ctype)
		{
			imagex_error(T("Cannot specify a compression type that is "
				       "not the same as that used in the "
				       "destination WIM"));
			ret = -1;
			goto out;
		}
	} else {
		wim_is_new = true;
		/* dest_wimfile is not an existing file, so create a new WIM. */
		if (!compression_type_specified)
			compression_type = wimlib_get_compression_type(src_w);
		if (errno == ENOENT) {
			ret = wimlib_create_new_wim(compression_type, &dest_w);
			if (ret != 0)
				goto out;
		} else {
			imagex_error_with_errno(T("Cannot stat file \"%"TS"\""),
						dest_wimfile);
			ret = -1;
			goto out;
		}
	}

	image = wimlib_resolve_image(src_w, src_image_num_or_name);
	ret = verify_image_exists(image, src_image_num_or_name, src_wimfile);
	if (ret != 0)
		goto out;

	if (swm_glob) {
		ret = open_swms_from_glob(swm_glob, src_wimfile, open_flags,
					  &additional_swms,
					  &num_additional_swms);
		if (ret != 0)
			goto out;
	}

	ret = wimlib_export_image(src_w, image, dest_w, dest_name, dest_desc,
				  export_flags, additional_swms,
				  num_additional_swms, imagex_progress_func);
	if (ret != 0)
		goto out;


	if (wim_is_new)
		ret = wimlib_write(dest_w, dest_wimfile, WIMLIB_ALL_IMAGES,
				   write_flags, num_threads,
				   imagex_progress_func);
	else
		ret = wimlib_overwrite(dest_w, write_flags, num_threads,
				       imagex_progress_func);
out:
	if (ret == WIMLIB_ERR_REOPEN)
		ret = 0;
	wimlib_free(src_w);
	wimlib_free(dest_w);
	if (additional_swms) {
		for (unsigned i = 0; i < num_additional_swms; i++)
			wimlib_free(additional_swms[i]);
		free(additional_swms);
	}
	return ret;
}

static bool
is_root_wim_path(const tchar *path)
{
	const tchar *p;
	for (p = path; *p; p++)
		if (*p != T('\\') && *p != T('/'))
			return false;
	return true;
}

static void
free_extract_commands(struct wimlib_extract_command *cmds, size_t num_cmds,
		      const tchar *dest_dir)
{
	for (size_t i = 0; i < num_cmds; i++)
		if (cmds[i].fs_dest_path != dest_dir)
			free(cmds[i].fs_dest_path);
	free(cmds);
}

static struct wimlib_extract_command *
prepare_extract_commands(tchar **paths, unsigned num_paths,
			 int extract_flags, tchar *dest_dir,
			 size_t *num_cmds_ret)
{
	struct wimlib_extract_command *cmds;
	size_t num_cmds;
	tchar *emptystr = T("");

	if (num_paths == 0) {
		num_paths = 1;
		paths = &emptystr;
	}
	num_cmds = num_paths;
	cmds = calloc(num_cmds, sizeof(cmds[0]));
	if (!cmds) {
		imagex_error(T("Out of memory!"));
		return NULL;
	}

	for (size_t i = 0; i < num_cmds; i++) {
		cmds[i].extract_flags = extract_flags;
		cmds[i].wim_source_path = paths[i];
		if (is_root_wim_path(paths[i])) {
			cmds[i].fs_dest_path = dest_dir;
		} else {
			size_t len = tstrlen(dest_dir) + 1 + tstrlen(paths[i]);
			cmds[i].fs_dest_path = malloc((len + 1) * sizeof(tchar));
			if (!cmds[i].fs_dest_path) {
				free_extract_commands(cmds, num_cmds, dest_dir);
				return NULL;
			}
			tsprintf(cmds[i].fs_dest_path, T("%"TS"/%"TS), dest_dir,
				 tbasename(paths[i]));
		}
	}
	*num_cmds_ret = num_cmds;
	return cmds;
}

/* Extract files or directories from a WIM image */
static int
imagex_extract(int argc, tchar **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int image;
	WIMStruct *wim;
	int ret;
	const tchar *wimfile;
	const tchar *image_num_or_name;
	tchar *dest_dir = T(".");
	int extract_flags = WIMLIB_EXTRACT_FLAG_SEQUENTIAL | WIMLIB_EXTRACT_FLAG_NORPFIX;

	const tchar *swm_glob = NULL;
	WIMStruct **additional_swms = NULL;
	unsigned num_additional_swms = 0;

	struct wimlib_extract_command *cmds;
	size_t num_cmds;

	for_opt(c, extract_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_VERBOSE_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_VERBOSE;
			break;
		case IMAGEX_REF_OPTION:
			swm_glob = optarg;
			break;
		case IMAGEX_UNIX_DATA_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_UNIX_DATA;
			break;
		case IMAGEX_NO_ACLS_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_NO_ACLS;
			break;
		case IMAGEX_STRICT_ACLS_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_STRICT_ACLS;
			break;
		case IMAGEX_DEST_DIR_OPTION:
			dest_dir = optarg;
			break;
		case IMAGEX_TO_STDOUT_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_TO_STDOUT;
			imagex_be_quiet = true;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2)
		goto out_usage;

	wimfile = argv[0];
	image_num_or_name = argv[1];

	argc -= 2;
	argv += 2;

	cmds = prepare_extract_commands(argv, argc, extract_flags, dest_dir,
					&num_cmds);
	if (!cmds) {
		ret = -1;
		goto out;
	}

	ret = wimlib_open_wim(wimfile, open_flags, &wim, imagex_progress_func);
	if (ret)
		goto out_free_cmds;

	image = wimlib_resolve_image(wim, image_num_or_name);
	ret = verify_image_exists_and_is_single(image,
						image_num_or_name,
						wimfile);
	if (ret)
		goto out_wimlib_free;

	if (swm_glob) {
		ret = open_swms_from_glob(swm_glob, wimfile, open_flags,
					  &additional_swms,
					  &num_additional_swms);
		if (ret)
			goto out_wimlib_free;
	}

#ifdef __WIN32__
	win32_acquire_restore_privileges();
#endif

	ret = wimlib_extract_files(wim, image, cmds, num_cmds, 0,
				   additional_swms, num_additional_swms,
				   imagex_progress_func);
	if (ret == 0) {
		if (!imagex_be_quiet)
			tprintf(T("Done extracting files.\n"));
	} else if (ret == WIMLIB_ERR_PATH_DOES_NOT_EXIST) {
		tfprintf(stderr, T("Note: You can use `"IMAGEX_PROGNAME" dir' to see what "
				   "files and directories\n"
				   "      are in the WIM image.\n"));
	}
#ifdef __WIN32__
	win32_release_restore_privileges();
#endif
	if (additional_swms) {
		for (unsigned i = 0; i < num_additional_swms; i++)
			wimlib_free(additional_swms[i]);
		free(additional_swms);
	}
out_wimlib_free:
	wimlib_free(wim);
out_free_cmds:
	free_extract_commands(cmds, num_cmds, dest_dir);
out:
	return ret;
out_usage:
	usage(EXTRACT);
	ret = -1;
	goto out;
}

/* Prints information about a WIM file; also can mark an image as bootable,
 * change the name of an image, or change the description of an image. */
static int
imagex_info(int argc, tchar **argv)
{
	int c;
	bool boot         = false;
	bool check        = false;
	bool header       = false;
	bool lookup_table = false;
	bool xml          = false;
	bool metadata     = false;
	bool short_header = true;
	const tchar *xml_out_file = NULL;
	const tchar *wimfile;
	const tchar *image_num_or_name = T("all");
	const tchar *new_name = NULL;
	const tchar *new_desc = NULL;
	WIMStruct *w;
	FILE *fp;
	int image;
	int ret;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int part_number;
	int total_parts;
	int num_images;

	for_opt(c, info_options) {
		switch (c) {
		case IMAGEX_BOOT_OPTION:
			boot = true;
			break;
		case IMAGEX_CHECK_OPTION:
			check = true;
			break;
		case IMAGEX_HEADER_OPTION:
			header = true;
			short_header = false;
			break;
		case IMAGEX_LOOKUP_TABLE_OPTION:
			lookup_table = true;
			short_header = false;
			break;
		case IMAGEX_XML_OPTION:
			xml = true;
			short_header = false;
			break;
		case IMAGEX_EXTRACT_XML_OPTION:
			xml_out_file = optarg;
			short_header = false;
			break;
		case IMAGEX_METADATA_OPTION:
			metadata = true;
			short_header = false;
			break;
		default:
			usage(INFO);
			return -1;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc == 0 || argc > 4) {
		usage(INFO);
		return -1;
	}
	wimfile = argv[0];
	if (argc > 1) {
		image_num_or_name = argv[1];
		if (argc > 2) {
			new_name = argv[2];
			if (argc > 3) {
				new_desc = argv[3];
			}
		}
	}

	if (check)
		open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;

	ret = wimlib_open_wim(wimfile, open_flags, &w,
			      imagex_progress_func);
	if (ret != 0)
		return ret;

	part_number = wimlib_get_part_number(w, &total_parts);

	image = wimlib_resolve_image(w, image_num_or_name);
	if (image == WIMLIB_NO_IMAGE && tstrcmp(image_num_or_name, T("0"))) {
		imagex_error(T("The image \"%"TS"\" does not exist"),
			     image_num_or_name);
		if (boot) {
			imagex_error(T("If you would like to set the boot "
				       "index to 0, specify image \"0\" with "
				       "the --boot flag."));
		}
		ret = WIMLIB_ERR_INVALID_IMAGE;
		goto out;
	}

	num_images = wimlib_get_num_images(w);

	if (num_images == 0) {
		if (boot) {
			imagex_error(T("--boot is meaningless on a WIM with no "
				       "images"));
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out;
		}
	}

	if (image == WIMLIB_ALL_IMAGES && num_images > 1) {
		if (boot) {
			imagex_error(T("Cannot specify the --boot flag "
				       "without specifying a specific "
				       "image in a multi-image WIM"));
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out;
		}
		if (new_name) {
			imagex_error(T("Cannot specify the NEW_NAME "
				       "without specifying a specific "
				       "image in a multi-image WIM"));
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out;
		}
	}

	/* Operations that print information are separated from operations that
	 * recreate the WIM file. */
	if (!new_name && !boot) {

		/* Read-only operations */

		if (image == WIMLIB_NO_IMAGE) {
			imagex_error(T("\"%"TS"\" is not a valid image"),
				     image_num_or_name);
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out;
		}

		if (image == WIMLIB_ALL_IMAGES && short_header)
			wimlib_print_wim_information(w);

		if (header)
			wimlib_print_header(w);

		if (lookup_table) {
			if (total_parts != 1) {
				tprintf(T("Warning: Only showing the lookup table "
					  "for part %d of a %d-part WIM.\n"),
					part_number, total_parts);
			}
			wimlib_print_lookup_table(w);
		}

		if (xml) {
			ret = wimlib_extract_xml_data(w, stdout);
			if (ret != 0)
				goto out;
		}

		if (xml_out_file) {
			fp = tfopen(xml_out_file, T("wb"));
			if (!fp) {
				imagex_error_with_errno(T("Failed to open the "
							  "file \"%"TS"\" for "
							  "writing "),
							xml_out_file);
				ret = -1;
				goto out;
			}
			ret = wimlib_extract_xml_data(w, fp);
			if (fclose(fp) != 0) {
				imagex_error(T("Failed to close the file "
					       "\"%"TS"\""),
					     xml_out_file);
				ret = -1;
			}

			if (ret != 0)
				goto out;
		}

		if (short_header)
			wimlib_print_available_images(w, image);

		if (metadata) {
			ret = wimlib_print_metadata(w, image);
			if (ret != 0)
				goto out;
		}
	} else {

		/* Modification operations */
		if (total_parts != 1) {
			imagex_error(T("Modifying a split WIM is not supported."));
			ret = -1;
			goto out;
		}
		if (image == WIMLIB_ALL_IMAGES)
			image = 1;

		if (image == WIMLIB_NO_IMAGE && new_name) {
			imagex_error(T("Cannot specify new_name (\"%"TS"\") "
				       "when using image 0"), new_name);
			ret = -1;
			goto out;
		}

		if (boot) {
			if (image == wimlib_get_boot_idx(w)) {
				tprintf(T("Image %d is already marked as "
					  "bootable.\n"), image);
				boot = false;
			} else {
				tprintf(T("Marking image %d as bootable.\n"),
					image);
				wimlib_set_boot_idx(w, image);
			}
		}
		if (new_name) {
			if (!tstrcmp(wimlib_get_image_name(w, image), new_name))
			{
				tprintf(T("Image %d is already named \"%"TS"\".\n"),
					image, new_name);
				new_name = NULL;
			} else {
				tprintf(T("Changing the name of image %d to "
					  "\"%"TS"\".\n"), image, new_name);
				ret = wimlib_set_image_name(w, image, new_name);
				if (ret != 0)
					goto out;
			}
		}
		if (new_desc) {
			const tchar *old_desc;
			old_desc = wimlib_get_image_description(w, image);
			if (old_desc && !tstrcmp(old_desc, new_desc)) {
				tprintf(T("The description of image %d is already "
					  "\"%"TS"\".\n"), image, new_desc);
				new_desc = NULL;
			} else {
				tprintf(T("Changing the description of image %d "
					  "to \"%"TS"\".\n"), image, new_desc);
				ret = wimlib_set_image_descripton(w, image,
								  new_desc);
				if (ret != 0)
					goto out;
			}
		}

		/* Only call wimlib_overwrite() if something actually needs to
		 * be changed. */
		if (boot || new_name || new_desc ||
		    (check && !wimlib_has_integrity_table(w)))
		{
			int write_flags;

			ret = file_writable(wimfile);
			if (ret != 0)
				goto out;

			if (check)
				write_flags = WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			else
				write_flags = 0;

			ret = wimlib_overwrite(w, write_flags, 1,
					       imagex_progress_func);
			if (ret == WIMLIB_ERR_REOPEN)
				ret = 0;
		} else {
			tprintf(T("The file \"%"TS"\" was not modified because nothing "
				  "needed to be done.\n"), wimfile);
			ret = 0;
		}
	}
out:
	wimlib_free(w);
	return ret;
}

/* Join split WIMs into one part WIM */
static int
imagex_join(int argc, tchar **argv)
{
	int c;
	int swm_open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int wim_write_flags = 0;
	const tchar *output_path;

	for_opt(c, join_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			swm_open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			wim_write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		default:
			goto err;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		imagex_error(T("Must specify one or more split WIM (.swm) "
			       "parts to join"));
		goto err;
	}
	output_path = argv[0];
	return wimlib_join((const tchar * const *)++argv,
			   --argc,
			   output_path,
			   swm_open_flags,
			   wim_write_flags,
			   imagex_progress_func);
err:
	usage(JOIN);
	return -1;
}

/* Mounts an image using a FUSE mount. */
static int
imagex_mount_rw_or_ro(int argc, tchar **argv)
{
	int c;
	int mount_flags = 0;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	const tchar *wimfile;
	const tchar *dir;
	WIMStruct *w;
	int image;
	int num_images;
	int ret;
	const tchar *swm_glob = NULL;
	WIMStruct **additional_swms = NULL;
	unsigned num_additional_swms = 0;
	const tchar *staging_dir = NULL;

	if (!tstrcmp(argv[0], T("mountrw")))
		mount_flags |= WIMLIB_MOUNT_FLAG_READWRITE;

	for_opt(c, mount_options) {
		switch (c) {
		case IMAGEX_ALLOW_OTHER_OPTION:
			mount_flags |= WIMLIB_MOUNT_FLAG_ALLOW_OTHER;
			break;
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_DEBUG_OPTION:
			mount_flags |= WIMLIB_MOUNT_FLAG_DEBUG;
			break;
		case IMAGEX_STREAMS_INTERFACE_OPTION:
			if (!tstrcasecmp(optarg, T("none")))
				mount_flags |= WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE;
			else if (!tstrcasecmp(optarg, T("xattr")))
				mount_flags |= WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR;
			else if (!tstrcasecmp(optarg, T("windows")))
				mount_flags |= WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS;
			else {
				imagex_error(T("Unknown stream interface \"%"TS"\""),
					     optarg);
				goto mount_usage;
			}
			break;
		case IMAGEX_REF_OPTION:
			swm_glob = optarg;
			break;
		case IMAGEX_STAGING_DIR_OPTION:
			staging_dir = optarg;
			break;
		case IMAGEX_UNIX_DATA_OPTION:
			mount_flags |= WIMLIB_MOUNT_FLAG_UNIX_DATA;
			break;
		default:
			goto mount_usage;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 && argc != 3)
		goto mount_usage;

	wimfile = argv[0];

	ret = wimlib_open_wim(wimfile, open_flags, &w,
			      imagex_progress_func);
	if (ret != 0)
		return ret;

	if (swm_glob) {
		ret = open_swms_from_glob(swm_glob, wimfile, open_flags,
					  &additional_swms,
					  &num_additional_swms);
		if (ret != 0)
			goto out;
	}

	if (argc == 2) {
		image = 1;
		num_images = wimlib_get_num_images(w);
		if (num_images != 1) {
			imagex_error(T("The file \"%"TS"\" contains %d images; Please "
				       "select one."), wimfile, num_images);
			usage((mount_flags & WIMLIB_MOUNT_FLAG_READWRITE)
					? MOUNTRW : MOUNT);
			ret = -1;
			goto out;
		}
		dir = argv[1];
	} else {
		image = wimlib_resolve_image(w, argv[1]);
		dir = argv[2];
		ret = verify_image_exists_and_is_single(image, argv[1], wimfile);
		if (ret != 0)
			goto out;
	}

	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		ret = file_writable(wimfile);
		if (ret != 0)
			goto out;
	}

	ret = wimlib_mount_image(w, image, dir, mount_flags, additional_swms,
				 num_additional_swms, staging_dir);
	if (ret != 0) {
		imagex_error(T("Failed to mount image %d from \"%"TS"\" "
			       "on \"%"TS"\""),
			     image, wimfile, dir);

	}
out:
	wimlib_free(w);
	if (additional_swms) {
		for (unsigned i = 0; i < num_additional_swms; i++)
			wimlib_free(additional_swms[i]);
		free(additional_swms);
	}
	return ret;
mount_usage:
	usage((mount_flags & WIMLIB_MOUNT_FLAG_READWRITE)
			? MOUNTRW : MOUNT);
	return -1;
}

/* Rebuild a WIM file */
static int
imagex_optimize(int argc, tchar **argv)
{
	int c;
	int open_flags = 0;
	int write_flags = WIMLIB_WRITE_FLAG_REBUILD;
	int ret;
	WIMStruct *w;
	const tchar *wimfile;
	off_t old_size;
	off_t new_size;
	unsigned num_threads = 0;

	for_opt(c, optimize_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_RECOMPRESS_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_RECOMPRESS;
			break;
		case IMAGEX_THREADS_OPTION:
			num_threads = parse_num_threads(optarg);
			if (num_threads == UINT_MAX)
				return -1;
			break;
		default:
			usage(OPTIMIZE);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage(OPTIMIZE);
		return -1;
	}

	wimfile = argv[0];

	ret = file_writable(wimfile);
	if (ret)
		return ret;

	ret = wimlib_open_wim(wimfile, open_flags, &w,
			      imagex_progress_func);
	if (ret)
		return ret;

	old_size = file_get_size(argv[0]);
	tprintf(T("\"%"TS"\" original size: "), wimfile);
	if (old_size == -1)
		tfputs(T("Unknown\n"), stdout);
	else
		tprintf(T("%"PRIu64" KiB\n"), old_size >> 10);

	ret = wimlib_overwrite(w, write_flags, num_threads,
			       imagex_progress_func);

	if (ret == 0) {
		new_size = file_get_size(argv[0]);
		tprintf(T("\"%"TS"\" optimized size: "), wimfile);
		if (new_size == -1)
			tfputs(T("Unknown\n"), stdout);
		else
			tprintf(T("%"PRIu64" KiB\n"), new_size >> 10);

		tfputs(T("Space saved: "), stdout);
		if (new_size != -1 && old_size != -1) {
			tprintf(T("%lld KiB\n"),
			       ((long long)old_size - (long long)new_size) >> 10);
		} else {
			tfputs(T("Unknown\n"), stdout);
		}
	}

	wimlib_free(w);
	return ret;
}

/* Split a WIM into a spanned set */
static int
imagex_split(int argc, tchar **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int write_flags = 0;
	unsigned long part_size;
	tchar *tmp;
	int ret;
	WIMStruct *w;

	for_opt(c, split_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		default:
			usage(SPLIT);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 3) {
		usage(SPLIT);
		return -1;
	}
	part_size = tstrtod(argv[2], &tmp) * (1 << 20);
	if (tmp == argv[2] || *tmp) {
		imagex_error(T("Invalid part size \"%"TS"\""), argv[2]);
		imagex_error(T("The part size must be an integer or "
			       "floating-point number of megabytes."));
		return -1;
	}
	ret = wimlib_open_wim(argv[0], open_flags, &w, imagex_progress_func);
	if (ret != 0)
		return ret;
	ret = wimlib_split(w, argv[1], part_size, write_flags, imagex_progress_func);
	wimlib_free(w);
	return ret;
}

/* Unmounts a mounted WIM image. */
static int
imagex_unmount(int argc, tchar **argv)
{
	int c;
	int unmount_flags = 0;
	int ret;

	for_opt(c, unmount_options) {
		switch (c) {
		case IMAGEX_COMMIT_OPTION:
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_COMMIT;
			break;
		case IMAGEX_CHECK_OPTION:
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_REBUILD_OPTION:
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_REBUILD;
			break;
		case IMAGEX_LAZY_OPTION:
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_LAZY;
			break;
		default:
			usage(UNMOUNT);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1) {
		usage(UNMOUNT);
		return -1;
	}

	ret = wimlib_unmount_image(argv[0], unmount_flags,
				   imagex_progress_func);
	if (ret != 0)
		imagex_error(T("Failed to unmount \"%"TS"\""), argv[0]);
	return ret;
}

/*
 * Add, delete, or rename files in a WIM image.
 */
static int
imagex_update(int argc, tchar **argv)
{
	const tchar *wimfile;
	const tchar *image_num_or_name;
	int image;
	WIMStruct *wim;
	int ret;
	int open_flags = 0;
	int write_flags = 0;
	int update_flags = 0;
	int default_add_flags = WIMLIB_ADD_IMAGE_FLAG_EXCLUDE_VERBOSE;
	int default_delete_flags = 0;
	unsigned num_threads = 0;
	int c;
	tchar *cmd_file_contents;
	size_t cmd_file_nchars;
	struct wimlib_update_command *cmds;
	size_t num_cmds;
	int num_images;

	const tchar *config_file = NULL;
	tchar *config_str;
	struct wimlib_capture_config *config = NULL;

	for_opt(c, update_options) {
		switch (c) {
		/* Generic or write options */
		case IMAGEX_THREADS_OPTION:
			num_threads = parse_num_threads(optarg);
			if (num_threads == UINT_MAX) {
				ret = -1;
				goto out;
			}
			break;
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_REBUILD_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_REBUILD;
			break;

		/* Default delete options */
		case IMAGEX_FORCE_OPTION:
			default_delete_flags |= WIMLIB_DELETE_FLAG_FORCE;
			break;
		case IMAGEX_RECURSIVE_OPTION:
			default_delete_flags |= WIMLIB_DELETE_FLAG_RECURSIVE;
			break;

		/* Global add option */
		case IMAGEX_CONFIG_OPTION:
			config_file = optarg;
			break;

		/* Default add options */
		case IMAGEX_VERBOSE_OPTION:
			default_add_flags |= WIMLIB_ADD_IMAGE_FLAG_VERBOSE;
			break;
		case IMAGEX_DEREFERENCE_OPTION:
			default_add_flags |= WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE;
			break;
		case IMAGEX_UNIX_DATA_OPTION:
			default_add_flags |= WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA;
			break;
		case IMAGEX_NO_ACLS_OPTION:
			default_add_flags |= WIMLIB_ADD_IMAGE_FLAG_NO_ACLS;
			break;
		case IMAGEX_STRICT_ACLS_OPTION:
			default_add_flags |= WIMLIB_ADD_IMAGE_FLAG_STRICT_ACLS;
			break;
		default:
			goto out_usage;
		}
	}
	argv += optind;
	argc -= optind;

	if (argc < 1 || argc > 2)
		goto out_usage;
	wimfile = argv[0];

	ret = file_writable(wimfile);
	if (ret)
		goto out;

	ret = wimlib_open_wim(wimfile, open_flags, &wim, imagex_progress_func);
	if (ret)
		goto out;

	if (argc == 2)
		image_num_or_name = argv[1];
	else
		image_num_or_name = T("1");

	image = wimlib_resolve_image(wim, image_num_or_name);

	ret = verify_image_exists_and_is_single(image, image_num_or_name,
						wimfile);
	if (ret)
		goto out_wimlib_free;

	num_images = wimlib_get_num_images(wim);
	if (argc == 1 && num_images != 1) {
		imagex_error(T("\"%"TS"\" contains %d images; Please select one."),
			     wimfile, num_images);
		usage(UPDATE);
		ret = -1;
		goto out_wimlib_free;
	}

	/* Parse capture configuration file if specified */
	if (config_file) {
		size_t config_len;

		config_str = file_get_text_contents(config_file, &config_len);
		if (!config_str) {
			ret = -1;
			goto out_wimlib_free;
		}

		config = alloca(sizeof(*config));
		ret = parse_capture_config(&config_str, config_len, config);
		if (ret)
			goto out_free_config;
	} else {
		config = &default_capture_config;
	}

	/* Read update commands from standard input */
	if (isatty(STDIN_FILENO)) {
		tputs(T("Reading update commands from standard input..."));
		recommend_man_page(T("update"));
	}
	cmd_file_contents = stdin_get_text_contents(&cmd_file_nchars);
	if (!cmd_file_contents) {
		ret = -1;
		goto out_free_config;
	}

	/* Parse the update commands */
	cmds = parse_update_command_file(&cmd_file_contents, cmd_file_nchars,
					 &num_cmds);
	if (!cmds) {
		ret = -1;
		goto out_free_cmd_file_contents;
	}

	/* Set default flags and capture config on the update commands */
	for (size_t i = 0; i < num_cmds; i++) {
		switch (cmds[i].op) {
		case WIMLIB_UPDATE_OP_ADD:
			cmds[i].add.add_flags |= default_add_flags;
			cmds[i].add.config = config;
			break;
		case WIMLIB_UPDATE_OP_DELETE:
			cmds[i].delete.delete_flags |= default_delete_flags;
			break;
		default:
			break;
		}
	}

	/* Execute the update commands */
	ret = wimlib_update_image(wim, image, cmds, num_cmds, update_flags,
				  imagex_progress_func);
	if (ret)
		goto out_free_cmds;

	/* Overwrite the updated WIM */
	ret = wimlib_overwrite(wim, write_flags, num_threads,
			       imagex_progress_func);
out_free_cmds:
	free(cmds);
out_free_cmd_file_contents:
	free(cmd_file_contents);
out_free_config:
	if (config != NULL && config != &default_capture_config) {
		free(config->exclusion_pats.pats);
		free(config->exclusion_exception_pats.pats);
		free(config_str);
	}
out_wimlib_free:
	wimlib_free(wim);
out:
	return ret;
out_usage:
	usage(UPDATE);
	ret = -1;
	goto out;
}

struct imagex_command {
	const tchar *name;
	int (*func)(int , tchar **);
	int cmd;
};


#define for_imagex_command(p) for (p = &imagex_commands[0]; \
		p != &imagex_commands[ARRAY_LEN(imagex_commands)]; p++)

static const struct imagex_command imagex_commands[] = {
	{T("append"),  imagex_capture_or_append, APPEND},
	{T("apply"),   imagex_apply,		 APPLY},
	{T("capture"), imagex_capture_or_append, CAPTURE},
	{T("delete"),  imagex_delete,		 DELETE},
	{T("dir"),     imagex_dir,		 DIR},
	{T("export"),  imagex_export,		 EXPORT},
	{T("extract"), imagex_extract,		 EXTRACT},
	{T("info"),    imagex_info,		 INFO},
	{T("join"),    imagex_join,		 JOIN},
	{T("mount"),   imagex_mount_rw_or_ro,	 MOUNT},
	{T("mountrw"), imagex_mount_rw_or_ro,	 MOUNTRW},
	{T("optimize"),imagex_optimize,		 OPTIMIZE},
	{T("split"),   imagex_split,		 SPLIT},
	{T("unmount"), imagex_unmount,		 UNMOUNT},
	{T("update"),  imagex_update,		 UPDATE},
};

static void
version(void)
{
	static const tchar *s =
	T(
IMAGEX_PROGNAME " (" PACKAGE ") " PACKAGE_VERSION "\n"
"Copyright (C) 2012, 2013 Eric Biggers\n"
"License GPLv3+; GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
"This is free software: you are free to change and redistribute it.\n"
"There is NO WARRANTY, to the extent permitted by law.\n"
"\n"
"Report bugs to "PACKAGE_BUGREPORT".\n"
	);
	tfputs(s, stdout);
}


static void
help_or_version(int argc, tchar **argv)
{
	int i;
	const tchar *p;
	const struct imagex_command *cmd;

	for (i = 1; i < argc; i++) {
		p = argv[i];
		if (*p == T('-'))
			p++;
		else
			continue;
		if (*p == T('-'))
			p++;
		if (!tstrcmp(p, T("help"))) {
			for_imagex_command(cmd) {
				if (!tstrcmp(cmd->name, argv[1])) {
					usage(cmd->cmd);
					exit(0);
				}
			}
			usage_all();
			exit(0);
		}
		if (!tstrcmp(p, T("version"))) {
			version();
			exit(0);
		}
	}
}


static void
usage(int cmd_type)
{
	const struct imagex_command *cmd;
	tprintf(T("Usage:\n%"TS), usage_strings[cmd_type]);
	for_imagex_command(cmd) {
		if (cmd->cmd == cmd_type) {
			tputc(T('\n'), stdout);
			recommend_man_page(cmd->name);
		}
	}
}

static void
usage_all(void)
{
	tfputs(T("Usage:\n"), stdout);
	for (int i = 0; i < ARRAY_LEN(usage_strings); i++)
		tprintf(T("    %"TS), usage_strings[i]);
	static const tchar *extra =
	T(
"    "IMAGEX_PROGNAME" --help\n"
"    "IMAGEX_PROGNAME" --version\n"
"\n"
"    The compression TYPE may be \"maximum\", \"fast\", or \"none\".\n"
"\n"
	);
	tfputs(extra, stdout);
	recommend_man_page(T(""));
}

/* Entry point for wimlib's ImageX implementation.  On UNIX the command
 * arguments will just be 'char' strings (ideally UTF-8 encoded, but could be
 * something else), while an Windows the command arguments will be UTF-16LE
 * encoded 'wchar_t' strings. */
int
#ifdef __WIN32__
wmain(int argc, wchar_t **argv, wchar_t **envp)
#else
main(int argc, char **argv)
#endif
{
	const struct imagex_command *cmd;
	int ret;
	int init_flags = 0;

#ifndef __WIN32__
	if (getenv("WIMLIB_IMAGEX_USE_UTF8")) {
		init_flags |= WIMLIB_INIT_FLAG_ASSUME_UTF8;
	} else {
		char *codeset;

		setlocale(LC_ALL, "");
		codeset = nl_langinfo(CODESET);
		if (!strstr(codeset, "UTF-8") &&
		    !strstr(codeset, "UTF8") &&
		    !strstr(codeset, "utf-8") &&
		    !strstr(codeset, "utf8"))
		{
			fputs(
"WARNING: Running "IMAGEX_PROGNAME" in a UTF-8 locale is recommended!\n"
"         Maybe try: `export LANG=en_US.UTF-8'?\n"
"         Alternatively, set the environmental variable WIMLIB_IMAGEX_USE_UTF8\n"
"         to any value to force wimlib to use UTF-8.\n",
			stderr);

		}
	}
#endif /* !__WIN32__ */

	if (argc < 2) {
		imagex_error(T("No command specified"));
		usage_all();
		ret = 2;
		goto out;
	}

	/* Handle --help and --version for all commands.  Note that this will
	 * not return if either of these arguments are present. */
	help_or_version(argc, argv);
	argc--;
	argv++;

	/* The user may like to see more informative error messages. */
	wimlib_set_print_errors(true);

	/* Do any initializations that the library needs */
	ret = wimlib_global_init(init_flags);
	if (ret)
		goto out_check_status;

	/* Search for the function to handle the ImageX subcommand. */
	for_imagex_command(cmd) {
		if (!tstrcmp(cmd->name, *argv)) {
			ret = cmd->func(argc, argv);
			goto out_check_write_error;
		}
	}

	imagex_error(T("Unrecognized command: `%"TS"'"), argv[0]);
	usage_all();
	ret = 2;
	goto out_cleanup;
out_check_write_error:
	/* For 'wimlib-imagex info' and 'wimlib-imagex dir', data printed to
	 * standard output is part of the program's actual behavior and not just
	 * for informational purposes, so we should set a failure exit status if
	 * there was a write error. */
	if (cmd == &imagex_commands[INFO] || cmd == &imagex_commands[DIR]) {
		if (ferror(stdout) || fclose(stdout)) {
			imagex_error_with_errno(T("error writing to standard output"));
			if (ret == 0)
				ret = -1;
		}
	}
out_check_status:
	/* Exit status (ret):  -1 indicates an error found by 'wimlib-imagex'
	 * outside of the wimlib library code.  0 indicates success.  > 0
	 * indicates a wimlib error code from which an error message can be
	 * printed. */
	if (ret > 0) {
		imagex_error(T("Exiting with error code %d:\n"
			       "       %"TS"."), ret,
			     wimlib_get_error_string(ret));
		if (ret == WIMLIB_ERR_NTFS_3G && errno != 0)
			imagex_error_with_errno(T("errno"));
	}
out_cleanup:
	/* Make the library free any resources it's holding (not strictly
	 * necessary because the process is ending anyway). */
	wimlib_global_cleanup();
out:
	return ret;
}
