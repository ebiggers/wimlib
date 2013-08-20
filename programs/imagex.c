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
#  define OS_PREFERRED_PATH_SEPARATOR L'\\'
#  define OS_PREFERRED_PATH_SEPARATOR_STRING L"\\"
#else /* __WIN32__ */
#  include <glob.h>
#  include <getopt.h>
#  include <langinfo.h>
#  define tbasename	basename
#  define OS_PREFERRED_PATH_SEPARATOR '/'
#  define OS_PREFERRED_PATH_SEPARATOR_STRING "/"
static inline void set_fd_to_binary_mode(int fd)
{
}
#endif /* !__WIN32 */

/* Don't confuse the user by presenting the mounting commands on Windows when
 * they will never work.  However on UNIX-like systems we always present them,
 * even if WITH_FUSE is not defined at this point, as to not tie the build of
 * wimlib-imagex to a specific build of wimlib.  */
#ifdef __WIN32__
#  define WIM_MOUNTING_SUPPORTED 0
#else
#  define WIM_MOUNTING_SUPPORTED 1
#endif

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

#define for_opt(c, opts) while ((c = getopt_long_only(argc, (tchar**)argv, T(""), \
				opts, NULL)) != -1)

enum {
	CMD_NONE = -1,
	CMD_APPEND = 0,
	CMD_APPLY,
	CMD_CAPTURE,
	CMD_DELETE,
	CMD_DIR,
	CMD_EXPORT,
	CMD_EXTRACT,
	CMD_INFO,
	CMD_JOIN,
#if WIM_MOUNTING_SUPPORTED
	CMD_MOUNT,
	CMD_MOUNTRW,
#endif
	CMD_OPTIMIZE,
	CMD_SPLIT,
#if WIM_MOUNTING_SUPPORTED
	CMD_UNMOUNT,
#endif
	CMD_UPDATE,
	CMD_MAX,
};

static void usage(int cmd, FILE *fp);
static void usage_all(FILE *fp);
static void recommend_man_page(int cmd, FILE *fp);
static const tchar *get_cmd_string(int cmd, bool nospace);

static int imagex_progress_func(enum wimlib_progress_msg msg,
				const union wimlib_progress_info *info);

static bool imagex_be_quiet = false;
static FILE *imagex_info_file;

#define imagex_printf(format, ...) \
		tfprintf(imagex_info_file, format, ##__VA_ARGS__)

enum {
	IMAGEX_ALLOW_OTHER_OPTION,
	IMAGEX_AS_DELTA_FROM_OPTION,
	IMAGEX_AS_UPDATE_OF_OPTION,
	IMAGEX_BOOT_OPTION,
	IMAGEX_CHECK_OPTION,
	IMAGEX_COMMAND_OPTION,
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
	IMAGEX_INCLUDE_INVALID_NAMES_OPTION,
	IMAGEX_LAZY_OPTION,
	IMAGEX_LOOKUP_TABLE_OPTION,
	IMAGEX_METADATA_OPTION,
	IMAGEX_NORPFIX_OPTION,
	IMAGEX_NOCHECK_OPTION,
	IMAGEX_NO_ACLS_OPTION,
	IMAGEX_NOT_PIPABLE_OPTION,
	IMAGEX_PATH_OPTION,
	IMAGEX_PIPABLE_OPTION,
	IMAGEX_REBUILD_OPTION,
	IMAGEX_RECOMPRESS_OPTION,
	IMAGEX_RECURSIVE_OPTION,
	IMAGEX_REF_OPTION,
	IMAGEX_RESUME_OPTION,
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
	{T("include-invalid-names"), no_argument,       NULL, IMAGEX_INCLUDE_INVALID_NAMES_OPTION},

	/* --resume is undocumented for now as it needs improvement.  */
	{T("resume"),      no_argument,       NULL, IMAGEX_RESUME_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option capture_or_append_options[] = {
	{T("boot"),        no_argument,       NULL, IMAGEX_BOOT_OPTION},
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("no-check"),    no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("nocheck"),     no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
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
	{T("pipable"),     no_argument,       NULL, IMAGEX_PIPABLE_OPTION},
	{T("not-pipable"), no_argument,       NULL, IMAGEX_NOT_PIPABLE_OPTION},
	{T("as-update-of"),  required_argument, NULL, IMAGEX_AS_UPDATE_OF_OPTION},
	{T("as-update-from"), required_argument, NULL, IMAGEX_AS_UPDATE_OF_OPTION},
	{T("as-delta-from"),   required_argument, NULL, IMAGEX_AS_DELTA_FROM_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option delete_options[] = {
	{T("check"), no_argument, NULL, IMAGEX_CHECK_OPTION},
	{T("soft"),  no_argument, NULL, IMAGEX_SOFT_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option dir_options[] = {
	{T("path"), required_argument, NULL, IMAGEX_PATH_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option export_options[] = {
	{T("boot"),        no_argument,       NULL, IMAGEX_BOOT_OPTION},
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("nocheck"),     no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("no-check"),    no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("compress"),    required_argument, NULL, IMAGEX_COMPRESS_OPTION},
	{T("ref"),         required_argument, NULL, IMAGEX_REF_OPTION},
	{T("threads"),     required_argument, NULL, IMAGEX_THREADS_OPTION},
	{T("rebuild"),     no_argument,       NULL, IMAGEX_REBUILD_OPTION},
	{T("pipable"),     no_argument,       NULL, IMAGEX_PIPABLE_OPTION},
	{T("not-pipable"), no_argument,       NULL, IMAGEX_NOT_PIPABLE_OPTION},
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
	{T("include-invalid-names"), no_argument, NULL, IMAGEX_INCLUDE_INVALID_NAMES_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option info_options[] = {
	{T("boot"),         no_argument,       NULL, IMAGEX_BOOT_OPTION},
	{T("check"),        no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("nocheck"),      no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("no-check"),     no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
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
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("nocheck"),     no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("no-check"),    no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("recompress"),  no_argument,       NULL, IMAGEX_RECOMPRESS_OPTION},
	{T("threads"),     required_argument, NULL, IMAGEX_THREADS_OPTION},
	{T("pipable"),     no_argument,       NULL, IMAGEX_PIPABLE_OPTION},
	{T("not-pipable"), no_argument,       NULL, IMAGEX_NOT_PIPABLE_OPTION},
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
	{T("command"),     required_argument, NULL, IMAGEX_COMMAND_OPTION},

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

#if 0
#	define _format_attribute(type, format_str, args_start) \
			__attribute__((format(type, format_str, args_start)))
#else
#	define _format_attribute(type, format_str, args_start)
#endif

/* Print formatted error message to stderr. */
static void _format_attribute(printf, 1, 2)
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
static void _format_attribute(printf, 1, 2)
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
			     "       You may use `%"TS"' to list the images "
			     "contained in a WIM."),
			     image_name, wim_name, get_cmd_string(CMD_INFO, false));
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

struct refglob_set {
	const tchar **globs;
	unsigned num_globs;
	unsigned num_alloc_globs;
};

#define REFGLOB_SET_INITIALIZER \
	{ .globs = NULL, .num_globs = 0, .num_alloc_globs = 0, }

#define REFGLOB_SET(_refglobs) \
	struct refglob_set _refglobs = REFGLOB_SET_INITIALIZER

static int
refglob_set_append(struct refglob_set *set, const tchar *glob)
{
	unsigned num_alloc_globs = set->num_alloc_globs;

	if (set->num_globs == num_alloc_globs) {
		const tchar **new_globs;

		num_alloc_globs += 4;
		new_globs = realloc(set->globs, sizeof(set->globs[0]) * num_alloc_globs);
		if (!new_globs) {
			imagex_error(T("Out of memory!"));
			return -1;
		}
		set->globs = new_globs;
		set->num_alloc_globs = num_alloc_globs;
	}
	set->globs[set->num_globs++] = glob;
	return 0;
}

static int
wim_reference_globs(WIMStruct *wim, struct refglob_set *set, int open_flags)
{
	return wimlib_reference_resource_files(wim, set->globs, set->num_globs,
					       WIMLIB_REF_FLAG_GLOB_ENABLE,
					       open_flags,
					       imagex_progress_func);
}

static void
refglob_set_destroy(struct refglob_set *set)
{
	free(set->globs);
}

static void
do_resource_not_found_warning(const tchar *wimfile,
			      const struct wimlib_wim_info *info,
			      const struct refglob_set *refglobs)
{
	if (info->total_parts > 1) {
		if (refglobs->num_globs == 0) {
			imagex_error(T("\"%"TS"\" is part of a split WIM. "
				       "Use --ref to specify the other parts."),
				     wimfile);
		} else {
			imagex_error(T("Perhaps the '--ref' argument did not "
				       "specify all other parts of the split "
				       "WIM?"));
		}
	} else {
		imagex_error(T("If this is a delta WIM, use the --ref argument "
			       "to specify the WIM on which it is based."));
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

	buf = malloc(len ? len : 1);
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

#define GIBIBYTE_MIN_NBYTES 10000000000ULL
#define MEBIBYTE_MIN_NBYTES 10000000ULL
#define KIBIBYTE_MIN_NBYTES 10000ULL

static unsigned
get_unit(uint64_t total_bytes, const tchar **name_ret)
{
	if (total_bytes >= GIBIBYTE_MIN_NBYTES) {
		*name_ret = T("GiB");
		return 30;
	} else if (total_bytes >= MEBIBYTE_MIN_NBYTES) {
		*name_ret = T("MiB");
		return 20;
	} else if (total_bytes >= KIBIBYTE_MIN_NBYTES) {
		*name_ret = T("KiB");
		return 10;
	} else {
		*name_ret = T("bytes");
		return 0;
	}
}

/* Progress callback function passed to various wimlib functions. */
static int
imagex_progress_func(enum wimlib_progress_msg msg,
		     const union wimlib_progress_info *info)
{
	unsigned percent_done;
	unsigned unit_shift;
	const tchar *unit_name;
	if (imagex_be_quiet)
		return 0;
	switch (msg) {
	case WIMLIB_PROGRESS_MSG_WRITE_STREAMS:
		unit_shift = get_unit(info->write_streams.total_bytes, &unit_name);
		percent_done = TO_PERCENT(info->write_streams.completed_bytes,
					  info->write_streams.total_bytes);

		if (info->write_streams.completed_streams == 0) {
			const tchar *data_type;

			data_type = get_data_type(info->write_streams.compression_type);
			imagex_printf(T("Writing %"TS" data using %u thread%"TS"\n"),
				data_type, info->write_streams.num_threads,
				(info->write_streams.num_threads == 1) ? T("") : T("s"));
		}
		if (info->write_streams.total_parts <= 1) {
			imagex_printf(T("\r%"PRIu64" %"TS" of %"PRIu64" %"TS" (uncompressed) "
				"written (%u%% done)"),
				info->write_streams.completed_bytes >> unit_shift,
				unit_name,
				info->write_streams.total_bytes >> unit_shift,
				unit_name,
				percent_done);
		} else {
			imagex_printf(T("\rWriting resources from part %u of %u: "
				  "%"PRIu64 " %"TS" of %"PRIu64" %"TS" (%u%%) written"),
				(info->write_streams.completed_parts ==
					info->write_streams.total_parts) ?
						info->write_streams.completed_parts :
						info->write_streams.completed_parts + 1,
				info->write_streams.total_parts,
				info->write_streams.completed_bytes >> unit_shift,
				unit_name,
				info->write_streams.total_bytes >> unit_shift,
				unit_name,
				percent_done);
		}
		if (info->write_streams.completed_bytes >= info->write_streams.total_bytes)
			imagex_printf(T("\n"));
		break;
	case WIMLIB_PROGRESS_MSG_SCAN_BEGIN:
		imagex_printf(T("Scanning \"%"TS"\""), info->scan.source);
		if (*info->scan.wim_target_path) {
			imagex_printf(T(" (loading as WIM path: "
				  "\""WIMLIB_WIM_PATH_SEPARATOR_STRING"%"TS"\")...\n"),
			       info->scan.wim_target_path);
		} else {
			imagex_printf(T(" (loading as root of WIM image)...\n"));
		}
		break;
	case WIMLIB_PROGRESS_MSG_SCAN_DENTRY:
		switch (info->scan.status) {
		case WIMLIB_SCAN_DENTRY_OK:
			imagex_printf(T("Scanning \"%"TS"\"\n"), info->scan.cur_path);
			break;
		case WIMLIB_SCAN_DENTRY_EXCLUDED:
			imagex_printf(T("Excluding \"%"TS"\" from capture\n"), info->scan.cur_path);
			break;
		case WIMLIB_SCAN_DENTRY_UNSUPPORTED:
			imagex_printf(T("WARNING: Excluding unsupported file or directory\n"
					"         \"%"TS"\" from capture\n"), info->scan.cur_path);
			break;
		}
		break;
	case WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY:
		unit_shift = get_unit(info->integrity.total_bytes, &unit_name);
		percent_done = TO_PERCENT(info->integrity.completed_bytes,
					  info->integrity.total_bytes);
		imagex_printf(T("\rVerifying integrity of \"%"TS"\": %"PRIu64" %"TS" "
			"of %"PRIu64" %"TS" (%u%%) done"),
			info->integrity.filename,
			info->integrity.completed_bytes >> unit_shift,
			unit_name,
			info->integrity.total_bytes >> unit_shift,
			unit_name,
			percent_done);
		if (info->integrity.completed_bytes == info->integrity.total_bytes)
			imagex_printf(T("\n"));
		break;
	case WIMLIB_PROGRESS_MSG_CALC_INTEGRITY:
		unit_shift = get_unit(info->integrity.total_bytes, &unit_name);
		percent_done = TO_PERCENT(info->integrity.completed_bytes,
					  info->integrity.total_bytes);
		imagex_printf(T("\rCalculating integrity table for WIM: %"PRIu64" %"TS" "
			  "of %"PRIu64" %"TS" (%u%%) done"),
			info->integrity.completed_bytes >> unit_shift,
			unit_name,
			info->integrity.total_bytes >> unit_shift,
			unit_name,
			percent_done);
		if (info->integrity.completed_bytes == info->integrity.total_bytes)
			imagex_printf(T("\n"));
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN:
		imagex_printf(T("Applying image %d (\"%"TS"\") from \"%"TS"\" "
			  "to %"TS" \"%"TS"\"\n"),
			info->extract.image,
			info->extract.image_name,
			info->extract.wimfile_name,
			((info->extract.extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) ?
			 T("NTFS volume") : T("directory")),
			info->extract.target);
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN:
		imagex_printf(T("Extracting "
			  "\""WIMLIB_WIM_PATH_SEPARATOR_STRING"%"TS"\" from image %d (\"%"TS"\") "
			  "in \"%"TS"\" to \"%"TS"\"\n"),
			info->extract.extract_root_wim_source_path,
			info->extract.image,
			info->extract.image_name,
			info->extract.wimfile_name,
			info->extract.target);
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS:
		percent_done = TO_PERCENT(info->extract.completed_bytes,
					  info->extract.total_bytes);
		unit_shift = get_unit(info->extract.total_bytes, &unit_name);
		imagex_printf(T("\rExtracting files: "
			  "%"PRIu64" %"TS" of %"PRIu64" %"TS" (%u%%) done"),
			info->extract.completed_bytes >> unit_shift,
			unit_name,
			info->extract.total_bytes >> unit_shift,
			unit_name,
			percent_done);
		if (info->extract.completed_bytes >= info->extract.total_bytes)
			imagex_printf(T("\n"));
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN:
		if (info->extract.total_parts != 1) {
			imagex_printf(T("\nReading split pipable WIM part %u of %u\n"),
				      info->extract.part_number,
				      info->extract.total_parts);
		}
		break;
	case WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS:
		if (info->extract.extract_root_wim_source_path[0] == T('\0'))
			imagex_printf(T("Setting timestamps on all extracted files...\n"));
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END:
		if (info->extract.extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
			imagex_printf(T("Unmounting NTFS volume \"%"TS"\"...\n"),
				info->extract.target);
		}
		break;
	case WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART:
		percent_done = TO_PERCENT(info->split.completed_bytes,
					  info->split.total_bytes);
		unit_shift = get_unit(info->split.total_bytes, &unit_name);
		imagex_printf(T("Writing \"%"TS"\" (part %u of %u): %"PRIu64" %"TS" of "
			  "%"PRIu64" %"TS" (%u%%) written\n"),
			info->split.part_name,
			info->split.cur_part_number,
			info->split.total_parts,
			info->split.completed_bytes >> unit_shift,
			unit_name,
			info->split.total_bytes >> unit_shift,
			unit_name,
			percent_done);
		break;
	case WIMLIB_PROGRESS_MSG_SPLIT_END_PART:
		if (info->split.completed_bytes == info->split.total_bytes) {
			imagex_printf(T("Finished writing split WIM part %u of %u\n"),
				info->split.cur_part_number,
				info->split.total_parts);
		}
		break;
	case WIMLIB_PROGRESS_MSG_UPDATE_END_COMMAND:
		switch (info->update.command->op) {
		case WIMLIB_UPDATE_OP_DELETE:
			imagex_printf(T("Deleted WIM path "
				  "\""WIMLIB_WIM_PATH_SEPARATOR_STRING "%"TS"\"\n"),
				info->update.command->delete.wim_path);
			break;
		case WIMLIB_UPDATE_OP_RENAME:
			imagex_printf(T("Renamed WIM path "
				  "\""WIMLIB_WIM_PATH_SEPARATOR_STRING "%"TS"\" => "
				  "\""WIMLIB_WIM_PATH_SEPARATOR_STRING "%"TS"\"\n"),
				info->update.command->rename.wim_source_path,
				info->update.command->rename.wim_target_path);
			break;
		case WIMLIB_UPDATE_OP_ADD:
		default:
			break;
		}
		break;
	default:
		break;
	}
	fflush(imagex_info_file);
	return 0;
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
			cmd->add.add_flags |= WIMLIB_ADD_FLAG_VERBOSE;
		else if (!tstrcmp(option, T("--unix-data")))
			cmd->add.add_flags |= WIMLIB_ADD_FLAG_UNIX_DATA;
		else if (!tstrcmp(option, T("--no-acls")) || !tstrcmp(option, T("--noacls")))
			cmd->add.add_flags |= WIMLIB_ADD_FLAG_NO_ACLS;
		else if (!tstrcmp(option, T("--strict-acls")))
			cmd->add.add_flags |= WIMLIB_ADD_FLAG_STRICT_ACLS;
		else if (!tstrcmp(option, T("--dereference")))
			cmd->add.add_flags |= WIMLIB_ADD_FLAG_DEREFERENCE;
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
					       "takes %zu nonoption arguments!)\n"),
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
 * one image from a WIM file to a NTFS volume.  */
static int
imagex_apply(int argc, tchar **argv, int cmd)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int image = WIMLIB_NO_IMAGE;
	WIMStruct *wim;
	struct wimlib_wim_info info;
	int ret;
	const tchar *wimfile;
	const tchar *target;
	const tchar *image_num_or_name = NULL;
	int extract_flags = WIMLIB_EXTRACT_FLAG_SEQUENTIAL;

	REFGLOB_SET(refglobs);

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
			ret = refglob_set_append(&refglobs, optarg);
			if (ret)
				goto out_free_refglobs;
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
		case IMAGEX_INCLUDE_INVALID_NAMES_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES;
			extract_flags |= WIMLIB_EXTRACT_FLAG_ALL_CASE_CONFLICTS;
			break;
		case IMAGEX_RESUME_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_RESUME;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 && argc != 3)
		goto out_usage;

	wimfile = argv[0];

	if (!tstrcmp(wimfile, T("-"))) {
		/* Attempt to apply pipable WIM from standard input.  */
		if (argc == 2) {
			image_num_or_name = NULL;
			target = argv[1];
		} else {
			image_num_or_name = argv[1];
			target = argv[2];
		}
		wim = NULL;
	} else {
		ret = wimlib_open_wim(wimfile, open_flags, &wim,
				      imagex_progress_func);
		if (ret)
			goto out_free_refglobs;

		wimlib_get_wim_info(wim, &info);

		if (argc >= 3) {
			/* Image explicitly specified.  */
			image_num_or_name = argv[1];
			image = wimlib_resolve_image(wim, image_num_or_name);
			ret = verify_image_exists(image, image_num_or_name, wimfile);
			if (ret)
				goto out_wimlib_free;
			target = argv[2];
		} else {
			/* No image specified; default to image 1, but only if the WIM
			 * contains exactly one image.  */

			if (info.image_count != 1) {
				imagex_error(T("\"%"TS"\" contains %d images; "
					       "Please select one (or all)."),
					     wimfile, info.image_count);
				wimlib_free(wim);
				goto out_usage;
			}
			image = 1;
			target = argv[1];
		}
	}

	if (refglobs.num_globs) {
		if (wim == NULL) {
			imagex_error(T("Can't specify --ref when applying from stdin!"));
			ret = -1;
			goto out_wimlib_free;
		}
		ret = wim_reference_globs(wim, &refglobs, open_flags);
		if (ret)
			goto out_wimlib_free;
	}

#ifndef __WIN32__
	{
		/* Interpret a regular file or block device target as a NTFS
		 * volume.  */
		struct stat stbuf;

		if (tstat(target, &stbuf)) {
			if (errno != ENOENT) {
				imagex_error_with_errno(T("Failed to stat \"%"TS"\""),
							target);
				ret = -1;
				goto out_wimlib_free;
			}
		} else {
			if (S_ISBLK(stbuf.st_mode) || S_ISREG(stbuf.st_mode))
				extract_flags |= WIMLIB_EXTRACT_FLAG_NTFS;
		}
	}
#endif

	if (wim) {
		ret = wimlib_extract_image(wim, image, target, extract_flags,
					   imagex_progress_func);
	} else {
		set_fd_to_binary_mode(STDIN_FILENO);
		ret = wimlib_extract_image_from_pipe(STDIN_FILENO,
						     image_num_or_name,
						     target, extract_flags,
						     imagex_progress_func);
	}
	if (ret == 0) {
		imagex_printf(T("Done applying WIM image.\n"));
	} else if (ret == WIMLIB_ERR_RESOURCE_NOT_FOUND) {
		if (wim) {
			do_resource_not_found_warning(wimfile, &info, &refglobs);
		} else {
			imagex_error(T(        "If you are applying an image "
					       "from a split pipable WIM,\n"
				       "       make sure you have "
				       "concatenated together all parts."));
		}
	}
out_wimlib_free:
	wimlib_free(wim);
out_free_refglobs:
	refglob_set_destroy(&refglobs);
	return ret;

out_usage:
	usage(CMD_APPLY, stderr);
	ret = -1;
	goto out_free_refglobs;
}

/* Create a WIM image from a directory tree, NTFS volume, or multiple files or
 * directory trees.  'wimlib-imagex capture': create a new WIM file containing
 * the desired image.  'wimlib-imagex append': add a new image to an existing
 * WIM file. */
static int
imagex_capture_or_append(int argc, tchar **argv, int cmd)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_WRITE_ACCESS;
	int add_image_flags = WIMLIB_ADD_IMAGE_FLAG_EXCLUDE_VERBOSE |
			      WIMLIB_ADD_IMAGE_FLAG_WINCONFIG;
	int write_flags = 0;
	int compression_type = WIMLIB_COMPRESSION_TYPE_LZX;
	const tchar *wimfile;
	int wim_fd;
	const tchar *name;
	const tchar *desc;
	const tchar *flags_element = NULL;

	WIMStruct *wim;
	WIMStruct *base_wim;
	const tchar *base_wimfile = NULL;
	WIMStruct *template_wim;
	const tchar *template_wimfile = NULL;
	const tchar *template_image_name_or_num = NULL;
	int template_image = WIMLIB_NO_IMAGE;

	int ret;
	unsigned num_threads = 0;

	tchar *source;
	tchar *source_copy;

	const tchar *config_file = NULL;
	tchar *config_str;
	struct wimlib_capture_config *config;

	bool source_list = false;
	size_t source_list_nchars = 0;
	tchar *source_list_contents;
	bool capture_sources_malloced;
	struct wimlib_capture_source *capture_sources;
	size_t num_sources;
	bool name_defaulted;

	for_opt(c, capture_or_append_options) {
		switch (c) {
		case IMAGEX_BOOT_OPTION:
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_BOOT;
			break;
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_NOCHECK_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY;
			break;
		case IMAGEX_CONFIG_OPTION:
			config_file = optarg;
			add_image_flags &= ~WIMLIB_ADD_IMAGE_FLAG_WINCONFIG;
			break;
		case IMAGEX_COMPRESS_OPTION:
			compression_type = get_compression_type(optarg);
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				goto out_err;
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
				goto out_err;
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
		case IMAGEX_PIPABLE_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
			break;
		case IMAGEX_NOT_PIPABLE_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NOT_PIPABLE;
			break;
		case IMAGEX_AS_UPDATE_OF_OPTION:
			if (template_image_name_or_num) {
				imagex_error(T("'--as-update-of' can only be "
					       "specified one time!"));
				goto out_err;
			} else {
				tchar *colon;
				colon = tstrrchr(optarg, T(':'));

				if (colon) {
					template_wimfile = optarg;
					*colon = T('\0');
					template_image_name_or_num = colon + 1;
				} else {
					template_wimfile = NULL;
					template_image_name_or_num = optarg;
				}
			}
			break;
		case IMAGEX_AS_DELTA_FROM_OPTION:
			if (cmd != CMD_CAPTURE) {
				imagex_error(T("'--as-delta-from' is only "
					       "valid for capture!"));
				goto out_usage;
			}
			if (base_wimfile) {
				imagex_error(T("'--as-delta-from' can only be "
					       "specified one time!"));
				goto out_err;
			}
			base_wimfile = optarg;
			write_flags |= WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2 || argc > 4)
		goto out_usage;

	source = argv[0];
	wimfile = argv[1];

	if (!tstrcmp(wimfile, T("-"))) {
		/* Writing captured WIM to standard output.  */
	#if 0
		if (!(write_flags & WIMLIB_WRITE_FLAG_PIPABLE)) {
			imagex_error("Can't write a non-pipable WIM to "
				     "standard output!  Specify --pipable\n"
				     "       if you want to create a pipable WIM "
				     "(but read the docs first).");
			goto out_err;
		}
	#else
		write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
	#endif
		if (cmd == CMD_APPEND) {
			imagex_error(T("Using standard output for append does "
				       "not make sense."));
			goto out_err;
		}
		wim_fd = STDOUT_FILENO;
		wimfile = NULL;
		imagex_info_file = stderr;
		set_fd_to_binary_mode(wim_fd);
	}

	/* If template image was specified using --as-update-of=IMAGE rather
	 * than --as-update-of=WIMFILE:IMAGE, set the default WIMFILE.  */
	if (template_image_name_or_num && !template_wimfile) {
		if (base_wimfile) {
			/* Capturing delta WIM:  default to base WIM.  */
			template_wimfile = base_wimfile;
		} else if (cmd == CMD_APPEND) {
			/* Appending to WIM:  default to WIM being appended to.
			 */
			template_wimfile = wimfile;
		} else {
			/* Capturing a normal (non-delta) WIM, so the WIM file
			 * *must* be explicitly specified.  */
			imagex_error(T("For capture of non-delta WIM, "
				       "'--as-update-of' must specify "
				       "WIMFILE:IMAGE!"));
			goto out_usage;
		}
	}

	if (argc >= 3) {
		name = argv[2];
		name_defaulted = false;
	} else {
		/* Set default name to SOURCE argument, omitting any directory
		 * prefixes and trailing slashes.  This requires making a copy
		 * of @source.  Leave some free characters at the end in case we
		 * append a number to keep the name unique. */
		size_t source_name_len;

		source_name_len = tstrlen(source);
		source_copy = alloca((source_name_len + 1 + 25) * sizeof(tchar));
		name = tbasename(tstrcpy(source_copy, source));
		name_defaulted = true;
	}
	/* Image description defaults to NULL if not given. */
	if (argc >= 4)
		desc = argv[3];
	else
		desc = NULL;

	if (source_list) {
		/* Set up capture sources in source list mode */
		if (source[0] == T('-') && source[1] == T('\0')) {
			source_list_contents = stdin_get_text_contents(&source_list_nchars);
		} else {
			source_list_contents = file_get_text_contents(source,
								      &source_list_nchars);
		}
		if (!source_list_contents)
			goto out_err;

		capture_sources = parse_source_list(&source_list_contents,
						    source_list_nchars,
						    &num_sources);
		if (!capture_sources) {
			ret = -1;
			goto out_free_source_list_contents;
		}
		capture_sources_malloced = true;
	} else {
		/* Set up capture source in non-source-list mode.  */
		capture_sources = alloca(sizeof(struct wimlib_capture_source));
		capture_sources[0].fs_source_path = source;
		capture_sources[0].wim_target_path = NULL;
		capture_sources[0].reserved = 0;
		num_sources = 1;
		capture_sources_malloced = false;
		source_list_contents = NULL;
	}

	if (config_file) {
		/* Read and parse capture configuration file.  */
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
		/* No capture configuration file specified; use default
		 * configuration for capturing Windows operating systems.  */
		config = NULL;
		add_image_flags |= WIMLIB_ADD_FLAG_WINCONFIG;
	}

	/* Open the existing WIM, or create a new one.  */
	if (cmd == CMD_APPEND)
		ret = wimlib_open_wim(wimfile, open_flags, &wim,
				      imagex_progress_func);
	else
		ret = wimlib_create_new_wim(compression_type, &wim);
	if (ret)
		goto out_free_config;

#ifndef __WIN32__
	/* Detect if source is regular file or block device and set NTFS volume
	 * capture mode.  */
	if (!source_list) {
		struct stat stbuf;

		if (tstat(source, &stbuf) == 0) {
			if (S_ISBLK(stbuf.st_mode) || S_ISREG(stbuf.st_mode)) {
				imagex_printf(T("Capturing WIM image from NTFS "
					  "filesystem on \"%"TS"\"\n"), source);
				add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_NTFS;
			}
		} else {
			if (errno != ENOENT) {
				imagex_error_with_errno(T("Failed to stat "
							  "\"%"TS"\""), source);
				ret = -1;
				goto out_free_wim;
			}
		}
	}
#endif

	/* If the user did not specify an image name, and the basename of the
	 * source already exists as an image name in the WIM file, append a
	 * suffix to make it unique. */
	if (cmd == CMD_APPEND && name_defaulted) {
		unsigned long conflict_idx;
		tchar *name_end = tstrchr(name, T('\0'));
		for (conflict_idx = 1;
		     wimlib_image_name_in_use(wim, name);
		     conflict_idx++)
		{
			tsprintf(name_end, T(" (%lu)"), conflict_idx);
		}
	}

	/* If capturing a delta WIM, reference resources from the base WIM
	 * before adding the new image.  */
	if (base_wimfile) {
		ret = wimlib_open_wim(base_wimfile, open_flags,
				      &base_wim, imagex_progress_func);
		if (ret)
			goto out_free_wim;

		imagex_printf(T("Capturing delta WIM based on \"%"TS"\"\n"),
			      base_wimfile);

		ret = wimlib_reference_resources(wim, &base_wim, 1, 0);
		if (ret)
			goto out_free_base_wim;
	} else {
		base_wim = NULL;
	}

	/* If capturing or appending as an update of an existing (template) image,
	 * open the WIM if needed and parse the image index.  */
	if (template_image_name_or_num) {


		if (template_wimfile == base_wimfile) {
			template_wim = base_wim;
		} else if (template_wimfile == wimfile) {
			template_wim = wim;
		} else {
			ret = wimlib_open_wim(template_wimfile, open_flags,
					      &template_wim, imagex_progress_func);
			if (ret)
				goto out_free_base_wim;
		}

		template_image = wimlib_resolve_image(template_wim,
						      template_image_name_or_num);

		if (template_image_name_or_num[0] == T('-')) {
			tchar *tmp;
			unsigned long n;
			struct wimlib_wim_info info;

			wimlib_get_wim_info(wim, &info);
			n = tstrtoul(template_image_name_or_num + 1, &tmp, 10);
			if (n >= 1 && n <= info.image_count &&
			    *tmp == T('\0') &&
			    tmp != template_image_name_or_num + 1)
			{
				template_image = info.image_count - (n - 1);
			}
		}
		ret = verify_image_exists_and_is_single(template_image,
							template_image_name_or_num,
							template_wimfile);
		if (ret)
			goto out_free_template_wim;
	} else {
		template_wim = NULL;
	}

	ret = wimlib_add_image_multisource(wim,
					   capture_sources,
					   num_sources,
					   name,
					   config,
					   add_image_flags,
					   imagex_progress_func);
	if (ret)
		goto out_free_template_wim;

	if (desc || flags_element || template_image_name_or_num) {
		/* User provided <DESCRIPTION> or <FLAGS> element, or an image
		 * on which the added one is to be based has been specified with
		 * --as-update-of.  Get the index of the image we just
		 *  added, then use it to call the appropriate functions.  */
		struct wimlib_wim_info info;

		wimlib_get_wim_info(wim, &info);

		if (desc) {
			ret = wimlib_set_image_descripton(wim,
							  info.image_count,
							  desc);
			if (ret)
				goto out_free_template_wim;
		}

		if (flags_element) {
			ret = wimlib_set_image_flags(wim, info.image_count,
						     flags_element);
			if (ret)
				goto out_free_template_wim;
		}

		/* Reference template image if the user provided one.  */
		if (template_image_name_or_num) {
			imagex_printf(T("Using image %d "
					"from \"%"TS"\" as template\n"),
					template_image, template_wimfile);
			ret = wimlib_reference_template_image(wim,
							      info.image_count,
							      template_wim,
							      template_image,
							      0, NULL);
			if (ret)
				goto out_free_template_wim;
		}
	}

	/* Write the new WIM or overwrite the existing WIM with the new image
	 * appended.  */
	if (cmd == CMD_APPEND) {
		ret = wimlib_overwrite(wim, write_flags, num_threads,
				       imagex_progress_func);
	} else if (wimfile) {
		ret = wimlib_write(wim, wimfile, WIMLIB_ALL_IMAGES,
				   write_flags, num_threads,
				   imagex_progress_func);
	} else {
		ret = wimlib_write_to_fd(wim, wim_fd, WIMLIB_ALL_IMAGES,
					 write_flags, num_threads,
					 imagex_progress_func);
	}
out_free_template_wim:
	/* template_wim may alias base_wim or wim.  */
	if (template_wim != base_wim && template_wim != wim)
		wimlib_free(template_wim);
out_free_base_wim:
	wimlib_free(base_wim);
out_free_wim:
	wimlib_free(wim);
out_free_config:
	if (config) {
		free(config->exclusion_pats.pats);
		free(config->exclusion_exception_pats.pats);
		free(config_str);
	}
out_free_capture_sources:
	if (capture_sources_malloced)
		free(capture_sources);
out_free_source_list_contents:
	free(source_list_contents);
out:
	return ret;

out_usage:
	usage(cmd, stderr);
out_err:
	ret = -1;
	goto out;
}

/* Remove image(s) from a WIM. */
static int
imagex_delete(int argc, tchar **argv, int cmd)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_WRITE_ACCESS;
	int write_flags = 0;
	const tchar *wimfile;
	const tchar *image_num_or_name;
	WIMStruct *wim;
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
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2) {
		if (argc < 1)
			imagex_error(T("Must specify a WIM file"));
		if (argc < 2)
			imagex_error(T("Must specify an image"));
		goto out_usage;
	}
	wimfile = argv[0];
	image_num_or_name = argv[1];

	ret = wimlib_open_wim(wimfile, open_flags, &wim,
			      imagex_progress_func);
	if (ret)
		goto out;

	image = wimlib_resolve_image(wim, image_num_or_name);

	ret = verify_image_exists(image, image_num_or_name, wimfile);
	if (ret)
		goto out_wimlib_free;

	ret = wimlib_delete_image(wim, image);
	if (ret) {
		imagex_error(T("Failed to delete image from \"%"TS"\""),
			     wimfile);
		goto out_wimlib_free;
	}

	ret = wimlib_overwrite(wim, write_flags, 0, imagex_progress_func);
	if (ret) {
		imagex_error(T("Failed to write the file \"%"TS"\" with image "
			       "deleted"), wimfile);
	}
out_wimlib_free:
	wimlib_free(wim);
out:
	return ret;

out_usage:
	usage(CMD_DELETE, stderr);
	ret = -1;
	goto out;
}

static int
print_full_path(const struct wimlib_dir_entry *wdentry, void *_ignore)
{
	int ret = tprintf(T("%"TS"\n"), wdentry->full_path);
	return (ret >= 0) ? 0 : -1;
}

/* Print the files contained in an image(s) in a WIM file. */
static int
imagex_dir(int argc, tchar **argv, int cmd)
{
	const tchar *wimfile;
	WIMStruct *wim = NULL;
	int image;
	int ret;
	const tchar *path = T("");
	int c;

	for_opt(c, dir_options) {
		switch (c) {
		case IMAGEX_PATH_OPTION:
			path = optarg;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		imagex_error(T("Must specify a WIM file"));
		goto out_usage;
	}
	if (argc > 2) {
		imagex_error(T("Too many arguments"));
		goto out_usage;
	}

	wimfile = argv[0];
	ret = wimlib_open_wim(wimfile, WIMLIB_OPEN_FLAG_SPLIT_OK, &wim,
			      imagex_progress_func);
	if (ret)
		goto out;

	if (argc >= 2) {
		image = wimlib_resolve_image(wim, argv[1]);
		ret = verify_image_exists(image, argv[1], wimfile);
		if (ret)
			goto out_wimlib_free;
	} else {
		/* No image specified; default to image 1, but only if the WIM
		 * contains exactly one image.  */

		struct wimlib_wim_info info;

		wimlib_get_wim_info(wim, &info);
		if (info.image_count != 1) {
			imagex_error(T("\"%"TS"\" contains %d images; Please "
				       "select one (or all)."),
				     wimfile, info.image_count);
			wimlib_free(wim);
			goto out_usage;
		}
		image = 1;
	}

	ret = wimlib_iterate_dir_tree(wim, image, path,
				      WIMLIB_ITERATE_DIR_TREE_FLAG_RECURSIVE,
				      print_full_path, NULL);
out_wimlib_free:
	wimlib_free(wim);
out:
	return ret;

out_usage:
	usage(CMD_DIR, stderr);
	ret = -1;
	goto out;
}

/* Exports one, or all, images from a WIM file to a new WIM file or an existing
 * WIM file. */
static int
imagex_export(int argc, tchar **argv, int cmd)
{
	int c;
	int open_flags = 0;
	int export_flags = 0;
	int write_flags = 0;
	int compression_type = WIMLIB_COMPRESSION_TYPE_INVALID;
	const tchar *src_wimfile;
	const tchar *src_image_num_or_name;
	const tchar *dest_wimfile;
	int dest_wim_fd;
	const tchar *dest_name;
	const tchar *dest_desc;
	WIMStruct *src_wim;
	struct wimlib_wim_info src_info;
	WIMStruct *dest_wim;
	int ret;
	int image;
	struct stat stbuf;
	bool wim_is_new;
	REFGLOB_SET(refglobs);
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
		case IMAGEX_NOCHECK_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY;
			break;
		case IMAGEX_COMPRESS_OPTION:
			compression_type = get_compression_type(optarg);
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				goto out_err;
			break;
		case IMAGEX_REF_OPTION:
			ret = refglob_set_append(&refglobs, optarg);
			if (ret)
				goto out_free_refglobs;
			break;
		case IMAGEX_THREADS_OPTION:
			num_threads = parse_num_threads(optarg);
			if (num_threads == UINT_MAX)
				goto out_err;
			break;
		case IMAGEX_REBUILD_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_REBUILD;
			break;
		case IMAGEX_PIPABLE_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
			break;
		case IMAGEX_NOT_PIPABLE_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NOT_PIPABLE;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 3 || argc > 5)
		goto out_usage;
	src_wimfile           = argv[0];
	src_image_num_or_name = argv[1];
	dest_wimfile          = argv[2];
	dest_name             = (argc >= 4) ? argv[3] : NULL;
	dest_desc             = (argc >= 5) ? argv[4] : NULL;
	ret = wimlib_open_wim(src_wimfile,
			      open_flags | WIMLIB_OPEN_FLAG_SPLIT_OK, &src_wim,
			      imagex_progress_func);
	if (ret)
		goto out_free_refglobs;

	wimlib_get_wim_info(src_wim, &src_info);

	/* Determine if the destination is an existing file or not.  If so, we
	 * try to append the exported image(s) to it; otherwise, we create a new
	 * WIM containing the exported image(s).  Furthermore, determine if we
	 * need to write a pipable WIM directly to standard output.  */

	if (tstrcmp(dest_wimfile, T("-")) == 0) {
	#if 0
		if (!(write_flags & WIMLIB_WRITE_FLAG_PIPABLE)) {
			imagex_error("Can't write a non-pipable WIM to "
				     "standard output!  Specify --pipable\n"
				     "       if you want to create a pipable WIM "
				     "(but read the docs first).");
			ret = -1;
			goto out_free_src_wim;
		}
	#else
		write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
	#endif
		dest_wimfile = NULL;
		dest_wim_fd = STDOUT_FILENO;
		imagex_info_file = stderr;
		set_fd_to_binary_mode(dest_wim_fd);
	}
	errno = ENOENT;
	if (dest_wimfile != NULL && tstat(dest_wimfile, &stbuf) == 0) {
		wim_is_new = false;
		/* Destination file exists. */

		if (!S_ISREG(stbuf.st_mode)) {
			imagex_error(T("\"%"TS"\" is not a regular file"),
				     dest_wimfile);
			ret = -1;
			goto out_free_src_wim;
		}
		ret = wimlib_open_wim(dest_wimfile, open_flags | WIMLIB_OPEN_FLAG_WRITE_ACCESS,
				      &dest_wim, imagex_progress_func);
		if (ret)
			goto out_free_src_wim;

		if (compression_type != WIMLIB_COMPRESSION_TYPE_INVALID) {
			/* The user specified a compression type, but we're
			 * exporting to an existing WIM.  Make sure the
			 * specified compression type is the same as the
			 * compression type of the existing destination WIM. */
			struct wimlib_wim_info dest_info;

			wimlib_get_wim_info(dest_wim, &dest_info);
			if (compression_type != dest_info.compression_type) {
				imagex_error(T("Cannot specify a compression type that is "
					       "not the same as that used in the "
					       "destination WIM"));
				ret = -1;
				goto out_free_dest_wim;
			}
		}
	} else {
		wim_is_new = true;

		if (errno != ENOENT) {
			imagex_error_with_errno(T("Cannot stat file \"%"TS"\""),
						dest_wimfile);
			ret = -1;
			goto out_free_src_wim;
		}

		/* dest_wimfile is not an existing file, so create a new WIM. */

		if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID) {
			/* The user did not specify a compression type; default
			 * to that of the source WIM.  */

			compression_type = src_info.compression_type;
		}
		ret = wimlib_create_new_wim(compression_type, &dest_wim);
		if (ret)
			goto out_free_src_wim;
	}

	image = wimlib_resolve_image(src_wim, src_image_num_or_name);
	ret = verify_image_exists(image, src_image_num_or_name, src_wimfile);
	if (ret)
		goto out_free_dest_wim;

	if (refglobs.num_globs) {
		ret = wim_reference_globs(src_wim, &refglobs, open_flags);
		if (ret)
			goto out_free_dest_wim;
	}

	if ((export_flags & WIMLIB_EXPORT_FLAG_BOOT) &&
	    image == WIMLIB_ALL_IMAGES && src_info.boot_index == 0)
	{
		imagex_error(T("--boot specified for all-images export, but source WIM "
			       "has no bootable image."));
		ret = -1;
		goto out_free_dest_wim;
	}

	ret = wimlib_export_image(src_wim, image, dest_wim, dest_name,
				  dest_desc, export_flags, imagex_progress_func);
	if (ret) {
		if (ret == WIMLIB_ERR_RESOURCE_NOT_FOUND) {
			do_resource_not_found_warning(src_wimfile,
						      &src_info, &refglobs);
		}
		goto out_free_dest_wim;
	}

	if (!wim_is_new)
		ret = wimlib_overwrite(dest_wim, write_flags, num_threads,
				       imagex_progress_func);
	else if (dest_wimfile)
		ret = wimlib_write(dest_wim, dest_wimfile, WIMLIB_ALL_IMAGES,
				   write_flags, num_threads,
				   imagex_progress_func);
	else
		ret = wimlib_write_to_fd(dest_wim, dest_wim_fd,
					 WIMLIB_ALL_IMAGES, write_flags,
					 num_threads, imagex_progress_func);
out_free_dest_wim:
	wimlib_free(dest_wim);
out_free_src_wim:
	wimlib_free(src_wim);
out_free_refglobs:
	refglob_set_destroy(&refglobs);
	return ret;

out_usage:
	usage(CMD_EXPORT, stderr);
out_err:
	ret = -1;
	goto out_free_refglobs;
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
			tsprintf(cmds[i].fs_dest_path,
				 T("%"TS""OS_PREFERRED_PATH_SEPARATOR_STRING"%"TS),
				 dest_dir, tbasename(paths[i]));
		}
	}
	*num_cmds_ret = num_cmds;
	return cmds;
}

/* Extract files or directories from a WIM image */
static int
imagex_extract(int argc, tchar **argv, int cmd)
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

	REFGLOB_SET(refglobs);

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
			ret = refglob_set_append(&refglobs, optarg);
			if (ret)
				goto out_free_refglobs;
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
			imagex_info_file = stderr;
			imagex_be_quiet = true;
			break;
		case IMAGEX_INCLUDE_INVALID_NAMES_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES;
			extract_flags |= WIMLIB_EXTRACT_FLAG_ALL_CASE_CONFLICTS;
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
	if (!cmds)
		goto out_err;

	ret = wimlib_open_wim(wimfile, open_flags, &wim, imagex_progress_func);
	if (ret)
		goto out_free_cmds;

	image = wimlib_resolve_image(wim, image_num_or_name);
	ret = verify_image_exists_and_is_single(image,
						image_num_or_name,
						wimfile);
	if (ret)
		goto out_wimlib_free;

	if (refglobs.num_globs) {
		ret = wim_reference_globs(wim, &refglobs, open_flags);
		if (ret)
			goto out_wimlib_free;
	}

	ret = wimlib_extract_files(wim, image, cmds, num_cmds, 0,
				   imagex_progress_func);
	if (ret == 0) {
		if (!imagex_be_quiet)
			imagex_printf(T("Done extracting files.\n"));
	} else if (ret == WIMLIB_ERR_PATH_DOES_NOT_EXIST) {
		tfprintf(stderr, T("Note: You can use `%"TS"' to see what "
				   "files and directories\n"
				   "      are in the WIM image.\n"),
				get_cmd_string(CMD_INFO, false));
	} else if (ret == WIMLIB_ERR_RESOURCE_NOT_FOUND) {
		struct wimlib_wim_info info;

		wimlib_get_wim_info(wim, &info);
		do_resource_not_found_warning(wimfile, &info, &refglobs);
	}
out_wimlib_free:
	wimlib_free(wim);
out_free_cmds:
	free_extract_commands(cmds, num_cmds, dest_dir);
out_free_refglobs:
	refglob_set_destroy(&refglobs);
	return ret;

out_usage:
	usage(CMD_EXTRACT, stderr);
out_err:
	ret = -1;
	goto out_free_refglobs;
}

static void print_byte_field(const uint8_t field[], size_t len)
{
	while (len--)
		tprintf(T("%02hhx"), *field++);
}

static void
print_wim_information(const tchar *wimfile, const struct wimlib_wim_info *info)
{
	tputs(T("WIM Information:"));
	tputs(T("----------------"));
	tprintf(T("Path:           %"TS"\n"), wimfile);
	tprintf(T("GUID:           0x"));
	print_byte_field(info->guid, sizeof(info->guid));
	tputchar(T('\n'));
	tprintf(T("Image Count:    %d\n"), info->image_count);
	tprintf(T("Compression:    %"TS"\n"),
		wimlib_get_compression_type_string(info->compression_type));
	tprintf(T("Part Number:    %d/%d\n"), info->part_number, info->total_parts);
	tprintf(T("Boot Index:     %d\n"), info->boot_index);
	tprintf(T("Size:           %"PRIu64" bytes\n"), info->total_bytes);
	tprintf(T("Integrity Info: %"TS"\n"),
		info->has_integrity_table ? T("yes") : T("no"));
	tprintf(T("Relative path junction: %"TS"\n"),
		info->has_rpfix ? T("yes") : T("no"));
	tprintf(T("Pipable:        %"TS"\n"),
		info->pipable ? T("yes") : T("no"));
	tputchar(T('\n'));
}

static int
print_resource(const struct wimlib_resource_entry *resource,
	       void *_ignore)
{

	tprintf(T("Uncompressed size   = %"PRIu64" bytes\n"),
		resource->uncompressed_size);

	tprintf(T("Compressed size     = %"PRIu64" bytes\n"),
		resource->compressed_size);

	tprintf(T("Offset              = %"PRIu64" bytes\n"),
		resource->offset);


	tprintf(T("Part Number         = %u\n"), resource->part_number);
	tprintf(T("Reference Count     = %u\n"), resource->reference_count);

	tprintf(T("Hash                = 0x"));
	print_byte_field(resource->sha1_hash, sizeof(resource->sha1_hash));
	tputchar(T('\n'));

	tprintf(T("Flags               = "));
	if (resource->is_compressed)
		tprintf(T("WIM_RESHDR_FLAG_COMPRESSED  "));
	if (resource->is_metadata)
		tprintf(T("WIM_RESHDR_FLAG_METADATA  "));
	if (resource->is_free)
		tprintf(T("WIM_RESHDR_FLAG_FREE  "));
	if (resource->is_spanned)
		tprintf(T("WIM_RESHDR_FLAG_SPANNED  "));
	tputchar(T('\n'));
	tputchar(T('\n'));
	return 0;
}

static void
print_lookup_table(WIMStruct *wim)
{
	wimlib_iterate_lookup_table(wim, 0, print_resource, NULL);
}

/* Prints information about a WIM file; also can mark an image as bootable,
 * change the name of an image, or change the description of an image. */
static int
imagex_info(int argc, tchar **argv, int cmd)
{
	int c;
	bool boot         = false;
	bool check        = false;
	bool nocheck      = false;
	bool header       = false;
	bool lookup_table = false;
	bool xml          = false;
	bool metadata     = false;
	bool short_header = true;
	const tchar *xml_out_file = NULL;
	const tchar *wimfile;
	const tchar *image_num_or_name;
	const tchar *new_name;
	const tchar *new_desc;
	WIMStruct *wim;
	int image;
	int ret;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	struct wimlib_wim_info info;

	for_opt(c, info_options) {
		switch (c) {
		case IMAGEX_BOOT_OPTION:
			boot = true;
			break;
		case IMAGEX_CHECK_OPTION:
			check = true;
			break;
		case IMAGEX_NOCHECK_OPTION:
			nocheck = true;
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
			goto out_usage;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc < 1 || argc > 4)
		goto out_usage;

	wimfile		  = argv[0];
	image_num_or_name = (argc >= 2) ? argv[1] : T("all");
	new_name	  = (argc >= 3) ? argv[2] : NULL;
	new_desc	  = (argc >= 4) ? argv[3] : NULL;

	if (check && nocheck) {
		imagex_error(T("Can't specify both --check and --nocheck"));
		goto out_err;
	}

	if (check)
		open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;

	ret = wimlib_open_wim(wimfile, open_flags, &wim, imagex_progress_func);
	if (ret)
		goto out;

	wimlib_get_wim_info(wim, &info);

	image = wimlib_resolve_image(wim, image_num_or_name);
	ret = WIMLIB_ERR_INVALID_IMAGE;
	if (image == WIMLIB_NO_IMAGE && tstrcmp(image_num_or_name, T("0"))) {
		imagex_error(T("The image \"%"TS"\" does not exist in \"%"TS"\""),
			     image_num_or_name, wimfile);
		if (boot) {
			imagex_error(T("If you would like to set the boot "
				       "index to 0, specify image \"0\" with "
				       "the --boot flag."));
		}
		goto out_wimlib_free;
	}

	if (boot && info.image_count == 0) {
		imagex_error(T("--boot is meaningless on a WIM with no images"));
		goto out_wimlib_free;
	}

	if (image == WIMLIB_ALL_IMAGES && info.image_count > 1) {
		if (boot) {
			imagex_error(T("Cannot specify the --boot flag "
				       "without specifying a specific "
				       "image in a multi-image WIM"));
			goto out_wimlib_free;
		}
		if (new_name) {
			imagex_error(T("Cannot specify the NEW_NAME "
				       "without specifying a specific "
				       "image in a multi-image WIM"));
			goto out_wimlib_free;
		}
	}

	/* Operations that print information are separated from operations that
	 * recreate the WIM file. */
	if (!new_name && !boot) {

		/* Read-only operations */

		if (image == WIMLIB_NO_IMAGE) {
			imagex_error(T("\"%"TS"\" is not a valid image in \"%"TS"\""),
				     image_num_or_name, wimfile);
			goto out_wimlib_free;
		}

		if (image == WIMLIB_ALL_IMAGES && short_header)
			print_wim_information(wimfile, &info);

		if (header)
			wimlib_print_header(wim);

		if (lookup_table) {
			if (info.total_parts != 1) {
				tfprintf(stderr, T("Warning: Only showing the lookup table "
						   "for part %d of a %d-part WIM.\n"),
					 info.part_number, info.total_parts);
			}
			print_lookup_table(wim);
		}

		if (xml) {
			ret = wimlib_extract_xml_data(wim, stdout);
			if (ret)
				goto out_wimlib_free;
		}

		if (xml_out_file) {
			FILE *fp;

			fp = tfopen(xml_out_file, T("wb"));
			if (!fp) {
				imagex_error_with_errno(T("Failed to open the "
							  "file \"%"TS"\" for "
							  "writing"),
							xml_out_file);
				ret = -1;
				goto out_wimlib_free;
			}
			ret = wimlib_extract_xml_data(wim, fp);
			if (fclose(fp)) {
				imagex_error(T("Failed to close the file "
					       "\"%"TS"\""),
					     xml_out_file);
				ret = -1;
			}
			if (ret)
				goto out_wimlib_free;
		}

		if (short_header)
			wimlib_print_available_images(wim, image);

		if (metadata) {
			ret = wimlib_print_metadata(wim, image);
			if (ret)
				goto out_wimlib_free;
		}
		ret = 0;
	} else {

		/* Modification operations */

		if (image == WIMLIB_ALL_IMAGES)
			image = 1;

		if (image == WIMLIB_NO_IMAGE && new_name) {
			imagex_error(T("Cannot specify new_name (\"%"TS"\") "
				       "when using image 0"), new_name);
			ret = -1;
			goto out_wimlib_free;
		}

		if (boot) {
			if (image == info.boot_index) {
				imagex_printf(T("Image %d is already marked as "
					  "bootable.\n"), image);
				boot = false;
			} else {
				imagex_printf(T("Marking image %d as bootable.\n"),
					image);
				info.boot_index = image;
				ret = wimlib_set_wim_info(wim, &info,
							  WIMLIB_CHANGE_BOOT_INDEX);
				if (ret)
					goto out_wimlib_free;
			}
		}
		if (new_name) {
			if (!tstrcmp(wimlib_get_image_name(wim, image), new_name))
			{
				imagex_printf(T("Image %d is already named \"%"TS"\".\n"),
					image, new_name);
				new_name = NULL;
			} else {
				imagex_printf(T("Changing the name of image %d to "
					  "\"%"TS"\".\n"), image, new_name);
				ret = wimlib_set_image_name(wim, image, new_name);
				if (ret)
					goto out_wimlib_free;
			}
		}
		if (new_desc) {
			const tchar *old_desc;
			old_desc = wimlib_get_image_description(wim, image);
			if (old_desc && !tstrcmp(old_desc, new_desc)) {
				imagex_printf(T("The description of image %d is already "
					  "\"%"TS"\".\n"), image, new_desc);
				new_desc = NULL;
			} else {
				imagex_printf(T("Changing the description of image %d "
					  "to \"%"TS"\".\n"), image, new_desc);
				ret = wimlib_set_image_descripton(wim, image,
								  new_desc);
				if (ret)
					goto out_wimlib_free;
			}
		}

		/* Only call wimlib_overwrite() if something actually needs to
		 * be changed.  */
		if (boot || new_name || new_desc ||
		    (check && !info.has_integrity_table) ||
		    (nocheck && info.has_integrity_table))
		{
			int write_flags = 0;

			if (check)
				write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			if (nocheck)
				write_flags |= WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY;
			ret = wimlib_overwrite(wim, write_flags, 1,
					       imagex_progress_func);
		} else {
			imagex_printf(T("The file \"%"TS"\" was not modified "
					"because nothing needed to be done.\n"),
				      wimfile);
			ret = 0;
		}
	}
out_wimlib_free:
	wimlib_free(wim);
out:
	return ret;

out_usage:
	usage(CMD_INFO, stderr);
out_err:
	ret = -1;
	goto out;
}

/* Join split WIMs into one part WIM */
static int
imagex_join(int argc, tchar **argv, int cmd)
{
	int c;
	int swm_open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int wim_write_flags = 0;
	const tchar *output_path;
	int ret;

	for_opt(c, join_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			swm_open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			wim_write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		imagex_error(T("Must specify one or more split WIM (.swm) "
			       "parts to join"));
		goto out_usage;
	}
	output_path = argv[0];
	ret = wimlib_join((const tchar * const *)++argv,
			  --argc,
			  output_path,
			  swm_open_flags,
			  wim_write_flags,
			  imagex_progress_func);
out:
	return ret;

out_usage:
	usage(CMD_JOIN, stderr);
	ret = -1;
	goto out;
}

#if WIM_MOUNTING_SUPPORTED

/* Mounts a WIM image.  */
static int
imagex_mount_rw_or_ro(int argc, tchar **argv, int cmd)
{
	int c;
	int mount_flags = 0;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	const tchar *staging_dir = NULL;
	const tchar *wimfile;
	const tchar *dir;
	WIMStruct *wim;
	struct wimlib_wim_info info;
	int image;
	int ret;

	REFGLOB_SET(refglobs);

	if (cmd == CMD_MOUNTRW) {
		mount_flags |= WIMLIB_MOUNT_FLAG_READWRITE;
		open_flags |= WIMLIB_OPEN_FLAG_WRITE_ACCESS;
	}

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
				goto out_usage;
			}
			break;
		case IMAGEX_REF_OPTION:
			ret = refglob_set_append(&refglobs, optarg);
			if (ret)
				goto out_free_refglobs;
			break;
		case IMAGEX_STAGING_DIR_OPTION:
			staging_dir = optarg;
			break;
		case IMAGEX_UNIX_DATA_OPTION:
			mount_flags |= WIMLIB_MOUNT_FLAG_UNIX_DATA;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 && argc != 3)
		goto out_usage;

	wimfile = argv[0];

	ret = wimlib_open_wim(wimfile, open_flags, &wim, imagex_progress_func);
	if (ret)
		goto out_free_refglobs;

	wimlib_get_wim_info(wim, &info);

	if (argc >= 3) {
		/* Image explicitly specified.  */
		image = wimlib_resolve_image(wim, argv[1]);
		dir = argv[2];
		ret = verify_image_exists_and_is_single(image, argv[1], wimfile);
		if (ret)
			goto out_free_wim;
	} else {
		/* No image specified; default to image 1, but only if the WIM
		 * contains exactly one image.  */

		if (info.image_count != 1) {
			imagex_error(T("\"%"TS"\" contains %d images; Please "
				       "select one."), wimfile, info.image_count);
			wimlib_free(wim);
			goto out_usage;
		}
		image = 1;
		dir = argv[1];
	}

	if (refglobs.num_globs) {
		ret = wim_reference_globs(wim, &refglobs, open_flags);
		if (ret)
			goto out_free_wim;
	}

	ret = wimlib_mount_image(wim, image, dir, mount_flags, staging_dir);
	if (ret) {
		imagex_error(T("Failed to mount image %d from \"%"TS"\" "
			       "on \"%"TS"\""),
			     image, wimfile, dir);
	}
out_free_wim:
	wimlib_free(wim);
out_free_refglobs:
	refglob_set_destroy(&refglobs);
	return ret;

out_usage:
	usage(cmd, stderr);
	ret = -1;
	goto out_free_refglobs;
}
#endif /* WIM_MOUNTING_SUPPORTED */

/* Rebuild a WIM file */
static int
imagex_optimize(int argc, tchar **argv, int cmd)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_WRITE_ACCESS;
	int write_flags = WIMLIB_WRITE_FLAG_REBUILD;
	int ret;
	WIMStruct *wim;
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
		case IMAGEX_NOCHECK_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY;
			break;
		case IMAGEX_RECOMPRESS_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_RECOMPRESS;
			break;
		case IMAGEX_THREADS_OPTION:
			num_threads = parse_num_threads(optarg);
			if (num_threads == UINT_MAX)
				goto out_err;
			break;
		case IMAGEX_PIPABLE_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
			break;
		case IMAGEX_NOT_PIPABLE_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NOT_PIPABLE;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		goto out_usage;

	wimfile = argv[0];

	ret = wimlib_open_wim(wimfile, open_flags, &wim, imagex_progress_func);
	if (ret)
		goto out;

	old_size = file_get_size(wimfile);
	tprintf(T("\"%"TS"\" original size: "), wimfile);
	if (old_size == -1)
		tputs(T("Unknown"));
	else
		tprintf(T("%"PRIu64" KiB\n"), old_size >> 10);

	ret = wimlib_overwrite(wim, write_flags, num_threads,
			       imagex_progress_func);
	if (ret) {
		imagex_error(T("Optimization of \"%"TS"\" failed."), wimfile);
		goto out_wimlib_free;
	}

	new_size = file_get_size(wimfile);
	tprintf(T("\"%"TS"\" optimized size: "), wimfile);
	if (new_size == -1)
		tputs(T("Unknown"));
	else
		tprintf(T("%"PRIu64" KiB\n"), new_size >> 10);

	tfputs(T("Space saved: "), stdout);
	if (new_size != -1 && old_size != -1) {
		tprintf(T("%lld KiB\n"),
		       ((long long)old_size - (long long)new_size) >> 10);
	} else {
		tputs(T("Unknown"));
	}
	ret = 0;
out_wimlib_free:
	wimlib_free(wim);
out:
	return ret;

out_usage:
	usage(CMD_OPTIMIZE, stderr);
out_err:
	ret = -1;
	goto out;
}

/* Split a WIM into a spanned set */
static int
imagex_split(int argc, tchar **argv, int cmd)
{
	int c;
	int open_flags = 0;
	int write_flags = 0;
	unsigned long part_size;
	tchar *tmp;
	int ret;
	WIMStruct *wim;

	for_opt(c, split_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 3)
		goto out_usage;

	part_size = tstrtod(argv[2], &tmp) * (1 << 20);
	if (tmp == argv[2] || *tmp) {
		imagex_error(T("Invalid part size \"%"TS"\""), argv[2]);
		imagex_error(T("The part size must be an integer or "
			       "floating-point number of megabytes."));
		goto out_err;
	}
	ret = wimlib_open_wim(argv[0], open_flags, &wim, imagex_progress_func);
	if (ret)
		goto out;

	ret = wimlib_split(wim, argv[1], part_size, write_flags, imagex_progress_func);
	wimlib_free(wim);
out:
	return ret;

out_usage:
	usage(CMD_SPLIT, stderr);
out_err:
	ret = -1;
	goto out;
}

#if WIM_MOUNTING_SUPPORTED
/* Unmounts a mounted WIM image. */
static int
imagex_unmount(int argc, tchar **argv, int cmd)
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
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		goto out_usage;

	ret = wimlib_unmount_image(argv[0], unmount_flags,
				   imagex_progress_func);
	if (ret)
		imagex_error(T("Failed to unmount \"%"TS"\""), argv[0]);
out:
	return ret;

out_usage:
	usage(CMD_UNMOUNT, stderr);
	ret = -1;
	goto out;
}
#endif /* WIM_MOUNTING_SUPPORTED */

/*
 * Add, delete, or rename files in a WIM image.
 */
static int
imagex_update(int argc, tchar **argv, int cmd)
{
	const tchar *wimfile;
	int image;
	WIMStruct *wim;
	int ret;
	int open_flags = WIMLIB_OPEN_FLAG_WRITE_ACCESS;
	int write_flags = 0;
	int update_flags = WIMLIB_UPDATE_FLAG_SEND_PROGRESS;
	int default_add_flags = WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE;
	int default_delete_flags = 0;
	unsigned num_threads = 0;
	int c;
	tchar *cmd_file_contents;
	size_t cmd_file_nchars;
	struct wimlib_update_command *cmds;
	size_t num_cmds;
	tchar *command_str = NULL;

	const tchar *config_file = NULL;
	tchar *config_str;
	struct wimlib_capture_config *config;

	for_opt(c, update_options) {
		switch (c) {
		/* Generic or write options */
		case IMAGEX_THREADS_OPTION:
			num_threads = parse_num_threads(optarg);
			if (num_threads == UINT_MAX)
				goto out_err;
			break;
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_REBUILD_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_REBUILD;
			break;
		case IMAGEX_COMMAND_OPTION:
			if (command_str) {
				imagex_error(T("--command may only be specified "
					       "one time.  Please provide\n"
					       "       the update commands "
					       "on standard input instead."));
				goto out_err;
			}
			command_str = tstrdup(optarg);
			if (!command_str) {
				imagex_error(T("Out of memory!"));
				goto out_err;
			}
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
			default_add_flags &= ~WIMLIB_ADD_FLAG_WINCONFIG;
			config_file = optarg;
			break;

		/* Default add options */
		case IMAGEX_VERBOSE_OPTION:
			default_add_flags |= WIMLIB_ADD_FLAG_VERBOSE;
			break;
		case IMAGEX_DEREFERENCE_OPTION:
			default_add_flags |= WIMLIB_ADD_FLAG_DEREFERENCE;
			break;
		case IMAGEX_UNIX_DATA_OPTION:
			default_add_flags |= WIMLIB_ADD_FLAG_UNIX_DATA;
			break;
		case IMAGEX_NO_ACLS_OPTION:
			default_add_flags |= WIMLIB_ADD_FLAG_NO_ACLS;
			break;
		case IMAGEX_STRICT_ACLS_OPTION:
			default_add_flags |= WIMLIB_ADD_FLAG_STRICT_ACLS;
			break;
		default:
			goto out_usage;
		}
	}
	argv += optind;
	argc -= optind;

	if (argc != 1 && argc != 2)
		goto out_usage;
	wimfile = argv[0];

	ret = wimlib_open_wim(wimfile, open_flags, &wim, imagex_progress_func);
	if (ret)
		goto out_free_command_str;

	if (argc >= 2) {
		/* Image explicitly specified.  */
		image = wimlib_resolve_image(wim, argv[1]);
		ret = verify_image_exists_and_is_single(image, argv[1],
							wimfile);
		if (ret)
			goto out_wimlib_free;
	} else {
		/* No image specified; default to image 1, but only if the WIM
		 * contains exactly one image.  */
		struct wimlib_wim_info info;

		wimlib_get_wim_info(wim, &info);
		if (info.image_count != 1) {
			imagex_error(T("\"%"TS"\" contains %d images; Please select one."),
				     wimfile, info.image_count);
			wimlib_free(wim);
			goto out_usage;
		}
		image = 1;
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
		config = NULL;
		default_add_flags |= WIMLIB_ADD_FLAG_WINCONFIG;
	}

	/* Read update commands from standard input, or the command string if
	 * specified.  */
	if (command_str) {
		cmd_file_contents = NULL;
		cmds = parse_update_command_file(&command_str, tstrlen(command_str),
						 &num_cmds);
	} else {
		if (isatty(STDIN_FILENO)) {
			tputs(T("Reading update commands from standard input..."));
			recommend_man_page(CMD_UPDATE, stdout);
		}
		cmd_file_contents = stdin_get_text_contents(&cmd_file_nchars);
		if (!cmd_file_contents) {
			ret = -1;
			goto out_free_config;
		}

		/* Parse the update commands */
		cmds = parse_update_command_file(&cmd_file_contents, cmd_file_nchars,
						 &num_cmds);
	}
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
	if (config) {
		free(config->exclusion_pats.pats);
		free(config->exclusion_exception_pats.pats);
		free(config_str);
	}
out_wimlib_free:
	wimlib_free(wim);
out_free_command_str:
	free(command_str);
	return ret;

out_usage:
	usage(CMD_UPDATE, stderr);
out_err:
	ret = -1;
	goto out_free_command_str;
}



struct imagex_command {
	const tchar *name;
	int (*func)(int argc, tchar **argv, int cmd);
};

static const struct imagex_command imagex_commands[] = {
	[CMD_APPEND]   = {T("append"),   imagex_capture_or_append},
	[CMD_APPLY]    = {T("apply"),    imagex_apply},
	[CMD_CAPTURE]  = {T("capture"),  imagex_capture_or_append},
	[CMD_DELETE]   = {T("delete"),   imagex_delete},
	[CMD_DIR ]     = {T("dir"),      imagex_dir},
	[CMD_EXPORT]   = {T("export"),   imagex_export},
	[CMD_EXTRACT]  = {T("extract"),  imagex_extract},
	[CMD_INFO]     = {T("info"),     imagex_info},
	[CMD_JOIN]     = {T("join"),     imagex_join},
#if WIM_MOUNTING_SUPPORTED
	[CMD_MOUNT]    = {T("mount"),    imagex_mount_rw_or_ro},
	[CMD_MOUNTRW]  = {T("mountrw"),  imagex_mount_rw_or_ro},
#endif
	[CMD_OPTIMIZE] = {T("optimize"), imagex_optimize},
	[CMD_SPLIT]    = {T("split"),    imagex_split},
#if WIM_MOUNTING_SUPPORTED
	[CMD_UNMOUNT]  = {T("unmount"),  imagex_unmount},
#endif
	[CMD_UPDATE]   = {T("update"),   imagex_update},
};

static const tchar *usage_strings[] = {
[CMD_APPEND] =
T(
"    %"TS" (DIRECTORY | NTFS_VOLUME) WIMFILE\n"
"                    [IMAGE_NAME [IMAGE_DESCRIPTION]] [--boot] [--check]\n"
"                    [--nocheck] [--flags EDITION_ID] [--verbose]\n"
"                    [--dereference] [--config=FILE] [--threads=NUM_THREADS]\n"
"                    [--rebuild] [--unix-data] [--source-list] [--no-acls]\n"
"                    [--strict-acls] [--rpfix] [--norpfix] [--pipable]\n"
"                    [--not-pipable] [--as-update-of=[WIMFILE:]IMAGE]\n"
),
[CMD_APPLY] =
T(
"    %"TS" WIMFILE [(IMAGE_NUM | IMAGE_NAME | all)]\n"
"                    (DIRECTORY | NTFS_VOLUME) [--check] [--hardlink]\n"
"                    [--symlink] [--verbose] [--ref=\"GLOB\"] [--unix-data]\n"
"                    [--no-acls] [--strict-acls] [--rpfix] [--norpfix]\n"
"                    [--include-invalid-names]\n"
),
[CMD_CAPTURE] =
T(
"    %"TS" (DIRECTORY | NTFS_VOLUME) WIMFILE\n"
"		     [IMAGE_NAME [IMAGE_DESCRIPTION]] [--boot] [--check]\n"
"                    [--nocheck] [--compress=TYPE] [--flags EDITION_ID]\n"
"                    [--verbose] [--dereference] [--config=FILE]\n"
"                    [--threads=NUM_THREADS] [--unix-data] [--source-list]\n"
"                    [--no-acls] [--strict-acls] [--norpfix] [--pipable]\n"
"                    [--as-update-of=[WIMFILE:]IMAGE] [--as-delta-from=WIMFILE]\n"
),
[CMD_DELETE] =
T(
"    %"TS" WIMFILE (IMAGE_NUM | IMAGE_NAME | all) [--check]\n"
"                    [--soft]\n"
),
[CMD_DIR] =
T(
"    %"TS" WIMFILE (IMAGE_NUM | IMAGE_NAME | all) [--path=PATH]\n"
),
[CMD_EXPORT] =
T(
"    %"TS" SRC_WIMFILE (SRC_IMAGE_NUM | SRC_IMAGE_NAME | all ) \n"
"                    DEST_WIMFILE [DEST_IMAGE_NAME [DEST_IMAGE_DESCRIPTION]]\n"
"                    [--boot] [--check] [--nocheck] [--compress=TYPE]\n"
"                    [--ref=\"GLOB\"] [--threads=NUM_THREADS] [--rebuild]\n"
"                    [--pipable] [--not-pipable]\n"
),
[CMD_EXTRACT] =
T(
"    %"TS" WIMFILE (IMAGE_NUM | IMAGE_NAME) [PATH...]\n"
"                    [--check] [--ref=\"GLOB\"] [--verbose] [--unix-data]\n"
"                    [--no-acls] [--strict-acls] [--to-stdout]\n"
"                    [--dest-dir=CMD_DIR] [--include-invalid-names]\n"
),
[CMD_INFO] =
T(
"    %"TS" WIMFILE [(IMAGE_NUM | IMAGE_NAME) [NEW_NAME\n"
"                    [NEW_DESC]]] [--boot] [--check] [--nocheck] [--header]\n"
"                    [--lookup-table] [--xml] [--extract-xml FILE]\n"
"                    [--metadata]\n"
),
[CMD_JOIN] =
T(
"    %"TS" OUT_WIMFILE SPLIT_WIM_PART... [--check]\n"
),
#if WIM_MOUNTING_SUPPORTED
[CMD_MOUNT] =
T(
"    %"TS" WIMFILE [(IMAGE_NUM | IMAGE_NAME)] DIRECTORY\n"
"                    [--check] [--debug] [--streams-interface=INTERFACE]\n"
"                    [--ref=\"GLOB\"] [--unix-data] [--allow-other]\n"
),
[CMD_MOUNTRW] =
T(
"    %"TS" WIMFILE [(IMAGE_NUM | IMAGE_NAME)] DIRECTORY\n"
"                    [--check] [--debug] [--streams-interface=INTERFACE]\n"
"                    [--staging-dir=CMD_DIR] [--unix-data] [--allow-other]\n"
),
#endif
[CMD_OPTIMIZE] =
T(
"    %"TS" WIMFILE [--check] [--nocheck] [--recompress]\n"
"                    [--threads=NUM_THREADS] [--pipable] [--not-pipable]\n"
),
[CMD_SPLIT] =
T(
"    %"TS" WIMFILE SPLIT_WIM_PART_1 PART_SIZE_MB [--check]\n"
),
#if WIM_MOUNTING_SUPPORTED
[CMD_UNMOUNT] =
T(
"    %"TS" DIRECTORY [--commit] [--check] [--rebuild] [--lazy]\n"
),
#endif
[CMD_UPDATE] =
T(
"    %"TS" WIMFILE [IMAGE_NUM | IMAGE_NAME] [--check] [--rebuild]\n"
"                    [--threads=NUM_THREADS] [DEFAULT_ADD_OPTIONS]\n"
"                    [DEFAULT_DELETE_OPTIONS] [--command=STRING] [< CMDFILE]\n"
),
};

static const tchar *invocation_name;
static int invocation_cmd = CMD_NONE;

static const tchar *get_cmd_string(int cmd, bool nospace)
{
	static tchar buf[50];
	if (cmd == CMD_NONE) {
		tsprintf(buf, T("%"TS), T(IMAGEX_PROGNAME));
	} else if (invocation_cmd != CMD_NONE) {
		tsprintf(buf, T("wim%"TS), imagex_commands[cmd].name);
	} else {
		const tchar *format;

		if (nospace)
			format = T("%"TS"-%"TS"");
		else
			format = T("%"TS" %"TS"");
		tsprintf(buf, format, invocation_name, imagex_commands[cmd].name);
	}
	return buf;
}

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
help_or_version(int argc, tchar **argv, int cmd)
{
	int i;
	const tchar *p;

	for (i = 1; i < argc; i++) {
		p = argv[i];
		if (p[0] == T('-') && p[1] == T('-')) {
			p += 2;
			if (!tstrcmp(p, T("help"))) {
				if (cmd == CMD_NONE)
					usage_all(stdout);
				else
					usage(cmd, stdout);
				exit(0);
			} else if (!tstrcmp(p, T("version"))) {
				version();
				exit(0);
			}
		}
	}
}

static void
print_usage_string(int cmd, FILE *fp)
{
	tfprintf(fp, usage_strings[cmd], get_cmd_string(cmd, false));
}

static void
recommend_man_page(int cmd, FILE *fp)
{
	const tchar *format_str;
#ifdef __WIN32__
	format_str = T("See %"TS".pdf in the doc directory for more details.\n");
#else
	format_str = T("Try `man %"TS"' for more details.\n");
#endif
	tfprintf(fp, format_str, get_cmd_string(cmd, true));
}

static void
usage(int cmd, FILE *fp)
{
	tfprintf(fp, T("Usage:\n"));
	print_usage_string(cmd, fp);
	tfprintf(fp, T("\n"));
	recommend_man_page(cmd, fp);
}

static void
usage_all(FILE *fp)
{
	tfprintf(fp, T("Usage:\n"));
	for (int cmd = 0; cmd < CMD_MAX; cmd++) {
		print_usage_string(cmd, fp);
		tfprintf(fp, T("\n"));
	}
	static const tchar *extra =
	T(
"    %"TS" --help\n"
"    %"TS" --version\n"
"\n"
"    The compression TYPE may be \"maximum\", \"fast\", or \"none\".\n"
"\n"
	);
	tfprintf(fp, extra, invocation_name, invocation_name);
	recommend_man_page(CMD_NONE, fp);
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
	int ret;
	int init_flags = 0;
	int cmd;

	imagex_info_file = stdout;
	invocation_name = tbasename(argv[0]);

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
			fprintf(stderr,
"WARNING: Running %"TS" in a UTF-8 locale is recommended!\n"
"         Maybe try: `export LANG=en_US.UTF-8'?\n"
"         Alternatively, set the environmental variable WIMLIB_IMAGEX_USE_UTF8\n"
"         to any value to force wimlib to use UTF-8.\n",
			invocation_name);

		}
	}
#endif /* !__WIN32__ */

	/* Allow being invoked as wimCOMMAND (e.g. wimapply).  */
	cmd = CMD_NONE;
	if (!tstrncmp(invocation_name, T("wim"), 3) &&
	    tstrcmp(invocation_name, T(IMAGEX_PROGNAME))) {
		for (int i = 0; i < CMD_MAX; i++) {
			if (!tstrcmp(invocation_name + 3,
				     imagex_commands[i].name))
			{
				invocation_cmd = i;
				cmd = i;
				break;
			}
		}
	}

	/* Unless already known from the invocation name, determine which
	 * command was specified.  */
	if (cmd == CMD_NONE) {
		if (argc < 2) {
			imagex_error(T("No command specified!\n"));
			usage_all(stderr);
			exit(2);
		}
		for (int i = 0; i < CMD_MAX; i++) {
			if (!tstrcmp(argv[1], imagex_commands[i].name)) {
				cmd = i;
				break;
			}
		}
		if (cmd != CMD_NONE) {
			argc--;
			argv++;
		}
	}

	/* Handle --help and --version.  --help can be either for the program as
	 * a whole (cmd == CMD_NONE) or just for a specific command (cmd !=
	 * CMD_NONE).  Note: help_or_version() will not return if a --help or
	 * --version argument was found.  */
	help_or_version(argc, argv, cmd);

	/* Bail if a valid command was not specified.  */
	if (cmd == CMD_NONE) {
		imagex_error(T("Unrecognized command: `%"TS"'\n"), argv[1]);
		usage_all(stderr);
		exit(2);
	}

	/* Enable warning and error messages in wimlib be more user-friendly.
	 * */
	wimlib_set_print_errors(true);

	/* Initialize wimlib.  */
	ret = wimlib_global_init(init_flags);
	if (ret)
		goto out_check_status;

	/* Call the command handler function.  */
	ret = imagex_commands[cmd].func(argc, argv, cmd);

	/* Check for error writing to standard output, especially since for some
	 * commands, writing to standard output is part of the program's actual
	 * behavior and not just for informational purposes.  */
	if (ferror(stdout) || fclose(stdout)) {
		imagex_error_with_errno(T("error writing to standard output"));
		if (ret == 0)
			ret = -1;
	}
out_check_status:
	/* Exit status (ret):  -1 indicates an error found by 'wimlib-imagex'
	 * itself (not by wimlib).  0 indicates success.  > 0 indicates a wimlib
	 * error code from which an error message can be printed.  */
	if (ret > 0) {
		imagex_error(T("Exiting with error code %d:\n"
			       "       %"TS"."), ret,
			     wimlib_get_error_string(ret));
		if (ret == WIMLIB_ERR_NTFS_3G && errno != 0)
			imagex_error_with_errno(T("errno"));
	}
	/* Make wimlib free any resources it's holding (although this is not
	 * strictly necessary because the process is ending anyway).  */
	wimlib_global_cleanup();
	return ret;
}
