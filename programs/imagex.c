/*
 * imagex.c
 *
 * Use wimlib to create, modify, extract, mount, unmount, or display information
 * about a WIM file
 */

/*
 * Copyright 2012-2023 Eric Biggers
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h" /* Need for PACKAGE_VERSION, etc. */
#endif

#include "wimlib.h"
#include "wimlib_tchar.h"

#include <ctype.h>
#include <errno.h>

#include <inttypes.h>
#ifdef _MSC_VER
#pragma warning(disable:4996)
#include"msvc/unistd.h"
#define PACKAGE_VERSION ""
#define PACKAGE_BUGREPORT ""
#define alloca		  _alloca
#define gmtime_r(x, y)	  gmtime_s(y, x)
#define S_IFMT		  00170000
#define S_IFSOCK	  0140000
#define S_IFLNK		  0120000
#define S_IFREG		  0100000
#define S_IFBLK		  0060000
#define S_IFDIR		  0040000
#define S_IFCHR		  0020000
#define S_IFIFO		  0010000
#define S_ISUID		  0004000
#define S_ISGID		  0002000
#define S_ISVTX		  0001000

#define S_ISLNK(m)  (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#if defined _M_AMD64
#ifdef _DEBUG
#pragma comment(lib, "../x64/Debug/libwim.lib")
#else
#pragma comment(lib, "../x64/Release/libwim.lib")
#endif
#elif defined _M_IX86
#ifdef _DEBUG
#pragma comment(lib, "../Debug/libwim.lib")
#else
#pragma comment(lib, "../Release/libwim.lib")
#endif
#elif defined _M_ARM
#ifdef _DEBUG
#pragma comment(lib, "../ARM/Debug/libwim.lib")
#else
#pragma comment(lib, "../ARM/Release/libwim.lib")
#endif
#elif defined _M_ARM64
#ifdef _DEBUG
#pragma comment(lib, "../ARM64/Debug/libwim.lib")
#else
#pragma comment(lib, "../ARM64/Release/libwim.lib")
#endif
#endif
#else
#include <libgen.h>
#include <unistd.h>
#endif
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <locale.h>

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif

#define WIMLIB_COMPRESSION_TYPE_INVALID (-1)

#ifdef _WIN32
#  include "imagex-win32.h"
#  define print_security_descriptor     win32_print_security_descriptor
#else /* _WIN32 */
#  include <getopt.h>
#  include <langinfo.h>
#  define print_security_descriptor	default_print_security_descriptor
static inline void set_fd_to_binary_mode(int fd)
{
}
/* NetBSD is missing getopt_long_only() but has getopt_long() */
#ifndef HAVE_GETOPT_LONG_ONLY
#  define getopt_long_only getopt_long
#endif
#endif /* !_WIN32 */

/* Don't confuse the user by presenting the mounting commands on Windows when
 * they will never work.  However on UNIX-like systems we always present them,
 * even if WITH_FUSE is not defined at this point, as to not tie the build of
 * wimlib-imagex to a specific build of wimlib.  */
#ifdef _WIN32
#  define WIM_MOUNTING_SUPPORTED 0
#else
#  define WIM_MOUNTING_SUPPORTED 1
#endif

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

static inline bool
is_any_path_separator(tchar c)
{
	return c == T('/') || c == T('\\');
}

/* Like basename(), but handles both forward and backwards slashes.  */
static tchar *
tbasename(tchar *path)
{
	tchar *p = tstrchr(path, T('\0'));

	for (;;) {
		if (p == path)
			return path;
		if (!is_any_path_separator(*--p))
			break;
		*p = T('\0');
	}

	for (;;) {
		if (p == path)
			return path;
		if (is_any_path_separator(*--p))
			return ++p;
	}
}

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
	CMD_VERIFY,
	CMD_MAX,
};

static void usage(int cmd, FILE *fp);
static void usage_all(FILE *fp);
static void recommend_man_page(int cmd, FILE *fp);
static const tchar *get_cmd_string(int cmd, bool only_short_form);

static FILE *imagex_info_file;

#define imagex_printf(format, ...)	\
	if (imagex_info_file)		\
		tfprintf(imagex_info_file, format, ##__VA_ARGS__)

static void imagex_suppress_output(void)
{
	imagex_info_file = NULL;
}

static void imagex_output_to_stderr(void)
{
	if (imagex_info_file)
		imagex_info_file = stderr;
}

static void imagex_flush_output(void)
{
	if (imagex_info_file)
		fflush(imagex_info_file);
}

enum {
	IMAGEX_ALLOW_OTHER_OPTION,
	IMAGEX_BLOBS_OPTION,
	IMAGEX_BOOT_OPTION,
	IMAGEX_CHECK_OPTION,
	IMAGEX_CHUNK_SIZE_OPTION,
	IMAGEX_COMMAND_OPTION,
	IMAGEX_COMMIT_OPTION,
	IMAGEX_COMPACT_OPTION,
	IMAGEX_COMPRESS_OPTION,
	IMAGEX_CONFIG_OPTION,
	IMAGEX_CREATE_OPTION,
	IMAGEX_DEBUG_OPTION,
	IMAGEX_DELTA_FROM_OPTION,
	IMAGEX_DEREFERENCE_OPTION,
	IMAGEX_DEST_DIR_OPTION,
	IMAGEX_DETAILED_OPTION,
	IMAGEX_EXTRACT_XML_OPTION,
	IMAGEX_FLAGS_OPTION,
	IMAGEX_FORCE_OPTION,
	IMAGEX_HEADER_OPTION,
	IMAGEX_IMAGE_PROPERTY_OPTION,
	IMAGEX_INCLUDE_INTEGRITY_OPTION,
	IMAGEX_INCLUDE_INVALID_NAMES_OPTION,
	IMAGEX_LAZY_OPTION,
	IMAGEX_METADATA_OPTION,
	IMAGEX_NEW_IMAGE_OPTION,
	IMAGEX_NOCHECK_OPTION,
	IMAGEX_NORPFIX_OPTION,
	IMAGEX_NOT_PIPABLE_OPTION,
	IMAGEX_NO_ACLS_OPTION,
	IMAGEX_NO_ATTRIBUTES_OPTION,
	IMAGEX_NO_GLOBS_OPTION,
	IMAGEX_NO_REPLACE_OPTION,
	IMAGEX_NO_SOLID_SORT_OPTION,
	IMAGEX_NULLGLOB_OPTION,
	IMAGEX_ONE_FILE_ONLY_OPTION,
	IMAGEX_PATH_OPTION,
	IMAGEX_PIPABLE_OPTION,
	IMAGEX_PRESERVE_DIR_STRUCTURE_OPTION,
	IMAGEX_REBUILD_OPTION,
	IMAGEX_RECOMPRESS_OPTION,
	IMAGEX_RECOVER_DATA_OPTION,
	IMAGEX_RECURSIVE_OPTION,
	IMAGEX_REF_OPTION,
	IMAGEX_RPFIX_OPTION,
	IMAGEX_SNAPSHOT_OPTION,
	IMAGEX_SOFT_OPTION,
	IMAGEX_SOLID_CHUNK_SIZE_OPTION,
	IMAGEX_SOLID_COMPRESS_OPTION,
	IMAGEX_SOLID_OPTION,
	IMAGEX_SOURCE_LIST_OPTION,
	IMAGEX_STAGING_DIR_OPTION,
	IMAGEX_STREAMS_INTERFACE_OPTION,
	IMAGEX_STRICT_ACLS_OPTION,
	IMAGEX_THREADS_OPTION,
	IMAGEX_TO_STDOUT_OPTION,
	IMAGEX_UNIX_DATA_OPTION,
	IMAGEX_UNSAFE_COMPACT_OPTION,
	IMAGEX_UPDATE_OF_OPTION,
	IMAGEX_VERBOSE_OPTION,
	IMAGEX_WIMBOOT_CONFIG_OPTION,
	IMAGEX_WIMBOOT_OPTION,
	IMAGEX_XML_OPTION,
};

static const struct option apply_options[] = {
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("verbose"),     no_argument,       NULL, IMAGEX_VERBOSE_OPTION},
	{T("ref"),         required_argument, NULL, IMAGEX_REF_OPTION},
	{T("unix-data"),   no_argument,       NULL, IMAGEX_UNIX_DATA_OPTION},
	{T("noacls"),      no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("no-acls"),     no_argument,       NULL, IMAGEX_NO_ACLS_OPTION},
	{T("strict-acls"), no_argument,       NULL, IMAGEX_STRICT_ACLS_OPTION},
	{T("no-attributes"), no_argument,     NULL, IMAGEX_NO_ATTRIBUTES_OPTION},
	{T("rpfix"),       no_argument,       NULL, IMAGEX_RPFIX_OPTION},
	{T("norpfix"),     no_argument,       NULL, IMAGEX_NORPFIX_OPTION},
	{T("include-invalid-names"), no_argument,       NULL, IMAGEX_INCLUDE_INVALID_NAMES_OPTION},
	{T("wimboot"),     no_argument,       NULL, IMAGEX_WIMBOOT_OPTION},
	{T("compact"),     required_argument, NULL, IMAGEX_COMPACT_OPTION},
	{T("recover-data"), no_argument,      NULL, IMAGEX_RECOVER_DATA_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option capture_or_append_options[] = {
	{T("boot"),        no_argument,       NULL, IMAGEX_BOOT_OPTION},
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("no-check"),    no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("nocheck"),     no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("include-integrity"), no_argument, NULL, IMAGEX_INCLUDE_INTEGRITY_OPTION},
	{T("compress"),    required_argument, NULL, IMAGEX_COMPRESS_OPTION},
	{T("chunk-size"),  required_argument, NULL, IMAGEX_CHUNK_SIZE_OPTION},
	{T("solid"),       no_argument,      NULL, IMAGEX_SOLID_OPTION},
	{T("solid-compress"),required_argument, NULL, IMAGEX_SOLID_COMPRESS_OPTION},
	{T("solid-chunk-size"),required_argument, NULL, IMAGEX_SOLID_CHUNK_SIZE_OPTION},
	{T("no-solid-sort"), no_argument,     NULL, IMAGEX_NO_SOLID_SORT_OPTION},
	{T("config"),      required_argument, NULL, IMAGEX_CONFIG_OPTION},
	{T("dereference"), no_argument,       NULL, IMAGEX_DEREFERENCE_OPTION},
	{T("flags"),       required_argument, NULL, IMAGEX_FLAGS_OPTION},
	{T("image-property"), required_argument, NULL, IMAGEX_IMAGE_PROPERTY_OPTION},
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
	{T("update-of"),   required_argument, NULL, IMAGEX_UPDATE_OF_OPTION},
	{T("delta-from"),  required_argument, NULL, IMAGEX_DELTA_FROM_OPTION},
	{T("wimboot"),     no_argument,       NULL, IMAGEX_WIMBOOT_OPTION},
	{T("unsafe-compact"), no_argument,    NULL, IMAGEX_UNSAFE_COMPACT_OPTION},
	{T("snapshot"),    no_argument,       NULL, IMAGEX_SNAPSHOT_OPTION},
	{T("create"),      no_argument,       NULL, IMAGEX_CREATE_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option delete_options[] = {
	{T("check"), no_argument, NULL, IMAGEX_CHECK_OPTION},
	{T("include-integrity"), no_argument, NULL, IMAGEX_INCLUDE_INTEGRITY_OPTION},
	{T("soft"),  no_argument, NULL, IMAGEX_SOFT_OPTION},
	{T("unsafe-compact"), no_argument, NULL, IMAGEX_UNSAFE_COMPACT_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option dir_options[] = {
	{T("path"),     required_argument, NULL, IMAGEX_PATH_OPTION},
	{T("detailed"), no_argument,       NULL, IMAGEX_DETAILED_OPTION},
	{T("one-file-only"), no_argument,  NULL, IMAGEX_ONE_FILE_ONLY_OPTION},
	{T("ref"),      required_argument, NULL, IMAGEX_REF_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option export_options[] = {
	{T("boot"),        no_argument,       NULL, IMAGEX_BOOT_OPTION},
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("nocheck"),     no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("no-check"),    no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("include-integrity"), no_argument, NULL, IMAGEX_INCLUDE_INTEGRITY_OPTION},
	{T("compress"),    required_argument, NULL, IMAGEX_COMPRESS_OPTION},
	{T("recompress"),  no_argument,       NULL, IMAGEX_RECOMPRESS_OPTION},
	{T("chunk-size"),  required_argument, NULL, IMAGEX_CHUNK_SIZE_OPTION},
	{T("solid"),       no_argument,       NULL, IMAGEX_SOLID_OPTION},
	{T("solid-compress"),required_argument, NULL, IMAGEX_SOLID_COMPRESS_OPTION},
	{T("solid-chunk-size"),required_argument, NULL, IMAGEX_SOLID_CHUNK_SIZE_OPTION},
	{T("no-solid-sort"), no_argument,     NULL, IMAGEX_NO_SOLID_SORT_OPTION},
	{T("ref"),         required_argument, NULL, IMAGEX_REF_OPTION},
	{T("threads"),     required_argument, NULL, IMAGEX_THREADS_OPTION},
	{T("rebuild"),     no_argument,       NULL, IMAGEX_REBUILD_OPTION},
	{T("pipable"),     no_argument,       NULL, IMAGEX_PIPABLE_OPTION},
	{T("not-pipable"), no_argument,       NULL, IMAGEX_NOT_PIPABLE_OPTION},
	{T("wimboot"),     no_argument,       NULL, IMAGEX_WIMBOOT_OPTION},
	{T("unsafe-compact"), no_argument,    NULL, IMAGEX_UNSAFE_COMPACT_OPTION},
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
	{T("no-attributes"), no_argument,     NULL, IMAGEX_NO_ATTRIBUTES_OPTION},
	{T("dest-dir"),    required_argument, NULL, IMAGEX_DEST_DIR_OPTION},
	{T("to-stdout"),   no_argument,       NULL, IMAGEX_TO_STDOUT_OPTION},
	{T("include-invalid-names"), no_argument, NULL, IMAGEX_INCLUDE_INVALID_NAMES_OPTION},
	{T("no-wildcards"), no_argument,      NULL, IMAGEX_NO_GLOBS_OPTION},
	{T("no-globs"),     no_argument,      NULL, IMAGEX_NO_GLOBS_OPTION},
	{T("nullglob"),     no_argument,      NULL, IMAGEX_NULLGLOB_OPTION},
	{T("preserve-dir-structure"), no_argument, NULL, IMAGEX_PRESERVE_DIR_STRUCTURE_OPTION},
	{T("wimboot"),     no_argument,       NULL, IMAGEX_WIMBOOT_OPTION},
	{T("compact"),     required_argument, NULL, IMAGEX_COMPACT_OPTION},
	{T("recover-data"), no_argument,      NULL, IMAGEX_RECOVER_DATA_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option info_options[] = {
	{T("boot"),         no_argument,       NULL, IMAGEX_BOOT_OPTION},
	{T("check"),        no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("nocheck"),      no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("no-check"),     no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("include-integrity"), no_argument,  NULL, IMAGEX_INCLUDE_INTEGRITY_OPTION},
	{T("extract-xml"),  required_argument, NULL, IMAGEX_EXTRACT_XML_OPTION},
	{T("header"),       no_argument,       NULL, IMAGEX_HEADER_OPTION},
	{T("lookup-table"), no_argument,       NULL, IMAGEX_BLOBS_OPTION},
	{T("blobs"),        no_argument,       NULL, IMAGEX_BLOBS_OPTION},
	{T("xml"),          no_argument,       NULL, IMAGEX_XML_OPTION},
	{T("image-property"), required_argument, NULL, IMAGEX_IMAGE_PROPERTY_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option join_options[] = {
	{T("check"), no_argument, NULL, IMAGEX_CHECK_OPTION},
	{T("include-integrity"), no_argument, NULL, IMAGEX_INCLUDE_INTEGRITY_OPTION},
	{NULL, 0, NULL, 0},
};

#if WIM_MOUNTING_SUPPORTED
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
#endif

static const struct option optimize_options[] = {
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("nocheck"),     no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("no-check"),    no_argument,       NULL, IMAGEX_NOCHECK_OPTION},
	{T("include-integrity"), no_argument, NULL, IMAGEX_INCLUDE_INTEGRITY_OPTION},
	{T("compress"),    required_argument, NULL, IMAGEX_COMPRESS_OPTION},
	{T("recompress"),  no_argument,       NULL, IMAGEX_RECOMPRESS_OPTION},
	{T("chunk-size"),  required_argument, NULL, IMAGEX_CHUNK_SIZE_OPTION},
	{T("solid"),       no_argument,       NULL, IMAGEX_SOLID_OPTION},
	{T("solid-compress"),required_argument, NULL, IMAGEX_SOLID_COMPRESS_OPTION},
	{T("solid-chunk-size"),required_argument, NULL, IMAGEX_SOLID_CHUNK_SIZE_OPTION},
	{T("no-solid-sort"), no_argument,     NULL, IMAGEX_NO_SOLID_SORT_OPTION},
	{T("threads"),     required_argument, NULL, IMAGEX_THREADS_OPTION},
	{T("pipable"),     no_argument,       NULL, IMAGEX_PIPABLE_OPTION},
	{T("not-pipable"), no_argument,       NULL, IMAGEX_NOT_PIPABLE_OPTION},
	{T("unsafe-compact"), no_argument,    NULL, IMAGEX_UNSAFE_COMPACT_OPTION},
	{NULL, 0, NULL, 0},
};

static const struct option split_options[] = {
	{T("check"), no_argument, NULL, IMAGEX_CHECK_OPTION},
	{T("include-integrity"), no_argument, NULL, IMAGEX_INCLUDE_INTEGRITY_OPTION},
	{NULL, 0, NULL, 0},
};

#if WIM_MOUNTING_SUPPORTED
static const struct option unmount_options[] = {
	{T("commit"),  no_argument, NULL, IMAGEX_COMMIT_OPTION},
	{T("check"),   no_argument, NULL, IMAGEX_CHECK_OPTION},
	{T("rebuild"), no_argument, NULL, IMAGEX_REBUILD_OPTION},
	{T("lazy"),    no_argument, NULL, IMAGEX_LAZY_OPTION},
	{T("force"),    no_argument, NULL, IMAGEX_FORCE_OPTION},
	{T("new-image"), no_argument, NULL, IMAGEX_NEW_IMAGE_OPTION},
	{NULL, 0, NULL, 0},
};
#endif

static const struct option update_options[] = {
	/* Careful: some of the options here set the defaults for update
	 * commands, but the flags given to an actual update command (and not to
	 * wimupdate itself) are also handled in update_command_add_option(). */
	{T("threads"),     required_argument, NULL, IMAGEX_THREADS_OPTION},
	{T("check"),       no_argument,       NULL, IMAGEX_CHECK_OPTION},
	{T("include-integrity"), no_argument, NULL, IMAGEX_INCLUDE_INTEGRITY_OPTION},
	{T("rebuild"),     no_argument,       NULL, IMAGEX_REBUILD_OPTION},
	{T("command"),     required_argument, NULL, IMAGEX_COMMAND_OPTION},
	{T("wimboot-config"), required_argument, NULL, IMAGEX_WIMBOOT_CONFIG_OPTION},
	{T("ref"),	   required_argument, NULL, IMAGEX_REF_OPTION},

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
	{T("no-replace"),  no_argument,       NULL, IMAGEX_NO_REPLACE_OPTION},
	{T("unsafe-compact"), no_argument,    NULL, IMAGEX_UNSAFE_COMPACT_OPTION},

	{NULL, 0, NULL, 0},
};

static const struct option verify_options[] = {
	{T("ref"), required_argument, NULL, IMAGEX_REF_OPTION},
	{T("nocheck"), no_argument, NULL, IMAGEX_NOCHECK_OPTION},

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
			     "image name.  To list the images\n"
			     "       contained in the WIM archive, run\n"
			     "\n"
			     "           %"TS" \"%"TS"\"\n"),
			     image_name, wim_name,
			     get_cmd_string(CMD_INFO, false), wim_name);
		return WIMLIB_ERR_INVALID_IMAGE;
	}
	return 0;
}

static int
verify_image_is_single(int image)
{
	if (image == WIMLIB_ALL_IMAGES) {
		imagex_error(T("Cannot specify all images for this action!"));
		return WIMLIB_ERR_INVALID_IMAGE;
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

static void
print_available_compression_types(FILE *fp)
{
	static const tchar * const s =
	T(
	"Available compression types:\n"
	"\n"
	"    none\n"
	"    xpress (alias: \"fast\")\n"
	"    lzx    (alias: \"maximum\") (default for capture)\n"
	"    lzms   (alias: \"recovery\")\n"
	"\n"
	);
	tfputs(s, fp);
}

/* Parse the argument to --compress or --solid-compress  */
static int
get_compression_type(tchar *optarg, bool solid)
{
	int ctype;
	unsigned int compression_level = 0;
	tchar *plevel;

	plevel = tstrchr(optarg, T(':'));
	if (plevel) {
		tchar *ptmp;
		unsigned long ultmp;

		*plevel++ = T('\0');
		ultmp = tstrtoul(plevel, &ptmp, 10);
		if (ultmp >= UINT_MAX || ultmp == 0 || *ptmp || ptmp == plevel) {
			imagex_error(T("Compression level must be a positive integer! "
				       "e.g. --compress=lzx:80"));
			return WIMLIB_COMPRESSION_TYPE_INVALID;
		}
		compression_level = ultmp;
	}

	if (!tstrcasecmp(optarg, T("maximum")) ||
	    !tstrcasecmp(optarg, T("lzx")) ||
	    !tstrcasecmp(optarg, T("max"))) {
		ctype = WIMLIB_COMPRESSION_TYPE_LZX;
	} else if (!tstrcasecmp(optarg, T("fast")) || !tstrcasecmp(optarg, T("xpress"))) {
		ctype = WIMLIB_COMPRESSION_TYPE_XPRESS;
	} else if (!tstrcasecmp(optarg, T("recovery"))) {
		if (!solid) {
			tfprintf(stderr,
T(
"Warning: use of '--compress=recovery' is discouraged because it behaves\n"
"   differently from DISM.  Instead, you typically want to use '--solid' to\n"
"   create a solid LZMS-compressed WIM or \"ESD file\", similar to DISM's\n"
"   /compress:recovery.  But if you really want *non-solid* LZMS compression,\n"
"   then you may suppress this warning by specifying '--compress=lzms' instead\n"
"   of '--compress=recovery'.\n"));
		}
		ctype = WIMLIB_COMPRESSION_TYPE_LZMS;
	} else if (!tstrcasecmp(optarg, T("lzms"))) {
		ctype = WIMLIB_COMPRESSION_TYPE_LZMS;
	} else if (!tstrcasecmp(optarg, T("none"))) {
		ctype = WIMLIB_COMPRESSION_TYPE_NONE;
	} else {
		imagex_error(T("Invalid compression type \"%"TS"\"!"), optarg);
		print_available_compression_types(stderr);
		return WIMLIB_COMPRESSION_TYPE_INVALID;
	}

	if (compression_level != 0)
		wimlib_set_default_compression_level(ctype, compression_level);
	return ctype;
}

/* Parse the argument to --compact */
static int
set_compact_mode(const tchar *arg, int *extract_flags)
{
	int flag = 0;
	if (!tstrcasecmp(arg, T("xpress4k")))
		flag = WIMLIB_EXTRACT_FLAG_COMPACT_XPRESS4K;
	else if (!tstrcasecmp(arg, T("xpress8k")))
		flag = WIMLIB_EXTRACT_FLAG_COMPACT_XPRESS8K;
	else if (!tstrcasecmp(arg, T("xpress16k")))
		flag = WIMLIB_EXTRACT_FLAG_COMPACT_XPRESS16K;
	else if (!tstrcasecmp(arg, T("lzx")))
		flag = WIMLIB_EXTRACT_FLAG_COMPACT_LZX;

	if (flag) {
		*extract_flags |= flag;
		return 0;
	}

	imagex_error(T(
"\"%"TS"\" is not a recognized System Compression format.  The options are:"
"\n"
"    --compact=xpress4k\n"
"    --compact=xpress8k\n"
"    --compact=xpress16k\n"
"    --compact=lzx\n"
	), arg);
	return -1;
}


struct string_list {
	tchar **strings;
	unsigned num_strings;
	unsigned num_alloc_strings;
};

#define STRING_LIST_INITIALIZER \
	{ .strings = NULL, .num_strings = 0, .num_alloc_strings = 0, }

#define STRING_LIST(_strings) \
	struct string_list _strings = STRING_LIST_INITIALIZER

static int
string_list_append(struct string_list *list, tchar *glob)
{
	unsigned num_alloc_strings = list->num_alloc_strings;

	if (list->num_strings == num_alloc_strings) {
		tchar **new_strings;

		num_alloc_strings += 4;
		new_strings = realloc(list->strings,
				      sizeof(list->strings[0]) * num_alloc_strings);
		if (!new_strings) {
			imagex_error(T("Out of memory!"));
			return -1;
		}
		list->strings = new_strings;
		list->num_alloc_strings = num_alloc_strings;
	}
	list->strings[list->num_strings++] = glob;
	return 0;
}

static void
string_list_destroy(struct string_list *list)
{
	free(list->strings);
}

static int
wim_reference_globs(WIMStruct *wim, struct string_list *list, int open_flags)
{
	return wimlib_reference_resource_files(wim, (const tchar **)list->strings,
					       list->num_strings,
					       WIMLIB_REF_FLAG_GLOB_ENABLE,
					       open_flags);
}

static int
append_image_property_argument(struct string_list *image_properties)
{
	if (!tstrchr(optarg, '=')) {
		imagex_error(T("'--image-property' argument "
			       "must be in the form NAME=VALUE"));
		return -1;
	}
	return string_list_append(image_properties, optarg);
}

static int
apply_image_properties(struct string_list *image_properties,
		       WIMStruct *wim, int image, bool *any_changes_ret)
{
	bool any_changes = false;
	for (unsigned i = 0; i < image_properties->num_strings; i++) {
		tchar *name, *value;
		const tchar *current_value;
		int ret;

		name = image_properties->strings[i];
		value = tstrchr(name, '=');
		*value++ = '\0';

		current_value = wimlib_get_image_property(wim, image, name);
		if (current_value && !tstrcmp(current_value, value)) {
			imagex_printf(T("The %"TS" property of image %d "
					"already has value \"%"TS"\".\n"),
				      name, image, value);
		} else {
			imagex_printf(T("Setting the %"TS" property of image "
					"%d to \"%"TS"\".\n"),
				      name, image, value);
			ret = wimlib_set_image_property(wim, image, name, value);
			if (ret)
				return ret;
			any_changes = true;
		}
	}
	if (any_changes_ret)
		*any_changes_ret = any_changes;
	return 0;
}

static void
do_resource_not_found_warning(const tchar *wimfile,
			      const struct wimlib_wim_info *info,
			      const struct string_list *refglobs)
{
	if (info->total_parts > 1) {
		if (refglobs->num_strings == 0) {
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
			       "to specify the WIM(s) on which it is based."));
	}
}

static void
do_metadata_not_found_warning(const tchar *wimfile,
			      const struct wimlib_wim_info *info)
{
	if (info->part_number != 1) {
		imagex_error(T("\"%"TS"\" is not the first part of the split WIM.\n"
			       "       You must specify the first part."),
			       wimfile);
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
		if (*line == T('#') || *line == T(';'))
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
	sources = calloc(nlines ? nlines: 1, sizeof(*sources));
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

#define TO_PERCENT(numerator, denominator) \
	(((denominator) == 0) ? 0 : ((numerator) * 100 / (denominator)))

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

static struct wimlib_progress_info_scan last_scan_progress;

static void
report_scan_progress(const struct wimlib_progress_info_scan *scan, bool done)
{
	uint64_t prev_count, cur_count;

	prev_count = last_scan_progress.num_nondirs_scanned +
		     last_scan_progress.num_dirs_scanned;
	cur_count = scan->num_nondirs_scanned + scan->num_dirs_scanned;

	if (done || prev_count == 0 || cur_count >= prev_count + 100 ||
	    cur_count % 128 == 0)
	{
		unsigned unit_shift;
		const tchar *unit_name;

		unit_shift = get_unit(scan->num_bytes_scanned, &unit_name);
		imagex_printf(T("\r%"PRIu64" %"TS" scanned (%"PRIu64" files, "
				"%"PRIu64" directories)    "),
			      scan->num_bytes_scanned >> unit_shift,
			      unit_name,
			      scan->num_nondirs_scanned,
			      scan->num_dirs_scanned);
		last_scan_progress = *scan;
	}
}

static struct wimlib_progress_info_split last_split_progress;

static void
report_split_progress(uint64_t bytes_completed_in_part)
{
	uint64_t completed_bytes = last_split_progress.completed_bytes +
				   bytes_completed_in_part;
	unsigned percent_done = TO_PERCENT(completed_bytes,
					   last_split_progress.total_bytes);
	unsigned unit_shift;
	const tchar *unit_name;

	unit_shift = get_unit(last_split_progress.total_bytes, &unit_name);
	imagex_printf(T("\rSplitting WIM: %"PRIu64" %"TS" of "
			"%"PRIu64" %"TS" (%u%%) written, part %u of %u"),
		      completed_bytes >> unit_shift,
		      unit_name,
		      last_split_progress.total_bytes >> unit_shift,
		      unit_name,
		      percent_done,
		      last_split_progress.cur_part_number,
		      last_split_progress.total_parts);
}

/* Progress callback function passed to various wimlib functions. */
static enum wimlib_progress_status
imagex_progress_func(enum wimlib_progress_msg msg,
		     union wimlib_progress_info *info,
		     void *_ignored_context)
{
	unsigned percent_done;
	unsigned unit_shift;
	const tchar *unit_name;

	switch (msg) {
	case WIMLIB_PROGRESS_MSG_WRITE_STREAMS:
		if (last_split_progress.total_bytes != 0) {
			/* wimlib_split() in progress; use the split-specific
			 * progress message.  */
			report_split_progress(info->write_streams.completed_compressed_bytes);
			break;
		}
		{
			static bool started;
			if (!started) {
				if (info->write_streams.compression_type != WIMLIB_COMPRESSION_TYPE_NONE) {
					imagex_printf(T("Using %"TS" compression "
							"with %u thread%"TS"\n"),
						      wimlib_get_compression_type_string(
								info->write_streams.compression_type),
						info->write_streams.num_threads,
						(info->write_streams.num_threads == 1) ? T("") : T("s"));
				}
				started = true;
			}
		}
		unit_shift = get_unit(info->write_streams.total_bytes, &unit_name);
		percent_done = TO_PERCENT(info->write_streams.completed_bytes,
					  info->write_streams.total_bytes);

		imagex_printf(T("\rArchiving file data: %"PRIu64" %"TS" of %"PRIu64" %"TS" (%u%%) done"),
			info->write_streams.completed_bytes >> unit_shift,
			unit_name,
			info->write_streams.total_bytes >> unit_shift,
			unit_name,
			percent_done);
		if (info->write_streams.completed_bytes >= info->write_streams.total_bytes)
			imagex_printf(T("\n"));
		break;
	case WIMLIB_PROGRESS_MSG_SCAN_BEGIN:
		imagex_printf(T("Scanning \"%"TS"\""), info->scan.source);
		if (WIMLIB_IS_WIM_ROOT_PATH(info->scan.wim_target_path)) {
			imagex_printf(T("\n"));
		} else {
			imagex_printf(T(" (loading as WIM path: \"%"TS"\")...\n"),
				      info->scan.wim_target_path);
		}
		memset(&last_scan_progress, 0, sizeof(last_scan_progress));
		break;
	case WIMLIB_PROGRESS_MSG_SCAN_DENTRY:
		switch (info->scan.status) {
		case WIMLIB_SCAN_DENTRY_OK:
			report_scan_progress(&info->scan, false);
			break;
		case WIMLIB_SCAN_DENTRY_EXCLUDED:
			imagex_printf(T("\nExcluding \"%"TS"\" from capture\n"), info->scan.cur_path);
			break;
		case WIMLIB_SCAN_DENTRY_UNSUPPORTED:
			imagex_printf(T("\nWARNING: Excluding unsupported file or directory\n"
					"         \"%"TS"\" from capture\n"), info->scan.cur_path);
			break;
		case WIMLIB_SCAN_DENTRY_FIXED_SYMLINK:
			/* Symlink fixups are enabled by default.  This is
			 * mainly intended for Windows, which for some reason
			 * uses absolute junctions (with drive letters!) in the
			 * default installation.  On UNIX-like systems, warn the
			 * user when fixing the target of an absolute symbolic
			 * link, so they know to disable this if they want.  */
		#ifndef _WIN32
			imagex_printf(T("\nWARNING: Adjusted target of "
					"absolute symbolic link \"%"TS"\"\n"
					"           (Use --norpfix to capture "
					"absolute symbolic links as-is)\n"),
				        info->scan.cur_path);
		#endif
			break;
		default:
			break;
		}
		break;
	case WIMLIB_PROGRESS_MSG_SCAN_END:
		report_scan_progress(&info->scan, true);
		imagex_printf(T("\n"));
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
	case WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE:
		if (info->extract.end_file_count >= 2000) {
			percent_done = TO_PERCENT(info->extract.current_file_count,
						  info->extract.end_file_count);
			imagex_printf(T("\rCreating files: %"PRIu64" of %"PRIu64" (%u%%) done"),
				      info->extract.current_file_count,
				      info->extract.end_file_count, percent_done);
			if (info->extract.current_file_count == info->extract.end_file_count)
				imagex_printf(T("\n"));
		}
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS:
		percent_done = TO_PERCENT(info->extract.completed_bytes,
					  info->extract.total_bytes);
		unit_shift = get_unit(info->extract.total_bytes, &unit_name);
		imagex_printf(T("\rExtracting file data: "
			  "%"PRIu64" %"TS" of %"PRIu64" %"TS" (%u%%) done"),
			info->extract.completed_bytes >> unit_shift,
			unit_name,
			info->extract.total_bytes >> unit_shift,
			unit_name,
			percent_done);
		if (info->extract.completed_bytes >= info->extract.total_bytes)
			imagex_printf(T("\n"));
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_METADATA:
		if (info->extract.end_file_count >= 2000) {
			percent_done = TO_PERCENT(info->extract.current_file_count,
						  info->extract.end_file_count);
			imagex_printf(T("\rApplying metadata to files: %"PRIu64" of %"PRIu64" (%u%%) done"),
				      info->extract.current_file_count,
				      info->extract.end_file_count, percent_done);
			if (info->extract.current_file_count == info->extract.end_file_count)
				imagex_printf(T("\n"));
		}
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN:
		if (info->extract.total_parts != 1) {
			imagex_printf(T("\nReading split pipable WIM part %u of %u\n"),
				      info->extract.part_number,
				      info->extract.total_parts);
		}
		break;
	case WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART:
	case WIMLIB_PROGRESS_MSG_SPLIT_END_PART:
		last_split_progress = info->split;
		report_split_progress(0);
		break;
	case WIMLIB_PROGRESS_MSG_UPDATE_END_COMMAND:
		switch (info->update.command->op) {
		case WIMLIB_UPDATE_OP_DELETE:
			imagex_printf(T("Deleted WIM path \"%"TS"\"\n"),
				info->update.command->delete_.wim_path);
			break;
		case WIMLIB_UPDATE_OP_RENAME:
			imagex_printf(T("Renamed WIM path \"%"TS"\" => \"%"TS"\"\n"),
				info->update.command->rename.wim_source_path,
				info->update.command->rename.wim_target_path);
			break;
		case WIMLIB_UPDATE_OP_ADD:
		default:
			break;
		}
		break;
	case WIMLIB_PROGRESS_MSG_REPLACE_FILE_IN_WIM:
		imagex_printf(T("Updating \"%"TS"\" in WIM image\n"),
			      info->replace.path_in_wim);
		break;
	case WIMLIB_PROGRESS_MSG_WIMBOOT_EXCLUDE:
		imagex_printf(T("\nExtracting \"%"TS"\" as normal file (not WIMBoot pointer)\n"),
			      info->wimboot_exclude.path_in_wim);
		break;
	case WIMLIB_PROGRESS_MSG_UNMOUNT_BEGIN:
		if (info->unmount.mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
			if (info->unmount.unmount_flags & WIMLIB_UNMOUNT_FLAG_COMMIT) {
				imagex_printf(T("Committing changes to %"TS" (image %d)\n"),
					      info->unmount.mounted_wim,
					      info->unmount.mounted_image);
			} else {
				imagex_printf(T("Discarding changes to %"TS" (image %d)\n"),
					      info->unmount.mounted_wim,
					      info->unmount.mounted_image);
				imagex_printf(T("\t(Use --commit to keep changes.)\n"));
			}
		}
		break;
	case WIMLIB_PROGRESS_MSG_BEGIN_VERIFY_IMAGE:
		imagex_printf(T("Verifying metadata for image %"PRIu32" of %"PRIu32"\n"),
			      info->verify_image.current_image,
			      info->verify_image.total_images);
		break;
	case WIMLIB_PROGRESS_MSG_VERIFY_STREAMS:
		percent_done = TO_PERCENT(info->verify_streams.completed_bytes,
					  info->verify_streams.total_bytes);
		unit_shift = get_unit(info->verify_streams.total_bytes, &unit_name);
		imagex_printf(T("\rVerifying file data: "
			  "%"PRIu64" %"TS" of %"PRIu64" %"TS" (%u%%) done"),
			info->verify_streams.completed_bytes >> unit_shift,
			unit_name,
			info->verify_streams.total_bytes >> unit_shift,
			unit_name,
			percent_done);
		if (info->verify_streams.completed_bytes == info->verify_streams.total_bytes)
			imagex_printf(T("\n"));
		break;
	default:
		break;
	}
	imagex_flush_output();
	return WIMLIB_PROGRESS_STATUS_CONTINUE;
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

static uint32_t
parse_chunk_size(const tchar *optarg)
{
	tchar *tmp;
	uint64_t chunk_size = tstrtoul(optarg, &tmp, 10);
	if (chunk_size == 0) {
		imagex_error(T("Invalid chunk size specification; must be a positive integer\n"
			       "       with optional K, M, or G suffix"));
		return UINT32_MAX;
	}
	if (*tmp) {
		if (*tmp == T('k') || *tmp == T('K')) {
			chunk_size <<= 10;
			tmp++;
		} else if (*tmp == T('m') || *tmp == T('M')) {
			chunk_size <<= 20;
			tmp++;
		} else if (*tmp == T('g') || *tmp == T('G')) {
			chunk_size <<= 30;
			tmp++;
		}
		if (*tmp && !(*tmp == T('i') && *(tmp + 1) == T('B'))) {
			imagex_error(T("Invalid chunk size specification; suffix must be K, M, or G"));
			return UINT32_MAX;
		}
	}
	if (chunk_size >= UINT32_MAX) {
		imagex_error(T("Invalid chunk size specification; the value is too large!"));
		return UINT32_MAX;
	}
	return chunk_size;
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
		else if (!tstrcmp(option, T("--no-replace")))
			cmd->add.add_flags |= WIMLIB_ADD_FLAG_NO_REPLACE;
		else
			recognized = false;
		break;
	case WIMLIB_UPDATE_OP_DELETE:
		if (!tstrcmp(option, T("--force")))
			cmd->delete_.delete_flags |= WIMLIB_DELETE_FLAG_FORCE;
		else if (!tstrcmp(option, T("--recursive")))
			cmd->delete_.delete_flags |= WIMLIB_DELETE_FLAG_RECURSIVE;
		else
			recognized = false;
		break;
	default:
		recognized = false;
		break;
	}
	return recognized;
}

/* How many nonoption arguments each wimupdate command expects */
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
		cmd->delete_.wim_path = (tchar*)nonoption;
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
 * Parse a command passed on stdin to wimupdate.
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
	cmds = calloc(nlines ? nlines: 1, sizeof(struct wimlib_update_command));
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

/* Apply one image, or all images, from a WIM file to a directory, OR apply
 * one image from a WIM file to an NTFS volume.  */
static int
imagex_apply(int argc, tchar **argv, int cmd)
{
	int c;
	int open_flags = 0;
	int image = WIMLIB_NO_IMAGE;
	WIMStruct *wim;
	struct wimlib_wim_info info;
	int ret;
	const tchar *wimfile;
	const tchar *target;
	const tchar *image_num_or_name = NULL;
	int extract_flags = 0;

	STRING_LIST(refglobs);

	for_opt(c, apply_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_VERBOSE_OPTION:
			/* No longer does anything.  */
			break;
		case IMAGEX_REF_OPTION:
			ret = string_list_append(&refglobs, optarg);
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
		case IMAGEX_NO_ATTRIBUTES_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES;
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
		case IMAGEX_WIMBOOT_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_WIMBOOT;
			break;
		case IMAGEX_COMPACT_OPTION:
			ret = set_compact_mode(optarg, &extract_flags);
			if (ret)
				goto out_free_refglobs;
			break;
		case IMAGEX_RECOVER_DATA_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_RECOVER_DATA;
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
		ret = wimlib_open_wim_with_progress(wimfile, open_flags, &wim,
						    imagex_progress_func, NULL);
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

	if (refglobs.num_strings) {
		if (wim == NULL) {
			imagex_error(T("Can't specify --ref when applying from stdin!"));
			ret = -1;
			goto out_wimlib_free;
		}
		ret = wim_reference_globs(wim, &refglobs, open_flags);
		if (ret)
			goto out_wimlib_free;
	}

#ifndef _WIN32
	{
		/* Interpret a regular file or block device target as an NTFS
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
		ret = wimlib_extract_image(wim, image, target, extract_flags);
	} else {
		set_fd_to_binary_mode(STDIN_FILENO);
		ret = wimlib_extract_image_from_pipe_with_progress(
					   STDIN_FILENO,
					   image_num_or_name,
					   target,
					   extract_flags,
					   imagex_progress_func,
					   NULL);
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
	} else if (ret == WIMLIB_ERR_METADATA_NOT_FOUND && wim) {
		do_metadata_not_found_warning(wimfile, &info);
	}
out_wimlib_free:
	wimlib_free(wim);
out_free_refglobs:
	string_list_destroy(&refglobs);
	return ret;

out_usage:
	usage(CMD_APPLY, stderr);
	ret = -1;
	goto out_free_refglobs;
}

/*
 * Create a WIM image from a directory tree, NTFS volume, or multiple files or
 * directory trees.  'wimcapture': create a new WIM file containing the desired
 * image.  'wimappend': add a new image to an existing WIM file; or, with
 * '--create' behave like 'wimcapture' if the WIM file doesn't exist.
 */
static int
imagex_capture_or_append(int argc, tchar **argv, int cmd)
{
	int c;
	bool create = false;
	bool appending = (cmd == CMD_APPEND);
	int open_flags = 0;
	int add_flags = WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE |
			WIMLIB_ADD_FLAG_WINCONFIG |
			WIMLIB_ADD_FLAG_VERBOSE |
			WIMLIB_ADD_FLAG_FILE_PATHS_UNNEEDED;
	int write_flags = 0;
	int compression_type = WIMLIB_COMPRESSION_TYPE_INVALID;
	uint32_t chunk_size = UINT32_MAX;
	uint32_t solid_chunk_size = UINT32_MAX;
	int solid_ctype = WIMLIB_COMPRESSION_TYPE_INVALID;
	const tchar *wimfile;
	int wim_fd;
	const tchar *name;
	STRING_LIST(image_properties);

	WIMStruct *wim;
	STRING_LIST(base_wimfiles);
	WIMStruct **base_wims;

	WIMStruct *template_wim = NULL;
	const tchar *template_wimfile = NULL;
	const tchar *template_image_name_or_num = NULL;
	int template_image = WIMLIB_NO_IMAGE;

	int ret;
	unsigned num_threads = 0;

	tchar *source;
	tchar *source_copy;

	tchar *config_file = NULL;

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
			add_flags |= WIMLIB_ADD_FLAG_BOOT;
			break;
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			/* fall-through */
		case IMAGEX_INCLUDE_INTEGRITY_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_NOCHECK_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY;
			break;
		case IMAGEX_CONFIG_OPTION:
			config_file = optarg;
			add_flags &= ~WIMLIB_ADD_FLAG_WINCONFIG;
			break;
		case IMAGEX_COMPRESS_OPTION:
			compression_type = get_compression_type(optarg, false);
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				goto out_err;
			break;
		case IMAGEX_CHUNK_SIZE_OPTION:
			chunk_size = parse_chunk_size(optarg);
			if (chunk_size == UINT32_MAX)
				goto out_err;
			break;
		case IMAGEX_SOLID_CHUNK_SIZE_OPTION:
			solid_chunk_size = parse_chunk_size(optarg);
			if (solid_chunk_size == UINT32_MAX)
				goto out_err;
			break;
		case IMAGEX_SOLID_COMPRESS_OPTION:
			solid_ctype = get_compression_type(optarg, true);
			if (solid_ctype == WIMLIB_COMPRESSION_TYPE_INVALID)
				goto out_err;
			break;
		case IMAGEX_SOLID_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_SOLID;
			break;
		case IMAGEX_NO_SOLID_SORT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_SOLID_SORT;
			break;
		case IMAGEX_FLAGS_OPTION: {
			tchar *p = alloca((6 + tstrlen(optarg) + 1) * sizeof(tchar));
			tsprintf(p, T("FLAGS=%"TS), optarg);
			ret = string_list_append(&image_properties, p);
			if (ret)
				goto out;
			break;
		}
		case IMAGEX_IMAGE_PROPERTY_OPTION:
			ret = append_image_property_argument(&image_properties);
			if (ret)
				goto out;
			break;
		case IMAGEX_DEREFERENCE_OPTION:
			add_flags |= WIMLIB_ADD_FLAG_DEREFERENCE;
			break;
		case IMAGEX_VERBOSE_OPTION:
			/* No longer does anything.  */
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
			add_flags |= WIMLIB_ADD_FLAG_UNIX_DATA;
			break;
		case IMAGEX_SOURCE_LIST_OPTION:
			source_list = true;
			break;
		case IMAGEX_NO_ACLS_OPTION:
			add_flags |= WIMLIB_ADD_FLAG_NO_ACLS;
			break;
		case IMAGEX_STRICT_ACLS_OPTION:
			add_flags |= WIMLIB_ADD_FLAG_STRICT_ACLS;
			break;
		case IMAGEX_RPFIX_OPTION:
			add_flags |= WIMLIB_ADD_FLAG_RPFIX;
			break;
		case IMAGEX_NORPFIX_OPTION:
			add_flags |= WIMLIB_ADD_FLAG_NORPFIX;
			break;
		case IMAGEX_PIPABLE_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
			break;
		case IMAGEX_NOT_PIPABLE_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NOT_PIPABLE;
			break;
		case IMAGEX_UPDATE_OF_OPTION:
			if (template_image_name_or_num) {
				imagex_error(T("'--update-of' can only be "
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
		#ifdef _WIN32
			imagex_printf(T("[WARNING] '--update-of' is unreliable on Windows!\n"));
		#endif
			break;
		case IMAGEX_DELTA_FROM_OPTION:
			ret = string_list_append(&base_wimfiles, optarg);
			if (ret)
				goto out;
			write_flags |= WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS;
			break;
		case IMAGEX_WIMBOOT_OPTION:
			add_flags |= WIMLIB_ADD_FLAG_WIMBOOT;
			break;
		case IMAGEX_UNSAFE_COMPACT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_UNSAFE_COMPACT;
			break;
		case IMAGEX_SNAPSHOT_OPTION:
			add_flags |= WIMLIB_ADD_FLAG_SNAPSHOT;
			break;
		case IMAGEX_CREATE_OPTION:
			if (cmd == CMD_CAPTURE) {
				imagex_error(T("'--create' is only valid for 'wimappend', not 'wimcapture'"));
				goto out_err;
			}
			create = true;
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

	/* Set default compression type and parameters.  */


	if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID) {
		/* No compression type specified.  Use the default.  */

		if (add_flags & WIMLIB_ADD_FLAG_WIMBOOT) {
			/* With --wimboot, default to XPRESS compression.  */
			compression_type = WIMLIB_COMPRESSION_TYPE_XPRESS;
		} else if (write_flags & WIMLIB_WRITE_FLAG_SOLID) {
			/* With --solid, default to LZMS compression.  (However,
			 * this will not affect solid resources!)  */
			compression_type = WIMLIB_COMPRESSION_TYPE_LZMS;
		} else {
			/* Otherwise, default to LZX compression.  */
			compression_type = WIMLIB_COMPRESSION_TYPE_LZX;
		}
	}

	if (!tstrcmp(wimfile, T("-"))) {
		/* Writing captured WIM to standard output.  */
		if (create)
			appending = false;
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
		if (appending) {
			imagex_error(T("Using standard output for append does "
				       "not make sense."));
			goto out_err;
		}
		wim_fd = STDOUT_FILENO;
		wimfile = NULL;
		imagex_output_to_stderr();
		set_fd_to_binary_mode(wim_fd);
	} else {
		struct stat stbuf;

		/* Check for 'wimappend --create' acting as wimcapture */
		if (create && tstat(wimfile, &stbuf) != 0 && errno == ENOENT) {

			appending = false;

			/* Ignore '--update-of' for the target WIMFILE */
			if (template_image_name_or_num &&
			    (!template_wimfile ||
			     !tstrcmp(template_wimfile, wimfile)))
			{
				template_image_name_or_num = NULL;
				template_wimfile = NULL;
			}
		}
	}

	if ((write_flags & WIMLIB_WRITE_FLAG_UNSAFE_COMPACT) && !appending) {
		imagex_error(T("'--unsafe-compact' is only valid for append!"));
		goto out_err;
	}

	/* If template image was specified using --update-of=IMAGE rather
	 * than --update-of=WIMFILE:IMAGE, set the default WIMFILE.  */
	if (template_image_name_or_num && !template_wimfile) {
		if (base_wimfiles.num_strings == 1) {
			/* Capturing delta WIM based on single WIM:  default to
			 * base WIM.  */
			template_wimfile = base_wimfiles.strings[0];
		} else if (appending) {
			/* Appending to WIM:  default to WIM being appended to.
			 */
			template_wimfile = wimfile;
		} else {
			/* Capturing a normal (non-delta) WIM, so the WIM file
			 * *must* be explicitly specified.  */
			if (base_wimfiles.num_strings > 1) {
				imagex_error(T("For capture of delta WIM "
					       "based on multiple existing "
					       "WIMs,\n"
					       "      '--update-of' must "
					       "specify WIMFILE:IMAGE!"));
			} else {
				imagex_error(T("For capture of non-delta WIM, "
					       "'--update-of' must specify "
					       "WIMFILE:IMAGE!"));
			}
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

	/* Image description (if given). */
	if (argc >= 4) {
		tchar *p = alloca((12 + tstrlen(argv[3]) + 1) * sizeof(tchar));
		tsprintf(p, T("DESCRIPTION=%"TS), argv[3]);
		ret = string_list_append(&image_properties, p);
		if (ret)
			goto out;
	}

	if (source_list) {
		/* Set up capture sources in source list mode */
		if (wimlib_load_text_file(source, &source_list_contents,
					  &source_list_nchars) != 0)
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
		capture_sources[0].wim_target_path = WIMLIB_WIM_ROOT_PATH;
		capture_sources[0].reserved = 0;
		num_sources = 1;
		capture_sources_malloced = false;
		source_list_contents = NULL;
	}

	/* Open the existing WIM, or create a new one.  */
	if (appending) {
		ret = wimlib_open_wim_with_progress(wimfile,
						    open_flags | WIMLIB_OPEN_FLAG_WRITE_ACCESS,
						    &wim,
						    imagex_progress_func,
						    NULL);
		if (ret)
			goto out_free_capture_sources;
	} else {
		ret = wimlib_create_new_wim(compression_type, &wim);
		if (ret)
			goto out_free_capture_sources;
		wimlib_register_progress_function(wim, imagex_progress_func, NULL);
	}

	/* Set chunk size if non-default.  */
	if (chunk_size != UINT32_MAX) {
		ret = wimlib_set_output_chunk_size(wim, chunk_size);
		if (ret)
			goto out_free_wim;
	} else if ((add_flags & WIMLIB_ADD_FLAG_WIMBOOT)) {

		int ctype = compression_type;

		if (appending) {
			struct wimlib_wim_info info;
			wimlib_get_wim_info(wim, &info);
			ctype = info.compression_type;
		}

		if (ctype == WIMLIB_COMPRESSION_TYPE_XPRESS) {
			ret = wimlib_set_output_chunk_size(wim, 4096);
			if (ret)
				goto out_free_wim;
		}
	}
	if (solid_ctype != WIMLIB_COMPRESSION_TYPE_INVALID) {
		ret = wimlib_set_output_pack_compression_type(wim, solid_ctype);
		if (ret)
			goto out_free_wim;
	}
	if (solid_chunk_size != UINT32_MAX) {
		ret = wimlib_set_output_pack_chunk_size(wim, solid_chunk_size);
		if (ret)
			goto out_free_wim;
	}

#ifndef _WIN32
	/* Detect if source is regular file or block device and set NTFS volume
	 * capture mode.  */
	if (!source_list) {
		struct stat stbuf;

		if (tstat(source, &stbuf) == 0) {
			if (S_ISBLK(stbuf.st_mode) || S_ISREG(stbuf.st_mode)) {
				imagex_printf(T("Capturing WIM image from NTFS "
					  "filesystem on \"%"TS"\"\n"), source);
				add_flags |= WIMLIB_ADD_FLAG_NTFS;
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
	if (appending && name_defaulted) {
		unsigned long conflict_idx;
		tchar *name_end = tstrchr(name, T('\0'));
		for (conflict_idx = 1;
		     wimlib_image_name_in_use(wim, name);
		     conflict_idx++)
		{
			tsprintf(name_end, T(" (%lu)"), conflict_idx);
		}
	}

	/* If capturing a delta WIM, reference resources from the base WIMs
	 * before adding the new image.  */
	if (base_wimfiles.num_strings) {
		base_wims = calloc(base_wimfiles.num_strings,
				   sizeof(base_wims[0]));
		if (base_wims == NULL) {
			imagex_error(T("Out of memory!"));
			ret = -1;
			goto out_free_wim;
		}

		for (size_t i = 0; i < base_wimfiles.num_strings; i++) {
			ret = wimlib_open_wim_with_progress(
				    base_wimfiles.strings[i], open_flags,
				    &base_wims[i], imagex_progress_func, NULL);
			if (ret)
				goto out_free_base_wims;

		}

		ret = wimlib_reference_resources(wim, base_wims,
						 base_wimfiles.num_strings, 0);
		if (ret)
			goto out_free_base_wims;

		if (base_wimfiles.num_strings == 1) {
			imagex_printf(T("Capturing delta WIM based on \"%"TS"\"\n"),
				      base_wimfiles.strings[0]);
		} else {
			imagex_printf(T("Capturing delta WIM based on %u WIMs\n"),
				      base_wimfiles.num_strings);
		}

	} else {
		base_wims = NULL;
	}

	/* If capturing or appending as an update of an existing (template) image,
	 * open the WIM if needed and parse the image index.  */
	if (template_image_name_or_num) {

		if (appending && !tstrcmp(template_wimfile, wimfile)) {
			template_wim = wim;
		} else {
			for (size_t i = 0; i < base_wimfiles.num_strings; i++) {
				if (!tstrcmp(template_wimfile,
					     base_wimfiles.strings[i])) {
					template_wim = base_wims[i];
					break;
				}
			}
		}

		if (!template_wim) {
			ret = wimlib_open_wim_with_progress(template_wimfile,
							    open_flags,
							    &template_wim,
							    imagex_progress_func,
							    NULL);
			if (ret)
				goto out_free_base_wims;
		}

		template_image = wimlib_resolve_image(template_wim,
						      template_image_name_or_num);

		if (template_image_name_or_num[0] == T('-')) {
			tchar *tmp;
			unsigned long n;
			struct wimlib_wim_info info;

			wimlib_get_wim_info(template_wim, &info);
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
	}

	ret = wimlib_add_image_multisource(wim,
					   capture_sources,
					   num_sources,
					   name,
					   config_file,
					   add_flags);
	if (ret)
		goto out_free_template_wim;

	if (image_properties.num_strings || template_image_name_or_num) {
		/* User asked to set additional image properties, or an image on
		 * which the added one is to be based has been specified with
		 * --update-of.  */
		struct wimlib_wim_info info;

		wimlib_get_wim_info(wim, &info);

		ret = apply_image_properties(&image_properties, wim,
					     info.image_count, NULL);
		if (ret)
			goto out_free_template_wim;

		/* Reference template image if the user provided one.  */
		if (template_image_name_or_num) {
			imagex_printf(T("Using image %d "
					"from \"%"TS"\" as template\n"),
					template_image, template_wimfile);
			ret = wimlib_reference_template_image(wim,
							      info.image_count,
							      template_wim,
							      template_image,
							      0);
			if (ret)
				goto out_free_template_wim;
		}
	}

	/* Write the new WIM or overwrite the existing WIM with the new image
	 * appended.  */
	if (appending) {
		ret = wimlib_overwrite(wim, write_flags, num_threads);
	} else if (wimfile) {
		ret = wimlib_write(wim, wimfile, WIMLIB_ALL_IMAGES,
				   write_flags, num_threads);
	} else {
		ret = wimlib_write_to_fd(wim, wim_fd, WIMLIB_ALL_IMAGES,
					 write_flags, num_threads);
	}
out_free_template_wim:
	/* 'template_wim' may alias 'wim' or any of the 'base_wims' */
	if (template_wim == wim)
		goto out_free_base_wims;
	for (size_t i = 0; i < base_wimfiles.num_strings; i++)
		if (template_wim == base_wims[i])
			goto out_free_base_wims;
	wimlib_free(template_wim);
out_free_base_wims:
	for (size_t i = 0; i < base_wimfiles.num_strings; i++)
		wimlib_free(base_wims[i]);
	free(base_wims);
out_free_wim:
	wimlib_free(wim);
out_free_capture_sources:
	if (capture_sources_malloced)
		free(capture_sources);
out_free_source_list_contents:
	free(source_list_contents);
out:
	string_list_destroy(&image_properties);
	string_list_destroy(&base_wimfiles);
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
			/* fall-through */
		case IMAGEX_INCLUDE_INTEGRITY_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_SOFT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_SOFT_DELETE;
			break;
		case IMAGEX_UNSAFE_COMPACT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_UNSAFE_COMPACT;
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

	ret = wimlib_open_wim_with_progress(wimfile, open_flags, &wim,
					    imagex_progress_func, NULL);
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

	ret = wimlib_overwrite(wim, write_flags, 0);
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

struct print_dentry_options {
	bool detailed;
};

static void
print_dentry_full_path(const struct wimlib_dir_entry *dentry)
{
	tprintf(T("%"TS"\n"), dentry->full_path);
}

static const struct {
	uint32_t flag;
	const tchar *name;
} file_attr_flags[] = {
	{WIMLIB_FILE_ATTRIBUTE_READONLY,	    T("READONLY")},
	{WIMLIB_FILE_ATTRIBUTE_HIDDEN,		    T("HIDDEN")},
	{WIMLIB_FILE_ATTRIBUTE_SYSTEM,		    T("SYSTEM")},
	{WIMLIB_FILE_ATTRIBUTE_DIRECTORY,	    T("DIRECTORY")},
	{WIMLIB_FILE_ATTRIBUTE_ARCHIVE,		    T("ARCHIVE")},
	{WIMLIB_FILE_ATTRIBUTE_DEVICE,		    T("DEVICE")},
	{WIMLIB_FILE_ATTRIBUTE_NORMAL,		    T("NORMAL")},
	{WIMLIB_FILE_ATTRIBUTE_TEMPORARY,	    T("TEMPORARY")},
	{WIMLIB_FILE_ATTRIBUTE_SPARSE_FILE,	    T("SPARSE_FILE")},
	{WIMLIB_FILE_ATTRIBUTE_REPARSE_POINT,	    T("REPARSE_POINT")},
	{WIMLIB_FILE_ATTRIBUTE_COMPRESSED,	    T("COMPRESSED")},
	{WIMLIB_FILE_ATTRIBUTE_OFFLINE,		    T("OFFLINE")},
	{WIMLIB_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, T("NOT_CONTENT_INDEXED")},
	{WIMLIB_FILE_ATTRIBUTE_ENCRYPTED,	    T("ENCRYPTED")},
	{WIMLIB_FILE_ATTRIBUTE_VIRTUAL,		    T("VIRTUAL")},
};

#define TIMESTR_MAX 100

static void
print_time(const tchar *type, const struct wimlib_timespec *wts,
	   int32_t high_part)
{
	tchar timestr[TIMESTR_MAX];
	time_t t;
	struct tm tm;

	if (sizeof(wts->tv_sec) == 4 && sizeof(t) > sizeof(wts->tv_sec))
		t = (uint32_t)wts->tv_sec | ((uint64_t)high_part << 32);
	else
		t = wts->tv_sec;

	gmtime_r(&t, &tm);
	tstrftime(timestr, TIMESTR_MAX, T("%a %b %d %H:%M:%S %Y UTC"), &tm);
	timestr[TIMESTR_MAX - 1] = '\0';

	tprintf(T("%-20"TS"= %"TS"\n"), type, timestr);
}

static void print_byte_field(const uint8_t field[], size_t len)
{
	while (len--)
		tprintf(T("%02hhx"), *field++);
}

static void
print_wim_information(const tchar *wimfile, const struct wimlib_wim_info *info)
{
	tchar attr_string[256];
	tchar *p;

	tputs(T("WIM Information:"));
	tputs(T("----------------"));
	tprintf(T("Path:           %"TS"\n"), wimfile);
	tprintf(T("GUID:           0x"));
	print_byte_field(info->guid, sizeof(info->guid));
	tputchar(T('\n'));
	tprintf(T("Version:        %u\n"), info->wim_version);
	tprintf(T("Image Count:    %d\n"), info->image_count);
	tprintf(T("Compression:    %"TS"\n"),
		wimlib_get_compression_type_string(info->compression_type));
	tprintf(T("Chunk Size:     %"PRIu32" bytes\n"),
		info->chunk_size);
	tprintf(T("Part Number:    %d/%d\n"), info->part_number, info->total_parts);
	tprintf(T("Boot Index:     %d\n"), info->boot_index);
	tprintf(T("Size:           %"PRIu64" bytes\n"), info->total_bytes);

	attr_string[0] = T('\0');

	if (info->pipable)
		tstrcat(attr_string, T("Pipable, "));

	if (info->has_integrity_table)
		tstrcat(attr_string, T("Integrity info, "));

	if (info->has_rpfix)
		tstrcat(attr_string, T("Relative path junction, "));

	if (info->resource_only)
		tstrcat(attr_string, T("Resource only, "));

	if (info->metadata_only)
		tstrcat(attr_string, T("Metadata only, "));

	if (info->is_marked_readonly)
		tstrcat(attr_string, T("Readonly, "));

	p = tstrchr(attr_string, T('\0'));
	if (p >= &attr_string[2] && p[-1] == T(' ') && p[-2] == T(','))
		p[-2] = T('\0');

	tprintf(T("Attributes:     %"TS"\n\n"), attr_string);
}

static int
print_resource(const struct wimlib_resource_entry *resource,
	       void *_ignore)
{
	tprintf(T("Hash              = 0x"));
	print_byte_field(resource->sha1_hash, sizeof(resource->sha1_hash));
	tputchar(T('\n'));

	if (!resource->is_missing) {
		tprintf(T("Uncompressed size = %"PRIu64" bytes\n"),
			resource->uncompressed_size);
		if (resource->packed) {
			tprintf(T("Solid resource    = %"PRIu64" => %"PRIu64" "
				  "bytes @ offset %"PRIu64"\n"),
				resource->raw_resource_uncompressed_size,
				resource->raw_resource_compressed_size,
				resource->raw_resource_offset_in_wim);

			tprintf(T("Solid offset      = %"PRIu64" bytes\n"),
				resource->offset);
		} else {
			tprintf(T("Compressed size   = %"PRIu64" bytes\n"),
				resource->compressed_size);

			tprintf(T("Offset in WIM     = %"PRIu64" bytes\n"),
				resource->offset);
		}

		tprintf(T("Part Number       = %u\n"), resource->part_number);
		tprintf(T("Reference Count   = %u\n"), resource->reference_count);

		tprintf(T("Flags             = "));
		if (resource->is_compressed)
			tprintf(T("WIM_RESHDR_FLAG_COMPRESSED  "));
		if (resource->is_metadata)
			tprintf(T("WIM_RESHDR_FLAG_METADATA  "));
		if (resource->is_free)
			tprintf(T("WIM_RESHDR_FLAG_FREE  "));
		if (resource->is_spanned)
			tprintf(T("WIM_RESHDR_FLAG_SPANNED  "));
		if (resource->packed)
			tprintf(T("WIM_RESHDR_FLAG_SOLID  "));
		tputchar(T('\n'));
	}
	tputchar(T('\n'));
	return 0;
}

static void
print_blobs(WIMStruct *wim)
{
	wimlib_iterate_lookup_table(wim, 0, print_resource, NULL);
}

#ifndef _WIN32
static void
default_print_security_descriptor(const uint8_t *sd, size_t size)
{
	tprintf(T("Security Descriptor = "));
	print_byte_field(sd, size);
	tputchar(T('\n'));
}
#endif

static bool
is_null_guid(const uint8_t *guid)
{
	static const uint8_t null_guid[WIMLIB_GUID_LEN];

	return !memcmp(guid, null_guid, WIMLIB_GUID_LEN);
}

static void
print_guid(const tchar *label, const uint8_t *guid)
{
	if (is_null_guid(guid))
		return;
	tprintf(T("%-20"TS"= 0x"), label);
	print_byte_field(guid, WIMLIB_GUID_LEN);
	tputchar(T('\n'));
}

static void
print_dentry_detailed(const struct wimlib_dir_entry *dentry)
{
	tprintf(T(
"----------------------------------------------------------------------------\n"));
	tprintf(T("Full Path           = \"%"TS"\"\n"), dentry->full_path);
	if (dentry->dos_name)
		tprintf(T("Short Name          = \"%"TS"\"\n"), dentry->dos_name);
	tprintf(T("Attributes          = 0x%08x\n"), dentry->attributes);
	for (size_t i = 0; i < ARRAY_LEN(file_attr_flags); i++)
		if (file_attr_flags[i].flag & dentry->attributes)
			tprintf(T("    FILE_ATTRIBUTE_%"TS" is set\n"),
				file_attr_flags[i].name);

	if (dentry->security_descriptor) {
		print_security_descriptor(dentry->security_descriptor,
					  dentry->security_descriptor_size);
	}

	print_time(T("Creation Time"),
		   &dentry->creation_time, dentry->creation_time_high);
	print_time(T("Last Write Time"),
		   &dentry->last_write_time, dentry->last_write_time_high);
	print_time(T("Last Access Time"),
		   &dentry->last_access_time, dentry->last_access_time_high);


	if (dentry->attributes & WIMLIB_FILE_ATTRIBUTE_REPARSE_POINT)
		tprintf(T("Reparse Tag         = 0x%"PRIx32"\n"), dentry->reparse_tag);

	tprintf(T("Link Group ID       = 0x%016"PRIx64"\n"), dentry->hard_link_group_id);
	tprintf(T("Link Count          = %"PRIu32"\n"), dentry->num_links);

	if (dentry->unix_mode != 0) {
		tprintf(T("UNIX Data           = uid:%"PRIu32" gid:%"PRIu32" "
			  "mode:0%"PRIo32" rdev:0x%"PRIx32"\n"),
			dentry->unix_uid, dentry->unix_gid,
			dentry->unix_mode, dentry->unix_rdev);
	}

	if (!is_null_guid(dentry->object_id.object_id)) {
		print_guid(T("Object ID"), dentry->object_id.object_id);
		print_guid(T("Birth Volume ID"), dentry->object_id.birth_volume_id);
		print_guid(T("Birth Object ID"), dentry->object_id.birth_object_id);
		print_guid(T("Domain ID"), dentry->object_id.domain_id);
	}

	for (uint32_t i = 0; i <= dentry->num_named_streams; i++) {
		if (dentry->streams[i].stream_name) {
			tprintf(T("\tNamed data stream \"%"TS"\":\n"),
				dentry->streams[i].stream_name);
		} else if (dentry->attributes & WIMLIB_FILE_ATTRIBUTE_ENCRYPTED) {
			tprintf(T("\tRaw encrypted data stream:\n"));
		} else if (dentry->attributes & WIMLIB_FILE_ATTRIBUTE_REPARSE_POINT) {
			tprintf(T("\tReparse point stream:\n"));
		} else {
			tprintf(T("\tUnnamed data stream:\n"));
		}
		print_resource(&dentry->streams[i].resource, NULL);
	}
}

static int
print_dentry(const struct wimlib_dir_entry *dentry, void *_options)
{
	const struct print_dentry_options *options = _options;
	if (!options->detailed)
		print_dentry_full_path(dentry);
	else
		print_dentry_detailed(dentry);
	return 0;
}

/* Print the files contained in an image(s) in a WIM file. */
static int
imagex_dir(int argc, tchar **argv, int cmd)
{
	const tchar *wimfile;
	WIMStruct *wim = NULL;
	int image;
	int ret;
	const tchar *path = WIMLIB_WIM_ROOT_PATH;
	int c;
	struct print_dentry_options options = {
		.detailed = false,
	};
	int iterate_flags = WIMLIB_ITERATE_DIR_TREE_FLAG_RECURSIVE;

	STRING_LIST(refglobs);

	for_opt(c, dir_options) {
		switch (c) {
		case IMAGEX_PATH_OPTION:
			path = optarg;
			break;
		case IMAGEX_DETAILED_OPTION:
			options.detailed = true;
			break;
		case IMAGEX_ONE_FILE_ONLY_OPTION:
			iterate_flags &= ~WIMLIB_ITERATE_DIR_TREE_FLAG_RECURSIVE;
			break;
		case IMAGEX_REF_OPTION:
			ret = string_list_append(&refglobs, optarg);
			if (ret)
				goto out_free_refglobs;
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
	ret = wimlib_open_wim_with_progress(wimfile, 0, &wim,
					    imagex_progress_func, NULL);
	if (ret)
		goto out_free_refglobs;

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

	if (refglobs.num_strings) {
		ret = wim_reference_globs(wim, &refglobs, 0);
		if (ret)
			goto out_wimlib_free;
	}

	ret = wimlib_iterate_dir_tree(wim, image, path, iterate_flags,
				      print_dentry, &options);
	if (ret == WIMLIB_ERR_METADATA_NOT_FOUND) {
		struct wimlib_wim_info info;

		wimlib_get_wim_info(wim, &info);
		do_metadata_not_found_warning(wimfile, &info);
	}
out_wimlib_free:
	wimlib_free(wim);
out_free_refglobs:
	string_list_destroy(&refglobs);
	return ret;

out_usage:
	usage(CMD_DIR, stderr);
	ret = -1;
	goto out_free_refglobs;
}

/* Exports one, or all, images from a WIM file to a new WIM file or an existing
 * WIM file. */
static int
imagex_export(int argc, tchar **argv, int cmd)
{
	int c;
	int open_flags = 0;
	int export_flags = WIMLIB_EXPORT_FLAG_GIFT;
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
	STRING_LIST(refglobs);
	unsigned num_threads = 0;
	uint32_t chunk_size = UINT32_MAX;
	uint32_t solid_chunk_size = UINT32_MAX;
	int solid_ctype = WIMLIB_COMPRESSION_TYPE_INVALID;

	for_opt(c, export_options) {
		switch (c) {
		case IMAGEX_BOOT_OPTION:
			export_flags |= WIMLIB_EXPORT_FLAG_BOOT;
			break;
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			/* fall-through */
		case IMAGEX_INCLUDE_INTEGRITY_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_NOCHECK_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY;
			break;
		case IMAGEX_COMPRESS_OPTION:
			compression_type = get_compression_type(optarg, false);
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				goto out_err;
			break;
		case IMAGEX_RECOMPRESS_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_RECOMPRESS;
			break;
		case IMAGEX_SOLID_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_SOLID;
			break;
		case IMAGEX_NO_SOLID_SORT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_SOLID_SORT;
			break;
		case IMAGEX_CHUNK_SIZE_OPTION:
			chunk_size = parse_chunk_size(optarg);
			if (chunk_size == UINT32_MAX)
				goto out_err;
			break;
		case IMAGEX_SOLID_CHUNK_SIZE_OPTION:
			solid_chunk_size = parse_chunk_size(optarg);
			if (solid_chunk_size == UINT32_MAX)
				goto out_err;
			break;
		case IMAGEX_SOLID_COMPRESS_OPTION:
			solid_ctype = get_compression_type(optarg, true);
			if (solid_ctype == WIMLIB_COMPRESSION_TYPE_INVALID)
				goto out_err;
			break;
		case IMAGEX_REF_OPTION:
			ret = string_list_append(&refglobs, optarg);
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
		case IMAGEX_WIMBOOT_OPTION:
			export_flags |= WIMLIB_EXPORT_FLAG_WIMBOOT;
			break;
		case IMAGEX_UNSAFE_COMPACT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_UNSAFE_COMPACT;
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
	ret = wimlib_open_wim_with_progress(src_wimfile, open_flags, &src_wim,
					    imagex_progress_func, NULL);
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
		imagex_output_to_stderr();
		set_fd_to_binary_mode(dest_wim_fd);
	}
	errno = ENOENT;
	if (dest_wimfile != NULL && tstat(dest_wimfile, &stbuf) == 0) {
		wim_is_new = false;
		/* Destination file exists. */

		if (!S_ISREG(stbuf.st_mode) && !S_ISBLK(stbuf.st_mode)) {
			imagex_error(T("\"%"TS"\" is not a regular file "
				       "or block device"), dest_wimfile);
			ret = -1;
			goto out_free_src_wim;
		}
		ret = wimlib_open_wim_with_progress(dest_wimfile,
						    open_flags |
							WIMLIB_OPEN_FLAG_WRITE_ACCESS,
						    &dest_wim,
						    imagex_progress_func,
						    NULL);
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

		if (write_flags & WIMLIB_WRITE_FLAG_UNSAFE_COMPACT) {
			imagex_error(T("'--unsafe-compact' is only valid when "
				       "exporting to an existing WIM file!"));
			ret = -1;
			goto out_free_src_wim;
		}

		/* dest_wimfile is not an existing file, so create a new WIM. */

		if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID) {
			/* The user did not specify a compression type; default
			 * to that of the source WIM, unless --solid or
			 * --wimboot was specified.   */

			if (write_flags & WIMLIB_WRITE_FLAG_SOLID)
				compression_type = WIMLIB_COMPRESSION_TYPE_LZMS;
			else if (export_flags & WIMLIB_EXPORT_FLAG_WIMBOOT)
				compression_type = WIMLIB_COMPRESSION_TYPE_XPRESS;
			else
				compression_type = src_info.compression_type;
		}
		ret = wimlib_create_new_wim(compression_type, &dest_wim);
		if (ret)
			goto out_free_src_wim;

		wimlib_register_progress_function(dest_wim,
						  imagex_progress_func, NULL);

		if ((export_flags & WIMLIB_EXPORT_FLAG_WIMBOOT)
		    && compression_type == WIMLIB_COMPRESSION_TYPE_XPRESS)
		{
			/* For --wimboot export, use small XPRESS chunks.  */
			wimlib_set_output_chunk_size(dest_wim, 4096);
		} else if (compression_type == src_info.compression_type &&
			   chunk_size == UINT32_MAX)
		{
			/* Use same chunk size if compression type is the same.  */
			wimlib_set_output_chunk_size(dest_wim, src_info.chunk_size);
		}
	}

	if (chunk_size != UINT32_MAX) {
		/* Set destination chunk size.  */
		ret = wimlib_set_output_chunk_size(dest_wim, chunk_size);
		if (ret)
			goto out_free_dest_wim;
	}
	if (solid_ctype != WIMLIB_COMPRESSION_TYPE_INVALID) {
		ret = wimlib_set_output_pack_compression_type(dest_wim, solid_ctype);
		if (ret)
			goto out_free_dest_wim;
	}
	if (solid_chunk_size != UINT32_MAX) {
		ret = wimlib_set_output_pack_chunk_size(dest_wim, solid_chunk_size);
		if (ret)
			goto out_free_dest_wim;
	}

	image = wimlib_resolve_image(src_wim, src_image_num_or_name);
	ret = verify_image_exists(image, src_image_num_or_name, src_wimfile);
	if (ret)
		goto out_free_dest_wim;

	if (refglobs.num_strings) {
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
				  dest_desc, export_flags);
	if (ret) {
		if (ret == WIMLIB_ERR_RESOURCE_NOT_FOUND) {
			do_resource_not_found_warning(src_wimfile,
						      &src_info, &refglobs);
		} else if (ret == WIMLIB_ERR_METADATA_NOT_FOUND) {
			do_metadata_not_found_warning(src_wimfile, &src_info);
		}
		goto out_free_dest_wim;
	}

	if (!wim_is_new)
		ret = wimlib_overwrite(dest_wim, write_flags, num_threads);
	else if (dest_wimfile)
		ret = wimlib_write(dest_wim, dest_wimfile, WIMLIB_ALL_IMAGES,
				   write_flags, num_threads);
	else
		ret = wimlib_write_to_fd(dest_wim, dest_wim_fd,
					 WIMLIB_ALL_IMAGES, write_flags,
					 num_threads);
out_free_dest_wim:
	wimlib_free(dest_wim);
out_free_src_wim:
	wimlib_free(src_wim);
out_free_refglobs:
	string_list_destroy(&refglobs);
	return ret;

out_usage:
	usage(CMD_EXPORT, stderr);
out_err:
	ret = -1;
	goto out_free_refglobs;
}

/* Extract files or directories from a WIM image */
static int
imagex_extract(int argc, tchar **argv, int cmd)
{
	int c;
	int open_flags = 0;
	int image;
	WIMStruct *wim;
	int ret;
	const tchar *wimfile;
	const tchar *image_num_or_name;
	tchar *dest_dir = T(".");
	int extract_flags = WIMLIB_EXTRACT_FLAG_NORPFIX |
			    WIMLIB_EXTRACT_FLAG_GLOB_PATHS |
			    WIMLIB_EXTRACT_FLAG_STRICT_GLOB;
	int notlist_extract_flags = WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE;

	STRING_LIST(refglobs);

	tchar *root_path = WIMLIB_WIM_ROOT_PATH;

	for_opt(c, extract_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_VERBOSE_OPTION:
			/* No longer does anything.  */
			break;
		case IMAGEX_REF_OPTION:
			ret = string_list_append(&refglobs, optarg);
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
		case IMAGEX_NO_ATTRIBUTES_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES;
			break;
		case IMAGEX_DEST_DIR_OPTION:
			dest_dir = optarg;
			break;
		case IMAGEX_TO_STDOUT_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_TO_STDOUT;
			imagex_suppress_output();
			set_fd_to_binary_mode(STDOUT_FILENO);
			break;
		case IMAGEX_INCLUDE_INVALID_NAMES_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES;
			extract_flags |= WIMLIB_EXTRACT_FLAG_ALL_CASE_CONFLICTS;
			break;
		case IMAGEX_NO_GLOBS_OPTION:
			extract_flags &= ~WIMLIB_EXTRACT_FLAG_GLOB_PATHS;
			break;
		case IMAGEX_NULLGLOB_OPTION:
			extract_flags &= ~WIMLIB_EXTRACT_FLAG_STRICT_GLOB;
			break;
		case IMAGEX_PRESERVE_DIR_STRUCTURE_OPTION:
			notlist_extract_flags &= ~WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE;
			break;
		case IMAGEX_WIMBOOT_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_WIMBOOT;
			break;
		case IMAGEX_COMPACT_OPTION:
			ret = set_compact_mode(optarg, &extract_flags);
			if (ret)
				goto out_free_refglobs;
			break;
		case IMAGEX_RECOVER_DATA_OPTION:
			extract_flags |= WIMLIB_EXTRACT_FLAG_RECOVER_DATA;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2)
		goto out_usage;

	if (!(extract_flags & (WIMLIB_EXTRACT_FLAG_GLOB_PATHS |
			       WIMLIB_EXTRACT_FLAG_STRICT_GLOB)))
	{
		imagex_error(T("Can't combine --no-globs and --nullglob!"));
		goto out_err;
	}

	wimfile = argv[0];
	image_num_or_name = argv[1];

	argc -= 2;
	argv += 2;

	ret = wimlib_open_wim_with_progress(wimfile, open_flags, &wim,
					    imagex_progress_func, NULL);
	if (ret)
		goto out_free_refglobs;

	image = wimlib_resolve_image(wim, image_num_or_name);
	ret = verify_image_exists_and_is_single(image,
						image_num_or_name,
						wimfile);
	if (ret)
		goto out_wimlib_free;

	if (refglobs.num_strings) {
		ret = wim_reference_globs(wim, &refglobs, open_flags);
		if (ret)
			goto out_wimlib_free;
	}

	if (argc == 0) {
		argv = &root_path;
		argc = 1;
		extract_flags &= ~WIMLIB_EXTRACT_FLAG_GLOB_PATHS;
	}

	while (argc != 0 && ret == 0) {
		int num_paths;

		for (num_paths = 0;
		     num_paths < argc && argv[num_paths][0] != T('@');
		     num_paths++)
			;

		if (num_paths) {
			ret = wimlib_extract_paths(wim, image, dest_dir,
						   (const tchar **)argv,
						   num_paths,
						   extract_flags | notlist_extract_flags);
			argc -= num_paths;
			argv += num_paths;
		} else {
			const tchar *listfile = argv[0] + 1;

			if (!tstrcmp(listfile, T("-"))) {
				tputs(T("Reading pathlist file from standard input..."));
				listfile = NULL;
			}

			ret = wimlib_extract_pathlist(wim, image, dest_dir,
						      listfile, extract_flags);
			argc--;
			argv++;
		}
	}

	if (ret == 0) {
		imagex_printf(T("Done extracting files.\n"));
	} else if (ret == WIMLIB_ERR_PATH_DOES_NOT_EXIST) {
		if ((extract_flags & (WIMLIB_EXTRACT_FLAG_STRICT_GLOB |
				      WIMLIB_EXTRACT_FLAG_GLOB_PATHS))
			== (WIMLIB_EXTRACT_FLAG_STRICT_GLOB |
			    WIMLIB_EXTRACT_FLAG_GLOB_PATHS))
		{
			tfprintf(stderr,
				 T("Note: You can use the '--nullglob' "
				   "option to ignore missing files.\n"));
		}
		tfprintf(stderr, T("Note: You can use `%"TS"' to see what "
				   "files and directories\n"
				   "      are in the WIM image.\n"),
				get_cmd_string(CMD_DIR, false));
	} else if (ret == WIMLIB_ERR_RESOURCE_NOT_FOUND) {
		struct wimlib_wim_info info;

		wimlib_get_wim_info(wim, &info);
		do_resource_not_found_warning(wimfile, &info, &refglobs);
	} else if (ret == WIMLIB_ERR_METADATA_NOT_FOUND) {
		struct wimlib_wim_info info;

		wimlib_get_wim_info(wim, &info);
		do_metadata_not_found_warning(wimfile, &info);
	}
out_wimlib_free:
	wimlib_free(wim);
out_free_refglobs:
	string_list_destroy(&refglobs);
	return ret;

out_usage:
	usage(CMD_EXTRACT, stderr);
out_err:
	ret = -1;
	goto out_free_refglobs;
}

/* Prints information about a WIM file; also can mark an image as bootable,
 * change the name of an image, or change the description of an image. */
static int
imagex_info(int argc, tchar **argv, int cmd)
{
	int c;
	bool boot         = false;
	bool header       = false;
	bool blobs        = false;
	bool xml          = false;
	bool short_header = true;
	const tchar *xml_out_file = NULL;
	const tchar *wimfile;
	const tchar *image_num_or_name;
	STRING_LIST(image_properties);
	WIMStruct *wim;
	int image;
	int ret;
	int open_flags = 0;
	int write_flags = 0;
	struct wimlib_wim_info info;

	for_opt(c, info_options) {
		switch (c) {
		case IMAGEX_BOOT_OPTION:
			boot = true;
			break;
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			/* fall-through */
		case IMAGEX_INCLUDE_INTEGRITY_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_NOCHECK_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY;
			break;
		case IMAGEX_HEADER_OPTION:
			header = true;
			short_header = false;
			break;
		case IMAGEX_BLOBS_OPTION:
			blobs = true;
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
		case IMAGEX_IMAGE_PROPERTY_OPTION:
			ret = append_image_property_argument(&image_properties);
			if (ret)
				goto out;
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

	if (argc >= 3) {
		/* NEW_NAME */
		tchar *p = alloca((5 + tstrlen(argv[2]) + 1) * sizeof(tchar));
		tsprintf(p, T("NAME=%"TS), argv[2]);
		ret = string_list_append(&image_properties, p);
		if (ret)
			goto out;
	}

	if (argc >= 4) {
		/* NEW_DESC */
		tchar *p = alloca((12 + tstrlen(argv[3]) + 1) * sizeof(tchar));
		tsprintf(p, T("DESCRIPTION=%"TS), argv[3]);
		ret = string_list_append(&image_properties, p);
		if (ret)
			goto out;
	}

	ret = wimlib_open_wim_with_progress(wimfile, open_flags, &wim,
					    imagex_progress_func, NULL);
	if (ret)
		goto out;

	wimlib_get_wim_info(wim, &info);

	image = wimlib_resolve_image(wim, image_num_or_name);
	ret = WIMLIB_ERR_INVALID_IMAGE;
	if (image == WIMLIB_NO_IMAGE && tstrcmp(image_num_or_name, T("0"))) {
		verify_image_exists(image, image_num_or_name, wimfile);
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
		if (image_properties.num_strings) {
			imagex_error(T("Can't change image properties without "
				       "specifying a specific image in a "
				       "multi-image WIM"));
			goto out_wimlib_free;
		}
	}

	/* Operations that print information are separated from operations that
	 * recreate the WIM file. */
	if (!image_properties.num_strings && !boot) {

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

		if (blobs) {
			if (info.total_parts != 1) {
				tfprintf(stderr, T("Warning: Only showing the blobs "
						   "for part %d of a %d-part WIM.\n"),
					 info.part_number, info.total_parts);
			}
			print_blobs(wim);
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

		ret = 0;
	} else {
		/* Modification operations */
		bool any_property_changes;

		if (image == WIMLIB_ALL_IMAGES)
			image = 1;

		if (image == WIMLIB_NO_IMAGE && image_properties.num_strings) {
			imagex_error(T("Cannot change image properties "
				       "when using image 0"));
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

		ret = apply_image_properties(&image_properties, wim, image,
					     &any_property_changes);
		if (ret)
			goto out_wimlib_free;

		/* Only call wimlib_overwrite() if something actually needs to
		 * be changed.  */
		if (boot || any_property_changes ||
		    ((write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) &&
		     !info.has_integrity_table) ||
		    ((write_flags & WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY) &&
		     info.has_integrity_table))
		{
			ret = wimlib_overwrite(wim, write_flags, 1);
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
	string_list_destroy(&image_properties);
	return ret;

out_usage:
	usage(CMD_INFO, stderr);
	ret = -1;
	goto out;
}

/* Join split WIMs into one part WIM */
static int
imagex_join(int argc, tchar **argv, int cmd)
{
	int c;
	int swm_open_flags = 0;
	int wim_write_flags = 0;
	const tchar *output_path;
	int ret;

	for_opt(c, join_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			swm_open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			/* fall-through */
		case IMAGEX_INCLUDE_INTEGRITY_OPTION:
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
	ret = wimlib_join_with_progress((const tchar * const *)++argv,
					--argc,
					output_path,
					swm_open_flags,
					wim_write_flags,
					imagex_progress_func,
					NULL);
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
	int open_flags = 0;
	const tchar *staging_dir = NULL;
	const tchar *wimfile;
	const tchar *dir;
	WIMStruct *wim;
	struct wimlib_wim_info info;
	int image;
	int ret;

	STRING_LIST(refglobs);

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
			ret = string_list_append(&refglobs, optarg);
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

	ret = wimlib_open_wim_with_progress(wimfile, open_flags, &wim,
					    imagex_progress_func, NULL);
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

	if (refglobs.num_strings) {
		ret = wim_reference_globs(wim, &refglobs, open_flags);
		if (ret)
			goto out_free_wim;
	}

	ret = wimlib_mount_image(wim, image, dir, mount_flags, staging_dir);
	if (ret) {
		if (ret == WIMLIB_ERR_METADATA_NOT_FOUND) {
			do_metadata_not_found_warning(wimfile, &info);
		} else {
			imagex_error(T("Failed to mount image %d from \"%"TS"\" "
				       "on \"%"TS"\""),
				     image, wimfile, dir);
		}
	}
out_free_wim:
	wimlib_free(wim);
out_free_refglobs:
	string_list_destroy(&refglobs);
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
	int compression_type = WIMLIB_COMPRESSION_TYPE_INVALID;
	uint32_t chunk_size = UINT32_MAX;
	uint32_t solid_chunk_size = UINT32_MAX;
	int solid_ctype = WIMLIB_COMPRESSION_TYPE_INVALID;
	int ret;
	WIMStruct *wim;
	struct wimlib_wim_info info;
	const tchar *wimfile;
	off_t old_size;
	off_t new_size;
	unsigned num_threads = 0;

	for_opt(c, optimize_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			/* fall-through */
		case IMAGEX_INCLUDE_INTEGRITY_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case IMAGEX_NOCHECK_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY;
			break;
		case IMAGEX_COMPRESS_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_RECOMPRESS;
			compression_type = get_compression_type(optarg, false);
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				goto out_err;
			break;
		case IMAGEX_RECOMPRESS_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_RECOMPRESS;
			break;
		case IMAGEX_CHUNK_SIZE_OPTION:
			chunk_size = parse_chunk_size(optarg);
			if (chunk_size == UINT32_MAX)
				goto out_err;
			break;
		case IMAGEX_SOLID_CHUNK_SIZE_OPTION:
			solid_chunk_size = parse_chunk_size(optarg);
			if (solid_chunk_size == UINT32_MAX)
				goto out_err;
			break;
		case IMAGEX_SOLID_COMPRESS_OPTION:
			solid_ctype = get_compression_type(optarg, true);
			if (solid_ctype == WIMLIB_COMPRESSION_TYPE_INVALID)
				goto out_err;
			break;
		case IMAGEX_SOLID_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_SOLID;
			write_flags |= WIMLIB_WRITE_FLAG_RECOMPRESS;
			/* Reset the non-solid compression type to LZMS. */
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				compression_type = WIMLIB_COMPRESSION_TYPE_LZMS;
			break;
		case IMAGEX_NO_SOLID_SORT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_NO_SOLID_SORT;
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
		case IMAGEX_UNSAFE_COMPACT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_UNSAFE_COMPACT;
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

	ret = wimlib_open_wim_with_progress(wimfile, open_flags, &wim,
					    imagex_progress_func, NULL);
	if (ret)
		goto out;

	wimlib_get_wim_info(wim, &info);

	if (compression_type != WIMLIB_COMPRESSION_TYPE_INVALID &&
	    compression_type != info.compression_type) {
		/* Change compression type.  */
		ret = wimlib_set_output_compression_type(wim, compression_type);
		if (ret)
			goto out_wimlib_free;

		/* Reset the chunk size. */
		if (chunk_size == UINT32_MAX)
			chunk_size = 0;
	}

	if (chunk_size != UINT32_MAX) {
		/* Change chunk size.  */
		ret = wimlib_set_output_chunk_size(wim, chunk_size);
		if (ret)
			goto out_wimlib_free;
	}
	if (solid_ctype != WIMLIB_COMPRESSION_TYPE_INVALID) {
		ret = wimlib_set_output_pack_compression_type(wim, solid_ctype);
		if (ret)
			goto out_wimlib_free;
	}
	if (solid_chunk_size != UINT32_MAX) {
		ret = wimlib_set_output_pack_chunk_size(wim, solid_chunk_size);
		if (ret)
			goto out_wimlib_free;
	}

	old_size = file_get_size(wimfile);
	tprintf(T("\"%"TS"\" original size: "), wimfile);
	if (old_size == -1)
		tputs(T("Unknown"));
	else
		tprintf(T("%"PRIu64" KiB\n"), old_size >> 10);

	ret = wimlib_overwrite(wim, write_flags, num_threads);
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
	uint64_t part_size;
	tchar *tmp;
	int ret;
	WIMStruct *wim;

	for_opt(c, split_options) {
		switch (c) {
		case IMAGEX_CHECK_OPTION:
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			/* fall-through */
		case IMAGEX_INCLUDE_INTEGRITY_OPTION:
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
	ret = wimlib_open_wim_with_progress(argv[0], open_flags, &wim,
					    imagex_progress_func, NULL);
	if (ret)
		goto out;

	ret = wimlib_split(wim, argv[1], part_size, write_flags);
	if (ret == 0)
		tprintf(T("\nFinished splitting \"%"TS"\"\n"), argv[0]);
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
		case IMAGEX_FORCE_OPTION:
			/* Now, unmount is lazy by default.  However, committing
			 * the image will fail with
			 * WIMLIB_ERR_MOUNTED_IMAGE_IS_BUSY if there are open
			 * file descriptors on the WIM image.  The
			 * WIMLIB_UNMOUNT_FLAG_FORCE option forces these file
			 * descriptors to be closed.  */
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_FORCE;
			break;
		case IMAGEX_NEW_IMAGE_OPTION:
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_NEW_IMAGE;
			break;
		default:
			goto out_usage;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		goto out_usage;

	if (unmount_flags & WIMLIB_UNMOUNT_FLAG_NEW_IMAGE) {
		if (!(unmount_flags & WIMLIB_UNMOUNT_FLAG_COMMIT)) {
			imagex_error(T("--new-image is meaningless "
				       "without --commit also specified!"));
			goto out_err;
		}
	}

	ret = wimlib_unmount_image_with_progress(argv[0], unmount_flags,
						 imagex_progress_func, NULL);
	if (ret) {
		imagex_error(T("Failed to unmount \"%"TS"\""), argv[0]);
		if (ret == WIMLIB_ERR_MOUNTED_IMAGE_IS_BUSY) {
			imagex_printf(T(
				"\tNote: Use --commit --force to force changes "
					"to be committed, regardless\n"
				"\t      of open files.\n"));
		}
	}
out:
	return ret;

out_usage:
	usage(CMD_UNMOUNT, stderr);
out_err:
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
	int default_add_flags = WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE |
				WIMLIB_ADD_FLAG_VERBOSE |
				WIMLIB_ADD_FLAG_WINCONFIG;
	int default_delete_flags = 0;
	unsigned num_threads = 0;
	STRING_LIST(refglobs);
	int c;
	tchar *cmd_file_contents;
	size_t cmd_file_nchars;
	struct wimlib_update_command *cmds;
	size_t num_cmds;
	tchar *command_str = NULL;
	tchar *config_file = NULL;
	tchar *wimboot_config = NULL;

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
			/* fall-through */
		case IMAGEX_INCLUDE_INTEGRITY_OPTION:
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
		case IMAGEX_WIMBOOT_CONFIG_OPTION:
			wimboot_config = optarg;
			break;
		case IMAGEX_REF_OPTION:
			ret = string_list_append(&refglobs, optarg);
			if (ret)
				goto out;
			/* assume delta WIM */
			write_flags |= WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS;
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
			/* No longer does anything.  */
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
		case IMAGEX_NO_REPLACE_OPTION:
			default_add_flags |= WIMLIB_ADD_FLAG_NO_REPLACE;
			break;
		case IMAGEX_UNSAFE_COMPACT_OPTION:
			write_flags |= WIMLIB_WRITE_FLAG_UNSAFE_COMPACT;
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

	ret = wimlib_open_wim_with_progress(wimfile, open_flags, &wim,
					    imagex_progress_func, NULL);
	if (ret)
		goto out;

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

	ret = wim_reference_globs(wim, &refglobs, open_flags);
	if (ret)
		goto out_wimlib_free;

	/* Read update commands from standard input, or the command string if
	 * specified.  */
	if (command_str) {
		cmd_file_contents = NULL;
		cmds = parse_update_command_file(&command_str, tstrlen(command_str),
						 &num_cmds);
		if (!cmds) {
			ret = -1;
			goto out_free_cmd_file_contents;
		}
	} else if (!wimboot_config) {
		if (isatty(STDIN_FILENO)) {
			tputs(T("Reading update commands from standard input..."));
			recommend_man_page(CMD_UPDATE, stdout);
		}
		if (wimlib_load_text_file(NULL, &cmd_file_contents,
					  &cmd_file_nchars) != 0) {
			ret = -1;
			goto out_wimlib_free;
		}

		/* Parse the update commands */
		cmds = parse_update_command_file(&cmd_file_contents, cmd_file_nchars,
						 &num_cmds);
		if (!cmds) {
			ret = -1;
			goto out_free_cmd_file_contents;
		}
	} else {
		cmd_file_contents = NULL;
		cmds = NULL;
		num_cmds = 0;
	}

	/* Set default flags and capture config on the update commands */
	for (size_t i = 0; i < num_cmds; i++) {
		switch (cmds[i].op) {
		case WIMLIB_UPDATE_OP_ADD:
			cmds[i].add.add_flags |= default_add_flags;
			cmds[i].add.config_file = config_file;
			break;
		case WIMLIB_UPDATE_OP_DELETE:
			cmds[i].delete_.delete_flags |= default_delete_flags;
			break;
		default:
			break;
		}
	}

	/* Execute the update commands */
	ret = wimlib_update_image(wim, image, cmds, num_cmds, update_flags);
	if (ret)
		goto out_free_cmds;

	if (wimboot_config) {
		/* --wimboot-config=FILE is short for an
		 * "add FILE /Windows/System32/WimBootCompress.ini" command.
		 */
		struct wimlib_update_command cmd;

		cmd.op = WIMLIB_UPDATE_OP_ADD;
		cmd.add.fs_source_path = wimboot_config;
		cmd.add.wim_target_path = T("/Windows/System32/WimBootCompress.ini");
		cmd.add.config_file = NULL;
		cmd.add.add_flags = 0;

		ret = wimlib_update_image(wim, image, &cmd, 1, update_flags);
		if (ret)
			goto out_free_cmds;
	}

	/* Overwrite the updated WIM */
	ret = wimlib_overwrite(wim, write_flags, num_threads);
out_free_cmds:
	free(cmds);
out_free_cmd_file_contents:
	free(cmd_file_contents);
out_wimlib_free:
	wimlib_free(wim);
out:
	free(command_str);
	string_list_destroy(&refglobs);
	return ret;

out_usage:
	usage(CMD_UPDATE, stderr);
out_err:
	ret = -1;
	goto out;
}

/* Verify a WIM file.  */
static int
imagex_verify(int argc, tchar **argv, int cmd)
{
	int ret;
	const tchar *wimfile;
	WIMStruct *wim;
	int open_flags = WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
	int verify_flags = 0;
	STRING_LIST(refglobs);
	int c;

	for_opt(c, verify_options) {
		switch (c) {
		case IMAGEX_REF_OPTION:
			ret = string_list_append(&refglobs, optarg);
			if (ret)
				goto out_free_refglobs;
			break;
		case IMAGEX_NOCHECK_OPTION:
			open_flags &= ~WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		default:
			goto out_usage;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1) {
		if (argc == 0)
			imagex_error(T("Must specify a WIM file!"));
		else
			imagex_error(T("At most one WIM file can be specified!"));
		goto out_usage;
	}

	wimfile = argv[0];

	ret = wimlib_open_wim_with_progress(wimfile,
					    open_flags,
					    &wim,
					    imagex_progress_func,
					    NULL);
	if (ret)
		goto out_free_refglobs;

	ret = wim_reference_globs(wim, &refglobs, open_flags);
	if (ret)
		goto out_wimlib_free;

	ret = wimlib_verify_wim(wim, verify_flags);
	if (ret) {
		tputc(T('\n'), stderr);
		imagex_error(T("\"%"TS"\" failed verification!"),
			     wimfile);
		if (ret == WIMLIB_ERR_RESOURCE_NOT_FOUND &&
		    refglobs.num_strings == 0)
		{
			imagex_printf(T("Note: if this WIM file is not standalone, "
					"use the --ref option to specify the other parts.\n"));
		}
	} else {
		imagex_printf(T("\n\"%"TS"\" was successfully verified.\n"),
			      wimfile);
	}

out_wimlib_free:
	wimlib_free(wim);
out_free_refglobs:
	string_list_destroy(&refglobs);
	return ret;

out_usage:
	usage(CMD_VERIFY, stderr);
	ret = -1;
	goto out_free_refglobs;
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
	[CMD_VERIFY]   = {T("verify"),   imagex_verify},
};

#ifdef _WIN32

   /* Can be a directory or source list file.  But source list file is probably
    * a rare use case, so just say directory.  */
#  define SOURCE_STR T("DIRECTORY")

   /* Can only be a directory  */
#  define TARGET_STR T("DIRECTORY")

#else
   /* Can be a directory, NTFS volume, or source list file. */
#  define SOURCE_STR T("SOURCE")

   /* Can be a directory or NTFS volume.  */
#  define TARGET_STR T("TARGET")

#endif

static const tchar * const usage_strings[] = {
[CMD_APPEND] =
T(
"    %"TS" " SOURCE_STR " WIMFILE [IMAGE_NAME [IMAGE_DESC]]\n"
"                    [--boot] [--check] [--nocheck] [--config=FILE]\n"
"                    [--threads=NUM_THREADS] [--no-acls] [--strict-acls]\n"
"                    [--rpfix] [--norpfix] [--update-of=[WIMFILE:]IMAGE]\n"
"                    [--delta-from=WIMFILE] [--wimboot] [--unix-data]\n"
"                    [--dereference] [--snapshot] [--create]\n"
),
[CMD_APPLY] =
T(
"    %"TS" WIMFILE [IMAGE] " TARGET_STR "\n"
"                    [--check] [--ref=\"GLOB\"] [--no-acls] [--strict-acls]\n"
"                    [--no-attributes] [--rpfix] [--norpfix]\n"
"                    [--include-invalid-names] [--wimboot] [--unix-data]\n"
"                    [--compact=FORMAT] [--recover-data]\n"
),
[CMD_CAPTURE] =
T(
"    %"TS" " SOURCE_STR " WIMFILE [IMAGE_NAME [IMAGE_DESC]]\n"
"                    [--compress=TYPE] [--boot] [--check] [--nocheck]\n"
"                    [--config=FILE] [--threads=NUM_THREADS]\n"
"                    [--no-acls] [--strict-acls] [--rpfix] [--norpfix]\n"
"                    [--update-of=[WIMFILE:]IMAGE] [--delta-from=WIMFILE]\n"
"                    [--wimboot] [--unix-data] [--dereference] [--solid]\n"
"                    [--snapshot]\n"
),
[CMD_DELETE] =
T(
"    %"TS" WIMFILE IMAGE [--check] [--soft]\n"
),
[CMD_DIR] =
T(
"    %"TS" WIMFILE [IMAGE] [--path=PATH] [--detailed]\n"
),
[CMD_EXPORT] =
T(
"    %"TS" SRC_WIMFILE SRC_IMAGE DEST_WIMFILE\n"
"                        [DEST_IMAGE_NAME [DEST_IMAGE_DESC]]\n"
"                    [--boot] [--check] [--nocheck] [--compress=TYPE]\n"
"                    [--ref=\"GLOB\"] [--threads=NUM_THREADS] [--rebuild]\n"
"                    [--wimboot] [--solid]\n"
),
[CMD_EXTRACT] =
T(
"    %"TS" WIMFILE IMAGE [(PATH | @LISTFILE)...]\n"
"                    [--check] [--ref=\"GLOB\"] [--dest-dir=CMD_DIR]\n"
"                    [--to-stdout] [--no-acls] [--strict-acls]\n"
"                    [--no-attributes] [--include-invalid-names] [--no-globs]\n"
"                    [--nullglob] [--preserve-dir-structure] [--recover-data]\n"
),
[CMD_INFO] =
T(
"    %"TS" WIMFILE [IMAGE [NEW_NAME [NEW_DESC]]]\n"
"                    [--boot] [--check] [--nocheck] [--xml]\n"
"                    [--extract-xml FILE] [--header] [--blobs]\n"
"                    [--image-property NAME=VALUE]\n"
),
[CMD_JOIN] =
T(
"    %"TS" OUT_WIMFILE SPLIT_WIM_PART... [--check]\n"
),
#if WIM_MOUNTING_SUPPORTED
[CMD_MOUNT] =
T(
"    %"TS" WIMFILE [IMAGE] DIRECTORY\n"
"                    [--check] [--streams-interface=INTERFACE]\n"
"                    [--ref=\"GLOB\"] [--allow-other] [--unix-data]\n"
),
[CMD_MOUNTRW] =
T(
"    %"TS" WIMFILE [IMAGE] DIRECTORY\n"
"                    [--check] [--streams-interface=INTERFACE]\n"
"                    [--staging-dir=CMD_DIR] [--allow-other] [--unix-data]\n"
),
#endif
[CMD_OPTIMIZE] =
T(
"    %"TS" WIMFILE\n"
"                    [--recompress] [--compress=TYPE] [--threads=NUM_THREADS]\n"
"                    [--check] [--nocheck] [--solid]\n"
"\n"
),
[CMD_SPLIT] =
T(
"    %"TS" WIMFILE SPLIT_WIM_PART_1 PART_SIZE_MB [--check]\n"
),
#if WIM_MOUNTING_SUPPORTED
[CMD_UNMOUNT] =
T(
"    %"TS" DIRECTORY\n"
"                    [--commit] [--force] [--new-image] [--check] [--rebuild]\n"
),
#endif
[CMD_UPDATE] =
T(
"    %"TS" WIMFILE [IMAGE]\n"
"                    [--check] [--rebuild] [--threads=NUM_THREADS]\n"
"                    [DEFAULT_ADD_OPTIONS] [DEFAULT_DELETE_OPTIONS]\n"
"                    [--command=STRING] [--wimboot-config=FILE]\n"
"                    [< CMDFILE]\n"
),
[CMD_VERIFY] =
T(
"    %"TS" WIMFILE [--ref=\"GLOB\"]\n"
),
};

static const tchar *invocation_name;
static int invocation_cmd = CMD_NONE;

static const tchar *get_cmd_string(int cmd, bool only_short_form)
{
	static tchar buf[50];

	if (cmd == CMD_NONE)
		return T("wimlib-imagex");

	if (only_short_form || invocation_cmd != CMD_NONE) {
		tsprintf(buf, T("wim%"TS), imagex_commands[cmd].name);
	} else {
		tsprintf(buf, T("%"TS" %"TS), invocation_name,
			 imagex_commands[cmd].name);
	}
	return buf;
}

static void
version(void)
{
	static const tchar * const fmt =
	T(
"wimlib-imagex " PACKAGE_VERSION " (using wimlib %"TS")\n"
"Copyright 2012-2023 Eric Biggers\n"
"License GPLv3+; GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n"
"This is free software: you are free to change and redistribute it.\n"
"There is NO WARRANTY, to the extent permitted by law.\n"
"\n"
"Report bugs to "PACKAGE_BUGREPORT".\n"
	);
	tfprintf(stdout, fmt, wimlib_get_version_string());
}

static void
do_common_options(int *argc_p, tchar **argv, int cmd)
{
	int argc = *argc_p;
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
			} else if (!tstrcmp(p, T("quiet"))) {
				imagex_suppress_output();
				memmove(&argv[i], &argv[i + 1],
					(argc - i) * sizeof(argv[i]));
				argc--;
				i--;
			} else if (!*p) /* reached "--", no more options */
				break;
		}
	}

	*argc_p = argc;
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
#ifdef _WIN32
	format_str = T("Some uncommon options are not listed;\n"
		       "See %"TS".pdf in the doc directory for more details.\n");
#else
	format_str = T("Some uncommon options are not listed; see `man %"TS"' for more details.\n");
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
	static const tchar * const extra =
	T(
"    %"TS" --help\n"
"    %"TS" --version\n"
"\n"
	);
	tfprintf(fp, extra, invocation_name, invocation_name);
	tfprintf(fp,
		 T("IMAGE can be the 1-based index or name of an image in the WIM file.\n"
		   "For some commands IMAGE is optional if the WIM file only contains one image.\n"
		   "For some commands IMAGE may be \"all\".\n"
		   "\n"));
	recommend_man_page(CMD_NONE, fp);
}

#ifdef _WIN32
int wmain(int argc, wchar_t **argv);
#define main wmain
#endif

/* Entry point for wimlib's ImageX implementation.  On UNIX the command
 * arguments will just be 'char' strings (ideally UTF-8 encoded, but could be
 * something else), while on Windows the command arguments will be UTF-16LE
 * encoded 'wchar_t' strings. */
int
main(int argc, tchar **argv)
{
	int ret;
	int init_flags = 0;
	int cmd;

	imagex_info_file = stdout;
	invocation_name = tbasename(argv[0]);

	{
		tchar *igcase = tgetenv(T("WIMLIB_IMAGEX_IGNORE_CASE"));
		if (igcase != NULL) {
			if (!tstrcmp(igcase, T("no")) ||
			    !tstrcmp(igcase, T("0")))
				init_flags |= WIMLIB_INIT_FLAG_DEFAULT_CASE_SENSITIVE;
			else if (!tstrcmp(igcase, T("yes")) ||
				 !tstrcmp(igcase, T("1")))
				init_flags |= WIMLIB_INIT_FLAG_DEFAULT_CASE_INSENSITIVE;
			else {
				fprintf(stderr,
					"WARNING: Ignoring unknown setting of "
					"WIMLIB_IMAGEX_IGNORE_CASE\n");
			}
		}
	}

	/* Allow being invoked as wimCOMMAND (e.g. wimapply).  */
	cmd = CMD_NONE;
	if (!tstrncmp(invocation_name, T("wim"), 3) &&
	    tstrcmp(invocation_name, T("wimlib-imagex"))) {
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

	/* Handle common options.  May exit early (for --help or --version).  */
	do_common_options(&argc, argv, cmd);

	/* Bail if a valid command was not specified.  */
	if (cmd == CMD_NONE) {
		imagex_error(T("Unrecognized command: `%"TS"'\n"), argv[1]);
		usage_all(stderr);
		exit(2);
	}

	/* Enable warning and error messages in wimlib to be more user-friendly.
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
