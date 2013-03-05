/*
 * imagex.c
 *
 * Use wimlib to create, modify, extract, mount, unmount, or display information
 * about a WIM file
 */

/*
 * Copyright (C) 2012 Eric Biggers
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

#include "config.h"

#include "wimlib.h"

#include <errno.h>
#include <getopt.h>
#include <glob.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

#define for_opt(c, opts) while ((c = getopt_long_only(argc, (char**)argv, "", \
				opts, NULL)) != -1)

enum imagex_op_type {
	APPEND,
	APPLY,
	CAPTURE,
	DELETE,
	DIR,
	EXPORT,
	INFO,
	JOIN,
	MOUNT,
	MOUNTRW,
	OPTIMIZE,
	SPLIT,
	UNMOUNT,
};

static void usage(int cmd_type);
static void usage_all();

static const char *usage_strings[] = {
[APPEND] =
"imagex append (DIRECTORY | NTFS_VOLUME) WIMFILE [IMAGE_NAME]\n"
"                     [DESCRIPTION] [--boot] [--check] [--flags EDITION_ID]\n"
"                     [--verbose] [--dereference] [--config=FILE]\n"
"                     [--threads=NUM_THREADS] [--rebuild] [--unix-data]\n",
[APPLY] =
"imagex apply WIMFILE [IMAGE_NUM | IMAGE_NAME | all]\n"
"                    (DIRECTORY | NTFS_VOLUME) [--check] [--hardlink]\n"
"                    [--symlink] [--verbose] [--ref=\"GLOB\"] [--unix-data]\n",
[CAPTURE] =
"imagex capture (DIRECTORY | NTFS_VOLUME) WIMFILE [IMAGE_NAME]\n"
"                      [DESCRIPTION] [--boot] [--check] [--compress=TYPE]\n"
"                      [--flags EDITION_ID] [--verbose] [--dereference]\n"
"                      [--config=FILE] [--threads=NUM_THREADS] [--unix-data]\n",
[DELETE] =
"imagex delete WIMFILE (IMAGE_NUM | IMAGE_NAME | all) [--check] [--soft]\n",
[DIR] =
"imagex dir WIMFILE (IMAGE_NUM | IMAGE_NAME | all)\n",
[EXPORT] =
"imagex export SRC_WIMFILE (SRC_IMAGE_NUM | SRC_IMAGE_NAME | all ) \n"
"              DEST_WIMFILE [DEST_IMAGE_NAME] [DEST_IMAGE_DESCRIPTION]\n"
"              [--boot] [--check] [--compress=TYPE] [--ref=\"GLOB\"]\n"
"              [--threads=NUM_THREADS] [--rebuild]\n",
[INFO] =
"imagex info WIMFILE [IMAGE_NUM | IMAGE_NAME] [NEW_NAME]\n"
"                   [NEW_DESC] [--boot] [--check] [--header] [--lookup-table]\n"
"                   [--xml] [--extract-xml FILE] [--metadata]\n",
[JOIN] =
"imagex join [--check] WIMFILE SPLIT_WIM...\n",
[MOUNT] =
"imagex mount WIMFILE (IMAGE_NUM | IMAGE_NAME) DIRECTORY\n"
"                    [--check] [--debug] [--streams-interface=INTERFACE]\n"
"                    [--ref=\"GLOB\"] [--unix-data] [--allow-other]\n",
[MOUNTRW] =
"imagex mountrw WIMFILE [IMAGE_NUM | IMAGE_NAME] DIRECTORY\n"
"                      [--check] [--debug] [--streams-interface=INTERFACE]\n"
"                      [--staging-dir=DIR] [--unix-data] [--allow-other]\n",
[OPTIMIZE] =
"imagex optimize WIMFILE [--check] [--recompress] [--compress=TYPE]\n",
[SPLIT] =
"imagex split WIMFILE SPLIT_WIMFILE PART_SIZE_MB [--check]\n",
[UNMOUNT] =
"imagex unmount DIRECTORY [--commit] [--check] [--rebuild]\n",
};

static const struct option common_options[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static const struct option apply_options[] = {
	{"check",     no_argument,       NULL, 'c'},
	{"hardlink",  no_argument,       NULL, 'h'},
	{"symlink",   no_argument,       NULL, 's'},
	{"verbose",   no_argument,       NULL, 'v'},
	{"ref",       required_argument, NULL, 'r'},
	{"unix-data", no_argument,       NULL, 'U'},
	{NULL, 0, NULL, 0},
};
static const struct option capture_or_append_options[] = {
	{"boot",	no_argument,       NULL, 'b'},
	{"check",	no_argument,       NULL, 'c'},
	{"compress",	required_argument, NULL, 'x'},
	{"config",	required_argument, NULL, 'C'},
	{"dereference", no_argument,	   NULL, 'L'},
	{"flags",	required_argument, NULL, 'f'},
	{"verbose",	no_argument,       NULL, 'v'},
	{"threads",     required_argument, NULL, 't'},
	{"rebuild",     no_argument,       NULL, 'R'},
	{"unix-data",   no_argument,       NULL, 'U'},
	{NULL, 0, NULL, 0},
};
static const struct option delete_options[] = {
	{"check", no_argument, NULL, 'c'},
	{"soft",  no_argument, NULL, 's'},
	{NULL, 0, NULL, 0},
};

static const struct option export_options[] = {
	{"boot",       no_argument,	  NULL, 'b'},
	{"check",      no_argument,	  NULL, 'c'},
	{"compress",   required_argument, NULL, 'x'},
	{"ref",        required_argument, NULL, 'r'},
	{"threads",    required_argument, NULL, 't'},
	{"rebuild",    no_argument,       NULL, 'R'},
	{NULL, 0, NULL, 0},
};

static const struct option info_options[] = {
	{"boot",         no_argument, NULL, 'b'},
	{"check",        no_argument, NULL, 'c'},
	{"extract-xml",  required_argument, NULL, 'X'},
	{"header",       no_argument, NULL, 'h'},
	{"lookup-table", no_argument, NULL, 'l'},
	{"metadata",     no_argument, NULL, 'm'},
	{"xml",          no_argument, NULL, 'x'},
	{NULL, 0, NULL, 0},
};

static const struct option join_options[] = {
	{"check", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static const struct option mount_options[] = {
	{"check",	      no_argument,	 NULL, 'c'},
	{"debug",	      no_argument,	 NULL, 'd'},
	{"streams-interface", required_argument, NULL, 's'},
	{"ref",               required_argument, NULL, 'r'},
	{"staging-dir",       required_argument, NULL, 'D'},
	{"unix-data",         no_argument,       NULL, 'U'},
	{"allow-other",       no_argument,       NULL, 'A'},
	{NULL, 0, NULL, 0},
};

static const struct option optimize_options[] = {
	{"check",      no_argument, NULL, 'c'},
	{"recompress", no_argument, NULL, 'r'},
	{NULL, 0, NULL, 0},
};

static const struct option split_options[] = {
	{"check", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static const struct option unmount_options[] = {
	{"commit",  no_argument, NULL, 'c'},
	{"check",   no_argument, NULL, 'C'},
	{"rebuild", no_argument, NULL, 'R'},
	{NULL, 0, NULL, 0},
};



/* Print formatted error message to stderr. */
static void imagex_error(const char *format, ...)
{
	va_list va;
	va_start(va, format);
	fputs("ERROR: ", stderr);
	vfprintf(stderr, format, va);
	putc('\n', stderr);
	va_end(va);
}

/* Print formatted error message to stderr. */
static void imagex_error_with_errno(const char *format, ...)
{
	int errno_save = errno;
	va_list va;
	va_start(va, format);
	fputs("ERROR: ", stderr);
	vfprintf(stderr, format, va);
	fprintf(stderr, ": %s\n", strerror(errno_save));
	va_end(va);
}

static int verify_image_exists(int image, const char *image_name,
			       const char *wim_name)
{
	if (image == WIMLIB_NO_IMAGE) {
		imagex_error("\"%s\" is not a valid image in `%s'!\n"
			     "       Please specify a 1-based imagex index or "
			     "image name.\n"
			     "       You may use `imagex info' to list the images "
			     "contained in a WIM.",
			     image_name, wim_name);
		return -1;
	}
	return 0;
}

static int verify_image_is_single(int image)
{
	if (image == WIMLIB_ALL_IMAGES) {
		imagex_error("Cannot specify all images for this action!");
		return -1;
	}
	return 0;
}

static int verify_image_exists_and_is_single(int image, const char *image_name,
					     const char *wim_name)
{
	int ret;
	ret = verify_image_exists(image, image_name, wim_name);
	if (ret == 0)
		ret = verify_image_is_single(image);
	return ret;
}

static int get_compression_type(const char *optarg)
{
	if (strcasecmp(optarg, "maximum") == 0 || strcasecmp(optarg, "lzx") == 0)
		return WIMLIB_COMPRESSION_TYPE_LZX;
	else if (strcasecmp(optarg, "fast") == 0 || strcasecmp(optarg, "xpress") == 0)
		return WIMLIB_COMPRESSION_TYPE_XPRESS;
	else if (strcasecmp(optarg, "none") == 0)
		return WIMLIB_COMPRESSION_TYPE_NONE;
	else {
		imagex_error("Invalid compression type `%s'! Must be "
			     "\"maximum\", \"fast\", or \"none\".", optarg);
		return WIMLIB_COMPRESSION_TYPE_INVALID;
	}
}

static off_t file_get_size(const char *filename)
{
	struct stat st;
	if (stat(filename, &st) == 0)
		return st.st_size;
	else
		return (off_t)-1;
}

static const char *default_capture_config =
"[ExclusionList]\n"
"\\$ntfs.log\n"
"\\hiberfil.sys\n"
"\\pagefile.sys\n"
"\\System Volume Information\n"
"\\RECYCLER\n"
"\\Windows\\CSC\n"
"\n"
"[CompressionExclusionList]\n"
"*.mp3\n"
"*.zip\n"
"*.cab\n"
"\\WINDOWS\\inf\\*.pnf\n";

static char *file_get_contents(const char *filename, size_t *len_ret)
{
	struct stat stbuf;
	char *buf;
	size_t len;
	FILE *fp;

	if (stat(filename, &stbuf) != 0) {
		imagex_error_with_errno("Failed to stat the file `%s'", filename);
		return NULL;
	}
	len = stbuf.st_size;

	fp = fopen(filename, "rb");
	if (!fp) {
		imagex_error_with_errno("Failed to open the file `%s'", filename);
		return NULL;
	}

	buf = malloc(len);
	if (!buf) {
		imagex_error("Failed to allocate buffer of %zu bytes to hold "
			     "contents of file `%s'", len, filename);
		goto out_fclose;
	}
	if (fread(buf, 1, len, fp) != len) {
		imagex_error_with_errno("Failed to read %lu bytes from the "
					"file `%s'", len, filename);
		goto out_free_buf;
	}
	*len_ret = len;
	return buf;
out_free_buf:
	free(buf);
out_fclose:
	fclose(fp);
	return NULL;
}

static int file_writable(const char *path)
{
	int ret;
	ret = access(path, W_OK);
	if (ret != 0)
		imagex_error_with_errno("Can't modify `%s'", path);
	return ret;
}

#define TO_PERCENT(numerator, denominator) \
	(((denominator) == 0) ? 0 : ((numerator) * 100 / (denominator)))

static const char *get_data_type(int ctype)
{
	switch (ctype) {
	case WIMLIB_COMPRESSION_TYPE_NONE:
		return "uncompressed";
	case WIMLIB_COMPRESSION_TYPE_LZX:
		return "LZX-compressed";
	case WIMLIB_COMPRESSION_TYPE_XPRESS:
		return "XPRESS-compressed";
	}
	return NULL;
}

static int imagex_progress_func(enum wimlib_progress_msg msg,
				const union wimlib_progress_info *info)
{
	unsigned percent_done;
	switch (msg) {
	case WIMLIB_PROGRESS_MSG_WRITE_STREAMS:
		percent_done = TO_PERCENT(info->write_streams.completed_bytes,
					  info->write_streams.total_bytes);
		if (info->write_streams.completed_streams == 0) {
			const char *data_type;

			data_type = get_data_type(info->write_streams.compression_type);
			printf("Writing %s data using %u thread%s\n",
			       data_type, info->write_streams.num_threads,
			       (info->write_streams.num_threads == 1) ? "" : "s");
		}
		printf("\r%"PRIu64" MiB of %"PRIu64" MiB (uncompressed) "
		       "written (%u%% done)",
		       info->write_streams.completed_bytes >> 20,
		       info->write_streams.total_bytes >> 20,
		       percent_done);
		if (info->write_streams.completed_bytes >= info->write_streams.total_bytes)
			putchar('\n');
		break;
	case WIMLIB_PROGRESS_MSG_SCAN_BEGIN:
		printf("Scanning `%s'...\n", info->scan.source);
		break;
	case WIMLIB_PROGRESS_MSG_SCAN_DENTRY:
		if (info->scan.excluded)
			printf("Excluding `%s' from capture\n", info->scan.cur_path);
		else
			printf("Scanning `%s'\n", info->scan.cur_path);
		break;
	/*case WIMLIB_PROGRESS_MSG_SCAN_END:*/
		/*break;*/
	case WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY:
		percent_done = TO_PERCENT(info->integrity.completed_bytes,
					  info->integrity.total_bytes);
		printf("\rVerifying integrity of `%s': %"PRIu64" MiB "
		       "of %"PRIu64" MiB (%u%%) done",
		       info->integrity.filename,
		       info->integrity.completed_bytes >> 20,
		       info->integrity.total_bytes >> 20,
		       percent_done);
		if (info->integrity.completed_bytes == info->integrity.total_bytes)
			putchar('\n');
		break;
	case WIMLIB_PROGRESS_MSG_CALC_INTEGRITY:
		percent_done = TO_PERCENT(info->integrity.completed_bytes,
					  info->integrity.total_bytes);
		printf("\rCalculating integrity table for WIM: %"PRIu64" MiB "
		       "of %"PRIu64" MiB (%u%%) done",
		       info->integrity.completed_bytes >> 20,
		       info->integrity.total_bytes >> 20,
		       percent_done);
		if (info->integrity.completed_bytes == info->integrity.total_bytes)
			putchar('\n');
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN:
		printf("Applying image %d (%s) from `%s' to %s `%s'\n",
		       info->extract.image,
		       info->extract.image_name,
		       info->extract.wimfile_name,
		       ((info->extract.extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) ?
				"NTFS volume" : "directory"),
		       info->extract.target);
		break;
	/*case WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN:*/
		/*printf("Applying directory structure to %s\n",*/
		       /*info->extract.target);*/
		/*break;*/
	case WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS:
		percent_done = TO_PERCENT(info->extract.completed_bytes,
					  info->extract.total_bytes);
		printf("\rExtracting files: "
		       "%"PRIu64" MiB of %"PRIu64" MiB (%u%%) done",
		       info->extract.completed_bytes >> 20,
		       info->extract.total_bytes >> 20,
		       percent_done);
		if (info->extract.completed_bytes >= info->extract.total_bytes)
			putchar('\n');
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY:
		puts(info->extract.cur_path);
		break;
	case WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS:
		printf("Setting timestamps on all extracted files...\n");
		break;
	case WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END:
		if (info->extract.extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
			printf("Unmounting NTFS volume `%s'...\n",
			       info->extract.target);
		}
		break;
	case WIMLIB_PROGRESS_MSG_JOIN_STREAMS:
		percent_done = TO_PERCENT(info->join.completed_bytes,
					  info->join.total_bytes);
		printf("Writing resources from part %u of %u: "
		       "%"PRIu64 " MiB of %"PRIu64" MiB (%u%%) written\n",
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
		printf("Writing `%s': %"PRIu64" MiB of %"PRIu64" MiB (%u%%) written\n",
		       info->split.part_name,
		       info->split.completed_bytes >> 20,
		       info->split.total_bytes >> 20,
		       percent_done);
		break;
	case WIMLIB_PROGRESS_MSG_SPLIT_END_PART:
		if (info->split.completed_bytes == info->split.total_bytes) {
			printf("Finished writing %u split WIM parts\n",
			       info->split.cur_part_number);
		}
		break;
	default:
		break;
	}
	fflush(stdout);
	return 0;
}


static int open_swms_from_glob(const char *swm_glob,
			       const char *first_part,
			       int open_flags,
			       WIMStruct ***additional_swms_ret,
			       unsigned *num_additional_swms_ret)
{
	unsigned num_additional_swms = 0;
	WIMStruct **additional_swms = NULL;
	glob_t globbuf;
	int ret;

	ret = glob(swm_glob, GLOB_ERR | GLOB_NOSORT, NULL, &globbuf);
	if (ret != 0) {
		if (ret == GLOB_NOMATCH) {
			imagex_error("Found no files for glob \"%s\"",
				     swm_glob);
		} else {
			imagex_error_with_errno("Failed to process glob "
						"\"%s\"", swm_glob);
		}
		ret = -1;
		goto out;
	}
	num_additional_swms = globbuf.gl_pathc;
	additional_swms = calloc(num_additional_swms, sizeof(additional_swms[0]));
	if (!additional_swms) {
		imagex_error("Out of memory");
		ret = -1;
		goto out_globfree;
	}
	unsigned offset = 0;
	for (unsigned i = 0; i < num_additional_swms; i++) {
		if (strcmp(globbuf.gl_pathv[i], first_part) == 0) {
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


static unsigned parse_num_threads(const char *optarg)
{
	char *tmp;
	unsigned nthreads = strtoul(optarg, &tmp, 10);
	if (nthreads == UINT_MAX || *tmp || tmp == optarg) {
		imagex_error("Number of threads must be a non-negative integer!");
		return UINT_MAX;
	} else {
		return nthreads;
	}
}


/* Extract one image, or all images, from a WIM file into a directory. */
static int imagex_apply(int argc, const char **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int image;
	int num_images;
	WIMStruct *w;
	int ret;
	const char *wimfile;
	const char *target;
	const char *image_num_or_name;
	int extract_flags = WIMLIB_EXTRACT_FLAG_SEQUENTIAL;

	const char *swm_glob = NULL;
	WIMStruct **additional_swms = NULL;
	unsigned num_additional_swms = 0;

	for_opt(c, apply_options) {
		switch (c) {
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		case 'h':
			extract_flags |= WIMLIB_EXTRACT_FLAG_HARDLINK;
			break;
		case 's':
			extract_flags |= WIMLIB_EXTRACT_FLAG_SYMLINK;
			break;
		case 'v':
			extract_flags |= WIMLIB_EXTRACT_FLAG_VERBOSE;
			break;
		case 'r':
			swm_glob = optarg;
			break;
		case 'U':
			extract_flags |= WIMLIB_EXTRACT_FLAG_UNIX_DATA;
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
		image_num_or_name = "1";
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
		imagex_error("`%s' contains %d images; Please select one "
			     "(or all)", wimfile, num_images);
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

	ret = stat(target, &stbuf);
	if (ret == 0) {
		if (S_ISBLK(stbuf.st_mode) || S_ISREG(stbuf.st_mode))
			extract_flags |= WIMLIB_EXTRACT_FLAG_NTFS;
	} else {
		if (errno != ENOENT) {
			imagex_error_with_errno("Failed to stat `%s'", target);
			ret = -1;
			goto out;
		}
	}

	ret = wimlib_extract_image(w, image, target, extract_flags,
				   additional_swms, num_additional_swms,
				   imagex_progress_func);
	if (ret == 0)
		printf("Done applying WIM image.\n");
out:
	wimlib_free(w);
	if (additional_swms) {
		for (unsigned i = 0; i < num_additional_swms; i++)
			wimlib_free(additional_swms[i]);
		free(additional_swms);
	}
	return ret;
}

static int imagex_capture_or_append(int argc, const char **argv)
{
	int c;
	int open_flags = 0;
	int add_image_flags = 0;
	int write_flags = 0;
	int compression_type = WIMLIB_COMPRESSION_TYPE_XPRESS;
	const char *source;
	const char *wimfile;
	const char *name;
	const char *desc;
	const char *flags_element = NULL;
	const char *config_file = NULL;
	char *config_str = NULL;
	size_t config_len = 0;
	WIMStruct *w = NULL;
	int ret;
	int cur_image;
	char *default_name;
	int cmd = strcmp(argv[0], "append") ? CAPTURE : APPEND;
	unsigned num_threads = 0;

	for_opt(c, capture_or_append_options) {
		switch (c) {
		case 'b':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_BOOT;
			break;
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case 'C':
			config_file = optarg;
			break;
		case 'x':
			compression_type = get_compression_type(optarg);
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				return -1;
			break;
		case 'f':
			flags_element = optarg;
			break;
		case 'L':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE;
			break;
		case 'v':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_VERBOSE;
			break;
		case 't':
			num_threads = parse_num_threads(optarg);
			if (num_threads == UINT_MAX)
				return -1;
			break;
		case 'R':
			write_flags |= WIMLIB_WRITE_FLAG_REBUILD;
			break;
		case 'U':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA;
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

	char source_copy[strlen(source) + 1];
	memcpy(source_copy, source, strlen(source) + 1);
	default_name = basename(source_copy);

	name = (argc >= 3) ? argv[2] : default_name;
	desc = (argc >= 4) ? argv[3] : NULL;

	if (config_file) {
		config_str = file_get_contents(config_file, &config_len);
		if (!config_str)
			return -1;
	}

	if (cmd == APPEND)
		ret = wimlib_open_wim(wimfile, open_flags, &w,
				      imagex_progress_func);
	else
		ret = wimlib_create_new_wim(compression_type, &w);
	if (ret != 0)
		goto out;

	struct stat stbuf;

	ret = stat(source, &stbuf);
	if (ret == 0) {
		if (S_ISBLK(stbuf.st_mode) || S_ISREG(stbuf.st_mode)) {
			printf("Capturing WIM image from NTFS filesystem on `%s'\n",
			       source);
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_NTFS;
		}
	} else {
		if (errno != ENOENT) {
			imagex_error_with_errno("Failed to stat `%s'", source);
			ret = -1;
			goto out;
		}
	}

	ret = wimlib_add_image(w, source, name,
			       (config_str ? config_str : default_capture_config),
			       (config_str ? config_len : strlen(default_capture_config)),
			       add_image_flags, imagex_progress_func);

	if (ret != 0)
		goto out;
	cur_image = wimlib_get_num_images(w);
	if (desc) {
		ret = wimlib_set_image_descripton(w, cur_image, desc);
		if (ret != 0)
			goto out;
	}
	if (flags_element) {
		ret = wimlib_set_image_flags(w, cur_image, flags_element);
		if (ret != 0)
			goto out;
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
		imagex_error("Failed to write the WIM file `%s'", wimfile);
out:
	wimlib_free(w);
	free(config_str);
	return ret;
}

/* Remove image(s) from a WIM. */
static int imagex_delete(int argc, const char **argv)
{
	int c;
	int open_flags = 0;
	int write_flags = 0;
	const char *wimfile;
	const char *image_num_or_name;
	WIMStruct *w;
	int image;
	int ret;

	for_opt(c, delete_options) {
		switch (c) {
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case 's':
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
			imagex_error("Must specify a WIM file");
		if (argc < 2)
			imagex_error("Must specify an image");
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
		imagex_error("Failed to delete image from `%s'", wimfile);
		goto out;
	}

	ret = wimlib_overwrite(w, write_flags, 0, imagex_progress_func);
	if (ret == WIMLIB_ERR_REOPEN)
		ret = 0;
	if (ret != 0) {
		imagex_error("Failed to write the file `%s' with image "
			     "deleted", wimfile);
	}
out:
	wimlib_free(w);
	return ret;
}

/* Print the files contained in an image(s) in a WIM file. */
static int imagex_dir(int argc, const char **argv)
{
	const char *wimfile;
	WIMStruct *w;
	int image;
	int ret;
	int num_images;

	if (argc < 2) {
		imagex_error("Must specify a WIM file");
		usage(DIR);
		return -1;
	}
	if (argc > 3) {
		imagex_error("Too many arguments");
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
			imagex_error("The file `%s' contains %d images; Please "
				     "select one.", wimfile, num_images);
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
static int imagex_export(int argc, const char **argv)
{
	int c;
	int open_flags = 0;
	int export_flags = 0;
	int write_flags = 0;
	int compression_type = WIMLIB_COMPRESSION_TYPE_NONE;
	bool compression_type_specified = false;
	const char *src_wimfile;
	const char *src_image_num_or_name;
	const char *dest_wimfile;
	const char *dest_name;
	const char *dest_desc;
	WIMStruct *src_w = NULL;
	WIMStruct *dest_w = NULL;
	int ret;
	int image;
	struct stat stbuf;
	bool wim_is_new;
	const char *swm_glob = NULL;
	WIMStruct **additional_swms = NULL;
	unsigned num_additional_swms = 0;
	unsigned num_threads = 0;

	for_opt(c, export_options) {
		switch (c) {
		case 'b':
			export_flags |= WIMLIB_EXPORT_FLAG_BOOT;
			break;
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case 'x':
			compression_type = get_compression_type(optarg);
			if (compression_type == WIMLIB_COMPRESSION_TYPE_INVALID)
				return -1;
			compression_type_specified = true;
			break;
		case 'r':
			swm_glob = optarg;
			break;
		case 't':
			num_threads = parse_num_threads(optarg);
			if (num_threads == UINT_MAX)
				return -1;
			break;
		case 'R':
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
	if (stat(dest_wimfile, &stbuf) == 0) {
		int dest_ctype;

		wim_is_new = false;
		/* Destination file exists. */
		if (!S_ISREG(stbuf.st_mode) && !S_ISLNK(stbuf.st_mode)) {
			imagex_error("`%s' is not a regular file",
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
			imagex_error("Cannot specify a compression type that is "
				     "not the same as that used in the "
				     "destination WIM");
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
			imagex_error_with_errno("Cannot stat file `%s'",
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

/* Prints information about a WIM file; also can mark an image as bootable,
 * change the name of an image, or change the description of an image. */
static int imagex_info(int argc, const char **argv)
{
	int c;
	bool boot         = false;
	bool check        = false;
	bool header       = false;
	bool lookup_table = false;
	bool xml          = false;
	bool metadata     = false;
	bool short_header = true;
	const char *xml_out_file = NULL;
	const char *wimfile;
	const char *image_num_or_name = "all";
	const char *new_name = NULL;
	const char *new_desc = NULL;
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
		case 'b':
			boot = true;
			break;
		case 'c':
			check = true;
			break;
		case 'h':
			header = true;
			short_header = false;
			break;
		case 'l':
			lookup_table = true;
			short_header = false;
			break;
		case 'x':
			xml = true;
			short_header = false;
			break;
		case 'X':
			xml_out_file = optarg;
			short_header = false;
			break;
		case 'm':
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
	if (image == WIMLIB_NO_IMAGE && strcmp(image_num_or_name, "0") != 0) {
		imagex_error("The image `%s' does not exist",
			     image_num_or_name);
		if (boot)
			imagex_error("If you would like to set the boot "
				     "index to 0, specify image \"0\" with "
				     "the --boot flag.");
		ret = WIMLIB_ERR_INVALID_IMAGE;
		goto out;
	}

	num_images = wimlib_get_num_images(w);

	if (num_images == 0) {
		if (boot) {
			imagex_error("--boot is meaningless on a WIM with no "
				     "images");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out;
		}
	}

	if (image == WIMLIB_ALL_IMAGES && num_images > 1) {
		if (boot) {
			imagex_error("Cannot specify the --boot flag "
				     "without specifying a specific "
				     "image in a multi-image WIM");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out;
		}
		if (new_name) {
			imagex_error("Cannot specify the NEW_NAME "
				     "without specifying a specific "
				     "image in a multi-image WIM");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out;
		}
	}

	/* Operations that print information are separated from operations that
	 * recreate the WIM file. */
	if (!new_name && !boot) {

		/* Read-only operations */

		if (image == WIMLIB_NO_IMAGE) {
			imagex_error("`%s' is not a valid image",
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
				printf("Warning: Only showing the lookup table "
				       "for part %d of a %d-part WIM.\n",
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
			fp = fopen(xml_out_file, "wb");
			if (!fp) {
				imagex_error_with_errno("Failed to open the "
							"file `%s' for "
							"writing ",
							xml_out_file);
				ret = -1;
				goto out;
			}
			ret = wimlib_extract_xml_data(w, fp);
			if (fclose(fp) != 0) {
				imagex_error("Failed to close the file `%s'",
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
			imagex_error("Modifying a split WIM is not supported.");
			ret = -1;
			goto out;
		}
		if (image == WIMLIB_ALL_IMAGES)
			image = 1;

		if (image == WIMLIB_NO_IMAGE && new_name) {
			imagex_error("Cannot specify new_name (`%s') when "
				     "using image 0", new_name);
			ret = -1;
			goto out;
		}

		if (boot) {
			if (image == wimlib_get_boot_idx(w)) {
				printf("Image %d is already marked as "
				       "bootable.\n", image);
				boot = false;
			} else {
				printf("Marking image %d as bootable.\n",
				       image);
				wimlib_set_boot_idx(w, image);
			}
		}
		if (new_name) {
			if (strcmp(wimlib_get_image_name(w, image),
						new_name) == 0) {
				printf("Image %d is already named \"%s\".\n",
				       image, new_name);
				new_name = NULL;
			} else {
				printf("Changing the name of image %d to "
				       "\"%s\".\n", image, new_name);
				ret = wimlib_set_image_name(w, image, new_name);
				if (ret != 0)
					goto out;
			}
		}
		if (new_desc) {
			const char *old_desc;
			old_desc = wimlib_get_image_description(w, image);
			if (old_desc && strcmp(old_desc, new_desc) == 0) {
				printf("The description of image %d is already "
				       "\"%s\".\n", image, new_desc);
				new_desc = NULL;
			} else {
				printf("Changing the description of image %d "
				       "to \"%s\".\n", image, new_desc);
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
				return ret;

			if (check)
				write_flags = WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			else
				write_flags = 0;

			ret = wimlib_overwrite(w, write_flags, 1,
					       imagex_progress_func);
			if (ret == WIMLIB_ERR_REOPEN)
				ret = 0;
		} else {
			printf("The file `%s' was not modified because nothing "
			       "needed to be done.\n", wimfile);
			ret = 0;
		}
	}
out:
	wimlib_free(w);
	return ret;
}

/* Join split WIMs into one part WIM */
static int imagex_join(int argc, const char **argv)
{
	int c;
	int swm_open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int wim_write_flags = 0;
	const char *output_path;

	for_opt(c, join_options) {
		switch (c) {
		case 'c':
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
		imagex_error("Must specify one or more split WIM (.swm) parts "
			     "to join");
		goto err;
	}
	output_path = argv[0];
	return wimlib_join(++argv, --argc, output_path, swm_open_flags,
			   wim_write_flags, imagex_progress_func);
err:
	usage(JOIN);
	return -1;
}

/* Mounts an image using a FUSE mount. */
static int imagex_mount_rw_or_ro(int argc, const char **argv)
{
	int c;
	int mount_flags = 0;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	const char *wimfile;
	const char *dir;
	WIMStruct *w;
	int image;
	int num_images;
	int ret;
	const char *swm_glob = NULL;
	WIMStruct **additional_swms = NULL;
	unsigned num_additional_swms = 0;
	const char *staging_dir = NULL;

	if (strcmp(argv[0], "mountrw") == 0)
		mount_flags |= WIMLIB_MOUNT_FLAG_READWRITE;

	for_opt(c, mount_options) {
		switch (c) {
		case 'A':
			mount_flags |= WIMLIB_MOUNT_FLAG_ALLOW_OTHER;
			break;
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		case 'd':
			mount_flags |= WIMLIB_MOUNT_FLAG_DEBUG;
			break;
		case 's':
			if (strcasecmp(optarg, "none") == 0)
				mount_flags |= WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE;
			else if (strcasecmp(optarg, "xattr") == 0)
				mount_flags |= WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR;
			else if (strcasecmp(optarg, "windows") == 0)
				mount_flags |= WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS;
			else {
				imagex_error("Unknown stream interface \"%s\"", optarg);
				goto mount_usage;
			}
			break;
		case 'r':
			swm_glob = optarg;
			break;
		case 'D':
			staging_dir = optarg;
			break;
		case 'U':
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
			imagex_error("The file `%s' contains %d images; Please "
				     "select one.", wimfile, num_images);
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
		imagex_error("Failed to mount image %d from `%s' on `%s'",
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

static int imagex_optimize(int argc, const char **argv)
{
	int c;
	int open_flags = 0;
	int write_flags = WIMLIB_WRITE_FLAG_REBUILD;
	int ret;
	WIMStruct *w;
	const char *wimfile;
	off_t old_size;
	off_t new_size;

	for_opt(c, optimize_options) {
		switch (c) {
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case 'r':
			write_flags |= WIMLIB_WRITE_FLAG_RECOMPRESS;
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

	ret = wimlib_open_wim(wimfile, open_flags, &w,
			      imagex_progress_func);
	if (ret != 0)
		return ret;

	old_size = file_get_size(argv[0]);
	printf("`%s' original size: ", wimfile);
	if (old_size == -1)
		puts("Unknown");
	else
		printf("%"PRIu64" KiB\n", old_size >> 10);

	ret = wimlib_overwrite(w, write_flags, 0, imagex_progress_func);

	if (ret == 0) {
		new_size = file_get_size(argv[0]);
		printf("`%s' optimized size: ", wimfile);
		if (new_size == -1)
			puts("Unknown");
		else
			printf("%"PRIu64" KiB\n", new_size >> 10);

		fputs("Space saved: ", stdout);
		if (new_size != -1 && old_size != -1) {
			printf("%lld KiB\n",
			       ((long long)old_size - (long long)new_size) >> 10);
		} else {
			puts("Unknown");
		}
	}

	wimlib_free(w);
	return ret;
}

/* Split a WIM into a spanned set */
static int imagex_split(int argc, const char **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SPLIT_OK;
	int write_flags = 0;
	unsigned long part_size;
	char *tmp;
	int ret;
	WIMStruct *w;

	for_opt(c, split_options) {
		switch (c) {
		case 'c':
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
	part_size = strtod(argv[2], &tmp) * (1 << 20);
	if (tmp == argv[2] || *tmp) {
		imagex_error("Invalid part size \"%s\"", argv[2]);
		imagex_error("The part size must be an integer or floating-point number of megabytes.");
		return -1;
	}
	ret = wimlib_open_wim(argv[0], open_flags, &w, imagex_progress_func);
	if (ret != 0)
		return ret;
	ret = wimlib_split(w, argv[1], part_size, write_flags, imagex_progress_func);
	wimlib_free(w);
	return ret;
}

/* Unmounts an image. */
static int imagex_unmount(int argc, const char **argv)
{
	int c;
	int unmount_flags = 0;
	int ret;

	for_opt(c, unmount_options) {
		switch (c) {
		case 'c':
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_COMMIT;
			break;
		case 'C':
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY;
			break;
		case 'R':
			unmount_flags |= WIMLIB_UNMOUNT_FLAG_REBUILD;
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
		imagex_error("Failed to unmount `%s'", argv[0]);
	return ret;
}

struct imagex_command {
	const char *name;
	int (*func)(int , const char **);
	int cmd;
};


#define for_imagex_command(p) for (p = &imagex_commands[0]; \
		p != &imagex_commands[ARRAY_LEN(imagex_commands)]; p++)

static const struct imagex_command imagex_commands[] = {
	{"append",  imagex_capture_or_append, APPEND},
	{"apply",   imagex_apply,	      APPLY},
	{"capture", imagex_capture_or_append, CAPTURE},
	{"delete",  imagex_delete,	      DELETE},
	{"dir",     imagex_dir,		      DIR},
	{"export",  imagex_export,	      EXPORT},
	{"info",    imagex_info,	      INFO},
	{"join",    imagex_join,	      JOIN},
	{"mount",   imagex_mount_rw_or_ro,    MOUNT},
	{"mountrw", imagex_mount_rw_or_ro,    MOUNTRW},
	{"optimize",imagex_optimize,          OPTIMIZE},
	{"split",   imagex_split,	      SPLIT},
	{"unmount", imagex_unmount,	      UNMOUNT},
};

static void version()
{
	static const char *s =
	"imagex (" PACKAGE ") " PACKAGE_VERSION "\n"
	"Copyright (C) 2012 Eric Biggers\n"
	"License GPLv3+; GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.\n"
	"\n"
	"Report bugs to "PACKAGE_BUGREPORT".\n";
	fputs(s, stdout);
}


static void help_or_version(int argc, const char **argv)
{
	int i;
	const char *p;
	const struct imagex_command *cmd;

	for (i = 1; i < argc; i++) {
		p = argv[i];
		if (*p == '-')
			p++;
		else
			continue;
		if (*p == '-')
			p++;
		if (strcmp(p, "help") == 0) {
			for_imagex_command(cmd) {
				if (strcmp(cmd->name, argv[1]) == 0) {
					usage(cmd->cmd);
					exit(0);
				}
			}
			usage_all();
			exit(0);
		}
		if (strcmp(p, "version") == 0) {
			version();
			exit(0);
		}
	}
}


static void usage(int cmd_type)
{
	const struct imagex_command *cmd;
	printf("Usage: %s", usage_strings[cmd_type]);
	for_imagex_command(cmd) {
		if (cmd->cmd == cmd_type)
			printf("\nTry `man imagex-%s' for more details.\n",
			       cmd->name);
	}
}

static void usage_all()
{
	puts("IMAGEX: Usage:");
	for (int i = 0; i < ARRAY_LEN(usage_strings); i++)
		printf("    %s", usage_strings[i]);
	static const char *extra =
"    imagex --help\n"
"    imagex --version\n"
"\n"
"    The compression TYPE may be \"maximum\", \"fast\", or \"none\".\n"
"\n"
"    Try `man imagex' for more information.\n"
	;
	fputs(extra, stdout);
}


int main(int argc, const char **argv)
{
	const struct imagex_command *cmd;
	int ret;

	if (argc < 2) {
		imagex_error("No command specified");
		usage_all();
		return 1;
	}

	help_or_version(argc, argv);
	argc--;
	argv++;

	wimlib_set_print_errors(true);
	ret = wimlib_global_init();
	if (ret)
		goto out;

	for_imagex_command(cmd) {
		if (strcmp(cmd->name, *argv) == 0) {
			ret = cmd->func(argc, argv);
			goto out;
		}
	}

	imagex_error("Unrecognized command: `%s'", argv[0]);
	usage_all();
	return 1;
out:
	if (ret > 0) {
		imagex_error("Exiting with error code %d:\n"
			     "       %s.", ret,
			     wimlib_get_error_string(ret));
		if (ret == WIMLIB_ERR_NTFS_3G && errno != 0)
			imagex_error_with_errno("errno");
	}
	wimlib_global_cleanup();
	return ret;
}
