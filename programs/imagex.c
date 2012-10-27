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

#include "wimlib.h"
#include "config.h"
#include <getopt.h>
#include <stdlib.h>
#include <stdarg.h>
#include <glob.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

#define swap(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); \
				a = __b; b = __a; })

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
	SPLIT,
	UNMOUNT,
};

static void usage(int cmd_type);
static void usage_all();

static const char *usage_strings[] = {
[APPEND] =
"    imagex append (DIRECTORY | NTFS_VOLUME) WIMFILE [IMAGE_NAME]\n"
"                  [DESCRIPTION] [--boot] [--check] [--flags EDITION_ID]\n"
"                  [--verbose] [--dereference] [--config=FILE]\n",
[APPLY] =
"    imagex apply WIMFILE [IMAGE_NUM | IMAGE_NAME | all]\n"
"                 (DIRECTORY | NTFS_VOLUME) [--check] [--hardlink]\n"
"                 [--symlink] [--verbose] [--ref=\"GLOB\"]\n",
[CAPTURE] =
"    imagex capture (DIRECTORY | NTFS_VOLUME) WIMFILE [IMAGE_NAME]\n"
"                   [DESCRIPTION] [--boot] [--check] [--compress=TYPE]\n"
"                   [--flags EDITION_ID] [--verbose] [--dereference]\n"
"                   [--config=FILE]\n",
[DELETE] =
"    imagex delete WIMFILE (IMAGE_NUM | IMAGE_NAME | all) [--check]\n",
[DIR] =
"    imagex dir WIMFILE (IMAGE_NUM | IMAGE_NAME | all)\n",
[EXPORT] =
"    imagex export SRC_WIMFILE (SRC_IMAGE_NUM | SRC_IMAGE_NAME | all ) \n"
"                  DEST_WIMFILE [DEST_IMAGE_NAME]\n"
"                  [DEST_IMAGE_DESCRIPTION] [--boot] [--check]\n"
"                  [--compress=TYPE] [--ref=\"GLOB\"]\n",
[INFO] =
"    imagex info WIMFILE [IMAGE_NUM | IMAGE_NAME] [NEW_NAME]\n"
"                [NEW_DESC] [--boot] [--check] [--header] [--lookup-table]\n"
"                [--xml] [--extract-xml FILE] [--metadata]\n",
[JOIN] =
"    imagex join [--check] WIMFILE SPLIT_WIM...\n",
[MOUNT] =
"    imagex mount WIMFILE (IMAGE_NUM | IMAGE_NAME) DIRECTORY\n"
"                 [--check] [--debug] [--streams-interface=INTERFACE]\n"
"                 [--ref=\"GLOB\"]\n",
[MOUNTRW] =
"    imagex mountrw WIMFILE [IMAGE_NUM | IMAGE_NAME] DIRECTORY\n"
"                   [--check] [--debug] [--streams-interface=INTERFACE]\n",
[SPLIT] =
"    imagex split WIMFILE SPLIT_WIMFILE PART_SIZE_MB [--check]\n",
[UNMOUNT] =
"    imagex unmount DIRECTORY [--commit] [--check]\n",
};

static const struct option common_options[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static const struct option apply_options[] = {
	{"check",    no_argument,       NULL, 'c'},
	{"hardlink", no_argument,       NULL, 'h'},
	{"symlink",  no_argument,       NULL, 's'},
	{"verbose",  no_argument,       NULL, 'v'},
	{"ref",      required_argument, NULL, 'r'},
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
	{NULL, 0, NULL, 0},
};
static const struct option delete_options[] = {
	{"check", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static const struct option export_options[] = {
	{"boot",       no_argument,	  NULL, 'b'},
	{"check",      no_argument,	  NULL, 'c'},
	{"compress",   required_argument, NULL, 'x'},
	{"ref",        required_argument, NULL, 'r'},
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
	{"check", no_argument, NULL, 'c'},
	{"debug", no_argument, NULL, 'd'},
	{"streams-interface", required_argument, NULL, 's'},
	{"ref",      required_argument, NULL, 'r'},
	{NULL, 0, NULL, 0},
};

static const struct option split_options[] = {
	{"check", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static const struct option unmount_options[] = {
	{"commit", no_argument, NULL, 'c'},
	{"check", no_argument, NULL, 'C'},
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

static const char *path_basename(const char *path)
{
	const char *p = path;
	while (*p)
		p++;
	p--;

	/* Trailing slashes. */
	while ((p != path - 1) && *p == '/')
		p--;

	while ((p != path - 1) && *p != '/')
		p--;

	return p + 1;
}


static int verify_image_exists(int image)
{
	if (image == WIM_NO_IMAGE) {
		imagex_error("Not a valid image");
		return WIMLIB_ERR_INVALID_IMAGE;
	}
	return 0;
}

static int verify_image_is_single(int image)
{
	if (image == WIM_ALL_IMAGES) {
		imagex_error("Cannot specify all images for this action");
		return WIMLIB_ERR_INVALID_IMAGE;
	}
	return 0;
}

static int verify_image_exists_and_is_single(int image)
{
	int ret;
	ret = verify_image_exists(image);
	if (ret == 0)
		ret = verify_image_is_single(image);
	return ret;
}

static int get_compression_type(const char *optarg)
{
	if (strcasecmp(optarg, "maximum") == 0 || strcasecmp(optarg, "lzx") == 0)
		return WIM_COMPRESSION_TYPE_LZX;
	else if (strcasecmp(optarg, "fast") == 0 || strcasecmp(optarg, "xpress") == 0)
		return WIM_COMPRESSION_TYPE_XPRESS;
	else if (strcasecmp(optarg, "none") == 0)
		return WIM_COMPRESSION_TYPE_NONE;
	else {
		imagex_error("Invalid compression type `%s'! Must be "
			     "\"maximum\", \"fast\", or \"none\".", optarg);
		return WIM_COMPRESSION_TYPE_INVALID;
	}
}

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
				      &additional_swms[i - offset]);
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


/* Extract one image, or all images, from a WIM file into a directory. */
static int imagex_apply(int argc, const char **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS |
			 WIMLIB_OPEN_FLAG_SPLIT_OK;
	int image;
	int num_images;
	WIMStruct *w;
	int ret;
	const char *wimfile;
	const char *dir;
	const char *image_num_or_name;
	int extract_flags = 0;

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
		dir = argv[1];
	} else {
		image_num_or_name = argv[1];
		dir = argv[2];
	}

	ret = wimlib_open_wim(wimfile, open_flags, &w);
	if (ret != 0)
		return ret;

	image = wimlib_resolve_image(w, image_num_or_name);
	ret = verify_image_exists(image);
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

#ifdef WITH_NTFS_3G
	struct stat stbuf;

	ret = stat(dir, &stbuf);
	if (ret == 0) {
		if (S_ISBLK(stbuf.st_mode) || S_ISREG(stbuf.st_mode)) {
			const char *ntfs_device = dir;
			printf("Applying image %d of `%s' to NTFS filesystem on `%s'\n",
			       image, wimfile, ntfs_device);
			ret = wimlib_apply_image_to_ntfs_volume(w, image,
								ntfs_device,
								extract_flags,
								additional_swms,
								num_additional_swms);
			goto out;
		}
	} else {
		if (errno != ENOENT) {
			imagex_error_with_errno("Failed to stat `%s'", dir);
			ret = -1;
			goto out;
		}
	}
#endif

	ret = wimlib_extract_image(w, image, dir, extract_flags,
				   additional_swms, num_additional_swms);
out:
	wimlib_free(w);
	if (additional_swms)
		for (unsigned i = 0; i < num_additional_swms; i++)
			wimlib_free(additional_swms[i]);
	return ret;
}

static int imagex_capture_or_append(int argc, const char **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	int add_image_flags = 0;
	int write_flags = WIMLIB_WRITE_FLAG_SHOW_PROGRESS;
	int compression_type = WIM_COMPRESSION_TYPE_XPRESS;
	const char *dir;
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
			if (compression_type == WIM_COMPRESSION_TYPE_INVALID)
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
			write_flags |= WIMLIB_WRITE_FLAG_VERBOSE;
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
	dir = argv[0];
	wimfile = argv[1];

	char dir_copy[strlen(dir) + 1];
	memcpy(dir_copy, dir, strlen(dir) + 1);
	default_name = basename(dir_copy);

	name = (argc >= 3) ? argv[2] : default_name;
	desc = (argc >= 4) ? argv[3] : NULL;

	if (config_file) {
		config_str = file_get_contents(config_file, &config_len);
		if (!config_str)
			return -1;
	}

	if (cmd == APPEND)
		ret = wimlib_open_wim(wimfile, open_flags, &w);
	else
		ret = wimlib_create_new_wim(compression_type, &w);
	if (ret != 0)
		goto out;

#ifdef WITH_NTFS_3G
	struct stat stbuf;

	ret = stat(dir, &stbuf);
	if (ret == 0) {
		if (S_ISBLK(stbuf.st_mode) || S_ISREG(stbuf.st_mode)) {
			const char *ntfs_device = dir;
			printf("Capturing WIM image NTFS filesystem on `%s'\n",
			       ntfs_device);
			ret = wimlib_add_image_from_ntfs_volume(w, ntfs_device,
								name,
								config_str,
								config_len,
								add_image_flags);
			goto out_write;
		}
	} else {
		if (errno != ENOENT) {
			imagex_error_with_errno("Failed to stat `%s'", dir);
			ret = -1;
			goto out;
		}
	}
#endif
	ret = wimlib_add_image(w, dir, name, config_str, config_len,
			       add_image_flags);

out_write:
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
	if (cmd == APPEND)
		ret = wimlib_overwrite(w, write_flags);
	else
		ret = wimlib_write(w, wimfile, WIM_ALL_IMAGES, write_flags);
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
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	int write_flags = WIMLIB_WRITE_FLAG_SHOW_PROGRESS;
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

	ret = wimlib_open_wim(wimfile, open_flags, &w);
	if (ret != 0)
		return ret;

	image = wimlib_resolve_image(w, image_num_or_name);

	ret = verify_image_exists(image);
	if (ret != 0)
		goto out;

	ret = wimlib_delete_image(w, image);
	if (ret != 0) {
		imagex_error("Failed to delete image from `%s'", wimfile);
		goto out;
	}

	ret = wimlib_overwrite(w, write_flags);
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
	ret = wimlib_open_wim(wimfile, WIMLIB_OPEN_FLAG_SPLIT_OK, &w);
	if (ret != 0)
		return ret;

	if (argc == 3) {
		image = wimlib_resolve_image(w, argv[2]);
		ret = verify_image_exists(image);
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
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	int export_flags = 0;
	int write_flags = WIMLIB_WRITE_FLAG_SHOW_PROGRESS;
	int compression_type;
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
			if (compression_type == WIM_COMPRESSION_TYPE_INVALID)
				return -1;
			compression_type_specified = true;
			break;
		case 'r':
			swm_glob = optarg;
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
			      open_flags | WIMLIB_OPEN_FLAG_SPLIT_OK, &src_w);
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
		ret = wimlib_open_wim(dest_wimfile, open_flags, &dest_w);
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
		compression_type = dest_ctype;
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
	ret = verify_image_exists(image);
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
				  num_additional_swms);
	if (ret != 0)
		goto out;


	if (wim_is_new)
		ret = wimlib_write(dest_w, dest_wimfile, WIM_ALL_IMAGES,
				   write_flags);
	else
		ret = wimlib_overwrite(dest_w, write_flags);
out:
	wimlib_free(src_w);
	wimlib_free(dest_w);
	if (additional_swms)
		for (unsigned i = 0; i < num_additional_swms; i++)
			wimlib_free(additional_swms[i]);
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
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS |
			 WIMLIB_OPEN_FLAG_SPLIT_OK;
	int part_number;
	int total_parts;

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

	ret = wimlib_open_wim(wimfile, open_flags, &w);
	if (ret != 0)
		return ret;

	part_number = wimlib_get_part_number(w, &total_parts);

	image = wimlib_resolve_image(w, image_num_or_name);
	if (image == WIM_NO_IMAGE && strcmp(image_num_or_name, "0") != 0) {
		imagex_error("The image `%s' does not exist",
						image_num_or_name);
		if (boot)
			imagex_error("If you would like to set the boot "
				     "index to 0, specify image \"0\" with "
				     "the --boot flag.");
		ret = WIMLIB_ERR_INVALID_IMAGE;
		goto out;
	}

	if (image == WIM_ALL_IMAGES && wimlib_get_num_images(w) > 1) {
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

		if (image == WIM_NO_IMAGE) {
			imagex_error("`%s' is not a valid image",
				     image_num_or_name);
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out;
		}

		if (image == WIM_ALL_IMAGES && short_header)
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
				goto out;
			}
			ret = wimlib_extract_xml_data(w, fp);
			if (fclose(fp) != 0) {
				imagex_error("Failed to close the file `%s'",
					     xml_out_file);
				goto out;
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
			return -1;
		}
		if (image == WIM_ALL_IMAGES)
			image = 1;

		if (image == WIM_NO_IMAGE && new_name) {
			imagex_error("Cannot specify new_name (`%s') when "
				     "using image 0", new_name);
			return -1;
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

		/* Only call wimlib_overwrite_xml_and_header() if something
		 * actually needs to be changed. */
		if (boot || new_name || new_desc ||
				check != wimlib_has_integrity_table(w)) {

			ret = wimlib_overwrite_xml_and_header(w, check ?
					WIMLIB_WRITE_FLAG_CHECK_INTEGRITY |
					WIMLIB_WRITE_FLAG_SHOW_PROGRESS : 0);
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
	int flags = WIMLIB_OPEN_FLAG_SPLIT_OK | WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	const char *output_path;

	for_opt(c, join_options) {
		switch (c) {
		case 'c':
			flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			break;
		default:
			goto err;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		imagex_error("Must specify at least one split WIM (.swm) parts "
			     "to join");
		goto err;
	}
	output_path = argv[0];
	return wimlib_join(++argv, --argc, output_path, flags);
err:
	usage(JOIN);
	return -1;
}

/* Mounts an image using a FUSE mount. */
static int imagex_mount_rw_or_ro(int argc, const char **argv)
{
	int c;
	int mount_flags = 0;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS |
			 WIMLIB_OPEN_FLAG_SPLIT_OK;
	const char *wimfile;
	const char *dir;
	WIMStruct *w;
	int image;
	int num_images;
	int ret;
	const char *swm_glob = NULL;
	WIMStruct **additional_swms = NULL;
	unsigned num_additional_swms = 0;

	if (strcmp(argv[0], "mountrw") == 0)
		mount_flags |= WIMLIB_MOUNT_FLAG_READWRITE;

	for_opt(c, mount_options) {
		switch (c) {
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
		default:
			goto mount_usage;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 && argc != 3)
		goto mount_usage;

	wimfile = argv[0];

	ret = wimlib_open_wim(wimfile, open_flags, &w);
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
				     "select one", wimfile, num_images);
			usage((mount_flags & WIMLIB_MOUNT_FLAG_READWRITE)
					? MOUNTRW : MOUNT);
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out;
		}
		dir = argv[1];
	} else {
		image = wimlib_resolve_image(w, argv[1]);
		dir = argv[2];
	}

	ret = verify_image_exists_and_is_single(image);
	if (ret != 0)
		goto out;

	ret = wimlib_mount(w, image, dir, mount_flags, additional_swms,
			   num_additional_swms);
	if (ret != 0) {
		imagex_error("Failed to mount image %d from `%s' on `%s'",
			     image, wimfile, dir);

	}
out:
	wimlib_free(w);
	if (additional_swms)
		for (unsigned i = 0; i < num_additional_swms; i++)
			wimlib_free(additional_swms[i]);
	return ret;
mount_usage:
	usage((mount_flags & WIMLIB_MOUNT_FLAG_READWRITE)
			? MOUNTRW : MOUNT);
	return -1;
}

/* Split a WIM into a spanned set */
static int imagex_split(int argc, const char **argv)
{
	int c;
	int flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	unsigned long part_size;
	char *tmp;

	for_opt(c, split_options) {
		switch (c) {
		case 'c':
			flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
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
	return wimlib_split(argv[0], argv[1], part_size, flags);
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

	ret = wimlib_unmount(argv[0], unmount_flags);
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
	puts("IMAGEX: Usage:");
	fputs(usage_strings[cmd_type], stdout);
	for_imagex_command(cmd)
		if (cmd->cmd == cmd_type)
			printf("\nTry `man imagex-%s' for more details.\n",
			       cmd->name);
}

static void usage_all()
{
	puts("IMAGEX: Usage:");
	for (int i = 0; i < ARRAY_LEN(usage_strings); i++)
		fputs(usage_strings[i], stdout);
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

	for_imagex_command(cmd) {
		if (strcmp(cmd->name, *argv) == 0) {
			ret = cmd->func(argc, argv);
			if (ret > 0) {
				imagex_error("Exiting with error code %d:\n"
					     "       %s.", ret,
					     wimlib_get_error_string(ret));
				if (ret == WIMLIB_ERR_NTFS_3G)
					imagex_error_with_errno("errno");
			}
			return ret;
		}
	}

	imagex_error("Unrecognized command: `%s'", argv[0]);
	usage_all();
	return 1;
}
