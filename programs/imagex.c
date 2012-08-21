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
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#ifdef WITH_NTFS_3G
#include <unistd.h>
#include <sys/wait.h>
#endif

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


static const char *usage_strings[] = {
[APPEND] = 
"    imagex append DIRECTORY WIMFILE [\"IMAGE_NAME\"] [\"DESCRIPTION\"] [--boot]\n"
"                  [--check] [--flags EDITIONID] [--dereference]\n",
[APPLY] = 
"    imagex apply WIMFILE [IMAGE_NUM | IMAGE_NAME | all] DIRECTORY [--check]\n"
"                 [--hardlink] [--symlink] [--verbose]\n",
[CAPTURE] = 
"    imagex capture DIRECTORY WIMFILE [\"IMAGE_NAME\"] [\"DESCRIPTION\"]\n"
"       l           [--boot] [--check] [--compress[=TYPE]]\n"
"                   [--flags \"EditionID\"] [--verbose] [--dereference]\n",
[DELETE] = 
"    imagex delete WIMFILE (IMAGE_NUM | IMAGE_NAME | all) [--check]\n",
[DIR] = 
"    imagex dir WIMFILE (IMAGE_NUM | IMAGE_NAME | \"all\")\n",
[EXPORT] = 
"    imagex export SRC_WIMFILE (SRC_IMAGE_NUM | SRC_IMAGE_NAME | all ) \n"
"        DEST_WIMFILE [\"DEST_IMAGE_NAME\"] [\"DEST_IMAGE_DESCRIPTION\"]\n"
"                  [--boot] [--check] [--compress[=TYPE]]\n",
[INFO] = 
"    imagex info WIMFILE [IMAGE_NUM | IMAGE_NAME] [NEW_NAME]\n"
"                [NEW_DESC] [--boot] [--check] [--header] [--lookup-table]\n"
"                [--xml] [--extract-xml FILE] [--metadata]\n",
[JOIN] = 
"    imagex join [--check] WIMFILE SPLIT_WIM...\n",
[MOUNT] = 
"    imagex mount WIMFILE (IMAGE_NUM | IMAGE_NAME) DIRECTORY\n"
"                 [--check] [--debug] [--stream-interface=INTERFACE]\n",
[MOUNTRW] = 
"    imagex mountrw WIMFILE [IMAGE_NUM | IMAGE_NAME] DIRECTORY\n"
"                   [--check] [--debug] [--stream-interface=INTERFACE]\n",
[SPLIT] = 
"    imagex split WIMFILE SPLIT_WIMFILE PART_SIZE [--check]\n",
[UNMOUNT] = 
"    imagex unmount DIRECTORY [--commit] [--check]\n",
};

static const struct option common_options[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static const struct option append_options[] = {
	{"boot",   no_argument,       NULL, 'b'},
	{"check",  no_argument,       NULL, 'c'},
	{"flags",    required_argument, NULL, 'f'},
	{"dereference", no_argument, NULL, 'L'},
	{NULL, 0, NULL, 0},
};
static const struct option apply_options[] = {
	{"check",    no_argument,       NULL, 'c'},
	{"hardlink", no_argument,       NULL, 'h'},
	{"symlink",  no_argument,       NULL, 's'},
	{"verbose",  no_argument,       NULL, 'v'},
	{NULL, 0, NULL, 0},
};
static const struct option capture_options[] = {
	{"boot",     no_argument,       NULL, 'b'},
	{"check",    no_argument,       NULL, 'c'},
	{"compress", optional_argument, NULL, 'x'},
	{"flags",    required_argument, NULL, 'f'},
	{"verbose",  no_argument,       NULL,'v'},
	{"dereference", no_argument, NULL, 'L'},
	{NULL, 0, NULL, 0},
};
static const struct option delete_options[] = {
	{"check", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static const struct option export_options[] = {
	{"boot",       no_argument, NULL, 'b'},
	{"check",      no_argument , NULL, 'c'},
	{"compress",   optional_argument, NULL, 'x'},
	{NULL, 0, NULL, 0},
};

static const struct option info_options[] = {
	{"boot",         no_argument, NULL, 'b'},
	{"check",        no_argument, NULL, 'c'},
	{"header",       no_argument, NULL, 'h'},
	{"lookup-table", no_argument, NULL, 'l'},
	{"xml",          no_argument, NULL, 'x'},
	{"extract-xml",  required_argument, NULL, 'X'},
	{"metadata",     no_argument, NULL, 'm'},
	{NULL, 0, NULL, 0},
};

static const struct option join_options[] = {
	{"check", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static const struct option mount_options[] = {
	{"check", no_argument, NULL, 'c'},
	{"debug", no_argument, NULL, 'd'},
	{"stream-interface", required_argument, NULL, 's'},
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


static inline void version()
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

static inline void usage(int cmd)
{
	puts("IMAGEX: Usage:");
	fputs(usage_strings[cmd], stdout);
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
	;
	fputs(extra, stdout);
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
	if (!optarg)
		return WIM_COMPRESSION_TYPE_LZX;
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

static int imagex_append(int argc, const char **argv)
{
	int c;
	const char *flags_element = NULL;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	int add_image_flags = 0;
	int write_flags = WIMLIB_WRITE_FLAG_SHOW_PROGRESS;
	const char *dir;
	const char *wimfile;
	const char *name;
	const char *desc;
	WIMStruct *w;
	int ret;

	for_opt(c, append_options) {
		switch (c) {
		case 'b':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_BOOT;
			break;
		case 'c':
			open_flags |= WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case 'f':
			flags_element = optarg;
			break;
		case 'L':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE;
			break;
		default:
			usage(APPEND);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 2 || argc > 4) {
		usage(APPEND);
		return -1;
	}
	dir     = argv[0];
	wimfile = argv[1];
	name    = (argc >= 3) ? argv[2] : path_basename(dir);
	desc    = (argc >= 4) ? argv[3] : NULL;

	ret = wimlib_open_wim(wimfile, open_flags, &w);
	if (ret != 0)
		return ret;

	ret = wimlib_add_image(w, dir, name, desc, 
			       flags_element, add_image_flags);
	if (ret != 0)
		goto done;
	ret = wimlib_overwrite(w, write_flags);
done:
	wimlib_free(w);
	return ret;
}

/* Extract one image, or all images, from a WIM file into a directory. */
static int imagex_apply(int argc, const char **argv)
{
	int c;
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	int image;
	int num_images;
	WIMStruct *w;
	int ret;
	const char *wimfile;
	const char *dir;
	const char *image_num_or_name;
	int extract_flags = 0;

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
		image_num_or_name =  "1";
		dir = argv[1];
	} else {
		image_num_or_name = argv[1];
		dir = argv[2];
	}

	ret = wimlib_open_wim(wimfile, open_flags, &w);
	if (ret != 0)
		goto out;

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
								extract_flags);
			goto out;
		}
	} else {
		if (errno != -ENOENT)
			imagex_error_with_errno("Failed to stat `%s'", dir);
	}
#endif

	ret = wimlib_extract_image(w, image, dir, extract_flags);
out:
	wimlib_free(w);
	return ret;
}


/* Create a WIM file from a directory. */
static int imagex_capture(int argc, const char **argv)
{
	int c;
	int add_image_flags = 0;
	int write_flags = WIMLIB_WRITE_FLAG_SHOW_PROGRESS;
	int compression_type = WIM_COMPRESSION_TYPE_NONE;
	const char *flags_element = NULL;
	const char *dir;
	const char *wimfile;
	const char *name;
	const char *desc;
	WIMStruct *w;
	int ret;

	for_opt(c, capture_options) {
		switch (c) {
		case 'b':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_BOOT;
			break;
		case 'c':
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			break;
		case 'x':
			compression_type = get_compression_type(optarg);
			if (compression_type == WIM_COMPRESSION_TYPE_INVALID)
				return -1;
			break;
		case 'f':
			flags_element = optarg;
			break;
		case 'v':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_VERBOSE;
			break;
		case 'N':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_NTFS;
			break;
		case 'L':
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE;
			break;
		default:
			usage(CAPTURE);
			return -1;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc < 2 || argc > 4) {
		usage(CAPTURE);
		return -1;
	}
	dir     = argv[0];
	wimfile = argv[1];
	name    = (argc >= 3) ? argv[2] : dir;
	desc    = (argc >= 4) ? argv[3] : NULL;

	ret = wimlib_create_new_wim(compression_type, &w);
	if (ret != 0)
		return ret;

	ret = wimlib_add_image(w, dir, name, desc, flags_element, 
			       add_image_flags);
	if (ret != 0) {
		imagex_error("Failed to add the image `%s'", dir);
		goto done;
	}

	ret = wimlib_write(w, wimfile, WIM_ALL_IMAGES, write_flags);
	if (ret != 0)
		imagex_error("Failed to write the WIM file `%s'", wimfile);
done:
	wimlib_free(w);
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
		goto done;

	ret = wimlib_delete_image(w, image);
	if (ret != 0) {
		imagex_error("Failed to delete image from `%s'", wimfile);
		goto done;
	}

	ret = wimlib_overwrite(w, write_flags);
	if (ret != 0) {
		imagex_error("Failed to write the file `%s' with image "
			     "deleted", wimfile);
	}
done:
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
	int part_number;

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

	part_number = wimlib_get_part_number(w, NULL);
	if (part_number != 1) {
		imagex_error("`%s' is part %d of a split WIM!  Specify the "
			     "first part to see the files",
			     wimfile, part_number);
		ret = WIMLIB_ERR_SPLIT_UNSUPPORTED;
		goto done;
	}

	if (argc == 3) {
		image = wimlib_resolve_image(w, argv[2]);
		ret = verify_image_exists(image);
		if (ret != 0)
			goto done;
	} else {
		/* Image was not specified.  If the WIM only contains one image,
		 * choose that one; otherwise, print an error. */
		num_images = wimlib_get_num_images(w);
		if (num_images != 1) {
			imagex_error("The file `%s' contains %d images; Please "
				     "select one.", wimfile, num_images);
			usage(DIR);
			ret = -1;
			goto done;
		}
		image = 1;
	}

	ret = wimlib_print_files(w, image);
done:
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
	int compression_type = WIM_COMPRESSION_TYPE_NONE;
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
	ret = wimlib_open_wim(src_wimfile, open_flags, &src_w);
	if (ret != 0)
		return ret;

	/* Determine if the destination is an existing file or not.  
	 * If so, we try to append the exported image(s) to it; otherwise, we
	 * create a new WIM containing the exported image(s). */
	if (stat(dest_wimfile, &stbuf) == 0) {
		wim_is_new = false;
		/* Destination file exists. */
		if (!S_ISREG(stbuf.st_mode)) {
			imagex_error("`%s' is not a regular file",
					dest_wimfile);
			goto done;
		}
		ret = wimlib_open_wim(dest_wimfile, open_flags, &dest_w);
		if (ret != 0)
			goto done;

		if (compression_type_specified && compression_type != 
				wimlib_get_compression_type(dest_w)) {
			imagex_error("Cannot specify a compression type that is "
				     "not the same as that used in the "
				     "destination WIM");
			ret = -1;
			goto done;
		}
		compression_type = wimlib_get_compression_type(dest_w);
	} else {
		wim_is_new = true;
		/* dest_wimfile is not an existing file, so create a new WIM. */
		if (errno == ENOENT) {
			ret = wimlib_create_new_wim(compression_type, &dest_w);
			if (ret != 0)
				goto done;
		} else {
			imagex_error_with_errno("Cannot stat file `%s'",
						dest_wimfile);
			goto done;
		}
	}

	image = wimlib_resolve_image(src_w, src_image_num_or_name);
	ret = verify_image_exists(image);
	if (ret != 0)
		goto done;

	ret = wimlib_export_image(src_w, image, dest_w, dest_name, dest_desc, 
				  export_flags);
	if (ret != 0)
		goto done;


	if (wim_is_new)
		ret = wimlib_write(dest_w, dest_wimfile, WIM_ALL_IMAGES, 
				   write_flags);
	else
		ret = wimlib_overwrite(dest_w, write_flags);
done:
	wimlib_free(src_w);
	wimlib_free(dest_w);
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

	/*if (total_parts > 1 && part_number > 1) {*/
		/*printf("Warning: this is part %d of a %d-part split WIM.\n"*/
		       /*"         Select the first part if you want to see information\n"*/
		       /*"         about images in the WIM.\n", */
		       /*part_number, total_parts);*/
	/*}*/

	image = wimlib_resolve_image(w, image_num_or_name);
	if (image == WIM_NO_IMAGE && strcmp(image_num_or_name, "0") != 0) {
		imagex_error("The image `%s' does not exist", 
						image_num_or_name);
		if (boot)
			imagex_error("If you would like to set the boot "
				     "index to 0, specify image \"0\" with "
				     "the --boot flag.");
		ret = WIMLIB_ERR_INVALID_IMAGE;
		goto done;
	}

	if (image == WIM_ALL_IMAGES && wimlib_get_num_images(w) > 1) {
		if (boot) {
			imagex_error("Cannot specify the --boot flag "
				     "without specifying a specific "
				     "image in a multi-image WIM");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto done;
		}
		if (new_name) {
			imagex_error("Cannot specify the NEW_NAME "
				     "without specifying a specific "
				     "image in a multi-image WIM");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto done;
		}
	}

	/* Operations that print information are separated from operations that
	 * recreate the WIM file. */
	if (!new_name && !boot) {

		if (image == WIM_NO_IMAGE) {
			imagex_error("`%s' is not a valid image",
				     image_num_or_name);
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto done;
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
				goto done;
		}

		if (xml_out_file) {
			fp = fopen(xml_out_file, "wb");
			if (!fp) {
				imagex_error_with_errno("Failed to open the "
							"file `%s' for "
							"writing ",
							xml_out_file);
				goto done;
			}
			ret = wimlib_extract_xml_data(w, fp);
			if (fclose(fp) != 0) {
				imagex_error("Failed to close the file `%s'",
					     xml_out_file);
				goto done;
			}

			if (ret != 0)
				goto done;
		}

		if (short_header)
			wimlib_print_available_images(w, image);

		if (metadata) {
			if (total_parts != 1 && part_number != 1) {
				imagex_error("Select part 1 of this %d-part WIM "
					     "to see the image metadata",
					     total_parts);
				return WIMLIB_ERR_SPLIT_UNSUPPORTED;
			}
			ret = wimlib_print_metadata(w, image);
			if (ret != 0)
				goto done;
		}
	} else {
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
					goto done;
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
					goto done;
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

done:
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
	int open_flags = WIMLIB_OPEN_FLAG_SHOW_PROGRESS;
	const char *wimfile;
	const char *dir;
	WIMStruct *w;
	int image;
	int num_images;
	int ret;

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

	if (argc == 2) {
		image = 1;
		num_images = wimlib_get_num_images(w);
		if (num_images != 1) {
			imagex_error("The file `%s' contains %d images; Please "
				     "select one", wimfile, num_images);
			usage((mount_flags & WIMLIB_MOUNT_FLAG_READWRITE)  
					? MOUNTRW : MOUNT);
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto done;
		}
		dir = argv[1];
	} else {
		image = wimlib_resolve_image(w, argv[1]);
		dir = argv[2];
	}

	ret = verify_image_exists_and_is_single(image);
	if (ret != 0)
		goto done;

	ret = wimlib_mount(w, image, dir, mount_flags);
	if (ret != 0) {
		imagex_error("Failed to mount image %d from `%s' on `%s'",
			     image, wimfile, dir);

	}
done:
	wimlib_free(w);
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
	part_size = strtoul(argv[2], NULL, 10) * (1 << 20);
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

static struct imagex_command imagex_commands[] = {
	{"append",  imagex_append,	   APPEND},
	{"apply",   imagex_apply,   	   APPLY},
	{"capture", imagex_capture,	   CAPTURE},
	{"delete",  imagex_delete,	   DELETE},
	{"dir",     imagex_dir,		   DIR},
	{"export",  imagex_export,	   EXPORT},
	{"info",    imagex_info,	   INFO},
	{"join",    imagex_join,	   JOIN},
	{"mount",   imagex_mount_rw_or_ro, MOUNT},
	{"mountrw", imagex_mount_rw_or_ro, MOUNTRW},
	{"split",   imagex_split,          SPLIT},
	{"unmount", imagex_unmount,	   UNMOUNT},
};

#define for_imagex_command(p) for (p = &imagex_commands[0]; \
		p != &imagex_commands[ARRAY_LEN(imagex_commands)]; p++)

static void help_or_version(int argc, const char **argv)
{
	int i;
	const char *p;
	struct imagex_command *cmd;

	for (i = 1; i < argc; i++) {
		p = argv[i];
		if (*p == '-')
			p++;
		else
			continue;
		if (*p == '-')
			p++;
		if (strcmp(p, "help") == 0 || (*p == '?' && *(p + 1) == '\0')) {
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


int main(int argc, const char **argv)
{
	struct imagex_command *cmd;
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
/*#ifndef WITH_NTFS_3G*/
		/*ERROR("wimlib was not compiled with support for NTFS-3g, so we cannot extract");*/
		/*ERROR("a WIM to a NTFS filesystem while preserving NTFS-specific metadata.");*/
		/*ERROR("Please apply the WIM to a directory rather than a block device, ");*/
		/*ERROR("and without the NTFS flag; or compile in support for NTFS-3g.");*/
		/*return WIMLIB_ERR_UNSUPPORTED;*/
/*#endif*/
