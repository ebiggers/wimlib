/*
 * wim.c - Stuff that doesn't fit into any other file
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/error.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/file_io.h"
#include "wimlib/integrity.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#ifdef WITH_NTFS_3G
#  include "wimlib/ntfs_3g.h" /* for do_ntfs_umount() */
#endif
#include "wimlib/security.h"
#include "wimlib/wim.h"
#include "wimlib/xml.h"

#ifdef __WIN32__
#  include "wimlib/win32.h" /* for realpath() replacement */
#endif

#include <errno.h>
#include <fcntl.h>
#ifndef __WIN32__
#  include <langinfo.h>
#endif
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

static int
image_print_metadata(WIMStruct *wim)
{
	DEBUG("Printing metadata for image %d", wim->current_image);
	print_wim_security_data(wim_security_data(wim));
	return for_dentry_in_tree(wim_root_dentry(wim), print_dentry,
				  wim->lookup_table);
}


static int
image_print_files(WIMStruct *wim)
{
	return for_dentry_in_tree(wim_root_dentry(wim), print_dentry_full_path,
				  NULL);
}

static WIMStruct *
new_wim_struct(void)
{
	WIMStruct *wim = CALLOC(1, sizeof(WIMStruct));
	if (wim) {
		wim->in_fd.fd = -1;
		wim->out_fd.fd = -1;
	}
	return wim;
}

/*
 * Calls a function on images in the WIM.  If @image is WIMLIB_ALL_IMAGES, @visitor
 * is called on the WIM once for each image, with each image selected as the
 * current image in turn.  If @image is a certain image, @visitor is called on
 * the WIM only once, with that image selected.
 */
int
for_image(WIMStruct *wim, int image, int (*visitor)(WIMStruct *))
{
	int ret;
	int start;
	int end;
	int i;

	if (image == WIMLIB_ALL_IMAGES) {
		start = 1;
		end = wim->hdr.image_count;
	} else if (image >= 1 && image <= wim->hdr.image_count) {
		start = image;
		end = image;
	} else {
		return WIMLIB_ERR_INVALID_IMAGE;
	}
	for (i = start; i <= end; i++) {
		ret = select_wim_image(wim, i);
		if (ret != 0)
			return ret;
		ret = visitor(wim);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_create_new_wim(int ctype, WIMStruct **wim_ret)
{
	WIMStruct *wim;
	struct wim_lookup_table *table;
	int ret;

	wimlib_global_init(WIMLIB_INIT_FLAG_ASSUME_UTF8);

	DEBUG("Creating new WIM with %"TS" compression.",
	      wimlib_get_compression_type_string(ctype));

	/* Allocate the WIMStruct. */
	wim = new_wim_struct();
	if (!wim)
		return WIMLIB_ERR_NOMEM;

	ret = init_wim_header(&wim->hdr, ctype);
	if (ret != 0)
		goto out_free;

	table = new_lookup_table(9001);
	if (!table) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free;
	}
	wim->lookup_table = table;
	wim->refcnts_ok = 1;
	wim->compression_type = ctype;
	*wim_ret = wim;
	return 0;
out_free:
	FREE(wim);
	return ret;
}

int
select_wim_image(WIMStruct *wim, int image)
{
	struct wim_image_metadata *imd;
	int ret;

	DEBUG("Selecting image %d", image);

	if (image == WIMLIB_NO_IMAGE) {
		ERROR("Invalid image: %d", WIMLIB_NO_IMAGE);
		return WIMLIB_ERR_INVALID_IMAGE;
	}

	if (image == wim->current_image)
		return 0;

	if (image < 1 || image > wim->hdr.image_count) {
		ERROR("Cannot select image %d: There are only %u images",
		      image, wim->hdr.image_count);
		return WIMLIB_ERR_INVALID_IMAGE;
	}

	if (wim->hdr.part_number != 1) {
		ERROR("Cannot select an image from a non-first part of a split WIM");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	/* If a valid image is currently selected, it can be freed if it is not
	 * modified.  */
	if (wim->current_image != WIMLIB_NO_IMAGE) {
		imd = wim_get_current_image_metadata(wim);
		if (!imd->modified) {
			wimlib_assert(list_empty(&imd->unhashed_streams));
			DEBUG("Freeing image %u", wim->current_image);
			destroy_image_metadata(imd, NULL, false);
		}
	}
	wim->current_image = image;
	imd = wim_get_current_image_metadata(wim);
	if (imd->root_dentry || imd->modified) {
		ret = 0;
	} else {
		#ifdef ENABLE_DEBUG
		DEBUG("Reading metadata resource specified by the following "
		      "lookup table entry:");
		print_lookup_table_entry(imd->metadata_lte, stderr);
		#endif
		ret = read_metadata_resource(wim, imd);
		if (ret)
			wim->current_image = WIMLIB_NO_IMAGE;
	}
	return ret;
}


/* API function documented in wimlib.h  */
WIMLIBAPI const tchar *
wimlib_get_compression_type_string(int ctype)
{
	switch (ctype) {
		case WIMLIB_COMPRESSION_TYPE_NONE:
			return T("None");
		case WIMLIB_COMPRESSION_TYPE_LZX:
			return T("LZX");
		case WIMLIB_COMPRESSION_TYPE_XPRESS:
			return T("XPRESS");
		default:
			return T("Invalid");
	}
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_resolve_image(WIMStruct *wim, const tchar *image_name_or_num)
{
	tchar *p;
	long image;
	int i;

	if (!image_name_or_num || !*image_name_or_num)
		return WIMLIB_NO_IMAGE;

	if (!tstrcasecmp(image_name_or_num, T("all"))
	    || !tstrcasecmp(image_name_or_num, T("*")))
		return WIMLIB_ALL_IMAGES;
	image = tstrtol(image_name_or_num, &p, 10);
	if (p != image_name_or_num && *p == T('\0') && image > 0) {
		if (image > wim->hdr.image_count)
			return WIMLIB_NO_IMAGE;
		return image;
	} else {
		for (i = 1; i <= wim->hdr.image_count; i++) {
			if (!tstrcmp(image_name_or_num,
				     wimlib_get_image_name(wim, i)))
				return i;
		}
		return WIMLIB_NO_IMAGE;
	}
}

/* API function documented in wimlib.h  */
WIMLIBAPI void
wimlib_print_wim_information(const WIMStruct *wim)
{
	struct wimlib_wim_info info;

	wimlib_get_wim_info((WIMStruct*)wim, &info);

	tputs(T("WIM Information:"));
	tputs(T("----------------"));
	tprintf(T("Path:           %"TS"\n"), wim->filename);
	tfputs(T("GUID:           0x"), stdout);
	print_byte_field(info.guid, WIM_GID_LEN, stdout);
	tputchar(T('\n'));
	tprintf(T("Image Count:    %d\n"), info.image_count);
	tprintf(T("Compression:    %"TS"\n"),
		wimlib_get_compression_type_string(info.compression_type));
	tprintf(T("Part Number:    %d/%d\n"), info.part_number, info.total_parts);
	tprintf(T("Boot Index:     %d\n"), info.boot_index);
	tprintf(T("Size:           %"PRIu64" bytes\n"), info.total_bytes);
	tprintf(T("Integrity Info: %"TS"\n"),
		info.has_integrity_table ? T("yes") : T("no"));
	tprintf(T("Relative path junction: %"TS"\n"),
		info.has_rpfix ? T("yes") : T("no"));
	tputchar(T('\n'));
}

/* API function documented in wimlib.h  */
WIMLIBAPI void
wimlib_print_available_images(const WIMStruct *wim, int image)
{
	int first;
	int last;
	int i;
	int n;
	if (image == WIMLIB_ALL_IMAGES) {
		n = tprintf(T("Available Images:\n"));
		first = 1;
		last = wim->hdr.image_count;
	} else if (image >= 1 && image <= wim->hdr.image_count) {
		n = tprintf(T("Information for Image %d\n"), image);
		first = image;
		last = image;
	} else {
		tprintf(T("wimlib_print_available_images(): Invalid image %d"),
			image);
		return;
	}
	for (i = 0; i < n - 1; i++)
		tputchar(T('-'));
	tputchar(T('\n'));
	for (i = first; i <= last; i++)
		print_image_info(wim->wim_info, i);
}


/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_print_metadata(WIMStruct *wim, int image)
{
	if (wim->hdr.part_number != 1) {
		ERROR("Cannot show the metadata from part %hu of a %hu-part split WIM!",
		       wim->hdr.part_number, wim->hdr.total_parts);
		ERROR("Select the first part of the split WIM to see the metadata.");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}
	return for_image(wim, image, image_print_metadata);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_print_files(WIMStruct *wim, int image)
{
	if (wim->hdr.part_number != 1) {
		ERROR("Cannot list the files from part %hu of a %hu-part split WIM!",
		       wim->hdr.part_number, wim->hdr.total_parts);
		ERROR("Select the first part of the split WIM if you'd like to list the files.");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}
	return for_image(wim, image, image_print_files);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_get_wim_info(WIMStruct *wim, struct wimlib_wim_info *info)
{
	memset(info, 0, sizeof(struct wimlib_wim_info));
	memcpy(info->guid, wim->hdr.guid, WIMLIB_GUID_LEN);
	info->image_count = wim->hdr.image_count;
	info->boot_index = wim->hdr.boot_idx;
	info->wim_version = WIM_VERSION;
	info->chunk_size = WIM_CHUNK_SIZE;
	info->part_number = wim->hdr.part_number;
	info->total_parts = wim->hdr.total_parts;
	info->compression_type = wim->compression_type;
	info->total_bytes = wim_info_get_total_bytes(wim->wim_info);
	info->has_integrity_table = wim_has_integrity_table(wim);
	info->opened_from_file = (wim->filename != NULL);
	info->is_readonly = (wim->hdr.flags & WIM_HDR_FLAG_READONLY) ||
			     (wim->hdr.total_parts != 1) ||
			     (wim->filename && taccess(wim->filename, W_OK));
	info->has_rpfix = (wim->hdr.flags & WIM_HDR_FLAG_RP_FIX) != 0;
	info->is_marked_readonly = (wim->hdr.flags & WIM_HDR_FLAG_READONLY) != 0;
	info->write_in_progress = (wim->hdr.flags & WIM_HDR_FLAG_WRITE_IN_PROGRESS) != 0;
	info->metadata_only = (wim->hdr.flags & WIM_HDR_FLAG_METADATA_ONLY) != 0;
	info->resource_only = (wim->hdr.flags & WIM_HDR_FLAG_RESOURCE_ONLY) != 0;
	info->spanned = (wim->hdr.flags & WIM_HDR_FLAG_SPANNED) != 0;
	info->pipable = wim_is_pipable(wim);
	return 0;
}


/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_get_boot_idx(const WIMStruct *wim)
{
	struct wimlib_wim_info info;

	wimlib_get_wim_info((WIMStruct*)wim, &info);
	return info.boot_index;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_get_compression_type(const WIMStruct *wim)
{
	struct wimlib_wim_info info;

	wimlib_get_wim_info((WIMStruct*)wim, &info);
	return info.compression_type;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_get_num_images(const WIMStruct *wim)
{
	struct wimlib_wim_info info;

	wimlib_get_wim_info((WIMStruct*)wim, &info);
	return info.image_count;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_get_part_number(const WIMStruct *wim, int *total_parts_ret)
{
	struct wimlib_wim_info info;

	wimlib_get_wim_info((WIMStruct*)wim, &info);
	if (total_parts_ret)
		*total_parts_ret = info.total_parts;
	return info.part_number;
}

/* API function documented in wimlib.h  */
WIMLIBAPI bool
wimlib_has_integrity_table(const WIMStruct *wim)
{
	struct wimlib_wim_info info;

	wimlib_get_wim_info((WIMStruct*)wim, &info);
	return info.has_integrity_table;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_wim_info(WIMStruct *wim, const struct wimlib_wim_info *info, int which)
{
	int ret;

	if (which & WIMLIB_CHANGE_READONLY_FLAG) {
		if (info->is_marked_readonly)
			wim->hdr.flags |= WIM_HDR_FLAG_READONLY;
		else
			wim->hdr.flags &= ~WIM_HDR_FLAG_READONLY;
	}

	if ((which & ~WIMLIB_CHANGE_READONLY_FLAG) == 0)
		return 0;

	ret = can_modify_wim(wim);
	if (ret)
		return ret;

	if (which & WIMLIB_CHANGE_GUID)
		memcpy(wim->hdr.guid, info->guid, WIM_GID_LEN);

	if (which & WIMLIB_CHANGE_BOOT_INDEX) {
		if (info->boot_index > wim->hdr.image_count) {
			ERROR("%u is not 0 or a valid image in the WIM to mark as bootable",
			      info->boot_index);
			return WIMLIB_ERR_INVALID_IMAGE;
		}
		wim->hdr.boot_idx = info->boot_index;
	}

	if (which & WIMLIB_CHANGE_RPFIX_FLAG) {
		if (info->has_rpfix)
			wim->hdr.flags |= WIM_HDR_FLAG_RP_FIX;
		else
			wim->hdr.flags &= ~WIM_HDR_FLAG_RP_FIX;
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_boot_idx(WIMStruct *wim, int boot_idx)
{
	struct wimlib_wim_info info;

	info.boot_index = boot_idx;
	return wimlib_set_wim_info(wim, &info, WIMLIB_CHANGE_BOOT_INDEX);
}

static int
do_open_wim(const tchar *filename, struct filedes *fd_ret)
{
	int raw_fd;

	raw_fd = topen(filename, O_RDONLY | O_BINARY);
	if (raw_fd < 0) {
		ERROR_WITH_ERRNO("Can't open \"%"TS"\" read-only", filename);
		return WIMLIB_ERR_OPEN;
	}
	filedes_init(fd_ret, raw_fd);
	return 0;
}

int
reopen_wim(WIMStruct *wim)
{
	wimlib_assert(!filedes_valid(&wim->in_fd));
	return do_open_wim(wim->filename, &wim->in_fd);
}

int
close_wim(WIMStruct *wim)
{
	if (filedes_valid(&wim->in_fd)) {
		filedes_close(&wim->in_fd);
		filedes_invalidate(&wim->in_fd);
	}
	return 0;
}

/*
 * Begins the reading of a WIM file; opens the file and reads its header and
 * lookup table, and optionally checks the integrity.
 */
static int
begin_read(WIMStruct *wim, const void *wim_filename_or_fd,
	   int open_flags, wimlib_progress_func_t progress_func)
{
	int ret;
	int xml_num_images;
	const tchar *wimfile;

	if (open_flags & WIMLIB_OPEN_FLAG_FROM_PIPE) {
		wimfile = NULL;
		filedes_init(&wim->in_fd, *(const int*)wim_filename_or_fd);
		wim->in_fd.is_pipe = 1;
	} else {
		wimfile = wim_filename_or_fd;
		DEBUG("Reading the WIM file `%"TS"'", wimfile);
		ret = do_open_wim(wimfile, &wim->in_fd);
		if (ret)
			return ret;

		/* The absolute path to the WIM is requested so that
		 * wimlib_overwrite() still works even if the process changes
		 * its working directory.  This actually happens if a WIM is
		 * mounted read-write, since the FUSE thread changes directory
		 * to "/", and it needs to be able to find the WIM file again.
		 *
		 * This will break if the full path to the WIM changes in the
		 * intervening time...
		 *
		 * Warning: in Windows native builds, realpath() calls the
		 * replacement function in win32.c.
		 */
		wim->filename = realpath(wimfile, NULL);
		if (!wim->filename) {
			ERROR_WITH_ERRNO("Failed to resolve WIM filename");
			if (errno == ENOMEM)
				return WIMLIB_ERR_NOMEM;
			else
				return WIMLIB_ERR_OPEN;
		}
	}

	ret = read_wim_header(wim->filename, &wim->in_fd, &wim->hdr);
	if (ret)
		return ret;

	if (wim->hdr.flags & WIM_HDR_FLAG_WRITE_IN_PROGRESS) {
		WARNING("The WIM_HDR_FLAG_WRITE_IN_PROGRESS is set in the header of \"%"TS"\".\n"
			"          It may be being changed by another process, or a process\n"
			"          may have crashed while writing the WIM.", wimfile);
	}

	if (open_flags & WIMLIB_OPEN_FLAG_WRITE_ACCESS) {
		ret = can_modify_wim(wim);
		if (ret)
			return ret;
	}

	if (wim->hdr.total_parts != 1 && !(open_flags & WIMLIB_OPEN_FLAG_SPLIT_OK)) {
		ERROR("\"%"TS"\": This WIM is part %u of a %u-part WIM",
		      wimfile, wim->hdr.part_number, wim->hdr.total_parts);
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	DEBUG("According to header, WIM contains %u images", wim->hdr.image_count);

	/* If the boot index is invalid, print a warning and set it to 0 */
	if (wim->hdr.boot_idx > wim->hdr.image_count) {
		WARNING("In `%"TS"', image %u is marked as bootable, "
			"but there are only %u images in the WIM",
			wimfile, wim->hdr.boot_idx, wim->hdr.image_count);
		wim->hdr.boot_idx = 0;
	}

	/* Check and cache the compression type */
	if (wim->hdr.flags & WIM_HDR_FLAG_COMPRESSION) {
		if (wim->hdr.flags & WIM_HDR_FLAG_COMPRESS_LZX) {
			if (wim->hdr.flags & WIM_HDR_FLAG_COMPRESS_XPRESS) {
				ERROR("Multiple compression flags are set in \"%"TS"\"",
				      wimfile);
				return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
			}
			wim->compression_type = WIMLIB_COMPRESSION_TYPE_LZX;
		} else if (wim->hdr.flags & WIM_HDR_FLAG_COMPRESS_XPRESS) {
			wim->compression_type = WIMLIB_COMPRESSION_TYPE_XPRESS;
		} else {
			ERROR("The compression flag is set on \"%"TS"\", but "
			      "neither the XPRESS nor LZX flag is set",
			      wimfile);
			return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
		}
	} else {
		wim->compression_type = WIMLIB_COMPRESSION_TYPE_NONE;
	}

	if (open_flags & WIMLIB_OPEN_FLAG_CHECK_INTEGRITY) {
		ret = check_wim_integrity(wim, progress_func);
		if (ret == WIM_INTEGRITY_NONEXISTENT) {
			WARNING("No integrity information for `%"TS"'; skipping "
				"integrity check.", wimfile);
		} else if (ret == WIM_INTEGRITY_NOT_OK) {
			ERROR("WIM is not intact! (Failed integrity check)");
			return WIMLIB_ERR_INTEGRITY;
		} else if (ret != WIM_INTEGRITY_OK) {
			return ret;
		}
	}

	if (wim->hdr.image_count != 0 && wim->hdr.part_number == 1) {
		wim->image_metadata = new_image_metadata_array(wim->hdr.image_count);
		if (!wim->image_metadata)
			return WIMLIB_ERR_NOMEM;
	}

	if (open_flags & WIMLIB_OPEN_FLAG_FROM_PIPE) {
		wim->lookup_table = new_lookup_table(9001);
		if (!wim->lookup_table)
			return WIMLIB_ERR_NOMEM;
	} else {
		ret = read_wim_lookup_table(wim);
		if (ret)
			return ret;

		ret = read_wim_xml_data(wim);
		if (ret)
			return ret;

		xml_num_images = wim_info_get_num_images(wim->wim_info);
		if (xml_num_images != wim->hdr.image_count) {
			ERROR("In the file `%"TS"', there are %u <IMAGE> elements "
			      "in the XML data,", wimfile, xml_num_images);
			ERROR("but %u images in the WIM!  There must be exactly one "
			      "<IMAGE> element per image.", wim->hdr.image_count);
			return WIMLIB_ERR_IMAGE_COUNT;
		}
		DEBUG("Done beginning read of WIM file `%"TS"'.", wimfile);
	}
	return 0;
}

int
open_wim_as_WIMStruct(const void *wim_filename_or_fd, int open_flags,
		      WIMStruct **wim_ret, wimlib_progress_func_t progress_func)
{
	WIMStruct *wim;
	int ret;

	wimlib_global_init(WIMLIB_INIT_FLAG_ASSUME_UTF8);

	ret = WIMLIB_ERR_INVALID_PARAM;
	if (!wim_ret)
		goto out;

	ret = WIMLIB_ERR_NOMEM;
	wim = new_wim_struct();
	if (!wim)
		goto out;

	ret = begin_read(wim, wim_filename_or_fd, open_flags, progress_func);
	if (ret)
		goto out_wimlib_free;

	ret = 0;
	*wim_ret = wim;
	goto out;
out_wimlib_free:
	wimlib_free(wim);
out:
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_open_wim(const tchar *wimfile, int open_flags,
		WIMStruct **wim_ret, wimlib_progress_func_t progress_func)
{
	open_flags &= WIMLIB_OPEN_MASK_PUBLIC;
	return open_wim_as_WIMStruct(wimfile, open_flags, wim_ret,
				     progress_func);
}

void
destroy_image_metadata(struct wim_image_metadata *imd,
		       struct wim_lookup_table *table,
		       bool free_metadata_lte)
{
	free_dentry_tree(imd->root_dentry, table);
	imd->root_dentry = NULL;
	free_wim_security_data(imd->security_data);
	imd->security_data = NULL;

	if (free_metadata_lte) {
		free_lookup_table_entry(imd->metadata_lte);
		imd->metadata_lte = NULL;
	}
	if (!table) {
		struct wim_lookup_table_entry *lte, *tmp;
		list_for_each_entry_safe(lte, tmp, &imd->unhashed_streams, unhashed_list)
			free_lookup_table_entry(lte);
	}
	INIT_LIST_HEAD(&imd->unhashed_streams);
	INIT_LIST_HEAD(&imd->inode_list);
#ifdef WITH_NTFS_3G
	if (imd->ntfs_vol) {
		do_ntfs_umount(imd->ntfs_vol);
		imd->ntfs_vol = NULL;
	}
#endif
}

void
put_image_metadata(struct wim_image_metadata *imd,
		   struct wim_lookup_table *table)
{
	if (imd && --imd->refcnt == 0) {
		destroy_image_metadata(imd, table, true);
		FREE(imd);
	}
}

/* Appends the specified image metadata structure to the array of image metadata
 * for a WIM, and increments the image count. */
int
append_image_metadata(WIMStruct *wim, struct wim_image_metadata *imd)
{
	struct wim_image_metadata **imd_array;

	DEBUG("Reallocating image metadata array for image_count = %u",
	      wim->hdr.image_count + 1);
	imd_array = REALLOC(wim->image_metadata,
			    sizeof(wim->image_metadata[0]) * (wim->hdr.image_count + 1));

	if (!imd_array)
		return WIMLIB_ERR_NOMEM;
	wim->image_metadata = imd_array;
	imd_array[wim->hdr.image_count++] = imd;
	return 0;
}


struct wim_image_metadata *
new_image_metadata(void)
{
	struct wim_image_metadata *imd;

	imd = CALLOC(1, sizeof(*imd));
	if (imd) {
		imd->refcnt = 1;
		INIT_LIST_HEAD(&imd->inode_list);
		INIT_LIST_HEAD(&imd->unhashed_streams);
		DEBUG("Created new image metadata (refcnt=1)");
	} else {
		ERROR_WITH_ERRNO("Failed to allocate new image metadata structure");
	}
	return imd;
}

struct wim_image_metadata **
new_image_metadata_array(unsigned num_images)
{
	struct wim_image_metadata **imd_array;

	DEBUG("Creating new image metadata array for %u images",
	      num_images);

	imd_array = CALLOC(num_images, sizeof(imd_array[0]));

	if (!imd_array) {
		ERROR("Failed to allocate memory for %u image metadata structures",
		      num_images);
		return NULL;
	}
	for (unsigned i = 0; i < num_images; i++) {
		imd_array[i] = new_image_metadata();
		if (!imd_array[i]) {
			for (unsigned j = 0; j < i; j++)
				put_image_metadata(imd_array[j], NULL);
			FREE(imd_array);
			return NULL;
		}
	}
	return imd_array;
}

/* Checksum all streams that are unhashed (other than the metadata streams),
 * merging them into the lookup table as needed.  This is a no-op unless the
 * library has previously used to add or mount an image using the same
 * WIMStruct. */
int
wim_checksum_unhashed_streams(WIMStruct *wim)
{
	int ret;
	for (int i = 0; i < wim->hdr.image_count; i++) {
		struct wim_lookup_table_entry *lte, *tmp;
		struct wim_image_metadata *imd = wim->image_metadata[i];
		image_for_each_unhashed_stream_safe(lte, tmp, imd) {
			ret = hash_unhashed_stream(lte, wim->lookup_table, NULL);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/*
 * can_modify_wim - Check if a given WIM is writeable.  This is only the case if
 * it meets the following three conditions:
 *
 * 1. Write access is allowed to the underlying file (if any) at the filesystem level.
 * 2. The WIM is not part of a spanned set.
 * 3. The WIM_HDR_FLAG_READONLY flag is not set in the WIM header.
 *
 * Return value is 0 if writable; WIMLIB_ERR_WIM_IS_READONLY otherwise.
 */
int
can_modify_wim(WIMStruct *wim)
{
	if (wim->filename) {
		if (taccess(wim->filename, W_OK)) {
			ERROR_WITH_ERRNO("Can't modify \"%"TS"\"", wim->filename);
			return WIMLIB_ERR_WIM_IS_READONLY;
		}
	}
	if (wim->hdr.total_parts != 1) {
		ERROR("Cannot modify \"%"TS"\": is part of a spanned set",
		      wim->filename);
		return WIMLIB_ERR_WIM_IS_READONLY;
	}
	if (wim->hdr.flags & WIM_HDR_FLAG_READONLY) {
		ERROR("Cannot modify \"%"TS"\": is marked read-only",
		      wim->filename);
		return WIMLIB_ERR_WIM_IS_READONLY;
	}
	return 0;
}

/*
 * can_delete_from_wim - Check if files or images can be deleted from a given
 * WIM file.
 *
 * This theoretically should be exactly the same as can_modify_wim(), but
 * unfortunately, due to bugs in Microsoft's software that generate incorrect
 * reference counts for some WIM resources, we need to run expensive
 * verifications to make sure the reference counts are correct on all WIM
 * resources.  Otherwise we might delete a WIM resource whose reference count
 * has fallen to 0, but is actually still referenced somewhere.
 */
int
can_delete_from_wim(WIMStruct *wim)
{
	int ret;

	ret = can_modify_wim(wim);
	if (ret)
		return ret;
	if (!wim->refcnts_ok)
		wim_recalculate_refcnts(wim);
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI void
wimlib_free(WIMStruct *wim)
{
	DEBUG("Freeing WIMStruct");

	if (!wim)
		return;
	if (wim->in_fd.fd != -1)
		close(wim->in_fd.fd);
	if (wim->out_fd.fd != -1)
		close(wim->out_fd.fd);

	free_lookup_table(wim->lookup_table);

	FREE(wim->filename);
	free_wim_info(wim->wim_info);
	if (wim->image_metadata) {
		for (unsigned i = 0; i < wim->hdr.image_count; i++)
			put_image_metadata(wim->image_metadata[i], NULL);
		FREE(wim->image_metadata);
	}
	FREE(wim);
	DEBUG("Freed WIMStruct");
}

static bool
test_locale_ctype_utf8(void)
{
#ifdef __WIN32__
	return false;
#else
	char *ctype = nl_langinfo(CODESET);

	return (!strstr(ctype, "UTF-8") ||
		!strstr(ctype, "UTF8") ||
		!strstr(ctype, "utf8") ||
		!strstr(ctype, "utf-8"));
#endif
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_global_init(int init_flags)
{
	static bool already_inited = false;

	if (already_inited)
		return 0;
	libxml_global_init();
	if (!(init_flags & WIMLIB_INIT_FLAG_ASSUME_UTF8)) {
		wimlib_mbs_is_utf8 = test_locale_ctype_utf8();
	#ifdef WITH_NTFS_3G
		if (!wimlib_mbs_is_utf8)
			libntfs3g_global_init();
	#endif
	}
#ifdef __WIN32__
	win32_global_init(init_flags);
#endif
	already_inited = true;
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI void
wimlib_global_cleanup(void)
{
	libxml_global_cleanup();
	iconv_global_cleanup();
#ifdef __WIN32__
	win32_global_cleanup();
#endif
}
