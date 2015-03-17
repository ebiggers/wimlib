/*
 * wim.c - High-level code dealing with WIMStructs and images.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#ifndef __WIN32__
#  include <langinfo.h>
#endif
#include <stdlib.h>
#include <unistd.h>

#include "wimlib.h"
#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/bitops.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/file_io.h"
#include "wimlib/integrity.h"
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

static int
wim_default_solid_compression_type(void)
{
	return WIMLIB_COMPRESSION_TYPE_LZMS;
}

static u32
wim_default_solid_chunk_size(int ctype) {
	switch (ctype) {
	case WIMLIB_COMPRESSION_TYPE_LZMS:
		return (u32)1 << 26; /* 67108864  */
	default:
		return (u32)1 << 15; /* 32768     */
	}
}

static WIMStruct *
new_wim_struct(void)
{
	WIMStruct *wim = CALLOC(1, sizeof(WIMStruct));
	if (!wim)
		return NULL;

	filedes_invalidate(&wim->in_fd);
	filedes_invalidate(&wim->out_fd);
	wim->out_solid_compression_type = wim_default_solid_compression_type();
	wim->out_solid_chunk_size = wim_default_solid_chunk_size(
					wim->out_solid_compression_type);
	INIT_LIST_HEAD(&wim->subwims);
	return wim;
}

/* Determine if the chunk size is valid for the specified compression type.  */
static bool
wim_chunk_size_valid(u32 chunk_size, int ctype)
{
	u32 order;

	/* Chunk size is meaningless for uncompressed WIMs --- any value is
	 * okay.  */
	if (ctype == WIMLIB_COMPRESSION_TYPE_NONE)
		return true;

	/* Chunk size must be power of 2.  */
	if (chunk_size == 0)
		return false;
	order = fls32(chunk_size);
	if (chunk_size != 1U << order)
		return false;

	/* Order	Size
	 * =====	====
	 * 15		32768
	 * 16		65536
	 * 17		131072
	 * 18		262144
	 * 19		524288
	 * 20		1048576
	 * 21		2097152
	 * 22		4194304
	 * 23		8388608
	 * 24		16777216
	 * 25		33554432
	 * 26		67108864
	 */

	/* See the documentation for the --chunk-size option of `wimlib-imagex
	 * capture' for information about allowed chunk sizes.  */
	switch (ctype) {
	case WIMLIB_COMPRESSION_TYPE_LZX:
		return order >= 15 && order <= 21;
	case WIMLIB_COMPRESSION_TYPE_XPRESS:
		return order >= 12 && order <= 16;
	case WIMLIB_COMPRESSION_TYPE_LZMS:
		return order >= 15 && order <= 30;
	}
	return false;
}

/* Return the default chunk size to use for the specified compression type.
 *
 * See notes above in wim_chunk_size_valid().  */
static u32
wim_default_chunk_size(int ctype)
{
	switch (ctype) {
	case WIMLIB_COMPRESSION_TYPE_LZMS:
		return 1U << 17; /* 131072  */
	default:
		return 1U << 15; /* 32768   */
	}
}

/*
 * Calls a function on images in the WIM.  If @image is WIMLIB_ALL_IMAGES,
 * @visitor is called on the WIM once for each image, with each image selected
 * as the current image in turn.  If @image is a certain image, @visitor is
 * called on the WIM only once, with that image selected.
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
	int ret;

	ret = wimlib_global_init(WIMLIB_INIT_FLAG_ASSUME_UTF8);
	if (ret)
		return ret;

	wim = new_wim_struct();
	if (!wim)
		return WIMLIB_ERR_NOMEM;

	ret = init_wim_header(&wim->hdr, ctype, wim_default_chunk_size(ctype));
	if (ret)
		goto out_free_wim;

	wim->blob_table = new_blob_table(9001);
	if (!wim->blob_table) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_wim;
	}
	wim->compression_type = ctype;
	wim->out_compression_type = ctype;
	wim->chunk_size = wim->hdr.chunk_size;
	wim->out_chunk_size = wim->hdr.chunk_size;
	*wim_ret = wim;
	return 0;

out_free_wim:
	FREE(wim);
	return ret;
}

static void
destroy_image_metadata(struct wim_image_metadata *imd,
		       struct blob_table *table,
		       bool free_metadata_blob_descriptor)
{
	free_dentry_tree(imd->root_dentry, table);
	imd->root_dentry = NULL;
	free_wim_security_data(imd->security_data);
	imd->security_data = NULL;

	if (free_metadata_blob_descriptor) {
		free_blob_descriptor(imd->metadata_blob);
		imd->metadata_blob = NULL;
	}
	if (!table) {
		struct blob_descriptor *blob, *tmp;
		list_for_each_entry_safe(blob, tmp, &imd->unhashed_blobs, unhashed_list)
			free_blob_descriptor(blob);
	}
	INIT_LIST_HEAD(&imd->unhashed_blobs);
	INIT_LIST_HEAD(&imd->inode_list);
#ifdef WITH_NTFS_3G
	if (imd->ntfs_vol) {
		do_ntfs_umount(imd->ntfs_vol);
		imd->ntfs_vol = NULL;
	}
#endif
}

void
put_image_metadata(struct wim_image_metadata *imd, struct blob_table *table)
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
		INIT_LIST_HEAD(&imd->unhashed_blobs);
	}
	return imd;
}

static struct wim_image_metadata **
new_image_metadata_array(unsigned num_images)
{
	struct wim_image_metadata **imd_array;

	imd_array = CALLOC(num_images, sizeof(imd_array[0]));

	if (!imd_array)
		return NULL;
	for (unsigned i = 0; i < num_images; i++) {
		imd_array[i] = new_image_metadata();
		if (unlikely(!imd_array[i])) {
			for (unsigned j = 0; j < i; j++)
				put_image_metadata(imd_array[j], NULL);
			FREE(imd_array);
			return NULL;
		}
	}
	return imd_array;
}


/*
 * Load the metadata for the specified WIM image into memory and set it
 * as the WIMStruct's currently selected image.
 *
 * @wim
 *	The WIMStruct for the WIM.
 * @image
 *	The 1-based index of the image in the WIM to select.
 *
 * On success, 0 will be returned, wim->current_image will be set to
 * @image, and wim_get_current_image_metadata() can be used to retrieve
 * metadata information for the image.
 *
 * On failure, WIMLIB_ERR_INVALID_IMAGE, WIMLIB_ERR_METADATA_NOT_FOUND,
 * or another error code will be returned.
 */
int
select_wim_image(WIMStruct *wim, int image)
{
	struct wim_image_metadata *imd;
	int ret;

	if (image == WIMLIB_NO_IMAGE)
		return WIMLIB_ERR_INVALID_IMAGE;

	if (image == wim->current_image)
		return 0;

	if (image < 1 || image > wim->hdr.image_count)
		return WIMLIB_ERR_INVALID_IMAGE;

	if (!wim_has_metadata(wim))
		return WIMLIB_ERR_METADATA_NOT_FOUND;

	/* If a valid image is currently selected, its metadata can be freed if
	 * it has not been modified.  */
	deselect_current_wim_image(wim);
	wim->current_image = image;
	imd = wim_get_current_image_metadata(wim);
	if (imd->root_dentry || imd->modified) {
		ret = 0;
	} else {
		ret = read_metadata_resource(imd);
		if (ret)
			wim->current_image = WIMLIB_NO_IMAGE;
	}
	return ret;
}

void
deselect_current_wim_image(WIMStruct *wim)
{
	struct wim_image_metadata *imd;
	if (wim->current_image == WIMLIB_NO_IMAGE)
		return;
	imd = wim_get_current_image_metadata(wim);
	if (!imd->modified) {
		wimlib_assert(list_empty(&imd->unhashed_blobs));
		destroy_image_metadata(imd, NULL, false);
	}
	wim->current_image = WIMLIB_NO_IMAGE;
}

/* API function documented in wimlib.h  */
WIMLIBAPI const tchar *
wimlib_get_compression_type_string(int ctype)
{
	switch (ctype) {
	case WIMLIB_COMPRESSION_TYPE_NONE:
		return T("None");
	case WIMLIB_COMPRESSION_TYPE_XPRESS:
		return T("XPRESS");
	case WIMLIB_COMPRESSION_TYPE_LZX:
		return T("LZX");
	case WIMLIB_COMPRESSION_TYPE_LZMS:
		return T("LZMS");
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
wimlib_get_wim_info(WIMStruct *wim, struct wimlib_wim_info *info)
{
	memset(info, 0, sizeof(struct wimlib_wim_info));
	memcpy(info->guid, wim->hdr.guid, WIMLIB_GUID_LEN);
	info->image_count = wim->hdr.image_count;
	info->boot_index = wim->hdr.boot_idx;
	info->wim_version = wim->hdr.wim_version;
	info->chunk_size = wim->chunk_size;
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
wimlib_set_wim_info(WIMStruct *wim, const struct wimlib_wim_info *info, int which)
{
	if (which & ~(WIMLIB_CHANGE_READONLY_FLAG |
		      WIMLIB_CHANGE_GUID |
		      WIMLIB_CHANGE_BOOT_INDEX |
		      WIMLIB_CHANGE_RPFIX_FLAG))
		return WIMLIB_ERR_INVALID_PARAM;

	if ((which & WIMLIB_CHANGE_BOOT_INDEX) &&
	    info->boot_index > wim->hdr.image_count)
		return WIMLIB_ERR_INVALID_IMAGE;

	if (which & WIMLIB_CHANGE_READONLY_FLAG) {
		if (info->is_marked_readonly)
			wim->hdr.flags |= WIM_HDR_FLAG_READONLY;
		else
			wim->hdr.flags &= ~WIM_HDR_FLAG_READONLY;
	}

	if (which & WIMLIB_CHANGE_GUID)
		memcpy(wim->hdr.guid, info->guid, WIM_GUID_LEN);

	if (which & WIMLIB_CHANGE_BOOT_INDEX)
		wim->hdr.boot_idx = info->boot_index;

	if (which & WIMLIB_CHANGE_RPFIX_FLAG) {
		if (info->has_rpfix)
			wim->hdr.flags |= WIM_HDR_FLAG_RP_FIX;
		else
			wim->hdr.flags &= ~WIM_HDR_FLAG_RP_FIX;
	}
	return 0;
}

static int
set_out_ctype(int ctype, u8 *out_ctype_p)
{
	switch (ctype) {
	case WIMLIB_COMPRESSION_TYPE_NONE:
	case WIMLIB_COMPRESSION_TYPE_LZX:
	case WIMLIB_COMPRESSION_TYPE_XPRESS:
	case WIMLIB_COMPRESSION_TYPE_LZMS:
		*out_ctype_p = ctype;
		return 0;
	}
	return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_output_compression_type(WIMStruct *wim, int ctype)
{
	int ret = set_out_ctype(ctype, &wim->out_compression_type);
	if (ret)
		return ret;

	/* Reset the chunk size if it's no longer valid.  */
	if (!wim_chunk_size_valid(wim->out_chunk_size, ctype))
		wim->out_chunk_size = wim_default_chunk_size(ctype);
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_output_pack_compression_type(WIMStruct *wim, int ctype)
{
	int ret = set_out_ctype(ctype, &wim->out_solid_compression_type);
	if (ret)
		return ret;

	/* Reset the chunk size if it's no longer valid.  */
	if (!wim_chunk_size_valid(wim->out_solid_chunk_size, ctype))
		wim->out_solid_chunk_size = wim_default_solid_chunk_size(ctype);
	return 0;
}

static int
set_out_chunk_size(u32 chunk_size, int ctype, u32 *out_chunk_size_p)
{
	if (!wim_chunk_size_valid(chunk_size, ctype))
		return WIMLIB_ERR_INVALID_CHUNK_SIZE;

	*out_chunk_size_p = chunk_size;
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_output_chunk_size(WIMStruct *wim, uint32_t chunk_size)
{
	if (chunk_size == 0) {
		wim->out_chunk_size =
			wim_default_chunk_size(wim->out_compression_type);
		return 0;
	}

	return set_out_chunk_size(chunk_size,
				  wim->out_compression_type,
				  &wim->out_chunk_size);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_output_pack_chunk_size(WIMStruct *wim, uint32_t chunk_size)
{
	if (chunk_size == 0) {
		wim->out_solid_chunk_size =
			wim_default_solid_chunk_size(wim->out_solid_compression_type);
		return 0;
	}

	return set_out_chunk_size(chunk_size,
				  wim->out_solid_compression_type,
				  &wim->out_solid_chunk_size);
}

WIMLIBAPI void
wimlib_register_progress_function(WIMStruct *wim,
				  wimlib_progress_func_t progfunc,
				  void *progctx)
{
	wim->progfunc = progfunc;
	wim->progctx = progctx;
}

static int
open_wim_file(const tchar *filename, struct filedes *fd_ret)
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

/*
 * Begins the reading of a WIM file; opens the file and reads its header and
 * blob table, and optionally checks the integrity.
 */
static int
begin_read(WIMStruct *wim, const void *wim_filename_or_fd, int open_flags)
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
		ret = open_wim_file(wimfile, &wim->in_fd);
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
		 * replacement function in win32_replacements.c.
		 */
		wim->filename = realpath(wimfile, NULL);
		if (!wim->filename) {
			ERROR_WITH_ERRNO("Failed to get full path to file "
					 "\"%"TS"\"", wimfile);
			if (errno == ENOMEM)
				return WIMLIB_ERR_NOMEM;
			else
				return WIMLIB_ERR_NO_FILENAME;
		}
	}

	ret = read_wim_header(wim, &wim->hdr);
	if (ret)
		return ret;

	if (wim->hdr.flags & WIM_HDR_FLAG_WRITE_IN_PROGRESS) {
		WARNING("The WIM_HDR_FLAG_WRITE_IN_PROGRESS flag is set in the header of\n"
			"          \"%"TS"\".  It may be being changed by another process,\n"
			"          or a process may have crashed while writing the WIM.",
			wimfile);
	}

	if (open_flags & WIMLIB_OPEN_FLAG_WRITE_ACCESS) {
		ret = can_modify_wim(wim);
		if (ret)
			return ret;
	}

	if ((open_flags & WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT) &&
	    (wim->hdr.total_parts != 1))
		return WIMLIB_ERR_IS_SPLIT_WIM;

	/* If the boot index is invalid, print a warning and set it to 0 */
	if (wim->hdr.boot_idx > wim->hdr.image_count) {
		WARNING("Ignoring invalid boot index.");
		wim->hdr.boot_idx = 0;
	}

	/* Check and cache the compression type */
	if (wim->hdr.flags & WIM_HDR_FLAG_COMPRESSION) {
		if (wim->hdr.flags & WIM_HDR_FLAG_COMPRESS_LZX) {
			wim->compression_type = WIMLIB_COMPRESSION_TYPE_LZX;
		} else if (wim->hdr.flags & (WIM_HDR_FLAG_COMPRESS_XPRESS |
					     WIM_HDR_FLAG_COMPRESS_XPRESS_2)) {
			wim->compression_type = WIMLIB_COMPRESSION_TYPE_XPRESS;
		} else if (wim->hdr.flags & WIM_HDR_FLAG_COMPRESS_LZMS) {
			wim->compression_type = WIMLIB_COMPRESSION_TYPE_LZMS;
		} else {
			return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
		}
	} else {
		wim->compression_type = WIMLIB_COMPRESSION_TYPE_NONE;
	}
	wim->out_compression_type = wim->compression_type;

	/* Check and cache the chunk size.  */
	wim->chunk_size = wim->hdr.chunk_size;
	wim->out_chunk_size = wim->chunk_size;
	if (!wim_chunk_size_valid(wim->chunk_size, wim->compression_type)) {
		ERROR("Invalid chunk size (%"PRIu32" bytes) "
		      "for compression type %"TS"!", wim->chunk_size,
		      wimlib_get_compression_type_string(wim->compression_type));
		return WIMLIB_ERR_INVALID_CHUNK_SIZE;
	}

	if (open_flags & WIMLIB_OPEN_FLAG_CHECK_INTEGRITY) {
		ret = check_wim_integrity(wim);
		if (ret == WIM_INTEGRITY_NONEXISTENT) {
			WARNING("\"%"TS"\" does not contain integrity "
				"information.  Skipping integrity check.",
				wimfile);
		} else if (ret == WIM_INTEGRITY_NOT_OK) {
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
		wim->blob_table = new_blob_table(9001);
		if (!wim->blob_table)
			return WIMLIB_ERR_NOMEM;
	} else {

		ret = read_wim_xml_data(wim);
		if (ret)
			return ret;

		xml_num_images = wim_info_get_num_images(wim->wim_info);
		if (xml_num_images != wim->hdr.image_count) {
			ERROR("The WIM's header is inconsistent with its XML data.\n"
			      "        Please submit a bug report if you believe this "
			      "WIM file should be considered valid.");
			return WIMLIB_ERR_IMAGE_COUNT;
		}

		ret = read_blob_table(wim);
		if (ret)
			return ret;
	}
	return 0;
}

int
open_wim_as_WIMStruct(const void *wim_filename_or_fd, int open_flags,
		      WIMStruct **wim_ret,
		      wimlib_progress_func_t progfunc, void *progctx)
{
	WIMStruct *wim;
	int ret;

	ret = wimlib_global_init(WIMLIB_INIT_FLAG_ASSUME_UTF8);
	if (ret)
		return ret;

	wim = new_wim_struct();
	if (!wim)
		return WIMLIB_ERR_NOMEM;

	wim->progfunc = progfunc;
	wim->progctx = progctx;

	ret = begin_read(wim, wim_filename_or_fd, open_flags);
	if (ret) {
		wimlib_free(wim);
		return ret;
	}

	*wim_ret = wim;
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_open_wim_with_progress(const tchar *wimfile, int open_flags,
			      WIMStruct **wim_ret,
			      wimlib_progress_func_t progfunc, void *progctx)
{
	if (open_flags & ~(WIMLIB_OPEN_FLAG_CHECK_INTEGRITY |
			   WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT |
			   WIMLIB_OPEN_FLAG_WRITE_ACCESS))
		return WIMLIB_ERR_INVALID_PARAM;

	if (!wimfile || !*wimfile || !wim_ret)
		return WIMLIB_ERR_INVALID_PARAM;

	return open_wim_as_WIMStruct(wimfile, open_flags, wim_ret,
				     progfunc, progctx);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_open_wim(const tchar *wimfile, int open_flags, WIMStruct **wim_ret)
{
	return wimlib_open_wim_with_progress(wimfile, open_flags, wim_ret,
					     NULL, NULL);
}

/* Checksum all blobs that are unhashed (other than the metadata blobs), merging
 * them into the blob table as needed.  This is a no-op unless files have been
 * added to an image in the same WIMStruct.  */
int
wim_checksum_unhashed_blobs(WIMStruct *wim)
{
	int ret;

	if (!wim_has_metadata(wim))
		return 0;
	for (int i = 0; i < wim->hdr.image_count; i++) {
		struct blob_descriptor *blob, *tmp;
		struct wim_image_metadata *imd = wim->image_metadata[i];
		image_for_each_unhashed_blob_safe(blob, tmp, imd) {
			struct blob_descriptor *new_blob;
			ret = hash_unhashed_blob(blob, wim->blob_table, &new_blob);
			if (ret)
				return ret;
			if (new_blob != blob)
				free_blob_descriptor(blob);
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
		ERROR("Cannot modify \"%"TS"\": is part of a split WIM",
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

/* API function documented in wimlib.h  */
WIMLIBAPI void
wimlib_free(WIMStruct *wim)
{
	if (!wim)
		return;

	while (!list_empty(&wim->subwims)) {
		WIMStruct *subwim;

		subwim = list_entry(wim->subwims.next, WIMStruct, subwim_node);
		list_del(&subwim->subwim_node);
		wimlib_free(subwim);
	}

	if (filedes_valid(&wim->in_fd))
		filedes_close(&wim->in_fd);
	if (filedes_valid(&wim->out_fd))
		filedes_close(&wim->out_fd);

	free_blob_table(wim->blob_table);

	wimlib_free_decompressor(wim->decompressor);

	FREE(wim->filename);
	free_wim_info(wim->wim_info);
	if (wim->image_metadata) {
		for (unsigned i = 0; i < wim->hdr.image_count; i++)
			put_image_metadata(wim->image_metadata[i], NULL);
		FREE(wim->image_metadata);
	}
	FREE(wim);
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
WIMLIBAPI u32
wimlib_get_version(void)
{
	return (WIMLIB_MAJOR_VERSION << 20) |
	       (WIMLIB_MINOR_VERSION << 10) |
		WIMLIB_PATCH_VERSION;
}

static bool lib_initialized = false;

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_global_init(int init_flags)
{
	if (lib_initialized)
		return 0;

#ifdef ENABLE_ERROR_MESSAGES
	if (!wimlib_error_file)
		wimlib_error_file = stderr;
#endif

	if (init_flags & ~(WIMLIB_INIT_FLAG_ASSUME_UTF8 |
			   WIMLIB_INIT_FLAG_DONT_ACQUIRE_PRIVILEGES |
			   WIMLIB_INIT_FLAG_STRICT_CAPTURE_PRIVILEGES |
			   WIMLIB_INIT_FLAG_STRICT_APPLY_PRIVILEGES |
			   WIMLIB_INIT_FLAG_DEFAULT_CASE_SENSITIVE |
			   WIMLIB_INIT_FLAG_DEFAULT_CASE_INSENSITIVE))
		return WIMLIB_ERR_INVALID_PARAM;

	libxml_global_init();
	if (!(init_flags & WIMLIB_INIT_FLAG_ASSUME_UTF8)) {
		wimlib_mbs_is_utf8 = test_locale_ctype_utf8();
	#ifdef WITH_NTFS_3G
		if (!wimlib_mbs_is_utf8)
			libntfs3g_global_init();
	#endif
	}
#ifdef __WIN32__
	{
		int ret = win32_global_init(init_flags);
		if (ret)
			return ret;
	}
#endif
	iconv_global_init();
	init_upcase();
	if (init_flags & WIMLIB_INIT_FLAG_DEFAULT_CASE_SENSITIVE)
		default_ignore_case = false;
	else if (init_flags & WIMLIB_INIT_FLAG_DEFAULT_CASE_INSENSITIVE)
		default_ignore_case = true;
	lib_initialized = true;
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI void
wimlib_global_cleanup(void)
{
	if (!lib_initialized)
		return;
	libxml_global_cleanup();
	iconv_global_cleanup();
#ifdef __WIN32__
	win32_global_cleanup();
#endif

	wimlib_set_error_file(NULL);
	lib_initialized = false;
}
