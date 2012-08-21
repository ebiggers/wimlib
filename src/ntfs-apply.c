/*
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "config.h"
#include "wimlib_internal.h"


#ifdef WITH_NTFS_3G
#include "dentry.h"
#include "lookup_table.h"
#include <ntfs-3g/layout.h>
#include <ntfs-3g/acls.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/misc.h>
#include <ntfs-3g/reparse.h>
#include <ntfs-3g/security.h>
#include <ntfs-3g/volume.h>
#include <stdlib.h>
#include <unistd.h>

struct ntfs_apply_args {
	ntfs_volume *vol;
	int extract_flags;
	WIMStruct *w;
};

extern int _ntfs_set_file_security(ntfs_volume *vol, ntfs_inode *ni,
				   u32 selection, const char *attr);
extern int _ntfs_set_file_attributes(ntfs_inode *ni, s32 attrib);

/* 
 * Extracts a WIM resource to a NTFS attribute.
 */
static int extract_resource_to_ntfs_attr(WIMStruct *w, const struct resource_entry *entry, 
					 ntfs_attr *na)
{
	u8 buf[min(entry->original_size, WIM_CHUNK_SIZE)];
	u64 num_chunks = (entry->original_size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;
	u64 n = WIM_CHUNK_SIZE;
	int res_ctype = wim_resource_compression_type(w, entry);
	u64 offset = 0;
	for (u64 i = 0; i < num_chunks; i++) {
		DEBUG("Write chunk %u of %u", i + 1, num_chunks);
		int ret;
		if (i == num_chunks - 1) {
			n = entry->original_size % WIM_CHUNK_SIZE;
			if (n == 0) {
				n = WIM_CHUNK_SIZE;
			}
		}

		ret = read_resource(w->fp, entry->size, entry->original_size,
				    entry->offset, res_ctype, n, offset, buf);
		if (ret != 0)
			return ret;

		if (ntfs_attr_pwrite(na, offset, n, buf) != n) {
			ERROR("Failed to write to NTFS data stream");
			return WIMLIB_ERR_WRITE;
		}
		offset += n;
	}
	return 0;
}

/* Writes the data streams to a NTFS file
 *
 * @ni:	     The NTFS inode for the file.
 * @dentry:  The directory entry in the WIM file.
 * @w:	     The WIMStruct for the WIM containing the image we are applying.
 *
 * Returns 0 on success, nonzero on failure.
 */
static int write_ntfs_data_streams(ntfs_inode *ni, const struct dentry *dentry,
				   WIMStruct *w)
{
	ntfs_attr *na;
	struct lookup_table_entry *lte;
	int ret;


	DEBUG("Writing NTFS data streams for `%s'", dentry->full_path_utf8);

	wimlib_assert(dentry->num_ads == 0);

	lte = dentry_stream_lte(dentry, 0, w->lookup_table);
	if (lte && lte->resource_entry.original_size != 0) {

		na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
		if (!na) {
			ERROR_WITH_ERRNO("Failed to open unnamed data stream of "
					 "extracted file `%s'",
					 dentry->full_path_utf8);
			return WIMLIB_ERR_NTFS_3G;
		}
		ret = extract_resource_to_ntfs_attr(w, &lte->resource_entry, na);
		if (ret != 0)
			return ret;
		ntfs_attr_close(na);
	}

	return 0;
}

/*
 * Makes a NTFS hard link
 *
 * It is named @from_dentry->file_name and is located under the directory
 * specified by @dir_ni, and it is made to point to the previously extracted
 * file located at @to_dentry->extracted_file.
 *
 * Return 0 on success, nonzero on failure.
 */
static int wim_apply_hardlink_ntfs(const struct dentry *from_dentry,
				   const struct dentry *to_dentry,
				   ntfs_inode *dir_ni)
{
	int ret;
	ntfs_inode *to_ni;

	DEBUG("Extracting NTFS hard link `%s' => `%s'",
	      from_dentry->full_path_utf8, to_dentry->extracted_file);

	to_ni = ntfs_pathname_to_inode(dir_ni->vol, NULL,
				       to_dentry->extracted_file);
	if (!to_ni) {
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 to_dentry->extracted_file);
		return WIMLIB_ERR_NTFS_3G;
	}
	ret = ntfs_link(to_ni, dir_ni,
			(ntfschar*)from_dentry->file_name,
			from_dentry->file_name_len / 2);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Could not create hard link `%s' => `%s'",
				 from_dentry->full_path_utf8,
				 to_dentry->extracted_file);
		ret = WIMLIB_ERR_NTFS_3G;
	}
	if (ntfs_inode_close(to_ni) != 0) {
		ERROR_WITH_ERRNO("Failed to close NTFS inode for `%s'",
				 to_dentry->extracted_file);
		ret = WIMLIB_ERR_NTFS_3G;
	}
	return ret;
}

/* 
 * Applies a WIM dentry to a NTFS filesystem.
 *
 * @dentry:  The WIM dentry to apply
 * @dir_ni:  The NTFS inode for the parent directory
 * @w:	     The WIMStruct for the WIM containing the image we are applying.
 *
 * @return:  0 on success; nonzero on failure.
 */
static int do_wim_apply_dentry_ntfs(struct dentry *dentry, ntfs_inode *dir_ni,
			            WIMStruct *w)
{
	ntfs_inode *ni;
	int ret;
	mode_t type;

	if (dentry_is_directory(dentry)) {
		type = S_IFDIR;
	} else {
		type = S_IFREG;
		const struct list_head *head = &dentry->link_group_list;
		if (head->next != head) {
			/* This dentry is one of a hard link set of at least 2
			 * dentries.  If one of the other dentries has already
			 * been extracted, make a hard link to the file
			 * corresponding to this already-extracted directory.
			 * Otherwise, extract the file, and set the
			 * dentry->extracted_file field so that other dentries
			 * in the hard link group can link to it. */
			struct dentry *other;
			list_for_each_entry(other, head, link_group_list) {
				if (other->extracted_file) {
					return wim_apply_hardlink_ntfs(
							dentry, other, dir_ni);
				}
			}
		}
		FREE(dentry->extracted_file);
		dentry->extracted_file = STRDUP(dentry->full_path_utf8);
		if (!dentry->extracted_file) {
			ERROR("Failed to allocate memory for filename");
			return WIMLIB_ERR_NOMEM;
		}
	}

	/* 
	 * Create a directory or file.
	 *
	 * Note: if it's a reparse point (such as a symbolic link), we still
	 * pass S_IFREG here, since we manually set the reparse data later.
	 */
	ni = ntfs_create(dir_ni, 0, (ntfschar*)dentry->file_name,
			 dentry->file_name_len / 2, type);

	if (!ni) {
		ERROR_WITH_ERRNO("Could not create NTFS object for `%s'",
				 dentry->full_path_utf8);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	/* Write the data streams, unless this is a directory or reparse point
	 * */
	if (!dentry_is_directory(dentry) &&
	     !(dentry->attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		ret = write_ntfs_data_streams(ni, dentry, w);
		if (ret != 0)
			goto out;
	}

	DEBUG("Setting NTFS file attributes on `%s' to %#"PRIx32,
	      dentry->full_path_utf8, dentry->attributes);

	if (!_ntfs_set_file_attributes(ni, dentry->attributes)) {
		ERROR("Failed to set NTFS file attributes on `%s'",
		       dentry->full_path_utf8);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	if (dentry->security_id != -1) {
		const struct wim_security_data *sd = wim_security_data(w);
		wimlib_assert(dentry->security_id < sd->num_entries);
		DEBUG("Applying security descriptor %d to `%s'",
		      dentry->security_id, dentry->full_path_utf8);
		if (!_ntfs_set_file_security(ni->vol, ni, ~0,
					     sd->descriptors[dentry->security_id]))
		{
			ERROR_WITH_ERRNO("Failed to set security data on `%s'",
					dentry->full_path_utf8);
			ret = WIMLIB_ERR_NTFS_3G;
			goto out;
		}
	}

	if (dentry->attributes & FILE_ATTR_REPARSE_POINT) {
		struct lookup_table_entry *lte;
		ntfs_inode *ni;
		lte = dentry_first_lte(dentry, w->lookup_table);
		if (!lte) {
			ERROR("Could not find reparse data for `%s'",
			      dentry->full_path_utf8);
			ret = WIMLIB_ERR_INVALID_DENTRY;
			goto out;
		}
		
		ret = ntfs_set_ntfs_reparse_data(ni, lte->symlink_buf,
						 lte->resource_entry.original_size,
						 0);
		if (ret != 0) {
			ERROR_WITH_ERRNO("Failed to set NTFS reparse data on "
					 "`%s'", dentry->full_path_utf8);
			ret = WIMLIB_ERR_NTFS_3G;
			goto out;
		}
	}

	if (ntfs_inode_close_in_dir(ni, dir_ni) != 0) {
		ERROR_WITH_ERRNO("Failed to close new inode");
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}
out:
	return ret;
}

static int wim_apply_dentry_ntfs(struct dentry *dentry, void *arg)
{
	struct ntfs_apply_args *args = arg;
	ntfs_volume *vol             = args->vol;
	int extract_flags            = args->extract_flags;
	WIMStruct *w                 = args->w;
	ntfs_inode *dir_ni;
	int ret;
	char *p;
	char orig;
	const char *dir_name;

	wimlib_assert(dentry->full_path_utf8);

	DEBUG("Applying dentry `%s' to NTFS", dentry->full_path_utf8);

	if (dentry_is_root(dentry))
		return 0;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_VERBOSE)
		puts(dentry->full_path_utf8);

	p = dentry->full_path_utf8 + dentry->full_path_utf8_len;
	do {
		p--;
	} while (*p != '/');

	orig = *p;
	*p = '\0';
	dir_name = dentry->full_path_utf8;

	dir_ni = ntfs_pathname_to_inode(vol, NULL, dir_name);
	*p = orig;
	if (!dir_ni) {
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 dir_name);
		return WIMLIB_ERR_NTFS_3G;
	}
	DEBUG("Found NTFS inode for `%s'", dir_name);

	ret = do_wim_apply_dentry_ntfs(dentry, dir_ni, w);

	if (ntfs_inode_close(dir_ni) != 0) {
		if (ret == 0)
			ret = WIMLIB_ERR_NTFS_3G;
		ERROR_WITH_ERRNO("Failed to close directory inode");
	}
	return ret;

}

static int do_wim_apply_image_ntfs(WIMStruct *w, const char *device, int extract_flags)
{
	ntfs_volume *vol;
	int ret;
	
	vol = ntfs_mount(device, 0);
	if (!vol) {
		ERROR_WITH_ERRNO("Failed to mount NTFS volume `%s'", device);
		return WIMLIB_ERR_NTFS_3G;
	}
	struct ntfs_apply_args args = {
		.vol           = vol,
		.extract_flags = extract_flags,
		.w             = w,
	};
	ret = for_dentry_in_tree(wim_root_dentry(w), wim_apply_dentry_ntfs,
				 &args);
	if (ntfs_umount(vol, FALSE) != 0) {
		ERROR_WITH_ERRNO("Failed to unmount NTFS volume");
		if (ret == 0)
			ret = WIMLIB_ERR_NTFS_3G;
	}
	return ret;
}

WIMLIBAPI int wimlib_apply_image_to_ntfs_volume(WIMStruct *w, int image,
					 	const char *device, int flags)
{
	int ret;

	if (!device)
		return WIMLIB_ERR_INVALID_PARAM;
	if (image == WIM_ALL_IMAGES) {
		ERROR("Can only apply a single image when applying "
		      "directly to a NTFS volume");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	if (flags & (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK)) {
		ERROR("Cannot specifcy symlink or hardlink flags when applying ");
		ERROR("directly to a NTFS volume");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	ret = wimlib_select_image(w, image);
	if (ret != 0)
		return ret;

#if 0
	if (getuid() != 0) {
		ERROR("We are not root, but NTFS-3g requires root privileges to set arbitrary");
		ERROR("security data on the NTFS filesystem.  Please run this program as root");
		ERROR("if you want to extract a WIM image while preserving NTFS-specific");
		ERROR("information.");

		return WIMLIB_ERR_NOT_ROOT;
	}
#endif
	return do_wim_apply_image_ntfs(w, device, flags);
}

#else /* WITH_NTFS_3G */
WIMLIBAPI int wimlib_apply_image_to_ntfs_volume(WIMStruct *w, int image,
					 	const char *device, int flags)
{
	ERROR("wimlib was compiled without support for NTFS-3g, so");
	ERROR("we cannot apply a WIM image directly to a NTFS volume");
	return WIMLIB_ERR_UNSUPPORTED;
}
#endif /* WITH_NTFS_3G */
