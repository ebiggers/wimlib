/*
 * ntfs-apply.c
 *
 * Apply a WIM image to a NTFS volume.  We restore everything we can, including
 * security data and alternate data streams.
 */

/*
 * Copyright (C) 2012 Eric Biggers
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

#include "config.h"
#include "wimlib_internal.h"


#ifdef WITH_NTFS_3G
#include "dentry.h"
#include "lookup_table.h"
#include "io.h"
#include <ntfs-3g/layout.h>
#include <ntfs-3g/acls.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/security.h> /* security.h before xattrs.h */
#include <ntfs-3g/xattrs.h>
#include <ntfs-3g/reparse.h>
#include <stdlib.h>
#include <unistd.h>

struct ntfs_apply_args {
	ntfs_volume *vol;
	int extract_flags;
	WIMStruct *w;
};


#if 0
extern int ntfs_set_inode_security(ntfs_inode *ni, u32 selection,
				   const char *attr);
extern int ntfs_set_inode_attributes(ntfs_inode *ni, u32 attrib);
#endif

/* 
 * Extracts a WIM resource to a NTFS attribute.
 */
static int
extract_wim_resource_to_ntfs_attr(const struct lookup_table_entry *lte,
			          ntfs_attr *na)
{
	u64 bytes_remaining = wim_resource_size(lte);
	u8 buf[min(WIM_CHUNK_SIZE, bytes_remaining)];
	u64 offset = 0;
	int ret = 0;
	u8 hash[SHA1_HASH_SIZE];

	SHA_CTX ctx;
	sha1_init(&ctx);

	while (bytes_remaining) {
		u64 to_read = min(bytes_remaining, WIM_CHUNK_SIZE);
		ret = read_wim_resource(lte, buf, to_read, offset, false);
		if (ret != 0)
			break;
		sha1_update(&ctx, buf, to_read);
		if (ntfs_attr_pwrite(na, offset, to_read, buf) != to_read) {
			ERROR_WITH_ERRNO("Error extracting WIM resource");
			return WIMLIB_ERR_WRITE;
		}
		bytes_remaining -= to_read;
		offset += to_read;
	}
	sha1_final(hash, &ctx);
	if (!hashes_equal(hash, lte->hash)) {
		ERROR("Invalid checksum on a WIM resource "
		      "(detected when extracting to NTFS stream)");
		ERROR("The following WIM resource is invalid:");
		print_lookup_table_entry(lte);
		return WIMLIB_ERR_INVALID_RESOURCE_HASH;
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
	int ret = 0;
	unsigned stream_idx = 0;
	ntfschar *stream_name = AT_UNNAMED;
	u32 stream_name_len = 0;

	DEBUG("Writing %u NTFS data stream%s for `%s'",
	      dentry->num_ads + 1,
	      (dentry->num_ads == 0 ? "" : "s"),
	      dentry->full_path_utf8);

	while (1) {
		struct lookup_table_entry *lte;
		ntfs_attr *na;

		lte = dentry_stream_lte(dentry, stream_idx, w->lookup_table);

		if (stream_name_len) {
			/* Create an empty named stream. */
			ret = ntfs_attr_add(ni, AT_DATA, stream_name,
					    stream_name_len, NULL, 0);
			if (ret != 0) {
				ERROR_WITH_ERRNO("Failed to create name data "
						 "stream for extracted file "
						 "`%s'",
						 dentry->full_path_utf8);
				ret = WIMLIB_ERR_NTFS_3G;
				break;

			}
		}
		/* If there's no lookup table entry, it's an empty stream.
		 * Otherwise, we must open the attribute and extract the data.
		 * */
		if (lte) {
			na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_len);
			if (!na) {
				ERROR_WITH_ERRNO("Failed to open a data stream of "
						 "extracted file `%s'",
						 dentry->full_path_utf8);
				ret = WIMLIB_ERR_NTFS_3G;
				break;
			}
			ret = extract_wim_resource_to_ntfs_attr(lte, na);
			if (ret != 0)
				break;
			ntfs_attr_close(na);
		}
		if (stream_idx == dentry->num_ads)
			break;
		stream_name = (ntfschar*)dentry->ads_entries[stream_idx].stream_name;
		stream_name_len = dentry->ads_entries[stream_idx].stream_name_len / 2;
		stream_idx++;
	}
	return ret;
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
				   ntfs_inode *dir_ni,
				   ntfs_inode **to_ni_ret)
{
	int ret;
	char *p;
	char orig;
	const char *dir_name;

	ntfs_inode *to_ni;
	ntfs_volume *vol;

	wimlib_assert(dentry_is_regular_file(from_dentry)
			&& dentry_is_regular_file(to_dentry));

	if (ntfs_inode_close(dir_ni) != 0) {
		ERROR_WITH_ERRNO("Error closing directory");
		return WIMLIB_ERR_NTFS_3G;
	}

	vol = dir_ni->vol;

	DEBUG("Extracting NTFS hard link `%s' => `%s'",
	      from_dentry->full_path_utf8, to_dentry->extracted_file);

	to_ni = ntfs_pathname_to_inode(vol, NULL,
				       to_dentry->extracted_file);
	if (!to_ni) {
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 to_dentry->extracted_file);
		return WIMLIB_ERR_NTFS_3G;
	}
	p = from_dentry->full_path_utf8 + from_dentry->full_path_utf8_len;
	do {
		p--;
	} while (*p != '/');

	orig = *p;
	*p = '\0';
	dir_name = from_dentry->full_path_utf8;

	dir_ni = ntfs_pathname_to_inode(vol, NULL, dir_name);
	if (!dir_ni) {
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 from_dentry->full_path_utf8);
		*p = orig;
		return WIMLIB_ERR_NTFS_3G;
	}
	*p = orig;

	ret = ntfs_link(to_ni, dir_ni,
			(ntfschar*)from_dentry->file_name,
			from_dentry->file_name_len / 2);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Could not create hard link `%s' => `%s'",
				 from_dentry->full_path_utf8,
				 to_dentry->extracted_file);
		ret = WIMLIB_ERR_NTFS_3G;
	}
	*to_ni_ret = to_ni;
	return ret;
}

/*#define HAVE_NTFS_INODE_FUNCTIONS*/

static int
apply_file_attributes_and_security_data(ntfs_inode *ni,
					ntfs_inode *dir_ni,
					const struct dentry *dentry,
					const WIMStruct *w)
{
	DEBUG("Setting NTFS file attributes on `%s' to %#"PRIx32,
	      dentry->full_path_utf8, dentry->attributes);
	int ret;
#ifdef HAVE_NTFS_INODE_FUNCTIONS
	ret = ntfs_set_inode_attributes(ni, dentry->attributes);
#else
	struct SECURITY_CONTEXT ctx;
	u32 attributes_le32;
 	attributes_le32 = cpu_to_le32(dentry->attributes);
	memset(&ctx, 0, sizeof(ctx));
	ctx.vol = ni->vol;
	ret = ntfs_xattr_system_setxattr(&ctx, XATTR_NTFS_ATTRIB,
					 ni, dir_ni,
					 (const char*)&attributes_le32,
					 sizeof(u32), 0);
#endif
	if (ret != 0) {
		ERROR("Failed to set NTFS file attributes on `%s'",
		       dentry->full_path_utf8);
		return WIMLIB_ERR_NTFS_3G;
	}
	if (dentry->security_id != -1) {
		const struct wim_security_data *sd;
		const char *descriptor;
		
		sd = wim_const_security_data(w);
		wimlib_assert(dentry->security_id < sd->num_entries);
		descriptor = sd->descriptors[dentry->security_id];
		DEBUG("Applying security descriptor %d to `%s'",
		      dentry->security_id, dentry->full_path_utf8);

	#ifdef HAVE_NTFS_INODE_FUNCTIONS
		u32 selection = OWNER_SECURITY_INFORMATION |
				GROUP_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION  |
				SACL_SECURITY_INFORMATION;
		ret = ntfs_set_inode_security(ni, selection, descriptor);
	#else
		ret = ntfs_xattr_system_setxattr(&ctx, XATTR_NTFS_ACL,
						 ni, dir_ni, descriptor,
					   	 sd->sizes[dentry->security_id], 0);
	#endif
				
		if (ret != 0) {
			ERROR_WITH_ERRNO("Failed to set security data on `%s'",
					dentry->full_path_utf8);
			return WIMLIB_ERR_NTFS_3G;
		}
	}
	return 0;
}

static int apply_reparse_data(ntfs_inode *ni, const struct dentry *dentry,
			      const WIMStruct *w)
{
	struct lookup_table_entry *lte;
	int ret = 0;

	wimlib_assert(dentry->attributes & FILE_ATTRIBUTE_REPARSE_POINT);

	lte = dentry_unnamed_lte(dentry, w->lookup_table);

	DEBUG("Applying reparse data to `%s'", dentry->full_path_utf8);

	if (!lte) {
		ERROR("Could not find reparse data for `%s'",
		      dentry->full_path_utf8);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	if (wim_resource_size(lte) >= 0xffff) {
		ERROR("Reparse data of `%s' is too long (%lu bytes)",
		      dentry->full_path_utf8, wim_resource_size(lte));
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	u8 reparse_data_buf[8 + wim_resource_size(lte)];
	u8 *p = reparse_data_buf;
	p = put_u32(p, dentry->reparse_tag); /* ReparseTag */
	p = put_u16(p, wim_resource_size(lte)); /* ReparseDataLength */
	p = put_u16(p, 0); /* Reserved */

	ret = read_full_wim_resource(lte, p);
	if (ret != 0)
		return ret;

	ret = ntfs_set_ntfs_reparse_data(ni, (char*)reparse_data_buf,
					 wim_resource_size(lte) + 8, 0);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to set NTFS reparse data on `%s'",
				 dentry->full_path_utf8);
		return WIMLIB_ERR_NTFS_3G;
	}
	return 0;
}

static int do_wim_apply_dentry_ntfs(struct dentry *dentry, ntfs_inode *dir_ni,
				    WIMStruct *w);

/* 
 * If @dentry is part of a hard link group, search for hard-linked dentries in
 * the same directory that have a nonempty DOS (short) filename.  There should
 * be exactly 0 or 1 such dentries.  If there is 1, extract that dentry first,
 * so that the DOS name is correctly associated with the corresponding long name
 * in the Win32 namespace, and not any of the additional names in the POSIX
 * namespace created from hard links.
 */
static int preapply_dentry_with_dos_name(struct dentry *dentry,
				    	 ntfs_inode **dir_ni_p,
					 WIMStruct *w)
{
	struct dentry *other;
	struct dentry *dentry_with_dos_name;

	dentry_with_dos_name = NULL;
	list_for_each_entry(other, &dentry->link_group_list,
			    link_group_list)
	{
		if (dentry->parent == other->parent && other->short_name_len) {
			if (dentry_with_dos_name) {
				ERROR("Found multiple DOS names for file `%s' "
				      "in the same directory",
				      dentry_with_dos_name->full_path_utf8);
				return WIMLIB_ERR_INVALID_DENTRY;
			}
			dentry_with_dos_name = other;
		}
	}
	/* If there's a dentry with a DOS name, extract it first */
	if (dentry_with_dos_name
	    && !dentry_with_dos_name->extracted_file)
	{
		char *p;
		const char *dir_name;
		char orig;
		int ret;
		ntfs_volume *vol = (*dir_ni_p)->vol;

		DEBUG("pre-applying DOS name `%s'",
		      dentry_with_dos_name->full_path_utf8);
		ret = do_wim_apply_dentry_ntfs(dentry_with_dos_name,
					       *dir_ni_p, w);
		if (ret != 0)
			return ret;
		p = dentry->full_path_utf8 + dentry->full_path_utf8_len;
		do {
			p--;
		} while (*p != '/');

		orig = *p;
		*p = '\0';
		dir_name = dentry->full_path_utf8;

		*dir_ni_p = ntfs_pathname_to_inode(vol, NULL, dir_name);
		*p = orig;
		if (!*dir_ni_p) {
			ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
					 dir_name);
			return WIMLIB_ERR_NTFS_3G;
		}
	}
	return 0;
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
	int ret = 0;
	mode_t type;
	ntfs_inode *ni = NULL;
	bool is_hardlink = false;
	ntfs_volume *vol = dir_ni->vol;

	if (dentry->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		type = S_IFDIR;
	} else {
		struct dentry *other;

		/* Apply hard-linked directory in same directory with DOS name
		 * (if there is one) before this dentry */
		if (dentry->short_name_len == 0) {
			ret = preapply_dentry_with_dos_name(dentry,
							    &dir_ni, w);
			if (ret != 0)
				return ret;
		}

		type = S_IFREG;
		/* See if we can make a hard link */
		list_for_each_entry(other, &dentry->link_group_list,
				    link_group_list) {
			if (other->extracted_file) {
				/* Already extracted another dentry in the hard
				 * link group.  We can make a hard link instead
				 * of extracting the file data. */
				ret = wim_apply_hardlink_ntfs(dentry, other,
							      dir_ni, &ni);
				is_hardlink = true;
				if (ret) {
					goto out_close_dir_ni;
				} else {
					dentry->extracted_file = dentry->full_path_utf8;
					goto out_set_dos_name;
				}
			}
		}
		/* Can't make a hard link; extract the file itself */
		dentry->extracted_file = dentry->full_path_utf8;
	}

	/* 
	 * Create a directory or file.
	 *
	 * Note: For symbolic links that are not directory junctions, pass
	 * S_IFREG here, since we manually set the reparse data later.
	 */
	ni = ntfs_create(dir_ni, 0, (ntfschar*)dentry->file_name,
			 dentry->file_name_len / 2, type);

	if (!ni) {
		ERROR_WITH_ERRNO("Could not create NTFS object for `%s'",
				 dentry->full_path_utf8);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out_close_dir_ni;
	}

	/* Write the data streams, unless this is a directory or reparse point
	 * */
	if (!dentry_is_directory(dentry) &&
	     !(dentry->attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		ret = write_ntfs_data_streams(ni, dentry, w);
		if (ret != 0)
			goto out_close_dir_ni;
	}


	ret = apply_file_attributes_and_security_data(ni, dir_ni, dentry, w);
	if (ret != 0)
		goto out_close_dir_ni;

	if (dentry->attributes & FILE_ATTR_REPARSE_POINT) {
		ret = apply_reparse_data(ni, dentry, w);
		if (ret != 0)
			goto out_close_dir_ni;
	}

out_set_dos_name:
	/* Set DOS (short) name if given */
	if (dentry->short_name_len != 0) {

		char *short_name_utf8;
		size_t short_name_utf8_len;
		short_name_utf8 = utf16_to_utf8(dentry->short_name,
					   	dentry->short_name_len,
					        &short_name_utf8_len);
		if (!short_name_utf8) {
			ERROR("Out of memory");
			ret = WIMLIB_ERR_NOMEM;
			goto out_close_dir_ni;
		}

		if (is_hardlink) {
			char *p;
			char orig;
			const char *dir_name;

			/* ntfs_set_ntfs_dos_name() closes the inodes in the
			 * wrong order if we have applied a hard link.   Close
			 * them ourselves, then re-open then. */
			if (ntfs_inode_close(dir_ni) != 0) {
				if (ret == 0)
					ret = WIMLIB_ERR_NTFS_3G;
				ERROR_WITH_ERRNO("Failed to close directory inode");
			}
			if (ntfs_inode_close(ni) != 0) {
				if (ret == 0)
					ret = WIMLIB_ERR_NTFS_3G;
				ERROR_WITH_ERRNO("Failed to close hard link target inode");
			}
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
			ni = ntfs_pathname_to_inode(vol, dir_ni,
						    dentry->file_name_utf8);
			if (!ni) {
				ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
						 dir_name);
				return WIMLIB_ERR_NTFS_3G;
			}
		}

		DEBUG("Setting short (DOS) name of `%s' to %s",
		      dentry->full_path_utf8, short_name_utf8);

		ret = ntfs_set_ntfs_dos_name(ni, dir_ni, short_name_utf8,
					     short_name_utf8_len, 0);
		FREE(short_name_utf8);
		if (ret != 0) {
			ERROR_WITH_ERRNO("Could not set DOS (short) name for `%s'",
					 dentry->full_path_utf8);
			ret = WIMLIB_ERR_NTFS_3G;
		}
		/* inodes have been closed by ntfs_set_ntfs_dos_name(). */
		return ret;
	}

out_close_dir_ni:
	if (ntfs_inode_close(dir_ni) != 0) {
		if (ret == 0)
			ret = WIMLIB_ERR_NTFS_3G;
		ERROR_WITH_ERRNO("Failed to close directory inode");
	}
	if (ni && ntfs_inode_close(ni) != 0) {
		if (ret == 0)
			ret = WIMLIB_ERR_NTFS_3G;
		ERROR_WITH_ERRNO("Failed to close inode");
	}
	return ret;
}

static int wim_apply_root_dentry_ntfs(const struct dentry *dentry,
				      ntfs_volume *vol,
				      const WIMStruct *w)
{
	ntfs_inode *ni;
	int ret = 0;

	wimlib_assert(dentry_is_directory(dentry));
	ni = ntfs_pathname_to_inode(vol, NULL, "/");
	if (!ni) {
		ERROR_WITH_ERRNO("Could not find root NTFS inode");
		return WIMLIB_ERR_NTFS_3G;
	}
	ret = apply_file_attributes_and_security_data(ni, ni, dentry, w);
	if (ntfs_inode_close(ni) != 0) {
		ERROR_WITH_ERRNO("Failed to close NTFS inode for root "
				 "directory");
		ret = WIMLIB_ERR_NTFS_3G;
	}
	return ret;
}

/* Applies a WIM dentry to the NTFS volume */
static int wim_apply_dentry_ntfs(struct dentry *dentry, void *arg)
{
	struct ntfs_apply_args *args = arg;
	ntfs_volume *vol             = args->vol;
	int extract_flags            = args->extract_flags;
	WIMStruct *w                 = args->w;
	ntfs_inode *dir_ni;
	char *p;
	char orig;
	const char *dir_name;

	if (dentry->extracted_file)
		return 0;

	wimlib_assert(dentry->full_path_utf8);

	DEBUG("Applying dentry `%s' to NTFS", dentry->full_path_utf8);

	if (extract_flags & WIMLIB_EXTRACT_FLAG_VERBOSE)
		puts(dentry->full_path_utf8);

	if (dentry_is_root(dentry))
		return wim_apply_root_dentry_ntfs(dentry, vol, w);

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
	return do_wim_apply_dentry_ntfs(dentry, dir_ni, w);
}

static int wim_apply_dentry_timestamps(struct dentry *dentry, void *arg)
{
	struct ntfs_apply_args *args = arg;
	ntfs_volume *vol             = args->vol;
	u8 *p;
	u8 buf[24];
	ntfs_inode *ni;
	int ret = 0;


	DEBUG("Setting timestamps on `%s'", dentry->full_path_utf8);

	ni = ntfs_pathname_to_inode(vol, NULL, dentry->full_path_utf8);
	if (!ni) {
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 dentry->full_path_utf8);
		return WIMLIB_ERR_NTFS_3G;
	}

	p = buf;
	p = put_u64(p, dentry->creation_time);
	p = put_u64(p, dentry->last_write_time);
	p = put_u64(p, dentry->last_access_time);
	ret = ntfs_inode_set_times(ni, (const char*)buf, 3 * sizeof(u64), 0);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to set NTFS timestamps on `%s'",
				 dentry->full_path_utf8);
		ret = WIMLIB_ERR_NTFS_3G;
	}

	if (ntfs_inode_close(ni) != 0) {
		if (ret == 0)
			ret = WIMLIB_ERR_NTFS_3G;
		ERROR_WITH_ERRNO("Failed to close NTFS inode for `%s'",
				 dentry->full_path_utf8);
	}
	return ret;
}

static int dentry_clear_extracted_file(struct dentry *dentry, void *ignore)
{
	if (dentry->extracted_file != dentry->full_path_utf8)
		FREE(dentry->extracted_file);
	dentry->extracted_file = NULL;
	return 0;
}

static int do_wim_apply_image_ntfs(WIMStruct *w, const char *device, int extract_flags)
{
	ntfs_volume *vol;
	int ret;
	struct dentry *root;
	struct ntfs_apply_args args;
	
	DEBUG("Mounting NTFS volume `%s'", device);
	vol = ntfs_mount(device, 0);
	if (!vol) {
		ERROR_WITH_ERRNO("Failed to mount NTFS volume `%s'", device);
		return WIMLIB_ERR_NTFS_3G;
	}
	args.vol = vol;
	args.extract_flags = extract_flags;
	args.w = w;
	root = wim_root_dentry(w);

	for_dentry_in_tree(root, dentry_clear_extracted_file, NULL);

	ret = for_dentry_in_tree(root, wim_apply_dentry_ntfs, &args);
	if (ret != 0)
		goto out;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_VERBOSE)
		printf("Setting timestamps of extracted files on NTFS "
		       "volume `%s'\n", device);
	ret = for_dentry_in_tree_depth(root, wim_apply_dentry_timestamps,
				       &args);

	if (ret == 0 && (extract_flags & WIMLIB_EXTRACT_FLAG_VERBOSE))
		printf("Finished applying image %d of %s to NTFS "
		       "volume `%s'\n",
		       w->current_image,
		       w->filename ? w->filename : "WIM",
		       device);
out:
	DEBUG("Unmounting NTFS volume `%s'", device);
	if (ntfs_umount(vol, FALSE) != 0) {
		ERROR_WITH_ERRNO("Failed to unmount NTFS volume `%s'", device);
		if (ret == 0)
			ret = WIMLIB_ERR_NTFS_3G;
	}
	return ret;
}


/* 
 * API entry point for applying a WIM image to a NTFS volume.
 *
 * Please note that this is a NTFS *volume* and not a directory.  The intention
 * is that the volume contain an empty filesystem, and the WIM image contain a
 * full filesystem to be applied to the volume.
 */
WIMLIBAPI int wimlib_apply_image_to_ntfs_volume(WIMStruct *w, int image,
					 	const char *device, int flags,
						WIMStruct **additional_swms,
						unsigned num_additional_swms)
{
	struct lookup_table *joined_tab, *w_tab_save;
	int ret;

	DEBUG("w->filename = %s, image = %d, device = %s, flags = 0x%x, "
	      "num_additional_swms = %u",
	      w->filename, image, device, flags, num_additional_swms);

	if (!w || !device)
		return WIMLIB_ERR_INVALID_PARAM;
	if (image == WIM_ALL_IMAGES) {
		ERROR("Can only apply a single image when applying "
		      "directly to a NTFS volume");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	if (flags & (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK)) {
		ERROR("Cannot specify symlink or hardlink flags when applying ");
		ERROR("directly to a NTFS volume");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	ret = verify_swm_set(w, additional_swms, num_additional_swms);
	if (ret != 0)
		return ret;

	if (num_additional_swms) {
		ret = new_joined_lookup_table(w, additional_swms,
					      num_additional_swms, &joined_tab);
		if (ret != 0)
			return ret;
		w_tab_save = w->lookup_table;
		w->lookup_table = joined_tab;
	}

	ret = wimlib_select_image(w, image);
	if (ret != 0)
		goto out;

	ret = do_wim_apply_image_ntfs(w, device, flags);

out:
	if (num_additional_swms) {
		free_lookup_table(w->lookup_table);
		w->lookup_table = w_tab_save;
	}
	return ret;
}

#else /* WITH_NTFS_3G */
WIMLIBAPI int wimlib_apply_image_to_ntfs_volume(WIMStruct *w, int image,
					 	const char *device, int flags,
						WIMStruct **additional_swms,
						unsigned num_additional_swms)
{
	ERROR("wimlib was compiled without support for NTFS-3g, so");
	ERROR("we cannot apply a WIM image directly to a NTFS volume");
	return WIMLIB_ERR_UNSUPPORTED;
}
#endif /* WITH_NTFS_3G */
