/*
 * ntfs-apply.c
 *
 * Apply a WIM image to a NTFS volume.  Restore as much information as possible,
 * including security data, file attributes, DOS names, and alternate data
 * streams.
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

#include <ntfs-3g/endians.h>
#include <ntfs-3g/types.h>

#include "wimlib_internal.h"
#include "buffer_io.h"
#include "dentry.h"
#include "lookup_table.h"

#include <ntfs-3g/attrib.h>
#include <ntfs-3g/security.h> /* security.h before xattrs.h */
#include <ntfs-3g/reparse.h>
#include <ntfs-3g/xattrs.h>
#include <string.h>

static int extract_wim_chunk_to_ntfs_attr(const u8 *buf, size_t len,
					  u64 offset, void *arg)
{
	ntfs_attr *na = arg;
	if (ntfs_attr_pwrite(na, offset, len, buf) == len) {
		return 0;
	} else {
		ERROR_WITH_ERRNO("Error extracting WIM resource to NTFS attribute");
		return WIMLIB_ERR_WRITE;
	}
}

/*
 * Extracts a WIM resource to a NTFS attribute.
 */
static int
extract_wim_resource_to_ntfs_attr(const struct wim_lookup_table_entry *lte,
			          ntfs_attr *na)
{
	return extract_wim_resource(lte, wim_resource_size(lte),
				    extract_wim_chunk_to_ntfs_attr, na);
}

/* Writes the data streams of a WIM inode to the data attributes of a NTFS
 * inode.
 *
 * @ni:	     The NTFS inode to which the streams are to be extracted.
 *
 * @dentry:  The WIM dentry being extracted.  The @d_inode member points to the
 *	     corresponding WIM inode that contains the streams being extracted.
 *	     The WIM dentry itself is only needed to provide a file path for
 *	     better error messages.
 *
 * @progress_info:  Progress information for the image application.  The number
 * 		    of extracted bytes will be incremented by the uncompressed
 * 		    size of each stream extracted.
 *
 * Returns 0 on success, nonzero on failure.
 */
static int write_ntfs_data_streams(ntfs_inode *ni, const struct wim_dentry *dentry,
				   union wimlib_progress_info *progress_info)
{
	int ret = 0;
	unsigned stream_idx = 0;
	ntfschar *stream_name = AT_UNNAMED;
	u32 stream_name_len = 0;
	const struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table_entry *lte;

	DEBUG("Writing %u NTFS data stream%s for `%s'",
	      inode->i_num_ads + 1,
	      (inode->i_num_ads == 0 ? "" : "s"),
	      dentry->full_path_utf8);

	lte = inode->i_lte;
	while (1) {
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
		 * Otherwise, open the attribute and extract the data. */
		if (lte) {
			ntfs_attr *na;

			na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_len);
			if (!na) {
				ERROR_WITH_ERRNO("Failed to open a data stream of "
						 "extracted file `%s'",
						 dentry->full_path_utf8);
				ret = WIMLIB_ERR_NTFS_3G;
				break;
			}

			/* The WIM lookup table entry provides the stream
			 * length, so the NTFS attribute should be resized to
			 * this length before starting to extract the data. */
			ret = ntfs_attr_truncate_solid(na, wim_resource_size(lte));
			if (ret != 0) {
				ntfs_attr_close(na);
				break;
			}

			/* Actually extract the stream */
			ret = extract_wim_resource_to_ntfs_attr(lte, na);

			/* Close the attribute */
			ntfs_attr_close(na);
			if (ret != 0)
				break;

			/* Record the number of bytes of uncompressed data that
			 * have been extracted. */
			progress_info->extract.completed_bytes += wim_resource_size(lte);
		}
		if (stream_idx == inode->i_num_ads) /* Has the last stream been extracted? */
			break;

		/* Get the name and lookup table entry for the next stream. */
		stream_name = (ntfschar*)inode->i_ads_entries[stream_idx].stream_name;
		stream_name_len = inode->i_ads_entries[stream_idx].stream_name_len / 2;
		lte = inode->i_ads_entries[stream_idx].lte;
		stream_idx++;
	}
	return ret;
}

/* Open the NTFS inode that corresponds to the parent of a WIM dentry.  Returns
 * the opened inode, or NULL on failure. */
static ntfs_inode *dentry_open_parent_ni(const struct wim_dentry *dentry,
					 ntfs_volume *vol)
{
	char *p;
	const char *dir_name;
	ntfs_inode *dir_ni;
	char orig;

	p = dentry->full_path_utf8 + dentry->full_path_utf8_len;
	do {
		p--;
	} while (*p != '/');

	orig = *p;
	*p = '\0';
	dir_name = dentry->full_path_utf8;
	dir_ni = ntfs_pathname_to_inode(vol, NULL, dir_name);
	if (!dir_ni) {
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 dir_name);
	}
	*p = orig;
	return dir_ni;
}

/*
 * Makes a NTFS hard link.
 *
 * The hard link is named @from_dentry->file_name and is located under the
 * directory specified by @dir_ni, and it is made to point to the previously
 * extracted file located at @inode->i_extracted_file.
 *
 * Or, in other words, this adds a new name @from_dentry->full_path_utf8 to an
 * existing NTFS inode which already has a name @inode->i_extracted_file.
 *
 * The new name is made in the POSIX namespace (this is the behavior of
 * ntfs_link()).  I am assuming this is an acceptable behavior; however, it's
 * possible that the original name was actually in the Win32 namespace.  Note
 * that the WIM format does not provide enough information to distinguish Win32
 * names from POSIX names in all cases.
 *
 * Return 0 on success, nonzero on failure.
 */
static int apply_ntfs_hardlink(const struct wim_dentry *from_dentry,
			       const struct wim_inode *inode,
			       ntfs_inode **dir_ni_p)
{
	int ret;
	ntfs_inode *to_ni;
	ntfs_inode *dir_ni;
	ntfs_volume *vol;

	dir_ni = *dir_ni_p;
	vol = dir_ni->vol;
	ret = ntfs_inode_close(dir_ni);
	*dir_ni_p = NULL;
	if (ret != 0) {
		ERROR_WITH_ERRNO("Error closing directory");
		return WIMLIB_ERR_NTFS_3G;
	}

	DEBUG("Extracting NTFS hard link `%s' => `%s'",
	      from_dentry->full_path_utf8, inode->i_extracted_file);

	to_ni = ntfs_pathname_to_inode(vol, NULL, inode->i_extracted_file);
	if (!to_ni) {
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 inode->i_extracted_file);
		return WIMLIB_ERR_NTFS_3G;
	}

	dir_ni = dentry_open_parent_ni(from_dentry, vol);
	if (!dir_ni) {
		ntfs_inode_close(to_ni);
		return WIMLIB_ERR_NTFS_3G;
	}

	*dir_ni_p = dir_ni;

	ret = ntfs_link(to_ni, dir_ni,
			(ntfschar*)from_dentry->file_name,
			from_dentry->file_name_len / 2);
	if (ntfs_inode_close_in_dir(to_ni, dir_ni) || ret != 0) {
		ERROR_WITH_ERRNO("Could not create hard link `%s' => `%s'",
				 from_dentry->full_path_utf8,
				 inode->i_extracted_file);
		ret = WIMLIB_ERR_NTFS_3G;
	}
	return ret;
}

/* Transfers file attributes and possibly a security descriptor from a WIM inode
 * to a NTFS inode.
 *
 * @ni:	     The NTFS inode to apply the metadata to.
 * @dir_ni:  The NTFS inode for a directory containing @ni.
 * @dentry:  The WIM dentry whose inode contains the metadata to apply.
 * @w:       The WIMStruct for the WIM, through which the table of security
 * 		descriptors can be accessed.
 *
 * Returns 0 on success, nonzero on failure.
 */
static int
apply_file_attributes_and_security_data(ntfs_inode *ni,
					ntfs_inode *dir_ni,
					const struct wim_dentry *dentry,
					const WIMStruct *w)
{
	int ret;
	struct SECURITY_CONTEXT ctx;
	u32 attributes_le32;
	const struct wim_inode *inode;

	inode = dentry->d_inode;

	DEBUG("Setting NTFS file attributes on `%s' to %#"PRIx32,
	      dentry->full_path_utf8, inode->i_attributes);

	attributes_le32 = cpu_to_le32(inode->i_attributes);
	memset(&ctx, 0, sizeof(ctx));
	ctx.vol = ni->vol;
	ret = ntfs_xattr_system_setxattr(&ctx, XATTR_NTFS_ATTRIB,
					 ni, dir_ni,
					 (const char*)&attributes_le32,
					 sizeof(u32), 0);
	if (ret != 0) {
		ERROR("Failed to set NTFS file attributes on `%s'",
		       dentry->full_path_utf8);
		return WIMLIB_ERR_NTFS_3G;
	}
	if (inode->i_security_id != -1) {
		const char *desc;
		const struct wim_security_data *sd;

		sd = wim_const_security_data(w);
		wimlib_assert(inode->i_security_id < sd->num_entries);
		desc = (const char *)sd->descriptors[inode->i_security_id];
		DEBUG("Applying security descriptor %d to `%s'",
		      inode->i_security_id, dentry->full_path_utf8);

		ret = ntfs_xattr_system_setxattr(&ctx, XATTR_NTFS_ACL,
						 ni, dir_ni, desc,
						 sd->sizes[inode->i_security_id], 0);

		if (ret != 0) {
			ERROR_WITH_ERRNO("Failed to set security data on `%s'",
					dentry->full_path_utf8);
			return WIMLIB_ERR_NTFS_3G;
		}
	}
	return 0;
}

/*
 * Transfers the reparse data from a WIM inode (which must represent a reparse
 * point) to a NTFS inode.
 */
static int apply_reparse_data(ntfs_inode *ni, const struct wim_dentry *dentry,
			      union wimlib_progress_info *progress_info)
{
	struct wim_lookup_table_entry *lte;
	int ret = 0;

	lte = inode_unnamed_lte_resolved(dentry->d_inode);

	DEBUG("Applying reparse data to `%s'", dentry->full_path_utf8);

	if (!lte) {
		ERROR("Could not find reparse data for `%s'",
		      dentry->full_path_utf8);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	if (wim_resource_size(lte) >= 0xffff) {
		ERROR("Reparse data of `%s' is too long (%"PRIu64" bytes)",
		      dentry->full_path_utf8, wim_resource_size(lte));
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	u8 reparse_data_buf[8 + wim_resource_size(lte)];
	u8 *p = reparse_data_buf;
	p = put_u32(p, dentry->d_inode->i_reparse_tag); /* ReparseTag */
	p = put_u16(p, wim_resource_size(lte)); /* ReparseDataLength */
	p = put_u16(p, 0); /* Reserved */

	ret = read_full_wim_resource(lte, p, 0);
	if (ret != 0)
		return ret;

	ret = ntfs_set_ntfs_reparse_data(ni, (char*)reparse_data_buf,
					 wim_resource_size(lte) + 8, 0);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to set NTFS reparse data on `%s'",
				 dentry->full_path_utf8);
		return WIMLIB_ERR_NTFS_3G;
	}
	progress_info->extract.completed_bytes += wim_resource_size(lte);
	return 0;
}

/*
 * Applies a WIM dentry to a NTFS filesystem.
 *
 * @dentry:  The WIM dentry to apply
 * @dir_ni:  The NTFS inode for the parent directory
 *
 * @return:  0 on success; nonzero on failure.
 */
static int do_apply_dentry_ntfs(struct wim_dentry *dentry, ntfs_inode *dir_ni,
				struct apply_args *args)
{
	int ret = 0;
	mode_t type;
	ntfs_inode *ni = NULL;
	ntfs_volume *vol = dir_ni->vol;
	struct wim_inode *inode = dentry->d_inode;
	dentry->is_extracted = 1;

	if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
		type = S_IFDIR;
	} else {
		type = S_IFREG;
		if (inode->i_nlink > 1) {
			/* Inode has multiple dentries referencing it. */

			if (inode->i_extracted_file) {
				/* Already extracted another dentry in the hard
				 * link group.  Make a hard link instead of
				 * extracting the file data. */
				ret = apply_ntfs_hardlink(dentry, inode,
							  &dir_ni);
				goto out_close_dir_ni;
			} else {
				/* None of the dentries of this inode have been
				 * extracted yet, so go ahead and extract the
				 * first one. */
				FREE(inode->i_extracted_file);
				inode->i_extracted_file = STRDUP(dentry->full_path_utf8);
				if (!inode->i_extracted_file) {
					ret = WIMLIB_ERR_NOMEM;
					goto out_close_dir_ni;
				}
			}
		}
	}

	/* Create a NTFS directory or file.
	 *
	 * Note: For symbolic links that are not directory junctions, S_IFREG is
	 * passed here, since the reparse data and file attributes are set
	 * later. */
	ni = ntfs_create(dir_ni, 0, (ntfschar*)dentry->file_name,
			 dentry->file_name_len / 2, type);

	if (!ni) {
		ERROR_WITH_ERRNO("Could not create NTFS inode for `%s'",
				 dentry->full_path_utf8);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out_close_dir_ni;
	}

	/* Write the data streams, unless this is a directory or reparse point
	 * */
	if (!(inode->i_attributes & (FILE_ATTRIBUTE_REPARSE_POINT |
				   FILE_ATTRIBUTE_DIRECTORY))) {
		ret = write_ntfs_data_streams(ni, dentry, &args->progress);
		if (ret != 0)
			goto out_close_dir_ni;
	}


	ret = apply_file_attributes_and_security_data(ni, dir_ni, dentry,
						      args->w);
	if (ret != 0)
		goto out_close_dir_ni;

	if (inode->i_attributes & FILE_ATTR_REPARSE_POINT) {
		ret = apply_reparse_data(ni, dentry, &args->progress);
		if (ret != 0)
			goto out_close_dir_ni;
	}

	/* Set DOS (short) name if given */
	if (dentry->short_name_len != 0) {
		char *short_name_utf8;
		size_t short_name_utf8_len;
		ret = utf16_to_utf8(dentry->short_name,
				    dentry->short_name_len,
				    &short_name_utf8,
				    &short_name_utf8_len);
		if (ret != 0)
			goto out_close_dir_ni;

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
		goto out;
	}
out_close_dir_ni:
	if (dir_ni) {
		if (ni) {
			if (ntfs_inode_close_in_dir(ni, dir_ni)) {
				if (ret == 0)
					ret = WIMLIB_ERR_NTFS_3G;
				ERROR_WITH_ERRNO("Failed to close inode for `%s'",
						 dentry->full_path_utf8);
			}
		}
		if (ntfs_inode_close(dir_ni)) {
			if (ret == 0)
				ret = WIMLIB_ERR_NTFS_3G;
			ERROR_WITH_ERRNO("Failed to close inode of directory "
					 "containing `%s'", dentry->full_path_utf8);
		}
	}
out:
	return ret;
}

static int apply_root_dentry_ntfs(const struct wim_dentry *dentry,
				  ntfs_volume *vol, const WIMStruct *w)
{
	ntfs_inode *ni;
	int ret = 0;

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
int apply_dentry_ntfs(struct wim_dentry *dentry, void *arg)
{
	struct apply_args *args = arg;
	ntfs_volume *vol = args->vol;
	WIMStruct *w = args->w;
	struct wim_dentry *orig_dentry;
	struct wim_dentry *other;
	int ret;

	/* Treat the root dentry specially. */
	if (dentry_is_root(dentry))
		return apply_root_dentry_ntfs(dentry, vol, w);
	/* NTFS filename namespaces need careful consideration.  A name for a
	 * NTFS file may be in either the POSIX, Win32, DOS, or Win32+DOS
	 * namespaces.  The following list of assumptions and facts clarify the
	 * way that WIM dentries are mapped to NTFS files.  The statements
	 * marked ASSUMPTION are statements I am assuming to be true due to the
	 * lack of documentation; they are verified in verify_dentry() and
	 * verify_inode() in verify.c.
	 *
	 * - ASSUMPTION: The root WIM dentry has neither a "long name" nor a
	 *   "short name".
	 *
	 * - ASSUMPTION: Every WIM dentry other than the root directory provides
	 *   a non-empty "long name" and a possibly empty "short name".  The
	 *   "short name" corresponds to the DOS name of the file, while the
	 *   "long name" may be Win32 or POSIX.
	 *
	 *   XXX It may actually be legal to have a short name but no long name
	 *
	 * - FACT: If a dentry has a "long name" but no "short name", then it is
	 *   ambigious whether the name is POSIX or Win32+DOS, unless the name
	 *   is a valid POSIX name but not a valid Win32+DOS name.  wimlib
	 *   currently will always create POSIX names for these files, as this
	 *   is the behavior of the ntfs_create() and ntfs_link() functions.
	 *
	 * - FACT: Multiple WIM dentries may correspond to the same underlying
	 *   inode, as provided at this point in the code by the d_inode member.
	 */


	/* Currently wimlib does not apply DOS names to hard linked files due to
	 * issues with ntfs-3g, so the following is commented out. */
#if 0
again:
	/*
	 * libntfs-3g requires that for an NTFS inode with a DOS name, the
	 * corresponding long name be extracted first so that the DOS name is
	 * associated with the correct long name.  Note that by the last
	 * ASSUMPTION above, a NTFS inode can have at most one DOS name (i.e. a
	 * WIM inode can have at most one non-empty short name).
	 *
	 * Therefore, search for an alias of this dentry that has a short name,
	 * and extract it first unless it was already extracted.
	 */
	orig_dentry = NULL;
	if (!dentry->d_inode->i_dos_name_extracted) {
		inode_for_each_dentry(other, dentry->d_inode) {
			if (other->short_name_len && other != dentry &&
			    !other->is_extracted)
			{
				orig_dentry = dentry;
				dentry = other;
				break;
			}
		}
		dentry->d_inode->i_dos_name_extracted = 1;
	}
#endif

	ntfs_inode *dir_ni = dentry_open_parent_ni(dentry, vol);
	if (dir_ni)
		ret = do_apply_dentry_ntfs(dentry, dir_ni, arg);
	else
		ret = WIMLIB_ERR_NTFS_3G;

#if 0
	if (ret == 0 && orig_dentry) {
		dentry = orig_dentry;
		goto again;
	}
#endif
	return ret;
}

/* Transfers the 100-nanosecond precision timestamps from a WIM dentry to a NTFS
 * inode */
int apply_dentry_timestamps_ntfs(struct wim_dentry *dentry, void *arg)
{
	struct apply_args *args = arg;
	ntfs_volume *vol = args->vol;
	u8 *p;
	u8 buf[24];
	ntfs_inode *ni;
	int ret;

	DEBUG("Setting timestamps on `%s'", dentry->full_path_utf8);

	ni = ntfs_pathname_to_inode(vol, NULL, dentry->full_path_utf8);
	if (!ni) {
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 dentry->full_path_utf8);
		return WIMLIB_ERR_NTFS_3G;
	}

	p = buf;
	p = put_u64(p, dentry->d_inode->i_creation_time);
	p = put_u64(p, dentry->d_inode->i_last_write_time);
	p = put_u64(p, dentry->d_inode->i_last_access_time);
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
