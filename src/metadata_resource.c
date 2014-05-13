/*
 * metadata_resource.c
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/resource.h"
#include "wimlib/security.h"
#include "wimlib/write.h"

/*
 * Reads and parses a metadata resource for an image in the WIM file.
 *
 * @wim:
 *	Pointer to the WIMStruct for the WIM file.
 *
 * @imd:
 *	Pointer to the image metadata structure for the image whose metadata
 *	resource we are reading.  Its `metadata_lte' member specifies the lookup
 *	table entry for the metadata resource.  The rest of the image metadata
 *	entry will be filled in by this function.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	WIMLIB_ERR_NOMEM
 *	WIMLIB_ERR_READ
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 *	WIMLIB_ERR_DECOMPRESSION
 */
int
read_metadata_resource(WIMStruct *wim, struct wim_image_metadata *imd)
{
	const struct wim_lookup_table_entry *metadata_lte;
	void *buf;
	int ret;
	struct wim_security_data *sd;
	struct wim_dentry *root;
	struct wim_inode *inode;

	metadata_lte = imd->metadata_lte;

	DEBUG("Reading metadata resource (size=%"PRIu64").", metadata_lte->size);

	/* Read the metadata resource into memory.  (It may be compressed.)  */
	ret = read_full_stream_into_alloc_buf(metadata_lte, &buf);
	if (ret)
		return ret;

	/* Checksum the metadata resource.  */
	if (!metadata_lte->dont_check_metadata_hash) {
		u8 hash[SHA1_HASH_SIZE];

		sha1_buffer(buf, metadata_lte->size, hash);
		if (!hashes_equal(metadata_lte->hash, hash)) {
			ERROR("Metadata resource is corrupted "
			      "(invalid SHA-1 message digest)!");
			ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
			goto out_free_buf;
		}
	}

	/* Parse the metadata resource.
	 *
	 * Notes: The metadata resource consists of the security data, followed
	 * by the directory entry for the root directory, followed by all the
	 * other directory entries in the filesystem.  The subdir_offset field
	 * of each directory entry gives the start of its child entries from the
	 * beginning of the metadata resource.  An end-of-directory is signaled
	 * by a directory entry of length '0', really of length 8, because
	 * that's how long the 'length' field is.  */

	ret = read_wim_security_data(buf, metadata_lte->size, &sd);
	if (ret)
		goto out_free_buf;

	ret = read_dentry_tree(buf, metadata_lte->size, sd->total_length, &root);
	if (ret)
		goto out_free_security_data;

	/* We have everything we need from the buffer now.  */
	FREE(buf);
	buf = NULL;

	/* Calculate and validate inodes.  */

	ret = dentry_tree_fix_inodes(root, &imd->inode_list);
	if (ret)
		goto out_free_dentry_tree;

	image_for_each_inode(inode, imd) {
		ret = verify_inode(inode, sd);
		if (ret)
			goto out_free_dentry_tree;
	}

	/* Success; fill in the image_metadata structure.  */
	imd->root_dentry = root;
	imd->security_data = sd;
	INIT_LIST_HEAD(&imd->unhashed_streams);
	DEBUG("Done parsing metadata resource.");
	return 0;

out_free_dentry_tree:
	free_dentry_tree(root, NULL);
out_free_security_data:
	free_wim_security_data(sd);
out_free_buf:
	FREE(buf);
	return ret;
}

static void
recalculate_security_data_length(struct wim_security_data *sd)
{
	u32 total_length = sizeof(u64) * sd->num_entries + 2 * sizeof(u32);
	for (u32 i = 0; i < sd->num_entries; i++)
		total_length += sd->sizes[i];
	sd->total_length = (total_length + 7) & ~7;
}

static int
prepare_metadata_resource(WIMStruct *wim, int image,
			  u8 **buf_ret, size_t *len_ret)
{
	u8 *buf;
	u8 *p;
	int ret;
	u64 subdir_offset;
	struct wim_dentry *root;
	u64 len;
	struct wim_security_data *sd;
	struct wim_image_metadata *imd;

	DEBUG("Preparing metadata resource for image %d", image);

	ret = select_wim_image(wim, image);
	if (ret)
		return ret;

	imd = wim->image_metadata[image - 1];

	root = imd->root_dentry;
	sd = imd->security_data;

	if (!root) {
		/* Empty image; create a dummy root.  */
		ret = new_filler_directory(&root);
		if (ret)
			return ret;
		imd->root_dentry = root;
	}

	/* Offset of first child of the root dentry.  It's equal to:
	 * - The total length of the security data, rounded to the next 8-byte
	 *   boundary,
	 * - plus the total length of the root dentry,
	 * - plus 8 bytes for an end-of-directory entry following the root
	 *   dentry (shouldn't really be needed, but just in case...)
	 */
	recalculate_security_data_length(sd);
	subdir_offset = (((u64)sd->total_length + 7) & ~7) +
			dentry_out_total_length(root) + 8;

	/* Calculate the subdirectory offsets for the entire dentry tree.  */
	calculate_subdir_offsets(root, &subdir_offset);

	/* Total length of the metadata resource (uncompressed).  */
	len = subdir_offset;

	/* Allocate a buffer to contain the uncompressed metadata resource.  */
	buf = MALLOC(len);
	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for "
		      "metadata resource", len);
		return WIMLIB_ERR_NOMEM;
	}

	/* Write the security data into the resource buffer.  */
	p = write_wim_security_data(sd, buf);

	/* Write the dentry tree into the resource buffer.  */
	p = write_dentry_tree(root, p);

	/* We MUST have exactly filled the buffer; otherwise we calculated its
	 * size incorrectly or wrote the data incorrectly.  */
	wimlib_assert(p - buf == len);

	*buf_ret = buf;
	*len_ret = len;
	return 0;
}

int
write_metadata_resource(WIMStruct *wim, int image, int write_resource_flags)
{
	int ret;
	u8 *buf;
	size_t len;
	struct wim_image_metadata *imd;

	ret = prepare_metadata_resource(wim, image, &buf, &len);
	if (ret)
		return ret;

	imd = wim->image_metadata[image - 1];

	/* Write the metadata resource to the output WIM using the proper
	 * compression type, in the process updating the lookup table entry for
	 * the metadata resource.  */
	ret = write_wim_resource_from_buffer(buf, len, WIM_RESHDR_FLAG_METADATA,
					     &wim->out_fd,
					     wim->out_compression_type,
					     wim->out_chunk_size,
					     &imd->metadata_lte->out_reshdr,
					     imd->metadata_lte->hash,
					     write_resource_flags);

	/* Original checksum was overridden; set a flag so it isn't used.  */
	imd->metadata_lte->dont_check_metadata_hash = 1;

	FREE(buf);
	return ret;
}
