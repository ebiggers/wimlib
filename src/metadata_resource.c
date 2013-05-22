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
#include "wimlib/file_io.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/resource.h"
#include "wimlib/security.h"

/*
 * Reads a metadata resource for an image in the WIM file.  The metadata
 * resource consists of the security data, followed by the directory entry for
 * the root directory, followed by all the other directory entries in the
 * filesystem.  The subdir_offset field of each directory entry gives the start
 * of its child entries from the beginning of the metadata resource.  An
 * end-of-directory is signaled by a directory entry of length '0', really of
 * length 8, because that's how long the 'length' field is.
 *
 * @w:		Pointer to the WIMStruct for the WIM file.
 *
 * @imd:	Pointer to the image metadata structure for the image whose
 *		metadata resource we are reading.  Its `metadata_lte' member
 *		specifies the lookup table entry for the metadata resource.  The
 *		rest of the image metadata entry will be filled in by this
 *		function.
 *
 * Returns:	Zero on success, nonzero on failure.
 */
int
read_metadata_resource(WIMStruct *wim, struct wim_image_metadata *imd)
{
	u8 *buf;
	int ret;
	struct wim_dentry *root;
	const struct wim_lookup_table_entry *metadata_lte;
	u64 metadata_len;
	u8 hash[SHA1_HASH_SIZE];
	struct wim_security_data *security_data;
	struct wim_inode *inode;

	metadata_lte = imd->metadata_lte;
	metadata_len = wim_resource_size(metadata_lte);

	DEBUG("Reading metadata resource: original_size = %"PRIu64", "
	      "size = %"PRIu64", offset = %"PRIu64"",
	      metadata_lte->resource_entry.original_size,
	      metadata_lte->resource_entry.size,
	      metadata_lte->resource_entry.offset);

	/* There is no way the metadata resource could possibly be less than (8
	 * + WIM_DENTRY_DISK_SIZE) bytes, where the 8 is for security data (with
	 * no security descriptors) and WIM_DENTRY_DISK_SIZE is for the root
	 * entry. */
	if (metadata_len < 8 + WIM_DENTRY_DISK_SIZE) {
		ERROR("Expected at least %u bytes for the metadata resource",
		      8 + WIM_DENTRY_DISK_SIZE);
		return WIMLIB_ERR_INVALID_RESOURCE_SIZE;
	}

	if (sizeof(size_t) < 8 && metadata_len > 0xffffffff) {
		ERROR("Metadata resource is too large (%"PRIu64" bytes",
		      metadata_len);
		return WIMLIB_ERR_INVALID_RESOURCE_SIZE;
	}

	/* Allocate memory for the uncompressed metadata resource. */
	buf = MALLOC(metadata_len);

	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for uncompressed "
		      "metadata resource", metadata_len);
		return WIMLIB_ERR_NOMEM;
	}

	/* Read the metadata resource into memory.  (It may be compressed.) */
	ret = read_full_resource_into_buf(metadata_lte, buf);
	if (ret)
		goto out_free_buf;

	sha1_buffer(buf, metadata_len, hash);
	if (!hashes_equal(metadata_lte->hash, hash)) {
		ERROR("Metadata resource is corrupted (invalid SHA-1 message digest)!");
		ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
		goto out_free_buf;
	}

	DEBUG("Finished reading metadata resource into memory.");

	/* The root directory entry starts after security data, aligned on an
	 * 8-byte boundary within the metadata resource.
	 *
	 * The security data starts with a 4-byte integer giving its total
	 * length, so if we round that up to an 8-byte boundary that gives us
	 * the offset of the root dentry.
	 *
	 * Here we read the security data into a wim_security_data structure,
	 * which takes case of rouding total_length.  If successful, go ahead
	 * and calculate the offset in the metadata resource of the root dentry.
	 * */

	ret = read_wim_security_data(buf, metadata_len, &security_data);
	if (ret)
		goto out_free_buf;

	DEBUG("Reading root dentry");

	/* Allocate memory for the root dentry and read it into memory */
	root = MALLOC(sizeof(struct wim_dentry));
	if (!root) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_security_data;
	}

	ret = read_dentry(buf, metadata_len,
			  security_data->total_length, root);

	if (ret == 0 && root->length == 0) {
		WARNING("Metadata resource begins with end-of-directory entry "
			"(treating as empty image)");
		FREE(root);
		root = NULL;
		goto out_success;
	}

	if (ret) {
		FREE(root);
		goto out_free_security_data;
	}

	if (dentry_has_long_name(root) || dentry_has_short_name(root)) {
		WARNING("The root directory has a nonempty name (removing it)");
		FREE(root->file_name);
		FREE(root->short_name);
		root->file_name = NULL;
		root->short_name = NULL;
		root->file_name_nbytes = 0;
		root->short_name_nbytes = 0;
	}

	/* This is the root dentry, so set its parent to itself. */
	root->parent = root;

	inode_add_dentry(root, root->d_inode);

	/* Now read the entire directory entry tree into memory. */
	DEBUG("Reading dentry tree");
	ret = read_dentry_tree(buf, metadata_len, root);
	if (ret)
		goto out_free_dentry_tree;

	/* Build hash table that maps hard link group IDs to dentry sets */
	ret = dentry_tree_fix_inodes(root, &imd->inode_list);
	if (ret)
		goto out_free_dentry_tree;


	DEBUG("Running miscellaneous verifications on the dentry tree");
	image_for_each_inode(inode, imd) {
		ret = verify_inode(inode, security_data);
		if (ret)
			goto out_free_dentry_tree;
	}
	DEBUG("Done reading image metadata");
out_success:
	imd->root_dentry = root;
	imd->security_data = security_data;
	INIT_LIST_HEAD(&imd->unhashed_streams);
	ret = 0;
	goto out_free_buf;
out_free_dentry_tree:
	free_dentry_tree(root, wim->lookup_table);
out_free_security_data:
	free_wim_security_data(security_data);
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

/* Like write_wim_resource(), but the resource is specified by a buffer of
 * uncompressed data rather a lookup table entry; also writes the SHA1 hash of
 * the buffer to @hash.  */
static int
write_wim_resource_from_buffer(const void *buf, size_t buf_size,
			       int out_fd, int out_ctype,
			       struct resource_entry *out_res_entry,
			       u8 hash[SHA1_HASH_SIZE])
{
	/* Set up a temporary lookup table entry to provide to
	 * write_wim_resource(). */
	struct wim_lookup_table_entry lte;
	int ret;
	lte.resource_location            = RESOURCE_IN_ATTACHED_BUFFER;
	lte.attached_buffer              = (void*)buf;
	lte.resource_entry.original_size = buf_size;
	lte.resource_entry.flags         = 0;
	lte.unhashed                     = 1;
	ret = write_wim_resource(&lte, out_fd, out_ctype, out_res_entry, 0);
	if (ret == 0)
		copy_hash(hash, lte.hash);
	return ret;
}

/* Write the metadata resource for the current WIM image. */
int
write_metadata_resource(WIMStruct *w)
{
	u8 *buf;
	u8 *p;
	int ret;
	u64 subdir_offset;
	struct wim_dentry *root;
	struct wim_lookup_table_entry *lte;
	u64 metadata_original_size;
	struct wim_security_data *sd;
	struct wim_image_metadata *imd;

	wimlib_assert(w->out_fd != -1);
	wimlib_assert(w->current_image != WIMLIB_NO_IMAGE);

	DEBUG("Writing metadata resource for image %d (offset = %"PRIu64")",
	      w->current_image, filedes_offset(w->out_fd));

	imd = w->image_metadata[w->current_image - 1];

	root = imd->root_dentry;
	sd = imd->security_data;

	if (!root) {
		/* Empty image; create a dummy root. */
		ret = new_filler_directory(T(""), &root);
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
			dentry_correct_total_length(root) + 8;

	/* Calculate the subdirectory offsets for the entire dentry tree. */
	calculate_subdir_offsets(root, &subdir_offset);

	/* Total length of the metadata resource (uncompressed) */
	metadata_original_size = subdir_offset;

	/* Allocate a buffer to contain the uncompressed metadata resource */
	buf = MALLOC(metadata_original_size);
	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for "
		      "metadata resource", metadata_original_size);
		return WIMLIB_ERR_NOMEM;
	}

	/* Write the security data into the resource buffer */
	p = write_wim_security_data(sd, buf);

	/* Write the dentry tree into the resource buffer */
	p = write_dentry_tree(root, p);

	/* We MUST have exactly filled the buffer; otherwise we calculated its
	 * size incorrectly or wrote the data incorrectly. */
	wimlib_assert(p - buf == metadata_original_size);

	/* Get the lookup table entry for the metadata resource so we can update
	 * it. */
	lte = wim_get_current_image_metadata(w)->metadata_lte;

	/* Write the metadata resource to the output WIM using the proper
	 * compression type.  The lookup table entry for the metadata resource
	 * is updated. */
	ret = write_wim_resource_from_buffer(buf, metadata_original_size,
					     w->out_fd,
					     wimlib_get_compression_type(w),
					     &lte->output_resource_entry,
					     lte->hash);
	/* Note that although the SHA1 message digest of the metadata resource
	 * is very likely to have changed, the corresponding lookup table entry
	 * is not actually located in the hash table, so it need not be
	 * re-inserted in the hash table. */

	/* All the data has been written to the new WIM; no need for the buffer
	 * anymore */
	FREE(buf);
	return ret;
}
