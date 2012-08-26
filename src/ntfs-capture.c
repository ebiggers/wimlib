/*
 * ntfs-capture.c
 *
 * Capture a WIM image from a NTFS volume.  We capture everything we can,
 * including security data and alternate data streams.  There should be no loss
 * of information.
 */

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
#include "io.h"
#include <ntfs-3g/layout.h>
#include <ntfs-3g/acls.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/misc.h>
#include <ntfs-3g/reparse.h>
#include <ntfs-3g/security.h>
#include <ntfs-3g/volume.h>
#include <stdlib.h>
#include <unistd.h>

extern int ntfs_inode_get_security(ntfs_inode *ni, u32 selection, char *buf,
				   u32 buflen, u32 *psize);

extern int ntfs_inode_get_attributes(ntfs_inode *ni);

struct sd_tree {
	u32 num_sds;
	struct wim_security_data *sd;
	struct sd_node *root;
};

struct sd_node {
	int security_id;
	u8 hash[SHA1_HASH_SIZE];
	struct sd_node *left;
	struct sd_node *right;
};

static void free_sd_tree(struct sd_node *root)
{
	if (root) {
		free_sd_tree(root->left);
		free_sd_tree(root->right);
		FREE(root);
	}
}

static void insert_sd_node(struct sd_node *new, struct sd_node *root)
{
	int cmp = hashes_cmp(root->hash, new->hash);
	if (cmp < 0) {
		if (root->left)
			insert_sd_node(new, root->left);
		else 
			root->left = new;
	} else if (cmp > 0) {
		if (root->right)
			insert_sd_node(new, root->right);
		else 
			root->right = new;
	} else {
		wimlib_assert(0);
	}
}

static int lookup_sd(const u8 hash[SHA1_HASH_SIZE], struct sd_node *node)
{
	int cmp;
	if (!node)
		return -1;
	cmp = hashes_cmp(hash, node->hash);
	if (cmp < 0)
		return lookup_sd(hash, node->left);
	else if (cmp > 0)
		return lookup_sd(hash, node->right);
	else
		return node->security_id;
}

static int tree_add_sd(struct sd_tree *tree, const u8 *descriptor,
		       size_t size)
{
	u8 hash[SHA1_HASH_SIZE];
	int security_id;
	struct sd_node *new;
	u8 **descriptors;
	u64 *sizes;
	u8 *descr_copy;
	struct wim_security_data *sd = tree->sd;
	sha1_buffer(descriptor, size, hash);

	security_id = lookup_sd(hash, tree->root);
	if (security_id >= 0)
		return security_id;

	new = MALLOC(sizeof(struct sd_node));
	if (!new)
		return -1;
	descr_copy = MALLOC(size);
	if (!descr_copy)
		goto out_free_node;
	memcpy(descr_copy, descriptor, size);
	new->security_id = tree->num_sds++;
	new->left = NULL;
	new->right = NULL;
	copy_hash(new->hash, hash);

	descriptors = REALLOC(sd->descriptors,
			      (sd->num_entries + 1) * sizeof(sd->descriptors[0]));
	if (!descriptors)
		goto out_free_descr;
	sd->descriptors = descriptors;
	sizes = REALLOC(sd->sizes,
			(sd->num_entries + 1) * sizeof(sd->sizes[0]));
	if (!sizes)
		goto out_free_descr;
	sd->sizes = sizes;
	sd->descriptors[sd->num_entries] = descr_copy;
	sd->sizes[sd->num_entries] = size;
	sd->num_entries++;
	sd->total_length += size + 8;

	if (tree->root)
		insert_sd_node(tree->root, new);
	else
		tree->root = new;
	return new->security_id;
out_free_descr:
	FREE(descr_copy);
out_free_node:
	FREE(new);
	return -1;
}

#if 0
static int build_sd_tree(struct wim_security_data *sd, struct sd_tree *tree)
{
	int ret;
	u32 orig_num_entries = sd->num_entries;
	u32 orig_total_length = sd->total_length;

	tree->num_sds = 0;
	tree->sd = sd;
	tree->root = NULL;

	for (u32 i = 0; i < sd->num_entries; i++) {
		ret = tree_add_sd(tree, sd->descriptors[i], sd->sizes[i]);
		if (ret < 0)
			goto out_revert;
	}
	return 0;
out_revert:
	sd->num_entries = orig_num_entries;
	sd->total_length = orig_total_length;
	free_sd_tree(tree->root);
	return ret;
}
#endif

static int ntfs_attr_sha1sum(ntfs_inode *ni, ATTR_RECORD *ar,
			     u8 md[SHA1_HASH_SIZE])
{
	s64 pos = 0;
	s64 bytes_remaining;
	char buf[4096];
	ntfs_attr *na;
	SHA_CTX ctx;

	na = ntfs_attr_open(ni, ar->type,
			    (ntfschar*)((u8*)ar + le16_to_cpu(ar->name_offset)),
			    ar->name_length);
	if (!na) {
		ERROR_WITH_ERRNO("Failed to open NTFS attribute");
		return WIMLIB_ERR_NTFS_3G;
	}

	bytes_remaining = na->data_size;
	sha1_init(&ctx);

	while (bytes_remaining) {
		s64 to_read = min(bytes_remaining, sizeof(buf));
		if (ntfs_attr_pread(na, pos, to_read, buf) != to_read) {
			ERROR_WITH_ERRNO("Error reading NTFS attribute");
			return WIMLIB_ERR_NTFS_3G;
		}
		sha1_update(&ctx, buf, to_read);
		pos += to_read;
		bytes_remaining -= to_read;
	}
	sha1_final(md, &ctx);
	ntfs_attr_close(na);
	return 0;
}

static int __build_dentry_tree_ntfs(struct dentry *dentry, ntfs_inode *ni,
				    char path[], size_t path_len,
				    struct lookup_table *lookup_table,
				    struct sd_tree *tree)
{
	u32 attributes = ntfs_inode_get_attributes(ni);
	int mrec_flags = ni->mrec->flags;
	u32 sd_size;
	int ret = 0;

	dentry->creation_time    = le64_to_cpu(ni->creation_time);
	dentry->last_write_time  = le64_to_cpu(ni->last_data_change_time);
	dentry->last_access_time = le64_to_cpu(ni->last_access_time);
	dentry->security_id      = le32_to_cpu(ni->security_id);
	dentry->attributes       = le32_to_cpu(attributes);
	dentry->resolved = true;

	if (mrec_flags & MFT_RECORD_IS_DIRECTORY) {
		if (attributes & FILE_ATTR_REPARSE_POINT) {
			/* Junction point */
		} else {
			/* Normal directory */
		}
	} else {
		if (attributes & FILE_ATTR_REPARSE_POINT) {
			/* Symbolic link or other reparse point */
		} else {
			/* Normal file */
			ntfs_attr_search_ctx *actx;
			u8 attr_hash[SHA1_HASH_SIZE];
			struct lookup_table_entry *lte;

			actx = ntfs_attr_get_search_ctx(ni, NULL);
			if (!actx) {
				ERROR_WITH_ERRNO("Cannot get attribute search "
						 "context");
				return WIMLIB_ERR_NTFS_3G;
			}
			while (!ntfs_attr_lookup(AT_DATA, NULL, 0,
						 CASE_SENSITIVE, 0, NULL, 0, actx))
			{
				ret = ntfs_attr_sha1sum(ni, actx->attr, attr_hash);
				if (ret != 0)
					return ret;
				lte = __lookup_resource(lookup_table, attr_hash);
				if (lte) {
					lte->refcnt++;
				} else {
					/*char *file_on_disk = STRDUP(root_disk_path);*/
					/*if (!file_on_disk) {*/
						/*ERROR("Failed to allocate memory for file path");*/
						/*return WIMLIB_ERR_NOMEM;*/
					/*}*/
					/*lte = new_lookup_table_entry();*/
					/*if (!lte) {*/
						/*FREE(file_on_disk);*/
						/*return WIMLIB_ERR_NOMEM;*/
					/*}*/
					/*lte->file_on_disk = file_on_disk;*/
					/*lte->resource_location = RESOURCE_IN_FILE_ON_DISK;*/
					/*lte->resource_entry.original_size = root_stbuf.st_size;*/
					/*lte->resource_entry.size = root_stbuf.st_size;*/
					/*copy_hash(lte->hash, hash);*/
					/*lookup_table_insert(lookup_table, lte);*/
				}
				dentry->lte = lte;
			}
		}
	}
	ret = ntfs_inode_get_security(ni,
				      OWNER_SECURITY_INFORMATION |
				      GROUP_SECURITY_INFORMATION |
				      DACL_SECURITY_INFORMATION  |
				      SACL_SECURITY_INFORMATION,
				      NULL, 0, &sd_size);
	u8 sd[sd_size];
	ret = ntfs_inode_get_security(ni,
				      OWNER_SECURITY_INFORMATION |
				      GROUP_SECURITY_INFORMATION |
				      DACL_SECURITY_INFORMATION  |
				      SACL_SECURITY_INFORMATION,
				      sd, sd_size, &sd_size);
	dentry->security_id = tree_add_sd(tree, sd, sd_size);
	return 0;
}

static int build_dentry_tree_ntfs(struct dentry *root_dentry,
				  const char *device,
				  struct lookup_table *lookup_table,
				  struct wim_security_data *sd,
				  int flags,
				  void *extra_arg)
{
	ntfs_volume *vol;
	ntfs_inode *root_ni;
	int ret = 0;
	struct sd_tree tree;
	tree.sd = sd;
	tree.root = NULL;
	ntfs_volume **ntfs_vol_p = extra_arg;
	
	vol = ntfs_mount(device, MS_RDONLY);
	if (!vol) {
		ERROR_WITH_ERRNO("Failed to mount NTFS volume `%s' read-only",
				 device);
		return WIMLIB_ERR_NTFS_3G;
	}
	root_ni = ntfs_inode_open(vol, FILE_root);
	if (!root_ni) {
		ERROR_WITH_ERRNO("Failed to open root inode of NTFS volume "
				 "`%s'", device);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}
	char path[4096];
	path[0] = '/';
	path[1] = '\0';
	ret = __build_dentry_tree_ntfs(root_dentry, root_ni, path, 1,
				       lookup_table, &tree);

out:
	if (ntfs_umount(vol, FALSE) != 0) {
		ERROR_WITH_ERRNO("Failed to unmount NTFS volume `%s'", device);
		if (ret == 0)
			ret = WIMLIB_ERR_NTFS_3G;
	}
	return ret;
}

WIMLIBAPI int wimlib_add_image_from_ntfs_volume(WIMStruct *w,
						const char *device,
						const char *name,
						const char *description,
						const char *flags_element,
						int flags)
{
	if (flags & (WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE)) {
		ERROR("Cannot dereference files when capturing directly from NTFS");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	return do_add_image(w, device, name, description, flags_element, flags,
			    build_dentry_tree_ntfs,
			    &w->ntfs_vol);
}

#else /* WITH_NTFS_3G */
WIMLIBAPI int wimlib_add_image_from_ntfs_volume(WIMStruct *w,
						const char *device,
						const char *name,
						const char *description,
						const char *flags_element,
						int flags)
{
	ERROR("wimlib was compiled without support for NTFS-3g, so");
	ERROR("we cannot capture a WIM image directly from a NTFS volume");
	return WIMLIB_ERR_UNSUPPORTED;
}
#endif /* WITH_NTFS_3G */
