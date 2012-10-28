/*
 * ntfs-capture.c
 *
 * Capture a WIM image from a NTFS volume.  We capture everything we can,
 * including security data and alternate data streams.
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

#ifdef WITH_NTFS_3G
#include <ntfs-3g/endians.h>
#include <ntfs-3g/types.h>
#endif

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
#include <ntfs-3g/security.h> /* security.h before xattrs.h */
#include <ntfs-3g/xattrs.h>
#include <ntfs-3g/volume.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/* Structure that allows searching the security descriptors by SHA1 message
 * digest. */
struct sd_set {
	struct wim_security_data *sd;
	struct sd_node *root;
};

/* Binary tree node of security descriptors, indexed by the @hash field. */
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
/* Frees a security descriptor index set. */
static void destroy_sd_set(struct sd_set *sd_set)
{
	free_sd_tree(sd_set->root);
}

/* Inserts a a new node into the security descriptor index tree. */
static void insert_sd_node(struct sd_node *new, struct sd_node *root)
{
	int cmp = hashes_cmp(new->hash, root->hash);
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

/* Returns the security ID of the security data having a SHA1 message digest of
 * @hash in the security descriptor index tree rooted at @root.
 *
 * If not found, return -1. */
static int lookup_sd(const u8 hash[SHA1_HASH_SIZE], struct sd_node *root)
{
	int cmp;
	if (!root)
		return -1;
	cmp = hashes_cmp(hash, root->hash);
	if (cmp < 0)
		return lookup_sd(hash, root->left);
	else if (cmp > 0)
		return lookup_sd(hash, root->right);
	else
		return root->security_id;
}

/*
 * Adds a security descriptor to the indexed security descriptor set as well as
 * the corresponding `struct wim_security_data', and returns the new security
 * ID; or, if there is an existing security descriptor that is the same, return
 * the security ID for it.  If a new security descriptor cannot be allocated,
 * return -1.
 */
static int sd_set_add_sd(struct sd_set *sd_set, const char descriptor[],
		         size_t size)
{
	u8 hash[SHA1_HASH_SIZE];
	int security_id;
	struct sd_node *new;
	u8 **descriptors;
	u64 *sizes;
	u8 *descr_copy;
	struct wim_security_data *sd;

	sha1_buffer((const u8*)descriptor, size, hash);

	security_id = lookup_sd(hash, sd_set->root);
	if (security_id >= 0)
		return security_id;

	new = MALLOC(sizeof(*new));
	if (!new)
		goto out;
	descr_copy = MALLOC(size);
	if (!descr_copy)
		goto out_free_node;

	sd = sd_set->sd;

	memcpy(descr_copy, descriptor, size);
	new->security_id = sd->num_entries;
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
	DEBUG("There are now %d security descriptors", sd->num_entries);
	sd->total_length += size + sizeof(sd->sizes[0]);

	if (sd_set->root)
		insert_sd_node(new, sd_set->root);
	else
		sd_set->root = new;
	return new->security_id;
out_free_descr:
	FREE(descr_copy);
out_free_node:
	FREE(new);
out:
	return -1;
}

static inline ntfschar *attr_record_name(ATTR_RECORD *ar)
{
	return (ntfschar*)((u8*)ar + le16_to_cpu(ar->name_offset));
}

/* Calculates the SHA1 message digest of a NTFS attribute.
 *
 * @ni:  The NTFS inode containing the attribute.
 * @ar:	 The ATTR_RECORD describing the attribute.
 * @md:  If successful, the returned SHA1 message digest.
 * @reparse_tag_ret:	Optional pointer into which the first 4 bytes of the
 * 				attribute will be written (to get the reparse
 * 				point ID)
 *
 * Return 0 on success or nonzero on error.
 */
static int ntfs_attr_sha1sum(ntfs_inode *ni, ATTR_RECORD *ar,
			     u8 md[SHA1_HASH_SIZE],
			     u32 *reparse_tag_ret)
{
	s64 pos = 0;
	s64 bytes_remaining;
	char buf[4096];
	ntfs_attr *na;
	SHA_CTX ctx;

	na = ntfs_attr_open(ni, ar->type, attr_record_name(ar),
			    ar->name_length);
	if (!na) {
		ERROR_WITH_ERRNO("Failed to open NTFS attribute");
		return WIMLIB_ERR_NTFS_3G;
	}

	bytes_remaining = na->data_size;
	sha1_init(&ctx);

	DEBUG2("Calculating SHA1 message digest (%"PRIu64" bytes)",
	       bytes_remaining);

	while (bytes_remaining) {
		s64 to_read = min(bytes_remaining, sizeof(buf));
		if (ntfs_attr_pread(na, pos, to_read, buf) != to_read) {
			ERROR_WITH_ERRNO("Error reading NTFS attribute");
			return WIMLIB_ERR_NTFS_3G;
		}
		if (bytes_remaining == na->data_size && reparse_tag_ret)
			*reparse_tag_ret = le32_to_cpu(*(u32*)buf);
		sha1_update(&ctx, buf, to_read);
		pos += to_read;
		bytes_remaining -= to_read;
	}
	sha1_final(md, &ctx);
	ntfs_attr_close(na);
	return 0;
}

/* Load the streams from a WIM file or reparse point in the NTFS volume into the
 * WIM lookup table */
static int capture_ntfs_streams(struct dentry *dentry, ntfs_inode *ni,
				char path[], size_t path_len,
				struct lookup_table *lookup_table,
				ntfs_volume **ntfs_vol_p,
				ATTR_TYPES type)
{
	ntfs_attr_search_ctx *actx;
	u8 attr_hash[SHA1_HASH_SIZE];
	struct ntfs_location *ntfs_loc = NULL;
	int ret = 0;
	struct lookup_table_entry *lte;

	DEBUG2("Capturing NTFS data streams from `%s'", path);

	/* Get context to search the streams of the NTFS file. */
	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		ERROR_WITH_ERRNO("Cannot get NTFS attribute search "
				 "context");
		return WIMLIB_ERR_NTFS_3G;
	}

	/* Capture each data stream or reparse data stream. */
	while (!ntfs_attr_lookup(type, NULL, 0,
				 CASE_SENSITIVE, 0, NULL, 0, actx))
	{
		char *stream_name_utf8;
		u32 reparse_tag;
		u64 data_size = ntfs_get_attribute_value_length(actx->attr);
		u64 name_length = actx->attr->name_length;

		if (data_size == 0) {
			if (errno != 0) {
				ERROR_WITH_ERRNO("Failed to get size of attribute of "
						 "`%s'", path);
				ret = WIMLIB_ERR_NTFS_3G;
				goto out_put_actx;
			}
			/* Empty stream.  No lookup table entry is needed. */
			lte = NULL;
		} else {
			if (type == AT_REPARSE_POINT && data_size < 8) {
				ERROR("`%s': reparse point buffer too small",
				      path);
				ret = WIMLIB_ERR_NTFS_3G;
				goto out_put_actx;
			}
			/* Checksum the stream. */
			ret = ntfs_attr_sha1sum(ni, actx->attr, attr_hash, &reparse_tag);
			if (ret != 0)
				goto out_put_actx;

			/* Make a lookup table entry for the stream, or use an existing
			 * one if there's already an identical stream. */
			lte = __lookup_resource(lookup_table, attr_hash);
			ret = WIMLIB_ERR_NOMEM;
			if (lte) {
				lte->refcnt++;
			} else {
				ntfs_loc = CALLOC(1, sizeof(*ntfs_loc));
				if (!ntfs_loc)
					goto out_put_actx;
				ntfs_loc->ntfs_vol_p = ntfs_vol_p;
				ntfs_loc->path_utf8 = MALLOC(path_len + 1);
				if (!ntfs_loc->path_utf8)
					goto out_free_ntfs_loc;
				memcpy(ntfs_loc->path_utf8, path, path_len + 1);
				if (name_length) {
					ntfs_loc->stream_name_utf16 = MALLOC(name_length * 2);
					if (!ntfs_loc->stream_name_utf16)
						goto out_free_ntfs_loc;
					memcpy(ntfs_loc->stream_name_utf16,
					       attr_record_name(actx->attr),
					       actx->attr->name_length * 2);
					ntfs_loc->stream_name_utf16_num_chars = name_length;
				}

				lte = new_lookup_table_entry();
				if (!lte)
					goto out_free_ntfs_loc;
				lte->ntfs_loc = ntfs_loc;
				lte->resource_location = RESOURCE_IN_NTFS_VOLUME;
				if (type == AT_REPARSE_POINT) {
					dentry->d_inode->reparse_tag = reparse_tag;
					ntfs_loc->is_reparse_point = true;
					lte->resource_entry.original_size = data_size - 8;
					lte->resource_entry.size = data_size - 8;
				} else {
					ntfs_loc->is_reparse_point = false;
					lte->resource_entry.original_size = data_size;
					lte->resource_entry.size = data_size;
				}
				ntfs_loc = NULL;
				DEBUG("Add resource for `%s' (size = %zu)",
				      dentry->file_name_utf8,
				      lte->resource_entry.original_size);
				copy_hash(lte->hash, attr_hash);
				lookup_table_insert(lookup_table, lte);
			}
		}
		if (name_length == 0) {
			/* Unnamed data stream.  Put the reference to it in the
			 * dentry's inode. */
			if (dentry->d_inode->lte) {
				ERROR("Found two un-named data streams for "
				      "`%s'", path);
				ret = WIMLIB_ERR_NTFS_3G;
				goto out_free_lte;
			}
			dentry->d_inode->lte = lte;
		} else {
			/* Named data stream.  Put the reference to it in the
			 * alternate data stream entries */
			struct ads_entry *new_ads_entry;
			size_t stream_name_utf8_len;
			stream_name_utf8 = utf16_to_utf8((const char*)attr_record_name(actx->attr),
							 name_length * 2,
							 &stream_name_utf8_len);
			if (!stream_name_utf8)
				goto out_free_lte;
			new_ads_entry = inode_add_ads(dentry->d_inode, stream_name_utf8);
			FREE(stream_name_utf8);
			if (!new_ads_entry)
				goto out_free_lte;

			wimlib_assert(new_ads_entry->stream_name_len == name_length * 2);

			new_ads_entry->lte = lte;
		}
	}
	ret = 0;
	goto out_put_actx;
out_free_lte:
	free_lookup_table_entry(lte);
out_free_ntfs_loc:
	if (ntfs_loc) {
		FREE(ntfs_loc->path_utf8);
		FREE(ntfs_loc->stream_name_utf16);
		FREE(ntfs_loc);
	}
out_put_actx:
	ntfs_attr_put_search_ctx(actx);
	if (ret == 0)
		DEBUG2("Successfully captured NTFS streams from `%s'", path);
	else
		ERROR("Failed to capture NTFS streams from `%s", path);
	return ret;
}

struct readdir_ctx {
	struct dentry	    *parent;
	ntfs_inode	    *dir_ni;
	char		    *path;
	size_t		     path_len;
	struct lookup_table *lookup_table;
	struct sd_set	    *sd_set;
	const struct capture_config *config;
	ntfs_volume	   **ntfs_vol_p;
	int		     flags;
};

static int
build_dentry_tree_ntfs_recursive(struct dentry **root_p, ntfs_inode *dir_ni,
				 ntfs_inode *ni, char path[], size_t path_len,
				 int name_type,
				 struct lookup_table *lookup_table,
				 struct sd_set *sd_set,
				 const struct capture_config *config,
				 ntfs_volume **ntfs_vol_p,
				 int flags);

static int wim_ntfs_capture_filldir(void *dirent, const ntfschar *name,
				    const int name_len, const int name_type,
				    const s64 pos, const MFT_REF mref,
				    const unsigned dt_type)
{
	struct readdir_ctx *ctx;
	size_t utf8_name_len;
	char *utf8_name;
	struct dentry *child = NULL;
	int ret;
	size_t path_len;

	if (name_type == FILE_NAME_DOS)
		return 0;

	ret = -1;

 	utf8_name = utf16_to_utf8((const char*)name, name_len * 2,
				  &utf8_name_len);
	if (!utf8_name)
		goto out;

	if (utf8_name[0] == '.' &&
	     (utf8_name[1] == '\0' ||
	      (utf8_name[1] == '.' && utf8_name[2] == '\0'))) {
		ret = 0;
		goto out_free_utf8_name;
	}

	ctx = dirent;

	ntfs_inode *ni = ntfs_inode_open(ctx->dir_ni->vol, mref);
	if (!ni) {
		ERROR_WITH_ERRNO("Failed to open NTFS inode");
		goto out_free_utf8_name;
	}
	path_len = ctx->path_len;
	if (path_len != 1)
		ctx->path[path_len++] = '/';
	memcpy(ctx->path + path_len, utf8_name, utf8_name_len + 1);
	path_len += utf8_name_len;
	ret = build_dentry_tree_ntfs_recursive(&child, ctx->dir_ni,
					       ni, ctx->path, path_len, name_type,
					       ctx->lookup_table, ctx->sd_set,
					       ctx->config, ctx->ntfs_vol_p,
					       ctx->flags);

	if (child)
		link_dentry(child, ctx->parent);

	ntfs_inode_close(ni);
out_free_utf8_name:
	FREE(utf8_name);
out:
	return ret;
}

static int change_dentry_short_name(struct dentry *dentry,
				    const char short_name_utf8[],
				    int short_name_utf8_len)
{
	size_t short_name_utf16_len;
	char *short_name_utf16;
	short_name_utf16 = utf8_to_utf16(short_name_utf8, short_name_utf8_len,
					 &short_name_utf16_len);
	if (!short_name_utf16) {
		ERROR_WITH_ERRNO("Failed to convert short name to UTF-16");
		return WIMLIB_ERR_NOMEM;
	}
	dentry->short_name = short_name_utf16;
	dentry->short_name_len = short_name_utf16_len;
	return 0;
}

/* Recursively build a WIM dentry tree corresponding to a NTFS volume.
 * At the same time, update the WIM lookup table with lookup table entries for
 * the NTFS streams, and build an array of security descriptors.
 */
static int build_dentry_tree_ntfs_recursive(struct dentry **root_p,
					    ntfs_inode *dir_ni,
					    ntfs_inode *ni,
				    	    char path[],
					    size_t path_len,
					    int name_type,
				    	    struct lookup_table *lookup_table,
				    	    struct sd_set *sd_set,
				    	    const struct capture_config *config,
				    	    ntfs_volume **ntfs_vol_p,
					    int flags)
{
	u32 attributes;
	int mrec_flags;
	int ret;
	char dos_name_utf8[64];
	struct dentry *root;

	mrec_flags = ni->mrec->flags;
	struct SECURITY_CONTEXT ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.vol = ni->vol;
	ret = ntfs_xattr_system_getxattr(&ctx, XATTR_NTFS_ATTRIB,
					 ni, dir_ni, (char *)&attributes,
					 sizeof(u32));
	if (ret != 4) {
		ERROR_WITH_ERRNO("Failed to get NTFS attributes from `%s'",
				 path);
		return WIMLIB_ERR_NTFS_3G;
	}

	if (exclude_path(path, config, false)) {
		if (flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE) {
			const char *file_type;
			if (attributes & MFT_RECORD_IS_DIRECTORY)
				file_type = "directory";
			else
				file_type = "file";
			printf("Excluding %s `%s' from capture\n",
			       file_type, path);
		}
		*root_p = NULL;
		return 0;
	}

	if (flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
		printf("Scanning `%s'\n", path);

	root = new_dentry_with_timeless_inode(path_basename(path));
	if (!root)
		return WIMLIB_ERR_NOMEM;
	*root_p = root;

	if (dir_ni && (name_type == FILE_NAME_WIN32_AND_DOS
		       || name_type == FILE_NAME_WIN32))
	{
		ret = ntfs_get_ntfs_dos_name(ni, dir_ni, dos_name_utf8,
					     sizeof(dos_name_utf8));
		if (ret > 0) {
			DEBUG("Changing short name of `%s'", path);
			ret = change_dentry_short_name(root, dos_name_utf8,
						       ret);
			if (ret != 0)
				return ret;
		} else {
		#ifdef ENODATA
			if (errno != ENODATA) {
				ERROR_WITH_ERRNO("Error getting DOS name "
						 "of `%s'", path);
				return WIMLIB_ERR_NTFS_3G;
			}
		#endif
		}
	}

	root->d_inode->creation_time    = le64_to_cpu(ni->creation_time);
	root->d_inode->last_write_time  = le64_to_cpu(ni->last_data_change_time);
	root->d_inode->last_access_time = le64_to_cpu(ni->last_access_time);
	root->d_inode->attributes       = le32_to_cpu(attributes);
	root->d_inode->ino              = ni->mft_no;
	root->d_inode->resolved         = true;

	if (attributes & FILE_ATTR_REPARSE_POINT) {
		/* Junction point, symbolic link, or other reparse point */
		ret = capture_ntfs_streams(root, ni, path, path_len,
					   lookup_table, ntfs_vol_p,
					   AT_REPARSE_POINT);
	} else if (mrec_flags & MFT_RECORD_IS_DIRECTORY) {

		/* Normal directory */
		s64 pos = 0;
		struct readdir_ctx ctx = {
			.parent       = root,
			.dir_ni       = ni,
			.path         = path,
			.path_len     = path_len,
			.lookup_table = lookup_table,
			.sd_set       = sd_set,
			.config       = config,
			.ntfs_vol_p   = ntfs_vol_p,
			.flags	      = flags,
		};
		ret = ntfs_readdir(ni, &pos, &ctx, wim_ntfs_capture_filldir);
		if (ret != 0) {
			ERROR_WITH_ERRNO("ntfs_readdir()");
			ret = WIMLIB_ERR_NTFS_3G;
		}
	} else {
		/* Normal file */
		ret = capture_ntfs_streams(root, ni, path, path_len,
					   lookup_table, ntfs_vol_p,
					   AT_DATA);
	}
	if (ret != 0)
		return ret;

	char _sd[1];
	char *sd = _sd;
	errno = 0;
	ret = ntfs_xattr_system_getxattr(&ctx, XATTR_NTFS_ACL,
					 ni, dir_ni, sd,
					 sizeof(sd));
	if (ret > sizeof(sd)) {
		sd = alloca(ret);
		ret = ntfs_xattr_system_getxattr(&ctx, XATTR_NTFS_ACL,
						 ni, dir_ni, sd, ret);
	}
	if (ret > 0) {
		root->d_inode->security_id = sd_set_add_sd(sd_set, sd, ret);
		if (root->d_inode->security_id == -1) {
			ERROR("Out of memory");
			return WIMLIB_ERR_NOMEM;
		}
		DEBUG("Added security ID = %u for `%s'",
		      root->d_inode->security_id, path);
		ret = 0;
	} else if (ret < 0) {
		ERROR_WITH_ERRNO("Failed to get security information from "
				 "`%s'", path);
		ret = WIMLIB_ERR_NTFS_3G;
	} else {
		root->d_inode->security_id = -1;
		DEBUG("No security ID for `%s'", path);
	}
	return ret;
}

static int build_dentry_tree_ntfs(struct dentry **root_p,
				  const char *device,
				  struct lookup_table *lookup_table,
				  struct wim_security_data *sd,
				  const struct capture_config *config,
				  int flags,
				  void *extra_arg)
{
	ntfs_volume *vol;
	ntfs_inode *root_ni;
	int ret = 0;
	struct sd_set sd_set = {
		.sd = sd,
		.root = NULL,
	};
	ntfs_volume **ntfs_vol_p = extra_arg;

	DEBUG("Mounting NTFS volume `%s' read-only", device);

	vol = ntfs_mount(device, MS_RDONLY);
	if (!vol) {
		ERROR_WITH_ERRNO("Failed to mount NTFS volume `%s' read-only",
				 device);
		return WIMLIB_ERR_NTFS_3G;
	}
	ntfs_open_secure(vol);

	/* We don't want to capture the special NTFS files such as $Bitmap.  Not
	 * to be confused with "hidden" or "system" files which are real files
	 * that we do need to capture.  */
	NVolClearShowSysFiles(vol);

	DEBUG("Opening root NTFS dentry");
	root_ni = ntfs_inode_open(vol, FILE_root);
	if (!root_ni) {
		ERROR_WITH_ERRNO("Failed to open root inode of NTFS volume "
				 "`%s'", device);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	/* Currently we assume that all the UTF-8 paths fit into this length and
	 * there is no check for overflow. */
	char *path = MALLOC(32768);
	if (!path) {
		ERROR("Could not allocate memory for NTFS pathname");
		goto out_cleanup;
	}

	path[0] = '/';
	path[1] = '\0';
	ret = build_dentry_tree_ntfs_recursive(root_p, NULL, root_ni, path, 1,
					       FILE_NAME_POSIX, lookup_table,
					       &sd_set, config, ntfs_vol_p,
					       flags);
out_cleanup:
	FREE(path);
	ntfs_inode_close(root_ni);
	destroy_sd_set(&sd_set);

out:
	if (ret) {
		if (ntfs_umount(vol, FALSE) != 0) {
			ERROR_WITH_ERRNO("Failed to unmount NTFS volume `%s'",
					 device);
			if (ret == 0)
				ret = WIMLIB_ERR_NTFS_3G;
		}
	} else {
		/* We need to leave the NTFS volume mounted so that we can read
		 * the NTFS files again when we are actually writing the WIM */
		*ntfs_vol_p = vol;
	}
	return ret;
}



WIMLIBAPI int wimlib_add_image_from_ntfs_volume(WIMStruct *w,
						const char *device,
						const char *name,
						const char *config_str,
						size_t config_len,
						int flags)
{
	if (flags & (WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE)) {
		ERROR("Cannot dereference files when capturing directly from NTFS");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	return do_add_image(w, device, name, config_str, config_len, flags,
			    build_dentry_tree_ntfs, &w->ntfs_vol);
}

#else /* WITH_NTFS_3G */
WIMLIBAPI int wimlib_add_image_from_ntfs_volume(WIMStruct *w,
						const char *device,
						const char *name,
						const char *config_str,
						size_t config_len,
						int flags)
{
	ERROR("wimlib was compiled without support for NTFS-3g, so");
	ERROR("we cannot capture a WIM image directly from a NTFS volume");
	return WIMLIB_ERR_UNSUPPORTED;
}
#endif /* WITH_NTFS_3G */
