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
#include <ntfs-3g/volume.h>
#include <ntfs-3g/security.h>
#include <ntfs-3g/misc.h>
#include <stdlib.h>
#include <unistd.h>

struct ntfs_apply_args {
	struct SECURITY_API *scapi;
	ntfs_volume *vol;
	const struct wim_security_data *sd;
	int flags;
	struct ntfs_inode *parent;
};

/*
 *		Initializations before calling ntfs_get_file_security()
 *	ntfs_set_file_security() and ntfs_read_directory()
 *
 *	Returns an (obscured) struct SECURITY_API* needed for further calls
 *		NULL if device is mounted (EBUSY)
 */

static struct SECURITY_API *_ntfs_initialize_file_security(const char *device,
							   unsigned long flags)
{
	ntfs_volume *vol;
	unsigned long mntflag;
	int mnt;
	struct SECURITY_API *scapi;
	struct SECURITY_CONTEXT *scx;

	scapi = (struct SECURITY_API*)NULL;
	mnt = ntfs_check_if_mounted(device, &mntflag);
	if (!mnt && !(mntflag & NTFS_MF_MOUNTED)) {
		vol = ntfs_mount(device, flags);
		if (vol) {
			scapi = (struct SECURITY_API*)
				ntfs_malloc(sizeof(struct SECURITY_API));
			if (!ntfs_volume_get_free_space(vol)
			    && scapi) {
				scapi->magic = MAGIC_API;
				scapi->seccache = (struct PERMISSIONS_CACHE*)NULL;
				scx = &scapi->security;
				scx->vol = vol;
				scx->uid = 0;
				scx->gid = 0;
				scx->pseccache = &scapi->seccache;
				scx->vol->secure_flags = (1 << SECURITY_DEFAULT) |
							(1 << SECURITY_RAW);
				ntfs_open_secure(vol);
				ntfs_build_mapping(scx,(const char*)NULL,TRUE);
			} else {
				if (scapi)
					free(scapi);
				else
					errno = ENOMEM;
				mnt = ntfs_umount(vol,FALSE);
				scapi = (struct SECURITY_API*)NULL;
			}
		}
	} else
		errno = EBUSY;
	return (scapi);
}

static int ntfs_apply_dentry(struct dentry *dentry, void *arg)
{
	struct ntfs_apply_args *args       = arg;
	struct SECURITY_API *scapi         = args->scapi;
	ntfs_volume *vol                   = args->vol;
	const struct wim_security_data *sd = args->sd;
	int flags                          = args->flags;
	int ret = 0;
	ntfs_inode *dir_ni, *ni;
	le32 secid;

	DEBUG("Applying `%s'", dentry->full_path_utf8);

	if (dentry_is_root(dentry))
		return 0;

	if (flags & WIMLIB_EXTRACT_FLAG_VERBOSE) {
		wimlib_assert(dentry->full_path_utf8);
		puts(dentry->full_path_utf8);
	}

	char *p = dentry->full_path_utf8 + dentry->full_path_utf8_len;
	do {
		p--;
	} while (*p != '/');

	char orig = *p;
	*p = '\0';
	const char *dir_name;
	if (p == dentry->full_path_utf8)
		dir_name = "/"; 
	else
		dir_name = dentry->full_path_utf8;

	dir_ni = ntfs_pathname_to_inode(vol, NULL, dir_name);
	if (!dir_ni) {
		ret = WIMLIB_ERR_NTFS_3G;
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 dir_name);
		goto out;
	}
	DEBUG("Found NTFS inode for `%s'", dir_name);
	*p = orig;

	ret = 0;
	secid = 0;
	if (dentry_is_regular_file(dentry)) {
		ni = ntfs_create(dir_ni, 0, (ntfschar*)dentry->file_name,
				 dentry->file_name_len / 2, S_IFREG);
	} else if (dentry_is_directory(dentry)) {
		ni = ntfs_create(dir_ni, 0, (ntfschar*)dentry->file_name,
				 dentry->file_name_len / 2, S_IFDIR);
	} else {
		wimlib_assert(0);
		goto out;
	}
	if (!ni) {
		*p = orig;
		ERROR_WITH_ERRNO("Could not create NTFS object for `%s'",
				 dentry->full_path_utf8);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}
	if (ntfs_inode_close_in_dir(ni, dir_ni) != 0) {
		ERROR_WITH_ERRNO("Failed to close new inode");
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	} else {
		DEBUG("Closed inode `%s'", dentry->full_path_utf8);
	}
	if (ntfs_inode_close(dir_ni) != 0) {
		ret = WIMLIB_ERR_NTFS_3G;
		ERROR_WITH_ERRNO("Failed to close directory inode");
		goto out;
	} else {
		DEBUG("Closed parent inode");
	}
	if (dentry->security_id != -1) {
		wimlib_assert(dentry->security_id < sd->num_entries);
		DEBUG("Applying security descriptor %d to `%s'",
		      dentry->security_id, dentry->full_path_utf8);
		ret = ntfs_set_file_security(scapi, dentry->full_path_utf8,
					     ~0,
					     sd->descriptors[dentry->security_id]);
		if (ret != 0) {
			ERROR_WITH_ERRNO("Failed to set security data on `%s'",
					dentry->full_path_utf8);
			ret = WIMLIB_ERR_NTFS_3G;
			goto out;
		}
	}
	DEBUG("Setting file attributes 0x%x on `%s'",
	       dentry->attributes, dentry->full_path_utf8);
	if (!ntfs_set_file_attributes(scapi, dentry->full_path_utf8,
				      dentry->attributes)) {
		ERROR_WITH_ERRNO("Failed to set NTFS file attributes on `%s'",
				 dentry->full_path_utf8);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}
out:
	return ret;
}

static int do_ntfs_apply(WIMStruct *w, const char *device, int flags)
{
	struct SECURITY_API *scapi;
	int ret;
	
	scapi = _ntfs_initialize_file_security(device, 0);
	if (!scapi) {
		ERROR_WITH_ERRNO("Failed to initialize NTFS file security API "
				 "on NTFS volume `%s'", device);
		return WIMLIB_ERR_NTFS_3G;
	}
	struct ntfs_apply_args args = {
		.scapi = scapi,
		.vol   = scapi->security.vol,
		.sd    = wim_security_data(w),
		.flags = flags,
	};
	ret = for_dentry_in_tree(wim_root_dentry(w), ntfs_apply_dentry,
				 &args);
out:
	if (!ntfs_leave_file_security(scapi)) {
		ERROR_WITH_ERRNO("Failed to leave file security");
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

	/*if (getuid() != 0) {*/
		/*ERROR("We are not root, but NTFS-3g requires root privileges to set arbitrary");*/
		/*ERROR("security data on the NTFS filesystem.  Please run this program as root");*/
		/*ERROR("if you want to extract a WIM image while preserving NTFS-specific");*/
		/*ERROR("information.");*/

		/*return WIMLIB_ERR_NOT_ROOT;*/
	/*}*/
	return do_ntfs_apply(w, device, flags);
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
