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
#include <unistd.h>

struct ntfs_apply_args {
	struct SECURITY_API *scapi;
	ntfs_volume *vol;
	const struct wim_security_data *sd;
	int flags;
	struct ntfs_inode *parent;
};

static int ntfs_apply_dentry(struct dentry *dentry, void *arg)
{
	struct ntfs_apply_args *args       = arg;
	struct SECURITY_API *scapi         = args->scapi;
	ntfs_volume *vol                   = args->vol;
	const struct wim_security_data *sd = args->sd;
	int flags                          = args->flags;
	int ret = 0;
	ntfs_inode *dir_ni, *ni;

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
	const char *dir_name = dentry->full_path_utf8;

	dir_ni = ntfs_pathname_to_inode(vol, NULL, dir_name);
	if (!dir_ni) {
		ret = WIMLIB_ERR_NTFS_3G;
		ERROR_WITH_ERRNO("Could not find NTFS inode for `%s'",
				 dir_name);
		goto out;
	}

	ret = 0;
	if (dentry_is_regular_file(dentry)) {
		ni = ntfs_create(dir_ni, 0, (ntfschar*)dentry->file_name,
				 dentry->file_name_len, S_IFREG);
	} else if (dentry_is_directory(dentry)) {
		ni = ntfs_create(dir_ni, 0, (ntfschar*)dentry->file_name,
				 dentry->file_name_len, S_IFDIR);
	} else {
		goto out;
	}
	if (!ni) {
		ERROR_WITH_ERRNO("Could not create NTFS object for `%s'",
				 dentry->full_path_utf8);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}
out:
	*p = orig;
	return ret;
}

static int do_ntfs_apply(WIMStruct *w, const char *device, int flags)
{
	struct SECURITY_API *scapi;
	
	scapi = ntfs_initialize_file_security(device, 0);
	if (!scapi) {
		ERROR_WITH_ERRNO("Failed to initialize NTFS file security API "
				 "on NTFS volume `%s'", device);
	}
	struct ntfs_apply_args args = {
		.scapi = scapi,
		.vol = scapi->security.vol,
		.sd = wim_security_data(w),
		.flags = flags,
	};
	return for_dentry_in_tree(wim_root_dentry(w), ntfs_apply_dentry,
				  &args);
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

	if (getuid() != 0) {
		ERROR("We are not root, but NTFS-3g requires root privileges to set arbitrary");
		ERROR("security data on the NTFS filesystem.  Please run this program as root");
		ERROR("if you want to extract a WIM image while preserving NTFS-specific");
		ERROR("information.");

		return WIMLIB_ERR_NOT_ROOT;
	}
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
