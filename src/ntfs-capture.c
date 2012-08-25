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


WIMLIBAPI int wimlib_add_image_from_ntfs_volume(WIMStruct *w,
						const char *device,
						const char *name,
						const char *description,
						const char *flags_element,
						int flags)
{
	int ret;

	if (!device)
		return WIMLIB_ERR_INVALID_PARAM;
	if (flags & (WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE)) {
		ERROR("Cannot dereference files when capturing directly from NTFS");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	return 0;
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
