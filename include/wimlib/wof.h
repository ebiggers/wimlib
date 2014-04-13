/*
 * wof.h
 *
 * Definitions for Windows Overlay File System Filter (WOF) ioctls.  See
 * http://msdn.microsoft.com/en-us/library/windows/hardware/ff540367(v=vs.85).aspx
 * for more information.
 */

#ifndef _WOF_H_
#define _WOF_H_

#include "wimlib/types.h"

#define WOF_CURRENT_VERSION	1
#define WOF_PROVIDER_WIM	1
#define WIM_PROVIDER_CURRENT_VERSION 1

/* Identifies a backing provider for a specific overlay service version.  */
struct wof_external_info {

	/* Version of the overlay service supported by the backing provider.
	 * Set to WOF_CURRENT_VERSION.  */
	u32 version;

	/* Identifier for the backing provider.  Example value:
	 * WOF_PROVIDER_WIM.  */
	u32 provider;
};

/* WOF reparse points can't be directly manipulated on Windows; setting the
 * reparse data doesn't seem to work, and the WOF driver hides the reparse
 * points so their data can't be read from Windows 8.1 and later.  Use the
 * ioctls (FSCTL_SET_EXTERNAL_BACKING, FSCTL_GET_EXTERNAL_BACKING,
 * FSCTL_DELETE_EXTERNAL_BACKING) instead.  */
#if 0
/*
 * Format of the reparse data of WoF (Windows Overlay File System Filter)
 * reparse points.  These include WIMBoot "pointer files".
 *
 * Notes:
 *	- Reparse tag is 0x80000017
 *	- Don't make these if the file has no unnamed data stream, has an empty
 *	  unnamed data stream, or already is a reparse point.
 *	- There is nowhere to put named data streams.  They have to copied
 *	  literally to the reparse point file.
 */
struct wof_rpdata_disk {
	struct wof_external_info info;
	union {
		struct {
			/* (Guess) Version of this structure --- set to 2.  */
			u64 version;

			/* Integer ID that identifies the WIM.  */
			u64 data_source_id;

			/* SHA1 message digest of the file's unnamed data
			 * stream.  */
			u8 stream_sha1[20];

			/* SHA1 message digest of the WIM's lookup table.  */
			u8 wim_lookup_table_sha1[20];

			/* Uncompressed size of the file's unnamed data stream,
			 * in bytes.  */
			u64 stream_uncompressed_size;

			/* Compressed size of the file's unnamed data stream, in
			 * bytes.  If stream is stored uncompressed, set this
			 * the same as the uncompressed size.  */
			u64 stream_compressed_size;

			/* Byte offset of the file's unnamed data stream in the
			 * WIM.  */
			u64 stream_offset_in_wim;
		} wim;
	} provider_data;
};
#endif

/*****************************************************************************
 *
 * --- FSCTL_SET_EXTERNAL_BACKING ---
 *
 * Sets the backing source of a file.
 *
 * DeviceType:	9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:	0 (FILE_ANY_ACCESS)
 * Function:	195
 * Method:	0 (METHOD_BUFFERED)
 *
 * Input buffer:  'struct wof_external_info' followed by provider-specific data
 * ('struct wim_provider_external_info' in the case of WIM).
 *
 * Output buffer: None
 */
#define FSCTL_SET_EXTERNAL_BACKING 0x9030C

struct wim_provider_external_info {

	/* Set to WIM_PROVIDER_CURRENT_VERSION.  */
	u32 version;

	/* 0 when WIM provider active, otherwise
	 * WIM_PROVIDER_EXTERNAL_FLAG_NOT_ACTIVE or
	 * WIM_PROVIDER_EXTERNAL_FLAG_SUSPENDED.  */
	u32 flags;

	/* Integer ID that identifies the WIM.  Get this with the
	 * FSCTL_ADD_OVERLAY ioctl.  */
	u64 data_source_id;

	/* SHA1 message digest of the file's unnamed data stream.  */
	u8 resource_hash[20];
};

/*****************************************************************************
 *
 * --- FSCTL_ADD_OVERLAY ---
 *
 * Adds a new external backing source to a volume.
 *
 * DeviceType: 9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:     2 (FILE_WRITE_ACCESS)
 * Function:   204
 * Method:     0 (METHOD_BUFFERED)
 *
 * Input buffer:  'struct wof_external_info' followed by provider-specific data
 * ('struct wim_provider_add_overlay_input' in the case of WIM).
 *
 * Output buffer:  Buffer large enough to receive any information resulting from
 * the add operation.  For the WIM provider, this must be an 8 byte buffer that
 * receives the 64-bit WIM file ID.
 */
#define FSCTL_ADD_OVERLAY 0x98330

struct wim_provider_add_overlay_input {

	/* Type of WIM file.  */
	u32 wim_type;
#define WIM_BOOT_OS_WIM		0
#define WIM_BOOT_NOT_OS_WIM	1

	/* Index of the image in the WIM to use??? (This doesn't really make
	 * sense, since WIM files combine streams for all images into a single
	 * table.  Set to 1 if unsure...)  */
	u32 wim_index;

	/* Byte offset of wim_file_name in this buffer, not including the
	 * preceding 'struct wof_external_info' (should be 16).  */
	u32 wim_file_name_offset;

	/* Number of bytes in wim_file_name.  */
	u32 wim_file_name_length;

	/* Full path to the WIM, e.g. "\??\d:\test-wimboot.wim".
	 * Does NOT need to be null terminated (MS docs claim otherwise).  */
	wchar_t wim_file_name[];
};

#endif /* _WOF_H_ */
