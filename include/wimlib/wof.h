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
 * --- FSCTL_GET_EXTERNAL_BACKING ---
 *
 * Get external backing information for the specified file.
 *
 * DeviceType: 9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:     0 (FILE_ANY_ACCESS)
 * Function:   196
 * Method:     0 (METHOD_BUFFERED)
 *
 * Input buffer: None
 * Output buffer:  'struct wof_external_info' followed by provider-specific data
 * ('struct wim_provider_external_info' in the case of WIM).
 */
#define FSCTL_GET_EXTERNAL_BACKING 0x90310

/*****************************************************************************
 *
 * --- FSCTL_DELETE_EXTERNAL_BACKING ---
 *
 * Copy a file from its backing source to its volume, then disassociate it from
 * its backing provider.
 *
 * DeviceType: 9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:     0 (FILE_ANY_ACCESS)
 * Function:   197
 * Method:     0 (METHOD_BUFFERED)
 *
 * Input buffer: None
 * Output buffer: None
 */
#define FSCTL_DELETE_EXTERNAL_BACKING 0x90314

/*****************************************************************************
 *
 * --- FSCTL_ENUM_EXTERNAL_BACKING ---
 *
 * Enumerate externally backed files on a volume.
 *
 * DeviceType: 9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:     0 (FILE_ANY_ACCESS)
 * Function:   198
 * Method:     0 (METHOD_BUFFERED)
 *
 * Input buffer: None
 * Output buffer: A 16-byte buffer that receives the 128-bit file ID for the
 * next externally backed file.
 *
 * The handle used may be either the volume handle or the handle for any file or
 * directory on the volume.
 *
 * When all externally backed files on the volume have been enumerated, the
 * function fails with ERROR_NO_MORE_FILES.
 */
#define FSCTL_ENUM_EXTERNAL_BACKING 0x90318

/*****************************************************************************
 *
 * --- FSCTL_ENUM_OVERLAY ---
 *
 * Enumerates the volume's overlay sources from the specified provider.
 *
 * DeviceType: 9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:     0 (FILE_ANY_ACCESS)
 * Function:   199
 * Method:     3 (METHOD_NEITHER)
 *
 * Input buffer:  'struct wof_external_info' to specify the provider for which
 * to enumerate the overlay sources.
 *
 * Output buffer:  Provider-specific data.  For the WIM provider, an array of
 * 'struct wim_provider_overlay_entry'.
 *
 * This ioctl must be performed on the volume handle, such as \\.\C:
 */
#define FSCTL_ENUM_OVERLAY 0x9031F

struct wim_provider_overlay_entry {
	/* Byte offset of the next entry from the beginning of this structure,
	 * or 0 if there are no more entries.  */
	uint32_t next_entry_offset;

	uint32_t padding;

	/* Identifier for the WIM file.  */
	uint64_t data_source_id;

	/* GUID of the WIM file.  */
	uint8_t guid[16];

	/* Byte offset of the WIM's file name from the beginning of this
	 * structure.  */
	uint32_t wim_file_name_offset;

	/* Type of WIM file: WIM_BOOT_OS_WIM or WIM_BOOT_NOT_OS_WIM.  */
	uint32_t wim_type;

	/* Index of the backing image in the WIM??? (This doesn't really make
	 * sense, since WIM files combine streams for all images into a single
	 * table.)  */
	uint32_t wim_index;

	/* 0 when WIM provider active, otherwise
	 * WIM_PROVIDER_EXTERNAL_FLAG_NOT_ACTIVE or
	 * WIM_PROVIDER_EXTERNAL_FLAG_SUSPENDED.  */
	uint32_t flags;

	/* Full path to the WIM in the NT device namespace, e.g.
	 * "\Device\HardDiskVolume2\test.wim".  Seems to be null-terminated,
	 * although you probably shouldn't assume so.  */
	wchar_t wim_file_name[];
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
 *
 * This ioctl must be performed on the volume handle, such as \\.\C:
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

	/* Full path to the WIM, e.g. "\??\C:\test-wimboot.wim".
	 * Does NOT need to be null terminated (MS docs claim otherwise).  */
	wchar_t wim_file_name[];
};

/*****************************************************************************
 *
 * --- FSCTL_REMOVE_OVERLAY ---
 *
 * Removes an external backing source from a volume.
 *
 * DeviceType: 9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:     2 (FILE_WRITE_ACCESS)
 * Function:   205
 * Method:     0 (METHOD_BUFFERED)
 *
 * Input buffer:  'struct wof_external_info' followed by provider-specific data
 * ('struct wim_provider_remove_overlay_input' in the case of WIM).
 *
 * Output buffer:  None
 *
 * This ioctl must be performed on the volume handle, such as \\.\C:
 */
#define FSCTL_REMOVE_OVERLAY 0x98334

struct wim_provider_remove_overlay_input {
	/* Integer ID that identifies the WIM.  */
	u64 data_source_id;
};


/*****************************************************************************
 *
 * --- FSCTL_UPDATE_OVERLAY ---
 *
 * Updates an overlay source for a volume.
 *
 * DeviceType: 9 (FILE_DEVICE_FILE_SYSTEM)
 * Access:     2 (FILE_WRITE_ACCESS)
 * Function:   206
 * Method:     0 (METHOD_BUFFERED)
 *
 * Input buffer:  'struct wof_external_info' followed by provider-specific data
 * ('struct wim_provider_update_overlay_input' in the case of WIM).
 *
 * Output buffer:  None
 *
 * This ioctl must be performed on the volume handle, such as \\.\C:
 */
#define FSCTL_UPDATE_OVERLAY 0x98338

struct wim_provider_update_overlay_input {
	/* Integer ID that identifies the WIM data source.  */
	u64 data_source_id;

	/* Byte offset of wim_file_name in this buffer, not including the
	 * preceding 'struct wof_external_info' (should be 16).  */
	u32 wim_file_name_offset;

	/* Number of bytes in wim_file_name.  */
	u32 wim_file_name_length;

	/* Full path to the WIM, e.g. "\??\C:\test-wimboot.wim".
	 * Does NOT need to be null terminated (MS docs claim otherwise).
	 * This WIM must be renamed from the original WIM, or at least be an
	 * identical copy of it!  (Maybe the WIM's GUID field is checked.)  */
	wchar_t wim_file_name[];
};

#endif /* _WOF_H_ */
