/*
 * wof.h
 *
 * Definitions for the Windows Overlay File System Filter (WOF) ioctls, as well
 * some definitions for associated undocumented data structures.  See
 * http://msdn.microsoft.com/en-us/library/windows/hardware/ff540367(v=vs.85).aspx
 * for more information about the documented ioctls.
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WOF_H_
#define _WOF_H_

#include "wimlib/compiler.h"
#include "wimlib/types.h"

/*
 * The Windows Overlay FileSystem Filter (WOF, a.k.a. wof.sys) is a filesystem
 * filter driver, available in Windows 8.1 and later, which allows files to be
 * "externally backed", meaning that their data is stored in another location,
 * possibly in compressed form.
 *
 * WOF implements a plug-in mechanism by which a specific "provider" is
 * responsible for actually externally backing a given file.  The currently
 * known providers are:
 *
 *	- The WIM provider: allows a file to be externally backed by a
 *	  compressed resource in a WIM archive
 *	- The file provider: allows a file to be "externally backed" by a named
 *	  data stream stored with the file itself, where that named data stream
 *	  has the format of a compressed WIM resource
 *
 * For both of these providers, externally backed files are effectively
 * read-only.  If you try to write to such a file, Windows automatically
 * decompresses it and turns it into a regular, non-externally-backed file.
 *
 * WOF provides various ioctls that control its operation.  For example,
 * FSCTL_SET_EXTERNAL_BACKING sets up a file as externally backed.
 *
 * WOF external backings are implemented using reparse points.  One consequence
 * of this is that WOF external backings can only be set on files that do not
 * already have a reparse point set.  Another consequence of this is that it is
 * possible to create a WOF external backing by manually creating the reparse
 * point, although this requires dealing with undocumented data structures and
 * it only works when the WOF driver is not currently attached to the volume.
 *
 * Note that only the unnamed data stream portion of a file can be externally
 * backed.  Other NTFS streams and metadata are not externally backed.
 */


/* Current version of the WOF driver/protocol  */
#define WOF_CURRENT_VERSION		1

/* Specifies the WIM backing provider  */
#define WOF_PROVIDER_WIM		1

/* Specifies the "file" backing provider (a.k.a. System Compression)  */
#define WOF_PROVIDER_FILE		2

/* The current version of the WIM backing provider  */
#define WIM_PROVIDER_CURRENT_VERSION	1

/* The current version of the file backing provider  */
#define FILE_PROVIDER_CURRENT_VERSION	1

/* Identifies a backing provider for a specific overlay service version.  */
struct wof_external_info {

	/* Version of the overlay service supported by the backing provider.
	 * Set to WOF_CURRENT_VERSION.  */
	u32 version;

	/* Identifier for the backing provider.  Example value:
	 * WOF_PROVIDER_WIM.  */
	u32 provider;
};


/*
 * Format of the WIM provider reparse data.  This is the data which follows the
 * portion of the reparse point common to WOF.  (The common portion consists of
 * a reparse point header where the reparse tag is 0x80000017, then a 'struct
 * wof_external_info' which specifies the provider.)
 *
 * Note that Microsoft does not document any of the reparse point formats for
 * WOF, although they document the structures which must be passed into the
 * ioctls, which are often similar.
 */
struct wim_provider_rpdata {
	/* Set to 2.  Uncertain meaning.  */
	le32 version;

	/* 0 when WIM provider active, otherwise
	 * WIM_PROVIDER_EXTERNAL_FLAG_NOT_ACTIVE or
	 * WIM_PROVIDER_EXTERNAL_FLAG_SUSPENDED.  */
	le32 flags;

	/* Integer ID that identifies the WIM.  */
	le64 data_source_id;

	/* SHA-1 message digest of the file's unnamed data stream.  */
	u8 unnamed_data_stream_hash[20];

	/* SHA-1 message digest of the WIM's blob table as stored on disk.  */
	u8 blob_table_hash[20];

	/* Uncompressed size of the file's unnamed data stream, in bytes.  */
	le64 unnamed_data_stream_size;

	/* Size of the file's unnamed data stream as stored in the WIM file.
	 * If this is the same as unnamed_data_stream_size, then the stream is
	 * uncompressed.  If this is the *not* the same as
	 * unnamed_data_stream_size, then the stream is compressed.  */
	le64 unnamed_data_stream_size_in_wim;

	/* Byte offset of the file's unnamed data stream in the WIM.  */
	le64 unnamed_data_stream_offset_in_wim;
} _packed_attribute;

/* WIM-specific information about a WIM data source  */
struct WimOverlay_dat_entry_1 {

	/* Identifier for the WIM data source, (normally allocated by
	 * FSCTL_ADD_OVERLAY).  Every 'WimOverlay_dat_entry_1' should have a
	 * different value for this.  */
	le64 data_source_id;

	/* Byte offset, from the beginning of the file, of the corresponding
	 * 'struct WimOverlay_dat_entry_2' for this WIM data source.  */
	le32 entry_2_offset;

	/* Size, in bytes, of the corresponding 'struct WimOverlay_dat_entry_2
	 * for this WIM data source, including wim_file_name and its null
	 * terminator.  */
	le32 entry_2_length;

	/* Type of the WIM file: WIM_BOOT_OS_WIM or WIM_BOOT_NOT_OS_WIM.  */
	le32 wim_type;

	/* Index of the image in the WIM to use??? (This doesn't really make
	 * sense, since WIM files combine file data "blobs" for all images into
	 * a single table.  Set to 1 if unsure...)  */
	le32 wim_index;

	/* GUID of the WIM file (copied from the WIM header, offset +0x18).  */
	u8 guid[16];
} _packed_attribute;

/*
 * Format of file: "\System Volume Information\WimOverlay.dat"
 *
 * Not documented by Microsoft.
 *
 * The file consists of a 'struct WimOverlay_dat_header' followed by one or more
 * 'struct WimOverlay_dat_entry_1', followed by the same number of 'struct
 * WimOverlay_dat_entry_2'.  Note that 'struct WimOverlay_dat_entry_1' is of
 * fixed length, whereas 'struct WimOverlay_dat_entry_2' is of variable length.
 */
struct WimOverlay_dat_header {
	/* Set to WIMOVERLAY_DAT_MAGIC  */
	le32 magic;
#define WIMOVERLAY_DAT_MAGIC 0x66436F57

	/* Set to 1 (WIM_PROVIDER_CURRENT_VERSION)  */
	le32 wim_provider_version;

	/* Set to 0x00000028  */
	le32 unknown_0x08;

	/* Set to number of WIMs registered;
	 * also the number of 'struct WimOverlay_dat_entry_1' that follow.  */
	le32 num_entries_1;

	/* Set to number of WIMs registered;
	 * also the number of 'struct WimOverlay_dat_entry_2' that follow.  */
	le32 num_entries_2;

	/* Set to 0  */
	le32 unknown_0x14;

	struct WimOverlay_dat_entry_1 entry_1s[];
} _packed_attribute;

/* Location information about a WIM data source  */
struct WimOverlay_dat_entry_2 {
	/* Set to 0  */
	le32 unknown_0x00;

	/* Set to 0  */
	le32 unknown_0x04;

	/* Size, in bytes, of this 'struct WimOverlay_dat_entry_2', including
	 * wim_file_name and its null terminator.  */
	le32 entry_2_length;

	/* Set to 0  */
	le32 unknown_0x0C;

	/* Set to 5  */
	le32 unknown_0x10;

	struct {
		/* Set to 1  */
		le32 unknown_0x14;

		/* Size of this inner structure, in bytes.  */
		le32 inner_struct_size;

		/* Set to 5  */
		le32 unknown_0x1C;

		/* Set to 6  */
		le32 unknown_0x20;

		/* Set to 0  */
		le32 unknown_0x24;

		/* Set to 0x48  */
		le32 unknown_0x28;

		/* Set to 0  */
		le32 unknown_0x2C;

		/*************************
		 * Partition information
		 ************************/

		/* Partition identifier  */
		union {
			/* (For MBR-formatted disks)  */
			struct {
				/* Offset, in bytes, of the MBR partition, from
				 * the beginning of the disk.  */
				le64 part_start_offset;

				/* Set to 0  */
				le64 padding;
			} mbr;

			/* (For GPT-formatted disks)  */
			struct {
				/* Unique GUID of the GPT partition  */
				u8 part_unique_guid[16];
			} gpt;
		} partition;

		/* Set to 0  */
		le32 unknown_0x40;

		/***********************
		 * Disk information
		 **********************/

		/* 1 for MBR, 0 for GPT  */
		le32 partition_table_type;
	#define WIMOVERLAY_PARTITION_TYPE_MBR 1
	#define WIMOVERLAY_PARTITION_TYPE_GPT 0

		/* Disk identifier  */
		union {
			/* (For MBR-formatted disks)  */
			struct {
				/* 4-byte ID of the MBR disk  */
				le32 disk_id;

				/* Set to 0  */
				le32 padding[3];
			} mbr;

			/* (For GPT-formatted disks)  */
			struct {
				/* GUID of the GPT disk  */
				u8 disk_guid[16];
			} gpt;
		} disk;

		/* Set to 0.  (This is the right size for some sort of optional
		 * GUID...)  */
		le32 unknown_0x58[4];

		/**************************
		 * Location in filesystem
		 *************************/

		/* Null-terminated path to WIM file.  Begins with \ but does
		 * *not* include drive letter!  */
		utf16lechar wim_file_name[];
	} _packed_attribute;
} _packed_attribute;

static _unused_attribute void
wof_check_structs(void)
{
	STATIC_ASSERT(sizeof(struct WimOverlay_dat_header) == 24);
	STATIC_ASSERT(sizeof(struct WimOverlay_dat_entry_1) == 40);
	STATIC_ASSERT(sizeof(struct WimOverlay_dat_entry_2) == 104);
}

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

	/* SHA-1 message digest of the file's unnamed data stream.  */
	u8 unnamed_data_stream_hash[20];
};

struct file_provider_external_info {

	/* Set to FILE_PROVIDER_CURRENT_VERSION.  */
	u32 version;

	u32 compression_format;
#define FILE_PROVIDER_COMPRESSION_FORMAT_XPRESS4K	0
#define FILE_PROVIDER_COMPRESSION_FORMAT_LZX		1
#define FILE_PROVIDER_COMPRESSION_FORMAT_XPRESS8K	2
#define FILE_PROVIDER_COMPRESSION_FORMAT_XPRESS16K	3
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

#define STATUS_OBJECT_NOT_EXTERNALLY_BACKED	0xC000046D

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
	u32 next_entry_offset;

	u32 padding;

	/* Identifier for the WIM file.  */
	u64 data_source_id;

	/* GUID of the WIM file.  */
	u8 guid[16];

	/* Byte offset of the WIM's file name from the beginning of this
	 * structure.  */
	u32 wim_file_name_offset;

	/* Type of WIM file: WIM_BOOT_OS_WIM or WIM_BOOT_NOT_OS_WIM.  */
	u32 wim_type;

	/* Index of the image in the WIM to use??? (This doesn't really make
	 * sense, since WIM files combine file data "blobs" for all images into
	 * a single table.  Set to 1 if unsure...)  */
	u32 wim_index;

	/* 0 when WIM provider active, otherwise
	 * WIM_PROVIDER_EXTERNAL_FLAG_NOT_ACTIVE or
	 * WIM_PROVIDER_EXTERNAL_FLAG_SUSPENDED.  */
	u32 flags;

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
	 * sense, since WIM files combine file data "blobs" for all images into
	 * a single table.  Set to 1 if unsure...)  */
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
