#ifndef _WIMLIB_HEADER_H
#define _WIMLIB_HEADER_H

#include "wimlib/resource.h"
#include "wimlib/types.h"
#include "wimlib/endianness.h"

/* Length of "Globally Unique ID" field in WIM header.  */
#define WIM_GID_LEN    16

/* Length of the WIM header on disk.  wimlib currently requires that the header
 * be exactly this size.  */
#define WIM_HEADER_DISK_SIZE 208

/* Default WIM version number.  Streams are always compressed independently.  */
#define WIM_VERSION_DEFAULT 0x10d00

/* Version number used for WIMs that allow multiple streams packed into one
 * resource ("solid blocks", marked by WIM_RESHDR_FLAG_PACKED_STREAMS) and also
 * a new compression format (LZMS).  This version is new as of Windows 8
 * WIMGAPI.  Although it is used by Windows 8 web downloader, it is not yet
 * properly documented by Microsoft.  */
#define WIM_VERSION_PACKED_STREAMS 0xe00

/* Note: there is another WIM version from Vista pre-releases, but it is not
 * supported by wimlib.  */

/* WIM magic characters, translated to a single 64-bit number.  */
#define WIM_MAGIC				\
		(((u64)'M'  <<  0) |		\
		 ((u64)'S'  <<  8) |		\
		 ((u64)'W'  << 16) |		\
		 ((u64)'I'  << 24) |		\
		 ((u64)'M'  << 32) |		\
		 ((u64)'\0' << 40) |		\
		 ((u64)'\0' << 48) |		\
		 ((u64)'\0' << 54))

/* wimlib pipable WIM magic characters, translated to a single 64-bit number.
 * */
#define PWM_MAGIC				\
		(((u64)'W'  <<  0) |		\
		 ((u64)'L'  <<  8) |		\
		 ((u64)'P'  << 16) |		\
		 ((u64)'W'  << 24) |		\
		 ((u64)'M'  << 32) |		\
		 ((u64)'\0' << 40) |		\
		 ((u64)'\0' << 48) |		\
		 ((u64)'\0' << 54))

/* On-disk format of the WIM header.  */
struct wim_header_disk {

	/* +0x00: Magic characters WIM_MAGIC or PWM_MAGIC.  */
	le64 magic;

	/* +0x08: Size of the WIM header, in bytes; WIM_HEADER_DISK_SIZE
	 * expected (currently the only supported value).  */
	u32 hdr_size;

	/* +0x0c: Version of the WIM file.  Recognized values are the
	 * WIM_VERSION_* constants from above.  */
	u32 wim_version;

	/* +0x10: Flags for the WIM file (WIM_HDR_FLAG_*).  */
	u32 wim_flags;

	/* +0x14: Uncompressed chunk size for compressed resources in the WIM
	 * other than packed resources, or 0 if the WIM is uncompressed.
	 * (However wimlib will currently accept any value here if the WIM is
	 * uncompressed.)  */
	u32 chunk_size;

	/* +0x18: Globally unique identifier for the WIM file.  Basically a
	 * bunch of random bytes.  */
	u8 guid[WIM_GID_LEN];

	/* +0x28: Number of this WIM part in the split WIM file, indexed from 1,
	 * or 1 if the WIM is not split.  */
	u16 part_number;

	/* +0x2a: Total number of parts of the split WIM file, or 1 if the WIM
	 * is not split.  */
	u16 total_parts;

	/* +0x2c: Number of images in the WIM.  WIMGAPI requires that this be at
	 * least 1.  wimlib allows 0.  */
	u32 image_count;

	/* +0x30: Location and size of the WIM's lookup table.  */
	struct wim_reshdr_disk lookup_table_reshdr;

	/* +0x48: Location and size of the WIM's XML data.  */
	struct wim_reshdr_disk xml_data_reshdr;

	/* +0x60: Location and size of metadata resource for the bootable image
	 * of the WIM, or all zeroes if no image is bootable.  */
	struct wim_reshdr_disk boot_metadata_reshdr;

	/* +0x78: 1-based index of the bootable image of the WIM, or 0 if no
	 * image is bootable.  */
	u32 boot_idx;

	/* +0x7c: Location and size of the WIM's integrity table, or all zeroes
	 * if the WIM has no integrity table.
	 *
	 * Note the integrity_table_reshdr here is 4-byte aligned even though it
	 * would ordinarily be 8-byte aligned--- hence, the _packed_attribute on
	 * this structure is essential.  */
	struct wim_reshdr_disk integrity_table_reshdr;

	/* +0x94: Unused bytes.  */
	u8 unused[60];

	/* +0xd0 (208)  */
} _packed_attribute;


/* In-memory representation of a WIM header.  See `struct wim_header_disk' for
 * field descriptions.  */
struct wim_header {
	u64 magic;
	u32 wim_version;
	u32 flags;
	u32 chunk_size;
	u8 guid[WIM_GID_LEN];
	u16 part_number;
	u16 total_parts;
	u32 image_count;
	struct wim_reshdr lookup_table_reshdr;
	struct wim_reshdr xml_data_reshdr;
	struct wim_reshdr boot_metadata_reshdr;
	u32 boot_idx;
	struct wim_reshdr integrity_table_reshdr;
};

/* WIM header flags ('wim_flags' field of 'struct wim_header_disk'):  */

/* Reserved flag.  */
#define WIM_HDR_FLAG_RESERVED           0x00000001

/* The WIM may contain compressed resources --- specifically, resources with
 * WIM_RESHDR_FLAG_COMPRESSED set in their headers.  Exactly one of the more
 * specific WIM_HDR_FLAG_COMPRESSION_* flags must be set to specify the
 * compression format used.  */
#define WIM_HDR_FLAG_COMPRESSION        0x00000002

/* The WIM is read-only, so modifications should not be allowed even if the WIM
 * is writable at the filesystem level.  */
#define WIM_HDR_FLAG_READONLY           0x00000004

/* The WIM is part of a split WIM.  */
#define WIM_HDR_FLAG_SPANNED            0x00000008

/* All streams included in the WIM's lookup table are non-metadata (do not have
 * WIM_RESHDR_FLAG_METADATA set).  wimlib ignores this flag and clears it on new
 * WIM files it writes.  */
#define WIM_HDR_FLAG_RESOURCE_ONLY      0x00000010

/* All streams included in the WIM's lookup table are metadata (have
 * WIM_RESHDR_FLAG_METADATA set).  wimlib ignores this flag and clears it on
 * new WIM files it writes.  */
#define WIM_HDR_FLAG_METADATA_ONLY      0x00000020

/* The WIM is currently being written or appended to.  */
#define WIM_HDR_FLAG_WRITE_IN_PROGRESS  0x00000040

/* Reparse point fixup flag.  See docs for the --rpfix and --norpfix options to
 * 'wimlib-imagex capture', or the WIMLIB_ADD_FLAG_{RPFIX,NORPFIX} flags in
 * wimlib.h.  Note that WIM_HDR_FLAG_RP_FIX is a header flag and just sets the
 * default behavior for the WIM; it can still be programatically overridden on a
 * per-image basis.  But there is no flag in the file format to set the default
 * behavior for a specific image.  */
#define WIM_HDR_FLAG_RP_FIX             0x00000080

/* Unused, reserved flag for another compression type.  */
#define WIM_HDR_FLAG_COMPRESS_RESERVED  0x00010000

/* Resources in the WIM with WIM_RESHDR_FLAG_COMPRESSED set in their headers are
 * compressed with XPRESS compression.  */
#define WIM_HDR_FLAG_COMPRESS_XPRESS    0x00020000

/* Resources in the WIM with WIM_RESHDR_FLAG_COMPRESSED set in their headers are
 * compressed with LZX compression.  */
#define WIM_HDR_FLAG_COMPRESS_LZX       0x00040000

/* Resources in the WIM with WIM_RESHDR_FLAG_COMPRESSED set in their headers are
 * compressed with LZMS compression.  Note: this flag is only valid if the WIM
 * version is WIM_VERSION_PACKED_STREAMS.  Also, this flag is only supported in
 * wimlib v1.6.0 and later and WIMGAPI Windows 8 and later.  */
#define WIM_HDR_FLAG_COMPRESS_LZMS      0x00080000

#endif /* _WIMLIB_HEADER_H */
