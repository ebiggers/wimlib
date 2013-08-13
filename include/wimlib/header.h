#ifndef _WIMLIB_HEADER_H
#define _WIMLIB_HEADER_H

#include "wimlib/resource.h"
#include "wimlib/types.h"
#include "wimlib/endianness.h"

/* Length of "Globally Unique ID" field in WIM header.  */
#define WIM_GID_LEN    16

/* Length of the WIM header on disk.  */
#define WIM_HEADER_DISK_SIZE 208

/* Compressed resources in the WIM are divided into separated compressed chunks
 * of this size.  This value is unfortunately not configurable (at least when
 * compatibility with Microsoft's software is desired).  */
#define WIM_CHUNK_SIZE 32768

/* Version of the WIM file.  There is an older version, but wimlib doesn't
 * support it.  The differences between the versions are undocumented.  */
#define WIM_VERSION 0x10d00

/* WIM magic characters, translated to a single 64-bit little endian number.  */
#define WIM_MAGIC \
		cpu_to_le64(((u64)'M' << 0) |		\
			    ((u64)'S' << 8) |		\
			    ((u64)'W' << 16) |		\
			    ((u64)'I' << 24) |		\
			    ((u64)'M' << 32) |		\
			    ((u64)'\0' << 40) |		\
			    ((u64)'\0' << 48) |		\
			    ((u64)'\0' << 54))

/* wimlib pipable WIM magic characters, translated to a single 64-bit little
 * endian number.  */
#define PWM_MAGIC \
		cpu_to_le64(((u64)'W' << 0) |		\
			    ((u64)'L' << 8) |		\
			    ((u64)'P' << 16) |		\
			    ((u64)'W' << 24) |		\
			    ((u64)'M' << 32) |		\
			    ((u64)'\0' << 40) |		\
			    ((u64)'\0' << 48) |		\
			    ((u64)'\0' << 54))

/* Header at the very beginning of the WIM file.  This is the in-memory
 * representation and does not include all fields; see `struct wim_header_disk'
 * for the on-disk structure.  */
struct wim_header {

	/* Magic characters: either WIM_MAGIC or PWM_MAGIC.  */
	le64 magic;

	/* Bitwise OR of one or more of the WIM_HDR_FLAG_* defined below. */
	u32 flags;

	/* A unique identifier for the WIM file. */
	u8 guid[WIM_GID_LEN];

	/* Part number of the WIM file in a spanned set. */
	u16 part_number;

	/* Total number of parts in a spanned set. */
	u16 total_parts;

	/* Number of images in the WIM file. */
	u32 image_count;

	/* Location, size, and flags of the lookup table of the WIM. */
	struct resource_entry lookup_table_res_entry;

	/* Location, size, and flags for the XML data of the WIM. */
	struct resource_entry xml_res_entry;

	/* Location, size, and flags for the boot metadata.  This means the
	 * metadata resource for the image specified by boot_idx below.  Should
	 * be zeroed out if boot_idx is 0. */
	struct resource_entry boot_metadata_res_entry;

	/* The index of the bootable image in the WIM file. If 0, there are no
	 * bootable images available. */
	u32 boot_idx;

	/* The location of the optional integrity table used to verify the
	 * integrity WIM.  Zeroed out if there is no integrity table.*/
	struct resource_entry integrity;
};

/* Flags for the `flags' field of the struct wim_header: */

/* Reserved for future use */
#define WIM_HDR_FLAG_RESERVED           0x00000001

/* Files and metadata in the WIM are compressed. */
#define WIM_HDR_FLAG_COMPRESSION        0x00000002

/* WIM is read-only, so modifications should not be allowed even if the WIM is
 * writable at the filesystem level. */
#define WIM_HDR_FLAG_READONLY           0x00000004

/* Resource data specified by images in this WIM may be contained in a different
 * WIM.  Or in other words, this WIM is part of a split WIM.  */
#define WIM_HDR_FLAG_SPANNED            0x00000008

/* The WIM contains resources only; no filesystem metadata.  wimlib ignores this
 * flag, as it looks for resources in all the WIMs anyway. */
#define WIM_HDR_FLAG_RESOURCE_ONLY      0x00000010

/* The WIM contains metadata only.  wimlib ignores this flag.  Note that all the
 * metadata resources for a split WIM should be in the first part. */
#define WIM_HDR_FLAG_METADATA_ONLY      0x00000020

/* The WIM is currently being written or appended to.  */
#define WIM_HDR_FLAG_WRITE_IN_PROGRESS  0x00000040

/* Reparse point fixup flag.  See docs for --rpfix and --norpfix in imagex, or
 * WIMLIB_ADD_FLAG_{RPFIX,NORPFIX} in wimlib.h.  Note that
 * WIM_HDR_FLAG_RP_FIX is a header flag and just sets the default behavior for
 * the WIM; it can still be overridder on a per-image basis.  But there is no
 * flag to set the default behavior for a specific image. */
#define WIM_HDR_FLAG_RP_FIX             0x00000080

/* Unused, reserved flag for another compression type */
#define WIM_HDR_FLAG_COMPRESS_RESERVED  0x00010000

/* Resources within the WIM are compressed using "XPRESS" compression, which is
 * a LZ77-based compression algorithm. */
#define WIM_HDR_FLAG_COMPRESS_XPRESS    0x00020000

/* Resources within the WIM are compressed using "LZX" compression.  This is also
 * a LZ77-based algorithm. */
#define WIM_HDR_FLAG_COMPRESS_LZX       0x00040000

#endif /* _WIMLIB_HEADER_H */
