/*
 * header.c
 *
 * Read, write, or create a WIM header.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/assert.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/header.h"
#include "wimlib/util.h"
#include "wimlib/wim.h"

#include <limits.h>
#include <string.h>

/* WIM magic characters, translated to a single 64-bit little endian number. */
#define WIM_MAGIC \
		cpu_to_le64(((u64)'M' << 0) |		\
			    ((u64)'S' << 8) |		\
			    ((u64)'W' << 16) |		\
			    ((u64)'I' << 24) |		\
			    ((u64)'M' << 32) |		\
			    ((u64)'\0' << 40) |		\
			    ((u64)'\0' << 48) |		\
			    ((u64)'\0' << 54))

/* On-disk format of the WIM header. */
struct wim_header_disk {

	/* Magic characters "MSWIM\0\0\0" */
	le64 magic;

	/* Size of the WIM header, in bytes; WIM_HEADER_DISK_SIZE expected
	 * (currently the only supported value). */
	u32 hdr_size;

	/* Version of the WIM file; WIM_VERSION expected (currently the only
	 * supported value). */
	u32 wim_version;

	/* Flags for the WIM file (WIM_HDR_FLAG_*) */
	u32 wim_flags;

	/* Uncompressed chunk size of resources in the WIM.  0 if the WIM is
	 * uncompressed.  If compressed, WIM_CHUNK_SIZE is expected (currently
	 * the only supported value).  */
	u32 chunk_size;

	/* Globally unique identifier for the WIM file.  Basically a bunch of
	 * random bytes. */
	u8 guid[WIM_GID_LEN];

	/* Number of this WIM part in the split WIM file, indexed from 1, or 1
	 * if the WIM is not split. */
	u16 part_number;

	/* Total number of parts of the split WIM file, or 1 if the WIM is not
	 * split. */
	u16 total_parts;

	/* Number of images in the WIM. */
	u32 image_count;

	/* Location and size of the WIM's lookup table. */
	struct resource_entry_disk lookup_table_res_entry;

	/* Location and size of the WIM's XML data. */
	struct resource_entry_disk xml_data_res_entry;

	/* Location and size of metadata resource for the bootable image of the
	 * WIM, or all zeroes if no image is bootable. */
	struct resource_entry_disk boot_metadata_res_entry;

	/* 1-based index of the bootable image of the WIM, or 0 if no image is
	 * bootable. */
	u32 boot_idx;

	/* Location and size of the WIM's integrity table, or all zeroes if the
	 * WIM has no integrity table.
	 *
	 * Note the integrity_table_res_entry here is 4-byte aligned even though
	 * it would ordinarily be 8-byte aligned--- hence, the _packed_attribute
	 * on the `struct wim_header_disk' is essential. */
	struct resource_entry_disk integrity_table_res_entry;

	/* Unused bytes. */
	u8 unused[60];
} _packed_attribute;

/* Reads the header from a WIM file.  */
int
read_header(const tchar *filename, int in_fd,
	    struct wim_header *hdr, int open_flags)
{
	struct wim_header_disk disk_hdr _aligned_attribute(8);

	BUILD_BUG_ON(sizeof(struct wim_header_disk) != WIM_HEADER_DISK_SIZE);

	DEBUG("Reading WIM header from \"%"TS"\"", filename);

	if (full_pread(in_fd, &disk_hdr, sizeof(disk_hdr), 0) != sizeof(disk_hdr)) {
		ERROR_WITH_ERRNO("\"%"TS"\": Error reading header", filename);
		return WIMLIB_ERR_READ;
	}

	if (disk_hdr.magic != WIM_MAGIC) {
		ERROR("\"%"TS"\": Invalid magic characters in header", filename);
		return WIMLIB_ERR_NOT_A_WIM_FILE;
	}

	if (le32_to_cpu(disk_hdr.hdr_size) != sizeof(struct wim_header_disk)) {
		ERROR("\"%"TS"\": Header size is invalid (%u bytes)",
		      filename, le32_to_cpu(disk_hdr.hdr_size));
		return WIMLIB_ERR_INVALID_HEADER_SIZE;
	}

	if (le32_to_cpu(disk_hdr.wim_version) != WIM_VERSION) {
		ERROR("\"%"TS"\": The WIM header says the WIM version is %u, "
		      "but wimlib only knows about version %u",
		      filename, le32_to_cpu(disk_hdr.wim_version), WIM_VERSION);
		return WIMLIB_ERR_UNKNOWN_VERSION;
	}

	hdr->flags = le32_to_cpu(disk_hdr.wim_flags);
	if (le32_to_cpu(disk_hdr.chunk_size) != WIM_CHUNK_SIZE &&
	    (hdr->flags & WIM_HDR_FLAG_COMPRESSION)) {
		ERROR("\"%"TS"\": Unexpected chunk size of %u! Ask the author to "
		      "implement support for other chunk sizes.",
		      filename, le32_to_cpu(disk_hdr.chunk_size));
		ERROR("(Or it might just be that the WIM header is invalid.)");
		return WIMLIB_ERR_INVALID_CHUNK_SIZE;
	}

	memcpy(hdr->guid, disk_hdr.guid, WIM_GID_LEN);

	hdr->part_number = le16_to_cpu(disk_hdr.part_number);
	hdr->total_parts = le16_to_cpu(disk_hdr.total_parts);

	if (hdr->total_parts == 0 || hdr->part_number == 0 ||
	    hdr->part_number > hdr->total_parts)
	{
		ERROR("\"%"TS"\": Invalid WIM part number: %hu of %hu",
		      filename, hdr->part_number, hdr->total_parts);
		return WIMLIB_ERR_INVALID_PART_NUMBER;
	}

	if (!(open_flags & WIMLIB_OPEN_FLAG_SPLIT_OK) && hdr->total_parts != 1)
	{
		ERROR("\"%"TS"\": This WIM is part %u of a %u-part WIM",
		      filename, hdr->part_number, hdr->total_parts);
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	hdr->image_count = le32_to_cpu(disk_hdr.image_count);

	DEBUG("part_number = %u, total_parts = %u, image_count = %u",
	      hdr->part_number, hdr->total_parts, hdr->image_count);

	if (hdr->image_count >= INT_MAX) {
		ERROR("\"%"TS"\": Invalid image count (%u)",
		      filename, hdr->image_count);
		return WIMLIB_ERR_IMAGE_COUNT;
	}

	get_resource_entry(&disk_hdr.lookup_table_res_entry, &hdr->lookup_table_res_entry);
	get_resource_entry(&disk_hdr.xml_data_res_entry, &hdr->xml_res_entry);
	get_resource_entry(&disk_hdr.boot_metadata_res_entry, &hdr->boot_metadata_res_entry);
	hdr->boot_idx = le32_to_cpu(disk_hdr.boot_idx);
	get_resource_entry(&disk_hdr.integrity_table_res_entry, &hdr->integrity);
	return 0;
}

/*
 * Writes the header for a WIM file.
 *
 * @hdr: 	A pointer to a struct wim_header structure that describes the header.
 * @out_fd:	The file descriptor to the WIM file, opened for writing.
 *
 * Returns zero on success, nonzero on failure.
 */
int
write_header(const struct wim_header *hdr, int out_fd)
{
	struct wim_header_disk disk_hdr _aligned_attribute(8);
	DEBUG("Writing WIM header.");

	disk_hdr.magic = WIM_MAGIC;
	disk_hdr.hdr_size = cpu_to_le32(sizeof(struct wim_header_disk));
	disk_hdr.wim_version = cpu_to_le32(WIM_VERSION);
	disk_hdr.wim_flags = cpu_to_le32(hdr->flags);
	disk_hdr.chunk_size = cpu_to_le32((hdr->flags & WIM_HDR_FLAG_COMPRESSION) ?
					  	WIM_CHUNK_SIZE : 0);
	memcpy(disk_hdr.guid, hdr->guid, WIM_GID_LEN);

	disk_hdr.part_number = cpu_to_le16(hdr->part_number);
	disk_hdr.total_parts = cpu_to_le16(hdr->total_parts);
	disk_hdr.image_count = cpu_to_le32(hdr->image_count);
	put_resource_entry(&hdr->lookup_table_res_entry, &disk_hdr.lookup_table_res_entry);
	put_resource_entry(&hdr->xml_res_entry, &disk_hdr.xml_data_res_entry);
	put_resource_entry(&hdr->boot_metadata_res_entry, &disk_hdr.boot_metadata_res_entry);
	disk_hdr.boot_idx = cpu_to_le32(hdr->boot_idx);
	put_resource_entry(&hdr->integrity, &disk_hdr.integrity_table_res_entry);
	memset(disk_hdr.unused, 0, sizeof(disk_hdr.unused));

	if (full_pwrite(out_fd, &disk_hdr, sizeof(disk_hdr), 0) != sizeof(disk_hdr)) {
		ERROR_WITH_ERRNO("Failed to write WIM header");
		return WIMLIB_ERR_WRITE;
	}
	DEBUG("Done writing WIM header");
	return 0;
}

/*
 * Initializes the header for a WIM file.
 */
int
init_header(struct wim_header *hdr, int ctype)
{
	memset(hdr, 0, sizeof(struct wim_header));
	switch (ctype) {
	case WIMLIB_COMPRESSION_TYPE_NONE:
		hdr->flags = 0;
		break;
	case WIMLIB_COMPRESSION_TYPE_LZX:
		hdr->flags = WIM_HDR_FLAG_COMPRESSION |
			     WIM_HDR_FLAG_COMPRESS_LZX;
		break;
	case WIMLIB_COMPRESSION_TYPE_XPRESS:
		hdr->flags = WIM_HDR_FLAG_COMPRESSION |
			     WIM_HDR_FLAG_COMPRESS_XPRESS;
		break;
	default:
		ERROR("Invalid compression type specified (%d)", ctype);
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
	}
	hdr->total_parts = 1;
	hdr->part_number = 1;
	randomize_byte_array(hdr->guid, sizeof(hdr->guid));
	return 0;
}

struct hdr_flag {
	u32 flag;
	const char *name;
};
struct hdr_flag hdr_flags[] = {
	{WIM_HDR_FLAG_RESERVED, 	"RESERVED"},
	{WIM_HDR_FLAG_COMPRESSION,	"COMPRESSION"},
	{WIM_HDR_FLAG_READONLY,		"READONLY"},
	{WIM_HDR_FLAG_SPANNED,		"SPANNED"},
	{WIM_HDR_FLAG_RESOURCE_ONLY,	"RESOURCE_ONLY"},
	{WIM_HDR_FLAG_METADATA_ONLY,	"METADATA_ONLY"},
	{WIM_HDR_FLAG_WRITE_IN_PROGRESS,"WRITE_IN_PROGRESS"},
	{WIM_HDR_FLAG_RP_FIX,		"RP_FIX"},
	{WIM_HDR_FLAG_COMPRESS_RESERVED,"COMPRESS_RESERVED"},
	{WIM_HDR_FLAG_COMPRESS_LZX,	"COMPRESS_LZX"},
	{WIM_HDR_FLAG_COMPRESS_XPRESS,	"COMPRESS_XPRESS"},
};

/* Prints information from the header of the WIM file associated with @w. */
WIMLIBAPI void
wimlib_print_header(const WIMStruct *w)
{
	const struct wim_header *hdr = &w->hdr;

	tprintf(T("Magic Characters            = MSWIM\\000\\000\\000\n"));
	tprintf(T("Header Size                 = %u\n"), WIM_HEADER_DISK_SIZE);
	tprintf(T("Version                     = 0x%x\n"), WIM_VERSION);

	tprintf(T("Flags                       = 0x%x\n"), hdr->flags);
	for (size_t i = 0; i < ARRAY_LEN(hdr_flags); i++)
		if (hdr_flags[i].flag & hdr->flags)
			tprintf(T("    WIM_HDR_FLAG_%s is set\n"), hdr_flags[i].name);

	tprintf(T("Chunk Size                  = %u\n"), WIM_CHUNK_SIZE);
	tfputs (T("GUID                        = "), stdout);
	print_byte_field(hdr->guid, WIM_GID_LEN, stdout);
	tputchar(T('\n'));
	tprintf(T("Part Number                 = %hu\n"), w->hdr.part_number);
	tprintf(T("Total Parts                 = %hu\n"), w->hdr.total_parts);
	tprintf(T("Image Count                 = %u\n"), hdr->image_count);
	tprintf(T("Lookup Table Size           = %"PRIu64"\n"),
				(u64)hdr->lookup_table_res_entry.size);
	tprintf(T("Lookup Table Flags          = 0x%hhx\n"),
				(u8)hdr->lookup_table_res_entry.flags);
	tprintf(T("Lookup Table Offset         = %"PRIu64"\n"),
				hdr->lookup_table_res_entry.offset);
	tprintf(T("Lookup Table Original_size  = %"PRIu64"\n"),
				hdr->lookup_table_res_entry.original_size);
	tprintf(T("XML Data Size               = %"PRIu64"\n"),
				(u64)hdr->xml_res_entry.size);
	tprintf(T("XML Data Flags              = 0x%hhx\n"),
				(u8)hdr->xml_res_entry.flags);
	tprintf(T("XML Data Offset             = %"PRIu64"\n"),
				hdr->xml_res_entry.offset);
	tprintf(T("XML Data Original Size      = %"PRIu64"\n"),
				hdr->xml_res_entry.original_size);
	tprintf(T("Boot Metadata Size          = %"PRIu64"\n"),
				(u64)hdr->boot_metadata_res_entry.size);
	tprintf(T("Boot Metadata Flags         = 0x%hhx\n"),
				(u8)hdr->boot_metadata_res_entry.flags);
	tprintf(T("Boot Metadata Offset        = %"PRIu64"\n"),
				hdr->boot_metadata_res_entry.offset);
	tprintf(T("Boot Metadata Original Size = %"PRIu64"\n"),
				hdr->boot_metadata_res_entry.original_size);
	tprintf(T("Boot Index                  = %u\n"), hdr->boot_idx);
	tprintf(T("Integrity Size              = %"PRIu64"\n"),
				(u64)hdr->integrity.size);
	tprintf(T("Integrity Flags             = 0x%hhx\n"),
				(u8)hdr->integrity.flags);
	tprintf(T("Integrity Offset            = %"PRIu64"\n"),
				hdr->integrity.offset);
	tprintf(T("Integrity Original_size     = %"PRIu64"\n"),
				hdr->integrity.original_size);
}
