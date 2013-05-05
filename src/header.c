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

#include "wimlib_internal.h"
#include "buffer_io.h"
#include <limits.h>

/* First 8 bytes in every WIM file. */
static const u8 wim_magic_chars[WIM_MAGIC_LEN] = {
			'M', 'S', 'W', 'I', 'M', '\0', '\0', '\0' };

/* Reads the header from a WIM file.  */
int
read_header(filedes_t in_fd, struct wim_header *hdr, int open_flags)
{
	size_t bytes_read;
	u8 buf[WIM_HEADER_DISK_SIZE];
	const void *p;

	u32 hdr_size;
	u32 wim_version;
	u32 chunk_size;

	DEBUG("Reading WIM header.");

	bytes_read = full_pread(in_fd, buf, WIM_HEADER_DISK_SIZE, 0);

	if (bytes_read != WIM_HEADER_DISK_SIZE) {
		ERROR_WITH_ERRNO("Error reading WIM header");
		return WIMLIB_ERR_READ;
	}

	p = buf;
	if (memcmp(p, wim_magic_chars, WIM_MAGIC_LEN)) {
		ERROR("Invalid magic characters in WIM header");
		return WIMLIB_ERR_NOT_A_WIM_FILE;
	}

	/* Byte 8 */
	p = get_u32(p + 8, &hdr_size);
	if (hdr_size != WIM_HEADER_DISK_SIZE) {
		ERROR("Header is %u bytes (expected %u bytes)",
		      hdr_size, WIM_HEADER_DISK_SIZE);
		return WIMLIB_ERR_INVALID_HEADER_SIZE;
	}

	/* Byte 12 */
	p = get_u32(buf + WIM_MAGIC_LEN + sizeof(u32), &wim_version);
	if (wim_version != WIM_VERSION) {
		ERROR("The WIM header says the WIM version is %u, but wimlib "
		      "only knows about version %u",
		      wim_version, WIM_VERSION);
		return WIMLIB_ERR_UNKNOWN_VERSION;
	}

	p = get_u32(p, &hdr->flags);
	p = get_u32(p, &chunk_size);
	if (chunk_size != WIM_CHUNK_SIZE &&
	    (hdr->flags & WIM_HDR_FLAG_COMPRESSION)) {
		ERROR("Unexpected chunk size of %u! Ask the author to "
		      "implement support for other chunk sizes.",
		      chunk_size);
		ERROR("(Or it might just be that the WIM header is invalid.)");
		return WIMLIB_ERR_INVALID_CHUNK_SIZE;
	}

	p = get_bytes(p, WIM_GID_LEN, hdr->guid);
	p = get_u16(p, &hdr->part_number);
	p = get_u16(p, &hdr->total_parts);

	if (hdr->total_parts == 0 ||
	    hdr->part_number == 0 ||
	    hdr->part_number > hdr->total_parts)
	{
		ERROR("Invalid WIM part number: %hu of %hu",
		      hdr->part_number, hdr->total_parts);
		return WIMLIB_ERR_INVALID_PART_NUMBER;
	}

	if (!(open_flags & WIMLIB_OPEN_FLAG_SPLIT_OK) &&
	    hdr->total_parts != 1)
	{
		ERROR("This WIM is part %u of a %u-part WIM",
		      hdr->part_number, hdr->total_parts);
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	p = get_u32(p, &hdr->image_count);

	DEBUG("part_number = %u, total_parts = %u, image_count = %u",
	      hdr->part_number, hdr->total_parts, hdr->image_count);

	if (hdr->image_count >= INT_MAX) {
		ERROR("Invalid image count (%u)", hdr->image_count);
		return WIMLIB_ERR_IMAGE_COUNT;
	}

	/* Byte 48 */

	p = get_resource_entry(p, &hdr->lookup_table_res_entry);
	p = get_resource_entry(p, &hdr->xml_res_entry);
	p = get_resource_entry(p, &hdr->boot_metadata_res_entry);

	/* Byte 120 */

	p = get_u32(p, &hdr->boot_idx);

	/* Byte 124 */

	p = get_resource_entry(p, &hdr->integrity);

	/* Byte 148 */

	/* 60 bytes of unused stuff. */

	/* Byte 208 */

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
	u8 buf[WIM_HEADER_DISK_SIZE];
	u8 *p;
	DEBUG("Writing WIM header.");

	p = put_bytes(buf, WIM_MAGIC_LEN, wim_magic_chars);
	p = put_u32(p, WIM_HEADER_DISK_SIZE);
	p = put_u32(p, WIM_VERSION);
	p = put_u32(p, hdr->flags);
	p = put_u32(p, (hdr->flags & WIM_HDR_FLAG_COMPRESSION) ?
				WIM_CHUNK_SIZE : 0);
	/* Byte 24 */

	p = put_bytes(p, WIM_GID_LEN, hdr->guid);
	p = put_u16(p, hdr->part_number);

	/* Byte 40 */

	p = put_u16(p, hdr->total_parts);
	p = put_u32(p, hdr->image_count);
	p = put_resource_entry(p, &hdr->lookup_table_res_entry);
	p = put_resource_entry(p, &hdr->xml_res_entry);
	p = put_resource_entry(p, &hdr->boot_metadata_res_entry);
	p = put_u32(p, hdr->boot_idx);
	p = put_resource_entry(p, &hdr->integrity);
	p = put_zeroes(p, WIM_UNUSED_LEN);
	wimlib_assert(p - buf == sizeof(buf));

	if (full_pwrite(out_fd, buf, sizeof(buf), 0) != sizeof(buf)) {
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
