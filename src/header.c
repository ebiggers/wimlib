/*
 * header.c
 *
 * Read, write, or create a WIM header.
 *
 * Copyright (C) 2010 Carl Thijssen
 * Copyright (C) 2012 Eric Biggers
 *
 * wimlib - Library for working with WIM files 
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "wimlib_internal.h"
#include "io.h"

/* First 8 bytes in every WIM file. */
static const u8 wim_magic_chars[WIM_MAGIC_LEN] = { 
			'M', 'S', 'W', 'I', 'M', '\0', '\0', '\0' };

/* Reads the header for a WIM file.  */
int read_header(FILE *fp, struct wim_header *hdr, int split_ok)
{
	size_t bytes_read;
	u8 buf[WIM_HEADER_DISK_SIZE];
	size_t hdr_rem_size;
	const u8 *p;

	u32 hdr_size;
	u32 wim_version;
	u32 chunk_size;
	u16 part_number;
	u16 total_parts;

	DEBUG("Reading WIM header.\n");
	
	bytes_read = fread(buf, 1, WIM_MAGIC_LEN, fp);

	if (bytes_read != WIM_MAGIC_LEN)
		goto err;

	/* Byte 8 */

	if (memcmp(buf, wim_magic_chars, WIM_MAGIC_LEN) != 0) {
		ERROR("Invalid magic characters in WIM header\n");
		return WIMLIB_ERR_NOT_A_WIM_FILE;
	}

	bytes_read = fread(&hdr_size, 1, sizeof(u32), fp);
	if (bytes_read != sizeof(u32))
		goto err;

	TO_LE32(hdr_size);

	/* Byte 12 */

	if (hdr_size != WIM_HEADER_DISK_SIZE) {
		DEBUG("ERROR: Header is size %u (expected %u)\n",
				hdr_size, WIM_HEADER_DISK_SIZE);
		return WIMLIB_ERR_INVALID_HEADER_SIZE;
	}

	/* Read the rest of the header into a buffer. */

	hdr_rem_size = WIM_HEADER_DISK_SIZE - WIM_MAGIC_LEN - sizeof(u32);

	bytes_read = fread(buf + WIM_MAGIC_LEN + sizeof(u32), 1, 
			   hdr_rem_size, fp);
	if (bytes_read != hdr_rem_size)
		goto err;

	p = get_u32(buf + WIM_MAGIC_LEN + sizeof(u32), &wim_version);

	if (wim_version != WIM_VERSION) {
		ERROR("The WIM header says the WIM version is %u, but Wimlib "
			"only knows about version %u.\n", wim_version, 
								WIM_VERSION);
		return WIMLIB_ERR_UNKNOWN_VERSION;
	}

	p = get_u32(p, &hdr->flags);
	p = get_u32(p, &chunk_size);
	if (chunk_size != WIM_CHUNK_SIZE && 
			(hdr->flags & WIM_HDR_FLAG_COMPRESSION)) {
		ERROR("Unexpected chunk size of %u! Ask the author to "
				"implement support for other chunk sizes. "
				"(Or it might just be that the WIM header is "
				"invalid.)\n", chunk_size);
		return WIMLIB_ERR_INVALID_CHUNK_SIZE;
	}

	p = get_bytes(p, WIM_GID_LEN, hdr->guid);
	p = get_u16(p, &hdr->part_number);
	p = get_u16(p, &hdr->total_parts);

	if (!split_ok && (hdr->part_number != 1 || hdr->total_parts != 1)) {
		ERROR("This WIM is part %u of a %u-part WIM.\n",
			hdr->part_number, hdr->total_parts);
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	p = get_u32(p, &hdr->image_count);

	DEBUG("part_number = %u, total_parts = %u, image_count = %u\n",
			hdr->part_number, hdr->total_parts, hdr->image_count);

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

err:
	if (feof(fp))
		ERROR("Unexpected EOF while reading WIM header!\n");
	else
		ERROR("Error reading WIM header: %m\n");
	return WIMLIB_ERR_READ;
}

/* 
 * Writes the header for a WIM file.
 *
 * @hdr: 	A pointer to a struct wim_header structure that describes the header.
 * @out:	The FILE* for the output file, positioned at the appropriate
 * 		place (the beginning of the file).
 * @return:	True on success, false on failure.
 */
int write_header(const struct wim_header *hdr, FILE *out)
{
	u8 buf[WIM_HEADER_DISK_SIZE];
	u8 *p;
	DEBUG("Writing WIM header.\n");

	p = put_bytes(buf, WIM_MAGIC_LEN, wim_magic_chars);
	p = put_u32(p, WIM_HEADER_DISK_SIZE);
	p = put_u32(p, WIM_VERSION);
	p = put_u32(p, hdr->flags);
	p = put_u32(p, (hdr->flags & WIM_HDR_FLAG_COMPRESSION) ? 
				WIM_CHUNK_SIZE : 0);
	randomize_byte_array(p, WIM_GID_LEN);
	p += WIM_GID_LEN;
	p = put_u16(p, 1); /* part number */
	p = put_u16(p, 1); /* total parts */
	p = put_u32(p, hdr->image_count);
	p = put_resource_entry(p, &hdr->lookup_table_res_entry);
	p = put_resource_entry(p, &hdr->xml_res_entry);
	p = put_resource_entry(p, &hdr->boot_metadata_res_entry);
	p = put_u32(p, hdr->boot_idx);
	p = put_resource_entry(p, &hdr->integrity);
	memset(p, 0, WIM_UNUSED_LEN);
	if (fwrite(buf, 1, sizeof(buf), out) != sizeof(buf)) {
		DEBUG("Failed to write WIM header: %m\n");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/*
 * Initializes the header for a WIM file.
 */
int init_header(struct wim_header *hdr, int ctype)
{
	memset(hdr, 0, sizeof(struct wim_header));
	switch (ctype) {
	case WIM_COMPRESSION_TYPE_NONE:
		hdr->flags = 0;
		break;
	case WIM_COMPRESSION_TYPE_LZX:
		hdr->flags = WIM_HDR_FLAG_COMPRESSION | 
			WIM_HDR_FLAG_COMPRESS_LZX;
		break;
	case WIM_COMPRESSION_TYPE_XPRESS:
		hdr->flags = WIM_HDR_FLAG_COMPRESSION | 
			WIM_HDR_FLAG_COMPRESS_XPRESS;
		break;
	default:
		ERROR("Invalid compression type specified (%d)!\n", ctype);
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
	}
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
WIMLIBAPI void wimlib_print_header(const WIMStruct *w)
{
	const struct wim_header *hdr = &w->hdr;
	uint i;

	printf("Magic Characters            = MSWIM\\000\\000\\000\n");
	printf("Header Size                 = %u\n", WIM_HEADER_DISK_SIZE);
	printf("Version                     = 0x%x\n", WIM_VERSION);

	printf("Flags                       = 0x%x\n", hdr->flags);
	for (i = 0; i < ARRAY_LEN(hdr_flags); i++)
		if (hdr_flags[i].flag & hdr->flags)
			printf("    WIM_HDR_FLAG_%s is set\n", hdr_flags[i].name);

	printf("Chunk Size                  = %u\n", WIM_CHUNK_SIZE);
	fputs ("GUID                        = ", stdout);
	print_byte_field(hdr->guid, WIM_GID_LEN);
	putchar('\n');
	printf("Part Number                 = %hu\n", 1);
	printf("Total Parts                 = %hu\n", 1);
	printf("Image Count                 = %u\n", hdr->image_count);
	printf("Lookup Table Size           = %"PRIu64"\n", 
				(u64)hdr->lookup_table_res_entry.size);
	printf("Lookup Table Flags          = 0x%hhx\n", 
				hdr->lookup_table_res_entry.flags);
	printf("Lookup Table Offset         = %"PRIu64"\n",
				hdr->lookup_table_res_entry.offset);
	printf("Lookup Table Original_size  = %"PRIu64"\n", 
				hdr->lookup_table_res_entry.original_size);
	printf("XML Data Size               = %"PRIu64"\n", 
				(u64)hdr->xml_res_entry.size);
	printf("XML Data Flags              = 0x%hhx\n", 
				hdr->xml_res_entry.flags);
	printf("XML Data Offset             = %"PRIu64"\n", 
				hdr->xml_res_entry.offset);
	printf("XML Data Original Size      = %"PRIu64"\n", 
				hdr->xml_res_entry.original_size);
	printf("Boot Metadata Size          = %"PRIu64"\n", 
				(u64)hdr->boot_metadata_res_entry.size);
	printf("Boot Metadata Flags         = 0x%hhx\n", 
				hdr->boot_metadata_res_entry.flags);
	printf("Boot Metadata Offset        = %"PRIu64"\n", 
				hdr->boot_metadata_res_entry.offset);
	printf("Boot Metadata Original Size = %"PRIu64"\n", 
				hdr->boot_metadata_res_entry.original_size);
	printf("Boot Index                  = %u\n", hdr->boot_idx);
	printf("Integrity Size              = %"PRIu64"\n", 
					(u64)hdr->integrity.size);
	printf("Integrity Flags             = 0x%hhx\n", 
					hdr->integrity.flags);
	printf("Integrity Offset            = %"PRIu64"\n", 
					hdr->integrity.offset);
	printf("Integrity Original_size     = %"PRIu64"\n", 
					hdr->integrity.original_size);
}
