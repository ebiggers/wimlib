/*
 * security.c
 *
 * Read and write the WIM security data.  The security data is a table of
 * security descriptors. Each WIM image has its own security data, but it's
 * possible that an image's security data have no security descriptors.
 */

/*
 * Copyright (C) 2012 Eric Biggers
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
#include "io.h"
#include "security.h"

/* 
 * This is a hack to work around a problem in libntfs-3g.  libntfs-3g validates
 * security descriptors with a function named ntfs_valid_descr().
 * ntfs_valid_descr() considers a security descriptor that ends in a SACL
 * (Sysetm Access Control List) with no ACE's (Access Control Entries) to be
 * invalid.  However, a security descriptor like this exists in the Windows 7
 * install.wim.  Here, security descriptors matching this pattern are modified
 * to have no SACL.  This should make no difference since the SACL had no
 * entries anyway; however  his ensures that that the security descriptors pass
 * the validation in libntfs-3g.
 */
static void empty_sacl_fixup(char *descr, u64 *size_p)
{
	if (*size_p >= sizeof(SecurityDescriptor)) {
		SecurityDescriptor *sd = (SecurityDescriptor*)descr;
		u32 sacl_offset = le32_to_cpu(sd->sacl_offset);
		if (sacl_offset == *size_p - sizeof(ACL)) {
			sd->sacl_offset = to_le32(0);
			*size_p -= sizeof(ACL);
		}
	}
}

/* 
 * Reads the security data from the metadata resource.
 *
 * @metadata_resource:	An array that contains the uncompressed metadata
 * 				resource for the WIM file.
 * @metadata_resource_len:	The length of @metadata_resource.  It MUST be at
 *				least 8 bytes.
 * @sd_p:	A pointer to a pointer to a wim_security_data structure that
 * 		will be filled in with a pointer to a new wim_security_data
 * 		structure on success.
 *
 * Note: There is no `offset' argument because the security data is located at
 * the beginning of the metadata resource.
 */
int read_security_data(const u8 metadata_resource[], u64 metadata_resource_len,
		       struct wim_security_data **sd_p)
{
	struct wim_security_data *sd;
	const u8 *p;
	int ret;
	u64 total_len;

	sd = MALLOC(sizeof(struct wim_security_data));
	if (!sd) {
		ERROR("Out of memory");
		return WIMLIB_ERR_NOMEM;
	}
	sd->sizes	= NULL;
	sd->descriptors = NULL;
	sd->refcnt	= 1;

	p = metadata_resource;
	p = get_u32(p, &sd->total_length);
	p = get_u32(p, (u32*)&sd->num_entries);

	if (sd->num_entries > 0x7fffffff) {
		ERROR("Security data has too many entries!");
		ret = WIMLIB_ERR_INVALID_SECURITY_DATA;
		goto out_free_sd;
	}

	/* Verify the listed total length of the security data is big enough to
	 * include the sizes array, verify that the file data is big enough to
	 * include it as well, then allocate the array of sizes.
	 *
	 * Note: The total length of the security data must fit in a 32-bit
	 * integer, even though each security descriptor size is a 64-bit
	 * integer.  This is stupid, and we need to be careful not to actually
	 * let the security descriptor sizes be over 0xffffffff.  */
	if ((u64)sd->total_length > metadata_resource_len) {
		ERROR("Security data total length (%u) is bigger than the "
		      "metadata resource length (%"PRIu64")",
		      sd->total_length, metadata_resource_len);
		ret = WIMLIB_ERR_INVALID_SECURITY_DATA;
		goto out_free_sd;
	}

	DEBUG("Reading security data: %u entries, length = %u",
	      sd->num_entries, sd->total_length);

	if (sd->num_entries == 0) {
		/* No security data. */
		total_len = 8;
		goto out;
	}

	u64 sizes_size = (u64)sd->num_entries * sizeof(u64);
	u64 size_no_descriptors = 8 + sizes_size;
	if (size_no_descriptors > (u64)sd->total_length) {
		ERROR("Security data total length of %u is too short because "
		      "there must be at least %"PRIu64" bytes of security data",
		      sd->total_length, 8 + sizes_size);
		ret = WIMLIB_ERR_INVALID_SECURITY_DATA;
		goto out_free_sd;
	}
	sd->sizes = MALLOC(sizes_size);
	if (!sd->sizes) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_sd;
	}

	/* Copy the sizes array in from the file data. */
	p = get_bytes(p, sizes_size, sd->sizes);
	array_to_le64(sd->sizes, sd->num_entries);

	/* Allocate the array of pointers to descriptors, and read them in. */
	sd->descriptors = CALLOC(sd->num_entries, sizeof(u8*));
	if (!sd->descriptors) {
		ERROR("Out of memory while allocating security "
		      "descriptors");
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_sd;
	}
	total_len = size_no_descriptors;

	for (u32 i = 0; i < sd->num_entries; i++) {
		/* Watch out for huge security descriptor sizes that could
		 * overflow the total length and wrap it around. */
		if (total_len + sd->sizes[i] < total_len) {
			ERROR("Caught overflow in security descriptor lengths "
			      "(current total length = %"PRIu64", security "
			      "descriptor size = %"PRIu64")",
			      total_len, sd->sizes[i]);
			ret = WIMLIB_ERR_INVALID_SECURITY_DATA;
			goto out_free_sd;
		}
		total_len += sd->sizes[i];
		if (total_len > (u64)sd->total_length) {
			ERROR("Security data total length of %u is too short "
			      "because there are at least %"PRIu64" bytes of "
			      "security data", sd->total_length, total_len);
			ret = WIMLIB_ERR_INVALID_SECURITY_DATA;
			goto out_free_sd;
		}
		sd->descriptors[i] = MALLOC(sd->sizes[i]);
		if (!sd->descriptors[i]) {
			ERROR("Out of memory while allocating security "
			      "descriptors");
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_sd;
		}
		p = get_bytes(p, sd->sizes[i], sd->descriptors[i]);
		empty_sacl_fixup(sd->descriptors[i], &sd->sizes[i]);
	}
out:
	sd->total_length = (u32)total_len;
	*sd_p = sd;
	return 0;
out_free_sd:
	free_security_data(sd);
	return ret;
}

/* 
 * Writes security data to an in-memory buffer.
 */
u8 *write_security_data(const struct wim_security_data *sd, u8 *p)
{
	DEBUG("Writing security data (total_length = %"PRIu32", num_entries "
	      "= %"PRIu32")", sd->total_length, sd->num_entries);

	u32 aligned_length = (sd->total_length + 7) & ~7;

	u8 *orig_p = p;
	p = put_u32(p, aligned_length);
	p = put_u32(p, sd->num_entries);

	for (u32 i = 0; i < sd->num_entries; i++)
		p = put_u64(p, sd->sizes[i]);

	for (u32 i = 0; i < sd->num_entries; i++)
		p = put_bytes(p, sd->sizes[i], sd->descriptors[i]);

	wimlib_assert(p - orig_p == sd->total_length);
	p = put_zeroes(p, aligned_length - sd->total_length);

	DEBUG("Successfully wrote security data.");
	return p;
}

static void print_acl(const u8 *p, const char *type)
{
	ACL *acl = (ACL*)p;
	TO_LE16(acl->acl_size);
	TO_LE16(acl->acl_count);
	printf("    [%s ACL]\n", type);
	printf("    Revision = %u\n", acl->revision);
	printf("    ACL Size = %u\n", acl->acl_size);
	printf("    ACE Count = %u\n", acl->ace_count);

	p += sizeof(ACL);
	for (uint i = 0; i < acl->ace_count; i++) {
		ACEHeader *hdr = (ACEHeader*)p;
		printf("        [ACE]\n");
		printf("        ACE type  = %d\n", hdr->type);
		printf("        ACE flags = 0x%x\n", hdr->flags);
		printf("        ACE size  = %u\n", hdr->size);
		AccessAllowedACE *aaa = (AccessAllowedACE*)hdr;
		printf("        ACE mask = %x\n", to_le32(aaa->mask));
		printf("        SID start = %u\n", to_le32(aaa->sid_start));
		p += hdr->size;
	}
	putchar('\n');
}

static void print_sid(const u8 *p, const char *type)
{
	SID *sid = (SID*)p;
	printf("    [%s SID]\n", type);
	printf("    Revision = %u\n", sid->revision);
	printf("    Subauthority count = %u\n", sid->sub_authority_count);
	printf("    Identifier authority = ");
	print_byte_field(sid->identifier_authority, sizeof(sid->identifier_authority));
	putchar('\n');
	for (uint i = 0; i < sid->sub_authority_count; i++)
		printf("    Subauthority %u = %u\n", i, to_le32(sid->sub_authority[i]));
	putchar('\n');
}

static void print_security_descriptor(const u8 *p, u64 size)
{
	SecurityDescriptor *sd = (SecurityDescriptor*)p;
	TO_LE16(sd->security_descriptor_control);
	TO_LE32(sd->owner_offset);
	TO_LE32(sd->group_offset);
	TO_LE32(sd->sacl_offset);
	TO_LE32(sd->dacl_offset);
	printf("Revision = %u\n", sd->revision);
	printf("Security Descriptor Control = %#x\n", sd->security_descriptor_control);
	printf("Owner offset = %u\n", sd->owner_offset);
	printf("Group offset = %u\n", sd->group_offset);
	printf("System ACL offset = %u\n", sd->sacl_offset);
	printf("Discretionary ACL offset = %u\n", sd->dacl_offset);

	if (sd->owner_offset != 0)
		print_sid(p + sd->owner_offset, "Owner");
	if (sd->group_offset != 0)
		print_sid(p + sd->group_offset, "Group");
	if (sd->sacl_offset != 0)
		print_acl(p + sd->sacl_offset, "System");
	if (sd->dacl_offset != 0)
		print_acl(p + sd->dacl_offset, "Discretionary");
}

/* 
 * Prints the security data for a WIM file.
 */
void print_security_data(const struct wim_security_data *sd)
{
	puts("[SECURITY DATA]");
	printf("Length            = %"PRIu32" bytes\n", sd->total_length);
	printf("Number of Entries = %"PRIu32"\n", sd->num_entries);

	for (u32 i = 0; i < sd->num_entries; i++) {
		printf("[SecurityDescriptor %"PRIu32", length = %"PRIu64"]\n", 
		       i, sd->sizes[i]);
		print_security_descriptor(sd->descriptors[i], sd->sizes[i]);
		putchar('\n');
	}
	putchar('\n');
}

void free_security_data(struct wim_security_data *sd)
{
	if (!sd)
		return;
	wimlib_assert(sd->refcnt != 0);
	if (--sd->refcnt == 0) {
		u8 **descriptors = sd->descriptors;
		u32 num_entries  = sd->num_entries;
		if (descriptors)
			while (num_entries--)
				FREE(*descriptors++);
		FREE(sd->sizes);
		FREE(sd->descriptors);
		FREE(sd);
	}
}
