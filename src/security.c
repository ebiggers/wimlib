/*
 * security.c
 *
 * Read the security data from the WIM.  Doing anything with the security data
 * is not yet implemented other than printing some information about it.
 *
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
#include "security.h"

/* 
 * Reads the security data from the metadata resource.
 *
 * @metadata_resource:	An array that contains the uncompressed metadata
 * 				resource for the WIM file.
 * @metadata_resource_len:	The length of @metadata_resource.
 * @sd:		A pointer to a WIMSecurityData structure that is filled in with
 * 		the security data.
 * @return:	True on success, false on failure.
 *
 * Note: There is no `offset' argument because the security data is located at
 * the beginning of the metadata resource.
 */
bool read_security_data(const u8 metadata_resource[], 
		u64 metadata_resource_len, WIMSecurityData *sd)
{
	sd->num_entries = 0;
	sd->descriptors = NULL;
	sd->sizes       = NULL;

	if (metadata_resource_len < 8) {
		ERROR("Not enough space in %"PRIu64"-byte file resource for "
				"security data!\n", metadata_resource_len);
		return false;
	}
	const u8 *p = metadata_resource;
	p = get_u32(p, &sd->total_length);
	p = get_u32(p, &sd->num_entries);

	/* Verify the listed total length of the security data is big enough to
	 * include the sizes array, verify that the file data is big enough to
	 * include it as well, then allocate the array of sizes. */
	u64 sizes_size = sd->num_entries * sizeof(u64);

	DEBUG("Reading security data with %u entries\n", sd->num_entries);

	if (sd->num_entries == 0) {
		sd->sizes = NULL;
		sd->descriptors = NULL;
		return true;
	}

	u64 size_no_descriptors = 8 + sizes_size;
	if (size_no_descriptors > sd->total_length) {
		ERROR("Security data total length of %"PRIu64" is too short "
				"because there must be at least %"PRIu64" bytes of security "
				"data!\n", sd->total_length, 
				8 + sizes_size);
		return false;
	}
	if (size_no_descriptors > metadata_resource_len) {
		ERROR("File resource of %"PRIu64" bytes is not big enough "
				"to hold security data of at least %"PRIu64" "
				"bytes!\n", metadata_resource_len, size_no_descriptors);
		return false;
	}
	sd->sizes = xmalloc(sizes_size);

	/* Copy the sizes array in from the file data. */
	p = get_bytes(p, sizes_size, sd->sizes);
	array_to_le64(sd->sizes, sd->num_entries);

	/* Allocate the array of pointers to descriptors, and read them in. */
	sd->descriptors = xmalloc(sd->num_entries * sizeof(u8*));
	u64 total_len = size_no_descriptors;

	for (uint i = 0; i < sd->num_entries; i++) {

		total_len += sd->sizes[i];
		if (total_len > sd->total_length) {
			ERROR("Security data total length of %"PRIu64" is too "
					"short because there are at least %"PRIu64" "
					"bytes of security data!\n", 
					sd->total_length, total_len);
			sd->num_entries = i;
			return false;
		}
		if (total_len > metadata_resource_len) {
			sd->num_entries = i;
			ERROR("File resource of %"PRIu64" bytes is not big enough "
					"to hold security data of at least %"PRIu64" "
					"bytes!\n", metadata_resource_len, total_len);
			return false;
		}
		sd->descriptors[i] = xmalloc(sd->sizes[i]);
		p = get_bytes(p, sd->sizes[i], sd->descriptors[i]);
	}

	/* The total_length field seems to take into account padding for
	 * quadword alignment of the dentry following it, so we can ignore the
	 * case where the actual length read so far is less than the specified
	 * total length of the security data. */
	#if 0
	if (total_len < sd->total_length) {
		/*ERROR("Warning: security data was actually %"PRIu64" bytes, but "*/
				/*"it says its length is %"PRIu64" bytes!\n",*/
				/*total_len, sd->total_length);*/
	}
	#endif

	return true;
}

/* 
 * Writes the security data to the output file.
 *
 * @sd:  	The security data structure.
 * @out:  	The FILE* for the output file.
 * @return:  	True on success, false on failure.
 */
u8 *write_security_data(const WIMSecurityData *sd, u8 *p)
{
	DEBUG("Writing security data (total_length = %u, num_entries = %u)\n",
			sd->total_length, sd->num_entries);
	u8 *orig_p = p;
	p = put_u32(p, sd->total_length);
	p = put_u32(p, sd->num_entries);

	for (uint i = 0; i < sd->num_entries; i++)
		p = put_u64(p, sd->sizes[i]);

	for (uint i = 0; i < sd->num_entries; i++)
		p = put_bytes(p, sd->sizes[i], sd->descriptors[i]);

	wimlib_assert(p - orig_p <= sd->total_length);

	DEBUG("Successfully wrote security data.\n");
	return orig_p + sd->total_length;
}

/* XXX We don't actually do anything with the ACL's yet besides being able to
 * print a few things.  It seems it would be a lot of work to have comprehensive
 * support for all the weird flags and stuff, and Windows PE seems to be okay
 * running from a WIM file that doesn't have any security data at all...  */

static void print_acl(const u8 *p)
{
	ACL *acl = (ACL*)p;
	TO_LE16(acl->acl_size);
	TO_LE16(acl->acl_count);
	printf("    [ACL]\n");
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
}

static void print_sid(const u8 *p)
{
	SID *sid = (SID*)p;
	printf("    [SID]\n");
	printf("    Revision = %u\n", sid->revision);
	printf("    Subauthority count = %u\n", sid->sub_authority_count);
	printf("    Identifier authority = ");
	print_byte_field(sid->identifier_authority, sizeof(sid->identifier_authority));
	putchar('\n');
	for (uint i = 0; i < sid->sub_authority_count; i++)
		printf("    Subauthority %u = %u\n", i, to_le32(sid->sub_authority[i]));
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
	printf("Security Descriptor Control = %u\n", sd->security_descriptor_control);
	printf("Owner offset = %u\n", sd->owner_offset);
	printf("Group offset = %u\n", sd->group_offset);
	printf("System ACL offset = %u\n", sd->sacl_offset);
	printf("Discretionary ACL offset = %u\n", sd->dacl_offset);

	if (sd->owner_offset != 0)
		print_sid(p + sd->owner_offset);
	if (sd->group_offset != 0)
		print_sid(p + sd->group_offset);
	if (sd->sacl_offset != 0)
		print_acl(p + sd->sacl_offset);
	if (sd->dacl_offset != 0)
		print_acl(p + sd->dacl_offset);
}

/* 
 * Prints the security data for a WIM file.
 *
 * @sd:	A pointer to the WIMSecurityData structure.
 */
void print_security_data(const WIMSecurityData *sd)
{
	puts("[SECURITY DATA]");
	printf("Length            = %u bytes\n", sd->total_length);
	printf("Number of Entries = %u\n", sd->num_entries);

	u64 num_entries = (u64)sd->num_entries;
	for (u64 i = 0; i < num_entries; i++) {
		printf("[SecurityDescriptor %"PRIu64", length = %"PRIu64"]\n", i,
				sd->sizes[i]);
		print_security_descriptor(sd->descriptors[i], sd->sizes[i]);
		putchar('\n');
	}
	putchar('\n');
}

void init_security_data(WIMSecurityData *sd)
{
	sd->total_length = 8;
	sd->num_entries  = 0;
	sd->sizes        = NULL;
	sd->descriptors  = NULL;
	/* XXX figure out what the security descriptors actually do */
}

void destroy_security_data(WIMSecurityData *sd)
{
	u8 **descriptors = sd->descriptors;
	u32 num_entries = sd->num_entries;
	while (num_entries--)
		FREE(*descriptors++);
	sd->num_entries = 0;
	FREE(sd->sizes);
	sd->sizes = NULL;
	FREE(sd->descriptors);
	sd->descriptors = NULL;
}

