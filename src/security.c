/*
 * security.c
 *
 * Read and write the per-WIM-image table of security descriptors.
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
#include "security.h"

/* At the start of each type of access control entry.  */
typedef struct {
	/* enum ace_type, specifies what type of ACE this is.  */
	u8 type;

	/* bitwise OR of the inherit ACE flags #defined above */
	u8 flags;

	/* Size of the access control entry. */
	u8 size;
} ACEHeader;

/* Grants rights to a user or group */
typedef struct {
	ACEHeader hdr;
	u32 mask;
	u32 sid_start;
} AccessAllowedACE;

/* Denies rights to a user or group */
typedef struct {
	ACEHeader hdr;
	u32 mask;
	u32 sid_start;
} AccessDeniedACE;

typedef struct {
	ACEHeader hdr;
	u32 mask;
	u32 sid_start;
} SystemAuditACE;


/* Header of an access control list. */
typedef struct {
	/* ACL_REVISION or ACL_REVISION_DS */
	u8 revision;

	/* padding */
	u8 sbz1;

	/* Total size of the ACL, including all access control entries */
	u16 acl_size;

	/* Number of access control entry structures that follow the ACL
	 * structure. */
	u16 ace_count;

	/* padding */
	u16 sbz2;
} ACL;

/* A structure used to identify users or groups. */
typedef struct {

	/* example: 0x1 */
	u8  revision;
	u8  sub_authority_count;

	/* Identifies the authority that issued the SID.  Can be, but does not
	 * have to be, one of enum sid_authority_value */
	u8  identifier_authority[6];

	u32 sub_authority[0];
} SID;


typedef struct {
	/* Example: 0x1 */
	u8 revision;
	/* Example: 0x0 */
	u8 sbz1;
	/* Example: 0x4149 */
	u16 security_descriptor_control;

	/* Offset of a SID structure in the security descriptor. */
	/* Example: 0x14 */
	u32 owner_offset;

	/* Offset of a SID structure in the security descriptor. */
	/* Example: 0x24 */
	u32 group_offset;

	/* Offset of an ACL structure in the security descriptor. */
	/* System ACL. */
	/* Example: 0x00 */
	u32 sacl_offset;

	/* Offset of an ACL structure in the security descriptor. */
	/* Discretionary ACL. */
	/* Example: 0x34 */
	u32 dacl_offset;
} SecurityDescriptor;

/*
 * This is a hack to work around a problem in libntfs-3g.  libntfs-3g validates
 * security descriptors with a function named ntfs_valid_descr().
 * ntfs_valid_descr() considers a security descriptor that ends in a SACL
 * (Sysetm Access Control List) with no ACE's (Access Control Entries) to be
 * invalid.  However, a security descriptor like this exists in the Windows 7
 * install.wim.  Here, security descriptors matching this pattern are modified
 * to have no SACL.  This should make no difference since the SACL had no
 * entries anyway; however this ensures that that the security descriptors pass
 * the validation in libntfs-3g.
 */
static void
empty_sacl_fixup(u8 *descr, u64 *size_p)
{
	/* No-op if no NTFS-3g support, or if NTFS-3g is version 2013 or later
	 * */
#if defined(WITH_NTFS_3G) && !defined(HAVE_NTFS_MNT_RDONLY)
	if (*size_p >= sizeof(SecurityDescriptor)) {
		SecurityDescriptor *sd = (SecurityDescriptor*)descr;
		u32 sacl_offset = le32_to_cpu(sd->sacl_offset);
		if (sacl_offset == *size_p - sizeof(ACL)) {
			sd->sacl_offset = cpu_to_le32(0);
			*size_p -= sizeof(ACL);
		}
	}
#endif
}

/*
 * Reads the security data from the metadata resource.
 *
 * @metadata_resource:	An array that contains the uncompressed metadata
 * 				resource for the WIM file.
 * @metadata_resource_len:	The length of @metadata_resource.  It must be at
 *				least 8 bytes.
 * @sd_p:	A pointer to a pointer to a wim_security_data structure that
 * 		will be filled in with a pointer to a new wim_security_data
 * 		structure on success.
 *
 * Note: There is no `offset' argument because the security data is located at
 * the beginning of the metadata resource.
 */
int
read_security_data(const u8 metadata_resource[], u64 metadata_resource_len,
		   struct wim_security_data **sd_p)
{
	struct wim_security_data *sd;
	const u8 *p;
	int ret;
	u64 total_len;

	wimlib_assert(metadata_resource_len >= 8);

	/*
	 * Sorry this function is excessively complicated--- I'm just being
	 * extremely careful about integer overflows.
	 */

	sd = MALLOC(sizeof(struct wim_security_data));
	if (!sd) {
		ERROR("Out of memory");
		return WIMLIB_ERR_NOMEM;
	}
	sd->sizes	= NULL;
	sd->descriptors = NULL;

	p = metadata_resource;
	p = get_u32(p, &sd->total_length);
	p = get_u32(p, (u32*)&sd->num_entries);

	/* The security_id field of each dentry is a signed 32-bit integer, so
	 * the possible indices into the security descriptors table are 0
	 * through 0x7fffffff.  Which means 0x80000000 security descriptors
	 * maximum.  Not like you should ever have anywhere close to that many
	 * security descriptors! */
	if (sd->num_entries > 0x80000000) {
		ERROR("Security data has too many entries!");
		goto out_invalid_sd;
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
		goto out_invalid_sd;
	}

	DEBUG("Reading security data: %u entries, length = %u",
	      sd->num_entries, sd->total_length);

	if (sd->num_entries == 0) {
		/* No security descriptors.  We allow the total_length field to
		 * be either 8 (which is correct, since there are always 2
		 * 32-bit integers) or 0. */
		if (sd->total_length != 0 && sd->total_length != 8) {
			ERROR("Invalid security data length (%u): expected 0 or 8",
			      sd->total_length);
			goto out_invalid_sd;
		}
		sd->total_length = 8;
		goto out_return_sd;
	}

	u64 sizes_size = (u64)sd->num_entries * sizeof(u64);
	u64 size_no_descriptors = 8 + sizes_size;
	if (size_no_descriptors > (u64)sd->total_length) {
		ERROR("Security data total length of %u is too short because "
		      "there seem to be at least %"PRIu64" bytes of security data",
		      sd->total_length, 8 + sizes_size);
		goto out_invalid_sd;
	}

	sd->sizes = MALLOC(sizes_size);
	if (!sd->sizes) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_sd;
	}

	/* Copy the sizes array in from the file data. */
	p = get_bytes(p, sizes_size, sd->sizes);
	array_le64_to_cpu(sd->sizes, sd->num_entries);

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
			goto out_invalid_sd;
		}
		total_len += sd->sizes[i];
		/* This check ensures that the descriptor size fits in a 32 bit
		 * integer.  Because if it didn't, the total length would come
		 * out bigger than sd->total_length, which is a 32 bit integer.
		 * */
		if (total_len > (u64)sd->total_length) {
			ERROR("Security data total length of %u is too short "
			      "because there seem to be at least %"PRIu64" "
			      "bytes of security data",
			      sd->total_length, total_len);
			goto out_invalid_sd;
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
	wimlib_assert(total_len <= 0xffffffff);
	if (((total_len + 7) & ~7) != ((sd->total_length + 7) & ~7)) {
		ERROR("Expected security data total length = %u, but "
		      "calculated %u", sd->total_length, (unsigned)total_len);
		goto out_invalid_sd;
	}
	sd->total_length = total_len;
out_return_sd:
	*sd_p = sd;
	return 0;
out_invalid_sd:
	ret = WIMLIB_ERR_INVALID_SECURITY_DATA;
out_free_sd:
	free_security_data(sd);
	return ret;
}

/*
 * Writes security data to an in-memory buffer.
 */
u8 *
write_security_data(const struct wim_security_data *sd, u8 *p)
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

static void
print_acl(const void *p, const tchar *type)
{
	const ACL *acl = p;
	u8 revision = acl->revision;
	u16 acl_size = le16_to_cpu(acl->acl_size);
	u16 ace_count = le16_to_cpu(acl->ace_count);
	tprintf(T("    [%"TS" ACL]\n"), type);
	tprintf(T("    Revision = %u\n"), revision);
	tprintf(T("    ACL Size = %u\n"), acl_size);
	tprintf(T("    ACE Count = %u\n"), ace_count);

	p += sizeof(ACL);
	for (u16 i = 0; i < ace_count; i++) {
		const ACEHeader *hdr = p;
		tprintf(T("        [ACE]\n"));
		tprintf(T("        ACE type  = %d\n"), hdr->type);
		tprintf(T("        ACE flags = 0x%x\n"), hdr->flags);
		tprintf(T("        ACE size  = %u\n"), hdr->size);
		const AccessAllowedACE *aaa = (const AccessAllowedACE*)hdr;
		tprintf(T("        ACE mask = %x\n"), le32_to_cpu(aaa->mask));
		tprintf(T("        SID start = %u\n"), le32_to_cpu(aaa->sid_start));
		p += hdr->size;
	}
	tputchar(T('\n'));
}

static void
print_sid(const void *p, const tchar *type)
{
	const SID *sid = p;
	tprintf(T("    [%"TS" SID]\n"), type);
	tprintf(T("    Revision = %u\n"), sid->revision);
	tprintf(T("    Subauthority count = %u\n"), sid->sub_authority_count);
	tprintf(T("    Identifier authority = "));
	print_byte_field(sid->identifier_authority,
			 sizeof(sid->identifier_authority), stdout);
	tputchar(T('\n'));
	for (u8 i = 0; i < sid->sub_authority_count; i++) {
		tprintf(T("    Subauthority %u = %u\n"),
			i, le32_to_cpu(sid->sub_authority[i]));
	}
	tputchar(T('\n'));
}

static void
print_security_descriptor(const void *p, u64 size)
{
	const SecurityDescriptor *sd = p;

	u8 revision      = sd->revision;
	u16 control      = le16_to_cpu(sd->security_descriptor_control);
	u32 owner_offset = le32_to_cpu(sd->owner_offset);
	u32 group_offset = le32_to_cpu(sd->group_offset);
	u32 sacl_offset  = le32_to_cpu(sd->sacl_offset);
	u32 dacl_offset  = le32_to_cpu(sd->dacl_offset);
	tprintf(T("Revision = %u\n"), revision);
	tprintf(T("Security Descriptor Control = %#x\n"), control);
	tprintf(T("Owner offset = %u\n"), owner_offset);
	tprintf(T("Group offset = %u\n"), group_offset);
	tprintf(T("System ACL offset = %u\n"), sacl_offset);
	tprintf(T("Discretionary ACL offset = %u\n"), dacl_offset);

	if (sd->owner_offset != 0)
		print_sid(p + owner_offset, T("Owner"));
	if (sd->group_offset != 0)
		print_sid(p + group_offset, T("Group"));
	if (sd->sacl_offset != 0)
		print_acl(p + sacl_offset, T("System"));
	if (sd->dacl_offset != 0)
		print_acl(p + dacl_offset, T("Discretionary"));
}

/*
 * Prints the security data for a WIM file.
 */
void
print_security_data(const struct wim_security_data *sd)
{
	wimlib_assert(sd != NULL);

	tputs(T("[SECURITY DATA]"));
	tprintf(T("Length            = %"PRIu32" bytes\n"), sd->total_length);
	tprintf(T("Number of Entries = %"PRIu32"\n"), sd->num_entries);

	for (u32 i = 0; i < sd->num_entries; i++) {
		tprintf(T("[SecurityDescriptor %"PRIu32", length = %"PRIu64"]\n"),
			i, sd->sizes[i]);
		print_security_descriptor(sd->descriptors[i], sd->sizes[i]);
		tputchar(T('\n'));
	}
	tputchar(T('\n'));
}

void
free_security_data(struct wim_security_data *sd)
{
	if (sd) {
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

struct sd_node {
	int security_id;
	u8 hash[SHA1_HASH_SIZE];
	struct rb_node rb_node;
};

static void
free_sd_tree(struct rb_node *node)
{
	if (node) {
		free_sd_tree(node->rb_left);
		free_sd_tree(node->rb_right);
		FREE(container_of(node, struct sd_node, rb_node));
	}
}

/* Frees a security descriptor index set. */
void
destroy_sd_set(struct sd_set *sd_set)
{
	free_sd_tree(sd_set->rb_root.rb_node);
}

/* Inserts a a new node into the security descriptor index tree. */
static void
insert_sd_node(struct sd_set *set, struct sd_node *new)
{
	struct rb_root *root = &set->rb_root;
	struct rb_node **p = &(root->rb_node);
	struct rb_node *rb_parent = NULL;

	while (*p) {
		struct sd_node *this = container_of(*p, struct sd_node, rb_node);
		int cmp = hashes_cmp(new->hash, this->hash);

		rb_parent = *p;
		if (cmp < 0)
			p = &((*p)->rb_left);
		else if (cmp > 0)
			p = &((*p)->rb_right);
		else
			wimlib_assert(0); /* Duplicate SHA1 message digest */
	}
	rb_link_node(&new->rb_node, rb_parent, p);
	rb_insert_color(&new->rb_node, root);
}

/* Returns the index of the security descriptor having a SHA1 message digest of
 * @hash.  If not found, return -1. */
int
lookup_sd(struct sd_set *set, const u8 hash[SHA1_HASH_SIZE])
{
	struct rb_node *node = set->rb_root.rb_node;

	while (node) {
		struct sd_node *sd_node = container_of(node, struct sd_node, rb_node);
		int cmp = hashes_cmp(hash, sd_node->hash);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return sd_node->security_id;
	}
	return -1;
}

/*
 * Adds a security descriptor to the indexed security descriptor set as well as
 * the corresponding `struct wim_security_data', and returns the new security
 * ID; or, if there is an existing security descriptor that is the same, return
 * the security ID for it.  If a new security descriptor cannot be allocated,
 * return -1.
 */
int
sd_set_add_sd(struct sd_set *sd_set, const char descriptor[], size_t size)
{
	u8 hash[SHA1_HASH_SIZE];
	int security_id;
	struct sd_node *new;
	u8 **descriptors;
	u64 *sizes;
	u8 *descr_copy;
	struct wim_security_data *sd;

	sha1_buffer((const u8*)descriptor, size, hash);

	security_id = lookup_sd(sd_set, hash);
	if (security_id >= 0) /* Identical descriptor already exists */
		return security_id;

	/* Need to add a new security descriptor */
	new = MALLOC(sizeof(*new));
	if (!new)
		goto out;
	descr_copy = MALLOC(size);
	if (!descr_copy)
		goto out_free_node;

	sd = sd_set->sd;

	memcpy(descr_copy, descriptor, size);
	new->security_id = sd->num_entries;
	copy_hash(new->hash, hash);

	/* There typically are only a few dozen security descriptors in a
	 * directory tree, so expanding the array of security descriptors by
	 * only 1 extra space each time should not be a problem. */
	descriptors = REALLOC(sd->descriptors,
			      (sd->num_entries + 1) * sizeof(sd->descriptors[0]));
	if (!descriptors)
		goto out_free_descr;
	sd->descriptors = descriptors;
	sizes = REALLOC(sd->sizes,
			(sd->num_entries + 1) * sizeof(sd->sizes[0]));
	if (!sizes)
		goto out_free_descr;
	sd->sizes = sizes;
	sd->descriptors[sd->num_entries] = descr_copy;
	sd->sizes[sd->num_entries] = size;
	sd->num_entries++;
	DEBUG("There are now %d security descriptors", sd->num_entries);
	sd->total_length += size + sizeof(sd->sizes[0]);
	insert_sd_node(sd_set, new);
	return new->security_id;
out_free_descr:
	FREE(descr_copy);
out_free_node:
	FREE(new);
out:
	return -1;
}
