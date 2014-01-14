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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/assert.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/security.h"
#include "wimlib/security_descriptor.h"
#include "wimlib/sha1.h"
#include "wimlib/util.h"

struct wim_security_data_disk {
	le32 total_length;
	le32 num_entries;
	le64 sizes[];
} _packed_attribute;

struct wim_security_data *
new_wim_security_data(void)
{
	return CALLOC(1, sizeof(struct wim_security_data));
}

/*
 * Reads the security data from the metadata resource of a WIM image.
 *
 * @metadata_resource:	An array that contains the uncompressed metadata
 *				resource for the WIM image.
 * @metadata_resource_len:	The length of @metadata_resource.
 * @sd_ret:	A pointer to a pointer to a wim_security_data structure that
 *		will be filled in with a pointer to a new wim_security_data
 *		structure containing the security data on success.
 *
 * Note: There is no `offset' argument because the security data is located at
 * the beginning of the metadata resource.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	WIMLIB_ERR_NOMEM
 */
int
read_wim_security_data(const u8 metadata_resource[], size_t metadata_resource_len,
		       struct wim_security_data **sd_ret)
{
	struct wim_security_data *sd;
	int ret;
	u64 total_len;
	u64 sizes_size;
	u64 size_no_descriptors;
	const struct wim_security_data_disk *sd_disk;
	const u8 *p;

	if (metadata_resource_len < 8)
		return WIMLIB_ERR_INVALID_METADATA_RESOURCE;

	sd = new_wim_security_data();
	if (!sd)
		goto out_of_memory;

	sd_disk = (const struct wim_security_data_disk*)metadata_resource;
	sd->total_length = le32_to_cpu(sd_disk->total_length);
	sd->num_entries = le32_to_cpu(sd_disk->num_entries);

	DEBUG("Reading security data: num_entries=%u, total_length=%u",
	      sd->num_entries, sd->total_length);

	/* Length field of 0 is a special case that really means length
	 * of 8. */
	if (sd->total_length == 0)
		sd->total_length = 8;

	/* The security_id field of each dentry is a signed 32-bit integer, so
	 * the possible indices into the security descriptors table are 0
	 * through 0x7fffffff.  Which means 0x80000000 security descriptors
	 * maximum.  Not like you should ever have anywhere close to that many
	 * security descriptors! */
	if (sd->num_entries > 0x80000000)
		goto out_invalid_sd;

	/* Verify the listed total length of the security data is big enough to
	 * include the sizes array, verify that the file data is big enough to
	 * include it as well, then allocate the array of sizes.
	 *
	 * Note: The total length of the security data must fit in a 32-bit
	 * integer, even though each security descriptor size is a 64-bit
	 * integer.  This is stupid, and we need to be careful not to actually
	 * let the security descriptor sizes be over 0xffffffff.  */
	if (sd->total_length > metadata_resource_len)
		goto out_invalid_sd;

	sizes_size = (u64)sd->num_entries * sizeof(u64);
	size_no_descriptors = 8 + sizes_size;
	if (size_no_descriptors > sd->total_length)
		goto out_invalid_sd;

	total_len = size_no_descriptors;

	/* Return immediately if no security descriptors. */
	if (sd->num_entries == 0)
		goto out_align_total_length;

	/* Allocate a new buffer for the sizes array */
	sd->sizes = MALLOC(sizes_size);
	if (!sd->sizes)
		goto out_of_memory;

	/* Copy the sizes array into the new buffer */
	for (u32 i = 0; i < sd->num_entries; i++) {
		sd->sizes[i] = le64_to_cpu(sd_disk->sizes[i]);
		if (sd->sizes[i] > 0xffffffff)
			goto out_invalid_sd;
	}

	p = (const u8*)sd_disk + size_no_descriptors;

	/* Allocate the array of pointers to the security descriptors, then read
	 * them into separate buffers. */
	sd->descriptors = CALLOC(sd->num_entries, sizeof(sd->descriptors[0]));
	if (!sd->descriptors)
		goto out_of_memory;

	for (u32 i = 0; i < sd->num_entries; i++) {
		if (sd->sizes[i] == 0)
			continue;
		total_len += sd->sizes[i];
		if (total_len > (u64)sd->total_length)
			goto out_invalid_sd;
		sd->descriptors[i] = memdup(p, sd->sizes[i]);
		if (!sd->descriptors[i])
			goto out_of_memory;
		p += sd->sizes[i];
	}
out_align_total_length:
	total_len = (total_len + 7) & ~7;
	sd->total_length = (sd->total_length + 7) & ~7;
	if (total_len != sd->total_length) {
		WARNING("Expected WIM security data total length of "
			"%u bytes, but calculated %u bytes",
			sd->total_length, (unsigned)total_len);
	}
	if (sd->total_length > metadata_resource_len)
		goto out_invalid_sd;
	*sd_ret = sd;
	ret = 0;
	goto out;
out_invalid_sd:
	ERROR("WIM security data is invalid!");
	ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
	goto out_free_sd;
out_of_memory:
	ERROR("Out of memory while reading WIM security data!");
	ret = WIMLIB_ERR_NOMEM;
out_free_sd:
	free_wim_security_data(sd);
out:
	return ret;
}

/*
 * Writes the security data for a WIM image to an in-memory buffer.
 */
u8 *
write_wim_security_data(const struct wim_security_data * restrict sd,
			u8 * restrict p)
{
	DEBUG("Writing security data (total_length = %"PRIu32", num_entries "
	      "= %"PRIu32")", sd->total_length, sd->num_entries);

	u8 *orig_p = p;
	struct wim_security_data_disk *sd_disk = (struct wim_security_data_disk*)p;
	u32 num_entries = sd->num_entries;

	sd_disk->total_length = cpu_to_le32(sd->total_length);
	sd_disk->num_entries = cpu_to_le32(num_entries);

	for (u32 i = 0; i < num_entries; i++)
		sd_disk->sizes[i] = cpu_to_le64(sd->sizes[i]);

	p = (u8*)&sd_disk->sizes[num_entries];

	for (u32 i = 0; i < num_entries; i++)
		p = mempcpy(p, sd->descriptors[i], sd->sizes[i]);

	while ((uintptr_t)p & 7)
		*p++ = 0;

	wimlib_assert(p - orig_p == sd->total_length);

	DEBUG("Successfully wrote security data.");
	return p;
}

static void
print_acl(const wimlib_ACL *acl, const tchar *type, size_t max_size)
{
	const u8 *p;

	if (max_size < sizeof(wimlib_ACL))
		return;

	u8 revision = acl->revision;
	u16 acl_size = le16_to_cpu(acl->acl_size);
	u16 ace_count = le16_to_cpu(acl->ace_count);

	tprintf(T("    [%"TS" ACL]\n"), type);
	tprintf(T("    Revision = %u\n"), revision);
	tprintf(T("    ACL Size = %u\n"), acl_size);
	tprintf(T("    ACE Count = %u\n"), ace_count);

	p = (const u8*)acl + sizeof(wimlib_ACL);
	for (u16 i = 0; i < ace_count; i++) {
		if (max_size < p + sizeof(wimlib_ACCESS_ALLOWED_ACE) - (const u8*)acl)
			break;
		const wimlib_ACCESS_ALLOWED_ACE *aaa = (const wimlib_ACCESS_ALLOWED_ACE*)p;
		tprintf(T("        [ACE]\n"));
		tprintf(T("        ACE type  = %d\n"), aaa->hdr.type);
		tprintf(T("        ACE flags = 0x%x\n"), aaa->hdr.flags);
		tprintf(T("        ACE size  = %u\n"), le16_to_cpu(aaa->hdr.size));
		tprintf(T("        ACE mask = %x\n"), le32_to_cpu(aaa->mask));
		tprintf(T("        SID start = %u\n"), le32_to_cpu(aaa->sid_start));
		p += le16_to_cpu(aaa->hdr.size);
	}
	tputchar(T('\n'));
}

static void
print_sid(const wimlib_SID *sid, const tchar *type, size_t max_size)
{
	if (max_size < sizeof(wimlib_SID))
		return;

	tprintf(T("    [%"TS" SID]\n"), type);
	tprintf(T("    Revision = %u\n"), sid->revision);
	tprintf(T("    Subauthority count = %u\n"), sid->sub_authority_count);
	tprintf(T("    Identifier authority = "));
	print_byte_field(sid->identifier_authority,
			 sizeof(sid->identifier_authority), stdout);
	tputchar(T('\n'));
	if (max_size < sizeof(wimlib_SID) + (size_t)sid->sub_authority_count * sizeof(u32))
		return;
	for (u8 i = 0; i < sid->sub_authority_count; i++) {
		tprintf(T("    Subauthority %u = %u\n"),
			i, le32_to_cpu(sid->sub_authority[i]));
	}
	tputchar(T('\n'));
}

static void
print_security_descriptor(const wimlib_SECURITY_DESCRIPTOR_RELATIVE *descr,
			  size_t size)
{
	u8 revision      = descr->revision;
	u16 control      = le16_to_cpu(descr->control);
	u32 owner_offset = le32_to_cpu(descr->owner_offset);
	u32 group_offset = le32_to_cpu(descr->group_offset);
	u32 dacl_offset  = le32_to_cpu(descr->dacl_offset);
	u32 sacl_offset  = le32_to_cpu(descr->sacl_offset);

	tprintf(T("Revision = %u\n"), revision);
	tprintf(T("Security Descriptor Control = %#x\n"), control);
	tprintf(T("Owner offset = %u\n"), owner_offset);
	tprintf(T("Group offset = %u\n"), group_offset);
	tprintf(T("Discretionary ACL offset = %u\n"), dacl_offset);
	tprintf(T("System ACL offset = %u\n"), sacl_offset);

	if (owner_offset != 0 && owner_offset <= size)
		print_sid((const wimlib_SID*)((const u8*)descr + owner_offset),
			  T("Owner"), size - owner_offset);

	if (group_offset != 0 && group_offset <= size)
		print_sid((const wimlib_SID*)((const u8*)descr + group_offset),
			  T("Group"), size - group_offset);

	if (dacl_offset != 0 && dacl_offset <= size)
		print_acl((const wimlib_ACL*)((const u8*)descr + dacl_offset),
			  T("Discretionary"), size - dacl_offset);

	if (sacl_offset != 0 && sacl_offset <= size)
		print_acl((const wimlib_ACL*)((const u8*)descr + sacl_offset),
			  T("System"), size - sacl_offset);
}

/*
 * Prints the security data for a WIM file.
 */
void
print_wim_security_data(const struct wim_security_data *sd)
{
	tputs(T("[SECURITY DATA]"));
	tprintf(T("Length            = %"PRIu32" bytes\n"), sd->total_length);
	tprintf(T("Number of Entries = %"PRIu32"\n"), sd->num_entries);

	for (u32 i = 0; i < sd->num_entries; i++) {
		tprintf(T("[SECURITY_DESCRIPTOR_RELATIVE %"PRIu32", length = %"PRIu64"]\n"),
			i, sd->sizes[i]);
		print_security_descriptor((const wimlib_SECURITY_DESCRIPTOR_RELATIVE*)sd->descriptors[i],
					  sd->sizes[i]);
		tputchar(T('\n'));
	}
	tputchar(T('\n'));
}

void
free_wim_security_data(struct wim_security_data *sd)
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
destroy_sd_set(struct wim_sd_set *sd_set, bool rollback)
{
	if (rollback) {
		struct wim_security_data *sd = sd_set->sd;
		u8 **descriptors = sd->descriptors + sd_set->orig_num_entries;
		u32 num_entries  = sd->num_entries - sd_set->orig_num_entries;
		while (num_entries--)
			FREE(*descriptors++);
		sd->num_entries = sd_set->orig_num_entries;
	}
	free_sd_tree(sd_set->rb_root.rb_node);
}

/* Inserts a a new node into the security descriptor index tree. */
static bool
insert_sd_node(struct wim_sd_set *set, struct sd_node *new)
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
			return false; /* Duplicate security descriptor */
	}
	rb_link_node(&new->rb_node, rb_parent, p);
	rb_insert_color(&new->rb_node, root);
	return true;
}

/* Returns the index of the security descriptor having a SHA1 message digest of
 * @hash.  If not found, return -1. */
int
lookup_sd(struct wim_sd_set *set, const u8 hash[SHA1_HASH_SIZE])
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
sd_set_add_sd(struct wim_sd_set *sd_set, const char *descriptor, size_t size)
{
	u8 hash[SHA1_HASH_SIZE];
	int security_id;
	struct sd_node *new;
	u8 **descriptors;
	u64 *sizes;
	u8 *descr_copy;
	struct wim_security_data *sd;
	bool bret;

	sha1_buffer(descriptor, size, hash);

	security_id = lookup_sd(sd_set, hash);
	if (security_id >= 0) /* Identical descriptor already exists */
		goto out;

	/* Need to add a new security descriptor */
	security_id = -1;

	new = MALLOC(sizeof(*new));
	if (!new)
		goto out;

	descr_copy = memdup(descriptor, size);
	if (!descr_copy)
		goto out_free_node;

	sd = sd_set->sd;
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
	DEBUG("There are now %u security descriptors", sd->num_entries);
	bret = insert_sd_node(sd_set, new);
	wimlib_assert(bret);
	security_id = new->security_id;
	goto out;
out_free_descr:
	FREE(descr_copy);
out_free_node:
	FREE(new);
out:
	return security_id;
}

/* Initialize a `struct sd_set' mapping from SHA1 message digests of security
 * descriptors to indices into the security descriptors table of the WIM image
 * (security IDs).  */
int
init_sd_set(struct wim_sd_set *sd_set, struct wim_security_data *sd)
{
	int ret;

	sd_set->sd = sd;
	sd_set->rb_root.rb_node = NULL;

	/* Remember the original number of security descriptors so that newly
	 * added ones can be rolled back if needed. */
	sd_set->orig_num_entries = sd->num_entries;
	for (u32 i = 0; i < sd->num_entries; i++) {
		struct sd_node *new;

		new = MALLOC(sizeof(struct sd_node));
		if (!new) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_destroy_sd_set;
		}
		sha1_buffer(sd->descriptors[i], sd->sizes[i], new->hash);
		new->security_id = i;
		if (!insert_sd_node(sd_set, new))
			FREE(new); /* Ignore duplicate security descriptor */
	}
	ret = 0;
	goto out;
out_destroy_sd_set:
	destroy_sd_set(sd_set, false);
out:
	return ret;
}
