/*
 * test_support.c - Supporting code for tests
 */

/*
 * Copyright (C) 2015-2016 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

/*
 * This file contains specialized test code which is only compiled when the
 * library is configured with --enable-test-support.  The major features are:
 *
 *	- Random directory tree generation
 *	- Directory tree comparison
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef ENABLE_TEST_SUPPORT

#include <ctype.h>
#include <math.h>

#include "wimlib.h"
#include "wimlib/endianness.h"
#include "wimlib/encoding.h"
#include "wimlib/metadata.h"
#include "wimlib/dentry.h"
#include "wimlib/inode.h"
#include "wimlib/reparse.h"
#include "wimlib/scan.h"
#include "wimlib/security_descriptor.h"
#include "wimlib/test_support.h"

/*----------------------------------------------------------------------------*
 *                            File tree generation                            *
 *----------------------------------------------------------------------------*/

struct generation_context {
	struct scan_params *params;
	struct wim_dentry *used_short_names[256];
	bool metadata_only;
};

static u32
rand32(void)
{
	static u64 state = 0x55DB93D0AB838771;

	/* A simple linear congruential generator  */
	state = (state * 25214903917 + 11) & ((1ULL << 48) - 1);
	return state >> 16;
}

static bool
randbool(void)
{
	return (rand32() & 1) != 0;
}

static u8
rand8(void)
{
	return (u8)rand32();
}

static u16
rand16(void)
{
	return (u16)rand32();
}

static u64
rand64(void)
{
	return ((u64)rand32() << 32) | rand32();
}

static u64
generate_random_timestamp(void)
{
	/* When setting timestamps on Windows:
	 * - 0 is a special value meaning "not specified"
	 * - if the high bit is set you get STATUS_INVALID_PARAMETER  */
	return (1 + rand64()) & ~(1ULL << 63);
}

static const struct {
	u8 num_subauthorities;
	u64 identifier_authority;
	u32 subauthorities[6];
} common_sids[] = {
	{ 1, 0, {0}}, /* NULL_SID  */
	{ 1, 1, {0}}, /* WORLD_SID */
	{ 1, 2, {0}}, /* LOCAL_SID */
	{ 1, 3, {0}}, /* CREATOR_OWNER_SID */
	{ 1, 3, {1}}, /* CREATOR_GROUP_SID */
	{ 1, 3, {2}}, /* CREATOR_OWNER_SERVER_SID */
	{ 1, 3, {3}}, /* CREATOR_GROUP_SERVER_SID */
	// { 0, 5, {}},	 /* NT_AUTHORITY_SID */
	{ 1, 5, {1}}, /* DIALUP_SID */
	{ 1, 5, {2}}, /* NETWORK_SID */
	{ 1, 5, {3}}, /* BATCH_SID */
	{ 1, 5, {4}}, /* INTERACTIVE_SID */
	{ 1, 5, {6}}, /* SERVICE_SID */
	{ 1, 5, {7}}, /* ANONYMOUS_LOGON_SID */
	{ 1, 5, {8}}, /* PROXY_SID */
	{ 1, 5, {9}}, /* SERVER_LOGON_SID */
	{ 1, 5, {10}}, /* SELF_SID */
	{ 1, 5, {11}}, /* AUTHENTICATED_USER_SID */
	{ 1, 5, {12}}, /* RESTRICTED_CODE_SID */
	{ 1, 5, {13}}, /* TERMINAL_SERVER_SID */
	{ 1, 5, {18}}, /* NT AUTHORITY\SYSTEM */
	{ 1, 5, {19}}, /* NT AUTHORITY\LOCAL SERVICE */
	{ 1, 5, {20}}, /* NT AUTHORITY\NETWORK SERVICE */
	{ 5 ,80, {956008885, 3418522649, 1831038044, 1853292631, 2271478464}}, /* trusted installer  */
	{ 2 ,5, {32, 544} } /* BUILTIN\ADMINISTRATORS  */
};

/* Generate a SID and return its size in bytes.  */
static size_t
generate_random_sid(wimlib_SID *sid, struct generation_context *ctx)
{
	u32 r = rand32();

	sid->revision = 1;

	if (r & 1) {
		/* Common SID  */
		r = (r >> 1) % ARRAY_LEN(common_sids);

		sid->sub_authority_count = common_sids[r].num_subauthorities;
		for (int i = 0; i < 6; i++) {
			sid->identifier_authority[i] =
				common_sids[r].identifier_authority >> (40 - i * 8);
		}
		for (int i = 0; i < common_sids[r].num_subauthorities; i++)
			sid->sub_authority[i] = cpu_to_le32(common_sids[r].subauthorities[i]);
	} else {
		/* Random SID  */

		sid->sub_authority_count = 1 + ((r >> 1) % 15);

		for (int i = 0; i < 6; i++)
			sid->identifier_authority[i] = rand8();

		for (int i = 0; i < sid->sub_authority_count; i++)
			sid->sub_authority[i] = cpu_to_le32(rand32());
	}
	return (u8 *)&sid->sub_authority[sid->sub_authority_count] - (u8 *)sid;
}

/* Generate an ACL and return its size in bytes.  */
static size_t
generate_random_acl(wimlib_ACL *acl, bool dacl, struct generation_context *ctx)
{
	u8 *p;
	u16 ace_count;

	ace_count = rand32() % 16;

	acl->revision = 2;
	acl->sbz1 = 0;
	acl->ace_count = cpu_to_le16(ace_count);
	acl->sbz2 = 0;

	p = (u8 *)(acl + 1);

	for (int i = 0; i < ace_count; i++) {
		wimlib_ACCESS_ALLOWED_ACE *ace = (wimlib_ACCESS_ALLOWED_ACE *)p;

		/* ACCESS_ALLOWED, ACCESS_DENIED, or SYSTEM_AUDIT; format is the
		 * same for all  */
		if (dacl)
			ace->hdr.type = rand32() % 2;
		else
			ace->hdr.type = 2;
		ace->hdr.flags = rand8();
		ace->mask = cpu_to_le32(rand32() & 0x001F01FF);

		p += offsetof(wimlib_ACCESS_ALLOWED_ACE, sid) +
			generate_random_sid(&ace->sid, ctx);
		ace->hdr.size = cpu_to_le16(p - (u8 *)ace);
	}

	acl->acl_size = cpu_to_le16(p - (u8 *)acl);
	return p - (u8 *)acl;
}

/* Generate a security descriptor and return its size in bytes.  */
static size_t
generate_random_security_descriptor(void *_desc, struct generation_context *ctx)
{
	wimlib_SECURITY_DESCRIPTOR_RELATIVE *desc = _desc;
	u16 control;
	u8 *p;

	control = rand16();

	control &= (wimlib_SE_DACL_AUTO_INHERITED |
		    wimlib_SE_SACL_AUTO_INHERITED);

	control |= wimlib_SE_SELF_RELATIVE |
		   wimlib_SE_DACL_PRESENT |
		   wimlib_SE_SACL_PRESENT;

	desc->revision = 1;
	desc->sbz1 = 0;
	desc->control = cpu_to_le16(control);

	p = (u8 *)(desc + 1);

	desc->owner_offset = cpu_to_le32(p - (u8 *)desc);
	p += generate_random_sid((wimlib_SID *)p, ctx);

	desc->group_offset = cpu_to_le32(p - (u8 *)desc);
	p += generate_random_sid((wimlib_SID *)p, ctx);

	if ((control & wimlib_SE_DACL_PRESENT) && randbool()) {
		desc->dacl_offset = cpu_to_le32(p - (u8 *)desc);
		p += generate_random_acl((wimlib_ACL *)p, true, ctx);
	} else {
		desc->dacl_offset = cpu_to_le32(0);
	}

	if ((control & wimlib_SE_SACL_PRESENT) && randbool()) {
		desc->sacl_offset = cpu_to_le32(p - (u8 *)desc);
		p += generate_random_acl((wimlib_ACL *)p, false, ctx);
	} else {
		desc->sacl_offset = cpu_to_le32(0);
	}

	return p - (u8 *)desc;
}

static int
set_random_metadata(struct wim_inode *inode, struct generation_context *ctx)
{
	u32 v = rand32();
	u32 attrib = (v & (FILE_ATTRIBUTE_READONLY |
			   FILE_ATTRIBUTE_HIDDEN |
			   FILE_ATTRIBUTE_SYSTEM |
			   FILE_ATTRIBUTE_ARCHIVE |
			   FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
			   FILE_ATTRIBUTE_COMPRESSED));

	/* File attributes  */
	inode->i_attributes |= attrib;

	/* Timestamps  */
	inode->i_creation_time = generate_random_timestamp();
	inode->i_last_access_time = generate_random_timestamp();
	inode->i_last_write_time = generate_random_timestamp();

	/* Security descriptor  */
	if (randbool()) {
		char desc[8192] _aligned_attribute(8);
		size_t size;

		size = generate_random_security_descriptor(desc, ctx);

		wimlib_assert(size <= sizeof(desc));

		inode->i_security_id = sd_set_add_sd(ctx->params->sd_set,
						     desc, size);
		if (unlikely(inode->i_security_id < 0))
			return WIMLIB_ERR_NOMEM;
	}

	return 0;

}

/* Choose a random size for generated file data.  We want to usually generate
 * empty, small, or medium files, but occasionally generate large files.  */
static size_t
select_stream_size(struct generation_context *ctx)
{
	if (ctx->metadata_only)
		return 0;

	switch (rand32() % 2048) {
	default:
		/* Empty  */
		return 0;
	case 600 ... 799:
		/* Microscopic  */
		return rand32() % 64;
	case 800 ... 1319:
		/* Tiny  */
		return rand32() % 4096;
	case 1320 ... 1799:
		/* Small  */
		return rand32() % 32768;
	case 1800 ... 2046:
		/* Medium  */
		return rand32() % 262144;
	case 2047:
		/* Large  */
		return rand32() % 134217728;
	}
}

/* Fill 'buffer' with 'size' bytes of "interesting" file data.  */
static void
generate_data(u8 *buffer, size_t size, struct generation_context *ctx)
{
	size_t mask = -1;
	size_t num_byte_fills = rand32() % 256;

	memset(buffer, rand32() % 256, size);

	for (size_t i = 0; i < num_byte_fills; i++) {
		u8 b = rand8();

		size_t count = ((double)size / (double)num_byte_fills) *
				((double)rand32() / 2e9);
		size_t offset = rand32() & ~mask;

		while (count--) {
			buffer[(offset +
				((rand32()) & mask)) % size] = b;
		}


		if (rand32() % 4 == 0)
			mask = (size_t)-1 << rand32() % 4;
	}

	if (rand32() % 8 == 0) {
		double magnitude = rand32() % 128;
		double scale = 1.0 / (1 + (rand32() % 256));

		for (size_t i = 0; i < size; i++)
			buffer[i] += (int)(magnitude * cos(i * scale));
	}
}

static int
add_stream(struct wim_inode *inode, struct generation_context *ctx,
	   int stream_type, const utf16lechar *stream_name,
	   void *buffer, size_t size)
{
	struct blob_descriptor *blob = NULL;
	struct wim_inode_stream *strm;

	if (size) {
		blob = new_blob_descriptor();
		if (!blob)
			goto err_nomem;
		blob->attached_buffer = buffer;
		blob->blob_location = BLOB_IN_ATTACHED_BUFFER;
		blob->size = size;
	}

	strm = inode_add_stream(inode, stream_type, stream_name, blob);
	if (unlikely(!strm))
		goto err_nomem;

	prepare_unhashed_blob(blob, inode, strm->stream_id,
			      ctx->params->unhashed_blobs);
	return 0;

err_nomem:
	free_blob_descriptor(blob);
	return WIMLIB_ERR_NOMEM;
}

static int
set_random_reparse_point(struct wim_inode *inode, struct generation_context *ctx)
{
	void *buffer = NULL;
	size_t rpdatalen = select_stream_size(ctx) % (REPARSE_DATA_MAX_SIZE + 1);

	if (rpdatalen) {
		buffer = MALLOC(rpdatalen);
		if (!buffer)
			return WIMLIB_ERR_NOMEM;
		generate_data(buffer, rpdatalen, ctx);
	}

	inode->i_attributes |= FILE_ATTRIBUTE_REPARSE_POINT;
	inode->i_rp_reserved = rand16();

	if (rpdatalen >= GUID_SIZE && randbool()) {
		/* Non-Microsoft reparse tag (16-byte GUID required)  */
		u8 *guid = buffer;
		guid[6] = (guid[6] & 0x0F) | 0x40;
		guid[8] = (guid[8] & 0x3F) | 0x80;
		inode->i_reparse_tag = 0x00000100;
	} else {
		/* Microsoft reparse tag  */
		inode->i_reparse_tag = 0x80000000;
	}

	return add_stream(inode, ctx, STREAM_TYPE_REPARSE_POINT, NO_STREAM_NAME,
			  buffer, rpdatalen);
}

static int
add_random_data_stream(struct wim_inode *inode, struct generation_context *ctx,
		       const utf16lechar *stream_name)
{
	void *buffer = NULL;
	size_t size;

	size = select_stream_size(ctx);
	if (size) {
		buffer = MALLOC(size);
		if (!buffer)
			return WIMLIB_ERR_NOMEM;
		generate_data(buffer, size, ctx);
	}

	return add_stream(inode, ctx, STREAM_TYPE_DATA, stream_name,
			  buffer, size);
}

static int
set_random_streams(struct wim_inode *inode, struct generation_context *ctx,
		   bool reparse_ok)
{
	int ret;
	u32 r;

	/* Reparse point (sometimes)  */
	if (reparse_ok && rand32() % 8 == 0) {
		ret = set_random_reparse_point(inode, ctx);
		if (ret)
			return ret;
	}

	/* Unnamed data stream (nondirectories only)  */
	if (!(inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)) {
		ret = add_random_data_stream(inode, ctx, NO_STREAM_NAME);
		if (ret)
			return ret;
	}

	/* Named data streams (sometimes)  */
	r = rand32() % 256;
	if (r > 230) {
		utf16lechar stream_name[2] = {cpu_to_le16('a'), '\0'};
		r -= 230;
		while (r--) {
			ret = add_random_data_stream(inode, ctx, stream_name);
			if (ret)
				return ret;
			stream_name[0] += cpu_to_le16(1);
		}
	}

	return 0;
}

static inline bool
is_valid_windows_filename_char(utf16lechar c)
{
	return le16_to_cpu(c) > 31 &&
		c != cpu_to_le16('/') &&
		c != cpu_to_le16('<') &&
		c != cpu_to_le16('>') &&
		c != cpu_to_le16(':') &&
		c != cpu_to_le16('"') &&
		c != cpu_to_le16('/' ) &&
		c != cpu_to_le16('\\') &&
		c != cpu_to_le16('|') &&
		c != cpu_to_le16('?') &&
		c != cpu_to_le16('*');
}

/* Is the character valid in a filename on the current platform? */
static inline bool
is_valid_filename_char(utf16lechar c)
{
#ifdef __WIN32__
	return is_valid_windows_filename_char(c);
#else
	return c != cpu_to_le16('\0') && c != cpu_to_le16('/');
#endif
}

/* Generate a random filename and return its length. */
static int
generate_random_filename(utf16lechar name[], int max_len,
			 struct generation_context *ctx)
{
	int len;

	/* Choose the length of the name. */
	switch (rand32() % 8) {
	default:
		/* short name  */
		len = 1 + (rand32() % 6);
		break;
	case 2:
	case 3:
	case 4:
		/* medium-length name  */
		len = 7 + (rand32() % 8);
		break;
	case 5:
	case 6:
		/* long name  */
		len = 15 + (rand32() % 15);
		break;
	case 7:
		/* very long name  */
		len = 30 + (rand32() % 90);
		break;
	}
	len = min(len, max_len);

	/* Generate the characters in the name. */
	for (int i = 0; i < len; i++) {
		do {
			name[i] = rand16();
		} while (!is_valid_filename_char(name[i]));
	}

	/* Add a null terminator. */
	name[len] = cpu_to_le16('\0');

	return len;
}

/* The set of characters which are valid in short filenames. */
static const char valid_short_name_chars[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
	'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'!', '#', '$', '%', '&', '\'', '(', ')', '-', '@', '^', '_', '`', '{',
	'}', '~',
	/* TODO: why doesn't Windows accept these characters? */
	/* ' ', */
	/*128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141,*/
	/*142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,*/
	/*156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169,*/
	/*170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183,*/
	/*184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,*/
	/*198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,*/
	/*212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225,*/
	/*226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,*/
	/*240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253,*/
	/*254, 255*/
};

static int
generate_short_name_component(utf16lechar p[], int len)
{
	for (int i = 0; i < len; i++) {
		char c = valid_short_name_chars[rand32() %
						ARRAY_LEN(valid_short_name_chars)];
		p[i] = cpu_to_le16(c);
	}
#if 0 /* TODO: we aren't using space yet anyway */
	while (len > 1 && p[len - 1] == cpu_to_le16(' '))
		len--;
	if (p[len - 1] == cpu_to_le16(' '))
		p[len - 1] = cpu_to_le16('A');
#endif
	return len;
}

/* Generate a random short (8.3) filename and return its length.
 * The @name array must have length >= 13 (8 + 1 + 3 + 1). */
static int
generate_random_short_name(utf16lechar name[], struct generation_context *ctx)
{
	/*
	 * Legal short names on Windows consist of 1 to 8 characters, optionally
	 * followed by a dot then 1 to 3 more characters.  Only certain
	 * characters are allowed.  In addition, trailing spaces are not
	 * significant.
	 */
	int base_len = 1 + (rand32() % 8);
	int ext_len = rand32() % 4;
	int total_len;

	base_len = generate_short_name_component(name, base_len);

	if (ext_len) {
		name[base_len] = cpu_to_le16('.');
		ext_len = generate_short_name_component(&name[base_len + 1],
							ext_len);
		total_len = base_len + 1 + ext_len;
	} else {
		total_len = base_len;
	}
	name[total_len] = cpu_to_le16('\0');
	return total_len;
}

static u64
select_inode_number(struct generation_context *ctx)
{
	const struct wim_inode_table *table = ctx->params->inode_table;
	const struct hlist_head *head;
	const struct wim_inode *inode;

	head = &table->array[rand32() % table->capacity];
	hlist_for_each_entry(inode, head, i_hlist_node)
		if (randbool())
			return inode->i_ino;

	return rand32();
}

static u32
select_num_children(u32 depth, struct generation_context *ctx)
{
	const double b = 1.01230;
	u32 r = rand32() % 500;
	return ((pow(b, pow(b, r)) - 1) / pow(depth, 1.5)) +
		(2 - exp(0.04/depth));
}

static bool
is_name_valid_in_win32_namespace(const utf16lechar *name)
{
	const utf16lechar *p;

	static const utf16lechar forbidden_names[][5] = {
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('N'), },
		{ cpu_to_le16('P'), cpu_to_le16('R'), cpu_to_le16('N'), },
		{ cpu_to_le16('A'), cpu_to_le16('U'), cpu_to_le16('X'), },
		{ cpu_to_le16('N'), cpu_to_le16('U'), cpu_to_le16('L'), },
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M'), cpu_to_le16('1'), },
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M'), cpu_to_le16('2'), },
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M'), cpu_to_le16('3'), },
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M'), cpu_to_le16('4'), },
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M'), cpu_to_le16('5'), },
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M'), cpu_to_le16('6'), },
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M'), cpu_to_le16('7'), },
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M'), cpu_to_le16('8'), },
		{ cpu_to_le16('C'), cpu_to_le16('O'), cpu_to_le16('M'), cpu_to_le16('9'), },
		{ cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T'), cpu_to_le16('1'), },
		{ cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T'), cpu_to_le16('2'), },
		{ cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T'), cpu_to_le16('3'), },
		{ cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T'), cpu_to_le16('4'), },
		{ cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T'), cpu_to_le16('5'), },
		{ cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T'), cpu_to_le16('6'), },
		{ cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T'), cpu_to_le16('7'), },
		{ cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T'), cpu_to_le16('8'), },
		{ cpu_to_le16('L'), cpu_to_le16('P'), cpu_to_le16('T'), cpu_to_le16('9'), },
	};

	/* The name must be nonempty. */
	if (!name || !*name)
		return false;

	/* All characters must be valid on Windows. */
	for (p = name; *p; p++)
		if (!is_valid_windows_filename_char(*p))
			return false;

	/* Note: a trailing dot or space is permitted, even though on Windows
	 * such a file can only be accessed using a WinNT-style path. */

	/* The name can't be one of the reserved names (case insensitively). */
	for (size_t i = 0; i < ARRAY_LEN(forbidden_names); i++)
		if (!cmp_utf16le_strings_z(forbidden_names[i], name, true))
			return false;

	return true;
}

static int
set_random_short_name(struct wim_dentry *dir, struct wim_dentry *child,
		      struct generation_context *ctx)
{
	utf16lechar name[12 + 1];
	int name_len;
	u32 hash;
	struct wim_dentry **bucket;

	/* If the long name is not allowed in the Win32 namespace, then it
	 * cannot be assigned a corresponding short name.  */
	if (!is_name_valid_in_win32_namespace(child->d_name))
		return 0;

retry:
	/* Don't select a short name that is already used by a long name within
	 * the same directory.  */
	do {
		name_len = generate_random_short_name(name, ctx);
	} while (get_dentry_child_with_utf16le_name(dir, name, name_len * 2,
						    WIMLIB_CASE_INSENSITIVE));


	/* Don't select a short name that is already used by another short name
	 * within the same directory.  */
	hash = 0;
	for (const utf16lechar *p = name; *p; p++)
		hash = (hash * 31) + *p;
	FREE(child->d_short_name);
	child->d_short_name = memdup(name, (name_len + 1) * 2);
	child->d_short_name_nbytes = name_len * 2;

	if (!child->d_short_name)
		return WIMLIB_ERR_NOMEM;

	bucket = &ctx->used_short_names[hash % ARRAY_LEN(ctx->used_short_names)];

	for (struct wim_dentry *d = *bucket; d != NULL;
	     d = d->d_next_extraction_alias) {
		if (!cmp_utf16le_strings(child->d_short_name, name_len,
					 d->d_short_name, d->d_short_name_nbytes / 2,
					 true)) {
			goto retry;
		}
	}

	if (!is_name_valid_in_win32_namespace(child->d_short_name))
		goto retry;

	child->d_next_extraction_alias = *bucket;
	*bucket = child;
	return 0;
}

static bool
inode_has_short_name(const struct wim_inode *inode)
{
	const struct wim_dentry *dentry;

	inode_for_each_dentry(dentry, inode)
		if (dentry_has_short_name(dentry))
			return true;

	return false;
}

static int
generate_dentry_tree_recursive(struct wim_dentry *dir, u32 depth,
			       struct generation_context *ctx)
{
	u32 num_children = select_num_children(depth, ctx);
	struct wim_dentry *child;
	int ret;

	memset(ctx->used_short_names, 0, sizeof(ctx->used_short_names));

	/* Generate 'num_children' dentries within 'dir'.  Some may be
	 * directories themselves.  */

	for (u32 i = 0; i < num_children; i++) {

		/* Generate the next child dentry.  */
		struct wim_inode *inode;
		u64 ino;
		bool is_directory;
		utf16lechar name[63 + 1]; /* for UNIX extraction: 63 * 4 <= 255 */
		int name_len;
		struct wim_dentry *duplicate;

		/* Decide whether to create a directory or not.  If not a
		 * directory, also decide on the inode number (i.e. we may
		 * generate a "hard link" to an existing file).  */
		is_directory = ((rand32() % 16) <= 6);
		if (is_directory)
			ino = 0;
		else
			ino = select_inode_number(ctx);

		/* Create the dentry. */
		ret = inode_table_new_dentry(ctx->params->inode_table, NULL,
					     ino, 0, is_directory, &child);
		if (ret)
			return ret;

		/* Choose a filename that is unique within the directory.*/
		do {
			name_len = generate_random_filename(name,
							    ARRAY_LEN(name) - 1,
							    ctx);
		} while (get_dentry_child_with_utf16le_name(dir, name, name_len * 2,
							    WIMLIB_CASE_PLATFORM_DEFAULT));

		ret = dentry_set_name_utf16le(child, name, name_len * 2);
		if (ret) {
			free_dentry(child);
			return ret;
		}

		/* Add the dentry to the directory. */
		duplicate = dentry_add_child(dir, child);
		wimlib_assert(!duplicate);

		inode = child->d_inode;

		if (inode->i_nlink > 1)  /* Existing inode?  */
			continue;

		/* New inode; set attributes, metadata, and data.  */

		if (is_directory)
			inode->i_attributes |= FILE_ATTRIBUTE_DIRECTORY;

		ret = set_random_metadata(inode, ctx);
		if (ret)
			return ret;

		ret = set_random_streams(inode, ctx, true);
		if (ret)
			return ret;

		/* Recurse if it's a directory.  */
		if (is_directory &&
		    !(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT))
		{
			ret = generate_dentry_tree_recursive(child, depth + 1,
							     ctx);
			if (ret)
				return ret;
		}
	}

	for_dentry_child(child, dir) {
		/* sometimes generate a unique short name  */
		if (randbool() && !inode_has_short_name(child->d_inode)) {
			ret = set_random_short_name(dir, child, ctx);
			if (ret)
				return ret;
		}
	}

	return 0;
}

int
generate_dentry_tree(struct wim_dentry **root_ret, const tchar *_ignored,
		     struct scan_params *params)
{
	int ret;
	struct wim_dentry *root = NULL;
	struct generation_context ctx = {
		.params = params,
	};

	ctx.metadata_only = ((rand32() % 8) != 0); /* usually metadata only  */

	ret = inode_table_new_dentry(params->inode_table, NULL, 0, 0, true, &root);
	if (!ret) {
		root->d_inode->i_attributes = FILE_ATTRIBUTE_DIRECTORY;
		ret = set_random_metadata(root->d_inode, &ctx);
	}
	if (!ret)
		ret = set_random_streams(root->d_inode, &ctx, false);
	if (!ret)
		ret = generate_dentry_tree_recursive(root, 1, &ctx);
	if (!ret)
		*root_ret = root;
	else
		free_dentry_tree(root, params->blob_table);
	return ret;
}

/*----------------------------------------------------------------------------*
 *                            File tree comparison                            *
 *----------------------------------------------------------------------------*/

#define INDEX_NODE_TO_DENTRY(node)	\
	((node) ? avl_tree_entry((node), struct wim_dentry, d_index_node) : NULL)

static struct wim_dentry *
dentry_first_child(struct wim_dentry *dentry)
{
	return INDEX_NODE_TO_DENTRY(
			avl_tree_first_in_order(dentry->d_inode->i_children));
}

static struct wim_dentry *
dentry_next_sibling(struct wim_dentry *dentry)
{
	return INDEX_NODE_TO_DENTRY(
			avl_tree_next_in_order(&dentry->d_index_node));
}

/*
 * Verify that the dentries in the tree 'd1' exactly match the dentries in the
 * tree 'd2', considering long and short filenames.  In addition, set
 * 'd_corresponding' of each dentry to point to the corresponding dentry in the
 * other tree, and set 'i_corresponding' of each inode to point to the
 * unverified corresponding inode in the other tree.
 */
static int
calc_corresponding_files_recursive(struct wim_dentry *d1, struct wim_dentry *d2,
				   int cmp_flags)
{
	struct wim_dentry *child1;
	struct wim_dentry *child2;
	int ret;

	/* Compare long filenames, case sensitively.  */
	if (cmp_utf16le_strings(d1->d_name, d1->d_name_nbytes / 2,
				d2->d_name, d2->d_name_nbytes / 2,
				false))
	{
		ERROR("Filename mismatch; path1=\"%"TS"\", path2=\"%"TS"\"",
		      dentry_full_path(d1), dentry_full_path(d2));
		return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;
	}

	/* Compare short filenames, case insensitively.  */
	if (!(d2->d_short_name_nbytes == 0 &&
	      (cmp_flags & WIMLIB_CMP_FLAG_SHORT_NAMES_NOT_PRESERVED)) &&
	    cmp_utf16le_strings(d1->d_short_name, d1->d_short_name_nbytes / 2,
				d2->d_short_name, d2->d_short_name_nbytes / 2,
				true))
	{
		ERROR("Short name mismatch; path=\"%"TS"\"",
		      dentry_full_path(d1));
		return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;
	}

	/* Match up the dentries  */
	d1->d_corresponding = d2;
	d2->d_corresponding = d1;

	/* Match up the inodes (may overwrite previous value)  */
	d1->d_inode->i_corresponding = d2->d_inode;
	d2->d_inode->i_corresponding = d1->d_inode;

	/* Process children  */
	child1 = dentry_first_child(d1);
	child2 = dentry_first_child(d2);
	while (child1 || child2) {

		if (!child1 || !child2) {
			ERROR("Child count mismatch; "
			      "path1=\"%"TS"\", path2=\"%"TS"\"",
			      dentry_full_path(d1), dentry_full_path(d2));
			return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;
		}

		/* Recurse on this pair of children.  */
		ret = calc_corresponding_files_recursive(child1, child2,
							 cmp_flags);
		if (ret)
			return ret;

		/* Continue to the next pair of children.  */
		child1 = dentry_next_sibling(child1);
		child2 = dentry_next_sibling(child2);
	}
	return 0;
}

/* Perform sanity checks on an image's inodes.  All assertions here should pass,
 * even if the images being compared are different.  */
static void
assert_inodes_sane(const struct wim_image_metadata *imd)
{
	const struct wim_inode *inode;
	const struct wim_dentry *dentry;
	size_t link_count;

	image_for_each_inode(inode, imd) {
		link_count = 0;
		inode_for_each_dentry(dentry, inode) {
			wimlib_assert(dentry->d_inode == inode);
			link_count++;
		}
		wimlib_assert(link_count > 0);
		wimlib_assert(link_count == inode->i_nlink);
		wimlib_assert(inode->i_corresponding != NULL);
	}
}

static int
check_hard_link(struct wim_dentry *dentry, void *_ignore)
{
	/* My inode is my corresponding dentry's inode's corresponding inode,
	 * and my inode's corresponding inode is my corresponding dentry's
	 * inode.  */
	const struct wim_inode *a = dentry->d_inode;
	const struct wim_inode *b = dentry->d_corresponding->d_inode;
	if (a == b->i_corresponding && a->i_corresponding == b)
		return 0;
	ERROR("Hard link difference; path=%"TS"", dentry_full_path(dentry));
	return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;
}

static int
cmp_inodes(const struct wim_inode *inode1, const struct wim_inode *inode2,
	   const struct wim_image_metadata *imd1,
	   const struct wim_image_metadata *imd2, int cmp_flags)
{
	const u32 attrib_diff = inode1->i_attributes ^ inode2->i_attributes;
	bool reparse_point_should_preserved = true;

	/* Compare attributes  */
	if (cmp_flags & WIMLIB_CMP_FLAG_ATTRIBUTES_NOT_PRESERVED) {

		/* In this mode, we expect that most attributes are not
		 * preserved.  However, FILE_ATTRIBUTE_DIRECTORY should always
		 * match.  */
		if (attrib_diff & FILE_ATTRIBUTE_DIRECTORY)
			goto attrib_mismatch;

		/* We may also expect FILE_ATTRIBUTE_REPARSE_POINT to be
		 * preserved for symlinks.  It also shouldn't be set if it
		 * wasn't set before.  */

		if ((cmp_flags & WIMLIB_CMP_FLAG_IMAGE2_SHOULD_HAVE_SYMLINKS) &&
		    inode_is_symlink(inode1))
			reparse_point_should_preserved = true;
		else
			reparse_point_should_preserved = false;

		if ((attrib_diff & FILE_ATTRIBUTE_REPARSE_POINT) &&
		    (reparse_point_should_preserved ||
		     (inode2->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)))
			goto attrib_mismatch;
	} else {

		/* Most attributes should be preserved.  */

		/* Nothing other than COMPRESSED and NORMAL should have changed.
		 */
		if (attrib_diff & ~(FILE_ATTRIBUTE_COMPRESSED |
				    FILE_ATTRIBUTE_NORMAL))
			goto attrib_mismatch;

		/* COMPRESSED shouldn't have changed unless specifically
		 * excluded.  */
		if ((attrib_diff & FILE_ATTRIBUTE_COMPRESSED) &&
		    !(cmp_flags & WIMLIB_CMP_FLAG_COMPRESSION_NOT_PRESERVED))
			goto attrib_mismatch;

		/* We allow NORMAL to change, but not if the file ended up with
		 * other attributes set as well.  */
		if ((attrib_diff & FILE_ATTRIBUTE_NORMAL) &&
		    (inode2->i_attributes & ~FILE_ATTRIBUTE_NORMAL))
			goto attrib_mismatch;
	}

	/* Compare security descriptors  */
	if (inode_has_security_descriptor(inode1)) {
		if (inode_has_security_descriptor(inode2)) {
			const void *desc1 = imd1->security_data->descriptors[inode1->i_security_id];
			const void *desc2 = imd2->security_data->descriptors[inode2->i_security_id];
			size_t size1 = imd1->security_data->sizes[inode1->i_security_id];
			size_t size2 = imd2->security_data->sizes[inode2->i_security_id];

			if (size1 != size2 || memcmp(desc1, desc2, size1)) {
				ERROR("Security descriptor of %"TS" differs!",
				      inode_any_full_path(inode1));
				return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;
			}
		} else if (!(cmp_flags & WIMLIB_CMP_FLAG_SECURITY_NOT_PRESERVED)) {
			ERROR("%"TS" has a security descriptor in the first image but "
			      "not in the second image!", inode_any_full_path(inode1));
			return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;
		}
	} else if (inode_has_security_descriptor(inode2)) {
		/* okay --- consider it acceptable if a default security
		 * descriptor was assigned  */
		/*ERROR("%"TS" has a security descriptor in the second image but "*/
		      /*"not in the first image!", inode_any_full_path(inode1));*/
		/*return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;*/
	}

	/* Compare streams  */
	for (unsigned i = 0; i < inode1->i_num_streams; i++) {
		const struct wim_inode_stream *strm1 = &inode1->i_streams[i];
		const struct wim_inode_stream *strm2;

		if (strm1->stream_type == STREAM_TYPE_REPARSE_POINT &&
		    !reparse_point_should_preserved)
			continue;

		if (strm1->stream_type == STREAM_TYPE_UNKNOWN)
			continue;

		/* Get the corresponding stream from the second file  */
		strm2 = inode_get_stream(inode2, strm1->stream_type, strm1->stream_name);

		if (!strm2) {
			/* Corresponding stream not found  */
			if (stream_is_named(strm1) &&
			    (cmp_flags & WIMLIB_CMP_FLAG_ADS_NOT_PRESERVED))
				continue;
			ERROR("Stream of %"TS" is missing in second image; "
			      "type %d, named=%d, empty=%d",
			      inode_any_full_path(inode1),
			      strm1->stream_type,
			      stream_is_named(strm1),
			      is_zero_hash(stream_hash(strm1)));
			return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;
		}

		if (!hashes_equal(stream_hash(strm1), stream_hash(strm2))) {
			ERROR("Stream of %"TS" differs; type %d",
			      inode_any_full_path(inode1), strm1->stream_type);
			return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;
		}
	}

	return 0;

attrib_mismatch:
	ERROR("Attribute mismatch; %"TS" has attributes 0x%08"PRIx32" "
	      "in first image but attributes 0x%08"PRIx32" in second image",
	      inode_any_full_path(inode1), inode1->i_attributes,
	      inode2->i_attributes);
	return WIMLIB_ERR_IMAGES_ARE_DIFFERENT;
}

static int
cmp_images(const struct wim_image_metadata *imd1,
	   const struct wim_image_metadata *imd2, int cmp_flags)
{
	struct wim_dentry *root1 = imd1->root_dentry;
	struct wim_dentry *root2 = imd2->root_dentry;
	const struct wim_inode *inode;
	int ret;

	ret = calc_corresponding_files_recursive(root1, root2, cmp_flags);
	if (ret)
		return ret;

	/* Verify that the hard links match up between the two images.  */
	assert_inodes_sane(imd1);
	assert_inodes_sane(imd2);
	ret = for_dentry_in_tree(root1, check_hard_link, NULL);
	if (ret)
		return ret;

	/* Compare corresponding inodes.  */
	image_for_each_inode(inode, imd1) {
		ret = cmp_inodes(inode, inode->i_corresponding,
				 imd1, imd2, cmp_flags);
		if (ret)
			return ret;
	}

	return 0;
}

static int
load_image(WIMStruct *wim, int image, struct wim_image_metadata **imd_ret)
{
	int ret = select_wim_image(wim, image);
	if (!ret) {
		*imd_ret = wim_get_current_image_metadata(wim);
		mark_image_dirty(*imd_ret);
	}
	return ret;
}

WIMLIBAPI int
wimlib_compare_images(WIMStruct *wim1, int image1,
		      WIMStruct *wim2, int image2, int cmp_flags)
{
	int ret;
	struct wim_image_metadata *imd1, *imd2;

	ret = load_image(wim1, image1, &imd1);
	if (!ret)
		ret = load_image(wim2, image2, &imd2);
	if (!ret)
		ret = cmp_images(imd1, imd2, cmp_flags);
	return ret;
}

#endif /* ENABLE_TEST_SUPPORT */
