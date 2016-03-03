/*
 * tagged_items.c
 *
 * Support for tagged metadata items that can be appended to WIM directory
 * entries.
 */

/*
 * Copyright (C) 2014-2016 Eric Biggers
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/endianness.h"
#include "wimlib/inode.h"
#include "wimlib/object_id.h"
#include "wimlib/types.h"
#include "wimlib/unix_data.h"

/* Object ID tag; this is also used by the Microsoft implementation.  */
#define TAG_OBJECT_ID		0x00000001

/* Random number that we'll use for tagging our UNIX data items.  */
#define TAG_WIMLIB_UNIX_DATA	0x337DD873

/* Header that begins each tagged metadata item in the metadata resource  */
struct tagged_item_header {

	/* Unique identifier for this item.  */
	le32 tag;

	/* Size of the data of this tagged item, in bytes.  This excludes this
	 * header and should be a multiple of 8.  */
	le32 length;

	/* Variable length data  */
	u8 data[];
};

/* Unconfirmed: are all 64 bytes of the object ID always present?  Since NTFS-3G
 * permits shorter object IDs, we'll do the same for now.  */
#define OBJECT_ID_MIN_LENGTH	16

struct object_id_disk {
	u8 object_id[16];
	u8 birth_volume_id[16];
	u8 birth_object_id[16];
	u8 domain_id[16];
};

struct wimlib_unix_data_disk {
	le32 uid;
	le32 gid;
	le32 mode;
	le32 rdev;
};

/* Retrieves the first tagged item with the specified tag and minimum length
 * from the WIM inode.  Returns a pointer to the tagged data, which can be read
 * and/or modified in place.  Or, if no matching tagged item is found, returns
 * NULL.  */
static void *
inode_get_tagged_item(const struct wim_inode *inode,
		      u32 desired_tag, u32 min_data_len, u32 *actual_len_ret)
{
	size_t minlen_with_hdr = sizeof(struct tagged_item_header) + min_data_len;
	size_t len_remaining;
	u8 *p;

	if (!inode->i_extra)
		return NULL;

	len_remaining = inode->i_extra->size;
	p = inode->i_extra->data;

	/* Iterate through the tagged items.  */
	while (len_remaining >= minlen_with_hdr) {
		struct tagged_item_header *hdr;
		u32 tag;
		u32 len;

		hdr = (struct tagged_item_header *)p;
		tag = le32_to_cpu(hdr->tag);
		len = ALIGN(le32_to_cpu(hdr->length), 8);

		/* Length overflow?  */
		if (unlikely(len > len_remaining - sizeof(struct tagged_item_header)))
			return NULL;

		/* Matches the item we wanted?  */
		if (tag == desired_tag && len >= min_data_len) {
			if (actual_len_ret)
				*actual_len_ret = len;
			return hdr->data;
		}

		len_remaining -= sizeof(struct tagged_item_header) + len;
		p += sizeof(struct tagged_item_header) + len;
	}
	return NULL;
}

/* Adds a tagged item to a WIM inode and returns a pointer to its uninitialized
 * data, which must be initialized in-place by the caller.  */
static void *
inode_add_tagged_item(struct wim_inode *inode, u32 tag, u32 len)
{
	size_t itemsize;
	size_t newsize;
	struct wim_inode_extra *extra;
	struct tagged_item_header *hdr;

	/* We prepend the item instead of appending it because it's easier.  */

	itemsize = sizeof(struct tagged_item_header) + ALIGN(len, 8);
	newsize = itemsize;
	if (inode->i_extra)
		newsize += inode->i_extra->size;

	extra = MALLOC(sizeof(struct wim_inode_extra) + newsize);
	if (!extra)
		return NULL;
	if (inode->i_extra) {
		memcpy(&extra->data[itemsize], inode->i_extra->data,
		       inode->i_extra->size);
		FREE(inode->i_extra);
	}
	extra->size = newsize;
	inode->i_extra = extra;

	hdr = (struct tagged_item_header *)extra->data;
	hdr->tag = cpu_to_le32(tag);
	hdr->length = cpu_to_le32(len);
	return memset(hdr->data, 0, ALIGN(len, 8));
}

static inline struct wimlib_unix_data_disk *
inode_get_unix_data_disk(const struct wim_inode *inode)
{
	return inode_get_tagged_item(inode, TAG_WIMLIB_UNIX_DATA,
				     sizeof(struct wimlib_unix_data_disk),
				     NULL);
}

static inline struct wimlib_unix_data_disk *
inode_add_unix_data_disk(struct wim_inode *inode)
{
	return inode_add_tagged_item(inode, TAG_WIMLIB_UNIX_DATA,
				     sizeof(struct wimlib_unix_data_disk));
}

/* Returns %true if the specified WIM inode has UNIX data; otherwise %false.
 * This is a wimlib extension.  */
bool
inode_has_unix_data(const struct wim_inode *inode)
{
	return inode_get_unix_data_disk(inode) != NULL;
}

/* Retrieves UNIX data from the specified WIM inode.
 * This is a wimlib extension.
 *
 * Returns %true and fills @unix_data if the inode has UNIX data.
 * Otherwise returns %false.  */
bool
inode_get_unix_data(const struct wim_inode *inode,
		    struct wimlib_unix_data *unix_data)
{
	const struct wimlib_unix_data_disk *p;

	p = inode_get_unix_data_disk(inode);
	if (!p)
		return false;

	unix_data->uid = le32_to_cpu(p->uid);
	unix_data->gid = le32_to_cpu(p->gid);
	unix_data->mode = le32_to_cpu(p->mode);
	unix_data->rdev = le32_to_cpu(p->rdev);
	return true;
}

/* Sets UNIX data on the specified WIM inode.
 * This is a wimlib extension.
 *
 * Callers must specify all members in @unix_data.  If the inode does not yet
 * have UNIX data, it is given these values.  Otherwise, only the values that
 * also have the corresponding flags in @which set are changed.
 *
 * Returns %true if successful, %false if failed (out of memory).  */
bool
inode_set_unix_data(struct wim_inode *inode, struct wimlib_unix_data *unix_data,
		    int which)
{
	struct wimlib_unix_data_disk *p;

	p = inode_get_unix_data_disk(inode);
	if (!p) {
		p = inode_add_unix_data_disk(inode);
		if (!p)
			return false;
		which = UNIX_DATA_ALL;
	}
	if (which & UNIX_DATA_UID)
		p->uid = cpu_to_le32(unix_data->uid);
	if (which & UNIX_DATA_GID)
		p->gid = cpu_to_le32(unix_data->gid);
	if (which & UNIX_DATA_MODE)
		p->mode = cpu_to_le32(unix_data->mode);
	if (which & UNIX_DATA_RDEV)
		p->rdev = cpu_to_le32(unix_data->rdev);
	return true;
}

/* Return %true iff the specified inode has an object ID.  */
bool
inode_has_object_id(const struct wim_inode *inode)
{
	return inode_get_object_id(inode, NULL) != NULL;
}

/* Retrieve a pointer to the object ID of the specified inode and write its
 * length to @len_ret.  Return NULL if the inode does not have an object ID.  */
const void *
inode_get_object_id(const struct wim_inode *inode, u32 *len_ret)
{
	return inode_get_tagged_item(inode, TAG_OBJECT_ID,
				     OBJECT_ID_MIN_LENGTH, len_ret);
}

/* Set the inode's object ID to the value specified by @object_id and @len.
 * Assumes the inode didn't already have an object ID set.  Returns %true if
 * successful, %false if failed (out of memory).  */
bool
inode_set_object_id(struct wim_inode *inode, const void *object_id, u32 len)
{
	void *p;

	p = inode_add_tagged_item(inode, TAG_OBJECT_ID, len);
	if (!p)
		return false;

	memcpy(p, object_id, len);
	return true;
}
