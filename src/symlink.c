/*
 * symlink.c
 *
 * Code to read and set symbolic links in WIM files.
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

#include "dentry.h"
#include "io.h"
#include "lookup_table.h"
#include "sha1.h"
#include <errno.h>

/*
 * Find the symlink target of a symbolic link or junction point in the WIM.
 *
 * See http://msdn.microsoft.com/en-us/library/cc232006(v=prot.10).aspx
 * Except the first 8 bytes aren't included in the resource (presumably because
 * we already know the reparse tag from the dentry, and we already know the
 * reparse tag len from the lookup table entry resource length).
 */
static ssize_t get_symlink_name(const u8 *resource, size_t resource_len,
			        char *buf, size_t buf_len,
			        u32 reparse_tag)
{
	const u8 *p = resource;
	u16 substitute_name_offset;
	u16 substitute_name_len;
	u16 print_name_offset;
	u16 print_name_len;
	char *link_target;
	size_t link_target_len;
	ssize_t ret;
	unsigned header_size;
	char *translated_target;
	bool is_absolute;
	u32 flags;

	if (resource_len < 12)
		return -EIO;
	p = get_u16(p, &substitute_name_offset);
	p = get_u16(p, &substitute_name_len);
	p = get_u16(p, &print_name_offset);
	p = get_u16(p, &print_name_len);
	get_u32(p, &flags);

	wimlib_assert(reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
		      reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT);

	/* I think that some junction points incorrectly get marked as symbolic
	 * links.  So, parse the link buffer as a symlink if the flags seem
	 * plausible. */
	if (flags <= 1)
		reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;

	if (reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT) {
		header_size = 8;
	} else {
		is_absolute = (flags & 1) ? false : true;
		header_size = 12;
		p += 4;
	}
	if (header_size + substitute_name_offset + substitute_name_len > resource_len)
		return -EIO;
	link_target = utf16_to_utf8((const char *)p + substitute_name_offset,
				    substitute_name_len,
				    &link_target_len);

	if (!link_target)
		return -EIO;

	if (link_target_len + 1 > buf_len) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	translated_target = link_target;
	if (reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT || is_absolute) {
		if (link_target_len < 7
		      || memcmp(translated_target, "\\??\\", 4) != 0
		      || translated_target[4] == '\0'
		      || translated_target[5] != ':'
		      || translated_target[6] != '\\') {
			ret = -EIO;
			goto out;
		}
		translated_target += 4;
		link_target_len -= 4;
		/* There's a drive letter, so just leave the backslashes since
		 * it won't go anyhwere on UNIX anyway... 
		 *
		 * XXX
		 * NTFS-3g tries to re-map these links to actually point to
		 * something, so maybe we could do something like that here
		 * XXX*/
	} else {
		for (size_t i = 0; i < link_target_len; i++)
			if (translated_target[i] == '\\')
				translated_target[i] = '/';
	}

	memcpy(buf, translated_target, link_target_len + 1);
	ret = link_target_len;
out:
	FREE(link_target);
	return ret;
}

void *make_symlink_reparse_data_buf(const char *symlink_target, size_t *len_ret)
{
	size_t utf8_len = strlen(symlink_target);
	size_t utf16_len;
	char *name_utf16 = utf8_to_utf16(symlink_target, utf8_len, &utf16_len);
	if (!name_utf16)
		return NULL;
	/*DEBUG("utf16_len = %zu", utf16_len);*/
	for (size_t i = 0; i < utf16_len / 2; i++)
		if (((u16*)name_utf16)[i] == to_le16('/'))
			((u16*)name_utf16)[i] = to_le16('\\');
	size_t len = 12 + utf16_len * 2 + 4;
	void *buf = MALLOC(len);
	if (!buf)
		goto out;
	/* XXX Fix absolute paths */

	u8 *p = buf;
	p = put_u16(p, utf16_len + 2); /* Substitute name offset */
	p = put_u16(p, utf16_len); /* Substitute name length */
	p = put_u16(p, 0); /* Print name offset */
	p = put_u16(p, utf16_len); /* Print name length */
	p = put_u32(p, 1);
	p = put_bytes(p, utf16_len, (const u8*)name_utf16);
	p = put_u16(p, 0);
	p = put_bytes(p, utf16_len, (const u8*)name_utf16);
	p = put_u16(p, 0);
	/*DEBUG("utf16_len = %zu, len = %zu", utf16_len, len);*/
	*len_ret = len;
out:
	FREE(name_utf16);
	return buf;
}

/* Get the symlink target from a dentry.
 *
 * The dentry may be either "real" symlink or a junction point.
 */
ssize_t inode_readlink(const struct inode *inode, char *buf, size_t buf_len,
		       const WIMStruct *w)
{
	const struct lookup_table_entry *lte;
	int ret;

	wimlib_assert(inode_is_symlink(inode));

	lte = inode_unnamed_lte(inode, w->lookup_table);
	if (!lte)
		return -EIO;

	if (wim_resource_size(lte) > 10000)
		return -EIO;

	u8 res_buf[wim_resource_size(lte)];
	ret = read_full_wim_resource(lte, res_buf);
	if (ret != 0)
		return -EIO;
	return get_symlink_name(res_buf, wim_resource_size(lte), buf,
				buf_len, inode->reparse_tag);
}

static int inode_set_symlink_buf(struct inode *inode,
				 struct lookup_table_entry *lte)
{
#if 0
	struct ads_entry *ads_entries;

	ads_entries = MALLOC(2, sizeof(struct ads_entry));
	if (!ads_entries)
		return WIMLIB_ERR_NOMEM;
	ads_entry_init(&ads_entries[0]);
	ads_entry_init(&ads_entries[1]);

	wimlib_assert(dentry->num_ads == 0);
	wimlib_assert(dentry->ads_entries == NULL);

	ads_entries[0].lte = lte;

	/*dentry_free_ads_entries(dentry);*/
	dentry->num_ads = 2;
	dentry->ads_entries = ads_entries;
#endif
	wimlib_assert(inode->resolved);
	inode->lte = lte;
	return 0;
}

/* 
 * Sets @dentry to be a symbolic link pointing to @target.
 *
 * A lookup table entry for the symbolic link data buffer is created and
 * inserted into @lookup_table, unless there is an existing lookup table entry
 * for the exact same data, in which its reference count is incremented.
 *
 * The lookup table entry is returned in @lte_ret.
 *
 * On failure @dentry and @lookup_table are not modified.
 */
int inode_set_symlink(struct inode *inode, const char *target,
		      struct lookup_table *lookup_table,
		      struct lookup_table_entry **lte_ret)

{
	int ret;
	size_t symlink_buf_len;
	struct lookup_table_entry *lte = NULL, *existing_lte;
	u8 symlink_buf_hash[SHA1_HASH_SIZE];
	void *symlink_buf;
	
	symlink_buf = make_symlink_reparse_data_buf(target, &symlink_buf_len);
	if (!symlink_buf)
		return WIMLIB_ERR_NOMEM;

	DEBUG("Made symlink reparse data buf (len = %zu, name len = %zu)",
			symlink_buf_len, symlink_buf_len);
	
	sha1_buffer(symlink_buf, symlink_buf_len, symlink_buf_hash);

	existing_lte = __lookup_resource(lookup_table, symlink_buf_hash);

	if (existing_lte) {
		lte = existing_lte;
		FREE(symlink_buf);
		symlink_buf = NULL;
	} else {
		DEBUG("Creating new lookup table entry for symlink buf");
		lte = new_lookup_table_entry();
		if (!lte) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_symlink_buf;
		}
		lte->resource_location            = RESOURCE_IN_ATTACHED_BUFFER;
		lte->attached_buffer              = symlink_buf;
		lte->resource_entry.original_size = symlink_buf_len;
		lte->resource_entry.size          = symlink_buf_len;
		lte->resource_entry.flags         = 0;
		copy_hash(lte->hash, symlink_buf_hash);
	}

	ret = inode_set_symlink_buf(inode, lte);

	if (ret != 0)
		goto out_free_lte;

	inode->resolved = true;

	DEBUG("Loaded symlink buf");

	if (existing_lte)
		lte->refcnt++;
	else
		lookup_table_insert(lookup_table, lte);
	if (lte_ret)
		*lte_ret = lte;
	return 0;
out_free_lte:
	if (lte != existing_lte)
		FREE(lte);
out_free_symlink_buf:
	FREE(symlink_buf);
	return ret;
}
