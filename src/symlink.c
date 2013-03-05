/*
 * symlink.c
 *
 * Code to read and set symbolic links in WIM files.
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

#include "dentry.h"
#include "buffer_io.h"
#include "lookup_table.h"
#include "sha1.h"
#include <errno.h>

/*
 * Find the symlink target of a symbolic link or junction point in the WIM.
 *
 * See http://msdn.microsoft.com/en-us/library/cc232006(v=prot.10).aspx for a
 * description of the format of the so-called "reparse point data buffers".
 *
 * But, in the WIM format, the first 8 bytes of the reparse point data buffer
 * are omitted, presumably because we already know the reparse tag from the
 * dentry, and we already know the reparse tag length from the lookup table
 * entry resource length.
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

	if (reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT) {
		header_size = 8;
	} else {
		is_absolute = (flags & 1) ? false : true;
		header_size = 12;
		p += 4;
	}
	if (header_size + substitute_name_offset + substitute_name_len > resource_len)
		return -EIO;

	ret = utf16_to_utf8((const char *)p + substitute_name_offset,
			    substitute_name_len,
			    &link_target, &link_target_len);
	if (ret == WIMLIB_ERR_INVALID_UTF16_STRING)
		return -EILSEQ;
	else if (ret == WIMLIB_ERR_NOMEM)
		return -ENOMEM;

	wimlib_assert(ret == 0);

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

static int make_symlink_reparse_data_buf(const char *symlink_target,
					 size_t *len_ret, void **buf_ret)
{
	size_t utf8_len = strlen(symlink_target);
	char *name_utf16;
	size_t utf16_len;
	int ret;

	ret = utf8_to_utf16(symlink_target, utf8_len,
			    &name_utf16, &utf16_len);
	if (ret != 0)
		return ret;

	for (size_t i = 0; i < utf16_len / 2; i++)
		if (((u16*)name_utf16)[i] == cpu_to_le16('/'))
			((u16*)name_utf16)[i] = cpu_to_le16('\\');
	size_t len = 12 + utf16_len * 2;
	void *buf = MALLOC(len);
	if (buf) {
		u8 *p = buf;
		p = put_u16(p, utf16_len); /* Substitute name offset */
		p = put_u16(p, utf16_len); /* Substitute name length */
		p = put_u16(p, 0); /* Print name offset */
		p = put_u16(p, utf16_len); /* Print name length */
		p = put_u32(p, 1); /* flags: 0 iff *full* target, including drive letter??? */
		p = put_bytes(p, utf16_len, (const u8*)name_utf16);
		p = put_bytes(p, utf16_len, (const u8*)name_utf16);
		*len_ret = len;
		*buf_ret = buf;
		ret = 0;
	} else {
		ret = WIMLIB_ERR_NOMEM;
	}
	FREE(name_utf16);
	return ret;
}

/* Get the symlink target from a WIM inode.
 *
 * The inode may be either a "real" symlink (reparse tag
 * WIM_IO_REPARSE_TAG_SYMLINK), or it may be a junction point (reparse tag
 * WIM_IO_REPARSE_TAG_MOUNT_POINT).
 */
ssize_t inode_readlink(const struct wim_inode *inode, char *buf, size_t buf_len,
		       const WIMStruct *w, int read_resource_flags)
{
	const struct wim_lookup_table_entry *lte;
	int ret;

	wimlib_assert(inode_is_symlink(inode));

	lte = inode_unnamed_lte(inode, w->lookup_table);
	if (!lte)
		return -EIO;

	if (wim_resource_size(lte) > 10000)
		return -EIO;

	u8 res_buf[wim_resource_size(lte)];
	ret = read_full_wim_resource(lte, res_buf, read_resource_flags);
	if (ret != 0)
		return -EIO;
	return get_symlink_name(res_buf, wim_resource_size(lte), buf,
				buf_len, inode->i_reparse_tag);
}

/*
 * Sets @inode to be a symbolic link pointing to @target.
 *
 * A lookup table entry for the symbolic link data buffer is created and
 * inserted into @lookup_table, unless there is an existing lookup table entry
 * for the exact same data, in which its reference count is incremented.
 *
 * The lookup table entry is returned in @lte_ret.
 *
 * On failure @dentry and @lookup_table are not modified.
 */
int inode_set_symlink(struct wim_inode *inode, const char *target,
		      struct wim_lookup_table *lookup_table,
		      struct wim_lookup_table_entry **lte_ret)

{
	int ret;
	size_t symlink_buf_len;
	struct wim_lookup_table_entry *lte = NULL, *existing_lte;
	u8 symlink_buf_hash[SHA1_HASH_SIZE];
	void *symlink_buf;

	ret = make_symlink_reparse_data_buf(target, &symlink_buf_len,
					    &symlink_buf);
	if (ret != 0)
		return ret;

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
		copy_hash(lte->hash, symlink_buf_hash);
	}

	inode->i_lte = lte;
	inode->i_resolved = 1;

	DEBUG("Loaded symlink buf");

	if (existing_lte)
		lte->refcnt++;
	else
		lookup_table_insert(lookup_table, lte);
	if (lte_ret)
		*lte_ret = lte;
	return 0;
out_free_symlink_buf:
	FREE(symlink_buf);
	return ret;
}
