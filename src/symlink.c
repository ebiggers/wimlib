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

/* UNIX version of getting and setting the data in reparse points */
#if !defined(__WIN32__)

#include <sys/stat.h>

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
static ssize_t
get_symlink_name(const void *resource, size_t resource_len, char *buf,
		 size_t buf_len, u32 reparse_tag)
{
	const void *p = resource;
	u16 substitute_name_offset;
	u16 substitute_name_len;
	u16 print_name_offset;
	u16 print_name_len;
	char *link_target;
	char *translated_target;
	size_t link_target_len;
	ssize_t ret;
	unsigned header_size;
	bool translate_slashes;

	if (resource_len < 12)
		return -EIO;
	p = get_u16(p, &substitute_name_offset);
	p = get_u16(p, &substitute_name_len);
	p = get_u16(p, &print_name_offset);
	p = get_u16(p, &print_name_len);

	wimlib_assert(reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
		      reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT);

	if (reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT)
		header_size = 8;
	else {
		header_size = 12;
		p += 4;
	}
	if (header_size + substitute_name_offset + substitute_name_len > resource_len)
		return -EIO;

	ret = utf16le_to_tstr((const utf16lechar*)(p + substitute_name_offset),
			      substitute_name_len,
			      &link_target, &link_target_len);
	if (ret)
		return -errno;

	if (link_target_len + 1 > buf_len) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	DEBUG("Interpeting substitute name \"%s\" (ReparseTag=0x%x)",
	      link_target, reparse_tag);
	translate_slashes = true;
	translated_target = link_target;
	if (link_target_len >= 7 &&
	    translated_target[0] == '\\' &&
	    translated_target[1] == '?' &&
	    translated_target[2] == '?' &&
	    translated_target[3] == '\\' &&
	    translated_target[4] != '\0' &&
	    translated_target[5] == ':' &&
	    translated_target[6] == '\\')
	{
		/* "Full" symlink or junction (\??\x:\ prefixed path) */
		translated_target += 6;
		link_target_len -= 6;
	} else if (reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT &&
		   link_target_len >= 12 &&
		   memcmp(translated_target, "\\\\?\\Volume{", 11) == 0 &&
		   translated_target[link_target_len - 1] == '\\')
	{
		/* Volume junction.  Can't really do anything with it. */
		translate_slashes = false;
	} else if (reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK &&
		   link_target_len >= 3 &&
		   translated_target[0] != '\0' &&
		   translated_target[1] == ':' &&
		   translated_target[2] == '/')
	{
		/* "Absolute" symlink, with drive letter */
		translated_target += 2;
		link_target_len -= 2;
	} else if (reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK &&
		   link_target_len >= 1)
	{
		if (translated_target[0] == '/')
			/* "Absolute" symlink, without drive letter */
			;
		else
			/* "Relative" symlink, without drive letter */
			;
	} else {
		ERROR("Invalid reparse point: \"%s\"", translated_target);
		ret = -EIO;
		goto out;
	}

	if (translate_slashes)
		for (size_t i = 0; i < link_target_len; i++)
			if (translated_target[i] == '\\')
				translated_target[i] = '/';
	memcpy(buf, translated_target, link_target_len + 1);
	ret = link_target_len;
out:
	FREE(link_target);
	return ret;
}

static int
make_symlink_reparse_data_buf(const char *symlink_target,
			      size_t *len_ret, void **buf_ret)
{
	utf16lechar *name_utf16le;
	size_t name_utf16le_nbytes;
	int ret;

	ret = tstr_to_utf16le(symlink_target, strlen(symlink_target),
			      &name_utf16le, &name_utf16le_nbytes);
	if (ret)
		return ret;

	for (size_t i = 0; i < name_utf16le_nbytes / 2; i++)
		if (name_utf16le[i] == cpu_to_le16('/'))
			name_utf16le[i] = cpu_to_le16('\\');

	size_t len = 12 + (name_utf16le_nbytes + 2) * 2;
	void *buf = MALLOC(len);
	if (buf) {
		void *p = buf;
		p = put_u16(p, 0); /* Substitute name offset */
		p = put_u16(p, name_utf16le_nbytes); /* Substitute name length */
		p = put_u16(p, name_utf16le_nbytes + 2); /* Print name offset */
		p = put_u16(p, name_utf16le_nbytes); /* Print name length */
		p = put_u32(p, 1); /* flags: 0 if relative link, otherwise 1 */
		p = put_bytes(p, name_utf16le_nbytes, name_utf16le);
		p = put_u16(p, 0);
		p = put_bytes(p, name_utf16le_nbytes, name_utf16le);
		p = put_u16(p, 0);
		*len_ret = len;
		*buf_ret = buf;
		ret = 0;
	} else {
		ret = WIMLIB_ERR_NOMEM;
	}
	FREE(name_utf16le);
	return ret;
}

/* Get the symlink target from a WIM inode.
 *
 * The inode may be either a "real" symlink (reparse tag
 * WIM_IO_REPARSE_TAG_SYMLINK), or it may be a junction point (reparse tag
 * WIM_IO_REPARSE_TAG_MOUNT_POINT).
 */
ssize_t
inode_readlink(const struct wim_inode *inode, char *buf, size_t buf_len,
	       const WIMStruct *w, bool threadsafe)
{
	const struct wim_lookup_table_entry *lte;
	int ret;

	wimlib_assert(inode_is_symlink(inode));

	lte = inode_unnamed_lte(inode, w->lookup_table);
	if (!lte)
		return -EIO;

	if (wim_resource_size(lte) > REPARSE_POINT_MAX_SIZE)
		return -EIO;

	u8 res_buf[wim_resource_size(lte)];
	ret = read_full_resource_into_buf(lte, res_buf, threadsafe);
	if (ret)
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
int
inode_set_symlink(struct wim_inode *inode,
		  const char *target,
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
	if (ret)
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

static int
unix_get_ino_and_dev(const char *path, u64 *ino_ret, u64 *dev_ret)
{
	struct stat stbuf;
	if (stat(path, &stbuf)) {
		WARNING_WITH_ERRNO("Failed to stat \"%s\"", path);
		/* Treat as a link pointing outside the capture root (it
		 * most likely is). */
		return WIMLIB_ERR_STAT;
	} else {
		*ino_ret = stbuf.st_ino;
		*dev_ret = stbuf.st_dev;
		return 0;
	}
}

#endif /* !defined(__WIN32__) */

#ifdef __WIN32__
#  include "win32.h"
#  define RP_PATH_SEPARATOR L'\\'
#  define os_get_ino_and_dev win32_get_file_and_vol_ids
#else
#  define RP_PATH_SEPARATOR '/'
#  define os_get_ino_and_dev unix_get_ino_and_dev
#endif

/* Fix up reparse points--- mostly shared between UNIX and Windows */
tchar *
fixup_symlink(tchar *dest, u64 capture_root_ino, u64 capture_root_dev)
{
	tchar *p = dest;

#ifdef __WIN32__
	/* Skip over drive letter */
	if (*p != RP_PATH_SEPARATOR)
		p += 2;
#endif

	DEBUG("Fixing symlink or junction \"%"TS"\"", dest);
	for (;;) {
		tchar save;
		int ret;
		u64 ino;
		u64 dev;

		while (*p == RP_PATH_SEPARATOR)
			p++;

		save = *p;
		*p = T('\0');
		ret = os_get_ino_and_dev(dest, &ino, &dev);
		*p = save;

		if (ino == capture_root_ino && dev == capture_root_dev) {
			/* Link points inside capture root.  Return abbreviated
			 * path. */
			if (*p == T('\0'))
				*(p - 1) = RP_PATH_SEPARATOR;
			while (p - 1 >= dest && *(p - 1) == RP_PATH_SEPARATOR)
				p--;
		#ifdef __WIN32__
			/* Add back drive letter */
			if (*dest != RP_PATH_SEPARATOR) {
				*--p = *(dest + 1);
				*--p = *dest;
			}
		#endif
			wimlib_assert(p >= dest);
			return p;
		}

		if (*p == T('\0')) {
			/* Link points outside capture root. */
			return NULL;
		}

		do {
			p++;
		} while (*p != RP_PATH_SEPARATOR && *p != T('\0'));
	}
}

