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

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif

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
	if (header_size +
	    substitute_name_offset + substitute_name_len > resource_len)
		return -EIO;

	ret = utf16le_to_tstr((const utf16lechar*)(p + substitute_name_offset),
			      substitute_name_len,
			      &link_target, &link_target_len);
	if (ret)
		return -errno;

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
		   translated_target[2] == '\\')
	{
		/* "Absolute" symlink, with drive letter */
		translated_target += 2;
		link_target_len -= 2;
	} else if (reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK &&
		   link_target_len >= 1)
	{
		if (translated_target[0] == '\\')
			/* "Absolute" symlink, without drive letter */
			;
		else
			/* "Relative" symlink, without drive letter */
			;
	} else {
		ERROR("Invalid reparse point substitute name: \"%s\"", translated_target);
		ret = -EIO;
		goto out;
	}

	if (translate_slashes)
		for (size_t i = 0; i < link_target_len; i++)
			if (translated_target[i] == '\\')
				translated_target[i] = '/';

	if (link_target_len > buf_len) {
		link_target_len = buf_len;
		ret = -ENAMETOOLONG;
	} else {
		ret = link_target_len;
	}
	memcpy(buf, translated_target, link_target_len);
out:
	FREE(link_target);
	return ret;
}

#define SYMBOLIC_LINK_RELATIVE 0x00000001

/* Given a UNIX symlink target, prepare the corresponding symbolic link reparse
 * data buffer. */
static int
make_symlink_reparse_data_buf(const char *symlink_target, void *rpdata,
			      size_t *rplen_ret)
{
	int ret;
	utf16lechar *name_utf16le;
	size_t name_utf16le_nbytes;
	size_t substitute_name_nbytes;
	size_t print_name_nbytes;
	static const char abs_subst_name_prefix[12] = "\\\0?\0?\0\\\0C\0:\0";
	static const char abs_print_name_prefix[4] = "C\0:\0";
	u32 flags;
	size_t rplen;
	void *p;

	ret = tstr_to_utf16le(symlink_target, strlen(symlink_target),
			      &name_utf16le, &name_utf16le_nbytes);
	if (ret)
		return ret;

	for (size_t i = 0; i < name_utf16le_nbytes / 2; i++)
		if (name_utf16le[i] == cpu_to_le16('/'))
			name_utf16le[i] = cpu_to_le16('\\');

	/* Compatability notes:
	 *
	 * On UNIX, an absolute symbolic link begins with '/'; everything else
	 * is a relative symbolic link.  (Quite simple compared to the various
	 * ways to provide Windows paths.)
	 *
	 * To change a UNIX relative symbolic link to Windows format, we only
	 * need to translate it to UTF-16LE and replace backslashes with forward
	 * slashes.  We do not make any attempt to handle filename character
	 * problems, such as a link target that itself contains backslashes on
	 * UNIX.  Then, for these relative links, we set the reparse header
	 * @flags field to SYMBOLIC_LINK_RELATIVE.
	 *
	 * For UNIX absolute symbolic links, we must set the @flags field to 0.
	 * Then, there are multiple options as to actually represent the
	 * absolute link targets:
	 *
	 * (1) An absolute path beginning with one backslash character. similar
	 * to UNIX-style, just with a different path separator.  Print name same
	 * as substitute name.
	 *
	 * (2) Absolute path beginning with drive letter followed by a
	 * backslash.  Print name same as substitute name.
	 *
	 * (3) Absolute path beginning with drive letter followed by a
	 * backslash; substitute name prefixed with \??\, otherwise same as
	 * print name.
	 *
	 * We choose option (3) here, and we just assume C: for the drive
	 * letter.  The reasoning for this is:
	 *
	 * (1) Microsoft imagex.exe has a bug where it does not attempt to do
	 * reparse point fixups for these links, even though they are valid
	 * absolute links.  (Note: in this case prefixing the substitute name
	 * with \??\ does not work; it just makes the data unable to be restored
	 * at all.)
	 * (2) Microsoft imagex.exe will fail when doing reparse point fixups
	 * for these.  It apparently contains a bug that causes it to create an
	 * invalid reparse point, which then cannot be restored.
	 * (3) This is the only option I tested for which reparse point fixups
	 * worked properly in Microsoft imagex.exe.
	 *
	 * So option (3) it is.
	 */

	substitute_name_nbytes = name_utf16le_nbytes;
	print_name_nbytes = name_utf16le_nbytes;
	if (symlink_target[0] == '/') {
		substitute_name_nbytes += sizeof(abs_subst_name_prefix);
		print_name_nbytes += sizeof(abs_print_name_prefix);
	}

	rplen = 12 + substitute_name_nbytes + print_name_nbytes +
			2 * sizeof(utf16lechar);

	if (rplen > REPARSE_POINT_MAX_SIZE) {
		ERROR("Symlink \"%s\" is too long!", symlink_target);
		return WIMLIB_ERR_LINK;
	}

	p = rpdata;

	/* Substitute name offset */
	p = put_u16(p, 0);

	/* Substitute name length */
	p = put_u16(p, substitute_name_nbytes);

	/* Print name offset */
	p = put_u16(p, substitute_name_nbytes + sizeof(utf16lechar));

	/* Print name length */
	p = put_u16(p, print_name_nbytes);

	/* Flags */
	flags = 0;
	if (symlink_target[0] != '/')
		flags |= SYMBOLIC_LINK_RELATIVE;
	p = put_u32(p, flags);

	/* Substitute name */
	if (symlink_target[0] == '/')
		p = put_bytes(p, sizeof(abs_subst_name_prefix), abs_subst_name_prefix);
	p = put_bytes(p, name_utf16le_nbytes, name_utf16le);
	p = put_u16(p, 0);

	/* Print name */
	if (symlink_target[0] == '/')
		p = put_bytes(p, sizeof(abs_print_name_prefix), abs_print_name_prefix);
	p = put_bytes(p, name_utf16le_nbytes, name_utf16le);
	p = put_u16(p, 0);

	*rplen_ret = rplen;
	ret = 0;
out_free_name_utf16le:
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
	u8 *res_buf;

	wimlib_assert(inode_is_symlink(inode));

	lte = inode_unnamed_lte(inode, w->lookup_table);
	if (!lte)
		return -EIO;

	if (wim_resource_size(lte) > REPARSE_POINT_MAX_SIZE)
		return -EIO;

	res_buf = alloca(wim_resource_size(lte));
	ret = read_full_resource_into_buf(lte, res_buf, threadsafe);
	if (ret)
		return -EIO;
	return get_symlink_name(res_buf, wim_resource_size(lte),
				buf, buf_len, inode->i_reparse_tag);
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

	/* Buffer for reparse point data */
	u8 rpdata[REPARSE_POINT_MAX_SIZE];

	/* Actual length of the reparse point data (to be calculated by
	 * make_symlink_reparse_data_buf()) */
	size_t rplen;

	DEBUG("Creating reparse point data buffer "
	      "for UNIX symlink target \"%s\"", target);

	ret = make_symlink_reparse_data_buf(target, rpdata, &rplen);
	if (ret)
		return ret;

	ret = inode_set_unnamed_stream(inode, rpdata, rplen, lookup_table);
	if (ret)
		return ret;

	if (lte_ret)
		*lte_ret = inode->i_lte;
	return 0;
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
#  define is_rp_path_separator(c) ((c) == L'\\' || (c) == L'/')
#  define os_get_ino_and_dev win32_get_file_and_vol_ids
#else
#  define RP_PATH_SEPARATOR '/'
#  define is_rp_path_separator(c) ((c) == '/')
#  define os_get_ino_and_dev unix_get_ino_and_dev
#endif

/* Fix up absolute symbolic link targets--- mostly shared between UNIX and
 * Windows */
tchar *
fixup_symlink(tchar *dest, u64 capture_root_ino, u64 capture_root_dev)
{
	tchar *p = dest;

#ifdef __WIN32__
	/* Skip over drive letter */
	if (!is_rp_path_separator(*p))
		p += 2;
#endif

	DEBUG("Fixing symlink or junction \"%"TS"\"", dest);
	for (;;) {
		tchar save;
		int ret;
		u64 ino;
		u64 dev;

		while (is_rp_path_separator(*p))
			p++;

		save = *p;
		*p = T('\0');
		ret = os_get_ino_and_dev(dest, &ino, &dev);
		*p = save;

		if (ret) /* stat() failed before we got to the capture root---
			    assume the link points outside it. */
			return NULL;

		if (ino == capture_root_ino && dev == capture_root_dev) {
			/* Link points inside capture root.  Return abbreviated
			 * path. */
			if (*p == T('\0'))
				*(p - 1) = RP_PATH_SEPARATOR;
			while (p - 1 >= dest && is_rp_path_separator(*(p - 1)))
				p--;
		#ifdef __WIN32__
			/* Add back drive letter */
			if (!is_rp_path_separator(*dest)) {
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
		} while (!is_rp_path_separator(*p) && *p != T('\0'));
	}
}
