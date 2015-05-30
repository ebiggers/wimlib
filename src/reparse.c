/*
 * reparse.c - Handle reparse data.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include <errno.h>

#include "wimlib/alloca.h"
#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/compiler.h"
#include "wimlib/endianness.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/inode.h"
#include "wimlib/reparse.h"
#include "wimlib/resource.h"

/*
 * Read the data from a symbolic link, junction, or mount point reparse point
 * buffer into a `struct reparse_data'.
 *
 * See http://msdn.microsoft.com/en-us/library/cc232006(v=prot.10).aspx for a
 * description of the format of the reparse point buffers.
 */
int
parse_reparse_data(const u8 * restrict rpbuf, u16 rpbuflen,
		   struct reparse_data * restrict rpdata)
{
	u16 substitute_name_offset;
	u16 print_name_offset;
	const struct reparse_buffer_disk *rpbuf_disk =
		(const struct reparse_buffer_disk*)rpbuf;
	const u8 *data;

	memset(rpdata, 0, sizeof(*rpdata));
	if (rpbuflen < 16)
		goto out_invalid;
	rpdata->rptag = le32_to_cpu(rpbuf_disk->rptag);
	wimlib_assert(rpdata->rptag == WIM_IO_REPARSE_TAG_SYMLINK ||
		      rpdata->rptag == WIM_IO_REPARSE_TAG_MOUNT_POINT);
	rpdata->rpdatalen = le16_to_cpu(rpbuf_disk->rpdatalen);
	rpdata->rpreserved = le16_to_cpu(rpbuf_disk->rpreserved);
	substitute_name_offset = le16_to_cpu(rpbuf_disk->symlink.substitute_name_offset);
	rpdata->substitute_name_nbytes = le16_to_cpu(rpbuf_disk->symlink.substitute_name_nbytes);
	print_name_offset = le16_to_cpu(rpbuf_disk->symlink.print_name_offset);
	rpdata->print_name_nbytes = le16_to_cpu(rpbuf_disk->symlink.print_name_nbytes);

	if ((substitute_name_offset & 1) | (print_name_offset & 1) |
	    (rpdata->substitute_name_nbytes & 1) | (rpdata->print_name_nbytes & 1))
	{
		/* Names would be unaligned... */
		goto out_invalid;
	}

	if (rpdata->rptag == WIM_IO_REPARSE_TAG_SYMLINK) {
		if (rpbuflen < 20)
			goto out_invalid;
		rpdata->rpflags = le32_to_cpu(rpbuf_disk->symlink.rpflags);
		data = rpbuf_disk->symlink.data;
	} else {
		data = rpbuf_disk->junction.data;
	}
	if ((size_t)substitute_name_offset + rpdata->substitute_name_nbytes +
	    (data - rpbuf) > rpbuflen)
		goto out_invalid;
	if ((size_t)print_name_offset + rpdata->print_name_nbytes +
	    (data - rpbuf) > rpbuflen)
		goto out_invalid;
	rpdata->substitute_name = (utf16lechar*)&data[substitute_name_offset];
	rpdata->print_name = (utf16lechar*)&data[print_name_offset];
	return 0;
out_invalid:
	ERROR("Invalid reparse data");
	return WIMLIB_ERR_INVALID_REPARSE_DATA;
}

/*
 * Create a reparse point data buffer.
 *
 * @rpdata:  Structure that contains the data we need.
 *
 * @rpbuf:     Buffer into which to write the reparse point data buffer.  Must be
 *		at least REPARSE_POINT_MAX_SIZE bytes long.
 */
int
make_reparse_buffer(const struct reparse_data * restrict rpdata,
		    u8 * restrict rpbuf,
		    u16 * restrict rpbuflen_ret)
{
	struct reparse_buffer_disk *rpbuf_disk =
		(struct reparse_buffer_disk*)rpbuf;
	u8 *data;

	if (rpdata->rptag == WIM_IO_REPARSE_TAG_SYMLINK)
		data = rpbuf_disk->symlink.data;
	else
		data = rpbuf_disk->junction.data;

	if ((data - rpbuf) + rpdata->substitute_name_nbytes +
	    rpdata->print_name_nbytes +
	    2 * sizeof(utf16lechar) > REPARSE_POINT_MAX_SIZE)
	{
		ERROR("Reparse data is too long!");
		return WIMLIB_ERR_INVALID_REPARSE_DATA;
	}

	rpbuf_disk->rptag = cpu_to_le32(rpdata->rptag);
	rpbuf_disk->rpreserved = cpu_to_le16(rpdata->rpreserved);
	rpbuf_disk->symlink.substitute_name_offset = cpu_to_le16(0);
	rpbuf_disk->symlink.substitute_name_nbytes = cpu_to_le16(rpdata->substitute_name_nbytes);
	rpbuf_disk->symlink.print_name_offset = cpu_to_le16(rpdata->substitute_name_nbytes + 2);
	rpbuf_disk->symlink.print_name_nbytes = cpu_to_le16(rpdata->print_name_nbytes);

	if (rpdata->rptag == WIM_IO_REPARSE_TAG_SYMLINK)
		rpbuf_disk->symlink.rpflags = cpu_to_le32(rpdata->rpflags);

	/* We null-terminate the substitute and print names, although this may
	 * not be strictly necessary.  Note that the byte counts should not
	 * include the null terminators. */
	data = mempcpy(data, rpdata->substitute_name, rpdata->substitute_name_nbytes);
	*(utf16lechar*)data = cpu_to_le16(0);
	data += 2;
	data = mempcpy(data, rpdata->print_name, rpdata->print_name_nbytes);
	*(utf16lechar*)data = cpu_to_le16(0);
	data += 2;
	rpbuf_disk->rpdatalen = cpu_to_le16(data - rpbuf - REPARSE_DATA_OFFSET);
	*rpbuflen_ret = data - rpbuf;
	return 0;
}

/* UNIX version of getting and setting the data in reparse points */
#ifndef __WIN32__

/*
 * Read the reparse data from a WIM inode that is a reparse point.
 *
 * @rpbuf points to a buffer at least REPARSE_POINT_MAX_SIZE bytes into which
 * the reparse point data buffer will be reconstructed.
 *
 * Note: in the WIM format, the first 8 bytes of the reparse point data buffer
 * are omitted, presumably because we already know the reparse tag from the
 * dentry, and we already know the reparse tag length from the blob length.
 * However, we reconstruct the first 8 bytes in the buffer returned by this
 * function.
 */
static int
wim_inode_get_reparse_data(const struct wim_inode * restrict inode,
			   u8 * restrict rpbuf,
			   u16 * restrict rpbuflen_ret,
			   const struct blob_descriptor *blob_override)
{
	const struct blob_descriptor *blob;
	int ret;
	struct reparse_buffer_disk *rpbuf_disk;
	u16 rpdatalen;

	wimlib_assert(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT);

	if (blob_override) {
		blob = blob_override;
	} else {
		struct wim_inode_stream *strm;

		strm = inode_get_unnamed_stream(inode, STREAM_TYPE_REPARSE_POINT);
		if (strm)
			blob = stream_blob_resolved(strm);
		else
			blob = NULL;
		if (!blob) {
			ERROR("Reparse point has no reparse data!");
			return WIMLIB_ERR_INVALID_REPARSE_DATA;
		}
	}

	if (blob->size > REPARSE_DATA_MAX_SIZE) {
		ERROR("Reparse data is too long!");
		return WIMLIB_ERR_INVALID_REPARSE_DATA;
	}
	rpdatalen = blob->size;

	/* Read the reparse data from blob  */
	ret = read_blob_into_buf(blob, rpbuf + REPARSE_DATA_OFFSET);
	if (ret)
		return ret;

	/* Reconstruct the first 8 bytes of the reparse point buffer */
	rpbuf_disk = (struct reparse_buffer_disk*)rpbuf;

	/* ReparseTag */
	rpbuf_disk->rptag = cpu_to_le32(inode->i_reparse_tag);

	/* ReparseDataLength */
	rpbuf_disk->rpdatalen = cpu_to_le16(rpdatalen);

	/* ReparseReserved
	 * XXX this could be one of the unknown fields in the WIM dentry. */
	rpbuf_disk->rpreserved = cpu_to_le16(0);

	*rpbuflen_ret = rpdatalen + REPARSE_DATA_OFFSET;
	return 0;
}

static const utf16lechar volume_junction_prefix[11] = {
	cpu_to_le16('\\'),
	cpu_to_le16('?'),
	cpu_to_le16('?'),
	cpu_to_le16('\\'),
	cpu_to_le16('V'),
	cpu_to_le16('o'),
	cpu_to_le16('l'),
	cpu_to_le16('u'),
	cpu_to_le16('m'),
	cpu_to_le16('e'),
	cpu_to_le16('{'),
};

enum {
	SUBST_NAME_IS_RELATIVE_LINK = -1,
	SUBST_NAME_IS_VOLUME_JUNCTION = -2,
	SUBST_NAME_IS_UNKNOWN = -3,
};

/* Parse the "substitute name" (link target) from a symbolic link or junction
 * reparse point.
 *
 * Return value is:
 *
 * Non-negative integer:
 *	The name is an absolute symbolic link in one of several formats,
 *	and the return value is the number of UTF-16LE characters that need to
 *	be advanced to reach a simple "absolute" path starting with a backslash
 *	(i.e. skip over \??\ and/or drive letter)
 * Negative integer:
 *	SUBST_NAME_IS_VOLUME_JUNCTION:
 *		The name is a volume junction.
 *	SUBST_NAME_IS_RELATIVE_LINK:
 *		The name is a relative symbolic link.
 *	SUBST_NAME_IS_UNKNOWN:
 *		The name does not appear to be a valid symbolic link, junction,
 *		or mount point.
 */
static int
parse_substitute_name(const utf16lechar *substitute_name,
		      u16 substitute_name_nbytes, u32 rptag)
{
	u16 substitute_name_nchars = substitute_name_nbytes / 2;

	if (substitute_name_nchars >= 7 &&
	    substitute_name[0] == cpu_to_le16('\\') &&
	    substitute_name[1] == cpu_to_le16('?') &&
	    substitute_name[2] == cpu_to_le16('?') &&
	    substitute_name[3] == cpu_to_le16('\\') &&
	    substitute_name[4] != cpu_to_le16('\0') &&
	    substitute_name[5] == cpu_to_le16(':') &&
	    substitute_name[6] == cpu_to_le16('\\'))
	{
		/* "Full" symlink or junction (\??\x:\ prefixed path) */
		return 6;
	} else if (rptag == WIM_IO_REPARSE_TAG_MOUNT_POINT &&
		   substitute_name_nchars >= 12 &&
		   memcmp(substitute_name, volume_junction_prefix,
			  sizeof(volume_junction_prefix)) == 0 &&
		   substitute_name[substitute_name_nchars - 1] == cpu_to_le16('\\'))
	{
		/* Volume junction.  Can't really do anything with it. */
		return SUBST_NAME_IS_VOLUME_JUNCTION;
	} else if (rptag == WIM_IO_REPARSE_TAG_SYMLINK &&
		   substitute_name_nchars >= 3 &&
		   substitute_name[0] != cpu_to_le16('\0') &&
		   substitute_name[1] == cpu_to_le16(':') &&
		   substitute_name[2] == cpu_to_le16('\\'))
	{
		/* "Absolute" symlink, with drive letter */
		return 2;
	} else if (rptag == WIM_IO_REPARSE_TAG_SYMLINK &&
		   substitute_name_nchars >= 1)
	{
		if (substitute_name[0] == cpu_to_le16('\\'))
			/* "Absolute" symlink, without drive letter */
			return 0;
		else
			/* "Relative" symlink, without drive letter */
			return SUBST_NAME_IS_RELATIVE_LINK;
	} else {
		return SUBST_NAME_IS_UNKNOWN;
	}
}

/*
 * Get the UNIX-style symlink target from the WIM inode for a reparse point.
 * Specifically, this translates the target from UTF-16 to the current multibyte
 * encoding, strips the drive prefix if present, and swaps backslashes and
 * forward slashes.
 *
 * @inode
 *	The inode to read the symlink from.  It must be a reparse point with
 *	tag WIM_IO_REPARSE_TAG_SYMLINK (a real symlink) or
 *	WIM_IO_REPARSE_TAG_MOUNT_POINT (a mount point or junction point).
 *
 * @buf
 *	Buffer into which to place the link target.
 *
 * @bufsize
 *	Available space in @buf, in bytes.
 *
 * @blob_override
 *	If not NULL, the blob from which to read the reparse data.  Otherwise,
 *	the reparse data will be read from the reparse point stream of @inode.
 *
 * If the entire symbolic link target was placed in the buffer, returns the
 * number of bytes written.  The resulting string is not null-terminated.  If
 * the symbolic link target was too large to be placed in the buffer, the first
 * @bufsize bytes of it are placed in the buffer and
 * -ENAMETOOLONG is returned.  Otherwise, a negative errno value indicating
 *  another error is returned.
 */
ssize_t
wim_inode_readlink(const struct wim_inode * restrict inode,
		   char * restrict buf, size_t bufsize,
		   const struct blob_descriptor *blob_override)
{
	int ret;
	struct reparse_buffer_disk rpbuf_disk _aligned_attribute(8);
	struct reparse_data rpdata;
	char *link_target;
	char *translated_target;
	size_t link_target_len;
	u16 rpbuflen;

	wimlib_assert(inode_is_symlink(inode));

	if (wim_inode_get_reparse_data(inode, (u8*)&rpbuf_disk, &rpbuflen,
				       blob_override))
		return -EIO;

	if (parse_reparse_data((const u8*)&rpbuf_disk, rpbuflen, &rpdata))
		return -EINVAL;

	ret = utf16le_to_tstr(rpdata.substitute_name,
			      rpdata.substitute_name_nbytes,
			      &link_target, &link_target_len);
	if (ret)
		return -errno;

	translated_target = link_target;
	ret = parse_substitute_name(rpdata.substitute_name,
				    rpdata.substitute_name_nbytes,
				    rpdata.rptag);
	switch (ret) {
	case SUBST_NAME_IS_RELATIVE_LINK:
		goto out_translate_slashes;
	case SUBST_NAME_IS_VOLUME_JUNCTION:
		goto out_have_link;
	case SUBST_NAME_IS_UNKNOWN:
		ERROR("Can't understand reparse point "
		      "substitute name \"%s\"", link_target);
		ret = -EIO;
		goto out_free_link_target;
	default:
		translated_target += ret;
		link_target_len -= ret;
		break;
	}

out_translate_slashes:
	for (size_t i = 0; i < link_target_len; i++) {
		if (translated_target[i] == '\\')
			translated_target[i] = '/';
		else if (translated_target[i] == '/')
			translated_target[i] = '\\';
	}
out_have_link:
	if (link_target_len > bufsize) {
		link_target_len = bufsize;
		ret = -ENAMETOOLONG;
	} else {
		ret = link_target_len;
	}
	memcpy(buf, translated_target, link_target_len);
out_free_link_target:
	FREE(link_target);
	return ret;
}

/* Given a UNIX-style symbolic link target, create a Windows-style reparse point
 * buffer and assign it to the specified inode.  */
int
wim_inode_set_symlink(struct wim_inode *inode, const char *target,
		      struct blob_table *blob_table)

{
	struct reparse_buffer_disk rpbuf_disk _aligned_attribute(8);
	struct reparse_data rpdata;
	static const char abs_subst_name_prefix[12] = "\\\0?\0?\0\\\0C\0:\0";
	static const char abs_print_name_prefix[4] = "C\0:\0";
	utf16lechar *name_utf16le;
	size_t name_utf16le_nbytes;
	int ret;
	u16 rpbuflen;

	DEBUG("Creating reparse point data buffer for UNIX "
	      "symlink target \"%s\"", target);
	memset(&rpdata, 0, sizeof(rpdata));
	ret = tstr_to_utf16le(target, strlen(target),
			      &name_utf16le, &name_utf16le_nbytes);
	if (ret)
		goto out;

	for (size_t i = 0; i < name_utf16le_nbytes / 2; i++) {
		if (name_utf16le[i] == cpu_to_le16('/'))
			name_utf16le[i] = cpu_to_le16('\\');
		else if (name_utf16le[i] == cpu_to_le16('\\'))
			name_utf16le[i] = cpu_to_le16('/');
	}

	/* Compatability notes:
	 *
	 * On UNIX, an absolute symbolic link begins with '/'; everything else
	 * is a relative symbolic link.  (Quite simple compared to the various
	 * ways to provide Windows paths.)
	 *
	 * To change a UNIX relative symbolic link to Windows format, we need to
	 * translate it to UTF-16LE, swap forward slashes and backslashes, and
	 * set 'rpflags' to SYMBOLIC_LINK_RELATIVE.
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

	rpdata.rptag = inode->i_reparse_tag;
	if (target[0] == '/') {
		rpdata.substitute_name_nbytes = name_utf16le_nbytes +
						sizeof(abs_subst_name_prefix);
		rpdata.print_name_nbytes = name_utf16le_nbytes +
					   sizeof(abs_print_name_prefix);
		rpdata.substitute_name = alloca(rpdata.substitute_name_nbytes);
		rpdata.print_name = alloca(rpdata.print_name_nbytes);
		memcpy(rpdata.substitute_name, abs_subst_name_prefix,
		       sizeof(abs_subst_name_prefix));
		memcpy(rpdata.print_name, abs_print_name_prefix,
		       sizeof(abs_print_name_prefix));
		memcpy((void*)rpdata.substitute_name + sizeof(abs_subst_name_prefix),
		       name_utf16le, name_utf16le_nbytes);
		memcpy((void*)rpdata.print_name + sizeof(abs_print_name_prefix),
		       name_utf16le, name_utf16le_nbytes);
	} else {
		rpdata.substitute_name_nbytes = name_utf16le_nbytes;
		rpdata.print_name_nbytes = name_utf16le_nbytes;
		rpdata.substitute_name = name_utf16le;
		rpdata.print_name = name_utf16le;
		rpdata.rpflags = SYMBOLIC_LINK_RELATIVE;
	}

	ret = make_reparse_buffer(&rpdata, (u8*)&rpbuf_disk, &rpbuflen);
	if (ret)
		goto out_free_name;

	ret = WIMLIB_ERR_NOMEM;
	if (!inode_add_stream_with_data(inode,
					STREAM_TYPE_REPARSE_POINT,
					NO_STREAM_NAME,
					(u8*)&rpbuf_disk + REPARSE_DATA_OFFSET,
					rpbuflen - REPARSE_DATA_OFFSET,
					blob_table))
		goto out_free_name;

	ret = 0;
out_free_name:
	FREE(name_utf16le);
out:
	return ret;
}

#endif /* !__WIN32__ */
