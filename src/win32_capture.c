/*
 * win32_capture.c - Windows-specific code for capturing files into a WIM image.
 *
 * This now uses the native Windows NT API a lot and not just Win32.
 */

/*
 * Copyright (C) 2013, 2014 Eric Biggers
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

#ifdef __WIN32__

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/win32_common.h"

#include "wimlib/capture.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/paths.h"
#include "wimlib/reparse.h"

#include <errno.h>

struct winnt_scan_stats {
	unsigned long num_get_sd_access_denied;
	unsigned long num_get_sacl_priv_notheld;
	unsigned long num_long_path_warnings;
};

static inline const wchar_t *
printable_path(const wchar_t *full_path)
{
	/* Skip over \\?\ or \??\  */
	return full_path + 4;
}

/*
 * If cur_dir is not NULL, open an existing file relative to the already-open
 * directory cur_dir.
 *
 * Otherwise, open the file specified by @path, which must be a Windows NT
 * namespace path.
 */
static NTSTATUS
winnt_openat(HANDLE cur_dir, const wchar_t *path, size_t path_nchars,
	     ACCESS_MASK perms, HANDLE *h_ret)
{
	UNICODE_STRING name;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;

	name.Length = path_nchars * sizeof(wchar_t);
	name.MaximumLength = name.Length + sizeof(wchar_t);
	name.Buffer = (wchar_t *)path;

	attr.Length = sizeof(attr);
	attr.RootDirectory = cur_dir;
	attr.ObjectName = &name;
	attr.Attributes = 0;
	attr.SecurityDescriptor = NULL;
	attr.SecurityQualityOfService = NULL;

retry:
	status = (*func_NtOpenFile)(h_ret, perms, &attr, &iosb,
				    FILE_SHARE_READ |
					    FILE_SHARE_WRITE |
					    FILE_SHARE_DELETE,
				    FILE_OPEN_REPARSE_POINT |
					    FILE_OPEN_FOR_BACKUP_INTENT |
					    FILE_SYNCHRONOUS_IO_NONALERT |
					    FILE_SEQUENTIAL_ONLY);
	if (!NT_SUCCESS(status)) {
		/* Try requesting fewer permissions  */
		if (status == STATUS_ACCESS_DENIED ||
		    status == STATUS_PRIVILEGE_NOT_HELD) {
			if (perms & ACCESS_SYSTEM_SECURITY) {
				perms &= ~ACCESS_SYSTEM_SECURITY;
				goto retry;
			}
			if (perms & READ_CONTROL) {
				perms &= ~READ_CONTROL;
				goto retry;
			}
		}
	}
	return status;
}

/* Read the first @size bytes from the file, or named data stream of a file,
 * from which the stream entry @lte was created.  */
int
read_winnt_file_prefix(const struct wim_lookup_table_entry *lte, u64 size,
		       consume_data_callback_t cb, void *cb_ctx)
{
	const wchar_t *path;
	HANDLE h;
	NTSTATUS status;
	u8 buf[BUFFER_SIZE];
	u64 bytes_remaining;
	int ret;

	/* This is an NT namespace path.  */
	path = lte->file_on_disk;

	status = winnt_openat(NULL, path, wcslen(path),
			      FILE_READ_DATA | SYNCHRONIZE, &h);
	if (!NT_SUCCESS(status)) {
		set_errno_from_nt_status(status);
		ERROR_WITH_ERRNO("\"%ls\": Can't open for reading "
				 "(status=0x%08"PRIx32")",
				 printable_path(path), (u32)status);
		return WIMLIB_ERR_OPEN;
	}

	ret = 0;
	bytes_remaining = size;
	while (bytes_remaining) {
		IO_STATUS_BLOCK iosb;
		ULONG count;
		ULONG bytes_read;

		count = min(sizeof(buf), bytes_remaining);

		status = (*func_NtReadFile)(h, NULL, NULL, NULL,
					    &iosb, buf, count, NULL, NULL);
		if (!NT_SUCCESS(status)) {
			set_errno_from_nt_status(status);
			ERROR_WITH_ERRNO("\"%ls\": Error reading data "
					 "(status=0x%08"PRIx32")",
					 printable_path(path), (u32)status);
			ret = WIMLIB_ERR_READ;
			break;
		}

		bytes_read = iosb.Information;

		bytes_remaining -= bytes_read;
		ret = (*cb)(buf, bytes_read, cb_ctx);
		if (ret)
			break;
	}
	(*func_NtClose)(h);
	return ret;
}

struct win32_encrypted_read_ctx {
	consume_data_callback_t read_prefix_cb;
	void *read_prefix_ctx;
	int wimlib_err_code;
	u64 bytes_remaining;
};

static DWORD WINAPI
win32_encrypted_export_cb(unsigned char *data, void *_ctx, unsigned long len)
{
	struct win32_encrypted_read_ctx *ctx = _ctx;
	int ret;
	size_t bytes_to_consume = min(len, ctx->bytes_remaining);

	if (bytes_to_consume == 0)
		return ERROR_SUCCESS;

	ret = (*ctx->read_prefix_cb)(data, bytes_to_consume, ctx->read_prefix_ctx);
	if (ret) {
		ctx->wimlib_err_code = ret;
		/* Shouldn't matter what error code is returned here, as long as
		 * it isn't ERROR_SUCCESS.  */
		return ERROR_READ_FAULT;
	}
	ctx->bytes_remaining -= bytes_to_consume;
	return ERROR_SUCCESS;
}

int
read_win32_encrypted_file_prefix(const struct wim_lookup_table_entry *lte,
				 u64 size,
				 consume_data_callback_t cb, void *cb_ctx)
{
	struct win32_encrypted_read_ctx export_ctx;
	DWORD err;
	void *file_ctx;
	int ret;

	export_ctx.read_prefix_cb = cb;
	export_ctx.read_prefix_ctx = cb_ctx;
	export_ctx.wimlib_err_code = 0;
	export_ctx.bytes_remaining = size;

	err = OpenEncryptedFileRaw(lte->file_on_disk, 0, &file_ctx);
	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Failed to open encrypted file \"%ls\" "
				 "for raw read",
				 printable_path(lte->file_on_disk));
		return WIMLIB_ERR_OPEN;
	}
	err = ReadEncryptedFileRaw(win32_encrypted_export_cb,
				   &export_ctx, file_ctx);
	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Failed to read encrypted file \"%ls\"",
				 printable_path(lte->file_on_disk));
		ret = export_ctx.wimlib_err_code;
		if (ret == 0)
			ret = WIMLIB_ERR_READ;
	} else if (export_ctx.bytes_remaining != 0) {
		ERROR("Only could read %"PRIu64" of %"PRIu64" bytes from "
		      "encryted file \"%ls\"",
		      size - export_ctx.bytes_remaining, size,
		      printable_path(lte->file_on_disk));
		ret = WIMLIB_ERR_READ;
	} else {
		ret = 0;
	}
	CloseEncryptedFileRaw(file_ctx);
	return ret;
}

/*
 * Load the short name of a file into a WIM dentry.
 */
static NTSTATUS
winnt_get_short_name(HANDLE h, struct wim_dentry *dentry)
{
	/* It's not any harder to just make the NtQueryInformationFile() system
	 * call ourselves, and it saves a dumb call to FindFirstFile() which of
	 * course has to create its own handle.  */
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	u8 buf[128] _aligned_attribute(8);
	const FILE_NAME_INFORMATION *info;

	status = (*func_NtQueryInformationFile)(h, &iosb, buf, sizeof(buf),
						FileAlternateNameInformation);
	info = (const FILE_NAME_INFORMATION *)buf;
	if (NT_SUCCESS(status) && info->FileNameLength != 0) {
		dentry->short_name = utf16le_dupz(info->FileName,
						  info->FileNameLength);
		if (!dentry->short_name)
			return STATUS_NO_MEMORY;
		dentry->short_name_nbytes = info->FileNameLength;
	}
	return status;
}

/*
 * Load the security descriptor of a file into the corresponding inode, and the
 * WIM image's security descriptor set.
 */
static NTSTATUS
winnt_get_security_descriptor(HANDLE h, struct wim_inode *inode,
			      struct wim_sd_set *sd_set,
			      struct winnt_scan_stats *stats, int add_flags)
{
	SECURITY_INFORMATION requestedInformation;
	u8 _buf[4096] _aligned_attribute(8);
	u8 *buf;
	ULONG bufsize;
	ULONG len_needed;
	NTSTATUS status;

	requestedInformation = DACL_SECURITY_INFORMATION |
			       SACL_SECURITY_INFORMATION |
			       OWNER_SECURITY_INFORMATION |
			       GROUP_SECURITY_INFORMATION;
	buf = _buf;
	bufsize = sizeof(_buf);

	/*
	 * We need the file's security descriptor in
	 * SECURITY_DESCRIPTOR_RELATIVE format, and we currently have a handle
	 * opened with as many relevant permissions as possible.  At this point,
	 * on Windows there are a number of options for reading a file's
	 * security descriptor:
	 *
	 * GetFileSecurity():  This takes in a path and returns the
	 * SECURITY_DESCRIPTOR_RELATIVE.  Problem: this uses an internal handle,
	 * not ours, and the handle created internally doesn't specify
	 * FILE_FLAG_BACKUP_SEMANTICS.  Therefore there can be access denied
	 * errors on some files and directories, even when running as the
	 * Administrator.
	 *
	 * GetSecurityInfo():  This takes in a handle and returns the security
	 * descriptor split into a bunch of different parts.  This should work,
	 * but it's dumb because we have to put the security descriptor back
	 * together again.
	 *
	 * BackupRead():  This can read the security descriptor, but this is a
	 * difficult-to-use API, probably only works as the Administrator, and
	 * the format of the returned data is not well documented.
	 *
	 * NtQuerySecurityObject():  This is exactly what we need, as it takes
	 * in a handle and returns the security descriptor in
	 * SECURITY_DESCRIPTOR_RELATIVE format.  Only problem is that it's a
	 * ntdll function and therefore not officially part of the Win32 API.
	 * Oh well.
	 */
	while (!(NT_SUCCESS(status = (*func_NtQuerySecurityObject)(h,
								   requestedInformation,
								   (PSECURITY_DESCRIPTOR)buf,
								   bufsize,
								   &len_needed))))
	{
		switch (status) {
		case STATUS_BUFFER_TOO_SMALL:
			wimlib_assert(buf == _buf);
			buf = MALLOC(len_needed);
			if (!buf)
				return STATUS_NO_MEMORY;
			bufsize = len_needed;
			break;
		case STATUS_PRIVILEGE_NOT_HELD:
		case STATUS_ACCESS_DENIED:
			if (add_flags & WIMLIB_ADD_FLAG_STRICT_ACLS) {
		default:
				/* Permission denied in STRICT_ACLS mode, or
				 * unknown error.  */
				goto out_free_buf;
			}
			if (requestedInformation & SACL_SECURITY_INFORMATION) {
				/* Try again without the SACL.  */
				stats->num_get_sacl_priv_notheld++;
				requestedInformation &= ~SACL_SECURITY_INFORMATION;
				break;
			}
			/* Fake success (useful when capturing as
			 * non-Administrator).  */
			stats->num_get_sd_access_denied++;
			status = STATUS_SUCCESS;
			goto out_free_buf;
		}
	}

	/* Add the security descriptor to the WIM image, and save its ID in
	 * file's inode.  */
	inode->i_security_id = sd_set_add_sd(sd_set, buf, len_needed);
	if (unlikely(inode->i_security_id < 0))
		status = STATUS_NO_MEMORY;
out_free_buf:
	if (unlikely(buf != _buf))
		FREE(buf);
	return status;
}

static int
winnt_build_dentry_tree_recursive(struct wim_dentry **root_ret,
				  HANDLE cur_dir,
				  wchar_t *full_path,
				  size_t full_path_nchars,
				  const wchar_t *filename,
				  size_t filename_nchars,
				  struct add_image_params *params,
				  struct winnt_scan_stats *stats,
				  u32 vol_flags);

static int
winnt_recurse_directory(HANDLE h,
			wchar_t *full_path,
			size_t full_path_nchars,
			struct wim_dentry *parent,
			struct add_image_params *params,
			struct winnt_scan_stats *stats,
			u32 vol_flags)
{
	void *buf;
	const size_t bufsize = 8192;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	int ret;

	buf = MALLOC(bufsize);
	if (!buf)
		return WIMLIB_ERR_NOMEM;

	/* Using NtQueryDirectoryFile() we can re-use the same open handle,
	 * which we opened with FILE_FLAG_BACKUP_SEMANTICS.  */

	while (NT_SUCCESS(status = (*func_NtQueryDirectoryFile)(h, NULL, NULL, NULL,
								&iosb, buf, bufsize,
								FileNamesInformation,
								FALSE, NULL, FALSE)))
	{
		const FILE_NAMES_INFORMATION *info = buf;
		for (;;) {
			if (!(info->FileNameLength == 2 && info->FileName[0] == L'.') &&
			    !(info->FileNameLength == 4 && info->FileName[0] == L'.' &&
							   info->FileName[1] == L'.'))
			{
				wchar_t *p;
				struct wim_dentry *child;

				p = full_path + full_path_nchars;
				*p++ = L'\\';
				p = wmempcpy(p, info->FileName,
					     info->FileNameLength / 2);
				*p = '\0';

				ret = winnt_build_dentry_tree_recursive(
							&child,
							h,
							full_path,
							p - full_path,
							full_path + full_path_nchars + 1,
							info->FileNameLength / 2,
							params,
							stats,
							vol_flags);

				full_path[full_path_nchars] = L'\0';

				if (ret)
					goto out_free_buf;
				if (child)
					dentry_add_child(parent, child);
			}
			if (info->NextEntryOffset == 0)
				break;
			info = (const FILE_NAMES_INFORMATION *)
					((const u8 *)info + info->NextEntryOffset);
		}
	}

	if (unlikely(status != STATUS_NO_MORE_FILES)) {
		set_errno_from_nt_status(status);
		ERROR_WITH_ERRNO("\"%ls\": Can't read directory "
				 "(status=0x%08"PRIx32")",
				 printable_path(full_path), (u32)status);
		ret = WIMLIB_ERR_READ;
	}
out_free_buf:
	FREE(buf);
	return ret;
}

/* Reparse point fixup status code */
enum rp_status {
	/* Reparse point corresponded to an absolute symbolic link or junction
	 * point that pointed outside the directory tree being captured, and
	 * therefore was excluded. */
	RP_EXCLUDED       = 0x0,

	/* Reparse point was not fixed as it was either a relative symbolic
	 * link, a mount point, or something else we could not understand. */
	RP_NOT_FIXED      = 0x1,

	/* Reparse point corresponded to an absolute symbolic link or junction
	 * point that pointed inside the directory tree being captured, where
	 * the target was specified by a "full" \??\ prefixed path, and
	 * therefore was fixed to be relative to the root of the directory tree
	 * being captured. */
	RP_FIXED_FULLPATH = 0x2,

	/* Same as RP_FIXED_FULLPATH, except the absolute link target did not
	 * have the \??\ prefix.  It may have begun with a drive letter though.
	 * */
	RP_FIXED_ABSPATH  = 0x4,

	/* Either RP_FIXED_FULLPATH or RP_FIXED_ABSPATH. */
	RP_FIXED          = RP_FIXED_FULLPATH | RP_FIXED_ABSPATH,
};

/* Given the "substitute name" target of a Windows reparse point, try doing a
 * fixup where we change it to be absolute relative to the root of the directory
 * tree being captured.
 *
 * Note that this is only executed when WIMLIB_ADD_FLAG_RPFIX has been
 * set.
 *
 * @capture_root_ino and @capture_root_dev indicate the inode number and device
 * of the root of the directory tree being captured.  They are meant to identify
 * this directory (as an alternative to its actual path, which could potentially
 * be reached via multiple destinations due to other symbolic links).  This may
 * not work properly on FAT, which doesn't seem to supply proper inode numbers
 * or file IDs.  However, FAT doesn't support reparse points so this function
 * wouldn't even be called anyway.
 */
static enum rp_status
winnt_capture_maybe_rpfix_target(wchar_t *target, u16 *target_nbytes_p,
				 u64 capture_root_ino, u64 capture_root_dev,
				 u32 rptag)
{
	u16 target_nchars = *target_nbytes_p / 2;
	size_t stripped_chars;
	wchar_t *orig_target;
	int ret;

	ret = parse_substitute_name(target, *target_nbytes_p, rptag);
	if (ret < 0)
		return RP_NOT_FIXED;
	stripped_chars = ret;
	if (stripped_chars)
		stripped_chars -= 2;
	target[target_nchars] = L'\0';
	orig_target = target;
	target = capture_fixup_absolute_symlink(target + stripped_chars,
						capture_root_ino, capture_root_dev);
	if (!target)
		return RP_EXCLUDED;
	target_nchars = wcslen(target);
	wmemmove(orig_target + stripped_chars, target, target_nchars + 1);
	*target_nbytes_p = (target_nchars + stripped_chars) * sizeof(wchar_t);
	if (stripped_chars)
		return RP_FIXED_FULLPATH;
	else
		return RP_FIXED_ABSPATH;
}

/* Returns: `enum rp_status' value on success; negative WIMLIB_ERR_* value on
 * failure. */
static int
winnt_capture_try_rpfix(u8 *rpbuf, u16 *rpbuflen_p,
			u64 capture_root_ino, u64 capture_root_dev,
			const wchar_t *path, struct add_image_params *params)
{
	struct reparse_data rpdata;
	int ret;
	enum rp_status rp_status;

	ret = parse_reparse_data(rpbuf, *rpbuflen_p, &rpdata);
	if (ret)
		return -ret;

	rp_status = winnt_capture_maybe_rpfix_target(rpdata.substitute_name,
						     &rpdata.substitute_name_nbytes,
						     capture_root_ino,
						     capture_root_dev,
						     le32_to_cpu(*(le32*)rpbuf));
	if (rp_status & RP_FIXED) {
		wimlib_assert(rpdata.substitute_name_nbytes % 2 == 0);
		utf16lechar substitute_name_copy[rpdata.substitute_name_nbytes / 2];
		wmemcpy(substitute_name_copy, rpdata.substitute_name,
			rpdata.substitute_name_nbytes / 2);
		rpdata.substitute_name = substitute_name_copy;
		rpdata.print_name = substitute_name_copy;
		rpdata.print_name_nbytes = rpdata.substitute_name_nbytes;
		if (rp_status == RP_FIXED_FULLPATH) {
			/* "full path", meaning \??\ prefixed.  We should not
			 * include this prefix in the print name, as it is
			 * apparently meant for the filesystem driver only. */
			rpdata.print_name += 4;
			rpdata.print_name_nbytes -= 8;
		}
		ret = make_reparse_buffer(&rpdata, rpbuf, rpbuflen_p);
		if (ret == 0)
			ret = rp_status;
		else
			ret = -ret;
	} else {
		if (rp_status == RP_EXCLUDED) {
			/* Ignoring absolute symbolic link or junction point
			 * that points out of the tree to be captured.  */
			size_t print_name_nchars = rpdata.print_name_nbytes / 2;
			wchar_t print_name0[print_name_nchars + 1];
			print_name0[print_name_nchars] = L'\0';
			wmemcpy(print_name0, rpdata.print_name, print_name_nchars);

			params->progress.scan.cur_path = printable_path(path);
			params->progress.scan.symlink_target = print_name0;
			do_capture_progress(params,
					    WIMLIB_SCAN_DENTRY_EXCLUDED_SYMLINK,
					    NULL);
		}
		ret = rp_status;
	}
	return ret;
}

/*
 * Loads the reparse point data from a reparse point into memory, optionally
 * fixing the targets of absolute symbolic links and junction points to be
 * relative to the root of capture.
 *
 * @h:	    Open handle to the reparse point.
 * @path:   Path to the reparse point file.
 * @params: Additional parameters, including whether to do reparse point fixups
 *          or not.
 * @rpbuf:  Buffer of length at least REPARSE_POINT_MAX_SIZE bytes into which
 *          the reparse point buffer will be loaded.
 * @rpbuflen_ret:  On success, the length of the reparse point buffer in bytes
 *                 is written to this location.
 *
 * Returns:
 *	On success, returns an `enum rp_status' value that indicates if and/or
 *	how the reparse point fixup was done.
 *
 *	On failure, returns a negative value that is a negated WIMLIB_ERR_*
 *	code.
 */
static int
winnt_get_reparse_data(HANDLE h, const wchar_t *path,
		       struct add_image_params *params,
		       u8 *rpbuf, u16 *rpbuflen_ret)
{
	DWORD bytesReturned;
	u32 reparse_tag;
	int ret;
	u16 rpbuflen;

	if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT,
			     NULL, /* "Not used with this operation; set to NULL" */
			     0, /* "Not used with this operation; set to 0" */
			     rpbuf, /* "A pointer to a buffer that
						   receives the reparse point data */
			     REPARSE_POINT_MAX_SIZE, /* "The size of the output
							buffer, in bytes */
			     &bytesReturned,
			     NULL))
	{
		set_errno_from_GetLastError();
		return -WIMLIB_ERR_READ;
	}

	if (bytesReturned < 8 || bytesReturned > REPARSE_POINT_MAX_SIZE) {
		errno = EINVAL;
		return -WIMLIB_ERR_INVALID_REPARSE_DATA;
	}

	rpbuflen = bytesReturned;
	reparse_tag = le32_to_cpu(*(le32*)rpbuf);
	if (params->add_flags & WIMLIB_ADD_FLAG_RPFIX &&
	    (reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
	     reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT))
	{
		/* Try doing reparse point fixup */
		ret = winnt_capture_try_rpfix(rpbuf,
					      &rpbuflen,
					      params->capture_root_ino,
					      params->capture_root_dev,
					      path,
					      params);
	} else {
		ret = RP_NOT_FIXED;
	}
	*rpbuflen_ret = rpbuflen;
	return ret;
}

static DWORD WINAPI
win32_tally_encrypted_size_cb(unsigned char *_data, void *_size_ret,
			      unsigned long len)
{
	*(u64*)_size_ret += len;
	return ERROR_SUCCESS;
}

static int
win32_get_encrypted_file_size(const wchar_t *path, u64 *size_ret)
{
	DWORD err;
	void *file_ctx;
	int ret;

	err = OpenEncryptedFileRaw(path, 0, &file_ctx);
	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Failed to open encrypted file \"%ls\" "
				 "for raw read", printable_path(path));
		return WIMLIB_ERR_OPEN;
	}
	*size_ret = 0;
	err = ReadEncryptedFileRaw(win32_tally_encrypted_size_cb,
				   size_ret, file_ctx);
	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Failed to read raw encrypted data from "
				 "\"%ls\"", printable_path(path));
		ret = WIMLIB_ERR_READ;
	} else {
		ret = 0;
	}
	CloseEncryptedFileRaw(file_ctx);
	return ret;
}

static bool
get_data_stream_name(const wchar_t *raw_stream_name, size_t raw_stream_name_nchars,
		     const wchar_t **stream_name_ret, size_t *stream_name_nchars_ret)
{
	const wchar_t *sep, *type, *end;

	/* The stream name should be returned as :NAME:TYPE  */
	if (raw_stream_name_nchars < 1)
		return false;
	if (raw_stream_name[0] != L':')
		return false;

	raw_stream_name++;
	raw_stream_name_nchars--;

	end = raw_stream_name + raw_stream_name_nchars;

	sep = wmemchr(raw_stream_name, L':', raw_stream_name_nchars);
	if (!sep)
		return false;

	type = sep + 1;
	if (end - type != 5)
		return false;

	if (wmemcmp(type, L"$DATA", 5))
		return false;

	*stream_name_ret = raw_stream_name;
	*stream_name_nchars_ret = sep - raw_stream_name;
	return true;
}

static wchar_t *
build_stream_path(const wchar_t *path, size_t path_nchars,
		  const wchar_t *stream_name, size_t stream_name_nchars)
{
	size_t stream_path_nchars;
	wchar_t *stream_path;
	wchar_t *p;

	stream_path_nchars = path_nchars;
	if (stream_name_nchars)
		stream_path_nchars += 1 + stream_name_nchars;

	stream_path = MALLOC((stream_path_nchars + 1) * sizeof(wchar_t));
	if (stream_path) {
		p = wmempcpy(stream_path, path, path_nchars);
		if (stream_name_nchars) {
			*p++ = L':';
			p = wmempcpy(p, stream_name, stream_name_nchars);
		}
		*p++ = L'\0';
	}
	return stream_path;
}

static int
winnt_scan_stream(const wchar_t *path, size_t path_nchars,
		  const wchar_t *raw_stream_name, size_t raw_stream_name_nchars,
		  u64 stream_size,
		  struct wim_inode *inode, struct list_head *unhashed_streams)
{
	const wchar_t *stream_name;
	size_t stream_name_nchars;
	struct wim_ads_entry *ads_entry;
	wchar_t *stream_path;
	struct wim_lookup_table_entry *lte;
	u32 stream_id;

	/* Given the raw stream name (which is something like
	 * :streamname:$DATA), extract just the stream name part.
	 * Ignore any non-$DATA streams.  */
	if (!get_data_stream_name(raw_stream_name, raw_stream_name_nchars,
				  &stream_name, &stream_name_nchars))
		return 0;

	/* If this is a named stream, allocate an ADS entry for it.  */
	if (stream_name_nchars) {
		ads_entry = inode_add_ads_utf16le(inode, stream_name,
						  stream_name_nchars *
							sizeof(wchar_t));
		if (!ads_entry)
			return WIMLIB_ERR_NOMEM;
	} else {
		ads_entry = NULL;
	}

	/* If the stream is empty, no lookup table entry is needed. */
	if (stream_size == 0)
		return 0;

	/* Build the path to the stream.  For unnamed streams, this is simply
	 * the path to the file.  For named streams, this is the path to the
	 * file, followed by a colon, followed by the stream name.  */
	stream_path = build_stream_path(path, path_nchars,
					stream_name, stream_name_nchars);
	if (!stream_path)
		return WIMLIB_ERR_NOMEM;

	/* Set up the lookup table entry for the stream.  */
	lte = new_lookup_table_entry();
	if (!lte) {
		FREE(stream_path);
		return WIMLIB_ERR_NOMEM;
	}
	lte->file_on_disk = stream_path;
	lte->resource_location = RESOURCE_IN_WINNT_FILE_ON_DISK;
	lte->size = stream_size;
	if ((inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED) && !ads_entry) {
		/* Special case for encrypted file.  */

		/* OpenEncryptedFileRaw() expects Win32 name, not NT name.
		 * Change \??\ into \\?\  */
		lte->file_on_disk[1] = L'\\';
		wimlib_assert(!wmemcmp(lte->file_on_disk, L"\\\\?\\", 4));

		u64 encrypted_size;
		int ret;

		ret = win32_get_encrypted_file_size(lte->file_on_disk,
						    &encrypted_size);
		if (ret) {
			free_lookup_table_entry(lte);
			return ret;
		}
		lte->size = encrypted_size;
		lte->resource_location = RESOURCE_WIN32_ENCRYPTED;
	}

	if (ads_entry) {
		stream_id = ads_entry->stream_id;
		ads_entry->lte = lte;
	} else {
		stream_id = 0;
		inode->i_lte = lte;
	}
	add_unhashed_stream(lte, inode, stream_id, unhashed_streams);
	return 0;
}

/*
 * Load information about the streams of an open file into a WIM inode.
 *
 * We use the NtQueryInformationFile() system call instead of FindFirstStream()
 * and FindNextStream().  This is done for two reasons:
 *
 * - FindFirstStream() opens its own handle to the file or directory and
 *   apparently does so without specifying FILE_FLAG_BACKUP_SEMANTICS, thereby
 *   causing access denied errors on certain files (even when running as the
 *   Administrator).
 * - FindFirstStream() and FindNextStream() is only available on Windows Vista
 *   and later, whereas the stream support in NtQueryInformationFile() was
 *   already present in Windows XP.
 */
static int
winnt_scan_streams(HANDLE *hFile_p, const wchar_t *path, size_t path_nchars,
		   struct wim_inode *inode, struct list_head *unhashed_streams,
		   u64 file_size, u32 vol_flags)
{
	int ret;
	u8 _buf[1024] _aligned_attribute(8);
	u8 *buf;
	size_t bufsize;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	const FILE_STREAM_INFORMATION *info;

	buf = _buf;
	bufsize = sizeof(_buf);

	if (!(vol_flags & FILE_NAMED_STREAMS))
		goto unnamed_only;

	/* Get a buffer containing the stream information.  */
	while (!NT_SUCCESS(status = (*func_NtQueryInformationFile)(*hFile_p,
								   &iosb,
								   buf,
								   bufsize,
								   FileStreamInformation)))
	{

		switch (status) {
		case STATUS_BUFFER_OVERFLOW:
			{
				u8 *newbuf;

				bufsize *= 2;
				if (buf == _buf)
					newbuf = MALLOC(bufsize);
				else
					newbuf = REALLOC(buf, bufsize);
				if (!newbuf) {
					ret = WIMLIB_ERR_NOMEM;
					goto out_free_buf;
				}
				buf = newbuf;
			}
			break;
		case STATUS_NOT_IMPLEMENTED:
		case STATUS_NOT_SUPPORTED:
		case STATUS_INVALID_INFO_CLASS:
			goto unnamed_only;
		default:
			set_errno_from_nt_status(status);
			ERROR_WITH_ERRNO("\"%ls\": Failed to query stream "
					 "information (status=0x%08"PRIx32")",
					 printable_path(path), (u32)status);
			ret = WIMLIB_ERR_READ;
			goto out_free_buf;
		}
	}

	if (iosb.Information == 0) {
		/* No stream information.  */
		ret = 0;
		goto out_free_buf;
	}

	if (unlikely(inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED)) {
		/* OpenEncryptedFileRaw() seems to fail with
		 * ERROR_SHARING_VIOLATION if there are any handles opened to
		 * the file.  */
		(*func_NtClose)(*hFile_p);
		*hFile_p = INVALID_HANDLE_VALUE;
	}

	/* Parse one or more stream information structures.  */
	info = (const FILE_STREAM_INFORMATION *)buf;
	for (;;) {
		/* Load the stream information.  */
		ret = winnt_scan_stream(path, path_nchars,
					info->StreamName,
					info->StreamNameLength / 2,
					info->StreamSize.QuadPart,
					inode, unhashed_streams);
		if (ret)
			goto out_free_buf;

		if (info->NextEntryOffset == 0) {
			/* No more stream information.  */
			break;
		}
		/* Advance to next stream information.  */
		info = (const FILE_STREAM_INFORMATION *)
				((const u8 *)info + info->NextEntryOffset);
	}
	ret = 0;
	goto out_free_buf;

unnamed_only:
	/* The volume does not support named streams.  Only capture the unnamed
	 * data stream.  */
	if (inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
				   FILE_ATTRIBUTE_REPARSE_POINT))
	{
		ret = 0;
		goto out_free_buf;
	}

	ret = winnt_scan_stream(path, path_nchars, L"::$DATA", 7,
				file_size, inode, unhashed_streams);
out_free_buf:
	/* Free buffer if allocated on heap.  */
	if (unlikely(buf != _buf))
		FREE(buf);
	return ret;
}

static int
winnt_build_dentry_tree_recursive(struct wim_dentry **root_ret,
				  HANDLE cur_dir,
				  wchar_t *full_path,
				  size_t full_path_nchars,
				  const wchar_t *filename,
				  size_t filename_nchars,
				  struct add_image_params *params,
				  struct winnt_scan_stats *stats,
				  u32 vol_flags)
{
	struct wim_dentry *root = NULL;
	struct wim_inode *inode = NULL;
	HANDLE h = INVALID_HANDLE_VALUE;
	int ret;
	NTSTATUS status;
	FILE_ALL_INFORMATION file_info;
	u8 *rpbuf;
	u16 rpbuflen;
	u16 not_rpfixed;

	if (should_exclude_path(full_path + params->capture_root_nchars,
				full_path_nchars - params->capture_root_nchars,
				params->config))
	{
		ret = 0;
		goto out_progress;
	}

	/* Open the file.  */
	status = winnt_openat(cur_dir,
			      (cur_dir ? filename : full_path),
			      (cur_dir ? filename_nchars : full_path_nchars),
			      FILE_READ_DATA |
					FILE_READ_ATTRIBUTES |
					READ_CONTROL |
					ACCESS_SYSTEM_SECURITY |
					SYNCHRONIZE,
			      &h);
	if (unlikely(!NT_SUCCESS(status))) {
		set_errno_from_nt_status(status);
		ERROR_WITH_ERRNO("\"%ls\": Can't open file "
				 "(status=0x%08"PRIx32")",
				 printable_path(full_path), (u32)status);
		ret = WIMLIB_ERR_OPEN;
		goto out;
	}

	/* Get information about the file.  */
	{
		IO_STATUS_BLOCK iosb;

		status = (*func_NtQueryInformationFile)(h, &iosb,
							&file_info,
							sizeof(file_info),
							FileAllInformation);

		if (unlikely(!NT_SUCCESS(status) &&
			     status != STATUS_BUFFER_OVERFLOW))
		{
			set_errno_from_nt_status(status);
			ERROR_WITH_ERRNO("\"%ls\": Can't get file information "
					 "(status=0x%08"PRIx32")",
					 printable_path(full_path), (u32)status);
			ret = WIMLIB_ERR_STAT;
			goto out;
		}
	}

	if (unlikely(!cur_dir)) {

		/* Root of tree being captured; get volume information.  */

		FILE_FS_ATTRIBUTE_INFORMATION attr_info;
		FILE_FS_VOLUME_INFORMATION vol_info;
		IO_STATUS_BLOCK iosb;

		/* Get volume flags  */
		status = (*func_NtQueryVolumeInformationFile)(h, &iosb,
							      &attr_info,
							      sizeof(attr_info),
							      FileFsAttributeInformation);
		if (likely((NT_SUCCESS(status) ||
			    (status == STATUS_BUFFER_OVERFLOW)) &&
			   (iosb.Information >=
				offsetof(FILE_FS_ATTRIBUTE_INFORMATION,
					 FileSystemAttributes) +
				sizeof(attr_info.FileSystemAttributes))))
		{
			vol_flags = attr_info.FileSystemAttributes;
		} else {
			set_errno_from_nt_status(status);
			WARNING_WITH_ERRNO("\"%ls\": Can't get volume attributes "
					   "(status=0x%"PRIx32")",
					   printable_path(full_path),
					   (u32)status);
			vol_flags = 0;
		}

		/* Set inode number of root directory  */
		params->capture_root_ino =
			file_info.InternalInformation.IndexNumber.QuadPart;

		/* Get volume ID.  */
		status = (*func_NtQueryVolumeInformationFile)(h, &iosb,
							      &vol_info,
							      sizeof(vol_info),
							      FileFsVolumeInformation);
		if (likely((NT_SUCCESS(status) ||
			    (status == STATUS_BUFFER_OVERFLOW)) &&
			   (iosb.Information >=
				offsetof(FILE_FS_VOLUME_INFORMATION,
					 VolumeSerialNumber) +
				sizeof(vol_info.VolumeSerialNumber))))
		{
			params->capture_root_dev = vol_info.VolumeSerialNumber;
		} else {
			set_errno_from_nt_status(status);
			WARNING_WITH_ERRNO("\"%ls\": Can't get volume ID "
					   "(status=0x%08"PRIx32")",
					   printable_path(full_path),
					   (u32)status);
			params->capture_root_dev = 0;
		}
	}

	/* If this is a reparse point, read the reparse data.  */
	if (unlikely(file_info.BasicInformation.FileAttributes &
		     FILE_ATTRIBUTE_REPARSE_POINT))
	{
		rpbuf = alloca(REPARSE_POINT_MAX_SIZE);
		ret = winnt_get_reparse_data(h, full_path, params,
					     rpbuf, &rpbuflen);
		if (ret < 0) {
			/* WIMLIB_ERR_* (inverted) */
			ret = -ret;
			ERROR_WITH_ERRNO("\"%ls\": Can't get reparse data",
					 printable_path(full_path));
			goto out;
		} else if (ret & RP_FIXED) {
			not_rpfixed = 0;
		} else if (ret == RP_EXCLUDED) {
			ret = 0;
			goto out;
		} else {
			not_rpfixed = 1;
		}
	}

	/* Create a WIM dentry with an associated inode, which may be shared.
	 *
	 * However, we need to explicitly check for directories and files with
	 * only 1 link and refuse to hard link them.  This is because Windows
	 * has a bug where it can return duplicate File IDs for files and
	 * directories on the FAT filesystem. */
	ret = inode_table_new_dentry(params->inode_table,
				     filename,
				     file_info.InternalInformation.IndexNumber.QuadPart,
				     0, /* We don't follow mount points, so we
					   currently don't need to get the
					   volume ID / device number.  */
				     (file_info.StandardInformation.NumberOfLinks <= 1 ||
				        (file_info.BasicInformation.FileAttributes &
					 FILE_ATTRIBUTE_DIRECTORY)),
				     &root);
	if (ret)
		goto out;

	/* Get the short (DOS) name of the file.  */
	status = winnt_get_short_name(h, root);

	/* If we can't read the short filename for any reason other than
	 * out-of-memory, just ignore the error and assume the file has no short
	 * name.  This shouldn't be an issue, since the short names are
	 * essentially obsolete anyway.  */
	if (unlikely(status == STATUS_NO_MEMORY)) {
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	inode = root->d_inode;

	if (inode->i_nlink > 1) {
		/* Shared inode (hard link); skip reading per-inode information.
		 */
		ret = 0;
		goto out_progress;
	}

	inode->i_attributes = file_info.BasicInformation.FileAttributes;
	inode->i_creation_time = file_info.BasicInformation.CreationTime.QuadPart;
	inode->i_last_write_time = file_info.BasicInformation.LastWriteTime.QuadPart;
	inode->i_last_access_time = file_info.BasicInformation.LastAccessTime.QuadPart;
	inode->i_resolved = 1;

	/* Get the file's security descriptor, unless we are capturing in
	 * NO_ACLS mode or the volume does not support security descriptors.  */
	if (!(params->add_flags & WIMLIB_ADD_FLAG_NO_ACLS)
	    && (vol_flags & FILE_PERSISTENT_ACLS))
	{
		status = winnt_get_security_descriptor(h, inode,
						       params->sd_set, stats,
						       params->add_flags);
		if (!NT_SUCCESS(status)) {
			set_errno_from_nt_status(status);
			ERROR_WITH_ERRNO("\"%ls\": Can't read security "
					 "descriptor (status=0x%08"PRIu32")",
					 printable_path(full_path),
					 (u32)status);
			ret = WIMLIB_ERR_STAT;
			goto out;
		}
	}

	/* Load information about the unnamed data stream and any named data
	 * streams.  */
	ret = winnt_scan_streams(&h,
				 full_path,
				 full_path_nchars,
				 inode,
				 params->unhashed_streams,
				 file_info.StandardInformation.EndOfFile.QuadPart,
				 vol_flags);
	if (ret)
		goto out;

	if (unlikely(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {

		/* Reparse point: set the reparse data (already read).  */

		inode->i_not_rpfixed = not_rpfixed;
		inode->i_reparse_tag = le32_to_cpu(*(le32*)rpbuf);
		ret = inode_set_unnamed_stream(inode, rpbuf + 8, rpbuflen - 8,
					       params->lookup_table);
		if (ret)
			goto out;
	} else if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {

		/* Directory: recurse to children.  */

		if (unlikely(h == INVALID_HANDLE_VALUE)) {
			/* Re-open handle that was closed to read raw encrypted
			 * data.  */
			status = winnt_openat(cur_dir,
					      (cur_dir ?
					       filename : full_path),
					      (cur_dir ?
					       filename_nchars : full_path_nchars),
					      FILE_LIST_DIRECTORY | SYNCHRONIZE,
					      &h);
			if (!NT_SUCCESS(status)) {
				set_errno_from_nt_status(status);
				ERROR_WITH_ERRNO("\"%ls\": Can't re-open file "
						 "(status=0x%08"PRIx32")",
						 printable_path(full_path),
						 (u32)status);
				ret = WIMLIB_ERR_OPEN;
				goto out;
			}
		}
		ret = winnt_recurse_directory(h,
					      full_path,
					      full_path_nchars,
					      root,
					      params,
					      stats,
					      vol_flags);
		if (ret)
			goto out;
	}

out_progress:
	params->progress.scan.cur_path = printable_path(full_path);
	if (likely(root))
		do_capture_progress(params, WIMLIB_SCAN_DENTRY_OK, inode);
	else
		do_capture_progress(params, WIMLIB_SCAN_DENTRY_EXCLUDED, NULL);
out:
	if (likely(h != INVALID_HANDLE_VALUE))
		(*func_NtClose)(h);
	if (likely(ret == 0))
		*root_ret = root;
	else
		free_dentry_tree(root, params->lookup_table);
	return ret;
}

static void
winnt_do_scan_warnings(const wchar_t *path, const struct winnt_scan_stats *stats)
{
	if (likely(stats->num_get_sacl_priv_notheld == 0 &&
		   stats->num_get_sd_access_denied == 0))
		return;

	WARNING("Scan of \"%ls\" complete, but with one or more warnings:", path);
	if (stats->num_get_sacl_priv_notheld != 0) {
		WARNING("- Could not capture SACL (System Access Control List)\n"
			"            on %lu files or directories.",
			stats->num_get_sacl_priv_notheld);
	}
	if (stats->num_get_sd_access_denied != 0) {
		WARNING("- Could not capture security descriptor at all\n"
			"            on %lu files or directories.",
			stats->num_get_sd_access_denied);
	}
	WARNING("To fully capture all security descriptors, run the program\n"
		"          with Administrator rights.");
}

#define WINDOWS_NT_MAX_PATH 32768

/* Win32 version of capturing a directory tree.  */
int
win32_build_dentry_tree(struct wim_dentry **root_ret,
			const wchar_t *root_disk_path,
			struct add_image_params *params)
{
	wchar_t *path;
	DWORD dret;
	size_t path_nchars;
	int ret;
	struct winnt_scan_stats stats;

	/* WARNING: There is no check for overflow later when this buffer is
	 * being used!  But it's as long as the maximum path length understood
	 * by Windows NT (which is NOT the same as MAX_PATH).  */
	path = MALLOC((WINDOWS_NT_MAX_PATH + 1) * sizeof(wchar_t));
	if (!path)
		return WIMLIB_ERR_NOMEM;

	/* Translate into full path.  */
	dret = GetFullPathName(root_disk_path, WINDOWS_NT_MAX_PATH - 3,
			       &path[4], NULL);

	if (unlikely(dret == 0 || dret >= WINDOWS_NT_MAX_PATH - 3)) {
		ERROR("Can't get full path name for \"%ls\"", root_disk_path);
		return WIMLIB_ERR_UNSUPPORTED;
	}

	/* Add \??\ prefix to form the NT namespace path.  */
	wmemcpy(path, L"\\??\\", 4);
	path_nchars = dret + 4;

       /* Strip trailing slashes.  If we don't do this, we may create a path
	* with multiple consecutive backslashes, which for some reason causes
	* Windows to report that the file cannot be found.  */
	while (unlikely(path[path_nchars - 1] == L'\\' &&
			path[path_nchars - 2] != L':'))
		path[--path_nchars] = L'\0';

	params->capture_root_nchars = path_nchars;

	memset(&stats, 0, sizeof(stats));

	ret = winnt_build_dentry_tree_recursive(root_ret, NULL,
						path, path_nchars, L"", 0,
						params, &stats, 0);
	FREE(path);
	if (ret == 0)
		winnt_do_scan_warnings(root_disk_path, &stats);
	return ret;
}

#endif /* __WIN32__ */
