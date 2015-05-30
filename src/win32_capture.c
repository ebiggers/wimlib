/*
 * win32_capture.c - Windows-specific code for capturing files into a WIM image.
 *
 * This now uses the native Windows NT API a lot and not just Win32.
 */

/*
 * Copyright (C) 2013, 2014, 2015 Eric Biggers
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

#ifdef __WIN32__

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/win32_common.h"

#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/capture.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/paths.h"
#include "wimlib/reparse.h"

struct winnt_scan_stats {
	unsigned long num_get_sd_access_denied;
	unsigned long num_get_sacl_priv_notheld;
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
				    FILE_SHARE_VALID_FLAGS,
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
 * described by @blob.  */
int
read_winnt_stream_prefix(const struct blob_descriptor *blob, u64 size,
			 const struct read_blob_callbacks *cbs)
{
	const wchar_t *path;
	HANDLE h;
	NTSTATUS status;
	u8 buf[BUFFER_SIZE];
	u64 bytes_remaining;
	int ret;

	/* This is an NT namespace path.  */
	path = blob->file_on_disk;

	status = winnt_openat(NULL, path, wcslen(path),
			      FILE_READ_DATA | SYNCHRONIZE, &h);
	if (!NT_SUCCESS(status)) {
		winnt_error(status, L"\"%ls\": Can't open for reading",
			    printable_path(path));
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
			winnt_error(status, L"\"%ls\": Error reading data",
				    printable_path(path));
			ret = WIMLIB_ERR_READ;
			break;
		}

		bytes_read = iosb.Information;

		bytes_remaining -= bytes_read;
		ret = call_consume_chunk(buf, bytes_read, cbs);
		if (ret)
			break;
	}
	(*func_NtClose)(h);
	return ret;
}

struct win32_encrypted_read_ctx {
	const struct read_blob_callbacks *cbs;
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

	ret = call_consume_chunk(data, bytes_to_consume, ctx->cbs);
	if (ret) {
		ctx->wimlib_err_code = ret;
		/* It doesn't matter what error code is returned here, as long
		 * as it isn't ERROR_SUCCESS.  */
		return ERROR_READ_FAULT;
	}
	ctx->bytes_remaining -= bytes_to_consume;
	return ERROR_SUCCESS;
}

int
read_win32_encrypted_file_prefix(const struct blob_descriptor *blob,
				 u64 size,
				 const struct read_blob_callbacks *cbs)
{
	struct win32_encrypted_read_ctx export_ctx;
	DWORD err;
	void *file_ctx;
	int ret;
	DWORD flags = 0;

	if (blob->file_inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
		flags |= CREATE_FOR_DIR;

	export_ctx.cbs = cbs;
	export_ctx.wimlib_err_code = 0;
	export_ctx.bytes_remaining = size;

	err = OpenEncryptedFileRaw(blob->file_on_disk, flags, &file_ctx);
	if (err != ERROR_SUCCESS) {
		win32_error(err,
			    L"Failed to open encrypted file \"%ls\" for raw read",
			    printable_path(blob->file_on_disk));
		return WIMLIB_ERR_OPEN;
	}
	err = ReadEncryptedFileRaw(win32_encrypted_export_cb,
				   &export_ctx, file_ctx);
	if (err != ERROR_SUCCESS) {
		ret = export_ctx.wimlib_err_code;
		if (ret == 0) {
			win32_error(err,
				    L"Failed to read encrypted file \"%ls\"",
				    printable_path(blob->file_on_disk));
			ret = WIMLIB_ERR_READ;
		}
	} else if (export_ctx.bytes_remaining != 0) {
		ERROR("Only could read %"PRIu64" of %"PRIu64" bytes from "
		      "encrypted file \"%ls\"",
		      size - export_ctx.bytes_remaining, size,
		      printable_path(blob->file_on_disk));
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
 * Load the security descriptor of a file into the corresponding inode and the
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

	/*
	 * LABEL_SECURITY_INFORMATION is needed on Windows Vista and 7 because
	 * Microsoft decided to add mandatory integrity labels to the SACL but
	 * not have them returned by SACL_SECURITY_INFORMATION.
	 *
	 * BACKUP_SECURITY_INFORMATION is needed on Windows 8 because Microsoft
	 * decided to add even more stuff to the SACL and still not have it
	 * returned by SACL_SECURITY_INFORMATION; but they did remember that
	 * backup applications exist and simply want to read the stupid thing
	 * once and for all, so they added a flag to read the entire security
	 * descriptor.
	 *
	 * Older versions of Windows tolerate these new flags being passed in.
	 */
	requestedInformation = OWNER_SECURITY_INFORMATION |
			       GROUP_SECURITY_INFORMATION |
			       DACL_SECURITY_INFORMATION |
			       SACL_SECURITY_INFORMATION |
			       LABEL_SECURITY_INFORMATION |
			       BACKUP_SECURITY_INFORMATION;

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
				requestedInformation &= ~(SACL_SECURITY_INFORMATION |
							  LABEL_SECURITY_INFORMATION |
							  BACKUP_SECURITY_INFORMATION);
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
				  struct capture_params *params,
				  struct winnt_scan_stats *stats,
				  u32 vol_flags);

static int
winnt_recurse_directory(HANDLE h,
			wchar_t *full_path,
			size_t full_path_nchars,
			struct wim_dentry *parent,
			struct capture_params *params,
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
				wchar_t *filename;
				struct wim_dentry *child;

				p = full_path + full_path_nchars;
				/* Only add a backslash if we don't already have
				 * one.  This prevents a duplicate backslash
				 * from being added when the path to the capture
				 * dir had a trailing backslash.  */
				if (*(p - 1) != L'\\')
					*p++ = L'\\';
				filename = p;
				p = wmempcpy(filename, info->FileName,
					     info->FileNameLength / 2);
				*p = '\0';

				ret = winnt_build_dentry_tree_recursive(
							&child,
							h,
							full_path,
							p - full_path,
							filename,
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
		winnt_error(status, L"\"%ls\": Can't read directory",
			    printable_path(full_path));
		ret = WIMLIB_ERR_READ;
	}
out_free_buf:
	FREE(buf);
	return ret;
}

/* Reparse point fixup status code  */
enum rp_status {
	/* Reparse point will be captured literally (no fixup)  */
	RP_NOT_FIXED	= -1,

	/* Reparse point will be captured with fixup  */
	RP_FIXED	= -2,
};

static bool
file_has_ino_and_dev(HANDLE h, u64 ino, u64 dev)
{
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	FILE_INTERNAL_INFORMATION int_info;
	FILE_FS_VOLUME_INFORMATION vol_info;

	status = (*func_NtQueryInformationFile)(h, &iosb,
						&int_info, sizeof(int_info),
						FileInternalInformation);
	if (!NT_SUCCESS(status))
		return false;

	if (int_info.IndexNumber.QuadPart != ino)
		return false;

	status = (*func_NtQueryVolumeInformationFile)(h, &iosb,
						      &vol_info, sizeof(vol_info),
						      FileFsVolumeInformation);
	if (!(NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW))
		return false;

	if (iosb.Information <
	     offsetof(FILE_FS_VOLUME_INFORMATION, VolumeSerialNumber) +
	     sizeof(vol_info.VolumeSerialNumber))
		return false;

	return (vol_info.VolumeSerialNumber == dev);
}

/*
 * Given an (expected) NT namespace symbolic link or junction target @target of
 * length @target_nbytes, determine if a prefix of the target points to a file
 * identified by @capture_root_ino and @capture_root_dev.
 *
 * If yes, return a pointer to the portion of the link following this prefix.
 *
 * If no, return NULL.
 *
 * If the link target does not appear to be a valid NT namespace path, return
 * @target itself.
 */
static const wchar_t *
winnt_get_root_relative_target(const wchar_t *target, size_t target_nbytes,
			       u64 capture_root_ino, u64 capture_root_dev)
{
	UNICODE_STRING name;
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	const wchar_t *target_end;
	const wchar_t *p;

	target_end = target + (target_nbytes / sizeof(wchar_t));

	/* Empty path??? */
	if (target_end == target)
		return target;

	/* No leading slash???  */
	if (target[0] != L'\\')
		return target;

	/* UNC path???  */
	if ((target_end - target) >= 2 &&
	    target[0] == L'\\' && target[1] == L'\\')
		return target;

	attr.Length = sizeof(attr);
	attr.RootDirectory = NULL;
	attr.ObjectName = &name;
	attr.Attributes = 0;
	attr.SecurityDescriptor = NULL;
	attr.SecurityQualityOfService = NULL;

	name.Buffer = (wchar_t *)target;
	name.Length = 0;
	p = target;
	do {
		HANDLE h;
		const wchar_t *orig_p = p;

		/* Skip non-backslashes  */
		while (p != target_end && *p != L'\\')
			p++;

		/* Skip backslashes  */
		while (p != target_end && *p == L'\\')
			p++;

		/* Append path component  */
		name.Length += (p - orig_p) * sizeof(wchar_t);
		name.MaximumLength = name.Length;

		/* Try opening the file  */
		status = (*func_NtOpenFile) (&h,
					     FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
					     &attr,
					     &iosb,
					     FILE_SHARE_VALID_FLAGS,
					     FILE_OPEN_FOR_BACKUP_INTENT);

		if (NT_SUCCESS(status)) {
			/* Reset root directory  */
			if (attr.RootDirectory)
				(*func_NtClose)(attr.RootDirectory);
			attr.RootDirectory = h;
			name.Buffer = (wchar_t *)p;
			name.Length = 0;

			if (file_has_ino_and_dev(h, capture_root_ino,
						 capture_root_dev))
				goto out_close_root_dir;
		}
	} while (p != target_end);

	p = NULL;

out_close_root_dir:
	if (attr.RootDirectory)
		(*func_NtClose)(attr.RootDirectory);
	return p;
}

static int
winnt_rpfix_progress(struct capture_params *params, const wchar_t *path,
		     const struct reparse_data *rpdata, int scan_status)
{
	size_t print_name_nchars = rpdata->print_name_nbytes / sizeof(wchar_t);
	wchar_t print_name0[print_name_nchars + 1];

	wmemcpy(print_name0, rpdata->print_name, print_name_nchars);
	print_name0[print_name_nchars] = L'\0';

	params->progress.scan.cur_path = printable_path(path);
	params->progress.scan.symlink_target = print_name0;
	return do_capture_progress(params, scan_status, NULL);
}

static int
winnt_try_rpfix(u8 *rpbuf, u16 *rpbuflen_p,
		u64 capture_root_ino, u64 capture_root_dev,
		const wchar_t *path, struct capture_params *params)
{
	struct reparse_data rpdata;
	const wchar_t *rel_target;
	int ret;

	if (parse_reparse_data(rpbuf, *rpbuflen_p, &rpdata)) {
		/* Couldn't even understand the reparse data.  Don't try the
		 * fixup.  */
		return RP_NOT_FIXED;
	}

	/*
	 * Don't do reparse point fixups on relative symbolic links.
	 *
	 * On Windows, a relative symbolic link is supposed to be identifiable
	 * by having reparse tag WIM_IO_REPARSE_TAG_SYMLINK and flags
	 * SYMBOLIC_LINK_RELATIVE.  We will use this information, although this
	 * may not always do what the user expects, since drive-relative
	 * symbolic links such as "\Users\Public" have SYMBOLIC_LINK_RELATIVE
	 * set, in addition to truely relative symbolic links such as "Users" or
	 * "Users\Public".  However, WIMGAPI (as of Windows 8.1) has this same
	 * behavior.
	 *
	 * Otherwise, as far as I can tell, the targets of symbolic links that
	 * are NOT relative, as well as junctions (note: a mountpoint is the
	 * sames thing as a junction), must be NT namespace paths, for example:
	 *
	 *     - \??\e:\Users\Public
	 *     - \DosDevices\e:\Users\Public
	 *     - \Device\HardDiskVolume4\Users\Public
	 *     - \??\Volume{c47cb07c-946e-4155-b8f7-052e9cec7628}\Users\Public
	 *     - \DosDevices\Volume{c47cb07c-946e-4155-b8f7-052e9cec7628}\Users\Public
	 */
	if (rpdata.rptag == WIM_IO_REPARSE_TAG_SYMLINK &&
	    (rpdata.rpflags & SYMBOLIC_LINK_RELATIVE))
		return RP_NOT_FIXED;

	rel_target = winnt_get_root_relative_target(rpdata.substitute_name,
						    rpdata.substitute_name_nbytes,
						    capture_root_ino,
						    capture_root_dev);
	if (!rel_target) {
		/* Target points outside of the tree being captured.  Don't
		 * adjust it.  */
		ret = winnt_rpfix_progress(params, path, &rpdata,
					   WIMLIB_SCAN_DENTRY_NOT_FIXED_SYMLINK);
		if (ret)
			return ret;
		return RP_NOT_FIXED;
	}

	if (rel_target == rpdata.substitute_name) {
		/* Weird target --- keep the reparse point and don't mess with
		 * it.  */
		return RP_NOT_FIXED;
	}

	/* We have an absolute target pointing within the directory being
	 * captured. @rel_target is the suffix of the link target that is the
	 * part relative to the directory being captured.
	 *
	 * We will cut off the prefix before this part (which is the path to the
	 * directory being captured) and add a dummy prefix.  Since the process
	 * will need to be reversed when applying the image, it shouldn't matter
	 * what exactly the prefix is, as long as it looks like an absolute
	 * path.
	 */

	{
		size_t rel_target_nbytes =
			rpdata.substitute_name_nbytes - ((const u8 *)rel_target -
							 (const u8 *)rpdata.substitute_name);
		size_t rel_target_nchars = rel_target_nbytes / sizeof(wchar_t);

		wchar_t tmp[rel_target_nchars + 7];

		wmemcpy(tmp, L"\\??\\X:\\", 7);
		wmemcpy(tmp + 7, rel_target, rel_target_nchars);

		rpdata.substitute_name = tmp;
		rpdata.substitute_name_nbytes = rel_target_nbytes + (7 * sizeof(wchar_t));
		rpdata.print_name = tmp + 4;
		rpdata.print_name_nbytes = rel_target_nbytes + (3 * sizeof(wchar_t));

		if (make_reparse_buffer(&rpdata, rpbuf, rpbuflen_p))
			return RP_NOT_FIXED;
	}
	ret = winnt_rpfix_progress(params, path, &rpdata,
				   WIMLIB_SCAN_DENTRY_FIXED_SYMLINK);
	if (ret)
		return ret;
	return RP_FIXED;
}

/*
 * Loads the reparse point data from a reparse point into memory, optionally
 * fixing the targets of absolute symbolic links and junction points to be
 * relative to the root of capture.
 *
 * @h:
 *	Open handle to the reparse point file.
 * @path:
 *	Path to the reparse point file.
 * @params:
 *	Capture parameters.  add_flags, capture_root_ino, capture_root_dev,
 *	progfunc, progctx, and progress are used.
 * @rpbuf:
 *	Buffer of length at least REPARSE_POINT_MAX_SIZE bytes into which the
 *	reparse point buffer will be loaded.
 * @rpbuflen_ret:
 *	On success, the length of the reparse point buffer in bytes is written
 *	to this location.
 *
 * On success, returns a negative `enum rp_status' value.
 * On failure, returns a positive error code.
 */
static int
winnt_get_reparse_data(HANDLE h, const wchar_t *path,
		       struct capture_params *params,
		       u8 *rpbuf, u16 *rpbuflen_ret)
{
	DWORD bytes_returned;
	u32 reparse_tag;
	int ret;
	u16 rpbuflen;

	if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT,
			     NULL, 0, rpbuf, REPARSE_POINT_MAX_SIZE,
			     &bytes_returned, NULL))
	{
		win32_error(GetLastError(), L"\"%ls\": Can't get reparse data",
			    printable_path(path));
		return WIMLIB_ERR_READ;
	}

	if (unlikely(bytes_returned < REPARSE_DATA_OFFSET)) {
		ERROR("\"%ls\": Reparse point data is invalid",
		      printable_path(path));
		return WIMLIB_ERR_INVALID_REPARSE_DATA;
	}

	rpbuflen = bytes_returned;
	reparse_tag = le32_to_cpu(*(le32*)rpbuf);
	ret = RP_NOT_FIXED;
	if (params->add_flags & WIMLIB_ADD_FLAG_RPFIX &&
	    (reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
	     reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT))
	{
		ret = winnt_try_rpfix(rpbuf, &rpbuflen,
				      params->capture_root_ino,
				      params->capture_root_dev,
				      path, params);
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
win32_get_encrypted_file_size(const wchar_t *path, bool is_dir, u64 *size_ret)
{
	DWORD err;
	void *file_ctx;
	int ret;
	DWORD flags = 0;

	if (is_dir)
		flags |= CREATE_FOR_DIR;

	err = OpenEncryptedFileRaw(path, flags, &file_ctx);
	if (err != ERROR_SUCCESS) {
		win32_error(err,
			    L"Failed to open encrypted file \"%ls\" for raw read",
			    printable_path(path));
		return WIMLIB_ERR_OPEN;
	}
	*size_ret = 0;
	err = ReadEncryptedFileRaw(win32_tally_encrypted_size_cb,
				   size_ret, file_ctx);
	if (err != ERROR_SUCCESS) {
		win32_error(err,
			    L"Failed to read raw encrypted data from \"%ls\"",
			    printable_path(path));
		ret = WIMLIB_ERR_READ;
	} else {
		ret = 0;
	}
	CloseEncryptedFileRaw(file_ctx);
	return ret;
}

static int
winnt_scan_efsrpc_raw_data(struct wim_inode *inode, const wchar_t *nt_path,
			   struct list_head *unhashed_blobs)
{
	struct blob_descriptor *blob;
	struct wim_inode_stream *strm;
	int ret;

	blob = new_blob_descriptor();
	if (!blob)
		goto err_nomem;

	blob->file_on_disk = WCSDUP(nt_path);
	if (!blob->file_on_disk)
		goto err_nomem;
	blob->blob_location = BLOB_WIN32_ENCRYPTED;

	/* OpenEncryptedFileRaw() expects a Win32 name.  */
	wimlib_assert(!wmemcmp(blob->file_on_disk, L"\\??\\", 4));
	blob->file_on_disk[1] = L'\\';

	blob->file_inode = inode;

	ret = win32_get_encrypted_file_size(blob->file_on_disk,
					    (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY),
					    &blob->size);
	if (ret)
		goto err;

	/* Empty EFSRPC data does not make sense  */
	wimlib_assert(blob->size != 0);

	strm = inode_add_stream(inode, STREAM_TYPE_EFSRPC_RAW_DATA,
				NO_STREAM_NAME, blob);
	if (!strm)
		goto err_nomem;

	prepare_unhashed_blob(blob, inode, strm->stream_id, unhashed_blobs);
	return 0;

err_nomem:
	ret = WIMLIB_ERR_NOMEM;
err:
	free_blob_descriptor(blob);
	return ret;
}

static bool
get_data_stream_name(wchar_t *raw_stream_name, size_t raw_stream_name_nchars,
		     wchar_t **stream_name_ret, size_t *stream_name_nchars_ret)
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

/* Build the path to the data stream.  For unnamed streams, this is simply the
 * path to the file.  For named streams, this is the path to the file, followed
 * by a colon, followed by the stream name.  */
static wchar_t *
build_data_stream_path(const wchar_t *path, size_t path_nchars,
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
winnt_scan_data_stream(const wchar_t *path, size_t path_nchars,
		       wchar_t *raw_stream_name, size_t raw_stream_name_nchars,
		       u64 stream_size,
		       struct wim_inode *inode, struct list_head *unhashed_blobs)
{
	wchar_t *stream_name;
	size_t stream_name_nchars;
	struct blob_descriptor *blob;
	struct wim_inode_stream *strm;

	/* Given the raw stream name (which is something like
	 * :streamname:$DATA), extract just the stream name part (streamname).
	 * Ignore any non-$DATA streams.  */
	if (!get_data_stream_name(raw_stream_name, raw_stream_name_nchars,
				  &stream_name, &stream_name_nchars))
		return 0;

	stream_name[stream_name_nchars] = L'\0';

	/* If the stream is non-empty, set up a blob descriptor for it.  */
	if (stream_size != 0) {
		blob = new_blob_descriptor();
		if (!blob)
			goto err_nomem;
		blob->file_on_disk = build_data_stream_path(path,
							    path_nchars,
							    stream_name,
							    stream_name_nchars);
		if (!blob->file_on_disk)
			goto err_nomem;
		blob->blob_location = BLOB_IN_WINNT_FILE_ON_DISK;
		blob->size = stream_size;
		blob->file_inode = inode;
	} else {
		blob = NULL;
	}

	strm = inode_add_stream(inode, STREAM_TYPE_DATA, stream_name, blob);
	if (!strm)
		goto err_nomem;

	prepare_unhashed_blob(blob, inode, strm->stream_id, unhashed_blobs);
	return 0;

err_nomem:
	free_blob_descriptor(blob);
	return WIMLIB_ERR_NOMEM;
}

/*
 * Load information about the data streams of an open file into a WIM inode.
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
winnt_scan_data_streams(HANDLE h, const wchar_t *path, size_t path_nchars,
			struct wim_inode *inode, struct list_head *unhashed_blobs,
			u64 file_size, u32 vol_flags)
{
	int ret;
	u8 _buf[1024] _aligned_attribute(8);
	u8 *buf;
	size_t bufsize;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	FILE_STREAM_INFORMATION *info;

	buf = _buf;
	bufsize = sizeof(_buf);

	if (!(vol_flags & FILE_NAMED_STREAMS))
		goto unnamed_only;

	/* Get a buffer containing the stream information.  */
	while (!NT_SUCCESS(status = (*func_NtQueryInformationFile)(h,
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
			winnt_error(status,
				    L"\"%ls\": Failed to query stream information",
				    printable_path(path));
			ret = WIMLIB_ERR_READ;
			goto out_free_buf;
		}
	}

	if (iosb.Information == 0) {
		/* No stream information.  */
		ret = 0;
		goto out_free_buf;
	}

	/* Parse one or more stream information structures.  */
	info = (FILE_STREAM_INFORMATION *)buf;
	for (;;) {
		/* Load the stream information.  */
		ret = winnt_scan_data_stream(path, path_nchars,
					     info->StreamName,
					     info->StreamNameLength / 2,
					     info->StreamSize.QuadPart,
					     inode, unhashed_blobs);
		if (ret)
			goto out_free_buf;

		if (info->NextEntryOffset == 0) {
			/* No more stream information.  */
			break;
		}
		/* Advance to next stream information.  */
		info = (FILE_STREAM_INFORMATION *)
				((u8 *)info + info->NextEntryOffset);
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

	{
		wchar_t stream_name[] = L"::$DATA";
		ret = winnt_scan_data_stream(path, path_nchars, stream_name, 7,
					     file_size, inode, unhashed_blobs);
	}
out_free_buf:
	/* Free buffer if allocated on heap.  */
	if (unlikely(buf != _buf))
		FREE(buf);
	return ret;
}

static u64
get_sort_key(HANDLE h)
{
	STARTING_VCN_INPUT_BUFFER in = { .StartingVcn.QuadPart = 0 };
	RETRIEVAL_POINTERS_BUFFER out;
	DWORD bytesReturned;

	if (!DeviceIoControl(h, FSCTL_GET_RETRIEVAL_POINTERS,
			     &in, sizeof(in),
			     &out, sizeof(out),
			     &bytesReturned, NULL))
		return 0;

	if (out.ExtentCount < 1)
		return 0;

	return out.Extents[0].Lcn.QuadPart;
}

static void
set_sort_key(struct wim_inode *inode, u64 sort_key)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++) {
		struct wim_inode_stream *strm = &inode->i_streams[i];
		struct blob_descriptor *blob = stream_blob_resolved(strm);
		if (blob && (blob->blob_location == BLOB_IN_WINNT_FILE_ON_DISK ||
			     blob->blob_location == BLOB_WIN32_ENCRYPTED))
			blob->sort_key = sort_key;
	}
}

static int
winnt_build_dentry_tree_recursive(struct wim_dentry **root_ret,
				  HANDLE cur_dir,
				  wchar_t *full_path,
				  size_t full_path_nchars,
				  const wchar_t *filename,
				  size_t filename_nchars,
				  struct capture_params *params,
				  struct winnt_scan_stats *stats,
				  u32 vol_flags)
{
	struct wim_dentry *root = NULL;
	struct wim_inode *inode = NULL;
	HANDLE h = NULL;
	int ret;
	NTSTATUS status;
	FILE_ALL_INFORMATION file_info;
	ACCESS_MASK requestedPerms;
	u64 sort_key;

	ret = try_exclude(full_path, full_path_nchars, params);
	if (ret < 0) /* Excluded? */
		goto out_progress;
	if (ret > 0) /* Error? */
		goto out;

	/* Open the file.  */
	requestedPerms = FILE_READ_DATA |
			 FILE_READ_ATTRIBUTES |
			 READ_CONTROL |
			 ACCESS_SYSTEM_SECURITY |
			 SYNCHRONIZE;
retry_open:
	status = winnt_openat(cur_dir,
			      (cur_dir ? filename : full_path),
			      (cur_dir ? filename_nchars : full_path_nchars),
			      requestedPerms,
			      &h);
	if (unlikely(!NT_SUCCESS(status))) {
		if (status == STATUS_DELETE_PENDING) {
			WARNING("\"%ls\": Deletion pending; skipping file",
				printable_path(full_path));
			ret = 0;
			goto out;
		}
		if (status == STATUS_ACCESS_DENIED &&
		    (requestedPerms & FILE_READ_DATA)) {
			/* This happens on encrypted files.  */
			requestedPerms &= ~FILE_READ_DATA;
			goto retry_open;
		}

		winnt_error(status, L"\"%ls\": Can't open file",
			    printable_path(full_path));
		if (status == STATUS_FVE_LOCKED_VOLUME)
			ret = WIMLIB_ERR_FVE_LOCKED_VOLUME;
		else
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
			winnt_error(status,
				    L"\"%ls\": Can't get file information",
				    printable_path(full_path));
			ret = WIMLIB_ERR_STAT;
			goto out;
		}
	}

	if (unlikely(!(requestedPerms & FILE_READ_DATA)) &&
	    !(file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED))
	{
		ERROR("\"%ls\": Permission to read data was denied",
		      printable_path(full_path));
		ret = WIMLIB_ERR_OPEN;
		goto out;
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
			winnt_warning(status,
				      L"\"%ls\": Can't get volume attributes",
				      printable_path(full_path));
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
			winnt_warning(status, L"\"%ls\": Can't get volume ID",
				      printable_path(full_path));
			params->capture_root_dev = 0;
		}
	}

	/* Create a WIM dentry with an associated inode, which may be shared.
	 *
	 * However, we need to explicitly check for directories and files with
	 * only 1 link and refuse to hard link them.  This is because Windows
	 * has a bug where it can return duplicate File IDs for files and
	 * directories on the FAT filesystem.
	 *
	 * Since we don't follow mount points on Windows, we don't need to query
	 * the volume ID per-file.  Just once, for the root, is enough.  But we
	 * can't simply pass 0, because then there could be inode collisions
	 * among multiple calls to win32_build_dentry_tree() that are scanning
	 * files on different volumes.  */
	ret = inode_table_new_dentry(params->inode_table,
				     filename,
				     file_info.InternalInformation.IndexNumber.QuadPart,
				     params->capture_root_dev,
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
		goto out_progress;
	}

	inode->i_attributes = file_info.BasicInformation.FileAttributes;
	inode->i_creation_time = file_info.BasicInformation.CreationTime.QuadPart;
	inode->i_last_write_time = file_info.BasicInformation.LastWriteTime.QuadPart;
	inode->i_last_access_time = file_info.BasicInformation.LastAccessTime.QuadPart;

	/* Get the file's security descriptor, unless we are capturing in
	 * NO_ACLS mode or the volume does not support security descriptors.  */
	if (!(params->add_flags & WIMLIB_ADD_FLAG_NO_ACLS)
	    && (vol_flags & FILE_PERSISTENT_ACLS))
	{
		status = winnt_get_security_descriptor(h, inode,
						       params->sd_set, stats,
						       params->add_flags);
		if (!NT_SUCCESS(status)) {
			winnt_error(status,
				    L"\"%ls\": Can't read security descriptor",
				    printable_path(full_path));
			ret = WIMLIB_ERR_STAT;
			goto out;
		}
	}

	/* If this is a reparse point, load the reparse data.  */
	if (unlikely(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED) {
			/* See comment above assign_stream_types_encrypted()  */
			WARNING("Ignoring reparse data of encrypted file \"%ls\"",
				printable_path(full_path));
		} else {
			u8 rpbuf[REPARSE_POINT_MAX_SIZE] _aligned_attribute(8);
			u16 rpbuflen;

			ret = winnt_get_reparse_data(h, full_path, params,
						     rpbuf, &rpbuflen);
			switch (ret) {
			case RP_FIXED:
				inode->i_not_rpfixed = 0;
				break;
			case RP_NOT_FIXED:
				inode->i_not_rpfixed = 1;
				break;
			default:
				goto out;
			}
			inode->i_reparse_tag = le32_to_cpu(*(le32*)rpbuf);
			if (!inode_add_stream_with_data(inode,
							STREAM_TYPE_REPARSE_POINT,
							NO_STREAM_NAME,
							rpbuf + REPARSE_DATA_OFFSET,
							rpbuflen - REPARSE_DATA_OFFSET,
							params->blob_table))
			{
				ret = WIMLIB_ERR_NOMEM;
				goto out;
			}
		}
	}

	sort_key = get_sort_key(h);

	if (unlikely(inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED)) {
		/* Load information about the raw encrypted data.  This is
		 * needed for any directory or non-directory that has
		 * FILE_ATTRIBUTE_ENCRYPTED set.
		 *
		 * Note: since OpenEncryptedFileRaw() fails with
		 * ERROR_SHARING_VIOLATION if there are any open handles to the
		 * file, we have to close the file and re-open it later if
		 * needed.  */
		(*func_NtClose)(h);
		h = NULL;
		ret = winnt_scan_efsrpc_raw_data(inode, full_path,
						 params->unhashed_blobs);
		if (ret)
			goto out;
	} else {
		/*
		 * Load information about data streams (unnamed and named).
		 *
		 * Skip this step for encrypted files, since the data from
		 * ReadEncryptedFileRaw() already contains all data streams (and
		 * they do in fact all get restored by WriteEncryptedFileRaw().)
		 *
		 * Note: WIMGAPI (as of Windows 8.1) gets wrong and stores both
		 * the EFSRPC data and the named data stream(s)...!
		 */
		ret = winnt_scan_data_streams(h,
					      full_path,
					      full_path_nchars,
					      inode,
					      params->unhashed_blobs,
					      file_info.StandardInformation.EndOfFile.QuadPart,
					      vol_flags);
		if (ret)
			goto out;
	}

	set_sort_key(inode, sort_key);

	if (inode_is_directory(inode)) {

		/* Directory: recurse to children.  */

		if (unlikely(!h)) {
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
				winnt_error(status,
					    L"\"%ls\": Can't re-open file",
					    printable_path(full_path));
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
		ret = do_capture_progress(params, WIMLIB_SCAN_DENTRY_OK, inode);
	else
		ret = do_capture_progress(params, WIMLIB_SCAN_DENTRY_EXCLUDED, NULL);
out:
	if (likely(h))
		(*func_NtClose)(h);
	if (unlikely(ret)) {
		free_dentry_tree(root, params->blob_table);
		root = NULL;
		ret = report_capture_error(params, ret, full_path);
	}
	*root_ret = root;
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
			struct capture_params *params)
{
	wchar_t *path;
	int ret;
	UNICODE_STRING ntpath;
	struct winnt_scan_stats stats;
	size_t ntpath_nchars;

	/* WARNING: There is no check for overflow later when this buffer is
	 * being used!  But it's as long as the maximum path length understood
	 * by Windows NT (which is NOT the same as MAX_PATH).  */
	path = MALLOC((WINDOWS_NT_MAX_PATH + 1) * sizeof(wchar_t));
	if (!path)
		return WIMLIB_ERR_NOMEM;

	ret = win32_path_to_nt_path(root_disk_path, &ntpath);
	if (ret)
		goto out_free_path;

	if (ntpath.Length < 4 * sizeof(wchar_t) ||
	    ntpath.Length > WINDOWS_NT_MAX_PATH * sizeof(wchar_t) ||
	    wmemcmp(ntpath.Buffer, L"\\??\\", 4))
	{
		ERROR("\"%ls\": unrecognized path format", root_disk_path);
		ret = WIMLIB_ERR_INVALID_PARAM;
	} else {
		ntpath_nchars = ntpath.Length / sizeof(wchar_t);
		wmemcpy(path, ntpath.Buffer, ntpath_nchars);
		path[ntpath_nchars] = L'\0';

		params->capture_root_nchars = ntpath_nchars;
		if (path[ntpath_nchars - 1] == L'\\')
			params->capture_root_nchars--;
		ret = 0;
	}
	HeapFree(GetProcessHeap(), 0, ntpath.Buffer);
	if (ret)
		goto out_free_path;

	memset(&stats, 0, sizeof(stats));

	ret = winnt_build_dentry_tree_recursive(root_ret, NULL,
						path, ntpath_nchars,
						L"", 0, params, &stats, 0);
out_free_path:
	FREE(path);
	if (ret == 0)
		winnt_do_scan_warnings(root_disk_path, &stats);
	return ret;
}

#endif /* __WIN32__ */
