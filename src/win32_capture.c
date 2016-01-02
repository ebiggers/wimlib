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
#include "wimlib/win32_vss.h"
#include "wimlib/wof.h"

struct winnt_scan_ctx {
	u32 vol_flags;
	unsigned long num_get_sd_access_denied;
	unsigned long num_get_sacl_priv_notheld;

	/* True if WOF is definitely not attached to the volume being scanned;
	 * false if it may be  */
	bool wof_not_attached;

	/* A reference to the VSS snapshot being used, or NULL if none  */
	struct vss_snapshot *snapshot;
};

static inline const wchar_t *
printable_path(const wchar_t *full_path)
{
	/* Skip over \\?\ or \??\  */
	return full_path + 4;
}

/* Description of where data is located on a Windows filesystem  */
struct windows_file {

	/* Is the data the raw encrypted data of an EFS-encrypted file?  */
	u64 is_encrypted : 1;

	/* The file's LCN (logical cluster number) for sorting, or 0 if unknown.
	 */
	u64 sort_key : 63;

	/* A reference to the VSS snapshot containing the file, or NULL if none.
	 */
	struct vss_snapshot *snapshot;

	/* The path to the file.  If 'is_encrypted=0' this is an NT namespace
	 * path; if 'is_encrypted=1' this is a Win32 namespace path.  */
	wchar_t path[];
};

/* Allocate a 'struct windows_file' to describe the location of a data stream.
 */
static struct windows_file *
alloc_windows_file(bool is_encrypted, struct vss_snapshot *snapshot,
		   const wchar_t *path, size_t path_nchars,
		   const wchar_t *stream_name, size_t stream_name_nchars)
{
	struct windows_file *file;
	wchar_t *p;

	file = MALLOC(sizeof(struct windows_file) +
		      (path_nchars + (stream_name_nchars ? 1 : 0) +
		       stream_name_nchars + 1) * sizeof(wchar_t));
	if (!file)
		return NULL;

	file->is_encrypted = is_encrypted;
	file->sort_key = 0;
	file->snapshot = vss_get_snapshot(snapshot);
	p = wmempcpy(file->path, path, path_nchars);
	if (stream_name_nchars) {
		/* Named data stream  */
		*p++ = L':';
		p = wmempcpy(p, stream_name, stream_name_nchars);
	}
	*p = L'\0';
	return file;
}

/* Add a stream, located on a Windows filesystem, to the specified WIM inode.
 */
static int
add_stream(struct wim_inode *inode, bool is_encrypted,
	   struct vss_snapshot *snapshot, u64 size,
	   const wchar_t *path, size_t path_nchars,
	   int stream_type, const utf16lechar *stream_name, size_t stream_name_nchars,
	   struct list_head *unhashed_blobs)
{
	struct blob_descriptor *blob = NULL;
	struct wim_inode_stream *strm;

	/* If the stream is nonempty, create a blob descriptor for it.  */
	if (size) {
		blob = new_blob_descriptor();
		if (!blob)
			goto err_nomem;

		blob->windows_file = alloc_windows_file(is_encrypted, snapshot,
							path, path_nchars,
							stream_name,
							stream_name_nchars);
		if (!blob->windows_file)
			goto err_nomem;

		blob->blob_location = BLOB_IN_WINDOWS_FILE;
		blob->file_inode = inode;
		blob->size = size;
	}

	strm = inode_add_stream(inode, stream_type, stream_name, blob);
	if (!strm)
		goto err_nomem;

	prepare_unhashed_blob(blob, inode, strm->stream_id, unhashed_blobs);
	return 0;

err_nomem:
	free_blob_descriptor(blob);
	return WIMLIB_ERR_NOMEM;
}

struct windows_file *
clone_windows_file(const struct windows_file *file)
{
	struct windows_file *new;

	new = memdup(file, sizeof(struct windows_file) +
			   (wcslen(file->path) + 1) * sizeof(wchar_t));
	if (new)
		vss_get_snapshot(new->snapshot);
	return new;
}

void
free_windows_file(struct windows_file *file)
{
	vss_put_snapshot(file->snapshot);
	FREE(file);
}

int
cmp_windows_files(const struct windows_file *file1,
		  const struct windows_file *file2)
{
	/* Compare by starting LCN (logical cluster number)  */
	int v = cmp_u64(file1->sort_key, file2->sort_key);
	if (v)
		return v;

	/* Compare files by path: just a heuristic that will place files
	 * in the same directory next to each other.  */
	return wcscmp(file1->path, file2->path);
}

const wchar_t *
get_windows_file_path(const struct windows_file *file)
{
	return file->path;
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

static int
read_winnt_stream_prefix(const wchar_t *path, u64 size,
			 const struct read_blob_callbacks *cbs)
{
	HANDLE h;
	NTSTATUS status;
	u8 buf[BUFFER_SIZE];
	u64 bytes_remaining;
	int ret;

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
		if (unlikely(!NT_SUCCESS(status))) {
			if (status == STATUS_END_OF_FILE) {
				ERROR("\"%ls\": File was concurrently truncated",
				      printable_path(path));
				ret = WIMLIB_ERR_CONCURRENT_MODIFICATION_DETECTED;
			} else {
				winnt_error(status, L"\"%ls\": Error reading data",
					    printable_path(path));
				ret = WIMLIB_ERR_READ;
			}
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

static int
read_win32_encrypted_file_prefix(const wchar_t *path, bool is_dir, u64 size,
				 const struct read_blob_callbacks *cbs)
{
	struct win32_encrypted_read_ctx export_ctx;
	DWORD err;
	void *file_ctx;
	int ret;
	DWORD flags = 0;

	if (is_dir)
		flags |= CREATE_FOR_DIR;

	export_ctx.cbs = cbs;
	export_ctx.wimlib_err_code = 0;
	export_ctx.bytes_remaining = size;

	err = OpenEncryptedFileRaw(path, flags, &file_ctx);
	if (err != ERROR_SUCCESS) {
		win32_error(err,
			    L"Failed to open encrypted file \"%ls\" for raw read",
			    printable_path(path));
		return WIMLIB_ERR_OPEN;
	}
	err = ReadEncryptedFileRaw(win32_encrypted_export_cb,
				   &export_ctx, file_ctx);
	if (err != ERROR_SUCCESS) {
		ret = export_ctx.wimlib_err_code;
		if (ret == 0) {
			win32_error(err,
				    L"Failed to read encrypted file \"%ls\"",
				    printable_path(path));
			ret = WIMLIB_ERR_READ;
		}
	} else if (export_ctx.bytes_remaining != 0) {
		ERROR("Only could read %"PRIu64" of %"PRIu64" bytes from "
		      "encrypted file \"%ls\"",
		      size - export_ctx.bytes_remaining, size,
		      printable_path(path));
		ret = WIMLIB_ERR_READ;
	} else {
		ret = 0;
	}
	CloseEncryptedFileRaw(file_ctx);
	return ret;
}

/* Read the first @size bytes from the file, or named data stream of a file,
 * described by @blob.  */
int
read_windows_file_prefix(const struct blob_descriptor *blob, u64 size,
			 const struct read_blob_callbacks *cbs)
{
	const struct windows_file *file = blob->windows_file;

	if (unlikely(file->is_encrypted)) {
		bool is_dir = (blob->file_inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY);
		return read_win32_encrypted_file_prefix(file->path, is_dir, size, cbs);
	}

	return read_winnt_stream_prefix(file->path, size, cbs);
}

/*
 * Load the short name of a file into a WIM dentry.
 */
static noinline_for_stack NTSTATUS
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
		dentry->d_short_name = utf16le_dupz(info->FileName,
						    info->FileNameLength);
		if (!dentry->d_short_name)
			return STATUS_NO_MEMORY;
		dentry->d_short_name_nbytes = info->FileNameLength;
	}
	return status;
}

/*
 * Load the security descriptor of a file into the corresponding inode and the
 * WIM image's security descriptor set.
 */
static noinline_for_stack NTSTATUS
winnt_get_security_descriptor(HANDLE h, struct wim_inode *inode,
			      struct wim_sd_set *sd_set,
			      struct winnt_scan_ctx *ctx, int add_flags)
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
				ctx->num_get_sacl_priv_notheld++;
				requestedInformation &= ~(SACL_SECURITY_INFORMATION |
							  LABEL_SECURITY_INFORMATION |
							  BACKUP_SECURITY_INFORMATION);
				break;
			}
			/* Fake success (useful when capturing as
			 * non-Administrator).  */
			ctx->num_get_sd_access_denied++;
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
				  struct winnt_scan_ctx *ctx);

static int
winnt_recurse_directory(HANDLE h,
			wchar_t *full_path,
			size_t full_path_nchars,
			struct wim_dentry *parent,
			struct capture_params *params,
			struct winnt_scan_ctx *ctx)
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
			if (!should_ignore_filename(info->FileName,
						    info->FileNameLength / 2))
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
							ctx);

				full_path[full_path_nchars] = L'\0';

				if (ret)
					goto out_free_buf;
				attach_scanned_tree(parent, child, params->blob_table);
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
#define RP_FIXED	(-1)

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
 * This is the Windows equivalent of unix_relativize_link_target(); see there
 * for general details.  This version works with an "absolute" Windows link
 * target, specified from the root of the Windows kernel object namespace.  Note
 * that we have to open directories with a trailing slash when present because
 * \??\E: opens the E: device itself and not the filesystem root directory.
 */
static const wchar_t *
winnt_relativize_link_target(const wchar_t *target, size_t target_nbytes,
			     u64 ino, u64 dev)
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

			if (file_has_ino_and_dev(h, ino, dev))
				goto out_close_root_dir;
		}
	} while (p != target_end);

	p = target;

out_close_root_dir:
	if (attr.RootDirectory)
		(*func_NtClose)(attr.RootDirectory);
	while (p > target && *(p - 1) == L'\\')
		p--;
	return p;
}

static int
winnt_rpfix_progress(struct capture_params *params, const wchar_t *path,
		     const struct link_reparse_point *link, int scan_status)
{
	size_t print_name_nchars = link->print_name_nbytes / sizeof(wchar_t);
	wchar_t print_name0[print_name_nchars + 1];

	wmemcpy(print_name0, link->print_name, print_name_nchars);
	print_name0[print_name_nchars] = L'\0';

	params->progress.scan.cur_path = printable_path(path);
	params->progress.scan.symlink_target = print_name0;
	return do_capture_progress(params, scan_status, NULL);
}

static int
winnt_try_rpfix(struct reparse_buffer_disk *rpbuf, u16 *rpbuflen_p,
		const wchar_t *path, struct capture_params *params)
{
	struct link_reparse_point link;
	const wchar_t *rel_target;
	int ret;

	if (parse_link_reparse_point(rpbuf, *rpbuflen_p, &link)) {
		/* Couldn't understand the reparse data; don't do the fixup.  */
		return 0;
	}

	/*
	 * Don't do reparse point fixups on relative symbolic links.
	 *
	 * On Windows, a relative symbolic link is supposed to be identifiable
	 * by having reparse tag WIM_IO_REPARSE_TAG_SYMLINK and flags
	 * SYMBOLIC_LINK_RELATIVE.  We will use this information, although this
	 * may not always do what the user expects, since drive-relative
	 * symbolic links such as "\Users\Public" have SYMBOLIC_LINK_RELATIVE
	 * set, in addition to truly relative symbolic links such as "Users" or
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
	if (link_is_relative_symlink(&link))
		return 0;

	rel_target = winnt_relativize_link_target(link.substitute_name,
						  link.substitute_name_nbytes,
						  params->capture_root_ino,
						  params->capture_root_dev);

	if (rel_target == link.substitute_name) {
		/* Target points outside of the tree being captured or had an
		 * unrecognized path format.  Don't adjust it.  */
		return winnt_rpfix_progress(params, path, &link,
					    WIMLIB_SCAN_DENTRY_NOT_FIXED_SYMLINK);
	}

	/* We have an absolute target pointing within the directory being
	 * captured. @rel_target is the suffix of the link target that is the
	 * part relative to the directory being captured.
	 *
	 * We will cut off the prefix before this part (which is the path to the
	 * directory being captured) and add a dummy prefix.  Since the process
	 * will need to be reversed when applying the image, it doesn't matter
	 * what exactly the prefix is, as long as it looks like an absolute
	 * path.  */

	static const wchar_t prefix[6] = L"\\??\\X:";
	static const size_t num_unprintable_chars = 4;

	size_t rel_target_nbytes =
		link.substitute_name_nbytes - ((const u8 *)rel_target -
					       (const u8 *)link.substitute_name);

	wchar_t tmp[(sizeof(prefix) + rel_target_nbytes) / sizeof(wchar_t)];

	memcpy(tmp, prefix, sizeof(prefix));
	memcpy(tmp + ARRAY_LEN(prefix), rel_target, rel_target_nbytes);

	link.substitute_name = tmp;
	link.substitute_name_nbytes = sizeof(tmp);

	link.print_name = link.substitute_name + num_unprintable_chars;
	link.print_name_nbytes = link.substitute_name_nbytes -
				 (num_unprintable_chars * sizeof(wchar_t));

	if (make_link_reparse_point(&link, rpbuf, rpbuflen_p))
		return 0;

	ret = winnt_rpfix_progress(params, path, &link,
				   WIMLIB_SCAN_DENTRY_FIXED_SYMLINK);
	if (ret)
		return ret;
	return RP_FIXED;
}

/* Load the reparse data of a file into the corresponding WIM inode.  If the
 * reparse point is a symbolic link or junction with an absolute target and
 * RPFIX mode is enabled, then also rewrite its target to be relative to the
 * capture root.  */
static noinline_for_stack int
winnt_load_reparse_data(HANDLE h, struct wim_inode *inode,
			const wchar_t *full_path, struct capture_params *params)
{
	struct reparse_buffer_disk rpbuf;
	DWORD bytes_returned;
	u16 rpbuflen;
	int ret;

	if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED) {
		/* See comment above assign_stream_types_encrypted()  */
		WARNING("Ignoring reparse data of encrypted file \"%ls\"",
			printable_path(full_path));
		return 0;
	}

	if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT,
			     NULL, 0, &rpbuf, REPARSE_POINT_MAX_SIZE,
			     &bytes_returned, NULL))
	{
		win32_error(GetLastError(), L"\"%ls\": Can't get reparse point",
			    printable_path(full_path));
		return WIMLIB_ERR_READLINK;
	}

	rpbuflen = bytes_returned;

	if (unlikely(rpbuflen < REPARSE_DATA_OFFSET)) {
		ERROR("\"%ls\": reparse point buffer is too short",
		      printable_path(full_path));
		return WIMLIB_ERR_INVALID_REPARSE_DATA;
	}

	if (params->add_flags & WIMLIB_ADD_FLAG_RPFIX) {
		ret = winnt_try_rpfix(&rpbuf, &rpbuflen, full_path, params);
		if (ret == RP_FIXED)
			inode->i_rp_flags &= ~WIM_RP_FLAG_NOT_FIXED;
		else if (ret)
			return ret;
	}

	inode->i_reparse_tag = le32_to_cpu(rpbuf.rptag);
	inode->i_rp_reserved = le16_to_cpu(rpbuf.rpreserved);

	if (!inode_add_stream_with_data(inode,
					STREAM_TYPE_REPARSE_POINT,
					NO_STREAM_NAME,
					rpbuf.rpdata,
					rpbuflen - REPARSE_DATA_OFFSET,
					params->blob_table))
		return WIMLIB_ERR_NOMEM;

	return 0;
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
winnt_scan_efsrpc_raw_data(struct wim_inode *inode,
			   wchar_t *path, size_t path_nchars,
			   struct list_head *unhashed_blobs,
			   struct vss_snapshot *snapshot)
{
	const bool is_dir = (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY);
	u64 size;
	int ret;

	/* OpenEncryptedFileRaw() expects a Win32 name.  */
	wimlib_assert(!wmemcmp(path, L"\\??\\", 4));
	path[1] = L'\\';

	ret = win32_get_encrypted_file_size(path, is_dir, &size);
	if (ret)
		goto out;

	/* Empty EFSRPC data does not make sense  */
	wimlib_assert(size != 0);

	ret = add_stream(inode, true, snapshot, size,
			 path, path_nchars,
			 STREAM_TYPE_EFSRPC_RAW_DATA, NO_STREAM_NAME, 0,
			 unhashed_blobs);
out:
	path[1] = L'?';
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

static int
winnt_scan_data_stream(const wchar_t *path, size_t path_nchars,
		       wchar_t *raw_stream_name, size_t raw_stream_name_nchars,
		       u64 stream_size,
		       struct wim_inode *inode, struct list_head *unhashed_blobs,
		       struct vss_snapshot *snapshot)
{
	wchar_t *stream_name;
	size_t stream_name_nchars;

	/* Given the raw stream name (which is something like
	 * :streamname:$DATA), extract just the stream name part (streamname).
	 * Ignore any non-$DATA streams.  */
	if (!get_data_stream_name(raw_stream_name, raw_stream_name_nchars,
				  &stream_name, &stream_name_nchars))
		return 0;

	stream_name[stream_name_nchars] = L'\0';

	return add_stream(inode, false, snapshot, stream_size,
			  path, path_nchars,
			  STREAM_TYPE_DATA, stream_name, stream_name_nchars,
			  unhashed_blobs);
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
static noinline_for_stack int
winnt_scan_data_streams(HANDLE h, const wchar_t *path, size_t path_nchars,
			struct wim_inode *inode, struct list_head *unhashed_blobs,
			u64 file_size, u32 vol_flags,
			struct vss_snapshot *snapshot)
{
	int ret;
	u8 _buf[4096] _aligned_attribute(8);
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
					     inode, unhashed_blobs,
					     snapshot);
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
					     file_size, inode, unhashed_blobs,
					     snapshot);
	}
out_free_buf:
	/* Free buffer if allocated on heap.  */
	if (unlikely(buf != _buf))
		FREE(buf);
	return ret;
}

static noinline_for_stack u64
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
		if (blob && blob->blob_location == BLOB_IN_WINDOWS_FILE)
			blob->windows_file->sort_key = sort_key;
	}
}

static inline bool
should_try_to_use_wimboot_hash(const struct wim_inode *inode,
			       const struct winnt_scan_ctx *ctx,
			       const struct capture_params *params)
{
	/* Directories and encrypted files aren't valid for external backing. */
	if (inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
				   FILE_ATTRIBUTE_ENCRYPTED))
		return false;

	/* If the file is a reparse point, then try the hash fixup if it's a WOF
	 * reparse point and we're in WIMBOOT mode.  Otherwise, try the hash
	 * fixup if WOF may be attached. */
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		return (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_WOF) &&
			(params->add_flags & WIMLIB_ADD_FLAG_WIMBOOT);
	return !ctx->wof_not_attached;
}

/*
 * This function implements an optimization for capturing files from a
 * filesystem with a backing WIM(s).  If a file is WIM-backed, then we can
 * retrieve the SHA-1 message digest of its original contents from its reparse
 * point.  This may eliminate the need to read the file's data and/or allow the
 * file's data to be immediately deduplicated with existing data in the WIM.
 *
 * If WOF is attached, then this function is merely an optimization, but
 * potentially a very effective one.  If WOF is detached, then this function
 * really causes WIM-backed files to be, effectively, automatically
 * "dereferenced" when possible; the unnamed data stream is updated to reference
 * the original contents and the reparse point is removed.
 *
 * This function returns 0 if the fixup succeeded or was intentionally not
 * executed.  Otherwise it returns an error code.
 */
static noinline_for_stack int
try_to_use_wimboot_hash(HANDLE h, struct wim_inode *inode,
			struct blob_table *blob_table,
			struct winnt_scan_ctx *ctx, const wchar_t *full_path)
{
	struct wim_inode_stream *reparse_strm = NULL;
	struct wim_inode_stream *strm;
	struct blob_descriptor *blob;
	u8 hash[SHA1_HASH_SIZE];
	int ret;

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		struct reparse_buffer_disk rpbuf;
		struct {
			struct wof_external_info wof_info;
			struct wim_provider_rpdata wim_info;
		} *rpdata = (void *)rpbuf.rpdata;
		struct blob_descriptor *reparse_blob;

		/* The file has a WOF reparse point, so WOF must be detached.
		 * We can read the reparse point directly.  */
		ctx->wof_not_attached = true;
		reparse_strm = inode_get_unnamed_stream(inode, STREAM_TYPE_REPARSE_POINT);
		reparse_blob = stream_blob_resolved(reparse_strm);

		if (!reparse_blob || reparse_blob->size < sizeof(*rpdata))
			return 0;  /* Not a WIM-backed file  */

		ret = read_blob_into_buf(reparse_blob, rpdata);
		if (ret)
			return ret;

		if (rpdata->wof_info.version != WOF_CURRENT_VERSION ||
		    rpdata->wof_info.provider != WOF_PROVIDER_WIM ||
		    rpdata->wim_info.version != 2)
			return 0;  /* Not a WIM-backed file  */

		/* Okay, this is a WIM backed file.  Get its SHA-1 hash.  */
		copy_hash(hash, rpdata->wim_info.unnamed_data_stream_hash);
	} else {
		struct {
			struct wof_external_info wof_info;
			struct wim_provider_external_info wim_info;
		} out;
		IO_STATUS_BLOCK iosb;
		NTSTATUS status;

		/* WOF may be attached.  Try reading this file's external
		 * backing info.  */
		status = (*func_NtFsControlFile)(h, NULL, NULL, NULL, &iosb,
						 FSCTL_GET_EXTERNAL_BACKING,
						 NULL, 0, &out, sizeof(out));

		/* Is WOF not attached?  */
		if (status == STATUS_INVALID_DEVICE_REQUEST ||
		    status == STATUS_NOT_SUPPORTED) {
			ctx->wof_not_attached = true;
			return 0;
		}

		/* Is this file not externally backed?  */
		if (status == STATUS_OBJECT_NOT_EXTERNALLY_BACKED)
			return 0;

		/* Does this file have an unknown type of external backing that
		 * needed a larger information buffer?  */
		if (status == STATUS_BUFFER_TOO_SMALL)
			return 0;

		/* Was there some other failure?  */
		if (status != STATUS_SUCCESS) {
			winnt_error(status,
				    L"\"%ls\": FSCTL_GET_EXTERNAL_BACKING failed",
				    full_path);
			return WIMLIB_ERR_STAT;
		}

		/* Is this file backed by a WIM?  */
		if (out.wof_info.version != WOF_CURRENT_VERSION ||
		    out.wof_info.provider != WOF_PROVIDER_WIM ||
		    out.wim_info.version != WIM_PROVIDER_CURRENT_VERSION)
			return 0;

		/* Okay, this is a WIM backed file.  Get its SHA-1 hash.  */
		copy_hash(hash, out.wim_info.unnamed_data_stream_hash);
	}

	/* If the file's unnamed data stream is nonempty, then fill in its hash
	 * and deduplicate it if possible.
	 *
	 * With WOF detached, we require that the blob *must* de-duplicable for
	 * any action can be taken, since without WOF we can't fall back to
	 * getting the "dereferenced" data by reading the stream (the real
	 * stream is sparse and contains all zeroes).  */
	strm = inode_get_unnamed_data_stream(inode);
	if (strm && (blob = stream_blob_resolved(strm))) {
		struct blob_descriptor **back_ptr;

		if (reparse_strm && !lookup_blob(blob_table, hash))
			return 0;
		back_ptr = retrieve_pointer_to_unhashed_blob(blob);
		copy_hash(blob->hash, hash);
		if (after_blob_hashed(blob, back_ptr, blob_table) != blob)
			free_blob_descriptor(blob);
	}

	/* Remove the reparse point, if present.  */
	if (reparse_strm) {
		inode_remove_stream(inode, reparse_strm, blob_table);
		inode->i_attributes &= ~(FILE_ATTRIBUTE_REPARSE_POINT |
					 FILE_ATTRIBUTE_SPARSE_FILE);
		if (inode->i_attributes == 0)
			inode->i_attributes = FILE_ATTRIBUTE_NORMAL;
	}

	return 0;
}

static noinline_for_stack u32
get_volume_information(HANDLE h, const wchar_t *full_path,
		       struct capture_params *params)
{
	FILE_FS_ATTRIBUTE_INFORMATION attr_info;
	FILE_FS_VOLUME_INFORMATION vol_info;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	u32 vol_flags;

	/* Get volume flags  */
	status = (*func_NtQueryVolumeInformationFile)(h, &iosb,
						      &attr_info,
						      sizeof(attr_info),
						      FileFsAttributeInformation);
	if (likely((NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) &&
		   (iosb.Information >=
			offsetof(FILE_FS_ATTRIBUTE_INFORMATION,
				 FileSystemAttributes) +
			sizeof(attr_info.FileSystemAttributes))))
	{
		vol_flags = attr_info.FileSystemAttributes;
	} else {
		winnt_warning(status, L"\"%ls\": Can't get volume attributes",
			      printable_path(full_path));
		vol_flags = 0;
	}

	/* Get volume ID.  */
	status = (*func_NtQueryVolumeInformationFile)(h, &iosb,
						      &vol_info,
						      sizeof(vol_info),
						      FileFsVolumeInformation);
	if (likely((NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) &&
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
	return vol_flags;
}

struct file_info {
	u32 attributes;
	u32 num_links;
	u64 creation_time;
	u64 last_write_time;
	u64 last_access_time;
	u64 ino;
	u64 end_of_file;
};

static noinline_for_stack NTSTATUS
get_file_info(HANDLE h, struct file_info *info)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	FILE_ALL_INFORMATION all_info;

	status = (*func_NtQueryInformationFile)(h, &iosb, &all_info,
						sizeof(all_info),
						FileAllInformation);

	if (unlikely(!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW))
		return status;

	info->attributes = all_info.BasicInformation.FileAttributes;
	info->num_links = all_info.StandardInformation.NumberOfLinks;
	info->creation_time = all_info.BasicInformation.CreationTime.QuadPart;
	info->last_write_time = all_info.BasicInformation.LastWriteTime.QuadPart;
	info->last_access_time = all_info.BasicInformation.LastAccessTime.QuadPart;
	info->ino = all_info.InternalInformation.IndexNumber.QuadPart;
	info->end_of_file = all_info.StandardInformation.EndOfFile.QuadPart;
	return STATUS_SUCCESS;
}

static int
winnt_build_dentry_tree_recursive(struct wim_dentry **root_ret,
				  HANDLE cur_dir,
				  wchar_t *full_path,
				  size_t full_path_nchars,
				  const wchar_t *filename,
				  size_t filename_nchars,
				  struct capture_params *params,
				  struct winnt_scan_ctx *ctx)
{
	struct wim_dentry *root = NULL;
	struct wim_inode *inode = NULL;
	HANDLE h = NULL;
	int ret;
	NTSTATUS status;
	struct file_info file_info;
	ACCESS_MASK requestedPerms;
	u64 sort_key;

	ret = try_exclude(full_path, params);
	if (unlikely(ret < 0)) /* Excluded? */
		goto out_progress;
	if (unlikely(ret > 0)) /* Error? */
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
	status = get_file_info(h, &file_info);
	if (!NT_SUCCESS(status)) {
		winnt_error(status, L"\"%ls\": Can't get file information",
			    printable_path(full_path));
		ret = WIMLIB_ERR_STAT;
		goto out;
	}

	if (unlikely(!(requestedPerms & FILE_READ_DATA)) &&
	    !(file_info.attributes & FILE_ATTRIBUTE_ENCRYPTED))
	{
		ERROR("\"%ls\": Permission to read data was denied",
		      printable_path(full_path));
		ret = WIMLIB_ERR_OPEN;
		goto out;
	}

	if (unlikely(!cur_dir)) {
		/* Root of tree being captured; get volume information.  */
		ctx->vol_flags = get_volume_information(h, full_path, params);
		params->capture_root_ino = file_info.ino;
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
				     file_info.ino,
				     params->capture_root_dev,
				     (file_info.num_links <= 1),
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

	inode->i_attributes = file_info.attributes;
	inode->i_creation_time = file_info.creation_time;
	inode->i_last_write_time = file_info.last_write_time;
	inode->i_last_access_time = file_info.last_access_time;

	/* Get the file's security descriptor, unless we are capturing in
	 * NO_ACLS mode or the volume does not support security descriptors.  */
	if (!(params->add_flags & WIMLIB_ADD_FLAG_NO_ACLS)
	    && (ctx->vol_flags & FILE_PERSISTENT_ACLS))
	{
		status = winnt_get_security_descriptor(h, inode,
						       params->sd_set, ctx,
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
		ret = winnt_load_reparse_data(h, inode, full_path, params);
		if (ret)
			goto out;
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
		ret = winnt_scan_efsrpc_raw_data(inode,
						 full_path,
						 full_path_nchars,
						 params->unhashed_blobs,
						 ctx->snapshot);
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
					      file_info.end_of_file,
					      ctx->vol_flags,
					      ctx->snapshot);
		if (ret)
			goto out;
	}

	if (unlikely(should_try_to_use_wimboot_hash(inode, ctx, params))) {
		ret = try_to_use_wimboot_hash(h, inode, params->blob_table, ctx,
					      full_path);
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
					      ctx);
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
winnt_do_scan_warnings(const wchar_t *path, const struct winnt_scan_ctx *ctx)
{
	if (likely(ctx->num_get_sacl_priv_notheld == 0 &&
		   ctx->num_get_sd_access_denied == 0))
		return;

	WARNING("Scan of \"%ls\" complete, but with one or more warnings:", path);
	if (ctx->num_get_sacl_priv_notheld != 0) {
		WARNING("- Could not capture SACL (System Access Control List)\n"
			"            on %lu files or directories.",
			ctx->num_get_sacl_priv_notheld);
	}
	if (ctx->num_get_sd_access_denied != 0) {
		WARNING("- Could not capture security descriptor at all\n"
			"            on %lu files or directories.",
			ctx->num_get_sd_access_denied);
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
	wchar_t *path = NULL;
	struct winnt_scan_ctx ctx = {};
	UNICODE_STRING ntpath;
	size_t ntpath_nchars;
	int ret;

	/* WARNING: There is no check for overflow later when this buffer is
	 * being used!  But it's as long as the maximum path length understood
	 * by Windows NT (which is NOT the same as MAX_PATH).  */
	path = MALLOC((WINDOWS_NT_MAX_PATH + 1) * sizeof(wchar_t));
	if (!path)
		return WIMLIB_ERR_NOMEM;

	if (params->add_flags & WIMLIB_ADD_FLAG_SNAPSHOT)
		ret = vss_create_snapshot(root_disk_path, &ntpath, &ctx.snapshot);
	else
		ret = win32_path_to_nt_path(root_disk_path, &ntpath);

	if (ret)
		goto out;

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
		goto out;

	ret = winnt_build_dentry_tree_recursive(root_ret, NULL,
						path, ntpath_nchars,
						L"", 0, params, &ctx);
out:
	vss_put_snapshot(ctx.snapshot);
	FREE(path);
	if (ret == 0)
		winnt_do_scan_warnings(root_disk_path, &ctx);
	return ret;
}

#endif /* __WIN32__ */
