/*
 * win32_apply.c - Windows-specific code for applying files from a WIM image.
 */

/*
 * Copyright (C) 2013 Eric Biggers
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

#include <aclapi.h> /* for SetSecurityInfo() */

#include "win32_common.h"
#include "wimlib_internal.h"
#include "dentry.h"
#include "lookup_table.h"
#include "endianness.h"

#define MAX_CREATE_HARD_LINK_WARNINGS 5
#define MAX_CREATE_SOFT_LINK_WARNINGS 5

#define MAX_SET_SD_ACCESS_DENIED_WARNINGS 1
#define MAX_SET_SACL_PRIV_NOTHELD_WARNINGS 1

static const wchar_t *apply_access_denied_msg =
L"If you are not running this program as the administrator, you may\n"
 "          need to do so, so that all data and metadata can be extracted\n"
 "          exactly as the origignal copy.  However, if you do not care that\n"
 "          the security descriptors are extracted correctly, you could run\n"
 "          `wimlib-imagex apply' with the --no-acls flag instead.\n"
 ;


static int
win32_extract_try_rpfix(u8 *rpbuf,
			const wchar_t *extract_root_realpath,
			unsigned extract_root_realpath_nchars)
{
	struct reparse_data rpdata;
	wchar_t *target;
	size_t target_nchars;
	size_t stripped_nchars;
	wchar_t *stripped_target;
	wchar_t stripped_target_nchars;
	int ret;

	utf16lechar *new_target;
	utf16lechar *new_print_name;
	size_t new_target_nchars;
	size_t new_print_name_nchars;
	utf16lechar *p;

	ret = parse_reparse_data(rpbuf, 8 + le16_to_cpu(*(u16*)(rpbuf + 4)),
				 &rpdata);
	if (ret)
		return ret;

	if (extract_root_realpath[0] == L'\0' ||
	    extract_root_realpath[1] != L':' ||
	    extract_root_realpath[2] != L'\\')
	{
		ERROR("Can't understand full path format \"%ls\".  "
		      "Try turning reparse point fixups off...",
		      extract_root_realpath);
		return WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED;
	}

	ret = parse_substitute_name(rpdata.substitute_name,
				    rpdata.substitute_name_nbytes,
				    rpdata.rptag);
	if (ret < 0)
		return 0;
	stripped_nchars = ret;
	target = rpdata.substitute_name;
	target_nchars = rpdata.substitute_name_nbytes / sizeof(utf16lechar);
	stripped_target = target + 6;
	stripped_target_nchars = target_nchars - stripped_nchars;

	new_target = alloca((6 + extract_root_realpath_nchars +
			     stripped_target_nchars) * sizeof(utf16lechar));

	p = new_target;
	if (stripped_nchars == 6) {
		/* Include \??\ prefix if it was present before */
		wmemcpy(p, L"\\??\\", 4);
		p += 4;
	}

	/* Print name excludes the \??\ if present. */
	new_print_name = p;
	if (stripped_nchars != 0) {
		/* Get drive letter from real path to extract root, if a drive
		 * letter was present before. */
		*p++ = extract_root_realpath[0];
		*p++ = extract_root_realpath[1];
	}
	/* Copy the rest of the extract root */
	wmemcpy(p, extract_root_realpath + 2, extract_root_realpath_nchars - 2);
	p += extract_root_realpath_nchars - 2;

	/* Append the stripped target */
	wmemcpy(p, stripped_target, stripped_target_nchars);
	p += stripped_target_nchars;
	new_target_nchars = p - new_target;
	new_print_name_nchars = p - new_print_name;

	if (new_target_nchars * sizeof(utf16lechar) >= REPARSE_POINT_MAX_SIZE ||
	    new_print_name_nchars * sizeof(utf16lechar) >= REPARSE_POINT_MAX_SIZE)
	{
		ERROR("Path names too long to do reparse point fixup!");
		return WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED;
	}
	rpdata.substitute_name = new_target;
	rpdata.substitute_name_nbytes = new_target_nchars * sizeof(utf16lechar);
	rpdata.print_name = new_print_name;
	rpdata.print_name_nbytes = new_print_name_nchars * sizeof(utf16lechar);
	return make_reparse_buffer(&rpdata, rpbuf);
}

/* Wrapper around the FSCTL_SET_REPARSE_POINT ioctl to set the reparse data on
 * an extracted reparse point. */
static int
win32_set_reparse_data(HANDLE h,
		       const struct wim_inode *inode,
		       const struct wim_lookup_table_entry *lte,
		       const wchar_t *path,
		       struct apply_args *args)
{
	int ret;
	u8 rpbuf[REPARSE_POINT_MAX_SIZE];
	DWORD bytesReturned;

	DEBUG("Setting reparse data on \"%ls\"", path);

	ret = wim_inode_get_reparse_data(inode, rpbuf);
	if (ret)
		return ret;

	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX &&
	    (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
	     inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT) &&
	    !inode->i_not_rpfixed)
	{
		ret = win32_extract_try_rpfix(rpbuf,
					      args->target_realpath,
					      args->target_realpath_len);
		if (ret)
			return WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED;
	}

	/* Set the reparse data on the open file using the
	 * FSCTL_SET_REPARSE_POINT ioctl.
	 *
	 * There are contradictions in Microsoft's documentation for this:
	 *
	 * "If hDevice was opened without specifying FILE_FLAG_OVERLAPPED,
	 * lpOverlapped is ignored."
	 *
	 * --- So setting lpOverlapped to NULL is okay since it's ignored.
	 *
	 * "If lpOverlapped is NULL, lpBytesReturned cannot be NULL. Even when an
	 * operation returns no output data and lpOutBuffer is NULL,
	 * DeviceIoControl makes use of lpBytesReturned. After such an
	 * operation, the value of lpBytesReturned is meaningless."
	 *
	 * --- So lpOverlapped not really ignored, as it affects another
	 *  parameter.  This is the actual behavior: lpBytesReturned must be
	 *  specified, even though lpBytesReturned is documented as:
	 *
	 *  "Not used with this operation; set to NULL."
	 */
	if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, rpbuf,
			     8 + le16_to_cpu(*(u16*)(rpbuf + 4)),
			     NULL, 0,
			     &bytesReturned /* lpBytesReturned */,
			     NULL /* lpOverlapped */))
	{
		DWORD err = GetLastError();
		if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD)
		{
			args->num_soft_links_failed++;
			if (args->num_soft_links_failed <= MAX_CREATE_SOFT_LINK_WARNINGS) {
				WARNING("Can't set reparse data on \"%ls\": Access denied!\n"
				        "          You may be trying to extract a symbolic "
					"link without the\n"
					"          SeCreateSymbolicLink privilege, which by "
					"default non-Administrator\n"
					"          accounts do not have.", path);
			}
			if (args->num_hard_links_failed == MAX_CREATE_HARD_LINK_WARNINGS) {
				WARNING("Suppressing further warnings regarding failure to extract\n"
					"          reparse points due to insufficient privileges...");
			}
		} else {
			ERROR("Failed to set reparse data on \"%ls\"", path);
			win32_error(err);
			if (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
			    inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT)
				return WIMLIB_ERR_LINK;
			else
				return WIMLIB_ERR_WRITE;
		}
	}
	return 0;
}

/* Wrapper around the FSCTL_SET_COMPRESSION ioctl to change the
 * FILE_ATTRIBUTE_COMPRESSED flag of a file or directory. */
static int
win32_set_compression_state(HANDLE hFile, USHORT format, const wchar_t *path)
{
	DWORD bytesReturned;
	if (!DeviceIoControl(hFile, FSCTL_SET_COMPRESSION,
			     &format, sizeof(USHORT),
			     NULL, 0,
			     &bytesReturned, NULL))
	{
		/* Could be a warning only, but we only call this if the volume
		 * supports compression.  So I'm calling this an error. */
		DWORD err = GetLastError();
		ERROR("Failed to set compression flag on \"%ls\"", path);
		win32_error(err);
		if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD)
			return WIMLIB_ERR_INSUFFICIENT_PRIVILEGES_TO_EXTRACT;
		else
			return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/* Wrapper around FSCTL_SET_SPARSE ioctl to set a file as sparse. */
static int
win32_set_sparse(HANDLE hFile, const wchar_t *path)
{
	DWORD bytesReturned;
	if (!DeviceIoControl(hFile, FSCTL_SET_SPARSE,
			     NULL, 0,
			     NULL, 0,
			     &bytesReturned, NULL))
	{
		/* Could be a warning only, but we only call this if the volume
		 * supports sparse files.  So I'm calling this an error. */
		DWORD err = GetLastError();
		WARNING("Failed to set sparse flag on \"%ls\"", path);
		win32_error(err);
		if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD)
			return WIMLIB_ERR_INSUFFICIENT_PRIVILEGES_TO_EXTRACT;
		else
			return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/*
 * Sets the security descriptor on an extracted file.
 */
static int
win32_set_security_data(const struct wim_inode *inode,
			HANDLE hFile,
			const wchar_t *path,
			struct apply_args *args)
{
	PSECURITY_DESCRIPTOR descriptor;
	unsigned long n;
	DWORD err;
	const struct wim_security_data *sd;

	SECURITY_INFORMATION securityInformation = 0;

	void *owner = NULL;
	void *group = NULL;
	ACL *dacl = NULL;
	ACL *sacl = NULL;

	BOOL owner_defaulted;
	BOOL group_defaulted;
	BOOL dacl_present;
	BOOL dacl_defaulted;
	BOOL sacl_present;
	BOOL sacl_defaulted;

	sd = wim_const_security_data(args->w);
	descriptor = sd->descriptors[inode->i_security_id];

	GetSecurityDescriptorOwner(descriptor, &owner, &owner_defaulted);
	if (owner)
		securityInformation |= OWNER_SECURITY_INFORMATION;

	GetSecurityDescriptorGroup(descriptor, &group, &group_defaulted);
	if (group)
		securityInformation |= GROUP_SECURITY_INFORMATION;

	GetSecurityDescriptorDacl(descriptor, &dacl_present,
				  &dacl, &dacl_defaulted);
	if (dacl)
		securityInformation |= DACL_SECURITY_INFORMATION;

	GetSecurityDescriptorSacl(descriptor, &sacl_present,
				  &sacl, &sacl_defaulted);
	if (sacl)
		securityInformation |= SACL_SECURITY_INFORMATION;

again:
	if (securityInformation == 0)
		return 0;
	if (SetSecurityInfo(hFile, SE_FILE_OBJECT,
			    securityInformation, owner, group, dacl, sacl))
		return 0;
	err = GetLastError();
	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS)
		goto fail;
	switch (err) {
	case ERROR_PRIVILEGE_NOT_HELD:
		if (securityInformation & SACL_SECURITY_INFORMATION) {
			n = args->num_set_sacl_priv_notheld++;
			securityInformation &= ~SACL_SECURITY_INFORMATION;
			sacl = NULL;
			if (n < MAX_SET_SACL_PRIV_NOTHELD_WARNINGS) {
				WARNING(
"We don't have enough privileges to set the full security\n"
"          descriptor on \"%ls\"!\n", path);
				if (args->num_set_sd_access_denied +
				    args->num_set_sacl_priv_notheld == 1)
				{
					WARNING("%ls", apply_access_denied_msg);
				}
				WARNING("Re-trying with SACL omitted.\n", path);
			} else if (n == MAX_SET_SACL_PRIV_NOTHELD_WARNINGS) {
				WARNING(
"Suppressing further 'privileges not held' error messages when setting\n"
"          security descriptors.");
			}
			goto again;
		}
		/* Fall through */
	case ERROR_INVALID_OWNER:
	case ERROR_ACCESS_DENIED:
		n = args->num_set_sd_access_denied++;
		if (n < MAX_SET_SD_ACCESS_DENIED_WARNINGS) {
			WARNING("Failed to set security descriptor on \"%ls\": "
				"Access denied!\n", path);
			if (args->num_set_sd_access_denied +
			    args->num_set_sacl_priv_notheld == 1)
			{
				WARNING("%ls", apply_access_denied_msg);
			}
		} else if (n == MAX_SET_SD_ACCESS_DENIED_WARNINGS) {
			WARNING(
"Suppressing further access denied error messages when setting\n"
"          security descriptors");
		}
		return 0;
	default:
fail:
		ERROR("Failed to set security descriptor on \"%ls\"", path);
		win32_error(err);
		if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD)
			return WIMLIB_ERR_INSUFFICIENT_PRIVILEGES_TO_EXTRACT;
		else
			return WIMLIB_ERR_WRITE;
	}
}


static int
win32_extract_chunk(const void *buf, size_t len, void *arg)
{
	HANDLE hStream = arg;

	DWORD nbytes_written;
	wimlib_assert(len <= 0xffffffff);

	if (!WriteFile(hStream, buf, len, &nbytes_written, NULL) ||
	    nbytes_written != len)
	{
		DWORD err = GetLastError();
		ERROR("WriteFile(): write error");
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

static int
do_win32_extract_stream(HANDLE hStream, const struct wim_lookup_table_entry *lte)
{
	return extract_wim_resource(lte, wim_resource_size(lte),
				    win32_extract_chunk, hStream);
}

struct win32_encrypted_extract_ctx {
	const struct wim_lookup_table_entry *lte;
	u64 offset;
};

static DWORD WINAPI
win32_encrypted_import_cb(unsigned char *data, void *_ctx,
			  unsigned long *len_p)
{
	struct win32_encrypted_extract_ctx *ctx = _ctx;
	unsigned long len = *len_p;
	const struct wim_lookup_table_entry *lte = ctx->lte;

	len = min(len, wim_resource_size(lte) - ctx->offset);

	if (read_partial_wim_resource_into_buf(lte, len, ctx->offset, data))
		return ERROR_READ_FAULT;

	ctx->offset += len;
	*len_p = len;
	return ERROR_SUCCESS;
}

/* Create an encrypted file and extract the raw encrypted data to it.
 *
 * @path:  Path to encrypted file to create.
 * @lte:   WIM lookup_table entry for the raw encrypted data.
 *
 * This is separate from do_win32_extract_stream() because the WIM is supposed
 * to contain the *raw* encrypted data, which needs to be extracted ("imported")
 * using the special APIs OpenEncryptedFileRawW(), WriteEncryptedFileRaw(), and
 * CloseEncryptedFileRaw().
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
do_win32_extract_encrypted_stream(const wchar_t *path,
				  const struct wim_lookup_table_entry *lte)
{
	void *file_ctx;
	int ret;

	DEBUG("Opening file \"%ls\" to extract raw encrypted data", path);

	ret = OpenEncryptedFileRawW(path, CREATE_FOR_IMPORT, &file_ctx);
	if (ret) {
		ERROR("Failed to open \"%ls\" to write raw encrypted data", path);
		win32_error(ret);
		return WIMLIB_ERR_OPEN;
	}

	if (lte) {
		struct win32_encrypted_extract_ctx ctx;

		ctx.lte = lte;
		ctx.offset = 0;
		ret = WriteEncryptedFileRaw(win32_encrypted_import_cb, &ctx, file_ctx);
		if (ret == ERROR_SUCCESS) {
			ret = 0;
		} else {
			ret = WIMLIB_ERR_WRITE;
			ERROR("Failed to extract encrypted file \"%ls\"", path);
		}
	}
	CloseEncryptedFileRaw(file_ctx);
	return ret;
}

static bool
path_is_root_of_drive(const wchar_t *path)
{
	if (!*path)
		return false;

	if (*path != L'/' && *path != L'\\') {
		if (*(path + 1) == L':')
			path += 2;
		else
			return false;
	}
	while (*path == L'/' || *path == L'\\')
		path++;
	return (*path == L'\0');
}

static inline DWORD
win32_mask_attributes(DWORD i_attributes)
{
	return i_attributes & ~(FILE_ATTRIBUTE_SPARSE_FILE |
				FILE_ATTRIBUTE_COMPRESSED |
				FILE_ATTRIBUTE_REPARSE_POINT |
				FILE_ATTRIBUTE_DIRECTORY |
				FILE_ATTRIBUTE_ENCRYPTED |
				FILE_FLAG_DELETE_ON_CLOSE |
				FILE_FLAG_NO_BUFFERING |
				FILE_FLAG_OPEN_NO_RECALL |
				FILE_FLAG_OVERLAPPED |
				FILE_FLAG_RANDOM_ACCESS |
				/*FILE_FLAG_SESSION_AWARE |*/
				FILE_FLAG_SEQUENTIAL_SCAN |
				FILE_FLAG_WRITE_THROUGH);
}

static inline DWORD
win32_get_create_flags_and_attributes(DWORD i_attributes)
{
	/*
	 * Some attributes cannot be set by passing them to CreateFile().  In
	 * particular:
	 *
	 * FILE_ATTRIBUTE_DIRECTORY:
	 *   CreateDirectory() must be called instead of CreateFile().
	 *
	 * FILE_ATTRIBUTE_SPARSE_FILE:
	 *   Needs an ioctl.
	 *   See: win32_set_sparse().
	 *
	 * FILE_ATTRIBUTE_COMPRESSED:
	 *   Not clear from the documentation, but apparently this needs an
	 *   ioctl as well.
	 *   See: win32_set_compressed().
	 *
	 * FILE_ATTRIBUTE_REPARSE_POINT:
	 *   Needs an ioctl, with the reparse data specified.
	 *   See: win32_set_reparse_data().
	 *
	 * In addition, clear any file flags in the attributes that we don't
	 * want, but also specify FILE_FLAG_OPEN_REPARSE_POINT and
	 * FILE_FLAG_BACKUP_SEMANTICS as we are a backup application.
	 */
	return win32_mask_attributes(i_attributes) |
		FILE_FLAG_OPEN_REPARSE_POINT |
		FILE_FLAG_BACKUP_SEMANTICS;
}

/* Set compression and/or sparse attributes on a stream, if supported by the
 * volume. */
static int
win32_set_special_stream_attributes(HANDLE hFile, const struct wim_inode *inode,
				    struct wim_lookup_table_entry *unnamed_stream_lte,
				    const wchar_t *path, unsigned vol_flags)
{
	int ret;

	if (inode->i_attributes & FILE_ATTRIBUTE_COMPRESSED) {
		if (vol_flags & FILE_FILE_COMPRESSION) {
			ret = win32_set_compression_state(hFile,
							  COMPRESSION_FORMAT_DEFAULT,
							  path);
			if (ret)
				return ret;
		} else {
			DEBUG("Cannot set compression attribute on \"%ls\": "
			      "volume does not support transparent compression",
			      path);
		}
	}

	if (inode->i_attributes & FILE_ATTRIBUTE_SPARSE_FILE) {
		if (vol_flags & FILE_SUPPORTS_SPARSE_FILES) {
			DEBUG("Setting sparse flag on \"%ls\"", path);
			ret = win32_set_sparse(hFile, path);
			if (ret)
				return ret;
		} else {
			DEBUG("Cannot set sparse attribute on \"%ls\": "
			      "volume does not support sparse files",
			      path);
		}
	}
	return 0;
}

/* Pre-create directories; extract encrypted streams */
static int
win32_begin_extract_unnamed_stream(const struct wim_inode *inode,
				   const struct wim_lookup_table_entry *lte,
				   const wchar_t *path,
				   DWORD *creationDisposition_ret,
				   unsigned int vol_flags)
{
	DWORD err;
	int ret;

	/* Directories must be created with CreateDirectoryW().  Then the call
	 * to CreateFileW() will merely open the directory that was already
	 * created rather than creating a new file. */
	if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY &&
	    !path_is_root_of_drive(path)) {
		if (!CreateDirectoryW(path, NULL)) {
			err = GetLastError();
			if (err != ERROR_ALREADY_EXISTS) {
				ERROR("Failed to create directory \"%ls\"",
				      path);
				win32_error(err);
				return WIMLIB_ERR_MKDIR;
			}
		}
		DEBUG("Created directory \"%ls\"", path);
		*creationDisposition_ret = OPEN_EXISTING;
	}
	if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED &&
	    vol_flags & FILE_SUPPORTS_ENCRYPTION)
	{
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
			unsigned remaining_sharing_violations = 100;
			while (!EncryptFile(path)) {
				if (remaining_sharing_violations &&
				    err == ERROR_SHARING_VIOLATION)
				{
					WARNING("Couldn't encrypt directory \"%ls\" "
						"due to sharing violation; re-trying "
						"after 100 ms", path);
					Sleep(100);
					remaining_sharing_violations--;
				} else {
					err = GetLastError();
					ERROR("Failed to encrypt directory \"%ls\"",
					      path);
					win32_error(err);
					return WIMLIB_ERR_WRITE;
				}
			}
		} else {
			ret = do_win32_extract_encrypted_stream(path, lte);
			if (ret)
				return ret;
			DEBUG("Extracted encrypted file \"%ls\"", path);
		}
		*creationDisposition_ret = OPEN_EXISTING;
	}

	/* Set file attributes if we created the file.  Otherwise, we haven't
	 * created the file set and we will set the attributes in the call to
	 * CreateFileW().
	 *
	 * The FAT filesystem does not let you change the attributes of the root
	 * directory, so treat that as a special case and do not set attributes.
	 * */
	if (*creationDisposition_ret == OPEN_EXISTING &&
	    !path_is_root_of_drive(path))
	{
		if (!SetFileAttributesW(path,
					win32_mask_attributes(inode->i_attributes)))
		{
			err = GetLastError();
			ERROR("Failed to set attributes on \"%ls\"", path);
			win32_error(err);
			return WIMLIB_ERR_WRITE;
		}
	}
	return 0;
}

/* Set security descriptor and extract stream data or reparse data (skip the
 * unnamed data stream of encrypted files, which was already extracted). */
static int
win32_finish_extract_stream(HANDLE h, const struct wim_dentry *dentry,
			    const struct wim_lookup_table_entry *lte,
			    const wchar_t *stream_path,
			    const wchar_t *stream_name_utf16,
			    struct apply_args *args)
{
	int ret = 0;
	const struct wim_inode *inode = dentry->d_inode;
	const wchar_t *short_name;
	if (stream_name_utf16 == NULL) {
		/* Unnamed stream. */

		/* Set security descriptor, unless the extract_flags indicate
		 * not to or the volume does not supported it.  Note that this
		 * is only done when the unnamed stream is being extracted, as
		 * security descriptors are per-file and not per-stream. */
		if (inode->i_security_id >= 0 &&
		    !(args->extract_flags & WIMLIB_EXTRACT_FLAG_NO_ACLS)
		    && (args->vol_flags & FILE_PERSISTENT_ACLS))
		{
			ret = win32_set_security_data(inode, h, stream_path, args);
			if (ret)
				return ret;
		}

		/* Handle reparse points.  The data for them needs to be set
		 * using a special ioctl.  Note that the reparse point may have
		 * been created using CreateFileW() in the case of
		 * non-directories or CreateDirectoryW() in the case of
		 * directories; but the ioctl works either way.  Also, it is
		 * only this step that actually sets the
		 * FILE_ATTRIBUTE_REPARSE_POINT, as it is not valid to set it
		 * using SetFileAttributesW() or CreateFileW().
		 *
		 * If the volume does not support reparse points we simply
		 * ignore the reparse data.  (N.B. the code currently doesn't
		 * actually reach this case because reparse points are skipped
		 * entirely on such volumes.) */
		if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
			if (args->vol_flags & FILE_SUPPORTS_REPARSE_POINTS) {
				ret = win32_set_reparse_data(h, inode,
							     lte, stream_path,
							     args);
				if (ret)
					return ret;
			} else {
				DEBUG("Cannot set reparse data on \"%ls\": volume "
				      "does not support reparse points", stream_path);
			}
		} else if (lte != NULL &&
			   !(args->vol_flags & FILE_SUPPORTS_ENCRYPTION &&
			     inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED))
		{
			/* Extract the data of the unnamed stream, unless the
			 * lookup table entry is NULL (indicating an empty
			 * stream for which no data needs to be extracted), or
			 * the stream is encrypted and therefore was already
			 * extracted as a special case. */
			ret = do_win32_extract_stream(h, lte);
			if (ret)
				return ret;
		}

		if (dentry_has_short_name(dentry))
			SetFileShortNameW(h, short_name);
		else if (running_on_windows_7_or_later())
			SetFileShortNameW(h, L"");
	} else {
		/* Extract the data for a named data stream. */
		if (lte != NULL) {
			DEBUG("Extracting named data stream \"%ls\" (len = %"PRIu64")",
			      stream_path, wim_resource_size(lte));
			ret = do_win32_extract_stream(h, lte);
		}
	}
	return ret;
}

static int
win32_decrypt_file(HANDLE open_handle, const wchar_t *path)
{
	DWORD err;
	/* We cannot call DecryptFileW() while there is an open handle to the
	 * file.  So close it first. */
	if (!CloseHandle(open_handle)) {
		err = GetLastError();
		ERROR("Failed to close handle for \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	if (!DecryptFileW(path, 0 /* reserved parameter; set to 0 */)) {
		err = GetLastError();
		ERROR("Failed to decrypt file \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/*
 * Create and extract a stream to a file, or create a directory, using the
 * Windows API.
 *
 * This handles reparse points, directories, alternate data streams, encrypted
 * files, compressed files, etc.
 *
 * @dentry: WIM dentry for the file or directory being extracted.
 *
 * @path:  Path to extract the file to.
 *
 * @stream_name_utf16:
 * 	   Name of the stream, or NULL if the stream is unnamed.  This will
 * 	   be called with a NULL stream_name_utf16 before any non-NULL
 * 	   stream_name_utf16's.
 *
 * @lte:   WIM lookup table entry for the stream.  May be NULL to indicate
 *         a stream of length 0.
 *
 * @args:  Additional apply context, including flags indicating supported
 *         volume features.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
win32_extract_stream(const struct wim_dentry *dentry,
		     const wchar_t *path,
		     const wchar_t *stream_name_utf16,
		     struct wim_lookup_table_entry *lte,
		     struct apply_args *args)
{
	wchar_t *stream_path;
	HANDLE h;
	int ret;
	DWORD err;
	DWORD creationDisposition = CREATE_ALWAYS;
	DWORD requestedAccess;
	BY_HANDLE_FILE_INFORMATION file_info;
	unsigned remaining_sharing_violations = 1000;
	const struct wim_inode *inode = dentry->d_inode;

	if (stream_name_utf16) {
		/* Named stream.  Create a buffer that contains the UTF-16LE
		 * string [./]path:stream_name_utf16.  This is needed to
		 * create and open the stream using CreateFileW().  I'm not
		 * aware of any other APIs to do this.  Note: the '$DATA' suffix
		 * seems to be unneeded.  Additional note: a "./" prefix needs
		 * to be added when the path is not absolute to avoid ambiguity
		 * with drive letters. */
		size_t stream_path_nchars;
		size_t path_nchars;
		size_t stream_name_nchars;
		const wchar_t *prefix;

		path_nchars = wcslen(path);
		stream_name_nchars = wcslen(stream_name_utf16);
		stream_path_nchars = path_nchars + 1 + stream_name_nchars;
		if (path[0] != cpu_to_le16(L'\0') &&
		    path[0] != cpu_to_le16(L'/') &&
		    path[0] != cpu_to_le16(L'\\') &&
		    path[1] != cpu_to_le16(L':'))
		{
			prefix = L"./";
			stream_path_nchars += 2;
		} else {
			prefix = L"";
		}
		stream_path = alloca((stream_path_nchars + 1) * sizeof(wchar_t));
		swprintf(stream_path, L"%ls%ls:%ls",
			 prefix, path, stream_name_utf16);
	} else {
		/* Unnamed stream; its path is just the path to the file itself.
		 * */
		stream_path = (wchar_t*)path;

		ret = win32_begin_extract_unnamed_stream(inode, lte, path,
							 &creationDisposition,
							 args->vol_flags);
		if (ret)
			goto fail;
	}

	DEBUG("Opening \"%ls\"", stream_path);
	/* DELETE access is needed for SetFileShortNameW(), for some reason. */
	requestedAccess = GENERIC_READ | GENERIC_WRITE | DELETE |
			  ACCESS_SYSTEM_SECURITY;
try_open_again:
	/* Open the stream to be extracted.  Depending on what we have set
	 * creationDisposition to, we may be creating this for the first time,
	 * or we may be opening on existing stream we already created using
	 * CreateDirectoryW() or OpenEncryptedFileRawW(). */
	h = CreateFileW(stream_path,
			requestedAccess,
			FILE_SHARE_READ,
			NULL,
			creationDisposition,
			win32_get_create_flags_and_attributes(inode->i_attributes),
			NULL);
	if (h == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err == ERROR_ACCESS_DENIED &&
		    path_is_root_of_drive(stream_path))
		{
			ret = 0;
			goto out;
		}
		if ((err == ERROR_PRIVILEGE_NOT_HELD ||
		     err == ERROR_ACCESS_DENIED) &&
		    (requestedAccess & ACCESS_SYSTEM_SECURITY))
		{
			/* Try opening the file again without privilege to
			 * modify SACL. */
			requestedAccess &= ~ACCESS_SYSTEM_SECURITY;
			goto try_open_again;
		}
		if (err == ERROR_SHARING_VIOLATION) {
			if (remaining_sharing_violations) {
				--remaining_sharing_violations;
				/* This can happen when restoring encrypted directories
				 * for some reason.  Probably a bug in EncryptFile(). */
				WARNING("Couldn't open \"%ls\" due to sharing violation; "
					"re-trying after 100ms", stream_path);
				Sleep(100);
				goto try_open_again;
			} else {
				ERROR("Too many sharing violations; giving up...");
			}
		} else {
			if (creationDisposition == OPEN_EXISTING)
				ERROR("Failed to open \"%ls\"", stream_path);
			else
				ERROR("Failed to create \"%ls\"", stream_path);
			win32_error(err);
		}
		ret = WIMLIB_ERR_OPEN;
		goto fail;
	}

	/* Check the attributes of the file we just opened, and remove
	 * encryption or compression if either was set by default but is not
	 * supposed to be set based on the WIM inode attributes. */
	if (!GetFileInformationByHandle(h, &file_info)) {
		err = GetLastError();
		ERROR("Failed to get attributes of \"%ls\"", stream_path);
		win32_error(err);
		ret = WIMLIB_ERR_STAT;
		goto fail_close_handle;
	}

	/* Remove encryption? */
	if (file_info.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED &&
	    !(inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED))
	{
		/* File defaulted to encrypted due to being in an encrypted
		 * directory, but is not actually supposed to be encrypted.
		 *
		 * This is a workaround, because I'm not aware of any way to
		 * directly (e.g. with CreateFileW()) create an unencrypted file
		 * in a directory with FILE_ATTRIBUTE_ENCRYPTED set. */
		ret = win32_decrypt_file(h, stream_path);
		if (ret)
			goto fail; /* win32_decrypt_file() closed the handle. */
		creationDisposition = OPEN_EXISTING;
		goto try_open_again;
	}

	/* Remove compression? */
	if (file_info.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED &&
	    !(inode->i_attributes & FILE_ATTRIBUTE_COMPRESSED))
	{
		/* Similar to the encrypted case, above, if the file defaulted
		 * to compressed due to being in an compressed directory, but is
		 * not actually supposed to be compressed, explicitly set the
		 * compression format to COMPRESSION_FORMAT_NONE. */
		ret = win32_set_compression_state(h, COMPRESSION_FORMAT_NONE,
						  stream_path);
		if (ret)
			goto fail_close_handle;
	}

	/* Set compression and/or sparse attributes if needed */
	ret = win32_set_special_stream_attributes(h, inode, lte, path,
						  args->vol_flags);

	if (ret)
		goto fail_close_handle;

	/* At this point we have at least created the needed stream with the
	 * appropriate attributes.  We have yet to set the appropriate security
	 * descriptor and actually extract the stream data (other than for
	 * extracted files, which were already extracted).
	 * win32_finish_extract_stream() handles these additional steps. */
	ret = win32_finish_extract_stream(h, dentry, lte, stream_path,
					  stream_name_utf16, args);
	if (ret)
		goto fail_close_handle;

	/* Done extracting the stream.  Close the handle and return. */
	DEBUG("Closing \"%ls\"", stream_path);
	if (!CloseHandle(h)) {
		err = GetLastError();
		ERROR("Failed to close \"%ls\"", stream_path);
		win32_error(err);
		ret = WIMLIB_ERR_WRITE;
		goto fail;
	}
	ret = 0;
	goto out;
fail_close_handle:
	CloseHandle(h);
fail:
	ERROR("Error extracting \"%ls\"", stream_path);
out:
	return ret;
}

/*
 * Creates a file, directory, or reparse point and extracts all streams to it
 * (unnamed data stream and/or reparse point stream, plus any alternate data
 * streams).  Handles sparse, compressed, and/or encrypted files.
 *
 * @dentry:	WIM dentry for this file or directory.
 * @path:	UTF-16LE external path to extract the inode to.
 * @args:	Additional extraction context.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
win32_extract_streams(const struct wim_dentry *dentry,
		      const wchar_t *path, struct apply_args *args)
{
	struct wim_lookup_table_entry *unnamed_lte;
	int ret;
	const struct wim_inode *inode = dentry->d_inode;

	/* First extract the unnamed stream. */

	unnamed_lte = inode_unnamed_lte_resolved(inode);
	ret = win32_extract_stream(dentry, path, NULL, unnamed_lte, args);
	if (ret)
		goto out;

	/* Extract any named streams, if supported by the volume. */

	if (!(args->vol_flags & FILE_NAMED_STREAMS))
		goto out;
	for (u16 i = 0; i < inode->i_num_ads; i++) {
		const struct wim_ads_entry *ads_entry = &inode->i_ads_entries[i];

		/* Skip the unnamed stream if it's in the ADS entries (we
		 * already extracted it...) */
		if (ads_entry->stream_name_nbytes == 0)
			continue;

		/* Skip special UNIX data entries (see documentation for
		 * WIMLIB_ADD_FLAG_UNIX_DATA) */
		if (ads_entry->stream_name_nbytes == WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES
		    && !memcmp(ads_entry->stream_name,
			       WIMLIB_UNIX_DATA_TAG_UTF16LE,
			       WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES))
			continue;

		/* Extract the named stream */
		ret = win32_extract_stream(dentry,
					   path,
					   ads_entry->stream_name,
					   ads_entry->lte,
					   args);
		if (ret)
			break;
	}
out:
	return ret;
}

static int
dentry_clear_inode_visited(struct wim_dentry *dentry, void *_ignore)
{
	dentry->d_inode->i_visited = 0;
	return 0;
}

static int
dentry_get_features(struct wim_dentry *dentry, void *_features_p)
{
	DWORD features = 0;
	DWORD *features_p = _features_p;
	struct wim_inode *inode = dentry->d_inode;

	if (inode->i_visited) {
		features |= FILE_SUPPORTS_HARD_LINKS;
	} else {
		inode->i_visited = 1;
		if (inode->i_attributes & FILE_ATTRIBUTE_SPARSE_FILE)
			features |= FILE_SUPPORTS_SPARSE_FILES;
		if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
			features |= FILE_SUPPORTS_REPARSE_POINTS;
		for (unsigned i = 0; i < inode->i_num_ads; i++)
			if (inode->i_ads_entries[i].stream_name_nbytes)
				features |= FILE_NAMED_STREAMS;
		if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED)
			features |= FILE_SUPPORTS_ENCRYPTION;
		if (inode->i_attributes & FILE_ATTRIBUTE_COMPRESSED)
			features |= FILE_FILE_COMPRESSION;
		if (inode->i_security_id != -1)
			features |= FILE_PERSISTENT_ACLS;
	}
	*features_p |= features;
	return 0;
}

/* If not done already, load the supported feature flags for the volume onto
 * which the image is being extracted, and warn the user about any missing
 * features that could be important. */
static int
win32_check_vol_flags(const wchar_t *output_path,
		      struct wim_dentry *root, struct apply_args *args)
{
	DWORD dentry_features = 0;
	DWORD missing_features;

	if (args->have_vol_flags)
		return 0;

	for_dentry_in_tree(root, dentry_clear_inode_visited, NULL);
	for_dentry_in_tree(root, dentry_get_features, &dentry_features);

	win32_get_vol_flags(output_path, &args->vol_flags);
	args->have_vol_flags = true;

	missing_features = dentry_features & ~args->vol_flags;

	/* Warn the user about data that may not be extracted. */
	if (missing_features & FILE_SUPPORTS_SPARSE_FILES)
		WARNING("Volume does not support sparse files!\n"
			"          Sparse files will be extracted as non-sparse.");
	if (missing_features & FILE_SUPPORTS_REPARSE_POINTS)
		WARNING("Volume does not support reparse points!\n"
			"          Reparse point data will not be extracted.");
	if (missing_features & FILE_NAMED_STREAMS) {
		WARNING("Volume does not support named data streams!\n"
			"          Named data streams will not be extracted.");
	}
	if (missing_features & FILE_SUPPORTS_ENCRYPTION) {
		WARNING("Volume does not support encryption!\n"
			"          Encrypted files will be extracted as raw data.");
	}
	if (missing_features & FILE_FILE_COMPRESSION) {
		WARNING("Volume does not support transparent compression!\n"
			"          Compressed files will be extracted as non-compressed.");
	}
	if (missing_features & FILE_PERSISTENT_ACLS) {
		if (args->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS) {
			ERROR("Strict ACLs requested, but the volume does not "
			      "support ACLs!");
			return WIMLIB_ERR_VOLUME_LACKS_FEATURES;
		} else {
			WARNING("Volume does not support persistent ACLS!\n"
				"          File permissions will not be extracted.");
		}
	}
	if (running_on_windows_7_or_later() &&
	    (missing_features & FILE_SUPPORTS_HARD_LINKS))
	{
		WARNING("Volume does not support hard links!\n"
			"          Hard links will be extracted as duplicate files.");
	}
	return 0;
}

/*
 * Try extracting a hard link.
 *
 * @output_path:  Path to link to be extracted.
 *
 * @inode:        WIM inode that the link is to; inode->i_extracted_file
 *		  the path to a name of the file that has already been
 *		  extracted (we use this to create the hard link).
 *
 * @args:         Additional apply context, used here to keep track of
 *                the number of times creating a hard link failed due to
 *                ERROR_INVALID_FUNCTION.  This error should indicate that hard
 *                links are not supported by the volume, and we would like to
 *                warn the user a few times, but not too many times.
 *
 * Returns 0 if the hard link was successfully extracted.  Returns
 * WIMLIB_ERR_LINK (> 0) if an error occurred, other than hard links possibly
 * being unsupported by the volume.  Returns a negative value if creating the
 * hard link failed due to ERROR_INVALID_FUNCTION.
 */
static int
win32_try_hard_link(const wchar_t *output_path, const struct wim_inode *inode,
		    struct apply_args *args)
{
	DWORD err;

	/* There is a volume flag for this (FILE_SUPPORTS_HARD_LINKS),
	 * but it's only available on Windows 7 and later.
	 *
	 * Otherwise, CreateHardLinkW() will apparently return
	 * ERROR_INVALID_FUNCTION if the volume does not support hard links. */

	DEBUG("Creating hard link \"%ls => %ls\"",
	      output_path, inode->i_extracted_file);

	if (running_on_windows_7_or_later() &&
	    !(args->vol_flags & FILE_SUPPORTS_HARD_LINKS))
		goto hard_links_unsupported;

	if (CreateHardLinkW(output_path, inode->i_extracted_file, NULL))
		return 0;

	err = GetLastError();
	if (err != ERROR_INVALID_FUNCTION) {
		ERROR("Can't create hard link \"%ls => %ls\"",
		      output_path, inode->i_extracted_file);
		win32_error(err);
		return WIMLIB_ERR_LINK;
	}
hard_links_unsupported:
	args->num_hard_links_failed++;
	if (args->num_hard_links_failed <= MAX_CREATE_HARD_LINK_WARNINGS) {
		if (running_on_windows_7_or_later())
		{
			WARNING("Extracting duplicate copy of \"%ls\" "
				"rather than hard link", output_path);
		} else {
			WARNING("Can't create hard link \"%ls\" => \"%ls\":\n"
				"          Volume does not support hard links!\n"
				"          Falling back to extracting a copy of the file.",
				output_path, inode->i_extracted_file);
		}
	}
	if (args->num_hard_links_failed == MAX_CREATE_HARD_LINK_WARNINGS)
		WARNING("Suppressing further hard linking warnings...");
	return -1;
}

/* Extract a file, directory, reparse point, or hard link to an
 * already-extracted file using the Win32 API */
int
win32_do_apply_dentry(const wchar_t *output_path,
		      size_t output_path_num_chars,
		      struct wim_dentry *dentry,
		      struct apply_args *args)
{
	int ret;
	struct wim_inode *inode = dentry->d_inode;

	ret = win32_check_vol_flags(output_path, dentry, args);
	if (ret)
		return ret;
	if (inode->i_nlink > 1 && inode->i_extracted_file != NULL) {
		/* Linked file, with another name already extracted.  Create a
		 * hard link. */
		ret = win32_try_hard_link(output_path, inode, args);
		if (ret >= 0)
			return ret;
		/* Negative return value from win32_try_hard_link() indicates
		 * that hard links are probably not supported by the volume.
		 * Fall back to extracting a copy of the file. */
	}

	/* If this is a reparse point and the volume does not support reparse
	 * points, just skip it completely. */
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT &&
	    !(args->vol_flags & FILE_SUPPORTS_REPARSE_POINTS))
	{
		WARNING("Not extracting reparse point \"%ls\"", output_path);
	} else {
		/* Create the file, directory, or reparse point, and extract the
		 * data streams. */
		ret = win32_extract_streams(dentry, output_path, args);
		if (ret)
			return ret;
	}
	if (inode->i_extracted_file == NULL) {
		const struct wim_lookup_table_entry *lte;

		/* Tally bytes extracted, including all alternate data streams,
		 * unless we extracted a hard link (or, at least extracted a
		 * name that was supposed to be a hard link) */
		for (unsigned i = 0; i <= inode->i_num_ads; i++) {
			lte = inode_stream_lte_resolved(inode, i);
			if (lte)
				args->progress.extract.completed_bytes +=
							wim_resource_size(lte);
		}
		if (inode->i_nlink > 1) {
			/* Save extracted path for a later call to
			 * CreateHardLinkW() if this inode has multiple links.
			 * */
			inode->i_extracted_file = WSTRDUP(output_path);
			if (!inode->i_extracted_file)
				return WIMLIB_ERR_NOMEM;
		}
	}
	return 0;
}

/* Set timestamps on an extracted file using the Win32 API */
int
win32_do_apply_dentry_timestamps(const wchar_t *path,
				 size_t path_num_chars,
				 struct wim_dentry *dentry,
				 struct apply_args *args)
{
	DWORD err;
	HANDLE h;
	const struct wim_inode *inode = dentry->d_inode;

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT &&
	    !(args->vol_flags & FILE_SUPPORTS_REPARSE_POINTS))
	{
		/* Skip reparse points not extracted */
		return 0;
	}

	/* Windows doesn't let you change the timestamps of the root directory
	 * (at least on FAT, which is dumb but expected since FAT doesn't store
	 * any metadata about the root directory...) */
	if (path_is_root_of_drive(path))
		return 0;

	DEBUG("Opening \"%ls\" to set timestamps", path);
	h = win32_open_existing_file(path, FILE_WRITE_ATTRIBUTES);
	if (h == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		goto fail;
	}

	FILETIME creationTime = {.dwLowDateTime = inode->i_creation_time & 0xffffffff,
				 .dwHighDateTime = inode->i_creation_time >> 32};
	FILETIME lastAccessTime = {.dwLowDateTime = inode->i_last_access_time & 0xffffffff,
				  .dwHighDateTime = inode->i_last_access_time >> 32};
	FILETIME lastWriteTime = {.dwLowDateTime = inode->i_last_write_time & 0xffffffff,
				  .dwHighDateTime = inode->i_last_write_time >> 32};

	DEBUG("Calling SetFileTime() on \"%ls\"", path);
	if (!SetFileTime(h, &creationTime, &lastAccessTime, &lastWriteTime)) {
		err = GetLastError();
		CloseHandle(h);
		goto fail;
	}
	DEBUG("Closing \"%ls\"", path);
	if (!CloseHandle(h)) {
		err = GetLastError();
		goto fail;
	}
	goto out;
fail:
	/* Only warn if setting timestamps failed; still return 0. */
	WARNING("Can't set timestamps on \"%ls\"", path);
	win32_error(err);
out:
	return 0;
}

#endif /* __WIN32__ */
