/*
 * extract_image.c
 *
 * Support for extracting WIM files.
 *
 * This code does NOT contain any filesystem-specific features.  In particular,
 * security information (i.e. file permissions) and alternate data streams are
 * ignored, except possibly to read an alternate data stream that contains
 * symbolic link data.
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

#include "config.h"

#if defined(__CYGWIN__) || defined(__WIN32__)
#include <windows.h>
#ifdef ERROR
#undef ERROR
#endif
#include <wchar.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/time.h>

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#include <unistd.h>

#include "dentry.h"
#include "lookup_table.h"
#include "timestamp.h"
#include "wimlib_internal.h"
#include "xml.h"

#ifdef WITH_NTFS_3G
#include <ntfs-3g/volume.h>
#endif

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#else
#include <stdlib.h>
#endif

#if defined(__CYGWIN__) || defined(__WIN32__)

static int win32_set_reparse_data(HANDLE h,
				  u32 reparse_tag,
				  const struct wim_lookup_table_entry *lte,
				  const wchar_t *path)
{
	int ret;
	u8 *buf;
	size_t len;

	if (!lte) {
		WARNING("\"%ls\" is marked as a reparse point but had no reparse data",
			path);
		return 0;
	}
	len = wim_resource_size(lte);
	if (len > 16 * 1024 - 8) {
		WARNING("\"%ls\": reparse data too long!", path);
		return 0;
	}

	/* The WIM stream omits the ReparseTag and ReparseDataLength fields, so
	 * leave 8 bytes of space for them at the beginning of the buffer, then
	 * set them manually. */
	buf = alloca(len + 8);
	ret = read_full_wim_resource(lte, buf + 8, 0);
	if (ret)
		return ret;
	*(u32*)(buf + 0) = reparse_tag;
	*(u16*)(buf + 4) = len;
	*(u16*)(buf + 6) = 0;

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
	DWORD bytesReturned;
	if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, buf, len + 8,
			     NULL, 0,
			     &bytesReturned /* lpBytesReturned */,
			     NULL /* lpOverlapped */))
	{
		DWORD err = GetLastError();
		ERROR("Failed to set reparse data on \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}


static int win32_extract_chunk(const u8 *buf, size_t len, u64 offset, void *arg)
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

static int do_win32_extract_stream(HANDLE hStream, struct wim_lookup_table_entry *lte)
{
	return extract_wim_resource(lte, wim_resource_size(lte),
				    win32_extract_chunk, hStream);
}

static int win32_extract_stream(const struct wim_inode *inode,
				const wchar_t *path,
				const wchar_t *stream_name_utf16,
				struct wim_lookup_table_entry *lte)
{
	wchar_t *stream_path;
	HANDLE h;
	int ret;
	DWORD err;
	DWORD creationDisposition = CREATE_ALWAYS;

	if (stream_name_utf16) {
		/* Named stream.  Create a buffer that contains the UTF-16LE
		 * string [./]@path:@stream_name_utf16.  This is needed to
		 * create and open the stream using CreateFileW().  I'm not
		 * aware of any other APIs to do this.  Note: note that the
		 * '$DATA' suffix seems to be unneeded; Additional note: a "./"
		 * prefix needs to be added when the path is not absolute to
		 * avoid ambiguity with drive letters. */
		size_t stream_path_nchars;
		size_t path_nchars;
		size_t stream_name_nchars;
		const wchar_t *prefix;

 		path_nchars = wcslen(path);
		stream_name_nchars = wcslen(stream_name_utf16);
		stream_path_nchars = path_nchars + 1 + stream_name_nchars;
		if (path[0] != L'/' && path[1] != L'\\') {
			prefix = L"./";
			stream_path_nchars += 2;
		} else {
			prefix = L"";
		}
		stream_path = alloca((stream_path_nchars + 1) * sizeof(wchar_t));
		swprintf(stream_path, stream_path_nchars + 1, L"%ls%ls:%ls",
			 prefix, path, stream_name_utf16);
	} else {
		/* Unnamed stream; it's path is just the path to the file
		 * itself. */
		stream_path = (wchar_t*)path;

		/* Directories must be created with CreateDirectoryW().  Then
		 * the call to CreateFileW() will merely open the directory that
		 * was already created rather than creating a new file. */
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (!CreateDirectoryW(stream_path, NULL)) {
				err = GetLastError();
				if (err != ERROR_ALREADY_EXISTS) {
					ERROR("Failed to create directory \"%ls\"",
					      path);
					win32_error(err);
					ret = WIMLIB_ERR_MKDIR;
					goto fail;
				}
			}
			DEBUG("Created directory \"%ls\"", stream_path);
			if (!(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
				ret = 0;
				goto out;
			}
			creationDisposition = OPEN_EXISTING;
		}
	}

	DEBUG("Opening \"%ls\"", stream_path);
	h = CreateFileW(stream_path,
			GENERIC_WRITE | WRITE_OWNER | WRITE_DAC,
			0,
			NULL,
			creationDisposition,
			FILE_FLAG_OPEN_REPARSE_POINT |
			    FILE_FLAG_BACKUP_SEMANTICS |
			    inode->i_attributes,
			NULL);
	if (h == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		ERROR("Failed to create \"%ls\"", stream_path);
		win32_error(err);
		ret = WIMLIB_ERR_OPEN;
		goto fail;
	}

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT &&
	    stream_name_utf16 == NULL)
	{
		DEBUG("Setting reparse data on \"%ls\"", path);
		ret = win32_set_reparse_data(h, inode->i_reparse_tag, lte, path);
		if (ret)
			goto fail_close_handle;
	} else {
		if (lte) {
			DEBUG("Extracting \"%ls\" (len = %zu)",
			      stream_path, wim_resource_size(lte));
			ret = do_win32_extract_stream(h, lte);
			if (ret)
				goto fail_close_handle;
		}
	}

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
	ERROR("Error extracting %ls", stream_path);
out:
	return ret;
}

/*
 * Creates a file, directory, or reparse point and extracts all streams to it
 * (unnamed data stream and/or reparse point stream, plus any alternate data
 * streams).  This in Win32-specific code.
 *
 * @inode:	WIM inode for this file or directory.
 * @path:	UTF-16LE external path to extract the inode to.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int win32_extract_streams(struct wim_inode *inode,
				 const wchar_t *path)
{
	struct wim_lookup_table_entry *unnamed_lte;
	int ret;

	unnamed_lte = inode_unnamed_lte_resolved(inode);
	ret = win32_extract_stream(inode, path, NULL, unnamed_lte);
	if (ret)
		goto out;
	for (u16 i = 0; i < inode->i_num_ads; i++) {
		const struct wim_ads_entry *ads_entry = &inode->i_ads_entries[i];
		if (ads_entry->stream_name_len != 0) {
			/* Skip special UNIX data entries (see documentation for
			 * WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA) */
			if (ads_entry->stream_name_len == WIMLIB_UNIX_DATA_TAG_LEN
			    && !memcmp(ads_entry->stream_name_utf8,
				       WIMLIB_UNIX_DATA_TAG,
				       WIMLIB_UNIX_DATA_TAG_LEN))
				continue;
			ret = win32_extract_stream(inode,
						   path,
						   (const wchar_t*)ads_entry->stream_name,
						   ads_entry->lte);
			if (ret)
				break;
		}
	}
out:
	return ret;
}

/*
 * Sets the security descriptor on an extracted file.  This is Win32-specific
 * code.
 *
 * @inode:	The WIM inode that was extracted and has a security descriptor.
 * @path:	UTF-16LE external path that the inode was extracted to.
 * @sd:		Security data for the WIM image.
 * @path_utf8:  @path in UTF-8 for error messages only.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int win32_set_security_data(const struct wim_inode *inode,
				   const wchar_t *path,
				   const struct wim_security_data *sd)
{
	SECURITY_INFORMATION securityInformation = DACL_SECURITY_INFORMATION |
					           SACL_SECURITY_INFORMATION |
					           OWNER_SECURITY_INFORMATION |
					           GROUP_SECURITY_INFORMATION;
	if (!SetFileSecurityW(path, securityInformation,
			      (PSECURITY_DESCRIPTOR)sd->descriptors[inode->i_security_id]))
	{
		DWORD err = GetLastError();
		ERROR("Can't set security descriptor on \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

#else
static int extract_regular_file_linked(struct wim_dentry *dentry,
				       const char *output_path,
				       struct apply_args *args,
				       struct wim_lookup_table_entry *lte)
{
	/* This mode overrides the normal hard-link extraction and
	 * instead either symlinks or hardlinks *all* identical files in
	 * the WIM, even if they are in a different image (in the case
	 * of a multi-image extraction) */

	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_HARDLINK) {
		if (link(lte->extracted_file, output_path) != 0) {
			ERROR_WITH_ERRNO("Failed to hard link "
					 "`%s' to `%s'",
					 output_path, lte->extracted_file);
			return WIMLIB_ERR_LINK;
		}
	} else {
		int num_path_components;
		int num_output_dir_path_components;
		size_t extracted_file_len;
		char *p;
		const char *p2;
		size_t i;

		num_path_components =
			get_num_path_components(dentry->full_path_utf8) - 1;
		num_output_dir_path_components =
			get_num_path_components(args->target);

		if (args->extract_flags & WIMLIB_EXTRACT_FLAG_MULTI_IMAGE) {
			num_path_components++;
			num_output_dir_path_components--;
		}
		extracted_file_len = strlen(lte->extracted_file);

		char buf[extracted_file_len + 3 * num_path_components + 1];
		p = &buf[0];

		for (i = 0; i < num_path_components; i++) {
			*p++ = '.';
			*p++ = '.';
			*p++ = '/';
		}
		p2 = lte->extracted_file;
		while (*p2 == '/')
			p2++;
		while (num_output_dir_path_components--)
			p2 = path_next_part(p2, NULL);
		strcpy(p, p2);
		if (symlink(buf, output_path) != 0) {
			ERROR_WITH_ERRNO("Failed to symlink `%s' to "
					 "`%s'",
					 buf, lte->extracted_file);
			return WIMLIB_ERR_LINK;
		}
	}
	return 0;
}

static int symlink_apply_unix_data(const char *link,
				   const struct wimlib_unix_data *unix_data)
{
	if (lchown(link, unix_data->uid, unix_data->gid)) {
		if (errno == EPERM) {
			/* Ignore */
			WARNING_WITH_ERRNO("failed to set symlink UNIX owner/group");
		} else {
			ERROR_WITH_ERRNO("failed to set symlink UNIX owner/group");
			return WIMLIB_ERR_INVALID_DENTRY;
		}
	}
	return 0;
}

static int fd_apply_unix_data(int fd, const struct wimlib_unix_data *unix_data)
{
	if (fchown(fd, unix_data->uid, unix_data->gid)) {
		if (errno == EPERM) {
			WARNING_WITH_ERRNO("failed to set file UNIX owner/group");
			/* Ignore? */
		} else {
			ERROR_WITH_ERRNO("failed to set file UNIX owner/group");
			return WIMLIB_ERR_INVALID_DENTRY;
		}
	}

	if (fchmod(fd, unix_data->mode)) {
		if (errno == EPERM) {
			WARNING_WITH_ERRNO("failed to set UNIX file mode");
			/* Ignore? */
		} else {
			ERROR_WITH_ERRNO("failed to set UNIX file mode");
			return WIMLIB_ERR_INVALID_DENTRY;
		}
	}
	return 0;
}

static int dir_apply_unix_data(const char *dir,
			       const struct wimlib_unix_data *unix_data)
{
	int dfd = open(dir, O_RDONLY);
	int ret;
	if (dfd >= 0) {
		ret = fd_apply_unix_data(dfd, unix_data);
		if (close(dfd)) {
			ERROR_WITH_ERRNO("can't close directory `%s'", dir);
			ret = WIMLIB_ERR_MKDIR;
		}
	} else {
		ERROR_WITH_ERRNO("can't open directory `%s'", dir);
		ret = WIMLIB_ERR_MKDIR;
	}
	return ret;
}

static int extract_regular_file_unlinked(struct wim_dentry *dentry,
				         struct apply_args *args,
				         const char *output_path,
				         struct wim_lookup_table_entry *lte)
{
	/* Normal mode of extraction.  Regular files and hard links are
	 * extracted in the way that they appear in the WIM. */

	int out_fd;
	int ret;
	struct wim_inode *inode = dentry->d_inode;

	if (!((args->extract_flags & WIMLIB_EXTRACT_FLAG_MULTI_IMAGE)
		&& (args->extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
				     WIMLIB_EXTRACT_FLAG_HARDLINK))))
	{
		/* If the dentry is part of a hard link set of at least 2
		 * dentries and one of the other dentries has already been
		 * extracted, make a hard link to the file corresponding to this
		 * already-extracted directory.  Otherwise, extract the file and
		 * set the inode->i_extracted_file field so that other dentries
		 * in the hard link group can link to it. */
		if (inode->i_nlink > 1) {
			if (inode->i_extracted_file) {
				DEBUG("Extracting hard link `%s' => `%s'",
				      output_path, inode->i_extracted_file);
				if (link(inode->i_extracted_file, output_path) != 0) {
					ERROR_WITH_ERRNO("Failed to hard link "
							 "`%s' to `%s'",
							 output_path,
							 inode->i_extracted_file);
					return WIMLIB_ERR_LINK;
				}
				return 0;
			}
			FREE(inode->i_extracted_file);
			inode->i_extracted_file = STRDUP(output_path);
			if (!inode->i_extracted_file) {
				ERROR("Failed to allocate memory for filename");
				return WIMLIB_ERR_NOMEM;
			}
		}
	}

	/* Extract the contents of the file to @output_path. */

	out_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out_fd == -1) {
		ERROR_WITH_ERRNO("Failed to open the file `%s' for writing",
				 output_path);
		return WIMLIB_ERR_OPEN;
	}

	if (!lte) {
		/* Empty file with no lookup table entry */
		DEBUG("Empty file `%s'.", output_path);
		ret = 0;
		goto out_extract_unix_data;
	}

	ret = extract_wim_resource_to_fd(lte, out_fd, wim_resource_size(lte));
	if (ret != 0) {
		ERROR("Failed to extract resource to `%s'", output_path);
		goto out;
	}

out_extract_unix_data:
	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		struct wimlib_unix_data unix_data;
		ret = inode_get_unix_data(inode, &unix_data, NULL);
		if (ret > 0)
			;
		else if (ret < 0)
			ret = 0;
		else
			ret = fd_apply_unix_data(out_fd, &unix_data);
		if (ret != 0)
			goto out;
	}
	if (lte)
		args->progress.extract.completed_bytes += wim_resource_size(lte);
out:
	if (close(out_fd) != 0) {
		ERROR_WITH_ERRNO("Failed to close file `%s'", output_path);
		if (ret == 0)
			ret = WIMLIB_ERR_WRITE;
	}
	return ret;
}

static int extract_regular_file(struct wim_dentry *dentry,
				struct apply_args *args,
				const char *output_path)
{
	struct wim_lookup_table_entry *lte;
	const struct wim_inode *inode = dentry->d_inode;

	lte = inode_unnamed_lte_resolved(inode);

	if (lte && (args->extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
					   WIMLIB_EXTRACT_FLAG_HARDLINK)))
	{
		if (lte->extracted_file) {
			return extract_regular_file_linked(dentry, output_path, args, lte);
		} else {
			lte->extracted_file = STRDUP(output_path);
			if (!lte->extracted_file)
				return WIMLIB_ERR_NOMEM;
		}
	}
	return extract_regular_file_unlinked(dentry, args, output_path, lte);
}

static int extract_symlink(struct wim_dentry *dentry,
			   struct apply_args *args,
			   const char *output_path)
{
	char target[4096];
	ssize_t ret = inode_readlink(dentry->d_inode, target,
				     sizeof(target), args->w, 0);
	struct wim_lookup_table_entry *lte;

	if (ret <= 0) {
		ERROR("Could not read the symbolic link from dentry `%s'",
		      dentry->full_path_utf8);
		return WIMLIB_ERR_INVALID_DENTRY;
	}
	ret = symlink(target, output_path);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to symlink `%s' to `%s'",
				 output_path, target);
		return WIMLIB_ERR_LINK;
	}
	lte = inode_unnamed_lte_resolved(dentry->d_inode);
	wimlib_assert(lte != NULL);
	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		struct wimlib_unix_data unix_data;
		ret = inode_get_unix_data(dentry->d_inode, &unix_data, NULL);
		if (ret > 0)
			;
		else if (ret < 0)
			ret = 0;
		else
			ret = symlink_apply_unix_data(output_path, &unix_data);
		if (ret != 0)
			return ret;
	}
	args->progress.extract.completed_bytes += wim_resource_size(lte);
	return 0;
}

#endif /* !__CYGWIN__ && !__WIN32__ */

static int extract_directory(struct wim_dentry *dentry,
			     const char *output_path, bool is_root)
{
	int ret;
	struct stat stbuf;

	ret = stat(output_path, &stbuf);
	if (ret == 0) {
		if (S_ISDIR(stbuf.st_mode)) {
			/*if (!is_root)*/
				/*WARNING("`%s' already exists", output_path);*/
			goto dir_exists;
		} else {
			ERROR("`%s' is not a directory", output_path);
			return WIMLIB_ERR_MKDIR;
		}
	} else {
		if (errno != ENOENT) {
			ERROR_WITH_ERRNO("Failed to stat `%s'", output_path);
			return WIMLIB_ERR_STAT;
		}
	}
	if (mkdir(output_path, S_IRWXU | S_IRGRP | S_IXGRP |
			       S_IROTH | S_IXOTH) != 0) {
		ERROR_WITH_ERRNO("Cannot create directory `%s'",
				 output_path);
		return WIMLIB_ERR_MKDIR;
	}
dir_exists:
	ret = 0;
#if !defined(__CYGWIN__) && !defined(__WIN32__)
	if (dentry) {
		struct wimlib_unix_data unix_data;
		ret = inode_get_unix_data(dentry->d_inode, &unix_data, NULL);
		if (ret > 0)
			;
		else if (ret < 0)
			ret = 0;
		else
			ret = dir_apply_unix_data(output_path, &unix_data);
	}
#endif
	return ret;
}

/* Extracts a file, directory, or symbolic link from the WIM archive. */
static int apply_dentry_normal(struct wim_dentry *dentry, void *arg)
{
	struct apply_args *args = arg;
	struct wim_inode *inode = dentry->d_inode;
	size_t len;
	char *output_path;

	len = strlen(args->target);
	if (dentry_is_root(dentry)) {
		output_path = (char*)args->target;
	} else {
		output_path = alloca(len + dentry->full_path_utf8_len + 1);
		memcpy(output_path, args->target, len);
		memcpy(output_path + len, dentry->full_path_utf8, dentry->full_path_utf8_len);
		output_path[len + dentry->full_path_utf8_len] = '\0';
		len += dentry->full_path_utf8_len;
	}

#if defined(__CYGWIN__) || defined(__WIN32__)
	char *utf16_path;
	size_t utf16_path_len;
	DWORD err;
	int ret;
	ret = utf8_to_utf16(output_path, len, &utf16_path, &utf16_path_len);
	if (ret)
		return ret;

	if (inode->i_nlink > 1 && inode->i_extracted_file != NULL) {
		/* Linked file, with another name already extracted.  Create a
		 * hard link. */
		DEBUG("Creating hard link \"%ls => %ls\"",
		      (const wchar_t*)utf16_path,
		      (const wchar_t*)inode->i_extracted_file);
		if (!CreateHardLinkW((const wchar_t*)utf16_path,
				     (const wchar_t*)inode->i_extracted_file,
				     NULL))
		{
			err = GetLastError();
			ERROR("Can't create hard link \"%ls => %ls\"",
			      (const wchar_t*)utf16_path,
			      (const wchar_t*)inode->i_extracted_file);
			ret = WIMLIB_ERR_LINK;
			win32_error(err);
		}
	} else {
		/* Create the file, directory, or reparse point, and extract the
		 * data streams. */
		ret = win32_extract_streams(inode, (const wchar_t*)utf16_path);
		if (ret)
			goto out_free_utf16_path;

		/* Set security descriptor if present */
		if (inode->i_security_id != -1) {
			DEBUG("Setting security descriptor %d on %s",
			      inode->i_security_id, output_path);
			ret = win32_set_security_data(inode,
						      (const wchar_t*)utf16_path,
						      wim_const_security_data(args->w));
			if (ret)
				goto out_free_utf16_path;
		}
		if (inode->i_nlink > 1) {
			/* Save extracted path for a later call to
			 * CreateHardLinkW() if this inode has multiple links.
			 * */
			inode->i_extracted_file = utf16_path;
			goto out;
		}
	}
out_free_utf16_path:
	FREE(utf16_path);
out:
	return ret;
#else
	if (inode_is_symlink(inode))
		return extract_symlink(dentry, args, output_path);
	else if (inode_is_directory(inode))
		return extract_directory((args->extract_flags &
					   WIMLIB_EXTRACT_FLAG_UNIX_DATA) ? dentry : NULL,
					 output_path, false);
	else
		return extract_regular_file(dentry, args, output_path);
#endif
}

/* Apply timestamps to an extracted file or directory */
static int apply_dentry_timestamps_normal(struct wim_dentry *dentry, void *arg)
{
	struct apply_args *args = arg;
	size_t len;
	char *output_path;
	int ret;
	const struct wim_inode *inode = dentry->d_inode;

	len = strlen(args->target);
	if (dentry_is_root(dentry)) {
		output_path = (char*)args->target;
	} else {
		output_path = alloca(len + dentry->full_path_utf8_len + 1);
		memcpy(output_path, args->target, len);
		memcpy(output_path + len, dentry->full_path_utf8, dentry->full_path_utf8_len);
		output_path[len + dentry->full_path_utf8_len] = '\0';
		len += dentry->full_path_utf8_len;
	}

#if defined(__CYGWIN__) || defined(__WIN32__)
	/* Win32 */
	char *utf16_path;
	size_t utf16_path_len;
	DWORD err;
	HANDLE h;
	BOOL bret1, bret2;

	ret = utf8_to_utf16(output_path, len, &utf16_path, &utf16_path_len);
	if (ret)
		return ret;

	DEBUG("Opening \"%ls\" to set timestamps", utf16_path);
	h = CreateFileW(utf16_path, GENERIC_WRITE, FILE_SHARE_READ,
			NULL, OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
			NULL);

	if (h == INVALID_HANDLE_VALUE)
		err = GetLastError();
	FREE(utf16_path);
	if (h == INVALID_HANDLE_VALUE)
		goto fail;

	FILETIME creationTime = {.dwLowDateTime = dentry->d_inode->i_creation_time & 0xffffffff,
				 .dwHighDateTime = dentry->d_inode->i_creation_time >> 32};
	FILETIME lastAccessTime = {.dwLowDateTime = dentry->d_inode->i_last_access_time & 0xffffffff,
				  .dwHighDateTime = dentry->d_inode->i_last_access_time >> 32};
	FILETIME lastWriteTime = {.dwLowDateTime = dentry->d_inode->i_last_write_time & 0xffffffff,
				  .dwHighDateTime = dentry->d_inode->i_last_write_time >> 32};

	DEBUG("Calling SetFileTime() on \"%s\"", output_path);
	if (!SetFileTime(h, &creationTime, &lastAccessTime, &lastWriteTime)) {
		err = GetLastError();
		CloseHandle(h);
		goto fail;
	}
	DEBUG("Closing \"%s\"", output_path);
	if (!CloseHandle(h)) {
		err = GetLastError();
		goto fail;
	}
	return 0;
fail:
	ERROR("Can't set timestamps on \"%s\"", output_path);
	win32_error(err);
	return WIMLIB_ERR_WRITE;
#else
	/* UNIX */

	/* Convert the WIM timestamps, which are accurate to 100 nanoseconds,
	 * into struct timeval's. */
	struct timeval tv[2];
	wim_timestamp_to_timeval(inode->i_last_access_time, &tv[0]);
	wim_timestamp_to_timeval(inode->i_last_write_time, &tv[1]);
	#ifdef HAVE_LUTIMES
	ret = lutimes(output_path, tv);
	#else
	ret = -1;
	errno = ENOSYS;
	#endif
	if (ret != 0) {
		#ifdef HAVE_UTIME
		if (errno == ENOSYS) {
			struct utimbuf buf;
			buf.actime = wim_timestamp_to_unix(inode->i_last_access_time);
			buf.modtime = wim_timestamp_to_unix(inode->i_last_write_time);
			if (utime(output_path, &buf) == 0)
				return 0;
		}
		#endif
		if (errno != ENOSYS || args->num_lutimes_warnings < 10) {
			/*WARNING_WITH_ERRNO("Failed to set timestamp on file `%s',*/
					    /*output_path");*/
			args->num_lutimes_warnings++;
		}
	}
	return 0;
#endif
}

/* Extract a dentry if it hasn't already been extracted, and either the dentry
 * has no streams or WIMLIB_EXTRACT_FLAG_NO_STREAMS is not specified. */
static int maybe_apply_dentry(struct wim_dentry *dentry, void *arg)
{
	struct apply_args *args = arg;
	int ret;

	if (dentry->is_extracted)
		return 0;

	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_NO_STREAMS)
		if (inode_unnamed_lte_resolved(dentry->d_inode))
			return 0;

	if ((args->extract_flags & WIMLIB_EXTRACT_FLAG_VERBOSE) &&
	     args->progress_func) {
		args->progress.extract.cur_path = dentry->full_path_utf8;
		args->progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY,
				    &args->progress);
	}
	ret = args->apply_dentry(dentry, args);
	if (ret == 0)
		dentry->is_extracted = 1;
	return ret;
}

static int cmp_streams_by_wim_position(const void *p1, const void *p2)
{
	const struct wim_lookup_table_entry *lte1, *lte2;
	lte1 = *(const struct wim_lookup_table_entry**)p1;
	lte2 = *(const struct wim_lookup_table_entry**)p2;
	if (lte1->resource_entry.offset < lte2->resource_entry.offset)
		return -1;
	else if (lte1->resource_entry.offset > lte2->resource_entry.offset)
		return 1;
	else
		return 0;
}

static int sort_stream_list_by_wim_position(struct list_head *stream_list)
{
	struct list_head *cur;
	size_t num_streams;
	struct wim_lookup_table_entry **array;
	size_t i;
	size_t array_size;

	num_streams = 0;
	list_for_each(cur, stream_list)
		num_streams++;
	array_size = num_streams * sizeof(array[0]);
	array = MALLOC(array_size);
	if (!array) {
		ERROR("Failed to allocate %zu bytes to sort stream entries",
		      array_size);
		return WIMLIB_ERR_NOMEM;
	}
	cur = stream_list->next;
	for (i = 0; i < num_streams; i++) {
		array[i] = container_of(cur, struct wim_lookup_table_entry, staging_list);
		cur = cur->next;
	}

	qsort(array, num_streams, sizeof(array[0]), cmp_streams_by_wim_position);

	INIT_LIST_HEAD(stream_list);
	for (i = 0; i < num_streams; i++)
		list_add_tail(&array[i]->staging_list, stream_list);
	FREE(array);
	return 0;
}

static void calculate_bytes_to_extract(struct list_head *stream_list,
				       int extract_flags,
				       union wimlib_progress_info *progress)
{
	struct wim_lookup_table_entry *lte;
	u64 total_bytes = 0;
	u64 num_streams = 0;

	/* For each stream to be extracted... */
	list_for_each_entry(lte, stream_list, staging_list) {
		if (extract_flags &
		    (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
		{
			/* In the symlink or hard link extraction mode, each
			 * stream will be extracted one time regardless of how
			 * many dentries share the stream. */
			wimlib_assert(!(extract_flags & WIMLIB_EXTRACT_FLAG_NTFS));
			if (!lte->extracted_file) {
				num_streams++;
				total_bytes += wim_resource_size(lte);
			}
		} else {
			num_streams += lte->out_refcnt;
			total_bytes += lte->out_refcnt * wim_resource_size(lte);
		}
	}
	progress->extract.num_streams = num_streams;
	progress->extract.total_bytes = total_bytes;
	progress->extract.completed_bytes = 0;
}

static void maybe_add_stream_for_extraction(struct wim_lookup_table_entry *lte,
					    struct list_head *stream_list)
{
	if (++lte->out_refcnt == 1) {
		INIT_LIST_HEAD(&lte->inode_list);
		list_add_tail(&lte->staging_list, stream_list);
	}
}

static void inode_find_streams_for_extraction(struct wim_inode *inode,
					      struct list_head *stream_list,
					      int extract_flags)
{
	struct wim_lookup_table_entry *lte;
	bool inode_added = false;

	lte = inode_unnamed_lte_resolved(inode);
	if (lte) {
		maybe_add_stream_for_extraction(lte, stream_list);
		list_add_tail(&inode->i_lte_inode_list, &lte->inode_list);
		inode_added = true;
	}
#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		for (unsigned i = 0; i < inode->i_num_ads; i++) {
			if (inode->i_ads_entries[i].stream_name_len != 0) {
				lte = inode->i_ads_entries[i].lte;
				if (lte) {
					maybe_add_stream_for_extraction(lte,
									stream_list);
					if (!inode_added) {
						list_add_tail(&inode->i_lte_inode_list,
							      &lte->inode_list);
						inode_added = true;
					}
				}
			}
		}
	}
#endif
}

static void find_streams_for_extraction(struct hlist_head *inode_list,
					struct list_head *stream_list,
					struct wim_lookup_table *lookup_table,
					int extract_flags)
{
	struct wim_inode *inode;
	struct hlist_node *cur;
	struct wim_dentry *dentry;

	for_lookup_table_entry(lookup_table, lte_zero_out_refcnt, NULL);
	INIT_LIST_HEAD(stream_list);
	hlist_for_each_entry(inode, cur, inode_list, i_hlist) {
		if (!inode->i_resolved)
			inode_resolve_ltes(inode, lookup_table);
		inode_for_each_dentry(dentry, inode)
			dentry->is_extracted = 0;
		inode_find_streams_for_extraction(inode, stream_list,
						  extract_flags);
	}
}

struct apply_operations {
	int (*apply_dentry)(struct wim_dentry *dentry, void *arg);
	int (*apply_dentry_timestamps)(struct wim_dentry *dentry, void *arg);
};

static const struct apply_operations normal_apply_operations = {
	.apply_dentry = apply_dentry_normal,
	.apply_dentry_timestamps = apply_dentry_timestamps_normal,
};

#ifdef WITH_NTFS_3G
static const struct apply_operations ntfs_apply_operations = {
	.apply_dentry = apply_dentry_ntfs,
	.apply_dentry_timestamps = apply_dentry_timestamps_ntfs,
};
#endif

static int apply_stream_list(struct list_head *stream_list,
			     struct apply_args *args,
			     const struct apply_operations *ops,
			     wimlib_progress_func_t progress_func)
{
	uint64_t bytes_per_progress = args->progress.extract.total_bytes / 100;
	uint64_t next_progress = bytes_per_progress;
	struct wim_lookup_table_entry *lte;
	struct wim_inode *inode;
	struct wim_dentry *dentry;
	int ret;

	/* This complicated loop is essentially looping through the dentries,
	 * although dentries may be visited more than once (if a dentry contains
	 * two different nonempty streams) or not at all (if a dentry contains
	 * no non-empty streams).
	 *
	 * The outer loop is over the distinct streams to be extracted so that
	 * sequential reading of the WIM can be implemented. */

	/* For each distinct stream to be extracted */
	list_for_each_entry(lte, stream_list, staging_list) {
		/* For each inode that contains the stream */
		list_for_each_entry(inode, &lte->inode_list, i_lte_inode_list) {
			/* For each dentry that points to the inode */
			inode_for_each_dentry(dentry, inode) {
				/* Extract the dentry if it was not already
				 * extracted */
				ret = maybe_apply_dentry(dentry, args);
				if (ret != 0)
					return ret;
				if (progress_func &&
				    args->progress.extract.completed_bytes >= next_progress)
				{
					progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS,
						      &args->progress);
					if (args->progress.extract.completed_bytes >=
					    args->progress.extract.total_bytes)
					{
						next_progress = ~0ULL;
					} else {
						next_progress =
							min (args->progress.extract.completed_bytes +
							     bytes_per_progress,
							     args->progress.extract.total_bytes);
					}
				}
			}
		}
	}
	return 0;
}

/* Extracts the image @image from the WIM @w to the directory or NTFS volume
 * @target. */
static int extract_single_image(WIMStruct *w, int image,
				const char *target, int extract_flags,
				wimlib_progress_func_t progress_func)
{
	int ret;
	struct list_head stream_list;
	struct hlist_head *inode_list;

	struct apply_args args;
	const struct apply_operations *ops;

	args.w                    = w;
	args.target               = target;
	args.extract_flags        = extract_flags;
	args.num_lutimes_warnings = 0;
	args.stream_list          = &stream_list;
	args.progress_func	  = progress_func;

	if (progress_func) {
		args.progress.extract.wimfile_name = w->filename;
		args.progress.extract.image = image;
		args.progress.extract.extract_flags = (extract_flags &
						       WIMLIB_EXTRACT_MASK_PUBLIC);
		args.progress.extract.image_name = wimlib_get_image_name(w, image);
		args.progress.extract.target = target;
	}

#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		args.vol = ntfs_mount(target, 0);
		if (!args.vol) {
			ERROR_WITH_ERRNO("Failed to mount NTFS volume `%s'", target);
			return WIMLIB_ERR_NTFS_3G;
		}
		ops = &ntfs_apply_operations;
	} else
#endif
		ops = &normal_apply_operations;

	ret = select_wim_image(w, image);
	if (ret != 0)
		goto out;

	inode_list = &w->image_metadata[image - 1].inode_list;

	/* Build a list of the streams that need to be extracted */
	find_streams_for_extraction(inode_list, &stream_list,
				    w->lookup_table, extract_flags);

	/* Calculate the number of bytes of data that will be extracted */
	calculate_bytes_to_extract(&stream_list, extract_flags,
				   &args.progress);

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN,
			      &args.progress);
	}

	/* If a sequential extraction was specified, sort the streams to be
	 * extracted by their position in the WIM file, so that the WIM file can
	 * be read sequentially. */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_SEQUENTIAL) {
		ret = sort_stream_list_by_wim_position(&stream_list);
		if (ret != 0) {
			WARNING("Falling back to non-sequential extraction");
			extract_flags &= ~WIMLIB_EXTRACT_FLAG_SEQUENTIAL;
		}
	}

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,
			      &args.progress);
	}

	/* Make the directory structure and extract empty files */
	args.extract_flags |= WIMLIB_EXTRACT_FLAG_NO_STREAMS;
	args.apply_dentry = ops->apply_dentry;
	ret = for_dentry_in_tree(wim_root_dentry(w), maybe_apply_dentry, &args);
	args.extract_flags &= ~WIMLIB_EXTRACT_FLAG_NO_STREAMS;
	if (ret != 0)
		goto out;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,
			      &args.progress);
	}

	/* Extract non-empty files */
	ret = apply_stream_list(&stream_list, &args, ops, progress_func);
	if (ret != 0)
		goto out;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS,
			      &args.progress);
	}

	/* Apply timestamps */
	ret = for_dentry_in_tree_depth(wim_root_dentry(w),
				       ops->apply_dentry_timestamps, &args);
	if (ret != 0)
		goto out;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END,
			      &args.progress);
	}
out:
#ifdef WITH_NTFS_3G
	/* Unmount the NTFS volume */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		if (ntfs_umount(args.vol, FALSE) != 0) {
			ERROR_WITH_ERRNO("Failed to unmount NTFS volume `%s'", args.target);
			if (ret == 0)
				ret = WIMLIB_ERR_NTFS_3G;
		}
	}
#endif
	return ret;
}


/* Extracts all images from the WIM to the directory @target, with the images
 * placed in subdirectories named by their image names. */
static int extract_all_images(WIMStruct *w, const char *target,
			      int extract_flags,
			      wimlib_progress_func_t progress_func)
{
	size_t image_name_max_len = max(xml_get_max_image_name_len(w), 20);
	size_t output_path_len = strlen(target);
	char buf[output_path_len + 1 + image_name_max_len + 1];
	int ret;
	int image;
	const char *image_name;

	ret = extract_directory(NULL, target, true);
	if (ret != 0)
		return ret;

	memcpy(buf, target, output_path_len);
	buf[output_path_len] = '/';
	for (image = 1; image <= w->hdr.image_count; image++) {
		image_name = wimlib_get_image_name(w, image);
		if (image_name && *image_name) {
			strcpy(buf + output_path_len + 1, image_name);
		} else {
			/* Image name is empty. Use image number instead */
			sprintf(buf + output_path_len + 1, "%d", image);
		}
		ret = extract_single_image(w, image, buf, extract_flags,
					   progress_func);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/* Extracts a single image or all images from a WIM file to a directory or NTFS
 * volume. */
WIMLIBAPI int wimlib_extract_image(WIMStruct *w,
				   int image,
				   const char *target,
				   int extract_flags,
				   WIMStruct **additional_swms,
				   unsigned num_additional_swms,
				   wimlib_progress_func_t progress_func)
{
	struct wim_lookup_table *joined_tab, *w_tab_save;
	int ret;

	if (!target)
		return WIMLIB_ERR_INVALID_PARAM;

	extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
			== (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
		return WIMLIB_ERR_INVALID_PARAM;

#if defined(__CYGWIN__) || defined(__WIN32__)
	if (extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		ERROR("Extracting UNIX data is not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK)) {
		ERROR("Linked extraction modes are not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
#endif

	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
#ifdef WITH_NTFS_3G
		if ((extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))) {
			ERROR("Cannot specify symlink or hardlink flags when applying\n"
			      "        directly to a NTFS volume");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (image == WIMLIB_ALL_IMAGES) {
			ERROR("Can only apply a single image when applying "
			      "directly to a NTFS volume");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
			ERROR("Cannot restore UNIX-specific data in the NTFS extraction mode");
			return WIMLIB_ERR_INVALID_PARAM;
		}
#else
		ERROR("wimlib was compiled without support for NTFS-3g, so");
		ERROR("we cannot apply a WIM image directly to a NTFS volume");
		return WIMLIB_ERR_UNSUPPORTED;
#endif
	}

	ret = verify_swm_set(w, additional_swms, num_additional_swms);
	if (ret != 0)
		return ret;

	if (num_additional_swms) {
		ret = new_joined_lookup_table(w, additional_swms,
					      num_additional_swms, &joined_tab);
		if (ret != 0)
			return ret;
		w_tab_save = w->lookup_table;
		w->lookup_table = joined_tab;
	}

	if (image == WIMLIB_ALL_IMAGES) {
		extract_flags |= WIMLIB_EXTRACT_FLAG_MULTI_IMAGE;
		ret = extract_all_images(w, target, extract_flags,
					 progress_func);
	} else {
		extract_flags &= ~WIMLIB_EXTRACT_FLAG_MULTI_IMAGE;
		ret = extract_single_image(w, image, target, extract_flags,
					   progress_func);
	}

	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			     WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(w->lookup_table,
				       lte_free_extracted_file,
				       NULL);
	}

	if (num_additional_swms) {
		free_lookup_table(w->lookup_table);
		w->lookup_table = w_tab_save;
	}
	return ret;
}
