/*
 * wimboot.c
 *
 * Support for creating WIMBoot pointer files.
 *
 * See http://technet.microsoft.com/en-us/library/dn594399.aspx for general
 * information about WIMBoot.
 *
 * Note that WIMBoot pointer files are actually implemented on top of the
 * Windows Overlay File System Filter (WOF).  See wof.h for more info.
 */

/*
 * Copyright (C) 2014 Eric Biggers
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


#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef __WIN32__

#include "wimlib/win32_common.h"
#include "wimlib/win32.h"
#include "wimlib/assert.h"
#include "wimlib/error.h"
#include "wimlib/util.h"
#include "wimlib/wimboot.h"
#include "wimlib/wof.h"

static int
win32_get_drive_path(const wchar_t *file_path, wchar_t drive_path[7])
{
	tchar *file_abspath;

	file_abspath = realpath(file_path, NULL);
	if (!file_abspath)
		return WIMLIB_ERR_NOMEM;

	if (file_abspath[0] == L'\0' || file_abspath[1] != L':') {
		ERROR("\"%ls\": Path format not recognized", file_abspath);
		FREE(file_abspath);
		return WIMLIB_ERR_UNSUPPORTED;
	}

	wsprintf(drive_path, L"\\\\.\\%lc:", file_abspath[0]);
	FREE(file_abspath);
	return 0;
}

/* Try to attach an instance of the Windows Overlay File System Filter Driver to
 * the specified drive (such as C:)  */
static bool
try_to_attach_wof(const wchar_t *drive)
{
	HMODULE fltlib;
	bool retval = false;

	/* Use FilterAttach() from Fltlib.dll.  */

	fltlib = LoadLibrary(L"Fltlib.dll");

	if (!fltlib) {
		WARNING("Failed to load Fltlib.dll");
		return retval;
	}

	HRESULT (WINAPI *func_FilterAttach)(LPCWSTR lpFilterName,
					    LPCWSTR lpVolumeName,
					    LPCWSTR lpInstanceName,
					    DWORD dwCreatedInstanceNameLength,
					    LPWSTR lpCreatedInstanceName);

	func_FilterAttach = (void *)GetProcAddress(fltlib, "FilterAttach");

	if (func_FilterAttach) {
		HRESULT res;

		res = (*func_FilterAttach)(L"WoF", drive, NULL, 0, NULL);

		if (res == S_OK)
			retval = true;
	} else {
		WARNING("FilterAttach() does not exist in Fltlib.dll");
	}

	FreeLibrary(fltlib);

	return retval;
}

/*
 * Allocate a WOF data source ID for a WIM file.
 *
 * @wim_path
 *	Absolute path to the WIM file.  This must include a drive letter and use
 *	backslash path separators.
 * @image
 *	Index of the image in the WIM being applied.
 * @target
 *	Path to the target drive.
 * @data_source_id_ret
 *	On success, an identifier for the backing WIM file will be returned
 *	here.
 *
 * Returns 0 on success, or a positive error code on failure.
 */
int
wimboot_alloc_data_source_id(const wchar_t *wim_path, int image,
			     const wchar_t *target, u64 *data_source_id_ret)
{
	tchar drive_path[7];
	size_t wim_path_nchars;
	size_t wim_file_name_length;
	void *in;
	size_t insize;
	struct wof_external_info *wof_info;
	struct wim_provider_add_overlay_input *wim_info;
	HANDLE h;
	u64 data_source_id;
	DWORD bytes_returned;
	int ret;
	const wchar_t *prefix = L"\\??\\";
	const size_t prefix_nchars = 4;
	bool tried_to_attach_wof = false;

	ret = win32_get_drive_path(target, drive_path);
	if (ret)
		return ret;

	wimlib_assert(!wcschr(wim_path, L'/'));
	wimlib_assert(wim_path[0] != L'\0' && wim_path[1] == L':');

	wim_path_nchars = wcslen(wim_path);
	wim_file_name_length = sizeof(wchar_t) *
			       (wim_path_nchars + prefix_nchars);

	insize = sizeof(struct wof_external_info) +
		 sizeof(struct wim_provider_add_overlay_input) +
		 wim_file_name_length;

	in = MALLOC(insize);
	if (!in) {
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	wof_info = (struct wof_external_info *)in;
	wof_info->version = WOF_CURRENT_VERSION;
	wof_info->provider = WOF_PROVIDER_WIM;

	wim_info = (struct wim_provider_add_overlay_input *)(wof_info + 1);
	wim_info->wim_type = WIM_BOOT_NOT_OS_WIM;
	wim_info->wim_index = image;
	wim_info->wim_file_name_offset = offsetof(struct wim_provider_add_overlay_input,
						  wim_file_name);
	wim_info->wim_file_name_length = wim_file_name_length;
	wmemcpy(&wim_info->wim_file_name[0], prefix, prefix_nchars);
	wmemcpy(&wim_info->wim_file_name[prefix_nchars], wim_path, wim_path_nchars);

retry_ioctl:
	h = CreateFile(drive_path, GENERIC_WRITE,
		       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		       NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE) {
		set_errno_from_GetLastError();
		ERROR_WITH_ERRNO("Failed to open \"%ls\"", drive_path + 4);
		ret = WIMLIB_ERR_OPEN;
		goto out_free_in;
	}

	if (!DeviceIoControl(h, FSCTL_ADD_OVERLAY,
			     in, insize,
			     &data_source_id, sizeof(data_source_id),
			     &bytes_returned, NULL))
	{
		DWORD err = GetLastError();
		if (err == ERROR_INVALID_FUNCTION) {
			if (!tried_to_attach_wof) {
				CloseHandle(h);
				h = INVALID_HANDLE_VALUE;
				tried_to_attach_wof = true;
				if (try_to_attach_wof(drive_path + 4))
					goto retry_ioctl;
			}
			ERROR("The version of Windows you are running does not appear to support\n"
			      "        the Windows Overlay File System Filter Driver.  Therefore, wimlib\n"
			      "        cannot apply WIMBoot information.  Please run from Windows 8.1\n"
			      "        Update 1 or later.");
			ret = WIMLIB_ERR_UNSUPPORTED;
			goto out_close_handle;
		} else {
			set_errno_from_win32_error(err);
			ERROR_WITH_ERRNO("Failed to add overlay source \"%ls\" "
					 "to volume \"%ls\" (err=0x%08"PRIu32")",
					 wim_path, drive_path + 4, (uint32_t)err);
			ret = WIMLIB_ERR_WIMBOOT;
			goto out_close_handle;
		}
	}

	if (bytes_returned != sizeof(data_source_id)) {
		set_errno_from_win32_error(ERROR_INVALID_DATA);
		ret = WIMLIB_ERR_WIMBOOT;
		ERROR("Unexpected result size when adding "
		      "overlay source \"%ls\" to volume \"%ls\"",
		      wim_path, drive_path + 4);
		goto out_close_handle;
	}

	*data_source_id_ret = data_source_id;
	ret = 0;

out_close_handle:
	CloseHandle(h);
out_free_in:
	FREE(in);
out:
	return ret;
}


/*
 * Set WIMBoot information on the specified file.
 *
 * @path
 *	Path to extracted file (already created).
 * @data_source_id
 *	Identifier for backing WIM file.
 * @hash
 *	SHA-1 message digest of the file's unnamed data stream.
 *
 * Returns 0 on success, or a positive error code on failure.
 */
int
wimboot_set_pointer(const wchar_t *path, u64 data_source_id,
		    const u8 hash[20])
{
	struct {
		struct wof_external_info wof_info;
		struct wim_provider_external_info wim_info;
	} in;
	HANDLE h;
	DWORD bytes_returned;
	int ret;

	in.wof_info.version = WOF_CURRENT_VERSION;
	in.wof_info.provider = WOF_PROVIDER_WIM;

	in.wim_info.version = WIM_PROVIDER_CURRENT_VERSION;
	in.wim_info.flags = 0;
	in.wim_info.data_source_id = data_source_id;
	memcpy(in.wim_info.resource_hash, hash, 20);

	h = win32_open_existing_file(path, GENERIC_WRITE);
	if (h == INVALID_HANDLE_VALUE) {
		set_errno_from_GetLastError();
		ret = WIMLIB_ERR_OPEN;
		goto out;
	}

	if (!DeviceIoControl(h, FSCTL_SET_EXTERNAL_BACKING,
			     &in, sizeof(in), NULL, 0, &bytes_returned, NULL))
	{
		DWORD err = GetLastError();
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("\"%ls\": Couldn't set WIMBoot pointer data "
				 "(err=0x%08x)", path, (uint32_t)err);
		ret = WIMLIB_ERR_WIMBOOT;
		goto out_close_handle;
	}
	ret = 0;
out_close_handle:
	CloseHandle(h);
out:
	return ret;
}

#endif /* __WIN32__ */
