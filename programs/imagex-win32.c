/* Windows-specific code for wimlib-imagex.  */

#ifndef __WIN32__
#  error "This file contains Windows code"
#endif

#include "imagex-win32.h"
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <windows.h>

/* Convert a string from the "current Windows codepage" to UTF-16LE.  */
wchar_t *
win32_mbs_to_wcs(const char *mbs, size_t mbs_nbytes, size_t *num_wchars_ret)
{
	if (mbs_nbytes > INT_MAX) {
		fwprintf(stderr, L"ERROR: too much data (%zu bytes)!\n",
			 mbs_nbytes);
		return NULL;
	}
	if (mbs_nbytes == 0) {
		*num_wchars_ret = 0;
		return (wchar_t*)mbs;
	}
	int len = MultiByteToWideChar(CP_ACP,
				      MB_ERR_INVALID_CHARS,
				      mbs,
				      mbs_nbytes,
				      NULL,
				      0);
	if (len <= 0)
		goto out_invalid;
	wchar_t *wcs = malloc(len * sizeof(wchar_t));
	if (!wcs) {
		fwprintf(stderr, L"ERROR: out of memory!\n");
		return NULL;
	}
	int len2 = MultiByteToWideChar(CP_ACP,
				       MB_ERR_INVALID_CHARS,
				       mbs,
				       mbs_nbytes,
				       wcs,
				       len);
	if (len2 != len) {
		free(wcs);
		goto out_invalid;
	}
	*num_wchars_ret = len;
	return wcs;
out_invalid:
	fwprintf(stderr,
L"ERROR: Invalid multi-byte string in the text file you provided as input!\n"
L"       Maybe try converting your text file to UTF-16LE?\n"
	);
	return NULL;
}

/* Set a file descriptor to binary mode.  */
void set_fd_to_binary_mode(int fd)
{
	_setmode(fd, _O_BINARY);
}

#include <sddl.h>

static wchar_t *
get_security_descriptor_string(PSECURITY_DESCRIPTOR desc)
{
	wchar_t *str = NULL;
	/* 52 characters!!!  */
	ConvertSecurityDescriptorToStringSecurityDescriptorW(
			desc,
			SDDL_REVISION_1,
			OWNER_SECURITY_INFORMATION |
				GROUP_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION |
				SACL_SECURITY_INFORMATION,
			&str,
			NULL);
	return str;
}

void
win32_print_security_descriptor(const uint8_t *sd, size_t size)
{
	wchar_t *str;
	const wchar_t *printstr;

	/* 'size' is ignored here due to the crappy Windows APIs.  Oh well, this
	 * is just for debugging anyway.  */
	str = get_security_descriptor_string((PSECURITY_DESCRIPTOR)sd);
	if (str)
		printstr = str;
	else
		printstr = L"(invalid)";

	wprintf(L"Security Descriptor = %ls\n", printstr);

	LocalFree(str);
}
