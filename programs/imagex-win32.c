/* Windows-specific code for wimlib-imagex.  */

#ifndef _WIN32
#  error "This file contains Windows code"
#endif

#include "imagex-win32.h"
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <windows.h>

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
