#include <inttypes.h>
#include <stdio.h>
#include <windows.h>

static wchar_t *
win32_error_string(DWORD err_code)
{
	static wchar_t buf[1024];
	buf[0] = L'\0';
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err_code, 0,
		      buf, 1024, NULL);
	return buf;
}

static void
fail(const char *func, DWORD code)
{
	fprintf(stderr, "%s (err 0x%08x: %ls)\n", func,
		(unsigned int)code, win32_error_string(code));
	exit(1);
}

int
wmain(int argc, wchar_t **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %ls FILE\n", argv[0]);
		return 2;
	}

	HANDLE h = CreateFile(argv[1],
			      GENERIC_WRITE,
			      FILE_SHARE_VALID_FLAGS,
			      NULL,
			      OPEN_EXISTING,
			      FILE_FLAG_BACKUP_SEMANTICS,
			      NULL);
	if (h == INVALID_HANDLE_VALUE)
		fail("CreateFile", GetLastError());

	uint8_t in[128];
	uint8_t *p = in;
	*(uint32_t *)p = 0x80000000; /* rptag */
	p += 4;
	*(uint16_t *)p = 80; /* rpdatalen */
	p += 2;
	*(uint16_t *)p = 0; /* rpreserved */
	p += 2;
	memset(p, 0, 80); /* rpdata */
	p += 80;

	DWORD bytes_returned;

	if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, in, p - in,
			     NULL, 0, &bytes_returned, NULL))
		fail("DeviceIoControl", GetLastError());

	CloseHandle(h);

	return 0;
}
