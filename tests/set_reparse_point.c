#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

static const wchar_t *
win32_error_string(DWORD err)
{
	static wchar_t buf[1024];
	buf[0] = L'\0';
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buf, 1024, NULL);
	return buf;
}

static void
fail(const char *func)
{
	DWORD err = GetLastError();
	fprintf(stderr, "%s (err 0x%08x: %ls)\n", func,
		(uint32_t)err, win32_error_string(err));
	exit(1);
}

int
wmain(int argc, wchar_t **argv)
{
	uint16_t rpdatalen = 80;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %ls FILE [rpdatalen]\n", argv[0]);
		return 1;
	}

	if (argc == 3)
		rpdatalen = wcstol(argv[2], NULL, 10);

	HANDLE h = CreateFile(argv[1],
			      GENERIC_WRITE,
			      FILE_SHARE_VALID_FLAGS,
			      NULL,
			      OPEN_EXISTING,
			      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
			      NULL);
	if (h == INVALID_HANDLE_VALUE)
		fail("CreateFile");

	uint8_t in[8 + rpdatalen];
	uint8_t *p = in;
	*(uint32_t *)p = 0x80000000; /* rptag */
	p += 4;
	*(uint16_t *)p = rpdatalen; /* rpdatalen */
	p += 2;
	*(uint16_t *)p = 0x1234; /* rpreserved */
	p += 2;
	memset(p, 0, rpdatalen); /* rpdata */
	p += rpdatalen;

	DWORD bytes_returned;

	if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, in, p - in,
			     NULL, 0, &bytes_returned, NULL))
		fail("DeviceIoControl");

	CloseHandle(h);

	return 0;
}
