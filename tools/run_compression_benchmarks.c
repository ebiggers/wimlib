/*
 * run_compression_benchmarks.c
 *
 * Program to measure compression ratio and performance of wimlib and WIMGAPI.
 */

#define _WIN32_WINNT 0x0602
#include "wimlib.h"
#include "wimgapi_wrapper.h"

#define ARRAY_LEN(A)	(sizeof(A) / sizeof((A)[0]))

#define VOLUME		L"E:\\"
#define INFILE		L"in.wim"
#define IN_IMAGE	1
#define OUTFILE		L"out.wim"
#define TMPDIR		L"."
#define OUTDIR		L"t"

static void
fatal_wimlib_error(const wchar_t *msg, int err)
{
	fwprintf(stderr, L"Error %ls: wimlib error code %d: %ls\n", msg,
		 err, wimlib_get_error_string(err));
	exit(1);
}

static wchar_t *
get_win32_error_string(DWORD err)
{
	static wchar_t buf[1024];
	buf[0] = L'\0';
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0,
		      buf, ARRAY_LEN(buf), NULL);
	return buf;
}

static void
fatal_win32_error(const wchar_t *msg)
{
	DWORD err = GetLastError();
	fwprintf(stderr, L"Error %ls: Win32 error code %u: %ls\n", msg,
		 err, get_win32_error_string(err));
	exit(1);
}

static uint64_t start_time_ms;

static void
sync_volume(void)
{
	wchar_t path[16];
	HANDLE h;

	wsprintf(path, L"\\\\.\\%lc:", VOLUME[0]);

	h = CreateFile(path, GENERIC_WRITE, FILE_SHARE_VALID_FLAGS,
		       NULL, OPEN_EXISTING, 0, NULL);

	if (!FlushFileBuffers(h))
		fatal_win32_error(L"Unable to sync volume " VOLUME);

	CloseHandle(h);
}

static void
prefetch_input_wim(void)
{
	WIMStruct *wim;
	int ret;

	ret = wimlib_open_wim(INFILE, 0, &wim);
	if (ret)
		fatal_wimlib_error(L"opening input WIM for prefetch", ret);

	ret = wimlib_verify_wim(wim, 0);
	if (ret)
		fatal_wimlib_error(L"prefetching input WIM", ret);

	wimlib_free(wim);
}

static void
begin_test(void)
{
	sync_volume();
	prefetch_input_wim();
	start_time_ms = GetTickCount64();
}

static void
verify_output_wim_with_wimlib(void)
{
	WIMStruct *wim;
	int ret;

	ret = wimlib_open_wim(OUTFILE, 0, &wim);
	if (ret) {
		fatal_wimlib_error(L"opening output WIM for verification with "
				   "wimlib", ret);
	}

	ret = wimlib_verify_wim(wim, 0);
	if (ret)
		fatal_wimlib_error(L"verifying output WIM with wimlib", ret);

	wimlib_free(wim);
}

static void
verify_output_wim_with_wimgapi(void)
{
	HANDLE hWim;
	HANDLE hImage;

	hWim = WIMCreateFile(OUTFILE, WIM_GENERIC_READ, WIM_OPEN_EXISTING,
			     WIM_FLAG_SOLID, 0, NULL);
	if (!hWim) {
		fatal_win32_error(L"opening output WIM for verification with "
				  "WIMGAPI");
	}
	WIMSetTemporaryPath(hWim, TMPDIR);

	hImage = WIMLoadImage(hWim, 1);
	if (!hImage) {
		fatal_win32_error(L"loading WIM image for verification with "
				  "WIMGAPI");
	}

	CreateDirectory(OUTDIR, NULL);

	if (!WIMApplyImage(hImage, OUTDIR, WIM_FLAG_VERIFY))
		fatal_win32_error(L"verifying output WIM with WIMGAPI");

	WIMCloseHandle(hImage);
	WIMCloseHandle(hWim);
}


static void
verify_output_wim(void)
{
	verify_output_wim_with_wimlib();
	verify_output_wim_with_wimgapi();
}

static void
end_test(const char *description)
{
	uint64_t end_time_ms = GetTickCount64();
	HANDLE h = CreateFile(OUTFILE, 0, FILE_SHARE_VALID_FLAGS, NULL,
			      OPEN_EXISTING, 0, NULL);
	LARGE_INTEGER compressed_size = {.QuadPart = -1};
	GetFileSizeEx(h, &compressed_size);
	CloseHandle(h);
	printf("%s: %"PRIu64" in %.1fs\n", description,
	       compressed_size.QuadPart,
	       (double)(end_time_ms - start_time_ms) / 1000);

	verify_output_wim();
}

static const struct wimlib_test_spec {
	const char *description;
	enum wimlib_compression_type ctype;
	int level;
	uint32_t chunk_size;
	bool solid;
} wimlib_test_specs[] = {
	{
		.description = "wimlib, LZMS (solid)",
		.ctype = WIMLIB_COMPRESSION_TYPE_LZMS,
		.solid = true,
	},
	{
		.description = "wimlib, LZMS (non-solid)",
		.ctype = WIMLIB_COMPRESSION_TYPE_LZMS,
	},
	{
		.description = "wimlib, LZX (slow)",
		.ctype = WIMLIB_COMPRESSION_TYPE_LZX,
		.level = 100,
	},
	{
		.description = "wimlib, LZX (normal)",
		.ctype = WIMLIB_COMPRESSION_TYPE_LZX,
	},
	{
		.description = "wimlib, LZX (quick)",
		.ctype = WIMLIB_COMPRESSION_TYPE_LZX,
		.level = 20,
	},
	{
		.description = "wimlib, XPRESS (slow)",
		.ctype = WIMLIB_COMPRESSION_TYPE_XPRESS,
		.level = 80,
	},
	{
		.description = "wimlib, XPRESS",
		.ctype = WIMLIB_COMPRESSION_TYPE_XPRESS,
	},
	{
		.description = "wimlib, \"WIMBoot\" (slow)",
		.ctype = WIMLIB_COMPRESSION_TYPE_XPRESS,
		.level = 80,
		.chunk_size = 4096,
	},
	{
		.description = "wimlib, \"WIMBoot\"",
		.ctype = WIMLIB_COMPRESSION_TYPE_XPRESS,
		.chunk_size = 4096,
	},
	{
		.description = "wimlib, None",
		.ctype = WIMLIB_COMPRESSION_TYPE_NONE,
	},
};

static const struct wimgapi_test_spec {
	const char *description;
	DWORD compressionType;
	bool solid;
	bool wimboot;
} wimgapi_test_specs[] = {
	{
		.description = "WIMGAPI, LZMS (solid)",
		.compressionType = WIM_COMPRESS_LZMS,
		.solid = true,
	},
	{
		.description = "WIMGAPI, LZX",
		.compressionType = WIM_COMPRESS_LZX,
	},
	{
		.description = "WIMGAPI, XPRESS",
		.compressionType = WIM_COMPRESS_XPRESS,
	},
	{
		.description = "WIMGAPI, \"WIMBoot\"",
		.compressionType = WIM_COMPRESS_XPRESS,
		.wimboot = true,
	},
	{
		.description = "WIMGAPI, None",
		.compressionType = WIM_COMPRESS_NONE,
	},
};

static void
run_wimlib_test(const struct wimlib_test_spec *testspec)
{
	WIMStruct *in, *out;
	int ret;

	ret = wimlib_set_default_compression_level(-1, 0);
	if (ret)
		fatal_wimlib_error(L"resetting wimlib compression levels", ret);

	begin_test();

	ret = wimlib_open_wim(INFILE, 0, &in);
	if (ret)
		fatal_wimlib_error(L"opening input WIM with wimlib", ret);

	if (testspec->level) {
		ret = wimlib_set_default_compression_level(testspec->ctype,
							   testspec->level);
		if (ret) {
			fatal_wimlib_error(L"setting wimlib compression level",
					   ret);
		}
	}

	ret = wimlib_create_new_wim(testspec->ctype, &out);
	if (ret)
		fatal_wimlib_error(L"creating output WIMStruct", ret);

	if (testspec->solid) {
		ret = wimlib_set_output_pack_compression_type(out,
							      testspec->ctype);
		if (ret) {
			fatal_wimlib_error(L"setting wimlib solid compression "
					   "type", ret);
		}
	}

	if (testspec->chunk_size) {
		if (testspec->solid) {
			ret = wimlib_set_output_pack_chunk_size(out,
							testspec->chunk_size);
		} else {
			ret = wimlib_set_output_chunk_size(out,
							   testspec->chunk_size);
		}
		if (ret) {
			fatal_wimlib_error(L"setting wimlib output chunk size",
					   ret);
		}
	}

	ret = wimlib_export_image(in, IN_IMAGE, out, NULL, NULL, 0);
	if (ret)
		fatal_wimlib_error(L"exporting image with wimlib", ret);

	ret = wimlib_write(out, OUTFILE, WIMLIB_ALL_IMAGES,
			   (testspec->solid ? WIMLIB_WRITE_FLAG_SOLID : 0), 0);
	if (ret)
		fatal_wimlib_error(L"writing output WIM with wimlib", ret);

	wimlib_free(in);
	wimlib_free(out);

	end_test(testspec->description);
}

static void
run_wimgapi_test(const struct wimgapi_test_spec *testspec)
{
	HANDLE hInWim, hOutWim;
	HANDLE hInImage;
	DWORD flags = 0;

	begin_test();

	hInWim = WIMCreateFile(INFILE, WIM_GENERIC_READ, WIM_OPEN_EXISTING,
			       0, 0, NULL);

	if (!hInWim)
		fatal_win32_error(L"opening input WIM with WIMGAPI");

	WIMSetTemporaryPath(hInWim, TMPDIR);

	hInImage = WIMLoadImage(hInWim, IN_IMAGE);
	if (!hInImage)
		fatal_win32_error(L"loading input image with WIMGAPI");

	if (testspec->solid)
		flags |= WIM_FLAG_SOLID;
	if (testspec->wimboot)
		flags |= WIM_FLAG_WIM_BOOT;
	hOutWim = WIMCreateFile(OUTFILE, WIM_GENERIC_WRITE, WIM_CREATE_ALWAYS,
				flags, testspec->compressionType, NULL);
	if (!hOutWim)
		fatal_win32_error(L"opening output WIM with WIMGAPI");

	WIMSetTemporaryPath(hOutWim, TMPDIR);

	if (!WIMExportImage(hInImage, hOutWim, 0))
		fatal_win32_error(L"exporting image with WIMGAPI");

	WIMCloseHandle(hOutWim);
	WIMCloseHandle(hInImage);
	WIMCloseHandle(hInWim);

	end_test(testspec->description);
}

int
wmain(int argc, wchar_t *argv[])
{
	if (!SetCurrentDirectory(VOLUME))
		fatal_win32_error(L"changing directory to " VOLUME);

	for (size_t i = 0; i < ARRAY_LEN(wimlib_test_specs); i++)
		run_wimlib_test(&wimlib_test_specs[i]);

	for (size_t i = 0; i < ARRAY_LEN(wimgapi_test_specs); i++)
		run_wimgapi_test(&wimgapi_test_specs[i]);

	return 0;
}
