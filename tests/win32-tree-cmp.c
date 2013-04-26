/*
 * Compare directory trees (Windows version)
 */

#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <assert.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define REPARSE_POINT_MAX_SIZE (16 * 1024)

static wchar_t *
win32_error_string(DWORD err_code)
{
	static wchar_t buf[1024];
	buf[0] = L'\0';
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err_code, 0,
		      buf, 1024, NULL);
	return buf;
}

static void __attribute__((noreturn))
error(const wchar_t *format, ...)
{
	va_list va;
	va_start(va, format);
	vfwprintf(stderr, format, va);
	va_end(va);
	putwc(L'\n', stderr);
	exit(1);
}

static void __attribute__((noreturn))
win32_error(const wchar_t *format, ...)
{
	va_list va;
	DWORD err = GetLastError();

	va_start(va, format);
	vfwprintf(stderr, format, va);
	fwprintf(stderr, L": %ls\n", win32_error_string(err));
	va_end(va);
	exit(1);
}

struct node {
	u64 ino_from;
	u64 ino_to;
	struct node *left;
	struct node *right;
};

static struct node *tree = NULL;

static u64 do_lookup_ino(struct node *tree, u64 ino_from)
{
	if (!tree)
		return -1;
	if (ino_from == tree->ino_from)
		return tree->ino_to;
	else if (ino_from < tree->ino_from)
		return do_lookup_ino(tree->left, ino_from);
	else
		return do_lookup_ino(tree->right, ino_from);
}

static void do_insert(struct node *tree, struct node *node)
{
	if (node->ino_from < tree->ino_from) {
		if (tree->left)
			return do_insert(tree->left, node);
		else
			tree->left = node;
	} else {
		if (tree->right)
			return do_insert(tree->right, node);
		else
			tree->right = node;
	}
}

static u64 lookup_ino(u64 ino_from)
{
	return do_lookup_ino(tree, ino_from);
}

static void insert_ino(u64 ino_from, u64 ino_to)
{
	struct node *node = malloc(sizeof(struct node));
	if (!node)
		error(L"Out of memory");
	node->ino_from = ino_from;
	node->ino_to   = ino_to;
	node->left     = NULL;
	node->right    = NULL;
	if (!tree)
		tree = node;
	else
		do_insert(tree, node);
}

static HANDLE
win32_open_file_readonly(const wchar_t *path)
{
	HANDLE hFile = CreateFile(path,
				  GENERIC_READ | ACCESS_SYSTEM_SECURITY,
				  FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
				  NULL,
				  OPEN_EXISTING,
				  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
				  NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		win32_error(L"Failed to open file %ls read-only", path);
	return hFile;
}

static size_t
get_reparse_data(HANDLE hFile, const wchar_t *path,
		 char *rpdata)
{
	DWORD bytesReturned = 0;
	if (!DeviceIoControl(hFile,
			     FSCTL_GET_REPARSE_POINT,
			     NULL, /* "Not used with this operation; set to NULL" */
			     0, /* "Not used with this operation; set to 0" */
			     rpdata, /* "A pointer to a buffer that
						   receives the reparse point data */
			     REPARSE_POINT_MAX_SIZE, /* "The size of the output
							buffer, in bytes */
			     &bytesReturned,
			     NULL))
		win32_error(L"Can't get reparse data from %ls", path);
	return bytesReturned;
}

static void
cmp_reparse_data(HANDLE hFile_1, const wchar_t *path_1,
		 HANDLE hFile_2, const wchar_t *path_2)
{
	char rpdata_1[REPARSE_POINT_MAX_SIZE];
	char rpdata_2[REPARSE_POINT_MAX_SIZE];
	size_t len_1;
	size_t len_2;

	len_1 = get_reparse_data(hFile_1, path_1, rpdata_1);
	len_2 = get_reparse_data(hFile_2, path_2, rpdata_2);
	if (len_1 != len_2 || memcmp(rpdata_1, rpdata_2, len_1)) {
		error(L"Reparse point data for %ls and %ls differs",
		      path_1, path_2);
	}
}

struct win32_stream_wrapper {
	struct win32_stream_wrapper *next;
	WIN32_FIND_STREAM_DATA dat;
};

static int
qsort_cmp_streams_by_name(const void *p1, const void *p2)
{
	const WIN32_FIND_STREAM_DATA *s1 = p1, *s2 = p2;
	return wcscmp(s1->cStreamName, s2->cStreamName);
}

static WIN32_FIND_STREAM_DATA *
get_stream_array(const wchar_t *path, size_t *nstreams_ret)
{
	WIN32_FIND_STREAM_DATA dat;
	WIN32_FIND_STREAM_DATA *array = NULL;
	WIN32_FIND_STREAM_DATA *p;
	size_t nstreams = 0;
	struct win32_stream_wrapper *stream_list = NULL;
	HANDLE hFind;

	hFind = FindFirstStreamW(path, FindStreamInfoStandard, &dat, 0);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			struct win32_stream_wrapper *wrapper;

			wrapper = malloc(sizeof(*wrapper));
			if (!wrapper)
				error(L"out of memory");
			memcpy(&wrapper->dat, &dat, sizeof(dat));
			wrapper->next = stream_list;
			stream_list = wrapper;
			nstreams++;
		} while (FindNextStreamW(hFind, &dat));
	}
	if (GetLastError() != ERROR_HANDLE_EOF)
		win32_error(L"Can't lookup streams from %ls", path);
	if (hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);
	array = malloc(nstreams * sizeof(array[0]));
	p = array;
	while (stream_list) {
		struct win32_stream_wrapper *next;

		memcpy(p, &stream_list->dat, sizeof(*p));
		next = stream_list->next;
		free(stream_list);
		stream_list = next;
		p++;
	}
	assert(p - array == nstreams);
	qsort(array, nstreams, sizeof(array[0]), qsort_cmp_streams_by_name);
	*nstreams_ret = nstreams;
	return array;
}

static const wchar_t *
fix_stream_name(wchar_t *stream_name)
{
	wchar_t *colon;

	/* The stream name should be returned as :NAME:TYPE */
	if (stream_name[0] != L':')
		return NULL;
	colon = wcschr(stream_name + 1, L':');
	if (!colon)
		return NULL;
	if (wcscmp(colon + 1, L"$DATA"))
		return NULL;
	*colon = L'\0';
	if (stream_name == colon - 1)
		stream_name = colon;
	return stream_name;
}

#define BUFSIZE 32768

static void
cmp_data(HANDLE hFile_1, const wchar_t *path_1,
	 HANDLE hFile_2, const wchar_t *path_2, u64 size)
{
	u8 buf_1[BUFSIZE];
	u8 buf_2[BUFSIZE];
	u64 bytes_remaining = size;
	DWORD bytesRead;
	DWORD bytesToRead;

	while (bytes_remaining) {
		bytesToRead = BUFSIZE;
		if (bytesToRead > bytes_remaining)
			bytesToRead = bytes_remaining;
		if (!ReadFile(hFile_1, buf_1, bytesToRead, &bytesRead, NULL) ||
		    bytesRead != bytesToRead)
		{
			win32_error(L"Error reading from %ls", path_1);
		}
		if (!ReadFile(hFile_2, buf_2, bytesToRead, &bytesRead, NULL) ||
		    bytesRead != bytesToRead)
		{
			win32_error(L"Error reading from %ls", path_2);
		}
		if (memcmp(buf_1, buf_2, bytesToRead))
			error(L"Data of %ls and %ls differs", path_1, path_2);
		bytes_remaining -= bytesToRead;
	}
}

static void
cmp_stream(wchar_t *path_1, size_t path_1_len, WIN32_FIND_STREAM_DATA *dat_1,
	   wchar_t *path_2, size_t path_2_len, WIN32_FIND_STREAM_DATA *dat_2)
{
	const wchar_t *stream_name;

	if (wcscmp(dat_1->cStreamName, dat_2->cStreamName)) {
		error(L"%ls%ls and %ls%ls are not named the same",
		      path_1, dat_1->cStreamName,
		      path_2, dat_2->cStreamName);
	}
	if (dat_1->StreamSize.QuadPart != dat_2->StreamSize.QuadPart) {
		error(L"%ls%ls (%"PRIu64" bytes) and %ls%ls "
		      "(%"PRIu64" bytes) are not the same size",
		      path_1, dat_1->cStreamName, dat_1->StreamSize.QuadPart,
		      path_2, dat_2->cStreamName, dat_2->StreamSize.QuadPart);
	}

	stream_name = fix_stream_name(dat_1->cStreamName);

	if (!stream_name)
		return;

	wcscpy(&path_1[path_1_len], stream_name);
	wcscpy(&path_2[path_2_len], stream_name);

	HANDLE hFile_1 = win32_open_file_readonly(path_1);
	HANDLE hFile_2 = win32_open_file_readonly(path_2);

	cmp_data(hFile_1, path_1, hFile_2, path_2,
		 dat_1->StreamSize.QuadPart);

	CloseHandle(hFile_1);
	CloseHandle(hFile_2);
	path_1[path_1_len] = L'\0';
	path_2[path_2_len] = L'\0';
}

static void
cmp_streams(wchar_t *path_1, size_t path_1_len,
	    wchar_t *path_2, size_t path_2_len)
{
	WIN32_FIND_STREAM_DATA *streams_1, *streams_2;
	size_t nstreams_1, nstreams_2;
	size_t i;

	streams_1 = get_stream_array(path_1, &nstreams_1);
	streams_2 = get_stream_array(path_2, &nstreams_2);

	if (nstreams_1 != nstreams_2) {
		error(L"%ls and %ls do not have the same number of streams",
		      path_1, path_2);
	}

	for (i = 0; i < nstreams_1; i++)
		cmp_stream(path_1, path_1_len, &streams_1[i],
			   path_2, path_2_len, &streams_2[i]);
	free(streams_1);
	free(streams_2);
}

struct win32_dentry_wrapper {
	struct win32_dentry_wrapper *next;
	WIN32_FIND_DATA dat;
};

static int
qsort_cmp_dentries_by_name(const void *p1, const void *p2)
{
	const WIN32_FIND_DATA *d1 = p1, *d2 = p2;
	return wcscmp(d1->cFileName, d2->cFileName);
}

static WIN32_FIND_DATA *
get_dentry_array(wchar_t *path, size_t path_len, size_t *ndentries_ret)
{
	WIN32_FIND_DATA dat;
	WIN32_FIND_DATA *array = NULL;
	WIN32_FIND_DATA *p;
	size_t ndentries = 0;
	struct win32_dentry_wrapper *dentry_list = NULL;
	HANDLE hFind;
	DWORD err;

	path[path_len] = L'\\';
	path[path_len + 1] = L'*';
	path[path_len + 2] = L'\0';
	hFind = FindFirstFile(path, &dat);
	path[path_len] = L'\0';
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			struct win32_dentry_wrapper *wrapper;

			wrapper = malloc(sizeof(*wrapper));
			if (!wrapper)
				error(L"out of memory");
			memcpy(&wrapper->dat, &dat, sizeof(dat));
			wrapper->next = dentry_list;
			dentry_list = wrapper;
			ndentries++;
		} while (FindNextFile(hFind, &dat));
	}
	err = GetLastError();
	if (err != ERROR_NO_MORE_FILES && err != ERROR_FILE_NOT_FOUND)
		win32_error(L"Can't lookup dentries from %ls", path);
	if (hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);
	array = malloc(ndentries * sizeof(array[0]));
	p = array;
	while (dentry_list) {
		struct win32_dentry_wrapper *next;

		memcpy(p, &dentry_list->dat, sizeof(*p));
		next = dentry_list->next;
		free(dentry_list);
		dentry_list = next;
		p++;
	}
	assert(p - array == ndentries);
	qsort(array, ndentries, sizeof(array[0]), qsort_cmp_dentries_by_name);
	*ndentries_ret = ndentries;
	return array;
}

static void
tree_cmp(wchar_t *path_1, size_t path_1_len, wchar_t *path_2, size_t path_2_len);

static void
recurse_directory(wchar_t *path_1, size_t path_1_len,
		  wchar_t *path_2, size_t path_2_len)
{
	WIN32_FIND_DATA *dentries_1, *dentries_2;
	size_t ndentries_1, ndentries_2;
	size_t i;

	dentries_1 = get_dentry_array(path_1, path_1_len, &ndentries_1);
	dentries_2 = get_dentry_array(path_2, path_2_len, &ndentries_2);

	if (ndentries_1 != ndentries_2) {
		error(L"%ls and %ls do not have the same number of dentries",
		      path_1, path_2);
	}

	path_1[path_1_len] = L'\\';
	path_2[path_2_len] = L'\\';
	for (i = 0; i < ndentries_1; i++) {
		size_t name_1_len, name_2_len;

		name_1_len = wcslen(dentries_1[i].cFileName);
		name_2_len = wcslen(dentries_2[i].cFileName);
		wmemcpy(&path_1[path_1_len + 1], dentries_1[i].cFileName, name_1_len + 1);
		wmemcpy(&path_2[path_2_len + 1], dentries_2[i].cFileName, name_2_len + 1);

		if (wcscmp(dentries_1[i].cFileName,
			   dentries_2[i].cFileName))
			error(L"%ls and %ls do not have the same name",
			      path_1, path_2);

		if (wcscmp(dentries_1[i].cAlternateFileName,
			   dentries_2[i].cAlternateFileName))
			error(L"%ls and %ls do not have the same short name",
			      path_1, path_2);

		if (!wcscmp(dentries_1[i].cFileName, L".") ||
		    !wcscmp(dentries_2[i].cFileName, L".."))
			continue;
		tree_cmp(path_1, path_1_len + 1 + name_1_len,
			 path_2, path_2_len + 1 + name_2_len);
	}
	path_1[path_1_len] = L'\0';
	path_2[path_2_len] = L'\0';
	free(dentries_1);
	free(dentries_2);
}

static int
file_times_equal(const FILETIME *t1, const FILETIME *t2)
{
	return t1->dwLowDateTime == t2->dwLowDateTime &&
	       t1->dwHighDateTime == t2->dwHighDateTime;
}

static void *
get_security(const wchar_t *path, size_t *len_ret)
{
	DWORD lenNeeded;
	DWORD requestedInformation = DACL_SECURITY_INFORMATION |
				     SACL_SECURITY_INFORMATION |
				     OWNER_SECURITY_INFORMATION |
				     GROUP_SECURITY_INFORMATION;
	void *descr;
	BOOL bret;


	bret = GetFileSecurity(path, requestedInformation,
			       NULL, 0, &lenNeeded);

	if (bret || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		goto err;
	descr = malloc(lenNeeded);
	if (!descr)
		error(L"out of memory");
	if (!GetFileSecurity(path, requestedInformation, descr, lenNeeded,
			     &lenNeeded))
		goto err;
	*len_ret = lenNeeded;
	return descr;
err:
	win32_error(L"Can't read security descriptor of %ls", path);
}

static void
cmp_security(const wchar_t *path_1, const wchar_t *path_2)
{
	void *descr_1, *descr_2;
	size_t len_1, len_2;

	descr_1 = get_security(path_1, &len_1);
	descr_2 = get_security(path_2, &len_2);

	if (len_1 != len_2 || memcmp(descr_1, descr_2, len_1))
		error(L"%ls and %ls do not have the same security descriptor",
		      path_1, path_2);
	free(descr_1);
	free(descr_2);
}

static void
tree_cmp(wchar_t *path_1, size_t path_1_len, wchar_t *path_2, size_t path_2_len)
{
	HANDLE hFile_1, hFile_2;
	BY_HANDLE_FILE_INFORMATION file_info_1, file_info_2;
	u64 size_1, size_2;
	u64 ino_1, ino_2;
	u64 ino_to;
	DWORD attribs;

	hFile_1 = win32_open_file_readonly(path_1);
	hFile_2 = win32_open_file_readonly(path_2);
	if (!GetFileInformationByHandle(hFile_1, &file_info_1))
		win32_error(L"Failed to get file information for %ls", path_1);
	if (!GetFileInformationByHandle(hFile_2, &file_info_2))
		win32_error(L"Failed to get file information for %ls", path_2);

	if (file_info_1.dwFileAttributes != file_info_2.dwFileAttributes) {
		error(L"Attributes for %ls (%#x) differ from attributes for %ls (%#x)",
		      path_1, (unsigned)file_info_1.dwFileAttributes,
		      path_2, (unsigned)file_info_2.dwFileAttributes);
	}

	size_1 = ((u64)file_info_1.nFileSizeHigh << 32) |
			file_info_1.nFileSizeLow;
	size_2 = ((u64)file_info_2.nFileSizeHigh << 32) |
			file_info_2.nFileSizeLow;
	if (size_1 != size_2) {
		error(L"Size for %ls (%"PRIu64") differs from size for %ls (%"PRIu64")",
		      path_1, size_1, path_2, size_2);
	}
	if (file_info_1.nNumberOfLinks != file_info_2.nNumberOfLinks) {
		error(L"Number of links for %ls (%u) differs from number "
		      "of links for %ls (%u)",
		      path_1, (unsigned)file_info_1.nNumberOfLinks,
		      path_2, (unsigned)file_info_2.nNumberOfLinks);
	}
	ino_1 = ((u64)file_info_1.nFileIndexHigh << 32) |
			file_info_1.nFileIndexLow;
	ino_2 = ((u64)file_info_2.nFileIndexHigh << 32) |
			file_info_2.nFileIndexLow;
	ino_to = lookup_ino(ino_1);
	if (ino_to == -1)
		insert_ino(ino_1, ino_2);
	else if (ino_to != ino_2)
		error(L"Inode number on %ls is wrong", path_2);

	if (!file_times_equal(&file_info_1.ftCreationTime, &file_info_2.ftCreationTime))
		error(L"Creation times on %ls and %ls differ",
		      path_1, path_2);

	if (!file_times_equal(&file_info_1.ftLastWriteTime, &file_info_2.ftLastWriteTime))
		error(L"Last write times on %ls and %ls differ",
		      path_1, path_2);

	attribs = file_info_1.dwFileAttributes;

	cmp_security(path_1, path_2);
	cmp_streams(path_1, path_1_len, path_2, path_2_len);
	if (attribs & FILE_ATTRIBUTE_REPARSE_POINT)
		cmp_reparse_data(hFile_1, path_1, hFile_2, path_2);
	else if (attribs & FILE_ATTRIBUTE_DIRECTORY)
		recurse_directory(path_1, path_1_len, path_2, path_2_len);
	CloseHandle(hFile_1);
	CloseHandle(hFile_2);
}

static void
enable_privilege(const wchar_t *privilege)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES newState;

	if (!OpenProcessToken(GetCurrentProcess(),
			      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		win32_error(L"Failed to open process token");

	if (!LookupPrivilegeValueW(NULL, privilege, &luid))
		win32_error(L"Failed to look up privileges %ls", privilege);

	newState.PrivilegeCount = 1;
	newState.Privileges[0].Luid = luid;
	newState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL))
		win32_error(L"Failed to acquire privilege %ls", privilege);
	CloseHandle(hToken);
}

int wmain(int argc, wchar_t **argv, wchar_t **envp)
{
	wchar_t dir_1[32769], dir_2[32769];
	size_t len_1, len_2;

	if (argc != 3) {
		fwprintf(stderr, L"Usage: win32-tree-cmp DIR1 DIR2\n");
		return 2;
	}

	enable_privilege(SE_BACKUP_NAME);
	enable_privilege(SE_SECURITY_NAME);

	len_1 = wcslen(argv[1]);
	len_2 = wcslen(argv[2]);
	wmemcpy(dir_1, argv[1], len_1 + 1);
	wmemcpy(dir_2, argv[2], len_2 + 1);
	tree_cmp(dir_1, len_1, dir_2, len_2);
	return 0;
}
