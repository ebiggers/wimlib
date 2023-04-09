/*
 * wlfuzz.c - Randomized tests for wimlib
 */

/*
 * Copyright 2015-2023 Eric Biggers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * This program is a randomized test runner for wimlib.  It must be linked
 * against a build of the library compiled with --enable-test-support.
 *
 * Various types of tests are run. Most important is the "apply and capture"
 * test, which works as follows:
 *
 *	1. Generate an in-memory WIM image containing a random directory tree
 *	2. Persist the image into a WIM file
 *	3. Apply the WIM image to somewhere
 *	4. Re-capture the applied image
 *	5. Compare the directory tree of the re-captured image to the original
 *
 * Note that this is an "apply and capture" test, not a "capture and apply"
 * test.  By using the filesystem as the intermediary rather than as the
 * starting point and ending point, the tests will run nearly unchanged
 * regardless of filesystem type (e.g. UNIX, Windows, or NTFS-3G).  This style
 * of test has been effective at finding bugs in wimlib as well as bugs in
 * NTFS-3G where its behavior differs from that of Windows.
 *
 * Care is taken to exercise different options, such as different compression
 * formats, when multiple are available.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifndef ENABLE_TEST_SUPPORT
#  error "This program requires that wimlib was configured with --enable-test-support."
#endif

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef WITH_NTFS_3G
#  include <sys/wait.h>
#endif
#include <unistd.h>

#ifdef _WIN32
#  include <windows.h>
#  include <winternl.h>
#  include <ntstatus.h>
#else
#  include <linux/magic.h>
#  include <sys/vfs.h>
#endif

#include "wimlib.h"
#include "wimlib_tchar.h"
#include "wimlib/test_support.h"
#include "wimlib/wof.h"

#ifndef O_BINARY
#  define O_BINARY 0
#endif

#define ARRAY_LEN(A)	(sizeof(A) / sizeof((A)[0]))

#define TMP_TARGET_NAME	T("wlfuzz-tmp-target")
#define MAX_NUM_WIMS		4

static bool wimfile_in_use[MAX_NUM_WIMS];
static int in_use_wimfile_indices[MAX_NUM_WIMS];
static int num_wimfiles_in_use = 0;
#ifndef _WIN32
static u32 filesystem_type;
#endif

static void
assertion_failed(int line, const char *format, ...)
{
	va_list va;

	va_start(va, format);
	fprintf(stderr, "ASSERTION FAILED at line %d: ", line);
	vfprintf(stderr, format, va);
	fputc('\n', stderr);
	va_end(va);

	exit(1);
}

#define ASSERT(expr, msg, ...)						\
({									\
	if (__builtin_expect(!(expr), 0))				\
		assertion_failed(__LINE__, (msg), ##__VA_ARGS__);	\
})

#define CHECK_RET(ret)							\
({									\
	int r = (ret);							\
	ASSERT(!r, "%"TS, wimlib_get_error_string(r));			\
})

static void
change_to_temporary_directory(void)
{
#ifdef _WIN32
	const wchar_t *tmpdir = _wgetenv(T("TMPDIR"));

	ASSERT(tmpdir != NULL, "TMPDIR must be set");
	_wmkdir(tmpdir);
	ASSERT(!_wchdir(tmpdir),
	       "failed to change to temporary directory '%ls'", tmpdir);
#else /* _WIN32 */
	const char *tmpdir = getenv("TMPDIR") ?: P_tmpdir;
	struct statfs fs;

	mkdir(tmpdir, 0700);
	ASSERT(!chdir(tmpdir),
	       "failed to change to temporary directory '%s': %m", tmpdir);
	ASSERT(!statfs(".", &fs), "statfs of '%s' failed: %m", tmpdir);
	filesystem_type = fs.f_type;
#endif /* !_WIN32 */
}

static void __attribute__((unused))
copy_file(const tchar *src, const tchar *dst)
{
	int in_fd = topen(src, O_RDONLY|O_BINARY);
	int out_fd = topen(dst, O_WRONLY|O_TRUNC|O_CREAT|O_BINARY, 0644);
	char buf[32768];
	ssize_t bytes_read, bytes_written, i;

	ASSERT(in_fd >= 0, "%"TS": open error: %m", src);
	ASSERT(out_fd >= 0, "%"TS": open error: %m", dst);
	while ((bytes_read = read(in_fd, buf, sizeof(buf))) > 0) {
		for (i = 0; i < bytes_read; i += bytes_written) {
			bytes_written = write(out_fd, &buf[i], bytes_read - i);
			ASSERT(bytes_written > 0, "%"TS": write error: %m", dst);
		}
	}
	ASSERT(bytes_read == 0, "%"TS": read error: %m", src);
	close(in_fd);
	close(out_fd);
}

#ifdef WITH_NTFS_3G
static void
create_ntfs_volume(const char *name)
{
	int fd;
	int pid;
	int status;
	static const char buffer[1] = {0};

	fd = open(name, O_WRONLY|O_TRUNC|O_CREAT|O_NOFOLLOW, 0644);
	ASSERT(fd >= 0, "%s: open error: %m", name);

	ASSERT(lseek(fd, 999999999, SEEK_SET) != -1, "%s: lseek error: %m", name);

	ASSERT(write(fd, buffer, 1) == 1, "%s: write error: %m", name);

	ASSERT(close(fd) == 0, "%s: close error: %m", name);

	pid = fork();
	ASSERT(pid >= 0, "fork error: %m");
	if (pid == 0) {
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		execlp("mkntfs", "mkntfs", "--force", "--fast",
		       name, (char *)NULL);
		ASSERT(false, "Failed to execute mkntfs: %m");
	}

	ASSERT(wait(&status) != -1, "wait error: %m");
	ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	       "mkntfs error: exited with status %d", status);
}
#endif /* WITH_NTFS_3G */

#ifdef _WIN32

WINAPI NTSTATUS NtQueryDirectoryFile(HANDLE FileHandle,
				     HANDLE Event,
				     PIO_APC_ROUTINE ApcRoutine,
				     PVOID ApcContext,
				     PIO_STATUS_BLOCK IoStatusBlock,
				     PVOID FileInformation,
				     ULONG Length,
				     FILE_INFORMATION_CLASS FileInformationClass,
				     BOOLEAN ReturnSingleEntry,
				     PUNICODE_STRING FileName,
				     BOOLEAN RestartScan);

static void
delete_directory_tree_recursive(HANDLE cur_dir, UNICODE_STRING *name)
{
	OBJECT_ATTRIBUTES attr = { .Length = sizeof(attr), };
	IO_STATUS_BLOCK iosb;
	FILE_BASIC_INFORMATION basic = { .FileAttributes = FILE_ATTRIBUTE_NORMAL, };
	HANDLE h;
	const size_t bufsize = 8192;
	void *buf;
	NTSTATUS status;
	ULONG perms;
	ULONG flags;

	flags = FILE_DELETE_ON_CLOSE |
		      FILE_OPEN_REPARSE_POINT |
		      FILE_OPEN_FOR_BACKUP_INTENT |
		      FILE_SYNCHRONOUS_IO_NONALERT |
		      FILE_SEQUENTIAL_ONLY;

	name->MaximumLength = name->Length;

	attr.RootDirectory = cur_dir;
	attr.ObjectName = name;

	perms = DELETE | SYNCHRONIZE | FILE_LIST_DIRECTORY | FILE_TRAVERSE;
retry:
	status = NtOpenFile(&h, perms, &attr, &iosb, FILE_SHARE_VALID_FLAGS, flags);
	if (!NT_SUCCESS(status)) {
		if (status == STATUS_OBJECT_NAME_NOT_FOUND)
			return;
		if (status == STATUS_CANNOT_DELETE && (perms & DELETE)) {
			perms &= ~DELETE;
			flags &= ~FILE_DELETE_ON_CLOSE;
			perms |= FILE_WRITE_ATTRIBUTES;
			goto retry;
		}
		ASSERT(false, "NtOpenFile() for deletion failed; status=0x%08"PRIx32, status);
	}
	if (perms & FILE_WRITE_ATTRIBUTES) {
		status = NtSetInformationFile(h, &iosb, &basic,
					      sizeof(basic), FileBasicInformation);
		NtClose(h);
		if (!NT_SUCCESS(status)) {
			ASSERT(false, "NtSetInformationFile() for deletion "
			       "failed; status=0x%08"PRIx32, status);
		}
		perms &= ~FILE_WRITE_ATTRIBUTES;
		perms |= DELETE;
		flags |= FILE_DELETE_ON_CLOSE;
		goto retry;
	}

	buf = malloc(bufsize);
	ASSERT(buf != NULL, "out of memory!");

	while (NT_SUCCESS(status = NtQueryDirectoryFile(h, NULL, NULL, NULL,
							&iosb, buf, bufsize,
							FileNamesInformation,
							FALSE, NULL, FALSE)))
	{
		const FILE_NAMES_INFORMATION *info = buf;
		for (;;) {
			if (!(info->FileNameLength == 2 && info->FileName[0] == L'.') &&
			    !(info->FileNameLength == 4 && info->FileName[0] == L'.' &&
							   info->FileName[1] == L'.'))
			{
				name->Buffer = (wchar_t *)info->FileName;
				name->Length = info->FileNameLength;
				delete_directory_tree_recursive(h, name);
			}
			if (info->NextEntryOffset == 0)
				break;
			info = (const FILE_NAMES_INFORMATION *)
					((const char *)info + info->NextEntryOffset);
		}
	}

	ASSERT(status == STATUS_NO_MORE_FILES || /* end of directory  */
	       status == STATUS_INVALID_PARAMETER, /* not a directory  */
	       "NtQueryDirectoryFile() for deletion failed; "
	       "status=0x%08"PRIx32, status);

	free(buf);
	NtClose(h);
}

static void
delete_directory_tree(const wchar_t *name)
{
	UNICODE_STRING uname;
	void *buffer;

	ASSERT(RtlDosPathNameToNtPathName_U(name, &uname, NULL, NULL),
	       "Unable to translate %ls to NT namespace path", name);
	buffer = uname.Buffer;
	delete_directory_tree_recursive(NULL, &uname);
	HeapFree(GetProcessHeap(), 0, buffer);
	ASSERT(GetFileAttributes(name) == 0xFFFFFFFF, "Deletion didn't work!");
}

#else /* _WIN32 */

static void
delete_directory_tree_recursive(int dirfd, const char *name)
{
	int fd;
	DIR *dir;
	struct dirent *ent;

	if (!unlinkat(dirfd, name, 0) || errno == ENOENT)
		return;
	ASSERT(errno == EISDIR, "%s: unlink error: %m", name);

	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_DIRECTORY);
	ASSERT(fd >= 0, "%m");

	dir = fdopendir(fd);
	ASSERT(dir != NULL, "%m");
	while (errno = 0, (ent = readdir(dir)))
		if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, ".."))
			delete_directory_tree_recursive(fd, ent->d_name);
	closedir(dir);

	ASSERT(!unlinkat(dirfd, name, AT_REMOVEDIR), "%m");
}

static void
delete_directory_tree(const tchar *name)
{
	delete_directory_tree_recursive(AT_FDCWD, name);
}

#endif /* !_WIN32 */

static u64 random_state;

static u32
rand32(void)
{
	/* A simple linear congruential generator */
	random_state = (random_state * 25214903917 + 11) % (1ULL << 48);
	return random_state >> 16;
}

static bool
randbool(void)
{
	return rand32() % 2;
}

static u64
rand64(void)
{
	return ((u64)rand32() << 32) | rand32();
}

static tchar wimfile[32];

static const tchar *
get_wimfile(int index)
{
	tsprintf(wimfile, T("wim%d"), index);
	return wimfile;
}

static int
select_random_wimfile_index(void)
{
	return in_use_wimfile_indices[rand32() % num_wimfiles_in_use];
}

static const tchar *
select_new_wimfile(void)
{
	int index = 0;

	while (wimfile_in_use[index])
		index++;

	in_use_wimfile_indices[num_wimfiles_in_use++] = index;
	wimfile_in_use[index] = true;

	return get_wimfile(index);
}

static WIMStruct *
open_wim(int index)
{
	const tchar *wimfile = get_wimfile(index);
	WIMStruct *wim;
	int open_flags = 0;

	open_flags |= randbool() ? 0 : WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;

	printf("Opening %"TS" with flags 0x%08x\n", wimfile, open_flags);

	CHECK_RET(wimlib_open_wim(wimfile, open_flags, &wim));

	return wim;
}

static WIMStruct *
open_random_wim(void)
{
	return open_wim(select_random_wimfile_index());
}

static int
get_image_count(WIMStruct *wim)
{
	struct wimlib_wim_info info;

	CHECK_RET(wimlib_get_wim_info(wim, &info));

	return info.image_count;
}

#ifdef _WIN32
static bool
is_wimboot_capable(WIMStruct *wim)
{
	struct wimlib_wim_info info;

	CHECK_RET(wimlib_get_wim_info(wim, &info));

	return info.wim_version == 0x10D00 &&
		((info.compression_type == WIMLIB_COMPRESSION_TYPE_XPRESS &&
		  (info.chunk_size == 4096 || info.chunk_size == 8192 ||
		   info.chunk_size == 16384 || info.chunk_size == 32768)) ||
		 (info.compression_type == WIMLIB_COMPRESSION_TYPE_LZX &&
		  info.chunk_size == 32768));
}
#endif /* _WIN32 */

static void
overwrite_wim(WIMStruct *wim)
{
	int write_flags = 0;
	struct wimlib_wim_info info;

	CHECK_RET(wimlib_get_wim_info(wim, &info));

	switch (rand32() % 4) {
	case 0:
		write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
		break;
	case 1:
		write_flags |= WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY;
		break;
	}

	switch (rand32() % 8) {
	case 0:
		write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
		break;
	case 1:
		write_flags |= WIMLIB_WRITE_FLAG_NOT_PIPABLE;
		break;
	}

	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_RECOMPRESS;
	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_FSYNC;
	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_REBUILD;
	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_SOFT_DELETE;
	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_IGNORE_READONLY_FLAG;
	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_RETAIN_GUID;
	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_SEND_DONE_WITH_FILE_MESSAGES;
	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_NO_SOLID_SORT;

	if (rand32() % 8 == 0 &&
	    !(write_flags & WIMLIB_WRITE_FLAG_PIPABLE) &&
	    (!info.pipable || (write_flags & WIMLIB_WRITE_FLAG_NOT_PIPABLE)))
		write_flags |= WIMLIB_WRITE_FLAG_SOLID;

	if (randbool() && !info.pipable &&
	    !(write_flags & (WIMLIB_WRITE_FLAG_RECOMPRESS |
			     WIMLIB_WRITE_FLAG_PIPABLE)))
		write_flags |= WIMLIB_WRITE_FLAG_UNSAFE_COMPACT;

	printf("overwrite with flags: 0x%08x\n", write_flags);

	CHECK_RET(wimlib_overwrite(wim, write_flags, 0));
}

static int
get_random_write_flags(void)
{
	int write_flags = 0;

	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_SEND_DONE_WITH_FILE_MESSAGES;
	write_flags |= randbool() ? 0 : WIMLIB_WRITE_FLAG_NO_SOLID_SORT;
	switch (rand32() % 8) {
	case 0:
		write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
		break;
	case 1:
		write_flags |= WIMLIB_WRITE_FLAG_SOLID;
		break;
	}

	return write_flags;
}

static u32
get_random_chunk_size(int min_order, int max_order)
{
	return 1 << (min_order + (rand32() % (max_order - min_order + 1)));
}

static void
op__create_new_wim(void)
{
	printf(":::op__create_new_wim\n");

	const tchar *wimfile;
	enum wimlib_compression_type ctype = WIMLIB_COMPRESSION_TYPE_NONE;
	u32 chunk_size = 0;
	u32 solid_chunk_size = 0;
	int write_flags;
	WIMStruct *wim;

	if (num_wimfiles_in_use == MAX_NUM_WIMS)
		return;

	wimfile = select_new_wimfile();

	/* Select a random compression type and chunk size.  */
	switch (rand32() % 4) {
	case 0:
		break;
	case 1:
		ctype = WIMLIB_COMPRESSION_TYPE_XPRESS;
		chunk_size = get_random_chunk_size(12, 16);
		break;
	case 2:
		ctype = WIMLIB_COMPRESSION_TYPE_LZX;
		if (randbool())
			chunk_size = 1 << 15;
		else
			chunk_size = get_random_chunk_size(15, 21);
		break;
	case 3:
		ctype = WIMLIB_COMPRESSION_TYPE_LZMS;
		chunk_size = get_random_chunk_size(15, 28);
		if (randbool())
			solid_chunk_size = get_random_chunk_size(15, 26);
		else
			solid_chunk_size = get_random_chunk_size(26, 28);
		break;
	}

	/* Select random write flags.  */
	write_flags = get_random_write_flags();

	printf("Creating %"TS" with write flags 0x%08x, compression_type=%"TS", chunk_size=%u, solid_chunk_size=%u\n",
	       wimfile, write_flags,
	       wimlib_get_compression_type_string(ctype),
	       chunk_size, solid_chunk_size);

	CHECK_RET(wimlib_create_new_wim(ctype, &wim));
	if (chunk_size != 0)
		CHECK_RET(wimlib_set_output_chunk_size(wim, chunk_size));
	if (solid_chunk_size != 0)
		CHECK_RET(wimlib_set_output_pack_chunk_size(wim, solid_chunk_size));

	CHECK_RET(wimlib_write(wim, wimfile, WIMLIB_ALL_IMAGES, write_flags, 0));

	wimlib_free(wim);
}

static void
op__add_empty_image_to_random_wim(void)
{
	printf(":::op__add_empty_image_to_random_wim\n");

	WIMStruct *wim;
	int new_idx;

	if (num_wimfiles_in_use < 1)
		return;

	wim = open_random_wim();
	CHECK_RET(wimlib_add_empty_image(wim, NULL, &new_idx));
	printf("Adding empty image to %"TS" at index %d\n", wimfile, new_idx);
	overwrite_wim(wim);
	wimlib_free(wim);
}

static void
op__delete_random_image_from_random_wim(void)
{
	printf(":::op__delete_random_image_from_random_wim\n");

	WIMStruct *wim;
	int image;
	int image_count;

	if (num_wimfiles_in_use == 0)
		return;

	wim = open_random_wim();
	image_count = get_image_count(wim);
	if (image_count != 0) {
		image = 1 + (rand32() % image_count);
		CHECK_RET(wimlib_delete_image(wim, image));
		printf("Deleting image %d from %"TS"\n", image, wimfile);
		overwrite_wim(wim);
	}
	wimlib_free(wim);
}

static void
op__delete_random_wim(void)
{
	printf(":::op__delete_random_wim\n");

	const tchar *wimfile;
	int which;
	int index;

	if (num_wimfiles_in_use == 0)
		return;

	which = rand32() % num_wimfiles_in_use;
	index = in_use_wimfile_indices[which];

	wimfile = get_wimfile(index);

	ASSERT(!tunlink(wimfile), "failed to unlink %"TS": %m", wimfile);

	printf("Deleted %"TS"\n", wimfile);

	for (int i = which; i < num_wimfiles_in_use - 1; i++)
		in_use_wimfile_indices[i] = in_use_wimfile_indices[i + 1];
	num_wimfiles_in_use--;
	wimfile_in_use[index] = false;
}

static void
op__verify_random_wim(void)
{
	printf(":::op__verify_random_wim\n");

	WIMStruct *wim;

	if (num_wimfiles_in_use == 0)
		return;

	wim = open_random_wim();
	CHECK_RET(wimlib_verify_wim(wim, 0));
	printf("Verified %"TS"\n", wimfile);
	wimlib_free(wim);
}

static void
op__overwrite_with_no_changes(void)
{
	printf(":::op__overwrite_with_no_changes\n");

	WIMStruct *wim;

	if (num_wimfiles_in_use == 0)
		return;

	wim = open_random_wim();
	overwrite_wim(wim);
	wimlib_free(wim);
}

static void
op__export_random_image(void)
{
	printf(":::op__export_random_image\n");

	int src_wimfile_index;
	int dst_wimfile_index;
	WIMStruct *src_wim;
	WIMStruct *dst_wim;
	int src_image_count;
	int dst_image_count;
	int src_image;
	int dst_image;

	if (num_wimfiles_in_use < 2)
		return;

	src_wimfile_index = select_random_wimfile_index();
	do {
		dst_wimfile_index = select_random_wimfile_index();
	} while (dst_wimfile_index == src_wimfile_index);

	src_wim = open_wim(src_wimfile_index);
	dst_wim = open_wim(dst_wimfile_index);

	src_image_count = get_image_count(src_wim);
	dst_image_count = get_image_count(dst_wim);

	/* Choose a random source image --- single or all.  */
	src_image = WIMLIB_ALL_IMAGES;
	if (src_image_count != 0 && randbool())
		src_image = 1 + (rand32() % src_image_count);

	printf("Exporting image %d of %d from wim %d into wim %d\n",
	       src_image, src_image_count, src_wimfile_index, dst_wimfile_index);
	CHECK_RET(wimlib_export_image(src_wim, src_image, dst_wim, NULL, NULL, 0));

	overwrite_wim(dst_wim);
	wimlib_free(dst_wim);

	dst_wim = open_wim(dst_wimfile_index);

	/* Compare the images.  */
	dst_image = dst_image_count;
	for (int image = (src_image == WIMLIB_ALL_IMAGES ? 1 : src_image);
	     image <= (src_image == WIMLIB_ALL_IMAGES ? src_image_count : src_image);
	     image++)
	{
		CHECK_RET(wimlib_compare_images(src_wim, image, dst_wim, ++dst_image, 0));
	}

	wimlib_free(src_wim);
	wimlib_free(dst_wim);
}

static void
op__apply_and_capture_test(void)
{
	printf(":::op__apply_and_capture_test\n");

	WIMStruct *wim;
	int image;
	int index;
	int extract_flags = 0;
	int add_flags = 0;
	int cmp_flags = 0;

	if (num_wimfiles_in_use == 0)
		return;

	/* Generate a random image.  */
	index = select_random_wimfile_index();
	wim = open_wim(index);

	CHECK_RET(wimlib_add_image(wim, (void *)rand32, NULL, NULL,
				   WIMLIB_ADD_FLAG_GENERATE_TEST_DATA |
				   WIMLIB_ADD_FLAG_NORPFIX));

	image = get_image_count(wim);

	printf("generated wim%d image %d\n", index, image);

	{
		/*
		 * Compare the in-memory version of the generated image with a
		 * version written to disk
		 */
		WIMStruct *tmp_wim;

		CHECK_RET(wimlib_write(wim, T("tmp.wim"), image, 0, 0));
		CHECK_RET(wimlib_open_wim(T("tmp.wim"), 0, &tmp_wim));
		CHECK_RET(wimlib_compare_images(wim, image, tmp_wim, 1, 0));
		wimlib_free(tmp_wim);
	}

	overwrite_wim(wim);
	wimlib_free(wim);

	/* Apply the generated image.  */
	wim = open_wim(index);
	delete_directory_tree(TMP_TARGET_NAME);
#ifdef WITH_NTFS_3G
	if (rand32() & 1) {
		printf("applying in NTFS mode\n");
		extract_flags |= WIMLIB_EXTRACT_FLAG_NTFS;
		extract_flags |= WIMLIB_EXTRACT_FLAG_STRICT_ACLS;
		extract_flags |= WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES;
		extract_flags |= WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS;
		add_flags |= WIMLIB_ADD_FLAG_NTFS;
		cmp_flags |= WIMLIB_CMP_FLAG_NTFS_3G_MODE;
		create_ntfs_volume(TMP_TARGET_NAME);
	} else
#endif
	{
#ifdef _WIN32
		printf("applying in Windows mode\n");
		cmp_flags |= WIMLIB_CMP_FLAG_WINDOWS_MODE;
#else /* _WIN32 */
		printf("applying in UNIX mode\n");
		extract_flags |= WIMLIB_EXTRACT_FLAG_UNIX_DATA;
		add_flags |= WIMLIB_ADD_FLAG_UNIX_DATA;
		cmp_flags |= WIMLIB_CMP_FLAG_UNIX_MODE;
		if (filesystem_type == EXT4_SUPER_MAGIC)
			cmp_flags |= WIMLIB_CMP_FLAG_EXT4;
#endif /* !_WIN32 */
	}
	add_flags |= WIMLIB_ADD_FLAG_NORPFIX;
	CHECK_RET(wimlib_extract_image(wim, image, TMP_TARGET_NAME,
				       extract_flags));

	/* Sometimes extract twice so that we test overwriting existing files.
	 */
	if (!(extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) && randbool()) {
		CHECK_RET(wimlib_extract_image(wim, image, TMP_TARGET_NAME,
					       extract_flags));
	}

	/* Capture the applied image.  */
	CHECK_RET(wimlib_add_image(wim, TMP_TARGET_NAME, NULL, NULL, add_flags));
	overwrite_wim(wim);
	wimlib_free(wim);

	/* Compare the generated image with the captured image.  */
	wim = open_wim(index);
	CHECK_RET(wimlib_compare_images(wim, image, wim, image + 1, cmp_flags));
	wimlib_free(wim);
}

#ifdef _WIN32

/*
 * Enumerate and unregister all backing WIMs from the volume containing the
 * current directory.
 */
static void
unregister_all_backing_wims(void)
{
	wchar_t full_path[MAX_PATH];
	DWORD path_len;
	wchar_t volume[7];
	HANDLE h;
	void *overlay_list;
	DWORD bytes_returned;
	const WIM_PROVIDER_OVERLAY_ENTRY *entry;
	struct {
		WOF_EXTERNAL_INFO wof_info;
		WIM_PROVIDER_REMOVE_OVERLAY_INPUT wim;
	} in;

	path_len = GetFullPathName(L".", ARRAY_LEN(full_path), full_path, NULL);
	ASSERT(path_len > 0,
	       "Failed to get full path of current directory; error=%u",
	       (unsigned)GetLastError());

	wsprintf(volume, L"\\\\.\\%lc:", full_path[0]);
	h = CreateFile(volume, GENERIC_READ | GENERIC_WRITE,
		       FILE_SHARE_VALID_FLAGS, NULL, OPEN_EXISTING,
		       FILE_FLAG_BACKUP_SEMANTICS, NULL);
	ASSERT(h != INVALID_HANDLE_VALUE,
	       "Failed to open %ls; error=%u", volume, (unsigned)GetLastError());

	overlay_list = malloc(32768);
	ASSERT(overlay_list != NULL, "out of memory");

	in.wof_info.Version = WOF_CURRENT_VERSION;
	in.wof_info.Provider = WOF_PROVIDER_WIM;

	if (!DeviceIoControl(h, FSCTL_ENUM_OVERLAY,
			     &in, sizeof(WOF_EXTERNAL_INFO),
			     overlay_list, 32768, &bytes_returned, NULL))
	{
		ASSERT(GetLastError() == ERROR_INVALID_FUNCTION ||
		       GetLastError() == ERROR_INVALID_PARAMETER ||
		       GetLastError() == ERROR_FILE_NOT_FOUND,
		       "FSCTL_ENUM_OVERLAY failed; error=%u", GetLastError());
		return;
	}

	entry = overlay_list;
	for (;;) {
		printf("Unregistering data source ID %"PRIu64"\n",
		       entry->DataSourceId.QuadPart);
		in.wim.DataSourceId = entry->DataSourceId;
		ASSERT(DeviceIoControl(h, FSCTL_REMOVE_OVERLAY, &in, sizeof(in),
				       NULL, 0, &bytes_returned, NULL),
		       "FSCTL_REMOVE_OVERLAY failed; error=%u",
		       (unsigned)GetLastError());
		if (entry->NextEntryOffset == 0)
			break;
		entry = (const WIM_PROVIDER_OVERLAY_ENTRY *)
			((const u8 *)entry + entry->NextEntryOffset);
	}
	free(overlay_list);
	CloseHandle(h);
}

static void
op__wimboot_test(void)
{
	int index;
	int index2;
	WIMStruct *wim;
	WIMStruct *wim2;
	int image_count;
	int image;

	if (num_wimfiles_in_use == 0)
		return;

	index = select_random_wimfile_index();

	unregister_all_backing_wims();
	copy_file(get_wimfile(index), L"wimboot.wim");

	CHECK_RET(wimlib_open_wim(L"wimboot.wim", 0, &wim));

	image_count = get_image_count(wim);
	if (image_count == 0 || !is_wimboot_capable(wim)) {
		wimlib_free(wim);
		return;
	}


	image = 1 + (rand32() % image_count);

	printf("WIMBOOT test; wim%d image %d\n", index, image);

	delete_directory_tree(TMP_TARGET_NAME);

	CHECK_RET(wimlib_extract_image(wim, image, TMP_TARGET_NAME,
				       WIMLIB_EXTRACT_FLAG_WIMBOOT));

	if (randbool()) {
		CHECK_RET(wimlib_extract_image(wim, image, TMP_TARGET_NAME,
					       WIMLIB_EXTRACT_FLAG_WIMBOOT));
	}

	index2 = select_random_wimfile_index();
	wim2 = open_wim(index2);
	image_count = get_image_count(wim2);

	CHECK_RET(wimlib_add_image(wim2, TMP_TARGET_NAME, NULL, NULL,
				   WIMLIB_ADD_FLAG_NORPFIX));

	overwrite_wim(wim2);
	wimlib_free(wim2);

	wim2 = open_wim(index2);

	printf("comparing wimboot.wim:%d with wim%d:%d\n",
	       image, index2, image_count + 1);

	CHECK_RET(wimlib_compare_images(wim, image, wim2, image_count + 1,
					WIMLIB_CMP_FLAG_WINDOWS_MODE));

	wimlib_free(wim);
	wimlib_free(wim2);
}
#endif /* _WIN32 */

static int
is_solid_resource(const struct wimlib_resource_entry *resource, void *_ctx)
{
	return resource->packed;
}

static bool
wim_contains_solid_resources(WIMStruct *wim)
{
	return wimlib_iterate_lookup_table(wim, 0, is_solid_resource, NULL);
}

static void
op__split_test(void)
{
	printf(":::op__split_test\n");

	WIMStruct *wim;
	WIMStruct *swm;
	WIMStruct *joined_wim;
	u64 part_size;
	int write_flags;
	const tchar *globs[] = { T("tmp*.swm") };
	int image_count;

	if (num_wimfiles_in_use == 0)
		return;

	/* split, join, and compare  */

	wim = open_random_wim();

	if (wim_contains_solid_resources(wim)) {
		/* Can't split a WIM containing solid resources  */
		wimlib_free(wim);
		return;
	}

	image_count = get_image_count(wim);

	part_size = 10000 + (rand32() % 1000000);
	write_flags = get_random_write_flags();
	write_flags &= ~WIMLIB_WRITE_FLAG_SOLID;

	printf("splitting WIM %"TS": part_size=%"PRIu64", write_flags=0x%08x\n",
	       wimfile, part_size, write_flags);

	CHECK_RET(wimlib_split(wim, T("tmp.swm"), part_size, write_flags));

	CHECK_RET(wimlib_open_wim(T("tmp.swm"), WIMLIB_OPEN_FLAG_CHECK_INTEGRITY,
				  &swm));

	CHECK_RET(wimlib_reference_resource_files(swm, globs, 1,
						  WIMLIB_REF_FLAG_GLOB_ENABLE |
							WIMLIB_REF_FLAG_GLOB_ERR_ON_NOMATCH,
						  WIMLIB_OPEN_FLAG_CHECK_INTEGRITY));

	CHECK_RET(wimlib_verify_wim(swm, 0));

	CHECK_RET(wimlib_write(swm, T("joined.wim"), WIMLIB_ALL_IMAGES, write_flags, 0));
	wimlib_free(swm);

	CHECK_RET(wimlib_open_wim(T("joined.wim"), 0, &joined_wim));
	for (int i = 1; i <= image_count; i++)
		CHECK_RET(wimlib_compare_images(wim, 1, joined_wim, 1, 0));
	CHECK_RET(wimlib_verify_wim(joined_wim, 0));
	wimlib_free(joined_wim);
	wimlib_free(wim);

	tunlink(T("tmp.swm"));
	for (int i = 2; ; i++) {
		tchar name[32];
		tsprintf(name, T("tmp%d.swm"), i);
		if (tunlink(name))
			break;
	}
}

static void
op__set_compression_level(void)
{
	printf(":::op__set_compression_level\n");

	unsigned int level = rand32() % 100;
	printf("Changing compression levels to %d\n", level);
	wimlib_set_default_compression_level(-1, level);
}

typedef void (*operation_func)(void);

static const operation_func operation_table[] = {
	op__create_new_wim,
	op__add_empty_image_to_random_wim,
	op__delete_random_image_from_random_wim,
	op__delete_random_wim,
	op__delete_random_wim,
	op__verify_random_wim,
	op__overwrite_with_no_changes,
	op__export_random_image,
	op__apply_and_capture_test,
	op__apply_and_capture_test,
	op__apply_and_capture_test,
	op__apply_and_capture_test,
	op__apply_and_capture_test,
	op__split_test,
	op__set_compression_level,
#ifdef _WIN32
	op__wimboot_test,
#endif
};

#ifdef _WIN32
int wmain(int argc, wchar_t **argv);
#define main wmain
#endif

int
main(int argc, tchar **argv)
{
	unsigned long time_limit = 0;
	time_t start_time;
	u64 i;

	/* If you want to make the tests deterministic, delete this line. */
	random_state = ((u64)time(NULL) << 16) ^ getpid();

	if (argc >= 2)
		time_limit = tstrtoul(argv[1], NULL, 10);

	if (time_limit == 0)
		printf("Starting wlfuzz with no time limit\n");
	else
		printf("Starting wlfuzz with time limit of %lu seconds\n",
		       time_limit);

	CHECK_RET(wimlib_global_init(WIMLIB_INIT_FLAG_STRICT_APPLY_PRIVILEGES |
				     WIMLIB_INIT_FLAG_STRICT_CAPTURE_PRIVILEGES));
	wimlib_set_print_errors(true);
	wimlib_seed_random(rand64());

	change_to_temporary_directory();

	for (i = 0; i < MAX_NUM_WIMS; i++)
		ASSERT(!tunlink(get_wimfile(i)) || errno == ENOENT, "unlink: %m");

	i = 0;
	start_time = time(NULL);
	while (time_limit == 0 || time(NULL) < start_time + time_limit) {
		printf("--> iteration %"PRIu64"\n", ++i);
		(*operation_table[rand32() % ARRAY_LEN(operation_table)])();
	}

	wimlib_global_cleanup();
	return 0;
}
