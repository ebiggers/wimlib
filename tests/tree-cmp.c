/*
 * A program to compare directory trees
 *
 * There are two modes:
 * 	- Normal mode for any filesystems.  We compare file names, contents,
 * 	sizes, modes, access times, and hard links.
 * 	- NTFS mode for NTFS-3G mounted volumes.  In this mode we need to
 * 	  compare various NTFS-specific attributes such as named data streams
 * 	  and DOS names.
 *
 * Both modes compare hard link groups between the two directory trees.  If two
 * files are hard linked together in one directory tree, exactly the same two
 * files are expected to be hard linked together in the other directory tree.
 */

#include "config.h"


#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#ifdef HAVE_ATTR_XATTR_H
#include <attr/xattr.h>
#endif
#include <assert.h>

typedef uint64_t u64;

#if 0
#	define DEBUG(format, ...)					\
	({								\
 		int __errno_save = errno;				\
		fprintf(stdout, "[%s %d] %s(): " format,		\
			__FILE__, __LINE__, __func__, ## __VA_ARGS__);	\
	 	putchar('\n');						\
		fflush(stdout);						\
		errno = __errno_save;					\
	})
#else
#define DEBUG(format, ...)
#endif
static bool ntfs_mode = false;

static void difference(const char *format, ...)
{
	va_list va;
	va_start(va, format);
	fflush(stdout);
	fputs("tree-cmp: ", stderr);
	vfprintf(stderr, format, va);
	putc('\n', stderr);
	fflush(stderr);
	va_end(va);
	exit(1);
}

static void error(const char *format, ...)
{
	va_list va;
	int err = errno;
	va_start(va, format);
	fflush(stdout);
	fputs("tree-cmp: ", stderr);
	vfprintf(stderr, format, va);
	fprintf(stderr, ": %s\n", strerror(err));
	va_end(va);
	exit(2);
}

/* This is just a binary tree that maps inode numbers in one NTFS tree to inode
 * numbers in the other NTFS tree.  This is so we can tell if the hard link
 * groups are the same between the two NTFS trees.  */
struct node {
	u64 ino_from;
	u64 ino_to;
	struct node *left;
	struct node *right;
};

static struct node *tree = NULL;

static const char *root1, *root2;

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
		error("Out of memory");
	node->ino_from = ino_from;
	node->ino_to   = ino_to;
	node->left     = NULL;
	node->right    = NULL;
	if (!tree)
		tree = node;
	else
		do_insert(tree, node);
}


/* Compares the "normal" contents of two files of size @size. */
static void cmp(const char *file1, const char *file2, size_t size)
{
	int fd1, fd2;
	char buf1[4096], buf2[4096];
	ssize_t to_read = 4096;
	fd1 = open(file1, O_RDONLY);
	if (fd1 == -1)
		error("Could not open `%s'", file1);
	fd2 = open(file2, O_RDONLY);
	if (fd2 == -1)
		error("Could not open `%s'", file2);
	for (; size; size -= to_read) {
		if (to_read > size)
			to_read = size;
		if (read(fd1, buf1, to_read) != to_read)
			error("Error reading `%s'", file1);
		if (read(fd2, buf2, to_read) != to_read)
			error("Error reading `%s'", file2);
		if (memcmp(buf1, buf2, to_read))
			difference("File contents of `%s' and `%s' differ",
				   file1, file2);
	}
	close(fd1);
	close(fd2);
}

#ifdef HAVE_ATTR_XATTR_H
/* Compares an extended attribute of the files. */
static void cmp_xattr(const char *file1, const char *file2,
		      const char *xattr_name, ssize_t max_size,
		      bool missingok)
{
	ssize_t len1, len2;
	char *buf1, *buf2;
	DEBUG("cmp xattr \"%s\" of files %s, %s", xattr_name, file1, file2);
	len1 = lgetxattr(file1, xattr_name, NULL, 0);
	if (len1 == -1) {
		if (errno == ENOATTR) {
			if (missingok) {
				errno = 0;
				lgetxattr(file2, xattr_name, NULL, 0);
				if (errno == ENOATTR)
					return;
				else
					difference("xattr `%s' exists on file `%s' "
					      "but not on file `%s'",
					      xattr_name, file1, file2);
			} else {
				error("Could not find attribute `%s' of `%s'",
				      xattr_name, file1);
			}
		} else {
			error("Could not read xattr `%s' of `%s'",
			      xattr_name, file1);
		}
	}
	buf1 = malloc(len1);
	buf2 = malloc(len1);
	if (!buf1 || !buf2)
		error("Out of memory");
	if (lgetxattr(file1, xattr_name, buf1, len1) != len1)
		error("Could not read xattr `%s' of `%s'",
		      xattr_name, file1);

	len2 = lgetxattr(file2, xattr_name, buf2, len1);
	if (len2 == len1) {
		if (memcmp(buf1, buf2,
			   (max_size == 0 || len1 <= max_size) ? len1 : max_size))
		{
			difference("xattr `%s' of files `%s' and `%s' differs",
				   xattr_name, file1, file2);
		}
	} else {
		if (len2 == -1) {
			error("Could not read xattr `%s' from `%s'",
			      xattr_name, file2);
		}
		if (len1 != len2)
			difference("xattr `%s' of files `%s' and `%s' differs",
				   xattr_name, file1, file2);
	}
	free(buf1);
	free(buf2);
}

/* Compares all alternate data streams of the files */
static void cmp_ads(const char *file1, const char *file2)
{
	char _list1[256], _list2[sizeof(_list1)];
	char *list1 = _list1, *list2 = _list2;
	char *pe, *p;
	ssize_t len1, len2, tmp;
	errno = 0;
	len1 = llistxattr(file1, list1, sizeof(_list1));
	if (len1 == -1) {
		if (errno != ERANGE || ((len1 = llistxattr(file1, NULL, 0) == -1)))
			error("Could not get xattr list of `%s'", file1);
		list1 = malloc(len1);
		list2 = malloc(len1);
		if (!list1 || !list2)
			error("Out of memory");
		tmp = llistxattr(file1, list1, len1);
		if (tmp == -1)
			error("Could not get xattr list of `%s'", file1);
		if (tmp != len1)
			error("xattr list of `%s' changed as we read it",
			      file1);
	}
	errno = 0;
	len2 = llistxattr(file2, list2, len1);
	if (len1 == -1) {
		if (errno == ERANGE)
			difference("`%s' and `%s' do not have the same "
				   "xattr list", file1, file2);
		else
			error("Could not get xattr list of `%s'", file2);
	}
	if (len1 != len2 || memcmp(list1, list2, len1))
		difference("`%s' and `%s' do not have the same "
			   "xattr list", file1, file2);
	p = list1;
	pe = list1 + len1 - 1;
	while (p < pe) {
		cmp_xattr(file1, file2, p, 0, false);
		p += strlen(p) + 1;
	}
	if (list1 != _list1) {
		free(list1);
		free(list2);
	}
}
#endif

/* Compares special NTFS data of the files, as accessed through extended
 * attributes. */
static void special_cmp(const char *file1, const char *file2)
{
#ifdef HAVE_ATTR_XATTR_H
	cmp_xattr(file1, file2, "system.ntfs_acl", 0, false);
	cmp_xattr(file1, file2, "system.ntfs_attrib", 0, false);
	cmp_xattr(file1, file2, "system.ntfs_dos_name", 0, true);
	cmp_xattr(file1, file2, "system.ntfs_object_id", 64, true);
	cmp_xattr(file1, file2, "system.ntfs_reparse_data", 0, true);
	cmp_xattr(file1, file2, "system.ntfs_times", 16, false);
	cmp_ads(file1, file2);
#else
	fprintf(stderr, "tree-cmp: Warning: cannot compare xattrs of `%s' and `%s'\n",
			file1, file2);
	fprintf(stderr, "          You need to install the attr development files for this.\n");
#endif
}


/* Recursively compares directory tree rooted at file1 to directory tree rooted at file2 */
static void tree_cmp(char file1[], int file1_len, char file2[], int file2_len)
{
	struct stat st1, st2;
	u64 ino_from, ino_to;

	DEBUG("cmp files %s, %s", file1, file2);
	if (lstat(file1, &st1))
		error("Failed to stat `%s'", file1);
	if (lstat(file2, &st2))
		error("Failed to stat `%s'", file2);
	ino_from = st1.st_ino;
	ino_to = lookup_ino(ino_from);
	if (ino_to == -1)
		insert_ino(ino_from, st2.st_ino);
	else if (ino_to != st2.st_ino)
		difference("Inode number on `%s' is wrong", file2);
	if ((st1.st_mode & ~(S_IRWXU | S_IRWXG | S_IRWXO)) !=
	    (st2.st_mode & ~(S_IRWXU | S_IRWXG | S_IRWXO)))
		difference("Modes of `%s' and `%s' are not the same",
			   file1, file2);
	if (S_ISREG(st1.st_mode) && st1.st_size != st2.st_size)
		difference("Sizes of `%s' and `%s' are not the same",
			   file1, file2);
#if 0
	if (ntfs_mode && st1.st_atime != st2.st_atime)
		difference("Access times of `%s' and `%s' are not the same",
			   file1, file2);
	if (st1.st_mtime != st2.st_mtime)
		difference("Modification times of `%s' (%x) and `%s' (%x) are "
		           "not the same",
			   file1, st1.st_mtime, file2, st2.st_mtime);
	if (st1.st_ctime != st2.st_ctime)
		difference("Status change times of `%s' and `%s' are not the same",
			   file1, file2);
#endif
	if ((ntfs_mode || S_ISREG(st1.st_mode)) && st1.st_nlink != st2.st_nlink)
		difference("Link count of `%s' (%u) and `%s' (%u) "
			   "are not the same",
			   file1, st1.st_nlink, file2, st2.st_nlink);
	if (ntfs_mode && strcmp(file1, root1) != 0)
		special_cmp(file1, file2);
	if (S_ISREG(st1.st_mode))
		cmp(file1, file2, st1.st_size);
	else if (S_ISDIR(st1.st_mode)) {
		int ret1, ret2;
		int i;
		struct dirent **namelist1, **namelist2;
		const char *dir1 = file1, *dir2 = file2;

		ret1 = scandir(dir1, &namelist1, NULL, alphasort);
		if (ret1 == -1)
			error("Error scanning directory `%s'", dir1);
		ret2 = scandir(dir2, &namelist2, NULL, alphasort);
		if (ret2 == -1)
			error("Error scanning directory `%s'", dir2);
		if (ret1 != ret2)
			difference("Directories `%s' and `%s' do not contain "
				   "the same number of entries", dir1, dir2);
		file1[file1_len] = '/';
		file2[file2_len] = '/';
		for (i = 0; i < ret1; i++) {
			int name_len;
			const char *name;
			if (strcmp(namelist1[i]->d_name, namelist2[i]->d_name)) {
				difference("Files `%s' and `%s' in directories "
					   "`%s' and `%s', respectively, do "
					   "not have the same name",
					   namelist1[i]->d_name,
					   namelist2[i]->d_name,
					   dir1, dir2);
			}
			name = namelist1[i]->d_name;
			name_len = strlen(name);
			if (!(name[0] == '.' &&
			      (name[1] == '\0' ||
			       (name[1] == '.' && name[2] == '\0'))))
			{
				memcpy(file1 + file1_len + 1, name, name_len + 1);
				memcpy(file2 + file2_len + 1, name, name_len + 1);
				tree_cmp(file1, file1_len + 1 + name_len,
					 file2, file2_len + 1 + name_len);
			}

			free(namelist1[i]);
			free(namelist2[i]);
		}
		free(namelist1);
		free(namelist2);
		file1[file1_len] = '\0';
		file2[file2_len] = '\0';
	} else if (!ntfs_mode && S_ISLNK(st1.st_mode)) {
		char buf1[4096], buf2[sizeof(buf1)];
		ssize_t ret1, ret2;
		ret1 = readlink(file1, buf1, sizeof(buf1));
		if (ret1 == -1)
			error("Failed to get symlink target of `%s'", file1);
		ret2 = readlink(file2, buf2, sizeof(buf2));
		if (ret2 == -1)
			error("Failed to get symlink target of `%s'", file2);
		if (ret1 != ret2 || memcmp(buf1, buf2, ret1))
			error("Symlink targets of `%s' and `%s' differ",
			      file1, file2);
	}
}

int main(int argc, char **argv)
{
	if (argc != 3 && argc != 4) {
		fprintf(stderr, "Usage: %s DIR1 DIR2 [NTFS]", argv[0]);
		return 2;
	}
	if (argc > 3 && strcmp(argv[3], "NTFS") == 0)
		ntfs_mode = true;

	char dir1[4096];
	char dir2[4096];
	strcpy(dir1, argv[1]);
	strcpy(dir2, argv[2]);
	root1 = argv[1];
	root2 = argv[2];
	tree_cmp(dir1, strlen(dir1), dir2, strlen(dir2));
	return 0;
}
