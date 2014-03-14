/*
 * mount_image.c
 *
 * This file implements mounting of WIM files using FUSE, which stands for
 * Filesystem in Userspace.  FUSE allows a filesystem to be implemented in a
 * userspace process by implementing the filesystem primitives--- read(),
 * write(), readdir(), etc.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/error.h"

#ifdef WITH_FUSE

#ifdef __WIN32__
#  error "FUSE mount not supported on Win32!  Please configure --without-fuse"
#endif

#include "wimlib/encoding.h"
#include "wimlib/file_io.h"
#include "wimlib/dentry.h"
#include "wimlib/inode.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/reparse.h"
#include "wimlib/resource.h"
#include "wimlib/timestamp.h"
#include "wimlib/version.h"
#include "wimlib/write.h"
#include "wimlib/xml.h"

#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <mqueue.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#ifdef ENABLE_XATTR
#include <attr/xattr.h>
#endif

#define MSG_VERSION_TOO_HIGH	-1
#define MSG_BREAK_LOOP		-2

/* File descriptor to a file open on the WIM filesystem. */
struct wimfs_fd {
	struct wim_inode *f_inode;
	struct wim_lookup_table_entry *f_lte;
	struct filedes staging_fd;
	u16 idx;
	u32 stream_id;
};

struct wimfs_context {
	/* The WIMStruct for the mounted WIM. */
	WIMStruct *wim;

	/* Name of the staging directory for a read-write mount.  Whenever a new file is
	 * created, it is done so in the staging directory.  Furthermore, whenever a
	 * file in the WIM is modified, it is extracted to the staging directory.  If
	 * changes are commited when the WIM is unmounted, the file resources are merged
	 * in from the staging directory when writing the new WIM. */
	char *staging_dir_name;
	size_t staging_dir_name_len;

	/* Flags passed to wimlib_mount(). */
	int mount_flags;

	/* Default flags to use when looking up a WIM dentry (depends on whether
	 * the Windows interface to alternate data streams is being used or
	 * not). */
	int default_lookup_flags;

	/* Next inode number to be assigned.  Note: I didn't bother with a
	 * bitmap of free inode numbers since this isn't even a "real"
	 * filesystem anyway. */
	u64 next_ino;

	/* List of inodes in the mounted image */
	struct list_head *image_inode_list;

	/* Original list of streams in the mounted image, linked by
	 * mount_orig_stream_list.  */
	struct list_head orig_stream_list;

	/* Name and message queue descriptors for message queues between the
	 * filesystem daemon process and the unmount process.  These are used
	 * when the filesystem is unmounted and the process running
	 * wimlib_unmount_image() needs to communicate with the filesystem
	 * daemon running fuse_main() (i.e. the process created by a call to
	 * wimlib_mount_image().  */
	char *unmount_to_daemon_mq_name;
	char *daemon_to_unmount_mq_name;
	mqd_t unmount_to_daemon_mq;
	mqd_t daemon_to_unmount_mq;

	uid_t default_uid;
	gid_t default_gid;

	int status;
	bool have_status;
};

static void
init_wimfs_context(struct wimfs_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->unmount_to_daemon_mq = (mqd_t)-1;
	ctx->daemon_to_unmount_mq = (mqd_t)-1;
}

#define WIMFS_CTX(fuse_ctx) ((struct wimfs_context*)(fuse_ctx)->private_data)

static inline struct wimfs_context *
wimfs_get_context(void)
{
	return WIMFS_CTX(fuse_get_context());
}

static inline WIMStruct *
wimfs_get_WIMStruct(void)
{
	return wimfs_get_context()->wim;
}

static inline int
get_lookup_flags(const struct wimfs_context *ctx)
{
	return ctx->default_lookup_flags;
}

/* Returns nonzero if write permission is requested on the file open flags */
static inline int
flags_writable(int open_flags)
{
	int accmode = (open_flags & O_ACCMODE);
	return (accmode == O_RDWR || accmode == O_WRONLY);
}

/*
 * Allocate a file descriptor for a stream.
 *
 * @inode:	inode containing the stream we're opening
 * @stream_id:	ID of the stream we're opening
 * @lte:	Lookup table entry for the stream (may be NULL)
 * @fd_ret:	Return the allocated file descriptor if successful.
 *
 * Return 0 iff successful or negative error code if unsuccessful.
 */
static int
alloc_wimfs_fd(struct wim_inode *inode,
	       u32 stream_id,
	       struct wim_lookup_table_entry *lte,
	       struct wimfs_fd **fd_ret)
{
	static const u16 fds_per_alloc = 8;
	static const u16 max_fds = 0xffff;

	DEBUG("Allocating fd for stream ID %u from inode %#"PRIx64" "
	      "(open = %u, allocated = %u)",
	      stream_id, inode->i_ino, inode->i_num_opened_fds,
	      inode->i_num_allocated_fds);

	if (inode->i_num_opened_fds == inode->i_num_allocated_fds) {
		struct wimfs_fd **fds;
		u16 num_new_fds;

		if (inode->i_num_allocated_fds == max_fds)
			return -EMFILE;

		num_new_fds = min(fds_per_alloc,
				  max_fds - inode->i_num_allocated_fds);

		fds = REALLOC(inode->i_fds,
			      (inode->i_num_allocated_fds + num_new_fds) *
			        sizeof(inode->i_fds[0]));
		if (!fds)
			return -ENOMEM;

		memset(&fds[inode->i_num_allocated_fds], 0,
		       num_new_fds * sizeof(fds[0]));
		inode->i_fds = fds;
		inode->i_num_allocated_fds += num_new_fds;
	}
	for (u16 i = 0; ; i++) {
		if (!inode->i_fds[i]) {
			struct wimfs_fd *fd = CALLOC(1, sizeof(*fd));
			if (!fd)
				return -ENOMEM;

			fd->f_inode     = inode;
			fd->f_lte       = lte;
			filedes_invalidate(&fd->staging_fd);
			fd->idx         = i;
			fd->stream_id   = stream_id;
			*fd_ret         = fd;
			inode->i_fds[i] = fd;
			inode->i_num_opened_fds++;
			if (lte)
				lte->num_opened_fds++;
			DEBUG("Allocated fd (idx = %u)", fd->idx);
			return 0;
		}
	}
}

static void
inode_put_fd(struct wim_inode *inode, struct wimfs_fd *fd)
{
	wimlib_assert(inode != NULL);
	wimlib_assert(fd->f_inode == inode);
	wimlib_assert(inode->i_num_opened_fds != 0);
	wimlib_assert(fd->idx < inode->i_num_allocated_fds);
	wimlib_assert(inode->i_fds[fd->idx] == fd);

	inode->i_fds[fd->idx] = NULL;
	FREE(fd);
	if (--inode->i_num_opened_fds == 0) {
		FREE(inode->i_fds);
		inode->i_fds = NULL;
		inode->i_num_allocated_fds = 0;
		if (inode->i_nlink == 0)
			free_inode(inode);
	}
}

static int
lte_put_fd(struct wim_lookup_table_entry *lte, struct wimfs_fd *fd)
{
	wimlib_assert(fd->f_lte == lte);

	if (!lte) /* Empty stream with no lookup table entry */
		return 0;

	/* Close staging file descriptor if needed. */

	if (lte->resource_location == RESOURCE_IN_STAGING_FILE
	     && filedes_valid(&fd->staging_fd))
	{
		if (filedes_close(&fd->staging_fd)) {
			ERROR_WITH_ERRNO("Failed to close staging file");
			return -errno;
		}
	}
	lte_decrement_num_opened_fds(lte);
	return 0;
}

/* Close a file descriptor. */
static int
close_wimfs_fd(struct wimfs_fd *fd)
{
	int ret;
	DEBUG("Closing fd (ino = %#"PRIx64", opened = %u, allocated = %u)",
	      fd->f_inode->i_ino, fd->f_inode->i_num_opened_fds,
	      fd->f_inode->i_num_allocated_fds);
	ret = lte_put_fd(fd->f_lte, fd);
	if (ret)
		return ret;

	inode_put_fd(fd->f_inode, fd);
	return 0;
}

static mode_t
fuse_mask_mode(mode_t mode, struct fuse_context *fuse_ctx)
{
#if FUSE_MAJOR_VERSION > 2 || (FUSE_MAJOR_VERSION == 2 && FUSE_MINOR_VERSION >= 8)
	mode &= ~fuse_ctx->umask;
#endif
	return mode;
}

/*
 * Add a new dentry with a new inode to a WIM image.
 *
 * Returns 0 on success, or negative error number on failure.
 */
static int
create_dentry(struct fuse_context *fuse_ctx, const char *path,
	      mode_t mode, int attributes, struct wim_dentry **dentry_ret)
{
	struct wim_dentry *parent;
	struct wim_dentry *new;
	const char *basename;
	struct wimfs_context *wimfs_ctx = WIMFS_CTX(fuse_ctx);
	int ret;

	parent = get_parent_dentry(wimfs_ctx->wim, path, WIMLIB_CASE_SENSITIVE);
	if (!parent)
		return -errno;

	if (!dentry_is_directory(parent))
		return -ENOTDIR;

	basename = path_basename(path);
	if (get_dentry_child_with_name(parent, basename, WIMLIB_CASE_SENSITIVE))
		return -EEXIST;

	ret = new_dentry_with_inode(basename, &new);
	if (ret)
		return -ENOMEM;

	new->d_inode->i_resolved = 1;
	new->d_inode->i_ino = wimfs_ctx->next_ino++;
	new->d_inode->i_attributes = attributes;

	if (wimfs_ctx->mount_flags & WIMLIB_MOUNT_FLAG_UNIX_DATA) {
		if (inode_set_unix_data(new->d_inode,
					fuse_ctx->uid,
					fuse_ctx->gid,
					fuse_mask_mode(mode, fuse_ctx),
					wimfs_ctx->wim->lookup_table,
					UNIX_DATA_ALL | UNIX_DATA_CREATE))
		{
			free_dentry(new);
			return -ENOMEM;
		}
	}
	dentry_add_child(parent, new);
	list_add_tail(&new->d_inode->i_list, wimfs_ctx->image_inode_list);
	if (dentry_ret)
		*dentry_ret = new;
	return 0;
}

static struct wim_inode *
wim_pathname_to_inode(WIMStruct *wim, const tchar *path)
{
	struct wim_dentry *dentry;
	dentry = get_dentry(wim, path, WIMLIB_CASE_SENSITIVE);
	if (dentry)
		return dentry->d_inode;
	else
		return NULL;
}

/* Remove a dentry from a mounted WIM image; i.e. remove an alias for the
 * corresponding inode.
 *
 * If there are no remaining references to the inode either through dentries or
 * open file descriptors, the inode is freed.  Otherwise, the inode is not
 * removed, but the dentry is unlinked and freed.
 *
 * Either way, all lookup table entries referenced by the inode have their
 * reference count decremented.  If a lookup table entry has no open file
 * descriptors and no references remaining, it is freed, and the corresponding
 * staging file is unlinked.
 */
static void
remove_dentry(struct wim_dentry *dentry,
	      struct wim_lookup_table *lookup_table)
{
	struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table_entry *lte;
	unsigned i;

	for (i = 0; i <= inode->i_num_ads; i++) {
		lte = inode_stream_lte(inode, i, lookup_table);
		if (lte)
			lte_decrement_refcnt(lte, lookup_table);
	}
	unlink_dentry(dentry);
	free_dentry(dentry);
}

static mode_t
inode_default_unix_mode(const struct wim_inode *inode)
{
	if (inode_is_symlink(inode))
		return S_IFLNK | 0777;
	else if (inode_is_directory(inode))
		return S_IFDIR | 0777;
	else
		return S_IFREG | 0777;
}

/* Transfers file attributes from a struct wim_inode to a `stat' buffer.
 *
 * The lookup table entry tells us which stream in the inode we are statting.
 * For a named data stream, everything returned is the same as the unnamed data
 * stream except possibly the size and block count. */
static int
inode_to_stbuf(const struct wim_inode *inode,
	       const struct wim_lookup_table_entry *lte,
	       struct stat *stbuf)
{
	const struct wimfs_context *ctx = wimfs_get_context();

	memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_mode = inode_default_unix_mode(inode);
	stbuf->st_uid = ctx->default_uid;
	stbuf->st_gid = ctx->default_gid;
	if (ctx->mount_flags & WIMLIB_MOUNT_FLAG_UNIX_DATA) {
		struct wimlib_unix_data unix_data;
		if (inode_get_unix_data(inode, &unix_data, NULL) == 0) {
			stbuf->st_uid = unix_data.uid;
			stbuf->st_gid = unix_data.gid;
			stbuf->st_mode = unix_data.mode;
		}
	}
	stbuf->st_ino = (ino_t)inode->i_ino;
	stbuf->st_nlink = inode->i_nlink;
	if (lte)
		stbuf->st_size = lte->size;
	else
		stbuf->st_size = 0;
#ifdef HAVE_STAT_NANOSECOND_PRECISION
	stbuf->st_atim = wim_timestamp_to_timespec(inode->i_last_access_time);
	stbuf->st_mtim = wim_timestamp_to_timespec(inode->i_last_write_time);
	stbuf->st_ctim = stbuf->st_mtim;
#else
	stbuf->st_atime = wim_timestamp_to_unix(inode->i_last_access_time);
	stbuf->st_mtime = wim_timestamp_to_unix(inode->i_last_write_time);
	stbuf->st_ctime = stbuf->st_mtime;
#endif
	stbuf->st_blocks = (stbuf->st_size + 511) / 512;
	return 0;
}

static void
touch_inode(struct wim_inode *inode)
{
	u64 now = get_wim_timestamp();
	inode->i_last_access_time = now;
	inode->i_last_write_time = now;
}

/* Creates a new staging file and returns its file descriptor opened for
 * writing.
 *
 * @name_ret: A location into which the a pointer to the newly allocated name of
 *	      the staging file is stored.
 *
 * @ctx:      Context for the WIM filesystem; this provides the name of the
 *	      staging directory.
 *
 * On success, returns the file descriptor for the staging file, opened for
 * writing.  On failure, returns -1 and sets errno.
 */
static int
create_staging_file(char **name_ret, struct wimfs_context *ctx)
{
	size_t name_len;
	char *name;
	struct stat stbuf;
	int fd;
	int errno_save;

	static const size_t STAGING_FILE_NAME_LEN = 20;

	name_len = ctx->staging_dir_name_len + 1 + STAGING_FILE_NAME_LEN;
	name = MALLOC(name_len + 1);
	if (!name) {
		errno = ENOMEM;
		return -1;
	}

	do {

		memcpy(name, ctx->staging_dir_name, ctx->staging_dir_name_len);
		name[ctx->staging_dir_name_len] = '/';
		randomize_char_array_with_alnum(name + ctx->staging_dir_name_len + 1,
						STAGING_FILE_NAME_LEN);
		name[name_len] = '\0';


	/* Just in case, verify that the randomly generated name doesn't name an
	 * existing file, and try again if so  */
	} while (stat(name, &stbuf) == 0);

	if (errno != ENOENT) /* other error?! */
		return -1;

	/* doesn't exist--- ok */

	DEBUG("Creating staging file `%s'", name);

	fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -1) {
		errno_save = errno;
		FREE(name);
		errno = errno_save;
	} else {
		*name_ret = name;
	}
	return fd;
}

/*
 * Extract a WIM resource to the staging directory.
 *
 * @inode:  Inode that contains the stream we are extracting
 *
 * @stream_id: Identifier for the stream (it stays constant even if the indices
 * of the stream entries are changed)
 *
 * @lte: Pointer to pointer to the lookup table entry for the stream we need to
 * extract, or NULL if there was no lookup table entry present for the stream
 *
 * @size:  Number of bytes of the stream we want to extract (this supports the
 * wimfs_truncate() function).  It may be more than the actual stream length, in
 * which case the extra space is filled with zeroes.
 *
 * @ctx:  Context for the WIM filesystem.
 *
 * Returns 0 on success or a negative error code on failure.
 */
static int
extract_resource_to_staging_dir(struct wim_inode *inode,
				u32 stream_id,
				struct wim_lookup_table_entry **lte,
				off_t size,
				struct wimfs_context *ctx)
{
	char *staging_file_name;
	int ret;
	int fd;
	struct wim_lookup_table_entry *old_lte, *new_lte;
	off_t extract_size;

	DEBUG("Extracting resource to staging dir: inode %"PRIu64", "
	      "stream id %"PRIu32, inode->i_ino, stream_id);

	old_lte = *lte;

	wimlib_assert(old_lte == NULL ||
		      old_lte->resource_location != RESOURCE_IN_STAGING_FILE);

	/* Create the staging file */
	fd = create_staging_file(&staging_file_name, ctx);
	if (fd == -1)
		return -errno;

	/* Extract the stream to the staging file (possibly truncated) */
	if (old_lte) {
		struct filedes wimlib_fd;
		filedes_init(&wimlib_fd, fd);
		extract_size = min(old_lte->size, size);
		ret = extract_stream_to_fd(old_lte, &wimlib_fd, extract_size);
	} else {
		ret = 0;
		extract_size = 0;
	}

	/* In the case of truncate() to more than the file length, extend the
	 * file with zeroes by calling ftruncate() on the underlying staging
	 * file */
	if (ret == 0 && size > extract_size)
		ret = ftruncate(fd, size);

	/* Close the staging file descriptor and check for errors.  If there's
	 * an error, unlink the staging file. */
	if (ret != 0 || close(fd) != 0) {
		if (errno != 0)
			ret = -errno;
		else
			ret = -EIO;
		close(fd);
		goto out_delete_staging_file;
	}

	/* Now deal with the lookup table entries.  We may be able to re-use the
	 * existing entry, but we may have to create a new one instead. */

	if (old_lte && inode->i_nlink == old_lte->refcnt) {
		/* The reference count of the existing lookup table entry is the
		 * same as the link count of the inode that contains the stream
		 * we're opening.  Therefore, ALL the references to the lookup
		 * table entry correspond to the stream we're trying to extract,
		 * so the lookup table entry can be re-used.  */
		DEBUG("Re-using lookup table entry");
		lookup_table_unlink(ctx->wim->lookup_table, old_lte);
		new_lte = old_lte;
	} else {
		if (old_lte) {
			/* There's an existing lookup table entry, but its
			 * reference count is greater than the link count for
			 * the inode containing a stream we're opening.
			 * Therefore, we need to split the lookup table entry.
			 */
			wimlib_assert(old_lte->refcnt > inode->i_nlink);
			DEBUG("Splitting lookup table entry "
			      "(inode->i_nlink = %u, old_lte->refcnt = %u)",
			      inode->i_nlink, old_lte->refcnt);
		}

		new_lte = new_lookup_table_entry();
		if (!new_lte) {
			ret = -ENOMEM;
			goto out_delete_staging_file;
		}

		/* There may already be open file descriptors to this stream if
		 * it's previously been opened read-only, but just now we're
		 * opening it read-write.  Identify those file descriptors and
		 * change their lookup table entry pointers to point to the new
		 * lookup table entry, and open staging file descriptors for
		 * them.
		 *
		 * At the same time, we need to count the number of these opened
		 * file descriptors to the new lookup table entry.  If there's
		 * an old lookup table entry, this number needs to be subtracted
		 * from the fd's opened to the old entry. */
		for (u16 i = 0, j = 0; j < inode->i_num_opened_fds; i++) {
			struct wimfs_fd *fd = inode->i_fds[i];
			if (fd) {
				if (fd->stream_id == stream_id) {
					int raw_fd;

					wimlib_assert(fd->f_lte == old_lte);
					wimlib_assert(!filedes_valid(&fd->staging_fd));
					fd->f_lte = new_lte;
					new_lte->num_opened_fds++;
					raw_fd = open(staging_file_name, O_RDONLY);
					if (raw_fd < 0) {
						ret = -errno;
						goto out_revert_fd_changes;
					}
					filedes_init(&fd->staging_fd, raw_fd);
				}
				j++;
			}
		}
		DEBUG("%hu fd's were already opened to the file we extracted",
		      new_lte->num_opened_fds);
		if (old_lte) {
			old_lte->num_opened_fds -= new_lte->num_opened_fds;
			old_lte->refcnt -= inode->i_nlink;
		}
	}

	lte_put_resource(new_lte);
	new_lte->refcnt              = inode->i_nlink;
	new_lte->resource_location   = RESOURCE_IN_STAGING_FILE;
	new_lte->staging_file_name   = staging_file_name;
	new_lte->size                = size;

	add_unhashed_stream(new_lte, inode, stream_id,
			    &wim_get_current_image_metadata(ctx->wim)->unhashed_streams);
	*retrieve_lte_pointer(new_lte) = new_lte;
	*lte = new_lte;
	return 0;
out_revert_fd_changes:
	for (u16 i = 0, j = 0; j < new_lte->num_opened_fds; i++) {
		struct wimfs_fd *fd = inode->i_fds[i];
		if (fd && fd->stream_id == stream_id && fd->f_lte == new_lte) {
			fd->f_lte = old_lte;
			if (filedes_valid(&fd->staging_fd)) {
				filedes_close(&fd->staging_fd);
				filedes_invalidate(&fd->staging_fd);
			}
			j++;
		}
	}
	free_lookup_table_entry(new_lte);
out_delete_staging_file:
	unlink(staging_file_name);
	FREE(staging_file_name);
	return ret;
}

/*
 * Creates a randomly named staging directory and saves its name in the
 * filesystem context structure.
 */
static int
make_staging_dir(struct wimfs_context *ctx, const char *user_prefix)
{
	static const size_t random_suffix_len = 10;
	static const char *common_suffix = ".staging";
	static const size_t common_suffix_len = 8;

	char *staging_dir_name = NULL;
	size_t staging_dir_name_len;
	size_t prefix_len;
	const char *wim_basename;
	char *real_user_prefix = NULL;
	int ret;

	if (user_prefix) {
		real_user_prefix = realpath(user_prefix, NULL);
		if (!real_user_prefix) {
			ERROR_WITH_ERRNO("Could not resolve `%s'",
					 real_user_prefix);
			ret = WIMLIB_ERR_NOTDIR;
			goto out;
		}
		wim_basename = path_basename(ctx->wim->filename);
		prefix_len = strlen(real_user_prefix) + 1 + strlen(wim_basename);
	} else {
		prefix_len = strlen(ctx->wim->filename);
	}

	staging_dir_name_len = prefix_len + common_suffix_len + random_suffix_len;

	staging_dir_name = MALLOC(staging_dir_name_len + 1);
	if (!staging_dir_name) {
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	if (real_user_prefix)
		sprintf(staging_dir_name, "%s/%s", real_user_prefix, wim_basename);
	else
		strcpy(staging_dir_name, ctx->wim->filename);

	strcat(staging_dir_name, common_suffix);

	randomize_char_array_with_alnum(staging_dir_name + prefix_len + common_suffix_len,
					random_suffix_len);

	staging_dir_name[staging_dir_name_len] = '\0';

	if (mkdir(staging_dir_name, 0700) != 0) {
		ERROR_WITH_ERRNO("Failed to create temporary directory `%s'",
				 staging_dir_name);
		ret = WIMLIB_ERR_MKDIR;
	} else {
		ret = 0;
	}
out:
	FREE(real_user_prefix);
	if (ret == 0) {
		ctx->staging_dir_name = staging_dir_name;
		ctx->staging_dir_name_len = staging_dir_name_len;
	} else {
		FREE(staging_dir_name);
	}
	return ret;
}

static int
remove_file_or_directory(const char *fpath, const struct stat *sb,
			 int typeflag, struct FTW *ftwbuf)
{
	if (remove(fpath) == 0)
		return 0;
	else {
		ERROR_WITH_ERRNO("Cannot remove `%s'", fpath);
		return WIMLIB_ERR_DELETE_STAGING_DIR;
	}
}

/*
 * Deletes the staging directory and all the files contained in it.
 */
static int
delete_staging_dir(struct wimfs_context *ctx)
{
	int ret;
	ret = nftw(ctx->staging_dir_name, remove_file_or_directory,
		   10, FTW_DEPTH);
	FREE(ctx->staging_dir_name);
	ctx->staging_dir_name = NULL;
	return ret;
}

static int
inode_close_fds(struct wim_inode *inode)
{
	u16 num_opened_fds = inode->i_num_opened_fds;
	for (u16 i = 0, j = 0; j < num_opened_fds; i++) {
		struct wimfs_fd *fd = inode->i_fds[i];
		if (fd) {
			wimlib_assert(fd->f_inode == inode);
			int ret = close_wimfs_fd(fd);
			if (ret != 0)
				return ret;
			j++;
		}
	}
	return 0;
}

/* Overwrites the WIM file, with changes saved. */
static int
rebuild_wim(struct wimfs_context *ctx, int write_flags,
	    wimlib_progress_func_t progress_func)
{
	int ret;
	struct wim_lookup_table_entry *lte, *tmp;
	WIMStruct *wim = ctx->wim;
	struct wim_image_metadata *imd = wim_get_current_image_metadata(ctx->wim);

	DEBUG("Closing all staging file descriptors.");
	image_for_each_unhashed_stream_safe(lte, tmp, imd) {
		ret = inode_close_fds(lte->back_inode);
		if (ret)
			return ret;
	}

	DEBUG("Freeing entries for zero-length streams");
	image_for_each_unhashed_stream_safe(lte, tmp, imd) {
		wimlib_assert(lte->unhashed);
		if (lte->size == 0) {
			struct wim_lookup_table_entry **back_ptr;
			back_ptr = retrieve_lte_pointer(lte);
			*back_ptr = NULL;
			list_del(&lte->unhashed_list);
			free_lookup_table_entry(lte);
		}
	}

	xml_update_image_info(wim, wim->current_image);
	ret = wimlib_overwrite(wim, write_flags, 0, progress_func);
	if (ret)
		ERROR("Failed to commit changes to mounted WIM image");
	return ret;
}

/* Simple function that returns the concatenation of 2 strings. */
static char *
strcat_dup(const char *s1, const char *s2, size_t max_len)
{
	size_t len = strlen(s1) + strlen(s2);
	if (len > max_len)
		len = max_len;
	char *p = MALLOC(len + 1);
	if (!p)
		return NULL;
	snprintf(p, len + 1, "%s%s", s1, s2);
	return p;
}

static int
set_message_queue_names(struct wimfs_context *ctx, const char *mount_dir)
{
	static const char *u2d_prefix = "/wimlib-unmount-to-daemon-mq";
	static const char *d2u_prefix = "/wimlib-daemon-to-unmount-mq";
	char *dir_path;
	char *p;
	int ret;

	dir_path = realpath(mount_dir, NULL);
	if (!dir_path) {
		ERROR_WITH_ERRNO("Failed to resolve path \"%s\"", mount_dir);
		if (errno == ENOMEM)
			return WIMLIB_ERR_NOMEM;
		else
			return WIMLIB_ERR_NOTDIR;
	}

	for (p = dir_path; *p; p++)
		if (*p == '/')
			*p = 0xff;

	ctx->unmount_to_daemon_mq_name = strcat_dup(u2d_prefix, dir_path,
						    NAME_MAX);
	if (!ctx->unmount_to_daemon_mq_name) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_dir_path;
	}
	ctx->daemon_to_unmount_mq_name = strcat_dup(d2u_prefix, dir_path,
						    NAME_MAX);
	if (!ctx->daemon_to_unmount_mq_name) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_unmount_to_daemon_mq_name;
	}

	ret = 0;
	goto out_free_dir_path;
out_free_unmount_to_daemon_mq_name:
	FREE(ctx->unmount_to_daemon_mq_name);
	ctx->unmount_to_daemon_mq_name = NULL;
out_free_dir_path:
	FREE(dir_path);
	return ret;
}

static void
free_message_queue_names(struct wimfs_context *ctx)
{
	FREE(ctx->unmount_to_daemon_mq_name);
	FREE(ctx->daemon_to_unmount_mq_name);
	ctx->unmount_to_daemon_mq_name = NULL;
	ctx->daemon_to_unmount_mq_name = NULL;
}

/*
 * Opens two POSIX message queue: one for sending messages from the unmount
 * process to the daemon process, and one to go the other way.  The names of the
 * message queues, which must be system-wide unique, are be based on the mount
 * point.
 *
 * @daemon specifies whether the calling process is the filesystem daemon or the
 * unmount process.
 */
static int
open_message_queues(struct wimfs_context *ctx, bool daemon)
{
	int unmount_to_daemon_mq_flags = O_WRONLY | O_CREAT;
	int daemon_to_unmount_mq_flags = O_RDONLY | O_CREAT;
	mode_t mode;
	mode_t orig_umask;
	int ret;

	if (daemon) {
		swap(unmount_to_daemon_mq_flags, daemon_to_unmount_mq_flags);
		mode = 0600;
	} else {
		mode = 0666;
	}

	orig_umask = umask(0000);
	DEBUG("Opening message queue \"%s\"", ctx->unmount_to_daemon_mq_name);
	ctx->unmount_to_daemon_mq = mq_open(ctx->unmount_to_daemon_mq_name,
					    unmount_to_daemon_mq_flags, mode, NULL);

	if (ctx->unmount_to_daemon_mq == (mqd_t)-1) {
		ERROR_WITH_ERRNO("mq_open()");
		ret = WIMLIB_ERR_MQUEUE;
		goto out;
	}

	DEBUG("Opening message queue \"%s\"", ctx->daemon_to_unmount_mq_name);
	ctx->daemon_to_unmount_mq = mq_open(ctx->daemon_to_unmount_mq_name,
					    daemon_to_unmount_mq_flags, mode, NULL);

	if (ctx->daemon_to_unmount_mq == (mqd_t)-1) {
		ERROR_WITH_ERRNO("mq_open()");
		mq_close(ctx->unmount_to_daemon_mq);
		mq_unlink(ctx->unmount_to_daemon_mq_name);
		ctx->unmount_to_daemon_mq = (mqd_t)-1;
		ret = WIMLIB_ERR_MQUEUE;
		goto out;
	}
	ret = 0;
out:
	umask(orig_umask);
	return ret;
}

/* Try to determine the maximum message size of a message queue.  The return
 * value is the maximum message size, or a guess of 8192 bytes if it cannot be
 * determined. */
static long
mq_get_msgsize(mqd_t mq)
{
	static const char *msgsize_max_file = "/proc/sys/fs/mqueue/msgsize_max";
	FILE *fp;
	struct mq_attr attr;
	long msgsize;

	if (mq_getattr(mq, &attr) == 0) {
		msgsize = attr.mq_msgsize;
	} else {
		ERROR_WITH_ERRNO("mq_getattr()");
		ERROR("Attempting to read %s", msgsize_max_file);
		fp = fopen(msgsize_max_file, "rb");
		if (fp) {
			if (fscanf(fp, "%ld", &msgsize) != 1) {
				ERROR("Assuming message size of 8192");
				msgsize = 8192;
			}
			fclose(fp);
		} else {
			ERROR_WITH_ERRNO("Failed to open the file `%s'",
					 msgsize_max_file);
			ERROR("Assuming message size of 8192");
			msgsize = 8192;
		}
	}
	return msgsize;
}

static int
get_mailbox(mqd_t mq, long needed_msgsize, long *msgsize_ret,
	    void **mailbox_ret)
{
	long msgsize;
	void *mailbox;

	msgsize = mq_get_msgsize(mq);

	if (msgsize < needed_msgsize) {
		ERROR("Message queue max size must be at least %ld!",
		      needed_msgsize);
		return WIMLIB_ERR_MQUEUE;
	}

	mailbox = MALLOC(msgsize);
	if (!mailbox) {
		ERROR("Failed to allocate %ld bytes for mailbox", msgsize);
		return WIMLIB_ERR_NOMEM;
	}
	*msgsize_ret = msgsize;
	*mailbox_ret = mailbox;
	return 0;
}

static void
unlink_message_queues(struct wimfs_context *ctx)
{
	mq_unlink(ctx->unmount_to_daemon_mq_name);
	mq_unlink(ctx->daemon_to_unmount_mq_name);
}

/* Closes the message queues, which are allocated in static variables */
static void
close_message_queues(struct wimfs_context *ctx)
{
	DEBUG("Closing message queues");
	mq_close(ctx->unmount_to_daemon_mq);
	ctx->unmount_to_daemon_mq = (mqd_t)(-1);
	mq_close(ctx->daemon_to_unmount_mq);
	ctx->daemon_to_unmount_mq = (mqd_t)(-1);
	unlink_message_queues(ctx);
}


struct unmount_msg_hdr {
	u32 min_version;
	u32 cur_version;
	u32 msg_type;
	u32 msg_size;
} _packed_attribute;

struct msg_unmount_request {
	struct unmount_msg_hdr hdr;
	u32 unmount_flags;
	u8 want_progress_messages;
} _packed_attribute;

struct msg_daemon_info {
	struct unmount_msg_hdr hdr;
	pid_t daemon_pid;
	u32 mount_flags;
} _packed_attribute;

struct msg_unmount_finished {
	struct unmount_msg_hdr hdr;
	s32 status;
} _packed_attribute;

struct msg_write_streams_progress {
	struct unmount_msg_hdr hdr;
	union wimlib_progress_info info;
} _packed_attribute;

enum {
	MSG_TYPE_UNMOUNT_REQUEST,
	MSG_TYPE_DAEMON_INFO,
	MSG_TYPE_WRITE_STREAMS_PROGRESS,
	MSG_TYPE_UNMOUNT_FINISHED,
	MSG_TYPE_MAX,
};

struct msg_handler_context_hdr {
	int timeout_seconds;
};

struct unmount_msg_handler_context {
	struct msg_handler_context_hdr hdr;
	pid_t daemon_pid;
	int mount_flags;
	int status;
	wimlib_progress_func_t progress_func;
};

struct daemon_msg_handler_context {
	struct msg_handler_context_hdr hdr;
	struct wimfs_context *wimfs_ctx;
};

static int
send_unmount_request_msg(mqd_t mq, int unmount_flags, u8 want_progress_messages)
{
	DEBUG("Sending unmount request msg");
	struct msg_unmount_request msg = {
		.hdr = {
			.min_version = ((unmount_flags & WIMLIB_UNMOUNT_FLAG_NEW_IMAGE) ?
						WIMLIB_MAKEVERSION(1, 6, 2) :
						WIMLIB_MAKEVERSION(1, 2, 1)),
			.cur_version = WIMLIB_VERSION_CODE,
			.msg_type    = MSG_TYPE_UNMOUNT_REQUEST,
			.msg_size    = sizeof(msg),
		},
		.unmount_flags = unmount_flags,
		.want_progress_messages = want_progress_messages,
	};

	if (mq_send(mq, (void*)&msg, sizeof(msg), 1)) {
		ERROR_WITH_ERRNO("Failed to communicate with filesystem daemon");
		return WIMLIB_ERR_MQUEUE;
	}
	return 0;
}

static int
send_daemon_info_msg(mqd_t mq, pid_t pid, int mount_flags)
{
	DEBUG("Sending daemon info msg (pid = %d, mount_flags=%x)",
	      pid, mount_flags);

	struct msg_daemon_info msg = {
		.hdr = {
			.min_version = WIMLIB_MAKEVERSION(1, 2, 1),
			.cur_version = WIMLIB_VERSION_CODE,
			.msg_type = MSG_TYPE_DAEMON_INFO,
			.msg_size = sizeof(msg),
		},
		.daemon_pid = pid,
		.mount_flags = mount_flags,
	};
	if (mq_send(mq, (void*)&msg, sizeof(msg), 1)) {
		ERROR_WITH_ERRNO("Failed to send daemon info to unmount process");
		return WIMLIB_ERR_MQUEUE;
	}
	return 0;
}

static void
send_unmount_finished_msg(mqd_t mq, int status)
{
	DEBUG("Sending unmount finished msg");
	struct msg_unmount_finished msg = {
		.hdr = {
			.min_version = WIMLIB_MAKEVERSION(1, 2, 1),
			.cur_version = WIMLIB_VERSION_CODE,
			.msg_type = MSG_TYPE_UNMOUNT_FINISHED,
			.msg_size = sizeof(msg),
		},
		.status = status,
	};
	if (mq_send(mq, (void*)&msg, sizeof(msg), 1))
		ERROR_WITH_ERRNO("Failed to send status to unmount process");
}

static int
unmount_progress_func(enum wimlib_progress_msg msg,
		      const union wimlib_progress_info *info)
{
	if (msg == WIMLIB_PROGRESS_MSG_WRITE_STREAMS) {
		struct msg_write_streams_progress msg = {
			.hdr = {
				.min_version = WIMLIB_MAKEVERSION(1, 2, 1),
				.cur_version = WIMLIB_VERSION_CODE,
				.msg_type = MSG_TYPE_WRITE_STREAMS_PROGRESS,
				.msg_size = sizeof(msg),
			},
			.info = *info,
		};
		if (mq_send(wimfs_get_context()->daemon_to_unmount_mq,
			    (void*)&msg, sizeof(msg), 1))
		{
			ERROR_WITH_ERRNO("Failed to send progress information "
					 "to unmount process");
		}
	}
	return 0;
}

static void
release_extra_refcnts(struct wimfs_context *ctx)
{
	struct list_head *list = &ctx->orig_stream_list;
	struct wim_lookup_table *lookup_table = ctx->wim->lookup_table;
	struct wim_lookup_table_entry *lte, *tmp;

	list_for_each_entry_safe(lte, tmp, list, orig_stream_list)
		while (lte->out_refcnt--)
			lte_decrement_refcnt(lte, lookup_table);
}

/* Moves the currently selected image, which may have been modified, to a new
 * index, and sets the original index to refer to a reset (unmodified) copy of
 * the image.  */
static int
renew_current_image(struct wimfs_context *ctx)
{
	WIMStruct *wim = ctx->wim;
	int ret;
	int idx = wim->current_image - 1;
	struct wim_image_metadata *imd = wim->image_metadata[idx];
	struct wim_image_metadata *replace_imd;
	struct wim_lookup_table_entry *new_lte;

	if (imd->metadata_lte->resource_location != RESOURCE_IN_WIM) {
		ERROR("Can't reset modified image that doesn't yet "
		      "exist in the on-disk WIM file!");
		return WIMLIB_ERR_METADATA_NOT_FOUND;
	}

	/* Create 'replace_imd' structure to use for the reset original,
	 * unmodified image.  */
	replace_imd = new_image_metadata();
	if (!replace_imd)
		return WIMLIB_ERR_NOMEM;

	/* Create new stream reference for the modified image's metadata
	 * resource, which doesn't exist yet.  */
	ret = WIMLIB_ERR_NOMEM;
	new_lte = new_lookup_table_entry();
	if (!new_lte)
		goto err_put_replace_imd;
	new_lte->flags = WIM_RESHDR_FLAG_METADATA;
	new_lte->unhashed = 1;

	/* Make the image being moved available at a new index.  Increments the
	 * WIM's image count, but does not increment the reference count of the
	 * 'struct image_metadata'.  */
	ret = append_image_metadata(wim, imd);
	if (ret)
		goto err_free_new_lte;

	ret = xml_add_image(wim, T(""));
	if (ret)
		goto err_undo_append;

	replace_imd->metadata_lte = imd->metadata_lte;
	imd->metadata_lte = new_lte;
	wim->image_metadata[idx] = replace_imd;
	wim->current_image = wim->hdr.image_count;
	return 0;

err_undo_append:
	wim->hdr.image_count--;
err_free_new_lte:
	free_lookup_table_entry(new_lte);
err_put_replace_imd:
	put_image_metadata(replace_imd, NULL);
	return ret;
}

static int
msg_unmount_request_handler(const void *_msg, void *_handler_ctx)
{
	const struct msg_unmount_request *msg = _msg;
	struct daemon_msg_handler_context *handler_ctx = _handler_ctx;
	struct wimfs_context *wimfs_ctx;
	int status = 0;
	int ret;
	int unmount_flags;
	wimlib_progress_func_t progress_func;

	DEBUG("Handling unmount request msg");

	wimfs_ctx = handler_ctx->wimfs_ctx;
	if (msg->hdr.msg_size < sizeof(*msg)) {
		status = WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE;
		goto out;
	}

	unmount_flags = msg->unmount_flags;
	if (msg->want_progress_messages)
		progress_func = unmount_progress_func;
	else
		progress_func = NULL;

	ret = send_daemon_info_msg(wimfs_ctx->daemon_to_unmount_mq, getpid(),
				   wimfs_ctx->mount_flags);
	if (ret != 0) {
		status = ret;
		goto out;
	}

	if (wimfs_ctx->mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		if (unmount_flags & WIMLIB_UNMOUNT_FLAG_COMMIT) {

			if (unmount_flags & WIMLIB_UNMOUNT_FLAG_NEW_IMAGE) {
				ret = renew_current_image(wimfs_ctx);
				if (ret) {
					status = ret;
					goto out;
				}
			} else {
				release_extra_refcnts(wimfs_ctx);
			}
			INIT_LIST_HEAD(&wimfs_ctx->orig_stream_list);

			int write_flags = 0;
			if (unmount_flags & WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY)
				write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
			if (unmount_flags & WIMLIB_UNMOUNT_FLAG_REBUILD)
				write_flags |= WIMLIB_WRITE_FLAG_REBUILD;
			if (unmount_flags & WIMLIB_UNMOUNT_FLAG_RECOMPRESS)
				write_flags |= WIMLIB_WRITE_FLAG_RECOMPRESS;
			status = rebuild_wim(wimfs_ctx, write_flags,
					     progress_func);
		}
	} else {
		DEBUG("Read-only mount");
		status = 0;
	}

out:
	if (wimfs_ctx->mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		ret = delete_staging_dir(wimfs_ctx);
		if (ret != 0) {
			ERROR("Failed to delete the staging directory");
			if (status == 0)
				status = ret;
		}
	}
	wimfs_ctx->status = status;
	wimfs_ctx->have_status = true;
	return MSG_BREAK_LOOP;
}

static int
msg_daemon_info_handler(const void *_msg, void *_handler_ctx)
{
	const struct msg_daemon_info *msg = _msg;
	struct unmount_msg_handler_context *handler_ctx = _handler_ctx;

	DEBUG("Handling daemon info msg");
	if (msg->hdr.msg_size < sizeof(*msg))
		return WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE;
	handler_ctx->daemon_pid = msg->daemon_pid;
	handler_ctx->mount_flags = msg->mount_flags;
	handler_ctx->hdr.timeout_seconds = 1;
	DEBUG("pid of daemon is %d; mount flags were %#x",
	      handler_ctx->daemon_pid,
	      handler_ctx->mount_flags);
	return 0;
}

static int
msg_write_streams_progress_handler(const void *_msg, void *_handler_ctx)
{
	const struct msg_write_streams_progress *msg = _msg;
	struct unmount_msg_handler_context *handler_ctx = _handler_ctx;

	if (msg->hdr.msg_size < sizeof(*msg))
		return WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE;
	if (handler_ctx->progress_func) {
		handler_ctx->progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
					   &msg->info);
	}
	return 0;
}

static int
msg_unmount_finished_handler(const void *_msg, void *_handler_ctx)
{
	const struct msg_unmount_finished *msg = _msg;
	struct unmount_msg_handler_context *handler_ctx = _handler_ctx;

	DEBUG("Handling unmount finished message");
	if (msg->hdr.msg_size < sizeof(*msg))
		return WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE;
	handler_ctx->status = msg->status;
	DEBUG("status is %d", handler_ctx->status);
	return MSG_BREAK_LOOP;
}

static int
unmount_timed_out_cb(void *_handler_ctx)
{
	const struct unmount_msg_handler_context *handler_ctx = _handler_ctx;

	if (handler_ctx->daemon_pid == 0 ||
	    (kill(handler_ctx->daemon_pid, 0) != 0 && errno == ESRCH))
	{
		ERROR("The filesystem daemon has crashed!  Changes to the "
		      "WIM may not have been commited.");
		return WIMLIB_ERR_FILESYSTEM_DAEMON_CRASHED;
	}

	DEBUG("Filesystem daemon is still alive... "
	      "Waiting another %d seconds", handler_ctx->hdr.timeout_seconds);
	return 0;
}

static int
daemon_timed_out_cb(void *_handler_ctx)
{
	ERROR("Timed out waiting for unmount request! "
	      "Changes to the mounted WIM will not be committed.");
	return WIMLIB_ERR_TIMEOUT;
}

typedef int (*msg_handler_t)(const void *_msg, void *_handler_ctx);

struct msg_handler_callbacks {
	int (*timed_out)(void * _handler_ctx);
	msg_handler_t msg_handlers[MSG_TYPE_MAX];
};

static const struct msg_handler_callbacks unmount_msg_handler_callbacks = {
	.timed_out = unmount_timed_out_cb,
	.msg_handlers = {
		[MSG_TYPE_DAEMON_INFO] = msg_daemon_info_handler,
		[MSG_TYPE_WRITE_STREAMS_PROGRESS] = msg_write_streams_progress_handler,
		[MSG_TYPE_UNMOUNT_FINISHED] = msg_unmount_finished_handler,
	},
};

static const struct msg_handler_callbacks daemon_msg_handler_callbacks = {
	.timed_out = daemon_timed_out_cb,
	.msg_handlers = {
		[MSG_TYPE_UNMOUNT_REQUEST] = msg_unmount_request_handler,
	},
};

static int
receive_message(mqd_t mq,
		struct msg_handler_context_hdr *handler_ctx,
		const msg_handler_t msg_handlers[],
		long mailbox_size, void *mailbox)
{
	struct timeval now;
	struct timespec timeout;
	ssize_t bytes_received;
	struct unmount_msg_hdr *hdr;
	int ret;

	gettimeofday(&now, NULL);
	timeout.tv_sec = now.tv_sec + handler_ctx->timeout_seconds;
	timeout.tv_nsec = now.tv_usec * 1000;

	bytes_received = mq_timedreceive(mq, mailbox,
					 mailbox_size, NULL, &timeout);
	hdr = mailbox;
	if (bytes_received == -1) {
		if (errno == ETIMEDOUT) {
			ret = WIMLIB_ERR_TIMEOUT;
		} else {
			ERROR_WITH_ERRNO("mq_timedreceive()");
			ret = WIMLIB_ERR_MQUEUE;
		}
	} else if (bytes_received < sizeof(*hdr) ||
		   bytes_received != hdr->msg_size) {
		ret = WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE;
	} else if (WIMLIB_VERSION_CODE < hdr->min_version) {
		/*ERROR("Cannot understand the received message. "*/
		      /*"Please upgrade wimlib to at least v%d.%d.%d",*/
		      /*WIMLIB_GET_MAJOR_VERSION(hdr->min_version),*/
		      /*WIMLIB_GET_MINOR_VERSION(hdr->min_version),*/
		      /*WIMLIB_GET_PATCH_VERSION(hdr->min_version));*/
		ret = MSG_VERSION_TOO_HIGH;
	} else if (hdr->msg_type >= MSG_TYPE_MAX) {
		ret = WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE;
	} else if (msg_handlers[hdr->msg_type] == NULL) {
		ret = WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE;
	} else {
		ret = msg_handlers[hdr->msg_type](mailbox, handler_ctx);
	}
	return ret;
}

static int
message_loop(mqd_t mq,
	     const struct msg_handler_callbacks *callbacks,
	     struct msg_handler_context_hdr *handler_ctx)
{
	static const size_t MAX_MSG_SIZE = 512;
	long msgsize;
	void *mailbox;
	int ret;

	DEBUG("Entering message loop");

	ret = get_mailbox(mq, MAX_MSG_SIZE, &msgsize, &mailbox);
	if (ret != 0)
		return ret;
	while (1) {
		ret = receive_message(mq, handler_ctx,
				      callbacks->msg_handlers,
				      msgsize, mailbox);
		if (ret == 0 || ret == MSG_VERSION_TOO_HIGH) {
			continue;
		} else if (ret == MSG_BREAK_LOOP) {
			ret = 0;
			break;
		} else if (ret == WIMLIB_ERR_TIMEOUT) {
			if (callbacks->timed_out)
				ret = callbacks->timed_out(handler_ctx);
			if (ret == 0)
				continue;
			else
				break;
		} else {
			ERROR_WITH_ERRNO("Error communicating with "
					 "filesystem daemon");
			break;
		}
	}
	FREE(mailbox);
	DEBUG("Exiting message loop");
	return ret;
}

/* Execute `fusermount -u', which is installed setuid root, to unmount the WIM.
 *
 * FUSE does not yet implement synchronous unmounts.  This means that fusermount
 * -u will return before the filesystem daemon returns from wimfs_destroy().
 *  This is partly what we want, because we need to send a message from this
 *  process to the filesystem daemon telling whether --commit was specified or
 *  not.  However, after that, the unmount process must wait for the filesystem
 *  daemon to finish writing the WIM file.
 */
static int
execute_fusermount(const char *dir, bool lazy)
{
	pid_t pid;
	int ret;
	int status;

	pid = fork();
	if (pid == -1) {
		ERROR_WITH_ERRNO("Failed to fork()");
		return WIMLIB_ERR_FORK;
	}
	if (pid == 0) {
		/* Child */
		char *argv[10];
		char **argp = argv;
		*argp++ = "fusermount";
		if (lazy)
			*argp++ = "-z";
		*argp++ = "-u";
		*argp++ = (char*)dir;
		*argp = NULL;
		execvp("fusermount", argv);
		ERROR_WITH_ERRNO("Failed to execute `fusermount'");
		exit(WIMLIB_ERR_FUSERMOUNT);
	}

	/* Parent */
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		ERROR_WITH_ERRNO("Failed to wait for fusermount process to "
				 "terminate");
		return WIMLIB_ERR_FUSERMOUNT;
	}

	if (!WIFEXITED(status)) {
		ERROR("'fusermount' did not terminate normally!");
		return WIMLIB_ERR_FUSERMOUNT;
	}

	status = WEXITSTATUS(status);

	if (status == 0)
		return 0;

	if (status != WIMLIB_ERR_FUSERMOUNT)
		return WIMLIB_ERR_FUSERMOUNT;

	/* Try again, but with the `umount' program.  This is required on other
	 * FUSE implementations such as FreeBSD's that do not have a
	 * `fusermount' program. */
	ERROR("Falling back to 'umount'.  Note: you may need to be "
	      "root for this to work");
	pid = fork();
	if (pid == -1) {
		ERROR_WITH_ERRNO("Failed to fork()");
		return WIMLIB_ERR_FORK;
	}
	if (pid == 0) {
		/* Child */
		char *argv[10];
		char **argp = argv;
		*argp++ = "umount";
		if (lazy)
			*argp++ = "-l";
		*argp++ = (char*)dir;
		*argp = NULL;
		execvp("umount", argv);
		ERROR_WITH_ERRNO("Failed to execute `umount'");
		exit(WIMLIB_ERR_FUSERMOUNT);
	}

	/* Parent */
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		ERROR_WITH_ERRNO("Failed to wait for `umount' process to "
				 "terminate");
		return WIMLIB_ERR_FUSERMOUNT;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		ERROR("`umount' did not successfully complete");
		return WIMLIB_ERR_FUSERMOUNT;
	}

	return 0;
}

static int
wimfs_chmod(const char *path, mode_t mask)
{
	struct wim_dentry *dentry;
	struct wimfs_context *ctx = wimfs_get_context();
	int ret;

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_UNIX_DATA))
		return -EPERM;

	ret = wim_pathname_to_stream(ctx->wim, path, LOOKUP_FLAG_DIRECTORY_OK,
				     &dentry, NULL, NULL);
	if (ret)
		return ret;

	ret = inode_set_unix_data(dentry->d_inode, ctx->default_uid,
				  ctx->default_gid, mask,
				  ctx->wim->lookup_table, UNIX_DATA_MODE);
	return ret ? -ENOMEM : 0;
}

static int
wimfs_chown(const char *path, uid_t uid, gid_t gid)
{
	struct wim_dentry *dentry;
	struct wimfs_context *ctx = wimfs_get_context();
	int ret;

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_UNIX_DATA))
		return -EPERM;

	ret = wim_pathname_to_stream(ctx->wim, path, LOOKUP_FLAG_DIRECTORY_OK,
				     &dentry, NULL, NULL);
	if (ret)
		return ret;

	ret = inode_set_unix_data(dentry->d_inode, uid, gid,
				  inode_default_unix_mode(dentry->d_inode),
				  ctx->wim->lookup_table,
				  UNIX_DATA_UID | UNIX_DATA_GID);
	return ret ? -ENOMEM : 0;
}

/* Called when the filesystem is unmounted. */
static void
wimfs_destroy(void *p)
{
	struct wimfs_context *wimfs_ctx = wimfs_get_context();
	if (open_message_queues(wimfs_ctx, true) == 0) {
		struct daemon_msg_handler_context handler_ctx = {
			.hdr = {
				.timeout_seconds = 5,
			},
			.wimfs_ctx = wimfs_ctx,
		};
		message_loop(wimfs_ctx->unmount_to_daemon_mq,
			     &daemon_msg_handler_callbacks,
			     &handler_ctx.hdr);
	}
}

static int
wimfs_fgetattr(const char *path, struct stat *stbuf,
	       struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = (struct wimfs_fd*)(uintptr_t)fi->fh;
	return inode_to_stbuf(fd->f_inode, fd->f_lte, stbuf);
}

static int
wimfs_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = (struct wimfs_fd*)(uintptr_t)fi->fh;
	int ret = ftruncate(fd->staging_fd.fd, size);
	if (ret)
		return -errno;
	touch_inode(fd->f_inode);
	fd->f_lte->size = size;
	return 0;
}

/*
 * Fills in a `struct stat' that corresponds to a file or directory in the WIM.
 */
static int
wimfs_getattr(const char *path, struct stat *stbuf)
{
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	int ret;
	struct wimfs_context *ctx = wimfs_get_context();

	ret = wim_pathname_to_stream(ctx->wim, path,
				     get_lookup_flags(ctx) |
					LOOKUP_FLAG_DIRECTORY_OK,
				     &dentry, &lte, NULL);
	if (ret != 0)
		return ret;
	return inode_to_stbuf(dentry->d_inode, lte, stbuf);
}

#ifdef ENABLE_XATTR
/* Read an alternate data stream through the XATTR interface, or get its size */
static int
wimfs_getxattr(const char *path, const char *name, char *value,
	       size_t size)
{
	int ret;
	struct wim_inode *inode;
	struct wim_ads_entry *ads_entry;
	u64 stream_size;
	struct wim_lookup_table_entry *lte;
	struct wimfs_context *ctx = wimfs_get_context();

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR))
		return -ENOTSUP;

	if (strlen(name) <= 5 || memcmp(name, "user.", 5) != 0)
		return -ENOATTR;
	name += 5;

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	ads_entry = inode_get_ads_entry(inode, name, NULL);
	if (!ads_entry)
		return -ENOATTR;

	lte = ads_entry->lte;
	stream_size = lte->size;

	if (size == 0)
		return stream_size;

	if (stream_size > size)
		return -ERANGE;

	ret = read_full_stream_into_buf(lte, value);
	if (ret) {
		if (errno)
			return -errno;
		else
			return -EIO;
	}
	return stream_size;
}
#endif

/* Create a hard link */
static int
wimfs_link(const char *to, const char *from)
{
	struct wim_dentry *from_dentry, *from_dentry_parent;
	const char *link_name;
	struct wim_inode *inode;
	WIMStruct *wim = wimfs_get_WIMStruct();
	int ret;

	inode = wim_pathname_to_inode(wim, to);
	if (!inode)
		return -errno;

	if (inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
				   FILE_ATTRIBUTE_REPARSE_POINT))
		return -EPERM;

	from_dentry_parent = get_parent_dentry(wim, from, WIMLIB_CASE_SENSITIVE);
	if (!from_dentry_parent)
		return -errno;
	if (!dentry_is_directory(from_dentry_parent))
		return -ENOTDIR;

	link_name = path_basename(from);
	if (get_dentry_child_with_name(from_dentry_parent, link_name,
				       WIMLIB_CASE_SENSITIVE))
		return -EEXIST;

	ret = new_dentry(link_name, &from_dentry);
	if (ret)
		return -ENOMEM;

	inode->i_nlink++;
	inode_ref_streams(inode);
	from_dentry->d_inode = inode;
	inode_add_dentry(from_dentry, inode);
	dentry_add_child(from_dentry_parent, from_dentry);
	return 0;
}

#ifdef ENABLE_XATTR
static int
wimfs_listxattr(const char *path, char *list, size_t size)
{
	size_t needed_size;
	struct wim_inode *inode;
	struct wimfs_context *ctx = wimfs_get_context();
	u16 i;
	char *p;
	bool size_only = (size == 0);

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR))
		return -ENOTSUP;

	/* List alternate data streams, or get the list size */

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	p = list;
	for (i = 0; i < inode->i_num_ads; i++) {

		if (!ads_entry_is_named_stream(&inode->i_ads_entries[i]))
			continue;

		char *stream_name_mbs;
		size_t stream_name_mbs_nbytes;
		int ret;

		ret = utf16le_to_tstr(inode->i_ads_entries[i].stream_name,
				      inode->i_ads_entries[i].stream_name_nbytes,
				      &stream_name_mbs,
				      &stream_name_mbs_nbytes);
		if (ret)
			return -errno;

		needed_size = stream_name_mbs_nbytes + 6;
		if (!size_only) {
			if (needed_size > size) {
				FREE(stream_name_mbs);
				return -ERANGE;
			}
			sprintf(p, "user.%s", stream_name_mbs);
			size -= needed_size;
		}
		p += needed_size;
		FREE(stream_name_mbs);
	}
	return p - list;
}
#endif


/* Create a directory in the WIM image. */
static int
wimfs_mkdir(const char *path, mode_t mode)
{
	return create_dentry(fuse_get_context(), path, mode | S_IFDIR,
			     FILE_ATTRIBUTE_DIRECTORY, NULL);
}

/* Create a regular file or alternate data stream in the WIM image. */
static int
wimfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	const char *stream_name;
	struct fuse_context *fuse_ctx = fuse_get_context();
	struct wimfs_context *wimfs_ctx = WIMFS_CTX(fuse_ctx);

	if (!S_ISREG(mode))
		return -EPERM;

	if ((wimfs_ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS)
	     && (stream_name = path_stream_name(path))) {
		/* Make an alternate data stream */
		struct wim_ads_entry *new_entry;
		struct wim_inode *inode;

		char *p = (char*)stream_name - 1;
		wimlib_assert(*p == ':');
		*p = '\0';

		inode = wim_pathname_to_inode(wimfs_ctx->wim, path);
		if (!inode)
			return -errno;
		if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
			return -ENOENT;
		if (inode_get_ads_entry(inode, stream_name, NULL))
			return -EEXIST;
		new_entry = inode_add_ads(inode, stream_name);
		if (!new_entry)
			return -ENOMEM;
		return 0;
	} else {
		/* Make a normal file (not an alternate data stream) */
		return create_dentry(fuse_ctx, path, mode | S_IFREG,
				     FILE_ATTRIBUTE_NORMAL, NULL);
	}
}

/* Open a file.  */
static int
wimfs_open(const char *path, struct fuse_file_info *fi)
{
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	int ret;
	struct wimfs_fd *fd;
	struct wim_inode *inode;
	u16 stream_idx;
	u32 stream_id;
	struct wimfs_context *ctx = wimfs_get_context();
	struct wim_lookup_table_entry **back_ptr;

	ret = wim_pathname_to_stream(ctx->wim, path, get_lookup_flags(ctx),
				     &dentry, &lte, &stream_idx);
	if (ret)
		return ret;

	inode = dentry->d_inode;

	if (stream_idx == 0) {
		stream_id = 0;
		back_ptr = &inode->i_lte;
	} else {
		stream_id = inode->i_ads_entries[stream_idx - 1].stream_id;
		back_ptr = &inode->i_ads_entries[stream_idx - 1].lte;
	}

	/* The file resource may be in the staging directory (read-write mounts
	 * only) or in the WIM.  If it's in the staging directory, we need to
	 * open a native file descriptor for the corresponding file.  Otherwise,
	 * we can read the file resource directly from the WIM file if we are
	 * opening it read-only, but we need to extract the resource to the
	 * staging directory if we are opening it writable. */

	if (flags_writable(fi->flags) &&
            (!lte || lte->resource_location != RESOURCE_IN_STAGING_FILE)) {
		u64 size = (lte) ? lte->size : 0;
		ret = extract_resource_to_staging_dir(inode, stream_id,
						      &lte, size, ctx);
		if (ret)
			return ret;
		*back_ptr = lte;
	}

	ret = alloc_wimfs_fd(inode, stream_id, lte, &fd);
	if (ret)
		return ret;

	if (lte && lte->resource_location == RESOURCE_IN_STAGING_FILE) {
		int raw_fd;

		raw_fd = open(lte->staging_file_name, fi->flags);
		if (raw_fd < 0) {
			int errno_save = errno;
			close_wimfs_fd(fd);
			return -errno_save;
		}
		filedes_init(&fd->staging_fd, raw_fd);
	}
	fi->fh = (uintptr_t)fd;
	return 0;
}

/* Opens a directory. */
static int
wimfs_opendir(const char *path, struct fuse_file_info *fi)
{
	struct wim_inode *inode;
	int ret;
	struct wimfs_fd *fd = NULL;
	struct wimfs_context *ctx = wimfs_get_context();
	WIMStruct *wim = ctx->wim;

	inode = wim_pathname_to_inode(wim, path);
	if (!inode)
		return -errno;
	if (!inode_is_directory(inode))
		return -ENOTDIR;
	ret = alloc_wimfs_fd(inode, 0, NULL, &fd);
	fi->fh = (uintptr_t)fd;
	return ret;
}


/*
 * Read data from a file in the WIM or in the staging directory.
 */
static int
wimfs_read(const char *path, char *buf, size_t size,
	   off_t offset, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = (struct wimfs_fd*)(uintptr_t)fi->fh;
	ssize_t ret;
	u64 stream_size;

	if (!fd)
		return -EBADF;

	if (size == 0)
		return 0;

	if (fd->f_lte)
		stream_size = fd->f_lte->size;
	else
		stream_size = 0;

	if (offset > stream_size)
		return -EOVERFLOW;

	size = min(size, stream_size - offset);
	if (size == 0)
		return 0;

	switch (fd->f_lte->resource_location) {
	case RESOURCE_IN_STAGING_FILE:
		ret = raw_pread(&fd->staging_fd, buf, size, offset);
		if (ret == -1)
			ret = -errno;
		break;
	case RESOURCE_IN_WIM:
		if (read_partial_wim_stream_into_buf(fd->f_lte, size,
						     offset, buf))
			ret = errno ? -errno : -EIO;
		else
			ret = size;
		break;
	case RESOURCE_IN_ATTACHED_BUFFER:
		memcpy(buf, fd->f_lte->attached_buffer + offset, size);
		ret = size;
		break;
	default:
		ERROR("Invalid resource location");
		ret = -EIO;
		break;
	}
	return ret;
}

struct fill_params {
	void *buf;
	fuse_fill_dir_t filler;
};

static int
dentry_fuse_fill(struct wim_dentry *dentry, void *arg)
{
	struct fill_params *fill_params = arg;

	char *file_name_mbs;
	size_t file_name_mbs_nbytes;
	int ret;

	ret = utf16le_to_tstr(dentry->file_name,
			      dentry->file_name_nbytes,
			      &file_name_mbs,
			      &file_name_mbs_nbytes);
	if (ret)
		return -errno;

	ret = fill_params->filler(fill_params->buf, file_name_mbs, NULL, 0);
	FREE(file_name_mbs);
	return ret;
}

/* Fills in the entries of the directory specified by @path using the
 * FUSE-provided function @filler.  */
static int
wimfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	      off_t offset, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = (struct wimfs_fd*)(uintptr_t)fi->fh;
	struct wim_inode *inode;

	if (!fd)
		return -EBADF;

	inode = fd->f_inode;

	struct fill_params fill_params = {
		.buf = buf,
		.filler = filler,
	};

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	return for_dentry_in_rbtree(inode->i_children.rb_node,
				    dentry_fuse_fill, &fill_params);
}


static int
wimfs_readlink(const char *path, char *buf, size_t buf_len)
{
	struct wimfs_context *ctx = wimfs_get_context();
	struct wim_inode *inode = wim_pathname_to_inode(ctx->wim, path);
	int ret;
	if (!inode)
		return -errno;
	if (!inode_is_symlink(inode))
		return -EINVAL;
	if (buf_len == 0)
		return -EINVAL;
	ret = wim_inode_readlink(inode, buf, buf_len - 1, NULL);
	if (ret >= 0) {
		wimlib_assert(ret <= buf_len - 1);
		buf[ret] = '\0';
		ret = 0;
	} else if (ret == -ENAMETOOLONG) {
		buf[buf_len - 1] = '\0';
	}
	return ret;
}

/* Close a file. */
static int
wimfs_release(const char *path, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = (struct wimfs_fd*)(uintptr_t)fi->fh;
	return close_wimfs_fd(fd);
}

/* Close a directory */
static int
wimfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = (struct wimfs_fd*)(uintptr_t)fi->fh;
	return close_wimfs_fd(fd);
}

#ifdef ENABLE_XATTR
/* Remove an alternate data stream through the XATTR interface */
static int
wimfs_removexattr(const char *path, const char *name)
{
	struct wim_inode *inode;
	struct wim_ads_entry *ads_entry;
	u16 ads_idx;
	struct wimfs_context *ctx = wimfs_get_context();

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR))
		return -ENOTSUP;

	if (strlen(name) < 5 || memcmp(name, "user.", 5) != 0)
		return -ENOATTR;
	name += 5;

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	ads_entry = inode_get_ads_entry(inode, name, &ads_idx);
	if (!ads_entry)
		return -ENOATTR;
	inode_remove_ads(inode, ads_idx, ctx->wim->lookup_table);
	return 0;
}
#endif

/* Renames a file or directory.  See rename (3) */
static int
wimfs_rename(const char *from, const char *to)
{
	return rename_wim_path(wimfs_get_WIMStruct(), from, to,
			       WIMLIB_CASE_SENSITIVE);
}

/* Remove a directory */
static int
wimfs_rmdir(const char *path)
{
	struct wim_dentry *dentry;
	WIMStruct *wim = wimfs_get_WIMStruct();

	dentry = get_dentry(wim, path, WIMLIB_CASE_SENSITIVE);
	if (!dentry)
		return -errno;

	if (!dentry_is_directory(dentry))
		return -ENOTDIR;

	if (dentry_has_children(dentry))
		return -ENOTEMPTY;

	remove_dentry(dentry, wim->lookup_table);
	return 0;
}

#ifdef ENABLE_XATTR
/* Write an alternate data stream through the XATTR interface */
static int
wimfs_setxattr(const char *path, const char *name,
	       const char *value, size_t size, int flags)
{
	struct wim_ads_entry *existing_ads_entry;
	struct wim_inode *inode;
	u16 ads_idx;
	struct wimfs_context *ctx = wimfs_get_context();
	int ret;

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR))
		return -ENOTSUP;

	if (strlen(name) <= 5 || memcmp(name, "user.", 5) != 0)
		return -ENOATTR;
	name += 5;

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	existing_ads_entry = inode_get_ads_entry(inode, name, &ads_idx);
	if (existing_ads_entry) {
		if (flags & XATTR_CREATE)
			return -EEXIST;
	} else {
		if (flags & XATTR_REPLACE)
			return -ENOATTR;
	}

	ret = inode_add_ads_with_data(inode, name, value,
				      size, ctx->wim->lookup_table);
	if (ret == 0) {
		if (existing_ads_entry)
			inode_remove_ads(inode, ads_idx, ctx->wim->lookup_table);
	} else {
		ret = -ENOMEM;
	}
	return ret;
}
#endif

static int
wimfs_symlink(const char *to, const char *from)
{
	struct fuse_context *fuse_ctx = fuse_get_context();
	struct wimfs_context *wimfs_ctx = WIMFS_CTX(fuse_ctx);
	struct wim_dentry *dentry;
	int ret;

	ret = create_dentry(fuse_ctx, from, S_IFLNK | 0777,
			    FILE_ATTRIBUTE_REPARSE_POINT, &dentry);
	if (ret == 0) {
		dentry->d_inode->i_reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;
		ret = wim_inode_set_symlink(dentry->d_inode, to,
					    wimfs_ctx->wim->lookup_table);
		if (ret) {
			remove_dentry(dentry, wimfs_ctx->wim->lookup_table);
			if (ret == WIMLIB_ERR_NOMEM)
				ret = -ENOMEM;
			else
				ret = -EIO;
		}
	}
	return ret;
}


/* Reduce the size of a file */
static int
wimfs_truncate(const char *path, off_t size)
{
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	int ret;
	u16 stream_idx;
	u32 stream_id;
	struct wim_inode *inode;
	struct wimfs_context *ctx = wimfs_get_context();

	ret = wim_pathname_to_stream(ctx->wim, path, get_lookup_flags(ctx),
				     &dentry, &lte, &stream_idx);

	if (ret != 0)
		return ret;

	if (lte == NULL && size == 0)
		return 0;

	if (lte != NULL && lte->resource_location == RESOURCE_IN_STAGING_FILE) {
		ret = truncate(lte->staging_file_name, size);
		if (ret)
			ret = -errno;
		else
			lte->size = size;
	} else {
		/* File in WIM.  Extract it to the staging directory, but only
		 * the first @size bytes of it. */
		struct wim_lookup_table_entry **back_ptr;

		inode = dentry->d_inode;
		if (stream_idx == 0) {
			stream_id = 0;
			back_ptr = &inode->i_lte;
		} else {
			stream_id = inode->i_ads_entries[stream_idx - 1].stream_id;
			back_ptr = &inode->i_ads_entries[stream_idx - 1].lte;
		}
		ret = extract_resource_to_staging_dir(inode, stream_id,
						      &lte, size, ctx);
		*back_ptr = lte;
	}
	return ret;
}

/* Unlink a non-directory or alternate data stream */
static int
wimfs_unlink(const char *path)
{
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	int ret;
	u16 stream_idx;
	struct wimfs_context *ctx = wimfs_get_context();

	ret = wim_pathname_to_stream(ctx->wim, path, get_lookup_flags(ctx),
				     &dentry, &lte, &stream_idx);

	if (ret != 0)
		return ret;

	if (inode_stream_name_nbytes(dentry->d_inode, stream_idx) == 0)
		remove_dentry(dentry, ctx->wim->lookup_table);
	else
		inode_remove_ads(dentry->d_inode, stream_idx - 1,
				 ctx->wim->lookup_table);
	return 0;
}

#ifdef HAVE_UTIMENSAT
/*
 * Change the timestamp on a file dentry.
 *
 * Note that alternate data streams do not have their own timestamps.
 */
static int
wimfs_utimens(const char *path, const struct timespec tv[2])
{
	struct wim_dentry *dentry;
	struct wim_inode *inode;
	WIMStruct *wim = wimfs_get_WIMStruct();

	dentry = get_dentry(wim, path, WIMLIB_CASE_SENSITIVE);
	if (!dentry)
		return -errno;
	inode = dentry->d_inode;

	if (tv[0].tv_nsec != UTIME_OMIT) {
		if (tv[0].tv_nsec == UTIME_NOW)
			inode->i_last_access_time = get_wim_timestamp();
		else
			inode->i_last_access_time = timespec_to_wim_timestamp(tv[0]);
	}
	if (tv[1].tv_nsec != UTIME_OMIT) {
		if (tv[1].tv_nsec == UTIME_NOW)
			inode->i_last_write_time = get_wim_timestamp();
		else
			inode->i_last_write_time = timespec_to_wim_timestamp(tv[1]);
	}
	return 0;
}
#else /* HAVE_UTIMENSAT */
static int
wimfs_utime(const char *path, struct utimbuf *times)
{
	struct wim_dentry *dentry;
	struct wim_inode *inode;
	WIMStruct *wim = wimfs_get_WIMStruct();

	dentry = get_dentry(wim, path, WIMLIB_CASE_SENSITIVE);
	if (!dentry)
		return -errno;
	inode = dentry->d_inode;

	inode->i_last_write_time = unix_timestamp_to_wim(times->modtime);
	inode->i_last_access_time = unix_timestamp_to_wim(times->actime);
	return 0;
}
#endif /* !HAVE_UTIMENSAT */

/* Writes to a file in the WIM filesystem.
 * It may be an alternate data stream, but here we don't even notice because we
 * just get a lookup table entry. */
static int
wimfs_write(const char *path, const char *buf, size_t size,
	    off_t offset, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = (struct wimfs_fd*)(uintptr_t)fi->fh;
	int ret;

	if (!fd)
		return -EBADF;

	wimlib_assert(fd->f_lte != NULL);
	wimlib_assert(fd->f_lte->staging_file_name != NULL);
	wimlib_assert(filedes_valid(&fd->staging_fd));
	wimlib_assert(fd->f_inode != NULL);

	/* Write the data. */
	ret = raw_pwrite(&fd->staging_fd, buf, size, offset);
	if (ret == -1)
		return -errno;

	/* Update file size */
	if (offset + size > fd->f_lte->size) {
		DEBUG("Update file size %"PRIu64 " => %"PRIu64"",
		      fd->f_lte->size, offset + size);
		fd->f_lte->size = offset + size;
	}

	/* Update timestamps */
	touch_inode(fd->f_inode);
	return ret;
}

static struct fuse_operations wimfs_operations = {
	.chmod       = wimfs_chmod,
	.chown       = wimfs_chown,
	.destroy     = wimfs_destroy,
	.fgetattr    = wimfs_fgetattr,
	.ftruncate   = wimfs_ftruncate,
	.getattr     = wimfs_getattr,
#ifdef ENABLE_XATTR
	.getxattr    = wimfs_getxattr,
#endif
	.link        = wimfs_link,
#ifdef ENABLE_XATTR
	.listxattr   = wimfs_listxattr,
#endif
	.mkdir       = wimfs_mkdir,
	.mknod       = wimfs_mknod,
	.open        = wimfs_open,
	.opendir     = wimfs_opendir,
	.read        = wimfs_read,
	.readdir     = wimfs_readdir,
	.readlink    = wimfs_readlink,
	.release     = wimfs_release,
	.releasedir  = wimfs_releasedir,
#ifdef ENABLE_XATTR
	.removexattr = wimfs_removexattr,
#endif
	.rename      = wimfs_rename,
	.rmdir       = wimfs_rmdir,
#ifdef ENABLE_XATTR
	.setxattr    = wimfs_setxattr,
#endif
	.symlink     = wimfs_symlink,
	.truncate    = wimfs_truncate,
	.unlink      = wimfs_unlink,
#ifdef HAVE_UTIMENSAT
	.utimens     = wimfs_utimens,
#else
	.utime       = wimfs_utime,
#endif
	.write       = wimfs_write,

	/* wimfs keeps file descriptor structures (struct wimfs_fd), so there is
	 * no need to have the file path provided on operations such as read()
	 * where only the file descriptor is needed. */
#if FUSE_MAJOR_VERSION > 2 || (FUSE_MAJOR_VERSION == 2 && FUSE_MINOR_VERSION >= 8)
	.flag_nullpath_ok = 1,
#endif
#if FUSE_MAJOR_VERSION > 2 || (FUSE_MAJOR_VERSION == 2 && FUSE_MINOR_VERSION >= 9)
	.flag_nopath = 1,
	.flag_utime_omit_ok = 1,
#endif
};


/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_mount_image(WIMStruct *wim, int image, const char *dir,
		   int mount_flags, const char *staging_dir)
{
	int argc;
	char *argv[16];
	int ret;
	char *dir_copy;
	struct wim_image_metadata *imd;
	struct wimfs_context ctx;
	struct wim_inode *inode;

	DEBUG("Mount: wim = %p, image = %d, dir = %s, flags = %d, ",
	      wim, image, dir, mount_flags);

	if (!wim || !dir)
		return WIMLIB_ERR_INVALID_PARAM;

	if (mount_flags & ~(WIMLIB_MOUNT_FLAG_READWRITE |
			    WIMLIB_MOUNT_FLAG_DEBUG |
			    WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE |
			    WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR |
			    WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS |
			    WIMLIB_MOUNT_FLAG_UNIX_DATA |
			    WIMLIB_MOUNT_FLAG_ALLOW_OTHER))
		return WIMLIB_ERR_INVALID_PARAM;

	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		ret = can_delete_from_wim(wim);
		if (ret)
			return ret;
	}

	ret = select_wim_image(wim, image);
	if (ret)
		return ret;

	DEBUG("Selected image %d", image);

	imd = wim_get_current_image_metadata(wim);

	if (imd->modified) {
		/* wimfs_read() only supports a limited number of stream
		 * locations, not including RESOURCE_IN_FILE_ON_DISK,
		 * RESOURCE_IN_NTFS_VOLUME, etc. that might appear if files were
		 * added to the WIM image.  */
		ERROR("Cannot mount an image with newly added files!");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		ret = lock_wim(wim, wim->in_fd.fd);
		if (ret)
			return ret;
	}

	/* Use default stream interface if one was not specified */
	if (!(mount_flags & (WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE |
		       WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR |
		       WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS)))
		mount_flags |= WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR;

	DEBUG("Initializing struct wimfs_context");
	init_wimfs_context(&ctx);
	ctx.wim = wim;
	ctx.mount_flags = mount_flags;
	ctx.image_inode_list = &imd->inode_list;
	ctx.default_uid = getuid();
	ctx.default_gid = getgid();
	wimlib_assert(list_empty(&imd->unhashed_streams));
	if (mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS)
		ctx.default_lookup_flags = LOOKUP_FLAG_ADS_OK;

	DEBUG("Unlinking message queues in case they already exist");
	ret = set_message_queue_names(&ctx, dir);
	if (ret)
		goto out_unlock;
	unlink_message_queues(&ctx);

	DEBUG("Preparing arguments to fuse_main()");

	dir_copy = STRDUP(dir);
	if (!dir_copy) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_message_queue_names;
	}

	argc = 0;
	argv[argc++] = "wimlib";
	argv[argc++] = dir_copy;

	/* disable multi-threaded operation */
	argv[argc++] = "-s";

	if (mount_flags & WIMLIB_MOUNT_FLAG_DEBUG)
		argv[argc++] = "-d";

	/*
	 * We provide the use_ino option to the FUSE mount because we are going
	 * to assign inode numbers ourselves. */
	char optstring[256] =
		"use_ino"
		",subtype=wimfs"
		",attr_timeout=0"
#if FUSE_MAJOR_VERSION > 2 || (FUSE_MAJOR_VERSION == 2 && FUSE_MINOR_VERSION >= 8)
		",hard_remove"
#endif
		",default_permissions"
		;
	argv[argc++] = "-o";
	argv[argc++] = optstring;
	if ((mount_flags & WIMLIB_MOUNT_FLAG_READWRITE)) {
		/* Read-write mount.  Make the staging directory */
		ret = make_staging_dir(&ctx, staging_dir);
		if (ret)
			goto out_free_dir_copy;
	} else {
		/* Read-only mount */
		strcat(optstring, ",ro");
	}
	if (mount_flags & WIMLIB_MOUNT_FLAG_ALLOW_OTHER)
		strcat(optstring, ",allow_other");
	argv[argc] = NULL;

#ifdef ENABLE_DEBUG
	{
		int i;
		DEBUG("FUSE command line (argc = %d): ", argc);
		for (i = 0; i < argc; i++) {
			fputs(argv[i], stdout);
			putchar(' ');
		}
		putchar('\n');
		fflush(stdout);
	}
#endif

	/* Assign inode numbers.  Also, if a read-write mount was requested,
	 * mark the dentry tree as modified, and add each streams referenced by
	 * files in the image to a list and preemptively double the number of
	 * references to each.  The latter is done to allow implementing the
	 * WIMLIB_UNMOUNT_FLAG_NEW_IMAGE semantics.  */
	ctx.next_ino = 1;
	INIT_LIST_HEAD(&ctx.orig_stream_list);
	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		imd->modified = 1;
		image_for_each_inode(inode, imd) {
			inode->i_ino = ctx.next_ino++;
			for (unsigned i = 0; i <= inode->i_num_ads; i++) {
				struct wim_lookup_table_entry *lte;

				lte = inode_stream_lte(inode, i, wim->lookup_table);
				if (lte) {
					lte->orig_stream_list = (struct list_head){NULL, NULL};
					lte->out_refcnt = 0;
				}
			}
		}
		image_for_each_inode(inode, imd) {
			for (unsigned i = 0; i <= inode->i_num_ads; i++) {
				struct wim_lookup_table_entry *lte;

				lte = inode_stream_lte(inode, i,
						       wim->lookup_table);
				if (lte) {
					if (lte->out_refcnt == 0)
						list_add(&lte->orig_stream_list,
							 &ctx.orig_stream_list);
					lte->out_refcnt += inode->i_nlink;
					lte->refcnt += inode->i_nlink;
				}
			}
		}
	} else {
		image_for_each_inode(inode, imd)
			inode->i_ino = ctx.next_ino++;
	}

	DEBUG("(next_ino = %"PRIu64")", ctx.next_ino);

	DEBUG("Calling fuse_main()");

	ret = fuse_main(argc, argv, &wimfs_operations, &ctx);

	DEBUG("Returned from fuse_main() (ret = %d)", ret);

	if (ret) {
		ret = WIMLIB_ERR_FUSE;
	} else {
		if (ctx.have_status)
			ret = ctx.status;
		else
			ret = WIMLIB_ERR_TIMEOUT;
	}
	if (ctx.daemon_to_unmount_mq != (mqd_t)(-1)) {
		send_unmount_finished_msg(ctx.daemon_to_unmount_mq, ret);
		close_message_queues(&ctx);
	}

	release_extra_refcnts(&ctx);

	/* Try to delete the staging directory if a deletion wasn't yet
	 * attempted due to an earlier error */
	if (ctx.staging_dir_name)
		delete_staging_dir(&ctx);
out_free_dir_copy:
	FREE(dir_copy);
out_unlock:
	wim->wim_locked = 0;
out_free_message_queue_names:
	free_message_queue_names(&ctx);
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_unmount_image(const char *dir, int unmount_flags,
		     wimlib_progress_func_t progress_func)
{
	int ret;
	struct wimfs_context wimfs_ctx;

	if (unmount_flags & ~(WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY |
			      WIMLIB_UNMOUNT_FLAG_COMMIT |
			      WIMLIB_UNMOUNT_FLAG_REBUILD |
			      WIMLIB_UNMOUNT_FLAG_RECOMPRESS |
			      WIMLIB_UNMOUNT_FLAG_LAZY |
			      WIMLIB_UNMOUNT_FLAG_NEW_IMAGE))
		return WIMLIB_ERR_INVALID_PARAM;

	init_wimfs_context(&wimfs_ctx);

	ret = set_message_queue_names(&wimfs_ctx, dir);
	if (ret != 0)
		goto out;

	ret = open_message_queues(&wimfs_ctx, false);
	if (ret != 0)
		goto out_free_message_queue_names;

	ret = send_unmount_request_msg(wimfs_ctx.unmount_to_daemon_mq,
				       unmount_flags,
				       progress_func != NULL);
	if (ret != 0)
		goto out_close_message_queues;

	ret = execute_fusermount(dir, (unmount_flags & WIMLIB_UNMOUNT_FLAG_LAZY) != 0);
	if (ret != 0)
		goto out_close_message_queues;

	struct unmount_msg_handler_context handler_ctx = {
		.hdr = {
			.timeout_seconds = 5,
		},
		.daemon_pid = 0,
		.progress_func = progress_func,
	};

	ret = message_loop(wimfs_ctx.daemon_to_unmount_mq,
			   &unmount_msg_handler_callbacks,
			   &handler_ctx.hdr);
	if (ret == 0)
		ret = handler_ctx.status;
out_close_message_queues:
	close_message_queues(&wimfs_ctx);
out_free_message_queue_names:
	free_message_queue_names(&wimfs_ctx);
out:
	return ret;
}

#else /* WITH_FUSE */


static int
mount_unsupported_error(void)
{
#if defined(__WIN32__)
	ERROR("Sorry-- Mounting WIM images is not supported on Windows!");
#else
	ERROR("wimlib was compiled with --without-fuse, which disables support "
	      "for mounting WIMs.");
#endif
	return WIMLIB_ERR_UNSUPPORTED;
}

WIMLIBAPI int
wimlib_unmount_image(const tchar *dir, int unmount_flags,
		     wimlib_progress_func_t progress_func)
{
	return mount_unsupported_error();
}

WIMLIBAPI int
wimlib_mount_image(WIMStruct *wim, int image, const tchar *dir,
		   int mount_flags, const tchar *staging_dir)
{
	return mount_unsupported_error();
}

#endif /* !WITH_FUSE */
