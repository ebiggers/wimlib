/*
 * mount_image.c
 *
 * This file implements mounting of WIM files using FUSE, which stands for
 * Filesystem in Userspace.  FUSE allows a filesystem to be implemented in a
 * userspace process by implementing the filesystem primitives--- read(),
 * write(), readdir(), etc.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
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

#ifdef WITH_FUSE

#ifdef __WIN32__
#  error "FUSE mount not supported on Windows!  Please configure --without-fuse"
#endif

#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/progress.h"
#include "wimlib/reparse.h"
#include "wimlib/timestamp.h"
#include "wimlib/unix_data.h"
#include "wimlib/write.h"
#include "wimlib/xml.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <mqueue.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <attr/xattr.h>

#ifndef O_NOFOLLOW
#  define O_NOFOLLOW 0  /* Security only...  */
#endif

#define WIMFS_MQUEUE_NAME_LEN 32

#define WIMLIB_UNMOUNT_FLAG_SEND_PROGRESS 0x80000000

struct wimfs_unmount_info {
	unsigned unmount_flags;
	char mq_name[WIMFS_MQUEUE_NAME_LEN + 1];
};

struct commit_progress_report {
	enum wimlib_progress_msg msg;
	union wimlib_progress_info info;
};

/* Description of an open file on a mounted WIM image.  Actually, this
 * represents the open state of a particular data stream of an inode, rather
 * than the inode itself.  (An inode might have multiple named data streams in
 * addition to the default, unnamed data stream.)  At a given time, an inode in
 * the WIM image might have multiple file descriptors open to it, each to any
 * one of its data streams.  */
struct wimfs_fd {

	/* Pointer to the inode of this open file.
	 * 'i_num_opened_fds' of the inode tracks the number of file descriptors
	 * that reference it.  */
	struct wim_inode *f_inode;

	/* Pointer to the lookup table entry for the data stream that has been
	 * opened.  'num_opened_fds' of the lookup table entry tracks the number
	 * of file descriptors that reference it.  Or, this value may be NULL,
	 * which indicates that the opened stream is empty and consequently does
	 * not have a lookup table entry.  */
	struct wim_lookup_table_entry *f_lte;

	/* If valid (filedes_valid(&f_staging_fd)), this contains the
	 * corresponding native file descriptor for the staging file that has
	 * been created for reading from and/or writing to this open stream.  A
	 * single staging file might have multiple file descriptors open to it
	 * simultaneously, each used by a different 'struct wimfs_fd'.
	 *
	 * Or, if invalid (!filedes_valid(&f_staging_fd)), this 'struct
	 * wimfs_fd' is not associated with a staging file.  This is permissible
	 * only if this 'struct wimfs_fd' was opened read-only and the stream
	 * has not yet been extracted to a staging file.  */
	struct filedes f_staging_fd;

	/* 0-based index of this file descriptor in the file descriptor table of
	 * its inode.  */
	u16 f_idx;

	/* Unique ID of the opened stream in the inode.  This will stay the same
	 * even if the indices of the inode's alternate data streams are changed
	 * by a deletion.  */
	u32 f_stream_id;
};

#define WIMFS_FD(fi) ((struct wimfs_fd *)(uintptr_t)((fi)->fh))

/* Context structure for a mounted WIM image.  */
struct wimfs_context {
	/* The WIMStruct containing the mounted image.  The mounted image is the
	 * currently selected image (wim->current_image).  */
	WIMStruct *wim;

	/* Flags passed to wimlib_mount_image() (WIMLIB_MOUNT_FLAG_*).  */
	int mount_flags;

	/* Default flags for path lookup in the WIM image.  */
	int default_lookup_flags;

	/* Information about the user who has mounted the WIM image  */
	uid_t owner_uid;
	gid_t owner_gid;

	/* Information about the staging directory for a read-write mount.  */
	int parent_dir_fd;
	int staging_dir_fd;
	char *staging_dir_name;

	/* For read-write mounts, the inode number to be assigned to the next
	 * created file.  Note: since this isn't a persistent filesystem and we
	 * can re-assign the inode numbers just before mounting the image, it's
	 * good enough to just generate inode numbers sequentially.  */
	u64 next_ino;

	/* Number of file descriptors open to the mounted WIM image.  */
	unsigned long num_open_fds;

	/* Original list of single-instance streams in the mounted image, linked
	 * by 'struct wim_lookup_table_entry'.orig_stream_list.  */
	struct list_head orig_stream_list;
};

#define WIMFS_CTX(fuse_ctx) ((struct wimfs_context*)(fuse_ctx)->private_data)

/* Retrieve the context structure for the currently mounted WIM image.
 *
 * Note: this is a per-thread variable.  It is possible for different threads to
 * mount different images at the same time in the same process, although they
 * must use different WIMStructs!  */
static inline struct wimfs_context *
wimfs_get_context(void)
{
	return WIMFS_CTX(fuse_get_context());
}

static void
wimfs_inc_num_open_fds(void)
{
	wimfs_get_context()->num_open_fds++;
}

static void
wimfs_dec_num_open_fds(void)
{
	wimfs_get_context()->num_open_fds--;
}

/* Retrieve the WIMStruct for the currently mounted WIM image.  */
static inline WIMStruct *
wimfs_get_WIMStruct(void)
{
	return wimfs_get_context()->wim;
}

/* Is write permission requested on the file?  */
static inline bool
flags_writable(int open_flags)
{
	int accmode = (open_flags & O_ACCMODE);
	return (accmode == O_RDWR || accmode == O_WRONLY);
}

static mode_t
fuse_mask_mode(mode_t mode, const struct fuse_context *fuse_ctx)
{
#if FUSE_MAJOR_VERSION > 2 || (FUSE_MAJOR_VERSION == 2 && FUSE_MINOR_VERSION >= 8)
	mode &= ~fuse_ctx->umask;
#endif
	return mode;
}

/*
 * Allocate a file descriptor to a data stream in the mounted WIM image.
 *
 * @inode
 *	A pointer to the inode containing the stream being opened.
 * @stream_id
 *	The ID of the data stream being opened within the inode.
 * @lte
 *	A pointer to the lookup table entry for the stream data.  Or, for a
 *	0-byte stream, this may be NULL.
 * @fd_ret
 *	On success, a pointer to the new file descriptor will be stored here.
 *
 * Returns 0 or a -errno code.
 */
static int
alloc_wimfs_fd(struct wim_inode *inode,
	       u32 stream_id,
	       struct wim_lookup_table_entry *lte,
	       struct wimfs_fd **fd_ret)
{
	static const u16 min_fds_per_alloc = 8;
	static const u16 max_fds = 0xffff;
	u16 i;
	struct wimfs_fd *fd;

	if (inode->i_num_opened_fds == inode->i_num_allocated_fds) {
		u16 num_new_fds;
		struct wimfs_fd **fds;

		/* Expand this inode's file descriptor table.  */

		num_new_fds = max(min_fds_per_alloc,
				  inode->i_num_allocated_fds / 4);

		num_new_fds = min(num_new_fds,
				  max_fds - inode->i_num_allocated_fds);

		if (num_new_fds == 0)
			return -EMFILE;

		fds = REALLOC(inode->i_fds,
			      (inode->i_num_allocated_fds + num_new_fds) *
			        sizeof(fds[0]));
		if (!fds)
			return -ENOMEM;

		memset(&fds[inode->i_num_allocated_fds], 0,
		       num_new_fds * sizeof(fds[0]));
		inode->i_fds = fds;
		inode->i_num_allocated_fds += num_new_fds;
		inode->i_next_fd = inode->i_num_opened_fds;
	}

	/* Allocate the file descriptor in the first available space in the
	 * inode's file descriptor table.
	 *
	 * i_next_fd is the lower bound on the next open slot.  */
	for (i = inode->i_next_fd; inode->i_fds[i]; i++)
		;

	fd = MALLOC(sizeof(*fd));
	if (!fd)
		return -ENOMEM;

	fd->f_inode     = inode;
	fd->f_lte       = lte;
	filedes_invalidate(&fd->f_staging_fd);
	fd->f_idx       = i;
	fd->f_stream_id = stream_id;
	*fd_ret         = fd;
	inode->i_fds[i] = fd;
	inode->i_num_opened_fds++;
	if (lte)
		lte->num_opened_fds++;
	wimfs_inc_num_open_fds();
	inode->i_next_fd = i + 1;
	return 0;
}

/*
 * Close a file descriptor to a data stream in the mounted WIM image.
 *
 * Returns 0 or a -errno code.  The file descriptor is always closed.
 */
static int
close_wimfs_fd(struct wimfs_fd *fd)
{
	int ret = 0;
	struct wim_inode *inode;

	/* Close the staging file if open.  */
	if (filedes_valid(&fd->f_staging_fd))
		 if (filedes_close(&fd->f_staging_fd))
			 ret = -errno;

	/* Release this file descriptor from its lookup table entry.  */
	if (fd->f_lte)
		lte_decrement_num_opened_fds(fd->f_lte);

	wimfs_dec_num_open_fds();

	/* Release this file descriptor from its inode.  */
	inode = fd->f_inode;
	inode->i_fds[fd->f_idx] = NULL;
	if (fd->f_idx < inode->i_next_fd)
		inode->i_next_fd = fd->f_idx;
	FREE(fd);
	if (--inode->i_num_opened_fds == 0) {
		/* The last file descriptor to this inode was closed.  */
		FREE(inode->i_fds);
		inode->i_fds = NULL;
		inode->i_num_allocated_fds = 0;
		if (inode->i_nlink == 0)
			/* No links to this inode remain.  Get rid of it.  */
			free_inode(inode);
	}
	return ret;
}

/*
 * Translate a path into the corresponding inode in the mounted WIM image.
 *
 * See get_dentry() for more information.
 *
 * Returns a pointer to the resulting inode, or NULL with errno set.
 */
static struct wim_inode *
wim_pathname_to_inode(WIMStruct *wim, const char *path)
{
	struct wim_dentry *dentry;

	dentry = get_dentry(wim, path, WIMLIB_CASE_SENSITIVE);
	if (!dentry)
		return NULL;
	return dentry->d_inode;
}

/* Can look up named data stream with colon syntax  */
#define LOOKUP_FLAG_ADS_OK		0x01

/* Can look up directory (otherwise get -ENOTDIR)  */
#define LOOKUP_FLAG_DIRECTORY_OK	0x02

/*
 * Translate a path into the corresponding dentry, lookup table entry, and
 * stream index in the mounted WIM image.
 *
 * Returns 0 or a -errno code.  All of @dentry_ret, @lte_ret, and
 * @stream_idx_ret are optional.
 */
static int
wim_pathname_to_stream(const struct wimfs_context *ctx, const char *path,
		       int lookup_flags,
		       struct wim_dentry **dentry_ret,
		       struct wim_lookup_table_entry **lte_ret,
		       u16 *stream_idx_ret)
{
	WIMStruct *wim = ctx->wim;
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	u16 stream_idx;
	const tchar *stream_name = NULL;
	struct wim_inode *inode;
	tchar *p = NULL;

	lookup_flags |= ctx->default_lookup_flags;

	if (lookup_flags & LOOKUP_FLAG_ADS_OK) {
		stream_name = path_stream_name(path);
		if (stream_name) {
			p = (tchar*)stream_name - 1;
			*p = T('\0');
		}
	}

	dentry = get_dentry(wim, path, WIMLIB_CASE_SENSITIVE);
	if (p)
		*p = T(':');
	if (!dentry)
		return -errno;

	inode = dentry->d_inode;

	if (!inode->i_resolved)
		if (inode_resolve_streams(inode, wim->lookup_table, false))
			return -EIO;

	if (!(lookup_flags & LOOKUP_FLAG_DIRECTORY_OK)
	      && inode_is_directory(inode))
		return -EISDIR;

	if (stream_name) {
		struct wim_ads_entry *ads_entry;

		ads_entry = inode_get_ads_entry(inode, stream_name);
		if (!ads_entry)
			return -errno;

		stream_idx = ads_entry - inode->i_ads_entries + 1;
		lte = ads_entry->lte;
	} else {
		lte = inode_unnamed_stream_resolved(inode, &stream_idx);
	}
	if (dentry_ret)
		*dentry_ret = dentry;
	if (lte_ret)
		*lte_ret = lte;
	if (stream_idx_ret)
		*stream_idx_ret = stream_idx;
	return 0;
}

/*
 * Create a new file in the mounted WIM image.
 *
 * @fuse_ctx
 *	The FUSE context for the mounted image.
 * @path
 *	The path at which to create the first link to the new file.  If a file
 *	already exists at this path, -EEXIST is returned.
 * @mode
 *	The UNIX mode for the new file.  This is only honored if
 *	WIMLIB_MOUNT_FLAG_UNIX_DATA was passed to wimlib_mount_image().
 * @rdev
 *	The device ID for the new file, encoding the major and minor device
 *	numbers.  This is only honored if WIMLIB_MOUNT_FLAG_UNIX_DATA was passed
 *	to wimlib_mount_image().
 * @attributes
 *	Windows file attributes to use for the new file.
 * @dentry_ret
 *	On success, a pointer to the new dentry is returned here.  Its d_inode
 *	member will point to the new inode that was created for it and added to
 *	the mounted WIM image.
 *
 * Returns 0 or a -errno code.
 */
static int
create_dentry(struct fuse_context *fuse_ctx, const char *path,
	      mode_t mode, dev_t rdev, u32 attributes,
	      struct wim_dentry **dentry_ret)
{
	struct wimfs_context *wimfs_ctx = WIMFS_CTX(fuse_ctx);
	struct wim_dentry *parent;
	const char *basename;
	struct wim_dentry *new_dentry;
	struct wim_inode *new_inode;

	parent = get_parent_dentry(wimfs_ctx->wim, path, WIMLIB_CASE_SENSITIVE);
	if (!parent)
		return -errno;

	if (!dentry_is_directory(parent))
		return -ENOTDIR;

	basename = path_basename(path);

	if (get_dentry_child_with_name(parent, basename, WIMLIB_CASE_SENSITIVE))
		return -EEXIST;

	if (new_dentry_with_inode(basename, &new_dentry))
		return -ENOMEM;

	new_inode = new_dentry->d_inode;

	new_inode->i_resolved = 1;
	new_inode->i_ino = wimfs_ctx->next_ino++;
	new_inode->i_attributes = attributes;

	if (wimfs_ctx->mount_flags & WIMLIB_MOUNT_FLAG_UNIX_DATA) {
		struct wimlib_unix_data unix_data;

		unix_data.uid = fuse_ctx->uid;
		unix_data.gid = fuse_ctx->gid;
		unix_data.mode = fuse_mask_mode(mode, fuse_ctx);
		unix_data.rdev = rdev;
		if (!inode_set_unix_data(new_inode, &unix_data, UNIX_DATA_ALL))
		{
			free_dentry(new_dentry);
			return -ENOMEM;
		}
	}

	list_add_tail(&new_inode->i_list,
		      &wim_get_current_image_metadata(wimfs_ctx->wim)->inode_list);

	dentry_add_child(parent, new_dentry);

	if (dentry_ret)
		*dentry_ret = new_dentry;
	return 0;
}

/*
 * Remove a dentry from the mounted WIM image; i.e. remove an alias for an
 * inode.
 */
static void
remove_dentry(struct wim_dentry *dentry,
	      struct wim_lookup_table *lookup_table)
{
	/* Drop the reference to each stream the inode contains.  */
	inode_unref_streams(dentry->d_inode, lookup_table);

	/* Unlink the dentry from the image's dentry tree.  */
	unlink_dentry(dentry);

	/* Delete the dentry.  This will also decrement the link count of the
	 * corresponding inode, and possibly cause it to be deleted as well.  */
	free_dentry(dentry);
}

/* Generate UNIX filetype mode bits for the specified WIM inode, based on its
 * Windows file attributes.  */
static mode_t
inode_unix_file_type(const struct wim_inode *inode)
{
	if (inode_is_symlink(inode))
		return S_IFLNK;
	else if (inode_is_directory(inode))
		return S_IFDIR;
	else
		return S_IFREG;
}

/* Generate a default UNIX mode for the specified WIM inode.  */
static mode_t
inode_default_unix_mode(const struct wim_inode *inode)
{
	return inode_unix_file_type(inode) | 0777;
}

/*
 * Retrieve standard UNIX metadata ('struct stat') for a WIM inode.
 *
 * @lte specifies the stream of the inode that is being queried.  We mostly
 * return the same information for all streams, but st_size and st_blocks may be
 * different for different streams.
 *
 * This always returns 0.
 */
static int
inode_to_stbuf(const struct wim_inode *inode,
	       const struct wim_lookup_table_entry *lte,
	       struct stat *stbuf)
{
	const struct wimfs_context *ctx = wimfs_get_context();
	struct wimlib_unix_data unix_data;

	memset(stbuf, 0, sizeof(struct stat));
	if ((ctx->mount_flags & WIMLIB_MOUNT_FLAG_UNIX_DATA) &&
	    inode_get_unix_data(inode, &unix_data))
	{
		/* Use the user ID, group ID, mode, and device ID from the
		 * inode's extra UNIX metadata information.  */
		stbuf->st_uid = unix_data.uid;
		stbuf->st_gid = unix_data.gid;
		stbuf->st_mode = unix_data.mode;
		stbuf->st_rdev = unix_data.rdev;
	} else {
		/* Generate default values for the user ID, group ID, and mode.
		 *
		 * Note: in the case of an allow_other mount, fuse_context.uid
		 * may not be the same as wimfs_context.owner_uid!  */
		stbuf->st_uid = ctx->owner_uid;
		stbuf->st_gid = ctx->owner_gid;
		stbuf->st_mode = inode_default_unix_mode(inode);
	}
	stbuf->st_ino = inode->i_ino;
	stbuf->st_nlink = inode->i_nlink;
	if (lte)
		stbuf->st_size = lte->size;
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

/* Update the last access and last write timestamps of a WIM inode.  */
static void
touch_inode(struct wim_inode *inode)
{
	u64 now = get_wim_timestamp();
	inode->i_last_access_time = now;
	inode->i_last_write_time = now;
}

static void
touch_parent(struct wim_dentry *dentry)
{
	touch_inode(dentry->d_parent->d_inode);
}

/*
 * Create a new file in the staging directory for a read-write mounted image.
 *
 * On success, returns the file descriptor for the new staging file, opened for
 * writing.  In addition, stores the allocated name of the staging file in
 * @name_ret.
 *
 * On failure, returns -1 and sets errno.
 */
static int
create_staging_file(const struct wimfs_context *ctx, char **name_ret)
{

	static const size_t STAGING_FILE_NAME_LEN = 20;
	char *name;
	int fd;

	name = MALLOC(STAGING_FILE_NAME_LEN + 1);
	if (!name)
		return -1;
	name[STAGING_FILE_NAME_LEN] = '\0';

retry:
	randomize_char_array_with_alnum(name, STAGING_FILE_NAME_LEN);
	fd = openat(ctx->staging_dir_fd, name,
		    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
	if (unlikely(fd < 0)) {
		if (unlikely(errno == EEXIST))
			/* Try again with another name.  */
			goto retry;
		FREE(name);
	} else {
		*name_ret = name;
	}
	return fd;
}

/*
 * Extract a WIM resource to the staging directory.
 * This is necessary if a stream using the resource is being opened for writing.
 *
 * @inode
 *	The inode containing the stream being opened for writing.
 *
 * @stream_idx
 *	The index of the stream in @inode being opened for writing.
 *
 * @lte_ptr
 *	*lte_ptr is the lookup table entry for the stream being extracted, or
 *	NULL if the stream does not have a lookup table entry (which is possible
 *	if the stream is empty).  On success, *lte_ptr will be set to point to a
 *	lookup table entry that represents the resource in its new location in a
 *	staging file.  This may be the same as the old entry in the case that it
 *	was reused, or it may be a new entry.
 *
 * @size
 *	Number of bytes of the stream to extract and include in the staging file
 *	resource.  It may be less than the actual stream length, in which case
 *	only a prefix of the resource will be extracted.  It may also be more
 *	than the actual stream length, in which case the extra space will be
 *	zero-filled.
 *
 * Returns 0 or a -errno code.
 */
static int
extract_resource_to_staging_dir(struct wim_inode *inode,
				u16 stream_idx,
				struct wim_lookup_table_entry **lte_ptr,
				off_t size,
				const struct wimfs_context *ctx)
{
	struct wim_lookup_table_entry *old_lte;
	struct wim_lookup_table_entry *new_lte;
	char *staging_file_name;
	int staging_fd;
	off_t extract_size;
	int result;
	u32 stream_id;
	int ret;

	old_lte = *lte_ptr;

	/* Create the staging file.  */
	staging_fd = create_staging_file(ctx, &staging_file_name);
	if (unlikely(staging_fd < 0))
		return -errno;

	/* Extract the stream to the staging file (possibly truncated).  */
	if (old_lte) {
		struct filedes fd;

		filedes_init(&fd, staging_fd);
		errno = 0;
		extract_size = min(old_lte->size, size);
		result = extract_stream_to_fd(old_lte, &fd, extract_size);
	} else {
		extract_size = 0;
		result = 0;
	}

	/* In the case of truncate() to more than the file length, extend the
	 * staging file with zeroes by calling ftruncate().  */
	if (!result && size > extract_size)
		result = ftruncate(staging_fd, size);

	/* Close the staging file.  */
	if (close(staging_fd))
		result = -1;

	/* If an error occurred, unlink the staging file.  */
	if (unlikely(result)) {
		/* extract_stream_to_fd() should set errno, but if it didn't,
		 * set a default value.  */
		ret = errno ? -errno : -EIO;
		goto out_delete_staging_file;
	}

	/* Now deal with the lookup table entries.  We may be able to re-use the
	 * existing entry, but we may have to create a new one instead.  */

	stream_id = inode_stream_idx_to_id(inode, stream_idx);

	if (old_lte && inode->i_nlink == old_lte->refcnt) {
		/* The reference count of the existing lookup table entry is the
		 * same as the link count of the inode that contains the stream
		 * we're opening.  Therefore, all the references to the lookup
		 * table entry correspond to the stream we're trying to extract,
		 * so the lookup table entry can be re-used.  */
		lookup_table_unlink(ctx->wim->lookup_table, old_lte);
		lte_put_resource(old_lte);
		new_lte = old_lte;
	} else {
		/* We need to split the old lookup table entry because it also
		 * has other references.  Or, there was no old lookup table
		 * entry, so we need to create a new one anyway.  */

		new_lte = new_lookup_table_entry();
		if (unlikely(!new_lte)) {
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
		 * from the fd's opened to the old entry.  */
		for (u16 i = 0, j = 0; j < inode->i_num_opened_fds; i++) {
			struct wimfs_fd *fd;
			int raw_fd;

			fd = inode->i_fds[i];
			if (!fd)
				continue;

			j++;

			if (fd->f_stream_id != stream_id)
				continue;

			/* This is a readonly fd for the same stream.  */
			fd->f_lte = new_lte;
			new_lte->num_opened_fds++;
			raw_fd = openat(ctx->staging_dir_fd, staging_file_name,
					O_RDONLY | O_NOFOLLOW);
			if (unlikely(raw_fd < 0)) {
				ret = -errno;
				goto out_revert_fd_changes;
			}
			filedes_init(&fd->f_staging_fd, raw_fd);
		}
		if (old_lte) {
			old_lte->num_opened_fds -= new_lte->num_opened_fds;
			old_lte->refcnt -= inode->i_nlink;
		}
	}

	new_lte->refcnt		   = inode->i_nlink;
	new_lte->resource_location = RESOURCE_IN_STAGING_FILE;
	new_lte->staging_file_name = staging_file_name;
	new_lte->staging_dir_fd	   = ctx->staging_dir_fd;
	new_lte->size		   = size;

	add_unhashed_stream(new_lte, inode, stream_id,
			    &wim_get_current_image_metadata(ctx->wim)->unhashed_streams);
	if (stream_idx == 0)
		inode->i_lte = new_lte;
	else
		inode->i_ads_entries[stream_idx - 1].lte = new_lte;
	*lte_ptr = new_lte;
	return 0;

out_revert_fd_changes:
	for (u16 i = 0; new_lte->num_opened_fds; i++) {
		struct wimfs_fd *fd = inode->i_fds[i];
		if (fd && fd->f_stream_id == stream_id) {
			fd->f_lte = old_lte;
			if (filedes_valid(&fd->f_staging_fd)) {
				filedes_close(&fd->f_staging_fd);
				filedes_invalidate(&fd->f_staging_fd);
			}
			new_lte->num_opened_fds--;
		}
	}
	free_lookup_table_entry(new_lte);
out_delete_staging_file:
	unlinkat(ctx->staging_dir_fd, staging_file_name, 0);
	FREE(staging_file_name);
	return ret;
}

/*
 * Create the staging directory for the WIM file.
 *
 * The staging directory will be created in the directory specified by the open
 * file descriptor @parent_dir_fd.  It will be given a randomly generated name
 * based on @wim_basename, the name of the WIM file.
 *
 * On success, returns a file descriptor to the open staging directory with
 * O_RDONLY access.  In addition, stores the allocated name of the staging
 * directory (relative to @parent_dir_fd) in @staging_dir_name_ret.
 * On failure, returns -1 and sets errno.
 */
static int
make_staging_dir_at(int parent_dir_fd, const char *wim_basename,
		    char **staging_dir_name_ret)
{
	static const char common_suffix[8] = ".staging";
	static const size_t random_suffix_len = 10;
	size_t wim_basename_len;
	size_t staging_dir_name_len;
	char *staging_dir_name;
	char *p;
	int fd;

	wim_basename_len = strlen(wim_basename);
	staging_dir_name_len = wim_basename_len + sizeof(common_suffix) +
			       random_suffix_len;
	staging_dir_name = MALLOC(staging_dir_name_len + 1);
	if (!staging_dir_name)
		return -1;

	p = staging_dir_name;
	p = mempcpy(p, wim_basename, wim_basename_len);
	p = mempcpy(p, common_suffix, sizeof(common_suffix));
	randomize_char_array_with_alnum(p, random_suffix_len);
	p += random_suffix_len;
	*p = '\0';

	if (mkdirat(parent_dir_fd, staging_dir_name, 0700))
		goto err1;

	fd = openat(parent_dir_fd, staging_dir_name,
		    O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (fd < 0)
		goto err2;

	*staging_dir_name_ret = staging_dir_name;
	return fd;

err2:
	unlinkat(parent_dir_fd, staging_dir_name, AT_REMOVEDIR);
err1:
	FREE(staging_dir_name);
	return -1;
}

/*
 * Create the staging directory and set ctx->staging_dir_fd,
 * ctx->staging_dir_name, and ctx->parent_dir_fd.
 */
static int
make_staging_dir(struct wimfs_context *ctx, const char *parent_dir_path)
{
	const char *wim_basename;
	char *end = NULL;
	int ret;

	wim_basename = path_basename(ctx->wim->filename);

	if (!parent_dir_path) {
		/* The user did not specify a directory.  Default to creating
		 * the staging directory alongside the WIM file.  */
		if (wim_basename > ctx->wim->filename) {
			parent_dir_path = ctx->wim->filename;
			end = (char *)(wim_basename - 1);
			/* *end must be a slash.  Temporarily overwrite it so we
			 * can open the parent directory.  */
			*end = '\0';
		} else {
			parent_dir_path = ".";
		}
	}

	/* Open the parent directory (in which we'll create our staging
	 * directory).  */
	ctx->parent_dir_fd = open(parent_dir_path, O_RDONLY | O_DIRECTORY);
	if (ctx->parent_dir_fd < 0) {
		ERROR_WITH_ERRNO("Can't open directory \"%s\"",
				 parent_dir_path);
		ret = WIMLIB_ERR_OPENDIR;
		goto out_restore_wim_filename;
	}

	ctx->staging_dir_fd = make_staging_dir_at(ctx->parent_dir_fd,
						  wim_basename,
						  &ctx->staging_dir_name);
	if (ctx->staging_dir_fd < 0) {
		ERROR_WITH_ERRNO("Can't create staging directory in \"%s\"",
				 parent_dir_path);
		close(ctx->parent_dir_fd);
		ret = WIMLIB_ERR_MKDIR;
		goto out_restore_wim_filename;
	}
	ret = 0;
out_restore_wim_filename:
	if (end)
		*end = '/';
	return ret;
}

/* Deletes the staging directory, undoing the effects of a succesful call to
 * make_staging_dir().  */
static void
delete_staging_dir(struct wimfs_context *ctx)
{
	DIR *dir;
	struct dirent *ent;

	dir = fdopendir(ctx->staging_dir_fd);
	if (dir) {
		while ((ent = readdir(dir)))
			unlinkat(ctx->staging_dir_fd, ent->d_name, 0);
		closedir(dir);
	} else {
		close(ctx->staging_dir_fd);
	}
	if (unlinkat(ctx->parent_dir_fd, ctx->staging_dir_name, AT_REMOVEDIR))
		WARNING_WITH_ERRNO("Could not delete staging directory");
	FREE(ctx->staging_dir_name);
	close(ctx->parent_dir_fd);
}

static void
reassign_inode_numbers(struct wimfs_context *ctx)
{
	struct wim_image_metadata *imd;
	struct wim_inode *inode;

	ctx->next_ino = 1;
	imd = wim_get_current_image_metadata(ctx->wim);
	image_for_each_inode(inode, imd)
		inode->i_ino = ctx->next_ino++;
}

static void
release_extra_refcnts(struct wimfs_context *ctx)
{
	struct list_head *list = &ctx->orig_stream_list;
	struct wim_lookup_table *lookup_table = ctx->wim->lookup_table;
	struct wim_lookup_table_entry *lte, *tmp;

	list_for_each_entry_safe(lte, tmp, list, orig_stream_list) {
		u32 n = lte->out_refcnt;
		while (n--)
			lte_decrement_refcnt(lte, lookup_table);
	}
}

static void
delete_empty_streams(struct wimfs_context *ctx)
{
	struct wim_lookup_table_entry *lte, *tmp;
	struct wim_image_metadata *imd;

	imd = wim_get_current_image_metadata(ctx->wim);

        image_for_each_unhashed_stream_safe(lte, tmp, imd) {
                if (!lte->size) {
                        *retrieve_lte_pointer(lte) = NULL;
                        list_del(&lte->unhashed_list);
                        free_lookup_table_entry(lte);
                }
        }
}

static void
inode_close_fds(struct wim_inode *inode)
{
	u16 num_open_fds = inode->i_num_opened_fds;
	for (u16 i = 0; num_open_fds; i++) {
		if (inode->i_fds[i]) {
			close_wimfs_fd(inode->i_fds[i]);
			num_open_fds--;
		}
	}
}

static void
close_all_fds(struct wimfs_context *ctx)
{
	struct wim_inode *inode, *tmp;
	struct wim_image_metadata *imd;

	imd = wim_get_current_image_metadata(ctx->wim);

	list_for_each_entry_safe(inode, tmp, &imd->inode_list, i_list)
		inode_close_fds(inode);
}

/* Moves the currently selected image, which may have been modified, to a new
 * index, and sets the original index to refer to a reset (unmodified) copy of
 * the image.  */
static int
renew_current_image(struct wimfs_context *ctx)
{
	WIMStruct *wim = ctx->wim;
	int idx = wim->current_image - 1;
	struct wim_image_metadata *imd = wim->image_metadata[idx];
	struct wim_image_metadata *replace_imd;
	struct wim_lookup_table_entry *new_lte;
	int ret;

	/* Create 'replace_imd' structure to use for the reset original,
	 * unmodified image.  */
	ret = WIMLIB_ERR_NOMEM;
	replace_imd = new_image_metadata();
	if (!replace_imd)
		goto err;

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
err:
	return ret;
}

static enum wimlib_progress_status
commit_progress_func(enum wimlib_progress_msg msg,
		     union wimlib_progress_info *info, void *progctx)
{
	mqd_t mq = *(mqd_t *)progctx;
	struct commit_progress_report report;

	memset(&report, 0, sizeof(report));
	report.msg = msg;
	if (info)
		report.info = *info;
	mq_send(mq, (const char *)&report, sizeof(report), 1);
	return WIMLIB_PROGRESS_STATUS_CONTINUE;
}

/* Commit the mounted image to the underlying WIM file.  */
static int
commit_image(struct wimfs_context *ctx, int unmount_flags, mqd_t mq)
{
	int write_flags;

	if (unmount_flags & WIMLIB_UNMOUNT_FLAG_SEND_PROGRESS)
		wimlib_register_progress_function(ctx->wim,
						  commit_progress_func, &mq);
	else
		wimlib_register_progress_function(ctx->wim, NULL, NULL);

	if (unmount_flags & WIMLIB_UNMOUNT_FLAG_NEW_IMAGE) {
		int ret = renew_current_image(ctx);
		if (ret)
			return ret;
	} else {
		release_extra_refcnts(ctx);
	}
	INIT_LIST_HEAD(&ctx->orig_stream_list);
	delete_empty_streams(ctx);
	xml_update_image_info(ctx->wim, ctx->wim->current_image);

	write_flags = 0;
	if (unmount_flags & WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY)
		write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
	if (unmount_flags & WIMLIB_UNMOUNT_FLAG_REBUILD)
		write_flags |= WIMLIB_WRITE_FLAG_REBUILD;
	if (unmount_flags & WIMLIB_UNMOUNT_FLAG_RECOMPRESS)
		write_flags |= WIMLIB_WRITE_FLAG_RECOMPRESS;
	return wimlib_overwrite(ctx->wim, write_flags, 0);
}

static int
unmount_wimfs(const struct wimfs_unmount_info *info)
{
	struct fuse_context *fuse_ctx = fuse_get_context();
	struct wimfs_context *wimfs_ctx = WIMFS_CTX(fuse_ctx);
	int unmount_flags = info->unmount_flags;
	mqd_t mq = (mqd_t)-1;
	int status;

	if (fuse_ctx->uid != wimfs_ctx->owner_uid &&
	    fuse_ctx->uid != 0)
		return -EPERM;

	if (info->mq_name[0]) {
		mq = mq_open(info->mq_name, O_WRONLY | O_NONBLOCK);
		if (mq == (mqd_t)-1)
			return -errno;
	}

	/* Ignore COMMIT if the image is mounted read-only.  */
	if (!(wimfs_ctx->mount_flags & WIMLIB_MOUNT_FLAG_READWRITE))
		unmount_flags &= ~WIMLIB_UNMOUNT_FLAG_COMMIT;

	if (wimfs_ctx->num_open_fds) {
		if ((unmount_flags & (WIMLIB_UNMOUNT_FLAG_COMMIT |
				      WIMLIB_UNMOUNT_FLAG_FORCE))
				 == WIMLIB_UNMOUNT_FLAG_COMMIT)
		{
			status = WIMLIB_ERR_MOUNTED_IMAGE_IS_BUSY;
			goto out_send_status;
		}
		close_all_fds(wimfs_ctx);
	}

	if (unmount_flags & WIMLIB_UNMOUNT_FLAG_COMMIT)
		status = commit_image(wimfs_ctx, unmount_flags, mq);
	else
		status = 0;
	fuse_exit(fuse_ctx->fuse);
out_send_status:
	if (mq != (mqd_t)-1) {
		mq_send(mq, (const char *)&status, sizeof(int), 1);
		mq_close(mq);
	}
	return 0;
}

static int
wimfs_chmod(const char *path, mode_t mask)
{
	const struct wimfs_context *ctx = wimfs_get_context();
	struct wim_inode *inode;
	struct wimlib_unix_data unix_data;

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_UNIX_DATA))
		return -EOPNOTSUPP;

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	unix_data.uid = ctx->owner_uid;
	unix_data.gid = ctx->owner_gid;
	unix_data.mode = mask;
	unix_data.rdev = 0;

	if (!inode_set_unix_data(inode, &unix_data, UNIX_DATA_MODE))
		return -ENOMEM;

	return 0;
}

static int
wimfs_chown(const char *path, uid_t uid, gid_t gid)
{
	const struct wimfs_context *ctx = wimfs_get_context();
	struct wim_inode *inode;
	struct wimlib_unix_data unix_data;
	int which;

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_UNIX_DATA))
		return -EOPNOTSUPP;

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	which = 0;

	if (uid != (uid_t)-1)
		which |= UNIX_DATA_UID;
	else
		uid = ctx->owner_uid;

	if (gid != (gid_t)-1)
		which |= UNIX_DATA_GID;
	else
		gid = ctx->owner_gid;

	unix_data.uid = uid;
	unix_data.gid = gid;
	unix_data.mode = inode_default_unix_mode(inode);
	unix_data.rdev = 0;

	if (!inode_set_unix_data(inode, &unix_data, which))
		return -ENOMEM;

	return 0;
}

static int
wimfs_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = WIMFS_FD(fi);
	return inode_to_stbuf(fd->f_inode, fd->f_lte, stbuf);
}

static int
wimfs_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = WIMFS_FD(fi);
	if (ftruncate(fd->f_staging_fd.fd, size))
		return -errno;
	touch_inode(fd->f_inode);
	fd->f_lte->size = size;
	return 0;
}

static int
wimfs_getattr(const char *path, struct stat *stbuf)
{
	const struct wimfs_context *ctx = wimfs_get_context();
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	int ret;

	ret = wim_pathname_to_stream(ctx, path, LOOKUP_FLAG_DIRECTORY_OK,
				     &dentry, &lte, NULL);
	if (ret)
		return ret;
	return inode_to_stbuf(dentry->d_inode, lte, stbuf);
}

static int
copy_xattr(char *dest, size_t destsize, const void *src, size_t srcsize)
{
	if (!destsize)
		return srcsize;
	if (destsize < srcsize)
		return -ERANGE;
	memcpy(dest, src, srcsize);
	return srcsize;
}

static int
wimfs_getxattr(const char *path, const char *name, char *value,
	       size_t size)
{
	struct fuse_context *fuse_ctx = fuse_get_context();
	const struct wimfs_context *ctx = WIMFS_CTX(fuse_ctx);
	struct wim_inode *inode;
	struct wim_ads_entry *ads_entry;
	struct wim_lookup_table_entry *lte;

	if (!strncmp(name, "wimfs.", 6)) {
		/* Handle some magical extended attributes.  These really should
		 * be ioctls, but directory ioctls aren't supported until
		 * libfuse 2.9, and even then they are broken.  */
		name += 6;
		if (!strcmp(name, "wim_filename")) {
			return copy_xattr(value, size, ctx->wim->filename,
					  strlen(ctx->wim->filename));
		}
		if (!strcmp(name, "wim_info")) {
			struct wimlib_wim_info info;

			wimlib_get_wim_info(ctx->wim, &info);

			return copy_xattr(value, size, &info, sizeof(info));
		}
		if (!strcmp(name, "mounted_image")) {
			return copy_xattr(value, size,
					  &ctx->wim->current_image, sizeof(int));
		}
		if (!strcmp(name, "mount_flags")) {
			return copy_xattr(value, size,
					  &ctx->mount_flags, sizeof(int));
		}
		if (!strcmp(name, "unmount")) {
			struct wimfs_unmount_info info;
			memset(&info, 0, sizeof(info));
			return unmount_wimfs(&info);
		}
		return -ENOATTR;
	}

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR))
		return -ENOTSUP;

	if (strncmp(name, "user.", 5))
		return -ENOATTR;
	name += 5;

	/* Querying a named data stream  */

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	ads_entry = inode_get_ads_entry(inode, name);
	if (!ads_entry)
		return (errno == ENOENT) ? -ENOATTR : -errno;

	lte = ads_entry->lte;
	if (!lte)
		return 0;

	if (unlikely(lte->size > INT_MAX))
		return -EFBIG;

	if (size) {
		if (lte->size > size)
			return -ERANGE;

		if (read_full_stream_into_buf(lte, value))
			return -errno;
	}
	return lte->size;
}

static int
wimfs_link(const char *existing_path, const char *new_path)
{
	WIMStruct *wim = wimfs_get_WIMStruct();
	const char *new_name;
	struct wim_inode *inode;
	struct wim_dentry *dir;
	struct wim_dentry *new_alias;

	inode = wim_pathname_to_inode(wim, existing_path);
	if (!inode)
		return -errno;

	if (inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
				   FILE_ATTRIBUTE_REPARSE_POINT))
		return -EPERM;

	new_name = path_basename(new_path);

	dir = get_parent_dentry(wim, new_path, WIMLIB_CASE_SENSITIVE);
	if (!dir)
		return -errno;

	if (!dentry_is_directory(dir))
		return -ENOTDIR;

	if (get_dentry_child_with_name(dir, new_name, WIMLIB_CASE_SENSITIVE))
		return -EEXIST;

	if (new_dentry(new_name, &new_alias))
		return -ENOMEM;

	new_alias->d_inode = inode;
	inode_add_dentry(new_alias, inode);
	dentry_add_child(dir, new_alias);
	touch_inode(dir->d_inode);
	inode->i_nlink++;
	inode_ref_streams(inode);
	return 0;
}

static int
wimfs_listxattr(const char *path, char *list, size_t size)
{
	const struct wimfs_context *ctx = wimfs_get_context();
	const struct wim_inode *inode;
	char *p = list;
	char *end = list + size;
	int total_size = 0;

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR))
		return -ENOTSUP;

	/* List named data streams, or get the list size.  We report each named
	 * data stream "X" as an extended attribute "user.X".  */

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	for (u16 i = 0; i < inode->i_num_ads; i++) {
		const struct wim_ads_entry *entry;
		char *stream_name_mbs;
		size_t stream_name_mbs_nbytes;

		entry = &inode->i_ads_entries[i];

		if (!entry->stream_name_nbytes)
			continue;

		if (utf16le_to_tstr(entry->stream_name,
				    entry->stream_name_nbytes,
				    &stream_name_mbs,
				    &stream_name_mbs_nbytes))
			return -errno;

		if (unlikely(INT_MAX - total_size < stream_name_mbs_nbytes + 6)) {
			FREE(stream_name_mbs);
			return -EFBIG;
		}

		total_size += stream_name_mbs_nbytes + 6;
		if (size) {
			if (end - p < stream_name_mbs_nbytes + 6) {
				FREE(stream_name_mbs);
				return -ERANGE;
			}
			p = mempcpy(p, "user.", 5);
			p = mempcpy(p, stream_name_mbs, stream_name_mbs_nbytes);
			*p++ = '\0';
		}
		FREE(stream_name_mbs);
	}
	return total_size;
}

static int
wimfs_mkdir(const char *path, mode_t mode)
{
	struct wim_dentry *dentry;
	int ret;

	/* Note: according to fuse.h, mode may not include S_IFDIR  */
	ret = create_dentry(fuse_get_context(), path, mode | S_IFDIR, 0,
			    FILE_ATTRIBUTE_DIRECTORY, &dentry);
	if (ret)
		return ret;
	touch_parent(dentry);
	return 0;
}

static int
wimfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	struct fuse_context *fuse_ctx = fuse_get_context();
	struct wimfs_context *wimfs_ctx = WIMFS_CTX(fuse_ctx);
	const char *stream_name;

	if ((wimfs_ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS)
	     && (stream_name = path_stream_name(path)))
	{
		struct wim_ads_entry *old_entry;
		struct wim_ads_entry *new_entry;
		struct wim_inode *inode;
		char *p;

		/* Create a named data stream.  */

		if (!S_ISREG(mode))
			return -EOPNOTSUPP;

		p = (char *)stream_name - 1;

		*p = '\0';
		inode = wim_pathname_to_inode(wimfs_ctx->wim, path);
		*p = ':';
		if (!inode)
			return -errno;

		old_entry = inode_get_ads_entry(inode, stream_name);
		if (old_entry)
			return -EEXIST;
		if (errno != ENOENT)
			return -errno;

		new_entry = inode_add_ads(inode, stream_name);
		if (!new_entry)
			return -errno;
		return 0;
	} else {
		/* Create a regular file, device node, named pipe, or socket.
		 */
		struct wim_dentry *dentry;
		int ret;

		if (!S_ISREG(mode) &&
		    !(wimfs_ctx->mount_flags & WIMLIB_MOUNT_FLAG_UNIX_DATA))
			return -EPERM;

		/* Note: we still use FILE_ATTRIBUTE_NORMAL for device nodes,
		 * named pipes, and sockets.  The real mode is in the UNIX
		 * metadata.  */
		ret = create_dentry(fuse_ctx, path, mode, rdev,
				    FILE_ATTRIBUTE_NORMAL, &dentry);
		if (ret)
			return ret;
		touch_parent(dentry);
		return 0;
	}
}

static int
wimfs_open(const char *path, struct fuse_file_info *fi)
{
	struct wimfs_context *ctx = wimfs_get_context();
	struct wim_dentry *dentry;
	struct wim_inode *inode;
	struct wim_lookup_table_entry *lte;
	u16 stream_idx;
	struct wimfs_fd *fd;
	int ret;

	ret = wim_pathname_to_stream(ctx, path, 0, &dentry, &lte, &stream_idx);
	if (ret)
		return ret;

	inode = dentry->d_inode;

	/* The file resource may be in the staging directory (read-write mounts
	 * only) or in the WIM.  If it's in the staging directory, we need to
	 * open a native file descriptor for the corresponding file.  Otherwise,
	 * we can read the file resource directly from the WIM file if we are
	 * opening it read-only, but we need to extract the resource to the
	 * staging directory if we are opening it writable.  */

	if (flags_writable(fi->flags) &&
            (!lte || lte->resource_location != RESOURCE_IN_STAGING_FILE)) {
		ret = extract_resource_to_staging_dir(inode,
						      stream_idx,
						      &lte,
						      lte ? lte->size : 0,
						      ctx);
		if (ret)
			return ret;
	}

	ret = alloc_wimfs_fd(inode, inode_stream_idx_to_id(inode, stream_idx),
			     lte, &fd);
	if (ret)
		return ret;

	if (lte && lte->resource_location == RESOURCE_IN_STAGING_FILE) {
		int raw_fd;

		raw_fd = openat(lte->staging_dir_fd, lte->staging_file_name,
				(fi->flags & O_ACCMODE) | O_NOFOLLOW);
		if (raw_fd < 0) {
			close_wimfs_fd(fd);
			return -errno;
		}
		filedes_init(&fd->f_staging_fd, raw_fd);
	}
	fi->fh = (uintptr_t)fd;
	return 0;
}

static int
wimfs_opendir(const char *path, struct fuse_file_info *fi)
{
	WIMStruct *wim = wimfs_get_WIMStruct();
	struct wim_inode *inode;
	struct wimfs_fd *fd;
	int ret;

	inode = wim_pathname_to_inode(wim, path);
	if (!inode)
		return -errno;
	if (!inode_is_directory(inode))
		return -ENOTDIR;
	ret = alloc_wimfs_fd(inode, 0, NULL, &fd);
	if (ret)
		return ret;
	fi->fh = (uintptr_t)fd;
	return 0;
}

static int
wimfs_read(const char *path, char *buf, size_t size,
	   off_t offset, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = WIMFS_FD(fi);
	const struct wim_lookup_table_entry *lte;
	ssize_t ret;

	lte = fd->f_lte;
	if (!lte)
		return 0;

	if (offset >= lte->size)
		return 0;

	if (size > lte->size - offset)
		size = lte->size - offset;

	if (!size)
		return 0;

	switch (lte->resource_location) {
	case RESOURCE_IN_WIM:
		if (read_partial_wim_stream_into_buf(lte, size, offset, buf))
			ret = -errno;
		else
			ret = size;
		break;
	case RESOURCE_IN_STAGING_FILE:
		ret = raw_pread(&fd->f_staging_fd, buf, size, offset);
		if (ret < 0)
			ret = -errno;
		break;
	case RESOURCE_IN_ATTACHED_BUFFER:
		memcpy(buf, lte->attached_buffer + offset, size);
		ret = size;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int
wimfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	      off_t offset, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = WIMFS_FD(fi);
	const struct wim_inode *inode;
	const struct wim_dentry *child;
	int ret;

	inode = fd->f_inode;

	ret = filler(buf, ".", NULL, 0);
	if (ret)
		return ret;
	ret = filler(buf, "..", NULL, 0);
	if (ret)
		return ret;

	for_inode_child(child, inode) {
		char *file_name_mbs;
		size_t file_name_mbs_nbytes;

		ret = utf16le_to_tstr(child->file_name,
				      child->file_name_nbytes,
				      &file_name_mbs,
				      &file_name_mbs_nbytes);
		if (ret)
			return -errno;

		ret = filler(buf, file_name_mbs, NULL, 0);
		FREE(file_name_mbs);
		if (ret)
			return ret;
	}
	return 0;
}

static int
wimfs_readlink(const char *path, char *buf, size_t buf_len)
{
	WIMStruct *wim = wimfs_get_WIMStruct();
	const struct wim_inode *inode;
	ssize_t ret;

	inode = wim_pathname_to_inode(wim, path);
	if (!inode)
		return -errno;
	if (!inode_is_symlink(inode))
		return -EINVAL;
	if (buf_len == 0)
		return -EINVAL;
	ret = wim_inode_readlink(inode, buf, buf_len - 1, NULL);
	if (ret >= 0) {
		buf[ret] = '\0';
		ret = 0;
	} else if (ret == -ENAMETOOLONG) {
		buf[buf_len - 1] = '\0';
	}
	return ret;
}

/* We use this for both release() and releasedir(), since in both cases we
 * simply need to close the file descriptor.  */
static int
wimfs_release(const char *path, struct fuse_file_info *fi)
{
	return close_wimfs_fd(WIMFS_FD(fi));
}

static int
wimfs_removexattr(const char *path, const char *name)
{
	struct wimfs_context *ctx = wimfs_get_context();
	struct wim_inode *inode;
	struct wim_ads_entry *ads_entry;

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR))
		return -ENOTSUP;

	if (strncmp(name, "user.", 5))
		return -ENOATTR;
	name += 5;

	/* Removing a named data stream.  */

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	ads_entry = inode_get_ads_entry(inode, name);
	if (!ads_entry)
		return (errno == ENOENT) ? -ENOATTR : -errno;

	inode_remove_ads(inode, ads_entry, ctx->wim->lookup_table);
	return 0;
}

static int
wimfs_rename(const char *from, const char *to)
{
	return rename_wim_path(wimfs_get_WIMStruct(), from, to,
			       WIMLIB_CASE_SENSITIVE, NULL);
}

static int
wimfs_rmdir(const char *path)
{
	WIMStruct *wim = wimfs_get_WIMStruct();
	struct wim_dentry *dentry;

	dentry = get_dentry(wim, path, WIMLIB_CASE_SENSITIVE);
	if (!dentry)
		return -errno;

	if (!dentry_is_directory(dentry))
		return -ENOTDIR;

	if (dentry_has_children(dentry))
		return -ENOTEMPTY;

	touch_parent(dentry);
	remove_dentry(dentry, wim->lookup_table);
	return 0;
}

static int
wimfs_setxattr(const char *path, const char *name,
	       const char *value, size_t size, int flags)
{
	struct wimfs_context *ctx = wimfs_get_context();
	struct wim_inode *inode;
	struct wim_ads_entry *existing_entry;

	if (!strncmp(name, "wimfs.", 6)) {
		/* Handle some magical extended attributes.  These really should
		 * be ioctls, but directory ioctls aren't supported until
		 * libfuse 2.9, and even then they are broken.  */
		name += 6;
		if (!strcmp(name, "unmount")) {
			if (size < sizeof(struct wimfs_unmount_info))
				return -EINVAL;
			return unmount_wimfs((const void *)value);
		}
		return -ENOATTR;
	}

	if (!(ctx->mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR))
		return -ENOTSUP;

	if (strncmp(name, "user.", 5))
		return -ENOATTR;
	name += 5;

	/* Setting the contents of a named data stream.  */

	inode = wim_pathname_to_inode(ctx->wim, path);
	if (!inode)
		return -errno;

	existing_entry = inode_get_ads_entry(inode, name);
	if (existing_entry) {
		if (flags & XATTR_CREATE)
			return -EEXIST;
	} else {
		if (errno != ENOENT)
			return -errno;
		if (flags & XATTR_REPLACE)
			return -ENOATTR;
	}

	if (!inode_add_ads_with_data(inode, name, value,
				     size, ctx->wim->lookup_table))
		return -errno;
	if (existing_entry)
		inode_remove_ads(inode, existing_entry, ctx->wim->lookup_table);
	return 0;
}

static int
wimfs_symlink(const char *to, const char *from)
{
	struct fuse_context *fuse_ctx = fuse_get_context();
	struct wimfs_context *wimfs_ctx = WIMFS_CTX(fuse_ctx);
	struct wim_dentry *dentry;
	int ret;

	ret = create_dentry(fuse_ctx, from, S_IFLNK | 0777, 0,
			    FILE_ATTRIBUTE_REPARSE_POINT, &dentry);
	if (ret)
		return ret;
	dentry->d_inode->i_reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;
	ret = wim_inode_set_symlink(dentry->d_inode, to,
				    wimfs_ctx->wim->lookup_table);
	if (ret) {
		remove_dentry(dentry, wimfs_ctx->wim->lookup_table);
		if (ret == WIMLIB_ERR_NOMEM)
			ret = -ENOMEM;
		else
			ret = -EINVAL;
	} else {
		touch_parent(dentry);
	}
	return ret;
}

static int
wimfs_truncate(const char *path, off_t size)
{
	const struct wimfs_context *ctx = wimfs_get_context();
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	u16 stream_idx;
	int ret;
	int fd;

	ret = wim_pathname_to_stream(ctx, path, 0, &dentry, &lte, &stream_idx);
	if (ret)
		return ret;

	if (!lte && !size)
		return 0;

	if (!lte || lte->resource_location != RESOURCE_IN_STAGING_FILE) {
		return extract_resource_to_staging_dir(dentry->d_inode,
						       stream_idx, &lte,
						       size, ctx);
	}

	/* Truncate the staging file.  */
	fd = openat(lte->staging_dir_fd, lte->staging_file_name,
		    O_WRONLY | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	ret = ftruncate(fd, size);
	if (close(fd) || ret)
		return -errno;
	lte->size = size;
	return 0;
}

static int
wimfs_unlink(const char *path)
{
	const struct wimfs_context *ctx = wimfs_get_context();
	struct wim_dentry *dentry;
	u16 stream_idx;
	int ret;

	ret = wim_pathname_to_stream(ctx, path, 0, &dentry, NULL, &stream_idx);
	if (ret)
		return ret;

	if (inode_stream_name_nbytes(dentry->d_inode, stream_idx) == 0) {
		touch_parent(dentry);
		remove_dentry(dentry, ctx->wim->lookup_table);
	} else {
		inode_remove_ads(dentry->d_inode,
				 &dentry->d_inode->i_ads_entries[stream_idx - 1],
				 ctx->wim->lookup_table);
	}
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
	WIMStruct *wim = wimfs_get_WIMStruct();
	struct wim_inode *inode;

	inode = wim_pathname_to_inode(wim, path);
	if (!inode)
		return -errno;

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
	WIMStruct *wim = wimfs_get_WIMStruct();
	struct wim_inode *inode;

	inode = wim_pathname_to_inode(wim, path);
	if (!inode)
		return -errno;

	inode->i_last_access_time = unix_timestamp_to_wim(times->actime);
	inode->i_last_write_time = unix_timestamp_to_wim(times->modtime);
	return 0;
}
#endif /* !HAVE_UTIMENSAT */

static int
wimfs_write(const char *path, const char *buf, size_t size,
	    off_t offset, struct fuse_file_info *fi)
{
	struct wimfs_fd *fd = WIMFS_FD(fi);
	ssize_t ret;

	ret = raw_pwrite(&fd->f_staging_fd, buf, size, offset);
	if (ret < 0)
		return -errno;

	if (offset + size > fd->f_lte->size)
		fd->f_lte->size = offset + size;

	touch_inode(fd->f_inode);
	return ret;
}

static struct fuse_operations wimfs_operations = {
	.chmod       = wimfs_chmod,
	.chown       = wimfs_chown,
	.fgetattr    = wimfs_fgetattr,
	.ftruncate   = wimfs_ftruncate,
	.getattr     = wimfs_getattr,
	.getxattr    = wimfs_getxattr,
	.link        = wimfs_link,
	.listxattr   = wimfs_listxattr,
	.mkdir       = wimfs_mkdir,
	.mknod       = wimfs_mknod,
	.open        = wimfs_open,
	.opendir     = wimfs_opendir,
	.read        = wimfs_read,
	.readdir     = wimfs_readdir,
	.readlink    = wimfs_readlink,
	.release     = wimfs_release,
	.releasedir  = wimfs_release,
	.removexattr = wimfs_removexattr,
	.rename      = wimfs_rename,
	.rmdir       = wimfs_rmdir,
	.setxattr    = wimfs_setxattr,
	.symlink     = wimfs_symlink,
	.truncate    = wimfs_truncate,
	.unlink      = wimfs_unlink,
#ifdef HAVE_UTIMENSAT
	.utimens     = wimfs_utimens,
#else
	.utime       = wimfs_utime,
#endif
	.write       = wimfs_write,

	/* We keep track of file descriptor structures (struct wimfs_fd), so
	 * there is no need to have the file path provided on operations such as
	 * read().  */
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
	int ret;
	struct wim_image_metadata *imd;
	struct wimfs_context ctx;
	char *fuse_argv[16];
	int fuse_argc;

	if (!wim || !dir || !*dir)
		return WIMLIB_ERR_INVALID_PARAM;

	if (mount_flags & ~(WIMLIB_MOUNT_FLAG_READWRITE |
			    WIMLIB_MOUNT_FLAG_DEBUG |
			    WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE |
			    WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR |
			    WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS |
			    WIMLIB_MOUNT_FLAG_UNIX_DATA |
			    WIMLIB_MOUNT_FLAG_ALLOW_OTHER))
		return WIMLIB_ERR_INVALID_PARAM;

	/* For read-write mount, check for write access to the WIM.  */
	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		ret = can_delete_from_wim(wim);
		if (ret)
			return ret;
	}

	/* Select the image to mount.  */
	ret = select_wim_image(wim, image);
	if (ret)
		return ret;

	/* Get the metadata for the image to mount.  */
	imd = wim_get_current_image_metadata(wim);

	if (imd->modified) {
		/* To avoid complicating things, we don't support mounting
		 * images to which in-memory modifications have already been
		 * made.  */
		ERROR("Cannot mount a modified WIM image!");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	ret = lock_wim_for_append(wim, wim->in_fd.fd);
	if (ret)
		return ret;

	/* If the user did not specify an interface for accessing named
	 * data streams, use the default (extended attributes).  */
	if (!(mount_flags & (WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE |
			     WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR |
			     WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS)))
		mount_flags |= WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR;

	/* Start initializing the wimfs_context.  */
	memset(&ctx, 0, sizeof(struct wimfs_context));
	ctx.wim = wim;
	ctx.mount_flags = mount_flags;
	if (mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS)
		ctx.default_lookup_flags = LOOKUP_FLAG_ADS_OK;
	/* For read-write mount, create the staging directory.  */
	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		ret = make_staging_dir(&ctx, staging_dir);
		if (ret)
			goto out_unlock;
	}
	ctx.owner_uid = getuid();
	ctx.owner_gid = getgid();

	/* Add each stream referenced by files in the image to a list and
	 * preemptively double the number of references to each.  The latter is
	 * done to allow implementing the WIMLIB_UNMOUNT_FLAG_NEW_IMAGE
	 * semantics.  */
	INIT_LIST_HEAD(&ctx.orig_stream_list);
	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		unsigned i;
		struct wim_inode *inode;
		struct wim_lookup_table_entry *lte;

		image_for_each_inode(inode, imd) {
			for (i = 0; i <= inode->i_num_ads; i++) {
				lte = inode_stream_lte(inode, i,
						       wim->lookup_table);
				if (lte)
					lte->out_refcnt = 0;
			}
		}

		image_for_each_inode(inode, imd) {
			for (i = 0; i <= inode->i_num_ads; i++) {
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
	}

	/* Assign new inode numbers.  */
	reassign_inode_numbers(&ctx);

	/* If a read-write mount, mark the image as modified.  */
	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE)
		imd->modified = 1;

	/* Build the FUSE command line.  */

	fuse_argc = 0;
	fuse_argv[fuse_argc++] = "wimlib";
	fuse_argv[fuse_argc++] = (char *)dir;

	/* Disable multi-threaded operation.  */
	fuse_argv[fuse_argc++] = "-s";

	/* Enable FUSE debug mode (don't fork) if requested by the user.  */
	if (mount_flags & WIMLIB_MOUNT_FLAG_DEBUG)
		fuse_argv[fuse_argc++] = "-d";

	/*
	 * Build the FUSE mount options:
	 *
	 * use_ino
	 *	FUSE will use the inode numbers we provide.  We want this,
	 *	because we have inodes and will number them ourselves.
	 *
	 * subtype=wimfs
	 *	Name for our filesystem (main type is "fuse").
	 *
	 * hard_remove
	 *	If an open file is unlinked, unlink it for real rather than
	 *	renaming it to a hidden file.  Our code supports this; an
	 *	unlinked inode is retained until all its file descriptors have
	 *	been closed.
	 *
	 * default_permissions
	 *	FUSE will perform permission checking.  Useful when
	 *	WIMLIB_MOUNT_FLAG_UNIX_DATA is provided and the WIM image
	 *	contains the UNIX permissions for each file.
	 *
	 * kernel_cache
	 *	Cache the contents of files.  This will speed up repeated access
	 *	to files on a mounted WIM image, since they won't need to be
	 *	decompressed repeatedly.  This option is valid because data in
	 *	the WIM image should never be changed externally.  (Although, if
	 *	someone really wanted to they could modify the WIM file or mess
	 *	with the staging directory; but then they're asking for
	 *	trouble.)
	 *
	 * entry_timeout=1000000000
	 *	Cache positive name lookups indefinitely, since names can only
	 *	be added, removed, or modified through the mounted filesystem
	 *	itself.
	 *
	 * negative_timeout=1000000000
	 *	Cache negative name lookups indefinitely, since names can only
	 *	be added, removed, or modified through the mounted filesystem
	 *	itself.
	 *
	 * attr_timeout=0
	 *	Don't cache file/directory attributes.  This is needed as a
	 *	workaround for the fact that when caching attributes, the high
	 *	level interface to libfuse considers a file which has several
	 *	hard-linked names as several different files.  (Otherwise, we
	 *	could cache our file/directory attributes indefinitely, since
	 *	they can only be changed through the mounted filesystem itself.)
	 */
	char optstring[256] =
		"use_ino"
		",subtype=wimfs"
		",attr_timeout=0"
		",hard_remove"
		",default_permissions"
		",kernel_cache"
		",entry_timeout=1000000000"
		",negative_timeout=1000000000"
		",attr_timeout=0"
		;
	fuse_argv[fuse_argc++] = "-o";
	fuse_argv[fuse_argc++] = optstring;
	if (!(mount_flags & WIMLIB_MOUNT_FLAG_READWRITE))
		strcat(optstring, ",ro");
	if (mount_flags & WIMLIB_MOUNT_FLAG_ALLOW_OTHER)
		strcat(optstring, ",allow_other");
	fuse_argv[fuse_argc] = NULL;

	/* Mount our filesystem.  */
	ret = fuse_main(fuse_argc, fuse_argv, &wimfs_operations, &ctx);

	/* Cleanup and return.  */
	if (ret)
		ret = WIMLIB_ERR_FUSE;
	release_extra_refcnts(&ctx);
	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE)
		delete_staging_dir(&ctx);
out_unlock:
	unlock_wim_for_append(wim, wim->in_fd.fd);
	return ret;
}

struct commit_progress_thread_args {
	mqd_t mq;
	wimlib_progress_func_t progfunc;
	void *progctx;
	int status;
};

static void *
commit_progress_thread_proc(void *_args)
{
	struct commit_progress_thread_args *args = _args;
	struct commit_progress_report report;
	ssize_t ret;

	args->status = WIMLIB_ERR_NOT_A_MOUNTPOINT;
	for (;;) {
		ret = mq_receive(args->mq,
				 (char *)&report, sizeof(report), NULL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (ret == sizeof(int)) {
			args->status = *(int *)&report;
			break;
		}
		if (ret < sizeof(report))
			continue;
		call_progress(args->progfunc, report.msg,
			      &report.info, args->progctx);
	}
	return NULL;
}

static void
generate_message_queue_name(char name[WIMFS_MQUEUE_NAME_LEN + 1])
{
	name[0] = '/';
	memcpy(name + 1, "wimfs-", 6);
	randomize_char_array_with_alnum(name + 7, WIMFS_MQUEUE_NAME_LEN - 7);
	name[WIMFS_MQUEUE_NAME_LEN] = '\0';
}

static mqd_t
create_message_queue(const char *name, bool have_progfunc)
{
	bool am_root = (getuid() == 0);
	mode_t umask_save = 0;
	mode_t mode = 0600;
	struct mq_attr attr;
	mqd_t mq;

	memset(&attr, 0, sizeof(attr));
	attr.mq_maxmsg = 8;
	if (have_progfunc)
		attr.mq_msgsize = sizeof(struct commit_progress_report);
	else
		attr.mq_msgsize = sizeof(int);

	if (am_root) {
		/* Filesystem mounted as normal user with --allow-other should
		 * be able to send messages to root user, if they're doing the
		 * unmount.  */
		umask_save = umask(0);
		mode = 0666;
	}
	mq = mq_open(name, O_RDWR | O_CREAT | O_EXCL, mode, &attr);
	if (am_root)
		umask(umask_save);
	return mq;
}

/* Unmount a read-write mounted WIM image, committing the changes.  */
static int
do_unmount_commit(const char *dir, int unmount_flags,
		  wimlib_progress_func_t progfunc, void *progctx)
{
	struct wimfs_unmount_info unmount_info;
	mqd_t mq;
	struct commit_progress_thread_args args;
	pthread_t commit_progress_tid;
	int ret;

	memset(&unmount_info, 0, sizeof(unmount_info));
	unmount_info.unmount_flags = unmount_flags;
	generate_message_queue_name(unmount_info.mq_name);

	mq = create_message_queue(unmount_info.mq_name, progfunc != NULL);
	if (mq == (mqd_t)-1) {
		ERROR_WITH_ERRNO("Can't create POSIX message queue");
		return WIMLIB_ERR_MQUEUE;
	}

	/* The current thread will be stuck in setxattr() until the image is
	 * committed.  Create a thread to handle the progress messages.  */
	if (progfunc) {
		args.mq = mq;
		args.progfunc = progfunc;
		args.progctx = progctx;
		ret = pthread_create(&commit_progress_tid, NULL,
				     commit_progress_thread_proc, &args);
		if (ret) {
			errno = ret;
			ERROR_WITH_ERRNO("Can't create thread");
			ret = WIMLIB_ERR_NOMEM;
			goto out_delete_mq;
		}
		unmount_info.unmount_flags |= WIMLIB_UNMOUNT_FLAG_SEND_PROGRESS;
	}

	if (!setxattr(dir, "wimfs.unmount",
		     (const char *)&unmount_info, sizeof(unmount_info), 0))
		ret = 0;
	else if (errno == EACCES || errno == EPERM)
		ret = WIMLIB_ERR_NOT_PERMITTED_TO_UNMOUNT;
	else
		ret = WIMLIB_ERR_NOT_A_MOUNTPOINT;

	if (progfunc) {
		/* Terminate the progress thread and retrieve final unmount
		 * status.  */

		int tmp = -1;
		mq_send(mq, (const char *)&tmp, sizeof(int), 1);

		pthread_join(commit_progress_tid, NULL);
		if (!ret && args.status != -1)
			ret = args.status;
	} else if (!ret) {
		/* Retrieve the final unmount status.  */

		int tmp = -1;
		int len;

		mq_send(mq, (const char *)&tmp, sizeof(int), 1);
		len = mq_receive(mq, (char *)&tmp, sizeof(int), NULL);

		if (len == 4 && tmp != -1)
			ret = tmp;
		else
			ret = WIMLIB_ERR_NOT_A_MOUNTPOINT;
	}
out_delete_mq:
	mq_close(mq);
	mq_unlink(unmount_info.mq_name);
	return ret;
}

/* Unmount a read-only or read-write mounted WIM image, discarding any changes.
 */
static int
do_unmount_discard(const char *dir)
{
	if (!getxattr(dir, "wimfs.unmount", NULL, 0))
		return 0;
	else if (errno == EACCES || errno == EPERM)
		return WIMLIB_ERR_NOT_PERMITTED_TO_UNMOUNT;
	else
		return WIMLIB_ERR_NOT_A_MOUNTPOINT;
}

static int
begin_unmount(const char *dir, int unmount_flags, int *mount_flags_ret,
	      wimlib_progress_func_t progfunc, void *progctx)
{
	int mount_flags;
	int mounted_image;
	int wim_filename_len;
	union wimlib_progress_info progress;

	if (getxattr(dir, "wimfs.mount_flags",
		     &mount_flags, sizeof(int)) != sizeof(int))
		return WIMLIB_ERR_NOT_A_MOUNTPOINT;

	*mount_flags_ret = mount_flags;

	if (!progfunc)
		return 0;

	if (getxattr(dir, "wimfs.mounted_image",
		     &mounted_image, sizeof(int)) != sizeof(int))
		return WIMLIB_ERR_NOT_A_MOUNTPOINT;

	wim_filename_len = getxattr(dir, "wimfs.wim_filename", NULL, 0);
	if (wim_filename_len < 0)
		return WIMLIB_ERR_NOT_A_MOUNTPOINT;

	char wim_filename[wim_filename_len + 1];
	if (getxattr(dir, "wimfs.wim_filename",
		     wim_filename, wim_filename_len) != wim_filename_len)
		return WIMLIB_ERR_NOT_A_MOUNTPOINT;
	wim_filename[wim_filename_len] = '\0';

	progress.unmount.mountpoint = dir;
	progress.unmount.mounted_wim = wim_filename;
	progress.unmount.mounted_image = mounted_image;
	progress.unmount.mount_flags = mount_flags;
	progress.unmount.unmount_flags = unmount_flags;

	return call_progress(progfunc, WIMLIB_PROGRESS_MSG_UNMOUNT_BEGIN,
			     &progress, progctx);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_unmount_image_with_progress(const char *dir, int unmount_flags,
				   wimlib_progress_func_t progfunc, void *progctx)
{
	int mount_flags;
	int ret;

	wimlib_global_init(WIMLIB_INIT_FLAG_ASSUME_UTF8);

	if (unmount_flags & ~(WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY |
			      WIMLIB_UNMOUNT_FLAG_COMMIT |
			      WIMLIB_UNMOUNT_FLAG_REBUILD |
			      WIMLIB_UNMOUNT_FLAG_RECOMPRESS |
			      WIMLIB_UNMOUNT_FLAG_FORCE |
			      WIMLIB_UNMOUNT_FLAG_NEW_IMAGE))
		return WIMLIB_ERR_INVALID_PARAM;

	ret = begin_unmount(dir, unmount_flags, &mount_flags,
			    progfunc, progctx);
	if (ret)
		return ret;

	if ((unmount_flags & WIMLIB_UNMOUNT_FLAG_COMMIT) &&
	    (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE))
		return do_unmount_commit(dir, unmount_flags,
					 progfunc, progctx);
	else
		return do_unmount_discard(dir);
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
wimlib_unmount_image_with_progress(const tchar *dir, int unmount_flags,
				   wimlib_progress_func_t progfunc, void *progctx)
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

WIMLIBAPI int
wimlib_unmount_image(const tchar *dir, int unmount_flags)
{
	return wimlib_unmount_image_with_progress(dir, unmount_flags, NULL, NULL);
}
