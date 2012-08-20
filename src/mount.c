/*
 * mount.c
 *
 * This file implements mounting of WIM files using FUSE, which stands for
 * Filesystem in Userspace.  FUSE allows a filesystem to be implemented in a
 * userspace process by implementing the filesystem primitives--- read(),
 * write(), readdir(), etc.
 */

/*
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "wimlib_internal.h"

#ifdef WITH_FUSE
#include "sha1.h"
#include "lookup_table.h"
#include "xml.h"
#include "io.h"
#include "timestamp.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#define FUSE_USE_VERSION 26
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <fuse.h>
#include <ftw.h>
#include <mqueue.h>

struct wimlib_fd {
	u16 idx;
	int staging_fd;
	u64 hard_link_group;
	struct lookup_table_entry *lte;
	struct dentry *dentry;
};

/* The WIMStruct for the mounted WIM. */
static WIMStruct *w;

/* Working directory when `imagex mount' is run. */
static const char *working_directory;

/* Name of the staging directory for a read-write mount.  Whenever a new file is
 * created, it is done so in the staging directory.  Furthermore, whenever a
 * file in the WIM is modified, it is extracted to the staging directory.  If
 * changes are commited when the WIM is unmounted, the file resources are merged
 * in from the staging directory when writing the new WIM. */
static char *staging_dir_name;
static size_t staging_dir_name_len;

/* Flags passed to wimlib_mount(). */
static int mount_flags;

/* Name of the directory on which the WIM file is mounted. */
static const char *mount_dir;

/* Next hard link group ID to be assigned.  These are also used as the inode
 * numbers. */
static u64 next_link_group_id;

/* List of lookup table entries in the staging directory */
static LIST_HEAD(staging_list);

static inline int get_lookup_flags()
{
	if (mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS)
		return LOOKUP_FLAG_ADS_OK;
	else
		return 0;
}

/* Returns nonzero if write permission is requested on the file open flags */
static inline int flags_writable(int open_flags)
{
	return open_flags & (O_RDWR | O_WRONLY);
}

/* 
 * Allocate a file descriptor for a lookup table entry
 */
static int alloc_wimlib_fd(struct lookup_table_entry *lte,
			   struct wimlib_fd **fd_ret)
{
	static const u16 fds_per_alloc = 8;
	static const u16 max_fds = 0xffff;

	if (lte->num_opened_fds == lte->num_allocated_fds) {
		struct wimlib_fd **fds;
		u16 num_new_fds;

		if (lte->num_allocated_fds == max_fds)
			return -EMFILE;
		num_new_fds = min(fds_per_alloc, max_fds - lte->num_allocated_fds);
		
		fds = REALLOC(lte->fds, (lte->num_allocated_fds + num_new_fds) *
			       sizeof(lte->fds[0]));
		if (!fds)
			return -ENOMEM;
		memset(&fds[lte->num_allocated_fds], 0,
		       num_new_fds * sizeof(fds[0]));
		lte->fds = fds;
		lte->num_allocated_fds += num_new_fds;
	}
	for (u16 i = 0; ; i++) {
		if (!lte->fds[i]) {
			struct wimlib_fd *fd = CALLOC(1, sizeof(*fd));
			if (!fd)
				return -ENOMEM;
			fd->staging_fd = -1;
			fd->idx        = i;
			fd->lte        = lte;
			lte->fds[i]    = fd;
			lte->num_opened_fds++;
			*fd_ret        = fd;
			return 0;
		}
	}
}

static int close_wimlib_fd(struct wimlib_fd *fd)
{
	struct lookup_table_entry *lte = fd->lte;

	wimlib_assert(lte);
	wimlib_assert(lte->num_opened_fds);

	if (lte->staging_file_name) {
		wimlib_assert(fd->staging_fd != -1);
		if (close(fd->staging_fd) != 0)
			return -errno;
	}
	if (--lte->num_opened_fds == 0 && lte->refcnt == 0) {
		if (lte->staging_file_name)
			unlink(lte->staging_file_name);
		free_lookup_table_entry(lte);
	}
	wimlib_assert(lte->fds[fd->idx] == fd);
	lte->fds[fd->idx] = NULL;
	FREE(fd);
	return 0;
}

/* Remove a dentry and all its alternate file streams */
static void remove_dentry(struct dentry *dentry,
			  struct lookup_table *lookup_table)
{
	wimlib_assert(dentry);
	wimlib_assert(dentry->resolved);

	struct lookup_table_entry *lte = dentry->lte;
	u16 i = 0;
	while (1) {
		lte = lte_decrement_refcnt(lte, lookup_table);
		if (lte && lte->num_opened_fds)
			for (u16 i = 0; i < lte->num_allocated_fds; i++)
				if (lte->fds[i] && lte->fds[i]->dentry == dentry)
					lte->fds[i]->dentry = NULL;
		if (i == dentry->num_ads)
			break;
		lte = dentry->ads_entries[i].lte;
		i++;
	}

	unlink_dentry(dentry);
	put_dentry(dentry);
}

/* Transfers file attributes from a struct dentry to a `stat' buffer. */
int dentry_to_stbuf(const struct dentry *dentry, struct stat *stbuf)
{
	struct lookup_table_entry *lte;

	if (dentry_is_symlink(dentry))
		stbuf->st_mode = S_IFLNK | 0777;
	else if (dentry_is_directory(dentry))
		stbuf->st_mode = S_IFDIR | 0755;
	else
		stbuf->st_mode = S_IFREG | 0644;

	stbuf->st_ino = (ino_t)dentry->hard_link;

	stbuf->st_nlink = dentry_link_group_size(dentry);
	stbuf->st_uid   = getuid();
	stbuf->st_gid   = getgid();

	/* Use the size of the unnamed (default) file stream. */
	lte = dentry_first_lte_resolved(dentry);
	if (lte) {
		if (lte->staging_file_name) {
			struct stat native_stat;
			if (stat(lte->staging_file_name, &native_stat) != 0) {
				DEBUG("Failed to stat `%s': %m",
				      lte->staging_file_name);
				return -errno;
			}
			stbuf->st_size = native_stat.st_size;
		} else {
			stbuf->st_size = lte->resource_entry.original_size;
		}
	} else {
		stbuf->st_size = 0;
	}

	stbuf->st_atime   = wim_timestamp_to_unix(dentry->last_access_time);
	stbuf->st_mtime   = wim_timestamp_to_unix(dentry->last_write_time);
	stbuf->st_ctime   = wim_timestamp_to_unix(dentry->creation_time);
	stbuf->st_blocks  = (stbuf->st_size + 511) / 512;
	return 0;
}

/* Creates a new staging file and returns its file descriptor opened for
 * writing.
 *
 * @name_ret: A location into which the a pointer to the newly allocated name of
 * 			the staging file is stored.
 * @return:  The file descriptor for the new file.  Returns -1 and sets errno on
 * 		error, for any reason possible from the creat() function.
 */
static int create_staging_file(char **name_ret, int open_flags)
{
	size_t name_len;
	char *name;
	struct stat stbuf;
	int fd;
	int errno_save;

	name_len = staging_dir_name_len + 1 + SHA1_HASH_SIZE;
 	name = MALLOC(name_len + 1);
	if (!name) {
		errno = ENOMEM;
		return -1;
	}

	do {

		memcpy(name, staging_dir_name, staging_dir_name_len);
		name[staging_dir_name_len] = '/';
		randomize_char_array_with_alnum(name + staging_dir_name_len + 1,
						SHA1_HASH_SIZE);
		name[name_len] = '\0';


	/* Just in case, verify that the randomly generated name doesn't name an
	 * existing file, and try again if so  */
	} while (stat(name, &stbuf) == 0);

	if (errno != ENOENT)
		/* other error! */
		return -1;

	/* doesn't exist--- ok */

	DEBUG("Creating staging file `%s'", name);

	fd = open(name, open_flags | O_CREAT | O_TRUNC, 0600); 
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
 * Removes open file descriptors from a lookup table entry @old_lte where the
 * file descriptors have opened the corresponding file resource in the context
 * of the hard link group @link_group; these file descriptors are extracted and
 * placed in a new lookup table entry, which is returned.
 */
static struct lookup_table_entry *
lte_extract_fds(struct lookup_table_entry *old_lte, u64 link_group)
{
	int ret;
	u16 num_transferred_fds;
	struct lookup_table_entry *new_lte;

	new_lte = new_lookup_table_entry();
	if (!new_lte)
		return NULL;

	num_transferred_fds = 0;
	for (u16 i = 0; i < old_lte->num_allocated_fds; i++)
		if (old_lte->fds[i] && old_lte->fds[i]->dentry &&
		    old_lte->fds[i]->dentry->hard_link == link_group)
			num_transferred_fds++;
	DEBUG("Transferring %u file descriptors",
	      num_transferred_fds);
	new_lte->fds = MALLOC(num_transferred_fds * sizeof(new_lte->fds[0]));
	if (!new_lte->fds) {
		FREE(new_lte);
		return NULL;
	}
	for (u16 i = 0, j = 0; ; i++) {
		if (old_lte->fds[i] && old_lte->fds[i]->dentry &&
		    old_lte->fds[i]->dentry->hard_link == link_group) {
			struct wimlib_fd *fd = old_lte->fds[i];
			old_lte->fds[i] = NULL;
			fd->lte = new_lte;
			fd->idx = j;
			new_lte->fds[j] = fd;
			if (++j == num_transferred_fds)
				break;
		}
	}
	DEBUG("old_lte: %u fds open; new_lte: %u fds open",
	      old_lte->num_opened_fds, new_lte->num_opened_fds);
	old_lte->num_opened_fds -= num_transferred_fds;
	new_lte->num_opened_fds = num_transferred_fds;
	new_lte->num_allocated_fds = num_transferred_fds;
	return new_lte;
}

/* 
 * Transfers an alternate data stream entry to a new lookup table entry
 */
static void lte_transfer_ads_entry(struct lookup_table_entry *new_lte,
				   struct ads_entry *ads_entry)
{
	list_del(&ads_entry->lte_group_list.list);
	list_add(&ads_entry->lte_group_list.list, &new_lte->lte_group_list);
	ads_entry->lte = new_lte;
}

/* 
 * Transfers a dentry to a new lookup table entry
 */
static void lte_transfer_dentry(struct lookup_table_entry *new_lte,
				struct dentry *dentry)
{
	wimlib_assert(dentry->lte_group_list.list.next);
	wimlib_assert(new_lte->lte_group_list.next);
	list_del(&dentry->lte_group_list.list);
	list_add(&dentry->lte_group_list.list, &new_lte->lte_group_list);
	dentry->lte = new_lte;
}

static void lte_transfer_stream_entries(struct lookup_table_entry *new_lte,
				        struct dentry *dentry,
					unsigned stream_idx)
{
	INIT_LIST_HEAD(&new_lte->lte_group_list);
	if (stream_idx == 0) {
		struct list_head *pos = &dentry->link_group_list;
		do {
			struct dentry *d;
			d = container_of(pos, struct dentry, link_group_list);
			wimlib_assert(d->hard_link == dentry->hard_link);
			lte_transfer_dentry(new_lte, d);
			pos = pos->next;
		} while (pos != &dentry->link_group_list);
	} else {
		struct ads_entry *ads_entry;
		wimlib_assert(stream_idx <= dentry->num_ads);
		ads_entry = &dentry->ads_entries[stream_idx - 1];
		lte_transfer_ads_entry(new_lte, ads_entry);
	}
}

/* 
 * Extract a WIM resource to the staging directory.
 *
 * @dentry, @stream_idx:  The stream on whose behalf we are modifying the lookup
 * table entry (these may be more streams than this that reference the lookup
 * table entry)
 *
 * @lte: Pointer to pointer to the lookup table entry for the stream we need to
 * extract, or NULL if there was no lookup table entry present for the stream
 *
 * @size:  Number of bytes of the stream we want to extract (this supports the
 * wimfs_truncate() function).
 */
static int extract_resource_to_staging_dir(struct dentry *dentry,
					   unsigned stream_idx,
					   struct lookup_table_entry **lte,
					   off_t size)
{
	char *staging_file_name;
	int ret;
	int fd;
	struct lookup_table_entry *old_lte, *new_lte;
	size_t link_group_size;

	/*
	 * We need to:
	 * - Create a staging file for the WIM resource
	 * - Extract the resource to it
	 * - Create a new lte for the file resource
	 * - Transfer fds from the old lte to the new lte, but only if they share the
	 *   same hard link group as this dentry.  If there is no old lte, then this
	 *   step does not need to be done
	 * - Transfer stream entries from the old lte's list to the new lte's list.  If
	 *   there is no old lte, we instead transfer entries for the hard link group.
	 *
	 *   Note: *lte is permitted to be NULL, in which case there is no old
	 *   lookup table entry.
	 */

	DEBUG("Extracting resource `%s' to staging directory", dentry->full_path_utf8);

	old_lte = *lte;
	fd = create_staging_file(&staging_file_name, O_WRONLY);
	if (fd == -1)
		return -errno;

	if (old_lte)
		ret = extract_resource_to_fd(w, &old_lte->resource_entry, fd,
					     size);
	else
		ret = 0;
	if (ret != 0 || close(fd) != 0) {
		if (errno != 0)
			ret = -errno;
		else
			ret = -EIO;
		close(fd);
		goto out_delete_staging_file;
	}

	link_group_size = dentry_link_group_size(dentry);

	if (old_lte) {
		if (link_group_size == old_lte->refcnt) {
			/* This hard link group is the only user of the lookup
			 * table entry, so we can re-use it. */
			DEBUG("Re-using lookup table entry");
			lookup_table_unlink(w->lookup_table, old_lte);
			new_lte = old_lte;
		} else {
			DEBUG("Splitting lookup table entry "
			      "(link_group_size = %u, lte refcnt = %u)",
			      link_group_size, old_lte->refcnt);
			/* Split a hard link group away from the "lookup table
			 * entry" hard link group (i.e. we had two hard link
			 * groups that were identical, but now we are changing
			 * one of them) */

			/* XXX 
			 * The ADS really complicate things here and not
			 * everything is going to work correctly yet.  For
			 * example it could be the same that a file contains two
			 * file streams that are identical and therefore share
			 * the same lookup table entry despite the fact that the
			 * streams themselves are not hardlinked. 
			 * XXX*/
			wimlib_assert(old_lte->refcnt > link_group_size);

			new_lte = lte_extract_fds(old_lte, dentry->hard_link);
			if (!new_lte) {
				ret = -ENOMEM;
				goto out_delete_staging_file;
			}

			lte_transfer_stream_entries(new_lte, dentry, stream_idx);
			old_lte->refcnt -= link_group_size;
		} 
	} else {
		/* No old_lte was supplied, so the resource had no lookup table
		 * entry before (it must be an empty resource) */
		new_lte = new_lookup_table_entry();
		if (!new_lte) {
			ret = -ENOMEM;
			goto out_delete_staging_file;
		}
		lte_transfer_stream_entries(new_lte, dentry, stream_idx);
	}
	new_lte->resource_entry.original_size = size;
	new_lte->refcnt = link_group_size;
	random_hash(new_lte->hash);
	new_lte->staging_file_name = staging_file_name;

	lookup_table_insert(w->lookup_table, new_lte);
	list_add(&new_lte->staging_list, &staging_list);
	*lte = new_lte;
	return 0;
out_delete_staging_file:
	unlink(staging_file_name);
	FREE(staging_file_name);
	return ret;
}

/* 
 * Creates a randomly named staging directory and returns its name into the
 * static variable staging_dir_name.
 *
 * If the staging directory cannot be created, staging_dir_name is set to NULL.
 * */
static void make_staging_dir()
{
	/* XXX Give the user an option of where to stage files */

	static char prefix[] = "wimlib-staging-";
	static const size_t prefix_len = 15;
	static const size_t suffix_len = 10;

	size_t pwd_len = strlen(working_directory);

	staging_dir_name_len = pwd_len + 1 + prefix_len + suffix_len;

	staging_dir_name = MALLOC(staging_dir_name_len + 1);
	if (!staging_dir_name) {
		ERROR("Out of memory");
		return;
	}

	memcpy(staging_dir_name, working_directory, pwd_len);
	staging_dir_name[pwd_len] = '/';
	memcpy(staging_dir_name + pwd_len + 1, prefix, prefix_len);
	randomize_char_array_with_alnum(staging_dir_name + pwd_len + 1 + prefix_len,
				suffix_len);
	staging_dir_name[staging_dir_name_len] = '\0';

	if (mkdir(staging_dir_name, 0700) != 0) {
		ERROR_WITH_ERRNO("Failed to create temporary directory `%s'",
				 staging_dir_name);
		FREE(staging_dir_name);
		staging_dir_name = NULL;
	}
}

static int remove_file_or_directory(const char *fpath, const struct stat *sb,
		int typeflag, struct FTW *ftwbuf)
{
	if (remove(fpath) == 0)
		return 0;
	else
		return WIMLIB_ERR_DELETE_STAGING_DIR;
}


/* 
 * Deletes the staging directory and all the files contained in it. 
 */
static inline int delete_staging_dir()
{
	int ret;
	
	ret = nftw(staging_dir_name, remove_file_or_directory,10, FTW_DEPTH);
	staging_dir_name = NULL;
	return ret;
}

/* Name and message queue descriptors for message queues between the filesystem
 * daemon process and the unmount process.  These are used when the filesystem
 * is unmounted and the process running wimlib_mount() (i.e. the `imagex
 * unmount' command) needs to communicate with the filesystem daemon running
 * fuse_main() (i.e. that spawned by the `imagex mount' or `imagex mountrw'
 * commands */
static char *unmount_to_daemon_mq_name;
static char *daemon_to_unmount_mq_name;
static int unmount_to_daemon_mq;
static int daemon_to_unmount_mq;

/* Simple function that returns the concatenation of 4 strings. */
static char *strcat_dup(const char *s1, const char *s2, const char *s3, 
							const char *s4)
{
	size_t len = strlen(s1) + strlen(s2) + strlen(s3) + strlen(s4) + 1;
	char *p = MALLOC(len);
	if (!p)
		return NULL;
	*p = '\0';
	strcat(p, s1);
	strcat(p, s2);
	strcat(p, s3);
	strcat(p, s4);
	return p;
}

/* Removes trailing forward slashes in a string. */
static void remove_trailing_slashes(char *s)
{
	long len = strlen(s);
	for (long i = len - 1; i >= 1; i--) {
		if (s[i] == '/')
			s[i] = '\0';
		else
			break;
	}
}

/* Changes forward slashes to underscores in a string. */
static void s_slashes_underscores_g(char *s)
{
	while (*s) {
		if (*s == '/')
			*s = '_';
		s++;
	}
}

/* 
 * Opens two POSIX message queue: one for sending messages from the unmount
 * process to the daemon process, and one to go the other way.  The names of the
 * message queues, which must be system-wide unique, are be based on the mount
 * point.  (There of course is still a possibility of a collision if one were to
 * unmount two identically named directories simultaneously...)
 *
 * @daemon specifies whether the calling process is the filesystem daemon or the
 * unmount process.
 */
static int open_message_queues(bool daemon)
{
	static const char *slash = "/";
	static const char *prefix = "wimlib-";
	static const char *u2d_suffix = "unmount-to-daemon-mq";
	static const char *d2u_suffix = "daemon-to-unmount-mq";

	const char *mount_dir_basename = path_basename(mount_dir);
	int flags;
	int ret;

	unmount_to_daemon_mq_name = strcat_dup(slash, mount_dir_basename,
						prefix, u2d_suffix);
	if (!unmount_to_daemon_mq_name) {
		ERROR("Out of memory");
		return WIMLIB_ERR_NOMEM;
	}
	daemon_to_unmount_mq_name = strcat_dup(slash, mount_dir_basename,
						prefix, d2u_suffix);
	if (!daemon_to_unmount_mq_name) {
		ERROR("Out of memory");
		ret = WIMLIB_ERR_NOMEM;
		goto err1;
	}

	remove_trailing_slashes(unmount_to_daemon_mq_name);
	remove_trailing_slashes(daemon_to_unmount_mq_name);
	s_slashes_underscores_g(unmount_to_daemon_mq_name + 1);
	s_slashes_underscores_g(daemon_to_unmount_mq_name + 1);

	if (daemon)
		flags = O_RDONLY | O_CREAT;
	else
		flags = O_WRONLY | O_CREAT;

	unmount_to_daemon_mq = mq_open(unmount_to_daemon_mq_name, flags, 
				       0700, NULL);

	if (unmount_to_daemon_mq == -1) {
		ERROR_WITH_ERRNO("mq_open()");
		ret = WIMLIB_ERR_MQUEUE;
		goto err2;
	}

	if (daemon)
		flags = O_WRONLY | O_CREAT;
	else
		flags = O_RDONLY | O_CREAT;

	daemon_to_unmount_mq = mq_open(daemon_to_unmount_mq_name, flags, 
				       0700, NULL);

	if (daemon_to_unmount_mq == -1) {
		ERROR_WITH_ERRNO("mq_open()");
		ret = WIMLIB_ERR_MQUEUE;
		goto err3;
	}
	return 0;
err3:
	mq_close(unmount_to_daemon_mq);
	mq_unlink(unmount_to_daemon_mq_name);
err2:
	FREE(daemon_to_unmount_mq_name);
err1:
	FREE(unmount_to_daemon_mq_name);
	return ret;
}

static int mq_get_msgsize(mqd_t mq)
{
	static const char *msgsize_max_file = "/proc/sys/fs/mqueue/msgsize_max";
	FILE *fp;
	struct mq_attr attr;
	int msgsize;

	if (mq_getattr(unmount_to_daemon_mq, &attr) == 0) {
		msgsize = attr.mq_msgsize;
	} else {
		ERROR_WITH_ERRNO("mq_getattr()");
		ERROR("Attempting to read %s", msgsize_max_file);
		fp = fopen(msgsize_max_file, "rb");
		if (fp) {
			if (fscanf(fp, "%d", &msgsize) != 1) {
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

/* Closes the message queues, which are allocated in static variables */
static void close_message_queues()
{
	mq_close(unmount_to_daemon_mq);
	mq_close(daemon_to_unmount_mq);
	mq_unlink(unmount_to_daemon_mq_name);
	mq_unlink(daemon_to_unmount_mq_name);
}

static int wimfs_access(const char *path, int mask)
{
	/* XXX Permissions not implemented */
	return 0;
}

/* Closes the staging file descriptor associated with the lookup table entry, if
 * it is opened. */
static int close_lte_fds(struct lookup_table_entry *lte)
{
	for (u16 i = 0, j = 0; j < lte->num_opened_fds; i++) {
		if (lte->fds[i] && lte->fds[i]->staging_fd != -1) {
			if (close(lte->fds[i]->staging_fd) != 0) {
				ERROR_WITH_ERRNO("Failed close file `%s'",
						 lte->staging_file_name);
				return WIMLIB_ERR_WRITE;
			}
			j++;
		}
	}
	return 0;
}

static void lte_list_change_lte_ptr(struct lookup_table_entry *lte,
				    struct lookup_table_entry *newptr)
{
	struct list_head *pos;
	struct stream_list_head *head;
	list_for_each(pos, &lte->lte_group_list) {
		head = container_of(pos, struct stream_list_head, list);
		if (head->type == STREAM_TYPE_ADS) {
			struct ads_entry *ads_entry;
			ads_entry = container_of(head, struct ads_entry, lte_group_list);

			ads_entry->lte = newptr;
		} else {
			wimlib_assert(head->type == STREAM_TYPE_NORMAL);

			struct dentry *dentry;
			dentry = container_of(head, struct dentry, lte_group_list);

			dentry->lte = newptr;
		}
	}
}


static int calculate_sha1sum_of_staging_file(struct lookup_table_entry *lte,
					     struct lookup_table *table)
{
	struct lookup_table_entry *duplicate_lte;
	int ret;
	u8 hash[SHA1_HASH_SIZE];

	ret = sha1sum(lte->staging_file_name, hash);
	if (ret != 0)
		return ret;

	lookup_table_unlink(table, lte);
	copy_hash(lte->hash, hash);

	duplicate_lte = __lookup_resource(table, hash);

	if (duplicate_lte) {
		/* Merge duplicate lookup table entries */

		lte_list_change_lte_ptr(lte, duplicate_lte);
		duplicate_lte->refcnt += lte->refcnt;
		list_splice(&duplicate_lte->lte_group_list,
			    &lte->lte_group_list);

		free_lookup_table_entry(lte);
	} else {
		lookup_table_insert(table, lte);
	}

	return 0;
}

/* Overwrites the WIM file, with changes saved. */
static int rebuild_wim(WIMStruct *w, bool check_integrity)
{
	int ret;
	struct lookup_table_entry *lte, *tmp;

	/* Close all the staging file descriptors. */
	DEBUG("Closing all staging file descriptors.");
	list_for_each_entry(lte, &staging_list, staging_list) {
		ret = close_lte_fds(lte);
		if (ret != 0)
			return ret;
	}

	/* Calculate SHA1 checksums for all staging files, and merge unnecessary
	 * lookup table entries. */
	DEBUG("Calculating SHA1 checksums for all new staging files.");
	list_for_each_entry_safe(lte, tmp, &staging_list, staging_list) {
		ret = calculate_sha1sum_of_staging_file(lte, w->lookup_table);
		if (ret != 0)
			return ret;
	}
	if (ret != 0)
		return ret;

	xml_update_image_info(w, w->current_image);

	ret = wimlib_overwrite(w, check_integrity);
	if (ret != 0) {
		ERROR("Failed to commit changes");
		return ret;
	}
	return ret;
}

/* Called when the filesystem is unmounted. */
static void wimfs_destroy(void *p)
{
	/* For read-write mounts, the `imagex unmount' command, which is
	 * running in a separate process and is executing the
	 * wimlib_unmount() function, will send this process a byte
	 * through a message queue that indicates whether the --commit
	 * option was specified or not. */

	int msgsize;
	struct timespec timeout;
	struct timeval now;
	ssize_t bytes_received;
	int ret;
	char commit;
	char check_integrity;
	char status;

	ret = open_message_queues(true);
	if (ret != 0)
		exit(1);

	msgsize = mq_get_msgsize(unmount_to_daemon_mq);
	char msg[msgsize];
	msg[0] = 0;
	msg[1] = 0;

	/* Wait at most 3 seconds before giving up and discarding changes. */
	gettimeofday(&now, NULL);
	timeout.tv_sec = now.tv_sec + 3;
	timeout.tv_nsec = now.tv_usec * 1000;
	DEBUG("Waiting for message telling us whether to commit or not, and "
	      "whether to include integrity checks.");

	bytes_received = mq_timedreceive(unmount_to_daemon_mq, msg, 
					 msgsize, NULL, &timeout);
	commit = msg[0];
	check_integrity = msg[1];
	if (bytes_received == -1) {
		if (errno == ETIMEDOUT) {
			ERROR("Timed out.");
		} else {
			ERROR_WITH_ERRNO("mq_timedreceive()");
		}
		ERROR("Not committing.");
	} else {
		DEBUG("Received message: [%d %d]", msg[0], msg[1]);
	}

	status = 0;
	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		if (commit) {
			status = chdir(working_directory);
			if (status != 0) {
				ERROR_WITH_ERRNO("chdir()");
				status = WIMLIB_ERR_NOTDIR;
				goto done;
			}
			status = rebuild_wim(w, (check_integrity != 0));
		}
		ret = delete_staging_dir();
		if (ret != 0) {
			ERROR_WITH_ERRNO("Failed to delete the staging "
					 "directory");
			if (status == 0)
				status = ret;
		}
	} else {
		DEBUG("Read-only mount");
	}
done:
	DEBUG("Sending status %u", status);
	ret = mq_send(daemon_to_unmount_mq, &status, 1, 1);
	if (ret == -1)
		ERROR_WITH_ERRNO("Failed to send status to unmount process");
	close_message_queues();
}

static int wimfs_fallocate(const char *path, int mode,
			   off_t offset, off_t len, struct fuse_file_info *fi)
{
	struct wimlib_fd *fd = (struct wimlib_fd*)fi->fh;
	wimlib_assert(fd->staging_fd != -1);
	return fallocate(fd->staging_fd, mode, offset, len);
}

static int wimfs_fgetattr(const char *path, struct stat *stbuf,
			  struct fuse_file_info *fi)
{
	struct wimlib_fd *fd = (struct wimlib_fd*)fi->fh;
	return dentry_to_stbuf(fd->dentry, stbuf);
}

static int wimfs_ftruncate(const char *path, off_t size,
			   struct fuse_file_info *fi)
{
	struct wimlib_fd *fd = (struct wimlib_fd*)fi->fh;
	int ret = ftruncate(fd->staging_fd, size);
	if (ret != 0)
		return ret;
	fd->lte->resource_entry.original_size = size;
	return 0;
}

/*
 * Fills in a `struct stat' that corresponds to a file or directory in the WIM.
 */
static int wimfs_getattr(const char *path, struct stat *stbuf)
{
	struct dentry *dentry = get_dentry(w, path);
	if (!dentry)
		return -ENOENT;
	return dentry_to_stbuf(dentry, stbuf);
}

static int wimfs_getxattr(const char *path, const char *name, char *value,
			  size_t size)
{
	/* XXX */
	return -ENOTSUP;
}

/* Create a hard link */
static int wimfs_link(const char *to, const char *from)
{
	struct dentry *to_dentry, *from_dentry, *from_dentry_parent;
	const char *link_name;

	to_dentry = get_dentry(w, to);
	if (!to_dentry)
		return -ENOENT;
	if (!dentry_is_regular_file(to_dentry))
		return -EPERM;

	from_dentry_parent = get_parent_dentry(w, from);
	if (!from_dentry_parent)
		return -ENOENT;
	if (!dentry_is_directory(from_dentry_parent))
		return -ENOTDIR;

	link_name = path_basename(from);
	if (get_dentry_child_with_name(from_dentry_parent, link_name))
		return -EEXIST;
	from_dentry = clone_dentry(to_dentry);
	if (!from_dentry)
		return -ENOMEM;
	if (change_dentry_name(from_dentry, link_name) != 0) {
		FREE(from_dentry);
		return -ENOMEM;
	}

	/* Add the new dentry to the dentry list for the link group */
	list_add(&from_dentry->link_group_list, &to_dentry->link_group_list);

	/* Increment reference counts for the unnamed file stream and all
	 * alternate data streams. */
	if (from_dentry->lte) {
		list_add(&from_dentry->lte_group_list.list,
			 &to_dentry->lte_group_list.list);
		from_dentry->lte->refcnt++;
	}
	for (u16 i = 0; i < from_dentry->num_ads; i++) {
		struct ads_entry *ads_entry = &from_dentry->ads_entries[i];
		if (ads_entry->lte)
			ads_entry->lte->refcnt++;
	}

	/* The ADS entries are owned by another dentry. */
	from_dentry->ads_entries_status = ADS_ENTRIES_USER;

	link_dentry(from_dentry, from_dentry_parent);
	return 0;
}

static int wimfs_listxattr(const char *path, char *list, size_t size)
{
	/* XXX */
	return -ENOTSUP;
}

/* 
 * Create a directory in the WIM.  
 * @mode is currently ignored.
 */
static int wimfs_mkdir(const char *path, mode_t mode)
{
	struct dentry *parent;
	struct dentry *newdir;
	const char *basename;
	
	parent = get_parent_dentry(w, path);
	if (!parent)
		return -ENOENT;

	if (!dentry_is_directory(parent))
		return -ENOTDIR;

	basename = path_basename(path);
	if (get_dentry_child_with_name(parent, basename))
		return -EEXIST;

	newdir = new_dentry(basename);
	newdir->attributes |= FILE_ATTRIBUTE_DIRECTORY;
	newdir->resolved = true;
	newdir->hard_link = next_link_group_id++;
	link_dentry(newdir, parent);
	return 0;
}


/* Creates a regular file. */
static int wimfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	const char *stream_name;
	if ((mount_flags & WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS)
	     && (stream_name = path_stream_name(path))) {
		/* Make an alternate data stream */
		struct ads_entry *new_entry;
		struct dentry *dentry;

		dentry = get_dentry(w, path);
		if (!dentry || !dentry_is_regular_file(dentry))
			return -ENOENT;
		if (dentry_get_ads_entry(dentry, stream_name))
			return -EEXIST;
		new_entry = dentry_add_ads(dentry, stream_name);
		if (!new_entry)
			return -ENOENT;
	} else {
		struct dentry *dentry, *parent;
		const char *basename;

		/* Make a normal file (not an alternate data stream) */

		/* Make sure that the parent of @path exists and is a directory, and
		 * that the dentry named by @path does not already exist.  */
		parent = get_parent_dentry(w, path);
		if (!parent)
			return -ENOENT;
		if (!dentry_is_directory(parent))
			return -ENOTDIR;

		basename = path_basename(path);
		if (get_dentry_child_with_name(parent, path))
			return -EEXIST;

		dentry = new_dentry(basename);
		if (!dentry)
			return -ENOMEM;
		dentry->resolved = true;
		dentry->hard_link = next_link_group_id++;
		dentry->lte_group_list.type = STREAM_TYPE_NORMAL;
		INIT_LIST_HEAD(&dentry->lte_group_list.list);
		link_dentry(dentry, parent);
	}
	return 0;
}


/* Open a file.  */
static int wimfs_open(const char *path, struct fuse_file_info *fi)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	u8 *dentry_hash;
	int ret;
	struct wimlib_fd *fd;
	unsigned stream_idx;

	ret = lookup_resource(w, path, get_lookup_flags(), &dentry, &lte,
			      &stream_idx);
	if (ret != 0)
		return ret;

	if (!lte) {
		/* Empty file with no lookup-table entry.  This is fine if it's
		 * a read-only filesystem.  Otherwise we need to create a lookup
		 * table entry so that we can keep track of the file descriptors
		 * (this is important in case someone opens the file for
		 * writing) */
		if (!(mount_flags & WIMLIB_MOUNT_FLAG_READWRITE)) {
			fi->fh = 0;
			return 0;
		}

		ret = extract_resource_to_staging_dir(dentry, stream_idx,
						      &lte, 0);
		if (ret != 0)
			return ret;
	}

	ret = alloc_wimlib_fd(lte, &fd);
	if (ret != 0)
		return ret;

	fd->dentry = dentry;

	/* The file resource may be in the staging directory (read-write
	 * mounts only) or in the WIM.  If it's in the staging
	 * directory, we need to open a native file descriptor for the
	 * corresponding file.  Otherwise, we can read the file resource
	 * directly from the WIM file if we are opening it read-only,
	 * but we need to extract the resource to the staging directory
	 * if we are opening it writable. */
	if (flags_writable(fi->flags) && !lte->staging_file_name) {
		ret = extract_resource_to_staging_dir(dentry, stream_idx, &lte,
						      lte->resource_entry.original_size);
		if (ret != 0)
			return ret;
	}
	if (lte->staging_file_name) {
		fd->staging_fd = open(lte->staging_file_name, fi->flags);
		if (fd->staging_fd == -1) {
			close_wimlib_fd(fd);
			return -errno;
		}
	}
	fi->fh = (uint64_t)fd;
	return 0;
}

/* Opens a directory. */
static int wimfs_opendir(const char *path, struct fuse_file_info *fi)
{
	struct dentry *dentry;
	
	dentry = get_dentry(w, path);
	if (!dentry)
		return -ENOENT;
	if (!dentry_is_directory(dentry))
		return -ENOTDIR;
	dentry->num_times_opened++;
	fi->fh = (uint64_t)dentry;
	return 0;
}


/*
 * Read data from a file in the WIM or in the staging directory. 
 */
static int wimfs_read(const char *path, char *buf, size_t size, 
		      off_t offset, struct fuse_file_info *fi)
{
	struct wimlib_fd *fd = (struct wimlib_fd*)fi->fh;

	if (!fd) {
		/* Empty file with no lookup table entry on read-only mounted
		 * WIM */
		wimlib_assert(!(mount_flags & WIMLIB_MOUNT_FLAG_READWRITE));
		return 0;
	}

	wimlib_assert(fd->lte);

	if (fd->lte->staging_file_name) {
		/* Read from staging file */

		wimlib_assert(fd->staging_fd != -1);

		ssize_t ret;
		DEBUG("Seek to offset %zu", offset);

		if (lseek(fd->staging_fd, offset, SEEK_SET) == -1)
			return -errno;
		ret = read(fd->staging_fd, buf, size);
		if (ret == -1)
			return -errno;
		return ret;
	} else {
		/* Read from WIM */

		struct resource_entry *res_entry;
		int ctype;
		
		res_entry = &fd->lte->resource_entry;

		ctype = wim_resource_compression_type(w, res_entry);

		if (offset > res_entry->original_size)
			return -EOVERFLOW;

		size = min(size, res_entry->original_size - offset);

		if (read_resource(w->fp, res_entry->size, 
				  res_entry->original_size,
				  res_entry->offset, ctype, size, 
				  offset, buf) != 0)
			return -EIO;
		return size;
	}
}

/* Fills in the entries of the directory specified by @path using the
 * FUSE-provided function @filler.  */
static int wimfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
			 off_t offset, struct fuse_file_info *fi)
{
	struct dentry *parent, *child;
	
	parent = (struct dentry*)fi->fh;
	wimlib_assert(parent);
	child = parent->children;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	if (!child)
		return 0;

	do {
		if (filler(buf, child->file_name_utf8, NULL, 0))
			return 0;
		child = child->next;
	} while (child != parent->children);
	return 0;
}


static int wimfs_readlink(const char *path, char *buf, size_t buf_len)
{
	struct dentry *dentry = get_dentry(w, path);
	int ret;
	if (!dentry)
		return -ENOENT;
	if (!dentry_is_symlink(dentry))
		return -EINVAL;

	ret = dentry_readlink(dentry, buf, buf_len, w);
	if (ret > 0)
		ret = 0;
	return ret;
}

/* Close a file. */
static int wimfs_release(const char *path, struct fuse_file_info *fi)
{
	int ret;
	struct wimlib_fd *fd = (struct wimlib_fd*)fi->fh;

	if (!fd) {
		/* Empty file with no lookup table entry on read-only mounted
		 * WIM */
		wimlib_assert(!(mount_flags & WIMLIB_MOUNT_FLAG_READWRITE));
		return 0;
	}

	if (flags_writable(fi->flags) && fd->dentry) {
		u64 now = get_wim_timestamp();
		fd->dentry->last_access_time = now;
		fd->dentry->last_write_time = now;
	}

	return close_wimlib_fd(fd);
}

static int wimfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct dentry *dentry = (struct dentry *)fi->fh;

	wimlib_assert(dentry);
	wimlib_assert(dentry->num_times_opened);
	if (--dentry->num_times_opened == 0)
		free_dentry(dentry);
	return 0;
}

static int wimfs_removexattr(const char *path, const char *name)
{
	/* XXX */
	return -ENOTSUP;
}

/* Renames a file or directory.  See rename (3) */
static int wimfs_rename(const char *from, const char *to)
{
	struct dentry *src;
	struct dentry *dst;
	struct dentry *parent_of_dst;
	char *file_name_utf16 = NULL, *file_name_utf8 = NULL;
	u16 file_name_utf16_len, file_name_utf8_len;
	int ret;

	/* This rename() implementation currently only supports actual files
	 * (not alternate data streams) */
	
	src = get_dentry(w, from);
	if (!src)
		return -ENOENT;

	dst = get_dentry(w, to);


	ret = get_names(&file_name_utf16, &file_name_utf8,
			&file_name_utf16_len, &file_name_utf8_len,
			path_basename(to));
	if (ret != 0)
		return -ENOMEM;

	if (dst) {
		/* Destination file exists */

		if (src == dst) /* Same file */
			return 0;

		if (!dentry_is_directory(src)) {
			/* Cannot rename non-directory to directory. */
			if (dentry_is_directory(dst))
				return -EISDIR;
		} else {
			/* Cannot rename directory to a non-directory or a non-empty
			 * directory */
			if (!dentry_is_directory(dst))
				return -ENOTDIR;
			if (dst->children != NULL)
				return -ENOTEMPTY;
		}
		parent_of_dst = dst->parent;
		remove_dentry(dst, w->lookup_table);
	} else {
		/* Destination does not exist */
		parent_of_dst = get_parent_dentry(w, to);
		if (!parent_of_dst)
			return -ENOENT;

		if (!dentry_is_directory(parent_of_dst))
			return -ENOTDIR;
	}

	FREE(src->file_name);
	FREE(src->file_name_utf8);
	src->file_name          = file_name_utf16;
	src->file_name_utf8     = file_name_utf8;
	src->file_name_len      = file_name_utf16_len;
	src->file_name_utf8_len = file_name_utf8_len;

	unlink_dentry(src);
	link_dentry(src, parent_of_dst);
	return 0;
}

/* Remove a directory */
static int wimfs_rmdir(const char *path)
{
	struct dentry *dentry;
	
	dentry = get_dentry(w, path);
	if (!dentry)
		return -ENOENT;

	if (!dentry_is_empty_directory(dentry))
		return -ENOTEMPTY;

	unlink_dentry(dentry);
	if (dentry->num_times_opened == 0)
		free_dentry(dentry);
	return 0;
}

static int wimfs_setxattr(const char *path, const char *name,
			  const char *value, size_t size, int flags)
{
	/* XXX */
	return -ENOTSUP;
}

static int wimfs_symlink(const char *to, const char *from)
{
	struct dentry *dentry_parent, *dentry;
	const char *link_name;
	struct lookup_table_entry *lte;
	
	dentry_parent = get_parent_dentry(w, from);
	if (!dentry_parent)
		return -ENOENT;
	if (!dentry_is_directory(dentry_parent))
		return -ENOTDIR;

	link_name = path_basename(from);

	if (get_dentry_child_with_name(dentry_parent, link_name))
		return -EEXIST;
	dentry = new_dentry(link_name);
	if (!dentry)
		return -ENOMEM;

	dentry->attributes = FILE_ATTRIBUTE_REPARSE_POINT;
	dentry->reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;
	dentry->hard_link = next_link_group_id++;

	if (dentry_set_symlink(dentry, to, w->lookup_table, &lte) != 0)
		goto out_free_dentry;

	wimlib_assert(lte);

	dentry->ads_entries[1].lte_group_list.type = STREAM_TYPE_ADS;
	list_add(&dentry->ads_entries[1].lte_group_list.list,
		 &lte->lte_group_list);
	wimlib_assert(dentry->resolved);

	link_dentry(dentry, dentry_parent);
	return 0;
out_free_dentry:
	free_dentry(dentry);
	return -ENOMEM;
}


/* Reduce the size of a file */
static int wimfs_truncate(const char *path, off_t size)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	int ret;
	unsigned stream_idx;
	
	ret = lookup_resource(w, path, get_lookup_flags(), &dentry,
			      &lte, &stream_idx);

	if (ret != 0)
		return ret;

	if (!lte) /* Already a zero-length file */
		return 0;

	if (lte->staging_file_name) {
		ret = truncate(lte->staging_file_name, size);
		if (ret != 0)
			return -errno;
		lte->resource_entry.original_size = size;
	} else {
		/* File in WIM.  Extract it to the staging directory, but only
		 * the first @size bytes of it. */
		ret = extract_resource_to_staging_dir(dentry, stream_idx,
						      &lte, size);
	}
	dentry_update_all_timestamps(dentry);
	return ret;
}

/* Remove a regular file */
static int wimfs_unlink(const char *path)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	int ret;
	u8 *dentry_hash;
	unsigned stream_idx;
	
	ret = lookup_resource(w, path, get_lookup_flags(), &dentry,
			      &lte, &stream_idx);

	if (ret != 0)
		return ret;

	if (stream_idx == 0) {
		/* We are removing the full dentry including all alternate data
		 * streams. */
		remove_dentry(dentry, w->lookup_table);
	} else {
		/* We are removing an alternate data stream. */
		struct ads_entry *ads_entry;
		
		ads_entry = &dentry->ads_entries[stream_idx - 1];
		lte = lte_decrement_refcnt(lte, w->lookup_table);
		if (lte)
			list_del(&ads_entry->lte_group_list.list);
		dentry_remove_ads(dentry, ads_entry);
	}
	/* Beware: The lookup table entry(s) may still be referenced by users
	 * that have opened the corresponding streams.  They are freed later in
	 * wimfs_release() when the last file user has closed the stream. */
	return 0;
}

/* 
 * Change the timestamp on a file dentry. 
 *
 * Note that alternate data streams do not have their own timestamps.
 */
static int wimfs_utimens(const char *path, const struct timespec tv[2])
{
	struct dentry *dentry = get_dentry(w, path);
	if (!dentry)
		return -ENOENT;
	if (tv[0].tv_nsec != UTIME_OMIT) {
		if (tv[0].tv_nsec == UTIME_NOW)
			dentry->last_access_time = get_wim_timestamp();
		else
			dentry->last_access_time = timespec_to_wim_timestamp(&tv[0]);
	}
	if (tv[1].tv_nsec != UTIME_OMIT) {
		if (tv[1].tv_nsec == UTIME_NOW)
			dentry->last_write_time = get_wim_timestamp();
		else
			dentry->last_write_time = timespec_to_wim_timestamp(&tv[1]);
	}
	return 0;
}

/* Writes to a file in the WIM filesystem. 
 * It may be an alternate data stream, but here we don't even notice because we
 * just get a lookup table entry. */
static int wimfs_write(const char *path, const char *buf, size_t size, 
		       off_t offset, struct fuse_file_info *fi)
{
	struct wimlib_fd *fd = (struct wimlib_fd*)fi->fh;
	int ret;

	wimlib_assert(fd);
	wimlib_assert(fd->lte);
	wimlib_assert(fd->lte->staging_file_name);
	wimlib_assert(fd->staging_fd != -1);

	/* Seek to the requested position */
	if (lseek(fd->staging_fd, offset, SEEK_SET) == -1)
		return -errno;

	/* Write the data. */
	ret = write(fd->staging_fd, buf, size);
	if (ret == -1)
		return -errno;

	return ret;
}

static struct fuse_operations wimfs_operations = {
	.access      = wimfs_access,
	.destroy     = wimfs_destroy,
	.fallocate   = wimfs_fallocate,
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
	.releasedir  = wimfs_releasedir,
	.removexattr = wimfs_removexattr,
	.rename      = wimfs_rename,
	.rmdir       = wimfs_rmdir,
	.setxattr    = wimfs_setxattr,
	.symlink     = wimfs_symlink,
	.truncate    = wimfs_truncate,
	.unlink      = wimfs_unlink,
	.utimens     = wimfs_utimens,
	.write       = wimfs_write,
};


static int check_lte_refcnt(struct lookup_table_entry *lte, void *ignore)
{
	size_t lte_group_size = 0;
	struct list_head *cur;
	list_for_each(cur, &lte->lte_group_list)
		lte_group_size++;
	if (lte_group_size > lte->refcnt) {
#ifdef ENABLE_ERROR_MESSAGES
		ERROR("The following lookup table entry has a reference count "
		      "of %u, but", lte->refcnt);
		ERROR("We found %u references to it", lte_group_size);
		print_lookup_table_entry(lte);
#endif
		return WIMLIB_ERR_INVALID_DENTRY;
	}
	return 0;
}

/* Mounts a WIM file. */
WIMLIBAPI int wimlib_mount(WIMStruct *wim, int image, const char *dir, 
			   int flags)
{
	int argc = 0;
	char *argv[16];
	int ret;
	char *p;

	DEBUG("Mount: wim = %p, image = %d, dir = %s, flags = %d, ",
			wim, image, dir, flags);

	if (!dir)
		return WIMLIB_ERR_INVALID_PARAM;

	ret = wimlib_select_image(wim, image);

	if (ret != 0)
		return ret;

	DEBUG("Selected image %d", image);

	next_link_group_id = assign_link_groups(wim->image_metadata[image - 1].lgt);

	/* Resolve all the lookup table entries of the dentry tree */
	for_dentry_in_tree(wim_root_dentry(wim), dentry_resolve_ltes,
			   wim->lookup_table);

	ret = for_lookup_table_entry(wim->lookup_table, check_lte_refcnt, NULL);
	if (ret != 0)
		return ret;

	if (flags & WIMLIB_MOUNT_FLAG_READWRITE)
		wim_get_current_image_metadata(wim)->modified = true;

	if (!(flags & (WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE |
		       WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR |
		       WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS)))
		flags |= WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR;

	mount_dir = dir;
	working_directory = getcwd(NULL, 0);
	if (!working_directory) {
		ERROR_WITH_ERRNO("Could not determine current directory");
		return WIMLIB_ERR_NOTDIR;
	}

	p = STRDUP(dir);
	if (!p)
		return WIMLIB_ERR_NOMEM;

	argv[argc++] = "mount";
	argv[argc++] = p;
	argv[argc++] = "-s"; /* disable multi-threaded operation */

	if (flags & WIMLIB_MOUNT_FLAG_DEBUG)
		argv[argc++] = "-d";

	/* 
	 * We provide the use_ino option because we are going to assign inode
	 * numbers oursides.  We've already numbered the hard link groups with
	 * unique numbers with the assign_link_groups() function, and the static
	 * variable next_link_group_id is set to the next available link group
	 * ID that we will assign to new dentries.
	 */
	char optstring[256] = "use_ino";
	argv[argc++] = "-o";
	argv[argc++] = optstring;
	if ((flags & WIMLIB_MOUNT_FLAG_READWRITE)) {
		/* Read-write mount.  Make the staging directory */
		make_staging_dir();
		if (!staging_dir_name) {
			FREE(p);
			return WIMLIB_ERR_MKDIR;
		}
	} else {
		/* Read-only mount */
		strcat(optstring, ",ro");
	}
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

	/* Set static variables. */
	w = wim;
	mount_flags = flags;

	ret = fuse_main(argc, argv, &wimfs_operations, NULL);

	return (ret == 0) ? 0 : WIMLIB_ERR_FUSE;
}


/* 
 * Unmounts the WIM file that was previously mounted on @dir by using
 * wimlib_mount().
 */
WIMLIBAPI int wimlib_unmount(const char *dir, int flags)
{
	pid_t pid;
	int status;
	int ret;
	char msg[2];
	struct timeval now;
	struct timespec timeout;
	int msgsize;
	int errno_save;

	/* Execute `fusermount -u', which is installed setuid root, to unmount
	 * the WIM.
	 *
	 * FUSE does not yet implement synchronous unmounts.  This means that
	 * fusermount -u will return before the filesystem daemon returns from
	 * wimfs_destroy().  This is partly what we want, because we need to
	 * send a message from this process to the filesystem daemon telling
	 * whether --commit was specified or not.  However, after that, the
	 * unmount process must wait for the filesystem daemon to finish writing
	 * the WIM file. 
	 */

	mount_dir = dir;
	pid = fork();
	if (pid == -1) {
		ERROR_WITH_ERRNO("Failed to fork()");
		return WIMLIB_ERR_FORK;
	}
	if (pid == 0) {
		execlp("fusermount", "fusermount", "-u", dir, NULL);
		ERROR_WITH_ERRNO("Failed to execute `fusermount'");
		return WIMLIB_ERR_FUSERMOUNT;
	}

	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		ERROR_WITH_ERRNO("Failed to wait for fusermount process to "
				 "terminate");
		return WIMLIB_ERR_FUSERMOUNT;
	}

	if (status != 0) {
		ERROR("fusermount exited with status %d", status);
		return WIMLIB_ERR_FUSERMOUNT;
	}

	/* Open message queues between the unmount process and the
	 * filesystem daemon. */
	ret = open_message_queues(false);
	if (ret != 0)
		return ret;

	/* Send a message to the filesystem saying whether to commit or
	 * not. */
	msg[0] = (flags & WIMLIB_UNMOUNT_FLAG_COMMIT) ? 1 : 0;
	msg[1] = (flags & WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY) ? 1 : 0;

	DEBUG("Sending message: %s, %s", 
			(msg[0] == 0) ? "don't commit" : "commit",
			(msg[1] == 0) ? "don't check"  : "check");
	ret = mq_send(unmount_to_daemon_mq, msg, 2, 1);
	if (ret == -1) {
		ERROR("Failed to notify filesystem daemon whether we want to "
		      "commit changes or not");
		close_message_queues();
		return WIMLIB_ERR_MQUEUE;
	}

	/* Wait for a message from the filesytem daemon indicating whether  the
	 * filesystem was unmounted successfully (0) or an error occurred (1).
	 * This may take a long time if a big WIM file needs to be rewritten. */

	/* Wait at most 600??? seconds before giving up and returning false.
	 * Either it's a really big WIM file, or (more likely) the
	 * filesystem daemon has crashed or failed for some reason.
	 *
	 * XXX come up with some method to determine if the filesystem
	 * daemon has really crashed or not. 
	 *
	 * XXX Idea: have mount daemon write its PID into the WIM file header?
	 * */

	gettimeofday(&now, NULL);
	timeout.tv_sec = now.tv_sec + 600;
	timeout.tv_nsec = now.tv_usec * 1000;

	msgsize = mq_get_msgsize(daemon_to_unmount_mq);
	char mailbox[msgsize];

	mailbox[0] = 0;
	DEBUG("Waiting for message telling us whether the unmount was "
			"successful or not.");
	ret = mq_timedreceive(daemon_to_unmount_mq, mailbox, msgsize,
			      NULL, &timeout);
	errno_save = errno;
	close_message_queues();
	if (ret == -1) {
		if (errno_save == ETIMEDOUT) {
			ERROR("Timed out- probably the filesystem daemon "
			      "crashed and the WIM was not written "
			      "successfully.");
			return WIMLIB_ERR_TIMEOUT;
		} else {
			ERROR("mq_receive(): %s", strerror(errno_save));
			return WIMLIB_ERR_MQUEUE;
		}

	}
	DEBUG("Received message: %s",
	      (mailbox[0] == 0) ?  "Unmount OK" : "Unmount Failed");
	if (mailbox[0] != 0)
		ERROR("Unmount failed");
	return mailbox[0];
}

#else /* WITH_FUSE */


static inline int mount_unsupported_error()
{
	ERROR("WIMLIB was compiled with --without-fuse, which disables support "
	      "for mounting WIMs.");
	return WIMLIB_ERR_UNSUPPORTED;
}

WIMLIBAPI int wimlib_unmount(const char *dir, int flags)
{
	return mount_unsupported_error();
}

WIMLIBAPI int wimlib_mount(WIMStruct *wim_p, int image, const char *dir, 
			   int flags)
{
	return mount_unsupported_error();
}

#endif /* WITH_FUSE */
