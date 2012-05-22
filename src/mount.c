/*
 * mount.c
 *
 * This file implements mounting of WIM files using FUSE, which stands for
 * Filesystem in Userspace.  FUSE allows a filesystem to be implemented in a
 * userspace process by implementing the filesystem primitives--- read(),
 * write(), readdir(), etc.
 *
 * Copyright (C) 2012 Eric Biggers
 *
 * wimlib - Library for working with WIM files 
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "wimlib_internal.h"

#ifdef WITH_FUSE
#include "lookup_table.h"
#include "xml.h"
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
		ERROR("Out of memory!\n");
		return;
	}

	memcpy(staging_dir_name, working_directory, pwd_len);
	staging_dir_name[pwd_len] = '/';
	memcpy(staging_dir_name + pwd_len + 1, prefix, prefix_len);
	randomize_char_array_with_alnum(staging_dir_name + pwd_len + 1 + prefix_len,
				suffix_len);
	staging_dir_name[staging_dir_name_len] = '\0';

	if (mkdir(staging_dir_name, 0700) != 0) {
		ERROR("Failed to create temporary directory `%s': %m\n",
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
	return nftw(staging_dir_name, remove_file_or_directory, 10, FTW_DEPTH);
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
		ERROR("Out of memory!\n");
		return WIMLIB_ERR_NOMEM;
	}
	daemon_to_unmount_mq_name = strcat_dup(slash, mount_dir_basename,
						prefix, d2u_suffix);
	if (!daemon_to_unmount_mq_name) {
		ERROR("Out of memory!\n");
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
		ERROR("mq_open(): %m\n");
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
		ERROR("mq_open(): %m\n");
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
		ERROR("mq_getattr(): %m\n");
		ERROR("Attempting to read %s\n", msgsize_max_file);
		fp = fopen(msgsize_max_file, "rb");
		if (fp) {
			if (fscanf(fp, "%d", &msgsize) != 1) {
				ERROR("Assuming message size of 8192\n");
				msgsize = 8192;
			}
			fclose(fp);
		} else {
			ERROR("Failed to open file %s: %m\n", 
				msgsize_max_file);
			ERROR("Assuming message size of 8192\n");
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
static int close_staging_file(struct lookup_table_entry *lte, void *ignore)
{
	if (lte->staging_file_name && lte->staging_num_times_opened) {
		if (close(lte->staging_fd) != 0) {
			ERROR("Failed close file `%s': %m\n",
					lte->staging_file_name);
			return WIMLIB_ERR_WRITE;
		}
	}
	return 0;
}


/* Calculates the SHA1 sum for @dentry if its file resource is in a staging
 * file.  Updates the SHA1 sum in the dentry and the lookup table entry.  If
 * there is already a lookup table entry with the same checksum, increment its
 * reference count and destroy the lookup entry with the updated checksum. */
static int calculate_sha1sum_for_staging_file(struct dentry *dentry, void *lookup_table)
{
	struct lookup_table *table;
	struct lookup_table_entry *lte; 
	struct lookup_table_entry *existing;
	int ret;

	table = lookup_table;
	lte = lookup_resource(table, dentry->hash);
	
	if (lte && lte->staging_file_name) {

		DEBUG("Calculating SHA1 hash for file `%s'\n", dentry->file_name_utf8);
		ret = sha1sum(lte->staging_file_name, dentry->hash);
		if (ret != 0)
			return ret;

		lookup_table_unlink(table, lte);
		memcpy(lte->hash, dentry->hash, WIM_HASH_SIZE);
		existing = lookup_resource(table, dentry->hash);
		if (existing) {
			DEBUG("Merging duplicate lookup table entries for "
				"file `%s'\n", dentry->file_name_utf8);
			free_lookup_table_entry(lte);
			existing->refcnt++;
		} else {
			lookup_table_insert(table, lte);
		}
	}
	return 0;
}

/* Overwrites the WIM file, with changes saved. */
static int rebuild_wim(WIMStruct *w, bool check_integrity)
{
	int ret;
	struct dentry *root;

	root = wim_root_dentry(w);

	DEBUG("Closing all staging file descriptors.\n");
	/* Close all the staging file descriptors. */
	ret = for_lookup_table_entry(w->lookup_table, 
				     close_staging_file, NULL);
	if (ret != 0) {
		ERROR("Failed to close all staging files!\n");
		return ret;
	}

	DEBUG("Calculating SHA1 checksums for all new staging files.\n");
	/* Calculate SHA1 checksums for all staging files, and merge unnecessary
	 * lookup table entries. */
	ret = for_dentry_in_tree(root, calculate_sha1sum_for_staging_file,
				 w->lookup_table);
	if (ret != 0) {
		ERROR("Failed to calculate new SHA1 checksums!\n");
		return ret;
	}

	xml_update_image_info(w, w->current_image);

	ret = wimlib_overwrite(w, check_integrity);
	if (ret != 0) {
		ERROR("Failed to commit changes\n");
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
	DEBUG("Waiting for message telling us whether to commit or not, "
			"and whether to include integrity checks.\n");

	bytes_received = mq_timedreceive(unmount_to_daemon_mq, msg, 
					 msgsize, NULL, &timeout);
	commit = msg[0];
	check_integrity = msg[1];
	if (bytes_received == -1) {
		if (errno == ETIMEDOUT) {
			ERROR("Timed out.\n");
		} else {
			ERROR("mq_timedreceive(): %m\n");
		}
		ERROR("Not committing.\n");
	} else {
		DEBUG("Received message: [%d %d]\n", msg[0], msg[1]);
	}

	status = 0;
	if (mount_flags & WIMLIB_MOUNT_FLAG_READWRITE) {
		if (commit) {
			status = chdir(working_directory);
			if (status != 0) {
				ERROR("chdir(): %m\n");
				status = WIMLIB_ERR_NOTDIR;
				goto done;
			}
			status = rebuild_wim(w, (check_integrity != 0));
		}
		ret = delete_staging_dir();
		if (ret != 0) {
			ERROR("Failed to delete the staging directory: %m\n");
			if (status == 0)
				status = ret;
		}
	}
done:
	ret = mq_send(daemon_to_unmount_mq, &status, 1, 1);
	if (ret == -1)
		ERROR("Failed to send status to unmount process: %m\n");
	close_message_queues();
}

/*
 * Fills in a `struct stat' that corresponds to a file or directory in the WIM.
 */
static int wimfs_getattr(const char *path, struct stat *stbuf)
{
	struct dentry *dentry = get_dentry(w, path);
	if (!dentry)
		return -ENOENT;
	dentry_to_stbuf(dentry, stbuf, w->lookup_table);
	return 0;
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
	newdir->attributes |= WIM_FILE_ATTRIBUTE_DIRECTORY;
	link_dentry(newdir, parent);
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
static int create_staging_file(char **name_ret)
{
	size_t name_len;
	char *name;
	struct stat stbuf;
	int fd;
	int errno_save;

	name_len = staging_dir_name_len + 1 + WIM_HASH_SIZE;
 	name = MALLOC(name_len + 1);
	if (!name) {
		errno = ENOMEM;
		return -1;
	}

	memcpy(name, staging_dir_name, staging_dir_name_len);
	name[staging_dir_name_len] = '/';
	randomize_char_array_with_alnum(name + staging_dir_name_len + 1,
					WIM_HASH_SIZE);
	name[name_len] = '\0';


	/* Just in case, verify that the randomly generated name doesn't name an
	 * existing file, and try again if so  */
	if (stat(name, &stbuf) == 0) {
		/* stat succeeded-- the file must exist. Try another name. */
		FREE(name);
		return create_staging_file(name_ret);
	} else {
		if (errno != ENOENT)
			/* other error! */
			return -1;
		/* doesn't exist--- ok */
	}

	DEBUG("Creating staging file '%s'\n", name);

	fd = creat(name, 0600); 
	if (fd == -1) {
		errno_save = errno;
		FREE(name);
		errno = errno_save;
	} else {
		*name_ret = name;
	}
	return fd;
}

/* Creates a regular file.  This is done in the staging directory.  */
static int wimfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	struct dentry *parent, *dentry;
	const char *basename;
	struct lookup_table_entry *lte;
	char *tmpfile_name;
	int fd;
	int err;

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

	/* XXX fill in a temporary random hash value- really should check for
	 * duplicates */
	randomize_byte_array(dentry->hash, WIM_HASH_SIZE);

	/* Create a lookup table entry having the same hash value */
	lte = new_lookup_table_entry();
	lte->staging_num_times_opened = 0;
	lte->resource_entry.original_size = 0;
	memcpy(lte->hash, dentry->hash, WIM_HASH_SIZE);

	fd = create_staging_file(&tmpfile_name);

	if (fd == -1)
		goto mknod_error;

	if (close(fd) != 0)
		goto mknod_error;

	lte->staging_file_name = tmpfile_name;

	/* Insert the lookup table entry, and link the new dentry with its
	 * parent. */
	lookup_table_insert(w->lookup_table, lte);
	link_dentry(dentry, parent);
	return 0;
mknod_error:
	err = errno;
	free_lookup_table_entry(lte);
	return -err;
}

/* Open a file.  */
static int wimfs_open(const char *path, struct fuse_file_info *fi)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	
	dentry = get_dentry(w, path);

	if (!dentry)
		return -EEXIST;
	if (dentry_is_directory(dentry))
		return -EISDIR;
	lte = wim_lookup_resource(w, dentry);

	if (lte) {
		/* If this file is in the staging directory and the file is not
		 * currently open, open it. */
		if (lte->staging_file_name && lte->staging_num_times_opened == 0) {
			lte->staging_fd = open(lte->staging_file_name, O_RDWR);
			if (lte->staging_fd == -1)
				return -errno;
			lte->staging_offset = 0;
		}
	} else {
		/* no lookup table entry, so the file must be empty.  Create a
		 * lookup table entry for the file. */
		char *tmpfile_name;
		int err;
		int fd;

		lte = new_lookup_table_entry();
		if (!lte)
			return -ENOMEM;

		fd = create_staging_file(&tmpfile_name);

		if (fd == -1) {
			err = errno;
			free(lte);
			return -errno;
		}
		lte->resource_entry.original_size = 0;
		randomize_byte_array(lte->hash, WIM_HASH_SIZE);
		memcpy(dentry->hash, lte->hash, WIM_HASH_SIZE);
		lte->staging_file_name = tmpfile_name;
		lte->staging_fd = fd;
		lte->staging_offset = 0;
		lookup_table_insert(w->lookup_table, lte);
	}
	lte->staging_num_times_opened++;
	return 0;
}

/* Opens a directory. */
static int wimfs_opendir(const char *path, struct fuse_file_info *fi)
{
	struct dentry *dentry;
	
	dentry = get_dentry(w, path);
	if (!dentry || !dentry_is_directory(dentry))
		return -ENOTDIR;
	return 0;
}


/*
 * Read data from a file in the WIM or in the staging directory. 
 */
static int wimfs_read(const char *path, char *buf, size_t size, 
		off_t offset, struct fuse_file_info *fi)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	
	dentry = get_dentry(w, path);

	if (!dentry)
		return -EEXIST;

	if (!dentry_is_regular_file(dentry))
		return -EISDIR;

	lte = wim_lookup_resource(w, dentry);

	if (!lte)
		return 0;

	if (lte->staging_file_name) {

		/* Read from staging */
		int fd;
		off_t cur_offset;
		ssize_t ret;

		if (lte->staging_num_times_opened == 0)
			return -EBADF;

		fd = lte->staging_fd;
		cur_offset = lte->staging_offset;
		if (cur_offset != offset)
			if (lseek(fd, offset, SEEK_SET) == -1)
				return -errno;
		lte->staging_offset = offset;

		ret = read(fd, buf, size);
		if (ret == -1)
			return -errno;
		lte->staging_offset = offset + ret;

		return ret;
	} else {

		/* Read from WIM */

		struct resource_entry *res_entry;
		int ctype;
		
		res_entry = &lte->resource_entry;

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
	struct dentry *parent;
	struct dentry *child;
	struct stat st;

	parent = get_dentry(w, path);

	if (!parent)
		return -EEXIST;

	if (!dentry_is_directory(parent))
		return -ENOTDIR;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	child = parent->children;

	if (!child)
		return 0;

	do {
		memset(&st, 0, sizeof(st));
		if (filler(buf, child->file_name_utf8, &st, 0))
			return 0;
		child = child->next;
	} while (child != parent->children);
	return 0;
}

/* Close a file. */
static int wimfs_release(const char *path, struct fuse_file_info *fi)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	int ret;
	
	dentry = get_dentry(w, path);
	if (!dentry)
		return -EEXIST;
	lte = wim_lookup_resource(w, dentry);

	if (!lte)
		return 0;
	
	if (lte->staging_num_times_opened == 0)
		return -EBADF;

	if (--lte->staging_num_times_opened == 0 && lte->staging_file_name) {
		ret = close(lte->staging_fd);
		if (ret != 0)
			return -errno;
	}
	return 0;
}

/* Renames a file or directory.  See rename (3) */
static int wimfs_rename(const char *from, const char *to)
{
	struct dentry *src;
	struct dentry *dst;
	struct dentry *parent_of_dst;
	
	src = get_dentry(w, from);
	if (!src)
		return -ENOENT;

	dst = get_dentry(w, to);

	if (dst) {
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
		unlink_dentry(dst);
		lookup_table_decrement_refcnt(w->lookup_table, dst->hash);
		free_dentry(dst);
	} else {
		parent_of_dst = get_parent_dentry(w, to);
		if (!parent_of_dst)
			return -ENOENT;
	}

	unlink_dentry(src);
	change_dentry_name(src, path_basename(to));
	link_dentry(src, parent_of_dst);
	/*calculate_dentry_full_path(src);*/
	return 0;
}

/* Remove a directory */
static int wimfs_rmdir(const char *path)
{
	struct dentry *dentry;
	
	dentry = get_dentry(w, path);
	if (!dentry)
		return -EEXIST;

	if (!dentry_is_empty_directory(dentry))
		return -EEXIST;

	unlink_dentry(dentry);
	free_dentry(dentry);
	return 0;
}

/* Extracts the resource corresponding to @dentry and its lookup table entry
 * @lte to a file in the staging directory.  The lookup table entry for @dentry
 * is updated to point to the new file.  If @lte has multiple dentries
 * referencing it, a new lookup table entry is created and the hash of @dentry
 * is changed to point to the new lookup table entry.
 *
 * Only @size bytes are extracted, to support truncating the file. 
 *
 * Returns the negative error code on failure.
 */
static int extract_resource_to_staging_dir(struct dentry *dentry, 
					   struct lookup_table_entry *lte, 
					   u64 size)
{
	int err, fd;
	bool ret;
	char *staging_file_name;
	struct lookup_table_entry *new_lte;

	/* File in WIM.  Copy it to the staging directory. */
	fd = create_staging_file(&staging_file_name);
	if (fd == -1)
		return -errno;

	ret = extract_resource_to_fd(w, &lte->resource_entry, fd, size);
	if (ret != 0) {
		if (errno != 0)
			ret = -errno;
		else
			ret = -EIO;
		unlink(staging_file_name);
		FREE(staging_file_name);
		return ret;
	}

	if (lte->refcnt != 1) {
		/* Need to make a new lookup table entry if we are
		 * changing only one copy of a hardlinked entry */
		lte->refcnt--;

		new_lte = new_lookup_table_entry();
		if (!new_lte)
			return -ENOMEM;
		randomize_byte_array(dentry->hash, WIM_HASH_SIZE);
		memcpy(new_lte->hash, dentry->hash, WIM_HASH_SIZE);

		new_lte->resource_entry.flags = 0;
		new_lte->staging_num_times_opened = lte->staging_num_times_opened;

		lookup_table_insert(w->lookup_table, new_lte);

		lte = new_lte;
	} 

	lte->resource_entry.original_size = size;
	lte->staging_file_name = staging_file_name;
	
	if (lte->staging_num_times_opened == 0)
		close(fd);
	else
		lte->staging_fd = fd;
	return 0;
}

/* Reduce the size of a file */
static int wimfs_truncate(const char *path, off_t size)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	int ret;

	dentry = get_dentry(w, path);
	if (!dentry)
		return -EEXIST;
	lte = wim_lookup_resource(w, dentry);

	if (!lte) /* Already a zero-length file */
		return 0;
	if (lte->staging_file_name) {
		/* File on disk.  Call POSIX API */
		if (lte->staging_num_times_opened != 0)
			ret = ftruncate(lte->staging_fd, size);
		else
			ret = truncate(lte->staging_file_name, size);
		if (ret != 0)
			return -errno;
		dentry_update_all_timestamps(dentry);
		lte->resource_entry.original_size = size;
		return 0;
	} else {
		/* File in WIM.  Extract it to the staging directory, but only
		 * the first @size bytes of it. */
		return extract_resource_to_staging_dir(dentry, lte, size);
	}
}

/* Remove a regular file */
static int wimfs_unlink(const char *path)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	
	dentry = get_dentry(w, path);
	if (!dentry)
		return -EEXIST;

	if (!dentry_is_regular_file(dentry))
		return -EEXIST;

	lte = wim_lookup_resource(w, dentry);
	if (lte) {
		if (lte->staging_file_name)
			if (unlink(lte->staging_file_name) != 0)
				return -errno;
		lookup_table_decrement_refcnt(w->lookup_table, dentry->hash);
	}

	unlink_dentry(dentry);
	free_dentry(dentry);
	return 0;
}

/* Writes to a file in the WIM filesystem. */
static int wimfs_write(const char *path, const char *buf, size_t size, 
				off_t offset, struct fuse_file_info *fi)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	ssize_t ret;

	dentry = get_dentry(w, path);
	if (!dentry)
		return -EEXIST;
	lte = wim_lookup_resource(w, dentry);

	if (!lte) /* this should not happen */
		return -EEXIST;

	if (lte->staging_num_times_opened == 0)
		return -EBADF;
	if (lte->staging_file_name) {

		/* File in staging directory. We can write to it directly. */

		/* Seek to correct position in file if needed. */
		if (lte->staging_offset != offset) {
			if (lseek(lte->staging_fd, offset, SEEK_SET) == -1)
				return -errno;
			lte->staging_offset = offset;
		}

		/* Write the data. */
		ret = write(lte->staging_fd, buf, size);
		if (ret == -1)
			return -errno;

		/* Adjust the stored offset of staging_fd. */
		lte->staging_offset = offset + ret;

		/* Increase file size if needed. */
		if (lte->resource_entry.original_size < lte->staging_offset)
			lte->resource_entry.original_size = lte->staging_offset;

		/* The file has been modified, so all its timestamps must be
		 * updated. */
		dentry_update_all_timestamps(dentry);
		return ret;
	} else {
		/* File in the WIM.  We must extract it to the staging directory
		 * before it can be written to. */
		ret = extract_resource_to_staging_dir(dentry, lte, 
					lte->resource_entry.original_size);
		if (ret != 0)
			return ret;
		else
			return wimfs_write(path, buf, size, offset, fi);
	}
}


static struct fuse_operations wimfs_oper = {
	.access   = wimfs_access,
	.destroy  = wimfs_destroy,
	.getattr  = wimfs_getattr,
	.mkdir    = wimfs_mkdir,
	.mknod    = wimfs_mknod,
	.open     = wimfs_open,
	.opendir  = wimfs_opendir,
	.read     = wimfs_read,
	.readdir  = wimfs_readdir,
	.release  = wimfs_release,
	.rename   = wimfs_rename,
	.rmdir    = wimfs_rmdir,
	.truncate = wimfs_truncate,
	.unlink   = wimfs_unlink,
	.write    = wimfs_write,
};


/* Mounts a WIM file. */
WIMLIBAPI int wimlib_mount(WIMStruct *wim, int image, const char *dir, 
			   int flags)
{
	int argc = 0;
	char *argv[6];
	int ret;
	char *p;

	DEBUG("Mount: wim = %p, image = %d, dir = %s, flags = %d, ",
			wim, image, dir, flags);

	if (!dir)
		return WIMLIB_ERR_INVALID_PARAM;

	ret = wimlib_select_image(wim, image);

	if (ret != 0)
		return ret;

	if (flags & WIMLIB_MOUNT_FLAG_READWRITE)
		wim_get_current_image_metadata(wim)->modified = true;

	mount_dir = dir;
	working_directory = getcwd(NULL, 0);
	if (!working_directory) {
		ERROR("Could not determine current directory: %m\n");
		return WIMLIB_ERR_NOTDIR;
	}

	p = STRDUP(dir);
	if (!p)
		return WIMLIB_ERR_NOMEM;

	argv[argc++] = "mount";
	argv[argc++] = p;
	argv[argc++] = "-s"; /* disable multi-threaded operation */

	if (flags & WIMLIB_MOUNT_FLAG_DEBUG) {
		argv[argc++] = "-d";
	}
	if (!(flags & WIMLIB_MOUNT_FLAG_READWRITE)) {
		argv[argc++] = "-o";
		argv[argc++] = "ro";
	} else {
		make_staging_dir();
		if (!staging_dir_name) {
			FREE(p);
			return WIMLIB_ERR_MKDIR;
		}
	}

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

	ret = fuse_main(argc, argv, &wimfs_oper, NULL);

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
		ERROR("Failed to fork(): %m\n");
		return WIMLIB_ERR_FORK;
	}
	if (pid == 0) {
		execlp("fusermount", "fusermount", "-u", dir, NULL);
		ERROR("Failed to execute `fusermount': %m\n");
		return WIMLIB_ERR_FUSERMOUNT;
	}

	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		ERROR("Failed to wait for fusermount process to "
				"terminate: %m\n");
		return WIMLIB_ERR_FUSERMOUNT;
	}

	if (status != 0) {
		ERROR("fusermount exited with status %d!\n", status);
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

	DEBUG("Sending message: %s, %s\n", 
			(msg[0] == 0) ? "don't commit" : "commit",
			(msg[1] == 0) ? "don't check"  : "check");
	ret = mq_send(unmount_to_daemon_mq, msg, 2, 1);
	if (ret == -1) {
		ERROR("Failed to notify filesystem daemon whether "
				"we want to commit changes or not!\n");
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
	 * daemon has really crashed or not. */

	gettimeofday(&now, NULL);
	timeout.tv_sec = now.tv_sec + 600;
	timeout.tv_nsec = now.tv_usec * 1000;

	msgsize = mq_get_msgsize(daemon_to_unmount_mq);
	char mailbox[msgsize];

	mailbox[0] = 0;
	DEBUG("Waiting for message telling us whether the unmount was "
			"successful or not.\n");
	ret = mq_timedreceive(daemon_to_unmount_mq, mailbox, msgsize,
			      NULL, &timeout);
	errno_save = errno;
	close_message_queues();
	if (ret == -1) {
		if (errno_save == ETIMEDOUT) {
			ERROR("Timed out- probably the filesystem "
					"daemon crashed and the WIM was not "
					"written successfully.\n");
			return WIMLIB_ERR_TIMEOUT;
		} else {
			ERROR("mq_receive(): %s\n",
					strerror(errno_save));
			return WIMLIB_ERR_MQUEUE;
		}

	}
	DEBUG("Received message: %s\n", (mailbox[0] == 0) ? 
					"Unmount OK" : "Unmount Failed");
	if (mailbox[0] != 0)
		ERROR("Unmount failed\n");
	return mailbox[0];
}

#else /* WITH_FUSE */


static inline int mount_unsupported_error()
{
	ERROR("WIMLIB was compiled with --without-fuse, which "
			"disables support for mounting WIMs.\n");
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
