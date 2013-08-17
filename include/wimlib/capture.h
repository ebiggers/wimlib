#ifndef _WIMLIB_CAPTURE_H
#define _WIMLIB_CAPTURE_H

#include "wimlib.h"
#include "wimlib/list.h"
#include "wimlib/security.h"
#include "wimlib/util.h"

struct wim_lookup_table;
struct wim_dentry;

/* Hash table to find inodes, given an inode number (in the case of reading
 * a WIM images), or both an inode number and a device number (in the case of
 * capturing a WIM image). */
struct wim_inode_table {
	/* Fields for the hash table */
	struct hlist_head *array;
	u64 num_entries;
	u64 capacity;

	/*
	 * Linked list of "extra" inodes.  These may be:
	 *
	 * - inodes with link count 1, which are all allowed to have 0 for their
	 *   inode number, meaning we cannot insert them into the hash table.
         *
	 * - Groups we create ourselves by splitting a nominal inode due to
	 *   inconsistencies in the dentries.  These inodes will share an inode
	 *   number with some other inode until assign_inode_numbers() is
	 *   called.
	 */
	struct list_head extra_inodes;
};

/* Common parameters to implementations of building an in-memory dentry tree
 * from an on-disk directory structure. */
struct add_image_params {
	/* Pointer to the lookup table of the WIM. */
	struct wim_lookup_table *lookup_table;

	/* Hash table of inodes that have been captured for this tree so far. */
	struct wim_inode_table inode_table;

	/* The set of security descriptors that have been captured for this
	 * image so far. */
	struct wim_sd_set sd_set;

	/* Pointer to the capture configuration, which indicates whether any
	 * files should be excluded from capture or not. */
	struct wimlib_capture_config *config;

	/* Flags that affect the capture operation (WIMLIB_ADD_FLAG_*) */
	int add_flags;

	/* Extra argument; set to point to a pointer to the ntfs_volume for
	 * libntfs-3g capture.  */
	void *extra_arg;

	u64 capture_root_ino;
	u64 capture_root_dev;

	/* If non-NULL, the user-supplied progress function. */
	wimlib_progress_func_t progress_func;

	/* Progress data.  */
	union wimlib_progress_info progress;
};


/* capture_common.c */

extern void
do_capture_progress(struct add_image_params *params, int status);

extern bool
exclude_path(const tchar *path, size_t path_len,
	     const struct wimlib_capture_config *config,
	     bool exclude_prefix);

extern struct wimlib_capture_config *
copy_capture_config(const struct wimlib_capture_config *config);

extern int
copy_and_canonicalize_capture_config(const struct wimlib_capture_config *config,
				     struct wimlib_capture_config **config_copy_ret);

extern void
free_capture_config(struct wimlib_capture_config *config);

/* hardlink.c */

extern int
init_inode_table(struct wim_inode_table *table, size_t capacity);

extern int
inode_table_new_dentry(struct wim_inode_table *table, const tchar *name,
		       u64 ino, u64 devno, bool noshare,
		       struct wim_dentry **dentry_ret);

extern void
inode_table_prepare_inode_list(struct wim_inode_table *table,
			       struct list_head *head);

static inline void
destroy_inode_table(struct wim_inode_table *table)
{
	FREE(table->array);
}


#ifdef WITH_NTFS_3G
/* ntfs-3g_capture.c */
extern int
build_dentry_tree_ntfs(struct wim_dentry **root_p,
		       const tchar *device,
		       struct add_image_params *params);
#endif

#ifdef __WIN32__
/* win32_capture.c */
extern int
win32_build_dentry_tree(struct wim_dentry **root_ret,
			const tchar *root_disk_path,
			struct add_image_params *params);
#else
/* unix_capture.c */
extern int
unix_build_dentry_tree(struct wim_dentry **root_ret,
		       const tchar *root_disk_path,
		       struct add_image_params *params);
#endif

#define WIMLIB_ADD_FLAG_ROOT	0x80000000

#endif /* _WIMLIB_CAPTURE_H */
