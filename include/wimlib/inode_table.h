#ifndef _WIMLIB_INODE_TABLE_H
#define _WIMLIB_INODE_TABLE_H

#include "wimlib/list.h"
#include "wimlib/types.h"

struct wim_dentry;

/* Hash table to find inodes, given an inode number (in the case of reading
 * a WIM images), or both an inode number and a device number (in the case of
 * capturing a WIM image). */
struct wim_inode_table {
	/* Fields for the hash table */
	struct hlist_head *array;
	size_t num_entries;
	size_t capacity;

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


extern int
init_inode_table(struct wim_inode_table *table, size_t capacity);

extern int
inode_table_new_dentry(struct wim_inode_table *table, const tchar *name,
		       u64 ino, u64 devno, bool noshare,
		       struct wim_dentry **dentry_ret);

extern void
inode_table_prepare_inode_list(struct wim_inode_table *table,
			       struct list_head *head);

extern void
destroy_inode_table(struct wim_inode_table *table);

#endif /* _WIMLIB_INODE_TABLE_H  */
