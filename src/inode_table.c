/*
 * inode_table.c - hard link detection
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/inode.h"
#include "wimlib/inode_table.h"
#include "wimlib/list.h"
#include "wimlib/util.h"

/* Initialize a hash table for hard link detection.  */
int
init_inode_table(struct wim_inode_table *table, size_t capacity)
{
	table->array = CALLOC(capacity, sizeof(table->array[0]));
	if (!table->array)
		return WIMLIB_ERR_NOMEM;
	table->num_entries = 0;
	table->capacity = capacity;
	INIT_HLIST_HEAD(&table->extra_inodes);
	return 0;
}

/* Free the memory allocated by init_inode_table().  */
void
destroy_inode_table(struct wim_inode_table *table)
{
	FREE(table->array);
}

/*
 * Allocate a new dentry, with hard link detection.
 *
 * @table
 *	The inode table being used for the current directory scan operation.  It
 *	will contain the mapping from (ino, devno) pairs to inodes.
 *
 * @name
 *	The name to give the new dentry.
 *
 * @ino
 *	The inode number of the file, read from the filesystem.
 *
 * @devno
 *	The device number of the file, read from the filesystem.  Proper setting
 *	of this parameter prevents cross-device hardlinks from being created.
 *	If this is not a problem (perhaps because the current directory scan
 *	operation is guaranteed to never traverse a filesystem boundary), then
 *	this parameter can just be a fixed value such as 0.
 *
 * @noshare
 *	If %true, the new dentry will not be hard linked to any existing inode,
 *	regardless of the values of @ino and @devno.  If %false, normal hard
 *	link detection will be done.
 *
 * @dentry_ret
 *	On success, a pointer to the new dentry will be returned in this
 *	location.  If i_nlink of the dentry's inode is greater than 1, then this
 *	function created a hard link to an existing inode rather than creating a
 *	new inode.
 *
 * On success, returns 0.  On failure, returns WIMLIB_ERR_NOMEM or an error code
 * resulting from a failed string conversion.
 */
int
inode_table_new_dentry(struct wim_inode_table *table, const tchar *name,
		       u64 ino, u64 devno, bool noshare,
		       struct wim_dentry **dentry_ret)
{
	struct wim_dentry *dentry;
	struct wim_inode *inode;
	int ret;

	if (noshare) {
		/* File that cannot be hardlinked--- Return a new inode with its
		 * inode and device numbers left at 0. */
		ret = new_dentry_with_new_inode(name, false, &dentry);
		if (ret)
			return ret;
		hlist_add_head(&dentry->d_inode->i_hlist_node, &table->extra_inodes);
	} else {
		size_t pos;

		/* File that can be hardlinked--- search the table for an
		 * existing inode matching the inode number and device.  */
		pos = hash_u64(hash_u64(ino) + hash_u64(devno)) % table->capacity;
		hlist_for_each_entry(inode, &table->array[pos], i_hlist_node) {
			if (inode->i_ino == ino && inode->i_devno == devno) {
				/* Found; use the existing inode.  */
				return new_dentry_with_existing_inode(name, inode,
								      dentry_ret);
			}
		}

		/* Not found; create a new inode and add it to the table.  */
		ret = new_dentry_with_new_inode(name, false, &dentry);
		if (ret)
			return ret;
		inode = dentry->d_inode;
		inode->i_ino = ino;
		inode->i_devno = devno;
		hlist_add_head(&inode->i_hlist_node, &table->array[pos]);
		table->num_entries++;
	}
	*dentry_ret = dentry;
	return 0;
}

/*
 * Following the allocation of dentries with hard link detection using
 * inode_table_new_dentry(), this function will assign consecutive inode numbers
 * to the new set of inodes.  It will also append the list of new inodes to the
 * list @head, which must contain any inodes already existing in the WIM image.
 */
void
inode_table_prepare_inode_list(struct wim_inode_table *table,
			       struct hlist_head *head)
{
	struct wim_inode *inode;
	struct hlist_node *tmp;
	u64 cur_ino = 1;

	/* Re-assign inode numbers in the existing list to avoid duplicates. */
	hlist_for_each_entry(inode, head, i_hlist_node)
		inode->i_ino = cur_ino++;

	/* Assign inode numbers to the new inodes and move them to the image's
	 * inode list. */
	for (size_t i = 0; i < table->capacity; i++) {
		hlist_for_each_entry_safe(inode, tmp, &table->array[i], i_hlist_node) {
			inode->i_ino = cur_ino++;
			hlist_add_head(&inode->i_hlist_node, head);
		}
		INIT_HLIST_HEAD(&table->array[i]);
	}
	hlist_for_each_entry_safe(inode, tmp, &table->extra_inodes, i_hlist_node) {
		inode->i_ino = cur_ino++;
		hlist_add_head(&inode->i_hlist_node, head);
	}
	INIT_HLIST_HEAD(&table->extra_inodes);
	table->num_entries = 0;
}
