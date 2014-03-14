/*
 * inode_fixup.c
 *
 * See dentry_tree_fix_inodes() for description.
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

#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/inode.h"
#include "wimlib/inode_table.h"
#include "wimlib/lookup_table.h"

/* Manual link count of inode (normally we can just check i_nlink)  */
static inline size_t
inode_link_count(const struct wim_inode *inode)
{
	const struct list_head *cur;
	size_t size = 0;
	list_for_each(cur, &inode->i_dentry)
		size++;
	return size;
}

static inline void
print_inode_dentries(const struct wim_inode *inode)
{
	struct wim_dentry *dentry;
	inode_for_each_dentry(dentry, inode)
		tfprintf(stderr, T("%"TS"\n"), dentry_full_path(dentry));
}

static void
inconsistent_inode(const struct wim_inode *inode)
{
	if (wimlib_print_errors) {
		ERROR("An inconsistent hard link group that cannot be corrected has "
		      "been detected");
		ERROR("The dentries are located at the following paths:");
		print_inode_dentries(inode);
	}
}

static bool
ads_entries_have_same_name(const struct wim_ads_entry *entry_1,
			   const struct wim_ads_entry *entry_2)
{
	return entry_1->stream_name_nbytes == entry_2->stream_name_nbytes &&
	       memcmp(entry_1->stream_name, entry_2->stream_name,
		      entry_1->stream_name_nbytes) == 0;
}

static bool
ref_inodes_consistent(const struct wim_inode * restrict ref_inode_1,
		      const struct wim_inode * restrict ref_inode_2)
{
	wimlib_assert(ref_inode_1 != ref_inode_2);

	if (ref_inode_1->i_num_ads != ref_inode_2->i_num_ads)
		return false;
	if (ref_inode_1->i_security_id != ref_inode_2->i_security_id
	    || ref_inode_1->i_attributes != ref_inode_2->i_attributes)
		return false;
	for (unsigned i = 0; i <= ref_inode_1->i_num_ads; i++) {
		const u8 *ref_1_hash, *ref_2_hash;
		ref_1_hash = inode_stream_hash(ref_inode_1, i);
		ref_2_hash = inode_stream_hash(ref_inode_2, i);
		if (!hashes_equal(ref_1_hash, ref_2_hash))
			return false;
		if (i && !ads_entries_have_same_name(&ref_inode_1->i_ads_entries[i - 1],
						     &ref_inode_2->i_ads_entries[i - 1]))
			return false;

	}
	return true;
}

/* Returns true iff the specified inode has any data streams with nonzero hash.
 */
static bool
inode_has_data_streams(const struct wim_inode *inode)
{
	for (unsigned i = 0; i <= inode->i_num_ads; i++)
		if (!is_zero_hash(inode_stream_hash(inode, i)))
			return true;
	return false;
}

/* Returns true iff the specified dentry has any data streams with nonzero hash.
 */
static bool
dentry_has_data_streams(const struct wim_dentry *dentry)
{
	return inode_has_data_streams(dentry->d_inode);
}

static bool
inodes_consistent(const struct wim_inode *ref_inode,
		  const struct wim_inode *inode)
{
	if (ref_inode->i_security_id != inode->i_security_id) {
		ERROR("Security ID mismatch: %d != %d",
		      ref_inode->i_security_id, inode->i_security_id);
		return false;
	}

	if (ref_inode->i_attributes != inode->i_attributes) {
		ERROR("Attributes mismatch: 0x%08x != 0x%08x",
		      ref_inode->i_attributes, inode->i_attributes);
		return false;
	}

	if (inode_has_data_streams(inode)) {
		if (ref_inode->i_num_ads != inode->i_num_ads) {
			ERROR("Stream count mismatch: %u != %u",
			      ref_inode->i_num_ads, inode->i_num_ads);
			return false;
		}
		for (unsigned i = 0; i <= ref_inode->i_num_ads; i++) {
			const u8 *ref_hash, *hash;

			ref_hash = inode_stream_hash(ref_inode, i);
			hash = inode_stream_hash(inode, i);
			if (!hashes_equal(ref_hash, hash) && !is_zero_hash(hash)) {
				ERROR("Stream hash mismatch");
				return false;
			}
			if (i && !ads_entries_have_same_name(&ref_inode->i_ads_entries[i - 1],
							     &inode->i_ads_entries[i - 1]))
			{
				ERROR("Stream name mismatch");
				return false;
			}
		}
	}
	return true;
}

/* Fix up a "true" inode and check for inconsistencies */
static int
fix_true_inode(struct wim_inode *inode, struct list_head *inode_list)
{
	struct wim_dentry *dentry;
	struct wim_dentry *ref_dentry = NULL;
	struct wim_inode *ref_inode;
	u64 last_ctime = 0;
	u64 last_mtime = 0;
	u64 last_atime = 0;

	inode_for_each_dentry(dentry, inode) {
		if (!ref_dentry || dentry->d_inode->i_num_ads > ref_dentry->d_inode->i_num_ads)
			ref_dentry = dentry;
		if (dentry->d_inode->i_creation_time > last_ctime)
			last_ctime = dentry->d_inode->i_creation_time;
		if (dentry->d_inode->i_last_write_time > last_mtime)
			last_mtime = dentry->d_inode->i_last_write_time;
		if (dentry->d_inode->i_last_access_time > last_atime)
			last_atime = dentry->d_inode->i_last_access_time;
	}

	ref_inode = ref_dentry->d_inode;
	wimlib_assert(ref_inode->i_nlink == 1);
	list_add_tail(&ref_inode->i_list, inode_list);

	list_del(&inode->i_dentry);
	list_add(&ref_inode->i_dentry, &ref_dentry->d_alias);

	inode_for_each_dentry(dentry, ref_inode) {
		if (dentry != ref_dentry) {
			if (!inodes_consistent(ref_inode, dentry->d_inode)) {
				inconsistent_inode(ref_inode);
				return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
			}
			/* Free the unneeded `struct wim_inode'. */
			wimlib_assert(dentry->d_inode->i_nlink == 1);
			free_inode(dentry->d_inode);
			dentry->d_inode = ref_inode;
			ref_inode->i_nlink++;
		}
	}
	ref_inode->i_creation_time = last_ctime;
	ref_inode->i_last_write_time = last_mtime;
	ref_inode->i_last_access_time = last_atime;
	wimlib_assert(inode_link_count(ref_inode) == ref_inode->i_nlink);
	return 0;
}

/*
 * Fixes up a nominal inode.
 *
 * By a nominal inode we mean a group of two or more dentries that share the
 * same hard link group ID.
 *
 * If dentries in the inode are found to be inconsistent, we may split the inode
 * into several "true" inodes.
 *
 * After splitting up each nominal inode into the "true" inodes we will
 * canonicalize the link group by getting rid of all the unnecessary `struct
 * wim_inode's.  There will be just one `struct wim_inode' for each hard link
 * group remaining.
 */
static int
fix_nominal_inode(struct wim_inode *inode, struct list_head *inode_list,
		  bool *ino_changes_needed)
{
	struct wim_dentry *dentry;
	struct hlist_node *cur, *tmp;
	int ret;
	size_t num_true_inodes;

	LIST_HEAD(dentries_with_data_streams);
	LIST_HEAD(dentries_with_no_data_streams);
	HLIST_HEAD(true_inodes);

        /* Create a list of dentries in the nominal inode that have at
         * least one data stream with a non-zero hash, and another list that
         * contains the dentries that have a zero hash for all data streams. */
	inode_for_each_dentry(dentry, inode) {
		if (dentry_has_data_streams(dentry))
			list_add(&dentry->tmp_list, &dentries_with_data_streams);
		else
			list_add(&dentry->tmp_list, &dentries_with_no_data_streams);
	}

	/* If there are no dentries with data streams, we require the nominal
	 * inode to be a true inode */
	if (list_empty(&dentries_with_data_streams)) {
	#ifdef ENABLE_DEBUG
		unsigned nominal_group_size = inode_link_count(inode);
		if (nominal_group_size > 1) {
			DEBUG("Found link group of size %u without "
			      "any data streams:", nominal_group_size);
			print_inode_dentries(inode);
			DEBUG("We are going to interpret it as true "
			      "link group, provided that the dentries "
			      "are consistent.");
		}
	#endif
		return fix_true_inode(inode, inode_list);
	}

        /* One or more dentries had data streams specified.  We check each of
         * these dentries for consistency with the others to form a set of true
         * inodes. */
	num_true_inodes = 0;
	list_for_each_entry(dentry, &dentries_with_data_streams, tmp_list) {
		/* Look for a true inode that is consistent with this dentry and
		 * add this dentry to it.  Or, if none of the true inodes are
		 * consistent with this dentry, add a new one (if that happens,
		 * we have split the hard link group). */
		hlist_for_each_entry(inode, cur, &true_inodes, i_hlist) {
			if (ref_inodes_consistent(inode, dentry->d_inode)) {
				inode_add_dentry(dentry, inode);
				goto next_dentry_2;
			}
		}
		num_true_inodes++;
		INIT_LIST_HEAD(&dentry->d_inode->i_dentry);
		inode_add_dentry(dentry, dentry->d_inode);
		hlist_add_head(&dentry->d_inode->i_hlist, &true_inodes);
next_dentry_2:
		;
	}

	wimlib_assert(num_true_inodes != 0);

        /* If there were dentries with no data streams, we require there to only
         * be one true inode so that we know which inode to assign the
         * streamless dentries to. */
	if (!list_empty(&dentries_with_no_data_streams)) {
		if (num_true_inodes != 1) {
			ERROR("Hard link ambiguity detected!");
			ERROR("We split up inode 0x%"PRIx64" due to "
			      "inconsistencies,", inode->i_ino);
			ERROR("but dentries with no stream information remained. "
			      "We don't know which inode");
			ERROR("to assign them to.");
			ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
			goto out_cleanup_true_inode_list;
		}
		inode = container_of(true_inodes.first, struct wim_inode, i_hlist);
		/* Assign the streamless dentries to the one and only true
		 * inode. */
		list_for_each_entry(dentry, &dentries_with_no_data_streams, tmp_list)
			inode_add_dentry(dentry, inode);
	}
        if (num_true_inodes != 1) {
	#ifdef ENABLE_DEBUG
		inode = container_of(true_inodes.first, struct wim_inode, i_hlist);

		tprintf(T("Split nominal inode 0x%"PRIx64" into %zu "
			  "inodes:\n"), inode->i_ino, num_true_inodes);
		tputs(T("----------------------------------------------------"
			"--------------------------"));
		size_t i = 1;
		hlist_for_each_entry(inode, cur, &true_inodes, i_hlist) {
			tprintf(T("[Split inode %zu]\n"), i++);
			print_inode_dentries(inode);
			tputchar(T('\n'));
		}
		tputs(T("----------------------------------------------------"
			"--------------------------"));
	#endif
		*ino_changes_needed = true;
        }

	hlist_for_each_entry_safe(inode, cur, tmp, &true_inodes, i_hlist) {
		hlist_del_init(&inode->i_hlist);
		ret = fix_true_inode(inode, inode_list);
		if (ret)
			goto out_cleanup_true_inode_list;
	}
	ret = 0;
	goto out;
out_cleanup_true_inode_list:
	hlist_for_each_entry_safe(inode, cur, tmp, &true_inodes, i_hlist)
		hlist_del_init(&inode->i_hlist);
out:
	return ret;
}

static int
fix_inodes(struct wim_inode_table *table, struct list_head *inode_list,
	   bool *ino_changes_needed)
{
	struct wim_inode *inode;
	struct hlist_node *cur, *tmp;
	int ret;
	INIT_LIST_HEAD(inode_list);
	for (u64 i = 0; i < table->capacity; i++) {
		hlist_for_each_entry_safe(inode, cur, tmp, &table->array[i], i_hlist) {
			hlist_del_init(&inode->i_hlist);
			ret = fix_nominal_inode(inode, inode_list, ino_changes_needed);
			if (ret)
				return ret;
		}
	}
	list_splice_tail(&table->extra_inodes, inode_list);
	return 0;
}

/* Insert a dentry into the inode table based on the inode number of the
 * attached inode (which came from the hard link group ID field of the on-disk
 * WIM dentry) */
static int
inode_table_insert(struct wim_dentry *dentry, void *_table)
{
	struct wim_inode_table *table = _table;
	struct wim_inode *d_inode = dentry->d_inode;

	if (d_inode->i_ino == 0) {
		/* A dentry with a hard link group ID of 0 indicates that it's
		 * in a hard link group by itself.  Add it to the list of extra
		 * inodes rather than inserting it into the hash lists. */
		list_add_tail(&d_inode->i_list, &table->extra_inodes);
	} else {
		size_t pos;
		struct wim_inode *inode;
		struct hlist_node *cur;

		/* Try adding this dentry to an existing inode */
		pos = d_inode->i_ino % table->capacity;
		hlist_for_each_entry(inode, cur, &table->array[pos], i_hlist) {
			if (inode->i_ino == d_inode->i_ino) {
				if (unlikely((inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) ||
					     (d_inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)))
				{
					ERROR("Unsupported directory hard link "
					      "\"%"TS"\" <=> \"%"TS"\"",
					      dentry_full_path(dentry),
					      dentry_full_path(inode_first_dentry(inode)));
					return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
				}
				inode_add_dentry(dentry, inode);
				return 0;
			}
		}

		/* No inode in the table has the same number as this one, so add
		 * it to the table. */
		hlist_add_head(&d_inode->i_hlist, &table->array[pos]);

		/* XXX Make the table grow when too many entries have been
		 * inserted. */
		table->num_entries++;
	}
	return 0;
}


/*
 * dentry_tree_fix_inodes():
 *
 * This function takes as input a tree of WIM dentries that initially has a
 * different inode associated with each dentry.  Sets of dentries that should
 * share the same inode (a.k.a. hard link groups) are built using the i_ino
 * field of each inode, then the link count and alias list for one inode in each
 * set is set correctly and the unnecessary struct wim_inode's freed.  The
 * effect is to correctly associate exactly one struct wim_inode with each
 * original inode, regardless of how many dentries are aliases for that inode.
 *
 * The special inode number of 0 indicates that the dentry is in a hard link
 * group by itself, and therefore has a 'struct wim_inode' with i_nlink=1 to
 * itself.
 *
 * This function also checks the dentries in each hard link group for
 * consistency.  In some WIMs, such as install.wim for some versions of Windows
 * 7, dentries can share the same hard link group ID but not actually be hard
 * linked to each other (based on conflicting information, such as file
 * contents).  This should be an error, but this case needs be handled.  So,
 * each "nominal" inode (the inode based on the inode numbers provided in the
 * WIM) is examined for consistency and may be split into multiple "true" inodes
 * that are maximally sized consistent sets of dentries.
 *
 * On success, the list of "true" inodes, linked by the i_hlist field,
 * is returned in the hlist @inode_list.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	WIMLIB_ERR_NOMEM
 */
int
dentry_tree_fix_inodes(struct wim_dentry *root, struct list_head *inode_list)
{
	struct wim_inode_table inode_tab;
	int ret;
	bool ino_changes_needed;
	struct wim_inode *inode;

	DEBUG("Inserting dentries into inode table");
	ret = init_inode_table(&inode_tab, 9001);
	if (ret)
		goto out;

	ret = for_dentry_in_tree(root, inode_table_insert, &inode_tab);
	if (ret)
		goto out_destroy_inode_table;

	DEBUG("Cleaning up the hard link groups");
	ino_changes_needed = false;
	ret = fix_inodes(&inode_tab, inode_list, &ino_changes_needed);
	if (ret)
		goto out_destroy_inode_table;

	if (ino_changes_needed) {
		u64 cur_ino = 1;

		WARNING("The WIM image contains invalid hard links.  Fixing.");

		list_for_each_entry(inode, inode_list, i_list) {
			if (inode->i_nlink > 1)
				inode->i_ino = cur_ino++;
			else
				inode->i_ino = 0;
		}
	}
	/* On success, all the inodes have been moved to the image inode list,
	 * so there's no need to delete from from the hash lists in the inode
	 * table before freeing the hash buckets array directly. */
	ret = 0;
	goto out_destroy_inode_table_raw;
out_destroy_inode_table:
	for (size_t i = 0; i < inode_tab.capacity; i++) {
		struct hlist_node *cur, *tmp;
		hlist_for_each_entry_safe(inode, cur, tmp, &inode_tab.array[i], i_hlist)
			hlist_del_init(&inode->i_hlist);
	}
	{
		struct wim_inode *tmp;
		list_for_each_entry_safe(inode, tmp, &inode_tab.extra_inodes, i_list)
			list_del_init(&inode->i_list);
	}
out_destroy_inode_table_raw:
	destroy_inode_table(&inode_tab);
out:
	return ret;
}
