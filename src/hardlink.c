/*
 * hardlink.c
 *
 * Code to deal with hard links in WIMs.
 */

/*
 * Copyright (C) 2012 Eric Biggers
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

#include "wimlib_internal.h"
#include "dentry.h"
#include "list.h"
#include "lookup_table.h"

/*                             NULL        NULL
 *                              ^           ^
 *         dentry               |           |
 *        /     \          -----------  -----------
 *        |      dentry<---|  struct  | |  struct  |---> dentry
 *        \     /          | wim_inode| | wim_inode|
 *         dentry          ------------ ------------
 *                              ^           ^
 *                              |           |
 *                              |           |                   dentry
 *                         -----------  -----------            /      \
 *               dentry<---|  struct  | |  struct  |---> dentry        dentry
 *              /          | wim_inode| | wim_inode|           \      /
 *         dentry          ------------ ------------            dentry
 *                              ^           ^
 *                              |           |
 *                            -----------------
 *    wim_inode_table->array  | idx 0 | idx 1 |
 *                            -----------------
 */

/* Hash table to find inodes, identified by their inode ID.
 * */
struct wim_inode_table {
	/* Fields for the hash table */
	struct hlist_head *array;
	u64 num_entries;
	u64 capacity;

	/*
	 * Linked list of "extra" inodes.  These may be:
	 *
	 * - inodes with link count 1, which are all allowed to have 0 for their
	 *   inode number, meaning we cannot insert them into the hash table
	 *   before calling assign_inode_numbers().
         *
	 * - Groups we create ourselves by splitting a nominal inode due to
	 *   inconsistencies in the dentries.  These inodes will share a inode
	 *   ID with some other inode until assign_inode_numbers() is called.
	 */
	struct hlist_head extra_inodes;
};

static inline void destroy_inode_table(struct wim_inode_table *table)
{
	FREE(table->array);
}

static int init_inode_table(struct wim_inode_table *table, size_t capacity)
{
	table->array = CALLOC(capacity, sizeof(table->array[0]));
	if (!table->array) {
		ERROR("Cannot initalize inode table: out of memory");
		return WIMLIB_ERR_NOMEM;
	}
	table->num_entries  = 0;
	table->capacity     = capacity;
	INIT_HLIST_HEAD(&table->extra_inodes);
	return 0;
}

static inline size_t inode_link_count(const struct wim_inode *inode)
{
	const struct list_head *cur;
	size_t size = 0;
	list_for_each(cur, &inode->i_dentry)
		size++;
	return size;
}

/* Insert a dentry into the inode table based on the inode number of the
 * attached inode (which came from the hard link group ID field of the on-disk
 * WIM dentry) */
static int inode_table_insert(struct wim_dentry *dentry, void *__table)
{
	struct wim_inode_table *table = __table;
	struct wim_inode *d_inode = dentry->d_inode;

	if (d_inode->i_ino == 0) {
		/* A dentry with a hard link group ID of 0 indicates that it's
		 * in a hard link group by itself.  Add it to the list of extra
		 * inodes rather than inserting it into the hash lists. */
		hlist_add_head(&d_inode->i_hlist, &table->extra_inodes);

		wimlib_assert(d_inode->i_dentry.next == &dentry->d_alias);
		wimlib_assert(d_inode->i_dentry.prev == &dentry->d_alias);
		wimlib_assert(d_inode->i_nlink == 1);
	} else {
		size_t pos;
		struct wim_inode *inode;
		struct hlist_node *cur;

		/* Try adding this dentry to an existing inode */
		pos = d_inode->i_ino % table->capacity;
		hlist_for_each_entry(inode, cur, &table->array[pos], i_hlist) {
			if (inode->i_ino == d_inode->i_ino) {
				inode_add_dentry(dentry, inode);
				inode->i_nlink++;
				return 0;
			}
		}

		/* No inode in the table has the same number as this one, so add
		 * it to the table. */
		hlist_add_head(&d_inode->i_hlist, &table->array[pos]);

		wimlib_assert(d_inode->i_dentry.next == &dentry->d_alias);
		wimlib_assert(d_inode->i_dentry.prev == &dentry->d_alias);
		wimlib_assert(d_inode->i_nlink == 1);

		/* XXX Make the table grow when too many entries have been
		 * inserted. */
		table->num_entries++;
	}
	return 0;
}

static void print_inode_dentries(const struct wim_inode *inode)
{
	struct wim_dentry *dentry;
	inode_for_each_dentry(dentry, inode)
		printf("`%s'\n", dentry->full_path_utf8);
}

static void inconsistent_inode(const struct wim_inode *inode)
{
	ERROR("An inconsistent hard link group that cannot be corrected has "
	      "been detected");
	ERROR("The dentries are located at the following paths:");
#ifdef ENABLE_ERROR_MESSAGES
	print_inode_dentries(inode);
#endif
}

static bool ref_inodes_consistent(const struct wim_inode * restrict ref_inode_1,
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

static bool inodes_consistent(const struct wim_inode * restrict ref_inode,
			      const struct wim_inode * restrict inode)
{
	wimlib_assert(ref_inode != inode);

	if (ref_inode->i_num_ads != inode->i_num_ads &&
	    inode->i_num_ads != 0)
		return false;
	if (ref_inode->i_security_id != inode->i_security_id
	    || ref_inode->i_attributes != inode->i_attributes)
		return false;
	for (unsigned i = 0; i <= min(ref_inode->i_num_ads, inode->i_num_ads); i++) {
		const u8 *ref_hash, *hash;
		ref_hash = inode_stream_hash(ref_inode, i);
		hash = inode_stream_hash(inode, i);
		if (!hashes_equal(ref_hash, hash) && !is_zero_hash(hash))
			return false;
		if (i && !ads_entries_have_same_name(&ref_inode->i_ads_entries[i - 1],
						     &inode->i_ads_entries[i - 1]))
			return false;
	}
	return true;
}

/* Fix up a "true" inode and check for inconsistencies */
static int fix_true_inode(struct wim_inode *inode, struct hlist_head *inode_list)
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
	ref_inode->i_nlink = 1;
	hlist_add_head(&ref_inode->i_hlist, inode_list);

	list_del(&inode->i_dentry);
	list_add(&ref_inode->i_dentry, &ref_dentry->d_alias);

	inode_for_each_dentry(dentry, ref_inode) {
		if (dentry != ref_dentry) {
			if (!inodes_consistent(ref_inode, dentry->d_inode)) {
				inconsistent_inode(ref_inode);
				return WIMLIB_ERR_INVALID_DENTRY;
			}
			/* Free the unneeded `struct wim_inode'. */
			dentry->d_inode->i_hlist.next = NULL;
			dentry->d_inode->i_hlist.pprev = NULL;
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
static int fix_nominal_inode(struct wim_inode *inode,
			     struct hlist_head *inode_list)
{
	struct wim_dentry *dentry;
	struct hlist_node *cur, *tmp;
	int ret;
	size_t num_true_inodes;

	wimlib_assert(inode->i_nlink == inode_link_count(inode));

	LIST_HEAD(dentries_with_data_streams);
	LIST_HEAD(dentries_with_no_data_streams);
	HLIST_HEAD(true_inodes);

        /* Create a list of dentries in the nominal inode that have at
         * least one data stream with a non-zero hash, and another list that
         * contains the dentries that have a zero hash for all data streams. */
	inode_for_each_dentry(dentry, inode) {
		for (unsigned i = 0; i <= dentry->d_inode->i_num_ads; i++) {
			const u8 *hash;
			hash = inode_stream_hash(dentry->d_inode, i);
			if (!is_zero_hash(hash)) {
				list_add(&dentry->tmp_list,
					 &dentries_with_data_streams);
				goto next_dentry;
			}
		}
		list_add(&dentry->tmp_list,
			 &dentries_with_no_data_streams);
	next_dentry:
		;
	}

	/* If there are no dentries with data streams, we require the nominal
	 * inode to be a true inode */
	if (list_empty(&dentries_with_data_streams)) {
	#ifdef ENABLE_DEBUG
		if (inode->i_nlink > 1) {
			DEBUG("Found link group of size %u without "
			      "any data streams:", inode->i_nlink);
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
			ERROR("Hard inode ambiguity detected!");
			ERROR("We split up inode 0x%"PRIx64" due to "
			      "inconsistencies,", inode->i_ino);
			ERROR("but dentries with no stream information remained. "
			      "We don't know which inode");
			ERROR("to assign them to.");
			return WIMLIB_ERR_INVALID_DENTRY;
		}
		inode = container_of(true_inodes.first, struct wim_inode, i_hlist);
		/* Assign the streamless dentries to the one and only true
		 * inode. */
		list_for_each_entry(dentry, &dentries_with_no_data_streams, tmp_list)
			inode_add_dentry(dentry, inode);
	}
	#ifdef ENABLE_DEBUG
        if (num_true_inodes != 1) {
		inode = container_of(true_inodes.first, struct wim_inode, i_hlist);

		printf("Split nominal inode 0x%"PRIx64" into %zu "
		       "inodes:\n",
		       inode->i_ino, num_true_inodes);
		puts("------------------------------------------------------------------------------");
		size_t i = 1;
		hlist_for_each_entry(inode, cur, &true_inodes, i_hlist) {
			printf("[Split inode %zu]\n", i++);
			print_inode_dentries(inode);
			putchar('\n');
		}
		puts("------------------------------------------------------------------------------");
        }
	#endif

	hlist_for_each_entry_safe(inode, cur, tmp, &true_inodes, i_hlist) {
		ret = fix_true_inode(inode, inode_list);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static int fix_inodes(struct wim_inode_table *table,
		      struct hlist_head *inode_list)
{
	struct wim_inode *inode;
	struct hlist_node *cur, *tmp;
	int ret;
	INIT_HLIST_HEAD(inode_list);
	for (u64 i = 0; i < table->capacity; i++) {
		hlist_for_each_entry_safe(inode, cur, tmp, &table->array[i], i_hlist) {
			ret = fix_nominal_inode(inode, inode_list);
			if (ret != 0)
				return ret;
		}
	}
	hlist_for_each_safe(cur, tmp, &table->extra_inodes)
		hlist_add_head(cur, inode_list);
	return 0;
}

/*
 * dentry_tree_fix_inodes():
 *
 * This function takes as input a tree of WIM dentries that has a different
 * inode associated with every dentry.  Sets of dentries that share the same
 * inode (a.k.a. hard link groups) are built using the i_ino field of each
 * inode, then the link count and alias list for one inode in each set is set
 * correctly and the unnecessary struct wim_inode's freed.  The effect is to
 * correctly associate exactly one struct wim_inode with each original inode,
 * regardless of how many dentries are aliases for that inode.
 *
 * The special inode number of 0 indicates that the dentry is in a hard link
 * group by itself, and therefore has a 'struct wim_inode' with i_nlink=1 to
 * itself.
 *
 * This function also checks the dentries in each hard link group for
 * consistency.  In some WIMs, such as install.wim for some versions of Windows
 * 7, dentries can share the same hard link group ID but not actually be hard
 * linked to each other (e.g. to having different data streams).  This should be
 * an error, but this case needs be handled.  So, each "nominal" inode (the
 * inode based on the inode numbers provided in the WIM) is examined for
 * consistency and may be split into multiple "true" inodes that are maximally
 * sized consistent sets of dentries.
 *
 * Return 0 on success; WIMLIB_ERR_NOMEM or WIMLIB_ERR_INVALID_DENTRY on
 * failure.  On success, the list of "true" inodes, linked by the i_hlist field,
 * is returned in the hlist @inode_list.
 */
int dentry_tree_fix_inodes(struct wim_dentry *root, struct hlist_head *inode_list)
{
	struct wim_inode_table inode_tab;
	int ret;

	DEBUG("Inserting dentries into inode table");
	ret = init_inode_table(&inode_tab, 9001);
	if (ret != 0)
		return ret;

	for_dentry_in_tree(root, inode_table_insert, &inode_tab);

	DEBUG("Cleaning up the hard link groups");
	ret = fix_inodes(&inode_tab, inode_list);
	destroy_inode_table(&inode_tab);
	return ret;
}

/* Assign inode numbers to a list of inode, and return the next available
 * number. */
u64 assign_inode_numbers(struct hlist_head *inode_list)
{
	DEBUG("Assigning inode numbers");
	struct wim_inode *inode;
	struct hlist_node *cur;
	u64 cur_ino = 1;
	hlist_for_each_entry(inode, cur, inode_list, i_hlist) {
		inode->i_ino = cur_ino;
		cur_ino++;
	}
	return cur_ino;
}
