/*
 * hardlink.c
 *
 * Code to deal with hard links in WIMs.  Essentially, the WIM dentries are put
 * into a hash table indexed by the inode ID field, then for each hard
 * inode, a linked list is made to connect the dentries.
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
 *        \     /          |inode| |inode|       
 *         dentry          ------------ ------------
 *                              ^           ^
 *                              |           |
 *                              |           |                   dentry
 *                         -----------  -----------            /      \
 *               dentry<---|  struct  | |  struct  |---> dentry        dentry
 *              /          |inode| |inode|           \      /
 *         dentry          ------------ ------------            dentry
 *                              ^           ^
 *                              |           |
 *                            -----------------
 *    inode_table->array | idx 0 | idx 1 | 
 *                            -----------------
 */


int init_inode_table(struct inode_table *table, size_t capacity)
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


static size_t inode_link_count(const struct inode *inode)
{
	const struct list_head *cur;
	size_t size = 0;
	list_for_each(cur, &inode->dentry_list)
		size++;
	return size;
}

/* 
 * Insert a dentry into the inode table based on its inode
 * ID.
 *
 * If there is already a dentry in the table having the same inode ID,
 * and the inode ID is not 0, the dentry is added to the circular
 * linked list for that inode.
 *
 * If the inode ID is 0, this indicates a dentry that's in a hard link
 * inode by itself (has a link count of 1).  We can't insert it into the hash
 * table itself because we don't know what inode numbers are available to
 * give it (this could be kept track of but would be more difficult).  Instead
 * we keep a linked list of the single dentries, and assign them inode
 * numbers later.
 */
int inode_table_insert(struct dentry *dentry, void *__table)
{
	struct inode_table *table = __table;
	struct inode *d_inode = dentry->inode;

	if (d_inode->ino == 0) {
		/* Single inode--- Add to the list of extra inodes (we can't put
		 * it in the table itself because all the singles have a link
		 * inode ID of 0) */
		hlist_add_head(&d_inode->hlist, &table->extra_inodes);

		wimlib_assert(d_inode->dentry_list.next == &dentry->inode_dentry_list);
		wimlib_assert(d_inode->dentry_list.prev == &dentry->inode_dentry_list);
		wimlib_assert(d_inode->link_count == 1);
	} else {
		/* Inode that may have multiple corresponding dentries (the code
		 * will work even if the inode actually contains only 1 dentry
		 * though) */

		size_t pos;
		struct inode *inode;
		struct hlist_node *cur;

		/* Try adding to existing inode */
		pos = d_inode->ino % table->capacity;
		hlist_for_each_entry(inode, cur, &table->array[pos], hlist) {
			if (inode->ino == d_inode->ino) {
				inode_add_dentry(dentry, inode);
				inode->link_count++;
				return 0;
			}
		}

		/* Add new inode to the table */
		hlist_add_head(&d_inode->hlist, &table->array[pos]);

		wimlib_assert(d_inode->dentry_list.next == &dentry->inode_dentry_list);
		wimlib_assert(d_inode->dentry_list.prev == &dentry->inode_dentry_list);
		wimlib_assert(d_inode->link_count == 1);

		/* XXX Make the table grow when too many entries have been
		 * inserted. */
		table->num_entries++;
	}
	return 0;
}

/* Assign the inode numbers to dentries in a inode table, and return the
 * next available inode ID. */
u64 assign_inode_numbers(struct hlist_head *inode_list)
{
	DEBUG("Assigning inode numbers");
	struct inode *inode;
	struct hlist_node *cur;
	u64 cur_ino = 1;
	hlist_for_each_entry(inode, cur, inode_list, hlist) {
		inode->ino = cur_ino;
		cur_ino++;
	}
	return cur_ino;
}


static void print_inode_dentries(const struct inode *inode)
{
	struct dentry *dentry;
	inode_for_each_dentry(dentry, inode)
		printf("`%s'\n", dentry->full_path_utf8);
}

static void inconsistent_inode(const struct inode *inode)
{
	ERROR("An inconsistent hard link group that we cannot correct has been "
	      "detected");
	ERROR("The dentries are located at the following paths:");
	print_inode_dentries(inode);
}

static bool ref_inodes_consistent(const struct inode * restrict ref_inode_1,
				  const struct inode * restrict ref_inode_2)
{
	wimlib_assert(ref_inode_1 != ref_inode_2);

	if (ref_inode_1->num_ads != ref_inode_2->num_ads)
		return false;
	if (ref_inode_1->security_id != ref_inode_2->security_id
	    || ref_inode_1->attributes != ref_inode_2->attributes)
		return false;
	for (unsigned i = 0; i <= ref_inode_1->num_ads; i++) {
		const u8 *ref_1_hash, *ref_2_hash;
		ref_1_hash = inode_stream_hash(ref_inode_1, i);
		ref_2_hash = inode_stream_hash(ref_inode_2, i);
		if (!hashes_equal(ref_1_hash, ref_2_hash))
			return false;
		if (i && !ads_entries_have_same_name(&ref_inode_1->ads_entries[i - 1],
						     &ref_inode_2->ads_entries[i - 1]))
			return false;

	}
	return true;
}

static bool inodes_consistent(const struct inode * restrict ref_inode,
			      const struct inode * restrict inode)
{
	wimlib_assert(ref_inode != inode);

	if (ref_inode->num_ads != inode->num_ads &&
	    inode->num_ads != 0)
		return false;
	if (ref_inode->security_id != inode->security_id
	    || ref_inode->attributes != inode->attributes)
		return false;
	for (unsigned i = 0; i <= min(ref_inode->num_ads, inode->num_ads); i++) {
		const u8 *ref_hash, *hash;
		ref_hash = inode_stream_hash(ref_inode, i);
		hash = inode_stream_hash(inode, i);
		if (!hashes_equal(ref_hash, hash) && !is_zero_hash(hash))
			return false;
		if (i && !ads_entries_have_same_name(&ref_inode->ads_entries[i - 1],
						     &inode->ads_entries[i - 1]))
			return false;
	}
	return true;
}

/* Fix up a "true" inode and check for inconsistencies */
static int fix_true_inode(struct inode *inode)
{
	struct dentry *dentry;
	struct dentry *ref_dentry = NULL;
	struct inode *ref_inode;
	u64 last_ctime = 0;
	u64 last_mtime = 0;
	u64 last_atime = 0;

	inode_for_each_dentry(dentry, inode) {
		if (!ref_dentry || dentry->inode->num_ads > ref_dentry->inode->num_ads)
			ref_dentry = dentry;
		if (dentry->inode->creation_time > last_ctime)
			last_ctime = dentry->inode->creation_time;
		if (dentry->inode->last_write_time > last_mtime)
			last_mtime = dentry->inode->last_write_time;
		if (dentry->inode->last_access_time > last_atime)
			last_atime = dentry->inode->last_access_time;
	}

	ref_inode = ref_dentry->inode;
	ref_inode->link_count = 1;

	list_del(&inode->dentry_list);
	list_add(&ref_inode->dentry_list, &ref_dentry->inode_dentry_list);

	inode_for_each_dentry(dentry, ref_inode) {
		if (dentry != ref_dentry) {
			if (!inodes_consistent(ref_inode, dentry->inode)) {
				inconsistent_inode(ref_inode);
				return WIMLIB_ERR_INVALID_DENTRY;
			}
			/* Free the unneeded `struct inode'. */
			free_inode(dentry->inode);
			dentry->inode = ref_inode;
			ref_inode->link_count++;
		}
	}
	ref_inode->creation_time = last_ctime;
	ref_inode->last_write_time = last_mtime;
	ref_inode->last_access_time = last_atime;
	wimlib_assert(inode_link_count(ref_inode) == ref_inode->link_count);
	return 0;
}

/* 
 * Fixes up a nominal inode.
 *
 * By a nominal inode we mean a group of two or more dentries that share
 * the same hard link group ID.
 *
 * If dentries in the inode are found to be inconsistent, we may split the inode
 * into several "true" inodes.
 *
 * After splitting up each nominal inode into the "true" inodes we will
 * canonicalize the link group by getting rid of all the unnecessary `struct
 * inodes'.  There will be just one `struct inode' for each hard link group
 * remaining.
 */
static int
fix_nominal_inode(struct inode *inode, struct hlist_head *inode_list)
{
	struct dentry *dentry, *ref_dentry;
	struct hlist_node *cur, *tmp;
	int ret;
	size_t num_true_inodes;

	wimlib_assert(inode->link_count == inode_link_count(inode));

	LIST_HEAD(dentries_with_data_streams);
	LIST_HEAD(dentries_with_no_data_streams);
	HLIST_HEAD(true_inodes);

        /* Create a list of dentries in the nominal inode that have at
         * least one data stream with a non-zero hash, and another list that
         * contains the dentries that have a zero hash for all data streams. */
	inode_for_each_dentry(dentry, inode) {
		for (unsigned i = 0; i <= dentry->inode->num_ads; i++) {
			const u8 *hash;
			hash = inode_stream_hash(dentry->inode, i);
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
		if (inode->link_count > 1) {
			DEBUG("Found link group of size %zu without "
			      "any data streams:", inode->link_count);
			print_inode_dentries(inode);
			DEBUG("We are going to interpret it as true "
			      "link group, provided that the dentries "
			      "are consistent.");
		}
	#endif
		hlist_add_head(&inode->hlist, inode_list);
		return fix_true_inode(inode);
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
		hlist_for_each_entry(inode, cur, &true_inodes, hlist) {
			if (ref_inodes_consistent(inode, dentry->inode)) {
				inode_add_dentry(dentry, inode);
				goto next_dentry_2;
			}
		}
		num_true_inodes++;
		INIT_LIST_HEAD(&dentry->inode->dentry_list);
		inode_add_dentry(dentry, dentry->inode);
		hlist_add_head(&dentry->inode->hlist, &true_inodes);
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
			      "inconsistencies,", inode->ino);
			ERROR("but dentries with no stream information remained. "
			      "We don't know which inode");
			ERROR("to assign them to.");
			return WIMLIB_ERR_INVALID_DENTRY;
		}
		inode = container_of(true_inodes.first, struct inode, hlist);
		/* Assign the streamless dentries to the one and only true
		 * inode. */
		list_for_each_entry(dentry, &dentries_with_no_data_streams, tmp_list)
			inode_add_dentry(dentry, inode);
	}
	#ifdef ENABLE_DEBUG
        if (num_true_inodes != 1) {
		inode = container_of(true_inodes.first, struct inode, hlist);

		printf("Split nominal inode 0x%"PRIx64" into %zu "
		       "inodes:\n",
		       inode->ino, num_true_inodes);
		puts("------------------------------------------------------------------------------");
		size_t i = 1;
		hlist_for_each_entry(inode, cur, &true_inodes, hlist) {
			printf("[Split inode %zu]\n", i++);
			print_inode_dentries(inode);
			putchar('\n');
		}
		puts("------------------------------------------------------------------------------");
        }
	#endif

	hlist_for_each_entry_safe(inode, cur, tmp, &true_inodes, hlist) {
		hlist_add_head(&inode->hlist, inode_list);
		ret = fix_true_inode(inode);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/*
 * Goes through each hard link group (dentries sharing the same hard link group
 * ID field) that's been inserted into the inode table and shares the `struct
 * inode's among members of each hard link group.
 *
 * In the process, the dentries belonging to each inode are checked for
 * consistency.  If they contain data features that indicate they cannot really
 * correspond to the same inode, this should be an error, but in reality this
 * case needs to be handled, so we split the dentries into different inodes.
 *
 * After this function returns, the inodes are no longer in the inode table, and
 * the inode table should be destroyed.  A list of the inodes, including all
 * split inodes as well as the inodes that were good before, is returned in the
 * list @inode_list.
 */
int fix_inodes(struct inode_table *table, struct hlist_head *inode_list)
{
	struct inode *inode;
	struct hlist_node *cur, *tmp;
	int ret;
	INIT_HLIST_HEAD(inode_list);
	for (u64 i = 0; i < table->capacity; i++) {
		hlist_for_each_entry_safe(inode, cur, tmp, &table->array[i], hlist) {
			ret = fix_nominal_inode(inode, inode_list);
			if (ret != 0)
				return ret;
		}
	}
	hlist_for_each_safe(cur, tmp, &table->extra_inodes)
		hlist_add_head(cur, inode_list);
	return 0;
}
