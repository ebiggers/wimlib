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

/* Hash table to find inodes, identified by their inode ID.
 * */
struct inode_table {
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

/* Returns pointer to a new inode table having the specified capacity */
struct inode_table *new_inode_table(size_t capacity)
{
	struct inode_table *table;
	struct hlist_head *array;

	table = MALLOC(sizeof(struct inode_table));
	if (!table)
		goto err;
	array = CALLOC(capacity, sizeof(array[0]));
	if (!array) {
		FREE(table);
		goto err;
	}
	table->num_entries  = 0;
	table->capacity     = capacity;
	table->array        = array;
	INIT_HLIST_HEAD(&table->extra_inodes);
	return table;
err:
	ERROR("Failed to allocate memory for inode table with capacity %zu",
	      capacity);
	return NULL;
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
	size_t pos;
	struct inode *inode;
	struct inode *d_inode = dentry->inode;

	if (d_inode->ino == 0) {

		/* Single inode--- Add to the list of extra inodes (we can't put
		 * it in the table itself because all the singles have a link
		 * inode ID of 0) */
		list_add(&dentry->inode_dentry_list, &d_inode->dentry_list);
		hlist_add_head(&d_inode->hlist, &table->extra_inodes);
	} else {
                /* Hard inode that may contain multiple dentries (the code
                 * will work even if the inode actually contains only 1 dentry
                 * though) */
		struct hlist_node *cur;

		/* Try adding to existing inode */
		pos = d_inode->ino % table->capacity;
		hlist_for_each_entry(inode, cur, &table->array[pos], hlist) {
			if (inode->ino == d_inode->ino) {
				list_add(&dentry->inode_dentry_list,
					 &inode->dentry_list);
			}
		}

		/* Add new inode to the table */
		list_add(&dentry->inode_dentry_list, &d_inode->dentry_list);
		hlist_add_head(&d_inode->hlist, &table->array[pos]);

		/* XXX Make the table grow when too many entries have been
		 * inserted. */
		table->num_entries++;
	}
	return 0;
}

/* Frees a inode table. */
void free_inode_table(struct inode_table *table)
{
	if (table) {
		FREE(table->array);
                FREE(table);
        }
}

static u64
assign_inos_to_list(struct hlist_head *head, u64 cur_ino)
{
	struct inode *inode;
	struct hlist_node *cur;
	struct dentry *dentry;
	hlist_for_each_entry(inode, cur, head, hlist) {
	}
	return cur_ino;
}

/* Assign the inode numbers to dentries in a inode table, and return the
 * next available inode ID. */
u64 assign_inode_numbers(struct hlist_head *inode_list)
{
	struct inode *inode;
	struct hlist_node *cur;
	u64 cur_ino = 1;
	struct dentry *dentry;
	hlist_for_each_entry(inode, cur, inode_list, hlist) {
		list_for_each_entry(dentry, &inode->dentry_list, inode_dentry_list)
			dentry->link_group_id = cur_ino;
		inode->ino = cur_ino;
		cur_ino++;
	}
	return cur_ino;
}


static void
print_inode_dentries(const struct inode *inode)
{
	struct dentry *dentry;
	list_for_each_entry(dentry, &inode->dentry_list, inode_dentry_list)
		printf("`%s'\n", dentry->full_path_utf8);
}

static void inconsistent_inode(const struct inode *inode)
{
	ERROR("An inconsistent hard link group that we cannot correct has been "
	      "detected");
	ERROR("The dentries are located at the following paths:");
	print_inode_dentries(inode);
}

static bool ref_dentries_consistent(const struct dentry * restrict ref_dentry_1,
				    const struct dentry * restrict ref_dentry_2)
{
	wimlib_assert(ref_dentry_1 != ref_dentry_2);

	if (ref_dentry_1->inode->num_ads != ref_dentry_2->inode->num_ads)
		return false;
	if (ref_dentry_1->inode->security_id != ref_dentry_2->inode->security_id
	    || ref_dentry_1->inode->attributes != ref_dentry_2->inode->attributes)
		return false;
	for (unsigned i = 0; i <= ref_dentry_1->inode->num_ads; i++) {
		const u8 *ref_1_hash, *ref_2_hash;
		ref_1_hash = inode_stream_hash(ref_dentry_1->inode, i);
		ref_2_hash = inode_stream_hash(ref_dentry_2->inode, i);
		if (!hashes_equal(ref_1_hash, ref_2_hash))
			return false;
		if (i && !ads_entries_have_same_name(ref_dentry_1->inode->ads_entries[i - 1],
						     ref_dentry_2->inode->ads_entries[i - 1]))
			return false;

	}
	return true;
}

static bool dentries_consistent(const struct dentry * restrict ref_dentry,
				const struct dentry * restrict dentry)
{
	wimlib_assert(ref_dentry != dentry);

	if (ref_dentry->inode->num_ads != dentry->inode->num_ads &&
	    dentry->inode->num_ads != 0)
		return false;
	if (ref_dentry->inode->security_id != dentry->inode->security_id
	    || ref_dentry->inode->attributes != dentry->inode->attributes)
		return false;
	for (unsigned i = 0; i <= min(ref_dentry->inode->num_ads, dentry->inode->num_ads); i++) {
		const u8 *ref_hash, *hash;
		ref_hash = inode_stream_hash(ref_dentry->inode, i);
		hash = inode_stream_hash(dentry->inode, i);
		if (!hashes_equal(ref_hash, hash) && !is_zero_hash(hash))
			return false;
		if (i && !ads_entries_have_same_name(ref_dentry->inode->ads_entries[i - 1],
						     dentry->inode->ads_entries[i - 1]))
			return false;
	}
	return true;
}

#ifdef ENABLE_DEBUG
static void
print_dentry_list(const struct dentry *first_dentry)
{
	const struct dentry *dentry = first_dentry;
	do {
		printf("`%s'\n", dentry->full_path_utf8);
	} while ((dentry = container_of(dentry->inode_dentry_list.next,
					struct dentry,
					inode_dentry_list)) != first_dentry);
}

#endif

static size_t inode_link_count(const struct inode *inode)
{
	const struct list_head *cur;
	size_t size = 0;
	list_for_each(cur, &inode->dentry_list)
		size++;
	return size;
}

static struct dentry *inode_first_dentry(struct inode *inode)
{
	return container_of(inode->dentry_list.next, struct dentry,
		 	    inode_dentry_list);
}

/* Fix up a "true" inode and check for inconsistencies */
static int fix_true_inode(struct inode *inode)
{
	struct dentry *dentry;
	struct dentry *ref_dentry = NULL;
	u64 last_ctime = 0;
	u64 last_mtime = 0;
	u64 last_atime = 0;
	bool found_short_name = false;

	list_for_each_entry(dentry, &inode->dentry_list, inode_dentry_list) {
		if (!ref_dentry || ref_dentry->inode->num_ads == 0)
			ref_dentry = dentry;
		if (dentry->short_name_len) {
			if (found_short_name) {
				ERROR("Multiple short names in hard link "
				      "group!");
				inconsistent_inode(inode);
				return WIMLIB_ERR_INVALID_DENTRY;
			} else {
				found_short_name = true;
			}
		}
		if (dentry->inode->creation_time > last_ctime)
			last_ctime = dentry->inode->creation_time;
		if (dentry->inode->last_write_time > last_mtime)
			last_mtime = dentry->inode->last_write_time;
		if (dentry->inode->last_access_time > last_atime)
			last_atime = dentry->inode->last_access_time;
	}

	list_for_each_entry(dentry, &inode->dentry_list, inode_dentry_list) {
		if (dentry != ref_dentry) {
			if (!dentries_consistent(ref_dentry, dentry)) {
				inconsistent_inode(inode);
				return WIMLIB_ERR_INVALID_DENTRY;
			}
			/* Free the unneeded `struct inode'. */
			free_inode(dentry->inode);
			dentry->inode = ref_dentry->inode;
			ref_dentry->inode->link_count++;
		}
	}
	ref_dentry->inode->creation_time = last_ctime;
	ref_dentry->inode->last_write_time = last_mtime;
	ref_dentry->inode->last_access_time = last_atime;
	wimlib_assert(inode_link_count(inode) == inode->link_count);
	return 0;
}

/* 
 * Fixes up a nominal inode.
 *
 * By a nominal inode we mean a group of two or more dentries that share
 * the same hard link group ID.
 *
 * If dentries in the inode are found to be inconsistent, we may split the inode
 * into several "true" inodes.  @new_inodes points to a linked list of
 * these split inodes, and if we create any, they will be added to this list.
 *
 * After splitting up each nominal inode into the "true" inodes we
 * will canonicalize the link group by getting rid of all the superfluous
 * `struct inodes'.  There will be just one `struct inode' for each hard link
 * group remaining.
 */
static int
fix_nominal_inode(struct inode *inode, struct hlist_head *inode_list)
{
	struct dentry *tmp, *dentry, *ref_dentry;
	struct hlist_node *cur;
	int ret;
	size_t num_true_inodes;

	LIST_HEAD(dentries_with_data_streams);
	LIST_HEAD(dentries_with_no_data_streams);
	HLIST_HEAD(true_inodes);

        /* Create a list of dentries in the nominal inode that have at
         * least one data stream with a non-zero hash, and another list that
         * contains the dentries that have a zero hash for all data streams. */
	list_for_each_entry(dentry, &inode->dentry_list, inode_dentry_list) {
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
		{
			if (inode->link_count > 1) {
				DEBUG("Found link group of size %zu without "
				      "any data streams:", inode->link_count);
				print_inode_dentries(inode);
				DEBUG("We are going to interpret it as true "
				      "link group, provided that the dentries "
				      "are consistent.");
			}
		}
	#endif
		hlist_add_head(&inode->hlist, inode_list);
		return fix_true_inode(inode);
	}

        /* One or more dentries had data streams specified.  We check each of
         * these dentries for consistency with the others to form a set of true
         * inodes. */
	num_true_inodes = 0;
	list_for_each_entry(dentry, &dentries_with_data_streams, tmp_list)
	{
		/* Look for a true inode that is consistent with
		 * this dentry and add this dentry to it.  Or, if none
		 * of the true inodes are consistent with this
		 * dentry, make a new one. */
		hlist_for_each_entry(inode, cur, &true_inodes, hlist) {
			if (ref_dentries_consistent(inode_first_dentry(inode), dentry)) {
				list_add(&dentry->inode_dentry_list,
					 &inode->dentry_list);
				goto next_dentry_2;
			}
		}
		num_true_inodes++;
		hlist_add_head(&dentry->inode->hlist, &true_inodes);
		INIT_LIST_HEAD(&dentry->inode->dentry_list);
		list_add(&dentry->inode_dentry_list, &dentry->inode->dentry_list);
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
			      "We don't know which true hard link");
			ERROR("inode to assign them to.");
			return WIMLIB_ERR_INVALID_DENTRY;
		}
		/* Assign the streamless dentries to the one and only true link
		 * inode. */
		ref_dentry = inode_first_dentry(inode);
		list_for_each_entry(dentry, &dentries_with_no_data_streams, tmp_list)
			list_add(&dentry->inode_dentry_list, &inode->dentry_list);
	}
        if (num_true_inodes != 1) {
		#ifdef ENABLE_DEBUG
		{
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
        }

	hlist_for_each_entry(inode, cur, &true_inodes, hlist) {
		hlist_add_head(&inode->hlist, inode_list);
		ret = fix_true_inode(inode);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/*
 * Goes through each inode and shares the inodes among members of a hard
 * inode.
 *
 * In the process, the dentries in each inode are checked for consistency.
 * If they contain data features that indicate they cannot really be in the same
 * inode, this should be an error, but in reality this case needs to
 * be handled, so we split the dentries into different inodes.
 */
int fix_inodes(struct inode_table *table, struct hlist_head *inode_list)
{
	struct inode *inode;
	struct hlist_node *cur, *tmp;
	int ret = 0;
	INIT_HLIST_HEAD(inode_list);
	for (u64 i = 0; i < table->capacity; i++) {
		hlist_for_each_entry_safe(inode, cur, tmp, &table->array[i], hlist) {
			ret = fix_nominal_inode(inode, inode_list);
			if (ret != 0)
				break;
		}
	}
	return ret;
}
