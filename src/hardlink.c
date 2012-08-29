/*
 * hardlink.c
 *
 * Code to deal with hard links in WIMs.  Essentially, the WIM dentries are put
 * into a hash table indexed by the hard link group ID field, then for each hard
 * link group, a linked list is made to connect the dentries.
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
#include "dentry.h"
#include "list.h"
#include "lookup_table.h"

/*                             NULL        NULL
 *                              ^           ^
 *         dentry               |           |                
 *        /     \          -----------  -----------           
 *        |      dentry<---|  struct  | |  struct  |---> dentry
 *        \     /          |link_group| |link_group|       
 *         dentry          ------------ ------------
 *                              ^           ^
 *                              |           |
 *                              |           |                   dentry
 *                         -----------  -----------            /      \
 *               dentry<---|  struct  | |  struct  |---> dentry        dentry
 *              /          |link_group| |link_group|           \      /
 *         dentry          ------------ ------------            dentry
 *                              ^           ^
 *                              |           |
 *                            -----------------
 *    link_group_table->array | idx 0 | idx 1 | 
 *                            -----------------
 */

/* Hard link group; it's identified by its hard link group ID and points to a
 * circularly linked list of dentries. */
struct link_group {
	u64 link_group_id;

	/* Pointer to use to make a singly-linked list of link groups. */
	struct link_group *next;

	/* This is a pointer to the circle and not part of the circle itself.
	 * This makes it easy to iterate through other dentries hard-linked to a
	 * given dentry without having to find the "head" of the list first. */
	struct list_head *dentry_list;
};

/* Hash table to find hard link groups, identified by their hard link group ID.
 * */
struct link_group_table {
	/* Fields for the hash table */
	struct link_group **array;
	u64 num_entries;
	u64 capacity;

	/* 
	 * Linked list of "extra" groups.  These may be:
	 *
	 * - Hard link groups of size 1, which are all allowed to have 0 for
	 *   their hard link group ID, meaning we cannot insert them into the
	 *   hash table before calling assign_link_group_ids().
         *
         * - Groups we create ourselves by splitting a nominal hard link group
         *   due to inconsistencies in the dentries.  These groups will share a
         *   hard link group ID with some other group until
         *   assign_link_group_ids() is called.
	 */
	struct link_group *extra_groups;
};

/* Returns pointer to a new link group table having the specified capacity */
struct link_group_table *new_link_group_table(size_t capacity)
{
	struct link_group_table *table;
	struct link_group **array;

	table = MALLOC(sizeof(struct link_group_table));
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
	table->extra_groups = NULL;
	return table;
err:
	ERROR("Failed to allocate memory for link group table with capacity %zu",
	      capacity);
	return NULL;
}

/* 
 * Insert a dentry into the hard link group table based on its hard link group
 * ID.
 *
 * If there is already a dentry in the table having the same hard link group ID,
 * and the hard link group ID is not 0, the dentry is added to the circular
 * linked list for that hard link group.
 *
 * If the hard link group ID is 0, this indicates a dentry that's in a hard link
 * group by itself (has a link count of 1).  We can't insert it into the hash
 * table itself because we don't know what hard link group IDs are available to
 * give it (this could be kept track of but would be more difficult).  Instead
 * we keep a linked list of the single dentries, and assign them hard link group
 * IDs later.
 */
int link_group_table_insert(struct dentry *dentry, void *__table)
{
	struct link_group_table *table = __table;
	size_t pos;
	struct link_group *group;

	if (dentry->link_group_id == 0) {
		/* Single group--- Add to the list of extra groups (we can't put
		 * it in the table itself because all the singles have a link
		 * group ID of 0) */
		group = MALLOC(sizeof(struct link_group));
		if (!group)
			return WIMLIB_ERR_NOMEM;
		group->link_group_id = 0;
		group->next          = table->extra_groups;
		table->extra_groups  = group;
		INIT_LIST_HEAD(&dentry->link_group_list);
		group->dentry_list = &dentry->link_group_list;
	} else {
                /* Hard link group that may contain multiple dentries (the code
                 * will work even if the group actually contains only 1 dentry
                 * though) */

		/* Try adding to existing hard link group */
		pos = dentry->link_group_id % table->capacity;
		group = table->array[pos];
		while (group) {
			if (group->link_group_id == dentry->link_group_id) {
				list_add(&dentry->link_group_list,
					 group->dentry_list);
				return 0;
			}
			group = group->next;
		}

		/* Add new hard link group to the table */

		group = MALLOC(sizeof(struct link_group));
		if (!group)
			return WIMLIB_ERR_NOMEM;
		group->link_group_id   = dentry->link_group_id;
		group->next            = table->array[pos];
		INIT_LIST_HEAD(&dentry->link_group_list);
		group->dentry_list = &dentry->link_group_list;
		table->array[pos]      = group;

		/* XXX Make the table grow when too many entries have been
		 * inserted. */
		table->num_entries++;
	}
	return 0;
}

static void free_link_group_list(struct link_group *group)
{
	struct link_group *next_group;
	while (group) {
		next_group = group->next;
		FREE(group);
		group = next_group;
	}
}

/* Frees a link group table. */
void free_link_group_table(struct link_group_table *table)
{
	struct link_group *single, *next;

	if (table) {
                if (table->array)
                        for (size_t i = 0; i < table->capacity; i++)
                                free_link_group_list(table->array[i]);
                free_link_group_list(table->extra_groups);
                FREE(table);
        }
}

u64 assign_link_group_ids_to_list(struct link_group *group, u64 id,
                                  struct link_group **extra_groups)
{
	struct dentry *dentry;
	struct list_head *cur_head;
        struct link_group *prev_group = NULL;
        struct link_group *cur_group = group;
	while (cur_group) {
		cur_head = cur_group->dentry_list;
		do {
			dentry = container_of(cur_head,
					      struct dentry,
					      link_group_list);
			dentry->link_group_id = id;
			cur_head = cur_head->next;
		} while (cur_head != cur_group->dentry_list);
		cur_group->link_group_id = id;
		id++;
                prev_group = cur_group;
		cur_group = cur_group->next;
	}
        if (group && extra_groups) {
                prev_group->next = *extra_groups;
                *extra_groups = group;
        }
	return id;
}

/* Insert the link groups in the `extra_groups' list into the hash table */
static void insert_extra_groups(struct link_group_table *table)
{
	struct link_group *group, *next_group;
	size_t pos;

	group = table->extra_groups;
	while (group) {
		next_group        = group->next;
		pos               = group->link_group_id % table->capacity;
		group->next       = table->array[pos];
		table->array[pos] = group;
		group             = next_group;
	}
	table->extra_groups = NULL;
}

/* Assign the link group IDs to dentries in a link group table, and return the
 * next available link group ID. */
u64 assign_link_group_ids(struct link_group_table *table)
{
	DEBUG("Assigning link groups");
        struct link_group *extra_groups = table->extra_groups;

	/* Assign consecutive link group IDs to each link group in the hash
	 * table */
	u64 id = 1;
	for (size_t i = 0; i < table->capacity; i++) {
		id = assign_link_group_ids_to_list(table->array[i], id,
                                                   &table->extra_groups);
                table->array[i] = NULL;
        }

	/* Assign link group IDs to the "extra" link groups and insert them into
	 * the hash table */
	id = assign_link_group_ids_to_list(extra_groups, id, NULL);
	insert_extra_groups(table);
	return id;
}



static void inconsistent_link_group(const struct dentry *first_dentry)
{
	const struct dentry *dentry = first_dentry;

	ERROR("An inconsistent hard link group that we cannot correct has been "
	      "detected");
	ERROR("The dentries are located at the following paths:");
	do {
		ERROR("`%s'", dentry->full_path_utf8);
	} while ((dentry = container_of(dentry->link_group_list.next,
				        const struct dentry,
					link_group_list)) != first_dentry);
}

static bool ref_dentries_consistent(const struct dentry * restrict ref_dentry_1,
				    const struct dentry * restrict ref_dentry_2)
{
	wimlib_assert(ref_dentry_1 != ref_dentry_2);

	if (ref_dentry_1->num_ads != ref_dentry_2->num_ads)
		return false;
	if (ref_dentry_1->security_id != ref_dentry_2->security_id
	    || ref_dentry_1->attributes != ref_dentry_2->attributes)
		return false;
	for (unsigned i = 0; i <= ref_dentry_1->num_ads; i++) {
		const u8 *ref_1_hash, *ref_2_hash;
		ref_1_hash = dentry_stream_hash(ref_dentry_1, i);
		ref_2_hash = dentry_stream_hash(ref_dentry_2, i);
		if (!hashes_equal(ref_1_hash, ref_2_hash))
			return false;
		if (i && !ads_entries_have_same_name(&ref_dentry_1->ads_entries[i - 1],
						     &ref_dentry_2->ads_entries[i - 1]))
			return false;

	}
	return true;
}

static bool dentries_consistent(const struct dentry * restrict ref_dentry,
				const struct dentry * restrict dentry)
{
	wimlib_assert(ref_dentry != dentry);

	if (ref_dentry->num_ads != dentry->num_ads && dentry->num_ads != 0)
		return false;
	if (ref_dentry->security_id != dentry->security_id
	    || ref_dentry->attributes != dentry->attributes)
		return false;
	for (unsigned i = 0; i <= min(ref_dentry->num_ads, dentry->num_ads); i++) {
		const u8 *ref_hash, *hash;
		ref_hash = dentry_stream_hash(ref_dentry, i);
		hash = dentry_stream_hash(dentry, i);
		if (!hashes_equal(ref_hash, hash) && !is_zero_hash(hash))
			return false;
		if (i && !ads_entries_have_same_name(&ref_dentry->ads_entries[i - 1],
						     &dentry->ads_entries[i - 1]))
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
	} while ((dentry = container_of(dentry->link_group_list.next,
					struct dentry,
					link_group_list)) != first_dentry);
}
#endif

/* Fix up a "true" link group and check for inconsistencies */
static int
fix_true_link_group(struct dentry *first_dentry)
{
	struct dentry *dentry;
	struct dentry *ref_dentry = NULL;
	u64 last_ctime = 0;
	u64 last_mtime = 0;
	u64 last_atime = 0;

	dentry = first_dentry;
	do {
		if (!ref_dentry || ref_dentry->num_ads == 0)
			ref_dentry = dentry;
		if (dentry->creation_time > last_ctime)
			last_ctime = dentry->creation_time;
		if (dentry->last_write_time > last_mtime)
			last_mtime = dentry->last_write_time;
		if (dentry->last_access_time > last_atime)
			last_atime = dentry->last_access_time;
	} while ((dentry = container_of(dentry->link_group_list.next,
					struct dentry,
					link_group_list)) != first_dentry);


	ref_dentry->ads_entries_status = ADS_ENTRIES_OWNER;
	dentry = first_dentry;
	do {
		if (dentry != ref_dentry) {
			if (!dentries_consistent(ref_dentry, dentry)) {
				inconsistent_link_group(first_dentry);
				return WIMLIB_ERR_INVALID_DENTRY;
			}
			copy_hash(dentry->hash, ref_dentry->hash);
			dentry_free_ads_entries(dentry);
			dentry->num_ads            = ref_dentry->num_ads;
			dentry->ads_entries        = ref_dentry->ads_entries;
			dentry->ads_entries_status = ADS_ENTRIES_USER;
		}
		dentry->creation_time    = last_ctime;
		dentry->last_write_time  = last_mtime;
		dentry->last_access_time = last_atime;
	} while ((dentry = container_of(dentry->link_group_list.next,
					struct dentry,
					link_group_list)) != first_dentry);
	return 0;
}

/* 
 * Fixes up a nominal link group.
 *
 * By a nominal link group we mean a group of two or more dentries that share
 * the same hard link group ID.
 *
 * If dentries in the group are found to be inconsistent, we may split the group
 * into several "true" hard link groups.  @new_groups points to a linked list of
 * these split groups, and if we create any, they will be added to this list.
 *
 * After splitting up each nominal link group into the "true" link groups we
 * will canonicalize the link groups.  To do this, we:
 *
 *      - Assign all the dentries in the link group the most recent timestamp
 *      among all the corresponding timestamps in the link group, for each of
 *      the three categories of time stamps.
 *
 *      - Make sure the dentry->hash field is valid in all the dentries, if
 *      possible (this field may be all zeroes, and in the context of a hard
 *      link group this must be interpreted as implicitly refering to the same
 *      stream as another dentry in the hard link group that does NOT have all
 *      zeroes for this field).
 *
 *      - Make sure dentry->num_ads is the same in all the dentries in the link
 *      group.  In some cases, it's possible for it to be set to 0 when it
 *      actually must be interpreted as being the same as the number of
 *      alternate data streams in another dentry in the hard link group that has
 *      a nonzero number of alternate data streams.
 *
 *      - Make sure only the dentry->ads_entries array is only allocated for one
 *      dentry in the hard link group.  This dentry will have
 *      dentry->ads_entries_status set to ADS_ENTRIES_OWNER, while the others
 *      will have dentry->ads_entries_status set to ADS_ENTRIES_USER.
 */
static int
fix_nominal_link_group(struct link_group *group,
		       struct link_group **new_groups)
{
	struct dentry *tmp, *dentry, *ref_dentry;
	int ret;
	size_t num_true_link_groups;
	struct list_head *head;
	u64 link_group_id;

	LIST_HEAD(dentries_with_data_streams);
	LIST_HEAD(dentries_with_no_data_streams);
	LIST_HEAD(true_link_groups);

        /* Create a list of dentries in the nominal hard link group that have at
         * least one data stream with a non-zero hash, and another list that
         * contains the dentries that have a zero hash for all data streams. */
	dentry = container_of(group->dentry_list, struct dentry,
			      link_group_list);
	do {
		for (unsigned i = 0; i <= dentry->num_ads; i++) {
			const u8 *hash;
			hash = dentry_stream_hash(dentry, i);
			if (!is_zero_hash(hash)) {
				list_add(&dentry->tmp_list,
					 &dentries_with_data_streams);
				goto next_dentry;
			}
		}
		list_add(&dentry->tmp_list,
			 &dentries_with_no_data_streams);
	next_dentry:
		dentry = container_of(dentry->link_group_list.next,
				      struct dentry,
				      link_group_list);
	} while (&dentry->link_group_list != group->dentry_list);

	/* If there are no dentries with data streams, we require the nominal
	 * link group to be a true link group */
	if (list_empty(&dentries_with_data_streams)) {
	#ifdef ENABLE_DEBUG
		DEBUG("Found link group of size %zu without any data streams:",
		      dentry_link_group_size(dentry));
		print_dentry_list(dentry);
		DEBUG("We are going to interpret it as true link group, provided "
		      "that the dentries are consistent.");
	#endif
		return fix_true_link_group(container_of(group->dentry_list,
							struct dentry,
							link_group_list));
	}

        /* One or more dentries had data streams specified.  We check each of
         * these dentries for consistency with the others to form a set of true
         * link groups. */
	num_true_link_groups = 0;
	list_for_each_entry_safe(dentry, tmp, &dentries_with_data_streams,
				 tmp_list)
	{
		list_del(&dentry->tmp_list);

		/* Look for a true link group that is consistent with
		 * this dentry and add this dentry to it.  Or, if none
		 * of the true link groups are consistent with this
		 * dentry, make a new one. */
		list_for_each_entry(ref_dentry, &true_link_groups, tmp_list) {
			if (ref_dentries_consistent(ref_dentry, dentry)) {
				list_add(&dentry->link_group_list,
					 &ref_dentry->link_group_list);
				goto next_dentry_2;
			}
		}
		num_true_link_groups++;
		list_add(&dentry->tmp_list, &true_link_groups);
		INIT_LIST_HEAD(&dentry->link_group_list);
next_dentry_2:
		;
	}

	wimlib_assert(num_true_link_groups != 0);

        /* If there were dentries with no data streams, we require there to only
         * be one true link group so that we know which link group to assign the
         * streamless dentries to. */
	if (!list_empty(&dentries_with_no_data_streams)) {
		if (num_true_link_groups != 1) {
			ERROR("Hard link group ambiguity detected!");
			ERROR("We split up hard link group 0x%"PRIx64" due to "
			      "inconsistencies,", group->link_group_id);
			ERROR("but dentries with no stream information remained. "
			      "We don't know which true hard link");
			ERROR("group to assign them to.");
			return WIMLIB_ERR_INVALID_DENTRY;
		}
		/* Assign the streamless dentries to the one and only true link
		 * group. */
		ref_dentry = container_of(true_link_groups.next,
					  struct dentry,
					  tmp_list);
		list_for_each_entry(dentry, &dentries_with_no_data_streams, tmp_list)
			list_add(&dentry->link_group_list, &ref_dentry->link_group_list);
	}
        if (num_true_link_groups != 1) {
		#ifdef ENABLE_DEBUG
		{
			printf("Split nominal link group 0x%"PRIx64" into %zu "
			       "link groups:\n",
			       group->link_group_id, num_true_link_groups);
			puts("------------------------------------------------------------------------------");
			size_t i = 1;
			list_for_each_entry(dentry, &true_link_groups, tmp_list) {
				printf("[Split link group %zu]\n", i++);
				print_dentry_list(dentry);
				putchar('\n');
			}
			puts("------------------------------------------------------------------------------");
		}
		#endif
        }

	list_for_each_entry(dentry, &true_link_groups, tmp_list) {
		ret = fix_true_link_group(dentry);
		if (ret != 0)
			return ret;
	}

	/* Make new `struct link_group's for the new link groups */
	for (head = true_link_groups.next->next;
	     head != &true_link_groups;
	     head = head->next)
	{
		dentry = container_of(head, struct dentry, tmp_list);
		group = MALLOC(sizeof(*group));
		if (!group) {
			ERROR("Out of memory");
			return WIMLIB_ERR_NOMEM;
		}
		group->link_group_id = link_group_id;
		group->dentry_list = &dentry->link_group_list;
		group->next = *new_groups;
		*new_groups = group;
	}
	return 0;
}

/*
 * Goes through each link group and shares the ads_entries (Alternate Data
 * Stream entries) field of each dentry among members of a hard link group.
 *
 * In the process, the dentries in each link group are checked for consistency.
 * If they contain data features that indicate they cannot really be in the same
 * hard link group, this should be an error, but in reality this case needs to
 * be handled, so we split the dentries into different hard link groups.
 *
 * One of the dentries in each hard link group group is arbitrarily assigned the
 * role of "owner" of the memory pointed to by the @ads_entries field,
 * (ADS_ENTRIES_OWNER), while the others are "users" (ADS_ENTRIES_USER) who are
 * not allowed to free the memory.
 */
int fix_link_groups(struct link_group_table *table)
{
	for (u64 i = 0; i < table->capacity; i++) {
		struct link_group *group = table->array[i];
		while (group) {
			int ret;
			ret = fix_nominal_link_group(group, &table->extra_groups);
			if (ret != 0)
				return ret;
			group = group->next;
		}
	}
	return 0;
}
