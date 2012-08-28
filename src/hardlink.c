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

/* Hard link group; it's identified by its hard link group ID and consists of a
 * circularly linked list of dentries. */
struct link_group {
	u64 link_group_id;
	struct link_group *next;
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
	 *   hash table
	 * - Groups we create ourselves by splitting a nominal hard link group
	 *   due to inconsistencies in the dentries.  These groups will have a
	 *   hard link group ID duplicated with some other group until
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
 * we link the dentries together in a circular list.
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

	if (dentry->hard_link == 0) {
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
		/* Hard link group that may should multiple dentries (the code
		 * will work even if the group actually contains only 1 dentry
		 * though) */

		/* Try adding to existing hard link group */
		pos = dentry->hard_link % table->capacity;
		group = table->array[pos];
		while (group) {
			if (group->link_group_id == dentry->hard_link) {
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
		group->link_group_id   = dentry->hard_link;
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

	if (!table)
		return;
	if (table->array)
		for (size_t i = 0; i < table->capacity; i++)
			free_link_group_list(table->array[i]);
	free_link_group_list(table->extra_groups);

	FREE(table);
}

u64 assign_link_group_ids_to_list(struct link_group *group, u64 id)
{
	struct dentry *dentry;
	struct list_head *cur;
	while (group) {
		cur = group->dentry_list;
		do {
			dentry = container_of(cur,
					      struct dentry,
					      link_group_list);
			dentry->hard_link = id;
			cur = cur->next;
		} while (cur != group->dentry_list);
		group->link_group_id = id;
		id++;
		group = group->next;
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
		next_group = group->next;
		pos = group->link_group_id % table->capacity;
		group->next = table->array[pos];
		table->array[pos] = group;
		group = next_group;
	}
	table->extra_groups = NULL;
}

/* Assign the link group IDs to dentries in a link group table, and return the
 * next available link group ID. */
u64 assign_link_group_ids(struct link_group_table *table)
{
	DEBUG("Assigning link groups");

	/* Assign consecutive link group IDs to each link group in the hash
	 * table */
	u64 id = 1;
	for (size_t i = 0; i < table->capacity; i++)
		id = assign_link_group_ids_to_list(table->array[i], id);

	/* Assign link group IDs to the "extra" link groups and insert them into
	 * the hash table */
	id = assign_link_group_ids_to_list(table->extra_groups, id);
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
				        struct dentry,
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
		ref_1_hash = dentry_stream_hash_unresolved(ref_dentry_1, i);
		ref_2_hash = dentry_stream_hash_unresolved(ref_dentry_2, i);
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
		ref_hash = dentry_stream_hash_unresolved(ref_dentry, i);
		hash = dentry_stream_hash_unresolved(dentry, i);
		if (!hashes_equal(ref_hash, hash) && !is_zero_hash(hash))
			return false;
		if (i && !ads_entries_have_same_name(&ref_dentry->ads_entries[i - 1],
						     &dentry->ads_entries[i - 1]))
			return false;
	}
	return true;
}

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

	/* Create the lists @dentries_with_data_streams and
	 * @dentries_with_no_data_streams. */
	dentry = container_of(group->dentry_list, struct dentry,
			      link_group_list);
	do {
		for (unsigned i = 0; i <= dentry->num_ads; i++) {
			const u8 *hash;
			hash = dentry_stream_hash_unresolved(dentry, i);
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
	if (list_empty(&dentries_with_data_streams))
		return fix_true_link_group(container_of(group->dentry_list,
							struct dentry,
							link_group_list));

	/* One or more dentries had data streams.  We check each of these
	 * dentries for consistency with the others to form a set of true link
	 * groups. */
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
	 *
	 * streamless dentries to. */
	if (!list_empty(&dentries_with_no_data_streams)) {
		if (num_true_link_groups != 1) {
			ERROR("Hard link group ambiguity detected!");
			ERROR("We split up hard link group 0x%"PRIx64" due to "
			      "inconsistencies,");
			ERROR("but dentries with no stream information remained. "
			      "We don't know which true hard link");
			ERROR("group to assign them to.");
			return WIMLIB_ERR_INVALID_DENTRY;
		}
		ref_dentry = container_of(true_link_groups.next,
					  struct dentry,
					  tmp_list);
		list_for_each_entry(dentry, &dentries_with_no_data_streams,
				    tmp_list)
		{
			list_add(&dentry->link_group_list,
				 &ref_dentry->link_group_list);
		}
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
	} while ((head = head->next) != &true_link_groups);
	return 0;
}

/*
 * Goes through each link group and shares the ads_entries (Alternate Data
 * Stream entries) field of each dentry between members of a hard link group.
 *
 * In the process, the dentries in each link group are checked for consistency.
 * If they contain data features that indicate they cannot really be in the same
 * hard link group, this should be an error, but in reality this case needs to
 * be handled, so we split the dentries into different hard link groups.
 *
 * One of the dentries in the group is arbitrarily assigned the role of "owner"
 * (ADS_ENTRIES_OWNER), while the others are "users" (ADS_ENTRIES_USER).
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

#if 0
static bool dentries_have_same_ads(const struct dentry *d1,
				   const struct dentry *d2)
{
	wimlib_assert(d1->num_ads == d2->num_ads);
	/* Verify stream names and hashes are the same */
	for (u16 i = 0; i < d1->num_ads; i++) {
		if (strcmp(d1->ads_entries[i].stream_name_utf8,
			   d2->ads_entries[i].stream_name_utf8) != 0)
			return false;
		if (!hashes_equal(d1->ads_entries[i].hash,
				  d2->ads_entries[i].hash))
			return false;
	}
	return true;
}

/* 
 * Share the alternate stream entries between hard-linked dentries.
 *
 * Notes:
 * - If you use 'imagex.exe' (version 6.1.7600.16385) to create a WIM containing
 *   hard-linked files, only one dentry in the hard link set will refer to data
 *   streams, including all alternate data streams.  The rest of the dentries in
 *   the hard link set will be marked as having 0 alternate data streams and
 *   will not refer to any main file stream (the SHA1 message digest will be all
 *   0's).
 *
 * - However, if you look at the WIM's that Microsoft actually distributes (e.g.
 *   Windows 7/8 boot.wim, install.wim), it's not the same as above.  The
 *   dentries in hard link sets will have stream information duplicated.  I
 *   can't say anything about the alternate data streams because these WIMs do
 *   not contain alternate data streams.
 *
 * - Windows 7 'install.wim' contains hard link sets containing dentries with
 *   inconsistent streams and other inconsistent information such as security
 *   ID.  The only way I can think to handle these is to treat the hard link
 *   grouping as erroneous and split up the hard link group.
 */
static int share_dentry_ads(struct dentry *owner, struct dentry *user)
{
	const char *mismatch_type;
	bool data_streams_shared = true;
	wimlib_assert(owner->num_ads == 0 ||
		      owner->ads_entries != user->ads_entries);
	if (owner->attributes != user->attributes) {
		mismatch_type = "attributes";
		goto mismatch;
	}
	if (owner->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		WARNING("`%s' is hard-linked to `%s', which is a directory ",
		        user->full_path_utf8, owner->full_path_utf8);
		return WIMLIB_ERR_INVALID_DENTRY;
	}
	if (owner->security_id != user->security_id) {
		mismatch_type = "security ID";
		goto mismatch;
	}
	if (!hashes_equal(owner->hash, user->hash)) {
		if (is_zero_hash(user->hash)) {
			data_streams_shared = false;
			copy_hash(user->hash, owner->hash);
		} else {
			mismatch_type = "main file resource";
			goto mismatch;
		}
	}
	if (data_streams_shared) {
		if (!dentries_have_same_ads(owner, user)) {
			mismatch_type = "Alternate Stream Entries";
			goto mismatch;
		}
	}
	if (owner->last_access_time != user->last_access_time
	    || owner->last_write_time != user->last_write_time
	    || owner->creation_time != user->creation_time) {
	}
	dentry_free_ads_entries(user);
	user->ads_entries = owner->ads_entries;
	user->ads_entries_status = ADS_ENTRIES_USER;
	return 0;
mismatch:
	WARNING("Dentries `%s' and `%s' are supposedly in the same hard-link "
		"group but do not share the same %s",
	        owner->full_path_utf8, user->full_path_utf8,
	        mismatch_type);
	return WIMLIB_ERR_INVALID_DENTRY;
}
#endif
