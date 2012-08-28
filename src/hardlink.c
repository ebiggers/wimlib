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
	struct link_group **array;
	u64 num_entries;
	u64 capacity;
	struct link_group *singles;
};

/* Returns pointer to a new link group table having the specified capacity */
struct link_group_table *new_link_group_table(u64 capacity)
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
	table->num_entries = 0;
	table->capacity = capacity;
	table->array = array;
	table->singles = NULL;
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
		/* Single group--- Add to the singles list (we can't put it in
		 * the table itself because all the singles have a link group ID
		 * of 0) */
		group = MALLOC(sizeof(struct link_group));
		if (!group)
			return WIMLIB_ERR_NOMEM;
		group->link_group_id = 0;
		group->next          = table->singles;
		table->singles       = group;
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

/* Frees a link group table. */
void free_link_group_table(struct link_group_table *table)
{
	struct link_group *single, *next;

	if (!table)
		return;
	if (table->array) {
		for (u64 i = 0; i < table->capacity; i++) {
			struct link_group *group = table->array[i];
			struct link_group *next;
			while (group) {
				next = group->next;
				FREE(group);
				group = next;
			}
		}
		FREE(table->array);
	}
	single = table->singles;
	while (single) {
		next = single->next;
		FREE(single);
		single = next;
	}

	FREE(table);
}

/* Assign the link group IDs to dentries in a link group table, and return the
 * next available link group ID. */
u64 assign_link_groups(struct link_group_table *table)
{
	DEBUG("Assigning link groups");

	/* Assign consecutive link group IDs to each link group in the hash
	 * table */
	u64 id = 1;
	for (u64 i = 0; i < table->capacity; i++) {
		struct link_group *group = table->array[i];
		struct link_group *next_group;
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
			id++;
			group = group->next;
		}
	}
	/* Assign link group IDs to the link groups that previously had link
	 * group IDs of 0, and insert them into the hash table */
	struct link_group *single = table->singles;
	while (single) {
		struct dentry *dentry;
		struct link_group *next_single;
		size_t pos;

		next_single = single->next;

		dentry = container_of(single->dentry_list, struct dentry,
				      link_group_list);
		dentry->hard_link = id;

		pos = id % table->capacity;
		single->next = table->array[pos];
		table->array[pos] = single;

		single = next_single;
		id++;
	}
	table->singles = NULL;
	return id;
}

static bool dentries_have_same_ads(const struct dentry *d1,
				   const struct dentry *d2)
{
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

static int link_group_free_duplicate_data(struct link_group *group,
					  struct link_group **bad_links)
{
	struct dentry *owner, *user, *tmp;

	/* Find a dentry with non-zero hash to use as a possible link group
	 * owner (see comments above the share_dentry_ads() function */
	owner = container_of(group->dentry_list, struct dentry,
			      link_group_list);
	do {
		/* imagex.exe may move the un-named data stream from the dentry
		 * itself to the first alternate data stream, if there are
		 * other alternate data streams */
		if (!is_zero_hash(owner->hash) ||
		    (owner->num_ads && !is_zero_hash(owner->ads_entries[0].hash)))
			goto found_owner;
		owner = container_of(owner->link_group_list.next,
				     struct dentry,
				     link_group_list);
	} while (&owner->link_group_list != group->dentry_list);

	ERROR("Could not find owner of data streams in hard link group");
	return WIMLIB_ERR_INVALID_DENTRY;
found_owner:
	owner->ads_entries_status = ADS_ENTRIES_OWNER;
	list_for_each_entry_safe(user, tmp, &owner->link_group_list,
				 link_group_list)
	{
		/* I would like it to be an error if two dentries are in the
		 * same hard link group but have irreconcilable differences such
		 * as different file permissions, but unfortunately some of M$'s
		 * WIMs contain many instances of this error.  This problem is
		 * worked around here by splitting each offending dentry off
		 * into its own hard link group. */
		if (share_dentry_ads(owner, user) != 0) {
			struct link_group *single;
			single = MALLOC(sizeof(struct link_group));
			if (!single)
				return WIMLIB_ERR_NOMEM;
			list_del(&user->link_group_list);
			INIT_LIST_HEAD(&user->link_group_list);
			single->link_group_id = 0;
			single->next          = *bad_links;
			single->dentry_list   = &user->link_group_list;
			*bad_links            = single;
			user->ads_entries_status = ADS_ENTRIES_OWNER;
		}
	}
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
int link_groups_free_duplicate_data(struct link_group_table *table)
{
	for (u64 i = 0; i < table->capacity; i++) {
		struct link_group *group = table->array[i];
		while (group) {
			int ret;
			ret = link_group_free_duplicate_data(group,
							     &table->singles);
			if (ret != 0)
				return ret;
			group = group->next;
		}
	}
	return 0;
}
