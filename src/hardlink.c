#include "wimlib_internal.h"
#include "dentry.h"
#include "list.h"
#include "lookup_table.h"

struct link_group {
	u64 link_group_id;
	struct link_group *next;
	struct list_head *dentry_list;
};

struct link_group_table {
	struct link_group **array;
	u64 num_entries;
	u64 capacity;
	struct link_group *singles;
};

#include <sys/mman.h>

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

/* Insert a dentry into the hard link group table based on its hard link group
 * ID.
 *
 * If there is already a dentry in the table having the same hard link group ID,
 * we link the dentries together in a circular list.
 *
 * If the hard link group ID is 0, this is a no-op and the dentry is not
 * inserted.
 */
int link_group_table_insert(struct dentry *dentry, struct link_group_table *table)
{
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
		return 0;
	}

	/* Try adding to existing hard link group */
	pos = dentry->hard_link % table->capacity;
	group = table->array[pos];
	while (group) {
		if (group->link_group_id == dentry->hard_link) {
			list_add(&dentry->link_group_list, group->dentry_list);
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

	/* XXX Make the table grow when too many entries have been inserted. */
	table->num_entries++;
	return 0;
}

/* Frees a link group table. */
void free_link_group_table(struct link_group_table *table)
{
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
	FREE(table);
}

/* Assign the link group IDs to dentries in a link group table, and return the
 * next available link group ID. */
u64 assign_link_groups(struct link_group_table *table)
{
	DEBUG("Assigning link groups");
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
	/* Singles */
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

static int link_group_free_duplicate_data(struct link_group *group,
					  struct link_group **bad_links)
{
	struct dentry *master, *slave, *tmp;

	master = container_of(group->dentry_list, struct dentry,
			      link_group_list);
	master->link_group_master_status = GROUP_MASTER;

	list_for_each_entry_safe(slave, tmp, group->dentry_list,
				 link_group_list)
	{
		/* I would it to be an error if two dentries are the same hard
		 * link group but have irreconcilable differences such as
		 * different file permissions, but unfortunately some of M$'s
		 * WIMs contain many instances of this error.  This problem is
		 * worked around here by splitting each offending dentry off
		 * into its own hard link group. */
		if (share_dentry_ads(master, slave) != 0) {
			struct link_group *single;
			single = MALLOC(sizeof(struct link_group));
			if (!single)
				return WIMLIB_ERR_NOMEM;
			list_del(&slave->link_group_list);
			INIT_LIST_HEAD(&slave->link_group_list);
			single->link_group_id = 0;
			single->next          = *bad_links;
			single->dentry_list   = &slave->link_group_list;
			*bad_links            = single;
			slave->link_group_master_status = GROUP_INDEPENDENT;
		}
	}
	return 0;
}

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
