#include "wimlib_internal.h"
#include "dentry.h"
#include "list.h"
#include "lookup_table.h"

struct link_group {
	u64 link_group_id;
	struct link_group *next;
	struct list_head dentry_list;
};

struct link_group_table {
	struct link_group **array;
	u64 num_entries;
	u64 capacity;
};

#include <sys/mman.h>

struct link_group_table *new_link_group_table(u64 capacity)
{
	return (struct link_group_table*)new_lookup_table(capacity);
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

	if (dentry->hard_link == 0)
		return 0;

	/* Try adding to existing hard link group */
	pos = dentry->hard_link % table->capacity;
	group = table->array[pos];
	while (group) {
		if (group->link_group_id == dentry->hard_link) {
			list_add(&dentry->link_group_list, &group->dentry_list);
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
	INIT_LIST_HEAD(&group->dentry_list);
	list_add(&dentry->link_group_list, &group->dentry_list);
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
	struct link_group *remaining_groups = NULL;
	u64 id = 1;
	for (u64 i = 0; i < table->capacity; i++) {
		struct link_group *group = table->array[i];
		struct link_group *next_group;
		struct dentry *dentry;
		while (group) {
			next_group = group->next;
			if (list_is_singular(&group->dentry_list)) {
				/* Hard link group of size 1.  Change the hard
				 * link ID to 0 and discard the link_group */
				dentry = container_of(group->dentry_list.next,
						      struct dentry,
						      link_group_list);
				dentry->hard_link = 0;
				FREE(group);
			} else {
				/* Hard link group of size > 1.  Assign the
				 * dentries in the group the next available hard
				 * link IDs and queue the group to be
				 * re-inserted into the table. */
				list_for_each_entry(dentry, &group->dentry_list,
						    link_group_list)
					dentry->hard_link = id;
				group->next = remaining_groups;
				remaining_groups = group;
				id++;
			}
			group = next_group;
		}
	}
	memset(table->array, 0, table->capacity * sizeof(table->array[0]));
	table->num_entries = 0;
	while (remaining_groups) {
		struct link_group *group = remaining_groups;
		size_t pos = group->link_group_id % table->capacity;

		table->num_entries++;
		group->next = table->array[pos];
		table->array[pos] = group;
		remaining_groups = remaining_groups->next;
	}
	return id;
}

#if 0
/* Load a dentry tree into the link group table */
int load_link_groups(struct link_group_table *table, struct dentry *root)
{
	int ret = for_dentry_in_tree(dentry, link_group_table_insert, table);
	if (ret == 0)
		assign_link_groups(table);
	return ret;
}
#endif
