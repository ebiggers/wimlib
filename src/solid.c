/*
 * solid.c
 *
 * Heuristic sorting of streams to optimize solid compression.
 */

/*
 * Copyright (C) 2015 Eric Biggers
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
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/solid.h"
#include "wimlib/unaligned.h"

static const utf16lechar *
get_extension(const utf16lechar *name, size_t nbytes)
{
	const utf16lechar *p = name + (nbytes / sizeof(utf16lechar));
	for (;;) {
		if (p == name)
			return NULL;
		if (*(p - 1) == cpu_to_le16('/') || *(p - 1) == cpu_to_le16('\\'))
			return NULL;
		if (*(p - 1) == cpu_to_le16('.'))
			return p;
		p--;
	}
}

/*
 * Sort order for solid compression:
 *
 * 1. Streams without sort names
 *	- sorted by sequential order
 * 2. Streams with sort names:
 *    a. Streams whose sort name does not have an extension
 *	  - sorted by sort name
 *    b. Streams whose sort name has an extension
 *        - sorted primarily by extension (case insensitive),
 *	    secondarily by sort name (case insensitive)
 */
static int
cmp_streams_by_solid_sort_name(const void *p1, const void *p2)
{
	const struct wim_lookup_table_entry *lte1, *lte2;

	lte1 = *(const struct wim_lookup_table_entry **)p1;
	lte2 = *(const struct wim_lookup_table_entry **)p2;

	if (lte1->solid_sort_name) {
		if (!lte2->solid_sort_name)
			return 1;
		const utf16lechar *extension1 = get_extension(lte1->solid_sort_name,
							      lte1->solid_sort_name_nbytes);
		const utf16lechar *extension2 = get_extension(lte2->solid_sort_name,
							      lte2->solid_sort_name_nbytes);
		if (extension1) {
			if (!extension2)
				return 1;
			int res = cmp_utf16le_strings(extension1,
						      utf16le_strlen(extension1) / sizeof(utf16lechar),
						      extension2,
						      utf16le_strlen(extension2) / sizeof(utf16lechar),
						      true); /* case insensitive */
			if (res)
				return res;
		} else {
			if (extension2)
				return -1;
		}
		int res = cmp_utf16le_strings(lte1->solid_sort_name,
					      lte1->solid_sort_name_nbytes / sizeof(utf16lechar),
					      lte2->solid_sort_name,
					      lte2->solid_sort_name_nbytes / sizeof(utf16lechar),
					      true); /* case insensitive */
		if (res)
			return res;
	} else {
		if (lte2->solid_sort_name)
			return -1;
	}
	return cmp_streams_by_sequential_order(p1, p2);
}

static void
lte_set_solid_sort_name_from_inode(struct wim_lookup_table_entry *lte,
				   const struct wim_inode *inode)
{
	const struct wim_dentry *dentry;
	const utf16lechar *best_name = NULL;
	size_t best_name_nbytes = SIZE_MAX;

	if (lte->solid_sort_name) /* Sort name already set?  */
		return;

	/* If this file has multiple names, choose the shortest one.  */
	inode_for_each_dentry(dentry, inode) {
		if (dentry->file_name_nbytes < best_name_nbytes) {
			best_name = dentry->file_name;
			best_name_nbytes = dentry->file_name_nbytes;
		}
	}
	lte->solid_sort_name = utf16le_dupz(best_name, best_name_nbytes);
	lte->solid_sort_name_nbytes = best_name_nbytes;
}

struct temp_lookup_table {
	struct hlist_head *table;
	size_t capacity;
};

static int
dentry_fill_in_solid_sort_names(struct wim_dentry *dentry, void *_lookup_table)
{
	const struct temp_lookup_table *lookup_table = _lookup_table;
	const struct wim_inode *inode = dentry->d_inode;
	const u8 *hash;
	struct hlist_head *head;
	struct hlist_node *cur;
	struct wim_lookup_table_entry *lte;

	hash = inode_unnamed_stream_hash(inode);
	head = &lookup_table->table[load_size_t_unaligned(hash) %
				    lookup_table->capacity];
	hlist_for_each_entry(lte, cur, head, hash_list_2) {
		if (hashes_equal(hash, lte->hash)) {
			lte_set_solid_sort_name_from_inode(lte, inode);
			break;
		}
	}
	return 0;
}

static int
image_fill_in_solid_sort_names(WIMStruct *wim)
{
	return for_dentry_in_tree(wim_get_current_root_dentry(wim),
				  dentry_fill_in_solid_sort_names,
				  wim->private);
}

int
sort_stream_list_for_solid_compression(struct list_head *stream_list)
{
	size_t num_streams = 0;
	struct temp_lookup_table lookup_table;
	WIMStruct *wims[128];
	int num_wims = 0;
	struct wim_lookup_table_entry *lte;
	int ret;

	/* Count the number of streams to be written.  */
	list_for_each_entry(lte, stream_list, write_streams_list)
		num_streams++;

	/* Allocate a temporary hash table for mapping stream hash => stream  */
	lookup_table.capacity = num_streams;
	lookup_table.table = CALLOC(lookup_table.capacity,
				    sizeof(lookup_table.table[0]));
	if (!lookup_table.table)
		return WIMLIB_ERR_NOMEM;

	/*
	 * For each stream to be written:
	 * - Reset the sort name
	 * - If it's in non-solid WIM resource, then save the WIMStruct.
	 * - If it's in a file on disk, then set its sort name from that.
	 */
	list_for_each_entry(lte, stream_list, write_streams_list) {
		lte->solid_sort_name = NULL;
		lte->solid_sort_name_nbytes = 0;
		switch (lte->resource_location) {
		case RESOURCE_IN_WIM:
			if (lte->size != lte->rspec->uncompressed_size)
				continue;
			for (int i = 0; i < num_wims; i++)
				if (lte->rspec->wim == wims[i])
					goto found_wim;
			if (num_wims >= ARRAY_LEN(wims))
				continue;
			wims[num_wims++] = lte->rspec->wim;
		found_wim:
			hlist_add_head(&lte->hash_list_2,
				       &lookup_table.table[load_size_t_unaligned(lte->hash) %
							   lookup_table.capacity]);
			break;
		case RESOURCE_IN_FILE_ON_DISK:
	#ifdef __WIN32__
		case RESOURCE_IN_WINNT_FILE_ON_DISK:
	#endif
			lte_set_solid_sort_name_from_inode(lte, lte->file_inode);
			break;
		default:
			break;
		}
	}

	/* For each WIMStruct that was found, search for dentry references to
	 * each stream and fill in the sort name this way.  This is useful e.g.
	 * when exporting a solid WIM file from a non-solid WIM file.  */
	for (int i = 0; i < num_wims; i++) {
		if (!wim_has_metadata(wims[i]))
			continue;
		wims[i]->private = &lookup_table;
		ret = for_image(wims[i], WIMLIB_ALL_IMAGES,
				image_fill_in_solid_sort_names);
		if (ret)
			goto out_free_lookup_table;
		deselect_current_wim_image(wims[i]);
	}

	ret = sort_stream_list(stream_list,
			       offsetof(struct wim_lookup_table_entry,
					write_streams_list),
			       cmp_streams_by_solid_sort_name);

	list_for_each_entry(lte, stream_list, write_streams_list)
		FREE(lte->solid_sort_name);
out_free_lookup_table:
	FREE(lookup_table.table);
	return ret;
}
