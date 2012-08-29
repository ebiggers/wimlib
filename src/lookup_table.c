/*
 * lookup_table.c
 *
 * Lookup table, implemented as a hash table, that maps dentries to file
 * resources.
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
#include "lookup_table.h"
#include "io.h"
#include <errno.h>

struct lookup_table *new_lookup_table(size_t capacity)
{
	struct lookup_table *table;
	struct hlist_head *array;

	table = MALLOC(sizeof(struct lookup_table));
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
	return table;
err:
	ERROR("Failed to allocate memory for lookup table with capacity %zu",
	      capacity);
	return NULL;
}

struct lookup_table_entry *new_lookup_table_entry()
{
	struct lookup_table_entry *lte;
	
	lte = CALLOC(1, sizeof(struct lookup_table_entry));
	if (!lte) {
		ERROR("Out of memory (tried to allocate %zu bytes for "
		      "lookup table entry)",
		      sizeof(struct lookup_table_entry));
		return NULL;
	}

	lte->part_number  = 1;
	lte->refcnt       = 1;
	INIT_LIST_HEAD(&lte->lte_group_list);
	return lte;
}

void free_lookup_table_entry(struct lookup_table_entry *lte)
{
	if (lte) {
#ifdef WITH_FUSE
		if (lte->staging_list.next)
			list_del(&lte->staging_list);
#endif
		switch (lte->resource_location) {
		case RESOURCE_IN_STAGING_FILE:
		case RESOURCE_IN_ATTACHED_BUFFER:
		case RESOURCE_IN_FILE_ON_DISK:
			wimlib_assert((&lte->file_on_disk ==
				      &lte->staging_file_name)
				      && (&lte->file_on_disk ==
				      &lte->attached_buffer));
			FREE(lte->file_on_disk);
			break;
#ifdef WITH_NTFS_3G
		case RESOURCE_IN_NTFS_VOLUME:
			if (lte->ntfs_loc) {
				FREE(lte->ntfs_loc->path_utf8);
				FREE(lte->ntfs_loc->stream_name_utf16);
				FREE(lte->ntfs_loc);
			}
			break;
#endif
		default:
			break;
		}
		FREE(lte);
	}
}

static int do_free_lookup_table_entry(struct lookup_table_entry *entry,
				      void *ignore)
{
	free_lookup_table_entry(entry);
	return 0;
}


void free_lookup_table(struct lookup_table *table)
{
	DEBUG("Freeing lookup table");
	if (table) {
		if (table->array) {
			for_lookup_table_entry(table,
					       do_free_lookup_table_entry,
					       NULL);
			FREE(table->array);
		}
		FREE(table);
	}
}

/*
 * Inserts an entry into the lookup table.
 *
 * @table:	A pointer to the lookup table.
 * @entry:	A pointer to the entry to insert.
 */
void lookup_table_insert(struct lookup_table *table, 
			 struct lookup_table_entry *lte)
{
	size_t i = lte->hash_short % table->capacity;
	hlist_add_head(&lte->hash_list, &table->array[i]);

	/* XXX Make the table grow when too many entries have been inserted. */
	table->num_entries++;
}



/* Decrements the reference count for the lookup table entry @lte.  If its
 * reference count reaches 0, it is unlinked from the lookup table.  If,
 * furthermore, the entry has no opened file descriptors associated with it, the
 * entry is freed.  */
struct lookup_table_entry *
lte_decrement_refcnt(struct lookup_table_entry *lte, struct lookup_table *table)
{
	if (lte) {
		wimlib_assert(lte->refcnt);
		if (--lte->refcnt == 0) {
			lookup_table_unlink(table, lte);
		#ifdef WITH_FUSE
			if (lte->num_opened_fds == 0)
		#endif
			{
				free_lookup_table_entry(lte);
				lte = NULL;
			}
		}
	}
	return lte;
}

/* 
 * Calls a function on all the entries in the lookup table.  Stop early and
 * return nonzero if any call to the function returns nonzero.
 */
int for_lookup_table_entry(struct lookup_table *table, 
			   int (*visitor)(struct lookup_table_entry *, void *),
			   void *arg)
{
	struct lookup_table_entry *lte;
	struct hlist_node *pos, *tmp;
	int ret;

	for (size_t i = 0; i < table->capacity; i++) {
		hlist_for_each_entry_safe(lte, pos, tmp, &table->array[i],
					  hash_list)
		{
			ret = visitor(lte, arg);
			if (ret != 0)
				return ret;
		}
	}
	return 0;
}


/*
 * Reads the lookup table from a WIM file.
 */
int read_lookup_table(WIMStruct *w)
{
	u64    num_entries;
	u8     buf[WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE];
	int    ret;
	struct lookup_table *table;

	DEBUG("Reading lookup table: offset %"PRIu64", size %"PRIu64"",
	      w->hdr.lookup_table_res_entry.offset,
	      w->hdr.lookup_table_res_entry.original_size);

	if (fseeko(w->fp, w->hdr.lookup_table_res_entry.offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" to read "
				 "lookup table",
				 w->hdr.lookup_table_res_entry.offset);
		return WIMLIB_ERR_READ;
	}

	num_entries = w->hdr.lookup_table_res_entry.original_size /
		      WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE;
	table = new_lookup_table(num_entries * 2 + 1);
	if (!table)
		return WIMLIB_ERR_NOMEM;

	while (num_entries--) {
		const u8 *p;
		struct lookup_table_entry *cur_entry, *duplicate_entry;

		if (fread(buf, 1, sizeof(buf), w->fp) != sizeof(buf)) {
			if (feof(w->fp)) {
				ERROR("Unexpected EOF in WIM lookup table!");
			} else {
				ERROR_WITH_ERRNO("Error reading WIM lookup "
						 "table");
			}
			ret = WIMLIB_ERR_READ;
			goto out;
		}
		cur_entry = new_lookup_table_entry();
		if (!cur_entry) {
			ret = WIMLIB_ERR_NOMEM;
			goto out;
		}
		cur_entry->wim = w;
		cur_entry->resource_location = RESOURCE_IN_WIM;
			 
		p = get_resource_entry(buf, &cur_entry->resource_entry);
		p = get_u16(p, &cur_entry->part_number);
		p = get_u32(p, &cur_entry->refcnt);
		p = get_bytes(p, SHA1_HASH_SIZE, cur_entry->hash);

		if (is_zero_hash(cur_entry->hash)) {
			ERROR("The WIM lookup table contains an entry with a "
			      "SHA1 message digest of all 0's");
			ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
			FREE(cur_entry);
			goto out;
		}

		duplicate_entry = __lookup_resource(table, cur_entry->hash);
		if (duplicate_entry) {
			ERROR("The WIM lookup table contains two entries with the "
			      "same SHA1 message digest!");
			ERROR("The first entry is:");
			print_lookup_table_entry(duplicate_entry);
			ERROR("The second entry is:");
			print_lookup_table_entry(cur_entry);
			ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
			FREE(cur_entry);
			goto out;
		}
		lookup_table_insert(table, cur_entry);

		if (!(cur_entry->resource_entry.flags & WIM_RESHDR_FLAG_COMPRESSED)
		    && (cur_entry->resource_entry.size !=
		      cur_entry->resource_entry.original_size))
		{
			ERROR("Found uncompressed resource with original size "
			      "not the same as compressed size");
			ERROR("The lookup table entry for the resource is as follows:");
			print_lookup_table_entry(cur_entry);
			ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
			goto out;
		}
	}
	DEBUG("Done reading lookup table.");
	w->lookup_table = table;
	return 0;
out:
	free_lookup_table(table);
	return ret;
}


/* 
 * Writes a lookup table entry to the output file.
 */
int write_lookup_table_entry(struct lookup_table_entry *lte, void *__out)
{
	FILE *out;
	u8 buf[WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE];
	u8 *p;

	out = __out;

	/* Don't write entries that have not had file resources or metadata
	 * resources written for them. */
	if (lte->out_refcnt == 0)
		return 0;

	if (lte->output_resource_entry.flags & WIM_RESHDR_FLAG_METADATA)
		DEBUG("Writing metadata entry at %lu (orig size = %zu)",
		      ftello(out), lte->output_resource_entry.original_size);

	p = put_resource_entry(buf, &lte->output_resource_entry);
	p = put_u16(p, lte->part_number);
	p = put_u32(p, lte->out_refcnt);
	p = put_bytes(p, SHA1_HASH_SIZE, lte->hash);
	if (fwrite(buf, 1, sizeof(buf), out) != sizeof(buf)) {
		ERROR_WITH_ERRNO("Failed to write lookup table entry");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}



int zero_out_refcnts(struct lookup_table_entry *entry, void *ignore)
{
	entry->out_refcnt = 0;
	return 0;
}

void print_lookup_table_entry(const struct lookup_table_entry *lte)
{
	if (!lte) {
		putchar('\n');
		return;
	}
	printf("Offset            = %"PRIu64" bytes\n", 
	       lte->resource_entry.offset);
	printf("Size              = %"PRIu64" bytes\n", 
	       (u64)lte->resource_entry.size);
	printf("Original size     = %"PRIu64" bytes\n", 
	       lte->resource_entry.original_size);
	printf("Part Number       = %hu\n", lte->part_number);
	printf("Reference Count   = %u\n", lte->refcnt);
	printf("Hash              = 0x");
	print_hash(lte->hash);
	putchar('\n');
	printf("Flags             = ");
	u8 flags = lte->resource_entry.flags;
	if (flags & WIM_RESHDR_FLAG_COMPRESSED)
		fputs("WIM_RESHDR_FLAG_COMPRESSED, ", stdout);
	if (flags & WIM_RESHDR_FLAG_FREE)
		fputs("WIM_RESHDR_FLAG_FREE, ", stdout);
	if (flags & WIM_RESHDR_FLAG_METADATA)
		fputs("WIM_RESHDR_FLAG_METADATA, ", stdout);
	if (flags & WIM_RESHDR_FLAG_SPANNED)
		fputs("WIM_RESHDR_FLAG_SPANNED, ", stdout);
	putchar('\n');
	switch (lte->resource_location) {
	case RESOURCE_IN_WIM:
		if (lte->wim->filename) {
			printf("WIM file          = `%s'\n",
			       lte->wim->filename);
		}
		break;
	case RESOURCE_IN_FILE_ON_DISK:
		printf("File on Disk      = `%s'\n", lte->file_on_disk);
		break;
	case RESOURCE_IN_STAGING_FILE:
		printf("Staging File      = `%s'\n", lte->staging_file_name);
		break;
	default:
		break;
	}
	putchar('\n');
}

static int do_print_lookup_table_entry(struct lookup_table_entry *lte,
				       void *ignore)
{
	print_lookup_table_entry(lte);
	return 0;
}

/*
 * Prints the lookup table of a WIM file. 
 */
WIMLIBAPI void wimlib_print_lookup_table(WIMStruct *w)
{
	for_lookup_table_entry(w->lookup_table, 
			       do_print_lookup_table_entry,
			       NULL);
}

/* 
 * Looks up an entry in the lookup table.
 */
struct lookup_table_entry *
__lookup_resource(const struct lookup_table *table, const u8 hash[])
{
	size_t i;
	struct lookup_table_entry *lte;
	struct hlist_node *pos;

	i = *(size_t*)hash % table->capacity;
	hlist_for_each_entry(lte, pos, &table->array[i], hash_list)
		if (hashes_equal(hash, lte->hash))
			return lte;
	return NULL;
}

/* 
 * Finds the dentry, lookup table entry, and stream index for a WIM file stream,
 * given a path name.
 *
 * This is only for pre-resolved dentries.
 */
int lookup_resource(WIMStruct *w, const char *path,
		    int lookup_flags,
		    struct dentry **dentry_ret,
		    struct lookup_table_entry **lte_ret,
		    unsigned *stream_idx_ret)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	unsigned stream_idx;
	const char *stream_name = NULL;
	char *p = NULL;

	if (lookup_flags & LOOKUP_FLAG_ADS_OK) {
		stream_name = path_stream_name(path);
		if (stream_name) {
			p = (char*)stream_name - 1;
			*p = '\0';
		}
	}

	dentry = get_dentry(w, path);
	if (p)
		*p = ':';
	if (!dentry)
		return -ENOENT;

	wimlib_assert(dentry->resolved);

	lte = dentry->lte;
	if (!(lookup_flags & LOOKUP_FLAG_DIRECTORY_OK)
	      && dentry_is_directory(dentry))
		return -EISDIR;
	stream_idx = 0;
	if (stream_name) {
		size_t stream_name_len = strlen(stream_name);
		for (u16 i = 0; i < dentry->num_ads; i++) {
			if (ads_entry_has_name(&dentry->ads_entries[i],
					       stream_name,
					       stream_name_len))
			{
				stream_idx = i + 1;
				lte = dentry->ads_entries[i].lte;
				goto out;
			}
		}
		return -ENOENT;
	}
out:
	if (dentry_ret)
		*dentry_ret = dentry;
	if (lte_ret)
		*lte_ret = lte;
	if (stream_idx_ret)
		*stream_idx_ret = stream_idx;
	return 0;
}

/* Resolve a dentry's lookup table entries 
 *
 * This replaces the SHA1 hash fields (which are used to lookup an entry in the
 * lookup table) with pointers directly to the lookup table entries.  A circular
 * linked list of streams sharing the same lookup table entry is created.
 *
 * This function always succeeds; unresolved lookup table entries are given a
 * NULL pointer.
 */
int dentry_resolve_ltes(struct dentry *dentry, void *__table)
{
	struct lookup_table *table = __table;
	struct lookup_table_entry *lte;

	if (dentry->resolved)
		return 0;

	/* Resolve the default file stream */
	lte = __lookup_resource(table, dentry->hash);
	if (lte)
		list_add(&dentry->lte_group_list.list, &lte->lte_group_list);
	else
		INIT_LIST_HEAD(&dentry->lte_group_list.list);
	dentry->lte = lte;
	dentry->lte_group_list.type = STREAM_TYPE_NORMAL;
	dentry->resolved = true;

	/* Resolve the alternate data streams */
	if (dentry->ads_entries_status != ADS_ENTRIES_USER) {
		for (u16 i = 0; i < dentry->num_ads; i++) {
			struct ads_entry *cur_entry = &dentry->ads_entries[i];

			lte = __lookup_resource(table, cur_entry->hash);
			if (lte)
				list_add(&cur_entry->lte_group_list.list,
					 &lte->lte_group_list);
			else
				INIT_LIST_HEAD(&cur_entry->lte_group_list.list);
			cur_entry->lte = lte;
			cur_entry->lte_group_list.type = STREAM_TYPE_ADS;
		}
	}
	return 0;
}

/* Return the lookup table entry for the unnamed data stream of a dentry, or
 * NULL if there is none.
 *
 * You'd think this would be easier than it actually is, since the unnamed data
 * stream should be the one referenced from the dentry itself.  Alas, if there
 * are named data streams, Microsoft's "imagex.exe" program will put the unnamed
 * data stream in one of the alternate data streams instead of inside the
 * dentry.  So we need to check the alternate data streams too.
 *
 * Also, note that a dentry may appear to have than one unnamed stream, but if
 * the SHA1 message digest is all 0's then the corresponding stream does not
 * really "count" (this is the case for the dentry's own file stream when the
 * file stream that should be there is actually in one of the alternate stream
 * entries.).  This is despite the fact that we may need to extract such a
 * missing entry as an empty file or empty named data stream.
 */
struct lookup_table_entry *
dentry_unnamed_lte(const struct dentry *dentry,
		   const struct lookup_table *table)
{
	if (dentry->resolved)
		return dentry_unnamed_lte_resolved(dentry);
	else
		return dentry_unnamed_lte_unresolved(dentry, table);
}

