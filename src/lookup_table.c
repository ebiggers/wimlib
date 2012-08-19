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

struct lookup_table *new_lookup_table(size_t capacity)
{
	struct lookup_table *table;
	struct lookup_table_entry **array;

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
	return lte;
}



/*
 * Inserts an entry into the lookup table.
 *
 * @lookup_table:	A pointer to the lookup table.
 * @entry:		A pointer to the entry to insert.
 */
void lookup_table_insert(struct lookup_table *table, 
			 struct lookup_table_entry *lte)
{
	size_t pos;
	pos = lte->hash_short % table->capacity;
	lte->next = table->array[pos];
	table->array[pos] = lte;
	/* XXX Make the table grow when too many entries have been inserted. */
	table->num_entries++;
}


/* Unlinks a lookup table entry from the table; does not free it. */
void lookup_table_unlink(struct lookup_table *table, 
			 struct lookup_table_entry *lte)
{
	size_t pos;
	struct lookup_table_entry *prev, *cur_entry, *next;

	pos = lte->hash_short % table->capacity;
	prev = NULL;
	cur_entry = table->array[pos];

	while (cur_entry) {
		next = cur_entry->next;
		if (cur_entry == lte) {
			if (prev)
				prev->next = next;
			else
				table->array[pos] = next;
			table->num_entries--;
			return;
		}
		prev = cur_entry;
		cur_entry = next;
	}
}


/* Decrement the reference count for the dentry having hash value @hash in the
 * lookup table.  The lookup table entry is unlinked and freed if there are no
 * references to in remaining.  */
bool lookup_table_decrement_refcnt(struct lookup_table* table, const u8 hash[])
{
	size_t pos = *(size_t*)hash % table->capacity;
	struct lookup_table_entry *prev = NULL;
	struct lookup_table_entry *entry = table->array[pos];
	struct lookup_table_entry *next;
	while (entry) {
		next = entry->next;
		if (memcmp(hash, entry->hash, WIM_HASH_SIZE) == 0) {
			wimlib_assert(entry->refcnt != 0);
			if (--entry->refcnt == 0) {
				if (entry->num_opened_fds == 0)
					free_lookup_table_entry(entry);
				if (prev)
					prev->next = next;
				else
					table->array[pos] = next;
				return true;
			}
		}
		prev = entry;
		entry = next;
	}
	return false;
}


/* 
 * Calls a function on all the entries in the lookup table.  Stop early and
 * return nonzero if any call to the function returns nonzero.
 */
int for_lookup_table_entry(struct lookup_table *table, 
			   int (*visitor)(struct lookup_table_entry *, void *),
			   void *arg)
{
	struct lookup_table_entry *entry, *next;
	size_t i;
	int ret;

	for (i = 0; i < table->capacity; i++) {
		entry = table->array[i];
		while (entry) {
			next = entry->next;
			ret = visitor(entry, arg);
			if (ret != 0)
				return ret;
			entry = next;
		}
	}
	return 0;
}


/*
 * Reads the lookup table from a WIM file.
 *
 * @fp:  		The FILE* for the WIM file.
 * @offset:  		The offset of the lookup table resource.
 * @size:  		The size of the lookup table resource.
 * @lookup_table_ret:  	A pointer to a struct lookup_table structure into which the
 * 				lookup table will be returned.
 * @return:		True on success, false on failure.
 */
int read_lookup_table(FILE *fp, u64 offset, u64 size, 
		      struct lookup_table **table_ret)
{
	size_t num_entries;
	u8     buf[WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE];
	int    ret;
	struct lookup_table *table;
	const u8 *p;
	struct lookup_table_entry *cur_entry;

	DEBUG("Reading lookup table: offset %"PRIu64", size %"PRIu64"",
	      offset, size);

	if (fseeko(fp, offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" to read "
				 "lookup table", offset);
		return WIMLIB_ERR_READ;
	}

	num_entries = size / WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE;
	table = new_lookup_table(num_entries * 2 + 1);
	if (!table)
		return WIMLIB_ERR_NOMEM;

	while (num_entries--) {
		if (fread(buf, 1, sizeof(buf), fp) != sizeof(buf)) {
			if (feof(fp)) {
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
			 
		p = get_resource_entry(buf, &cur_entry->resource_entry);
		p = get_u16(p, &cur_entry->part_number);
		p = get_u32(p, &cur_entry->refcnt);
		p = get_bytes(p, WIM_HASH_SIZE, cur_entry->hash);
		lookup_table_insert(table, cur_entry);
	}
	DEBUG("Done reading lookup table.");
	*table_ret = table;
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

	/* do not write lookup table entries for empty files */
	if (lte->output_resource_entry.original_size == 0)
		return 0;

	/* Don't write entries that have not had file resources or metadata
	 * resources written for them. */
	if (lte->out_refcnt == 0)
		return 0;

	if (lte->output_resource_entry.flags & WIM_RESHDR_FLAG_METADATA)
		DEBUG("Writing metadata entry at %lu", ftello(out));

	p = put_resource_entry(buf, &lte->output_resource_entry);
	p = put_u16(p, lte->part_number);
	p = put_u32(p, lte->out_refcnt);
	p = put_bytes(p, WIM_HASH_SIZE, lte->hash);
	if (fwrite(buf, 1, sizeof(buf), out) != sizeof(buf)) {
		ERROR_WITH_ERRNO("Failed to write lookup table entry");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

static int do_free_lookup_table_entry(struct lookup_table_entry *entry,
				      void *ignore)
{
	free_lookup_table_entry(entry);
	return 0;
}

void free_lookup_table(struct lookup_table *table)
{
	if (!table)
		return;
	if (table->array) {
		for_lookup_table_entry(table, do_free_lookup_table_entry, NULL);
		FREE(table->array);
	}
	FREE(table);
}

int zero_out_refcnts(struct lookup_table_entry *entry, void *ignore)
{
	entry->out_refcnt = 0;
	return 0;
}

int print_lookup_table_entry(struct lookup_table_entry *entry, void *ignore)
{
	printf("Offset            = %"PRIu64" bytes\n", 
	       entry->resource_entry.offset);
	printf("Size              = %"PRIu64" bytes\n", 
	       (u64)entry->resource_entry.size);
	printf("Original size     = %"PRIu64" bytes\n", 
	       entry->resource_entry.original_size);
	printf("Part Number       = %hu\n", entry->part_number);
	printf("Reference Count   = %u\n", entry->refcnt);
	printf("Hash              = ");
	print_hash(entry->hash);
	putchar('\n');
	printf("Flags             = ");
	u8 flags = entry->resource_entry.flags;
	if (flags & WIM_RESHDR_FLAG_COMPRESSED)
		fputs("WIM_RESHDR_FLAG_COMPRESSED, ", stdout);
	if (flags & WIM_RESHDR_FLAG_FREE)
		fputs("WIM_RESHDR_FLAG_FREE, ", stdout);
	if (flags & WIM_RESHDR_FLAG_METADATA)
		fputs("WIM_RESHDR_FLAG_METADATA, ", stdout);
	if (flags & WIM_RESHDR_FLAG_SPANNED)
		fputs("WIM_RESHDR_FLAG_SPANNED, ", stdout);
	putchar('\n');
	if (entry->file_on_disk)
		printf("File on Disk      = `%s'\n", entry->file_on_disk);
	putchar('\n');
	return 0;
}

/*
 * Prints the lookup table of a WIM file. 
 */
WIMLIBAPI void wimlib_print_lookup_table(WIMStruct *w)
{
	for_lookup_table_entry(w->lookup_table, 
			       print_lookup_table_entry, NULL);
}

/* 
 * Looks up an entry in the lookup table.
 */
struct lookup_table_entry *
__lookup_resource(const struct lookup_table *lookup_table, const u8 hash[])
{
	size_t pos;
	struct lookup_table_entry *lte;

	pos = *(size_t*)hash % lookup_table->capacity;
	lte = lookup_table->array[pos];
	while (lte) {
		if (memcmp(hash, lte->hash, WIM_HASH_SIZE) == 0)
			return lte;
		lte = lte->next;
	}
	return NULL;
}

int lookup_resource(WIMStruct *w, const char *path,
		    int lookup_flags,
		    struct dentry **dentry_ret,
		    struct lookup_table_entry **lte_ret,
		    u8 **hash_ret)
{
	struct dentry *dentry = get_dentry(w, path);
	struct lookup_table_entry *lte;
	u8 *hash;
	if (!dentry)
		return -ENOENT;
	if (!(lookup_flags & LOOKUP_FLAG_DIRECTORY_OK)
	      && dentry_is_directory(dentry))
		return -EISDIR;
	if (lookup_flags & LOOKUP_FLAG_ADS_OK) {
		const char *stream_name = path_stream_name(path);
		if (stream_name) {
			for (u16 i = 0; i < dentry->num_ads; i++) {
				if (strcmp(stream_name, dentry->ads_entries[i].stream_name) == 0) {
					hash = dentry->ads_entries[i].hash;
					goto do_lookup;
				}
			}
			return -ENOENT;
		}
	}
	hash = dentry->hash;
do_lookup:
	lte = __lookup_resource(w->lookup_table, hash);
	if (dentry_ret)
		*dentry_ret = dentry;
	if (lte_ret)
		*lte_ret = lte;
	if (hash_ret)
		*hash_ret = hash;
	return 0;
}
