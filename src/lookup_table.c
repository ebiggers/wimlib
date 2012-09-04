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
#include "lookup_table.h"
#include "io.h"
#include <errno.h>

#ifdef WITH_FUSE
#include <unistd.h>
#endif

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
	return lte;
}

void free_lookup_table_entry(struct lookup_table_entry *lte)
{
	if (lte) {
		switch (lte->resource_location) {
		case RESOURCE_IN_STAGING_FILE:
		case RESOURCE_IN_ATTACHED_BUFFER:
		case RESOURCE_IN_FILE_ON_DISK:
			wimlib_assert(((void*)&lte->file_on_disk ==
				      (void*)&lte->staging_file_name)
				      && ((void*)&lte->file_on_disk ==
				      (void*)&lte->attached_buffer));
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
		FREE(lte->extracted_file);
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
	DEBUG2("Freeing lookup table");
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

static void finalize_lte(struct lookup_table_entry *lte)
{
	#ifdef WITH_FUSE
	if (lte->resource_location == RESOURCE_IN_STAGING_FILE) {
		unlink(lte->staging_file_name);
		wimlib_assert(lte->staging_list.next);
		wimlib_assert(lte->staging_list.prev);
		list_del(&lte->staging_list);
	}
	#endif
	free_lookup_table_entry(lte);
}

/* Decrements the reference count for the lookup table entry @lte.  If its
 * reference count reaches 0, it is unlinked from the lookup table.  If,
 * furthermore, the entry has no opened file descriptors associated with it, the
 * entry is freed.  */
struct lookup_table_entry *
lte_decrement_refcnt(struct lookup_table_entry *lte, struct lookup_table *table)
{
	wimlib_assert(lte);
	wimlib_assert(lte->refcnt);
	if (--lte->refcnt == 0) {
		lookup_table_unlink(table, lte);
	#ifdef WITH_FUSE
		if (lte->num_opened_fds == 0)
	#endif
		{
			finalize_lte(lte);
			lte = NULL;
		}
	}
	return lte;
}

#ifdef WITH_FUSE
struct lookup_table_entry *
lte_decrement_num_opened_fds(struct lookup_table_entry *lte,
			     struct lookup_table *table)
{
	if (lte) {
		wimlib_assert(lte->num_opened_fds);
		if (--lte->num_opened_fds == 0 && lte->refcnt == 0) {
			lookup_table_unlink(table, lte);
			finalize_lte(lte);
			lte = NULL;
		}
	}
	return lte;
}
#endif

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
	struct lookup_table_entry *cur_entry = NULL, *duplicate_entry;

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

		if (cur_entry->part_number != w->hdr.part_number) {
			ERROR("A lookup table entry in part %hu of the WIM "
			      "points to part %hu",
			      w->hdr.part_number, cur_entry->part_number);
			ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
			goto out_free_cur_entry;
			
		}

		if (is_zero_hash(cur_entry->hash)) {
			ERROR("The WIM lookup table contains an entry with a "
			      "SHA1 message digest of all 0's");
			ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
			goto out_free_cur_entry;
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
			goto out_free_cur_entry;
		}

		if (!(cur_entry->resource_entry.flags & WIM_RESHDR_FLAG_COMPRESSED)
		    && (cur_entry->resource_entry.size !=
		      cur_entry->resource_entry.original_size))
		{
			ERROR("Found uncompressed resource with original size "
			      "not the same as compressed size");
			ERROR("The lookup table entry for the resource is as follows:");
			print_lookup_table_entry(cur_entry);
			ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
			goto out_free_cur_entry;
		}
		lookup_table_insert(table, cur_entry);

	}
	DEBUG("Done reading lookup table.");
	w->lookup_table = table;
	return 0;
out_free_cur_entry:
	FREE(cur_entry);
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


int lte_zero_real_refcnt(struct lookup_table_entry *lte, void *ignore)
{
	lte->real_refcnt = 0;
	return 0;
}

int lte_zero_out_refcnt(struct lookup_table_entry *lte, void *ignore)
{
	lte->out_refcnt = 0;
	return 0;
}

int lte_free_extracted_file(struct lookup_table_entry *lte, void *ignone)
{
	FREE(lte->extracted_file);
	lte->extracted_file = NULL;
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

	wimlib_assert(table);

	i = *(size_t*)hash % table->capacity;
	hlist_for_each_entry(lte, pos, &table->array[i], hash_list)
		if (hashes_equal(hash, lte->hash))
			return lte;
	return NULL;
}

#ifdef WITH_FUSE
/* 
 * Finds the dentry, lookup table entry, and stream index for a WIM file stream,
 * given a path name.
 *
 * This is only for pre-resolved inodes.
 */
int lookup_resource(WIMStruct *w, const char *path,
		    int lookup_flags,
		    struct dentry **dentry_ret,
		    struct lookup_table_entry **lte_ret,
		    u16 *stream_idx_ret)
{
	struct dentry *dentry;
	struct lookup_table_entry *lte;
	u16 stream_idx;
	const char *stream_name = NULL;
	struct inode *inode;
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

	inode = dentry->d_inode;

	wimlib_assert(inode->resolved);

	if (!(lookup_flags & LOOKUP_FLAG_DIRECTORY_OK)
	      && inode_is_directory(inode))
		return -EISDIR;

	if (stream_name) {
		struct ads_entry *ads_entry;
		u16 ads_idx;
		ads_entry = inode_get_ads_entry(inode, stream_name,
						&ads_idx);
		if (ads_entry) {
			stream_idx = ads_idx + 1;
			lte = ads_entry->lte;
			goto out;
		} else {
			return -ENOENT;
		}
	} else {
		lte = inode->lte;
		stream_idx = 0;
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
#endif

static void inode_resolve_ltes(struct inode *inode, struct lookup_table *table)
{
	struct lookup_table_entry *lte;

	/* Resolve the default file stream */
	lte = __lookup_resource(table, inode->hash);
	inode->lte = lte;
	inode->resolved = true;

	/* Resolve the alternate data streams */
	for (u16 i = 0; i < inode->num_ads; i++) {
		struct ads_entry *cur_entry = &inode->ads_entries[i];
		lte = __lookup_resource(table, cur_entry->hash);
		cur_entry->lte = lte;
	}
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
int dentry_resolve_ltes(struct dentry *dentry, void *table)
{
	if (!dentry->d_inode->resolved)
		inode_resolve_ltes(dentry->d_inode, table);
	return 0;
}

/* Return the lookup table entry for the unnamed data stream of an inode, or
 * NULL if there is none.
 *
 * You'd think this would be easier than it actually is, since the unnamed data
 * stream should be the one referenced from the inode itself.  Alas, if there
 * are named data streams, Microsoft's "imagex.exe" program will put the unnamed
 * data stream in one of the alternate data streams instead of inside the WIM
 * dentry itself.  So we need to check the alternate data streams too.
 *
 * Also, note that a dentry may appear to have than one unnamed stream, but if
 * the SHA1 message digest is all 0's then the corresponding stream does not
 * really "count" (this is the case for the inode's own file stream when the
 * file stream that should be there is actually in one of the alternate stream
 * entries.).  This is despite the fact that we may need to extract such a
 * missing entry as an empty file or empty named data stream.
 */
struct lookup_table_entry *
inode_unnamed_lte(const struct inode *inode,
		   const struct lookup_table *table)
{
	if (inode->resolved)
		return inode_unnamed_lte_resolved(inode);
	else
		return inode_unnamed_lte_unresolved(inode, table);
}

