/*
 * lookup_table.c
 *
 * Lookup table, implemented as a hash table, that maps SHA1 message digests to
 * data streams.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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
#include "buffer_io.h"
#include <errno.h>

#ifdef WITH_FUSE
#include <unistd.h>
#endif

struct wim_lookup_table *new_lookup_table(size_t capacity)
{
	struct wim_lookup_table *table;
	struct hlist_head *array;

	table = MALLOC(sizeof(struct wim_lookup_table));
	if (table) {
		array = CALLOC(capacity, sizeof(array[0]));
		if (array) {
			table->num_entries = 0;
			table->capacity = capacity;
			table->array = array;
		} else {
			FREE(table);
			table = NULL;
			ERROR("Failed to allocate memory for lookup table with capacity %zu",
			      capacity);
		}
	}
	return table;
}

struct wim_lookup_table_entry *
new_lookup_table_entry()
{
	struct wim_lookup_table_entry *lte;

	lte = CALLOC(1, sizeof(struct wim_lookup_table_entry));
	if (lte) {
		lte->part_number  = 1;
		lte->refcnt       = 1;
	} else {
		ERROR("Out of memory (tried to allocate %zu bytes for "
		      "lookup table entry)",
		      sizeof(struct wim_lookup_table_entry));
	}
	return lte;
}

struct wim_lookup_table_entry *
clone_lookup_table_entry(const struct wim_lookup_table_entry *old)
{
	struct wim_lookup_table_entry *new;

	new = MALLOC(sizeof(*new));
	if (!new)
		return NULL;

	memcpy(new, old, sizeof(*old));
	new->extracted_file = NULL;
	switch (new->resource_location) {
	case RESOURCE_WIN32:
	case RESOURCE_IN_STAGING_FILE:
	case RESOURCE_IN_FILE_ON_DISK:
		BUILD_BUG_ON((void*)&old->file_on_disk !=
			     (void*)&old->staging_file_name);
		new->staging_file_name = TSTRDUP(old->staging_file_name);
		if (!new->staging_file_name)
			goto out_free;
		break;
	case RESOURCE_IN_ATTACHED_BUFFER:
		new->attached_buffer = MALLOC(wim_resource_size(old));
		if (!new->attached_buffer)
			goto out_free;
		memcpy(new->attached_buffer, old->attached_buffer,
		       wim_resource_size(old));
		break;
#ifdef WITH_NTFS_3G
	case RESOURCE_IN_NTFS_VOLUME:
		if (old->ntfs_loc) {
			struct ntfs_location *loc;
			loc = MALLOC(sizeof(*loc));
			if (!loc)
				goto out_free;
			memcpy(loc, old->ntfs_loc, sizeof(*loc));
			loc->path = NULL;
			loc->stream_name = NULL;
			new->ntfs_loc = loc;
			loc->path = STRDUP(old->ntfs_loc->path);
			if (!loc->path)
				goto out_free;
			loc->stream_name = MALLOC((loc->stream_name_nchars + 1) * 2);
			if (!loc->stream_name)
				goto out_free;
			memcpy(loc->stream_name,
			       old->ntfs_loc->stream_name,
			       (loc->stream_name_nchars + 1) * 2);
		}
		break;
#endif
	default:
		break;
	}
	return new;
out_free:
	free_lookup_table_entry(new);
	return NULL;
}

void free_lookup_table_entry(struct wim_lookup_table_entry *lte)
{
	if (lte) {
		switch (lte->resource_location) {
		case RESOURCE_IN_STAGING_FILE:
		case RESOURCE_IN_ATTACHED_BUFFER:
		case RESOURCE_IN_FILE_ON_DISK:
#ifdef __WIN32__
		case RESOURCE_WIN32:
#endif
			BUILD_BUG_ON((void*)&lte->file_on_disk !=
				     (void*)&lte->staging_file_name);
			BUILD_BUG_ON((void*)&lte->file_on_disk !=
				     (void*)&lte->attached_buffer);
			FREE(lte->file_on_disk);
			break;
#ifdef WITH_NTFS_3G
		case RESOURCE_IN_NTFS_VOLUME:
			if (lte->ntfs_loc) {
				FREE(lte->ntfs_loc->path);
				FREE(lte->ntfs_loc->stream_name);
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

static int do_free_lookup_table_entry(struct wim_lookup_table_entry *entry,
				      void *ignore)
{
	free_lookup_table_entry(entry);
	return 0;
}


void free_lookup_table(struct wim_lookup_table *table)
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
 * @lte:	A pointer to the entry to insert.
 */
void lookup_table_insert(struct wim_lookup_table *table,
			 struct wim_lookup_table_entry *lte)
{
	size_t i = lte->hash_short % table->capacity;
	hlist_add_head(&lte->hash_list, &table->array[i]);

	/* XXX Make the table grow when too many entries have been inserted. */
	table->num_entries++;
}

static void finalize_lte(struct wim_lookup_table_entry *lte)
{
	#ifdef WITH_FUSE
	if (lte->resource_location == RESOURCE_IN_STAGING_FILE) {
		unlink(lte->staging_file_name);
		list_del(&lte->staging_list);
	}
	#endif
	free_lookup_table_entry(lte);
}

/* Decrements the reference count for the lookup table entry @lte.  If its
 * reference count reaches 0, it is unlinked from the lookup table.  If,
 * furthermore, the entry has no opened file descriptors associated with it, the
 * entry is freed.  */
void lte_decrement_refcnt(struct wim_lookup_table_entry *lte,
			  struct wim_lookup_table *table)
{
	wimlib_assert(lte != NULL);
	wimlib_assert(lte->refcnt != 0);
	if (--lte->refcnt == 0) {
		lookup_table_unlink(table, lte);
	#ifdef WITH_FUSE
		if (lte->num_opened_fds == 0)
	#endif
			finalize_lte(lte);
	}
}

#ifdef WITH_FUSE
void lte_decrement_num_opened_fds(struct wim_lookup_table_entry *lte)
{
	if (lte->num_opened_fds != 0)
		if (--lte->num_opened_fds == 0 && lte->refcnt == 0)
			finalize_lte(lte);
}
#endif

/* Calls a function on all the entries in the WIM lookup table.  Stop early and
 * return nonzero if any call to the function returns nonzero. */
int for_lookup_table_entry(struct wim_lookup_table *table,
			   int (*visitor)(struct wim_lookup_table_entry *, void *),
			   void *arg)
{
	struct wim_lookup_table_entry *lte;
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
	u64 num_entries;
	u8 buf[WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE];
	int ret;
	struct wim_lookup_table *table;
	struct wim_lookup_table_entry *cur_entry = NULL, *duplicate_entry;

	if (resource_is_compressed(&w->hdr.lookup_table_res_entry)) {
		ERROR("Didn't expect a compressed lookup table!");
		ERROR("Ask the author to implement support for this.");
		return WIMLIB_ERR_COMPRESSED_LOOKUP_TABLE;
	}

	DEBUG("Reading lookup table: offset %"PRIu64", size %"PRIu64"",
	      w->hdr.lookup_table_res_entry.offset,
	      w->hdr.lookup_table_res_entry.original_size);

	if (fseeko(w->fp, w->hdr.lookup_table_res_entry.offset, SEEK_SET) != 0)
	{
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

		/* Ordinarily, no two streams should share the same SHA1 message
		 * digest.  However, this constraint can be broken for metadata
		 * resources--- two identical images will have the same metadata
		 * resource, but their lookup table entries are not shared. */
		duplicate_entry = __lookup_resource(table, cur_entry->hash);
		if (duplicate_entry
		    && !((duplicate_entry->resource_entry.flags & WIM_RESHDR_FLAG_METADATA)
			  && cur_entry->resource_entry.flags & WIM_RESHDR_FLAG_METADATA))
		{
		#ifdef ENABLE_ERROR_MESSAGES
			ERROR("The WIM lookup table contains two entries with the "
			      "same SHA1 message digest!");
			ERROR("The first entry is:");
			print_lookup_table_entry(duplicate_entry, stderr);
			ERROR("The second entry is:");
			print_lookup_table_entry(cur_entry, stderr);
		#endif
			ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
			goto out_free_cur_entry;
		}

		if (!(cur_entry->resource_entry.flags & WIM_RESHDR_FLAG_COMPRESSED)
		    && (cur_entry->resource_entry.size !=
		        cur_entry->resource_entry.original_size))
		{
		#ifdef ENABLE_ERROR_MESSAGES
			ERROR("Found uncompressed resource with original size "
			      "not the same as compressed size");
			ERROR("The lookup table entry for the resource is as follows:");
			print_lookup_table_entry(cur_entry, stderr);
		#endif
			ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
			goto out_free_cur_entry;
		}
		if ((cur_entry->resource_entry.flags & WIM_RESHDR_FLAG_METADATA)
		    && cur_entry->refcnt != 1)
		{
		#ifdef ENABLE_ERROR_MESSAGES
			ERROR("Found metadata resource with refcnt != 1:");
			print_lookup_table_entry(cur_entry, stderr);
		#endif
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
int write_lookup_table_entry(struct wim_lookup_table_entry *lte, void *__out)
{
	FILE *out;
	u8 buf[WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE];
	u8 *p;

	out = __out;

	/* Don't write entries that have not had file resources or metadata
	 * resources written for them. */
	if (lte->out_refcnt == 0)
		return 0;

	if (lte->output_resource_entry.flags & WIM_RESHDR_FLAG_METADATA) {
		DEBUG("Writing metadata entry at %"PRIu64" "
		      "(orig size = %"PRIu64")",
		      ftello(out), lte->output_resource_entry.original_size);
	}

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

/* Writes the lookup table to the output file. */
int write_lookup_table(struct wim_lookup_table *table, FILE *out,
		       struct resource_entry *out_res_entry)
{
	off_t start_offset, end_offset;
	int ret;

	start_offset = ftello(out);
	if (start_offset == -1)
		return WIMLIB_ERR_WRITE;

	ret = for_lookup_table_entry(table, write_lookup_table_entry, out);
	if (ret != 0)
		return ret;

	end_offset = ftello(out);
	if (end_offset == -1)
		return WIMLIB_ERR_WRITE;

	out_res_entry->offset        = start_offset;
	out_res_entry->size          = end_offset - start_offset;
	out_res_entry->original_size = end_offset - start_offset;
	out_res_entry->flags         = WIM_RESHDR_FLAG_METADATA;

	return 0;
}


int lte_zero_real_refcnt(struct wim_lookup_table_entry *lte, void *ignore)
{
	lte->real_refcnt = 0;
	return 0;
}

int lte_zero_out_refcnt(struct wim_lookup_table_entry *lte, void *ignore)
{
	lte->out_refcnt = 0;
	return 0;
}

int lte_free_extracted_file(struct wim_lookup_table_entry *lte, void *ignore)
{
	if (lte->extracted_file != NULL) {
		FREE(lte->extracted_file);
		lte->extracted_file = NULL;
	}
	return 0;
}

void print_lookup_table_entry(const struct wim_lookup_table_entry *lte,
			      FILE *out)
{
	if (!lte) {
		tputc(T('\n'), out);
		return;
	}
	tfprintf(out, T("Offset            = %"PRIu64" bytes\n"),
		 lte->resource_entry.offset);

	tfprintf(out, T("Size              = %"PRIu64" bytes\n"),
		 (u64)lte->resource_entry.size);

	tfprintf(out, T("Original size     = %"PRIu64" bytes\n"),
		 lte->resource_entry.original_size);

	tfprintf(out, T("Part Number       = %hu\n"), lte->part_number);
	tfprintf(out, T("Reference Count   = %u\n"), lte->refcnt);

	tfprintf(out, T("Hash              = 0x"));
	print_hash(lte->hash);
	tputc(T('\n'), out);

	tfprintf(out, T("Flags             = "));
	u8 flags = lte->resource_entry.flags;
	if (flags & WIM_RESHDR_FLAG_COMPRESSED)
		tfputs(T("WIM_RESHDR_FLAG_COMPRESSED, "), out);
	if (flags & WIM_RESHDR_FLAG_FREE)
		tfputs(T("WIM_RESHDR_FLAG_FREE, "), out);
	if (flags & WIM_RESHDR_FLAG_METADATA)
		tfputs(T("WIM_RESHDR_FLAG_METADATA, "), out);
	if (flags & WIM_RESHDR_FLAG_SPANNED)
		tfputs(T("WIM_RESHDR_FLAG_SPANNED, "), out);
	tputc(T('\n'), out);
	switch (lte->resource_location) {
	case RESOURCE_IN_WIM:
		if (lte->wim->filename) {
			tfprintf(out, T("WIM file          = `%"TS"'\n"),
				 lte->wim->filename);
		}
		break;
	case RESOURCE_IN_FILE_ON_DISK:
		tfprintf(out, T("File on Disk      = `%"TS"'\n"),
			 lte->file_on_disk);
		break;
	case RESOURCE_IN_STAGING_FILE:
		tfprintf(out, T("Staging File      = `%"TS"'\n"),
				lte->staging_file_name);
		break;
	default:
		break;
	}
	tputc(T('\n'), out);
}

static int do_print_lookup_table_entry(struct wim_lookup_table_entry *lte,
				       void *fp)
{
	print_lookup_table_entry(lte, (FILE*)fp);
	return 0;
}

/*
 * Prints the lookup table of a WIM file.
 */
WIMLIBAPI void wimlib_print_lookup_table(WIMStruct *w)
{
	for_lookup_table_entry(w->lookup_table,
			       do_print_lookup_table_entry,
			       stdout);
}

/* Given a SHA1 message digest, return the corresponding entry in the WIM's
 * lookup table, or NULL if there is none.  */
struct wim_lookup_table_entry *
__lookup_resource(const struct wim_lookup_table *table, const u8 hash[])
{
	size_t i;
	struct wim_lookup_table_entry *lte;
	struct hlist_node *pos;

	wimlib_assert(table != NULL);
	wimlib_assert(hash != NULL);

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
int
lookup_resource(WIMStruct *w,
		const tchar *path,
		int lookup_flags,
		struct wim_dentry **dentry_ret,
		struct wim_lookup_table_entry **lte_ret,
		u16 *stream_idx_ret)
{
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	u16 stream_idx;
	const tchar *stream_name = NULL;
	struct wim_inode *inode;
	tchar *p = NULL;

	if (lookup_flags & LOOKUP_FLAG_ADS_OK) {
		stream_name = path_stream_name(path);
		if (stream_name) {
			p = (tchar*)stream_name - 1;
			*p = T('\0');
		}
	}

	dentry = get_dentry(w, path);
	if (p)
		*p = T(':');
	if (!dentry)
		return -errno;

	inode = dentry->d_inode;

	wimlib_assert(inode->i_resolved);

	if (!(lookup_flags & LOOKUP_FLAG_DIRECTORY_OK)
	      && inode_is_directory(inode))
		return -EISDIR;

	if (stream_name) {
		struct wim_ads_entry *ads_entry;
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
		lte = inode->i_lte;
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

/* Resolve an inode's lookup table entries
 *
 * This replaces the SHA1 hash fields (which are used to lookup an entry in the
 * lookup table) with pointers directly to the lookup table entries.  A circular
 * linked list of streams sharing the same lookup table entry is created.
 *
 * This function always succeeds; unresolved lookup table entries are given a
 * NULL pointer.
 */
void inode_resolve_ltes(struct wim_inode *inode, struct wim_lookup_table *table)
{

	if (!inode->i_resolved) {
		struct wim_lookup_table_entry *lte;
		/* Resolve the default file stream */
		lte = __lookup_resource(table, inode->i_hash);
		inode->i_lte = lte;
		inode->i_resolved = 1;

		/* Resolve the alternate data streams */
		for (u16 i = 0; i < inode->i_num_ads; i++) {
			struct wim_ads_entry *cur_entry = &inode->i_ads_entries[i];
			lte = __lookup_resource(table, cur_entry->hash);
			cur_entry->lte = lte;
		}
	}
}

void inode_unresolve_ltes(struct wim_inode *inode)
{
	if (inode->i_resolved) {
		if (inode->i_lte)
			copy_hash(inode->i_hash, inode->i_lte->hash);
		else
			zero_out_hash(inode->i_hash);

		for (u16 i = 0; i < inode->i_num_ads; i++) {
			if (inode->i_ads_entries[i].lte)
				copy_hash(inode->i_ads_entries[i].hash,
					  inode->i_ads_entries[i].lte->hash);
			else
				zero_out_hash(inode->i_ads_entries[i].hash);
		}
		inode->i_resolved = 0;
	}
}

/*
 * Returns the lookup table entry for stream @stream_idx of the inode, where
 * stream_idx = 0 means the default un-named file stream, and stream_idx >= 1
 * corresponds to an alternate data stream.
 *
 * This works for both resolved and un-resolved dentries.
 */
struct wim_lookup_table_entry *
inode_stream_lte(const struct wim_inode *inode, unsigned stream_idx,
		 const struct wim_lookup_table *table)
{
	if (inode->i_resolved)
		return inode_stream_lte_resolved(inode, stream_idx);
	else
		return inode_stream_lte_unresolved(inode, stream_idx, table);
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
 * Also, note that a dentry may appear to have more than one unnamed stream, but
 * if the SHA1 message digest is all 0's then the corresponding stream does not
 * really "count" (this is the case for the inode's own file stream when the
 * file stream that should be there is actually in one of the alternate stream
 * entries.).  This is despite the fact that we may need to extract such a
 * missing entry as an empty file or empty named data stream.
 */
struct wim_lookup_table_entry *
inode_unnamed_lte(const struct wim_inode *inode,
		  const struct wim_lookup_table *table)
{
	if (inode->i_resolved)
		return inode_unnamed_lte_resolved(inode);
	else
		return inode_unnamed_lte_unresolved(inode, table);
}

static int lte_add_stream_size(struct wim_lookup_table_entry *lte,
			       void *total_bytes_p)
{
	*(u64*)total_bytes_p += lte->resource_entry.size;
	return 0;
}

u64 lookup_table_total_stream_size(struct wim_lookup_table *table)
{
	u64 total_size = 0;
	for_lookup_table_entry(table, lte_add_stream_size, &total_size);
	return total_size;
}
