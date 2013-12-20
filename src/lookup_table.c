/*
 * lookup_table.c
 *
 * Lookup table, implemented as a hash table, that maps SHA1 message digests to
 * data streams; plus code to read and write the corresponding on-disk data.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/glob.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/resource.h"
#include "wimlib/util.h"
#include "wimlib/write.h"

#include <errno.h>
#include <stdlib.h>
#ifdef WITH_FUSE
#  include <unistd.h> /* for unlink() */
#endif

struct wim_lookup_table *
new_lookup_table(size_t capacity)
{
	struct wim_lookup_table *table;
	struct hlist_head *array;

	table = CALLOC(1, sizeof(struct wim_lookup_table));
	if (table) {
		array = CALLOC(capacity, sizeof(array[0]));
		if (array) {
			table->num_entries = 0;
			table->capacity = capacity;
			table->array = array;
		} else {
			FREE(table);
			table = NULL;
			ERROR("Failed to allocate memory for lookup table "
			      "with capacity %zu", capacity);
		}
	}
	return table;
}

struct wim_lookup_table_entry *
new_lookup_table_entry(void)
{
	struct wim_lookup_table_entry *lte;

	lte = CALLOC(1, sizeof(struct wim_lookup_table_entry));
	if (lte == NULL) {
		ERROR("Out of memory (tried to allocate %zu bytes for "
		      "lookup table entry)",
		      sizeof(struct wim_lookup_table_entry));
		return NULL;
	}
	lte->refcnt = 1;
	BUILD_BUG_ON(RESOURCE_NONEXISTENT != 0);
	return lte;
}

struct wim_lookup_table_entry *
clone_lookup_table_entry(const struct wim_lookup_table_entry *old)
{
	struct wim_lookup_table_entry *new;

	new = memdup(old, sizeof(struct wim_lookup_table_entry));
	if (!new)
		return NULL;

	new->extracted_file = NULL;
	switch (new->resource_location) {
	case RESOURCE_IN_WIM:
		list_add(&new->wim_resource_list, &new->rspec->lte_list);
		break;

	case RESOURCE_IN_FILE_ON_DISK:
#ifdef __WIN32__
	case RESOURCE_WIN32_ENCRYPTED:
#endif
#ifdef WITH_FUSE
	case RESOURCE_IN_STAGING_FILE:
		BUILD_BUG_ON((void*)&old->file_on_disk !=
			     (void*)&old->staging_file_name);
#endif
		new->file_on_disk = TSTRDUP(old->file_on_disk);
		if (!new->file_on_disk)
			goto out_free;
		break;
	case RESOURCE_IN_ATTACHED_BUFFER:
		new->attached_buffer = memdup(old->attached_buffer, old->size);
		if (!new->attached_buffer)
			goto out_free;
		break;
#ifdef WITH_NTFS_3G
	case RESOURCE_IN_NTFS_VOLUME:
		if (old->ntfs_loc) {
			struct ntfs_location *loc;
			loc = memdup(old->ntfs_loc, sizeof(struct ntfs_location));
			if (!loc)
				goto out_free;
			loc->path = NULL;
			loc->stream_name = NULL;
			new->ntfs_loc = loc;
			loc->path = STRDUP(old->ntfs_loc->path);
			if (!loc->path)
				goto out_free;
			if (loc->stream_name_nchars) {
				loc->stream_name = memdup(old->ntfs_loc->stream_name,
							  loc->stream_name_nchars * 2);
				if (!loc->stream_name)
					goto out_free;
			}
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

void
free_lookup_table_entry(struct wim_lookup_table_entry *lte)
{
	if (lte) {
		switch (lte->resource_location) {
		case RESOURCE_IN_WIM:
			list_del(&lte->wim_resource_list);
			if (list_empty(&lte->rspec->lte_list))
				FREE(lte->rspec);
			break;
		case RESOURCE_IN_FILE_ON_DISK:
	#ifdef __WIN32__
		case RESOURCE_WIN32_ENCRYPTED:
	#endif
	#ifdef WITH_FUSE
		case RESOURCE_IN_STAGING_FILE:
			BUILD_BUG_ON((void*)&lte->file_on_disk !=
				     (void*)&lte->staging_file_name);
	#endif
		case RESOURCE_IN_ATTACHED_BUFFER:
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

static int
do_free_lookup_table_entry(struct wim_lookup_table_entry *entry, void *ignore)
{
	free_lookup_table_entry(entry);
	return 0;
}


void
free_lookup_table(struct wim_lookup_table *table)
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
void
lookup_table_insert(struct wim_lookup_table *table,
		    struct wim_lookup_table_entry *lte)
{
	size_t i = lte->hash_short % table->capacity;
	hlist_add_head(&lte->hash_list, &table->array[i]);

	/* XXX Make the table grow when too many entries have been inserted. */
	table->num_entries++;
}

static void
finalize_lte(struct wim_lookup_table_entry *lte)
{
	#ifdef WITH_FUSE
	if (lte->resource_location == RESOURCE_IN_STAGING_FILE) {
		unlink(lte->staging_file_name);
		list_del(&lte->unhashed_list);
	}
	#endif
	free_lookup_table_entry(lte);
}

/* Decrements the reference count for the lookup table entry @lte.  If its
 * reference count reaches 0, it is unlinked from the lookup table.  If,
 * furthermore, the entry has no opened file descriptors associated with it, the
 * entry is freed.  */
void
lte_decrement_refcnt(struct wim_lookup_table_entry *lte,
		     struct wim_lookup_table *table)
{
	wimlib_assert(lte != NULL);
	wimlib_assert(lte->refcnt != 0);
	if (--lte->refcnt == 0) {
		if (lte->unhashed)
			list_del(&lte->unhashed_list);
		else
			lookup_table_unlink(table, lte);
	#ifdef WITH_FUSE
		if (lte->num_opened_fds == 0)
	#endif
			finalize_lte(lte);
	}
}

#ifdef WITH_FUSE
void
lte_decrement_num_opened_fds(struct wim_lookup_table_entry *lte)
{
	if (lte->num_opened_fds != 0)
		if (--lte->num_opened_fds == 0 && lte->refcnt == 0)
			finalize_lte(lte);
}
#endif

/* Calls a function on all the entries in the WIM lookup table.  Stop early and
 * return nonzero if any call to the function returns nonzero. */
int
for_lookup_table_entry(struct wim_lookup_table *table,
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
			wimlib_assert2(!(lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA));
			ret = visitor(lte, arg);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/* qsort() callback that sorts streams (represented by `struct
 * wim_lookup_table_entry's) into an order optimized for reading and writing.
 *
 * Sorting is done primarily by resource location, then secondarily by a
 * per-resource location order.  For example, resources in WIM files are sorted
 * primarily by part number, then secondarily by offset, as to implement optimal
 * reading of either a standalone or split WIM.  */
static int
cmp_streams_by_sequential_order(const void *p1, const void *p2)
{
	const struct wim_lookup_table_entry *lte1, *lte2;
	int v;
	WIMStruct *wim1, *wim2;
	u64 offset1, offset2;

	lte1 = *(const struct wim_lookup_table_entry**)p1;
	lte2 = *(const struct wim_lookup_table_entry**)p2;

	v = (int)lte1->resource_location - (int)lte2->resource_location;

	/* Different resource locations?  */
	if (v)
		return v;

	switch (lte1->resource_location) {
	case RESOURCE_IN_WIM:
		wim1 = lte1->rspec->wim;
		wim2 = lte2->rspec->wim;

		/* Different (possibly split) WIMs?  */
		if (wim1 != wim2) {
			v = memcmp(wim1->hdr.guid, wim2->hdr.guid, WIM_GID_LEN);
			if (v)
				return v;
		}

		/* Different part numbers in the same WIM?  */
		v = (int)wim1->hdr.part_number - (int)wim2->hdr.part_number;
		if (v)
			return v;

		/* Compare by offset.  */
		offset1 = lte1->rspec->offset_in_wim + lte1->offset_in_res;
		offset2 = lte2->rspec->offset_in_wim + lte2->offset_in_res;

		if (offset1 < offset2)
			return -1;
		if (offset1 > offset2)
			return 1;
		return 0;
	case RESOURCE_IN_FILE_ON_DISK:
#ifdef WITH_FUSE
	case RESOURCE_IN_STAGING_FILE:
#endif
#ifdef __WIN32__
	case RESOURCE_WIN32_ENCRYPTED:
#endif
		/* Compare files by path: just a heuristic that will place files
		 * in the same directory next to each other.  */
		return tstrcmp(lte1->file_on_disk, lte2->file_on_disk);
#ifdef WITH_NTFS_3G
	case RESOURCE_IN_NTFS_VOLUME:
		return tstrcmp(lte1->ntfs_loc->path, lte2->ntfs_loc->path);
#endif
	default:
		/* No additional sorting order defined for this resource
		 * location (e.g. RESOURCE_IN_ATTACHED_BUFFER); simply compare
		 * everything equal to each other.  */
		return 0;
	}
}

int
sort_stream_list_by_sequential_order(struct list_head *stream_list,
				     size_t list_head_offset)
{
	struct list_head *cur;
	struct wim_lookup_table_entry **array;
	size_t i;
	size_t array_size;
	size_t num_streams = 0;

	list_for_each(cur, stream_list)
		num_streams++;

	array_size = num_streams * sizeof(array[0]);
	array = MALLOC(array_size);
	if (array == NULL)
		return WIMLIB_ERR_NOMEM;
	cur = stream_list->next;
	for (i = 0; i < num_streams; i++) {
		array[i] = (struct wim_lookup_table_entry*)((u8*)cur -
							    list_head_offset);
		cur = cur->next;
	}

	qsort(array, num_streams, sizeof(array[0]),
	      cmp_streams_by_sequential_order);

	INIT_LIST_HEAD(stream_list);
	for (i = 0; i < num_streams; i++) {
		list_add_tail((struct list_head*)
			       ((u8*)array[i] + list_head_offset),
			      stream_list);
	}
	FREE(array);
	return 0;
}


static int
add_lte_to_array(struct wim_lookup_table_entry *lte,
		 void *_pp)
{
	struct wim_lookup_table_entry ***pp = _pp;
	*(*pp)++ = lte;
	return 0;
}

/* Iterate through the lookup table entries, but first sort them by stream
 * offset in the WIM.  Caution: this is intended to be used when the stream
 * offset field has actually been set. */
int
for_lookup_table_entry_pos_sorted(struct wim_lookup_table *table,
				  int (*visitor)(struct wim_lookup_table_entry *,
						 void *),
				  void *arg)
{
	struct wim_lookup_table_entry **lte_array, **p;
	size_t num_streams = table->num_entries;
	int ret;

	lte_array = MALLOC(num_streams * sizeof(lte_array[0]));
	if (!lte_array)
		return WIMLIB_ERR_NOMEM;
	p = lte_array;
	for_lookup_table_entry(table, add_lte_to_array, &p);

	wimlib_assert(p == lte_array + num_streams);

	qsort(lte_array, num_streams, sizeof(lte_array[0]),
	      cmp_streams_by_sequential_order);
	ret = 0;
	for (size_t i = 0; i < num_streams; i++) {
		ret = visitor(lte_array[i], arg);
		if (ret)
			break;
	}
	FREE(lte_array);
	return ret;
}

/* On-disk format of a WIM lookup table entry (stream entry). */
struct wim_lookup_table_entry_disk {
	/* Size, offset, and flags of the stream.  */
	struct wim_reshdr_disk reshdr;

	/* Which part of the split WIM this stream is in; indexed from 1. */
	le16 part_number;

	/* Reference count of this stream over all WIM images. */
	le32 refcnt;

	/* SHA1 message digest of the uncompressed data of this stream, or
	 * optionally all zeroes if this stream is of zero length. */
	u8 hash[SHA1_HASH_SIZE];
} _packed_attribute;

#define WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE 50

static int
validate_resource(const struct wim_resource_spec *rspec)
{
	struct wim_lookup_table_entry *lte;
	if (!list_is_singular(&rspec->lte_list)) {
		list_for_each_entry(lte, &rspec->lte_list, wim_resource_list) {
			if (rspec->flags & WIM_RESHDR_FLAG_COMPRESSED)
				lte->flags |= WIM_RESHDR_FLAG_COMPRESSED;
			else
				lte->flags &= ~WIM_RESHDR_FLAG_COMPRESSED;

			if (lte->offset_in_res + lte->size < lte->size ||
			    lte->offset_in_res + lte->size > rspec->uncompressed_size)
			{
				return WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
			}
		}
	}
	return 0;
}

/*
 * Reads the lookup table from a WIM file.
 *
 * Saves lookup table entries for non-metadata streams in a hash table, and
 * saves the metadata entry for each image in a special per-image location (the
 * image_metadata array).
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY
 *	WIMLIB_ERR_RESOURCE_NOT_FOUND
 */
int
read_wim_lookup_table(WIMStruct *wim)
{
	int ret;
	size_t i;
	size_t num_entries;
	struct wim_lookup_table *table;
	struct wim_lookup_table_entry *cur_entry, *duplicate_entry;
	struct wim_resource_spec *cur_rspec;
	void *buf;

	BUILD_BUG_ON(sizeof(struct wim_lookup_table_entry_disk) !=
		     WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE);

	DEBUG("Reading lookup table.");

	/* Calculate number of entries in the lookup table.  */
	num_entries = wim->hdr.lookup_table_reshdr.uncompressed_size /
		      sizeof(struct wim_lookup_table_entry_disk);

	/* Read the lookup table into a buffer.  */
	ret = wim_reshdr_to_data(&wim->hdr.lookup_table_reshdr, wim, &buf);
	if (ret)
		goto out;

	/* Allocate hash table.  */
	table = new_lookup_table(num_entries * 2 + 1);
	if (table == NULL) {
		ERROR("Not enough memory to read lookup table.");
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_buf;
	}

	/* Allocate and initalize `struct wim_lookup_table_entry's from the
	 * on-disk lookup table.  */
	wim->current_image = 0;
	cur_rspec = NULL;
	for (i = 0; i < num_entries; i++) {
		const struct wim_lookup_table_entry_disk *disk_entry =
			&((const struct wim_lookup_table_entry_disk*)buf)[i];
		u16 part_number;
		struct wim_reshdr reshdr;

		ret = get_wim_reshdr(&disk_entry->reshdr, &reshdr);
		if (ret) {
			ERROR("Resource header is invalid!");
			goto out_free_lookup_table;
		}

		DEBUG("reshdr: size_in_wim=%"PRIu64", "
		      "uncompressed_size=%"PRIu64", "
		      "offset_in_wim=%"PRIu64", "
		      "flags=0x%02x",
		      reshdr.size_in_wim, reshdr.uncompressed_size,
		      reshdr.offset_in_wim, reshdr.flags);

		cur_entry = new_lookup_table_entry();
		if (cur_entry == NULL) {
			ERROR("Not enough memory to read lookup table!");
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_lookup_table;
		}

		part_number = le16_to_cpu(disk_entry->part_number);
		cur_entry->refcnt = le32_to_cpu(disk_entry->refcnt);
		copy_hash(cur_entry->hash, disk_entry->hash);

		if (part_number != wim->hdr.part_number) {
			WARNING("A lookup table entry in part %hu of the WIM "
				"points to part %hu (ignoring it)",
				wim->hdr.part_number, part_number);
			free_lookup_table_entry(cur_entry);
			continue;
		}

		if (cur_rspec == NULL ||
		    !(reshdr.flags & WIM_RESHDR_FLAG_CONCAT))
		{
			/* Starting new run of stream entries that all share the
			 * same WIM resource (streams concatenated together); or
			 * simply a single normal entry by itself.  */

			if (cur_rspec != NULL) {
				ret = validate_resource(cur_rspec);
				if (ret)
					goto out_free_cur_entry;
			}

			cur_rspec = MALLOC(sizeof(struct wim_resource_spec));
			if (cur_rspec == NULL) {
				ERROR("Not enough memory to read lookup table!");
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_cur_entry;
			}
			wim_res_hdr_to_spec(&reshdr, wim, cur_rspec);
			if (reshdr.flags & WIM_RESHDR_FLAG_CONCAT) {
				cur_rspec->size_in_wim = 0;
				cur_rspec->uncompressed_size = 0;
			}
		} else if (is_zero_hash(cur_entry->hash)) {
			/* Found the resource specification for the run.  */
			cur_rspec->offset_in_wim = reshdr.offset_in_wim;
			cur_rspec->size_in_wim = reshdr.size_in_wim;
			cur_rspec->flags = reshdr.flags;
			DEBUG("Full run is %"PRIu64" compressed bytes "
			      "at file offset %"PRIu64" (flags 0x%02x)",
			      cur_rspec->size_in_wim,
			      cur_rspec->offset_in_wim,
			      cur_rspec->flags);
			free_lookup_table_entry(cur_entry);
			continue;
		}

		if (reshdr.flags & WIM_RESHDR_FLAG_CONCAT) {
			/* Continuing the run with another stream.  */
			DEBUG("Continuing concat run with stream: "
			      "%"PRIu64" uncompressed bytes @ resource offset %"PRIu64")",
			      reshdr.size_in_wim, reshdr.offset_in_wim);
			cur_rspec->uncompressed_size += reshdr.size_in_wim;
		}

		lte_bind_wim_resource_spec(cur_entry, cur_rspec);
		if (reshdr.flags & WIM_RESHDR_FLAG_CONCAT) {
			/* In concatenation runs, the offset field is used for
			 * in-resource offset, not the in-WIM offset, and the
			 * size field is used for the uncompressed size, not the
			 * compressed size.  */
			cur_entry->offset_in_res = reshdr.offset_in_wim;
			cur_entry->size = reshdr.size_in_wim;
			cur_entry->flags = reshdr.flags;
		} else {
			cur_entry->offset_in_res = 0;
			cur_entry->size = reshdr.uncompressed_size;
			cur_entry->flags = reshdr.flags;
			cur_rspec = NULL;
		}

		if (is_zero_hash(cur_entry->hash)) {
			WARNING("The WIM lookup table contains an entry with a "
				"SHA1 message digest of all 0's (ignoring it)");
			free_lookup_table_entry(cur_entry);
			continue;
		}

		if (cur_entry->flags & WIM_RESHDR_FLAG_METADATA) {
			/* Lookup table entry for a metadata resource */
			if (cur_entry->refcnt != 1) {
				/* Metadata entries with no references must be
				 * ignored.  See for example the WinPE WIMs from
				 * WAIK v2.1.  */
				if (cur_entry->refcnt == 0) {
					free_lookup_table_entry(cur_entry);
					continue;
				}
				if (wimlib_print_errors) {
					ERROR("Found metadata resource with refcnt != 1:");
					print_lookup_table_entry(cur_entry, stderr);
				}
				ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
				goto out_free_cur_entry;
			}

			if (wim->hdr.part_number != 1) {
				WARNING("Ignoring metadata resource found in a "
					"non-first part of the split WIM");
				free_lookup_table_entry(cur_entry);
				continue;
			}
			if (wim->current_image == wim->hdr.image_count) {
				WARNING("The WIM header says there are %u images "
					"in the WIM, but we found more metadata "
					"resources than this (ignoring the extra)",
					wim->hdr.image_count);
				free_lookup_table_entry(cur_entry);
				continue;
			}

			/* Notice very carefully:  We are assigning the metadata
			 * resources in the exact order mirrored by their lookup
			 * table entries on disk, which is the behavior of
			 * Microsoft's software.  In particular, this overrides
			 * the actual locations of the metadata resources
			 * themselves in the WIM file as well as any information
			 * written in the XML data. */
			DEBUG("Found metadata resource for image %u at "
			      "offset %"PRIu64".",
			      wim->current_image + 1,
			      cur_entry->rspec->offset_in_wim);
			wim->image_metadata[
				wim->current_image++]->metadata_lte = cur_entry;
		} else {
			/* Lookup table entry for a stream that is not a
			 * metadata resource */
			duplicate_entry = lookup_resource(table, cur_entry->hash);
			if (duplicate_entry) {
				if (wimlib_print_errors) {
					WARNING("The WIM lookup table contains two entries with the "
					      "same SHA1 message digest!");
					WARNING("The first entry is:");
					print_lookup_table_entry(duplicate_entry, stderr);
					WARNING("The second entry is:");
					print_lookup_table_entry(cur_entry, stderr);
				}
				free_lookup_table_entry(cur_entry);
				continue;
			} else {
				lookup_table_insert(table, cur_entry);
			}
		}
	}

	if (cur_rspec != NULL) {
		ret = validate_resource(cur_rspec);
		if (ret)
			goto out_free_cur_entry;
	}

	if (wim->hdr.part_number == 1 && wim->current_image != wim->hdr.image_count) {
		WARNING("The header of \"%"TS"\" says there are %u images in\n"
			"          the WIM, but we only found %d metadata resources!  Acting as if\n"
			"          the header specified only %d images instead.",
			wim->filename, wim->hdr.image_count,
			wim->current_image, wim->current_image);
		for (int i = wim->current_image; i < wim->hdr.image_count; i++)
			put_image_metadata(wim->image_metadata[i], NULL);
		wim->hdr.image_count = wim->current_image;
	}
	DEBUG("Done reading lookup table.");
	wim->lookup_table = table;
	ret = 0;
	goto out_free_buf;

out_free_cur_entry:
	FREE(cur_entry);
out_free_lookup_table:
	free_lookup_table(table);
out_free_buf:
	FREE(buf);
out:
	wim->current_image = 0;
	return ret;
}


static void
write_wim_lookup_table_entry(const struct wim_lookup_table_entry *lte,
			     struct wim_lookup_table_entry_disk *disk_entry,
			     u16 part_number)
{
	put_wim_reshdr(&lte->out_reshdr, &disk_entry->reshdr);
	disk_entry->part_number = cpu_to_le16(part_number);
	disk_entry->refcnt = cpu_to_le32(lte->out_refcnt);
	copy_hash(disk_entry->hash, lte->hash);
}

static int
write_wim_lookup_table_from_stream_list(struct list_head *stream_list,
					struct filedes *out_fd,
					u16 part_number,
					struct wim_reshdr *out_reshdr,
					int write_resource_flags,
					struct wimlib_lzx_context **comp_ctx)
{
	size_t table_size;
	struct wim_lookup_table_entry *lte;
	struct wim_lookup_table_entry_disk *table_buf;
	struct wim_lookup_table_entry_disk *table_buf_ptr;
	int ret;

	table_size = 0;
	list_for_each_entry(lte, stream_list, lookup_table_list)
		table_size += sizeof(struct wim_lookup_table_entry_disk);

	DEBUG("Writing WIM lookup table (size=%zu, offset=%"PRIu64")",
	      table_size, out_fd->offset);

	table_buf = MALLOC(table_size);
	if (!table_buf) {
		ERROR("Failed to allocate %zu bytes for temporary lookup table",
		      table_size);
		return WIMLIB_ERR_NOMEM;
	}
	table_buf_ptr = table_buf;
	list_for_each_entry(lte, stream_list, lookup_table_list)
		write_wim_lookup_table_entry(lte, table_buf_ptr++, part_number);

	/* Write the lookup table uncompressed.  Although wimlib can handle a
	 * compressed lookup table, MS software cannot.  */
	ret = write_wim_resource_from_buffer(table_buf,
					     table_size,
					     WIM_RESHDR_FLAG_METADATA,
					     out_fd,
					     WIMLIB_COMPRESSION_TYPE_NONE,
					     0,
					     out_reshdr,
					     NULL,
					     write_resource_flags,
					     comp_ctx);
	FREE(table_buf);
	DEBUG("ret=%d", ret);
	return ret;
}

static int
append_lookup_table_entry(struct wim_lookup_table_entry *lte, void *_list)
{
	/* Lookup table entries with 'out_refcnt' == 0 correspond to streams not
	 * written and not present in the resulting WIM file, and should not be
	 * included in the lookup table.
	 *
	 * Lookup table entries marked as filtered (EXTERNAL_WIM) with
	 * 'out_refcnt != 0' were referenced as part of the logical write but
	 * correspond to streams that were not in fact written, and should not
	 * be included in the lookup table.
	 *
	 * Lookup table entries marked as filtered (SAME_WIM) with 'out_refcnt
	 * != 0' were referenced as part of the logical write but correspond to
	 * streams that were not in fact written, but nevertheless were already
	 * present in the WIM being overwritten in-place.  These entries must be
	 * included in the lookup table, and the resource information to write
	 * needs to be copied from the resource information read originally.
	 */
	if (lte->out_refcnt != 0 && !(lte->filtered & FILTERED_EXTERNAL_WIM)) {
		if (lte->filtered & FILTERED_SAME_WIM)
			wim_res_spec_to_hdr(lte->rspec, &lte->out_reshdr);
		list_add_tail(&lte->lookup_table_list, (struct list_head*)_list);
	}
	return 0;
}

int
write_wim_lookup_table(WIMStruct *wim, int image, int write_flags,
		       struct wim_reshdr *out_reshdr,
		       struct list_head *stream_list_override)
{
	int write_resource_flags;
	struct list_head _stream_list;
	struct list_head *stream_list;

	if (stream_list_override) {
		stream_list = stream_list_override;
	} else {
		stream_list = &_stream_list;
		INIT_LIST_HEAD(stream_list);
	}

	if (!(write_flags & WIMLIB_WRITE_FLAG_NO_METADATA)) {
		int start_image;
		int end_image;

		if (image == WIMLIB_ALL_IMAGES) {
			start_image = 1;
			end_image = wim->hdr.image_count;
		} else {
			start_image = image;
			end_image = image;
		}

		/* Push metadata resource lookup table entries onto the front of
		 * the list in reverse order, so that they're written in order.
		 */
		for (int i = end_image; i >= start_image; i--) {
			struct wim_lookup_table_entry *metadata_lte;

			metadata_lte = wim->image_metadata[i - 1]->metadata_lte;
			metadata_lte->out_refcnt = 1;
			metadata_lte->out_reshdr.flags |= WIM_RESHDR_FLAG_METADATA;
			list_add(&metadata_lte->lookup_table_list, stream_list);
		}
	}

	/* Append additional lookup table entries that need to be written, with
	 * some special handling for streams that have been marked as filtered.
	 */
	if (!stream_list_override) {
		for_lookup_table_entry(wim->lookup_table,
				       append_lookup_table_entry, stream_list);
	}

	write_resource_flags = 0;
	if (write_flags & WIMLIB_WRITE_FLAG_PIPABLE)
		write_resource_flags |= WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE;
	return write_wim_lookup_table_from_stream_list(stream_list,
						       &wim->out_fd,
						       wim->hdr.part_number,
						       out_reshdr,
						       write_resource_flags,
						       &wim->lzx_context);
}


int
lte_zero_real_refcnt(struct wim_lookup_table_entry *lte, void *_ignore)
{
	lte->real_refcnt = 0;
	return 0;
}

int
lte_zero_out_refcnt(struct wim_lookup_table_entry *lte, void *_ignore)
{
	lte->out_refcnt = 0;
	return 0;
}

int
lte_free_extracted_file(struct wim_lookup_table_entry *lte, void *_ignore)
{
	if (lte->extracted_file != NULL) {
		FREE(lte->extracted_file);
		lte->extracted_file = NULL;
	}
	return 0;
}

void
print_lookup_table_entry(const struct wim_lookup_table_entry *lte, FILE *out)
{
	if (lte == NULL) {
		tputc(T('\n'), out);
		return;
	}


	tprintf(T("Uncompressed size     = %"PRIu64" bytes\n"),
		lte->size);
	if (lte_is_partial(lte)) {
		tprintf(T("Offset                = %"PRIu64" bytes\n"),
			lte->offset_in_res);

		tprintf(T("Raw uncompressed size = %"PRIu64" bytes\n"),
			lte->rspec->uncompressed_size);

		tprintf(T("Raw compressed size   = %"PRIu64" bytes\n"),
			lte->rspec->size_in_wim);

		tprintf(T("Raw offset            = %"PRIu64" bytes\n"),
			lte->rspec->offset_in_wim);
	} else if (lte->resource_location == RESOURCE_IN_WIM) {
		tprintf(T("Compressed size       = %"PRIu64" bytes\n"),
			lte->rspec->size_in_wim);

		tprintf(T("Offset                = %"PRIu64" bytes\n"),
			lte->rspec->offset_in_wim);
	}

	tfprintf(out, T("Reference Count       = %u\n"), lte->refcnt);

	if (lte->unhashed) {
		tfprintf(out, T("(Unhashed: inode %p, stream_id = %u)\n"),
			 lte->back_inode, lte->back_stream_id);
	} else {
		tfprintf(out, T("Hash                  = 0x"));
		print_hash(lte->hash, out);
		tputc(T('\n'), out);
	}

	tfprintf(out, T("Flags                 = "));
	u8 flags = lte->flags;
	if (flags & WIM_RESHDR_FLAG_COMPRESSED)
		tfputs(T("WIM_RESHDR_FLAG_COMPRESSED, "), out);
	if (flags & WIM_RESHDR_FLAG_FREE)
		tfputs(T("WIM_RESHDR_FLAG_FREE, "), out);
	if (flags & WIM_RESHDR_FLAG_METADATA)
		tfputs(T("WIM_RESHDR_FLAG_METADATA, "), out);
	if (flags & WIM_RESHDR_FLAG_SPANNED)
		tfputs(T("WIM_RESHDR_FLAG_SPANNED, "), out);
	if (flags & WIM_RESHDR_FLAG_CONCAT)
		tfputs(T("WIM_RESHDR_FLAG_CONCAT, "), out);
	tputc(T('\n'), out);
	switch (lte->resource_location) {
	case RESOURCE_IN_WIM:
		if (lte->rspec->wim->filename) {
			tfprintf(out, T("WIM file              = `%"TS"'\n"),
				 lte->rspec->wim->filename);
		}
		break;
#ifdef __WIN32__
	case RESOURCE_WIN32_ENCRYPTED:
#endif
	case RESOURCE_IN_FILE_ON_DISK:
		tfprintf(out, T("File on Disk          = `%"TS"'\n"),
			 lte->file_on_disk);
		break;
#ifdef WITH_FUSE
	case RESOURCE_IN_STAGING_FILE:
		tfprintf(out, T("Staging File          = `%"TS"'\n"),
				lte->staging_file_name);
		break;
#endif
	default:
		break;
	}
	tputc(T('\n'), out);
}

void
lte_to_wimlib_resource_entry(const struct wim_lookup_table_entry *lte,
			     struct wimlib_resource_entry *wentry)
{
	memset(wentry, 0, sizeof(*wentry));

	wentry->uncompressed_size = lte->size;
	if (lte->resource_location == RESOURCE_IN_WIM) {
		wentry->part_number = lte->rspec->wim->hdr.part_number;
		if (lte_is_partial(lte)) {
			wentry->compressed_size = 0;
			wentry->offset = lte->offset_in_res;
		} else {
			wentry->compressed_size = lte->rspec->size_in_wim;
			wentry->offset = lte->rspec->offset_in_wim;
		}
		wentry->raw_resource_offset_in_wim = lte->rspec->offset_in_wim;
		wentry->raw_resource_uncompressed_size = lte->rspec->uncompressed_size;
		wentry->raw_resource_compressed_size = lte->rspec->size_in_wim;
	}
	copy_hash(wentry->sha1_hash, lte->hash);
	wentry->reference_count = lte->refcnt;
	wentry->is_compressed = (lte->flags & WIM_RESHDR_FLAG_COMPRESSED) != 0;
	wentry->is_metadata = (lte->flags & WIM_RESHDR_FLAG_METADATA) != 0;
	wentry->is_free = (lte->flags & WIM_RESHDR_FLAG_FREE) != 0;
	wentry->is_spanned = (lte->flags & WIM_RESHDR_FLAG_SPANNED) != 0;
	wentry->is_partial = lte_is_partial(lte);
}

struct iterate_lte_context {
	wimlib_iterate_lookup_table_callback_t cb;
	void *user_ctx;
};

static int
do_iterate_lte(struct wim_lookup_table_entry *lte, void *_ctx)
{
	struct iterate_lte_context *ctx = _ctx;
	struct wimlib_resource_entry entry;

	lte_to_wimlib_resource_entry(lte, &entry);
	return (*ctx->cb)(&entry, ctx->user_ctx);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_iterate_lookup_table(WIMStruct *wim, int flags,
			    wimlib_iterate_lookup_table_callback_t cb,
			    void *user_ctx)
{
	struct iterate_lte_context ctx = {
		.cb = cb,
		.user_ctx = user_ctx,
	};
	if (wim->hdr.part_number == 1) {
		int ret;
		for (int i = 0; i < wim->hdr.image_count; i++) {
			ret = do_iterate_lte(wim->image_metadata[i]->metadata_lte,
					     &ctx);
			if (ret)
				return ret;
		}
	}
	return for_lookup_table_entry(wim->lookup_table, do_iterate_lte, &ctx);
}

/* Given a SHA1 message digest, return the corresponding entry in the WIM's
 * lookup table, or NULL if there is none.  */
struct wim_lookup_table_entry *
lookup_resource(const struct wim_lookup_table *table, const u8 hash[])
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
wim_pathname_to_stream(WIMStruct *wim,
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

	dentry = get_dentry(wim, path);
	if (p)
		*p = T(':');
	if (!dentry)
		return -errno;

	inode = dentry->d_inode;

	if (!inode->i_resolved)
		if (inode_resolve_ltes(inode, wim->lookup_table, false))
			return -EIO;

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
		lte = inode_unnamed_stream_resolved(inode, &stream_idx);
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

int
resource_not_found_error(const struct wim_inode *inode, const u8 *hash)
{
	if (wimlib_print_errors) {
		ERROR("\"%"TS"\": resource not found", inode_first_full_path(inode));
		tfprintf(stderr, T("        SHA-1 message digest of missing resource:\n        "));
		print_hash(hash, stderr);
		tputc(T('\n'), stderr);
	}
	return WIMLIB_ERR_RESOURCE_NOT_FOUND;
}

/*
 * Resolve an inode's lookup table entries.
 *
 * This replaces the SHA1 hash fields (which are used to lookup an entry in the
 * lookup table) with pointers directly to the lookup table entries.
 *
 * If @force is %false:
 *	If any needed SHA1 message digests are not found in the lookup table,
 *	WIMLIB_ERR_RESOURCE_NOT_FOUND is returned and the inode is left
 *	unmodified.
 * If @force is %true:
 *	If any needed SHA1 message digests are not found in the lookup table,
 *	new entries are allocated and inserted into the lookup table.
 */
int
inode_resolve_ltes(struct wim_inode *inode, struct wim_lookup_table *table,
		   bool force)
{
	const u8 *hash;

	if (!inode->i_resolved) {
		struct wim_lookup_table_entry *lte, *ads_lte;

		/* Resolve the default file stream */
		lte = NULL;
		hash = inode->i_hash;
		if (!is_zero_hash(hash)) {
			lte = lookup_resource(table, hash);
			if (!lte) {
				if (force) {
					lte = new_lookup_table_entry();
					if (!lte)
						return WIMLIB_ERR_NOMEM;
					copy_hash(lte->hash, hash);
					lookup_table_insert(table, lte);
				} else {
					goto resource_not_found;
				}
			}
		}

		/* Resolve the alternate data streams */
		struct wim_lookup_table_entry *ads_ltes[inode->i_num_ads];
		for (u16 i = 0; i < inode->i_num_ads; i++) {
			struct wim_ads_entry *cur_entry;

			ads_lte = NULL;
			cur_entry = &inode->i_ads_entries[i];
			hash = cur_entry->hash;
			if (!is_zero_hash(hash)) {
				ads_lte = lookup_resource(table, hash);
				if (!ads_lte) {
					if (force) {
						ads_lte = new_lookup_table_entry();
						if (!ads_lte)
							return WIMLIB_ERR_NOMEM;
						copy_hash(ads_lte->hash, hash);
						lookup_table_insert(table, ads_lte);
					} else {
						goto resource_not_found;
					}
				}
			}
			ads_ltes[i] = ads_lte;
		}
		inode->i_lte = lte;
		for (u16 i = 0; i < inode->i_num_ads; i++)
			inode->i_ads_entries[i].lte = ads_ltes[i];
		inode->i_resolved = 1;
	}
	return 0;

resource_not_found:
	return resource_not_found_error(inode, hash);
}

void
inode_unresolve_ltes(struct wim_inode *inode)
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
 * This works for both resolved and un-resolved inodes.
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

struct wim_lookup_table_entry *
inode_unnamed_stream_resolved(const struct wim_inode *inode, u16 *stream_idx_ret)
{
	wimlib_assert(inode->i_resolved);
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		if (inode_stream_name_nbytes(inode, i) == 0 &&
		    !is_zero_hash(inode_stream_hash_resolved(inode, i)))
		{
			*stream_idx_ret = i;
			return inode_stream_lte_resolved(inode, i);
		}
	}
	*stream_idx_ret = 0;
	return NULL;
}

struct wim_lookup_table_entry *
inode_unnamed_lte_resolved(const struct wim_inode *inode)
{
	u16 stream_idx;
	return inode_unnamed_stream_resolved(inode, &stream_idx);
}

struct wim_lookup_table_entry *
inode_unnamed_lte_unresolved(const struct wim_inode *inode,
			     const struct wim_lookup_table *table)
{
	wimlib_assert(!inode->i_resolved);
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		if (inode_stream_name_nbytes(inode, i) == 0 &&
		    !is_zero_hash(inode_stream_hash_unresolved(inode, i)))
		{
			return inode_stream_lte_unresolved(inode, i, table);
		}
	}
	return NULL;
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

/* Returns the SHA1 message digest of the unnamed data stream of a WIM inode, or
 * 'zero_hash' if the unnamed data stream is missing has all zeroes in its SHA1
 * message digest field.  */
const u8 *
inode_unnamed_stream_hash(const struct wim_inode *inode)
{
	const u8 *hash;

	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		if (inode_stream_name_nbytes(inode, i) == 0) {
			hash = inode_stream_hash(inode, i);
			if (!is_zero_hash(hash))
				return hash;
		}
	}
	return zero_hash;
}

struct wim_lookup_table_entry **
retrieve_lte_pointer(struct wim_lookup_table_entry *lte)
{
	wimlib_assert(lte->unhashed);
	struct wim_inode *inode = lte->back_inode;
	u32 stream_id = lte->back_stream_id;
	if (stream_id == 0)
		return &inode->i_lte;
	else
		for (u16 i = 0; i < inode->i_num_ads; i++)
			if (inode->i_ads_entries[i].stream_id == stream_id)
				return &inode->i_ads_entries[i].lte;
	wimlib_assert(0);
	return NULL;
}

/* Calculate the SHA1 message digest of a stream and move it from the list of
 * unhashed streams to the stream lookup table, possibly joining it with an
 * existing lookup table entry for an identical stream.
 *
 * @lte:  An unhashed lookup table entry.
 * @lookup_table:  Lookup table for the WIM.
 * @lte_ret:  On success, write a pointer to the resulting lookup table
 *            entry to this location.  This will be the same as @lte
 *            if it was inserted into the lookup table, or different if
 *            a duplicate stream was found.
 *
 * Returns 0 on success; nonzero if there is an error reading the stream.
 */
int
hash_unhashed_stream(struct wim_lookup_table_entry *lte,
		     struct wim_lookup_table *lookup_table,
		     struct wim_lookup_table_entry **lte_ret)
{
	int ret;
	struct wim_lookup_table_entry *duplicate_lte;
	struct wim_lookup_table_entry **back_ptr;

	wimlib_assert(lte->unhashed);

	/* back_ptr must be saved because @back_inode and @back_stream_id are in
	 * union with the SHA1 message digest and will no longer be valid once
	 * the SHA1 has been calculated. */
	back_ptr = retrieve_lte_pointer(lte);

	ret = sha1_stream(lte);
	if (ret)
		return ret;

	/* Look for a duplicate stream */
	duplicate_lte = lookup_resource(lookup_table, lte->hash);
	list_del(&lte->unhashed_list);
	if (duplicate_lte) {
		/* We have a duplicate stream.  Transfer the reference counts
		 * from this stream to the duplicate, update the reference to
		 * this stream (in an inode or ads_entry) to point to the
		 * duplicate, then free this stream. */
		wimlib_assert(!(duplicate_lte->unhashed));
		duplicate_lte->refcnt += lte->refcnt;
		duplicate_lte->out_refcnt += lte->out_refcnt;
		*back_ptr = duplicate_lte;
		free_lookup_table_entry(lte);
		lte = duplicate_lte;
	} else {
		/* No duplicate stream, so we need to insert
		 * this stream into the lookup table and treat
		 * it as a hashed stream. */
		lookup_table_insert(lookup_table, lte);
		lte->unhashed = 0;
	}
	if (lte_ret)
		*lte_ret = lte;
	return 0;
}

static int
lte_clone_if_new(struct wim_lookup_table_entry *lte, void *_lookup_table)
{
	struct wim_lookup_table *lookup_table = _lookup_table;

	if (lookup_resource(lookup_table, lte->hash))
		return 0;  /*  Resource already present.  */

	lte = clone_lookup_table_entry(lte);
	if (!lte)
		return WIMLIB_ERR_NOMEM;
	lte->out_refcnt = 1;
	lookup_table_insert(lookup_table, lte);
	return 0;
}

static int
lte_delete_if_new(struct wim_lookup_table_entry *lte, void *_lookup_table)
{
	struct wim_lookup_table *lookup_table = _lookup_table;

	if (lte->out_refcnt) {
		lookup_table_unlink(lookup_table, lte);
		free_lookup_table_entry(lte);
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_reference_resources(WIMStruct *wim,
			   WIMStruct **resource_wims, unsigned num_resource_wims,
			   int ref_flags)
{
	int ret;
	unsigned i;

	if (wim == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	if (num_resource_wims != 0 && resource_wims == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	for (i = 0; i < num_resource_wims; i++)
		if (resource_wims[i] == NULL)
			return WIMLIB_ERR_INVALID_PARAM;

	for_lookup_table_entry(wim->lookup_table, lte_zero_out_refcnt, NULL);

	for (i = 0; i < num_resource_wims; i++) {
		ret = for_lookup_table_entry(resource_wims[i]->lookup_table,
					     lte_clone_if_new,
					     wim->lookup_table);
		if (ret)
			goto out_rollback;
	}
	return 0;

out_rollback:
	for_lookup_table_entry(wim->lookup_table, lte_delete_if_new,
			       wim->lookup_table);
	return ret;
}

static int
reference_resource_paths(WIMStruct *wim,
			 const tchar * const *resource_wimfiles,
			 unsigned num_resource_wimfiles,
			 int ref_flags,
			 int open_flags,
			 wimlib_progress_func_t progress_func)
{
	WIMStruct **resource_wims;
	unsigned i;
	int ret;

	resource_wims = CALLOC(num_resource_wimfiles, sizeof(resource_wims[0]));
	if (!resource_wims)
		return WIMLIB_ERR_NOMEM;

	for (i = 0; i < num_resource_wimfiles; i++) {
		DEBUG("Referencing resources from path \"%"TS"\"",
		      resource_wimfiles[i]);
		ret = wimlib_open_wim(resource_wimfiles[i], open_flags,
				      &resource_wims[i], progress_func);
		if (ret)
			goto out_free_resource_wims;
	}

	ret = wimlib_reference_resources(wim, resource_wims,
					 num_resource_wimfiles, ref_flags);
	if (ret)
		goto out_free_resource_wims;

	for (i = 0; i < num_resource_wimfiles; i++)
		list_add_tail(&resource_wims[i]->subwim_node, &wim->subwims);

	ret = 0;
	goto out_free_array;

out_free_resource_wims:
	for (i = 0; i < num_resource_wimfiles; i++)
		wimlib_free(resource_wims[i]);
out_free_array:
	FREE(resource_wims);
	return ret;
}

static int
reference_resource_glob(WIMStruct *wim, const tchar *refglob,
			int ref_flags, int open_flags,
			wimlib_progress_func_t progress_func)
{
	glob_t globbuf;
	int ret;

	/* Note: glob() is replaced in Windows native builds.  */
	ret = tglob(refglob, GLOB_ERR | GLOB_NOSORT, NULL, &globbuf);
	if (ret) {
		if (ret == GLOB_NOMATCH) {
			if (ref_flags & WIMLIB_REF_FLAG_GLOB_ERR_ON_NOMATCH) {
				ERROR("Found no files for glob \"%"TS"\"", refglob);
				return WIMLIB_ERR_GLOB_HAD_NO_MATCHES;
			} else {
				return reference_resource_paths(wim,
								&refglob,
								1,
								ref_flags,
								open_flags,
								progress_func);
			}
		} else {
			ERROR_WITH_ERRNO("Failed to process glob \"%"TS"\"", refglob);
			if (ret == GLOB_NOSPACE)
				return WIMLIB_ERR_NOMEM;
			else
				return WIMLIB_ERR_READ;
		}
	}

	ret = reference_resource_paths(wim,
				       (const tchar * const *)globbuf.gl_pathv,
				       globbuf.gl_pathc,
				       ref_flags,
				       open_flags,
				       progress_func);
	globfree(&globbuf);
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_reference_resource_files(WIMStruct *wim,
				const tchar * const * resource_wimfiles_or_globs,
				unsigned count,
				int ref_flags,
				int open_flags,
				wimlib_progress_func_t progress_func)
{
	unsigned i;
	int ret;

	if (ref_flags & WIMLIB_REF_FLAG_GLOB_ENABLE) {
		for (i = 0; i < count; i++) {
			ret = reference_resource_glob(wim,
						      resource_wimfiles_or_globs[i],
						      ref_flags,
						      open_flags,
						      progress_func);
			if (ret)
				return ret;
		}
		return 0;
	} else {
		return reference_resource_paths(wim, resource_wimfiles_or_globs,
						count, ref_flags,
						open_flags, progress_func);
	}
}
