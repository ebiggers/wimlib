/*
 * lookup_table.c
 *
 * Lookup table, implemented as a hash table, that maps SHA1 message digests to
 * data streams; plus code to read and write the corresponding on-disk data.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
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

#include "wimlib/assert.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/ntfs_3g.h"
#include "wimlib/resource.h"
#include "wimlib/util.h"
#include "wimlib/write.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* for unlink()  */

/* WIM lookup table:
 *
 * This is a logical mapping from SHA1 message digests to the data streams
 * contained in a WIM.
 *
 * Here it is implemented as a hash table.
 *
 * Note: Everything will break horribly if there is a SHA1 collision.
 */
struct wim_lookup_table {
	struct hlist_head *array;
	size_t num_entries;
	size_t capacity;
};

struct wim_lookup_table *
new_lookup_table(size_t capacity)
{
	struct wim_lookup_table *table;
	struct hlist_head *array;

	table = MALLOC(sizeof(struct wim_lookup_table));
	if (table == NULL)
		goto oom;

	array = CALLOC(capacity, sizeof(array[0]));
	if (array == NULL) {
		FREE(table);
		goto oom;
	}

	table->num_entries = 0;
	table->capacity = capacity;
	table->array = array;
	return table;

oom:
	ERROR("Failed to allocate memory for lookup table "
	      "with capacity %zu", capacity);
	return NULL;
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
	DEBUG("Freeing lookup table.");
	if (table == NULL)
		return;

	if (table->array) {
		for_lookup_table_entry(table,
				       do_free_lookup_table_entry,
				       NULL);
		FREE(table->array);
	}
	FREE(table);
}

struct wim_lookup_table_entry *
new_lookup_table_entry(void)
{
	struct wim_lookup_table_entry *lte;

	lte = CALLOC(1, sizeof(struct wim_lookup_table_entry));
	if (lte == NULL)
		return NULL;

	lte->refcnt = 1;

	/* lte->resource_location = RESOURCE_NONEXISTENT  */
	BUILD_BUG_ON(RESOURCE_NONEXISTENT != 0);

	return lte;
}

struct wim_lookup_table_entry *
clone_lookup_table_entry(const struct wim_lookup_table_entry *old)
{
	struct wim_lookup_table_entry *new;

	new = memdup(old, sizeof(struct wim_lookup_table_entry));
	if (new == NULL)
		return NULL;

	new->extracted_file = NULL;
	switch (new->resource_location) {
	case RESOURCE_IN_WIM:
		list_add(&new->rspec_node, &new->rspec->stream_list);
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
		if (new->file_on_disk == NULL)
			goto out_free;
		break;
	case RESOURCE_IN_ATTACHED_BUFFER:
		new->attached_buffer = memdup(old->attached_buffer, old->size);
		if (new->attached_buffer == NULL)
			goto out_free;
		break;
#ifdef WITH_NTFS_3G
	case RESOURCE_IN_NTFS_VOLUME:
		if (old->ntfs_loc) {
			struct ntfs_location *loc;
			loc = memdup(old->ntfs_loc, sizeof(struct ntfs_location));
			if (loc == NULL)
				goto out_free;
			loc->path = NULL;
			loc->stream_name = NULL;
			new->ntfs_loc = loc;
			loc->path = STRDUP(old->ntfs_loc->path);
			if (loc->path == NULL)
				goto out_free;
			if (loc->stream_name_nchars != 0) {
				loc->stream_name = memdup(old->ntfs_loc->stream_name,
							  loc->stream_name_nchars * 2);
				if (loc->stream_name == NULL)
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
lte_put_resource(struct wim_lookup_table_entry *lte)
{
	switch (lte->resource_location) {
	case RESOURCE_IN_WIM:
		list_del(&lte->rspec_node);
		if (list_empty(&lte->rspec->stream_list))
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
}

void
free_lookup_table_entry(struct wim_lookup_table_entry *lte)
{
	if (lte) {
		lte_put_resource(lte);
		FREE(lte);
	}
}

/* Should this stream be retained even if it has no references?  */
static bool
should_retain_lte(const struct wim_lookup_table_entry *lte)
{
	return lte->resource_location == RESOURCE_IN_WIM;
}

static void
finalize_lte(struct wim_lookup_table_entry *lte)
{
	if (!should_retain_lte(lte))
		free_lookup_table_entry(lte);
}

/*
 * Decrements the reference count for the lookup table entry @lte, which must be
 * inserted in the stream lookup table @table.
 *
 * If the reference count reaches 0, this may cause @lte to be destroyed.
 * However, we may retain entries with 0 reference count.  This does not affect
 * correctness, but it prevents the entries for valid streams in a WIM archive,
 * which will continue to be present after appending to the file, from being
 * lost merely because we dropped all references to them.
 */
void
lte_decrement_refcnt(struct wim_lookup_table_entry *lte,
		     struct wim_lookup_table *table)
{
	wimlib_assert(lte->refcnt != 0);

	if (--lte->refcnt == 0) {
		if (lte->unhashed) {
			list_del(&lte->unhashed_list);
		#ifdef WITH_FUSE
			/* If the stream has been extracted to a staging file
			 * for a FUSE mount, unlink the staging file.  (Note
			 * that there still may be open file descriptors to it.)
			 * */
			if (lte->resource_location == RESOURCE_IN_STAGING_FILE)
				unlink(lte->staging_file_name);
		#endif
		} else {
			if (!should_retain_lte(lte))
				lookup_table_unlink(table, lte);
		}

		/* If FUSE mounts are enabled, we don't actually free the entry
		 * until the last file descriptor has been closed by
		 * lte_decrement_num_opened_fds().  */
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
	wimlib_assert(lte->num_opened_fds != 0);

	if (--lte->num_opened_fds == 0 && lte->refcnt == 0)
		finalize_lte(lte);
}
#endif

static void
lookup_table_insert_raw(struct wim_lookup_table *table,
			struct wim_lookup_table_entry *lte)
{
	size_t i = lte->hash_short % table->capacity;

	hlist_add_head(&lte->hash_list, &table->array[i]);
}

static void
enlarge_lookup_table(struct wim_lookup_table *table)
{
	size_t old_capacity, new_capacity;
	struct hlist_head *old_array, *new_array;
	struct wim_lookup_table_entry *lte;
	struct hlist_node *cur, *tmp;
	size_t i;

	old_capacity = table->capacity;
	new_capacity = old_capacity * 2;
	new_array = CALLOC(new_capacity, sizeof(struct hlist_head));
	if (new_array == NULL)
		return;
	old_array = table->array;
	table->array = new_array;
	table->capacity = new_capacity;

	for (i = 0; i < old_capacity; i++) {
		hlist_for_each_entry_safe(lte, cur, tmp, &old_array[i], hash_list) {
			hlist_del(&lte->hash_list);
			lookup_table_insert_raw(table, lte);
		}
	}
	FREE(old_array);
}

/* Inserts an entry into the lookup table.  */
void
lookup_table_insert(struct wim_lookup_table *table,
		    struct wim_lookup_table_entry *lte)
{
	lookup_table_insert_raw(table, lte);
	if (++table->num_entries > table->capacity)
		enlarge_lookup_table(table);
}

/* Unlinks a lookup table entry from the table; does not free it.  */
void
lookup_table_unlink(struct wim_lookup_table *table,
		    struct wim_lookup_table_entry *lte)
{
	wimlib_assert(!lte->unhashed);
	wimlib_assert(table->num_entries != 0);

	hlist_del(&lte->hash_list);
	table->num_entries--;
}

/* Given a SHA1 message digest, return the corresponding entry in the WIM's
 * lookup table, or NULL if there is none.  */
struct wim_lookup_table_entry *
lookup_stream(const struct wim_lookup_table *table, const u8 hash[])
{
	size_t i;
	struct wim_lookup_table_entry *lte;
	struct hlist_node *pos;

	i = *(size_t*)hash % table->capacity;
	hlist_for_each_entry(lte, pos, &table->array[i], hash_list)
		if (hashes_equal(hash, lte->hash))
			return lte;
	return NULL;
}

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
			ret = visitor(lte, arg);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/* qsort() callback that sorts streams (represented by `struct
 * wim_lookup_table_entry's) into an order optimized for reading.
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

		if (lte1->rspec->offset_in_wim != lte2->rspec->offset_in_wim)
			return cmp_u64(lte1->rspec->offset_in_wim,
				       lte2->rspec->offset_in_wim);

		return cmp_u64(lte1->offset_in_res, lte2->offset_in_res);

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
sort_stream_list(struct list_head *stream_list,
		 size_t list_head_offset,
		 int (*compar)(const void *, const void*))
{
	struct list_head *cur;
	struct wim_lookup_table_entry **array;
	size_t i;
	size_t array_size;
	size_t num_streams = 0;

	list_for_each(cur, stream_list)
		num_streams++;

	if (num_streams <= 1)
		return 0;

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

	qsort(array, num_streams, sizeof(array[0]), compar);

	INIT_LIST_HEAD(stream_list);
	for (i = 0; i < num_streams; i++) {
		list_add_tail((struct list_head*)
			       ((u8*)array[i] + list_head_offset),
			      stream_list);
	}
	FREE(array);
	return 0;
}

/* Sort the specified list of streams in an order optimized for reading.  */
int
sort_stream_list_by_sequential_order(struct list_head *stream_list,
				     size_t list_head_offset)
{
	return sort_stream_list(stream_list, list_head_offset,
				cmp_streams_by_sequential_order);
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

/* Given a nonempty run of consecutive lookup table entries with the
 * PACKED_STREAMS flag set, count how many specify resources (as opposed to
 * streams within those resources).
 *
 * Returns the resulting count.  */
static size_t
count_subpacks(const struct wim_lookup_table_entry_disk *entries, size_t max)
{
	size_t count = 0;
	do {
		struct wim_reshdr reshdr;

		get_wim_reshdr(&(entries++)->reshdr, &reshdr);

		if (!(reshdr.flags & WIM_RESHDR_FLAG_PACKED_STREAMS)) {
			/* Run was terminated by a stand-alone stream entry.  */
			break;
		}

		if (reshdr.uncompressed_size == WIM_PACK_MAGIC_NUMBER) {
			/* This is a resource entry.  */
			count++;
		}
	} while (--max);
	return count;
}

/* Given a run of consecutive lookup table entries with the PACKED_STREAMS flag
 * set and having @num_subpacks resource entries, load resource information from
 * them into the resource specifications in the @subpacks array.
 *
 * Returns 0 on success, or a nonzero error code on failure.  */
static int
do_load_subpack_info(WIMStruct *wim, struct wim_resource_spec **subpacks,
		     size_t num_subpacks,
		     const struct wim_lookup_table_entry_disk *entries)
{
	for (size_t i = 0; i < num_subpacks; i++) {
		struct wim_reshdr reshdr;
		struct alt_chunk_table_header_disk hdr;
		struct wim_resource_spec *rspec;
		int ret;

		/* Advance to next resource entry.  */

		do {
			get_wim_reshdr(&(entries++)->reshdr, &reshdr);
		} while (reshdr.uncompressed_size != WIM_PACK_MAGIC_NUMBER);

		rspec = subpacks[i];

		wim_res_hdr_to_spec(&reshdr, wim, rspec);

		/* For packed resources, the uncompressed size, compression
		 * type, and chunk size are stored in the resource itself, not
		 * in the lookup table.  */

		ret = full_pread(&wim->in_fd, &hdr,
				 sizeof(hdr), reshdr.offset_in_wim);
		if (ret) {
			ERROR("Failed to read header of packed resource "
			      "(offset_in_wim=%"PRIu64")",
			      reshdr.offset_in_wim);
			return ret;
		}

		rspec->uncompressed_size = le64_to_cpu(hdr.res_usize);

		/* Compression format numbers must be the same as in
		 * WIMGAPI to be compatible here.  */
		BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_NONE != 0);
		BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_XPRESS != 1);
		BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_LZX != 2);
		BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_LZMS != 3);
		rspec->compression_type = le32_to_cpu(hdr.compression_format);

		rspec->chunk_size = le32_to_cpu(hdr.chunk_size);

		DEBUG("Subpack %zu/%zu: %"PRIu64" => %"PRIu64" "
		      "(%"TS"/%"PRIu32") @ +%"PRIu64"",
		      i + 1, num_subpacks,
		      rspec->uncompressed_size,
		      rspec->size_in_wim,
		      wimlib_get_compression_type_string(rspec->compression_type),
		      rspec->chunk_size,
		      rspec->offset_in_wim);

	}
	return 0;
}

/* Given a nonempty run of consecutive lookup table entries with the
 * PACKED_STREAMS flag set, allocate a 'struct wim_resource_spec' for each
 * resource within that run.
 *
 * Returns 0 on success, or a nonzero error code on failure.
 * Returns the pointers and count in *subpacks_ret and *num_subpacks_ret.
 */
static int
load_subpack_info(WIMStruct *wim,
		  const struct wim_lookup_table_entry_disk *entries,
		  size_t num_remaining_entries,
		  struct wim_resource_spec ***subpacks_ret,
		  size_t *num_subpacks_ret)
{
	size_t num_subpacks;
	struct wim_resource_spec **subpacks;
	size_t i;
	int ret;

	num_subpacks = count_subpacks(entries, num_remaining_entries);
	subpacks = CALLOC(num_subpacks, sizeof(subpacks[0]));
	if (!subpacks)
		return WIMLIB_ERR_NOMEM;

	for (i = 0; i < num_subpacks; i++) {
		subpacks[i] = MALLOC(sizeof(struct wim_resource_spec));
		if (!subpacks[i]) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_subpacks;
		}
	}

	ret = do_load_subpack_info(wim, subpacks, num_subpacks, entries);
	if (ret)
		goto out_free_subpacks;

	*subpacks_ret = subpacks;
	*num_subpacks_ret = num_subpacks;
	return 0;

out_free_subpacks:
	for (i = 0; i < num_subpacks; i++)
		FREE(subpacks[i]);
	FREE(subpacks);
	return ret;
}

/* Given a 'struct wim_lookup_table_entry' allocated for a stream entry with
 * PACKED_STREAMS set, try to bind it to a subpack of the current PACKED_STREAMS
 * run.  */
static int
bind_stream_to_subpack(const struct wim_reshdr *reshdr,
		       struct wim_lookup_table_entry *stream,
		       struct wim_resource_spec **subpacks,
		       size_t num_subpacks)
{
	u64 offset = reshdr->offset_in_wim;

	/* XXX: This linear search will be slow in the degenerate case where the
	 * number of subpacks is huge.  */
	stream->size = reshdr->size_in_wim;
	stream->flags = reshdr->flags;
	for (size_t i = 0; i < num_subpacks; i++) {
		if (offset + stream->size <= subpacks[i]->uncompressed_size) {
			stream->offset_in_res = offset;
			lte_bind_wim_resource_spec(stream, subpacks[i]);
			return 0;
		}
		offset -= subpacks[i]->uncompressed_size;
	}
	ERROR("Packed stream could not be assigned to any resource");
	return WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
}

static void
free_subpack_info(struct wim_resource_spec **subpacks, size_t num_subpacks)
{
	if (subpacks) {
		for (size_t i = 0; i < num_subpacks; i++)
			if (list_empty(&subpacks[i]->stream_list))
				FREE(subpacks[i]);
		FREE(subpacks);
	}
}

static int
cmp_streams_by_offset_in_res(const void *p1, const void *p2)
{
	const struct wim_lookup_table_entry *lte1, *lte2;

	lte1 = *(const struct wim_lookup_table_entry**)p1;
	lte2 = *(const struct wim_lookup_table_entry**)p2;

	return cmp_u64(lte1->offset_in_res, lte2->offset_in_res);
}

/* Validate the size and location of a WIM resource.  */
static int
validate_resource(struct wim_resource_spec *rspec)
{
	struct wim_lookup_table_entry *lte;
	bool out_of_order;
	u64 expected_next_offset;
	int ret;

	/* Verify that the resource itself has a valid offset and size.  */
	if (rspec->offset_in_wim + rspec->size_in_wim < rspec->size_in_wim)
		goto invalid_due_to_overflow;

	/* Verify that each stream in the resource has a valid offset and size.
	 */
	expected_next_offset = 0;
	out_of_order = false;
	list_for_each_entry(lte, &rspec->stream_list, rspec_node) {
		if (lte->offset_in_res + lte->size < lte->size ||
		    lte->offset_in_res + lte->size > rspec->uncompressed_size)
			goto invalid_due_to_overflow;

		if (lte->offset_in_res >= expected_next_offset)
			expected_next_offset = lte->offset_in_res + lte->size;
		else
			out_of_order = true;
	}

	/* If the streams were not located at strictly increasing positions (not
	 * allowing for overlap), sort them.  Then make sure that none overlap.
	 */
	if (out_of_order) {
		ret = sort_stream_list(&rspec->stream_list,
				       offsetof(struct wim_lookup_table_entry,
						rspec_node),
				       cmp_streams_by_offset_in_res);
		if (ret)
			return ret;

		expected_next_offset = 0;
		list_for_each_entry(lte, &rspec->stream_list, rspec_node) {
			if (lte->offset_in_res >= expected_next_offset)
				expected_next_offset = lte->offset_in_res + lte->size;
			else
				goto invalid_due_to_overlap;
		}
	}

	return 0;

invalid_due_to_overflow:
	ERROR("Invalid resource entry (offset overflow)");
	return WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;

invalid_due_to_overlap:
	ERROR("Invalid resource entry (streams in packed resource overlap)");
	return WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
}

static int
finish_subpacks(struct wim_resource_spec **subpacks, size_t num_subpacks)
{
	int ret = 0;
	for (size_t i = 0; i < num_subpacks; i++) {
		ret = validate_resource(subpacks[i]);
		if (ret)
			break;
	}
	free_subpack_info(subpacks, num_subpacks);
	return ret;
}

/*
 * Reads the lookup table from a WIM file.  Usually, each entry specifies a
 * stream that the WIM file contains, along with its location and SHA1 message
 * digest.
 *
 * Saves lookup table entries for non-metadata streams in a hash table (set to
 * wim->lookup_table), and saves the metadata entry for each image in a special
 * per-image location (the wim->image_metadata array).
 *
 * This works for both version WIM_VERSION_DEFAULT (68864) and version
 * WIM_VERSION_PACKED_STREAMS (3584) WIMs.  In the latter, a consecutive run of
 * lookup table entries that all have flag WIM_RESHDR_FLAG_PACKED_STREAMS (0x10)
 * set is a "packed run".  A packed run logically contains zero or more
 * resources, each of which logically contains zero or more streams.
 * Physically, in such a run, a "lookup table entry" with uncompressed size
 * WIM_PACK_MAGIC_NUMBER (0x100000000) specifies a resource, whereas any other
 * entry specifies a stream.  Within such a run, stream entries and resource
 * entries need not be in any particular order, except that the order of the
 * resource entries is important, as it affects how streams are assigned to
 * resources.  See the code for details.
 *
 * Possible return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY
 *	WIMLIB_ERR_NOMEM
 *
 *	Or an error code caused by failure to read the lookup table from the WIM
 *	file.
 */
int
read_wim_lookup_table(WIMStruct *wim)
{
	int ret;
	size_t num_entries;
	void *buf = NULL;
	struct wim_lookup_table *table = NULL;
	struct wim_lookup_table_entry *cur_entry = NULL;
	size_t num_duplicate_entries = 0;
	size_t num_wrong_part_entries = 0;
	u32 image_index = 0;
	struct wim_resource_spec **cur_subpacks = NULL;
	size_t cur_num_subpacks = 0;

	DEBUG("Reading lookup table.");

	/* Sanity check: lookup table entries are 50 bytes each.  */
	BUILD_BUG_ON(sizeof(struct wim_lookup_table_entry_disk) !=
		     WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE);

	/* Calculate the number of entries in the lookup table.  */
	num_entries = wim->hdr.lookup_table_reshdr.uncompressed_size /
		      sizeof(struct wim_lookup_table_entry_disk);

	/* Read the lookup table into a buffer.  */
	ret = wim_reshdr_to_data(&wim->hdr.lookup_table_reshdr, wim, &buf);
	if (ret)
		goto out;

	/* Allocate a hash table to map SHA1 message digests into stream
	 * specifications.  This is the in-memory "lookup table".  */
	table = new_lookup_table(num_entries * 2 + 1);
	if (!table)
		goto oom;

	/* Allocate and initalize stream entries ('struct
	 * wim_lookup_table_entry's) from the raw lookup table buffer.  Each of
	 * these entries will point to a 'struct wim_resource_spec' that
	 * describes the underlying resource.  In WIMs with version number
	 * WIM_VERSION_PACKED_STREAMS, a resource may contain multiple streams.
	 */
	for (size_t i = 0; i < num_entries; i++) {
		const struct wim_lookup_table_entry_disk *disk_entry =
			&((const struct wim_lookup_table_entry_disk*)buf)[i];
		struct wim_reshdr reshdr;
		u16 part_number;

		/* Get the resource header  */
		get_wim_reshdr(&disk_entry->reshdr, &reshdr);

		DEBUG("reshdr: size_in_wim=%"PRIu64", "
		      "uncompressed_size=%"PRIu64", "
		      "offset_in_wim=%"PRIu64", "
		      "flags=0x%02x",
		      reshdr.size_in_wim, reshdr.uncompressed_size,
		      reshdr.offset_in_wim, reshdr.flags);

		/* Ignore PACKED_STREAMS flag if it isn't supposed to be used in
		 * this WIM version.  */
		if (wim->hdr.wim_version == WIM_VERSION_DEFAULT)
			reshdr.flags &= ~WIM_RESHDR_FLAG_PACKED_STREAMS;

		/* Allocate a new 'struct wim_lookup_table_entry'.  */
		cur_entry = new_lookup_table_entry();
		if (!cur_entry)
			goto oom;

		/* Get the part number, reference count, and hash.  */
		part_number = le16_to_cpu(disk_entry->part_number);
		cur_entry->refcnt = le32_to_cpu(disk_entry->refcnt);
		copy_hash(cur_entry->hash, disk_entry->hash);

		if (reshdr.flags & WIM_RESHDR_FLAG_PACKED_STREAMS) {

			/* PACKED_STREAMS entry  */

			if (!cur_subpacks) {
				/* Starting new run  */
				ret = load_subpack_info(wim, disk_entry,
							num_entries - i,
							&cur_subpacks,
							&cur_num_subpacks);
				if (ret)
					goto out;
			}

			if (reshdr.uncompressed_size == WIM_PACK_MAGIC_NUMBER) {
				/* Resource entry, not stream entry  */
				goto free_cur_entry_and_continue;
			}

			/* Stream entry  */

			ret = bind_stream_to_subpack(&reshdr,
						     cur_entry,
						     cur_subpacks,
						     cur_num_subpacks);
			if (ret)
				goto out;

		} else {
			/* Normal stream/resource entry; PACKED_STREAMS not set.
			 */

			struct wim_resource_spec *rspec;

			if (unlikely(cur_subpacks)) {
				/* This entry terminated a packed run.  */
				ret = finish_subpacks(cur_subpacks,
						      cur_num_subpacks);
				cur_subpacks = NULL;
				if (ret)
					goto out;
			}

			/* How to handle an uncompressed resource with its
			 * uncompressed size different from its compressed size?
			 *
			 * Based on a simple test, WIMGAPI seems to handle this
			 * as follows:
			 *
			 * if (size_in_wim > uncompressed_size) {
			 *	Ignore uncompressed_size; use size_in_wim
			 *	instead.
			 * } else {
			 *	Honor uncompressed_size, but treat the part of
			 *	the file data above size_in_wim as all zeros.
			 * }
			 *
			 * So we will do the same.  */
			if (unlikely(!(reshdr.flags &
				       WIM_RESHDR_FLAG_COMPRESSED) &&
				     (reshdr.size_in_wim >
				      reshdr.uncompressed_size)))
			{
				reshdr.uncompressed_size = reshdr.size_in_wim;
			}

			/* Set up a resource specification for this stream.  */

			rspec = MALLOC(sizeof(struct wim_resource_spec));
			if (!rspec)
				goto oom;

			wim_res_hdr_to_spec(&reshdr, wim, rspec);

			cur_entry->offset_in_res = 0;
			cur_entry->size = reshdr.uncompressed_size;
			cur_entry->flags = reshdr.flags;

			lte_bind_wim_resource_spec(cur_entry, rspec);
		}

		/* cur_entry is now a stream bound to a resource.  */

		/* Ignore entries with all zeroes in the hash field.  */
		if (is_zero_hash(cur_entry->hash))
			goto free_cur_entry_and_continue;

		/* Verify that the part number matches that of the underlying
		 * WIM file.  */
		if (part_number != wim->hdr.part_number) {
			num_wrong_part_entries++;
			goto free_cur_entry_and_continue;
		}

		if (reshdr.flags & WIM_RESHDR_FLAG_METADATA) {

			/* Lookup table entry for a metadata resource.  */

			/* Metadata entries with no references must be ignored.
			 * See, for example, the WinPE WIMs from the WAIK v2.1.
			 */
			if (cur_entry->refcnt == 0)
				goto free_cur_entry_and_continue;

			if (cur_entry->refcnt != 1) {
				/* We don't currently support this case due to
				 * the complications of multiple images sharing
				 * the same metadata resource or a metadata
				 * resource also being referenced by files.  */
				ERROR("Found metadata resource with refcnt != 1");
				ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
				goto out;
			}

			if (wim->hdr.part_number != 1) {
				WARNING("Ignoring metadata resource found in a "
					"non-first part of the split WIM");
				goto free_cur_entry_and_continue;
			}

			/* The number of entries in the lookup table with
			 * WIM_RESHDR_FLAG_METADATA set should be the same as
			 * the image_count field in the WIM header.  */
			if (image_index == wim->hdr.image_count) {
				WARNING("Found more metadata resources than images");
				goto free_cur_entry_and_continue;
			}

			/* Notice very carefully:  We are assigning the metadata
			 * resources to images in the same order in which their
			 * lookup table entries occur on disk.  (This is also
			 * the behavior of Microsoft's software.)  In
			 * particular, this overrides the actual locations of
			 * the metadata resources themselves in the WIM file as
			 * well as any information written in the XML data.  */
			DEBUG("Found metadata resource for image %"PRIu32" at "
			      "offset %"PRIu64".",
			      image_index + 1,
			      reshdr.offset_in_wim);

			wim->image_metadata[image_index++]->metadata_lte = cur_entry;
		} else {
			/* Lookup table entry for a non-metadata stream.  */

			/* Ignore this stream if it's a duplicate.  */
			if (lookup_stream(table, cur_entry->hash)) {
				num_duplicate_entries++;
				goto free_cur_entry_and_continue;
			}

			/* Insert the stream into the in-memory lookup table,
			 * keyed by its SHA1 message digest.  */
			lookup_table_insert(table, cur_entry);
		}

		continue;

	free_cur_entry_and_continue:
		if (cur_subpacks &&
		    cur_entry->resource_location == RESOURCE_IN_WIM)
			lte_unbind_wim_resource_spec(cur_entry);
		free_lookup_table_entry(cur_entry);
	}
	cur_entry = NULL;

	if (cur_subpacks) {
		/* End of lookup table terminated a packed run.  */
		ret = finish_subpacks(cur_subpacks, cur_num_subpacks);
		cur_subpacks = NULL;
		if (ret)
			goto out;
	}

	if (wim->hdr.part_number == 1 && image_index != wim->hdr.image_count) {
		WARNING("Could not find metadata resources for all images");
		for (u32 i = image_index; i < wim->hdr.image_count; i++)
			put_image_metadata(wim->image_metadata[i], NULL);
		wim->hdr.image_count = image_index;
	}

	if (num_duplicate_entries > 0) {
		WARNING("Ignoring %zu duplicate streams in the WIM lookup table",
			num_duplicate_entries);
	}

	if (num_wrong_part_entries > 0) {
		WARNING("Ignoring %zu streams with wrong part number",
			num_wrong_part_entries);
	}

	DEBUG("Done reading lookup table.");
	wim->lookup_table = table;
	ret = 0;
	goto out_free_buf;

oom:
	ERROR("Not enough memory to read lookup table!");
	ret = WIMLIB_ERR_NOMEM;
out:
	free_subpack_info(cur_subpacks, cur_num_subpacks);
	free_lookup_table_entry(cur_entry);
	free_lookup_table(table);
out_free_buf:
	FREE(buf);
	return ret;
}

static void
put_wim_lookup_table_entry(struct wim_lookup_table_entry_disk *disk_entry,
			   const struct wim_reshdr *out_reshdr,
			   u16 part_number, u32 refcnt, const u8 *hash)
{
	put_wim_reshdr(out_reshdr, &disk_entry->reshdr);
	disk_entry->part_number = cpu_to_le16(part_number);
	disk_entry->refcnt = cpu_to_le32(refcnt);
	copy_hash(disk_entry->hash, hash);
}

/* Note: the list of stream entries must be sorted so that all entries for the
 * same packed resource are consecutive.  In addition, entries with
 * WIM_RESHDR_FLAG_METADATA set must be in the same order as the indices of the
 * underlying images.  */
int
write_wim_lookup_table_from_stream_list(struct list_head *stream_list,
					struct filedes *out_fd,
					u16 part_number,
					struct wim_reshdr *out_reshdr,
					int write_resource_flags)
{
	size_t table_size;
	struct wim_lookup_table_entry *lte;
	struct wim_lookup_table_entry_disk *table_buf;
	struct wim_lookup_table_entry_disk *table_buf_ptr;
	int ret;
	u64 prev_res_offset_in_wim = ~0ULL;
	u64 prev_uncompressed_size;
	u64 logical_offset;

	table_size = 0;
	list_for_each_entry(lte, stream_list, lookup_table_list) {
		table_size += sizeof(struct wim_lookup_table_entry_disk);

		if (lte->out_reshdr.flags & WIM_RESHDR_FLAG_PACKED_STREAMS &&
		    lte->out_res_offset_in_wim != prev_res_offset_in_wim)
		{
			table_size += sizeof(struct wim_lookup_table_entry_disk);
			prev_res_offset_in_wim = lte->out_res_offset_in_wim;
		}
	}

	DEBUG("Writing WIM lookup table (size=%zu, offset=%"PRIu64")",
	      table_size, out_fd->offset);

	table_buf = MALLOC(table_size);
	if (table_buf == NULL) {
		ERROR("Failed to allocate %zu bytes for temporary lookup table",
		      table_size);
		return WIMLIB_ERR_NOMEM;
	}
	table_buf_ptr = table_buf;

	prev_res_offset_in_wim = ~0ULL;
	prev_uncompressed_size = 0;
	logical_offset = 0;
	list_for_each_entry(lte, stream_list, lookup_table_list) {
		if (lte->out_reshdr.flags & WIM_RESHDR_FLAG_PACKED_STREAMS) {
			struct wim_reshdr tmp_reshdr;

			/* Eww.  When WIMGAPI sees multiple resource packs, it
			 * expects the offsets to be adjusted as if there were
			 * really only one pack.  */

			if (lte->out_res_offset_in_wim != prev_res_offset_in_wim) {
				/* Put the resource entry for pack  */
				tmp_reshdr.offset_in_wim = lte->out_res_offset_in_wim;
				tmp_reshdr.size_in_wim = lte->out_res_size_in_wim;
				tmp_reshdr.uncompressed_size = WIM_PACK_MAGIC_NUMBER;
				tmp_reshdr.flags = WIM_RESHDR_FLAG_PACKED_STREAMS;

				put_wim_lookup_table_entry(table_buf_ptr++,
							   &tmp_reshdr,
							   part_number,
							   1, zero_hash);

				logical_offset += prev_uncompressed_size;

				prev_res_offset_in_wim = lte->out_res_offset_in_wim;
				prev_uncompressed_size = lte->out_res_uncompressed_size;
			}
			tmp_reshdr = lte->out_reshdr;
			tmp_reshdr.offset_in_wim += logical_offset;
			put_wim_lookup_table_entry(table_buf_ptr++,
						   &tmp_reshdr,
						   part_number,
						   lte->out_refcnt,
						   lte->hash);
		} else {
			put_wim_lookup_table_entry(table_buf_ptr++,
						   &lte->out_reshdr,
						   part_number,
						   lte->out_refcnt,
						   lte->hash);
		}

	}
	wimlib_assert((u8*)table_buf_ptr - (u8*)table_buf == table_size);

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
					     write_resource_flags);
	FREE(table_buf);
	DEBUG("ret=%d", ret);
	return ret;
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

/* Allocate a stream entry for the contents of the buffer, or re-use an existing
 * entry in @lookup_table for the same stream.  */
struct wim_lookup_table_entry *
new_stream_from_data_buffer(const void *buffer, size_t size,
			    struct wim_lookup_table *lookup_table)
{
	u8 hash[SHA1_HASH_SIZE];
	struct wim_lookup_table_entry *lte, *existing_lte;

	sha1_buffer(buffer, size, hash);
	existing_lte = lookup_stream(lookup_table, hash);
	if (existing_lte) {
		wimlib_assert(existing_lte->size == size);
		lte = existing_lte;
		lte->refcnt++;
	} else {
		void *buffer_copy;
		lte = new_lookup_table_entry();
		if (lte == NULL)
			return NULL;
		buffer_copy = memdup(buffer, size);
		if (buffer_copy == NULL) {
			free_lookup_table_entry(lte);
			return NULL;
		}
		lte->resource_location  = RESOURCE_IN_ATTACHED_BUFFER;
		lte->attached_buffer    = buffer_copy;
		lte->size               = size;
		copy_hash(lte->hash, hash);
		lookup_table_insert(lookup_table, lte);
	}
	return lte;
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
	duplicate_lte = lookup_stream(lookup_table, lte->hash);
	list_del(&lte->unhashed_list);
	if (duplicate_lte) {
		/* We have a duplicate stream.  Transfer the reference counts
		 * from this stream to the duplicate and update the reference to
		 * this stream (in an inode or ads_entry) to point to the
		 * duplicate.  The caller is responsible for freeing @lte if
		 * needed.  */
		wimlib_assert(!(duplicate_lte->unhashed));
		wimlib_assert(duplicate_lte->size == lte->size);
		duplicate_lte->refcnt += lte->refcnt;
		lte->refcnt = 0;
		*back_ptr = duplicate_lte;
		lte = duplicate_lte;
	} else {
		/* No duplicate stream, so we need to insert this stream into
		 * the lookup table and treat it as a hashed stream. */
		lookup_table_insert(lookup_table, lte);
		lte->unhashed = 0;
	}
	*lte_ret = lte;
	return 0;
}

void
lte_to_wimlib_resource_entry(const struct wim_lookup_table_entry *lte,
			     struct wimlib_resource_entry *wentry)
{
	memset(wentry, 0, sizeof(*wentry));

	wentry->uncompressed_size = lte->size;
	if (lte->resource_location == RESOURCE_IN_WIM) {
		wentry->part_number = lte->rspec->wim->hdr.part_number;
		if (lte->flags & WIM_RESHDR_FLAG_PACKED_STREAMS) {
			wentry->compressed_size = 0;
			wentry->offset = lte->offset_in_res;
		} else {
			wentry->compressed_size = lte->rspec->size_in_wim;
			wentry->offset = lte->rspec->offset_in_wim;
		}
		wentry->raw_resource_offset_in_wim = lte->rspec->offset_in_wim;
		/*wentry->raw_resource_uncompressed_size = lte->rspec->uncompressed_size;*/
		wentry->raw_resource_compressed_size = lte->rspec->size_in_wim;
	}
	copy_hash(wentry->sha1_hash, lte->hash);
	wentry->reference_count = lte->refcnt;
	wentry->is_compressed = (lte->flags & WIM_RESHDR_FLAG_COMPRESSED) != 0;
	wentry->is_metadata = (lte->flags & WIM_RESHDR_FLAG_METADATA) != 0;
	wentry->is_free = (lte->flags & WIM_RESHDR_FLAG_FREE) != 0;
	wentry->is_spanned = (lte->flags & WIM_RESHDR_FLAG_SPANNED) != 0;
	wentry->packed = (lte->flags & WIM_RESHDR_FLAG_PACKED_STREAMS) != 0;
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
	if (flags != 0)
		return WIMLIB_ERR_INVALID_PARAM;

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
