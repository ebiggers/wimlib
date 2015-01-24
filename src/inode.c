/*
 * inode.c
 *
 * Functions that operate on WIM inodes.
 *
 * See dentry.c for a description of the relationship between WIM dentries and
 * WIM inodes.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
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

#include <errno.h>

#include "wimlib/assert.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/inode.h"
#include "wimlib/lookup_table.h"
#include "wimlib/security.h"
#include "wimlib/timestamp.h"

/* Allocate a new inode.  Set the timestamps to the current time.  */
struct wim_inode *
new_inode(void)
{
	struct wim_inode *inode = new_timeless_inode();
	if (inode) {
		u64 now = now_as_wim_timestamp();
		inode->i_creation_time = now;
		inode->i_last_access_time = now;
		inode->i_last_write_time = now;
	}
	return inode;
}

/* Allocate a new inode.  Leave the timestamps zeroed out.  */
struct wim_inode *
new_timeless_inode(void)
{
	struct wim_inode *inode = CALLOC(1, sizeof(struct wim_inode));
	if (inode) {
		inode->i_security_id = -1;
		/*inode->i_nlink = 0;*/
		inode->i_next_stream_id = 1;
		inode->i_not_rpfixed = 1;
		inode->i_canonical_streams = 1;
		INIT_LIST_HEAD(&inode->i_list);
		INIT_LIST_HEAD(&inode->i_dentry);
	}
	return inode;
}

/* Free memory allocated within an alternate data stream entry.  */
static void
destroy_ads_entry(struct wim_ads_entry *ads_entry)
{
	FREE(ads_entry->stream_name);
}

static void
free_inode(struct wim_inode *inode)
{
	if (unlikely(inode->i_ads_entries)) {
		for (unsigned i = 0; i < inode->i_num_ads; i++)
			destroy_ads_entry(&inode->i_ads_entries[i]);
		FREE(inode->i_ads_entries);
	}
	if (unlikely(inode->i_extra))
		FREE(inode->i_extra);
	/* HACK: This may instead delete the inode from i_list, but hlist_del()
	 * behaves the same as list_del(). */
	if (!hlist_unhashed(&inode->i_hlist))
		hlist_del(&inode->i_hlist);
	FREE(inode);
}

static inline void
free_inode_if_unneeded(struct wim_inode *inode)
{
	if (inode->i_nlink)
		return;
#ifdef WITH_FUSE
	if (inode->i_num_opened_fds)
		return;
#endif
	free_inode(inode);
}

/* Associate a dentry with the specified inode.  */
void
d_associate(struct wim_dentry *dentry, struct wim_inode *inode)
{
	wimlib_assert(!dentry->d_inode);

	list_add_tail(&dentry->d_alias, &inode->i_dentry);
	dentry->d_inode = inode;
	inode->i_nlink++;
}

/* Disassociate a dentry from its inode, if any.  Following this, free the inode
 * if it is no longer in use.  */
void
d_disassociate(struct wim_dentry *dentry)
{
	struct wim_inode *inode = dentry->d_inode;

	if (unlikely(!inode))
		return;

	wimlib_assert(inode->i_nlink > 0);

	list_del(&dentry->d_alias);
	dentry->d_inode = NULL;
	inode->i_nlink--;

	free_inode_if_unneeded(inode);
}

#ifdef WITH_FUSE
void
inode_dec_num_opened_fds(struct wim_inode *inode)
{
	wimlib_assert(inode->i_num_opened_fds > 0);

	if (--inode->i_num_opened_fds == 0) {
		/* The last file descriptor to this inode was closed.  */
		FREE(inode->i_fds);
		inode->i_fds = NULL;
		inode->i_num_allocated_fds = 0;

		free_inode_if_unneeded(inode);
	}
}
#endif

/*
 * Returns the alternate data stream entry belonging to @inode that has the
 * stream name @stream_name, or NULL if the inode has no alternate data stream
 * with that name.
 *
 * If @p stream_name is the empty string, NULL is returned --- that is, this
 * function will not return "unnamed" alternate data stream entries.
 *
 * If NULL is returned, errno is set.
 */
struct wim_ads_entry *
inode_get_ads_entry(struct wim_inode *inode, const tchar *stream_name)
{
	int ret;
	const utf16lechar *stream_name_utf16le;
	size_t stream_name_utf16le_nbytes;
	unsigned i;
	struct wim_ads_entry *result;

	if (inode->i_num_ads == 0) {
		errno = ENOENT;
		return NULL;
	}

	if (stream_name[0] == T('\0')) {
		errno = ENOENT;
		return NULL;
	}

	ret = tstr_get_utf16le_and_len(stream_name, &stream_name_utf16le,
				       &stream_name_utf16le_nbytes);
	if (ret)
		return NULL;

	i = 0;
	result = NULL;
	do {
		if (!cmp_utf16le_strings(inode->i_ads_entries[i].stream_name,
					 inode->i_ads_entries[i].stream_name_nbytes /
						sizeof(utf16lechar),
					 stream_name_utf16le,
					 stream_name_utf16le_nbytes /
						sizeof(utf16lechar),
					 default_ignore_case))
		{
			result = &inode->i_ads_entries[i];
			break;
		}
	} while (++i != inode->i_num_ads);

	tstr_put_utf16le(stream_name_utf16le);

	if (!result)
		errno = ENOENT;
	return result;
}

static struct wim_ads_entry *
do_inode_add_ads(struct wim_inode *inode,
		 utf16lechar *stream_name, size_t stream_name_nbytes)
{
	unsigned num_ads;
	struct wim_ads_entry *ads_entries;
	struct wim_ads_entry *new_entry;

	if (unlikely(inode->i_num_ads >= 0xfffe)) {
		ERROR("File \"%"TS"\" has too many alternate data streams!",
		      inode_first_full_path(inode));
		errno = EFBIG;
		return NULL;
	}
	num_ads = inode->i_num_ads + 1;
	ads_entries = REALLOC(inode->i_ads_entries,
			      num_ads * sizeof(inode->i_ads_entries[0]));
	if (!ads_entries)
		return NULL;

	inode->i_ads_entries = ads_entries;

	new_entry = &inode->i_ads_entries[num_ads - 1];

	memset(new_entry, 0, sizeof(struct wim_ads_entry));
	new_entry->stream_name = stream_name;
	new_entry->stream_name_nbytes = stream_name_nbytes;
	new_entry->stream_id = inode->i_next_stream_id++;
	inode->i_num_ads = num_ads;
	return new_entry;
}

/*
 * Add an alternate data stream entry to a WIM inode (UTF-16LE version).  On
 * success, returns a pointer to the new entry.  Note that this pointer might
 * become invalid if another ADS entry is added to the inode.  On failure,
 * returns NULL and sets errno.
 */
struct wim_ads_entry *
inode_add_ads_utf16le(struct wim_inode *inode,
		      const utf16lechar *stream_name, size_t stream_name_nbytes)
{
	utf16lechar *dup = NULL;
	struct wim_ads_entry *result;

	if (stream_name_nbytes) {
		dup = utf16le_dupz(stream_name, stream_name_nbytes);
		if (!dup)
			return NULL;
	}

	result = do_inode_add_ads(inode, dup, stream_name_nbytes);
	if (!result)
		FREE(dup);
	return result;
}

/*
 * Add an alternate data stream entry to a WIM inode (tchar version).  On
 * success, returns a pointer to the new entry.  Note that this pointer might
 * become invalid if another ADS entry is added to the inode.  On failure,
 * returns NULL and sets errno.
 */
struct wim_ads_entry *
inode_add_ads(struct wim_inode *inode, const tchar *stream_name)
{
	utf16lechar *stream_name_utf16le = NULL;
	size_t stream_name_utf16le_nbytes = 0;
	struct wim_ads_entry *result;

	if (stream_name && *stream_name)
		if (tstr_to_utf16le(stream_name,
				    tstrlen(stream_name) * sizeof(tchar),
				    &stream_name_utf16le,
				    &stream_name_utf16le_nbytes))
			return NULL;

	result = do_inode_add_ads(inode, stream_name_utf16le,
				  stream_name_utf16le_nbytes);
	if (!result)
		FREE(stream_name_utf16le);
	return result;
}

/*
 * Add an data alternate stream entry to a WIM inode, where the contents of the
 * new stream are specified in a data buffer.  The inode must be resolved.
 *
 * On success, returns a pointer to the new alternate data stream entry.  Note
 * that this pointer might become invalid if another ADS entry is added to the
 * inode.  On failure, returns NULL and sets errno.
 */
struct wim_ads_entry *
inode_add_ads_with_data(struct wim_inode *inode, const tchar *name,
			const void *value, size_t size,
			struct wim_lookup_table *lookup_table)
{
	struct wim_ads_entry *new_entry;

	wimlib_assert(inode->i_resolved);

	new_entry = inode_add_ads(inode, name);
	if (unlikely(!new_entry))
		return NULL;

	new_entry->lte = new_stream_from_data_buffer(value, size, lookup_table);
	if (unlikely(!new_entry->lte)) {
		inode_remove_ads(inode, new_entry, NULL);
		return NULL;
	}
	return new_entry;
}

/* Remove an alternate data stream from a WIM inode.  */
void
inode_remove_ads(struct wim_inode *inode, struct wim_ads_entry *entry,
		 struct wim_lookup_table *lookup_table)
{
	struct wim_lookup_table_entry *lte;
	unsigned idx = entry - inode->i_ads_entries;

	wimlib_assert(idx < inode->i_num_ads);
	wimlib_assert(inode->i_resolved);

	lte = entry->lte;
	if (lte)
		lte_decrement_refcnt(lte, lookup_table);

	destroy_ads_entry(entry);

	memmove(&inode->i_ads_entries[idx],
		&inode->i_ads_entries[idx + 1],
		(inode->i_num_ads - idx - 1) * sizeof(inode->i_ads_entries[0]));
	inode->i_num_ads--;
}

/* Return true iff the specified inode has at least one named data stream.  */
bool
inode_has_named_stream(const struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_ads; i++)
		if (inode->i_ads_entries[i].stream_name_nbytes)
			return true;
	return false;
}

/* Set the unnamed stream of a WIM inode, given a data buffer containing the
 * stream contents.  The inode must be resolved and cannot already have an
 * unnamed stream.  */
int
inode_set_unnamed_stream(struct wim_inode *inode, const void *data, size_t len,
			 struct wim_lookup_table *lookup_table)
{
	wimlib_assert(inode->i_resolved);
	wimlib_assert(!inode->i_lte);

	inode->i_lte = new_stream_from_data_buffer(data, len, lookup_table);
	if (!inode->i_lte)
		return WIMLIB_ERR_NOMEM;
	return 0;
}

/*
 * Resolve an inode's single-instance streams.
 *
 * This takes each SHA-1 message digest stored in the inode or one of its ADS
 * entries and replaces it with a pointer directly to the appropriate 'struct
 * wim_lookup_table_entry' currently inserted into @table to represent the
 * single-instance stream having that SHA-1 message digest.
 *
 * If @force is %false:
 *	If any of the needed single-instance streams do not exist in @table,
 *	return WIMLIB_ERR_RESOURCE_NOT_FOUND and leave the inode unmodified.
 * If @force is %true:
 *	If any of the needed single-instance streams do not exist in @table,
 *	allocate new entries for them and insert them into @table.  This does
 *	not, of course, cause these streams to magically exist, but this is
 *	needed by the code for extraction from a pipe.
 *
 * If the inode is already resolved, this function does nothing.
 *
 * Returns 0 on success; WIMLIB_ERR_NOMEM if out of memory; or
 * WIMLIB_ERR_RESOURCE_NOT_FOUND if @force is %false and at least one
 * single-instance stream referenced by the inode was missing.
 */
int
inode_resolve_streams(struct wim_inode *inode, struct wim_lookup_table *table,
		      bool force)
{
	const u8 *hash;
	struct wim_lookup_table_entry *lte, *ads_lte;

	if (inode->i_resolved)
		return 0;

	struct wim_lookup_table_entry *ads_ltes[inode->i_num_ads];

	/* Resolve the default data stream */
	lte = NULL;
	hash = inode->i_hash;
	if (!is_zero_hash(hash)) {
		lte = lookup_stream(table, hash);
		if (!lte) {
			if (force) {
				lte = new_lookup_table_entry();
				if (!lte)
					return WIMLIB_ERR_NOMEM;
				copy_hash(lte->hash, hash);
				lookup_table_insert(table, lte);
			} else {
				goto stream_not_found;
			}
		}
	}

	/* Resolve the alternate data streams */
	for (unsigned i = 0; i < inode->i_num_ads; i++) {
		struct wim_ads_entry *cur_entry;

		ads_lte = NULL;
		cur_entry = &inode->i_ads_entries[i];
		hash = cur_entry->hash;
		if (!is_zero_hash(hash)) {
			ads_lte = lookup_stream(table, hash);
			if (!ads_lte) {
				if (force) {
					ads_lte = new_lookup_table_entry();
					if (!ads_lte)
						return WIMLIB_ERR_NOMEM;
					copy_hash(ads_lte->hash, hash);
					lookup_table_insert(table, ads_lte);
				} else {
					goto stream_not_found;
				}
			}
		}
		ads_ltes[i] = ads_lte;
	}
	inode->i_lte = lte;
	for (unsigned i = 0; i < inode->i_num_ads; i++)
		inode->i_ads_entries[i].lte = ads_ltes[i];
	inode->i_resolved = 1;
	return 0;

stream_not_found:
	return stream_not_found_error(inode, hash);
}

/*
 * Undo the effects of inode_resolve_streams().
 *
 * If the inode is not resolved, this function does nothing.
 */
void
inode_unresolve_streams(struct wim_inode *inode)
{
	if (!inode->i_resolved)
		return;

	if (inode->i_lte)
		copy_hash(inode->i_hash, inode->i_lte->hash);
	else
		zero_out_hash(inode->i_hash);

	for (unsigned i = 0; i < inode->i_num_ads; i++) {
		if (inode->i_ads_entries[i].lte)
			copy_hash(inode->i_ads_entries[i].hash,
				  inode->i_ads_entries[i].lte->hash);
		else
			zero_out_hash(inode->i_ads_entries[i].hash);
	}
	inode->i_resolved = 0;
}

int
stream_not_found_error(const struct wim_inode *inode, const u8 *hash)
{
	if (wimlib_print_errors) {
		tchar hashstr[SHA1_HASH_SIZE * 2 + 1];

		sprint_hash(hash, hashstr);

		ERROR("\"%"TS"\": stream not found\n"
		      "        SHA-1 message digest of missing stream:\n"
		      "        %"TS"",
		      inode_first_full_path(inode), hashstr);
	}
	return WIMLIB_ERR_RESOURCE_NOT_FOUND;
}

/*
 * Return the lookup table entry for the specified stream of the inode, or NULL
 * if the specified stream is empty or not available.
 *
 * stream_idx = 0: default data stream
 * stream_idx > 0: alternate data stream
 */
struct wim_lookup_table_entry *
inode_stream_lte(const struct wim_inode *inode, unsigned stream_idx,
		 const struct wim_lookup_table *table)
{
	if (inode->i_resolved)
		return inode_stream_lte_resolved(inode, stream_idx);
	if (stream_idx == 0)
		return lookup_stream(table, inode->i_hash);
	return lookup_stream(table, inode->i_ads_entries[stream_idx - 1].hash);
}

/*
 * Return the lookup table entry for the unnamed data stream of a *resolved*
 * inode, or NULL if the inode's unnamed data stream is empty.  Also return the
 * 0-based index of the unnamed data stream in *stream_idx_ret.
 */
struct wim_lookup_table_entry *
inode_unnamed_stream_resolved(const struct wim_inode *inode,
			      unsigned *stream_idx_ret)
{
	wimlib_assert(inode->i_resolved);

	*stream_idx_ret = 0;
	if (likely(inode->i_lte))
		return inode->i_lte;

	for (unsigned i = 0; i < inode->i_num_ads; i++) {
		if (inode->i_ads_entries[i].stream_name_nbytes == 0 &&
		    inode->i_ads_entries[i].lte)
		{
			*stream_idx_ret = i + 1;
			return inode->i_ads_entries[i].lte;
		}
	}
	return NULL;
}

/*
 * Return the lookup table entry for the unnamed data stream of an inode, or
 * NULL if the inode's unnamed data stream is empty or not available.
 *
 * Note: this is complicated by the fact that WIMGAPI may put the unnamed data
 * stream in an alternate data stream entry rather than in the dentry itself.
 */
struct wim_lookup_table_entry *
inode_unnamed_lte(const struct wim_inode *inode,
		  const struct wim_lookup_table *table)
{
	struct wim_lookup_table_entry *lte;

	if (inode->i_resolved)
		return inode_unnamed_lte_resolved(inode);

	lte = lookup_stream(table, inode->i_hash);
	if (likely(lte))
		return lte;

	for (unsigned i = 0; i < inode->i_num_ads; i++) {
		if (inode->i_ads_entries[i].stream_name_nbytes)
			continue;
		lte = lookup_stream(table, inode->i_ads_entries[i].hash);
		if (lte)
			return lte;
	}
	return NULL;
}

/* Return the SHA-1 message digest of the specified stream of the inode, or a
 * void SHA-1 of all zeroes if the specified stream is empty.   */
const u8 *
inode_stream_hash(const struct wim_inode *inode, unsigned stream_idx)
{
	if (inode->i_resolved) {
		struct wim_lookup_table_entry *lte;

		lte = inode_stream_lte_resolved(inode, stream_idx);
		if (lte)
			return lte->hash;
		return zero_hash;
	}
	if (stream_idx == 0)
		return inode->i_hash;
	return inode->i_ads_entries[stream_idx - 1].hash;
}

/* Return the SHA-1 message digest of the unnamed data stream of the inode, or a
 * void SHA-1 of all zeroes if the inode's unnamed data stream is empty.   */
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

/* Acquire another reference to each single-instance stream referenced by this
 * inode.  This is necessary when creating a hard link to this inode.
 *
 * The inode must be resolved.  */
void
inode_ref_streams(struct wim_inode *inode)
{
	wimlib_assert(inode->i_resolved);

	if (inode->i_lte)
		inode->i_lte->refcnt++;
	for (unsigned i = 0; i < inode->i_num_ads; i++)
		if (inode->i_ads_entries[i].lte)
			inode->i_ads_entries[i].lte->refcnt++;
}

/* Drop a reference to each single-instance stream referenced by this inode.
 * This is necessary when deleting a hard link to this inode.  */
void
inode_unref_streams(struct wim_inode *inode,
		    struct wim_lookup_table *lookup_table)
{
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		struct wim_lookup_table_entry *lte;

		lte = inode_stream_lte(inode, i, lookup_table);
		if (lte)
			lte_decrement_refcnt(lte, lookup_table);
	}
}

/*
 * Read the alternate data stream entries of a WIM dentry.
 *
 * @p:
 *	Pointer to buffer that starts with the first alternate stream entry.
 *
 * @inode:
 *	Inode to load the alternate data streams into.  @inode->i_num_ads must
 *	have been set to the number of alternate data streams that are expected.
 *
 * @nbytes_remaining_p:
 *	Number of bytes of data remaining in the buffer pointed to by @p.
 *	On success this will be updated to point just past the ADS entries.
 *
 * On success, inode->i_ads_entries is set to an array of `struct
 * wim_ads_entry's of length inode->i_num_ads.  On failure, @inode is not
 * modified.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	WIMLIB_ERR_NOMEM
 */
int
read_ads_entries(const u8 * restrict p, struct wim_inode * restrict inode,
		 size_t *nbytes_remaining_p)
{
	size_t nbytes_remaining = *nbytes_remaining_p;
	unsigned num_ads;
	struct wim_ads_entry *ads_entries;
	int ret;

	BUILD_BUG_ON(sizeof(struct wim_ads_entry_on_disk) != WIM_ADS_ENTRY_DISK_SIZE);

	/* Allocate an array for our in-memory representation of the alternate
	 * data stream entries. */
	num_ads = inode->i_num_ads;
	ads_entries = CALLOC(num_ads, sizeof(inode->i_ads_entries[0]));
	if (!ads_entries)
		goto out_of_memory;

	/* Read the entries into our newly allocated buffer. */
	for (unsigned i = 0; i < num_ads; i++) {
		u64 length;
		struct wim_ads_entry *cur_entry;
		const struct wim_ads_entry_on_disk *disk_entry =
			(const struct wim_ads_entry_on_disk*)p;

		cur_entry = &ads_entries[i];
		ads_entries[i].stream_id = i + 1;

		/* Do we have at least the size of the fixed-length data we know
		 * need? */
		if (nbytes_remaining < sizeof(struct wim_ads_entry_on_disk))
			goto out_invalid;

		/* Read the length field */
		length = le64_to_cpu(disk_entry->length);

		/* Make sure the length field is neither so small it doesn't
		 * include all the fixed-length data nor so large it overflows
		 * the metadata resource buffer. */
		if (length < sizeof(struct wim_ads_entry_on_disk) ||
		    length > nbytes_remaining)
			goto out_invalid;

		/* Read the rest of the fixed-length data. */

		cur_entry->reserved = le64_to_cpu(disk_entry->reserved);
		copy_hash(cur_entry->hash, disk_entry->hash);
		cur_entry->stream_name_nbytes = le16_to_cpu(disk_entry->stream_name_nbytes);

		/* If stream_name_nbytes != 0, this is a named stream.
		 * Otherwise this is an unnamed stream, or in some cases (bugs
		 * in Microsoft's software I guess) a meaningless entry
		 * distinguished from the real unnamed stream entry, if any, by
		 * the fact that the real unnamed stream entry has a nonzero
		 * hash field. */
		if (cur_entry->stream_name_nbytes) {
			/* The name is encoded in UTF16-LE, which uses 2-byte
			 * coding units, so the length of the name had better be
			 * an even number of bytes... */
			if (cur_entry->stream_name_nbytes & 1)
				goto out_invalid;

			/* Add the length of the stream name to get the length
			 * we actually need to read.  Make sure this isn't more
			 * than the specified length of the entry. */
			if (sizeof(struct wim_ads_entry_on_disk) +
			    cur_entry->stream_name_nbytes > length)
				goto out_invalid;

			cur_entry->stream_name = utf16le_dupz(disk_entry->stream_name,
							      cur_entry->stream_name_nbytes);
			if (!cur_entry->stream_name)
				goto out_of_memory;
		} else {
			/* Mark inode as having weird stream entries.  */
			inode->i_canonical_streams = 0;
		}

		/* It's expected that the size of every ADS entry is a multiple
		 * of 8.  However, to be safe, I'm allowing the possibility of
		 * an ADS entry at the very end of the metadata resource ending
		 * unaligned.  So although we still need to increment the input
		 * pointer by @length to reach the next ADS entry, it's possible
		 * that less than @length is actually remaining in the metadata
		 * resource. We should set the remaining bytes to 0 if this
		 * happens. */
		length = (length + 7) & ~7;
		p += length;
		if (nbytes_remaining < length)
			nbytes_remaining = 0;
		else
			nbytes_remaining -= length;
	}
	inode->i_ads_entries = ads_entries;
	inode->i_next_stream_id = inode->i_num_ads + 1;
	*nbytes_remaining_p = nbytes_remaining;
	ret = 0;
	goto out;
out_of_memory:
	ret = WIMLIB_ERR_NOMEM;
	goto out_free_ads_entries;
out_invalid:
	ERROR("An alternate data stream entry is invalid");
	ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
out_free_ads_entries:
	if (ads_entries) {
		for (unsigned i = 0; i < num_ads; i++)
			destroy_ads_entry(&ads_entries[i]);
		FREE(ads_entries);
	}
out:
	return ret;
}

/* Check a WIM inode for unusual field values.  */
void
check_inode(struct wim_inode *inode, const struct wim_security_data *sd)
{
	/* Check the security ID.  -1 is valid and means "no security
	 * descriptor".  Anything else has to be a valid index into the WIM
	 * image's security descriptors table. */
	if (inode->i_security_id < -1 ||
	    (inode->i_security_id >= 0 &&
	     inode->i_security_id >= sd->num_entries))
	{
		WARNING("\"%"TS"\" has an invalid security ID (%d)",
			inode_first_full_path(inode), inode->i_security_id);
		inode->i_security_id = -1;
	}

	/* Make sure there is only one unnamed data stream. */
	unsigned num_unnamed_streams = 0;
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		const u8 *hash;
		hash = inode_stream_hash(inode, i);
		if (inode_stream_name_nbytes(inode, i) == 0 && !is_zero_hash(hash))
			num_unnamed_streams++;
	}
	if (num_unnamed_streams > 1) {
		WARNING("\"%"TS"\" has multiple (%u) unnamed streams",
			inode_first_full_path(inode), num_unnamed_streams);
		/* We currently don't treat this as an error and will just end
		 * up using the first unnamed data stream in the inode.  */
	}
}

/*
 * Translate a single-instance stream entry into the pointer contained in the
 * inode (or ads entry of an inode) that references it.
 *
 * This is only possible for "unhashed" streams, which are guaranteed to have
 * only one reference, and that reference is guaranteed to be in a resolved
 * inode.  (It can't be in an unresolved inode, since that would imply the hash
 * is known!)
 */
struct wim_lookup_table_entry **
retrieve_lte_pointer(struct wim_lookup_table_entry *lte)
{
	wimlib_assert(lte->unhashed);
	struct wim_inode *inode = lte->back_inode;
	u32 stream_id = lte->back_stream_id;
	if (stream_id == 0)
		return &inode->i_lte;
	for (unsigned i = 0; i < inode->i_num_ads; i++)
		if (inode->i_ads_entries[i].stream_id == stream_id)
			return &inode->i_ads_entries[i].lte;
	wimlib_assert(0);
	return NULL;
}
