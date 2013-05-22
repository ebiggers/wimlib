/*
 * verify.c
 *
 * Verify WIM inodes and stream reference counts.
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

#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/security.h"

/*
 * Verify a WIM inode:
 *
 * - Check to make sure the security ID is valid
 * - Check to make sure there is at most one unnamed stream
 * - Check to make sure there is at most one DOS name.
 */
int
verify_inode(struct wim_inode *inode, const struct wim_security_data *sd)
{
	struct wim_dentry *dentry;

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
		WARNING("\"%"TS"\" has multiple (%u) un-named streams",
			inode_first_full_path(inode), num_unnamed_streams);
	}

	/* Files cannot have multiple DOS names, even if they have multiple
	 * names in multiple directories (i.e. hard links).
	 * Source: NTFS-3g authors. */
	struct wim_dentry *dentry_with_dos_name = NULL;
	inode_for_each_dentry(dentry, inode) {
		if (dentry_has_short_name(dentry)) {
			if (dentry_with_dos_name) {
				/* This was previously an error, but if we
				 * capture a WIM from UDF on Windows, hard links
				 * are supported but DOS names are automatically
				 * generated for all names for an inode.  */
			#if 0
				ERROR("Hard-linked file has a DOS name at "
				      "both `%"TS"' and `%"TS"'",
				      dentry_full_path(dentry_with_dos_name),
				      dentry_full_path(dentry));
				return WIMLIB_ERR_INVALID_DENTRY;
			#else
				dentry->dos_name_invalid = 1;
			#endif
			}
			dentry_with_dos_name = dentry;
		}
	}
	return 0;
}

static int
lte_fix_refcnt(struct wim_lookup_table_entry *lte, void *ctr)
{
	if (lte->refcnt != lte->real_refcnt) {
		if (wimlib_print_errors) {
			WARNING("The following lookup table entry has a reference "
				"count of %u, but", lte->refcnt);
			WARNING("We found %u references to it",
				lte->real_refcnt);
			print_lookup_table_entry(lte, stderr);
		}
		lte->refcnt = lte->real_refcnt;
		++*(unsigned long *)ctr;
	}
	return 0;
}

static void
tally_inode_refcnts(const struct wim_inode *inode,
		    const struct wim_lookup_table *lookup_table)
{
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		struct wim_lookup_table_entry *lte;
		lte = inode_stream_lte(inode, i, lookup_table);
		if (lte)
			lte->real_refcnt += inode->i_nlink;
	}
}


static int
tally_image_refcnts(WIMStruct *wim)
{
	const struct wim_image_metadata *imd;
	const struct wim_inode *inode;

	imd = wim_get_current_image_metadata(wim);
	image_for_each_inode(inode, imd)
		tally_inode_refcnts(inode, wim->lookup_table);
	return 0;
}


/* Ideally this would be unnecessary... however, the WIMs for Windows 8 are
 * screwed up because some lookup table entries are referenced more times than
 * their stated reference counts.  So theoretically, if we delete all the
 * references to a stream and then remove it, it might still be referenced
 * somewhere else, making a file be missing from the WIM... So, work around this
 * problem by looking at ALL the images to re-calculate the reference count of
 * EVERY lookup table entry.  This only absolutely has to be done before an image
 * is deleted or before an image is mounted read-write. */
void
wim_recalculate_refcnts(WIMStruct *wim)
{
	unsigned long num_ltes_with_bogus_refcnt = 0;

	for_lookup_table_entry(wim->lookup_table, lte_zero_real_refcnt, NULL);
	for_image(wim, WIMLIB_ALL_IMAGES, tally_image_refcnts);
	num_ltes_with_bogus_refcnt = 0;
	for_lookup_table_entry(wim->lookup_table, lte_fix_refcnt,
			       &num_ltes_with_bogus_refcnt);
	if (num_ltes_with_bogus_refcnt != 0) {
		WARNING("A total of %lu entries in the WIM's stream "
			"lookup table had to have\n"
			"          their reference counts fixed.",
			num_ltes_with_bogus_refcnt);
	}
	wim->refcnts_ok = 1;
}
