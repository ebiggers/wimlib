/*
 * verify.c
 *
 * Some functions to verify that stuff in the WIM is valid.  Of course, not
 * *all* the verifications of the input data are in this file.
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

static int
verify_inode(struct wim_inode *inode, const WIMStruct *w)
{
	const struct wim_lookup_table *table = w->lookup_table;
	const struct wim_security_data *sd = wim_const_security_data(w);
	struct wim_dentry *first_dentry = inode_first_dentry(inode);
	struct wim_dentry *dentry;

	/* Check the security ID.  -1 is valid and means "no security
	 * descriptor".  Anything else has to be a valid index into the WIM
	 * image's security descriptors table. */
	if (inode->i_security_id < -1 ||
	    (inode->i_security_id >= 0 &&
	     inode->i_security_id >= sd->num_entries))
	{
		WARNING("\"%"TS"\" has an invalid security ID (%d)",
			dentry_full_path(first_dentry), inode->i_security_id);
		inode->i_security_id = -1;
	}

	/* Check that lookup table entries for all the inode's stream exist,
	 * except if the SHA1 message digest is all 0's, which indicates an
	 * empty stream.
	 *
	 * This check is skipped on split WIMs. */
	if (w->hdr.total_parts == 1 && !inode->i_resolved) {
		for (unsigned i = 0; i <= inode->i_num_ads; i++) {
			struct wim_lookup_table_entry *lte;
			const u8 *hash;
			hash = inode_stream_hash(inode, i);
			lte = __lookup_resource(table, hash);
			if (!lte && !is_zero_hash(hash)) {
				ERROR("Could not find lookup table entry for stream "
				      "%u of dentry `%"TS"'",
				      i, dentry_full_path(first_dentry));
				return WIMLIB_ERR_INVALID_DENTRY;
			}
			if (lte)
				lte->real_refcnt += inode->i_nlink;
		}
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
			dentry_full_path(first_dentry), num_unnamed_streams);
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

	inode->i_verified = 1;
	return 0;
}

/* Run some miscellaneous verifications on a WIM dentry */
int
verify_dentry(struct wim_dentry *dentry, void *wim)
{
	int ret;
	WIMStruct *w = wim;
	/* Verify the associated inode, but only one time no matter how many
	 * dentries it has (unless we are doing a full verification of the WIM,
	 * in which case we need to force the inode to be verified again.) */
	if (!dentry->d_inode->i_verified) {
		ret = verify_inode(dentry->d_inode, w);
		if (ret)
			return ret;
	}
	return 0;
}

static int
image_run_full_verifications(WIMStruct *w)
{
	struct wim_image_metadata *imd;
	struct wim_inode *inode;

	imd = wim_get_current_image_metadata(w);
	image_for_each_inode(inode, imd)
		inode->i_verified = 0;
	return for_dentry_in_tree(imd->root_dentry, verify_dentry, w);
}

static int
lte_fix_refcnt(struct wim_lookup_table_entry *lte, void *ctr)
{
	if (lte->refcnt != lte->real_refcnt) {
	#ifdef ENABLE_ERROR_MESSAGES
		WARNING("The following lookup table entry has a reference "
			"count of %u, but", lte->refcnt);
		WARNING("We found %u references to it",
			lte->real_refcnt);
		print_lookup_table_entry(lte, stderr);
	#endif
		lte->refcnt = lte->real_refcnt;
		++*(unsigned long *)ctr;
	}
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
int
wim_run_full_verifications(WIMStruct *w)
{
	int ret;

	for_lookup_table_entry(w->lookup_table, lte_zero_real_refcnt, NULL);

	w->all_images_verified = 1; /* Set *before* image_run_full_verifications,
				       because of check in read_metadata_resource() */
	ret = for_image(w, WIMLIB_ALL_IMAGES, image_run_full_verifications);
	if (ret == 0) {
		unsigned long num_ltes_with_bogus_refcnt = 0;
		for_lookup_table_entry(w->lookup_table, lte_fix_refcnt,
				       &num_ltes_with_bogus_refcnt);
		if (num_ltes_with_bogus_refcnt != 0) {
			WARNING("A total of %lu entries in the WIM's stream "
				"lookup table had to have\n"
				"          their reference counts fixed.",
				num_ltes_with_bogus_refcnt);
		}
	} else {
		w->all_images_verified = 0;
	}
	return ret;
}
