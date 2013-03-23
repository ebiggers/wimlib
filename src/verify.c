/*
 * verify.c
 *
 * Some functions to verify that stuff in the WIM is valid.  Of course, not
 * *all* the verifications of the input data are in this file.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * wimlib - Library for working with WIM files
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
#include "dentry.h"
#include "lookup_table.h"

static int
verify_inode(struct wim_inode *inode, const WIMStruct *w)
{
	const struct wim_lookup_table *table = w->lookup_table;
	const struct wim_security_data *sd = wim_const_security_data(w);
	const struct wim_dentry *first_dentry = inode_first_dentry(inode);
	const struct wim_dentry *dentry;
	int ret = WIMLIB_ERR_INVALID_DENTRY;

	/* Check the security ID.  -1 is valid and means "no security
	 * descriptor".  Anything else has to be a valid index into the WIM
	 * image's security descriptors table. */
	if (inode->i_security_id < -1) {
		ERROR("Dentry `%"TS"' has an invalid security ID (%d)",
		      first_dentry->full_path, inode->i_security_id);
		goto out;
	}

	if (inode->i_security_id >= sd->num_entries) {
		ERROR("Dentry `%"TS"' has an invalid security ID (%d) "
		      "(there are only %u entries in the security table)",
		      first_dentry->full_path, inode->i_security_id,
		      sd->num_entries);
		goto out;
	}

	/* Check that lookup table entries for all the inode's stream exist,
	 * except if the SHA1 message digest is all 0's, which indicates an
	 * empty stream.
	 *
	 * This check is skipped on split WIMs. */
	if (w->hdr.total_parts == 1) {
		for (unsigned i = 0; i <= inode->i_num_ads; i++) {
			struct wim_lookup_table_entry *lte;
			const u8 *hash;
			hash = inode_stream_hash_unresolved(inode, i);
			lte = __lookup_resource(table, hash);
			if (!lte && !is_zero_hash(hash)) {
				ERROR("Could not find lookup table entry for stream "
				      "%u of dentry `%"TS"'",
				      i, first_dentry->full_path);
				goto out;
			}
			if (lte)
				lte->real_refcnt += inode->i_nlink;
		}
	}

	/* Make sure there is only one unnamed data stream. */
	unsigned num_unnamed_streams = 0;
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		const u8 *hash;
		hash = inode_stream_hash_unresolved(inode, i);
		if (inode_stream_name_nbytes(inode, i) == 0 && !is_zero_hash(hash))
			num_unnamed_streams++;
	}
	if (num_unnamed_streams > 1) {
		ERROR("Dentry `%"TS"' has multiple (%u) un-named streams",
		      first_dentry->full_path, num_unnamed_streams);
		goto out;
	}

	/* Files cannot have multiple DOS names, even if they have multiple
	 * names in multiple directories (i.e. hard links).
	 * Source: NTFS-3g authors. */
	const struct wim_dentry *dentry_with_dos_name = NULL;
	inode_for_each_dentry(dentry, inode) {
		if (dentry_has_short_name(dentry)) {
			if (dentry_with_dos_name) {
				ERROR("Hard-linked file has a DOS name at "
				      "both `%"TS"' and `%"TS"'",
				      dentry_with_dos_name->full_path,
				      dentry->full_path);
				goto out;
			}
			dentry_with_dos_name = dentry;
		}
	}

	/* Directories with multiple links have not been tested. XXX */
	if (inode->i_nlink > 1 && inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
		ERROR("Hard-linked directory `%"TS"' is unsupported",
		      first_dentry->full_path);
		goto out;
	}

	inode->i_verified = 1;
	ret = 0;
out:
	return ret;
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
	if (!dentry->d_inode->i_verified || w->full_verification_in_progress) {
		ret = verify_inode(dentry->d_inode, w);
		if (ret != 0)
			return ret;
	}

	/* Make sure root dentry is unnamed, while every other dentry has at
	 * least a long name.
	 *
	 * I am assuming that dentries having only a DOS name is illegal; i.e.,
	 * Windows will always combine the Win32 name and DOS name for a file
	 * into a single WIM dentry, even if they are stored separately on NTFS.
	 * (This seems to be the case...) */
	if (dentry_is_root(dentry)) {
		if (dentry_has_long_name(dentry) || dentry_has_short_name(dentry)) {
			ERROR("The root dentry has a nonempty name!");
			return WIMLIB_ERR_INVALID_DENTRY;
		}
	} else {
		if (!dentry_has_long_name(dentry)) {
			ERROR("Dentry `%"TS"' has no long name!",
			      dentry->full_path);
			return WIMLIB_ERR_INVALID_DENTRY;
		}
	}

#if 0
	/* Check timestamps */
	if (inode->i_last_access_time < inode->i_creation_time ||
	    inode->i_last_write_time < inode->i_creation_time) {
		WARNING("Dentry `%"TS"' was created after it was last accessed or "
			"written to", dentry->full_path);
	}
#endif

	return 0;
}

static int
image_run_full_verifications(WIMStruct *w)
{
	return for_dentry_in_tree(wim_root_dentry(w), verify_dentry, w);
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
	w->all_images_verified = 1;
	w->full_verification_in_progress = 1;
	ret = for_image(w, WIMLIB_ALL_IMAGES, image_run_full_verifications);
	w->full_verification_in_progress = 0;
	if (ret == 0) {
		unsigned long num_ltes_with_bogus_refcnt = 0;
		for (int i = 0; i < w->hdr.image_count; i++)
			w->image_metadata[i].metadata_lte->real_refcnt++;
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

/*
 * verify_swm_set: - Sanity checks to make sure a set of WIMs correctly
 *		     correspond to a spanned set.
 *
 * @w:
 * 	Part 1 of the set.
 *
 * @additional_swms:
 * 	All parts of the set other than part 1.
 *
 * @num_additional_swms:
 * 	Number of WIMStructs in @additional_swms.  Or, the total number of parts
 * 	in the set minus 1.
 *
 * @return:
 * 	0 on success; WIMLIB_ERR_SPLIT_INVALID if the set is not valid.
 */
int
verify_swm_set(WIMStruct *w, WIMStruct **additional_swms,
	       unsigned num_additional_swms)
{
	unsigned total_parts = w->hdr.total_parts;
	int ctype;
	const u8 *guid;

	if (total_parts != num_additional_swms + 1) {
		ERROR("`%"TS"' says there are %u parts in the spanned set, "
		      "but %"TS"%u part%"TS" provided",
		      w->filename, total_parts,
		      (num_additional_swms + 1 < total_parts) ? T("only ") : T(""),
		      num_additional_swms + 1,
		      (num_additional_swms) ? T("s were") : T(" was"));
		return WIMLIB_ERR_SPLIT_INVALID;
	}
	if (w->hdr.part_number != 1) {
		ERROR("WIM `%"TS"' is not the first part of the split WIM.",
		      T(w->filename));
		return WIMLIB_ERR_SPLIT_INVALID;
	}
	for (unsigned i = 0; i < num_additional_swms; i++) {
		if (additional_swms[i]->hdr.total_parts != total_parts) {
			ERROR("WIM `%"TS"' says there are %u parts in the "
			      "spanned set, but %u parts were provided",
			      additional_swms[i]->filename,
			      additional_swms[i]->hdr.total_parts,
			      total_parts);
			return WIMLIB_ERR_SPLIT_INVALID;
		}
	}

	/* keep track of ctype and guid just to make sure they are the same for
	 * all the WIMs. */
	ctype = wimlib_get_compression_type(w);
	guid = w->hdr.guid;

	{
		/* parts_to_swms is not allocated at function scope because it
		 * should only be allocated after num_additional_swms was
		 * checked to be the same as w->hdr.total_parts.  Otherwise, it
		 * could be unexpectedly high and cause a stack overflow. */
		WIMStruct *parts_to_swms[num_additional_swms];
		ZERO_ARRAY(parts_to_swms);
		for (unsigned i = 0; i < num_additional_swms; i++) {

			WIMStruct *swm = additional_swms[i];

			if (wimlib_get_compression_type(swm) != ctype) {
				ERROR("The split WIMs do not all have the same "
				      "compression type");
				return WIMLIB_ERR_SPLIT_INVALID;
			}
			if (memcmp(guid, swm->hdr.guid, WIM_GID_LEN) != 0) {
				ERROR("The split WIMs do not all have the same "
				      "GUID");
				return WIMLIB_ERR_SPLIT_INVALID;
			}
			if (swm->hdr.part_number == 1) {
				ERROR("WIMs `%"TS"' and `%"TS"' both are marked "
				      "as the first WIM in the spanned set",
				      w->filename, swm->filename);
				return WIMLIB_ERR_SPLIT_INVALID;
			}
			if (swm->hdr.part_number == 0 ||
			    swm->hdr.part_number > total_parts)
			{
				ERROR("WIM `%"TS"' says it is part %u in the "
				      "spanned set, but the part number must "
				      "be in the range [1, %u]",
				      swm->filename, swm->hdr.part_number, total_parts);
				return WIMLIB_ERR_SPLIT_INVALID;
			}
			if (parts_to_swms[swm->hdr.part_number - 2])
			{
				ERROR("`%"TS"' and `%"TS"' are both marked as "
				      "part %u of %u in the spanned set",
				      parts_to_swms[swm->hdr.part_number - 2]->filename,
				      swm->filename,
				      swm->hdr.part_number,
				      total_parts);
				return WIMLIB_ERR_SPLIT_INVALID;
			} else {
				parts_to_swms[swm->hdr.part_number - 2] = swm;
			}
		}
	}
	return 0;
}
