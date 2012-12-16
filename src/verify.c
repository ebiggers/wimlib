/*
 * verify.c
 *
 * Some functions to verify that stuff in the WIM is valid.  Of course, not
 * *all* the verifications of the input data are in this file.
 */

/*
 * Copyright (C) 2012 Eric Biggers
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

static inline struct dentry *inode_first_dentry(struct inode *inode)
{
	wimlib_assert(inode->dentry_list.next != &inode->dentry_list);
	return container_of(inode->dentry_list.next, struct dentry,
			    inode_dentry_list);
}

static int verify_inode(struct inode *inode, const WIMStruct *w)
{
	const struct lookup_table *table = w->lookup_table;
	const struct wim_security_data *sd = wim_const_security_data(w);
	const struct dentry *first_dentry = inode_first_dentry(inode);
	int ret = WIMLIB_ERR_INVALID_DENTRY;

	/* Check the security ID */
	if (inode->security_id < -1) {
		ERROR("Dentry `%s' has an invalid security ID (%d)",
			first_dentry->full_path_utf8, inode->security_id);
		goto out;
	}
	if (inode->security_id >= sd->num_entries) {
		ERROR("Dentry `%s' has an invalid security ID (%d) "
		      "(there are only %u entries in the security table)",
			first_dentry->full_path_utf8, inode->security_id,
			sd->num_entries);
		goto out;
	}

	/* Check that lookup table entries for all the resources exist, except
	 * if the SHA1 message digest is all 0's, which indicates there is
	 * intentionally no resource there.  */
	if (w->hdr.total_parts == 1) {
		for (unsigned i = 0; i <= inode->num_ads; i++) {
			struct lookup_table_entry *lte;
			const u8 *hash;
			hash = inode_stream_hash_unresolved(inode, i);
			lte = __lookup_resource(table, hash);
			if (!lte && !is_zero_hash(hash)) {
				ERROR("Could not find lookup table entry for stream "
				      "%u of dentry `%s'", i, first_dentry->full_path_utf8);
				goto out;
			}
			if (lte)
				lte->real_refcnt += inode->link_count;

			/* The following is now done when required by
			 * wim_run_full_verifications(). */

		#if 0
			if (lte && !w->full_verification_in_progress &&
			    lte->real_refcnt > lte->refcnt)
			{
			#ifdef ENABLE_ERROR_MESSAGES
				WARNING("The following lookup table entry "
					"has a reference count of %u, but",
					lte->refcnt);
				WARNING("We found %u references to it",
					lte->real_refcnt);
				WARNING("(One dentry referencing it is at `%s')",
					 first_dentry->full_path_utf8);

				print_lookup_table_entry(lte);
			#endif
				/* Guess what!  install.wim for Windows 8
				 * contains many streams referenced by more
				 * dentries than the refcnt stated in the lookup
				 * table entry.  So we will need to handle this
				 * case and not just make it be an error...  I'm
				 * just setting the reference count to the
				 * number of references we found.
				 * (Unfortunately, even after doing this, the
				 * reference count could be too low if it's also
				 * referenced in other WIM images) */

			#if 1
				lte->refcnt = lte->real_refcnt;
				WARNING("Fixing reference count");
			#else
				goto out;
			#endif
			}
		#endif
		}
	}

	/* Make sure there is only one un-named stream. */
	unsigned num_unnamed_streams = 0;
	for (unsigned i = 0; i <= inode->num_ads; i++) {
		const u8 *hash;
		hash = inode_stream_hash_unresolved(inode, i);
		if (!inode_stream_name_len(inode, i) && !is_zero_hash(hash))
			num_unnamed_streams++;
	}
	if (num_unnamed_streams > 1) {
		ERROR("Dentry `%s' has multiple (%u) un-named streams",
		      first_dentry->full_path_utf8, num_unnamed_streams);
		goto out;
	}
	inode->verified = true;
	ret = 0;
out:
	return ret;
}

/* Run some miscellaneous verifications on a WIM dentry */
int verify_dentry(struct dentry *dentry, void *wim)
{
	int ret;

	if (!dentry->d_inode->verified) {
		ret = verify_inode(dentry->d_inode, wim);
		if (ret != 0)
			return ret;
	}

	/* Cannot have a short name but no long name */
	if (dentry->short_name_len && !dentry->file_name_len) {
		ERROR("Dentry `%s' has a short name but no long name",
		      dentry->full_path_utf8);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	/* Make sure root dentry is unnamed */
	if (dentry_is_root(dentry)) {
		if (dentry->file_name_len) {
			ERROR("The root dentry is named `%s', but it must "
			      "be unnamed", dentry->file_name_utf8);
			return WIMLIB_ERR_INVALID_DENTRY;
		}
	}

#if 0
	/* Check timestamps */
	if (inode->last_access_time < inode->creation_time ||
	    inode->last_write_time < inode->creation_time) {
		WARNING("Dentry `%s' was created after it was last accessed or "
		      "written to", dentry->full_path_utf8);
	}
#endif

	return 0;
}

static int image_run_full_verifications(WIMStruct *w)
{
	return for_dentry_in_tree(wim_root_dentry(w), verify_dentry, w);
}

static int lte_fix_refcnt(struct lookup_table_entry *lte, void *ctr)
{
	if (lte->refcnt != lte->real_refcnt) {
		WARNING("The following lookup table entry has a reference "
			"count of %u, but", lte->refcnt);
		WARNING("We found %u references to it",
			lte->real_refcnt);
		print_lookup_table_entry(lte);
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
int wim_run_full_verifications(WIMStruct *w)
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
 * Sanity checks to make sure a set of WIMs correctly correspond to a spanned
 * set.
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
int verify_swm_set(WIMStruct *w, WIMStruct **additional_swms,
		   unsigned num_additional_swms)
{
	unsigned total_parts = w->hdr.total_parts;
	int ctype;
	const u8 *guid;

	if (total_parts != num_additional_swms + 1) {
		ERROR("`%s' says there are %u parts in the spanned set, "
		      "but %s%u part%s provided",
		      w->filename, total_parts,
		      (num_additional_swms + 1 < total_parts) ? "only " : "",
		      num_additional_swms + 1,
		      (num_additional_swms) ? "s were" : " was");
		return WIMLIB_ERR_SPLIT_INVALID;
	}
	if (w->hdr.part_number != 1) {
		ERROR("WIM `%s' is not the first part of the split WIM.",
		      w->filename);
		return WIMLIB_ERR_SPLIT_INVALID;
	}
	for (unsigned i = 0; i < num_additional_swms; i++) {
		if (additional_swms[i]->hdr.total_parts != total_parts) {
			ERROR("WIM `%s' says there are %u parts in the spanned set, "
			      "but %u parts were provided",
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
			ERROR("WIMs `%s' and `%s' both are marked as the "
			      "first WIM in the spanned set",
			      w->filename, swm->filename);
			return WIMLIB_ERR_SPLIT_INVALID;
		}
		if (swm->hdr.part_number == 0 ||
		    swm->hdr.part_number > total_parts)
		{
			ERROR("WIM `%s' says it is part %u in the spanned set, "
			      "but the part number must be in the range "
			      "[1, %u]",
			      swm->filename, swm->hdr.part_number, total_parts);
			return WIMLIB_ERR_SPLIT_INVALID;
		}
		if (parts_to_swms[swm->hdr.part_number - 2])
		{
			ERROR("`%s' and `%s' are both marked as part %u of %u "
			      "in the spanned set",
			      parts_to_swms[swm->hdr.part_number - 2]->filename,
			      swm->filename,
			      swm->hdr.part_number,
			      total_parts);
			return WIMLIB_ERR_SPLIT_INVALID;
		} else {
			parts_to_swms[swm->hdr.part_number - 2] = swm;
		}
	}
	return 0;
}

