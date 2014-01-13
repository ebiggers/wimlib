/*
 * verify.c
 *
 * Verify stream reference counts.
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
lte_fix_refcnt(struct wim_lookup_table_entry *lte, void *ctr)
{
	if (lte->refcnt != lte->real_refcnt) {
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
int
wim_recalculate_refcnts(WIMStruct *wim)
{
	unsigned long num_ltes_with_bogus_refcnt = 0;
	int ret;

	for_lookup_table_entry(wim->lookup_table, lte_zero_real_refcnt, NULL);
	ret = for_image(wim, WIMLIB_ALL_IMAGES, tally_image_refcnts);
	if (ret)
		return ret;
	num_ltes_with_bogus_refcnt = 0;
	for_lookup_table_entry(wim->lookup_table, lte_fix_refcnt,
			       &num_ltes_with_bogus_refcnt);
	if (num_ltes_with_bogus_refcnt != 0) {
		WARNING("%lu stream(s) had incorrect reference count.",
			num_ltes_with_bogus_refcnt);
	}
	wim->refcnts_ok = 1;
	return 0;
}
