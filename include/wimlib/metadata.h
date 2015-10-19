#ifndef _WIMLIB_METADATA_H
#define _WIMLIB_METADATA_H

#include "wimlib/blob_table.h"
#include "wimlib/list.h"
#include "wimlib/types.h"
#include "wimlib/wim.h"

/* Metadata for a WIM image  */
struct wim_image_metadata {

	/* Number of WIMStruct's that are sharing this image metadata (from
	 * calls to wimlib_export_image().) */
	unsigned long refcnt;

	/* Pointer to the root dentry of the image. */
	struct wim_dentry *root_dentry;

	/* Pointer to the security data of the image. */
	struct wim_security_data *security_data;

	/* Pointer to the blob descriptor for this image's metadata resource.
	 * If this image metadata is sourced from a WIM file (as opposed to
	 * being created from scratch) and hasn't been modified from the version
	 * in that WIM file, then this blob descriptor's data corresponds to the
	 * WIM backing source.  Otherwise, this blob descriptor is a dummy entry
	 * with blob_location==BLOB_NONEXISTENT.  */
	struct blob_descriptor *metadata_blob;

	/* Linked list of 'struct wim_inode's for this image. */
	struct hlist_head inode_list;

	/* Linked list of 'struct blob_descriptor's for blobs that are
	 * referenced by this image's dentry tree, but have not had their SHA-1
	 * message digests calculated yet and therefore have not been inserted
	 * into the WIMStruct's blob table.  This list is appended to when files
	 * are scanned for inclusion in this WIM image.  */
	struct list_head unhashed_blobs;
};

/* Retrieve the metadata of the image in @wim currently selected with
 * select_wim_image().  */
static inline struct wim_image_metadata *
wim_get_current_image_metadata(WIMStruct *wim)
{
	return wim->image_metadata[wim->current_image - 1];
}

/* Retrieve the root dentry of the image in @wim currently selected with
 * select_wim_image().  */
static inline struct wim_dentry *
wim_get_current_root_dentry(WIMStruct *wim)
{
	return wim_get_current_image_metadata(wim)->root_dentry;
}

/* Retrieve the security data of the image in @wim currently selected with
 * select_wim_image().  */
static inline struct wim_security_data *
wim_get_current_security_data(WIMStruct *wim)
{
	return wim_get_current_image_metadata(wim)->security_data;
}

/* Return true iff the specified image has been changed since being read from
 * its backing file or has been created from scratch.  */
static inline bool
is_image_dirty(const struct wim_image_metadata *imd)
{
	/* The only possible values here are BLOB_NONEXISTENT and BLOB_IN_WIM */
	return imd->metadata_blob->blob_location == BLOB_NONEXISTENT;
}

/* Return true iff the specified image is unchanged since being read from the
 * specified backing WIM file.  */
static inline bool
is_image_unchanged_from_wim(const struct wim_image_metadata *imd,
			    const WIMStruct *wim)
{
	return !is_image_dirty(imd) && imd->metadata_blob->rdesc->wim == wim;
}

/* Mark the metadata for the specified WIM image "dirty" following changes to
 * the image's directory tree.  This records that the metadata no longer matches
 * the version in the WIM file (if any).  */
static inline void
mark_image_dirty(struct wim_image_metadata *imd)
{
	blob_release_location(imd->metadata_blob);
}

/* Iterate over each inode in a WIM image  */
#define image_for_each_inode(inode, imd) \
	hlist_for_each_entry(inode, &(imd)->inode_list, i_hlist_node)

/* Iterate over each inode in a WIM image (safe against inode removal)  */
#define image_for_each_inode_safe(inode, tmp, imd) \
	hlist_for_each_entry_safe(inode, tmp, &(imd)->inode_list, i_hlist_node)

/* Iterate over each blob in a WIM image that has not yet been hashed */
#define image_for_each_unhashed_blob(blob, imd) \
	list_for_each_entry(blob, &(imd)->unhashed_blobs, unhashed_list)

/* Iterate over each blob in a WIM image that has not yet been hashed (safe
 * against blob removal) */
#define image_for_each_unhashed_blob_safe(blob, tmp, imd) \
	list_for_each_entry_safe(blob, tmp, &(imd)->unhashed_blobs, unhashed_list)

extern void
put_image_metadata(struct wim_image_metadata *imd, struct blob_table *table);

extern int
append_image_metadata(WIMStruct *wim, struct wim_image_metadata *imd);

extern struct wim_image_metadata *
new_image_metadata(void) _malloc_attribute;

#endif /* _WIMLIB_METADATA_H */
