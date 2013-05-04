#ifndef _WIMLIB_XML_H
#define _WIMLIB_XML_H

#include "util.h"

/* A struct wim_info structure corresponds to the entire XML data for a WIM file. */
struct wim_info {
	u64 total_bytes;
	int num_images;
	/* Array of `struct image_info's, one for each image in the WIM that is
	 * mentioned in the XML data. */
	struct image_info *images;
};

/* xml.c */
extern int
xml_export_image(const struct wim_info *old_wim_info, int image,
		 struct wim_info **new_wim_info_p,
		 const tchar *dest_image_name,
		 const tchar *dest_image_description);

extern size_t
xml_get_max_image_name_len(const WIMStruct *w);

extern void
xml_update_image_info(WIMStruct *w, int image);

extern void
xml_delete_image(struct wim_info **wim_info_p, int image);

extern int
xml_add_image(WIMStruct *w, const tchar *name);

extern void
free_wim_info(struct wim_info *info);

extern void
print_image_info(const struct wim_info *wim_info, int image);

extern int
read_xml_data(filedes_t in_fd, const struct resource_entry *res,
	      struct wim_info **info_ret);

extern int
write_xml_data(const struct wim_info *wim_info, int image, filedes_t out_fd,
	       u64 total_bytes, struct resource_entry *out_res_entry);

extern void
libxml_global_init();

extern void
libxml_global_cleanup();

static inline u64
wim_info_get_total_bytes(const struct wim_info *info)
{
	return info->total_bytes;
}

static inline unsigned
wim_info_get_num_images(const struct wim_info *info)
{
	return info->num_images;
}

#endif
