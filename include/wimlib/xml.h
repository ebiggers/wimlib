#ifndef _WIMLIB_XML_H
#define _WIMLIB_XML_H

#include "wimlib/types.h"
#include "wimlib/file_io.h"

struct wim_info;
struct wim_reshdr;

extern u64
wim_info_get_total_bytes(const struct wim_info *info);

extern u64
wim_info_get_image_hard_link_bytes(const struct wim_info *info, int image);

extern u64
wim_info_get_image_total_bytes(const struct wim_info *info, int image);

extern unsigned
wim_info_get_num_images(const struct wim_info *info);

extern void
wim_info_set_wimboot(struct wim_info *info, int image, bool value);

extern int
xml_export_image(const struct wim_info *old_wim_info, int image,
		 struct wim_info **new_wim_info_p,
		 const tchar *dest_image_name,
		 const tchar *dest_image_description);

extern size_t
xml_get_max_image_name_len(const WIMStruct *wim);

extern void
xml_update_image_info(WIMStruct *wim, int image);

extern void
xml_delete_image(struct wim_info **wim_info_p, int image);

extern int
xml_add_image(WIMStruct *wim, const tchar *name);

extern void
free_wim_info(struct wim_info *info);

extern void
print_image_info(const struct wim_info *wim_info, int image);

#define WIM_TOTALBYTES_USE_EXISTING  ((u64)0 - 1)
#define WIM_TOTALBYTES_OMIT          ((u64)0 - 2)

extern int
read_wim_xml_data(WIMStruct *wim);

extern int
write_wim_xml_data(WIMStruct *wim, int image,
		   u64 total_bytes, struct wim_reshdr *out_reshdr,
		   int write_resource_flags);

extern void
libxml_global_init(void);

extern void
libxml_global_cleanup(void);

extern void
xml_set_memory_allocator(void *(*malloc_func)(size_t),
			 void (*free_func)(void *),
			 void *(*realloc_func)(void *, size_t));

#endif
