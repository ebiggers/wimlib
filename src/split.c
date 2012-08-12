/*
 * split.c
 *
 * Split a WIM file into parts.
 */

/*
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "wimlib_internal.h"
#include "lookup_table.h"
#include "xml.h"
#include "io.h"

struct args {
	WIMStruct *w;
	char *swm_base_name;
	size_t swm_base_name_len;
	const char *swm_suffix;
	struct lookup_table_entry *lte_chain_head;
	struct lookup_table_entry *lte_chain_tail;
	int    part_number;
	int    write_flags;
	long   size_remaining;
	size_t part_size;
	u64    total_bytes;
	u64    total_bytes_written;
};

static int finish_swm(WIMStruct *w, struct lookup_table_entry *lte_chain_head,
		      int write_flags)
{
	off_t lookup_table_offset = ftello(w->out_fp);
	int ret;

	DEBUG("Writing lookup table for SWM (offset %"PRIu64")\n", 
			lookup_table_offset);

	while (lte_chain_head != NULL) {
		ret = write_lookup_table_entry(lte_chain_head, w->out_fp);
		if (ret != 0)
			return ret;
		struct lookup_table_entry *prev = lte_chain_head;
		lte_chain_head = prev->next_lte_in_swm;
		prev->next_lte_in_swm = NULL;
	}
	off_t xml_data_offset = ftello(w->out_fp);

	if (lookup_table_offset == -1 || xml_data_offset == -1)
		return WIMLIB_ERR_WRITE;
	w->hdr.lookup_table_res_entry.offset = lookup_table_offset;
	w->hdr.lookup_table_res_entry.size = 
				xml_data_offset - lookup_table_offset;
	ret = finish_write(w, WIM_ALL_IMAGES, write_flags, 0);
	if (ret != 0)
		return ret;

	ret = fclose(w->out_fp);
	if (ret != 0)
		ret = WIMLIB_ERR_WRITE;
	w->out_fp = NULL;
	return ret;
}

static int copy_resource_to_swm(struct lookup_table_entry *lte, void *__args)
{
	struct args *args = (struct args*)__args;
	WIMStruct *w = args->w;
	FILE *out_fp = w->out_fp;
	int ret;

	/* metadata resources were already written. */
	if (lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA)
		return 0;

	if (args->size_remaining < 0 || 
			(u64)args->size_remaining < lte->resource_entry.size) {

		/* No space for this resource.  Finish the previous swm and
		 * start a new one. */

		ret = finish_swm(w, args->lte_chain_head, args->write_flags);

		args->lte_chain_tail = NULL;
		args->lte_chain_head = NULL;

		sprintf(args->swm_base_name + args->swm_base_name_len, "%d", 
			++args->part_number);
		strcat(args->swm_base_name, args->swm_suffix);

		w->hdr.part_number = args->part_number;

		if (args->write_flags & WIMLIB_OPEN_FLAG_SHOW_PROGRESS)
			printf("Writing `%s' (%"PRIu64" of %"PRIu64" bytes, "
					"%.0f%% done)\n", 
				args->swm_base_name, 
				args->total_bytes_written,
				args->total_bytes,
				(double)args->total_bytes_written /
				 	(double)args->total_bytes * 100.0);

		ret = begin_write(w, args->swm_base_name, args->write_flags);
		if (ret != 0)
			return ret;
		args->size_remaining = args->part_size;
	}
	args->size_remaining -= lte->resource_entry.size;
	args->total_bytes_written += lte->resource_entry.size;
	if (args->lte_chain_tail)
		args->lte_chain_tail->next_lte_in_swm = lte;
	else
		args->lte_chain_head = lte;
	args->lte_chain_tail = lte;
	return copy_resource(lte, w);
}

/* Splits the WIM file @wimfile into multiple parts prefixed by @swm_name with
 * size at most @part_size. */
WIMLIBAPI int wimlib_split(const char *wimfile, const char *swm_name, 
			   size_t part_size, int flags)
{
	int ret;
	WIMStruct *w;
	int write_flags = 0;
	size_t swm_name_len = strlen(swm_name);
	size_t swm_base_name_len;
	char name[swm_name_len + 20];
	char *swm_suffix;

	struct lookup_table_entry *lte_chain_head = NULL;
	struct lookup_table_entry *lte_chain_tail = NULL;
	long size_remaining = part_size;
	u64 total_bytes_written = 0;
	u64 total_bytes;

	ret = wimlib_open_wim(wimfile, flags, &w);
	if (ret != 0)
		return ret;

	total_bytes = wim_info_get_total_bytes(w->wim_info);

	if (flags & WIMLIB_OPEN_FLAG_CHECK_INTEGRITY)
		write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
	if (flags & WIMLIB_OPEN_FLAG_SHOW_PROGRESS)
		write_flags |= WIMLIB_WRITE_FLAG_SHOW_PROGRESS;

	w->hdr.flags |= WIM_HDR_FLAG_SPANNED;
	w->hdr.boot_idx = 0;
	randomize_byte_array(w->hdr.guid, WIM_GID_LEN);
	ret = begin_write(w, swm_name, write_flags);
	if (ret != 0)
		return ret;

	swm_suffix = strchr(swm_name, '.');
	memcpy(name, swm_name, swm_name_len + 1);
	if (swm_suffix) {
		swm_base_name_len = swm_suffix - swm_name;
	} else {
		swm_base_name_len = swm_name_len;
		name[sizeof(name) - 1] = '\0';
		swm_suffix = &name[sizeof(name) - 1];
	}

	if (write_flags & WIMLIB_OPEN_FLAG_SHOW_PROGRESS)
		printf("Writing `%s' (%.2f %% done)\n", 
			swm_name, 
			(double)total_bytes_written /
				(double)total_bytes * 100.0);

	w->write_metadata = true;
	for (int i = 0; i < w->hdr.image_count; i++) {

		struct lookup_table_entry *metadata_lte;

		metadata_lte = w->image_metadata[i].lookup_table_entry;
		ret = copy_resource(metadata_lte, w);
		if (ret != 0)
			return ret;
		size_remaining -= metadata_lte->resource_entry.size;
		total_bytes_written += metadata_lte->resource_entry.size;
		if (lte_chain_tail)
			lte_chain_tail->next_lte_in_swm = metadata_lte;
		else
			lte_chain_head = metadata_lte;
		lte_chain_tail = metadata_lte;
	}
	w->write_metadata = false;

	struct args args = {
		.w                 = w,
		.swm_base_name     = name,
		.swm_base_name_len = swm_base_name_len,
		.swm_suffix        = swm_suffix,
		.lte_chain_head    = lte_chain_head,
		.lte_chain_tail    = lte_chain_tail,
		.part_number       = 1,
		.write_flags       = write_flags,
		.size_remaining    = size_remaining,
		.part_size         = part_size,
		.total_bytes        = total_bytes,
		.total_bytes_written = total_bytes_written,
	};

	ret = for_lookup_table_entry(w->lookup_table, copy_resource_to_swm, &args);
	if (ret != 0)
		return ret;

	ret = finish_swm(w, args.lte_chain_head, write_flags);
	if (ret != 0)
		return ret;


	/* The swms are all ready now, except the total_parts and part_number
	 * fields in their headers are wrong (we don't know the total parts
	 * until they are all written).  Fix them. */
	int total_parts = args.part_number;
	for (int i = 1; i <= total_parts; i++) {
		const char *p;
		if (i == 1) {
			p = swm_name;
		} else {
			sprintf(name + swm_base_name_len, "%d", i);
			p = strcat(name, swm_suffix);
		}

		FILE *fp = fopen(p, "r+b");
		if (!fp) {
			ERROR("Failed to open `%s': %m\n", p);
			return WIMLIB_ERR_OPEN;
		}
		char buf[4];
		put_u16(buf, i);
		put_u16(buf + 2, total_parts);

		if (fseek(fp, 40, SEEK_SET) != 0 || 
				fwrite(buf, 1, sizeof(buf), fp) != sizeof(buf)
				|| fclose(fp) != 0) {
			ERROR("Error overwriting header of `%s': %m\n", name);
			return WIMLIB_ERR_WRITE;
		}
	}
	if (write_flags & WIMLIB_OPEN_FLAG_SHOW_PROGRESS)
		printf("Done!\n");
	wimlib_free(w);
	return 0;
}
