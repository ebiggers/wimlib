#include "dentry.h"
#include "io.h"
#include "lookup_table.h"

/*
 * Find the symlink target of a symbolic link or junction point in the WIM.
 *
 * See http://msdn.microsoft.com/en-us/library/cc232006(v=prot.10).aspx
 * Except the first 8 bytes aren't included in the resource (presumably because
 * we already know the reparse tag from the dentry, and we already know the
 * reparse tag len from the lookup table entry resource length).
 */
static ssize_t get_symlink_name(const u8 *resource, size_t resource_len,
			        char *buf, size_t buf_len,
			        bool is_junction_point)
{
	const u8 *p = resource;
	u16 substitute_name_offset;
	u16 substitute_name_len;
	u16 print_name_offset;
	u16 print_name_len;
	char *link_target;
	size_t link_target_len;
	ssize_t ret;
	unsigned header_size;
	char *translated_target;
	bool is_absolute;

	if (resource_len < 12)
		return -EIO;
	p = get_u16(p, &substitute_name_offset);
	p = get_u16(p, &substitute_name_len);
	p = get_u16(p, &print_name_offset);
	p = get_u16(p, &print_name_len);
	if (is_junction_point) {
		header_size = 8;
	} else {
		u32 flags;
		p = get_u32(p, &flags);
		is_absolute = (flags & 1) ? false : true;
		header_size = 12;
	}
	if (header_size + substitute_name_offset + substitute_name_len > resource_len)
		return -EIO;
	link_target = utf16_to_utf8(p + substitute_name_offset,
				    substitute_name_len,
				    &link_target_len);

	if (!link_target)
		return -EIO;

	if (link_target_len + 1 > buf_len) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	translated_target = link_target;
	if (is_junction_point || is_absolute) {
		if (link_target_len < 7
		      || memcmp(translated_target, "\\??\\", 4) != 0
		      || translated_target[4] == '\0'
		      || translated_target[5] != ':'
		      || translated_target[6] != '\\') {
			ret = -EIO;
			goto out;
		}
		translated_target += 4;
		link_target_len -= 4;
	}
	for (size_t i = 0; i < link_target_len; i++)
		if (translated_target[i] == '\\')
			translated_target[i] = '/';

	memcpy(buf, translated_target, link_target_len + 1);
	ret = link_target_len;
out:
	FREE(link_target);
	return ret;
}

void *make_symlink_reparse_data_buf(const char *symlink_target, size_t *len_ret)
{
	size_t utf8_len = strlen(symlink_target);
	size_t utf16_len;
	char *name_utf16 = utf8_to_utf16(symlink_target, utf8_len, &utf16_len);
	if (!name_utf16)
		return NULL;
	/*DEBUG("utf16_len = %zu", utf16_len);*/
	for (size_t i = 0; i < utf16_len / 2; i++)
		if (((u16*)name_utf16)[i] == to_le16('/'))
			((u16*)name_utf16)[i] = to_le16('\\');
	size_t len = 12 + utf16_len * 2;
	void *buf = MALLOC(len);
	if (!buf)
		goto out;

	u8 *p = buf;
	p = put_u16(p, 0); /* Substitute name offset */
	p = put_u16(p, utf16_len); /* Substitute name length */
	p = put_u16(p, utf16_len); /* Print name offset */
	p = put_u16(p, utf16_len); /* Print name length */
	p = put_u32(p, (symlink_target[0] == '/') ?  0 : 1);
	p = put_bytes(p, utf16_len, name_utf16);
	p = put_bytes(p, utf16_len, name_utf16);
	/*DEBUG("utf16_len = %zu, len = %zu", utf16_len, len);*/
	*len_ret = len;
out:
	FREE(name_utf16);
	return buf;
}

/* Get the symlink target from a dentry that's already checked to be either a
 * "real" symlink or a junction point. */
ssize_t dentry_readlink(const struct dentry *dentry, char *buf, size_t buf_len,
			const WIMStruct *w)
{
	struct ads_entry *ads;
	struct lookup_table_entry *entry;
	struct resource_entry *res_entry;
	bool is_junction_point;

	wimlib_assert(dentry_is_symlink(dentry));

	if (dentry->reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK) {
		is_junction_point = false;
		/* 
		 * This is of course not actually documented, but what I think is going
		 * on here is that the symlink dentries have 2 alternate data streams;
		 * one is the default data stream, which is not used and is empty, and
		 * one is the symlink buffer data stream, which is confusingly also
		 * unnamed, but isn't empty as it contains the symlink target within the
		 * resource.
		 */
		if (dentry->num_ads != 2)
			return -EIO;
		if ((entry = __lookup_resource(w->lookup_table, dentry->ads_entries[0].hash)))
			goto do_readlink;
		if ((entry = __lookup_resource(w->lookup_table, dentry->ads_entries[1].hash)))
			goto do_readlink;
	} else {
		wimlib_assert(dentry->reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT);

		is_junction_point = true;

		if ((entry = __lookup_resource(w->lookup_table, dentry->hash)))
			goto do_readlink;
	}
	return -EIO;
do_readlink:
	res_entry = &entry->resource_entry;
	if (res_entry->original_size > 10000)
		return -EIO;
	char res_buf[res_entry->original_size];
	if (read_full_resource(w->fp, res_entry->size, 
			       res_entry->original_size,
			       res_entry->offset,
			       wim_resource_compression_type(w, res_entry),
			       res_buf) != 0)
		return -EIO;
	return get_symlink_name(res_buf, res_entry->original_size, buf,
				buf_len, is_junction_point);
}
