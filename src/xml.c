/*
 * xml.c
 *
 * Deals with the XML information in WIM files.  Uses the C library libxml2.
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

#include "dentry.h"
#include "lookup_table.h"
#include "timestamp.h"
#include "wimlib_internal.h"
#include "xml.h"

#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlwriter.h>
#include <libxml/encoding.h>
#include <limits.h>

/* Structures used to form an in-memory representation of the XML data (other
 * than the raw parse tree from libxml). */

struct windows_version {
	u64 major;
	u64 minor;
	u64 build;
	u64 sp_build;
	u64 sp_level;
};

struct windows_info {
	u64      arch;
	tchar   *product_name;
	tchar   *edition_id;
	tchar   *installation_type;
	tchar   *hal;
	tchar   *product_type;
	tchar   *product_suite;
	tchar  **languages;
	tchar   *default_language;
	size_t   num_languages;
	tchar   *system_root;
	bool     windows_version_exists;
	struct   windows_version windows_version;
};

struct image_info {
	int index;
	bool windows_info_exists;
	u64 dir_count;
	u64 file_count;
	u64 total_bytes;
	u64 hard_link_bytes;
	u64 creation_time;
	u64 last_modification_time;
	struct windows_info windows_info;
	tchar *name;
	tchar *description;
	tchar *display_name;
	tchar *display_description;
	tchar *flags;
	struct wim_lookup_table *lookup_table; /* Temporary field only */
};

struct xml_string_spec {
	const char *name;
	size_t offset;
};

#define ELEM(STRING_NAME, MEMBER_NAME) \
	{STRING_NAME, offsetof(struct image_info, MEMBER_NAME)}
static const struct xml_string_spec
image_info_xml_string_specs[] = {
	ELEM("NAME", name),
	ELEM("DESCRIPTION", description),
	ELEM("DISPLAYNAME", display_name),
	ELEM("DISPLAYDESCRIPTION", display_description),
	ELEM("FLAGS", flags),
};
#undef ELEM

#define ELEM(STRING_NAME, MEMBER_NAME) \
	{STRING_NAME, offsetof(struct windows_info, MEMBER_NAME)}
static const struct xml_string_spec
windows_info_xml_string_specs[] = {
	ELEM("PRODUCTNAME", product_name),
	ELEM("EDITIONID", edition_id),
	ELEM("INSTALLATIONTYPE", installation_type),
	ELEM("HAL", hal),
	ELEM("PRODUCTTYPE", product_type),
	ELEM("PRODUCTSUITE", product_suite),
};
#undef ELEM


/* Returns a statically allocated string that is a string representation of the
 * architecture number. */
static const tchar *
get_arch(int arch)
{
	switch (arch) {
	case 0:
		return T("x86");
	case 6:
		return T("ia64");
	case 9:
		return T("x86_64");
	/* XXX Are there other arch values? */
	default:
		return T("unknown");
	}
}


/* Iterate through the children of an xmlNode. */
#define for_node_child(parent, child)	\
	for (child = parent->children; child != NULL; child = child->next)

/* Utility functions for xmlNodes */
static inline bool
node_is_element(xmlNode *node)
{
	return node->type == XML_ELEMENT_NODE;
}

static inline bool
node_is_text(xmlNode *node)
{
	return node->type == XML_TEXT_NODE;
}

static inline bool
node_name_is(xmlNode *node, const char *name)
{
	/* For now, both upper case and lower case element names are accepted. */
	return strcasecmp((const char *)node->name, name) == 0;
}

static u64
node_get_number(const xmlNode *u64_node, int base)
{
	xmlNode *child;
	for_node_child(u64_node, child)
		if (node_is_text(child))
			return strtoull(child->content, NULL, base);
	return 0;
}

/* Finds the text node that is a child of an element node and returns its
 * content converted to a 64-bit unsigned integer.  Returns 0 if no text node is
 * found. */
static u64
node_get_u64(const xmlNode *u64_node)
{
	return node_get_number(u64_node, 10);
}

/* Like node_get_u64(), but expects a number in base 16. */
static u64
node_get_hex_u64(const xmlNode *u64_node)
{
	return node_get_number(u64_node, 16);
}

static int
node_get_string(const xmlNode *string_node, tchar **tstr_ret)
{
	xmlNode *child;
	tchar *tstr = NULL;
	int ret;

	for_node_child(string_node, child) {
		if (node_is_text(child) && child->content) {
			ret = utf8_to_tstr_simple(child->content, &tstr);
			if (ret)
				return ret;
			break;
		}
	}
	*tstr_ret = tstr;
	return 0;
}

/* Returns the timestamp from a time node.  It has child elements <HIGHPART> and
 * <LOWPART> that are then used to construct a 64-bit timestamp. */
static u64
node_get_timestamp(const xmlNode *time_node)
{
	u32 high_part = 0;
	u32 low_part = 0;
	xmlNode *child;
	for_node_child(time_node, child) {
		if (!node_is_element(child))
			continue;
		if (node_name_is(child, "HIGHPART"))
			high_part = node_get_hex_u64(child);
		else if (node_name_is(child, "LOWPART"))
			low_part = node_get_hex_u64(child);
	}
	return (u64)low_part | ((u64)high_part << 32);
}

/* Used to sort an array of struct image_infos by their image indices. */
static int
sort_by_index(const void *p1, const void *p2)
{
	int index_1 = ((const struct image_info*)p1)->index;
	int index_2 = ((const struct image_info*)p2)->index;
	if (index_1 < index_2)
		return -1;
	else if (index_1 > index_2)
		return 1;
	else
		return 0;
}


/* Frees memory allocated inside a struct windows_info structure. */
static void
destroy_windows_info(struct windows_info *windows_info)
{
	FREE(windows_info->product_name);
	FREE(windows_info->edition_id);
	FREE(windows_info->installation_type);
	FREE(windows_info->hal);
	FREE(windows_info->product_type);
	FREE(windows_info->product_suite);
	for (size_t i = 0; i < windows_info->num_languages; i++)
		FREE(windows_info->languages[i]);
	FREE(windows_info->languages);
	FREE(windows_info->default_language);
	FREE(windows_info->system_root);
}

/* Frees memory allocated inside a struct image_info structure. */
static void
destroy_image_info(struct image_info *image_info)
{
	FREE(image_info->name);
	FREE(image_info->description);
	FREE(image_info->flags);
	FREE(image_info->display_name);
	FREE(image_info->display_description);
	destroy_windows_info(&image_info->windows_info);
	memset(image_info, 0, sizeof(struct image_info));
}

void
free_wim_info(struct wim_info *info)
{
	if (info) {
		if (info->images) {
			for (int i = 0; i < info->num_images; i++)
				destroy_image_info(&info->images[i]);
			FREE(info->images);
		}
		FREE(info);
	}
}

/* Reads the information from a <VERSION> element inside the <WINDOWS> element.
 * */
static void
xml_read_windows_version(const xmlNode *version_node,
			 struct windows_version* windows_version)
{
	xmlNode *child;
	for_node_child(version_node, child) {
		if (!node_is_element(child))
			continue;
		if (node_name_is(child, "MAJOR"))
			windows_version->major = node_get_u64(child);
		else if (node_name_is(child, "MINOR"))
			windows_version->minor = node_get_u64(child);
		else if (node_name_is(child, "BUILD"))
			windows_version->build = node_get_u64(child);
		else if (node_name_is(child, "SPBUILD"))
			windows_version->sp_build = node_get_u64(child);
		else if (node_name_is(child, "SPLEVEL"))
			windows_version->sp_level = node_get_u64(child);
	}
}

/* Reads the information from a <LANGUAGE> element inside a <WINDOWS> element.
 * */
static int
xml_read_languages(const xmlNode *languages_node,
		   tchar ***languages_ret,
		   size_t *num_languages_ret,
		   tchar **default_language_ret)
{
	xmlNode *child;
	size_t num_languages = 0;
	tchar **languages;
	int ret;

	for_node_child(languages_node, child)
		if (node_is_element(child) && node_name_is(child, "LANGUAGE"))
			num_languages++;

	languages = CALLOC(num_languages, sizeof(languages[0]));
	if (!languages)
		return WIMLIB_ERR_NOMEM;

	*languages_ret = languages;
	*num_languages_ret = num_languages;

	ret = 0;
	for_node_child(languages_node, child) {
		if (!node_is_element(child))
			continue;
		if (node_name_is(child, "LANGUAGE"))
			ret = node_get_string(child, languages++);
		else if (node_name_is(child, "DEFAULT"))
			ret = node_get_string(child, default_language_ret);
		if (ret != 0)
			break;
	}
	return ret;
}

/* Reads the information from a <WINDOWS> element inside an <IMAGE> element. */
static int
xml_read_windows_info(const xmlNode *windows_node,
		      struct windows_info *windows_info)
{
	xmlNode *child;
	int ret = 0;

	for_node_child(windows_node, child) {
		if (!node_is_element(child))
			continue;
		if (node_name_is(child, "ARCH")) {
			windows_info->arch = node_get_u64(child);
		} else if (node_name_is(child, "PRODUCTNAME")) {
			ret = node_get_string(child,
					      &windows_info->product_name);
		} else if (node_name_is(child, "EDITIONID")) {
			ret = node_get_string(child,
					      &windows_info->edition_id);
		} else if (node_name_is(child, "INSTALLATIONTYPE")) {
			ret = node_get_string(child,
					      &windows_info->installation_type);
		} else if (node_name_is(child, "PRODUCTTYPE")) {
			ret = node_get_string(child,
					      &windows_info->product_type);
		} else if (node_name_is(child, "PRODUCTSUITE")) {
			ret = node_get_string(child,
					      &windows_info->product_suite);
		} else if (node_name_is(child, "LANGUAGES")) {
			ret = xml_read_languages(child,
						 &windows_info->languages,
						 &windows_info->num_languages,
						 &windows_info->default_language);
		} else if (node_name_is(child, "VERSION")) {
			xml_read_windows_version(child,
						&windows_info->windows_version);
			windows_info->windows_version_exists = true;
		} else if (node_name_is(child, "SYSTEMROOT")) {
			ret = node_get_string(child, &windows_info->system_root);
		} else if (node_name_is(child, "HAL")) {
			ret = node_get_string(child, &windows_info->hal);
		}
		if (ret != 0)
			return ret;
	}
	return ret;
}

/* Reads the information from an <IMAGE> element. */
static int
xml_read_image_info(xmlNode *image_node, struct image_info *image_info)
{
	xmlNode *child;
	xmlChar *index_prop;
	int ret;

	index_prop = xmlGetProp(image_node, "INDEX");
	if (index_prop) {
		image_info->index = atoi(index_prop);
		FREE(index_prop);
	} else {
		image_info->index = 1;
	}

	ret = 0;
	for_node_child(image_node, child) {
		if (!node_is_element(child))
			continue;
		if (node_name_is(child, "DIRCOUNT"))
			image_info->dir_count = node_get_u64(child);
		else if (node_name_is(child, "FILECOUNT"))
			image_info->file_count = node_get_u64(child);
		else if (node_name_is(child, "TOTALBYTES"))
			image_info->total_bytes = node_get_u64(child);
		else if (node_name_is(child, "HARDLINKBYTES"))
			image_info->hard_link_bytes = node_get_u64(child);
		else if (node_name_is(child, "CREATIONTIME"))
			image_info->creation_time = node_get_timestamp(child);
		else if (node_name_is(child, "LASTMODIFICATIONTIME"))
			image_info->last_modification_time = node_get_timestamp(child);
		else if (node_name_is(child, "WINDOWS")) {
			DEBUG("Found <WINDOWS> tag");
			ret = xml_read_windows_info(child,
						    &image_info->windows_info);
			image_info->windows_info_exists = true;
		} else if (node_name_is(child, "NAME")) {
			ret = node_get_string(child, &image_info->name);
		} else if (node_name_is(child, "DESCRIPTION")) {
			ret = node_get_string(child, &image_info->description);
		} else if (node_name_is(child, "FLAGS")) {
			ret = node_get_string(child, &image_info->flags);
		} else if (node_name_is(child, "DISPLAYNAME")) {
			ret = node_get_string(child, &image_info->display_name);
		} else if (node_name_is(child, "DISPLAYDESCRIPTION")) {
			ret = node_get_string(child, &image_info->display_description);
		}
		if (ret != 0)
			return ret;
	}
	if (!image_info->name) {
		tchar *empty_name;
		WARNING("Image with index %d has no name", image_info->index);
		empty_name = TMALLOC(1);
		if (!empty_name)
			return WIMLIB_ERR_NOMEM;
		*empty_name = T('\0');
		image_info->name = empty_name;
	}
	return ret;
}

/* Reads the information from a <WIM> element, which should be the root element
 * of the XML tree. */
static int
xml_read_wim_info(const xmlNode *wim_node, struct wim_info **wim_info_ret)
{
	struct wim_info *wim_info;
	xmlNode *child;
	int ret;
	int num_images;
	int i;

	wim_info = CALLOC(1, sizeof(struct wim_info));
	if (!wim_info)
		return WIMLIB_ERR_NOMEM;

	/* Count how many images there are. */
	num_images = 0;
	for_node_child(wim_node, child) {
		if (node_is_element(child) && node_name_is(child, "IMAGE")) {
			if (num_images == INT_MAX) {
				return WIMLIB_ERR_IMAGE_COUNT;
			}
			num_images++;
		}
	}

	if (num_images > 0) {
		/* Allocate the array of struct image_infos and fill them in. */
		wim_info->images = CALLOC(num_images, sizeof(wim_info->images[0]));
		if (!wim_info->images) {
			ret = WIMLIB_ERR_NOMEM;
			goto err;
		}
		wim_info->num_images = num_images;
		i = 0;
		for_node_child(wim_node, child) {
			if (!node_is_element(child))
				continue;
			if (node_name_is(child, "IMAGE")) {
				DEBUG("Found <IMAGE> tag");
				ret = xml_read_image_info(child,
							  &wim_info->images[i]);
				if (ret != 0)
					goto err;
				i++;
			} else if (node_name_is(child, "TOTALBYTES")) {
				wim_info->total_bytes = node_get_u64(child);
			}
		}

		/* Sort the array of image info by image index. */
		qsort(wim_info->images, num_images,
		      sizeof(struct image_info), sort_by_index);

		/* Make sure the image indices make sense */
		for (i = 0; i < num_images; i++) {
			if (wim_info->images[i].index != i + 1) {
				ERROR("WIM images are not indexed [1...%d] "
				      "in XML data as expected",
				      num_images);
				return WIMLIB_ERR_IMAGE_COUNT;
			}
		}

	}
	*wim_info_ret = wim_info;
	return 0;
err:
	free_wim_info(wim_info);
	return ret;
}

/* Prints the information contained in a `struct windows_info'.
 *
 * Warning: any strings printed here are in UTF-8 encoding.  If the locale
 * character encoding is not UTF-8, the printed strings may be garbled. */
static void
print_windows_info(const struct windows_info *windows_info)
{
	const struct windows_version *windows_version;

	tprintf(T("Architecture:           %"TS"\n"),
		get_arch(windows_info->arch));

	if (windows_info->product_name) {
		tprintf(T("Product Name:           %"TS"\n"),
			windows_info->product_name);
	}

	if (windows_info->edition_id) {
		tprintf(T("Edition ID:             %"TS"\n"),
			windows_info->edition_id);
	}

	if (windows_info->installation_type) {
		tprintf(T("Installation Type:      %"TS"\n"),
			windows_info->installation_type);
	}

	if (windows_info->hal) {
		tprintf(T("HAL:                    %"TS"\n"),
			      windows_info->hal);
	}

	if (windows_info->product_type) {
		tprintf(T("Product Type:           %"TS"\n"),
			windows_info->product_type);
	}

	if (windows_info->product_suite) {
		tprintf(T("Product Suite:          %"TS"\n"),
			windows_info->product_suite);
	}

	tprintf(T("Languages:              "));
	for (size_t i = 0; i < windows_info->num_languages; i++) {

		tfputs(windows_info->languages[i], stdout);
		tputchar(T(' '));
	}
	tputchar(T('\n'));
	if (windows_info->default_language) {
		tprintf(T("Default Language:       %"TS"\n"),
			windows_info->default_language);
	}
	if (windows_info->system_root) {
		tprintf(T("System Root:            %"TS"\n"),
			      windows_info->system_root);
	}

	if (windows_info->windows_version_exists) {
		windows_version = &windows_info->windows_version;
		tprintf(T("Major Version:          %"PRIu64"\n"),
			windows_version->major);
		tprintf(T("Minor Version:          %"PRIu64"\n"),
			windows_version->minor);
		tprintf(T("Build:                  %"PRIu64"\n"),
			windows_version->build);
		tprintf(T("Service Pack Build:     %"PRIu64"\n"),
			windows_version->sp_build);
		tprintf(T("Service Pack Level:     %"PRIu64"\n"),
			windows_version->sp_level);
	}
}

static int
xml_write_string(xmlTextWriter *writer, const char *name,
		 const tchar *tstr)
{
	if (tstr) {
		char *utf8_str;
		int rc = tstr_to_utf8_simple(tstr, &utf8_str);
		if (rc)
			return rc;
		rc = xmlTextWriterWriteElement(writer, name, utf8_str);
		FREE(utf8_str);
		if (rc < 0)
			return rc;
	}
	return 0;
}

static int
xml_write_strings_from_specs(xmlTextWriter *writer,
			     const void *struct_with_strings,
			     const struct xml_string_spec specs[],
			     size_t num_specs)
{
	for (size_t i = 0; i < num_specs; i++) {
		int rc = xml_write_string(writer, specs[i].name,
				      *(const tchar * const *)
				      	(struct_with_strings + specs[i].offset));
		if (rc)
			return rc;
	}
	return 0;
}

static int
dup_strings_from_specs(const void *old_struct_with_strings,
		       void *new_struct_with_strings,
		       const struct xml_string_spec specs[],
		       size_t num_specs)
{
	for (size_t i = 0; i < num_specs; i++) {
		const tchar *old_str = *(const tchar * const *)
					((const void*)old_struct_with_strings + specs[i].offset);
		tchar **new_str_p = (tchar **)((void*)new_struct_with_strings + specs[i].offset);
		if (old_str) {
			*new_str_p = TSTRDUP(old_str);
			if (!*new_str_p)
				return WIMLIB_ERR_NOMEM;
		}
	}
	return 0;
}

/* Writes the information contained in a `struct windows_version' to the XML
 * document being written.  This is the <VERSION> element inside the <WINDOWS>
 * element. */
static int
xml_write_windows_version(xmlTextWriter *writer,
			  const struct windows_version *version)
{
	int rc;
	rc = xmlTextWriterStartElement(writer, "VERSION");
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "MAJOR", "%"PRIu64,
					     version->major);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "MINOR", "%"PRIu64,
					     version->minor);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "BUILD", "%"PRIu64,
					     version->build);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "SPBUILD", "%"PRIu64,
					     version->sp_build);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "SPLEVEL", "%"PRIu64,
					     version->sp_level);
	if (rc < 0)
		return rc;

	return xmlTextWriterEndElement(writer); /* </VERSION> */
}

/* Writes the information contained in a `struct windows_info' to the XML
 * document being written. This is the <WINDOWS> element. */
static int
xml_write_windows_info(xmlTextWriter *writer,
		       const struct windows_info *windows_info)
{
	int rc;
	rc = xmlTextWriterStartElement(writer, "WINDOWS");
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "ARCH", "%"PRIu64,
					     windows_info->arch);
	if (rc < 0)
		return rc;

	rc = xml_write_strings_from_specs(writer,
					  windows_info,
					  windows_info_xml_string_specs,
					  ARRAY_LEN(windows_info_xml_string_specs));
	if (rc)
		return rc;

	if (windows_info->num_languages) {
		rc = xmlTextWriterStartElement(writer, "LANGUAGES");
		if (rc < 0)
			return rc;

		for (size_t i = 0; i < windows_info->num_languages; i++) {
			rc = xml_write_string(writer, "LANGUAGE",
					      windows_info->languages[i]);
			if (rc)
				return rc;
		}

		rc = xml_write_string(writer, "DEFAULT",
				      windows_info->default_language);
		if (rc)
			return rc;

		rc = xmlTextWriterEndElement(writer); /* </LANGUAGES> */
		if (rc < 0)
			return rc;
	}

	if (windows_info->windows_version_exists) {
		rc = xml_write_windows_version(writer, &windows_info->windows_version);
		if (rc < 0)
			return rc;
	}

	rc = xml_write_string(writer, "SYSTEMROOT",
			      windows_info->system_root);
	if (rc)
		return rc;

	return xmlTextWriterEndElement(writer); /* </WINDOWS> */
}

/* Writes a time element to the XML document being constructed in memory. */
static int
xml_write_time(xmlTextWriter *writer, const char *element_name, u64 time)
{
	int rc;
	rc = xmlTextWriterStartElement(writer, element_name);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "HIGHPART",
					     "0x%08"PRIX32, (u32)(time >> 32));
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "LOWPART",
					     "0x%08"PRIX32, (u32)time);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterEndElement(writer); /* </@element_name> */
	if (rc < 0)
		return rc;
	return 0;
}

/* Writes an <IMAGE> element to the XML document. */
static int
xml_write_image_info(xmlTextWriter *writer, const struct image_info *image_info)
{
	int rc;
	rc = xmlTextWriterStartElement(writer, "IMAGE");
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatAttribute(writer, "INDEX", "%d",
					       image_info->index);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "DIRCOUNT", "%"PRIu64,
					     image_info->dir_count);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "FILECOUNT", "%"PRIu64,
					     image_info->file_count);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "TOTALBYTES", "%"PRIu64,
					     image_info->total_bytes);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "HARDLINKBYTES", "%"PRIu64,
					     image_info->hard_link_bytes);
	if (rc < 0)
		return rc;

	rc = xml_write_time(writer, "CREATIONTIME", image_info->creation_time);
	if (rc < 0)
		return rc;

	rc = xml_write_time(writer, "LASTMODIFICATIONTIME",
			    image_info->last_modification_time);
	if (rc < 0)
		return rc;

	if (image_info->windows_info_exists) {
		rc = xml_write_windows_info(writer, &image_info->windows_info);
		if (rc)
			return rc;
	}

	rc = xml_write_strings_from_specs(writer, image_info,
					  image_info_xml_string_specs,
					  ARRAY_LEN(image_info_xml_string_specs));
	if (rc)
		return rc;

	rc = xmlTextWriterEndElement(writer); /* </IMAGE> */
	if (rc < 0)
		return rc;
	return 0;
}



/* Makes space for another image in the XML information and return a pointer to
 * it.*/
static struct image_info *
add_image_info_struct(struct wim_info *wim_info)
{
	struct image_info *images;

	images = CALLOC(wim_info->num_images + 1, sizeof(struct image_info));
	if (!images)
		return NULL;
	memcpy(images, wim_info->images,
	       wim_info->num_images * sizeof(struct image_info));
	FREE(wim_info->images);
	wim_info->images = images;
	wim_info->num_images++;
	return &images[wim_info->num_images - 1];
}

static int
clone_windows_info(const struct windows_info *old, struct windows_info *new)
{
	int ret;

	ret = dup_strings_from_specs(old, new, windows_info_xml_string_specs,
				     ARRAY_LEN(windows_info_xml_string_specs));
	if (ret)
		return ret;

	if (old->languages) {
		new->languages = CALLOC(old->num_languages, sizeof(new->languages[0]));
		if (!new->languages)
			return WIMLIB_ERR_NOMEM;
		new->num_languages = old->num_languages;
		for (size_t i = 0; i < new->num_languages; i++) {
			if (!old->languages[i])
				continue;
			new->languages[i] = TSTRDUP(old->languages[i]);
			if (!new->languages[i])
				return WIMLIB_ERR_NOMEM;
		}
	}
	if (old->default_language &&
			!(new->default_language = TSTRDUP(old->default_language)))
		return WIMLIB_ERR_NOMEM;
	if (old->system_root && !(new->system_root = TSTRDUP(old->system_root)))
		return WIMLIB_ERR_NOMEM;
	if (old->windows_version_exists) {
		new->windows_version_exists = true;
		memcpy(&new->windows_version, &old->windows_version,
		       sizeof(old->windows_version));
	}
	return 0;
}

static int
clone_image_info(const struct image_info *old, struct image_info *new)
{
	int ret;

	new->dir_count              = old->dir_count;
	new->file_count             = old->file_count;
	new->total_bytes            = old->total_bytes;
	new->hard_link_bytes        = old->hard_link_bytes;
	new->creation_time          = old->creation_time;
	new->last_modification_time = old->last_modification_time;

	ret = dup_strings_from_specs(old, new,
				     image_info_xml_string_specs,
				     ARRAY_LEN(image_info_xml_string_specs));
	if (ret)
		return ret;

	if (old->windows_info_exists) {
		new->windows_info_exists = true;
		ret = clone_windows_info(&old->windows_info,
					 &new->windows_info);
		if (ret)
			return ret;
	}
	return 0;
}

/* Copies the XML information for an image between WIM files.
 *
 * @dest_image_name and @dest_image_description are ignored if they are NULL;
 * otherwise, they are used to override the image name and/or image description
 * from the XML data in the source WIM file.
 *
 * On failure, WIMLIB_ERR_NOMEM is returned and no changes are made.  Otherwise,
 * 0 is returned and the WIM information at *new_wim_info_p is modified.
 */
int
xml_export_image(const struct wim_info *old_wim_info,
		 int image,
		 struct wim_info **new_wim_info_p,
		 const tchar *dest_image_name,
		 const tchar *dest_image_description)
{
	struct wim_info *new_wim_info;
	struct image_info *image_info;
	int ret;

	DEBUG("Copying XML data between WIM files for source image %d.", image);

	wimlib_assert(old_wim_info != NULL);
	wimlib_assert(image >= 1 && image <= old_wim_info->num_images);

	if (*new_wim_info_p) {
		new_wim_info = *new_wim_info_p;
	} else {
		new_wim_info = CALLOC(1, sizeof(struct wim_info));
		if (!new_wim_info)
			goto err;
	}

	image_info = add_image_info_struct(new_wim_info);
	if (!image_info)
		goto err;

	ret = clone_image_info(&old_wim_info->images[image - 1], image_info);
	if (ret != 0)
		goto err_destroy_image_info;

	image_info->index = new_wim_info->num_images;

	if (dest_image_name) {
		FREE(image_info->name);
		image_info->name = TSTRDUP(dest_image_name);
		if (!image_info->name)
			goto err_destroy_image_info;
	}
	if (dest_image_description) {
		FREE(image_info->description);
		image_info->description = TSTRDUP(dest_image_description);
		if (!image_info->description)
			goto err_destroy_image_info;
	}
	*new_wim_info_p = new_wim_info;
	return 0;
err_destroy_image_info:
	destroy_image_info(image_info);
err:
	if (new_wim_info != *new_wim_info_p)
		free_wim_info(new_wim_info);
	return WIMLIB_ERR_NOMEM;
}

/* Removes an image from the XML information. */
void
xml_delete_image(struct wim_info **wim_info_p, int image)
{
	struct wim_info *wim_info;

	wim_info = *wim_info_p;
	wimlib_assert(image >= 1 && image <= wim_info->num_images);
	DEBUG("Deleting image %d from the XML data.", image);

	destroy_image_info(&wim_info->images[image - 1]);

	memmove(&wim_info->images[image - 1],
		&wim_info->images[image],
		(wim_info->num_images - image) * sizeof(struct image_info));

	if (--wim_info->num_images == 0) {
		free_wim_info(wim_info);
		*wim_info_p = NULL;
	} else {
		for (int i = image - 1; i < wim_info->num_images; i++)
			wim_info->images[i].index--;
	}
}

size_t
xml_get_max_image_name_len(const WIMStruct *w)
{
	size_t max_len = 0;
	if (w->wim_info) {
		for (int i = 0; i < w->wim_info->num_images; i++) {
			size_t len = tstrlen(w->wim_info->images[i].name);
			if (len > max_len)
				max_len = len;
		}
	}
	return max_len;
}

#ifdef ENABLE_CUSTOM_MEMORY_ALLOCATOR
void
xml_set_memory_allocator(void *(*malloc_func)(size_t),
			 void (*free_func)(void *),
			 void *(*realloc_func)(void *, size_t))
{
	xmlMemSetup(free_func, malloc_func, realloc_func, STRDUP);
}
#endif

static int
calculate_dentry_statistics(struct wim_dentry *dentry, void *arg)
{
	struct image_info *info = arg;
	struct wim_lookup_table *lookup_table = info->lookup_table;
	const struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table_entry *lte;

	/* Update directory count and file count.
	 *
	 * Each dentry counts as either a file or a directory, but not both.
	 * The root directory is an exception: it is not counted at all.
	 *
	 * Symbolic links and junction points (and presumably other reparse
	 * points) count as regular files.  This is despite the fact that
	 * junction points have FILE_ATTRIBUTE_DIRECTORY set.
	 */
	if (dentry_is_root(dentry))
		return 0;

	if (inode_is_directory(inode))
		info->dir_count++;
	else
		info->file_count++;

	/*
	 * Update total bytes and hard link bytes.
	 *
	 * Unfortunately there are some inconsistencies/bugs in the way this is
	 * done.
	 *
	 * If there are no alternate data streams in the image, the "total
	 * bytes" is the sum of the size of the un-named data stream of each
	 * inode times the link count of that inode.  In other words, it would
	 * be the total number of bytes of regular files you would have if you
	 * extracted the full image without any hard-links.  The "hard link
	 * bytes" is equal to the "total bytes" minus the size of the un-named
	 * data stream of each inode.  In other words, the "hard link bytes"
	 * counts the size of the un-named data stream for all the links to each
	 * inode except the first one.
	 *
	 * Reparse points and directories don't seem to be counted in either the
	 * total bytes or the hard link bytes.
	 *
	 * And now we get to the most confusing part, the alternate data
	 * streams.  They are not counted in the "total bytes".  However, if the
	 * link count of an inode with alternate data streams is 2 or greater,
	 * the size of all the alternate data streams is included in the "hard
	 * link bytes", and this size is multiplied by the link count (NOT one
	 * less than the link count).
	 */
	lte = inode_unnamed_lte(inode, info->lookup_table);
	if (lte) {
		info->total_bytes += wim_resource_size(lte);
		if (!dentry_is_first_in_inode(dentry))
			info->hard_link_bytes += wim_resource_size(lte);
	}

	if (inode->i_nlink >= 2 && dentry_is_first_in_inode(dentry)) {
		for (unsigned i = 0; i < inode->i_num_ads; i++) {
			if (inode->i_ads_entries[i].stream_name_nbytes) {
				lte = inode_stream_lte(inode, i + 1, lookup_table);
				if (lte) {
					info->hard_link_bytes += inode->i_nlink *
								 wim_resource_size(lte);
				}
			}
		}
	}
	return 0;
}

/*
 * Calculate what to put in the <FILECOUNT>, <DIRCOUNT>, <TOTALBYTES>, and
 * <HARDLINKBYTES> elements of each <IMAGE>.
 *
 * Please note there is no official documentation for exactly how this is done.
 * But, see calculate_dentry_statistics().
 */
void
xml_update_image_info(WIMStruct *w, int image)
{
	struct image_info *image_info;

	DEBUG("Updating the image info for image %d", image);

	image_info = &w->wim_info->images[image - 1];

	image_info->file_count      = 0;
	image_info->dir_count       = 0;
	image_info->total_bytes     = 0;
	image_info->hard_link_bytes = 0;
	image_info->lookup_table = w->lookup_table;

	for_dentry_in_tree(w->image_metadata[image - 1].root_dentry,
			   calculate_dentry_statistics,
			   image_info);
	image_info->last_modification_time = get_wim_timestamp();
}

/* Adds an image to the XML information. */
int
xml_add_image(WIMStruct *w, const tchar *name)
{
	struct wim_info *wim_info;
	struct image_info *image_info;

	wimlib_assert(name != NULL);

	/* If this is the first image, allocate the struct wim_info.  Otherwise
	 * use the existing struct wim_info. */
	if (w->wim_info) {
		wim_info = w->wim_info;
	} else {
		wim_info = CALLOC(1, sizeof(struct wim_info));
		if (!wim_info)
			return WIMLIB_ERR_NOMEM;
	}

	image_info = add_image_info_struct(wim_info);
	if (!image_info)
		goto out_free_wim_info;

	if (!(image_info->name = TSTRDUP(name)))
		goto out_destroy_image_info;

	w->wim_info = wim_info;
	image_info->index = wim_info->num_images;
	image_info->creation_time = get_wim_timestamp();
	xml_update_image_info(w, image_info->index);
	return 0;

out_destroy_image_info:
	destroy_image_info(image_info);
	wim_info->num_images--;
out_free_wim_info:
	if (wim_info != w->wim_info)
		FREE(wim_info);
	return WIMLIB_ERR_NOMEM;
}

/* Prints information about the specified image from struct wim_info structure.
 * */
void
print_image_info(const struct wim_info *wim_info, int image)
{
	const struct image_info *image_info;
	const tchar *desc;
	tchar buf[50];

	wimlib_assert(image >= 1 && image <= wim_info->num_images);

	image_info = &wim_info->images[image - 1];

	tprintf(T("Index:                  %d\n"), image_info->index);
	tprintf(T("Name:                   %"TS"\n"), image_info->name);

	/* Always print the Description: part even if there is no
	 * description. */
	if (image_info->description)
		desc = image_info->description;
	else
		desc = T("");
	tprintf(T("Description:            %"TS"\n"), desc);

	if (image_info->display_name) {
		tprintf(T("Display Name:           %"TS"\n"),
			image_info->display_name);
	}

	if (image_info->display_description) {
		tprintf(T("Display Description:    %"TS"\n"),
			image_info->display_description);
	}

	tprintf(T("Directory Count:        %"PRIu64"\n"), image_info->dir_count);
	tprintf(T("File Count:             %"PRIu64"\n"), image_info->file_count);
	tprintf(T("Total Bytes:            %"PRIu64"\n"), image_info->total_bytes);
	tprintf(T("Hard Link Bytes:        %"PRIu64"\n"), image_info->hard_link_bytes);

	wim_timestamp_to_str(image_info->creation_time, buf, sizeof(buf));
	tprintf(T("Creation Time:          %"TS"\n"), buf);

	wim_timestamp_to_str(image_info->creation_time, buf, sizeof(buf));
	tprintf(T("Last Modification Time: %"TS"\n"), buf);
	if (image_info->windows_info_exists)
		print_windows_info(&image_info->windows_info);
	if (image_info->flags)
		tprintf(T("Flags:                  %"TS"\n"), image_info->flags);
	tputchar('\n');
}

void
libxml_global_init()
{
	xmlInitParser();
	xmlInitCharEncodingHandlers();
}

void
libxml_global_cleanup()
{
	xmlCleanupParser();
	xmlCleanupCharEncodingHandlers();
}

/*
 * Reads the XML data from a WIM file.
 */
int
read_xml_data(FILE *fp, const struct resource_entry *res_entry,
	      utf16lechar **xml_data_ret, struct wim_info **info_ret)
{
	utf16lechar *xml_data;
	xmlDoc *doc;
	xmlNode *root;
	int ret;

	DEBUG("XML data is %"PRIu64" bytes at offset %"PRIu64"",
	      (u64)res_entry->size, res_entry->offset);

	if (resource_is_compressed(res_entry)) {
		ERROR("XML data is supposed to be uncompressed");
		ret = WIMLIB_ERR_XML;
		goto out;
	}

	if (res_entry->size < 2) {
		ERROR("XML data must be at least 2 bytes long");
		ret = WIMLIB_ERR_XML;
		goto out;
	}

	xml_data = MALLOC(res_entry->size + 3);
	if (!xml_data) {
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	ret = read_uncompressed_resource(fp, res_entry->offset,
					 res_entry->size, xml_data);
	if (ret != 0)
		goto out_free_xml_data;

	/* Null-terminate just in case */
	((u8*)xml_data)[res_entry->size] = 0;
	((u8*)xml_data)[res_entry->size + 1] = 0;
	((u8*)xml_data)[res_entry->size + 2] = 0;

	DEBUG("Parsing XML using libxml2 to create XML tree");

	doc = xmlReadMemory((const char *)xml_data,
			    res_entry->size, "noname.xml", "UTF-16", 0);

	if (!doc) {
		ERROR("Failed to parse XML data");
		ret = WIMLIB_ERR_XML;
		goto out_free_xml_data;
	}

	DEBUG("Constructing WIM information structure from XML tree.");

	root = xmlDocGetRootElement(doc);
	if (!root) {
		ERROR("WIM XML data is an empty XML document");
		ret = WIMLIB_ERR_XML;
		goto out_free_doc;
	}

	if (!node_is_element(root) || !node_name_is(root, "WIM")) {
		ERROR("Expected <WIM> for the root XML element");
		ret = WIMLIB_ERR_XML;
		goto out_free_doc;
	}

	ret = xml_read_wim_info(root, info_ret);
	if (ret != 0)
		goto out_free_doc;

	*xml_data_ret = xml_data;
	xml_data = NULL;
out_free_doc:
	DEBUG("Freeing XML tree.");
	xmlFreeDoc(doc);
out_free_xml_data:
	FREE(xml_data);
out:
	return ret;
}

#define CHECK_RET  ({ 	if (ret < 0)  { \
				ERROR("Error writing XML data"); \
				ret = WIMLIB_ERR_WRITE; \
				goto out_free_text_writer; \
			} })

/*
 * Writes XML data to a WIM file.
 *
 * If @total_bytes is non-zero, it specifies what to write to the TOTALBYTES
 * element in the XML data.  If zero, TOTALBYTES is given the default value of
 * the offset of the XML data.
 */
int
write_xml_data(const struct wim_info *wim_info, int image, FILE *out,
	       u64 total_bytes, struct resource_entry *out_res_entry)
{
	xmlCharEncodingHandler *encoding_handler;
	xmlOutputBuffer *out_buffer;
	xmlTextWriter *writer;
	int ret;
	off_t start_offset;
	off_t end_offset;

	wimlib_assert(image == WIMLIB_ALL_IMAGES ||
			(wim_info != NULL && image >= 1 &&
			 image <= wim_info->num_images));

	start_offset = ftello(out);
	if (start_offset == -1)
		return WIMLIB_ERR_WRITE;

	DEBUG("Writing XML data for image %d at offset %"PRIu64,
	      image, start_offset);

	/* 2 bytes endianness marker for UTF-16LE.  This is _required_ for WIM
	 * XML data. */
	if ((putc(0xff, out)) == EOF || (putc(0xfe, out) == EOF)) {
		ERROR_WITH_ERRNO("Error writing XML data");
		return WIMLIB_ERR_WRITE;
	}

	/* The contents of the <TOTALBYTES> element in the XML data, under the
	 * <WIM> element (not the <IMAGE> element), is for non-split WIMs the
	 * size of the WIM file excluding the XML data and integrity table.
	 * This should be equal to the current position in the output stream,
	 * since the XML data and integrity table are the last elements of the
	 * WIM.
	 *
	 * For split WIMs, <TOTALBYTES> takes into account the entire WIM, not
	 * just the current part.  In that case, @total_bytes should be passed
	 * in to this function. */
	if (total_bytes == 0)
		total_bytes = start_offset;

	/* The encoding of the XML data must be UTF-16LE. */
	encoding_handler = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF16LE);
	if (!encoding_handler) {
		ERROR("Failed to get XML character encoding handler for UTF-16LE");
		ret = WIMLIB_ERR_LIBXML_UTF16_HANDLER_NOT_AVAILABLE;
		goto out;
	}

	out_buffer = xmlOutputBufferCreateFile(out, encoding_handler);
	if (!out_buffer) {
		ERROR("Failed to allocate xmlOutputBuffer");
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	writer = xmlNewTextWriter(out_buffer);
	if (!writer) {
		ERROR("Failed to allocate xmlTextWriter");
		ret = WIMLIB_ERR_NOMEM;
		goto out_output_buffer_close;
	}

	DEBUG("Writing <WIM> element");

	ret = xmlTextWriterStartElement(writer, "WIM");
	CHECK_RET;

	ret = xmlTextWriterWriteFormatElement(writer, "TOTALBYTES", "%"PRIu64,
					      total_bytes);
	CHECK_RET;

	if (wim_info != NULL) {
		int first, last;
		if (image == WIMLIB_ALL_IMAGES) {
			first = 1;
			last = wim_info->num_images;
		} else {
			first = image;
			last = image;
		}
		DEBUG("Writing %d <IMAGE> elements", last - first + 1);
		for (int i = first; i <= last; i++) {
			ret = xml_write_image_info(writer, &wim_info->images[i - 1]);
			if (ret) {
				CHECK_RET;
				goto out_free_text_writer;
			}
		}
	}

	ret = xmlTextWriterEndElement(writer);
	CHECK_RET;

	ret = xmlTextWriterEndDocument(writer);
	CHECK_RET;

	DEBUG("Ended XML document");

	/* Call xmlFreeTextWriter() before ftello() because the former will
	 * flush the file stream. */
	xmlFreeTextWriter(writer);
	writer = NULL;

	end_offset = ftello(out);
	if (end_offset == -1) {
		ret = WIMLIB_ERR_WRITE;
	} else {
		ret = 0;
		out_res_entry->offset        = start_offset;
		out_res_entry->size          = end_offset - start_offset;
		out_res_entry->original_size = end_offset - start_offset;
		out_res_entry->flags         = WIM_RESHDR_FLAG_METADATA;
	}
out_free_text_writer:
	/* xmlFreeTextWriter will free the attached xmlOutputBuffer. */
	xmlFreeTextWriter(writer);
	out_buffer = NULL;
out_output_buffer_close:
	if (out_buffer != NULL)
		xmlOutputBufferClose(out_buffer);
out:
	if (ret == 0)
		DEBUG("Successfully wrote XML data");
	return ret;
}

/* Returns the name of the specified image. */
WIMLIBAPI const tchar *
wimlib_get_image_name(const WIMStruct *w, int image)
{
	if (image < 1 || image > w->hdr.image_count)
		return NULL;
	return w->wim_info->images[image - 1].name;
}

/* Returns the description of the specified image. */
WIMLIBAPI const tchar *
wimlib_get_image_description(const WIMStruct *w, int image)
{
	if (image < 1 || image > w->hdr.image_count)
		return NULL;
	return w->wim_info->images[image - 1].description;
}

/* Determines if an image name is already used by some image in the WIM. */
WIMLIBAPI bool
wimlib_image_name_in_use(const WIMStruct *w, const tchar *name)
{
	if (!name || !*name)
		return false;
	for (int i = 1; i <= w->hdr.image_count; i++)
		if (!tstrcmp(w->wim_info->images[i - 1].name, name))
			return true;
	return false;
}


/* Extracts the raw XML data to a file stream. */
WIMLIBAPI int
wimlib_extract_xml_data(WIMStruct *w, FILE *fp)
{
	size_t bytes_written;

	if (!w->xml_data)
		return WIMLIB_ERR_INVALID_PARAM;
	bytes_written = fwrite(w->xml_data, 1, w->hdr.xml_res_entry.size, fp);
	if (bytes_written != w->hdr.xml_res_entry.size) {
		ERROR_WITH_ERRNO("Failed to extract XML data");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/* Sets the name of an image in the WIM. */
WIMLIBAPI int
wimlib_set_image_name(WIMStruct *w, int image, const tchar *name)
{
	tchar *p;
	int i;

	DEBUG("Setting the name of image %d to %"TS, image, name);

	if (!name || !*name) {
		ERROR("Must specify a non-empty string for the image name");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if (image < 1 || image > w->hdr.image_count) {
		ERROR("%d is not a valid image", image);
		return WIMLIB_ERR_INVALID_IMAGE;
	}

	for (i = 1; i <= w->hdr.image_count; i++) {
		if (i == image)
			continue;
		if (tstrcmp(w->wim_info->images[i - 1].name, name) == 0) {
			ERROR("The name \"%"TS"\" is already in use in the WIM!",
			      name);
			return WIMLIB_ERR_IMAGE_NAME_COLLISION;
		}
	}

	p = TSTRDUP(name);
	if (!p)
		return WIMLIB_ERR_NOMEM;

	FREE(w->wim_info->images[image - 1].name);
	w->wim_info->images[image - 1].name = p;
	return 0;
}

static int
do_set_image_info_str(WIMStruct *w, int image, const tchar *tstr,
		      size_t offset)
{
	tchar *tstr_copy;
	tchar **dest_tstr_p;

	if (image < 1 || image > w->hdr.image_count) {
		ERROR("%d is not a valid image", image);
		return WIMLIB_ERR_INVALID_IMAGE;
	}
	if (tstr) {
		tstr_copy = TSTRDUP(tstr);
		if (!tstr_copy)
			return WIMLIB_ERR_NOMEM;
	} else {
		tstr_copy = NULL;
	}
	dest_tstr_p = (tchar**)((void*)&w->wim_info->images[image - 1] + offset);

	FREE(*dest_tstr_p);
	*dest_tstr_p = tstr_copy;
	return 0;
}

/* Sets the description of an image in the WIM. */
WIMLIBAPI int
wimlib_set_image_descripton(WIMStruct *w, int image,
			    const tchar *description)
{
	return do_set_image_info_str(w, image, description,
				     offsetof(struct image_info, description));
}

/* Set the <FLAGS> element of a WIM image */
WIMLIBAPI int
wimlib_set_image_flags(WIMStruct *w, int image, const tchar *flags)
{
	return do_set_image_info_str(w, image, flags,
				     offsetof(struct image_info, flags));
}
