/*
 * xml.c
 *
 * Deals with the XML information in WIM files.  Uses the C library libxml2.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <libxml/encoding.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlwriter.h>
#include <string.h>

#include "wimlib/assert.h"
#include "wimlib/blob_table.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/metadata.h"
#include "wimlib/resource.h"
#include "wimlib/timestamp.h"
#include "wimlib/xml.h"
#include "wimlib/write.h"

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
	tchar   *pkeyconfigversion;
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
	bool wimboot;

	/* Note: must update clone_image_info() if adding new fields here  */
};

/* A struct wim_info structure corresponds to the entire XML data for a WIM file. */
struct wim_info {
	u64 total_bytes;
	int num_images;
	/* Array of `struct image_info's, one for each image in the WIM that is
	 * mentioned in the XML data. */
	struct image_info *images;
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

u64
wim_info_get_total_bytes(const struct wim_info *info)
{
	if (info)
		return info->total_bytes;
	else
		return 0;
}

u64
wim_info_get_image_hard_link_bytes(const struct wim_info *info, int image)
{
	if (info)
		return info->images[image - 1].hard_link_bytes;
	else
		return 0;
}

u64
wim_info_get_image_total_bytes(const struct wim_info *info, int image)
{
	if (info)
		return info->images[image - 1].total_bytes;
	else
		return 0;
}

unsigned
wim_info_get_num_images(const struct wim_info *info)
{
	if (info)
		return info->num_images;
	else
		return 0;
}

void
wim_info_set_wimboot(struct wim_info *info, int image, bool value)
{
	info->images[image - 1].wimboot = value;
}

bool
wim_info_get_wimboot(const struct wim_info *info, int image)
{
	return info->images[image - 1].wimboot;
}

/* Architecture constants are from w64 mingw winnt.h  */
#define PROCESSOR_ARCHITECTURE_INTEL 0
#define PROCESSOR_ARCHITECTURE_MIPS 1
#define PROCESSOR_ARCHITECTURE_ALPHA 2
#define PROCESSOR_ARCHITECTURE_PPC 3
#define PROCESSOR_ARCHITECTURE_SHX 4
#define PROCESSOR_ARCHITECTURE_ARM 5
#define PROCESSOR_ARCHITECTURE_IA64 6
#define PROCESSOR_ARCHITECTURE_ALPHA64 7
#define PROCESSOR_ARCHITECTURE_MSIL 8
#define PROCESSOR_ARCHITECTURE_AMD64 9
#define PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 10

/* Returns a statically allocated string that is a string representation of the
 * architecture number. */
static const tchar *
get_arch(int arch)
{
	switch (arch) {
	case PROCESSOR_ARCHITECTURE_INTEL:
		return T("x86");
	case PROCESSOR_ARCHITECTURE_MIPS:
		return T("MIPS");
	case PROCESSOR_ARCHITECTURE_ARM:
		return T("ARM");
	case PROCESSOR_ARCHITECTURE_IA64:
		return T("ia64");
	case PROCESSOR_ARCHITECTURE_AMD64:
		return T("x86_64");
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

	if (*tstr_ret)
		return 0;

	for_node_child(string_node, child)
		if (node_is_text(child) && child->content)
			return utf8_to_tstr_simple(child->content, tstr_ret);
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
	FREE(windows_info->pkeyconfigversion);
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
		} else if (node_name_is(child, "SERVICINGDATA")) {
			xmlNode *grandchild;

			for_node_child(child, grandchild) {
				if (node_is_element(grandchild) &&
				    node_name_is(grandchild, "PKEYCONFIGVERSION"))
				{
					ret = node_get_string(grandchild,
							      &windows_info->pkeyconfigversion);
				}
			}
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
		xmlFree(index_prop);
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
		} else if (node_name_is(child, "WIMBOOT")) {
			if (node_get_u64(child) == 1) {
				image_info->wimboot = true;
			}
		}
		if (ret != 0)
			return ret;
	}
	if (!image_info->name) {
		tchar *empty_name;
		empty_name = MALLOC(sizeof(tchar));
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
			if (unlikely(num_images == MAX_IMAGES)) {
				ret = WIMLIB_ERR_IMAGE_COUNT;
				goto err;
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
				ret = xml_read_image_info(child,
							  &wim_info->images[i]);
				if (ret != 0)
					goto err;
				i++;
			} else if (node_name_is(child, "TOTALBYTES")) {
				wim_info->total_bytes = node_get_u64(child);
			} else if (node_name_is(child, "ESD")) {
				xmlNode *esdchild;
				for_node_child(child, esdchild) {
					if (node_is_element(esdchild) &&
					    node_name_is(esdchild, "ENCRYPTED"))
					{
						ret = WIMLIB_ERR_WIM_IS_ENCRYPTED;
						goto err;
					}
				}
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
				ret = WIMLIB_ERR_IMAGE_COUNT;
				goto err;
			}
		}

	}
	*wim_info_ret = wim_info;
	return 0;
err:
	free_wim_info(wim_info);
	return ret;
}

/* Prints the information contained in a `struct windows_info'.  */
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

	rc = xmlTextWriterEndElement(writer); /* </VERSION> */
	if (rc < 0)
		return rc;

	return 0;
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

	if (windows_info->pkeyconfigversion) {
		rc = xmlTextWriterStartElement(writer, "SERVICINGDATA");
		if (rc < 0)
			return rc;

		rc = xml_write_string(writer, "PKEYCONFIGVERSION",
				      windows_info->pkeyconfigversion);
		if (rc)
			return rc;

		rc = xmlTextWriterEndElement(writer);
		if (rc < 0)
			return rc;
	}

	if (windows_info->windows_version_exists) {
		rc = xml_write_windows_version(writer, &windows_info->windows_version);
		if (rc)
			return rc;
	}

	rc = xml_write_string(writer, "SYSTEMROOT", windows_info->system_root);
	if (rc)
		return rc;

	rc = xmlTextWriterEndElement(writer); /* </WINDOWS> */
	if (rc < 0)
		return rc;

	return 0;
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
xml_write_image_info(xmlTextWriter *writer, const struct image_info *image_info,
		     int index)
{
	int rc;

	rc = xmlTextWriterStartElement(writer, "IMAGE");
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatAttribute(writer, "INDEX", "%d", index);
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

	if (image_info->wimboot) {
		rc = xmlTextWriterWriteFormatElement(writer, "WIMBOOT", "%d", 1);
		if (rc < 0)
			return rc;
	}

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

	new->arch = old->arch;

	ret = dup_strings_from_specs(old, new, windows_info_xml_string_specs,
				     ARRAY_LEN(windows_info_xml_string_specs));
	if (ret)
		return ret;

	if (old->pkeyconfigversion) {
		new->pkeyconfigversion = TSTRDUP(old->pkeyconfigversion);
		if (new->pkeyconfigversion == NULL)
			return WIMLIB_ERR_NOMEM;
	}

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
	new->wimboot = old->wimboot;
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
xml_get_max_image_name_len(const WIMStruct *wim)
{
	size_t max_len = 0;
	for (u32 i = 0; i < wim->hdr.image_count; i++)
		max_len = max(max_len, tstrlen(wim->wim_info->images[i].name));
	return max_len;
}

void
xml_set_memory_allocator(void *(*malloc_func)(size_t),
			 void (*free_func)(void *),
			 void *(*realloc_func)(void *, size_t))
{
	xmlMemSetup(free_func, malloc_func, realloc_func, STRDUP);
}

static u64
inode_sum_stream_sizes(const struct wim_inode *inode,
		       const struct blob_table *blob_table)
{
	u64 total_size = 0;

	for (unsigned i = 0; i < inode->i_num_streams; i++) {
		const struct blob_descriptor *blob;

		blob = stream_blob(&inode->i_streams[i], blob_table);
		if (blob)
			total_size += blob->size;
	}
	return total_size;
}

/*
 * Calculate what to put in the <FILECOUNT>, <DIRCOUNT>, <TOTALBYTES>, and
 * <HARDLINKBYTES> elements of the specified WIM image.
 *
 * Note: since these stats are likely to be used for display purposes only, we
 * no longer attempt to duplicate WIMGAPI's weird bugs when calculating them.
 */
void
xml_update_image_info(WIMStruct *wim, int image)
{
	struct image_info *info;
	struct wim_image_metadata *imd;
	struct wim_inode *inode;
	u64 size;

	info = &wim->wim_info->images[image - 1];
	imd = wim->image_metadata[image - 1];

	info->file_count = 0;
	info->dir_count = 0;
	info->total_bytes = 0;
	info->hard_link_bytes = 0;

	image_for_each_inode(inode, imd) {
		if (inode_is_directory(inode))
			info->dir_count += inode->i_nlink;
		else
			info->file_count += inode->i_nlink;
		size = inode_sum_stream_sizes(inode, wim->blob_table);
		info->total_bytes += size * inode->i_nlink;
		info->hard_link_bytes += size * (inode->i_nlink - 1);
	}

	info->last_modification_time = now_as_wim_timestamp();
}

/* Adds an image to the XML information. */
int
xml_add_image(WIMStruct *wim, const tchar *name)
{
	struct wim_info *wim_info;
	struct image_info *image_info;

	wimlib_assert(name != NULL);

	/* If this is the first image, allocate the struct wim_info.  Otherwise
	 * use the existing struct wim_info. */
	if (wim->wim_info) {
		wim_info = wim->wim_info;
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

	wim->wim_info = wim_info;
	image_info->index = wim_info->num_images;
	image_info->creation_time = now_as_wim_timestamp();
	xml_update_image_info(wim, image_info->index);
	return 0;

out_destroy_image_info:
	destroy_image_info(image_info);
	wim_info->num_images--;
out_free_wim_info:
	if (wim_info != wim->wim_info)
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

	wim_timestamp_to_str(image_info->last_modification_time, buf, sizeof(buf));
	tprintf(T("Last Modification Time: %"TS"\n"), buf);
	if (image_info->windows_info_exists)
		print_windows_info(&image_info->windows_info);
	if (image_info->flags)
		tprintf(T("Flags:                  %"TS"\n"), image_info->flags);
	tprintf(T("WIMBoot compatible:     %"TS"\n"),
		image_info->wimboot ? T("yes") : T("no"));
	tputchar('\n');
}

void
libxml_global_init(void)
{
	xmlInitParser();
	xmlInitCharEncodingHandlers();
}

void
libxml_global_cleanup(void)
{
	xmlCleanupParser();
	xmlCleanupCharEncodingHandlers();
}

/* Reads the XML data from a WIM file.  */
int
read_wim_xml_data(WIMStruct *wim)
{
	void *buf;
	size_t bufsize;
	u8 *xml_data;
	xmlDoc *doc;
	xmlNode *root;
	int ret;

	ret = wimlib_get_xml_data(wim, &buf, &bufsize);
	if (ret)
		goto out;
	xml_data = buf;

	doc = xmlReadMemory((const char *)xml_data, bufsize,
			    NULL, "UTF-16LE", 0);
	if (!doc) {
		ERROR("Failed to parse XML data");
		ret = WIMLIB_ERR_XML;
		goto out_free_xml_data;
	}

	root = xmlDocGetRootElement(doc);
	if (!root || !node_is_element(root) || !node_name_is(root, "WIM")) {
		ERROR("WIM XML data is invalid");
		ret = WIMLIB_ERR_XML;
		goto out_free_doc;
	}

	ret = xml_read_wim_info(root, &wim->wim_info);
out_free_doc:
	xmlFreeDoc(doc);
out_free_xml_data:
	FREE(xml_data);
out:
	return ret;
}

/* Prepares an in-memory buffer containing the UTF-16LE XML data for a WIM file.
 *
 * total_bytes is the number to write in <TOTALBYTES>, or
 * WIM_TOTALBYTES_USE_EXISTING to use the existing value in memory, or
 * WIM_TOTALBYTES_OMIT to omit <TOTALBYTES> entirely.
 */
static int
prepare_wim_xml_data(WIMStruct *wim, int image, u64 total_bytes,
		     u8 **xml_data_ret, size_t *xml_len_ret)
{
	xmlCharEncodingHandler *encoding_handler;
	xmlBuffer *buf;
	xmlOutputBuffer *outbuf;
	xmlTextWriter *writer;
	int ret;
	const xmlChar *content;
	int len;
	u8 *xml_data;
	size_t xml_len;

	/* Open an xmlTextWriter that writes to an in-memory buffer using
	 * UTF-16LE encoding.  */

	encoding_handler = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF16LE);
	if (!encoding_handler) {
		ERROR("Failed to get XML character encoding handler for UTF-16LE");
		ret = WIMLIB_ERR_LIBXML_UTF16_HANDLER_NOT_AVAILABLE;
		goto out;
	}

	buf = xmlBufferCreate();
	if (!buf) {
		ERROR("Failed to create xmlBuffer");
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	outbuf = xmlOutputBufferCreateBuffer(buf, encoding_handler);
	if (!outbuf) {
		ERROR("Failed to allocate xmlOutputBuffer");
		ret = WIMLIB_ERR_NOMEM;
		goto out_buffer_free;
	}

	writer = xmlNewTextWriter(outbuf);
	if (!writer) {
		ERROR("Failed to allocate xmlTextWriter");
		ret = WIMLIB_ERR_NOMEM;
		goto out_output_buffer_close;
	}

	/* Write the XML document.  */

	ret = xmlTextWriterStartElement(writer, "WIM");
	if (ret < 0)
		goto out_write_error;

	/* The contents of the <TOTALBYTES> element in the XML data, under the
	 * <WIM> element (not the <IMAGE> element), is for non-split WIMs the
	 * size of the WIM file excluding the XML data and integrity table.
	 * For split WIMs, <TOTALBYTES> takes into account the entire WIM, not
	 * just the current part.  */
	if (total_bytes != WIM_TOTALBYTES_OMIT) {
		if (total_bytes == WIM_TOTALBYTES_USE_EXISTING) {
			if (wim->wim_info)
				total_bytes = wim->wim_info->total_bytes;
			else
				total_bytes = 0;
		}
		ret = xmlTextWriterWriteFormatElement(writer, "TOTALBYTES",
						      "%"PRIu64, total_bytes);
		if (ret < 0)
			goto out_write_error;
	}

	if (image == WIMLIB_ALL_IMAGES) {
		for (int i = 0; i < wim->hdr.image_count; i++) {
			ret = xml_write_image_info(writer,
						   &wim->wim_info->images[i],
						   i + 1);
			if (ret < 0)
				goto out_write_error;
			if (ret > 0)
				goto out_free_text_writer;
		}
	} else {
		ret = xml_write_image_info(writer,
					   &wim->wim_info->images[image - 1],
					   1);
		if (ret < 0)
			goto out_write_error;
		if (ret > 0)
			goto out_free_text_writer;
	}

	ret = xmlTextWriterEndElement(writer);
	if (ret < 0)
		goto out_write_error;

	ret = xmlTextWriterEndDocument(writer);
	if (ret < 0)
		goto out_write_error;

	ret = xmlTextWriterFlush(writer);
	if (ret < 0)
		goto out_write_error;

	/* Retrieve the buffer into which the document was written.  */

	content = xmlBufferContent(buf);
	len = xmlBufferLength(buf);

	/* Copy the data into a new buffer, and prefix it with the UTF-16LE BOM
	 * (byte order mark), which is required by MS's software to understand
	 * the data.  */

	xml_len = len + 2;
	xml_data = MALLOC(xml_len);
	if (!xml_data) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_text_writer;
	}
	xml_data[0] = 0xff;
	xml_data[1] = 0xfe;
	memcpy(&xml_data[2], content, len);

	/* Clean up libxml objects and return success.  */
	*xml_data_ret = xml_data;
	*xml_len_ret = xml_len;
	ret = 0;
out_free_text_writer:
	/* xmlFreeTextWriter will free the attached xmlOutputBuffer.  */
	xmlFreeTextWriter(writer);
	goto out_buffer_free;
out_output_buffer_close:
	xmlOutputBufferClose(outbuf);
out_buffer_free:
	xmlBufferFree(buf);
out:
	return ret;

out_write_error:
	ERROR("Error writing XML data");
	ret = WIMLIB_ERR_WRITE;
	goto out_free_text_writer;
}

/* Writes the XML data to a WIM file.  */
int
write_wim_xml_data(WIMStruct *wim, int image, u64 total_bytes,
		   struct wim_reshdr *out_reshdr,
		   int write_resource_flags)
{
	int ret;
	u8 *xml_data;
	size_t xml_len;

	ret = prepare_wim_xml_data(wim, image, total_bytes,
				   &xml_data, &xml_len);
	if (ret)
		return ret;

	/* Write the XML data uncompressed.  Although wimlib can handle
	 * compressed XML data, MS software cannot.  */
	ret = write_wim_resource_from_buffer(xml_data,
					     xml_len,
					     true,
					     &wim->out_fd,
					     WIMLIB_COMPRESSION_TYPE_NONE,
					     0,
					     out_reshdr,
					     NULL,
					     write_resource_flags);
	FREE(xml_data);
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI const tchar *
wimlib_get_image_name(const WIMStruct *wim, int image)
{
	if (image < 1 || image > wim->hdr.image_count)
		return NULL;
	return wim->wim_info->images[image - 1].name;
}

/* API function documented in wimlib.h  */
WIMLIBAPI const tchar *
wimlib_get_image_description(const WIMStruct *wim, int image)
{
	if (image < 1 || image > wim->hdr.image_count)
		return NULL;
	return wim->wim_info->images[image - 1].description;
}

/* API function documented in wimlib.h  */
WIMLIBAPI bool
wimlib_image_name_in_use(const WIMStruct *wim, const tchar *name)
{
	if (!name || !*name)
		return false;
	for (int i = 1; i <= wim->hdr.image_count; i++)
		if (!tstrcmp(wim->wim_info->images[i - 1].name, name))
			return true;
	return false;
}


/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_get_xml_data(WIMStruct *wim, void **buf_ret, size_t *bufsize_ret)
{
	const struct wim_reshdr *xml_reshdr;

	if (wim->filename == NULL && filedes_is_seekable(&wim->in_fd))
		return WIMLIB_ERR_NO_FILENAME;

	if (buf_ret == NULL || bufsize_ret == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	xml_reshdr = &wim->hdr.xml_data_reshdr;

	*bufsize_ret = xml_reshdr->uncompressed_size;
	return wim_reshdr_to_data(xml_reshdr, wim, buf_ret);
}

WIMLIBAPI int
wimlib_extract_xml_data(WIMStruct *wim, FILE *fp)
{
	int ret;
	void *buf;
	size_t bufsize;

	ret = wimlib_get_xml_data(wim, &buf, &bufsize);
	if (ret)
		return ret;

	if (fwrite(buf, 1, bufsize, fp) != bufsize) {
		ERROR_WITH_ERRNO("Failed to extract XML data");
		ret = WIMLIB_ERR_WRITE;
	}
	FREE(buf);
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_image_name(WIMStruct *wim, int image, const tchar *name)
{
	tchar *p;
	int i;

	if (name == NULL)
		name = T("");

	if (image < 1 || image > wim->hdr.image_count)
		return WIMLIB_ERR_INVALID_IMAGE;

	if (*name) {
		for (i = 1; i <= wim->hdr.image_count; i++) {
			if (i == image)
				continue;
			if (!tstrcmp(wim->wim_info->images[i - 1].name, name))
				return WIMLIB_ERR_IMAGE_NAME_COLLISION;
		}
	}

	p = TSTRDUP(name);
	if (!p)
		return WIMLIB_ERR_NOMEM;

	FREE(wim->wim_info->images[image - 1].name);
	wim->wim_info->images[image - 1].name = p;
	return 0;
}

static int
do_set_image_info_str(WIMStruct *wim, int image, const tchar *tstr,
		      size_t offset)
{
	tchar *tstr_copy;
	tchar **dest_tstr_p;

	if (image < 1 || image > wim->hdr.image_count) {
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
	dest_tstr_p = (tchar**)((void*)&wim->wim_info->images[image - 1] + offset);

	FREE(*dest_tstr_p);
	*dest_tstr_p = tstr_copy;
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_image_descripton(WIMStruct *wim, int image,
			    const tchar *description)
{
	return do_set_image_info_str(wim, image, description,
				     offsetof(struct image_info, description));
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_image_flags(WIMStruct *wim, int image, const tchar *flags)
{
	return do_set_image_info_str(wim, image, flags,
				     offsetof(struct image_info, flags));
}
