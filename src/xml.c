/*
 * xml.c
 *
 * Deals with the XML information in WIM files.  Uses the C library libxml2.
 *
 * Copyright (C) 2012 Eric Biggers
 *
 * wimlib - Library for working with WIM files 
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "wimlib_internal.h"
#include "dentry.h"
#include "xml.h"
#include "timestamp.h"
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlwriter.h>

/* The following 4 structures are used to form an in-memory representation of
 * the XML data (other than the raw parse tree from libxml). */

struct windows_version {
	u64 major;
	u64 minor;
	u64 build;
	u64 sp_build;
	u64 sp_level;
};

struct windows_info {
	u64    arch;
	char  *product_name;
	char  *edition_id;
	char  *installation_type;
	char  *hal;
	char  *product_type;
	char  *product_suite;
	char **languages;
	char  *default_language;
	u64    num_languages;
	char  *system_root;
	bool   windows_version_exists;
	struct windows_version windows_version;
};

struct image_info {
	u64   index;
	u64   dir_count;
	u64   file_count;
	u64   total_bytes;
	u64   hard_link_bytes;
	u64   creation_time;
	u64   last_modification_time;
	bool  windows_info_exists;
	struct windows_info windows_info;
	char *name;
	char *description;
	char  *display_name;
	char  *display_description;
	char  *flags;
};


/* Returns a statically allocated string that is a string representation of the
 * architecture number. */
static const char *get_arch(int arch)
{
	static char buf[20];
	switch (arch) {
	case 0:
		return "x86";
	case 6:
		return "ia64";
	case 9:
		return "x86_64";
	/* XXX Are there other arch values? */
	default:
		snprintf(buf, sizeof(buf), "%d (unknown)", arch);
		return buf;
	}
}


/* Iterate through the children of an xmlNode. */
#define for_node_child(parent, child) for (child = parent->children; \
				child != NULL; child = child->next)

/* Utility functions for xmlNodes */
static inline bool node_is_element(xmlNode *node)
{
	return node->type == XML_ELEMENT_NODE;
}

static inline bool node_is_text(xmlNode *node)
{
	return node->type == XML_TEXT_NODE;
}

static inline bool node_is_attribute(xmlNode *node)
{
	return node->type == XML_ATTRIBUTE_NODE;
}

static inline bool node_name_is(xmlNode *node, const char *name)
{
	/* For now, both upper case and lower case element names are accepted. */
	return strcasecmp((const char *)node->name, name) == 0;
}

/* Finds the text node that is a child of an element node and returns its
 * content converted to a 64-bit unsigned integer.  Returns 0 if no text node is
 * found. */
static u64 node_get_u64(const xmlNode *u64_node)
{
	xmlNode *child;
	for_node_child(u64_node, child)
		if (node_is_text(child))
			return strtoull((const char *)child->content, NULL, 10);
	return 0;
}

/* Like node_get_u64(), but expects a number in base 16. */
static u64 node_get_hex_u64(const xmlNode *u64_node)
{
	xmlNode *child;
	for_node_child(u64_node, child)
		if (node_is_text(child))
			return strtoull(child->content, NULL, 16);
	return 0;
}

static int node_get_string(const xmlNode *string_node, char **str)
{
	xmlNode *child;
	char *p = NULL;

	for_node_child(string_node, child) {
		if (node_is_text(child) && child->content) {
			p = STRDUP(child->content);
			if (!p)
				return WIMLIB_ERR_NOMEM;
			break;
		}
	}
	*str = p;
	return 0;
}

/* Returns the timestamp from a time node.  It has child elements <HIGHPART> and
 * <LOWPART> that are then used to construct a 64-bit timestamp. */
static u64 node_get_timestamp(const xmlNode *time_node)
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
static int sort_by_index(const void *p1, const void *p2)
{
	u64 index_1 = ((struct image_info*)p1)->index;
	u64 index_2 = ((struct image_info*)p1)->index;
	if (index_1 < index_2)
		return -1;
	else if (index_1 > index_2)
		return 1;
	else
		return 0;
}


/* Frees memory allocated inside a struct windows_info structure. */
static void destroy_windows_info(struct windows_info *windows_info)
{
	uint i;

	FREE(windows_info->product_name);
	FREE(windows_info->edition_id);
	FREE(windows_info->installation_type);
	FREE(windows_info->product_type);
	for (i = 0; i < windows_info->num_languages; i++)
		FREE(windows_info->languages[i]);
	FREE(windows_info->languages);
	FREE(windows_info->system_root);
}

/* Frees memory allocated inside a struct image_info structure. */
static void destroy_image_info(struct image_info *image_info)
{
	FREE(image_info->name);
	FREE(image_info->description);
	FREE(image_info->flags);
	FREE(image_info->display_name);
	FREE(image_info->display_description);
	destroy_windows_info(&image_info->windows_info);
	memset(image_info, 0, sizeof(struct image_info));
}

void free_wim_info(struct wim_info *info)
{
	uint i;
	if (info) {
		if (info->images) {
			for (i = 0; i < info->num_images; i++)
				destroy_image_info(&info->images[i]);
			FREE(info->images);
		}
		FREE(info);
	}
}

/* Reads the information from a <VERSION> element inside the <WINDOWS> element.
 * */
static void xml_read_windows_version(const xmlNode *version_node, 
				     struct windows_version* windows_version)
{
	xmlNode *child;
	for_node_child(version_node, child) {
		if (!node_is_element(child))
			continue;
		if (node_name_is(child, "MAJOR"))
			windows_version->major    = node_get_u64(child);
		else if (node_name_is(child, "MINOR"))
			windows_version->minor    = node_get_u64(child);
		else if (node_name_is(child, "BUILD"))
			windows_version->build    = node_get_u64(child);
		else if (node_name_is(child, "SPBUILD"))
			windows_version->sp_build = node_get_u64(child);
		else if (node_name_is(child, "SPLEVEL"))
			windows_version->sp_level = node_get_u64(child);
	}
}

/* Reads the information from a <LANGUAGE> element inside a <WINDOWS> element.
 * */
static int xml_read_languages(const xmlNode *languages_node, 
			      char ***languages_ret, 
			      u64 *num_languages_ret,
			      char **default_language_ret)
{
	xmlNode *child;
	uint i;
	uint num_languages;
	char **languages;
	int ret;

	num_languages = 0;
	for_node_child(languages_node, child)
		if (node_is_element(child) && node_name_is(child, "LANGUAGE"))
			num_languages++;

	languages = CALLOC(num_languages, sizeof(char*));
	if (!languages)
		return WIMLIB_ERR_NOMEM;

	*languages_ret = languages;
	*num_languages_ret = num_languages;

	i = 0;
	ret = 0;
	for_node_child(languages_node, child) {
		if (!node_is_element(child))
			continue;
		if (node_name_is(child, "LANGUAGE"))
			ret = node_get_string(child, &languages[i++]);
		else if (node_name_is(child, "DEFAULT"))
			ret = node_get_string(child, default_language_ret);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/* Reads the information from a <WINDOWS> element inside an <IMAGE> element. */
static int xml_read_windows_info(const xmlNode *windows_node, 
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
	return 0;
}

/* Reads the information from an <IMAGE> element. */
static int xml_read_image_info(xmlNode *image_node, 
			       struct image_info *image_info)
{
	xmlNode *child;
	xmlChar *index_prop;
	int ret;
	
	index_prop = xmlGetProp(image_node, "INDEX");
	if (index_prop) {
		image_info->index = strtoul(index_prop, NULL, 10);
		FREE(index_prop);
	} else {
		image_info->index = 0;
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
			DEBUG("Found <WINDOWS> tag\n");
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
		WARNING("Image with index %"PRIu64" has no name\n", 
					image_info->index);
		image_info->name = MALLOC(1);
		if (!image_info->name) {
			ERROR("Out of memory!\n");
			return WIMLIB_ERR_NOMEM;
		}
		image_info->name[0] = '\0';
		return 0;
	}
	
	return 0;
}

/* Reads the information from a <WIM> element, which should be the root element
 * of the XML tree. */
static int xml_read_wim_info(const xmlNode *wim_node, struct wim_info **wim_info_ret)
{
	struct wim_info *wim_info;
	xmlNode *child;
	int ret;
	uint num_images;
	struct image_info *cur_image_info;

	wim_info = CALLOC(1, sizeof(struct wim_info));
	if (!wim_info) {
		ERROR("Out of memory!\n");
		return WIMLIB_ERR_NOMEM;
	}

	/* Count how many images there are. */
	num_images = 0;
	for_node_child(wim_node, child)
		if (node_is_element(child) && node_name_is(child, "IMAGE"))
			num_images++;

	if (num_images == 0)
		goto done;

	/* Allocate the array of struct image_infos and fill them in. */
	wim_info->images = CALLOC(num_images, sizeof(wim_info->images[0]));
	if (!wim_info->images) {
		ret = WIMLIB_ERR_NOMEM;
		ERROR("Out of memory!\n");
		goto err;
	}
	wim_info->num_images = num_images;
	cur_image_info = wim_info->images;
	for_node_child(wim_node, child) {
		if (!node_is_element(child))
			continue;
		if (node_name_is(child, "IMAGE")) {
			DEBUG("Found <IMAGE> tag\n");
			ret = xml_read_image_info(child, cur_image_info++);
			if (ret != 0)
				goto err;
		} else if (node_name_is(child, "TOTALBYTES")) {
			wim_info->total_bytes = node_get_u64(child);
		}
	}

	/* Sort the array of struct image_infos by image index. */
	qsort(wim_info->images, wim_info->num_images, 
	      sizeof(struct image_info), sort_by_index);
done:
	*wim_info_ret = wim_info;
	return 0;
err:
	free_wim_info(wim_info);
	return ret;
}

/* Prints the information contained in a struct windows_info structure. */
static void print_windows_info(const struct windows_info *windows_info)
{
	uint i;
	const struct windows_version *windows_version;

	printf("Architecture:           %s\n", get_arch(windows_info->arch));
	printf("Product Name:           %s\n", windows_info->product_name);
	printf("Edition ID:             %s\n", windows_info->edition_id);
	printf("Installation Type:      %s\n", windows_info->installation_type);
	if (windows_info->hal)
		printf("HAL:                    %s\n", windows_info->hal);
	printf("Product Type:           %s\n", windows_info->product_type);
	if (windows_info->product_suite)
		printf("Product Suite:          %s\n", windows_info->product_suite);
	printf("Languages:              ");
	for (i = 0; i < windows_info->num_languages; i++) {
		fputs(windows_info->languages[i], stdout);
		putchar(' ');
	}
	putchar('\n');
	printf("Default Language:       %s\n", windows_info->default_language);
	printf("System Root:            %s\n", windows_info->system_root);
	if (windows_info->windows_version_exists) {
		windows_version = &windows_info->windows_version;
		printf("Major Version:          %"PRIu64"\n", 
				windows_version->major);
		printf("Minor Version:          %"PRIu64"\n", 
				windows_version->minor);
		printf("Build:                  %"PRIu64"\n", 
				windows_version->build);
		printf("Service Pack Build:     %"PRIu64"\n", 
				windows_version->sp_build);
		printf("Service Pack Level:     %"PRIu64"\n", 
				windows_version->sp_level);
	}
}


/* Writes the information contained in a struct windows_version structure to the XML
 * document being constructed in memory.  This is the <VERSION> element inside
 * the <WINDOWS> element. */
static int xml_write_windows_version(xmlTextWriter *writer, 
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

/* Writes the information contained in a struct windows_info structure to the XML
 * document being constructed in memory. This is the <WINDOWS> element. */
static int xml_write_windows_info(xmlTextWriter *writer, 
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
	
	if (windows_info->product_name) {
		rc = xmlTextWriterWriteElement(writer, "PRODUCTNAME", 
							windows_info->product_name);
		if (rc < 0)
			return rc;
	}

	if (windows_info->edition_id) {
		rc = xmlTextWriterWriteElement(writer, "EDITIONID", 
							windows_info->edition_id);
		if (rc < 0)
			return rc;
	}

	if (windows_info->installation_type) {
		rc = xmlTextWriterWriteElement(writer, "INSTALLATIONTYPE", 
							windows_info->installation_type);
		if (rc < 0)
			return rc;
	}

	if (windows_info->hal) {
		rc = xmlTextWriterWriteElement(writer, "HAL", 
							windows_info->hal);
		if (rc < 0)
			return rc;
	}

	if (windows_info->system_root) {
		rc = xmlTextWriterWriteElement(writer, "SYSTEMROOT", 
						windows_info->system_root);
			if (rc < 0)
				return rc;
	}

	if (windows_info->product_type) {
		rc = xmlTextWriterWriteElement(writer, "PRODUCTTYPE", 
						windows_info->product_type);
		if (rc < 0)
			return rc;
	}

	if (windows_info->product_suite) {
		rc = xmlTextWriterWriteElement(writer, "PRODUCTSUITE", 
						windows_info->product_suite);
			if (rc < 0)
				return rc;
	}

	if (windows_info->num_languages) {
		rc = xmlTextWriterStartElement(writer, "LANGUAGES");
		if (rc < 0)
			return rc;

		for (int i = 0; i < windows_info->num_languages; i++) {
			rc = xmlTextWriterWriteElement(writer, "LANGUAGE", 
							windows_info->languages[i]);
			if (rc < 0)
				return rc;
		}
		rc = xmlTextWriterWriteElement(writer, "DEFAULT", 
						windows_info->default_language);
		if (rc < 0)
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

	return xmlTextWriterEndElement(writer); /* </WINDOWS> */
}

/* Writes a time element to the XML document being constructed in memory. */
static int xml_write_time(xmlTextWriter *writer, const char *element_name, 
								u64 time) 
{
	int rc;
	rc = xmlTextWriterStartElement(writer, element_name);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "HIGHPART", 
					"0x%"PRIX32, (u32)(time >> 32));
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatElement(writer, "LOWPART",
						"0x%"PRIX32, (u32)time);
	if (rc < 0)
		return rc;

	rc = xmlTextWriterEndElement(writer); /* </@element_name> */
	if (rc < 0)
		return rc;
	return 0;
}


/* Writes an <IMAGE> element to the XML document. */
static int xml_write_image_info(xmlTextWriter *writer, 
				const struct image_info *image_info)
{
	int rc;
	rc = xmlTextWriterStartElement(writer, "IMAGE");
	if (rc < 0)
		return rc;

	rc = xmlTextWriterWriteFormatAttribute(writer, "INDEX", "%"PRIu64, 
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

	rc = xml_write_time(writer, "CREATIONTIME", 
						image_info->creation_time);
	if (rc < 0)
		return rc;

	rc = xml_write_time(writer, "LASTMODIFICATIONTIME", 
						image_info->last_modification_time);
	if (rc < 0)
		return rc;

	if (image_info->windows_info_exists) {
		rc = xml_write_windows_info(writer, &image_info->windows_info);
		if (rc < 0)
			return rc;
	} else {
		DEBUG("<WINDOWS> tag does not exist.\n");
	}

	if (image_info->name) {
		rc = xmlTextWriterWriteElement(writer, "NAME", image_info->name);
		if (rc < 0)
			return rc;
	}
	if (image_info->description) {
		rc = xmlTextWriterWriteElement(writer, "DESCRIPTION", 
							image_info->description);
		if (rc < 0)
			return rc;
	}
	if (image_info->display_name) {
		rc = xmlTextWriterWriteElement(writer, "DISPLAYNAME", 
						image_info->display_name);
		if (rc < 0)
			return rc;
	}
	if (image_info->display_description) {
		rc = xmlTextWriterWriteElement(writer, "DISPLAYDESCRIPTION", 
						image_info->display_description);
		if (rc < 0)
			return rc;
	}

	if (image_info->flags) {
		rc = xmlTextWriterWriteElement(writer, "FLAGS",
				image_info->flags);
		if (rc < 0)
			return rc;
	}

	return xmlTextWriterEndElement(writer); /* </IMAGE> */
}



/* Makes space for another image in the XML information and return a pointer to
 * it.*/
static struct image_info *add_image_info_struct(struct wim_info *wim_info)
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

static int clone_windows_info(const struct windows_info *old, 
			      struct windows_info *new)
{
	uint i;

	if (old->product_name && !(new->product_name = STRDUP(old->product_name)))
		return WIMLIB_ERR_NOMEM;
	if (old->edition_id && !(new->edition_id = STRDUP(old->edition_id)))
		return WIMLIB_ERR_NOMEM;
	if (old->installation_type && !(new->installation_type = 
					STRDUP(old->installation_type)))
		return WIMLIB_ERR_NOMEM;
	if (old->hal && !(new->hal = STRDUP(old->hal)))
		return WIMLIB_ERR_NOMEM;
	if (old->product_type && !(new->product_type = STRDUP(old->product_type)))
		return WIMLIB_ERR_NOMEM;
	if (old->product_suite && !(new->product_suite = STRDUP(old->product_suite)))
		return WIMLIB_ERR_NOMEM;

	if (old->languages) {
		new->languages = CALLOC(old->num_languages, sizeof(char*));
		if (!new->languages)
			return WIMLIB_ERR_NOMEM;
		new->num_languages = old->num_languages;
		for (i = 0; i < new->num_languages; i++) {
			if (!old->languages[i])
				continue;
			new->languages[i] = STRDUP(old->languages[i]);
			if (!new->languages[i])
				return WIMLIB_ERR_NOMEM;
		}
	}
	if (old->default_language && 
			!(new->default_language = STRDUP(old->default_language)))
		return WIMLIB_ERR_NOMEM;
	if (old->system_root && !(new->system_root = STRDUP(old->system_root)))
		return WIMLIB_ERR_NOMEM;
	return 0;
}

static int clone_image_info(const struct image_info *old, struct image_info *new)
{
	int ret;

	new->dir_count              = old->dir_count;
	new->file_count             = old->file_count;
	new->total_bytes            = old->total_bytes;
	new->hard_link_bytes        = old->hard_link_bytes;
	new->creation_time          = old->creation_time;
	new->last_modification_time = old->last_modification_time;

	if (!(new->name = STRDUP(old->name)))
		return WIMLIB_ERR_NOMEM;

	if (old->description)
		if (!(new->description = STRDUP(old->description)))
			return WIMLIB_ERR_NOMEM;

	if (old->display_name)
		if (!(new->display_name = STRDUP(old->display_name)))
			return WIMLIB_ERR_NOMEM;

	if (old->display_description)
		if (!(new->display_description = STRDUP(old->display_description)))
			return WIMLIB_ERR_NOMEM;

	if (old->flags)
		if (!(new->flags = STRDUP(old->flags)))
			return WIMLIB_ERR_NOMEM;

	if (old->windows_info_exists) {
		new->windows_info_exists = true;
		return clone_windows_info(&old->windows_info, 
					  &new->windows_info);
	}
	return 0;
}

/* Copies the XML information for an image between WIM files. 
 *
 * @dest_image_name and @dest_image_description are ignored if they are NULL;
 * otherwise, they are used to override the image name and/or image description
 * from the XML data in the source WIM file. */
int xml_export_image(const struct wim_info *old_wim_info, 
		     int image, 
		     struct wim_info **new_wim_info_p, 
		     const char *dest_image_name, 
		     const char *dest_image_description)
{
	struct wim_info *new_wim_info;
	struct image_info *image_info;
	int ret;
	char *name;
	char *desc;

	DEBUG("Copying XML data between WIM files for source image %d\n",
			image);

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
		goto err;

	image_info->index = new_wim_info->num_images;

	if (dest_image_name) {
		FREE(image_info->name);
		image_info->name = STRDUP(dest_image_name);
		if (!image_info->name)
			goto err;
	}
	if (dest_image_description) {
		FREE(image_info->description);
		image_info->description = STRDUP(dest_image_description);
		if (!image_info->description)
			goto err;
	}
	*new_wim_info_p = new_wim_info;
	return 0;
err:
	ERROR("Out of memory!\n");
	free_wim_info(new_wim_info);
	return WIMLIB_ERR_NOMEM;
}

/* Removes an image from the XML information. */
void xml_delete_image(struct wim_info **wim_info_p, int image)
{
	struct wim_info *wim_info;
	int i;

	DEBUG("Deleting image %d from the XML data\n", image);
	
	wim_info = *wim_info_p;

	wimlib_assert(wim_info);
	wimlib_assert(image >= 1 && image <= wim_info->num_images);

	destroy_image_info(&wim_info->images[image - 1]);

	for (i = image - 1; i < wim_info->num_images - 1; i++) {
		memcpy(&wim_info->images[i], &wim_info->images[i + 1],
					sizeof(struct image_info));
		wim_info->images[i].index--;
	}

	if (--wim_info->num_images == 0) {
		free_wim_info(wim_info);
		*wim_info_p = NULL;
	}
}

size_t xml_get_max_image_name_len(const WIMStruct *w)
{
	size_t len = 0;
	uint i;
	uint num_images = w->wim_info->num_images;
	for (i = 0; i < num_images; i++)
		len = max(len, strlen(w->wim_info->images[i].name));
	return len;
}

#ifdef ENABLE_CUSTOM_MEMORY_ALLOCATOR
void xml_set_memory_allocator(void *(*malloc_func)(size_t),
				   void (*free_func)(void *),
				   void *(*realloc_func)(void *, size_t))
{
	xmlMemSetup(free_func, malloc_func, realloc_func, STRDUP);
}
#endif

void xml_update_image_info(WIMStruct *w, int image)
{
	struct image_info *image_info;
	struct dentry *root; 

	DEBUG("Updating the image info for image %d\n", image);

	image_info = &w->wim_info->images[image - 1];
	root = w->image_metadata[image - 1].root_dentry;

	calculate_dir_tree_statistics(root, w->lookup_table, 
				      &image_info->dir_count,
				      &image_info->file_count, 
				      &image_info->total_bytes,
				      &image_info->hard_link_bytes);

	image_info->last_modification_time = get_timestamp();
}

/* Adds an image to the XML information. */
int xml_add_image(WIMStruct *w, struct dentry *root_dentry, const char *name, 
		  const char *description, const char *flags_element)
{
	struct wim_info *wim_info;
	struct image_info *image_info;

	wimlib_assert(name);

	DEBUG("Adding image: name = %s, description = %s, flags_element = %s\n",
			name, description, flags_element);

	/* If this is the first image, allocate the struct wim_info.  Otherwise
	 * use the existing struct wim_info. */
	if (w->wim_info) {
		wim_info = w->wim_info;
	} else {
		DEBUG("Allocing struct wim_info with 1 image\n");
		wim_info = CALLOC(1, sizeof(struct wim_info));
		if (!wim_info) {
			ERROR("Could not allocate WIM information struct--- "
					"out of memory!\n");
			return WIMLIB_ERR_NOMEM;
		}
	}

	image_info = add_image_info_struct(wim_info);
	if (!image_info)
		goto err_nomem1;

	if (!(image_info->name = STRDUP(name)))
		goto err_nomem2;

	if (description && !(image_info->description = STRDUP(description)))
		goto err_nomem2;
	if (flags_element && !(image_info->flags = STRDUP(flags_element)))
		goto err_nomem2;
		
	w->wim_info = wim_info;
	image_info->index = wim_info->num_images;
	image_info->creation_time = get_timestamp();
	xml_update_image_info(w, image_info->index);
	return 0;

err_nomem2:
	destroy_image_info(image_info);
err_nomem1:
	if (w->wim_info)
		wim_info->num_images--;
	else
		FREE(wim_info);
	ERROR("Out of memory!\n");
	return WIMLIB_ERR_NOMEM;
}

/* Prints information about the specified image from struct wim_info structure. 
 * @image may be WIM_ALL_IMAGES. */
void print_image_info(const struct wim_info *wim_info, int image)
{
	uint i;
	const struct image_info *image_info;
	const char *desc;
	time_t ctime;
	time_t mtime;

	DEBUG("Printing the image info for image %d\n", image);

	if (image == WIM_ALL_IMAGES) {
		for (i = 1; i <= wim_info->num_images; i++)
			print_image_info(wim_info, i);
	} else {
		image_info = &wim_info->images[image - 1];

		printf("Index:                  %"PRIu64"\n", 
			image_info->index);
		printf("Name:                   %s\n", 
			image_info->name);

		/* Always print the Description: part even if there is no
		 * description. */
		if (image_info->description)
			desc = image_info->description;
		else
			desc = "";
		printf("Description:            %s\n", desc);

		if (image_info->display_name)
			printf("Display Name:           %s\n", 
				image_info->display_name);

		if (image_info->display_description)
			printf("Display Description:    %s\n", 
				image_info->display_description);

		printf("Directory Count:        %"PRIu64"\n", 
				image_info->dir_count);
		printf("File Count:             %"PRIu64"\n", 
				image_info->file_count);
		printf("Total Bytes:            %"PRIu64"\n", 
				image_info->total_bytes);
		printf("Hard Link Bytes:        %"PRIu64"\n", 
				image_info->hard_link_bytes);

		ctime = ms_timestamp_to_unix(image_info->creation_time);
		mtime = ms_timestamp_to_unix(image_info->last_modification_time);

		printf("Creation Time:          %s", asctime(localtime(&ctime)));
		printf("Last Modification Time: %s", asctime(localtime(&mtime)));
		if (image_info->windows_info_exists)
			print_windows_info(&image_info->windows_info);
		if (image_info->flags)
			printf("Flags:                  %s\n", image_info->flags);
		putchar('\n');
	}
}

/* 
 * Reads the XML data from a WIM file.
 */
int read_xml_data(FILE *fp, const struct resource_entry *res, u8 **xml_data_ret,
		  struct wim_info **info_ret)
{
	u8 *xml_data;
	xmlDoc *doc;
	xmlNode *root;
	int ret;

	DEBUG("XML data is %"PRIu64" bytes long.\n", (u64)res->size);

	if (resource_is_compressed(res)) {
		ERROR("XML data is supposed to be uncompressed!\n");
		ret = WIMLIB_ERR_XML;
		goto err0;
	}
	if (res->size < 2) {
		ERROR("XML data must be at least 2 bytes!\n");
		ret = WIMLIB_ERR_XML;
		goto err0;
	}

	xml_data = MALLOC(res->size + 2);
	if (!xml_data) {
		ret = WIMLIB_ERR_NOMEM;
		goto err0;
	}
	ret = read_full_resource(fp, res->size, res->size, res->offset, 
				 WIM_COMPRESSION_TYPE_NONE, xml_data);
	if (ret != 0)
		goto err1;

	xml_data[res->size] = 0;
	xml_data[res->size + 1] = 0;

	DEBUG("Parsing XML using libxml2 to create XML tree.\n");

	doc = xmlReadMemory(xml_data, res->size, "noname.xml", "UTF-16", 0);


	if (!doc) {
		ERROR("Failed to parse XML data!\n");
		ret = WIMLIB_ERR_XML;
		goto err1;
	}

	DEBUG("Constructing WIM information structure from XML tree.\n");

	root = xmlDocGetRootElement(doc);
	if (!root) {
		ERROR("Empty XML document!\n");
		ret = WIMLIB_ERR_XML;
		goto err2;
	}

	if (!node_is_element(root) || !node_name_is(root, "WIM")) {
		ERROR("Expected <WIM> for the root XML element! "
				"(found <%s>)\n", root->name);
		ret = WIMLIB_ERR_XML;
		goto err2;
	}

	ret = xml_read_wim_info(root, info_ret);
	if (ret != 0)
		goto err2;

	DEBUG("Freeing XML tree.\n");

	xmlFreeDoc(doc);
	xmlCleanupParser();
	*xml_data_ret = xml_data;
	return 0;
err2:
	xmlFreeDoc(doc);
err1:
	FREE(xml_data);
err0:
	xmlCleanupParser();
	return ret;
}

#define CHECK_RET  ({ 	if (ret < 0)  { \
				ERROR("Error writing XML data!\n"); \
				ret = WIMLIB_ERR_WRITE; \
				goto err2; \
			} })

/* 
 * Writes XML data to a WIM file.
 */
int write_xml_data(const struct wim_info *wim_info, int image, FILE *out)
{
	xmlBuffer     *buf;
	xmlTextWriter *writer;
	char          *utf16_str;
	int ret;
	off_t total_bytes;
	int num_images;
	int i;
	const xmlChar *content;
	size_t len;
	size_t utf16_len;
	size_t bytes_written;

	wimlib_assert(image == WIM_ALL_IMAGES || 
			(wim_info != NULL && image >= 1 && 
			 image <= wim_info->num_images));

	/* The contents of the <TOTALBYTES> element in the XML data, under the
	 * <WIM> element not the <IMAGE> element, is the size of the WIM file
	 * excluding the XML data and integrity table.  Which is the current
	 * offset, since the XML data goes at the end of the WIM file before the
	 * integrity table. */
	total_bytes = ftello(out);
	if (total_bytes == -1)
		return WIMLIB_ERR_WRITE;

	DEBUG("Creating XML buffer and text writer\n");
	buf = xmlBufferCreate();
	if (!buf) {
		ERROR("Failed to allocate XML buffer!\n");
		ret = WIMLIB_ERR_NOMEM;
		goto err0;
	}
	writer = xmlNewTextWriterMemory(buf, 0);
	if (!writer) {
		ERROR("Failed to allocate XML writer!\n");
		ret = WIMLIB_ERR_NOMEM;
		goto err1;
	}

	/* XXX */
	/* M$'s WIM files do not have XML declarations, so do not write one.
	 * I'm not sure how we can force the document to be written in UTF-16
	 * without calling xmlTextWriterStartDocument(), though, so currently it
	 * is composed in a buffer UTF-8, then converted to UTF-16. */
#if 0
	ret = xmlTextWriterStartDocument(writer, NULL, "UTF-16", NULL);
	CHECK_RET;
#endif

	DEBUG("Writing <WIM> element\n");
	ret = xmlTextWriterStartElement(writer, "WIM");
	CHECK_RET;

	ret = xmlTextWriterWriteFormatElement(writer, "TOTALBYTES", "%"PRIu64,
					      total_bytes);
	CHECK_RET;

	if (wim_info)
		num_images = wim_info->num_images;
	else
		num_images = 0;
	DEBUG("Writing %u <IMAGE> elements\n", num_images);

	for (i = 1; i <= num_images; i++) {
		if (image != WIM_ALL_IMAGES && i != image)
			continue;
		DEBUG("Writing <IMAGE> element for image %d\n", i);
		ret = xml_write_image_info(writer, &wim_info->images[i - 1]);
		CHECK_RET;
	}

	ret = xmlTextWriterEndElement(writer);
	CHECK_RET;

	ret = xmlTextWriterEndDocument(writer);
	CHECK_RET;

	DEBUG("Done composing XML document. Now converting to UTF-16 and "
			"writing it to the output file.\n");

	content = xmlBufferContent(buf);
	len = xmlBufferLength(buf);

	utf16_str = utf8_to_utf16(content, len, &utf16_len);
	if (!utf16_str) {
		ret = WIMLIB_ERR_NOMEM;
		goto err2;
	}

	if ((putc(0xff, out)) == EOF || (putc(0xfe, out) == EOF) || 
		((bytes_written = fwrite(utf16_str, 1, utf16_len, out))
				!= utf16_len)) {
		ERROR("Error writing XML data: %m\n");
		ret = WIMLIB_ERR_WRITE;
		goto err3;
	}

	DEBUG("Cleaning up.\n");

	ret = 0;
err3:
	FREE(utf16_str);
err2:
	xmlFreeTextWriter(writer);
err1:
	xmlBufferFree(buf);
err0:
	return ret;
}

/* Returns the name of the specified image. */
WIMLIBAPI const char *wimlib_get_image_name(const WIMStruct *w, int image)
{
	DEBUG("Getting the name of image %d\n", image);
	if (image < 1 || image > w->hdr.image_count)
		return NULL;

	return w->wim_info->images[image - 1].name;
}

/* Returns the description of the specified image. */
WIMLIBAPI const char *wimlib_get_image_description(const WIMStruct *w, 
						   int image)
{
	DEBUG("Getting the description of image %d\n", image);
	if (image < 1 || image > w->hdr.image_count)
		return NULL;

	return w->wim_info->images[image - 1].description;
}

/* Determines if an image name is already used by some image in the WIM. */
WIMLIBAPI bool wimlib_image_name_in_use(const WIMStruct *w, const char *name)
{
	int i;

	DEBUG("Checking to see if the image name `%s' is already "
						"in use\n", name);
	if (!name || !w->wim_info)
		return false;
	for (i = 1; i <= w->wim_info->num_images; i++)
		if (strcmp(w->wim_info->images[i - 1].name, name) == 0)
			return true;

	return false;
}

WIMLIBAPI int wimlib_extract_xml_data(WIMStruct *w, FILE *fp)
{
	DEBUG("Extracting the XML data.\n");
	if (fwrite(w->xml_data, 1, w->hdr.xml_res_entry.size, fp) != 
			w->hdr.xml_res_entry.size) {
		ERROR("Failed to extract XML data!\n");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/* Sets the name of an image in the WIM. */
WIMLIBAPI int wimlib_set_image_name(WIMStruct *w, int image, const char *name)
{
	char *p;
	int i;

	DEBUG("Setting the name of image %d to %s\n", image, name);

	if (!name || !*name) {
		ERROR("Must specify a non-empty string for the image "
				"name!\n");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	if (image < 1 || image > w->hdr.image_count) {
		ERROR("%d is not a valid image!\n", image);
		return WIMLIB_ERR_INVALID_IMAGE;
	}

	for (i = 1; i <= w->hdr.image_count; i++) {
		if (i == image)
			continue;
		if (strcmp(w->wim_info->images[i - 1].name, name) == 0) {
			ERROR("The name `%s' is already used for image %d!\n",
					name, i);
			return WIMLIB_ERR_IMAGE_NAME_COLLISION;
		}
	}

	p = STRDUP(name);
	if (!p) {
		ERROR("Out of memory!\n");
		return WIMLIB_ERR_NOMEM;
	}
	FREE(w->wim_info->images[image - 1].name);
	w->wim_info->images[image - 1].name = p;
	return 0;
}

/* Sets the description of an image in the WIM. */
WIMLIBAPI int wimlib_set_image_descripton(WIMStruct *w, int image, 
					  const char *description)
{
	char *p;

	DEBUG("Setting the description of image %d to %s\n", image, 
	      description);

	if (image < 1 || image > w->hdr.image_count) {
		ERROR("%d is not a valid image!\n", image);
		return WIMLIB_ERR_INVALID_IMAGE;
	}
	if (description) {
		p = STRDUP(description);
		if (!p) {
			ERROR("Out of memory!\n");
			return WIMLIB_ERR_NOMEM;
		}
	} else {
		p = NULL;
	}
	FREE(w->wim_info->images[image - 1].description);
	w->wim_info->images[image - 1].description = p;
	return 0;
}
