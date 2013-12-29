/**
 * @file wimlib.h
 * @brief External header for wimlib.
 *
 * This file contains extensive comments for generating documentation with
 * Doxygen.  The built HTML documentation can be viewed at
 * http://wimlib.sourceforge.net.  Make sure to see the <a
 * href="modules.html">Modules page</a> to make more sense of the declarations
 * in this header.
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

/**
 * @mainpage
 *
 * @section sec_intro Introduction
 *
 * This is the documentation for the library interface of wimlib 1.6.0, a C
 * library for creating, modifying, extracting, and mounting files in the
 * Windows Imaging Format.  This documentation is intended for developers only.
 * If you have installed wimlib and want to know how to use the @b wimlib-imagex
 * program, please see the README file or manual pages.
 *
 * @section sec_installing_and_compiling Installing and Compiling
 *
 * wimlib uses the GNU autotools, so, on UNIX-like systems, it should be easy to
 * install with <code>configure && make && sudo make install</code>; however,
 * please see the README for more information about installing it.
 *
 * To use wimlib in your program after installing it, include wimlib.h and link
 * your program with @c -lwim.
 *
 * As of wimlib 1.5.0, wimlib.h is also compatible with C++.
 *
 * Note: before calling any other function declared in wimlib.h,
 * wimlib_global_init() can (and in some cases, must) be called.  See its
 * documentation for more details.
 *
 * @section sec_basic_wim_handling_concepts Basic WIM handling concepts
 *
 * wimlib wraps up a WIM file in an opaque ::WIMStruct structure.   There are
 * two ways to create such a structure: wimlib_open_wim(), which opens a WIM
 * file and creates a ::WIMStruct representing it, and wimlib_create_new_wim(),
 * which creates a new ::WIMStruct that initially contains no images and does
 * not yet have a backing on-disk file.  See @ref G_creating_and_opening_wims
 * for more details.
 *
 * A WIM file, represented by a ::WIMStruct, contains zero or more images.
 * Images can be extracted (or "applied") using wimlib_extract_image(), added
 * (or "captured" or "appended") using wimlib_add_image(), deleted using
 * wimlib_delete_image(), exported using wimlib_export_image(), and updated or
 * modified using wimlib_update_image().  However, changes made to a WIM
 * represented by a ::WIMStruct have no persistent effect until the WIM is
 * actually written to an on-disk file.  This can be done using wimlib_write(),
 * but if the WIM was originally opened using wimlib_open_wim(), then
 * wimlib_overwrite() can be used instead.  See @ref G_extracting_wims, @ref
 * G_modifying_wims, and @ref G_writing_and_overwriting_wims for more details.
 *
 * Note that with this ::WIMStruct abstraction, performing many tasks on WIM
 * files is a multi-step process.  For example, to add, or "append" an image to
 * an existing stand-alone WIM file in a way similar to <b>wimlib-imagex
 * append</b>, you must call the following functions:
 *
 * 1. wimlib_open_wim()
 * 2. wimlib_add_image()
 * 3. wimlib_overwrite()
 *
 * This design is very much on purpose as it makes the library more useful in
 * general by allowing functions to be composed in different ways.  For example,
 * you can make multiple changes to a WIM and commit them all to the underlying
 * file in only one overwrite operation, which is more efficient.
 *
 * @section sec_cleaning_up Cleaning up
 *
 * After you are done with any ::WIMStruct, you can call wimlib_free() to free
 * all resources associated with it.  Also, when you are completely done with
 * using wimlib in your program, you can call wimlib_global_cleanup() to free
 * any other resources allocated by the library.
 *
 * @section sec_error_handling Error Handling
 *
 * Most functions in wimlib return 0 on success and a positive error code on
 * failure.  Use wimlib_get_error_string() to get a string that describes an
 * error code.  wimlib also can print error messages to standard error itself
 * when an error happens, and these may be more informative than the error code;
 * to enable this, call wimlib_set_print_errors().  Please note that this is for
 * convenience only, and some errors can occur without a message being printed.
 * Currently, error messages and strings (as well as all documentation, for that
 * matter) are only available in English.
 *
 * @section sec_encodings Locales and character encodings
 *
 * To support Windows as well as UNIX-like systems, wimlib's API typically takes
 * and returns strings of ::wimlib_tchar, which are in a platform-dependent
 * encoding.
 *
 * On Windows, each ::wimlib_tchar is 2 bytes and is the same as a "wchar_t",
 * and the encoding is UTF-16LE.
 *
 * On UNIX-like systems, each ::wimlib_tchar is 1 byte and is simply a "char",
 * and the encoding is the locale-dependent multibyte encoding.  I recommend you
 * set your locale to a UTF-8 capable locale to avoid any issues.  Also, by
 * default, wimlib on UNIX will assume the locale is UTF-8 capable unless you
 * call wimlib_global_init() after having set your desired locale.
 *
 * @section sec_advanced Additional information and features
 *
 *
 * @subsection subsec_mounting_wim_images Mounting WIM images
 *
 * See @ref G_mounting_wim_images.
 *
 * @subsection subsec_progress_functions Progress Messages
 *
 * See @ref G_progress.
 *
 * @subsection subsec_non_standalone_wims Non-standalone WIMs
 *
 * See @ref G_nonstandalone_wims.
 *
 * @subsection subsec_pipable_wims Pipable WIMs
 *
 * wimlib supports a special "pipable" WIM format which unfortunately is @b not
 * compatible with Microsoft's software.  To create a pipable WIM, call
 * wimlib_write(), wimlib_write_to_fd(), or wimlib_overwrite() with
 * ::WIMLIB_WRITE_FLAG_PIPABLE specified.  Pipable WIMs are pipable in both
 * directions, so wimlib_write_to_fd() can be used to write a pipable WIM to a
 * pipe, and wimlib_extract_image_from_pipe() can be used to apply an image from
 * a pipable WIM.  wimlib can also transparently open and operate on pipable WIM
 * s using a seekable file descriptor using the regular function calls (e.g.
 * wimlib_open_wim(), wimlib_extract_image()).
 *
 * See the documentation for the <b>--pipable</b> flag of <b>wimlib-imagex
 * capture</b> for more information about pipable WIMs.
 *
 * @subsection subsec_thread_safety Thread Safety
 *
 * wimlib is thread-safe, with the following exceptions:
 * - Different threads cannot operate on the same ::WIMStruct at the same time;
 *   they must use different ::WIMStruct's.
 * - You must call wimlib_global_init() in one thread before calling any other
 *   functions.
 * - wimlib_set_print_errors() and wimlib_set_memory_allocator() both apply globally.
 * - wimlib_mount_image(), while it can be used to mount multiple WIMs
 *   concurrently in the same process, will daemonize the entire process when it
 *   does so for the first time.  This includes changing the working directory
 *   to the root directory.
 *
 * @subsection subsec_limitations Limitations
 *
 * This section documents some technical limitations of wimlib not already
 * documented in the man page for @b wimlib-imagex.
 *
 * - The old WIM format from Vista pre-releases is not supported.
 * - wimlib does not provide a clone of the @b PEImg tool, or the @b Dism
 *   functionality other than that already present in @b ImageX, that allows you
 *   to make certain Windows-specific modifications to a Windows PE image, such
 *   as adding a driver or Windows component.  Such a tool could be implemented
 *   on top of wimlib.
 *
 * @subsection more_info More information
 *
 * You are advised to read the README as well as the manual pages for
 * <b>wimlib-imagex</b>, since not all relevant information is repeated here in
 * the API documentation.
 */

/** @defgroup G_general General
 *
 * @brief Declarations and structures shared across the library.
 */

/** @defgroup G_creating_and_opening_wims Creating and Opening WIMs
 *
 * @brief Create new WIMs and open existing WIMs.
 */

/** @defgroup G_wim_information Retrieving WIM information and directory listings
 *
 * @brief Retrieve information about a WIM or WIM image.
 */

/** @defgroup G_modifying_wims Modifying WIMs
 *
 * @brief Make changes to a WIM.
 *
 * @section sec_adding_images Capturing and adding WIM images
 *
 * As described in @ref sec_basic_wim_handling_concepts, capturing a new WIM or
 * appending an image to an existing WIM is a multi-step process, but at its
 * core is wimlib_add_image() or an equivalent function.  Normally,
 * wimlib_add_image() takes an on-disk directory tree and logically adds it to a
 * ::WIMStruct as a new image.  However, when supported by the build of the
 * library, there is also a special NTFS volume capture mode (entered when
 * ::WIMLIB_ADD_FLAG_NTFS is specified) that allows adding the image directly
 * from an unmounted NTFS volume.
 *
 * Another function, wimlib_add_image_multisource() is also provided.  It
 * generalizes wimlib_add_image() to allow combining multiple files or directory
 * trees into a single WIM image in a configurable way.
 *
 * For maximum customization of WIM image creation, it is also possible to add a
 * completely empty WIM image with wimlib_add_empty_image(), then update it with
 * wimlib_update_image().  (This is in fact what wimlib_add_image() and
 * wimlib_add_image_multisource() do internally.)
 *
 * Note that some details of how image addition/capture works are documented
 * more fully in the manual page for <b>wimlib-imagex capture</b>.
 *
 * @section sec_deleting_images Deleting WIM images
 *
 * wimlib_delete_image() can delete an image from a ::WIMStruct.  But as usual,
 * wimlib_write() or wimlib_overwrite() must be called to cause the changes to
 * be made persistent in an on-disk WIM file.
 *
 * @section sec_exporting_images Exporting WIM images
 *
 * wimlib_export_image() can copy, or "export", an image from one WIM to
 * another.
 *
 * @section sec_other_modifications Other modifications
 *
 * wimlib_update_image() can add, delete, and rename files in a WIM image.
 *
 * wimlib_set_image_name(), wimlib_set_image_descripton(), and
 * wimlib_set_image_flags() can change other image metadata.
 *
 * wimlib_set_wim_info() can change information about the WIM file itself, such
 * as the boot index.
 */

/** @defgroup G_extracting_wims Extracting WIMs
 *
 * @brief Extract files, directories, and images from a WIM.
 *
 * wimlib_extract_image() extracts, or "applies", an image from a WIM
 * (represented, as usual, by a ::WIMStruct).  This normally extracts the image
 * to a directory, but when supported by the build of the library there is also
 * a special NTFS volume extraction mode (entered when
 * ::WIMLIB_EXTRACT_FLAG_NTFS is specified) that allows extracting a WIM image
 * directly to an unmounted NTFS volume.  Various other flags allow further
 * customization of image extraction.
 *
 * Another function, wimlib_extract_files(), is also provided.  It can extract
 * certain files or directories from a WIM image, instead of a full image.
 *
 * wimlib_extract_paths() and wimlib_extract_pathlist() allow extracting a set
 * of paths from a WIM image in a manner that may be easier to use than
 * wimlib_extract_files(), and also allow wildcard patterns.
 *
 * wimlib_extract_image_from_pipe() allows an image to be extracted from a
 * pipable WIM sent over a pipe; see @ref subsec_pipable_wims.
 *
 * Note that some details of how image extraction/application works are
 * documented more fully in the manual pages for <b>wimlib-imagex apply</b> and
 * <b>wimlib-imagex extract</b>.
 */

/** @defgroup G_mounting_wim_images Mounting WIM images
 *
 * @brief Mount and unmount WIM images.
 *
 * On UNIX-like systems supporting FUSE (such as Linux), wimlib supports
 * mounting images from WIM files either read-only or read-write.  To mount an
 * image, call wimlib_mount_image().  To unmount an image, call
 * wimlib_unmount_image().  Mounting can be done without root privileges because
 * it is implemented using FUSE (Filesystem in Userspace).  If wimlib is
 * compiled with the <code>--without-fuse</code> flag, these functions will be
 * available but will fail with ::WIMLIB_ERR_UNSUPPORTED.  Note that mounting an
 * image read-write is an alternative to calling wimlib_update_image().
 */

/** @defgroup G_progress Progress Messages
 *
 * @brief Track the progress of long WIM operations.
 *
 * When operating on large archives, operations such as extraction will
 * naturally take a while to complete.  Because of this and to improve the
 * potential user-friendliness of library clients, a number of functions take a
 * pointer to a progress function of type ::wimlib_progress_func_t.  This
 * function will be called periodically during the WIM operation(s) to report on
 * the progress of the operation (for example, how many bytes have been written
 * so far).
 */

/** @defgroup G_writing_and_overwriting_wims Writing and Overwriting WIMs
 *
 * @brief Write and overwrite on-disk WIM files.
 *
 * As described in @ref sec_basic_wim_handling_concepts, these functions are
 * critical to the design of the library as they allow new or modified WIMs to
 * actually be written to on-disk files.  Generally, wimlib_write() is the
 * function you need to call to write a new WIM file, and wimlib_overwrite() is
 * the function you need to call to persistently update an existing WIM file.
 */

/** @defgroup G_nonstandalone_wims Creating and handling non-standalone WIMs
 *
 * @brief Create and handle non-standalone WIMs, such as split and delta WIMs.
 *
 * Normally, ::WIMStruct represents a WIM file, but there's a bit more to it
 * than that.  Normally, WIM files are "standalone".  However, WIM files can
 * also be arranged in non-standalone ways, such as a set of on-disk files that
 * together form a single "split WIM" or "delta WIM".  Such arrangements are
 * fully supported by wimlib.  However, as a result, in such cases a ::WIMStruct
 * created from one of these on-disk files initially only partially represents
 * the full WIM and needs to, in effect, be logically combined with other
 * ::WIMStruct's before performing certain operations, such as extracting files
 * with wimlib_extract_image() or wimlib_extract_files().  This is done by
 * calling wimlib_reference_resource_files() or wimlib_reference_resources().
 *
 * wimlib_write() can create delta WIMs as well as standalone WIMs, but a
 * specialized function (wimlib_split()) is needed to create a split WIM.
 */

#ifndef _WIMLIB_H
#define _WIMLIB_H

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>

/** @ingroup G_general
 * @{ */

/** Major version of the library (for example, the 1 in 1.2.5).  */
#define WIMLIB_MAJOR_VERSION 1

/** Minor version of the library (for example, the 2 in 1.2.5). */
#define WIMLIB_MINOR_VERSION 6

/** Patch version of the library (for example, the 5 in 1.2.5). */
#define WIMLIB_PATCH_VERSION 0

#ifdef __cplusplus
extern "C" {
#endif

/** @} */
/** @ingroup G_general
 * @{ */

/**
 * Opaque structure that represents a WIM file.  This is an in-memory structure
 * and need not correspond to a specific on-disk file.  However, a ::WIMStruct
 * obtained from wimlib_open_wim() depends on the underlying on-disk WIM file
 * continuing to exist so that data can be read from it as needed.
 *
 * Most functions in this library will work the same way regardless of whether a
 * given ::WIMStruct was obtained through wimlib_open_wim() or
 * wimlib_create_new_wim().  Exceptions are documented.
 *
 * Use wimlib_write() or wimlib_overwrite() to actually write an on-disk WIM
 * file from a ::WIMStruct.
 *
 * See @ref sec_basic_wim_handling_concepts for more information.
 */
#ifndef WIMLIB_WIMSTRUCT_DECLARED
typedef struct WIMStruct WIMStruct;
#define WIMLIB_WIMSTRUCT_DECLARED
#endif

#ifdef __WIN32__
typedef wchar_t wimlib_tchar;
#else
/** See @ref sec_encodings */
typedef char wimlib_tchar;
#endif

#ifdef __WIN32__
/** Path separator for WIM paths passed back to progress callbacks. */
#  define WIMLIB_WIM_PATH_SEPARATOR '\\'
#  define WIMLIB_WIM_PATH_SEPARATOR_STRING L"\\"
#else
/** Path separator for WIM paths passed back to progress callbacks. */
#  define WIMLIB_WIM_PATH_SEPARATOR '/'
#  define WIMLIB_WIM_PATH_SEPARATOR_STRING "/"
#endif

#ifdef __GNUC__
#  define _wimlib_deprecated __attribute__((deprecated))
#else
#  define _wimlib_deprecated
#endif

#define WIMLIB_GUID_LEN 16

/**
 * Specifies the compression type of a WIM file.
 */
enum wimlib_compression_type {
	/** An invalid compression type. */
	WIMLIB_COMPRESSION_TYPE_INVALID = -1,

	/** The WIM does not include any compressed resources. */
	WIMLIB_COMPRESSION_TYPE_NONE = 0,

	/** Compressed resources in the WIM use LZX compression. */
	WIMLIB_COMPRESSION_TYPE_LZX = 1,

	/** Compressed resources in the WIM use XPRESS compression. */
	WIMLIB_COMPRESSION_TYPE_XPRESS = 2,

	/** Compressed resources in the WIM use LZMS compression.  Note: LZMS
	 * compression is only compatible with wimlib v1.6.0 and later and with
	 * WIMGAPI Windows 8 and later (and some restrictions apply on the
	 * latter).  */
	WIMLIB_COMPRESSION_TYPE_LZMS = 3,
};

/** @} */
/** @ingroup G_progress
 * @{ */

/** Possible values of the first parameter to the user-supplied
 * ::wimlib_progress_func_t progress function */
enum wimlib_progress_msg {

	/** A WIM image is about to be extracted.  @p info will point to
	 * ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN = 0,

	/** One or more file or directory trees within a WIM image (not the full
	 * image) is about to be extracted.  @p info will point to
	 * ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN,

	/** The directory structure of the WIM image is about to be extracted.
	 * @p info will point to ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,

	/** The directory structure of the WIM image has been successfully
	 * extracted.  @p info will point to ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,

	/** File data is currently being extracted.  @p info will point to
	 * ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS,

	/** Starting to read a new part of a split pipable WIM over the pipe.
	 * @p info will point to ::wimlib_progress_info.extract.  */
	WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN,

	/** All the WIM files and directories have been extracted, and
	 * timestamps are about to be applied.  @p info will point to
	 * ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS,

	/** A WIM image has been successfully extracted.  @p info will point to
	 * ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END,

	/** A file or directory tree within a WIM image (not the full image) has
	 * been successfully extracted.  @p info will point to
	 * ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END,

	/** The directory or NTFS volume is about to be scanned to build a tree
	 * of WIM dentries in-memory.  @p info will point to
	 * ::wimlib_progress_info.scan. */
	WIMLIB_PROGRESS_MSG_SCAN_BEGIN,

	/** A directory or file is being scanned.  @p info will point to
	 * ::wimlib_progress_info.scan, and its @p cur_path member will be
	 * valid.  This message is only sent if ::WIMLIB_ADD_FLAG_VERBOSE
	 * is passed to wimlib_add_image(). */
	WIMLIB_PROGRESS_MSG_SCAN_DENTRY,

	/** The directory or NTFS volume has been successfully scanned, and a
	 * tree of WIM dentries has been built in-memory. @p info will point to
	 * ::wimlib_progress_info.scan. */
	WIMLIB_PROGRESS_MSG_SCAN_END,

	/**
	 * File resources are currently being written to the WIM.
	 * @p info will point to ::wimlib_progress_info.write_streams. */
	WIMLIB_PROGRESS_MSG_WRITE_STREAMS,

	/**
	 * The metadata resource for each image is about to be written to the
	 * WIM. @p info will not be valid. */
	WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN,

	/**
	 * The metadata resource for each image has successfully been writen to
	 * the WIM.  @p info will not be valid. */
	WIMLIB_PROGRESS_MSG_WRITE_METADATA_END,

	/**
	 * The temporary file has successfully been renamed to the original WIM
	 * file.  Only happens when wimlib_overwrite() is called and the
	 * overwrite is not done in-place.
	 * @p info will point to ::wimlib_progress_info.rename. */
	WIMLIB_PROGRESS_MSG_RENAME,

	/** The contents of the WIM are being checked against the integrity
	 * table.  Only happens when wimlib_open_wim() is called with the
	 * ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY flag.  @p info will point to
	 * ::wimlib_progress_info.integrity. */
	WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY,

	/** An integrity table is being calculated for the WIM being written.
	 * Only happens when wimlib_write() or wimlib_overwrite() is called with
	 * the ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY flag.  @p info will point to
	 * ::wimlib_progress_info.integrity. */
	WIMLIB_PROGRESS_MSG_CALC_INTEGRITY,

	/** Reserved.  */
	WIMLIB_PROGRESS_MSG_RESERVED,

	/** A wimlib_split() operation is in progress, and a new split part is
	 * about to be started.  @p info will point to
	 * ::wimlib_progress_info.split. */
	WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART,

	/** A wimlib_split() operation is in progress, and a split part has been
	 * finished. @p info will point to ::wimlib_progress_info.split. */
	WIMLIB_PROGRESS_MSG_SPLIT_END_PART,

	/**
	 * A WIM update command is just about to be executed; @p info will point
	 * to ::wimlib_progress_info.update.
	 */
	WIMLIB_PROGRESS_MSG_UPDATE_BEGIN_COMMAND,

	/**
	 * A WIM update command has just been executed; @p info will point to
	 * ::wimlib_progress_info.update.
	 */
	WIMLIB_PROGRESS_MSG_UPDATE_END_COMMAND,

};

/** A pointer to this union is passed to the user-supplied
 * ::wimlib_progress_func_t progress function.  One (or none) of the structures
 * contained in this union will be applicable for the operation
 * (::wimlib_progress_msg) indicated in the first argument to the progress
 * function. */
union wimlib_progress_info {

	/* N.B. I wanted these to be anonymous structs, but Doxygen won't
	 * document them if they aren't given a name... */

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_WRITE_STREAMS. */
	struct wimlib_progress_info_write_streams {
		/** Number of bytes that are going to be written for all the
		 * streams combined.  This is the amount in uncompressed data.
		 * (The actual number of bytes will be less if the data is being
		 * written compressed.) */
		uint64_t total_bytes;

		/** Number of streams that are going to be written. */
		uint64_t total_streams;

		/** Number of uncompressed bytes that have been written so far.
		 * Will be 0 initially, and equal to @p total_bytes at the end.
		 * */
		uint64_t completed_bytes;

		/** Number of streams that have been written.  Will be 0
		 * initially, and equal to @p total_streams at the end. */
		uint64_t completed_streams;

		/** Number of threads that are being used to compress resources
		 * (if applicable).  */
		unsigned num_threads;

		/** The compression type being used to write the streams; either
		 * ::WIMLIB_COMPRESSION_TYPE_NONE,
		 * ::WIMLIB_COMPRESSION_TYPE_XPRESS, or
		 * ::WIMLIB_COMPRESSION_TYPE_LZX. */
		int	 compression_type;

		/** Number of split WIM parts from which streams are being
		 * written (may be 0 if irrelevant).  */
		unsigned total_parts;

		/** Number of split WIM parts from which streams have been
		 * written (may be 0 if irrelevant).  */
		unsigned completed_parts;
	} write_streams;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_SCAN_BEGIN,
	 * ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY, and
	 * ::WIMLIB_PROGRESS_MSG_SCAN_END.  */
	struct wimlib_progress_info_scan {
		/** Top-level directory being scanned; or, when capturing a NTFS
		 * volume with ::WIMLIB_ADD_FLAG_NTFS, this is instead the path
		 * to the file or block device that contains the NTFS volume
		 * being scanned.  */
		const wimlib_tchar *source;

		/** Path to the file (or directory) that has been scanned, valid
		 * on ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY.  When capturing a NTFS
		 * volume with ::WIMLIB_ADD_FLAG_NTFS, this path will be
		 * relative to the root of the NTFS volume.  */
		const wimlib_tchar *cur_path;

		/** Dentry scan status, valid on
		 * ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY.  */
		enum {
			/** The file looks okay and will be captured.  */
			WIMLIB_SCAN_DENTRY_OK = 0,

			/** File is being excluded from capture due to the
			 * capture configuration.  */
			WIMLIB_SCAN_DENTRY_EXCLUDED,

			/** File is being excluded from capture due to being
			 * unsupported (e.g. an encrypted or device file).  */
			WIMLIB_SCAN_DENTRY_UNSUPPORTED,

			/** The file is an absolute symbolic link or junction
			 * point and it is being excluded from capture because
			 * it points outside of the capture directory and
			 * reparse-point fixups are enabled.  (Reparse point
			 * fixups can be disabled by using the flag
			 * ::WIMLIB_ADD_FLAG_NORPFIX.)  */
			WIMLIB_SCAN_DENTRY_EXCLUDED_SYMLINK,
		} status;

		union {
			/** Target path in the WIM image.  Only valid on
			 * messages ::WIMLIB_PROGRESS_MSG_SCAN_BEGIN and
			 * ::WIMLIB_PROGRESS_MSG_SCAN_END.  If capturing a full
			 * image, this will be the empty string; otherwise it
			 * will name the place in the WIM image at which the
			 * directory tree is being added.  */
			const wimlib_tchar *wim_target_path;

			/** For ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY and a status
			 * of ::WIMLIB_SCAN_DENTRY_EXCLUDED_SYMLINK, this is the
			 * target of the absolute symbolic link or junction
			 * point.  */
			const wimlib_tchar *symlink_target;
		};

		/** Number of directories scanned so far, including the root
		 * directory but excluding any unsupported/excluded directories.
		 *
		 * Details: On Windows and in NTFS capture mode, a reparse point
		 * counts as a directory if and only if it has
		 * FILE_ATTRIBUTE_DIRECTORY set.  Otherwise, a symbolic link
		 * counts as a directory if and only if when fully dereferenced
		 * it points to an accessible directory.  If a file has multiple
		 * names (hard links), it is only counted one time.  */
		uint64_t num_dirs_scanned;

		/** Number of non-directories scanned so far, excluding any
		 * unsupported/excluded files.
		 *
		 * Details: On Windows and in NTFS capture mode, a reparse point
		 * counts as a non-directory if and only if it does not have
		 * FILE_ATTRIBUTE_DIRECTORY set.  Otherwise, a symbolic link
		 * counts as a non-directory if and only if when fully
		 * dereferenced it points to a non-directory or its target is
		 * inaccessible.  If a file has multiple names (hard links), it
		 * is only counted one time.  */
		uint64_t num_nondirs_scanned;

		/** Number of bytes of file data that have been detected so far.
		 *
		 * Details: This data may not actually have been read yet, and
		 * it will not actually be written to the WIM file until
		 * wimlib_write() or wimlib_overwrite() has been called.  Data
		 * from excluded files is not counted.  This number includes
		 * default file contents as well as named data streams and
		 * reparse point data.  The size of reparse point data is
		 * tallied after any reparse-point fixups, and in the case of
		 * capturing a symbolic link on a UNIX-like system, the creation
		 * of the reparse point data itself.  If a file has multiple
		 * names (hard links), its size(s) are only counted one time.
		 * On Windows, encrypted files have their encrypted size
		 * counted, not their unencrypted size; however, compressed
		 * files have their uncompressed size counted.  */
		uint64_t num_bytes_scanned;
	} scan;

	/** Valid on messages
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END, and
	 * ::WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS.
	 *
	 * Note: most of the time of an extraction operation will be spent
	 * extracting streams, and the application will receive
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS during this time.  Using @p
	 * completed_bytes and @p total_bytes, the application can calculate a
	 * percentage complete.  However, note that this message does not, in
	 * general, actually provide information about which "file" is currently
	 * being extracted.  This is because wimlib, by default, extracts the
	 * individual data streams in whichever order it determines to be the
	 * most efficient.  */
	struct wimlib_progress_info_extract {
		/** Number of the image from which files are being extracted
		 * (1-based).  */
		int image;

		/** Extraction flags being used.  */
		int extract_flags;

		/** Full path to the WIM file from which files are being
		 * extracted, or @c NULL if the WIMStruct has no associated
		 * on-disk file.  */
		const wimlib_tchar *wimfile_name;

		/** Name of the image from which files are being extracted, or
		 * the empty string if the image is unnamed.  */
		const wimlib_tchar *image_name;

		/** Path to the directory or NTFS volume to which the files are
		 * being extracted.  */
		const wimlib_tchar *target;

		/** Reserved.  */
		const wimlib_tchar *reserved;

		/** Number of bytes of uncompressed data that will be extracted.
		 * If a file has multiple names (hard links), its size (or
		 * sizes, in the case of named data streams) is only counted one
		 * time.  For "reparse points" and symbolic links, the size to
		 * be extracted is the size of the reparse data buffer.
		 *
		 * This number will stay constant throughout the extraction.  */
		uint64_t total_bytes;

		/** Number of bytes of uncompressed data that have been
		 * extracted so far.  This initially be 0 and will equal to @p
		 * total_bytes at the end of the extraction.  */
		uint64_t completed_bytes;

		/** Number of (not necessarily unique) streams that will be
		 * extracted.  This may be more or less than the number of
		 * "files" to be extracted due to hard links as well as
		 * potentially multiple streams per file (named data streams).
		 * A "stream" may be the default contents of a file, a named
		 * data stream, or a reparse data buffer.  */
		uint64_t num_streams;

		/** When extracting files using wimlib_extract_files(), this
		 * will be the path within the WIM image to the file or
		 * directory tree currently being extracted.  Otherwise, this
		 * will be the empty string.  */
		const wimlib_tchar *extract_root_wim_source_path;

		/** Currently only used for
		 * ::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN.  */
		unsigned part_number;

		/** Currently only used for
		 * ::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN.  */
		unsigned total_parts;

		/** Currently only used for
		 * ::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN.  */
		uint8_t guid[WIMLIB_GUID_LEN];
	} extract;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_RENAME. */
	struct wimlib_progress_info_rename {
		/** Name of the temporary file that the WIM was written to. */
		const wimlib_tchar *from;

		/** Name of the original WIM file to which the temporary file is
		 * being renamed. */
		const wimlib_tchar *to;
	} rename;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_UPDATE_BEGIN_COMMAND and
	 * ::WIMLIB_PROGRESS_MSG_UPDATE_END_COMMAND. */
	struct wimlib_progress_info_update {
		/** Pointer to the update command that will be executed or has
		 * just been executed. */
		const struct wimlib_update_command *command;

		/** Number of update commands that have been completed so far.
		 */
		size_t completed_commands;

		/** Number of update commands that are being executed as part of
		 * this call to wimlib_update_image(). */
		size_t total_commands;
	} update;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY and
	 * ::WIMLIB_PROGRESS_MSG_CALC_INTEGRITY. */
	struct wimlib_progress_info_integrity {
		/** Number of bytes from the end of the WIM header to the end of
		 * the lookup table (the area that is covered by the SHA1
		 * integrity checks.) */
		uint64_t total_bytes;

		/** Number of bytes that have been SHA1-summed so far.  Will be
		 * 0 initially, and equal @p total_bytes at the end. */
		uint64_t completed_bytes;

		/** Number of chunks that the checksummed region is divided
		 * into. */
		uint32_t total_chunks;

		/** Number of chunks that have been SHA1-summed so far.   Will
		 * be 0 initially, and equal to @p total_chunks at the end. */
		uint32_t completed_chunks;

		/** Size of the chunks used for the integrity calculation. */
		uint32_t chunk_size;

		/** Filename of the WIM (only valid if the message is
		 * ::WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY). */
		const wimlib_tchar *filename;
	} integrity;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART and
	 * ::WIMLIB_PROGRESS_MSG_SPLIT_END_PART. */
	struct wimlib_progress_info_split {
		/** Total size of the original WIM's file and metadata resources
		 * (compressed). */
		uint64_t total_bytes;

		/** Number of bytes of file and metadata resources that have
		 * been copied out of the original WIM so far.  Will be 0
		 * initially, and equal to @p total_bytes at the end. */
		uint64_t completed_bytes;

		/** Number of the split WIM part that is about to be started
		 * (::WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART) or has just been
		 * finished (::WIMLIB_PROGRESS_MSG_SPLIT_END_PART). */
		unsigned cur_part_number;

		/** Total number of split WIM parts that are being written.  */
		unsigned total_parts;

		/** Name of the split WIM part that is about to be started
		 * (::WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART) or has just been
		 * finished (::WIMLIB_PROGRESS_MSG_SPLIT_END_PART). */
		const wimlib_tchar *part_name;
	} split;
};

/** A user-supplied function that will be called periodically during certain WIM
 * operations.  The first argument will be the type of operation that is being
 * performed or is about to be started or has been completed.  The second
 * argument will be a pointer to one of a number of structures depending on the
 * first argument.  It may be @c NULL for some message types.
 *
 * The return value of the progress function is currently ignored, but it may do
 * something in the future.  (Set it to 0 for now.)
 */
typedef int (*wimlib_progress_func_t)(enum wimlib_progress_msg msg_type,
				      const union wimlib_progress_info *info);

/** @} */
/** @ingroup G_modifying_wims
 * @{ */

/** An array of these structures is passed to wimlib_add_image_multisource() to
 * specify the sources from which to create a WIM image. */
struct wimlib_capture_source {
	/** Absolute or relative path to a file or directory on the external
	 * filesystem to be included in the WIM image. */
	wimlib_tchar *fs_source_path;

	/** Destination path in the WIM image.  Leading and trailing slashes are
	 * ignored.  The empty string or @c NULL means the root directory of the
	 * WIM image. */
	wimlib_tchar *wim_target_path;

	/** Reserved; set to 0. */
	long reserved;
};

/** Structure that specifies a list of path patterns. */
struct wimlib_pattern_list {
	/** Array of patterns.  The patterns may be modified by library code,
	 * but the @p pats pointer itself will not.  See the man page for
	 * <b>wimlib-imagex capture</b> for more information about allowed
	 * patterns. */
	wimlib_tchar **pats;

	/** Number of patterns in the @p pats array. */
	size_t num_pats;

	/** Ignored; may be used by the calling code. */
	size_t num_allocated_pats;
};

/** A structure that contains lists of wildcards that match paths to treat
 * specially when capturing a WIM image. */
struct wimlib_capture_config {
	/** Paths matching any pattern this list are excluded from being
	 * captured, except if the same path appears in @p
	 * exclusion_exception_pats. */
	struct wimlib_pattern_list exclusion_pats;

	/** Paths matching any pattern in this list are never excluded from
	 * being captured. */
	struct wimlib_pattern_list exclusion_exception_pats;

	/** Reserved for future capture configuration options. */
	struct wimlib_pattern_list reserved1;

	/** Reserved for future capture configuration options. */
	struct wimlib_pattern_list reserved2;

	/** Library internal use only. */
	wimlib_tchar *_prefix;

	/** Library internal use only. */
	size_t _prefix_num_tchars;
};

/** Set or unset the WIM header flag that marks it read-only
 * (WIM_HDR_FLAG_READONLY in Microsoft's documentation), based on the
 * ::wimlib_wim_info.is_marked_readonly member of the @p info parameter.  This
 * is distinct from basic file permissions; this flag can be set on a WIM file
 * that is physically writable.  If this flag is set, all further operations to
 * modify the WIM will fail, except calling wimlib_overwrite() with
 * ::WIMLIB_WRITE_FLAG_IGNORE_READONLY_FLAG specified, which is a loophole that
 * allows you to set this flag persistently on the underlying WIM file.
 */
#define WIMLIB_CHANGE_READONLY_FLAG		0x00000001

/** Set the GUID (globally unique identifier) of the WIM file to the value
 * specified in ::wimlib_wim_info.guid of the @p info parameter. */
#define WIMLIB_CHANGE_GUID			0x00000002

/** Change the bootable image of the WIM to the value specified in
 * ::wimlib_wim_info.boot_index of the @p info parameter.  */
#define WIMLIB_CHANGE_BOOT_INDEX		0x00000004

/** Change the WIM_HDR_FLAG_RP_FIX flag of the WIM file to the value specified
 * in ::wimlib_wim_info.has_rpfix of the @p info parameter.  This flag generally
 * indicates whether an image in the WIM has been captured with reparse-point
 * fixups enabled.  wimlib also treats this flag as specifying whether to do
 * reparse-point fixups by default when capturing or applying WIM images.  */
#define WIMLIB_CHANGE_RPFIX_FLAG		0x00000008

/** @} */
/** @ingroup G_wim_information
 * @{ */

/** General information about a WIM file. */
struct wimlib_wim_info {

	/** Globally unique identifier for the WIM file.  Note: all parts of a
	 * split WIM should have an identical value in this field.  */
	uint8_t  guid[WIMLIB_GUID_LEN];

	/** Number of images in the WIM.  */
	uint32_t image_count;

	/** 1-based index of the bootable image in the WIM, or 0 if no image is
	 * bootable.  */
	uint32_t boot_index;

	/** Version of the WIM file.  */
	uint32_t wim_version;

	/** Chunk size used for compression.  */
	uint32_t chunk_size;

	/** For split WIMs, the 1-based index of this part within the split WIM;
	 * otherwise 1.  */
	uint16_t part_number;

	/** For split WIMs, the total number of parts in the split WIM;
	 * otherwise 1.  */
	uint16_t total_parts;

	/** One of the ::wimlib_compression_type values that specifies the
	 * method used to compress resources in the WIM.  */
	int32_t  compression_type;

	/** Size of the WIM file in bytes, excluding the XML data and integrity
	 * table.  */
	uint64_t total_bytes;

	/** 1 if the WIM has an integrity table.  Note: if the ::WIMStruct was
	 * created via wimlib_create_new_wim() rather than wimlib_open_wim(),
	 * this will always be 0, even if the ::WIMStruct was written to
	 * somewhere by calling wimlib_write() with the
	 * ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY flag specified. */
	uint32_t has_integrity_table : 1;

	/** 1 if the ::WIMStruct was created via wimlib_open_wim() rather than
	 * wimlib_create_new_wim(). */
	uint32_t opened_from_file : 1;

	/** 1 if the WIM is considered readonly for any reason. */
	uint32_t is_readonly : 1;

	/** 1 if reparse-point fixups are supposedly enabled for one or more
	 * images in the WIM.  */
	uint32_t has_rpfix : 1;

	/** 1 if the WIM is marked as read-only.  */
	uint32_t is_marked_readonly : 1;

	/** 1 if the WIM is part of a spanned set.  */
	uint32_t spanned : 1;

	uint32_t write_in_progress : 1;
	uint32_t metadata_only : 1;
	uint32_t resource_only : 1;

	/** 1 if the WIM is pipable (see ::WIMLIB_WRITE_FLAG_PIPABLE).  */
	uint32_t pipable : 1;
	uint32_t reserved_flags : 22;
	uint32_t reserved[9];
};

/** Information about a unique stream in the WIM file.  (A stream is the same
 * thing as a "resource", except in the case of packed resources.)  */
struct wimlib_resource_entry {
	/** Uncompressed size of the stream in bytes. */
	uint64_t uncompressed_size;

	/** Compressed size of the stream in bytes.  This will be the same as @p
	 * uncompressed_size if the stream is uncompressed.  Or, if @p
	 * is_packed_streams is 1, this will be 0.  */
	uint64_t compressed_size;

	/** Offset, in bytes, of this stream from the start of the WIM file.  Or
	 * if @p packed is 1, then this is actually the offset at which this
	 * stream begins in the uncompressed contents of the packed resource.
	 */
	uint64_t offset;

	/** SHA1 message digest of the stream's uncompressed contents.  */
	uint8_t sha1_hash[20];

	/** Which part number of the split WIM this stream is in.  This should
	 * be the same as the part number provided by wimlib_get_wim_info().  */
	uint32_t part_number;

	/** Number of times this stream is referenced over all WIM images.  */
	uint32_t reference_count;

	/** 1 if this stream is compressed.  */
	uint32_t is_compressed : 1;

	/** 1 if this stream is a metadata resource rather than a file resource.
	 * */
	uint32_t is_metadata : 1;

	uint32_t is_free : 1;
	uint32_t is_spanned : 1;

	/** 1 if this stream was not found in the lookup table of the
	 * ::WIMStruct.  This normally implies a missing call to
	 * wimlib_reference_resource_files() or wimlib_reference_resources().
	 * */
	uint32_t is_missing : 1;

	/** 1 if this stream is located in a packed resource which may contain
	 * other streams (all compressed together) as well.  */
	uint32_t packed : 1;

	uint32_t reserved_flags : 26;

	/** If @p packed is 1, then this will specify the offset of the packed
	 * resource in the WIM.  */
	uint64_t raw_resource_offset_in_wim;

	/** If @p is_packed_streams is 1, then this will specify the compressed
	 * size of the packed resource in the WIM.  */
	uint64_t raw_resource_compressed_size;

	uint64_t reserved[2];
};

/** A stream of a file in the WIM.  */
struct wimlib_stream_entry {
	/** Name of the stream, or NULL if the stream is unnamed. */
	const wimlib_tchar *stream_name;
	/** Location, size, etc. of the stream within the WIM file.  */
	struct wimlib_resource_entry resource;
	uint64_t reserved[4];
};

/** Structure passed to the wimlib_iterate_dir_tree() callback function.
 * Roughly, the information about a "file" in the WIM--- but really a directory
 * entry ("dentry") because hard links are allowed.  The hard_link_group_id
 * field can be used to distinguish actual file inodes.  */
struct wimlib_dir_entry {
	/** Name of the file, or NULL if this file is unnamed (only possible for
	 * the root directory) */
	const wimlib_tchar *filename;

	/** 8.3 DOS name of this file, or NULL if this file has no such name.
	 * */
	const wimlib_tchar *dos_name;

	/** Full path to this file within the WIM image.  */
	const wimlib_tchar *full_path;

	/** Depth of this directory entry, where 0 is the root, 1 is the root's
	 * children, ..., etc. */
	size_t depth;

	/** Pointer to the security descriptor for this file, in Windows
	 * SECURITY_DESCRIPTOR_RELATIVE format, or NULL if this file has no
	 * security descriptor.  */
	const char *security_descriptor;

	/** Length of the above security descriptor.  */
	size_t security_descriptor_size;

#define WIMLIB_FILE_ATTRIBUTE_READONLY            0x00000001
#define WIMLIB_FILE_ATTRIBUTE_HIDDEN              0x00000002
#define WIMLIB_FILE_ATTRIBUTE_SYSTEM              0x00000004
#define WIMLIB_FILE_ATTRIBUTE_DIRECTORY           0x00000010
#define WIMLIB_FILE_ATTRIBUTE_ARCHIVE             0x00000020
#define WIMLIB_FILE_ATTRIBUTE_DEVICE              0x00000040
#define WIMLIB_FILE_ATTRIBUTE_NORMAL              0x00000080
#define WIMLIB_FILE_ATTRIBUTE_TEMPORARY           0x00000100
#define WIMLIB_FILE_ATTRIBUTE_SPARSE_FILE         0x00000200
#define WIMLIB_FILE_ATTRIBUTE_REPARSE_POINT       0x00000400
#define WIMLIB_FILE_ATTRIBUTE_COMPRESSED          0x00000800
#define WIMLIB_FILE_ATTRIBUTE_OFFLINE             0x00001000
#define WIMLIB_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define WIMLIB_FILE_ATTRIBUTE_ENCRYPTED           0x00004000
#define WIMLIB_FILE_ATTRIBUTE_VIRTUAL             0x00010000
	/** File attributes, such as whether the file is a directory or not.
	 * These are the "standard" Windows FILE_ATTRIBUTE_* values, although in
	 * wimlib.h they are defined as WIMLIB_FILE_ATTRIBUTE_* for convenience
	 * on other platforms.  */
	uint32_t attributes;

#define WIMLIB_REPARSE_TAG_RESERVED_ZERO	0x00000000
#define WIMLIB_REPARSE_TAG_RESERVED_ONE		0x00000001
#define WIMLIB_REPARSE_TAG_MOUNT_POINT		0xA0000003
#define WIMLIB_REPARSE_TAG_HSM			0xC0000004
#define WIMLIB_REPARSE_TAG_HSM2			0x80000006
#define WIMLIB_REPARSE_TAG_DRIVER_EXTENDER	0x80000005
#define WIMLIB_REPARSE_TAG_SIS			0x80000007
#define WIMLIB_REPARSE_TAG_DFS			0x8000000A
#define WIMLIB_REPARSE_TAG_DFSR			0x80000012
#define WIMLIB_REPARSE_TAG_FILTER_MANAGER	0x8000000B
#define WIMLIB_REPARSE_TAG_SYMLINK		0xA000000C
	/** If the file is a reparse point (FILE_ATTRIBUTE_DIRECTORY set in the
	 * attributes), this will give the reparse tag.  This tells you whether
	 * the reparse point is a symbolic link, junction point, or some other,
	 * more unusual kind of reparse point.  */
	uint32_t reparse_tag;

	/*  Number of (hard) links to this file.  */
	uint32_t num_links;

	/** Number of named data streams that this file has.  Normally 0.  */
	uint32_t num_named_streams;

	/** Roughly, the inode number of this file.  However, it may be 0 if
	 * @p num_links == 1.  */
	uint64_t hard_link_group_id;

	/** Time this file was created.  */
	struct timespec creation_time;

	/** Time this file was last written to.  */
	struct timespec last_write_time;

	/** Time this file was last accessed.  */
	struct timespec last_access_time;
	uint64_t reserved[16];

	/** Array of streams that make up this file.  The first entry will
	 * always exist and will correspond to the unnamed data stream (default
	 * file contents), so it will have @p stream_name == @c NULL.  There
	 * will then be @p num_named_streams additional entries that specify the
	 * named data streams, if any, each of which will have @p stream_name !=
	 * @c NULL.  */
	struct wimlib_stream_entry streams[];
};

/**
 * Type of a callback function to wimlib_iterate_dir_tree().  Must return 0 on
 * success.
 */
typedef int (*wimlib_iterate_dir_tree_callback_t)(const struct wimlib_dir_entry *dentry,
						  void *user_ctx);

/**
 * Type of a callback function to wimlib_iterate_lookup_table().  Must return 0
 * on success.
 */
typedef int (*wimlib_iterate_lookup_table_callback_t)(const struct wimlib_resource_entry *resource,
						      void *user_ctx);

/** For wimlib_iterate_dir_tree(): Iterate recursively on children rather than
 * just on the specified path. */
#define WIMLIB_ITERATE_DIR_TREE_FLAG_RECURSIVE 0x00000001

/** For wimlib_iterate_dir_tree(): Don't iterate on the file or directory
 * itself; only its children (in the case of a non-empty directory) */
#define WIMLIB_ITERATE_DIR_TREE_FLAG_CHILDREN  0x00000002

/** Return ::WIMLIB_ERR_RESOURCE_NOT_FOUND if any resources needed to fill in
 * the ::wimlib_resource_entry's for the iteration cannot be found in the lookup
 * table of the ::WIMStruct.  The default behavior without this flag is to fill
 * in the SHA1 message digest of the ::wimlib_resource_entry and set the @ref
 * wimlib_resource_entry::is_missing "is_missing" flag.  */
#define WIMLIB_ITERATE_DIR_TREE_FLAG_RESOURCES_NEEDED  0x00000004


/** @} */
/** @ingroup G_modifying_wims
 * @{ */

/** Directly capture a NTFS volume rather than a generic directory.  This flag
 * cannot be combined with ::WIMLIB_ADD_FLAG_DEREFERENCE or
 * ::WIMLIB_ADD_FLAG_UNIX_DATA.   */
#define WIMLIB_ADD_FLAG_NTFS			0x00000001

/** Follow symlinks; archive and dump the files they point to.  Cannot be used
 * with ::WIMLIB_ADD_FLAG_NTFS. */
#define WIMLIB_ADD_FLAG_DEREFERENCE		0x00000002

/** Call the progress function with the message
 * ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY when each directory or file has been
 * scanned.  */
#define WIMLIB_ADD_FLAG_VERBOSE			0x00000004

/** Mark the image being added as the bootable image of the WIM. */
#define WIMLIB_ADD_FLAG_BOOT			0x00000008

/** Store the UNIX owner, group, and mode.  This is done by adding a special
 * alternate data stream to each regular file, symbolic link, and directory to
 * contain this information.  Please note that this flag is for convenience
 * only; Microsoft's implementation will not understand this special
 * information.  This flag cannot be combined with ::WIMLIB_ADD_FLAG_NTFS.  */
#define WIMLIB_ADD_FLAG_UNIX_DATA		0x00000010

/** Do not capture security descriptors.  Only has an effect in NTFS capture
 * mode, or in Windows native builds. */
#define WIMLIB_ADD_FLAG_NO_ACLS			0x00000020

/** Fail immediately if the full security descriptor of any file or directory
 * cannot be accessed.  Only has an effect in Windows native builds.  The
 * default behavior without this flag is to first try omitting the SACL from the
 * security descriptor, then to try omitting the security descriptor entirely.
 * */
#define WIMLIB_ADD_FLAG_STRICT_ACLS		0x00000040

/** Call the progress function with the message
 * ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY when a directory or file is excluded from
 * capture.  This is a subset of the messages provided by
 * ::WIMLIB_ADD_FLAG_VERBOSE. */
#define WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE		0x00000080

/** Reparse-point fixups:  Modify absolute symbolic links (or junction points,
 * in the case of Windows) that point inside the directory being captured to
 * instead be absolute relative to the directory being captured, rather than the
 * current root; also exclude absolute symbolic links that point outside the
 * directory tree being captured.
 *
 * Without this flag, the default is to do this if WIM_HDR_FLAG_RP_FIX is set in
 * the WIM header or if this is the first image being added.
 * WIM_HDR_FLAG_RP_FIX is set if the first image in a WIM is captured with
 * reparse point fixups enabled and currently cannot be unset. */
#define WIMLIB_ADD_FLAG_RPFIX			0x00000100

/** Don't do reparse point fixups.  The default behavior is described in the
 * documentation for ::WIMLIB_ADD_FLAG_RPFIX. */
#define WIMLIB_ADD_FLAG_NORPFIX			0x00000200

/** Do not automatically exclude unsupported files or directories from capture;
 * e.g. encrypted directories in NTFS-3g capture mode, or device files and FIFOs
 * on UNIX-like systems.  Instead, fail with ::WIMLIB_ERR_UNSUPPORTED_FILE when
 * such a file is encountered.  */
#define WIMLIB_ADD_FLAG_NO_UNSUPPORTED_EXCLUDE	0x00000400

/** Automatically select a capture configuration appropriate for capturing
 * filesystems containing Windows operating systems.  When this flag is
 * specified, the corresponding @p config parameter or member must be @c NULL.
 *
 * Currently, selecting this capture configuration will cause the following
 * files and directories to be excluded from capture:
 *
 * - "\$ntfs.log"
 * - "\hiberfil.sys"
 * - "\pagefile.sys"
 * - "\System Volume Information"
 * - "\RECYCLER"
 * - "\Windows\CSC"
 *
 * Note that the default behavior--- that is, when this flag is not specified
 * and @p config is @c NULL--- is to use no capture configuration, meaning that
 * no files are excluded from capture.
 */
#define WIMLIB_ADD_FLAG_WINCONFIG		0x00000800

#define WIMLIB_ADD_IMAGE_FLAG_NTFS		WIMLIB_ADD_FLAG_NTFS
#define WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE	WIMLIB_ADD_FLAG_DEREFERENCE
#define WIMLIB_ADD_IMAGE_FLAG_VERBOSE		WIMLIB_ADD_FLAG_VERBOSE
#define WIMLIB_ADD_IMAGE_FLAG_BOOT		WIMLIB_ADD_FLAG_BOOT
#define WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA		WIMLIB_ADD_FLAG_UNIX_DATA
#define WIMLIB_ADD_IMAGE_FLAG_NO_ACLS		WIMLIB_ADD_FLAG_NO_ACLS
#define WIMLIB_ADD_IMAGE_FLAG_STRICT_ACLS	WIMLIB_ADD_FLAG_STRICT_ACLS
#define WIMLIB_ADD_IMAGE_FLAG_EXCLUDE_VERBOSE	WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE
#define WIMLIB_ADD_IMAGE_FLAG_RPFIX		WIMLIB_ADD_FLAG_RPFIX
#define WIMLIB_ADD_IMAGE_FLAG_NORPFIX		WIMLIB_ADD_FLAG_NORPFIX
#define WIMLIB_ADD_IMAGE_FLAG_NO_UNSUPPORTED_EXCLUDE \
						WIMLIB_ADD_FLAG_NO_UNSUPPORTED_EXCLUDE
#define WIMLIB_ADD_IMAGE_FLAG_WINCONFIG		WIMLIB_ADD_FLAG_WINCONFIG

/** @} */
/** @ingroup G_modifying_wims
 * @{ */

/** Do not issue an error if the path to delete does not exist. */
#define WIMLIB_DELETE_FLAG_FORCE			0x00000001

/** Delete the file or directory tree recursively; if not specified, an error is
 * issued if the path to delete is a directory. */
#define WIMLIB_DELETE_FLAG_RECURSIVE			0x00000002

/** @} */
/** @ingroup G_modifying_wims
 * @{ */

/**
 * If a single image is being exported, mark it bootable in the destination WIM.
 * Alternatively, if ::WIMLIB_ALL_IMAGES is specified as the image to export,
 * the image in the source WIM (if any) that is marked as bootable is also
 * marked as bootable in the destination WIM.
 */
#define WIMLIB_EXPORT_FLAG_BOOT				0x00000001

/** Give the exported image(s) no names.  Avoids problems with image name
 * collisions.
 */
#define WIMLIB_EXPORT_FLAG_NO_NAMES			0x00000002

/** Give the exported image(s) no descriptions.  */
#define WIMLIB_EXPORT_FLAG_NO_DESCRIPTIONS		0x00000004

/** @} */
/** @ingroup G_extracting_wims
 * @{ */

/** Extract the image directly to a NTFS volume rather than a generic directory.
 * This mode is only available if wimlib was compiled with libntfs-3g support;
 * if not, ::WIMLIB_ERR_UNSUPPORTED will be returned.  In this mode, the
 * extraction target will be interpreted as the path to a NTFS volume image (as
 * a regular file or block device) rather than a directory.  It will be opened
 * using libntfs-3g, and the image will be extracted to the NTFS filesystem's
 * root directory.  Note: this flag cannot be used when wimlib_extract_image()
 * is called with ::WIMLIB_ALL_IMAGES as the @p image.  */
#define WIMLIB_EXTRACT_FLAG_NTFS			0x00000001

/** When identical files are extracted from the WIM, always hard link them
 * together.  */
#define WIMLIB_EXTRACT_FLAG_HARDLINK			0x00000002

/** When identical files are extracted from the WIM, always symlink them
 * together.  */
#define WIMLIB_EXTRACT_FLAG_SYMLINK			0x00000004

/** This flag no longer does anything but is reserved for future use.  */
#define WIMLIB_EXTRACT_FLAG_VERBOSE			0x00000008

/** Read the WIM file sequentially while extracting the image.  As of wimlib
 * v1.6.0 this is the default behavior, and this flag no longer does anything.
 */
#define WIMLIB_EXTRACT_FLAG_SEQUENTIAL			0x00000010

/** Extract special UNIX data captured with ::WIMLIB_ADD_FLAG_UNIX_DATA.  Only
 * valid on UNIX-like platforms, and when ::WIMLIB_EXTRACT_FLAG_NTFS was not
 * specified.  */
#define WIMLIB_EXTRACT_FLAG_UNIX_DATA			0x00000020

/** Do not extract security descriptors.  */
#define WIMLIB_EXTRACT_FLAG_NO_ACLS			0x00000040

/** Fail immediately if the full security descriptor of any file or directory
 * cannot be set exactly as specified in the WIM file.  On Windows, the default
 * behavior without this flag is to fall back to setting the security descriptor
 * with the SACL omitted, then only the default inherited security descriptor,
 * if we do not have permission to set the desired one.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_ACLS			0x00000080

/** This is the extraction equivalent to ::WIMLIB_ADD_FLAG_RPFIX.  This forces
 * reparse-point fixups on, so absolute symbolic links or junction points will
 * be fixed to be absolute relative to the actual extraction root.  Reparse
 * point fixups are done by default if WIM_HDR_FLAG_RP_FIX is set in the WIM
 * header.  This flag may only be specified when extracting a full image (not a
 * file or directory tree within one).  */
#define WIMLIB_EXTRACT_FLAG_RPFIX			0x00000100

/** Force reparse-point fixups on extraction off, regardless of the state of the
 * WIM_HDR_FLAG_RP_FIX flag in the WIM header.  */
#define WIMLIB_EXTRACT_FLAG_NORPFIX			0x00000200

/** Extract the specified file to standard output.  This is only valid in an
 * extraction command that specifies the extraction of a regular file in the WIM
 * image.  */
#define WIMLIB_EXTRACT_FLAG_TO_STDOUT			0x00000400

/** Instead of ignoring files and directories with names that cannot be
 * represented on the current platform (note: Windows has more restrictions on
 * filenames than POSIX-compliant systems), try to replace characters or append
 * junk to the names so that they can be extracted in some form.  */
#define WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES	0x00000800

/** On Windows, when there exist two or more files with the same case
 * insensitive name but different case sensitive names, try to extract them all
 * by appending junk to the end of them, rather than arbitrarily extracting only
 * one.  */
#define WIMLIB_EXTRACT_FLAG_ALL_CASE_CONFLICTS		0x00001000

/** Do not ignore failure to set timestamps on extracted files.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS		0x00002000

/** Do not ignore failure to set short names on extracted files.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES          0x00004000

/** Do not ignore failure to extract symbolic links (and junction points, on
 * Windows) due to permissions problems.  By default, such failures are ignored
 * since the default configuration of Windows only allows the Administrator to
 * create symbolic links.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS             0x00008000

/** TODO: this flag is intended to allow resuming an aborted extraction, but the
 * behavior is currently less than satisfactory.  Do not use (yet).  */
#define WIMLIB_EXTRACT_FLAG_RESUME			0x00010000

/** Perform the extraction ordered by the tree of files to extract rather than
 * how the underlying streams are arranged in the WIM file.  For regular WIM
 * files this may decrease or increase performance, depending on various
 * factors.  For WIM files containing packed streams this will decrease
 * performance.  */
#define WIMLIB_EXTRACT_FLAG_FILE_ORDER			0x00020000

/** For wimlib_extract_paths() and wimlib_extract_pathlist() only:  Treat the
 * paths in the WIM as "glob" patterns which may contain the wildcard characters
 * '?' and '*'.  The '?' character matches any character except a path
 * separator, whereas the '*' character matches zero or more non-path-separator
 * characters.  Each glob pattern may match zero or more paths in the WIM file.
 * If a glob pattern ends in a path separator, it will only match directories
 * (including reparse points with FILE_ATTRIBUTE_DIRECTORY set).  By default, if
 * a glob pattern does not match any files, a warning but not an error will be
 * issued, even if the glob pattern did not actually contain wildcard
 * characters.  Use ::WIMLIB_EXTRACT_FLAG_STRICT_GLOB to get an error instead.
 */
#define WIMLIB_EXTRACT_FLAG_GLOB_PATHS			0x00040000

/** In combination with ::WIMLIB_EXTRACT_FLAG_GLOB_PATHS, causes an error
 * (::WIMLIB_ERR_PATH_DOES_NOT_EXIST) rather than a warning to be issued when
 * one of the provided globs did not match a file.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_GLOB			0x00080000

/** @} */
/** @ingroup G_mounting_wim_images
 * @{ */

/** Mount the WIM image read-write rather than the default of read-only. */
#define WIMLIB_MOUNT_FLAG_READWRITE			0x00000001

/** Enable FUSE debugging by passing the @c -d flag to @c fuse_main().*/
#define WIMLIB_MOUNT_FLAG_DEBUG				0x00000002

/** Do not allow accessing alternate data streams in the mounted WIM image. */
#define WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE		0x00000004

/** Access alternate data streams in the mounted WIM image through extended file
 * attributes.  This is the default mode. */
#define WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR	0x00000008

/** Access alternate data streams in the mounted WIM image by specifying the
 * file name, a colon, then the alternate file stream name. */
#define WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS	0x00000010

/** Use UNIX file owners, groups, and modes if available in the WIM (see
 * ::WIMLIB_ADD_FLAG_UNIX_DATA). */
#define WIMLIB_MOUNT_FLAG_UNIX_DATA			0x00000020

/** Allow other users to see the mounted filesystem.  (this passes the @c
 * allow_other option to FUSE mount) */
#define WIMLIB_MOUNT_FLAG_ALLOW_OTHER			0x00000040

/** @} */
/** @ingroup G_creating_and_opening_wims
 * @{ */

/** Verify the WIM contents against the WIM's integrity table, if present.  This
 * causes the raw data of the WIM file, divided into 10 MB chunks, to be
 * checksummed and checked against the SHA1 message digests specified in the
 * integrity table.  ::WIMLIB_ERR_INTEGRITY is returned if there are any
 * mismatches (or, ::WIMLIB_ERR_INVALID_INTEGRITY_TABLE is returned if the
 * integrity table is invalid).  */
#define WIMLIB_OPEN_FLAG_CHECK_INTEGRITY		0x00000001

/** Issue an error if the WIM is part of a split WIM.  Software can provide
 * this flag for convenience if it explicitly does not want to support split
 * WIMs.  */
#define WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT			0x00000002

/** Check if the WIM is writable and return ::WIMLIB_ERR_WIM_IS_READONLY if it
 * is not.  A WIM is considered writable only if it is writable at the
 * filesystem level, does not have the WIM_HDR_FLAG_READONLY flag set in its
 * header, and is not part of a spanned set.  It is not required to provide this
 * flag before attempting to make changes to the WIM, but with this flag you get
 * an error sooner rather than later. */
#define WIMLIB_OPEN_FLAG_WRITE_ACCESS			0x00000004

/** @} */
/** @ingroup G_mounting_wim_images
 * @{ */

/** See ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY.  */
#define WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY		0x00000001

/** Unless this flag is given, changes to a read-write mounted WIM are
 * discarded.  Ignored for read-only mounts.  */
#define WIMLIB_UNMOUNT_FLAG_COMMIT			0x00000002

/** See ::WIMLIB_WRITE_FLAG_REBUILD.  */
#define WIMLIB_UNMOUNT_FLAG_REBUILD			0x00000004

/** See ::WIMLIB_WRITE_FLAG_RECOMPRESS */
#define WIMLIB_UNMOUNT_FLAG_RECOMPRESS			0x00000008

/** Do a "lazy" unmount (detach filesystem immediately, even if busy).  */
#define WIMLIB_UNMOUNT_FLAG_LAZY			0x00000010

/** @} */
/** @ingroup G_modifying_wims
 * @{ */

/** Send ::WIMLIB_PROGRESS_MSG_UPDATE_BEGIN_COMMAND and
 * ::WIMLIB_PROGRESS_MSG_UPDATE_END_COMMAND messages.  */
#define WIMLIB_UPDATE_FLAG_SEND_PROGRESS		0x00000001

/** @} */
/** @ingroup G_writing_and_overwriting_wims
 * @{ */

/** Include an integrity table in the WIM.
 *
 * For WIMs created with wimlib_open_wim(), the default behavior is to include
 * an integrity table if and only if one was present before.  For WIMs created
 * with wimlib_create_new_wim(), the default behavior is to not include an
 * integrity table.  */
#define WIMLIB_WRITE_FLAG_CHECK_INTEGRITY		0x00000001

/** Do not include an integrity table in the new WIM file.  This is the default
 * behavior, unless the WIM already included an integrity table.  */
#define WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY		0x00000002

/** Write the WIM as "pipable".  After writing a WIM with this flag specified,
 * images from it can be applied directly from a pipe using
 * wimlib_extract_image_from_pipe().  See the documentation for the --pipable
 * flag of `wimlib-imagex capture' for more information.  Beware: WIMs written
 * with this flag will not be compatible with Microsoft's software.
 *
 * For WIMs created with wimlib_open_wim(), the default behavior is to write the
 * WIM as pipable if and only if it was pipable before.  For WIMs created with
 * wimlib_create_new_wim(), the default behavior is to write the WIM as
 * non-pipable.  */
#define WIMLIB_WRITE_FLAG_PIPABLE			0x00000004

/** Do not write the WIM as "pipable".  This is the default behavior, unless the
 * WIM was pipable already.  */
#define WIMLIB_WRITE_FLAG_NOT_PIPABLE			0x00000008

/** Recompress all resources, even if they could otherwise be copied from a
 * different WIM with the same compression type (in the case of
 * wimlib_export_image() being called previously).  This flag is also valid in
 * the @p wim_write_flags of wimlib_join(), in which case all resources included
 * in the joined WIM file will be recompressed.  */
#define WIMLIB_WRITE_FLAG_RECOMPRESS			0x00000010

/** Call fsync() just before the WIM file is closed.  */
#define WIMLIB_WRITE_FLAG_FSYNC				0x00000020

/** wimlib_overwrite() only:  Re-build the entire WIM file rather than appending
 * data to it if possible.  */
#define WIMLIB_WRITE_FLAG_REBUILD			0x00000040

/** wimlib_overwrite() only:  Specifying this flag overrides the default
 * behavior of wimlib_overwrite() after one or more calls to
 * wimlib_delete_image(), which is to rebuild the entire WIM.  With this flag,
 * only minimal changes to correctly remove the image from the WIM will be
 * taken.  In particular, all streams will be left alone, even if they are no
 * longer referenced.  This is probably not what you want, because almost no
 * space will be saved by deleting an image in this way.  */
#define WIMLIB_WRITE_FLAG_SOFT_DELETE			0x00000080

/** wimlib_overwrite() only:  Allow overwriting the WIM even if the readonly
 * flag is set in the WIM header.  This can be used in combination with
 * wimlib_set_wim_info() with the ::WIMLIB_CHANGE_READONLY_FLAG flag to actually
 * set the readonly flag on the on-disk WIM file.  */
#define WIMLIB_WRITE_FLAG_IGNORE_READONLY_FLAG		0x00000100

/** Do not include non-metadata resources already present in other WIMs.  This
 * flag can be used to write a "delta" WIM after resources from the WIM on which
 * the delta is to be based were referenced with
 * wimlib_reference_resource_files() or wimlib_reference_resources().  */
#define WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS		0x00000200

/** Asserts that for writes of all WIM images, all streams needed for the WIM
 * are already present (not in external resource WIMs) and their reference
 * counts are correct, so the code does not need to recalculate which streams
 * are referenced.  This is for optimization purposes only, since with this flag
 * specified, the metadata resources may not need to be decompressed and parsed.
 *
 * This flag can be passed to wimlib_write() and wimlib_write_to_fd(), but is
 * already implied for wimlib_overwrite().  */
#define WIMLIB_WRITE_FLAG_STREAMS_OK			0x00000400

#define WIMLIB_WRITE_FLAG_RESERVED			0x00000800

/**
 * When writing streams in the resulting WIM file, pack multiple streams into a
 * single WIM resource instead of compressing them independently.  This tends to
 * produce a better compression ratio at the cost of less random access.
 * However, WIMs created with this flag are only compatible with wimlib v1.6.0
 * or later and WIMGAPI Windows 8 or later, seemingly for Windows Setup only and
 * <b>not including ImageX and Dism</b>.  WIMs created with this flag must use
 * version number 3584 in their header instead of 68864.
 *
 * If this flag is passed to wimlib_overwrite() and the WIM did not previously
 * contain packed streams, the WIM's version number will be changed to 3584 and
 * the new streams will be written packed.  Use ::WIMLIB_WRITE_FLAG_REBUILD to
 * force the WIM to be fully rebuilt.  */
#define WIMLIB_WRITE_FLAG_PACK_STREAMS			0x00001000

/** @} */
/** @ingroup G_general
 * @{ */

/** Assume that strings are represented in UTF-8, even if this is not the
 * locale's character encoding.  This flag is ignored on Windows, where wimlib
 * always uses UTF-16LE.  */
#define WIMLIB_INIT_FLAG_ASSUME_UTF8			0x00000001

/** Windows-only: do not attempt to acquire additional privileges (currently
 * SeBackupPrivilege, SeRestorePrivilege, SeSecurityPrivilege, and
 * SeTakeOwnershipPrivilege) when initializing the library.  This is intended
 * for the case where the calling program manages these privileges itself.
 * Note: no error is issued if privileges cannot be acquired, although related
 * errors may be reported later, depending on if the operations performed
 * actually require additional privileges or not.  */
#define WIMLIB_INIT_FLAG_DONT_ACQUIRE_PRIVILEGES	0x00000002

/** Windows only:  If ::WIMLIB_INIT_FLAG_DONT_ACQUIRE_PRIVILEGES not specified,
 * return ::WIMLIB_ERR_INSUFFICIENT_PRIVILEGES if privileges that may be needed
 * to read all possible data and metadata for a capture operation could not be
 * acquired.  Can be combined with ::WIMLIB_INIT_FLAG_STRICT_APPLY_PRIVILEGES.
 */
#define WIMLIB_INIT_FLAG_STRICT_CAPTURE_PRIVILEGES	0x00000004

/** Windows only:  If ::WIMLIB_INIT_FLAG_DONT_ACQUIRE_PRIVILEGES not specified,
 * return ::WIMLIB_ERR_INSUFFICIENT_PRIVILEGES if privileges that may be needed
 * to restore all possible data and metadata for an apply operation could not be
 * acquired.  Can be combined with ::WIMLIB_INIT_FLAG_STRICT_CAPTURE_PRIVILEGES.
 */
#define WIMLIB_INIT_FLAG_STRICT_APPLY_PRIVILEGES	0x00000008

/** Default to interpreting WIM paths case sensitively (default on UNIX-like
 * systems).  */
#define WIMLIB_INIT_FLAG_DEFAULT_CASE_SENSITIVE		0x00000010

/** Default to interpreting WIM paths case insensitively (default on Windows).
 * This does not apply to mounted images.  */
#define WIMLIB_INIT_FLAG_DEFAULT_CASE_INSENSITIVE	0x00000020

/** @} */
/** @ingroup G_nonstandalone_wims
 * @{ */

/** wimlib_reference_resource_files() only:  Enable shell-style filename
 * globbing.  */
#define WIMLIB_REF_FLAG_GLOB_ENABLE		0x00000001

/** wimlib_reference_resource_files() only:  Issue an error
 * (::WIMLIB_ERR_GLOB_HAD_NO_MATCHES) if a glob did not match any files.  The
 * default behavior without this flag is to issue no error at that point, but
 * then attempt to open the glob as a literal path, which of course will fail
 * anyway if no file exists at that path.  No effect if
 * ::WIMLIB_REF_FLAG_GLOB_ENABLE is not also specified.  */
#define WIMLIB_REF_FLAG_GLOB_ERR_ON_NOMATCH	0x00000002

/** @} */
/** @ingroup G_modifying_wims
 * @{ */

/** The specific type of update to perform. */
enum wimlib_update_op {
	/** Add a new file or directory tree to the WIM image in a
	 * certain location. */
	WIMLIB_UPDATE_OP_ADD = 0,

	/** Delete a file or directory tree from the WIM image. */
	WIMLIB_UPDATE_OP_DELETE,

	/** Rename a file or directory tree in the WIM image. */
	WIMLIB_UPDATE_OP_RENAME,
};

/** Data for a ::WIMLIB_UPDATE_OP_ADD operation. */
struct wimlib_add_command {
	/** Filesystem path to the file or directory tree to
	 * add. */
	wimlib_tchar *fs_source_path;
	/** Path, specified from the root of the WIM image, at
	 * which to add the file or directory tree within the
	 * WIM image. */
	wimlib_tchar *wim_target_path;

	/** Configuration for excluded files.  @c NULL means
	 * exclude no files (use no configuration), unless
	 * ::WIMLIB_ADD_FLAG_WINCONFIG is specified in @p
	 * add_flags.  */
	struct wimlib_capture_config *config;

	/** Bitwise OR of WIMLIB_ADD_FLAG_* flags. */
	int add_flags;
};

/** Data for a ::WIMLIB_UPDATE_OP_DELETE operation. */
struct wimlib_delete_command {
	/** Path, specified from the root of the WIM image, for
	 * the file or directory tree within the WIM image to be
	 * deleted. */
	wimlib_tchar *wim_path;
	/** Bitwise OR of WIMLIB_DELETE_FLAG_* flags. */
	int delete_flags;
};

/** Data for a ::WIMLIB_UPDATE_OP_RENAME operation. */
struct wimlib_rename_command {
	/** Path, specified from the root of the WIM image, for
	 * the source file or directory tree within the WIM
	 * image. */
	wimlib_tchar *wim_source_path;
	/** Path, specified from the root of the WIM image, for
	 * the destination file or directory tree within the WIM
	 * image. */
	wimlib_tchar *wim_target_path;
	/** Reserved; set to 0. */
	int rename_flags;
};

/** Specification of an update to perform on a WIM image. */
struct wimlib_update_command {

	enum wimlib_update_op op;

	union {
		struct wimlib_add_command add;
		struct wimlib_delete_command delete_; /* Underscore is for C++
							 compatibility.  */
		struct wimlib_rename_command rename;
	};
};

/** @} */
/** @ingroup G_extracting_wims
 * @{ */

/** Specification of a file or directory tree to extract from a WIM image.  Used
 * in calls to wimlib_extract_files().  */
struct wimlib_extract_command {
	/** Path to file or directory tree within the WIM image to extract.  It
	 * must be provided as an absolute path from the root of the WIM image.
	 * The path separators may be either forward slashes or backslashes. */
	wimlib_tchar *wim_source_path;

	/** Filesystem path to extract the file or directory tree to. */
	wimlib_tchar *fs_dest_path;

	/** Bitwise or of zero or more of the WIMLIB_EXTRACT_FLAG_* flags. */
	int extract_flags;
};


/** @} */
/** @ingroup G_general
 * @{ */

/**
 * Possible values of the error code returned by many functions in wimlib.
 *
 * See the documentation for each wimlib function to see specifically what error
 * codes can be returned by a given function, and what they mean.
 */
enum wimlib_error_code {
	WIMLIB_ERR_SUCCESS = 0,
	WIMLIB_ERR_ALREADY_LOCKED,
	WIMLIB_ERR_DECOMPRESSION,
	WIMLIB_ERR_DELETE_STAGING_DIR,
	WIMLIB_ERR_FILESYSTEM_DAEMON_CRASHED,
	WIMLIB_ERR_FORK,
	WIMLIB_ERR_FUSE,
	WIMLIB_ERR_FUSERMOUNT,
	WIMLIB_ERR_GLOB_HAD_NO_MATCHES,
	WIMLIB_ERR_ICONV_NOT_AVAILABLE,
	WIMLIB_ERR_IMAGE_COUNT,
	WIMLIB_ERR_IMAGE_NAME_COLLISION,
	WIMLIB_ERR_INSUFFICIENT_PRIVILEGES,
	WIMLIB_ERR_INTEGRITY,
	WIMLIB_ERR_INVALID_CAPTURE_CONFIG,
	WIMLIB_ERR_INVALID_CHUNK_SIZE,
	WIMLIB_ERR_INVALID_COMPRESSION_TYPE,
	WIMLIB_ERR_INVALID_HEADER,
	WIMLIB_ERR_INVALID_IMAGE,
	WIMLIB_ERR_INVALID_INTEGRITY_TABLE,
	WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY,
	WIMLIB_ERR_INVALID_METADATA_RESOURCE,
	WIMLIB_ERR_INVALID_MULTIBYTE_STRING,
	WIMLIB_ERR_INVALID_OVERLAY,
	WIMLIB_ERR_INVALID_PARAM,
	WIMLIB_ERR_INVALID_PART_NUMBER,
	WIMLIB_ERR_INVALID_PIPABLE_WIM,
	WIMLIB_ERR_INVALID_REPARSE_DATA,
	WIMLIB_ERR_INVALID_RESOURCE_HASH,
	WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE,
	WIMLIB_ERR_INVALID_UTF16_STRING,
	WIMLIB_ERR_INVALID_UTF8_STRING,
	WIMLIB_ERR_IS_DIRECTORY,
	WIMLIB_ERR_IS_SPLIT_WIM,
	WIMLIB_ERR_LIBXML_UTF16_HANDLER_NOT_AVAILABLE,
	WIMLIB_ERR_LINK,
	WIMLIB_ERR_METADATA_NOT_FOUND,
	WIMLIB_ERR_MKDIR,
	WIMLIB_ERR_MQUEUE,
	WIMLIB_ERR_NOMEM,
	WIMLIB_ERR_NOTDIR,
	WIMLIB_ERR_NOTEMPTY,
	WIMLIB_ERR_NOT_A_REGULAR_FILE,
	WIMLIB_ERR_NOT_A_WIM_FILE,
	WIMLIB_ERR_NOT_PIPABLE,
	WIMLIB_ERR_NO_FILENAME,
	WIMLIB_ERR_NTFS_3G,
	WIMLIB_ERR_OPEN,
	WIMLIB_ERR_OPENDIR,
	WIMLIB_ERR_PATH_DOES_NOT_EXIST,
	WIMLIB_ERR_READ,
	WIMLIB_ERR_READLINK,
	WIMLIB_ERR_RENAME,
	WIMLIB_ERR_REOPEN,
	WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED,
	WIMLIB_ERR_RESOURCE_NOT_FOUND,
	WIMLIB_ERR_RESOURCE_ORDER,
	WIMLIB_ERR_SET_ATTRIBUTES,
	WIMLIB_ERR_SET_REPARSE_DATA,
	WIMLIB_ERR_SET_SECURITY,
	WIMLIB_ERR_SET_SHORT_NAME,
	WIMLIB_ERR_SET_TIMESTAMPS,
	WIMLIB_ERR_SPLIT_INVALID,
	WIMLIB_ERR_STAT,
	WIMLIB_ERR_TIMEOUT,
	WIMLIB_ERR_UNEXPECTED_END_OF_FILE,
	WIMLIB_ERR_UNICODE_STRING_NOT_REPRESENTABLE,
	WIMLIB_ERR_UNKNOWN_VERSION,
	WIMLIB_ERR_UNSUPPORTED,
	WIMLIB_ERR_UNSUPPORTED_FILE,
	WIMLIB_ERR_VOLUME_LACKS_FEATURES,
	WIMLIB_ERR_WIM_IS_READONLY,
	WIMLIB_ERR_WRITE,
	WIMLIB_ERR_XML,
	WIMLIB_ERR_WIM_IS_ENCRYPTED,
};


/** Used to indicate no WIM image or an invalid WIM image. */
#define WIMLIB_NO_IMAGE		0

/** Used to specify all images in the WIM. */
#define WIMLIB_ALL_IMAGES	(-1)

/**
 * @ingroup G_modifying_wims
 *
 * Appends an empty image to a WIM file.  This empty image will initially
 * contain no files or directories, although if written without further
 * modifications, a root directory will be created automatically for it.  After
 * calling this function, you can use wimlib_update_image() to add files to the
 * new WIM image.  This gives you slightly more control over making the new
 * image compared to calling wimlib_add_image() or
 * wimlib_add_image_multisource() directly.
 *
 * @param wim
 *	Pointer to the ::WIMStruct for the WIM file to which the image is to be
 *	added.
 * @param name
 *	Name to give the new image.  If @c NULL or empty, the new image is given
 *	no name.  If nonempty, it must specify a name that does not already
 *	exist in @p wim.
 * @param new_idx_ret
 *	If non-<code>NULL</code>, the index of the newly added image is returned
 *	in this location.
 *
 * @return 0 on success; nonzero on failure.  The possible error codes are:
 *
 * @retval ::WIMLIB_ERR_IMAGE_NAME_COLLISION
 *	There is already an image in @p wim named @p name.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Failed to allocate the memory needed to add the new image.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	The WIM file is considered read-only because of any of the reasons
 *	mentioned in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS
 *	flag.
 */
extern int
wimlib_add_empty_image(WIMStruct *wim,
		       const wimlib_tchar *name,
		       int *new_idx_ret);

/**
 * @ingroup G_modifying_wims
 *
 * Adds an image to a WIM file from an on-disk directory tree or NTFS volume.
 *
 * The directory tree or NTFS volume is scanned immediately to load the dentry
 * tree into memory, and file attributes and symbolic links are read.  However,
 * actual file data is not read until wimlib_write() or wimlib_overwrite() is
 * called.
 *
 * See the manual page for the @b wimlib-imagex program for more information
 * about the "normal" capture mode versus the NTFS capture mode (entered by
 * providing the flag ::WIMLIB_ADD_FLAG_NTFS).
 *
 * Note that @b no changes are committed to the underlying WIM file (if
 * any) until wimlib_write() or wimlib_overwrite() is called.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file to which the image will be
 * 	added.
 * @param source
 * 	A path to a directory or unmounted NTFS volume that will be captured as
 * 	a WIM image.
 * @param name
 *	Name to give the new image.  If @c NULL or empty, the new image is given
 *	no name.  If nonempty, it must specify a name that does not already
 *	exist in @p wim.
 * @param config
 * 	Capture configuration that specifies files, directories, or path globs
 * 	to exclude from being captured.  If @c NULL, a dummy configuration where
 * 	no paths are treated specially is used.
 * @param add_flags
 * 	Bitwise OR of flags prefixed with WIMLIB_ADD_FLAG.
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.  The progress messages that will be
 * 	received are ::WIMLIB_PROGRESS_MSG_SCAN_BEGIN,
 * 	::WIMLIB_PROGRESS_MSG_SCAN_END, and, if ::WIMLIB_ADD_FLAG_VERBOSE was
 * 	included in @p add_flags, also ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY.
 *
 * @return 0 on success; nonzero on error.  On error, changes to @p wim are
 * discarded so that it appears to be in the same state as when this function
 * was called.
 *
 * This function is implemented by calling wimlib_add_empty_image(), then
 * calling wimlib_update_image() with a single "add" command, so any error code
 * returned by wimlib_add_empty_image() may be returned, as well as any error
 * codes returned by wimlib_update_image() other than ones documented as only
 * being returned specifically by an update involving delete or rename commands.
 */
extern int
wimlib_add_image(WIMStruct *wim,
		 const wimlib_tchar *source,
		 const wimlib_tchar *name,
		 const struct wimlib_capture_config *config,
		 int add_flags,
		 wimlib_progress_func_t progress_func);

/**
 * @ingroup G_modifying_wims
 *
 * This function is equivalent to wimlib_add_image() except it allows for
 * multiple sources to be combined into a single WIM image.  This is done by
 * specifying the @p sources and @p num_sources parameters instead of the @p
 * source parameter of wimlib_add_image().  The rest of the parameters are the
 * same as wimlib_add_image().  See the documentation for <b>wimlib-imagex
 * capture</b> for full details on how this mode works.
 *
 * In addition to the error codes that wimlib_add_image() can return,
 * wimlib_add_image_multisource() can return ::WIMLIB_ERR_INVALID_OVERLAY
 * when trying to overlay a non-directory on a directory or when otherwise
 * trying to overlay multiple conflicting files to the same location in the WIM
 * image.  It will also return ::WIMLIB_ERR_INVALID_PARAM if
 * ::WIMLIB_ADD_FLAG_NTFS was specified in @p add_flags but there
 * was not exactly one capture source with the target being the root directory.
 * (In this respect, there is no advantage to using
 * wimlib_add_image_multisource() instead of wimlib_add_image() when requesting
 * NTFS mode.) */
extern int
wimlib_add_image_multisource(WIMStruct *wim,
			     const struct wimlib_capture_source *sources,
			     size_t num_sources,
			     const wimlib_tchar *name,
			     const struct wimlib_capture_config *config,
			     int add_flags,
			     wimlib_progress_func_t progress_func);

/**
 * @ingroup G_creating_and_opening_wims
 *
 * Creates a ::WIMStruct for a new WIM file.
 *
 * This only creates an in-memory structure for a WIM that initially contains no
 * images.  No on-disk file is created until wimlib_write() is called.
 *
 * @param ctype
 * 	The type of compression to be used in the new WIM file.  Must be
 * 	::WIMLIB_COMPRESSION_TYPE_NONE, ::WIMLIB_COMPRESSION_TYPE_LZX, or
 * 	::WIMLIB_COMPRESSION_TYPE_XPRESS.
 * @param wim_ret
 * 	On success, a pointer to an opaque ::WIMStruct for the new WIM file is
 * 	written to the memory location pointed to by this paramater.  The
 * 	::WIMStruct must be freed using using wimlib_free() when finished with
 * 	it.
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 * 	@p ctype was not ::WIMLIB_COMPRESSION_TYPE_NONE,
 * 	::WIMLIB_COMPRESSION_TYPE_LZX, or ::WIMLIB_COMPRESSION_TYPE_XPRESS.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 */
extern int
wimlib_create_new_wim(int ctype, WIMStruct **wim_ret);

/**
 * @ingroup G_modifying_wims
 *
 * Deletes an image, or all images, from a WIM file.
 *
 * All streams referenced by the image(s) being deleted are removed from the
 * lookup table of the WIM if they are not referenced by any other images in the
 * WIM.
 *
 * Please note that @b no changes are committed to the underlying WIM file (if
 * any) until wimlib_write() or wimlib_overwrite() is called.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for the WIM file that contains the image(s)
 * 	being deleted.
 * @param image
 * 	The number of the image to delete, or ::WIMLIB_ALL_IMAGES to delete all
 * 	images.
 * @return 0 on success; nonzero on failure.  On failure, @p wim is guaranteed
 * to be left unmodified only if @p image specified a single image.  If instead
 * @p image was ::WIMLIB_ALL_IMAGES and @p wim contained more than one image, it's
 * possible for some but not all of the images to have been deleted when a
 * failure status is returned.
 *
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p image does not exist in the WIM and is not ::WIMLIB_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	The WIM file is considered read-only because of any of the reasons
 *	mentioned in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS
 *	flag.
 *
 * This function can additionally return ::WIMLIB_ERR_DECOMPRESSION,
 * ::WIMLIB_ERR_INVALID_METADATA_RESOURCE, ::WIMLIB_ERR_METADATA_NOT_FOUND,
 * ::WIMLIB_ERR_NOMEM, ::WIMLIB_ERR_READ, or
 * ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE, all of which indicate failure (for
 * different reasons) to read the metadata resource for an image that needed to
 * be deleted.
 */
extern int
wimlib_delete_image(WIMStruct *wim, int image);

/**
 * @ingroup G_modifying_wims
 *
 * Exports an image, or all the images, from a WIM file, into another WIM file.
 *
 * The destination image is made to share the same dentry tree and security data
 * structure as the source image.  This places some restrictions on additional
 * functions that may be called.  wimlib_mount_image() may not be called on
 * either the source image or the destination image without an intervening call
 * to a function that un-shares the images, such as wimlib_free() on @p
 * dest_wim, or wimlib_delete_image() on either the source or destination image.
 * Furthermore, you may not call wimlib_free() on @p src_wim before calling
 * wimlib_write() or wimlib_overwrite() on @p dest_wim because @p dest_wim will
 * have references back to @p src_wim.
 *
 * If this function fails, all changes to @p dest_wim are rolled back.
 *
 * Please note that no changes are committed to the underlying WIM file of @p
 * dest_wim (if any) until wimlib_write() or wimlib_overwrite() is called.
 *
 * @param src_wim
 *	The WIM from which to export the images, specified as a pointer to the
 *	::WIMStruct for a standalone WIM file, a delta WIM file, or part 1 of a
 *	split WIM.  In the case of a WIM file that is not standalone, this
 *	::WIMStruct must have had any needed external resources previously
 *	referenced using wimlib_reference_resources() or
 *	wimlib_reference_resource_files().
 * @param src_image
 * 	The image to export from @p src_wim, as either a 1-based image index to
 * 	export a single image, or ::WIMLIB_ALL_IMAGES to export all images.
 * @param dest_wim
 * 	Pointer to the ::WIMStruct for a WIM that will receive the images being
 * 	exported.
 * @param dest_name
 * 	For single-image exports, the name to give the exported image in @p
 * 	dest_wim.  If left @c NULL, the name from @p src_wim is used.  For
 * 	::WIMLIB_ALL_IMAGES exports, this parameter must be left @c NULL; in
 * 	that case, the names are all taken from @p src_wim.  This parameter is
 * 	overridden by ::WIMLIB_EXPORT_FLAG_NO_NAMES.
 * @param dest_description
 * 	For single-image exports, the description to give the exported image in
 * 	the new WIM file.  If left @c NULL, the description from @p src_wim is
 * 	used.  For ::WIMLIB_ALL_IMAGES exports, this parameter must be left @c
 * 	NULL; in that case, the description are all taken from @p src_wim.  This
 * 	parameter is overridden by ::WIMLIB_EXPORT_FLAG_NO_DESCRIPTIONS.
 * @param export_flags
 *	Bitwise OR of flags prefixed with WIMLIB_EXPORT_FLAG.
 * @param progress_func
 *	Currently ignored, but reserved for a function that will be called with
 *	information about the operation.  Use NULL if no additional information
 *	is desired.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_IMAGE_NAME_COLLISION
 * 	One or more of the names being given to an exported image was already in
 * 	use in the destination WIM.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p src_image does not exist in @p src_wim and was not
 * 	::WIMLIB_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@p src_wim and/or @p dest_wim were @c NULL; or @p src_image was
 * 	::WIMLIB_ALL_IMAGES but @p dest_name and/or @p dest_description were not
 * 	@c NULL.
 * @retval ::WIMLIB_ERR_METADATA_NOT_FOUND
 *	Either @p src_wim or @p dest_wim did not contain metadata resources; for
 *	example, one of them was a non-first part of a split WIM.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_RESOURCE_NOT_FOUND
 *	A resource that needed to be exported could not be found in either the
 *	source or destination WIMs.  This error can occur if, for example, @p
 *	src_wim is part of a split WIM but needed resources from the other split
 *	WIM parts were not referenced with wimlib_reference_resources() or
 *	wimlib_reference_resource_files() before the call to
 *	wimlib_export_image().
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	@p dest_wim is considered read-only because of any of the reasons
 *	mentioned in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS
 *	flag.
 *
 * This function can additionally return ::WIMLIB_ERR_DECOMPRESSION,
 * ::WIMLIB_ERR_INVALID_METADATA_RESOURCE, ::WIMLIB_ERR_METADATA_NOT_FOUND,
 * ::WIMLIB_ERR_NOMEM, ::WIMLIB_ERR_READ, or
 * ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE, all of which indicate failure (for
 * different reasons) to read the metadata resource for an image in @p src_wim
 * that needed to be exported.
 */
extern int
wimlib_export_image(WIMStruct *src_wim, int src_image,
		    WIMStruct *dest_wim,
		    const wimlib_tchar *dest_name,
		    const wimlib_tchar *dest_description,
		    int export_flags,
		    wimlib_progress_func_t progress_func);

/**
 * @ingroup G_extracting_wims
 *
 * Extract zero or more files or directory trees from a WIM image.
 *
 * This generalizes the single-image extraction functionality of
 * wimlib_extract_image() to allow extracting only the specified subsets of the
 * image.
 *
 * @param wim
 *	The WIM from which to extract the files, specified as a pointer to the
 *	::WIMStruct for a standalone WIM file, a delta WIM file, or part 1 of a
 *	split WIM.  In the case of a WIM file that is not standalone, this
 *	::WIMStruct must have had any needed external resources previously
 *	referenced using wimlib_reference_resources() or
 *	wimlib_reference_resource_files().
 *
 * @param image
 *	The 1-based number of the image in @p wim from which the files or
 *	directory trees are to be extracted.  It cannot be ::WIMLIB_ALL_IMAGES.
 *
 * @param cmds
 *	An array of ::wimlib_extract_command structures that specifies the
 *	extractions to perform.
 *
 * @param num_cmds
 *	Number of commands in the @p cmds array.
 *
 * @param default_extract_flags
 *	Default extraction flags; the behavior shall be as if these flags had
 *	been specified in the ::wimlib_extract_command.extract_flags member in
 *	each extraction command, in combination with any flags already present.
 *
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.  The possible error codes include
 * most of those documented as returned by wimlib_extract_image() as well as the
 * following additional error codes:
 *
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 *	@p image was ::WIMLIB_ALL_IMAGES (or was not otherwise a valid image in
 *	the WIM file).
 * @retval ::WIMLIB_ERR_PATH_DOES_NOT_EXIST
 *	The ::wimlib_extract_command.wim_source_path member in one of the
 *	extract commands did not exist in the WIM.
 * @retval ::WIMLIB_ERR_NOT_A_REGULAR_FILE
 *	::WIMLIB_EXTRACT_FLAG_TO_STDOUT was specified for an extraction command
 *	in which ::wimlib_extract_command.wim_source_path existed but was not a
 *	regular file or directory.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	::WIMLIB_EXTRACT_FLAG_HARDLINK or ::WIMLIB_EXTRACT_FLAG_SYMLINK was
 *	specified for some commands but not all; or
 *	::wimlib_extract_command.fs_dest_path was @c NULL or the empty string
 *	for one or more commands; or ::WIMLIB_EXTRACT_FLAG_RPFIX was specified
 *	for a command in which ::wimlib_extract_command.wim_source_path did not
 *	specify the root directory of the WIM image.
 */
extern int
wimlib_extract_files(WIMStruct *wim,
		     int image,
		     const struct wimlib_extract_command *cmds,
		     size_t num_cmds,
		     int default_extract_flags,
		     wimlib_progress_func_t progress_func);

/**
 * @ingroup G_extracting_wims
 *
 * Extracts an image, or all images, from a WIM to a directory or directly to a
 * NTFS volume image.
 *
 * The exact behavior of how wimlib extracts files from a WIM image is
 * controllable by the @p extract_flags parameter, but there also are
 * differences depending on the platform (UNIX-like vs Windows).  See the manual
 * page for <b>wimlib-imagex apply</b> for more information, including about the
 * special "NTFS volume extraction mode" entered by providing
 * ::WIMLIB_EXTRACT_FLAG_NTFS.
 *
 * All extracted data is SHA1-summed, and ::WIMLIB_ERR_INVALID_RESOURCE_HASH is
 * returned if any resulting SHA1 message digests do not match the values
 * provided in the WIM file.  Therefore, if this function is successful, you can
 * be fairly sure that any compressed data in the WIM was uncompressed
 * correctly.
 *
 * @param wim
 *	The WIM from which to extract the image(s), specified as a pointer to
 *	the ::WIMStruct for a standalone WIM file, a delta WIM file, or part 1
 *	of a split WIM.  In the case of a WIM file that is not standalone, this
 *	::WIMStruct must have had any needed external resources previously
 *	referenced using wimlib_reference_resources() or
 *	wimlib_reference_resource_files().
 * @param image
 * 	The image to extract.  Can be the number of an image, or ::WIMLIB_ALL_IMAGES
 * 	to specify that all images are to be extracted.  ::WIMLIB_ALL_IMAGES cannot
 * 	be used if ::WIMLIB_EXTRACT_FLAG_NTFS is specified in @p extract_flags.
 * @param target
 * 	Directory to extract the WIM image(s) to (created if it does not already
 * 	exist); or, with ::WIMLIB_EXTRACT_FLAG_NTFS in @p extract_flags, the
 * 	path to the unmounted NTFS volume to extract the image to.
 * @param extract_flags
 * 	Bitwise OR of the flags prefixed with WIMLIB_EXTRACT_FLAG.
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	Failed to decompress a resource to be extracted.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	Both ::WIMLIB_EXTRACT_FLAG_HARDLINK and ::WIMLIB_EXTRACT_FLAG_SYMLINK
 * 	were specified in @p extract_flags; or both
 * 	::WIMLIB_EXTRACT_FLAG_STRICT_ACLS and ::WIMLIB_EXTRACT_FLAG_NO_ACLS were
 * 	specified in @p extract_flags; or both ::WIMLIB_EXTRACT_FLAG_RPFIX and
 * 	::WIMLIB_EXTRACT_FLAG_NORPFIX were specified in @p extract_flags; or
 * 	::WIMLIB_EXTRACT_FLAG_RESUME was specified in @p extract_flags; or if
 * 	::WIMLIB_EXTRACT_FLAG_NTFS was specified in @p extract_flags and
 * 	@p image was ::WIMLIB_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_HASH
 * 	The SHA1 message digest of an extracted stream did not match the SHA1
 * 	message digest given in the WIM file.
 * @retval ::WIMLIB_ERR_LINK
 * 	Failed to create a symbolic link or a hard link.
 * @retval ::WIMLIB_ERR_MKDIR
 * 	Failed create a directory.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_OPEN
 * 	Could not create a file, or failed to open an already-extracted file.
 * @retval ::WIMLIB_ERR_READ
 * 	Failed to read data from the WIM file associated with @p wim.
 * @retval ::WIMLIB_ERR_READLINK
 *	Failed to determine the target of a symbolic link in the WIM.
 * @retval ::WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED
 *	Failed to fix the target of an absolute symbolic link (e.g. if the
 *      target would have exceeded the maximum allowed length).  (Only if
 *      reparse data was supported by the extraction mode and
 *      ::WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS was specified in @p extract_flags.)
 * @retval ::WIMLIB_ERR_RESOURCE_NOT_FOUND
 *	One of the files or directories that needed to be extracted referenced a
 *	stream not present in the WIM's lookup table (or in any of the lookup
 *	tables of the split WIM	parts).
 * @retval ::WIMLIB_ERR_SET_ATTRIBUTES
 *	Failed to set attributes on a file.
 * @retval ::WIMLIB_ERR_SET_REPARSE_DATA
 *	Failed to set reparse data on a file (only if reparse data was supported
 *	by the extraction mode).
 * @retval ::WIMLIB_ERR_SET_SECURITY
 *	Failed to set security descriptor on a file
 *	(only if ::WIMLIB_EXTRACT_FLAG_STRICT_ACLS was specified in @p
 *	extract_flags).
 * @retval ::WIMLIB_ERR_SET_SHORT_NAME
 *	Failed to set the short name of a file (only if
 *	::WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES was specified in @p extract_flags).
 * @retval ::WIMLIB_ERR_SET_TIMESTAMPS
 *	Failed to set timestamps on a file (only if
 *	::WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS was specified in @p extract_flags).
 * @retval ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 * 	Unexpected end-of-file occurred when reading data from the WIM file
 * 	associated with @p wim.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 *	A requested extraction flag, or the data or metadata that must be
 *	extracted to support it, is unsupported in the build and configuration
 *	of wimlib, or on the current platform or extraction mode or target
 *	volume.  Flags affected by this include ::WIMLIB_EXTRACT_FLAG_NTFS,
 *	::WIMLIB_EXTRACT_FLAG_UNIX_DATA, ::WIMLIB_EXTRACT_FLAG_STRICT_ACLS,
 *	::WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES,
 *	::WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS,
 *	::WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS, ::WIMLIB_EXTRACT_FLAG_SYMLINK,
 *	and ::WIMLIB_EXTRACT_FLAG_HARDLINK.  For example, if
 *	::WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES is specified in @p
 *	extract_flags,
 *	::WIMLIB_ERR_UNSUPPORTED will be returned if the WIM image contains one
 *	or more files with short names, but extracting short names is not
 *	supported --- on Windows, this occurs if the target volume does not
 *	support short names, while on non-Windows, this occurs if
 *	::WIMLIB_EXTRACT_FLAG_NTFS was not specified in @p extract_flags.
 * @retval ::WIMLIB_ERR_WRITE
 * 	Failed to write data to a file being extracted.
 *
 * This function can additionally return ::WIMLIB_ERR_DECOMPRESSION,
 * ::WIMLIB_ERR_INVALID_METADATA_RESOURCE, ::WIMLIB_ERR_METADATA_NOT_FOUND,
 * ::WIMLIB_ERR_NOMEM, ::WIMLIB_ERR_READ, or
 * ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE, all of which indicate failure (for
 * different reasons) to read the metadata resource for an image that needed to
 * be extracted.
 */
extern int
wimlib_extract_image(WIMStruct *wim, int image,
		     const wimlib_tchar *target,
		     int extract_flags,
		     wimlib_progress_func_t progress_func);

/**
 * @ingroup G_extracting_wims
 *
 * Since wimlib v1.5.0:  Extract one or more images from a pipe on which a
 * pipable WIM is being sent.
 *
 * See the documentation for ::WIMLIB_WRITE_FLAG_PIPABLE for more information
 * about pipable WIMs.
 *
 * This function operates in a special way to read the WIM fully sequentially.
 * As a result, there is no ::WIMStruct is made visible to library users, and
 * you cannot call wimlib_open_wim() on the pipe.  (You can, however, use
 * wimlib_open_wim() to transparently open a pipable WIM if it's available as a
 * seekable file, not a pipe.)
 *
 * @param pipe_fd
 *	File descriptor, which may be a pipe, opened for reading and positioned
 *	at the start of the pipable WIM.
 * @param image_num_or_name
 *	String that specifies the 1-based index or name of the image to extract.
 *	It is translated to an image index using the same rules that
 *	wimlib_resolve_image() uses.  However, unlike wimlib_extract_image(),
 *	only a single image (not all images) can be specified.  Alternatively,
 *	specify @p NULL here to use the first image in the WIM if it contains
 *	exactly one image but otherwise return ::WIMLIB_ERR_INVALID_IMAGE.
 * @param target
 *	Same as the corresponding parameter to wimlib_extract_image().
 * @param extract_flags
 *	Same as the corresponding parameter to wimlib_extract_image(), except
 *	for the following exceptions:  ::WIMLIB_EXTRACT_FLAG_SEQUENTIAL is
 *	always implied, since data is always read from @p pipe_fd sequentially
 *	in this mode; also, ::WIMLIB_EXTRACT_FLAG_TO_STDOUT is invalid and will
 *	result in ::WIMLIB_ERR_INVALID_PARAM being returned.
 * @param progress_func
 *	Same as the corresponding parameter to wimlib_extract_image(), except
 *	::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN messages will also be
 *	received.
 *
 * @return 0 on success; nonzero on error.  The possible error codes include
 * those returned by wimlib_extract_image() as well as the following:
 *
 * @retval ::WIMLIB_ERR_INVALID_PIPABLE_WIM
 *	Data read from the pipable WIM was invalid.
 * @retval ::WIMLIB_ERR_NOT_PIPABLE
 *	The WIM being piped in a @p pipe_fd is a normal WIM, not a pipable WIM.
 */
extern int
wimlib_extract_image_from_pipe(int pipe_fd,
			       const wimlib_tchar *image_num_or_name,
			       const wimlib_tchar *target, int extract_flags,
			       wimlib_progress_func_t progress_func);

/**
 * Similar to wimlib_extract_paths(), but the paths to extract from the WIM
 * image specified in the UTF-8 text file named by @p path_list_file which
 * itself contains the list of paths to use, one per line.  Leading and trailing
 * whitespace, and otherwise empty lines and lines beginning with the ';'
 * character are ignored.  No quotes are needed as paths are otherwise delimited
 * by the newline character.
 */
extern int
wimlib_extract_pathlist(WIMStruct *wim, int image,
			const wimlib_tchar *target,
			const wimlib_tchar *path_list_file,
			int extract_flags,
			wimlib_progress_func_t progress_func);

/**
 * Similar to wimlib_extract_files(), but the files or directories to extract
 * from the WIM image are specified as an array of paths.
 *
 * Each path will be extracted to a corresponding subdirectory of the @p target
 * based on its location in the WIM image.  For example, if one of the paths to
 * extract is "/Windows/explorer.exe" and the target is "outdir", the file will
 * be extracted to "outdir/Windows/explorer.exe".  Each path to extract must be
 * specified as the absolute path to a directory within the WIM image.
 * Separators in the paths to extract may be either forwards or backwards
 * slashes, and leading path separators are optional.  Symbolic links are not
 * dereferenced when interpreting paths to extract.  Paths to extract will be
 * interpreted either case-sensitively (UNIX default) or case-insensitively
 * (Windows default); this can be changed by wimlib_global_init().
 *
 * The @p target path, on the other hand, is expected to be a native path.  On
 * UNIX-like systems it may not contain backslashes, for example.
 *
 * By default, if any paths to extract do not exist,
 * ::WIMLIB_ERR_PATH_DOES_NOT_EXIST is issued.  This behavior changes if
 * ::WIMLIB_EXTRACT_FLAG_GLOB_PATHS is specified.
 *
 * With ::WIMLIB_EXTRACT_FLAG_GLOB_PATHS specified in @p extract_flags, this
 * function additionally allows paths to be globs using the wildcard characters
 * '*' and '?'.
 */
extern int
wimlib_extract_paths(WIMStruct *wim,
		     int image,
		     const wimlib_tchar *target,
		     const wimlib_tchar * const *paths,
		     size_t num_paths,
		     int extract_flags,
		     wimlib_progress_func_t progress_func);

/**
 * @ingroup G_wim_information
 *
 * Extracts the XML data of a WIM file to a file stream.  Every WIM file
 * includes a string of XML that describes the images contained in the WIM.
 *
 * See wimlib_get_xml_data() to read the XML data into memory instead.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file, which does not necessarily
 * 	have to be standalone (e.g. it could be part of a split WIM).
 * @param fp
 * 	@c stdout, or a FILE* opened for writing, to extract the data to.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@p wim is not a ::WIMStruct that was created by wimlib_open_wim().
 * @retval ::WIMLIB_ERR_NOMEM
 * @retval ::WIMLIB_ERR_READ
 * @retval ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 * 	Failed to read the XML data from the WIM.
 * @retval ::WIMLIB_ERR_WRITE
 * 	Failed to completely write the XML data to @p fp.
 */
extern int
wimlib_extract_xml_data(WIMStruct *wim, FILE *fp);

/**
 * @ingroup G_general
 *
 * Frees all memory allocated for a WIMStruct and closes all files associated
 * with it.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 *
 * @return This function has no return value.
 */
extern void
wimlib_free(WIMStruct *wim);

/**
 * @ingroup G_general
 *
 * Converts a ::wimlib_compression_type value into a string.
 *
 * @param ctype
 * 	::WIMLIB_COMPRESSION_TYPE_NONE, ::WIMLIB_COMPRESSION_TYPE_LZX,
 * 	::WIMLIB_COMPRESSION_TYPE_XPRESS, or another value.
 *
 * @return
 * 	A statically allocated string: "None", "LZX", "XPRESS", or "Invalid",
 * 	respectively.
 */
extern const wimlib_tchar *
wimlib_get_compression_type_string(int ctype);

/**
 * @ingroup G_general
 *
 * Converts an error code into a string describing it.
 *
 * @param code
 * 	The error code returned by one of wimlib's functions.
 *
 * @return
 * 	Pointer to a statically allocated string describing the error code,
 * 	or @c NULL if the error code is not valid.
 */
extern const wimlib_tchar *
wimlib_get_error_string(enum wimlib_error_code code);

/**
 * @ingroup G_wim_information
 *
 * Returns the description of the specified image.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file that does not necessarily have
 * 	to be standalone (e.g. it could be part of a split WIM).
 * @param image
 * 	The number of the image, numbered starting at 1.
 *
 * @return
 * 	The description of the image, or @c NULL if there is no such image, or
 * 	@c NULL if the specified image has no description.  The description
 * 	string is in library-internal memory and may not be modified or freed;
 * 	in addition, the string will become invalid if the description of the
 * 	image is changed, the image is deleted, or the ::WIMStruct is destroyed.
 */
extern const wimlib_tchar *
wimlib_get_image_description(const WIMStruct *wim, int image);

/**
 * @ingroup G_wim_information
 *
 * Returns the name of the specified image.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file that does not necessarily have
 * 	to be standalone (e.g. it could be part of a split WIM).
 * @param image
 * 	The number of the image, numbered starting at 1.
 *
 * @return
 * 	The name of the image, or @c NULL if there is no such image, or an empty
 * 	string if the image is unnamed.  The name string is in
 * 	library-internal memory and may not be modified or freed; in addition,
 * 	the string will become invalid if the name of the image is changed, the
 * 	image is deleted, or the ::WIMStruct is destroyed.
 */
extern const wimlib_tchar *
wimlib_get_image_name(const WIMStruct *wim, int image);


/**
 * @ingroup G_wim_information
 *
 * Get basic information about a WIM file.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file that does not necessarily have
 * 	to be standalone (e.g. it could be part of a split WIM).
 * @param info
 *	A ::wimlib_wim_info structure that will be filled in with information
 *	about the WIM file.
 * @return
 *	0
 */
extern int
wimlib_get_wim_info(WIMStruct *wim, struct wimlib_wim_info *info);

/**
 * @ingroup G_wim_information
 *
 * Read the XML data of a WIM file into an in-memory buffer.  Every WIM file
 * includes a string of XML that describes the images contained in the WIM.
 *
 * See wimlib_extract_xml_data() to extract the XML data to a file stream
 * instead.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file, which does not necessarily
 * 	have to be standalone (e.g. it could be part of a split WIM).
 * @param buf_ret
 *	On success, a pointer to an allocated buffer containing the raw UTF16-LE
 *	XML data is written to this location.
 * @param bufsize_ret
 *	The size of the XML data in bytes is written to this location.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@p wim is not a ::WIMStruct that was created by wimlib_open_wim(), or
 * 	@p buf_ret or @p bufsize_ret was @c NULL.
 * @retval ::WIMLIB_ERR_NOMEM
 * @retval ::WIMLIB_ERR_READ
 * @retval ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 * 	Failed to read the XML data from the WIM.
 */
extern int
wimlib_get_xml_data(WIMStruct *wim, void **buf_ret, size_t *bufsize_ret);

/**
 * @ingroup G_general
 *
 * Initialization function for wimlib.  Call before using any other wimlib
 * function except wimlib_set_print_errors().  If not done manually, this
 * function will be called automatically with @p init_flags set to
 * ::WIMLIB_INIT_FLAG_ASSUME_UTF8.  This function does nothing if called again
 * after it has already successfully run.
 *
 * @param init_flags
 *	Bitwise OR of flags prefixed with WIMLIB_INIT_FLAG.
 *
 * @return 0 on success; nonzero on failure.  Currently, only the following
 * error code is defined:
 *
 * @retval ::WIMLIB_ERR_INSUFFICIENT_PRIVILEGES
 *	::WIMLIB_INIT_FLAG_STRICT_APPLY_PRIVILEGES and/or
 *	::WIMLIB_INIT_FLAG_STRICT_CAPTURE_PRIVILEGES were specified in @p
 *	init_flags, but the corresponding privileges could not be acquired.
 */
extern int
wimlib_global_init(int init_flags);

/**
 * @ingroup G_general
 *
 * Cleanup function for wimlib.  You are not required to call this function, but
 * it will release any global resources allocated by the library.
 */
extern void
wimlib_global_cleanup(void);

/**
 * @ingroup G_wim_information
 *
 * Determines if an image name is already used by some image in the WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param name
 * 	The name to check.
 *
 * @return
 * 	@c true if there is already an image in @p wim named @p name; @c false
 * 	if there is no image named @p name in @p wim.  If @p name is @c NULL or
 * 	the empty string, @c false is returned.
 */
extern bool
wimlib_image_name_in_use(const WIMStruct *wim, const wimlib_tchar *name);

/**
 * @ingroup G_wim_information
 *
 * Iterate through a file or directory tree in the WIM image.  By specifying
 * appropriate flags and a callback function, you can get the attributes of a
 * file in the WIM, get a directory listing, or even get a listing of the entire
 * WIM image.
 *
 * @param wim
 *	The WIM containing the image(s) over which to iterate, specified as a
 *	pointer to the ::WIMStruct for a standalone WIM file, a delta WIM file,
 *	or part 1 of a split WIM.  In the case of a WIM file that is not
 *	standalone, this ::WIMStruct should have had any needed external
 *	resources previously referenced using wimlib_reference_resources() or
 *	wimlib_reference_resource_files().  If not, see
 *	::WIMLIB_ITERATE_DIR_TREE_FLAG_RESOURCES_NEEDED for information about
 *	the behavior when resources are missing.
 *
 * @param image
 *	The 1-based number of the image in @p wim that contains the files or
 *	directories to iterate over, or ::WIMLIB_ALL_IMAGES to repeat the same
 *	iteration on all images in the WIM.
 *
 * @param path
 *	Path in the WIM image at which to do the iteration.
 *
 * @param flags
 *	Bitwise OR of flags prefixed with WIMLIB_ITERATE_DIR_TREE_FLAG.
 *
 * @param cb
 *	A callback function that will receive each directory entry.
 *
 * @param user_ctx
 *	An extra parameter that will always be passed to the callback function
 *	@p cb.
 *
 * @return Normally, returns 0 if all calls to @p cb returned 0; otherwise the
 * first nonzero value that was returned from @p cb.  However, additional error
 * codes may be returned, including the following:
 *
 * @retval ::WIMLIB_ERR_PATH_DOES_NOT_EXIST
 *	@p path did not exist in the WIM image.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Failed to allocate memory needed to create a ::wimlib_dir_entry.
 *
 * This function can additionally return ::WIMLIB_ERR_DECOMPRESSION,
 * ::WIMLIB_ERR_INVALID_METADATA_RESOURCE, ::WIMLIB_ERR_METADATA_NOT_FOUND,
 * ::WIMLIB_ERR_NOMEM, ::WIMLIB_ERR_READ, or
 * ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE, all of which indicate failure (for
 * different reasons) to read the metadata resource for an image over which
 * iteration needed to be done.
 */
extern int
wimlib_iterate_dir_tree(WIMStruct *wim, int image, const wimlib_tchar *path,
			int flags,
			wimlib_iterate_dir_tree_callback_t cb, void *user_ctx);

/**
 * @ingroup G_wim_information
 *
 * Iterate through the lookup table of a WIM file.  This can be used to directly
 * get a listing of the unique resources contained in a WIM file over all
 * images.  Both file resources and metadata resources are included.  However,
 * only resources actually included in the file represented by @a wim, plus
 * explicitly referenced external resources (via wimlib_reference_resources() or
 * wimlib_reference_resource_files()) are included in the iteration.  For
 * example, if @p wim represents just one part of a split WIM, then only
 * resources in that part will be included, unless other resources were
 * explicitly referenced.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file that does not necessarily have
 * 	to be standalone (e.g. it could be part of a split WIM).
 *
 * @param flags
 *	Reserved; set to 0.
 *
 * @param cb
 *	A callback function that will receive each resource.
 *
 * @param user_ctx
 *	An extra parameter that will always be passed to the callback function
 *	@p cb.
 *
 * @return 0 if all calls to @p cb returned 0; otherwise the first nonzero value
 * that was returned from @p cb.
 */
extern int
wimlib_iterate_lookup_table(WIMStruct *wim, int flags,
			    wimlib_iterate_lookup_table_callback_t cb,
			    void *user_ctx);

/**
 * @ingroup G_nonstandalone_wims
 *
 * Joins a split WIM into a stand-alone one-part WIM.
 *
 * @param swms
 * 	An array of strings that gives the filenames of all parts of the split
 * 	WIM.  No specific order is required, but all parts must be included with
 * 	no duplicates.
 * @param num_swms
 * 	Number of filenames in @p swms.
 * @param swm_open_flags
 *	Open flags for the split WIM parts (e.g.
 *	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY).
 * @param wim_write_flags
 * 	Bitwise OR of relevant flags prefixed with WIMLIB_WRITE_FLAG, which will
 * 	be used to write the joined WIM.
 * @param output_path
 * 	The path to write the joined WIM file to.
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.  This function may return most error
 * codes that can be returned by wimlib_open_wim() and wimlib_write(), as well
 * as the following error code:
 *
 * @retval ::WIMLIB_ERR_SPLIT_INVALID
 * 	The split WIMs do not form a valid WIM because they do not include all
 * 	the parts of the original WIM, there are duplicate parts, or not all the
 * 	parts have the same GUID and compression type.
 *
 * Note: wimlib is generalized enough that this function is not actually needed
 * to join a split WIM; instead, you could open the first part of the split WIM,
 * then reference the other parts with wimlib_reference_resource_files(), then
 * write the joined WIM using wimlib_write().  However, wimlib_join() provides
 * an easy-to-use wrapper around this that has some advantages (e.g.  extra
 * sanity checks).
 */
extern int
wimlib_join(const wimlib_tchar * const *swms,
	    unsigned num_swms,
	    const wimlib_tchar *output_path,
	    int swm_open_flags,
	    int wim_write_flags,
	    wimlib_progress_func_t progress_func);


/**
 * @ingroup G_mounting_wim_images
 *
 * Mounts an image in a WIM file on a directory read-only or read-write.
 *
 * As this is implemented using FUSE (Filesystme in UserSpacE), this is not
 * supported if wimlib was configured with @c --without-fuse.  This includes
 * Windows builds of wimlib; ::WIMLIB_ERR_UNSUPPORTED will be returned in such
 * cases.
 *
 * Calling this function daemonizes the process, unless
 * ::WIMLIB_MOUNT_FLAG_DEBUG was specified or an early occur occurs.  If the
 * mount is read-write (::WIMLIB_MOUNT_FLAG_READWRITE specified), modifications
 * to the WIM are staged in a temporary directory.
 *
 * It is safe to mount multiple images from the same underlying WIM file
 * read-only at the same time, but only if different ::WIMStruct's are used.  It
 * is @b not safe to mount multiple images from the same WIM file read-write at
 * the same time.
 *
 * wimlib_mount_image() cannot be used on an image that was exported with
 * wimlib_export_image() while the dentry trees for both images are still in
 * memory.  In addition, wimlib_mount_image() may not be used to mount an image
 * that already has modifications pending (e.g. an image added with
 * wimlib_add_image()).
 *
 * @param wim
 * 	Pointer to the ::WIMStruct containing the image to be mounted.
 * @param image
 * 	The number of the image to mount, indexed starting from it.  It must be
 * 	an existing, single image.
 * @param dir
 * 	The path to an existing empty directory to mount the image on.
 * @param mount_flags
 * 	Bitwise OR of the flags prefixed with WIMLIB_MOUNT_FLAG.
 * @param staging_dir
 * 	If non-NULL, the name of a directory in which the staging directory will
 * 	be created.  Ignored if ::WIMLIB_MOUNT_FLAG_READWRITE is not specified
 * 	in @p mount_flags.  If left @c NULL, the staging directory is created in
 * 	the same directory as the WIM file that @p wim was originally read from.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_ALREADY_LOCKED
 * 	A read-write mount was requested, but an an exclusive advisory lock on
 * 	the on-disk WIM file could not be acquired because another thread or
 * 	process has mounted an image from the WIM read-write or is currently
 * 	modifying the WIM in-place.
 * @retval ::WIMLIB_ERR_FUSE
 * 	A non-zero status was returned by @c fuse_main().
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p image does not specify an existing, single image in @p wim.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@p image is shared among multiple ::WIMStruct's as a result of a call to
 * 	wimlib_export_image(), or @p image has been added with
 * 	wimlib_add_image().
 * @retval ::WIMLIB_ERR_MKDIR
 * 	::WIMLIB_MOUNT_FLAG_READWRITE was specified in @p mount_flags, but the
 * 	staging directory could not be created.
 * @retval ::WIMLIB_ERR_NOTDIR
 * 	Could not determine the current working directory.
 * @retval ::WIMLIB_ERR_RESOURCE_NOT_FOUND
 *	One of the dentries in the image referenced a stream not present in the
 *	WIM's lookup table (or in any of the lookup tables of the split WIM
 *	parts).
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	::WIMLIB_MOUNT_FLAG_READWRITE was specified in @p mount_flags, but @p
 *	wim is considered read-only because of any of the reasons mentioned in
 *	the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS flag.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	Mounting is not supported, either because the platform is Windows, or
 * 	because the platform is UNIX-like and wimlib was compiled with @c
 * 	--without-fuse.
 *
 * This function can additionally return ::WIMLIB_ERR_DECOMPRESSION,
 * ::WIMLIB_ERR_INVALID_METADATA_RESOURCE, ::WIMLIB_ERR_METADATA_NOT_FOUND,
 * ::WIMLIB_ERR_NOMEM, ::WIMLIB_ERR_READ, or
 * ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE, all of which indicate failure (for
 * different reasons) to read the metadata resource for the image to mount.
 */
extern int
wimlib_mount_image(WIMStruct *wim,
		   int image,
		   const wimlib_tchar *dir,
		   int mount_flags,
		   const wimlib_tchar *staging_dir);

/**
 * @ingroup G_creating_and_opening_wims
 *
 * Opens a WIM file and creates a ::WIMStruct for it.
 *
 * @param wim_file
 * 	The path to the WIM file to open.
 *
 * @param open_flags
 * 	Bitwise OR of flags prefixed with WIMLIB_OPEN_FLAG.
 *
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.  Currently, the only messages sent
 * 	will be ::WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY, and only if
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY was specified in @p open_flags.
 *
 * @param wim_ret
 * 	On success, a pointer to an opaque ::WIMStruct for the opened WIM file
 * 	is written to the memory location pointed to by this parameter.  The
 * 	::WIMStruct can be freed using using wimlib_free() when finished with
 * 	it.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_IMAGE_COUNT
 * 	The WIM is not the non-first part of a split WIM, and the number of
 * 	metadata resources found in the WIM did not match the image count given
 * 	in the WIM header, or the number of &lt;IMAGE&gt; elements in the XML
 * 	data for the WIM did not match the image count given in the WIM header.
 * @retval ::WIMLIB_ERR_INTEGRITY
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY was specified in @p open_flags and @p
 * 	wim_file contains an integrity table, but the SHA1 message digest for a
 * 	chunk of the WIM does not match the corresponding message digest given
 * 	in the integrity table.
 * @retval ::WIMLIB_ERR_INVALID_CHUNK_SIZE
 * 	Resources in @p wim_file are compressed, but the chunk size was invalid
 * 	for the WIM's compression format.
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 * 	The header of @p wim_file says that resources in the WIM are compressed,
 * 	but the header flag indicating LZX or XPRESS compression is not set.
 * @retval ::WIMLIB_ERR_INVALID_HEADER
 * 	The header of @p wim_file was otherwise invalid.
 * @retval ::WIMLIB_ERR_INVALID_INTEGRITY_TABLE
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY was specified in @p open_flags and @p
 * 	wim_file contains an integrity table, but the integrity table is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY
 * 	The lookup table for the WIM contained duplicate entries that are not
 * 	for metadata resources, or it contained an entry with a SHA1 message
 * 	digest of all 0's.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	@p wim_ret was @c NULL.
 * @retval ::WIMLIB_ERR_IS_SPLIT_WIM
 * 	@p wim_file is a split WIM and ::WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT was
 * 	specified in @p open_flags.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocated needed memory.
 * @retval ::WIMLIB_ERR_NOT_A_WIM_FILE
 * 	@p wim_file does not begin with the expected magic characters.
 * @retval ::WIMLIB_ERR_OPEN
 * 	Failed to open the file @p wim_file for reading.
 * @retval ::WIMLIB_ERR_READ
 * 	Failed to read data from @p wim_file.
 * @retval ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 *	Unexpected end-of-file while reading data from @p wim_file.
 * @retval ::WIMLIB_ERR_UNKNOWN_VERSION
 * 	A number other than 0x10d00 is written in the version field of the WIM
 * 	header of @p wim_file.  (May be a pre-Vista WIM.)
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	::WIMLIB_OPEN_FLAG_WRITE_ACCESS was specified but the WIM file was
 *	considered read-only because of any of the reasons mentioned in the
 *	documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS flag.
 * @retval ::WIMLIB_ERR_XML
 * 	The XML data for @p wim_file is invalid.
 */
extern int
wimlib_open_wim(const wimlib_tchar *wim_file,
		int open_flags,
		WIMStruct **wim_ret,
		wimlib_progress_func_t progress_func);

/**
 * @ingroup G_writing_and_overwriting_wims
 *
 * Overwrites the file that the WIM was originally read from, with changes made.
 * This only makes sense for ::WIMStruct's obtained from wimlib_open_wim()
 * rather than wimlib_create_new_wim().
 *
 * There are two ways that a WIM may be overwritten.  The first is to do a full
 * rebuild.  In this mode, the new WIM is written to a temporary file and then
 * renamed to the original file after it is has been completely written.  The
 * temporary file is made in the same directory as the original WIM file.  A
 * full rebuild may take a while, but can be used even if images have been
 * modified or deleted, will produce a WIM with no holes, and has little chance
 * of unintentional data loss because the temporary WIM is fsync()ed before
 * being renamed to the original WIM.
 *
 * The second way to overwrite a WIM is by appending to the end of it and
 * overwriting the header.  This can be much faster than a full rebuild, but the
 * disadvantage is that some space will be wasted.  Writing a WIM in this mode
 * begins with writing any new file resources *after* everything in the old WIM,
 * even though this will leave a hole where the old lookup table, XML data, and
 * integrity were.  This is done so that the WIM remains valid even if the
 * operation is aborted mid-write.  The WIM header is only overwritten at the
 * very last moment, and up until that point the WIM will be seen as the old
 * version.
 *
 * By default, wimlib_overwrite() does the append-style overwrite described
 * above, unless resources in the WIM are arranged in an unusual way or if
 * images have been deleted from the WIM.  Use the flag
 * ::WIMLIB_WRITE_FLAG_REBUILD to explicitly request a full rebuild, and use the
 * ::WIMLIB_WRITE_FLAG_SOFT_DELETE to request the in-place overwrite even if
 * images have been deleted from the WIM.
 *
 * In the temporary-file overwrite mode, no changes are made to the WIM on
 * failure, and the temporary file is deleted if possible.  Abnormal termination
 * of the program will result in the temporary file being orphaned.  In the
 * direct append mode, the WIM is truncated to the original length on failure;
 * and while abnormal termination of the program will result in extra data
 * appended to the original WIM, it should still be a valid WIM.
 *
 * If this function completes successfully, no more functions should be called
 * on @p wim other than wimlib_free().  You must use wimlib_open_wim() to read
 * the WIM file anew.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for the WIM file to write.  There may have
 * 	been in-memory changes made to it, which are then reflected in the
 * 	output file.
 * @param write_flags
 * 	Bitwise OR of relevant flags prefixed with WIMLIB_WRITE_FLAG.
 * @param num_threads
 * 	Number of threads to use for compression (see wimlib_write()).
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.  This function may return most error
 * codes returned by wimlib_write() as well as the following error codes:
 *
 * @retval ::WIMLIB_ERR_ALREADY_LOCKED
 * 	The WIM was going to be modified in-place (with no temporary file), but
 * 	an exclusive advisory lock on the on-disk WIM file could not be acquired
 * 	because another thread or process has mounted an image from the WIM
 * 	read-write or is currently modifying the WIM in-place.
 * @retval ::WIMLIB_ERR_NO_FILENAME
 * 	@p wim corresponds to a WIM created with wimlib_create_new_wim() rather
 * 	than a WIM read with wimlib_open_wim().
 * @retval ::WIMLIB_ERR_RENAME
 * 	The temporary file that the WIM was written to could not be renamed to
 * 	the original filename of @p wim.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	The WIM file is considered read-only because of any of the reasons
 *	mentioned in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS
 *	flag.
 */
extern int
wimlib_overwrite(WIMStruct *wim, int write_flags, unsigned num_threads,
		 wimlib_progress_func_t progress_func);

/**
 * @ingroup G_wim_information
 *
 * Prints information about one image, or all images, contained in a WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param image
 * 	The image about which to print information.  Can be the number of an
 * 	image, or ::WIMLIB_ALL_IMAGES to print information about all images in the
 * 	WIM.
 *
 * @return This function has no return value.  No error checking is done when
 * printing the information.  If @p image is invalid, an error message is
 * printed.
 */
extern void
wimlib_print_available_images(const WIMStruct *wim, int image);

/**
 * @ingroup G_wim_information
 *
 * Deprecated in favor of wimlib_get_wim_info(), which provides the information
 * in a way that can be accessed programatically.
 */
extern void
wimlib_print_header(const WIMStruct *wim) _wimlib_deprecated;

/**
 * @ingroup G_wim_information
 *
 * Deprecated in favor of wimlib_iterate_dir_tree(), which provides the
 * information in a way that can be accessed programatically.
 */
extern int
wimlib_print_metadata(WIMStruct *wim, int image) _wimlib_deprecated;

/**
 * @ingroup G_nonstandalone_wims
 *
 * Reference resources from other WIM files or split WIM parts.  This function
 * can be used on WIMs that are not standalone, such as split or "delta" WIMs,
 * to load needed resources (that is, "streams" keyed by SHA1 message digest)
 * from other files, before calling a function such as wimlib_extract_image()
 * that requires the resources to be present.
 *
 * @param wim
 *	The ::WIMStruct for a WIM that contains metadata resources, but is not
 *	necessarily "standalone".  In the case of split WIMs, this should be the
 *	first part, since only the first part contains the metadata resources.
 *	In the case of delta WIMs, this should be the delta WIM rather than the
 *	WIM on which it is based.
 * @param resource_wimfiles_or_globs
 *	Array of paths to WIM files and/or split WIM parts to reference.
 *	Alternatively, when ::WIMLIB_REF_FLAG_GLOB_ENABLE is specified in @p
 *	ref_flags, these are treated as globs rather than literal paths.  That
 *	is, using this function you can specify zero or more globs, each of
 *	which expands to one or more literal paths.
 * @param count
 *	Number of entries in @p resource_wimfiles_or_globs.
 * @param ref_flags
 *	Bitwise OR of ::WIMLIB_REF_FLAG_GLOB_ENABLE and/or
 *	::WIMLIB_REF_FLAG_GLOB_ERR_ON_NOMATCH.
 * @param open_flags
 *	Additional open flags, such as ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY, to
 *	pass to internal calls to wimlib_open_wim() on the reference files.
 * @param progress_func
 *	Passed to internal calls to wimlib_open_wim() on the reference files.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_GLOB_HAD_NO_MATCHES
 *	One of the specified globs did not match any paths (only with both
 *	::WIMLIB_REF_FLAG_GLOB_ENABLE and ::WIMLIB_REF_FLAG_GLOB_ERR_ON_NOMATCH
 *	specified in @p ref_flags).
 * @retval ::WIMLIB_ERR_NOMEM
 *	Failed to allocate memory.
 * @retval ::WIMLIB_ERR_READ
 *	I/O or permissions error while processing a file glob.
 *
 * This function can additionally return most values that can be returned by
 * wimlib_open_wim().
 */
extern int
wimlib_reference_resource_files(WIMStruct *wim,
				const wimlib_tchar * const *resource_wimfiles_or_globs,
				unsigned count,
				int ref_flags,
				int open_flags,
				wimlib_progress_func_t progress_func);

/**
 * @ingroup G_nonstandalone_wims
 *
 * Similar to wimlib_reference_resource_files(), but operates at a lower level
 * where the caller must open the ::WIMStruct for each referenced file itself.
 *
 * @param wim
 *	The ::WIMStruct for a WIM that contains metadata resources, but is not
 *	necessarily "standalone".  In the case of split WIMs, this should be the
 *	first part, since only the first part contains the metadata resources.
 * @param resource_wims
 *	Array of pointers to the ::WIMStruct's for additional resource WIMs or
 *	split WIM parts to reference.
 * @param num_resource_wims
 *	Number of entries in @p resource_wims.
 * @param ref_flags
 *	Currently ignored (set to 0).
 *
 * @return 0 on success; nonzero on error.  On success, the ::WIMStruct's of the
 * @p resource_wims are referenced internally by @p wim and must not be freed
 * with wimlib_free() or overwritten with wimlib_overwrite() until @p wim has
 * been freed with wimlib_free(), or immediately before freeing @p wim with
 * wimlib_free().
 *
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	@p wim was @c NULL, or @p num_resource_wims was nonzero but @p
 *	resource_wims was @c NULL, or an entry in @p resource_wims was @p NULL.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Failed to allocate memory.
 */
extern int
wimlib_reference_resources(WIMStruct *wim, WIMStruct **resource_wims,
			   unsigned num_resource_wims, int ref_flags);

/**
 * @ingroup G_modifying_wims
 *
 * Declares that a newly added image is mostly the same as a prior image, but
 * captured at a later point in time, possibly with some modifications in the
 * intervening time.  This is designed to be used in incremental backups of the
 * same filesystem or directory tree.
 *
 * This function compares the metadata of the directory tree of the newly added
 * image against that of the old image.  Any files that are present in both the
 * newly added image and the old image and have timestamps that indicate they
 * haven't been modified are deemed not to have been modified and have their
 * SHA1 message digest copied from the old image.  Because of this and because
 * WIM uses single-instance streams, such files need not be read from the
 * filesystem when the WIM is being written or overwritten.  Note that these
 * unchanged files will still be "archived" and will be logically present in the
 * new image; the optimization is that they don't need to actually be read from
 * the filesystem because the WIM already contains them.
 *
 * This function is provided to optimize incremental backups.  The resulting WIM
 * file will still be the same regardless of whether this function is called.
 * (This is, however, assuming that timestamps have not been manipulated or
 * unmaintained as to trick this function into thinking a file has not been
 * modified when really it has.  To partly guard against such cases, other
 * metadata such as file sizes will be checked as well.)
 *
 * This function must be called after adding the new image (e.g. with
 * wimlib_add_image()), but before writing the updated WIM file (e.g. with
 * wimlib_overwrite()).
 *
 * @param wim
 *	Pointer to the ::WIMStruct for a WIM.
 * @param new_image
 *	1-based index in the WIM of the newly added image.  This image can have
 *	been added with wimlib_add_image() or wimlib_add_image_multisource(), or
 *	wimlib_add_empty_image() followed by wimlib_update_image().
 * @param template_wim
 *	The ::WIMStruct for the WIM containing the template image.  This can be
 *	the same as @p wim, or it can be a different ::WIMStruct.
 * @param template_image
 *	1-based index in the WIM of a template image that reflects a prior state
 *	of the directory tree being captured.
 * @param flags
 *	Reserved; must be 0.
 * @param progress_func
 *	Currently ignored, but reserved for a function that will be called with
 *	information about the operation.  Use NULL if no additional information
 *	is desired.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 *	@p new_image and/or @p template_image were not a valid image indices in
 *	the WIM.
 * @retval ::WIMLIB_ERR_METADATA_NOT_FOUND
 *	The specified ::WIMStruct did not actually contain the metadata resource
 *	for the new or template image; for example, it was a non-first part of a
 *	split WIM.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	@p new_image was equal to @p template_image, or @p new_image specified
 *	an image that had not been modified since opening the WIM.
 *
 * This function can additionally return ::WIMLIB_ERR_DECOMPRESSION,
 * ::WIMLIB_ERR_INVALID_METADATA_RESOURCE, ::WIMLIB_ERR_METADATA_NOT_FOUND,
 * ::WIMLIB_ERR_NOMEM, ::WIMLIB_ERR_READ, or
 * ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE, all of which indicate failure (for
 * different reasons) to read the metadata resource for the template image.
 */
extern int
wimlib_reference_template_image(WIMStruct *wim, int new_image,
				WIMStruct *template_wim, int template_image,
				int flags, wimlib_progress_func_t progress_func);

/**
 * @ingroup G_wim_information
 *
 * Translates a string specifying the name or number of an image in the WIM into
 * the number of the image.  The images are numbered starting at 1.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM.
 * @param image_name_or_num
 * 	A string specifying the name or number of an image in the WIM.  If it
 * 	parses to a positive integer, this integer is taken to specify the
 * 	number of the image, indexed starting at 1.  Otherwise, it is taken to
 * 	be the name of an image, as given in the XML data for the WIM file.  It
 * 	also may be the keyword "all" or the string "*", both of which will
 * 	resolve to ::WIMLIB_ALL_IMAGES.
 * 	<br/> <br/>
 * 	There is no way to search for an image actually named "all", "*", or an
 * 	integer number, or an image that has no name.  However, you can use
 * 	wimlib_get_image_name() to get the name of any image.
 *
 * @return
 * 	If the string resolved to a single existing image, the number of that
 * 	image, indexed starting at 1, is returned.  If the keyword "all" or "*"
 * 	was specified, ::WIMLIB_ALL_IMAGES is returned.  Otherwise,
 * 	::WIMLIB_NO_IMAGE is returned.  If @p image_name_or_num was @c NULL or
 * 	the empty string, ::WIMLIB_NO_IMAGE is returned, even if one or more
 * 	images in @p wim has no name.
 */
extern int
wimlib_resolve_image(WIMStruct *wim,
		     const wimlib_tchar *image_name_or_num);

/**
 * @ingroup G_modifying_wims
 *
 * Changes the description of an image in the WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM.
 * @param image
 * 	The number of the image for which to change the description.
 * @param description
 * 	The new description to give the image.  It may be @c NULL, which
 * 	indicates that the image is to be given no description.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p image does not specify a single existing image in @p wim.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate the memory needed to duplicate the @p description
 * 	string.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	@p wim is considered read-only because of any of the reasons mentioned
 *	in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS flag.
 */
extern int
wimlib_set_image_descripton(WIMStruct *wim, int image,
			    const wimlib_tchar *description);

/**
 * @ingroup G_writing_and_overwriting_wims
 *
 * Set the compression chunk size of a WIM to use in subsequent calls to
 * wimlib_write() or wimlib_overwrite().
 *
 * A compression chunk size will result in a greater compression ratio, but the
 * speed of random access to the WIM will be reduced, and the effect of an
 * increased compression chunk size is limited by the size of each file being
 * compressed.
 *
 * <b>WARNING: Microsoft's software is seemingly incompatible with LZX chunk
 * sizes other than 32768.  Chunk sizes other than 32768 (for any format) are
 * also incompatible with wimlib v1.5.3 and earlier.</b>
 *
 * @param wim
 *	::WIMStruct for a WIM.
 * @param out_chunk_size
 *	The chunk size (in bytes) to set.  The valid chunk sizes are dependent
 *	on the compression format.  The XPRESS compression format supports chunk
 *	sizes that are powers of 2 with exponents between 15 and 26 inclusively,
 *	whereas the LZX compression format supports chunk sizes that are powers
 *	of 2 with exponents between 15 and 21 inclusively.  As a special case,
 *	if @p out_chunk_size is specified as 0, the chunk size is set to the
 *	default for the currently selected output compression type.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_CHUNK_SIZE
 *	@p ctype is not a supported chunk size.
 */
extern int
wimlib_set_output_chunk_size(WIMStruct *wim, uint32_t chunk_size);

/**
 * @ingroup G_writing_and_overwriting_wims
 *
 * Similar to wimlib_set_output_chunk_size(), but set the chunk size for writing
 * packed streams.
 */
extern int
wimlib_set_output_pack_chunk_size(WIMStruct *wim, uint32_t chunk_size);

/**
 * @ingroup G_writing_and_overwriting_wims
 *
 * Set the compression type of a WIM to use in subsequent calls to
 * wimlib_write() or wimlib_overwrite().
 *
 * @param wim
 *	::WIMStruct for a WIM.
 * @param ctype
 *	The compression type to set (one of ::wimlib_compression_type).  If this
 *	compression type is incompatible with the current output chunk size
 *	(either the default or as set with wimlib_set_output_chunk_size()), the
 *	output chunk size is reset to the default for that compression type.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 *	@p ctype did not specify a valid compression type.
 */
extern int
wimlib_set_output_compression_type(WIMStruct *wim, int ctype);

/**
 * @ingroup G_writing_and_overwriting_wims
 *
 * Similar to wimlib_set_output_compression_type(), but set the compression type
 * for writing packed streams.
 */
extern int
wimlib_set_output_pack_compression_type(WIMStruct *wim, int ctype);

/**
 * @ingroup G_modifying_wims
 *
 * Set basic information about a WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM.
 * @param info
 *	A struct ::wimlib_wim_info that contains the information to set.  Only
 *	the information explicitly specified in the @p which flags need be
 *	valid.
 * @param which
 *	Flags that specify which information to set.  This is a bitwise OR of
 *	::WIMLIB_CHANGE_READONLY_FLAG, ::WIMLIB_CHANGE_GUID,
 *	::WIMLIB_CHANGE_BOOT_INDEX, and/or ::WIMLIB_CHANGE_RPFIX_FLAG.
 *
 * @return 0 on success; nonzero on failure.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	The WIM file is considered read-only because of any of the reasons
 *	mentioned in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS
 *	flag.  However, as a special case, if you are using
 *	::WIMLIB_CHANGE_READONLY_FLAG to unset the readonly flag, then this
 *	function will not fail due to the readonly flag being previously set.
 * @retval ::WIMLIB_ERR_IMAGE_COUNT
 *	::WIMLIB_CHANGE_BOOT_INDEX was specified, but
 *	::wimlib_wim_info.boot_index did not specify 0 or a valid 1-based image
 *	index in the WIM.
 */
extern int
wimlib_set_wim_info(WIMStruct *wim, const struct wimlib_wim_info *info,
		    int which);

/**
 * @ingroup G_modifying_wims
 *
 * Changes what is written in the \<FLAGS\> element in the WIM XML data
 * (something like "Core" or "Ultimate")
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM.
 * @param image
 * 	The number of the image for which to change the description.
 * @param flags
 * 	The new \<FLAGS\> element to give the image.  It may be @c NULL, which
 * 	indicates that the image is to be given no \<FLAGS\> element.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p image does not specify a single existing image in @p wim.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate the memory needed to duplicate the @p flags string.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	@p wim is considered read-only because of any of the reasons mentioned
 *	in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS flag.
 */
extern int
wimlib_set_image_flags(WIMStruct *wim, int image, const wimlib_tchar *flags);

/**
 * @ingroup G_modifying_wims
 *
 * Changes the name of an image in the WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM.
 * @param image
 * 	The number of the image for which to change the name.
 * @param name
 *	New name to give the new image.  If @c NULL or empty, the new image is
 *	given no name.  If nonempty, it must specify a name that does not
 *	already exist in @p wim.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_IMAGE_NAME_COLLISION
 * 	There is already an image named @p name in @p wim.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p image does not specify a single existing image in @p wim.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate the memory needed to duplicate the @p name string.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	@p wim is considered read-only because of any of the reasons mentioned
 *	in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS flag.
 */
extern int
wimlib_set_image_name(WIMStruct *wim, int image, const wimlib_tchar *name);

/**
 * @ingroup G_general
 *
 * Set the functions that wimlib uses to allocate and free memory.
 *
 * These settings are global and not per-WIM.
 *
 * The default is to use the default @c malloc() and @c free() from the C
 * library.
 *
 * Please note that some external functions, such as those in @c libntfs-3g, may
 * use the standard memory allocation functions.
 *
 * @param malloc_func
 * 	A function equivalent to @c malloc() that wimlib will use to allocate
 * 	memory.  If @c NULL, the allocator function is set back to the default
 * 	@c malloc() from the C library.
 * @param free_func
 * 	A function equivalent to @c free() that wimlib will use to free memory.
 * 	If @c NULL, the free function is set back to the default @c free() from
 * 	the C library.
 * @param realloc_func
 * 	A function equivalent to @c realloc() that wimlib will use to reallocate
 * 	memory.  If @c NULL, the free function is set back to the default @c
 * 	realloc() from the C library.
 * @return 0
 */
extern int
wimlib_set_memory_allocator(void *(*malloc_func)(size_t),
			    void (*free_func)(void *),
			    void *(*realloc_func)(void *, size_t));

/**
 * @ingroup G_general
 *
 * Sets whether wimlib is to print error messages to @c stderr when a function
 * fails.  These error messages may provide information that cannot be
 * determined only from the error code that is returned.  Not every error will
 * result in an error message being printed.
 *
 * This setting is global and not per-WIM.
 *
 * By default, error messages are not printed.
 *
 * This can be called before wimlib_global_init().
 *
 * @param show_messages
 * 	@c true if error messages are to be printed; @c false if error messages
 * 	are not to be printed.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	@p show_messages was @c true, but wimlib was compiled with the @c
 * 	--without-error-messages option.   Therefore, error messages cannot be
 * 	shown.
 */
extern int
wimlib_set_print_errors(bool show_messages);

/**
 * @ingroup G_nonstandalone_wims
 *
 * Splits a WIM into multiple parts.
 *
 * @param wim
 * 	The ::WIMStruct for the WIM to split.
 * @param swm_name
 * 	Name of the SWM file to create.  This will be the name of the first
 * 	part.  The other parts will have the same name with 2, 3, 4, ..., etc.
 * 	appended before the suffix.
 * @param part_size
 * 	The maximum size per part, in bytes.  Unfortunately, it is not
 * 	guaranteed that this will really be the maximum size per part, because
 * 	some file resources in the WIM may be larger than this size, and the WIM
 * 	file format provides no way to split up file resources among multiple
 * 	WIMs.
 * @param write_flags
 * 	Bitwise OR of relevant flags prefixed with @c WIMLIB_WRITE_FLAG.  These
 * 	flags will be used to write each split WIM part.  Specify 0 here to get
 * 	the default behavior.
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation
 * 	(::WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART and
 * 	::WIMLIB_PROGRESS_MSG_SPLIT_END_PART).
 *
 * @return 0 on success; nonzero on error.  This function may return most error
 * codes that can be returned by wimlib_write() as well as the following error
 * codes:
 *
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@p swm_name was not a nonempty string, or @p part_size was 0.
 *
 * Note: the WIM's uncompressed and compressed resources are not checksummed
 * when they are copied from the joined WIM to the split WIM parts, nor are
 * compressed resources re-compressed (unless explicitly requested with
 * ::WIMLIB_WRITE_FLAG_RECOMPRESS).
 */
extern int
wimlib_split(WIMStruct *wim,
	     const wimlib_tchar *swm_name,
	     uint64_t part_size,
	     int write_flags,
	     wimlib_progress_func_t progress_func);

/**
 * @ingroup G_mounting_wim_images
 *
 * Unmounts a WIM image that was mounted using wimlib_mount_image().
 *
 * The image to unmount is specified by the path to the mountpoint, not the
 * original ::WIMStruct passed to wimlib_mount_image(), which should not be
 * touched and also may have been allocated in a different process.
 *
 * To unmount the image, the process calling this function communicates with the
 * process that is managing the mounted WIM image.  This function blocks until it
 * is known whether the unmount succeeded or failed.  In the case of a
 * read-write mounted WIM, the unmount is not considered to have succeeded until
 * all changes have been saved to the underlying WIM file.
 *
 * @param dir
 * 	The directory that the WIM image was mounted on.
 * @param unmount_flags
 * 	Bitwise OR of the flags ::WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY,
 * 	::WIMLIB_UNMOUNT_FLAG_COMMIT, ::WIMLIB_UNMOUNT_FLAG_REBUILD, and/or
 * 	::WIMLIB_UNMOUNT_FLAG_RECOMPRESS.  None of these flags affect read-only
 * 	mounts.
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.  Currently, only
 * 	::WIMLIB_PROGRESS_MSG_WRITE_STREAMS will be sent.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_DELETE_STAGING_DIR
 * 	The filesystem daemon was unable to remove the staging directory and the
 * 	temporary files that it contains.
 * @retval ::WIMLIB_ERR_FILESYSTEM_DAEMON_CRASHED
 * 	The filesystem daemon appears to have terminated before sending an exit
 * 	status.
 * @retval ::WIMLIB_ERR_FORK
 * 	Could not @c fork() the process.
 * @retval ::WIMLIB_ERR_FUSERMOUNT
 * 	The @b fusermount program could not be executed or exited with a failure
 * 	status.
 * @retval ::WIMLIB_ERR_MQUEUE
 * 	Could not open a POSIX message queue to communicate with the filesystem
 * 	daemon servicing the mounted filesystem, could not send a message
 * 	through the queue, or could not receive a message through the queue.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_OPEN
 * 	The filesystem daemon could not open a temporary file for writing the
 * 	new WIM.
 * @retval ::WIMLIB_ERR_READ
 * 	A read error occurred when the filesystem daemon tried to a file from
 * 	the staging directory
 * @retval ::WIMLIB_ERR_RENAME
 * 	The filesystem daemon failed to rename the newly written WIM file to the
 * 	original WIM file.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	Mounting is not supported, either because the platform is Windows, or
 * 	because the platform is UNIX-like and wimlib was compiled with @c
 * 	--without-fuse.
 * @retval ::WIMLIB_ERR_WRITE
 * 	A write error occurred when the filesystem daemon was writing to the new
 * 	WIM file, or the filesystem daemon was unable to flush changes that had
 * 	been made to files in the staging directory.
 */
extern int
wimlib_unmount_image(const wimlib_tchar *dir,
		     int unmount_flags,
		     wimlib_progress_func_t progress_func);

/**
 * @ingroup G_modifying_wims
 *
 * Update a WIM image by adding, deleting, and/or renaming files or directories.
 *
 * @param wim
 *	Pointer to the ::WIMStruct for the WIM file to update.
 * @param image
 *	The 1-based index of the image in the WIM to update.  It cannot be
 *	::WIMLIB_ALL_IMAGES.
 * @param cmds
 *	An array of ::wimlib_update_command's that specify the update operations
 *	to perform.
 * @param num_cmds
 *	Number of commands in @p cmds.
 * @param update_flags
 *	::WIMLIB_UPDATE_FLAG_SEND_PROGRESS or 0.
 * @param progress_func
 *	If non-NULL, a function that will be called periodically with the
 *	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.  On failure, some but not all of the
 * update commands may have been executed.  No individual update command will
 * have been partially executed.  Possible error codes include:
 *
 * @retval ::WIMLIB_ERR_INVALID_CAPTURE_CONFIG
 *	The capture configuration structure specified for an add command was
 *	invalid.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 *	@p image did not specify a single, existing image in @p wim.
 * @retval ::WIMLIB_ERR_INVALID_OVERLAY
 *	Attempted to perform an add command that conflicted with previously
 *	existing files in the WIM when an overlay was attempted.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	An unknown operation type was specified in the update commands; or,
 *	attempted to execute an add command where ::WIMLIB_ADD_FLAG_NTFS was set
 *	in the @p add_flags, but the same image had previously already been
 *	added from a NTFS volume; or, both ::WIMLIB_ADD_FLAG_RPFIX and
 *	::WIMLIB_ADD_FLAG_NORPFIX were specified in the @p add_flags for one add
 *	command; or, ::WIMLIB_ADD_FLAG_NTFS or ::WIMLIB_ADD_FLAG_RPFIX were
 *	specified in the @p add_flags for an add command in which @p
 *	wim_target_path was not the root directory of the WIM image.
 * @retval ::WIMLIB_ERR_INVALID_REPARSE_DATA
 *	(Windows only):  While executing an add command, tried to capture a
 *	reparse point with invalid data.
 * @retval ::WIMLIB_ERR_IS_DIRECTORY
 *	A delete command without ::WIMLIB_DELETE_FLAG_RECURSIVE specified was
 *	for a WIM path that corresponded to a directory; or, a rename command
 *	attempted to rename a directory to a non-directory.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_NOTDIR
 *	A rename command attempted to rename a directory to a non-directory; or,
 *	an add command was executed that attempted to set the root of the WIM
 *	image as a non-directory; or, a path component used as a directory in a
 *	rename command was not, in fact, a directory.
 * @retval ::WIMLIB_ERR_NOTEMPTY
 *	A rename command attempted to rename a directory to a non-empty
 *	directory.
 * @retval ::WIMLIB_ERR_NTFS_3G
 *	While executing an add command with ::WIMLIB_ADD_FLAG_NTFS specified, an
 *	error occurred while reading data from the NTFS volume using libntfs-3g.
 * @retval ::WIMLIB_ERR_OPEN
 *	Failed to open a file to be captured while executing an add command.
 * @retval ::WIMLIB_ERR_OPENDIR
 *	Failed to open a directory to be captured while executing an add command.
 * @retval ::WIMLIB_ERR_PATH_DOES_NOT_EXIST
 *	A delete command without ::WIMLIB_DELETE_FLAG_FORCE specified was for a
 *	WIM path that did not exist; or, a rename command attempted to rename a
 *	file that does not exist.
 * @retval ::WIMLIB_ERR_READ
 *	While executing an add command, failed to read data from a file or
 *	directory to be captured.
 * @retval ::WIMLIB_ERR_READLINK
 *	While executing an add command, failed to read the target of a symbolic
 *	link or junction point.
 * @retval ::WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED
 *	(Windows only) Failed to perform a reparse point fixup because of
 *	problems with the data of a reparse point.
 * @retval ::WIMLIB_ERR_STAT
 *	While executing an add command, failed to get attributes for a file or
 *	directory.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	::WIMLIB_ADD_FLAG_NTFS was specified in the @p add_flags for an update
 * 	command, but wimlib was configured with the @c --without-ntfs-3g flag;
 * 	or, the platform is Windows and either the ::WIMLIB_ADD_FLAG_UNIX_DATA
 * 	or the ::WIMLIB_ADD_FLAG_DEREFERENCE flags were specified in the @p
 * 	add_flags for an update command.
 * @retval ::WIMLIB_ERR_UNSUPPORTED_FILE
 *	While executing an add command, attempted to capture a file that was not
 *	a supported file type (e.g. a device file).  Only if
 *	::WIMLIB_ADD_FLAG_NO_UNSUPPORTED_EXCLUDE specified in @p the add_flags
 *	for an update command.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	The WIM file is considered read-only because of any of the reasons
 *	mentioned in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS
 *	flag.
 *
 * This function can additionally return ::WIMLIB_ERR_DECOMPRESSION,
 * ::WIMLIB_ERR_INVALID_METADATA_RESOURCE, ::WIMLIB_ERR_METADATA_NOT_FOUND,
 * ::WIMLIB_ERR_NOMEM, ::WIMLIB_ERR_READ, or
 * ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE, all of which indicate failure (for
 * different reasons) to read the metadata resource for an image that needed to
 * be updated.
 */
extern int
wimlib_update_image(WIMStruct *wim,
		    int image,
		    const struct wimlib_update_command *cmds,
		    size_t num_cmds,
		    int update_flags,
		    wimlib_progress_func_t progress_func);

/**
 * @ingroup G_writing_and_overwriting_wims
 *
 * Writes a WIM to a file.
 *
 * This brings in resources from any external locations, such as directory trees
 * or NTFS volumes scanned with wimlib_add_image(), or other WIM files via
 * wimlib_export_image(), and incorporates them into a new on-disk WIM file.
 *
 * By default, the new WIM file is written as stand-alone.  Using the
 * ::WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS flag, a "delta" WIM can be written
 * instead.  However, this function cannot directly write a "split" WIM; use
 * wimlib_split() for that.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM.  There may have been in-memory
 * 	changes made to it, which are then reflected in the output file.
 * @param path
 * 	The path to the file to write the WIM to.
 * @param image
 * 	Normally, specify ::WIMLIB_ALL_IMAGES here.  This indicates that all
 * 	images are to be included in the new on-disk WIM file.  If for some
 * 	reason you only want to include a single image, specify the index of
 * 	that image instead.
 * @param write_flags
 * 	Bitwise OR of any of the flags prefixed with @c WIMLIB_WRITE_FLAG.
 * @param num_threads
 * 	Number of threads to use for compressing data.  If 0, the number of
 * 	threads is taken to be the number of online processors.  Note: if no
 * 	data compression needs to be done, no additional threads will be created
 * 	regardless of this parameter (e.g. if writing an uncompressed WIM, or
 * 	exporting an image from a compressed WIM to another WIM of the same
 * 	compression type without ::WIMLIB_WRITE_FLAG_RECOMPRESS specified in @p
 * 	write_flags).
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.  The possible messages are
 * 	::WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN,
 * 	::WIMLIB_PROGRESS_MSG_WRITE_METADATA_END, and
 * 	::WIMLIB_PROGRESS_MSG_WRITE_STREAMS.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p image does not specify a single existing image in @p wim, and is not
 * 	::WIMLIB_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_HASH
 * 	A file that had previously been scanned for inclusion in the WIM by
 * 	wimlib_add_image() was concurrently modified, so it failed the SHA1
 * 	message digest check.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@p path was @c NULL.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_OPEN
 * 	Failed to open @p path for writing, or some file resources in @p wim
 * 	refer to files in the outside filesystem, and one of these files could
 * 	not be opened for reading.
 * @retval ::WIMLIB_ERR_READ
 * 	An error occurred when trying to read data from the WIM file associated
 * 	with @p wim, or some file resources in @p wim refer to files in the
 * 	outside filesystem, and a read error occurred when reading one of these
 * 	files.
 * @retval ::WIMLIB_ERR_RESOURCE_NOT_FOUND
 *	A stream that needed to be written could not be found in the stream
 *	lookup table of @p wim.  This error can occur if, for example, @p wim is
 *	part of a split WIM but needed resources from the other split WIM parts
 *	were not referenced with wimlib_reference_resources() or
 *	wimlib_reference_resource_files() before the call to wimlib_write().
 * @retval ::WIMLIB_ERR_WRITE
 * 	An error occurred when trying to write data to the new WIM file.
 *
 * This function can additionally return ::WIMLIB_ERR_DECOMPRESSION,
 * ::WIMLIB_ERR_INVALID_METADATA_RESOURCE, ::WIMLIB_ERR_METADATA_NOT_FOUND,
 * ::WIMLIB_ERR_NOMEM, ::WIMLIB_ERR_READ, or
 * ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE, all of which indicate failure (for
 * different reasons) to read the metadata resource for an image that needed to
 * be written.
 */
extern int
wimlib_write(WIMStruct *wim,
	     const wimlib_tchar *path,
	     int image,
	     int write_flags,
	     unsigned num_threads,
	     wimlib_progress_func_t progress_func);

/**
 * @ingroup G_writing_and_overwriting_wims
 *
 * Since wimlib v1.5.0:  Same as wimlib_write(), but write the WIM directly to a
 * file descriptor, which need not be seekable if the write is done in a special
 * pipable WIM format by providing ::WIMLIB_WRITE_FLAG_PIPABLE in @p
 * write_flags.  This can, for example, allow capturing a WIM image and
 * streaming it over the network.  See the documentation for
 * ::WIMLIB_WRITE_FLAG_PIPABLE for more information about pipable WIMs.
 *
 * The file descriptor @p fd will @b not be closed when the write is complete;
 * the calling code is responsible for this.
 *
 * Returns 0 on success; nonzero on failure.  The possible error codes include
 * those that can be returned by wimlib_write() as well as the following:
 *
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	@p fd was not seekable, but ::WIMLIB_WRITE_FLAG_PIPABLE was not
 *	specified in @p write_flags.
 */
extern int
wimlib_write_to_fd(WIMStruct *wim,
		   int fd,
		   int image,
		   int write_flags,
		   unsigned num_threads,
		   wimlib_progress_func_t progress_func);

/**
 * @defgroup G_compression Compression and decompression functions
 *
 * @brief Functions for LZX, XPRESS, and LZMS compression and decompression,
 * exported for convenience only, as they are already used by wimlib internally
 * when appropriate.
 *
 * These functions can be used for general-purpose lossless data compression,
 * but some limitations apply; for example, none of the compressors or
 * decompressors currently support sliding windows, and there also exist
 * slightly different variants of these formats that are not supported
 * unmodified.
 */

/**
 * @ingroup G_compression
 * @{
 */

/** Header for compression parameters to pass to wimlib_create_compressor() or
 * wimlib_set_default_compressor_params().  */
struct wimlib_compressor_params_header {
	/** Size of the parameters, in bytes.  */
	uint32_t size;
};

/** Header for decompression parameters to pass to wimlib_create_decompressor()
 * or wimlib_set_default_decompressor_params() */
struct wimlib_decompressor_params_header {
	/** Size of the parameters, in bytes.  */
	uint32_t size;
};

/** LZX compression parameters that can optionally be passed to
 * wimlib_create_compressor() with the compression type
 * ::WIMLIB_COMPRESSION_TYPE_LZX.  */
struct wimlib_lzx_compressor_params {
	/** hdr.size Must be set to the size of this structure, in bytes.  */
	struct wimlib_compressor_params_header hdr;

	/** Relatively fast LZX compression algorithm with a decent compression
	 * ratio; the suggested default.  */
#define WIMLIB_LZX_ALGORITHM_FAST 0

	/** Slower LZX compression algorithm that provides a better compression
	 * ratio.  */
#define WIMLIB_LZX_ALGORITHM_SLOW 1

	/** Algorithm to use to perform the compression: either
	 * ::WIMLIB_LZX_ALGORITHM_FAST or ::WIMLIB_LZX_ALGORITHM_SLOW.  The
	 * format is still LZX; this refers to the method the code will use to
	 * perform LZX-compatible compression.  */
	uint32_t algorithm : 3;

	/** If set to 1, the default parameters for the specified algorithm are
	 * used rather than the ones specified in the following union.  */
	uint32_t use_defaults : 1;

	union {
		/** Parameters for the fast algorithm.  */
		struct wimlib_lzx_fast_params {
			uint32_t fast_reserved1[10];
		} fast;

		/** Parameters for the slow algorithm.  */
		struct wimlib_lzx_slow_params {
			/** If set to 1, the compressor can output length 2
			 * matches.  If set 0, the compressor only outputs
			 * matches of length 3 or greater.  Suggested value: 1
			 */
			uint32_t use_len2_matches : 1;

			uint32_t slow_reserved1 : 31;

			/** Matches with length (in bytes) longer than this
			 * value are immediately taken without spending time on
			 * minimum-cost measurements.  Suggested value: 32.  */
			uint32_t num_fast_bytes;

			/** Number of passes to compute a match/literal sequence
			 * for each LZX block.  This is for an iterative
			 * algorithm that attempts to minimize the cost of the
			 * match/literal sequence by using a cost model provided
			 * by the previous iteration.  Must be at least 1.
			 * Suggested value: 2.  */
			uint32_t num_optim_passes;

			/** Reserved; set to 0.  */
			uint32_t slow_reserved_blocksplit;

			/** Maximum depth to search for matches at each
			 * position.  Suggested value: 50.  */
			uint32_t max_search_depth;

			/** Maximum number of potentially good matches to
			 * consider for each position.  Suggested value: 3.  */
			uint32_t max_matches_per_pos;

			uint32_t slow_reserved2[2];

			/** Assumed cost of a main symbol with zero frequency.
			 * Must be at least 1 and no more than 16.  Suggested
			 * value: 15.  */
			uint8_t main_nostat_cost;

			/** Assumed cost of a length symbol with zero frequency.
			 * Must be at least 1 and no more than 16.  Suggested
			 * value: 15.  */
			uint8_t len_nostat_cost;

			/** Assumed cost of an aligned symbol with zero
			 * frequency.  Must be at least 1 and no more than 8.
			 * Suggested value: 7.  */
			uint8_t aligned_nostat_cost;

			uint8_t slow_reserved3[5];
		} slow;
	} alg_params;
};

/** Opaque compressor handle.  */
struct wimlib_compressor;

/** Opaque decompressor handle.  */
struct wimlib_decompressor;

/**
 * Set the default compression parameters for the specified compression type.
 * This will affect both explicit and wimlib-internal calls to
 * wimlib_create_compressor().
 *
 * @param ctype
 *	Compression type for which to set the default compression parameters.
 * @param params
 *	Compression-type specific parameters.  This may be @c NULL, in which
 *	case the "default default" parameters are restored.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 *	@p ctype was not a supported compression type.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Not enough memory to duplicate the parameters (perhaps @c params->size
 *	was invalid).
 */
extern int
wimlib_set_default_compressor_params(enum wimlib_compression_type ctype,
				     const struct wimlib_compressor_params_header *params);

/**
 * Allocate a compressor for the specified compression type using the specified
 * parameters.
 *
 * @param ctype
 *	Compression type for which to create the compressor.
 * @param max_block_size
 *	Maximum block size to support.  The exact meaning and allowed values for
 *	this parameter depend on the compression type, but it at least specifies
 *	the maximum allowed value for @p uncompressed_size to wimlib_compress().
 * @param extra_params
 *	An optional pointer to extra compressor parameters for the specified
 *	compression type.  For LZX, a pointer to ::wimlib_lzx_compressor_params
 *	may be specified here.  If left @c NULL, the default parameters are
 *	used.
 * @param compressor_ret
 *	A location into which to return the pointer to the allocated compressor,
 *	which can be used for any number of calls to wimlib_compress() before
 *	being freed with wimlib_free_compressor().
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 *	@p ctype was not a supported compression type.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	The compression parameters were invalid.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Insufficient memory to allocate the compressor.
 */
extern int
wimlib_create_compressor(enum wimlib_compression_type ctype,
			 size_t max_block_size,
			 const struct wimlib_compressor_params_header *extra_params,
			 struct wimlib_compressor **compressor_ret);

/**
 * Losslessly compress a block of data using a compressor previously created
 * with wimlib_create_compressor().
 *
 * @param uncompressed_data
 *	Buffer containing the data to compress.
 * @param uncompressed_size
 *	Size, in bytes, of the data to compress.
 * @param compressed_data
 *	Buffer into which to write the compressed data.
 * @param compressed_size_avail
 *	Number of bytes available in @p compressed_data.
 * @param compressor
 *	A compressor previously allocated with wimlib_create_compressor().
 *
 * @return
 *	The size of the compressed data, in bytes, or 0 if the input data could
 *	not be compressed to @p compressed_size_avail or fewer bytes.
 */
extern size_t
wimlib_compress(const void *uncompressed_data, size_t uncompressed_size,
		void *compressed_data, size_t compressed_size_avail,
		struct wimlib_compressor *compressor);

/**
 * Free a compressor previously allocated with wimlib_create_compressor().
 *
 * @param compressor
 *	The compressor to free.
 */
extern void
wimlib_free_compressor(struct wimlib_compressor *compressor);

/**
 * Set the default decompression parameters for the specified compression type.
 * This will affect both explicit and wimlib-internal calls to
 * wimlib_create_decompressor().
 *
 * @param ctype
 *	Compression type for which to set the default decompression parameters.
 * @param params
 *	Compression-type specific parameters.  This may be @c NULL, in which
 *	case the "default default" parameters are restored.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 *	@p ctype was not a supported compression type.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Not enough memory to duplicate the parameters (perhaps @c params->size
 *	was invalid).
 */
extern int
wimlib_set_default_decompressor_params(enum wimlib_compression_type ctype,
				       const struct wimlib_decompressor_params_header *params);

/**
 * Allocate a decompressor for the specified compression type using the
 * specified parameters.
 *
 * @param ctype
 *	Compression type for which to create the decompressor.
 * @param max_block_size
 *	Maximum block size to support.  The exact meaning and allowed values for
 *	this parameter depend on the compression type, but it at least specifies
 *	the maximum allowed value for @p uncompressed_size to
 *	wimlib_decompress().
 * @param extra_params
 *	An optional pointer to extra decompressor parameters for the specified
 *	compression type.  If @c NULL, the default parameters are used.
 * @param decompressor_ret
 *	A location into which to return the pointer to the allocated
 *	decompressor, which can be used for any number of calls to
 *	wimlib_decompress() before being freed with wimlib_free_decompressor().
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 *	@p ctype was not a supported compression type.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	The decompression parameters were invalid.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Insufficient memory to allocate the decompressor.
 */
extern int
wimlib_create_decompressor(enum wimlib_compression_type ctype,
			   size_t max_block_size,
			   const struct wimlib_decompressor_params_header *extra_params,
			   struct wimlib_decompressor **decompressor_ret);

/**
 * Decompress a block of data using a decompressor previously created with
 * wimlib_create_decompressor().
 *
 * @param compressed_data
 *	Buffer containing the data to decompress.
 * @param compressed_size
 *	Size, in bytes, of the data to decompress.
 * @param uncompressed_data
 *	Buffer into which to write the uncompressed data.
 * @param uncompressed_size
 *	Size, in bytes, of the data when uncompressed.
 * @param decompressor
 *	A decompressor previously allocated with wimlib_create_decompressor().
 *
 * @return 0 on success; nonzero on error.
 */
extern int
wimlib_decompress(const void *compressed_data, size_t compressed_size,
		  void *uncompressed_data, size_t uncompressed_size,
		  struct wimlib_decompressor *decompressor);

/**
 * Free a decompressor previously allocated with wimlib_create_decompressor().
 *
 * @param decompressor
 *	The decompressor to free.
 */
extern void
wimlib_free_decompressor(struct wimlib_decompressor *decompressor);


struct wimlib_lzx_params_old;
struct wimlib_lzx_context_old;

/** Deprecated; do not use.  */
extern int
wimlib_lzx_set_default_params(const struct wimlib_lzx_params_old *params)
		_wimlib_deprecated;

/** Deprecated; do not use.  */
extern int
wimlib_lzx_alloc_context(const struct wimlib_lzx_params_old *params,
			 struct wimlib_lzx_context_old **ctx_pp)
		_wimlib_deprecated;

/** Deprecated; do not use.  */
extern void
wimlib_lzx_free_context(struct wimlib_lzx_context_old *ctx)
		_wimlib_deprecated;

/** Deprecated; do not use.  */
extern unsigned
wimlib_lzx_compress2(const void *udata, unsigned ulen, void *cdata,
		     struct wimlib_lzx_context_old *ctx)
		_wimlib_deprecated;

/** Deprecated; do not use.  */
extern unsigned
wimlib_lzx_compress(const void *udata, unsigned ulen, void *cdata)
		_wimlib_deprecated;

/** Deprecated; do not use.  */
extern unsigned
wimlib_xpress_compress(const void *udata, unsigned ulen, void *cdata)
		_wimlib_deprecated;

/** Deprecated; do not use.  */
extern int
wimlib_lzx_decompress(const void *cdata, unsigned clen,
		      void *udata, unsigned ulen)
		_wimlib_deprecated;

/** Deprecated; do not use.  */
extern int
wimlib_xpress_decompress(const void *cdata, unsigned clen,
			 void *udata, unsigned ulen)
		_wimlib_deprecated;

/** @} */



#ifdef __cplusplus
}
#endif

#endif /* _WIMLIB_H */
