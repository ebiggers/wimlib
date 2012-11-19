/*
 * wimlib.h
 *
 * External header for wimlib.
 */

/*
 * Copyright (C) 2012 Eric Biggers
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

/** \mainpage
 *
 * \section intro Introduction
 *
 * wimlib is a C library to read, write, and mount archive files in the Windows
 * Imaging Format (WIM files).  These files are normally created using the @c
 * imagex.exe utility on Windows, but this library provides a free
 * implementetion of @c imagex for UNIX-based systems and an API to allow other
 * programs to read, write, and mount WIM files.  wimlib is comparable to
 * Microsoft's WIMGAPI, but was designed independently and is not a clone of it.
 *
 * \section format WIM files
 *
 * A <b>Windows Imaging (WIM)</b> file is an archive.  Like some other archive
 * formats such as ZIP, files in WIM archives may be compressed.  WIM archives
 * support two Microsoft-specific compression formats:  @b LZX and @b XPRESS.
 * Both are based on LZ77 and Huffman encoding, and both are supported by
 * wimlib.
 *
 * Unlike ZIP files, WIM files can contain multiple independent toplevel
 * directory trees known as @a images.  While each image has its own metadata,
 * files are not duplicated for each image; instead, each file is included only
 * once in the entire WIM. Microsoft did this so that in one WIM file, they
 * could do things like have 5 different versions of Windows that are almost
 * exactly the same.
 *
 * Microsoft provides documentation for the WIM file format, XPRESS compression
 * format, and LZX compression format.  The XPRESS documentation is acceptable,
 * but the LZX documentation is not entirely correct, and the WIM documentation
 * itself is very incomplete and is of unacceptable quality.
 *
 * A WIM file may be either stand-alone or split into multiple parts.
 *
 * \section winpe Windows PE
 *
 * A major use for this library is to create customized images of Windows PE, the
 * Windows Preinstallation Environment, without having to rely on Windows.  Windows
 * PE is a lightweight version of Windows that can run entirely from memory and can
 * be used to install Windows from local media or a network drive or perform
 * maintenance.  Windows PE is the operating system that runs when you boot from
 * the Windows installation media.
 *
 * You can find Windows PE on the installation DVD for Windows Vista, Windows 7,
 * or Windows 8, in the file @c sources/boot.wim.  Windows PE can also be found
 * in the Windows Automated Installation Kit (WAIK), which is free to download
 * from Microsoft, inside the @c WinPE.cab file, which you can extract if you
 * install either the @c cabextract or @c p7zip programs.
 *
 * In addition, Windows installations and recovery partitions frequently contain a
 * WIM containing an image of the Windows Recovery Environment, which is similar to
 * Windows PE.
 *
 * \section ntfs NTFS support
 *
 * As of version 1.0.0, wimlib supports capturing and applying images directly
 * to NTFS volumes.  This was made possible with the help of libntfs-3g from the
 * NTFS-3g project.  This feature supports capturing and restoring NTFS-specific
 * data such as security descriptors, alternate data streams, and reparse point
 * data.

 * The code for NTFS image capture and image application is complete enough that
 * it is possible to apply an image from the "install.wim" contained in recent
 * Windows installation media (Vista, Windows 7, or Windows 8) directly to a
 * NTFS volume, and then boot Windows from it after preparing the Boot
 * Configuration Data.  In addition, a Windows installation can be captured (or
 * backed up) into a WIM file, and then re-applied later.
 *
 * \section starting Getting Started
 *
 * wimlib uses the GNU autotools, so it should be easy to install with
 * <code>configure && make && sudo make install</code>; however, please see the
 * README for more information about installing it.  To use wimlib in a program
 * after installing it, include @c wimlib.h and link your program with @c -lwim.
 *
 * wimlib wraps up a WIM file in an opaque ::WIMStruct structure.  A ::WIMStruct
 * may represent either a stand-alone WIM or one part of a split WIM.
 *
 * All functions in wimlib's public API are prefixed with @c wimlib.  Most
 * return an integer error code on failure.  Use wimlib_get_error_string() to
 * get a string that describes an error code.  wimlib also can print error
 * messages itself when an error happens, and these may be more informative than
 * the error code; to enable this, call wimlib_set_print_errors().  Please note
 * that this is for convenience only, and some errors can occur without a
 * message being printed.
 *
 * wimlib is thread-safe as long as different ::WIMStruct's are used, except for
 * the fact that wimlib_set_print_errors() and wimlib_set_memory_allocator()
 * both apply globally.
 *
 * To open an existing WIM, use wimlib_open_wim().
 *
 * To create a new WIM that initially contains no images, use
 * wimlib_create_new_wim().
 *
 * To add an image to a WIM file from a directory tree on your filesystem, call
 * wimlib_add_image().  This can be done with a ::WIMStruct gotten from
 * wimlib_open_wim() or from wimlib_create_new_wim().  Alternatively, if you
 * want to capture a WIM image directly from a NTFS volume while preserving
 * NTFS-specific data such as security descriptors, call
 * wimlib_add_image_from_ntfs_volume() instead.
 *
 * To extract an image from a WIM file, call wimlib_extract_image().
 * Alternatively, if you want to apply a WIM image directly to a NTFS volume
 * while setting NTFS-specific data such as security descriptors, call
 * wimlib_apply_image_to_ntfs_volume().
 *
 * The NTFS functions will fail if wimlib was compiled with the
 * <code>--without-ntfs-3g</code> flag.
 *
 * wimlib supports mounting WIM files either read-only or read-write.  Mounting
 * is done using wimlib_mount() and unmounting is done using wimlib_unmount().
 * Mounting can be done without root privileges because it is implemented using
 * FUSE (Filesystem in Userspace).  If wimlib is compiled with the
 * <code>--without-fuse</code> flag, these functions will be available but will
 * fail.
 *
 * After creating or modifying a WIM file, you can write it to a file using
 * wimlib_write().  Alternatively,  if the WIM was originally read from a file,
 * you can use wimlib_overwrite() to overwrite the original file.
 *
 * Please not: merely by calling wimlib_add_image() or many of the other
 * functions in this library that operate on ::WIMStruct's, you are @b not
 * modifing the WIM file on disk.  Changes are not saved until you explicitly
 * call wimlib_write() or wimlib_overwrite().
 *
 * After you are done with the WIM file, use wimlib_free() to free all memory
 * associated with a ::WIMStruct and close all files associated with it.
 *
 * To see an example of how to use wimlib, see the file @c programs/imagex.c in
 * wimlib's source tree.
 *
 * wimlib supports custom memory allocators; use wimlib_set_memory_allocator()
 * for this.  However, if wimlib calls into @c libntfs-3g, the custom memory
 * allocator may not be used.
 *
 * \section imagex imagex
 *
 * wimlib comes with the <b>imagex</b> program, which is documented in man pages.
 *
 * \section mkwinpeimg mkwinpeimg
 *
 * wimlib comes with the <b>mkwinpeimg</b> script, which is documented in a man
 * page.
 *
 * \section Limitations
 *
 * While wimlib supports the main features of WIM files, wimlib currently has
 * the following limitations:
 * - Different versions of the WIM file format are unsupported.  There is one
 *   different version of the format from development versions of Windows Vista,
 *   but I'm not planning to support it.
 * - Compressed resource chunk sizes other than 32768 are unsupported (except for
 *   uncompressed WIMs, for which the chunk size field is ignored).  As far as I
 *   can tell, other chunk sizes are not used in compressed WIMs.  Let me know
 *   if you find a WIM file with a different chunk size.
 * - wimlib does not provide a clone of the @b PEImg tool that allows you to
 *   make certain Windows-specific modifications to a Windows PE image, such as
 *   adding a driver or Windows component.  Such a tool could conceivably be
 *   implemented on top of wimlib, although it likely would be hard to implement
 *   because it would have to do very Windows-specific things such as
 *   manipulating the driver store.  wimlib does provide the @b mkwinpeimg
 *   script for a similar purpose, however.  With regards to adding drivers to
 *   Windows PE, you have the option of putting them anywhere in the Windows PE
 *   image, then loading them after boot using @b drvload.exe.
 * - There is not yet a way to extract specific files or directories from a WIM
 *   file without mounting it, or to add, remove, or modify files in a WIM
 *   without mounting it, other than by adding or removing an entire image.  I
 *   can implement this if requested, but I intend the FUSE mount feature to be
 *   used for this purpose, as it is easy to do these things in whatever way you
 *   want after the image is mounted.
 * - Currently, Microsoft's @a image.exe can create slightly smaller WIM files
 *   than wimlib when using maximum (LZX) compression because it knows how to
 *   split up LZX compressed blocks, which is not yet implemented in wimlib.
 * - wimlib is experimental and likely contains bugs; use Microsoft's @a
 *   imagex.exe if you want to make sure your WIM files are made "correctly".
 *
 * \section legal License
 *
 * The wimlib library, as well as the programs and scripts distributed with it
 * (@b imagex and @b mkwinpeimg), is licensed under the GNU General Public
 * License version 3 or later.
 */

#ifndef _WIMLIB_H
#define _WIMLIB_H

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef _WIMLIB_INTERNAL_H
/**
 * Opaque structure that represents a WIM file.
 */
typedef struct WIMStruct WIMStruct;
#endif

/**
 * Specifies the compression type of a WIM file.
 */

enum wim_compression_type {
	/** An invalid compression type. */
	WIM_COMPRESSION_TYPE_INVALID = -1,

	/** The WIM does not include any compressed resources. */
	WIM_COMPRESSION_TYPE_NONE = 0,

	/** Compressed resources in the WIM use LZX compression. */
	WIM_COMPRESSION_TYPE_LZX = 1,

	/** Compressed resources in the WIM use XPRESS compression. */
	WIM_COMPRESSION_TYPE_XPRESS = 2,
};

/** Mount the WIM read-write. */
#define WIMLIB_MOUNT_FLAG_READWRITE		0x00000001

/** For debugging only. (This passes the @c -d flag to @c fuse_main()).*/
#define WIMLIB_MOUNT_FLAG_DEBUG			0x00000002

/** Do not allow accessing alternate data streams. */
#define WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE		0x00000010

/** Access alternate data streams through extended file attributes.  This is the
 * default mode. */
#define WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR	0x00000020

/** Access alternate data streams by specifying the file name, a colon, then the
 * alternate file stream name. */
#define WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS	0x00000040

/** Include an integrity table in the new WIM being written during the unmount.
 * Ignored for read-only mounts. */
#define WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY	0x00000001

/** Unless this flag is given, changes to a mounted WIM are discarded.  Ignored
 * for read-only mounts. */
#define WIMLIB_UNMOUNT_FLAG_COMMIT		0x00000002

/** Include an integrity table in the new WIM file. */
#define WIMLIB_WRITE_FLAG_CHECK_INTEGRITY	0x00000001

/** Print progress information when writing streams and when writing the
 * integrity table. */
#define WIMLIB_WRITE_FLAG_SHOW_PROGRESS		0x00000002

/** Print file paths as we write then */
#define WIMLIB_WRITE_FLAG_VERBOSE		0x00000004

/** Call fsync() when the WIM file is closed */
#define WIMLIB_WRITE_FLAG_FSYNC			0x00000008

/** Re-build the entire WIM file rather than appending data to it, if possible.
 * (Applies to wimlib_overwrite(), not wimlib_write()). */
#define WIMLIB_WRITE_FLAG_REBUILD		0x00000010

/** Mark the image being added as the bootable image of the WIM. */
#define WIMLIB_ADD_IMAGE_FLAG_BOOT		0x00000001

/** Print the name of each file or directory as it is scanned to be included in
 * the WIM image. */
#define WIMLIB_ADD_IMAGE_FLAG_VERBOSE		0x00000002

/** Follow symlinks; archive and dump the files they point to. */
#define WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE	0x00000004

/** Show progress information when scanning a directory tree */
#define WIMLIB_ADD_IMAGE_FLAG_SHOW_PROGRESS	0x00000008

/** See documentation for wimlib_export_image(). */
#define WIMLIB_EXPORT_FLAG_BOOT			0x00000001

/** Verify the integrity of the WIM if an integrity table is present. */
#define WIMLIB_OPEN_FLAG_CHECK_INTEGRITY	0x00000001

/** Print progress information when verifying integrity table. */
#define WIMLIB_OPEN_FLAG_SHOW_PROGRESS		0x00000002

/** If this flag is not given, an error is issued if the WIM is part of a split
 * WIM.  */
#define WIMLIB_OPEN_FLAG_SPLIT_OK		0x00000004


/** When identical files are extracted from the WIM, always hard link them
 * together. */
#define WIMLIB_EXTRACT_FLAG_HARDLINK		0x00000001

/** When identical files are extracted from the WIM, always symlink them
 * together. */
#define WIMLIB_EXTRACT_FLAG_SYMLINK		0x00000002

/** Print the name of each file as it is extracted from the WIM image. */
#define WIMLIB_EXTRACT_FLAG_VERBOSE		0x00000008

/**
 * Possible values of the error code returned by many functions in wimlib.
 *
 * See the documentation for each wimlib function to see specifically what error
 * codes can be returned by a given function, and what they mean.
 */
enum wimlib_error_code {
	WIMLIB_ERR_SUCCESS = 0,
	WIMLIB_ERR_COMPRESSED_LOOKUP_TABLE,
	WIMLIB_ERR_DECOMPRESSION,
	WIMLIB_ERR_DELETE_STAGING_DIR,
	WIMLIB_ERR_FORK,
	WIMLIB_ERR_FUSE,
	WIMLIB_ERR_FUSERMOUNT,
	WIMLIB_ERR_IMAGE_COUNT,
	WIMLIB_ERR_IMAGE_NAME_COLLISION,
	WIMLIB_ERR_INTEGRITY,
	WIMLIB_ERR_INVALID_CAPTURE_CONFIG,
	WIMLIB_ERR_INVALID_CHUNK_SIZE,
	WIMLIB_ERR_INVALID_COMPRESSION_TYPE,
	WIMLIB_ERR_INVALID_DENTRY,
	WIMLIB_ERR_INVALID_HEADER_SIZE,
	WIMLIB_ERR_INVALID_IMAGE,
	WIMLIB_ERR_INVALID_INTEGRITY_TABLE,
	WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY,
	WIMLIB_ERR_INVALID_PARAM,
	WIMLIB_ERR_INVALID_RESOURCE_HASH,
	WIMLIB_ERR_INVALID_RESOURCE_SIZE,
	WIMLIB_ERR_INVALID_SECURITY_DATA,
	WIMLIB_ERR_LINK,
	WIMLIB_ERR_MKDIR,
	WIMLIB_ERR_MQUEUE,
	WIMLIB_ERR_NOMEM,
	WIMLIB_ERR_NOTDIR,
	WIMLIB_ERR_NOT_A_WIM_FILE,
	WIMLIB_ERR_NO_FILENAME,
	WIMLIB_ERR_NTFS_3G,
	WIMLIB_ERR_OPEN,
	WIMLIB_ERR_OPENDIR,
	WIMLIB_ERR_READLINK,
	WIMLIB_ERR_READ,
	WIMLIB_ERR_RENAME,
	WIMLIB_ERR_REOPEN,
	WIMLIB_ERR_RESOURCE_ORDER,
	WIMLIB_ERR_SPECIAL_FILE,
	WIMLIB_ERR_SPLIT_INVALID,
	WIMLIB_ERR_SPLIT_UNSUPPORTED,
	WIMLIB_ERR_STAT,
	WIMLIB_ERR_TIMEOUT,
	WIMLIB_ERR_UNKNOWN_VERSION,
	WIMLIB_ERR_UNSUPPORTED,
	WIMLIB_ERR_WRITE,
	WIMLIB_ERR_XML,
};


/** Used to indicate that no WIM image is currently selected. */
#define WIM_NO_IMAGE	0

/** Used to specify all images in the WIM. */
#define WIM_ALL_IMAGES	(-1)


/**
 * Adds an image to a WIM file from a directory tree on disk.
 *
 * The directory tree is read immediately for the purpose of constructing a
 * directory entry tree in-memory.  Also, all files are read to calculate their
 * SHA1 message digests.  However, because the directory tree may contain a very
 * large amount of data, the files themselves are not read into memory
 * permanently, and instead references to their paths saved.  The files are then
 * read on-demand if wimlib_write() or wimlib_overwrite() is called.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file to which the image will be
 * 	added.
 * @param dir
 * 	A path to a directory in the outside filesystem.  It will become the
 * 	root directory for the WIM image.
 * @param name
 * 	The name to give the image.  This must be non-@c NULL.
 * @param config
 * 	Pointer to the contents of an image capture configuration file.  If @c
 * 	NULL, a default string is used.  Please see the manual page for
 * 	<b>imagex capture</b> for more information.
 * @param config_len
 * 	Length of the string @a config in bytes.  Ignored if @a config is @c
 * 	NULL.
 *
 * @param flags
 * 	Bitwise OR of flags prefixed with WIMLIB_ADD_IMAGE_FLAG.  If
 * 	::WIMLIB_ADD_IMAGE_FLAG_BOOT is specified, the image in @a wim that is
 * 	marked as bootable is changed to the one being added.  If
 * 	::WIMLIB_ADD_IMAGE_FLAG_VERBOSE is specified, the name of each file is
 * 	printed as it is scanned or captured.  If
 * 	::WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE is specified, the files or
 * 	directories pointed to by symbolic links are archived rather than the
 * 	symbolic links themselves.  If ::WIMLIB_ADD_IMAGE_FLAG_SHOW_PROGRESS is
 * 	specified, progress information will be printed (distinct from the
 * 	verbose information).
 *
 * @return 0 on success; nonzero on error.  On error, changes to @a wim are
 * discarded so that it appears to be in the same state as when this function
 * was called.
 *
 * @retval ::WIMLIB_ERR_IMAGE_NAME_COLLISION
 * 	There is already an image named @a name in @a w.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a dir was @c NULL, @a name was @c NULL, or @a name was the empty string.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_NOTDIR
 * 	@a dir is not a directory.
 * @retval ::WIMLIB_ERR_OPEN
 * 	Failed to open a file or directory in the directory tree rooted at @a
 * 	dir.
 * @retval ::WIMLIB_ERR_READ
 * 	Failed to read a file in the directory tree rooted at @a dir.
 * @retval ::WIMLIB_ERR_SPECIAL_FILE
 * 	The directory tree rooted at @dir contains a special file that is not a
 * 	directory, regular file, or symbolic link.
 * @retval ::WIMLIB_ERR_STAT
 * 	Failed obtain the metadata for a file or directory in the directory tree
 * 	rooted at @a dir.
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	@a wim is part of a split WIM.  Adding an image to a split WIM is
 * 	unsupported.
 */
extern int wimlib_add_image(WIMStruct *wim, const char *dir,
			    const char *name, const char *config,
			    size_t config_len, int flags);

/**
 * This function is similar to wimlib_add_image(), except instead of capturing
 * the WIM image from a directory, it is captured from a NTFS volume specified
 * by @a device.  NTFS-3g errors are reported as ::WIMLIB_ERR_NTFS_3G.
 * ::WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE may not be specified because we capture
 * the reparse points exactly as they are.
 */
extern int wimlib_add_image_from_ntfs_volume(WIMStruct *wim, const char *device,
					     const char *name,
					     const char *config,
					     size_t config_len,
					     int flags);

/**
 * This function is similar to wimlib_extract_image(), except that @a image may
 * not be ::WIM_ALL_IMAGES, and @a device specifies the name of a file or block
 * device containing a NTFS volume to apply the image to.  NTFS-3g errors are
 * reported as ::WIMLIB_ERR_NTFS_3G, and ::WIMLIB_EXTRACT_FLAG_HARDLINK or
 * ::WIMLIB_EXTRACT_FLAG_SYMLINK may not be specified because in the NTFS
 * apply mode we apply the reparse points and hard links exactly as they are in
 * the WIM.
 */
extern int wimlib_apply_image_to_ntfs_volume(WIMStruct *wim, int image,
				 	     const char *device, int flags,
					     WIMStruct **additional_swms,
					     unsigned num_additional_swms);

/**
 * Creates a WIMStruct for a new WIM file.
 *
 * @param ctype
 * 	The type of compression to be used in the new WIM file.  Must be
 * 	::WIM_COMPRESSION_TYPE_NONE, ::WIM_COMPRESSION_TYPE_LZX, or
 * 	::WIM_COMPRESSION_TYPE_XPRESS.
 * @param wim_ret
 * 	On success, a pointer to an opaque ::WIMStruct for the new WIM file is
 * 	written to the memory location pointed to by this paramater.  The
 * 	::WIMStruct must be freed using using wimlib_free() when finished with
 * 	it.
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 * 	@a ctype was not ::WIM_COMPRESSION_TYPE_NONE,
 * 	::WIM_COMPRESSION_TYPE_LZX, or ::WIM_COMPRESSION_TYPE_XPRESS.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 */
extern int wimlib_create_new_wim(int ctype, WIMStruct **wim_ret);

/**
 * Deletes an image, or all images, from a WIM file.
 *
 * All streams referenced by the image(s) being deleted are removed from the
 * lookup table of the WIM if they are not referenced by any other images in the
 * WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for the WIM file that contains the image(s)
 * 	being deleted.
 * @param image
 * 	The number of the image to delete, or ::WIM_ALL_IMAGES to delete all
 * 	images.
 * @return 0 on success; nonzero on failure.  On failure, @a wim is guaranteed
 * to be left unmodified only if @a image specified a single image.  If instead
 * @a image was ::WIM_ALL_IMAGES and @a wim contained more than one image, it's
 * possible for some but not all of the images to have been deleted when a
 * failure status is returned.
 *
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	Could not decompress the metadata resource for @a image.
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for @a image in the WIM is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not exist in the WIM and is not ::WIM_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_SIZE
 *	The metadata resource for @a image in the WIM is invalid.
 * @retval ::WIMLIB_ERR_INVALID_SECURITY_DATA
 *	The security data for @a image in the WIM is invalid.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_READ
 * 	Could not read the metadata resource for @a image from the WIM.
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	@a wim is part of a split WIM.  Deleting an image from a split WIM is
 * 	unsupported.
 */
extern int wimlib_delete_image(WIMStruct *wim, int image);

/**
 * Exports an image, or all the images, from a WIM file, into another WIM file.
 *
 * The destination image is made to share the same dentry tree and security data
 * structure as the source image.  This places some restrictions on additional
 * functions that may be called.  wimlib_mount() may not be called on either the
 * source image or the destination image without an intervening call to a
 * function that un-shares the images, such as wimlib_free() on @a dest_wim, or
 * wimlib_delete_image() on either the source or destination image.
 * Furthermore, you may not call wimlib_free() or wimlib_overwrite() on @a
 * src_wim before any calls to functions such as wimlib_write() on @a dest_wim
 * because @a dest_wim will have references back to @a src_wim.
 *
 * Previous versions of this function left @a dest_wim in an indeterminate state
 * on failure.  This is no longer the case; all changes to @a dest_wim made by
 * this function are rolled back on failure.
 *
 * Previous versions of this function did not allow exporting an image that had
 * been added by wimlib_add_image().  This is no longer the case; you may now
 * export an image regardless of how it was added.
 *
 * Regardless of whether this function succeeds or fails, no user-visible
 * changes are made to @a src_wim.
 *
 * @param src_wim
 * 	Pointer to the ::WIMStruct for a stand-alone WIM or part 1 of a split
 * 	WIM that contains the image(s) being exported.
 * @param src_image
 * 	The image to export from @a src_wim.  Can be the number of an image, or
 * 	::WIM_ALL_IMAGES to export all images.
 * @param dest_wim
 * 	Pointer to the ::WIMStruct for a WIM file that will receive the images
 * 	being exported.
 * @param dest_name
 * 	The name to give the exported image in the new WIM file.  If left @c NULL,
 * 	the name from @a src_wim is used.  This parameter must be left @c NULL
 * 	if @a src_image is ::WIM_ALL_IMAGES and @a src_wim contains more than one
 * 	image; in that case, the names are all taken from the @a src_wim.
 * @param dest_description
 * 	The description to give the exported image in the new WIM file.  If left
 * 	@c NULL, the description from the @a src_wim is used.  This parameter must
 * 	be left @c NULL if @a src_image is ::WIM_ALL_IMAGES and @a src_wim contains
 * 	more than one image; in that case, the descriptions are all taken from
 * 	@a src_wim.
 * @param flags
 * 	::WIMLIB_EXPORT_FLAG_BOOT if the image being exported is to be made
 * 	bootable, or 0 if which image is marked as bootable in the destination
 * 	WIM is to be left unchanged.  If @a src_image is ::WIM_ALL_IMAGES and
 * 	there are multiple images in @a src_wim, specifying
 * 	::WIMLIB_EXPORT_FLAG_BOOT is valid only if one of the exported images is
 * 	currently marked as bootable in @a src_wim; if that is the case, then
 * 	that image is marked as bootable in the destination WIM.
 * @param additional_swms
 * 	Array of pointers to the ::WIMStruct for each additional part in the
 * 	split WIM.  Ignored if @a num_additional_swms is 0.  The pointers do not
 * 	need to be in any particular order, but they must include all parts of
 * 	the split WIM other than the first part, which must be provided in the
 * 	@a wim parameter.
 * @param num_additional_swms
 * 	Number of additional WIM parts provided in the @a additional_swms array.
 * 	This number should be one less than the total number of parts in the
 * 	split WIM.  Set to 0 if the WIM is a standalone WIM.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	Could not decompress the metadata resource for @a src_image
 * 	in @a src_wim
 * @retval ::WIMLIB_ERR_IMAGE_NAME_COLLISION
 * 	One or more of the names being given to an exported image was already in
 * 	use in the destination WIM.
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for @a src_image in @a
 * 	src_wim is invalid.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a src_image does not exist in @a src_wim.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	::WIMLIB_EXPORT_FLAG_BOOT was specified in @a flags, @a src_image was
 * 	::WIM_ALL_IMAGES, @a src_wim contains multiple images, and no images in
 * 	@a src_wim are marked as bootable; or @a dest_name and/or @a
 * 	dest_description were non-<code>NULL</code>, @a src_image was
 * 	::WIM_ALL_IMAGES, and @a src_wim contains multiple images; or @a src_wim
 * 	or @a dest_wim was @c NULL.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_SIZE
 *	The metadata resource for @a src_image in @a src_wim is invalid.
 * @retval ::WIMLIB_ERR_INVALID_SECURITY_DATA
 *	The security data for @a src_image in @a src_wim is invalid.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_READ
 * 	Could not read the metadata resource for @a src_image from @a src_wim.
 * @retval ::WIMLIB_ERR_SPLIT_INVALID
 * 	The source WIM is a split WIM, but the parts specified do not form a
 * 	complete split WIM because they do not include all the parts of the
 * 	original WIM, there are duplicate parts, or not all the parts have the
 * 	same GUID and compression type.
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	@a dest_wim is part of a split WIM.  Exporting an image to a split WIM
 * 	is unsupported.
 */
extern int wimlib_export_image(WIMStruct *src_wim, int src_image,
			       WIMStruct *dest_wim, const char *dest_name,
			       const char *dest_description, int flags,
			       WIMStruct **additional_swms,
			       unsigned num_additional_swms);

/**
 * Extracts an image, or all images, from a standalone or split WIM file.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a standalone WIM file, or part 1 of a
 * 	split WIM.
 * @param image
 * 	The image to extract.  Can be the number of an image, or ::WIM_ALL_IMAGES
 * 	to specify that all images are to be extracted.
 * @param output_dir
 * 	Directory to extract the WIM image(s) to.  It is created if it does not
 * 	already exist.
 * @param flags
 * 	Bitwise or of the flags prefixed with WIMLIB_EXTRACT_FLAG.
 *
 * 	One or none of ::WIMLIB_EXTRACT_FLAG_HARDLINK or
 * 	::WIMLIB_EXTRACT_FLAG_SYMLINK may be specified.  These flags cause
 * 	extracted files that are identical to be hardlinked or symlinked
 * 	together, depending on the flag.  These flags override the hard link
 * 	groups that are specified in the WIM file itself.  If ::WIM_ALL_IMAGES
 * 	is provided as the @a image parameter, files may be hardlinked or
 * 	symlinked across images if a file is found to occur in more than one
 * 	image.
 *
 * 	You may also specify the flag ::WIMLIB_EXTRACT_FLAG_VERBOSE to cause
 * 	informational messages to be printed during the extraction, including
 * 	the name of each extracted file or directory.
 * @param additional_swms
 * 	Array of pointers to the ::WIMStruct for each additional part in the
 * 	split WIM.  Ignored if @a num_additional_swms is 0.  The pointers do not
 * 	need to be in any particular order, but they must include all parts of
 * 	the split WIM other than the first part, which must be provided in the
 * 	@a wim parameter.
 * @param num_additional_swms
 * 	Number of additional WIM parts provided in the @a additional_swms array.
 * 	This number should be one less than the total number of parts in the
 * 	split WIM.  Set to 0 if the WIM is a standalone WIM.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	Could not decompress a resource (file or metadata) for @a image in @a
 * 	wim.
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for @a image in @a wim is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_HASH
 * 	The SHA1 message digest of an extracted stream did not match the SHA1
 * 	message digest given in the WIM file.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_SIZE
 *	A resource (file or metadata) for @a image in @a wim is invalid.
 * @retval ::WIMLIB_ERR_INVALID_SECURITY_DATA
 *	The security data for @a image in @a wim is invalid.
 * @retval ::WIMLIB_ERR_LINK
 * 	Failed to create a symbolic link or a hard link.
 * @retval ::WIMLIB_ERR_MKDIR
 * 	Failed create a needed directory.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_OPEN
 * 	Could not open one of the files being extracted for writing.
 * @retval ::WIMLIB_ERR_READ
 * 	A unexpected end-of-file or read error occurred when trying to read data
 * 	from the WIM file associated with @a wim.
 * @retval ::WIMLIB_ERR_SPLIT_INVALID
 * 	The WIM is a split WIM, but the parts specified do not form a complete
 * 	split WIM because they do not include all the parts of the original WIM,
 * 	there are duplicate parts, or not all the parts have the same GUID and
 * 	compression type.
 * @retval ::WIMLIB_ERR_WRITE
 * 	Failed to write a file being extracted.
 */
extern int wimlib_extract_image(WIMStruct *wim, int image,
				const char *output_dir, int flags,
				WIMStruct **additional_swms,
				unsigned num_additional_swms);

/**
 * Extracts the XML data for a WIM file to a file stream.  Every WIM file
 * includes a string of XML that describes the images contained in the WIM.
 * This function works on standalone WIMs as well as split WIM parts.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param fp
 * 	@c stdout, or a FILE* opened for writing, to extract the data to.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_WRITE
 * 	Failed to completely write the XML data to @a fp.
 */
extern int wimlib_extract_xml_data(WIMStruct *wim, FILE *fp);

/**
 * Frees all memory allocated for a WIMStruct and closes all files associated
 * with it.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 *
 * @return This function has no return value.
 */
extern void wimlib_free(WIMStruct *wim);

/**
 * Finds which image in a WIM is bootable.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 *
 * @return
 * 	0 if no image is marked as bootable, or the number of the image marked
 * 	as bootable (numbered starting at 1).
 */
extern int wimlib_get_boot_idx(const WIMStruct *wim);

/**
 * Gets the compression type used in the WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file
 *
 * @return
 * 	::WIM_COMPRESSION_TYPE_NONE, ::WIM_COMPRESSION_TYPE_LZX, or
 * 	::WIM_COMPRESSION_TYPE_XPRESS.
 */
extern int wimlib_get_compression_type(const WIMStruct *wim);

/**
 * Converts a compression type enumeration value into a string.
 *
 * @param ctype
 * 	::WIM_COMPRESSION_TYPE_NONE, ::WIM_COMPRESSION_TYPE_LZX,
 * 	::WIM_COMPRESSION_TYPE_XPRESS, or another value.
 *
 * @return
 * 	A statically allocated string: "None", "LZX", "XPRESS", or "Invalid",
 * 	respectively.
 */
extern const char *wimlib_get_compression_type_string(int ctype);

/**
 * Converts an error code into a string describing it.
 *
 * @param code
 * 	The error code returned by one of wimlib's functions.
 *
 * @return
 * 	Pointer to a statically allocated string describing the error code,
 * 	or @c NULL if the error code is not valid.
 */
extern const char *wimlib_get_error_string(enum wimlib_error_code code);

/**
 * Returns the description of the specified image.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.  It may be either a
 * 	standalone WIM or a split WIM part.
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
extern const char *wimlib_get_image_description(const WIMStruct *wim, int image);

/**
 * Returns the name of the specified image.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.  It may be either a
 * 	standalone WIM or a split WIM part.
 * @param image
 * 	The number of the image, numbered starting at 1.
 *
 * @return
 * 	The name of the image, or @c NULL if there is no such image.  The name
 * 	string is in library-internal memory and may not be modified or freed;
 * 	in addition, the string will become invalid if the name of the image is
 * 	changed, the image is deleted, or the ::WIMStruct is destroyed.
 */
extern const char *wimlib_get_image_name(const WIMStruct *wim, int image);


/**
 * Gets the number of images contained in the WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.  It may be either a
 * 	standalone WIM or a split WIM part.
 *
 * @return
 * 	The number of images contained in the WIM file.
 */
extern int wimlib_get_num_images(const WIMStruct *wim);

/**
 * Gets the part number of part of a split WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param total_parts_ret
 * 	If non-@c NULL, the total number of parts in the split WIM (1 for
 * 	non-split WIMs) is written to this location.
 *
 * @return
 * 	The part number of the WIM (1 for non-split WIMs)
 */
extern int wimlib_get_part_number(const WIMStruct *wim, int *total_parts_ret);

/**
 * Returns true if the WIM has an integrity table.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @return
 * 	@c true if the WIM has an integrity table; @c false otherwise.
 */
extern bool wimlib_has_integrity_table(const WIMStruct *wim);


/**
 * Determines if an image name is already used by some image in the WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param name
 * 	The name to check.
 *
 * @return
 * 	@c true if there is already an image in @a wim named @a name; @c false
 * 	if there is no image named @a name in @a wim.  (If @a name is @c NULL,
 * 	@c false is returned.)
 */
extern bool wimlib_image_name_in_use(const WIMStruct *wim, const char *name);

/**
 * Joins a set of split WIMs into a one-part WIM.
 *
 * @param swms
 * 	An array of strings that give the filenames of all parts of the split
 * 	WIM.
 * @param num_swms
 * 	Number of filenames in @a swms.
 * @param output_path
 * 	The path to write the one-part WIM to.
 * @param flags
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY to check the split WIMs' integrity
 * 	tables (if present) when opening them, and include an integrity table in
 * 	the output WIM.
 *
 * @return 0 on success; nonzero on error.  This function may return any value
 * returned by wimlib_open_wim() except ::WIMLIB_ERR_SPLIT_UNSUPPORTED, as well
 * as the following error codes:
 *
 * @retval ::WIMLIB_ERR_SPLIT_INVALID
 * 	The split WIMs do not form a valid WIM because they do not include all
 * 	the parts of the original WIM, there are duplicate parts, or not all the
 * 	parts have the same GUID and compression type.
 * @retval ::WIMLIB_ERR_WRITE
 * 	An error occurred when trying to write data to the new WIM at @a output_path.
 *
 * Note that this function merely copies the resources, so it will not check to
 * see if the resources, including the metadata resources, are valid or not.
 *
 * Also, after this function is called, the only function that may be called on
 * the ::WIMStruct's in the @a swms array is wimlib_free().
 */
extern int wimlib_join(const char **swms, unsigned num_swms,
		       const char *output_path, int flags);

/**
 * Mounts an image in a WIM file on a directory read-only or read-write.
 *
 * A daemon will be forked to service the filesystem.
 *
 * If the mount is read-write, modifications to the WIM are staged in a staging
 * directory.
 *
 * wimlib_mount() may be called from multiple threads without intervening calls
 * to wimlib_unmount(), provided that different ::WIMStruct's are used.  (This
 * was not the case for versions of this library 1.0.3 and earlier.)
 *
 * wimlib_mount() cannot be used on an image that was exported with
 * wimlib_export_image() while the dentry trees for both images are still in
 * memory.  In addition, wimlib_mount() may not be used to mount an image that
 * has just been added with wimlib_add_image() or
 * wimlib_add_image_from_ntfs_volume(), unless the WIM has been written and read
 * into a new ::WIMStruct.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for the WIM file to be mounted.
 * @param image
 * 	The number of the image to mount, numbered from 1.  It must be an
 * 	existing, single image.
 * @param dir
 * 	The path to an existing directory to mount the image on.
 * @param flags
 * 	Bitwise OR of the flags prefixed with WIMLIB_MOUNT_FLAG.  If
 * 	::WIMLIB_MOUNT_FLAG_READWRITE is not given, the WIM is mounted
 * 	read-only.  The interface to the WIM named data streams is specified by
 * 	exactly one of ::WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE,
 * 	::WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR, or
 * 	::WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS.  The default interface is
 * 	the XATTR interface.
 * @param additional_swms
 * 	Array of pointers to the ::WIMStruct for each additional part in the
 * 	split WIM.  Ignored if @a num_additional_swms is 0.  The pointers do not
 * 	need to be in any particular order, but they must include all parts of
 * 	the split WIM other than the first part, which must be provided in the
 * 	@a wim parameter.
 * @param num_additional_swms
 * 	Number of additional WIM parts provided in the @a additional_swms array.
 * 	This number should be one less than the total number of parts in the
 * 	split WIM.  Set to 0 if the WIM is a standalone WIM.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	Could not decompress the metadata resource for @a image in @a wim.
 * @retval ::WIMLIB_ERR_FUSE
 * 	A non-zero status was returned by @c fuse_main().
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for @a image in @a wim is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not specify an existing, single image in @a wim.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a image is shared among multiple ::WIMStruct's as a result of a call to
 * 	wimlib_export_image(), or @a image has been added with
 * 	wimlib_add_image() or wimlib_add_image_from_ntfs_volume().
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_SIZE
 *	The metadata resource for @a image in @a wim is invalid.
 * @retval ::WIMLIB_ERR_INVALID_SECURITY_DATA
 *	The security data for @a image in @a wim is invalid.
 * @retval ::WIMLIB_ERR_MKDIR
 * 	::WIMLIB_MOUNT_FLAG_READWRITE was specified in @a flags, but the staging
 * 	directory could not be created.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_NOTDIR
 * 	Could not determine the current working directory.
 * @retval ::WIMLIB_ERR_READ
 * 	An unexpected end-of-file or read error occurred when trying to read
 * 	data from the WIM file associated with @a wim.
 * @retval ::WIMLIB_ERR_SPLIT_INVALID
 * 	The WIM is a split WIM, but the parts specified do not form a complete
 * 	split WIM because they do not include all the parts of the original WIM,
 * 	there are duplicate parts, or not all the parts have the same GUID and
 * 	compression type.
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	The WIM is a split WIM and a read-write mount was requested.  We only
 * 	support mounting a split WIM read-only.
 */
extern int wimlib_mount(WIMStruct *wim, int image, const char *dir, int flags,
			WIMStruct **additional_swms,
			unsigned num_additional_swms);

/**
 * Opens a WIM file and creates a ::WIMStruct for it.
 *
 * @param wim_file
 * 	The path to the WIM file to open.
 * @param flags
 * 	Bitwise OR of ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY and/or
 * 	::WIMLIB_OPEN_FLAG_SHOW_PROGRESS.
 * 	If ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY is given, the integrity table
 * 	of the WIM, if it exists, is checked, and the function will fail with an
 * 	::WIMLIB_ERR_INTEGRITY status if any of the computed SHA1 message
 * 	digests of the WIM do not exactly match the corresponding message
 * 	digests given in the integrity table.
 * 	If ::WIMLIB_OPEN_FLAG_SHOW_PROGRESS is given, progress information will
 * 	be shown if the integrity of the WIM is checked.
 * 	If ::WIMLIB_OPEN_FLAG_SPLIT_OK is given, no error will be issued if the
 * 	WIM is part of a split WIM; otherwise ::WIMLIB_ERR_SPLIT_UNSUPPORTED is
 * 	returned.  (This flag may be removed in the future, in which case no
 * 	error will be issued when opening a split WIM.)
 *
 * @param wim_ret
 * 	On success, a pointer to an opaque ::WIMStruct for the opened WIM file
 * 	is written to the memory location pointed to by this parameter.  The
 * 	::WIMStruct must be freed using using wimlib_free() when finished with
 * 	it.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_COMPRESSED_LOOKUP_TABLE
 * 	The lookup table of @a wim_file is compressed.  Support for this can be
 * 	added to wimlib if needed, but it appears to be the case that the lookup
 * 	table is never compressed.
 * @retval ::WIMLIB_ERR_IMAGE_COUNT
 * 	The WIM is not the non-first part of a split WIM, and the number of
 * 	metadata resources found in the WIM did not match the image count given
 * 	in the WIM header, or the number of &lt;IMAGE&gt; elements in the XML
 * 	data for the WIM did not match the image count given in the WIM header.
 * @retval ::WIMLIB_ERR_INTEGRITY
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY was specified in @a flags and @a
 * 	wim_file contains an integrity table, but the SHA1 message digest for a
 * 	chunk of the WIM does not match the corresponding message digest given
 * 	in the integrity table.
 * @retval ::WIMLIB_ERR_INVALID_CHUNK_SIZE
 * 	Resources in @a wim_file are compressed, but the chunk size is not 32768.
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 * 	The header of @a wim_file says that resources in the WIM are compressed,
 * 	but the header flag indicating LZX or XPRESS compression is not set.
 * @retval ::WIMLIB_ERR_INVALID_HEADER_SIZE
 * 	The length field of the WIM header is not 208.
 * @retval ::WIMLIB_ERR_INVALID_INTEGRITY_TABLE
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY was specified in @a flags and @a
 * 	wim_file contains an integrity table, but the integrity table is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY
 * 	The lookup table for the WIM contained duplicate entries, or it
 * 	contained an entry with a SHA1 message digest of all 0's.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocated needed memory.
 * @retval ::WIMLIB_ERR_NOT_A_WIM_FILE
 * 	@a wim_file does not begin with the expected magic characters.
 * @retval ::WIMLIB_ERR_OPEN
 * 	Failed to open the file @a wim_file for reading.
 * @retval ::WIMLIB_ERR_READ
 * 	An unexpected end-of-file or read error occurred when trying to read
 * 	data from @a wim_file.
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	@a wim_file is a split WIM, but ::WIMLIB_OPEN_FLAG_SPLIT_OK was not
 * 	givin in @a flags.
 * @retval ::WIMLIB_ERR_UNKNOWN_VERSION
 * 	A number other than 0x10d00 is written in the version field of the WIM
 * 	header of @a wim_file.
 * @retval ::WIMLIB_ERR_XML
 * 	The XML data for @a wim_file is invalid.
 */
extern int wimlib_open_wim(const char *wim_file, int flags,
			   WIMStruct **wim_ret);

/**
 * Overwrites the file that the WIM was originally read from, with changes made.
 *
 * There are two ways that a WIM may be overwritten.  The first is to do a full
 * rebuild: the new WIM is written to a temporary file and then renamed to the
 * original file after it is has been completely written.  The temporary file
 * currently is made in the same directory as the original WIM file.  A full
 * rebuild may take a while, but can be used even if images have been modified
 * or deleted, will produce a WIM with no holes, and has little chance of
 * unintentional data loss because the temporary WIM is fsync()ed before being
 * renamed to the original WIM.
 *
 * The second way to overwrite a WIM is by appending to the end of it.  This can
 * be much faster than a full rebuild, but it only works if the only operations
 * on the WIM have been to change the header or XML data, or to add new images.
 * Writing a WIM in this mode begins with writing any new file resources *after*
 * everything in the old WIM, even though this will leave a hole where the old
 * lookup table, XML data, and integrity were.  This is done so that the WIM
 * remains valid even if the operation is aborted mid-write.
 *
 * By default, the overwrite mode is chosen based on the past operations
 * performed on the WIM.  Use the flag ::WIMLIB_WRITE_FLAG_REBUILD to explicitly
 * request a full rebuild.
 *
 * In the temporary-file overwrite mode, no changes are made to the WIM on
 * failure, and the temporary file is deleted (if possible).  Abnormal
 * termination of the program will result in the temporary file being orphaned.
 * In the direct append mode, the WIM is truncated to the original length on
 * failure, while abnormal termination of the program will result in extra data
 * appended to the original WIM, but it will still be a valid WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for the WIM file to write.  There may have
 * 	been in-memory changes made to it, which are then reflected in the
 * 	output file.
 * @param write_flags
 * 	Bitwise OR of ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY and/or
 * 	::WIMLIB_WRITE_FLAG_SHOW_PROGRESS.
 * @param num_threads
 * 	Number of threads to use for compression (see wimlib_write()).
 *
 * @return 0 on success; nonzero on error.  This function may return any value
 * returned by wimlib_write() as well as the following error codes:
 * @retval ::WIMLIB_ERR_NO_FILENAME
 * 	@a wim corresponds to a WIM created with wimlib_create_new_wim() rather
 * 	than a WIM read with wimlib_open_wim().
 * @retval ::WIMLIB_ERR_RENAME
 * 	The temporary file that the WIM was written to could not be renamed to
 * 	the original filename of @a wim.
 * @retval ::WIMLIB_ERR_REOPEN
 * 	The WIM was overwritten successfully, but it could not be re-opened
 * 	read-only.  Therefore, the resources in the WIM can no longer be
 * 	accessed, so this limits the functions that can be called on @a wim
 * 	before calling wimlib_free().
 */
extern int wimlib_overwrite(WIMStruct *wim, int write_flags,
			    unsigned num_threads);

/**
 * This function is deprecated; call wimlib_overwrite() without the
 * WIMLIB_WRITE_FLAG_REBUILD flag instead.
 */
extern int wimlib_overwrite_xml_and_header(WIMStruct *wim, int write_flags);

/**
 * Prints information about one image, or all images, contained in a WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param image
 * 	The image about which to print information.  Can be the number of an
 * 	image, or ::WIM_ALL_IMAGES to print information about all images in the
 * 	WIM.
 *
 * @return This function has no return value.  No error checking is done when
 * printing the information.  If @a image is invalid, an error message is
 * printed.
 */
extern void wimlib_print_available_images(const WIMStruct *wim, int image);

/**
 * Prints the full paths to all files contained in an image, or all images, in a
 * WIM file.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param image
 * 	Which image to print files for.  Can be the number of an image, or
 * 	::WIM_ALL_IMAGES to print the files contained in all images.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	The metadata resource for one of the specified images could not be
 * 	decompressed.
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for one of the specified
 * 	images is invaled.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not specify a valid image in @a wim, and is not
 * 	::WIM_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a wim was @c NULL.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_SIZE
 * 	The metadata resource for one of the specified images is invalid.
 * @retval ::WIMLIB_ERR_INVALID_SECURITY_DATA
 *	The security data for one of the specified images is invalid.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_READ
 * 	An unexpected read error or end-of-file occurred when reading the
 * 	metadata resource for one of the specified images.
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	@a wim was not a standalone WIM and was not the first part of a split
 * 	WIM.
 */
extern int wimlib_print_files(WIMStruct *wim, int image);

/**
 * Prints detailed information from the header of a WIM file.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.  It may be either a
 * 	standalone WIM or part of a split WIM.
 *
 * @return This function has no return value.
 *
 */
extern void wimlib_print_header(const WIMStruct *wim);

/**
 * Prints the lookup table of a WIM file.  The lookup table maps SHA1 message
 * digests, as found in the directory entry tree in the WIM file, to file
 * resources in the WIM file.  This table includes one entry for each unique
 * file in the WIM, so it can be quite long.  There is only one lookup table per
 * WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 *
 * @return This function has no return value.
 */
extern void wimlib_print_lookup_table(WIMStruct *wim);

/**
 * Prints the metadata of the specified image in a WIM file.  The metadata
 * consists of the security data as well as the directory entry tree, and each
 * image has its own metadata.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param image
 * 	Which image to print the metadata for.  Can be the number of an image,
 * 	or ::WIM_ALL_IMAGES to print the metadata for all images in the WIM.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	The metadata resource for one of the specified images could not be
 * 	decompressed.
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for one of the specified
 * 	images is invaled.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not specify a valid image in @a wim, and is not
 * 	::WIM_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a wim was @c NULL.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_SIZE
 * 	The metadata resource for one of the specified images is invalid.
 * @retval ::WIMLIB_ERR_INVALID_SECURITY_DATA
 *	The security data for one of the specified images is invalid.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_READ
 * 	An unexpected read error or end-of-file occurred when reading the
 * 	metadata resource for one of the specified images.
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	@a wim was not a standalone WIM and was not the first part of a split
 * 	WIM.
 */
extern int wimlib_print_metadata(WIMStruct *wim, int image);

/**
 * Prints some basic information about a WIM file.  All information printed by
 * this function is also printed by wimlib_print_header(), but
 * wimlib_print_wim_information() prints some of this information more concisely
 * and in a more readable form.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 *
 * @return This function has no return value.
 */
extern void wimlib_print_wim_information(const WIMStruct *wim);

/**
 * Translates a string specifying the name or number of an image in the WIM into
 * the number of the image.  The images are numbered starting at 1.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param image_name_or_num
 * 	A string specifying which image.  If it begins with a number, it is
 * 	taken to be a string specifying the image number.  Otherwise, it is
 * 	taken to be the name of an image, as specified in the XML data for the
 * 	WIM file.  It also may be the keyword "all" or the string "*", both of
 * 	which will resolve to ::WIM_ALL_IMAGES.
 *
 * @return
 * 	If the string resolved to a single existing image, the number of that
 * 	image, counting starting at 1, is returned.  If the keyword "all" was
 * 	specified, ::WIM_ALL_IMAGES is returned.  Otherwise, ::WIM_NO_IMAGE is
 * 	returned.
 */
extern int wimlib_resolve_image(WIMStruct *wim, const char *image_name_or_num);

/**
 * Sets which image in the WIM is marked as bootable.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param boot_idx
 * 	The number of the image to mark as bootable, or 0 to mark no image as
 * 	bootable.
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a wim was @c NULL.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a boot_idx does not specify an existing image in @a wim, and it was not
 * 	0.
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	@a wim is part of a split WIM.  We do not support changing the boot
 * 	index of a split WIM.
 */
extern int wimlib_set_boot_idx(WIMStruct *wim, int boot_idx);

/**
 * Changes the description of an image in the WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.  It may be either a
 * 	standalone WIM or part of a split WIM; however, you should set the same
 * 	description on all parts of a split WIM.
 * @param image
 * 	The number of the image for which to change the description.
 * @param description
 * 	The new description to give the image.  It may be @c NULL, which
 * 	indicates that the image is to be given no description.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not specify a single existing image in @a wim.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a wim was @c NULL.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate the memory needed to duplicate the @a description
 * 	string.
 */
extern int wimlib_set_image_descripton(WIMStruct *wim, int image,
				       const char *description);

/**
 * Changes what is written in the \<FLAGS\> element in the WIM XML data
 * (something like "Core" or "Ultimate")
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.  It may be either a
 * 	standalone WIM or part of a split WIM; however, you should set the same
 * 	\<FLAGS\> element on all parts of a split WIM.
 * @param image
 * 	The number of the image for which to change the description.
 * @param flags
 * 	The new \<FLAGS\> element to give the image.  It may be @c NULL, which
 * 	indicates that the image is to be given no \<FLAGS\> element.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not specify a single existing image in @a wim.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a wim was @c NULL.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate the memory needed to duplicate the @a flags string.
 */
extern int wimlib_set_image_flags(WIMStruct *wim, int image, const char *flags);

/**
 * Changes the name of an image in the WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.  It may be either a
 * 	standalone WIM or part of a split WIM; however, you should set the same
 * 	name on all parts of a split WIM.
 * @param image
 * 	The number of the image for which to change the name.
 * @param name
 * 	The new name to give the image.  It must not a nonempty string.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_IMAGE_NAME_COLLISION
 * 	There is already an image named @a name in @a wim.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a name was @c NULL or the empty string, or @a wim was @c NULL.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not specify a single existing image in @a wim.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate the memory needed to duplicate the @a name string.
 */
extern int wimlib_set_image_name(WIMStruct *wim, int image, const char *name);

/**
 * Set the functions that wimlib uses to allocate and free memory.
 *
 * These settings are global and not per-WIM.
 *
 * The default is to use the default @c malloc() and @c free() from the C
 * library.
 *
 * Please note that some external functions we call still may use the standard
 * memory allocation functions.
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
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	wimlib was compiled with the @c --without-custom-memory-allocator flag,
 * 	so custom memory allocators are unsupported.
 */
int wimlib_set_memory_allocator(void *(*malloc_func)(size_t),
			         void (*free_func)(void *),
			         void *(*realloc_func)(void *, size_t));

/**
 * Sets whether wimlib is to print error messages to @c stderr when a function
 * fails.  These error messages may provide information that cannot be
 * determined only from the error code that is returned.  Not every error will
 * result in an error message being printed.
 *
 * This setting is global and not per-WIM.
 *
 * By default, error messages are not printed.
 *
 * @param show_messages
 * 	@c true if error messages are to be printed; @c false if error messages
 * 	are not to be printed.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	@a show_messages was @c true, but wimlib was compiled with the @c
 * 	--without-error-messages option.   Therefore, error messages cannot be
 * 	shown.
 */
extern int wimlib_set_print_errors(bool show_messages);

/**
 * Splits a WIM into multiple parts.
 *
 * @param wimfile
 * 	Name of the WIM file to split.  It must be a standalone, one-part WIM.
 * @param swm_name
 * 	Name of the SWM file to create.  This will be the name of the first
 * 	part.  The other parts will have the same name with 2, 3, 4, ..., etc.
 * 	appended.
 * @param part_size
 * 	The maximum size per part, in bytes.  It is not guaranteed that this
 * 	will really be the maximum size per part, because some file resources in
 * 	the WIM may be larger than this size, and the WIM file format provides
 * 	no way to split up file resources among multiple WIMs.
 * @param flags
 * 	Bitwise OR of ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY and/or
 * 	::WIMLIB_OPEN_FLAG_SHOW_PROGRESS.
 *
 * @return 0 on success; nonzero on error.  This function may return any value
 * returned by wimlib_open_wim() as well as the following error codes:
 *
 * @retval ::WIMLIB_ERR_WRITE
 * 	An error occurred when trying to write data to one of the split WIMs.
 *
 */
extern int wimlib_split(const char *wimfile, const char *swm_name,
			size_t part_size, int flags);

/**
 * Unmounts a WIM image that was mounted using wimlib_mount().
 *
 * Blocks until it is known whether the mount succeeded or failed.
 *
 * To perform this operation, the process calling wimlib_unmount() communicates
 * with the process that had called wimlib_mount().
 *
 * There is currently a design problem with this function because it is hard to
 * know whether the filesystem daemon is still working or whether it has
 * crashed, has been killed, or has reached an infinite loop. However, ideally
 * there should be no infinite loops or crashes in the code, so this wouldn't be
 * much of a problem.  Currently, a timeout of 600 seconds (so long because WIMs
 * can be very large) is implemented so that this function will not wait forever
 * before returning failure.
 *
 * @param dir
 * 	The directory that the WIM image was mounted on.
 * @param flags
 * 	Bitwise OR of the flags ::WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY or
 * 	::WIMLIB_UNMOUNT_FLAG_COMMIT.  Neither of these flags affect read-only
 * 	mounts.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DELETE_STAGING_DIR
 * 	The filesystem daemon was unable to remove the staging directory and the
 * 	temporary files that it contains.
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
 * @retval ::WIMLIB_ERR_TIMEOUT
 * 	600 seconds elapsed while waiting for the filesystem daemon to notify
 * 	the process of its exit status, so the WIM file probably was not written
 * 	successfully.
 * @retval ::WIMLIB_ERR_READ
 * 	A read error occurred when the filesystem daemon tried to a file from
 * 	the staging directory
 * @retval ::WIMLIB_ERR_RENAME
 * 	The filesystem daemon failed to rename the newly written WIM file to the
 * 	original WIM file.
 * @retval ::WIMLIB_ERR_WRITE
 * 	A write error occurred when the filesystem daemon was writing to the new
 * 	WIM file, or the filesystem daemon was unable to flush changes that had
 * 	been made to files in the staging directory.
 */
extern int wimlib_unmount(const char *dir, int flags);

/**
 * Writes the WIM to a file.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.  There may have been
 * 	in-memory changes made to it, which are then reflected in the output
 * 	file.
 * @param path
 * 	The path to the file to write the WIM to.
 * @param image
 * 	The image inside the WIM to write.  Use ::WIM_ALL_IMAGES to include all
 * 	images.
 * @param write_flags
 * 	Bitwise OR of ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY and/or
 * 	::WIMLIB_WRITE_FLAG_SHOW_PROGRESS.  If
 * 	::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY is given, an integrity table is
 * 	included in the WIM being written.  If ::WIMLIB_WRITE_FLAG_SHOW_PROGRESS
 * 	is given, the progress of the calculation of the integrity table is
 * 	shown.
 * @param num_threads
 * 	Number of threads to use for compressing data.  Autodetected if set to
 * 	0.  Note: if no data compression needs to be done, no threads will be
 * 	created regardless of this parameter (e.g. if writing an uncompressed
 * 	WIM, or exporting an image from a compressed WIM to another WIM of the
 * 	same compression type).
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	Failed to decompress a metadata or file resource in @a wim.
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for @a image in @a wim is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not specify a single existing image in @a wim, and is not
 * 	::WIM_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_HASH
 * 	A file that had previously been scanned for inclusion in the WIM by the
 * 	wimlib_add_image() or wimlib_add_image_from_ntfs_volume() functions was
 * 	concurrently modified, so it failed the SHA1 message digest check.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a wim or @a path was @c NULL.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_SIZE
 *	The metadata resource for @a image in @a wim is invalid.
 * @retval ::WIMLIB_ERR_INVALID_SECURITY_DATA
 *	The security data for @a image in @a wim is invalid.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_OPEN
 * 	Failed to open @a path for writing, or some file resources in @a
 * 	wim refer to files in the outside filesystem, and one of these files
 * 	could not be opened for reading.
 * @retval ::WIMLIB_ERR_READ
 * 	An error occurred when trying to read data from the WIM file associated
 * 	with @a wim, or some file resources in @a wim refer to files in the
 * 	outside filesystem, and a read error occurred when reading one of these
 * 	files.
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	@a wim is part of a split WIM.  You may not call this function on a
 * 	split WIM.
 * @retval ::WIMLIB_ERR_WRITE
 * 	An error occurred when trying to write data to the new WIM file at @a
 * 	path.
 */
extern int wimlib_write(WIMStruct *wim, const char *path, int image,
			int write_flags, unsigned num_threads);



#endif /* _WIMLIB_H */

