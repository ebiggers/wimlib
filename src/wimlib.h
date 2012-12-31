/*
 * wimlib.h
 *
 * External header for wimlib.
 *
 * This file contains extensive comments for generating documentation with
 * Doxygen.  The built HTML documentation can be viewed at
 * http://wimlib.sourceforge.net.
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
 * This is the documentation for the library interface of wimlib 1.2.3.  If you
 * have installed wimlib and want to know how to use the @c imagex program,
 * please see the man pages instead.
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
 * itself is incomplete.
 *
 * A WIM file may be either stand-alone or split into multiple parts.
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
 * wimlib_open_wim() or from wimlib_create_new_wim().  wimlib_add_image() can
 * also capture a WIM image directly from a NTFS volume if you provide the
 * ::WIMLIB_ADD_IMAGE_FLAG_NTFS flag, provided that wimlib was not compiled with
 * the <code>--without-ntfs-3g</code> flag.
 *
 * To extract an image from a WIM file, call wimlib_extract_image().  You may
 * extract an image either to a directory or directly to a NTFS volume, the
 * latter of which will preserve NTFS-specific data such as security
 * descriptors.
 *
 * wimlib supports mounting WIM files either read-only or read-write.  Mounting
 * is done using wimlib_mount_image() and unmounting is done using
 * wimlib_unmount_image().  Mounting can be done without root privileges because
 * it is implemented using FUSE (Filesystem in Userspace).  If wimlib is
 * compiled with the <code>--without-fuse</code> flag, these functions will be
 * available but will fail with ::WIMLIB_ERR_UNSUPPORTED.
 *
 * After creating or modifying a WIM file, you can write it to a file using
 * wimlib_write().  Alternatively,  if the WIM was originally read from a file
 * (using wimlib_open_wim() rather than wimlib_create_new_wim()), you can use
 * wimlib_overwrite() to overwrite the original file.
 *
 * Please note: merely by calling wimlib_add_image() or many of the other
 * functions in this library that operate on ::WIMStruct's, you are @b not
 * modifying the WIM file on disk.  Changes are not saved until you explicitly
 * call wimlib_write() or wimlib_overwrite().
 *
 * After you are done with the WIM file, use wimlib_free() to free all memory
 * associated with a ::WIMStruct and close all files associated with it.
 *
 * A number of functions take a pointer to a progress function of type
 * ::wimlib_progress_func_t.  This function will be called periodically during
 * the WIM operation(s) to report on the progress of the operation (for example,
 * how many bytes have been written so far).
 *
 * \section imagex imagex
 *
 * wimlib comes with a command-line interface, the @b imagex program.  It is
 * documented with man pages.  See its source code (@c programs/imagex.c in
 * wimlib's source tree) for an example of how to use wimlib in your program.
 *
 * \section mkwinpeimg mkwinpeimg
 *
 * wimlib also comes with the <b>mkwinpeimg</b> script, which is documented in a
 * man page.
 *
 * \section Limitations
 *
 * While wimlib supports the main features of WIM files, wimlib currently has
 * the following limitations:
 * - wimlib cannot be used on MS-Windows.
 * - There is no way to add, remove, modify, or extract specific files in a WIM
 *   without mounting it, other than by adding, removing, or extracting an
 *   entire image.  The FUSE mount feature should be used for this purpose.
 * - Currently, Microsoft's @a image.exe can create slightly smaller WIM files
 *   than wimlib when using maximum (LZX) compression because it knows how to
 *   split up LZX compressed blocks, which is not yet implemented in wimlib.
 * - wimlib is experimental and likely contains bugs; use Microsoft's @a
 *   imagex.exe if you want to make sure your WIM files are made "correctly".
 * - The old WIM format from Vista pre-releases is not supported.
 * - Compressed resource chunk sizes other than 32768 are not supported,
 *   although this doesn't seem to be a problem because the chunk size always
 *   seems to be this value.
 * - wimlib does not provide a clone of the @b PEImg tool that allows you to
 *   make certain Windows-specific modifications to a Windows PE image, such as
 *   adding a driver or Windows component.  Such a tool could conceivably be
 *   implemented on top of wimlib, although it likely would be hard to implement
 *   because it would have to do very Windows-specific things such as
 *   manipulating the driver store.  wimlib does provide the @b mkwinpeimg
 *   script for a similar purpose, however.  With regards to adding drivers to
 *   Windows PE, you have the option of putting them anywhere in the Windows PE
 *   image, then loading them after boot using @b drvload.exe.
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
#include <inttypes.h>

#define WIMLIB_MAJOR_VERSION 1
#define WIMLIB_MINOR_VERSION 2
#define WIMLIB_PATCH_VERSION 3

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
 */
typedef struct WIMStruct WIMStruct;

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
};

/** Possible values of the first parameter to the user-supplied
 * ::wimlib_progress_func_t progress function */
enum wimlib_progress_msg {

	/** A WIM image is about to be extracted.  @a info will point to
	 * ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN,

	/** The directory structure of the WIM image is about to be extracted.
	 * @a info will point to ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,

	/** The directory structure of the WIM image has been successfully
	 * extracted.  @a info will point to ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,

	/** The WIM image's files resources are currently being extracted.  @a
	 * info will point to ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS,

	/** A file or directory is being extracted.  @a info will point to
	 * ::wimlib_progress_info.extract, and the @a cur_path member will be
	 * valid. */
	WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY,

	/** All the WIM files and directories have been extracted, and
	 * timestamps are about to be applied.  @a info will point to
	 * ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS,

	/** A WIM image has been successfully extracted.  @a info will point to
	 * ::wimlib_progress_info.extract. */
	WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END,

	/** The directory or NTFS volume is about to be scanned to build a tree
	 * of WIM dentries in-memory.  @a info will point to
	 * ::wimlib_progress_info.scan. */
	WIMLIB_PROGRESS_MSG_SCAN_BEGIN,

	/** A directory or file is being scanned.  @a info will point to
	 * ::wimlib_progress_info.scan, and its @a cur_path member will be
	 * valid.  This message is only sent if ::WIMLIB_ADD_IMAGE_FLAG_VERBOSE
	 * is passed to wimlib_add_image(). */
	WIMLIB_PROGRESS_MSG_SCAN_DENTRY,

	/** The directory or NTFS volume has been successfully scanned, and a
	 * tree of WIM dentries has been built in-memory. @a info will point to
	 * ::wimlib_progress_info.scan. */
	WIMLIB_PROGRESS_MSG_SCAN_END,

	/**
	 * File resources are currently being written to the WIM.
	 * @a info will point to ::wimlib_progress_info.write_streams. */
	WIMLIB_PROGRESS_MSG_WRITE_STREAMS,

	/**
	 * The metadata resource for each image is about to be written to the
	 * WIM. @a info will not be valid. */
	WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN,

	/**
	 * The metadata resource for each image has successfully been writen to
	 * the WIM.  @a info will not be valid. */
	WIMLIB_PROGRESS_MSG_WRITE_METADATA_END,

	/**
	 * The temporary file has successfully been renamed to the original WIM
	 * file.  Only happens when wimlib_overwrite() is called and the
	 * overwrite is not done in-place.
	 * @a info will point to ::wimlib_progress_info.rename. */
	WIMLIB_PROGRESS_MSG_RENAME,

	/** The contents of the WIM are being checked against the integrity
	 * table.  Only happens when wimlib_open_wim() is called with the
	 * ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY flag.  @a info will point to
	 * ::wimlib_progress_info.integrity. */
	WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY,

	/** An integrity table is being calculated for the WIM being written.
	 * Only happens when wimlib_write() or wimlib_overwrite() is called with
	 * the ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY flag.  @a info will point to
	 * ::wimlib_progress_info.integrity. */
	WIMLIB_PROGRESS_MSG_CALC_INTEGRITY,

	/** A wimlib_join() operation is in progress.  @a info will point to
	 * ::wimlib_progress_info.join. */
	WIMLIB_PROGRESS_MSG_JOIN_STREAMS,

	/** A wimlib_split() operation is in progress, and a new split part is
	 * about to be started.  @a info will point to
	 * ::wimlib_progress_info.split. */
	WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART,

	/** A wimlib_split() operation is in progress, and a split part has been
	 * finished. @a info will point to ::wimlib_progress_info.split. */
	WIMLIB_PROGRESS_MSG_SPLIT_END_PART,
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
		 * Will be 0 initially, and equal to @a total_bytes at the end.
		 * */
		uint64_t completed_bytes;

		/** Number of streams that have been written.  Will be 0
		 * initially, and equal to @a total_streams at the end. */
		uint64_t completed_streams;

		/** Number of threads that are being used to compress resources
		 * (if applicable). */
		unsigned num_threads;

		/** The compression type being used to write the streams; either
		 * ::WIMLIB_COMPRESSION_TYPE_NONE,
		 * ::WIMLIB_COMPRESSION_TYPE_XPRESS, or
		 * ::WIMLIB_COMPRESSION_TYPE_LZX. */
		int	 compression_type;
	} write_streams;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_SCAN_BEGIN and
	 * ::WIMLIB_PROGRESS_MSG_SCAN_END. */
	struct wimlib_progress_info_scan {
		/** Directory or NTFS volume that is being scanned. */
		const char *source;

		/** Path to the file or directory that is about to be scanned,
		 * relative to the root of the image capture or the NTFS volume.
		 * */
		const char *cur_path;

		/** True iff @a cur_path is being excluded from the image
		 * capture due to the capture configuration file. */
		bool excluded;
	} scan;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS, and
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END. */
	struct wimlib_progress_info_extract {
		/** Number of the image being extracted (1-based). */
		int image;

		/** Flags passed to to wimlib_extract_image() */
		int extract_flags;

		/** Full path to the WIM file being extracted. */
		const char *wimfile_name;

		/** Name of the image being extracted. */
		const char *image_name;

		/** Directory or NTFS volume to which the image is being
		 * extracted. */
		const char *target;

		/** Current dentry being extracted.  (Valid only if message is
		 * ::WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY.) */
		const char *cur_path;

		/** Number of bytes of uncompressed data that will be extracted.
		 * Takes into account hard links (they are not counted for each
		 * link.)
		 * */
		uint64_t total_bytes;

		/** Number of bytes that have been written so far.  Will be 0
		 * initially, and equal to @a total_bytes at the end. */
		uint64_t completed_bytes;

		/** Number of streams that will be extracted.  This may more or
		 * less than the number of "files" to be extracted due to
		 * special cases (hard links, symbolic links, and alternate data
		 * streams.) */
		uint64_t num_streams;
	} extract;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_RENAME. */
	struct wimlib_progress_info_rename {
		/** Name of the temporary file that the WIM was written to. */
		const char *from;

		/** Name of the original WIM file to which the temporary file is
		 * being renamed. */
		const char *to;
	} rename;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY and
	 * ::WIMLIB_PROGRESS_MSG_CALC_INTEGRITY. */
	struct wimlib_progress_info_integrity {
		/** Number of bytes from the end of the WIM header to the end of
		 * the lookup table (the area that is covered by the SHA1
		 * integrity checks.) */
		uint64_t total_bytes;

		/** Number of bytes that have been SHA1-summed so far.  Will be
		 * 0 initially, and equal @a total_bytes at the end. */
		uint64_t completed_bytes;

		/** Number of chunks that the checksummed region is divided
		 * into. */
		uint32_t total_chunks;

		/** Number of chunks that have been SHA1-summed so far.   Will
		 * be 0 initially, and equal to @a total_chunks at the end. */
		uint32_t completed_chunks;

		/** Size of the chunks used for the integrity calculation. */
		uint32_t chunk_size;

		/** Filename of the WIM (only valid if the message is
		 * ::WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY). */
		const char *filename;
	} integrity;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_JOIN_STREAMS. */
	struct wimlib_progress_info_join {
		/** Total number of bytes of compressed data contained in all
		 * the split WIM part's file and metadata resources. */
		uint64_t total_bytes;

		/** Number of bytes that have been copied to the joined WIM so
		 * far.  Will be 0 initially, and equal to @a total_bytes at the
		 * end. */
		uint64_t completed_bytes;

		/** Number of split WIM parts that have had all their file and
		 * metadata resources copied over to the joined WIM so far. */
		unsigned completed_parts;

		/** Number of split WIM parts. */
		unsigned total_parts;
	} join;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART and
	 * ::WIMLIB_PROGRESS_MSG_SPLIT_END_PART. */
	struct wimlib_progress_info_split {
		/** Total size of the original WIM's file and metadata resources
		 * (compressed). */
		uint64_t total_bytes;

		/** Number of bytes of file and metadata resources that have
		 * been copied out of the original WIM so far.  Will be 0
		 * initially, and equal to @a total_bytes at the end. */
		uint64_t completed_bytes;

		/** Number of the split WIM part that is about to be started
		 * (::WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART) or has just been
		 * finished (::WIMLIB_PROGRESS_MSG_SPLIT_END_PART). */
		unsigned cur_part_number;

		/** Name of the split WIM part that is about to be started
		 * (::WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART) or has just been
		 * finished (::WIMLIB_PROGRESS_MSG_SPLIT_END_PART). */
		const char *part_name;
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


/*****************************
 * WIMLIB_ADD_IMAGE_FLAG_*   *
 *****************************/

/** Directly capture a NTFS volume rather than a generic directory */
#define WIMLIB_ADD_IMAGE_FLAG_NTFS			0x00000001

/** Follow symlinks; archive and dump the files they point to.  Cannot be used
 * with ::WIMLIB_ADD_IMAGE_FLAG_NTFS. */
#define WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE		0x00000002

/** Call the progress function with the message
 * ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY when each directory or file is starting to
 * be scanned. */
#define WIMLIB_ADD_IMAGE_FLAG_VERBOSE			0x00000004

/** Mark the image being added as the bootable image of the WIM. */
#define WIMLIB_ADD_IMAGE_FLAG_BOOT			0x00000008

/******************************
 * WIMLIB_EXPORT_FLAG_* *
 ******************************/

/** See documentation for wimlib_export_image(). */
#define WIMLIB_EXPORT_FLAG_BOOT				0x00000001

/******************************
 * WIMLIB_EXTRACT_FLAG_*      *
 ******************************/

/** Extract the image directly to a NTFS volume rather than a generic directory.
 * */
#define WIMLIB_EXTRACT_FLAG_NTFS			0x00000001

/** When identical files are extracted from the WIM, always hard link them
 * together.  Cannot be used with ::WIMLIB_EXTRACT_FLAG_NTFS. */
#define WIMLIB_EXTRACT_FLAG_HARDLINK			0x00000002

/** When identical files are extracted from the WIM, always symlink them
 * together.  Cannot be used with ::WIMLIB_EXTRACT_FLAG_NTFS. */
#define WIMLIB_EXTRACT_FLAG_SYMLINK			0x00000004

/** Call the progress function with the argument
 * ::WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY each time a file or directory is
 * extracted.  Note: these calls will be interspersed with calls for the message
 * ::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS. */
#define WIMLIB_EXTRACT_FLAG_VERBOSE			0x00000008

/** Read the WIM file sequentially while extracting the image. */
#define WIMLIB_EXTRACT_FLAG_SEQUENTIAL			0x00000010

/******************************
 * WIMLIB_MOUNT_FLAG_*        *
 ******************************/

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

/******************************
 * WIMLIB_OPEN_FLAG_*         *
 ******************************/

/** Verify the WIM contents against the WIM's integrity table, if present. */
#define WIMLIB_OPEN_FLAG_CHECK_INTEGRITY		0x00000001

/** Do not issue an error if the WIM is part of a split WIM. */
#define WIMLIB_OPEN_FLAG_SPLIT_OK			0x00000002

/******************************
 * WIMLIB_UNMOUNT_FLAG_*      *
 ******************************/

/** Include an integrity table in the WIM after it's been unmounted.  Ignored
 * for read-only mounts. */
#define WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY		0x00000001

/** Unless this flag is given, changes to a read-write mounted WIM are
 * discarded.  Ignored for read-only mounts. */
#define WIMLIB_UNMOUNT_FLAG_COMMIT			0x00000002

/** See ::WIMLIB_WRITE_FLAG_REBUILD */
#define WIMLIB_UNMOUNT_FLAG_REBUILD			0x00000004

/** See ::WIMLIB_WRITE_FLAG_RECOMPRESS */
#define WIMLIB_UNMOUNT_FLAG_RECOMPRESS			0x00000008

/******************************
 * WIMLIB_WRITE_FLAG_*        *
 ******************************/

/** Include an integrity table in the new WIM file. */
#define WIMLIB_WRITE_FLAG_CHECK_INTEGRITY		0x00000001

/** Re-build the entire WIM file rather than appending data to it, if possible.
 * (Applies to wimlib_overwrite(), not wimlib_write()). */
#define WIMLIB_WRITE_FLAG_REBUILD			0x00000002

/** Recompress all resources, even if they could otherwise be copied from a
 * different WIM with the same compression type (in the case of
 * wimlib_export_image() being called previously). */
#define WIMLIB_WRITE_FLAG_RECOMPRESS			0x00000004

/** Call fsync() when the WIM file is closed */
#define WIMLIB_WRITE_FLAG_FSYNC				0x00000008

/* Specifying this flag overrides the default behavior of wimlib_overwrite()
 * after one or more calls to wimlib_delete_image(), which is to rebuild the
 * entire WIM.
 *
 * If you specifiy this flag to wimlib_overwrite(), only minimal changes to
 * correctly remove the image from the WIM will be taken.  In particular, all
 * streams will be left alone, even if they are no longer referenced.  This is
 * probably not what you want, because almost no space will be spaced by
 * deleting an image in this way. */
#define WIMLIB_WRITE_FLAG_SOFT_DELETE			0x00000010

/**
 * Possible values of the error code returned by many functions in wimlib.
 *
 * See the documentation for each wimlib function to see specifically what error
 * codes can be returned by a given function, and what they mean.
 */
enum wimlib_error_code {
	WIMLIB_ERR_SUCCESS = 0,
	WIMLIB_ERR_ALREADY_LOCKED,
	WIMLIB_ERR_COMPRESSED_LOOKUP_TABLE,
	WIMLIB_ERR_DECOMPRESSION,
	WIMLIB_ERR_DELETE_STAGING_DIR,
	WIMLIB_ERR_FILESYSTEM_DAEMON_CRASHED,
	WIMLIB_ERR_FORK,
	WIMLIB_ERR_FUSE,
	WIMLIB_ERR_FUSERMOUNT,
	WIMLIB_ERR_ICONV_NOT_AVAILABLE,
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
	WIMLIB_ERR_INVALID_PART_NUMBER,
	WIMLIB_ERR_INVALID_RESOURCE_HASH,
	WIMLIB_ERR_INVALID_RESOURCE_SIZE,
	WIMLIB_ERR_INVALID_SECURITY_DATA,
	WIMLIB_ERR_INVALID_UNMOUNT_MESSAGE,
	WIMLIB_ERR_INVALID_UTF8_STRING,
	WIMLIB_ERR_INVALID_UTF16_STRING,
	WIMLIB_ERR_LIBXML_UTF16_HANDLER_NOT_AVAILABLE,
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


/** Used to indicate that no WIM image or an invalid WIM image. */
#define WIMLIB_NO_IMAGE		0

/** Used to specify all images in the WIM. */
#define WIMLIB_ALL_IMAGES	(-1)

/**
 * Adds an image to a WIM file from an on-disk directory tree or NTFS volume.
 *
 * The directory tree is read immediately for the purpose of constructing a
 * directory entry tree in-memory.  Also, all files are read to calculate their
 * SHA1 message digests.  However, because the directory tree may contain a very
 * large amount of data, the files themselves are not read into memory
 * permanently, and instead references to their paths saved.  The files are then
 * read on-demand if wimlib_write() or wimlib_overwrite() is called.
 *
 * Please note that @b no changes are committed to the underlying WIM file (if
 * any) until wimlib_write() or wimlib_overwrite() is called.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file to which the image will be
 * 	added.
 * @param source
 * 	A path to a directory or unmounted NTFS volume that will be captured as
 * 	a WIM image.
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
 * @param add_image_flags
 * 	Bitwise OR of flags prefixed with WIMLIB_ADD_IMAGE_FLAG.  If
 * 	::WIMLIB_ADD_IMAGE_FLAG_BOOT is specified, the image in @a wim that is
 * 	marked as bootable is changed to the one being added.  If
 * 	::WIMLIB_ADD_IMAGE_FLAG_VERBOSE is specified, the name of each file is
 * 	printed as it is scanned or captured.  If
 * 	::WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE is specified, the files or
 * 	directories pointed to by symbolic links are archived rather than the
 * 	symbolic links themselves.
 *
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.  On error, changes to @a wim are
 * discarded so that it appears to be in the same state as when this function
 * was called.
 *
 * @retval ::WIMLIB_ERR_IMAGE_NAME_COLLISION
 * 	There is already an image named @a name in @a wim.
 * @retval ::WIMLIB_ERR_INVALID_CAPTURE_CONFIG
 * 	@a config was not @c NULL and did not specify a valid image capture
 * 	configuration.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a dir was @c NULL, @a name was @c NULL, or @a name was the empty string.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_NOTDIR
 * 	@a source is not a directory (only if ::WIMLIB_ADD_IMAGE_FLAG_NTFS was
 * 	not specified in @a add_image_flags).
 * @retval ::WIMLIB_ERR_NTFS_3G
 * 	An error was returned from a libntfs-3g function when the NTFS volume
 * 	was being opened, scanned, or closed (only if
 * 	::WIMLIB_ADD_IMAGE_FLAG_NTFS was specified in @a add_image_flags).
 * @retval ::WIMLIB_ERR_OPEN
 * 	Failed to open a file or directory in the directory tree rooted at @a
 * 	source (only if ::WIMLIB_ADD_IMAGE_FLAG_NTFS was not specified in @a
 * 	add_image_flags).
 * @retval ::WIMLIB_ERR_READ
 * 	Failed to read a file in the directory tree rooted at @a source (only if
 * 	::WIMLIB_ADD_IMAGE_FLAG_NTFS was not specified in @a add_image_flags).
 * @retval ::WIMLIB_ERR_SPECIAL_FILE
 * 	The directory tree rooted at @a source contains a special file that is
 * 	not a directory, regular file, or symbolic link.  This currently can
 * 	only be returned if ::WIMLIB_ADD_IMAGE_FLAG_NTFS was not specified in @a
 * 	add_image_flags, but it may be returned for unsupported NTFS files in
 * 	the future.
 * @retval ::WIMLIB_ERR_STAT
 * 	Failed obtain the metadata for a file or directory in the directory tree
 * 	rooted at @a source (only if ::WIMLIB_ADD_IMAGE_FLAG_NTFS was not
 * 	specified in @a add_image_flags).
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED
 * 	@a wim is part of a split WIM.  Adding an image to a split WIM is
 * 	unsupported.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	::WIMLIB_ADD_IMAGE_FLAG_NTFS was specified in @a add_image_flags, but
 * 	wimlib was configured with the @c --without-ntfs-3g flag.
 */
extern int wimlib_add_image(WIMStruct *wim, const char *source,
			    const char *name, const char *config,
			    size_t config_len, int add_image_flags,
			    wimlib_progress_func_t progress_func);

/**
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
 * 	@a ctype was not ::WIMLIB_COMPRESSION_TYPE_NONE,
 * 	::WIMLIB_COMPRESSION_TYPE_LZX, or ::WIMLIB_COMPRESSION_TYPE_XPRESS.
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
 * Please note that @b no changes are committed to the underlying WIM file (if
 * any) until wimlib_write() or wimlib_overwrite() is called.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for the WIM file that contains the image(s)
 * 	being deleted.
 * @param image
 * 	The number of the image to delete, or ::WIMLIB_ALL_IMAGES to delete all
 * 	images.
 * @return 0 on success; nonzero on failure.  On failure, @a wim is guaranteed
 * to be left unmodified only if @a image specified a single image.  If instead
 * @a image was ::WIMLIB_ALL_IMAGES and @a wim contained more than one image, it's
 * possible for some but not all of the images to have been deleted when a
 * failure status is returned.
 *
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	Could not decompress the metadata resource for @a image.
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for @a image in the WIM is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not exist in the WIM and is not ::WIMLIB_ALL_IMAGES.
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
 * functions that may be called.  wimlib_mount_image() may not be called on
 * either the source image or the destination image without an intervening call
 * to a function that un-shares the images, such as wimlib_free() on @a
 * dest_wim, or wimlib_delete_image() on either the source or destination image.
 * Furthermore, you may not call wimlib_free() on @a src_wim before calling
 * wimlib_write() or wimlib_overwrite() on @a dest_wim because @a dest_wim will
 * have references back to @a src_wim.
 *
 * Previous versions of this function left @a dest_wim in an indeterminate state
 * on failure.  This is no longer the case; all changes to @a dest_wim made by
 * this function are rolled back on failure.
 *
 * Previous versions of this function did not allow exporting an image that had
 * been added by wimlib_add_image().  This is no longer the case; you may now
 * export an image regardless of how it was added.
 *
 * Regardless of whether this function succeeds or fails, no changes are made to
 * @a src_wim.
 *
 * Please note that no changes are committed to the underlying WIM file of @a
 * dest_wim (if any) until wimlib_write() or wimlib_overwrite() is called.
 *
 * @param src_wim
 * 	Pointer to the ::WIMStruct for a stand-alone WIM or part 1 of a split
 * 	WIM that contains the image(s) being exported.
 * @param src_image
 * 	The image to export from @a src_wim.  Can be the number of an image, or
 * 	::WIMLIB_ALL_IMAGES to export all images.
 * @param dest_wim
 * 	Pointer to the ::WIMStruct for a WIM file that will receive the images
 * 	being exported.
 * @param dest_name
 * 	The name to give the exported image in the new WIM file.  If left @c
 * 	NULL, the name from @a src_wim is used.  This parameter must be left @c
 * 	NULL if @a src_image is ::WIMLIB_ALL_IMAGES and @a src_wim contains more
 * 	than one image; in that case, the names are all taken from the @a
 * 	src_wim.  (This is allowed even if one or more images being exported has
 * 	no name.)
 * @param dest_description
 * 	The description to give the exported image in the new WIM file.  If left
 * 	@c NULL, the description from the @a src_wim is used.  This parameter must
 * 	be left @c NULL if @a src_image is ::WIMLIB_ALL_IMAGES and @a src_wim contains
 * 	more than one image; in that case, the descriptions are all taken from
 * 	@a src_wim.  (This is allowed even if one or more images being exported
 * 	has no description.)
 * @param export_flags
 * 	::WIMLIB_EXPORT_FLAG_BOOT if the image being exported is to be made
 * 	bootable, or 0 if which image is marked as bootable in the destination
 * 	WIM is to be left unchanged.  If @a src_image is ::WIMLIB_ALL_IMAGES and
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
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
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
 * 	::WIMLIB_ALL_IMAGES, @a src_wim contains multiple images, and no images in
 * 	@a src_wim are marked as bootable; or @a dest_name and/or @a
 * 	dest_description were non-<code>NULL</code>, @a src_image was
 * 	::WIMLIB_ALL_IMAGES, and @a src_wim contains multiple images.
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
			       const char *dest_description, int export_flags,
			       WIMStruct **additional_swms,
			       unsigned num_additional_swms,
			       wimlib_progress_func_t progress_func);

/**
 * Extracts an image, or all images, from a standalone or split WIM file to a
 * directory or a NTFS volume.
 *
 * Please see the manual page for the @c imagex program for more information
 * about the "normal" extraction mode versus the NTFS extraction mode
 * (entered by providing flag ::WIMLIB_EXTRACT_FLAG_NTFS).
 *
 * Extraction is done with one thread.
 *
 * All extracted data is SHA1-summed, and ::WIMLIB_ERR_INVALID_RESOURCE_HASH is
 * returned if any resulting SHA1 message digests do not match the values
 * provided in the WIM file.  Therefore, if this function is successful, you can
 * be fairly sure that any compressed data in the WIM was uncompressed
 * correctly.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a standalone WIM file, or part 1 of a
 * 	split WIM.
 * @param image
 * 	The image to extract.  Can be the number of an image, or ::WIMLIB_ALL_IMAGES
 * 	to specify that all images are to be extracted.  ::WIMLIB_ALL_IMAGES cannot
 * 	be used if ::WIMLIB_EXTRACT_FLAG_NTFS is specified in @a extract_flags.
 * @param target
 * 	Directory to extract the WIM image(s) to (created if it does not already
 * 	exist); or, with ::WIMLIB_EXTRACT_FLAG_NTFS in @a extract_flags, the
 * 	path to the unmounted NTFS volume to extract the image to.
 * @param extract_flags
 * 	Bitwise OR of the flags prefixed with WIMLIB_EXTRACT_FLAG.
 * 	<br/> <br/>
 * 	If ::WIMLIB_EXTRACT_FLAG_NTFS is specified, @a target is interpreted as
 * 	a NTFS volume to extract the image to.  The volume will be opened using
 * 	NTFS-3g and the image will be extracted to the root of the NTFS volume.
 * 	Otherwise, @a target is interpreted as a directory to extract the
 * 	image(s) to.
 * 	<br/> <br/>
 * 	If ::WIMLIB_EXTRACT_FLAG_NTFS is not specified, one or none of
 * 	::WIMLIB_EXTRACT_FLAG_HARDLINK or ::WIMLIB_EXTRACT_FLAG_SYMLINK may be
 * 	specified.  These flags cause extracted files that are identical to be
 * 	hardlinked or symlinked together, depending on the flag.  These flags
 * 	override the hard link groups that are specified in the WIM file itself.
 * 	If ::WIMLIB_ALL_IMAGES is provided as the @a image parameter, files may be
 * 	hardlinked or symlinked across images if a file is found to occur in
 * 	more than one image.
 * 	<br/> <br/>
 * 	You may also specify the flag ::WIMLIB_EXTRACT_FLAG_VERBOSE to print the
 * 	name of each file or directory as it is extracted.
 * 	<br/> <br/>
 * 	If ::WIMLIB_EXTRACT_FLAG_SEQUENTIAL is specified, data is read from the
 * 	WIM sequentially, if possible.  If ::WIMLIB_ALL_IMAGES is specified,
 * 	each image is considered separately with regards to the sequential
 * 	order.  It is also possible for alternate data streams to break the
 * 	sequential order (this only applies if ::WIMLIB_EXTRACT_FLAG_NTFS is
 * 	specified).
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
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	Could not decompress a resource (file or metadata) for @a image in @a
 * 	wim.
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for @a image in @a wim is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a target was @c NULL, or both ::WIMLIB_EXTRACT_FLAG_HARDLINK and
 * 	::WIMLIB_EXTRACT_FLAG_SYMLINK were specified in @a extract_flags, or
 * 	both ::WIMLIB_EXTRACT_FLAG_NTFS and either
 * 	::WIMLIB_EXTRACT_FLAG_HARDLINK or ::WIMLIB_EXTRACT_FLAG_SYMLINK were
 * 	specified in @a extract_flags, or ::WIMLIB_EXTRACT_FLAG_NTFS was
 * 	specified in @a extract_flags and @a image was ::WIMLIB_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_HASH
 * 	The SHA1 message digest of an extracted stream did not match the SHA1
 * 	message digest given in the WIM file.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_SIZE
 *	A resource (file or metadata) for @a image in @a wim is invalid.
 * @retval ::WIMLIB_ERR_INVALID_SECURITY_DATA
 *	The security data for @a image in @a wim is invalid.
 * @retval ::WIMLIB_ERR_LINK
* 	Failed to create a symbolic link or a hard link (only if
 * 	::WIMLIB_EXTRACT_FLAG_NTFS was not specified in @a extract_flags).
 * @retval ::WIMLIB_ERR_MKDIR
 * 	Failed create a needed directory (only if ::WIMLIB_EXTRACT_FLAG_NTFS was
 * 	not specified in @a extract_flags).
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_NTFS_3G
 * 	An error was returned from a libntfs-3g function while the WIM image was
 * 	being extracted to the NTFS volume (only if ::WIMLIB_EXTRACT_FLAG_NTFS
 * 	was specified in @a extract_flags).
 * @retval ::WIMLIB_ERR_OPEN
 * 	Could not open one of the files being extracted for writing (only if
 * 	::WIMLIB_EXTRACT_FLAG_NTFS was not specified in @a extract_flags).
 * @retval ::WIMLIB_ERR_READ
 * 	A unexpected end-of-file or read error occurred when trying to read data
 * 	from the WIM file associated with @a wim.
 * @retval ::WIMLIB_ERR_SPLIT_INVALID
 * 	The WIM is a split WIM, but the parts specified do not form a complete
 * 	split WIM because they do not include all the parts of the original WIM,
 * 	there are duplicate parts, or not all the parts have the same GUID and
 * 	compression type.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	::WIMLIB_EXTRACT_FLAG_NTFS was specified in @a extract_flags, but wimlib
 * 	was configured with the @c --without-ntfs-3g flag.
 * @retval ::WIMLIB_ERR_WRITE
 * 	Failed to write a file being extracted (only if
 * 	::WIMLIB_EXTRACT_FLAG_NTFS was not specified in @a extract_flags).
 */
extern int wimlib_extract_image(WIMStruct *wim, int image,
				const char *target, int extract_flags,
				WIMStruct **additional_swms,
				unsigned num_additional_swms,
				wimlib_progress_func_t progress_func);

/**
 * Extracts the XML data of a WIM file to a file stream.  Every WIM file
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
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a wim is not a ::WIMStruct that was created by wimlib_open_wim().
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
 * Returns the index of the bootable image of the WIM.
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
 * Returns the compression type used in the WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file
 *
 * @return
 * 	::WIMLIB_COMPRESSION_TYPE_NONE, ::WIMLIB_COMPRESSION_TYPE_LZX, or
 * 	::WIMLIB_COMPRESSION_TYPE_XPRESS.
 */
extern int wimlib_get_compression_type(const WIMStruct *wim);

/**
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
 *
 * 	If @a wim was read with wimlib_open_wim(), it is allowed for image(s) in
 * 	the WIM to be unnamed, in which case an empty string will be returned
 * 	when the corresponding name is requested.
 */
extern const char *wimlib_get_image_name(const WIMStruct *wim, int image);


/**
 * Returns the number of images contained in a WIM.
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
 * Returns the part number of a WIM in a split WIM and the total number of parts
 * of the split WIM.
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
 * 	@c true if the WIM has an integrity table; @c false otherwise.  If @a
 * 	wim is a ::WIMStruct created with wimlib_create_new_wim() rather than
 * 	wimlib_open_wim(), @c false will be returned, even if wimlib_write() has
 * 	been called on @a wim with ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY set.
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
 * 	if there is no image named @a name in @a wim.  If @a name is @c NULL or
 * 	the empty string, @c false is returned.
 */
extern bool wimlib_image_name_in_use(const WIMStruct *wim, const char *name);

/**
 * Joins a split WIM into a stand-alone one-part WIM.
 *
 * @param swms
 * 	An array of strings that gives the filenames of all parts of the split
 * 	WIM.  No specific order is required, but all parts must be included with
 * 	no duplicates.
 * @param num_swms
 * 	Number of filenames in @a swms.
 * @param swm_open_flags
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY if the integrity of each split WIM
 * 	part should be verified, if integrity tables are present.  Otherwise,
 * 	set to 0.
 * @param wim_write_flags
 * 	Bitwise OR of ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY, and/or ::WIMLIB_WRITE_FLAG_FSYNC.
 * @param output_path
 * 	The path to write the one-part WIM to.
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.  This function may return any value
 * returned by wimlib_open_wim() and wimlib_write() except
 * ::WIMLIB_ERR_SPLIT_UNSUPPORTED, as well as the following error code:
 *
 * @retval ::WIMLIB_ERR_SPLIT_INVALID
 * 	The split WIMs do not form a valid WIM because they do not include all
 * 	the parts of the original WIM, there are duplicate parts, or not all the
 * 	parts have the same GUID and compression type.
 *
 * Note: the WIM's uncompressed and compressed resources are not checksummed
 * when they are copied from the split WIM parts to the joined WIM, nor are
 * compressed resources re-compressed.
 *
 * Note: wimlib_export_image() can provide similar functionality to
 * wimlib_join(), since it is possible to export all images from a split WIM.
 */
extern int wimlib_join(const char **swms, unsigned num_swms,
		       const char *output_path, int swm_open_flags,
		       int wim_write_flags,
		       wimlib_progress_func_t progress_func);

/**
 * Mounts an image in a WIM file on a directory read-only or read-write.
 *
 * The calling thread will be daemonized to service the filesystem, and this
 * function will not return until the image is unmounted, unless an error occurs
 * before the filesystem is successfully mounted.
 *
 * If the mount is read-write (::WIMLIB_MOUNT_FLAG_READWRITE specified),
 * modifications to the WIM are staged in a temporary directory.
 *
 * It is safe to mount multiple images from the same WIM file read-only at the
 * same time, but only if different ::WIMStruct's are used.  It is @b not safe
 * to mount multiple images from the same WIM file read-write at the same time.
 *
 * wimlib_mount_image() cannot be used on an image that was exported with
 * wimlib_export_image() while the dentry trees for both images are still in
 * memory.  In addition, wimlib_mount_image() may not be used to mount an image
 * that has just been added with wimlib_add_image(), unless the WIM has been
 * written and read into a new ::WIMStruct.
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
 * 	<br/><br/>
 * 	If ::WIMLIB_MOUNT_FLAG_READWRITE is given, the WIM is mounted read-write
 * 	rather than the default of read-only.
 * 	<br/> <br/>
 * 	WIMs may contain named (alternate) data streams, which are a somewhat
 * 	obscure NTFS feature.  They can be read and written on a mounted WIM
 * 	through one of several interfaces.  The interface to use if specified by
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
 * @param staging_dir
 * 	If non-NULL, the name of a directory in which the staging directory will
 * 	be created.  Ignored if ::WIMLIB_MOUNT_FLAG_READWRITE is not specified
 * 	in @a mount_flags.  If left @c NULL, the staging directory is created in
 * 	the same directory as the WIM file that @a wim was originally read from.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_ALREADY_LOCKED
 * 	A read-write mount was requested, but an an exclusive advisory lock on
 * 	the on-disk WIM file could not be acquired because another thread or
 * 	process has mounted an image from the WIM read-write or is currently
 * 	modifying the WIM in-place.
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
 * 	::WIMLIB_MOUNT_FLAG_READWRITE was specified in @a mount_flags, but the
 * 	staging directory could not be created.
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
extern int wimlib_mount_image(WIMStruct *wim, int image, const char *dir,
			      int mount_flags, WIMStruct **additional_swms,
			      unsigned num_additional_swms,
			      const char *staging_dir);

/**
 * Opens a WIM file and creates a ::WIMStruct for it.
 *
 * @param wim_file
 * 	The path to the WIM file to open.
 * @param open_flags
 * 	Bitwise OR of flags ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY and/or
 * 	::WIMLIB_OPEN_FLAG_SPLIT_OK.
 * 	<br/> <br/>
 * 	If ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY is given, the integrity table of
 * 	the WIM, if it exists, is checked, and this function will fail with an
 * 	::WIMLIB_ERR_INTEGRITY status if any of the computed SHA1 message
 * 	digests of the WIM do not exactly match the corresponding message
 * 	digests given in the integrity table.
 * 	<br/> <br/>
 * 	If ::WIMLIB_OPEN_FLAG_SPLIT_OK is given, no error will be issued if the
 * 	WIM is part of a split WIM; otherwise ::WIMLIB_ERR_SPLIT_UNSUPPORTED is
 * 	returned.  (This flag may be removed in the future, in which case no
 * 	error will be issued when opening a split WIM.)
 *
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
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
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY was specified in @a open_flags and @a
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
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY was specified in @a open_flags and @a
 * 	wim_file contains an integrity table, but the integrity table is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY
 * 	The lookup table for the WIM contained duplicate entries that are not
 * 	for metadata resources, or it contained an entry with a SHA1 message
 * 	digest of all 0's.
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
 * 	specified in @a open_flags.
 * @retval ::WIMLIB_ERR_UNKNOWN_VERSION
 * 	A number other than 0x10d00 is written in the version field of the WIM
 * 	header of @a wim_file.  (Probably a pre-Vista WIM).
 * @retval ::WIMLIB_ERR_XML
 * 	The XML data for @a wim_file is invalid.
 */
extern int wimlib_open_wim(const char *wim_file, int open_flags,
			   WIMStruct **wim_ret,
			   wimlib_progress_func_t progress_func);

/**
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
 * overwriting the header.  This can be much faster than a full rebuild, but it
 * only works if the only operations on the WIM have been to change the header
 * and/or XML data, or to add new images.  Writing a WIM in this mode begins
 * with writing any new file resources *after* everything in the old WIM, even
 * though this will leave a hole where the old lookup table, XML data, and
 * integrity were.  This is done so that the WIM remains valid even if the
 * operation is aborted mid-write.  The WIM header is only overwritten at the
 * very last moment, and up until that point the WIM will be seen as the old
 * version.
 *
 * By default, the overwrite mode is determine automatically based on the past
 * operations performed on the ::WIMStruct.  Use the flag
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
 * @param wim
 * 	Pointer to the ::WIMStruct for the WIM file to write.  There may have
 * 	been in-memory changes made to it, which are then reflected in the
 * 	output file.
 * @param write_flags
 * 	Bitwise OR of the flags ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY,
 * 	::WIMLIB_WRITE_FLAG_REBUILD, ::WIMLIB_WRITE_FLAG_RECOMPRESS, and/or
 * 	::WIMLIB_WRITE_FLAG_SOFT_DELETE.
 * @param num_threads
 * 	Number of threads to use for compression (see wimlib_write()).
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.  This function may return any value
 * returned by wimlib_write() as well as the following error codes:
 * @retval ::WIMLIB_ERR_ALREADY_LOCKED
 * 	The WIM was going to be modifien in-place (with no temporary file), but
 * 	an exclusive advisory lock on the on-disk WIM file could not be acquired
 * 	because another thread or process has mounted an image from the WIM
 * 	read-write or is currently modifying the WIM in-place.
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
			    unsigned num_threads,
			    wimlib_progress_func_t progress_func);

/**
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
 * 	::WIMLIB_ALL_IMAGES to print the files contained in all images.
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
 * 	::WIMLIB_ALL_IMAGES.
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
 * WIM file, but each split WIM part has its own lookup table.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 *
 * @return This function has no return value.
 */
extern void wimlib_print_lookup_table(WIMStruct *wim);

/**
 * Prints the metadata of the specified image in a WIM file.  The metadata
 * consists of the security data as well as the directory entry tree.  Each
 * image has its own metadata.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM file.
 * @param image
 * 	Which image to print the metadata for.  Can be the number of an image,
 * 	or ::WIMLIB_ALL_IMAGES to print the metadata for all images in the WIM.
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
 * 	::WIMLIB_ALL_IMAGES.
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
 * 	::WIMLIB_NO_IMAGE is returned.  If @a image_name_or_num was @c NULL or
 * 	the empty string, ::WIMLIB_NO_IMAGE is returned, even if one or more
 * 	images in @a wim has no name.
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
 * 	@a name was @c NULL or the empty string.
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
 * @param wim
 * 	The ::WIMStruct for the WIM to split.  It must be a standalone, one-part
 * 	WIM.
 * @param swm_name
 * 	Name of the SWM file to create.  This will be the name of the first
 * 	part.  The other parts will have the same name with 2, 3, 4, ..., etc.
 * 	appended before the suffix.
 * @param part_size
 * 	The maximum size per part, in bytes.  It is not guaranteed that this
 * 	will really be the maximum size per part, because some file resources in
 * 	the WIM may be larger than this size, and the WIM file format provides
 * 	no way to split up file resources among multiple WIMs.
 * @param write_flags
 * 	::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY if integrity tables are to be
 * 	included in the split WIM parts.
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.  This function may return any value
 * returned by wimlib_write() as well as the following error codes:
 *
 * @retval ::WIMLIB_ERR_SPLIT_UNSUPPORTED:
 * 	@a wim is not part 1 of a stand-alone WIM.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a swm_name was @c NULL, or @a part_size was 0.
 *
 * Note: the WIM's uncompressed and compressed resources are not checksummed
 * when they are copied from the joined WIM to the split WIM parts, nor are
 * compressed resources re-compressed.
 */
extern int wimlib_split(WIMStruct *wim, const char *swm_name,
			size_t part_size, int write_flags,
			wimlib_progress_func_t progress_func);

/**
 * Unmounts a WIM image that was mounted using wimlib_mount_image().
 *
 * The image to unmount is specified by the path to the mountpoint, not the
 * original ::WIMStruct passed to wimlib_mount_image(), which should not be
 * touched and also may have been allocated in a different process.
 *
 * To unmount the image, the thread calling this function communicates with the
 * thread that is managing the mounted WIM image.  This function blocks until it
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
 * 	progress of the current operation.
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
 * @retval ::WIMLIB_ERR_WRITE
 * 	A write error occurred when the filesystem daemon was writing to the new
 * 	WIM file, or the filesystem daemon was unable to flush changes that had
 * 	been made to files in the staging directory.
 */
extern int wimlib_unmount_image(const char *dir, int unmount_flags,
				wimlib_progress_func_t progress_func);

/**
 * Writes a standalone WIM to a file.
 *
 * This brings in resources from any external locations, such as directory trees
 * or NTFS volumes scanned with wimlib_add_image(), or other WIM files via
 * wimlib_export_image(), and incorporates them into a new on-disk WIM file.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for a WIM.  There may have been in-memory
 * 	changes made to it, which are then reflected in the output file.
 * @param path
 * 	The path to the file to write the WIM to.
 * @param image
 * 	The image inside the WIM to write.  Use ::WIMLIB_ALL_IMAGES to include all
 * 	images.
 * @param write_flags
 * 	Bitwise OR of the flags ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY,
 * 	::WIMLIB_WRITE_FLAG_RECOMPRESS, ::WIMLIB_WRITE_FLAG_FSYNC, and/or
 * 	::WIMLIB_WRITE_FLAG_SOFT_DELETE.
 * @param num_threads
 * 	Number of threads to use for compressing data.  If 0, the number of
 * 	threads is taken to be the number of online processors.  Note: if no
 * 	data compression needs to be done, no additional threads will be created
 * 	regardless of this parameter (e.g. if writing an uncompressed WIM, or
 * 	exporting an image from a compressed WIM to another WIM of the same
 * 	compression type without ::WIMLIB_WRITE_FLAG_RECOMPRESS specified in @a
 * 	write_flags).
 * @param progress_func
 * 	If non-NULL, a function that will be called periodically with the
 * 	progress of the current operation.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 * 	Failed to decompress a metadata or file resource in @a wim.
 * @retval ::WIMLIB_ERR_INVALID_DENTRY
 * 	A directory entry in the metadata resource for @a image in @a wim is
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@a image does not specify a single existing image in @a wim, and is not
 * 	::WIMLIB_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_HASH
 * 	A file that had previously been scanned for inclusion in the WIM by the
 * 	wimlib_add_image() or wimlib_add_image_from_ntfs_volume() functions was
 * 	concurrently modified, so it failed the SHA1 message digest check.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@a path was @c NULL.
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
			int write_flags, unsigned num_threads,
			wimlib_progress_func_t progress_func);

#endif /* _WIMLIB_H */
