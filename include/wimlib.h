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

/**
 * @mainpage
 *
 * This is the documentation for the library interface of wimlib 1.7.4, a C
 * library for creating, modifying, extracting, and mounting files in the
 * Windows Imaging Format.  This documentation is intended for developers only.
 * If you have installed wimlib and want to know how to use the @b wimlib-imagex
 * program, please see the manual pages and also the <a
 * href="http://sourceforge.net/p/wimlib/code/ci/master/tree/README">README
 * file</a>.
 *
 * @section sec_installing Installing
 *
 * @subsection UNIX
 *
 * Download the source code from <a
 * href="http://sourceforge.net/projects/wimlib/files">http://sourceforge.net/projects/wimlib/files</a>.
 * Install the library by running <c>configure && make && sudo make install</c>.
 * See the README for information about configuration options.  To use wimlib in
 * your program after installing it, include wimlib.h and link your program with
 * <c>-lwim</c>.
 *
 * @subsection Windows
 *
 * Download the Windows binary distribution with the appropriate architecture
 * (i686 or x86_64 --- also called "x86" and "amd64" respectively) from <a
 * href="http://sourceforge.net/projects/wimlib/files">http://sourceforge.net/projects/wimlib/files</a>.
 * Link your program with the libwim-15.dll file.  Make sure to also download
 * the source code so you can get wimlib.h, as it is not included in the binary
 * distribution.  If you need to access the DLL from other programming
 * languages, note that the calling convention is "cdecl".
 *
 * @section sec_examples Examples
 *
 * Several examples are located in the <a
 * href="http://sourceforge.net/p/wimlib/code/ci/master/tree/examples">examples</a>
 * directory of the source distribution.
 *
 * There is also the <a
 * href="http://sourceforge.net/p/wimlib/code/ci/master/tree/programs/imagex.c">
 * source code of <b>wimlib-imagex</b></a>, which is complicated but uses most
 * capabilities of wimlib.
 *
 * @section backwards_compatibility Backwards Compatibility
 *
 * New releases of wimlib are intended to be API/ABI compatible with old
 * releases, except when the libtool "age" is reset.  This most recently
 * occurred for the v1.4.0 (libwim7), v1.5.0 (libwim9), and v1.7.0 (libwim15)
 * releases.  However, the library is becoming increasingly stable, and the goal
 * is to maintain the current API/ABI for as long as possible unless there is a
 * strong reason not to.  Even for the v1.7.0 release (libwim15), the changes
 * were fairly limited.
 *
 * As with any other library, applications should not rely on internal
 * implementation details that may be subject to change.
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
 * Note: before calling any other function declared in wimlib.h,
 * wimlib_global_init() can (and in some cases, must) be called.  See its
 * documentation for more details.
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
 * - wimlib does not provide a clone of the @b PEImg tool, or the @b DISM
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
 * wimlib_extract_image() extracts, or "applies", an image from a WIM,
 * represented by a ::WIMStruct.  This normally extracts the image to a
 * directory, but when supported by the build of the library there is also a
 * special NTFS volume extraction mode (entered when ::WIMLIB_EXTRACT_FLAG_NTFS
 * is specified) that allows extracting a WIM image directly to an unmounted
 * NTFS volume.  Various other flags allow further customization of image
 * extraction.
 *
 * wimlib_extract_paths() and wimlib_extract_pathlist() allow extracting a list
 * of (possibly wildcard) paths from a WIM image.
 *
 * wimlib_extract_image_from_pipe() extracts an image from a pipable WIM sent
 * over a pipe; see @ref subsec_pipable_wims.
 *
 * Some details of how WIM extraction works are documented more fully in the
 * manual pages for <b>wimlib-imagex apply</b> and <b>wimlib-imagex extract</b>.
 */

/** @defgroup G_mounting_wim_images Mounting WIM images
 *
 * @brief Mount and unmount WIM images.
 *
 * On Linux, wimlib supports mounting images from WIM files either read-only or
 * read-write.  To mount an image, call wimlib_mount_image().  To unmount an
 * image, call wimlib_unmount_image().  Mounting can be done without root
 * privileges because it is implemented using FUSE (Filesystem in Userspace).
 *
 * If wimlib is compiled using the <code>--without-fuse</code> flag, these
 * functions will be available but will fail with ::WIMLIB_ERR_UNSUPPORTED.
 *
 * Note: if mounting is unsupported, wimlib still provides another way to modify
 * a WIM image (wimlib_update_image()).
 */

/**
 * @defgroup G_progress Progress Messages
 *
 * @brief Track the progress of long WIM operations.
 *
 * Library users can provide a progress function which will be called
 * periodically during operations such as extracting a WIM image or writing a
 * WIM image.  A ::WIMStruct can have a progress function of type
 * ::wimlib_progress_func_t associated with it by calling
 * wimlib_register_progress_function() or by opening the ::WIMStruct using
 * wimlib_open_wim_with_progress().  Once this is done, the progress function
 * will be called automatically during many operations, such as
 * wimlib_extract_image() and wimlib_write().
 *
 * Some functions that do not operate directly on a user-provided ::WIMStruct,
 * such as wimlib_join(), also take the progress function directly using an
 * extended version of the function, such as wimlib_join_with_progress().
 *
 * In wimlib v1.7.0 and later, progress functions are no longer just
 * unidirectional.  You can now return ::WIMLIB_PROGRESS_STATUS_ABORT to cause
 * the current operation to be aborted.  wimlib v1.7.0 also added the third
 * argument to ::wimlib_progress_func_t, which is a user-supplied context.
 */

/** @defgroup G_writing_and_overwriting_wims Writing and Overwriting WIMs
 *
 * @brief Write and overwrite on-disk WIM files.
 *
 * As described in @ref sec_basic_wim_handling_concepts, these functions are
 * fundamental to the design of the library as they allow new or modified
 * ::WIMStruct's to actually be written to on-disk files.  Call wimlib_write()
 * to write a new WIM file, or wimlib_overwrite() to persistently update an
 * existing WIM file.
 */

/** @defgroup G_nonstandalone_wims Creating and handling non-standalone WIMs
 *
 * @brief Create and handle non-standalone WIMs, such as split and delta WIMs.
 *
 * Normally, a ::WIMStruct represents a WIM file, but there's a bit more to it
 * than that.  Normally, WIM files are "standalone".  However, WIM files can
 * also be arranged in non-standalone ways, such as a set of on-disk files that
 * together form a single "split WIM" or "delta WIM".  Such arrangements are
 * fully supported by wimlib.  However, as a result, in such cases a ::WIMStruct
 * created from one of these on-disk files initially only partially represents
 * the full WIM and needs to, in effect, be logically combined with other
 * ::WIMStruct's before performing certain operations, such as extracting files
 * with wimlib_extract_image() or wimlib_extract_paths().  This is done by
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

#ifdef __GNUC__
#  define _wimlib_deprecated __attribute__((deprecated))
#else
#  define _wimlib_deprecated
#endif

/** @addtogroup G_general
 * @{ */

/** Major version of the library (for example, the 1 in 1.2.5).  */
#define WIMLIB_MAJOR_VERSION 1

/** Minor version of the library (for example, the 2 in 1.2.5). */
#define WIMLIB_MINOR_VERSION 7

/** Patch version of the library (for example, the 5 in 1.2.5). */
#define WIMLIB_PATCH_VERSION 4

#ifdef __cplusplus
extern "C" {
#endif

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
/** Path separator for WIM paths passed back to progress callbacks.
 * This is forward slash on UNIX and backslash on Windows.  */
#  define WIMLIB_WIM_PATH_SEPARATOR '\\'
#  define WIMLIB_WIM_PATH_SEPARATOR_STRING L"\\"
#else
/** Path separator for WIM paths passed back to progress callbacks.
 * This is forward slash on UNIX and backslash on Windows.  */
#  define WIMLIB_WIM_PATH_SEPARATOR '/'
#  define WIMLIB_WIM_PATH_SEPARATOR_STRING "/"
#endif

/** Use this to specify the root directory of the WIM image.  */
#define WIMLIB_WIM_ROOT_PATH WIMLIB_WIM_PATH_SEPARATOR_STRING

/** Use this to test if the specified path refers to the root directory of the
 * WIM image.  */
#define WIMLIB_IS_WIM_ROOT_PATH(path) \
		((path)[0] == WIMLIB_WIM_PATH_SEPARATOR &&	\
		 (path)[1] == 0)

/** Length of a Globally Unique Identifier (GUID)  */
#define WIMLIB_GUID_LEN 16

/**
 * Specifies a compression format.  Pass one of these values to
 * wimlib_create_new_wim(), wimlib_set_output_compression_type(),
 * wimlib_create_compressor(), or wimlib_create_decompressor().
 *
 * A WIM file has one default compression type and chunk size.  Normally, each
 * resource in the WIM file is compressed with this compression type.  However,
 * resources may be stored as uncompressed; for example, wimlib will do so if a
 * resource does not compress to less than its original size.  In addition, a
 * WIM with the new version number of 3584, or "ESD file", might contain solid
 * blocks with different compression types.
 */
enum wimlib_compression_type {
	/**
	 * No compression.
	 *
	 * This is a valid argument to wimlib_create_new_wim() and
	 * wimlib_set_output_compression_type(), but not to the functions in the
	 * compression API such as wimlib_create_compressor().
	 */
	WIMLIB_COMPRESSION_TYPE_NONE = 0,

	/**
	 * The XPRESS compression format.  This format combines Lempel-Ziv
	 * factorization with Huffman encoding.  Compression and decompression
	 * are both fast.  This format supports chunk sizes that are powers of 2
	 * between <c>2^12</c> and <c>2^16</c>, inclusively.
	 *
	 * wimlib's XPRESS compressor will, with the default settings, usually
	 * produce a better compression ratio, and work more quickly, than the
	 * implementation in Microsoft's WIMGAPI (as of Windows 8.1).
	 * Non-default compression levels are also supported.  For example,
	 * level 80 will enable two-pass optimal parsing, which is significantly
	 * slower but usually improves compression by several percent over the
	 * default level of 50.
	 *
	 * If using wimlib_create_compressor() to create an XPRESS compressor
	 * directly, the @p max_block_size parameter may be any positive value
	 * up to and including <c>2^16</c>.
	 */
	WIMLIB_COMPRESSION_TYPE_XPRESS = 1,

	/**
	 * The LZX compression format.  This format combines Lempel-Ziv
	 * factorization with Huffman encoding, but with more features and
	 * complexity than XPRESS.  Compression is slow to somewhat fast,
	 * depending on the settings.  Decompression is fast but slower than
	 * XPRESS.  This format supports chunk sizes that are powers of 2
	 * between <c>2^15</c> and <c>2^21</c>, inclusively.  Note: chunk sizes
	 * other than <c>2^15</c> are not compatible with the Microsoft
	 * implementation.
	 *
	 * wimlib's LZX compressor will, with the default settings, usually
	 * produce a better compression ratio, and work more quickly, than the
	 * implementation in Microsoft's WIMGAPI (as of Windows 8.1).
	 * Non-default compression levels are also supported.  For example,
	 * level 20 will provide fast compression, almost as fast as XPRESS.
	 *
	 * If using wimlib_create_compressor() to create an LZX compressor
	 * directly, the @p max_block_size parameter may be any positive value
	 * up to and including <c>2^21</c>.
	 */
	WIMLIB_COMPRESSION_TYPE_LZX = 2,

	/**
	 * The LZMS compression format.  This format combines Lempel-Ziv
	 * factorization with adaptive Huffman encoding and range coding.
	 * Compression and decompression are both fairly slow.  This format
	 * supports chunk sizes that are powers of 2 between <c>2^15</c> and
	 * <c>2^30</c>, inclusively.  This format is best used for large chunk
	 * sizes.  Note: LZMS compression is only compatible with wimlib v1.6.0
	 * and later, WIMGAPI Windows 8 and later, and DISM Windows 8.1 and
	 * later.  Also, chunk sizes larger than <c>2^26</c> are not compatible
	 * with the Microsoft implementation.
	 *
	 * wimlib's LZMS compressor is currently faster but will usually not
	 * compress as much as the implementation in Microsoft's WIMGAPI
	 * (Windows 8.1).
	 *
	 * If using wimlib_create_compressor() to create an LZMS compressor
	 * directly, the @p max_block_size parameter may be any positive value
	 * up to and including <c>1180427429</c>.
	 */
	WIMLIB_COMPRESSION_TYPE_LZMS = 3,
};

/** @} */
/** @addtogroup G_progress
 * @{ */

/** Possible values of the first parameter to the user-supplied
 * ::wimlib_progress_func_t progress function */
enum wimlib_progress_msg {

	/** A WIM image is about to be extracted.  @p info will point to
	 * ::wimlib_progress_info.extract.  This message is received once per
	 * image for calls to wimlib_extract_image() and
	 * wimlib_extract_image_from_pipe().  */
	WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN = 0,

	/** One or more file or directory trees within a WIM image is about to
	 * be extracted.  @p info will point to ::wimlib_progress_info.extract.
	 * This message is received only once per wimlib_extract_paths() and
	 * wimlib_extract_pathlist(), since wimlib combines all paths into a
	 * single extraction operation for optimization purposes.  */
	WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN = 1,

	/** This message may be sent periodically (not for every file) while
	 * files or directories are being created, prior to data stream
	 * extraction.  @p info will point to ::wimlib_progress_info.extract.
	 * In particular, the @p current_file_count and @p end_file_count
	 * members may be used to track the progress of this phase of
	 * extraction.  */
	WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE = 3,

	/** File data is currently being extracted.  @p info will point to
	 * ::wimlib_progress_info.extract.  This is the main message to track
	 * the progress of an extraction operation.  */
	WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS = 4,

	/** Starting to read a new part of a split pipable WIM over the pipe.
	 * @p info will point to ::wimlib_progress_info.extract.  */
	WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN = 5,

	/** This message may be sent periodically (not for every file) while
	 * file and directory metadata is being applied, following data stream
	 * extraction.  @p info will point to ::wimlib_progress_info.extract.
	 * In particular, the @p current_file_count and @p end_file_count
	 * members may be used to track the progress of this phase of
	 * extraction.  */
	WIMLIB_PROGRESS_MSG_EXTRACT_METADATA = 6,

	/** Confirms that the image has been successfully extracted.  @p info
	 * will point to ::wimlib_progress_info.extract.  This is paired with
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN.  */
	WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END = 7,

	/** Confirms that the files or directory trees have been successfully
	 * extracted.  @p info will point to ::wimlib_progress_info.extract.
	 * This is paired with ::WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN.  */
	WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END = 8,

	/** The directory or NTFS volume is about to be scanned for metadata.
	 * @p info will point to ::wimlib_progress_info.scan.  This message is
	 * received once per call to wimlib_add_image(), or once per capture
	 * source passed to wimlib_add_image_multisource(), or once per add
	 * command passed to wimlib_update_image().  */
	WIMLIB_PROGRESS_MSG_SCAN_BEGIN = 9,

	/** A directory or file has been scanned.  @p info will point to
	 * ::wimlib_progress_info.scan, and its @p cur_path member will be
	 * valid.  This message is only sent if ::WIMLIB_ADD_FLAG_VERBOSE has
	 * been specified.  */
	WIMLIB_PROGRESS_MSG_SCAN_DENTRY = 10,

	/** Confirms that the directory or NTFS volume has been successfully
	 * scanned.  @p info will point to ::wimlib_progress_info.scan.  This is
	 * paired with a previous ::WIMLIB_PROGRESS_MSG_SCAN_BEGIN message,
	 * possibly with many intervening ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY
	 * messages.  */
	WIMLIB_PROGRESS_MSG_SCAN_END = 11,

	/** File resources ("streams") are currently being written to the WIM.
	 * @p info will point to ::wimlib_progress_info.write_streams.  This
	 * message may be received many times while the WIM file is being
	 * written or appended to with wimlib_write(), wimlib_overwrite(), or
	 * wimlib_write_to_fd().  */
	WIMLIB_PROGRESS_MSG_WRITE_STREAMS = 12,

	/** Per-image metadata is about to be written to the WIM file.  @p info
	 * will not be valid. */
	WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN = 13,

	/** Confirms that per-image metadata has been successfully been written
	 * to the WIM file.  @p info will not be valid.  This message is paired
	 * with a preceding ::WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN message.
	 */
	WIMLIB_PROGRESS_MSG_WRITE_METADATA_END = 14,

	/** wimlib_overwrite() has successfully renamed the temporary file to
	 * the original WIM file, thereby committing the update.  @p info will
	 * point to ::wimlib_progress_info.rename.  Note: this message is not
	 * received if wimlib_overwrite() chose to append to the WIM file
	 * in-place.  */
	WIMLIB_PROGRESS_MSG_RENAME = 15,

	/** The contents of the WIM file are being checked against the integrity
	 * table.  @p info will point to ::wimlib_progress_info.integrity.  This
	 * message is only received (and may be received many times) when
	 * wimlib_open_wim_with_progress() is called with the
	 * ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY flag.  */
	WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY = 16,

	/** An integrity table is being calculated for the WIM being written.
	 * @p info will point to ::wimlib_progress_info.integrity.  This message
	 * is only received (and may be received many times) when a WIM file is
	 * being written with the flag ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY.  */
	WIMLIB_PROGRESS_MSG_CALC_INTEGRITY = 17,

	/** A wimlib_split() operation is in progress, and a new split part is
	 * about to be started.  @p info will point to
	 * ::wimlib_progress_info.split.  */
	WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART = 19,

	/** A wimlib_split() operation is in progress, and a split part has been
	 * finished. @p info will point to ::wimlib_progress_info.split.  */
	WIMLIB_PROGRESS_MSG_SPLIT_END_PART = 20,

	/** A WIM update command is just about to be executed. @p info will
	 * point to ::wimlib_progress_info.update.  This message is received
	 * once per update command when wimlib_update_image() is called with the
	 * flag ::WIMLIB_UPDATE_FLAG_SEND_PROGRESS.  */
	WIMLIB_PROGRESS_MSG_UPDATE_BEGIN_COMMAND = 21,

	/** A WIM update command has just been executed. @p info will point to
	 * ::wimlib_progress_info.update.  This message is received once per
	 * update command when wimlib_update_image() is called with the flag
	 * ::WIMLIB_UPDATE_FLAG_SEND_PROGRESS.  */
	WIMLIB_PROGRESS_MSG_UPDATE_END_COMMAND = 22,

	/** A file in the WIM image is being replaced as a result of a
	 * ::wimlib_add_command without ::WIMLIB_ADD_FLAG_NO_REPLACE specified.
	 * @p info will point to ::wimlib_progress_info.replace.  This is only
	 * received when ::WIMLIB_ADD_FLAG_VERBOSE is also specified in the add
	 * command.  */
	WIMLIB_PROGRESS_MSG_REPLACE_FILE_IN_WIM = 23,

	/** A WIM image is being applied with ::WIMLIB_EXTRACT_FLAG_WIMBOOT, and
	 * a file is being extracted normally (not as a WIMBoot "pointer file")
	 * due to it matching a pattern in the [PrepopulateList] section of the
	 * configuration file @c \\Windows\\System32\\WimBootCompress.ini in the
	 * WIM image.  @p info will point to
	 * ::wimlib_progress_info.wimboot_exclude.
	 */
	WIMLIB_PROGRESS_MSG_WIMBOOT_EXCLUDE = 24,

	/** Starting to unmount a WIM image.  @p info will point to
	 * ::wimlib_progress_info.unmount.  */
	WIMLIB_PROGRESS_MSG_UNMOUNT_BEGIN = 25,

	/** wimlib has used a file's data for the last time (including all data
	 * streams, if it has multiple).  @p info will point to
	 * ::wimlib_progress_info.done_with_file.  This message is only received
	 * if ::WIMLIB_WRITE_FLAG_SEND_DONE_WITH_FILE_MESSAGES was provided.  */
	WIMLIB_PROGRESS_MSG_DONE_WITH_FILE = 26,

	/** wimlib_verify_wim() is starting to verify the metadata for an image.
	 * @p info will point to ::wimlib_progress_info.verify_image.  */
	WIMLIB_PROGRESS_MSG_BEGIN_VERIFY_IMAGE = 27,

	/** wimlib_verify_wim() has finished verifying the metadata for an
	 * image.  @p info will point to ::wimlib_progress_info.verify_image.
	 */
	WIMLIB_PROGRESS_MSG_END_VERIFY_IMAGE = 28,

	/** wimlib_verify_wim() is verifying stream integrity.  @p info will
	 * point to ::wimlib_progress_info.verify_streams.  */
	WIMLIB_PROGRESS_MSG_VERIFY_STREAMS = 29,

	/**
	 * The progress function is being asked whether a file should be
	 * excluded from capture or not.  @p info will point to
	 * ::wimlib_progress_info.test_file_exclusion.  This is a bidirectional
	 * message that allows the progress function to set a flag if the file
	 * should be excluded.
	 *
	 * This message is only received if the flag
	 * ::WIMLIB_ADD_FLAG_TEST_FILE_EXCLUSION is used.  This method for file
	 * exclusions is independent of the "capture configuration file"
	 * mechanism.
	 */
	WIMLIB_PROGRESS_MSG_TEST_FILE_EXCLUSION = 30,

	/**
	 * An error has occurred and the progress function is being asked
	 * whether to ignore the error or not.  @p info will point to
	 * ::wimlib_progress_info.handle_error.  This is a bidirectional
	 * message.
	 *
	 * This message provides a limited capability for applications to
	 * recover from "unexpected" errors (i.e. those with no in-library
	 * handling policy) arising from the underlying operating system.
	 * Normally, any such error will cause the library to abort the current
	 * operation.  By implementing a handler for this message, the
	 * application can instead choose to ignore a given error.
	 *
	 * Currently, only the following types of errors will result in this
	 * progress message being sent:
	 *
	 *	- Directory tree scan errors, e.g. from wimlib_add_image()
	 *	- Most extraction errors; currently restricted to the Windows
	 *	  build of the library only.
	 */
	WIMLIB_PROGRESS_MSG_HANDLE_ERROR = 31,
};

/** Valid return values from user-provided progress functions
 * (::wimlib_progress_func_t).
 *
 * (Note: if an invalid value is returned, ::WIMLIB_ERR_UNKNOWN_PROGRESS_STATUS
 * will be issued.)
 */
enum wimlib_progress_status {

	/** The operation should be continued.  This is the normal return value.
	 */
	WIMLIB_PROGRESS_STATUS_CONTINUE	= 0,

	/** The operation should be aborted.  This will cause the current
	 * operation to fail with ::WIMLIB_ERR_ABORTED_BY_PROGRESS.  */
	WIMLIB_PROGRESS_STATUS_ABORT	= 1,
};

/**
 * A pointer to this union is passed to the user-supplied
 * ::wimlib_progress_func_t progress function.  One (or none) of the structures
 * contained in this union will be applicable for the operation
 * (::wimlib_progress_msg) indicated in the first argument to the progress
 * function. */
union wimlib_progress_info {

	/* N.B. I wanted these to be anonymous structs, but Doxygen won't
	 * document them if they aren't given a name... */

	/** Valid on the message ::WIMLIB_PROGRESS_MSG_WRITE_STREAMS.  This is
	 * the primary message for tracking the progress of writing a WIM file.
	 */
	struct wimlib_progress_info_write_streams {
		/** Total number of uncompressed bytes of stream data being
		 * written.  This can be thought of as the total uncompressed
		 * size of the files being archived, with some caveats.  WIM
		 * files use single-instance streams, so the size provided here
		 * only counts distinct streams, except for the following
		 * exception: the size provided here may include the sizes of
		 * all newly added (e.g. with wimlib_add_image() streams,
		 * pending automatic de-duplication during the write operation
		 * itself.  When each such stream de-duplication occurs, this
		 * number will be decreased by the size of the duplicate stream
		 * that need not be written.
		 *
		 * In the case of a wimlib_overwrite() that the library opted to
		 * perform in-place, both @p total_streams and @p total_bytes
		 * will only count the streams actually being written and not
		 * pre-existing streams in the WIM file.  */
		uint64_t total_bytes;

		/** Total number of streams being written.  This can be thought
		 * of as the total number of files being archived, with some
		 * caveats.  In general, a single file or directory may contain
		 * multiple data streams, each of which will be represented
		 * separately in this number.  Furthermore, WIM files use
		 * single-instance streams, so the stream count provided here
		 * only counts distinct streams, except for the following
		 * exception: the stream count provided here may include newly
		 * added (e.g. with wimlib_add_image() streams, pending
		 * automatic de-duplication during the write operation itself.
		 * When each such stream de-duplication occurs, this number will
		 * be decreased by 1 to account for the duplicate stream that
		 * need not be written.  */
		uint64_t total_streams;

		/** Number of uncompressed bytes of stream data that have been
		 * written so far.  This number be 0 initially, and will be
		 * equal to @p total_bytes at the end of the write operation.
		 * Note that @p total_bytes (but not @p completed_bytes) may
		 * decrease throughout the write operation due to the discovery
		 * of stream duplications.  */
		uint64_t completed_bytes;

		/** Number of streams that have been written so far.  This
		 * number will be 0 initially, and will be equal to @p
		 * total_streams at the end of the write operation.  Note that
		 * @p total_streams (but not @p completed_streams) may decrease
		 * throughout the write operation due to the discovery of stream
		 * duplications.
		 *
		 * For applications that wish to calculate a simple "percent
		 * complete" for the write operation, it will likely be more
		 * accurate to calculate the percentage from @p completed_bytes
		 * and @p total_bytes rather than @p completed_streams and
		 * @p total_streams because the time for the operation to
		 * complete is mainly determined by the number of bytes that
		 * need to be read, compressed, and written, not just the number
		 * of files being archived.  */
		uint64_t completed_streams;

		/** Number of threads that are being used to compress streams,
		 * or 1 if streams are being written uncompressed.  */
		uint32_t num_threads;

		/** The compression type being used to write the streams, as one
		 * of the ::wimlib_compression_type constants.  */
		int32_t	 compression_type;

		/** Number of split WIM parts from which streams are being
		 * written (may be 0 if irrelevant).   */
		uint32_t total_parts;

		/** This is currently broken and will always be 0.  */
		uint32_t completed_parts;
	} write_streams;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_SCAN_BEGIN,
	 * ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY, and
	 * ::WIMLIB_PROGRESS_MSG_SCAN_END.  */
	struct wimlib_progress_info_scan {
		/** Top-level directory being scanned; or, when capturing an NTFS
		 * volume with ::WIMLIB_ADD_FLAG_NTFS, this is instead the path
		 * to the file or block device that contains the NTFS volume
		 * being scanned.  */
		const wimlib_tchar *source;

		/** Path to the file (or directory) that has been scanned, valid
		 * on ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY.  When capturing an NTFS
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
			 * that points into the capture directory, and
			 * reparse-point fixups are enabled, so its target is
			 * being adjusted.  (Reparse point fixups can be
			 * disabled with the flag ::WIMLIB_ADD_FLAG_NORPFIX.)
			 */
			WIMLIB_SCAN_DENTRY_FIXED_SYMLINK,

			/** Reparse-point fixups are enabled, but the file is an
			 * absolute symbolic link or junction that does
			 * <b>not</b> point into the capture directory, so its
			 * target is <b>not</b> being adjusted.  */
			WIMLIB_SCAN_DENTRY_NOT_FIXED_SYMLINK,
		} status;

		union {
			/** Target path in the WIM image.  Only valid on
			 * messages ::WIMLIB_PROGRESS_MSG_SCAN_BEGIN and
			 * ::WIMLIB_PROGRESS_MSG_SCAN_END.  */
			const wimlib_tchar *wim_target_path;

			/** For ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY and a status
			 * of @p WIMLIB_SCAN_DENTRY_FIXED_SYMLINK or @p
			 * WIMLIB_SCAN_DENTRY_NOT_FIXED_SYMLINK, this is the
			 * target of the absolute symbolic link or junction.  */
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
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_METADATA,
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END, and
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END.
	 *
	 * Note: most of the time of an extraction operation will be spent
	 * extracting streams, and the application will receive
	 * ::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS during this time.  Using @p
	 * completed_bytes and @p total_bytes, the application can calculate a
	 * percentage complete.  However, note that this message does not, in
	 * general, actually provide information about which "file" is currently
	 * being extracted.  This is because wimlib, by default, extracts the
	 * individual data streams in whichever order it determines to be the
	 * most efficient.
	 */
	struct wimlib_progress_info_extract {
		/** Number of the image from which files are being extracted
		 * (1-based).  */
		uint32_t image;

		/** Extraction flags being used.  */
		uint32_t extract_flags;

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
		uint64_t total_streams;

		/** Number of (not necessarily unique) streams that have been
		 * extracted so far.  */
		uint64_t completed_streams;

		/** Currently only used for
		 * ::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN.  */
		uint32_t part_number;

		/** Currently only used for
		 * ::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN.  */
		uint32_t total_parts;

		/** Currently only used for
		 * ::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN.  */
		uint8_t guid[WIMLIB_GUID_LEN];

		/** For ::WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE and
		 * ::WIMLIB_PROGRESS_MSG_EXTRACT_METADATA messages, this is the
		 * number of files that have been processed so far.  Once the
		 * corresponding phase of extraction is complete, this value
		 * will be equal to @c end_file_count.  */
		uint64_t current_file_count;

		/** For ::WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE and
		 * ::WIMLIB_PROGRESS_MSG_EXTRACT_METADATA messages, this is
		 * total number of files that will be processed.
		 *
		 * This number is provided for informational purposes only.
		 * This number will not necessarily be equal to the number of
		 * files actually being extracted.  This is because extraction
		 * backends are free to implement an extraction algorithm that
		 * might be more efficient than processing every file in the
		 * "extract file structure" and "extract metadata" phases.  For
		 * example, the current implementation of the UNIX extraction
		 * backend will create files on-demand during the stream
		 * extraction phase. Therefore, when using that particular
		 * extraction backend, @p end_file_count will only include
		 * directories and empty files.  */
		uint64_t end_file_count;
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
		 * finished (::WIMLIB_PROGRESS_MSG_SPLIT_END_PART).
		 * As of wimlib v1.7.0, the library user may change this when
		 * receiving ::WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART in order to
		 * cause the next split WIM part to be written to a different
		 * location.  */
		wimlib_tchar *part_name;
	} split;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_REPLACE_FILE_IN_WIM  */
	struct wimlib_progress_info_replace {
		/** Path to the file in the WIM image that is being replaced  */
		const wimlib_tchar *path_in_wim;
	} replace;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_WIMBOOT_EXCLUDE  */
	struct wimlib_progress_info_wimboot_exclude {
		/** Path to the file in the WIM image  */
		const wimlib_tchar *path_in_wim;

		/** Path to which the file is being extracted  */
		const wimlib_tchar *extraction_path;
	} wimboot_exclude;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_UNMOUNT_BEGIN.  */
	struct wimlib_progress_info_unmount {
		/** Path to directory being unmounted  */
		const wimlib_tchar *mountpoint;

		/** Path to WIM file being unmounted  */
		const wimlib_tchar *mounted_wim;

		/** 1-based index of image being unmounted.  */
		uint32_t mounted_image;

		/** Flags that were passed to wimlib_mount_image() when the
		 * mountpoint was set up.  */
		uint32_t mount_flags;

		/** Flags passed to wimlib_unmount_image().  */
		uint32_t unmount_flags;
	} unmount;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_DONE_WITH_FILE.  */
	struct wimlib_progress_info_done_with_file {
		/* Path to the file whose data has been written to the WIM file,
		 * or is currently being asynchronously compressed in memory,
		 * and therefore is no longer needed by wimlib.
		 *
		 * WARNING: The file data will not actually be accessible in the
		 * WIM file until the WIM file has been completely written.
		 * Ordinarily you should <b>not</b> treat this message as a
		 * green light to go ahead and delete the specified file, since
		 * that would result in data loss if the WIM file cannot be
		 * successfully created for any reason.
		 *
		 * If a file has multiple names (hard links),
		 * ::WIMLIB_PROGRESS_MSG_DONE_WITH_FILE will only be received
		 * for one name.  Also, this message will not be received for
		 * empty files or reparse points (or symbolic links), unless
		 * they have nonempty named data streams.
		 */
		const wimlib_tchar *path_to_file;
	} done_with_file;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_BEGIN_VERIFY_IMAGE and
	 * ::WIMLIB_PROGRESS_MSG_END_VERIFY_IMAGE.  */
	struct wimlib_progress_info_verify_image {
		const wimlib_tchar *wimfile;
		uint32_t total_images;
		uint32_t current_image;
	} verify_image;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_VERIFY_STREAMS.  */
	struct wimlib_progress_info_verify_streams {
		const wimlib_tchar *wimfile;
		uint64_t total_streams;
		uint64_t total_bytes;
		uint64_t completed_streams;
		uint64_t completed_bytes;
	} verify_streams;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_TEST_FILE_EXCLUSION.  */
	struct wimlib_progress_info_test_file_exclusion {

		/**
		 * Path to the file for which exclusion is being tested.
		 *
		 * UNIX capture mode:  The path will be a standard relative or
		 * absolute UNIX filesystem path.
		 *
		 * NTFS-3g capture mode:  The path will be given relative to the
		 * root of the NTFS volume, with a leading slash.
		 *
		 * Windows capture mode:  The path will be a Win32 namespace
		 * path to the file.
		 */
		const wimlib_tchar *path;

		/**
		 * Indicates whether the file or directory will be excluded from
		 * capture or not.  This will be <tt>false</tt> by default.  The
		 * progress function can set this to <tt>true</tt> if it decides
		 * that the file needs to be excluded.
		 */
		bool will_exclude;
	} test_file_exclusion;

	/** Valid on messages ::WIMLIB_PROGRESS_MSG_HANDLE_ERROR.  */
	struct wimlib_progress_info_handle_error {

		/** Path to the file for which the error occurred, or NULL if
		 * not relevant.  */
		const wimlib_tchar *path;

		/** The wimlib error code associated with the error.  */
		int error_code;

		/**
		 * Indicates whether the error will be ignored or not.  This
		 * will be <tt>false</tt> by default; the progress function may
		 * set it to <tt>true</tt>.
		 */
		bool will_ignore;
	} handle_error;
};

/**
 * A user-supplied function that will be called periodically during certain WIM
 * operations.
 *
 * The first argument will be the type of operation that is being performed or
 * is about to be started or has been completed.
 *
 * The second argument will be a pointer to one of a number of structures
 * depending on the first argument.  It may be @c NULL for some message types.
 * Note that although this argument is not @c const, users should not modify it
 * except in explicitly documented cases.
 *
 * The third argument will be a user-supplied value that was provided when
 * registering or specifying the progress function.
 *
 * This function must return one of the ::wimlib_progress_status values.  By
 * default, you should return ::WIMLIB_PROGRESS_STATUS_CONTINUE (0).
 */
typedef enum wimlib_progress_status
	(*wimlib_progress_func_t)(enum wimlib_progress_msg msg_type,
				  union wimlib_progress_info *info,
				  void *progctx);

/** @} */
/** @addtogroup G_modifying_wims
 * @{ */

/** An array of these structures is passed to wimlib_add_image_multisource() to
 * specify the sources from which to create a WIM image. */
struct wimlib_capture_source {
	/** Absolute or relative path to a file or directory on the external
	 * filesystem to be included in the WIM image. */
	wimlib_tchar *fs_source_path;

	/** Destination path in the WIM image.  Use ::WIMLIB_WIM_ROOT_PATH to
	 * specify the root directory of the WIM image.  */
	wimlib_tchar *wim_target_path;

	/** Reserved; set to 0. */
	long reserved;
};

/** Set or unset the "readonly" WIM header flag (WIM_HDR_FLAG_READONLY in
 * Microsoft's documentation), based on the ::wimlib_wim_info.is_marked_readonly
 * member of the @p info parameter.  This is distinct from basic file
 * permissions; this flag can be set on a WIM file that is physically writable.
 *
 * wimlib disallows modifying on-disk WIM files with the readonly flag set.
 * However, wimlib_overwrite() with ::WIMLIB_WRITE_FLAG_IGNORE_READONLY_FLAG
 * will override this --- and in fact, this is necessary to set the readonly
 * flag persistently on an existing WIM file.
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

/** @addtogroup G_wim_information  */

/** @{ */

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

	/** 1 if reparse-point fixups are enabled for one or more images in the
	 * WIM.  */
	uint32_t has_rpfix : 1;

	/** 1 if the WIM is marked read-only.  */
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
 * thing as a "resource", except in the case of solid resources.)  */
struct wimlib_resource_entry {
	/** Uncompressed size of the stream in bytes. */
	uint64_t uncompressed_size;

	/** Compressed size of the stream in bytes.  This will be the same as @p
	 * uncompressed_size if the stream is uncompressed.  Or, if @p packed is
	 * 1, this will be 0.  */
	uint64_t compressed_size;

	/** Offset, in bytes, of this stream from the start of the WIM file.  Or
	 * if @p packed is 1, then this is actually the offset at which this
	 * stream begins in the uncompressed contents of the solid resource.
	 */
	uint64_t offset;

	/** SHA1 message digest of the stream's uncompressed contents.  */
	uint8_t sha1_hash[20];

	/** Which part of WIM this stream is in.  */
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

	/** 1 if this stream is located in a solid resource which may contain
	 * other streams (all compressed together) as well.  */
	uint32_t packed : 1;

	uint32_t reserved_flags : 26;

	/** If @p packed is 1, then this will specify the offset of the solid
	 * resource in the WIM.  */
	uint64_t raw_resource_offset_in_wim;

	/** If @p packed is 1, then this will specify the compressed size of the
	 * solid resource in the WIM.  */
	uint64_t raw_resource_compressed_size;

	uint64_t reserved[2];
};

/**
 * Information about a stream of a particular file in the WIM.
 *
 * Normally, only WIM images captured from NTFS filesystems will have multiple
 * streams per file.  In practice, this is a rarely used feature of the
 * filesystem.
 */
struct wimlib_stream_entry {
	/** Name of the stream, or NULL if the stream is unnamed. */
	const wimlib_tchar *stream_name;
	/** Location, size, and other information about the stream's data as
	 * stored in the WIM file.  */
	struct wimlib_resource_entry resource;
	uint64_t reserved[4];
};

/** Structure passed to the wimlib_iterate_dir_tree() callback function.
 * Roughly, the information about a "file" in the WIM--- but really a directory
 * entry ("dentry") because hard links are allowed.  The hard_link_group_id
 * field can be used to distinguish actual file inodes.  */
struct wimlib_dir_entry {
	/** Name of the file, or NULL if this file is unnamed.  Only the root
	 * directory of an image will be unnamed.  */
	const wimlib_tchar *filename;

	/** 8.3 name (or "DOS name", or "short name") of this file; or NULL if
	 * this file has no such name.  */
	const wimlib_tchar *dos_name;

	/** Full path to this file within the WIM image.  Path separators will
	 * be ::WIMLIB_WIM_PATH_SEPARATOR.  */
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
#define WIMLIB_REPARSE_TAG_WOF			0x80000017
#define WIMLIB_REPARSE_TAG_SYMLINK		0xA000000C
	/** If the file is a reparse point (FILE_ATTRIBUTE_REPARSE_POINT set in
	 * the attributes), this will give the reparse tag.  This tells you
	 * whether the reparse point is a symbolic link, junction point, or some
	 * other, more unusual kind of reparse point.  */
	uint32_t reparse_tag;

	/** Number of links to this file's inode (hard links).
	 *
	 * Currently, this will always be 1 for directories.  However, it can be
	 * greater than 1 for nondirectory files.  */
	uint32_t num_links;

	/** Number of named data streams this file has.  Normally 0.  */
	uint32_t num_named_streams;

	/** A unique identifier for this file's inode.  However, as a special
	 * case, if the inode only has a single link (@p num_links == 1), this
	 * value may be 0.
	 *
	 * Note: if a WIM image is captured from a filesystem, this value is not
	 * guaranteed to be the same as the original number of the inode on the
	 * filesystem.  */
	uint64_t hard_link_group_id;

	/** Time this file was created.  */
	struct timespec creation_time;

	/** Time this file was last written to.  */
	struct timespec last_write_time;

	/** Time this file was last accessed.  */
	struct timespec last_access_time;

	/** The UNIX user ID of this file.  This is a wimlib extension.
	 *
	 * This field is only valid if @p unix_mode != 0.  */
	uint32_t unix_uid;

	/** The UNIX group ID of this file.  This is a wimlib extension.
	 *
	 * This field is only valid if @p unix_mode != 0.  */
	uint32_t unix_gid;

	/** The UNIX mode of this file.  This is a wimlib extension.
	 *
	 * If this field is 0, then @p unix_uid, @p unix_gid, @p unix_mode, and
	 * @p unix_rdev are all unknown (fields are not present in the WIM
	 * image).  */
	uint32_t unix_mode;

	/** The UNIX device ID (major and minor number) of this file.  This is a
	 * wimlib extension.
	 *
	 * This field is only valid if @p unix_mode != 0.  */
	uint32_t unix_rdev;

	uint64_t reserved[14];

	/**
	 * Array of streams that make up this file.
	 *
	 * The first entry will always exist and will correspond to the unnamed
	 * data stream (default file contents), so it will have <c>stream_name
	 * == NULL</c>.  Alternatively, for reparse point files, the first entry
	 * will corresponding to the reparse data stream.
	 *
	 * Then, following the first entry, there be @p num_named_streams
	 * additional entries that specify the named data streams, if any, each
	 * of which will have <c>stream_name != NULL</c>.
	 */
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
/** @addtogroup G_modifying_wims
 * @{ */

/** UNIX-like systems only: Directly capture an NTFS volume rather than a
 * generic directory.  This requires that wimlib was compiled with support for
 * libntfs-3g.
 *
 * This flag cannot be combined with ::WIMLIB_ADD_FLAG_DEREFERENCE or
 * ::WIMLIB_ADD_FLAG_UNIX_DATA.
 *
 * Do not use this flag on Windows, where wimlib already supports all
 * Windows-native filesystems, including NTFS, through the Windows APIs.  */
#define WIMLIB_ADD_FLAG_NTFS			0x00000001

/** Follow symbolic links when scanning the directory tree.  Currently only
 * supported on UNIX-like systems.  */
#define WIMLIB_ADD_FLAG_DEREFERENCE		0x00000002

/** Call the progress function with the message
 * ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY when each directory or file has been
 * scanned.  */
#define WIMLIB_ADD_FLAG_VERBOSE			0x00000004

/** Mark the image being added as the bootable image of the WIM.  This flag is
 * valid only for wimlib_add_image() and wimlib_add_image_multisource().
 *
 * Note that you can also change the bootable image of a WIM using
 * wimlib_set_wim_info().
 *
 * Note: ::WIMLIB_ADD_FLAG_BOOT does something different from, and independent
 * from, ::WIMLIB_ADD_FLAG_WIMBOOT.  */
#define WIMLIB_ADD_FLAG_BOOT			0x00000008

/** UNIX-like systems only: Store the UNIX owner, group, mode, and device ID
 * (major and minor number) of each file.  Also allows capturing special files
 * such as device nodes and FIFOs.  See the documentation for the
 * <b>--unix-data</b> option to <b>wimlib-imagex capture</b> for more
 * information.  */
#define WIMLIB_ADD_FLAG_UNIX_DATA		0x00000010

/** Do not capture security descriptors.  Only has an effect in NTFS capture
 * mode, or in Windows native builds.  */
#define WIMLIB_ADD_FLAG_NO_ACLS			0x00000020

/** Fail immediately if the full security descriptor of any file or directory
 * cannot be accessed.  Only has an effect in Windows native builds.  The
 * default behavior without this flag is to first try omitting the SACL from the
 * security descriptor, then to try omitting the security descriptor entirely.
 */
#define WIMLIB_ADD_FLAG_STRICT_ACLS		0x00000040

/** Call the progress function with the message
 * ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY when a directory or file is excluded from
 * capture.  This is a subset of the messages provided by
 * ::WIMLIB_ADD_FLAG_VERBOSE.  */
#define WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE		0x00000080

/** Reparse-point fixups:  Modify absolute symbolic links (and junctions, in the
 * case of Windows) that point inside the directory being captured to instead be
 * absolute relative to the directory being captured.
 *
 * Without this flag, the default is to do reparse-point fixups if
 * WIM_HDR_FLAG_RP_FIX is set in the WIM header or if this is the first image
 * being added.  WIM_HDR_FLAG_RP_FIX is set if the first image in a WIM is
 * captured with reparse point fixups enabled and currently cannot be unset. */
#define WIMLIB_ADD_FLAG_RPFIX			0x00000100

/** Don't do reparse point fixups.  See ::WIMLIB_ADD_FLAG_RPFIX.  */
#define WIMLIB_ADD_FLAG_NORPFIX			0x00000200

/** Do not automatically exclude unsupported files or directories from capture;
 * e.g. encrypted files in NTFS-3g capture mode, or device files and FIFOs on
 * UNIX-like systems when not also using ::WIMLIB_ADD_FLAG_UNIX_DATA.  Instead,
 * fail with ::WIMLIB_ERR_UNSUPPORTED_FILE when such a file is encountered.  */
#define WIMLIB_ADD_FLAG_NO_UNSUPPORTED_EXCLUDE	0x00000400

/**
 * Automatically select a capture configuration appropriate for capturing
 * filesystems containing Windows operating systems.  For example,
 * "/pagefile.sys" and "System Volume Information" will be excluded.
 *
 * When this flag is specified, the corresponding @p config parameter (for
 * wimlib_add_image()) or member (for wimlib_update_image()) must be @c NULL.
 * Otherwise, ::WIMLIB_ERR_INVALID_PARAM will be returned.
 *
 * Note that the default behavior--- that is, when neither
 * ::WIMLIB_ADD_FLAG_WINCONFIG nor ::WIMLIB_ADD_FLAG_WIMBOOT is specified and @p
 * config is @c NULL--- is to use no capture configuration, meaning that no
 * files are excluded from capture.
 */
#define WIMLIB_ADD_FLAG_WINCONFIG		0x00000800

/**
 * Capture image as WIMBoot compatible.  In addition, if no capture
 * configuration file is explicitly specified use the capture configuration file
 * <c>$SOURCE/Windows/System32/WimBootCompress.ini</c> if it exists, where
 * <c>$SOURCE</c> is the directory being captured; or, if a capture
 * configuration file is explicitly specified, use it and also place it at
 * /Windows/System32/WimBootCompress.ini in the WIM image.
 *
 * Note: this will not by itself change the compression type.  Before writing
 * the WIM file, it's recommended to also do:
 *
 * \code
 *	wimlib_set_output_compression_type(wim, WIMLIB_COMPRESSION_TYPE_XPRESS);
 *	wimlib_set_output_chunk_size(wim, 4096);
 * \endcode
 *
 * since that makes access to the data faster (at the cost of a worse
 * compression ratio compared to the 32768-byte LZX chunks usually used).
 *
 * Note: ::WIMLIB_ADD_FLAG_WIMBOOT does something different from, and
 * independent from, ::WIMLIB_ADD_FLAG_BOOT.
 */
#define WIMLIB_ADD_FLAG_WIMBOOT			0x00001000

/**
 * If the add command involves adding a non-directory file to a location at
 * which there already exists a nondirectory file in the WIM image, issue
 * ::WIMLIB_ERR_INVALID_OVERLAY instead of replacing the file.  This only has an
 * effect when updating an existing image with wimlib_update_image().
 * This was the default behavior in wimlib v1.6.2 and earlier.
 */
#define WIMLIB_ADD_FLAG_NO_REPLACE		0x00002000

/**
 * Send ::WIMLIB_PROGRESS_MSG_TEST_FILE_EXCLUSION messages to the progress
 * function.
 *
 * Note: This method for file exclusions is independent from the capture
 * configuration file mechanism.
 */
#define WIMLIB_ADD_FLAG_TEST_FILE_EXCLUSION	0x00004000

/* Note: the WIMLIB_ADD_IMAGE_FLAG names are retained for source compatibility.
 * Use the WIMLIB_ADD_FLAG names in new code.  */
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
#define WIMLIB_ADD_IMAGE_FLAG_WIMBOOT		WIMLIB_ADD_FLAG_WIMBOOT


/** @} */
/** @addtogroup G_modifying_wims
 * @{ */

/** Do not issue an error if the path to delete does not exist. */
#define WIMLIB_DELETE_FLAG_FORCE			0x00000001

/** Delete the file or directory tree recursively; if not specified, an error is
 * issued if the path to delete is a directory. */
#define WIMLIB_DELETE_FLAG_RECURSIVE			0x00000002

/** @} */
/** @addtogroup G_modifying_wims
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

/** This advises the library that the program is finished with the source
 * WIMStruct and will not attempt to access it after the call to
 * wimlib_export_image(), with the exception of the call to wimlib_free().  */
#define WIMLIB_EXPORT_FLAG_GIFT				0x00000008

/**
 * Mark each exported image as WIMBoot-compatible.
 *
 * Note: by itself, this does change the destination WIM's compression type, nor
 * does it add the file @c \\Windows\\System32\\WimBootCompress.ini in the WIM
 * image.  Before writing the destination WIM, it's recommended to do something
 * like:
 *
 * \code
 *	wimlib_set_output_compression_type(wim, WIMLIB_COMPRESSION_TYPE_XPRESS);
 *	wimlib_set_output_chunk_size(wim, 4096);
 *	wimlib_add_tree(wim, image, L"myconfig.ini",
 *			L"\\Windows\\System32\\WimBootCompress.ini", 0);
 * \endcode
 */
#define WIMLIB_EXPORT_FLAG_WIMBOOT			0x00000010

/** @} */
/** @addtogroup G_extracting_wims
 * @{ */

/** Extract the image directly to an NTFS volume rather than a generic directory.
 * This mode is only available if wimlib was compiled with libntfs-3g support;
 * if not, ::WIMLIB_ERR_UNSUPPORTED will be returned.  In this mode, the
 * extraction target will be interpreted as the path to an NTFS volume image (as
 * a regular file or block device) rather than a directory.  It will be opened
 * using libntfs-3g, and the image will be extracted to the NTFS filesystem's
 * root directory.  Note: this flag cannot be used when wimlib_extract_image()
 * is called with ::WIMLIB_ALL_IMAGES as the @p image, nor can it be used with
 * wimlib_extract_paths() when passed multiple paths.  */
#define WIMLIB_EXTRACT_FLAG_NTFS			0x00000001

/** UNIX-like systems only:  Extract special UNIX data captured with
 * ::WIMLIB_ADD_FLAG_UNIX_DATA.  This flag cannot be combined with
 * ::WIMLIB_EXTRACT_FLAG_NTFS.  */
#define WIMLIB_EXTRACT_FLAG_UNIX_DATA			0x00000020

/** Do not extract security descriptors.  This flag cannot be combined with
 * ::WIMLIB_EXTRACT_FLAG_STRICT_ACLS.  */
#define WIMLIB_EXTRACT_FLAG_NO_ACLS			0x00000040

/** Fail immediately if the full security descriptor of any file or directory
 * cannot be set exactly as specified in the WIM file.  On Windows, the default
 * behavior without this flag when wimlib does not have permission to set the
 * correct security descriptor is to fall back to setting the security
 * descriptor with the SACL omitted, then with the DACL omitted, then with the
 * owner omitted, then not at all.  This flag cannot be combined with
 * ::WIMLIB_EXTRACT_FLAG_NO_ACLS.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_ACLS			0x00000080

/** This is the extraction equivalent to ::WIMLIB_ADD_FLAG_RPFIX.  This forces
 * reparse-point fixups on, so absolute symbolic links or junction points will
 * be fixed to be absolute relative to the actual extraction root.  Reparse-
 * point fixups are done by default for wimlib_extract_image() and
 * wimlib_extract_image_from_pipe() if WIM_HDR_FLAG_RP_FIX is set in the WIM
 * header.  This flag cannot be combined with ::WIMLIB_EXTRACT_FLAG_NORPFIX.  */
#define WIMLIB_EXTRACT_FLAG_RPFIX			0x00000100

/** Force reparse-point fixups on extraction off, regardless of the state of the
 * WIM_HDR_FLAG_RP_FIX flag in the WIM header.  This flag cannot be combined
 * with ::WIMLIB_EXTRACT_FLAG_RPFIX.  */
#define WIMLIB_EXTRACT_FLAG_NORPFIX			0x00000200

/** For wimlib_extract_paths() and wimlib_extract_pathlist() only:  Extract the
 * paths, each of which must name a regular file, to standard output.  */
#define WIMLIB_EXTRACT_FLAG_TO_STDOUT			0x00000400

/** Instead of ignoring files and directories with names that cannot be
 * represented on the current platform (note: Windows has more restrictions on
 * filenames than POSIX-compliant systems), try to replace characters or append
 * junk to the names so that they can be extracted in some form.
 *
 * Note: this flag is unlikely to have any effect when extracting a WIM image
 * that was captured on Windows.
 */
#define WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES	0x00000800

/** On Windows, when there exist two or more files with the same case
 * insensitive name but different case sensitive names, try to extract them all
 * by appending junk to the end of them, rather than arbitrarily extracting only
 * one.
 *
 * Note: this flag is unlikely to have any effect when extracting a WIM image
 * that was captured on Windows.
 */
#define WIMLIB_EXTRACT_FLAG_ALL_CASE_CONFLICTS		0x00001000

/** Do not ignore failure to set timestamps on extracted files.  This flag
 * currently only has an effect when extracting to a directory on UNIX-like
 * systems.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS		0x00002000

/** Do not ignore failure to set short names on extracted files.  This flag
 * currently only has an effect on Windows.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES          0x00004000

/** Do not ignore failure to extract symbolic links and junctions due to
 * permissions problems.  This flag currently only has an effect on Windows.  By
 * default, such failures are ignored since the default configuration of Windows
 * only allows the Administrator to create symbolic links.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS             0x00008000

/** Reserved for future use.  */
#define WIMLIB_EXTRACT_FLAG_RESUME			0x00010000

/** For wimlib_extract_paths() and wimlib_extract_pathlist() only:  Treat the
 * paths to extract as wildcard patterns ("globs") which may contain the
 * wildcard characters @c ? and @c *.  The @c ? character matches any
 * non-path-separator character, whereas the @c * character matches zero or more
 * non-path-separator characters.  Consequently, each glob may match zero or
 * more actual paths in the WIM image.
 *
 * By default, if a glob does not match any files, a warning but not an error
 * will be issued.  This is the case even if the glob did not actually contain
 * wildcard characters.  Use ::WIMLIB_EXTRACT_FLAG_STRICT_GLOB to get an error
 * instead.
 * */
#define WIMLIB_EXTRACT_FLAG_GLOB_PATHS			0x00040000

/** In combination with ::WIMLIB_EXTRACT_FLAG_GLOB_PATHS, causes an error
 * (::WIMLIB_ERR_PATH_DOES_NOT_EXIST) rather than a warning to be issued when
 * one of the provided globs did not match a file.  */
#define WIMLIB_EXTRACT_FLAG_STRICT_GLOB			0x00080000

/** Do not extract Windows file attributes such as readonly, hidden, etc.
 *
 * This flag has an effect on Windows as well as in the NTFS-3g extraction mode.
 */
#define WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES		0x00100000

/** For wimlib_extract_paths() and wimlib_extract_pathlist() only:  Do not
 * preserve the directory structure of the archive when extracting --- that is,
 * place each extracted file or directory tree directly in the target directory.
 *
 * The target directory will still be created if it does not already exist.  */
#define WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE	0x00200000

/** Windows only: Extract files as "pointers" back to the WIM archive.
 *
 * The effects of this option are fairly complex.  See the documentation for the
 * <b>--wimboot</b> option of <b>wimlib-imagex apply</b> for more information.
 */
#define WIMLIB_EXTRACT_FLAG_WIMBOOT			0x00400000

/** @} */
/** @addtogroup G_mounting_wim_images
 * @{ */

/** Mount the WIM image read-write rather than the default of read-only. */
#define WIMLIB_MOUNT_FLAG_READWRITE			0x00000001

/** Enable FUSE debugging by passing the @c -d option to @c fuse_main().  */
#define WIMLIB_MOUNT_FLAG_DEBUG				0x00000002

/** Do not allow accessing named data streams in the mounted WIM image.  */
#define WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_NONE		0x00000004

/** Access named data streams in the mounted WIM image through extended file
 * attributes named "user.X", where X is the name of a data stream.  This is the
 * default mode.  */
#define WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_XATTR	0x00000008

/** Access named data streams in the mounted WIM image by specifying the file
 * name, a colon, then the name of the data stream.  */
#define WIMLIB_MOUNT_FLAG_STREAM_INTERFACE_WINDOWS	0x00000010

/** Use UNIX metadata if available in the WIM image.  See
 * ::WIMLIB_ADD_FLAG_UNIX_DATA.  */
#define WIMLIB_MOUNT_FLAG_UNIX_DATA			0x00000020

/** Allow other users to see the mounted filesystem.  This passes the @c
 * allow_other option to fuse_main().  */
#define WIMLIB_MOUNT_FLAG_ALLOW_OTHER			0x00000040

/** @} */
/** @addtogroup G_creating_and_opening_wims
 * @{ */

/** Verify the WIM contents against the WIM's integrity table, if present.  This
 * causes the raw data of the WIM file, divided into 10 MB chunks, to be
 * checksummed and checked against the SHA1 message digests specified in the
 * integrity table.  If there are any mismatches, ::WIMLIB_ERR_INTEGRITY is
 * issued.  If the WIM file does not contain an integrity table, this flag has
 * no effect.  */
#define WIMLIB_OPEN_FLAG_CHECK_INTEGRITY		0x00000001

/** Issue an error (::WIMLIB_ERR_IS_SPLIT_WIM) if the WIM is part of a split
 * WIM.  Software can provide this flag for convenience if it explicitly does
 * not want to support split WIMs.  */
#define WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT			0x00000002

/** Check if the WIM is writable and issue an error
 * (::WIMLIB_ERR_WIM_IS_READONLY) if it is not.  A WIM is considered writable
 * only if it is writable at the filesystem level, does not have the
 * WIM_HDR_FLAG_READONLY flag set in its header, and is not part of a spanned
 * set.  It is not required to provide this flag before attempting to make
 * changes to the WIM, but with this flag you get an error immediately rather
 * than potentially much later, when wimlib_overwrite() is finally called.  */
#define WIMLIB_OPEN_FLAG_WRITE_ACCESS			0x00000004

/** @} */
/** @addtogroup G_mounting_wim_images
 * @{ */

/** Provide ::WIMLIB_WRITE_FLAG_CHECK_INTEGRITY when committing the WIM image.
 * Ignored if ::WIMLIB_UNMOUNT_FLAG_COMMIT not also specified.  */
#define WIMLIB_UNMOUNT_FLAG_CHECK_INTEGRITY		0x00000001

/** Commit changes to the read-write mounted WIM image.
 * If this flag is not specified, changes will be discarded.  */
#define WIMLIB_UNMOUNT_FLAG_COMMIT			0x00000002

/** Provide ::WIMLIB_WRITE_FLAG_REBUILD when committing the WIM image.
 * Ignored if ::WIMLIB_UNMOUNT_FLAG_COMMIT not also specified.  */
#define WIMLIB_UNMOUNT_FLAG_REBUILD			0x00000004

/** Provide ::WIMLIB_WRITE_FLAG_RECOMPRESS when committing the WIM image.
 * Ignored if ::WIMLIB_UNMOUNT_FLAG_COMMIT not also specified.  */
#define WIMLIB_UNMOUNT_FLAG_RECOMPRESS			0x00000008

/**
 * In combination with ::WIMLIB_UNMOUNT_FLAG_COMMIT for a read-write mounted WIM
 * image, forces all file descriptors to the open WIM image to be closed before
 * committing it.
 *
 * Without ::WIMLIB_UNMOUNT_FLAG_COMMIT or with a read-only mounted WIM image,
 * this flag has no effect.
 */
#define WIMLIB_UNMOUNT_FLAG_FORCE			0x00000010

/** In combination with ::WIMLIB_UNMOUNT_FLAG_COMMIT for a read-write mounted
 * WIM image, causes the modified image to be committed to the WIM file as a
 * new, unnamed image appended to the archive.  The original image in the WIM
 * file will be unmodified.  */
#define WIMLIB_UNMOUNT_FLAG_NEW_IMAGE			0x00000020

/** @} */
/** @addtogroup G_modifying_wims
 * @{ */

/** Send ::WIMLIB_PROGRESS_MSG_UPDATE_BEGIN_COMMAND and
 * ::WIMLIB_PROGRESS_MSG_UPDATE_END_COMMAND messages.  */
#define WIMLIB_UPDATE_FLAG_SEND_PROGRESS		0x00000001

/** @} */
/** @addtogroup G_writing_and_overwriting_wims
 * @{ */

/**
 * Include an integrity table in the resulting WIM file.
 *
 * For ::WIMStruct's created with wimlib_open_wim(), the default behavior is to
 * include an integrity table if and only if one was present before.  For
 * ::WIMStruct's created with wimlib_create_new_wim(), the default behavior is
 * to not include an integrity table.
 */
#define WIMLIB_WRITE_FLAG_CHECK_INTEGRITY		0x00000001

/**
 * Do not include an integrity table in the resulting WIM file.  This is the
 * default behavior, unless the ::WIMStruct was created by opening a WIM with an
 * integrity table.
 */
#define WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY		0x00000002

/**
 * Write the WIM as "pipable".  After writing a WIM with this flag specified,
 * images from it can be applied directly from a pipe using
 * wimlib_extract_image_from_pipe().  See the documentation for the
 * <b>--pipable</b> option of <b>wimlib-imagex capture</b> for more information.
 * Beware: WIMs written with this flag will not be compatible with Microsoft's
 * software.
 *
 * For ::WIMStruct's created with wimlib_open_wim(), the default behavior is to
 * write the WIM as pipable if and only if it was pipable before.  For
 * ::WIMStruct's created with wimlib_create_new_wim(), the default behavior is
 * to write the WIM as non-pipable.
 */
#define WIMLIB_WRITE_FLAG_PIPABLE			0x00000004

/**
 * Do not write the WIM as "pipable".  This is the default behavior, unless the
 * ::WIMStruct was created by opening a pipable WIM.
 */
#define WIMLIB_WRITE_FLAG_NOT_PIPABLE			0x00000008

/**
 * When writing streams to the WIM file, recompress them, even if their data is
 * already available in the desired compressed form (for example, in a WIM file
 * from which an image has been exported using wimlib_export_image()).
 *
 * ::WIMLIB_WRITE_FLAG_RECOMPRESS can be used to recompress with a higher
 * compression ratio for the same compression type and chunk size.  Simply using
 * the default compression settings may suffice for this, especially if the WIM
 * file was created using another program/library that may not use as
 * sophisticated compression algorithms.  Or,
 * wimlib_set_default_compression_level() can be called beforehand to set an
 * even higher compression level than the default.
 *
 * If the WIM contains solid resources, then ::WIMLIB_WRITE_FLAG_RECOMPRESS can
 * be used in combination with ::WIMLIB_WRITE_FLAG_SOLID to prevent any solid
 * resources from being re-used.  Otherwise, solid resources are re-used
 * somewhat more liberally than normal compressed resources.
 *
 * ::WIMLIB_WRITE_FLAG_RECOMPRESS does <b>not</b> cause recompression of streams
 * that would not otherwise be written.  For example, a call to
 * wimlib_overwrite() with ::WIMLIB_WRITE_FLAG_RECOMPRESS will not, by itself,
 * cause already-existing streams in the WIM file to be recompressed.  To force
 * the WIM file to be fully rebuilt and recompressed, combine
 * ::WIMLIB_WRITE_FLAG_RECOMPRESS with ::WIMLIB_WRITE_FLAG_REBUILD.
 */
#define WIMLIB_WRITE_FLAG_RECOMPRESS			0x00000010

/**
 * Immediately before closing the WIM file, sync its data to disk.
 *
 * This flag forces the function to wait until the data is safely on disk before
 * returning success.  Otherwise, modern operating systems tend to cache data
 * for some time (in some cases, 30+ seconds) before actually writing it to
 * disk, even after reporting to the application that the writes have succeeded.
 *
 * wimlib_overwrite() will set this flag automatically if it decides to
 * overwrite the WIM file via a temporary file instead of in-place.  This is
 * necessary on POSIX systems; it will, for example, avoid problems with delayed
 * allocation on ext4.
 */
#define WIMLIB_WRITE_FLAG_FSYNC				0x00000020

/**
 * For wimlib_overwrite(), rebuild the entire WIM file, even if it otherwise
 * could be updated in-place by appending to it.
 *
 * When rebuilding the WIM file, stream reference counts will be recomputed, and
 * any streams with 0 reference count (e.g. from deleted files or images) will
 * not be included in the resulting WIM file.  This can free up space that is
 * currently not being used.
 *
 * This flag can be combined with ::WIMLIB_WRITE_FLAG_RECOMPRESS to force all
 * data to be recompressed.  Otherwise, compressed data is re-used if possible.
 *
 * wimlib_write() ignores this flag.
 */
#define WIMLIB_WRITE_FLAG_REBUILD			0x00000040

/**
 * For wimlib_overwrite(), override the default behavior after one or more calls
 * to wimlib_delete_image(), which is to rebuild the entire WIM file.  With this
 * flag, only minimal changes to correctly remove the image from the WIM file
 * will be taken.  In particular, all streams will be retained, even if they are
 * no longer referenced.  This may not be what you want, because no space will
 * be saved by deleting an image in this way.
 *
 * wimlib_write() ignores this flag.
 */
#define WIMLIB_WRITE_FLAG_SOFT_DELETE			0x00000080

/**
 * For wimlib_overwrite(), allow overwriting the WIM file even if the readonly
 * flag (WIM_HDR_FLAG_READONLY) is set in the WIM header.  This can be used
 * following a call to wimlib_set_wim_info() with the
 * ::WIMLIB_CHANGE_READONLY_FLAG flag to actually set the readonly flag on the
 * on-disk WIM file.
 *
 * wimlib_write() ignores this flag.
 */
#define WIMLIB_WRITE_FLAG_IGNORE_READONLY_FLAG		0x00000100

/**
 * Do not include streams already present in other WIMs.  This flag can be used
 * to write a "delta" WIM after resources from the WIM on which the delta is to
 * be based were referenced with wimlib_reference_resource_files() or
 * wimlib_reference_resources().
 */
#define WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS		0x00000200

/**
 * Advises the library that for writes of all WIM images, all streams needed for
 * the WIM are already present (not in external resource WIMs) and their
 * reference counts are correct, so the code does not need to recalculate which
 * streams are referenced.  This is for optimization purposes only, since with
 * this flag specified, the metadata resources may not need to be decompressed
 * and parsed.
 *
 * wimlib_overwrite() will set this flag automatically.
 */
#define WIMLIB_WRITE_FLAG_STREAMS_OK			0x00000400

/**
 * For wimlib_write(), retain the WIM's GUID instead of generating a new one.
 *
 * wimlib_overwrite() sets this by default, since the WIM remains, logically,
 * the same file.
 */
#define WIMLIB_WRITE_FLAG_RETAIN_GUID			0x00000800

/**
 * When writing streams in the resulting WIM file, combine multiple streams into
 * a single compressed resource instead of compressing them independently.  This
 * is also known as creating a "solid archive".  This tends to produce a better
 * compression ratio at the cost of much slower random access.
 *
 * WIM files created with this flag are only compatible with wimlib v1.6.0 or
 * later, WIMGAPI Windows 8 or later, and DISM Windows 8.1 or later.  WIM files
 * created with this flag use a different version number in their header (3584
 * instead of 68864) and are also called "ESD files".
 *
 * If this flag is passed to wimlib_overwrite(), any new data streams will be
 * written in solid mode.  Use both ::WIMLIB_WRITE_FLAG_REBUILD and
 * ::WIMLIB_WRITE_FLAG_RECOMPRESS to force the entire WIM file be rebuilt with
 * all streams recompressed in solid mode.
 *
 * Currently, new solid resources will, by default, be written using LZMS
 * compression with 32 MiB (33554432 byte) chunks.  Use
 * wimlib_set_output_pack_compression_type() and/or
 * wimlib_set_output_pack_chunk_size() to change this.  This is independent of
 * the WIM's main compression type and chunk size; you can have a WIM that
 * nominally uses LZX compression and 32768 byte chunks but actually contains
 * LZMS-compressed solid resources, for example.  However, if including solid
 * blocks, I suggest that you set the WIM's main compression type to LZMS as
 * well, either by creating the WIM with
 * ::wimlib_create_new_wim(::WIMLIB_COMPRESSION_TYPE_LZMS, ...) or by calling
 * ::wimlib_set_output_compression_type(..., ::WIMLIB_COMPRESSION_TYPE_LZMS).
 *
 * This flag will be set by default when writing or overwriting a WIM file that
 * either already contains solid resources, or has had solid resources exported
 * into it and the WIM's main compression type is LZMS.
 */
#define WIMLIB_WRITE_FLAG_SOLID				0x00001000

/**
 * Deprecated: this is the old name for ::WIMLIB_WRITE_FLAG_SOLID, retained for
 * source compatibility.
 */
#define WIMLIB_WRITE_FLAG_PACK_STREAMS			WIMLIB_WRITE_FLAG_SOLID

/**
 * Send ::WIMLIB_PROGRESS_MSG_DONE_WITH_FILE messages while writing the WIM
 * file.  This is only needed in the unusual case that the library user needs to
 * know exactly when wimlib has read each file for the last time.
 */
#define WIMLIB_WRITE_FLAG_SEND_DONE_WITH_FILE_MESSAGES	0x00002000

/** @} */
/** @addtogroup G_general
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
/** @addtogroup G_nonstandalone_wims
 * @{ */

/** For wimlib_reference_resource_files(), enable shell-style filename globbing.
 * Ignored by wimlib_reference_resources().  */
#define WIMLIB_REF_FLAG_GLOB_ENABLE		0x00000001

/** For wimlib_reference_resource_files(), issue an error
 * (::WIMLIB_ERR_GLOB_HAD_NO_MATCHES) if a glob did not match any files.  The
 * default behavior without this flag is to issue no error at that point, but
 * then attempt to open the glob as a literal path, which of course will fail
 * anyway if no file exists at that path.  No effect if
 * ::WIMLIB_REF_FLAG_GLOB_ENABLE is not also specified.  Ignored by
 * wimlib_reference_resources().  */
#define WIMLIB_REF_FLAG_GLOB_ERR_ON_NOMATCH	0x00000002

/** @} */
/** @addtogroup G_modifying_wims
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
	/** Filesystem path to the file or directory tree to add.  */
	wimlib_tchar *fs_source_path;

	/** Destination path in the WIM image.  Use ::WIMLIB_WIM_ROOT_PATH to
	 * specify the root directory of the WIM image.  */
	wimlib_tchar *wim_target_path;

	/** Path to capture configuration file to use, or @c NULL for default.
	 */
	wimlib_tchar *config_file;

	/** Bitwise OR of WIMLIB_ADD_FLAG_* flags. */
	int add_flags;
};

/** Data for a ::WIMLIB_UPDATE_OP_DELETE operation. */
struct wimlib_delete_command {

	/** Path, specified from the root of the WIM image, for the file or
	 * directory tree within the WIM image to be deleted.  */
	wimlib_tchar *wim_path;

	/** Bitwise OR of WIMLIB_DELETE_FLAG_* flags.  */
	int delete_flags;
};

/** Data for a ::WIMLIB_UPDATE_OP_RENAME operation. */
struct wimlib_rename_command {

	/** Path, specified from the root of the WIM image, for the source file
	 * or directory tree within the WIM image.  */
	wimlib_tchar *wim_source_path;

	/** Path, specified from the root of the WIM image, for the destination
	 * file or directory tree within the WIM image.  */
	wimlib_tchar *wim_target_path;

	/** Reserved; set to 0.  */
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
/** @addtogroup G_general
 * @{ */

/**
 * Possible values of the error code returned by many functions in wimlib.
 *
 * See the documentation for each wimlib function to see specifically what error
 * codes can be returned by a given function, and what they mean.
 */
enum wimlib_error_code {
	WIMLIB_ERR_SUCCESS                            = 0,
	WIMLIB_ERR_ALREADY_LOCKED                     = 1,
	WIMLIB_ERR_DECOMPRESSION                      = 2,
	WIMLIB_ERR_FUSE                               = 6,
	WIMLIB_ERR_GLOB_HAD_NO_MATCHES                = 8,
	WIMLIB_ERR_ICONV_NOT_AVAILABLE                = 9,
	WIMLIB_ERR_IMAGE_COUNT                        = 10,
	WIMLIB_ERR_IMAGE_NAME_COLLISION               = 11,
	WIMLIB_ERR_INSUFFICIENT_PRIVILEGES            = 12,
	WIMLIB_ERR_INTEGRITY                          = 13,
	WIMLIB_ERR_INVALID_CAPTURE_CONFIG             = 14,
	WIMLIB_ERR_INVALID_CHUNK_SIZE                 = 15,
	WIMLIB_ERR_INVALID_COMPRESSION_TYPE           = 16,
	WIMLIB_ERR_INVALID_HEADER                     = 17,
	WIMLIB_ERR_INVALID_IMAGE                      = 18,
	WIMLIB_ERR_INVALID_INTEGRITY_TABLE            = 19,
	WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY         = 20,
	WIMLIB_ERR_INVALID_METADATA_RESOURCE          = 21,
	WIMLIB_ERR_INVALID_MULTIBYTE_STRING           = 22,
	WIMLIB_ERR_INVALID_OVERLAY                    = 23,
	WIMLIB_ERR_INVALID_PARAM                      = 24,
	WIMLIB_ERR_INVALID_PART_NUMBER                = 25,
	WIMLIB_ERR_INVALID_PIPABLE_WIM                = 26,
	WIMLIB_ERR_INVALID_REPARSE_DATA               = 27,
	WIMLIB_ERR_INVALID_RESOURCE_HASH              = 28,
	WIMLIB_ERR_INVALID_UTF16_STRING               = 30,
	WIMLIB_ERR_INVALID_UTF8_STRING                = 31,
	WIMLIB_ERR_IS_DIRECTORY                       = 32,
	WIMLIB_ERR_IS_SPLIT_WIM                       = 33,
	WIMLIB_ERR_LIBXML_UTF16_HANDLER_NOT_AVAILABLE = 34,
	WIMLIB_ERR_LINK                               = 35,
	WIMLIB_ERR_METADATA_NOT_FOUND                 = 36,
	WIMLIB_ERR_MKDIR                              = 37,
	WIMLIB_ERR_MQUEUE                             = 38,
	WIMLIB_ERR_NOMEM                              = 39,
	WIMLIB_ERR_NOTDIR                             = 40,
	WIMLIB_ERR_NOTEMPTY                           = 41,
	WIMLIB_ERR_NOT_A_REGULAR_FILE                 = 42,
	WIMLIB_ERR_NOT_A_WIM_FILE                     = 43,
	WIMLIB_ERR_NOT_PIPABLE                        = 44,
	WIMLIB_ERR_NO_FILENAME                        = 45,
	WIMLIB_ERR_NTFS_3G                            = 46,
	WIMLIB_ERR_OPEN                               = 47,
	WIMLIB_ERR_OPENDIR                            = 48,
	WIMLIB_ERR_PATH_DOES_NOT_EXIST                = 49,
	WIMLIB_ERR_READ                               = 50,
	WIMLIB_ERR_READLINK                           = 51,
	WIMLIB_ERR_RENAME                             = 52,
	WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED         = 54,
	WIMLIB_ERR_RESOURCE_NOT_FOUND                 = 55,
	WIMLIB_ERR_RESOURCE_ORDER                     = 56,
	WIMLIB_ERR_SET_ATTRIBUTES                     = 57,
	WIMLIB_ERR_SET_REPARSE_DATA                   = 58,
	WIMLIB_ERR_SET_SECURITY                       = 59,
	WIMLIB_ERR_SET_SHORT_NAME                     = 60,
	WIMLIB_ERR_SET_TIMESTAMPS                     = 61,
	WIMLIB_ERR_SPLIT_INVALID                      = 62,
	WIMLIB_ERR_STAT                               = 63,
	WIMLIB_ERR_UNEXPECTED_END_OF_FILE             = 65,
	WIMLIB_ERR_UNICODE_STRING_NOT_REPRESENTABLE   = 66,
	WIMLIB_ERR_UNKNOWN_VERSION                    = 67,
	WIMLIB_ERR_UNSUPPORTED                        = 68,
	WIMLIB_ERR_UNSUPPORTED_FILE                   = 69,
	WIMLIB_ERR_WIM_IS_READONLY                    = 71,
	WIMLIB_ERR_WRITE                              = 72,
	WIMLIB_ERR_XML                                = 73,
	WIMLIB_ERR_WIM_IS_ENCRYPTED                   = 74,
	WIMLIB_ERR_WIMBOOT                            = 75,
	WIMLIB_ERR_ABORTED_BY_PROGRESS                = 76,
	WIMLIB_ERR_UNKNOWN_PROGRESS_STATUS            = 77,
	WIMLIB_ERR_MKNOD                              = 78,
	WIMLIB_ERR_MOUNTED_IMAGE_IS_BUSY              = 79,
	WIMLIB_ERR_NOT_A_MOUNTPOINT                   = 80,
	WIMLIB_ERR_NOT_PERMITTED_TO_UNMOUNT           = 81,
	WIMLIB_ERR_FVE_LOCKED_VOLUME		      = 82,
};


/** Used to indicate no WIM image or an invalid WIM image. */
#define WIMLIB_NO_IMAGE		0

/** Used to specify all images in the WIM. */
#define WIMLIB_ALL_IMAGES	(-1)

/** @}  */

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
 * 	Pointer to the ::WIMStruct to which to add the image.
 * @param source
 * 	A path to a directory or unmounted NTFS volume that will be captured as
 * 	a WIM image.
 * @param name
 *	Name to give the new image.  If @c NULL or empty, the new image is given
 *	no name.  If nonempty, it must specify a name that does not already
 *	exist in @p wim.
 * @param config_file
 *	Path to capture configuration file, or @c NULL.  This file may specify,
 *	among other things, which files to exclude from capture.  See the man
 *	page for <b>wimlib-imagex capture</b> (<b>--config</b> option) for
 *	details of the file format.  If @c NULL, the default capture
 *	configuration shall be used.  Ordinarily, the default capture
 *	configuration will result in no files being excluded from capture purely
 *	based on name; however, the ::WIMLIB_ADD_FLAG_WINCONFIG and
 *	::WIMLIB_ADD_FLAG_WIMBOOT flags modify the default.
 * @param add_flags
 * 	Bitwise OR of flags prefixed with WIMLIB_ADD_FLAG.
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
 *
 * If a progress function is registered with @p wim, it will receive the
 * messages ::WIMLIB_PROGRESS_MSG_SCAN_BEGIN and ::WIMLIB_PROGRESS_MSG_SCAN_END.
 * In addition, if ::WIMLIB_ADD_FLAG_VERBOSE is specified in @p add_flags, it
 * will receive ::WIMLIB_PROGRESS_MSG_SCAN_DENTRY.
 */
extern int
wimlib_add_image(WIMStruct *wim,
		 const wimlib_tchar *source,
		 const wimlib_tchar *name,
		 const wimlib_tchar *config_file,
		 int add_flags);

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
			     const wimlib_tchar *config_file,
			     int add_flags);

/**
 * @ingroup G_modifying_wims
 *
 * Add the file or directory tree at @p fs_source_path on the filesystem to the
 * location @p wim_target_path within the specified @p image of the @p wim.
 *
 * This just builds an appropriate ::wimlib_add_command and passes it to
 * wimlib_update_image().
 */
extern int
wimlib_add_tree(WIMStruct *wim, int image,
		const wimlib_tchar *fs_source_path,
		const wimlib_tchar *wim_target_path, int add_flags);

/**
 * @ingroup G_creating_and_opening_wims
 *
 * Creates a ::WIMStruct for a new WIM file.
 *
 * This only creates an in-memory structure for a WIM that initially contains no
 * images.  No on-disk file is created until wimlib_write() is called.
 *
 * @param ctype
 * 	The type of compression to be used in the new WIM file, as one of the
 * 	::wimlib_compression_type constants.
 * 	<br/>
 * 	This choice is not necessarily final; if desired, it can still be
 * 	changed at any time before the WIM is written to disk, using
 * 	wimlib_set_output_compression_type().  In addition, if you wish to use a
 * 	non-default chunk size, you will need to call
 * 	wimlib_set_output_chunk_size().
 * @param wim_ret
 * 	On success, a pointer to an opaque ::WIMStruct for the new WIM file is
 * 	written to the memory location pointed to by this parameter.  The
 * 	::WIMStruct must be freed using using wimlib_free() when finished with
 * 	it.
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 * 	@p ctype was not a supported compression type.
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
 * Note: no changes are committed to the underlying WIM file (if any) until
 * wimlib_write() or wimlib_overwrite() is called.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for the WIM file that contains the image(s)
 * 	being deleted.
 * @param image
 * 	The number of the image to delete, or ::WIMLIB_ALL_IMAGES to delete all
 * 	images.
 *
 * @return 0 on success; nonzero on failure.  On failure, @p wim is guaranteed
 * to be left unmodified only if @p image specified a single image.  If instead
 * @p image was ::WIMLIB_ALL_IMAGES and @p wim contained more than one image, it's
 * possible for some but not all of the images to have been deleted when a
 * failure status is returned.
 *
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p image does not exist in the WIM and is not ::WIMLIB_ALL_IMAGES.
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
 * Delete the @p path from the specified @p image of the @p wim.
 *
 * This just builds an appropriate ::wimlib_delete_command and passes it to
 * wimlib_update_image().
 */
extern int
wimlib_delete_path(WIMStruct *wim, int image,
		   const wimlib_tchar *path, int delete_flags);

/**
 * @ingroup G_modifying_wims
 *
 * Exports an image, or all the images, from a WIM file, into another WIM file.
 *
 * The destination image is made to share the same dentry tree and security data
 * structure as the source image.  This places some restrictions on additional
 * functions that may be called.  For example, you may not call wimlib_free() on
 * @p src_wim before calling wimlib_write() or wimlib_overwrite() on @p dest_wim
 * because @p dest_wim will have references back to @p src_wim.
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
		    int export_flags);

/**
 * @ingroup G_extracting_wims
 *
 * Extracts an image, or all images, from a WIM to a directory or NTFS volume
 * image.
 *
 * The exact behavior of how wimlib extracts files from a WIM image is
 * controllable by the @p extract_flags parameter, but there also are
 * differences depending on the platform (UNIX-like vs Windows).  See the manual
 * page for <b>wimlib-imagex apply</b> for more information, including about the
 * NTFS-3g extraction mode.
 *
 * @param wim
 *	The WIM from which to extract the image(s), specified as a pointer to
 *	the ::WIMStruct for a standalone WIM file, a delta WIM file, or part 1
 *	of a split WIM.  In the case of a WIM file that is not standalone, this
 *	::WIMStruct must have had any needed external resources previously
 *	referenced using wimlib_reference_resources() or
 *	wimlib_reference_resource_files().
 * @param image
 *	The image to extract, specified as either the 1-based index of a single
 *	image to extract, or ::WIMLIB_ALL_IMAGES to specify that all images are
 *	to be extracted.  However, ::WIMLIB_ALL_IMAGES cannot be used if
 *	::WIMLIB_EXTRACT_FLAG_NTFS is specified in @p extract_flags.
 * @param target
 *	Directory to extract the WIM image(s) to; or, with
 *	::WIMLIB_EXTRACT_FLAG_NTFS specified in @p extract_flags, the path to
 *	the unmounted NTFS volume to which to extract the image.
 * @param extract_flags
 *	Bitwise OR of flags prefixed with WIMLIB_EXTRACT_FLAG.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 *	Failed to decompress data contained in the WIM.
 * @retval ::WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	The metadata for one of the images to extract was invalid.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	The extraction flags were invalid; more details may be found in the
 *	documentation for the specific extraction flags that were specified.  Or
 *	@p target was @c NULL or an empty string, or @p wim was @c NULL.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_HASH
 *	The SHA1 message digest of an extracted stream did not match the SHA1
 *	message digest given in the WIM.  In other words, the WIM file is
 *	corrupted, so the data cannot be extracted in its original form.
 * @retval ::WIMLIB_ERR_LINK
 *	Failed to create a symbolic link or a hard link.
 * @retval ::WIMLIB_ERR_METADATA_NOT_FOUND
 *	The metadata resource for one of the images to extract was not found.
 *	This can happen if @p wim represents a non-first part of a split WIM.
 * @retval ::WIMLIB_ERR_MKDIR
 *	Failed create a directory.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_OPEN
 *	Could not create a file, or failed to open an already-extracted file.
 * @retval ::WIMLIB_ERR_READ
 *	Failed to read data from the WIM.
 * @retval ::WIMLIB_ERR_READLINK
 *	Failed to determine the target of a symbolic link in the WIM.
 * @retval ::WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED
 *	Failed to fix the target of an absolute symbolic link (e.g. if the
 *	target would have exceeded the maximum allowed length).  (Only if
 *	reparse data was supported by the extraction mode and
 *	::WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS was specified in @p
 *	extract_flags.)
 * @retval ::WIMLIB_ERR_RESOURCE_NOT_FOUND
 *	One of the files or directories that needed to be extracted referenced a
 *	stream not present in the WIM's lookup table (or in any of the lookup
 *	tables of the split WIM	parts).  This can happen if the WIM is not
 *	standalone and the necessary resource WIMs, or split WIM parts, were not
 *	referenced with wimlib_reference_resource_files().
 * @retval ::WIMLIB_ERR_SET_ATTRIBUTES
 *	Failed to set attributes on a file.
 * @retval ::WIMLIB_ERR_SET_REPARSE_DATA
 *	Failed to set reparse data on a file (only if reparse data was supported
 *	by the extraction mode).
 * @retval ::WIMLIB_ERR_SET_SECURITY
 *	Failed to set security descriptor on a file.
 * @retval ::WIMLIB_ERR_SET_SHORT_NAME
 *	Failed to set the short name of a file.
 * @retval ::WIMLIB_ERR_SET_TIMESTAMPS
 *	Failed to set timestamps on a file.
 * @retval ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 *	Unexpected end-of-file occurred when reading data from the WIM.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 *	A requested extraction flag, or the data or metadata that must be
 *	extracted to support it, is unsupported in the build and configuration
 *	of wimlib, or on the current platform or extraction mode or target
 *	volume.  Flags affected by this include ::WIMLIB_EXTRACT_FLAG_NTFS,
 *	::WIMLIB_EXTRACT_FLAG_UNIX_DATA, ::WIMLIB_EXTRACT_FLAG_STRICT_ACLS,
 *	::WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES,
 *	::WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS, and
 *	::WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS.  For example, if
 *	::WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES is specified in @p
 *	extract_flags, ::WIMLIB_ERR_UNSUPPORTED will be returned if the WIM
 *	image contains one or more files with short names, but extracting short
 *	names is not supported --- on Windows, this occurs if the target volume
 *	does not support short names, while on non-Windows, this occurs if
 *	::WIMLIB_EXTRACT_FLAG_NTFS was not specified in @p extract_flags.
 * @retval ::WIMLIB_ERR_WIMBOOT
 *	::WIMLIB_EXTRACT_FLAG_WIMBOOT was specified in @p extract_flags, but
 *	there was a problem creating WIMBoot pointer files.
 * @retval ::WIMLIB_ERR_WRITE
 * 	Failed to write data to a file being extracted.
 *
 * If a progress function is registered with @p wim, then as each image is
 * extracted it will receive ::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN, then
 * zero or more ::WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE messages, then zero
 * or more ::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS messages, then zero or more
 * ::WIMLIB_PROGRESS_MSG_EXTRACT_METADATA messages, then
 * ::WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END.
 */
extern int
wimlib_extract_image(WIMStruct *wim, int image,
		     const wimlib_tchar *target, int extract_flags);

/**
 * @ingroup G_extracting_wims
 *
 * Extract one image from a pipe on which a pipable WIM is being sent.
 *
 * See the documentation for ::WIMLIB_WRITE_FLAG_PIPABLE, and @ref
 * subsec_pipable_wims, for more information about pipable WIMs.
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
 *	Same as the corresponding parameter to wimlib_extract_image().
 *
 * @return 0 on success; nonzero on error.  The possible error codes include
 * those returned by wimlib_extract_image() and wimlib_open_wim() as well as the
 * following:
 *
 * @retval ::WIMLIB_ERR_INVALID_PIPABLE_WIM
 *	Data read from the pipable WIM was invalid.
 * @retval ::WIMLIB_ERR_NOT_PIPABLE
 *	The WIM being piped over @p pipe_fd is a normal WIM, not a pipable WIM.
 */
extern int
wimlib_extract_image_from_pipe(int pipe_fd,
			       const wimlib_tchar *image_num_or_name,
			       const wimlib_tchar *target, int extract_flags);

/*
 * @ingroup G_extracting_wims
 *
 * Same as wimlib_extract_image_from_pipe(), but allows specifying a progress
 * function.  The progress function will be used while extracting the WIM image
 * and will receive the normal extraction progress messages, such as
 * ::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS, in addition to
 * ::WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN.
 */
extern int
wimlib_extract_image_from_pipe_with_progress(int pipe_fd,
					     const wimlib_tchar *image_num_or_name,
					     const wimlib_tchar *target,
					     int extract_flags,
					     wimlib_progress_func_t progfunc,
					     void *progctx);

/**
 * @ingroup G_extracting_wims
 *
 * Similar to wimlib_extract_paths(), but the paths to extract from the WIM
 * image are specified in the ASCII, UTF-8, or UTF-16LE text file named by @p
 * path_list_file which itself contains the list of paths to use, one per line.
 * Leading and trailing whitespace is ignored.  Empty lines and lines beginning
 * with the ';' or '#' characters are ignored.  No quotes are needed, as paths
 * are otherwise delimited by the newline character.  However, quotes will be
 * stripped if present.
 *
 * The error codes are the same as those returned by wimlib_extract_paths(),
 * except that wimlib_extract_pathlist() returns an appropriate error code if it
 * cannot read the path list file (e.g. ::WIMLIB_ERR_OPEN, ::WIMLIB_ERR_STAT,
 * ::WIMLIB_ERR_READ).
 */
extern int
wimlib_extract_pathlist(WIMStruct *wim, int image,
			const wimlib_tchar *target,
			const wimlib_tchar *path_list_file,
			int extract_flags);

/**
 * @ingroup G_extracting_wims
 *
 * Extract zero or more paths (files or directory trees) from the specified WIM
 * image.
 *
 * By default, each path will be extracted to a corresponding subdirectory of
 * the target based on its location in the WIM image.  For example, if one of
 * the paths to extract is "/Windows/explorer.exe" and the target is "outdir",
 * the file will be extracted to "outdir/Windows/explorer.exe".  This behavior
 * can be changed by providing the flag
 * ::WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE, which will cause each file
 * or directory tree to be placed directly in the target directory --- so the
 * same example would extract "/Windows/explorer.exe" to "outdir/explorer.exe".
 *
 * Symbolic links will not be dereferenced when paths in the WIM image are
 * interpreted.
 *
 * @param wim
 *	WIM from which to extract the paths, specified as a pointer to the
 *	::WIMStruct for a standalone WIM file, a delta WIM file, or part 1 of a
 *	split WIM.  In the case of a WIM file that is not standalone, this
 *	::WIMStruct must have had any needed external resources previously
 *	referenced using wimlib_reference_resources() or
 *	wimlib_reference_resource_files().
 * @param image
 *	1-based index of the WIM image from which to extract the paths.
 * @param paths
 *	Array of paths to extract.  Each element must be the absolute path to a
 *	file or directory within the WIM image.  Separators may be either
 *	forwards or backwards slashes, and leading path separators are optional.
 *	The paths will be interpreted either case-sensitively (UNIX default) or
 *	case-insensitively (Windows default); however, the behavior can be
 *	configured explicitly at library initialization time by passing an
 *	appropriate flag to wimlib_global_init().
 *	<br/>
 *	By default, the characters @c * and @c ? are interpreted literally.
 *	This can be changed by specifying ::WIMLIB_EXTRACT_FLAG_GLOB_PATHS in @p
 *	extract_flags.
 *	<br/>
 *	By default, if any paths to extract do not exist, the error code
 *	::WIMLIB_ERR_PATH_DOES_NOT_EXIST is returned.  This behavior changes if
 *	::WIMLIB_EXTRACT_FLAG_GLOB_PATHS is specified in @p extract_flags.
 * @param num_paths
 *	Number of paths specified in @p paths.
 * @param target
 *	Directory to which to extract the paths; or with
 *	::WIMLIB_EXTRACT_FLAG_NTFS specified in @p extract_flags, the path to an
 *	unmounted NTFS volume to which to extract the paths.  Unlike the @p
 *	paths being extracted, the @p target must be native path.  On UNIX-like
 *	systems it may not contain backslashes, for example.
 * @param extract_flags
 *	Bitwise OR of flags prefixed with WIMLIB_EXTRACT_FLAG.
 *
 * @return 0 on success; nonzero on error.  Most of the error codes are the same
 * as those returned by wimlib_extract_image().  Below, some of the error codes
 * returned in situations specific to path-mode extraction are documented:
 *
 * @retval ::WIMLIB_ERR_PATH_DOES_NOT_EXIST
 *	One of the paths to extract did not exist in the WIM image.  This error
 *	code can only be returned if ::WIMLIB_EXTRACT_FLAG_GLOB_PATHS was not
 *	specified in @p extract_flags, or if both
 *	::WIMLIB_EXTRACT_FLAG_GLOB_PATHS and ::WIMLIB_EXTRACT_FLAG_STRICT_GLOB
 *	were specified in @p extract_flags.
 * @retval ::WIMLIB_ERR_NOT_A_REGULAR_FILE
 *	::WIMLIB_EXTRACT_FLAG_TO_STDOUT was specified in @p extract_flags, but
 *	one of the paths to extract did not name a regular file.
 *
 * If a progress function is registered with @p wim, it will receive
 * ::WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS.  Note that because the extraction code
 * is stream-based and not file-based, there is no way to get information about
 * which path is currently being extracted, but based on byte count you can
 * still calculate an approximate percentage complete for the extraction overall
 * which may be all you really need anyway.
 */
extern int
wimlib_extract_paths(WIMStruct *wim,
		     int image,
		     const wimlib_tchar *target,
		     const wimlib_tchar * const *paths,
		     size_t num_paths,
		     int extract_flags);

/**
 * @ingroup G_wim_information
 *
 * Extracts the XML data of a WIM file to a file stream.  Every WIM file
 * includes a string of XML that describes the images contained in the WIM.
 *
 * See wimlib_get_xml_data() to read the XML data into memory instead.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct to query.  This need not represent a
 * 	standalone WIM (e.g. it could represent part of a split WIM).
 * @param fp
 * 	@c stdout, or a FILE* opened for writing, to extract the data to.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@p wim is not a ::WIMStruct that was created by wimlib_open_wim().
 * @retval ::WIMLIB_ERR_NOMEM
 *	Failed to allocate needed memory.
 * @retval ::WIMLIB_ERR_READ
 *	Error reading the XML data from the WIM file.
 * @retval ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 *	Error reading the XML data from the WIM file.
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
 * 	Pointer to the ::WIMStruct to free.
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
 * 	The ::wimlib_compression_type value to convert.
 *
 * @return
 * 	A statically allocated string naming the compression algorithm,
 * 	such as "None", "LZX", "XPRESS", or "Invalid".
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
 * 	Pointer to a statically allocated string describing the error code.  If
 * 	the error code is for some reason not recognized by the library, the
 * 	string will be "Unknown error".
 */
extern const wimlib_tchar *
wimlib_get_error_string(enum wimlib_error_code code);

/**
 * @ingroup G_wim_information
 *
 * Returns the description of the specified image.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct to query.  This need not represent a
 * 	standalone WIM (e.g. it could represent part of a split WIM).
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
 * 	Pointer to the ::WIMStruct to query.  This need not represent a
 * 	standalone WIM (e.g. it could represent part of a split WIM).
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
 * @ingroup G_general
 *
 * Returns the version of wimlib as a 32-bit number whose top 12 bits contain
 * the major version, the next 10 bits contain the minor version, and the low 10
 * bits contain the patch version.
 *
 * In other words, the returned value is equal to <code>((WIMLIB_MAJOR_VERSION
 * << 20) | (WIMLIB_MINOR_VERSION << 10) | WIMLIB_PATCH_VERSION)</code> for the
 * corresponding header file.
 */
extern uint32_t
wimlib_get_version(void);

/**
 * @ingroup G_wim_information
 *
 * Get basic information about a WIM file.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct to query.  This need not represent a
 * 	standalone WIM (e.g. it could represent part of a split WIM).
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
 * 	Pointer to the ::WIMStruct to query.  This need not represent a
 * 	standalone WIM (e.g. it could represent part of a split WIM).
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
 * 	Pointer to the ::WIMStruct to query.  This need not represent a
 * 	standalone WIM (e.g. it could represent part of a split WIM).
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
 * 	Pointer to the ::WIMStruct to query.  This need not represent a
 * 	standalone WIM (e.g. it could represent part of a split WIM).
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
	    int wim_write_flags);

/**
 * @ingroup G_nonstandalone_wims
 *
 * Same as wimlib_join(), but allows specifying a progress function.  The
 * progress function will receive the write progress messages, such as
 * ::WIMLIB_PROGRESS_MSG_WRITE_STREAMS, while writing the joined WIM.  In
 * addition, if ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY is specified in @p
 * swm_open_flags, the progress function will receive a series of
 * ::WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY messages when each of the split WIM
 * parts is opened.
 */
extern int
wimlib_join_with_progress(const wimlib_tchar * const *swms,
			  unsigned num_swms,
			  const wimlib_tchar *output_path,
			  int swm_open_flags,
			  int wim_write_flags,
			  wimlib_progress_func_t progfunc,
			  void *progctx);


/**
 * @ingroup G_mounting_wim_images
 *
 * Mounts an image from a WIM file on a directory read-only or read-write.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct containing the image to be mounted.
 * @param image
 * 	The 1-based index of the image to mount.
 * @param dir
 * 	The path to an existing empty directory on which to mount the WIM image.
 * @param mount_flags
 * 	Bitwise OR of flags prefixed with WIMLIB_MOUNT_FLAG.  Use
 * 	::WIMLIB_MOUNT_FLAG_READWRITE to request a read-write mount instead of a
 * 	read-only mount.
 * @param staging_dir
 * 	If non-NULL, the name of a directory in which a temporary directory for
 * 	storing modified or added files will be created.  Ignored if
 * 	::WIMLIB_MOUNT_FLAG_READWRITE is not specified in @p mount_flags.  If
 * 	left @c NULL, the staging directory is created in the same directory as
 * 	the WIM file that @p wim was originally read from.  The staging
 * 	directory is automatically deleted when the image is unmounted.
 *
 * @return 0 on success; nonzero on error.  The possible error codes include:
 *
 * @retval ::WIMLIB_ERR_ALREADY_LOCKED
 * 	An image from the WIM file is already mounted read-write, or another
 * 	process is currently appending data to the WIM file.
 * @retval ::WIMLIB_ERR_FUSE
 * 	A non-zero status code was returned by @c fuse_main().
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p image does not specify an existing, single image in @p wim.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	@p wim was @c NULL; or @p dir was NULL or an empty string; or an
 *	unrecognized flag was specified in @p mount_flags; or the WIM image has
 *	already been modified in memory (e.g. by wimlib_update_image()).
 * @retval ::WIMLIB_ERR_MKDIR
 * 	::WIMLIB_MOUNT_FLAG_READWRITE was specified in @p mount_flags, but the
 * 	staging directory could not be created.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	::WIMLIB_MOUNT_FLAG_READWRITE was specified in @p mount_flags, but the
 *	WIM file is considered read-only because of any of the reasons mentioned
 *	in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS flag.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	Mounting is not supported in this build of the library.
 *
 * This function can additionally return ::WIMLIB_ERR_DECOMPRESSION,
 * ::WIMLIB_ERR_INVALID_METADATA_RESOURCE, ::WIMLIB_ERR_METADATA_NOT_FOUND,
 * ::WIMLIB_ERR_NOMEM, ::WIMLIB_ERR_READ, or
 * ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE, all of which indicate failure (for
 * different reasons) to read the metadata resource for the image to mount.
 *
 * The ability to mount WIM image is implemented using FUSE (Filesystem in
 * UserSpacE).  Depending on how FUSE is set up on your system, this function
 * may work as normal users in addition to the root user.
 *
 * Mounting WIM images is not supported if wimlib was configured
 * <code>--without-fuse</code>.  This includes Windows builds of wimlib;
 * ::WIMLIB_ERR_UNSUPPORTED will be returned in such cases.
 *
 * Calling this function daemonizes the process, unless
 * ::WIMLIB_MOUNT_FLAG_DEBUG was specified or an early error occurs.
 *
 * It is safe to mount multiple images from the same underlying WIM file
 * read-only at the same time, but only if different ::WIMStruct's are used.  It
 * is @b not safe to mount multiple images from the same WIM file read-write at
 * the same time.
 *
 * To unmount the image, call wimlib_unmount_image().  This may be done in a
 * different process.
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
 * @param wim_ret
 * 	On success, a pointer to an opaque ::WIMStruct for the opened WIM file
 * 	is written to the memory location pointed to by this parameter.  The
 * 	::WIMStruct must be freed using using wimlib_free() when finished with
 * 	it.
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_IMAGE_COUNT
 * 	The number of metadata resources found in the WIM did not match the
 * 	image count specified in the WIM header, or the number of &lt;IMAGE&gt;
 * 	elements in the XML data of the WIM did not match the image count
 * 	specified in the WIM header.
 * @retval ::WIMLIB_ERR_INTEGRITY
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY was specified in @p open_flags and
 * 	the WIM contained an integrity table, but the SHA1 message digest for a
 * 	chunk of the WIM did not match the corresponding value in the integrity
 * 	table.
 * @retval ::WIMLIB_ERR_INVALID_CHUNK_SIZE
 * 	The library did not recognize the compression chunk size of the WIM as
 * 	valid for its compression type.
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 * 	The library did not recognize the compression type of the WIM.
 * @retval ::WIMLIB_ERR_INVALID_HEADER
 * 	The header of the WIM was otherwise invalid.
 * @retval ::WIMLIB_ERR_INVALID_INTEGRITY_TABLE
 * 	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY was specified in @p open_flags and
 * 	the WIM contained an integrity table, but the integrity table was
 * 	invalid.
 * @retval ::WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY
 * 	The lookup table of the WIM was invalid.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	@p wim_ret was @c NULL; or, @p wim_file was not a nonempty string.
 * @retval ::WIMLIB_ERR_IS_SPLIT_WIM
 * 	The WIM was a split WIM and ::WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT was
 * 	specified in @p open_flags.
 * @retval ::WIMLIB_ERR_NOMEM
 * 	Failed to allocated needed memory.
 * @retval ::WIMLIB_ERR_NOT_A_WIM_FILE
 * 	The file did not begin with the magic characters that identify a WIM
 * 	file.
 * @retval ::WIMLIB_ERR_OPEN
 * 	Failed to open the WIM file for reading.  Some possible reasons: the WIM
 * 	file does not exist, or the calling process does not have permission to
 * 	open it.
 * @retval ::WIMLIB_ERR_READ
 * 	Failed to read data from the WIM file.
 * @retval ::WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 *	Unexpected end-of-file while reading data from the WIM file.
 * @retval ::WIMLIB_ERR_UNKNOWN_VERSION
 * 	The WIM version number was not recognized. (May be a pre-Vista WIM.)
 * @retval ::WIMLIB_ERR_WIM_IS_ENCRYPTED
 *	The WIM cannot be opened because it contains encrypted segments.  (It
 *	may be a Windows 8 "ESD" file.)
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	::WIMLIB_OPEN_FLAG_WRITE_ACCESS was specified but the WIM file was
 *	considered read-only because of any of the reasons mentioned in the
 *	documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS flag.
 * @retval ::WIMLIB_ERR_XML
 * 	The XML data of the WIM was invalid.
 */
extern int
wimlib_open_wim(const wimlib_tchar *wim_file,
		int open_flags,
		WIMStruct **wim_ret);

/**
 * @ingroup G_creating_and_opening_wims
 *
 * Same as wimlib_open_wim(), but allows specifying a progress function and
 * progress context.  If successful, the progress function will be registered in
 * the newly open ::WIMStruct, as if by an automatic call to
 * wimlib_register_progress_function().  In addition, if
 * ::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY is specified in @p open_flags, the
 * progress function will receive ::WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY
 * messages while checking the WIM file's integrity.
 */
extern int
wimlib_open_wim_with_progress(const wimlib_tchar *wim_file,
			      int open_flags,
			      WIMStruct **wim_ret,
			      wimlib_progress_func_t progfunc,
			      void *progctx);

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
 * full rebuild may take a while, but it will save space by producing a WIM with
 * no "holes".
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
 * If this function completes successfully, no more functions should be called
 * on @p wim other than wimlib_free().  If you need to continue using the WIM,
 * you must use wimlib_open_wim() to read it anew.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct for the WIM file to write.  There may have
 * 	been in-memory changes made to it, which are then reflected in the
 * 	output file.
 * @param write_flags
 * 	Bitwise OR of relevant flags prefixed with WIMLIB_WRITE_FLAG.
 * @param num_threads
 * 	Number of threads to use for compression, or 0 for the default. (See
 * 	wimlib_write().)
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
 * 	@p wim corresponds to a ::WIMStruct created with wimlib_create_new_wim()
 * 	rather than a WIM read with wimlib_open_wim().
 * @retval ::WIMLIB_ERR_RENAME
 * 	The temporary file that the WIM was written to could not be renamed to
 * 	the original filename of @p wim.
 * @retval ::WIMLIB_ERR_WIM_IS_READONLY
 *	The WIM file is considered read-only because of any of the reasons
 *	mentioned in the documentation for the ::WIMLIB_OPEN_FLAG_WRITE_ACCESS
 *	flag.
 *
 * If a progress function is registered with @p wim, it will receive the
 * messages ::WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
 * ::WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN, and
 * ::WIMLIB_PROGRESS_MSG_WRITE_METADATA_END.
 */
extern int
wimlib_overwrite(WIMStruct *wim, int write_flags, unsigned num_threads);

/**
 * @ingroup G_wim_information
 *
 * Prints information about one image, or all images, contained in a WIM.
 *
 * @param wim
 * 	Pointer to the ::WIMStruct to query.  This need not represent a
 * 	standalone WIM (e.g. it could represent part of a split WIM).
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
				int open_flags);

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
				int flags);

/**
 * @ingroup G_general
 *
 * Registers a progress function with a ::WIMStruct.
 *
 * @param wim
 *	The ::WIMStruct for which to register the progress function.
 * @param progfunc
 *	Pointer to the progress function to register.  If the WIM already has a
 *	progress function registered, it will be replaced with this one.  If @p
 *	NULL, the current progress function (if any) will be unregistered.
 * @param progctx
 *	The value which will be passed as the third argument to calls to @p
 *	progfunc.
 */
extern void
wimlib_register_progress_function(WIMStruct *wim,
				  wimlib_progress_func_t progfunc,
				  void *progctx);

/**
 * @ingroup G_modifying_wims
 *
 * Rename the @p source_path to the @p dest_path in the specified @p image of
 * the @p wim.
 *
 * This just builds an appropriate ::wimlib_rename_command and passes it to
 * wimlib_update_image().
 */
extern int
wimlib_rename_path(WIMStruct *wim, int image,
		   const wimlib_tchar *source_path, const wimlib_tchar *dest_path);

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
 * @ingroup G_general
 *
 * Sets the file to which the library will print error and warning messages.
 *
 * This version of the function takes a C library <c>FILE *</c> opened for
 * writing (or appending).  Use wimlib_set_error_file_by_name() to specify the
 * file by name instead.
 *
 * This also enables error messages, as if by a call to
 * wimlib_set_print_errors(true).
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	wimlib was compiled using the <c>--without-error-messages</c> option.
 */
extern int
wimlib_set_error_file(FILE *fp);

/**
 * @ingroup G_general
 *
 * Sets the path to the file to which the library will print error and warning
 * messages.  The library will open this file for appending.
 *
 * This also enables error messages, as if by a call to
 * wimlib_set_print_errors(true).
 *
 * @return 0 on success; nonzero on error.
 * @retval ::WIMLIB_ERR_OPEN
 *	The file named by @p path could not be opened for appending.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	wimlib was compiled using the <c>--without-error-messages</c> option.
 */
extern int
wimlib_set_error_file_by_name(const wimlib_tchar *path);

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
 * A larger compression chunk size will likely result in a better compression
 * ratio, but the speed of random access to the WIM will be reduced.
 * Furthermore, the effect of a larger compression chunk size is limited by the
 * size of each stream ("file") being compressed.
 *
 * @param wim
 *	::WIMStruct for a WIM.
 * @param chunk_size
 *	The chunk size (in bytes) to set.  The valid chunk sizes are dependent
 *	on the compression format.  See the documentation for each
 *	::wimlib_compression_type constant for more information.  As a special
 *	case, if @p chunk_size is specified as 0, the chunk size is set to the
 *	default for the currently selected output compression type.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_CHUNK_SIZE
 *	@p chunk_size is not a supported chunk size for the currently selected
 *	output compression type.
 */
extern int
wimlib_set_output_chunk_size(WIMStruct *wim, uint32_t chunk_size);

/**
 * @ingroup G_writing_and_overwriting_wims
 *
 * Similar to wimlib_set_output_chunk_size(), but set the chunk size for writing
 * solid resources.
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
 * for writing solid resources.
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
 * use the standard memory allocation functions regardless of this setting.
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
 *
 * @return 0 on success; nonzero on error.  This function may return most error
 * codes that can be returned by wimlib_write() as well as the following error
 * codes:
 *
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@p swm_name was not a nonempty string, or @p part_size was 0.
 *
 * If a progress function is registered with @p wim, for each split WIM part
 * that is written it will receive the messages
 * ::WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART and
 * ::WIMLIB_PROGRESS_MSG_SPLIT_END_PART.
 */
extern int
wimlib_split(WIMStruct *wim,
	     const wimlib_tchar *swm_name,
	     uint64_t part_size,
	     int write_flags);

/**
 * @ingroup G_general
 *
 * Perform verification checks on a WIM file.
 *
 * @param wim
 *	The ::WIMStruct for the WIM file to verify.  Note: for an extra layer of
 *	verification, it is a good idea to have used
 *	::WIMLIB_OPEN_FLAG_CHECK_INTEGRITY when you opened the file.
 *	<br/>
 *	If verifying a split WIM, specify the first part of the split WIM here,
 *	and reference the other parts using wimlib_reference_resource_files()
 *	before calling this function.
 *
 * @param verify_flags
 *	Reserved; must be 0.
 *
 * @retval 0 if the WIM file was successfully verified; nonzero if it failed
 * verification or another error occurred.  Some of the possible error codes
 * are:
 *
 * @retval ::WIMLIB_ERR_DECOMPRESSION
 *	A compressed resource could not be decompressed.
 * @retval ::WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	The metadata resource for an image is invalid.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_HASH
 *	One of the files did not decompress to its original data, as given by a
 *	cryptographic checksum.
 * @retval ::WIMLIB_ERR_RESOURCE_NOT_FOUND
 *	One of the files referenced by an image could not be located.
 *
 * If a progress function is registered with @p wim, it will receive the
 * following progress messages: ::WIMLIB_PROGRESS_MSG_BEGIN_VERIFY_IMAGE,
 * ::WIMLIB_PROGRESS_MSG_END_VERIFY_IMAGE, and
 * ::WIMLIB_PROGRESS_MSG_VERIFY_STREAMS.
 */
extern int
wimlib_verify_wim(WIMStruct *wim, int verify_flags);

/**
 * @ingroup G_mounting_wim_images
 *
 * Unmounts a WIM image that was mounted using wimlib_mount_image().
 *
 * When unmounting a read-write mounted image, the default behavior is to
 * discard changes to the image.  Use ::WIMLIB_UNMOUNT_FLAG_COMMIT to cause the
 * WIM image to be committed.
 *
 * @param dir
 * 	The directory the WIM image was mounted on.
 * @param unmount_flags
 * 	Bitwise OR of flags prefixed with @p WIMLIB_UNMOUNT_FLAG.
 *
 * @return 0 on success; nonzero on error.  The possible error codes include:
 *
 * @retval ::WIMLIB_ERR_NOT_A_MOUNTPOINT
 * 	There is no WIM image mounted on the specified directory.
 * @retval ::WIMLIB_ERR_MOUNTED_IMAGE_IS_BUSY
 *	The read-write mounted WIM image cannot be committed because there are
 *	file descriptors open to it, and ::WIMLIB_UNMOUNT_FLAG_FORCE was not
 *	specified.
 * @retval ::WIMLIB_ERR_MQUEUE
 * 	Could not create a POSIX message queue.
 * @retval ::WIMLIB_ERR_NOT_PERMITTED_TO_UNMOUNT
 *	The WIM image was mounted by a different user.
 * @retval ::WIMLIB_ERR_UNSUPPORTED
 * 	Mounting is not supported in this build of the library.
 *
 * Note: you can also unmount the image by using the @c umount() system call, or
 * by using the @c umount or @c fusermount programs.  However, you need to call
 * this function if you want changes to be committed.
 */
extern int
wimlib_unmount_image(const wimlib_tchar *dir, int unmount_flags);

/**
 * @ingroup G_mounting_wim_images
 *
 * Same as wimlib_unmount_image(), but allows specifying a progress function.
 * If changes are committed from a read-write mount, the progress function will
 * receive ::WIMLIB_PROGRESS_MSG_WRITE_STREAMS messages.
 */
extern int
wimlib_unmount_image_with_progress(const wimlib_tchar *dir,
				   int unmount_flags,
				   wimlib_progress_func_t progfunc,
				   void *progctx);

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
 *
 * @return 0 on success; nonzero on error.  On failure, all update commands will
 * be rolled back, and no visible changes shall have been made to @p wim.
 * Possible error codes include:
 *
 * @retval ::WIMLIB_ERR_FVE_LOCKED_VOLUME
 *	Windows-only: One of the "add" commands attempted to add files from an
 *	encrypted BitLocker volume that hasn't yet been unlocked.
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
 *	added from an NTFS volume; or, both ::WIMLIB_ADD_FLAG_RPFIX and
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
		    int update_flags);

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
 * 	threads will be set by the library automatically.  This chosen value
 * 	will generally be the number of online processors, but the
 * 	implementation may take into account other information (e.g. available
 * 	memory and overall system activity).
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_IMAGE
 * 	@p image does not specify a single existing image in @p wim, and is not
 * 	::WIMLIB_ALL_IMAGES.
 * @retval ::WIMLIB_ERR_INVALID_RESOURCE_HASH
 * 	A file resource failed a SHA-1 message digest check.  This can happen if
 * 	a file that had previously been scanned for inclusion in the WIM by was
 * 	concurrently modified.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 * 	@p path was not a nonempty string, or invalid flags were passed.
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
 * different reasons) to read the data from a WIM archive.
 *
 * If a progress function is registered with @p wim, it will receive the
 * messages ::WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
 * ::WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN, and
 * ::WIMLIB_PROGRESS_MSG_WRITE_METADATA_END.
 */
extern int
wimlib_write(WIMStruct *wim,
	     const wimlib_tchar *path,
	     int image,
	     int write_flags,
	     unsigned num_threads);

/**
 * @ingroup G_writing_and_overwriting_wims
 *
 * Same as wimlib_write(), but write the WIM directly to a file descriptor,
 * which need not be seekable if the write is done in a special pipable WIM
 * format by providing ::WIMLIB_WRITE_FLAG_PIPABLE in @p write_flags.  This can,
 * for example, allow capturing a WIM image and streaming it over the network.
 * See @ref subsec_pipable_wims for more information about pipable WIMs.
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
		   unsigned num_threads);

/**
 * @defgroup G_compression Compression and decompression functions
 *
 * @brief Functions for XPRESS, LZX, and LZMS compression and decompression.
 *
 * These functions are already used by wimlib internally when appropriate for
 * reading and writing WIM archives.  But they are exported and documented so
 * that they can be used in other applications or libraries for general-purpose
 * lossless data compression.  They are implemented in highly optimized C code,
 * using state-of-the-art compression techniques.  The main limitation is the
 * lack of sliding window support; this has, however, allowed the algorithms to
 * be optimized for block-based compression.
 *
 * @{
 */

/** Opaque compressor handle.  */
struct wimlib_compressor;

/** Opaque decompressor handle.  */
struct wimlib_decompressor;

/**
 * Set the default compression level for the specified compression type.  This
 * is the compression level that wimlib_create_compressor() assumes if it is
 * called with @p compression_level specified as 0.
 *
 * wimlib's WIM writing code (e.g. wimlib_write()) will pass 0 to
 * wimlib_create_compressor() internally.  Therefore, calling this function will
 * affect the compression level of any data later written to WIM files using the
 * specified compression type.
 *
 * The initial state, before this function is called, is that all compression
 * types have a default compression level of 50.
 *
 * @param ctype
 *	Compression type for which to set the default compression level, as one
 *	of the ::wimlib_compression_type constants.  Or, if this is the special
 *	value -1, the default compression levels for all compression types will
 *	be set.
 * @param compression_level
 *	The default compression level to set.  If 0, the "default default" level
 *	of 50 is restored.  Otherwise, a higher value indicates higher
 *	compression, whereas a lower value indicates lower compression.  See
 *	wimlib_create_compressor() for more information.
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 *	@p ctype was neither a supported compression type nor -1.
 */
extern int
wimlib_set_default_compression_level(int ctype, unsigned int compression_level);

/**
 * Returns the approximate number of bytes needed to allocate a compressor with
 * wimlib_create_compressor() for the specified compression type, maximum block
 * size, and compression level.  @p compression_level may be 0, in which case
 * the current default compression level for @p ctype is used.  Returns 0 if the
 * compression type is invalid, or the @p max_block_size for that compression
 * type is invalid.
 */
extern uint64_t
wimlib_get_compressor_needed_memory(enum wimlib_compression_type ctype,
				    size_t max_block_size,
				    unsigned int compression_level);

/**
 * Allocate a compressor for the specified compression type using the specified
 * parameters.  This function is part of wimlib's compression API; it is not
 * necessary to call this to process a WIM file.
 *
 * @param ctype
 *	Compression type for which to create the compressor, as one of the
 *	::wimlib_compression_type constants.
 * @param max_block_size
 *	The maximum compression block size to support.  This specifies the
 *	maximum allowed value for the @p uncompressed_size parameter of
 *	wimlib_compress() when called using this compressor.
 *	<br/>
 *	Usually, the amount of memory used by the compressor will scale in
 *	proportion to the @p max_block_size parameter.
 *	wimlib_get_compressor_needed_memory() can be used to query the specific
 *	amount of memory that will be required.
 *	<br/>
 *	This parameter must be at least 1 and must be less than or equal to a
 *	compression-type-specific limit.
 *	<br/>
 *	In general, the same value of @p max_block_size must be passed to
 *	wimlib_create_decompressor() when the data is later decompressed.
 *	However, some compression types have looser requirements regarding this.
 * @param compression_level
 *	The compression level to use.  If 0, the default compression level (50,
 *	or another value as set through wimlib_set_default_compression_level())
 *	is used.  Otherwise, a higher value indicates higher compression.  The
 *	values are scaled so that 10 is low compression, 50 is medium
 *	compression, and 100 is high compression.  This is not a percentage;
 *	values above 100 are also valid.
 *	<br/>
 *	Using a higher-than-default compression level can result in a better
 *	compression ratio, but can significantly reduce performance.  Similarly,
 *	using a lower-than-default compression level can result in better
 *	performance, but can significantly worsen the compression ratio.  The
 *	exact results will depend heavily on the compression type and what
 *	algorithms are implemented for it.  If you are considering using a
 *	non-default compression level, you should run benchmarks to see if it is
 *	worthwhile for your application.
 *	<br/>
 *	The compression level does not affect the format of the compressed data.
 *	Therefore, it is a compressor-only parameter and does not need to be
 *	passed to the decompressor.
 * @param compressor_ret
 *	A location into which to return the pointer to the allocated compressor.
 *	The allocated compressor can be used for any number of calls to
 *	wimlib_compress() before being freed with wimlib_free_compressor().
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 *	@p ctype was not a supported compression type.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	@p max_block_size was invalid for the compression type, or @p
 *	compressor_ret was @c NULL.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Insufficient memory to allocate the compressor.
 */
extern int
wimlib_create_compressor(enum wimlib_compression_type ctype,
			 size_t max_block_size,
			 unsigned int compression_level,
			 struct wimlib_compressor **compressor_ret);

/**
 * Compress a buffer of data.
 *
 * @param uncompressed_data
 *	Buffer containing the data to compress.
 * @param uncompressed_size
 *	Size, in bytes, of the data to compress.  This cannot be greater than
 *	the @p max_block_size with which wimlib_create_compressor() was called.
 *	(If it is, the data will not be compressed and 0 will be returned.)
 * @param compressed_data
 *	Buffer into which to write the compressed data.
 * @param compressed_size_avail
 *	Number of bytes available in @p compressed_data.
 * @param compressor
 *	A compressor previously allocated with wimlib_create_compressor().
 *
 * @return
 *	The size of the compressed data, in bytes, or 0 if the data could not be
 *	compressed to @p compressed_size_avail or fewer bytes.
 */
extern size_t
wimlib_compress(const void *uncompressed_data, size_t uncompressed_size,
		void *compressed_data, size_t compressed_size_avail,
		struct wimlib_compressor *compressor);

/**
 * Free a compressor previously allocated with wimlib_create_compressor().
 *
 * @param compressor
 *	The compressor to free.  If @c NULL, no action is taken.
 */
extern void
wimlib_free_compressor(struct wimlib_compressor *compressor);

/**
 * Allocate a decompressor for the specified compression type.  This function is
 * part of wimlib's compression API; it is not necessary to call this to process
 * a WIM file.
 *
 * @param ctype
 *	Compression type for which to create the decompressor, as one of the
 *	::wimlib_compression_type constants.
 * @param max_block_size
 *	The maximum compression block size to support.  This specifies the
 *	maximum allowed value for the @p uncompressed_size parameter of
 *	wimlib_decompress().
 *	<br/>
 *	In general, this parameter must be the same as the @p max_block_size
 *	that was passed to wimlib_create_compressor() when the data was
 *	compressed.  However, some compression types have looser requirements
 *	regarding this.
 * @param decompressor_ret
 *	A location into which to return the pointer to the allocated
 *	decompressor.  The allocated decompressor can be used for any number of
 *	calls to wimlib_decompress() before being freed with
 *	wimlib_free_decompressor().
 *
 * @return 0 on success; nonzero on error.
 *
 * @retval ::WIMLIB_ERR_INVALID_COMPRESSION_TYPE
 *	@p ctype was not a supported compression type.
 * @retval ::WIMLIB_ERR_INVALID_PARAM
 *	@p max_block_size was invalid for the compression type, or @p
 *	decompressor_ret was @c NULL.
 * @retval ::WIMLIB_ERR_NOMEM
 *	Insufficient memory to allocate the decompressor.
 */
extern int
wimlib_create_decompressor(enum wimlib_compression_type ctype,
			   size_t max_block_size,
			   struct wimlib_decompressor **decompressor_ret);

/**
 * Decompress a buffer of data.
 *
 * @param compressed_data
 *	Buffer containing the data to decompress.
 * @param compressed_size
 *	Size, in bytes, of the data to decompress.
 * @param uncompressed_data
 *	Buffer into which to write the uncompressed data.
 * @param uncompressed_size
 *	Size, in bytes, of the data when uncompressed.  This cannot exceed the
 *	@p max_block_size with which wimlib_create_decompressor() was called.
 *	(If it does, the data will not be decompressed and a nonzero value will
 *	be returned.)
 * @param decompressor
 *	A decompressor previously allocated with wimlib_create_decompressor().
 *
 * @return 0 on success; nonzero on error.
 *
 * No specific error codes are defined; any nonzero value indicates that the
 * decompression failed.  This can only occur if the data is truly invalid;
 * there will never be transient errors like "out of memory", for example.
 *
 * This function requires that the exact uncompressed size of the data be passed
 * as the @p uncompressed_size parameter.  If this is not done correctly,
 * decompression may fail or the data may be decompressed incorrectly.
 */
extern int
wimlib_decompress(const void *compressed_data, size_t compressed_size,
		  void *uncompressed_data, size_t uncompressed_size,
		  struct wimlib_decompressor *decompressor);

/**
 * Free a decompressor previously allocated with wimlib_create_decompressor().
 *
 * @param decompressor
 *	The decompressor to free.  If @c NULL, no action is taken.
 */
extern void
wimlib_free_decompressor(struct wimlib_decompressor *decompressor);


/**
 * @}
 */


#ifdef __cplusplus
}
#endif

#endif /* _WIMLIB_H */
