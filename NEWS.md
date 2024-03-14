# wimlib release notes

## Version 1.14.4

- Fixed potential crash when writing WIM XML data, introduced in v1.14.0.

- Improved some documentation.

- Fixed the Windows build script to avoid an unnecessary DLL dependency when
  building with MSYS2 MINGW32 or MSYS2 MINGW64.

## Version 1.14.3

- Fixed a bug introduced in v1.14.0 where non-ASCII characters stopped being
  accepted in image names and descriptions.  This bug only affected UNIX-like
  systems that use `signed char`, e.g. x86 Linux systems.

## Version 1.14.2

- Fixed a bug introduced in v1.14.0 where a crash would sometimes occur if a
  Delphi application or Visual Studio compiled application called into the
  32-bit x86 build of the library.

- Fixed an issue where some WIM images written by wimlib weren't accepted by
  some MS software versions.  wimlib-written WIM images containing directory
  reparse points (e.g. junctions) weren't accepted by some versions of the
  Windows 8 setup wizard.  Also, recent versions of DISM had stopped accepting
  wimlib-written WIM images containing directories with named data streams.

- Commands passed to wimupdate on standard input are now interpreted as UTF-8 or
  UTF-16LE (autodetected), just like wimcapture config files and wimextract path
  list files.  Previously, on Windows the Windows code page was used instead of
  UTF-8, which made it hard to specify non-ASCII file paths in wimupdate
  commands.  The same change also applies to wimcapture source list files.

## Version 1.14.1

- Fixed a bug introduced in v1.14.0 where wimlib would crash on older CPUs.

## Version 1.14.0

- Removed libxml2 and libcrypto (OpenSSL) as dependencies of wimlib.  Also
  removed winpthreads as a dependency of wimlib on Windows.

- Upgraded the support for mounting WIM images on Linux from fuse2 to fuse3.
  fuse2 is no longer supported.

- Converted the README, README.WINDOWS, and NEWS files to Markdown.

- Simplified the process of building wimlib for Windows.  See README.WINDOWS for
  the updated instructions, which use MSYS2 instead of Cygwin.  Windows ARM64
  builds are now supported (experimentally) as well.

- Improved performance on CPUs that have SHA-1 instructions in cases where
  wimlib wasn't using OpenSSL, e.g. the Windows binaries.

- Fixed a bug in `wimsplit` where it didn't accept part sizes of 4 GiB or larger
  on Windows and on 32-bit platforms.

- `wimupdate` now supports the `--ref` option.  It should be specified when
  updating a delta WIM to avoid two minor issues.

- `wimoptimize` now has better default behavior when converting to and from
  solid archives, i.e. WIM <=> ESD.  It now is consistent with `wimcapture` and
  `wimexport`.  For WIM => ESD, `wimoptimize --solid` now works.  Before, the
  needed command was `wimoptimize --solid --compress=LZMS --chunk-size=128K`.
  For ESD => WIM, `wimoptimize --compress=LZX` now works.  Before, the needed
  command was `wimoptimize --compress=LZX --chunk-size=32K`.

- Removed support for Windows XP.

- Added a GitHub Actions workflow that tests wimlib.

## Version 1.13.6

- `wimsplit` no longer prints a success message on failure.

- `wimlib_iterate_dir_tree()` no longer hashes files that haven't yet been
  written to the WIM file.

- Reduced the maximum number of file descriptors that wimlib can use when
  extracting files from a WIM image on macOS.

- The files that used the CC0 public domain dedication now use the MIT license
  instead.

- Removed some configuration options (`--disable-assertions`,
  `--disable-error-messages`, and `--disable-multithreaded-compression`) that
  probably weren't being used by anyone.

## Version 1.13.5

- Exporting "all" images from a WIM file no longer fails if multiple
  images in that WIM file have the same name.

- wimlib now warns rather than aborts if two files have the same SHA-1
  hash but different sizes.

- Fixed build errors with the latest version of MinGW-w64.

## Version 1.13.4

- wimsplit now prints progress messages regularly rather than just once per WIM
  part.

- Added support for a data recovery mode which causes files to be extracted even
  if they are corrupted.  The option is `--recover-data` for `wimapply` and
  `wimextract`, and `WIMLIB_EXTRACT_FLAG_RECOVER_DATA` for the library.  Note
  that this option won't help with all types of corruption; some types of
  corruption will still cause a fatal error.

## Version 1.13.3

- On Windows, improved performance of capturing an entire drive in some cases.

- On Windows, fixed leaking a directory handle (or triggering a SEH exception
  when running under a debugger) when referencing WIM files.

- On Windows, when applying a Windows OS image using the `--compact` flag,
  bootloader files can now be compressed with stronger compression algorithms if
  the version of Windows is recent enough to support it.

- Clarified the license text.

## Version 1.13.2

- Prevented miscompilation with gcc 10 at -O3 due to [a gcc
  bug](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=94994).

- Avoided some compiler warnings with gcc 9 and later.

- The `mkwinpeimg` script now also looks for syslinux modules in
  `/usr/share/syslinux`, to handle where openSUSE installs them.

- Removed obsolete packaging files from the source tree.

## Version 1.13.1

- Fixed a crash or incorrect output during LZMS compression with a compression
  level greater than 50 and a chunk size greater than 64 MiB.  This affected
  wimlib v1.8.0 and later.  In the unlikely event that you used all these
  non-default compression settings in combination, e.g. `wimcapture --solid
  --solid-compress=LZMS:100 --solid-chunk-size=128M`, run `wimverify` on your
  archives to verify your data is intact.

## Version 1.13.0

- On Windows, wimlib now supports capturing and applying extended attributes
  (EAs).  It is compatible with DISM with the `/EA` option, available since
  Windows 10 version 1607.  wimlib's EA support is on by default and works on
  older versions of Windows too.

- Partially fixed a bug where `[ExclusionException]` entries didn't take effect
  when the containing directory is matched by `[ExclusionList]`.  It now works
  when the `[ExclusionException]` patterns are absolute.  For example, listing
  `/dir/file` in `[ExclusionException]` now works even if `/dir` is matched by
  `[ExclusionList]`.

- Added a `--create` option to `wimappend` which makes it create the WIM
  file (like `wimcapture`) if it doesn't exist yet.

- Added an `--include-integrity` option to various `wimlib-imagex` commands.
  `--include-integrity` is like `--check`, but it will just include an integrity
  table in the output WIM(s), while skipping verification of any existing
  integrity tables.  This can be useful to avoid unwanted verification of large
  WIM files, e.g. WIMs given by `--delta-from`.

- `wimextract` now reads a pathlist file from standard input when `@-` is given
  as an argument.

- `wimsplit` (API: `wimlib_split()`) now correctly handles a dot in the path to
  the first split WIM part, prior to the filename extension.

- `wimlib-imagex --version` now shows the version of the library it is actually
  using (in case it is different from `wimlib-imagex`'s version).

## Version 1.12.0

- Fixed a bug that was causing the LZMS decompressor to be miscompiled with GCC
  7 (this broke extracting "solid" archives).

- The Windows 10 Recycle Bin directory (`\$RECYCLE.BIN`) has been added to the
  default exclusion list.

- Added a `--quiet` option to `wimlib-imagex`.

- The `mkwinpeimg` script now also looks for the syslinux BIOS modules in the
  directory `/usr/lib/syslinux/modules/bios`.

- Files with timestamps before the year 1970 are now extracted correctly to
  UNIX-style filesystems, are displayed correctly by `wimdir --detailed`, and
  show up correctly in mounted WIM images.

- Files with timestamps after the year 2038 are now displayed correctly by the
  32-bit Windows build of wimlib.

## Version 1.11.0

- Fixed a data corruption bug (incorrect compression) when storing an already
  highly-compressed file in an LZX-compressed WIM with a chunk size greater than
  or equal to 64K.  Note that this is not the default setting and such WIMs are
  not supported by Microsoft's WIM software, so only users who used the
  `--chunk-size` option to `wimlib-imagex` or the
  `wimlib_set_output_chunk_size()` API function may have been affected.  This
  bug was introduced in wimlib v1.10.0.  See [this forum
  thread](https://wimlib.net/forums/viewtopic.php?f=1&t=300) for more details.

- On all platforms, sparse files are now extracted as sparse.

- Sparse files captured from UNIX-style filesystems are now marked as sparse in
  the resulting WIM image.

- Added support for storing Linux-style extended attributes in WIM images.  When
  the `--unix-data` option is used on Linux, `wimlib-imagex` now captures and
  applies extended attributes, in addition to the already-supported standard
  UNIX file permissions (owner/group/mode) and special files.

- `--delta-from` is now supported by `wimappend`.  (Previously it was only
  supported by `wimcapture`.)

- On Windows, improved the way in which files deduplicated with Windows' Data
  Deduplication feature are captured.

- The development files needed to link with wimlib using Visual Studio are now
  included in the Windows release archives.

- `wimlib.h` can now be included by Visual Studio without errors.

- The example programs can now be compiled in C++ mode, and they also now work
  on Windows.

- Updated `mkwinpeimg` to work correctly on images that have a `windows`
  (lower case) directory rather than a `Windows` (upper case) directory.

- Fixed configuring with `--enable-ssse3-sha1` from release tarball (the file
  `nasm_lt.sh` was missing).

- Made some documentation improvements.

## Version 1.10.0

- The LZX compression ratio has been slightly improved.  The default mode, LZX
  level 50, is now almost as good as the old LZX level 100, while being nearly
  the same speed as before.

- Decompression performance has been slightly improved.

- Filenames are now always listed in NTFS collation order.

- On UNIX-like systems, wimlib can now process Windows filenames that are
  not valid Unicode due to the presence of unpaired surrogates.

- On UNIX-like systems, wimlib now always assumes UTF-8 encoding with the
  addition of surrogate codepoints.  Consequently, the environmental variable
  `WIMLIB_IMAGEX_USE_UTF8` and the flag `WIMLIB_INIT_FLAG_ASSUME_UTF8` no longer
  have any effect.

- wimlib no longer depends on iconv.

- Reduced memory usage slightly.

- When a WIM image is applied in NTFS-3G mode, security descriptors are now
  created in NTFS v3.0 format when supported by the volume.

- Workarounds for bugs in libntfs-3g version 2013.1.13 and earlier have been
  removed.  Users are advised to upgrade to a later version of libntfs-3g.

- On Windows, wimlib now supports case-sensitive filename extraction when
  supported by the underlying operating system and filesystem (operating system
  support requires a registry setting).

## Version 1.9.2

- On UNIX, wimlib can now overwrite readonly files when extracting.

- On Windows, fixed a bug where wimlib could leave a null DACL (a.k.a. "no NTFS
  permissions") set on some existing directories after extraction.

- On Windows, when applying a WIM image in "WIMBoot mode" when the WOF driver is
  not loaded, wimlib can now correctly register a new WIM file with the target
  volume when the target volume previously had had WIM files unregistered.

- Added a new testing program.

- Clarified the main license text and updated public domain dedications for
  certain files to be more thorough.

## Version 1.9.1

- Object IDs are now saved and restored on Windows and in NTFS-3G mode.

- Reduced memory usage when exporting large numbers of WIM images.

- Non UTF-8 locales are now detected correctly.

- Addressed compiler warnings and enabled "silent" make rules by default.

- Windows-specific updates:

  - Fixed a bug where duplicate backslashes could be generated in link targets
    when extracting symbolic links and junctions.

  - Fixed a bug where the `.cmd` shortcuts for `wimlib-imagex` wouldn't work if
    their full path contained a space.

  - Fixed bugs related to scanning SMB filesystems.

  - Added warning message about known issue with WindowsApps folder.

  - Added instructions for building from source on Windows.

  - VSS support is no longer marked "experimental".

  - Added missing license file for libdivsufsort-lite.

## Version 1.9.0

- Added experimental support for Windows VSS (Volume Shadow Copy Service).  The
  new `--snapshot` argument to `wimcapture` makes wimlib automatically create
  and use a temporary VSS snapshot when capturing a WIM image.

- Implemented setting of Windows-specific XML information, such as architecture,
  system root, and version details.  This information is now automatically set
  in newly captured WIM images, when appropriate.

- Improved performance of directory tree scans on Windows.

- On Windows, to improve capture performance, wimlib now sometimes opens files
  by inode number rather than by path.  This is enabled for `wimcapture` and
  `wimappend`, but for now other applications have to opt-in.

- The progress messages printed by `wimlib-imagex` while writing WIM files have
  been slightly tweaked.

- Progress information for directory tree scans now counts all hard links.
  Also, on Windows `\\?\` is no longer stripped from the current path.

- Added a new `--image-property` option to `wimcapture`, `wimappend`, and
  `wiminfo`.  This option lets you assign values to elements in a WIM file's XML
  document by name.

- The `wimlib_get_image_property()` and `wimlib_set_image_property()` API
  functions now support numerically indexed elements.

- Fixed a bug where, on Windows, wimlib would change the security descriptor of
  the target directory of an extraction even when the `--no-acls` option was
  specified.

## Version 1.8.3

- Fixed a bug with libntfs-3g extraction present since v1.8.1.  Sometimes, some
  Microsoft software would not correctly recognize data in the resulting
  filesystem.

- Made some small improvements to the compression algorithms:
  - LZX compression ratio was slightly improved.
  - XPRESS compression ratio and speed was slightly improved.
  - LZMS compression speed was slightly improved.

- Improved handling of WIM XML data.  wimlib no longer drops unrecognized
  elements when exporting images.  In addition, two API functions were added for
  better access to elements in the XML document: `wimlib_get_image_property()`
  and `wimlib_set_image_property()`.

- Added support for (unsafe) in-place compaction of WIM files.

- Improved performance of image export by reusing metadata resources
  instead of always rebuilding and recompressing them.

- Improved performance of `wimlib_update_image()` by delaying the update to the
  WIM's XML document until a write is requested.

- On Windows, the target of an extraction may now be a reparse point
  (which will be dereferenced).

- On Windows, wimlib now correctly restores non-Microsoft reparse points.
  However, this remains broken in NTFS-3G mode due to a libntfs-3g bug.

- On Windows, wimlib now has improved performance when archiving files
  from a filesystem backed by a WIM (a "WIMBoot" setup).

- Several improvements to System Compression (compact mode) support:

  - `wof.sys` (or `wofadk.sys`) is now automatically attached to the target
    volume if needed.

  - Compact-mode extractions now work correctly with `wofadk.sys` on older
    versions of Windows.

  - For compatibility with the Windows bootloader, the requested compression
    format now is overridden on certain files.

- Other minor bugfixes.

## Version 1.8.2

- This release primarily contains various minor bug fixes and improvements,
  including:

  - Improved handling of deep directory structures.

  - Fixed a bug where on 32-bit systems, the library could enter an infinite
    loop if a WIM file was malformed in a specific way.

  - Added a workaround for a case where libntfs-3g may report duplicate streams
    in an NTFS file.

  - Windows symbolic links and junctions in mounted WIM images are now
    automatically rewritten to be valid in the mounted location.

  - Reparse point fixes: correctly handle the "ReparseReserved" field, and
    correctly handle "empty" (data-less) reparse points.

  - On Windows, wimlib now acquires SeManageVolumePrivilege, which is needed to
    create externally backed files using the `wofadk.sys` driver.

  - Improved validation of filenames.

  - Improved LZMS decompression speed.

  - The configure script now honors alternate pkg-config settings.

  - Links have been updated to point to the new website.

- In addition, experimental support has been added for compressing extracted
  files using System Compression on Windows 10.  This functionality is available
  through the new `--compact` option to `wimapply` and `wimextract` as well as
  new library flags.

## Version 1.8.1

- Fixed a bug in the LZX decompressor: malicious input data could cause out of
  bounds writes to memory (since wimlib v1.2.2).

- The output of the `wiminfo` command now consolidates various boolean flags
  (such as "Relative path junction") into a single line.

- A file can now have both an unnamed data stream ("file contents") and a
  reparse point stream.  Such files can exist as a result of the use of certain
  Windows features, such as offline storage, including "OneDrive".  wimlib will
  now store and restore both streams on Windows as well as in NTFS-3G mode.
  Microsoft's WIMGAPI also has this behavior.

- On Windows, named data streams of encrypted files are no longer stored twice
  in WIM archives.

- On Windows, named data streams are now correctly extracted to existing
  "readonly" directories.  Before, an error would be reported.

- On Windows, it is now possible to do a "WIMBoot mode" extraction with
  non-standalone WIMs such as delta WIMs.

- On Windows, when doing an extraction in "WIMBoot mode", files larger
  than 4 gigabytes are now never extracted as externally backed.  This
  works around a bug in Microsoft's "WOF" driver.

- The `--enable-verify-compression` configure option has been removed.  If you
  want to verify a WIM file, use the `wimverify` program.

- The way the "file count", "directory count", "total bytes", and "hard link
  bytes" image statistics (stored in the WIM XML data) is calculated has been
  slightly changed.

- In mounted WIM images, the disk usage provided for each file (`st_blocks`) is
  now the compressed size rather than the uncompressed size.

- The performance of the NTFS-3G and Windows capture modes has been slightly
  improved.

- On UNIX-like systems, symbolic links whose targets contain the backslash
  character are now handled correctly (losslessly).

## Version 1.8.0

- Improved the LZX compressor.  It is now 15-20% faster than before and provides
  a slightly better compression ratio.

- Improved the LZMS compressor.  It now provides a compression ratio slightly
  better than WIMGAPI while still being faster and using slightly less memory.

- The compression chunk size in solid resources, e.g. when capturing or
  exporting a WIM file using the `--solid` option, now defaults to 64 MiB
  (67108864 bytes) instead of 32 MiB (33554432 bytes).  This provides a better
  compression ratio and is the same value that WIMGAPI uses.  The memory usage
  is less than 50% higher than wimlib v1.7.4 and is slightly lower than
  WIMGAPI's memory usage, but if it is too much, it is still possible to choose
  a lower value, e.g. with the `--solid-chunk-size` option to `wimlib-imagex`.

- The `--chunk-size` and `--solid-chunk-size` options to `wimlib-imagex` now
  accept the 'K', 'M', and 'G' suffixes.

- Files are now sorted by name extension when creating a solid WIM file.

- Fixed various issues related to capture/apply of EFS-encrypted files on
  Windows.

- The file list printed by `wimdir` is now sorted by the platform-specific
  case sensitivity setting, rather than always case sensitively.  This
  also affects the library function `wimlib_iterate_dir_tree()`.

- On Windows, some error and warning messages have been improved.

## Version 1.7.4

- The Windows binary distribution no longer contains third party DLLs.  These
  dependencies are instead compiled directly into the libwim DLL.

- Added more fixes for wimlib on non-x86 architectures such as ARM.

- Extracting files to a Windows PE in-memory filesystem no longer fails if
  the target files do not yet exist.

- Improved the performance of XPRESS compression and LZMS decompression.

- Enabled SSSE3 accelerated SHA-1 computation in `x86_64` Windows builds.  It
  will automatically be faster on newer Intel and AMD processors.

- Removed the `--with-imagex-progname` and `--enable-more-assertions` configure
  options.

## Version 1.7.3

- Fix for very slow export from solid WIM / ESD files.

- Fix for LZX and LZMS algorithms on non-x86 architectures, such as ARM.

- New progress message: `WIMLIB_PROGRESS_MSG_HANDLE_ERROR`.  Applications may
  use this to treat some types of errors as non-fatal.

- The library now permits making in-memory changes to a WIMStruct backed by a
  read-only WIM file.

- Fixes for "WIMBoot" extraction mode (Windows only):

  - When not using the WOF driver, extraction no longer fails if the disk
    containing the WIM file has too many partitions.

  - When matching patterns in `[PrepopulateList]`, all hard links of each file
    are now considered.

  - The system registry files are now automatically treated as being in
    `[PrepopulateList]`.

  - Added a hack to try to work around an intermittent bug in Microsoft's WOF
    (Windows Overlay Filesystem) driver.

## Version 1.7.2

- Made more improvements to the XPRESS, LZX, and LZMS compressors.

- A number of improvements to the Windows port:

  - Fixes for setting short filenames.

  - Faster "WIMBoot" extraction.

  - Updated and slimmed down the dependent DLLs.

  - ACL inheritence bits are now restored.

  - Mandatory integrity labels are now backed up and restored.

- Added a workaround for an issue where in rare cases, wimlib could create a
  compressed data stream that could not be read correctly by Windows after an
  extraction in "WIMBoot" mode.

- Library changes:

  - Added file count progress data for
    `WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE` and
    `WIMLIB_PROGRESS_MSG_EXTRACT_METADATA`.

  - Added support for testing file exclusions via the user-provided progress
    function.

  - Some documentation improvements.

- Made some clarifications to the license text in the COPYING file.

## Version 1.7.1

- Made more improvements to the XPRESS, LZX, and LZMS compressors.

- The default compression mode for wimcapture is now LZX compression in its
  default mode, which is the same as `--compress=maximum`.

- You can now specify an optional integer compression level to the
  `--compress` option; e.g. `--compress=lzx:75`.

- Made a minor change to the LZMS compressor and decompressor to fix an
  incompatibility with the Microsoft implementation.  In the unlikely event that
  you created an LZMS-compressed WIM with wimlib v1.7.0 or earlier and a
  checksum error is reported when extracting files from it with wimlib v1.7.1,
  decompress it with v1.7.0 then compress it with v1.7.1.

- Added `verify` subcommand to `wimlib-imagex`.

- Notable library changes:

  - Custom compressor parameters have been removed from the library in favor of
    the simpler level-based API.

  - Decompressor parameters have been removed entirely.

  - Library users can now specify a custom file for warning and error messages
    to be sent to, rather than the default of standard error.

  - New progress messages: `WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE`,
    `WIMLIB_PROGRESS_MSG_EXTRACT_METADATA`.

    New function: `wimlib_verify_wim()`.

## Version 1.7.0

- Improved compression, decompression, and extraction performance.

- Improved compatibility with version 3584 WIM / ESD files:

  - Add support for reading and writing multiple solid blocks per archive, which
    WIMGAPI/DISM can create when appending an image.

  - Correctly create solid blocks larger than 4 GiB.

- `add` commands passed to wimupdate will now replace existing nondirectory
  files by default.  Use the `--no-replace` option to get the old behavior.

- The license for the library now contains an exception that allows using it
  under the LGPL.  See the COPYING file for details.

- In reparse-point fixup mode (the default for capture), symbolic links and
  junctions that point outside the tree being captured are no longer excluded
  from capture.

- Added support for "WIMBoot" capture and extraction.  See the documentation for
  the new `--wimboot` option to wimcapture and wimapply for more information.

- On UNIX-like systems, you can now backup and restore device nodes, named
  pipes, and sockets.  In addition, 32-bit user and group IDs are now supported.

- The way that UNIX data is stored in WIM files has been changed.  If you
  captured any WIMs with the `--unix-data` option, to upgrade them you'll need
  to apply them with `--unix-data` using `wimlib-imagex` v1.6.2, then re-capture
  them with `--unix-data` using this version.

- wimlib now understands tagged metadata items, such as object IDs, that
  can be stored in WIM directory entries.

- Removed the `--hardlink` and `--symlink` options to wimapply, since I don't
  think they are too useful and they got in the way of improving the code.

- WIMs will now retain their GUIDs when rebuilt (e.g. with wimoptimize).

- The `mkwinpeimg` script now supports writing the ISO image to standard output.

- The `<ARCH>` element in WIM XML data is now exported correctly.

- On Windows, sparse file attributes are no longer set on extracted files.
  Oddly enough, this actually saves disk space in some cases.

- On UNIX, configuring with `--disable-xattr` or `--enable-xattr` is no longer
  supported.  Mounting WIM images now always requires extended attribute
  support.  Use `--without-fuse` to disable support for mounting WIM images;
  this will also disable the need for extended attribute support.

- Configuring with `--enable-ssse3-sha1` now works correctly.

- The shared library version has been bumped up.  The main incompatibilities
  are:

  - `WIMLIB_COMPRESSION_TYPE_XPRESS` is now 1 and `WIMLIB_COMPRESSION_TYPE_LZX`
    is now 2 (so it's the same as WIMGAPI).

  - User-provided progress functions are now registered using a separate
    function, `wimlib_register_progress_function()`.  The `progress_func`
    argument to many functions no longer exists.

  - The return value from user-provided progress functions is now significant.

  - A context argument has been added to the prototype of user-provided progress
    functions.

  - `struct wimlib_capture_config` has been removed.  The library now takes the
    path to the configuration file directly.  This affects `wimlib_add_image()`,
    `wimlib_add_image_multisource()`, and `wimlib_update_image()`.  However, a
    NULL value passed in the argument retains the same meaning.

  - Removed deprecated functions: some (de)compression functions,
    `wimlib_extract_files()`, and `wimlib_print_metadata()`.

  - Removed extraction flags: `WIMLIB_EXTRACT_FLAG_HARDLINK`,
    `WIMLIB_EXTRACT_FLAG_SYMLINK`, `WIMLIB_EXTRACT_FLAG_FILE_ORDER`, and
    `WIMLIB_EXTRACT_FLAG_SEQUENTIAL`.

  - Removed some progress messages: `WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS`,
    `WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN`,
    `WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END`.  Numbering stays the same.

  - Removed some error codes.  Numbering stays the same.

  - Replaced `WIMLIB_UNMOUNT_FLAG_LAZY` with `WIMLIB_UNMOUNT_FLAG_FORCE`.

  - WIM paths passed to progress functions now have a leading slash.

## Version 1.6.2

- Case-insensitive comparisons of strings (e.g. filenames) containing UTF-16
  codepoints above 32767 are now done correctly.

- Fixed build failure on Mac OS X.

- `wimunmount` now provides the `--new-image` option to cause changes to a
  read-write mounted image to be committed as a new image rather than as an
  update of the mounted image.  (The corresponding new library flag is
  `WIMLIB_UNMOUNT_FLAG_NEW_IMAGE`.)

- The LZMS ("recovery") compression chunk size, or "dictionary size", may now be
  up to 1 GiB (1,073,741,824 bytes).

- The performance of LZX ("maximum") and LZMS ("recovery") compression with
  large chunk sizes has been slightly improved.

## Version 1.6.1

- Stored files with size exactly 4 GiB (4,294,967,296 bytes) are now
  decompressed correctly.

- Fixed a bug in the LZX compressor introduced in v1.5.3.  The bug occurred in
  an unlikely case, and due to validity checks it did not affect successfully
  created archives.

- Fixed a minor compatibility issue with the LZMS compressor and decompressor.
  This is *not* the default compression type and was only introduced in v1.6.0.
  In the unlikely event that you created an LZMS-compressed WIM with v1.6.0 and
  a checksum error is reported when applying it with v1.6.1, decompress it with
  v1.6.0 then compress it with v1.6.1.

- Memory usage for LZMS and LZX compression has been decreased.

- wimextract now allows wildcard characters in paths specified on the command
  line.  Also, the `--strict-wildcards` option has been removed and replaced
  with the inverse option `--nullglob`.  See the documentation for wimextract
  for more details and changes.

- The `wimlib_extract_files()` function is now considered deprecated in favor of
  `wimlib_extract_paths()`.

- Fixed more permissions problems when extracting files on Windows.

- A new `--no-attributes` option has been added to `wimapply` and `wimextract`.
  The library flag is `WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES`.

- The default chunk size is now set correctly when changing the compression type
  of a WIM, for example with `wimoptimize`.

- The `--metadata` option to `wiminfo` has been replaced with the `--detailed`
  option to `wimdir`.

- In relevant `wimlib-imagex` commands, `--solid` may now be used as an alias
  for `--pack-streams`.

## Version 1.6.0

- Support for extracting and updating the new version 3584 WIMs has been added.
  These WIMs typically pack many streams ("files") together into a single
  compressed resource, thereby saving space.  This degrades the performance of
  random access (such as that which occurs on a mounted image), but
  optimizations have been implemented for extraction.  These new WIM files also
  typically use a new compression format (LZMS), which is similar to LZMA and
  can offer a better compression ratio than LZX.  These new WIM files can be
  created using `wimcapture` with the `--compress=lzms --pack-streams` options.
  Note: this new WIM format is used by the Windows 8 web downloader, but
  important segments of the raw `.esd` files are encrypted, so wimlib will not
  be able to extract such files until they are first decrypted.

- wimlib now supports extracting files and directories from a WIM image based on
  a "listfile" that itself contains the list of paths to extract.  For
  `wimextract`, the syntax is to specify `@LISTFILE` instead of a `PATH`, and
  for the library itself, the new APIs are `wimlib_extract_pathlist()` and
  `wimlib_extract_paths()`.  Path globs containing wildcard characters are
  supported.

- For searching WIM files, wimlib now has configurable case sensitivity.  The
  default on Windows is still case-insensitive and the default on UNIX-like
  systems is still case-sensitive, but this can be overridden on either platform
  through flags to `wimlib_global_init()`.  For `wimlib-imagex`, the
  environmental variable `WIMLIB_IMAGEX_IGNORE_CASE` can be set to 1 or 0 for
  case-insensitive or case-sensitive behavior, respectively.

- Support for compression chunk sizes greater than the default of 32768
  bytes has been added.  A larger chunk size typically results in a better
  compression ratio.  However, the MS implementation is seemingly not
  compatible with all chunk sizes, especially for LZX compression, so the
  defaults remain unchanged, with the exception of the new LZMS-compressed
  WIMs, which use a larger chunk size by default.

- The compression/decompression API exported by wimlib has been changed.  Now
  one set of functions handles all supported compression formats.

- `wimcapture` and `wimappend` will now display the progress of scanning the
  directory tree to capture, in addition to the progress of writing data to the
  WIM.  The `--verbose` option no longer does anything.  The library API change
  for this is the addition of several members to `struct
  wimlib_progress_info_scan` available to progress callbacks.

- `mkwinpeimg` now correctly handles the `--start-script` option when the start
  script is not in the working directory.

- Sequential extraction, previously requested by using
  `WIMLIB_EXTRACT_FLAG_SEQUENTIAL`, is now the default.
  `WIMLIB_EXTRACT_FLAG_FILE_ORDER` can be used to get the old default behavior
  (extract in file order).

## Version 1.5.3

- The new LZX compressor added in v1.5.2 has been improved and is now enabled by
  default, except when `wimcapture` or `wimappend` is run *without* the
  `--compress` option, in which case the faster LZX compressor is used (the same
  as before).  This behavior is reasonably consistent with ImageX which actually
  uses "fast" (XPRESS) compression by default.  In those cases, use
  `--compress=maximum` to explicitly capture a WIM image using the new (slower
  but better) LZX compressor.

  The `--compress-slow` option still exists to `wimlib-imagex optimize`, but its
  new behavior is to tweak the new LZX compressor even more to produce an even
  better compression ratio at the cost of more time spent compressing.

- `wimlib-imagex optimize` now supports the `--compress=TYPE` option, which
  recompresses the WIM file using the specified compression TYPE.  The new
  library API function used for this is `wimlib_set_output_compression_type()`.

- Added the `wimlib_get_xml_data()` function to allow library clients to easily
  retrieve the raw XML data from a WIM file if needed.

- Fixed a bug that could cause an error code to be incorrectly returned when
  writing XML data containing a `<WINDOWS>` element.

- Mounted WIM images will now correctly show the default file stream even if
  appears in the alternate data stream entries of the corresponding WIM
  directory entry.

## Version 1.5.2

- Added a new experimental LZX compressor which can be enabled by passing
  `--compress-slow` to `wimlib-imagex capture` or `wimlib-imagex optimize`.
  (The latter is only applicable if the WIM is already LZX-compressed and the
  `--recompress` option is also given.)  The experimental compressor is much
  slower but compresses the data slightly more --- currently usually to within a
  fraction of a percent of the results from WIMGAPI/ImageX.

- A workaround has been added for compatibility with versions of WinPE that
  interpret alternate data stream entries in the boot WIM incorrectly.

- An alignment bug that caused a crash in the LZX decompressor on some builds
  was fixed.

- wimlib now attempts to clear the `WIM_HDR_FLAG_WRITE_IN_PROGRESS` flag in the
  WIM header when restoring the previous state of a WIM it failed to
  successfully update.

- Added a workaround to avoid an access denied error on Windows when replacing a
  WIM file that another process has opened.

## Version 1.5.1

- wimlib can now open WinPE WIMs from WAIK v2.1, which had a quirk that needed
  to be handled.

- A bug in the interpretation of negative `IMAGE` indices in the
  `--update-of=[WIMFILE:]IMAGE` option to `wimlib-imagex capture` and
  `wimlib-imagex append` has been fixed.

- A workaround has been added to successfully apply security descriptors with
  empty DACLs when the NTFS-3G apply mode is being used with NTFS-3G 2013.1.13
  or earlier.

- `wimlib-imagex capture` can now accept the `--delta-from` option multiple
  times.

## Version 1.5.0

- Added support for "pipable" WIMs.  Pipable WIMs allow capturing images to
  standard output and applying images from standard input, but they are not
  compatible with Microsoft's software and are not created by default.  See the
  documentation for `--pipable` flag of `wimlib-imagex capture` for more
  information.

- To better support incremental backups, added support for declaring an image as
  a modified form of another image.  See the documentation for the `--update-of`
  option of `wimlib-imagex append` and `wimlib-imagex capture`.

- Added supported for "delta" WIMs.  See the documentation for the
  `--delta-from` option of `wimlib-imagex capture`.

- The library support for managing split WIMs has been changed to support other
  arrangements, such as delta WIMs, and be easier to use.  This change is
  visible in `wimlib-imagex`, which also can now accept the `--ref` option
  multiple times, and also now supports "delta" WIMs as mentioned above.

- wimlib now preserves WIM integrity tables by default, even if
  `WIMLIB_WRITE_FLAG_CHECK_INTEGRITY` is not specified.  This changes the
  behavior of `wimlib-imagex` whenever the WIM being operated on contains
  an integrity table and the `--check` option is not specified.

- `wimlib-imagex capture` now creates LZX-compressed WIMs by default (when
  `--compress` is not specified).  This provides the best compression ratio by
  default, which is usually what is desired, at a cost of some speed.

- `wimlib-imagex` now supports being invoked as `wimCOMMAND`, where `COMMAND` is
  the command as in `wimlib-imagex COMMAND`; for example, it can be invoked as
  `wimapply` as an alternative to `wimlib-imagex apply`.  The appropriate hard
  links are created in UNIX installations of `wimlib-imagex`, while for the
  Windows distribution of `wimlib-imagex`, batch files that emulate this
  behavior are generated.

- Security descriptors are now extracted correctly on Windows.

- Fixed archiving DOS names in NTFS-3G capture mode.

- The extraction code has been rewritten and it will now be easier to support
  new features on all supported backends (currently Win32, UNIX, and NTFS-3G).
  For example, hard-linked extraction mode (`--hardlink`) is now supported on
  all backends, not just UNIX.

- `mkwinpeimg` now supports grabbing files from the WAIK supplement rather
  than the WAIK itself.

- `wimlib_global_init()` now, by default, attempts to acquire additional
  privileges on Windows, so library clients need not do this.

- This update bumps the shared library version number up to 9, since it is not
  binary compatibible with previous releases.

## Version 1.4.2

- Fixed bug in `wimlib-imagex export` that made it impossible to export an image
  from a WIM that is readonly at the filesystem level.

- Return error code rather than segfaulting when trying to list files from a
  non-first part of a split WIM.

- Joining a WIM will now preserve the `RP_FIX` and `READONLY` flags.

## Version 1.4.1

- On Windows, paths given to `wimlib-imagex` are now treated case insensitively.

- Improved behavior regarding invalid filenames; in particular, on Windows,
  `wimlib-imagex` will, when extracting, now omit (with an option to override
  this default) filenames differing only in case, or filenames containing
  characters not valid on Windows.

- On Windows, wimlib now supports capturing and extracting long paths (longer
  than the so-called `MAX_PATH`).

- On Windows, `wimlib-imagex update` now acquires proper privileges when running
  as an Administrator.

- `wimlib-imagex update` will now complain if no image is specified when trying
  to update a multi-image WIM.

- `wimlib-imagex update` now supports specifying a single update command
  directly on the command line using the `--command` option.

- `wimlib-imagex` will now choose different units for progress messages,
  depending on the amount of data that needs to be processed.

- `wimlib-imagex append` will now generate a unique WIM image name if no name is
  specified and the defaulted name already exists in the WIM.

- wimlib now allows you to create unnamed WIM images, which can then only be
  referred to by index.

- wimlib now allows you to explicitly declare you want write access to a WIM by
  providing the `WIMLIB_OPEN_FLAG_WRITE_ACCESS` flag to `wimlib_open_wim()`.

- wimlib now respects the `WIM_HDR_FLAG_READONLY` flag when set in the WIM header.

- Progress callbacks have been added to wimlib's `wimlib_update_image()`
  function.

- Added `wimlib_get_wim_info()`, `wimlib_set_wim_info()`,
  `wimlib_iterate_dir_tree()`, and `wimlib_iterate_lookup_table()` functions to
  the library.

- NTFS-3G capture now only warns about two conditions previously treated as
  errors.

- Fixed a couple issues with using `wimlib-imagex` on UDF filesystems on
  Windows.

- wimlib now correctly detects and returns an error when reading a WIM image
  with a cyclic directory structure.  (Fun fact: such a WIM will crash
  Microsoft's software.)

## Version 1.4.0

- Added new "extract" and "update" subcommands to `wimlib-imagex`, along with
  associated APIs in the library.  These commands are intended mainly for
  Windows use but can be used on UNIX as well.

- Many documentation improvements.

- Fixed a bug in the Windows build where relative symbolic links were not
  captured in reparse-point fixup mode.

- Fixed a bug in the Windows build where file handles were left open to the WIM
  file, causing `wimlib-imagex optimize` to fail in some cases.

- Fixed a bug in the Windows build of `wimlib-imagex` where globbing split-WIM
  parts could cause the program to crash.

- Fixed a bug where the creation time of WIM images would be shown instead of
  the last modification time.

- With the Windows build it is now possible to restore a WIM containing symbolic
  links as a non-Administrator; however you will receive warnings about not
  being able to extract the symbolic links.

## Version 1.3.3

- Capturing a WIM image should now be significantly faster in most cases due to
  improved use of the operating system's cache and avoiding reading files twice
  whenever possible.

- The Windows build should now work on Windows XP.

- The Windows build now supports capturing and restoring hidden, compressed,
  sparse, and encrypted files.

- The Windows build now supports capturing and applying WIM images from
  filesystems other than NTFS (with some reduced functionality).

- The Windows build now extracts short names correctly.

- Added support for "reparse-point" fixups (i.e. fixing up of symbolic links).
  See docs for `--rpfix` and `--norpfix` flags of `wimlib-imagex capture` and
  `wimlib-imagex apply`.

- The performance of splitting and joining WIMs should be slightly improved.

- The LZX and XPRESS compression and decompression functions are now exported
  from the library.

## Version 1.3.2

- Improvements and bugfixes for the Windows build.

- Added `--strict-acls` options.

- Fixed the way that wimlib determines the order of images in the WIM.

## Version 1.3.1

- Since wimlib can now be used on Windows, wimlib's implementation of ImageX has
  been renamed to `wimlib-imagex` to avoid confusion with Microsoft's
  implementation of ImageX, which would have the same file name (`imagex.exe`).
  If you really don't like this you can pass the `--with-imagex-progname` option
  to `configure` to choose a different name, or even simply rename the binary
  yourself (but the former way will configure the man pages to use the chosen
  name).

- Various bugs fixed in the Windows build.  Mainly to do with capturing and
  restoring alternate data streams correctly in weird cases, and requesting the
  correct privileges when opening files.  Also added the `--noacls` options to
  `wimlib-imagex` capture, append, and apply.

- Windows build again: `FindFirstStreamW()` and `FindNextStreamW()` are now
  dynamically loaded, so this may make the library compatible with Windows XP
  (however, there may still be other problems).

## Version 1.3.0

- Added experimental support for native Windows builds.  Binaries can be
  downloaded from the SourceForge page.

- `--source-list` option added to `imagex capture` and `imagex append`.

- Better support for different character encodings.

## Version 1.2.6

- Storing UNIX file owners, groups, and modes in WIM images is now
- possible using `imagex capture` with the `--unix-data` flag.

- Minor bug fixes and documentation fixes.

## Version 1.2.5

- NTFS capture: Fixed capturing duplicate reparse points.

- NTFS capture: Capture first unnamed stream if there are more than one (print
  warning instead of error).

- Allow multiple test cases to execute concurrently (e.g. `make -j2 check`).

## Version 1.2.4

- Added `--arch` switch to mkwinpeimg script to support getting AMD64 WinPE from
  the WAIK.

- Update to work with ntfs-3g version 2013.1.13.

## Version 1.2.3

- Fixed truncating file to shorter but non-zero length on read-write mounted WIM
  image.

- Various code cleanups and minor documentation fixes.

## Version 1.2.2

- LZX and XPRESS decompression have received some additional optimizations and
  should now be even faster.  (Although, they were already pretty fast --- much
  faster than typical I/O speeds.)

- Fixed a bug introduced in v1.2.1 that would cause a directory tree containing
  hard links to be captured incorrectly in some cases.

## Version 1.2.1

- By default, unmounting a read-write mounted WIM with `imagex unmount --commit`
  will now change the WIM in-place without needing to write the entire WIM
  again.  Use `imagex unmount --commit --rebuild` to get the old behavior.

- `imagex unmount` no longer has a hard-coded limit of 10 minutes to wait for a
  response from the daemon servicing the mounted WIM.  Instead, every second
  `imagex unmount` will check if the daemon is still alive, and keep waiting if
  so, otherwise terminate with an error.

- `imagex unmount --commit` on a read-write mounted WIM will now print progress
  information regarding the writing of new or modified streams the WIM, just
  like when capturing or appending a WIM.

- A small change has been made to XPRESS compression and it should improve the
  compression ratio slightly.

- A change was made that may improve performance slightly when applying a WIM
  image to a NTFS volume.

- Microsoft has managed to introduce even more bugs into their software, and now
  the WIMs for Windows 8 have incorrect (too low) reference counts for some
  streams.  This is unsafe because such streams can be removed when they are in
  actuality still referenced in the WIM (perhaps by a different image).  wimlib
  will now work around this problem by fixing the stream reference counts.  This
  is only done when `wimlib_delete_image()` is called (`imagex delete`) or when
  `wimlib_mount_image()` is called with `WIMLIB_MOUNT_FLAG_READWRITE` (`imagex
  mountrw`).  Please note that this requires reading the metadata for all images
  in the WIM, so this will make these operations noticably slower on WIMs with
  multiple images.

- Various other bugfixes.

## Version 1.2.0

- Appending images to a WIM is now be done by default without re-building the
  whole WIM.  Use the `--rebuild` flag to get the old behavior (which was to
  re-build the entire WIM when a new image is appended).

- A new command `imagex optimize` is now available to manually re-build a WIM
  that has wasted space due to repeated appends.

- Progress information has been improved, and now arbitrary callback functions
  can be used to show the progress of a WIM operation.

- A possible bug with changing the bootable image of a WIM was fixed.

- Some advisory locking is now done to prevent two processes from modifying a
  WIM at the same time (but only in some cases).  For example, you cannot mount
  two images from a WIM read-write at the same time.

- Some functions have been reorganized:
  - `wimlib_mount()` renamed to `wimlib_mount_image()`.
  - `wimlib_unmount()` renamed to `wimlib_unmount_image()`.
  - `wimlib_overwrite_xml_and_header()` removed as `wimlib_overwrite()` suffices
    now.
  - `wimlib_apply_image_to_ntfs_volume()` removed as `wimlib_extract_image()`
    suffices now.
  - `wimlib_add_image_from_ntfs_volume()` removed as `wimlib_add_image()`
    suffices now.

- Previously, the soname of libwim.so has been 0.0.0, despite many interface
  changes.  The soname is now updated to 1.0.0 and will now be updated each
  release.

## Version 1.1.0

- Resources will now be compressed using multiple threads by default.  (This
  applies to `imagex capture`, `imagex append`, and `imagex export`).

- Some performance improvements in mounted WIMs.

- More progress information is shown when capturing a WIM.

## Version 1.0.4

- Lots of minor fixes, code cleanups, and some documentation updates.  Nothing
  in particular is really noteworthy.

## Version 1.0.3

- LZX and XPRESS compression improvements.

- Fixed calculation of Directory Count, File Count, Total Bytes, and Hard Link
  Bytes of the WIM.

## Version 1.0.2

- Fixed bug when capturing NTFS file with multiple named data streams.

- Internally, we are now using inode structures, even though these don't appear
  literally in the WIM file.  This simplifies some of the code (mainly for WIM
  mounting) and likely fixed a few problems, although it needs more testing.

## Version 1.0.1

- Fixed problem when exporting images from XPRESS to LZX compressed WIM or vice
  versa

## Version 1.0.0

- Enough changes to call it version 1.0.0!

- Capturing a WIM directly from a NTFS volume, and applying a WIM directly to a
  NTFS volume, is now supported.

- Hard links and symbolic links have much improved support.  They are supported
  for WIM capture, WIM application, and mounted WIMs (you can even make them on
  read-write mounted WIMs).

- Alternate data streams are now supported on mounted WIMs through an xattr or a
  Windows-style stream interface.  Also they are supported when capturing a WIM
  from NTFS or applying a WIM to NTFS.

- Split WIMs are better supported.  You may now apply an image directly from a
  split WIM, mount an image from a split WIM read-only, or export an image from
  a split WIM.

- Using a capture configuration file is now supported (but not fully yet).

- SHA1 message digests are checked in more places, so we can make sure applied
  and captured data is correct.

- Man pages have been updated and consolidated.

## Version 0.7.2

- Fixed segfault when unmounting read-only WIM.

## Version 0.7.1

- Support for joining and splitting WIMs.

- Also, security data is now preserved by default.

## Version 0.6.3

- Can now build with older gcc and system headers, like on CentOS 5.

## Version 0.6.2

- Fixed bug that made it impossible to overwrite files in read-write mount.

## Version 0.6.1

- Write byte-order mark before WIM XML data.  (`imagex.exe` requires this to be
  there.)
