# Introduction

This is wimlib version 1.14.3 (September 2023).  wimlib is a C library for
creating, modifying, extracting, and mounting files in the Windows Imaging
Format (WIM files).  wimlib and its command-line frontend `wimlib-imagex`
provide a free and cross-platform alternative to Microsoft's WIMGAPI, ImageX,
and DISM.

For the release notes, see the [NEWS file](NEWS.md).

# Table of Contents

- [Installation](#installation)
- [WIM files](#wim-files)
- [ImageX implementation](#imagex-implementation)
- [Compression](#compression)
- [NTFS support](#ntfs-support)
- [Windows PE](#windows-pe)
- [Dependencies](#dependencies)
- [Configuration](#configuration)
- [Portability](#portability)
- [References](#references)
- [History](#history)
- [Notices](#notices)

# Installation

To install wimlib and `wimlib-imagex` on UNIX-like systems, you can compile from
source (e.g. `./configure && make && sudo make install`).  Alternatively, check
if a package has already been prepared for your operating system.

To install wimlib and `wimlib-imagex` on Windows, just download and extract the
ZIP file containing the latest binaries.  For more details, see
[README.WINDOWS.md](README.WINDOWS.md).

All official wimlib releases are available from
[wimlib.net](https://wimlib.net).

# WIM files

A Windows Imaging (WIM) file is an archive designed primarily for archiving
Windows filesystems.  However, it can be used on other platforms as well, with
some limitations.  Like some other archive formats such as ZIP, files in WIM
archives may be compressed.  WIM archives support multiple compression formats,
including LZX, XPRESS, and LZMS.  All these formats are supported by wimlib.

A WIM archive contains one or more "images", each of which is a logically
independent directory tree.  Each image has a 1-based index and usually a name.

WIM archives provide data deduplication at the level of full file contents.  In
other words, each unique "file contents" is only stored once in the archive,
regardless of how many files have that contents across all images.

A WIM archive may be either stand-alone or split into multiple parts.

An update of the WIM format --- first added by Microsoft for Windows 8 ---
supports solid-mode compression.  This refers to files being compressed together
(e.g. as in a .tar.xz or .7z archive) rather than separately (e.g. as in a .zip
archive).  This usually produces a much better compression ratio.  Solid
archives are sometimes called "ESD files" by Microsoft and may have the ".esd"
file extension rather than ".wim".  They are supported in wimlib since v1.6.0.

# ImageX implementation

wimlib itself is a C library, and it provides a [documented public
API](https://wimlib.net/apidoc) for other programs to use.  However, it is also
distributed with a command-line program called `wimlib-imagex` that uses this
library to implement an imaging tool similar to Microsoft's `ImageX`.
`wimlib-imagex` supports almost all the capabilities of Microsoft's `ImageX` as
well as additional capabilities.  `wimlib-imagex` works on both UNIX-like
systems and Windows, although some features differ between the platforms.

Run `wimlib-imagex` with no arguments to see an overview of the available
commands and their syntax.  Note that the commands have both long and short
forms, e.g. `wimlib-imagex apply` is equivalent to `wimapply`.  For additional
documentation:

- If you have installed `wimlib-imagex` on a UNIX-like system, you will find
  further documentation in the man pages; run `man wimlib-imagex` to get
  started.

- If you have downloaded the Windows binary distribution, you will find the
  documentation for `wimlib-imagex` in PDF format in the `doc` directory.  Note
  that although the documentation is written in the style of UNIX manual pages,
  it does document Windows-specific behavior when relevant.

# Compression

wimlib (and `wimlib-imagex`) can create XPRESS, LZX, and LZMS compressed WIM
archives.  wimlib's compression codecs usually outperform and outcompress their
closed-source Microsoft equivalents.  Multiple compression levels and chunk
sizes as well as solid mode compression are supported.  Compression is
multithreaded by default.  Detailed benchmark results and descriptions of the
algorithms used can be found at
[wimlib.net](https://wimlib.net/compression.html).

# NTFS support

WIM images may contain data, such as named data streams and
compression/encryption flags, that are best represented on the NTFS filesystem
used on Windows.  Also, WIM images may contain security descriptors which are
specific to Windows and cannot be represented on other operating systems.
wimlib handles this NTFS-specific or Windows-specific data in a
platform-dependent way:

- In the Windows version of wimlib and `wimlib-imagex`, NTFS-specific and
  Windows-specific data are supported natively.

- In the UNIX version of wimlib and `wimlib-imagex`, NTFS-specific and
  Windows-specific data are ordinarily ignored; however, there is also special
  support for capturing and extracting images directly to/from unmounted NTFS
  volumes.  This was made possible with the help of libntfs-3g from the NTFS-3G
  project.

For both platforms the code for NTFS capture and extraction is complete enough
that it is possible to apply an image from the `install.wim` contained in recent
Windows installation media (Vista or later) directly to an NTFS filesystem, and
then boot Windows from it after preparing the Boot Configuration Data.  In
addition, a Windows installation can be captured (or backed up) into a WIM file,
and then re-applied later.

# Windows PE

wimlib can also be used to create customized images of Windows PE on either
UNIX-like systems or Windows.  Windows PE (Preinstallation Environment) is a
lightweight version of Windows that runs entirely from memory and can be used to
perform maintenance or to install Windows.  It is the operating system that runs
when you boot from the Windows installation media.

A copy of Windows PE can be found on the installation media for Windows (Vista
or later) as the file `sources/boot.wim`, or in the Windows Automated
Installation Kit (WAIK), which is free to download from Microsoft.

A shell script `mkwinpeimg` is provided with wimlib on UNIX-like systems to
simplify the process of creating and customizing a bootable Windows PE image,
sourcing the needed files from the Windows installation media or from the WAIK.

# Dependencies

This section documents the dependencies of wimlib and the programs distributed
with it, when building for a UNIX-like system from source.  If you have
downloaded the Windows binary distribution of wimlib and `wimlib-imagex` then
all dependencies were already included and this section is irrelevant.

- `libfuse3` (optional but recommended)

  Unless configured `--without-fuse`, wimlib requires `libfuse3`, for mounting
  WIM images using [FUSE](https://github.com/libfuse/libfuse).  Most Linux
  distributions already include this, but make sure you have the `fuse3` package
  installed, and also `libfuse3-dev` if your distribution distributes
  development files separately.  FUSE also requires a kernel module.  If the
  kernel module is available it should automatically be loaded if you try to
  mount a WIM image.

- `libntfs-3g` (optional but recommended)

  Unless configured `--without-ntfs-3g`, wimlib requires the library and headers
  for libntfs-3g to be installed.  The minimum required version is 2011-4-12,
  but newer versions contain important bug fixes.

- `cdrkit` (optional)
- `mtools` (optional)
- `syslinux` (optional)
- `cabextract` (optional)

  The `mkwinpeimg` shell script will look for several other programs depending
  on what options are given to it.  Depending on your Linux distribution, you
  may already have these programs installed, or they may be in the software
  repository.  Making an ISO filesystem requires `mkisofs` from
  [`cdrkit`](https://www.cdrkit.org).  Making a disk image requires
  [`mtools`](https://www.gnu.org/software/mtools) and
  [`syslinux`](https://www.syslinux.org).  Retrieving files from the Windows
  Automated Installation Kit requires
  [`cabextract`](https://www.cabextract.org.uk).

# Configuration

This section documents the most important options that may be passed to the
"configure" script when building from source:

- `--without-ntfs-3g`

  If libntfs-3g is not available or is not version 2011-4-12 or later, wimlib
  can be built without it, in which case it will not be possible to capture or
  apply WIM images directly from/to NTFS volumes.

  The default is `--with-ntfs-3g` when building for any UNIX-like system, and
  `--without-ntfs-3g` when building for Windows.

- `--without-fuse`

  The `--without-fuse` option disables support for mounting WIM images.  This
  removes dependencies on libfuse and librt.  The `wimmount`, `wimmountrw`, and
  `wimunmount` commands will not work.

  The default is `--with-fuse` when building for Linux, and `--without-fuse`
  otherwise.

# Portability

wimlib works on both UNIX-like systems (Linux, Mac OS X, FreeBSD, etc.) and
Windows (Vista and later).

As much code as possible is shared among all supported platforms, but there
necessarily are some differences in what features are supported on each platform
and how they are implemented.  Most notable is that file tree scanning and
extraction are implemented separately for Windows, UNIX, and UNIX (NTFS-3G
mode), to ensure a fast and feature-rich implementation of each platform/mode.

wimlib is mainly used on x86 and x86\_64 CPUs, but it should also work on a
number of other GCC-supported 32-bit or 64-bit architectures.  It has been
tested on the ARM and MIPS architectures.

Currently, gcc and clang are the only supported compilers.  A few nonstandard
extensions are used in the code.

# References

The WIM file format is partially specified in a document that can be found in
the Microsoft Download Center.  However, this document really only provides an
overview of the format and is not a formal specification.  It also does not
cover later extensions of the format, such as solid resources.

With regards to the supported compression formats:

- Microsoft has official documentation for XPRESS that is of reasonable quality.
- Microsoft has official documentation for LZX, but in two different documents,
  neither of which is completely applicable to its use in the WIM format, and
  the first of which contains multiple errors.
- There does not seem to be any official documentation for LZMS, so my comments
  and code in `src/lzms_decompress.c` may in fact be the best documentation
  available for this particular compression format.

The algorithms used by wimlib's compression and decompression codecs are
inspired by a variety of sources, including open source projects and computer
science papers.

The code in `ntfs-3g_apply.c` and `ntfs-3g_capture.c` uses the [NTFS-3G
library](https://github.com/tuxera/ntfs-3g), which is a library for reading and
writing to NTFS filesystems (the filesystem used by recent versions of Windows).

A limited number of other free programs can handle some parts of the WIM
file format:

- 7-Zip is able to extract and create WIMs (as well as files in many other
  archive formats).  However, wimlib is designed specifically to handle WIM
  files and provides features previously only available in Microsoft's
  implementation, such as the ability to mount WIMs read-write as well as
  read-only, the ability to create compressed WIMs, the correct handling of
  security descriptors and hard links, and support for LZMS compression.

- [`ImagePyX`](https://github.com/maxpat78/ImagePyX) is a Python program that
  provides some capabilities of `wimlib-imagex`, with the help of external
  compression codecs.

If you are looking for an archive format that provides features similar to WIM
but was designed primarily for UNIX, you may want to consider
[SquashFS](https://docs.kernel.org/filesystems/squashfs.html).  However, you may
find that wimlib works surprisingly well on UNIX.  It will store hard links and
symbolic links, and it supports storing standard UNIX file permissions (owners,
groups, and modes); special files such as device nodes and FIFOs; and extended
attributes.  Actually, I use it to back up my own files on Linux!

# History

wimlib was originally a project started by Carl Thijssen for use on Linux in the
[Ultimate Deployment Appliance](https://www.ultimatedeployment.org).  Since then
the code has been entirely rewritten and improved (main author: Eric Biggers).
Windows support has been available since version 1.3.0 (March 2013).  A list of
version-to-version changes can be found in the [NEWS file](NEWS.md).

# Notices

wimlib is free software that comes with NO WARRANTY, to the extent permitted by
law.  For full details, see the [COPYING file](COPYING).

Bug reports, suggestions, and other contributions are appreciated and should be
posted to [the forums](https://wimlib.net/forums/).

wimlib is independently developed and does not contain any code, data, or files
copyrighted by Microsoft.  It is not known to be affected by any patents.
