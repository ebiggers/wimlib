# Introduction

wimlib is free and open source software that is available on both UNIX-like
systems and Windows.  This file provides additional information specifically
about the Windows version of wimlib and the command line tool `wimlib-imagex`
that is distributed with it.  It does not obsolete the generic
[README](README.md), which you should read too.

# Windows distribution

The Windows distribution of wimlib is a ZIP file containing the following items:

- `wimlib-imagex.exe`, a command-line tool to deal with WIM (.wim), split WIM
  (.swm), and ESD (.esd) files that is inspired by Microsoft's ImageX and DISM.
  This is a ready-to-run executable and not an installer.

- Very short batch scripts (e.g. `wimapply.cmd`) which are shortcuts to the
  corresponding `wimlib-imagex` commands (e.g. `wimlib-imagex apply`).

- The library itself in DLL format (`libwim-15.dll`).  `wimlib-imagex.exe`
  requires this to run.

- The documentation, including this file, the generic README, and PDF
  documentation for `wimlib-imagex` in the `doc` folder.

- License files for all software included.  These are all free software
  licenses.  `COPYING.txt` is the main license, and it refers to
  `COPYING.GPLv3.txt` and `COPYING.LGPLv3.txt`.  The other licenses are for
  third-party software included in the library.

- Development files in the `devel` folder.  These are only needed if you are
  developing C or C++ applications that use wimlib.

Note that there are separate ZIP files for 32-bit `i686` and 64-bit `x86_64`
binaries.  They are both fully supported, but you should prefer the 64-bit
binaries when possible as they can be noticeably faster.

# wimlib-imagex

`wimlib-imagex` supports most features of Microsoft's ImageX as well as some
features that are supported by DISM but not by ImageX.  wimlib-imagex also
supports some features that neither ImageX nor DISM support.  Some of the
advantages of `wimlib-imagex` compared to ImageX and DISM are:

- `wimlib-imagex` provides "extract" and "update" commands which allow you to
  quickly work with WIM images without mounting them.

- `wimlib-imagex` provides an easy-to-use "optimize" command which removes
  wasted space from a WIM file and optionally recompresses it with stronger
  compression.

- wimlib includes advanced implementations of all compression algorithms used in
  WIM files.  They usually outperform and outcompress their Microsoft
  equivalents.

- `wimlib-imagex` supports solid WIM files and LZMS compression, for example as
  used in ESD (.esd) files.  (These are partially supported by recent DISM
  versions but not by ImageX.)

- `wimlib-imagex` supports imaging a live Windows system.  Just use the
  `--snapshot` option.

- In many cases, `wimlib-imagex` has simpler command-line syntax than either
  ImageX or DISM.

- Whenever possible, `wimlib-imagex` includes improved documentation and
  informational output compared to Microsoft's software.

- wimlib and `wimlib-imagex` are free software, so you can modify and/or audit
  the source code.

However, some limitations of `wimlib-imagex` compared to ImageX and DISM are:

- On Windows, `wimlib-imagex` does not support mounting WIM images.

- `wimlib-imagex` has no awareness of Windows "packages".

# Additional notes

It's recommended to use `wimlib-imagex` in scripts to avoid having to
interactively enter commands.  However, note that `wimlib-imagex` is largely
just a command-line front-end for wimlib, and it's possible to use wimlib's API
in other front-ends or applications.  Currently there is no official graphical
user interface available for wimlib or `wimlib-imagex`.  However,
[Wimlib-clc](https://reboot.pro/files/file/588-wimlib-clc/) is an unofficial,
Windows-only graphical user interface for `wimlib-imagex`.

# Building from source

As with other open source software, advanced users may choose to build wimlib
from source, potentially with customizations.  Currently, wimlib depends on
MinGW-w64 for its Windows support; Visual Studio is not supported.  The Windows
binaries can be cross-compiled on Linux, or built on Windows using MSYS2 or
Cygwin.  The following instructions show the MSYS2 method.

First, install MSYS2 by running the installer from
[msys2.org](https://www.msys2.org).

Then, open any MSYS2 shell and run the following command:

    pacman -Syu --noconfirm

After that, open any MSYS2 shell again and run the following commands:

    pacman -Syu --noconfirm git
    git clone https://wimlib.net/git/wimlib

Note: By default the git repository will be on the `master` branch, which is the
latest development snapshot.  Optionally, you can check out a specific version,
e.g. `cd wimlib && git checkout v1.14.4`.  For old versions, please refer to the
documentation for that version, as things may have changed.  It is also possible
to use a release tarball (e.g. `wimlib-1.14.4.tar.gz`) instead of the git repo.

Finally, to actually do a build, close the MSYS2 shell you have open, then open
one of the following from the Start menu:

- "MSYS2 MINGW64" - for `x86_64` binaries, built with gcc
- "MSYS2 CLANG64" - for `x86_64` binaries, built with clang
- "MSYS2 MINGW32" - for `i686` binaries, built with gcc
- "MSYS2 CLANG32" - for `i686` binaries, built with clang
- "MSYS2 CLANGARM64" - for ARM64 binaries (EXPERIMENTAL)

(If unsure, use "MSYS2 MINGW64".)  Then run the following commands:

    cd wimlib
    tools/windows-build.sh --install-prerequisites

The script will automatically download and install the packages needed to build
wimlib in the chosen MSYS2 environment, then build wimlib.  The output will be
in a folder named similarly to `wimlib-1.14.4-windows-x86_64-bin`.  Note that
your "home" folder within MSYS2 is `C:\msys64\home\%USERNAME%` by default.
Therefore, the full path to the output folder will be similar to
`C:\msys64\home\%USERNAME%\wimlib\wimlib-1.14.4-windows-x86_64-bin`.
