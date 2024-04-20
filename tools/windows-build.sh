#!/bin/bash
#
# This script builds wimlib for Windows.  It supports both MSYS2 and Linux.

set -e -u

SCRIPTNAME="$0"
TOPDIR=$(dirname "$(dirname "$(realpath "$0")")")
cd "$TOPDIR" # Top-level directory of the git repo

# Global variables, read-only after parse_options has run
ARCH=
CC_PKG=
DESTDIR=
EXTRA_CMAKE_ARGS=()
INCLUDE_DOCS=false
INSTALL_PREREQUISITES=false
MSYSTEM=${MSYSTEM:-}
INCREMENTAL=false
VERSION=$(tools/get-version-number.sh)
ZIP=false
ZIPFILE=

PREBUILT_LLVM_MINGW_ENABLED=false
PREBUILT_LLVM_MINGW_URL=https://github.com/mstorsjo/llvm-mingw/releases/download/20230320/llvm-mingw-20230320-msvcrt-x86_64.zip
PREBUILT_LLVM_MINGW_ZIP=$(basename "$PREBUILT_LLVM_MINGW_URL")
PREBUILT_LLVM_MINGW=${PREBUILT_LLVM_MINGW_ZIP%.zip}
PREBUILT_LLVM_MINGW_BIN="/$PREBUILT_LLVM_MINGW/bin"

usage()
{
	cat << EOF
Usage: $SCRIPTNAME [OPTION]... [EXTRA_CMAKE_ARGS]...
Options:
  --arch=ARCH               Specify the CPU architecture.  This is unnecessary
                            when using MSYS2.

  --include-docs            Build and install the PDF manual pages.

  --incremental             Skip cleaning the build directory.  Only use this if
                            you are sure you didn't change any option.

  --install-prerequisites   Install the prerequisite packages needed to build
                            wimlib.  This is only supported in MSYS2.  You can
                            omit this if you have already done this for the same
                            MSYS2 environment.  This option normally only
                            installs MSYS2 packages, but for ARM64 cross-builds
                            it also installs a separate prebuilt toolchain.

  --zip                     Zip the output files up into a zip file.
EOF
}

parse_options()
{
	case "$MSYSTEM" in
	"")
		ARCH=x86_64
		;;
	MINGW32)
		ARCH=i686
		CC_PKG=mingw-w64-i686-gcc
		;;
	MINGW64)
		ARCH=x86_64
		CC_PKG=mingw-w64-x86_64-gcc
		;;
	CLANG32)
		ARCH=i686
		CC_PKG=mingw-w64-clang-i686-clang
		;;
	CLANG64)
		ARCH=x86_64
		CC_PKG=mingw-w64-clang-x86_64-clang
		;;
	CLANGARM64)
		ARCH=aarch64
		# MSYS2 doesn't yet support cross-compiling for ARM64, so use a
		# separate prebuilt toolchain for that case.
		if [ "$(uname -m)" = x86_64 ]; then
			PREBUILT_LLVM_MINGW_ENABLED=true
			export PATH="$PREBUILT_LLVM_MINGW_BIN:$PATH"
		else
			CC_PKG=mingw-w64-clang-aarch64-clang
		fi
		;;
	*)
		echo 1>&2 "Unsupported MSYS2 environment: $MSYSTEM.  This script supports"
		echo 1>&2 "MINGW32, MINGW64, CLANG32, CLANG64, and CLANGARM64."
		echo 1>&2 "See https://www.msys2.org/docs/environments/"
		exit 1
	esac

	local longopts="help"
	longopts+=",arch:"
	longopts+=",include-docs"
	longopts+=",incremental"
	longopts+=",install-prerequisites"
	longopts+=",zip"

	local options
	if ! options=$(getopt -o "" -l "$longopts" -- "$@"); then
		usage 1>&2
		exit 1
	fi
	eval set -- "$options"
	while true; do
		case "$1" in
		--help)
			usage
			exit 0
			;;
		--arch)
			ARCH=$2
			shift
			;;
		--include-docs)
			INCLUDE_DOCS=true
			;;
		--incremental)
			INCREMENTAL=true
			;;
		--install-prerequisites)
			if [ -z "$MSYSTEM" ]; then
				echo 1>&2 "--install-prerequisites is only supported in MSYS2."
				exit 1
			fi
			INSTALL_PREREQUISITES=true
			;;
		--zip)
			ZIP=true
			;;
		--)
			shift
			break
			;;
		*)
			echo 1>&2 "Invalid option '$1'"
			usage 1>&2
			exit 1
			;;
		esac
		shift
	done
	case "$ARCH" in
	i686|x86_64|aarch64)
		;;
	*)
		echo 1>&2 "Unknown ARCH: $ARCH.  Please specify a supported architecture with --arch"
		exit 1
		;;
	esac
	DESTDIR=wimlib-${VERSION}-windows-${ARCH}-bin
	ZIPFILE=$DESTDIR.zip
	EXTRA_CMAKE_ARGS+=("$@")
}

install_prebuilt_llvm_mingw()
{
	if [ -e "$PREBUILT_LLVM_MINGW_BIN" ]; then
		echo "Prebuilt $PREBUILT_LLVM_MINGW is already installed"
		return
	fi
	echo "Downloading $PREBUILT_LLVM_MINGW_ZIP..."
	wget "$PREBUILT_LLVM_MINGW_URL" -O "/$PREBUILT_LLVM_MINGW_ZIP"
	echo "Unzipping $PREBUILT_LLVM_MINGW_ZIP..."
	unzip "/$PREBUILT_LLVM_MINGW_ZIP" -d /
	if [ ! -e "$PREBUILT_LLVM_MINGW_BIN" ]; then
		echo 1>&2 "$PREBUILT_LLVM_MINGW_BIN not found after unzip"
		exit 1
	fi
	echo "Done installing prebuilt toolchain $PREBUILT_LLVM_MINGW"
}

install_prerequisites()
{
	echo "Installing the MSYS2 $MSYSTEM packages needed to build wimlib..."
	local packages=(cmake ninja git pkgconf)
	if "$PREBUILT_LLVM_MINGW_ENABLED"; then
		echo "Will use prebuilt toolchain instead of MSYS2 one"
		packages+=(wget unzip)
	else
		packages+=("$CC_PKG")
	fi
	pacman -Syu --noconfirm --needed "${packages[@]}"
	echo "Done installing the MSYS2 $MSYSTEM packages needed to build wimlib."

	if $PREBUILT_LLVM_MINGW_ENABLED; then
		install_prebuilt_llvm_mingw
	fi
}

configure_wimlib()
{
	echo "Configuring wimlib..."
	rm -rf build
	if [ -z "$MSYSTEM" ]; then
		EXTRA_CMAKE_ARGS+=("-DCMAKE_TOOLCHAIN_FILE=tools/toolchain-$ARCH-w64-mingw32.cmake")
	fi
	cmake -B build -G Ninja "${EXTRA_CMAKE_ARGS[@]}"
}

build_wimlib()
{
	echo "Building wimlib..."
	ninja -C build
}

list_imagex_commands()
{
	for cmd in ./doc/man1/wim*.1; do
		local cmd=${cmd##*/}
		cmd=${cmd%.1}
		case "$cmd" in
		wimlib-imagex|wimmount|wimmountrw|wimunmount)
			;;
		*)
			echo "$cmd"
			;;
		esac
	done
}

install_binaries()
{
	echo "Installing binaries..."
	cp build/libwim.dll "$DESTDIR"/libwim-15.dll
	cp build/programs/wimlib-imagex.exe "$DESTDIR"/
	strip "$DESTDIR"/*.{dll,exe}
}

install_text_files()
{
	echo "Installing NEWS, README, and licenses..."
	cp NEWS* README* COPYING* "$DESTDIR"
	sed -n '/^#/q; s/^[\/\* ]*//; p' src/divsufsort.c > "$DESTDIR"/COPYING.libdivsufsort-lite
	if ! grep -q 'Copyright' "$DESTDIR"/COPYING.libdivsufsort-lite; then
		echo 1>&2 "ERROR: failed to extract libdivsufsort-lite license text"
		exit 1
	fi
	cd "$DESTDIR"
	for fil in NEWS* README* COPYING*; do
		sed < "$fil" > "${fil%.md}".txt -e 's/$/\r/g'
		rm "$fil"
	done
	cd ..
}

gen_pdf_from_man_page()
{
	local cmd=$1
	local pdf=${DESTDIR}/doc/${cmd}.pdf

	echo "Generating $pdf"
	MANPATH="./doc" man -t "$cmd" | ps2pdf - "$pdf"
}

install_pdf_docs()
{
	echo "Installing PDF manual pages..."
	mkdir "$DESTDIR"/doc
	for cmd in $(list_imagex_commands); do
		gen_pdf_from_man_page "$cmd"
	done
	gen_pdf_from_man_page wimlib-imagex
}

install_cmd_aliases()
{
	echo "Installing wim*.cmd files..."
	for cmd in $(list_imagex_commands); do
		sed 's/$/\r/g' > "${DESTDIR}/${cmd}.cmd" <<- EOF
			@echo off
			"%~dp0\\wimlib-imagex" ${cmd#wim} %*
		EOF
		chmod +x "${DESTDIR}/${cmd}.cmd"
	done
}

install_development_files()
{
	echo "Installing development files..."
	mkdir "$DESTDIR"/devel
	cp build/libwim.dll.a "$DESTDIR"/devel/libwim.lib
	cp include/wimlib.h "$DESTDIR"/devel/
}

create_zip_file()
{
	echo "Creating zip file..."
	cd "$DESTDIR"
	7z -mx9 a ../"$ZIPFILE" . > /dev/null
	cd ..
}

parse_options "$@"
rm -rf -- "$DESTDIR" "$ZIPFILE"
mkdir -- "$DESTDIR"
if $INSTALL_PREREQUISITES; then
	install_prerequisites
fi
if ! $INCREMENTAL || [ ! -e build ]; then
	configure_wimlib
fi
build_wimlib
install_binaries
install_text_files
if $INCLUDE_DOCS; then
	install_pdf_docs
fi
install_cmd_aliases
install_development_files
if $ZIP; then
	create_zip_file
	echo "Success!  Output is in $ZIPFILE"
else
	echo "Success!  Output is in $DESTDIR"
fi
