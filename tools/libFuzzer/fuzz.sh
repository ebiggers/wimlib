#!/bin/bash

set -e -u -o pipefail

cd "$(dirname "$0")"
TOPDIR=../..
SCRIPTDIR=$PWD

read -r -a AVAILABLE_TARGETS < <(echo */fuzz.c | sed 's@/fuzz.c@@g')

usage()
{
	cat << EOF
Usage: $0 [OPTION]... FUZZ_TARGET

Fuzz wimlib with LLVM's libFuzzer.

Options:
   --asan          Enable AddressSanitizer
   --input=INPUT   Test a single input file only
   --max-len=LEN   Maximum length of generated inputs (default: $MAX_LEN)
   --msan          Enable MemorySanitizer
   --time=SECONDS  Stop after the given time has passed
   --ubsan         Enable UndefinedBehaviorSanitizer

Available fuzz targets: ${AVAILABLE_TARGETS[*]}
EOF
}

die()
{
	echo "$*" 1>&2
	exit 1
}

run_cmd()
{
	echo "$*"
	"$@"
}

EXTRA_SANITIZERS=
EXTRA_FUZZER_ARGS=()
INPUT=
MAX_LEN=32768

longopts_array=(
asan
help
input:
max-len:
msan
time:
ubsan
)
longopts=$(echo "${longopts_array[@]}" | tr ' ' ',')

if ! options=$(getopt -o "" -l "$longopts" -- "$@"); then
	usage 1>&2
	exit 1
fi
eval set -- "$options"
while true; do
	case "$1" in
	--asan)
		EXTRA_SANITIZERS+=",address"
		;;
	--help)
		usage
		exit 0
		;;
	--input)
		INPUT=$2
		shift
		;;
	--max-len)
		MAX_LEN=$2
		shift
		;;
	--msan)
		EXTRA_SANITIZERS+=",memory"
		;;
	--time)
		EXTRA_FUZZER_ARGS+=("-max_total_time=$2")
		shift
		;;
	--ubsan)
		EXTRA_SANITIZERS+=",undefined"
		;;
	--)
		shift
		break
		;;
	*)
		echo 1>&2 "Invalid option '$1'"
		usage 1>&2
		exit 1
	esac
	shift
done
EXTRA_FUZZER_ARGS+=("-max_len=$MAX_LEN")

if (( $# != 1 )); then
	echo 1>&2 "No fuzz target specified!"
	usage 1>&2
	exit 1
fi
TARGET=$1
if [ ! -e "$TARGET/fuzz.c" ]; then
	echo 1>&2 "'$TARGET' is not a valid fuzz target!"
	usage 1>&2
	exit 1
fi
cd "$TOPDIR"
cflags="-g -O1 -Wall -Werror"
cflags+=" -fsanitize=fuzzer-no-link$EXTRA_SANITIZERS"
if [ -n "$EXTRA_SANITIZERS" ]; then
	cflags+=" -fno-sanitize-recover=${EXTRA_SANITIZERS#,}"
fi
if ! [ -e config.log ] || ! grep -q -- "'CFLAGS=$cflags'" config.log; then
	run_cmd ./configure --enable-test-support --without-fuse --without-ntfs-3g \
		CC=clang CFLAGS="$cflags"
fi
run_cmd make "-j$(getconf _NPROCESSORS_ONLN)"
cd "$SCRIPTDIR"
if [ -n "$INPUT" ]; then
	run_cmd clang -g -O1 -fsanitize=fuzzer-no-link$EXTRA_SANITIZERS -Wall -Werror \
		-I "$TOPDIR/include" "$TARGET/fuzz.c" test-one-input.c fault-injection.c \
		"$TOPDIR/.libs/libwim.a" -o test-one-input
	run_cmd ./test-one-input "$INPUT"
else
	run_cmd clang -g -O1 -fsanitize=fuzzer$EXTRA_SANITIZERS -Wall -Werror \
		-I "$TOPDIR/include" "$TARGET/fuzz.c" fault-injection.c \
		"$TOPDIR/.libs/libwim.a" -o "$TARGET/fuzz"
	run_cmd "$TARGET/fuzz" "${EXTRA_FUZZER_ARGS[@]}" "$TARGET/corpus"
fi
