cmake_minimum_required(VERSION 3.7)

# Default to a release build.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "No build type selected; defaulting to Release")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build" FORCE)
endif()

#execute_process(COMMAND tools/get-version-number.sh
                #OUTPUT_VARIABLE WIMLIB_VERSION
                #OUTPUT_STRIP_TRAILING_WHITESPACE)
#message(STATUS "WIMLIB_VERSION=${WIMLIB_VERSION}")

# Declare the project.
project(wimlib
        LANGUAGES C
        VERSION 1.14.4)

# Include the CMake modules required by the top-level directory.
include(CMakePackageConfigHelpers)
include(CheckCCompilerFlag)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckStructHasMember)
include(FindPkgConfig)
include(FindThreads)
include(GNUInstallDirs)

# Set default options for the platform.
if(WIN32)
    set(NTFS_3G_DEFAULT OFF)
    set(FUSE_DEFAULT OFF)
elseif(LINUX)
    set(NTFS_3G_DEFAULT ON)
    set(FUSE_DEFAULT ON)
else()
    set(NTFS_3G_DEFAULT ON)
    set(FUSE_DEFAULT OFF)
endif()

# Declare the options, which can be overridden via 'cmake -DOPTION=VALUE'.
option(WIMLIB_NTFS_3G_SUPPORT
       "Enable support for applying/capturing WIM images directly to/from \
unmounted NTFS volumes.  This requires libntfs-3g and is not supported \
on Windows."
       ${NTFS_3G_DEFAULT})
option(WIMLIB_FUSE_SUPPORT
       "Enable support for mounting WIM images.  This requires libfuse and \
is only supported on Linux."
       ${FUSE_DEFAULT})
option(WIMLIB_FUZZ_TEST_SUPPORT "Enable fuzz testing support code" OFF)
option(BUILD_SHARED_LIBS "Build a shared library, not a static library" ON)
option(WIMLIB_BUILD_TESTS "Build test programs" OFF)

if(WIMLIB_NTFS_3G_SUPPORT)
    add_compile_options(-DWITH_NTFS_3G)
    pkg_check_modules(NTFS_3G REQUIRED libntfs-3g)
endif()
if(WIMLIB_FUSE_SUPPORT)
    add_compile_options(-DWITH_FUSE)
    pkg_check_modules(FUSE REQUIRED fuse3)
    find_library(RT rt REQUIRED)
endif()
if(WIMLIB_FUZZ_TEST_SUPPORT)
    add_compile_options(-DENABLE_TEST_SUPPORT)
endif()

#if(LIBDEFLATE_BUILD_TESTS)
    #enable_testing()
#endif()

## Set common C compiler flags for all targets (the library and the programs).
set(CMAKE_C_FLAGS_RELEASE "-O2")
add_compile_options(
    -DPACKAGE_VERSION="${PROJECT_VERSION}"
    -DPACKAGE_BUGREPORT="https://wimlib.net/forums"
    -D_LARGEFILE_SOURCE
    -D_FILE_OFFSET_BITS=64
    -D_GNU_SOURCE
    -fno-common
    -std=gnu99
    -Wall
    -Wmissing-prototypes
    -Wno-pointer-sign
    -Wstrict-prototypes
    -Wundef
)
if(WIN32)
    add_compile_options(
        -D_POSIX
        -D_POSIX_THREAD_SAFE_FUNCTIONS
        -DUNICODE
        -D_UNICODE
        -D_CRT_NON_CONFORMING_SWPRINTFS
        -D__MINGW_USE_VC2005_COMPAT
        -D_WIN32_WINNT=0x0600
        -municode
        -mno-ms-bitfields
    )
endif()

check_include_file(alloca.h HAVE_ALLOCA_H)
check_include_file(byteswap.h HAVE_BYTESWAP_H)
check_include_file(endian.h HAVE_ENDIAN_H)
check_include_file(glob.h HAVE_GLOB_H)
check_include_file(machine/endian.h HAVE_MACHINE_ENDIAN_H)
check_include_file(sys/byteorder.h HAVE_SYS_BYTEORDER_H)
check_include_file(sys/endian.h HAVE_SYS_ENDIAN_H)
check_include_file(sys/file.h HAVE_SYS_FILE_H)
check_include_file(sys/param.h HAVE_SYS_PARAM_H)
check_include_file(sys/syscall.h HAVE_SYS_SYSCALL_H)
check_include_file(sys/sysctl.h HAVE_SYS_SYSCTL_H)
check_include_file(sys/xattr.h HAVE_SYS_XATTR_H)
check_include_file(utime.h HAVE_UTIME_H)
add_compile_options(
    $<$<BOOL:${HAVE_ALLOCA_H}>:-DHAVE_ALLOCA_H>
    $<$<BOOL:${HAVE_BYTESWAP_H}>:-DHAVE_BYTESWAP_H>
    $<$<BOOL:${HAVE_ENDIAN_H}>:-DHAVE_ENDIAN_H>
    $<$<BOOL:${HAVE_GLOB_H}>:-DHAVE_GLOB_H>
    $<$<BOOL:${HAVE_MACHINE_ENDIAN_H}>:-DHAVE_MACHINE_ENDIAN_H>
    $<$<BOOL:${HAVE_SYS_BYTEORDER_H}>:-DHAVE_SYS_BYTEORDER_H>
    $<$<BOOL:${HAVE_SYS_ENDIAN_H}>:-DHAVE_SYS_ENDIAN_H>
    $<$<BOOL:${HAVE_SYS_FILE_H}>:-DHAVE_SYS_FILE_H>
    $<$<BOOL:${HAVE_SYS_PARAM_H}>:-DHAVE_SYS_PARAM_H>
    $<$<BOOL:${HAVE_SYS_SYSCALL_H}>:-DHAVE_SYS_SYSCALL_H>
    $<$<BOOL:${HAVE_SYS_SYSCTL_H}>:-DHAVE_SYS_SYSCTL_H>
    $<$<BOOL:${HAVE_SYS_XATTR_H}>:-DHAVE_SYS_XATTR_H>
    $<$<BOOL:${HAVE_UTIME_H}>:-DHAVE_UTIME_H>
)
add_compile_options(
    -DHAVE_ERRNO_H
    -DHAVE_STDDEF_H
    -DHAVE_STDINT_H
    -DHAVE_STDIO_H
    -DHAVE_STDLIB_H
    -DHAVE_SYS_STAT_H
    -DHAVE_SYS_TIME_H
    -DHAVE_SYS_TYPES_H
)

check_function_exists(fdopendir HAVE_FDOPENDIR)
check_function_exists(flock HAVE_FLOCK)
check_function_exists(fsetxattr HAVE_FSETXATTR)
check_function_exists(fstatat HAVE_FSTATAT)
check_function_exists(futimens HAVE_FUTIMENS)
check_function_exists(getopt_long_only HAVE_GETOPT_LONG_ONLY)
check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)
check_function_exists(lgetxattr HAVE_LGETXATTR)
check_function_exists(llistxattr HAVE_LLISTXATTR)
check_function_exists(lsetxattr HAVE_LSETXATTR)
check_function_exists(mempcpy HAVE_MEMPCPY)
check_function_exists(openat HAVE_OPENAT)
check_function_exists(posix_fallocate HAVE_POSIX_FALLOCATE)
check_function_exists(readlinkat HAVE_READLINKAT)
check_function_exists(utimensat HAVE_UTIMENSAT)
add_compile_options(
    $<$<BOOL:${HAVE_FDOPENDIR}>:-DHAVE_FDOPENDIR>
    $<$<BOOL:${HAVE_FLOCK}>:-DHAVE_FLOCK>
    $<$<BOOL:${HAVE_FSETXATTR}>:-DHAVE_FSETXATTR>
    $<$<BOOL:${HAVE_FSTATAT}>:-DHAVE_FSTATAT>
    $<$<BOOL:${HAVE_FUTIMENS}>:-DHAVE_FUTIMENS>
    $<$<BOOL:${HAVE_GETTIMEOFDAY}>:-DHAVE_GETTIMEOFDAY>
    $<$<BOOL:${HAVE_GETOPT_LONG_ONLY}>:-DHAVE_GETOPT_LONG_ONLY>
    $<$<BOOL:${HAVE_LGETXATTR}>:-DHAVE_LGETXATTR>
    $<$<BOOL:${HAVE_LLISTXATTR}>:-DHAVE_LLISTXATTR>
    $<$<BOOL:${HAVE_LSETXATTR}>:-DHAVE_LSETXATTR>
    $<$<BOOL:${HAVE_MEMPCPY}>:-DHAVE_MEMPCPY>
    $<$<BOOL:${HAVE_OPENAT}>:-DHAVE_OPENAT>
    $<$<BOOL:${HAVE_POSIX_FALLOCATE}>:-DHAVE_POSIX_FALLOCATE>
    $<$<BOOL:${HAVE_READLINKAT}>:-DHAVE_READLINKAT>
    $<$<BOOL:${HAVE_UTIMENSAT}>:-DHAVE_UTIMENSAT>
)

# Does stat() support nanosecond-precision timestamps?  (This is relevant on
# UNIX but not on Windows.)
CHECK_STRUCT_HAS_MEMBER("struct stat" st_mtim sys/stat.h
                        HAVE_STAT_NANOSECOND_PRECISION)
add_compile_options(
    $<$<BOOL:${HAVE_STAT_NANOSECOND_PRECISION}>:-DHAVE_STAT_NANOSECOND_PRECISION>
)

## Determine the list of source files and the list of compiler options that will
## be used for both the static library and the shared library.

set(LIB_SOURCES
    include/wimlib.h
    include/wimlib_tchar.h
    include/wimlib/alloca.h
    include/wimlib/apply.h
    include/wimlib/assert.h
    include/wimlib/avl_tree.h
    include/wimlib/bitops.h
    include/wimlib/blob_table.h
    include/wimlib/bt_matchfinder.h
    include/wimlib/case.h
    include/wimlib/chunk_compressor.h
    include/wimlib/compiler.h
    include/wimlib/compress_common.h
    include/wimlib/compressor_ops.h
    include/wimlib/cpu_features.h
    include/wimlib/decompress_common.h
    include/wimlib/decompressor_ops.h
    include/wimlib/dentry.h
    include/wimlib/divsufsort.h
    include/wimlib/encoding.h
    include/wimlib/endianness.h
    include/wimlib/error.h
    include/wimlib/file_io.h
    include/wimlib/glob.h
    include/wimlib/guid.h
    include/wimlib/hc_matchfinder.h
    include/wimlib/header.h
    include/wimlib/inode.h
    include/wimlib/inode_table.h
    include/wimlib/integrity.h
    include/wimlib/lcpit_matchfinder.h
    include/wimlib/list.h
    include/wimlib/lzms_common.h
    include/wimlib/lzms_constants.h
    include/wimlib/lzx_common.h
    include/wimlib/lzx_constants.h
    include/wimlib/matchfinder_common.h
    include/wimlib/metadata.h
    include/wimlib/object_id.h
    include/wimlib/pathlist.h
    include/wimlib/paths.h
    include/wimlib/pattern.h
    include/wimlib/progress.h
    include/wimlib/registry.h
    include/wimlib/reparse.h
    include/wimlib/resource.h
    include/wimlib/scan.h
    include/wimlib/security_descriptor.h
    include/wimlib/security.h
    include/wimlib/sha1.h
    include/wimlib/solid.h
    include/wimlib/tagged_items.h
    include/wimlib/test_support.h
    include/wimlib/textfile.h
    include/wimlib/threads.h
    include/wimlib/timestamp.h
    include/wimlib/types.h
    include/wimlib/unaligned.h
    include/wimlib/unix_data.h
    include/wimlib/util.h
    include/wimlib/wim.h
    include/wimlib/write.h
    include/wimlib/xattr.h
    include/wimlib/xml.h
    include/wimlib/xmlproc.h
    include/wimlib/xml_windows.h
    include/wimlib/xpress_constants.h
    src/add_image.c
    src/avl_tree.c
    src/blob_table.c
    src/compress.c
    src/compress_common.c
    src/compress_parallel.c
    src/compress_serial.c
    src/cpu_features.c
    src/decompress.c
    src/decompress_common.c
    src/delete_image.c
    src/dentry.c
    src/divsufsort.c
    src/encoding.c
    src/error.c
    src/export_image.c
    src/extract.c
    src/file_io.c
    src/header.c
    src/inode.c
    src/inode_fixup.c
    src/inode_table.c
    src/integrity.c
    src/iterate_dir.c
    src/join.c
    src/lcpit_matchfinder.c
    src/lzms_common.c
    src/lzms_compress.c
    src/lzms_decompress.c
    src/lzx_common.c
    src/lzx_compress.c
    src/lzx_decompress.c
    src/metadata_resource.c
    src/mount_image.c
    src/pathlist.c
    src/paths.c
    src/pattern.c
    src/progress.c
    src/reference.c
    src/registry.c
    src/reparse.c
    src/resource.c
    src/scan.c
    src/security.c
    src/sha1.c
    src/solid.c
    src/split.c
    src/tagged_items.c
    src/template.c
    src/textfile.c
    src/threads.c
    src/timestamp.c
    src/update_image.c
    src/util.c
    src/verify.c
    src/wimboot.c
    src/wim.c
    src/write.c
    src/xml.c
    src/xmlproc.c
    src/xml_windows.c
    src/xpress_compress.c
    src/xpress_decompress.c
)
if(WIN32)
    list(APPEND LIB_SOURCES
        include/wimlib/wimboot.h
        include/wimlib/win32.h
        include/wimlib/win32_common.h
        include/wimlib/win32_vss.h
        include/wimlib/wof.h
        src/wimboot.c
        src/win32_apply.c
        src/win32_capture.c
        src/win32_common.c
        src/win32_replacements.c
        src/win32_vss.c)
else()
    list(APPEND LIB_SOURCES
         src/unix_apply.c
         src/unix_capture.c)
endif()
if(WIMLIB_NTFS_3G_SUPPORT)
    list(APPEND LIB_SOURCES
         include/wimlib/ntfs_3g.h
         src/ntfs-3g_apply.c
         src/ntfs-3g_capture.c)
endif()
if(WIMLIB_FUZZ_TEST_SUPPORT)
    list(APPEND LIB_SOURCES
         src/test_support.c)
endif()

set(LIB_INCLUDE_DIRS
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_FULL_INCLUDEDIR}>)

add_library(wimlib ${LIB_SOURCES})

# This alias allows third-party usage of the library with CMake to work the same
# way with add_subdirectory() as with other ways.
add_library(wimlib::wimlib ALIAS wimlib)
set_target_properties(wimlib PROPERTIES
                      OUTPUT_NAME wim
                      PUBLIC_HEADER include/wimlib.h
                      C_VISIBILITY_PRESET hidden
                      VERSION 15.26.0
                      SOVERSION 15)
target_include_directories(wimlib PUBLIC ${LIB_INCLUDE_DIRS})
target_compile_definitions(wimlib PRIVATE -DBUILDING_WIMLIB)
target_link_libraries(wimlib PRIVATE Threads::Threads)
set(CMAKE_PKGCONFIG_PRIVATE_REQUIRES)
set(CMAKE_PKGCONFIG_PRIVATE_LIBS)
if(WIMLIB_NTFS_3G_SUPPORT)
    target_compile_options(wimlib PRIVATE ${NTFS_3G_CFLAGS})
    target_link_libraries(wimlib PRIVATE ${NTFS_3G_LDFLAGS})
    string(APPEND CMAKE_PKGCONFIG_PRIVATE_REQUIRES " libntfs-3g")
endif()
if(WIMLIB_FUSE_SUPPORT)
    target_compile_options(wimlib PRIVATE ${FUSE_CFLAGS})
    target_link_libraries(wimlib PRIVATE ${FUSE_LDFLAGS} -lrt)
    string(APPEND CMAKE_PKGCONFIG_PRIVATE_LIBS " -lrt")
    string(APPEND CMAKE_PKGCONFIG_PRIVATE_REQUIRES " fuse")
endif()
if(WIMLIB_FUZZ_TEST_SUPPORT)
    target_link_libraries(wimlib PRIVATE -lm)
endif()
if(WIN32)
    target_link_libraries(wimlib PRIVATE ntdll)
    target_link_libraries(wimlib PRIVATE -municode)
endif()

# Install the library.
install(TARGETS wimlib
        EXPORT wimlib_exported_targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Generate and install the pkg-config file.  (Don't confuse this with the CMake
# package config file, which is CMake-specific.)  Take care to define the
# include and lib directories in terms of the ${prefix} and ${exec_prefix}
# pkg-config variables when possible, since some pkg-config users expect to be
# able to override these variables to relocate packages.
if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
    set(CMAKE_PKGCONFIG_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}")
else()
    set(CMAKE_PKGCONFIG_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
endif()
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
    set(CMAKE_PKGCONFIG_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
else()
    set(CMAKE_PKGCONFIG_LIBDIR "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
endif()
configure_file(wimlib.pc.in wimlib.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wimlib.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# Generate a "wimlib-targets.cmake" file in the build tree that can be
# included by outside projects to import targets from the build tree.
export(EXPORT wimlib_exported_targets
       NAMESPACE wimlib::
       FILE wimlib-targets.cmake)

# Generate and install a separate "wimlib-targets.cmake" file that can be
# included by outside projects to import targets from the installation tree.
install(EXPORT wimlib_exported_targets
        NAMESPACE wimlib::
        FILE wimlib-targets.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wimlib)

# Generate and install the CMake package version and config files.
write_basic_package_version_file(wimlib-config-version.cmake
                                 VERSION ${PROJECT_VERSION}
                                 COMPATIBILITY AnyNewerVersion)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/wimlib-config.cmake.in
    wimlib-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wimlib)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wimlib-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/wimlib-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wimlib)

# Build the programs subdirectory.
add_subdirectory(programs)

# Build the tests subdirectory.
if(WIMLIB_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
