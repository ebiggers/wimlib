if(WIN32)
    add_executable(win32-tree-cmp win32-tree-cmp.c)
    add_executable(set_reparse_point set_reparse_point.c)
else()
    add_executable(tree-cmp tree-cmp.c)
endif()
if(WIMLIB_FUZZ_TEST_SUPPORT)
    add_executable(wlfuzz wlfuzz.c)
    target_link_libraries(wlfuzz PUBLIC wimlib)
endif()

if(NOT WIN32)
    set(TEST_SCRIPTS
        test-imagex
        test-imagex-capture_and_apply
        test-imagex-update_and_extract
    )
    if(WIMLIB_NTFS_3G_SUPPORT)
        list(APPEND TEST_SCRIPTS test-imagex-ntfs)
    endif()
    if(WIMLIB_FUSE_SUPPORT)
        list(APPEND TEST_SCRIPTS test-imagex-mount)
    endif()
    foreach(SCRIPT ${TEST_SCRIPTS})
        add_test(NAME ${SCRIPT} COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/${SCRIPT})
    endforeach()
endif()
