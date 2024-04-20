# Build and install the wimlib-imagex binary.
set(EXE_SOURCES imagex.c)
if(WIN32)
    list(APPEND EXE_SOURCES
         imagex-win32.c
         imagex-win32.h
         wgetopt.c
         wgetopt.h)
endif()
add_executable(wimlib-imagex ${EXE_SOURCES})
target_link_libraries(wimlib-imagex PUBLIC wimlib)
set_target_properties(wimlib-imagex PROPERTIES
                      # Console application, not a GUI executable.
                      WIN32_EXECUTABLE OFF)
if(WIN32)
    target_link_libraries(wimlib-imagex PRIVATE -municode)
endif()
install(TARGETS wimlib-imagex)

# Build and install the mkwinpeimg shell script.
configure_file(mkwinpeimg.in mkwinpeimg @ONLY)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/mkwinpeimg
        DESTINATION ${CMAKE_INSTALL_BINDIR})
