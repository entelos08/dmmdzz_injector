# =============================================================================
# driver/CMakeLists.txt
#
# IMPORTANT: A kernel-mode .sys file MUST be linked against ntoskrnl.lib and
# compiled with the WDK's kernel headers. The WDK is only available on
# Windows. CMake can drive that build on a Windows host with Visual Studio's
# "MSVC + WDK" toolchain.
#
# On Linux you can NOT produce a proper signed .sys with MinGW. This file is
# therefore written to be cross-host-aware:
#
#   * On Windows with WDK detected -> builds dmmdzz_injector.sys
#   * Otherwise                   -> emits the sources only (no target)
#
# The driver sources are still useful for reading/studying and for building
# on a Windows machine later.
# =============================================================================
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(WDK)

if(NOT WDK_FOUND)
    message(WARNING
      "WDK not found - skipping kernel driver build.\n"
      "The driver sources in driver/ are still emitted for educational "
      "reading and for building on a Windows host with the WDK.\n"
      "To enable: install WDK on Windows and pass -DBUILD_DRIVER=ON.")
    return()
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(WARNING
      "Cross-compiling a .sys with MinGW on Linux is not supported by the "
      "WDK. The driver target is disabled. Use the Windows build host.")
    return()
endif()

set(WDK_INC "${WDK_INCLUDE_DIR}/${WDK_VERSION}")
set(WDK_LIB "${WDK_LIB_DIR}/${WDK_VERSION}")

set(DRIVER_SOURCES
    main.c
    ioctl.c
    memory.c
    process.c)

add_library(dmmdzz_injector SHARED ${DRIVER_SOURCES})

set_target_properties(dmmdzz_injector PROPERTIES
    SUFFIX ".sys"
    PREFIX "")

target_include_directories(dmmdzz_injector PRIVATE
    "${WDK_INC}/km"
    "${WDK_INC}/km/crt"
    "${CMAKE_CURRENT_SOURCE_DIR}")

# Kernel-mode compile flags (MSVC)
target_compile_options(dmmdzz_injector PRIVATE
    /kernel
    /GS-
    /Zl
    /D_KERNEL_MODE=1
    /DNT=1
    /D_WIN32_WINNT=0x0A00)

# Linker flags for a driver
target_link_options(dmmdzz_injector PRIVATE
    /SUBSYSTEM:NATIVE
    /DRIVER
    /ENTRY:DriverEntry
    /NODEFAULTLIB
    /MACHINE:X64)

target_link_libraries(dmmdzz_injector PRIVATE
    "${WDK_LIB}/km/x64/ntoskrnl.lib"
    "${WDK_LIB}/km/x64/hal.lib")

# Copy the .inf next to the .sys so the pair is installable
add_custom_command(TARGET dmmdzz_injector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/dmmdzz_injector.inf"
        "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
