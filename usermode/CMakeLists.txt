# =============================================================================
# usermode/CMakeLists.txt
#
# This is the part that IS meant to cross-compile cleanly on Linux with
# MinGW-w64. It produces a single .exe that talks to the driver via Win32
# DeviceIoControl.
# =============================================================================
# --- Common setup ---
set(USERMODE_SOURCES
    driver_ctl.cpp
    driver_loader.cpp
    process.cpp)

# We need the shared driver.h that defines IOCTL codes + structs.
set(USERMODE_INCLUDES
    "${CMAKE_CURRENT_SOURCE_DIR}/../driver")

# Win32 libs
set(USERMODE_LIBS kernel32 user32 advapi32 psapi)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    list(APPEND USERMODE_LIBS ntdll)
endif()

# MinGW compile flags
set(MINGW_FLAGS "")
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(MINGW_FLAGS -Wall -Wextra -Wno-unused-parameter
        -finput-charset=UTF-8 -fexec-charset=UTF-8 -Wno-format)
endif()

# =============================================================================
# dmmdzz_ctl — original demo program
# =============================================================================
add_executable(dmmdzz_ctl
    main.cpp
    ${USERMODE_SOURCES})

target_include_directories(dmmdzz_ctl PRIVATE ${USERMODE_INCLUDES})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(dmmdzz_ctl PRIVATE ${USERMODE_LIBS})
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(dmmdzz_ctl PRIVATE ${MINGW_FLAGS})
endif()

set_target_properties(dmmdzz_ctl PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

# =============================================================================
# dmmdzz_ce — Cheat Engine style memory scanner
# =============================================================================
add_executable(dmmdzz_ce
    ce_cli.cpp
    scanner.cpp
    ${USERMODE_SOURCES})

target_include_directories(dmmdzz_ce PRIVATE ${USERMODE_INCLUDES})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(dmmdzz_ce PRIVATE ${USERMODE_LIBS})
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(dmmdzz_ce PRIVATE ${MINGW_FLAGS})
endif()

set_target_properties(dmmdzz_ce PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
