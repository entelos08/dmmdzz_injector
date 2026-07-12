# =============================================================================
# Educational Windows Kernel Driver Communication Tool
# Top-level CMake configuration
#
# This project is intended for EDUCATIONAL PURPOSES ONLY, to learn about
# Windows kernel driver development, IRP handling, IRQL rules, and user/kernel
# communication. The "target" process is a placeholder ("target.exe") for
# demonstration. Do NOT use against processes you do not own.
# =============================================================================
cmake_minimum_required(VERSION 3.16)

project(dmmdzz_injector
    VERSION 0.1.0
    DESCRIPTION "Educational Windows kernel driver communication tool"
    LANGUAGES C CXX ASM)

# ---------------------------------------------------------------------------
# Global build options
# ---------------------------------------------------------------------------
set(CMAKE_C_STANDARD    11)
set(CMAKE_CXX_STANDARD  17)
set(CMAKE_C_STANDARD_REQUIRED   ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build type default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Output directories (keeps the build tree clean)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---------------------------------------------------------------------------
# Options - the usermode app is cross-compiled with MinGW-w64 on Linux.
# The driver .sys normally needs the WDK on Windows. For learning, the
# driver target is only activated when WDK is detected; otherwise we still
# emit the source so it can be built on a Windows machine.
# ---------------------------------------------------------------------------
option(BUILD_USERMODE "Build the user-mode controller (MinGW-w64)" ON)
option(BUILD_DRIVER   "Build the kernel driver (requires WDK on Windows)" OFF)
option(BUILD_ASM      "Build the educational asm module"                 ON)

message(STATUS "============================================================")
message(STATUS " dmmdzz_injector - EDUCATIONAL KERNEL LEARNING TOOL")
message(STATUS "   CMAKE_SYSTEM_NAME  = ${CMAKE_SYSTEM_NAME}")
message(STATUS "   CMAKE_C_COMPILER   = ${CMAKE_C_COMPILER}")
message(STATUS "   CMAKE_CXX_COMPILER = ${CMAKE_CXX_COMPILER}")
message(STATUS "   BUILD_USERMODE     = ${BUILD_USERMODE}")
message(STATUS "   BUILD_DRIVER       = ${BUILD_DRIVER}")
message(STATUS "   BUILD_ASM          = ${BUILD_ASM}")
message(STATUS "============================================================")

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------
if(BUILD_USERMODE)
    add_subdirectory(usermode)
endif()

if(BUILD_DRIVER)
    add_subdirectory(driver)
endif()

if(BUILD_ASM)
    add_subdirectory(asm)
endif()
