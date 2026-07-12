# =============================================================================
# MinGW-w64 cross-compilation toolchain file (Linux host -> Windows target)
#
# Usage from the project root:
#   mkdir build && cd build
#   cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-mingw-x86_64.cmake ..
#   cmake --build . -j
#
# On Debian/Ubuntu install with:
#   sudo apt install mingw-w64 cmake
# =============================================================================
set(CMAKE_SYSTEM_NAME      Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Pick the MinGW-w64 compilers (prefer posix threads / seh exceptions)
set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)

# Where the target runtime libraries live
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)

# Search programs only in the host environment, libs/headers only in target
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Static link of the CRT makes the .exe portable to machines without MinGW
set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")

# Win32 subsystem (no console pop-up) -- comment out if you want a console
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--subsystem,windows")
