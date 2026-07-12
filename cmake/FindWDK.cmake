# =============================================================================
# Optional: helper module to locate the Windows Driver Kit (WDK) on a Windows
# build host. This is only used when BUILD_DRIVER=ON. The WDK ships headers
# and libraries required to compile a .sys kernel-mode binary.
#
# On Linux there is no native WDK; cross-compiling a .sys with MinGW is
# theoretically possible but not officially supported. For learning, build
# the driver on a Windows machine that has Visual Studio + WDK installed.
# =============================================================================
# Inputs:
#   WDK_ROOT  (env or cache) - explicit WDK install path
#
# Outputs:
#   WDK_FOUND       - TRUE if a usable WDK was located
#   WDK_INCLUDE_DIR - root of WDK headers (e.g. .../Include/10.0.22621.0)
#   WDK_LIB_DIR     - root of WDK libs     (e.g. .../Lib/10.0.22621.0)
#   WDK_NTDDK_HDR   - full path to ntddk.h
# =============================================================================

# Common install locations
set(_wdk_candidates
    "$ENV{WDK_ROOT}"
    "C:/Program Files (x86)/Windows Kits/10"
    "C:/Program Files/Windows Kits/10")

find_path(WDK_INCLUDE_DIR
    NAMES um/Windows.h km/ntddk.h
    PATHS ${_wdk_candidates}
    PATH_SUFFIXES Include
    DOC "WDK Include root")

find_path(WDK_LIB_DIR
    NAMES km/x64/ntoskrnl.lib
    PATHS ${_wdk_candidates}
    PATH_SUFFIXES Lib
    DOC "WDK Lib root")

if(WDK_INCLUDE_DIR AND WDK_LIB_DIR)
    set(WDK_FOUND TRUE)
    # Find the newest kit version subdirectory
    file(GLOB _wdk_versions LIST_DIRECTORIES true RELATIVE ${WDK_INCLUDE_DIR} ${WDK_INCLUDE_DIR}/*)
    list(SORT _wdk_versions)
    list(REVERSE _wdk_versions)
    list(GET _wdk_versions 0 WDK_VERSION)
    set(WDK_NTDDK_HDR "${WDK_INCLUDE_DIR}/${WDK_VERSION}/km/ntddk.h")
    message(STATUS "Found WDK: version ${WDK_VERSION}")
    message(STATUS "  includes: ${WDK_INCLUDE_DIR}/${WDK_VERSION}")
    message(STATUS "  libs:     ${WDK_LIB_DIR}/${WDK_VERSION}")
else()
    set(WDK_FOUND FALSE)
endif()

mark_as_advanced(WDK_INCLUDE_DIR WDK_LIB_DIR WDK_VERSION WDK_NTDDK_HDR)
