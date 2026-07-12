# =============================================================================
# asm/CMakeLists.txt
#
# Builds a tiny standalone educational program that links a NASM-assembled
# x64 object file with a MinGW C harness. This proves the cross-toolchain
# (NASM + MinGW-w64) works and lets learners single-step through the syscall
# instruction in a debugger.
# =============================================================================
enable_language(ASM)

# Find NASM. On Debian/Ubuntu:  sudo apt install nasm
find_program(NASM_EXECUTABLE nasm)

if(NOT NASM_EXECUTABLE)
    message(WARNING
      "NASM not found - skipping the asm educational module.\n"
      "Install with 'sudo apt install nasm' on Linux or 'choco install nasm' "
      "on Windows to enable it.")
    return()
endif()

# NASM flags for x64 Windows MinGW object format
set(ASM_FLAGS -f win64 -D_WIN64)

# Assemble the .asm into an object file
add_custom_command(
    OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/syscall_demo.obj
    COMMAND ${NASM_EXECUTABLE} ${ASM_FLAGS}
            -I${CMAKE_CURRENT_SOURCE_DIR}/
            ${CMAKE_CURRENT_SOURCE_DIR}/syscall_demo.asm
            -o ${CMAKE_CURRENT_BINARY_DIR}/syscall_demo.obj
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/syscall_demo.asm
    VERBATIM)

add_executable(dmmdzz_asm_demo
    example.c
    ${CMAKE_CURRENT_BINARY_DIR}/syscall_demo.obj)

target_include_directories(dmmdzz_asm_demo PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../driver")

set_target_properties(dmmdzz_asm_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

if(CMAKE_C_COMPILER_ID MATCHES "GNU")
    target_compile_options(dmmdzz_asm_demo PRIVATE -Wall -Wextra)
endif()
