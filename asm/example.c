// =============================================================================
// asm/example.c
//
// Tiny C harness that calls the NASM stubs so the linker has something to
// resolve. This is purely for demonstrating cross-language linkage between
// MinGW C and NASM assembly on Linux.
//
// Build with:  cmake -DBUILD_ASM=ON ...
// =============================================================================
#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Imported from syscall_demo.asm
uint32_t dmmdzz_NtQueryInformationProcess_direct(void* hProc,
                                                 uint32_t infoClass,
                                                 void*  buf,
                                                 uint32_t bufLen,
                                                 uint32_t* retLen);
uint32_t dmmdzz_GetLastErrorMock(void);

#ifdef __cplusplus
}
#endif

int dmmdzz_asm_demo(void)
{
    printf("[asm] Calling NASM stub dmmdzz_GetLastErrorMock() ...\n");
    uint32_t marker = dmmdzz_GetLastErrorMock();
    printf("[asm]   returned 0x%08X (expected 0xDEADBEEF)\n", marker);

    printf("[asm] Direct NtQueryInformationProcess stub is linked but\n");
    printf("     NOT called by default - calling it without a real\n");
    printf("     HANDLE would crash. Read syscall_demo.asm to see the\n");
    printf("     syscall instruction and the Win10/11 ABI remapping\n");
    printf("     (RCX -> R10) the kernel performs.\n");
    return 0;
}

/* MinGW 链接器默认查找 main 或 WinMain 作为入口点。提供 main 让 demo
 * 可执行; 它仅转发到上面的演示函数。 */
int main(void)
{
    return dmmdzz_asm_demo();
}
