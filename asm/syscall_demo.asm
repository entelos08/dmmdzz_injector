; =============================================================================
; asm/syscall_demo.asm  (x86_64, NASM syntax, MinGW-w64 compatible)
;
; EDUCATIONAL PURPOSE
; -------------------
; This file demonstrates three things:
;
;   1. How a user-mode call ends up in the kernel via the syscall instruction
;      on Windows x64. Every Nt* / Zw* call in ntdll.dll ends with a single
;      `syscall` instruction after loading the syscall number into eax.
;
;   2. How to assemble a standalone .asm object file with NASM and link it
;      into a MinGW-w64 executable. The C function in asm/example.c calls
;      these stubs.
;
;   3. Why directly issuing syscalls is interesting for learning:
;      it lets you observe the kernel's syscall dispatcher (KiSystemCall64)
;      in a debugger without the wrapping that ntdll does.
;
; NOTE: Direct syscalls bypass user-mode hooks, but they are FRAGILE -
;       syscall numbers change between Windows builds. We hard-code
;       Windows 10/11 numbers here for ILLUSTRATION ONLY; the project does
;       not actually rely on these stubs (it uses DeviceIoControl like a
;       normal application). Build with BUILD_ASM=ON to study the linkage.
;
; ABI (Windows x64):
;   - First 4 integer args in RCX, RDX, R8, R9
;   - Shadow space: 32 bytes above return address
;   - Volatile: RAX, RCX, RDX, R8, R9, R10, R11
;   - For syscalls, the kernel clobbers RCX (saved RIP) and R11 (RFLAGS).
; =============================================================================

BITS 64
DEFAULT REL

; -----------------------------------------------------------------------------
; Exported symbols (cdecl-like; we use the standard x64 Windows ABI)
; -----------------------------------------------------------------------------
global dmmdzz_NtQueryInformationProcess_direct
global dmmdzz_GetLastErrorMock

; -----------------------------------------------------------------------------
; Section layout: standard .text for code.
; -----------------------------------------------------------------------------
section .text

; -----------------------------------------------------------------------------
; ULONG dmmdzz_NtQueryInformationProcess_direct(
;            HANDLE   ProcessHandle,      ; RCX
;            ULONG    ProcessInformationClass, ; RDX
;            PVOID    ProcessInformation, ; R8
;            ULONG    ProcessInformationLength, ; R9
;            PULONG   ReturnLength);      ; [rsp+0x28]
;
; Windows 10/11 syscall number for NtQueryInformationProcess is 0x19 (25).
; Replace with the value for your build if needed.
;
; We:
;   1. Save R9 (4th arg) into R10 (the kernel ABI expects args in R10, RDX,
;      R8, R9 -- the kernel remaps RCX->R10 because RCX is used for RIP).
;   2. Move the syscall number into EAX.
;   3. Execute `syscall`.
;   4. The kernel returns the NTSTATUS in RAX.
; -----------------------------------------------------------------------------
dmmdzz_NtQueryInformationProcess_direct:
    ; Prologue: reserve shadow space for the callee (none here, but show it)
    sub  rsp, 0x28                       ; 0x20 shadow + 8 align

    ; The Windows x64 syscall ABI requires:
    ;   R10 = first arg (NOT RCX, because RCX holds return RIP after `syscall`)
    mov  r10, rcx                        ; copy arg1 to r10
    mov  eax, 0x19                       ; syscall # for NtQueryInformationProcess
    syscall                              ; enter the kernel via KiSystemCall64

    ; RAX now contains the NTSTATUS. Return it.
    add  rsp, 0x28
    ret

; -----------------------------------------------------------------------------
; ULONG dmmdzz_GetLastErrorMock(void)
;
; Returns the value of EAX after a syscall, but mock-styled so we can
; demonstrate a leaf function with no arguments. Returns 0xDEADBEEF as a
; marker so you can spot it in a debugger.
; -----------------------------------------------------------------------------
dmmdzz_GetLastErrorMock:
    mov  eax, 0xDEADBEEF
    ret
