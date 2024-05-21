#include <windows.h>
#include <cstdio>
#include <shlobj.h>
#include "ProxyCaller.h"
#include "Syscalls.h"

#pragma comment (lib, "shell32.lib")

SYSCALL_API g_syscallApi = { 0 };

VOID AddWin32uToIat() {
    WCHAR szPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

int main() {
    PVOID       pAddress    = NULL;
    PTP_WORK    WorkReturn  = NULL;
    SIZE_T      memSize     = 4096;
    NTSTATUS    ntStatus    = 0x0;

    AddWin32uToIat();
    if (!InitSyscalls(&g_syscallApi)) {
        return 0;
    }

    SYSCALL_ARGS<6> ntAllocateVirtualMemoryArgs;
    ntAllocateVirtualMemoryArgs.pSyscallInstruction = (UINT_PTR)g_syscallApi.NtAllocateVirtualMemory.pSyscallInstructionAddress;
    ntAllocateVirtualMemoryArgs.dwSsn               = (UINT_PTR)g_syscallApi.NtAllocateVirtualMemory.dwSsn;
    ntAllocateVirtualMemoryArgs.pArgs[0]            = (UINT_PTR)NtCurrentProcess();
    ntAllocateVirtualMemoryArgs.pArgs[1]            = (UINT_PTR)&pAddress;
    ntAllocateVirtualMemoryArgs.pArgs[2]            = (UINT_PTR)NULL;
    ntAllocateVirtualMemoryArgs.pArgs[3]            = (UINT_PTR)&memSize;
    ntAllocateVirtualMemoryArgs.pArgs[4]            = (UINT_PTR)(MEM_COMMIT|MEM_RESERVE);
    ntAllocateVirtualMemoryArgs.pArgs[5]            = (UINT_PTR)PAGE_EXECUTE_READWRITE;
    ntAllocateVirtualMemoryArgs.pNtStatus           = &ntStatus;

    __typeof__(TpAllocWork)*    TpAllocWork     = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocWork");
    __typeof__(TpPostWork)*     TpPostWork      = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpPostWork");
    __typeof__(TpReleaseWork)*  TpReleaseWork   = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpReleaseWork");

    TpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)ProxyCaller, &ntAllocateVirtualMemoryArgs, NULL);
    TpPostWork(WorkReturn);
    TpReleaseWork(WorkReturn);

    Sleep(1000);

    printf("Memory allocated at: %p\n", pAddress);
    printf("NTSTATUS: 0x%X\n", ntStatus);
    getchar();
    return 0;
}
