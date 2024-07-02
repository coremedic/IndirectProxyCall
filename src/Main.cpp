#include <windows.h>
#include <cstdio>
#include <shlobj.h>
#include "ProxyCaller.h"
#include "Syscalls.h"

#pragma comment (lib, "shell32.lib")

SYSCALL_API     g_syscallApi        = { 0 };
volatile LONG*  pNtStatus           = NULL;
HANDLE          g_hEvent            = NULL;
PVOID           g_pReturnAddress    = NULL;

LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    static bool bpSet = false;
    CONTEXT* ctx = ExceptionInfo->ContextRecord;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {

        if (!bpSet) {
            ctx->Dr0 = (DWORD64)g_pReturnAddress;
            ctx->Dr7 = 0x00000001;
            ctx->Rip += 2;
            bpSet = true;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    } else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        *pNtStatus = (NTSTATUS)ctx->Rax;
        ctx->Dr0 = 0;
        ctx->Dr7 = 0;

        SetEvent(g_hEvent);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

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

    pNtStatus = (volatile LONG*)VirtualAlloc(NULL, sizeof(LONG), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pNtStatus) {
        return 0;
    }

    g_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_hEvent) {
        return 0;
    }
    g_pReturnAddress = (PVOID)((UINT_PTR)g_syscallApi.NtAllocateVirtualMemory.pSyscallInstructionAddress + 2);
    AddVectoredExceptionHandler(1, VectoredHandler);

    SYSCALL_ARGS<6> ntAllocateVirtualMemoryArgs;
    ntAllocateVirtualMemoryArgs.pSyscallInstruction = (UINT_PTR)g_syscallApi.NtAllocateVirtualMemory.pSyscallInstructionAddress;
    ntAllocateVirtualMemoryArgs.dwSsn               = (UINT_PTR)g_syscallApi.NtAllocateVirtualMemory.dwSsn;
    ntAllocateVirtualMemoryArgs.pArgs[0]            = (UINT_PTR)NtCurrentProcess();
    ntAllocateVirtualMemoryArgs.pArgs[1]            = (UINT_PTR)&pAddress;
    ntAllocateVirtualMemoryArgs.pArgs[2]            = (UINT_PTR)NULL;
    ntAllocateVirtualMemoryArgs.pArgs[3]            = (UINT_PTR)&memSize;
    ntAllocateVirtualMemoryArgs.pArgs[4]            = (UINT_PTR)(MEM_COMMIT|MEM_RESERVE);
    ntAllocateVirtualMemoryArgs.pArgs[5]            = (UINT_PTR)PAGE_EXECUTE_READWRITE;

    __typeof__(TpAllocWork)*    TpAllocWork     = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocWork");
    __typeof__(TpPostWork)*     TpPostWork      = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpPostWork");
    __typeof__(TpReleaseWork)*  TpReleaseWork   = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpReleaseWork");

    TpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)ProxyCaller, &ntAllocateVirtualMemoryArgs, NULL);
    TpPostWork(WorkReturn);
    TpReleaseWork(WorkReturn);

    WaitForSingleObject(g_hEvent, INFINITE);

    ntStatus = *pNtStatus;
    printf("Memory allocated at: %p\n", pAddress);
    printf("NTSTATUS: 0x%X\n", ntStatus);
    getchar();

    CloseHandle(g_hEvent);
    VirtualFree((LPVOID)pNtStatus, 0, MEM_RELEASE);
    return 0;
}
