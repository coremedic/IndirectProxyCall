#ifndef INDIRECTPROXYCALL_SYSCALLS_H
#define INDIRECTPROXYCALL_SYSCALLS_H

#include <windows.h>

typedef struct _SYSCALL {
    DWORD   dwSsn;
    PVOID   pSyscallInstructionAddress;
} SYSCALL, *PSYSCALL;

typedef struct _SYSCALL_API {
    SYSCALL NtAllocateVirtualMemory;
    BOOL    bInit;
} SYSCALL_API, *PSYSCALL_API;

typedef struct _MODULE_CONFIG {
    PDWORD      pdwArrayOfAddresses;
    PDWORD      pdwArrayOfNames;
    PWORD       pwArrayOfOrdinals;
    DWORD       dwNumberOfNames;
    ULONG_PTR   pModule;
    BOOLEAN     bInit;
} MODULE_CONFIG, *PMODULE_CONFIG;

EXTERN_C BOOL InitSyscalls(_Out_ PSYSCALL_API pSyscallApi);

#endif //INDIRECTPROXYCALL_SYSCALLS_H
