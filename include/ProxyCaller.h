#ifndef INDIRECTPROXYCALL_PROXYCALLER_H
#define INDIRECTPROXYCALL_PROXYCALLER_H

#include <windows.h>

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

template<UINT64 N>
struct SYSCALL_ARGS {
    UINT_PTR    pSyscallInstruction;
    DWORD       dwSsn;
    UINT64      argCount = N;
    UINT_PTR    pArgs[N];
};

NTSYSAPI
NTSTATUS
NTAPI
TpAllocWork(
        _Out_ PTP_WORK *WorkReturn,
        _In_ PTP_WORK_CALLBACK Callback,
        _Inout_opt_ PVOID Context,
        _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
);

NTSYSAPI
VOID
NTAPI
TpPostWork(
        _Inout_ PTP_WORK Work
);

NTSYSAPI
VOID
NTAPI
TpReleaseWork(
        _Inout_ PTP_WORK Work
);

EXTERN_C VOID CALLBACK ProxyCaller(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

#endif //INDIRECTPROXYCALL_PROXYCALLER_H
