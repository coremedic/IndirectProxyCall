#include <windows.h>
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
    PVOID allocatedAddress  = NULL;
    SIZE_T allocatedsize    = 0x1000;

    AddWin32uToIat();
    if (!InitSyscalls(&g_syscallApi)) {
        return 0;
    }
}