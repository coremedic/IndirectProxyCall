#include "Syscalls.h"

#define STUB_SIZE       0x20

#define UP              (-1 * STUB_SIZE)
#define DOWN            STUB_SIZE
#define SEARCH_RANGE    0xFF

#define MOV1_OPCODE     0x4C
#define R10_OPCODE      0x8B
#define RCX_OPCODE      0xD1
#define MOV2_OPCODE     0xB8
#define JMP_OPCODE      0xE9
#define RET_OPCODE      0xC3

MODULE_CONFIG g_ntdllConf    = {NULL};
MODULE_CONFIG g_win32uConf   = {NULL};

unsigned int GenerateRandomInt() {
    static unsigned int state = 123456789;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

// PEB walk, I don't even understand how the fuck my PEB talk
BOOL InitModuleConfig(_Out_ PMODULE_CONFIG pModuleConfig, _In_ ULONG_PTR pBaseAddress) {
    PIMAGE_NT_HEADERS       pImageNtHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY pImageExportDir = NULL;

    if (!pBaseAddress) {
        return FALSE;
    }
    pModuleConfig -> pModule = pBaseAddress;

    pImageNtHeaders = (PIMAGE_NT_HEADERS)(pModuleConfig->pModule + ((PIMAGE_DOS_HEADER)pModuleConfig->pModule)->e_lfanew);
    if (!pImageNtHeaders || pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    if (pImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return FALSE;
    }

    pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)(pModuleConfig->pModule + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImageExportDir) {
        return FALSE;
    }

    pModuleConfig->dwNumberOfNames      = pImageExportDir->NumberOfNames;
    pModuleConfig->pdwArrayOfNames      = (PDWORD)(pModuleConfig->pModule + pImageExportDir->AddressOfNames);
    pModuleConfig->pdwArrayOfAddresses  = (PDWORD)(pModuleConfig->pModule + pImageExportDir->AddressOfFunctions);
    pModuleConfig->pwArrayOfOrdinals    = (PWORD)(pModuleConfig->pModule + pImageExportDir->AddressOfNameOrdinals);

    if (!pModuleConfig->dwNumberOfNames || !pModuleConfig->pdwArrayOfNames || !pModuleConfig->pdwArrayOfAddresses || !pModuleConfig->pwArrayOfOrdinals) {
        return FALSE;
    }

    pModuleConfig->bInit = TRUE;
    return TRUE;
}

// Find that syscall instruction
BOOL FindSyscallInstruction(_Out_ PVOID* ppSyscallInstructionAddress) {
    if (!ppSyscallInstructionAddress) {
        return FALSE;
    }

    int idx = GenerateRandomInt() % 16,
            cnt = 0;

    if (!g_win32uConf.bInit) {
        if (!InitModuleConfig(&g_win32uConf, (ULONG_PTR)GetModuleHandleA("win32u.dll"))) {
            return FALSE;
        }
    }

    if (!g_win32uConf.dwNumberOfNames || !g_win32uConf.pdwArrayOfNames) {
        return FALSE;
    }

    for (DWORD i = 0; i < g_win32uConf.dwNumberOfNames; i++) {
        PCHAR pcFuncName = (PCHAR)(g_win32uConf.pModule + g_win32uConf.pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)(g_win32uConf.pModule + g_win32uConf.pdwArrayOfAddresses[g_win32uConf.pwArrayOfOrdinals[i]]);

        if (!pcFuncName || !pFuncAddress)
            continue;
        for (DWORD offset = 0; offset < STUB_SIZE; offset++) {
            unsigned short* pOpcode = (unsigned short*)((ULONG_PTR)pFuncAddress + offset);
            BYTE* pRetOpcode = (BYTE*)((ULONG_PTR)pFuncAddress + offset + sizeof(unsigned short));

            if (*pOpcode == (0x052A ^ 0x25) && *pRetOpcode == RET_OPCODE) {
                if (cnt == idx) {
                    *ppSyscallInstructionAddress = (PVOID)((ULONG_PTR)pFuncAddress + offset);
                    break;
                }
                cnt++;
            }
        }
        if (*ppSyscallInstructionAddress) {
            return TRUE;
        }
    }
    return FALSE;
}

// Find the syscall stub from ntdll
BOOL FetchNtSyscallStub(_In_ PCHAR pcSyscallName, _Out_ PSYSCALL pNtSyscall) {
    if (!g_ntdllConf.bInit) {
        if (!InitModuleConfig(&g_ntdllConf, (UINT_PTR)GetModuleHandleA("ntdll.dll"))) {
            return FALSE;
        }
    }

    for (DWORD i = 0; i < g_ntdllConf.dwNumberOfNames; i++) {

        PCHAR pcFuncName    = (PCHAR)(g_ntdllConf.pModule + g_ntdllConf.pdwArrayOfNames[i]);
        PVOID pFuncAddress  = (PVOID)(g_ntdllConf.pModule + g_ntdllConf.pdwArrayOfAddresses[g_ntdllConf.pwArrayOfOrdinals[i]]);

        if (strcmp(pcFuncName, pcSyscallName) == 0) {
            if (*((PBYTE)pFuncAddress) == MOV1_OPCODE
                && *((PBYTE)pFuncAddress + 1) == R10_OPCODE
                && *((PBYTE)pFuncAddress + 2) == RCX_OPCODE
                && *((PBYTE)pFuncAddress + 3) == MOV2_OPCODE
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE    high   = *((PBYTE)pFuncAddress + 5);
                BYTE    low    = *((PBYTE)pFuncAddress + 4);
                pNtSyscall->dwSsn = (high << 8) | low;
                break;
            }

            if (*((PBYTE)pFuncAddress) == JMP_OPCODE) {

                for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == MOV1_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == R10_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == RCX_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == MOV2_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSyscall->dwSsn = (high << 8) | low - idx;
                        break;
                    }
                    if (*((PBYTE)pFuncAddress + idx * UP) == MOV1_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == R10_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == RCX_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == MOV2_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSyscall->dwSsn = (high << 8) | low + idx;
                        break;
                    }
                }
            }

            if (*((PBYTE)pFuncAddress + 3) == JMP_OPCODE) {

                for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == MOV1_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == R10_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == RCX_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == MOV2_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSyscall->dwSsn = (high << 8) | low - idx;
                        break;
                    }
                    if (*((PBYTE)pFuncAddress + idx * UP) == MOV1_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == R10_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == RCX_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == MOV2_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSyscall->dwSsn = (high << 8) | low + idx;
                        break;
                    }
                }
            }
            break;
        }
    }

    if (!pNtSyscall->dwSsn) {
        return FALSE;
    }

    return FindSyscallInstruction(&pNtSyscall->pSyscallInstructionAddress);
}

// Init all syscalls
BOOL InitSyscalls(_Out_ PSYSCALL_API pSyscallApi) {
    if (!pSyscallApi) {
        return FALSE;
    }

    if (pSyscallApi->bInit) {
        return TRUE;
    }

    if (!FetchNtSyscallStub("NtAllocateVirtualMemory", &pSyscallApi->NtAllocateVirtualMemory)) {
        return FALSE;
    }

    pSyscallApi->bInit = TRUE;
    return TRUE;
}