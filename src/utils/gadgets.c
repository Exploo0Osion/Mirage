#include "myloader.h"

#ifndef UNW_FLAG_CHAININFO
#define UNW_FLAG_CHAININFO 0x4
#endif

static BOOL DecodeCallInstruction(PBYTE p, PBYTE end, size_t* outLen) {
    if (!p || !end || p >= end || !outLen) return FALSE;
    *outLen = 0;

    if (p + 5 <= end && p[0] == 0xE8) {
        *outLen = 5; // call rel32
        return TRUE;
    }

    if (p + 6 <= end && p[0] == 0xFF && p[1] == 0x15) {
        *outLen = 6; // call [rip+rel32]
        return TRUE;
    }

    if (p + 2 <= end) {
        if ((p[0] == 0x0F && (p[1] == 0x05 || p[1] == 0x34)) || (p[0] == 0xCD && p[1] == 0x2E)) {
            *outLen = 2; // syscall / sysenter / int 2e
            return TRUE;
        }
    }

    size_t idx = 0;
    if (p + 2 <= end && (p[0] >= 0x40 && p[0] <= 0x4F)) {
        idx = 1; // REX prefix
    }

    if (p + idx + 2 <= end && p[idx] == 0xFF) {
        BYTE modrm = p[idx + 1];
        BYTE reg = (modrm >> 3) & 0x7;
        if (reg != 2) return FALSE; // not CALL r/m

        BYTE mod = (modrm >> 6) & 0x3;
        BYTE rm = modrm & 0x7;
        size_t len = idx + 2; // rex + opcode + modrm

        if (mod != 3 && rm == 4) {
            if (p + len + 1 > end) return FALSE;
            BYTE sib = p[len];
            BYTE base = sib & 0x7;
            len += 1;
            if (mod == 0 && base == 5) {
                len += 4;
            }
        }

        if (mod == 1) {
            len += 1;
        } else if (mod == 2) {
            len += 4;
        } else if (mod == 0 && rm == 5) {
            len += 4;
        }

        if (p + len <= end) {
            *outLen = len;
            return TRUE; // call r/m (rex.w=1 or rex.w=0)
        }
    }

    return FALSE;
}

static BOOL IsCallPreceding(PBYTE addr, PBYTE codeStart, PBYTE codeEnd) {
    if (!addr || !codeStart || !codeEnd || addr <= codeStart || addr > codeEnd) return FALSE;

    const size_t maxBack = 15;
    PBYTE scanStart = (addr > codeStart + maxBack) ? (addr - maxBack) : codeStart;

    for (PBYTE p = scanStart; p < addr; p++) {
        size_t len = 0;
        if (DecodeCallInstruction(p, addr, &len) && p + len == addr) {
            return TRUE;
        }
    }

    return FALSE;
}

// [保留] 辅助函数
PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

// 查找函数入口
PRUNTIME_FUNCTION VxLookupFunctionEntry(DWORD64 ControlPc, PVOID ImageBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pDos->e_lfanew);
    PIMAGE_DATA_DIRECTORY pDataDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    PRUNTIME_FUNCTION pFirstEntry = (PRUNTIME_FUNCTION)((PBYTE)ImageBase + pDataDir->VirtualAddress);
    PRUNTIME_FUNCTION pEndEntry = pFirstEntry + (pDataDir->Size / sizeof(RUNTIME_FUNCTION));

    for (PRUNTIME_FUNCTION pEntry = pFirstEntry; pEntry < pEndEntry; pEntry++) {
        if (ControlPc >= (DWORD64)ImageBase + pEntry->BeginAddress && 
            ControlPc < (DWORD64)ImageBase + pEntry->EndAddress) {
            return pEntry;
        }
    }
    return NULL;
}
DWORD FindCallSiteOffset(PVOID funcAddr, PVOID moduleBase) {
    PRUNTIME_FUNCTION rf = VxLookupFunctionEntry((DWORD64)funcAddr, moduleBase);
    if (!rf) return 0x10; // 找不到 Unwind Info，回退到默认

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    
    DWORD64 start = (DWORD64)moduleBase + rf->BeginAddress;
    DWORD64 end = (DWORD64)moduleBase + rf->EndAddress;
    
    // 简单的反汇编扫描
    for (DWORD64 ptr = start; ptr < end - 5; ptr++) {
        BYTE b1 = *(BYTE*)ptr;
        BYTE b2 = *(BYTE*)(ptr+1);

        // 1. 匹配 E8 xx xx xx xx (CALL rel32)
        if (b1 == 0xE8) {
            DWORD offset = (DWORD)(ptr + 5 - start);
            return offset;
        }

        // 2. 匹配 FF 15 xx xx xx xx (CALL [RIP+x]) - 常用于系统 API 调用
        if (b1 == 0xFF && b2 == 0x15) {
            DWORD offset = (DWORD)(ptr + 6 - start);
            return offset;
        }
    }

    return 0x10; // 没找到 Call，回退到硬编码偏移
}
//栈大小计算函数 (RSP-Based)
DWORD CalculateFunctionStackSize(PVOID funcAddr, PVOID moduleBase) {
    PRUNTIME_FUNCTION rf = VxLookupFunctionEntry((DWORD64)funcAddr, moduleBase);
    if (!rf) return 0;

    DWORD64 imageBase = (DWORD64)moduleBase;
    PUNWIND_INFO info = (PUNWIND_INFO)(imageBase + rf->UnwindData);
    
    DWORD totalStackSize = 0;
    
    for (UBYTE i = 0; i < info->CountOfCodes; i++) {
        UNWIND_CODE code = info->UnwindCode[i];
        UBYTE op = code.UnwindOp;
        UBYTE opInfo = code.OpInfo;

        switch (op) {
            case UWOP_PUSH_NONVOL:     // push reg
                totalStackSize += 8;
                break;
            case UWOP_ALLOC_LARGE:     // sub rsp, X
                if (opInfo == 0) {
                    i++; 
                    totalStackSize += (info->UnwindCode[i].FrameOffset * 8);
                } else {
                    i += 2;
                    DWORD size = *(DWORD*)&info->UnwindCode[i-1]; 
                    totalStackSize += size;
                }
                break;
            case UWOP_ALLOC_SMALL:     // sub rsp, X
                totalStackSize += (opInfo + 1) * 8;
                break;
            case UWOP_PUSH_MACH_FRAME:
                totalStackSize += (opInfo ? 0x48 : 0x40);
                break;
            // 跳过不影响 RSP 的指令
            case UWOP_SAVE_NONVOL: i++; break;
            case UWOP_SAVE_NONVOL_BIG: i += 2; break;
            case UWOP_SAVE_XMM128: i++; break;
            case UWOP_SAVE_XMM128BIG: i += 2; break;
            case UWOP_SET_FPREG: break; 
        }
    }
    return totalStackSize;
}

static DWORD GetStackFrameSizeWhereRbpIsPushedOnStack(PUNWIND_INFO info, DWORD* outStackSize) {
    DWORD unwindOffset = 0;
    BOOL rbpPushed = FALSE;
    DWORD saveStackOffset = 0;

    if (!info || !outStackSize) return RBP_OFFSET_INVALID;
    *outStackSize = 0;

    if (info->Flags & UNW_FLAG_CHAININFO) {
        return RBP_OFFSET_INVALID;
    }

    for (UBYTE i = 0; i < info->CountOfCodes; i++) {
        UNWIND_CODE code = info->UnwindCode[i];
        UBYTE op = code.UnwindOp;
        UBYTE opInfo = code.OpInfo;

        switch (op) {
            case UWOP_PUSH_NONVOL:
                if (opInfo == RSP) return RBP_OFFSET_INVALID;
                if (opInfo == RBP) {
                    if (rbpPushed) return RBP_OFFSET_INVALID;
                    rbpPushed = TRUE;
                    saveStackOffset = unwindOffset;
                }
                unwindOffset += 8;
                break;
            case UWOP_ALLOC_LARGE:
                if (opInfo == 0) {
                    if (i + 1 >= info->CountOfCodes) return RBP_OFFSET_INVALID;
                    i++;
                    unwindOffset += (info->UnwindCode[i].FrameOffset * 8);
                }
                else {
                    if (i + 2 >= info->CountOfCodes) return RBP_OFFSET_INVALID;
                    i += 2;
                    DWORD size = *(DWORD*)&info->UnwindCode[i - 1];
                    unwindOffset += size;
                }
                break;
            case UWOP_ALLOC_SMALL:
                unwindOffset += (opInfo + 1) * 8;
                break;
            case UWOP_SET_FPREG:
                return RBP_OFFSET_INVALID;
            case UWOP_SAVE_NONVOL:
                if (opInfo == RSP) return RBP_OFFSET_INVALID;
                if (i + 1 >= info->CountOfCodes) return RBP_OFFSET_INVALID;
                i++;
                break;
            case UWOP_SAVE_NONVOL_BIG:
                if (opInfo == RSP) return RBP_OFFSET_INVALID;
                if (i + 2 >= info->CountOfCodes) return RBP_OFFSET_INVALID;
                i += 2;
                break;
            case UWOP_PUSH_MACH_FRAME:
                unwindOffset += (opInfo ? 0x48 : 0x40);
                break;
            case UWOP_SAVE_XMM128:
                i++;
                break;
            case UWOP_SAVE_XMM128BIG:
                i += 2;
                break;
            case UWOP_EPILOG:
            case UWOP_SPARE_CODE:
            default:
                break;
        }
    }

    *outStackSize = unwindOffset;

    if (!rbpPushed) {
        return RBP_OFFSET_INVALID;
    }

    if (saveStackOffset >= unwindOffset) {
        return RBP_OFFSET_INVALID;
    }

    return saveStackOffset;
}

static BOOL HasUwopSetFpreg(PUNWIND_INFO info, DWORD* outFpOffset) {
    if (outFpOffset) *outFpOffset = 0;
    if (!info) return FALSE;
    if (info->FrameRegister != RBP) return FALSE;

    for (UBYTE i = 0; i < info->CountOfCodes; i++) {
        UNWIND_CODE code = info->UnwindCode[i];
        UBYTE op = code.UnwindOp;
        UBYTE opInfo = code.OpInfo;

        switch (op) {
            case UWOP_SET_FPREG:
                if (outFpOffset) *outFpOffset = (DWORD)info->FrameOffset * 16;
                return TRUE;
            case UWOP_ALLOC_LARGE:
                if (opInfo == 0) {
                    i++;
                } else {
                    i += 2;
                }
                break;
            case UWOP_SAVE_NONVOL:
            case UWOP_SAVE_XMM128:
                i++;
                break;
            case UWOP_SAVE_NONVOL_BIG:
            case UWOP_SAVE_XMM128BIG:
                i += 2;
                break;
            default:
                break;
        }
    }

    return FALSE;
}

static DWORD CalculateStackSizeWithFpregInfo(PUNWIND_INFO info) {
    if (!info) return 0;

    LONG totalStackSize = 0;

    for (UBYTE i = 0; i < info->CountOfCodes; i++) {
        UNWIND_CODE code = info->UnwindCode[i];
        UBYTE op = code.UnwindOp;
        UBYTE opInfo = code.OpInfo;

        switch (op) {
            case UWOP_PUSH_NONVOL:
                totalStackSize += 8;
                break;
            case UWOP_ALLOC_LARGE:
                if (opInfo == 0) {
                    if (i + 1 >= info->CountOfCodes) return 0;
                    i++;
                    totalStackSize += (info->UnwindCode[i].FrameOffset * 8);
                } else {
                    if (i + 2 >= info->CountOfCodes) return 0;
                    i += 2;
                    DWORD size = *(DWORD*)&info->UnwindCode[i - 1];
                    totalStackSize += size;
                }
                break;
            case UWOP_ALLOC_SMALL:
                totalStackSize += (opInfo + 1) * 8;
                break;
            case UWOP_SET_FPREG:
                totalStackSize += (LONG)(-16 * (LONG)info->FrameOffset);
                break;
            case UWOP_PUSH_MACH_FRAME:
                totalStackSize += (opInfo ? 0x48 : 0x40);
                break;
            case UWOP_SAVE_NONVOL:
            case UWOP_SAVE_XMM128:
                i++;
                break;
            case UWOP_SAVE_NONVOL_BIG:
            case UWOP_SAVE_XMM128BIG:
                i += 2;
                break;
            default:
                break;
        }
    }

    if (totalStackSize <= 0) return 0;
    return (DWORD)totalStackSize;
}

BOOL FindPrologFrame(PVOID moduleBase, PVOID* outFunction, DWORD* outFrameSize, DWORD* outFpOffset) {
    if (!moduleBase || !outFunction || !outFrameSize || !outFpOffset) return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    PIMAGE_DATA_DIRECTORY pDataDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!pDataDir->VirtualAddress || pDataDir->Size < sizeof(RUNTIME_FUNCTION)) return FALSE;

    PRUNTIME_FUNCTION pFirstEntry = (PRUNTIME_FUNCTION)((PBYTE)moduleBase + pDataDir->VirtualAddress);
    DWORD entryCount = pDataDir->Size / sizeof(RUNTIME_FUNCTION);

    for (DWORD i = 0; i < entryCount; i++) {
        PRUNTIME_FUNCTION entry = &pFirstEntry[i];
        if (!entry->BeginAddress || !entry->UnwindData) continue;

        PUNWIND_INFO info = (PUNWIND_INFO)((PBYTE)moduleBase + entry->UnwindData);
        if (info->Flags & UNW_FLAG_CHAININFO) continue;

        DWORD fpOffset = 0;
        if (!HasUwopSetFpreg(info, &fpOffset)) continue;

        DWORD stackSize = CalculateStackSizeWithFpregInfo(info);
        if (stackSize == 0) continue;

        *outFunction = (PBYTE)moduleBase + entry->BeginAddress;
        *outFrameSize = stackSize;
        *outFpOffset = fpOffset;
        return TRUE;
    }
    return FALSE;
}

DWORD GetRbpPushOffset(PVOID funcAddr, PVOID moduleBase, DWORD* outStackSize) {
    if (outStackSize) *outStackSize = 0;
    if (!funcAddr || !moduleBase) return RBP_OFFSET_INVALID;

    PRUNTIME_FUNCTION rf = VxLookupFunctionEntry((DWORD64)funcAddr, moduleBase);
    if (!rf) return RBP_OFFSET_INVALID;

    PUNWIND_INFO info = (PUNWIND_INFO)((PBYTE)moduleBase + rf->UnwindData);
    DWORD rbpOffset = GetStackFrameSizeWhereRbpIsPushedOnStack(info, outStackSize);
    return rbpOffset;
}

BOOL FindPushRbpFrame(PVOID moduleBase, PVOID* outFunction, DWORD* outFrameSize, DWORD* outRbpOffset) {
    if (!moduleBase || !outFunction || !outFrameSize || !outRbpOffset) return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    PIMAGE_DATA_DIRECTORY pDataDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!pDataDir->VirtualAddress || pDataDir->Size < sizeof(RUNTIME_FUNCTION)) return FALSE;

    PRUNTIME_FUNCTION pFirstEntry = (PRUNTIME_FUNCTION)((PBYTE)moduleBase + pDataDir->VirtualAddress);
    DWORD entryCount = pDataDir->Size / sizeof(RUNTIME_FUNCTION);

    for (DWORD i = 0; i < entryCount; i++) {
        PRUNTIME_FUNCTION entry = &pFirstEntry[i];
        if (!entry->BeginAddress || !entry->UnwindData) continue;

        PUNWIND_INFO info = (PUNWIND_INFO)((PBYTE)moduleBase + entry->UnwindData);
        DWORD stackSize = 0;
        DWORD rbpOffset = GetStackFrameSizeWhereRbpIsPushedOnStack(info, &stackSize);
        if (rbpOffset == RBP_OFFSET_INVALID || stackSize == 0) continue;
        if (rbpOffset < 0x20 || rbpOffset > (stackSize - 8)) {
            continue;
        }

        *outFunction = (PBYTE)moduleBase + entry->BeginAddress;
        *outFrameSize = stackSize;
        *outRbpOffset = rbpOffset;
        return TRUE;
    }
    return FALSE;
}

// 查找 Gadget (AddRsp)
PVOID FindAddRspGadget(PVOID pModuleBase, DWORD* outSize) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
	PBYTE start = (PBYTE)pModuleBase + pNt->OptionalHeader.BaseOfCode;
	DWORD size = pNt->OptionalHeader.SizeOfCode;
	for (DWORD i = 0; i + 4 < size; i++) {
		if (start[i] == 0x48 && start[i + 1] == 0x83 && start[i + 2] == 0xC4 && start[i + 4] == 0xC3){
			BYTE gadgetSize = start[i + 3];
            // NtCreateThreadEx 需要 0x58 空间，我们留点余量，找个 0x68 或更大的
            if (gadgetSize % 8 == 0 && gadgetSize >= 0x68) {
                if (!IsCallPreceding(start + i, start, start + size)) {
                    continue;
                }
                DWORD stackSize = CalculateFunctionStackSize((PVOID)(start + i), pModuleBase);
                if (stackSize == 0) {
                    continue;
                }
                if (stackSize != gadgetSize) {
                    continue;
                }
                if (outSize) {
                    *outSize = stackSize;
                }
                return (PVOID)(start + i);
            }
		}
	}
	return NULL;
}
PVOID GetSyscallGadget(PVOID pModuleBase) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
	PBYTE start = (PBYTE)pModuleBase + pNt->OptionalHeader.BaseOfCode;
	DWORD size = pNt->OptionalHeader.SizeOfCode;
	for (DWORD i = 0; i < size; i++) {
		if (start[i] == 0x0F && start[i + 1] == 0x05 && start[i + 2] == 0xC3) {
			return (PVOID)(start + i);
        }
	}
	return NULL;
}
//查找 Jmp [RBX]
PVOID FindJmpRbxGadget(PVOID moduleBase,DWORD *size) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    DWORD64 txtStart = (DWORD64)moduleBase + pSection->VirtualAddress;
    DWORD64 txtSize = pSection->Misc.VirtualSize;
    
    for (DWORD64 ptr = txtStart; ptr < txtStart + txtSize; ptr++) {
        // FF 23 (jmp [rbx])
        if (*(BYTE*)ptr == 0xFF && *(BYTE*)(ptr+1) == 0x23) {
            if (!IsCallPreceding((PBYTE)ptr, (PBYTE)txtStart, (PBYTE)(txtStart + txtSize))) {
            }
            DWORD stacksize = CalculateFunctionStackSize((PVOID)ptr, moduleBase);
			*size = (DWORD)stacksize;
            return (PVOID)ptr;
        }
    }
    return NULL;
}
