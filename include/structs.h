#pragma once
#include <Windows.h>

typedef unsigned char UBYTE;
typedef struct _PEB PEB, * PPEB;
typedef struct _TEB TEB, * PTEB;
typedef struct _LDR_DATA_TABLE_ENTRY LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef enum _UNWIND_REGISTER_CODES {
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RBX = 3,
    RSP = 4,
    RBP = 5,
    RSI = 6,
    RDI = 7,
    R8  = 8,
    R9  = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15
} UNWIND_REGISTER_CODES;

/*--------------------------------------------------------------------
  UNWIND STRUCTURES (Ported for C)
--------------------------------------------------------------------*/
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_BIG,
    UWOP_EPILOG,
    UWOP_SPARE_CODE,
    UWOP_SAVE_XMM128,
    UWOP_SAVE_XMM128BIG,
    UWOP_PUSH_MACH_FRAME
} UNWIND_OP_CODES;

typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    UBYTE Version : 3;
    UBYTE Flags : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;

/*--------------------------------------------------------------------
  SPOOFER CONFIGURATION
--------------------------------------------------------------------*/
typedef struct _SPOOFER {
    PVOID FirstFrameFunctionPointer;      // +0x00
    PVOID SecondFrameFunctionPointer;     // +0x08
    PVOID JmpRbxGadget;                   // +0x10
    PVOID AddRspXGadget;                  // +0x18

    DWORD64 FirstFrameSize;               // +0x20
    DWORD64 FirstFrameRandomOffset;       // +0x28
    DWORD64 SecondFrameSize;              // +0x30
    DWORD64 SecondFrameRandomOffset;      // +0x38
    DWORD64 JmpRbxGadgetFrameSize;        // +0x40
    DWORD64 AddRspXGadgetFrameSize;       // +0x48

    DWORD64 StackOffsetWhereRbpIsPushed;  // +0x50
    PVOID JmpRbxGadgetRef;                // +0x58
    PVOID SpoofFunctionPointer;           // +0x60
    PVOID ReturnAddress;                  // +0x68

    DWORD64 Nargs;                        // +0x70
    PVOID Arg01;                          // +0x78
    PVOID Arg02;                          // +0x80
    PVOID Arg03;                          // +0x88
    PVOID Arg04;                          // +0x90
    PVOID Arg05;                          // +0x98
    PVOID Arg06;                          // +0xA0
    PVOID Arg07;                          // +0xA8
    PVOID Arg08;                          // +0xB0
    PVOID Arg09;                          // +0xB8
    PVOID Arg10;                          // +0xC0
    PVOID Arg11;                          // +0xC8
    PVOID Arg12;                          // +0xD0
} SPOOFER, * PSPOOFER;

/*--------------------------------------------------------------------
  EXISTING STRUCTURES
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
	PVOID   pSyscallInst;
	PVOID   pGadget_Clean;   // add rsp, X ; ret
	PVOID   pGadget_Thunk;   // jmp [rbx] gadget used to pivot back
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
	VX_TABLE_ENTRY NtOpenFile;
    VX_TABLE_ENTRY NtCreateSection;
    VX_TABLE_ENTRY NtMapViewOfSection;
    VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtOpenSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtQueryVirtualMemory;
} VX_TABLE, * PVX_TABLE;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

typedef struct __CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TEB {
	NT_TIB				NtTib;
	PVOID				EnvironmentPointer;
	CLIENT_ID			ClientId;
	PVOID				ActiveRpcHandle;
	PVOID				ThreadLocalStoragePointer;
	PPEB				ProcessEnvironmentBlock;
	ULONG               LastErrorValue;
	ULONG               CountOfOwnedCriticalSections;
	PVOID				CsrClientThread;
	PVOID				Win32ThreadInfo;
	ULONG               User32Reserved[26];
	ULONG               UserReserved[5];
	PVOID				WOW32Reserved;
	LCID                CurrentLocale;
	ULONG               FpSoftwareStatusRegister;
	PVOID				SystemReserved1[54];
	LONG                ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
	ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
	ACTIVATION_CONTEXT_STACK ActivationContextStack;
	UCHAR                  SpareBytes1[24];
#endif
	GDI_TEB_BATCH			GdiTebBatch;
	CLIENT_ID				RealClientId;
	PVOID					GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID					GdiThreadLocalInfo;
	PSIZE_T					Win32ClientInfo[62];
	PVOID					glDispatchTable[233];
	PSIZE_T					glReserved1[29];
	PVOID					glReserved2;
	PVOID					glSectionInfo;
	PVOID					glSection;
	PVOID					glTable;
	PVOID					glCurrentRC;
	PVOID					glContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING			StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[261];
	PVOID					DeallocationStack;
	PVOID					TlsSlots[64];
	LIST_ENTRY				TlsLinks;
	PVOID					Vdm;
	PVOID					ReservedForNtRpc;
	PVOID					DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                   HardErrorMode;
#else
	ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID					Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
	GUID                    ActivityId;
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
	PVOID					EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PVOID					Instrumentation[14];
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
#else
	PVOID					Instrumentation[16];
#endif
	PVOID					WinSockData;
	ULONG					GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	BOOLEAN                SpareBool0;
	BOOLEAN                SpareBool1;
	BOOLEAN                SpareBool2;
#else
	BOOLEAN                InDbgPrint;
	BOOLEAN                FreeStackOnTermination;
	BOOLEAN                HasFiberData;
#endif
	UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                  GuaranteedStackBytes;
#else
	ULONG                  Spare3;
#endif
	PVOID				   ReservedForPerf;
	PVOID				   ReservedForOle;
	ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID				   SavedPriorityState;
	ULONG_PTR			   SoftPatchPtr1;
	ULONG_PTR			   ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	ULONG_PTR			   SparePointer1;
	ULONG_PTR              SoftPatchPtr1;
	ULONG_PTR              SoftPatchPtr2;
#else
	Wx86ThreadState        Wx86Thread;
#endif
	PVOID* TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
	PVOID                  DeallocationBStore;
	PVOID                  BStoreLimit;
#endif
	ULONG                  ImpersonationLocale;
	ULONG                  IsImpersonating;
	PVOID                  NlsCache;
	PVOID                  pShimData;
	ULONG                  HeapVirtualAffinity;
	HANDLE                 CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME      ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
	PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID PreferredLangauges;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		struct
		{
			USHORT SpareCrossTebFlags : 16;
		};
		USHORT CrossTebFlags;
	};
	union
	{
		struct
		{
			USHORT DbgSafeThunkCall : 1;
			USHORT DbgInDebugPrint : 1;
			USHORT DbgHasFiberData : 1;
			USHORT DbgSkipThreadAttach : 1;
			USHORT DbgWerInShipAssertCode : 1;
			USHORT DbgIssuedInitialBp : 1;
			USHORT DbgClonedThread : 1;
			USHORT SpareSameTebBits : 9;
		};
		USHORT SameTebFlags;
	};
	PVOID TxnScopeEntercallback;
	PVOID TxnScopeExitCAllback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	ULONG64 LastSwitchTime;
	ULONG64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
#else
	BOOLEAN SafeThunkCall;
	BOOLEAN BooleanSpare[3];
#endif
} TEB, * PTEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _INITIAL_TEB {
	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;

/*--------------------------------------------------------------------
  SysWhispers3 definitions
--------------------------------------------------------------------*/
#define SW3_SEED 0x769430A3
#define SW3_ROL8(v) (v << 8 | v >> 24)
#define SW3_ROR8(v) (v >> 8 | v << 24)
#define SW3_ROX8(v) ((SW3_SEED % 2) ? SW3_ROL8(v) : SW3_ROR8(v))
#define SW3_MAX_ENTRIES 500
#define SW3_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) (DllBase) + (Rva))

typedef struct _SW3_SYSCALL_ENTRY {
	DWORD Hash;
	DWORD Address;
	PVOID SyscallAddress;
} SW3_SYSCALL_ENTRY, * PSW3_SYSCALL_ENTRY;

typedef struct _SW3_SYSCALL_LIST {
	DWORD Count;
	SW3_SYSCALL_ENTRY Entries[SW3_MAX_ENTRIES];
} SW3_SYSCALL_LIST, * PSW3_SYSCALL_LIST;

DWORD SW3_HashSyscall(PCSTR FunctionName);
BOOL SW3_PopulateSyscallList(PVOID ntdllBase);
DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash);

/*--------------------------------------------------------------------
  payloads definitions
--------------------------------------------------------------------*/
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef FILE_READ_DATA
#define FILE_READ_DATA            0x00000001
#endif

#ifndef FILE_EXECUTE
#define FILE_EXECUTE              0x00000020
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ           0x00000001
#endif

#ifndef SEC_IMAGE
#define SEC_IMAGE                 0x1000000
#endif

#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS        0xF001F // STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE
#endif

#ifndef SYNCHRONIZE
#define SYNCHRONIZE               0x00100000L
#endif

// 定义 IO_STATUS_BLOCK
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif


typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation,
    MemoryWorkingSetExInformation 
} MEMORY_INFORMATION_CLASS;
typedef struct _MEMORY_WORKING_SET_EX_BLOCK {
    union {
        struct {
            ULONG_PTR Valid : 1;
            ULONG_PTR ShareCount : 3;
            ULONG_PTR Win32Protection : 11;
            ULONG_PTR Shared : 1;  
            ULONG_PTR Node : 6;
            ULONG_PTR Locked : 1;
            ULONG_PTR LargePage : 1;
            ULONG_PTR Priority : 3;
            ULONG_PTR Reserved : 3;
            ULONG_PTR SharedOriginal : 1;
            ULONG_PTR Protection : 5;
        };
        ULONG_PTR Flags;
    };
} MEMORY_WORKING_SET_EX_BLOCK, *PMEMORY_WORKING_SET_EX_BLOCK;

typedef struct _MEMORY_WORKING_SET_EX_INFORMATION {
    PVOID VirtualAddress;
    MEMORY_WORKING_SET_EX_BLOCK VirtualAttributes;
} MEMORY_WORKING_SET_EX_INFORMATION, *PMEMORY_WORKING_SET_EX_INFORMATION;