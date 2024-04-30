/* Copyright (c) 2001  Microsoft Corporation
Abstract:
    Declarations of PEB and TEB, and some types contained in them.
    Address the maintenance problem that resulted from PEB and TEB being
    defined three times, once "native" in ntpsapi.w, and twice, 32bit and 64bit
    in wow64t.w.

Author:
    Jay Krell (JayKrell) April 2001
*/
#include <windows.h>

//typedef struct _LIST_ENTRY {
//	struct _LIST_ENTRY *Flink;
//	struct _LIST_ENTRY *Blink;
//} LIST_ENTRY, *PLIST_ENTRY, *PRLIST_ENTRY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

//typedef struct _RTL_CRITICAL_SECTION_DEBUG {
//	WORD Type;
//	WORD CreatorBackTraceIndex;
//	struct _RTL_CRITICAL_SECTION *CriticalSection;
//	LIST_ENTRY ProcessLocksList;
//	DWORD EntryCount;
//	DWORD ContentionCount;
//	DWORD Flags;
//	WORD CreatorBackTraceIndexHigh;
//	WORD SpareWORD;
//} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, *PRTL_RESOURCE_DEBUG;

//typedef struct _RTL_CRITICAL_SECTION {
//	PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
//
//	//
//	//  The following three fields control entering and exiting the critical
//	//  section for the resource
//	//
//
//	LONG LockCount;
//	LONG RecursionCount;
//	HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
//	HANDLE LockSemaphore;
//	ULONG_PTR SpinCount;        // force size on 64-bit systems when packed
//} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

//
// Handle tag bits for Peb Stdio File Handles
//
#define PEB_STDIO_HANDLE_NATIVE     0
#define PEB_STDIO_HANDLE_SUBSYS     1
#define PEB_STDIO_HANDLE_PM         2
#define PEB_STDIO_HANDLE_RESERVED   3
#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60
#if !defined(_IA64_) && !defined(_AMD64_)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif
typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _PEB_FREE_BLOCK {
	struct _PEB_FREE_BLOCK *Next;
	ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef VOID (*PPS_POST_PROCESS_INIT_ROUTINE)(VOID);
typedef PVOID *PPVOID;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
    BOOLEAN ReadImageFileExecOptions;   //
    BOOLEAN BeingDebugged;              //
    BOOLEAN SpareBool;                  //
    HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    struct _RTL_CRITICAL_SECTION* FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    ULONG SystemReserved[1];

    struct {
        ULONG ExecuteOptions : 2;
        ULONG SpareBits : 30;
    };    

    PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];         // TLS_MINIMUM_AVAILABLE bits
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PPVOID ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    //
    // Useful information for LdrpInitialize
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    //
    // Passed up from MmCreatePeb from Session Manager registry key
    //

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    //
    // Where heap manager keeps track of all heaps created for a process
    // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
    // to point to the first free byte after the PEB and MaximumNumberOfHeaps
    // is computed from the page size used to hold the PEB, less the fixed
    // size of this data structure.
    //

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PPVOID ProcessHeaps;

    //
    //
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PVOID LoaderLock;

    //
    // Following fields filled in by MmCreatePeb from system values and/or
    // image header.
    //

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];   // TLS_EXPANSION_SLOTS bits

    //
    // Id of the Hydra session in which this process is running
    //
    ULONG SessionId;

    //
    // Filled in by LdrpInstallAppcompatBackend
    //
    ULARGE_INTEGER AppCompatFlags;

    //
    // ntuser appcompat flags
    //
    ULARGE_INTEGER AppCompatFlagsUser;

    //
    // Filled in by LdrpInstallAppcompatBackend
    //
    PVOID pShimData;

    //
    // Filled in by LdrQueryImageFileExecutionOptions
    //
    PVOID AppCompatInfo;

    //
    // Used by GetVersionExW as the szCSDVersion string
    //
    UNICODE_STRING CSDVersion;

    //
    // Fusion stuff
    //
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    
    //
    // Enforced minimum initial commit stack
    //
    SIZE_T MinimumStackCommit;

} PEB, *PPEB;

//
//  Fusion/sxs thread state information
//

#define ACTIVATION_CONTEXT_STACK_FLAG_QUERIES_DISABLED (0x00000001)

typedef struct _ACTIVATION_CONTEXT_STACK {
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    PVOID ActiveFrame;
    LIST_ENTRY FrameListCache;

#if NT_SXS_PERF_COUNTERS_ENABLED
    struct _ACTIVATION_CONTEXT_STACK_PERF_COUNTERS {
        ULONGLONG Activations;
        ULONGLONG ActivationCycles;
        ULONGLONG Deactivations;
        ULONGLONG DeactivationCycles;
    } Counters;
#endif // NT_SXS_PERF_COUNTERS_ENABLED
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef const ACTIVATION_CONTEXT_STACK *PCACTIVATION_CONTEXT_STACK;

#define TEB_ACTIVE_FRAME_CONTEXT_FLAG_EXTENDED (0x00000001)

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef const struct _TEB_ACTIVE_FRAME_CONTEXT *PCTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT_EX {
    TEB_ACTIVE_FRAME_CONTEXT BasicContext;
    PCSTR SourceLocation; // e.g. "Z:\foo\bar\baz.c"
} TEB_ACTIVE_FRAME_CONTEXT_EX, *PTEB_ACTIVE_FRAME_CONTEXT_EX;

typedef const struct _TEB_ACTIVE_FRAME_CONTEXT_EX *PCTEB_ACTIVE_FRAME_CONTEXT_EX;

#define TEB_ACTIVE_FRAME_FLAG_EXTENDED (0x00000001)

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PCTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef const struct _TEB_ACTIVE_FRAME *PCTEB_ACTIVE_FRAME;

typedef struct _TEB_ACTIVE_FRAME_EX {
    TEB_ACTIVE_FRAME BasicFrame;
    PVOID ExtensionIdentifier; // use address of your DLL Main or something unique to your mapping in the address space
} TEB_ACTIVE_FRAME_EX, *PTEB_ACTIVE_FRAME_EX;

typedef const struct _TEB_ACTIVE_FRAME_EX *PCTEB_ACTIVE_FRAME_EX;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

//
// Gdi command batching
//
#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH {
	ULONG    Offset;
	ULONG_PTR HDC;
	ULONG    Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

//
// Wx86 thread state information
//
typedef struct _Wx86ThreadState {
	PULONG  CallBx86Eip;
	PVOID   DeallocationCpu;
	BOOLEAN UseKnownWx86Dll;
	char    OleStubInvoked;
} WX86THREAD, *PWX86THREAD;

//http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FLDR_MODULE.html
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
} LDR_MODULE, *PLDR_MODULE;

//
//  TEB - The thread environment block
//
#define STATIC_UNICODE_BUFFER_LENGTH 261
#define WIN32_CLIENT_INFO_LENGTH 62
#define WIN32_CLIENT_INFO_SPIN_COUNT 1
typedef struct _TEB {
    NT_TIB NtTib;
    PVOID  EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
#if defined(PEBTEB_BITS)
    PVOID ProcessEnvironmentBlock;
#else
    PPEB ProcessEnvironmentBlock;
#endif
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;          // PtiCurrent
    ULONG User32Reserved[26];       // user32.dll items
    ULONG UserReserved[5];          // Winsrv SwitchStack
    PVOID WOW32Reserved;            // used by WOW
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister; // offset known by outsiders!
    PVOID SystemReserved1[54];      // Used by FP emulator
    NTSTATUS ExceptionCode;         // for RaiseUserException
    ACTIVATION_CONTEXT_STACK ActivationContextStack;   // Fusion activation stack
    // sizeof(PVOID) is a way to express processor-dependence, more generally than #ifdef _WIN64
    UCHAR SpareBytes1[48 - sizeof(PVOID) - sizeof(ACTIVATION_CONTEXT_STACK)];
    GDI_TEB_BATCH GdiTebBatch;      // Gdi batching
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH]; // User32 Client Info
    PVOID glDispatchTable[233];     // OpenGL
    ULONG_PTR glReserved1[29];      // OpenGL
    PVOID glReserved2;              // OpenGL
    PVOID glSectionInfo;            // OpenGL
    PVOID glSection;                // OpenGL
    PVOID glTable;                  // OpenGL
    PVOID glCurrentRC;              // OpenGL
    PVOID glContext;                // OpenGL
    ULONG LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];
    PVOID DeallocationStack;
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];
    ULONG HardErrorsAreDisabled;
    PVOID Instrumentation[16];
    PVOID WinSockData;              // WinSock
    ULONG GdiBatchCount;
    BOOLEAN InDbgPrint;
    BOOLEAN FreeStackOnTermination;
    BOOLEAN HasFiberData;
    BOOLEAN IdealProcessor;
    ULONG Spare3;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    WX86THREAD Wx86Thread;
    PPVOID TlsExpansionSlots;
#if (defined(_IA64_) && !defined(PEBTEB_BITS)) \
    || ((defined(_IA64_) || defined(_X86_)) && defined(PEBTEB_BITS) && PEBTEB_BITS == 64)
    //
    // These are in the native ia64 TEB, and the TEB64 for ia64 and x86.
    //
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    LCID ImpersonationLocale;       // Current locale of impersonated user
    ULONG IsImpersonating;          // Thread impersonation status
    PVOID NlsCache;                 // NLS thread cache
    PVOID pShimData;                // Per thread data used in the shim
    ULONG HeapVirtualAffinity;
    HANDLE CurrentTransactionHandle;// reserved for TxF transaction context
    PTEB_ACTIVE_FRAME ActiveFrame;
} TEB;
typedef TEB *PTEB;