#ifndef DEFINITIONS_HEADER
#define DEFINITIONS_HEADER

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <wdm.h>
#pragma comment(lib, "ntoskrnl.lib")

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS,
* PSYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION,
* PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES,
* PRTL_PROCESS_MODULES;

extern "C" __declspec(dllimport)
NTSTATUS NTAPI ZwProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	PULONG ProtectSize,
	ULONG NewProtect,
	PULONG OldProtect
);

extern "C" NTKERNELAPI
PVOID NTAPI RtlFindExportedRoutineByName(
	_In_ PVOID ImageBase,
	_In_ PCCH RoutineName
);

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturningLength);

extern "C" NTKERNELAPI
PPEB PsGetProcessPeb(IN PEPROCESS Process);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

//

typedef struct _COMMUNICATIONPACKET
{
	ULONG64 MagicNumber;
	int instructionCode;
	bool targetChange;
	int pID;
	ULONG returnStatus;
	ULONG size;
	ULONG64 targetAddress;
	ULONG64 bufferAddress;
	const char* moduleName;
	ULONG64 baseAddress;
	void* output;
}COMMUNICATIONPACKET, * PCOMMUNICATIONPACKET;

typedef enum _INSTRUCTIONCODE {
	BASEADDRREQUEST,
	DLLBASEREQUEST,
	READREQUEST,
	WRITEREQUEST,
	TARGETCHANGE
}INSTRUCTIONCODE, * PINSTRUCTIONCODE;

//

extern "C" NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);


extern "C" NTKERNELAPI PVOID PsGetProcessWow64Process(__in PEPROCESS Process);

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(IN PEPROCESS Process);
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage; // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags; // LDR_*
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	// PVOID LoadedImports;
	// // seems they are exist only on XP !!! PVOID
	// EntryPointActivationContext; // -same-
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

#endif

//GAME RELATED

typedef struct _TEAM_CHARACTER {
	BYTE id; //0-46
	BYTE color;
	BYTE costume; //0-4
	BYTE assist; //0-2
} TEAM_CHARACTER, * PTEAM_CHARACTER;

typedef struct _RAID_PARTY_CHARACTER {
	BYTE id; //0-46
	BYTE color;
	BYTE stage;
	BYTE music;
	BYTE costume; //0-4
	BYTE assist; //0-2
} RAID_PARTY_CHARACTER, * PRAID_PARTY_CHARACTER;
