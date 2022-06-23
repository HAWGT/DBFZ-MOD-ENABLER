#include "Memory.h"
#include <cstdint>

//PEB - PROCESS ENVIRONMENT BLOCK
//MDL - MEMORY DESCRIPTOR LIST

PVOID GetSystemModuleBase(const char* moduleName)
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes) return NULL;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x48574754);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) return NULL;

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	PVOID moduleBase = 0, moduleSize = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (strcmp((char*)module[i].FullPathName, moduleName) == 0)
		{
			moduleBase = module[i].ImageBase;
			moduleSize = (PVOID)module[i].ImageSize;
			break;
		}
	}

	if (modules) ExFreePoolWithTag(modules, NULL);

	if (moduleBase <= 0) return NULL;

	return moduleBase;
}

PVOID GetSystemModuleExport(const char* moduleName, LPCTSTR routineName)
{
	PVOID lpModule = GetSystemModuleBase(moduleName);

	if (!lpModule) return NULL;

	return RtlFindExportedRoutineByName(lpModule, routineName);
}

bool WriteMemory(void* address, void* buffer, size_t size)
{
	return RtlCopyMemory(address, buffer, size);
}

bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size)
{
	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl) return false;

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	WriteMemory(Mapping, buffer, size);

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

//https://www.unknowncheats.me/forum/anti-cheat-bypass/444289-read-process-physical-memory-attach.html

PVOID GetProcessBaseAddress(int pID)
{
	PEPROCESS pProcess = NULL;
	if (pID == 0) return (PVOID)STATUS_UNSUCCESSFUL;
	//if (pID == 0) return NULL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pID, &pProcess);
	if (NtRet != STATUS_SUCCESS) return (PVOID)NtRet;
	//if (NtRet != STATUS_SUCCESS) return NULL;

	PVOID Base = PsGetProcessSectionBaseAddress(pProcess);
	ObDereferenceObject(pProcess);
	return Base;
}

//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

DWORD GetUserDirectoryTableBaseOffset()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);

	switch (ver.dwBuildNumber)
	{
	case WINDOWS_1803:
		return 0x0278;
		break;
	case WINDOWS_1809:
		return 0x0278;
		break;
	case WINDOWS_1903:
		return 0x0280;
		break;
	case WINDOWS_1909:
		return 0x0280;
		break;
	case WINDOWS_2004:
		return 0x0388;
		break;
	case WINDOWS_20H2:
		return 0x0388;
		break;
	case WINDOWS_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

//check normal dirbase if 0 then get from UserDirectoryTableBas
ULONG_PTR GetProcessCr3(PEPROCESS pProcess)
{
	PUCHAR process = (PUCHAR)pProcess;
	ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	if (process_dirbase == 0)
	{
		DWORD UserDirOffset = GetUserDirectoryTableBaseOffset();
		ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
		return process_userdirbase;
	}
	return process_dirbase;
}
ULONG_PTR GetKernelDirBase()
{
	PUCHAR process = (PUCHAR)PsGetCurrentProcess();
	ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	return cr3;
}

NTSTATUS ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read)
{
	uint64_t pAddress = TranslateLinearAddress(dirbase, address);
	return ReadPhysicalAddress(pAddress, buffer, size, read);
}

NTSTATUS WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written)
{
	uint64_t pAddress = TranslateLinearAddress(dirbase, address);
	return WritePhysicalAddress(pAddress, buffer, size, written);
}

NTSTATUS ReadPhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS AddrToRead = { 0 };
	AddrToRead.PhysicalAddress.QuadPart = TargetAddress;
	return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS WritePhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	if (!TargetAddress)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = TargetAddress;

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(pmapped_mem, lpBuffer, Size);

	*BytesWritten = Size;
	MmUnmapIoSpace(pmapped_mem, Size);
	return STATUS_SUCCESS;
}

#define PAGE_OFFSET_SIZE 12
static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress) {
	directoryTableBase &= ~0xf;

	uint64_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	uint64_t pte = ((virtualAddress >> 12) & (0x1ffll));
	uint64_t pt = ((virtualAddress >> 21) & (0x1ffll));
	uint64_t pd = ((virtualAddress >> 30) & (0x1ffll));
	uint64_t pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	uint64_t pdpe = 0;
	ReadPhysicalAddress(directoryTableBase + 8 * pdp, &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	uint64_t pde = 0;
	ReadPhysicalAddress((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	uint64_t pteAddr = 0;
	ReadPhysicalAddress((pde & PMASK) + 8 * pt, &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	ReadPhysicalAddress((pteAddr & PMASK) + 8 * pte, &virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}


//
NTSTATUS ReadProcessMemory(int pID, ULONG64 Address, ULONG64 AllocatedBuffer, SIZE_T size, SIZE_T* read)
{
	PEPROCESS pProcess = NULL;
	if (pID == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pID, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{

		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesRead = 0;
		NtRet = ReadPhysicalAddress(CurPhysAddr, (PVOID)(AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
		TotalSize -= BytesRead;
		CurOffset += BytesRead;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesRead == 0) break;
	}

	if (read != NULL) *read = CurOffset;
	return NtRet;
}

NTSTATUS WriteProcessMemory(int pID, ULONG64 Address, ULONG64 AllocatedBuffer, SIZE_T size, SIZE_T* written)
{
	PEPROCESS pProcess = NULL;
	if (pID == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pID, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);


	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{
		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, Address + CurOffset);

		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesWritten = 0;
		NtRet = WritePhysicalAddress(CurPhysAddr, (PVOID)(AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);

		TotalSize -= BytesWritten;
		CurOffset += BytesWritten;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesWritten == 0) break;
	}

	if (written != NULL) *written = CurOffset;

	return NtRet;
}

//
bool Is64Bit(int pid)
{
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);
	PVOID wow64 = PsGetProcessWow64Process(process);
	BOOLEAN iswow64 = (wow64 != NULL) ? TRUE : FALSE;
	ObDereferenceObject(process);
	return iswow64;
}

PVOID GetProcessPeb(HANDLE pid)
{
	if (!pid)
		return 0;

	PVOID peb_address = 0;
	PEPROCESS process;
	PsLookupProcessByProcessId(pid, &process);

	if (!process)
	{
		return 0;
	}

	PVOID wow64 = PsGetProcessWow64Process(process);
	BOOLEAN iswow64 = (wow64 != NULL) ? TRUE : FALSE;

	if (iswow64)
	{
		peb_address = wow64;
	}
	else
	{
		PPEB peb = PsGetProcessPeb(process);
		if (peb != nullptr)
			peb_address = (PVOID)peb;
	}

	ObfDereferenceObject(process);

	return peb_address;
}

PVOID GetModuleBase(int pID, UNICODE_STRING name)
{

	PEPROCESS pProcess;
	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pID, &pProcess);

	PVOID peb_address = GetProcessPeb((HANDLE)pID);

	if (!peb_address)
	{
		return 0;
	}

	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pID, &process);
	PVOID wow64 = PsGetProcessWow64Process(process);
	BOOLEAN iswow64 = (wow64 != NULL) ? TRUE : FALSE;
	ObDereferenceObject(process);

	if (iswow64)
	{
		PEB32 peb_process = { 0 };
		ReadProcessMemory(pID, (ULONG64)peb_address, (ULONG64)&peb_process, sizeof(PEB32), NULL);


		PEB_LDR_DATA32 peb_ldr_data = { 0 };

		ReadProcessMemory(pID, (ULONG64)peb_process.Ldr, (ULONG64)&peb_ldr_data, sizeof(PEB_LDR_DATA32), NULL);

		LIST_ENTRY32* ldr_list_head = (LIST_ENTRY32*)peb_ldr_data.InLoadOrderModuleList.Flink;
		LIST_ENTRY32* ldr_current_node = (LIST_ENTRY32*)peb_ldr_data.InLoadOrderModuleList.Flink;

		do
		{
			LDR_DATA_TABLE_ENTRY32 lst_entry = { 0 };
			ReadProcessMemory(pID, (ULONG64)ldr_current_node, (ULONG64)&lst_entry, sizeof(LDR_DATA_TABLE_ENTRY32), NULL);


			ldr_current_node = (LIST_ENTRY32*)lst_entry.InLoadOrderLinks.Flink;
			if (lst_entry.BaseDllName.Length > 0)
			{
				UNICODE_STRING DLLname;
				DLLname.Length = lst_entry.BaseDllName.Length;
				DLLname.MaximumLength = lst_entry.BaseDllName.MaximumLength;
				WCHAR basedllNameBuff[MAX_PATH] = { 0 };
				ReadProcessMemory(pID, lst_entry.BaseDllName.Buffer, (ULONG64)&basedllNameBuff, lst_entry.BaseDllName.Length, NULL);
				DLLname.Buffer = (PWCH)&basedllNameBuff;
				if (RtlCompareUnicodeString(&DLLname, &name, false) == 0)
				{
					return (PVOID)lst_entry.DllBase;
				}
			}

		} while (ldr_list_head != ldr_current_node);
	}
	else
	{
		PEB peb_process = { 0 };
		ReadProcessMemory(pID, (ULONG64)peb_address, (ULONG64)&peb_process, sizeof(PEB), NULL);


		PEB_LDR_DATA peb_ldr_data = { 0 };
		ReadProcessMemory(pID, (ULONG64)peb_process.Ldr, (ULONG64)&peb_ldr_data, sizeof(PEB_LDR_DATA), NULL);

		LIST_ENTRY* ldr_list_head = (LIST_ENTRY*)peb_ldr_data.ModuleListLoadOrder.Flink;
		LIST_ENTRY* ldr_current_node = (LIST_ENTRY*)peb_ldr_data.ModuleListLoadOrder.Flink;

		do
		{
			LDR_DATA_TABLE_ENTRY lst_entry = { 0 };
			ReadProcessMemory(pID, (ULONG64)ldr_current_node, (ULONG64)&lst_entry, sizeof(LDR_DATA_TABLE_ENTRY), NULL);


			ldr_current_node = (LIST_ENTRY*)lst_entry.InLoadOrderModuleList.Flink;
			if (lst_entry.BaseDllName.Length > 0)
			{

				WCHAR basedllNameBuff[MAX_PATH] = { 0 };
				ReadProcessMemory(pID, (ULONG64)lst_entry.BaseDllName.Buffer, (ULONG64)&basedllNameBuff, lst_entry.BaseDllName.Length, NULL);
				lst_entry.BaseDllName.Buffer = (PWCH)&basedllNameBuff;
				if (RtlCompareUnicodeString(&lst_entry.BaseDllName, &name, false) == 0)
				{
					return lst_entry.DllBase;
				}
			}

		} while (ldr_list_head != ldr_current_node);
	}
	return 0;
}


ULONG64 GetModuleBaseX64(PEPROCESS proc, UNICODE_STRING moduleName)
{
	PPEB pPeb = PsGetProcessPeb(proc);

	if (!pPeb) return NULL;

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr) {
		KeUnstackDetachProcess(&state);
		return NULL;
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink; list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &moduleName, TRUE) == NULL)
		{
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);

	return NULL;
}


//? or % without datatype
void DebugMessage(PCCH format, ...)
{
	CHAR message[512];
	va_list _valist;
	va_start(_valist, format);
	const ULONG N = _vsnprintf_s(message, sizeof(message) - 1, format, _valist);
	message[N] = L'\0';

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, message, _valist);

	va_end(_valist);
}


void Sleep(int ms)
{
	LARGE_INTEGER time;
	time.QuadPart = -(ms) * 10 * 1000;
	KeDelayExecutionThread(KernelMode, TRUE, &time);
}