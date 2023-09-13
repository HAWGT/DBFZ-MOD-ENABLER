#include <iostream>
#include "Process.h"
#include <TlHelp32.h>
#include <memory>
#include <vector>
#include "Definitions.h"

typedef UINT64(__fastcall* FunctionTemplate)(PCOMMUNICATIONPACKET packet);
FunctionTemplate Function;
FunctionTemplate hookedFunction;


HMODULE win32Module;

void Init()
{

	if (LoadLibrary("user32.dll") && LoadLibrary("win32u.dll"))
	{
		win32Module = GetModuleHandleA("win32u.dll");
	}
	if (win32Module != NULL)
	{
		hookedFunction = (FunctionTemplate)GetProcAddress(win32Module, "");
	}

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}

inline void CallHook(PCOMMUNICATIONPACKET packet)
{
	if (hookedFunction != NULL)
	{
		packet->MagicNumber = 0xDEFACE;
		hookedFunction(packet);
	}
}


using uniqueHandle = std::unique_ptr<HANDLE, HandleDisposer>;

uint32_t GetProcessID(std::string_view processName)
{
	PROCESSENTRY32 processEntry;
	const uniqueHandle snapshotHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

	if (snapshotHandle.get() == INVALID_HANDLE_VALUE)
		return NULL;

	processEntry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshotHandle.get(), &processEntry))
	{
		if (processName.compare(processEntry.szExeFile) == NULL)
		{
			return processEntry.th32ProcessID;
		}
	}

	return NULL;
}

ULONG64 GetModuleBaseAddress(uint32_t pID)
{
	COMMUNICATIONPACKET packet = { 0 };
	packet.pID = pID;
	packet.instructionCode = BASEADDRREQUEST;
	CallHook(&packet);

	ULONG64 base = NULL;
	base = packet.baseAddress;

	return base;
}

ULONG64 ReadULONG64(uint32_t pID, UINT_PTR readAddress)
{
	ULONG64 response;
	COMMUNICATIONPACKET packet;
	packet.targetAddress = readAddress;
	packet.pID = pID;
	packet.instructionCode = READREQUEST;
	packet.bufferAddress = (UINT_PTR)(&response);
	packet.size = sizeof(ULONG64);

	CallHook(&packet);

	return response;
}

BYTE ReadBYTE(uint32_t pID, UINT_PTR readAddress)
{
	BYTE response;
	COMMUNICATIONPACKET packet;
	packet.targetAddress = readAddress;
	packet.pID = pID;
	packet.instructionCode = READREQUEST;
	packet.bufferAddress = (UINT_PTR)(&response);
	packet.size = sizeof(BYTE);

	CallHook(&packet);

	return response;
}

void WriteMemory(uint32_t pID, UINT_PTR writeAddress, UINT_PTR sourceAddress, SIZE_T writeSize)
{
	COMMUNICATIONPACKET packet;
	packet.targetAddress = writeAddress;
	packet.pID = pID;
	packet.instructionCode = WRITEREQUEST;
	packet.bufferAddress = sourceAddress;
	packet.size = writeSize;
	CallHook(&packet);
}
