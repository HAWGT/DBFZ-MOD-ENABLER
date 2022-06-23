#include <iostream>
#include "Process.h"
#include <TlHelp32.h>
#include <memory>
#include <vector>
#include "Definitions.h"

typedef UINT64(__fastcall* FunctionTemplate)(char* a1, unsigned int a2, unsigned int a3, __int64* a4, unsigned __int64 a5);
FunctionTemplate Function;

uint64_t CallHook(PCOMMUNICATIONPACKET packet, unsigned int a2, unsigned int a3, __int64* a4, unsigned __int64 a5)
{
	LoadLibrary("user32.dll");
	void* hookedFunction = GetProcAddress(LoadLibrary("win32u.dll"), "NtTokenManagerCreateCompositionTokenHandle");

	auto function = reinterpret_cast<uint64_t(_stdcall*)(PCOMMUNICATIONPACKET, unsigned int, unsigned int, __int64*, unsigned __int64)>(hookedFunction);

	return function(packet, a2, a3, a4, a5);
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
	CallHook(&packet, 1337, 1337, (__int64*)1337, 1337);

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

	CallHook(&packet, 1337, 1337, (__int64*)1337, 1337);

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
	CallHook(&packet, 1337, 1337, (__int64*)1337, 1337);
}

template<typename S>
void Write(uint32_t pID, UINT_PTR writeAddress, const S& value)
{
	WriteMemory(pID, writeAddress, (UINT_PTR)&value, sizeof(S));
}