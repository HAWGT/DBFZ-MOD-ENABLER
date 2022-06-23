#ifndef MEMORY_HEADER
#define MEMORY_HEADER

#include "Definitions.h"
#include <cstdint>

PVOID GetSystemModuleBase(const char* moduleName);
PVOID GetSystemModuleExport(const char* moduleName, LPCTSTR routineName);
bool WriteMemory(void* address, void* buffer, size_t size);
bool WriteToReadOnlyMemory(void* address, void* buffer, size_t size);

PVOID GetProcessBaseAddress(int pID);
NTSTATUS ReadProcessMemory(int pID, ULONG64 Address, ULONG64 AllocatedBuffer, SIZE_T size, SIZE_T* read);
NTSTATUS WriteProcessMemory(int pID, ULONG64 Address, ULONG64 AllocatedBuffer, SIZE_T size, SIZE_T* written);

PVOID GetModuleBase(int pID, UNICODE_STRING name);

uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress);
NTSTATUS ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read);
NTSTATUS WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written);
NTSTATUS ReadPhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
NTSTATUS WritePhysicalAddress(ULONG64 TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);

void Sleep(int ms);
void DebugMessage(PCCH format, ...);

#endif