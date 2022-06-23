#include <string_view>
#include "Definitions.h"

uint32_t GetProcessID(std::string_view processName);

ULONG64 GetModuleBaseAddress(uint32_t pID);

ULONG64 ReadULONG64(uint32_t pID, UINT_PTR readAddress);

template<typename S>
void Write(uint32_t pID, UINT_PTR writeAddress, const S& value);

void WriteMemory(uint32_t pID, UINT_PTR writeAddress, UINT_PTR sourceAddress, SIZE_T writeSize);

