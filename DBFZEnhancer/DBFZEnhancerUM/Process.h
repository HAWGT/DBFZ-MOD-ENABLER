#include <string_view>
#include "Definitions.h"

void Init();

uint32_t GetProcessID(std::string_view processName);

ULONG64 GetModuleBaseAddress(uint32_t pID);

ULONG64 ReadULONG64(uint32_t pID, UINT_PTR readAddress);

BYTE ReadBYTE(uint32_t pID, UINT_PTR readAddress);

void WriteMemory(uint32_t pID, UINT_PTR writeAddress, UINT_PTR sourceAddress, SIZE_T writeSize);
