#ifndef HOOKLIBRARY_HEADER
#define HOOKLIBRARY_HEADER

#include "Memory.h"

static NTSTATUS HkpReplaceCode16Bytes(PVOID Address, PUCHAR Replacement);
static VOID HkpPlaceDetour(PVOID Address, PVOID Destination);
NTSTATUS HkRestoreFunction(PVOID HookedFunction, PVOID OriginalTrampoline);
NTSTATUS HkDetourFunction(PVOID TargetFunction, PVOID Hook, SIZE_T CodeLength, PVOID* OriginalTrampoline);

#endif