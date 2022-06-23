#include "Memory.h"

//
// jmp QWORD PTR [rip+0x0]
//
static const UCHAR HkpDetour[] = {
    0xff, 0x25, 0x00, 0x00, 0x00, 0x00
};

#define FULL_DETOUR_SIZE (sizeof(HkpDetour) + sizeof(PVOID))
#define INTERLOCKED_EXCHANGE_SIZE (16ul)

static NTSTATUS HkpReplaceCode16Bytes(PVOID Address, PUCHAR Replacement)
{
    if ((ULONG64)Address != ((ULONG64)Address & ~0xf))
    {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    PMDL Mdl = IoAllocateMdl(Address, INTERLOCKED_EXCHANGE_SIZE, FALSE, FALSE, NULL);
    if (Mdl == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try
    {
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl(Mdl);

        return STATUS_INVALID_ADDRESS;
    }

    PLONG64 RwMapping = (PLONG64)MmMapLockedPagesSpecifyCache(
        Mdl,
        KernelMode,
        MmNonCached,
        NULL,
        FALSE,
        NormalPagePriority
    );

    if (RwMapping == NULL)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);

        return STATUS_INTERNAL_ERROR;
    }

    NTSTATUS Status = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        MmUnmapLockedPages(RwMapping, Mdl);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);

        return Status;
    }

    LONG64 PreviousContent[2];
    PreviousContent[0] = RwMapping[0];
    PreviousContent[1] = RwMapping[1];

    InterlockedCompareExchange128(
        RwMapping,
        ((PLONG64)Replacement)[1],
        ((PLONG64)Replacement)[0],
        PreviousContent
    );

    MmUnmapLockedPages(RwMapping, Mdl);
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);

    return STATUS_SUCCESS;
}

static VOID HkpPlaceDetour(PVOID Address, PVOID Destination)
{

    RtlCopyMemory((PUCHAR)Address, HkpDetour, sizeof(HkpDetour));
    RtlCopyMemory((PUCHAR)Address + sizeof(HkpDetour), &Destination, sizeof(PVOID));
}

NTSTATUS HkRestoreFunction(PVOID HookedFunction, PVOID OriginalTrampoline)
{
    PUCHAR OriginalBytes = (PUCHAR)OriginalTrampoline - INTERLOCKED_EXCHANGE_SIZE;

    NTSTATUS Status = HkpReplaceCode16Bytes(HookedFunction, OriginalBytes);

    LARGE_INTEGER DelayInterval;
    DelayInterval.QuadPart = -100000;
    KeDelayExecutionThread(KernelMode, FALSE, &DelayInterval);


    ExFreePool(OriginalBytes);

    return Status;
}

NTSTATUS HkDetourFunction(PVOID TargetFunction, PVOID Hook, SIZE_T CodeLength, PVOID* OriginalTrampoline)
{
    if (CodeLength < FULL_DETOUR_SIZE)
    {
        return STATUS_INVALID_PARAMETER_3;
    }


    PUCHAR Trampoline = (PUCHAR)ExAllocatePool(NonPagedPool, INTERLOCKED_EXCHANGE_SIZE + FULL_DETOUR_SIZE + CodeLength);
    if (Trampoline == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }


    RtlCopyMemory(Trampoline, TargetFunction, INTERLOCKED_EXCHANGE_SIZE);


    RtlCopyMemory(Trampoline + INTERLOCKED_EXCHANGE_SIZE, TargetFunction, CodeLength);
    HkpPlaceDetour(Trampoline + INTERLOCKED_EXCHANGE_SIZE + CodeLength, (PVOID)((ULONG_PTR)TargetFunction + CodeLength));


    UCHAR DetourBytes[INTERLOCKED_EXCHANGE_SIZE];

    HkpPlaceDetour(DetourBytes, Hook);
    RtlCopyMemory((PUCHAR)DetourBytes + FULL_DETOUR_SIZE, (PUCHAR)TargetFunction + FULL_DETOUR_SIZE, INTERLOCKED_EXCHANGE_SIZE - FULL_DETOUR_SIZE);

    NTSTATUS Status = HkpReplaceCode16Bytes(TargetFunction, DetourBytes);
    if (!NT_SUCCESS(Status))
    {
        ExFreePool(Trampoline);
    }
    else
    {
        *OriginalTrampoline = Trampoline + INTERLOCKED_EXCHANGE_SIZE;
    }



    return Status;
}