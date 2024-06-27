#include "Memory.h"
#include "HookLibrary.h"

PEPROCESS pProcess;

ULONG processOffset = 0x220; //_KTHREAD->_KPROCESS* Process;
ULONG cidOffset = 0x478; //_ETHREAD->_CLIENT_ID Cid;  

CLIENT_ID currentCid = { 0 };

PEPROCESS targetApplication = nullptr;
ULONG pid = NULL;
ULONG writtenpid = NULL;

void MainThread()
{
    PEPROCESS currentProcess = IoGetCurrentProcess();
    PKTHREAD currentThread = KeGetCurrentThread();
    memcpy(&currentCid, (PVOID)((char*)currentThread + cidOffset), sizeof(CLIENT_ID));

    NTSTATUS status = STATUS_SUCCESS;
    START:

    while (true)
    {
        status = GetProcByName("RED-WIN64-SHIPPING.EXE", &targetApplication, 0);
        if (NT_SUCCESS(status))
            break;

        Sleep(300);
    }

    HANDLE procId = PsGetProcessId(targetApplication);

    if (!procId)
    {
        goto START;
    }
    pid = (ULONG)procId;

    ULONG64 baseAddress = (ULONG64)GetProcessBaseAddress(pid);

    BYTE patch = 0x78;

    BYTE readByte = 0x0;

    if (writtenpid == pid)
    {
        Sleep(1000);
        goto START;
    }

    ReadProcessMemory(pid, baseAddress + 0x349C380 + 0x2, (ULONG64)&readByte, 1, nullptr);

    if (readByte == 0x61)
    {
        WriteProcessMemory(pid, baseAddress + 0x349C380 + 0x2, (ULONG64)&patch, 1, nullptr); //PATTERN: 70 00 61 00 6B 00 00 00 70 00 61 00 6B 00 63 00 68 00 75 00 6E 00 6B 00 (do it from IDA)
        writtenpid = pid;
    }

    //PsTerminateSystemThread(STATUS_SUCCESS);

    goto START;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath)
{
    UNREFERENCED_PARAMETER(driverObject);
    UNREFERENCED_PARAMETER(regPath);

    NTSTATUS status = StartThread(MainThread);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("[SKYHOOK] FAILED \r\n");
        return STATUS_UNSUCCESSFUL;
    }

    DebugMessage("[SKYHOOK] SUCCESS \r\n");

    return STATUS_SUCCESS;
}
