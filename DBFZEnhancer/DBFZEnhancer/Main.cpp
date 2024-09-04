#include "Memory.h"
#include "HookLibrary.h"

PEPROCESS pProcess;

ULONG processOffset = 0x220; //_KTHREAD->_KPROCESS* Process;
ULONG cidOffset = 0x478; //_ETHREAD->_CLIENT_ID Cid;  

CLIENT_ID currentCid = { 0 };

PEPROCESS targetApplication = nullptr;
ULONG pid = NULL;
ULONG writtenpid1 = NULL;
ULONG writtenpid2 = NULL;

void MainThread()
{
	PEPROCESS currentProcess = IoGetCurrentProcess();
	PKTHREAD currentThread = KeGetCurrentThread();
	memcpy(&currentCid, (PVOID)((char*)currentThread + cidOffset), sizeof(CLIENT_ID));

	NTSTATUS status = STATUS_SUCCESS;
START:

	DebugMessage("[SKYHOOK] THREAD START \r\n");

	while (true)
	{
		DebugMessage("[SKYHOOK] LOOKING FOR GAME \r\n");

		status = GetProcByName("RED-Win64-Shipping.exe", &targetApplication, 0);
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

	DebugMessage("[SKYHOOK] FOUND PID %d\r\n", procId);

	ULONG64 baseAddress = (ULONG64)GetProcessBaseAddress(pid);

	BYTE patch = 0x78;

	BYTE readByte = 0x0;

	BYTE dlc[] = { 0xB0, 0x01, 0xC3 }; //mov al, 1 -> ret

	if (pid == writtenpid1 && pid == writtenpid2 && pid > 0 && writtenpid1 > 0 && writtenpid2 > 0)
	{
		DebugMessage("[SKYHOOK] ALREADY PATCHED %lld %lld %lld \r\n", pid, writtenpid1, writtenpid2);
		Sleep(1000);
		goto START;
	}

	DebugMessage("[SKYHOOK] PATCHING \r\n");

	ReadProcessMemory(pid, baseAddress + 0x349CDB8 + 0x2, (ULONG64)&readByte, 1, nullptr);

	DebugMessage("[SKYHOOK] READ %hhx\r\n", readByte);

	if (readByte == 0x61)
	{
		NTSTATUS wstatus = WriteProcessMemory(pid, baseAddress + 0x349CDB8 + 0x2, (ULONG64)&patch, 1, nullptr); //PATTERN: 70 00 61 00 6B 00 00 00 70 00 61 00 6B 00 63 00 68 00 75 00 6E 00 6B 00 (do it from IDA)

		if (NT_SUCCESS(wstatus))
		{
			writtenpid1 = pid;

			DebugMessage("[SKYHOOK] PATCHED PAK LOAD \r\n");
		}
		else
		{
			DebugMessage("[SKYHOOK] FAILED WRITE \r\n");
		}
	}
	else if (readByte == patch)
	{
		writtenpid1 = pid;
	}

	ReadProcessMemory(pid, baseAddress + 0x6D0A80, (ULONG64)&readByte, 1, nullptr);

	DebugMessage("[SKYHOOK] READ %hhx\r\n", readByte);

	if (readByte == 0x48)
	{
		NTSTATUS wstatus = WriteProcessMemory(pid, baseAddress + 0x6D0A80, (ULONG64)&dlc, 3, nullptr);

		//DLC

		//48 89 5C 24 08 55 56 57 48 8B EC 48 83 EC ? 48 8B F9

		if (NT_SUCCESS(wstatus))
		{
			writtenpid2 = pid;

			DebugMessage("[SKYHOOK] PATCHED DLC \r\n");
		}
		else
		{
			DebugMessage("[SKYHOOK] FAILED WRITE \r\n");
		}
	}
	else if (readByte == dlc[0])
	{
		writtenpid2 = pid;
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
