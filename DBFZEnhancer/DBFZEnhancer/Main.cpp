#include "Memory.h"
#include "HookLibrary.h"

PEPROCESS pProcess;

typedef UINT64(__fastcall* FunctionTemplate)(char* a1, unsigned int a2, unsigned int a3, __int64* a4, unsigned __int64 a5);
FunctionTemplate Function;

NTSTATUS HookKernel();
UINT64 __fastcall HookedFunctionCallback(char* a1, unsigned int a2, unsigned int a3, __int64* a4, unsigned __int64 a5);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath)
{
	UNREFERENCED_PARAMETER(driverObject);
	UNREFERENCED_PARAMETER(regPath);

	HookKernel();

	return STATUS_SUCCESS;
}

UINT64 __fastcall HookedFunctionCallback(char* a1, unsigned int a2, unsigned int a3, __int64* a4, unsigned __int64 a5)
{

    DebugMessage("[SKYHOOK] params = %i %i %i %i \r\n", a2, a3, a4, a5);

	if (a2 == 1337 && a3 == 1337 && a4 == (__int64*)1337 && a5 == 1337)
	{
		
        PCOMMUNICATIONPACKET packet = (PCOMMUNICATIONPACKET)a1;

        DebugMessage("[SKYHOOK] IC = %i \r\n", (int)packet->instructionCode);

        switch (packet->instructionCode)
        {
        
        case BASEADDRREQUEST:
        {
            DebugMessage("[SKYHOOK] PID = %i \r\n", packet->pID);
            packet->baseAddress = (ULONG64)GetProcessBaseAddress(packet->pID);
            DebugMessage("[SKYHOOK] POINTER = %p \r\n", GetProcessBaseAddress(packet->pID));
            return 0;
        }
        case DLLBASEREQUEST:
        {
            UNICODE_STRING modName = *(PUNICODE_STRING)packet->targetAddress;
            packet->bufferAddress = (ULONG64)GetModuleBase(packet->pID, modName);;
            return 0;
        }
        case READREQUEST:
        {
            NTSTATUS code = ReadProcessMemory(packet->pID, packet->targetAddress, packet->bufferAddress, packet->size, NULL);
            if (!NT_SUCCESS(code))
            {
                packet->returnStatus = code;
            }
            return 0;
        }
        case WRITEREQUEST:
        {
            SIZE_T read = 0;
            WriteProcessMemory(packet->pID, packet->targetAddress, packet->bufferAddress, packet->size, &read);
            return 0;
        }

        case TARGETCHANGE:
        {
            NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)packet->pID, &pProcess);
            packet->returnStatus = NtRet;
            return 0;
        }
        default:
            break;
        }
        return 0;
	}
	return Function(a1, a2, a3, a4, a5);
}

NTSTATUS HookKernel()
{
	PVOID hookaddr = GetSystemModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtTokenManagerCreateCompositionTokenHandle");


	DebugMessage("[SKYHOOK] = %p \r\n", hookaddr);

	NTSTATUS value = HkDetourFunction(
		hookaddr, //address of our target function
		HookedFunctionCallback,   //your callback
		16,               //size of bytes to replace (check the min amount of bytes needed for the hook in the hooking libary and make sure you increase it until it doesn't end in the middle of the assembly but after a full instruction
		(PVOID*)&Function); // store address for original


	DebugMessage("[SKYHOOK] RET = %x \r\n", value);

	return value;
}