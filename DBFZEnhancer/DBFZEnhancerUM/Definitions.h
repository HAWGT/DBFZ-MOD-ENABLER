#ifndef DEFINITIONS_HEADER
#define DEFINITIONS_HEADER

#include <Windows.h>

typedef struct _COMMUNICATIONPACKET
{
	int instructionCode;
	bool targetChange;
	int pID;
	ULONG returnStatus;
	ULONG size;
	ULONG64 targetAddress;
	ULONG64 bufferAddress;
	const char* moduleName;
	ULONG64 baseAddress;
	void* output;
}COMMUNICATIONPACKET, * PCOMMUNICATIONPACKET;

typedef enum _INSTRUCTIONCODE {
	BASEADDRREQUEST,
	DLLBASEREQUEST,
	READREQUEST,
	WRITEREQUEST,
	TARGETCHANGE
}INSTRUCTIONCODE, * PINSTRUCTIONCODE;

struct HandleDisposer
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const
	{
		if (handle != NULL && handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
		}
	}
};

#endif