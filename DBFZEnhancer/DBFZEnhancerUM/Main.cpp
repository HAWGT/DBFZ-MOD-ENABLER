#include <iostream>
#include "Process.h"
#include <thread>
#include "../DBFZEnhancer/Definitions.h"


void SteamIDWatcher(int pid, ULONG64 baseAddress);
void PatchPakLoader(int pid, ULONG64 baseAddr);
void PatchTeamSelection(int pid, ULONG64 baseAddr);
void SecretCharacterSelect(int pid, ULONG64 baseAddr);

std::atomic<bool> canRun = false;

int main()
{
	Init();

	std::cout << "DBFZ MOD Enabler" << std::endl;
	
	int pid = 0;
	int oldPid = -1;
	ULONG64 baseAddress = 0;

	while (true)
	{
		pid = GetProcessID("RED-Win64-Shipping.exe");

		if (pid == 0)
		{
			canRun = false;
		}

		if (pid != oldPid && pid != 0)
		{
			oldPid = pid;
			std::cout << "PID: " << pid << std::endl;

			while (baseAddress == 0)
			{
				baseAddress = GetModuleBaseAddress(pid);
			}

			canRun = true;

			std::cout << "Base Address: " << std::hex << baseAddress << std::dec << std::endl;

			PatchPakLoader(pid, baseAddress);
			PatchTeamSelection(pid, baseAddress);

			std::thread steamIDWatcher(SteamIDWatcher, pid, baseAddress);
			steamIDWatcher.detach();

			std::thread secretCharacterSelect(SecretCharacterSelect, pid, baseAddress);
			secretCharacterSelect.detach();
		}
	}
	return 0;
}

void SteamIDWatcher(int pid, ULONG64 baseAddress)
{
	ULONG64 offset = 0x3907E88; //Search for steamid64 8 bytes
	ULONG64 lastSteamID = 0;
	ULONG64 currentSteamID = 0;

	while (canRun)
	{
		Sleep(1000);
		currentSteamID = ReadULONG64(pid, baseAddress + offset);
		if (currentSteamID != lastSteamID && currentSteamID > 76560000000000000 && currentSteamID < 76570000000000000) {
			lastSteamID = currentSteamID;
			std::cout << "Profile URL: https://steamcommunity.com/profiles/" << lastSteamID << std::endl;
			Sleep(1000);
		}
	}
}

void PatchPakLoader(int pid, ULONG64 baseAddress)
{
	if (!canRun) return;
	//ULONG64 offset = 0x3433900; //PATTERN: 70 00 61 00 6B 00 00 00 70 00 61 00 6B 00 63 00 68 00 75 00 6E 00 6B 00
	//BYTE patch[] = { 0x70, 0x00, 0x78, 0x00, 0x6B, 0x00 }; //pxk (WIDE STRING)
	ULONG64 offset = 0x3433902; //PATTERN: 70 00 61 00 6B 00 00 00 70 00 61 00 6B 00 63 00 68 00 75 00 6E 00 6B 00
	BYTE patch[] = { 0x78 }; //x
	WriteMemory(pid, baseAddress + offset, (UINT_PTR)(&patch), sizeof(patch));
}

void PatchTeamSelection(int pid, ULONG64 baseAddress)
{
	if (!canRun) return;
	ULONG64 offset = 0x6837AF; //PATTERN 88 90 84 02 00 00 C6 80 88 02 00 00 01 42 0F B6 94 AE E9 02 00 00
	BYTE patch[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	WriteMemory(pid, baseAddress + offset, (UINT_PTR)(&patch), sizeof(patch));
}

void SecretCharacterSelect(int pid, ULONG64 baseAddress)
{
	ULONG64 baseOffset = 0x38343A8;
	ULONG64 costumeOffset = 0x4;
	ULONG64 assistOffset = 0x5;

	BYTE evil21 = { 0x18 };
	BYTE good21 = { 0x19 };
	BYTE defaultCostume = { 0x00 };
	BYTE altCostume1 = { 0x01 };
	BYTE altCostume2 = { 0x02 };
	BYTE altCostume3 = { 0x03 };
	BYTE altCostume4 = { 0x04 };
	BYTE assistA = { 0x00 };
	BYTE assistB = { 0x01 };
	BYTE assistC = { 0x02 };

	while (canRun)
	{
		if (GetAsyncKeyState(0x30) & 1) //Assist C
		{
			printf("Selected Assist C\r\n");
			WriteMemory(pid, baseAddress + baseOffset + assistOffset, (UINT_PTR)(&assistC), sizeof(assistC));
			Sleep(100);
		}
		else if (GetAsyncKeyState(0x31) & 1) //Evil 21
		{
			printf("Selected Android 21 (Evil)\r\n");
			WriteMemory(pid, baseAddress + baseOffset, (UINT_PTR)(&evil21), sizeof(evil21));
			Sleep(100);
		}
		else if (GetAsyncKeyState(0x32) & 1) //Good 21
		{
			printf("Selected Android 21 (Good)\r\n");
			WriteMemory(pid, baseAddress + baseOffset, (UINT_PTR)(&good21), sizeof(good21));
			Sleep(100);
		}
		else if (GetAsyncKeyState(0x33) & 1) //Default Costume
		{
			printf("Selected Default Costume\r\n");
			WriteMemory(pid, baseAddress + baseOffset + costumeOffset, (UINT_PTR)(&defaultCostume), sizeof(defaultCostume));
			Sleep(100);
		}
		else if (GetAsyncKeyState(0x34) & 1) //Alt Costume 1
		{
			printf("Selected Alt Costume 1\r\n");
			WriteMemory(pid, baseAddress + baseOffset + costumeOffset, (UINT_PTR)(&altCostume1), sizeof(altCostume1));
			Sleep(100);
		}
		else if (GetAsyncKeyState(0x35) & 1) //Alt Costume 2
		{
			printf("Selected Alt Costume 2\r\n");
			WriteMemory(pid, baseAddress + baseOffset + costumeOffset, (UINT_PTR)(&altCostume2), sizeof(altCostume2));
			Sleep(100);
		}
		else if (GetAsyncKeyState(0x36) & 1) //Alt Costume 3
		{
			printf("Selected Alt Costume 3\r\n");
			WriteMemory(pid, baseAddress + baseOffset + costumeOffset, (UINT_PTR)(&altCostume3), sizeof(altCostume3));
			Sleep(100);
		}
		else if (GetAsyncKeyState(0x37) & 1) //Alt Costume 4
		{
			printf("Selected Alt Costume 4\r\n");
			WriteMemory(pid, baseAddress + baseOffset + costumeOffset, (UINT_PTR)(&altCostume4), sizeof(altCostume4));
			Sleep(100);
		}
		else if (GetAsyncKeyState(0x38) & 1) //Assist A
		{
			printf("Selected Assist A\r\n");
			WriteMemory(pid, baseAddress + baseOffset + assistOffset, (UINT_PTR)(&assistA), sizeof(assistA));
			Sleep(100);
		}
		else if (GetAsyncKeyState(0x39) & 1) //Assist B
		{
			printf("Selected Assist B\r\n");
			WriteMemory(pid, baseAddress + baseOffset + assistOffset, (UINT_PTR)(&assistB), sizeof(assistB));
			Sleep(100);
		}
	}
}