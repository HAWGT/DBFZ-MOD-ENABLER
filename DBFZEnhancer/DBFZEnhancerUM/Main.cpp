#include <iostream>
#include "Process.h"
#include <thread>
#include "../DBFZEnhancer/Definitions.h"


void SteamIDWatcher(int pid, ULONG64 baseAddress);
void PatchPakLoader(int pid, ULONG64 baseAddr);

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

			std::thread steamIDWatcher(SteamIDWatcher, pid, baseAddress);
			steamIDWatcher.detach();
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
	ULONG64 offset = 0x3416530; //PATTERN: 70 00 61 00 6B 00 00 00 70 00 61 00 6B 00 63 00 68 00 75 00 6E 00 6B 00
	BYTE patch[] = { 0x78 }; //x
	WriteMemory(pid, baseAddress + offset, (UINT_PTR)(&patch), sizeof(patch));
}
