#include <iostream>
#include "Process.h"
#include <thread>


void SteamIDWatcher(int pid, ULONG64 baseAddress);
void PatchPakLoader(int pid, ULONG64 baseAddr);

std::atomic<bool> canRun = false;

int main()
{
	Init();

	int pid = 0;
	int oldPid = -1;
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
			ULONG64 baseAddress = GetModuleBaseAddress(pid);
			std::cout << "Base Address: " << std::hex << baseAddress << std::dec << std::endl;
			std::cout << "Patching..." << std::endl;

			PatchPakLoader(pid, baseAddress);

			canRun = true;

			std::thread watcher(SteamIDWatcher, pid, baseAddress);
			watcher.detach();
		}
	}
	return 0;
}

void SteamIDWatcher(int pid, ULONG64 baseAddress)
{
	ULONG64 offset = 0x38FDE88;
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

void PatchPakLoader(int pid, ULONG64 baseAddr)
{
	ULONG64 offset = 0x3433902; //2ND CHAR - PATTERN: 70 00 61 00 6B 00 00 00 70 00 61 00 6B 00 63 00 68 00 75 00 6E 00 6B 00
	BYTE patch[] = { 0x78 };
	WriteMemory(pid, baseAddr + offset, (UINT_PTR)(&patch), sizeof(patch));
}