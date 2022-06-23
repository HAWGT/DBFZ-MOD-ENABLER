#include <iostream>
#include "Process.h"
#include <thread>


void PatchTeamForcer(int pid, ULONG64 baseAddr);
void SteamIDWatcher(int pid, ULONG64 baseAddress);

std::atomic<bool> canRun = false;

int main()
{
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

			//PatchTeamForcer(pid, baseAddress);

			canRun = true;

			std::thread watcher(SteamIDWatcher, pid, baseAddress);
			watcher.join();
		}
	}
	return 0;
}

void PatchTeamForcer(int pid, ULONG64 baseAddr)
{
	ULONG64 offset_tm_pt_0 = 0x5CBEF8; //Training Mode - Practice Team
	BYTE patch_tm_pt_0[] = { 0x90, 0x90, 0x90, 0x90 };
	WriteMemory(pid, baseAddr + offset_tm_pt_0, (UINT_PTR)(&patch_tm_pt_0), sizeof(patch_tm_pt_0));

	ULONG64 offset_tm_pt_1 = 0x5CBD9; //Training Mode - Practice Team
	BYTE patch_tm_pt_1[] = { 0x90, 0x90, 0x90, 0x90 };
	WriteMemory(pid, baseAddr + offset_tm_pt_1, (UINT_PTR)(&patch_tm_pt_1), sizeof(patch_tm_pt_1));

	ULONG64 offset_tm_pt_2 = 0x5CC307; //Training Mode - Practice Team
	BYTE patch_tm_pt_2[] = { 0x90, 0x90, 0x90, 0x90 };
	WriteMemory(pid, baseAddr + offset_tm_pt_2, (UINT_PTR)(&patch_tm_pt_2), sizeof(patch_tm_pt_2));

	ULONG64 offset_tm_pt_3 = 0x5CC1A8; //Training Mode - Practice Team
	BYTE patch_tm_pt_3[] = { 0x90, 0x90, 0x90, 0x90 };
	WriteMemory(pid, baseAddr + offset_tm_pt_3, (UINT_PTR)(&patch_tm_pt_3), sizeof(patch_tm_pt_3));

	ULONG64 offset1 = 0x6826E5; //After match / entering training mode
	BYTE patch1[] = { 0x90, 0x90 };
	WriteMemory(pid, baseAddr + offset1, (UINT_PTR)(&patch1), sizeof(patch1));

	ULONG64 offset2 = 0x6832DF; //Team Selection
	BYTE patch2[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	WriteMemory(pid, baseAddr + offset2, (UINT_PTR)(&patch2), sizeof(patch2));

	ULONG64 offset3 = 0x6B00B6; //Training Mode - Matchmaking Team
	BYTE patch3[] = { 0x90, 0x90 };
	WriteMemory(pid, baseAddr + offset3, (UINT_PTR)(&patch3), sizeof(patch3));

	ULONG64 offset4 = 0x6B0208; //Training Mode - Matchmaking Team
	BYTE patch4[] = { 0x90, 0x90, 0x90, 0x90 };
	WriteMemory(pid, baseAddr + offset4, (UINT_PTR)(&patch4), sizeof(patch4));

	//68216D [4]
	//6822D1 [3]
	//682289 [2]

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