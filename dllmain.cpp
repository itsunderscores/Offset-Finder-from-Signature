// dllmain.cpp : Defines the entry point for the DLL application.
//#pragma comment(lib, "libMinHook.x64.lib")
//#include "MinHook.h"
#include "stdafx.h"
#include "types.h"
#include <iostream>
#include <thread>
#include <math.h>


using namespace std;

//uintptr_t moduleBase = (uintptr_t)GetModuleHandleW(L"GameAssembly.dll");
//uint64_t base = (uint64_t)GetModuleHandleA(NULL); //what we're attaching it to 

BOOL g_running = TRUE;

std::once_flag g_flag;

using DWGetLogonStatus_t = int (*)(int);

using MoveResponseToInventory_t = bool(__fastcall*)(LPVOID, int);

extern void Log_(const char* fmt, ...);
#define LOG(fmt, ...) Log_(xorstr_(fmt), ##__VA_ARGS__)

#define LOG_ADDR(var_name)										\
		LOG(#var_name ": 0x%llX (0x%llX)", var_name, var_name > base ? var_name - base : 0);	

#define INRANGE(x,a,b)	(x >= a && x <= b) 
#define getBits( x )	(INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )	(getBits(x[0]) << 4 | getBits(x[1]))

void Log_(const char* fmt, ...) {
	char		text[4096];
	va_list		ap;
	va_start(ap, fmt);
	vsprintf_s(text, fmt, ap);
	va_end(ap);

	std::ofstream logfile(xorstr_("log.txt"), std::ios::app);
	if (logfile.is_open() && text)	logfile << text << std::endl;
	logfile.close();
}

__int64 find_pattern(__int64 range_start, __int64 range_end, const char* pattern) {
	const char* pat = pattern;
	__int64 firstMatch = NULL;
	__int64 pCur = range_start;
	__int64 region_end;
	MEMORY_BASIC_INFORMATION mbi{};
	while (sizeof(mbi) == VirtualQuery((LPCVOID)pCur, &mbi, sizeof(mbi))) {
		if (pCur >= range_end - strlen(pattern))
			break;
		if (!(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READWRITE))) {
			pCur += mbi.RegionSize;
			continue;
		}
		region_end = pCur + mbi.RegionSize;
		while (pCur < region_end)
		{
			if (!*pat)
				return firstMatch;
			if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat)) {
				if (!firstMatch)
					firstMatch = pCur;
				if (!pat[1] || !pat[2])
					return firstMatch;

				if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
					pat += 3;
				else
					pat += 2;
			}
			else {
				if (firstMatch)
					pCur = firstMatch;
				pat = pattern;
				firstMatch = 0;
			}
			pCur++;
		}
	}
	return NULL;
}

namespace game {

	__int64 base;
	__int64 lootBase;
	__int64 fpGetLogonStatus;
	__int64 fpMoveResponseToInventory;
	__int64 fpFindStringtable;
	__int64 fpStringtableGetColumnValueForRow;

	bool init() {

		base = (__int64)GetModuleHandle(NULL);
		//uint64_t base = (uint64_t)GetModuleHandleA(NULL);
		return true;
	}

	bool find_sigs() {

		MODULEINFO moduleInfo;
		if (!GetModuleInformation((HANDLE)-1, GetModuleHandle(NULL), &moduleInfo, sizeof(MODULEINFO)) || !moduleInfo.lpBaseOfDll) {
			LOG("Couldnt GetModuleInformation");
			return NULL;
		}
		LOG("Base: 0x%llx", moduleInfo.lpBaseOfDll);
		LOG("Size: 0x%llx", moduleInfo.SizeOfImage);

		__int64 searchStart = (__int64)moduleInfo.lpBaseOfDll;
		__int64 searchEnd = (__int64)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage;

		bool result = true;

		auto resolve_jmp = [](__int64 addr) -> __int64 {
			return *(int*)(addr + 1) + addr + 5;
		};

		auto resolve_lea = [](__int64 addr) -> __int64 {
			return *(int*)(addr + 3) + addr + 7;
		};


		__int64 getassest1 = resolve_jmp(find_pattern(searchStart, searchEnd, xorstr_("E8 ? ? ? ? 48 8D 15 ? ? ? ? 8D 4B 36")));
		__int64 getcolforrow1 = resolve_jmp(find_pattern(searchStart, searchEnd, xorstr_("E8 ? ? ? ? 33 D2 48 8B C8 44 8D 42 16")));
		__int64 moverespontoinven = find_pattern(searchStart, searchEnd, xorstr_("40 53 55 56 57 41 55 41 56 48 83 EC 28 4C"));
		__int64 lootbase1 = resolve_lea(moverespontoinven + 17);

		std::cout << "Base: " << moduleInfo.lpBaseOfDll << "\n";
		std::cout << "StringTable_GetAsset: " << getassest1 << "\n";
		std::cout << "StringTable_GetColumnValueForRow: " << getcolforrow1 << "\n";
		std::cout << "pMoveResponseToInventory: " << moverespontoinven << "\n";
		std::cout << "pLootBase: " << lootbase1 << "\n";

		return result;
	}

	static void FindStringTable(const char* name, StringTable** table) {

		reinterpret_cast<void(__cdecl*)(const char*, StringTable**)>(fpFindStringtable)(name, table);
	}

	static char* StringTable_GetColumnValueForRow(void* stringTable, int row, int column) {

		return reinterpret_cast<char* (__cdecl*)(void*, int, int)>(fpStringtableGetColumnValueForRow)(stringTable, row, column);
	}
}

void boom(HMODULE hModule) {

	AllocConsole();
	FILE* f;
	freopen_s(&f, "CONOUT$", "w", stdout);

	//base = (__int64)GetModuleHandle(NULL);

	MODULEINFO moduleInfo;
	if (!GetModuleInformation((HANDLE)-1, GetModuleHandle(NULL), &moduleInfo, sizeof(MODULEINFO)) || !moduleInfo.lpBaseOfDll) {
		//LOG("Couldnt GetModuleInformation");
		std::cout << "Couldnt GetModuleInformation\n";
		system("pause");
	}
	LOG("Base: 0x%llx", moduleInfo.lpBaseOfDll);
	LOG("Size: 0x%llx", moduleInfo.SizeOfImage);

	__int64 searchStart = (__int64)moduleInfo.lpBaseOfDll;
	__int64 searchEnd = (__int64)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage;

	bool result = true;

	auto resolve_jmp = [](__int64 addr) -> __int64 {
		return *(int*)(addr + 1) + addr + 5;
	};

	auto resolve_lea = [](__int64 addr) -> __int64 {
		return *(int*)(addr + 3) + addr + 7;
	};

	__int64 fpGetLogonStatus123 = find_pattern(searchStart, searchEnd, xorstr_("40 53 48 83 EC 20 48 63 C1 BA"));
	__int64 getassest1 = resolve_jmp(find_pattern(searchStart, searchEnd, xorstr_("E8 ? ? ? ? 48 8D 15 ? ? ? ? 8D 4B 36")));
	__int64 getcolforrow1 = resolve_jmp(find_pattern(searchStart, searchEnd, xorstr_("E8 ? ? ? ? 33 D2 48 8B C8 44 8D 42 16")));
	__int64 moverespontoinven = find_pattern(searchStart, searchEnd, xorstr_("40 53 55 56 57 41 55 41 56 48 83 EC 28 4C"));
	__int64 lootbase1 = resolve_lea(moverespontoinven + 17);

	std::cout << "Base: " << moduleInfo.lpBaseOfDll << "\n";
	std::cout << "StringTable_GetAsset: " << getassest1 << "\n";
	std::cout << "StringTable_GetColumnValueForRow: " << getcolforrow1 << "\n";
	std::cout << "pMoveResponseToInventory: " << moverespontoinven << "\n";
	std::cout << "pLootBase: " << lootbase1 << "\n";
	std::cout << "LogOn: " << fpGetLogonStatus123 << "\n";

	system("pause");
	fclose(f);
	FreeConsole();
	FreeLibraryAndExitThread(hModule, 0);

}

void process(HMODULE hModule) {
	std::thread mw(boom, hModule);
	mw.detach();
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
		process(hModule);
    }
    return TRUE;
}

