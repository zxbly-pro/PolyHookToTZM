// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h> 
#ifdef _WIN64
#include "polyhook2/Detour/x64Detour.hpp"
#else
#include "polyhook2/Detour/x86Detour.hpp"
#endif // _WIN64



using namespace PLH;
//Detour测试
#pragma region Detour

//引入需要使用的hpp头文件
#ifdef _WIN64

#include "polyhook2/Detour/x64Detour.hpp"

#else

#include "polyhook2/Detour/x86Detour.hpp"

#endif // _WIN64



//为 jmp 申请的内存地址,用来恢复被 jmp 覆盖的指令
uint64_t u64_hMessageBoxA = NULL;

//hook后执行的方法
NOINLINE int __cdecl hook_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	//执行自定义方法
	return PLH::FnCast(u64_hMessageBoxA, &MessageBoxA)(NULL, "hook MessageBoxA", "LYSM", NULL);
}
#pragma endregion

//断点测试
#pragma region BreakPointHook

#include "polyhook2/Exceptions/BreakPointHook.hpp"

//自定义一个方法
NOINLINE int hookMe() {

	volatile int i = 0;
	i += 1;
	i += 2;

	return i;
}

std::shared_ptr<PLH::BreakPointHook> bpHook;

//自定义回调函数
NOINLINE int hookMeCallback() {

	std::cout << "调用 hookMe 前先进入回调函数" << std::endl;

	//回调完成执行原始方法
	return hookMe();
}
#pragma endregion 

#pragma region HWBreakPointHook
#include "polyhook2/Exceptions/HWBreakPointHook.hpp"
NOINLINE int hookMeHWBP() {
	volatile int i = 0;
	i += 1;
	i += 2;
	return i;
}
std::shared_ptr<PLH::HWBreakPointHook> hwBpHook;
NOINLINE int hookMeCallbackHWBP() {
	std::cout << "调用 hookMeHWBP 前先进入回调函数" << std::endl;
	return hookMeHWBP();
}
#pragma endregion

#pragma region IatHook
#include "polyhook2/PE/IatHook.hpp"
uint64_t oGetCurrentThreadID;
NOINLINE DWORD __stdcall hkGetCurrentThreadId() {
	return 0;
}
#pragma endregion

#pragma region EatHook
#include "polyhook2/PE/EatHook.hpp"
typedef void(*tEatTestExport)();
uint64_t oEatTestExport;
extern "C" __declspec(dllexport) NOINLINE void EatTestExport() {
	std::cout << "EatTestExport" << std::endl;
}
NOINLINE void hkEatTestExport() {
	std::cout << "hkEatTestExport" << std::endl;
}
#pragma endregion

#pragma region MemProtector
#include "polyhook2/MemProtector.hpp"
#pragma endregion 

#pragma region VTableSwapHook
#include "polyhook2/Virtuals/VTableSwapHook.hpp"
class VirtualTest {
public:
	virtual ~VirtualTest() {}
	virtual int NoParamVirt() {
		return 4;
	}
	virtual int NoParamVirt2() {
		return 7;
	}
};
typedef int(__thiscall* tVirtNoParams)(uintptr_t pThis);
PLH::VFuncMap origVFuncs;
NOINLINE int __fastcall hkVirtNoParams(uintptr_t pThis) {
	std::cout << "执行虚函数之前先执行 hkVirtNoParams" << std::endl;
	return ((tVirtNoParams)origVFuncs.at(1))(pThis);
}
#pragma endregion

#pragma region VFuncSwapHook
#include "polyhook2/Virtuals/VFuncSwapHook.hpp"
class VirtualTest2 {
public:
	virtual ~VirtualTest2() {}
	virtual int NoParamVirt() {
		return 4;
	}
	virtual int NoParamVirt2() {
		return 7;
	}
};
typedef int(__thiscall* tVirtNoParams)(uintptr_t pThis);
PLH::VFuncMap origVFuncs2;
NOINLINE int __fastcall hkVirtNoParams2(uintptr_t pThis) {
	std::cout << "执行虚函数之前先执行 hkVirtNoParams2" << std::endl;
	return ((tVirtNoParams)origVFuncs2.at(1))(pThis);
}
#pragma endregion

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	uint64_t msgAdress = reinterpret_cast<uint64_t>(&MessageBoxA);
	uint64_t msgAdressNew = reinterpret_cast<uint64_t>(&hook_MessageBoxA);
#ifdef _WIN64
	PLH::x64Detour detour(msgAdress, msgAdressNew, &u64_hMessageBoxA);
#else
	PLH::x86Detour detour(msgAdress, msgAdressNew, &u64_hMessageBoxA);
#endif // _WIN64


	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		MessageBoxA(NULL, "Failed.", "LYSM", NULL);
		detour.hook();
		std::cout << std::hex << "为 jmp 申请的内存地址,用来恢复被 jmp 覆盖的指令:" << u64_hMessageBoxA << std::endl;
		MessageBoxA(NULL, "Failed.", "LYSM", NULL);
		detour.unHook();
		MessageBoxA(NULL, "Failed.", "LYSM", NULL);
		// 测试 —— Detour

//		uint64_t msgAdress = reinterpret_cast<uint64_t>(&MessageBoxA);
//		uint64_t msgAdressNew = reinterpret_cast<uint64_t>(&hook_MessageBoxA);
//
//#ifdef _WIN64
//		PLH::x64Detour detour(msgAdress, msgAdressNew, &u64_hMessageBoxA);
//#else
//		PLH::x86Detour detour(msgAdress, msgAdressNew, &u64_hMessageBoxA);
//#endif // _WIN64
//
//
//		MessageBoxA(NULL, "Failed.", "LYSM", NULL);
//		detour.hook();
//		std::cout << std::hex << "为 jmp 申请的内存地址,用来恢复被 jmp 覆盖的指令:" << u64_hMessageBoxA << std::endl;
//		MessageBoxA(NULL, "Failed.", "LYSM", NULL);
//		detour.unHook();
//		MessageBoxA(NULL, "Failed.", "LYSM", NULL);

		// 测试 —— BreakPoint

		//bpHook = std::make_shared<PLH::BreakPointHook>((char*)&hookMe, (char*)&hookMeCallback);
		//std::cout << "hookMe():" << hookMe() << std::endl;
		//if (bpHook->hook() == true) {
		//	std::cout << "hook success." << std::endl;
		//}
		//std::cout << "hookMe():" << hookMe() << std::endl;
		//if (bpHook->unHook() == true) {
		//	std::cout << "unHook success." << std::endl;
		//}
		//std::cout << "hookMe():" << hookMe() << std::endl;


		//PLH::BreakPointHook bpHook2 = PLH::BreakPointHook((char*)&hookMe, (char*)&hookMeCallback);
		//std::cout << "hookMe():" << hookMe() << std::endl;
		//if (bpHook2.hook()) {
		//	std::cout << "hook success." << std::endl;
		//}
		//std::cout << "hookMe():" << hookMe() << std::endl;
		//if (bpHook2.unHook()) {
		//	std::cout << "unHook success." << std::endl;
		//}
		//std::cout << "hookMe():" << hookMe() << std::endl;

		// 测试 —— HWBreakPoint

		//hwBpHook = std::make_shared<PLH::HWBreakPointHook>((char*)&hookMeHWBP, (char*)&hookMeCallbackHWBP,GetCurrentThread());
		//std::cout << "hookMeHWBP():" << hookMeHWBP() << std::endl;
		//if (hwBpHook->hook() == true) {
		//	std::cout << "hook success." << std::endl;
		//}
		//std::cout << "hookMeHWBP():" << hookMeHWBP() << std::endl;
		//if (hwBpHook->unHook() == true) {
		//	std::cout << "unHook success." << std::endl;
		//}
		//std::cout << "hookMeHWBP():" << hookMeHWBP() << std::endl;

		// 测试 —— IatHook

		//PLH::IatHook hook("kernel32.dll", "GetCurrentThreadId", (char*)&hkGetCurrentThreadId, (uint64_t*)&oGetCurrentThreadID, L"");
		//std::cout << "TID:" << std::hex << GetCurrentThreadId() << std::endl;
		//if (hook.hook() == true) {
		//	std::cout << "hook success." << std::endl;
		//}
		//std::cout << "原 IAT 表中 GetCurrentThreadId 地址:0x" << std::hex << oGetCurrentThreadID << std::endl;
		//std::cout << "HOOK后 TID:" << GetCurrentThreadId() << std::endl;
		//if (hook.unHook() == true) {
		//	std::cout << "unhHook success." << std::endl;
		//}
		//std::cout << "取消HOOK后 TID:" << GetCurrentThreadId() << std::endl;

		// 测试 —— EatHook

		/*PLH::EatHook hook("EatTestExport", L"", (char*)&hkEatTestExport, (uint64_t*)&oEatTestExport);
		tEatTestExport pExport_0 = (tEatTestExport)GetProcAddress(GetModuleHandle(nullptr), "EatTestExport");
		pExport_0();
		if (hook.hook() == true) {
			std::cout << "hook success." << std::endl;
		}
		std::cout << "原 EAT 表中 EatTestExport 地址:0x" << std::hex << oEatTestExport << std::endl;
		tEatTestExport pExport_1 = (tEatTestExport)GetProcAddress(GetModuleHandle(nullptr), "EatTestExport");
		pExport_1();
		if (hook.unHook() == true) {
			std::cout << "unHook success." << std::endl;
		}
		tEatTestExport pExport_2 = (tEatTestExport)GetProcAddress(GetModuleHandle(nullptr), "EatTestExport");
		pExport_2();*/

		// 测试 —— MemProtector

		/*char* page = (char*)VirtualAlloc(0, 4 * 1024, MEM_COMMIT, PAGE_NOACCESS);
		PLH::MemoryProtector prot((uint64_t)page, 4 * 1024, PLH::ProtFlag::R | PLH::ProtFlag::W | PLH::ProtFlag::X);
		if (prot.isGood()) {
			std::cout << "修改内存保护属性成功." << std::endl;
		}
		page = "test";
		std::cout << "page:" << page << std::endl;
		VirtualFree(page, 0, MEM_RELEASE);*/

		// 测试 —— VTableSwapHook

		/*std::shared_ptr<VirtualTest> ClassToHook(new VirtualTest);
		PLH::VFuncMap redirect = { {(uint16_t)1, (uint64_t)&hkVirtNoParams} };
		PLH::VTableSwapHook hook((char*)ClassToHook.get(), redirect);
		if (hook.hook() == true) {
			std::cout << "hook success." << std::endl;
		}
		origVFuncs = hook.getOriginals();
		std::cout << "NoParamVirt:" << ClassToHook->NoParamVirt() << std::endl;
		if (hook.unHook() == true) {
			std::cout << "unHook success." << std::endl;
		}
		std::cout << "NoParamVirt:" << ClassToHook->NoParamVirt() << std::endl;*/

		// 测试 —— VFuncSwapHook

		/*std::shared_ptr<VirtualTest2> ClassToHook(new VirtualTest2);
		PLH::VFuncMap redirect = { {(uint16_t)1, (uint64_t)&hkVirtNoParams2} };
		PLH::VFuncSwapHook hook((char*)ClassToHook.get(), redirect, &origVFuncs2);
		if (hook.hook() == true) {
			std::cout << "hook success." << std::endl;
		}
		std::cout << "NoParamVirt:" << ClassToHook->NoParamVirt() << std::endl;
		if (hook.unHook() == true) {
			std::cout << "unHook success." << std::endl;
		}
		std::cout << "NoParamVirt:" << ClassToHook->NoParamVirt() << std::endl;*/
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

