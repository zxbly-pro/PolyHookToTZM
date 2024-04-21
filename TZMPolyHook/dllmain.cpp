// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "heads/TZM.h"
#include <Windows.h> 
#include <string>

#include "polyhook2/ZydisDisassembler.hpp"

//根据程序是64位还是32位初始化变量
#ifdef _WIN64
#include "polyhook2/Detour/x64Detour.hpp"
#else
#include "polyhook2/Detour/x86Detour.hpp"
#endif

using namespace std;
using namespace PLH;

char str[1024]{};
ULONG64 tzmAdress;

EXTERN_C ULONG64 jmpAdress = 0;
//函数声明
ULONG64 ScanTZM(PCHAR tzm);
uint64_t oldAdress;
int sum = 0;
void initTZM();

//根据程序是64位还是32位初始化变量
#ifdef _WIN64
unique_ptr<x64Detour> detour;
#else
unique_ptr<x86Detour> detour;
#endif
EXTERN_C void jmpFunction();
EXTERN_C int nowmoney = 2323;


//初始化需要的TZM数据
void initTZM()
{
	//noita.exe.text+82F445 - 8B 46 48              - mov eax,[esi+48]
	tzmAdress = ScanTZM("8B 46 48 89 46 58");
	if (tzmAdress == 0) {
		sprintf_s(str, 100, "未扫描到特征码\n");
	}
	else if (tzmAdress == 1) {
		sprintf_s(str, 100, "特征码不唯一\n");
	}
	else
		sprintf_s(str, 100, "有效特征码\n%016I64X\n", tzmAdress);
	MessageBox(0, str, "提示", MB_SYSTEMMODAL);
}

void hookTest() {
	initTZM();
	jmpAdress = tzmAdress + 6;
	//根据程序是64位还是32位初始化变量
#ifdef _WIN64
	detour = make_unique<x64Detour>((uint64_t)(tzmAdress), (uint64_t)&jmpFunction, &oldAdress);
#else
	detour = make_unique<x86Detour>((uint64_t)(tzmAdress), (uint64_t)&jmpFunction, &oldAdress);
#endif
	if (detour->hook())
	{
		sprintf_s(str, 100, "hook成功\n");
		MessageBox(0, str, "提示", MB_SYSTEMMODAL);
	}
	else {
		sprintf_s(str, 100, "hook失败\n");
		MessageBox(0, str, "提示", MB_SYSTEMMODAL);
	}
}





BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		hookTest();
		break;
		//主线程加载DLL后，创建一个新的进程的时候触发
	case DLL_THREAD_ATTACH:
		//当进程中关闭线程的时候触发
		break;
	case DLL_THREAD_DETACH:
		break;
		//当该DLL映像被进程卸载的时候触发
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

