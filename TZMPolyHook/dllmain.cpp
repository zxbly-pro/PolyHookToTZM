// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "heads/TZM.h"
#include <Windows.h> 
#include <string>
#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/ZydisDisassembler.hpp"
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
unique_ptr<x64Detour> detour;

EXTERN_C void jmpFunction();

//根据函数特征码扫描获取函数地址
ULONG64 ScanTZM(PCHAR tzm) {


	//输出结果
	string res = "";
	//接收结果数组
	ULONG64 addr[128] = { 0 };

	//获取当前程序pid
	int pid = _getpid();

	//记录特征码数量
	SIZE_T count = 0;

	//扫描特征码(如果劫持注入只能扫描到静态地址的TZM,因为还没初始化完成)
	count = FindMemoryTZM(pid, addr, sizeof(addr) / 8, tzm, 0x0000000000000000, 0x7FFFFFFFFFFF);

	//输出结果地址
	for (int i = 0; i < count; i++)
	{
		sprintf_s(str, 100, "%016I64X\n", addr[i]);
		res += str;
	}

	switch (count)
	{
	case 0:
		MessageBox(0, "未扫描到特征码", "提示", MB_SYSTEMMODAL);
		return 0;
		break;
	case 1:
		MessageBox(0, res.c_str(), "唯一TZM地址:", MB_SYSTEMMODAL);
		return addr[0];
		break;
	default:
		MessageBox(0, res.c_str(), "扫描到多个TZM地址:", MB_SYSTEMMODAL);
		return 0;
		break;
	}
	return 0;

}

//初始化需要的TZM数据
void initTZM()
{

	//tzmAdress = ScanTZM("48 89 54 24 10 48 89 4C 24 08 57 48 81 EC 40 04 00 00 48");// tttt.exe+4390 - 48 89 54 24 10        - mov [rsp+10],rdx
	tzmAdress = ScanTZM("89 01 48 8B 84 24 50 04 00 00 8B");// tttt.exe+4469 - 89 01                 - mov [rcx],eax
														 // tttt.exe+446B - 48 8B 84 24 50040000  - mov rax,[rsp+00000450]

}

void hookFunction() {
	sprintf_s(str, 100, "第%d次hook\n", sum);
	MessageBox(0, str, "提示", MB_SYSTEMMODAL);
	if (sum == 5)
	{
		sprintf_s(str, 100, "第%d次hook,开始取消hook\n", sum);
		MessageBox(0, str, "提示", MB_SYSTEMMODAL);
		detour->unHook();
	}
	sum++;
}

void hookTest() {
	initTZM();
	jmpAdress = tzmAdress + 10;
	detour = make_unique<x64Detour>((uint64_t)(tzmAdress), (uint64_t)&jmpFunction, &oldAdress);
	if (detour->hook())
	{
		sprintf_s(str, 100, "hook成功\n", sum);
		MessageBox(0, str, "提示", MB_SYSTEMMODAL);
	}
	else {
		sprintf_s(str, 100, "hook失败\n", sum);
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
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

