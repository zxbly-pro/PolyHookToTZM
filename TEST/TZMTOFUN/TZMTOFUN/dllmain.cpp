// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

#include <iostream>
#include "TZM.h"
#include <atlstr.h>

using namespace std;


//格式化输出中转数组
char str[100]{};
//根据函数特征码扫描获取函数地址并调用
ULONG64 startCall() {



	//输出结果
	string res = "";
	//接收结果数组
	ULONG64 addr[128] = { 0 };

	//获取当前程序pid
	int pid = _getpid();

	//记录特征码数量
	SIZE_T count = 0;

	//扫描特征码(如果劫持注入只能扫描到静态地址的TZM,因为还没初始化完成)
	count = FindMemoryTZM(pid, addr, sizeof(addr) / 8, (PCHAR)"48 ?? ?? 24 10 48 89 4C 24 08 57 48 81 EC 40 04", 0x0000000000000000, 0x7FFFFFFFFFFF);

	//输出结果地址
	for (int i = 0; i < count; i++)
	{
		//格式化输出
		//cout << hex << uppercase << addr[i] << endl;
		//printf("结果地址：%016I64X\n", addr[i]);
		sprintf_s(str, 100, "%016I64X\n", addr[i]);
		res += str;
		//MessageBox(0, str, "TZM地址:", MB_SYSTEMMODAL);
	}

	switch (count)
	{
	case 0:
		MessageBox(0, "未扫描到特征码", "提示", MB_SYSTEMMODAL);
		return 0;
		break;
	case 1:
		MessageBox(0, "扫描到唯一特征码.开始调用函数", "提示", MB_SYSTEMMODAL);
		MessageBox(0, res.c_str(), "TZM地址:", MB_SYSTEMMODAL);
		return addr[0];
		break;
	default:
		MessageBox(0, "扫描到多个特征码,取消调用函数", "提示", MB_SYSTEMMODAL);
		MessageBox(0, res.c_str(), "TZM地址:", MB_SYSTEMMODAL);
		return 0;
		break;
	}
	return 0;

}
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	int a = 2, b = 3;
	int ret = 0;
	ULONG64 res = 0;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		res = startCall();
		if (res) {
			sprintf_s(str, 100, "%016I64X\n", res);
			MessageBox(0, str, "TZM地址:", MB_SYSTEMMODAL);



			//函数指针指向函数地址
			int (*pfc)(int* a, int* b) = (int (*)(int* a, int* b))res;


			//调用函数
			ret = pfc(&a, &b);

			sprintf_s(str, 100, "%d\n", ret);
			MessageBox(0, str, "调用summ(2,3)", MB_SYSTEMMODAL);
			break;
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

