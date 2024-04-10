﻿//Generated by AheadLib4x64 by Evil0r
#include "pch.h"
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "TZM.h"
#include <atlstr.h>
#include <string>
#include "HOOK.h"

//设置是否是硬件断点(硬件断点只有4个,不会破坏汇编代码;页面权限断点可以无数个,但是会更改内存属性)
bool isCPU = true;

//根据函数特征码扫描获取函数地址并HOOK
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
		MessageBox(0, "扫描到唯一特征码.开始Hook", "提示", MB_SYSTEMMODAL);
		MessageBox(0, res.c_str(), "TZM地址:", MB_SYSTEMMODAL);
		return addr[0];
		break;
	default:
		MessageBox(0, "扫描到多个特征码,取消Hook", "提示", MB_SYSTEMMODAL);
		MessageBox(0, res.c_str(), "TZM地址:", MB_SYSTEMMODAL);
		return 0;
		break;
	}
	return 0;

}





// 入口函数
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	ULONG64 tzmAdress = 0, maxhp = 0, jinbi = 0;
	switch (ul_reason_for_call)
	{
		//DLL被初次映射到进程的地址空间中的时候触发
	case DLL_PROCESS_ATTACH:
		//用于使指定DLL的DLL_THREAD_ATTACH和DLL_THREAD_DETACH通知无效，这可减少某些应用程序的工作集空间
		//DisableThreadLibraryCalls(hModule);
		//自定义操作
		//提示框(MB_SYSTEMMODAL=置顶)
		MessageBox(0, "加载DLL成功", "提示", MB_SYSTEMMODAL);
		//HOOK扫描到的函数地址,设置HOOK后要执行的方法(如果hook方法是访问这种频繁执行的会导致未知异常,猜测是多线程的原因)
#ifdef _WIN64
		//tzmAdress = ScanTZM("48 89 54 24 10 48 89 4C 24 08 57 48 81 EC 40 04");//64位测试hook汇编函数头特征码	tttt.exe+4390 - 48 89 54 24 10        - mov [rsp+10],rdx
		tzmAdress = ScanTZM("89 01 48 8B 84 24 50 04 00 00 8B 00");//64位测试hook汇编代码特征码	tttt.exe+4469 - 89 01                 - mov [rcx],eax

#else
		//tzmAdress = ScanTZM("55 8B EC 81 EC 04 04 00 00 A1 64");//32位测试hook汇编函数头特征码
		tzmAdress = ScanTZM("89 02 8B 45 08 8B 00");//32位测试hook汇编代码特征码	tttt.exe+3A68 - 89 02                 - mov [edx],eax


		//jinbi = ScanTZM("89 46 48 89 56 4C 5F 5E 8B E5 5D C2 08 00 BA 38");//金币改变	noita.exe+5BE205 - 89 46 48              - mov [esi+48],eax
		//maxhp = ScanTZM("F2 0F 11 46 50 E9 35 0D 00 00");//最大生命值改变	noita.exe+BE4E7 - F2 0F11 46 50         - movsd [esi+50],xmm0



#endif // _WIN64

		//使用硬件断点(dr0->dr7=0x00000001;dr1->dr7=0x00000004;dr2->dr7=0x00000010;dr3->dr7=0x00000040)
		isCPU = true;
		if (isCPU) {


			if (tzmAdress) {
				CPUSINGLE cpuu;
				//设置第一个硬件断点的数据
				cpuu.Dr = tzmAdress;
				cpuu.Dr7 = 0x405;
				cpuu.hkFun = (uintptr_t)HookFuncCpu;
				cpuu.size = 2;
				cpuu.of = true;
			}

			//if (jinbi) {
			//	CPUSINGLE cpuu;
			//	//设置第一个硬件断点的数据
			//	cpuu.Dr = jinbi;
			//	cpuu.Dr7 = 0x405;
			//	cpuu.hkFun = (uintptr_t)HOOKjinbi;
			//	cpuu.size = 3;
			//	cpuu.of = 1;
			//	/*sprintf_s(str, 1024, "jinbi=%016I64X\ncpuu.Dr=%016I64X\n", jinbi, cpuu.Dr);
			//	MessageBox(0, str, "jinbi", MB_SYSTEMMODAL);*/
			//	exceptionInfo.push_back(cpuu);
			//}
			//if (maxhp) {
			//	CPUSINGLE cpuu;
			//	//设置第二个硬件断点的数据
			//	cpuu.Dr = 0;
			//	cpuu.Dr = maxhp;
			//	cpuu.Dr7 = 0x405;
			//	cpuu.hkFun = (uintptr_t)HOOKmaxhp;
			//	cpuu.size = 5;
			//	cpuu.of = 1;
			//	exceptionInfo.push_back(cpuu);
			//}



			//通过硬件断点触发VEH异常
			SetHook();
		}
		else
		{
			//设置GUARD_PAGE断点信息
			guardInfo.push_back(GUARD_PAGES{ (ULONG_PTR)tzmAdress ,(ULONG_PTR)HookFunc ,2,true,0 });
			//设置页面权限触发VEH异常
			Hook();
		}
		break;
		//主线程加载DLL后，创建一个新的进程的时候触发
	case DLL_THREAD_ATTACH:

		//硬件断点需要在新线程创建时也hook
		if (isCPU)
		{
			for (size_t i = 0; i < exceptionInfo.size(); i++)
				if (exceptionInfo[i].of)
					SetThreadHook(GetCurrentThread());
		}

		break;
		//当进程中关闭线程的时候触发
	case DLL_THREAD_DETACH:
		break;
		//当该DLL映像被进程卸载的时候触发
	case DLL_PROCESS_DETACH:

		//卸载所有VEH
		for (size_t i = 0; i < veh_Handle.size(); i++)
			RemoveVectoredExceptionHandler(veh_Handle[i]);

		//自定义操作
		MessageBox(0, "卸载DLL成功", "提示", MB_SYSTEMMODAL);
		break;
	}
	return TRUE;
}

