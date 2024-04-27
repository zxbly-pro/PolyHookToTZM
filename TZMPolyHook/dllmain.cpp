// dllmain.cpp : 定义 DLL 应用程序的入口点。
//#include "pch.h"


//根据程序是64位还是32位初始化变量
#ifdef _WIN64
#else
#endif
#include "../heads/d3dhook.h"
#include "../heads/vehhook.h"
//函数声明
ULONG64 ScanTZM(PCHAR tzm);
//设置是否是硬件断点(硬件断点只有4个,不会破坏汇编代码;页面权限断点可以无数个,但是会更改内存属性)
bool isCPU = true;
char str[1024]{};
extern ULONG64 tzmAdress;

ULONG64 nowhp = 0, jinbi = 0;
//DLL入口
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	isCPU = false;
	switch (ul_reason_for_call)
	{
		//主线程加载DLL后触发
	case DLL_PROCESS_ATTACH:
		//进行d3dhook
		//CreateThread(NULL, 0, InitHooks, NULL, 0, NULL);
		//-----------------------------------------------------------------------------------------------
		//使用硬件断点
		isCPU = false;
		tzmAdress = ScanTZM("8B 89 80 01 00 00 81 F9 A0");
		jmpAdress = tzmAdress + 6;
		if (isCPU) {
			////初始化硬件断点
			//for (size_t i = 0; i < 4; i++)
			//	exceptionInfo.push_back(CPUSINGLE{ 0,0,0,0 });


			//sprintf_s(str, 1024, "%016I64X\n", tzmAdress);
			//MessageBox(0, str, "最终函数地址为:", MB_SYSTEMMODAL);
			//设置exceptionInfo向量的大小,否则会空指针
			exceptionInfo.resize(1);
			//设置第一个硬件断点的数据

			CPUSINGLE newCpuSingle;
			newCpuSingle.Dr = tzmAdress;
			newCpuSingle.Dr7 = 0x405;
			newCpuSingle.hkFun = (uintptr_t)moneyfuncCPU;
			newCpuSingle.size = 6;
			newCpuSingle.of = true;

			exceptionInfo.push_back(newCpuSingle);
			SetHook();

			////直接调用程序原有方法
			//void (*moeny)(LONG oldmoney, LONG newmoney)= (void (*)(LONG, LONG))tzmAdress;
			//LONG a = 0;
			//LONG b = 0;
			//moeny(a,b);

		}
		else
		{
			//设置GUARD_PAGE断点信息
			guardInfo.push_back(GUARD_PAGES{ (ULONG_PTR)tzmAdress ,(ULONG_PTR)moneyfunc ,6,true,0 });
			//MessageBox(0, "添加hook", "提示", MB_SYSTEMMODAL);
			//设置页面权限触发VEH异常
			Hook();
		}
		//-----------------------------------------------------------------------------------------------
		break;
		//主线程加载DLL后，创建一个新的进程的时候触发
	case DLL_THREAD_ATTACH:
		////硬件断点需要在新线程创建时也hook
		//for (size_t i = 0; i < exceptionInfo.size(); i++)
		//	if (exceptionInfo[i].of)
		//		SetThreadHook(GetCurrentThread(), exceptionInfo[i]);

		break;
		//当进程中关闭线程的时候触发
	case DLL_THREAD_DETACH:
		break;
		//当该DLL映像被进程卸载的时候触发
	case DLL_PROCESS_DETACH:
		//------------------------------------------------------------------------------------------------
		////d3dhook解除hook
		//presentHook->unHook();
		//resizeBuffersHook->unHook();
		//pSSetShaderResourcesHook->unHook();
		//drawHook->unHook();
		//drawIndexedHook->unHook();
		//drawIndexedInstancedHook->unHook();
		//------------------------------------------------------------------------------------------------
		//卸载所有VEH
		for (size_t i = 0; i < veh_Handle.size(); i++)
			RemoveVectoredExceptionHandler(veh_Handle[i]);
		break;
	}
	return TRUE;
}

