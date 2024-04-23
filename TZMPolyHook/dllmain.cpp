// dllmain.cpp : 定义 DLL 应用程序的入口点。
//#include "pch.h"


//根据程序是64位还是32位初始化变量
#ifdef _WIN64
#else
#endif
#include "../heads/d3dhook.h"

//DLL入口
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
		//主线程加载DLL后触发
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, 0, InitHooks, NULL, 0, NULL);
		break;
		//主线程加载DLL后，创建一个新的进程的时候触发
	case DLL_THREAD_ATTACH:
		//当进程中关闭线程的时候触发
		break;
	case DLL_THREAD_DETACH:
		break;
		//当该DLL映像被进程卸载的时候触发
	case DLL_PROCESS_DETACH:
		presentHook->unHook();
		resizeBuffersHook->unHook();
		pSSetShaderResourcesHook->unHook();
		drawHook->unHook();
		drawIndexedHook->unHook();
		drawIndexedInstancedHook->unHook();
		break;
	}
	return TRUE;
}

