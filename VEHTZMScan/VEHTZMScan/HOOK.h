#pragma once
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include<tlhelp32.h>
#include<vector>

using namespace std;
//根据程序是64位还是32位初始化变量
#ifdef _WIN64
#define XAX Rax
#define XBX Rbx
#define XCX Rcx
#define XDX Rdx
#define XSI Rsi
#define XDI Rdi
#define XBP Rbp
#define XSP Rsp
#define XIP Rip
#else
#define XAX Eax
#define XBX Ebx
#define XCX Ecx
#define XDX Edx
#define XSI Esi
#define XDI Edi
#define XBP Ebp
#define XSP Esp
#define XIP Eip
#endif


//声明变量
PVOID VEH_Handle = nullptr;
char str[1024]{};

//将原始函数地址提供给asm文件使用
EXTERN_C uintptr_t ogAdress = 0;

//声明硬件断点结构
struct CPUSINGLE
{
	//硬件断点地址,hook地址
	uintptr_t Dr;
	//硬件断点控制位数据
	uintptr_t Dr7;
	//hook后自己在asm中实现的方法
	uintptr_t hkFun;
	//想要跳过的字节码长度
	uintptr_t size;
	//硬件断点是否启用
	bool of;
};

//声明GUARD_PAGE断点结构
struct GUARD_PAGES
{
	//标志位断点hook地址
	uintptr_t gpAdress;
	//hook后自己在asm中实现的方法
	uintptr_t hkFun;
	//想要跳过的字节码长度
	uintptr_t size;
	//是否启用断点
	bool ofGUARD_PAGE = true;
	//旧标志位
	DWORD oldProtection;
};

//声明硬件断点数组
vector<CPUSINGLE> exceptionInfo;

//声明GUARD_PAGE断点数组
vector<GUARD_PAGES> guardInfo;

//定义所有veh断点句柄数组
vector<PVOID> veh_Handle;

//声明方法
bool Hook();
bool AreInSamePage(const uint8_t* Addr1, const uint8_t* Addr2);
LONG WINAPI Handler(EXCEPTION_POINTERS* pExceptionInfo);



// _WIN64
#ifdef _WIN64

//替代原始函数执行的函数(已在汇编定义为保存寄存器->调用NewFunc->还原寄存器->调用下一句汇编)
EXTERN_C void HookFunc();

//替代原始函数执行的函数(已在汇编定义为保存寄存器->调用NewFunc->还原寄存器->调用下一句汇编)(硬件断点使用)
EXTERN_C void HookFuncCpu();

//自定义函数,可以进行一些骚操作,也可以替换成asm函数实现功能
EXTERN_C void NewFunc() {
	MessageBox(0, "进入asm文件的自定义函数!", "VEH Hook", MB_SYSTEMMODAL);
}

//自定义函数,可以进行一些骚操作,也可以替换成asm函数实现功能(硬件断点)
EXTERN_C void NewFuncCpu() {
	MessageBox(0, "进入asm文件的自定义函数!", "VEH Hook", MB_SYSTEMMODAL);
}
#else

//自定义函数,可以进行一些骚操作,也可以替换成asm函数实现功能
//void NewFunc() {
//	MessageBox(0, "进入asm文件的自定义函数!", "VEH Hook", MB_SYSTEMMODAL);
//}
EXTERN_C void NewFunc() {
	MessageBox(0, "进入asm文件的自定义函数!", "VEH Hook", MB_SYSTEMMODAL);
}

//自定义函数,可以进行一些骚操作,也可以替换成asm函数实现功能
void NewFuncCpu() {
	MessageBox(0, "进入asm文件的自定义函数!", "VEH Hook", MB_SYSTEMMODAL);
}

//替代原始函数执行的函数(已在汇编定义为保存寄存器->调用NewFunc->还原寄存器->调用下一句汇编)
EXTERN_C void HookFunc();

//替代原始函数执行的函数(已在汇编定义为保存寄存器->调用NewFunc->还原寄存器->调用下一句汇编)
EXTERN_C void HookFuncCpu();


EXTERN_C void HOOKjinbi();
EXTERN_C void HOOKmaxhp();

#endif 

//定义GUARD_PAGEVEH异常处理	ExceptionRecord-> 异常信息记录 ContextRecord-> 寄存器信息  返回-1：异常已处理，继续执行；返回0：继续调用VEH链的其它处理函数
LONG WINAPI  Handler(EXCEPTION_POINTERS* pExceptionInfo)
{
	//判断异常类型 STATUS_GUARD_PAGE_VIOLATION(GUARD_PAGE异常)  EXCEPTION_SINGLE_STEP(硬件断点异常)
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		//遍历所有断点
		for (size_t i = 0; i < guardInfo.size(); i++)
		{
			//判断是否为设置的异常位置
			if (pExceptionInfo->ContextRecord->XIP == (uintptr_t)guardInfo[i].gpAdress)
			{
				//根据程序是64位还是32位初始化变量
#ifdef _WIN64

			//自定义操作(Hook内容,可以操作寄存器)
				MessageBox(0, "进入VEH", "VEH Hook", MB_SYSTEMMODAL);
				MessageBox(0, "开始获取寄存器数据", "VEH Hook", MB_SYSTEMMODAL);


				sprintf_s(str, 1024, "RAX=%016I64X\nRBX=%016I64X\nRCX=%016I64X\nRDX=%016I64X\nRSI=%016I64X\nRDI=%016I64X\nRBP=%016I64X\nRSP=%016I64X\nR8=%016I64X\nR9=%016I64X\nR10=%016I64X\nR11=%016I64X\nR12=%016I64X\n",
					pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
					pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
					pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
					pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
					pExceptionInfo->ContextRecord->R8, pExceptionInfo->ContextRecord->R9,
					pExceptionInfo->ContextRecord->R10, pExceptionInfo->ContextRecord->R11,
					pExceptionInfo->ContextRecord->R12);

				MessageBox(0, str, "从VEH获取的寄存器数据:", MB_SYSTEMMODAL);

				//模拟修改寄存器数值
				//直接用其他寄存器数值替代
				//如果非dll注入需要memcpy函数操作内存
				//pExceptionInfo->ContextRecord->XCX = pExceptionInfo->ContextRecord->XDX;

				//手动赋值(需要跟原值类型匹配,测试程序是传递的指针,手动模拟了个指针)
				//pExceptionInfo->ContextRecord->Rcx = (DWORD64)0x7FF7DDA01360;

				/*sprintf_s(str, 1024, "RAX=%016I64X\nRBX=%016I64X\nRCX=%016I64X\nRDX=%016I64X\nRSI=%016I64X\nRDI=%016I64X\nRBP=%016I64X\nRSP=%016I64X\nR8=%016I64X\nR9=%016I64X\nR10=%016I64X\nR11=%016I64X\nR12=%016I64X\n",
					pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
					pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
					pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
					pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
					pExceptionInfo->ContextRecord->R8, pExceptionInfo->ContextRecord->R9,
					pExceptionInfo->ContextRecord->R10, pExceptionInfo->ContextRecord->R11,
					pExceptionInfo->ContextRecord->R12);

				MessageBox(0, str, "修改后获取的寄存器数据:", MB_SYSTEMMODAL);*/

				//将函数地址偏移X个字节到下一句汇编代码,X取决于hook的汇编代码长度,事后需要在asm里面还原原始汇编代码
				ogAdress = guardInfo[i].gpAdress + guardInfo[i].size;

				//如果hook汇编代码会导致asm无法调用方法,只能在这里进行取消hook
				DWORD old;
				VirtualProtect((LPVOID)guardInfo[i].gpAdress, 1, guardInfo[i].oldProtection, &old);

				//还需要让STATUS_SINGLE_STEP里面不继续添加,不然无限循环
				guardInfo[i].ofGUARD_PAGE = false;

				//跳转到自己的函数,还原跳过的汇编代码,然后jmp到函数地址+跳过的字节继续执行
				pExceptionInfo->ContextRecord->XIP = (uintptr_t)guardInfo[i].hkFun;

#else
//自定义修改消息框中的内容
//已知我们HOOK的函数是MessageBoxA，这个函数有四个参数，函数原型如下:/*int WINAPI MessageBoxA(  _In _opt_ HWND hWnd,_In_opt_ LPCSTR lpText,_In_opt_ LPCSTR lpCaption，_In_ UINT uType) ;*/
//那么在进入函数时，这四个参数分别位于ESP+Ox4、ESP+Ox8、ESP+0xC、ESP+0x10的位置上
//已知我们HOOK的函数是MessageBoxA，这个函数有四个参数，函数原型如下:/*int WINAPI MessageBoxA(  _In _opt_ HWND hWnd,_In_opt_ LPCSTR lpText,_In_opt_ LPCSTR lpCaption，_In_ UINT uType) ;*/
//那么在进入函数时，这四个参数分别位于ESP+Ox4、ESP+Ox8、ESP+0xC、ESP+0x10的位置上
//例如我们需要修改其中的lpText参数，那么这个参数就位于ESP+8的位置上，保存的是字符串的地址
//需要修改，首先我们需要准备一个替换用的字符串
// 

			//自定义操作(Hook内容,可以操作寄存器)
				MessageBox(0, "进入VEH", "VEH Hook", MB_SYSTEMMODAL);
				MessageBox(0, "开始获取寄存器数据", "VEH Hook", MB_SYSTEMMODAL);

				//输出寄存器数据
				sprintf_s(str, 1024, "XSP+4=%016I32X\nXSP+8=%016I32X\nEAX=%016I32X\nEBX=%016I32X\nECX=%016I32X\nEDX=%016I32X\nESI=%016I32X\nEDI=%016I32X\nEBP=%016I32X\nESP=%016I32X\nEIP=%016I32X\n",
					*(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x4), *(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x8),
					pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
					pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
					pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
					pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
					pExceptionInfo->ContextRecord->XIP);

				MessageBox(0, str, "从VEH获取的寄存器数据:", MB_SYSTEMMODAL);

				//模拟修改寄存器数值
				//直接用其他寄存器数值替代
				//*(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x4) = *(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x8);


				//输出寄存器数据
				/*sprintf_s(str, 1024, "XSP+4=%016I32X\nXSP+8=%016I32X\nEAX=%016I32X\nEBX=%016I32X\nECX=%016I32X\nEDX=%016I32X\nESI=%016I32X\nEDI=%016I32X\nEBP=%016I32X\nESP=%016I32X\nEIP=%016I32X\n",
					*(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x4), *(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x8),
					pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
					pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
					pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
					pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
					pExceptionInfo->ContextRecord->XIP);

				MessageBox(0, str, "修改后的寄存器数据:", MB_SYSTEMMODAL);*/

				//const char* szStr = "zxbly";
				//// 将ESP＋8强转成DWORD*，然后把值取出来，替换成szStr，szStr也需要强转
				//*(DWORD*)(pExceptionInfo->ContextRecord->Esp + 0x8) = (DWORD)szStr;



				///将函数地址偏移X个字节到下一句汇编代码,X取决于hook的汇编代码长度,事后需要在asm里面还原原始汇编代码
				ogAdress = guardInfo[i].gpAdress + guardInfo[i].size;

				//如果hook汇编代码会导致asm无法调用方法,只能在这里进行取消hook
				DWORD old;
				VirtualProtect((LPVOID)guardInfo[i].gpAdress, 1, guardInfo[i].oldProtection, &old);

				//还需要让STATUS_SINGLE_STEP里面不继续添加,不然无限循环
				guardInfo[i].ofGUARD_PAGE = false;

				//跳转到自己的函数,还原跳过的汇编代码,然后jmp到函数地址+跳过的字节继续执行
				pExceptionInfo->ContextRecord->XIP = (uintptr_t)guardInfo[i].hkFun;
#endif
			}
			//TF位设置成1，cpu进入单步调试模式；执行下一行指令时，同样会触发STATUS_SINGLE_STEP异常，会继续进入现在的这个if条件
			pExceptionInfo->ContextRecord->EFlags |= 0x100; //Will trigger an STATUS_SINGLE_STEP exception right after the next instruction get executed. In short, we come right back into this exception handler 1 instruction later

		//继续下一条指令
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	//还将捕获STATUS_SINGLE_STEP，这意味着刚刚发生了PAGE_GUARD异常,需要重新添加标志位
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		DWORD dwOld;
		for (size_t i = 0; i < guardInfo.size(); i++)
		{
			//判断是否为设置的异常位置并且设置启用
			if (guardInfo[i].ofGUARD_PAGE)
			{
				//重新应用PAGE_GUARD标志，因为每次触发它时，它都会被删除
				VirtualProtect((LPVOID)guardInfo[i].gpAdress, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld); //Reapply the PAGE_GUARD flag because every_time it is triggered, it get removes
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}

		//继续下一条指令
		return EXCEPTION_CONTINUE_EXECUTION;

	}
	//如果不是PAGE_GUARD或SINGLE_STEP，继续向下搜索异常处理列表以找到正确的处理程序
	return EXCEPTION_CONTINUE_SEARCH;
}
//定义硬件断点VEH异常处理	ExceptionRecord-> 异常信息记录 ContextRecord-> 寄存器信息  返回-1：异常已处理，继续执行；返回0：继续调用VEH链的其它处理函数
LONG WINAPI  CpuHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
	//判断异常类型 STATUS_GUARD_PAGE_VIOLATION(GUARD_PAGE异常)  EXCEPTION_SINGLE_STEP(硬件断点异常)
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		//判断是否为设置的异常位置
		for (size_t i = 0; i < exceptionInfo.size(); i++)
		{
			if (exceptionInfo[i].of && exceptionInfo[i].Dr == pExceptionInfo->ContextRecord->XIP)
			{
				//根据程序是64位还是32位初始化变量
#ifdef _WIN64

			//自定义操作(Hook内容,可以操作寄存器)
				MessageBox(0, "进入VEH", "VEH Hook", MB_SYSTEMMODAL);
				MessageBox(0, "开始获取寄存器数据", "VEH Hook", MB_SYSTEMMODAL);


				sprintf_s(str, 1024, "RAX=%016I64X\nRBX=%016I64X\nRCX=%016I64X\nRDX=%016I64X\nRSI=%016I64X\nRDI=%016I64X\nRBP=%016I64X\nRSP=%016I64X\nR8=%016I64X\nR9=%016I64X\nR10=%016I64X\nR11=%016I64X\nR12=%016I64X\n",
					pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
					pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
					pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
					pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
					pExceptionInfo->ContextRecord->R8, pExceptionInfo->ContextRecord->R9,
					pExceptionInfo->ContextRecord->R10, pExceptionInfo->ContextRecord->R11,
					pExceptionInfo->ContextRecord->R12);
				MessageBox(0, str, "从VEH获取的寄存器数据:", MB_SYSTEMMODAL);

				//模拟修改寄存器数值
				//直接用其他寄存器数值替代
				//如果非dll注入需要memcpy函数操作内存
				//pExceptionInfo->ContextRecord->XCX = pExceptionInfo->ContextRecord->XDX;

				//手动赋值(需要跟原值类型匹配,测试程序是传递的指针,手动模拟了个指针)
				//pExceptionInfo->ContextRecord->Rcx = (DWORD64)0x7FF7DDA01360;

				/*sprintf_s(str, 1024, "RAX=%016I64X\nRBX=%016I64X\nRCX=%016I64X\nRDX=%016I64X\nRSI=%016I64X\nRDI=%016I64X\nRBP=%016I64X\nRSP=%016I64X\nR8=%016I64X\nR9=%016I64X\nR10=%016I64X\nR11=%016I64X\nR12=%016I64X\n",
					pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
					pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
					pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
					pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
					pExceptionInfo->ContextRecord->R8, pExceptionInfo->ContextRecord->R9,
					pExceptionInfo->ContextRecord->R10, pExceptionInfo->ContextRecord->R11,
					pExceptionInfo->ContextRecord->R12);

				MessageBox(0, str, "修改后获取的寄存器数据:", MB_SYSTEMMODAL);*/

				//将函数地址偏移X个字节到下一句汇编代码,X取决于hook的汇编代码长度,事后需要在asm里面还原原始汇编代码
				ogAdress = exceptionInfo[i].Dr + exceptionInfo[i].size;
				//如果hook汇编代码会导致asm无法调用方法,只能在这里进行取消hook
				switch (i)
				{
				case 0:
					pExceptionInfo->ContextRecord->Dr0 = 0;
					break;
				case 1:
					pExceptionInfo->ContextRecord->Dr1 = 0;
					break;
				case 2:
					pExceptionInfo->ContextRecord->Dr2 = 0;
					break;;
				case 3:
					pExceptionInfo->ContextRecord->Dr3 = 0;
					break;
				default:
					break;
			}
				pExceptionInfo->ContextRecord->Dr7 = 0;
				exceptionInfo[i].of = 0;
				//TF位设置成1，cpu进入单步调试模式；执行下一行指令时，同样会触发STATUS_SINGLE_STEP异常，会继续进入现在的这个if条件；上面刚取消所有硬件断点，如果这里不设置单步模式，后续的硬件断点都会失效
				//pExceptionInfo->ContextRecord->EFlags |= 0x100;

				//跳转到自己的函数,还原跳过的汇编代码,然后jmp到函数地址+跳过的字节继续执行
				pExceptionInfo->ContextRecord->XIP = (uintptr_t)exceptionInfo[i].hkFun;
#else
//自定义修改消息框中的内容
//已知我们HOOK的函数是MessageBoxA，这个函数有四个参数，函数原型如下:/*int WINAPI MessageBoxA(  _In _opt_ HWND hWnd,_In_opt_ LPCSTR lpText,_In_opt_ LPCSTR lpCaption，_In_ UINT uType) ;*/
//那么在进入函数时，这四个参数分别位于ESP+Ox4、ESP+Ox8、ESP+0xC、ESP+0x10的位置上
//已知我们HOOK的函数是MessageBoxA，这个函数有四个参数，函数原型如下:/*int WINAPI MessageBoxA(  _In _opt_ HWND hWnd,_In_opt_ LPCSTR lpText,_In_opt_ LPCSTR lpCaption，_In_ UINT uType) ;*/
//那么在进入函数时，这四个参数分别位于ESP+Ox4、ESP+Ox8、ESP+0xC、ESP+0x10的位置上
//例如我们需要修改其中的lpText参数，那么这个参数就位于ESP+8的位置上，保存的是字符串的地址
//需要修改，首先我们需要准备一个替换用的字符串
// 

			//自定义操作(Hook内容,可以操作寄存器)
				//MessageBox(0, "进入VEH", "VEH Hook", MB_SYSTEMMODAL);
				//MessageBox(0, "开始获取寄存器数据", "VEH Hook", MB_SYSTEMMODAL);

				////输出寄存器数据
				//sprintf_s(str, 1024, "XSP+4=%016I32X\nXSP+8=%016I32X\nEAX=%016I32X\nEBX=%016I32X\nECX=%016I32X\nEDX=%016I32X\nESI=%016I32X\nEDI=%016I32X\nEBP=%016I32X\nESP=%016I32X\nEIP=%016I32X\n",
				//	*(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x4), *(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x8),
				//	pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
				//	pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
				//	pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
				//	pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
				//	pExceptionInfo->ContextRecord->XIP);

				//MessageBox(0, str, "从VEH获取的寄存器数据:", MB_SYSTEMMODAL);

				//模拟修改寄存器数值
				//直接用其他寄存器数值替代
				//*(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x4) = *(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x8);


				//输出寄存器数据
				/*sprintf_s(str, 1024, "XSP+4=%016I32X\nXSP+8=%016I32X\nEAX=%016I32X\nEBX=%016I32X\nECX=%016I32X\nEDX=%016I32X\nESI=%016I32X\nEDI=%016I32X\nEBP=%016I32X\nESP=%016I32X\nEIP=%016I32X\n",
					*(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x4), *(DWORD*)(pExceptionInfo->ContextRecord->XSP + 0x8),
					pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
					pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
					pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
					pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
					pExceptionInfo->ContextRecord->XIP);

				MessageBox(0, str, "修改后的寄存器数据:", MB_SYSTEMMODAL);*/

				//const char* szStr = "zxbly";
				//// 将ESP＋8强转成DWORD*，然后把值取出来，替换成szStr，szStr也需要强转
				//*(DWORD*)(pExceptionInfo->ContextRecord->Esp + 0x8) = (DWORD)szStr;


				//将函数地址偏移X个字节到下一句汇编代码,X取决于hook的汇编代码长度,事后需要在asm里面还原原始汇编代码
				ogAdress = exceptionInfo[i].Dr + exceptionInfo[i].size;
				//如果hook汇编代码会导致asm无法调用方法,只能在这里进行取消hook
				//如果只希望执行一次这里取消所有的硬件断点，不仅仅是当前的
				switch (i)
				{
				case 0:
					pExceptionInfo->ContextRecord->Dr0 = 0;
					break;
				case 1:
					pExceptionInfo->ContextRecord->Dr1 = 0;
					break;
				case 2:
					pExceptionInfo->ContextRecord->Dr2 = 0;
					break;;
				case 3:
					pExceptionInfo->ContextRecord->Dr3 = 0;
					break;
				default:
					break;
				}
				pExceptionInfo->ContextRecord->Dr7 = 0;
				exceptionInfo[i].of = 0;
				//TF位设置成1，cpu进入单步调试模式；执行下一行指令时，同样会触发STATUS_SINGLE_STEP异常，会继续进入现在的这个if条件；上面刚取消所有硬件断点，如果这里不设置单步模式，后续的硬件断点都会失效
				//pExceptionInfo->ContextRecord->EFlags |= 0x100;
				//跳转到自己的函数,还原跳过的汇编代码,然后jmp到函数地址+跳过的字节继续执行
				pExceptionInfo->ContextRecord->XIP = (uintptr_t)exceptionInfo[i].hkFun;
#endif
		}
			else
			{
				//避免硬件断点失效再设置一次
				switch (i)
				{
				case 0:
					pExceptionInfo->ContextRecord->Dr0 = exceptionInfo[i].Dr;
					break;
				case 1:
					pExceptionInfo->ContextRecord->Dr1 = exceptionInfo[i].Dr;
					break;
				case 2:
					pExceptionInfo->ContextRecord->Dr2 = exceptionInfo[i].Dr;
					break;;
				case 3:
					pExceptionInfo->ContextRecord->Dr3 = exceptionInfo[i].Dr;
					break;
				default:
					break;
				}

				pExceptionInfo->ContextRecord->Dr7 = exceptionInfo[i].Dr7;
			}
	}
		//继续下一条指令
		return EXCEPTION_CONTINUE_EXECUTION;
}

	//如果不是硬件断点异常，继续向下搜索异常处理列表以找到正确的处理程序
	return EXCEPTION_CONTINUE_SEARCH;
}

//判断是否是同一个页面的方法
bool  AreInSamePage(const uint8_t* Addr1, const uint8_t* Addr2)
{
	MEMORY_BASIC_INFORMATION mbi1;
	//获取Addr1的页面信息
	if (!VirtualQuery(Addr1, &mbi1, sizeof(mbi1)))
		return true;

	MEMORY_BASIC_INFORMATION mbi2;
	//获取Addr2的页面信息
	if (!VirtualQuery(Addr2, &mbi2, sizeof(mbi2)))
		return true;
	//检查是否为同一个页面
	if (mbi1.BaseAddress == mbi2.BaseAddress)
		//两个地址都在同一页中，中止挂钩！
		return true;
	return false;
}

//开启HOOK,第一个参数为HOOK点,第二个为自定义方法
bool  Hook()
{
	for (size_t i = 0; i < guardInfo.size(); i++)
	{
		//我们不能在同一页中钩住两个函数，因为我们将导致无限回调
		if (AreInSamePage((const uint8_t*)guardInfo[i].gpAdress, (const uint8_t*)guardInfo[i].hkFun))
			return false;
		//注册自定义异常处理程序	First：是否插入VEH链头部。Handler：异常处理函数。
		VEH_Handle = AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)Handler);
		veh_Handle.push_back(VEH_Handle);
		//切换页面上的PAGE_GUARD标志
		if (VEH_Handle && VirtualProtect((LPVOID)guardInfo[i].gpAdress, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &(guardInfo[i].oldProtection)))
			return true;
	}

	return false;
}


//设置线程的硬件断点
VOID SetThreadHook(HANDLE hThread) {
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &ctx);
	for (size_t i = 0; i < exceptionInfo.size(); i++)
	{
		if (exceptionInfo[i].of)
		{
			switch (i)
			{
			case 0:
				ctx.Dr0 = exceptionInfo[i].Dr;
				break;
			case 1:
				ctx.Dr1 = exceptionInfo[i].Dr;
				break;
			case 2:
				ctx.Dr2 = exceptionInfo[i].Dr;
				break;
			case 3:
				ctx.Dr3 = exceptionInfo[i].Dr;
				break;
			default:
				break;
			}
		}
	}
	ctx.Dr7 = 0x405;
	SetThreadContext(hThread, &ctx);
}

//设置硬件断点
VOID SetHook() {

	//设置异常断点
	VEH_Handle = AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)CpuHandler);
	veh_Handle.push_back(VEH_Handle);
	//遍历线程 通过openthread获取到线程环境后设置硬件断点
	HANDLE hThreadShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hThreadShot != INVALID_HANDLE_VALUE) {
		THREADENTRY32* ThreadInfo = new THREADENTRY32;
		ThreadInfo->dwSize = sizeof(THREADENTRY32);
		HANDLE hThread = NULL;
		//遍历线程
		while (Thread32Next(hThreadShot, ThreadInfo)) {
			//如果线程父进程ID为当前进程ID
			if (GetCurrentProcessId() == ThreadInfo->th32OwnerProcessID) {
				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadInfo->th32ThreadID);
				//暂停线程
				SuspendThread(hThread);
				//设置硬件断点
				SetThreadHook(hThread);
				//恢复线程
				ResumeThread(hThread);
				CloseHandle(hThread);
			}

		}

		CloseHandle(hThread);
	}
}


