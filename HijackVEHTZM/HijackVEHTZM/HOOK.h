#pragma once
#include <Windows.h>
#include <stdio.h>
#include <iostream>

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
//保存hook原始地址
uintptr_t og_fun;
//保存自定义方法地址
uintptr_t hk_fun;
PVOID VEH_Handle;
DWORD oldProtection;
char str[1024]{};

//声明方法
bool Hook(uintptr_t og_fun, uintptr_t hk_fun);
//bool Unhook();
bool AreInSamePage(const uint8_t* Addr1, const uint8_t* Addr2);
LONG WINAPI Handler(EXCEPTION_POINTERS* pExceptionInfo);

//取消HOOK(EXTERN_C供asm文件调用)
EXTERN_C bool  Unhook()
{
	MessageBox(0, "取消Hook", "VEH Hook", MB_SYSTEMMODAL);
	//定义旧标志
	DWORD old;
	if (VEH_Handle && //确保我们拥有注册VEH的有效句柄
		VirtualProtect((LPVOID)og_fun, 1, oldProtection, &old) && //还原旧标志
		RemoveVectoredExceptionHandler(VEH_Handle)) //卸载VEH
		return true;

	return false;
}

// _WIN64
#ifdef _WIN64

//将原始函数地址提供给asm文件使用
EXTERN_C INT64 ogAdress = 0;

//替代原始函数执行的函数(已在汇编定义为保存寄存器->调用Unhook->调用NewFunc->还原寄存器->调用原始函数)
EXTERN_C void HookFunc();

//自定义函数,可以进行一些骚操作,也可以替换成asm函数实现功能
EXTERN_C void NewFunc() {
	MessageBox(0, "进入asm文件的自定义函数!", "VEH Hook", MB_SYSTEMMODAL);
}
#else

//自定义函数,可以进行一些骚操作,也可以替换成asm函数实现功能
void NewFunc() {
	MessageBox(0, "进入asm文件的自定义函数!", "VEH Hook", MB_SYSTEMMODAL);
}

//__declspec(naked)禁止程序自动添加堆栈平衡,不加会被破坏堆栈,必须自己使用 RET 或 RET n 指令返回 (除非不返回，比如JMP到原函数); 
void __declspec(naked) HookFunc() {
	__asm {

		push eax;
		push ebx;
		push ecx;
		push edx;
		push esi;
		push edi;
		push ebp;
		push esp;
		call Unhook;
		call NewFunc;
		pop esp;
		pop ebp;
		pop edi;
		pop esi;
		pop edx;
		pop ecx;
		pop ebx;
		pop eax;
		jmp og_fun;

	}
}
#endif 






//定义VEH异常处理
LONG WINAPI  Handler(EXCEPTION_POINTERS* pExceptionInfo)
{
	//判断异常类型
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) //We will catch PAGE_GUARD Violation
	{

		//判断是否为设置的异常位置
		if (pExceptionInfo->ContextRecord->XIP == (uintptr_t)og_fun) //Make sure we are at the address we want within the page
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
			//pExceptionInfo->ContextRecord->Rcx = pExceptionInfo->ContextRecord->Rdx;

			//手动赋值(需要跟原值类型匹配,测试程序是传递的指针,手动模拟了个指针)
			//pExceptionInfo->ContextRecord->Rcx = (DWORD64)0x7FF7DDA01360;

			sprintf_s(str, 1024, "RAX=%016I64X\nRBX=%016I64X\nRCX=%016I64X\nRDX=%016I64X\nRSI=%016I64X\nRDI=%016I64X\nRBP=%016I64X\nRSP=%016I64X\nR8=%016I64X\nR9=%016I64X\nR10=%016I64X\nR11=%016I64X\nR12=%016I64X\n",
				pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
				pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
				pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
				pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
				pExceptionInfo->ContextRecord->R8, pExceptionInfo->ContextRecord->R9,
				pExceptionInfo->ContextRecord->R10, pExceptionInfo->ContextRecord->R11,
				pExceptionInfo->ContextRecord->R12);

			MessageBox(0, str, "修改后获取的寄存器数据:", MB_SYSTEMMODAL);


			//执行自定义方法(hk_fun),继续执行之前的方法(og_fun)
			//pExceptionInfo->ContextRecord->XIP = (uintptr_t)og_fun; //继续执行原函数
			pExceptionInfo->ContextRecord->XIP = (uintptr_t)hk_fun; //跳转到自己的函数,取消HOOK然后执行NewFunc,然后回到之前的函数地址继续执行,可用于初始化获取寄存器地址

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
			sprintf_s(str, 1024, "EAX=%016I32X\nEBX=%016I32X\nECX=%016I32X\nEDX=%016I32X\nESI=%016I32X\nEDI=%016I32X\nEBP=%016I32X\nESP=%016I32X\nEIP=%016I32X\n",
				pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
				pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
				pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
				pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
				pExceptionInfo->ContextRecord->XIP);

			MessageBox(0, str, "从VEH获取的寄存器数据:", MB_SYSTEMMODAL);

			//修改寄存器数据
			//pExceptionInfo->ContextRecord->XAX = (DWORD)0x270f;


			//输出寄存器数据
			sprintf_s(str, 1024, "EAX=%016I32X\nEBX=%016I32X\nECX=%016I32X\nEDX=%016I32X\nESI=%016I32X\nEDI=%016I32X\nEBP=%016I32X\nESP=%016I32X\nEIP=%016I32X\n",
				pExceptionInfo->ContextRecord->XAX, pExceptionInfo->ContextRecord->XBX,
				pExceptionInfo->ContextRecord->XCX, pExceptionInfo->ContextRecord->XDX,
				pExceptionInfo->ContextRecord->XSI, pExceptionInfo->ContextRecord->XDI,
				pExceptionInfo->ContextRecord->XBP, pExceptionInfo->ContextRecord->XSP,
				pExceptionInfo->ContextRecord->XIP);

			MessageBox(0, str, "修改后的寄存器数据:", MB_SYSTEMMODAL);

			//const char* szStr = "zxbly";
			//// 将ESP＋8强转成DWORD*，然后把值取出来，替换成szStr，szStr也需要强转
			//*(DWORD*)(pExceptionInfo->ContextRecord->Esp + 0x8) = (DWORD)szStr;

			//返回断点位置继续执行
			//pExceptionInfo->ContextRecord->XIP = (uintptr_t)og_fun;
			//跳过断点代码继续执行
			//pExceptionInfo->ContextRecord->XIP += 2;
			pExceptionInfo->ContextRecord->XIP = (uintptr_t)hk_fun;//跳转到自己的函数,取消HOOK然后执行NewFunc,然后回到之前的函数地址继续执行,可用于初始化获取寄存器地址

#endif
		}
		//自定义将在执行下一条指令后立即触发STATUS_SINGLE_STEP异常。简而言之，我们稍后将返回到这个异常处理程序1指令
		pExceptionInfo->ContextRecord->EFlags |= 0x100; //Will trigger an STATUS_SINGLE_STEP exception right after the next instruction get executed. In short, we come right back into this exception handler 1 instruction later
		//继续下一条指令
		return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
	}

	//我们还将捕获STATUS_SINGLE_STEP，这意味着我们刚刚发生了PAGE_GUARD冲突
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) //We will also catch STATUS_SINGLE_STEP, meaning we just had a PAGE_GUARD violation
	{
		DWORD dwOld;
		//重新应用PAGE_GUARD标志，因为每次触发它时，它都会被删除
		VirtualProtect((LPVOID)og_fun, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld); //Reapply the PAGE_GUARD flag because every_time it is triggered, it get removes
		//继续下一条指令
		return EXCEPTION_CONTINUE_EXECUTION; //Continue the next instruction
	}
	//如果不是PAGE_GUARD或SINGLE_STEP，请继续向下搜索异常处理列表以找到正确的处理程序
	return EXCEPTION_CONTINUE_SEARCH; //Keep going down the exception handling list to find the right handler IF it is not PAGE_GUARD nor SINGLE_STEP
}

//判断是否是同一个页面的方法
bool  AreInSamePage(const uint8_t* Addr1, const uint8_t* Addr2)
{
	MEMORY_BASIC_INFORMATION mbi1;
	//获取Addr1的页面信息
	if (!VirtualQuery(Addr1, &mbi1, sizeof(mbi1))) //Get Page information for Addr1
		return true;

	MEMORY_BASIC_INFORMATION mbi2;
	//获取Addr2的页面信息
	if (!VirtualQuery(Addr2, &mbi2, sizeof(mbi2))) //Get Page information for Addr1
		return true;
	//检查是否为同一个页面
	if (mbi1.BaseAddress == mbi2.BaseAddress) //See if the two pages start at the same Base Address
		//两个地址都在同一页中，中止挂钩！
		return true; //Both addresses are in the same page, abort hooking!

	return false;
}

//开启HOOK,第一个参数为HOOK点,第二个为自定义方法
bool  Hook(uintptr_t original_fun, uintptr_t hooked_fun)
{
	//初始化变量
	og_fun = 0;
	hk_fun = 0;
	VEH_Handle = nullptr;
	oldProtection = 0;


	//赋值变量
	og_fun = original_fun;
	hk_fun = hooked_fun;

#ifdef _WIN64
	//复制一份原始函数地址供asm文件调用
	ogAdress = original_fun;
#endif // _WIN64



	//我们不能在同一页中钩住两个函数，因为我们将导致无限回调
	if (AreInSamePage((const uint8_t*)og_fun, (const uint8_t*)hk_fun))
		return false;

	//注册自定义异常处理程序
	VEH_Handle = AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)Handler);

	//切换页面上的PAGE_GUARD标志
	if (VEH_Handle && VirtualProtect((LPVOID)og_fun, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtection))
		return true;

	return false;
}


