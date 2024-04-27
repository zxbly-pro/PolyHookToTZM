#pragma once
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <tlhelp32.h>
#include <vector>
//编译器首次遇到该文件时，判断名称STR是否被定义过，如果是，直接执行#endif后面的语句；如果不是，执行#ifndef与#endif之间的语句
#ifndef STR
//如果上面判断STR未被定义过，用#define定义STR
#define STR
//#ifndef与#endif之间的语句,随便你写内容
//条件编译结束
#endif
//声明变量来自于其他地方定义
extern char str[1024];
using namespace std;
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

//定义所有veh断点句柄数组
extern vector<PVOID> veh_Handle;

extern VOID SetThreadHook(HANDLE hThread, CPUSINGLE cpus);
EXTERN_C void moneyfunc();
EXTERN_C void moneyfuncCPU();
//声明硬件断点数组
extern vector<CPUSINGLE> exceptionInfo;

//声明GUARD_PAGE断点数组
extern vector<GUARD_PAGES> guardInfo;
//声明普通断点HOOK
extern bool  Hook();
//声明硬件断点HOOK
extern VOID SetHook();