#pragma once
#include <Windows.h>

//VOID Test();

SIZE_T FindMemoryTZM(CONST DWORD pid, ULONG64* buffer, CONST ULONG bufferCount, CONST PCHAR tzm, CONST ULONG64 startAddr = 0x401000, CONST ULONG64 endAddr = 0x7FFFFFFFFFFF);