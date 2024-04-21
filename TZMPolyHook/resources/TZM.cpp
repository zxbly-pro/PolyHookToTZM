#include<Windows.h>
#include <atlstr.h>
#include<vector>
#include<time.h>
#include<iostream>

//每次读取内存的最大大小
#define BLOCKMAXSIZE 409600

//每次将读取的内存读入这里
BYTE* MemoryData;

SHORT Next[260];

//特征码转字节集
WORD HecToDec(char* Tzm, WORD* tzmArray)
{
	int len = 0;
	WORD tzmLength = strlen(Tzm) / 3 + 1;
	//将十六进制特征码转为十进制
	for (int i = 0; i < strlen(Tzm); )
	{
		char num[2];
		num[0] = Tzm[i++];
		num[1] = Tzm[i++];
		i++;
		if (num[0] != '?' && num[1] != '?')
		{
			int sum = 0;
			WORD a[2];
			for (int i = 0; i < 2; i++)
			{
				if (num[i] >= '0' && num[i] <= '9')
				{
					a[i] = num[i] - '0';
				}
				else if (num[i] >= 'a' && num[i] <= 'z')
				{
					a[i] = num[i] - 87;
				}
				else if (num[i] >= 'A' && num[i] <= 'Z')
				{
					a[i] = num[i] - 55;
				}

			}
			sum = a[0] * 16 + a[1];
			tzmArray[len++] = sum;
		}
		else
		{
			tzmArray[len++] = 256;
		}
	}
	return tzmLength;
}

//扫描StartAddress开始的size块内存
void SearchMemoryBlock(HANDLE hProcess, WORD* Tzm, WORD tzmLength, ULONG64 StartAddress, ULONG size, std::vector<ULONG64>& ResultArray)
{
	if (!ReadProcessMemory(hProcess, (LPCVOID)StartAddress, MemoryData, size, NULL))
	{
		return;
	}

	for (int i = 0, j, k; i < size;)
	{
		j = i; k = 0;
		//特征码（字节集）的每个字节的范围在0-255（0-FF）之间，256用来表示问号，到260是为了防止越界
		for (; k < tzmLength && j < size && (Tzm[k] == MemoryData[j] || Tzm[k] == 256); k++, j++);

		if (k == tzmLength)
		{
			ResultArray.push_back(StartAddress + i);
		}

		if ((i + tzmLength) >= size)
		{
			return;
		}

		int num = Next[MemoryData[i + tzmLength]];
		if (num == -1)
			//如果特征码有问号，就从问号处开始匹配，如果没有就i+=-1
			i += (tzmLength - Next[256]);
		else
			i += (tzmLength - num);
	}
}

//搜索整个程序
int SearchMemory(HANDLE hProcess, char* Tzm, ULONG64 StartAddress, ULONG64 EndAddress, int InitSize, std::vector<ULONG64>& ResultArray)
{
	int i = 0;
	unsigned long BlockSize;
	MEMORY_BASIC_INFORMATION mbi;

	WORD tzmLength = strlen(Tzm) / 3 + 1;
	WORD* tzmArray = new WORD[tzmLength];

	HecToDec(Tzm, tzmArray);
	for (int i = 0; i < 260; i++)
		Next[i] = -1;
	for (int i = 0; i < tzmLength; i++)
		Next[tzmArray[i]] = i;
	//初始化结果数组
	ResultArray.clear();
	ResultArray.reserve(InitSize);

	while (VirtualQueryEx(hProcess, (LPCVOID)StartAddress, &mbi, sizeof(mbi)) != 0)
	{
		//页面保护属性
		if (//只读
			mbi.Protect == PAGE_READONLY ||
			//可读写
			mbi.Protect == PAGE_READWRITE ||
			//可执行
			mbi.Protect == PAGE_EXECUTE ||
			//可读可执行
			mbi.Protect == PAGE_EXECUTE_READ ||
			//可读可执行可写
			mbi.Protect == PAGE_EXECUTE_READWRITE)
		{
			i = 0;
			BlockSize = mbi.RegionSize;
			//搜索这块内存
			while (BlockSize >= BLOCKMAXSIZE)
			{
				SearchMemoryBlock(hProcess, tzmArray, tzmLength, StartAddress + (BLOCKMAXSIZE * i), BLOCKMAXSIZE, ResultArray);
				BlockSize -= BLOCKMAXSIZE; i++;
			}
			SearchMemoryBlock(hProcess, tzmArray, tzmLength, StartAddress + (BLOCKMAXSIZE * i), BlockSize, ResultArray);

		}
		StartAddress += mbi.RegionSize;

		if (EndAddress != 0 && StartAddress > EndAddress)
		{
			delete[] tzmArray;
			return ResultArray.size();
		}
	}
	delete[] tzmArray;
	return ResultArray.size();
}

//寻找特征码
SIZE_T FindMemoryTZM(CONST DWORD pid, ULONG64* buffer, CONST ULONG bufferCount, CONST PCHAR tzm, ULONG64 startAddr, ULONG64 endAddr) {
	MemoryData = new BYTE[BLOCKMAXSIZE];
	std::vector<ULONG64> ResultArray;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

	SearchMemory(hProcess, tzm, startAddr, endAddr, bufferCount, ResultArray);

	for (std::vector<ULONG64>::iterator it = ResultArray.begin(); it != ResultArray.end(); it++)
	{
		memcpy(buffer++, &*it, sizeof LPVOID);
	}
	delete[] MemoryData;
	return ResultArray.size();
}
//根据函数特征码扫描获取函数地址
ULONG64 ScanTZM(PCHAR tzm) {

	char str[1024]{};
	//输出结果
	std::string res = "";
	//接收结果数组
	ULONG64 addr[128] = { 0 };
	ULONG64 size = 0;
	//获取当前程序pid
	int pid = _getpid();

	//记录特征码数量
	SIZE_T count = 0;

	//扫描特征码(如果劫持注入只能扫描到静态地址的TZM,因为还没初始化完成)
	count = FindMemoryTZM(pid, addr, sizeof(addr) / 8, tzm, 0x0000000000000000, 0x7FFFFFFFFFFF);

	//输出结果地址
	for (int i = 0; i < count; i++)
	{
		sprintf_s(str, 100, "%016I64X长度%d\n", addr[i], strlen(tzm) / 3 + 1);
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
		return addr[0];
		break;
	}
	return 0;

}
