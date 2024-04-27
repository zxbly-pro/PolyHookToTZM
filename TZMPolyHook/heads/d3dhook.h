//d3d11 wallhack (main.h)

#pragma once
//编译器首次遇到该文件时，判断名称STR是否被定义过，如果是，直接执行#endif后面的语句；如果不是，执行#ifndef与#endif之间的语句
#ifndef STR
//如果上面判断STR未被定义过，用#define定义STR
#define STR
//#ifndef与#endif之间的语句,随便你写内容

//条件编译结束
#endif
//#include "../pch.h"
#include <intrin.h>
#include <d3d11.h>
#include <D3Dcompiler.h>
#include <tchar.h>
#include <atlstr.h>
#include <string>
#include "polyhook2/Detour/x64Detour.hpp"
#include <iostream>
#include <Windows.h>
#include <minwindef.h>
using namespace std;

#pragma comment(lib, "D3dcompiler.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "winmm.lib")

//imgui
#include "../resources/imgui/imgui.h"
#include "../resources/imgui/imgui_impl_win32.h"
#include "../resources/imgui/imgui_impl_dx11.h"
#include <timeapi.h>
EXTERN_C ULONG64 jmpAdress;
//声明变量来自于其他地方定义
extern char str[1024];

//声明需要的hook指针
extern unique_ptr<PLH::x64Detour> presentHook;
extern unique_ptr<PLH::x64Detour> resizeBuffersHook;
extern unique_ptr<PLH::x64Detour> pSSetShaderResourcesHook;
extern unique_ptr<PLH::x64Detour> drawHook;
extern unique_ptr<PLH::x64Detour> drawIndexedHook;
extern unique_ptr<PLH::x64Detour> drawIndexedInstancedHook;




#pragma warning( disable : 4244 )

//定义函数指针
typedef HRESULT(__stdcall* D3D11PresentHook) (IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags);
typedef HRESULT(__stdcall* D3D11ResizeBuffersHook) (IDXGISwapChain* pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags);
typedef void(__stdcall* D3D11PSSetShaderResourcesHook) (ID3D11DeviceContext* pContext, UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews);
typedef void(__stdcall* D3D11DrawHook) (ID3D11DeviceContext* pContext, UINT VertexCount, UINT StartVertexLocation);
typedef void(__stdcall* D3D11DrawIndexedHook) (ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);
typedef void(__stdcall* D3D11DrawIndexedInstancedHook) (ID3D11DeviceContext* pContext, UINT IndexCountPerInstance, UINT InstanceCount, UINT StartIndexLocation, INT BaseVertexLocation, UINT StartInstanceLocation);
typedef void(__stdcall* D3D11CreateQueryHook) (ID3D11Device* pDevice, const D3D11_QUERY_DESC* pQueryDesc, ID3D11Query** ppQuery);


DWORD __stdcall InitHooks(LPVOID);

//==========================================================================================================================

