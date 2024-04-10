// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "heads/TZM.h"
#include <intrin.h>
#include <d3d11.h>
#include <D3Dcompiler.h>
#include <tchar.h>
#include <atlstr.h>
#include <string>
#include "polyhook2/Detour/x64Detour.hpp"
#include "heads/main.h"
#include <iostream>
#include <Windows.h>

using namespace std;

#pragma comment(lib, "D3dcompiler.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "winmm.lib")

//imgui
#include "resources/imgui/imgui.h"
#include "resources/imgui/imgui_impl_win32.h"
#include "resources/imgui/imgui_impl_dx11.h"
#include <timeapi.h>


//原Detour需要的lib文件和头文件
//#include "detours.h"
//#if defined _M_X64
//#pragma comment(lib, "detours.X64/detours.lib")
//#elif defined _M_IX86
//#pragma comment(lib, "detours.X86/detours.lib")
//#endif


//创建hook对象指针

unique_ptr<PLH::x64Detour> presentHook;
unique_ptr<PLH::x64Detour> resizeBuffersHook;
unique_ptr<PLH::x64Detour> pSSetShaderResourcesHook;
unique_ptr<PLH::x64Detour> drawHook;
unique_ptr<PLH::x64Detour> drawIndexedHook;
unique_ptr<PLH::x64Detour> drawIndexedInstancedHook;

//unique_ptr<PLH::x64Detour> createQueryHook;



//备份hook函数原始地址
uint64_t presentHookRedirectOld;
uint64_t resizeBuffersHookRedirectOld;
uint64_t pSSetShaderResourcesHookRedirectOld;
uint64_t drawHookRedirectOld;
uint64_t drawIndexedHookRedirectOld;
uint64_t drawIndexedInstancedHookRedirectOld;

//uint64_t createQueryHookRedirectOld;


#pragma warning( disable : 4244 )

//定义函数指针
typedef HRESULT(__stdcall* D3D11PresentHook) (IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags);
typedef HRESULT(__stdcall* D3D11ResizeBuffersHook) (IDXGISwapChain* pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags);
typedef void(__stdcall* D3D11PSSetShaderResourcesHook) (ID3D11DeviceContext* pContext, UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews);
typedef void(__stdcall* D3D11DrawHook) (ID3D11DeviceContext* pContext, UINT VertexCount, UINT StartVertexLocation);
typedef void(__stdcall* D3D11DrawIndexedHook) (ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);
typedef void(__stdcall* D3D11DrawIndexedInstancedHook) (ID3D11DeviceContext* pContext, UINT IndexCountPerInstance, UINT InstanceCount, UINT StartIndexLocation, INT BaseVertexLocation, UINT StartInstanceLocation);
typedef void(__stdcall* D3D11CreateQueryHook) (ID3D11Device* pDevice, const D3D11_QUERY_DESC* pQueryDesc, ID3D11Query** ppQuery);

//初始化
D3D11PresentHook phookD3D11Present = NULL;
D3D11ResizeBuffersHook phookD3D11ResizeBuffers = NULL;
D3D11PSSetShaderResourcesHook phookD3D11PSSetShaderResources = NULL;
D3D11DrawHook phookD3D11Draw = NULL;
D3D11DrawIndexedHook phookD3D11DrawIndexed = NULL;
D3D11DrawIndexedInstancedHook phookD3D11DrawIndexedInstanced = NULL;
D3D11CreateQueryHook phookD3D11CreateQuery = NULL;

ID3D11Device* pDevice = NULL;
ID3D11DeviceContext* pContext = NULL;

DWORD_PTR* pSwapChainVtable = NULL;
DWORD_PTR* pContextVTable = NULL;
DWORD_PTR* pDeviceVTable = NULL;


// 设置为1禁用多采样
const int MultisampleCount = 1;


char str[1024]{};
ULONG64 tzmAdress;

EXTERN_C ULONG64 jmpAdress = 0;
//函数声明
ULONG64 ScanTZM(PCHAR tzm);
uint64_t oldAdress;
int sum = 0;
void initTZM();
unique_ptr<PLH::x64Detour> detour;

EXTERN_C void jmpFunction();

//根据函数特征码扫描获取函数地址
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
		MessageBox(0, res.c_str(), "唯一TZM地址:", MB_SYSTEMMODAL);
		return addr[0];
		break;
	default:
		MessageBox(0, res.c_str(), "扫描到多个TZM地址:", MB_SYSTEMMODAL);
		return 0;
		break;
	}
	return 0;

}

//初始化需要的TZM数据
void initTZM()
{
	//tzmAdress = ScanTZM("48 89 54 24 10 48 89 4C 24 08 57 48 81 EC 40 04 00 00 48");// tttt.exe+4390 - 48 89 54 24 10        - mov [rsp+10],rdx
	tzmAdress = ScanTZM("89 01 48 8B 84 24 50 04 00 00 8B");// tttt.exe+4469 - 89 01                 - mov [rcx],eax
														 // tttt.exe+446B - 48 8B 84 24 50040000  - mov rax,[rsp+00000450]

}

void hookFunction() {
	sprintf_s(str, 100, "第%d次hook\n", sum);
	MessageBox(0, str, "提示", MB_SYSTEMMODAL);
	if (sum == 5)
	{
		sprintf_s(str, 100, "第%d次hook,开始取消hook\n", sum);
		MessageBox(0, str, "提示", MB_SYSTEMMODAL);
		detour->unHook();
	}
	sum++;
}

void hookTest() {
	initTZM();
	jmpAdress = tzmAdress + 10;
	detour = make_unique<PLH::x64Detour>((uint64_t)(tzmAdress), (uint64_t)&jmpFunction, &oldAdress);
	detour->hook();
}

//回调函数
LRESULT CALLBACK DXGIMsgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) { return DefWindowProc(hwnd, uMsg, wParam, lParam); }

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// 键鼠事件的回调函数
LRESULT CALLBACK hWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	ImGuiIO& io = ImGui::GetIO();
	POINT mPos;
	GetCursorPos(&mPos);
	ScreenToClient(window, &mPos);
	ImGui::GetIO().MousePos.x = mPos.x;
	ImGui::GetIO().MousePos.y = mPos.y;
	//当释放非系统键时，发布到具有键盘焦点的窗口。
	if (uMsg == WM_KEYUP)
	{
		//判断是否为INSERT键
		if (wParam == VK_INSERT)
		{
			//如果imgui状态为显示
			if (ShowMenu)
				io.MouseDrawCursor = true;
			else
				io.MouseDrawCursor = false;
		}
	}

	if (ShowMenu)
	{
		// 由imgui处理消息
		ImGui_ImplWin32_WndProcHandler(hWnd, uMsg, wParam, lParam);
		//return true;
		return CallWindowProc(OriginalWndProcHandler, hWnd, uMsg, wParam, lParam);
	}
	// 将消息传递给下一窗口
	return CallWindowProc(OriginalWndProcHandler, hWnd, uMsg, wParam, lParam);
}

//==========================================================================================================================
// HOOK渲染函数
HRESULT __stdcall hookD3D11Present(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
{
	//Log("hookD3D11Present\n");
	// 判断是否第一次初始化
	if (firstTime)
	{
		Log("初始化\n");
		firstTime = false; //only once

		// 获取指向创建此接口的设备的指针。
		if (SUCCEEDED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pDevice)))
		{
			// SwapChain = pSwapChain;
			// 获取指向创建此接口的设备的指针。
			pSwapChain->GetDevice(__uuidof(pDevice), (void**)&pDevice);
			// GetImmediateContext获取可回放命令列表的即时上下文。GetImmediateContext方法返回一个ID3D11DeviceContext对象，该对象表示用于执行要立即提交给设备的呈现的即时上下文。
			// 对于大多数应用程序，直接上下文是用于绘制场景的主要对象。
			// GetImmediateContext方法将直接上下文的引用计数递增 1。因此，您必须在使用完返回的接口指针时调用Release以避免内存泄漏。
			pDevice->GetImmediateContext(&pContext);
		}

		//imgui
		// 描述交换链。
		DXGI_SWAP_CHAIN_DESC sd;
		// 获取适配器 (或视频卡) 的 DXGI 1.0 说明。
		pSwapChain->GetDesc(&sd);
		ImGui::CreateContext();
		ImGuiIO& io = ImGui::GetIO(); (void)io;
		// 加载中文字体
		io.Fonts->AddFontFromFileTTF("c:/windows/fonts/simhei.ttf", 13.0f, NULL, io.Fonts->GetGlyphRangesChineseSimplifiedCommon());

		// 用鼠标控制菜单
		ImGui::GetIO().WantCaptureMouse || ImGui::GetIO().WantTextInput || ImGui::GetIO().WantCaptureKeyboard;

		// 启用键盘控制
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
		window = sd.OutputWindow;

		// SetWindowLongPtr更改指定窗口的属性。 该函数还会在额外窗口内存中的指定偏移量设置值。
		OriginalWndProcHandler = (WNDPROC)SetWindowLongPtr(window, GWLP_WNDPROC, (LONG_PTR)hWndProc);

		ImGui_ImplWin32_Init(window);
		ImGui_ImplDX11_Init(pDevice, pContext);
		ImGui::GetIO().ImeWindowHandle = window;

		// D3D11_DEPTH_STENCIL_DESC描述深度模具状态。
		D3D11_DEPTH_STENCIL_DESC depthStencilDesc;
		// 是否启用深度测试。
		depthStencilDesc.DepthEnable = TRUE;
		// 深度值写入掩码
		depthStencilDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
		// 深度比较函数。
		depthStencilDesc.DepthFunc = D3D11_COMPARISON_ALWAYS;
		// 是否启用模具测试。
		depthStencilDesc.StencilEnable = FALSE;
		// 模板值读取掩码
		depthStencilDesc.StencilReadMask = D3D11_DEFAULT_STENCIL_READ_MASK;
		// 模板值写入掩码
		depthStencilDesc.StencilWriteMask = D3D11_DEFAULT_STENCIL_WRITE_MASK;
		// FrontFace：该结构体指定了不同测试结果下对模板值应做什么样的更新（对于正面朝向的三角形）
		// 若模板测试不通过对深度/模板缓冲区的模板值部分的操作
		depthStencilDesc.FrontFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;
		// 若模板测试通过，但深度测试不通过对深度/模板缓冲区的模板值部分的操作
		depthStencilDesc.FrontFace.StencilDepthFailOp = D3D11_STENCIL_OP_INCR;
		// 若模板/深度测试通过对深度/模板缓冲区的模板值部分的操作
		depthStencilDesc.FrontFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
		// 模板测试所用的比较函数
		depthStencilDesc.FrontFace.StencilFunc = D3D11_COMPARISON_ALWAYS;
		// BackFace：该结构体指定了不同测试结果下对模板值应做什么样的更新（对于背面朝向的三角形）
		// 若模板测试不通过对深度/模板缓冲区的模板值部分的操作
		depthStencilDesc.BackFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;
		// 若模板测试通过，但深度测试不通过对深度/模板缓冲区的模板值部分的操作
		depthStencilDesc.BackFace.StencilDepthFailOp = D3D11_STENCIL_OP_DECR;
		// 若模板/深度测试通过对深度/模板缓冲区的模板值部分的操作
		depthStencilDesc.BackFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
		// 模板测试所用的比较函数
		depthStencilDesc.BackFace.StencilFunc = D3D11_COMPARISON_ALWAYS;
		// CreateDepthStencilState创建深度模具状态对象，该对象封装输出合并阶段的深度模具测试信息。
		pDevice->CreateDepthStencilState(&depthStencilDesc, &DepthStencilState_FALSE);

		// D3D11_RASTERIZER_DESC描述光栅器状态。
		D3D11_RASTERIZER_DESC rasterizer_desc;
		//  ZeroMemory() 常被称为清零函数。它也被定义为RtlZeroMemory宏  用0来填充一块内存区域。
		ZeroMemory(&rasterizer_desc, sizeof(rasterizer_desc));
		// 确定呈现 (看到 D3D11_FILL_MODE) 时要使用的填充模式。
		rasterizer_desc.FillMode = D3D11_FILL_SOLID;
		// 指示不绘制面向指定方向的三角形， (看到 D3D11_CULL_MODE) 。
		rasterizer_desc.CullMode = D3D11_CULL_NONE; //D3D11_CULL_FRONT;
		// 确定三角形是正面还是后向。 如果此参数为 TRUE，则如果三角形在呈现目标上逆时针，并且如果三角形是顺时针的，则三角形将被视为正面。 如果此参数为 FALSE，则相反为 true。
		rasterizer_desc.FrontCounterClockwise = false;
		float bias = 1000.0f;
		float bias_float = static_cast<float>(-bias);
		bias_float /= 10000.0f;
		// 添加到给定像素的深度值
		rasterizer_desc.DepthBias = DEPTH_BIAS_D32_FLOAT(*(DWORD*)&bias_float);
		// 给定像素斜率上的标量。 
		rasterizer_desc.SlopeScaledDepthBias = 0.0f;
		// 像素的最大深度偏差。 
		rasterizer_desc.DepthBiasClamp = 0.0f;
		// 根据距离启用剪辑。
		rasterizer_desc.DepthClipEnable = true;
		// 启用剪刀矩形剔除。 活动剪刀矩形之外的所有像素都会被剔除。
		rasterizer_desc.ScissorEnable = false;
		// 指定在多采样反锯齿 (MSAA) 呈现目标上使用四边或 alpha 行反锯齿算法。 设置为 TRUE 以使用四边线抗锯齿算法，并设置为 FALSE 以使用 alpha 行反别名算法。
		rasterizer_desc.MultisampleEnable = false;
		// 指定是否启用行抗锯齿;仅当执行线条绘制和 MultisampleEnable 为 FALSE 时适用。
		rasterizer_desc.AntialiasedLineEnable = false;
		// CreateRasterizerState创建一个光栅器状态对象，该对象告知光栅器阶段的行为方式。
		pDevice->CreateRasterizerState(&rasterizer_desc, &DEPTHBIASState_FALSE);

		// D3D11_RASTERIZER_DESC描述光栅器状态。
		D3D11_RASTERIZER_DESC nrasterizer_desc;
		ZeroMemory(&nrasterizer_desc, sizeof(nrasterizer_desc));
		nrasterizer_desc.FillMode = D3D11_FILL_SOLID;
		//nrasterizer_desc.CullMode = D3D11_CULL_BACK; //flickering
		nrasterizer_desc.CullMode = D3D11_CULL_NONE;
		nrasterizer_desc.FrontCounterClockwise = false;
		nrasterizer_desc.DepthBias = 0.0f;
		nrasterizer_desc.SlopeScaledDepthBias = 0.0f;
		nrasterizer_desc.DepthBiasClamp = 0.0f;
		nrasterizer_desc.DepthClipEnable = true;
		nrasterizer_desc.ScissorEnable = false;
		nrasterizer_desc.MultisampleEnable = false;
		nrasterizer_desc.AntialiasedLineEnable = false;
		pDevice->CreateRasterizerState(&nrasterizer_desc, &DEPTHBIASState_TRUE);

		// 加载 cfg 配置
		LoadCfg();
	}

	// render-target-view 接口标识可在呈现期间访问的呈现目标子资源。
	if (RenderTargetView == NULL)
	{
		// RSGetViewports获取绑定到光栅器阶段的视区数组。
		pContext->RSGetViewports(&vps, &viewport);
		ScreenCenterX = viewport.Width / 2.0f;
		ScreenCenterY = viewport.Height / 2.0f;

		// ID3D11Texture2D 2D 纹理接口管理结构化内存的纹素数据。
		ID3D11Texture2D* backbuffer = NULL;
		hr = pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&backbuffer);
		if (FAILED(hr)) {
			Log("Failed to get BackBuffer");
			return hr;
		}

		// CreateRenderTargetView创建用于访问资源数据的呈现目标视图。
		hr = pDevice->CreateRenderTargetView(backbuffer, NULL, &RenderTargetView);
		backbuffer->Release();
		if (FAILED(hr)) {
			Log("Failed to get RenderTarget");
			return hr;
		}
	}
	else
		// OMSetRenderTargets以原子方式将一个或多个呈现目标绑定到输出合并阶段，并将深度模具缓冲区绑定到 输出合并阶段。
		pContext->OMSetRenderTargets(1, &RenderTargetView, NULL);


	//imgui
	ImGui_ImplWin32_NewFrame();
	ImGui_ImplDX11_NewFrame();
	ImGui::NewFrame();

	// imgui加载弹窗
	if (greetings)
	{
		ImVec4 Bgcol = ImColor(0.0f, 0.4f, 0.28f, 0.8f);
		ImGui::PushStyleColor(ImGuiCol_WindowBg, Bgcol);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.2f, 0.2f, 0.2f, 0.8f));

		ImGui::Begin(u8"标题", &greetings, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs);
		ImGui::Text(u8"已加载,通过INSERT开关菜单");
		ImGui::End();

		static DWORD lastTime = timeGetTime();
		DWORD timePassed = timeGetTime() - lastTime;
		// 显示时间
		if (timePassed > 6000)
		{
			greetings = false;
			lastTime = timeGetTime();
		}
	}

	// 根据是否显示菜单来决定是否绘制鼠标光标
	if (ShowMenu)
		ImGui::GetIO().MouseDrawCursor = 1;
	else
		ImGui::GetIO().MouseDrawCursor = 0;

	// 是否显示菜单
	if (ShowMenu)
	{
		//ImGui::SetNextWindowPos(ImVec2(50.0f, 400.0f)); //pos
		// 设置下一个窗口大小
		ImGui::SetNextWindowSize(ImVec2(510.0f, 400.0f)); //size
		ImVec4 Bgcol = ImColor(0.0f, 0.4f, 0.28f, 0.8f); //bg color
		ImGui::PushStyleColor(ImGuiCol_WindowBg, Bgcol);
		ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.2f, 0.2f, 0.2f, 0.8f)); //frame color

		ImGui::Begin(u8"菜单");
		//ImGui::Checkbox("Wallhack Texture", &Wallhack);

		const char* Wallhack_Options[] = { u8"关闭", u8"深度模板", u8"深度偏移" };
		ImGui::Text(u8"透视作弊器");
		ImGui::SameLine();
		ImGui::Combo(u8"##透视作弊器", (int*)&Wallhack, Wallhack_Options, IM_ARRAYSIZE(Wallhack_Options));

		ImGui::Checkbox(u8"删除纹理", &DeleteTexture); //the point is to highlight textures to see which we are logging
		ImGui::Checkbox(u8"查找模型", &ModelrecFinder);

		if (ModelrecFinder)
		{
			ImGui::SliderInt(u8"寻找Stride", &countStride, -1, 148);

			if (countIndexCount >= -1 && countIndexCount <= 147)
			{
				ImGui::SliderInt(u8"寻找IndexCount", &countIndexCount, -1, 148);
			}
			else if (countIndexCount >= 148 && countIndexCount <= 295)
			{
				ImGui::SliderInt(u8"寻找IndexCount", &countIndexCount, 149, 296);
			}
			else if (countIndexCount >= 296 && countIndexCount <= 443)
			{
				ImGui::SliderInt(u8"寻找IndexCount", &countIndexCount, 297, 444);
			}
			else if (countIndexCount >= 444 && countIndexCount <= 591)
			{
				ImGui::SliderInt(u8"寻找IndexCount", &countIndexCount, 445, 592);
			}
			else if (countIndexCount >= 592 && countIndexCount <= 739)
			{
				ImGui::SliderInt(u8"寻找IndexCount", &countIndexCount, 593, 740);
			}
			else if (countIndexCount >= 740 && countIndexCount <= 887)
			{
				ImGui::SliderInt(u8"寻找IndexCount", &countIndexCount, 741, 888);
			}
			else if (countIndexCount >= 888 && countIndexCount <= 1035)
			{
				ImGui::SliderInt(u8"寻找IndexCount", &countIndexCount, 889, 1036);
				if (countIndexCount == 1036)
					countIndexCount = -1;
			}

			ImGui::SliderInt(u8"寻找pscdesc.ByteWidth", &countpscdescByteWidth, -1, 148);
			ImGui::SliderInt(u8"寻找indesc.ByteWidth", &countindescByteWidth, -1, 148);
			ImGui::SliderInt(u8"寻找vedesc.ByteWidth", &countvedescByteWidth, -1, 148);

			ImGui::Text(u8"菜单说明");
			ImGui::Text(u8"通过TAB或者鼠标选中,空格确定");
			ImGui::Text(u8"通过F9记录绘制方法到log文件");
			ImGui::Text(u8"通过END记录删除纹理到log文件");
			ImGui::Spacing();
			ImGui::Text(u8"快捷键:");
			ImGui::Text(u8"ALT + F1 切换 作弊模式");
			ImGui::Text(u8"ALT + F2 切换 删除纹理");
			ImGui::Text(u8"ALT + F3 切换 查找模型");
			ImGui::Text(u8"通过 Page Up/Down 增减 Stride");
			ImGui::Text(u8"通过 7/8 增减 IndexCount");
		}
		ImGui::End();
	}

	ImGui::EndFrame();
	ImGui::Render();
	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());



	return PLH::FnCast(presentHookRedirectOld, phookD3D11Present)(pSwapChain, SyncInterval, Flags);
	//return phookD3D11Present(pSwapChain, SyncInterval, Flags);
}

//==========================================================================================================================
// HOOK调整窗口大小方法
HRESULT __stdcall hookD3D11ResizeBuffers(IDXGISwapChain* pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags)
{
	//Log("hookD3D11ResizeBuffers\n");
	// 验证设备对象
	ImGui_ImplDX11_InvalidateDeviceObjects();
	if (nullptr != RenderTargetView) { RenderTargetView->Release(); RenderTargetView = nullptr; }

	// 继续原始的方法
	//HRESULT toReturn = phookD3D11ResizeBuffers(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
	HRESULT toReturn = PLH::FnCast(resizeBuffersHookRedirectOld, phookD3D11ResizeBuffers)(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
	// 创建设备对象
	ImGui_ImplDX11_CreateDeviceObjects();
	return toReturn;
}

//==========================================================================================================================
// HOOK将着色器资源的数组绑定到像素着色器函数(纹理贴图)
void __stdcall hookD3D11PSSetShaderResources(ID3D11DeviceContext* pContext, UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews)
{
	//Log("hookD3D11PSSetShaderResources\n");
	pssrStartSlot = StartSlot;

	// 如果WndProc很慢或没有功能，使菜单仍然可用 
	if (GetAsyncKeyState(VK_INSERT) & 1)
	{
		SaveCfg();
		ShowMenu = !ShowMenu;
	}

	// 热键
	if (ShowMenu)
	{
		// alt + f1 to 切换 作弊模式
		//if (GetAsyncKeyState(VK_MENU) && GetAsyncKeyState(VK_F1) & 1)
			//Wallhack = !Wallhack;

		// alt + f1 to 切换 作弊模式
		if (GetAsyncKeyState(VK_MENU) && GetAsyncKeyState(VK_F1) & 1)
		{
			Wallhack++;
			if (Wallhack > 2) Wallhack = 0;
		}

		// alt + f2 to 切换 删除纹理
		if (GetAsyncKeyState(VK_MENU) && GetAsyncKeyState(VK_F2) & 1)
			DeleteTexture = !DeleteTexture;

		// alt + f3 to 切换 模型识别
		if (GetAsyncKeyState(VK_MENU) && GetAsyncKeyState(VK_F3) & 1)
			ModelrecFinder = !ModelrecFinder;

		// 按住page down/up键直到纹理发生变化
		if (GetAsyncKeyState(VK_NEXT) & 1) //page down
			countStride--;
		if (GetAsyncKeyState(VK_PRIOR) & 1) //page up
			countStride++;

		if (GetAsyncKeyState(0x37) & 1) //7-
			countIndexCount--;
		if (GetAsyncKeyState(0x38) & 1) //8+
			countIndexCount++;

		if (GetAsyncKeyState(0x35) & 1) //5-
			countpscdescByteWidth--;
		if (GetAsyncKeyState(0x36) & 1) //6+
			countpscdescByteWidth++;
		if (GetAsyncKeyState(0x33) & 1) //3-
			countindescByteWidth--;
		if (GetAsyncKeyState(0x34) & 1) //4+
			countindescByteWidth++;
	}

	// 使用alt和tab
	if (GetAsyncKeyState(VK_MENU) && GetAsyncKeyState(VK_TAB) & 1)
		ShowMenu = false;
	if (GetAsyncKeyState(VK_TAB) && GetAsyncKeyState(VK_MENU) & 1)
		ShowMenu = false;
	/*
	//texture stuff (usually not needed)
	for (UINT j = 0; j < NumViews; j++)
	{
		ID3D11ShaderResourceView* pShaderResView = ppShaderResourceViews[j];
		if (pShaderResView)
		{
			pShaderResView->GetDesc(&Descr);
			ID3D11Resource *Resource;
			pShaderResView->GetResource(&Resource);
			ID3D11Texture2D *Texture = (ID3D11Texture2D *)Resource;
			Texture->GetDesc(&texdesc);

			SAFE_RELEASE(Resource);
			SAFE_RELEASE(Texture);
		}
	}
	*/
	return PLH::FnCast(pSSetShaderResourcesHookRedirectOld, phookD3D11PSSetShaderResources)(pContext, StartSlot, NumViews, ppShaderResourceViews);
	//return phookD3D11PSSetShaderResources(pContext, StartSlot, NumViews, ppShaderResourceViews);
}

//==========================================================================================================================
// HOOK绘制非索引、非实例化图元函数
void __stdcall hookD3D11Draw(ID3D11DeviceContext* pContext, UINT VertexCount, UINT StartVertexLocation)
{
	//Log("hookD3D11Draw\n");

	if (GetAsyncKeyState(VK_F9) & 1)
		Log("Draw called");

	return PLH::FnCast(drawHookRedirectOld, phookD3D11Draw)(pContext, VertexCount, StartVertexLocation);
	//return phookD3D11Draw(pContext, VertexCount, StartVertexLocation);
}

//==========================================================================================================================
// HOOK绘制索引的、非实例化的图元函数
void __stdcall hookD3D11DrawIndexed(ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation)
{
	//Log("hookD3D11DrawIndexed\n");
	//// 捕获F9按下
	//if (GetAsyncKeyState(VK_F9) & 1)
	//{
	//	MessageBox(0, "F9", "提示", MB_SYSTEMMODAL);
	//	Log("DrawIndexed called");
	//}
	// 捕获F9按下
	if (GetAsyncKeyState(VK_F9) & 1)
	{
		f9 = true;
		MessageBox(0, "F9", "提示", MB_SYSTEMMODAL);
		//if (healthAdress == 0) {
		//initTZM();
		//}
		//创建线程进行初始化
		//CreateThread(NULL, 0, startCPUHook, NULL, 0, NULL);
	}
	//	// 捕获F10按下
	//	if (GetAsyncKeyState(VK_F10) & 1)
	//	{
	//		f10 = true;
	//		if (tzmAdress == 0) {
	//			tzmAdress = ScanTZM("8B 81 80 01 00 00 F7 D8 05 FF FF FF 7F");// 8B 81 80 01 00 00 mov eax,[rcx+00000180]
	//			if (tzmAdress == 0) {
	//				return phookD3D11DrawIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation);
	//			}
	//		}
	//#ifdef _WIN64
	//#else
	//#endif // _WIN64
	//
	//
	//	}
	//	// 捕获F11按下
	//	if (GetAsyncKeyState(VK_F11) & 1)
	//	{
	//		//if (nowMoeny == 0) {
	//		//指针类型转换
	//		//nowMoeny = reinterpret_cast <uintptr_t*>(playerAdress + 0x180);
	//		//}
	//		//if (nowHp == 0) {
	//		//nowHp = reinterpret_cast <uintptr_t*>(playerAdress + 0x174);
	//		//}
	//		//if (nowLev == 0) {
	//		//nowLev = reinterpret_cast <uintptr_t*>(playerAdress + 0x164);
	//		//}
	//		//直接修改内存中指针对应的值
	//		//*nowMoeny = 99999999;
	//		//*nowHp = 654321;
	//		//*nowLev = 1;
	//	}

		// 如果游戏在DrawIndexed中绘制玩家模型，那么在这里做所有的事情(见下面的代码)
		// 获取 stride & vedesc.ByteWidth
	pContext->IAGetVertexBuffers(0, 1, &veBuffer, &Stride, &veBufferOffset);
	if (veBuffer != NULL)
		veBuffer->GetDesc(&vedesc);
	if (veBuffer != NULL) { veBuffer->Release(); veBuffer = NULL; }

	// 获取 indesc.ByteWidth (comment out if not used)
	pContext->IAGetIndexBuffer(&inBuffer, &inFormat, &inOffset);
	if (inBuffer != NULL)
		inBuffer->GetDesc(&indesc);
	if (inBuffer != NULL) { inBuffer->Release(); inBuffer = NULL; }

	// 获取 pscdesc.ByteWidth (comment out if not used)
	pContext->PSGetConstantBuffers(pscStartSlot, 1, &pscBuffer);
	if (pscBuffer != NULL)
		pscBuffer->GetDesc(&pscdesc);
	if (pscBuffer != NULL) { pscBuffer->Release(); pscBuffer = NULL; }

	// 获取 vscdesc.ByteWidth (comment out if not used)
	pContext->VSGetConstantBuffers(vscStartSlot, 1, &vscBuffer);
	if (vscBuffer != NULL)
		vscBuffer->GetDesc(&vscdesc);
	if (vscBuffer != NULL) { vscBuffer->Release(); vscBuffer = NULL; }


	// 判断模式是否启用
	if (Wallhack == 1 || Wallhack == 2) //if wallhack option is enabled in menu
	//
	//ut4 model recognition example
	//if ((Stride == 32 && IndexCount == 10155)||(Stride == 44 && IndexCount == 11097)||(Stride == 40 && IndexCount == 11412)||(Stride == 40 && IndexCount == 11487)||(Stride == 44 && IndexCount == 83262)||(Stride == 40 && IndexCount == 23283))
	//if (Stride == 40 && pscdesc.ByteWidth == 256 && vscdesc.ByteWidth == 4096 && pssrStartSlot == 0) //swbf2 incomplete
	//_____________________________________________________________________________________________________________________________________________________________
	// 模型识别在这里，查看log.txt以获得正确的Stride等。你可能需要反复试验，看看哪个值最有效
		if ((countnum == pssrStartSlot || countStride == Stride || countIndexCount == IndexCount / 100 || countpscdescByteWidth == pscdesc.ByteWidth / 10 ||
			countindescByteWidth == indesc.ByteWidth / 1000 || countvedescByteWidth == vedesc.ByteWidth / 10000))
			//_____________________________________________________________________________________________________________________________________________________________
			//			
		{
			// 获取输出合并阶段的深度模板状态。
			if (Wallhack == 1)
				pContext->OMGetDepthStencilState(&DepthStencilState_ORIG, 0); //get original

			// 设置输出合并阶段的深度模板状态。
			if (Wallhack == 1)
				pContext->OMSetDepthStencilState(DepthStencilState_FALSE, 0); //depthstencil off

			// 为管道的光栅器阶段设置光栅器状态 。
			if (Wallhack == 2)
				pContext->RSSetState(DEPTHBIASState_FALSE); //depthbias off

			// 重新绘制
			phookD3D11DrawIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation); //redraw

			// 还原深度模板状态
			if (Wallhack == 1)
				pContext->OMSetDepthStencilState(DepthStencilState_ORIG, 0); //depthstencil on

			// 设置光栅器状态 (设置为true，而不是恢复原始，以获得另一种wallhack效果)
			if (Wallhack == 2)
				pContext->RSSetState(DEPTHBIASState_TRUE); //depthbias true

			// 释放
			if (Wallhack == 1)
				SAFE_RELEASE(DepthStencilState_ORIG); //release
		}

	// 模型写入log文件
	if (ShowMenu)
	{
		// 如何记录模型:
		// 运行游戏，注入dll，打开菜单
		//0. 按F9查看哪个绘图函数被游戏调用
		//1. 选择删除纹理
		//2. 选择Stride，使用滑块直到敌人模型/纹理消失
		//3. 按END将该模型/纹理的值记录到log.txt
		//4. 将Stride数字添加到您的模型识别中，例如if(Stride == 32)
		//5. 该模型的下一个日志IndexCount
		//6. 添加IndexCount到你的模型规则，例如if(Stride == 32 && IndexCount == 10155)
		//7. 等等

		if ((countnum == pssrStartSlot || countStride == Stride || countIndexCount == IndexCount / 100 || countpscdescByteWidth == pscdesc.ByteWidth / 10 ||
			countindescByteWidth == indesc.ByteWidth / 1000 || countvedescByteWidth == vedesc.ByteWidth / 10000))
			if (GetAsyncKeyState(VK_END) & 1)
				Log("Stride == %d && IndexCount == %d && indesc.ByteWidth == %d && vedesc.ByteWidth == %d && pscdesc.ByteWidth == %d && vscdesc.ByteWidth == %d && pssrStartSlot == %d && vscStartSlot == %d",
					Stride, IndexCount, indesc.ByteWidth, vedesc.ByteWidth, pscdesc.ByteWidth, vscdesc.ByteWidth, pssrStartSlot, vscStartSlot);

		//log specific model
		//if (Stride == 40 && pscdesc.ByteWidth == 256 && vscdesc.ByteWidth == 4096 && pssrStartSlot == 0)
		//if (GetAsyncKeyState(VK_F10) & 1)
		//Log("Stride == %d && IndexCount == %d && indesc.ByteWidth == %d && vedesc.ByteWidth == %d && pscdesc.ByteWidth == %d && vscdesc.ByteWidth == %d && pssrStartSlot == %d && vscStartSlot == %d && Descr.Format == %d && Descr.Buffer.NumElements == %d && texdesc.Format == %d && texdesc.Height == %d && texdesc.Width == %d",
			//Stride, IndexCount, indesc.ByteWidth, vedesc.ByteWidth, pscdesc.ByteWidth, vscdesc.ByteWidth, pssrStartSlot, vscStartSlot, Descr.Format, Descr.Buffer.NumElements, texdesc.Format, texdesc.Height, texdesc.Width);

		// 如果菜单开启了删除纹理
		if (DeleteTexture)
			if ((countnum == pssrStartSlot || countStride == Stride || countIndexCount == IndexCount / 100 || countpscdescByteWidth == pscdesc.ByteWidth / 10 ||
				countindescByteWidth == indesc.ByteWidth / 1000 || countvedescByteWidth == vedesc.ByteWidth / 100000))
				// 删除纹理
				return;
	}
	//return phookD3D11DrawIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation);
	return PLH::FnCast(drawIndexedHookRedirectOld, phookD3D11DrawIndexed)(pContext, IndexCount, StartIndexLocation, BaseVertexLocation);
}

//==========================================================================================================================
// HOOK绘制索引、实例化图元函数
void __stdcall hookD3D11DrawIndexedInstanced(ID3D11DeviceContext* pContext, UINT IndexCountPerInstance, UINT InstanceCount, UINT StartIndexLocation, INT BaseVertexLocation, UINT StartInstanceLocation)
{
	//Log("hookD3D11DrawIndexedInstanced\n");
	// 捕获F9按下
	if (GetAsyncKeyState(VK_F9) & 1)
		MessageBox(0, "f9成功", 0, MB_SYSTEMMODAL);

	//如果游戏在DrawIndexedInstanced中绘制玩家模型，那么在这里做所有的事情(见下面的代码)


	// 获取 stride & vedesc.ByteWidth
	pContext->IAGetVertexBuffers(0, 1, &veBuffer, &Stride, &veBufferOffset);
	if (veBuffer != NULL)
		veBuffer->GetDesc(&vedesc);
	if (veBuffer != NULL) { veBuffer->Release(); veBuffer = NULL; }

	// 获取 indesc.ByteWidth (comment out if not used)
	pContext->IAGetIndexBuffer(&inBuffer, &inFormat, &inOffset);
	if (inBuffer != NULL)
		inBuffer->GetDesc(&indesc);
	if (inBuffer != NULL) { inBuffer->Release(); inBuffer = NULL; }

	// 获取 pscdesc.ByteWidth (comment out if not used)
	pContext->PSGetConstantBuffers(pscStartSlot, 1, &pscBuffer);
	if (pscBuffer != NULL)
		pscBuffer->GetDesc(&pscdesc);
	if (pscBuffer != NULL) { pscBuffer->Release(); pscBuffer = NULL; }

	// 获取 vscdesc.ByteWidth (comment out if not used)
	pContext->VSGetConstantBuffers(vscStartSlot, 1, &vscBuffer);
	if (vscBuffer != NULL)
		vscBuffer->GetDesc(&vscdesc);
	if (vscBuffer != NULL) { vscBuffer->Release(); vscBuffer = NULL; }


	// 判断模式是否启用
	if (Wallhack == 1 || Wallhack == 2) //if wallhack option is enabled in menu
	//
	//ut4 model recognition example
	//if ((Stride == 32 && IndexCount == 10155)||(Stride == 44 && IndexCount == 11097)||(Stride == 40 && IndexCount == 11412)||(Stride == 40 && IndexCount == 11487)||(Stride == 44 && IndexCount == 83262)||(Stride == 40 && IndexCount == 23283))
	//if (Stride == 40 && pscdesc.ByteWidth == 256 && vscdesc.ByteWidth == 4096 && pssrStartSlot == 0) //swbf2 incomplete
	//_____________________________________________________________________________________________________________________________________________________________
	// 模型识别在这里，查看log.txt以获得正确的Stride等。你可能需要反复试验，看看哪个值最有效
		if ((countnum == pssrStartSlot || countStride == Stride || countIndexCount == IndexCountPerInstance / 100 || countpscdescByteWidth == pscdesc.ByteWidth / 10 ||
			countindescByteWidth == indesc.ByteWidth / 1000 || countvedescByteWidth == vedesc.ByteWidth / 10000))
			//_____________________________________________________________________________________________________________________________________________________________
			//			
		{
			// 获取输出合并阶段的深度模板状态。
			if (Wallhack == 1)
				pContext->OMGetDepthStencilState(&DepthStencilState_ORIG, 0); //get original

			// 设置输出合并阶段的深度模板状态
			if (Wallhack == 1)
				pContext->OMSetDepthStencilState(DepthStencilState_FALSE, 0); //depthstencil off

			// 为管道的光栅器阶段设置光栅器状态 
			if (Wallhack == 2)
				pContext->RSSetState(DEPTHBIASState_FALSE); //depthbias off

			// 重新绘制
			phookD3D11DrawIndexedInstanced(pContext, IndexCountPerInstance, InstanceCount, StartIndexLocation, BaseVertexLocation, StartInstanceLocation); //redraw

			// 还原深度模板状态
			if (Wallhack == 1)
				pContext->OMSetDepthStencilState(DepthStencilState_ORIG, 0); //depthstencil on

			// 设置光栅器状态 (设置为true，而不是恢复原始，以获得另一种wallhack效果)
			if (Wallhack == 2)
				pContext->RSSetState(DEPTHBIASState_TRUE); //depthbias true

			// 释放
			if (Wallhack == 1)
				SAFE_RELEASE(DepthStencilState_ORIG); //release
		}

	// 模型写入log文件
	if (ShowMenu)
	{
		// 如何记录模型:
		// 运行游戏，注入dll，打开菜单
		//0. 按F9查看哪个绘图函数被游戏调用
		//1. 选择删除纹理
		//2. 选择Stride，使用滑块直到敌人模型/纹理消失
		//3. 按END将该模型/纹理的值记录到log.txt
		//4. 将Stride数字添加到您的模型识别中，例如if(Stride == 32)
		//5. 该模型的下一个日志IndexCount
		//6. 添加IndexCount到你的模型规则，例如if(Stride == 32 && IndexCount == 10155)
		//7. 等等

		if ((countnum == pssrStartSlot || countStride == Stride || countIndexCount == IndexCountPerInstance / 100 || countpscdescByteWidth == pscdesc.ByteWidth / 10 ||
			countindescByteWidth == indesc.ByteWidth / 1000 || countvedescByteWidth == vedesc.ByteWidth / 10000))
			if (GetAsyncKeyState(VK_END) & 1)
				Log("Stride == %d && IndexCountPerInstance == %d && indesc.ByteWidth == %d && vedesc.ByteWidth == %d && pscdesc.ByteWidth == %d && vscdesc.ByteWidth == %d && pssrStartSlot == %d && vscStartSlot == %d",
					Stride, IndexCountPerInstance, indesc.ByteWidth, vedesc.ByteWidth, pscdesc.ByteWidth, vscdesc.ByteWidth, pssrStartSlot, vscStartSlot);

		//log specific model
		//if (Stride == 40 && pscdesc.ByteWidth == 256 && vscdesc.ByteWidth == 4096 && pssrStartSlot == 0)
		//if (GetAsyncKeyState(VK_F10) & 1)
		//Log("Stride == %d && IndexCountPerInstance == %d && indesc.ByteWidth == %d && vedesc.ByteWidth == %d && pscdesc.ByteWidth == %d && vscdesc.ByteWidth == %d && pssrStartSlot == %d && vscStartSlot == %d && Descr.Format == %d && Descr.Buffer.NumElements == %d && texdesc.Format == %d && texdesc.Height == %d && texdesc.Width == %d",
			//Stride, IndexCountPerInstance, indesc.ByteWidth, vedesc.ByteWidth, pscdesc.ByteWidth, vscdesc.ByteWidth, pssrStartSlot, vscStartSlot, Descr.Format, Descr.Buffer.NumElements, texdesc.Format, texdesc.Height, texdesc.Width);

		// 如果菜单开启了删除纹理
		if (DeleteTexture)
			if ((countnum == pssrStartSlot || countStride == Stride || countIndexCount == IndexCountPerInstance / 100 || countpscdescByteWidth == pscdesc.ByteWidth / 10 ||
				countindescByteWidth == indesc.ByteWidth / 1000 || countvedescByteWidth == vedesc.ByteWidth / 100000))
				// 删除纹理
				return;
	}

	return PLH::FnCast(drawIndexedInstancedHookRedirectOld, phookD3D11DrawIndexedInstanced)(pContext, IndexCountPerInstance, InstanceCount, StartIndexLocation, BaseVertexLocation, StartInstanceLocation);
	//return phookD3D11DrawIndexedInstanced(pContext, IndexCountPerInstance, InstanceCount, StartIndexLocation, BaseVertexLocation, StartInstanceLocation);
}

//==========================================================================================================================
//HOOK从 GPU 查询信息的函数
void __stdcall hookD3D11CreateQuery(ID3D11Device* pDevice, const D3D11_QUERY_DESC* pQueryDesc, ID3D11Query** ppQuery)
{
	/*
	// 禁用遮挡，阻止通过某些物体渲染玩家模型
	// 降低FPS，不推荐，只适用于客户端遮挡等情况
	if (pQueryDesc->Query == D3D11_QUERY_OCCLUSION)
	{
		D3D11_QUERY_DESC oqueryDesc = CD3D11_QUERY_DESC();
		(&oqueryDesc)->MiscFlags = pQueryDesc->MiscFlags;
		(&oqueryDesc)->Query = D3D11_QUERY_TIMESTAMP;

		return phookD3D11CreateQuery(pDevice, &oqueryDesc, ppQuery);
	}
	*/
	return phookD3D11CreateQuery(pDevice, pQueryDesc, ppQuery);
}

//传入需要查找的dll名称和函数名返回函数地址
/**
使用示例:
std::unordered_map<std::string, std::string> functionNames = {
		{"Present", "Present"},
		{"ResizeBuffers", "ResizeBuffers"},
		// 其他函数名...
	};

	std::unordered_map<std::string, FARPROC> functionAddresses = GetFunctionAddresses("dxgi.dll", functionNames);

	// 使用函数地址
	Present_t pPresent = reinterpret_cast<Present_t>(functionAddresses["Present"]);
	ResizeBuffers_t pResizeBuffers = reinterpret_cast<ResizeBuffers_t>(functionAddresses["ResizeBuffers"]);
	// 其他函数...

	// 打印函数地址
	std::cout << "Present address: " << pPresent << std::endl;
	std::cout << "ResizeBuffers address: " << pResizeBuffers << std::endl;
*/
std::unordered_map<std::string, FARPROC> GetFunctionAddresses(const std::string& moduleName, const std::unordered_map<std::string, std::string>& functionNames)
{
	std::unordered_map<std::string, FARPROC> functionAddresses;

	HMODULE hModule = GetModuleHandleA(moduleName.c_str());
	if (hModule != nullptr)
	{
		for (const auto& functionName : functionNames)
		{
			FARPROC pFunction = GetProcAddress(hModule, functionName.second.c_str());
			if (pFunction != nullptr)
			{
				functionAddresses[functionName.first] = pFunction;
				Log("赋值地址%p:\n", pFunction);
			}
			else
			{
				std::cout << "Failed to get address of function: " << functionName.first << std::endl;
			}
		}
	}
	else
	{
		std::cout << "Failed to get module handle for: " << moduleName << std::endl;
	}

	return functionAddresses;
}

// 初始化HOOK
DWORD __stdcall InitHooks(LPVOID)
{
	HMODULE hDXGIDLL = 0;
	do
	{
		hDXGIDLL = GetModuleHandle("dxgi.dll");
		Sleep(4000);
	} while (!hDXGIDLL);
	Sleep(100);

	IDXGISwapChain* pSwapChain;

	WNDCLASSEXA wc = { sizeof(WNDCLASSEX), CS_CLASSDC, DXGIMsgProc, 0L, 0L, GetModuleHandleA(NULL), NULL, NULL, NULL, NULL, "DX", NULL };
	RegisterClassExA(&wc);
	HWND hWnd = CreateWindowA("DX", NULL, WS_OVERLAPPEDWINDOW, 100, 100, 300, 300, NULL, NULL, wc.hInstance, NULL);

	D3D_FEATURE_LEVEL requestedLevels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1 };
	D3D_FEATURE_LEVEL obtainedLevel;

	DXGI_SWAP_CHAIN_DESC scd;
	ZeroMemory(&scd, sizeof(scd));
	scd.BufferCount = 1;
	scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	scd.BufferDesc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;
	scd.BufferDesc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED;
	scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;

	scd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	scd.OutputWindow = hWnd;
	scd.SampleDesc.Count = MultisampleCount;
	scd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
	scd.Windowed = ((GetWindowLongPtr(hWnd, GWL_STYLE) & WS_POPUP) != 0) ? false : true;

	scd.BufferDesc.Width = 1;
	scd.BufferDesc.Height = 1;
	scd.BufferDesc.RefreshRate.Numerator = 0;
	scd.BufferDesc.RefreshRate.Denominator = 1;

	UINT createFlags = 0;
#ifdef _DEBUG
	createFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

	if (FAILED(D3D11CreateDeviceAndSwapChain(
		nullptr,
		D3D_DRIVER_TYPE_HARDWARE,
		nullptr,
		createFlags,
		requestedLevels,
		sizeof(requestedLevels) / sizeof(D3D_FEATURE_LEVEL),
		D3D11_SDK_VERSION,
		&scd,
		&pSwapChain,
		&pDevice,
		&obtainedLevel,
		&pContext)))
	{
		MessageBox(hWnd, "Failed to create directX device and swapchain!", "Error", MB_ICONERROR);
		return NULL;
	}

	pSwapChainVtable = (DWORD_PTR*)pSwapChain;
	pSwapChainVtable = (DWORD_PTR*)pSwapChainVtable[0];

	pContextVTable = (DWORD_PTR*)pContext;
	pContextVTable = (DWORD_PTR*)pContextVTable[0];

	pDeviceVTable = (DWORD_PTR*)pDevice;
	pDeviceVTable = (DWORD_PTR*)pDeviceVTable[0];

	phookD3D11Present = (D3D11PresentHook)(DWORD_PTR*)pSwapChainVtable[8];
	phookD3D11ResizeBuffers = (D3D11ResizeBuffersHook)(DWORD_PTR*)pSwapChainVtable[13];
	phookD3D11PSSetShaderResources = (D3D11PSSetShaderResourcesHook)(DWORD_PTR*)pContextVTable[8];
	phookD3D11Draw = (D3D11DrawHook)(DWORD_PTR*)pContextVTable[13];
	phookD3D11DrawIndexed = (D3D11DrawIndexedHook)(DWORD_PTR*)pContextVTable[12];
	phookD3D11DrawIndexedInstanced = (D3D11DrawIndexedInstancedHook)(DWORD_PTR*)pContextVTable[20];
	//phookD3D11CreateQuery = (D3D11CreateQueryHook)(DWORD_PTR*)pDeviceVTable[24];

	//原Detour库hook操作
	// 
	// 开始事务
	//DetourTransactionBegin();
	//DetourUpdateThread(GetCurrentThread());
	// 设定hook规则
	//DetourAttach(&(LPVOID&)phookD3D11Present, (PBYTE)hookD3D11Present);
	//DetourAttach(&(LPVOID&)phookD3D11ResizeBuffers, (PBYTE)hookD3D11ResizeBuffers);
	//DetourAttach(&(LPVOID&)phookD3D11PSSetShaderResources, (PBYTE)hookD3D11PSSetShaderResources);
	//DetourAttach(&(LPVOID&)phookD3D11Draw, (PBYTE)hookD3D11Draw);
	//DetourAttach(&(LPVOID&)phookD3D11DrawIndexed, (PBYTE)hookD3D11DrawIndexed);
	//DetourAttach(&(LPVOID&)phookD3D11DrawIndexedInstanced, (PBYTE)hookD3D11DrawIndexedInstanced);
	//DetourAttach(&(LPVOID&)phookD3D11CreateQuery, (PBYTE)hookD3D11CreateQuery);
	// 提交hook
	//DetourTransactionCommit();


	//polyhook2库hook操作
	// 
	//指定hook规则
	presentHook = make_unique<PLH::x64Detour>(reinterpret_cast<std::uint64_t>(phookD3D11Present), reinterpret_cast<std::uint64_t>(&hookD3D11Present), &presentHookRedirectOld);
	resizeBuffersHook = make_unique<PLH::x64Detour>(reinterpret_cast<std::uint64_t>(phookD3D11ResizeBuffers), reinterpret_cast<std::uint64_t>(&hookD3D11ResizeBuffers), &resizeBuffersHookRedirectOld);
	pSSetShaderResourcesHook = make_unique<PLH::x64Detour>(reinterpret_cast<std::uint64_t>(phookD3D11PSSetShaderResources), reinterpret_cast<std::uint64_t>(&hookD3D11PSSetShaderResources), &pSSetShaderResourcesHookRedirectOld);
	drawHook = make_unique<PLH::x64Detour>(reinterpret_cast<std::uint64_t>(phookD3D11Draw), reinterpret_cast<std::uint64_t>(&hookD3D11Draw), &drawHookRedirectOld);
	drawIndexedHook = make_unique<PLH::x64Detour>(reinterpret_cast<std::uint64_t>(phookD3D11DrawIndexed), reinterpret_cast<std::uint64_t>(&hookD3D11DrawIndexed), &drawIndexedHookRedirectOld);
	drawIndexedInstancedHook = make_unique<PLH::x64Detour>(reinterpret_cast<std::uint64_t>(phookD3D11DrawIndexedInstanced), reinterpret_cast<std::uint64_t>(&hookD3D11DrawIndexedInstanced), &drawIndexedInstancedHookRedirectOld);

	//开始hook
	presentHook->hook();
	resizeBuffersHook->hook();
	pSSetShaderResourcesHook->hook();
	drawHook->hook();
	drawIndexedHook->hook();
	drawIndexedInstancedHook->hook();

	//还原内存标记

	DWORD dwOld;
	VirtualProtect(phookD3D11Present, 2, PAGE_EXECUTE_READWRITE, &dwOld);

	while (true) {
		Sleep(10);
	}

	pDevice->Release();
	pContext->Release();
	pSwapChain->Release();

	return NULL;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call) {
		// 加载dll
	case DLL_PROCESS_ATTACH:
		// 禁用指定的DLL的DLL_THREAD_ATTACH和DLL_THREAD_DETACH通知，减小某些程序的工作集大小
		DisableThreadLibraryCalls(hModule);
#ifdef _WIN64
		////获取当前进程已加载模块的文件的完整路径，该模块必须由当前进程加载
		//GetModuleFileName(hModule, dlldir, 512);
		//// 过滤路径
		//for (size_t i = strlen(dlldir); i > 0; i--) { if (dlldir[i] == '\\') { dlldir[i + 1] = 0; break; } }
		////初始化函数转发
		//for (INT i = 0; i < sizeof(m_dwReturn) / sizeof(DWORD); i++)
		//{
		//	m_dwReturn[i] = TlsAlloc();
		//}
		//InitAddr();
#else
		//Load();
#endif
		MessageBox(0, "DLL成功", 0, MB_SYSTEMMODAL);
		// 创建线程执行HOOK初始化
		CreateThread(NULL, 0, InitHooks, NULL, 0, NULL);
		break;
	case DLL_THREAD_ATTACH:break;
	case DLL_THREAD_DETACH:break;
		// 卸载dll
	case DLL_PROCESS_DETACH:
		// 取消hook
		//DetourTransactionBegin();
		//DetourUpdateThread(GetCurrentThread());
		//DetourDetach(&(LPVOID&)phookD3D11Present, (PBYTE)hookD3D11Present);
		//DetourDetach(&(LPVOID&)phookD3D11ResizeBuffers, (PBYTE)hookD3D11ResizeBuffers);
		//DetourDetach(&(LPVOID&)phookD3D11PSSetShaderResources, (PBYTE)hookD3D11PSSetShaderResources);
		//DetourDetach(&(LPVOID&)phookD3D11Draw, (PBYTE)hookD3D11Draw);
		//DetourDetach(&(LPVOID&)phookD3D11DrawIndexed, (PBYTE)hookD3D11DrawIndexed);
		//DetourDetach(&(LPVOID&)phookD3D11DrawIndexedInstanced, (PBYTE)hookD3D11DrawIndexedInstanced);
		////DetourDetach(&(LPVOID&)phookD3D11CreateQuery, (PBYTE)hookD3D11CreateQuery);
		//DetourTransactionCommit();

		presentHook->unHook();
		resizeBuffersHook->unHook();
		pSSetShaderResourcesHook->unHook();
		drawHook->unHook();
		drawIndexedHook->unHook();
		drawIndexedInstancedHook->unHook();
		//createQueryHook->unHook();

#ifdef _WIN64
		//释放内存
		/*for (INT i = 0; i < sizeof(m_dwReturn) / sizeof(DWORD); i++)
		{
			TlsFree(m_dwReturn[i]);
		}
		Free();*/
#else
		Free();
#endif
		break;
	}
	return TRUE;
}

