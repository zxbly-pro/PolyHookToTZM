//d3d11 wallhack (main.h)

//==========================================================================================================================

// 菜单默认设置
#include <d3d11.h>
#include <minwindef.h>
bool ModelrecFinder = true;
int Wallhack = 1;
bool DeleteTexture = true;

//是否第一次初始化
bool firstTime = true;

// 深度模具状态
ID3D11DepthStencilState* DepthStencilState_FALSE = NULL; //depth off
ID3D11DepthStencilState* DepthStencilState_ORIG = NULL; //depth on
// 光栅器状态
ID3D11RasterizerState* DEPTHBIASState_FALSE;
ID3D11RasterizerState* DEPTHBIASState_TRUE;
ID3D11RasterizerState* DEPTHBIASState_ORIG;
#define DEPTH_BIAS_D32_FLOAT(d) (d/(1/pow(2,23)))

// 视图点
UINT vps = 1;
D3D11_VIEWPORT viewport;
float ScreenCenterX;
float ScreenCenterY;

// RenderTargetView 接口标识可在呈现期间访问的呈现目标子资源。
ID3D11RenderTargetView* RenderTargetView = NULL;

//vertex
ID3D11Buffer* veBuffer;
UINT Stride;
UINT veBufferOffset;
D3D11_BUFFER_DESC vedesc;

//index
ID3D11Buffer* inBuffer;
DXGI_FORMAT inFormat;
UINT        inOffset;
D3D11_BUFFER_DESC indesc;

//psgetConstantbuffers
UINT pscStartSlot;
ID3D11Buffer* pscBuffer;
D3D11_BUFFER_DESC pscdesc;

//vsgetconstantbuffers
UINT vscStartSlot;
ID3D11Buffer* vscBuffer;
D3D11_BUFFER_DESC vscdesc;

//pssetshaderresources
UINT pssrStartSlot;
ID3D11Resource* Resource;
D3D11_SHADER_RESOURCE_VIEW_DESC Descr;
D3D11_TEXTURE2D_DESC texdesc;

// window消息处理
HWND window = nullptr;
// 判断imgui状态是否显示
bool ShowMenu = true;
// 原始windows消息处理
static WNDPROC OriginalWndProcHandler = nullptr;

// 日志,计数等
bool logger = false;
int countnum = -1;
int countStride = -1;
int countIndexCount = -1;
int countpscdescByteWidth = -1;
int countindescByteWidth = -1;
int countvedescByteWidth = -1;

wchar_t reportValue[256];
#define SAFE_RELEASE(x) if (x) { x->Release(); x = NULL; }
HRESULT hr;

// 是否弹出imgui加载弹窗
bool greetings = true;
bool f9 = false;
bool f10 = false;
bool f11 = false;
//ULONG64 tzmAdress = 0;
ULONG64 healthAdress = 0;

//==========================================================================================================================

using namespace std;
#include <fstream>
// 目录
char dlldir[320];
// 根据文件名获取目录
char* GetDirectoryFile(char* filename)
{
	static char path[320];
	strcpy_s(path, dlldir);
	strcat_s(path, filename);
	return path;
}

// 记录日志
void Log(const char* fmt, ...)
{
	if (!fmt)	return;

	char		text[4096];
	va_list		ap;
	va_start(ap, fmt);
	vsprintf_s(text, fmt, ap);
	va_end(ap);

	ofstream logfile(GetDirectoryFile("log.txt"), ios::app);
	if (logfile.is_open() && text)	logfile << text << endl;
	logfile.close();
}

//==========================================================================================================================

#include <string>
#include <fstream>
// 保存cfg
void SaveCfg()
{
	ofstream fout;
	fout.open(GetDirectoryFile("d3dwh.ini"), ios::trunc);
	fout << "Wallhack " << Wallhack << endl;
	fout << "ModelrecFinder " << ModelrecFinder << endl;
	fout.close();
}

// 加载 cfg
void LoadCfg()
{
	ifstream fin;
	string Word = "";
	fin.open(GetDirectoryFile("d3dwh.ini"), ifstream::in);
	fin >> Word >> Wallhack;
	fin >> Word >> ModelrecFinder;
	fin.close();
}