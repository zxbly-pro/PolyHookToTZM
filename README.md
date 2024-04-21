# PolyHookToTZM
 通过特征码扫描进行x64和x86的PolyHook

项目基于PolyHook_2_0进行额外开发,需要编译PolyHook_2_0所需依赖

源码构建

```shell
#源码下载
λ git clone --recursive https://github.com/stevemk14ebr/PolyHook_2_0.git
λ cd PolyHook_2_0
#子模块初始化
λ git submodule update --init --recursive
#dynamic build动态构建->dll 32位构建用 -A Win32,64位不带 -A参数或者-A x64
λ (dynamic build) cmake -B"./_build" -DCMAKE_INSTALL_PREFIX="./_install/" -DPOLYHOOK_BUILD_SHARED_LIB=ON -A Win32
#static build静态构建->lib 	32位构建用 -A Win32,64位不带 -A参数或者-A x64
λ (static build)  cmake -B"./_build" -DCMAKE_INSTALL_PREFIX="./_install/" -DPOLYHOOK_BUILD_SHARED_LIB=OFF -A Win32
#cmake编译
λ cmake --build "./_build" --config Release --target install
```

需要cmake环境,解压cmake压缩包,配置bin目录到path即可配置cmake

	构建完成后使用:
	
	项目属性->常规->c++语言标准和c语言标准尽量用17+
	
	项目属性->C/C++->代码生成->运行库->修改成	多线程(/MT)	--静态编译 动态编译dll不用改
	
	项目属性->C/C++->常规->附加包含目录->添加编译完成的_install下面的include目录
	
	项目属性->链接器->常规->附加库目录->添加编译完成的_install下面的lib目录(32位需要编译32位的lib文件,include文件不用)
	
	项目属性->链接器->输入->附加依赖项->添加	PolyHook_2.lib;asmjit.lib;asmtk.lib;Zycore.lib;Zydis.lib	如果没添加完整可能出现找不到依赖,需要手动绑定lib,例如:
	
	#pragma comment (lib, "asmjit.lib")
	#pragma comment (lib, "asmtk.lib")
	#pragma comment (lib, "PolyHook_2.lib")
	#pragma comment (lib, "Zydis.lib")
	#pragma comment (lib, "Zycore.lib")
	
	cpp里面添加需要的头文件,例如:
	
	#include <Windows.h> 
	#include "polyhook2/ZydisDisassembler.hpp"
	#include "polyhook2/Detour/x64Detour.hpp"
	
	using namespace PLH;
	
	然后直接使用
	
	PLH::x64Detour detour(msgAdress, msgAdressNew, &u64_hMessageBoxA);
	detour.hook();
	detour.unhook();

vs2022构建

```
需要一个最新的vs2022。首先克隆项目并执行上面的子模块初始化。不要运行 cmake 命令，而是：

打开 VS 2022，转到 file->open->cmake.. 这将加载项目并开始 cmake 生成。接下来转到cmake->build all或cmake->build，您还可以设置启动项和发布模式以使用播放按钮（不要使用安装目标）。 Capstone、Zydis 和 asmjit 设置为自动构建和链接，您不需要单独构建它们。
```

功能介绍

1. ```
   1. capstone 和 zydis 都支持作为反汇编后端，并且是完全抽象的。
   2. 内联挂钩（x86/x64 Detour）
      - 在序言处放置一个 jmp 到回调，然后分配一个蹦床以继续执行原始函数
      - 完全在中间指令对象上运行，反汇编引擎是可交换的，默认情况下包括 capstone
      - 编译时调用 conv 时是否可以进行 JIT 回调未知（请参阅 ILCallback.cpp）
      - 遵循已经挂钩的函数
      - 解决间接调用，例如通过 iat 和 hooks 底层函数
      - 重新定位序言并解析所有位置相关代码
        - 进入覆盖部分的分支将解析到新移动的位置
        - 从移动序言回到原始部分的跳转通过跳转表解决
        - 已移动部分内的重定位已解决（不使用重定位表，使用引擎进行反汇编）
        - 不可重定位指令通过动态二进制重写进行重写，并替换为语义等效的指令
      - x64 蹦床不限于 +- 2GB，可以在任何地方，避免影子空间 + 不会损坏寄存器（取决于绕行方案）。
        - 覆盖代码洞和填充字节可以设置为主要策略，或者作为后备方案
      - 如果内联挂钩在中间步骤失败，则原始函数不会出现格式错误。所有写入都会分批进行，直到我们知道后续步骤成功为止。
      - *完全*支持跨架构挂钩。包括重写内存访问例程以允许从 32 位进程读取/写入 64 位内存。如果您足够聪明，可以编写回调所需的 shellcode，则可以从 32 位进程中挂钩 64 位。
      - 实现了有效的 reHook-ing 逻辑。这可用于防止第三方将序言重写回原始字节。这被优化为一些简单的 memcpy，而不是重新执行 hook() 中的整个逻辑。
   3. 运行时内联钩子
      - 普通内联挂钩的所有优点，但 JIT 是与给定 typedef 和 ABI 兼容的翻译存根。翻译存根会将参数移动到一个小结构中，该结构作为指向回调的指针传递，并允许欺骗返回值。这允许工具在运行时生成钩子翻译存根，从而允许在运行时才知道 typedef 的函数的完全内联钩子。
   4. 虚拟功能交换（VFuncSwap）
      - 交换 C++ VTable 中给定索引处的指针以指向回调
   5. 虚拟表交换（VTableSwap）
      - 对 c++ VTable 执行深度复制，并用新分配的副本替换指向表的指针。然后交换副本中的指针条目以指向回调
   6. 软件断点钩子（BreakpointHook）
      - 用 0xCC 覆盖函数的第一个字节并在异常处理程序中调用回调。为用户提供自动恢复原始被覆盖字节的方法
   7. 硬件断点钩子（HWBreakpointHook）
      - 设置CPU的调试寄存器，为调用线程添加硬件执行BP。在异常处理程序中调用回调。**请记住，HW BP 是针对每个线程的，调用 hook() 的线程必须与被挂钩的线程相同。您可能会发现一个快速绕行，然后在绕行回调中设置 HWBP，然后取消挂钩成为一个有用的构造。**
   8. 导入地址表挂钩 (IatHook)
      - 通过 PEB 解析加载的模块，找到 IAT，然后将 thunk 指针交换到回调。
   9. 导出地址表挂钩（EatHook）
      - 通过 PEB 解析加载的模块，找到 EAT，然后交换指针以导出到回调。由于这是一个 32 位偏移量，如果超过 32 位，我们可以选择分配一个蹦床存根来完成回调的完整传输。
   ```

   
